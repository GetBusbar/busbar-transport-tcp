// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE CARRIER, BOTH DOORS, ONE WIRE** — the `tcp` carrier's linked + dropped-in conformance, run
//! against the busbar rev this repo pins (`.busbar-ref`) (#3: a transport is swappable, compiled in
//! OR dropped in over the ABI; #30: it rides the HOT lane; #2 rule (1): one contract, one loading
//! path; TRANSPORT-STACK: the HOT decl is the Carrier/Framer traits lowered one slot per method).
//!
//! The carrier is held three ways at once: LINKED (the logic crate's `linked::carrier`, driven as the
//! contract's [`Carrier`] directly — what a busbar build that compiles the wire in holds), its DECL
//! (the contract's `export_carrier!` lowering of the same type, `exports::TRANSPORT_DECL`, admitted
//! through the loader's `link_transport`), and DROPPED IN (this crate's built cdylib, signed
//! first-party into a fresh `plugins/` directory, found by the loader's scan and opened by
//! `open_transport`). Every decl runs the loader's ONE admission.
//!
//! THE FOLD. Each carrier runs the same script through the SAME trait methods against real
//! connections whose far end is a peer through a separate instance of the linked carrier — dial it
//! and exchange bytes, listen for it and exchange bytes — and records what crossed the wire in each
//! direction. The folds must be equal, and each must equal the bytes the script sent: the bytes on
//! the wire are identical whichever door the carrier came in by, and identical to what was asked for.
//!
//! THE RED ARM, kept: [`a_divergent_carrier_is_seen_by_the_fold`] runs the fold over a decl whose
//! `poll_write` slot alters one byte and requires the fold to DIFFER.
//!
//! Ported from busbar's `crates/plugin-loader/src/tests/transport_conformance_tests.rs` (TRANSPORT-STACK
//! (2)), where the carrier was proven before it moved to this repo.

use busbar_contract::abi::hot::transport::{CarrierSlots, RawWireOutcome, TransportDecl};
use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::transport::{Carrier, CarrierPoll, Dest, Role, TransportSettings};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::transport::{link_transport, wire_settings, Built, DynTransport};
use busbar_transport_tcp_plugin::{exports, linked};
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Wake, Waker};

/// The version both doors state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

// ── DRIVING A CARRIER ON THIS THREAD ────────────────────────────────────────────────────────────

/// Wakes the thread that parked on a poll.
struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Drive one future on this thread, parking between polls.
fn block_on<F: Future>(f: F) -> F::Output {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut f = std::pin::pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}

/// Poll one carrier method to its answer on this thread.
fn wait<T>(
    mut method: impl FnMut(&mut Context<'_>) -> CarrierPoll<T>,
) -> Result<T, TransportError> {
    block_on(std::future::poll_fn(|cx| method(cx)))
}

/// Offer every one of `bytes` to `conn`, then flush.
fn write_all(c: &dyn Carrier, conn: u64, bytes: &[u8]) -> Result<(), TransportError> {
    let mut at = 0;
    while at < bytes.len() {
        at += wait(|cx| c.poll_write(conn, cx, &bytes[at..]))?;
    }
    wait(|cx| c.poll_flush(conn, cx))
}

/// Read exactly `n` bytes of `conn`, in reads no longer than `chunk`.
fn read_exact(c: &dyn Carrier, conn: u64, n: usize, chunk: usize) -> Vec<u8> {
    let mut all = Vec::with_capacity(n);
    let mut buf = vec![0_u8; chunk];
    while all.len() < n {
        let want = (n - all.len()).min(chunk);
        match wait(|cx| c.poll_read(conn, cx, &mut buf[..want])) {
            Ok(0) => panic!("the far end closed after {} of {n} bytes", all.len()),
            Ok(got) => all.extend_from_slice(&buf[..got]),
            Err(e) => panic!("read failed mid-stream: {e:?}"),
        }
    }
    all
}

/// Read `conn` to its end, in reads no longer than `chunk`: the bytes, and how it ended (`Ok` for
/// the clean end, or the error that ended it).
fn drain(c: &dyn Carrier, conn: u64, chunk: usize) -> (Vec<u8>, Result<(), TransportError>) {
    let mut all = Vec::new();
    let mut buf = vec![0_u8; chunk];
    loop {
        match wait(|cx| c.poll_read(conn, cx, &mut buf)) {
            Ok(0) => return (all, Ok(())),
            Err(e) => return (all, Err(e)),
            Ok(n) => all.extend_from_slice(&buf[..n]),
        }
    }
}

// ── THE DOORS ───────────────────────────────────────────────────────────────────────────────────

/// A decl admitted through the linked door, once for the process per decl.
fn admitted(decl: &'static TransportDecl, display: &str) -> &'static DynTransport {
    static ROWS: Mutex<Vec<(usize, &'static DynTransport)>> = Mutex::new(Vec::new());
    let key = decl as *const TransportDecl as usize;
    let mut rows = ROWS.lock().unwrap();
    if let Some((_, row)) = rows.iter().find(|(k, _)| *k == key) {
        return row;
    }
    // SAFETY: `decl` is `'static` and laid out as `TransportDecl`, borrowing `'static` data.
    let row: &'static DynTransport = Box::leak(Box::new(
        unsafe { link_transport(decl, display) }.expect("the linked door admits the carrier"),
    ));
    rows.push((key, row));
    row
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_transport_tcp_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-transport-tcp-plugin cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// THE DROPPED-IN DOOR: the cdylib signed first-party into a fresh `plugins/` directory, scanned
/// under a policy holding the release key, and opened by name — once for the process.
fn dropped_in() -> &'static DynTransport {
    static ROW: OnceLock<DynTransport> = OnceLock::new();
    ROW.get_or_init(|| {
        let lib = cdylib();
        let dir = std::env::temp_dir().join(format!("transport-tcp-conf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the plugins dir");
        let manifest = Manifest {
            name: "wire".into(),
            alias: "wire".into(),
            kind: "transport".into(),
            version: VERSION.into(),
            publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: busbar_contract::abi::ABI_MINOR,
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
            declares: Default::default(),
        };
        let signed = sign(&release(), manifest, &lib);
        let tarball =
            busbar_plugin_loader::tarball::package(&signed, "libwire.so", &lib).expect("package");
        std::fs::write(dir.join("wire.tar.gz"), tarball).expect("write the tarball");
        let policy = TrustPolicy {
            first_party_key: Some(release().verifying_key()),
            binary_version: VERSION.into(),
            first_party_floors: Default::default(),
            first_party_high_water: Default::default(),
            publishers: Default::default(),
            allow_unsigned: false,
            allow_third_party: false,
            min_versions: Default::default(),
        };
        let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy)
            .unwrap_or_else(|e| panic!("the signed carrier scans: {e:?}"));
        let row = registry
            .open_transport("wire")
            .expect("the dropped-in door opens the carrier");
        let _ = std::fs::remove_dir_all(&dir);
        row
    })
}

/// A decl row's carrier, built.
fn carrier_of(row: &'static DynTransport) -> Arc<dyn Carrier> {
    match row
        .build(&wire_settings(&TransportSettings::default()))
        .expect("the carrier builds")
    {
        Built::Carrier(c) => c,
        Built::Framer(_) => panic!("tcp is a carrier"),
    }
}

// ── THE FAR END: a separate instance of the linked carrier ──────────────────────────────────────

/// The peer's carrier: a fresh instance of the linked carrier (not the one under test).
fn peer() -> Arc<dyn Carrier> {
    linked::carrier(&TransportSettings::default())
}

/// An address nothing answers on: a reserved port nobody may bind unprivileged.
const NOBODY: &str = "127.0.0.1:1";

/// Put every one of `bytes` on the peer's connection, then flush.
fn peer_write_all(c: &dyn Carrier, conn: u64, bytes: &[u8]) {
    write_all(c, conn, bytes).expect("the peer writes");
}

// ── THE FOLD ────────────────────────────────────────────────────────────────────────────────────

/// Bytes that exercise every value and outrun both the carrier's read chunk and the read buffer
/// below, so a stream is handed out across several reads.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Everything one carrier put on / took off the wire, and what it answered at the edges.
#[derive(Debug, PartialEq, Eq)]
struct Fold {
    key: &'static str,
    /// Dialled out: what the peer received, what the carrier read back and how that read ended,
    /// and the local port the dialled connection's arrival names.
    dial_peer_saw: Vec<u8>,
    dial_read_back: Vec<u8>,
    dial_end: Result<(), TransportError>,
    dial_local_port: Option<u16>,
    /// Listened: what the carrier read from the peer, what the peer received back and how that
    /// read ended, and whether the accepted connection's arrival named its far end as the accept
    /// did and the port the carrier listened on.
    accept_read: Vec<u8>,
    accept_peer_saw: Vec<u8>,
    accept_peer_end: Result<(), TransportError>,
    arrival_agrees: bool,
    /// What an unknown connection answers on write and close, a dial to a port nobody listens on
    /// once it settles, and a program destination.
    unknown_write: TransportError,
    unknown_close: Result<(), TransportError>,
    refused_dial: TransportError,
    program_dial: TransportError,
}

const SENT: (u8, usize) = (7, 40_000);
const REPLY: (u8, usize) = (91, 20_001);

/// THE SCRIPT, run identically against every carrier.
fn fold(c: &dyn Carrier) -> Fold {
    // ── dial the peer, send, read its reply to the clean end its close makes ──
    let far_carrier = peer();
    let (far_listener, authority) = far_carrier.listen("127.0.0.1:0").expect("the peer listens");
    let far = std::thread::spawn(move || {
        let (conn, _) =
            wait(|cx| far_carrier.poll_accept(far_listener, cx)).expect("the peer accepts");
        let got = read_exact(&*far_carrier, conn, SENT.1, 4096);
        peer_write_all(&*far_carrier, conn, &payload(REPLY.0, REPLY.1));
        let _ = wait(|cx| far_carrier.poll_close(conn, cx, CloseReason::Normal));
        got
    });
    let conn = c.dial(&Dest::Authority(&authority)).expect("dial");
    write_all(c, conn, &payload(SENT.0, SENT.1)).expect("write the request");
    let dial_local_port = c.arrival(conn).map(|a| a.local_port);
    let (dial_read_back, dial_end) = drain(c, conn, 1000);
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal)).expect("close");
    let dial_peer_saw = far.join().unwrap();

    // ── listen, take the peer's bytes, answer, close; the peer reads to the clean end ──
    let (listener, addr) = c.listen("127.0.0.1:0").expect("listen");
    let listen_port: u16 = addr
        .rsplit(':')
        .next()
        .and_then(|port| port.parse().ok())
        .expect("listen answers host:port");
    let near = std::thread::spawn(move || {
        let near = peer();
        let conn = near.dial(&Dest::Authority(&addr)).expect("the peer dials");
        wait(|cx| near.poll_flush(conn, cx)).expect("the peer's dial opens");
        peer_write_all(&*near, conn, &payload(SENT.0 ^ 0xff, SENT.1));
        drain(&*near, conn, 4096)
    });
    let (conn, peer_addr) = wait(|cx| c.poll_accept(listener, cx)).expect("accept");
    assert!(peer_addr.starts_with("127.0.0.1:"), "{peer_addr}");
    let arrival = c.arrival(conn).expect("an accepted connection's arrival");
    let arrival_agrees = arrival.peer == peer_addr && arrival.local_port == listen_port;
    let accept_read = read_exact(c, conn, SENT.1, 777);
    write_all(c, conn, &payload(REPLY.0 ^ 0xff, REPLY.1)).expect("write the answer");
    wait(|cx| c.poll_close(conn, cx, CloseReason::Normal)).expect("close");
    let (accept_peer_saw, accept_peer_end) = near.join().unwrap();

    // ── a dial nobody answers is refused when its opening settles ──
    let conn = c
        .dial(&Dest::Authority(NOBODY))
        .expect("dial answers at once");
    let refused_dial = wait(|cx| c.poll_flush(conn, cx)).unwrap_err();
    let _ = wait(|cx| c.poll_close(conn, cx, CloseReason::Normal));

    Fold {
        key: c.key(),
        dial_peer_saw,
        dial_read_back,
        dial_end,
        dial_local_port,
        accept_read,
        accept_peer_saw,
        accept_peer_end,
        arrival_agrees,
        unknown_write: wait(|cx| c.poll_write(u64::MAX, cx, b"x")).unwrap_err(),
        unknown_close: wait(|cx| c.poll_close(u64::MAX, cx, CloseReason::Normal)),
        refused_dial,
        program_dial: c
            .dial(&Dest::Program {
                program: "/bin/true",
                args: &[],
                env: &[],
            })
            .unwrap_err(),
    }
}

/// What the script sent, byte for byte, on each leg.
fn expected() -> Fold {
    Fold {
        key: linked::KEY,
        dial_peer_saw: payload(SENT.0, SENT.1),
        dial_read_back: payload(REPLY.0, REPLY.1),
        dial_end: Ok(()),
        dial_local_port: Some(0),
        accept_read: payload(SENT.0 ^ 0xff, SENT.1),
        accept_peer_saw: payload(REPLY.0 ^ 0xff, REPLY.1),
        accept_peer_end: Ok(()),
        arrival_agrees: true,
        unknown_write: TransportError::Closed,
        unknown_close: Ok(()),
        refused_dial: TransportError::Refused,
        program_dial: TransportError::AddressRefused,
    }
}

/// ONE ROW, WHICHEVER DOOR: every constant the carrier declares — read off its decl through the
/// linked door and through the dropped-in door — is the linked type's own row.
#[test]
fn a_linked_and_a_dropped_in_carrier_are_one_row() {
    let linked_row = admitted(&exports::TRANSPORT_DECL, "linked-wire");
    assert_eq!(*linked_row.row(), linked::ROW);
    assert_eq!(linked_row.role(), Role::Carrier);
    assert_eq!(linked_row.key(), "tcp");
    let dropped = dropped_in();
    assert_eq!(*dropped.row(), linked::ROW);
    assert_eq!(dropped.role(), Role::Carrier);
    // Two images, two decls: the dropped-in one is not the linked one read twice.
    assert_ne!(dropped.decl(), linked_row.decl());
}

/// THE WITNESS: the linked carrier, the carrier over its own decl, and the dropped-in carrier run
/// the script to the SAME record, and that record is the bytes the script put on the wire.
#[test]
fn both_doors_put_the_same_bytes_on_the_wire() {
    let linked_carrier = linked::carrier(&TransportSettings::default());
    let linked_fold = fold(&*linked_carrier);
    assert_eq!(
        linked_fold,
        expected(),
        "the linked carrier moves exactly the bytes it was given"
    );
    let decl_fold = fold(&*carrier_of(admitted(
        &exports::TRANSPORT_DECL,
        "linked-wire",
    )));
    assert_eq!(
        decl_fold, linked_fold,
        "the carrier over its own decl is the linked carrier"
    );
    assert_eq!(
        fold(&*carrier_of(dropped_in())),
        linked_fold,
        "a dropped-in carrier and the same carrier linked are observationally one carrier"
    );
}

/// Every constant the carrier declares reaches the host through its lowered decl, and the lowering
/// names every slot of the carrier role and none of the framer's.
#[test]
fn the_lowered_decl_carries_the_whole_row() {
    assert_eq!(
        *admitted(&exports::TRANSPORT_DECL, "linked-wire").row(),
        linked::ROW
    );
    let d = &exports::TRANSPORT_DECL;
    assert!(d.framer.is_null());
    let slots = real();
    assert!(
        slots.listen.is_some()
            && slots.poll_accept.is_some()
            && slots.dial.is_some()
            && slots.poll_read.is_some()
            && slots.poll_write.is_some()
            && slots.poll_flush.is_some()
            && slots.poll_close.is_some()
            && slots.arrival.is_some()
    );
}

// ── THE RED ARM ─────────────────────────────────────────────────────────────────────────────────

/// The carrier's real slot table.
fn real() -> &'static CarrierSlots {
    // SAFETY: tcp is a carrier, so its decl's carrier table is its `'static` table.
    unsafe { &*exports::TRANSPORT_DECL.carrier }
}

/// A `poll_write` slot that flips the first byte of every offer, then writes through the real slot.
extern "C-unwind" fn altering_write(
    state: *mut std::os::raw::c_void,
    conn: u64,
    token: u64,
    buf: *const u8,
    len: usize,
    out_written: *mut usize,
) -> RawWireOutcome {
    let real = real().poll_write.expect("the carrier writes");
    if buf.is_null() || len == 0 {
        return real(state, conn, token, buf, len, out_written);
    }
    // SAFETY: the host's live `len`-byte range for this call.
    let mut bytes = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    bytes[0] ^= 0x01;
    real(state, conn, token, bytes.as_ptr(), bytes.len(), out_written)
}

/// THE RED ARM, kept: a carrier whose `poll_write` alters one byte folds DIFFERENTLY, on exactly the
/// legs that write — so the equality the witness asserts is one a wrong carrier fails.
#[test]
fn a_divergent_carrier_is_seen_by_the_fold() {
    static SLOTS: OnceLock<CarrierSlots> = OnceLock::new();
    static ALTERED: OnceLock<TransportDecl> = OnceLock::new();
    let slots = SLOTS.get_or_init(|| CarrierSlots {
        poll_write: Some(altering_write),
        ..*real()
    });
    let altered = ALTERED.get_or_init(|| TransportDecl {
        carrier: slots,
        // SAFETY: a byte copy of the live decl; every pointer in it is `'static` image data.
        ..unsafe { core::ptr::read(&exports::TRANSPORT_DECL) }
    });
    let seen = fold(&*carrier_of(admitted(altered, "altered-wire")));
    let honest = expected();
    assert_ne!(
        seen, honest,
        "the fold must see a carrier that changed a byte"
    );
    assert_ne!(seen.dial_peer_saw, honest.dial_peer_saw);
    assert_ne!(seen.accept_peer_saw, honest.accept_peer_saw);
    // What the altered carrier only READ is untouched: the difference is where the bytes changed.
    assert_eq!(seen.accept_read, honest.accept_read);
    assert_eq!(seen.key, honest.key);
}
