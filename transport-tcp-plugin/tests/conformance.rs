// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE TRANSPORT, BOTH DOORS, ONE WIRE** — the `tcp` transport's linked + dropped-in conformance,
//! run against the busbar rev this repo pins (`.busbar-ref`) (#3, OWNER-LOCKED: a transport is
//! swappable, compiled in OR dropped in over the ABI; #30: it rides the HOT lane; #2 rule (1): one
//! contract, one loading path).
//!
//! The wire is held two ways at once: LINKED (the logic crate's `hot::TRANSPORT_DECL`, admitted
//! through the loader's `link_transport` — the row a busbar build that compiles the wire in folds)
//! and DROPPED IN (this crate's built cdylib, signed first-party into a fresh `plugins/` directory,
//! found by the loader's scan and opened by `open_transport`). Both rows run the loader's ONE
//! admission.
//!
//! THE FOLD. Each door then runs the same script against real sockets whose far end is a plain
//! `std::net` peer — dial it and exchange bytes, listen for it and exchange bytes — and records what
//! the transport declared and what crossed the wire in each direction. The two folds must be equal,
//! and each must equal the bytes the script sent: the bytes on the wire are identical whichever door
//! the transport came in by, and identical to what was asked for.
//!
//! The script drives the POLL slots (airlock minor 28) the way a host reactor does: register the
//! task's waker with a [`WakeToken`], poll with its id, park on `Pending` until the wire wakes it.
//!
//! THE RED ARM, kept: [`a_divergent_wire_is_seen_by_the_fold`] runs the fold over a decl whose
//! `poll_write` slot alters one byte and requires the fold to DIFFER — the comparison above is one
//! that can fail.
//!
//! Ported from busbar's `crates/plugin-loader/src/tests/transport_conformance_tests.rs`, where the
//! wire was proven before it moved to this repo; busbar still runs that test against the pinned wire.

use busbar_contract::abi::hot::transport::{
    RawWireOutcome, TransportDecl, WireOutcome, WirePollWriteFn, WireSettings,
};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::transport::{
    link_transport, wire_settings, BuiltTransport, DynTransport, WakeToken, WirePoll,
};
use std::future::Future;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

/// The version both doors state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

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

/// Poll one slot to its answer the way a host reactor does: register, poll with the token, park on
/// `Pending` until the wire wakes the token.
fn wait<T>(mut slot: impl FnMut(u64) -> WirePoll<T>) -> Result<T, WireOutcome> {
    let token = WakeToken::new();
    block_on(std::future::poll_fn(|cx| {
        token.register(cx.waker());
        slot(token.id())
    }))
}

/// Offer every one of `bytes` to `conn`, then flush.
fn write_all(built: &BuiltTransport<'_>, conn: u64, bytes: &[u8]) -> Result<(), WireOutcome> {
    let mut at = 0;
    while at < bytes.len() {
        at += wait(|t| built.poll_write(conn, t, &bytes[at..]))?;
    }
    wait(|t| built.poll_flush(conn, t))
}

/// The wire's decl, as the host's type: the address its `busbar_transport_decl` returns.
fn linked_decl() -> *const TransportDecl {
    core::ptr::addr_of!(busbar_transport_tcp_plugin::hot::TRANSPORT_DECL).cast::<TransportDecl>()
}

/// THE LINKED DOOR.
fn linked(display: &str) -> DynTransport {
    // SAFETY: the wire's decl is a `'static` image-owned decl laid out as `TransportDecl`
    // (`the_wire_restates_the_host_layout` pins every offset).
    unsafe { link_transport(linked_decl(), display) }.expect("the linked door admits the transport")
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
/// under a policy holding the release key, and opened by name.
fn dropped_in(tag: &str) -> DynTransport {
    let lib = cdylib();
    // One directory per call: tests run in parallel in this binary.
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let call = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "transport-tcp-conf-{tag}-{}-{call}",
        std::process::id()
    ));
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
    std::fs::write(dir.join(format!("{tag}.tar.gz")), tarball).expect("write the tarball");
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
        .unwrap_or_else(|e| panic!("the signed wire scans: {e:?}"));
    let wire = registry
        .open_transport("wire")
        .expect("the dropped-in door opens the transport");
    let _ = std::fs::remove_dir_all(&dir);
    wire
}

/// The deployment's settings, as the linked row takes them, handed to the decl's `build`.
fn settings() -> WireSettings {
    wire_settings(&busbar_contract::transport::TransportSettings::default())
}

/// Bytes that exercise every value and outrun both the wire's read chunk and the read buffer below,
/// so a frame is handed out across several reads.
fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Read `conn` to its clean end through `built`, in reads no longer than `chunk`.
fn drain(built: &BuiltTransport<'_>, conn: u64, chunk: usize) -> Vec<u8> {
    let mut all = Vec::new();
    let mut buf = vec![0_u8; chunk];
    loop {
        match wait(|t| built.poll_read(conn, t, &mut buf)) {
            Ok(0) => return all,
            Ok(n) => all.extend_from_slice(&buf[..n]),
            Err(e) => panic!("read failed mid-stream: {e:?}"),
        }
    }
}

/// Everything one door's transport declared and put on / took off the wire.
#[derive(Debug, PartialEq, Eq)]
struct Fold {
    key: String,
    composes_over: Vec<String>,
    /// Dialled out: what the peer received, and what the transport read back.
    dial_peer_saw: Vec<u8>,
    dial_read_back: Vec<u8>,
    /// Listened: what the transport read from the peer, and what the peer received back.
    accept_read: Vec<u8>,
    accept_peer_saw: Vec<u8>,
    /// What an unknown connection answers on write and close, and what a dial to a port nobody
    /// listens on answers once it settles.
    unknown_write: WireOutcome,
    unknown_close: WireOutcome,
    refused_dial: WireOutcome,
}

const SENT: (u8, usize) = (7, 40_000);
const REPLY: (u8, usize) = (91, 20_001);

/// THE SCRIPT, run identically against either door.
fn fold(t: &DynTransport) -> Fold {
    let built = t.build(None, &settings()).expect("the transport builds");

    // ── dial a plain peer, send, read its reply to the end ──
    let peer = TcpListener::bind("127.0.0.1:0").unwrap();
    let authority = peer.local_addr().unwrap().to_string();
    let far = std::thread::spawn(move || {
        let (mut s, _) = peer.accept().unwrap();
        let mut got = vec![0_u8; SENT.1];
        s.read_exact(&mut got).unwrap();
        s.write_all(&payload(REPLY.0, REPLY.1)).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        got
    });
    let conn = built.connect(&authority, None).expect("connect");
    write_all(&built, conn, &payload(SENT.0, SENT.1)).expect("write the request");
    let dial_read_back = drain(&built, conn, 1000);
    wait(|t| built.poll_close(conn, t)).expect("close");
    let dial_peer_saw = far.join().unwrap();

    // ── listen, take a plain peer's bytes to their end, answer, close ──
    let (listener, addr) = built.listen("127.0.0.1:0", None).expect("listen");
    let near = std::thread::spawn(move || {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&payload(SENT.0 ^ 0xff, SENT.1)).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut back = Vec::new();
        s.read_to_end(&mut back).unwrap();
        back
    });
    let (conn, peer_addr) = wait(|t| built.poll_accept(listener, t)).expect("accept");
    assert!(peer_addr.starts_with("127.0.0.1:"), "{peer_addr}");
    let accept_read = drain(&built, conn, 777);
    write_all(&built, conn, &payload(REPLY.0 ^ 0xff, REPLY.1)).expect("write the answer");
    wait(|t| built.poll_close(conn, t)).expect("close");
    let accept_peer_saw = near.join().unwrap();

    // ── a dial nobody answers is refused when its opening settles ──
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let nobody = closed.local_addr().unwrap().to_string();
    drop(closed);
    let conn = built
        .connect(&nobody, None)
        .expect("connect answers at once");
    let refused_dial = wait(|t| built.poll_flush(conn, t)).unwrap_err();
    built.close_now(conn);

    Fold {
        key: t.key().to_string(),
        composes_over: t.composes_over().iter().map(ToString::to_string).collect(),
        dial_peer_saw,
        dial_read_back,
        accept_read,
        accept_peer_saw,
        unknown_write: wait(|t| built.poll_write(u64::MAX, t, b"x")).unwrap_err(),
        unknown_close: wait(|t| built.poll_close(u64::MAX, t))
            .map_or_else(|e| e, |()| WireOutcome::Ok),
        refused_dial,
    }
}

/// What the script sent, byte for byte, on each leg.
fn expected(key: &str, composes_over: &[&str]) -> Fold {
    Fold {
        key: key.to_string(),
        composes_over: composes_over.iter().map(ToString::to_string).collect(),
        dial_peer_saw: payload(SENT.0, SENT.1),
        dial_read_back: payload(REPLY.0, REPLY.1),
        accept_read: payload(SENT.0 ^ 0xff, SENT.1),
        accept_peer_saw: payload(REPLY.0 ^ 0xff, REPLY.1),
        unknown_write: WireOutcome::Closed,
        unknown_close: WireOutcome::Ok,
        refused_dial: WireOutcome::Refused,
    }
}

/// ONE ROW, WHICHEVER DOOR: the key and the layers it composes over, as the linked row declares
/// them, are what both doors admit.
#[test]
fn a_linked_and_a_dropped_in_transport_are_one_row() {
    let linked = linked("linked-wire");
    // The decl's row IS the linked row the composition root folds: the same key, the same layers in
    // the same order.
    assert_eq!(linked.key(), busbar_transport_tcp_plugin::linked::KEY);
    assert_eq!(linked.key(), "tcp");
    assert_eq!(
        linked.composes_over(),
        busbar_transport_tcp_plugin::linked::COMPOSES_OVER
    );
    assert_eq!(
        linked.session(),
        busbar_transport_tcp_plugin::linked::SESSION
    );
    let dropped = dropped_in("transport-row");
    assert_eq!(dropped.key(), linked.key());
    assert_eq!(dropped.composes_over(), linked.composes_over());
    assert_eq!(dropped.session(), linked.session());
    // Two images, two decls: the dropped-in one is not the linked one read twice.
    assert_ne!(dropped.decl(), linked.decl());
}

/// THE WITNESS: both doors run the script and fold to the SAME record, and that record is the bytes
/// the script put on the wire — identical on the wire, whichever door.
#[test]
fn both_doors_put_the_same_bytes_on_the_wire() {
    let linked = linked("linked-wire");
    let linked_fold = fold(&linked);
    assert_eq!(
        linked_fold,
        expected(linked.key(), linked.composes_over()),
        "the linked transport moves exactly the bytes it was given"
    );
    let dropped = dropped_in("transport-fold");
    let dropped_fold = fold(&dropped);
    assert_eq!(
        dropped_fold, linked_fold,
        "a dropped-in transport and the same transport linked are observationally one transport"
    );
}

// ── THE RED ARM ─────────────────────────────────────────────────────────────────────────────────

/// The wire's real `poll_write`, for the altering slot below to forward to.
static REAL_WRITE: std::sync::OnceLock<WirePollWriteFn> = std::sync::OnceLock::new();

/// A `poll_write` slot that flips the first byte of every offer, then writes through the real slot.
extern "C-unwind" fn altering_write(
    state: *mut std::os::raw::c_void,
    conn: u64,
    token: u64,
    buf: *const u8,
    len: usize,
    out_written: *mut usize,
) -> RawWireOutcome {
    let real = REAL_WRITE.get().expect("the real write is recorded");
    if buf.is_null() || len == 0 {
        return real(state, conn, token, buf, len, out_written);
    }
    // SAFETY: the host's live `len`-byte range for this call.
    let mut bytes = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
    bytes[0] ^= 0x01;
    real(state, conn, token, bytes.as_ptr(), bytes.len(), out_written)
}

/// THE RED ARM, kept: a transport whose `poll_write` alters one byte folds DIFFERENTLY, on exactly
/// the legs that write — so the equality the witness asserts is one a wrong wire fails.
#[test]
fn a_divergent_wire_is_seen_by_the_fold() {
    // SAFETY: the wire's decl is live; its `poll_write` slot is set.
    let real = unsafe { (*linked_decl()).poll_write }.expect("the wire writes");
    let _ = REAL_WRITE.set(real);
    // SAFETY: the wire's decl is a live `TransportDecl`-layout value; copying its bytes out takes
    // nothing it owns (every pointer in it is to `'static` image data).
    let mut altered = unsafe { core::ptr::read(linked_decl()) };
    altered.poll_write = Some(altering_write);
    // SAFETY: `altered` is a copy of a valid decl that outlives `divergent` (both live to the end of
    // this test), and every range it borrows is the wire's `'static` data.
    let divergent = unsafe { link_transport(&altered, "altered-wire") }.unwrap();
    let honest = fold(&linked("linked-wire"));
    let seen = fold(&divergent);
    assert_ne!(seen, honest, "the fold must see a wire that changed a byte");
    assert_ne!(seen.dial_peer_saw, honest.dial_peer_saw);
    assert_ne!(seen.accept_peer_saw, honest.accept_peer_saw);
    // What the altered wire only READ is untouched: the difference is where the bytes changed.
    assert_eq!(seen.accept_read, honest.accept_read);
    assert_eq!(seen.key, honest.key);
}

/// A LAYOUT, NOT A CRATE (#84): the wire restates the published layout instead of linking the
/// crate that defines it, so this pins the restatement to the host's own at the pinned rev — every
/// offset, the size, the airlock constants, the handshake and every outcome byte. A drift here is a
/// misread there.
#[test]
fn the_wire_restates_the_host_layout() {
    use busbar_contract::abi::hot::transport::TransportDecl as Host;
    use busbar_transport_tcp_plugin::hot::layout::{self, TransportDecl as Restated};
    macro_rules! same {
        ($($f:ident),*) => {$(
            assert_eq!(
                core::mem::offset_of!(Restated, $f),
                core::mem::offset_of!(Host, $f),
                stringify!($f)
            );
        )*};
    }
    same!(
        abi,
        size,
        version,
        key,
        composes_over_ptr,
        composes_over_len,
        build,
        listen,
        accept,
        dial,
        read,
        write,
        close,
        session,
        init,
        connect,
        poll_accept,
        poll_read,
        poll_write,
        poll_flush,
        poll_close
    );
    assert_eq!(
        core::mem::size_of::<Restated>(),
        core::mem::size_of::<Host>()
    );
    assert_eq!(layout::ABI_MAGIC, busbar_contract::abi::ABI_MAGIC);
    assert_eq!(layout::ABI_MAJOR, busbar_contract::abi::ABI_MAJOR);
    assert!(
        (busbar_contract::abi::hot::TRANSPORT_DECL_MINOR..=busbar_contract::abi::ABI_MINOR)
            .contains(&layout::ABI_MINOR)
    );
    assert_eq!(
        layout::HANDSHAKE_VERSION,
        busbar_contract::abi::cold::TRANSPORT_VERSION
    );
    for (byte, outcome) in [
        (layout::outcome::OK, WireOutcome::Ok),
        (layout::outcome::REFUSED, WireOutcome::Refused),
        (layout::outcome::TIMEOUT, WireOutcome::Timeout),
        (layout::outcome::RESET, WireOutcome::Reset),
        (layout::outcome::CLOSED, WireOutcome::Closed),
        (
            layout::outcome::HANDSHAKE_FAILED,
            WireOutcome::HandshakeFailed,
        ),
        (
            layout::outcome::KEY_UNAVAILABLE,
            WireOutcome::KeyUnavailable,
        ),
        (
            layout::outcome::ADDRESS_REFUSED,
            WireOutcome::AddressRefused,
        ),
        (layout::outcome::BACKPRESSURE, WireOutcome::Backpressure),
        (layout::outcome::FRAMING, WireOutcome::Framing),
        (
            layout::outcome::HANDOFF_MISMATCH,
            WireOutcome::HandoffMismatch,
        ),
        (layout::outcome::FAULT, WireOutcome::Fault),
        (layout::outcome::PENDING, WireOutcome::Pending),
    ] {
        assert_eq!(RawWireOutcome(byte).outcome(), outcome);
    }
    assert_eq!(layout::NO_WAKER, busbar_contract::abi::hot::NO_WAKER);
    use busbar_contract::abi::hot::transport::WireWaker as HostWaker;
    use layout::WireWaker as RestatedWaker;
    for (restated, host) in [
        (
            core::mem::offset_of!(RestatedWaker, size),
            core::mem::offset_of!(HostWaker, size),
        ),
        (
            core::mem::offset_of!(RestatedWaker, version),
            core::mem::offset_of!(HostWaker, version),
        ),
        (
            core::mem::offset_of!(RestatedWaker, wake),
            core::mem::offset_of!(HostWaker, wake),
        ),
        (
            core::mem::size_of::<RestatedWaker>(),
            core::mem::size_of::<HostWaker>(),
        ),
    ] {
        assert_eq!(restated, host);
    }
    // Every slot this airlock retired is empty in the wire: it speaks the poll shape only.
    let d = &busbar_transport_tcp_plugin::hot::TRANSPORT_DECL;
    assert!(
        d.build.is_none()
            && d.accept.is_none()
            && d.dial.is_none()
            && d.read.is_none()
            && d.write.is_none()
            && d.close.is_none()
    );
}

/// THE HOT-LANE BUDGET (#30: < 1 µs per dispatch), measured on the dropped-in door: one poll-slot
/// crossing into the dlopened image and back — the sized slot read, the guarded indirect call, the
/// transport's own handle lookup — timed against the budget at the median and the 99th percentile.
/// Ignored by default (a timing claim belongs to an optimised build on a quiet machine); run with
/// `cargo test --release -p busbar-transport-tcp-plugin -- --ignored --nocapture`.
#[test]
#[ignore = "timing: run under --release on a quiet machine"]
fn a_hot_lane_crossing_is_under_a_microsecond() {
    let dropped = dropped_in("transport-perf");
    let built = dropped.build(None, &settings()).unwrap();
    let mut samples: Vec<u128> = (0..20_000)
        .map(|_| {
            let t = std::time::Instant::now();
            let _ = std::hint::black_box(built.poll_close(
                std::hint::black_box(u64::MAX),
                busbar_contract::abi::hot::NO_WAKER,
            ));
            t.elapsed().as_nanos()
        })
        .collect();
    samples.sort_unstable();
    let (p50, p99) = (
        samples[samples.len() / 2],
        samples[samples.len() * 99 / 100],
    );
    println!("transport HOT-lane crossing: p50 {p50} ns, p99 {p99} ns");
    assert!(p50 < 1_000 && p99 < 1_000, "p50 {p50} ns, p99 {p99} ns");
}
