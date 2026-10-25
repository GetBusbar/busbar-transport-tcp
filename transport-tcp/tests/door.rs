// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` carrier, driven through its own table the way the host drives it, over a SCRIPTED host
//! I/O table (`abi::host::io`): the one address an authority dials, the settling of a
//! connect, the frame bit on every read, the close, the arrival facts, and every framer op refused.
//! (An integration test, so the crate itself stays `#![forbid(unsafe_code)]`: driving a raw table is
//! the host's side, and needs it.) The real host's I/O is driven by busbar's conformance suite
//! (`tests/conformance.rs` of the plugin crate).

use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::sync::Mutex;

use busbar_contract::abi::host::io::{
    AddrIn, HandleIn, IoSlots, OpenIn as IoOpenIn, ReadIn as IoReadIn, ReadyIn, SLOTS,
};
use busbar_contract::abi::host::service::ServiceOut;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, Op, OutHead, Outcome, RawOutcome,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, OpenOut, RefreshIn, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::transport::check::{check_io, check_tail};
use busbar_contract::abi::transport::{
    slot, AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut,
    Destination, DialIn, EmitIn, EncodeIn, FinishIn, FramerOut, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, TransportTail,
    DEST_AUTHORITY, DEST_PROGRAM, READ_END_OF_FRAME, ROLE_CARRIER,
};
use busbar_transport_tcp::door;

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(t: &str) -> AbiStr {
    // SAFETY: `t` is the test's own text, live for every call it is passed to.
    unsafe { AbiStr::from_raw_parts(t.as_ptr(), t.len()) }
}

fn text(t: AbiStr) -> String {
    // SAFETY: the carrier's string, live for the call.
    String::from_utf8(unsafe { t.bytes() }.to_vec()).unwrap()
}

fn ops() -> &'static Ops {
    // SAFETY: `door()` answers the `'static` door of this crate.
    #[allow(unused_unsafe)]
    let d: *const Door = unsafe { door() };
    // SAFETY: the door answers a `'static` door whose table is this kind's `Ops`.
    unsafe { &*(*d).ops.cast::<Ops>() }
}

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I` leads with an `InHead`, `O` with an `OutHead` (the table's own structs).
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        (*ih).ticket = Ticket {
            slot: 1,
            generation: 1,
        };
        let oh = std::ptr::from_mut(o).cast::<OutHead>();
        (*oh).size = size_of::<O>() as u32;
    }
    // SAFETY: the slot is the door's own, called with the `in` and `out` built above.
    #[allow(unused_unsafe)]
    unsafe {
        (op.expect("every slot is filled"))(
            inst,
            std::ptr::from_ref(i).cast(),
            std::ptr::from_mut(o).cast(),
        )
    }
    .outcome()
}

// ── the scripted host ────────────────────────────────────────────────────────────────────────────

/// What the scripted host saw and what it answers.
#[derive(Default)]
struct Script {
    /// Every address `io.open` was asked for, in order.
    opened: Vec<String>,
    /// Addresses `io.open` refuses at once.
    refuse_open: Vec<String>,
    /// Handles whose connect `io.ready` fails.
    fail_ready: Vec<u64>,
    /// Handles closed.
    closed: Vec<u64>,
    /// What `io.read` answers next: `None` = PENDING.
    reads: Vec<Option<Vec<u8>>>,
}

/// A host handle is never the carrier's token: the scripted host numbers its handles from here.
const HANDLE_BASE: u64 = 100;
/// Listener and accepted-connection handles of the scripted host.
const LISTEN_BASE: u64 = 500;
const ACCEPT_BASE: u64 = 700;

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
/// One test at a time: they share the scripted host.
static ONE: Mutex<()> = Mutex::new(());

fn with<R>(f: impl FnOnce(&mut Script) -> R) -> R {
    f(SCRIPT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(Script::default))
}

fn answer(
    out: *mut ServiceOut,
    o: Outcome,
    value: u64,
    len: u64,
    error: &'static str,
) -> RawOutcome {
    // SAFETY: the carrier's `out`, live for the call.
    unsafe {
        (*out).outcome = RawOutcome::of(o);
        (*out).value = value;
        (*out).len = len;
        (*out).error = s(error);
    }
    RawOutcome::of(o)
}

extern "C" fn io_open(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the carrier's `in`.
    let i = unsafe { input.cast::<IoOpenIn>().read() };
    let addr = text(i.addr);
    with(|sc| {
        sc.opened.push(addr.clone());
        if sc.refuse_open.contains(&addr) {
            answer(out, Outcome::Refused, 0, 0, "not admitted for this dial")
        } else {
            answer(
                out,
                Outcome::Ready,
                HANDLE_BASE + sc.opened.len() as u64,
                0,
                "",
            )
        }
    })
}

extern "C" fn io_ready(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the carrier's `in`.
    let i = unsafe { input.cast::<ReadyIn>().read() };
    if with(|sc| sc.fail_ready.contains(&i.handle)) {
        answer(
            out,
            Outcome::Failed,
            0,
            0,
            "Connection refused (os error 111)",
        )
    } else {
        answer(out, Outcome::Ready, 0, 0, "")
    }
}

extern "C" fn io_read(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the carrier's `in`.
    let i = unsafe { input.cast::<IoReadIn>().read() };
    match with(|sc| sc.reads.remove(0)) {
        None => answer(out, Outcome::Pending, 0, 0, ""),
        Some(bytes) => {
            // SAFETY: the host buffer the carrier passed through, `cap` bytes.
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.buf, bytes.len()) };
            answer(out, Outcome::Ready, 0, bytes.len() as u64, "")
        }
    }
}

extern "C" fn io_close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the carrier's `in`.
    let i = unsafe { input.cast::<HandleIn>().read() };
    with(|sc| sc.closed.push(i.handle));
    answer(out, Outcome::Ready, 0, 0, "")
}

extern "C" fn io_listen(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, LISTEN_BASE + 1, 0, "")
}

extern "C" fn io_accept(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, ACCEPT_BASE, 0, "")
}

extern "C" fn io_ends(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the carrier's `in`.
    let i = unsafe { input.cast::<AddrIn>().read() };
    let peer = b"127.0.0.1:5555";
    // SAFETY: the address buffer, at least `MAX_ADDR`.
    unsafe { std::ptr::copy_nonoverlapping(peer.as_ptr(), i.addr_buf, peer.len()) };
    answer(out, Outcome::Ready, 8080, peer.len() as u64, "")
}

static IO: IoSlots = IoSlots {
    size: size_of::<IoSlots>() as u32,
    slots: SLOTS,
    open: Some(io_open),
    listen: Some(io_listen),
    accept: Some(io_accept),
    read: Some(io_read),
    write: None,
    ready: Some(io_ready),
    shut: None,
    close: Some(io_close),
    spawn: None,
    ends: Some(io_ends),
};

/// An open instance handed the scripted host, and the script reset.
fn open(script: Script) -> (*mut c_void, Box<HostTables>) {
    *SCRIPT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(script);
    let tables = Box::new(HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: std::ptr::null(),
        services: std::ptr::null(),
        io: &IO,
    });
    let mut i: OpenIn = z();
    i.host = &*tables;
    let mut o: OpenOut = z();
    let r = call(
        ops().head.open,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::OPEN,
    );
    assert_eq!(r, Outcome::Ready);
    (o.instance, tables)
}

fn dial(inst: *mut c_void, authority: &str) -> (Outcome, u64) {
    let (r, conn, _) = dial_said(inst, authority);
    (r, conn)
}

/// A dial, and the words its out head carries.
fn dial_said(inst: *mut c_void, authority: &str) -> (Outcome, u64, String) {
    let mut dest: Destination = z();
    dest.kind = DEST_AUTHORITY;
    dest.authority = s(authority);
    let mut i: DialIn = z();
    i.dest = &dest;
    let mut o: ConnOut = z();
    let r = call(ops().dial, inst, &mut i, &mut o, slot::DIAL);
    (r, o.conn, text(o.head.error))
}

fn flush(inst: *mut c_void, conn: u64) -> Outcome {
    let mut i: ConnIn = z();
    i.conn = conn;
    let mut o: OutHead = z();
    call(ops().flush, inst, &mut i, &mut o, slot::FLUSH)
}

// ── the tests ────────────────────────────────────────────────────────────────────────────────────

#[test]
fn the_tail_is_a_carrier_composing_over_nothing() {
    // SAFETY: the door's Statement is this crate's `'static` one, and its kind tail a `'static`
    // `TransportTail`.
    let statement = unsafe { &*(*door()).statement };
    let tail = unsafe { &*statement.kind_tail().cast::<TransportTail>() };
    assert_eq!(tail.role, ROLE_CARRIER);
    assert_eq!(tail.composes_over_len(), 0);
    assert_eq!(check_tail(tail), Ok(()));
}

#[test]
fn a_dial_opens_its_address_and_settles_under_flush() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (inst, _t) = open(Script::default());
    let (r, conn) = dial(inst, "127.0.0.1:80");
    assert_eq!(r, Outcome::Ready);
    assert_eq!(flush(inst, conn), Outcome::Ready);
    with(|sc| assert_eq!(sc.opened, ["127.0.0.1:80"]));
    // RED: a name is refused before the host is asked to open anything.
    let (r, _, said) = dial_said(inst, "example.test:80");
    assert_eq!(r, Outcome::Refused);
    assert_eq!(
        said,
        "dial: the authority is not an IP literal or unix: path; the carrier never resolves a name"
    );
    with(|sc| assert_eq!(sc.opened.len(), 1));
}

#[test]
fn a_refused_connect_answers_the_systems_words_and_closes_its_handle() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (inst, _t) = open(Script {
        fail_ready: vec![HANDLE_BASE + 1],
        ..Script::default()
    });
    let (r, conn) = dial(inst, "127.0.0.1:81");
    assert_eq!(r, Outcome::Ready);
    let mut i: ConnIn = z();
    i.conn = conn;
    let mut o: OutHead = z();
    assert_eq!(
        call(ops().flush, inst, &mut i, &mut o, slot::FLUSH),
        Outcome::Failed
    );
    assert_eq!(text(o.error), "flush: Connection refused (os error 111)");
    with(|sc| assert_eq!(sc.closed, [HANDLE_BASE + 1]));
    // The refused dial was forgotten: shut closes nothing twice.
    let mut si: ShutIn = z();
    si.conn = conn;
    let mut so: OutHead = z();
    assert_eq!(
        call(ops().shut, inst, &mut si, &mut so, slot::SHUT),
        Outcome::Ready
    );
    with(|sc| assert_eq!(sc.closed, [HANDLE_BASE + 1]));
}

#[test]
fn a_dial_the_host_does_not_admit_is_refused_in_the_hosts_words() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (inst, _t) = open(Script {
        refuse_open: vec!["127.0.0.1:84".to_owned()],
        ..Script::default()
    });
    let (r, _, said) = dial_said(inst, "127.0.0.1:84");
    assert_eq!(r, Outcome::Refused);
    assert_eq!(said, "dial: not admitted for this dial");
    // No connection was kept.
    let mut i: ConnIn = z();
    i.conn = 1;
    let mut o: OutHead = z();
    assert_eq!(
        call(ops().flush, inst, &mut i, &mut o, slot::FLUSH),
        Outcome::Failed
    );
    assert_eq!(text(o.error), "flush: no such connection");
    with(|sc| assert!(sc.closed.is_empty()));
}

#[test]
fn a_program_is_not_this_carriers_destination() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (inst, _t) = open(Script::default());
    let mut dest: Destination = z();
    dest.kind = DEST_PROGRAM;
    dest.program = s("/bin/cat");
    let mut i: DialIn = z();
    i.dest = &dest;
    let mut o: ConnOut = z();
    assert_eq!(
        call(ops().dial, inst, &mut i, &mut o, slot::DIAL),
        Outcome::Refused
    );
    assert_eq!(
        text(o.head.error),
        "dial: a tcp carrier reaches an authority, never a program"
    );
    with(|sc| assert!(sc.opened.is_empty()));
}

#[test]
fn every_read_is_a_frame_of_the_stream_a_pending_one_moves_nothing_and_shut_closes() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (inst, _t) = open(Script {
        reads: vec![None, Some(b"abc".to_vec()), Some(Vec::new())],
        ..Script::default()
    });
    let (_, conn) = dial(inst, "127.0.0.1:82");
    let mut buf = [0_u8; 16];
    let mut read = || {
        let mut i: ReadIn = z();
        i.conn = conn;
        i.buf = buf.as_mut_ptr();
        i.cap = buf.len();
        let mut o: IoOut = z();
        let r = call(ops().read, inst, &mut i, &mut o, slot::READ);
        (r, o.len, o.flags)
    };
    assert_eq!(read().0, Outcome::Pending);
    let (r, len, flags) = read();
    assert_eq!((r, len, flags), (Outcome::Ready, 3, READ_END_OF_FRAME));
    // The clean end: no bytes, no frame.
    assert_eq!(read(), (Outcome::Ready, 0, 0));
    assert_eq!(&buf[..3], b"abc");
    let mut o: IoOut = z();
    o.len = 3;
    o.flags = READ_END_OF_FRAME;
    assert_eq!(check_io(&o, 16), Ok(()));

    let mut i: ShutIn = z();
    i.conn = conn;
    let mut o: OutHead = z();
    assert_eq!(
        call(ops().shut, inst, &mut i, &mut o, slot::SHUT),
        Outcome::Ready
    );
    with(|sc| assert_eq!(sc.closed, [HANDLE_BASE + 1]));
    // Idempotent: an unknown connection is already closed.
    assert_eq!(
        call(ops().shut, inst, &mut i, &mut o, slot::SHUT),
        Outcome::Ready
    );
}

#[test]
fn arrival_answers_the_far_end_and_the_local_port() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (inst, _t) = open(Script::default());
    let (_, conn) = dial(inst, "127.0.0.1:83");
    let mut peer = [0_u8; 64];
    let mut i: ArrivalIn = z();
    i.conn = conn;
    i.peer_buf = peer.as_mut_ptr();
    i.peer_cap = peer.len();
    let mut o: ArrivalOut = z();
    assert_eq!(
        call(ops().arrival, inst, &mut i, &mut o, slot::ARRIVAL),
        Outcome::Ready
    );
    assert_eq!(o.local_port, 8080);
    assert_eq!(&peer[..o.peer_written as usize], b"127.0.0.1:5555");
    // A short peer buffer is the short path: FAILED, the size it needs, nothing written.
    i.peer_cap = 4;
    let mut o: ArrivalOut = z();
    assert_eq!(
        call(ops().arrival, inst, &mut i, &mut o, slot::ARRIVAL),
        Outcome::Failed
    );
    assert_eq!((o.peer_written, o.peer_needed), (0, 14));
}

#[test]
fn every_framer_op_is_refused() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (inst, _t) = open(Script::default());
    let mut i: LocateIn = z();
    let mut o: LocateOut = z();
    assert_eq!(
        call(ops().locate, inst, &mut i, &mut o, slot::LOCATE),
        Outcome::Refused,
        "locate"
    );
    assert_eq!(
        text(o.head.error),
        "locate: the tcp carrier does not serve this op"
    );
    let mut i: BeginIn = z();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().begin, inst, &mut i, &mut o, slot::BEGIN),
        Outcome::Refused,
        "begin"
    );
    assert_eq!(
        text(o.head.error),
        "begin: the tcp carrier does not serve this op"
    );
    let mut i: IngestIn = z();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().ingest, inst, &mut i, &mut o, slot::INGEST),
        Outcome::Refused,
        "ingest"
    );
    assert_eq!(
        text(o.head.error),
        "ingest: the tcp carrier does not serve this op"
    );
    let mut i: EmitIn = z();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().emit, inst, &mut i, &mut o, slot::EMIT),
        Outcome::Refused,
        "emit"
    );
    assert_eq!(
        text(o.head.error),
        "emit: the tcp carrier does not serve this op"
    );
    let mut i: EncodeIn = z();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().encode, inst, &mut i, &mut o, slot::ENCODE),
        Outcome::Refused,
        "encode"
    );
    assert_eq!(
        text(o.head.error),
        "encode: the tcp carrier does not serve this op"
    );
    let mut i: RefuseIn = z();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().refuse, inst, &mut i, &mut o, slot::REFUSE),
        Outcome::Refused,
        "refuse"
    );
    assert_eq!(
        text(o.head.error),
        "refuse: the tcp carrier does not serve this op"
    );
    let mut i: FinishIn = z();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().finish, inst, &mut i, &mut o, slot::FINISH),
        Outcome::Refused,
        "finish"
    );
    assert_eq!(
        text(o.head.error),
        "finish: the tcp carrier does not serve this op"
    );
    let mut i: FramingIn = z();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().detach, inst, &mut i, &mut o, slot::DETACH),
        Outcome::Refused,
        "detach"
    );
    assert_eq!(
        text(o.head.error),
        "detach: the tcp carrier does not serve this op"
    );
    let mut i: AdoptIn = z();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().adopt, inst, &mut i, &mut o, slot::ADOPT),
        Outcome::Refused,
        "adopt"
    );
    assert_eq!(
        text(o.head.error),
        "adopt: the tcp carrier does not serve this op"
    );
    let mut i: FramingIn = z();
    let mut o: FramerOut = z();
    assert_eq!(
        call(ops().timer, inst, &mut i, &mut o, slot::TIMER),
        Outcome::Refused,
        "timer"
    );
    assert_eq!(
        text(o.head.error),
        "timer: the tcp carrier does not serve this op"
    );
}

// ── settings, close ──────────────────────────────────────────────────────────────────────────────

/// `validate` over `settings`: the outcome and the words it names.
fn validate(settings: &'static [u8]) -> (Outcome, String) {
    let mut err = [0_u8; 256];
    let mut i: ValidateIn = z();
    i.settings = Blob::of(settings);
    i.err_buf = err.as_mut_ptr();
    i.err_cap = err.len();
    let mut o: OutHead = z();
    let r = call(
        ops().head.validate,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::VALIDATE,
    );
    (r, text(o.error))
}

fn refresh(inst: *mut c_void, settings: &'static [u8]) -> (Outcome, String) {
    let mut i: RefreshIn = z();
    i.settings = Blob::of(settings);
    let mut o: OutHead = z();
    let r = call(ops().head.refresh, inst, &mut i, &mut o, life::REFRESH);
    (r, text(o.error))
}

#[test]
fn tcp_declares_no_settings_so_every_key_is_refused_and_a_non_object_fails() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(validate(b"").0, Outcome::Ready);
    assert_eq!(validate(b"{}").0, Outcome::Ready);
    assert_eq!(
        validate(b"{\"nodelay\":true}"),
        (
            Outcome::Failed,
            "settings: nodelay is not a setting this transport reads".to_owned()
        )
    );
    assert_eq!(
        validate(b"[1]"),
        (
            Outcome::Failed,
            "settings: must be a JSON object".to_owned()
        )
    );
    let (inst, _t) = open(Script::default());
    assert_eq!(refresh(inst, b"{}").0, Outcome::Ready);
    assert_eq!(
        refresh(inst, b"{\"x\":1}"),
        (
            Outcome::Failed,
            "settings: x is not a setting this transport reads".to_owned()
        )
    );
    assert_eq!(
        refresh(inst, b"7"),
        (
            Outcome::Failed,
            "settings: must be a JSON object".to_owned()
        )
    );
}

#[test]
fn close_closes_every_held_listener_and_connection_then_answers_ready() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (inst, _t) = open(Script::default());
    dial(inst, "127.0.0.1:90");
    let (_, shut_conn) = dial(inst, "127.0.0.1:91");
    let mut so: OutHead = z();
    let mut si: ShutIn = z();
    si.conn = shut_conn;
    call(ops().shut, inst, &mut si, &mut so, slot::SHUT);
    let mut peer = [0_u8; 64];
    let mut addr = [0_u8; 64];
    let mut li: ListenIn = z();
    li.bind = s("127.0.0.1:0");
    li.addr_buf = addr.as_mut_ptr();
    li.addr_cap = addr.len();
    let mut lo: ListenOut = z();
    assert_eq!(
        call(ops().listen, inst, &mut li, &mut lo, slot::LISTEN),
        Outcome::Ready
    );
    let mut ai: AcceptIn = z();
    ai.listener = lo.listener;
    ai.peer_buf = peer.as_mut_ptr();
    ai.peer_cap = peer.len();
    let mut ao: AcceptOut = z();
    assert_eq!(
        call(ops().accept, inst, &mut ai, &mut ao, slot::ACCEPT),
        Outcome::Ready
    );
    with(|sc| assert_eq!(sc.closed, [HANDLE_BASE + 2]));

    let mut ci: InHead = z();
    let mut co: OutHead = z();
    assert_eq!(
        call(ops().head.close, inst, &mut ci, &mut co, life::CLOSE),
        Outcome::Ready
    );
    with(|sc| {
        let mut closed = sc.closed.clone();
        closed.sort_unstable();
        assert_eq!(
            closed,
            [
                HANDLE_BASE + 1,
                HANDLE_BASE + 2,
                LISTEN_BASE + 1,
                ACCEPT_BASE
            ],
            "every held handle, each once"
        );
    });
}

#[test]
fn an_op_without_host_io_fails_in_words_that_name_the_op() {
    let _one = ONE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let tables = Box::new(HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: std::ptr::null(),
        services: std::ptr::null(),
        io: std::ptr::null(),
    });
    let mut i: OpenIn = z();
    i.host = &*tables;
    let mut o: OpenOut = z();
    let r = call(
        ops().head.open,
        std::ptr::null_mut(),
        &mut i,
        &mut o,
        life::OPEN,
    );
    assert_eq!(r, Outcome::Ready);
    let mut ci: ConnIn = z();
    ci.conn = 1;
    let mut co: OutHead = z();
    assert_eq!(
        call(ops().flush, o.instance, &mut ci, &mut co, slot::FLUSH),
        Outcome::Failed
    );
    assert_eq!(text(co.error), "flush: the host lent this carrier no I/O");
}
