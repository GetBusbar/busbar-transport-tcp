// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tcp` DOOR: this transport as an IDENTITY FRAMER on the transport kind's table
//! (`busbar_contract::abi::transport`), compiled in or dropped in through the one door. Every slot
//! is a [`SafeSlot`] over the SDK's generic lifecycle (`life(Framings)`): no `unsafe` in this crate.
//!
//! The socket is the host's (`BUSBAR-1.6.0.md` THE DESIGN, §5): the host dials, accepts, reads
//! and writes it on the calling worker's reactor. This framer composes over nothing, so it frames
//! directly over that socket, and the framing it does is none: a byte stream stays a byte stream.
//!
//! * `ingest` answers the bytes the far side sent as ONE frame on stream `0`, in as many pieces as
//!   the host's sink holds (the last carries `PIECE_END_OF_FRAME`); the far side's end is
//!   `YIELD_ENDED`, since no frame follows on the connection.
//! * `emit` and `refuse` answer the bytes they are handed as the wire bytes, unchanged.
//! * `encode` renders an envelope as its body alone: a byte stream has no head, so an envelope with
//!   fields is refused.
//! * `detach` hands back every byte ingested and not yet answered; `adopt` takes such bytes and
//!   answers them as the connection's first frame.
//! * `locate` reads `host:port` (or `tcp://host:port`) as the authority to dial; nothing is offered
//!   to the far end and no connection security is asked for.
//! * every carrier op (`listen` .. `arrival`) is REFUSED: a framer is not a carrier.
//!
//! No op pends, no op asks for a deadline, and a full sink is back-pressure (`YIELD_MORE`): the host
//! calls again, with no new bytes, once it has drained what it was given.

use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::sdk::{HostBuf, Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, TransportTail,
    WriteIn, CANCEL_NOTHING_MOVED, FRAMING_STREAM, PIECE_END_OF_FRAME, ROLE_FRAMER,
    UNIT0_FIRST_BYTES, YIELD_ENDED, YIELD_MORE,
};
use busbar_contract::transport::registry::facts as tfacts;
use busbar_contract::SelectorForm;

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The claim this entry answers for.
pub const KEY: &str = "tcp";

/// The selector forms a `tcp` claim reads: the port it arrived on.
const SELECTOR_FORMS: &[SelectorForm] = &[SelectorForm::Port];
const SELECTOR_CODES: [u8; SELECTOR_FORMS.len()] = form_codes(SELECTOR_FORMS);

const FACTS: &[AbiStr] = &[abi_str(tfacts::PEER)];

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The schemes `tcp` claims, by name: the Statement's `claims`, the one place they are stated.
const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

/// Each claimed scheme's row, by index into [`CLAIM_NAMES`].
const CLAIMS: &[Claim] = &[Claim {
    selector_forms: AbiStr {
        ptr: SELECTOR_CODES.as_ptr(),
        len: SELECTOR_CODES.len(),
    },
    egress_selector_forms: abi_str(""),
    facts: FACTS.as_ptr(),
    facts_len: FACTS.len(),
    status_namespace: NONE,
    session: 1,
    session_bound: 0,
    unit0_trigger: UNIT0_FIRST_BYTES,
    status_at: 0,
    _reserved: 0,
}];

/// The transport kind's tail: a framer over the host's socket, composing over nothing.
const TAIL: TransportTail = TransportTail {
    head: KindTailHead {
        size: std::mem::size_of::<TransportTail>() as u32,
        _reserved: 0,
    },
    role: ROLE_FRAMER,
    framing: FRAMING_STREAM,
    facts: 0,
    handshake_max_steps: 0,
    composes_over: std::ptr::null(),
    composes_over_len: 0,
    claim_rows: CLAIMS.as_ptr(),
    claim_rows_len: CLAIMS.len(),
    upgrades_to: std::ptr::null(),
    upgrades_to_len: 0,
    handoff_from: NONE,
    handoff_to: NONE,
    handoff_binding_fact: NONE,
    handshake_frame_kind: NONE,
    status_rows: std::ptr::null(),
    status_rows_len: 0,
    settings: std::ptr::null(),
    settings_len: 0,
};

/// The door's Statement: the `tcp` identity framer.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};

// ── the instance ─────────────────────────────────────────────────────────────────────────────────

/// The framings one instance holds: the state the SDK's lifecycle opens and closes.
pub struct Framings {
    framings: Mutex<HashMap<u64, Framing>>,
    next: AtomicU64,
}

/// What every slot reads: the SDK's lifecycle state over [`Framings`].
type State = Held<Framings>;

impl Life for Framings {
    /// No framer op pends, so a cancel finds nothing in flight.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    /// This framer reads no setting.
    fn validate(_: &[u8]) -> Result<(), Refusal> {
        Ok(())
    }

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

impl Framings {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Framing>> {
        self.framings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Install `f` under a fresh framing token, and answer the token.
    fn begin(&self, f: Framing) -> u64 {
        let token = self.next.fetch_add(1, Ordering::Relaxed);
        self.lock().insert(token, f);
        token
    }
}

/// One connection's framing: the bytes owed to each side and not yet answered.
#[derive(Default)]
struct Framing {
    /// Bytes the far side sent, not yet answered as frame bytes.
    inbound: VecDeque<u8>,
    /// The far side ended.
    ended: bool,
    /// Bytes owed to the far side, not yet answered as wire bytes.
    outbound: VecDeque<u8>,
}

/// The open instance, or the refusal a call on none earns.
fn framings<'a>(i: &Instance<'a, State>) -> Result<&'a Framings, Refusal> {
    i.get()
        .map(Held::life)
        .ok_or_else(|| Refusal::failed("no open instance"))
}

// ── the carrier ops: refused ─────────────────────────────────────────────────────────────────────

/// A carrier op: REFUSED. The socket is the host's, so this framer carries nothing.
pub struct NotACarrier<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> SafeSlot for NotACarrier<I, O> {
    type In = I;
    type Out = O;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

// ── the framer ───────────────────────────────────────────────────────────────────────────────────

/// `locate`: `host:port` or `tcp://host:port` is the authority; no name, no connection security.
pub struct Locate;
impl SafeSlot for Locate {
    type In = LocateIn;
    type Out = LocateOut;
    type State = State;
    fn call(_: Instance<'_, State>, i: Lent<'_, LocateIn>, mut o: Out<'_, LocateOut>) -> Outcome {
        let target = i.field(|x| &x.target).bytes();
        let authority = target.strip_prefix(b"tcp://").unwrap_or(target);
        if authority.is_empty() || authority.contains(&b'/') {
            return o.fail(Refusal::failed("locate: the target is not host:port"));
        }
        o.set(|o| &o.secure, 0);
        o.set(|o| &o.has_name, 0);
        let mut buf = i.authority_buf();
        if authority.len() > buf.cap() {
            o.set(|o| &o.authority_needed, authority.len() as u64);
            return o.fail(Refusal::failed("locate: the authority buffer is too small"));
        }
        buf.extend(authority);
        o.set(|o| &o.authority_written, authority.len() as u64);
        Outcome::Ready
    }
}

/// `begin`: either side; nothing is owed to the far side first.
pub struct Begin;
impl SafeSlot for Begin {
    type In = BeginIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, _: Lent<'_, BeginIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        let token = s.begin(Framing::default());
        o.set(|o| &o.framing, token);
        Outcome::Ready
    }
}

/// `adopt`: the bytes another framer left unconsumed are this connection's first frame.
pub struct Adopt;
impl SafeSlot for Adopt {
    type In = AdoptIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, AdoptIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        let mut f = Framing::default();
        f.inbound.extend(i.leftover());
        f.answer(i.field(|x| &x.sink), &mut o);
        let token = s.begin(f);
        o.set(|o| &o.framing, token);
        Outcome::Ready
    }
}

/// Run `op` on the framing `token` names and answer what it owes into `sink`.
fn with(
    inst: &Instance<'_, State>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    op: impl FnOnce(&mut Framing),
) -> Outcome {
    let s = match framings(inst) {
        Ok(s) => s,
        Err(r) => return o.fail(r),
    };
    let mut framings = s.lock();
    let Some(f) = framings.get_mut(&token) else {
        return o.fail(Refusal::failed("no such framing"));
    };
    op(f);
    f.answer(sink, o);
    Outcome::Ready
}

/// `ingest`: the bytes are one frame on stream `0`; the far side's end ends the connection.
pub struct Ingest;
impl SafeSlot for Ingest {
    type In = IngestIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, IngestIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let bytes = i.bytes();
        with(&inst, i.framing, i.field(|x| &x.sink), &mut o, |f| {
            f.inbound.extend(bytes);
            f.ended |= i.end != 0;
        })
    }
}

/// `emit`: the bytes are the wire bytes.
pub struct Emit;
impl SafeSlot for Emit {
    type In = EmitIn;
    type Out = FramerOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, EmitIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        let bytes = i.bytes();
        with(&inst, i.framing, i.field(|x| &x.sink), &mut o, |f| {
            f.outbound.extend(bytes);
        })
    }
}

/// `refuse`: the refusal's bytes are the wire bytes.
pub struct Refuse;
impl SafeSlot for Refuse {
    type In = RefuseIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, RefuseIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let bytes = i.bytes();
        with(&inst, i.framing, i.field(|x| &x.sink), &mut o, |f| {
            f.outbound.extend(bytes);
        })
    }
}

/// `timer`: this framer asks for no deadline; a call answers what is still owed.
pub struct Timer;
impl SafeSlot for Timer {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        with(&inst, i.framing, i.field(|x| &x.sink), &mut o, |_| {})
    }
}

/// `finish`: the framing is forgotten; no frame follows.
pub struct Finish;
impl SafeSlot for Finish {
    type In = FinishIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FinishIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        if s.lock().remove(&i.framing).is_none() {
            return o.fail(Refusal::failed("finish: no such framing"));
        }
        o.set(|o| &o.yielded.flags, YIELD_ENDED);
        Outcome::Ready
    }
}

/// `detach`: every byte ingested and not yet answered, into `frame`, and the framing is forgotten.
/// A sink too small for them answers `YIELD_MORE` and keeps the framing until the rest is taken.
pub struct Detach;
impl SafeSlot for Detach {
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let s = match framings(&inst) {
            Ok(s) => s,
            Err(r) => return o.fail(r),
        };
        let mut framings = s.lock();
        let Some(f) = framings.get_mut(&i.framing) else {
            return o.fail(Refusal::failed("detach: no such framing"));
        };
        let n = drain_into(&mut f.inbound, &mut i.field(|x| &x.sink).frame());
        o.set(|o| &o.yielded.frame_len, n as u64);
        if f.inbound.is_empty() {
            framings.remove(&i.framing);
            o.set(|o| &o.yielded.flags, YIELD_ENDED);
        } else {
            o.set(|o| &o.yielded.flags, YIELD_MORE);
        }
        Outcome::Ready
    }
}

/// `encode`: a byte stream has no head, so the envelope is its body; fields are refused.
pub struct Encode;
impl SafeSlot for Encode {
    type In = EncodeIn;
    type Out = FramerOut;
    type State = State;
    fn call(_: Instance<'_, State>, i: Lent<'_, EncodeIn>, mut o: Out<'_, FramerOut>) -> Outcome {
        if i.fields_len != 0 {
            return o.fail(Refusal::failed("encode: a byte stream carries no fields"));
        }
        let body = i.body();
        let mut wire = i.field(|x| &x.sink).wire();
        if body.len() > wire.cap() {
            // `encode` renders a whole message at once: the host gives it room for the body.
            return o.fail(Refusal::failed(
                "encode: the wire buffer is smaller than the body",
            ));
        }
        wire.extend(body);
        o.set(|o| &o.yielded.wire_len, body.len() as u64);
        Outcome::Ready
    }
}

/// Move as many bytes off the front of `from` as `to` has room for; answers how many.
fn drain_into(from: &mut VecDeque<u8>, to: &mut HostBuf<'_, u8>) -> usize {
    let (a, b) = from.as_slices();
    let mut n = to.stream(a);
    if n == a.len() {
        n += to.stream(b);
    }
    from.drain(..n);
    n
}

impl Framing {
    /// Answer into `sink` what this framing owes: wire bytes, then the inbound frame as one piece
    /// (the one that drains it ends the frame), then the connection's end once nothing is left.
    fn answer(&mut self, sink: Lent<'_, FramerSink>, o: &mut Out<'_, FramerOut>) {
        let wire = drain_into(&mut self.outbound, &mut sink.wire());
        o.set(|o| &o.yielded.wire_len, wire as u64);
        let mut pieces = sink.pieces();
        let mut frame = sink.frame();
        if !self.inbound.is_empty() && pieces.cap() > 0 && frame.cap() > 0 {
            let n = drain_into(&mut self.inbound, &mut frame);
            let flags = if self.inbound.is_empty() {
                PIECE_END_OF_FRAME
            } else {
                0
            };
            pieces.push(FramePiece {
                stream: 0,
                offset: 0,
                len: n as u64,
                code: 0,
                status_class: 0,
                flags,
                _reserved: 0,
                retry_after_secs: 0,
            });
            o.set(|o| &o.yielded.frame_len, n as u64);
            o.set(|o| &o.yielded.pieces_len, 1);
        }
        let owed = !self.outbound.is_empty() || !self.inbound.is_empty();
        let flags = if owed {
            YIELD_MORE
        } else if self.ended {
            YIELD_ENDED
        } else {
            0
        };
        o.set(|o| &o.yielded.flags, flags);
    }
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: life(Framings),
    kind_ops: {
        listen: Safe<NotACarrier<ListenIn, ListenOut>>,
        accept: Safe<NotACarrier<AcceptIn, AcceptOut>>,
        dial: Safe<NotACarrier<DialIn, ConnOut>>,
        read: Safe<NotACarrier<ReadIn, IoOut>>,
        write: Safe<NotACarrier<WriteIn, IoOut>>,
        flush: Safe<NotACarrier<ConnIn, OutHead>>,
        shut: Safe<NotACarrier<ShutIn, OutHead>>,
        arrival: Safe<NotACarrier<ArrivalIn, ArrivalOut>>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Encode>,
        refuse: Safe<Refuse>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Adopt>,
        timer: Safe<Timer>,
    },
}
