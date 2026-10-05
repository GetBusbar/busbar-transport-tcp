// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` framer, as the kind's own file (`BUSBAR-1.6.0.md` THE DESIGN, §2): an IDENTITY framer
//! over the host's socket. The slots [`crate::door`] wires into the transport kind's table: the
//! carrier ops refused, and the framer ops that answer a byte stream as itself.

use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{HostBuf, Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::transport::{
    AdoptIn, BeginIn, EmitIn, EncodeIn, FinishIn, FramePiece, FramerOut, FramerSink, FramingIn,
    IngestIn, LocateIn, LocateOut, RefuseIn, CANCEL_NOTHING_MOVED, PIECE_END_OF_FRAME, YIELD_ENDED,
    YIELD_MORE,
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
                fault: 0,
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
