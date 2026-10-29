// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` CARRIER: the carrier ops over the HOST'S I/O (`busbar_contract::abi::host::io`,
//! `io.*`), and the framer ops refused. The host owns every socket; this carrier holds only the
//! host's opaque handles and owns the policy over them:
//!
//! * `listen` binds the address it is asked to, and `accept` takes each connection off it;
//! * `dial` reads the authority it is lent (`ip:port`, `[v6]:port` or `unix:` and an absolute path,
//!   byte for byte) as its ONE address — never a name, which it does not resolve: the host's one
//!   destination judge already pinned the address it may dial — and opens it, one attempt; the
//!   connect is bounded by the open the host runs it under;
//! * `read` answers what the socket has, straight into the host's buffer: a byte stream, so every
//!   read completes a frame (`READ_END_OF_FRAME`); `write` hands the host what it is offered, and
//!   a frame's end means nothing to a stream;
//! * `flush` settles the dial (connected, or the far end's refusal);
//! * `shut` closes the connection whatever the reason, and forgets it; `arrival` answers the far
//!   end's address and the local port, as the host reads them off the socket.
//!
//! No op holds a byte of its own: a PENDING op moved nothing, so a cancel finds nothing moved.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::Poll;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::io::{Io, IoFailure, DIR_WRITE, MAX_ADDR};
use busbar_contract::abi::sdk::life::{settings_object, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::net::SocketAddr;
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, ConnIn, ConnOut, DialIn, EmitIn,
    EncodeIn, FinishIn, FramerOut, FramingIn, IngestIn, IoOut, ListenIn, ListenOut, LocateIn,
    LocateOut, ReadIn, RefuseIn, ShutIn, WriteIn, CANCEL_NOTHING_MOVED, DEST_AUTHORITY,
    READ_END_OF_FRAME,
};

/// What one instance carries: its listeners and its connections, each by the token it minted.
pub struct Carried {
    listeners: Mutex<HashMap<u64, u64>>,
    conns: Mutex<HashMap<u64, Conn>>,
    next: AtomicU64,
}

/// One connection: the host's handle, and whether its dial has settled.
struct Conn {
    io: u64,
    settled: bool,
}

impl Conn {
    fn new(io: u64, settled: bool) -> Self {
        Self { io, settled }
    }
}

/// What every slot reads: the SDK's lifecycle state over [`Carried`].
type State = Held<Carried>;

impl Life for Carried {
    /// A PENDING carrier op moved nothing, so a cancel finds nothing moved.
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    /// This carrier reads no setting: a JSON object, and no key in it.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        no_settings(settings)
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        no_settings(settings)?;
        Ok(Self {
            listeners: Mutex::new(HashMap::new()),
            conns: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        no_settings(settings)?;
        Ok(Refreshed::default())
    }

    /// `close`: every host handle this instance still holds, listeners and connections, is closed
    /// through the host's I/O (errors ignored: the instance is going either way); the SDK answers
    /// READY and drops the state.
    fn close(&self, host: Option<&Host>) {
        let Some(mut io) = host.map(|h| h.io(Ticket::NONE)).filter(Io::armed) else {
            return;
        };
        let listeners: Vec<u64> = self.listeners().drain().map(|(_, h)| h).collect();
        let conns: Vec<u64> = self.conns().drain().map(|(_, c)| c.io).collect();
        for h in listeners.into_iter().chain(conns) {
            let _ = io.close(h);
        }
    }
}

/// The settings this carrier reads: none. A JSON object (or empty), and every key refused.
fn no_settings(settings: &[u8]) -> Result<(), Refusal> {
    match settings_object(settings)?.keys().next() {
        Some(key) => Err(Refusal::failed(format!(
            "settings: {key} is not a setting this transport reads"
        ))),
        None => Ok(()),
    }
}

impl Carried {
    fn conns(&self) -> MutexGuard<'_, HashMap<u64, Conn>> {
        self.conns.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn listeners(&self) -> MutexGuard<'_, HashMap<u64, u64>> {
        self.listeners
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn mint(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// The host handle of connection `conn`.
    fn handle(&self, conn: u64) -> Option<u64> {
        self.conns().get(&conn).map(|c| c.io)
    }
}

/// The open instance and the host's I/O for this op, or the refusal a call on none earns.
fn carried<'a>(i: &Instance<'a, State>, op: &str) -> Result<(&'a Carried, Io<'a>), Refusal> {
    let held = i
        .get()
        .ok_or_else(|| Refusal::failed(format!("{op}: no open instance")))?;
    let io = held
        .host()
        .map(|h| h.io(i.ticket()))
        .filter(Io::armed)
        .ok_or_else(|| Refusal::failed(format!("{op}: the host lent this carrier no I/O")))?;
    Ok((held.life(), io))
}

/// The host's answer, as an op's refusal: the host's policy is REFUSED, the system's FAILED, each in
/// the host's own words and nothing else. A plane passes a refused connect on to its caller (the
/// a2a card fetch's "tcp connect error: Connection refused"), so the carrier's op name is no part of
/// it: the host knows which op it crossed.
fn refusal(e: &IoFailure) -> Refusal {
    match e {
        IoFailure::Refused(t) => Refusal::refused(t.clone()),
        other => Refusal::failed(other.text().to_owned()),
    }
}

/// Run `body` over the instance and its I/O, failing the op without one.
macro_rules! over {
    ($op:literal, $inst:expr, $o:expr, |$c:ident, $io:ident| $body:block) => {
        match carried(&$inst, $op) {
            Ok(($c, mut $io)) => $body,
            Err(r) => return $o.fail(r),
        }
    };
}

/// One framer op's stub: REFUSED, in words that name the op (`abi::transport`: a transport fills the
/// slots of the role it does not play with a stub that answers REFUSED). A carrier frames nothing.
macro_rules! not_served {
    ($name:ident, $in:ty, $out:ty, $op:literal) => {
        #[doc = concat!("`", $op, "`: REFUSED, the tcp carrier frames nothing.")]
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = State;
            fn call(_: Instance<'_, State>, _: Lent<'_, $in>, mut o: Out<'_, $out>) -> Outcome {
                o.fail(Refusal::refused(concat!(
                    $op,
                    ": the tcp carrier does not serve this op"
                )))
            }
        }
    };
}

not_served!(NoLocate, LocateIn, LocateOut, "locate");
not_served!(NoBegin, BeginIn, FramerOut, "begin");
not_served!(NoIngest, IngestIn, FramerOut, "ingest");
not_served!(NoEmit, EmitIn, FramerOut, "emit");
not_served!(NoEncode, EncodeIn, FramerOut, "encode");
not_served!(NoRefuse, RefuseIn, FramerOut, "refuse");
not_served!(NoFinish, FinishIn, FramerOut, "finish");
not_served!(NoDetach, FramingIn, FramerOut, "detach");
not_served!(NoAdopt, AdoptIn, FramerOut, "adopt");
not_served!(NoTimer, FramingIn, FramerOut, "timer");

/// `listen`: bind the address, and answer the address bound into the host's buffer.
pub struct Listen;
impl SafeSlot for Listen {
    type In = ListenIn;
    type Out = ListenOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, ListenIn>,
        mut o: Out<'_, ListenOut>,
    ) -> Outcome {
        let Ok(bind) = i.bind().as_str() else {
            return o.fail(Refusal::failed("listen: the bind address is not UTF-8"));
        };
        over!("listen", inst, o, |c, io| {
            let mut addr = i.addr_buf();
            match io.listen_host(bind, &mut addr) {
                Ok(h) => {
                    let token = c.mint();
                    c.listeners().insert(token, h);
                    o.set(|o| &o.listener, token);
                    o.set(|o| &o.addr_written, addr.asked() as u64);
                    Outcome::Ready
                }
                Err(e) => o.fail(refusal(&e)),
            }
        })
    }
}

/// `accept`: the next connection off the listener, its far end into the host's buffer.
pub struct Accept;
impl SafeSlot for Accept {
    type In = AcceptIn;
    type Out = AcceptOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, AcceptIn>,
        mut o: Out<'_, AcceptOut>,
    ) -> Outcome {
        over!("accept", inst, o, |c, io| {
            let Some(l) = c.listeners().get(&i.listener()).copied() else {
                return o.fail(Refusal::failed("accept: no such listener"));
            };
            let mut peer = i.peer_buf();
            match io.accept_host(l, &mut peer) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(h)) => {
                    let token = c.mint();
                    c.conns().insert(token, Conn::new(h, true));
                    o.set(|o| &o.conn, token);
                    o.set(|o| &o.peer_written, peer.asked() as u64);
                    Outcome::Ready
                }
                Poll::Ready(Err(e)) => o.fail(refusal(&e)),
            }
        })
    }
}

/// The address a dial opens, byte for byte: an IP literal (`v4:port` or `[v6]:port`) or a `unix:`
/// absolute path, and nothing else. A name (`localhost` included) and a scheme prefix are not read
/// here: the host's one destination judge resolves and pins the address a dial may reach and hands
/// this carrier that pinned address, which the carrier dials exactly.
#[must_use]
pub fn resolve(authority: &str) -> Option<String> {
    let literal = authority.starts_with("unix:/") || authority.parse::<SocketAddr>().is_ok();
    literal.then(|| authority.to_owned())
}

/// `dial`: the authority's one address, opened once; the connection's token at once, its connect
/// settling under `flush`. A program is not this carrier's destination: REFUSED.
pub struct Dial;
impl SafeSlot for Dial {
    type In = DialIn;
    type Out = ConnOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, DialIn>, mut o: Out<'_, ConnOut>) -> Outcome {
        let Some(dest) = i.dest() else {
            return o.fail(Refusal::failed("dial: no destination"));
        };
        if dest.kind() != DEST_AUTHORITY {
            return o.fail(Refusal::refused(
                "dial: a tcp carrier reaches an authority, never a program",
            ));
        }
        let Ok(authority) = dest.authority().as_str() else {
            return o.fail(Refusal::failed("dial: the authority is not UTF-8"));
        };
        let Some(addr) = resolve(authority) else {
            return o.fail(Refusal::refused(
                "dial: the authority is not an IP literal or unix: path; the carrier never resolves a name",
            ));
        };
        over!("dial", inst, o, |c, io| {
            match io.open(&addr) {
                Ok(h) => {
                    let token = c.mint();
                    c.conns().insert(token, Conn::new(h, false));
                    o.set(|o| &o.conn, token);
                    Outcome::Ready
                }
                Err(e) => o.fail(refusal(&e)),
            }
        })
    }
}

/// `flush`: a dial settles — connected; or refused, and the dial answers the far end's refusal.
/// Nothing is held to write.
pub struct Flush;
impl SafeSlot for Flush {
    type In = ConnIn;
    type Out = OutHead;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, ConnIn>, mut o: Out<'_, OutHead>) -> Outcome {
        over!("flush", inst, o, |c, io| {
            let (h, settled) = match c.conns().get(&i.conn()) {
                Some(conn) => (conn.io, conn.settled),
                None => return o.fail(Refusal::failed("flush: no such connection")),
            };
            if settled {
                return Outcome::Ready;
            }
            match io.ready(h, DIR_WRITE) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(())) => {
                    if let Some(conn) = c.conns().get_mut(&i.conn()) {
                        conn.settled = true;
                    }
                    Outcome::Ready
                }
                Poll::Ready(Err(e)) => {
                    let _ = io.close(h);
                    c.conns().remove(&i.conn());
                    o.fail(refusal(&e))
                }
            }
        })
    }
}

/// `read`: what the socket has, straight into the host's buffer; every read a frame of the stream.
pub struct Read;
impl SafeSlot for Read {
    type In = ReadIn;
    type Out = IoOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, ReadIn>, mut o: Out<'_, IoOut>) -> Outcome {
        over!("read", inst, o, |c, io| {
            let Some(h) = c.handle(i.conn()) else {
                return o.fail(Refusal::failed("read: no such connection"));
            };
            let mut buf = i.buf();
            match io.read_host(h, &mut buf) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(n)) => {
                    o.set(|o| &o.len, n as u64);
                    if n > 0 {
                        o.set(|o| &o.flags, READ_END_OF_FRAME);
                    }
                    Outcome::Ready
                }
                Poll::Ready(Err(e)) => o.fail(refusal(&e)),
            }
        })
    }
}

/// `write`: what the socket takes of the bytes offered.
pub struct Write;
impl SafeSlot for Write {
    type In = WriteIn;
    type Out = IoOut;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, WriteIn>, mut o: Out<'_, IoOut>) -> Outcome {
        let bytes = i.bytes();
        over!("write", inst, o, |c, io| {
            let Some(h) = c.handle(i.conn()) else {
                return o.fail(Refusal::failed("write: no such connection"));
            };
            match io.write(h, bytes) {
                Poll::Pending => Outcome::Pending,
                Poll::Ready(Ok(n)) => {
                    o.set(|o| &o.len, n as u64);
                    Outcome::Ready
                }
                Poll::Ready(Err(e)) => o.fail(refusal(&e)),
            }
        })
    }
}

/// `shut`: the connection is closed, whatever the reason, and forgotten. An unknown connection is
/// already closed.
pub struct Shut;
impl SafeSlot for Shut {
    type In = ShutIn;
    type Out = OutHead;
    type State = State;
    fn call(inst: Instance<'_, State>, i: Lent<'_, ShutIn>, mut o: Out<'_, OutHead>) -> Outcome {
        over!("shut", inst, o, |c, io| {
            if let Some(conn) = c.conns().remove(&i.conn()) {
                let _ = io.close(conn.io);
            }
            Outcome::Ready
        })
    }
}

/// `arrival`: the far end's address and the local port, as the host reads them off the socket.
pub struct Arrival;
impl SafeSlot for Arrival {
    type In = ArrivalIn;
    type Out = ArrivalOut;
    type State = State;
    fn call(
        inst: Instance<'_, State>,
        i: Lent<'_, ArrivalIn>,
        mut o: Out<'_, ArrivalOut>,
    ) -> Outcome {
        over!("arrival", inst, o, |c, io| {
            let Some(h) = c.handle(i.conn()) else {
                return o.fail(Refusal::failed("arrival: no such connection"));
            };
            let mut peer = [0_u8; MAX_ADDR];
            match io.ends(h, &mut peer) {
                Ok((port, n)) => {
                    let mut buf = i.peer_buf();
                    buf.extend(&peer[..n]);
                    o.set(|o| &o.local_port, port);
                    o.set(|o| &o.peer_written, buf.written() as u64);
                    o.set(|o| &o.peer_needed, buf.needed() as u64);
                    if buf.fits() {
                        Outcome::Ready
                    } else {
                        o.fail(Refusal::failed("arrival: the peer buffer is too small"))
                    }
                }
                Err(e) => o.fail(refusal(&e)),
            }
        })
    }
}
