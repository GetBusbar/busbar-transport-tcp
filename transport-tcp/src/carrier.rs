// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRIER (TRANSPORT-STACK; #3, #30): `tcp` as the contract's [`Carrier`] — the one
//! implementation both doors drive. A build that links this crate holds a [`TcpCarrier`] as its
//! `Arc<dyn Carrier>` (`crate::linked::build`); the `cdylib` built with the `dropped-in` feature
//! lowers the same type to the HOT decl through the contract's `export_carrier!` ([`exports`]), and
//! the host drives it through the loader's decl-backed carrier — the same methods, one crossing each.
//!
//! No method blocks on the network: `listen` and `dial` answer at once (a `listen` on a hostname
//! rather than an IP literal resolves it through the system resolver first, synchronously), and the
//! `poll_*` methods answer Ready | Pending | Error, registering the caller's waker. The sockets' readiness and the dial clock are
//! driven by this carrier's own I/O reactor (one thread per built instance), which wakes the waker
//! the caller registered; the caller polls again on its own thread and the bytes move there.
//!
//! `listen` binds SO_REUSEPORT on unix: the host listens once per acceptor on one address (its
//! per-core fan-out, the same model as its own data listeners).

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use busbar_contract::transport::wire::{CloseReason, TransportError};
use busbar_contract::transport::{Carrier, CarrierFacts, CarrierPoll, Dest};
use busbar_contract::{AbiVersion, Kind, Plugin, Transport};
use tokio::net::TcpStream;

use crate::TcpTransport;

/// The `tcp` carrier: the transport's own connection registry, the listeners it bound, the dials
/// still opening, the wakers parked on each connection, and the I/O reactor its sockets are
/// registered with (declared last, so it stops after everything that holds a socket).
pub struct TcpCarrier {
    tcp: TcpTransport,
    wakers: Mutex<HashMap<u64, Parked>>,
    listeners: Mutex<HashMap<u64, Arc<tokio::net::TcpListener>>>,
    next_listener: AtomicU64,
    dialing: Mutex<HashMap<u64, Dial>>,
    #[cfg(test)]
    hooks: Hooks,
    reactor: Reactor,
}

/// A step a test runs at one point inside the carrier.
#[cfg(test)]
type Hook = Mutex<Option<Box<dyn FnOnce(&TcpCarrier) + Send>>>;

/// The points inside the carrier where a second thread's call could land mid-operation, so a test
/// replays that race deterministically on one thread.
#[cfg(test)]
#[derive(Default)]
struct Hooks {
    /// Inside `poll_close`, between its closing the connection and its draining the parked wakers.
    mid_close: Hook,
    /// Inside `settle`, once the dial's entry is gone and the dial registry released.
    dial_settled: Hook,
}

#[cfg(test)]
impl Hooks {
    fn run(hook: &Hook, carrier: &TcpCarrier) {
        let step = hook.lock().expect("hook poisoned").take();
        if let Some(step) = step {
            step(carrier);
        }
    }
}

impl std::fmt::Debug for TcpCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpCarrier").finish_non_exhaustive()
    }
}

/// A dial `dial` began: its connection's handle is out, its socket not yet open.
type Dialing =
    Pin<Box<dyn Future<Output = Result<(TcpStream, SocketAddr), TransportError>> + Send>>;

/// A dial whose connection is not (yet) registered: still opening, or failed with the refusal every
/// poll on it answers until it is closed.
enum Dial {
    Opening(Dialing),
    Failed(TransportError),
}

/// The wakers a connection's parked reading and writing hold — so a close wakes both, and each sees
/// the connection closed.
#[derive(Default)]
struct Parked {
    reading: Option<Waker>,
    writing: Option<Waker>,
}

/// This carrier's I/O reactor: a single-threaded runtime on a thread of its own, driving the
/// readiness of every socket this carrier registers and the clock that bounds its dials. It runs no
/// task of the caller's: it only delivers readiness, by waking the caller's waker.
struct Reactor {
    handle: tokio::runtime::Handle,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Reactor {
    fn start() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let handle = runtime.handle().clone();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("busbar-wire-io".into())
            .spawn(move || {
                runtime.block_on(async {
                    let _ = stopped.await;
                });
            })?;
        Ok(Self {
            handle,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Reactor {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl TcpCarrier {
    /// A carrier with an empty registry and its own reactor.
    ///
    /// # Panics
    ///
    /// The reactor thread cannot be started (the process is out of threads).
    #[must_use]
    pub fn new() -> Self {
        Self {
            tcp: TcpTransport::new(),
            wakers: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            next_listener: AtomicU64::new(1),
            dialing: Mutex::new(HashMap::new()),
            #[cfg(test)]
            hooks: Hooks::default(),
            reactor: Reactor::start().expect("the tcp carrier's reactor thread starts"),
        }
    }

    /// Remember `cx`'s waker as the one parked on `conn`'s reading or writing.
    fn park(&self, conn: u64, reading: bool, cx: &Context<'_>) {
        let mut wakers = self.wakers.lock().expect("waker registry poisoned");
        let parked = wakers.entry(conn).or_default();
        let slot = if reading {
            &mut parked.reading
        } else {
            &mut parked.writing
        };
        match slot {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => *slot = Some(cx.waker().clone()),
        }
    }

    /// Drive the dial `dial` began for `conn`, if it is still opening: the connection is held once
    /// its socket is open, and a failed dial kept as its refusal until the connection is closed.
    fn settle(&self, conn: u64, cx: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
        let mut dialing = self.dialing.lock().expect("dial registry poisoned");
        let dial = match dialing.get_mut(&conn) {
            None => return Poll::Ready(Ok(())),
            // A failed dial answers its refusal to every poll until it is closed, not only to the
            // poll that happened to settle it: the contract answers it under `poll_flush`.
            Some(Dial::Failed(refusal)) => return Poll::Ready(Err(*refusal)),
            Some(Dial::Opening(dial)) => dial,
        };
        let opened = std::task::ready!(dial.as_mut().poll(cx));
        // Registered while the dial registry is still held, and only then is the dial forgotten: a
        // close takes that lock first, so it finds either the dial (and drops it) or the registered
        // connection (and closes it). Forgotten first, a close in between found neither, and the
        // socket was registered under a handle its owner had already closed.
        let settled = opened.and_then(|(stream, addr)| {
            self.tcp
                .register_as(conn, stream, addr, true)
                .map(drop)
                .map_err(|e| TcpTransport::map_io_err(&e))
        });
        match settled {
            Ok(()) => drop(dialing.remove(&conn)),
            Err(refusal) => drop(dialing.insert(conn, Dial::Failed(refusal))),
        }
        drop(dialing);
        #[cfg(test)]
        Hooks::run(&self.hooks.dial_settled, self);
        // The dial kept only the waker of the poll that settled it: every other direction that
        // parked on it waits for this, whatever the outcome.
        self.wake_others(conn, cx);
        Poll::Ready(settled)
    }

    /// Wake every waker parked on `conn` other than `cx`'s.
    fn wake_others(&self, conn: u64, cx: &Context<'_>) {
        let (reading, writing) = match self
            .wakers
            .lock()
            .expect("waker registry poisoned")
            .get(&conn)
        {
            Some(parked) => (parked.reading.clone(), parked.writing.clone()),
            None => return,
        };
        reading
            .into_iter()
            .chain(writing)
            .filter(|w| !w.will_wake(cx.waker()))
            .for_each(Waker::wake);
    }

    /// Poll one direction of `conn` once its dial settled, parking `cx`'s waker on it.
    fn poll_conn<T>(
        &self,
        conn: u64,
        reading: bool,
        cx: &mut Context<'_>,
        op: impl FnOnce(&TcpTransport, &mut Context<'_>) -> Poll<Result<T, TransportError>>,
    ) -> Poll<Result<T, TransportError>> {
        let _in = self.reactor.handle.enter();
        // Parked BEFORE the dial is driven: a dial still opening keeps only the last poller's waker,
        // so a read and a write both waiting on it must each be found, and woken, when it settles.
        self.park(conn, reading, cx);
        let polled = match self.settle(conn, cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(refusal)) => Poll::Ready(Err(refusal)),
            Poll::Ready(Ok(())) => op(&self.tcp, cx),
        };
        if let Poll::Ready(Err(_)) = polled {
            self.forget_if_gone(conn, cx);
        }
        polled
    }

    /// Forget the wakers parked on `conn` once it is neither open nor still opening: a poll on a
    /// closed, reset or unknown connection parks before it finds that out, and the entry it made
    /// would pin the caller's waker until a close that may never come. Connection ids are never
    /// reused, so nothing live is forgotten. The other direction's waker, if one is parked, is woken
    /// as it is forgotten, so it polls again and sees the connection gone: a read error deregisters
    /// the connection, and dropping the socket's registration clears the waker the reactor held for
    /// a parked write without waking it, so this is the one wake that write gets.
    fn forget_if_gone(&self, conn: u64, cx: &Context<'_>) {
        // Asked under the dial registry's lock, so a dial settling into a registered connection is
        // seen as one or the other, never as neither.
        let dialing = self.dialing.lock().expect("dial registry poisoned");
        let opening = matches!(dialing.get(&conn), Some(Dial::Opening(_)));
        if opening || self.tcp.inner(conn).is_some() {
            return;
        }
        let parked = self
            .wakers
            .lock()
            .expect("waker registry poisoned")
            .remove(&conn);
        drop(dialing);
        if let Some(parked) = parked {
            parked
                .reading
                .into_iter()
                .chain(parked.writing)
                .filter(|w| !w.will_wake(cx.waker()))
                .for_each(Waker::wake);
        }
    }
}

impl Default for TcpCarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for TcpCarrier {
    fn key(&self) -> &'static str {
        crate::linked::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> AbiVersion {
        busbar_contract::transport::TRANSPORT_ABI
    }
}

impl Carrier for TcpCarrier {
    fn listen(&self, bind: &str) -> Result<(u64, String), TransportError> {
        let _in = self.reactor.handle.enter();
        let (listener, addr) = TcpTransport::bind_shared(bind)?;
        let id = self.next_listener.fetch_add(1, Ordering::Relaxed);
        self.listeners
            .lock()
            .expect("listener registry poisoned")
            .insert(id, Arc::new(listener));
        Ok((id, addr))
    }

    fn poll_accept(&self, listener: u64, cx: &mut Context<'_>) -> CarrierPoll<(u64, String)> {
        let Some(listening) = self
            .listeners
            .lock()
            .expect("listener registry poisoned")
            .get(&listener)
            .cloned()
        else {
            return Poll::Ready(Err(TransportError::Closed));
        };
        let _in = self.reactor.handle.enter();
        for _ in 0..crate::ACCEPT_BUDGET {
            let (stream, peer) = match std::task::ready!(listening.poll_accept(cx)) {
                Ok(accepted) => accepted,
                // A live listener's accept error is never `Closed`: that would end the host's
                // accept loop for good (`TcpTransport::accept_err`).
                Err(e) => match TcpTransport::accept_err(&e) {
                    None => continue,
                    Some(err) => return Poll::Ready(Err(err)),
                },
            };
            // A peer gone between its accept and its registration ends that connection, not the
            // listener: it is dropped and the next one taken.
            if let Ok(conn) = self.tcp.register(stream, peer) {
                return Poll::Ready(Ok((conn.id(), conn.peer())));
            }
        }
        // A run of connections each gone before it was taken: yield, and be polled again at once.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn dial(&self, dest: &Dest<'_>) -> Result<u64, TransportError> {
        // A byte stream reaches an authority; a program is not a place this carrier can dial.
        let Dest::Authority(authority) = dest else {
            return Err(TransportError::AddressRefused);
        };
        let _in = self.reactor.handle.enter();
        let dial = self.tcp.dialing(authority)?;
        let id = self.tcp.next_conn_id();
        self.dialing
            .lock()
            .expect("dial registry poisoned")
            .insert(id, Dial::Opening(Box::pin(dial)));
        Ok(id)
    }

    fn poll_read(&self, conn: u64, cx: &mut Context<'_>, buf: &mut [u8]) -> CarrierPoll<usize> {
        self.poll_conn(conn, true, cx, |tcp, cx| tcp.poll_read_into(conn, cx, buf))
    }

    fn poll_write(&self, conn: u64, cx: &mut Context<'_>, bytes: &[u8]) -> CarrierPoll<usize> {
        self.poll_conn(conn, false, cx, |tcp, cx| {
            tcp.poll_write_on(conn, cx, bytes)
        })
    }

    fn poll_flush(&self, conn: u64, cx: &mut Context<'_>) -> CarrierPoll<()> {
        self.poll_conn(conn, false, cx, |tcp, cx| tcp.poll_flush_on(conn, cx))
    }

    /// Forget the connection and close it the way the transport closes one, waking whatever was
    /// parked on it; a dial still opening is dropped where it stood, and a failed one's refusal
    /// forgotten. Idempotent.
    fn poll_close(&self, conn: u64, _cx: &mut Context<'_>, reason: CloseReason) -> CarrierPoll<()> {
        let _in = self.reactor.handle.enter();
        drop(
            self.dialing
                .lock()
                .expect("dial registry poisoned")
                .remove(&conn),
        );
        if let Some(handle) = self.tcp.conn_handle(conn) {
            self.tcp.close(handle, reason);
        }
        #[cfg(test)]
        Hooks::run(&self.hooks.mid_close, self);
        // Drained only once the connection is closed: a poll that parked before this point is woken
        // here, and one that parks after it finds the connection gone and answers `Closed`. Drained
        // first, a poll that parked in between saw the connection still open, answered `Pending`,
        // and was never woken.
        let parked = self
            .wakers
            .lock()
            .expect("waker registry poisoned")
            .remove(&conn);
        if let Some(parked) = parked {
            parked
                .reading
                .into_iter()
                .chain(parked.writing)
                .for_each(Waker::wake);
        }
        Poll::Ready(Ok(()))
    }

    fn arrival(&self, conn: u64) -> Option<CarrierFacts> {
        let (peer, local_port) = self.tcp.facts(conn)?;
        Some(CarrierFacts { peer, local_port })
    }
}

#[cfg(test)]
#[path = "tests/carrier.rs"]
mod tests;

/// The dropped-in door, compiled only into the dropped-in build (feature `dropped-in`): [`TcpCarrier`]
/// lowered to the HOT decl and registered as this image's ONE door through the contract's
/// `export_carrier!` — so `busbar_abi`, `busbar_plugin_kind() == "transport"` and
/// `busbar_transport_decl` are the contract's frozen symbols, defined once. The one module this
/// crate's `#![deny(unsafe_code)]` allows: every line of it is the macro's.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
pub mod exports {
    busbar_contract::export_carrier!(super::TcpCarrier, super::build);
}

/// The linked row's constructor, as the lowering calls it: this wire takes no setting.
#[cfg(feature = "dropped-in")]
fn build(_: &busbar_contract::transport::TransportSettings) -> TcpCarrier {
    TcpCarrier::new()
}
