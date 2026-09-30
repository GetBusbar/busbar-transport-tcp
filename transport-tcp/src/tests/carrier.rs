//! The carrier's own cells: what `poll_accept`, the dial's settling and `poll_close` answer, and
//! which wakers they wake, driven on this thread against real loopback sockets. The races are made
//! deterministic by the carrier's test hooks, which run a step at the one point a second thread
//! could.

use super::*;
use std::sync::atomic::AtomicUsize;
use std::task::Wake;
use std::time::{Duration, Instant};

/// Wakes the thread that parked on a poll.
struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Poll to an answer on this thread, parking between polls; ten seconds is a hang.
fn wait<T>(mut poll: impl FnMut(&mut Context<'_>) -> Poll<T>) -> T {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Poll::Ready(v) = poll(&mut cx) {
            return v;
        }
        assert!(Instant::now() < deadline, "no answer within ten seconds");
        std::thread::park_timeout(Duration::from_millis(50));
    }
}

/// A waker that counts how often it was woken.
#[derive(Default)]
struct Count(AtomicUsize);

impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Count {
    fn woken(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// A carrier listening on loopback, a raw peer connected to it, and the accepted connection.
fn accepted(carrier: &TcpCarrier) -> (std::net::TcpStream, u64) {
    let (listener, addr) = carrier.listen("127.0.0.1:0").expect("listen");
    let peer = std::net::TcpStream::connect(addr.as_str()).expect("connect");
    let (conn, _) = wait(|cx| carrier.poll_accept(listener, cx)).expect("accept");
    (peer, conn)
}

/// An accepted connection whose registration fails (its peer reset between the accept and the
/// registration) is passed over and the next one answered (TCP-2). RED when the registration's
/// `NotConnected` is answered as the accept's error: `Closed`, which ends the host's accept loop.
#[test]
fn an_accepted_connection_that_cannot_be_registered_is_passed_over() {
    let carrier = TcpCarrier::new();
    let (listener, addr) = carrier.listen("127.0.0.1:0").expect("listen");
    let _gone = std::net::TcpStream::connect(addr.as_str()).expect("connect");
    let _next = std::net::TcpStream::connect(addr.as_str()).expect("connect");
    carrier.tcp.register_faults.store(1, Ordering::Relaxed);
    let (conn, _) = wait(|cx| carrier.poll_accept(listener, cx))
        .expect("the listener passes over the dead connection and takes the next");
    assert_eq!(
        carrier.tcp.register_faults.load(Ordering::Relaxed),
        0,
        "the first registration failed"
    );
    assert!(carrier.tcp.inner(conn).is_some());
}

/// A read that parks while a close runs on another thread is woken by that close (TCP-3). The hook
/// runs the read at the one point inside `poll_close` a second thread's read could land. RED when
/// the parked wakers are drained before the connection is closed: the read parks after the drain,
/// finds the connection still open, answers `Pending`, and nothing ever wakes it.
#[test]
fn a_read_that_parks_while_the_close_runs_is_woken() {
    let carrier = TcpCarrier::new();
    let (_peer, conn) = accepted(&carrier);
    let reader = Arc::new(Count::default());
    let answered = Arc::new(Mutex::new(None));
    *carrier.hooks.mid_close.lock().unwrap() = Some(Box::new({
        let reader = Arc::clone(&reader);
        let answered = Arc::clone(&answered);
        move |c: &TcpCarrier| {
            let waker = Waker::from(reader);
            let mut buf = [0_u8; 16];
            let polled = c.poll_read(conn, &mut Context::from_waker(&waker), &mut buf);
            *answered.lock().unwrap() = Some(polled);
        }
    }));
    wait(|cx| carrier.poll_close(conn, cx, CloseReason::Normal)).expect("close");
    let polled = answered
        .lock()
        .unwrap()
        .take()
        .expect("the read ran inside the close");
    assert!(
        polled.is_ready() || reader.woken() > 0,
        "a read that parked while the close ran was never woken: {polled:?}"
    );
}

/// A poll on a connection that is gone leaves no waker behind (TCP-4). The poll parks before it
/// learns the connection is closed, and the entry it made held the caller's waker until a second
/// close; a host that closes once, as the contract asks, leaked one per closed connection. RED when
/// the entry outlives the poll that answered `Closed`.
#[test]
fn a_poll_on_a_closed_connection_leaves_no_waker_parked() {
    let carrier = TcpCarrier::new();
    let (_peer, conn) = accepted(&carrier);
    wait(|cx| carrier.poll_close(conn, cx, CloseReason::Normal)).expect("close");
    let mut buf = [0_u8; 16];
    assert_eq!(
        wait(|cx| carrier.poll_read(conn, cx, &mut buf)),
        Err(TransportError::Closed)
    );
    assert_eq!(
        wait(|cx| carrier.poll_write(conn, cx, b"x")),
        Err(TransportError::Closed)
    );
    assert!(
        !carrier.wakers.lock().unwrap().contains_key(&conn),
        "a closed connection's poll left its waker parked"
    );
}

/// A write parked on a connection whose read then fails is woken when the read forgets the
/// connection's wakers (TCP-4's follow-up). The read error deregisters the connection, and the
/// socket's registration drops the waker the reactor held for the write without waking it, so the
/// carrier's parked entry is the write's one way back. The write is parked in the carrier's
/// registry alone, as it stands once that registration is gone, so no readiness event can wake it
/// and the cell is deterministic. RED when the gone connection's entry is removed without waking
/// the other direction: the write is never woken.
#[test]
fn a_read_error_wakes_the_write_parked_on_the_connection() {
    let carrier = TcpCarrier::new();
    let (peer, conn) = accepted(&carrier);
    let _written = wait(|cx| carrier.poll_write(conn, cx, &[7_u8; 4096])).expect("write");
    wait(|cx| carrier.poll_flush(conn, cx)).expect("flush");
    let writer = Arc::new(Count::default());
    carrier.park(
        conn,
        false,
        &Context::from_waker(&Waker::from(Arc::clone(&writer))),
    );
    // Peeked, not read: the peer closes with bytes it never read, so its stack answers with an RST.
    peer.peek(&mut [0_u8; 1]).expect("the bytes arrive");
    drop(peer);
    let mut buf = [0_u8; 64];
    let read = wait(|cx| carrier.poll_read(conn, cx, &mut buf));
    assert!(
        read.is_err(),
        "a reset connection's read is an error: {read:?}"
    );
    assert!(
        writer.woken() > 0,
        "the write parked on the connection was never woken by the read that ended it"
    );
    assert!(
        !carrier.wakers.lock().unwrap().contains_key(&conn),
        "the gone connection's wakers are forgotten"
    );
}

/// A close that lands while a dial settles leaves nothing registered (TCP-6). The hook runs the close
/// at the point inside `settle` a second thread's close could land, once the dial's entry is gone.
/// RED when the entry is forgotten before the socket is registered: the close finds neither the dial
/// nor the connection, answers `Ok`, and the socket is registered after it under a closed handle.
#[test]
fn a_close_while_the_dial_settles_leaves_nothing_registered() {
    let carrier = TcpCarrier::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let authority = listener.local_addr().expect("addr").to_string();
    let conn = carrier.dial(&Dest::Authority(&authority)).expect("dial");
    *carrier.hooks.dial_settled.lock().unwrap() = Some(Box::new(move |c: &TcpCarrier| {
        let closed = c.poll_close(
            conn,
            &mut Context::from_waker(Waker::noop()),
            CloseReason::Normal,
        );
        assert_eq!(closed, Poll::Ready(Ok(())));
    }));
    let flushed = wait(|cx| carrier.poll_flush(conn, cx));
    assert!(
        carrier.tcp.inner(conn).is_none(),
        "the dial's socket was registered after its close"
    );
    assert_eq!(flushed, Err(TransportError::Closed));
}

/// A dial's refusal is answered by every poll on it until its close, whichever poll settled it
/// (TCP-7): the contract names `poll_flush` as where the refusal is answered. RED when the failed
/// dial is forgotten by the poll that settled it: a `poll_read` takes the refusal and the
/// `poll_flush` after it answers `Closed`.
#[test]
fn a_failed_dials_refusal_is_answered_until_its_close() {
    let carrier = TcpCarrier::new();
    // A reserved port nobody may bind unprivileged: the conformance fold's refused dial.
    let conn = carrier.dial(&Dest::Authority("127.0.0.1:1")).expect("dial");
    let mut buf = [0_u8; 16];
    assert_eq!(
        wait(|cx| carrier.poll_read(conn, cx, &mut buf)),
        Err(TransportError::Refused)
    );
    assert_eq!(
        wait(|cx| carrier.poll_flush(conn, cx)),
        Err(TransportError::Refused),
        "the flush after the read still answers the dial's refusal"
    );
    assert_eq!(
        wait(|cx| carrier.poll_write(conn, cx, b"x")),
        Err(TransportError::Refused)
    );
    wait(|cx| carrier.poll_close(conn, cx, CloseReason::Normal)).expect("close");
    assert_eq!(
        wait(|cx| carrier.poll_flush(conn, cx)),
        Err(TransportError::Closed),
        "the close forgets the refusal"
    );
    assert!(!carrier.dialing.lock().unwrap().contains_key(&conn));
    assert!(!carrier.wakers.lock().unwrap().contains_key(&conn));
}

/// A read and a flush both waiting on one dial are both woken when it settles (TCP-5). The dial
/// future keeps only the waker of the last poll, so the read's waker is lost unless the carrier
/// holds it. RED when a poll on an opening dial returns `Pending` without parking its waker: the
/// read waits forever on a dial that has long since settled.
#[test]
fn every_direction_waiting_on_a_dial_is_woken_when_it_settles() {
    let carrier = TcpCarrier {
        tcp: TcpTransport::new().with_dial_timeout(Duration::from_millis(500)),
        ..TcpCarrier::new()
    };
    // TEST-NET-1 (RFC 5737) is routed nowhere: the dial stays opening until its timeout settles it.
    let conn = carrier
        .dial(&Dest::Authority("192.0.2.1:80"))
        .expect("dial");
    let reader = Arc::new(Count::default());
    let mut buf = [0_u8; 16];
    let read = carrier.poll_read(
        conn,
        &mut Context::from_waker(&Waker::from(Arc::clone(&reader))),
        &mut buf,
    );
    assert!(read.is_pending(), "the dial is still opening: {read:?}");
    // The flush drives the same dial with its own waker, which the dial now keeps instead.
    assert_eq!(
        wait(|cx| carrier.poll_flush(conn, cx)),
        Err(TransportError::Timeout)
    );
    assert!(
        reader.woken() > 0,
        "the read parked on the dial was never woken when it settled"
    );
}

/// A dialled connection's facts name no local port (TCP-8): `CarrierFacts.local_port` is "`0` on one
/// that was dialled". An accepted one names the port it arrived on. RED when the dialled connection
/// reports its ephemeral port.
#[test]
fn a_dialled_connection_arrived_on_no_local_port() {
    let carrier = TcpCarrier::new();
    let (listener, addr) = carrier.listen("127.0.0.1:0").expect("listen");
    let conn = carrier.dial(&Dest::Authority(&addr)).expect("dial");
    wait(|cx| carrier.poll_flush(conn, cx)).expect("the dial opens");
    let (accepted, _) = wait(|cx| carrier.poll_accept(listener, cx)).expect("accept");
    let dialled = carrier.arrival(conn).expect("dialled facts");
    assert_eq!(
        dialled.local_port, 0,
        "a dialled connection arrived on no port"
    );
    assert_eq!(dialled.peer, addr);
    let listen_port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
    let accepted = carrier.arrival(accepted).expect("accepted facts");
    assert_eq!(
        accepted.local_port, listen_port,
        "an accepted connection arrived on the listener's port"
    );
}

/// A read error on a carrier connection ends it the way a close does: it is deregistered and
/// finalised (TCP-10), the carrier's twin of `a_read_error_deregisters_the_connection`. The peer
/// closes with bytes it never read, so its stack answers with an RST and the read is an error.
#[test]
fn a_read_error_on_a_carrier_connection_deregisters_it() {
    let carrier = TcpCarrier::new();
    let (peer, conn) = accepted(&carrier);
    let _written = wait(|cx| carrier.poll_write(conn, cx, &[7_u8; 4096])).expect("write");
    wait(|cx| carrier.poll_flush(conn, cx)).expect("flush");
    // Peeked, not read: the bytes have arrived and are still unread when the peer closes.
    peer.peek(&mut [0_u8; 1]).expect("the bytes arrive");
    drop(peer);
    let mut buf = [0_u8; 64];
    let read = wait(|cx| carrier.poll_read(conn, cx, &mut buf));
    assert!(
        read.is_err(),
        "a reset connection's read is an error: {read:?}"
    );
    assert!(
        carrier.tcp.inner(conn).is_none(),
        "a read error deregisters the connection"
    );
}

/// A close wakes the read and the write parked on the connection, and each then sees it closed
/// (TCP-11): the contract's "wakes a read or write parked on it". The close runs on another thread,
/// as the host's does.
#[test]
fn a_close_wakes_the_read_and_the_write_parked_on_the_connection() {
    let carrier = TcpCarrier::new();
    let (_peer, conn) = accepted(&carrier);
    let reader = Arc::new(Count::default());
    let writer = Arc::new(Count::default());
    let reading = Waker::from(Arc::clone(&reader));
    let writing = Waker::from(Arc::clone(&writer));
    let mut buf = [0_u8; 16];
    let read = carrier.poll_read(conn, &mut Context::from_waker(&reading), &mut buf);
    assert!(read.is_pending(), "nothing has been sent: {read:?}");
    // The peer never reads, so the send buffers fill and the write parks.
    let chunk = vec![0_u8; 64 * 1024];
    let parked = (0..100_000).any(|_| {
        carrier
            .poll_write(conn, &mut Context::from_waker(&writing), &chunk)
            .is_pending()
    });
    assert!(parked, "the write parks on a peer that never reads");

    std::thread::scope(|s| {
        s.spawn(|| wait(|cx| carrier.poll_close(conn, cx, CloseReason::Normal)))
            .join()
            .expect("the closing thread")
            .expect("close");
    });
    assert!(reader.woken() > 0, "the close woke the parked read");
    assert!(writer.woken() > 0, "the close woke the parked write");
    let read = carrier.poll_read(conn, &mut Context::from_waker(&reading), &mut buf);
    assert!(
        matches!(read, Poll::Ready(Err(TransportError::Closed) | Ok(0))),
        "the woken read sees the connection closed: {read:?}"
    );
}
