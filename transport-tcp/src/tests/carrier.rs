//! The carrier's own cells: what `poll_accept`, the dial's settling and `poll_close` answer, and
//! which wakers they wake, driven on this thread against real loopback sockets. The races are made
//! deterministic by the carrier's test hooks, which run a step at the one point a second thread
//! could.

use super::*;
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
