// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A listener whose process is out of descriptors is not a listener that is gone (TCP-1).
//!
//! The host's accept loop ends for good on `Closed` and backs off on anything else. An accept that
//! fails with EMFILE must therefore answer `Backpressure`, and the same listener must accept again
//! once descriptors are free: an unauthenticated peer that exhausts the table must not be able to
//! stop the door for the life of the process. Both paths are driven: the carrier's `poll_accept`
//! and the `Transport` trait's `accept`.
//!
//! Its own test binary with one test, because RLIMIT_NOFILE is process-wide: lowering it beside
//! other tests would starve them.

#![cfg(unix)]

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::plugin::TestKernelSeal;
use busbar_contract::transport::wire::TransportError;
use busbar_contract::transport::Carrier;
use busbar_contract::{ConfigView, Transport, TransportConfigView, TransportKeyHandle};
use busbar_transport_tcp::{TcpCarrier, TcpTransport};

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

struct Bind;

impl ConfigView for Bind {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

impl TransportConfigView for Bind {
    fn bind(&self) -> Option<&str> {
        Some("127.0.0.1:0")
    }
}

fn nofile() -> libc::rlimit {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, writable rlimit.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
        0
    );
    limit
}

fn set_soft_nofile(soft: libc::rlim_t) {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: nofile().rlim_max,
    };
    // SAFETY: `limit` is a live rlimit; a soft limit at or below the hard one is always permitted.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
}

#[test]
fn an_accept_out_of_descriptors_is_backpressure_and_the_listener_accepts_again() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let key = TransportKeyHandle::issue(&TestKernelSeal, 0, "test");

    let carrier = TcpCarrier::new();
    let (listener, addr) = carrier.listen("127.0.0.1:0").expect("the carrier listens");
    let transport = TcpTransport::new();
    let bound = runtime
        .block_on(transport.listen(&Bind, &key))
        .expect("the transport listens");

    // Connected BEFORE the table is exhausted: a connect afterwards would itself be EMFILE.
    let _peers = [
        std::net::TcpStream::connect(addr.as_str()).expect("connect"),
        std::net::TcpStream::connect(bound.local_addr()).expect("connect"),
    ];

    // Descriptors are handed out lowest first, so every one below the lowest free one is taken:
    // a soft limit of exactly that number leaves the process none to open.
    let saved = nofile();
    let lowest_free = std::fs::File::open("/dev/null").expect("probe").as_raw_fd();
    set_soft_nofile(libc::rlim_t::try_from(lowest_free).expect("a descriptor is not negative"));
    let carrier_exhausted = wait(|cx| carrier.poll_accept(listener, cx));
    let transport_exhausted = runtime.block_on(transport.accept(&bound));
    set_soft_nofile(saved.rlim_cur);

    assert_eq!(
        carrier_exhausted.err(),
        Some(TransportError::Backpressure),
        "the carrier's accept out of descriptors is backpressure, not the listener's end"
    );
    assert_eq!(
        transport_exhausted.err(),
        Some(TransportError::Backpressure),
        "the transport's accept out of descriptors is backpressure, not the listener's end"
    );

    // Descriptors free again: the same listeners take the connections that waited.
    assert!(
        wait(|cx| carrier.poll_accept(listener, cx)).is_ok(),
        "the carrier's listener accepts again"
    );
    assert!(
        runtime.block_on(transport.accept(&bound)).is_ok(),
        "the transport's listener accepts again"
    );
}
