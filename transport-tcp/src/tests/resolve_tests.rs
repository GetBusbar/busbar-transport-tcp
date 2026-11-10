// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::transport::resolve;

/// The carrier dials the pinned address; it does not resolve names here.
#[test]
fn an_authority_is_its_one_address_and_a_name_is_not_resolved_here() {
    assert!(resolve("127.0.0.1:80"));
    assert!(resolve("[::1]:443"));
    assert!(resolve("unix:/run/x.sock"));
    assert!(!resolve("tcp://127.0.0.1:80"));
    assert!(!resolve("LOCALHOST:9"));
    assert!(!resolve("localhost:9"));
    assert!(!resolve("unix:run/x.sock"));
    assert!(!resolve("example.test:80"));
    assert!(!resolve("127.0.0.1"));
    assert!(!resolve(" 127.0.0.1:80"));
    assert!(!resolve("127.0.0.1:80 "));
    assert!(!resolve("127.0.0.1:99999"));
    assert!(!resolve("UNIX:/run/x.sock"));
    assert!(!resolve(""));
}
