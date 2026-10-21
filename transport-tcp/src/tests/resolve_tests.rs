// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::transport::resolve;

/// THE CARRIER DIALS EXACTLY THE PINNED JUDGED ADDRESS (THE DESIGN §5; CONNECTOR-19): an IP
/// literal or a `unix:` absolute path, byte for byte. A name (`localhost` included) and a scheme
/// prefix are the connector's to read, never rewritten here. RED before the fix: `localhost` was
/// mapped to the IPv4 loopback and `tcp://` stripped inside the plugin.
#[test]
fn an_authority_is_its_one_address_and_a_name_is_not_resolved_here() {
    assert_eq!(resolve("127.0.0.1:80"), Some("127.0.0.1:80".into()));
    assert_eq!(resolve("[::1]:443"), Some("[::1]:443".into()));
    assert_eq!(resolve("unix:/run/x.sock"), Some("unix:/run/x.sock".into()));
    assert_eq!(resolve("tcp://127.0.0.1:80"), None);
    assert_eq!(resolve("LOCALHOST:9"), None);
    assert_eq!(resolve("localhost:9"), None);
    assert_eq!(resolve("unix:run/x.sock"), None);
    assert_eq!(resolve("example.test:80"), None);
    assert_eq!(resolve("127.0.0.1"), None);
}
