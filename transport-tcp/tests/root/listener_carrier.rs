// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn a_framer_that_does_not_accept_is_not_the_data_listeners() {
    let carrier = actual_transport(busbar_transport_tcp::door);
    assert!(
        !carrier.accepts(),
        "the actual TCP carrier has no accept framer"
    );
    assert!(data_framer(Arc::new(move |scheme| {
        (scheme == DATA_SCHEME).then(|| Arc::clone(&carrier))
    }))
    .is_none());
}
