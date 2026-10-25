// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The axis entry a busbar build folds: the same key, layers and session flag the door states.

use busbar_transport_tcp::linked;

#[test]
fn the_linked_entry_states_the_carriers_key_layers_and_session() {
    assert_eq!(linked::KEY, "tcp");
    assert!(linked::COMPOSES_OVER.is_empty());
    let session = linked::SESSION;
    assert!(session);
    // SAFETY: `door()` answers the `'static` door of this crate.
    #[allow(unused_unsafe)]
    let d = unsafe { (linked::door)() };
    assert!(!d.ops().is_null());
}
