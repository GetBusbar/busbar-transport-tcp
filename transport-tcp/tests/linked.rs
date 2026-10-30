// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `linked` entry the composition root folds, tied to the claim row the door declares.

use busbar_contract::abi::transport::{TransportTail, UNIT0_FIRST_BYTES};
use busbar_contract::SelectorForm;
use busbar_transport_tcp::{door, linked};

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

#[test]
fn linked_session_is_the_claim_rows_session_and_the_row_states_its_facts() {
    // SAFETY: the door's Statement is this crate's `'static` one, and its kind tail a `'static`
    // `TransportTail` whose claim rows are `'static`.
    let (statement, tail) = unsafe {
        let st = &*(*door()).statement();
        (st, &*st.kind_tail().cast::<TransportTail>())
    };
    // SAFETY: the tail's claim rows, `claim_rows_len` of them.
    let rows = unsafe { std::slice::from_raw_parts(tail.claim_rows, tail.claim_rows_len) };
    assert_eq!(statement.claims_len, 1);
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.session != 0, linked::SESSION);
    assert_eq!(row.session_bound, 0);
    assert_eq!(row.unit0_trigger, UNIT0_FIRST_BYTES);
    assert_eq!(row.status_at, 0);
    // SAFETY: the row's strings are `'static`.
    let forms = unsafe { row.selector_forms.bytes() };
    assert_eq!(forms.len(), 1);
    assert_eq!(
        forms,
        busbar_contract::abi::sdk::transport::form_codes::<1>(&[SelectorForm::Port])
    );
    assert!(unsafe { row.egress_selector_forms.bytes() }.is_empty());
    assert_eq!(row.facts_len, 1);
}
