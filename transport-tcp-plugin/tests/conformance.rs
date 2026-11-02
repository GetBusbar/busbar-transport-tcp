// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN** (busbar TODO ABI-b4; OWNER 2026-10-03:

use busbar_plugin_loader::dispatch::LinkedRow;

busbar_test_kit::conformance_suite! {
    door: busbar_transport_tcp::door,
    cdylib: "busbar_transport_tcp_plugin",
    inputs: include_str!("conformance.json"),
}

#[test]
fn the_statement_carries_the_declares_document() {
    let row = LinkedRow::of(busbar_transport_tcp::door).unwrap();
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    assert_eq!(
        busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes),
        Some(&include_bytes!("../../transport-tcp/declares.json")[..]),
    );
}
