// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN** (busbar TODO ABI-b4; OWNER 2026-10-03:
//! plugins test themselves against busbar). busbar's suite, at the commit this repo pins
//! (`.busbar-ref`), drives the `tcp` CARRIER two ways through the one loader: LINKED (the logic
//! crate's `door`) and DROPPED IN (this crate's built cdylib), over the transport kind's
//! carrier script with the inputs in `conformance.json`: listen and accept, a dial to an echo far
//! end over the suite's host I/O, a pending read the host's wake resumes, and the host's guard (a
//! dial the host did not admit is refused). Every step's crossings exactly at the script's pin, the
//! two folds equal, and the suite's RED arms kept. `plugin-ci.yml` runs it under `--release`.

use busbar_plugin_loader::dispatch::{LinkedRow, LoadedDoor};

/// This plugin's own door, named for the loader.
fn loaded_door() -> LoadedDoor {
    // SAFETY: `busbar_transport_tcp::door` is this crate's own door: it answers the `'static` door
    // of this plugin.
    #[allow(unused_unsafe)]
    let loaded = unsafe { LoadedDoor::from_raw(busbar_transport_tcp::door) };
    loaded
}

busbar_plugin_loader::conformance_suite! {
    loaded: loaded_door(),
    cdylib: "busbar_transport_tcp_plugin",
    inputs: include_str!("conformance.json"),
}

#[test]
fn the_statement_carries_the_declares_document() {
    let row = LinkedRow::of_loaded(loaded_door()).unwrap();
    let read = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    assert_eq!(
        busbar_contract::abi::mechanism::extensions::declares(&read.extensions.bytes),
        Some(&include_bytes!("../../transport-tcp/declares.json")[..]),
    );
}
