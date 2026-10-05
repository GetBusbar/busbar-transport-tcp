// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE PUBLISHED CONFORMANCE SUITE, RUN BY THIS PLUGIN** (busbar TODO ABI-b4; OWNER 2026-10-03:
//! plugins test themselves against busbar). busbar's suite, at the commit this repo pins
//! (`.busbar-ref`), drives the `tcp` CARRIER two ways through the one loader: LINKED (the logic
//! crate's `door::door`) and DROPPED IN (this crate's built cdylib), over the transport kind's
//! carrier script with the inputs in `conformance.json`: listen and accept, a dial to an echo far
//! end over the suite's host I/O, a pending read the host's wake resumes, and the host's guard (a
//! dial the host did not admit is refused). Every step's crossings exactly at the script's pin, the
//! two folds equal, and the suite's RED arms kept. `plugin-ci.yml` runs it under `--release`.

busbar_plugin_loader::conformance_suite! {
    door: busbar_transport_tcp::door::door,
    cdylib: "busbar_transport_tcp_plugin",
    inputs: include_str!("conformance.json"),
}
