// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` transport as a droppable plugin: the cdylib packaged in its signed tarball.

#![deny(unsafe_code)]

pub use busbar_transport_tcp::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_transport_tcp::door);
}
