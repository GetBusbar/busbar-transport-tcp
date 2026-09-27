// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **`tcp` transport as a droppable busbar plugin** — the `cdylib` a signed tarball of the wire
//! carries (`kind: transport`, key `tcp`).
//!
//! All the carrier lives in the `busbar-transport-tcp` crate, including its one door registration
//! (`busbar_contract::export_carrier!`, compiled under that crate's `dropped-in` feature, which
//! this crate turns on): the frozen symbols the loader looks up are the contract's, defined once, and
//! they answer through that door. This crate re-exports the wire so the library it builds carries
//! exactly the code the busbar binary links — one source, both doors (#3, DECISIONS #2 rule (1)).

#![deny(unsafe_code)]

pub use busbar_transport_tcp::*;
