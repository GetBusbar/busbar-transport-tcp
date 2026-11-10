// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` transport: a byte stream, and nothing else.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod claims;
mod door;
mod meta;
mod transport;

/// The door: the one entry, linked here and exported by the dropped-in build alike.
pub use door::{door, MACRO_DOOR};

/// The transport axis entry: its key, supported lower layers, session support, and door.
pub mod linked {
    /// The row's registry key.
    pub const KEY: &str = crate::meta::KEY;
    /// The layers this transport declares it can be built over: none, it is the bottom of its stack.
    pub const COMPOSES_OVER: &[&str] = crate::meta::COMPOSES_OVER;
    /// Whether this transport carries sessions.
    pub const SESSION: bool = crate::meta::SESSION;
    pub use crate::door::{door, MACRO_DOOR};
}

#[cfg(test)]
#[path = "tests/resolve_tests.rs"]
mod resolve_tests;

// Source-owned integration tests are compiled only by the assembling host test harness.
