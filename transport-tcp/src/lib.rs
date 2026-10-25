// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` transport: a byte stream, and nothing else.
//!
//! The socket is the host's (`BUSBAR-1.6.0.md` THE DESIGN, §5): no plugin opens a socket. This
//! crate is the CARRIER of that stream ([`door`]): it listens, accepts, dials, reads, writes and
//! closes through the host's I/O (`io.*`), holding only the host's opaque handles under tokens it
//! mints, and owns the policy over them: a dial reaches only an authority, never a program; it
//! opens the one judged address it is lent (an IP literal or a `unix:` path, never a name it would
//! resolve), once; the dial settles under `flush`, and a refused one is closed and forgotten; a
//! `shut` closes its connection whatever the reason. Each `accept` takes the one connection the
//! host has ready (the host drives the accepting); each `read` answers what the host reads off
//! the socket, straight into the host's buffer, as one frame of the stream; each `write` hands the
//! host what it is offered. Connection security and any framing above the stream are the host's to
//! stack on it. It spawns no thread and reads no clock.
//! It knows no protocol, no plane and no principal.
//!
//! One door, two ways in: a build that links this crate names [`linked::door`]; the sibling
//! `busbar-transport-tcp-plugin` cdylib exports the same door as its image's one symbol
//! (`export_door!`). This crate exports nothing, so linking it adds no door symbol.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// THE KIND'S SHAPE (`BUSBAR-1.6.0.md` THE DESIGN, §2), the same files every transport twin
// carries: what it declares (`meta`), what it claims (`claims`), the entry (`transport`), and the
// door that states them.
mod claims;
mod door;
mod meta;
mod transport;

/// THE DOOR (BUSBAR-1.6.0.md l.3567, Crate shape): the one entry, linked here and exported by the
/// dropped-in build alike.
pub use door::door;

/// THE TRANSPORT AXIS ENTRY: what the composition root folds for this transport: its key, the
/// layers it declares and its door. The root names none of them.
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
