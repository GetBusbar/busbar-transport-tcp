// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` transport: a byte stream, and nothing else.
//!
//! The socket is the host's (`BUSBAR-1.6.0.md` THE DESIGN, §5): no plugin opens a socket. This
//! crate is the CARRIER of that stream ([`door`]): it listens, accepts, dials, reads, writes and
//! closes through the host's I/O (`io.*`), holding only the host's opaque handles, and owns the
//! policy over them — one attempt at the one judged address a dial is lent, the accept loop, the chunking
//! of what it reads, how a connection closes and what its far end is. Connection security and any
//! framing above the stream are the host's to stack on it. It spawns no thread and reads no clock.
//! It knows no protocol, no plane and no principal.
//!
//! One door, two ways in: a build that links this crate names [`door`]; the sibling
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

/// THE DOOR: this plugin's one public item (BUSBAR-1.6.0.md l.3567, Crate shape).
pub use door::door;

#[cfg(test)]
#[path = "tests/resolve_tests.rs"]
mod resolve_tests;
