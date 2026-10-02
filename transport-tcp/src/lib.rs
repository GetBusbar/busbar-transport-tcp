// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `tcp` transport: a byte stream, and nothing else.
//!
//! The socket is the host's (`BUSBAR-1.6.0.md` THE DESIGN, §5): the host dials, accepts, reads
//! and writes it, with its readiness on the calling worker's reactor, and wraps it in connection
//! security where a binding asks for it. This crate is the framer that sits on that socket, an
//! IDENTITY framer ([`door`]): the bytes the far side sent are the frames, and the bytes handed to
//! it are the wire. It opens no socket, spawns no thread and reads no clock. It knows no protocol,
//! no plane and no principal.
//!
//! One door, two ways in: a build that links this crate names [`linked::door`]; the sibling
//! `busbar-transport-tcp-plugin` cdylib exports the same door as its image's one symbol
//! (`export_door!`). This crate exports nothing, so linking it adds no door symbol.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod door;

/// THE TRANSPORT AXIS ENTRY: what the composition root folds for this transport: its key, the
/// layers it declares and its door. The root names none of them.
pub mod linked {
    /// The row's registry key.
    pub const KEY: &str = crate::door::KEY;
    /// The layers this transport declares it can be built over: none, it frames the host's socket.
    pub const COMPOSES_OVER: &[&str] = &[];
    /// Whether this transport carries sessions.
    pub const SESSION: bool = true;
    pub use crate::door::door;
}
