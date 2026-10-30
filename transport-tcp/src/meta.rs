// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What this transport declares about itself: the key it answers on and the transport kind's tail
//! its door states. Read once at registration and sealed, so it is data, held apart from the
//! carrier code it describes.

use busbar_contract::abi::transport::{
    TransportTail, FRAME_PIECE_SIZE, FRAMING_STREAM, ROLE_CARRIER,
};

/// The claim this entry answers for.
pub const KEY: &str = "tcp";

/// The layers this carrier is built over: none, it is the bottom of its stack.
pub(crate) const COMPOSES_OVER: &[&str] = &[];

/// Whether this transport carries sessions (its claim row states `session = 1`).
pub(crate) const SESSION: bool = true;

/// The transport kind's tail: the CARRIER of the host's byte stream (the connector carries a tcp
/// need as a raw stream, frames no opening message for it, and may secure it mid-way), composing
/// over nothing.
pub(crate) const TAIL: TransportTail = {
    let mut t = TransportTail::EMPTY.with_claim_rows(crate::claims::CLAIMS);
    t.role = ROLE_CARRIER;
    t.framing = FRAMING_STREAM;
    t.frame_piece_size = FRAME_PIECE_SIZE;
    t
};
