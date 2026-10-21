// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tcp` DOOR: this transport as a CARRIER on the transport kind's table
//! (`busbar_contract::abi::transport`), compiled in or dropped in through the one door. Every slot
//! is a [`SafeSlot`](busbar_contract::abi::sdk::SafeSlot) over the SDK's generic lifecycle
//! (`life(Carried)`): no `unsafe` in this crate.
//!
//! The socket is the host's (`BUSBAR-1.6.0.md` THE DESIGN, §5): this carrier listens, accepts,
//! dials, reads, writes and closes through the host's I/O (`io.*`), holding only the host's opaque
//! handles, and owns the policy over them ([`crate::transport`]). Every framer op (`locate` ..
//! `timer`) is REFUSED: a carrier frames nothing.
//!
//! The door wires the kind's own files together: the key and tail [`crate::meta`] declares, the
//! claims [`crate::claims`] declares, and the carrier [`crate::transport`] runs.

use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::Safe;
use busbar_contract::abi::transport::{
    AdoptIn, BeginIn, EmitIn, EncodeIn, FinishIn, FramerOut, FramingIn, IngestIn, LocateIn,
    LocateOut, Ops, RefuseIn,
};

use crate::claims::CLAIM_NAMES;
pub use crate::meta::KEY;
use crate::meta::TAIL;
pub use crate::transport::{
    Accept, Arrival, Carried, Dial, Flush, Listen, NotAFramer, Read, Shut, Write,
};

// ── the statement ────────────────────────────────────────────────────────────────────────────────

busbar_contract::statement_extensions!(
    /// The Statement's extensions: this plugin's whole `declares` document (BUSBAR-1.6.0.md l.246).
    EXTENSIONS: [(
        busbar_contract::abi::mechanism::extensions::EXT_DECLARES,
        include_bytes!("../declares.json")
    )]
);

/// The door's Statement: the `tcp` carrier.
pub const STATEMENT: Statement = {
    let mut s = statement(KEY, env!("CARGO_PKG_VERSION"), 64)
        .with_kind_tail(&TAIL)
        .with_claims(CLAIM_NAMES);
    s.extensions = EXTENSIONS;
    s
};
busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: life(Carried),
    kind_ops: {
        listen: Safe<Listen>,
        accept: Safe<Accept>,
        dial: Safe<Dial>,
        read: Safe<Read>,
        write: Safe<Write>,
        flush: Safe<Flush>,
        shut: Safe<Shut>,
        arrival: Safe<Arrival>,
        locate: Safe<NotAFramer<LocateIn, LocateOut>>,
        begin: Safe<NotAFramer<BeginIn, FramerOut>>,
        ingest: Safe<NotAFramer<IngestIn, FramerOut>>,
        emit: Safe<NotAFramer<EmitIn, FramerOut>>,
        encode: Safe<NotAFramer<EncodeIn, FramerOut>>,
        refuse: Safe<NotAFramer<RefuseIn, FramerOut>>,
        finish: Safe<NotAFramer<FinishIn, FramerOut>>,
        detach: Safe<NotAFramer<FramingIn, FramerOut>>,
        adopt: Safe<NotAFramer<AdoptIn, FramerOut>>,
        timer: Safe<NotAFramer<FramingIn, FramerOut>>,
    },
}
