// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `tcp` DOOR: this transport as an IDENTITY FRAMER on the transport kind's table
//! (`busbar_contract::abi::transport`), compiled in or dropped in through the one door. Every slot
//! is a [`SafeSlot`] over the SDK's generic lifecycle (`life(Framings)`): no `unsafe` in this crate.
//!
//! The socket is the host's (`BUSBAR-1.6.0.md` THE DESIGN, §5): the host dials, accepts, reads
//! and writes it on the calling worker's reactor. This framer composes over nothing, so it frames
//! directly over that socket, and the framing it does is none: a byte stream stays a byte stream.
//!
//! * `ingest` answers the bytes the far side sent as ONE frame on stream `0`, in as many pieces as
//!   the host's sink holds (the last carries `PIECE_END_OF_FRAME`); the far side's end is
//!   `YIELD_ENDED`, since no frame follows on the connection.
//! * `emit` and `refuse` answer the bytes they are handed as the wire bytes, unchanged.
//! * `encode` renders an envelope as its body alone: a byte stream has no head, so an envelope with
//!   fields is refused.
//! * `detach` hands back every byte ingested and not yet answered; `adopt` takes such bytes and
//!   answers them as the connection's first frame.
//! * `locate` reads `host:port` (or `tcp://host:port`) as the authority to dial; nothing is offered
//!   to the far end and no connection security is asked for.
//! * every carrier op (`listen` .. `arrival`) is REFUSED: a framer is not a carrier.
//!
//! No op pends, no op asks for a deadline, and a full sink is back-pressure (`YIELD_MORE`): the host
//! calls again, with no new bytes, once it has drained what it was given.
//!
//! The door wires the kind's own files together: the key and tail [`crate::meta`] declares, the
//! claims [`crate::claims`] declares, and the framer [`crate::transport`] runs.

use busbar_contract::abi::mechanism::call::OutHead;
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::Safe;
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, ArrivalIn, ArrivalOut, ConnIn, ConnOut, DialIn, IoOut, ListenIn,
    ListenOut, Ops, ReadIn, ShutIn, TransportTail, WriteIn,
};

use crate::claims::CLAIM_NAMES;
pub use crate::meta::KEY;
use crate::meta::TAIL;
pub use crate::transport::{
    Adopt, Begin, Detach, Emit, Encode, Finish, Framings, Ingest, Locate, NotACarrier, Refuse,
    Timer,
};

// ── the statement ────────────────────────────────────────────────────────────────────────────────

/// The door's Statement: the `tcp` identity framer.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
    claims: CLAIM_NAMES.as_ptr(),
    claims_len: CLAIM_NAMES.len(),
    ..statement(KEY, env!("CARGO_PKG_VERSION"), 64)
};
busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: life(Framings),
    kind_ops: {
        listen: Safe<NotACarrier<ListenIn, ListenOut>>,
        accept: Safe<NotACarrier<AcceptIn, AcceptOut>>,
        dial: Safe<NotACarrier<DialIn, ConnOut>>,
        read: Safe<NotACarrier<ReadIn, IoOut>>,
        write: Safe<NotACarrier<WriteIn, IoOut>>,
        flush: Safe<NotACarrier<ConnIn, OutHead>>,
        shut: Safe<NotACarrier<ShutIn, OutHead>>,
        arrival: Safe<NotACarrier<ArrivalIn, ArrivalOut>>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Encode>,
        refuse: Safe<Refuse>,
        finish: Safe<Finish>,
        detach: Safe<Detach>,
        adopt: Safe<Adopt>,
        timer: Safe<Timer>,
    },
}
