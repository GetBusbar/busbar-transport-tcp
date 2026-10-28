// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The claims this transport declares: the schemes it answers for and, for each, the selector
//! forms a claim over it may read. A declaration and nothing else, read once at registration.

use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::transport::form_codes;
use busbar_contract::abi::transport::{Claim, UNIT0_FIRST_BYTES};
use busbar_contract::transport::registry::facts as tfacts;
use busbar_contract::SelectorForm;

/// The selector forms a `tcp` claim reads: the port it arrived on.
const SELECTOR_FORMS: &[SelectorForm] = &[SelectorForm::Port];
const SELECTOR_CODES: [u8; SELECTOR_FORMS.len()] = form_codes(SELECTOR_FORMS);

const FACTS: &[AbiStr] = &[abi_str(tfacts::PEER)];

/// The schemes `tcp` claims, by name: the Statement's `claims`, the one place they are stated.
pub(crate) const CLAIM_NAMES: &[AbiStr] = &[abi_str(crate::meta::KEY)];

/// Each claimed scheme's row, by index into [`CLAIM_NAMES`].
pub(crate) const CLAIMS: &[Claim] = &[{
    let mut c = Claim::EMPTY.with_facts(FACTS);
    c.selector_forms = AbiStr::of_bytes(&SELECTOR_CODES);
    c.egress_selector_forms = abi_str("");
    c.status_namespace = crate::meta::NONE;
    c.session = 1;
    c.session_bound = 0;
    c.unit0_trigger = UNIT0_FIRST_BYTES;
    c.status_at = 0;
    c
}];
