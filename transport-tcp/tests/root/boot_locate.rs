// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn registered_foreign_provider_claim_uses_its_declaration_and_duplicates_refuse() {
    use busbar_contract::abi::mechanism::door::{Door, DoorFn};
    use busbar_contract::abi::sdk::test_support::RestatedTransport;
    use busbar_contract::abi::transport::ROLE_CARRIER;
    // Restate the actual carrier through its sealed SDK factory, preserving its operations.
    extern "C" fn foreign() -> &'static Door {
        static ONE: RestatedTransport = RestatedTransport::new();
        let source = busbar_transport_tcp::linked::MACRO_DOOR;
        let facts = crate::root::loader::dispatch::kinds::transport::linked_facts(source.door_fn())
            .expect("the actual carrier has a valid declaration");
        assert_eq!(facts.role, ROLE_CARRIER);
        assert!(facts.ported);
        let claims: Vec<_> = (0..facts.claims.len())
            .map(|index| {
                if index == 0 {
                    "foreign-c6".to_string()
                } else {
                    format!("foreign-c6-{index}")
                }
            })
            .collect();
        let claims: Vec<_> = claims.iter().map(String::as_str).collect();
        ONE.get_or_init(source, &claims, &[])
    }
    let rows: Arc<dyn PluginRows> = Arc::new(PluginRegistry::empty());
    let door = foreign as DoorFn;
    let target = "foreign-c6://127.0.0.1:9443";
    let located = locate_provider_destination_with(&rows, target, &[("foreign", door)])
        .expect("registered foreign claim selects the actual carrier declaration");
    assert_eq!(located.authority, "127.0.0.1:9443");
    assert!(
        !located.secure,
        "a carrier authority cannot invent transport security"
    );
    let refused = locate_provider_destination_with(&rows, target, &[("one", door), ("two", door)])
        .expect_err("ambiguous declaration claims refuse before locate");
    assert!(
        refused.contains("multiple admitted transports claim 'foreign-c6'"),
        "{refused}"
    );
}
