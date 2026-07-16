use serde_json::json;
use wardrobe_core::*;

fn retention() -> OpenAiRetentionDeclarationV1 {
    OpenAiRetentionDeclarationV1 {
        mode: OpenAiRetentionModeV1::Default,
        provenance: "personal-project-settings:2026-07-15".to_owned(),
    }
}

fn envelope() -> OutfitRecommendationEnvelopeV1 {
    OutfitRecommendationEnvelopeV1 {
        prompt: "Plan an outfit for dinner".to_owned(),
        credential_id: CredentialId::new_v4(),
        constraints: OutfitRecommendationConstraintsV1 {
            occasion: Some(OutfitOccasionV1::Date),
            temperature_c: Some(18),
            precipitation: Some(OutfitPrecipitationV1::None),
        },
        excluded_item_ids: vec![ItemId::new_v4()],
        requested_proposal_count: 2,
        expected_catalog_revision: 7,
        expected_outfit_revision: 3,
        retention: retention(),
    }
}

#[test]
fn preview_and_request_envelopes_are_schema_v1_and_strict() {
    let preview = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "envelope": envelope()
    });
    assert!(
        serde_json::from_value::<PreviewOutfitRecommendationV1Request>(preview.clone()).is_ok()
    );

    let mut unknown_root = preview.clone();
    unknown_root["send_without_approval"] = json!(true);
    assert!(serde_json::from_value::<PreviewOutfitRecommendationV1Request>(unknown_root).is_err());

    let mut unknown_nested = preview.clone();
    unknown_nested["envelope"]["location"] = json!("home");
    assert!(
        serde_json::from_value::<PreviewOutfitRecommendationV1Request>(unknown_nested).is_err()
    );

    let mut wrong_version = preview;
    wrong_version["schema_version"] = json!(2);
    assert!(serde_json::from_value::<PreviewOutfitRecommendationV1Request>(wrong_version).is_err());

    let request = RequestOutfitRecommendationV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        approval_id: OutfitRecommendationApprovalId::new_v4(),
        envelope: envelope(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn request_values_are_closed_and_bounded() {
    let mut value = envelope();
    value.prompt = "x".repeat(MAX_RECOMMENDATION_PROMPT_CHARS + 1);
    assert_eq!(
        value.validate().unwrap_err().field,
        SafeFieldV1::RecommendationPrompt
    );

    let mut value = envelope();
    value.constraints.temperature_c = Some(MAX_RECOMMENDATION_TEMPERATURE_C + 1);
    assert_eq!(
        value.validate().unwrap_err().field,
        SafeFieldV1::RecommendationConstraints
    );

    let mut value = envelope();
    value.excluded_item_ids = vec![ItemId::new_v4(); 2];
    assert_eq!(
        value.validate().unwrap_err().field,
        SafeFieldV1::RecommendationExclusions
    );

    let mut value = envelope();
    value.requested_proposal_count = MAX_RECOMMENDATION_PROPOSALS + 1;
    assert_eq!(
        value.validate().unwrap_err().field,
        SafeFieldV1::RecommendationConstraints
    );

    let mut value = envelope();
    value.retention.provenance = "contains spaces".to_owned();
    assert_eq!(
        value.validate().unwrap_err().field,
        SafeFieldV1::RecommendationRetention
    );
}

#[test]
fn retention_disclosure_preserves_the_p00_privacy_distinctions() {
    let disclosure = OpenAiRetentionDisclosureV1::for_declaration(retention());
    assert!(disclosure.validate().is_ok());
    assert!(!disclosure.store);
    assert!(disclosure.store_false_is_not_zdr);
    assert_eq!(disclosure.default_abuse_monitoring_max_days, 30);
    assert!(disclosure.safety_review_exceptions_apply);
    assert_eq!(disclosure.prompt_cache_mode, "explicit");
    assert_eq!(disclosure.prompt_cache_breakpoint_count, 0);
    assert!(disclosure.no_breakpoints_no_cache_reads_or_writes);

    let mut invalid = disclosure;
    invalid.store = true;
    assert_eq!(
        invalid.validate().unwrap_err().field,
        SafeFieldV1::RecommendationRetention
    );
}

#[test]
fn cache_policy_violation_usage_remains_valid_audit_evidence() {
    let mut audit = OutfitRecommendationAuditV1 {
        provider: OUTFIT_RECOMMENDATION_PROVIDER_V1.to_owned(),
        model: OUTFIT_RECOMMENDATION_MODEL_V1.to_owned(),
        provider_request_id: Some("req_cache_policy".to_owned()),
        response_id: Some("resp_cache_policy".to_owned()),
        retention: OpenAiRetentionDisclosureV1::for_declaration(retention()),
        reported_cache_usage: true,
        usage: OutfitRecommendationUsageV1 {
            input_tokens: 20,
            output_tokens: 4,
            reasoning_tokens: 1,
            response_calls: 1,
            tool_calls: 0,
            prompt_cache_read_tokens: 7,
            prompt_cache_write_tokens: 3,
        },
    };

    assert!(audit.usage.validate().is_ok());
    assert!(audit.validate().is_ok());

    audit.reported_cache_usage = false;
    assert_eq!(
        audit.validate().unwrap_err().field,
        SafeFieldV1::RecommendationUsage
    );

    audit.reported_cache_usage = true;
    audit.usage.prompt_cache_read_tokens = 0;
    audit.usage.prompt_cache_write_tokens = 0;
    assert_eq!(
        audit.validate().unwrap_err().field,
        SafeFieldV1::RecommendationUsage
    );
}

#[test]
fn capability_tags_use_a_closed_case_sensitive_allowlist() {
    let tags = vec![
        "weather:rain".to_owned(),
        "weather:snow".to_owned(),
        "insulation:cold".to_owned(),
        "Weather:Rain".to_owned(),
        "casual".to_owned(),
        "weather:rain".to_owned(),
    ];
    assert_eq!(
        allowlisted_outfit_capability_tags(&tags),
        vec![
            OutfitCapabilityTagV1::WeatherRain,
            OutfitCapabilityTagV1::WeatherSnow,
            OutfitCapabilityTagV1::InsulationCold,
        ]
    );
    assert!(serde_json::from_str::<OutfitCapabilityTagV1>("\"casual\"").is_err());
}

#[test]
fn tool_registry_is_exactly_four_read_only_strict_functions() {
    let registry = OutfitToolRegistryV1::production();
    assert!(registry.validate().is_ok());
    assert_eq!(registry.tools.len(), 4);
    assert_eq!(
        registry
            .tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "search_confirmed_wardrobe",
            "search_wear_history",
            "get_style_preferences",
            "list_saved_outfits",
        ]
    );
    assert!(registry.tools.iter().all(|tool| {
        tool.capability == ToolCapabilityV1::ReadOnly
            && tool.strict
            && tool.contract_revision == OUTFIT_TOOL_CONTRACT_REVISION_V1
    }));
    assert_eq!(registry.maximum_response_calls, 4);
    assert_eq!(registry.maximum_tool_calls, 12);
    assert_eq!(registry.maximum_transcript_bytes, 512 * 1024);

    let mut changed = registry;
    changed.tools.pop();
    assert_eq!(
        changed.validate().unwrap_err().field,
        SafeFieldV1::RecommendationTool
    );
}

#[test]
fn tool_arguments_and_results_reject_unknown_or_unbounded_data() {
    let arguments = json!({
        "tool": "search_confirmed_wardrobe",
        "arguments": {
            "query": "white shirt",
            "categories": ["top"],
            "capability_tags": ["weather:rain"],
            "limit": 20
        }
    });
    let parsed: OutfitToolArgumentsV1 = serde_json::from_value(arguments.clone()).unwrap();
    assert!(parsed.validate().is_ok());

    let mut unknown = arguments;
    unknown["arguments"]["include_notes"] = json!(true);
    assert!(serde_json::from_value::<OutfitToolArgumentsV1>(unknown).is_err());

    let empty = json!({
        "tool": "get_style_preferences",
        "arguments": {"provider": "remote"}
    });
    assert!(serde_json::from_value::<OutfitToolArgumentsV1>(empty).is_err());

    let result = OutfitToolResultV1::SearchWearHistory {
        status: OutfitToolDataStatusV1::NotConfigured,
        records: vec![OutfitWearRecordV1 {
            item_id: ItemId::new_v4(),
            worn_on: "2026-07-15".to_owned(),
        }],
    };
    assert_eq!(
        result.validate().unwrap_err().field,
        SafeFieldV1::RecommendationTool
    );
}

#[test]
fn proposal_and_outcome_wire_shapes_are_strict_and_typed() {
    let item_ids = vec![ItemId::new_v4(), ItemId::new_v4()];
    let proposal = json!({
        "name": "Dinner separates",
        "item_ids": item_ids,
        "rationale": "A simple confirmed combination.",
        "caveats": [],
        "unresolved_constraints": [],
        "constraint_assessment": [{
            "constraint": "occasion",
            "status": "satisfied",
            "reason": null,
            "caveat": null
        }]
    });
    assert!(serde_json::from_value::<OutfitProposalV1>(proposal.clone()).is_ok());

    let mut unknown = proposal;
    unknown["confidence"] = json!(0.9);
    assert!(serde_json::from_value::<OutfitProposalV1>(unknown).is_err());

    let refusal = json!({
        "outcome": "refused",
        "audit": {
            "provider": "openai",
            "model": "gpt-5.6-sol",
            "provider_request_id": null,
            "response_id": null,
            "retention": OpenAiRetentionDisclosureV1::for_declaration(retention()),
            "reported_cache_usage": false,
            "usage": {
                "input_tokens": 1,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "response_calls": 1,
                "tool_calls": 0,
                "prompt_cache_read_tokens": 0,
                "prompt_cache_write_tokens": 0
            }
        }
    });
    assert!(serde_json::from_value::<OutfitRecommendationOutcomeV1>(refusal).is_ok());
}

#[test]
fn recommendation_types_are_exported_to_typescript() {
    let bindings = typescript_bindings();
    for name in [
        "OutfitRecommendationEnvelopeV1",
        "PreviewOutfitRecommendationV1Request",
        "RequestOutfitRecommendationV1Request",
        "OutfitToolRegistryV1",
        "OutfitToolArgumentsV1",
        "StructuredOutfitRecommendationV1",
        "OutfitRecommendationOutcomeV1",
    ] {
        assert!(bindings.contains(name), "missing {name}");
    }
}
