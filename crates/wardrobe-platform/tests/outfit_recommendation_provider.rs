#[path = "../src/outfit_recommendation_http.rs"]
mod outfit_recommendation_http;

mod outfit_recommendation_repository {
    pub use wardrobe_platform::OutfitRecommendationToolSnapshot;
}

#[path = "../src/outfit_recommendation_provider.rs"]
mod outfit_recommendation_provider;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use outfit_recommendation_http::{
    OpenAiResponsesHttpError, OpenAiResponsesHttpTransport, OPENAI_REQUEST_LIMIT_BYTES,
};
use outfit_recommendation_provider::OpenAiOutfitRecommendationProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use url::Url;
use wardrobe_core::{
    CredentialId, ItemCategoryV1, ItemId, OpenAiRetentionDeclarationV1, OpenAiRetentionModeV1,
    OutfitId, OutfitRecommendationApprovalId, OutfitRecommendationConstraintsV1,
    OutfitRecommendationFailureCodeV1, OutfitRecommendationOutcomeV1,
    OutfitRecommendationSnapshotItemV1, OutfitRecommendationSnapshotV1, OutfitToolSavedOutfitV1,
    OutfitToolWardrobeItemV1, RequestId, RequestOutfitRecommendationV1Request, SecretString,
    OUTFIT_CAPABILITY_REVISION_V1, OUTFIT_COMPATIBILITY_REVISION_V1,
    OUTFIT_RECOMMENDATION_SCHEMA_REVISION_V1, SCHEMA_VERSION_V1,
};
use wardrobe_platform::OutfitRecommendationToolSnapshot;

#[tokio::test]
async fn stateless_multi_round_loop_replays_exact_items_and_returns_grounded_result() {
    let fixture_data = FixtureData::new();
    let reasoning = json!({
        "id": "rs_1",
        "type": "reasoning",
        "summary": [],
        "encrypted_content": "encrypted-reasoning-sentinel"
    });
    let calls = vec![
        function_call(
            "fc_search",
            "call_search",
            "search_confirmed_wardrobe",
            json!({
                "query": null,
                "categories": [],
                "capability_tags": [],
                "limit": 100
            }),
        ),
        function_call(
            "fc_wear",
            "call_wear",
            "search_wear_history",
            json!({"item_ids": [fixture_data.top.to_string()], "limit": 10}),
        ),
        function_call(
            "fc_preferences",
            "call_preferences",
            "get_style_preferences",
            json!({}),
        ),
        function_call(
            "fc_outfits",
            "call_outfits",
            "list_saved_outfits",
            json!({"query": null, "limit": 10}),
        ),
    ];
    let mut first_output = vec![reasoning.clone()];
    first_output.extend(calls.iter().cloned());
    let proposal = valid_proposal(&fixture_data, [fixture_data.top, fixture_data.bottom]);
    let fixture = TlsFixture::start(vec![
        completed_response("resp_tools", first_output, usage(10, 3, 2, 0)),
        completed_response(
            "resp_final",
            vec![output_message(proposal)],
            usage(20, 8, 4, 0),
        ),
    ])
    .await;
    let provider = OpenAiOutfitRecommendationProvider::new(fixture.transport().unwrap());
    let request = fixture_data.request();
    let secret = SecretString::new("sk-provider-test".to_owned());

    let response = provider
        .recommend(&secret, &request, &fixture_data.snapshot())
        .await;
    let requests = fixture.finish().await;

    let (recommendation, audit) = match response.outcome {
        OutfitRecommendationOutcomeV1::Completed {
            recommendation,
            audit,
        } => (recommendation, audit),
        _ => panic!("expected completed recommendation"),
    };
    assert_eq!(
        recommendation.proposals[0].item_ids,
        vec![fixture_data.top, fixture_data.bottom]
    );
    assert_eq!(audit.usage.input_tokens, 30);
    assert_eq!(audit.usage.output_tokens, 11);
    assert_eq!(audit.usage.reasoning_tokens, 6);
    assert_eq!(audit.usage.response_calls, 2);
    assert_eq!(audit.usage.tool_calls, 4);
    assert_eq!(audit.usage.prompt_cache_read_tokens, 0);
    assert_eq!(audit.usage.prompt_cache_write_tokens, 0);
    assert_eq!(audit.provider_request_id.as_deref(), Some("req_fixture_2"));
    assert_eq!(audit.response_id.as_deref(), Some("resp_final"));

    assert_eq!(requests.len(), 2);
    let first = request_json(&requests[0]);
    assert_eq!(first["model"], "gpt-5.6-sol");
    assert_eq!(first["store"], false);
    assert_eq!(first["include"], json!(["reasoning.encrypted_content"]));
    assert_eq!(first["prompt_cache_options"], json!({"mode": "explicit"}));
    assert!(first.get("previous_response_id").is_none());
    assert!(first.get("conversation").is_none());
    assert!(first["prompt_cache_options"].get("breakpoints").is_none());
    assert_eq!(first["text"]["format"]["type"], "json_schema");
    assert_eq!(first["text"]["format"]["strict"], true);
    let tools = first["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4);
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "search_confirmed_wardrobe",
            "search_wear_history",
            "get_style_preferences",
            "list_saved_outfits"
        ]
    );
    assert!(tools.iter().all(|tool| tool["strict"] == true));

    let second = request_json(&requests[1]);
    let first_input = first["input"].as_array().unwrap();
    let second_input = second["input"].as_array().unwrap();
    assert_eq!(&second_input[..2], first_input);
    assert_eq!(second_input[2], reasoning);
    for (index, call) in calls.iter().enumerate() {
        let call_index = 3 + index;
        let output_index = 3 + calls.len() + index;
        assert_eq!(&second_input[call_index], call);
        assert_eq!(second_input[output_index]["type"], "function_call_output");
        assert_eq!(second_input[output_index]["call_id"], call["call_id"]);
    }
    let wardrobe_output: Value =
        serde_json::from_str(second_input[7]["output"].as_str().unwrap()).unwrap();
    let wardrobe_wire = wardrobe_output.to_string();
    assert!(wardrobe_wire.contains("private-green-shirt"));
    assert!(wardrobe_wire.contains("private-black-trousers"));
    assert!(!wardrobe_wire.contains("excluded-personal-sentinel"));
    assert!(!wardrobe_wire.contains("inactive-personal-sentinel"));
    let wear_output: Value =
        serde_json::from_str(second_input[8]["output"].as_str().unwrap()).unwrap();
    let preference_output: Value =
        serde_json::from_str(second_input[9]["output"].as_str().unwrap()).unwrap();
    assert_eq!(wear_output["result"]["status"], "not_configured");
    assert_eq!(preference_output["result"]["status"], "not_configured");

    let audit_wire = serde_json::to_string(&audit).unwrap();
    assert!(!audit_wire.contains("private-green-shirt"));
    assert!(!audit_wire.contains("date-personal-prompt"));
    assert!(audit_wire.contains("credential-personal-provenance"));
    let all_wire = requests.join("\n");
    assert!(!all_wire.contains(&request.envelope.credential_id.to_string()));
    assert!(!all_wire.contains("credential-personal-provenance"));
    assert!(!all_wire.contains("excluded-personal-sentinel"));
    assert!(!all_wire.contains("inactive-personal-sentinel"));
}

#[tokio::test]
async fn refusal_and_incomplete_are_distinct_terminal_outcomes() {
    let data = FixtureData::new();
    let refusal_fixture = TlsFixture::start(vec![completed_response(
        "resp_refusal",
        vec![json!({
            "id": "msg_refusal",
            "type": "message",
            "role": "assistant",
            "status": "completed",
            "content": [{"type": "refusal", "refusal": "sensitive refusal text"}]
        })],
        usage(2, 1, 0, 0),
    )])
    .await;
    let provider = OpenAiOutfitRecommendationProvider::new(refusal_fixture.transport().unwrap());
    let outcome = provider
        .recommend(
            &SecretString::new("sk-test".to_owned()),
            &data.request(),
            &data.snapshot(),
        )
        .await
        .outcome;
    refusal_fixture.finish().await;
    let audit = match outcome {
        OutfitRecommendationOutcomeV1::Refused { audit } => audit,
        _ => panic!("expected refusal"),
    };
    assert!(!serde_json::to_string(&audit)
        .unwrap()
        .contains("sensitive refusal text"));

    let incomplete_fixture = TlsFixture::start(vec![json!({
        "id": "resp_incomplete",
        "model": "gpt-5.6-sol",
        "status": "incomplete",
        "incomplete_details": {"reason": "max_output_tokens"},
        "output": [],
        "usage": usage(3, 4, 1, 0)
    })])
    .await;
    let provider = OpenAiOutfitRecommendationProvider::new(incomplete_fixture.transport().unwrap());
    let response = provider
        .recommend(
            &SecretString::new("sk-test".to_owned()),
            &data.request(),
            &data.snapshot(),
        )
        .await;
    incomplete_fixture.finish().await;
    assert_eq!(
        failure_code(&response.outcome),
        Some(OutfitRecommendationFailureCodeV1::Incomplete)
    );
}

#[tokio::test]
async fn malformed_output_and_grounding_failures_are_typed_after_a_real_tool_round() {
    let data = FixtureData::new();
    let search = function_call(
        "fc_search",
        "call_search",
        "search_confirmed_wardrobe",
        json!({
            "query": null,
            "categories": [],
            "capability_tags": [],
            "limit": 100
        }),
    );
    for (final_message, expected) in [
        (
            json!({
                "id": "msg_bad_json",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [{"type": "output_text", "text": "{not-json"}]
            }),
            OutfitRecommendationFailureCodeV1::MalformedOutput,
        ),
        (
            output_message(valid_proposal(&data, [data.top, ItemId::new_v4()])),
            OutfitRecommendationFailureCodeV1::Grounding,
        ),
    ] {
        let fixture = TlsFixture::start(vec![
            completed_response("resp_search", vec![search.clone()], usage(1, 1, 0, 0)),
            completed_response("resp_final", vec![final_message], usage(1, 1, 0, 0)),
        ])
        .await;
        let provider = OpenAiOutfitRecommendationProvider::new(fixture.transport().unwrap());
        let response = provider
            .recommend(
                &SecretString::new("sk-test".to_owned()),
                &data.request(),
                &data.snapshot(),
            )
            .await;
        fixture.finish().await;
        assert_eq!(failure_code(&response.outcome), Some(expected));
    }
}

#[tokio::test]
async fn unknown_tools_malformed_arguments_and_duplicate_call_ids_are_rejected() {
    let data = FixtureData::new();
    let cases = vec![
        vec![function_call(
            "fc_unknown",
            "call_unknown",
            "read_arbitrary_files",
            json!({}),
        )],
        vec![function_call(
            "fc_bad_args",
            "call_bad_args",
            "search_confirmed_wardrobe",
            json!({
                "query": null,
                "categories": [],
                "capability_tags": [],
                "limit": 10,
                "unexpected": true
            }),
        )],
        vec![
            function_call(
                "fc_one",
                "call_duplicate",
                "search_confirmed_wardrobe",
                json!({
                    "query": null,
                    "categories": [],
                    "capability_tags": [],
                    "limit": 10
                }),
            ),
            function_call(
                "fc_two",
                "call_duplicate",
                "get_style_preferences",
                json!({}),
            ),
        ],
    ];
    for output in cases {
        let fixture = TlsFixture::start(vec![completed_response(
            "resp_protocol",
            output,
            usage(1, 1, 0, 0),
        )])
        .await;
        let provider = OpenAiOutfitRecommendationProvider::new(fixture.transport().unwrap());
        let response = provider
            .recommend(
                &SecretString::new("sk-test".to_owned()),
                &data.request(),
                &data.snapshot(),
            )
            .await;
        fixture.finish().await;
        assert_eq!(
            failure_code(&response.outcome),
            Some(OutfitRecommendationFailureCodeV1::ToolProtocol)
        );
    }
}

#[tokio::test]
async fn tool_response_and_transcript_limits_are_enforced_without_extra_requests() {
    let data = FixtureData::new();
    let thirteen_calls = (0..13)
        .map(|index| {
            function_call(
                &format!("fc_{index}"),
                &format!("call_{index}"),
                "search_confirmed_wardrobe",
                json!({
                    "query": null,
                    "categories": [],
                    "capability_tags": [],
                    "limit": 1
                }),
            )
        })
        .collect();
    let fixture = TlsFixture::start(vec![completed_response(
        "resp_too_many_tools",
        thirteen_calls,
        usage(1, 1, 0, 0),
    )])
    .await;
    let provider = OpenAiOutfitRecommendationProvider::new(fixture.transport().unwrap());
    let response = provider
        .recommend(
            &SecretString::new("sk-test".to_owned()),
            &data.request(),
            &data.snapshot(),
        )
        .await;
    let requests = fixture.finish().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        failure_code(&response.outcome),
        Some(OutfitRecommendationFailureCodeV1::ToolLimit)
    );

    let search = function_call(
        "fc_large",
        "call_large",
        "search_confirmed_wardrobe",
        json!({
            "query": null,
            "categories": [],
            "capability_tags": [],
            "limit": 1
        }),
    );
    let fixture = TlsFixture::start(vec![completed_response(
        "resp_large",
        vec![
            json!({
                "id": "rs_large_one",
                "type": "reasoning",
                "summary": [],
                "encrypted_content": "a".repeat(300 * 1024)
            }),
            json!({
                "id": "rs_large_two",
                "type": "reasoning",
                "summary": [],
                "encrypted_content": "b".repeat(300 * 1024)
            }),
            search,
        ],
        usage(1, 1, 0, 0),
    )])
    .await;
    let provider = OpenAiOutfitRecommendationProvider::new(fixture.transport().unwrap());
    let response = provider
        .recommend(
            &SecretString::new("sk-test".to_owned()),
            &data.request(),
            &data.snapshot(),
        )
        .await;
    let requests = fixture.finish().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        failure_code(&response.outcome),
        Some(OutfitRecommendationFailureCodeV1::ToolLimit)
    );
}

#[tokio::test]
async fn four_response_call_limit_is_enforced() {
    let data = FixtureData::new();
    let rounds = (0..4)
        .map(|index| {
            completed_response(
                &format!("resp_{index}"),
                vec![function_call(
                    &format!("fc_{index}"),
                    &format!("call_{index}"),
                    "search_confirmed_wardrobe",
                    json!({
                        "query": null,
                        "categories": [],
                        "capability_tags": [],
                        "limit": 1
                    }),
                )],
                usage(1, 1, 0, 0),
            )
        })
        .collect();
    let fixture = TlsFixture::start(rounds).await;
    let provider = OpenAiOutfitRecommendationProvider::new(fixture.transport().unwrap());
    let response = provider
        .recommend(
            &SecretString::new("sk-test".to_owned()),
            &data.request(),
            &data.snapshot(),
        )
        .await;
    let requests = fixture.finish().await;
    assert_eq!(requests.len(), 4);
    assert_eq!(
        failure_code(&response.outcome),
        Some(OutfitRecommendationFailureCodeV1::ToolLimit)
    );
}

#[tokio::test]
async fn cache_policy_violations_fail_with_content_free_reported_usage_audits() {
    let data = FixtureData::new();
    let refusal_fixture = TlsFixture::start(vec![completed_response(
        "resp_cached_refusal",
        vec![json!({
            "id": "msg_cached_refusal",
            "type": "message",
            "role": "assistant",
            "status": "completed",
            "content": [{
                "type": "refusal",
                "refusal": "cache-refusal-content-sentinel"
            }]
        })],
        usage_with_cache(5, 2, 1, 3, 0),
    )])
    .await;
    let provider = OpenAiOutfitRecommendationProvider::new(refusal_fixture.transport().unwrap());
    let response = provider
        .recommend(
            &SecretString::new("sk-test".to_owned()),
            &data.request(),
            &data.snapshot(),
        )
        .await;
    refusal_fixture.finish().await;
    let audit = cache_policy_failure_audit(response.outcome);
    assert!(audit.reported_cache_usage);
    assert_eq!(audit.usage.prompt_cache_read_tokens, 3);
    assert_eq!(audit.usage.prompt_cache_write_tokens, 0);
    assert_eq!(audit.usage.response_calls, 1);
    assert_eq!(audit.response_id.as_deref(), Some("resp_cached_refusal"));
    assert!(!serde_json::to_string(&audit)
        .unwrap()
        .contains("cache-refusal-content-sentinel"));

    let search = function_call(
        "fc_search_before_cache",
        "call_search_before_cache",
        "search_confirmed_wardrobe",
        json!({
            "query": null,
            "categories": [],
            "capability_tags": [],
            "limit": 100
        }),
    );
    let mut proposal = valid_proposal(&data, [data.top, data.bottom]);
    proposal["proposals"][0]["rationale"] = json!("cache-output-content-sentinel");
    let completion_fixture = TlsFixture::start(vec![
        completed_response("resp_search", vec![search], usage(2, 1, 0, 0)),
        completed_response(
            "resp_cached_output",
            vec![output_message(proposal)],
            usage_with_cache(7, 3, 2, 0, 4),
        ),
    ])
    .await;
    let provider = OpenAiOutfitRecommendationProvider::new(completion_fixture.transport().unwrap());
    let response = provider
        .recommend(
            &SecretString::new("sk-test".to_owned()),
            &data.request(),
            &data.snapshot(),
        )
        .await;
    completion_fixture.finish().await;
    let audit = cache_policy_failure_audit(response.outcome);
    assert!(audit.reported_cache_usage);
    assert_eq!(audit.usage.input_tokens, 9);
    assert_eq!(audit.usage.output_tokens, 4);
    assert_eq!(audit.usage.reasoning_tokens, 2);
    assert_eq!(audit.usage.prompt_cache_read_tokens, 0);
    assert_eq!(audit.usage.prompt_cache_write_tokens, 4);
    assert_eq!(audit.usage.response_calls, 2);
    assert_eq!(audit.usage.tool_calls, 1);
    assert_eq!(audit.response_id.as_deref(), Some("resp_cached_output"));
    assert!(!serde_json::to_string(&audit)
        .unwrap()
        .contains("cache-output-content-sentinel"));

    let incomplete_fixture = TlsFixture::start(vec![json!({
        "id": "resp_cached_incomplete",
        "model": "gpt-5.6-sol",
        "status": "incomplete",
        "output": [],
        "usage": usage_with_cache(11, 1, 0, 2, 5)
    })])
    .await;
    let provider = OpenAiOutfitRecommendationProvider::new(incomplete_fixture.transport().unwrap());
    let response = provider
        .recommend(
            &SecretString::new("sk-test".to_owned()),
            &data.request(),
            &data.snapshot(),
        )
        .await;
    incomplete_fixture.finish().await;
    let audit = cache_policy_failure_audit(response.outcome);
    assert!(audit.reported_cache_usage);
    assert_eq!(audit.usage.prompt_cache_read_tokens, 2);
    assert_eq!(audit.usage.prompt_cache_write_tokens, 5);
    assert_eq!(audit.response_id.as_deref(), Some("resp_cached_incomplete"));
}

fn cache_policy_failure_audit(
    outcome: OutfitRecommendationOutcomeV1,
) -> wardrobe_core::OutfitRecommendationAuditV1 {
    match outcome {
        OutfitRecommendationOutcomeV1::Failed {
            code: OutfitRecommendationFailureCodeV1::ToolProtocol,
            retryable: false,
            audit: Some(audit),
        } => audit,
        _ => panic!("expected non-retryable cache-policy failure with audit"),
    }
}

fn usage_with_cache(
    input: u32,
    output: u32,
    reasoning: u32,
    cache_read: u32,
    cache_write: u32,
) -> Value {
    json!({
        "input_tokens": input,
        "input_tokens_details": {
            "cached_tokens": cache_read,
            "cache_write_tokens": cache_write
        },
        "output_tokens": output,
        "output_tokens_details": {"reasoning_tokens": reasoning},
        "total_tokens": input + output
    })
}

fn usage(input: u32, output: u32, reasoning: u32, cached: u32) -> Value {
    usage_with_cache(input, output, reasoning, cached, 0)
}

fn function_call(id: &str, call_id: &str, name: &str, arguments: Value) -> Value {
    json!({
        "id": id,
        "type": "function_call",
        "call_id": call_id,
        "name": name,
        "arguments": arguments.to_string(),
        "status": "completed"
    })
}

fn output_message(value: Value) -> Value {
    json!({
        "id": "msg_final",
        "type": "message",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": value.to_string()}]
    })
}

fn completed_response(id: &str, output: Vec<Value>, usage: Value) -> Value {
    json!({
        "id": id,
        "model": "gpt-5.6-sol",
        "status": "completed",
        "output": output,
        "usage": usage
    })
}

fn valid_proposal<const N: usize>(data: &FixtureData, item_ids: [ItemId; N]) -> Value {
    let item_ids = item_ids.into_iter().collect::<Vec<_>>();
    json!({
        "schema_revision": OUTFIT_RECOMMENDATION_SCHEMA_REVISION_V1,
        "compatibility_revision": OUTFIT_COMPATIBILITY_REVISION_V1,
        "capability_revision": OUTFIT_CAPABILITY_REVISION_V1,
        "catalog_revision": data.catalog_revision,
        "outfit_revision": data.outfit_revision,
        "proposals": [{
            "name": "Grounded outfit",
            "item_ids": item_ids,
            "rationale": "These confirmed items form a coherent outfit.",
            "caveats": [],
            "unresolved_constraints": [],
            "constraint_assessment": []
        }]
    })
}

fn failure_code(
    outcome: &OutfitRecommendationOutcomeV1,
) -> Option<OutfitRecommendationFailureCodeV1> {
    match outcome {
        OutfitRecommendationOutcomeV1::Failed { code, .. } => Some(*code),
        _ => None,
    }
}

struct FixtureData {
    top: ItemId,
    bottom: ItemId,
    excluded: ItemId,
    inactive: ItemId,
    catalog_revision: u64,
    outfit_revision: u64,
}

impl FixtureData {
    fn new() -> Self {
        Self {
            top: ItemId::new_v4(),
            bottom: ItemId::new_v4(),
            excluded: ItemId::new_v4(),
            inactive: ItemId::new_v4(),
            catalog_revision: 7,
            outfit_revision: 3,
        }
    }

    fn request(&self) -> RequestOutfitRecommendationV1Request {
        RequestOutfitRecommendationV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            approval_id: OutfitRecommendationApprovalId::new_v4(),
            envelope: wardrobe_core::OutfitRecommendationEnvelopeV1 {
                prompt: "date-personal-prompt".to_owned(),
                credential_id: CredentialId::new_v4(),
                constraints: OutfitRecommendationConstraintsV1 {
                    occasion: None,
                    temperature_c: None,
                    precipitation: None,
                },
                excluded_item_ids: vec![self.excluded],
                requested_proposal_count: 1,
                expected_catalog_revision: self.catalog_revision,
                expected_outfit_revision: self.outfit_revision,
                retention: OpenAiRetentionDeclarationV1 {
                    mode: OpenAiRetentionModeV1::Unknown,
                    provenance: "credential-personal-provenance".to_owned(),
                },
            },
        }
    }

    fn snapshot(&self) -> OutfitRecommendationToolSnapshot {
        let validation_items = vec![
            snapshot_item(self.top, true, ItemCategoryV1::Top),
            snapshot_item(self.bottom, true, ItemCategoryV1::Bottom),
            snapshot_item(self.excluded, true, ItemCategoryV1::Accessory),
            snapshot_item(self.inactive, false, ItemCategoryV1::Shoes),
        ];
        OutfitRecommendationToolSnapshot {
            validation: OutfitRecommendationSnapshotV1 {
                catalog_revision: self.catalog_revision,
                outfit_revision: self.outfit_revision,
                capability_revision: OUTFIT_CAPABILITY_REVISION_V1.to_owned(),
                items: validation_items,
            },
            wardrobe_items: vec![
                tool_item(self.top, "private-green-shirt", ItemCategoryV1::Top),
                tool_item(
                    self.bottom,
                    "private-black-trousers",
                    ItemCategoryV1::Bottom,
                ),
                tool_item(
                    self.excluded,
                    "excluded-personal-sentinel",
                    ItemCategoryV1::Accessory,
                ),
                tool_item(
                    self.inactive,
                    "inactive-personal-sentinel",
                    ItemCategoryV1::Shoes,
                ),
            ],
            saved_outfits: vec![OutfitToolSavedOutfitV1 {
                outfit_id: OutfitId::new_v4(),
                name: "Saved date outfit".to_owned(),
                item_ids: vec![self.top, self.bottom],
            }],
        }
    }
}

fn snapshot_item(
    item_id: ItemId,
    active: bool,
    category: ItemCategoryV1,
) -> OutfitRecommendationSnapshotItemV1 {
    OutfitRecommendationSnapshotItemV1 {
        item_id,
        item_revision: 1,
        active,
        category,
        capability_tags: Vec::new(),
    }
}

fn tool_item(
    item_id: ItemId,
    display_name: &str,
    category: ItemCategoryV1,
) -> OutfitToolWardrobeItemV1 {
    OutfitToolWardrobeItemV1 {
        item_id,
        display_name: display_name.to_owned(),
        category,
        primary_color: None,
        brand: None,
        capability_tags: Vec::new(),
    }
}

fn request_json(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}

struct TlsFixture {
    socket: SocketAddr,
    server: tokio::task::JoinHandle<Vec<String>>,
}

impl TlsFixture {
    async fn start(responses: Vec<Value>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socket = listener.local_addr().unwrap();
        let server_config = fixture_server_config();
        let server = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let mut requests = Vec::with_capacity(responses.len());
            for (index, response) in responses.into_iter().enumerate() {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let request = read_request(&mut stream).await;
                let body = serde_json::to_vec(&response).unwrap();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nX-Request-Id: req_fixture_{}\r\n\
                     Connection: close\r\n\r\n",
                    body.len(),
                    index + 1
                );
                stream.write_all(head.as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
                let _ = stream.shutdown().await;
                requests.push(String::from_utf8(request).unwrap());
            }
            requests
        });
        Self { socket, server }
    }

    fn transport(&self) -> Result<OpenAiResponsesHttpTransport, OpenAiResponsesHttpError> {
        OpenAiResponsesHttpTransport::for_test(
            Url::parse(&format!("https://fixture.invalid:{}/", self.socket.port())).unwrap(),
            fixture_root_certificate(),
            self.socket,
        )
    }

    async fn finish(self) -> Vec<String> {
        self.server.await.unwrap()
    }
}

async fn read_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
        assert!(request.len() <= OPENAI_REQUEST_LIMIT_BYTES + 16 * 1024);
    }
    let head_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let content_length = String::from_utf8_lossy(&request[..head_end])
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    while request.len() - head_end < content_length {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
    }
    request
}

fn fixture_server_config() -> rustls::ServerConfig {
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(fixture_der("FIXTURE_LEAF_CERT_DER"))],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture_der(
                "FIXTURE_LEAF_KEY_DER",
            ))),
        )
        .unwrap()
}

fn fixture_root_certificate() -> reqwest::Certificate {
    reqwest::Certificate::from_der(&fixture_der("FIXTURE_CERT_DER")).unwrap()
}

fn fixture_der(name: &str) -> Vec<u8> {
    let source = include_str!("receipt_image_downloader.rs");
    let marker = format!("const {name}: &str = \"");
    let start = source.find(&marker).unwrap() + marker.len();
    let end = source[start..].find("\";").unwrap() + start;
    STANDARD.decode(&source[start..end]).unwrap()
}
