use serde_json::json;
use wardrobe_core::*;

fn timestamp() -> String {
    "2026-07-16T21:30:00Z".to_owned()
}

fn retention() -> OpenAiRetentionDeclarationV1 {
    OpenAiRetentionDeclarationV1 {
        mode: OpenAiRetentionModeV1::Default,
        provenance: "personal-project-settings:2026-07-16".to_owned(),
    }
}

fn projection(texts: Vec<String>) -> ReceiptIntelligenceProjectionV1 {
    ReceiptIntelligenceProjectionV1 {
        revision: RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1.to_owned(),
        fragments: texts
            .into_iter()
            .enumerate()
            .map(|(ordinal, text)| ReceiptIntelligenceProjectionFragmentV1 {
                fragment_ref: format!("fragment-{ordinal:04}"),
                text,
            })
            .collect(),
    }
}

fn disclosure(projection: ReceiptIntelligenceProjectionV1) -> ReceiptIntelligenceDisclosureV1 {
    ReceiptIntelligenceDisclosureV1 {
        provider: RECEIPT_INTELLIGENCE_PROVIDER_V1.to_owned(),
        model: RECEIPT_INTELLIGENCE_MODEL_V1.to_owned(),
        purpose: RECEIPT_INTELLIGENCE_PURPOSE_V1.to_owned(),
        aggregate_text_bytes: projection.aggregate_text_bytes(),
        projection,
        raw_mime_disclosed: false,
        headers_disclosed: false,
        urls_disclosed: false,
        filenames_disclosed: false,
        attachment_metadata_disclosed: false,
        cid_metadata_disclosed: false,
        internal_identifiers_disclosed: false,
        hashes_disclosed: false,
        credentials_disclosed: false,
        image_bytes_disclosed: false,
        retention: ReceiptIntelligenceRetentionDisclosureV1::for_declaration(retention()),
        preparation_bounds: ReceiptIntelligencePreparationBoundsV1::production(),
        execution_bounds: ReceiptIntelligenceExecutionBoundsV1::production(),
    }
}

fn preview() -> ReceiptIntelligencePreviewV1 {
    let disclosure = disclosure(projection(vec![
        "Order confirmed\nSynthetic shirt, size M".to_owned(),
        "Total USD 42.00".to_owned(),
    ]));
    let consent_envelope = ReceiptIntelligenceConsentEnvelopeV1 {
        source_id: SourceId::new_v4(),
        source_revision_id: ReceiptIntelligenceSourceRevisionId::new_v4(),
        source_revision_sha256: Sha256Digest::from_bytes(b"source revision"),
        disclosed_fragment_sha256: disclosure.projection.fragment_sha256(),
        projection_sha256: disclosure.projection.sha256(),
        serialized_request_sha256: Sha256Digest::from_bytes(b"request"),
        serialized_request_bytes: 4096,
        credential_id: CredentialId::new_v4(),
        provider: RECEIPT_INTELLIGENCE_PROVIDER_V1.to_owned(),
        model: RECEIPT_INTELLIGENCE_MODEL_V1.to_owned(),
        prompt_revision: RECEIPT_INTELLIGENCE_PROMPT_REVISION_V1.to_owned(),
        schema_revision: RECEIPT_INTELLIGENCE_SCHEMA_REVISION_V1.to_owned(),
        projection_revision: RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1.to_owned(),
        parameter_revision: RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1.to_owned(),
        retention: disclosure.retention.clone(),
        preparation_bounds: disclosure.preparation_bounds.clone(),
        execution_bounds: disclosure.execution_bounds.clone(),
        expires_at: timestamp(),
    };
    ReceiptIntelligencePreviewV1 {
        disclosure,
        consent_envelope,
    }
}

#[test]
fn preview_consent_and_commands_are_strict_v1_contracts() {
    let preview_value = serde_json::to_value(preview()).unwrap();
    let request = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "consent": {
            "affirmative": true,
            "preview": preview_value
        }
    });
    let parsed: RequestReceiptIntelligenceV1Request =
        serde_json::from_value(request.clone()).unwrap();
    assert!(parsed.validate().is_ok());

    let mut unknown_root = request.clone();
    unknown_root["automatic_retry"] = json!(true);
    assert!(serde_json::from_value::<RequestReceiptIntelligenceV1Request>(unknown_root).is_err());

    let mut unknown_projection = request.clone();
    unknown_projection["consent"]["preview"]["disclosure"]["projection"]["fragments"][0]
        ["source_id"] = json!(SourceId::new_v4());
    assert!(
        serde_json::from_value::<RequestReceiptIntelligenceV1Request>(unknown_projection).is_err()
    );

    let mut wrong_version = request;
    wrong_version["schema_version"] = json!(2);
    assert!(serde_json::from_value::<RequestReceiptIntelligenceV1Request>(wrong_version).is_err());

    let cancelled = RequestReceiptIntelligenceV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        consent: ReceiptIntelligenceConsentV1 {
            affirmative: false,
            preview: preview(),
        },
    };
    assert!(cancelled.validate().is_err());
}

#[test]
fn provider_projection_has_only_opaque_handles_and_visible_text() {
    let projection = projection(vec!["Synthetic order text".to_owned()]);
    assert!(projection.validate().is_ok());
    let value = serde_json::to_value(&projection).unwrap();
    let fragment = value["fragments"][0].as_object().unwrap();
    assert_eq!(
        fragment.keys().cloned().collect::<Vec<_>>(),
        vec!["fragment_ref", "text"]
    );
    for forbidden in [
        "source_id",
        "sha256",
        "mime",
        "headers",
        "url",
        "filename",
        "attachment",
        "cid",
        "credential",
        "image",
    ] {
        assert!(!serde_json::to_string(&projection)
            .unwrap()
            .contains(forbidden));
    }

    let mut leaked_url = projection.clone();
    leaked_url.fragments[0].text = "Track at HTTPS://example.invalid/order".to_owned();
    assert!(leaked_url.validate().is_err());

    let mut non_opaque_handle = projection;
    non_opaque_handle.fragments[0].fragment_ref = "gmail-message-123".to_owned();
    assert!(non_opaque_handle.validate().is_err());
}

#[test]
fn provider_projection_rejects_url_and_uri_bearing_visible_text() {
    for text in [
        "Track at http://example.invalid/order/123",
        "Track at HTTPS://EXAMPLE.COM/order/123",
        "Track at www.example.com/order/123",
        "Track at shop.example/order/123",
        "Returns: example.com",
        "Returns: example.com.",
        "Visit www.shop.newretail",
        "Contact mailto:user@example.com",
        "Download ftp://files.example.com/invoice",
        "Call tel:+1-555-0100",
        "Payload data:text/plain,order",
        "Open file:///tmp/invoice.html",
        "Open file:/tmp/invoice.html",
        "Reference urn:isbn:9780143127741",
        "Open custom+wardrobe:order/123",
        "Preview //assets.new-retail-tld/catalog",
        "Preview shop.newretail/catalog",
        "Local preview localhost:8080/order/123",
        "Network preview 192.168.1.10/order/123",
        "Account user@example.com/orders/123",
    ] {
        assert!(
            projection(vec![text.to_owned()]).validate().is_err(),
            "URL-bearing projection was accepted: {text}"
        );
    }
}

#[test]
fn provider_projection_allows_normal_receipt_and_apparel_text() {
    for text in [
        "White T-Shirt, size M/L; 100% cotton.",
        "Order: confirmed. Style: relaxed. Color: navy.",
        "J.Crew Factory slim-fit chino",
        "A.P.C. cotton overshirt",
        "Total USD 42.00; tax USD 3.50",
        "Order #123-456; version 1.2.3",
        "SKU ABC.DEF and style code SHIRT-01",
        "Customer email user@example.com",
        "Windows import path C:\\Receipts\\order.eml",
        "Estimated arrival 12:30 PM",
    ] {
        assert!(
            projection(vec![text.to_owned()]).validate().is_ok(),
            "ordinary receipt text was rejected: {text}"
        );
    }
}

#[test]
fn every_preparation_bound_is_closed_and_fails_one_over() {
    let exact_fragment = projection(vec![
        "x".repeat(MAX_RECEIPT_INTELLIGENCE_FRAGMENT_BYTES_V1 as usize)
    ]);
    assert!(exact_fragment.validate().is_ok());
    let over_fragment = projection(vec![
        "x".repeat(MAX_RECEIPT_INTELLIGENCE_FRAGMENT_BYTES_V1 as usize + 1)
    ]);
    assert!(over_fragment.validate().is_err());

    let exact_count = projection(
        (0..MAX_RECEIPT_INTELLIGENCE_FRAGMENTS_V1)
            .map(|_| "x".to_owned())
            .collect(),
    );
    assert!(exact_count.validate().is_ok());
    let over_count = projection(
        (0..=MAX_RECEIPT_INTELLIGENCE_FRAGMENTS_V1)
            .map(|_| "x".to_owned())
            .collect(),
    );
    assert!(over_count.validate().is_err());

    let exact_aggregate = projection(vec![
        "x".repeat(
            MAX_RECEIPT_INTELLIGENCE_FRAGMENT_BYTES_V1 as usize
        );
        (MAX_RECEIPT_INTELLIGENCE_TEXT_BYTES_V1 / MAX_RECEIPT_INTELLIGENCE_FRAGMENT_BYTES_V1)
            as usize
    ]);
    assert_eq!(
        exact_aggregate.aggregate_text_bytes(),
        MAX_RECEIPT_INTELLIGENCE_TEXT_BYTES_V1
    );
    assert!(exact_aggregate.validate().is_ok());
    let mut over_aggregate = exact_aggregate;
    let next_ordinal = over_aggregate.fragments.len();
    over_aggregate
        .fragments
        .push(ReceiptIntelligenceProjectionFragmentV1 {
            fragment_ref: format!("fragment-{next_ordinal:04}"),
            text: "x".to_owned(),
        });
    assert!(over_aggregate.validate().is_err());

    let mut exact_request = preview();
    exact_request.consent_envelope.serialized_request_bytes =
        MAX_RECEIPT_INTELLIGENCE_SERIALIZED_REQUEST_BYTES_V1;
    assert!(exact_request.validate().is_ok());
    exact_request.consent_envelope.serialized_request_bytes += 1;
    assert!(exact_request.validate().is_err());
}

#[test]
fn consent_binds_every_disclosed_fragment_and_configured_bound() {
    let valid = preview();
    assert!(valid.validate().is_ok());

    let mut changed_text = valid.clone();
    changed_text.disclosure.projection.fragments[0]
        .text
        .push('!');
    changed_text.disclosure.aggregate_text_bytes += 1;
    assert!(changed_text.validate().is_err());

    let mut changed_hash = valid.clone();
    changed_hash.consent_envelope.disclosed_fragment_sha256[0] =
        Sha256Digest::from_bytes(b"different");
    assert!(changed_hash.validate().is_err());

    let mut changed_model = valid.clone();
    changed_model.consent_envelope.model = "different-model".to_owned();
    assert!(changed_model.validate().is_err());

    let mut changed_bound = valid;
    changed_bound
        .consent_envelope
        .execution_bounds
        .timeout_millis -= 1;
    assert!(changed_bound.validate().is_err());
}

#[test]
fn all_execution_bounds_and_stateless_parameters_are_exact() {
    let bounds = ReceiptIntelligenceExecutionBoundsV1::production();
    let exact = ReceiptIntelligenceUsageV1 {
        request_bytes: bounds.max_request_bytes,
        response_bytes: bounds.max_response_bytes,
        input_tokens: 12_000,
        output_tokens: bounds.max_output_tokens,
        total_tokens: 12_000 + bounds.max_output_tokens,
        reasoning_tokens: bounds.max_output_tokens,
        cached_input_tokens: 0,
        attempts: bounds.max_attempts,
    };
    assert!(exact.validate_with(&bounds).is_ok());

    let mut over = exact.clone();
    over.request_bytes += 1;
    assert!(over.validate_with(&bounds).is_err());
    let mut over = exact.clone();
    over.response_bytes += 1;
    assert!(over.validate_with(&bounds).is_err());
    let mut over = exact.clone();
    over.output_tokens += 1;
    assert!(over.validate_with(&bounds).is_err());
    let mut over = exact;
    over.attempts += 1;
    assert!(over.validate_with(&bounds).is_err());

    let parameters = ReceiptIntelligenceProviderParametersV1 {
        revision: RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1.to_owned(),
        store: false,
        background: false,
        tools_enabled: false,
        previous_response_id_present: false,
        strict_schema: true,
        reasoning_effort: ReceiptIntelligenceReasoningEffortV1::Low,
        max_output_tokens: MAX_RECEIPT_INTELLIGENCE_OUTPUT_TOKENS_V1,
        timeout_millis: RECEIPT_INTELLIGENCE_TIMEOUT_MILLIS_V1,
        max_attempts: MAX_RECEIPT_INTELLIGENCE_ATTEMPTS_V1,
    };
    assert!(parameters.validate().is_ok());

    let mut tool_access = parameters.clone();
    tool_access.tools_enabled = true;
    assert!(tool_access.validate().is_err());
    let mut continuation = parameters.clone();
    continuation.previous_response_id_present = true;
    assert!(continuation.validate().is_err());
    let mut timeout = parameters;
    timeout.timeout_millis -= 1;
    assert!(timeout.validate().is_err());
}

#[test]
fn retention_and_disclosure_fail_closed() {
    let valid = disclosure(projection(vec!["Synthetic order".to_owned()]));
    assert!(valid.validate().is_ok());
    assert!(!valid.retention.store);
    assert!(valid.retention.store_false_is_not_organization_zdr);
    assert!(!valid.retention.local_provider_payload_retained);

    let mut unknown = valid.clone();
    unknown.retention.declaration.mode = OpenAiRetentionModeV1::Unknown;
    assert!(unknown.validate().is_err());

    let mut leaked = valid;
    leaked.headers_disclosed = true;
    assert!(leaked.validate().is_err());
}

#[test]
fn receipt_intelligence_types_are_exported_to_typescript() {
    let bindings = typescript_bindings();
    for declaration in [
        "ReceiptIntelligenceProjectionV1",
        "ReceiptIntelligenceConsentV1",
        "PreviewReceiptIntelligenceV1Request",
        "RequestReceiptIntelligenceV1Request",
        "ListReceiptIntelligenceV1Request",
        "ReceiptIntelligenceClassificationEvidenceV1",
        "ReceiptIntelligenceAuditV1",
        "ReceiptIntelligenceOutcomeV1",
        "ReceiptSourceAuthorityV1",
    ] {
        assert!(bindings.contains(&format!("export type {declaration}")));
    }
}
