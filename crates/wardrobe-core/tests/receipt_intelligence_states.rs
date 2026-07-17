use serde_json::json;
use wardrobe_core::*;

fn timestamp(seconds: u8) -> String {
    format!("2026-07-16T21:30:{seconds:02}Z")
}

fn parameters() -> ReceiptIntelligenceProviderParametersV1 {
    ReceiptIntelligenceProviderParametersV1 {
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
    }
}

fn audit(
    attempt_id: ReceiptIntelligenceAttemptId,
    source_id: SourceId,
    source_revision_id: ReceiptIntelligenceSourceRevisionId,
) -> ReceiptIntelligenceAuditV1 {
    ReceiptIntelligenceAuditV1 {
        audit_id: ReceiptIntelligenceAuditId::new_v4(),
        attempt_id,
        source_id,
        source_revision_id,
        source_revision_sha256: Sha256Digest::from_bytes(b"source"),
        projection_sha256: Sha256Digest::from_bytes(b"projection"),
        serialized_request_sha256: Sha256Digest::from_bytes(b"request"),
        response_sha256: Some(Sha256Digest::from_bytes(b"response")),
        provider: RECEIPT_INTELLIGENCE_PROVIDER_V1.to_owned(),
        model: RECEIPT_INTELLIGENCE_MODEL_V1.to_owned(),
        provider_request_id: Some("req_synthetic".to_owned()),
        response_id: Some("resp_synthetic".to_owned()),
        prompt_revision: RECEIPT_INTELLIGENCE_PROMPT_REVISION_V1.to_owned(),
        schema_revision: RECEIPT_INTELLIGENCE_SCHEMA_REVISION_V1.to_owned(),
        projection_revision: RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1.to_owned(),
        retention_provenance: "personal-project-settings:2026-07-16".to_owned(),
        parameters: parameters(),
        execution_bounds: ReceiptIntelligenceExecutionBoundsV1::production(),
        usage: ReceiptIntelligenceUsageV1 {
            request_bytes: 2048,
            response_bytes: 1024,
            input_tokens: 500,
            output_tokens: 100,
            total_tokens: 600,
            reasoning_tokens: 20,
            cached_input_tokens: 0,
            attempts: 1,
        },
        dispatched_at: timestamp(0),
        finished_at: timestamp(1),
    }
}

#[test]
fn classification_requires_graphs_only_for_apparel_evidence() {
    let attempt_id = ReceiptIntelligenceAttemptId::new_v4();
    let source_id = SourceId::new_v4();
    let source_revision_id = ReceiptIntelligenceSourceRevisionId::new_v4();
    for classification in [
        ReceiptIntelligenceClassificationV1::Unrelated,
        ReceiptIntelligenceClassificationV1::Ambiguous,
    ] {
        let evidence = ReceiptIntelligenceClassificationEvidenceV1 {
            classification_id: ReceiptIntelligenceClassificationId::new_v4(),
            attempt_id,
            source_id,
            source_revision_id,
            classification,
            order_evidence_id: None,
            created_at: timestamp(1),
        };
        assert!(evidence.validate().is_ok());

        let mut leaked_graph = evidence;
        leaked_graph.order_evidence_id = Some(ReceiptOrderEvidenceId::new_v4());
        assert!(leaked_graph.validate().is_err());
    }

    for classification in [
        ReceiptIntelligenceClassificationV1::ApparelOrder,
        ReceiptIntelligenceClassificationV1::ApparelLifecycleUpdate,
    ] {
        let evidence = ReceiptIntelligenceClassificationEvidenceV1 {
            classification_id: ReceiptIntelligenceClassificationId::new_v4(),
            attempt_id,
            source_id,
            source_revision_id,
            classification,
            order_evidence_id: Some(ReceiptOrderEvidenceId::new_v4()),
            created_at: timestamp(1),
        };
        assert!(evidence.validate().is_ok());
    }
}

#[test]
fn all_attempt_states_have_closed_safe_shapes() {
    let attempt_id = ReceiptIntelligenceAttemptId::new_v4();
    let source_id = SourceId::new_v4();
    let source_revision_id = ReceiptIntelligenceSourceRevisionId::new_v4();
    let classification = ReceiptIntelligenceClassificationEvidenceV1 {
        classification_id: ReceiptIntelligenceClassificationId::new_v4(),
        attempt_id,
        source_id,
        source_revision_id,
        classification: ReceiptIntelligenceClassificationV1::Unrelated,
        order_evidence_id: None,
        created_at: timestamp(1),
    };
    let completed = ReceiptIntelligenceOutcomeV1::Completed {
        classification: classification.clone(),
        audit: audit(attempt_id, source_id, source_revision_id),
    };
    assert_eq!(
        completed.state(),
        ReceiptIntelligenceAttemptStateV1::Completed
    );
    assert!(completed.validate().is_ok());

    let refused = ReceiptIntelligenceOutcomeV1::Refused {
        attempt_id,
        audit: audit(attempt_id, source_id, source_revision_id),
    };
    assert_eq!(refused.state(), ReceiptIntelligenceAttemptStateV1::Refused);
    assert!(refused.validate().is_ok());

    let unknown = ReceiptIntelligenceOutcomeV1::OutcomeUnknown {
        attempt_id,
        audit: Some(audit(attempt_id, source_id, source_revision_id)),
    };
    assert_eq!(
        unknown.state(),
        ReceiptIntelligenceAttemptStateV1::OutcomeUnknown
    );
    assert!(unknown.validate().is_ok());

    let failure = ReceiptIntelligenceFailureV1 {
        code: ReceiptIntelligenceFailureCodeV1::ProviderUnavailable,
        retryable: false,
        user_action: ReceiptIntelligenceUserActionV1::StartNewPreview,
    };
    assert!(failure.validate().is_ok());
    let mut automatic_retry = failure;
    automatic_retry.retryable = true;
    assert!(automatic_retry.validate().is_err());

    let malformed = json!({
        "outcome": "outcome_unknown",
        "attempt_id": attempt_id,
        "audit": null,
        "retryable": true
    });
    assert!(serde_json::from_value::<ReceiptIntelligenceOutcomeV1>(malformed).is_err());
}

#[test]
fn consent_reservation_is_atomic_expiring_and_single_use() {
    let reservation = ReceiptIntelligenceReservationV1 {
        approval_id: ReceiptIntelligenceApprovalId::new_v4(),
        attempt_id: ReceiptIntelligenceAttemptId::new_v4(),
        source_id: SourceId::new_v4(),
        source_revision_id: ReceiptIntelligenceSourceRevisionId::new_v4(),
        state: ReceiptIntelligenceAttemptStateV1::NotSent,
        single_use: true,
        approval_created_at: timestamp(0),
        approval_consumed_at: timestamp(0),
        expires_at: timestamp(1),
    };
    assert!(reservation.validate().is_ok());

    let mut non_atomic = reservation.clone();
    non_atomic.approval_consumed_at = timestamp(1);
    non_atomic.expires_at = timestamp(2);
    assert!(non_atomic.validate().is_err());

    let mut reusable = reservation;
    reusable.single_use = false;
    assert!(reusable.validate().is_err());
}

#[test]
fn list_summaries_preserve_classification_and_content_free_attempt_state() {
    let attempt_id = ReceiptIntelligenceAttemptId::new_v4();
    let source_id = SourceId::new_v4();
    let source_revision_id = ReceiptIntelligenceSourceRevisionId::new_v4();
    let classification = ReceiptIntelligenceClassificationEvidenceV1 {
        classification_id: ReceiptIntelligenceClassificationId::new_v4(),
        attempt_id,
        source_id,
        source_revision_id,
        classification: ReceiptIntelligenceClassificationV1::Ambiguous,
        order_evidence_id: None,
        created_at: timestamp(1),
    };
    let summary = ReceiptIntelligenceSummaryV1 {
        attempt_id,
        approval_id: ReceiptIntelligenceApprovalId::new_v4(),
        source_id,
        source_revision_id,
        state: ReceiptIntelligenceAttemptStateV1::Completed,
        classification: Some(classification),
        failure: None,
        audit: Some(audit(attempt_id, source_id, source_revision_id)),
        created_at: timestamp(0),
        updated_at: timestamp(2),
    };
    assert!(summary.validate().is_ok());

    let response = ListReceiptIntelligenceV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        availability: ReceiptIntelligenceAvailabilityV1 {
            available: true,
            reason: None,
            offline_receipt_analysis_available: true,
            existing_wardrobe_access_available: true,
        },
        attempts: vec![summary.clone()],
        total_count: 1,
        receipt_intelligence_revision: 1,
        next_cursor: None,
    };
    assert!(response.validate().is_ok());

    let mut invalid_availability = response.clone();
    invalid_availability.availability.reason =
        Some(ReceiptIntelligenceAvailabilityReasonV1::CredentialUnavailable);
    assert!(invalid_availability.validate().is_err());

    let mut partial_failure = summary;
    partial_failure.state = ReceiptIntelligenceAttemptStateV1::Failed;
    partial_failure.failure = Some(ReceiptIntelligenceFailureV1 {
        code: ReceiptIntelligenceFailureCodeV1::PersistenceFailed,
        retryable: false,
        user_action: ReceiptIntelligenceUserActionV1::ReviewProviderStatus,
    });
    assert!(partial_failure.validate().is_err());
}

#[test]
fn source_authority_is_explicitly_user_reviewed_and_order_bound() {
    let order_evidence_id = ReceiptOrderEvidenceId::new_v4();
    let review_decision_id = ReceiptReviewDecisionId::new_v4();
    let authority = ReceiptSourceAuthorityV1 {
        authority_id: ReceiptSourceAuthorityId::new_v4(),
        source_id: SourceId::new_v4(),
        kind: ReceiptSourceAuthorityKindV1::UserReviewed,
        order_evidence_id,
        review_decision_id,
        review_head: ReceiptReviewHeadV1 {
            state: ReceiptStateV1::Confirmed,
            decision: ReceiptReviewDecisionV1 {
                decision_id: review_decision_id,
                order_evidence_id,
                action: ReceiptReviewActionV1::Confirm,
                corrected_order: None,
                receipt_revision: 3,
                created_at: timestamp(1),
            },
        },
        authority_revision: 1,
        advanced_at: timestamp(2),
    };
    assert!(authority.validate().is_ok());

    let mut remote_candidate_cannot_replace_head = authority;
    remote_candidate_cannot_replace_head.order_evidence_id = ReceiptOrderEvidenceId::new_v4();
    assert!(remote_candidate_cannot_replace_head.validate().is_err());
}

#[test]
fn availability_keeps_offline_receipts_and_wardrobe_access_enabled() {
    let disabled = ReceiptIntelligenceAvailabilityV1 {
        available: false,
        reason: Some(ReceiptIntelligenceAvailabilityReasonV1::LocalOnly),
        offline_receipt_analysis_available: true,
        existing_wardrobe_access_available: true,
    };
    assert!(disabled.validate().is_ok());

    let mut unsafe_gate = disabled;
    unsafe_gate.offline_receipt_analysis_available = false;
    assert!(unsafe_gate.validate().is_err());
}
