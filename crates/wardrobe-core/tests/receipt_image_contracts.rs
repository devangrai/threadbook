use wardrobe_core::*;

fn candidate() -> ReceiptImageCandidateSummaryV1 {
    ReceiptImageCandidateSummaryV1 {
        candidate_id: ReceiptImageCandidateId::new_v4(),
        source_id: SourceId::new_v4(),
        display_host: "images.example.test".to_owned(),
        candidate_url_sha256: Sha256Digest::from_bytes(b"https://images.example.test/item.png"),
        eligibility: ReceiptImageCandidateEligibilityV1::Eligible,
        latest_attempt: None,
    }
}

#[test]
fn image_approval_contract_is_strict_and_never_contains_a_url() {
    let candidate = candidate();
    let request = serde_json::json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "candidate_id": candidate.candidate_id,
        "approved_display_host": candidate.display_host,
        "candidate_url_sha256": candidate.candidate_url_sha256,
        "prior_attempt_id": null
    });
    let decoded: ApproveAndFetchReceiptImageV1Request =
        serde_json::from_value(request.clone()).unwrap();
    assert!(decoded.validate().is_ok());
    assert!(!serde_json::to_string(&decoded)
        .unwrap()
        .contains("https://"));

    let mut unknown = request;
    unknown["url"] = serde_json::json!("https://images.example.test/item.png");
    assert!(serde_json::from_value::<ApproveAndFetchReceiptImageV1Request>(unknown).is_err());
}

#[test]
fn attempt_and_artifact_shapes_are_consistent() {
    let candidate = candidate();
    let attempt_id = ReceiptImageAttemptId::new_v4();
    let success = ApproveAndFetchReceiptImageV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        candidate_id: candidate.candidate_id,
        attempt_id,
        outcome: ReceiptImageAttemptOutcomeV1::Succeeded,
        failure_code: None,
        artifact: Some(ReceiptRemoteImageV1 {
            image_id: ReceiptRemoteImageId::new_v4(),
            source_blob_sha256: Sha256Digest::from_bytes(b"source"),
            source_byte_length: 64,
            source_media_type: "image/png".to_owned(),
            display_blob_sha256: Sha256Digest::from_bytes(b"display"),
            display_byte_length: 64,
            display_media_type: "image/png".to_owned(),
            width: 32,
            height: 32,
            policy_revision: "policy-v1".to_owned(),
            decoder_revision: "decoder-v1".to_owned(),
            derivative_revision: "derivative-v1".to_owned(),
        }),
        replay_status: ReplayStatusV1::Created,
    };
    assert!(success.validate().is_ok());

    let mut inconsistent = success;
    inconsistent.outcome = ReceiptImageAttemptOutcomeV1::TransportFailed;
    assert_eq!(
        inconsistent.validate().unwrap_err().field,
        SafeFieldV1::ReceiptImageAttempt
    );
}

#[test]
fn candidate_lists_are_bounded_and_source_scoped() {
    let candidate = candidate();
    let response = ListReceiptImageCandidatesV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        source_id: candidate.source_id,
        candidates: vec![candidate],
        omitted_count: 0,
    };
    assert!(response.validate().is_ok());

    let mut wrong_source = response;
    wrong_source.candidates[0].source_id = SourceId::new_v4();
    assert!(wrong_source.validate().is_err());
}
