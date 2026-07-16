use serde_json::json;
use uuid::Uuid;
use wardrobe_core::*;

fn timestamp() -> String {
    "2026-07-15T12:30:00Z".to_owned()
}

fn retention() -> OpenAiRetentionDeclarationV1 {
    OpenAiRetentionDeclarationV1 {
        mode: OpenAiRetentionModeV1::Default,
        provenance: "personal-project-settings:2026-07-15".to_owned(),
    }
}

fn attributes() -> ItemAttributesV1 {
    ItemAttributesV1 {
        display_name: "Oxford shirt".to_owned(),
        category: ItemCategoryV1::Top,
        subcategory: Some("shirt".to_owned()),
        brand: Some("Test Brand".to_owned()),
        primary_color: Some("white".to_owned()),
        size: Some("M".to_owned()),
        notes: None,
        tags: vec![],
    }
}

fn asset(ordinal: u8, role: TryOnAssetRoleV1) -> TryOnDisclosureAssetV1 {
    let portrait = role == TryOnAssetRoleV1::Portrait;
    TryOnDisclosureAssetV1 {
        ordinal,
        role,
        transmitted_filename: format!("reference-{ordinal:02}.png"),
        portrait_source_revision_id: portrait.then(PhotoSourceRevisionId::new_v4),
        portrait_artifact_id: portrait.then(PhotoArtifactId::new_v4),
        item_id: (!portrait).then(ItemId::new_v4),
        evidence_id: (!portrait).then(EvidenceId::new_v4),
        source_id: (!portrait).then(SourceId::new_v4),
        canonical_sha256: Sha256Digest::from_bytes(&[ordinal]),
        media_type: TRY_ON_OUTPUT_MEDIA_TYPE_V1.to_owned(),
        byte_length: 1024,
        width: 512,
        height: 768,
    }
}

fn disclosure() -> TryOnDisclosureV1 {
    TryOnDisclosureV1 {
        provider: TRY_ON_PROVIDER_V1.to_owned(),
        model: TRY_ON_MODEL_V1.to_owned(),
        purpose: TRY_ON_PURPOSE_V1.to_owned(),
        prompt_revision: TRY_ON_PROMPT_REVISION_V1.to_owned(),
        assets: vec![
            asset(0, TryOnAssetRoleV1::Portrait),
            asset(1, TryOnAssetRoleV1::Garment),
            asset(2, TryOnAssetRoleV1::Garment),
        ],
        retention: TryOnRetentionDisclosureV1 {
            revision: TRY_ON_DISCLOSURE_REVISION_V1.to_owned(),
            declaration: retention(),
            images_api_has_application_state_retention: false,
            default_abuse_monitoring_max_days: 30,
            model_is_zdr_compatible: true,
            compatibility_is_not_project_enrollment: true,
            csam_input_scanning_applies: true,
            flagged_inputs_may_be_retained_for_review: true,
        },
    }
}

fn queued_job(outfit_id: OutfitId) -> TryOnJobV1 {
    TryOnJobV1 {
        job_id: TryOnJobId::new_v4(),
        approval_id: TryOnApprovalId::new_v4(),
        outfit_id,
        state: TryOnJobStateV1::Queued,
        attempt_count: 0,
        created_at: timestamp(),
        updated_at: timestamp(),
        completed_at: None,
        failure: None,
    }
}

fn garment(ordinal: u8) -> TryOnGarmentSourceV1 {
    let bytes = BoundedPhotoArtifactBytesV1::new(vec![ordinal, 2, 3]).unwrap();
    TryOnGarmentSourceV1 {
        ordinal,
        item_id: ItemId::new_v4(),
        item_updated_revision: 4,
        attributes: attributes(),
        evidence_id: EvidenceId::new_v4(),
        source_id: SourceId::new_v4(),
        media_type: PhotoMediaTypeV1::ImagePng,
        width: 100,
        height: 200,
        bytes_sha256: Sha256Digest::from_bytes(bytes.as_slice()),
        bytes,
    }
}

#[test]
fn all_four_commands_are_schema_v1_and_deny_unknown_fields() {
    let list = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "cursor": null,
        "limit": 20
    });
    assert!(serde_json::from_value::<ListTryOnPortraitCandidatesV1Request>(list.clone()).is_ok());

    let preview = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "outfit_id": OutfitId::new_v4(),
        "portrait_source_revision_id": PhotoSourceRevisionId::new_v4(),
        "credential_id": CredentialId::new_v4(),
        "retention": retention(),
        "expected_outfit_revision": 5
    });
    assert!(serde_json::from_value::<PreviewTryOnV1Request>(preview.clone()).is_ok());

    let submit = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "approval_id": TryOnApprovalId::new_v4()
    });
    assert!(serde_json::from_value::<SubmitTryOnV1Request>(submit).is_ok());

    let get = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "outfit_id": OutfitId::new_v4()
    });
    assert!(serde_json::from_value::<GetOutfitTryOnV1Request>(get).is_ok());

    let mut unknown = preview;
    unknown["portrait_path"] = json!("/private/photo.png");
    assert!(serde_json::from_value::<PreviewTryOnV1Request>(unknown).is_err());

    let mut wrong_version = list;
    wrong_version["schema_version"] = json!(2);
    assert!(serde_json::from_value::<ListTryOnPortraitCandidatesV1Request>(wrong_version).is_err());
}

#[test]
fn try_on_ids_require_canonical_non_nil_uuid_strings() {
    let raw = Uuid::new_v4();
    assert_eq!(
        TryOnApprovalId::new(raw).unwrap().to_string(),
        raw.hyphenated().to_string()
    );
    assert!(TryOnJobId::new(Uuid::nil()).is_err());
    assert!(
        serde_json::from_str::<TryOnJobId>("\"00000000-0000-0000-0000-000000000000\"").is_err()
    );
    assert!(serde_json::from_str::<TryOnApprovalId>(
        &format!("\"{}\"", raw.hyphenated()).to_uppercase()
    )
    .is_err());
}

#[test]
fn disclosure_is_fixed_bounded_ordered_and_role_consistent() {
    let value = disclosure();
    assert!(value.validate().is_ok());
    assert_eq!(value.assets[0].role, TryOnAssetRoleV1::Portrait);
    assert_eq!(value.assets[1].transmitted_filename, "reference-01.png");
    assert!(!value.retention.images_api_has_application_state_retention);
    assert!(value.retention.compatibility_is_not_project_enrollment);

    let mut reordered = value.clone();
    reordered.assets.swap(0, 1);
    assert!(reordered.validate().is_err());

    let mut leaked_identity = value.clone();
    leaked_identity.assets[0].item_id = Some(ItemId::new_v4());
    assert!(leaked_identity.validate().is_err());

    let mut oversized = value;
    oversized.assets[1].byte_length = TRY_ON_MAX_INPUT_BYTES + 1;
    assert!(oversized.validate().is_err());
}

#[test]
fn approval_is_expiring_single_use_and_preview_reports_replay() {
    let outfit_id = OutfitId::new_v4();
    let response = PreviewTryOnV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        disclosure: disclosure(),
        approval: TryOnApprovalV1 {
            approval_id: TryOnApprovalId::new_v4(),
            outfit_id,
            expires_at: timestamp(),
            single_use: true,
            garment_count: 2,
            asset_snapshot_sha256: Sha256Digest::from_bytes(b"snapshot"),
            outfit_revision: 3,
        },
        replay_status: ReplayStatusV1::Created,
    };
    assert!(response.validate().is_ok());

    let mut reusable = response;
    reusable.approval.single_use = false;
    assert!(reusable.validate().is_err());

    let mut mismatched_count = disclosure();
    mismatched_count
        .assets
        .push(asset(3, TryOnAssetRoleV1::Garment));
    let response = PreviewTryOnV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        disclosure: mismatched_count,
        approval: TryOnApprovalV1 {
            approval_id: TryOnApprovalId::new_v4(),
            outfit_id,
            expires_at: timestamp(),
            single_use: true,
            garment_count: 2,
            asset_snapshot_sha256: Sha256Digest::from_bytes(b"snapshot"),
            outfit_revision: 3,
        },
        replay_status: ReplayStatusV1::Created,
    };
    assert!(response.validate().is_err());
}

#[test]
fn job_states_and_failures_are_closed_and_actionable() {
    let outfit_id = OutfitId::new_v4();
    assert!(queued_job(outfit_id).validate().is_ok());

    let failed = TryOnJobV1 {
        job_id: TryOnJobId::new_v4(),
        approval_id: TryOnApprovalId::new_v4(),
        outfit_id,
        state: TryOnJobStateV1::Failed,
        attempt_count: 1,
        created_at: timestamp(),
        updated_at: timestamp(),
        completed_at: Some(timestamp()),
        failure: Some(TryOnFailureV1 {
            code: TryOnFailureCodeV1::OutcomeUnknown,
            retryable: false,
            user_action: TryOnUserActionV1::ReviewProviderStatus,
        }),
    };
    assert!(failed.validate().is_ok());

    let mut unsafe_retry = failed;
    unsafe_retry.failure.as_mut().unwrap().retryable = true;
    assert!(unsafe_retry.validate().is_err());

    assert!(serde_json::from_str::<TryOnFailureCodeV1>("\"free_form_provider_error\"").is_err());
}

#[test]
fn output_is_hash_checked_labeled_and_presentation_only() {
    let bytes = BoundedTryOnOutputBytesV1::new(vec![1, 2, 3]).unwrap();
    let output = TryOnOutputV1 {
        job_id: TryOnJobId::new_v4(),
        outfit_id: OutfitId::new_v4(),
        media_type: TRY_ON_OUTPUT_MEDIA_TYPE_V1.to_owned(),
        width: TRY_ON_OUTPUT_WIDTH_V1,
        height: TRY_ON_OUTPUT_HEIGHT_V1,
        bytes_sha256: Sha256Digest::from_bytes(bytes.as_slice()),
        bytes,
        use_class: TryOnOutputUseClassV1::PresentationOnly,
        eligible_as_evidence: false,
        label: TRY_ON_PRESENTATION_LABEL_V1.to_owned(),
        created_at: timestamp(),
    };
    assert!(output.validate().is_ok());

    let mut evidence = output.clone();
    evidence.eligible_as_evidence = true;
    assert!(evidence.validate().is_err());

    let mut misleading = output;
    misleading.label = "Virtual fitting result".to_owned();
    assert!(misleading.validate().is_err());
}

#[test]
fn get_response_keeps_ordered_real_sources_beside_matching_output() {
    let outfit_id = OutfitId::new_v4();
    let job_id = TryOnJobId::new_v4();
    let job = TryOnJobV1 {
        job_id,
        approval_id: TryOnApprovalId::new_v4(),
        outfit_id,
        state: TryOnJobStateV1::Succeeded,
        attempt_count: 1,
        created_at: timestamp(),
        updated_at: timestamp(),
        completed_at: Some(timestamp()),
        failure: None,
    };
    let bytes = BoundedTryOnOutputBytesV1::new(vec![7, 8, 9]).unwrap();
    let output = TryOnOutputV1 {
        job_id,
        outfit_id,
        media_type: TRY_ON_OUTPUT_MEDIA_TYPE_V1.to_owned(),
        width: TRY_ON_OUTPUT_WIDTH_V1,
        height: TRY_ON_OUTPUT_HEIGHT_V1,
        bytes_sha256: Sha256Digest::from_bytes(bytes.as_slice()),
        bytes,
        use_class: TryOnOutputUseClassV1::PresentationOnly,
        eligible_as_evidence: false,
        label: TRY_ON_PRESENTATION_LABEL_V1.to_owned(),
        created_at: timestamp(),
    };
    let response = GetOutfitTryOnV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        outfit_id,
        outfit_name: "Dinner outfit".to_owned(),
        latest_job: Some(job),
        output: Some(output),
        garment_sources: vec![garment(1), garment(2)],
        try_on_revision: 9,
    };
    assert!(response.validate().is_ok());

    let mut wrong_order = response.clone();
    wrong_order.garment_sources.swap(0, 1);
    assert!(wrong_order.validate().is_err());

    let mut detached = response;
    detached.output.as_mut().unwrap().job_id = TryOnJobId::new_v4();
    assert!(detached.validate().is_err());
}

#[test]
fn portrait_candidates_are_deduplicated_and_thumbnail_hash_checked() {
    let bytes = BoundedPhotoArtifactBytesV1::new(vec![4, 5, 6]).unwrap();
    let candidate = TryOnPortraitCandidateV1 {
        source_revision_id: PhotoSourceRevisionId::new_v4(),
        artifact_id: PhotoArtifactId::new_v4(),
        captured_at: Some(timestamp()),
        media_type: PhotoMediaTypeV1::ImageJpeg,
        width: 320,
        height: 480,
        bytes_sha256: Sha256Digest::from_bytes(bytes.as_slice()),
        thumbnail_bytes: bytes,
    };
    let response = ListTryOnPortraitCandidatesV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        candidates: vec![candidate.clone()],
        total_count: 1,
        photo_revision: 2,
        next_cursor: None,
    };
    assert!(response.validate().is_ok());

    let mut duplicate = response;
    duplicate.total_count = 2;
    duplicate.candidates.push(candidate);
    assert!(duplicate.validate().is_err());
}
