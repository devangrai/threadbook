use serde_json::json;
use uuid::Uuid;
use wardrobe_core::*;

#[test]
fn photo_requests_decode_strictly_and_require_schema_v1() {
    let request = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "import_root_id": ImportRootId::new_v4(),
        "expected_manifest_generation": 7
    });
    assert!(serde_json::from_value::<CreatePhotoScopeV1Request>(request.clone()).is_ok());

    let mut unknown = request.clone();
    unknown["path"] = json!("/private/photo.jpg");
    assert!(serde_json::from_value::<CreatePhotoScopeV1Request>(unknown).is_err());

    let mut wrong_version = request;
    wrong_version["schema_version"] = json!(2);
    assert!(serde_json::from_value::<CreatePhotoScopeV1Request>(wrong_version).is_err());

    let interactive = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "observation_id": PhotoObservationId::new_v4(),
        "box_rectangle": {"x": 1, "y": 1, "width": 4, "height": 3},
        "positive_points": [],
        "negative_points": [],
        "provider_id": "caller-must-not-select-providers"
    });
    assert!(serde_json::from_value::<PromptPhotoObservationV1Request>(interactive).is_err());
}

#[test]
fn photo_ids_are_canonical_non_nil_and_distinct_types() {
    let raw = Uuid::new_v4();
    let scope = PhotoScopeId::new(raw).unwrap();
    let artifact = PhotoArtifactId::new(raw).unwrap();
    assert_eq!(scope.to_string(), artifact.to_string());

    assert!(PhotoScopeId::new(Uuid::nil()).is_err());
    assert!(
        serde_json::from_str::<PhotoScopeId>("\"00000000-0000-0000-0000-000000000000\"").is_err()
    );
    assert!(serde_json::from_str::<PhotoScopeId>(
        &format!("\"{}\"", raw.hyphenated()).to_uppercase()
    )
    .is_err());
}

#[test]
fn rectangles_points_and_prompts_stay_inside_source_geometry() {
    assert!(RectV1 {
        x: 3,
        y: 2,
        width: 7,
        height: 6,
    }
    .validate_within(10, 8)
    .is_ok());
    assert!(RectV1 {
        x: 9,
        y: 0,
        width: 2,
        height: 1,
    }
    .validate_within(10, 8)
    .is_err());
    assert!(RectV1 {
        x: u32::MAX,
        y: 0,
        width: 2,
        height: 1,
    }
    .validate_within(10, 8)
    .is_err());
    assert!(PointV1 { x: 9, y: 7 }.validate_within(10, 8).is_ok());
    assert!(PointV1 { x: 10, y: 7 }.validate_within(10, 8).is_err());

    let duplicated_prompt = PromptPhotoObservationV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        observation_id: PhotoObservationId::new_v4(),
        box_rectangle: RectV1 {
            x: 0,
            y: 0,
            width: 10,
            height: 8,
        },
        positive_points: vec![PointV1 { x: 2, y: 3 }],
        negative_points: vec![PointV1 { x: 2, y: 3 }],
    };
    assert!(duplicated_prompt.validate().is_err());
}

#[test]
fn masks_require_exact_dimensions_nonzero_area_and_canonical_tail_bits() {
    let valid = MaskV1 {
        width: 3,
        height: 3,
        packed_bits: vec![0b1000_0000, 0b1000_0000],
        confidence: 0.75,
    };
    assert!(valid.validate_for_dimensions(3, 3).is_ok());

    let mut bad_tail = valid.clone();
    bad_tail.packed_bits[1] = 0b1000_0001;
    assert!(bad_tail.validate_for_dimensions(3, 3).is_err());

    let mut empty = valid.clone();
    empty.packed_bits = vec![0, 0];
    assert!(empty.validate_for_dimensions(3, 3).is_err());

    let mut non_finite = valid;
    non_finite.confidence = f32::NAN;
    assert!(non_finite.validate_for_dimensions(3, 3).is_err());
}

#[test]
fn artifact_bytes_are_bounded_and_hash_checked() {
    assert!(BoundedPhotoArtifactBytesV1::new(Vec::new()).is_err());
    let bytes = BoundedPhotoArtifactBytesV1::new(vec![1, 2, 3]).unwrap();
    let response = ReadPhotoArtifactV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        artifact_id: PhotoArtifactId::new_v4(),
        media_type: PhotoMediaTypeV1::ImagePng,
        width: 1,
        height: 1,
        bytes_sha256: Sha256Digest::from_bytes(bytes.as_slice()),
        bytes,
    };
    assert!(response.validate().is_ok());
    assert!(!serde_json::to_string(&response).unwrap().contains("path"));
}

#[test]
fn owner_commands_are_strict_and_actions_have_exact_selection_shapes() {
    let review_id = PhotoOwnerReviewId::new_v4();
    let request = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "owner_review_id": review_id,
        "action": "select_person",
        "selected_person_instance_id": PhotoPersonInstanceId::new_v4(),
        "expected_detection_revision": 2,
        "expected_owner_head_revision": 0,
        "expected_photo_revision": 4
    });
    let decoded = serde_json::from_value::<DecidePhotoOwnerV1Request>(request.clone()).unwrap();
    assert!(decoded.validate().is_ok());

    let mut unknown = request.clone();
    unknown["person_name"] = json!("Alice");
    assert!(serde_json::from_value::<DecidePhotoOwnerV1Request>(unknown).is_err());

    let mut absent_with_person = request.clone();
    absent_with_person["action"] = json!("owner_absent");
    assert!(
        serde_json::from_value::<DecidePhotoOwnerV1Request>(absent_with_person)
            .unwrap()
            .validate()
            .is_err()
    );

    let mut selection_without_person = request;
    selection_without_person["selected_person_instance_id"] = serde_json::Value::Null;
    assert!(
        serde_json::from_value::<DecidePhotoOwnerV1Request>(selection_without_person)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn owner_preview_bytes_are_bounded_hash_checked_and_path_free() {
    let bytes = BoundedPhotoArtifactBytesV1::new(vec![9, 8, 7]).unwrap();
    let mut response = ReadPhotoOwnerPreviewV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        owner_review_id: PhotoOwnerReviewId::new_v4(),
        preview_id: PhotoOwnerPreviewId::new_v4(),
        media_type: PhotoMediaTypeV1::ImageJpeg,
        width: 1,
        height: 1,
        byte_length: 3,
        bytes_sha256: Sha256Digest::from_bytes(bytes.as_slice()),
        bytes,
    };
    assert!(response.validate().is_ok());
    assert!(!serde_json::to_string(&response).unwrap().contains("path"));

    response.byte_length = 2;
    assert!(response.validate().is_err());
}

#[test]
fn missed_person_correction_requires_full_revision_envelope() {
    let request = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "owner_review_id": PhotoOwnerReviewId::new_v4(),
        "manual_rectangle": {"x": 2, "y": 3, "width": 10, "height": 20},
        "expected_terminal_attempt_id": PhotoPersonDetectionAttemptId::new_v4(),
        "expected_detection_revision": 1,
        "expected_owner_head_revision": 0,
        "expected_photo_revision": 7
    });
    assert!(
        serde_json::from_value::<CorrectPhotoPersonDetectionV1Request>(request.clone()).is_ok()
    );
    let mut missing_revision = request;
    missing_revision
        .as_object_mut()
        .unwrap()
        .remove("expected_owner_head_revision");
    assert!(
        serde_json::from_value::<CorrectPhotoPersonDetectionV1Request>(missing_revision).is_err()
    );
}

#[test]
fn scoped_person_detection_counts_account_for_every_terminal_member() {
    let mut response = DetectPhotoScopePeopleV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        scope_id: PhotoScopeId::new_v4(),
        run_id: PhotoAnalysisRunId::new_v4(),
        state: PhotoAnalysisRunStateV1::Completed,
        member_count: 5,
        completed_count: 5,
        terminal_review_count: 4,
        instances_available_count: 1,
        no_person_detected_count: 1,
        overflow_count: 1,
        retryable_failure_count: 1,
        permanent_unavailable_count: 0,
        skipped_count: 1,
        photo_revision: 4,
        owner_revision: 0,
        evidence_generation: 8,
        replay_status: ReplayStatusV1::Created,
    };
    assert!(response.validate().is_ok());

    response.permanent_unavailable_count = 1;
    assert!(response.validate().is_err());
}
