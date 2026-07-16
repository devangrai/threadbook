use serde_json::json;
use wardrobe_core::*;

const REQUEST_ID: &str = "a5b238c1-df7e-4ec8-8330-abe67f7ad536";
const SNAPSHOT_TOKEN: &str = "deletion-plan-token";
const PLAN_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn revisions() -> DeletionRevisionSnapshotV1 {
    DeletionRevisionSnapshotV1 {
        catalog_revision: 1,
        evidence_generation: 2,
        receipt_revision: 3,
        photo_revision: 4,
        reconciliation_revision: 5,
        outfit_revision: 6,
        try_on_revision: 7,
        photokit_revision: 8,
    }
}

fn execute_request() -> ExecuteDeletionV1Request {
    ExecuteDeletionV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: RequestId::new_v4(),
        preview_snapshot_token: DeletionSnapshotTokenV1::new(SNAPSHOT_TOKEN.to_owned()).unwrap(),
        plan_sha256: Sha256Digest::parse(PLAN_SHA256).unwrap(),
        expected_revisions: revisions(),
        confirmation: DeletionConfirmationV1::DeleteActiveLocalData,
    }
}

#[test]
fn execute_request_strictly_decodes_the_frozen_authority_only() {
    let valid = json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "preview_snapshot_token": SNAPSHOT_TOKEN,
        "plan_sha256": PLAN_SHA256,
        "expected_revisions": {
            "catalog_revision": 1,
            "evidence_generation": 2,
            "receipt_revision": 3,
            "photo_revision": 4,
            "reconciliation_revision": 5,
            "outfit_revision": 6,
            "try_on_revision": 7,
            "photokit_revision": 8
        },
        "confirmation": "delete_active_local_data"
    });
    let decoded: ExecuteDeletionV1Request = serde_json::from_value(valid.clone()).unwrap();
    decoded.validate().unwrap();

    for (field, value) in [
        ("target_id", json!("7c9687dd-632f-4ce8-90fa-c7ec15e58a21")),
        ("source_path", json!("/Users/example/private.jpg")),
        ("provider_instruction", json!("delete_remote_object")),
    ] {
        let mut invalid = valid.clone();
        invalid
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), value);
        assert!(
            serde_json::from_value::<ExecuteDeletionV1Request>(invalid).is_err(),
            "accepted forbidden field {field}"
        );
    }

    let mut invalid_confirmation = valid.clone();
    invalid_confirmation["confirmation"] = json!("delete_everything");
    assert!(serde_json::from_value::<ExecuteDeletionV1Request>(invalid_confirmation).is_err());

    let mut uppercase_hash = valid;
    uppercase_hash["plan_sha256"] = json!("A".repeat(64));
    assert!(serde_json::from_value::<ExecuteDeletionV1Request>(uppercase_hash).is_err());
}

#[test]
fn execute_request_serialization_contains_no_target_path_or_provider_instruction() {
    let value = serde_json::to_value(execute_request()).unwrap();
    let object = value.as_object().unwrap();
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "confirmation",
            "expected_revisions",
            "plan_sha256",
            "preview_snapshot_token",
            "request_id",
            "schema_version",
        ]
    );

    let serialized = serde_json::to_string(&value).unwrap();
    for excluded in ["target", "path", "provider", "remote_locator"] {
        assert!(
            !serialized.contains(excluded),
            "execute envelope exposed {excluded}"
        );
    }
}

#[test]
fn revision_and_retention_bounds_fail_closed() {
    let mut invalid_revisions = revisions();
    invalid_revisions.photo_revision = MAX_SAFE_INTEGER_V1;
    assert_eq!(
        invalid_revisions.validate().unwrap_err().field,
        SafeFieldV1::DeletionRevisions
    );
    invalid_revisions.photo_revision = 4;
    invalid_revisions.photokit_revision = MAX_SAFE_INTEGER_V1;
    assert_eq!(
        invalid_revisions.validate().unwrap_err().field,
        SafeFieldV1::DeletionRevisions
    );

    let report = DeletionRemoteRetentionV1 {
        provider: CredentialProviderV1::OpenAi,
        purpose: DeletionRemotePurposeV1::TryOn,
        retention_mode: OpenAiRetentionModeV1::Default,
        retention_provenance: "openai_policy_2026_07".to_owned(),
        dispatched_at: "2026-07-15T16:00:00Z".to_owned(),
        policy_expires_at: Some("2026-08-14T16:00:00Z".to_owned()),
        status: DeletionRemoteRetentionStatusV1::ProviderDeletionUnavailable,
    };
    report.validate().unwrap();

    let report_json = serde_json::to_value(&report).unwrap();
    for field in ["remote_locator", "request_payload", "source_path"] {
        let mut with_locator = report_json.clone();
        with_locator
            .as_object_mut()
            .unwrap()
            .insert(field.to_owned(), json!("private-value"));
        assert!(
            serde_json::from_value::<DeletionRemoteRetentionV1>(with_locator).is_err(),
            "accepted forbidden report field {field}"
        );
    }

    let mut locator_like = report.clone();
    locator_like.retention_provenance = "/private/provider/object/123".to_owned();
    assert_eq!(
        locator_like.validate().unwrap_err().field,
        SafeFieldV1::DeletionRetention
    );

    let response = ExecuteDeletionV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        run_id: DeletionRunId::new_v4(),
        complete: true,
        accepted_at: "2026-07-15T16:00:00Z".to_owned(),
        deadline_at: "2026-07-15T17:00:00Z".to_owned(),
        completed_at: "2026-07-15T16:01:00Z".to_owned(),
        deleted_local_record_count: 1,
        deleted_unique_blob_count: 1,
        deleted_unique_blob_bytes: 64,
        retained_shared_blob_count: 0,
        backup_retention: vec![],
        remote_retention: vec![report; MAX_DELETION_RETENTION_REPORTS + 1],
        replay_status: ReplayStatusV1::Created,
    };
    assert_eq!(
        response.validate().unwrap_err().field,
        SafeFieldV1::DeletionRetention
    );
}

#[test]
fn responses_are_complete_only_and_health_is_consistent() {
    let mut response: ExecuteDeletionV1Response = serde_json::from_value(json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "run_id": "7c9687dd-632f-4ce8-90fa-c7ec15e58a21",
        "complete": true,
        "accepted_at": "2026-07-15T16:00:00Z",
        "deadline_at": "2026-07-15T17:00:00Z",
        "completed_at": "2026-07-15T16:01:00Z",
        "deleted_local_record_count": 12,
        "deleted_unique_blob_count": 2,
        "deleted_unique_blob_bytes": 4096,
        "retained_shared_blob_count": 1,
        "backup_retention": [],
        "remote_retention": [],
        "replay_status": "created"
    }))
    .unwrap();
    response.validate().unwrap();
    response.complete = false;
    assert_eq!(
        response.validate().unwrap_err().field,
        SafeFieldV1::DeletionPlan
    );
    response.complete = true;
    response.completed_at = "2026-07-15T18:00:00Z".to_owned();
    response.validate().unwrap();
    response.accepted_at = "2026-07-15T16:00:00Z".to_owned();
    response.deadline_at = "2026-07-15T16:00:00.001Z".to_owned();
    response.validate().unwrap();
    response.deadline_at = "2026-07-15T15:59:59.999Z".to_owned();
    assert_eq!(
        response.validate().unwrap_err().field,
        SafeFieldV1::Timestamp
    );

    DeletionHealthV1::none().validate().unwrap();
    let inconsistent = DeletionHealthV1 {
        status: DeletionHealthStatusV1::None,
        deadline_at: Some("2026-07-15T17:00:00Z".to_owned()),
        counts: DeletionHealthCountsV1 {
            in_progress: 1,
            overdue: 0,
            needs_attention: 0,
        },
    };
    assert_eq!(
        inconsistent.validate().unwrap_err().field,
        SafeFieldV1::DeletionHealth
    );
}

#[test]
fn deletion_bindings_include_execution_and_health_contracts() {
    let bindings = typescript_bindings();
    for declaration in [
        "export type ExecuteDeletionV1Request",
        "export type ExecuteDeletionV1Response",
        "export type DeletionRevisionSnapshotV1",
        "export type DeletionHealthV1",
        "delete_active_local_data",
        "provider_deletion_unavailable",
        "photokit_enrollment",
        "photokit_asset",
        "photokit_revision",
    ] {
        assert!(bindings.contains(declaration), "missing {declaration}");
    }

    let request_binding = bindings
        .split("export type ExecuteDeletionV1Request")
        .nth(1)
        .unwrap()
        .split("export type")
        .next()
        .unwrap();
    for excluded in ["target_id", "path", "provider_instruction"] {
        assert!(!request_binding.contains(excluded));
    }
}

#[test]
fn photokit_deletion_targets_are_closed_wire_values() {
    assert_eq!(
        serde_json::to_value(DeletionTargetKindV1::PhotoKitEnrollment).unwrap(),
        json!("photokit_enrollment")
    );
    assert_eq!(
        serde_json::to_value(DeletionTargetKindV1::PhotoKitAsset).unwrap(),
        json!("photokit_asset")
    );
    assert!(serde_json::from_value::<DeletionTargetKindV1>(json!("photokit_source")).is_err());
}
