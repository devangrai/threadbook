use serde_json::{json, Value};
use wardrobe_core::*;

const REQUEST_ID: &str = "a5b238c1-df7e-4ec8-8330-abe67f7ad536";
const EPOCH: &str = "247a118b-6130-44dc-b165-39c83f38ca7b";
const SESSION: &str = "5c0f7690-ed56-4a87-8cd5-06974aaf42f0";

fn counts(observed: u16, available: u16, unavailable: u16) -> PhotoKitAssetCountsV1 {
    PhotoKitAssetCountsV1 {
        observed,
        available,
        unavailable,
    }
}

fn complete_snapshot() -> PhotoKitConnectorSnapshotV1 {
    PhotoKitConnectorSnapshotV1 {
        state: PhotoKitConnectorStateV1::Ready,
        authorization: PhotoKitAuthorizationV1::Authorized,
        enrollment_epoch: Some(PhotoKitEnrollmentEpochV1::new_v4()),
        membership_generation: Some(PhotoKitMembershipGenerationV1::new(7).unwrap()),
        photokit_revision: PhotoKitRevisionV1::new(11).unwrap(),
        allow_icloud_downloads: false,
        last_complete_at: Some("2026-07-15T20:30:00Z".to_owned()),
        counts: counts(2, 1, 1),
        availability_counts: vec![
            PhotoKitAvailabilityCountV1 {
                availability: PhotoKitAvailabilityV1::Available,
                reason: PhotoKitAvailabilityReasonV1::Materialized,
                count: 1,
            },
            PhotoKitAvailabilityCountV1 {
                availability: PhotoKitAvailabilityV1::Unavailable,
                reason: PhotoKitAvailabilityReasonV1::IcloudUnavailable,
                count: 1,
            },
        ],
    }
}

#[test]
fn photokit_envelopes_and_nested_values_reject_unknown_fields() {
    for value in [
        json!({"schema_version": 1, "request_id": REQUEST_ID, "extra": true}),
        json!({"schema_version": 1, "request_id": REQUEST_ID, "extra": true}),
        json!({"schema_version": 1, "request_id": REQUEST_ID, "extra": true}),
    ] {
        assert!(serde_json::from_value::<GetPhotoKitConnectorV1Request>(value.clone()).is_err());
        assert!(serde_json::from_value::<BeginPhotoKitSetupV1Request>(value.clone()).is_err());
        assert!(serde_json::from_value::<SyncPhotoKitV1Request>(value).is_err());
    }

    assert!(
        serde_json::from_value::<ConfigurePhotoKitScopeV1Request>(json!({
            "schema_version": 1,
            "request_id": REQUEST_ID,
            "setup_session_id": SESSION,
            "selection_token": "opaque-token",
            "allow_icloud_downloads": false,
            "native_identifier": "must-not-be-accepted"
        }))
        .is_err()
    );
    assert!(serde_json::from_value::<DisablePhotoKitV1Request>(json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "expected_photokit_revision": 4,
        "extra": 1
    }))
    .is_err());
    assert!(
        serde_json::from_value::<PhotoKitConnectorSnapshotV1>(json!({
            "state": "unconfigured",
            "authorization": "not_determined",
            "enrollment_epoch": null,
            "membership_generation": null,
            "photokit_revision": 0,
            "allow_icloud_downloads": false,
            "last_complete_at": null,
            "counts": {
                "observed": 0,
                "available": 0,
                "unavailable": 0,
                "extra": 1
            },
            "availability_counts": []
        }))
        .is_err()
    );
}

#[test]
fn photokit_schema_and_enums_are_closed() {
    assert!(
        serde_json::from_value::<GetPhotoKitConnectorV1Request>(json!({
            "schema_version": 2,
            "request_id": REQUEST_ID
        }))
        .is_err()
    );

    for value in [
        serde_json::from_value::<PhotoKitAuthorizationV1>(json!("full")).map(|_| ()),
        serde_json::from_value::<PhotoKitConnectorStateV1>(json!("disabled")).map(|_| ()),
        serde_json::from_value::<PhotoKitAvailabilityV1>(json!("missing")).map(|_| ()),
        serde_json::from_value::<PhotoKitAvailabilityReasonV1>(json!("native_error")).map(|_| ()),
        serde_json::from_value::<PhotoKitReconcileTriggerV1>(json!("notification")).map(|_| ()),
    ] {
        assert!(value.is_err());
    }
}

#[test]
fn photokit_identities_have_independent_strict_wire_domains() {
    let epoch: PhotoKitEnrollmentEpochV1 = serde_json::from_value(json!(EPOCH)).unwrap();
    let fence: PhotoKitReconciliationFenceV1 = serde_json::from_value(json!(3)).unwrap();
    let generation: PhotoKitMembershipGenerationV1 = serde_json::from_value(json!(4)).unwrap();
    let revision: PhotoKitRevisionV1 = serde_json::from_value(json!(0)).unwrap();

    assert_eq!(epoch.to_string(), EPOCH);
    assert_eq!(fence.get(), 3);
    assert_eq!(generation.get(), 4);
    assert_eq!(revision.get(), 0);
    assert!(serde_json::from_value::<PhotoKitEnrollmentEpochV1>(json!(
        "00000000-0000-0000-0000-000000000000"
    ))
    .is_err());
    assert!(serde_json::from_value::<PhotoKitReconciliationFenceV1>(json!(0)).is_err());
    assert!(serde_json::from_value::<PhotoKitMembershipGenerationV1>(json!(0)).is_err());
    assert!(serde_json::from_value::<PhotoKitRevisionV1>(json!(MAX_SAFE_INTEGER_V1)).is_err());
}

#[test]
fn setup_tokens_labels_candidates_and_asset_counts_are_bounded() {
    assert!(PhotoKitSelectionTokenV1::new("token_1").is_ok());
    assert!(PhotoKitSelectionTokenV1::new("").is_err());
    assert!(
        PhotoKitSelectionTokenV1::new("x".repeat(MAX_PHOTOKIT_SELECTION_TOKEN_BYTES + 1)).is_err()
    );
    assert!(PhotoKitSelectionTokenV1::new("token with space").is_err());

    let mut response = BeginPhotoKitSetupV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        snapshot: PhotoKitConnectorSnapshotV1 {
            state: PhotoKitConnectorStateV1::SetupRequired,
            authorization: PhotoKitAuthorizationV1::Authorized,
            enrollment_epoch: None,
            membership_generation: None,
            photokit_revision: PhotoKitRevisionV1::new(0).unwrap(),
            allow_icloud_downloads: false,
            last_complete_at: None,
            counts: counts(0, 0, 0),
            availability_counts: vec![],
        },
        setup_session_id: Some(PhotoKitSetupSessionIdV1::new_v4()),
        expires_at: Some("2026-07-15T20:40:00Z".to_owned()),
        album_candidates: vec![PhotoKitAlbumCandidateV1 {
            selection_token: PhotoKitSelectionTokenV1::new("album-token").unwrap(),
            display_label: "Wardrobe Imports".to_owned(),
        }],
        replay_status: ReplayStatusV1::Created,
    };
    assert!(response.validate().is_ok());

    response.album_candidates[0].display_label = "x".repeat(MAX_PHOTOKIT_ALBUM_LABEL_CHARS + 1);
    assert_eq!(
        response.validate().unwrap_err().field,
        SafeFieldV1::PhotoKitAlbumCandidates
    );
    response.album_candidates[0].display_label = "Wardrobe Imports".to_owned();
    response.album_candidates = (0..=MAX_PHOTOKIT_ALBUM_CANDIDATES)
        .map(|index| PhotoKitAlbumCandidateV1 {
            selection_token: PhotoKitSelectionTokenV1::new(format!("token-{index}")).unwrap(),
            display_label: format!("Album {index}"),
        })
        .collect();
    assert_eq!(
        response.validate().unwrap_err().field,
        SafeFieldV1::PhotoKitAlbumCandidates
    );

    assert!(counts(MAX_PHOTOKIT_ASSETS, 250, 250).validate().is_ok());
    assert_eq!(
        counts(MAX_PHOTOKIT_ASSETS + 1, 501, 0)
            .validate()
            .unwrap_err()
            .field,
        SafeFieldV1::PhotoKitCounts
    );
    assert!(counts(2, 1, 0).validate().is_err());
}

#[test]
fn snapshot_validates_generation_and_availability_invariants() {
    let mut snapshot = complete_snapshot();
    assert!(snapshot.validate().is_ok());

    snapshot
        .availability_counts
        .push(PhotoKitAvailabilityCountV1 {
            availability: PhotoKitAvailabilityV1::Available,
            reason: PhotoKitAvailabilityReasonV1::Materialized,
            count: 1,
        });
    assert_eq!(
        snapshot.validate().unwrap_err().field,
        SafeFieldV1::PhotoKitAvailability
    );

    let mut snapshot = complete_snapshot();
    snapshot.membership_generation = None;
    assert_eq!(
        snapshot.validate().unwrap_err().field,
        SafeFieldV1::PhotoKitStatus
    );

    let invalid_pair = PhotoKitAvailabilityCountV1 {
        availability: PhotoKitAvailabilityV1::Available,
        reason: PhotoKitAvailabilityReasonV1::AuthorizationDenied,
        count: 1,
    };
    assert_eq!(
        invalid_pair.validate().unwrap_err().field,
        SafeFieldV1::PhotoKitAvailability
    );
}

#[test]
fn durable_and_sync_response_shapes_are_replay_safe_and_native_identifier_free() {
    let native_values = [
        "A1B2C3/L0/001",
        "/Users/person/Pictures/private.heic",
        "private.heic",
        "opaque-selection-token",
        "Personal Album",
    ];
    let configure = ConfigurePhotoKitScopeV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        snapshot: complete_snapshot(),
        replay_status: ReplayStatusV1::Replayed,
    };
    let sync = SyncPhotoKitV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        operation_id: OperationId::new_v4(),
        trigger: PhotoKitReconcileTriggerV1::User,
        reconciliation_fence: PhotoKitReconciliationFenceV1::new(9).unwrap(),
        snapshot: complete_snapshot(),
        replay_status: ReplayStatusV1::Replayed,
    };
    let disable = DisablePhotoKitV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        state: PhotoKitConnectorStateV1::Unconfigured,
        disabled_enrollment_epoch: PhotoKitEnrollmentEpochV1::new_v4(),
        preserved_membership_generation: Some(PhotoKitMembershipGenerationV1::new(7).unwrap()),
        photokit_revision: PhotoKitRevisionV1::new(12).unwrap(),
        preserved_counts: counts(2, 1, 1),
        replay_status: ReplayStatusV1::Replayed,
    };

    for response in [
        serde_json::to_value(configure).unwrap(),
        serde_json::to_value(sync).unwrap(),
        serde_json::to_value(disable).unwrap(),
    ] {
        let encoded = response.to_string();
        for native in native_values {
            assert!(!encoded.contains(native), "leaked {native}");
        }
        for forbidden_key in [
            "local_identifier",
            "filename",
            "path",
            "selection_token",
            "setup_session_id",
        ] {
            assert!(!contains_key(&response, forbidden_key));
        }
        assert_eq!(
            response["replay_status"],
            Value::String("replayed".to_owned())
        );
    }
}

#[test]
fn photokit_types_are_in_generated_typescript_declarations() {
    let bindings = typescript_bindings();
    for name in [
        "PhotoKitEnrollmentEpochV1",
        "PhotoKitReconciliationFenceV1",
        "PhotoKitMembershipGenerationV1",
        "PhotoKitRevisionV1",
        "PhotoKitAuthorizationV1",
        "PhotoKitConnectorStateV1",
        "PhotoKitAvailabilityReasonV1",
        "PhotoKitConnectorSnapshotV1",
        "BeginPhotoKitSetupV1Response",
        "ConfigurePhotoKitScopeV1Request",
        "SyncPhotoKitV1Response",
        "DisablePhotoKitV1Response",
    ] {
        assert!(bindings.contains(name), "missing {name}");
    }
}

fn contains_key(value: &Value, needle: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.contains_key(needle) || object.values().any(|value| contains_key(value, needle))
        }
        Value::Array(values) => values.iter().any(|value| contains_key(value, needle)),
        _ => false,
    }
}
