use wardrobe_core::{
    typescript_bindings, CatalogSnapshotV1, DeletionHealthV1, FoundationSnapshotV1,
    FoundationVersionsV1, GetFoundationSnapshotV1Response, LocalOnlyAuthorityHealthV1,
    LocalSettingsSnapshotV1, ReplayStatusV1, RequestId, SafeFieldV1, SetLocalOnlyV1Request,
    SetLocalOnlyV1Response, StorageStatusV1, Validate, MAX_SAFE_INTEGER_V1,
};

const REQUEST_ID: &str = "a5b238c1-df7e-4ec8-8330-abe67f7ad536";

fn local_settings(
    local_only: bool,
    revision: u64,
    authority_health: LocalOnlyAuthorityHealthV1,
) -> LocalSettingsSnapshotV1 {
    LocalSettingsSnapshotV1 {
        local_only,
        revision,
        authority_health,
        storage_status: StorageStatusV1::Ready,
        deletion_health: DeletionHealthV1::none(),
    }
}

fn response(
    local_only: bool,
    revision: u64,
    authority_health: LocalOnlyAuthorityHealthV1,
) -> SetLocalOnlyV1Response {
    SetLocalOnlyV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        local_only,
        revision,
        authority_health,
        replay_status: ReplayStatusV1::Created,
    }
}

#[test]
fn request_decoding_is_strict() {
    let valid = serde_json::json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "enabled": true,
        "expected_revision": 0
    });
    assert!(serde_json::from_value::<SetLocalOnlyV1Request>(valid.clone()).is_ok());

    let mut unknown = valid.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("force".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<SetLocalOnlyV1Request>(unknown).is_err());

    let mut unsupported = valid;
    unsupported["schema_version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<SetLocalOnlyV1Request>(unsupported).is_err());
}

#[test]
fn authority_health_decoding_rejects_unknown_variants() {
    assert_eq!(
        serde_json::from_str::<LocalOnlyAuthorityHealthV1>(r#""persisted""#).unwrap(),
        LocalOnlyAuthorityHealthV1::Persisted
    );
    assert_eq!(
        serde_json::from_str::<LocalOnlyAuthorityHealthV1>(r#""fail_closed_uncertain""#,).unwrap(),
        LocalOnlyAuthorityHealthV1::FailClosedUncertain
    );
    assert!(serde_json::from_str::<LocalOnlyAuthorityHealthV1>(r#""unknown""#).is_err());
}

#[test]
fn every_local_only_contract_rejects_unknown_fields() {
    let request = serde_json::json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "enabled": false,
        "expected_revision": 0,
        "unexpected": null
    });
    let snapshot = serde_json::json!({
        "local_only": true,
        "revision": 0,
        "authority_health": "fail_closed_default",
        "storage_status": "ready",
        "deletion_health": DeletionHealthV1::none(),
        "unexpected": null
    });
    let response = serde_json::json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "local_only": true,
        "revision": 1,
        "authority_health": "persisted",
        "replay_status": "created",
        "unexpected": null
    });

    assert!(serde_json::from_value::<SetLocalOnlyV1Request>(request).is_err());
    assert!(serde_json::from_value::<LocalSettingsSnapshotV1>(snapshot).is_err());
    assert!(serde_json::from_value::<SetLocalOnlyV1Response>(response).is_err());
}

#[test]
fn request_and_returned_revisions_stay_in_the_javascript_safe_range() {
    let request = SetLocalOnlyV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        enabled: true,
        expected_revision: MAX_SAFE_INTEGER_V1 - 1,
    };
    assert!(request.validate().is_ok());

    let exhausted = SetLocalOnlyV1Request {
        expected_revision: MAX_SAFE_INTEGER_V1,
        ..request
    };
    assert_eq!(
        exhausted.validate().unwrap_err().field,
        SafeFieldV1::ExpectedLocalOnlyRevision
    );

    assert!(response(
        false,
        MAX_SAFE_INTEGER_V1,
        LocalOnlyAuthorityHealthV1::Persisted
    )
    .validate()
    .is_ok());
    assert_eq!(
        response(
            false,
            MAX_SAFE_INTEGER_V1 + 1,
            LocalOnlyAuthorityHealthV1::Persisted
        )
        .validate()
        .unwrap_err()
        .field,
        SafeFieldV1::ExpectedLocalOnlyRevision
    );
}

#[test]
fn persisted_snapshots_accept_both_boolean_modes() {
    assert!(
        local_settings(true, 1, LocalOnlyAuthorityHealthV1::Persisted)
            .validate()
            .is_ok()
    );
    assert!(
        local_settings(false, 1, LocalOnlyAuthorityHealthV1::Persisted)
            .validate()
            .is_ok()
    );
}

#[test]
fn fail_closed_default_snapshot_is_local_only_at_revision_zero() {
    assert!(
        local_settings(true, 0, LocalOnlyAuthorityHealthV1::FailClosedDefault)
            .validate()
            .is_ok()
    );
    for invalid in [
        local_settings(false, 0, LocalOnlyAuthorityHealthV1::FailClosedDefault),
        local_settings(true, 1, LocalOnlyAuthorityHealthV1::FailClosedDefault),
        local_settings(true, 0, LocalOnlyAuthorityHealthV1::Persisted),
    ] {
        assert_eq!(
            invalid.validate().unwrap_err().field,
            SafeFieldV1::LocalOnlyAuthority
        );
    }
}

#[test]
fn fail_closed_uncertain_snapshot_is_local_only_at_a_repairable_revision() {
    assert!(
        local_settings(true, 1, LocalOnlyAuthorityHealthV1::FailClosedUncertain)
            .validate()
            .is_ok()
    );
    for invalid in [
        local_settings(false, 1, LocalOnlyAuthorityHealthV1::FailClosedUncertain),
        local_settings(true, 0, LocalOnlyAuthorityHealthV1::FailClosedUncertain),
    ] {
        assert_eq!(
            invalid.validate().unwrap_err().field,
            SafeFieldV1::LocalOnlyAuthority
        );
    }
}

#[test]
fn set_response_requires_a_persisted_nonzero_revision_and_valid_header() {
    for local_only in [true, false] {
        assert!(
            response(local_only, 1, LocalOnlyAuthorityHealthV1::Persisted)
                .validate()
                .is_ok()
        );
    }

    assert_eq!(
        response(true, 1, LocalOnlyAuthorityHealthV1::FailClosedDefault)
            .validate()
            .unwrap_err()
            .field,
        SafeFieldV1::LocalOnlyAuthority
    );
    assert_eq!(
        response(true, 1, LocalOnlyAuthorityHealthV1::FailClosedUncertain)
            .validate()
            .unwrap_err()
            .field,
        SafeFieldV1::LocalOnlyAuthority
    );
    assert_eq!(
        response(true, 0, LocalOnlyAuthorityHealthV1::Persisted)
            .validate()
            .unwrap_err()
            .field,
        SafeFieldV1::ExpectedLocalOnlyRevision
    );

    let mut invalid_header = response(true, 1, LocalOnlyAuthorityHealthV1::Persisted);
    invalid_header.schema_version = 2;
    assert_eq!(
        invalid_header.validate().unwrap_err().field,
        SafeFieldV1::SchemaVersion
    );
}

#[test]
fn foundation_response_validates_its_header_and_nested_snapshot() {
    let mut response = GetFoundationSnapshotV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        snapshot: FoundationSnapshotV1 {
            schema_version: 1,
            versions: FoundationVersionsV1 {
                application: "0.1.0".to_owned(),
                database_schema: 1,
                job_pipeline: 1,
            },
            local_settings: local_settings(false, 1, LocalOnlyAuthorityHealthV1::Persisted),
            credential_references: vec![],
            recent_jobs: vec![],
            catalog: CatalogSnapshotV1 { items: vec![] },
        },
    };
    assert!(response.validate().is_ok());

    response.snapshot.local_settings.revision = MAX_SAFE_INTEGER_V1 + 1;
    assert_eq!(
        response.validate().unwrap_err().field,
        SafeFieldV1::ExpectedLocalOnlyRevision
    );
}

#[test]
fn typescript_bindings_include_every_local_only_contract() {
    let bindings = typescript_bindings();
    for declaration in [
        "export type LocalOnlyAuthorityHealthV1",
        "export type SetLocalOnlyV1Request",
        "export type SetLocalOnlyV1Response",
        "revision: number",
        "authority_health: LocalOnlyAuthorityHealthV1",
    ] {
        assert!(
            bindings.contains(declaration),
            "missing TypeScript declaration: {declaration}"
        );
    }
}
