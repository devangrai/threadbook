use wardrobe_core::{
    ErrorCodeV1, GetFoundationSnapshotV1Request, RequestId, SafeFieldV1, SaveCredentialV1Request,
    Validate, MAX_DISPLAY_LABEL_CHARS, MAX_SECRET_BYTES,
};

const REQUEST_ID: &str = "a5b238c1-df7e-4ec8-8330-abe67f7ad536";

#[test]
fn requests_reject_unknown_fields_and_non_v1_versions() {
    let unknown =
        format!(r#"{{"schema_version":1,"request_id":"{REQUEST_ID}","unexpected":true}}"#);
    let version = format!(r#"{{"schema_version":2,"request_id":"{REQUEST_ID}"}}"#);

    assert!(serde_json::from_str::<wardrobe_core::RunStorageCheckV1Request>(&unknown).is_err());
    assert!(serde_json::from_str::<wardrobe_core::RunStorageCheckV1Request>(&version).is_err());
}

#[test]
fn request_ids_require_canonical_non_nil_uuids() {
    for request_id in [
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
        "A5B238C1-DF7E-4EC8-8330-ABE67F7AD536",
        "a5b238c1df7e4ec88330abe67f7ad536",
    ] {
        let payload = format!(r#"{{"schema_version":1,"request_id":"{request_id}"}}"#);
        assert!(
            serde_json::from_str::<wardrobe_core::GetFoundationSnapshotV1Request>(&payload)
                .is_err(),
            "accepted {request_id}"
        );
    }
}

#[test]
fn credential_input_bounds_are_validated_without_exposing_secret() {
    let too_long = "x".repeat(MAX_DISPLAY_LABEL_CHARS + 1);
    let payload = format!(
        r#"{{"schema_version":1,"request_id":"{REQUEST_ID}","provider":"open_ai","display_label":"{too_long}","secret":"synthetic-secret"}}"#
    );
    let request: SaveCredentialV1Request = serde_json::from_str(&payload).unwrap();

    let error = request.validate().unwrap_err();
    assert_eq!(error.field, SafeFieldV1::DisplayLabel);
    assert!(!format!("{request:?}").contains("synthetic-secret"));

    let command_error = wardrobe_core::CommandErrorV1::from(error);
    assert_eq!(command_error.code, ErrorCodeV1::InvalidRequest);
}

#[test]
fn secret_and_schema_bounds_are_enforced() {
    for secret in [String::new(), "x".repeat(MAX_SECRET_BYTES + 1)] {
        let payload = format!(
            r#"{{"schema_version":1,"request_id":"{REQUEST_ID}","provider":"open_ai","display_label":"OpenAI","secret":"{secret}"}}"#
        );
        let request: SaveCredentialV1Request = serde_json::from_str(&payload).unwrap();
        assert_eq!(request.validate().unwrap_err().field, SafeFieldV1::Secret);
    }

    let request = GetFoundationSnapshotV1Request {
        schema_version: 2,
        request_id: RequestId::new_v4(),
    };
    let error = request.validate().unwrap_err();
    let command_error = wardrobe_core::CommandErrorV1::from(error);
    assert_eq!(command_error.code, ErrorCodeV1::UnsupportedSchemaVersion);
    assert_eq!(command_error.field, Some(SafeFieldV1::SchemaVersion));
}

fn attributes() -> wardrobe_core::ItemAttributesV1 {
    wardrobe_core::ItemAttributesV1 {
        display_name: "White T-Shirt".to_owned(),
        category: wardrobe_core::ItemCategoryV1::Top,
        subcategory: Some("T-Shirt".to_owned()),
        brand: None,
        primary_color: Some("White".to_owned()),
        size: Some("M".to_owned()),
        notes: None,
        tags: vec!["casual".to_owned()],
    }
}

#[test]
fn p02_requests_are_strict_and_require_revision_fields() {
    let item = wardrobe_core::ItemId::new_v4();
    let valid = serde_json::json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "item_id": item,
        "attributes": attributes(),
        "evidence_ids": [],
        "expected_catalog_revision": 0
    });
    assert!(serde_json::from_value::<wardrobe_core::SaveItemV1Request>(valid.clone()).is_ok());

    let mut unknown = valid.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("force".to_owned(), serde_json::json!(true));
    assert!(serde_json::from_value::<wardrobe_core::SaveItemV1Request>(unknown).is_err());

    let mut missing_revision = valid;
    missing_revision
        .as_object_mut()
        .unwrap()
        .remove("expected_catalog_revision");
    assert!(serde_json::from_value::<wardrobe_core::SaveItemV1Request>(missing_revision).is_err());
}

#[test]
fn item_attribute_and_collection_bounds_are_enforced() {
    let mut value = attributes();
    assert!(value.validate().is_ok());

    value.display_name = "x".repeat(wardrobe_core::MAX_ITEM_NAME_CHARS + 1);
    assert_eq!(value.validate().unwrap_err().field, SafeFieldV1::Attributes);

    let mut value = attributes();
    value.notes = Some("x".repeat(wardrobe_core::MAX_ITEM_NOTES_CHARS + 1));
    assert_eq!(value.validate().unwrap_err().field, SafeFieldV1::Attributes);

    let mut value = attributes();
    value.tags = vec!["duplicate".to_owned(), "duplicate".to_owned()];
    assert_eq!(value.validate().unwrap_err().field, SafeFieldV1::Collection);
}

#[test]
fn catalog_revisions_remain_exact_in_typescript() {
    let request = wardrobe_core::SaveItemV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        item_id: None,
        attributes: attributes(),
        evidence_ids: vec![],
        expected_catalog_revision: wardrobe_core::MAX_SAFE_INTEGER_V1,
    };
    assert_eq!(
        request.validate().unwrap_err().field,
        SafeFieldV1::ExpectedCatalogRevision
    );
}

#[test]
fn evidence_decisions_and_split_groups_are_unambiguous() {
    let evidence_id = wardrobe_core::EvidenceId::new_v4();
    let item_id = wardrobe_core::ItemId::new_v4();
    let invalid_assign = wardrobe_core::DecideEvidenceV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        evidence_id,
        action: wardrobe_core::EvidenceDecisionActionV1::Assign,
        item_id: None,
        expected_catalog_revision: 0,
    };
    assert_eq!(
        invalid_assign.validate().unwrap_err().field,
        SafeFieldV1::ItemId
    );

    let invalid_reject = wardrobe_core::DecideEvidenceV1Request {
        item_id: Some(item_id),
        action: wardrobe_core::EvidenceDecisionActionV1::Reject,
        ..invalid_assign
    };
    assert_eq!(
        invalid_reject.validate().unwrap_err().field,
        SafeFieldV1::ItemId
    );

    let duplicate = wardrobe_core::SplitItemV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        item_id,
        groups: vec![
            wardrobe_core::SplitGroupV1 {
                attributes: attributes(),
                evidence_ids: vec![evidence_id],
            },
            wardrobe_core::SplitGroupV1 {
                attributes: attributes(),
                evidence_ids: vec![evidence_id],
            },
        ],
        expected_catalog_revision: 0,
    };
    assert_eq!(
        duplicate.validate().unwrap_err().field,
        SafeFieldV1::EvidenceId
    );
}

#[test]
fn paging_and_deletion_tokens_are_bounded_opaque_values() {
    assert!(wardrobe_core::PageCursorV1::new("cursor-v1".to_owned()).is_ok());
    assert!(wardrobe_core::PageCursorV1::new(String::new()).is_err());
    assert!(wardrobe_core::PageCursorV1::new("bad\ncursor".to_owned()).is_err());

    let request = wardrobe_core::ListCatalogV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        cursor: None,
        limit: 0,
    };
    assert_eq!(request.validate().unwrap_err().field, SafeFieldV1::Limit);

    let noncanonical_target = wardrobe_core::PreviewDeletionV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        target_kind: wardrobe_core::DeletionTargetKindV1::Item,
        target_id: item_uuid_without_hyphens(),
        limit: 25,
    };
    assert_eq!(
        noncanonical_target.validate().unwrap_err().field,
        SafeFieldV1::DeletionTarget
    );
}

fn item_uuid_without_hyphens() -> String {
    wardrobe_core::ItemId::new_v4().to_string().replace('-', "")
}

#[test]
fn deletion_classes_cover_every_dependency_and_shared_retention() {
    use wardrobe_core::DeletionDependencyClassV1::*;

    let classes = [
        Originals,
        Derivatives,
        SourceRecords,
        EvidenceRecords,
        DecisionRecords,
        RemoteReferences,
        RetainedSharedBlobs,
    ];
    let mut unique = classes.to_vec();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 7);
}
