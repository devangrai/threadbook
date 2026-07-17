use serde_json::json;
use wardrobe_core::*;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn authority(review_decision_id: ReceiptReviewDecisionId) -> ReceiptPurchaseUnitAuthorityV1 {
    ReceiptPurchaseUnitAuthorityV1 {
        authority_id: ReceiptSourceAuthorityId::new_v4(),
        source_id: SourceId::new_v4(),
        order_evidence_id: ReceiptOrderEvidenceId::new_v4(),
        review_decision_id,
        review_action: ReceiptReviewActionV1::Correct,
        authority_revision: 3,
        receipt_revision: 8,
    }
}

fn values() -> ReceiptPurchaseUnitValuesV1 {
    ReceiptPurchaseUnitValuesV1 {
        merchant: Some("Synthetic Shop".to_owned()),
        order_identifier: None,
        purchase_date: Some("2026-07-16".to_owned()),
        currency: Some("USD".to_owned()),
        description: Some("Synthetic top".to_owned()),
        event_kind: ReceiptEventKindV1::Purchase,
        quantity: 2,
        unit_price_minor: None,
        brand: None,
        sku: None,
        size: Some("M".to_owned()),
        color: None,
    }
}

fn provenance(review_decision_id: ReceiptReviewDecisionId) -> ReceiptPurchaseUnitProvenanceV1 {
    let corrected = || ReceiptPurchaseUnitFieldProvenanceV1::UserCorrection { review_decision_id };
    ReceiptPurchaseUnitProvenanceV1 {
        merchant: corrected(),
        order_identifier: ReceiptPurchaseUnitFieldProvenanceV1::UnknownReceiptField,
        purchase_date: corrected(),
        currency: corrected(),
        description: corrected(),
        event_kind: corrected(),
        quantity: corrected(),
        unit_price_minor: ReceiptPurchaseUnitFieldProvenanceV1::UnknownReceiptField,
        brand: ReceiptPurchaseUnitFieldProvenanceV1::UnknownReceiptField,
        sku: ReceiptPurchaseUnitFieldProvenanceV1::UnknownReceiptField,
        size: corrected(),
        color: ReceiptPurchaseUnitFieldProvenanceV1::UnknownReceiptField,
    }
}

fn unit() -> ReceiptPurchaseUnitV1 {
    let order_line_id = ReceiptOrderLineId::new_v4();
    let review_decision_id = ReceiptReviewDecisionId::new_v4();
    ReceiptPurchaseUnitV1 {
        purchase_unit_id: ReceiptPurchaseUnitId::derive_v1(order_line_id, 0).unwrap(),
        order_line_id,
        unit_ordinal: 0,
        authoritative_quantity: 2,
        values: values(),
        provenance: provenance(review_decision_id),
        authority: authority(review_decision_id),
        purchase_unit_revision: 1,
        unit_snapshot_sha256: Sha256Digest::parse(DIGEST).unwrap(),
        catalog_revision: 4,
        evidence_generation: 6,
        status: ReceiptPurchaseUnitStatusV1::Available,
    }
}

fn attributes() -> ItemAttributesV1 {
    ItemAttributesV1 {
        display_name: "My synthetic top".to_owned(),
        category: ItemCategoryV1::Top,
        subcategory: None,
        brand: None,
        primary_color: None,
        size: Some("M".to_owned()),
        notes: None,
        tags: vec![],
    }
}

#[test]
fn purchase_unit_contracts_are_strict_distinct_and_snapshot_bound() {
    let first_line = ReceiptOrderLineId::new_v4();
    let second_line = ReceiptOrderLineId::new_v4();
    let first = ReceiptPurchaseUnitId::derive_v1(first_line, 0).unwrap();
    assert_eq!(
        first,
        ReceiptPurchaseUnitId::derive_v1(first_line, 0).unwrap()
    );
    assert_ne!(
        first,
        ReceiptPurchaseUnitId::derive_v1(first_line, 1).unwrap()
    );
    assert_ne!(
        first,
        ReceiptPurchaseUnitId::derive_v1(second_line, 0).unwrap()
    );
    assert!(ReceiptPurchaseUnitId::derive_v1(first_line, MAX_RECEIPT_QUANTITY as u32).is_err());
    assert_ne!(
        std::any::type_name::<ReceiptPurchaseUnitId>(),
        std::any::type_name::<ReceiptOrderLineId>()
    );
    assert_ne!(
        std::any::type_name::<ReceiptPurchaseUnitId>(),
        std::any::type_name::<EvidenceId>()
    );
    assert_ne!(
        std::any::type_name::<ReceiptPromotionId>(),
        std::any::type_name::<ItemId>()
    );

    let valid = unit();
    valid.validate().unwrap();
    let encoded = serde_json::to_value(&valid).unwrap();
    assert!(serde_json::from_value::<ReceiptPurchaseUnitV1>(encoded.clone()).is_ok());

    let mut unknown = encoded;
    unknown["snapshot_override"] = json!(DIGEST);
    assert!(serde_json::from_value::<ReceiptPurchaseUnitV1>(unknown).is_err());

    let mut missing_explicit_unknown = serde_json::to_value(&valid).unwrap();
    missing_explicit_unknown["values"]
        .as_object_mut()
        .unwrap()
        .remove("order_identifier");
    assert!(serde_json::from_value::<ReceiptPurchaseUnitV1>(missing_explicit_unknown).is_err());

    let mut invalid_currency = valid.clone();
    invalid_currency.values.currency = Some("usd".to_owned());
    assert_eq!(
        invalid_currency.validate().unwrap_err().field,
        SafeFieldV1::ReceiptPurchaseUnit
    );

    let mut invalid_date = valid.clone();
    invalid_date.values.purchase_date = Some("2026-02-30".to_owned());
    assert_eq!(
        invalid_date.validate().unwrap_err().field,
        SafeFieldV1::ReceiptPurchaseUnit
    );

    let mut missing_provenance = valid.clone();
    missing_provenance.provenance.merchant =
        ReceiptPurchaseUnitFieldProvenanceV1::UnknownReceiptField;
    assert_eq!(
        missing_provenance.validate().unwrap_err().field,
        SafeFieldV1::ReceiptPurchaseUnitProvenance
    );

    let mut confirmed_with_correction = valid.clone();
    confirmed_with_correction.authority.review_action = ReceiptReviewActionV1::Confirm;
    assert_eq!(
        confirmed_with_correction.validate().unwrap_err().field,
        SafeFieldV1::ReceiptPurchaseUnitProvenance
    );

    let mut wrong_identity = valid.clone();
    wrong_identity.purchase_unit_id = ReceiptPurchaseUnitId::new_v4();
    assert_eq!(
        wrong_identity.validate().unwrap_err().field,
        SafeFieldV1::ReceiptPurchaseUnit
    );

    let mut stale = valid;
    stale.purchase_unit_revision = MAX_SAFE_INTEGER_V1;
    assert_eq!(
        stale.validate().unwrap_err().field,
        SafeFieldV1::ReceiptPurchaseUnit
    );

    let list = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "source_id": null,
        "status": "available",
        "cursor": null,
        "limit": 25
    });
    let decoded: ListReceiptPurchaseUnitsV1Request = serde_json::from_value(list.clone()).unwrap();
    decoded.validate().unwrap();
    let mut wrong_version = list;
    wrong_version["schema_version"] = json!(2);
    assert!(serde_json::from_value::<ListReceiptPurchaseUnitsV1Request>(wrong_version).is_err());
}

#[test]
fn promotion_requires_affirmative_user_authority() {
    let unit = unit();
    let request = PromoteReceiptPurchaseUnitV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        purchase_unit_id: unit.purchase_unit_id,
        expected_purchase_unit_revision: unit.purchase_unit_revision,
        expected_unit_snapshot_sha256: unit.unit_snapshot_sha256.clone(),
        expected_authority_id: unit.authority.authority_id,
        expected_authority_revision: unit.authority.authority_revision,
        expected_receipt_revision: unit.authority.receipt_revision,
        expected_review_decision_id: unit.authority.review_decision_id,
        expected_catalog_revision: unit.catalog_revision,
        confirmation: ReceiptPromotionConfirmationV1::CreateOneWardrobeItem,
        category_authority: ReceiptPromotionCategoryAuthorityV1::UserSelected,
        attributes: attributes(),
    };
    request.validate().unwrap();
    assert_eq!(
        request.resulting_purchase_unit_revision(),
        Some(unit.purchase_unit_revision + 1)
    );

    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["confirmation"], json!("create_one_wardrobe_item"));
    assert_eq!(encoded["category_authority"], json!("user_selected"));

    let mut boolean_confirmation = encoded.clone();
    boolean_confirmation["confirmation"] = json!(true);
    assert!(
        serde_json::from_value::<PromoteReceiptPurchaseUnitV1Request>(boolean_confirmation)
            .is_err()
    );

    let mut non_affirmative = encoded.clone();
    non_affirmative["confirmation"] = json!("cancel");
    assert!(
        serde_json::from_value::<PromoteReceiptPurchaseUnitV1Request>(non_affirmative).is_err()
    );

    let mut inferred_category = encoded.clone();
    inferred_category["category_authority"] = json!("inferred");
    assert!(
        serde_json::from_value::<PromoteReceiptPurchaseUnitV1Request>(inferred_category).is_err()
    );

    let mut missing_category = encoded.clone();
    missing_category["attributes"]
        .as_object_mut()
        .unwrap()
        .remove("category");
    assert!(
        serde_json::from_value::<PromoteReceiptPurchaseUnitV1Request>(missing_category).is_err()
    );

    let mut missing_nullable_attribute = encoded.clone();
    missing_nullable_attribute["attributes"]
        .as_object_mut()
        .unwrap()
        .remove("brand");
    assert!(
        serde_json::from_value::<PromoteReceiptPurchaseUnitV1Request>(missing_nullable_attribute)
            .is_err()
    );

    let mut unknown = encoded;
    unknown["force"] = json!(true);
    assert!(serde_json::from_value::<PromoteReceiptPurchaseUnitV1Request>(unknown).is_err());
}

#[test]
fn promotion_decision_is_irreversible() {
    let decision = DecisionSnapshotV1 {
        decision_id: DecisionId::new_v4(),
        kind: DecisionKindV1::PromoteReceiptPurchaseUnit,
        affected_item_ids: vec![ItemId::new_v4()],
        affected_evidence_ids: vec![EvidenceId::new_v4()],
        compensates_decision_id: None,
        reversible: false,
    };
    decision.validate().unwrap();
    assert!(!decision.kind.allows_generic_undo());
    assert!(!decision.allows_generic_undo());
    assert_eq!(
        serde_json::to_value(decision.kind).unwrap(),
        json!("promote_receipt_purchase_unit")
    );

    let mut reversible = decision;
    reversible.reversible = true;
    assert_eq!(
        reversible.validate().unwrap_err().field,
        SafeFieldV1::DecisionId
    );

    let undo = UndoDecisionV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        decision_id: reversible.decision_id,
        expected_catalog_revision: 0,
    };
    undo.validate().unwrap();
    assert!(!DecisionKindV1::PromoteReceiptPurchaseUnit.allows_generic_undo());
}

#[test]
fn deletion_contracts_cover_unit_evidence_and_shared_records() {
    assert_eq!(
        serde_json::to_value(EvidenceKindV1::ReceiptPurchaseUnit).unwrap(),
        json!("receipt_purchase_unit")
    );
    assert_eq!(
        serde_json::to_value(DeletionTargetKindV1::PurchaseUnit).unwrap(),
        json!("purchase_unit")
    );
    assert_eq!(
        serde_json::to_value(DeletionTargetKindV1::ReceiptPurchaseUnitEvidence).unwrap(),
        json!("receipt_purchase_unit_evidence")
    );
    assert_eq!(
        serde_json::to_value(DeletionDependencyClassV1::RetainedSharedRecords).unwrap(),
        json!("retained_shared_records")
    );

    for (target_kind, target_id) in [
        (
            DeletionTargetKindV1::PurchaseUnit,
            ReceiptPurchaseUnitId::derive_v1(ReceiptOrderLineId::new_v4(), 0)
                .unwrap()
                .to_string(),
        ),
        (
            DeletionTargetKindV1::ReceiptPurchaseUnitEvidence,
            EvidenceId::new_v4().to_string(),
        ),
    ] {
        PreviewDeletionV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            target_kind,
            target_id,
            limit: 25,
        }
        .validate()
        .unwrap();
    }

    let count = DeletionClassCountV1 {
        class: DeletionDependencyClassV1::RetainedSharedRecords,
        count: 2,
    };
    assert_eq!(
        serde_json::to_value(count).unwrap(),
        json!({"class": "retained_shared_records", "count": 2})
    );
}
