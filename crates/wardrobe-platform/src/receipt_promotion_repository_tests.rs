use crate::{BlobStore, Database, LocalDeterministicReceiptProviderV1, PrivateAppPaths};
use rusqlite::Connection;
use std::collections::BTreeSet;
use std::fs;
use wardrobe_core::{
    AnalyzeReceiptV1Request, AnalyzeReceiptV1Response, ApplicationService, CatalogPort,
    DeletionConfirmationV1, DeletionDependencyClassV1, DeletionPlanItemV1, DeletionPort,
    DeletionTargetKindV1, ErrorCodeV1, ExecuteDeletionV1Request, ImportLocalSourcesV1Request,
    ItemAttributesV1, ItemCategoryV1, ListDeletionPlanItemsV1Request,
    ListReceiptPurchaseUnitsV1Request, ListReceiptPurchaseUnitsV1Response,
    PromoteReceiptPurchaseUnitV1Request, PromoteReceiptPurchaseUnitV1Response,
    ReceiptAnalysisPlanV1, ReceiptEvidenceProvider, ReceiptExtractionEnvelopeV1, ReceiptPort,
    ReceiptPromotionCategoryAuthorityV1, ReceiptPromotionConfirmationV1, ReceiptProviderResult,
    ReceiptPurchaseUnitExclusionReasonV1, ReceiptPurchaseUnitStatusV1, ReceiptPurchaseUnitV1,
    ReceiptReviewActionV1, ReplayStatusV1, RequestId, ReviewReceiptV1Request,
    ReviewReceiptV1Response, Validate, SCHEMA_VERSION_V1,
};

const RECEIPT: &[u8] = b"From: orders@example.invalid\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/plain; charset=utf-8\r\n\r\n\
Merchant: Example Shop\r\n\
Order: EX-100\r\n\
Date: 2026-07-15\r\n\
Currency: USD\r\n\
Purchase | Blue Shirt | Qty 2 | $12.50 | Brand Acme | SKU SH-1 | Size M | Color Blue\r\n\
Return | Red Socks | Qty 1 | $4.00\r\n";

struct Fixture {
    temporary: tempfile::TempDir,
    paths: PrivateAppPaths,
    database: Database,
    source_id: wardrobe_core::SourceId,
}

#[derive(Clone, Copy)]
struct RevisionedProvider(&'static str);

impl ReceiptEvidenceProvider for RevisionedProvider {
    fn extract(
        &self,
        parsed: &wardrobe_core::ParsedReceiptEvidenceV1,
    ) -> ReceiptProviderResult<ReceiptExtractionEnvelopeV1> {
        let mut envelope = LocalDeterministicReceiptProviderV1::new().extract(parsed)?;
        envelope.processing.provider_revision = self.0.to_owned();
        Ok(envelope)
    }
}

fn request_id() -> RequestId {
    RequestId::new_v4()
}

fn fixture() -> Fixture {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let imports = temporary.path().join("imports");
    fs::create_dir(&imports).unwrap();
    let receipt = imports.join("receipt.eml");
    fs::write(&receipt, RECEIPT).unwrap();
    let database = Database::open(&paths, 1).unwrap();
    let imported = database
        .import_local_sources(&ImportLocalSourcesV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            paths: vec![receipt.to_string_lossy().into_owned()],
        })
        .unwrap();
    Fixture {
        temporary,
        paths,
        database,
        source_id: imported.summaries[0].source_id.unwrap(),
    }
}

fn analyze<P: ReceiptEvidenceProvider>(
    database: &Database,
    _paths: &PrivateAppPaths,
    source_id: wardrobe_core::SourceId,
    provider: P,
) -> AnalyzeReceiptV1Response {
    let request = AnalyzeReceiptV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        source_id,
    };
    let ReceiptAnalysisPlanV1::Extract {
        parsed,
        preserved_review_head,
    } = database.prepare_receipt_analysis(&request).unwrap()
    else {
        panic!("expected a fresh receipt extraction plan");
    };
    let envelope = provider.extract(&parsed).unwrap();
    database
        .commit_receipt_analysis(&request, &parsed, &envelope, preserved_review_head.as_ref())
        .unwrap()
}

fn review(
    database: &Database,
    paths: &PrivateAppPaths,
    analyzed: &AnalyzeReceiptV1Response,
    action: ReceiptReviewActionV1,
    expected_receipt_revision: u64,
) -> ReviewReceiptV1Response {
    ApplicationService::new(database.clone(), BlobStore::new(paths), ())
        .with_receipt_provider(LocalDeterministicReceiptProviderV1::new())
        .review_receipt_v1(ReviewReceiptV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            order_evidence_id: analyzed.order.order_evidence_id,
            action,
            corrected_order: None,
            expected_receipt_revision,
        })
        .unwrap()
}

fn reviewed_fixture() -> (Fixture, AnalyzeReceiptV1Response, ReviewReceiptV1Response) {
    let fixture = fixture();
    let analyzed = analyze(
        &fixture.database,
        &fixture.paths,
        fixture.source_id,
        LocalDeterministicReceiptProviderV1::new(),
    );
    let reviewed = review(
        &fixture.database,
        &fixture.paths,
        &analyzed,
        ReceiptReviewActionV1::Confirm,
        0,
    );
    (fixture, analyzed, reviewed)
}

fn list_units(fixture: &Fixture) -> ListReceiptPurchaseUnitsV1Response {
    ApplicationService::new(fixture.database.clone(), BlobStore::new(&fixture.paths), ())
        .list_receipt_purchase_units_v1(ListReceiptPurchaseUnitsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            source_id: Some(fixture.source_id),
            status: None,
            cursor: None,
            limit: 100,
        })
        .unwrap()
}

fn attributes(display_name: &str) -> ItemAttributesV1 {
    ItemAttributesV1 {
        display_name: display_name.to_owned(),
        category: ItemCategoryV1::Top,
        subcategory: Some("Shirt".to_owned()),
        brand: Some("Acme".to_owned()),
        primary_color: Some("Blue".to_owned()),
        size: Some("M".to_owned()),
        notes: None,
        tags: vec!["receipt".to_owned()],
    }
}

fn promotion_request(
    unit: &ReceiptPurchaseUnitV1,
    request_id: RequestId,
) -> PromoteReceiptPurchaseUnitV1Request {
    PromoteReceiptPurchaseUnitV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id,
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
        attributes: attributes("Blue Shirt"),
    }
}

fn promote(
    fixture: &Fixture,
    request: PromoteReceiptPurchaseUnitV1Request,
) -> PromoteReceiptPurchaseUnitV1Response {
    ApplicationService::new(fixture.database.clone(), BlobStore::new(&fixture.paths), ())
        .promote_receipt_purchase_unit_v1(request)
        .unwrap()
}

fn promoted_fixture() -> (Fixture, PromoteReceiptPurchaseUnitV1Response) {
    let (fixture, _, _) = reviewed_fixture();
    let unit = list_units(&fixture).units[0].clone();
    let promoted = promote(&fixture, promotion_request(&unit, request_id()));
    (fixture, promoted)
}

fn count(connection: &Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn count_by(connection: &Connection, table: &str, column: &str, value: &str) -> i64 {
    connection
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1"),
            [value],
            |row| row.get(0),
        )
        .unwrap()
}

fn preview_deletion(
    fixture: &Fixture,
    target_kind: DeletionTargetKindV1,
    target_id: String,
) -> wardrobe_core::PreviewDeletionV1Response {
    ApplicationService::new(fixture.database.clone(), BlobStore::new(&fixture.paths), ())
        .preview_deletion_v1(wardrobe_core::PreviewDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            target_kind,
            target_id,
            limit: 100,
        })
        .unwrap()
}

fn execute_deletion(
    fixture: &Fixture,
    preview: &wardrobe_core::PreviewDeletionV1Response,
) -> wardrobe_core::ExecuteDeletionV1Response {
    let response = fixture
        .database
        .execute_deletion(&ExecuteDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            preview_snapshot_token: preview.preview_snapshot_token.clone(),
            plan_sha256: preview.plan_sha256.clone(),
            expected_revisions: preview.revisions.clone(),
            confirmation: DeletionConfirmationV1::DeleteActiveLocalData,
        })
        .unwrap();
    response.validate().unwrap();
    response
}

fn all_plan_items(
    database: &Database,
    preview: &wardrobe_core::PreviewDeletionV1Response,
) -> Vec<DeletionPlanItemV1> {
    let mut items = Vec::new();
    for class in [
        DeletionDependencyClassV1::Originals,
        DeletionDependencyClassV1::Derivatives,
        DeletionDependencyClassV1::SourceRecords,
        DeletionDependencyClassV1::EvidenceRecords,
        DeletionDependencyClassV1::DecisionRecords,
        DeletionDependencyClassV1::RemoteReferences,
        DeletionDependencyClassV1::RetainedSharedBlobs,
        DeletionDependencyClassV1::RetainedSharedRecords,
    ] {
        let page = database
            .list_deletion_plan_items(&ListDeletionPlanItemsV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                preview_snapshot_token: preview.preview_snapshot_token.clone(),
                class,
                cursor: None,
                limit: 100,
            })
            .unwrap();
        assert!(page.next_cursor.is_none(), "fixture plan exceeded one page");
        items.extend(page.items);
    }
    items
}

fn current_receipt_revision(database: &Database) -> u64 {
    database
        .connection()
        .unwrap()
        .query_row(
            "SELECT receipt_revision FROM revision_state WHERE singleton=1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap() as u64
}

#[test]
fn projection_expands_only_current_user_reviewed_purchases() {
    let fixture = fixture();
    let analyzed = analyze(
        &fixture.database,
        &fixture.paths,
        fixture.source_id,
        LocalDeterministicReceiptProviderV1::new(),
    );
    assert!(list_units(&fixture).units.is_empty());

    let confirmed = review(
        &fixture.database,
        &fixture.paths,
        &analyzed,
        ReceiptReviewActionV1::Confirm,
        0,
    );
    let listed = list_units(&fixture);
    assert_eq!(listed.units.len(), 2);
    assert_eq!(
        listed
            .units
            .iter()
            .map(|unit| unit.unit_ordinal)
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert!(listed.units.iter().all(|unit| {
        unit.values.description.as_deref() == Some("Blue Shirt")
            && unit.values.quantity == 2
            && unit.authority.review_decision_id == confirmed.decision.decision_id
            && unit.authority.review_action == ReceiptReviewActionV1::Confirm
    }));
    assert_eq!(listed.exclusions.len(), 1);
    assert_eq!(
        listed.exclusions[0].reason,
        ReceiptPurchaseUnitExclusionReasonV1::NonPurchase
    );

    let deferred = review(
        &fixture.database,
        &fixture.paths,
        &analyzed,
        ReceiptReviewActionV1::Defer,
        confirmed.new_receipt_revision,
    );
    let current = list_units(&fixture);
    assert!(current.units.is_empty());
    assert_eq!(current.exclusions.len(), analyzed.order.line_items.len());
    assert!(current
        .exclusions
        .iter()
        .all(|entry| entry.reason == ReceiptPurchaseUnitExclusionReasonV1::Deferred));
    assert_ne!(
        deferred.decision.decision_id,
        confirmed.decision.decision_id
    );
}

#[test]
fn promotion_is_atomic_replayable_and_cas_bound() {
    let (fixture, _, _) = reviewed_fixture();
    let listed = list_units(&fixture);
    let request = promotion_request(&listed.units[0], request_id());
    let sibling = listed.units[1].clone();
    let created = promote(&fixture, request.clone());
    assert_eq!(created.replay_status, ReplayStatusV1::Created);
    assert_eq!(
        created.unit.purchase_unit_revision,
        request.expected_purchase_unit_revision + 1
    );
    assert_eq!(
        created.new_catalog_revision,
        request.expected_catalog_revision + 1
    );
    assert!(matches!(
        created.unit.status,
        ReceiptPurchaseUnitStatusV1::Promoted { .. }
    ));

    let connection = fixture.database.connection().unwrap();
    assert_eq!(
        count_by(
            &connection,
            "catalog_items",
            "item_id",
            &created.item.item_id.to_string()
        ),
        1
    );
    assert_eq!(
        count_by(
            &connection,
            "evidence",
            "evidence_id",
            &created.promotion.evidence_id.to_string()
        ),
        1
    );
    assert_eq!(
        count_by(
            &connection,
            "item_evidence",
            "item_id",
            &created.item.item_id.to_string()
        ),
        1
    );
    assert_eq!(
        count_by(
            &connection,
            "catalog_decisions",
            "decision_id",
            &created.decision.decision_id.to_string()
        ),
        1
    );
    assert_eq!(
        count_by(
            &connection,
            "decision_entities",
            "decision_id",
            &created.decision.decision_id.to_string()
        ),
        2
    );
    assert_eq!(
        count_by(
            &connection,
            "receipt_authority_snapshots",
            "authority_snapshot_id",
            &created.authority_snapshot.authority_snapshot_id.to_string()
        ),
        1
    );
    assert_eq!(
        count_by(
            &connection,
            "receipt_purchase_unit_promotions",
            "promotion_id",
            &created.promotion.promotion_id.to_string()
        ),
        1
    );
    assert_eq!(
        count_by(
            &connection,
            "command_receipts",
            "request_id",
            &request.request_id.to_string()
        ),
        1
    );
    assert_eq!(
        count_by(
            &connection,
            "receipt_command_entities",
            "request_id",
            &request.request_id.to_string()
        ),
        3
    );
    let row_counts = (
        count(&connection, "catalog_items"),
        count(&connection, "evidence"),
        count(&connection, "catalog_decisions"),
        count(&connection, "receipt_purchase_unit_promotions"),
        count(&connection, "command_receipts"),
    );
    drop(connection);

    let replayed = promote(&fixture, request.clone());
    assert_eq!(replayed.replay_status, ReplayStatusV1::Replayed);
    assert_eq!(replayed.item.item_id, created.item.item_id);
    assert_eq!(
        replayed.promotion.promotion_id,
        created.promotion.promotion_id
    );
    assert_eq!(
        replayed.unit.purchase_unit_revision,
        created.unit.purchase_unit_revision
    );

    let mut changed_envelope = request;
    changed_envelope.attributes.display_name = "Changed Shirt".to_owned();
    let changed_error =
        ApplicationService::new(fixture.database.clone(), BlobStore::new(&fixture.paths), ())
            .promote_receipt_purchase_unit_v1(changed_envelope)
            .unwrap_err();
    assert_eq!(changed_error.code, ErrorCodeV1::RequestConflict);

    let stale_request = promotion_request(&sibling, request_id());
    let stale_error =
        ApplicationService::new(fixture.database.clone(), BlobStore::new(&fixture.paths), ())
            .promote_receipt_purchase_unit_v1(stale_request.clone())
            .unwrap_err();
    assert_eq!(stale_error.code, ErrorCodeV1::RequestConflict);
    let connection = fixture.database.connection().unwrap();
    assert_eq!(
        row_counts,
        (
            count(&connection, "catalog_items"),
            count(&connection, "evidence"),
            count(&connection, "catalog_decisions"),
            count(&connection, "receipt_purchase_unit_promotions"),
            count(&connection, "command_receipts"),
        )
    );
    assert_eq!(
        count_by(
            &connection,
            "command_receipts",
            "request_id",
            &stale_request.request_id.to_string()
        ),
        0
    );
}

#[test]
fn changed_line_ids_require_resolution_before_second_promotion() {
    let (fixture, first_analysis, _) = reviewed_fixture();
    let first_unit = list_units(&fixture).units[0].clone();
    let promoted = promote(&fixture, promotion_request(&first_unit, request_id()));

    let changed = analyze(
        &fixture.database,
        &fixture.paths,
        fixture.source_id,
        RevisionedProvider("local-deterministic-receipt-provider-v2"),
    );
    assert_ne!(
        changed.order.line_items[0].order_line_id,
        first_analysis.order.line_items[0].order_line_id
    );
    review(
        &fixture.database,
        &fixture.paths,
        &changed,
        ReceiptReviewActionV1::Confirm,
        current_receipt_revision(&fixture.database),
    );

    let listed = list_units(&fixture);
    assert_eq!(listed.units.len(), 1);
    assert_eq!(
        listed.units[0].purchase_unit_id,
        promoted.unit.purchase_unit_id
    );
    assert!(matches!(
        listed.units[0].status,
        ReceiptPurchaseUnitStatusV1::Promoted { .. }
    ));
    let changed_line_ids = changed
        .order
        .line_items
        .iter()
        .map(|line| line.order_line_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(listed.exclusions.len(), changed_line_ids.len());
    assert!(listed.exclusions.iter().all(|entry| {
        entry.reason == ReceiptPurchaseUnitExclusionReasonV1::AuthorityChangedResolutionRequired
            && entry
                .order_line_id
                .is_some_and(|line_id| changed_line_ids.contains(&line_id))
    }));
    assert!(!listed
        .units
        .iter()
        .any(|unit| changed_line_ids.contains(&unit.order_line_id)));
}

#[test]
fn unit_deletion_tombstones_survive_restart_and_preserve_siblings() {
    let (fixture, _, _) = reviewed_fixture();
    let units = list_units(&fixture).units;
    let deleted = units[0].clone();
    let sibling = units[1].clone();
    let preview = preview_deletion(
        &fixture,
        DeletionTargetKindV1::PurchaseUnit,
        deleted.purchase_unit_id.to_string(),
    );
    execute_deletion(&fixture, &preview);

    let listed = list_units(&fixture);
    assert_eq!(listed.units.len(), 1);
    assert_eq!(listed.units[0].purchase_unit_id, sibling.purchase_unit_id);
    assert!(listed.exclusions.iter().any(|entry| {
        entry.order_line_id == Some(deleted.order_line_id)
            && entry.unit_ordinal == Some(deleted.unit_ordinal)
            && entry.reason == ReceiptPurchaseUnitExclusionReasonV1::UserDeleted
    }));

    let Fixture {
        temporary,
        paths,
        database,
        source_id,
    } = fixture;
    drop(database);
    let restarted = Fixture {
        temporary,
        database: Database::open(&paths, 2).unwrap(),
        paths,
        source_id,
    };
    let after_restart = list_units(&restarted);
    assert_eq!(after_restart.units.len(), 1);
    assert_eq!(
        after_restart.units[0].purchase_unit_id,
        sibling.purchase_unit_id
    );
    assert!(after_restart.exclusions.iter().any(|entry| {
        entry.order_line_id == Some(deleted.order_line_id)
            && entry.unit_ordinal == Some(deleted.unit_ordinal)
            && entry.reason == ReceiptPurchaseUnitExclusionReasonV1::UserDeleted
    }));
    assert_eq!(
        count_by(
            &restarted.database.connection().unwrap(),
            "receipt_purchase_unit_deletions",
            "purchase_unit_id",
            &deleted.purchase_unit_id.to_string()
        ),
        1
    );
}

#[test]
fn changed_line_ids_after_each_deletion_target_remain_blocked_until_source_deletion() {
    for target_kind in [
        DeletionTargetKindV1::PurchaseUnit,
        DeletionTargetKindV1::ReceiptPurchaseUnitEvidence,
        DeletionTargetKindV1::Item,
    ] {
        let (fixture, promoted) = promoted_fixture();
        let target_id = match target_kind {
            DeletionTargetKindV1::PurchaseUnit => promoted.unit.purchase_unit_id.to_string(),
            DeletionTargetKindV1::ReceiptPurchaseUnitEvidence => {
                promoted.promotion.evidence_id.to_string()
            }
            DeletionTargetKindV1::Item => promoted.item.item_id.to_string(),
            _ => unreachable!(),
        };
        let preview = preview_deletion(&fixture, target_kind, target_id);
        execute_deletion(&fixture, &preview);

        let changed = analyze(
            &fixture.database,
            &fixture.paths,
            fixture.source_id,
            RevisionedProvider("local-deterministic-receipt-provider-after-deletion"),
        );
        assert_ne!(
            changed.order.line_items[0].order_line_id,
            promoted.unit.order_line_id
        );
        review(
            &fixture.database,
            &fixture.paths,
            &changed,
            ReceiptReviewActionV1::Confirm,
            current_receipt_revision(&fixture.database),
        );
        let blocked = list_units(&fixture);
        assert!(blocked.units.is_empty(), "{target_kind:?}");
        assert_eq!(
            blocked.exclusions.len(),
            changed.order.line_items.len(),
            "{target_kind:?}"
        );
        assert!(blocked.exclusions.iter().all(|entry| {
            entry.reason == ReceiptPurchaseUnitExclusionReasonV1::AuthorityChangedResolutionRequired
        }));

        let source_preview = preview_deletion(
            &fixture,
            DeletionTargetKindV1::Source,
            fixture.source_id.to_string(),
        );
        execute_deletion(&fixture, &source_preview);
        let connection = fixture.database.connection().unwrap();
        assert_eq!(
            count_by(
                &connection,
                "local_sources",
                "source_id",
                &fixture.source_id.to_string()
            ),
            0,
            "{target_kind:?}"
        );
        assert_eq!(
            count_by(
                &connection,
                "receipt_purchase_unit_deletions",
                "purchase_unit_id",
                &promoted.unit.purchase_unit_id.to_string()
            ),
            0,
            "{target_kind:?}"
        );
    }
}

#[test]
fn four_deletion_targets_have_directional_complete_closure() {
    for target_kind in [
        DeletionTargetKindV1::PurchaseUnit,
        DeletionTargetKindV1::ReceiptPurchaseUnitEvidence,
        DeletionTargetKindV1::Item,
        DeletionTargetKindV1::Source,
    ] {
        let (fixture, promoted) = promoted_fixture();
        let target_id = match target_kind {
            DeletionTargetKindV1::PurchaseUnit => promoted.unit.purchase_unit_id.to_string(),
            DeletionTargetKindV1::ReceiptPurchaseUnitEvidence => {
                promoted.promotion.evidence_id.to_string()
            }
            DeletionTargetKindV1::Item => promoted.item.item_id.to_string(),
            DeletionTargetKindV1::Source => fixture.source_id.to_string(),
            _ => unreachable!(),
        };
        let preview = preview_deletion(&fixture, target_kind, target_id);
        let items = all_plan_items(&fixture.database, &preview);
        let records = items
            .iter()
            .map(|item| item.record_id.as_str())
            .collect::<BTreeSet<_>>();
        for required in [
            promoted.item.item_id.to_string(),
            promoted.promotion.evidence_id.to_string(),
            format!(
                "item_evidence:{}:{}",
                promoted.item.item_id, promoted.promotion.evidence_id
            ),
            format!(
                "receipt_purchase_unit_promotion:{}:{}",
                promoted.unit.order_line_id, promoted.unit.unit_ordinal
            ),
            promoted.decision.decision_id.to_string(),
            format!(
                "receipt_authority_snapshot:{}",
                promoted.authority_snapshot.authority_snapshot_id
            ),
            format!("receipt_command_receipt:{}", promoted.promotion.request_id),
        ] {
            assert!(
                records.contains(required.as_str()),
                "{target_kind:?} omitted {required}"
            );
        }

        let retained_source = format!("retained_receipt_source:{}", fixture.source_id);
        if target_kind == DeletionTargetKindV1::Source {
            assert!(records.contains(fixture.source_id.to_string().as_str()));
            assert!(!records.contains(retained_source.as_str()));
        } else {
            assert!(
                records.contains(retained_source.as_str()),
                "{target_kind:?}"
            );
            assert!(records.contains(
                format!(
                    "retained_receipt_purchase_unit_deletion:{}",
                    promoted.unit.purchase_unit_id
                )
                .as_str()
            ));
        }
        assert_eq!(
            preview.counts.iter().map(|entry| entry.count).sum::<u64>(),
            items.len() as u64,
            "{target_kind:?}"
        );
    }
}

#[test]
fn promotion_undo_is_rejected_before_revision_or_write() {
    let (fixture, promoted) = promoted_fixture();
    let connection = fixture.database.connection().unwrap();
    let revision_before: i64 = connection
        .query_row(
            "SELECT catalog_revision FROM revision_state WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let decisions_before = count(&connection, "catalog_decisions");
    let receipts_before = count(&connection, "command_receipts");
    drop(connection);

    let undo_request_id = request_id();
    let error =
        ApplicationService::new(fixture.database.clone(), BlobStore::new(&fixture.paths), ())
            .undo_decision_v1(wardrobe_core::UndoDecisionV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: undo_request_id,
                decision_id: promoted.decision.decision_id,
                expected_catalog_revision: 0,
            })
            .unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::RequestConflict);

    let connection = fixture.database.connection().unwrap();
    assert_eq!(
        connection
            .query_row(
                "SELECT catalog_revision FROM revision_state WHERE singleton=1",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        revision_before
    );
    assert_eq!(count(&connection, "catalog_decisions"), decisions_before);
    assert_eq!(count(&connection, "command_receipts"), receipts_before);
    assert_eq!(
        count_by(
            &connection,
            "command_receipts",
            "request_id",
            &undo_request_id.to_string()
        ),
        0
    );
    assert_eq!(
        count_by(
            &connection,
            "receipt_purchase_unit_promotions",
            "promotion_id",
            &promoted.promotion.promotion_id.to_string()
        ),
        1
    );
    assert_eq!(
        count_by(
            &connection,
            "catalog_items",
            "item_id",
            &promoted.item.item_id.to_string()
        ),
        1
    );
}
