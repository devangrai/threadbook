use image::{ColorType, ImageFormat};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::fs;
use std::sync::{Arc, Barrier};
use uuid::Uuid;
use wardrobe_core::{
    CatalogPort, CorrectPhotoPersonDetectionV1Request, CreatePhotoScopeV1Request,
    DecidePhotoOwnerV1Request, DecideReconciliationCaseV1Request, DeletionDependencyClassV1,
    DeletionTargetKindV1, DetectPhotoScopePeopleV1Request, ImportLocalSourcesV1Request,
    InboxStateV1, ItemAttributesV1, ItemCategoryV1, ListDeletionPlanItemsV1Request,
    ListImportedPhotoRootsV1Request, ListInboxV1Request, ListPhotoObservationsV1Request,
    ListPhotoOwnerReviewsV1Request, LocalPersonDetectionProviderV1,
    OpenReconciliationCaseV1Request, PersonDetectionOutcomeV1, PersonDetectionProviderDescriptorV1,
    PersonDetectionProviderResult, PersonDetectionRequestV1, PersonDetectionResultV1,
    PhotoAnalysisPort, PhotoObservationStateV1, PhotoOwnerActionV1, PhotoOwnerReviewStateV1,
    PhotoReviewActionV1, PreviewDeletionV1Request, ReconciliationCandidateTargetV1,
    ReconciliationOutcomeV1, ReconciliationPort, ReconciliationPortErrorKind, RectV1,
    ReplayStatusV1, RequestId, ReviewPhotoObservationV1Request, SaveItemV1Request,
    APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1, LOCAL_PERSON_DETECTION_CONTRACT_V1,
    PHOTO_PREPROCESSING_REVISION_V1, SCHEMA_VERSION_V1,
};
use wardrobe_platform::{Database, PrivateAppPaths};

fn request_id() -> RequestId {
    RequestId::new_v4()
}

struct ZeroPeopleProvider;

impl LocalPersonDetectionProviderV1 for ZeroPeopleProvider {
    fn describe(&self) -> PersonDetectionProviderDescriptorV1 {
        PersonDetectionProviderDescriptorV1 {
            contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
            provider_revision: APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned(),
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            vision_request_revision: 2,
            os_build: "reconciliation-test-os".to_owned(),
            vision_framework_build: "reconciliation-test-vision".to_owned(),
        }
    }

    fn detect(
        &self,
        request: &PersonDetectionRequestV1,
    ) -> PersonDetectionProviderResult<PersonDetectionOutcomeV1> {
        Ok(PersonDetectionOutcomeV1 {
            contract_revision: request.contract_revision.clone(),
            request_handle: request.request_handle,
            source_revision_sha256: request.source_revision_sha256.clone(),
            input_blob_sha256: request.input_blob_sha256.clone(),
            result: PersonDetectionResultV1::SucceededZero,
        })
    }
}

fn fixture() -> (
    tempfile::TempDir,
    PrivateAppPaths,
    Database,
    wardrobe_core::PhotoObservationId,
    wardrobe_core::PhotoArtifactId,
    wardrobe_core::ItemId,
    u64,
) {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let folder = temporary.path().join("photos");
    fs::create_dir(&folder).unwrap();
    let pixels = (0..8 * 6)
        .flat_map(|index| {
            let value = (index * 5) as u8;
            [value, 255_u8.saturating_sub(value), value / 2]
        })
        .collect::<Vec<_>>();
    image::save_buffer_with_format(
        folder.join("shirt.png"),
        &pixels,
        8,
        6,
        ColorType::Rgb8,
        ImageFormat::Png,
    )
    .unwrap();
    let database = Database::open(&paths, 1).unwrap();
    database
        .import_local_sources(&ImportLocalSourcesV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            paths: vec![folder.to_string_lossy().into_owned()],
        })
        .unwrap();
    let root = database
        .list_imported_photo_roots(&ListImportedPhotoRootsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            cursor: None,
            limit: 20,
        })
        .unwrap()
        .roots
        .remove(0);
    let scope = database
        .create_photo_scope(&CreatePhotoScopeV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            import_root_id: root.import_root_id,
            expected_manifest_generation: root.manifest_generation,
        })
        .unwrap()
        .scope;
    let detected = database
        .detect_photo_scope_people(
            &DetectPhotoScopePeopleV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                scope_id: scope.scope_id,
            },
            &ZeroPeopleProvider,
        )
        .unwrap();
    assert_eq!(detected.no_person_detected_count, 1);
    let owner_review = database
        .list_photo_owner_reviews(&ListPhotoOwnerReviewsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            state: PhotoOwnerReviewStateV1::NoPersonDetected,
            cursor: None,
            limit: 20,
        })
        .unwrap()
        .reviews
        .remove(0);
    let correction = database
        .correct_photo_person_detection(&CorrectPhotoPersonDetectionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            owner_review_id: owner_review.owner_review_id,
            manual_rectangle: RectV1 {
                x: 0,
                y: 0,
                width: 8,
                height: 6,
            },
            expected_terminal_attempt_id: owner_review.terminal_attempt_id,
            expected_detection_revision: owner_review.detection_revision,
            expected_owner_head_revision: owner_review.owner_head_revision,
            expected_photo_revision: owner_review.photo_revision,
        })
        .unwrap();
    let owner = database
        .decide_photo_owner(&DecidePhotoOwnerV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            owner_review_id: correction.review.owner_review_id,
            action: PhotoOwnerActionV1::SelectPerson,
            selected_person_instance_id: Some(correction.instance.person_instance_id),
            expected_detection_revision: correction.review.detection_revision,
            expected_owner_head_revision: correction.review.owner_head_revision,
            expected_photo_revision: correction.review.photo_revision,
        })
        .unwrap();
    assert_eq!(owner.decision.action, PhotoOwnerActionV1::SelectPerson);
    assert_eq!(
        owner.decision.selected_person_instance_id,
        Some(correction.instance.person_instance_id)
    );
    let observation = database
        .list_photo_observations(&ListPhotoObservationsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            scope_id: scope.scope_id,
            state: PhotoObservationStateV1::NeedsReview,
            cursor: None,
            limit: 20,
        })
        .unwrap()
        .observations
        .remove(0);
    let reviewed = database
        .review_photo_observation(&ReviewPhotoObservationV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            observation_id: observation.observation_id,
            action: PhotoReviewActionV1::ConfirmCrop,
            replacement_rectangle: None,
            expected_photo_revision: owner.decision.photo_revision,
        })
        .unwrap();
    let image_evidence = database
        .list_inbox(&ListInboxV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            state: InboxStateV1::Unresolved,
            cursor: None,
            limit: 20,
        })
        .unwrap()
        .evidence
        .into_iter()
        .find(|evidence| evidence.kind == wardrobe_core::EvidenceKindV1::Image)
        .unwrap()
        .evidence_id;
    let item = database
        .save_item_and_append_decision(&SaveItemV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            item_id: None,
            attributes: ItemAttributesV1 {
                display_name: "Synthetic shirt".to_owned(),
                category: ItemCategoryV1::Top,
                subcategory: Some("T-shirt".to_owned()),
                brand: Some("Local".to_owned()),
                primary_color: Some("Green".to_owned()),
                size: Some("M".to_owned()),
                notes: None,
                tags: Vec::new(),
            },
            evidence_ids: vec![image_evidence],
            expected_catalog_revision: 0,
        })
        .unwrap()
        .item;
    seed_confirmed_receipt(&paths);
    (
        temporary,
        paths,
        database,
        reviewed.observation.observation_id,
        reviewed.observation.artifact.artifact_id,
        item.item_id,
        reviewed.new_photo_revision,
    )
}

fn seed_confirmed_receipt(paths: &PrivateAppPaths) {
    let connection = Connection::open(&paths.database).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    let source = Uuid::new_v4().hyphenated().to_string();
    let parse = Uuid::new_v4().hyphenated().to_string();
    let run = Uuid::new_v4().hyphenated().to_string();
    let order = Uuid::new_v4().hyphenated().to_string();
    let line = Uuid::new_v4().hyphenated().to_string();
    let variant = Uuid::new_v4().hyphenated().to_string();
    let review = Uuid::new_v4().hyphenated().to_string();
    let hash = "a".repeat(64);
    connection
        .execute(
            "INSERT INTO local_sources(
                source_id, source_kind, identity_key, canonical_locator,
                raw_sha256, blob_sha256, byte_length, media_type, status,
                no_blob_reason, created_at_ms, updated_at_ms
             ) VALUES (?1, 'eml', ?1, '/synthetic/receipt.eml', ?2, NULL,
                       0, 'message/rfc822', 'quarantined', 'synthetic', 2, 2)",
            params![source, hash],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_parses(
                parse_id, source_id, raw_sha256, parser_revision,
                sanitizer_revision, canonical_input_sha256, created_at_ms
             ) VALUES (?1, ?2, ?3, 'parser-v1', 'sanitizer-v1', ?3, 2)",
            params![parse, source, hash],
        )
        .unwrap();
    let output = "{}";
    let output_hash = format!("{:x}", Sha256::digest(output.as_bytes()));
    connection
        .execute(
            "INSERT INTO receipt_extraction_runs(
                run_id, parse_id, provider_id, provider_revision,
                schema_version, schema_sha256, ruleset_revision,
                ruleset_sha256, parameters_json, canonical_input_sha256,
                parent_source_sha256, parent_fragment_hashes_json,
                envelope_json, output_json, output_sha256, status,
                created_at_ms, completed_at_ms
             ) VALUES (
                ?1, ?2, 'local', 'local-v1', 'v1', ?3, 'rules-v1', ?3,
                '{}', ?3, ?3, '[]', '{}', ?4, ?5, 'succeeded', 2, 2
             )",
            params![run, parse, hash, output, output_hash],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_orders(order_evidence_id, run_id, line_count, created_at_ms)
             VALUES (?1, ?2, 1, 2)",
            params![order, run],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_order_lines(
                order_line_id, order_evidence_id, ordinal, event_kind, created_at_ms
             ) VALUES (?1, ?2, 0, 'purchase', 2)",
            params![line, order],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_variant_evidence(
                variant_evidence_id, order_line_id, created_at_ms
             ) VALUES (?1, ?2, 2)",
            params![variant, line],
        )
        .unwrap();
    for (owner, id, name, kind, value) in [
        (
            "order_evidence_id",
            order.as_str(),
            "merchant",
            "string",
            "Shop",
        ),
        (
            "order_evidence_id",
            order.as_str(),
            "purchase_date",
            "string",
            "2025-01-02",
        ),
        (
            "order_line_id",
            line.as_str(),
            "description",
            "string",
            "Receipt shirt",
        ),
        (
            "order_line_id",
            line.as_str(),
            "event_kind",
            "enum",
            "purchase",
        ),
        (
            "variant_evidence_id",
            variant.as_str(),
            "brand",
            "string",
            "Shop brand",
        ),
        (
            "variant_evidence_id",
            variant.as_str(),
            "sku",
            "string",
            "SKU-1",
        ),
        (
            "variant_evidence_id",
            variant.as_str(),
            "size",
            "string",
            "M",
        ),
        (
            "variant_evidence_id",
            variant.as_str(),
            "color",
            "string",
            "Green",
        ),
    ] {
        let sql = format!(
            "INSERT INTO receipt_fields(
                field_id, {owner}, field_name, value_kind,
                value_text, value_integer, is_known, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, 1, 2)"
        );
        connection
            .execute(
                &sql,
                params![
                    Uuid::new_v4().hyphenated().to_string(),
                    id,
                    name,
                    kind,
                    value
                ],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO receipt_review_decisions(
                review_decision_id, order_evidence_id, request_id,
                action, reviewed_order_json, receipt_revision, created_at_ms
             ) VALUES (?1, ?2, ?3, 'confirm', NULL, 1, 3)",
            params![review, order, Uuid::new_v4().hyphenated().to_string()],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_review_heads(
                order_evidence_id, review_decision_id, receipt_revision, updated_at_ms
             ) VALUES (?1, ?2, 1, 3)",
            params![order, review],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE revision_state SET receipt_revision = 1 WHERE singleton = 1",
            [],
        )
        .unwrap();
}

#[test]
fn real_repository_replay_five_decisions_snapshot_expiry_and_closure() {
    let (_temporary, paths, database, observation_id, artifact_id, item_id, photo_revision) =
        fixture();
    let open_request = OpenReconciliationCaseV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        observation_id,
        selected_artifact_id: artifact_id,
        expected_photo_revision: photo_revision,
    };
    let opened = database.open_reconciliation_case(&open_request).unwrap();
    assert_eq!(opened.reconciliation_revision, 1);
    assert_eq!(opened.case.candidates.len(), 3);
    assert!(matches!(
        opened.case.candidates.last().unwrap().target,
        ReconciliationCandidateTargetV1::NoMatch {}
    ));
    let visual_measurements = opened
        .case
        .candidates
        .iter()
        .find(|candidate| {
            matches!(
                candidate.target,
                ReconciliationCandidateTargetV1::WardrobeItem { .. }
            )
        })
        .unwrap()
        .evidence
        .iter()
        .filter_map(|evidence| evidence.measured_value)
        .collect::<Vec<_>>();
    assert_eq!(visual_measurements, vec![0, 0]);
    let replay = database.open_reconciliation_case(&open_request).unwrap();
    assert_eq!(replay.replay_status, ReplayStatusV1::Replayed);
    assert_eq!(replay.reconciliation_revision, 1);

    let preview = database
        .preview_deletion(&PreviewDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            target_kind: DeletionTargetKindV1::Item,
            target_id: item_id.to_string(),
            limit: 20,
        })
        .unwrap();
    let converged = database
        .open_reconciliation_case(&OpenReconciliationCaseV1Request {
            request_id: request_id(),
            ..open_request.clone()
        })
        .unwrap();
    assert_eq!(converged.case.case_id, opened.case.case_id);
    assert_eq!(converged.reconciliation_revision, 2);
    assert_eq!(
        database
            .list_deletion_plan_items(&ListDeletionPlanItemsV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                preview_snapshot_token: preview.preview_snapshot_token,
                class: DeletionDependencyClassV1::EvidenceRecords,
                cursor: None,
                limit: 20,
            })
            .unwrap_err()
            .kind,
        wardrobe_core::CatalogPortErrorKind::SnapshotExpired
    );

    let wardrobe = opened
        .case
        .candidates
        .iter()
        .find(|candidate| {
            matches!(
                candidate.target,
                ReconciliationCandidateTargetV1::WardrobeItem { .. }
            )
        })
        .unwrap()
        .candidate_id;
    let receipt = opened
        .case
        .candidates
        .iter()
        .find(|candidate| {
            matches!(
                candidate.target,
                ReconciliationCandidateTargetV1::ReceiptLine { .. }
            )
        })
        .unwrap()
        .candidate_id;
    let no_match = opened.case.candidates.last().unwrap().candidate_id;
    let mut case_revision = 1;
    for (outcome, selected) in [
        (ReconciliationOutcomeV1::SameItem, Some(wardrobe)),
        (ReconciliationOutcomeV1::SameVariant, Some(receipt)),
        (ReconciliationOutcomeV1::Different, Some(wardrobe)),
        (ReconciliationOutcomeV1::NoMatch, Some(no_match)),
        (ReconciliationOutcomeV1::Unresolved, None),
    ] {
        let request = DecideReconciliationCaseV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            case_id: opened.case.case_id,
            outcome,
            selected_candidate_id: selected,
            expected_case_revision: case_revision,
        };
        let response = database.decide_reconciliation_case(&request).unwrap();
        case_revision += 1;
        assert_eq!(response.case.case_revision, case_revision);
        assert_eq!(response.decision.outcome, outcome);
        let replay = database.decide_reconciliation_case(&request).unwrap();
        assert_eq!(replay.replay_status, ReplayStatusV1::Replayed);
        assert_eq!(
            replay.reconciliation_revision,
            response.reconciliation_revision
        );
    }
    assert_eq!(
        database
            .decide_reconciliation_case(&DecideReconciliationCaseV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                case_id: opened.case.case_id,
                outcome: ReconciliationOutcomeV1::Unresolved,
                selected_candidate_id: None,
                expected_case_revision: 1,
            })
            .unwrap_err()
            .kind,
        ReconciliationPortErrorKind::Conflict
    );

    let closure = database
        .preview_deletion(&PreviewDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            target_kind: DeletionTargetKindV1::Item,
            target_id: item_id.to_string(),
            limit: 100,
        })
        .unwrap();
    let connection = Connection::open(&paths.database).unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM deletion_preview_items
             WHERE snapshot_token = ?1
               AND entity_id LIKE 'reconciliation_%'",
            [closure.preview_snapshot_token.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(count >= 10);
}

#[test]
fn pinned_corruption_fails_new_open_but_exact_replay_is_write_free() {
    let (_temporary, paths, database, observation_id, artifact_id, _item_id, photo_revision) =
        fixture();
    let request = OpenReconciliationCaseV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        observation_id,
        selected_artifact_id: artifact_id,
        expected_photo_revision: photo_revision,
    };
    let created = database.open_reconciliation_case(&request).unwrap();
    let connection = Connection::open(&paths.database).unwrap();
    let blob: String = connection
        .query_row(
            "SELECT input_blob_sha256 FROM photo_artifacts WHERE artifact_id = ?1",
            [artifact_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let blob_path = paths.blobs.join(&blob[0..2]).join(&blob[2..4]).join(&blob);
    let mut bytes = fs::read(&blob_path).unwrap();
    bytes[0] ^= 0xff;
    fs::write(blob_path, bytes).unwrap();

    assert_eq!(
        database
            .open_reconciliation_case(&request)
            .unwrap()
            .replay_status,
        ReplayStatusV1::Replayed
    );
    assert_eq!(
        database
            .open_reconciliation_case(&OpenReconciliationCaseV1Request {
                request_id: request_id(),
                ..request
            })
            .unwrap_err()
            .kind,
        ReconciliationPortErrorKind::DataIntegrity
    );
    let connection = Connection::open(&paths.database).unwrap();
    let revision: i64 = connection
        .query_row(
            "SELECT reconciliation_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(revision, created.reconciliation_revision as i64);
}

#[test]
fn concurrent_distinct_opens_converge_with_ordered_operation_revisions() {
    let (_temporary, _paths, database, observation_id, artifact_id, _item_id, photo_revision) =
        fixture();
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let database = database.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let request = OpenReconciliationCaseV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                observation_id,
                selected_artifact_id: artifact_id,
                expected_photo_revision: photo_revision,
            };
            barrier.wait();
            database.open_reconciliation_case(&request).unwrap()
        }));
    }
    barrier.wait();
    let mut responses = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    responses.sort_by_key(|response| response.reconciliation_revision);
    assert_eq!(responses[0].reconciliation_revision, 1);
    assert_eq!(responses[1].reconciliation_revision, 2);
    assert_eq!(responses[0].case.case_id, responses[1].case.case_id);
}

#[test]
fn corrected_receipt_json_is_authoritative_including_explicit_nulls() {
    let (_temporary, paths, database, observation_id, artifact_id, _item_id, photo_revision) =
        fixture();
    let connection = Connection::open(&paths.database).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    let (order, line, variant): (String, String, String) = connection
        .query_row(
            "SELECT orders.order_evidence_id, line.order_line_id,
                    variant.variant_evidence_id
             FROM receipt_orders orders
             JOIN receipt_order_lines line
               ON line.order_evidence_id = orders.order_evidence_id
             JOIN receipt_variant_evidence variant
               ON variant.order_line_id = line.order_line_id",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let correction = serde_json::json!({
        "order_evidence_id": order,
        "merchant": null,
        "order_identifier": null,
        "purchase_date": null,
        "currency": null,
        "line_items": [{
            "order_line_id": line,
            "description": "Corrected shirt",
            "event_kind": "return",
            "quantity": null,
            "unit_price_minor": null,
            "variant": {
                "variant_evidence_id": variant,
                "brand": null,
                "sku": null,
                "size": null,
                "color": null
            }
        }]
    });
    let review = Uuid::new_v4().hyphenated().to_string();
    connection
        .execute(
            "INSERT INTO receipt_review_decisions(
                review_decision_id, order_evidence_id, request_id,
                action, reviewed_order_json, receipt_revision, created_at_ms
             ) VALUES (?1, ?2, ?3, 'correct', ?4, 2, 4)",
            params![
                review,
                order,
                Uuid::new_v4().hyphenated().to_string(),
                correction.to_string()
            ],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE receipt_review_heads
             SET review_decision_id = ?2, receipt_revision = 2, updated_at_ms = 4
             WHERE order_evidence_id = ?1",
            params![order, review],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE revision_state SET receipt_revision = 2 WHERE singleton = 1",
            [],
        )
        .unwrap();
    drop(connection);

    let opened = database
        .open_reconciliation_case(&OpenReconciliationCaseV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            observation_id,
            selected_artifact_id: artifact_id,
            expected_photo_revision: photo_revision,
        })
        .unwrap();
    let receipt = opened
        .case
        .candidates
        .iter()
        .find(|candidate| {
            matches!(
                candidate.target,
                ReconciliationCandidateTargetV1::ReceiptLine { .. }
            )
        })
        .unwrap();
    assert_eq!(receipt.display_name, "Corrected shirt");
    assert_eq!(receipt.detail, "Reviewed receipt evidence");
    assert!(receipt.date.is_none());
    assert!(receipt.evidence.iter().any(|evidence| {
        evidence.value_code == wardrobe_core::EVIDENCE_VALUE_EVENT_RETURN_V1
            && evidence.polarity == wardrobe_core::CandidateEvidencePolarityV1::Contradictory
    }));
    assert!(receipt.evidence.iter().any(|evidence| {
        evidence.value_code == wardrobe_core::EVIDENCE_VALUE_CORRECTED_CHANGED_V1
    }));
}

#[test]
fn empty_candidate_pools_still_persist_exactly_one_no_match() {
    let (_temporary, paths, database, observation_id, artifact_id, _item_id, photo_revision) =
        fixture();
    let connection = Connection::open(&paths.database).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    connection
        .execute("UPDATE catalog_items SET active = 0", [])
        .unwrap();
    let order: String = connection
        .query_row("SELECT order_evidence_id FROM receipt_orders", [], |row| {
            row.get(0)
        })
        .unwrap();
    let review = Uuid::new_v4().hyphenated().to_string();
    connection
        .execute(
            "INSERT INTO receipt_review_decisions(
                review_decision_id, order_evidence_id, request_id,
                action, reviewed_order_json, receipt_revision, created_at_ms
             ) VALUES (?1, ?2, ?3, 'reject', NULL, 2, 4)",
            params![review, order, Uuid::new_v4().hyphenated().to_string()],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE receipt_review_heads
             SET review_decision_id = ?2, receipt_revision = 2, updated_at_ms = 4
             WHERE order_evidence_id = ?1",
            params![order, review],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE revision_state SET catalog_revision = catalog_revision + 1,
                                       receipt_revision = 2
             WHERE singleton = 1",
            [],
        )
        .unwrap();
    drop(connection);

    let opened = database
        .open_reconciliation_case(&OpenReconciliationCaseV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            observation_id,
            selected_artifact_id: artifact_id,
            expected_photo_revision: photo_revision,
        })
        .unwrap();
    assert_eq!(opened.case.candidates.len(), 1);
    assert_eq!(
        opened.case.leading_candidate_id,
        opened.case.candidates[0].candidate_id
    );
    assert!(matches!(
        opened.case.candidates[0].target,
        ReconciliationCandidateTargetV1::NoMatch {}
    ));
}
