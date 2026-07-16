use image::{ColorType, ImageFormat};
use rusqlite::{params, Connection};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use wardrobe_core::{
    AnalyzePhotoScopeV1Request, CatalogPort, CreatePhotoScopeV1Request,
    GarmentSegmentationProvider, ImportLocalSourcesV1Request, ListImportedPhotoRootsV1Request,
    ListPhotoObservationsV1Request, PhotoAnalysisPort, PhotoAnalysisPortErrorKind,
    PhotoObservationStateV1, PhotoReviewActionV1, PromptPhotoObservationV1Request,
    ReadPhotoArtifactV1Request, RectV1, RefreshImportRootsV1Request, ReplayStatusV1, RequestId,
    ReviewPhotoObservationV1Request, SegmentationOutcomeV1, SegmentationProviderDescriptorV1,
    SegmentationProviderResult, SegmentationRequestV1, Sha256Digest,
    UnavailableGarmentSegmentationProviderV1, SCHEMA_VERSION_V1,
};
use wardrobe_platform::{Database, PrivateAppPaths};

fn request_id() -> RequestId {
    RequestId::new_v4()
}

fn write_png(path: &std::path::Path, value: u8) {
    let pixels = vec![value; 8 * 6 * 3];
    image::save_buffer_with_format(path, &pixels, 8, 6, ColorType::Rgb8, ImageFormat::Png).unwrap();
}

fn setup_folder(
    with_quarantine: bool,
) -> (
    tempfile::TempDir,
    PrivateAppPaths,
    Database,
    std::path::PathBuf,
) {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let folder = temporary.path().join("photos");
    fs::create_dir(&folder).unwrap();
    write_png(&folder.join("shirt.png"), 80);
    if with_quarantine {
        fs::write(folder.join("invalid.jpg"), b"not an image").unwrap();
    }
    let database = Database::open(&paths, 1).unwrap();
    database
        .import_local_sources(&ImportLocalSourcesV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            paths: vec![folder.to_string_lossy().into_owned()],
        })
        .unwrap();
    (temporary, paths, database, folder)
}

fn list_roots(database: &Database) -> wardrobe_core::ListImportedPhotoRootsV1Response {
    database
        .list_imported_photo_roots(&ListImportedPhotoRootsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            cursor: None,
            limit: 20,
        })
        .unwrap()
}

#[test]
fn production_unavailable_fallback_replay_review_and_artifact_read() {
    let (_temporary, paths, database, _folder) = setup_folder(true);
    let before = Connection::open(&paths.database).unwrap();
    let evidence_before: i64 = before
        .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
        .unwrap();
    drop(before);
    let listed = list_roots(&database);
    assert_eq!(listed.roots.len(), 1);
    assert_eq!(listed.roots[0].member_count, 2);
    assert_eq!(listed.roots[0].eligible_count, 1);
    assert_eq!(listed.roots[0].quarantined_count, 1);

    let create_request = CreatePhotoScopeV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        import_root_id: listed.roots[0].import_root_id,
        expected_manifest_generation: listed.roots[0].manifest_generation,
    };
    let created = database.create_photo_scope(&create_request).unwrap();
    let replayed = database.create_photo_scope(&create_request).unwrap();
    assert_eq!(replayed.replay_status, ReplayStatusV1::Replayed);
    assert_eq!(replayed.scope, created.scope);
    let converged = database
        .create_photo_scope(&CreatePhotoScopeV1Request {
            request_id: request_id(),
            ..create_request.clone()
        })
        .unwrap();
    assert_eq!(converged.replay_status, ReplayStatusV1::Created);
    assert_eq!(converged.scope, created.scope);
    let changed = CreatePhotoScopeV1Request {
        expected_manifest_generation: created.scope.manifest_generation + 1,
        ..create_request.clone()
    };
    assert_eq!(
        database.create_photo_scope(&changed).unwrap_err().kind,
        PhotoAnalysisPortErrorKind::Conflict
    );

    let analyze_request = AnalyzePhotoScopeV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        scope_id: created.scope.scope_id,
    };
    let analyzed = database
        .analyze_photo_scope(&analyze_request, &UnavailableGarmentSegmentationProviderV1)
        .unwrap();
    assert_eq!(analyzed.completed_count, 2);
    assert_eq!(analyzed.needs_review_count, 1);
    assert_eq!(analyzed.skipped_count, 1);
    assert_eq!(
        database
            .analyze_photo_scope(&analyze_request, &UnavailableGarmentSegmentationProviderV1)
            .unwrap()
            .replay_status,
        ReplayStatusV1::Replayed
    );
    let converged_analysis = database
        .analyze_photo_scope(
            &AnalyzePhotoScopeV1Request {
                request_id: request_id(),
                ..analyze_request.clone()
            },
            &UnavailableGarmentSegmentationProviderV1,
        )
        .unwrap();
    assert_eq!(converged_analysis.replay_status, ReplayStatusV1::Created);
    assert_eq!(converged_analysis.run_id, analyzed.run_id);

    let observations = database
        .list_photo_observations(&ListPhotoObservationsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            scope_id: created.scope.scope_id,
            state: PhotoObservationStateV1::NeedsReview,
            cursor: None,
            limit: 20,
        })
        .unwrap();
    assert_eq!(observations.observations.len(), 1);
    let initial = &observations.observations[0];
    assert_eq!(initial.artifact.rectangle.unwrap().width, 8);
    assert_eq!(
        initial.artifact.unavailable_reason,
        Some(wardrobe_core::SegmentationUnavailableReasonV1::ReviewedModelPackAbsent)
    );

    let read = database
        .read_photo_artifact(&ReadPhotoArtifactV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            artifact_id: initial.artifact.artifact_id,
        })
        .unwrap();
    assert_eq!(
        read.bytes_sha256,
        Sha256Digest::from_bytes(read.bytes.as_slice())
    );
    assert_eq!(read.width, 8);
    assert_eq!(read.height, 6);

    let prompted = database
        .prompt_photo_observation(
            &PromptPhotoObservationV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                observation_id: initial.observation_id,
                box_rectangle: RectV1 {
                    x: 1,
                    y: 1,
                    width: 4,
                    height: 3,
                },
                positive_points: Vec::new(),
                negative_points: Vec::new(),
            },
            &UnavailableGarmentSegmentationProviderV1,
        )
        .unwrap();
    assert_eq!(prompted.observation.artifact.rectangle.unwrap().width, 4);
    assert!(prompted.observation.review_head.is_none());

    let review_request = ReviewPhotoObservationV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        observation_id: initial.observation_id,
        action: PhotoReviewActionV1::ReplaceCrop,
        replacement_rectangle: Some(RectV1 {
            x: 2,
            y: 1,
            width: 3,
            height: 4,
        }),
        expected_photo_revision: 0,
    };
    let reviewed = database.review_photo_observation(&review_request).unwrap();
    assert_eq!(
        reviewed.observation.state,
        PhotoObservationStateV1::Replaced
    );
    assert_eq!(reviewed.observation.artifact.rectangle.unwrap().width, 3);
    assert!(reviewed.observation.review_head.is_some());
    assert_eq!(
        database
            .review_photo_observation(&review_request)
            .unwrap()
            .replay_status,
        ReplayStatusV1::Replayed
    );
    assert_eq!(
        database
            .prompt_photo_observation(
                &PromptPhotoObservationV1Request {
                    schema_version: SCHEMA_VERSION_V1,
                    request_id: request_id(),
                    observation_id: initial.observation_id,
                    box_rectangle: RectV1 {
                        x: 0,
                        y: 0,
                        width: 2,
                        height: 2,
                    },
                    positive_points: Vec::new(),
                    negative_points: Vec::new(),
                },
                &UnavailableGarmentSegmentationProviderV1,
            )
            .unwrap_err()
            .kind,
        PhotoAnalysisPortErrorKind::Conflict
    );

    let connection = Connection::open(&paths.database).unwrap();
    for table in ["catalog_items", "item_evidence", "catalog_decisions"] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must remain untouched");
    }
    let evidence_after: i64 = connection
        .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
        .unwrap();
    assert_eq!(evidence_after, evidence_before);
    let parent_edges: i64 = connection
        .query_row("SELECT COUNT(*) FROM photo_artifact_parents", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(parent_edges, 2);
    let provenance: String = connection
        .query_row(
            "SELECT provenance_json FROM photo_artifacts
             WHERE artifact_id = ?1",
            [prompted.observation.artifact.artifact_id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    for forbidden in ["path", "filename", "pixels", "free_text"] {
        assert!(!provenance.contains(forbidden));
    }
    drop(connection);

    let hash = read.bytes_sha256.as_str();
    let blob_path = paths.blobs.join(&hash[0..2]).join(&hash[2..4]).join(hash);
    let mut corrupted = read.bytes.as_slice().to_vec();
    corrupted[0] ^= 0xff;
    fs::write(blob_path, corrupted).unwrap();
    assert_eq!(
        database
            .read_photo_artifact(&ReadPhotoArtifactV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                artifact_id: initial.artifact.artifact_id,
            })
            .unwrap_err()
            .kind,
        PhotoAnalysisPortErrorKind::DataIntegrity
    );
}

#[test]
fn deletion_preview_closes_whole_photo_scope_and_preserves_source_authority() {
    let (_temporary, paths, database, _folder) = setup_folder(true);
    let listed = list_roots(&database);
    let created = database
        .create_photo_scope(&CreatePhotoScopeV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            import_root_id: listed.roots[0].import_root_id,
            expected_manifest_generation: listed.roots[0].manifest_generation,
        })
        .unwrap();
    database
        .analyze_photo_scope(
            &AnalyzePhotoScopeV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                scope_id: created.scope.scope_id,
            },
            &UnavailableGarmentSegmentationProviderV1,
        )
        .unwrap();

    let connection = Connection::open(&paths.database).unwrap();
    let (target_source, other_source): (String, String) = {
        let mut statement = connection
            .prepare(
                "SELECT source_id FROM local_sources
                 WHERE root_id = ?1 ORDER BY status, source_id",
            )
            .unwrap();
        let values = statement
            .query_map([listed.roots[0].import_root_id.to_string()], |row| {
                row.get::<_, String>(0)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        (values[0].clone(), values[1].clone())
    };
    drop(connection);

    let preview = database
        .preview_deletion(&wardrobe_core::PreviewDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            target_kind: wardrobe_core::DeletionTargetKindV1::Source,
            target_id: target_source.clone(),
            limit: 100,
        })
        .unwrap();
    let connection = Connection::open(&paths.database).unwrap();
    let token = preview.preview_snapshot_token.as_str();
    for prefix in [
        "photo_scope:",
        "photo_source_revision:",
        "photo_analysis_run:",
        "photo_segmentation_attempt:",
        "photo_artifact:",
        "photo_observation:",
        "photo_command_receipt:",
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM deletion_preview_items
                 WHERE snapshot_token = ?1 AND entity_id LIKE ?2",
                params![token, format!("{prefix}%")],
                |row| row.get(0),
            )
            .unwrap();
        assert!(count > 0, "missing deletion closure for {prefix}");
    }
    let other_source_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM deletion_preview_items
             WHERE snapshot_token = ?1 AND entity_id = ?2",
            params![token, other_source],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        other_source_rows, 0,
        "whole-scope invalidation must not broaden the local-source target"
    );
}

struct FenceStealingProvider {
    database_path: std::path::PathBuf,
    steal_once: AtomicBool,
}

impl GarmentSegmentationProvider for FenceStealingProvider {
    fn describe(&self) -> SegmentationProviderDescriptorV1 {
        UnavailableGarmentSegmentationProviderV1.describe()
    }

    fn segment(
        &self,
        request: &SegmentationRequestV1,
    ) -> SegmentationProviderResult<SegmentationOutcomeV1> {
        if self.steal_once.swap(false, Ordering::SeqCst) {
            let connection = Connection::open(&self.database_path).unwrap();
            connection.execute("PRAGMA foreign_keys = ON", []).unwrap();
            connection
                .execute(
                    "UPDATE photo_analysis_member_claims
                     SET state = 'pending', fence = fence + 1,
                         lease_owner = NULL, lease_expires_at_ms = NULL,
                         updated_at_ms = updated_at_ms + 1
                     WHERE state = 'running'",
                    [],
                )
                .unwrap();
        }
        UnavailableGarmentSegmentationProviderV1.segment(request)
    }
}

#[test]
fn stale_fence_has_no_effect_and_same_request_resumes_once() {
    let (_temporary, paths, database, _folder) = setup_folder(false);
    let root = list_roots(&database).roots.remove(0);
    let scope = database
        .create_photo_scope(&CreatePhotoScopeV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            import_root_id: root.import_root_id,
            expected_manifest_generation: root.manifest_generation,
        })
        .unwrap()
        .scope;
    let request = AnalyzePhotoScopeV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        scope_id: scope.scope_id,
    };
    let provider = FenceStealingProvider {
        database_path: paths.database.clone(),
        steal_once: AtomicBool::new(true),
    };
    assert_eq!(
        database
            .analyze_photo_scope(&request, &provider)
            .unwrap_err()
            .kind,
        PhotoAnalysisPortErrorKind::Conflict
    );
    let connection = Connection::open(&paths.database).unwrap();
    let effects: i64 = connection
        .query_row("SELECT COUNT(*) FROM photo_observations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(effects, 0);
    drop(connection);

    let resumed = database.analyze_photo_scope(&request, &provider).unwrap();
    assert_eq!(resumed.completed_count, 1);
    let connection = Connection::open(&paths.database).unwrap();
    for table in [
        "photo_segmentation_attempts",
        "photo_segmentation_outcomes",
        "photo_artifacts",
        "photo_observations",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "{table} must have one winning effect");
    }
}

#[test]
fn observation_cursor_is_revision_bound_and_has_no_empty_tail_page() {
    let (_temporary, _paths, database, folder) = setup_folder(false);
    let first_root = list_roots(&database).roots.remove(0);
    write_png(&folder.join("second.png"), 120);
    database
        .refresh_import_roots(&RefreshImportRootsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            import_root_ids: vec![first_root.import_root_id],
        })
        .unwrap();
    let root = list_roots(&database).roots.remove(0);
    let scope = database
        .create_photo_scope(&CreatePhotoScopeV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            import_root_id: root.import_root_id,
            expected_manifest_generation: root.manifest_generation,
        })
        .unwrap()
        .scope;
    database
        .analyze_photo_scope(
            &AnalyzePhotoScopeV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                scope_id: scope.scope_id,
            },
            &UnavailableGarmentSegmentationProviderV1,
        )
        .unwrap();
    let first_page = database
        .list_photo_observations(&ListPhotoObservationsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            scope_id: scope.scope_id,
            state: PhotoObservationStateV1::NeedsReview,
            cursor: None,
            limit: 1,
        })
        .unwrap();
    let cursor = first_page.next_cursor.clone().unwrap();
    let second_page = database
        .list_photo_observations(&ListPhotoObservationsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            scope_id: scope.scope_id,
            state: PhotoObservationStateV1::NeedsReview,
            cursor: Some(cursor.clone()),
            limit: 1,
        })
        .unwrap();
    assert_eq!(second_page.observations.len(), 1);
    assert!(second_page.next_cursor.is_none());

    database
        .review_photo_observation(&ReviewPhotoObservationV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            observation_id: first_page.observations[0].observation_id,
            action: PhotoReviewActionV1::ConfirmCrop,
            replacement_rectangle: None,
            expected_photo_revision: 0,
        })
        .unwrap();
    assert_eq!(
        database
            .list_photo_observations(&ListPhotoObservationsV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                scope_id: scope.scope_id,
                state: PhotoObservationStateV1::NeedsReview,
                cursor: Some(cursor),
                limit: 1,
            })
            .unwrap_err()
            .kind,
        PhotoAnalysisPortErrorKind::SnapshotExpired
    );
}

#[test]
fn frozen_scope_remains_bound_to_old_blob_after_refresh() {
    let (_temporary, _paths, database, folder) = setup_folder(false);
    let root = list_roots(&database).roots.remove(0);
    let scope = database
        .create_photo_scope(&CreatePhotoScopeV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            import_root_id: root.import_root_id,
            expected_manifest_generation: root.manifest_generation,
        })
        .unwrap()
        .scope;

    write_png(&folder.join("shirt.png"), 190);
    write_png(&folder.join("new.png"), 30);
    database
        .refresh_import_roots(&RefreshImportRootsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            import_root_ids: vec![root.import_root_id],
        })
        .unwrap();
    let analyzed = database
        .analyze_photo_scope(
            &AnalyzePhotoScopeV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                scope_id: scope.scope_id,
            },
            &UnavailableGarmentSegmentationProviderV1,
        )
        .unwrap();
    assert_eq!(analyzed.member_count, 1);
    assert_eq!(analyzed.needs_review_count, 1);
}

#[test]
fn running_scan_hides_root_and_blocks_scope_creation() {
    let (_temporary, paths, database, _folder) = setup_folder(false);
    let root = list_roots(&database).roots.remove(0);
    let connection = Connection::open(&paths.database).unwrap();
    connection.execute("PRAGMA foreign_keys = ON", []).unwrap();
    connection
        .execute(
            "INSERT INTO import_scans(
                scan_id, root_id, generation, status, started_at_ms
             ) VALUES (?1, ?2, ?3, 'running', 2)",
            params![
                uuid::Uuid::new_v4().to_string(),
                root.import_root_id.to_string(),
                root.manifest_generation as i64 + 1
            ],
        )
        .unwrap();
    drop(connection);
    assert!(list_roots(&database).roots.is_empty());
    assert_eq!(
        database
            .create_photo_scope(&CreatePhotoScopeV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                import_root_id: root.import_root_id,
                expected_manifest_generation: root.manifest_generation,
            })
            .unwrap_err()
            .kind,
        PhotoAnalysisPortErrorKind::SnapshotExpired
    );
}
