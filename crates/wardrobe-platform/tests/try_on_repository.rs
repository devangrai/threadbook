use std::{fs, io::Cursor};

use wardrobe_core::{
    AnalyzePhotoScopeV1Request, ApplicationService, CreateManualOutfitV1Request,
    CreatePhotoScopeV1Request, CredentialProviderV1, DatabasePort, DeletionDependencyClassV1,
    DeletionTargetKindV1, GetOutfitCollageV1Request, GetOutfitTryOnV1Request,
    ImportLocalSourcesV1Request, InboxStateV1, ItemAttributesV1, ItemCategoryV1,
    ListDeletionPlanItemsV1Request, ListImportedPhotoRootsV1Request, ListInboxV1Request,
    ListPhotoObservationsV1Request, ListTryOnPortraitCandidatesV1Request,
    OpenAiRetentionDeclarationV1, OpenAiRetentionModeV1, PhotoObservationStateV1,
    PreviewDeletionV1Request, PreviewTryOnV1Request, ReplayStatusV1, RequestId,
    SaveCredentialPlanV1, SaveItemV1Request, SubmitTryOnV1Request, TryOnFailureCodeV1,
    TryOnJobStateV1, UnavailableGarmentSegmentationProviderV1, SCHEMA_VERSION_V1,
    TRY_ON_MAX_OUTPUT_BYTES,
};
use wardrobe_platform::{BlobStore, Database, PrivateAppPaths};

fn request_id() -> RequestId {
    RequestId::new_v4()
}

fn attributes(name: &str) -> ItemAttributesV1 {
    ItemAttributesV1 {
        display_name: name.to_owned(),
        category: ItemCategoryV1::Top,
        subcategory: None,
        brand: None,
        primary_color: Some("Blue".to_owned()),
        size: None,
        notes: None,
        tags: Vec::new(),
    }
}

fn generated_output_png() -> Vec<u8> {
    let image = image::RgbaImage::from_pixel(1024, 1536, image::Rgba([24, 48, 72, 255]));
    let mut bytes = Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut bytes, image::ImageFormat::Png)
        .unwrap();
    bytes.into_inner()
}

#[test]
fn real_try_on_queue_is_explicit_restart_safe_and_credential_authorized() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let photos = temporary.path().join("photos");
    fs::create_dir(&photos).unwrap();
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../src-tauri/icons/32x32.png");
    for name in ["portrait.png", "shirt.png", "trousers.png"] {
        fs::copy(&fixture, photos.join(name)).unwrap();
    }

    let database = Database::open(&paths, 10).unwrap();
    let service = ApplicationService::new(database.clone(), BlobStore::new(&paths), ())
        .with_garment_segmentation_provider(UnavailableGarmentSegmentationProviderV1);

    service
        .import_local_sources_v1(ImportLocalSourcesV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            paths: vec![photos.to_string_lossy().into_owned()],
        })
        .unwrap();
    let inbox = service
        .list_inbox_v1(ListInboxV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            state: InboxStateV1::Unresolved,
            cursor: None,
            limit: 20,
        })
        .unwrap();
    assert_eq!(inbox.evidence.len(), 3);
    let first = service
        .save_item_v1(SaveItemV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            item_id: None,
            attributes: attributes("Blue Shirt"),
            evidence_ids: vec![inbox.evidence[0].evidence_id],
            expected_catalog_revision: 0,
        })
        .unwrap()
        .item;
    let second = service
        .save_item_v1(SaveItemV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            item_id: None,
            attributes: attributes("Navy Trousers"),
            evidence_ids: vec![inbox.evidence[1].evidence_id],
            expected_catalog_revision: 1,
        })
        .unwrap()
        .item;
    let outfit = service
        .create_manual_outfit_v1(CreateManualOutfitV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            name: "Dinner date".to_owned(),
            item_ids: vec![first.item_id, second.item_id],
            expected_catalog_revision: 2,
            expected_outfit_revision: 0,
        })
        .unwrap();
    assert!(outfit
        .outfit
        .members
        .iter()
        .all(|member| member.asset.blob_sha256.is_some()));

    let roots = service
        .list_imported_photo_roots_v1(ListImportedPhotoRootsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            cursor: None,
            limit: 20,
        })
        .unwrap();
    let scope = service
        .create_photo_scope_v1(CreatePhotoScopeV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            import_root_id: roots.roots[0].import_root_id,
            expected_manifest_generation: roots.roots[0].manifest_generation,
        })
        .unwrap()
        .scope;
    service
        .analyze_photo_scope_v1(AnalyzePhotoScopeV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            scope_id: scope.scope_id,
        })
        .unwrap();
    let observations = service
        .list_photo_observations_v1(ListPhotoObservationsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            scope_id: scope.scope_id,
            state: PhotoObservationStateV1::NeedsReview,
            cursor: None,
            limit: 20,
        })
        .unwrap();
    assert_eq!(observations.observations.len(), 3);
    let portraits = database
        .list_try_on_portrait_candidates(&ListTryOnPortraitCandidatesV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            cursor: None,
            limit: 20,
        })
        .unwrap();
    assert_eq!(portraits.candidates.len(), 3);
    assert_eq!(portraits.total_count, 3);

    let credential_request = request_id();
    let (credential_id, _locator) = match database
        .reserve_credential_save(
            credential_request,
            CredentialProviderV1::OpenAi,
            "Try-on test",
        )
        .unwrap()
    {
        SaveCredentialPlanV1::WriteSecret {
            locator,
            pending_reference,
        } => (pending_reference.credential_id, locator),
        SaveCredentialPlanV1::Replay { .. } => panic!("unexpected replay"),
    };
    database
        .activate_credential(credential_request, credential_id)
        .unwrap();

    let collage_request = GetOutfitCollageV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        outfit_id: outfit.outfit.outfit_id,
    };
    let collage_before = service
        .get_outfit_collage_v1(collage_request.clone())
        .unwrap();
    let preview_request = PreviewTryOnV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        outfit_id: outfit.outfit.outfit_id,
        portrait_source_revision_id: observations.observations[2].source_revision_id,
        credential_id,
        retention: OpenAiRetentionDeclarationV1 {
            mode: OpenAiRetentionModeV1::Unknown,
            provenance: "user_not_declared".to_owned(),
        },
        expected_outfit_revision: outfit.outfit_revision,
    };
    let preview = database.preview_try_on(&preview_request, 100).unwrap();
    assert_eq!(preview.disclosure.assets.len(), 3);
    assert_eq!(
        database
            .preview_try_on(&preview_request, 100)
            .unwrap()
            .replay_status,
        ReplayStatusV1::Replayed
    );
    let mut reused_preview_request = preview_request.clone();
    reused_preview_request.retention.provenance = "changed_declaration".to_owned();
    assert!(database
        .preview_try_on(&reused_preview_request, 100)
        .is_err());
    assert!(database
        .get_outfit_try_on(&GetOutfitTryOnV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            outfit_id: outfit.outfit.outfit_id,
        })
        .unwrap()
        .latest_job
        .is_none());

    let submit_request = SubmitTryOnV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        approval_id: preview.approval.approval_id,
    };
    let submitted = database.submit_try_on(&submit_request, 101).unwrap();
    assert_eq!(submitted.job.state, TryOnJobStateV1::Queued);
    assert_eq!(
        database
            .submit_try_on(&submit_request, 101)
            .unwrap()
            .replay_status,
        ReplayStatusV1::Replayed
    );
    let first_claim = database
        .claim_try_on_job("repository-smoke", 102, 30_000)
        .unwrap()
        .unwrap();
    assert_eq!(first_claim.assets.len(), 3);
    database.recover_try_on_jobs(103).unwrap();
    assert_eq!(
        database
            .get_outfit_try_on(&GetOutfitTryOnV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                outfit_id: outfit.outfit.outfit_id,
            })
            .unwrap()
            .latest_job
            .unwrap()
            .state,
        TryOnJobStateV1::Queued
    );
    let claim = database
        .claim_try_on_job("repository-smoke-restarted", 104, 30_000)
        .unwrap()
        .unwrap();
    assert!(claim.fence > first_claim.fence);
    assert!(database
        .authorize_try_on_transport(&first_claim, 105)
        .is_err());
    assert!(database
        .fail_try_on_job(&first_claim, TryOnFailureCodeV1::CredentialUnavailable, 105)
        .is_err());

    let transport_started_at_ms = 86_400_000;
    database
        .authorize_try_on_transport(&claim, transport_started_at_ms)
        .unwrap();
    database
        .mark_try_on_transport_started(&claim, transport_started_at_ms)
        .unwrap();
    let output_png = generated_output_png();
    let output_audit = format!(
        "{{\"transport_started_at_ms\":{transport_started_at_ms},\"automatic_retry\":false}}"
    );
    let output_hash = database
        .begin_try_on_output(&claim, &output_png, &output_audit, transport_started_at_ms)
        .unwrap();
    BlobStore::new(&paths)
        .put(
            &output_png,
            Some(&output_hash),
            TRY_ON_MAX_OUTPUT_BYTES as u64,
        )
        .unwrap();
    database
        .recover_try_on_jobs(transport_started_at_ms + 1)
        .unwrap();
    let recovered = database
        .get_outfit_try_on(&GetOutfitTryOnV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            outfit_id: outfit.outfit.outfit_id,
        })
        .unwrap();
    assert_eq!(
        recovered.latest_job.as_ref().unwrap().state,
        TryOnJobStateV1::Succeeded
    );
    assert_eq!(
        recovered.output.as_ref().unwrap().bytes.as_slice(),
        output_png
    );

    let second_preview_request = PreviewTryOnV1Request {
        request_id: request_id(),
        ..preview_request.clone()
    };
    let second_preview = database
        .preview_try_on(&second_preview_request, transport_started_at_ms + 2)
        .unwrap();
    let second_submit = database
        .submit_try_on(
            &SubmitTryOnV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                approval_id: second_preview.approval.approval_id,
            },
            transport_started_at_ms + 3,
        )
        .unwrap();
    let second_claim = database
        .claim_try_on_job("keychain-failure", transport_started_at_ms + 4, 30_000)
        .unwrap()
        .unwrap();
    assert_eq!(second_claim.job_id, second_submit.job.job_id.to_string());
    database
        .authorize_try_on_transport(&second_claim, transport_started_at_ms + 5)
        .unwrap();
    database
        .fail_try_on_job(
            &second_claim,
            TryOnFailureCodeV1::CredentialUnavailable,
            transport_started_at_ms + 5,
        )
        .unwrap();

    let third_preview = database
        .preview_try_on(
            &PreviewTryOnV1Request {
                request_id: request_id(),
                ..preview_request
            },
            transport_started_at_ms + 6,
        )
        .unwrap();
    let third_submit = database
        .submit_try_on(
            &SubmitTryOnV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request_id(),
                approval_id: third_preview.approval.approval_id,
            },
            transport_started_at_ms + 7,
        )
        .unwrap();
    let third_claim = database
        .claim_try_on_job("credential-race", transport_started_at_ms + 8, 30_000)
        .unwrap()
        .unwrap();
    assert_eq!(third_claim.job_id, third_submit.job.job_id.to_string());
    database
        .prepare_credential_delete(request_id(), credential_id)
        .unwrap();
    assert!(database
        .authorize_try_on_transport(&third_claim, transport_started_at_ms + 9)
        .is_err());
    database
        .fail_try_on_job(
            &third_claim,
            TryOnFailureCodeV1::CredentialUnavailable,
            transport_started_at_ms + 9,
        )
        .unwrap();
    let terminal = database
        .get_outfit_try_on(&GetOutfitTryOnV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            outfit_id: outfit.outfit.outfit_id,
        })
        .unwrap();
    assert_eq!(
        terminal.latest_job.as_ref().unwrap().state,
        TryOnJobStateV1::Failed
    );
    assert_eq!(terminal.garment_sources.len(), 2);
    assert!(terminal.output.is_none());

    let collage_after = service
        .get_outfit_collage_v1(GetOutfitCollageV1Request {
            request_id: request_id(),
            ..collage_request
        })
        .unwrap();
    assert_eq!(collage_before.name, collage_after.name);
    assert_eq!(collage_before.members, collage_after.members);

    let deletion = service
        .preview_deletion_v1(PreviewDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            target_kind: DeletionTargetKindV1::Item,
            target_id: first.item_id.to_string(),
            limit: 100,
        })
        .unwrap();
    let mut records = Vec::new();
    for class in [
        DeletionDependencyClassV1::SourceRecords,
        DeletionDependencyClassV1::EvidenceRecords,
        DeletionDependencyClassV1::DecisionRecords,
        DeletionDependencyClassV1::RemoteReferences,
    ] {
        records.extend(
            service
                .list_deletion_plan_items_v1(ListDeletionPlanItemsV1Request {
                    schema_version: SCHEMA_VERSION_V1,
                    request_id: request_id(),
                    preview_snapshot_token: deletion.preview_snapshot_token.clone(),
                    class,
                    cursor: None,
                    limit: 100,
                })
                .unwrap()
                .items
                .into_iter()
                .map(|item| item.record_id),
        );
    }
    assert!(records.iter().any(|id| id.starts_with("try_on_approval:")));
    assert!(records.iter().any(|id| id.starts_with("try_on_asset:")));
    assert!(records.iter().any(|id| id.starts_with("try_on_job:")));
    assert!(records.iter().any(|id| id.starts_with("try_on_attempt:")));
    assert!(records
        .iter()
        .any(|id| id.starts_with("try_on_remote_reference:")));
    let remote = service
        .list_deletion_plan_items_v1(ListDeletionPlanItemsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            preview_snapshot_token: deletion.preview_snapshot_token,
            class: DeletionDependencyClassV1::RemoteReferences,
            cursor: None,
            limit: 100,
        })
        .unwrap();
    assert_eq!(remote.items.len(), 1);
    assert!(remote.items[0].display_label.contains("1970-02-01"));
}
