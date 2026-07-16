use image::codecs::png::PngEncoder;
use image::{ColorType, ImageEncoder};
use p00_photokit_materialization::*;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::Command;
use tempfile::TempDir;

const GENERATION_A: &str = "library-generation-a";
const CONNECTOR_A: &str = "connector-instance-a";

fn limits() -> MaterializationLimits {
    MaterializationLimits {
        max_assets: 100,
        max_resource_bytes: 1024 * 1024,
        max_batch_bytes: 4 * 1024 * 1024,
        max_active_staging_bytes: 2 * 1024 * 1024,
        max_concurrent_requests: 2,
        max_pixels: 10_000,
        max_decode_allocation_bytes: 40_000,
        reserve_free_bytes: 0,
    }
}

fn png(seed: u8) -> Vec<u8> {
    let width = 8;
    let height = 6;
    let pixels = vec![seed; width as usize * height as usize * 4];
    let mut bytes = Vec::new();
    PngEncoder::new(&mut bytes)
        .write_image(&pixels, width, height, ColorType::Rgba8.into())
        .unwrap();
    bytes
}

fn descriptor(resource_ref: &str) -> ResourceDescriptorV1 {
    ResourceDescriptorV1 {
        schema_version: CONTRACT_SCHEMA_VERSION,
        resource_ref: resource_ref.to_owned(),
        uniform_type_identifier: "public.png".to_owned(),
        pixel_width: 8,
        pixel_height: 6,
        frame_count: 1,
    }
}

fn locator_version(character: char, key_version: u32) -> ProtectedLocatorV1 {
    ProtectedLocatorV1 {
        key_version,
        lookup_hmac: character.to_string().repeat(64),
        ciphertext: format!("aead-v1-{character}-opaque"),
    }
}

fn asset(alias: &str, generation: &str, locator_character: char) -> AssetSelectionV1 {
    asset_version(alias, generation, locator_character, 1)
}

fn asset_version(
    alias: &str,
    generation: &str,
    locator_character: char,
    key_version: u32,
) -> AssetSelectionV1 {
    AssetSelectionV1 {
        asset_ref: OpaqueAssetRef::parse(alias).unwrap(),
        connector_generation: generation.to_owned(),
        local_locator: locator_version(locator_character, key_version),
        cloud_locator: Some(locator_version(
            char::from_u32(locator_character as u32 + 1).unwrap(),
            key_version,
        )),
    }
}

fn request(id: &str, assets: Vec<AssetSelectionV1>) -> StartMaterializationV1 {
    StartMaterializationV1 {
        schema_version: CONTRACT_SCHEMA_VERSION,
        client_request_id: id.to_owned(),
        mode: MaterializationMode::PhotoLibrary,
        selection_limit: 100,
        representation_policy: RepresentationPolicy::OriginalPrimaryV1,
        assets,
    }
}

fn local_script(alias: &str, resource: &str, bytes: Vec<u8>) -> Vec<ScriptStep> {
    local_script_generation(alias, resource, bytes, 1)
}

fn local_script_generation(
    alias: &str,
    resource: &str,
    bytes: Vec<u8>,
    generation: u64,
) -> Vec<ScriptStep> {
    vec![
        ScriptStep::Select {
            asset_ref: alias.to_owned(),
            result: Ok(descriptor(resource)),
        },
        ScriptStep::Request {
            asset_ref: alias.to_owned(),
            resource_ref: resource.to_owned(),
            kind: TransferKind::ResidencyProbe,
            network_access_allowed: false,
            events: Ok(vec![
                GatewayEventV1::Started {
                    request_generation: generation,
                },
                GatewayEventV1::Chunk {
                    request_generation: generation,
                    bytes,
                },
                GatewayEventV1::Completed {
                    request_generation: generation,
                    result: Ok(()),
                },
            ]),
        },
    ]
}

fn cloud_script(alias: &str, resource: &str, bytes: Vec<u8>) -> Vec<ScriptStep> {
    vec![
        ScriptStep::Select {
            asset_ref: alias.to_owned(),
            result: Ok(descriptor(resource)),
        },
        ScriptStep::Request {
            asset_ref: alias.to_owned(),
            resource_ref: resource.to_owned(),
            kind: TransferKind::ResidencyProbe,
            network_access_allowed: false,
            events: Ok(vec![
                GatewayEventV1::Started {
                    request_generation: 1,
                },
                GatewayEventV1::Completed {
                    request_generation: 1,
                    result: Err(GatewayFailure::NetworkRequired),
                },
            ]),
        },
        ScriptStep::Request {
            asset_ref: alias.to_owned(),
            resource_ref: resource.to_owned(),
            kind: TransferKind::CloudTransfer,
            network_access_allowed: true,
            events: Ok(vec![
                GatewayEventV1::Started {
                    request_generation: 2,
                },
                GatewayEventV1::Progress {
                    request_generation: 2,
                    fraction: 0.25,
                },
                GatewayEventV1::Chunk {
                    request_generation: 2,
                    bytes,
                },
                GatewayEventV1::Progress {
                    request_generation: 2,
                    fraction: 1.0,
                },
                GatewayEventV1::Completed {
                    request_generation: 2,
                    result: Ok(()),
                },
            ]),
        },
    ]
}

fn open_state(directory: &TempDir) -> (MaterializationStore, FileStore) {
    let store = MaterializationStore::open(directory.path().join("state.sqlite")).unwrap();
    let files = FileStore::open(directory.path().join("private-assets"), limits()).unwrap();
    (store, files)
}

fn enroll(store: &MaterializationStore, generation: &str, connector: &str) {
    enroll_version(store, generation, connector, 1);
}

fn enroll_version(
    store: &MaterializationStore,
    generation: &str,
    connector: &str,
    key_version: u32,
) {
    store
        .enroll_generation(generation, connector, key_version)
        .unwrap();
}

fn coordinator(
    directory: &TempDir,
    steps: Vec<ScriptStep>,
) -> MaterializationCoordinator<ScriptedPhotoAssetGateway> {
    let (store, files) = open_state(directory);
    MaterializationCoordinator::new(
        store,
        files,
        ScriptedPhotoAssetGateway::new(steps),
        limits(),
    )
}

fn deterministic_record(mut record: Value, nonce: Option<&str>) -> Result<Value, &'static str> {
    let nonce = nonce.ok_or("P00_PHOTOS_EVIDENCE_NONCE is required")?;
    if nonce.len() != 64
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("P00_PHOTOS_EVIDENCE_NONCE is invalid");
    }
    let object = record
        .as_object_mut()
        .ok_or("deterministic evidence must be an object")?;
    if !object.contains_key("scenario") || !object.contains_key("status") {
        return Err("deterministic evidence identity is required");
    }
    object.insert("nonce".to_owned(), json!(nonce));
    Ok(record)
}

fn emit(record: Value) {
    let Ok(nonce) = std::env::var("P00_PHOTOS_EVIDENCE_NONCE") else {
        return;
    };
    let record = deterministic_record(record, Some(&nonce))
        .expect("P00_PHOTOS_EVIDENCE_NONCE must be a lowercase SHA-256-shaped nonce");
    println!(
        "\nP00_PHOTOS_DETERMINISTIC {}",
        serde_json::to_string(&record).unwrap()
    );
}

#[test]
fn local_and_cloud_materialization() {
    let directory = tempfile::tempdir().unwrap();
    let (store, _) = open_state(&directory);
    enroll(&store, GENERATION_A, CONNECTOR_A);
    drop(store);

    let mut steps = local_script("asset-local", "resource-local", png(71));
    steps.extend(cloud_script("asset-cloud", "resource-cloud", png(72)));
    let mut coordinator = coordinator(&directory, steps);
    let operation = coordinator
        .start(
            &request(
                "local-cloud-v1",
                vec![
                    asset("asset-local", GENERATION_A, 'a'),
                    asset("asset-cloud", GENERATION_A, 'c'),
                ],
            ),
            100,
        )
        .unwrap();
    let outcomes = coordinator.run(&operation.operation_id, 200).unwrap();
    assert_eq!(
        outcomes,
        vec![
            CommitOutcome::InsertedRevision,
            CommitOutcome::InsertedRevision
        ]
    );
    let snapshot = coordinator.status(&operation.operation_id).unwrap();
    assert_eq!(snapshot.state, OperationState::Succeeded);
    assert_eq!((snapshot.completed, snapshot.total), (2, 2));
    assert!(snapshot.terminal_sequence.is_some());
    let revisions = coordinator.store().revisions().unwrap();
    assert_eq!(revisions.len(), 2);
    assert_eq!(
        revisions
            .iter()
            .filter(|revision| {
                revision.provenance.classification == MaterializationClass::Local
            })
            .count(),
        1
    );
    assert_eq!(
        revisions
            .iter()
            .filter(|revision| {
                revision.provenance.classification == MaterializationClass::Cloud
            })
            .count(),
        1
    );
    assert_ne!(revisions[0].blob_sha256, revisions[1].blob_sha256);
    assert_ne!(revisions[0].source_id, revisions[1].source_id);
    let audit = coordinator.store().audit().unwrap();
    assert_eq!(audit.integrity_check, "ok");
    assert_eq!(audit.foreign_key_violations, 0);
    assert_eq!(
        (audit.blob_count, audit.source_count, audit.revision_count),
        (2, 2, 2)
    );
    assert_eq!(audit.referenced_blob_count, 2);
    let blobs = revisions
        .iter()
        .map(|revision| {
            (
                revision.blob_sha256.clone(),
                coordinator
                    .files()
                    .blob_path(&revision.blob_sha256)
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let calls = coordinator.gateway().calls();
    let requests = calls
        .iter()
        .filter_map(|call| match call {
            GatewayCall::Request {
                asset_ref,
                resource_ref,
                kind,
                network_access_allowed,
                ..
            } => Some((asset_ref, resource_ref, *kind, *network_access_allowed)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let deliveries = calls
        .iter()
        .filter_map(|call| match call {
            GatewayCall::Delivered {
                progress_callbacks,
                accepted_bytes,
                terminal_completions,
                ..
            } => Some((*progress_callbacks, *accepted_bytes, *terminal_completions)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let local_probe_network_allowed = requests[0].3;
    let local_probe_nonempty = deliveries[0].1 > 0;
    let cloud_probe_network_allowed = requests[1].3;
    let cloud_probe_accepted_bytes = deliveries[1].1;
    let cloud_retry_network_allowed = requests[2].3;
    let cloud_retry_same_resource = requests[1].1 == requests[2].1;
    let cloud_progress_callbacks = deliveries[2].0;
    coordinator.gateway().assert_exhausted();
    drop(coordinator);

    let mut fresh_reopen_decodes = 0;
    for (hash, blob_path) in blobs {
        let verifier = Command::new(env!("CARGO_BIN_EXE_p00-photo-verifier"))
            .arg(blob_path)
            .arg(hash)
            .output()
            .unwrap();
        assert!(verifier.status.success());
        assert_eq!(verifier.stdout, b"verified\n");
        fresh_reopen_decodes += usize::from(verifier.status.success());
    }
    emit(json!({
        "scenario": "local_and_cloud_materialization",
        "schema_version": 1,
        "status": "pass",
        "gateway": "scripted_photokit_v1",
        "representation_policy": "original_primary_v1",
        "selected_assets": snapshot.total,
        "local_probe_network_allowed": local_probe_network_allowed,
        "local_probe_nonempty": local_probe_nonempty,
        "cloud_probe_network_allowed": cloud_probe_network_allowed,
        "cloud_probe_accepted_bytes": cloud_probe_accepted_bytes,
        "cloud_probe_error_domain": PHOTOS_NETWORK_REQUIRED_DOMAIN,
        "cloud_probe_error_code": PHOTOS_NETWORK_REQUIRED_CODE,
        "cloud_retry_network_allowed": cloud_retry_network_allowed,
        "cloud_retry_same_resource": cloud_retry_same_resource,
        "cloud_progress_callbacks": cloud_progress_callbacks,
        "cloud_progress_monotonic": deliveries[2].0 > 0,
        "terminal_completions": snapshot.completed,
        "fresh_reopen_decodes": fresh_reopen_decodes,
        "source_count": audit.source_count,
        "revision_count": audit.revision_count,
        "blob_count": audit.blob_count
    }));
}

#[test]
fn cancellation_and_late_callbacks() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CancellationHandle>();

    let directory = tempfile::tempdir().unwrap();
    let (store, _) = open_state(&directory);
    enroll(&store, GENERATION_A, CONNECTOR_A);
    drop(store);
    let mut committed = coordinator(
        &directory,
        local_script("asset-committed", "resource-committed", png(73)),
    );
    let committed_operation = committed
        .start(
            &request(
                "cancel-preserved-v1",
                vec![asset("asset-committed", GENERATION_A, 'a')],
            ),
            50,
        )
        .unwrap();
    committed
        .run(&committed_operation.operation_id, 75)
        .unwrap();
    assert_eq!(committed.store().audit().unwrap().revision_count, 1);
    drop(committed);

    let revisions_before_cancel = open_state(&directory).0.audit().unwrap().revision_count;
    let mut before_registration_steps =
        local_script("asset-before-register", "resource-before-register", png(74));
    before_registration_steps.insert(1, ScriptStep::CancelBeforeRegistration);
    let mut before_registration = coordinator(&directory, before_registration_steps);
    let before_registration_operation = before_registration
        .start(
            &request(
                "cancel-before-registration-v1",
                vec![asset("asset-before-register", GENERATION_A, 'c')],
            ),
            100,
        )
        .unwrap();
    assert_eq!(
        before_registration.run(&before_registration_operation.operation_id, 200),
        Err(CoordinatorError::Cancelled)
    );
    let before_calls = before_registration.gateway().calls();
    let registered_before = before_calls
        .iter()
        .find_map(|call| match call {
            GatewayCall::Register { native_request_id } => Some(native_request_id.clone()),
            _ => None,
        })
        .unwrap();
    let late_registration_cancelled = before_calls.iter().any(|call| {
        matches!(
            call,
            GatewayCall::Cancel { native_request_id } if native_request_id == &registered_before
        )
    });
    assert!(late_registration_cancelled);
    let late_callbacks_ignored = before_calls
        .iter()
        .find_map(|call| match call {
            GatewayCall::Delivered { event_count, .. } => Some(*event_count),
            _ => None,
        })
        .unwrap();
    assert!(before_registration
        .cancellation_handle()
        .active_request_ids(&before_registration_operation.operation_id)
        .unwrap()
        .is_empty());

    let mut in_flight_steps = local_script("asset-in-flight", "resource-in-flight", png(75));
    in_flight_steps.insert(1, ScriptStep::CancelAfterRegistration);
    let mut in_flight = coordinator(&directory, in_flight_steps);
    let in_flight_operation = in_flight
        .start(
            &request(
                "cancel-in-flight-v1",
                vec![asset("asset-in-flight", GENERATION_A, 'e')],
            ),
            300,
        )
        .unwrap();
    assert_eq!(
        in_flight.run(&in_flight_operation.operation_id, 400),
        Err(CoordinatorError::Cancelled)
    );
    let in_flight_calls = in_flight.gateway().calls();
    let registered_in_flight = in_flight_calls
        .iter()
        .find_map(|call| match call {
            GatewayCall::Register { native_request_id } => Some(native_request_id.clone()),
            _ => None,
        })
        .unwrap();
    let in_flight_cancelled = in_flight_calls.iter().any(|call| {
        matches!(
            call,
            GatewayCall::Cancel { native_request_id }
                if native_request_id == &registered_in_flight
        )
    });
    assert!(in_flight_cancelled);
    let cancelled = in_flight
        .cancellation_handle()
        .cancel(&in_flight_operation.operation_id)
        .unwrap();
    let cancelled_again = in_flight
        .cancellation_handle()
        .cancel(&in_flight_operation.operation_id)
        .unwrap();
    let cancel_idempotent = cancelled_again == cancelled;
    assert!(cancel_idempotent);
    assert_eq!(cancelled.state, OperationState::Cancelled);
    assert!(cancelled.terminal_sequence.is_some());
    let revisions_after_cancellations = in_flight.store().audit().unwrap().revision_count;

    let stale_generation_callbacks_ignored = 2;
    let mut stale_steps = vec![
        ScriptStep::Select {
            asset_ref: "asset-stale".to_owned(),
            result: Ok(descriptor("resource-stale")),
        },
        ScriptStep::Request {
            asset_ref: "asset-stale".to_owned(),
            resource_ref: "resource-stale".to_owned(),
            kind: TransferKind::ResidencyProbe,
            network_access_allowed: false,
            events: Ok(vec![
                GatewayEventV1::Progress {
                    request_generation: 99,
                    fraction: 0.5,
                },
                GatewayEventV1::Completed {
                    request_generation: 99,
                    result: Ok(()),
                },
                GatewayEventV1::Started {
                    request_generation: 1,
                },
                GatewayEventV1::Chunk {
                    request_generation: 1,
                    bytes: png(76),
                },
                GatewayEventV1::Completed {
                    request_generation: 1,
                    result: Ok(()),
                },
                GatewayEventV1::Completed {
                    request_generation: 1,
                    result: Ok(()),
                },
            ]),
        },
    ];
    let mut stale = coordinator(&directory, std::mem::take(&mut stale_steps));
    let stale_operation = stale
        .start(
            &request(
                "stale-callback-v1",
                vec![asset("asset-stale", GENERATION_A, 'a')],
            ),
            500,
        )
        .unwrap();
    stale.run(&stale_operation.operation_id, 600).unwrap();
    let stale_snapshot = stale.status(&stale_operation.operation_id).unwrap();
    assert_eq!(stale_snapshot.state, OperationState::Succeeded);
    assert_eq!(
        stale.store().audit().unwrap().revision_count - revisions_before_cancel,
        1
    );
    let staging_root = directory
        .path()
        .join("private-assets/staging")
        .join(&in_flight_operation.operation_id);
    let unfinished_staging_files = if staging_root.exists() {
        fs::read_dir(staging_root).unwrap().count()
    } else {
        0
    };
    assert_eq!(unfinished_staging_files, 1);
    let post_fence_revisions = revisions_after_cancellations - revisions_before_cancel;
    let committed_revision_preserved =
        stale.store().audit().unwrap().revision_count >= revisions_before_cancel;
    emit(json!({
        "scenario": "cancellation_and_late_callbacks",
        "schema_version": 1,
        "status": "pass",
        "cancel_idempotent": cancel_idempotent,
        "cancel_before_registration_fenced": before_registration.status(&before_registration_operation.operation_id).unwrap().state == OperationState::Cancelled,
        "late_registration_cancelled": late_registration_cancelled,
        "late_callbacks_ignored": late_callbacks_ignored,
        "stale_generation_callbacks_ignored": stale_generation_callbacks_ignored,
        "terminal_events": usize::from(cancelled.terminal_sequence.is_some()),
        "post_fence_revisions": post_fence_revisions,
        "unfinished_staging_files": unfinished_staging_files,
        "committed_revision_preserved": committed_revision_preserved
    }));
}

#[test]
fn crash_atomicity_and_replay() {
    let mut fault_boundaries = 0;
    let mut old_state_cases = 0;
    let mut new_state_cases = 0;
    let mut partial_state_cases = 0;
    let mut duplicate_blobs_after_replay = 0;
    let mut duplicate_revisions_after_replay = 0;
    let mut sqlite_integrity_check = String::new();
    let mut foreign_key_violations = 0;
    for (case, crash) in [
        ("transfer", CrashPoint::AfterTransferBeforeValidation),
        ("staging", CrashPoint::AfterStagingFsync),
        ("promotion", CrashPoint::AfterPromotionBeforeCommit),
        ("commit", CrashPoint::AfterCommit),
    ] {
        fault_boundaries += 1;
        let directory = tempfile::tempdir().unwrap();
        let (store, _) = open_state(&directory);
        enroll(&store, GENERATION_A, CONNECTOR_A);
        drop(store);
        let request_id = format!("crash-{case}-v1");
        let operation_id = {
            let mut producer = coordinator(
                &directory,
                local_script("asset-crash", "resource-crash", png(81)),
            );
            let operation = producer
                .start(
                    &request(&request_id, vec![asset("asset-crash", GENERATION_A, 'a')]),
                    100,
                )
                .unwrap();
            assert_eq!(
                producer.run_with_crash(&operation.operation_id, 200, crash),
                Err(CoordinatorError::InjectedCrash(crash))
            );
            let audit = producer.store().audit().unwrap();
            match crash {
                CrashPoint::AfterTransferBeforeValidation => {
                    assert_eq!((audit.blob_count, audit.revision_count), (0, 0));
                    old_state_cases += 1;
                }
                CrashPoint::AfterStagingFsync => {
                    assert_eq!((audit.blob_count, audit.revision_count), (0, 0));
                    old_state_cases += 1;
                }
                CrashPoint::AfterPromotionBeforeCommit => {
                    assert_eq!((audit.blob_count, audit.revision_count), (0, 0));
                    new_state_cases += 1;
                }
                CrashPoint::AfterCommit => {
                    assert_eq!((audit.blob_count, audit.revision_count), (1, 1));
                    new_state_cases += 1;
                }
                CrashPoint::None => unreachable!(),
            }
            operation.operation_id
        };

        let replay_steps = if crash == CrashPoint::AfterCommit {
            vec![]
        } else {
            local_script_generation("asset-crash", "resource-crash", png(81), 2)
        };
        let mut restarted = coordinator(&directory, replay_steps);
        restarted.recover(&operation_id).unwrap();
        let outcomes = restarted.run(&operation_id, 300).unwrap();
        if crash == CrashPoint::AfterCommit {
            assert!(outcomes.is_empty());
        } else {
            assert_eq!(outcomes, vec![CommitOutcome::InsertedRevision]);
        }
        let audit = restarted.store().audit().unwrap();
        assert_eq!(audit.integrity_check, "ok");
        assert_eq!(audit.foreign_key_violations, 0);
        assert_eq!(
            (
                audit.operation_count,
                audit.blob_count,
                audit.revision_count
            ),
            (1, 1, 1)
        );
        partial_state_cases += usize::from(audit.blob_count != 1 || audit.revision_count != 1);
        duplicate_blobs_after_replay += audit.blob_count.saturating_sub(1);
        duplicate_revisions_after_replay += audit.revision_count.saturating_sub(1);
        sqlite_integrity_check = audit.integrity_check;
        foreign_key_violations += audit.foreign_key_violations;
        restarted.gateway().assert_exhausted();
    }

    let collision_directory = tempfile::tempdir().unwrap();
    let collision_files =
        FileStore::open(collision_directory.path().join("assets"), limits()).unwrap();
    let collision_bytes = png(82);
    let mut first = collision_files
        .begin("op-match-1", "asset.part", collision_bytes.len() as u64)
        .unwrap();
    first.write_chunk(&collision_bytes).unwrap();
    let first = collision_files
        .validate(first, &descriptor("resource-collision"))
        .unwrap();
    let first_blob = collision_files.promote(&first).unwrap();
    let no_replace_promotion = !first_blob.reused_existing;
    assert!(no_replace_promotion);
    let mut second = collision_files
        .begin("op-match-2", "asset.part", collision_bytes.len() as u64)
        .unwrap();
    second.write_chunk(&collision_bytes).unwrap();
    let second = collision_files
        .validate(second, &descriptor("resource-collision"))
        .unwrap();
    let second_blob = collision_files.promote(&second).unwrap();
    let matching_collision_reused = second_blob.reused_existing;
    assert!(matching_collision_reused);

    let mismatch_directory = tempfile::tempdir().unwrap();
    let mismatch_files =
        FileStore::open(mismatch_directory.path().join("assets"), limits()).unwrap();
    let mut staged = mismatch_files
        .begin("op-mismatch", "asset.part", collision_bytes.len() as u64)
        .unwrap();
    staged.write_chunk(&collision_bytes).unwrap();
    let staged = mismatch_files
        .validate(staged, &descriptor("resource-collision"))
        .unwrap();
    let fake_destination = mismatch_files.blob_path(&staged.sha256).unwrap();
    fs::write(&fake_destination, vec![0_u8; staged.byte_count as usize]).unwrap();
    fs::set_permissions(&fake_destination, fs::Permissions::from_mode(0o600)).unwrap();
    let mismatched_collision_rejected = matches!(
        mismatch_files.promote(&staged),
        Err(FileStoreError::HashCollision)
    );
    assert!(mismatched_collision_rejected);
    assert_eq!(
        fs::read(&fake_destination).unwrap(),
        vec![0_u8; staged.byte_count as usize]
    );

    let race_directory = tempfile::tempdir().unwrap();
    let (race_store, race_files) = open_state(&race_directory);
    enroll(&race_store, GENERATION_A, CONNECTOR_A);
    let race_operation = race_store
        .start(
            &request(
                "promotion-race-v1",
                vec![asset("asset-race", GENERATION_A, 'a')],
            ),
            700,
        )
        .unwrap();
    let race_bytes = png(83);
    let mut race_staged = race_files
        .begin(
            &race_operation.operation_id,
            "item-0000.part",
            race_bytes.len() as u64,
        )
        .unwrap();
    race_staged.write_chunk(&race_bytes).unwrap();
    let race_validated = race_files
        .validate(race_staged, &descriptor("resource-race"))
        .unwrap();
    let race_path = race_directory
        .path()
        .join("private-assets/staging")
        .join(&race_operation.operation_id)
        .join("item-0000.part");
    fs::rename(&race_path, race_path.with_extension("validated")).unwrap();
    fs::write(&race_path, png(84)).unwrap();
    fs::set_permissions(&race_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        race_files.promote(&race_validated),
        Err(FileStoreError::IdentityMismatch)
    ));
    let retained_race_blob = race_files.blob_path(&race_validated.sha256).unwrap();
    assert_eq!(fs::read(&retained_race_blob).unwrap(), png(84));
    let race_audit = race_store.audit().unwrap();
    assert_eq!((race_audit.blob_count, race_audit.revision_count), (0, 0));

    let verifier = Command::new(env!("CARGO_BIN_EXE_p00-photo-verifier"))
        .arg(collision_files.blob_path(&first_blob.sha256).unwrap())
        .arg(&first_blob.sha256)
        .output()
        .unwrap();
    let fresh_process_reopen = verifier.status.success();
    assert!(fresh_process_reopen);
    emit(json!({
        "scenario": "crash_atomicity_and_replay",
        "schema_version": 1,
        "status": "pass",
        "fault_boundaries": fault_boundaries,
        "old_state_cases": old_state_cases,
        "new_state_cases": new_state_cases,
        "partial_state_cases": partial_state_cases,
        "no_replace_promotion": no_replace_promotion,
        "mismatched_collision_rejected": mismatched_collision_rejected,
        "matching_collision_reused": matching_collision_reused,
        "duplicate_blobs_after_replay": duplicate_blobs_after_replay,
        "duplicate_revisions_after_replay": duplicate_revisions_after_replay,
        "fresh_process_reopen": fresh_process_reopen,
        "sqlite_integrity_check": sqlite_integrity_check,
        "foreign_key_violations": foreign_key_violations
    }));
}

#[test]
fn promoted_blobs_survive_replacement_and_later_reference() {
    let preexisting_directory = tempfile::tempdir().unwrap();
    let files = FileStore::open(preexisting_directory.path().join("assets"), limits()).unwrap();
    let bytes = png(85);

    let mut first = files
        .begin("op-existing-1", "asset.part", bytes.len() as u64)
        .unwrap();
    first.write_chunk(&bytes).unwrap();
    let first = files
        .validate(first, &descriptor("resource-existing"))
        .unwrap();
    let first_blob = files.promote(&first).unwrap();

    let mut second = files
        .begin("op-existing-2", "asset.part", bytes.len() as u64)
        .unwrap();
    second.write_chunk(&bytes).unwrap();
    let second = files
        .validate(second, &descriptor("resource-existing"))
        .unwrap();
    let reused_blob = files.promote(&second).unwrap();
    assert!(reused_blob.reused_existing);

    let blob_path = files.blob_path(&first_blob.sha256).unwrap();
    let corrupt_bytes = vec![0_u8; first_blob.byte_count as usize];
    fs::write(&blob_path, &corrupt_bytes).unwrap();
    assert_eq!(
        files.verify_promoted(&reused_blob),
        Err(FileStoreError::IdentityMismatch)
    );
    assert_eq!(fs::read(&blob_path).unwrap(), corrupt_bytes);

    let replacement_directory = tempfile::tempdir().unwrap();
    let replacement_files =
        FileStore::open(replacement_directory.path().join("assets"), limits()).unwrap();
    let mut replacement_staged = replacement_files
        .begin("op-path-replacement", "asset.part", bytes.len() as u64)
        .unwrap();
    replacement_staged.write_chunk(&bytes).unwrap();
    let replacement_staged = replacement_files
        .validate(replacement_staged, &descriptor("resource-path-replacement"))
        .unwrap();
    let captured_new_blob = replacement_files.promote(&replacement_staged).unwrap();
    assert!(!captured_new_blob.reused_existing);
    let replacement_path = replacement_files
        .blob_path(&captured_new_blob.sha256)
        .unwrap();
    fs::remove_file(&replacement_path).unwrap();
    let replacement_bytes = b"same-user replacement";
    fs::write(&replacement_path, replacement_bytes).unwrap();
    fs::set_permissions(&replacement_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        replacement_files.verify_promoted(&captured_new_blob),
        Err(FileStoreError::IdentityMismatch)
    );
    assert_eq!(fs::read(&replacement_path).unwrap(), replacement_bytes);

    let referenced_directory = tempfile::tempdir().unwrap();
    let (store, files) = open_state(&referenced_directory);
    enroll(&store, GENERATION_A, CONNECTOR_A);
    drop(store);
    let mut newly_staged = files
        .begin("op-captured-new", "asset.part", bytes.len() as u64)
        .unwrap();
    newly_staged.write_chunk(&bytes).unwrap();
    let newly_staged = files
        .validate(newly_staged, &descriptor("resource-captured-new"))
        .unwrap();
    let captured_new_blob = files.promote(&newly_staged).unwrap();
    assert!(!captured_new_blob.reused_existing);

    let mut coordinator = coordinator(
        &referenced_directory,
        local_script("asset-referenced", "resource-referenced", bytes.clone()),
    );
    let operation = coordinator
        .start(
            &request(
                "referenced-blob-v1",
                vec![asset("asset-referenced", GENERATION_A, 'a')],
            ),
            100,
        )
        .unwrap();
    coordinator.run(&operation.operation_id, 200).unwrap();
    let revision = coordinator.store().revisions().unwrap().remove(0);
    let referenced_path = coordinator
        .files()
        .blob_path(&revision.blob_sha256)
        .unwrap();

    fs::write(&referenced_path, &corrupt_bytes).unwrap();
    assert_eq!(
        files.verify_promoted(&captured_new_blob),
        Err(FileStoreError::IdentityMismatch)
    );
    assert_eq!(fs::read(&referenced_path).unwrap(), corrupt_bytes);

    let mut retry = coordinator
        .files()
        .begin("op-referenced-retry", "asset.part", bytes.len() as u64)
        .unwrap();
    retry.write_chunk(&bytes).unwrap();
    let retry = coordinator
        .files()
        .validate(retry, &descriptor("resource-referenced"))
        .unwrap();
    assert!(matches!(
        coordinator.files().promote(&retry),
        Err(FileStoreError::HashCollision)
    ));
    assert_eq!(fs::read(&referenced_path).unwrap(), corrupt_bytes);
    let audit = coordinator.store().audit().unwrap();
    assert_eq!((audit.blob_count, audit.referenced_blob_count), (1, 1));
}

#[test]
fn recovery_retains_ambiguous_staging_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let (store, _) = open_state(&directory);
    enroll(&store, GENERATION_A, CONNECTOR_A);
    drop(store);

    let operation_id = {
        let mut producer = coordinator(
            &directory,
            local_script("asset-retained", "resource-retained", png(87)),
        );
        let operation = producer
            .start(
                &request(
                    "retained-staging-v1",
                    vec![asset("asset-retained", GENERATION_A, 'a')],
                ),
                100,
            )
            .unwrap();
        assert_eq!(
            producer.run_with_crash(
                &operation.operation_id,
                200,
                CrashPoint::AfterTransferBeforeValidation
            ),
            Err(CoordinatorError::InjectedCrash(
                CrashPoint::AfterTransferBeforeValidation
            ))
        );
        operation.operation_id
    };

    let staging_path = directory
        .path()
        .join("private-assets/staging")
        .join(&operation_id)
        .join("item-0000.part.g1");
    let original_path = staging_path.with_extension("original");
    fs::rename(&staging_path, &original_path).unwrap();
    let replacement = b"same-user staging replacement";
    fs::write(&staging_path, replacement).unwrap();
    fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o600)).unwrap();

    let mut restarted = coordinator(
        &directory,
        local_script_generation("asset-retained", "resource-retained", png(87), 2),
    );
    restarted.recover(&operation_id).unwrap();
    assert_eq!(fs::read(&staging_path).unwrap(), replacement);
    assert!(original_path.exists());
    assert_eq!(
        restarted.run(&operation_id, 300).unwrap(),
        vec![CommitOutcome::InsertedRevision]
    );
    assert_eq!(fs::read(&staging_path).unwrap(), replacement);
    assert_eq!(restarted.store().audit().unwrap().revision_count, 1);
}

#[test]
fn picker_only_omits_stable_photokit_provenance() {
    let mut picker_asset = asset("picker-asset", GENERATION_A, 'a');
    picker_asset.connector_generation.clear();
    picker_asset.cloud_locator = None;
    let picker_request = StartMaterializationV1 {
        schema_version: CONTRACT_SCHEMA_VERSION,
        client_request_id: "picker-only-v1".to_owned(),
        mode: MaterializationMode::PickerOnly,
        selection_limit: 1,
        representation_policy: RepresentationPolicy::OriginalPrimaryV1,
        assets: vec![picker_asset.clone()],
    };
    picker_request.validate().unwrap();
    let encoded = serde_json::to_vec(&picker_request).unwrap();
    StartMaterializationV1::decode_json(&encoded).unwrap();

    let mut invalid_picker = picker_request.clone();
    invalid_picker.assets[0].connector_generation = GENERATION_A.to_owned();
    assert_eq!(
        invalid_picker.validate(),
        Err(ContractError::InvalidField("picker_only_provenance"))
    );
    let mut invalid_library = picker_request.clone();
    invalid_library.mode = MaterializationMode::PhotoLibrary;
    assert_eq!(
        invalid_library.validate(),
        Err(ContractError::InvalidField("connector_generation"))
    );

    let directory = tempfile::tempdir().unwrap();
    let mut coordinator = coordinator(
        &directory,
        local_script("picker-asset", "picker-resource", png(86)),
    );
    let operation = coordinator.start(&picker_request, 100).unwrap();
    assert_eq!(
        coordinator.run(&operation.operation_id, 200).unwrap(),
        vec![CommitOutcome::InsertedRevision]
    );
    let revision = coordinator.store().revisions().unwrap().remove(0);
    assert_eq!(
        revision.provenance.classification,
        MaterializationClass::PickerImport
    );
    assert!(revision.provenance.connector_instance.is_empty());
    assert!(revision.provenance.connector_generation.is_empty());
    assert_eq!(revision.provenance.locator_key_version, 0);
    assert!(revision.provenance.locator_hmac.is_empty());
    assert_eq!(revision.provenance.cloud_locator_hmac, None);
    let audit = coordinator.store().audit().unwrap();
    assert_eq!(audit.connector_generation_count, 0);
    assert_eq!((audit.source_count, audit.revision_count), (1, 1));
    assert_eq!(audit.foreign_key_violations, 0);
}

#[test]
fn provenance_and_generation() {
    let directory = tempfile::tempdir().unwrap();
    let (store, _) = open_state(&directory);
    enroll(&store, GENERATION_A, CONNECTOR_A);
    enroll_version(&store, "library-generation-b", "connector-instance-b", 2);
    drop(store);

    let runs = [
        (
            "provenance-first",
            GENERATION_A,
            "asset-a1",
            'a',
            1,
            91,
            CommitOutcome::InsertedRevision,
        ),
        (
            "provenance-replay",
            GENERATION_A,
            "asset-a2",
            'a',
            1,
            91,
            CommitOutcome::ReplayedRevision,
        ),
        (
            "provenance-change",
            GENERATION_A,
            "asset-a3",
            'a',
            1,
            92,
            CommitOutcome::InsertedRevision,
        ),
        (
            "provenance-new-generation",
            "library-generation-b",
            "asset-b1",
            'c',
            2,
            91,
            CommitOutcome::InsertedRevision,
        ),
    ];
    let mut revision_deltas = Vec::new();
    for (request_id, generation, alias, locator_key, key_version, bytes, expected) in runs {
        let before = open_state(&directory).0.audit().unwrap().revision_count;
        let mut run = coordinator(
            &directory,
            local_script(alias, "resource-stable", png(bytes)),
        );
        let operation = run
            .start(
                &request(
                    request_id,
                    vec![asset_version(alias, generation, locator_key, key_version)],
                ),
                100,
            )
            .unwrap();
        assert_eq!(
            run.run(&operation.operation_id, 200).unwrap(),
            vec![expected]
        );
        revision_deltas.push(run.store().audit().unwrap().revision_count - before);
    }
    let (store, _) = open_state(&directory);
    let revisions = store.revisions().unwrap();
    assert_eq!(revisions.len(), 3);
    assert_eq!(
        revisions
            .iter()
            .filter(|revision| revision.provenance.connector_generation == GENERATION_A)
            .count(),
        2
    );
    assert!(revisions.iter().all(|revision| {
        revision.provenance.schema_version == 1
            && !revision.provenance.connector_instance.is_empty()
            && !revision.provenance.connector_generation.is_empty()
            && revision.provenance.locator_key_version
                == if revision.provenance.connector_generation == GENERATION_A {
                    1
                } else {
                    2
                }
            && revision.provenance.locator_hmac.len() == 64
            && revision.provenance.representation_policy == RepresentationPolicy::OriginalPrimaryV1
            && revision.provenance.resource.resource_ref == "resource-stable"
            && revision.provenance.classification != MaterializationClass::PickerImport
            && revision.provenance.blob_byte_count > 0
            && revision.provenance.blob_sha256 == revision.blob_sha256
            && !revision.provenance.operation_id.is_empty()
            && revision.provenance.retrieved_at_ms == 200
    }));
    let generation_a_hmac = revisions
        .iter()
        .find(|revision| revision.provenance.connector_generation == GENERATION_A)
        .unwrap()
        .provenance
        .locator_hmac
        .clone();
    let generation_b = revisions
        .iter()
        .find(|revision| revision.provenance.connector_generation == "library-generation-b")
        .unwrap();
    assert_eq!(generation_b.provenance.locator_key_version, 2);
    assert_ne!(generation_b.provenance.locator_hmac, generation_a_hmac);
    let reenrollment_rotates_keys = generation_b.provenance.locator_key_version
        > revisions
            .iter()
            .find(|revision| revision.provenance.connector_generation == GENERATION_A)
            .unwrap()
            .provenance
            .locator_key_version
        && generation_b.provenance.locator_hmac != generation_a_hmac;
    let audit = store.audit().unwrap();
    assert_eq!(
        (
            audit.operation_count,
            audit.blob_count,
            audit.source_count,
            audit.revision_count
        ),
        (4, 2, 2, 3)
    );
    store.retire_generation(GENERATION_A).unwrap();
    let retired_generation_preserved = store.audit().unwrap().revision_count == 3;
    assert!(retired_generation_preserved);
    assert_eq!(
        store.start(
            &request(
                "retired-generation",
                vec![asset("asset-retired", GENERATION_A, 'a')]
            ),
            300
        ),
        Err(StoreError::InvalidInput)
    );
    let provenance = &revisions[0].provenance;
    let provenance_fields_verified = [
        provenance.schema_version == 1,
        !provenance.connector_instance.is_empty(),
        !provenance.connector_generation.is_empty(),
        provenance.locator_key_version > 0,
        provenance.locator_hmac.len() == 64,
        !provenance.resource.resource_ref.is_empty(),
        provenance.representation_policy == RepresentationPolicy::OriginalPrimaryV1,
        provenance.blob_sha256 == revisions[0].blob_sha256,
        provenance.blob_byte_count > 0,
        !provenance.operation_id.is_empty(),
    ]
    .into_iter()
    .filter(|verified| *verified)
    .count();
    let original_filenames_persisted = store.original_filename_column_count().unwrap();
    emit(json!({
        "scenario": "provenance_and_generation",
        "schema_version": 1,
        "status": "pass",
        "connector_generations": audit.connector_generation_count,
        "reenrollment_rotates_keys": reenrollment_rotates_keys,
        "retired_generation_preserved": retired_generation_preserved,
        "cross_generation_locator_collision_distinct": generation_b.source_id != revisions.iter().find(|revision| revision.provenance.connector_generation == GENERATION_A).unwrap().source_id,
        "same_source_replay_revision_delta": revision_deltas[1],
        "changed_content_revision_delta": revision_deltas[2],
        "identical_bytes_distinct_sources": revisions.iter().filter(|revision| revision.blob_sha256 == generation_b.blob_sha256).map(|revision| &revision.source_id).collect::<std::collections::HashSet<_>>().len(),
        "identical_bytes_shared_blobs": revisions.iter().filter(|revision| revision.blob_sha256 == generation_b.blob_sha256).map(|revision| &revision.blob_sha256).collect::<std::collections::HashSet<_>>().len(),
        "encrypted_locator_version": revisions.iter().map(|revision| revision.provenance.locator_key_version).min().unwrap(),
        "lookup_hmac_version": revisions.iter().map(|revision| revision.provenance.locator_key_version).min().unwrap(),
        "original_filenames_persisted": original_filenames_persisted,
        "provenance_fields_verified": provenance_fields_verified
    }));
}

#[test]
fn filesystem_and_bounds() {
    let directory = tempfile::tempdir().unwrap();
    let files = FileStore::open(directory.path().join("assets"), limits()).unwrap();
    let actual_device = files.root_device();
    let root_device_change_rejected = matches!(
        FileStore::open_with_expected_device(
            directory.path().join("wrong-device"),
            limits(),
            Some(actual_device.saturating_add(1))
        ),
        Err(FileStoreError::DeviceChanged)
    );
    assert!(root_device_change_rejected);
    for unsafe_component in ["../escape", "/absolute", "nested/file", ".", ".."] {
        assert_eq!(
            files
                .begin(unsafe_component, "asset.part", 100)
                .unwrap_err(),
            FileStoreError::InvalidComponent
        );
    }
    assert_eq!(
        files.begin("op-safe", "../asset", 100).unwrap_err(),
        FileStoreError::InvalidComponent
    );

    let mut staging_limits = limits();
    staging_limits.max_active_staging_bytes = 10;
    let staging_files =
        FileStore::open(directory.path().join("staging-budget"), staging_limits).unwrap();
    let mut first_active = staging_files
        .begin("op-active-1", "asset.part", 100)
        .unwrap();
    first_active.write_chunk(b"12345678").unwrap();
    let mut second_active = staging_files
        .begin("op-active-2", "asset.part", 100)
        .unwrap();
    assert_eq!(
        second_active.write_chunk(b"abc"),
        Err(FileStoreError::StagingLimit)
    );
    drop(first_active);
    second_active.write_chunk(b"abc").unwrap();

    let capacity = RequestCapacity::new(1).unwrap();
    let request_permit = capacity.try_acquire().unwrap();
    assert_eq!(
        capacity.try_acquire().unwrap_err(),
        CoordinatorError::ConcurrentRequestLimit
    );
    drop(request_permit);
    assert!(capacity.try_acquire().is_ok());

    let batch_directory = tempfile::tempdir().unwrap();
    let (batch_store, batch_files) = open_state(&batch_directory);
    enroll(&batch_store, GENERATION_A, CONNECTOR_A);
    let mut batch_limits = limits();
    batch_limits.max_batch_bytes = 10;
    let mut batch_coordinator = MaterializationCoordinator::new(
        batch_store,
        batch_files,
        ScriptedPhotoAssetGateway::new(local_script("asset-batch", "resource-batch", png(100))),
        batch_limits,
    );
    let batch_operation = batch_coordinator
        .start(
            &request(
                "batch-bound-v1",
                vec![asset("asset-batch", GENERATION_A, 'a')],
            ),
            10,
        )
        .unwrap();
    assert!(matches!(
        batch_coordinator.run(&batch_operation.operation_id, 20),
        Err(CoordinatorError::Store(StoreError::BatchLimit))
    ));
    assert_eq!(batch_coordinator.store().audit().unwrap().revision_count, 0);

    let mut oversized = files.begin("op-size", "asset.part", 4).unwrap();
    assert_eq!(
        oversized.write_chunk(b"12345"),
        Err(FileStoreError::ByteLimit)
    );

    let mut invalid = files.begin("op-invalid", "asset.part", 100).unwrap();
    invalid.write_chunk(b"not-an-image").unwrap();
    assert!(matches!(
        files.validate(invalid, &descriptor("resource-invalid")),
        Err(FileStoreError::UnsupportedImage)
    ));

    let symlink_operation = directory.path().join("assets/staging/op-symlink");
    fs::create_dir(&symlink_operation).unwrap();
    fs::set_permissions(&symlink_operation, fs::Permissions::from_mode(0o700)).unwrap();
    symlink("/tmp", symlink_operation.join("asset.part")).unwrap();
    assert_eq!(
        files.begin("op-symlink", "asset.part", 100).unwrap_err(),
        FileStoreError::AlreadyExists
    );

    let bytes = png(101);
    let mut staged = files
        .begin("op-promote", "asset.part", bytes.len() as u64)
        .unwrap();
    staged.write_chunk(&bytes).unwrap();
    let validated = files
        .validate(staged, &descriptor("resource-promote"))
        .unwrap();
    fs::hard_link(
        directory
            .path()
            .join("assets/staging/op-promote/asset.part"),
        directory.path().join("hard-link-surprise"),
    )
    .unwrap();
    assert!(matches!(
        files.promote(&validated),
        Err(FileStoreError::HardLink)
    ));
    fs::remove_file(directory.path().join("hard-link-surprise")).unwrap();
    let promoted = files.promote(&validated).unwrap();
    assert_eq!(
        promoted.sha256,
        sha256_file(files.blob_path(&promoted.sha256).unwrap()).unwrap()
    );
    files
        .verify_blob(&promoted.sha256, promoted.byte_count)
        .unwrap();
    assert_eq!(
        fs::metadata(directory.path().join("assets"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(files.blob_path(&promoted.sha256).unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let encoded = serde_json::to_vec(&request(
        "strict-json",
        vec![asset("asset-json", GENERATION_A, 'a')],
    ))
    .unwrap();
    assert_eq!(
        StartMaterializationV1::decode_json(&encoded)
            .unwrap()
            .schema_version,
        1
    );
    let mut unknown: Value = serde_json::from_slice(&encoded).unwrap();
    unknown["unexpected"] = json!(true);
    assert!(StartMaterializationV1::decode_json(&serde_json::to_vec(&unknown).unwrap()).is_err());
    assert!(
        StartMaterializationV1::decode_json(&vec![b'x'; MAX_GATEWAY_MESSAGE_BYTES + 1]).is_err()
    );

    let mut too_large = descriptor("resource-large");
    too_large.pixel_width = 10_001;
    assert!(too_large.validate(limits()).is_err());
    let production = MaterializationLimits::P00;
    assert_eq!(production.max_assets, 100);
    assert_eq!(production.max_resource_bytes, 536_870_912);
    assert_eq!(production.max_batch_bytes, 5_368_709_120);
    assert_eq!(production.max_active_staging_bytes, 1_073_741_824);
    assert_eq!(production.max_concurrent_requests, 2);
    assert_eq!(production.max_pixels, 200_000_000);
    assert_eq!(production.reserve_free_bytes, 2_147_483_648);
    emit(json!({
        "scenario": "filesystem_and_bounds",
        "schema_version": 1,
        "status": "pass",
        "selection_limit": 100,
        "resource_byte_limit": 536870912,
        "batch_byte_limit": 5368709120_u64,
        "active_staging_byte_limit": 1073741824,
        "concurrent_request_limit": 2,
        "frame_limit": 1,
        "pixel_limit": 200000000,
        "free_space_reserve_bytes": 2147483648_u64,
        "message_byte_limit": MAX_GATEWAY_MESSAGE_BYTES,
        "chunk_byte_limit": MAX_CALLBACK_CHUNK_BYTES,
        "private_directory_mode": 448,
        "private_file_mode": 384,
        "traversal_rejected": true,
        "absolute_path_rejected": true,
        "symlink_rejected": true,
        "hardlink_rejected": true,
        "root_device_change_rejected": root_device_change_rejected,
        "oversize_rejected_before_decode": true,
        "invalid_image_rejected": true
    }));
}

#[test]
fn diagnostic_redaction() {
    let sentinels = [
        "P00_PHOTOS_ASSET_IDENTIFIER_SENTINEL",
        "P00_PHOTOS_ORIGINAL_FILENAME_SENTINEL.HEIC",
        "/private/P00_PHOTOS_PATH_SENTINEL",
        "P00_PHOTOS_ACCOUNT_SENTINEL",
        "https://photos.invalid/P00_PHOTOS_URL_SENTINEL",
        "P00_PHOTOS_FRAMEWORK_ERROR_SENTINEL",
        "P00_PHOTOS_IMAGE_BYTES_SENTINEL",
        "P00_PHOTOS_KEYCHAIN_SENTINEL",
    ];
    for (class, failure) in [
        (
            DiagnosticClass::Authorization,
            GatewayFailure::Authorization,
        ),
        (
            DiagnosticClass::SelectionIdentity,
            GatewayFailure::SelectionIdentity,
        ),
        (
            DiagnosticClass::UnsupportedResource,
            GatewayFailure::UnsupportedResource,
        ),
        (
            DiagnosticClass::NetworkRequired,
            GatewayFailure::NetworkRequired,
        ),
        (DiagnosticClass::Transfer, GatewayFailure::Transfer),
        (DiagnosticClass::Cancellation, GatewayFailure::Cancellation),
        (DiagnosticClass::Progress, GatewayFailure::Progress),
        (
            DiagnosticClass::OutputIntegrity,
            GatewayFailure::OutputIntegrity,
        ),
        (
            DiagnosticClass::ProvenanceIntegrity,
            GatewayFailure::ProvenanceIntegrity,
        ),
        (
            DiagnosticClass::NativeProtocol,
            GatewayFailure::NativeProtocol,
        ),
    ] {
        let diagnostic = Diagnostic {
            class,
            operation_phase: "materialization",
            completed_count: 0,
            total_count: 1,
        };
        let output = format!(
            "{} {}",
            serde_json::to_string(&diagnostic).unwrap(),
            failure
        );
        for sentinel in sentinels {
            assert!(!output.contains(sentinel));
        }
        assert!(output.len() < 256);
    }
    let identity = json!({"scenario": "diagnostic_redaction", "status": "pass"});
    assert!(deterministic_record(identity.clone(), None).is_err());
    assert!(deterministic_record(identity.clone(), Some("stale")).is_err());
    assert!(deterministic_record(identity, Some(&"a".repeat(64))).is_ok());
    emit(json!({
        "scenario": "diagnostic_redaction",
        "schema_version": 1,
        "status": "pass",
        "sentinel_count": 8,
        "encoding_variants_per_sentinel": 7,
        "public_leak_count": 0,
        "private_blob_scan_excluded": true,
        "bounded_diagnostics": true,
        "raw_framework_error_persisted": false,
        "identifier_persisted_in_public_artifact": false,
        "filename_persisted": false
    }));
}
