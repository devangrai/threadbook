use rusqlite::{params, Connection};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use uuid::Uuid;
use wardrobe_core::{
    CatalogPort, DeletionConfirmationV1, DeletionPort, DeletionTargetKindV1,
    DisablePhotoKitV1Request, ExecuteDeletionV1Request, PhotoKitAuthorizationV1,
    PhotoKitAvailabilityReasonV1, PhotoKitReconcileTriggerV1, PreviewDeletionV1Request, RequestId,
    SCHEMA_VERSION_V1,
};
use wardrobe_platform::{
    BlobStore, Database, MaintenanceCoordinator, PhotoKitCoordinator, PhotoKitCoordinatorError,
    PhotoKitEnumerationSink, PhotoKitEnumerationTerminal, PhotoKitKeyError, PhotoKitKeyPort,
    PhotoKitNativeAsset, PhotoKitNativeByteSink, PhotoKitNativeError, PhotoKitNativePort,
    PhotoKitNativeResource, PhotoKitRepository, PhotoKitRootKey, PhotoKitTransferTerminal,
    PhotoKitValidatedImage, PlatformError, PrivateAppPaths,
};

#[derive(Clone, Default)]
struct TestKeys {
    values: Arc<Mutex<BTreeMap<String, [u8; 32]>>>,
}

impl TestKeys {
    fn remove_all(&self) {
        self.values.lock().unwrap().clear();
    }
}

impl PhotoKitKeyPort for TestKeys {
    fn create_root_key(&self, key_reference: &str) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
        let bytes = [0x5a; 32];
        self.values
            .lock()
            .unwrap()
            .insert(key_reference.to_owned(), bytes);
        Ok(PhotoKitRootKey::from_bytes(bytes))
    }

    fn load_root_key(
        &self,
        key_reference: &str,
        allow_authentication_ui: bool,
    ) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
        assert!(!allow_authentication_ui);
        self.values
            .lock()
            .unwrap()
            .get(key_reference)
            .copied()
            .map(PhotoKitRootKey::from_bytes)
            .ok_or(PhotoKitKeyError::NotFound)
    }

    fn delete_root_key(&self, key_reference: &str) -> Result<(), PhotoKitKeyError> {
        self.values.lock().unwrap().remove(key_reference);
        Ok(())
    }
}

#[derive(Clone)]
struct EnumerationScript {
    authorization: PhotoKitAuthorizationV1,
    terminal: PhotoKitEnumerationTerminal,
    assets: Vec<PhotoKitNativeAsset>,
}

struct TransferScript {
    token: &'static str,
    network: bool,
    terminal: PhotoKitTransferTerminal,
    chunks: Vec<Vec<u8>>,
}

#[derive(Default)]
struct ScriptedNative {
    enumerations: VecDeque<EnumerationScript>,
    transfers: VecDeque<TransferScript>,
    active: Option<EnumerationScript>,
    calls: Vec<String>,
    transfer_started: Option<mpsc::Sender<()>>,
    transfer_resume: Option<mpsc::Receiver<()>>,
}

impl ScriptedNative {
    fn push_enumeration(&mut self, script: EnumerationScript) {
        self.enumerations.push_back(script);
    }

    fn push_transfer(&mut self, script: TransferScript) {
        self.transfers.push_back(script);
    }
}

impl PhotoKitNativePort for ScriptedNative {
    fn authorization(
        &mut self,
        request_authorization: bool,
    ) -> Result<PhotoKitAuthorizationV1, PhotoKitNativeError> {
        assert!(!request_authorization);
        let script = self
            .enumerations
            .pop_front()
            .ok_or(PhotoKitNativeError::InvalidResponse)?;
        let authorization = script.authorization;
        self.active = Some(script);
        self.calls.push(format!("authorization:{authorization:?}"));
        Ok(authorization)
    }

    fn enumerate_regular_album(
        &mut self,
        album_locator: &str,
        _operation: &wardrobe_platform::PhotoKitOperation,
        sink: &mut dyn PhotoKitEnumerationSink,
    ) -> Result<PhotoKitEnumerationTerminal, PhotoKitNativeError> {
        assert_eq!(album_locator, "album-private-id");
        let script = self
            .active
            .take()
            .ok_or(PhotoKitNativeError::InvalidResponse)?;
        self.calls.push("enumerate".to_owned());
        for asset in script.assets {
            sink.observe(asset)
                .map_err(|_| PhotoKitNativeError::SinkRejected)?;
        }
        Ok(script.terminal)
    }

    fn transfer_resource(
        &mut self,
        _operation: &wardrobe_platform::PhotoKitOperation,
        operation_resource_token: &str,
        network_access_allowed: bool,
        sink: &mut dyn PhotoKitNativeByteSink,
    ) -> Result<PhotoKitTransferTerminal, PhotoKitNativeError> {
        let script = self
            .transfers
            .pop_front()
            .ok_or(PhotoKitNativeError::InvalidResponse)?;
        if let Some(started) = self.transfer_started.take() {
            started
                .send(())
                .map_err(|_| PhotoKitNativeError::Cancelled)?;
        }
        if let Some(resume) = self.transfer_resume.take() {
            resume.recv().map_err(|_| PhotoKitNativeError::Cancelled)?;
        }
        assert_eq!(script.token, operation_resource_token);
        assert_eq!(script.network, network_access_allowed);
        for chunk in script.chunks {
            sink.write_chunk(&chunk)
                .map_err(|_| PhotoKitNativeError::SinkRejected)?;
        }
        self.calls.push(format!(
            "transfer:{operation_resource_token}:{network_access_allowed}"
        ));
        Ok(script.terminal)
    }

    fn validate_image(
        &mut self,
        duplicated_read_only_file: File,
        _resource_uti: &str,
    ) -> Result<PhotoKitValidatedImage, PhotoKitNativeError> {
        assert!(duplicated_read_only_file.metadata().unwrap().len() > 0);
        Ok(PhotoKitValidatedImage {
            pixel_width: 1,
            pixel_height: 1,
            frame_count: 1,
        })
    }
}

fn asset(locator: &str, token: &'static str) -> PhotoKitNativeAsset {
    PhotoKitNativeAsset {
        asset_locator: locator.to_owned(),
        primary_resource: Some(PhotoKitNativeResource {
            operation_resource_token: token.to_owned(),
            resource_uti: "public.jpeg".to_owned(),
        }),
    }
}

fn complete_transfer(token: &'static str, bytes: &[u8]) -> TransferScript {
    TransferScript {
        token,
        network: false,
        terminal: PhotoKitTransferTerminal::Complete,
        chunks: vec![bytes.to_vec()],
    }
}

fn request_id() -> String {
    Uuid::new_v4().hyphenated().to_string()
}

fn setup() -> (
    tempfile::TempDir,
    PrivateAppPaths,
    PhotoKitRepository,
    TestKeys,
) {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let database = Database::open(&paths, 1).unwrap();
    (
        temporary,
        paths,
        PhotoKitRepository::new(database),
        TestKeys::default(),
    )
}

#[test]
fn complete_generations_atomically_cover_missed_changes_duplicates_replay_and_incomplete_enumeration(
) {
    let (_temporary, paths, repository, keys) = setup();
    let mut native = ScriptedNative::default();
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Complete,
        assets: vec![asset("asset-a", "token-a1"), asset("asset-b", "token-b1")],
    });
    native.push_transfer(complete_transfer("token-a1", b"same-image"));
    native.push_transfer(complete_transfer("token-b1", b"same-image"));
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Complete,
        assets: vec![asset("asset-a", "token-a2")],
    });
    native.push_transfer(complete_transfer("token-a2", b"same-image"));
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Incomplete,
        assets: vec![asset("asset-c", "token-never-used")],
    });
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Denied,
        terminal: PhotoKitEnumerationTerminal::Incomplete,
        assets: vec![],
    });

    let mut coordinator = PhotoKitCoordinator::new(repository.clone(), native, keys.clone());
    coordinator
        .configure_scope("album-private-id", false, 10)
        .unwrap();
    let first_request = request_id();
    let first = coordinator
        .reconcile(&first_request, PhotoKitReconcileTriggerV1::Startup, 20)
        .unwrap();
    assert_eq!(first.membership_generation, Some(1));
    assert_eq!(first.transitions, 2);
    assert_eq!(first.snapshot.counts.available, 2);
    let first_revision = first.snapshot.photokit_revision.get();

    let connection = Connection::open(&paths.database).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1,
        "identical bytes share one CAS/blob row"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM photokit_materializations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2,
        "provider assets remain distinct materializations"
    );

    let second_request = request_id();
    let second = coordinator
        .reconcile(&second_request, PhotoKitReconcileTriggerV1::Startup, 30)
        .unwrap();
    assert_eq!(second.membership_generation, Some(2));
    assert_eq!(second.transitions, 1);
    assert_eq!(second.snapshot.photokit_revision.get(), first_revision + 1);
    assert_eq!(second.snapshot.counts.observed, 2);
    assert_eq!(second.snapshot.counts.available, 1);
    assert_eq!(second.snapshot.counts.unavailable, 1);
    assert_eq!(
        second
            .snapshot
            .availability_counts
            .iter()
            .map(|count| count.count)
            .sum::<u16>(),
        second.snapshot.counts.observed
    );
    assert!(second.snapshot.availability_counts.iter().any(|count| {
        count.reason == PhotoKitAvailabilityReasonV1::AssetNotInScope && count.count == 1
    }));
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*)
                 FROM photokit_availability_heads head
                 JOIN photokit_availability_revisions revision
                   ON revision.revision_id = head.revision_id
                 WHERE revision.reason = 'asset_not_in_scope'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    let revision_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM photokit_availability_revisions",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let replay = coordinator
        .reconcile(&second_request, PhotoKitReconcileTriggerV1::Startup, 31)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(
        coordinator
            .native()
            .calls
            .iter()
            .filter(|call| call.starts_with("authorization:"))
            .count(),
        2,
        "request replay must not consult the native port"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM photokit_availability_revisions",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        revision_count
    );

    let incomplete = coordinator
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::LibraryChange, 40)
        .unwrap();
    assert_eq!(incomplete.membership_generation, Some(2));
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM photokit_membership_generations",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM photokit_operation_observations
                    WHERE operation_id = ?1)
                   +(SELECT COUNT(*) FROM photokit_locator_records
                     WHERE operation_id = ?1 AND finalized = 0)",
                [&incomplete.operation_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );

    let denied = coordinator
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::Startup, 50)
        .unwrap();
    assert_eq!(
        denied.snapshot.authorization,
        PhotoKitAuthorizationV1::Denied
    );
    assert_eq!(denied.snapshot.counts.unavailable, 2);
    assert_eq!(
        denied
            .snapshot
            .availability_counts
            .iter()
            .map(|count| count.count)
            .sum::<u16>(),
        denied.snapshot.counts.observed
    );
    let exact_replay = coordinator
        .reconcile(&second_request, PhotoKitReconcileTriggerV1::Startup, 51)
        .unwrap();
    assert!(exact_replay.replayed);
    assert_eq!(
        exact_replay.snapshot.authorization,
        PhotoKitAuthorizationV1::Authorized,
        "replay returns the atomically stored terminal publication, not current state"
    );
    assert_eq!(exact_replay.snapshot, second.snapshot);
}

#[test]
fn denied_key_loss_and_album_loss_publish_exact_unavailable_transitions() {
    let (_temporary, paths, repository, keys) = setup();
    let mut native = ScriptedNative::default();
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Complete,
        assets: vec![asset("asset-a", "token-a")],
    });
    native.push_transfer(complete_transfer("token-a", b"image-a"));
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Denied,
        terminal: PhotoKitEnumerationTerminal::Incomplete,
        assets: vec![],
    });
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Denied,
        terminal: PhotoKitEnumerationTerminal::Incomplete,
        assets: vec![],
    });
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Complete,
        assets: vec![],
    });

    let mut coordinator = PhotoKitCoordinator::new(repository.clone(), native, keys.clone());
    coordinator
        .configure_scope("album-private-id", false, 10)
        .unwrap();
    coordinator
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::Startup, 20)
        .unwrap();
    let denied = coordinator
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::User, 30)
        .unwrap();
    assert_eq!(denied.transitions, 1);
    assert_eq!(denied.snapshot.counts.unavailable, 1);
    assert_eq!(
        denied.snapshot.availability_counts[0].reason,
        PhotoKitAvailabilityReasonV1::AuthorizationDenied
    );
    let revision = denied.snapshot.photokit_revision.get();

    let repeated = coordinator
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::User, 31)
        .unwrap();
    assert_eq!(repeated.transitions, 0);
    assert_eq!(repeated.snapshot.photokit_revision.get(), revision);

    keys.remove_all();
    let key_loss = coordinator
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::Startup, 40)
        .unwrap();
    assert_eq!(key_loss.transitions, 1);
    assert_eq!(
        key_loss.snapshot.availability_counts[0].reason,
        PhotoKitAvailabilityReasonV1::ScopeUnavailable
    );
    let connection = Connection::open(&paths.database).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM blobs", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1,
        "unavailable transitions never delete immutable blobs"
    );

    let (_temporary2, _paths2, repository2, keys2) = setup();
    let mut native2 = ScriptedNative::default();
    native2.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::AlbumUnavailable,
        assets: vec![],
    });
    let mut coordinator2 = PhotoKitCoordinator::new(repository2, native2, keys2);
    coordinator2
        .configure_scope("album-private-id", false, 10)
        .unwrap();
    let album_loss = coordinator2
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::Startup, 20)
        .unwrap();
    assert_eq!(album_loss.membership_generation, None);
    assert_eq!(album_loss.snapshot.counts.observed, 0);
}

#[test]
fn icloud_retry_requires_zero_probe_bytes_consent_and_the_same_resource_token() {
    let (_temporary, _paths, repository, keys) = setup();
    let mut native = ScriptedNative::default();
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Complete,
        assets: vec![asset("cloud-asset", "cloud-token")],
    });
    native.push_transfer(TransferScript {
        token: "cloud-token",
        network: false,
        terminal: PhotoKitTransferTerminal::NetworkAccessRequired,
        chunks: vec![],
    });
    let mut coordinator = PhotoKitCoordinator::new(repository, native, keys);
    coordinator
        .configure_scope("album-private-id", false, 10)
        .unwrap();
    let unavailable = coordinator
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::User, 20)
        .unwrap();
    assert_eq!(unavailable.snapshot.counts.unavailable, 1);
    assert_eq!(
        unavailable.snapshot.availability_counts[0].reason,
        PhotoKitAvailabilityReasonV1::IcloudUnavailable
    );
    assert_eq!(
        coordinator
            .native()
            .calls
            .iter()
            .filter(|call| call.starts_with("transfer:"))
            .count(),
        1
    );

    let (_temporary, _paths, repository, keys) = setup();
    let mut native = ScriptedNative::default();
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Complete,
        assets: vec![asset("cloud-asset", "same-token")],
    });
    native.push_transfer(TransferScript {
        token: "same-token",
        network: false,
        terminal: PhotoKitTransferTerminal::NetworkAccessRequired,
        chunks: vec![],
    });
    native.push_transfer(TransferScript {
        token: "same-token",
        network: true,
        terminal: PhotoKitTransferTerminal::Complete,
        chunks: vec![b"cloud-image".to_vec()],
    });
    let mut coordinator = PhotoKitCoordinator::new(repository, native, keys);
    coordinator
        .configure_scope("album-private-id", true, 10)
        .unwrap();
    let materialized = coordinator
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::User, 20)
        .unwrap();
    assert_eq!(materialized.snapshot.counts.available, 1);
    assert_eq!(
        coordinator
            .native()
            .calls
            .iter()
            .filter(|call| call.starts_with("transfer:"))
            .count(),
        2
    );
}

#[test]
fn encrypted_locators_stale_fences_and_operation_recovery_are_fail_closed() {
    let (_temporary, paths, repository, keys) = setup();
    let mut coordinator =
        PhotoKitCoordinator::new(repository.clone(), ScriptedNative::default(), keys.clone());
    let enrollment = coordinator
        .configure_scope("album-private-id", true, 10)
        .unwrap();
    let raw_database = std::fs::read(&paths.database).unwrap();
    assert!(!raw_database
        .windows("album-private-id".len())
        .any(|window| window == b"album-private-id"));
    let connection = Connection::open(&paths.database).unwrap();
    let locator_shape: (String, i64, i64, i64) = connection
        .query_row(
            "SELECT typeof(ciphertext), length(ciphertext),
                    length(nonce), length(lookup_hmac)
             FROM photokit_locator_records WHERE record_kind = 'album'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(locator_shape, ("blob".to_owned(), 32, 24, 32));

    let active = repository.active_enrollment().unwrap().unwrap();
    let root = keys.load_root_key(&active.key_reference, false).unwrap();
    assert_eq!(
        repository
            .decrypt_album_locator(&enrollment.enrollment_epoch, &root)
            .unwrap(),
        "album-private-id"
    );
    assert!(repository
        .decrypt_album_locator(
            &enrollment.enrollment_epoch,
            &PhotoKitRootKey::from_bytes([7; 32]),
        )
        .is_err());

    let (older, _) = repository
        .begin_operation(
            &request_id(),
            PhotoKitReconcileTriggerV1::Startup,
            PhotoKitAuthorizationV1::Authorized,
            20,
        )
        .unwrap();
    let (newer, _) = repository
        .begin_operation(
            &request_id(),
            PhotoKitReconcileTriggerV1::User,
            PhotoKitAuthorizationV1::Authorized,
            21,
        )
        .unwrap();
    assert!(matches!(
        repository.record_observation(
            &older,
            &root,
            0,
            "stale-asset",
            Some("public.jpeg"),
            true,
            22,
        ),
        Err(PlatformError::Conflict("photokit_stale_fence"))
    ));
    repository
        .record_observation(
            &newer,
            &root,
            0,
            "provisional-asset",
            Some("public.jpeg"),
            true,
            22,
        )
        .unwrap();
    assert_eq!(repository.recover_operations(30).unwrap(), 2);
    assert!(matches!(
        coordinator.reconcile(&newer.request_id, PhotoKitReconcileTriggerV1::User, 31),
        Err(PhotoKitCoordinatorError::Platform(PlatformError::Conflict(
            "photokit_operation_not_replayable"
        )))
    ));
    assert_eq!(
        connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM photokit_operation_observations)
                   +(SELECT COUNT(*) FROM photokit_locator_records
                     WHERE finalized = 0)",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn hard_deleted_asset_reconciles_into_a_new_monotonic_generation() {
    let (_temporary, paths, repository, keys) = setup();
    let mut native = ScriptedNative::default();
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Complete,
        assets: vec![asset("asset-a", "token-a1"), asset("asset-b", "token-b1")],
    });
    native.push_transfer(complete_transfer("token-a1", b"first-image"));
    native.push_transfer(complete_transfer("token-b1", b"other-image"));
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Complete,
        assets: vec![asset("asset-a", "token-a2")],
    });
    native.push_transfer(complete_transfer("token-a2", b"second-image"));

    let mut coordinator = PhotoKitCoordinator::new(repository.clone(), native, keys);
    coordinator
        .configure_scope("album-private-id", false, 10)
        .unwrap();
    let first = coordinator
        .reconcile(&request_id(), PhotoKitReconcileTriggerV1::Startup, 20)
        .unwrap();
    assert_eq!(first.membership_generation, Some(1));

    let connection = Connection::open(&paths.database).unwrap();
    let asset_id: String = connection
        .query_row(
            "SELECT asset_id FROM photokit_operation_observations
             WHERE operation_id = ?1 AND ordinal = 0",
            [&first.operation_id],
            |row| row.get(0),
        )
        .unwrap();
    let preview = repository
        .database()
        .preview_deletion(&PreviewDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            target_kind: DeletionTargetKindV1::PhotoKitAsset,
            target_id: asset_id,
            limit: 100,
        })
        .unwrap();
    repository
        .database()
        .execute_deletion(&ExecuteDeletionV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            preview_snapshot_token: preview.preview_snapshot_token,
            plan_sha256: preview.plan_sha256,
            expected_revisions: preview.revisions,
            confirmation: DeletionConfirmationV1::DeleteActiveLocalData,
        })
        .unwrap();

    let second = coordinator
        .reconcile(
            &request_id(),
            PhotoKitReconcileTriggerV1::Startup,
            2_000_000_000_000,
        )
        .unwrap();
    assert_eq!(second.membership_generation, Some(2));
    assert_eq!(second.snapshot.counts.observed, 2);
    assert_eq!(second.snapshot.counts.available, 1);
    assert_eq!(second.snapshot.counts.unavailable, 1);
    assert!(second.snapshot.availability_counts.iter().any(|count| {
        count.reason == PhotoKitAvailabilityReasonV1::AssetNotInScope && count.count == 1
    }));

    for reconfigure in [false, true] {
        let (_temporary, paths, repository, keys) = setup();
        let mut native = ScriptedNative::default();
        native.push_enumeration(EnumerationScript {
            authorization: PhotoKitAuthorizationV1::Authorized,
            terminal: PhotoKitEnumerationTerminal::Complete,
            assets: vec![asset("asset-a", "token-a"), asset("asset-b", "token-b")],
        });
        native.push_transfer(complete_transfer("token-a", b"first-image"));
        native.push_transfer(complete_transfer("token-b", b"second-image"));
        let mut coordinator = PhotoKitCoordinator::new(repository.clone(), native, keys);
        let enrollment = coordinator
            .configure_scope("album-private-id", false, 10)
            .unwrap();
        let first = coordinator
            .reconcile(&request_id(), PhotoKitReconcileTriggerV1::Startup, 20)
            .unwrap();
        let connection = Connection::open(&paths.database).unwrap();
        let (deleted_asset, surviving_asset): (String, String) = connection
            .query_row(
                "SELECT
                    MAX(CASE WHEN ordinal = 0 THEN asset_id END),
                    MAX(CASE WHEN ordinal = 1 THEN asset_id END)
                 FROM photokit_operation_observations
                 WHERE operation_id = ?1",
                [&first.operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let preview = repository
            .database()
            .preview_deletion(&PreviewDeletionV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                target_kind: DeletionTargetKindV1::PhotoKitAsset,
                target_id: deleted_asset,
                limit: 100,
            })
            .unwrap();
        repository
            .database()
            .execute_deletion(&ExecuteDeletionV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                preview_snapshot_token: preview.preview_snapshot_token,
                plan_sha256: preview.plan_sha256,
                expected_revisions: preview.revisions,
                confirmation: DeletionConfirmationV1::DeleteActiveLocalData,
            })
            .unwrap();

        if reconfigure {
            coordinator
                .configure_scope("replacement-album-private-id", false, 30)
                .unwrap();
        } else {
            let snapshot = repository
                .snapshot(PhotoKitAuthorizationV1::Authorized)
                .unwrap();
            repository
                .disable_command(
                    &DisablePhotoKitV1Request {
                        schema_version: SCHEMA_VERSION_V1,
                        request_id: RequestId::new_v4(),
                        expected_photokit_revision: snapshot.photokit_revision,
                    },
                    &"a".repeat(64),
                    30,
                )
                .unwrap();
        }

        let head: (String, String, i64) = connection
            .query_row(
                "SELECT revision.reason, operation.state,
                        operation.terminal_publication_json IS NOT NULL
                 FROM photokit_availability_heads head
                 JOIN photokit_availability_revisions revision
                   ON revision.revision_id = head.revision_id
                 JOIN photokit_operations operation
                   ON operation.operation_id = revision.operation_id
                 WHERE head.asset_id = ?1",
                [&surviving_asset],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            head,
            ("scope_unavailable".to_owned(), "failed".to_owned(), 1)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT state FROM photokit_enrollments
                     WHERE enrollment_epoch = ?1",
                    [&enrollment.enrollment_epoch],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "inactive"
        );
    }
}

#[test]
fn exclusive_orphan_collection_cannot_cross_shared_promotion_to_ownership_window() {
    let (_temporary, paths, repository, _keys) = setup();
    let store = BlobStore::new(&paths);
    let owned = store.put(b"owned-after-promotion", None, 1024).unwrap();
    let shared = MaintenanceCoordinator::global().acquire_shared().unwrap();
    let (tx, rx) = mpsc::channel();
    let collector = repository.clone();
    let owned_hash = owned.sha256.clone();
    let thread = thread::spawn(move || {
        tx.send(
            collector
                .collect_unowned_blob(&owned_hash, Duration::ZERO, i64::MAX)
                .unwrap(),
        )
        .unwrap();
    });
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    Connection::open(&paths.database)
        .unwrap()
        .execute(
            "INSERT INTO blobs(sha256, byte_length, created_at_ms)
             VALUES (?1, ?2, 1)",
            params![owned.sha256, owned.byte_length as i64],
        )
        .unwrap();
    drop(shared);
    assert!(!rx.recv_timeout(Duration::from_secs(2)).unwrap());
    thread.join().unwrap();
    assert!(owned.path.exists());

    let orphan = store.put(b"unowned-after-crash", None, 1024).unwrap();
    let shared = MaintenanceCoordinator::global().acquire_shared().unwrap();
    let (tx, rx) = mpsc::channel();
    let collector = repository.clone();
    let orphan_hash = orphan.sha256.clone();
    let thread = thread::spawn(move || {
        tx.send(
            collector
                .collect_unowned_blob(&orphan_hash, Duration::ZERO, i64::MAX)
                .unwrap(),
        )
        .unwrap();
    });
    assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());
    drop(shared);
    assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap());
    thread.join().unwrap();
    assert!(!orphan.path.exists());
}

#[test]
fn maintenance_writer_between_transfer_and_publication_cannot_deadlock_reconciliation() {
    let (_temporary, _paths, repository, keys) = setup();
    let (transfer_started_tx, transfer_started_rx) = mpsc::channel();
    let (resume_transfer_tx, resume_transfer_rx) = mpsc::channel();
    let mut native = ScriptedNative {
        transfer_started: Some(transfer_started_tx),
        transfer_resume: Some(resume_transfer_rx),
        ..ScriptedNative::default()
    };
    native.push_enumeration(EnumerationScript {
        authorization: PhotoKitAuthorizationV1::Authorized,
        terminal: PhotoKitEnumerationTerminal::Complete,
        assets: vec![asset("asset-a", "token-a")],
    });
    native.push_transfer(complete_transfer("token-a", b"image-a"));
    let mut coordinator = PhotoKitCoordinator::new(repository, native, keys);
    coordinator
        .configure_scope("album-private-id", false, 10)
        .unwrap();

    let (reconcile_tx, reconcile_rx) = mpsc::channel();
    let reconcile_thread = thread::spawn(move || {
        reconcile_tx
            .send(coordinator.reconcile(&request_id(), PhotoKitReconcileTriggerV1::Startup, 20))
            .unwrap();
    });
    transfer_started_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap();

    let (writer_acquired_tx, writer_acquired_rx) = mpsc::channel();
    let (release_writer_tx, release_writer_rx) = mpsc::channel();
    let writer_thread = thread::spawn(move || {
        let permit = MaintenanceCoordinator::global()
            .acquire_exclusive()
            .unwrap();
        writer_acquired_tx.send(()).unwrap();
        release_writer_rx.recv().unwrap();
        drop(permit);
    });
    writer_acquired_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("the writer must acquire before reconciliation requests its narrow permit");

    resume_transfer_tx.send(()).unwrap();
    assert!(
        reconcile_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "reconciliation must wait while the exclusive writer owns maintenance"
    );
    release_writer_tx.send(()).unwrap();
    reconcile_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    reconcile_thread.join().unwrap();
    writer_thread.join().unwrap();
}
