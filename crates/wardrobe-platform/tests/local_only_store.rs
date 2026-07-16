use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use wardrobe_core::{
    LocalOnlyAuthorityHealthV1, ReplayStatusV1, RequestId, SetLocalOnlyV1Request, SCHEMA_VERSION_V1,
};
use wardrobe_platform::{
    LocalOnlyModeSnapshot, LocalOnlyModeStore, LocalOnlyStoreError, PlatformError, PrivateAppPaths,
};

fn request(request_id: RequestId, enabled: bool, expected_revision: u64) -> SetLocalOnlyV1Request {
    SetLocalOnlyV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id,
        enabled,
        expected_revision,
    }
}

#[test]
fn acknowledged_response_requires_the_exact_request_and_target_revision() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let store = LocalOnlyModeStore::new(&paths);
    let original = request(RequestId::new_v4(), false, 0);

    let written = store.set_local_only(&original).unwrap();
    assert_eq!(
        store.load_acknowledged_response(&original),
        Some(written.clone())
    );

    let changed_target = request(original.request_id, true, 0);
    assert!(store.load_acknowledged_response(&changed_target).is_none());
    let changed_revision = request(original.request_id, false, 1);
    assert!(store
        .load_acknowledged_response(&changed_revision)
        .is_none());
    let changed_request_id = request(RequestId::new_v4(), false, 0);
    assert!(store
        .load_acknowledged_response(&changed_request_id)
        .is_none());
}

fn assert_fail_closed(snapshot: LocalOnlyModeSnapshot) {
    assert!(snapshot.local_only);
    assert_eq!(snapshot.revision, 0);
    assert_eq!(
        snapshot.authority_health,
        LocalOnlyAuthorityHealthV1::FailClosedDefault
    );
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn record_paths(paths: &PrivateAppPaths) -> [&Path; 3] {
    [
        &paths.network_mode_intent,
        &paths.network_mode,
        &paths.network_mode_acknowledgment,
    ]
}

fn read_records(paths: &PrivateAppPaths) -> [Vec<u8>; 3] {
    record_paths(paths).map(|path| fs::read(path).unwrap())
}

fn write_records(paths: &PrivateAppPaths, records: &[Vec<u8>; 3]) {
    for (path, bytes) in record_paths(paths).into_iter().zip(records) {
        write_private(path, bytes);
    }
}

#[test]
fn private_layout_and_missing_state_are_fail_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let store = LocalOnlyModeStore::new(&paths);

    assert_eq!(
        fs::symlink_metadata(&paths.network_mode_dir)
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(paths.network_mode_dir.parent(), Some(paths.root.as_path()));
    assert!(!paths.network_mode_dir.starts_with(&paths.backups));
    assert_fail_closed(store.load());
}

#[test]
fn records_are_private_strict_canonical_and_bounded() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let store = LocalOnlyModeStore::new(&paths);
    store.set(&request(RequestId::new_v4(), false, 0)).unwrap();

    let original = read_records(&paths);
    for path in record_paths(&paths) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    write_private(&paths.network_mode, b"{");
    assert_fail_closed(store.load());

    write_private(&paths.network_mode, &vec![b' '; 4 * 1024 + 1]);
    assert_fail_closed(store.load());

    let mut unknown: Value = serde_json::from_slice(&original[1]).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_owned(), Value::Bool(true));
    write_private(&paths.network_mode, &serde_json::to_vec(&unknown).unwrap());
    assert_fail_closed(store.load());

    let noncanonical =
        serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&original[1]).unwrap()).unwrap();
    write_private(&paths.network_mode, &noncanonical);
    assert_fail_closed(store.load());

    let mut unsupported: Value = serde_json::from_slice(&original[1]).unwrap();
    unsupported["schema_version"] = Value::from(2);
    write_private(
        &paths.network_mode,
        &serde_json::to_vec(&unsupported).unwrap(),
    );
    assert_fail_closed(store.load());

    let mut bad_checksum: Value = serde_json::from_slice(&original[1]).unwrap();
    bad_checksum["local_only"] = Value::Bool(true);
    write_private(
        &paths.network_mode,
        &serde_json::to_vec(&bad_checksum).unwrap(),
    );
    assert_fail_closed(store.load());

    write_records(&paths, &original);
    let loaded = store.load();
    assert!(!loaded.local_only);
    assert_eq!(loaded.revision, 1);
    assert_eq!(
        loaded.authority_health,
        LocalOnlyAuthorityHealthV1::Persisted
    );
}

#[test]
fn every_partial_intent_active_ack_combination_is_fail_closed() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let store = LocalOnlyModeStore::new(&paths);
    store.set(&request(RequestId::new_v4(), false, 0)).unwrap();
    let records = read_records(&paths);

    for present in 0_u8..8 {
        for (index, path) in record_paths(&paths).into_iter().enumerate() {
            if present & (1 << index) == 0 {
                let _ = fs::remove_file(path);
            } else {
                write_private(path, &records[index]);
            }
        }
        if present == 0b111 {
            let loaded = store.load();
            assert!(!loaded.local_only);
            assert_eq!(loaded.revision, 1);
        } else {
            assert_fail_closed(store.load());
        }
    }
}

#[test]
fn false_mode_requires_the_exact_acknowledged_hash_chain() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let store = LocalOnlyModeStore::new(&paths);
    store.set(&request(RequestId::new_v4(), false, 0)).unwrap();
    let false_records = read_records(&paths);
    fs::remove_file(&paths.network_mode_acknowledgment).unwrap();
    assert_fail_closed(store.load());

    let repaired = store.set(&request(RequestId::new_v4(), true, 0)).unwrap();
    assert_eq!(repaired.revision, 1);
    let true_records = read_records(&paths);

    write_private(&paths.network_mode_intent, &false_records[0]);
    write_private(&paths.network_mode, &false_records[1]);
    write_private(&paths.network_mode_acknowledgment, &true_records[2]);
    assert_fail_closed(store.load());
}

#[test]
fn exact_request_replays_and_conflicting_requests_do_not_write() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let store = LocalOnlyModeStore::new(&paths);
    let request_id = RequestId::new_v4();
    let first_request = request(request_id, false, 0);
    let created = store.set(&first_request).unwrap();
    let created_records = read_records(&paths);

    assert_eq!(created.replay_status, ReplayStatusV1::Created);
    assert_eq!(
        store.set(&first_request).unwrap().replay_status,
        ReplayStatusV1::Replayed
    );
    assert_eq!(read_records(&paths), created_records);

    let reused = store.set(&request(request_id, true, 1)).unwrap_err();
    assert!(matches!(
        reused,
        LocalOnlyStoreError::Platform(PlatformError::Conflict("local_only_request_id_reused"))
    ));
    let stale = store
        .set(&request(RequestId::new_v4(), true, 0))
        .unwrap_err();
    assert!(matches!(
        stale,
        LocalOnlyStoreError::Platform(PlatformError::Conflict("local_only_stale_revision"))
    ));
    assert_eq!(read_records(&paths), created_records);
}

#[test]
fn unsafe_modes_and_symlink_targets_fail_closed_without_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let store = LocalOnlyModeStore::new(&paths);
    store.set(&request(RequestId::new_v4(), false, 0)).unwrap();
    let records = read_records(&paths);

    fs::set_permissions(&paths.network_mode, fs::Permissions::from_mode(0o644)).unwrap();
    assert_fail_closed(store.load());
    fs::set_permissions(&paths.network_mode, fs::Permissions::from_mode(0o600)).unwrap();

    fs::remove_file(&paths.network_mode).unwrap();
    let outside = temporary.path().join("outside");
    fs::write(&outside, b"must remain unchanged").unwrap();
    symlink(&outside, &paths.network_mode).unwrap();
    assert_fail_closed(store.load());

    let error = store
        .set(&request(RequestId::new_v4(), true, 0))
        .unwrap_err();
    assert!(matches!(
        error,
        LocalOnlyStoreError::Platform(PlatformError::Corrupt("local_only_target_identity"))
    ));
    assert_eq!(fs::read(&outside).unwrap(), b"must remain unchanged");
    assert!(fs::symlink_metadata(&paths.network_mode)
        .unwrap()
        .file_type()
        .is_symlink());

    fs::remove_file(&paths.network_mode).unwrap();
    write_records(&paths, &records);
}

#[test]
fn mixed_atomic_generations_load_only_complete_old_or_new_state() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let store = LocalOnlyModeStore::new(&paths);
    store.set(&request(RequestId::new_v4(), false, 0)).unwrap();
    let old = read_records(&paths);
    store.set(&request(RequestId::new_v4(), true, 1)).unwrap();
    let new = read_records(&paths);

    for generation_mask in 0_u8..8 {
        let mixed = std::array::from_fn(|index| {
            if generation_mask & (1 << index) == 0 {
                old[index].clone()
            } else {
                new[index].clone()
            }
        });
        write_records(&paths, &mixed);
        match generation_mask {
            0 => {
                let loaded = store.load();
                assert!(!loaded.local_only);
                assert_eq!(loaded.revision, 1);
            }
            0b111 => {
                let loaded = store.load();
                assert!(loaded.local_only);
                assert_eq!(loaded.revision, 2);
                assert_eq!(
                    loaded.authority_health,
                    LocalOnlyAuthorityHealthV1::Persisted
                );
            }
            _ => assert_fail_closed(store.load()),
        }
    }
}
