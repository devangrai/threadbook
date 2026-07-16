use crate::backup_repository::{
    digest_bytes, hash_private_file, lock_maintenance, write_private_file, BackupReason,
    BackupRepository, MaintenanceGuard, VerifiedBackup,
};
use crate::blob::sync_directory;
use crate::database;
use crate::{
    BlobStore, Database, MaintenanceCoordinator, PlatformError, PlatformResult, PrivateAppPaths,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use wardrobe_core::{BackupId, Sha256Digest};

const INTENT_SCHEMA_VERSION: u8 = 1;
const UPGRADE_INTENT_SCHEMA_VERSION: u8 = 1;
const APPLICATION_IDENTIFIER: &str = "com.wardrobe.desktop";
const MAX_INTENT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareRestoreResult {
    pub restart_required: bool,
    pub safety_backup_id: BackupId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RestorePhase {
    Requested,
    AssetsInstalled,
    LiveQuarantined,
    DatabaseInstalled,
    Validated,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreIntentV1 {
    schema_version: u8,
    application_identifier: String,
    operation_id: String,
    backup_id: String,
    expected_manifest_sha256: String,
    safety_backup_id: String,
    created_at_ms: i64,
    phase: RestorePhase,
    staged_database_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum UpgradeRecoveryPhase {
    Prepared,
    LiveQuarantined,
    SourcePublished,
    Verified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UpgradeRecoveryIntentV1 {
    schema_version: u8,
    application_identifier: String,
    operation_id: String,
    backup_id: String,
    expected_manifest_sha256: String,
    source_database_sha256: String,
    source_database_length: u64,
    source_schema_version: u32,
    source_migration_prefix_sha256: String,
    target_schema_version: u32,
    created_at_ms: i64,
    phase: UpgradeRecoveryPhase,
}

#[derive(Clone, Debug)]
pub struct RestoreRepository {
    paths: PrivateAppPaths,
}

impl RestoreRepository {
    pub fn new(paths: &PrivateAppPaths) -> Self {
        Self {
            paths: paths.clone(),
        }
    }

    pub(crate) fn prepare_upgrade_recovery(
        &self,
        backup: &VerifiedBackup,
        source_schema_version: u32,
        source_migration_prefix_sha256: &str,
        target_schema_version: u32,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let _exclusive = MaintenanceCoordinator::global().acquire_exclusive()?;
        let guard = lock_maintenance()?;
        if self.paths.upgrade_recovery_intent.exists()
            || self.paths.upgrade_recovery_intent_sha256.exists()
        {
            return Err(PlatformError::Conflict("upgrade_recovery_already_pending"));
        }
        verify_upgrade_backup(
            backup,
            source_schema_version,
            source_migration_prefix_sha256,
        )?;

        let operation_id = Uuid::new_v4().to_string();
        let operation = upgrade_operation_directory(&self.paths, &operation_id);
        create_private_directory(&operation)?;
        let staged = operation.join("source.sqlite3.staged");
        copy_private_file(
            &backup.package_path.join("catalog.sqlite3"),
            &staged,
            &backup.manifest.database.sha256,
            backup.manifest.database.byte_length,
        )?;
        database::verify_upgrade_source_database(
            &staged,
            &backup.manifest.database.sha256,
            backup.manifest.database.byte_length,
            source_schema_version,
            source_migration_prefix_sha256,
        )?;
        sync_directory(&operation)?;

        let intent = UpgradeRecoveryIntentV1 {
            schema_version: UPGRADE_INTENT_SCHEMA_VERSION,
            application_identifier: APPLICATION_IDENTIFIER.to_owned(),
            operation_id,
            backup_id: backup.record.backup_id.to_string(),
            expected_manifest_sha256: backup.record.manifest_sha256.as_str().to_owned(),
            source_database_sha256: backup.manifest.database.sha256.clone(),
            source_database_length: backup.manifest.database.byte_length,
            source_schema_version,
            source_migration_prefix_sha256: source_migration_prefix_sha256.to_owned(),
            target_schema_version,
            created_at_ms: now_ms,
            phase: UpgradeRecoveryPhase::Prepared,
        };
        if let Err(error) = write_upgrade_intent(&self.paths, &intent, true) {
            if !self.paths.upgrade_recovery_intent.exists()
                && !self.paths.upgrade_recovery_intent_sha256.exists()
            {
                let _ = fs::remove_dir_all(&operation);
                let _ = cleanup_upgrade_intent_temporaries(&self.paths);
                let _ = sync_directory(&self.paths.restore);
            }
            return Err(error);
        }
        drop(guard);
        Ok(())
    }

    pub(crate) fn recover_interrupted_upgrade(&self) -> PlatformResult<bool> {
        if !self.paths.upgrade_recovery_intent.exists()
            && !self.paths.upgrade_recovery_intent_sha256.exists()
        {
            cleanup_upgrade_intent_temporaries(&self.paths)?;
            return Ok(false);
        }
        let _exclusive = MaintenanceCoordinator::global().acquire_exclusive()?;
        let guard = lock_maintenance()?;
        let mut intent = read_upgrade_intent(&self.paths)?;
        if intent.phase == UpgradeRecoveryPhase::Verified {
            verify_terminal_upgrade_database(&self.paths, &intent)?;
            cleanup_verified_upgrade_recovery(&self.paths, &intent)?;
            return Ok(true);
        }

        let backup = BackupRepository::new(&self.paths).verify_locked(
            &intent.backup_id,
            Some(&intent.expected_manifest_sha256),
            &guard,
        )?;
        verify_upgrade_backup(
            &backup,
            intent.source_schema_version,
            &intent.source_migration_prefix_sha256,
        )?;
        if backup.manifest.database.sha256 != intent.source_database_sha256
            || backup.manifest.database.byte_length != intent.source_database_length
        {
            return Err(PlatformError::Corrupt("upgrade_recovery_backup_changed"));
        }

        self.recover_upgrade_locked(&mut intent)?;
        Ok(true)
    }

    pub(crate) fn commit_upgrade_recovery(&self) -> PlatformResult<()> {
        if !self.paths.upgrade_recovery_intent.exists()
            && !self.paths.upgrade_recovery_intent_sha256.exists()
        {
            return Ok(());
        }
        let _exclusive = MaintenanceCoordinator::global().acquire_exclusive()?;
        let _guard = lock_maintenance()?;
        let mut intent = read_upgrade_intent(&self.paths)?;
        database::verify_upgrade_target_database(
            &self.paths.database,
            intent.target_schema_version,
        )?;
        intent.phase = UpgradeRecoveryPhase::Verified;
        write_upgrade_intent(&self.paths, &intent, false)?;
        cleanup_verified_upgrade_recovery(&self.paths, &intent)
    }

    fn recover_upgrade_locked(&self, intent: &mut UpgradeRecoveryIntentV1) -> PlatformResult<()> {
        let operation = upgrade_operation_directory(&self.paths, &intent.operation_id);
        create_private_directory(&operation)?;
        let staged = operation.join("source.sqlite3.staged");
        let quarantine = operation.join("failed-live");

        if intent.phase == UpgradeRecoveryPhase::Prepared {
            if !staged.exists()
                && quarantine.join("wardrobe.sqlite3").exists()
                && exact_upgrade_source_matches(&self.paths.database, intent)
            {
                intent.phase = UpgradeRecoveryPhase::SourcePublished;
                write_upgrade_intent(&self.paths, intent, false)?;
            } else {
                database::verify_upgrade_source_database(
                    &staged,
                    &intent.source_database_sha256,
                    intent.source_database_length,
                    intent.source_schema_version,
                    &intent.source_migration_prefix_sha256,
                )?;
                create_private_directory(&quarantine)?;
                quarantine_database_family(&self.paths.database, &quarantine)?;
                intent.phase = UpgradeRecoveryPhase::LiveQuarantined;
                write_upgrade_intent(&self.paths, intent, false)?;
            }
        }

        if intent.phase == UpgradeRecoveryPhase::LiveQuarantined {
            publish_upgrade_source(&self.paths.database, &staged, intent)?;
            intent.phase = UpgradeRecoveryPhase::SourcePublished;
            write_upgrade_intent(&self.paths, intent, false)?;
        }

        if intent.phase == UpgradeRecoveryPhase::SourcePublished {
            database::verify_upgrade_source_database(
                &self.paths.database,
                &intent.source_database_sha256,
                intent.source_database_length,
                intent.source_schema_version,
                &intent.source_migration_prefix_sha256,
            )?;
            intent.phase = UpgradeRecoveryPhase::Verified;
            write_upgrade_intent(&self.paths, intent, false)?;
        }

        cleanup_verified_upgrade_recovery(&self.paths, intent)
    }

    pub fn prepare(
        &self,
        backup_id: BackupId,
        expected_manifest_sha256: &Sha256Digest,
        now_ms: i64,
    ) -> PlatformResult<PrepareRestoreResult> {
        if now_ms < 0 {
            return Err(PlatformError::InvalidInput("restore_created_at"));
        }
        let _exclusive = MaintenanceCoordinator::global().acquire_exclusive()?;
        let guard = lock_maintenance()?;
        if self.paths.restore_intent.exists() || self.paths.restore_intent_sha256.exists() {
            return Err(PlatformError::Conflict("restore_already_pending"));
        }
        let backups = BackupRepository::new(&self.paths);
        let backup_id_text = backup_id.to_string();
        backups.verify_locked(
            &backup_id_text,
            Some(expected_manifest_sha256.as_str()),
            &guard,
        )?;
        let safety = backups.create_locked(BackupReason::PreRestore, now_ms, &guard)?;
        let intent = RestoreIntentV1 {
            schema_version: INTENT_SCHEMA_VERSION,
            application_identifier: APPLICATION_IDENTIFIER.to_owned(),
            operation_id: Uuid::new_v4().to_string(),
            backup_id: backup_id_text,
            expected_manifest_sha256: expected_manifest_sha256.as_str().to_owned(),
            safety_backup_id: safety.backup_id.to_string(),
            created_at_ms: now_ms,
            phase: RestorePhase::Requested,
            staged_database_sha256: None,
        };
        write_intent(&self.paths, &intent, true)?;
        Ok(PrepareRestoreResult {
            restart_required: true,
            safety_backup_id: safety.backup_id,
        })
    }

    pub(crate) fn apply_pending(&self, now_ms: i64) -> PlatformResult<bool> {
        if !self.paths.restore_intent.exists() && !self.paths.restore_intent_sha256.exists() {
            return Ok(false);
        }
        let _exclusive = MaintenanceCoordinator::global().acquire_exclusive()?;
        let guard = lock_maintenance()?;
        let mut intent = read_intent(&self.paths)?;
        if intent.phase == RestorePhase::Requested {
            Database::recover_deletions_before_restore(&self.paths, &guard)?;
        }
        if intent.phase == RestorePhase::Committed {
            self.cleanup_committed(&intent)?;
            return Ok(false);
        }

        let result = self.apply_locked(&mut intent, now_ms, &guard);
        if let Err(error) = result {
            if restore_has_mutations(&self.paths, &intent) {
                self.rollback_locked(&intent)?;
                remove_intent(&self.paths)?;
            }
            return Err(error);
        }
        result
    }

    fn apply_locked(
        &self,
        intent: &mut RestoreIntentV1,
        now_ms: i64,
        guard: &MaintenanceGuard,
    ) -> PlatformResult<bool> {
        validate_intent(intent)?;
        let backup = BackupRepository::new(&self.paths).verify_locked(
            &intent.backup_id,
            Some(&intent.expected_manifest_sha256),
            guard,
        )?;
        let operation = operation_directory(&self.paths, &intent.operation_id);
        create_private_directory(&operation)?;

        if intent.phase == RestorePhase::Requested {
            let staged = operation.join("catalog.sqlite3.staged");
            let staged_sha256 = if staged.exists() {
                database::verify_staged_restore_database(&staged)?
            } else {
                database::stage_restore_database(
                    &backup.package_path.join("catalog.sqlite3"),
                    &staged,
                    now_ms,
                )?
            };
            if intent
                .staged_database_sha256
                .as_ref()
                .is_some_and(|expected| expected != &staged_sha256)
            {
                return Err(PlatformError::Corrupt("restore_staged_database_changed"));
            }
            intent.staged_database_sha256 = Some(staged_sha256);
            write_intent(&self.paths, intent, false)?;
            self.install_assets(&backup, intent)?;
            intent.phase = RestorePhase::AssetsInstalled;
            write_intent(&self.paths, intent, false)?;
        }

        if intent.phase == RestorePhase::AssetsInstalled {
            self.quarantine_live_database(intent)?;
            intent.phase = RestorePhase::LiveQuarantined;
            write_intent(&self.paths, intent, false)?;
        }

        if intent.phase == RestorePhase::LiveQuarantined {
            self.install_database(intent)?;
            intent.phase = RestorePhase::DatabaseInstalled;
            write_intent(&self.paths, intent, false)?;
        }

        if intent.phase == RestorePhase::DatabaseInstalled {
            self.validate_installed(&backup, intent)?;
            intent.phase = RestorePhase::Validated;
            write_intent(&self.paths, intent, false)?;
        }

        Ok(intent.phase == RestorePhase::Validated)
    }

    pub(crate) fn commit_pending(&self) -> PlatformResult<()> {
        if !self.paths.restore_intent.exists() && !self.paths.restore_intent_sha256.exists() {
            return Ok(());
        }
        let _exclusive = MaintenanceCoordinator::global().acquire_exclusive()?;
        let _guard = lock_maintenance()?;
        let mut intent = read_intent(&self.paths)?;
        if intent.phase != RestorePhase::Validated {
            return Err(PlatformError::Conflict("restore_not_validated"));
        }
        intent.phase = RestorePhase::Committed;
        write_intent(&self.paths, &intent, false)?;
        self.cleanup_committed(&intent)
    }

    fn install_assets(
        &self,
        backup: &VerifiedBackup,
        intent: &RestoreIntentV1,
    ) -> PlatformResult<()> {
        let operation = operation_directory(&self.paths, &intent.operation_id);
        let old_root = operation.join("blob-quarantine");
        let new_root = operation.join("blob-new");
        create_private_directory(&old_root)?;
        create_private_directory(&new_root)?;
        let store = BlobStore::new(&self.paths);

        for asset in &backup.manifest.assets {
            let source = backup
                .package_path
                .join("assets")
                .join(&asset.sha256[0..2])
                .join(&asset.sha256[2..4])
                .join(&asset.sha256);
            if hash_private_file(&source, Some(asset.byte_length))? != asset.sha256 {
                return Err(PlatformError::Corrupt("restore_backup_asset"));
            }
            let destination = store.path_for_hash(&asset.sha256)?;
            let destination_parent = destination
                .parent()
                .ok_or(PlatformError::Corrupt("restore_blob_parent"))?;
            create_private_directory(&self.paths.blobs.join(&asset.sha256[0..2]))?;
            create_private_directory(destination_parent)?;

            if destination.exists()
                && hash_private_file(&destination, Some(asset.byte_length))
                    .is_ok_and(|hash| hash == asset.sha256)
            {
                continue;
            }

            let quarantine = old_root
                .join(&asset.sha256[0..2])
                .join(&asset.sha256[2..4])
                .join(&asset.sha256);
            if destination.exists() {
                create_private_directory(
                    quarantine
                        .parent()
                        .and_then(Path::parent)
                        .ok_or(PlatformError::Corrupt("restore_blob_quarantine"))?,
                )?;
                create_private_directory(
                    quarantine
                        .parent()
                        .ok_or(PlatformError::Corrupt("restore_blob_quarantine"))?,
                )?;
                if quarantine.exists() {
                    fs::remove_file(&destination)?;
                } else {
                    fs::rename(&destination, &quarantine)?;
                    sync_directory(destination_parent)?;
                    sync_directory(
                        quarantine
                            .parent()
                            .ok_or(PlatformError::Corrupt("restore_blob_quarantine"))?,
                    )?;
                }
            } else if !quarantine.exists() {
                let marker = new_root.join(&asset.sha256);
                if !marker.exists() {
                    write_private_file(&marker, b"new\n")?;
                    sync_directory(&new_root)?;
                }
            }

            let temporary = self
                .paths
                .staging
                .join(format!("{}.restore", Uuid::new_v4()));
            copy_private_file(&source, &temporary, &asset.sha256, asset.byte_length)?;
            fs::rename(&temporary, &destination)?;
            sync_directory(&self.paths.staging)?;
            sync_directory(destination_parent)?;
            if hash_private_file(&destination, Some(asset.byte_length))? != asset.sha256 {
                return Err(PlatformError::Corrupt("restore_installed_asset"));
            }
        }
        sync_directory(&operation)?;
        Ok(())
    }

    fn quarantine_live_database(&self, intent: &RestoreIntentV1) -> PlatformResult<()> {
        let rollback = operation_directory(&self.paths, &intent.operation_id).join("database");
        create_private_directory(&rollback)?;
        for (source, name) in database_family(&self.paths.database) {
            let destination = rollback.join(name);
            match (source.exists(), destination.exists()) {
                (true, false) => {
                    let metadata = fs::symlink_metadata(&source)?;
                    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                        return Err(PlatformError::Corrupt("restore_database_family"));
                    }
                    fs::rename(source, destination)?;
                }
                (true, true) => {
                    return Err(PlatformError::Corrupt("restore_database_family_ambiguous"));
                }
                _ => {}
            }
        }
        if !rollback.join("wardrobe.sqlite3").exists() {
            return Err(PlatformError::Corrupt("restore_live_database_missing"));
        }
        sync_directory(
            self.paths
                .database
                .parent()
                .ok_or(PlatformError::Corrupt("restore_database_parent"))?,
        )?;
        sync_directory(&rollback)?;
        Ok(())
    }

    fn install_database(&self, intent: &RestoreIntentV1) -> PlatformResult<()> {
        let staged =
            operation_directory(&self.paths, &intent.operation_id).join("catalog.sqlite3.staged");
        match (staged.exists(), self.paths.database.exists()) {
            (true, false) => {
                fs::rename(&staged, &self.paths.database)?;
                sync_directory(
                    self.paths
                        .database
                        .parent()
                        .ok_or(PlatformError::Corrupt("restore_database_parent"))?,
                )?;
            }
            (false, true) => {
                let actual = database::verify_staged_restore_database(&self.paths.database)?;
                if intent
                    .staged_database_sha256
                    .as_ref()
                    .is_none_or(|expected| expected != &actual)
                {
                    return Err(PlatformError::Corrupt("restore_installed_database"));
                }
            }
            _ => return Err(PlatformError::Corrupt("restore_database_install_state")),
        }
        for sidecar in [
            path_with_suffix(&self.paths.database, "-wal"),
            path_with_suffix(&self.paths.database, "-shm"),
        ] {
            if sidecar.exists() {
                return Err(PlatformError::Corrupt("restore_database_sidecar"));
            }
        }
        Ok(())
    }

    fn validate_installed(
        &self,
        backup: &VerifiedBackup,
        intent: &RestoreIntentV1,
    ) -> PlatformResult<()> {
        let actual = database::verify_staged_restore_database(&self.paths.database)?;
        if intent
            .staged_database_sha256
            .as_ref()
            .is_none_or(|expected| expected != &actual)
        {
            return Err(PlatformError::Corrupt("restore_installed_database"));
        }
        let store = BlobStore::new(&self.paths);
        for asset in &backup.manifest.assets {
            let path = store.path_for_hash(&asset.sha256)?;
            if hash_private_file(&path, Some(asset.byte_length))? != asset.sha256 {
                return Err(PlatformError::Corrupt("restore_installed_asset"));
            }
        }
        Ok(())
    }

    fn rollback_locked(&self, intent: &RestoreIntentV1) -> PlatformResult<()> {
        let operation = operation_directory(&self.paths, &intent.operation_id);
        let rollback = operation.join("database");
        if rollback.join("wardrobe.sqlite3").exists() {
            for (live, _) in database_family(&self.paths.database) {
                if live.exists() {
                    fs::remove_file(live)?;
                }
            }
            for (live, name) in database_family(&self.paths.database) {
                let old = rollback.join(name);
                if old.exists() {
                    fs::rename(old, live)?;
                }
            }
            sync_directory(
                self.paths
                    .database
                    .parent()
                    .ok_or(PlatformError::Corrupt("restore_database_parent"))?,
            )?;
        }
        self.rollback_assets(intent)?;
        if operation.exists() {
            fs::remove_dir_all(&operation)?;
            sync_directory(&self.paths.restore)?;
        }
        Ok(())
    }

    fn rollback_assets(&self, intent: &RestoreIntentV1) -> PlatformResult<()> {
        let operation = operation_directory(&self.paths, &intent.operation_id);
        let old_root = operation.join("blob-quarantine");
        if old_root.exists() {
            restore_quarantined_blobs(&old_root, &self.paths.blobs)?;
        }
        let new_root = operation.join("blob-new");
        if new_root.exists() {
            let store = BlobStore::new(&self.paths);
            for entry in fs::read_dir(&new_root)? {
                let entry = entry?;
                let hash = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| PlatformError::Corrupt("restore_blob_marker"))?;
                let destination = store.path_for_hash(&hash)?;
                if destination.exists() {
                    fs::remove_file(&destination)?;
                    if let Some(parent) = destination.parent() {
                        sync_directory(parent)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn cleanup_committed(&self, intent: &RestoreIntentV1) -> PlatformResult<()> {
        let operation = operation_directory(&self.paths, &intent.operation_id);
        if operation.exists() {
            fs::remove_dir_all(operation)?;
            sync_directory(&self.paths.restore)?;
        }
        remove_intent(&self.paths)
    }
}

fn verify_upgrade_backup(
    backup: &VerifiedBackup,
    source_schema_version: u32,
    source_migration_prefix_sha256: &str,
) -> PlatformResult<()> {
    if backup.manifest.reason != BackupReason::PreUpgrade {
        return Err(PlatformError::Corrupt("upgrade_recovery_backup_reason"));
    }
    if backup.manifest.database.schema_version != source_schema_version
        || backup.manifest.database.migration_prefix_sha256 != source_migration_prefix_sha256
        || backup.record.database_schema_version != source_schema_version
    {
        return Err(PlatformError::Corrupt("upgrade_recovery_backup_version"));
    }
    validate_hash(source_migration_prefix_sha256)?;
    Ok(())
}

fn validate_upgrade_intent(intent: &UpgradeRecoveryIntentV1) -> PlatformResult<()> {
    if intent.schema_version != UPGRADE_INTENT_SCHEMA_VERSION
        || intent.application_identifier != APPLICATION_IDENTIFIER
    {
        return Err(PlatformError::Unsupported(
            "upgrade_recovery_intent_version",
        ));
    }
    for id in [&intent.operation_id, &intent.backup_id] {
        if Uuid::parse_str(id)
            .map(|parsed| parsed.to_string())
            .map_err(|_| PlatformError::Corrupt("upgrade_recovery_intent_id"))?
            != *id
        {
            return Err(PlatformError::Corrupt("upgrade_recovery_intent_id"));
        }
    }
    for hash in [
        &intent.expected_manifest_sha256,
        &intent.source_database_sha256,
        &intent.source_migration_prefix_sha256,
    ] {
        validate_hash(hash)?;
    }
    if intent.source_database_length == 0
        || intent.source_schema_version >= intent.target_schema_version
        || intent.created_at_ms < 0
    {
        return Err(PlatformError::Corrupt("upgrade_recovery_intent_bounds"));
    }
    Ok(())
}

fn upgrade_operation_directory(paths: &PrivateAppPaths, operation_id: &str) -> PathBuf {
    paths.restore.join(format!("upgrade-{operation_id}"))
}

fn quarantine_database_family(database: &Path, quarantine: &Path) -> PlatformResult<()> {
    let live_parent = database
        .parent()
        .ok_or(PlatformError::Corrupt("upgrade_recovery_database_parent"))?;
    for (index, (source, name)) in database_family(database).into_iter().enumerate() {
        let destination = quarantine.join(name);
        match (source.exists(), destination.exists()) {
            (true, false) => {
                let metadata = fs::symlink_metadata(&source)?;
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(PlatformError::Corrupt("upgrade_recovery_database_family"));
                }
                fs::rename(&source, &destination)?;
                sync_directory(live_parent)?;
                sync_directory(quarantine)?;
            }
            (true, true) => {
                return Err(PlatformError::Corrupt(
                    "upgrade_recovery_database_family_ambiguous",
                ));
            }
            (false, false) if index == 0 => {
                return Err(PlatformError::Corrupt(
                    "upgrade_recovery_live_database_missing",
                ));
            }
            _ => {}
        }
    }
    if !quarantine.join("wardrobe.sqlite3").exists() {
        return Err(PlatformError::Corrupt(
            "upgrade_recovery_live_database_missing",
        ));
    }
    Ok(())
}

fn publish_upgrade_source(
    database: &Path,
    staged: &Path,
    intent: &UpgradeRecoveryIntentV1,
) -> PlatformResult<()> {
    match (staged.exists(), database.exists()) {
        (true, false) => {
            fs::rename(staged, database)?;
            sync_directory(
                database
                    .parent()
                    .ok_or(PlatformError::Corrupt("upgrade_recovery_database_parent"))?,
            )?;
        }
        (false, true) => {
            database::verify_upgrade_source_database(
                database,
                &intent.source_database_sha256,
                intent.source_database_length,
                intent.source_schema_version,
                &intent.source_migration_prefix_sha256,
            )?;
        }
        _ => {
            return Err(PlatformError::Corrupt(
                "upgrade_recovery_database_publish_state",
            ));
        }
    }
    for sidecar in [
        path_with_suffix(database, "-wal"),
        path_with_suffix(database, "-shm"),
    ] {
        if sidecar.exists() {
            return Err(PlatformError::Corrupt("upgrade_recovery_database_sidecar"));
        }
    }
    Ok(())
}

fn exact_upgrade_source_matches(database: &Path, intent: &UpgradeRecoveryIntentV1) -> bool {
    database::verify_upgrade_source_database(
        database,
        &intent.source_database_sha256,
        intent.source_database_length,
        intent.source_schema_version,
        &intent.source_migration_prefix_sha256,
    )
    .is_ok()
}

fn verify_terminal_upgrade_database(
    paths: &PrivateAppPaths,
    intent: &UpgradeRecoveryIntentV1,
) -> PlatformResult<()> {
    if exact_upgrade_source_matches(&paths.database, intent) {
        return Ok(());
    }
    database::verify_upgrade_target_database(&paths.database, intent.target_schema_version)
}

fn cleanup_verified_upgrade_recovery(
    paths: &PrivateAppPaths,
    intent: &UpgradeRecoveryIntentV1,
) -> PlatformResult<()> {
    if intent.phase != UpgradeRecoveryPhase::Verified {
        return Err(PlatformError::Conflict("upgrade_recovery_not_verified"));
    }
    remove_upgrade_intent(paths)?;
    let operation = upgrade_operation_directory(paths, &intent.operation_id);
    if operation.exists() {
        fs::remove_dir_all(&operation)?;
        sync_directory(&paths.restore)?;
    }
    Ok(())
}

fn write_upgrade_intent(
    paths: &PrivateAppPaths,
    intent: &UpgradeRecoveryIntentV1,
    create_new: bool,
) -> PlatformResult<()> {
    validate_upgrade_intent(intent)?;
    let bytes = serde_json::to_vec(intent)?;
    if bytes.len() > MAX_INTENT_BYTES {
        return Err(PlatformError::InvalidInput("upgrade_recovery_intent_size"));
    }
    let token = Uuid::new_v4();
    let json_temporary = paths
        .restore
        .join(format!(".upgrade-recovery-{token}.json.tmp"));
    let hash_temporary = paths
        .restore
        .join(format!(".upgrade-recovery-{token}.sha256.tmp"));
    write_private_file(&json_temporary, &bytes)?;
    write_private_file(
        &hash_temporary,
        format!("{}\n", digest_bytes(&bytes)).as_bytes(),
    )?;
    if create_new
        && (paths.upgrade_recovery_intent.exists() || paths.upgrade_recovery_intent_sha256.exists())
    {
        let _ = fs::remove_file(json_temporary);
        let _ = fs::remove_file(hash_temporary);
        return Err(PlatformError::Conflict("upgrade_recovery_already_pending"));
    }
    fs::rename(json_temporary, &paths.upgrade_recovery_intent)?;
    sync_directory(&paths.restore)?;
    fs::rename(hash_temporary, &paths.upgrade_recovery_intent_sha256)?;
    sync_directory(&paths.restore)
}

fn read_upgrade_intent(paths: &PrivateAppPaths) -> PlatformResult<UpgradeRecoveryIntentV1> {
    recover_upgrade_intent_pair(paths)?;
    let bytes = read_private_bounded(&paths.upgrade_recovery_intent, MAX_INTENT_BYTES)?;
    match read_optional_private(&paths.upgrade_recovery_intent_sha256, 65)? {
        Some(sidecar) if checksum_matches(&bytes, &sidecar) => {}
        None => {
            let intent: UpgradeRecoveryIntentV1 = serde_json::from_slice(&bytes)?;
            validate_upgrade_intent(&intent)?;
            if intent.phase == UpgradeRecoveryPhase::Verified
                && serde_json::to_vec(&intent)? == bytes
            {
                return Ok(intent);
            }
            return Err(PlatformError::Corrupt("upgrade_recovery_intent_checksum"));
        }
        _ => {
            return Err(PlatformError::Corrupt("upgrade_recovery_intent_checksum"));
        }
    }
    let intent: UpgradeRecoveryIntentV1 = serde_json::from_slice(&bytes)?;
    validate_upgrade_intent(&intent)?;
    if serde_json::to_vec(&intent)? != bytes {
        return Err(PlatformError::Corrupt("upgrade_recovery_intent_canonical"));
    }
    Ok(intent)
}

fn recover_upgrade_intent_pair(paths: &PrivateAppPaths) -> PlatformResult<()> {
    let final_json = read_optional_private(&paths.upgrade_recovery_intent, MAX_INTENT_BYTES)?;
    let final_hash = read_optional_private(&paths.upgrade_recovery_intent_sha256, 65)?;
    if final_json
        .as_ref()
        .zip(final_hash.as_ref())
        .is_some_and(|(json, hash)| checksum_matches(json, hash))
    {
        cleanup_upgrade_intent_temporaries(paths)?;
        return Ok(());
    }

    let (temporary_json, temporary_hash) = upgrade_intent_temporaries(paths)?;
    if let Some(json) = final_json.as_ref() {
        for candidate in &temporary_hash {
            let hash = read_private_bounded(candidate, 65)?;
            if checksum_matches(json, &hash) {
                fs::rename(candidate, &paths.upgrade_recovery_intent_sha256)?;
                sync_directory(&paths.restore)?;
                cleanup_upgrade_intent_temporaries(paths)?;
                return Ok(());
            }
        }
    }
    if let Some(hash) = final_hash.as_ref() {
        for candidate in &temporary_json {
            let json = read_private_bounded(candidate, MAX_INTENT_BYTES)?;
            if checksum_matches(&json, hash) {
                fs::rename(candidate, &paths.upgrade_recovery_intent)?;
                sync_directory(&paths.restore)?;
                cleanup_upgrade_intent_temporaries(paths)?;
                return Ok(());
            }
        }
    }
    if final_json.is_some() && final_hash.is_none() {
        return Ok(());
    }
    Err(PlatformError::Corrupt("upgrade_recovery_intent_checksum"))
}

fn upgrade_intent_temporaries(
    paths: &PrivateAppPaths,
) -> PlatformResult<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut json = Vec::new();
    let mut hashes = Vec::new();
    for entry in fs::read_dir(&paths.restore)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(token) = name
            .strip_prefix(".upgrade-recovery-")
            .and_then(|value| value.strip_suffix(".json.tmp"))
        {
            validate_temporary_token(token)?;
            json.push(entry.path());
        } else if let Some(token) = name
            .strip_prefix(".upgrade-recovery-")
            .and_then(|value| value.strip_suffix(".sha256.tmp"))
        {
            validate_temporary_token(token)?;
            hashes.push(entry.path());
        }
        if json.len() + hashes.len() > 32 {
            return Err(PlatformError::Corrupt("upgrade_recovery_temporary_count"));
        }
    }
    json.sort();
    hashes.sort();
    Ok((json, hashes))
}

fn cleanup_upgrade_intent_temporaries(paths: &PrivateAppPaths) -> PlatformResult<()> {
    let (json, hashes) = upgrade_intent_temporaries(paths)?;
    let mut changed = false;
    for path in json.into_iter().chain(hashes) {
        fs::remove_file(path)?;
        changed = true;
    }
    if changed {
        sync_directory(&paths.restore)?;
    }
    Ok(())
}

fn remove_upgrade_intent(paths: &PrivateAppPaths) -> PlatformResult<()> {
    match fs::remove_file(&paths.upgrade_recovery_intent_sha256) {
        Ok(()) => sync_directory(&paths.restore)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::remove_file(&paths.upgrade_recovery_intent) {
        Ok(()) => sync_directory(&paths.restore)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    cleanup_upgrade_intent_temporaries(paths)
}

fn validate_intent(intent: &RestoreIntentV1) -> PlatformResult<()> {
    if intent.schema_version != INTENT_SCHEMA_VERSION
        || intent.application_identifier != APPLICATION_IDENTIFIER
    {
        return Err(PlatformError::Unsupported("restore_intent_version"));
    }
    for id in [
        &intent.operation_id,
        &intent.backup_id,
        &intent.safety_backup_id,
    ] {
        if Uuid::parse_str(id)
            .map(|parsed| parsed.to_string())
            .map_err(|_| PlatformError::Corrupt("restore_intent_id"))?
            != *id
        {
            return Err(PlatformError::Corrupt("restore_intent_id"));
        }
    }
    validate_hash(&intent.expected_manifest_sha256)?;
    if let Some(hash) = &intent.staged_database_sha256 {
        validate_hash(hash)?;
    }
    if intent.created_at_ms < 0 {
        return Err(PlatformError::Corrupt("restore_intent_timestamp"));
    }
    Ok(())
}

fn write_intent(
    paths: &PrivateAppPaths,
    intent: &RestoreIntentV1,
    create_new: bool,
) -> PlatformResult<()> {
    validate_intent(intent)?;
    let bytes = serde_json::to_vec(intent)?;
    if bytes.len() > MAX_INTENT_BYTES {
        return Err(PlatformError::InvalidInput("restore_intent_size"));
    }
    let digest = digest_bytes(&bytes);
    let token = Uuid::new_v4();
    let json_temporary = paths
        .root
        .join(format!(".restore-request-{token}.json.tmp"));
    let hash_temporary = paths
        .root
        .join(format!(".restore-request-{token}.sha256.tmp"));
    write_private_file(&json_temporary, &bytes)?;
    write_private_file(&hash_temporary, format!("{digest}\n").as_bytes())?;
    if create_new && (paths.restore_intent.exists() || paths.restore_intent_sha256.exists()) {
        let _ = fs::remove_file(json_temporary);
        let _ = fs::remove_file(hash_temporary);
        return Err(PlatformError::Conflict("restore_already_pending"));
    }
    fs::rename(json_temporary, &paths.restore_intent)?;
    sync_directory(&paths.root)?;
    fs::rename(hash_temporary, &paths.restore_intent_sha256)?;
    sync_directory(&paths.root)?;
    Ok(())
}

fn read_intent(paths: &PrivateAppPaths) -> PlatformResult<RestoreIntentV1> {
    recover_intent_pair(paths)?;
    let bytes = read_private_bounded(&paths.restore_intent, MAX_INTENT_BYTES)?;
    let sidecar = read_private_bounded(&paths.restore_intent_sha256, 65)?;
    if sidecar != format!("{}\n", digest_bytes(&bytes)).as_bytes() {
        return Err(PlatformError::Corrupt("restore_intent_checksum"));
    }
    let intent: RestoreIntentV1 = serde_json::from_slice(&bytes)?;
    validate_intent(&intent)?;
    if serde_json::to_vec(&intent)? != bytes {
        return Err(PlatformError::Corrupt("restore_intent_canonical"));
    }
    Ok(intent)
}

fn recover_intent_pair(paths: &PrivateAppPaths) -> PlatformResult<()> {
    let final_json = read_optional_private(&paths.restore_intent, MAX_INTENT_BYTES)?;
    let final_hash = read_optional_private(&paths.restore_intent_sha256, 65)?;
    if final_json
        .as_ref()
        .zip(final_hash.as_ref())
        .is_some_and(|(json, hash)| checksum_matches(json, hash))
    {
        cleanup_intent_temporaries(paths)?;
        return Ok(());
    }

    let (temporary_json, temporary_hash) = intent_temporaries(paths)?;
    if let Some(json) = final_json.as_ref() {
        for candidate in &temporary_hash {
            let hash = read_private_bounded(candidate, 65)?;
            if checksum_matches(json, &hash) {
                fs::rename(candidate, &paths.restore_intent_sha256)?;
                sync_directory(&paths.root)?;
                cleanup_intent_temporaries(paths)?;
                return Ok(());
            }
        }
    }
    if let Some(hash) = final_hash.as_ref() {
        for candidate in &temporary_json {
            let json = read_private_bounded(candidate, MAX_INTENT_BYTES)?;
            if checksum_matches(&json, hash) {
                fs::rename(candidate, &paths.restore_intent)?;
                sync_directory(&paths.root)?;
                cleanup_intent_temporaries(paths)?;
                return Ok(());
            }
        }
    }
    Err(PlatformError::Corrupt("restore_intent_checksum"))
}

fn read_optional_private(path: &Path, max_bytes: usize) -> PlatformResult<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_private_bounded(path, max_bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn checksum_matches(json: &[u8], hash: &[u8]) -> bool {
    hash == format!("{}\n", digest_bytes(json)).as_bytes()
}

fn intent_temporaries(paths: &PrivateAppPaths) -> PlatformResult<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut json = Vec::new();
    let mut hashes = Vec::new();
    for entry in fs::read_dir(&paths.root)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(token) = name
            .strip_prefix(".restore-request-")
            .and_then(|value| value.strip_suffix(".json.tmp"))
        {
            validate_temporary_token(token)?;
            json.push(entry.path());
        } else if let Some(token) = name
            .strip_prefix(".restore-request-")
            .and_then(|value| value.strip_suffix(".sha256.tmp"))
        {
            validate_temporary_token(token)?;
            hashes.push(entry.path());
        }
        if json.len() + hashes.len() > 32 {
            return Err(PlatformError::Corrupt("restore_intent_temporary_count"));
        }
    }
    json.sort();
    hashes.sort();
    Ok((json, hashes))
}

fn validate_temporary_token(token: &str) -> PlatformResult<()> {
    if Uuid::parse_str(token)
        .map(|value| value.to_string())
        .map_err(|_| PlatformError::Corrupt("restore_intent_temporary_name"))?
        != token
    {
        return Err(PlatformError::Corrupt("restore_intent_temporary_name"));
    }
    Ok(())
}

fn cleanup_intent_temporaries(paths: &PrivateAppPaths) -> PlatformResult<()> {
    let (json, hashes) = intent_temporaries(paths)?;
    let mut changed = false;
    for path in json.into_iter().chain(hashes) {
        fs::remove_file(path)?;
        changed = true;
    }
    if changed {
        sync_directory(&paths.root)?;
    }
    Ok(())
}

fn read_private_bounded(path: &Path, max_bytes: usize) -> PlatformResult<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() > max_bytes as u64
    {
        return Err(PlatformError::Corrupt("restore_intent_identity"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn remove_intent(paths: &PrivateAppPaths) -> PlatformResult<()> {
    for path in [&paths.restore_intent, &paths.restore_intent_sha256] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    sync_directory(&paths.root)
}

fn operation_directory(paths: &PrivateAppPaths, operation_id: &str) -> PathBuf {
    paths.restore.join(operation_id)
}

fn restore_has_mutations(paths: &PrivateAppPaths, intent: &RestoreIntentV1) -> bool {
    operation_directory(paths, &intent.operation_id).exists()
}

fn database_family(database: &Path) -> [(PathBuf, &'static str); 3] {
    [
        (database.to_path_buf(), "wardrobe.sqlite3"),
        (path_with_suffix(database, "-wal"), "wardrobe.sqlite3-wal"),
        (path_with_suffix(database, "-shm"), "wardrobe.sqlite3-shm"),
    ]
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn create_private_directory(path: &Path) -> PlatformResult<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(PlatformError::Corrupt("restore_directory_identity"));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if fs::symlink_metadata(path)?.mode() & 0o077 != 0 {
        return Err(PlatformError::Corrupt("restore_directory_identity"));
    }
    Ok(())
}

fn copy_private_file(
    source: &Path,
    destination: &Path,
    expected_hash: &str,
    expected_length: u64,
) -> PlatformResult<()> {
    let mut source_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    let source_metadata = source_file.metadata()?;
    if !source_metadata.file_type().is_file()
        || source_metadata.nlink() != 1
        || source_metadata.mode() & 0o077 != 0
        || source_metadata.len() != expected_length
    {
        return Err(PlatformError::Corrupt("restore_source_identity"));
    }
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)?;
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source_file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        destination_file.write_all(&buffer[..read])?;
        copied = copied
            .checked_add(read as u64)
            .ok_or(PlatformError::Corrupt("restore_source_length"))?;
    }
    if copied != expected_length {
        return Err(PlatformError::Corrupt("restore_source_length"));
    }
    destination_file.sync_all()?;
    drop(destination_file);
    if hash_private_file(destination, Some(expected_length))? != expected_hash {
        return Err(PlatformError::Corrupt("restore_source_hash"));
    }
    Ok(())
}

fn restore_quarantined_blobs(source_root: &Path, blob_root: &Path) -> PlatformResult<()> {
    for first in fs::read_dir(source_root)? {
        let first = first?;
        if !first.file_type()?.is_dir() {
            return Err(PlatformError::Corrupt("restore_blob_quarantine"));
        }
        let destination_first = blob_root.join(first.file_name());
        create_private_directory(&destination_first)?;
        for second in fs::read_dir(first.path())? {
            let second = second?;
            if !second.file_type()?.is_dir() {
                return Err(PlatformError::Corrupt("restore_blob_quarantine"));
            }
            let destination_second = destination_first.join(second.file_name());
            create_private_directory(&destination_second)?;
            for old in fs::read_dir(second.path())? {
                let old = old?;
                if !old.file_type()?.is_file() {
                    return Err(PlatformError::Corrupt("restore_blob_quarantine"));
                }
                let destination = destination_second.join(old.file_name());
                if destination.exists() {
                    fs::remove_file(&destination)?;
                }
                fs::rename(old.path(), destination)?;
            }
            sync_directory(&destination_second)?;
        }
        sync_directory(&destination_first)?;
    }
    Ok(())
}

fn validate_hash(hash: &str) -> PlatformResult<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlatformError::Corrupt("restore_sha256"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BackupReason, BackupRepository, Database};
    use rusqlite::params;
    use std::process::Command;

    const HELPER_ROOT: &str = "WARDROBE_RESTORE_HELPER_ROOT";

    fn prepare_upgrade_fixture() -> (
        tempfile::TempDir,
        PrivateAppPaths,
        VerifiedBackup,
        UpgradeRecoveryIntentV1,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        Database::open(&paths, 1_000).unwrap();
        let record = BackupRepository::new(&paths)
            .create(BackupReason::PreUpgrade, 2_000)
            .unwrap();
        let backup = BackupRepository::new(&paths)
            .verify(
                &record.backup_id.to_string(),
                Some(record.manifest_sha256.as_str()),
            )
            .unwrap();
        let source_version = backup.manifest.database.schema_version;
        let source_prefix = backup.manifest.database.migration_prefix_sha256.clone();
        RestoreRepository::new(&paths)
            .prepare_upgrade_recovery(
                &backup,
                source_version,
                &source_prefix,
                source_version + 1,
                3_000,
            )
            .unwrap();
        let intent = read_upgrade_intent(&paths).unwrap();
        (temporary, paths, backup, intent)
    }

    #[test]
    fn upgrade_recovery_restores_exact_managed_source_without_normalization() {
        let (_temporary, paths, backup, intent) = prepare_upgrade_fixture();
        let connection = rusqlite::Connection::open(&paths.database).unwrap();
        connection
            .execute(
                "INSERT OR REPLACE INTO settings(setting_key, value_json, updated_at_ms)
                 VALUES ('upgrade-probe', '\"changed\"', 4000)",
                [],
            )
            .unwrap();
        drop(connection);

        assert!(RestoreRepository::new(&paths)
            .recover_interrupted_upgrade()
            .unwrap());
        assert_eq!(
            hash_private_file(&paths.database, Some(backup.manifest.database.byte_length)).unwrap(),
            backup.manifest.database.sha256
        );
        database::verify_upgrade_source_database(
            &paths.database,
            &intent.source_database_sha256,
            intent.source_database_length,
            intent.source_schema_version,
            &intent.source_migration_prefix_sha256,
        )
        .unwrap();
        assert!(!paths.upgrade_recovery_intent.exists());
        assert!(!paths.upgrade_recovery_intent_sha256.exists());
        assert!(!upgrade_operation_directory(&paths, &intent.operation_id).exists());
    }

    #[test]
    fn upgrade_recovery_resumes_after_source_publish_before_phase_write() {
        let (_temporary, paths, _backup, intent) = prepare_upgrade_fixture();
        let operation = upgrade_operation_directory(&paths, &intent.operation_id);
        let quarantine = operation.join("failed-live");
        create_private_directory(&quarantine).unwrap();
        quarantine_database_family(&paths.database, &quarantine).unwrap();
        let staged = operation.join("source.sqlite3.staged");
        fs::rename(&staged, &paths.database).unwrap();
        sync_directory(paths.database.parent().unwrap()).unwrap();

        assert!(RestoreRepository::new(&paths)
            .recover_interrupted_upgrade()
            .unwrap());
        database::verify_upgrade_source_database(
            &paths.database,
            &intent.source_database_sha256,
            intent.source_database_length,
            intent.source_schema_version,
            &intent.source_migration_prefix_sha256,
        )
        .unwrap();
        assert!(!paths.upgrade_recovery_intent.exists());
    }

    #[test]
    fn verified_upgrade_recovery_cleans_up_after_checksum_removal_crash() {
        let (_temporary, paths, _backup, mut intent) = prepare_upgrade_fixture();
        let operation = upgrade_operation_directory(&paths, &intent.operation_id);
        let quarantine = operation.join("failed-live");
        create_private_directory(&quarantine).unwrap();
        quarantine_database_family(&paths.database, &quarantine).unwrap();
        let staged = operation.join("source.sqlite3.staged");
        fs::rename(&staged, &paths.database).unwrap();
        sync_directory(paths.database.parent().unwrap()).unwrap();
        intent.phase = UpgradeRecoveryPhase::Verified;
        write_upgrade_intent(&paths, &intent, false).unwrap();
        fs::remove_file(&paths.upgrade_recovery_intent_sha256).unwrap();
        sync_directory(&paths.restore).unwrap();

        assert!(RestoreRepository::new(&paths)
            .recover_interrupted_upgrade()
            .unwrap());
        database::verify_upgrade_source_database(
            &paths.database,
            &intent.source_database_sha256,
            intent.source_database_length,
            intent.source_schema_version,
            &intent.source_migration_prefix_sha256,
        )
        .unwrap();
        assert!(!paths.upgrade_recovery_intent.exists());
        assert!(!operation.exists());
    }

    #[test]
    fn upgrade_recovery_rejects_tampered_staging_without_touching_live() {
        let (_temporary, paths, _backup, intent) = prepare_upgrade_fixture();
        let staged =
            upgrade_operation_directory(&paths, &intent.operation_id).join("source.sqlite3.staged");
        let live_before = hash_private_file(&paths.database, None).unwrap();
        fs::write(&staged, b"tampered").unwrap();

        assert!(RestoreRepository::new(&paths)
            .recover_interrupted_upgrade()
            .is_err());
        assert_eq!(
            hash_private_file(&paths.database, None).unwrap(),
            live_before
        );
        assert!(paths.upgrade_recovery_intent.exists());
        assert!(staged.exists());
    }

    #[test]
    fn active_upgrade_recovery_intent_pins_managed_backup() {
        let (_temporary, paths, backup, intent) = prepare_upgrade_fixture();
        assert_eq!(
            BackupRepository::new(&paths)
                .cleanup_expired(100 * 24 * 60 * 60 * 1_000)
                .unwrap(),
            0
        );
        assert!(backup.package_path.exists());

        let mut verified = intent;
        verified.phase = UpgradeRecoveryPhase::Verified;
        write_upgrade_intent(&paths, &verified, false).unwrap();
        cleanup_verified_upgrade_recovery(&paths, &verified).unwrap();
        assert_eq!(
            BackupRepository::new(&paths)
                .cleanup_expired(100 * 24 * 60 * 60 * 1_000)
                .unwrap(),
            1
        );
        assert!(!backup.package_path.exists());
    }

    #[test]
    fn interrupted_upgrade_recovers_before_pending_user_restore() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        Database::open(&paths, 1_000).unwrap();
        let connection = rusqlite::Connection::open(&paths.database).unwrap();
        connection
            .execute(
                "INSERT INTO settings(setting_key, value_json, updated_at_ms)
                 VALUES ('recovery-order', '\"before\"', 1000)",
                [],
            )
            .unwrap();
        drop(connection);
        let user_backup = BackupRepository::new(&paths)
            .create(BackupReason::Manual, 2_000)
            .unwrap();

        rusqlite::Connection::open(&paths.database)
            .unwrap()
            .execute(
                "UPDATE settings SET value_json = '\"after\"', updated_at_ms = 3000
                 WHERE setting_key = 'recovery-order'",
                [],
            )
            .unwrap();
        let upgrade_record = BackupRepository::new(&paths)
            .create(BackupReason::PreUpgrade, 4_000)
            .unwrap();
        let upgrade_backup = BackupRepository::new(&paths)
            .verify(
                &upgrade_record.backup_id.to_string(),
                Some(upgrade_record.manifest_sha256.as_str()),
            )
            .unwrap();
        RestoreRepository::new(&paths)
            .prepare_upgrade_recovery(
                &upgrade_backup,
                upgrade_backup.manifest.database.schema_version,
                &upgrade_backup.manifest.database.migration_prefix_sha256,
                upgrade_backup.manifest.database.schema_version + 1,
                5_000,
            )
            .unwrap();
        RestoreRepository::new(&paths)
            .prepare(user_backup.backup_id, &user_backup.manifest_sha256, 6_000)
            .unwrap();
        rusqlite::Connection::open(&paths.database)
            .unwrap()
            .execute(
                "UPDATE settings SET value_json = '\"failed-target\"', updated_at_ms = 7000
                 WHERE setting_key = 'recovery-order'",
                [],
            )
            .unwrap();

        Database::open(&paths, 8_000).unwrap();
        assert_eq!(
            rusqlite::Connection::open(&paths.database)
                .unwrap()
                .query_row(
                    "SELECT value_json FROM settings WHERE setting_key = 'recovery-order'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "\"before\""
        );
        assert!(!paths.upgrade_recovery_intent.exists());
        assert!(!paths.restore_intent.exists());
    }

    fn setup_restore() -> (
        tempfile::TempDir,
        PrivateAppPaths,
        wardrobe_core::BackupRecordV1,
        String,
        Vec<u8>,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1_000).unwrap();
        let bytes = b"restore-asset".to_vec();
        let blob = BlobStore::new(&paths).put(&bytes, None, 1_024).unwrap();
        let connection = database.connection().unwrap();
        connection
            .execute(
                "INSERT INTO blobs(sha256, byte_length, created_at_ms)
                 VALUES (?1, ?2, 1000)",
                params![blob.sha256, blob.byte_length as i64],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO settings(setting_key, value_json, updated_at_ms)
                 VALUES ('restore_probe', '\"before\"', 1000)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO credential_references(
                    locator, credential_id, save_request_id, delete_request_id,
                    provider, display_label, status, created_at_ms, updated_at_ms
                 ) VALUES (
                    'wardrobe:test:restore', 'restore-credential', 'save-restore',
                    'delete-restore', 'open_ai', 'Restore credential',
                    'pending_delete', 1000, 1000
                 )",
                [],
            )
            .unwrap();
        drop(connection);
        let backup = BackupRepository::new(&paths)
            .create(BackupReason::Manual, 2_000)
            .unwrap();
        (temporary, paths, backup, blob.sha256, bytes)
    }

    #[test]
    fn child_process_restart_restores_catalog_assets_and_database_family() {
        let (_temporary, paths, backup, hash, bytes) = setup_restore();
        let connection = rusqlite::Connection::open(&paths.database).unwrap();
        connection
            .execute(
                "UPDATE settings
                 SET value_json = '\"after\"', updated_at_ms = 3000
                 WHERE setting_key = 'restore_probe'",
                [],
            )
            .unwrap();
        drop(connection);

        let prepared = RestoreRepository::new(&paths)
            .prepare(backup.backup_id, &backup.manifest_sha256, 4_000)
            .unwrap();
        assert!(prepared.restart_required);

        let active_asset = BlobStore::new(&paths).path_for_hash(&hash).unwrap();
        fs::write(&active_asset, b"corrupt").unwrap();
        for sidecar in [
            path_with_suffix(&paths.database, "-wal"),
            path_with_suffix(&paths.database, "-shm"),
        ] {
            if sidecar.exists() {
                fs::remove_file(&sidecar).unwrap();
            }
            write_private_file(&sidecar, b"stale-sidecar").unwrap();
        }

        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("restore_repository::tests::restart_helper")
            .arg("--ignored")
            .arg("--nocapture")
            .env(HELPER_ROOT, &paths.root)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "restart helper failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );

        assert_eq!(fs::read(active_asset).unwrap(), bytes);
        assert!(!paths.restore_intent.exists());
        assert!(!paths.restore_intent_sha256.exists());
        assert_eq!(fs::read_dir(&paths.restore).unwrap().count(), 0);
        let connection = rusqlite::Connection::open(&paths.database).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT value_json FROM settings WHERE setting_key = 'restore_probe'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "\"before\""
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM credential_references
                     WHERE credential_id = 'restore-credential'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "save_failed"
        );
    }

    #[test]
    #[ignore = "invoked as a child process by the restart smoke test"]
    fn restart_helper() {
        let root = std::env::var_os(HELPER_ROOT).expect("helper root");
        let paths = PrivateAppPaths::create(PathBuf::from(root)).unwrap();
        Database::open(&paths, 5_000).unwrap();
    }

    #[test]
    fn pending_restore_pins_selected_and_safety_backups_from_retention() {
        let (_temporary, paths, backup, _hash, _bytes) = setup_restore();
        let prepared = RestoreRepository::new(&paths)
            .prepare(backup.backup_id, &backup.manifest_sha256, 4_000)
            .unwrap();
        assert_eq!(
            BackupRepository::new(&paths)
                .cleanup_expired(100 * 24 * 60 * 60 * 1_000)
                .unwrap(),
            0
        );
        assert!(paths.backups.join(backup.backup_id.to_string()).exists());
        assert!(paths
            .backups
            .join(prepared.safety_backup_id.to_string())
            .exists());
    }

    #[test]
    fn rejects_checksummed_intent_tampering_before_live_changes() {
        let (_temporary, paths, backup, _hash, _bytes) = setup_restore();
        RestoreRepository::new(&paths)
            .prepare(backup.backup_id, &backup.manifest_sha256, 4_000)
            .unwrap();
        fs::write(
            &paths.restore_intent_sha256,
            format!("{}\n", "0".repeat(64)),
        )
        .unwrap();

        assert!(matches!(
            RestoreRepository::new(&paths).apply_pending(5_000),
            Err(PlatformError::Corrupt("restore_intent_checksum"))
        ));
        assert!(paths.database.exists());
        assert_eq!(fs::read_dir(&paths.restore).unwrap().count(), 0);
    }

    #[test]
    fn recovers_json_new_hash_old_intent_transition() {
        let (_temporary, paths, backup, _hash, _bytes) = setup_restore();
        RestoreRepository::new(&paths)
            .prepare(backup.backup_id, &backup.manifest_sha256, 4_000)
            .unwrap();
        let mut next = read_intent(&paths).unwrap();
        next.phase = RestorePhase::AssetsInstalled;
        publish_one_intent_half(&paths, &next, true);

        let recovered = read_intent(&paths).unwrap();
        assert_eq!(recovered.phase, RestorePhase::AssetsInstalled);
        assert!(checksum_matches(
            &fs::read(&paths.restore_intent).unwrap(),
            &fs::read(&paths.restore_intent_sha256).unwrap()
        ));
        assert!(intent_temporaries(&paths)
            .unwrap()
            .0
            .into_iter()
            .chain(intent_temporaries(&paths).unwrap().1)
            .next()
            .is_none());
    }

    #[test]
    fn recovers_hash_new_json_old_intent_transition() {
        let (_temporary, paths, backup, _hash, _bytes) = setup_restore();
        RestoreRepository::new(&paths)
            .prepare(backup.backup_id, &backup.manifest_sha256, 4_000)
            .unwrap();
        let mut next = read_intent(&paths).unwrap();
        next.phase = RestorePhase::LiveQuarantined;
        publish_one_intent_half(&paths, &next, false);

        let recovered = read_intent(&paths).unwrap();
        assert_eq!(recovered.phase, RestorePhase::LiveQuarantined);
        assert!(checksum_matches(
            &fs::read(&paths.restore_intent).unwrap(),
            &fs::read(&paths.restore_intent_sha256).unwrap()
        ));
        let temporaries = intent_temporaries(&paths).unwrap();
        assert!(temporaries.0.is_empty() && temporaries.1.is_empty());
    }

    #[test]
    fn empty_rollback_directory_never_removes_live_database_family() {
        let (_temporary, paths, backup, _hash, _bytes) = setup_restore();
        RestoreRepository::new(&paths)
            .prepare(backup.backup_id, &backup.manifest_sha256, 4_000)
            .unwrap();
        let intent = read_intent(&paths).unwrap();
        let operation = operation_directory(&paths, &intent.operation_id);
        create_private_directory(&operation).unwrap();
        create_private_directory(&operation.join("database")).unwrap();
        let before = hash_private_file(&paths.database, None).unwrap();

        RestoreRepository::new(&paths)
            .rollback_locked(&intent)
            .unwrap();

        assert!(paths.database.exists());
        assert_eq!(hash_private_file(&paths.database, None).unwrap(), before);
        assert_eq!(
            rusqlite::Connection::open(&paths.database)
                .unwrap()
                .query_row(
                    "SELECT value_json FROM settings WHERE setting_key = 'restore_probe'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "\"before\""
        );
    }

    fn publish_one_intent_half(
        paths: &PrivateAppPaths,
        intent: &RestoreIntentV1,
        publish_json: bool,
    ) {
        let bytes = serde_json::to_vec(intent).unwrap();
        let token = Uuid::new_v4();
        let json_temporary = paths
            .root
            .join(format!(".restore-request-{token}.json.tmp"));
        let hash_temporary = paths
            .root
            .join(format!(".restore-request-{token}.sha256.tmp"));
        write_private_file(&json_temporary, &bytes).unwrap();
        write_private_file(
            &hash_temporary,
            format!("{}\n", digest_bytes(&bytes)).as_bytes(),
        )
        .unwrap();
        if publish_json {
            fs::rename(json_temporary, &paths.restore_intent).unwrap();
        } else {
            fs::rename(hash_temporary, &paths.restore_intent_sha256).unwrap();
        }
        sync_directory(&paths.root).unwrap();
    }
}
