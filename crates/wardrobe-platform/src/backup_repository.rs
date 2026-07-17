use crate::blob::sync_directory;
use crate::database;
use crate::{BlobStore, PlatformError, PlatformResult, PrivateAppPaths};
use rusqlite::backup::Backup;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;
use wardrobe_core::{
    BackupId, BackupReasonV1, BackupRecordV1, DeletionBackupRetentionV1, DeletionTargetKindV1,
    Sha256Digest,
};

pub const BACKUP_FORMAT_VERSION: u8 = 1;
const ASSET_MANIFEST_VERSION: u8 = 1;
const APPLICATION_IDENTIFIER: &str = "com.wardrobe.desktop";
const MAX_ASSETS: usize = 100_000;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BACKUP_BYTES: u64 = 512 * 1024 * 1024 * 1024;
const DAY_MS: i64 = 24 * 60 * 60 * 1_000;

static MAINTENANCE_GATE: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) type MaintenanceGuard = MutexGuard<'static, ()>;

pub(crate) fn lock_maintenance() -> PlatformResult<MaintenanceGuard> {
    MAINTENANCE_GATE
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| PlatformError::Conflict("maintenance_gate_poisoned"))
}

pub type BackupReason = BackupReasonV1;
pub type BackupRecord = BackupRecordV1;

#[derive(Clone, Debug)]
pub struct VerifiedBackup {
    pub record: BackupRecord,
    pub(crate) package_path: PathBuf,
    pub(crate) manifest: BackupManifestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupAssetV1 {
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupDatabaseV1 {
    pub sha256: String,
    pub byte_length: u64,
    pub schema_version: u32,
    pub migration_prefix_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackupManifestV1 {
    pub application_identifier: String,
    pub format_version: u8,
    pub asset_manifest_version: u8,
    pub backup_id: String,
    pub reason: BackupReason,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub database: BackupDatabaseV1,
    pub assets: Vec<BackupAssetV1>,
}

#[derive(Clone, Debug)]
pub struct BackupRepository {
    paths: PrivateAppPaths,
}

impl BackupRepository {
    pub fn new(paths: &PrivateAppPaths) -> Self {
        Self {
            paths: paths.clone(),
        }
    }

    pub fn create(&self, reason: BackupReason, now_ms: i64) -> PlatformResult<BackupRecord> {
        let guard = lock_maintenance()?;
        self.create_locked(reason, now_ms, &guard)
    }

    pub fn create_scheduled_if_due(&self, now_ms: i64) -> PlatformResult<Option<BackupRecord>> {
        if now_ms < 0 {
            return Err(PlatformError::InvalidInput("backup_created_at"));
        }
        let guard = lock_maintenance()?;
        self.cleanup_staging_locked()?;
        let mut newest_scheduled = None;
        for entry in fs::read_dir(&self.paths.backups)? {
            let entry = entry?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if Uuid::parse_str(&id).is_err() {
                continue;
            }
            let Ok(verified) = self.verify_by_id(&id, None) else {
                continue;
            };
            if verified.manifest.reason == BackupReason::Scheduled {
                newest_scheduled = Some(
                    newest_scheduled
                        .unwrap_or(i64::MIN)
                        .max(verified.manifest.created_at_ms),
                );
            }
        }
        if newest_scheduled.is_some_and(|created_at| now_ms.saturating_sub(created_at) < DAY_MS) {
            return Ok(None);
        }
        self.create_locked(BackupReason::Scheduled, now_ms, &guard)
            .map(Some)
    }

    pub(crate) fn create_locked(
        &self,
        reason: BackupReason,
        now_ms: i64,
        _guard: &MaintenanceGuard,
    ) -> PlatformResult<BackupRecord> {
        if now_ms < 0 {
            return Err(PlatformError::InvalidInput("backup_created_at"));
        }
        self.cleanup_staging_locked()?;
        let backup_id = Uuid::new_v4().to_string();
        let staging = self.paths.backup_staging.join(&backup_id);
        create_private_directory_new(&staging)?;

        let result = self.build_package(&staging, &backup_id, reason, now_ms);
        if result.is_err() {
            let _ = remove_entry(&staging);
            let _ = sync_directory(&self.paths.backup_staging);
        }
        result
    }

    fn build_package(
        &self,
        staging: &Path,
        backup_id: &str,
        reason: BackupReason,
        now_ms: i64,
    ) -> PlatformResult<BackupRecord> {
        let database_path = staging.join("catalog.sqlite3");
        snapshot_database(&self.paths.database, &database_path)?;
        let snapshot = open_readonly_database(&database_path)?;
        database::verify_database(&snapshot)?;
        let schema_version = database::database_schema_version(&snapshot)?;
        let migration_prefix_sha256 = database::migration_prefix_sha256(schema_version)?;
        let assets = read_database_assets(&snapshot)?;
        drop(snapshot);

        let assets_root = staging.join("assets");
        create_private_directory_new(&assets_root)?;
        let blob_store = BlobStore::new(&self.paths);
        let mut asset_bytes = 0_u64;
        for asset in &assets {
            asset_bytes = asset_bytes
                .checked_add(asset.byte_length)
                .ok_or(PlatformError::InvalidInput("backup_total_bytes"))?;
            if asset_bytes > MAX_BACKUP_BYTES {
                return Err(PlatformError::InvalidInput("backup_total_bytes"));
            }
            let source = blob_store.path_for_hash(&asset.sha256)?;
            let first = assets_root.join(&asset.sha256[0..2]);
            let second = first.join(&asset.sha256[2..4]);
            create_private_directory(&first)?;
            create_private_directory(&second)?;
            copy_verified_file(
                &source,
                &second.join(&asset.sha256),
                &asset.sha256,
                asset.byte_length,
            )?;
        }
        sync_asset_directories(&assets_root, &assets)?;

        let database_length = private_file_metadata(&database_path)?.len();
        let database_sha256 = hash_private_file(&database_path, Some(database_length))?;
        let expires_at_ms = now_ms
            .checked_add(retention_ms(reason))
            .ok_or(PlatformError::InvalidInput("backup_expires_at"))?;
        let manifest = BackupManifestV1 {
            application_identifier: APPLICATION_IDENTIFIER.to_owned(),
            format_version: BACKUP_FORMAT_VERSION,
            asset_manifest_version: ASSET_MANIFEST_VERSION,
            backup_id: backup_id.to_owned(),
            reason,
            created_at_ms: now_ms,
            expires_at_ms,
            database: BackupDatabaseV1 {
                sha256: database_sha256,
                byte_length: database_length,
                schema_version,
                migration_prefix_sha256,
            },
            assets,
        };
        validate_manifest(&manifest)?;
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(PlatformError::InvalidInput("backup_manifest_size"));
        }
        let manifest_sha256 = digest_bytes(&manifest_bytes);
        write_private_file(&staging.join("manifest.json"), &manifest_bytes)?;
        write_private_file(
            &staging.join("manifest.sha256"),
            format!("{manifest_sha256}\n").as_bytes(),
        )?;
        sync_directory(staging)?;

        let final_path = self.paths.backups.join(backup_id);
        fs::rename(staging, &final_path)?;
        sync_directory(&self.paths.backup_staging)?;
        sync_directory(&self.paths.backups)?;

        let verified = self.verify_by_id(backup_id, Some(&manifest_sha256))?;
        Ok(verified.record)
    }

    pub fn list_verified(
        &self,
        cursor: Option<&str>,
        limit: usize,
    ) -> PlatformResult<Vec<BackupRecord>> {
        if limit == 0 || limit > 100 {
            return Err(PlatformError::InvalidInput("backup_limit"));
        }
        let _guard = lock_maintenance()?;
        self.cleanup_staging_locked()?;
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.paths.backups)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(id) = name.to_str() else {
                continue;
            };
            if Uuid::parse_str(id).is_err() {
                continue;
            }
            if let Ok(verified) = self.verify_by_id(id, None) {
                records.push(verified.record);
            }
        }
        records.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.backup_id.cmp(&left.backup_id))
        });
        let start = match cursor {
            None => 0,
            Some(cursor) => records
                .iter()
                .position(|record| record.backup_id.to_string() == cursor)
                .map(|index| index + 1)
                .ok_or(PlatformError::InvalidInput("backup_cursor"))?,
        };
        Ok(records.into_iter().skip(start).take(limit).collect())
    }

    pub(crate) fn count_verified_readonly(&self) -> PlatformResult<u64> {
        let _guard = lock_maintenance()?;
        let mut count = 0_u64;
        for entry in fs::read_dir(&self.paths.backups)? {
            let entry = entry?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if Uuid::parse_str(&id).is_ok() && self.verify_by_id(&id, None).is_ok() {
                count = count
                    .checked_add(1)
                    .ok_or(PlatformError::Corrupt("backup_count"))?;
            }
        }
        Ok(count)
    }

    pub fn verify(
        &self,
        backup_id: &str,
        expected_manifest_sha256: Option<&str>,
    ) -> PlatformResult<VerifiedBackup> {
        let _guard = lock_maintenance()?;
        self.verify_by_id(backup_id, expected_manifest_sha256)
    }

    pub(crate) fn verify_locked(
        &self,
        backup_id: &str,
        expected_manifest_sha256: Option<&str>,
        _guard: &MaintenanceGuard,
    ) -> PlatformResult<VerifiedBackup> {
        self.verify_by_id(backup_id, expected_manifest_sha256)
    }

    pub(crate) fn deletion_retention_locked(
        &self,
        target_kind: DeletionTargetKindV1,
        target_id: &str,
        unique_blobs: &BTreeSet<String>,
        _guard: &MaintenanceGuard,
    ) -> PlatformResult<Vec<DeletionBackupRetentionV1>> {
        let mut reports = Vec::new();
        for entry in fs::read_dir(&self.paths.backups)? {
            let entry = entry?;
            let Some(backup_id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if Uuid::parse_str(&backup_id).is_err() {
                continue;
            }
            let verified = self.verify_by_id(&backup_id, None)?;
            let snapshot = open_readonly_database(&verified.package_path.join("catalog.sqlite3"))?;
            let target_table = match target_kind {
                DeletionTargetKindV1::ImportRoot => ("import_roots", "root_id"),
                DeletionTargetKindV1::Source => ("local_sources", "source_id"),
                DeletionTargetKindV1::Item => ("catalog_items", "item_id"),
                DeletionTargetKindV1::PurchaseUnit => {
                    ("receipt_purchase_unit_promotions", "purchase_unit_id")
                }
                DeletionTargetKindV1::ReceiptPurchaseUnitEvidence => ("evidence", "evidence_id"),
                DeletionTargetKindV1::PhotoKitEnrollment => {
                    ("photokit_enrollments", "enrollment_epoch")
                }
                DeletionTargetKindV1::PhotoKitAsset => ("photokit_assets", "asset_id"),
            };
            let mut target_retained = table_exists(&snapshot, target_table.0)?
                && snapshot.query_row(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM {} WHERE {} = ?1)",
                        target_table.0, target_table.1
                    ),
                    [target_id],
                    |row| row.get::<_, bool>(0),
                )?;
            if target_kind == DeletionTargetKindV1::PurchaseUnit
                && table_exists(&snapshot, "receipt_purchase_unit_deletions")?
            {
                target_retained |= snapshot.query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM receipt_purchase_unit_deletions
                        WHERE purchase_unit_id=?1
                     )",
                    [target_id],
                    |row| row.get::<_, bool>(0),
                )?;
            }
            let blob_retained = if table_exists(&snapshot, "blobs")? {
                let mut statement =
                    snapshot.prepare("SELECT EXISTS(SELECT 1 FROM blobs WHERE sha256 = ?1)")?;
                unique_blobs.iter().try_fold(false, |retained, hash| {
                    Ok::<_, rusqlite::Error>(
                        retained || statement.query_row([hash], |row| row.get::<_, bool>(0))?,
                    )
                })?
            } else {
                false
            };
            if target_retained || blob_retained {
                reports.push(DeletionBackupRetentionV1 {
                    backup_id: BackupId::new(
                        Uuid::parse_str(&backup_id)
                            .map_err(|_| PlatformError::Corrupt("backup_id"))?,
                    )
                    .map_err(|_| PlatformError::Corrupt("backup_id"))?,
                    reason: verified.manifest.reason,
                    expires_at: format_timestamp(verified.manifest.expires_at_ms)?,
                });
            }
        }
        reports.sort_by_key(|report| report.backup_id);
        if reports.len() > wardrobe_core::MAX_DELETION_RETENTION_REPORTS {
            return Err(PlatformError::InvalidInput("deletion_backup_retention"));
        }
        Ok(reports)
    }

    fn verify_by_id(
        &self,
        backup_id: &str,
        expected_manifest_sha256: Option<&str>,
    ) -> PlatformResult<VerifiedBackup> {
        let parsed_id =
            Uuid::parse_str(backup_id).map_err(|_| PlatformError::InvalidInput("backup_id"))?;
        if parsed_id.to_string() != backup_id {
            return Err(PlatformError::InvalidInput("backup_id"));
        }
        if let Some(expected) = expected_manifest_sha256 {
            validate_hash(expected)?;
        }

        let package = self.paths.backups.join(backup_id);
        verify_private_directory(&package)?;
        let manifest_path = package.join("manifest.json");
        let manifest_metadata = private_file_metadata(&manifest_path)?;
        if manifest_metadata.len() > MAX_MANIFEST_BYTES {
            return Err(PlatformError::Corrupt("backup_manifest_size"));
        }
        let manifest_bytes = fs::read(&manifest_path)?;
        let actual_manifest_sha256 = digest_bytes(&manifest_bytes);
        if expected_manifest_sha256.is_some_and(|expected| expected != actual_manifest_sha256) {
            return Err(PlatformError::Conflict("backup_manifest_changed"));
        }
        let sidecar = read_small_private_file(&package.join("manifest.sha256"), 65)?;
        if sidecar != format!("{actual_manifest_sha256}\n").as_bytes() {
            return Err(PlatformError::Corrupt("backup_manifest_sidecar"));
        }
        let manifest: BackupManifestV1 = serde_json::from_slice(&manifest_bytes)?;
        validate_manifest(&manifest)?;
        if serde_json::to_vec(&manifest)? != manifest_bytes {
            return Err(PlatformError::Corrupt("backup_manifest_canonical"));
        }
        if manifest.backup_id != backup_id {
            return Err(PlatformError::Corrupt("backup_manifest_id"));
        }

        let database_path = package.join("catalog.sqlite3");
        let database_sha256 =
            hash_private_file(&database_path, Some(manifest.database.byte_length))?;
        if database_sha256 != manifest.database.sha256 {
            return Err(PlatformError::Corrupt("backup_database_hash"));
        }
        let connection = open_readonly_database(&database_path)?;
        database::verify_database(&connection)?;
        let schema_version = database::database_schema_version(&connection)?;
        if schema_version != manifest.database.schema_version {
            return Err(PlatformError::Corrupt("backup_database_schema"));
        }
        if database::migration_prefix_sha256(schema_version)?
            != manifest.database.migration_prefix_sha256
        {
            return Err(PlatformError::Corrupt("backup_migration_prefix"));
        }
        let database_assets = read_database_assets(&connection)?;
        drop(connection);
        if database_assets != manifest.assets {
            return Err(PlatformError::Corrupt("backup_asset_manifest"));
        }
        verify_asset_tree(&package.join("assets"), &manifest.assets)?;
        verify_package_entries(&package)?;

        let asset_bytes = manifest.assets.iter().try_fold(0_u64, |total, asset| {
            total
                .checked_add(asset.byte_length)
                .ok_or(PlatformError::Corrupt("backup_total_bytes"))
        })?;
        let total_bytes = manifest
            .database
            .byte_length
            .checked_add(asset_bytes)
            .ok_or(PlatformError::Corrupt("backup_total_bytes"))?;
        Ok(VerifiedBackup {
            record: BackupRecord {
                backup_id: BackupId::new(
                    Uuid::parse_str(&manifest.backup_id)
                        .map_err(|_| PlatformError::Corrupt("backup_manifest_id"))?,
                )
                .map_err(|_| PlatformError::Corrupt("backup_manifest_id"))?,
                reason: manifest.reason,
                created_at: format_timestamp(manifest.created_at_ms)?,
                expires_at: format_timestamp(manifest.expires_at_ms)?,
                manifest_sha256: Sha256Digest::parse(actual_manifest_sha256)
                    .map_err(|_| PlatformError::Corrupt("backup_manifest_hash"))?,
                database_schema_version: manifest.database.schema_version,
                asset_count: manifest.assets.len() as u64,
                total_bytes,
            },
            package_path: package,
            manifest,
        })
    }

    pub fn cleanup_expired(&self, now_ms: i64) -> PlatformResult<usize> {
        let _guard = lock_maintenance()?;
        self.cleanup_staging_locked()?;
        let pins = read_restore_pins(&self.paths)?;
        let mut removed = 0;
        for entry in fs::read_dir(&self.paths.backups)? {
            let entry = entry?;
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if Uuid::parse_str(&id).is_err() || pins.contains(&id) {
                continue;
            }
            let Ok(verified) = self.verify_by_id(&id, None) else {
                continue;
            };
            if verified.manifest.expires_at_ms > now_ms {
                continue;
            }
            let trash = self
                .paths
                .backup_trash
                .join(format!("{}-{}", id, Uuid::new_v4()));
            fs::rename(&verified.package_path, &trash)?;
            sync_directory(&self.paths.backups)?;
            sync_directory(&self.paths.backup_trash)?;
            remove_entry(&trash)?;
            sync_directory(&self.paths.backup_trash)?;
            removed += 1;
        }
        Ok(removed)
    }

    pub(crate) fn cleanup_staging(&self) -> PlatformResult<()> {
        let _guard = lock_maintenance()?;
        self.cleanup_staging_locked()
    }

    fn cleanup_staging_locked(&self) -> PlatformResult<()> {
        for entry in fs::read_dir(&self.paths.backup_staging)? {
            remove_entry(&entry?.path())?;
        }
        sync_directory(&self.paths.backup_staging)
    }
}

fn snapshot_database(source_path: &Path, destination_path: &Path) -> PlatformResult<()> {
    private_file_metadata(source_path)?;
    let source = Connection::open_with_flags(
        source_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    source.busy_timeout(Duration::from_secs(5))?;
    database::verify_database(&source)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination_path)?
        .sync_all()?;
    let mut destination = Connection::open_with_flags(
        destination_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    {
        let backup = Backup::new(&source, &mut destination)?;
        backup.run_to_completion(64, Duration::from_millis(10), None)?;
    }
    database::verify_database(&destination)?;
    destination.execute_batch(
        "PRAGMA wal_checkpoint(TRUNCATE);
         PRAGMA journal_mode = DELETE;",
    )?;
    drop(destination);
    for sidecar in [
        path_with_suffix(destination_path, "-wal"),
        path_with_suffix(destination_path, "-shm"),
    ] {
        match fs::remove_file(sidecar) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    File::open(destination_path)?.sync_all()?;
    Ok(())
}

fn open_readonly_database(path: &Path) -> PlatformResult<Connection> {
    private_file_metadata(path)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;")?;
    Ok(connection)
}

fn table_exists(connection: &Connection, table: &str) -> PlatformResult<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )?)
}

fn read_database_assets(connection: &Connection) -> PlatformResult<Vec<BackupAssetV1>> {
    let has_blobs: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema
             WHERE type = 'table' AND name = 'blobs'
         )",
        [],
        |row| row.get(0),
    )?;
    if !has_blobs {
        return Ok(Vec::new());
    }
    let mut statement =
        connection.prepare("SELECT sha256, byte_length FROM blobs ORDER BY sha256")?;
    let assets = statement
        .query_map([], |row| {
            let byte_length = row.get::<_, i64>(1)?;
            Ok((row.get::<_, String>(0)?, byte_length))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if assets.len() > MAX_ASSETS {
        return Err(PlatformError::InvalidInput("backup_asset_count"));
    }
    let mut result = Vec::with_capacity(assets.len());
    for (sha256, byte_length) in assets {
        validate_hash(&sha256)?;
        result.push(BackupAssetV1 {
            sha256,
            byte_length: u64::try_from(byte_length)
                .map_err(|_| PlatformError::Corrupt("backup_asset_length"))?,
        });
    }
    Ok(result)
}

fn validate_manifest(manifest: &BackupManifestV1) -> PlatformResult<()> {
    if manifest.application_identifier != APPLICATION_IDENTIFIER {
        return Err(PlatformError::Unsupported("backup_application"));
    }
    if manifest.format_version != BACKUP_FORMAT_VERSION {
        return Err(PlatformError::Unsupported("backup_format_version"));
    }
    if manifest.asset_manifest_version != ASSET_MANIFEST_VERSION {
        return Err(PlatformError::Unsupported("backup_asset_manifest_version"));
    }
    if Uuid::parse_str(&manifest.backup_id)
        .map(|id| id.to_string())
        .map_err(|_| PlatformError::Corrupt("backup_manifest_id"))?
        != manifest.backup_id
    {
        return Err(PlatformError::Corrupt("backup_manifest_id"));
    }
    if manifest.created_at_ms < 0
        || manifest.expires_at_ms
            != manifest
                .created_at_ms
                .checked_add(retention_ms(manifest.reason))
                .ok_or(PlatformError::Corrupt("backup_manifest_expiry"))?
    {
        return Err(PlatformError::Corrupt("backup_manifest_expiry"));
    }
    validate_hash(&manifest.database.sha256)?;
    validate_hash(&manifest.database.migration_prefix_sha256)?;
    if manifest.database.byte_length == 0 || manifest.assets.len() > MAX_ASSETS {
        return Err(PlatformError::Corrupt("backup_manifest_bounds"));
    }
    let mut previous: Option<&str> = None;
    let mut total = manifest.database.byte_length;
    for asset in &manifest.assets {
        validate_hash(&asset.sha256)?;
        if previous.is_some_and(|value| value >= asset.sha256.as_str()) {
            return Err(PlatformError::Corrupt("backup_asset_order"));
        }
        previous = Some(&asset.sha256);
        total = total
            .checked_add(asset.byte_length)
            .ok_or(PlatformError::Corrupt("backup_total_bytes"))?;
        if total > MAX_BACKUP_BYTES {
            return Err(PlatformError::Corrupt("backup_total_bytes"));
        }
    }
    Ok(())
}

fn verify_asset_tree(root: &Path, assets: &[BackupAssetV1]) -> PlatformResult<()> {
    verify_private_directory(root)?;
    let mut expected = BTreeSet::new();
    for asset in assets {
        let relative = PathBuf::from(&asset.sha256[0..2])
            .join(&asset.sha256[2..4])
            .join(&asset.sha256);
        expected.insert(relative.clone());
        let actual = hash_private_file(&root.join(relative), Some(asset.byte_length))?;
        if actual != asset.sha256 {
            return Err(PlatformError::Corrupt("backup_asset_hash"));
        }
    }
    let mut actual = BTreeSet::new();
    collect_asset_files(root, root, &mut actual)?;
    if actual != expected {
        return Err(PlatformError::Corrupt("backup_asset_tree"));
    }
    Ok(())
}

fn collect_asset_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<PathBuf>,
) -> PlatformResult<()> {
    verify_private_directory(directory)?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(PlatformError::Corrupt("backup_asset_identity"));
        }
        if metadata.file_type().is_dir() {
            collect_asset_files(root, &entry.path(), files)?;
        } else if metadata.file_type().is_file() {
            files.insert(
                entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|_| PlatformError::Corrupt("backup_asset_tree"))?
                    .to_path_buf(),
            );
        } else {
            return Err(PlatformError::Corrupt("backup_asset_identity"));
        }
    }
    Ok(())
}

fn verify_package_entries(package: &Path) -> PlatformResult<()> {
    let expected = BTreeSet::from([
        "assets".to_owned(),
        "catalog.sqlite3".to_owned(),
        "manifest.json".to_owned(),
        "manifest.sha256".to_owned(),
    ]);
    let actual = fs::read_dir(package)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected {
        return Err(PlatformError::Corrupt("backup_package_entries"));
    }
    Ok(())
}

fn copy_verified_file(
    source: &Path,
    destination: &Path,
    expected_hash: &str,
    expected_length: u64,
) -> PlatformResult<()> {
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    verify_metadata(
        &source.metadata()?,
        Some(expected_length),
        "backup_source_identity",
    )?;
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)?;
    let mut digest = Sha256::new();
    let copied = copy_and_hash(&mut source, &mut destination_file, &mut digest)?;
    if copied != expected_length || format!("{:x}", digest.finalize()) != expected_hash {
        return Err(PlatformError::Corrupt("backup_source_changed"));
    }
    destination_file.sync_all()?;
    drop(destination_file);
    let actual = hash_private_file(destination, Some(expected_length))?;
    if actual != expected_hash {
        return Err(PlatformError::Corrupt("backup_asset_copy"));
    }
    Ok(())
}

fn copy_and_hash(
    source: &mut File,
    destination: &mut File,
    digest: &mut Sha256,
) -> PlatformResult<u64> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        destination.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
        total = total
            .checked_add(read as u64)
            .ok_or(PlatformError::Corrupt("backup_asset_length"))?;
    }
}

fn sync_asset_directories(root: &Path, assets: &[BackupAssetV1]) -> PlatformResult<()> {
    let mut directories = BTreeSet::new();
    for asset in assets {
        directories.insert(root.join(&asset.sha256[0..2]).join(&asset.sha256[2..4]));
        directories.insert(root.join(&asset.sha256[0..2]));
    }
    for directory in directories.iter().rev() {
        sync_directory(directory)?;
    }
    sync_directory(root)
}

pub(crate) fn hash_private_file(
    path: &Path,
    expected_length: Option<u64>,
) -> PlatformResult<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    verify_metadata(&metadata, expected_length, "backup_file_identity")?;
    let mut digest = Sha256::new();
    let copied = std::io::copy(&mut file, &mut digest)?;
    if copied != metadata.len() {
        return Err(PlatformError::Corrupt("backup_file_changed"));
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn private_file_metadata(path: &Path) -> PlatformResult<fs::Metadata> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    verify_metadata(&metadata, None, "backup_file_identity")?;
    Ok(metadata)
}

fn verify_metadata(
    metadata: &fs::Metadata,
    expected_length: Option<u64>,
    code: &'static str,
) -> PlatformResult<()> {
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.gid() != unsafe { libc::getegid() }
        || expected_length.is_some_and(|length| length != metadata.len())
    {
        return Err(PlatformError::Corrupt(code));
    }
    Ok(())
}

fn verify_private_directory(path: &Path) -> PlatformResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.gid() != unsafe { libc::getegid() }
    {
        return Err(PlatformError::Corrupt("backup_directory_identity"));
    }
    Ok(())
}

fn create_private_directory_new(path: &Path) -> PlatformResult<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    verify_private_directory(path)
}

fn create_private_directory(path: &Path) -> PlatformResult<()> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    verify_private_directory(path)
}

pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> PlatformResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_small_private_file(path: &Path, max_bytes: u64) -> PlatformResult<Vec<u8>> {
    let metadata = private_file_metadata(path)?;
    if metadata.len() > max_bytes {
        return Err(PlatformError::Corrupt("backup_sidecar_size"));
    }
    Ok(fs::read(path)?)
}

fn remove_entry(path: &Path) -> PlatformResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn read_restore_pins(paths: &PrivateAppPaths) -> PlatformResult<BTreeSet<String>> {
    let mut pins = BTreeSet::new();
    read_intent_pins(
        &paths.restore_intent,
        &paths.restore_intent_sha256,
        &["backup_id", "safety_backup_id"],
        &mut pins,
    )?;
    read_intent_pins(
        &paths.upgrade_recovery_intent,
        &paths.upgrade_recovery_intent_sha256,
        &["backup_id"],
        &mut pins,
    )?;
    Ok(pins)
}

fn read_intent_pins(
    path: &Path,
    checksum_path: &Path,
    keys: &[&str],
    pins: &mut BTreeSet<String>,
) -> PlatformResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if checksum_path.exists() {
                return Err(PlatformError::Corrupt("backup_pin_intent_checksum"));
            }
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() > 64_000
    {
        return Err(PlatformError::Corrupt("backup_pin_intent_identity"));
    }
    let bytes = fs::read(path)?;
    let checksum_metadata = private_file_metadata(checksum_path)?;
    if checksum_metadata.len() != 65
        || fs::read(checksum_path)? != format!("{}\n", digest_bytes(&bytes)).as_bytes()
    {
        return Err(PlatformError::Corrupt("backup_pin_intent_checksum"));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    for key in keys {
        let id = value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(PlatformError::Corrupt("backup_pin_intent_id"))?;
        let canonical = Uuid::parse_str(id)
            .map(|parsed| parsed.to_string())
            .map_err(|_| PlatformError::Corrupt("backup_pin_intent_id"))?;
        if canonical != id {
            return Err(PlatformError::Corrupt("backup_pin_intent_id"));
        }
        pins.insert(id.to_owned());
    }
    Ok(())
}

fn validate_hash(hash: &str) -> PlatformResult<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlatformError::Corrupt("backup_sha256"));
    }
    Ok(())
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn retention_ms(reason: BackupReason) -> i64 {
    match reason {
        BackupReason::Manual | BackupReason::Scheduled => 30 * DAY_MS,
        BackupReason::PreUpgrade | BackupReason::PreRestore => 90 * DAY_MS,
    }
}

pub(crate) fn format_timestamp(milliseconds: i64) -> PlatformResult<String> {
    let nanoseconds = i128::from(milliseconds)
        .checked_mul(1_000_000)
        .ok_or(PlatformError::InvalidInput("backup_timestamp"))?;
    OffsetDateTime::from_unix_timestamp_nanos(nanoseconds)
        .map_err(|_| PlatformError::InvalidInput("backup_timestamp"))?
        .format(&Rfc3339)
        .map_err(|_| PlatformError::InvalidInput("backup_timestamp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Database, RestoreRepository};
    use rusqlite::params;

    fn populated_store() -> (tempfile::TempDir, PrivateAppPaths, String, Vec<u8>) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1_000).unwrap();
        let bytes = b"asset-complete-backup".to_vec();
        let blob = BlobStore::new(&paths).put(&bytes, None, 1_024).unwrap();
        database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO blobs(sha256, byte_length, created_at_ms)
                 VALUES (?1, ?2, 1000)",
                params![blob.sha256, blob.byte_length as i64],
            )
            .unwrap();
        (temporary, paths, blob.sha256, bytes)
    }

    #[test]
    fn publishes_canonical_asset_complete_independent_package() {
        let (_temporary, paths, hash, bytes) = populated_store();
        let repository = BackupRepository::new(&paths);
        let record = repository.create(BackupReason::Manual, 2_000).unwrap();
        let package = paths.backups.join(record.backup_id.to_string());
        let backup_asset = package
            .join("assets")
            .join(&hash[0..2])
            .join(&hash[2..4])
            .join(&hash);
        let active_asset = BlobStore::new(&paths).path_for_hash(&hash).unwrap();

        assert_eq!(fs::read(&backup_asset).unwrap(), bytes);
        assert_ne!(
            fs::metadata(&backup_asset).unwrap().ino(),
            fs::metadata(&active_asset).unwrap().ino()
        );
        assert_eq!(fs::metadata(&backup_asset).unwrap().nlink(), 1);
        let manifest_bytes = fs::read(package.join("manifest.json")).unwrap();
        let manifest: BackupManifestV1 = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&manifest).unwrap(), manifest_bytes);
        assert_eq!(manifest.assets.len(), 1);
        assert_eq!(manifest.assets[0].sha256, hash);
        assert_eq!(
            repository
                .verify(
                    &record.backup_id.to_string(),
                    Some(record.manifest_sha256.as_str())
                )
                .unwrap()
                .record,
            record
        );
    }

    #[test]
    fn creates_and_verifies_empty_catalog_backup_without_sqlite_sidecars() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        Database::open(&paths, 1_000).unwrap();
        let repository = BackupRepository::new(&paths);

        let record = repository.create(BackupReason::Manual, 2_000).unwrap();
        let package = paths.backups.join(record.backup_id.to_string());

        assert_eq!(record.asset_count, 0);
        assert!(package.join("assets").is_dir());
        assert!(!package.join("catalog.sqlite3-wal").exists());
        assert!(!package.join("catalog.sqlite3-shm").exists());
        repository
            .verify(
                &record.backup_id.to_string(),
                Some(record.manifest_sha256.as_str()),
            )
            .unwrap();
    }

    #[test]
    fn rejects_extra_asset_and_hard_linked_asset() {
        let (_temporary, paths, hash, _bytes) = populated_store();
        let repository = BackupRepository::new(&paths);
        let record = repository.create(BackupReason::Manual, 2_000).unwrap();
        let package = paths.backups.join(record.backup_id.to_string());
        let assets = package.join("assets");
        write_private_file(&assets.join("extra"), b"extra").unwrap();
        assert!(matches!(
            repository.verify(&record.backup_id.to_string(), None),
            Err(PlatformError::Corrupt("backup_asset_tree"))
        ));
        fs::remove_file(assets.join("extra")).unwrap();

        let backup_asset = assets.join(&hash[0..2]).join(&hash[2..4]).join(&hash);
        fs::hard_link(&backup_asset, assets.join("alias")).unwrap();
        assert!(matches!(
            repository.verify(&record.backup_id.to_string(), None),
            Err(PlatformError::Corrupt("backup_file_identity"))
        ));
    }

    #[test]
    fn removes_unpublished_staging_and_expired_package_via_trash() {
        let (_temporary, paths, _hash, _bytes) = populated_store();
        let abandoned = paths.backup_staging.join(Uuid::new_v4().to_string());
        create_private_directory_new(&abandoned).unwrap();
        write_private_file(&abandoned.join("partial"), b"partial").unwrap();
        let repository = BackupRepository::new(&paths);
        let record = repository.create(BackupReason::Manual, 2_000).unwrap();
        assert!(!abandoned.exists());

        assert_eq!(repository.cleanup_expired(31 * DAY_MS).unwrap(), 1);
        assert!(!paths.backups.join(record.backup_id.to_string()).exists());
        assert_eq!(fs::read_dir(&paths.backup_trash).unwrap().count(), 0);
    }

    #[test]
    fn scheduled_backup_runs_once_per_twenty_four_hours_at_boundary() {
        let (_temporary, paths, _hash, _bytes) = populated_store();
        let repository = BackupRepository::new(&paths);
        let first = repository.create_scheduled_if_due(10_000).unwrap().unwrap();
        assert_eq!(first.reason, BackupReason::Scheduled);
        assert!(repository
            .create_scheduled_if_due(10_000 + DAY_MS - 1)
            .unwrap()
            .is_none());

        let second = repository
            .create_scheduled_if_due(10_000 + DAY_MS)
            .unwrap()
            .unwrap();
        assert_ne!(first.backup_id, second.backup_id);
        assert!(repository
            .create_scheduled_if_due(10_000 + DAY_MS)
            .unwrap()
            .is_none());
    }

    #[test]
    fn scheduled_due_check_ignores_unverified_completed_directory() {
        let (_temporary, paths, _hash, _bytes) = populated_store();
        let repository = BackupRepository::new(&paths);
        let corrupt = repository.create_scheduled_if_due(10_000).unwrap().unwrap();
        fs::write(
            paths
                .backups
                .join(corrupt.backup_id.to_string())
                .join("manifest.sha256"),
            format!("{}\n", "0".repeat(64)),
        )
        .unwrap();

        let replacement = repository.create_scheduled_if_due(10_001).unwrap().unwrap();
        assert_eq!(replacement.reason, BackupReason::Scheduled);
        assert_ne!(replacement.backup_id, corrupt.backup_id);
    }

    #[test]
    fn corrupt_pending_intent_stops_expiry_instead_of_dropping_pins() {
        let (_temporary, paths, _hash, _bytes) = populated_store();
        let repository = BackupRepository::new(&paths);
        let selected = repository.create(BackupReason::Manual, 2_000).unwrap();
        RestoreRepository::new(&paths)
            .prepare(selected.backup_id, &selected.manifest_sha256, 3_000)
            .unwrap();
        fs::write(
            &paths.restore_intent_sha256,
            format!("{}\n", "0".repeat(64)),
        )
        .unwrap();

        assert!(matches!(
            repository.cleanup_expired(100 * DAY_MS),
            Err(PlatformError::Corrupt("backup_pin_intent_checksum"))
        ));
        assert!(paths.backups.join(selected.backup_id.to_string()).exists());
    }
}
