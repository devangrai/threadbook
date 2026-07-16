use crate::blob::sync_directory;
use crate::{
    BackupReason, BackupRepository, BlobRecord, PlatformError, PlatformResult, PrivateAppPaths,
    RestoreRepository,
};
use rusqlite::backup::Backup;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;
use wardrobe_core::{
    BlobRecordV1, CredentialId, CredentialLocator, CredentialPort, CredentialProviderV1,
    CredentialReferenceV1, CredentialStatusV1, DatabasePort, DeleteCredentialPlanV1, ErrorCodeV1,
    FoundationStateV1, FoundationVersionsV1, JobId, JobKindV1, JobSnapshotV1, JobStatusV1,
    LocalOnlyAuthorityHealthV1, LocalSettingsSnapshotV1, PortError, PortErrorKind, PortResult,
    ReplayStatusV1, RequestId, SaveCredentialPlanV1, StorageCheckId, StorageCheckRecordV1,
    StorageStatusV1, TerminalFailureV1, UserActionKeyV1,
};

const MIGRATION_0001_SQL: &str = include_str!("../migrations/0001_foundation.sql");
const MIGRATION_0001_SHA256: &str = include_str!("../migrations/0001_foundation.sha256");
const MIGRATION_0002_SQL: &str = include_str!("../migrations/0002_manual_catalog.sql");
const MIGRATION_0002_SHA256: &str = include_str!("../migrations/0002_manual_catalog.sha256");
const MIGRATION_0003_SQL: &str = include_str!("../migrations/0003_receipts.sql");
const MIGRATION_0003_SHA256: &str = include_str!("../migrations/0003_receipts.sha256");
const MIGRATION_0004_SQL: &str = include_str!("../migrations/0004_receipt_images.sql");
const MIGRATION_0004_SHA256: &str = include_str!("../migrations/0004_receipt_images.sha256");
const MIGRATION_0005_SQL: &str = include_str!("../migrations/0005_photo_analysis.sql");
const MIGRATION_0005_SHA256: &str = include_str!("../migrations/0005_photo_analysis.sha256");
const MIGRATION_0006_SQL: &str = include_str!("../migrations/0006_reconciliation.sql");
const MIGRATION_0006_SHA256: &str = include_str!("../migrations/0006_reconciliation.sha256");
const MIGRATION_0007_SQL: &str = include_str!("../migrations/0007_gmail_connector.sql");
const MIGRATION_0007_SHA256: &str = include_str!("../migrations/0007_gmail_connector.sha256");
const MIGRATION_0008_SQL: &str = include_str!("../migrations/0008_outfits.sql");
const MIGRATION_0008_SHA256: &str = include_str!("../migrations/0008_outfits.sha256");
const MIGRATION_0009_SQL: &str = include_str!("../migrations/0009_outfit_recommendations.sql");
const MIGRATION_0009_SHA256: &str =
    include_str!("../migrations/0009_outfit_recommendations.sha256");
const MIGRATION_0010_SQL: &str = include_str!("../migrations/0010_try_on.sql");
const MIGRATION_0010_SHA256: &str = include_str!("../migrations/0010_try_on.sha256");
const MIGRATION_0011_SQL: &str = include_str!("../migrations/0011_hard_deletion.sql");
const MIGRATION_0011_SHA256: &str = include_str!("../migrations/0011_hard_deletion.sha256");
const MIGRATION_0012_SQL: &str = include_str!("../migrations/0012_photokit_connector.sql");
const MIGRATION_0012_SHA256: &str = include_str!("../migrations/0012_photokit_connector.sha256");
const MIGRATION_0013_SQL: &str = include_str!("../migrations/0013_local_only_disconnect.sql");
const MIGRATION_0013_SHA256: &str = include_str!("../migrations/0013_local_only_disconnect.sha256");
const MIGRATION_0014_SQL: &str = include_str!("../migrations/0014_photo_owner_authority.sql");
const MIGRATION_0014_SHA256: &str = include_str!("../migrations/0014_photo_owner_authority.sha256");
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
struct Migration {
    version: i64,
    sql: &'static str,
    sha256: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: MIGRATION_0001_SQL,
        sha256: MIGRATION_0001_SHA256,
    },
    Migration {
        version: 2,
        sql: MIGRATION_0002_SQL,
        sha256: MIGRATION_0002_SHA256,
    },
    Migration {
        version: 3,
        sql: MIGRATION_0003_SQL,
        sha256: MIGRATION_0003_SHA256,
    },
    Migration {
        version: 4,
        sql: MIGRATION_0004_SQL,
        sha256: MIGRATION_0004_SHA256,
    },
    Migration {
        version: 5,
        sql: MIGRATION_0005_SQL,
        sha256: MIGRATION_0005_SHA256,
    },
    Migration {
        version: 6,
        sql: MIGRATION_0006_SQL,
        sha256: MIGRATION_0006_SHA256,
    },
    Migration {
        version: 7,
        sql: MIGRATION_0007_SQL,
        sha256: MIGRATION_0007_SHA256,
    },
    Migration {
        version: 8,
        sql: MIGRATION_0008_SQL,
        sha256: MIGRATION_0008_SHA256,
    },
    Migration {
        version: 9,
        sql: MIGRATION_0009_SQL,
        sha256: MIGRATION_0009_SHA256,
    },
    Migration {
        version: 10,
        sql: MIGRATION_0010_SQL,
        sha256: MIGRATION_0010_SHA256,
    },
    Migration {
        version: 11,
        sql: MIGRATION_0011_SQL,
        sha256: MIGRATION_0011_SHA256,
    },
    Migration {
        version: 12,
        sql: MIGRATION_0012_SQL,
        sha256: MIGRATION_0012_SHA256,
    },
    Migration {
        version: 13,
        sql: MIGRATION_0013_SQL,
        sha256: MIGRATION_0013_SHA256,
    },
    Migration {
        version: 14,
        sql: MIGRATION_0014_SQL,
        sha256: MIGRATION_0014_SHA256,
    },
];

#[derive(Clone, Debug)]
pub struct Database {
    pub(crate) paths: PrivateAppPaths,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCheckOutcome {
    pub check_id: String,
    pub job_id: String,
    pub blob_sha256: String,
    pub replayed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecord {
    pub locator: String,
    pub credential_id: String,
    pub provider: String,
    pub display_label: String,
    pub status: String,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSnapshot {
    pub job_id: String,
    pub kind: String,
    pub state: String,
    pub attempt: i64,
    pub failure_code: Option<String>,
    pub user_action_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundationSnapshot {
    pub credentials: Vec<CredentialRecord>,
    pub jobs: Vec<JobSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundationCounts {
    pub blobs: i64,
    pub storage_checks: i64,
    pub jobs: i64,
    pub results: i64,
    pub failures: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseCompatibility {
    pub schema_version: u32,
    pub migration_prefix_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DatabaseFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct LeasedJob {
    pub job_id: String,
    pub blob_sha256: String,
    pub owner: String,
    pub fence: i64,
    pub attempt: i64,
    pub retry_limit: i64,
    pub backoff_ms: i64,
}

#[derive(Debug, Serialize)]
struct MigrationSidecar<'a> {
    schema_version: u8,
    source_database_sha256: &'a str,
    backup_sha256: &'a str,
    source_schema_version: i64,
    target_schema_version: i64,
    created_at_ms: i64,
}

impl Database {
    pub fn open(paths: &PrivateAppPaths, now_ms: i64) -> PlatformResult<Self> {
        let restore_repository = RestoreRepository::new(paths);
        restore_repository.recover_interrupted_upgrade()?;
        let restored = restore_repository.apply_pending(now_ms)?;
        BackupRepository::new(paths).cleanup_staging()?;
        validate_migration_source()?;
        if let Ok(metadata) = fs::symlink_metadata(&paths.database) {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(PlatformError::Corrupt("database_file_identity"));
            }
        }
        let existed = paths.database.exists() && paths.database.metadata()?.len() > 0;
        if !paths.database.exists() {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&paths.database)?
                .sync_all()?;
        }
        fs::set_permissions(&paths.database, fs::Permissions::from_mode(0o600))?;
        if fs::symlink_metadata(&paths.database)?.nlink() != 1 {
            return Err(PlatformError::Corrupt("database_file_identity"));
        }

        let mut connection = open_connection(&paths.database)?;
        let starting_version: i64 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let target_version = MIGRATIONS
            .last()
            .ok_or(PlatformError::Corrupt("migration_manifest_empty"))?
            .version;
        if !(0..=target_version).contains(&starting_version) {
            return Err(PlatformError::Unsupported("database_schema_version"));
        }
        verify_applied_migrations(&connection, starting_version)?;
        let mut upgrade_recovery_prepared = false;
        if existed && starting_version < target_version {
            let backups = BackupRepository::new(paths);
            let record = backups.create(BackupReason::PreUpgrade, now_ms)?;
            let managed = backups.verify(
                &record.backup_id.to_string(),
                Some(record.manifest_sha256.as_str()),
            )?;
            let source_version = u32::try_from(starting_version)
                .map_err(|_| PlatformError::Corrupt("database_schema_version"))?;
            let source_prefix = migration_prefix_sha256(source_version)?;
            if managed.record.reason != BackupReason::PreUpgrade
                || managed.record.database_schema_version != source_version
                || managed.manifest.database.schema_version != source_version
                || managed.manifest.database.migration_prefix_sha256 != source_prefix
            {
                return Err(PlatformError::Corrupt("migration_backup_version"));
            }
            create_verified_backup(&connection, paths, now_ms, starting_version, target_version)?;
            restore_repository.prepare_upgrade_recovery(
                &managed,
                source_version,
                &source_prefix,
                u32::try_from(target_version)
                    .map_err(|_| PlatformError::Corrupt("database_schema_version"))?,
                now_ms,
            )?;
            upgrade_recovery_prepared = true;
        }

        let migration_result = (|| {
            for migration in MIGRATIONS
                .iter()
                .filter(|migration| migration.version > starting_version)
            {
                apply_migration(&mut connection, migration, now_ms)?;
            }
            verify_applied_migrations(&connection, target_version)?;
            verify_database(&connection)?;
            migration_recovery_failpoint("post_commit_verification")?;
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            migration_recovery_failpoint("post_checkpoint")?;
            verify_database(&connection)
        })();
        if let Err(error) = migration_result {
            drop(connection);
            if upgrade_recovery_prepared {
                restore_repository
                    .recover_interrupted_upgrade()
                    .map_err(|_| PlatformError::Corrupt("migration_recovery_failed"))?;
            }
            return Err(error);
        }
        drop(connection);

        let post_commit_result = (|| {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&paths.database)?
                .sync_all()?;
            migration_recovery_failpoint("post_database_sync")?;
            sync_directory(
                paths
                    .database
                    .parent()
                    .ok_or(PlatformError::Corrupt("database_parent"))?,
            )?;
            migration_recovery_failpoint("post_directory_sync")?;
            let verified = open_read_only_connection(&paths.database)?;
            verify_database(&verified)?;
            verify_applied_migrations(&verified, target_version)?;
            let version: i64 =
                verified.pragma_query_value(None, "user_version", |row| row.get(0))?;
            if version != target_version {
                return Err(PlatformError::Corrupt("database_schema_version"));
            }
            Ok(())
        })();
        if let Err(error) = post_commit_result {
            if upgrade_recovery_prepared {
                restore_repository
                    .recover_interrupted_upgrade()
                    .map_err(|_| PlatformError::Corrupt("migration_recovery_failed"))?;
            }
            return Err(error);
        }
        if upgrade_recovery_prepared {
            restore_repository.commit_upgrade_recovery()?;
        }
        let database = Self {
            paths: paths.clone(),
        };
        database.recover_deletions(now_ms)?;
        database.recover_expired_image_attempts(now_ms)?;
        if restored {
            database.recover_reserved_outfit_recommendations(now_ms)?;
            database.recover_try_on_jobs(now_ms)?;
            restore_repository.commit_pending()?;
        }
        Ok(database)
    }

    pub fn compatibility_snapshot(&self) -> PlatformResult<DatabaseCompatibility> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.paths.database)?;
        let before = private_database_identity(&file.metadata()?)?;
        let connection = open_read_only_connection(&self.paths.database)?;
        let opened_path = private_database_identity(&fs::symlink_metadata(&self.paths.database)?)?;
        if opened_path != before {
            return Err(PlatformError::Corrupt("database_file_changed"));
        }
        let schema_version = database_schema_version(&connection)?;
        let snapshot = DatabaseCompatibility {
            schema_version,
            migration_prefix_sha256: migration_prefix_sha256(schema_version)?,
        };
        let after = private_database_identity(&file.metadata()?)?;
        let final_path = private_database_identity(&fs::symlink_metadata(&self.paths.database)?)?;
        if after != before || final_path != before {
            return Err(PlatformError::Corrupt("database_file_changed"));
        }
        Ok(snapshot)
    }

    pub fn run_storage_check(
        &self,
        request_id: &str,
        blob: &BlobRecord,
        now_ms: i64,
    ) -> PlatformResult<StorageCheckOutcome> {
        if request_id.is_empty() || request_id.len() > 64 {
            return Err(PlatformError::InvalidInput("request_id"));
        }
        let envelope_hash = digest_text(&format!(
            "run_storage_check_v1:{request_id}:{}:{}:foundation-v1",
            blob.sha256, blob.byte_length
        ));
        let check_id = stable_id("check", request_id);
        let job_id = stable_id("job", request_id);
        let response = StorageCheckOutcome {
            check_id: check_id.clone(),
            job_id: job_id.clone(),
            blob_sha256: blob.sha256.clone(),
            replayed: false,
        };

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_envelope, response_json)) = transaction
            .query_row(
                "SELECT envelope_hash, response_json FROM command_receipts
                 WHERE request_id = ?1 AND command_name = 'run_storage_check_v1'",
                [request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if stored_envelope != envelope_hash {
                return Err(PlatformError::Conflict("command_envelope_changed"));
            }
            let mut replay: StorageCheckOutcome = serde_json::from_str(&response_json)?;
            replay.replayed = true;
            transaction.commit()?;
            return Ok(replay);
        }

        transaction.execute(
            "INSERT OR IGNORE INTO blobs(sha256, byte_length, created_at_ms)
             VALUES (?1, ?2, ?3)",
            params![
                blob.sha256,
                i64::try_from(blob.byte_length)
                    .map_err(|_| PlatformError::InvalidInput("blob_byte_length"))?,
                now_ms
            ],
        )?;
        let existing_length: i64 = transaction.query_row(
            "SELECT byte_length FROM blobs WHERE sha256 = ?1",
            [&blob.sha256],
            |row| row.get(0),
        )?;
        if existing_length != blob.byte_length as i64 {
            return Err(PlatformError::Conflict("blob_length_changed"));
        }
        transaction.execute(
            "INSERT OR IGNORE INTO provenance(
                provenance_id, blob_sha256, source_kind, source_locator, created_at_ms
             ) VALUES (?1, ?2, 'storage_check', ?3, ?4)",
            params![
                stable_id("provenance", request_id),
                blob.sha256,
                request_id,
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO storage_checks(check_id, request_id, blob_sha256, created_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![check_id, request_id, blob.sha256, now_ms],
        )?;
        insert_verify_job(
            &transaction,
            &job_id,
            &format!("storage-check:{request_id}"),
            &blob.sha256,
            now_ms,
        )?;
        transaction.execute(
            "INSERT INTO command_receipts(
                request_id, command_name, envelope_hash, response_json, created_at_ms
             ) VALUES (?1, 'run_storage_check_v1', ?2, ?3, ?4)",
            params![
                request_id,
                envelope_hash,
                serde_json::to_string(&response)?,
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok(response)
    }

    pub fn enqueue_verify_blob(
        &self,
        idempotency_key: &str,
        blob_sha256: &str,
        now_ms: i64,
    ) -> PlatformResult<String> {
        if idempotency_key.is_empty() || idempotency_key.len() > 128 {
            return Err(PlatformError::InvalidInput("idempotency_key"));
        }
        validate_hash(blob_sha256)?;
        let job_id = stable_id("job", idempotency_key);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_verify_job(&transaction, &job_id, idempotency_key, blob_sha256, now_ms)?;
        transaction.commit()?;
        Ok(job_id)
    }

    pub fn snapshot(&self, limit: usize) -> PlatformResult<FoundationSnapshot> {
        let connection = self.connection()?;
        let mut credential_query = connection.prepare(
            "SELECT locator, credential_id, provider, display_label, status, updated_at_ms
             FROM credential_references ORDER BY created_at_ms, locator",
        )?;
        let credentials = credential_query
            .query_map([], |row| {
                Ok(CredentialRecord {
                    locator: row.get(0)?,
                    credential_id: row.get(1)?,
                    provider: row.get(2)?,
                    display_label: row.get(3)?,
                    status: row.get(4)?,
                    updated_at_ms: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut job_query = connection.prepare(
            "SELECT j.job_id, j.kind, j.state, j.attempt,
                    f.failure_code, f.user_action_key
             FROM jobs j LEFT JOIN job_failures f ON f.job_id = j.job_id
             ORDER BY j.updated_at_ms DESC, j.job_id LIMIT ?1",
        )?;
        let jobs = job_query
            .query_map([limit.min(100) as i64], |row| {
                Ok(JobSnapshot {
                    job_id: row.get(0)?,
                    kind: row.get(1)?,
                    state: row.get(2)?,
                    attempt: row.get(3)?,
                    failure_code: row.get(4)?,
                    user_action_key: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(FoundationSnapshot { credentials, jobs })
    }

    pub fn counts(&self) -> PlatformResult<FoundationCounts> {
        let connection = self.connection()?;
        Ok(FoundationCounts {
            blobs: count(&connection, "blobs")?,
            storage_checks: count(&connection, "storage_checks")?,
            jobs: count(&connection, "jobs")?,
            results: count(&connection, "job_results")?,
            failures: count(&connection, "job_failures")?,
        })
    }

    pub fn reconcile_credentials<C: CredentialPort>(
        &self,
        credentials: &C,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let connection = self.connection()?;
        let mut query = connection.prepare(
            "SELECT locator, status FROM credential_references
             WHERE status IN ('pending_save', 'pending_delete')
             ORDER BY created_at_ms, locator",
        )?;
        let pending = query
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(query);
        drop(connection);

        for (locator_text, status) in pending {
            let locator = CredentialLocator::new(locator_text.clone())
                .map_err(|_| PlatformError::Corrupt("credential_locator"))?;
            match status.as_str() {
                "pending_save" => {
                    let next = if credentials
                        .contains(&locator)
                        .map_err(platform_credential_error)?
                    {
                        "active"
                    } else {
                        "save_failed"
                    };
                    self.connection()?.execute(
                        "UPDATE credential_references SET status = ?2, updated_at_ms = ?3
                         WHERE locator = ?1 AND status = 'pending_save'",
                        params![locator_text, next, now_ms],
                    )?;
                }
                "pending_delete" => {
                    credentials
                        .delete(&locator)
                        .map_err(platform_credential_error)?;
                    self.connection()?.execute(
                        "DELETE FROM credential_references
                         WHERE locator = ?1 AND status = 'pending_delete'",
                        [locator_text],
                    )?;
                }
                _ => return Err(PlatformError::Corrupt("credential_status")),
            }
        }
        Ok(())
    }

    pub(crate) fn claim(
        &self,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> PlatformResult<Option<LeasedJob>> {
        if owner.is_empty() || lease_ms <= 0 {
            return Err(PlatformError::InvalidInput("worker_lease"));
        }
        let expires = now_ms
            .checked_add(lease_ms)
            .ok_or(PlatformError::InvalidInput("worker_lease"))?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = transaction
            .query_row(
                "SELECT j.job_id
                 FROM jobs j
                 WHERE (
                    (j.state = 'queued' AND j.available_at_ms <= ?1)
                    OR (j.state = 'running' AND j.lease_expires_at_ms <= ?1)
                 )
                 AND NOT EXISTS (
                    SELECT 1 FROM job_dependencies d
                    JOIN jobs prerequisite ON prerequisite.job_id = d.depends_on_job_id
                    WHERE d.job_id = j.job_id AND prerequisite.state <> 'succeeded'
                 )
                 ORDER BY COALESCE(j.lease_expires_at_ms, j.available_at_ms), j.created_at_ms, j.job_id
                 LIMIT 1",
                [now_ms],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(job_id) = candidate else {
            transaction.commit()?;
            return Ok(None);
        };
        transaction.execute(
            "UPDATE jobs SET state = 'running', attempt = attempt + 1, fence = fence + 1,
                    lease_owner = ?2, lease_expires_at_ms = ?3, updated_at_ms = ?1
             WHERE job_id = ?4",
            params![now_ms, owner, expires, job_id],
        )?;
        let leased = transaction.query_row(
            "SELECT job_id, json_extract(payload_json, '$.blob_sha256'), lease_owner,
                    fence, attempt, retry_limit, backoff_ms
             FROM jobs WHERE job_id = ?1",
            [&job_id],
            |row| {
                Ok(LeasedJob {
                    job_id: row.get(0)?,
                    blob_sha256: row.get(1)?,
                    owner: row.get(2)?,
                    fence: row.get(3)?,
                    attempt: row.get(4)?,
                    retry_limit: row.get(5)?,
                    backoff_ms: row.get(6)?,
                })
            },
        )?;
        transaction.commit()?;
        Ok(Some(leased))
    }

    pub(crate) fn complete(
        &self,
        leased: &LeasedJob,
        byte_length: u64,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let result_json = serde_json::json!({
            "schema_version": 1,
            "blob_sha256": leased.blob_sha256,
            "byte_length": byte_length,
            "verified": true
        });
        let result_text = serde_json::to_string(&result_json)?;
        let result_hash = digest_text(&result_text);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_lease(&transaction, leased, now_ms)?;
        transaction.execute(
            "INSERT OR IGNORE INTO job_results(
                job_id, result_hash, result_json, winning_owner, winning_fence, committed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                leased.job_id,
                result_hash,
                result_text,
                leased.owner,
                leased.fence,
                now_ms
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE jobs SET state = 'succeeded', lease_owner = NULL,
                    lease_expires_at_ms = NULL, updated_at_ms = ?4
             WHERE job_id = ?1 AND lease_owner = ?2 AND fence = ?3 AND state = 'running'",
            params![leased.job_id, leased.owner, leased.fence, now_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::LeaseLost);
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn complete_known_blob(
        &self,
        leased: &LeasedJob,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let byte_length: i64 = self
            .connection()?
            .query_row(
                "SELECT byte_length FROM blobs WHERE sha256 = ?1",
                [&leased.blob_sha256],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(PlatformError::Corrupt("job_blob_record_missing"))?;
        self.complete(
            leased,
            u64::try_from(byte_length).map_err(|_| PlatformError::Corrupt("blob_byte_length"))?,
            now_ms,
        )
    }

    pub(crate) fn fail_permanently(
        &self,
        leased: &LeasedJob,
        failure_code: &str,
        user_action_key: &str,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_lease(&transaction, leased, now_ms)?;
        transaction.execute(
            "INSERT OR REPLACE INTO job_failures(
                job_id, failure_code, user_action_key, retryable, failed_at_ms
             ) VALUES (?1, ?2, ?3, 0, ?4)",
            params![leased.job_id, failure_code, user_action_key, now_ms],
        )?;
        let changed = transaction.execute(
            "UPDATE jobs SET state = 'failed', lease_owner = NULL,
                    lease_expires_at_ms = NULL, updated_at_ms = ?4
             WHERE job_id = ?1 AND lease_owner = ?2 AND fence = ?3 AND state = 'running'",
            params![leased.job_id, leased.owner, leased.fence, now_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::LeaseLost);
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn retry(&self, leased: &LeasedJob, now_ms: i64) -> PlatformResult<bool> {
        let next = now_ms.saturating_add(leased.backoff_ms);
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_lease(&transaction, leased, now_ms)?;
        if leased.attempt > leased.retry_limit {
            transaction.rollback()?;
            return Ok(false);
        }
        let changed = transaction.execute(
            "UPDATE jobs SET state = 'queued', available_at_ms = ?4,
                    lease_owner = NULL, lease_expires_at_ms = NULL, updated_at_ms = ?5
             WHERE job_id = ?1 AND lease_owner = ?2 AND fence = ?3 AND state = 'running'",
            params![leased.job_id, leased.owner, leased.fence, next, now_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::LeaseLost);
        }
        transaction.commit()?;
        Ok(true)
    }

    pub(crate) fn connection(&self) -> PlatformResult<Connection> {
        open_connection(&self.paths.database)
    }
}

fn open_connection(path: &Path) -> PlatformResult<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA fullfsync = ON;
         PRAGMA checkpoint_fullfsync = ON;
         PRAGMA trusted_schema = OFF;",
    )?;
    Ok(connection)
}

fn open_read_only_connection(path: &Path) -> PlatformResult<Connection> {
    let mut uri = url::Url::from_file_path(path)
        .map_err(|_| PlatformError::Corrupt("database_file_identity"))?;
    uri.query_pairs_mut()
        .append_pair("mode", "ro")
        .append_pair("immutable", "1");
    let connection = Connection::open_with_flags(
        uri.as_str(),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.execute_batch(
        "PRAGMA query_only = ON;
         PRAGMA trusted_schema = OFF;",
    )?;
    Ok(connection)
}

fn private_database_identity(metadata: &fs::Metadata) -> PlatformResult<DatabaseFileIdentity> {
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.gid() != unsafe { libc::getegid() }
        || metadata.len() == 0
    {
        return Err(PlatformError::Corrupt("database_file_identity"));
    }
    Ok(DatabaseFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        mode: metadata.mode() & 0o777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        links: metadata.nlink(),
    })
}

fn apply_migration(
    connection: &mut Connection,
    migration: &Migration,
    now_ms: i64,
) -> PlatformResult<()> {
    let rebuilds_constrained_parents = matches!(migration.version, 12 | 14);
    if rebuilds_constrained_parents {
        connection.pragma_update(None, "foreign_keys", false)?;
    }
    let result = (|| {
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations(version, sha256, applied_at_ms) VALUES (?1, ?2, ?3)",
            params![migration.version, migration.sha256.trim(), now_ms],
        )?;
        transaction.pragma_update(None, "user_version", migration.version)?;
        verify_database(&transaction)?;
        transaction.commit()?;
        Ok(())
    })();
    if rebuilds_constrained_parents {
        connection.pragma_update(None, "foreign_keys", true)?;
    }
    result
}

fn validate_migration_source() -> PlatformResult<()> {
    for (index, migration) in MIGRATIONS.iter().enumerate() {
        if migration.version != index as i64 + 1 {
            return Err(PlatformError::Corrupt("migration_manifest_gap"));
        }
        if digest_text(migration.sql) != migration.sha256.trim() {
            return Err(PlatformError::Corrupt("migration_source_checksum"));
        }
    }
    Ok(())
}

pub(crate) fn verify_applied_migrations(
    connection: &Connection,
    user_version: i64,
) -> PlatformResult<()> {
    if user_version == 0 {
        return Ok(());
    }
    let mut statement =
        connection.prepare("SELECT version, sha256 FROM schema_migrations ORDER BY version")?;
    let applied = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if applied.len() != user_version as usize {
        return Err(PlatformError::Corrupt("migration_applied_gap"));
    }
    for (index, (version, sha256)) in applied.iter().enumerate() {
        let expected = MIGRATIONS
            .get(index)
            .ok_or(PlatformError::Corrupt("migration_applied_unknown"))?;
        if *version != expected.version || sha256 != expected.sha256.trim() {
            return Err(PlatformError::Corrupt("migration_applied_checksum"));
        }
    }
    Ok(())
}

fn create_verified_backup(
    source: &Connection,
    paths: &PrivateAppPaths,
    now_ms: i64,
    source_version: i64,
    target_version: i64,
) -> PlatformResult<()> {
    source.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    verify_database(source)?;
    let source_hash = hash_file(&paths.database)?;
    let suffix = Uuid::new_v4();
    let backup_path = paths.backups.join(format!(
        "schema-v{source_version}-to-v{target_version}-{now_ms}-{suffix}.sqlite3"
    ));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&backup_path)?
        .sync_all()?;

    let mut destination = Connection::open_with_flags(
        &backup_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    {
        let backup = Backup::new(source, &mut destination)?;
        backup.run_to_completion(64, Duration::from_millis(10), None)?;
    }
    verify_database(&destination)?;
    drop(destination);
    File::open(&backup_path)?.sync_all()?;
    let backup_hash = hash_file(&backup_path)?;
    let sidecar = MigrationSidecar {
        schema_version: 1,
        source_database_sha256: &source_hash,
        backup_sha256: &backup_hash,
        source_schema_version: source_version,
        target_schema_version: target_version,
        created_at_ms: now_ms,
    };
    write_atomic_json(
        &paths.backups,
        &format!("schema-v{source_version}-to-v{target_version}-{now_ms}-{suffix}.json"),
        &sidecar,
    )?;
    sync_directory(&paths.backups)?;
    Ok(())
}

pub(crate) fn verify_database(connection: &Connection) -> PlatformResult<()> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(PlatformError::Corrupt("database_integrity"));
    }
    let foreign_key_violation = connection
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    if foreign_key_violation {
        return Err(PlatformError::Corrupt("database_foreign_key"));
    }
    Ok(())
}

pub(crate) fn database_schema_version(connection: &Connection) -> PlatformResult<u32> {
    validate_migration_source()?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let target = MIGRATIONS
        .last()
        .ok_or(PlatformError::Corrupt("migration_manifest_empty"))?
        .version;
    if !(0..=target).contains(&version) {
        return Err(PlatformError::Unsupported("database_schema_version"));
    }
    verify_applied_migrations(connection, version)?;
    u32::try_from(version).map_err(|_| PlatformError::Corrupt("database_schema_version"))
}

pub(crate) fn migration_prefix_sha256(version: u32) -> PlatformResult<String> {
    validate_migration_source()?;
    let version = usize::try_from(version)
        .map_err(|_| PlatformError::Unsupported("database_schema_version"))?;
    if version > MIGRATIONS.len() {
        return Err(PlatformError::Unsupported("database_schema_version"));
    }
    let mut prefix = String::new();
    for migration in MIGRATIONS.iter().take(version) {
        prefix.push_str(&migration.version.to_string());
        prefix.push(':');
        prefix.push_str(migration.sha256.trim());
        prefix.push('\n');
    }
    Ok(digest_text(&prefix))
}

pub(crate) fn stage_restore_database(
    source: &Path,
    destination: &Path,
    now_ms: i64,
) -> PlatformResult<String> {
    let mut source_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)?;
    let source_metadata = source_file.metadata()?;
    if !source_metadata.file_type().is_file()
        || source_metadata.nlink() != 1
        || source_metadata.mode() & 0o077 != 0
        || source_metadata.len() == 0
    {
        return Err(PlatformError::Corrupt("restore_database_source"));
    }
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)?;
    let copied = std::io::copy(&mut source_file, &mut destination_file)?;
    if copied != source_metadata.len() {
        return Err(PlatformError::Corrupt("restore_database_copy"));
    }
    destination_file.sync_all()?;
    drop(destination_file);

    let result = (|| {
        let mut connection = open_connection(destination)?;
        verify_database(&connection)?;
        let starting_version = i64::from(database_schema_version(&connection)?);
        for migration in MIGRATIONS
            .iter()
            .filter(|migration| migration.version > starting_version)
        {
            apply_migration(&mut connection, migration, now_ms)?;
        }
        normalize_restored_state(&mut connection, now_ms)?;
        let target_version = MIGRATIONS
            .last()
            .ok_or(PlatformError::Corrupt("migration_manifest_empty"))?
            .version;
        verify_applied_migrations(&connection, target_version)?;
        verify_database(&connection)?;
        connection.execute_batch(
            "PRAGMA wal_checkpoint(TRUNCATE);
             PRAGMA journal_mode = DELETE;",
        )?;
        drop(connection);
        for sidecar in [
            path_with_suffix(destination, "-wal"),
            path_with_suffix(destination, "-shm"),
        ] {
            match fs::remove_file(sidecar) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        File::open(destination)?.sync_all()?;
        verify_staged_restore_database(destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

pub(crate) fn verify_staged_restore_database(path: &Path) -> PlatformResult<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() == 0
    {
        return Err(PlatformError::Corrupt("restore_database_identity"));
    }
    for sidecar in [
        path_with_suffix(path, "-wal"),
        path_with_suffix(path, "-shm"),
    ] {
        if sidecar.exists() {
            return Err(PlatformError::Corrupt("restore_database_sidecar"));
        }
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    verify_database(&connection)?;
    let version = database_schema_version(&connection)?;
    if usize::try_from(version).ok() != Some(MIGRATIONS.len()) {
        return Err(PlatformError::Unsupported("restore_database_schema"));
    }
    drop(connection);
    crate::backup_repository::hash_private_file(path, Some(metadata.len()))
}

pub(crate) fn verify_upgrade_source_database(
    path: &Path,
    expected_sha256: &str,
    expected_length: u64,
    expected_schema_version: u32,
    expected_migration_prefix_sha256: &str,
) -> PlatformResult<()> {
    validate_hash(expected_sha256)?;
    validate_hash(expected_migration_prefix_sha256)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.gid() != unsafe { libc::getegid() }
        || metadata.len() != expected_length
    {
        return Err(PlatformError::Corrupt("upgrade_recovery_database_identity"));
    }
    for sidecar in [
        path_with_suffix(path, "-wal"),
        path_with_suffix(path, "-shm"),
    ] {
        if sidecar.exists() {
            return Err(PlatformError::Corrupt("upgrade_recovery_database_sidecar"));
        }
    }
    if crate::backup_repository::hash_private_file(path, Some(expected_length))? != expected_sha256
    {
        return Err(PlatformError::Corrupt("upgrade_recovery_database_hash"));
    }
    let connection = open_read_only_connection(path)?;
    verify_database(&connection)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != i64::from(expected_schema_version) {
        return Err(PlatformError::Corrupt("upgrade_recovery_database_version"));
    }
    verify_applied_migrations(&connection, version)?;
    if migration_prefix_sha256(expected_schema_version)? != expected_migration_prefix_sha256 {
        return Err(PlatformError::Corrupt("upgrade_recovery_migration_prefix"));
    }
    Ok(())
}

pub(crate) fn verify_upgrade_target_database(
    path: &Path,
    expected_schema_version: u32,
) -> PlatformResult<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    private_database_identity(&file.metadata()?)?;
    let connection = open_read_only_connection(path)?;
    verify_database(&connection)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != i64::from(expected_schema_version) {
        return Err(PlatformError::Corrupt("upgrade_recovery_target_version"));
    }
    verify_applied_migrations(&connection, version)
}

#[cfg(test)]
thread_local! {
    static MIGRATION_RECOVERY_FAILPOINT: std::cell::RefCell<Option<&'static str>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_migration_recovery_failpoint(name: &'static str) {
    MIGRATION_RECOVERY_FAILPOINT.with(|failpoint| {
        *failpoint.borrow_mut() = Some(name);
    });
}

fn migration_recovery_failpoint(name: &'static str) -> PlatformResult<()> {
    #[cfg(test)]
    {
        let should_fail = MIGRATION_RECOVERY_FAILPOINT.with(|failpoint| {
            let mut failpoint = failpoint.borrow_mut();
            if *failpoint == Some(name) {
                failpoint.take();
                true
            } else {
                false
            }
        });
        if should_fail {
            return Err(PlatformError::Corrupt("migration_recovery_injected"));
        }
    }
    #[cfg(not(test))]
    let _ = name;
    Ok(())
}

fn normalize_restored_state(connection: &mut Connection, now_ms: i64) -> PlatformResult<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // A restored disconnect is history, not authority over this installation's Keychain.
    if table_exists(&transaction, "gmail_disconnect_stages")?
        && table_exists(&transaction, "gmail_operations")?
        && table_exists(&transaction, "gmail_accounts")?
        && table_exists(&transaction, "credential_references")?
    {
        transaction.execute(
            "UPDATE gmail_accounts
             SET credential_locator = NULL
             WHERE credential_locator IS NOT NULL
               AND EXISTS (
                 SELECT 1
                 FROM gmail_disconnect_stages disconnect
                 JOIN gmail_operations operation
                   ON operation.request_id = disconnect.request_id
                 WHERE operation.command_name = 'disconnect_gmail_v1'
                   AND operation.stage <> 'terminal'
                   AND disconnect.account_key = gmail_accounts.account_key
                   AND disconnect.credential_locator =
                       gmail_accounts.credential_locator
               )",
            [],
        )?;
        transaction.execute(
            "DELETE FROM credential_references
             WHERE provider = 'gmail'
               AND EXISTS (
                 SELECT 1
                 FROM gmail_disconnect_stages disconnect
                 JOIN gmail_operations operation
                   ON operation.request_id = disconnect.request_id
                 WHERE operation.command_name = 'disconnect_gmail_v1'
                   AND operation.stage <> 'terminal'
                   AND disconnect.credential_locator =
                       credential_references.locator
               )",
            [],
        )?;
    }
    if table_exists(&transaction, "credential_references")? {
        transaction.execute(
            "UPDATE credential_references
             SET status = 'save_failed', delete_request_id = NULL, updated_at_ms = ?1
             WHERE status IN ('pending_delete', 'pending_save')",
            [now_ms],
        )?;
    }
    if table_exists(&transaction, "gmail_connector_state")? {
        transaction.execute(
            "UPDATE gmail_connector_state
             SET status = 'disconnected', account_key = NULL, scope_id = NULL,
                 revocation_state = NULL, updated_at_ms = ?1
             WHERE singleton = 1",
            [now_ms],
        )?;
    }
    if table_exists(&transaction, "gmail_operations")? {
        transaction.execute(
            "UPDATE gmail_operations
             SET stage = 'terminal',
                 response_json =
                    '{\"interrupted\":true,\"reason\":\"restore_interrupted\"}',
                 updated_at_ms = MAX(updated_at_ms, ?1)
             WHERE command_name = 'disconnect_gmail_v1'
               AND stage <> 'terminal'",
            [now_ms],
        )?;
    }
    if table_exists(&transaction, "jobs")? {
        transaction.execute(
            "UPDATE jobs
             SET state = 'queued', available_at_ms = ?1, fence = fence + 1,
                 lease_owner = NULL, lease_expires_at_ms = NULL, updated_at_ms = ?1
             WHERE state = 'running'",
            [now_ms],
        )?;
    }
    if table_exists(&transaction, "store_authority_epoch")? {
        sanitize_restored_deletion_authority(&transaction)?;
    }
    if table_exists(&transaction, "photokit_operations")? {
        normalize_restored_photokit_state(&transaction, now_ms)?;
    }
    transaction.commit()?;
    Ok(())
}

fn normalize_restored_photokit_state(connection: &Connection, now_ms: i64) -> PlatformResult<()> {
    connection.execute(
        "UPDATE photokit_operations
         SET state = 'interrupted', terminal_reason = 'restore_interrupted',
             finished_at_ms = ?1
         WHERE state IN ('enumerating', 'materializing')",
        [now_ms],
    )?;
    connection.execute(
        "DELETE FROM photokit_materialization_attempts
         WHERE operation_id IN (
             SELECT operation_id FROM photokit_operations
             WHERE state = 'interrupted'
               AND terminal_reason = 'restore_interrupted'
         )",
        [],
    )?;
    connection.execute(
        "DELETE FROM photokit_operation_observations
         WHERE operation_id IN (
             SELECT operation_id FROM photokit_operations
             WHERE state = 'interrupted'
               AND terminal_reason = 'restore_interrupted'
         )",
        [],
    )?;
    connection.execute(
        "DELETE FROM photokit_locator_records
         WHERE finalized = 0
           AND operation_id IN (
               SELECT operation_id FROM photokit_operations
               WHERE state = 'interrupted'
                 AND terminal_reason = 'restore_interrupted'
           )",
        [],
    )?;

    let pending = {
        let mut statement = connection.prepare(
            "SELECT enrollment_epoch, key_reference
             FROM photokit_enrollments
             WHERE state = 'pending'
             ORDER BY created_at_ms, enrollment_epoch",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    for (enrollment_epoch, key_reference) in pending {
        connection.execute(
            "INSERT OR IGNORE INTO photokit_key_cleanup_intents(
                intent_id, deletion_run_id, enrollment_epoch, key_reference,
                reason, state, created_at_ms
             ) VALUES (?1, NULL, ?2, ?3, 'incomplete_enrollment_restore',
                       'pending', ?4)",
            params![
                Uuid::new_v4().hyphenated().to_string(),
                enrollment_epoch,
                key_reference,
                now_ms
            ],
        )?;
        connection.execute(
            "DELETE FROM photokit_locator_records
             WHERE enrollment_epoch = ?1 AND finalized = 0",
            [&enrollment_epoch],
        )?;
        connection.execute(
            "DELETE FROM photokit_enrollments
             WHERE enrollment_epoch = ?1 AND state = 'pending'",
            [&enrollment_epoch],
        )?;
    }

    connection.execute(
        "UPDATE photokit_connector_state
         SET state = CASE
               WHEN active_enrollment_epoch IS NULL THEN 'unconfigured'
               ELSE 'ready'
             END,
             updated_at_ms = ?1
         WHERE state = 'reconciling'",
        [now_ms],
    )?;
    Ok(())
}

fn sanitize_restored_deletion_authority(connection: &Connection) -> PlatformResult<()> {
    connection.execute_batch(
        "DROP TRIGGER IF EXISTS deletion_receipts_no_delete;
         DELETE FROM domain_mutation_authority;",
    )?;
    if table_exists(connection, "photokit_key_cleanup_intents")? {
        connection.execute_batch(
            "INSERT INTO domain_mutation_authority(entity_kind,key_json)
             SELECT 'photokit_key_cleanup_restore',json_array(intent.intent_id)
             FROM photokit_key_cleanup_intents intent
             JOIN deletion_runs run ON run.run_id=intent.deletion_run_id
             WHERE run.state<>'complete';
             UPDATE photokit_key_cleanup_intents
             SET deletion_run_id=NULL
             WHERE intent_id IN (
                 SELECT json_extract(key_json,'$[0]')
                 FROM domain_mutation_authority
                 WHERE entity_kind='photokit_key_cleanup_restore'
             );
             DELETE FROM domain_mutation_authority
             WHERE entity_kind='photokit_key_cleanup_restore';",
        )?;
    }
    connection.execute_batch(
        "DELETE FROM deletion_execution_authority;
         DELETE FROM deletion_execution_receipts
          WHERE run_id IN (SELECT run_id FROM deletion_runs WHERE state <> 'complete');
         DELETE FROM deletion_run_blobs
          WHERE run_id IN (SELECT run_id FROM deletion_runs WHERE state <> 'complete');
         DELETE FROM deletion_run_backup_retention
          WHERE run_id IN (SELECT run_id FROM deletion_runs WHERE state <> 'complete');
         DELETE FROM deletion_run_remote_retention
          WHERE run_id IN (SELECT run_id FROM deletion_runs WHERE state <> 'complete');
         DELETE FROM deletion_runs WHERE state <> 'complete';
         DELETE FROM deletion_plan_entries;",
    )?;
    if table_exists(connection, "deletion_plan_photokit_key_cleanup")? {
        connection.execute("DELETE FROM deletion_plan_photokit_key_cleanup", [])?;
    }
    connection.execute_batch(
        "DELETE FROM deletion_plan_backup_retention;
         DELETE FROM deletion_plan_remote_retention;
         DELETE FROM deletion_preview_items;
         DELETE FROM deletion_plans;
         DELETE FROM deletion_previews;
         CREATE TRIGGER deletion_receipts_no_delete
         BEFORE DELETE ON deletion_execution_receipts
         BEGIN SELECT RAISE(ABORT, 'deletion receipts are immutable'); END;",
    )?;
    let rotated = Uuid::new_v4().simple().to_string();
    let changed = connection.execute(
        "UPDATE store_authority_epoch SET epoch=?1 WHERE singleton=1",
        [&rotated],
    )?;
    if changed != 1 {
        return Err(PlatformError::Corrupt("store_authority_epoch"));
    }
    let transient: i64 = connection.query_row(
        "SELECT
           (SELECT COUNT(*) FROM domain_mutation_authority)
           +(SELECT COUNT(*) FROM deletion_execution_authority)
           +(SELECT COUNT(*) FROM deletion_plans)
           +(SELECT COUNT(*) FROM deletion_runs WHERE state <> 'complete')",
        [],
        |row| row.get(0),
    )?;
    if transient != 0 {
        return Err(PlatformError::Corrupt(
            "restore_deletion_authority_sanitization",
        ));
    }
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> PlatformResult<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
         )",
        [table],
        |row| row.get(0),
    )?)
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn write_atomic_json<T: Serialize>(
    directory: &Path,
    final_name: &str,
    value: &T,
) -> PlatformResult<()> {
    let temporary = directory.join(format!(".{}.tmp", Uuid::new_v4()));
    let final_path = directory.join(final_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temporary, &final_path)?;
    sync_directory(directory)?;
    Ok(())
}

fn insert_verify_job(
    transaction: &Transaction<'_>,
    job_id: &str,
    idempotency_key: &str,
    blob_sha256: &str,
    now_ms: i64,
) -> PlatformResult<()> {
    validate_hash(blob_sha256)?;
    let payload = serde_json::json!({"schema_version": 1, "blob_sha256": blob_sha256});
    let payload_text = serde_json::to_string(&payload)?;
    let input_hash = digest_text(&payload_text);
    let inserted = transaction.execute(
        "INSERT OR IGNORE INTO jobs(
            job_id, idempotency_key, kind, payload_version, payload_json,
            input_hash, pipeline_version, state, available_at_ms, attempt,
            retry_limit, backoff_ms, fence, lease_owner, lease_expires_at_ms,
            created_at_ms, updated_at_ms
         ) VALUES (
            ?1, ?2, 'verify_blob_v1', 1, ?3, ?4, 'foundation-v1',
            'queued', ?5, 0, 2, 1000, 0, NULL, NULL, ?5, ?5
         )",
        params![job_id, idempotency_key, payload_text, input_hash, now_ms],
    )?;
    if inserted == 0 {
        let existing: (String, String, String) = transaction.query_row(
            "SELECT job_id, payload_json, input_hash FROM jobs WHERE idempotency_key = ?1",
            [idempotency_key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if existing != (job_id.to_owned(), payload_text, input_hash) {
            return Err(PlatformError::Conflict("job_envelope_changed"));
        }
    }
    Ok(())
}

fn ensure_lease(
    transaction: &Transaction<'_>,
    leased: &LeasedJob,
    now_ms: i64,
) -> PlatformResult<()> {
    let valid = transaction
        .query_row(
            "SELECT 1 FROM jobs
             WHERE job_id = ?1 AND state = 'running' AND lease_owner = ?2
               AND fence = ?3 AND lease_expires_at_ms > ?4",
            params![leased.job_id, leased.owner, leased.fence, now_ms],
            |_| Ok(()),
        )
        .optional()?;
    valid.ok_or(PlatformError::LeaseLost)
}

pub(crate) fn stable_id(prefix: &str, input: &str) -> String {
    let digest = Sha256::digest(format!("{prefix}:{input}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).hyphenated().to_string()
}

fn digest_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn validate_hash(hash: &str) -> PlatformResult<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlatformError::InvalidInput("sha256"));
    }
    Ok(())
}

fn hash_file(path: &Path) -> PlatformResult<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn count(connection: &Connection, table: &str) -> PlatformResult<i64> {
    let sql = match table {
        "blobs" => "SELECT COUNT(*) FROM blobs",
        "storage_checks" => "SELECT COUNT(*) FROM storage_checks",
        "jobs" => "SELECT COUNT(*) FROM jobs",
        "job_results" => "SELECT COUNT(*) FROM job_results",
        "job_failures" => "SELECT COUNT(*) FROM job_failures",
        _ => return Err(PlatformError::InvalidInput("count_table")),
    };
    Ok(connection.query_row(sql, [], |row| row.get(0))?)
}

impl DatabasePort for Database {
    fn load_foundation_state(&self, recent_jobs_limit: usize) -> PortResult<FoundationStateV1> {
        self.load_core_state(recent_jobs_limit).map_err(port_error)
    }

    fn record_storage_check_and_enqueue(
        &self,
        request_id: RequestId,
        blob: &BlobRecordV1,
    ) -> PortResult<StorageCheckRecordV1> {
        let now_ms = unix_now_ms().map_err(port_error)?;
        let platform_blob = BlobRecord {
            sha256: blob.digest.as_str().to_owned(),
            byte_length: blob.byte_length,
            path: PathBuf::new(),
            reused: false,
        };
        let outcome = self
            .run_storage_check(&request_id.to_string(), &platform_blob, now_ms)
            .map_err(port_error)?;
        Ok(StorageCheckRecordV1 {
            check_id: parse_storage_check_id(&outcome.check_id)?,
            job_id: parse_job_id(&outcome.job_id)?,
            replay_status: if outcome.replayed {
                ReplayStatusV1::Replayed
            } else {
                ReplayStatusV1::Created
            },
        })
    }

    fn reserve_credential_save(
        &self,
        request_id: RequestId,
        provider: CredentialProviderV1,
        display_label: &str,
    ) -> PortResult<SaveCredentialPlanV1> {
        self.reserve_core_credential(request_id, provider, display_label)
            .map_err(port_error)
    }

    fn activate_credential(
        &self,
        request_id: RequestId,
        credential_id: CredentialId,
    ) -> PortResult<CredentialReferenceV1> {
        self.activate_core_credential(request_id, credential_id)
            .map_err(port_error)
    }

    fn prepare_credential_delete(
        &self,
        request_id: RequestId,
        credential_id: CredentialId,
    ) -> PortResult<DeleteCredentialPlanV1> {
        self.prepare_core_credential_delete(request_id, credential_id)
            .map_err(port_error)
    }

    fn finish_credential_delete(
        &self,
        request_id: RequestId,
        credential_id: CredentialId,
    ) -> PortResult<()> {
        self.finish_core_credential_delete(request_id, credential_id)
            .map_err(port_error)
    }
}

impl Database {
    fn load_core_state(&self, recent_jobs_limit: usize) -> PlatformResult<FoundationStateV1> {
        let connection = self.connection()?;
        let mut credential_query = connection.prepare(
            "SELECT credential_id, provider, display_label, status, updated_at_ms
             FROM credential_references
             ORDER BY updated_at_ms DESC, credential_id
             LIMIT 32",
        )?;
        let credential_references = credential_query
            .query_map([], core_credential_from_row)?
            .collect::<Result<Vec<_>, _>>()?;

        let mut job_query = connection.prepare(
            "SELECT j.job_id, j.state, j.attempt, j.retry_limit, j.updated_at_ms,
                    f.failure_code, f.user_action_key
             FROM jobs j LEFT JOIN job_failures f ON f.job_id = j.job_id
             ORDER BY j.updated_at_ms DESC, j.job_id LIMIT ?1",
        )?;
        let recent_jobs = job_query
            .query_map([recent_jobs_limit.min(50) as i64], |row| {
                let state: String = row.get(1)?;
                let attempts: i64 = row.get(2)?;
                let retry_limit: i64 = row.get(3)?;
                let failure_code: Option<String> = row.get(5)?;
                let user_action: Option<String> = row.get(6)?;
                Ok(JobSnapshotV1 {
                    job_id: parse_job_id_sql(&row.get::<_, String>(0)?)?,
                    kind: JobKindV1::VerifyBlobV1,
                    status: match state.as_str() {
                        "queued" if attempts > 0 => JobStatusV1::RetryWaiting,
                        "queued" => JobStatusV1::Pending,
                        "running" => JobStatusV1::Running,
                        "succeeded" => JobStatusV1::Succeeded,
                        "failed" => JobStatusV1::Failed,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    },
                    attempts: u16::try_from(attempts)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, attempts))?,
                    max_attempts: u16::try_from(retry_limit + 1).map_err(|_| {
                        rusqlite::Error::IntegralValueOutOfRange(3, retry_limit + 1)
                    })?,
                    updated_at: timestamp_from_ms_sql(row.get(4)?)?,
                    terminal_failure: match (failure_code, user_action) {
                        (Some(code), Some(action)) => Some(TerminalFailureV1 {
                            code: error_code_from_db(&code),
                            user_action: user_action_from_db(&action),
                        }),
                        (None, None) => None,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    },
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(FoundationStateV1 {
            versions: FoundationVersionsV1 {
                application: env!("CARGO_PKG_VERSION").to_owned(),
                database_schema: database_schema_version(&connection)?,
                job_pipeline: 1,
            },
            local_settings: LocalSettingsSnapshotV1 {
                local_only: true,
                revision: 0,
                authority_health: LocalOnlyAuthorityHealthV1::FailClosedDefault,
                storage_status: StorageStatusV1::Ready,
                deletion_health: self.deletion_health(unix_now_ms()?)?,
            },
            credential_references,
            recent_jobs,
        })
    }

    fn reserve_core_credential(
        &self,
        request_id: RequestId,
        provider: CredentialProviderV1,
        display_label: &str,
    ) -> PlatformResult<SaveCredentialPlanV1> {
        let request = request_id.to_string();
        let provider_text = provider_to_db(provider);
        let envelope = digest_text(&format!(
            "save_credential_v1:{request}:{provider_text}:{display_label}"
        ));
        let now_ms = unix_now_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some((command, stored_envelope)) = transaction
            .query_row(
                "SELECT command_name, envelope_hash FROM command_receipts WHERE request_id = ?1",
                [&request],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if command != "save_credential_v1" || stored_envelope != envelope {
                return Err(PlatformError::Conflict("command_envelope_changed"));
            }
            let (reference, locator) = query_credential_by_save_request(&transaction, &request)?
                .ok_or(PlatformError::Corrupt(
                    "credential_receipt_without_reference",
                ))?;
            transaction.commit()?;
            return if reference.status == CredentialStatusV1::Active {
                Ok(SaveCredentialPlanV1::Replay { reference })
            } else {
                Ok(SaveCredentialPlanV1::WriteSecret {
                    locator,
                    pending_reference: reference,
                })
            };
        }

        let locator_text = Uuid::new_v4().hyphenated().to_string();
        let credential_id_text = stable_id("credential", &request);
        transaction.execute(
            "INSERT INTO credential_references(
                locator, credential_id, save_request_id, delete_request_id,
                provider, display_label, status, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, 'pending_save', ?6, ?6)",
            params![
                locator_text,
                credential_id_text,
                request,
                provider_text,
                display_label,
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO command_receipts(
                request_id, command_name, envelope_hash, response_json, created_at_ms
             ) VALUES (?1, 'save_credential_v1', ?2, ?3, ?4)",
            params![
                request,
                envelope,
                serde_json::json!({"credential_id": credential_id_text}).to_string(),
                now_ms
            ],
        )?;
        let (reference, locator) = query_credential_by_save_request(&transaction, &request)?
            .ok_or(PlatformError::Corrupt("credential_insert_missing"))?;
        transaction.commit()?;
        Ok(SaveCredentialPlanV1::WriteSecret {
            locator,
            pending_reference: reference,
        })
    }

    fn activate_core_credential(
        &self,
        request_id: RequestId,
        credential_id: CredentialId,
    ) -> PlatformResult<CredentialReferenceV1> {
        let now_ms = unix_now_ms()?;
        let connection = self.connection()?;
        let changed = connection.execute(
            "UPDATE credential_references
             SET status = 'active', updated_at_ms = ?3
             WHERE save_request_id = ?1 AND credential_id = ?2
               AND status IN ('pending_save', 'active')",
            params![request_id.to_string(), credential_id.to_string(), now_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict("credential_activation_mismatch"));
        }
        query_credential_by_id(&connection, &credential_id.to_string())?
            .map(|(reference, _)| reference)
            .ok_or(PlatformError::Corrupt("credential_activation_missing"))
    }

    fn prepare_core_credential_delete(
        &self,
        request_id: RequestId,
        credential_id: CredentialId,
    ) -> PlatformResult<DeleteCredentialPlanV1> {
        let request = request_id.to_string();
        let credential = credential_id.to_string();
        let envelope = digest_text(&format!("delete_credential_v1:{request}:{credential}"));
        let now_ms = unix_now_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((command, stored_envelope)) = transaction
            .query_row(
                "SELECT command_name, envelope_hash FROM command_receipts WHERE request_id = ?1",
                [&request],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        {
            if command != "delete_credential_v1" || stored_envelope != envelope {
                return Err(PlatformError::Conflict("command_envelope_changed"));
            }
            let existing = query_credential_by_id(&transaction, &credential)?;
            transaction.commit()?;
            return match existing {
                Some((_, locator)) => Ok(DeleteCredentialPlanV1::DeleteSecret {
                    locator,
                    credential_id,
                }),
                None => Ok(DeleteCredentialPlanV1::Replay {
                    credential_id,
                    deleted: true,
                }),
            };
        }

        let (_, locator) = query_credential_by_id(&transaction, &credential)?
            .ok_or(PlatformError::InvalidInput("credential_id"))?;
        transaction.execute(
            "UPDATE credential_references
             SET status = 'pending_delete', delete_request_id = ?2, updated_at_ms = ?3
             WHERE credential_id = ?1",
            params![credential, request, now_ms],
        )?;
        transaction.execute(
            "INSERT INTO command_receipts(
                request_id, command_name, envelope_hash, response_json, created_at_ms
             ) VALUES (?1, 'delete_credential_v1', ?2, ?3, ?4)",
            params![
                request,
                envelope,
                serde_json::json!({"credential_id": credential, "deleted": true}).to_string(),
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok(DeleteCredentialPlanV1::DeleteSecret {
            locator,
            credential_id,
        })
    }

    fn finish_core_credential_delete(
        &self,
        request_id: RequestId,
        credential_id: CredentialId,
    ) -> PlatformResult<()> {
        let changed = self.connection()?.execute(
            "DELETE FROM credential_references
             WHERE credential_id = ?1 AND delete_request_id = ?2 AND status = 'pending_delete'",
            params![credential_id.to_string(), request_id.to_string()],
        )?;
        if changed > 1 {
            return Err(PlatformError::Corrupt("credential_delete_cardinality"));
        }
        Ok(())
    }
}

fn query_credential_by_save_request(
    connection: &Connection,
    request_id: &str,
) -> PlatformResult<Option<(CredentialReferenceV1, CredentialLocator)>> {
    Ok(connection
        .query_row(
            "SELECT credential_id, provider, display_label, status, updated_at_ms, locator
             FROM credential_references WHERE save_request_id = ?1",
            [request_id],
            credential_and_locator_from_row,
        )
        .optional()?)
}

fn query_credential_by_id(
    connection: &Connection,
    credential_id: &str,
) -> PlatformResult<Option<(CredentialReferenceV1, CredentialLocator)>> {
    Ok(connection
        .query_row(
            "SELECT credential_id, provider, display_label, status, updated_at_ms, locator
             FROM credential_references WHERE credential_id = ?1",
            [credential_id],
            credential_and_locator_from_row,
        )
        .optional()?)
}

fn credential_and_locator_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<(CredentialReferenceV1, CredentialLocator)> {
    let reference = core_credential_from_row(row)?;
    let locator_text: String = row.get(5)?;
    let locator =
        CredentialLocator::new(locator_text).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok((reference, locator))
}

fn core_credential_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CredentialReferenceV1> {
    let credential_id: String = row.get(0)?;
    let provider: String = row.get(1)?;
    let status: String = row.get(3)?;
    Ok(CredentialReferenceV1 {
        credential_id: parse_credential_id_sql(&credential_id)?,
        provider: provider_from_db(&provider)?,
        display_label: row.get(2)?,
        status: credential_status_from_db(&status)?,
        updated_at: timestamp_from_ms_sql(row.get(4)?)?,
    })
}

fn parse_credential_id_sql(value: &str) -> rusqlite::Result<CredentialId> {
    let uuid = Uuid::parse_str(value).map_err(|_| rusqlite::Error::InvalidQuery)?;
    CredentialId::new(uuid).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn parse_job_id_sql(value: &str) -> rusqlite::Result<JobId> {
    let uuid = Uuid::parse_str(value).map_err(|_| rusqlite::Error::InvalidQuery)?;
    JobId::new(uuid).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn parse_storage_check_id(value: &str) -> PortResult<StorageCheckId> {
    let uuid = Uuid::parse_str(value).map_err(|_| PortError::new(PortErrorKind::DataIntegrity))?;
    StorageCheckId::new(uuid).map_err(|_| PortError::new(PortErrorKind::DataIntegrity))
}

fn parse_job_id(value: &str) -> PortResult<JobId> {
    let uuid = Uuid::parse_str(value).map_err(|_| PortError::new(PortErrorKind::DataIntegrity))?;
    JobId::new(uuid).map_err(|_| PortError::new(PortErrorKind::DataIntegrity))
}

fn provider_to_db(provider: CredentialProviderV1) -> &'static str {
    match provider {
        CredentialProviderV1::Gmail => "gmail",
        CredentialProviderV1::OpenAi => "open_ai",
    }
}

fn provider_from_db(value: &str) -> rusqlite::Result<CredentialProviderV1> {
    match value {
        "gmail" => Ok(CredentialProviderV1::Gmail),
        "open_ai" => Ok(CredentialProviderV1::OpenAi),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn credential_status_from_db(value: &str) -> rusqlite::Result<CredentialStatusV1> {
    match value {
        "active" => Ok(CredentialStatusV1::Active),
        "pending_save" => Ok(CredentialStatusV1::PendingSave),
        "pending_delete" => Ok(CredentialStatusV1::PendingDelete),
        "save_failed" => Ok(CredentialStatusV1::NeedsAttention),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn timestamp_from_ms_sql(value: i64) -> rusqlite::Result<String> {
    timestamp_from_ms(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn timestamp_from_ms(value: i64) -> PlatformResult<String> {
    let nanoseconds = i128::from(value)
        .checked_mul(1_000_000)
        .ok_or(PlatformError::Corrupt("timestamp_range"))?;
    let timestamp = time::OffsetDateTime::from_unix_timestamp_nanos(nanoseconds)
        .map_err(|_| PlatformError::Corrupt("timestamp_range"))?;
    timestamp
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| PlatformError::Corrupt("timestamp_format"))
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

fn error_code_from_db(value: &str) -> ErrorCodeV1 {
    match value {
        "blob_missing" => ErrorCodeV1::NotFound,
        "blob_integrity_failed" => ErrorCodeV1::DataIntegrity,
        "blob_unavailable" => ErrorCodeV1::StorageUnavailable,
        _ => ErrorCodeV1::Internal,
    }
}

fn user_action_from_db(value: &str) -> UserActionKeyV1 {
    match value {
        "rerun_storage_check" => UserActionKeyV1::ReviewStorage,
        "retry_when_storage_available" => UserActionKeyV1::Retry,
        _ => UserActionKeyV1::RestartApplication,
    }
}

fn port_error(error: PlatformError) -> PortError {
    let kind = match error {
        PlatformError::Conflict(_) => PortErrorKind::Conflict,
        PlatformError::Corrupt(_) => PortErrorKind::DataIntegrity,
        PlatformError::InvalidInput(_) => PortErrorKind::NotFound,
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PortErrorKind::NotFound
        }
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            PortErrorKind::PermissionDenied
        }
        PlatformError::Io(_) | PlatformError::Sqlite(_) => PortErrorKind::Unavailable,
        PlatformError::LeaseLost => PortErrorKind::Conflict,
        _ => PortErrorKind::Internal,
    };
    PortError::new(kind)
}

fn platform_credential_error(error: PortError) -> PlatformError {
    match error.kind {
        PortErrorKind::Conflict => PlatformError::Conflict("credential"),
        PortErrorKind::DataIntegrity => PlatformError::Corrupt("credential"),
        PortErrorKind::NotFound => PlatformError::Keychain("not_found"),
        PortErrorKind::PermissionDenied => PlatformError::Keychain("permission_denied"),
        PortErrorKind::Unavailable => PlatformError::Keychain("unavailable"),
        PortErrorKind::Internal => PlatformError::Keychain("internal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_snapshot_is_existing_file_read_only() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1_000).unwrap();
        let before_hash = hash_file(&paths.database).unwrap();
        let before_identity =
            private_database_identity(&fs::symlink_metadata(&paths.database).unwrap()).unwrap();
        let mut before_entries = fs::read_dir(&paths.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        before_entries.sort();

        let snapshot = database.compatibility_snapshot().unwrap();

        assert_eq!(snapshot.schema_version as usize, MIGRATIONS.len());
        assert_eq!(hash_file(&paths.database).unwrap(), before_hash);
        assert_eq!(
            private_database_identity(&fs::symlink_metadata(&paths.database).unwrap()).unwrap(),
            before_identity
        );
        let mut after_entries = fs::read_dir(&paths.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        after_entries.sort();
        assert_eq!(after_entries, before_entries);
    }

    #[test]
    fn compatibility_snapshot_never_recreates_a_missing_database() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1_000).unwrap();
        for path in [
            paths.database.clone(),
            path_with_suffix(&paths.database, "-wal"),
            path_with_suffix(&paths.database, "-shm"),
        ] {
            fs::remove_file(path).ok();
        }

        assert!(database.compatibility_snapshot().is_err());
        assert!(!paths.database.exists());
    }

    #[test]
    fn post_commit_failpoints_restore_exact_managed_pre_upgrade_database() {
        for failpoint in [
            "post_commit_verification",
            "post_checkpoint",
            "post_database_sync",
            "post_directory_sync",
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
            let source_version = create_pre_target_database(&paths, 10);
            set_migration_recovery_failpoint(failpoint);

            assert!(
                matches!(
                    Database::open(&paths, 1_000),
                    Err(PlatformError::Corrupt("migration_recovery_injected"))
                ),
                "failpoint {failpoint}"
            );
            let managed = BackupRepository::new(&paths)
                .list_verified(None, 100)
                .unwrap()
                .into_iter()
                .find(|record| record.reason == BackupReason::PreUpgrade)
                .unwrap();
            let verified = BackupRepository::new(&paths)
                .verify(
                    &managed.backup_id.to_string(),
                    Some(managed.manifest_sha256.as_str()),
                )
                .unwrap();
            assert_eq!(
                hash_file(&paths.database).unwrap(),
                verified.manifest.database.sha256,
                "failpoint {failpoint}"
            );
            let restored = open_read_only_connection(&paths.database).unwrap();
            assert_eq!(
                restored
                    .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                    .unwrap(),
                source_version,
                "failpoint {failpoint}"
            );
            verify_applied_migrations(&restored, source_version).unwrap();
            assert!(!paths.upgrade_recovery_intent.exists());
            assert!(!paths.upgrade_recovery_intent_sha256.exists());
            drop(restored);

            Database::open(&paths, 2_000).unwrap();
            assert_eq!(
                open_read_only_connection(&paths.database)
                    .unwrap()
                    .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                    .unwrap(),
                MIGRATIONS.last().unwrap().version,
                "failpoint {failpoint}"
            );
        }
    }

    fn create_v1_database(paths: &PrivateAppPaths, now_ms: i64) {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&paths.database)
            .unwrap();
        let mut connection = open_connection(&paths.database).unwrap();
        apply_migration(&mut connection, &MIGRATIONS[0], now_ms).unwrap();
        connection
            .execute(
                "INSERT INTO settings(setting_key, value_json, updated_at_ms)
                 VALUES ('retained', '{\"value\":true}', ?1)",
                [now_ms],
            )
            .unwrap();
    }

    fn create_v2_database(paths: &PrivateAppPaths, now_ms: i64) {
        create_v1_database(paths, now_ms);
        let mut connection = open_connection(&paths.database).unwrap();
        apply_migration(&mut connection, &MIGRATIONS[1], now_ms + 1).unwrap();
    }

    fn create_v3_database(paths: &PrivateAppPaths, now_ms: i64) {
        create_v2_database(paths, now_ms);
        let mut connection = open_connection(&paths.database).unwrap();
        apply_migration(&mut connection, &MIGRATIONS[2], now_ms + 2).unwrap();
    }

    fn create_v4_database(paths: &PrivateAppPaths, now_ms: i64) {
        create_v3_database(paths, now_ms);
        let mut connection = open_connection(&paths.database).unwrap();
        apply_migration(&mut connection, &MIGRATIONS[3], now_ms + 3).unwrap();
    }

    fn create_v5_database(paths: &PrivateAppPaths, now_ms: i64) {
        create_v4_database(paths, now_ms);
        let mut connection = open_connection(&paths.database).unwrap();
        apply_migration(&mut connection, &MIGRATIONS[4], now_ms + 4).unwrap();
    }

    fn create_v8_database(paths: &PrivateAppPaths, now_ms: i64) {
        create_v5_database(paths, now_ms);
        let mut connection = open_connection(&paths.database).unwrap();
        for (offset, migration) in MIGRATIONS[5..8].iter().enumerate() {
            apply_migration(
                &mut connection,
                migration,
                now_ms + i64::try_from(offset).unwrap() + 5,
            )
            .unwrap();
        }
    }

    fn create_v11_database(paths: &PrivateAppPaths, now_ms: i64) {
        create_v8_database(paths, now_ms);
        let mut connection = open_connection(&paths.database).unwrap();
        for (offset, migration) in MIGRATIONS[8..11].iter().enumerate() {
            apply_migration(
                &mut connection,
                migration,
                now_ms + i64::try_from(offset).unwrap() + 8,
            )
            .unwrap();
        }
    }

    fn create_v12_database(paths: &PrivateAppPaths, now_ms: i64) {
        create_v11_database(paths, now_ms);
        let mut connection = open_connection(&paths.database).unwrap();
        apply_migration(&mut connection, &MIGRATIONS[11], now_ms + 11).unwrap();
    }

    fn create_pre_target_database(paths: &PrivateAppPaths, now_ms: i64) -> i64 {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&paths.database)
            .unwrap();
        let mut connection = open_connection(&paths.database).unwrap();
        for (offset, migration) in MIGRATIONS[..MIGRATIONS.len() - 1].iter().enumerate() {
            apply_migration(
                &mut connection,
                migration,
                now_ms + i64::try_from(offset).unwrap(),
            )
            .unwrap();
        }
        MIGRATIONS[MIGRATIONS.len() - 2].version
    }

    fn only_backup(paths: &PrivateAppPaths) -> PathBuf {
        fs::read_dir(&paths.backups)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("sqlite3"))
            .unwrap()
    }

    fn only_sidecar(paths: &PrivateAppPaths) -> PathBuf {
        fs::read_dir(&paths.backups)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .unwrap()
    }

    #[test]
    fn existing_v0_migration_writes_final_target_backup_and_reaches_v10() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let legacy = Connection::open(&paths.database).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE legacy(value TEXT NOT NULL);
                 INSERT INTO legacy(value) VALUES ('retained');",
            )
            .unwrap();
        drop(legacy);

        Database::open(&paths, 1234).unwrap();
        let files = fs::read_dir(&paths.backups)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(
            files
                .iter()
                .filter(|path| path.extension().is_some())
                .count(),
            2
        );
        assert_eq!(
            files
                .iter()
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| Uuid::parse_str(name).is_ok())
                })
                .count(),
            1
        );
        let backup = files
            .iter()
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("sqlite3"))
            .unwrap();
        let sidecar = files
            .iter()
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .unwrap();
        let evidence: serde_json::Value =
            serde_json::from_slice(&fs::read(sidecar).unwrap()).unwrap();
        assert_eq!(
            evidence["backup_sha256"].as_str().unwrap(),
            hash_file(backup).unwrap()
        );
        assert_eq!(evidence["source_schema_version"], 0);
        assert_eq!(evidence["target_schema_version"], 14);

        let connection = open_connection(&paths.database).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            14
        );
        verify_applied_migrations(&connection, 14).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT receipt_revision, photo_revision,
                            reconciliation_revision
                     FROM revision_state WHERE singleton = 1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    }
                )
                .unwrap(),
            (0, 0, 0)
        );
    }

    #[test]
    fn expired_lease_is_reclaimed_with_a_new_fence() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        let missing = "0".repeat(64);
        database
            .enqueue_verify_blob("lease-reclaim", &missing, 10)
            .unwrap();

        let first = database.claim("worker-a", 10, 5).unwrap().unwrap();
        assert!(database.claim("worker-b", 14, 5).unwrap().is_none());
        let reclaimed = database.claim("worker-b", 15, 5).unwrap().unwrap();
        assert!(reclaimed.fence > first.fence);
        assert!(matches!(
            database.fail_permanently(&first, "stale", "retry", 16),
            Err(PlatformError::LeaseLost)
        ));
    }

    #[test]
    fn v1_to_v10_backup_is_hashed_openable_restorable_and_retains_data() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v1_database(&paths, 10);

        Database::open(&paths, 20).unwrap();
        let files = fs::read_dir(&paths.backups)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(
            files
                .iter()
                .filter(|path| path.extension().is_some())
                .count(),
            2
        );
        assert_eq!(
            files
                .iter()
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| Uuid::parse_str(name).is_ok())
                })
                .count(),
            1
        );
        let backup = files
            .iter()
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("sqlite3"))
            .unwrap();
        let sidecar = files
            .iter()
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .unwrap();
        let evidence: serde_json::Value =
            serde_json::from_slice(&fs::read(sidecar).unwrap()).unwrap();
        assert_eq!(evidence["source_schema_version"], 1);
        assert_eq!(evidence["target_schema_version"], 14);
        assert_eq!(
            evidence["backup_sha256"].as_str().unwrap(),
            hash_file(backup).unwrap()
        );

        let retained_backup = open_connection(backup).unwrap();
        assert_eq!(
            retained_backup
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        let retained: String = retained_backup
            .query_row(
                "SELECT value_json FROM settings WHERE setting_key = 'retained'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained, "{\"value\":true}");

        let migrated = open_connection(&paths.database).unwrap();
        assert_eq!(
            migrated
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            14
        );
        verify_applied_migrations(&migrated, 14).unwrap();
        assert_eq!(
            migrated
                .query_row(
                    "SELECT value_json FROM settings WHERE setting_key = 'retained'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "{\"value\":true}"
        );

        let restored_paths =
            PrivateAppPaths::create(temporary.path().join("restored-app")).unwrap();
        fs::copy(backup, &restored_paths.database).unwrap();
        let restored = open_connection(&restored_paths.database).unwrap();
        verify_database(&restored).unwrap();
        assert_eq!(
            restored
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            restored
                .query_row(
                    "SELECT value_json FROM settings WHERE setting_key = 'retained'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "{\"value\":true}"
        );
    }

    #[test]
    fn v2_to_v10_backup_retains_v2_and_names_final_target() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v2_database(&paths, 10);
        open_connection(&paths.database)
            .unwrap()
            .execute_batch(
                "INSERT INTO local_sources(
                    source_id, source_kind, identity_key, canonical_locator,
                    status, no_blob_reason, created_at_ms, updated_at_ms
                 ) VALUES (
                    '11111111-1111-4111-8111-111111111111', 'folder_image',
                    'migration-source', '/synthetic/migration.png',
                    'quarantined', 'synthetic', 10, 10
                 );
                 INSERT INTO evidence(
                    evidence_id, source_id, evidence_kind, state, created_at_ms, updated_at_ms
                 ) VALUES (
                    '22222222-2222-4222-8222-222222222222',
                    '11111111-1111-4111-8111-111111111111',
                    'image', 'assigned', 10, 10
                 );
                 INSERT INTO catalog_items(
                    item_id, display_name, attributes_json, active,
                    created_revision, updated_revision
                 ) VALUES (
                    '33333333-3333-4333-8333-333333333333',
                    'Migration item', '{}', 1, 1, 1
                 );
                 INSERT INTO item_evidence(item_id, evidence_id, assigned_revision)
                 VALUES (
                    '33333333-3333-4333-8333-333333333333',
                    '22222222-2222-4222-8222-222222222222', 1
                 );",
            )
            .unwrap();

        Database::open(&paths, 20).unwrap();
        let migrated = open_connection(&paths.database).unwrap();
        assert_eq!(
            migrated
                .query_row("SELECT evidence_kind FROM evidence", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "image"
        );
        assert_eq!(
            migrated
                .query_row("SELECT COUNT(*) FROM item_evidence", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        migrated
            .execute(
                "INSERT INTO evidence(
                    evidence_id, source_id, evidence_kind, state, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, 'receipt_order_line', 'unresolved', 20, 20)",
                params![
                    "44444444-4444-4444-8444-444444444444",
                    "11111111-1111-4111-8111-111111111111"
                ],
            )
            .unwrap();
        drop(migrated);
        let backup = only_backup(&paths);
        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(only_sidecar(&paths)).unwrap()).unwrap();
        assert_eq!(sidecar["source_schema_version"], 2);
        assert_eq!(sidecar["target_schema_version"], 14);
        assert_eq!(
            sidecar["backup_sha256"].as_str().unwrap(),
            hash_file(&backup).unwrap()
        );
        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        drop(retained);
        let restored_paths =
            PrivateAppPaths::create(temporary.path().join("restored-v2-app")).unwrap();
        fs::copy(&backup, &restored_paths.database).unwrap();
        let restored = open_connection(&restored_paths.database).unwrap();
        verify_database(&restored).unwrap();
        assert_eq!(
            restored
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }

    #[test]
    fn v3_to_v10_backup_is_openable_restorable_and_retains_receipts() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v3_database(&paths, 10);
        open_connection(&paths.database)
            .unwrap()
            .execute_batch(
                "INSERT INTO local_sources(
                    source_id, source_kind, identity_key, canonical_locator, raw_sha256,
                    blob_sha256, byte_length, media_type, status, no_blob_reason,
                    created_at_ms, updated_at_ms
                 ) VALUES (
                    '11111111-1111-4111-8111-111111111111', 'eml',
                    'v3-receipt', '/synthetic/v3.eml',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    NULL, 0, 'message/rfc822', 'quarantined', 'migration_fixture', 10, 10
                 );
                 INSERT INTO receipt_parses(
                    parse_id, source_id, raw_sha256, parser_revision,
                    sanitizer_revision, canonical_input_sha256, created_at_ms
                 ) VALUES (
                    '22222222-2222-4222-8222-222222222222',
                    '11111111-1111-4111-8111-111111111111',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    'parser-v1', 'sanitizer-v1',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    10
                 );",
            )
            .unwrap();

        Database::open(&paths, 20).unwrap();

        let migrated = open_connection(&paths.database).unwrap();
        verify_database(&migrated).unwrap();
        assert_eq!(
            migrated
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            14
        );
        assert_eq!(
            migrated
                .query_row("SELECT COUNT(*) FROM receipt_parses", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        drop(migrated);

        let backup = only_backup(&paths);
        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(only_sidecar(&paths)).unwrap()).unwrap();
        assert_eq!(sidecar["source_schema_version"], 3);
        assert_eq!(sidecar["target_schema_version"], 14);
        assert_eq!(
            sidecar["backup_sha256"].as_str().unwrap(),
            hash_file(&backup).unwrap()
        );
        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            retained
                .query_row("SELECT COUNT(*) FROM receipt_parses", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        drop(retained);

        let restored_paths =
            PrivateAppPaths::create(temporary.path().join("restored-v3-app")).unwrap();
        fs::copy(&backup, &restored_paths.database).unwrap();
        let restored = open_connection(&restored_paths.database).unwrap();
        verify_database(&restored).unwrap();
        assert_eq!(
            restored
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            3
        );
    }

    #[test]
    fn v4_to_v10_backup_is_verified_restorable_retained_and_preserves_rows() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v4_database(&paths, 10);
        open_connection(&paths.database)
            .unwrap()
            .execute_batch(
                "UPDATE revision_state
                 SET catalog_revision = 7,
                     evidence_generation = 8,
                     receipt_revision = 9
                 WHERE singleton = 1;
                 INSERT INTO deletion_previews(
                     snapshot_token, target_kind, target_id,
                     catalog_revision, evidence_generation, created_at_ms
                 ) VALUES ('retained-preview', 'source', 'retained-source', 7, 8, 13);",
            )
            .unwrap();

        Database::open(&paths, 20).unwrap();

        let migrated = open_connection(&paths.database).unwrap();
        verify_database(&migrated).unwrap();
        assert_eq!(
            migrated
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            14
        );
        verify_applied_migrations(&migrated, 14).unwrap();
        assert_eq!(
            migrated
                .query_row(
                    "SELECT catalog_revision, evidence_generation,
                            receipt_revision, photo_revision,
                            reconciliation_revision
                     FROM revision_state WHERE singleton = 1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .unwrap(),
            (7, 8, 9, 0, 0)
        );
        assert_eq!(
            migrated
                .query_row(
                    "SELECT catalog_revision, evidence_generation, photo_revision,
                            reconciliation_revision
                     FROM deletion_previews
                     WHERE snapshot_token = 'retained-preview'",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .unwrap(),
            (7, 8, 0, 0)
        );
        drop(migrated);

        let backup = only_backup(&paths);
        let backup_hash = hash_file(&backup).unwrap();
        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(only_sidecar(&paths)).unwrap()).unwrap();
        assert_eq!(sidecar["source_schema_version"], 4);
        assert_eq!(sidecar["target_schema_version"], 14);
        assert_eq!(sidecar["backup_sha256"], backup_hash);

        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            4
        );
        verify_applied_migrations(&retained, 4).unwrap();
        assert_eq!(
            retained
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('revision_state')
                     WHERE name = 'photo_revision'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            retained
                .query_row(
                    "SELECT catalog_revision, evidence_generation, receipt_revision
                     FROM revision_state WHERE singleton = 1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .unwrap(),
            (7, 8, 9)
        );
        drop(retained);

        let restored_paths =
            PrivateAppPaths::create(temporary.path().join("restored-v4-app")).unwrap();
        fs::copy(&backup, &restored_paths.database).unwrap();
        let restored = open_connection(&restored_paths.database).unwrap();
        verify_database(&restored).unwrap();
        assert_eq!(
            restored
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            4
        );
        assert_eq!(
            restored
                .query_row(
                    "SELECT COUNT(*) FROM deletion_previews
                     WHERE snapshot_token = 'retained-preview'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        drop(restored);

        Database::open(&paths, 21).unwrap();
        assert_eq!(
            fs::read_dir(&paths.backups).unwrap().count(),
            5,
            "opening an already-current database must retain the original backup"
        );
        assert_eq!(hash_file(&backup).unwrap(), backup_hash);
    }

    #[test]
    fn rejects_applied_checksum_tampering() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        Database::open(&paths, 1).unwrap();
        open_connection(&paths.database)
            .unwrap()
            .execute(
                "UPDATE schema_migrations SET sha256 = ?1 WHERE version = 2",
                ["0".repeat(64)],
            )
            .unwrap();
        assert!(matches!(
            Database::open(&paths, 2),
            Err(PlatformError::Corrupt("migration_applied_checksum"))
        ));
    }

    #[test]
    fn rejects_applied_migration_gap() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        Database::open(&paths, 1).unwrap();
        open_connection(&paths.database)
            .unwrap()
            .execute("DELETE FROM schema_migrations WHERE version = 2", [])
            .unwrap();
        assert!(matches!(
            Database::open(&paths, 2),
            Err(PlatformError::Corrupt("migration_applied_gap"))
        ));
    }

    #[test]
    fn direct_failed_v3_transaction_leaves_v2_live() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v2_database(&paths, 10);
        let mut connection = open_connection(&paths.database).unwrap();
        create_verified_backup(&connection, &paths, 20, 2, 6).unwrap();
        const BAD: Migration = Migration {
            version: 3,
            sql: "CREATE TABLE should_roll_back(value INTEGER) STRICT; INVALID SQL;",
            sha256: "",
        };
        assert!(apply_migration(&mut connection, &BAD, 20).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT value_json FROM settings WHERE setting_key = 'retained'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "{\"value\":true}"
        );
        assert!(connection
            .query_row("SELECT 1 FROM should_roll_back", [], |_| Ok(()))
            .is_err());
        let backup = only_backup(&paths);
        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(only_sidecar(&paths)).unwrap()).unwrap();
        assert_eq!(sidecar["source_schema_version"], 2);
        assert_eq!(sidecar["target_schema_version"], 6);
    }

    #[test]
    fn v1_start_commits_v2_before_v3_failure_and_retains_v1_backup() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v1_database(&paths, 10);
        let mut connection = open_connection(&paths.database).unwrap();
        create_verified_backup(&connection, &paths, 20, 1, 6).unwrap();
        apply_migration(&mut connection, &MIGRATIONS[1], 20).unwrap();
        const BAD_V3: Migration = Migration {
            version: 3,
            sql: "CREATE TABLE v3_partial(value INTEGER) STRICT; INVALID SQL;",
            sha256: "",
        };
        assert!(apply_migration(&mut connection, &BAD_V3, 20).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        verify_applied_migrations(&connection, 2).unwrap();
        assert!(connection
            .query_row("SELECT 1 FROM v3_partial", [], |_| Ok(()))
            .is_err());

        let backup = only_backup(&paths);
        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(only_sidecar(&paths)).unwrap()).unwrap();
        assert_eq!(sidecar["source_schema_version"], 1);
        assert_eq!(sidecar["target_schema_version"], 6);
    }

    #[test]
    fn failed_v5_transaction_leaves_v4_live_and_backup_restorable() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v4_database(&paths, 10);
        let mut connection = open_connection(&paths.database).unwrap();
        create_verified_backup(&connection, &paths, 20, 4, 6).unwrap();
        const BAD_V5: Migration = Migration {
            version: 5,
            sql: "ALTER TABLE revision_state
                  ADD COLUMN photo_revision INTEGER NOT NULL DEFAULT 0;
                  CREATE TABLE v5_partial(value INTEGER) STRICT;
                  INVALID SQL;",
            sha256: "",
        };

        assert!(apply_migration(&mut connection, &BAD_V5, 20).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            4
        );
        verify_applied_migrations(&connection, 4).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('revision_state')
                     WHERE name = 'photo_revision'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert!(connection
            .query_row("SELECT 1 FROM v5_partial", [], |_| Ok(()))
            .is_err());

        let backup = only_backup(&paths);
        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            4
        );
        verify_applied_migrations(&retained, 4).unwrap();
        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(only_sidecar(&paths)).unwrap()).unwrap();
        assert_eq!(sidecar["source_schema_version"], 4);
        assert_eq!(sidecar["target_schema_version"], 6);
        assert_eq!(sidecar["backup_sha256"], hash_file(&backup).unwrap());
    }

    #[test]
    fn v5_to_v10_backup_is_verified_restorable_and_preserves_photo_state() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v5_database(&paths, 10);
        open_connection(&paths.database)
            .unwrap()
            .execute(
                "UPDATE revision_state
                 SET catalog_revision = 3, receipt_revision = 4,
                     photo_revision = 5
                 WHERE singleton = 1",
                [],
            )
            .unwrap();

        Database::open(&paths, 20).unwrap();

        let migrated = open_connection(&paths.database).unwrap();
        assert_eq!(
            migrated
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            14
        );
        assert_eq!(
            migrated
                .query_row(
                    "SELECT catalog_revision, receipt_revision, photo_revision,
                            reconciliation_revision
                     FROM revision_state WHERE singleton = 1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .unwrap(),
            (3, 4, 5, 0)
        );

        let backup = only_backup(&paths);
        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            5
        );
        assert_eq!(
            retained
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('revision_state')
                     WHERE name = 'reconciliation_revision'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(only_sidecar(&paths)).unwrap()).unwrap();
        assert_eq!(sidecar["source_schema_version"], 5);
        assert_eq!(sidecar["target_schema_version"], 14);
        assert_eq!(sidecar["backup_sha256"], hash_file(&backup).unwrap());
    }

    #[test]
    fn failed_v6_transaction_leaves_v5_live_and_backup_restorable() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v5_database(&paths, 10);
        let mut connection = open_connection(&paths.database).unwrap();
        create_verified_backup(&connection, &paths, 20, 5, 6).unwrap();
        const BAD_V6: Migration = Migration {
            version: 6,
            sql: "ALTER TABLE revision_state
                  ADD COLUMN reconciliation_revision INTEGER NOT NULL DEFAULT 0;
                  CREATE TABLE v6_partial(value INTEGER) STRICT;
                  INVALID SQL;",
            sha256: "",
        };

        assert!(apply_migration(&mut connection, &BAD_V6, 20).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            5
        );
        verify_applied_migrations(&connection, 5).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('revision_state')
                     WHERE name = 'reconciliation_revision'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert!(connection
            .query_row("SELECT 1 FROM v6_partial", [], |_| Ok(()))
            .is_err());

        let backup = only_backup(&paths);
        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            5
        );
    }

    #[test]
    fn fresh_v14_schema_is_strict_restrictive_and_append_only() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        let connection = database.connection().unwrap();

        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            14
        );
        verify_applied_migrations(&connection, 14).unwrap();

        let strict_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_list
                 WHERE name GLOB 'photo_*' AND strict = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(strict_count, 24);
        let cascade_count: i64 = connection
            .query_row(
                "SELECT COUNT(*)
                 FROM pragma_table_list tables
                 JOIN pragma_foreign_key_list(tables.name) foreign_keys
                 WHERE tables.name GLOB 'photo_*'
                   AND foreign_keys.on_delete <> 'RESTRICT'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cascade_count, 0);
        let protected_table_count: i64 = connection
            .query_row(
                "SELECT COUNT(DISTINCT tbl_name)
                 FROM sqlite_schema
                 WHERE type = 'trigger'
                   AND name GLOB 'photo_*_no_update'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(protected_table_count, 15);
        let photo_revision: i64 = connection
            .query_row(
                "SELECT photo_revision FROM revision_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(photo_revision, 0);
        let reconciliation_revision: i64 = connection
            .query_row(
                "SELECT reconciliation_revision
                 FROM revision_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reconciliation_revision, 0);
        let reconciliation_table_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_list
                 WHERE name LIKE 'reconciliation_%' AND strict = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reconciliation_table_count, 7);
    }

    #[test]
    fn populated_v8_to_latest_backup_is_verified_restorable_and_retains_rows() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v8_database(&paths, 10);
        open_connection(&paths.database)
            .unwrap()
            .execute_batch(
                "INSERT INTO catalog_items(
                    item_id, display_name, attributes_json, active,
                    created_revision, updated_revision
                 ) VALUES (
                    '33333333-3333-4333-8333-333333333333',
                    'Retained top',
                    '{\"display_name\":\"Retained top\",\"category\":\"top\",\"subcategory\":null,\"brand\":null,\"primary_color\":null,\"size\":null,\"notes\":null,\"tags\":[]}',
                    1, 1, 1
                 );
                 UPDATE revision_state SET catalog_revision = 1 WHERE singleton = 1;",
            )
            .unwrap();

        Database::open(&paths, 30).unwrap();
        let migrated = open_connection(&paths.database).unwrap();
        assert_eq!(
            migrated
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            14
        );
        assert_eq!(
            migrated
                .query_row("SELECT display_name FROM catalog_items", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "Retained top"
        );
        assert_eq!(
            migrated
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_list
                     WHERE name LIKE 'outfit_recommendation_%' AND strict = 1",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            4
        );

        let backup = only_backup(&paths);
        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(only_sidecar(&paths)).unwrap()).unwrap();
        assert_eq!(sidecar["source_schema_version"], 8);
        assert_eq!(sidecar["target_schema_version"], 14);
        assert_eq!(
            sidecar["backup_sha256"].as_str().unwrap(),
            hash_file(&backup).unwrap()
        );
        let restored = open_connection(&backup).unwrap();
        verify_database(&restored).unwrap();
        assert_eq!(
            restored
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            8
        );
        assert_eq!(
            restored
                .query_row("SELECT display_name FROM catalog_items", [], |row| {
                    row.get::<_, String>(0)
                })
                .unwrap(),
            "Retained top"
        );
    }

    #[test]
    fn failed_v9_transaction_leaves_populated_v8_live_and_backup_restorable() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v8_database(&paths, 10);
        open_connection(&paths.database)
            .unwrap()
            .execute(
                "INSERT INTO settings(setting_key, value_json, updated_at_ms)
                 VALUES ('v8-retained', '{\"retained\":true}', 18)",
                [],
            )
            .unwrap();
        let mut connection = open_connection(&paths.database).unwrap();
        create_verified_backup(&connection, &paths, 20, 8, 9).unwrap();
        const BAD_V9: Migration = Migration {
            version: 9,
            sql: "CREATE TABLE v9_partial(value TEXT) STRICT;
                  INSERT INTO table_that_does_not_exist(value) VALUES ('fail');",
            sha256: "",
        };
        assert!(apply_migration(&mut connection, &BAD_V9, 21).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            8
        );
        assert!(connection
            .query_row("SELECT 1 FROM v9_partial", [], |_| Ok(()))
            .is_err());
        assert_eq!(
            connection
                .query_row(
                    "SELECT value_json FROM settings WHERE setting_key = 'v8-retained'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "{\"retained\":true}"
        );
        drop(connection);

        let backup = only_backup(&paths);
        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            8
        );
        assert_eq!(
            retained
                .query_row(
                    "SELECT value_json FROM settings WHERE setting_key = 'v8-retained'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "{\"retained\":true}"
        );
    }

    #[test]
    fn populated_v11_to_v12_is_backed_up_and_builds_strict_photokit_schema() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v11_database(&paths, 10);
        open_connection(&paths.database)
            .unwrap()
            .execute(
                "INSERT INTO deletion_previews(
                    snapshot_token, target_kind, target_id,
                    catalog_revision, evidence_generation, created_at_ms
                 ) VALUES ('v11-preview', 'source', 'v11-source', 3, 4, 19)",
                [],
            )
            .unwrap();

        Database::open(&paths, 30).unwrap();
        let migrated = open_connection(&paths.database).unwrap();
        assert_eq!(
            migrated
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            14
        );
        verify_applied_migrations(&migrated, 14).unwrap();
        assert_eq!(
            migrated
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_list
                     WHERE name LIKE 'photokit_%' AND strict = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            14
        );
        assert_eq!(
            migrated
                .query_row(
                    "SELECT photokit_revision FROM revision_state WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            migrated
                .query_row(
                    "SELECT photokit_revision FROM deletion_previews
                     WHERE snapshot_token = 'v11-preview'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        migrated
            .execute(
                "INSERT INTO deletion_previews(
                    snapshot_token, target_kind, target_id,
                    catalog_revision, evidence_generation, created_at_ms
                 ) VALUES ('photokit-preview', 'photokit_asset',
                           '11111111-1111-4111-8111-111111111111', 0, 0, 31)",
                [],
            )
            .unwrap();
        verify_database(&migrated).unwrap();

        let backup = only_backup(&paths);
        let retained = open_connection(&backup).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            11
        );
        assert_eq!(
            retained
                .query_row(
                    "SELECT COUNT(*) FROM deletion_previews
                     WHERE snapshot_token = 'v11-preview'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        let sidecar: serde_json::Value =
            serde_json::from_slice(&fs::read(only_sidecar(&paths)).unwrap()).unwrap();
        assert_eq!(sidecar["source_schema_version"], 11);
        assert_eq!(sidecar["target_schema_version"], 14);
    }

    #[test]
    fn failed_v12_rebuild_leaves_v11_live_with_verified_backup_and_foreign_keys_on() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v11_database(&paths, 10);
        let mut connection = open_connection(&paths.database).unwrap();
        create_verified_backup(&connection, &paths, 20, 11, 12).unwrap();
        const BAD_V12: Migration = Migration {
            version: 12,
            sql: "ALTER TABLE revision_state
                  ADD COLUMN photokit_revision INTEGER NOT NULL DEFAULT 0;
                  CREATE TABLE p06_partial(value INTEGER) STRICT;
                  INVALID SQL;",
            sha256: "",
        };
        assert!(apply_migration(&mut connection, &BAD_V12, 21).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            11
        );
        assert_eq!(
            connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('revision_state')
                     WHERE name = 'photokit_revision'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert!(connection
            .query_row("SELECT 1 FROM p06_partial", [], |_| Ok(()))
            .is_err());
        verify_database(&connection).unwrap();

        let backup = only_backup(&paths);
        let retained = open_connection(&backup).unwrap();
        verify_database(&retained).unwrap();
        assert_eq!(
            retained
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            11
        );
    }

    #[test]
    fn restored_photokit_state_drops_only_provisional_authority_and_preserves_history() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        Database::open(&paths, 1).unwrap();
        let mut connection = open_connection(&paths.database).unwrap();
        connection
            .execute_batch(
                "INSERT INTO photokit_enrollments(
                    enrollment_epoch, key_reference, state,
                    allow_icloud_downloads, operation_fence,
                    active_membership_generation, created_at_ms, activated_at_ms
                 ) VALUES (
                    '11111111-1111-4111-8111-111111111111', 'active-key',
                    'active', 0, 2, 1, 10, 11
                 );
                 INSERT INTO photokit_enrollments(
                    enrollment_epoch, key_reference, state,
                    allow_icloud_downloads, operation_fence,
                    active_membership_generation, created_at_ms
                 ) VALUES (
                    '22222222-2222-4222-8222-222222222222', 'pending-key',
                    'pending', 0, 0, NULL, 20
                 );
                 INSERT INTO photokit_locator_records(
                    locator_id, enrollment_epoch, operation_id, record_kind,
                    stable_row_id, key_version, lookup_hmac, nonce,
                    ciphertext, finalized, created_at_ms
                 ) VALUES (
                    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
                    '11111111-1111-4111-8111-111111111111', NULL, 'album',
                    '11111111-1111-4111-8111-111111111111', 1,
                    randomblob(32), randomblob(24), randomblob(17), 1, 10
                 );
                 UPDATE photokit_connector_state
                 SET state = 'reconciling', authorization = 'authorized',
                     active_enrollment_epoch =
                         '11111111-1111-4111-8111-111111111111',
                     active_membership_generation = 1,
                     observed_count = 1, available_count = 1,
                     unavailable_count = 0, last_complete_at_ms = 100,
                     updated_at_ms = 101
                 WHERE singleton = 1;
                 INSERT INTO photokit_operations(
                    operation_id, request_id, enrollment_epoch,
                    store_authority_epoch, reconciliation_fence,
                    proposed_membership_generation, trigger_kind, state,
                    observed_count, accepted_bytes, started_at_ms
                 ) VALUES (
                    '33333333-3333-4333-8333-333333333333',
                    '44444444-4444-4444-8444-444444444444',
                    '11111111-1111-4111-8111-111111111111',
                    (SELECT epoch FROM store_authority_epoch WHERE singleton = 1),
                    1, 1, 'startup', 'enumerating', 1, 3, 50
                 );
                 UPDATE photokit_operations SET state = 'materializing'
                 WHERE operation_id = '33333333-3333-4333-8333-333333333333';
                 INSERT INTO photokit_membership_generations(
                    enrollment_epoch, membership_generation, operation_id,
                    observed_count, available_count, unavailable_count,
                    completed_at_ms
                 ) VALUES (
                    '11111111-1111-4111-8111-111111111111', 1,
                    '33333333-3333-4333-8333-333333333333', 1, 1, 0, 100
                 );
                 INSERT INTO photokit_locator_records(
                    locator_id, enrollment_epoch, operation_id, record_kind,
                    stable_row_id, key_version, lookup_hmac, nonce,
                    ciphertext, finalized, created_at_ms
                 ) VALUES (
                    '55555555-5555-4555-8555-555555555555',
                    '11111111-1111-4111-8111-111111111111',
                    '33333333-3333-4333-8333-333333333333', 'asset',
                    '66666666-6666-4666-8666-666666666666', 1,
                    randomblob(32), randomblob(24), randomblob(17), 1, 60
                 );
                 INSERT INTO photokit_assets(
                    asset_id, enrollment_epoch, locator_id, created_at_ms
                 ) VALUES (
                    '66666666-6666-4666-8666-666666666666',
                    '11111111-1111-4111-8111-111111111111',
                    '55555555-5555-4555-8555-555555555555', 60
                 );
                 INSERT INTO blobs(sha256, byte_length, created_at_ms)
                 VALUES (
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    3, 60
                 );
                 INSERT INTO photokit_materializations(
                    materialization_id, asset_id, operation_id,
                    resource_fingerprint, blob_sha256, byte_length,
                    resource_uti, pixel_width, pixel_height,
                    selection_policy_revision, created_at_ms
                 ) VALUES (
                    '77777777-7777-4777-8777-777777777777',
                    '66666666-6666-4666-8666-666666666666',
                    '33333333-3333-4333-8333-333333333333',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    3, 'public.jpeg', 1, 1, 'original-primary-v1', 70
                 );
                 INSERT INTO photokit_availability_revisions(
                    revision_id, asset_id, enrollment_epoch, operation_id,
                    membership_generation, availability, reason,
                    materialization_id, created_at_ms
                 ) VALUES (
                    '88888888-8888-4888-8888-888888888888',
                    '66666666-6666-4666-8666-666666666666',
                    '11111111-1111-4111-8111-111111111111',
                    '33333333-3333-4333-8333-333333333333',
                    1, 'available', 'materialized',
                    '77777777-7777-4777-8777-777777777777', 80
                 );
                 INSERT INTO photokit_availability_heads(
                    asset_id, revision_id, updated_at_ms
                 ) VALUES (
                    '66666666-6666-4666-8666-666666666666',
                    '88888888-8888-4888-8888-888888888888', 80
                 );
                 INSERT INTO photokit_generation_members(
                    enrollment_epoch, membership_generation, ordinal,
                    asset_id, revision_id
                 ) VALUES (
                    '11111111-1111-4111-8111-111111111111', 1, 0,
                    '66666666-6666-4666-8666-666666666666',
                    '88888888-8888-4888-8888-888888888888'
                 );
                 UPDATE photokit_operations
                 SET state = 'complete', finished_at_ms = 100,
                     terminal_publication_json = json_object(
                        'operation_id',
                            '33333333-3333-4333-8333-333333333333',
                        'reconciliation_fence', 1,
                        'membership_generation', 1,
                        'transitions', 1,
                        'replayed', json('false'),
                        'snapshot', json_object(
                            'enrollment_epoch',
                                '11111111-1111-4111-8111-111111111111',
                            'membership_generation', 1
                        )
                     )
                 WHERE operation_id = '33333333-3333-4333-8333-333333333333';
                 INSERT INTO photokit_operations(
                    operation_id, request_id, enrollment_epoch,
                    store_authority_epoch, reconciliation_fence,
                    proposed_membership_generation, trigger_kind, state,
                    observed_count, accepted_bytes, started_at_ms
                 ) VALUES (
                    '99999999-9999-4999-8999-999999999999',
                    'abababab-abab-4bab-8bab-abababababab',
                    '11111111-1111-4111-8111-111111111111',
                    (SELECT epoch FROM store_authority_epoch WHERE singleton = 1),
                    2, 2, 'startup', 'enumerating', 1, 0, 110
                 );
                 INSERT INTO photokit_locator_records(
                    locator_id, enrollment_epoch, operation_id, record_kind,
                    stable_row_id, key_version, lookup_hmac, nonce,
                    ciphertext, finalized, created_at_ms
                 ) VALUES (
                    'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd',
                    '11111111-1111-4111-8111-111111111111',
                    '99999999-9999-4999-8999-999999999999', 'asset',
                    'dededede-dede-4ede-8ede-dededededede', 1,
                    randomblob(32), randomblob(24), randomblob(17), 0, 110
                 );
                 INSERT INTO photokit_operation_observations(
                    operation_id, ordinal, asset_id, locator_id,
                    resource_uti, resource_state
                 ) VALUES (
                    '99999999-9999-4999-8999-999999999999', 0,
                    'dededede-dede-4ede-8ede-dededededede',
                    'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd',
                    'public.jpeg', 'supported'
                 );
                 INSERT INTO photokit_key_cleanup_intents(
                    intent_id, deletion_run_id, enrollment_epoch,
                    key_reference, reason, state, created_at_ms
                 ) VALUES (
                    'efefefef-efef-4fef-8fef-efefefefefef', NULL,
                    'ffffffff-ffff-4fff-8fff-ffffffffffff',
                    'preserved-cleanup-key', 'final_key_owner', 'pending', 90
                 );
                 UPDATE revision_state SET photokit_revision = 1
                 WHERE singleton = 1;",
            )
            .unwrap();
        let original_epoch: String = connection
            .query_row(
                "SELECT epoch FROM store_authority_epoch WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();

        normalize_restored_state(&mut connection, 200).unwrap();

        let rotated_epoch: String = connection
            .query_row(
                "SELECT epoch FROM store_authority_epoch WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_ne!(rotated_epoch, original_epoch);
        assert_eq!(
            connection
                .query_row(
                    "SELECT store_authority_epoch FROM photokit_operations
                     WHERE operation_id =
                         '33333333-3333-4333-8333-333333333333'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            original_epoch
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT state FROM photokit_operations
                     WHERE operation_id =
                         '99999999-9999-4999-8999-999999999999'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "interrupted"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT
                       (SELECT COUNT(*) FROM photokit_operation_observations)
                       +(SELECT COUNT(*) FROM photokit_locator_records
                         WHERE finalized = 0)
                       +(SELECT COUNT(*) FROM photokit_enrollments
                         WHERE state = 'pending')",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT
                       (SELECT COUNT(*) FROM photokit_membership_generations)
                       +(SELECT COUNT(*) FROM photokit_materializations)
                       +(SELECT COUNT(*) FROM photokit_availability_revisions)",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            3
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM photokit_key_cleanup_intents",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT key_reference FROM photokit_enrollments
                     WHERE state = 'active'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "active-key"
        );
        verify_database(&connection).unwrap();
    }

    #[test]
    fn restored_pending_deletion_detaches_and_preserves_key_cleanup_intent() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        let connection = database.connection().unwrap();
        let epoch: String = connection
            .query_row(
                "SELECT epoch FROM store_authority_epoch WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let run_id = Uuid::new_v4().hyphenated().to_string();
        let intent_id = Uuid::new_v4().hyphenated().to_string();
        let enrollment_epoch = Uuid::new_v4().hyphenated().to_string();
        connection
            .execute(
                "INSERT INTO deletion_plans(
                    snapshot_token,epoch,target_kind,target_id,plan_sha256,
                    catalog_revision,evidence_generation,receipt_revision,photo_revision,
                    reconciliation_revision,outfit_revision,try_on_revision,
                    photokit_revision,prepared_at_ms,expires_at_ms,unique_blob_count,
                    unique_blob_bytes,retained_shared_blob_count
                 ) VALUES(
                    'restore-pending',?1,'item',?2,?3,0,0,0,0,0,0,0,0,1,2,0,0,0
                 )",
                params![epoch, Uuid::new_v4().to_string(), "1".repeat(64)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO deletion_runs(
                    run_id,epoch,snapshot_token,request_id,request_json,envelope_hash,
                    plan_sha256,state,accepted_at_ms,deadline_at_ms,photokit_revision
                 ) VALUES(
                    ?1,?2,'restore-pending',?3,'{}',?4,?5,'needs_attention',1,2,0
                 )",
                params![
                    run_id,
                    epoch,
                    Uuid::new_v4().to_string(),
                    "2".repeat(64),
                    "1".repeat(64)
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO photokit_key_cleanup_intents(
                    intent_id,deletion_run_id,enrollment_epoch,key_reference,
                    reason,state,created_at_ms
                 ) VALUES(?1,?2,?3,'restore-owned-key','final_key_owner','pending',1)",
                params![intent_id, run_id, enrollment_epoch],
            )
            .unwrap();

        sanitize_restored_deletion_authority(&connection).unwrap();

        assert_eq!(
            connection
                .query_row(
                    "SELECT deletion_run_id IS NULL
                     FROM photokit_key_cleanup_intents WHERE intent_id=?1",
                    [intent_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT
                       (SELECT COUNT(*) FROM deletion_runs)
                       +(SELECT COUNT(*) FROM deletion_plans)
                       +(SELECT COUNT(*) FROM domain_mutation_authority)",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        verify_database(&connection).unwrap();
    }

    #[test]
    fn migration_0013_preserves_v12_disconnect_rows_and_extends_one_outcome_domain() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v12_database(&paths, 10);
        let mut connection = open_connection(&paths.database).unwrap();
        let account_key = "a".repeat(64);
        connection
            .execute(
                "INSERT INTO gmail_accounts(account_key, credential_locator, created_at_ms)
                 VALUES (?1, 'migration-locator', 1)",
                [&account_key],
            )
            .unwrap();
        let outcomes = [
            (Uuid::new_v4().to_string(), None),
            (Uuid::new_v4().to_string(), Some("succeeded")),
            (Uuid::new_v4().to_string(), Some("already_invalid")),
            (Uuid::new_v4().to_string(), Some("failed")),
        ];
        for (request_id, outcome) in &outcomes {
            connection
                .execute(
                    "INSERT INTO gmail_operations(
                        request_id, command_name, request_envelope_sha256, stage,
                        response_json, created_at_ms, updated_at_ms
                     ) VALUES (?1, 'disconnect_gmail_v1', ?2, 'terminal', '{}', 1, 1)",
                    params![request_id, "b".repeat(64)],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO gmail_disconnect_stages(
                        request_id, account_key, credential_locator,
                        revocation_result, credential_deleted, updated_at_ms
                     ) VALUES (?1, ?2, 'migration-locator', ?3, 0, 1)",
                    params![request_id, account_key, outcome],
                )
                .unwrap();
        }

        apply_migration(&mut connection, &MIGRATIONS[12], 30).unwrap();

        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            13
        );
        verify_applied_migrations(&connection, 13).unwrap();
        let migrated = outcomes
            .iter()
            .map(|(request_id, _)| {
                connection
                    .query_row(
                        "SELECT revocation_result, credential_deleted, updated_at_ms
                         FROM gmail_disconnect_stages WHERE request_id = ?1",
                        [request_id],
                        |row| {
                            Ok((
                                row.get::<_, Option<String>>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, i64>(2)?,
                            ))
                        },
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            migrated,
            vec![
                (None, 0, 1),
                (Some("succeeded".into()), 0, 1),
                (Some("already_invalid".into()), 0, 1),
                (Some("failed".into()), 0, 1),
            ]
        );
        connection
            .execute(
                "UPDATE gmail_disconnect_stages
                 SET revocation_result = 'not_attempted_local_only'
                 WHERE request_id = ?1",
                [&outcomes[0].0],
            )
            .unwrap();
        assert!(connection
            .execute(
                "UPDATE gmail_disconnect_stages
                 SET revocation_result = 'unknown'
                 WHERE request_id = ?1",
                [&outcomes[0].0],
            )
            .is_err());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table' AND name = 'gmail_disconnect_stages_v12'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        verify_database(&connection).unwrap();
    }

    #[test]
    fn migration_0014_preserves_populated_v13_reconciliation_history_without_owner_fabrication() {
        use wardrobe_core::{
            AnalyzePhotoScopeV1Request, CatalogPort, CreatePhotoScopeV1Request,
            ImportLocalSourcesV1Request, ListImportedPhotoRootsV1Request,
            ListPhotoObservationsV1Request, PhotoAnalysisPort, PhotoObservationStateV1,
            PhotoReviewActionV1, ReviewPhotoObservationV1Request,
            UnavailableGarmentSegmentationProviderV1, SCHEMA_VERSION_V1,
        };

        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        assert_eq!(create_pre_target_database(&paths, 10), 13);
        let folder = temporary.path().join("photos");
        fs::create_dir(&folder).unwrap();
        let pixels = (0..8 * 6)
            .flat_map(|index| {
                let value = (index * 5) as u8;
                [value, 255_u8.saturating_sub(value), value / 2]
            })
            .collect::<Vec<_>>();
        image::save_buffer(
            folder.join("legacy-shirt.png"),
            &pixels,
            8,
            6,
            image::ColorType::Rgb8,
        )
        .unwrap();

        let database = Database {
            paths: paths.clone(),
        };
        database
            .import_local_sources(&ImportLocalSourcesV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                paths: vec![folder.to_string_lossy().into_owned()],
            })
            .unwrap();
        let root = database
            .list_imported_photo_roots(&ListImportedPhotoRootsV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                cursor: None,
                limit: 20,
            })
            .unwrap()
            .roots
            .remove(0);
        let scope = database
            .create_photo_scope(&CreatePhotoScopeV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                import_root_id: root.import_root_id,
                expected_manifest_generation: root.manifest_generation,
            })
            .unwrap()
            .scope;
        database
            .analyze_photo_scope(
                &AnalyzePhotoScopeV1Request {
                    schema_version: SCHEMA_VERSION_V1,
                    request_id: RequestId::new_v4(),
                    scope_id: scope.scope_id,
                },
                &UnavailableGarmentSegmentationProviderV1,
            )
            .unwrap();
        let observation = database
            .list_photo_observations(&ListPhotoObservationsV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                scope_id: scope.scope_id,
                state: PhotoObservationStateV1::NeedsReview,
                cursor: None,
                limit: 20,
            })
            .unwrap()
            .observations
            .remove(0);
        database
            .review_photo_observation(&ReviewPhotoObservationV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                observation_id: observation.observation_id,
                action: PhotoReviewActionV1::ConfirmCrop,
                replacement_rectangle: None,
                expected_photo_revision: 0,
            })
            .unwrap();

        let mut connection = open_connection(&paths.database).unwrap();
        let pin = connection
            .query_row(
                "SELECT observation.observation_id, observation.scope_id,
                        observation.source_revision_id,
                        source.source_revision_sha256,
                        head.current_artifact_id, artifact.artifact_sha256,
                        head.decision_id, head.photo_revision
                 FROM photo_observations observation
                 JOIN photo_source_revisions source
                   ON source.source_revision_id = observation.source_revision_id
                 JOIN photo_review_heads head
                   ON head.observation_id = observation.observation_id
                 JOIN photo_artifacts artifact
                   ON artifact.artifact_id = head.current_artifact_id",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .unwrap();
        let case_id = "51000000-0000-4000-8000-000000000001";
        let leading_id = "51000000-0000-4000-8000-000000000002";
        let no_match_id = "51000000-0000-4000-8000-000000000003";
        let item_id = "51000000-0000-4000-8000-000000000004";
        let evidence_id = "51000000-0000-4000-8000-000000000005";
        let decision_id = "51000000-0000-4000-8000-000000000006";
        let open_request_id = "51000000-0000-4000-8000-000000000007";
        let decision_request_id = "51000000-0000-4000-8000-000000000008";
        let envelope_hash = "a".repeat(64);
        let input_hash = "b".repeat(64);
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "INSERT INTO catalog_items(
                    item_id, display_name, attributes_json, active,
                    created_revision, updated_revision
                 ) VALUES (?1, 'Legacy shirt', '{}', 1, 1, 1)",
                [item_id],
            )
            .unwrap();
        for (request_id, command_name) in [
            (open_request_id, "open_reconciliation_case_v1"),
            (decision_request_id, "decide_reconciliation_case_v1"),
        ] {
            transaction
                .execute(
                    "INSERT INTO command_receipts(
                        request_id, command_name, envelope_hash,
                        response_json, created_at_ms
                     ) VALUES (?1, ?2, ?3, '{\"legacy\":true}', 30)",
                    params![request_id, command_name, envelope_hash],
                )
                .unwrap();
        }
        transaction
            .execute(
                "INSERT INTO reconciliation_cases(
                    case_id, observation_id, artifact_id, scope_id,
                    source_revision_id, source_revision_sha256,
                    artifact_sha256, photo_decision_id, photo_revision,
                    catalog_revision, receipt_revision, retrieval_revision,
                    observation_date, leading_candidate_id,
                    no_match_candidate_id, case_revision,
                    reconciliation_revision, created_at_ms
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                    1, 0, 'legacy-retrieval-v1', '2026-01-02',
                    ?10, ?11, 1, 1, 30
                 )",
                params![
                    case_id,
                    pin.0,
                    pin.4,
                    pin.1,
                    pin.2,
                    pin.3,
                    pin.5,
                    pin.6,
                    pin.7,
                    leading_id,
                    no_match_id
                ],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO reconciliation_candidates(
                    candidate_id, case_id, target_kind, target_item_id,
                    target_order_line_id, target_variant_evidence_id,
                    proposed_relation, rank, display_name, detail,
                    date_kind, date_value, reconciliation_revision,
                    created_at_ms
                 ) VALUES (
                    ?1, ?2, 'wardrobe_item', ?3, NULL, NULL,
                    'same_physical_item', 1, 'Legacy shirt',
                    'Legacy candidate', 'catalog_created', '2025-01-01',
                    1, 30
                 )",
                params![leading_id, case_id, item_id],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO reconciliation_candidates(
                    candidate_id, case_id, target_kind, target_item_id,
                    target_order_line_id, target_variant_evidence_id,
                    proposed_relation, rank, display_name, detail,
                    date_kind, date_value, reconciliation_revision,
                    created_at_ms
                 ) VALUES (
                    ?1, ?2, 'no_match', NULL, NULL, NULL, NULL, NULL,
                    'No match', 'Keep unresolved', NULL, NULL, 1, 30
                 )",
                params![no_match_id, case_id],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO reconciliation_candidate_evidence(
                    evidence_id, candidate_id, polarity, relation, feature,
                    source_kind, source_id, source_revision, extractor_id,
                    extractor_revision, value_code, measured_value,
                    reconciliation_revision, created_at_ms
                 ) VALUES (
                    ?1, ?2, 'supporting', 'visual_similarity',
                    'difference_hash_distance', 'photo_artifact', ?3,
                    'legacy-artifact-v1', 'legacy-extractor',
                    'legacy-extractor-v1', 'measured', 4, 1, 30
                 )",
                params![evidence_id, leading_id, pin.4],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO reconciliation_evidence_input_hashes(
                    evidence_id, input_ordinal, input_sha256,
                    reconciliation_revision
                 ) VALUES (?1, 0, ?2, 1)",
                params![evidence_id, input_hash],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO reconciliation_decisions(
                    decision_id, case_id, request_id, outcome,
                    selected_candidate_id, expected_case_revision,
                    case_revision, reconciliation_revision, created_at_ms
                 ) VALUES (?1, ?2, ?3, 'no_match', ?4, 1, 2, 2, 31)",
                params![decision_id, case_id, decision_request_id, no_match_id],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO reconciliation_decision_heads(
                    case_id, decision_id, case_revision,
                    reconciliation_revision, updated_at_ms
                 ) VALUES (?1, ?2, 2, 2, 31)",
                params![case_id, decision_id],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO reconciliation_command_entities(
                    request_id, entity_kind, entity_id,
                    reconciliation_revision
                 ) VALUES (?1, 'case', ?2, 1)",
                params![open_request_id, case_id],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO reconciliation_command_entities(
                    request_id, entity_kind, entity_id,
                    reconciliation_revision
                 ) VALUES (?1, 'decision', ?2, 2)",
                params![decision_request_id, decision_id],
            )
            .unwrap();
        transaction
            .execute(
                "UPDATE revision_state
                 SET catalog_revision = 1, reconciliation_revision = 2
                 WHERE singleton = 1",
                [],
            )
            .unwrap();
        transaction.commit().unwrap();

        apply_migration(&mut connection, &MIGRATIONS[13], 40).unwrap();
        verify_applied_migrations(&connection, 14).unwrap();
        verify_database(&connection).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT
                        owner_decision_id IS NULL,
                        person_instance_id IS NULL,
                        owner_revision IS NULL,
                        owner_evidence_sha256 IS NULL,
                        source_revision_sha256,
                        artifact_sha256,
                        photo_decision_id,
                        photo_revision,
                        reconciliation_revision
                     FROM reconciliation_cases WHERE case_id = ?1",
                    [case_id],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, i64>(7)?,
                            row.get::<_, i64>(8)?,
                        ))
                    },
                )
                .unwrap(),
            (1, 1, 1, 1, pin.3, pin.5, pin.6, pin.7, 1)
        );
        for (table, id_column, id) in [
            ("reconciliation_candidates", "candidate_id", leading_id),
            (
                "reconciliation_candidate_evidence",
                "evidence_id",
                evidence_id,
            ),
            ("reconciliation_decisions", "decision_id", decision_id),
            ("reconciliation_decision_heads", "decision_id", decision_id),
            ("command_receipts", "request_id", decision_request_id),
        ] {
            let sql = format!("SELECT COUNT(*) FROM {table} WHERE {id_column} = ?1");
            assert_eq!(
                connection
                    .query_row(&sql, [id], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT input_sha256
                     FROM reconciliation_evidence_input_hashes
                     WHERE evidence_id = ?1",
                    [evidence_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            input_hash
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM reconciliation_command_entities
                     WHERE request_id IN (?1, ?2)",
                    params![open_request_id, decision_request_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            2
        );
    }

    #[test]
    fn interrupted_migration_0014_restores_v13_and_reenables_foreign_keys() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        assert_eq!(create_pre_target_database(&paths, 10), 13);
        let mut connection = open_connection(&paths.database).unwrap();
        const BAD_V14: Migration = Migration {
            version: 14,
            sql: "ALTER TABLE photo_observations
                  RENAME TO p04_photo_observations_legacy;
                  CREATE TABLE photo_observations(partial INTEGER) STRICT;
                  INVALID SQL;",
            sha256: "",
        };

        assert!(apply_migration(&mut connection, &BAD_V14, 30).is_err());
        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            13
        );
        verify_applied_migrations(&connection, 13).unwrap();
        assert_eq!(
            connection
                .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('photo_observations')
                     WHERE name = 'observation_id'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table'
                       AND name = 'p04_photo_observations_legacy'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        verify_database(&connection).unwrap();
    }

    #[test]
    fn interrupted_migration_0013_rolls_back_to_complete_v12() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        create_v12_database(&paths, 10);
        let mut connection = open_connection(&paths.database).unwrap();
        const BAD_V13: Migration = Migration {
            version: 13,
            sql: "ALTER TABLE gmail_disconnect_stages
                  RENAME TO gmail_disconnect_stages_v12;
                  CREATE TABLE gmail_disconnect_stages(partial INTEGER) STRICT;
                  INVALID SQL;",
            sha256: "",
        };

        assert!(apply_migration(&mut connection, &BAD_V13, 30).is_err());

        assert_eq!(
            connection
                .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
                .unwrap(),
            12
        );
        verify_applied_migrations(&connection, 12).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('gmail_disconnect_stages')
                     WHERE name = 'revocation_result'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_schema
                     WHERE type = 'table' AND name = 'gmail_disconnect_stages_v12'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        verify_database(&connection).unwrap();
    }

    #[test]
    fn restore_normalization_detaches_pending_gmail_disconnect_recovery() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        let mut connection = database.connection().unwrap();
        let account_key = "c".repeat(64);
        let scope_id = Uuid::new_v4().to_string();
        let request_id = Uuid::new_v4().to_string();
        connection
            .execute(
                "INSERT INTO gmail_accounts(account_key, credential_locator, created_at_ms)
                 VALUES (?1, 'restored-disconnect-locator', 1)",
                [&account_key],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO credential_references(
                    locator, credential_id, save_request_id, provider, display_label,
                    status, created_at_ms, updated_at_ms
                 ) VALUES (
                    'restored-disconnect-locator', ?1, ?2, 'gmail', 'Gmail',
                    'active', 1, 1
                 )",
                params![Uuid::new_v4().to_string(), Uuid::new_v4().to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO gmail_scopes(
                    scope_id, account_key, scope_fingerprint, label_id, oauth_scope,
                    parser_revision, materialization_revision, created_at_ms
                 ) VALUES (?1, ?2, ?3, 'Label_1', ?4, 'parser', 'materializer', 1)",
                params![
                    scope_id,
                    account_key,
                    "d".repeat(64),
                    crate::GOOGLE_OAUTH_SCOPE
                ],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE gmail_connector_state
                 SET status = 'disconnecting', account_key = ?1, scope_id = ?2,
                     revocation_state = 'pending', updated_at_ms = 1
                 WHERE singleton = 1",
                params![account_key, scope_id],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO gmail_operations(
                    request_id, command_name, request_envelope_sha256, stage,
                    created_at_ms, updated_at_ms
                 ) VALUES (?1, 'disconnect_gmail_v1', ?2, 'revocation_pending', 1, 1)",
                params![request_id, "e".repeat(64)],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO gmail_disconnect_stages(
                    request_id, account_key, credential_locator, updated_at_ms
                 ) VALUES (?1, ?2, 'restored-disconnect-locator', 1)",
                params![request_id, account_key],
            )
            .unwrap();

        normalize_restored_state(&mut connection, 20).unwrap();

        assert_eq!(
            connection
                .query_row(
                    "SELECT stage, response_json FROM gmail_operations
                     WHERE request_id = ?1",
                    [&request_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            (
                "terminal".into(),
                "{\"interrupted\":true,\"reason\":\"restore_interrupted\"}".into()
            )
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT revocation_result FROM gmail_disconnect_stages
                     WHERE request_id = ?1",
                    [&request_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .unwrap(),
            None
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT credential_locator FROM gmail_accounts
                     WHERE account_key = ?1",
                    [&account_key],
                    |row| row.get::<_, Option<String>>(0),
                )
                .unwrap(),
            None
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM credential_references
                     WHERE locator = 'restored-disconnect-locator'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        verify_database(&connection).unwrap();
    }
}
