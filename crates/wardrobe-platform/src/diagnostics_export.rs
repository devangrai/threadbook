use crate::backup_repository::{format_timestamp, BackupRepository};
use crate::database::{database_schema_version, migration_prefix_sha256};
use crate::diagnostics::JsonlDiagnostics;
use crate::{PlatformError, PlatformResult, PrivateAppPaths};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{c_void, CString, OsStr};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use uuid::Uuid;
use wardrobe_core::{
    DeletionHealthCountsV1, DeletionHealthStatusV1, DeletionHealthV1, DiagnosticsCounterNameV1,
    DiagnosticsCounterV1, DiagnosticsExportV1, DiagnosticsHealthStateV1, DiagnosticsHealthV1,
    DiagnosticsJobFailureV1, DiagnosticsLogSummaryV1, DiagnosticsVersionsV1, ErrorCodeV1,
    ExportDiagnosticsV1Request, ExportDiagnosticsV1Response, JobKindV1, Sha256Digest,
    TryOnFailureCodeV1, TryOnFailureV1, TryOnUserActionV1, UserActionKeyV1, Validate,
    DIAGNOSTICS_EXPORT_MEDIA_TYPE_V1, MAX_DIAGNOSTICS_EXPORT_BYTES_V1, MAX_SAFE_INTEGER_V1,
    SCHEMA_VERSION_V1,
};

pub struct DiagnosticsExporter<'a> {
    private_paths: &'a PrivateAppPaths,
    diagnostics: &'a JsonlDiagnostics,
}

impl<'a> DiagnosticsExporter<'a> {
    pub fn new(private_paths: &'a PrivateAppPaths, diagnostics: &'a JsonlDiagnostics) -> Self {
        Self {
            private_paths,
            diagnostics,
        }
    }

    pub fn export(
        &self,
        request: &ExportDiagnosticsV1Request,
        now_ms: i64,
    ) -> PlatformResult<ExportDiagnosticsV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("diagnostics_request"))?;
        let generated_at = format_timestamp(now_ms)?;
        let diagnostic_log = self.diagnostics.snapshot()?;
        let report = self.project_report(&generated_at, diagnostic_log, now_ms)?;
        report
            .validate()
            .map_err(|_| PlatformError::Corrupt("diagnostics_report"))?;

        let mut bytes = serde_json::to_vec(&report)?;
        bytes.push(b'\n');
        if bytes.is_empty() || bytes.len() as u64 > MAX_DIAGNOSTICS_EXPORT_BYTES_V1 {
            return Err(PlatformError::Corrupt("diagnostics_report_size"));
        }
        let sha256 = Sha256Digest::from_bytes(&bytes);
        publish_report(
            Path::new(&request.destination_path),
            &bytes,
            self.private_paths,
            self.diagnostics.path(),
        )?;
        let response = ExportDiagnosticsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            generated_at,
            complete: true,
            media_type: DIAGNOSTICS_EXPORT_MEDIA_TYPE_V1.to_owned(),
            byte_length: bytes.len() as u64,
            sha256,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("diagnostics_response"))?;
        Ok(response)
    }

    fn project_report(
        &self,
        generated_at: &str,
        diagnostic_log: DiagnosticsLogSummaryV1,
        now_ms: i64,
    ) -> PlatformResult<DiagnosticsExportV1> {
        let verified_backups =
            BackupRepository::new(self.private_paths).count_verified_readonly()?;
        let mut connection = Connection::open_with_flags(
            &self.private_paths.database,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA query_only = ON;
             PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;",
        )?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let schema_version = database_schema_version(&transaction)?;
        verify_database_health(&transaction)?;
        let storage_check = storage_health(&transaction)?;
        let deletion = deletion_health(&transaction, now_ms)?;
        let counters = approved_contract::counters(&transaction, verified_backups)?;
        let job_failures = approved_contract::job_failures(&transaction)?;
        let migration_prefix_sha256 = Sha256Digest::parse(migration_prefix_sha256(schema_version)?)
            .map_err(|_| PlatformError::Corrupt("migration_prefix_sha256"))?;
        transaction.commit()?;

        Ok(DiagnosticsExportV1 {
            schema_version: SCHEMA_VERSION_V1,
            generated_at: generated_at.to_owned(),
            versions: DiagnosticsVersionsV1 {
                export_schema_version: SCHEMA_VERSION_V1,
                application_version: env!("CARGO_PKG_VERSION").to_owned(),
                database_schema_version: schema_version,
                migration_prefix_sha256,
                diagnostic_event_schema_version: SCHEMA_VERSION_V1,
            },
            health: DiagnosticsHealthV1 {
                database_integrity: DiagnosticsHealthStateV1::Ready,
                foreign_keys: DiagnosticsHealthStateV1::Ready,
                storage_check,
                deletion,
                diagnostic_log,
            },
            counters,
            job_failures,
        })
    }
}

fn verify_database_health(transaction: &Transaction<'_>) -> PlatformResult<()> {
    let quick_check: String =
        transaction.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(PlatformError::Corrupt("database_integrity"));
    }
    if transaction
        .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
        .optional()?
        .is_some()
    {
        return Err(PlatformError::Corrupt("database_foreign_key"));
    }
    Ok(())
}

fn storage_health(transaction: &Transaction<'_>) -> PlatformResult<DiagnosticsHealthStateV1> {
    let latest = transaction
        .query_row(
            "SELECT job.state
             FROM storage_checks storage
             JOIN jobs job
               ON job.idempotency_key = 'storage-check:' || storage.request_id
             ORDER BY storage.created_at_ms DESC, storage.check_id DESC
             LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    match latest.as_deref() {
        None => Ok(DiagnosticsHealthStateV1::NeverRun),
        Some("queued" | "running" | "succeeded") => Ok(DiagnosticsHealthStateV1::Ready),
        Some("failed") => Ok(DiagnosticsHealthStateV1::NeedsAttention),
        Some(_) => Err(PlatformError::Corrupt("storage_check_state")),
    }
}

fn deletion_health(transaction: &Transaction<'_>, now_ms: i64) -> PlatformResult<DeletionHealthV1> {
    let (in_progress, overdue, needs_attention, deadline): (i64, i64, i64, Option<i64>) =
        transaction.query_row(
            "SELECT
                SUM(CASE WHEN state='in_progress' AND deadline_at_ms>=?1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN state='in_progress' AND deadline_at_ms<?1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN state='needs_attention' THEN 1 ELSE 0 END),
                MIN(CASE WHEN state<>'complete' THEN deadline_at_ms END)
             FROM deletion_runs",
            [now_ms],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    row.get(3)?,
                ))
            },
        )?;
    let status = if needs_attention > 0 {
        DeletionHealthStatusV1::NeedsAttention
    } else if overdue > 0 {
        DeletionHealthStatusV1::Overdue
    } else if in_progress > 0 {
        DeletionHealthStatusV1::InProgress
    } else {
        DeletionHealthStatusV1::None
    };
    let health = DeletionHealthV1 {
        status,
        deadline_at: deadline.map(format_timestamp).transpose()?,
        counts: DeletionHealthCountsV1 {
            in_progress: u32::try_from(in_progress)
                .map_err(|_| PlatformError::Corrupt("deletion_health_count"))?,
            overdue: u32::try_from(overdue)
                .map_err(|_| PlatformError::Corrupt("deletion_health_count"))?,
            needs_attention: u32::try_from(needs_attention)
                .map_err(|_| PlatformError::Corrupt("deletion_health_count"))?,
        },
    };
    health
        .validate()
        .map_err(|_| PlatformError::Corrupt("deletion_health"))?;
    Ok(health)
}

mod approved_contract {
    use super::*;

    pub(super) fn counters(
        transaction: &Transaction<'_>,
        verified_backups: u64,
    ) -> PlatformResult<Vec<DiagnosticsCounterV1>> {
        DiagnosticsCounterNameV1::ALL
            .iter()
            .copied()
            .map(|name| {
                let value = if name == DiagnosticsCounterNameV1::VerifiedBackups {
                    verified_backups
                } else {
                    count_query(transaction, counter_sql(name)?)?
                };
                if value >= MAX_SAFE_INTEGER_V1 {
                    return Err(PlatformError::Corrupt("diagnostics_counter"));
                }
                Ok(DiagnosticsCounterV1 { name, value })
            })
            .collect()
    }

    fn count_query(transaction: &Transaction<'_>, sql: &str) -> PlatformResult<u64> {
        let value = transaction.query_row(sql, [], |row| row.get::<_, i64>(0))?;
        u64::try_from(value).map_err(|_| PlatformError::Corrupt("diagnostics_counter"))
    }

    fn counter_sql(name: DiagnosticsCounterNameV1) -> PlatformResult<&'static str> {
        let sql = match name {
            DiagnosticsCounterNameV1::CatalogItems => "SELECT COUNT(*) FROM catalog_items",
            DiagnosticsCounterNameV1::LocalSources => "SELECT COUNT(*) FROM local_sources",
            DiagnosticsCounterNameV1::LocalSourcesImported => {
                "SELECT COUNT(*) FROM local_sources WHERE status='imported'"
            }
            DiagnosticsCounterNameV1::LocalSourcesQuarantined => {
                "SELECT COUNT(*) FROM local_sources WHERE status='quarantined'"
            }
            DiagnosticsCounterNameV1::LocalSourcesMissing => {
                "SELECT COUNT(*) FROM local_sources WHERE status='missing'"
            }
            DiagnosticsCounterNameV1::LocalSourcesUnavailable => {
                "SELECT COUNT(*) FROM local_sources WHERE status='unavailable'"
            }
            DiagnosticsCounterNameV1::Evidence => "SELECT COUNT(*) FROM evidence",
            DiagnosticsCounterNameV1::EvidenceUnresolved => {
                "SELECT COUNT(*) FROM evidence WHERE state='unresolved'"
            }
            DiagnosticsCounterNameV1::EvidenceDeferred => {
                "SELECT COUNT(*) FROM evidence WHERE state='deferred'"
            }
            DiagnosticsCounterNameV1::EvidenceAssigned => {
                "SELECT COUNT(*) FROM evidence WHERE state='assigned'"
            }
            DiagnosticsCounterNameV1::EvidenceRejected => {
                "SELECT COUNT(*) FROM evidence WHERE state='rejected'"
            }
            DiagnosticsCounterNameV1::ReceiptOrders => "SELECT COUNT(*) FROM receipt_orders",
            DiagnosticsCounterNameV1::ReceiptReviewsConfirmed => {
                "SELECT COUNT(*) FROM receipt_review_heads head
             JOIN receipt_review_decisions decision
               ON decision.review_decision_id=head.review_decision_id
             WHERE decision.action='confirm'"
            }
            DiagnosticsCounterNameV1::ReceiptReviewsCorrected => {
                "SELECT COUNT(*) FROM receipt_review_heads head
             JOIN receipt_review_decisions decision
               ON decision.review_decision_id=head.review_decision_id
             WHERE decision.action='correct'"
            }
            DiagnosticsCounterNameV1::ReceiptReviewsDeferred => {
                "SELECT COUNT(*) FROM receipt_review_heads head
             JOIN receipt_review_decisions decision
               ON decision.review_decision_id=head.review_decision_id
             WHERE decision.action='defer'"
            }
            DiagnosticsCounterNameV1::ReceiptReviewsRejected => {
                "SELECT COUNT(*) FROM receipt_review_heads head
             JOIN receipt_review_decisions decision
               ON decision.review_decision_id=head.review_decision_id
             WHERE decision.action='reject'"
            }
            DiagnosticsCounterNameV1::PhotoObservations => {
                "SELECT COUNT(*) FROM photo_observations"
            }
            DiagnosticsCounterNameV1::PhotoObservationsNeedsReview => {
                "SELECT COUNT(*) FROM photo_observations observation
             LEFT JOIN photo_review_heads head
               ON head.observation_id=observation.observation_id
             WHERE head.observation_id IS NULL"
            }
            DiagnosticsCounterNameV1::PhotoObservationsConfirmed => {
                "SELECT COUNT(*) FROM photo_review_heads WHERE state='confirmed'"
            }
            DiagnosticsCounterNameV1::PhotoObservationsReplaced => {
                "SELECT COUNT(*) FROM photo_review_heads WHERE state='replaced'"
            }
            DiagnosticsCounterNameV1::PhotoObservationsDeferred => {
                "SELECT COUNT(*) FROM photo_review_heads WHERE state='deferred'"
            }
            DiagnosticsCounterNameV1::PhotoObservationsRejected => {
                "SELECT COUNT(*) FROM photo_review_heads WHERE state='rejected'"
            }
            DiagnosticsCounterNameV1::Outfits => "SELECT COUNT(*) FROM outfits",
            DiagnosticsCounterNameV1::TryOnJobs => "SELECT COUNT(*) FROM try_on_jobs",
            DiagnosticsCounterNameV1::TryOnJobsQueued => {
                "SELECT COUNT(*) FROM try_on_jobs WHERE state='queued'"
            }
            DiagnosticsCounterNameV1::TryOnJobsRunning => {
                "SELECT COUNT(*) FROM try_on_jobs WHERE state='running'"
            }
            DiagnosticsCounterNameV1::TryOnJobsSucceeded => {
                "SELECT COUNT(*) FROM try_on_jobs WHERE state='succeeded'"
            }
            DiagnosticsCounterNameV1::TryOnJobsFailed => {
                "SELECT COUNT(*) FROM try_on_jobs WHERE state='failed'"
            }
            DiagnosticsCounterNameV1::VerifiedBackups => {
                return Err(PlatformError::Corrupt("backup_counter_query"))
            }
            DiagnosticsCounterNameV1::FoundationJobs => "SELECT COUNT(*) FROM jobs",
            DiagnosticsCounterNameV1::FoundationJobsPending => {
                "SELECT COUNT(*) FROM jobs WHERE state='queued' AND attempt=0"
            }
            DiagnosticsCounterNameV1::FoundationJobsRunning => {
                "SELECT COUNT(*) FROM jobs WHERE state='running'"
            }
            DiagnosticsCounterNameV1::FoundationJobsRetryWaiting => {
                "SELECT COUNT(*) FROM jobs WHERE state='queued' AND attempt>0"
            }
            DiagnosticsCounterNameV1::FoundationJobsSucceeded => {
                "SELECT COUNT(*) FROM jobs WHERE state='succeeded'"
            }
            DiagnosticsCounterNameV1::FoundationJobsFailed => {
                "SELECT COUNT(*) FROM jobs WHERE state='failed'"
            }
            DiagnosticsCounterNameV1::DeletionRuns => "SELECT COUNT(*) FROM deletion_runs",
            DiagnosticsCounterNameV1::DeletionRunsInProgress => {
                "SELECT COUNT(*) FROM deletion_runs WHERE state='in_progress'"
            }
            DiagnosticsCounterNameV1::DeletionRunsNeedsAttention => {
                "SELECT COUNT(*) FROM deletion_runs WHERE state='needs_attention'"
            }
            DiagnosticsCounterNameV1::DeletionRunsComplete => {
                "SELECT COUNT(*) FROM deletion_runs WHERE state='complete'"
            }
        };
        Ok(sql)
    }

    pub(super) fn job_failures(
        transaction: &Transaction<'_>,
    ) -> PlatformResult<Vec<DiagnosticsJobFailureV1>> {
        let mut failures = foundation_failures(transaction)?;
        failures.extend(try_on_failures(transaction)?);
        if failures.len() > wardrobe_core::MAX_DIAGNOSTICS_FAILURE_GROUPS_V1 {
            return Err(PlatformError::Corrupt("diagnostics_failure_groups"));
        }
        failures.sort_by_key(|failure| serde_json::to_string(failure).unwrap_or_default());
        Ok(failures)
    }

    fn foundation_failures(
        transaction: &Transaction<'_>,
    ) -> PlatformResult<Vec<DiagnosticsJobFailureV1>> {
        let mut statement = transaction.prepare(
            "SELECT job.kind, failure.failure_code, failure.user_action_key,
                job.attempt, COUNT(*)
         FROM jobs job
         JOIN job_failures failure ON failure.job_id=job.job_id
         WHERE job.state='failed'
         GROUP BY job.kind, failure.failure_code, failure.user_action_key, job.attempt
         ORDER BY job.kind, failure.failure_code, failure.user_action_key, job.attempt",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .map(|row| {
                let (kind, code, user_action, attempt_count, occurrence_count) = row?;
                Ok(DiagnosticsJobFailureV1::Foundation {
                    kind: parse_foundation_kind(&kind)?,
                    code: parse_foundation_code(&code)?,
                    user_action: parse_foundation_action(&user_action)?,
                    attempt_count: safe_count(attempt_count)?,
                    occurrence_count: positive_safe_count(occurrence_count)?,
                })
            })
            .collect();
        rows
    }

    fn try_on_failures(
        transaction: &Transaction<'_>,
    ) -> PlatformResult<Vec<DiagnosticsJobFailureV1>> {
        let mut statement = transaction.prepare(
            "SELECT failure_code, retryable, user_action, attempt_count, COUNT(*)
         FROM try_on_jobs
         WHERE state='failed'
         GROUP BY failure_code, retryable, user_action, attempt_count
         ORDER BY failure_code, retryable, user_action, attempt_count",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .map(|row| {
                let (code, retryable, user_action, attempt_count, occurrence_count) = row?;
                let failure = TryOnFailureV1 {
                    code: parse_try_on_code(&code)?,
                    retryable: parse_bool(retryable)?,
                    user_action: parse_try_on_action(&user_action)?,
                };
                failure
                    .validate()
                    .map_err(|_| PlatformError::Corrupt("try_on_failure_contract"))?;
                Ok(DiagnosticsJobFailureV1::TryOn {
                    code: failure.code,
                    retryable: failure.retryable,
                    user_action: failure.user_action,
                    attempt_count: safe_count(attempt_count)?,
                    occurrence_count: positive_safe_count(occurrence_count)?,
                })
            })
            .collect();
        rows
    }

    fn parse_foundation_kind(value: &str) -> PlatformResult<JobKindV1> {
        match value {
            "verify_blob_v1" => Ok(JobKindV1::VerifyBlobV1),
            _ => Err(PlatformError::Corrupt("diagnostics_job_kind")),
        }
    }

    fn parse_foundation_code(value: &str) -> PlatformResult<ErrorCodeV1> {
        match value {
            "blob_missing" => Ok(ErrorCodeV1::NotFound),
            "blob_integrity_failed" => Ok(ErrorCodeV1::DataIntegrity),
            "blob_unavailable" => Ok(ErrorCodeV1::StorageUnavailable),
            _ => Err(PlatformError::Corrupt("diagnostics_failure_code")),
        }
    }

    fn parse_foundation_action(value: &str) -> PlatformResult<UserActionKeyV1> {
        match value {
            "rerun_storage_check" => Ok(UserActionKeyV1::ReviewStorage),
            "retry_when_storage_available" => Ok(UserActionKeyV1::Retry),
            "restart_application" => Ok(UserActionKeyV1::RestartApplication),
            _ => Err(PlatformError::Corrupt("diagnostics_user_action")),
        }
    }

    fn parse_try_on_code(value: &str) -> PlatformResult<TryOnFailureCodeV1> {
        match value {
            "moderation_blocked" => Ok(TryOnFailureCodeV1::ModerationBlocked),
            "rate_limited" => Ok(TryOnFailureCodeV1::RateLimited),
            "provider_failure" => Ok(TryOnFailureCodeV1::ProviderFailure),
            "provider_unavailable" => Ok(TryOnFailureCodeV1::ProviderUnavailable),
            "outcome_unknown" => Ok(TryOnFailureCodeV1::OutcomeUnknown),
            "authentication" => Ok(TryOnFailureCodeV1::Authentication),
            "permission_denied" => Ok(TryOnFailureCodeV1::PermissionDenied),
            "request_rejected" => Ok(TryOnFailureCodeV1::RequestRejected),
            "provider_protocol" => Ok(TryOnFailureCodeV1::ProviderProtocol),
            "credential_unavailable" => Ok(TryOnFailureCodeV1::CredentialUnavailable),
            "approval_expired" => Ok(TryOnFailureCodeV1::ApprovalExpired),
            "approval_consumed" => Ok(TryOnFailureCodeV1::ApprovalConsumed),
            "source_stale" => Ok(TryOnFailureCodeV1::SnapshotStale),
            "asset_unavailable" => Ok(TryOnFailureCodeV1::AssetUnavailable),
            "asset_integrity" => Ok(TryOnFailureCodeV1::AssetIntegrity),
            "output_materialization_interrupted" => {
                Ok(TryOnFailureCodeV1::OutputMaterializationInterrupted)
            }
            "cancelled" => Ok(TryOnFailureCodeV1::Cancelled),
            _ => Err(PlatformError::Corrupt("diagnostics_try_on_code")),
        }
    }

    fn parse_try_on_action(value: &str) -> PlatformResult<TryOnUserActionV1> {
        match value {
            "none" => Ok(TryOnUserActionV1::None),
            "start_new_preview" => Ok(TryOnUserActionV1::StartNewPreview),
            "retry_when_available" => Ok(TryOnUserActionV1::RetryWhenAvailable),
            "check_open_ai_credential" => Ok(TryOnUserActionV1::CheckOpenAiCredential),
            "review_source_assets" => Ok(TryOnUserActionV1::ReviewSourceAssets),
            "review_provider_status" => Ok(TryOnUserActionV1::ReviewProviderStatus),
            _ => Err(PlatformError::Corrupt("diagnostics_try_on_action")),
        }
    }

    fn parse_bool(value: i64) -> PlatformResult<bool> {
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(PlatformError::Corrupt("diagnostics_boolean")),
        }
    }

    fn safe_count(value: i64) -> PlatformResult<u64> {
        let value =
            u64::try_from(value).map_err(|_| PlatformError::Corrupt("diagnostics_count"))?;
        if value >= MAX_SAFE_INTEGER_V1 {
            Err(PlatformError::Corrupt("diagnostics_count"))
        } else {
            Ok(value)
        }
    }

    fn positive_safe_count(value: i64) -> PlatformResult<u64> {
        let value = safe_count(value)?;
        if value == 0 {
            Err(PlatformError::Corrupt("diagnostics_count"))
        } else {
            Ok(value)
        }
    }
}

fn publish_report(
    destination: &Path,
    bytes: &[u8],
    private_paths: &PrivateAppPaths,
    diagnostics_path: &Path,
) -> PlatformResult<()> {
    if !destination.is_absolute() {
        return Err(PlatformError::InvalidInput("diagnostics_destination"));
    }
    let parent_path = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(PlatformError::InvalidInput("diagnostics_destination"))?;
    let leaf = destination
        .file_name()
        .ok_or(PlatformError::InvalidInput("diagnostics_destination"))?;
    validate_destination_leaf(leaf)?;

    let parent = open_directory(parent_path)?;
    validate_destination_parent(&parent)?;
    reject_managed_destination(&parent, private_paths, diagnostics_path)?;
    let leaf = c_string(leaf)?;
    match stat_at(parent.as_raw_fd(), &leaf) {
        Ok(_) => return Err(PlatformError::Conflict("diagnostics_destination_exists")),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {}
        Err(error) => return Err(error.into()),
    }

    let (temporary_name, mut temporary) = open_unique_temporary(parent.as_raw_fd())?;
    let identity = file_identity(&temporary)?;
    let before_publication = (|| -> PlatformResult<()> {
        temporary.write_all(bytes)?;
        temporary.sync_all()?;
        verify_open_file(&mut temporary, bytes, identity)?;
        let named = stat_at(parent.as_raw_fd(), &temporary_name)?;
        if stat_identity(&named) != identity
            || named.st_nlink != 1
            || (named.st_mode & libc::S_IFMT) != libc::S_IFREG
            || named.st_mode & 0o777 != 0o600
        {
            return Err(PlatformError::Corrupt("diagnostics_temporary_identity"));
        }
        rename_no_replace(
            parent.as_raw_fd(),
            &temporary_name,
            parent.as_raw_fd(),
            &leaf,
        )
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::EEXIST) {
                PlatformError::Conflict("diagnostics_destination_exists")
            } else {
                PlatformError::Io(error)
            }
        })
    })();
    if let Err(error) = before_publication {
        unlink_if_owned(parent.as_raw_fd(), &temporary_name, identity);
        return Err(error);
    }

    let mut published = open_file_at(parent.as_raw_fd(), &leaf)?;
    verify_open_file(&mut published, bytes, identity)?;
    let named = stat_at(parent.as_raw_fd(), &leaf)?;
    if stat_identity(&named) != identity
        || named.st_nlink != 1
        || (named.st_mode & libc::S_IFMT) != libc::S_IFREG
        || named.st_mode & 0o777 != 0o600
        || named.st_size < 0
        || named.st_size as usize != bytes.len()
    {
        return Err(PlatformError::Corrupt("diagnostics_final_identity"));
    }
    parent.sync_all()?;
    Ok(())
}

fn validate_destination_leaf(leaf: &OsStr) -> PlatformResult<()> {
    let bytes = leaf.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes == b"."
        || bytes == b".."
        || Path::new(leaf).extension() != Some(OsStr::new("json"))
        || bytes.contains(&0)
    {
        return Err(PlatformError::InvalidInput("diagnostics_destination"));
    }
    Ok(())
}

fn open_directory(path: &Path) -> PlatformResult<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(Into::into)
}

fn validate_destination_parent(parent: &File) -> PlatformResult<()> {
    let metadata = parent.metadata()?;
    if !private_destination_parent(
        metadata.file_type().is_dir(),
        metadata.uid(),
        metadata.mode(),
        unsafe { libc::geteuid() },
    ) {
        return Err(PlatformError::InvalidInput(
            "diagnostics_destination_parent",
        ));
    }
    reject_extended_acl(parent.as_raw_fd())
}

fn private_destination_parent(is_directory: bool, owner: u32, mode: u32, euid: u32) -> bool {
    is_directory && owner == euid && mode & 0o022 == 0
}

#[cfg(target_os = "macos")]
fn reject_extended_acl(descriptor: RawFd) -> PlatformResult<()> {
    type Acl = *mut c_void;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut Acl) -> libc::c_int;
        fn acl_free(object: *mut c_void) -> libc::c_int;
    }
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;

    let acl = unsafe { acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(error.into());
    }
    let mut entry: Acl = std::ptr::null_mut();
    let status = unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut entry) };
    let free_status = unsafe { acl_free(acl) };
    if status < 0 || free_status != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if status == 1 {
        return Err(PlatformError::InvalidInput(
            "diagnostics_destination_parent_acl",
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn reject_extended_acl(_descriptor: RawFd) -> PlatformResult<()> {
    Err(PlatformError::Unsupported(
        "diagnostics_destination_parent_acl",
    ))
}

fn reject_managed_destination(
    selected_parent: &File,
    paths: &PrivateAppPaths,
    diagnostics_path: &Path,
) -> PlatformResult<()> {
    let diagnostic_parent = diagnostics_path
        .parent()
        .ok_or(PlatformError::Corrupt("diagnostic_log_parent"))?;
    let managed_paths = [
        paths.root.as_path(),
        paths.blobs.as_path(),
        paths.backups.as_path(),
        paths.backup_staging.as_path(),
        paths.restore.as_path(),
        paths.deletion_trash.as_path(),
        diagnostic_parent,
    ];
    let mut managed = BTreeSet::new();
    for path in managed_paths {
        managed.insert(file_identity(&open_directory(path)?)?);
    }

    let mut current = selected_parent.try_clone()?;
    loop {
        let identity = file_identity(&current)?;
        if managed.contains(&identity) {
            return Err(PlatformError::InvalidInput(
                "diagnostics_destination_managed",
            ));
        }
        let parent = open_directory_at(current.as_raw_fd(), OsStr::new(".."))?;
        let parent_identity = file_identity(&parent)?;
        if parent_identity == identity {
            break;
        }
        current = parent;
    }
    Ok(())
}

fn open_directory_at(parent: RawFd, leaf: &OsStr) -> PlatformResult<File> {
    let leaf = c_string(leaf)?;
    let descriptor = unsafe {
        libc::openat(
            parent,
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn open_unique_temporary(parent: RawFd) -> PlatformResult<(CString, File)> {
    for _ in 0..16 {
        let name = CString::new(format!(
            ".wardrobe-diagnostics-{}.tmp",
            Uuid::new_v4().simple()
        ))
        .map_err(|_| PlatformError::InvalidInput("diagnostics_destination"))?;
        match open_temporary(parent, &name) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(PlatformError::Conflict(
        "diagnostics_temporary_name_exhausted",
    ))
}

fn open_temporary(parent: RawFd, leaf: &CString) -> std::io::Result<File> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            leaf.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        let error = std::io::Error::last_os_error();
        if let Ok(metadata) = file.metadata() {
            unlink_if_owned(parent, leaf, (metadata.dev(), metadata.ino()));
        }
        return Err(error);
    }
    Ok(file)
}

fn open_file_at(parent: RawFd, leaf: &CString) -> PlatformResult<File> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn verify_open_file(
    file: &mut File,
    expected: &[u8],
    expected_identity: (u64, u64),
) -> PlatformResult<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != expected.len() as u64
        || file_identity(file)? != expected_identity
    {
        return Err(PlatformError::Corrupt("diagnostics_file_identity"));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut actual = vec![0; expected.len()];
    file.read_exact(&mut actual)?;
    if Sha256::digest(&actual).as_slice() != Sha256::digest(expected).as_slice() {
        return Err(PlatformError::Corrupt("diagnostics_file_verification"));
    }
    Ok(())
}

fn file_identity(file: &File) -> PlatformResult<(u64, u64)> {
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

fn stat_identity(value: &libc::stat) -> (u64, u64) {
    (value.st_dev as u64, value.st_ino as u64)
}

fn stat_at(parent: RawFd, leaf: &CString) -> std::io::Result<libc::stat> {
    let mut value = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstatat(parent, leaf.as_ptr(), &mut value, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        Ok(value)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn unlink_if_owned(parent: RawFd, leaf: &CString, identity: (u64, u64)) {
    let Ok(named) = stat_at(parent, leaf) else {
        return;
    };
    if stat_identity(&named) == identity
        && named.st_nlink == 1
        && (named.st_mode & libc::S_IFMT) == libc::S_IFREG
    {
        let _ = unsafe { libc::unlinkat(parent, leaf.as_ptr(), 0) };
    }
}

fn c_string(value: &OsStr) -> PlatformResult<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| PlatformError::InvalidInput("diagnostics_destination"))
}

#[cfg(target_os = "macos")]
fn rename_no_replace(
    from_parent: RawFd,
    from: &CString,
    to_parent: RawFd,
    to: &CString,
) -> std::io::Result<()> {
    let result = unsafe {
        libc::renameatx_np(
            from_parent,
            from.as_ptr(),
            to_parent,
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
fn rename_no_replace(
    _from_parent: RawFd,
    _from: &CString,
    _to_parent: RawFd,
    _to: &CString,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "macOS create-only rename is required",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use wardrobe_core::RequestId;

    #[test]
    fn exporter_writes_a_complete_redacted_report() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        crate::Database::open(&paths, 1_700_000_000_000).unwrap();
        let connection = Connection::open(&paths.database).unwrap();
        connection
            .execute(
                "INSERT INTO jobs(
                    job_id, idempotency_key, kind, payload_version, payload_json,
                    input_hash, pipeline_version, state, available_at_ms, attempt,
                    retry_limit, backoff_ms, fence, lease_owner, lease_expires_at_ms,
                    created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, 'verify_blob_v1', 1, ?3, ?4, 'test-v1',
                    'failed', 0, 1, 1, 0, 0, NULL, NULL, 0, 0)",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    "private/path/personal-file.jpg",
                    r#"{"prompt":"private model payload sentinel"}"#,
                    "a".repeat(64),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO job_failures(
                    job_id, failure_code, user_action_key, retryable, failed_at_ms
                 ) SELECT job_id, 'blob_missing', 'rerun_storage_check', 0, 0
                   FROM jobs WHERE idempotency_key=?1",
                ["private/path/personal-file.jpg"],
            )
            .unwrap();
        drop(connection);
        let logs = temporary.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o700)).unwrap();
        let diagnostics = JsonlDiagnostics::new(logs.join("diagnostics.jsonl"));
        let destination = temporary.path().join("report.json");
        let request = ExportDiagnosticsV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            destination_path: destination.to_string_lossy().into_owned(),
        };

        let response = DiagnosticsExporter::new(&paths, &diagnostics)
            .export(&request, 1_700_000_000_100)
            .unwrap();

        response.validate().unwrap();
        let bytes = std::fs::read(&destination).unwrap();
        let report: DiagnosticsExportV1 = serde_json::from_slice(&bytes).unwrap();
        report.validate().unwrap();
        assert_eq!(report.counters.len(), DiagnosticsCounterNameV1::ALL.len());
        assert_eq!(
            report
                .counters
                .iter()
                .find(|counter| { counter.name == DiagnosticsCounterNameV1::FoundationJobsFailed })
                .unwrap()
                .value,
            1
        );
        assert_eq!(
            report.job_failures,
            vec![DiagnosticsJobFailureV1::Foundation {
                kind: JobKindV1::VerifyBlobV1,
                code: ErrorCodeV1::NotFound,
                user_action: UserActionKeyV1::ReviewStorage,
                attempt_count: 1,
                occurrence_count: 1,
            }]
        );
        let serialized = String::from_utf8(bytes).unwrap();
        assert!(!serialized.contains("private/path/personal-file.jpg"));
        assert!(!serialized.contains("private model payload sentinel"));
        assert_eq!(
            std::fs::metadata(destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn publisher_is_create_only_and_rejects_unsafe_parents() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let logs = temporary.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        let diagnostics_path = logs.join("diagnostics.jsonl");
        let destination = temporary.path().join("report.json");
        let bytes = b"{\"schema_version\":1}\n";

        publish_report(&destination, bytes, &paths, &diagnostics_path).unwrap();
        assert!(matches!(
            publish_report(&destination, bytes, &paths, &diagnostics_path),
            Err(PlatformError::Conflict("diagnostics_destination_exists"))
        ));
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            publish_report(
                &temporary.path().join("unsafe.json"),
                bytes,
                &paths,
                &diagnostics_path
            ),
            Err(PlatformError::InvalidInput(
                "diagnostics_destination_parent"
            ))
        ));
    }

    #[test]
    fn publisher_rejects_link_special_and_symlink_parent_targets() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let logs = temporary.path().join("logs");
        std::fs::create_dir(&logs).unwrap();
        let diagnostics_path = logs.join("diagnostics.jsonl");
        let bytes = b"{\"schema_version\":1}\n";
        let target = temporary.path().join("existing-target");
        std::fs::write(&target, b"do not mutate").unwrap();

        let symlink_destination = temporary.path().join("symlink.json");
        symlink(&target, &symlink_destination).unwrap();
        let hardlink_destination = temporary.path().join("hardlink.json");
        std::fs::hard_link(&target, &hardlink_destination).unwrap();
        let directory_destination = temporary.path().join("directory.json");
        std::fs::create_dir(&directory_destination).unwrap();

        for destination in [
            &symlink_destination,
            &hardlink_destination,
            &directory_destination,
        ] {
            assert!(matches!(
                publish_report(destination, bytes, &paths, &diagnostics_path),
                Err(PlatformError::Conflict("diagnostics_destination_exists"))
            ));
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"do not mutate");

        let real_parent = temporary.path().join("real-parent");
        std::fs::create_dir(&real_parent).unwrap();
        let linked_parent = temporary.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(publish_report(
            &linked_parent.join("report.json"),
            bytes,
            &paths,
            &diagnostics_path
        )
        .is_err());
        assert!(!real_parent.join("report.json").exists());
    }

    #[test]
    fn directory_descriptor_cleanup_and_identity_checks_resist_substitution() {
        let temporary = tempfile::tempdir().unwrap();
        let selected = temporary.path().join("selected");
        let moved = temporary.path().join("moved");
        std::fs::create_dir(&selected).unwrap();
        std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = open_directory(&selected).unwrap();
        std::fs::rename(&selected, &moved).unwrap();
        std::fs::create_dir(&selected).unwrap();

        let leaf = CString::new("owned.tmp").unwrap();
        let mut owned = open_temporary(parent.as_raw_fd(), &leaf).unwrap();
        let identity = file_identity(&owned).unwrap();
        owned.write_all(b"complete").unwrap();
        owned.sync_all().unwrap();
        assert!(moved.join("owned.tmp").is_file());
        assert!(!selected.join("owned.tmp").exists());

        let alias = moved.join("alias");
        std::fs::hard_link(moved.join("owned.tmp"), &alias).unwrap();
        assert!(matches!(
            verify_open_file(&mut owned, b"complete", identity),
            Err(PlatformError::Corrupt("diagnostics_file_identity"))
        ));
        std::fs::remove_file(alias).unwrap();
        verify_open_file(&mut owned, b"complete", identity).unwrap();

        std::fs::remove_file(moved.join("owned.tmp")).unwrap();
        std::fs::write(moved.join("owned.tmp"), b"substitute").unwrap();
        unlink_if_owned(parent.as_raw_fd(), &leaf, identity);
        assert_eq!(
            std::fs::read(moved.join("owned.tmp")).unwrap(),
            b"substitute"
        );

        let cleanup_leaf = CString::new("cleanup.tmp").unwrap();
        let cleanup = open_temporary(parent.as_raw_fd(), &cleanup_leaf).unwrap();
        let cleanup_identity = file_identity(&cleanup).unwrap();
        drop(cleanup);
        unlink_if_owned(parent.as_raw_fd(), &cleanup_leaf, cleanup_identity);
        assert!(!moved.join("cleanup.tmp").exists());
    }

    #[test]
    fn destination_parent_policy_rejects_wrong_owner_and_writable_modes() {
        assert!(private_destination_parent(true, 501, 0o40700, 501));
        assert!(!private_destination_parent(false, 501, 0o100600, 501));
        assert!(!private_destination_parent(true, 502, 0o40700, 501));
        assert!(!private_destination_parent(true, 501, 0o40720, 501));
        assert!(!private_destination_parent(true, 501, 0o40702, 501));
    }
}
