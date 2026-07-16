use crate::model::{CompletionOutcome, EnqueueOutcome, JobOutput, LeasedJob, ModelError, NewJob};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row, TransactionBehavior};
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS jobs (
    id                  TEXT PRIMARY KEY,
    idempotency_key     TEXT NOT NULL UNIQUE,
    kind                TEXT NOT NULL,
    payload_version     INTEGER NOT NULL CHECK (payload_version > 0),
    payload_json        TEXT NOT NULL CHECK (json_valid(payload_json)),
    input_hash          TEXT NOT NULL,
    pipeline_version    TEXT NOT NULL,
    state               TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded')),
    available_at_ms     INTEGER NOT NULL,
    attempt             INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    fence               INTEGER NOT NULL DEFAULT 0 CHECK (fence >= 0),
    lease_owner         TEXT,
    lease_expires_at_ms INTEGER,
    created_at_ms       INTEGER NOT NULL,
    CHECK (
        (state = 'running' AND lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
        OR
        (state IN ('queued', 'succeeded') AND lease_owner IS NULL AND lease_expires_at_ms IS NULL)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS job_results (
    job_id          TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE RESTRICT,
    output_key      TEXT NOT NULL UNIQUE,
    result_hash     TEXT NOT NULL,
    output_json     TEXT NOT NULL CHECK (json_valid(output_json)),
    winning_owner   TEXT NOT NULL CHECK (length(winning_owner) > 0),
    winning_fence   INTEGER NOT NULL CHECK (winning_fence > 0),
    committed_at_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS jobs_ready_idx
    ON jobs(available_at_ms, created_at_ms, id)
    WHERE state = 'queued';
CREATE INDEX IF NOT EXISTS jobs_expired_idx
    ON jobs(lease_expires_at_ms, id)
    WHERE state = 'running';

PRAGMA user_version = 2;
"#;

#[derive(Clone, Debug)]
pub struct JobStore {
    path: PathBuf,
    busy_timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionStage {
    ResultInserted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PragmaSettings {
    pub journal_mode: String,
    pub synchronous: i64,
    pub foreign_keys: bool,
    pub busy_timeout_ms: i64,
    pub fullfsync: bool,
    pub checkpoint_fullfsync: bool,
    pub trusted_schema: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JobSnapshot {
    pub id: String,
    pub state: String,
    pub attempt: i64,
    pub fence: i64,
    pub lease_owner: Option<String>,
    pub lease_expires_at_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResultSnapshot {
    pub job_id: String,
    pub output_key: String,
    pub result_hash: String,
    pub winning_owner: String,
    pub winning_fence: i64,
    pub committed_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DatabaseAudit {
    pub integrity_check: String,
    pub foreign_key_violations: usize,
    pub job_count: i64,
    pub result_count: i64,
    pub runnable_job_count: i64,
}

#[derive(Debug)]
pub enum StoreError {
    Conflict(String),
    LeaseLost,
    InvalidInput(ModelError),
    InvalidTime(String),
    Invariant(String),
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(message) => write!(formatter, "conflict: {message}"),
            Self::LeaseLost => write!(formatter, "lease is no longer active"),
            Self::InvalidInput(error) => error.fmt(formatter),
            Self::InvalidTime(message) => write!(formatter, "invalid time: {message}"),
            Self::Invariant(message) => write!(formatter, "database invariant failed: {message}"),
            Self::Sqlite(error) => error.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidInput(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<ModelError> for StoreError {
    fn from(error: ModelError) -> Self {
        Self::InvalidInput(error)
    }
}

impl JobStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_busy_timeout(path, DEFAULT_BUSY_TIMEOUT)
    }

    pub fn open_with_busy_timeout(
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self, StoreError> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
            busy_timeout,
        };
        let connection = store.connection()?;
        connection.execute_batch(SCHEMA)?;
        Ok(store)
    }

    pub fn enqueue(
        &self,
        job: &NewJob,
        available_at_ms: i64,
    ) -> Result<EnqueueOutcome, StoreError> {
        job.validate()?;
        let payload_json = serde_json::to_string(&job.payload)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing = transaction
            .query_row(
                "SELECT id, idempotency_key, kind, payload_version, payload_json,
                        input_hash, pipeline_version
                 FROM jobs
                 WHERE idempotency_key = ?1 OR id = ?2
                 ORDER BY CASE WHEN idempotency_key = ?1 THEN 0 ELSE 1 END
                 LIMIT 1",
                params![job.idempotency_key, job.id],
                new_job_from_row,
            )
            .optional()?;

        if let Some(existing) = existing {
            if existing == *job {
                transaction.commit()?;
                return Ok(EnqueueOutcome::AlreadyPresent);
            }
            return Err(StoreError::Conflict(
                "job id or idempotency key has a different immutable envelope".into(),
            ));
        }

        transaction.execute(
            "INSERT INTO jobs (
                id, idempotency_key, kind, payload_version, payload_json,
                input_hash, pipeline_version, state, available_at_ms,
                attempt, fence, lease_owner, lease_expires_at_ms, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', ?8, 0, 0, NULL, NULL, ?8)",
            params![
                job.id,
                job.idempotency_key,
                job.kind,
                job.payload_version,
                payload_json,
                job.normalized_input_hash,
                job.pipeline_version,
                available_at_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(EnqueueOutcome::Enqueued)
    }

    pub fn claim(
        &self,
        worker: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<Option<LeasedJob>, StoreError> {
        self.claim_with_observer(worker, now_ms, lease_ms, |_| {})
    }

    pub fn claim_with_observer<F>(
        &self,
        worker: &str,
        now_ms: i64,
        lease_ms: i64,
        observer: F,
    ) -> Result<Option<LeasedJob>, StoreError>
    where
        F: FnOnce(&LeasedJob),
    {
        if worker.is_empty() {
            return Err(StoreError::InvalidTime(
                "worker identity must not be empty".into(),
            ));
        }
        if lease_ms <= 0 {
            return Err(StoreError::InvalidTime(
                "lease duration must be positive".into(),
            ));
        }
        let lease_expires_at_ms = now_ms
            .checked_add(lease_ms)
            .ok_or_else(|| StoreError::InvalidTime("lease expiry overflowed".into()))?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = transaction
            .query_row(
                "SELECT id
                 FROM jobs
                 WHERE (state = 'queued' AND available_at_ms <= ?1)
                    OR (state = 'running' AND lease_expires_at_ms <= ?1)
                 ORDER BY
                    CASE
                        WHEN state = 'queued' THEN available_at_ms
                        ELSE lease_expires_at_ms
                    END,
                    created_at_ms,
                    id
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
            "UPDATE jobs
             SET state = 'running',
                 attempt = attempt + 1,
                 fence = fence + 1,
                 lease_owner = ?2,
                 lease_expires_at_ms = ?3
             WHERE id = ?1",
            params![job_id, worker, lease_expires_at_ms],
        )?;

        let leased = transaction.query_row(
            "SELECT id, idempotency_key, kind, payload_version, payload_json,
                    input_hash, pipeline_version, attempt, lease_owner,
                    lease_expires_at_ms, fence
             FROM jobs
             WHERE id = ?1",
            [&job_id],
            leased_job_from_row,
        )?;
        observer(&leased);
        transaction.commit()?;
        Ok(Some(leased))
    }

    pub fn complete(
        &self,
        lease: &LeasedJob,
        now_ms: i64,
        output: &JobOutput,
    ) -> Result<CompletionOutcome, StoreError> {
        self.complete_with_observer(lease, now_ms, output, |_| {})
    }

    pub fn complete_with_observer<F>(
        &self,
        lease: &LeasedJob,
        now_ms: i64,
        output: &JobOutput,
        observer: F,
    ) -> Result<CompletionOutcome, StoreError>
    where
        F: FnOnce(CompletionStage),
    {
        output.validate()?;
        let output_json = serde_json::to_string(&output.output)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        let active = transaction
            .query_row(
                "SELECT state, lease_owner, lease_expires_at_ms, fence
                 FROM jobs WHERE id = ?1",
                [&lease.job.id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;

        let Some((state, owner, expires_at_ms, fence)) = active else {
            return Err(StoreError::LeaseLost);
        };

        if state == "succeeded" {
            let committed = transaction
                .query_row(
                    "SELECT result_hash, winning_owner, winning_fence
                     FROM job_results WHERE job_id = ?1",
                    [&lease.job.id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| {
                    StoreError::Invariant("succeeded job has no output receipt".into())
                })?;

            let (committed_hash, winning_owner, winning_fence) = committed;
            if winning_owner != lease.lease_owner || winning_fence != lease.fence {
                return Err(StoreError::LeaseLost);
            }
            if committed_hash == output.result_hash {
                transaction.commit()?;
                return Ok(CompletionOutcome::AlreadyCommitted);
            }
            return Err(StoreError::Conflict(
                "job already committed a different result hash".into(),
            ));
        }

        let owns_unexpired_lease = state == "running"
            && owner.as_deref() == Some(lease.lease_owner.as_str())
            && fence == lease.fence
            && expires_at_ms.is_some_and(|expiry| expiry > now_ms);
        if !owns_unexpired_lease {
            return Err(StoreError::LeaseLost);
        }

        let output_key_owner = transaction
            .query_row(
                "SELECT job_id FROM job_results WHERE output_key = ?1",
                [&output.output_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if output_key_owner.is_some() {
            return Err(StoreError::Conflict(
                "output key already belongs to another receipt".into(),
            ));
        }

        transaction.execute(
            "INSERT INTO job_results (
                job_id, output_key, result_hash, output_json, winning_owner,
                winning_fence, committed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                lease.job.id,
                output.output_key,
                output.result_hash,
                output_json,
                lease.lease_owner,
                lease.fence,
                now_ms,
            ],
        )?;
        observer(CompletionStage::ResultInserted);

        let updated = transaction.execute(
            "UPDATE jobs
             SET state = 'succeeded', lease_owner = NULL, lease_expires_at_ms = NULL
             WHERE id = ?1
               AND state = 'running'
               AND lease_owner = ?2
               AND fence = ?3
               AND lease_expires_at_ms > ?4",
            params![lease.job.id, lease.lease_owner, lease.fence, now_ms],
        )?;
        if updated != 1 {
            return Err(StoreError::LeaseLost);
        }

        transaction.commit()?;
        Ok(CompletionOutcome::Committed)
    }

    pub fn job(&self, job_id: &str) -> Result<Option<JobSnapshot>, StoreError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, state, attempt, fence, lease_owner, lease_expires_at_ms
                 FROM jobs WHERE id = ?1",
                [job_id],
                |row| {
                    Ok(JobSnapshot {
                        id: row.get(0)?,
                        state: row.get(1)?,
                        attempt: row.get(2)?,
                        fence: row.get(3)?,
                        lease_owner: row.get(4)?,
                        lease_expires_at_ms: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn result(&self, job_id: &str) -> Result<Option<ResultSnapshot>, StoreError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT job_id, output_key, result_hash, winning_owner, winning_fence,
                        committed_at_ms
                 FROM job_results WHERE job_id = ?1",
                [job_id],
                |row| {
                    Ok(ResultSnapshot {
                        job_id: row.get(0)?,
                        output_key: row.get(1)?,
                        result_hash: row.get(2)?,
                        winning_owner: row.get(3)?,
                        winning_fence: row.get(4)?,
                        committed_at_ms: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn pragmas(&self) -> Result<PragmaSettings, StoreError> {
        let connection = self.connection()?;
        read_pragmas(&connection)
    }

    pub fn audit(&self, now_ms: i64) -> Result<DatabaseAudit, StoreError> {
        let connection = self.connection()?;
        let integrity_check =
            connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        let mut foreign_key_check = connection.prepare("PRAGMA foreign_key_check")?;
        let mut foreign_key_rows = foreign_key_check.query([])?;
        let mut foreign_key_violations = 0;
        while foreign_key_rows.next()?.is_some() {
            foreign_key_violations += 1;
        }
        let job_count = connection.query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))?;
        let result_count =
            connection.query_row("SELECT COUNT(*) FROM job_results", [], |row| row.get(0))?;
        let runnable_job_count = connection.query_row(
            "SELECT COUNT(*)
             FROM jobs
             WHERE (state = 'queued' AND available_at_ms <= ?1)
                OR (state = 'running' AND lease_expires_at_ms <= ?1)",
            [now_ms],
            |row| row.get(0),
        )?;
        Ok(DatabaseAudit {
            integrity_check,
            foreign_key_violations,
            job_count,
            result_count,
            runnable_job_count,
        })
    }

    fn connection(&self) -> Result<Connection, StoreError> {
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        )?;
        connection.busy_timeout(self.busy_timeout)?;

        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Invariant(format!(
                "journal_mode is {journal_mode}, expected wal"
            )));
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "fullfsync", true)?;
        connection.pragma_update(None, "checkpoint_fullfsync", true)?;
        connection.pragma_update(None, "trusted_schema", false)?;

        let settings = read_pragmas(&connection)?;
        let expected_timeout = i64::try_from(self.busy_timeout.as_millis()).unwrap_or(i64::MAX);
        if settings.synchronous != 2
            || !settings.foreign_keys
            || settings.busy_timeout_ms != expected_timeout
            || !settings.fullfsync
            || !settings.checkpoint_fullfsync
            || settings.trusted_schema
        {
            return Err(StoreError::Invariant(format!(
                "connection PRAGMAs were not applied: {settings:?}"
            )));
        }
        Ok(connection)
    }
}

fn read_pragmas(connection: &Connection) -> Result<PragmaSettings, StoreError> {
    Ok(PragmaSettings {
        journal_mode: connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?,
        synchronous: connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?,
        foreign_keys: pragma_bool(connection, "PRAGMA foreign_keys")?,
        busy_timeout_ms: connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?,
        fullfsync: pragma_bool(connection, "PRAGMA fullfsync")?,
        checkpoint_fullfsync: pragma_bool(connection, "PRAGMA checkpoint_fullfsync")?,
        trusted_schema: pragma_bool(connection, "PRAGMA trusted_schema")?,
    })
}

fn pragma_bool(connection: &Connection, sql: &str) -> Result<bool, rusqlite::Error> {
    connection.query_row(sql, [], |row| Ok(row.get::<_, i64>(0)? != 0))
}

fn new_job_from_row(row: &Row<'_>) -> rusqlite::Result<NewJob> {
    let payload_json: String = row.get(4)?;
    let payload: Value = serde_json::from_str(&payload_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(NewJob {
        id: row.get(0)?,
        idempotency_key: row.get(1)?,
        kind: row.get(2)?,
        payload_version: row.get(3)?,
        payload,
        normalized_input_hash: row.get(5)?,
        pipeline_version: row.get(6)?,
    })
}

fn leased_job_from_row(row: &Row<'_>) -> rusqlite::Result<LeasedJob> {
    let job = new_job_from_row(row)?;
    Ok(LeasedJob {
        job,
        attempt: row.get(7)?,
        lease_owner: row.get(8)?,
        lease_expires_at_ms: row.get(9)?,
        fence: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, JobStore) {
        let directory = TempDir::new().unwrap();
        let store = JobStore::open(directory.path().join("jobs.sqlite")).unwrap();
        (directory, store)
    }

    fn job(id: &str, key: &str) -> NewJob {
        NewJob {
            id: id.into(),
            idempotency_key: key.into(),
            kind: "thumbnail".into(),
            payload_version: 1,
            payload: json!({"asset": id}),
            normalized_input_hash: format!("input-{id}"),
            pipeline_version: "pipeline-v1".into(),
        }
    }

    fn output(key: &str, hash: &str) -> JobOutput {
        JobOutput {
            output_key: key.into(),
            result_hash: hash.into(),
            output: json!({"thumbnail": key}),
        }
    }

    #[test]
    fn configures_every_required_pragma() {
        let (_directory, store) = fixture();
        let settings = store.pragmas().unwrap();
        assert_eq!(settings.journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(settings.synchronous, 2);
        assert!(settings.foreign_keys);
        assert_eq!(settings.busy_timeout_ms, 5_000);
        assert!(settings.fullfsync);
        assert!(settings.checkpoint_fullfsync);
        assert!(!settings.trusted_schema);
    }

    #[test]
    fn idempotent_enqueue_requires_an_identical_envelope() {
        let (_directory, store) = fixture();
        let original = job("job-1", "request-1");
        assert_eq!(
            store.enqueue(&original, 100).unwrap(),
            EnqueueOutcome::Enqueued
        );
        assert_eq!(
            store.enqueue(&original, 999).unwrap(),
            EnqueueOutcome::AlreadyPresent
        );

        let mut conflict = original.clone();
        conflict.normalized_input_hash = "different".into();
        assert!(matches!(
            store.enqueue(&conflict, 100),
            Err(StoreError::Conflict(_))
        ));

        let conflicting_id = job("job-1", "request-2");
        assert!(matches!(
            store.enqueue(&conflicting_id, 100),
            Err(StoreError::Conflict(_))
        ));
    }

    #[test]
    fn claims_ready_jobs_in_deterministic_order() {
        let (_directory, store) = fixture();
        store.enqueue(&job("job-b", "request-b"), 90).unwrap();
        store.enqueue(&job("job-a", "request-a"), 90).unwrap();
        store.enqueue(&job("job-c", "request-c"), 101).unwrap();

        assert_eq!(
            store.claim("worker", 100, 10).unwrap().unwrap().job.id,
            "job-a"
        );
        assert_eq!(
            store.claim("worker", 100, 10).unwrap().unwrap().job.id,
            "job-b"
        );
        assert!(store.claim("worker", 100, 10).unwrap().is_none());
    }

    #[test]
    fn exact_expiry_reclaims_and_increments_attempt_and_fence() {
        let (_directory, store) = fixture();
        store.enqueue(&job("job-1", "request-1"), 100).unwrap();
        let first = store.claim("worker-a", 100, 50).unwrap().unwrap();
        assert_eq!((first.attempt, first.fence), (1, 1));
        assert!(store.claim("worker-b", 149, 50).unwrap().is_none());

        let second = store.claim("worker-b", 150, 50).unwrap().unwrap();
        assert_eq!((second.attempt, second.fence), (2, 2));
        assert_eq!(second.lease_owner, "worker-b");
    }

    #[test]
    fn stale_fence_cannot_complete() {
        let (_directory, store) = fixture();
        store.enqueue(&job("job-1", "request-1"), 100).unwrap();
        let stale = store.claim("worker-a", 100, 50).unwrap().unwrap();
        let current = store.claim("worker-b", 150, 50).unwrap().unwrap();

        assert!(matches!(
            store.complete(&stale, 151, &output("output-1", "hash-a")),
            Err(StoreError::LeaseLost)
        ));
        assert_eq!(
            store
                .complete(&current, 151, &output("output-1", "hash-b"))
                .unwrap(),
            CompletionOutcome::Committed
        );
        assert_eq!(store.result("job-1").unwrap().unwrap().winning_fence, 2);

        assert!(matches!(
            store.complete(&stale, 152, &output("output-1", "hash-b")),
            Err(StoreError::LeaseLost)
        ));
        assert!(matches!(
            store.complete(&stale, 152, &output("output-1", "hash-c")),
            Err(StoreError::LeaseLost)
        ));
    }

    #[test]
    fn completion_is_atomic_and_idempotent_by_result_hash() {
        let (_directory, store) = fixture();
        store.enqueue(&job("job-1", "request-1"), 100).unwrap();
        let lease = store.claim("worker-a", 100, 50).unwrap().unwrap();
        let first = output("output-1", "hash-a");
        assert_eq!(
            store.complete(&lease, 101, &first).unwrap(),
            CompletionOutcome::Committed
        );
        assert_eq!(
            store.complete(&lease, 102, &first).unwrap(),
            CompletionOutcome::AlreadyCommitted
        );

        let same_hash_new_key = output("ignored-new-key", "hash-a");
        assert_eq!(
            store.complete(&lease, 102, &same_hash_new_key).unwrap(),
            CompletionOutcome::AlreadyCommitted
        );
        assert!(matches!(
            store.complete(&lease, 102, &output("output-1", "hash-b")),
            Err(StoreError::Conflict(_))
        ));

        let mut fabricated_owner = lease.clone();
        fabricated_owner.lease_owner = "worker-fabricated".into();
        assert!(matches!(
            store.complete(&fabricated_owner, 102, &first),
            Err(StoreError::LeaseLost)
        ));
        let mut fabricated_fence = lease.clone();
        fabricated_fence.fence += 1;
        assert!(matches!(
            store.complete(&fabricated_fence, 102, &first),
            Err(StoreError::LeaseLost)
        ));
        assert_eq!(store.audit(1_000).unwrap().result_count, 1);
    }

    #[test]
    fn completion_at_exact_expiry_loses_the_lease() {
        let (_directory, store) = fixture();
        store.enqueue(&job("job-1", "request-1"), 100).unwrap();
        let lease = store.claim("worker-a", 100, 50).unwrap().unwrap();
        assert!(matches!(
            store.complete(&lease, 150, &output("output-1", "hash-a")),
            Err(StoreError::LeaseLost)
        ));
        assert!(store.result("job-1").unwrap().is_none());
    }

    #[test]
    fn schema_is_strict_and_foreign_keys_are_enforced() {
        let (directory, store) = fixture();
        let connection = store.connection().unwrap();
        let strict: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_list
                 WHERE name IN ('jobs', 'job_results') AND strict = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(strict, 2);
        assert!(connection
            .execute(
                "INSERT INTO job_results (
                    job_id, output_key, result_hash, output_json, winning_owner,
                    winning_fence, committed_at_ms
                 ) VALUES ('missing', 'output', 'hash', '{}', 'worker', 1, 100)",
                [],
            )
            .is_err());
        drop(connection);
        drop(store);

        let fresh = JobStore::open(directory.path().join("jobs.sqlite")).unwrap();
        let audit = fresh.audit(100).unwrap();
        assert_eq!(audit.integrity_check, "ok");
        assert_eq!(audit.foreign_key_violations, 0);
    }
}
