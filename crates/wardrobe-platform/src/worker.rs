use crate::database::LeasedJob;
use crate::{BlobStore, Database, PlatformError, PlatformResult};
use std::collections::HashMap;
use std::sync::Mutex;
use wardrobe_core::{
    ErrorCodeV1, JobClaimV1, JobId, JobKindV1, JobPort, PortError, PortErrorKind, PortResult,
    Sha256Digest, UserActionKeyV1,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOutcome {
    Idle,
    Succeeded {
        job_id: String,
    },
    Retrying {
        job_id: String,
    },
    Failed {
        job_id: String,
        failure_code: &'static str,
    },
}

#[derive(Clone, Debug)]
pub struct VerifyBlobWorker {
    worker_id: String,
    lease_ms: i64,
}

#[derive(Debug)]
pub struct PlatformJobQueue {
    database: Database,
    worker_id: String,
    active: Mutex<HashMap<String, LeasedJob>>,
}

impl PlatformJobQueue {
    pub fn new(database: Database, worker_id: impl Into<String>) -> PlatformResult<Self> {
        let worker_id = worker_id.into();
        if worker_id.is_empty() || worker_id.len() > 64 {
            return Err(PlatformError::InvalidInput("worker_id"));
        }
        Ok(Self {
            database,
            worker_id,
            active: Mutex::new(HashMap::new()),
        })
    }
}

impl JobPort for PlatformJobQueue {
    fn claim_next(&self, lease_seconds: u32) -> PortResult<Option<JobClaimV1>> {
        let lease_ms = i64::from(lease_seconds)
            .checked_mul(1000)
            .ok_or_else(|| PortError::new(PortErrorKind::Conflict))?;
        let now_ms = unix_now_ms()?;
        let Some(leased) = self
            .database
            .claim(&self.worker_id, now_ms, lease_ms)
            .map_err(port_error)?
        else {
            return Ok(None);
        };
        let claim = JobClaimV1 {
            job_id: parse_job_id(&leased.job_id)?,
            kind: JobKindV1::VerifyBlobV1,
            input_digest: Sha256Digest::parse(leased.blob_sha256.clone())
                .map_err(|_| PortError::new(PortErrorKind::DataIntegrity))?,
            attempt: u16::try_from(leased.attempt)
                .map_err(|_| PortError::new(PortErrorKind::DataIntegrity))?,
            max_attempts: u16::try_from(leased.retry_limit + 1)
                .map_err(|_| PortError::new(PortErrorKind::DataIntegrity))?,
            fence: u64::try_from(leased.fence)
                .map_err(|_| PortError::new(PortErrorKind::DataIntegrity))?,
        };
        self.active
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal))?
            .insert(leased.job_id.clone(), leased);
        Ok(Some(claim))
    }

    fn complete(&self, job_id: JobId, fence: u64) -> PortResult<()> {
        let key = job_id.to_string();
        let leased = self.take_matching(&key, fence)?;
        self.database
            .complete_known_blob(&leased, unix_now_ms()?)
            .map_err(port_error)
    }

    fn fail(
        &self,
        job_id: JobId,
        fence: u64,
        code: ErrorCodeV1,
        user_action: UserActionKeyV1,
        retryable: bool,
    ) -> PortResult<()> {
        let key = job_id.to_string();
        let leased = self.take_matching(&key, fence)?;
        let now_ms = unix_now_ms()?;
        if retryable && self.database.retry(&leased, now_ms).map_err(port_error)? {
            return Ok(());
        }
        self.database
            .fail_permanently(
                &leased,
                error_code_to_db(code),
                user_action_to_db(user_action),
                now_ms,
            )
            .map_err(port_error)
    }
}

impl PlatformJobQueue {
    fn take_matching(&self, job_id: &str, fence: u64) -> PortResult<LeasedJob> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal))?;
        let leased = active
            .get(job_id)
            .cloned()
            .ok_or_else(|| PortError::new(PortErrorKind::Conflict))?;
        if u64::try_from(leased.fence).ok() != Some(fence) {
            return Err(PortError::new(PortErrorKind::Conflict));
        }
        active.remove(job_id);
        Ok(leased)
    }
}

impl VerifyBlobWorker {
    pub fn new(worker_id: impl Into<String>, lease_ms: i64) -> PlatformResult<Self> {
        let worker_id = worker_id.into();
        if worker_id.is_empty() || worker_id.len() > 64 || lease_ms <= 0 {
            return Err(PlatformError::InvalidInput("worker_configuration"));
        }
        Ok(Self {
            worker_id,
            lease_ms,
        })
    }

    pub fn run_once(
        &self,
        database: &Database,
        blobs: &BlobStore,
        now_ms: i64,
    ) -> PlatformResult<RunOutcome> {
        let Some(leased) = database.claim(&self.worker_id, now_ms, self.lease_ms)? else {
            return Ok(RunOutcome::Idle);
        };
        match blobs.verify(&leased.blob_sha256) {
            Ok(blob) => {
                database.complete(&leased, blob.byte_length, now_ms)?;
                Ok(RunOutcome::Succeeded {
                    job_id: leased.job_id,
                })
            }
            Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                permanent_failure(
                    database,
                    &leased,
                    "blob_missing",
                    "rerun_storage_check",
                    now_ms,
                )
            }
            Err(PlatformError::Corrupt(_)) => permanent_failure(
                database,
                &leased,
                "blob_integrity_failed",
                "rerun_storage_check",
                now_ms,
            ),
            Err(PlatformError::Io(_)) => {
                if database.retry(&leased, now_ms)? {
                    Ok(RunOutcome::Retrying {
                        job_id: leased.job_id,
                    })
                } else {
                    permanent_failure(
                        database,
                        &leased,
                        "blob_unavailable",
                        "retry_when_storage_available",
                        now_ms,
                    )
                }
            }
            Err(_) => permanent_failure(
                database,
                &leased,
                "verify_blob_failed",
                "rerun_storage_check",
                now_ms,
            ),
        }
    }
}

fn permanent_failure(
    database: &Database,
    leased: &LeasedJob,
    failure_code: &'static str,
    user_action_key: &'static str,
    now_ms: i64,
) -> PlatformResult<RunOutcome> {
    database.fail_permanently(leased, failure_code, user_action_key, now_ms)?;
    Ok(RunOutcome::Failed {
        job_id: leased.job_id.clone(),
        failure_code,
    })
}

fn unix_now_ms() -> PortResult<i64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PortError::new(PortErrorKind::Internal))?;
    i64::try_from(elapsed.as_millis()).map_err(|_| PortError::new(PortErrorKind::Internal))
}

fn parse_job_id(value: &str) -> PortResult<JobId> {
    let uuid =
        uuid::Uuid::parse_str(value).map_err(|_| PortError::new(PortErrorKind::DataIntegrity))?;
    JobId::new(uuid).map_err(|_| PortError::new(PortErrorKind::DataIntegrity))
}

fn port_error(error: PlatformError) -> PortError {
    let kind = match error {
        PlatformError::Conflict(_) | PlatformError::LeaseLost => PortErrorKind::Conflict,
        PlatformError::Corrupt(_) => PortErrorKind::DataIntegrity,
        PlatformError::InvalidInput(_) => PortErrorKind::Conflict,
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PortErrorKind::NotFound
        }
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            PortErrorKind::PermissionDenied
        }
        PlatformError::Io(_) | PlatformError::Sqlite(_) => PortErrorKind::Unavailable,
        _ => PortErrorKind::Internal,
    };
    PortError::new(kind)
}

fn error_code_to_db(code: ErrorCodeV1) -> &'static str {
    match code {
        ErrorCodeV1::NotFound => "blob_missing",
        ErrorCodeV1::DataIntegrity => "blob_integrity_failed",
        ErrorCodeV1::StorageUnavailable => "blob_unavailable",
        _ => "verify_blob_failed",
    }
}

fn user_action_to_db(action: UserActionKeyV1) -> &'static str {
    match action {
        UserActionKeyV1::ReviewStorage => "rerun_storage_check",
        UserActionKeyV1::Retry => "retry_when_storage_available",
        _ => "restart_application",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MacOsKeychain, PrivateAppPaths};
    use wardrobe_core::{
        ApplicationService, BlobPort, BlobRecordV1, GetFoundationSnapshotV1Request, JobPort,
        RequestId, RunStorageCheckV1Request, STORAGE_CHECK_BYTES,
    };

    #[test]
    fn production_storage_job_restart_and_terminal_failure_smoke() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let blobs = BlobStore::new(&paths);
        let database = Database::open(&paths, 1).unwrap();
        let service = ApplicationService::new(database.clone(), blobs.clone(), MacOsKeychain);
        let request_id = RequestId::new_v4();
        let first = service
            .run_storage_check_v1(RunStorageCheckV1Request {
                schema_version: 1,
                request_id,
            })
            .unwrap();
        let replay = service
            .run_storage_check_v1(RunStorageCheckV1Request {
                schema_version: 1,
                request_id,
            })
            .unwrap();
        assert_eq!(first.job_id, replay.job_id);
        assert_eq!(
            replay.replay_status,
            wardrobe_core::ReplayStatusV1::Replayed
        );
        let now = unix_now_ms().unwrap();

        let queue = PlatformJobQueue::new(database.clone(), "core-job-worker").unwrap();
        let claim = queue.claim_next(10).unwrap().unwrap();
        BlobPort::verify(
            &blobs,
            &BlobRecordV1 {
                digest: claim.input_digest.clone(),
                byte_length: STORAGE_CHECK_BYTES.len() as u64,
            },
        )
        .unwrap();
        queue.complete(claim.job_id, claim.fence).unwrap();
        drop(service);
        drop(queue);
        drop(database);

        let restarted = Database::open(&paths, now + 2).unwrap();
        assert_eq!(
            restarted.counts().unwrap(),
            crate::FoundationCounts {
                blobs: 1,
                storage_checks: 1,
                jobs: 1,
                results: 1,
                failures: 0,
            }
        );
        let missing_hash = "0".repeat(64);
        let failed_job = restarted
            .enqueue_verify_blob("forced-missing-smoke", &missing_hash, now + 3)
            .unwrap();
        let worker = VerifyBlobWorker::new("smoke-worker", 10_000).unwrap();
        assert_eq!(
            worker.run_once(&restarted, &blobs, now + 4).unwrap(),
            RunOutcome::Failed {
                job_id: failed_job.clone(),
                failure_code: "blob_missing",
            }
        );

        let activity = restarted.snapshot(20).unwrap();
        let visible = activity
            .jobs
            .iter()
            .find(|job| job.job_id == failed_job)
            .unwrap();
        assert_eq!(visible.state, "failed");
        assert_eq!(visible.failure_code.as_deref(), Some("blob_missing"));
        assert_eq!(
            visible.user_action_key.as_deref(),
            Some("rerun_storage_check")
        );
        assert_eq!(restarted.counts().unwrap().results, 1);
        let service = ApplicationService::new(restarted.clone(), blobs.clone(), MacOsKeychain);
        let snapshot = service
            .get_foundation_snapshot_v1(GetFoundationSnapshotV1Request {
                schema_version: 1,
                request_id: RequestId::new_v4(),
            })
            .unwrap();
        assert!(snapshot
            .snapshot
            .recent_jobs
            .iter()
            .any(|job| job.job_id == parse_job_id(&failed_job).unwrap()
                && job.status == wardrobe_core::JobStatusV1::Failed));
    }
}
