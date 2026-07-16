use std::cell::RefCell;
use std::rc::Rc;

use wardrobe_core::*;

const NOW: &str = "2026-07-15T01:05:11Z";

#[derive(Clone, Default)]
struct Recording {
    calls: Rc<RefCell<Vec<&'static str>>>,
}

impl Recording {
    fn push(&self, call: &'static str) {
        self.calls.borrow_mut().push(call);
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.borrow().clone()
    }
}

struct Database {
    recording: Recording,
    save_plan: RefCell<Option<SaveCredentialPlanV1>>,
    delete_plan: RefCell<Option<DeleteCredentialPlanV1>>,
    save_error: Option<PortError>,
}

impl Database {
    fn new(save_plan: SaveCredentialPlanV1, delete_plan: DeleteCredentialPlanV1) -> Self {
        Self::with_recording(Recording::default(), save_plan, delete_plan)
    }

    fn with_recording(
        recording: Recording,
        save_plan: SaveCredentialPlanV1,
        delete_plan: DeleteCredentialPlanV1,
    ) -> Self {
        Self {
            recording,
            save_plan: RefCell::new(Some(save_plan)),
            delete_plan: RefCell::new(Some(delete_plan)),
            save_error: None,
        }
    }

    fn with_save_error(
        save_plan: SaveCredentialPlanV1,
        delete_plan: DeleteCredentialPlanV1,
        save_error: PortError,
    ) -> Self {
        let mut database = Self::new(save_plan, delete_plan);
        database.save_error = Some(save_error);
        database
    }
}

impl DatabasePort for Database {
    fn load_foundation_state(&self, recent_jobs_limit: usize) -> PortResult<FoundationStateV1> {
        assert_eq!(recent_jobs_limit, MAX_RECENT_JOBS);
        self.recording.push("snapshot");
        Ok(FoundationStateV1 {
            versions: FoundationVersionsV1 {
                application: "0.1.0".to_owned(),
                database_schema: 1,
                job_pipeline: 1,
            },
            local_settings: LocalSettingsSnapshotV1 {
                local_only: true,
                revision: 0,
                authority_health: LocalOnlyAuthorityHealthV1::FailClosedDefault,
                storage_status: StorageStatusV1::Ready,
                deletion_health: DeletionHealthV1::none(),
            },
            credential_references: vec![],
            recent_jobs: vec![],
        })
    }

    fn record_storage_check_and_enqueue(
        &self,
        _request_id: RequestId,
        _blob: &BlobRecordV1,
    ) -> PortResult<StorageCheckRecordV1> {
        self.recording.push("record_check");
        Ok(StorageCheckRecordV1 {
            check_id: StorageCheckId::new_v4(),
            job_id: JobId::new_v4(),
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn reserve_credential_save(
        &self,
        _request_id: RequestId,
        _provider: CredentialProviderV1,
        _display_label: &str,
    ) -> PortResult<SaveCredentialPlanV1> {
        self.recording.push("reserve_save");
        if let Some(error) = self.save_error {
            return Err(error);
        }
        Ok(self.save_plan.borrow_mut().take().unwrap())
    }

    fn activate_credential(
        &self,
        _request_id: RequestId,
        credential_id: CredentialId,
    ) -> PortResult<CredentialReferenceV1> {
        self.recording.push("activate");
        Ok(reference(credential_id, CredentialStatusV1::Active))
    }

    fn prepare_credential_delete(
        &self,
        _request_id: RequestId,
        _credential_id: CredentialId,
    ) -> PortResult<DeleteCredentialPlanV1> {
        self.recording.push("prepare_delete");
        Ok(self.delete_plan.borrow_mut().take().unwrap())
    }

    fn finish_credential_delete(
        &self,
        _request_id: RequestId,
        _credential_id: CredentialId,
    ) -> PortResult<()> {
        self.recording.push("finish_delete");
        Ok(())
    }
}

#[derive(Default)]
struct Blobs {
    recording: Recording,
}

impl BlobPort for Blobs {
    fn put_verified(
        &self,
        expected_digest: &Sha256Digest,
        bytes: &[u8],
        max_bytes: u64,
    ) -> PortResult<BlobRecordV1> {
        self.recording.push("put_blob");
        assert_eq!(bytes, STORAGE_CHECK_BYTES);
        assert_eq!(max_bytes, STORAGE_CHECK_BYTES.len() as u64);
        Ok(BlobRecordV1 {
            digest: expected_digest.clone(),
            byte_length: bytes.len() as u64,
        })
    }

    fn verify(&self, _expected: &BlobRecordV1) -> PortResult<()> {
        Ok(())
    }
}

struct Credentials {
    recording: Recording,
    put_error: Option<PortError>,
}

impl Credentials {
    fn working() -> Self {
        Self::working_with(Recording::default())
    }

    fn working_with(recording: Recording) -> Self {
        Self {
            recording,
            put_error: None,
        }
    }
}

impl CredentialPort for Credentials {
    fn put(&self, _locator: &CredentialLocator, secret: &SecretString) -> PortResult<()> {
        self.recording.push("put_secret");
        assert_eq!(secret.expose_secret(), "synthetic-secret");
        self.put_error.map_or(Ok(()), Err)
    }

    fn contains(&self, _locator: &CredentialLocator) -> PortResult<bool> {
        Ok(false)
    }

    fn delete(&self, _locator: &CredentialLocator) -> PortResult<()> {
        self.recording.push("delete_secret");
        Ok(())
    }
}

fn reference(id: CredentialId, status: CredentialStatusV1) -> CredentialReferenceV1 {
    CredentialReferenceV1 {
        credential_id: id,
        provider: CredentialProviderV1::OpenAi,
        display_label: "OpenAI".to_owned(),
        status,
        updated_at: NOW.to_owned(),
    }
}

fn plans() -> (SaveCredentialPlanV1, DeleteCredentialPlanV1, CredentialId) {
    let credential_id = CredentialId::new_v4();
    (
        SaveCredentialPlanV1::WriteSecret {
            locator: CredentialLocator::new("opaque-account".to_owned()).unwrap(),
            pending_reference: reference(credential_id, CredentialStatusV1::PendingSave),
        },
        DeleteCredentialPlanV1::DeleteSecret {
            locator: CredentialLocator::new("opaque-account".to_owned()).unwrap(),
            credential_id,
        },
        credential_id,
    )
}

fn save_request() -> SaveCredentialV1Request {
    serde_json::from_str(&format!(
        r#"{{"schema_version":1,"request_id":"{}","provider":"open_ai","display_label":"OpenAI","secret":"synthetic-secret"}}"#,
        RequestId::new_v4()
    ))
    .unwrap()
}

#[test]
fn storage_check_writes_verified_blob_before_transactional_enqueue() {
    let (save, delete, _) = plans();
    let service = ApplicationService::new(
        Database::new(save, delete),
        Blobs::default(),
        Credentials::working(),
    );

    let response = service
        .run_storage_check_v1(RunStorageCheckV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
        })
        .unwrap();

    assert_eq!(response.replay_status, ReplayStatusV1::Created);
    assert_eq!(service.blobs().recording.calls(), vec!["put_blob"]);
    assert_eq!(service.database().recording.calls(), vec!["record_check"]);
}

#[test]
fn save_and_delete_use_resumable_database_secret_database_order() {
    let (save, delete, credential_id) = plans();
    let recording = Recording::default();
    let service = ApplicationService::new(
        Database::with_recording(recording.clone(), save, delete),
        Blobs::default(),
        Credentials::working_with(recording.clone()),
    );

    service.save_credential_v1(save_request()).unwrap();
    assert_eq!(
        recording.calls(),
        vec!["reserve_save", "put_secret", "activate"]
    );

    service
        .delete_credential_v1(DeleteCredentialV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            credential_id,
        })
        .unwrap();
    assert_eq!(
        recording.calls(),
        vec![
            "reserve_save",
            "put_secret",
            "activate",
            "prepare_delete",
            "delete_secret",
            "finish_delete"
        ]
    );
}

#[test]
fn validation_and_secret_store_failure_stop_later_effects() {
    let (save, delete, _) = plans();
    let service = ApplicationService::new(
        Database::new(save, delete),
        Blobs::default(),
        Credentials {
            recording: Recording::default(),
            put_error: Some(PortError::new(PortErrorKind::PermissionDenied)),
        },
    );
    let mut invalid = save_request();
    invalid.display_label = " ".to_owned();

    let invalid_error = service.save_credential_v1(invalid).unwrap_err();
    assert_eq!(invalid_error.field, Some(SafeFieldV1::DisplayLabel));
    assert!(service.database().recording.calls().is_empty());
    assert!(service.credentials().recording.calls().is_empty());

    let keychain_error = service.save_credential_v1(save_request()).unwrap_err();
    assert_eq!(keychain_error.code, ErrorCodeV1::PermissionDenied);
    assert_eq!(keychain_error.user_action, UserActionKeyV1::UnlockKeychain);
    assert_eq!(service.database().recording.calls(), vec!["reserve_save"]);
    assert_eq!(service.credentials().recording.calls(), vec!["put_secret"]);
}

#[test]
fn generic_gmail_secret_is_rejected_before_database_or_keychain_writes() {
    let (save, delete, _) = plans();
    let service = ApplicationService::new(
        Database::new(save, delete),
        Blobs::default(),
        Credentials::working(),
    );
    let request: SaveCredentialV1Request = serde_json::from_str(&format!(
        r#"{{"schema_version":1,"request_id":"{}","provider":"gmail","display_label":"Gmail","secret":"raw-gmail-secret"}}"#,
        RequestId::new_v4()
    ))
    .unwrap();

    let error = service.save_credential_v1(request).unwrap_err();

    assert_eq!(error.field, Some(SafeFieldV1::Provider));
    assert!(service.database().recording.calls().is_empty());
    assert!(service.credentials().recording.calls().is_empty());
}

#[test]
fn replay_does_not_touch_secret_store() {
    let credential_id = CredentialId::new_v4();
    let service = ApplicationService::new(
        Database::new(
            SaveCredentialPlanV1::Replay {
                reference: reference(credential_id, CredentialStatusV1::Active),
            },
            DeleteCredentialPlanV1::Replay {
                credential_id,
                deleted: true,
            },
        ),
        Blobs::default(),
        Credentials::working(),
    );

    let save = service.save_credential_v1(save_request()).unwrap();
    let delete = service
        .delete_credential_v1(DeleteCredentialV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            credential_id,
        })
        .unwrap();

    assert_eq!(save.replay_status, ReplayStatusV1::Replayed);
    assert_eq!(delete.replay_status, ReplayStatusV1::Replayed);
    assert!(service.credentials().recording.calls().is_empty());
}

#[test]
fn changed_idempotency_envelope_is_a_non_retryable_conflict() {
    let (save, delete, _) = plans();
    let service = ApplicationService::new(
        Database::with_save_error(save, delete, PortError::new(PortErrorKind::Conflict)),
        Blobs::default(),
        Credentials::working(),
    );

    let error = service.save_credential_v1(save_request()).unwrap_err();

    assert_eq!(error.code, ErrorCodeV1::RequestConflict);
    assert!(!error.retryable);
    assert_eq!(error.user_action, UserActionKeyV1::StartNewRequest);
    assert_eq!(service.database().recording.calls(), vec!["reserve_save"]);
    assert!(service.credentials().recording.calls().is_empty());
}
