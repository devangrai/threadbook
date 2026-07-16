use crate::backup_repository::format_timestamp;
use crate::{
    BlobRecord, BlobStore, Database, MaintenanceCoordinator, PlatformError, PlatformResult,
};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;
use uuid::Uuid;
use wardrobe_core::{
    ConfigurePhotoKitScopeV1Request, ConfigurePhotoKitScopeV1Response, DisablePhotoKitV1Request,
    DisablePhotoKitV1Response, OperationId, PhotoKitAssetCountsV1, PhotoKitAuthorizationV1,
    PhotoKitAvailabilityCountV1, PhotoKitAvailabilityReasonV1, PhotoKitAvailabilityV1,
    PhotoKitConnectorSnapshotV1, PhotoKitConnectorStateV1, PhotoKitEnrollmentEpochV1,
    PhotoKitMembershipGenerationV1, PhotoKitReconcileTriggerV1, PhotoKitRevisionV1, ReplayStatusV1,
    Validate, SCHEMA_VERSION_V1,
};
use zeroize::{Zeroize, Zeroizing};

pub const PHOTOKIT_ENROLLMENT_TARGET_KIND: &str = "photokit_enrollment";
pub const PHOTOKIT_ASSET_TARGET_KIND: &str = "photokit_asset";
pub const PHOTOKIT_FINAL_KEY_CLEANUP_TABLE: &str = "photokit_key_cleanup_intents";
pub const PHOTOKIT_BLOB_OWNER_TABLE: &str = "photokit_materializations";
pub const PHOTOKIT_BLOB_OWNER_COLUMN: &str = "blob_sha256";
pub const PHOTOKIT_BLOB_OWNER_KEY_EXPRESSION: &str = "json_array(materialization_id)";
pub const CONFIGURE_PHOTOKIT_COMMAND: &str = "configure_photokit_scope_v1";
pub const SYNC_PHOTOKIT_COMMAND: &str = "sync_photokit_v1";
pub const DISABLE_PHOTOKIT_COMMAND: &str = "disable_photokit_v1";
pub const PHOTOKIT_RESTORE_PROVISIONAL_TABLES: &[&str] = &[
    "photokit_materialization_attempts",
    "photokit_operation_observations",
    "photokit_locator_records",
];
pub const PHOTOKIT_SCHEMA_TABLES: &[&str] = &[
    "photokit_enrollments",
    "photokit_connector_state",
    "photokit_locator_records",
    "photokit_assets",
    "photokit_operations",
    "photokit_operation_observations",
    "photokit_materialization_attempts",
    "photokit_membership_generations",
    "photokit_materializations",
    "photokit_availability_revisions",
    "photokit_availability_heads",
    "photokit_generation_members",
    "photokit_command_receipts",
    "photokit_key_cleanup_intents",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhotoKitDeletionSchemaEntry {
    pub table: &'static str,
    pub key_expression: &'static str,
    pub delete_rank: i64,
}

pub const PHOTOKIT_DELETION_SCHEMA: &[PhotoKitDeletionSchemaEntry] = &[
    PhotoKitDeletionSchemaEntry {
        table: "photokit_command_receipts",
        key_expression: "json_array(request_id)",
        delete_rank: 10,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_availability_heads",
        key_expression: "json_array(asset_id)",
        delete_rank: 10,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_generation_members",
        key_expression: "json_array(enrollment_epoch,membership_generation,ordinal)",
        delete_rank: 15,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_materialization_attempts",
        key_expression: "json_array(attempt_id)",
        delete_rank: 20,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_availability_revisions",
        key_expression: "json_array(revision_id)",
        delete_rank: 25,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_materializations",
        key_expression: "json_array(materialization_id)",
        delete_rank: 30,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_operation_observations",
        key_expression: "json_array(operation_id,ordinal)",
        delete_rank: 35,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_membership_generations",
        key_expression: "json_array(enrollment_epoch,membership_generation)",
        delete_rank: 40,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_assets",
        key_expression: "json_array(asset_id)",
        delete_rank: 45,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_locator_records",
        key_expression: "json_array(locator_id)",
        delete_rank: 50,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_operations",
        key_expression: "json_array(operation_id)",
        delete_rank: 55,
    },
    PhotoKitDeletionSchemaEntry {
        table: "photokit_enrollments",
        key_expression: "json_array(enrollment_epoch)",
        delete_rank: 60,
    },
];

const LOCATOR_KEY_VERSION: i64 = 1;
const LOCATOR_AEAD_INFO: &[u8] = b"locator-aead-v1";
const LOCATOR_LOOKUP_INFO: &[u8] = b"locator-lookup-v1";
const LOCATOR_HKDF_SALT: &[u8] = b"wardrobe-photokit-locator-root-v1";
const MAX_LOCATOR_BYTES: usize = 1024;
const SELECTION_POLICY_REVISION: &str = "original-primary-v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhotoKitKeyError {
    NotFound,
    Locked,
    Unavailable,
    Integrity,
    Internal,
}

pub struct PhotoKitRootKey(Zeroizing<[u8; 32]>);

impl PhotoKitRootKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn generate() -> Result<Self, PhotoKitKeyError> {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| PhotoKitKeyError::Unavailable)?;
        Ok(Self::from_bytes(bytes))
    }

    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for PhotoKitRootKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PhotoKitRootKey([REDACTED])")
    }
}

pub trait PhotoKitKeyPort: Send + Sync {
    fn create_root_key(&self, key_reference: &str) -> Result<PhotoKitRootKey, PhotoKitKeyError>;

    fn load_root_key(
        &self,
        key_reference: &str,
        allow_authentication_ui: bool,
    ) -> Result<PhotoKitRootKey, PhotoKitKeyError>;

    fn delete_root_key(&self, key_reference: &str) -> Result<(), PhotoKitKeyError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedPhotoKitLocator {
    pub lookup_hmac: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhotoKitEnrollment {
    pub enrollment_epoch: String,
    pub key_reference: String,
    pub allow_icloud_downloads: bool,
    pub operation_fence: u64,
    pub membership_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhotoKitKeyCleanupIntent {
    pub intent_id: String,
    pub key_reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhotoKitOperation {
    pub operation_id: String,
    pub request_id: String,
    pub enrollment_epoch: String,
    pub store_authority_epoch: String,
    pub reconciliation_fence: u64,
    pub proposed_membership_generation: u64,
    pub trigger: PhotoKitReconcileTriggerV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhotoKitRecordedObservation {
    pub ordinal: u16,
    pub asset_id: String,
    pub locator_id: String,
    pub resource_uti: Option<String>,
    pub supported: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhotoKitMaterializationRecord {
    pub resource_fingerprint: String,
    pub blob: BlobRecord,
    pub resource_uti: String,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhotoKitFinalizedObservation {
    pub ordinal: u16,
    pub availability: PhotoKitAvailabilityV1,
    pub reason: PhotoKitAvailabilityReasonV1,
    pub materialization: Option<PhotoKitMaterializationRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PhotoKitPublication {
    pub operation_id: String,
    pub reconciliation_fence: u64,
    pub membership_generation: Option<u64>,
    pub transitions: u16,
    pub replayed: bool,
    pub snapshot: PhotoKitConnectorSnapshotV1,
}

#[derive(Clone, Debug)]
pub struct PhotoKitRepository {
    database: Database,
}

impl PhotoKitRepository {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub fn database(&self) -> &Database {
        &self.database
    }

    pub fn reserve_enrollment(
        &self,
        key_reference: &str,
        allow_icloud_downloads: bool,
        now_ms: i64,
    ) -> PlatformResult<PhotoKitEnrollment> {
        validate_key_reference(key_reference)?;
        let enrollment_epoch = Uuid::new_v4().hyphenated().to_string();
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO photokit_enrollments(
                enrollment_epoch, key_reference, state, allow_icloud_downloads,
                operation_fence, active_membership_generation, created_at_ms
             ) VALUES (?1, ?2, 'pending', ?3, 0, NULL, ?4)",
            params![
                enrollment_epoch,
                key_reference,
                i64::from(allow_icloud_downloads),
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok(PhotoKitEnrollment {
            enrollment_epoch,
            key_reference: key_reference.to_owned(),
            allow_icloud_downloads,
            operation_fence: 0,
            membership_generation: None,
        })
    }

    pub fn remove_pending_enrollment(
        &self,
        enrollment_epoch: &str,
        now_ms: i64,
        cleanup_reason: &str,
    ) -> PlatformResult<()> {
        validate_uuid(enrollment_epoch, "photokit_enrollment_epoch")?;
        if !matches!(
            cleanup_reason,
            "pending_enrollment_recovery" | "incomplete_enrollment_restore"
        ) {
            return Err(PlatformError::InvalidInput("photokit_cleanup_reason"));
        }
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let key_reference = transaction
            .query_row(
                "SELECT key_reference FROM photokit_enrollments
                 WHERE enrollment_epoch = ?1 AND state = 'pending'",
                [enrollment_epoch],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(key_reference) = key_reference {
            transaction.execute(
                "INSERT OR IGNORE INTO photokit_key_cleanup_intents(
                    intent_id, deletion_run_id, enrollment_epoch, key_reference,
                    reason, state, created_at_ms
                 ) VALUES (?1, NULL, ?2, ?3, ?4, 'pending', ?5)",
                params![
                    Uuid::new_v4().hyphenated().to_string(),
                    enrollment_epoch,
                    key_reference,
                    cleanup_reason,
                    now_ms
                ],
            )?;
            transaction.execute(
                "DELETE FROM photokit_locator_records
                 WHERE enrollment_epoch = ?1 AND finalized = 0",
                [enrollment_epoch],
            )?;
            transaction.execute(
                "DELETE FROM photokit_enrollments
                 WHERE enrollment_epoch = ?1 AND state = 'pending'",
                [enrollment_epoch],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_key_cleanup_complete(
        &self,
        key_reference: &str,
        now_ms: i64,
    ) -> PlatformResult<()> {
        validate_key_reference(key_reference)?;
        self.database.connection()?.execute(
            "UPDATE photokit_key_cleanup_intents
             SET state = 'complete', failure_code = NULL,
                 last_attempt_at_ms = ?2, completed_at_ms = ?2
             WHERE key_reference = ?1 AND state = 'pending'",
            params![key_reference, now_ms],
        )?;
        Ok(())
    }

    pub fn activate_enrollment(
        &self,
        enrollment_epoch: &str,
        root_key: &PhotoKitRootKey,
        album_locator: &str,
        now_ms: i64,
    ) -> PlatformResult<PhotoKitEnrollment> {
        validate_uuid(enrollment_epoch, "photokit_enrollment_epoch")?;
        let protected = protect_locator(
            root_key,
            enrollment_epoch,
            "album",
            enrollment_epoch,
            album_locator.as_bytes(),
        )?;
        let locator_id = Uuid::new_v4().hyphenated().to_string();
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let enrollment = activate_enrollment_in_transaction(
            &transaction,
            enrollment_epoch,
            &locator_id,
            &protected,
            now_ms,
        )?;
        transaction.commit()?;
        Ok(enrollment)
    }

    pub fn activate_enrollment_command(
        &self,
        enrollment_epoch: &str,
        root_key: &PhotoKitRootKey,
        album_locator: &str,
        request: &ConfigurePhotoKitScopeV1Request,
        envelope_hash: &str,
        now_ms: i64,
    ) -> PlatformResult<ConfigurePhotoKitScopeV1Response> {
        validate_uuid(enrollment_epoch, "photokit_enrollment_epoch")?;
        validate_envelope_hash(envelope_hash)?;
        let protected = protect_locator(
            root_key,
            enrollment_epoch,
            "album",
            enrollment_epoch,
            album_locator.as_bytes(),
        )?;
        let locator_id = Uuid::new_v4().hyphenated().to_string();
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let enrollment = activate_enrollment_in_transaction(
            &transaction,
            enrollment_epoch,
            &locator_id,
            &protected,
            now_ms,
        )?;
        let snapshot = snapshot_in_transaction(&transaction, PhotoKitAuthorizationV1::Authorized)?;
        let response = ConfigurePhotoKitScopeV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            snapshot,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("photokit_configure_response"))?;
        insert_command_receipt(
            &transaction,
            &request.request_id.to_string(),
            CONFIGURE_PHOTOKIT_COMMAND,
            envelope_hash,
            Some(&enrollment.enrollment_epoch),
            None,
            &response,
            now_ms,
        )?;
        transaction.commit()?;
        Ok(response)
    }

    pub fn active_enrollment(&self) -> PlatformResult<Option<PhotoKitEnrollment>> {
        let connection = self.database.connection()?;
        connection
            .query_row(
                "SELECT enrollment.enrollment_epoch, enrollment.key_reference,
                        enrollment.allow_icloud_downloads,
                        enrollment.operation_fence,
                        enrollment.active_membership_generation
                 FROM photokit_connector_state state
                 JOIN photokit_enrollments enrollment
                   ON enrollment.enrollment_epoch = state.active_enrollment_epoch
                 WHERE state.singleton = 1 AND enrollment.state = 'active'",
                [],
                |row| {
                    Ok(PhotoKitEnrollment {
                        enrollment_epoch: row.get(0)?,
                        key_reference: row.get(1)?,
                        allow_icloud_downloads: row.get::<_, i64>(2)? != 0,
                        operation_fence: row.get::<_, i64>(3)? as u64,
                        membership_generation: row
                            .get::<_, Option<i64>>(4)?
                            .map(|value| value as u64),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn decrypt_album_locator(
        &self,
        enrollment_epoch: &str,
        root_key: &PhotoKitRootKey,
    ) -> PlatformResult<String> {
        let row = self
            .database
            .connection()?
            .query_row(
                "SELECT stable_row_id, lookup_hmac, nonce, ciphertext
                 FROM photokit_locator_records
                 WHERE enrollment_epoch = ?1 AND record_kind = 'album'
                   AND finalized = 1",
                [enrollment_epoch],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::Corrupt("photokit_album_locator_missing"))?;
        let plaintext = decrypt_locator(
            root_key,
            enrollment_epoch,
            "album",
            &row.0,
            &row.1,
            &row.2,
            &row.3,
        )?;
        String::from_utf8(plaintext)
            .map_err(|_| PlatformError::Corrupt("photokit_album_locator_encoding"))
    }

    pub fn begin_operation(
        &self,
        request_id: &str,
        trigger: PhotoKitReconcileTriggerV1,
        authorization: PhotoKitAuthorizationV1,
        now_ms: i64,
    ) -> PlatformResult<(PhotoKitOperation, bool)> {
        validate_uuid(request_id, "photokit_request_id")?;
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(operation) = operation_by_request(&transaction, request_id)? {
            if operation.trigger != trigger {
                return Err(PlatformError::Conflict("photokit_request_reused"));
            }
            transaction.commit()?;
            return Ok((operation, true));
        }
        let (enrollment_epoch, current_fence): (String, i64) = transaction
            .query_row(
                "SELECT enrollment.enrollment_epoch, enrollment.operation_fence
                     FROM photokit_connector_state state
                     JOIN photokit_enrollments enrollment
                       ON enrollment.enrollment_epoch = state.active_enrollment_epoch
                     WHERE state.singleton = 1 AND enrollment.state = 'active'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(PlatformError::Conflict("photokit_not_configured"))?;
        let fence = current_fence
            .checked_add(1)
            .ok_or(PlatformError::Corrupt("photokit_fence"))?;
        let proposed_generation = next_membership_generation(&transaction, &enrollment_epoch)?;
        let store_authority_epoch: String = transaction.query_row(
            "SELECT epoch FROM store_authority_epoch WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let operation_id = Uuid::new_v4().hyphenated().to_string();
        transaction.execute(
            "UPDATE photokit_enrollments SET operation_fence = ?2
             WHERE enrollment_epoch = ?1 AND state = 'active'",
            params![enrollment_epoch, fence],
        )?;
        transaction.execute(
            "INSERT INTO photokit_operations(
                operation_id, request_id, enrollment_epoch,
                store_authority_epoch, reconciliation_fence,
                proposed_membership_generation, trigger_kind, state,
                started_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'enumerating', ?8)",
            params![
                operation_id,
                request_id,
                enrollment_epoch,
                store_authority_epoch,
                fence,
                proposed_generation,
                trigger_to_db(trigger),
                now_ms
            ],
        )?;
        transaction.execute(
            "UPDATE photokit_connector_state
             SET state = 'reconciling', authorization = ?1, updated_at_ms = ?2
             WHERE singleton = 1",
            params![authorization_to_db(authorization), now_ms],
        )?;
        transaction.commit()?;
        Ok((
            PhotoKitOperation {
                operation_id,
                request_id: request_id.to_owned(),
                enrollment_epoch,
                store_authority_epoch,
                reconciliation_fence: fence as u64,
                proposed_membership_generation: proposed_generation as u64,
                trigger,
            },
            false,
        ))
    }

    pub fn replay_publication(
        &self,
        request_id: &str,
        trigger: PhotoKitReconcileTriggerV1,
    ) -> PlatformResult<Option<PhotoKitPublication>> {
        validate_uuid(request_id, "photokit_request_id")?;
        let connection = self.database.connection()?;
        let row = connection
            .query_row(
                "SELECT operation_id, request_id, enrollment_epoch,
                        store_authority_epoch, reconciliation_fence,
                        proposed_membership_generation, trigger_kind,
                        state, terminal_publication_json
                 FROM photokit_operations WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok((
                        operation_from_row(row)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Option<String>>(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((operation, state, publication_json)) = row else {
            return Ok(None);
        };
        if operation.trigger != trigger {
            return Err(PlatformError::Conflict("photokit_request_reused"));
        }
        if !matches!(state.as_str(), "complete" | "failed") {
            return Err(PlatformError::Conflict("photokit_operation_not_replayable"));
        }
        let publication_json = publication_json.ok_or(PlatformError::Corrupt(
            "photokit_terminal_publication_missing",
        ))?;
        let mut publication: PhotoKitPublication = serde_json::from_str(&publication_json)?;
        validate_terminal_publication(&publication, &operation, &state)?;
        publication.replayed = true;
        Ok(Some(publication))
    }

    pub fn record_observation(
        &self,
        operation: &PhotoKitOperation,
        root_key: &PhotoKitRootKey,
        ordinal: u16,
        asset_locator: &str,
        resource_uti: Option<&str>,
        supported: bool,
        now_ms: i64,
    ) -> PlatformResult<PhotoKitRecordedObservation> {
        if ordinal >= 500 {
            return Err(PlatformError::InvalidInput("photokit_observation_ordinal"));
        }
        if let Some(uti) = resource_uti {
            validate_ascii(uti, 128, "photokit_resource_uti")?;
        }
        let lookup = locator_lookup(
            root_key,
            &operation.enrollment_epoch,
            "asset",
            asset_locator.as_bytes(),
        )?;
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_current_operation(&transaction, operation, "enumerating")?;
        let existing = transaction
            .query_row(
                "SELECT asset.asset_id, locator.locator_id
                 FROM photokit_locator_records locator
                 JOIN photokit_assets asset ON asset.locator_id = locator.locator_id
                 WHERE locator.enrollment_epoch = ?1
                   AND locator.record_kind = 'asset'
                   AND locator.lookup_hmac = ?2
                   AND locator.finalized = 1",
                params![operation.enrollment_epoch, lookup.as_slice()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let (asset_id, locator_id) = match existing {
            Some(value) => value,
            None => {
                let asset_id = Uuid::new_v4().hyphenated().to_string();
                let locator_id = Uuid::new_v4().hyphenated().to_string();
                let protected = protect_locator(
                    root_key,
                    &operation.enrollment_epoch,
                    "asset",
                    &asset_id,
                    asset_locator.as_bytes(),
                )?;
                if protected.lookup_hmac != lookup {
                    return Err(PlatformError::Corrupt("photokit_locator_lookup"));
                }
                transaction.execute(
                    "INSERT INTO photokit_locator_records(
                        locator_id, enrollment_epoch, operation_id, record_kind,
                        stable_row_id, key_version, lookup_hmac, nonce,
                        ciphertext, finalized, created_at_ms
                     ) VALUES (?1, ?2, ?3, 'asset', ?4, ?5, ?6, ?7, ?8, 0, ?9)",
                    params![
                        locator_id,
                        operation.enrollment_epoch,
                        operation.operation_id,
                        asset_id,
                        LOCATOR_KEY_VERSION,
                        protected.lookup_hmac.as_slice(),
                        protected.nonce.as_slice(),
                        protected.ciphertext,
                        now_ms
                    ],
                )?;
                (asset_id, locator_id)
            }
        };
        transaction.execute(
            "INSERT INTO photokit_operation_observations(
                operation_id, ordinal, asset_id, locator_id,
                resource_uti, resource_state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                operation.operation_id,
                i64::from(ordinal),
                asset_id,
                locator_id,
                resource_uti,
                if supported {
                    "supported"
                } else {
                    "unsupported"
                }
            ],
        )?;
        transaction.execute(
            "UPDATE photokit_operations SET observed_count = observed_count + 1
             WHERE operation_id = ?1",
            [&operation.operation_id],
        )?;
        transaction.commit()?;
        Ok(PhotoKitRecordedObservation {
            ordinal,
            asset_id,
            locator_id,
            resource_uti: resource_uti.map(str::to_owned),
            supported,
        })
    }

    pub fn mark_materializing(&self, operation: &PhotoKitOperation) -> PlatformResult<()> {
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_current_operation(&transaction, operation, "enumerating")?;
        let counts: (i64, i64) = transaction.query_row(
            "SELECT operation.observed_count, COUNT(observation.ordinal)
             FROM photokit_operations operation
             LEFT JOIN photokit_operation_observations observation
               ON observation.operation_id = operation.operation_id
             WHERE operation.operation_id = ?1
             GROUP BY operation.operation_id",
            [&operation.operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if counts.0 != counts.1 {
            return Err(PlatformError::Corrupt("photokit_observation_count"));
        }
        transaction.execute(
            "UPDATE photokit_operations SET state = 'materializing'
             WHERE operation_id = ?1 AND state = 'enumerating'",
            [&operation.operation_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn record_attempt(
        &self,
        operation: &PhotoKitOperation,
        ordinal: u16,
        attempt_ordinal: u8,
        network_access_allowed: bool,
        accepted_bytes: u64,
        result: &str,
        now_ms: i64,
    ) -> PlatformResult<()> {
        if attempt_ordinal > 1
            || accepted_bytes > 40 * 1024 * 1024
            || !matches!(
                result,
                "materialized"
                    | "network_access_required"
                    | "icloud_unavailable"
                    | "unsupported_resource"
                    | "transfer_failed"
                    | "blob_integrity_failed"
            )
        {
            return Err(PlatformError::InvalidInput("photokit_attempt"));
        }
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_current_operation(&transaction, operation, "materializing")?;
        transaction.execute(
            "INSERT INTO photokit_materialization_attempts(
                attempt_id, operation_id, observation_ordinal,
                attempt_ordinal, network_access_allowed, accepted_bytes,
                result, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                Uuid::new_v4().hyphenated().to_string(),
                operation.operation_id,
                i64::from(ordinal),
                i64::from(attempt_ordinal),
                i64::from(network_access_allowed),
                i64::try_from(accepted_bytes)
                    .map_err(|_| PlatformError::InvalidInput("photokit_attempt_bytes"))?,
                result,
                now_ms
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn fail_incomplete_operation(
        &self,
        operation: &PhotoKitOperation,
        now_ms: i64,
    ) -> PlatformResult<PhotoKitPublication> {
        self.finalize_global_unavailable(
            operation,
            PhotoKitAuthorizationV1::Authorized,
            None,
            "enumeration_incomplete",
            now_ms,
        )
    }

    pub fn finalize_global_unavailable(
        &self,
        operation: &PhotoKitOperation,
        authorization: PhotoKitAuthorizationV1,
        reason: Option<PhotoKitAvailabilityReasonV1>,
        terminal_reason: &str,
        now_ms: i64,
    ) -> PlatformResult<PhotoKitPublication> {
        validate_terminal_reason(terminal_reason)?;
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: String = transaction.query_row(
            "SELECT state FROM photokit_operations WHERE operation_id = ?1",
            [&operation.operation_id],
            |row| row.get(0),
        )?;
        if matches!(state.as_str(), "complete" | "failed") {
            let publication = terminal_publication_in_transaction(&transaction, operation)?;
            transaction.commit()?;
            return Ok(publication);
        }
        if matches!(state.as_str(), "interrupted" | "stale") {
            return Err(PlatformError::Conflict("photokit_operation_not_replayable"));
        }
        ensure_current_operation_any(&transaction, operation)?;
        let mut transitions = 0_u16;
        if let Some(reason) = reason {
            let asset_ids = availability_head_assets(&transaction, &operation.enrollment_epoch)?;
            for asset_id in asset_ids {
                let (_, changed) = transition_head(
                    &transaction,
                    &asset_id,
                    &operation.enrollment_epoch,
                    &operation.operation_id,
                    None,
                    PhotoKitAvailabilityV1::Unavailable,
                    reason,
                    None,
                    now_ms,
                )?;
                transitions = transitions
                    .checked_add(u16::from(changed))
                    .ok_or(PlatformError::Corrupt("photokit_transition_count"))?;
            }
            if transitions > 0 {
                increment_photokit_revision(&transaction)?;
            }
            let active_generation: Option<i64> = transaction.query_row(
                "SELECT active_membership_generation
                 FROM photokit_enrollments
                 WHERE enrollment_epoch = ?1",
                [&operation.enrollment_epoch],
                |row| row.get(0),
            )?;
            let (observed, available, unavailable) = if active_generation.is_some() {
                availability_head_counts(&transaction, &operation.enrollment_epoch)?
            } else {
                (0, 0, 0)
            };
            transaction.execute(
                "UPDATE photokit_connector_state
                 SET state = 'needs_attention', authorization = ?1,
                     observed_count = ?2, available_count = ?3,
                     unavailable_count = ?4, updated_at_ms = ?5
                 WHERE singleton = 1
                   AND active_enrollment_epoch = ?6",
                params![
                    authorization_to_db(authorization),
                    observed,
                    available,
                    unavailable,
                    now_ms,
                    operation.enrollment_epoch
                ],
            )?;
        } else {
            transaction.execute(
                "UPDATE photokit_connector_state
                 SET state = 'ready', authorization = ?1, updated_at_ms = ?2
                 WHERE singleton = 1
                   AND active_enrollment_epoch = ?3",
                params![
                    authorization_to_db(authorization),
                    now_ms,
                    operation.enrollment_epoch
                ],
            )?;
        }
        let snapshot = snapshot_in_transaction(&transaction, authorization)?;
        let publication = PhotoKitPublication {
            operation_id: operation.operation_id.clone(),
            reconciliation_fence: operation.reconciliation_fence,
            membership_generation: snapshot.membership_generation.map(|value| value.get()),
            transitions,
            replayed: false,
            snapshot,
        };
        let publication_json = serialize_terminal_publication(&publication, operation, "failed")?;
        let changed = transaction.execute(
            "UPDATE photokit_operations
             SET state = 'failed', terminal_reason = ?2, finished_at_ms = ?3,
                 terminal_publication_json = ?4
             WHERE operation_id = ?1
               AND state IN ('enumerating', 'materializing')
               AND terminal_publication_json IS NULL",
            params![
                operation.operation_id,
                terminal_reason,
                now_ms,
                publication_json
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict(
                "photokit_terminal_publication_exists",
            ));
        }
        cleanup_provisional_operation(&transaction, &operation.operation_id)?;
        transaction.commit()?;
        Ok(publication)
    }

    pub fn finalize_complete(
        &self,
        operation: &PhotoKitOperation,
        authorization: PhotoKitAuthorizationV1,
        observations: &[PhotoKitFinalizedObservation],
        now_ms: i64,
    ) -> PlatformResult<PhotoKitPublication> {
        if observations.len() > 500 {
            return Err(PlatformError::InvalidInput("photokit_observations"));
        }
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: String = transaction.query_row(
            "SELECT state FROM photokit_operations WHERE operation_id = ?1",
            [&operation.operation_id],
            |row| row.get(0),
        )?;
        if state == "complete" {
            let publication = terminal_publication_in_transaction(&transaction, operation)?;
            transaction.commit()?;
            return Ok(publication);
        }
        if matches!(state.as_str(), "failed" | "interrupted" | "stale") {
            return Err(PlatformError::Conflict("photokit_operation_not_replayable"));
        }
        ensure_current_operation(&transaction, operation, "materializing")?;
        let rows = load_operation_observations(&transaction, &operation.operation_id)?;
        if rows.len() != observations.len()
            || rows
                .iter()
                .zip(observations)
                .any(|(stored, result)| stored.ordinal != result.ordinal)
        {
            return Err(PlatformError::Conflict("photokit_enumeration_incomplete"));
        }
        let available_count = observations
            .iter()
            .filter(|item| item.availability == PhotoKitAvailabilityV1::Available)
            .count();
        let unavailable_count = observations.len() - available_count;
        transaction.execute(
            "INSERT INTO photokit_membership_generations(
                enrollment_epoch, membership_generation, operation_id,
                observed_count, available_count, unavailable_count,
                completed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                operation.enrollment_epoch,
                i64::try_from(operation.proposed_membership_generation)
                    .map_err(|_| PlatformError::Corrupt("photokit_generation"))?,
                operation.operation_id,
                observations.len() as i64,
                available_count as i64,
                unavailable_count as i64,
                now_ms
            ],
        )?;

        let mut transitions = 0_u16;
        let mut observed_assets = Vec::with_capacity(rows.len());
        for (stored, result) in rows.iter().zip(observations) {
            validate_availability_result(result)?;
            transaction.execute(
                "UPDATE photokit_locator_records SET finalized = 1
                 WHERE locator_id = ?1 AND finalized = 0",
                [&stored.locator_id],
            )?;
            transaction.execute(
                "INSERT OR IGNORE INTO photokit_assets(
                    asset_id, enrollment_epoch, locator_id, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    stored.asset_id,
                    operation.enrollment_epoch,
                    stored.locator_id,
                    now_ms
                ],
            )?;
            verify_asset_identity(
                &transaction,
                &stored.asset_id,
                &operation.enrollment_epoch,
                &stored.locator_id,
            )?;
            let materialization_id = match &result.materialization {
                Some(materialization) => Some(insert_materialization(
                    &transaction,
                    &stored.asset_id,
                    &operation.operation_id,
                    materialization,
                    now_ms,
                )?),
                None => None,
            };
            let (revision_id, changed) = transition_head(
                &transaction,
                &stored.asset_id,
                &operation.enrollment_epoch,
                &operation.operation_id,
                Some(operation.proposed_membership_generation),
                result.availability,
                result.reason,
                materialization_id.as_deref(),
                now_ms,
            )?;
            transitions = transitions
                .checked_add(u16::from(changed))
                .ok_or(PlatformError::Corrupt("photokit_transition_count"))?;
            transaction.execute(
                "INSERT INTO photokit_generation_members(
                    enrollment_epoch, membership_generation, ordinal,
                    asset_id, revision_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    operation.enrollment_epoch,
                    i64::try_from(operation.proposed_membership_generation)
                        .map_err(|_| PlatformError::Corrupt("photokit_generation"))?,
                    i64::from(result.ordinal),
                    stored.asset_id,
                    revision_id
                ],
            )?;
            observed_assets.push(stored.asset_id.clone());
        }

        for asset_id in prior_active_assets_not_observed(
            &transaction,
            &operation.enrollment_epoch,
            &observed_assets,
        )? {
            let (_, changed) = transition_head(
                &transaction,
                &asset_id,
                &operation.enrollment_epoch,
                &operation.operation_id,
                Some(operation.proposed_membership_generation),
                PhotoKitAvailabilityV1::Unavailable,
                PhotoKitAvailabilityReasonV1::AssetNotInScope,
                None,
                now_ms,
            )?;
            transitions = transitions
                .checked_add(u16::from(changed))
                .ok_or(PlatformError::Corrupt("photokit_transition_count"))?;
        }
        let (connector_observed_count, connector_available_count, connector_unavailable_count) =
            availability_head_counts(&transaction, &operation.enrollment_epoch)?;
        increment_photokit_revision(&transaction)?;
        transaction.execute(
            "UPDATE photokit_enrollments
             SET active_membership_generation = ?2
             WHERE enrollment_epoch = ?1 AND state = 'active'",
            params![
                operation.enrollment_epoch,
                i64::try_from(operation.proposed_membership_generation)
                    .map_err(|_| PlatformError::Corrupt("photokit_generation"))?
            ],
        )?;
        transaction.execute(
            "UPDATE photokit_connector_state
             SET state = 'ready', authorization = ?1,
                 active_membership_generation = ?2,
                 observed_count = ?3, available_count = ?4,
                 unavailable_count = ?5, last_complete_at_ms = ?6,
                 updated_at_ms = ?6
             WHERE singleton = 1 AND active_enrollment_epoch = ?7",
            params![
                authorization_to_db(authorization),
                i64::try_from(operation.proposed_membership_generation)
                    .map_err(|_| PlatformError::Corrupt("photokit_generation"))?,
                connector_observed_count,
                connector_available_count,
                connector_unavailable_count,
                now_ms,
                operation.enrollment_epoch
            ],
        )?;
        let snapshot = snapshot_in_transaction(&transaction, authorization)?;
        let publication = PhotoKitPublication {
            operation_id: operation.operation_id.clone(),
            reconciliation_fence: operation.reconciliation_fence,
            membership_generation: Some(operation.proposed_membership_generation),
            transitions,
            replayed: false,
            snapshot,
        };
        let publication_json = serialize_terminal_publication(&publication, operation, "complete")?;
        let changed = transaction.execute(
            "UPDATE photokit_operations
             SET state = 'complete', terminal_reason = NULL,
                 accepted_bytes = ?2, finished_at_ms = ?3,
                 terminal_publication_json = ?4
             WHERE operation_id = ?1 AND state = 'materializing'
               AND terminal_publication_json IS NULL",
            params![
                operation.operation_id,
                observations.iter().try_fold(0_i64, |total, item| {
                    let bytes = item
                        .materialization
                        .as_ref()
                        .map(|value| value.blob.byte_length)
                        .unwrap_or(0);
                    total
                        .checked_add(
                            i64::try_from(bytes)
                                .map_err(|_| PlatformError::Corrupt("photokit_accepted_bytes"))?,
                        )
                        .ok_or(PlatformError::Corrupt("photokit_accepted_bytes"))
                })?,
                now_ms,
                publication_json
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict(
                "photokit_terminal_publication_exists",
            ));
        }
        transaction.commit()?;
        Ok(publication)
    }

    pub fn snapshot(
        &self,
        authorization: PhotoKitAuthorizationV1,
    ) -> PlatformResult<PhotoKitConnectorSnapshotV1> {
        snapshot_in_connection(&self.database.connection()?, authorization)
    }

    pub fn replay_command_receipt<T: DeserializeOwned>(
        &self,
        request_id: &str,
        command_name: &str,
        envelope_hash: &str,
    ) -> PlatformResult<Option<T>> {
        validate_uuid(request_id, "photokit_request_id")?;
        validate_command_name(command_name)?;
        validate_envelope_hash(envelope_hash)?;
        replay_command_receipt_in_connection(
            &self.database.connection()?,
            request_id,
            command_name,
            envelope_hash,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_command_receipt<T: DeserializeOwned + Serialize>(
        &self,
        request_id: &str,
        command_name: &str,
        envelope_hash: &str,
        enrollment_epoch: Option<&str>,
        operation_id: Option<&str>,
        response: &T,
        now_ms: i64,
    ) -> PlatformResult<T> {
        validate_uuid(request_id, "photokit_request_id")?;
        validate_command_name(command_name)?;
        validate_envelope_hash(envelope_hash)?;
        if let Some(value) = enrollment_epoch {
            validate_uuid(value, "photokit_enrollment_epoch")?;
        }
        if let Some(value) = operation_id {
            validate_uuid(value, "photokit_operation_id")?;
        }
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(stored) = replay_command_receipt_in_connection(
            &transaction,
            request_id,
            command_name,
            envelope_hash,
        )? {
            transaction.commit()?;
            return Ok(stored);
        }
        insert_command_receipt(
            &transaction,
            request_id,
            command_name,
            envelope_hash,
            enrollment_epoch,
            operation_id,
            response,
            now_ms,
        )?;
        transaction.commit()?;
        serde_json::from_slice(&serde_json::to_vec(response)?).map_err(Into::into)
    }

    pub fn disable_command(
        &self,
        request: &DisablePhotoKitV1Request,
        envelope_hash: &str,
        now_ms: i64,
    ) -> PlatformResult<DisablePhotoKitV1Response> {
        validate_envelope_hash(envelope_hash)?;
        let request_id = request.request_id.to_string();
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) = replay_command_receipt_in_connection::<DisablePhotoKitV1Response>(
            &transaction,
            &request_id,
            DISABLE_PHOTOKIT_COMMAND,
            envelope_hash,
        )? {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }

        let revision: i64 = transaction.query_row(
            "SELECT photokit_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if revision as u64 != request.expected_photokit_revision.get() {
            return Err(PlatformError::Conflict("photokit_revision_changed"));
        }
        let (enrollment_epoch, generation, observed, available, unavailable): (
            String,
            Option<i64>,
            i64,
            i64,
            i64,
        ) = transaction
            .query_row(
                "SELECT active_enrollment_epoch, active_membership_generation,
                        observed_count, available_count, unavailable_count
                 FROM photokit_connector_state
                 WHERE singleton = 1 AND active_enrollment_epoch IS NOT NULL",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::Conflict("photokit_not_configured"))?;

        inactivate_enrollment(&transaction, &enrollment_epoch, now_ms)?;
        let after_inactivation: i64 = transaction.query_row(
            "SELECT photokit_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if after_inactivation == revision {
            increment_photokit_revision(&transaction)?;
        }
        transaction.execute(
            "UPDATE photokit_connector_state
             SET state = 'unconfigured', active_enrollment_epoch = NULL,
                 active_membership_generation = NULL,
                 observed_count = 0, available_count = 0,
                 unavailable_count = 0, last_complete_at_ms = NULL,
                 updated_at_ms = ?1
             WHERE singleton = 1",
            [now_ms],
        )?;
        let next_revision: i64 = transaction.query_row(
            "SELECT photokit_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let response = DisablePhotoKitV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            state: PhotoKitConnectorStateV1::Unconfigured,
            disabled_enrollment_epoch: PhotoKitEnrollmentEpochV1::new(
                Uuid::parse_str(&enrollment_epoch)
                    .map_err(|_| PlatformError::Corrupt("photokit_enrollment_epoch"))?,
            )
            .map_err(|_| PlatformError::Corrupt("photokit_enrollment_epoch"))?,
            preserved_membership_generation: generation
                .map(|value| {
                    PhotoKitMembershipGenerationV1::new(value as u64)
                        .map_err(|_| PlatformError::Corrupt("photokit_generation"))
                })
                .transpose()?,
            photokit_revision: PhotoKitRevisionV1::new(next_revision as u64)
                .map_err(|_| PlatformError::Corrupt("photokit_revision"))?,
            preserved_counts: PhotoKitAssetCountsV1 {
                observed: observed as u16,
                available: available as u16,
                unavailable: unavailable as u16,
            },
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("photokit_disable_response"))?;
        insert_command_receipt(
            &transaction,
            &request_id,
            DISABLE_PHOTOKIT_COMMAND,
            envelope_hash,
            Some(&enrollment_epoch),
            None,
            &response,
            now_ms,
        )?;
        transaction.commit()?;
        Ok(response)
    }

    pub fn recover_operations(&self, now_ms: i64) -> PlatformResult<usize> {
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation_ids = {
            let mut statement = transaction.prepare(
                "SELECT operation_id FROM photokit_operations
                 WHERE state IN ('enumerating', 'materializing')
                 ORDER BY started_at_ms, operation_id",
            )?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        for operation_id in &operation_ids {
            transaction.execute(
                "UPDATE photokit_operations
                 SET state = 'interrupted', terminal_reason = 'restore_interrupted',
                     finished_at_ms = ?2
                 WHERE operation_id = ?1
                   AND state IN ('enumerating', 'materializing')",
                params![operation_id, now_ms],
            )?;
            cleanup_provisional_operation(&transaction, operation_id)?;
        }
        transaction.execute(
            "UPDATE photokit_connector_state
             SET state = CASE
                    WHEN active_enrollment_epoch IS NULL THEN 'unconfigured'
                    ELSE 'ready'
                 END,
                 updated_at_ms = ?1
             WHERE state = 'reconciling'",
            [now_ms],
        )?;
        transaction.commit()?;
        Ok(operation_ids.len())
    }

    pub fn pending_enrollments(&self) -> PlatformResult<Vec<PhotoKitEnrollment>> {
        let connection = self.database.connection()?;
        let mut statement = connection.prepare(
            "SELECT enrollment_epoch, key_reference, allow_icloud_downloads,
                    operation_fence, active_membership_generation
             FROM photokit_enrollments
             WHERE state = 'pending'
             ORDER BY created_at_ms, enrollment_epoch",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(PhotoKitEnrollment {
                    enrollment_epoch: row.get(0)?,
                    key_reference: row.get(1)?,
                    allow_icloud_downloads: row.get::<_, i64>(2)? != 0,
                    operation_fence: row.get::<_, i64>(3)? as u64,
                    membership_generation: row.get::<_, Option<i64>>(4)?.map(|value| value as u64),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn pending_key_cleanup_intents(&self) -> PlatformResult<Vec<PhotoKitKeyCleanupIntent>> {
        let connection = self.database.connection()?;
        let mut statement = connection.prepare(
            "SELECT intent_id,key_reference
             FROM photokit_key_cleanup_intents
             WHERE state='pending'
             ORDER BY created_at_ms,intent_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(PhotoKitKeyCleanupIntent {
                    intent_id: row.get(0)?,
                    key_reference: row.get(1)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn complete_key_cleanup_intent(&self, intent_id: &str, now_ms: i64) -> PlatformResult<()> {
        validate_uuid(intent_id, "photokit_cleanup_intent")?;
        let changed = self.database.connection()?.execute(
            "UPDATE photokit_key_cleanup_intents
             SET state='complete',failure_code=NULL,last_attempt_at_ms=?2,
                 completed_at_ms=?2
             WHERE intent_id=?1 AND state='pending'",
            params![intent_id, now_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict("photokit_cleanup_intent_state"));
        }
        Ok(())
    }

    pub fn fail_key_cleanup_intent(
        &self,
        intent_id: &str,
        failure_code: &str,
        now_ms: i64,
    ) -> PlatformResult<()> {
        validate_uuid(intent_id, "photokit_cleanup_intent")?;
        if !matches!(failure_code, "locked" | "unavailable" | "internal") {
            return Err(PlatformError::InvalidInput("photokit_cleanup_failure_code"));
        }
        let changed = self.database.connection()?.execute(
            "UPDATE photokit_key_cleanup_intents
             SET failure_code=?2,last_attempt_at_ms=?3
             WHERE intent_id=?1 AND state='pending'",
            params![intent_id, failure_code, now_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict("photokit_cleanup_intent_state"));
        }
        Ok(())
    }

    pub fn collect_unowned_blob(
        &self,
        sha256: &str,
        minimum_age: Duration,
        now_ms: i64,
    ) -> PlatformResult<bool> {
        validate_hash(sha256)?;
        let _exclusive = MaintenanceCoordinator::global().acquire_exclusive()?;
        let mut connection = self.database.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let owned: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM blobs WHERE sha256 = ?1)",
            [sha256],
            |row| row.get(0),
        )?;
        if owned {
            transaction.commit()?;
            return Ok(false);
        }
        let store = BlobStore::new(&self.database.paths);
        let path = store.path_for_hash(sha256)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                transaction.commit()?;
                return Ok(false);
            }
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || store.verify(sha256)?.byte_length != metadata.len()
        {
            return Err(PlatformError::Corrupt("photokit_orphan_identity"));
        }
        let modified_ms = metadata
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| PlatformError::Corrupt("photokit_orphan_age"))?
            .as_millis();
        let modified_ms = i64::try_from(modified_ms)
            .map_err(|_| PlatformError::Corrupt("photokit_orphan_age"))?;
        let minimum_age_ms = i64::try_from(minimum_age.as_millis())
            .map_err(|_| PlatformError::InvalidInput("photokit_orphan_age"))?;
        if now_ms.saturating_sub(modified_ms) < minimum_age_ms {
            transaction.commit()?;
            return Ok(false);
        }
        fs::remove_file(&path)?;
        crate::blob::sync_directory(
            path.parent()
                .ok_or(PlatformError::Corrupt("blob_destination_parent"))?,
        )?;
        transaction.commit()?;
        Ok(true)
    }
}

#[derive(Clone, Debug)]
struct StoredObservation {
    ordinal: u16,
    asset_id: String,
    locator_id: String,
}

fn protect_locator(
    root_key: &PhotoKitRootKey,
    enrollment_epoch: &str,
    record_kind: &str,
    stable_row_id: &str,
    plaintext: &[u8],
) -> PlatformResult<ProtectedPhotoKitLocator> {
    if plaintext.is_empty() || plaintext.len() > MAX_LOCATOR_BYTES {
        return Err(PlatformError::InvalidInput("photokit_locator"));
    }
    let mut aead_key = hkdf_expand(root_key.expose(), LOCATOR_AEAD_INFO)?;
    let mut lookup_key = hkdf_expand(root_key.expose(), LOCATOR_LOOKUP_INFO)?;
    let lookup_hmac =
        locator_lookup_with_key(&lookup_key, enrollment_epoch, record_kind, plaintext)?;
    let mut nonce = [0_u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| PlatformError::Keychain("random_unavailable"))?;
    let aad = locator_aad(enrollment_epoch, record_kind, stable_row_id);
    let cipher = XChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|_| PlatformError::Corrupt("photokit_locator_key"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| PlatformError::Corrupt("photokit_locator_encrypt"))?;
    aead_key.zeroize();
    lookup_key.zeroize();
    Ok(ProtectedPhotoKitLocator {
        lookup_hmac,
        nonce,
        ciphertext,
    })
}

fn decrypt_locator(
    root_key: &PhotoKitRootKey,
    enrollment_epoch: &str,
    record_kind: &str,
    stable_row_id: &str,
    lookup_hmac: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> PlatformResult<Vec<u8>> {
    if lookup_hmac.len() != 32 || nonce.len() != 24 || ciphertext.len() < 17 {
        return Err(PlatformError::Corrupt("photokit_locator_record"));
    }
    let mut aead_key = hkdf_expand(root_key.expose(), LOCATOR_AEAD_INFO)?;
    let mut lookup_key = hkdf_expand(root_key.expose(), LOCATOR_LOOKUP_INFO)?;
    let aad = locator_aad(enrollment_epoch, record_kind, stable_row_id);
    let cipher = XChaCha20Poly1305::new_from_slice(&aead_key)
        .map_err(|_| PlatformError::Corrupt("photokit_locator_key"))?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| PlatformError::Corrupt("photokit_locator_decrypt"))?;
    let mut verifier = <HmacSha256 as Mac>::new_from_slice(&lookup_key)
        .map_err(|_| PlatformError::Corrupt("photokit_locator_key"))?;
    update_locator_lookup_mac(&mut verifier, enrollment_epoch, record_kind, &plaintext);
    verifier
        .verify_slice(lookup_hmac)
        .map_err(|_| PlatformError::Corrupt("photokit_locator_lookup"))?;
    aead_key.zeroize();
    lookup_key.zeroize();
    Ok(plaintext)
}

fn locator_lookup(
    root_key: &PhotoKitRootKey,
    enrollment_epoch: &str,
    record_kind: &str,
    plaintext: &[u8],
) -> PlatformResult<[u8; 32]> {
    let mut key = hkdf_expand(root_key.expose(), LOCATOR_LOOKUP_INFO)?;
    let result = locator_lookup_with_key(&key, enrollment_epoch, record_kind, plaintext);
    key.zeroize();
    result
}

fn locator_lookup_with_key(
    key: &[u8; 32],
    enrollment_epoch: &str,
    record_kind: &str,
    plaintext: &[u8],
) -> PlatformResult<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| PlatformError::Corrupt("photokit_locator_key"))?;
    update_locator_lookup_mac(&mut mac, enrollment_epoch, record_kind, plaintext);
    Ok(mac.finalize().into_bytes().into())
}

fn update_locator_lookup_mac(
    mac: &mut HmacSha256,
    enrollment_epoch: &str,
    record_kind: &str,
    plaintext: &[u8],
) {
    mac.update(enrollment_epoch.as_bytes());
    mac.update(&[0]);
    mac.update(record_kind.as_bytes());
    mac.update(&[0]);
    mac.update(plaintext);
}

fn hkdf_expand(root_key: &[u8; 32], info: &[u8]) -> PlatformResult<[u8; 32]> {
    let mut extract = <HmacSha256 as Mac>::new_from_slice(LOCATOR_HKDF_SALT)
        .map_err(|_| PlatformError::Corrupt("photokit_locator_key"))?;
    extract.update(root_key);
    let mut prk: [u8; 32] = extract.finalize().into_bytes().into();
    let mut expand = <HmacSha256 as Mac>::new_from_slice(&prk)
        .map_err(|_| PlatformError::Corrupt("photokit_locator_key"))?;
    expand.update(info);
    expand.update(&[1]);
    let output = expand.finalize().into_bytes().into();
    prk.zeroize();
    Ok(output)
}

fn locator_aad(enrollment_epoch: &str, record_kind: &str, stable_row_id: &str) -> Vec<u8> {
    [
        enrollment_epoch.as_bytes(),
        &[0],
        record_kind.as_bytes(),
        &[0],
        stable_row_id.as_bytes(),
    ]
    .concat()
}

fn load_enrollment(
    transaction: &Transaction<'_>,
    enrollment_epoch: &str,
) -> PlatformResult<Option<(String, String, bool)>> {
    Ok(transaction
        .query_row(
            "SELECT state, key_reference, allow_icloud_downloads
             FROM photokit_enrollments WHERE enrollment_epoch = ?1",
            [enrollment_epoch],
            |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, i64>(2)? != 0)),
        )
        .optional()?)
}

fn activate_enrollment_in_transaction(
    transaction: &Transaction<'_>,
    enrollment_epoch: &str,
    locator_id: &str,
    protected: &ProtectedPhotoKitLocator,
    now_ms: i64,
) -> PlatformResult<PhotoKitEnrollment> {
    let enrollment = load_enrollment(transaction, enrollment_epoch)?
        .ok_or(PlatformError::Conflict("photokit_enrollment_missing"))?;
    if enrollment.0 != "pending" {
        return Err(PlatformError::Conflict("photokit_enrollment_state"));
    }

    let previous: Option<String> = transaction.query_row(
        "SELECT active_enrollment_epoch FROM photokit_connector_state
         WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if let Some(previous) = previous.as_deref() {
        if previous != enrollment_epoch {
            inactivate_enrollment(transaction, previous, now_ms)?;
        }
    }
    transaction.execute(
        "INSERT INTO photokit_locator_records(
            locator_id, enrollment_epoch, operation_id, record_kind,
            stable_row_id, key_version, lookup_hmac, nonce, ciphertext,
            finalized, created_at_ms
         ) VALUES (?1, ?2, NULL, 'album', ?2, ?3, ?4, ?5, ?6, 1, ?7)",
        params![
            locator_id,
            enrollment_epoch,
            LOCATOR_KEY_VERSION,
            protected.lookup_hmac.as_slice(),
            protected.nonce.as_slice(),
            protected.ciphertext,
            now_ms
        ],
    )?;
    transaction.execute(
        "UPDATE photokit_enrollments
         SET state = 'active', activated_at_ms = ?2
         WHERE enrollment_epoch = ?1 AND state = 'pending'",
        params![enrollment_epoch, now_ms],
    )?;
    transaction.execute(
        "UPDATE photokit_connector_state
         SET state = 'ready', authorization = 'authorized',
             active_enrollment_epoch = ?1,
             active_membership_generation = NULL,
             observed_count = 0, available_count = 0,
             unavailable_count = 0, last_complete_at_ms = NULL,
             updated_at_ms = ?2
         WHERE singleton = 1",
        params![enrollment_epoch, now_ms],
    )?;
    Ok(PhotoKitEnrollment {
        enrollment_epoch: enrollment_epoch.to_owned(),
        key_reference: enrollment.1,
        allow_icloud_downloads: enrollment.2,
        operation_fence: 0,
        membership_generation: None,
    })
}

fn inactivate_enrollment(
    transaction: &Transaction<'_>,
    enrollment_epoch: &str,
    now_ms: i64,
) -> PlatformResult<()> {
    let current_fence: i64 = transaction.query_row(
        "SELECT operation_fence
         FROM photokit_enrollments
         WHERE enrollment_epoch = ?1 AND state = 'active'",
        [enrollment_epoch],
        |row| row.get(0),
    )?;
    let fence = current_fence
        .checked_add(1)
        .ok_or(PlatformError::Corrupt("photokit_fence"))?;
    let proposed_generation = next_membership_generation(transaction, enrollment_epoch)?;
    let operation_id = Uuid::new_v4().hyphenated().to_string();
    let request_id = Uuid::new_v4().hyphenated().to_string();
    let store_authority_epoch: String = transaction.query_row(
        "SELECT epoch FROM store_authority_epoch WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let operation = PhotoKitOperation {
        operation_id: operation_id.clone(),
        request_id: request_id.clone(),
        enrollment_epoch: enrollment_epoch.to_owned(),
        store_authority_epoch: store_authority_epoch.clone(),
        reconciliation_fence: fence as u64,
        proposed_membership_generation: proposed_generation as u64,
        trigger: PhotoKitReconcileTriggerV1::User,
    };
    transaction.execute(
        "UPDATE photokit_enrollments SET operation_fence = ?2
         WHERE enrollment_epoch = ?1 AND state = 'active'",
        params![enrollment_epoch, fence],
    )?;
    transaction.execute(
        "INSERT INTO photokit_operations(
            operation_id, request_id, enrollment_epoch,
            store_authority_epoch, reconciliation_fence,
            proposed_membership_generation, trigger_kind, state,
            started_at_ms
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, 'user', 'enumerating', ?7
         )",
        params![
            operation_id,
            request_id,
            enrollment_epoch,
            store_authority_epoch,
            fence,
            proposed_generation,
            now_ms
        ],
    )?;
    let mut transitions = 0_u16;
    for asset_id in active_generation_assets(transaction, enrollment_epoch)? {
        let (_, changed) = transition_head(
            transaction,
            &asset_id,
            enrollment_epoch,
            &operation_id,
            None,
            PhotoKitAvailabilityV1::Unavailable,
            PhotoKitAvailabilityReasonV1::ScopeUnavailable,
            None,
            now_ms,
        )?;
        transitions = transitions
            .checked_add(u16::from(changed))
            .ok_or(PlatformError::Corrupt("photokit_transition_count"))?;
    }
    if transitions > 0 {
        increment_photokit_revision(transaction)?;
    }
    let active_generation: Option<i64> = transaction.query_row(
        "SELECT active_membership_generation
         FROM photokit_enrollments
         WHERE enrollment_epoch = ?1",
        [enrollment_epoch],
        |row| row.get(0),
    )?;
    let (observed, available, unavailable) = if active_generation.is_some() {
        availability_head_counts(transaction, enrollment_epoch)?
    } else {
        (0, 0, 0)
    };
    let authorization: String = transaction.query_row(
        "SELECT authorization FROM photokit_connector_state
         WHERE singleton = 1 AND active_enrollment_epoch = ?1",
        [enrollment_epoch],
        |row| row.get(0),
    )?;
    transaction.execute(
        "UPDATE photokit_connector_state
         SET observed_count = ?2, available_count = ?3,
             unavailable_count = ?4, updated_at_ms = ?5
         WHERE singleton = 1 AND active_enrollment_epoch = ?1",
        params![enrollment_epoch, observed, available, unavailable, now_ms],
    )?;
    let snapshot = snapshot_in_transaction(transaction, authorization_from_db(&authorization)?)?;
    let publication = PhotoKitPublication {
        operation_id: operation.operation_id.clone(),
        reconciliation_fence: operation.reconciliation_fence,
        membership_generation: snapshot.membership_generation.map(|value| value.get()),
        transitions,
        replayed: false,
        snapshot,
    };
    let publication_json = serialize_terminal_publication(&publication, &operation, "failed")?;
    let changed = transaction.execute(
        "UPDATE photokit_operations
         SET state = 'failed', terminal_reason = 'scope_unavailable',
             finished_at_ms = ?2, terminal_publication_json = ?3
         WHERE operation_id = ?1 AND state = 'enumerating'
           AND terminal_publication_json IS NULL",
        params![operation.operation_id, now_ms, publication_json],
    )?;
    if changed != 1 {
        return Err(PlatformError::Conflict(
            "photokit_terminal_publication_exists",
        ));
    }
    transaction.execute(
        "UPDATE photokit_enrollments
         SET state = 'inactive', inactivated_at_ms = ?2
         WHERE enrollment_epoch = ?1 AND state = 'active'",
        params![enrollment_epoch, now_ms],
    )?;
    Ok(())
}

fn operation_by_request(
    transaction: &Transaction<'_>,
    request_id: &str,
) -> PlatformResult<Option<PhotoKitOperation>> {
    Ok(transaction
        .query_row(
            "SELECT operation_id, request_id, enrollment_epoch,
                    store_authority_epoch, reconciliation_fence,
                    proposed_membership_generation, trigger_kind
             FROM photokit_operations WHERE request_id = ?1",
            [request_id],
            operation_from_row,
        )
        .optional()?)
}

fn operation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<PhotoKitOperation> {
    let trigger: String = row.get(6)?;
    Ok(PhotoKitOperation {
        operation_id: row.get(0)?,
        request_id: row.get(1)?,
        enrollment_epoch: row.get(2)?,
        store_authority_epoch: row.get(3)?,
        reconciliation_fence: row.get::<_, i64>(4)? as u64,
        proposed_membership_generation: row.get::<_, i64>(5)? as u64,
        trigger: trigger_from_db(&trigger).map_err(|_| rusqlite::Error::InvalidQuery)?,
    })
}

fn ensure_current_operation(
    transaction: &Transaction<'_>,
    operation: &PhotoKitOperation,
    expected_state: &str,
) -> PlatformResult<()> {
    let valid = transaction
        .query_row(
            "SELECT 1
             FROM photokit_operations operation
             JOIN photokit_enrollments enrollment
               ON enrollment.enrollment_epoch = operation.enrollment_epoch
             JOIN photokit_connector_state state
               ON state.active_enrollment_epoch = operation.enrollment_epoch
             JOIN store_authority_epoch authority
               ON authority.epoch = operation.store_authority_epoch
             WHERE operation.operation_id = ?1
               AND operation.state = ?2
               AND operation.reconciliation_fence = ?3
               AND enrollment.operation_fence = ?3
               AND enrollment.state = 'active'",
            params![
                operation.operation_id,
                expected_state,
                i64::try_from(operation.reconciliation_fence)
                    .map_err(|_| PlatformError::Corrupt("photokit_fence"))?
            ],
            |_| Ok(()),
        )
        .optional()?;
    valid.ok_or(PlatformError::Conflict("photokit_stale_fence"))
}

fn ensure_current_operation_any(
    transaction: &Transaction<'_>,
    operation: &PhotoKitOperation,
) -> PlatformResult<()> {
    let state: String = transaction.query_row(
        "SELECT state FROM photokit_operations WHERE operation_id = ?1",
        [&operation.operation_id],
        |row| row.get(0),
    )?;
    if !matches!(state.as_str(), "enumerating" | "materializing") {
        return Err(PlatformError::Conflict("photokit_operation_state"));
    }
    ensure_current_operation(transaction, operation, &state)
}

fn load_operation_observations(
    transaction: &Transaction<'_>,
    operation_id: &str,
) -> PlatformResult<Vec<StoredObservation>> {
    let mut statement = transaction.prepare(
        "SELECT ordinal, asset_id, locator_id
         FROM photokit_operation_observations
         WHERE operation_id = ?1 ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map([operation_id], |row| {
            Ok(StoredObservation {
                ordinal: row.get::<_, i64>(0)? as u16,
                asset_id: row.get(1)?,
                locator_id: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn insert_materialization(
    transaction: &Transaction<'_>,
    asset_id: &str,
    operation_id: &str,
    materialization: &PhotoKitMaterializationRecord,
    now_ms: i64,
) -> PlatformResult<String> {
    validate_hash(&materialization.resource_fingerprint)?;
    validate_hash(&materialization.blob.sha256)?;
    validate_materialization(materialization)?;
    transaction.execute(
        "INSERT OR IGNORE INTO blobs(sha256, byte_length, created_at_ms)
         VALUES (?1, ?2, ?3)",
        params![
            materialization.blob.sha256,
            i64::try_from(materialization.blob.byte_length)
                .map_err(|_| PlatformError::InvalidInput("blob_byte_length"))?,
            now_ms
        ],
    )?;
    let stored_length: i64 = transaction.query_row(
        "SELECT byte_length FROM blobs WHERE sha256 = ?1",
        [&materialization.blob.sha256],
        |row| row.get(0),
    )?;
    if stored_length != materialization.blob.byte_length as i64 {
        return Err(PlatformError::Conflict("blob_length_changed"));
    }
    let materialization_id = Uuid::new_v4().hyphenated().to_string();
    transaction.execute(
        "INSERT OR IGNORE INTO photokit_materializations(
            materialization_id, asset_id, operation_id,
            resource_fingerprint, blob_sha256, byte_length, resource_uti,
            pixel_width, pixel_height, selection_policy_revision, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            materialization_id,
            asset_id,
            operation_id,
            materialization.resource_fingerprint,
            materialization.blob.sha256,
            i64::try_from(materialization.blob.byte_length)
                .map_err(|_| PlatformError::InvalidInput("blob_byte_length"))?,
            materialization.resource_uti,
            i64::from(materialization.pixel_width),
            i64::from(materialization.pixel_height),
            SELECTION_POLICY_REVISION,
            now_ms
        ],
    )?;
    let stored = transaction.query_row(
        "SELECT materialization_id, blob_sha256, byte_length, resource_uti,
                pixel_width, pixel_height
         FROM photokit_materializations
         WHERE asset_id = ?1 AND resource_fingerprint = ?2",
        params![asset_id, materialization.resource_fingerprint],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    if stored.1 != materialization.blob.sha256
        || stored.2 != materialization.blob.byte_length as i64
        || stored.3 != materialization.resource_uti
        || stored.4 != i64::from(materialization.pixel_width)
        || stored.5 != i64::from(materialization.pixel_height)
    {
        return Err(PlatformError::Conflict(
            "photokit_materialization_collision",
        ));
    }
    Ok(stored.0)
}

#[allow(clippy::too_many_arguments)]
fn transition_head(
    transaction: &Transaction<'_>,
    asset_id: &str,
    enrollment_epoch: &str,
    operation_id: &str,
    membership_generation: Option<u64>,
    availability: PhotoKitAvailabilityV1,
    reason: PhotoKitAvailabilityReasonV1,
    materialization_id: Option<&str>,
    now_ms: i64,
) -> PlatformResult<(String, bool)> {
    let desired = (
        availability_to_db(availability),
        reason_to_db(reason),
        materialization_id,
        enrollment_epoch,
    );
    if let Some(existing) = transaction
        .query_row(
            "SELECT revision.revision_id, revision.availability,
                    revision.reason, revision.materialization_id,
                    revision.enrollment_epoch
             FROM photokit_availability_heads head
             JOIN photokit_availability_revisions revision
               ON revision.revision_id = head.revision_id
             WHERE head.asset_id = ?1",
            [asset_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
    {
        if existing.1 == desired.0
            && existing.2 == desired.1
            && existing.3.as_deref() == desired.2
            && existing.4 == desired.3
        {
            return Ok((existing.0, false));
        }
    }
    let revision_id = Uuid::new_v4().hyphenated().to_string();
    transaction.execute(
        "INSERT INTO photokit_availability_revisions(
            revision_id, asset_id, enrollment_epoch, operation_id,
            membership_generation, availability, reason,
            materialization_id, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            revision_id,
            asset_id,
            enrollment_epoch,
            operation_id,
            membership_generation
                .map(i64::try_from)
                .transpose()
                .map_err(|_| PlatformError::Corrupt("photokit_generation"))?,
            desired.0,
            desired.1,
            materialization_id,
            now_ms
        ],
    )?;
    transaction.execute(
        "INSERT INTO photokit_availability_heads(asset_id, revision_id, updated_at_ms)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(asset_id) DO UPDATE SET
            revision_id = excluded.revision_id,
            updated_at_ms = excluded.updated_at_ms",
        params![asset_id, revision_id, now_ms],
    )?;
    Ok((revision_id, true))
}

fn prior_active_assets_not_observed(
    transaction: &Transaction<'_>,
    enrollment_epoch: &str,
    observed: &[String],
) -> PlatformResult<Vec<String>> {
    let generation: Option<i64> = transaction.query_row(
        "SELECT active_membership_generation FROM photokit_enrollments
         WHERE enrollment_epoch = ?1",
        [enrollment_epoch],
        |row| row.get(0),
    )?;
    let Some(generation) = generation else {
        return Ok(availability_head_assets(transaction, enrollment_epoch)?
            .into_iter()
            .filter(|asset_id| !observed.iter().any(|value| value == asset_id))
            .collect());
    };
    let mut statement = transaction.prepare(
        "SELECT asset_id FROM photokit_generation_members
         WHERE enrollment_epoch = ?1 AND membership_generation = ?2
         ORDER BY asset_id",
    )?;
    let prior = statement
        .query_map(params![enrollment_epoch, generation], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(prior
        .into_iter()
        .filter(|asset_id| !observed.iter().any(|value| value == asset_id))
        .collect())
}

fn active_generation_assets(
    transaction: &Transaction<'_>,
    enrollment_epoch: &str,
) -> PlatformResult<Vec<String>> {
    let generation: Option<i64> = transaction.query_row(
        "SELECT active_membership_generation FROM photokit_enrollments
         WHERE enrollment_epoch = ?1",
        [enrollment_epoch],
        |row| row.get(0),
    )?;
    let Some(generation) = generation else {
        return availability_head_assets(transaction, enrollment_epoch);
    };
    let mut statement = transaction.prepare(
        "SELECT asset_id
         FROM photokit_generation_members
         WHERE enrollment_epoch = ?1 AND membership_generation = ?2
         ORDER BY ordinal",
    )?;
    let rows = statement
        .query_map(params![enrollment_epoch, generation], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn availability_head_assets(
    transaction: &Transaction<'_>,
    enrollment_epoch: &str,
) -> PlatformResult<Vec<String>> {
    let mut statement = transaction.prepare(
        "SELECT head.asset_id
         FROM photokit_availability_heads head
         JOIN photokit_assets asset ON asset.asset_id = head.asset_id
         WHERE asset.enrollment_epoch = ?1
         ORDER BY head.asset_id",
    )?;
    let rows = statement
        .query_map([enrollment_epoch], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn availability_head_counts(
    transaction: &Transaction<'_>,
    enrollment_epoch: &str,
) -> PlatformResult<(i64, i64, i64)> {
    transaction
        .query_row(
            "SELECT
                COUNT(*),
                COALESCE(SUM(
                    CASE WHEN revision.availability = 'available' THEN 1 ELSE 0 END
                ), 0),
                COALESCE(SUM(
                    CASE WHEN revision.availability = 'unavailable' THEN 1 ELSE 0 END
                ), 0)
             FROM photokit_availability_heads head
             JOIN photokit_availability_revisions revision
               ON revision.revision_id = head.revision_id
             JOIN photokit_assets asset ON asset.asset_id = head.asset_id
             WHERE asset.enrollment_epoch = ?1",
            [enrollment_epoch],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(Into::into)
}

fn next_membership_generation(
    transaction: &Transaction<'_>,
    enrollment_epoch: &str,
) -> PlatformResult<i64> {
    let generation: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(membership_generation), 0)
         FROM photokit_membership_generations
         WHERE enrollment_epoch = ?1",
        [enrollment_epoch],
        |row| row.get(0),
    )?;
    generation
        .checked_add(1)
        .filter(|value| *value <= 9_007_199_254_740_990)
        .ok_or(PlatformError::Corrupt("photokit_generation"))
}

fn cleanup_provisional_operation(
    transaction: &Transaction<'_>,
    operation_id: &str,
) -> PlatformResult<()> {
    transaction.execute(
        "DELETE FROM photokit_materialization_attempts
         WHERE operation_id = ?1",
        [operation_id],
    )?;
    transaction.execute(
        "DELETE FROM photokit_operation_observations
         WHERE operation_id = ?1",
        [operation_id],
    )?;
    transaction.execute(
        "DELETE FROM photokit_locator_records
         WHERE operation_id = ?1 AND finalized = 0",
        [operation_id],
    )?;
    Ok(())
}

fn verify_asset_identity(
    transaction: &Transaction<'_>,
    asset_id: &str,
    enrollment_epoch: &str,
    locator_id: &str,
) -> PlatformResult<()> {
    let stored: (String, String) = transaction.query_row(
        "SELECT enrollment_epoch, locator_id
         FROM photokit_assets WHERE asset_id = ?1",
        [asset_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if stored != (enrollment_epoch.to_owned(), locator_id.to_owned()) {
        return Err(PlatformError::Conflict("photokit_asset_identity"));
    }
    Ok(())
}

fn increment_photokit_revision(transaction: &Transaction<'_>) -> PlatformResult<()> {
    let changed = transaction.execute(
        "UPDATE revision_state
         SET photokit_revision = photokit_revision + 1
         WHERE singleton = 1
           AND photokit_revision < 9007199254740990",
        [],
    )?;
    if changed != 1 {
        return Err(PlatformError::Corrupt("photokit_revision"));
    }
    Ok(())
}

fn validate_terminal_publication(
    publication: &PhotoKitPublication,
    operation: &PhotoKitOperation,
    terminal_state: &str,
) -> PlatformResult<()> {
    if publication.operation_id != operation.operation_id
        || publication.reconciliation_fence != operation.reconciliation_fence
        || publication.replayed
        || publication.transitions > 500
        || publication
            .snapshot
            .enrollment_epoch
            .as_ref()
            .map(ToString::to_string)
            .as_deref()
            != Some(operation.enrollment_epoch.as_str())
        || publication.membership_generation
            != publication
                .snapshot
                .membership_generation
                .map(|value| value.get())
        || (terminal_state == "complete"
            && publication.membership_generation != Some(operation.proposed_membership_generation))
        || !matches!(terminal_state, "complete" | "failed")
    {
        return Err(PlatformError::Corrupt(
            "photokit_terminal_publication_identity",
        ));
    }
    publication
        .snapshot
        .validate()
        .map_err(|_| PlatformError::Corrupt("photokit_terminal_publication_snapshot"))?;
    Ok(())
}

fn serialize_terminal_publication(
    publication: &PhotoKitPublication,
    operation: &PhotoKitOperation,
    terminal_state: &str,
) -> PlatformResult<String> {
    validate_terminal_publication(publication, operation, terminal_state)?;
    let publication_json = serde_json::to_string(publication)?;
    if publication_json.len() > 16_384 {
        return Err(PlatformError::Corrupt("photokit_terminal_publication_size"));
    }
    Ok(publication_json)
}

fn terminal_publication_in_transaction(
    transaction: &Transaction<'_>,
    operation: &PhotoKitOperation,
) -> PlatformResult<PhotoKitPublication> {
    let (state, publication_json): (String, Option<String>) = transaction.query_row(
        "SELECT state, terminal_publication_json
         FROM photokit_operations
         WHERE operation_id = ?1 AND state IN ('complete', 'failed')",
        [&operation.operation_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let publication_json = publication_json.ok_or(PlatformError::Corrupt(
        "photokit_terminal_publication_missing",
    ))?;
    let mut publication: PhotoKitPublication = serde_json::from_str(&publication_json)?;
    validate_terminal_publication(&publication, operation, &state)?;
    publication.replayed = true;
    Ok(publication)
}

fn snapshot_in_transaction(
    transaction: &Transaction<'_>,
    authorization: PhotoKitAuthorizationV1,
) -> PlatformResult<PhotoKitConnectorSnapshotV1> {
    snapshot_in_connection(transaction, authorization)
}

fn snapshot_in_connection(
    connection: &rusqlite::Connection,
    authorization: PhotoKitAuthorizationV1,
) -> PlatformResult<PhotoKitConnectorSnapshotV1> {
    let (
        state,
        enrollment_epoch,
        generation,
        allow_icloud,
        observed,
        available,
        unavailable,
        last_complete,
        revision,
    ): (
        String,
        Option<String>,
        Option<i64>,
        i64,
        i64,
        i64,
        i64,
        Option<i64>,
        i64,
    ) = connection.query_row(
        "SELECT state.state, state.active_enrollment_epoch,
                state.active_membership_generation,
                COALESCE(enrollment.allow_icloud_downloads, 0),
                state.observed_count, state.available_count,
                state.unavailable_count, state.last_complete_at_ms,
                revision.photokit_revision
         FROM photokit_connector_state state
         JOIN revision_state revision ON revision.singleton = 1
         LEFT JOIN photokit_enrollments enrollment
           ON enrollment.enrollment_epoch = state.active_enrollment_epoch
         WHERE state.singleton = 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
            ))
        },
    )?;
    let mut availability_counts = Vec::new();
    if let (Some(enrollment_epoch), Some(_generation)) = (enrollment_epoch.as_deref(), generation) {
        let mut statement = connection.prepare(
            "SELECT revision.availability, revision.reason, COUNT(*)
             FROM photokit_availability_heads head
             JOIN photokit_availability_revisions revision
               ON revision.revision_id = head.revision_id
             JOIN photokit_assets asset ON asset.asset_id = head.asset_id
             WHERE asset.enrollment_epoch = ?1
             GROUP BY revision.availability, revision.reason
             ORDER BY revision.availability, revision.reason",
        )?;
        let rows = statement
            .query_map([enrollment_epoch], |row| {
                let availability: String = row.get(0)?;
                let reason: String = row.get(1)?;
                Ok(PhotoKitAvailabilityCountV1 {
                    availability: availability_from_db(&availability)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    reason: reason_from_db(&reason).map_err(|_| rusqlite::Error::InvalidQuery)?,
                    count: row.get::<_, i64>(2)? as u16,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        availability_counts = rows;
    }
    Ok(PhotoKitConnectorSnapshotV1 {
        state: connector_state_from_db(&state)?,
        authorization,
        enrollment_epoch: enrollment_epoch
            .map(|value| {
                PhotoKitEnrollmentEpochV1::new(
                    Uuid::parse_str(&value)
                        .map_err(|_| PlatformError::Corrupt("photokit_enrollment_epoch"))?,
                )
                .map_err(|_| PlatformError::Corrupt("photokit_enrollment_epoch"))
            })
            .transpose()?,
        membership_generation: generation
            .map(|value| {
                PhotoKitMembershipGenerationV1::new(value as u64)
                    .map_err(|_| PlatformError::Corrupt("photokit_generation"))
            })
            .transpose()?,
        photokit_revision: PhotoKitRevisionV1::new(revision as u64)
            .map_err(|_| PlatformError::Corrupt("photokit_revision"))?,
        allow_icloud_downloads: allow_icloud != 0,
        last_complete_at: last_complete.map(format_timestamp).transpose()?,
        counts: PhotoKitAssetCountsV1 {
            observed: observed as u16,
            available: available as u16,
            unavailable: unavailable as u16,
        },
        availability_counts,
    })
}

fn validate_availability_result(value: &PhotoKitFinalizedObservation) -> PlatformResult<()> {
    let valid_reason = match value.availability {
        PhotoKitAvailabilityV1::Available => matches!(
            value.reason,
            PhotoKitAvailabilityReasonV1::Materialized | PhotoKitAvailabilityReasonV1::Accessible
        ),
        PhotoKitAvailabilityV1::Unavailable => !matches!(
            value.reason,
            PhotoKitAvailabilityReasonV1::Materialized | PhotoKitAvailabilityReasonV1::Accessible
        ),
    };
    if !valid_reason
        || (value.reason == PhotoKitAvailabilityReasonV1::Materialized)
            != value.materialization.is_some()
    {
        return Err(PlatformError::InvalidInput("photokit_availability_result"));
    }
    Ok(())
}

fn validate_materialization(value: &PhotoKitMaterializationRecord) -> PlatformResult<()> {
    if value.blob.byte_length == 0
        || value.blob.byte_length > 40 * 1024 * 1024
        || value.pixel_width == 0
        || value.pixel_width > 16_384
        || value.pixel_height == 0
        || value.pixel_height > 16_384
        || u64::from(value.pixel_width) * u64::from(value.pixel_height) > 64_000_000
        || !matches!(
            value.resource_uti.as_str(),
            "public.jpeg" | "public.png" | "public.heic" | "public.heif"
        )
    {
        return Err(PlatformError::InvalidInput("photokit_materialization"));
    }
    Ok(())
}

pub fn photokit_resource_fingerprint(
    blob_sha256: &str,
    resource_uti: &str,
    pixel_width: u32,
    pixel_height: u32,
) -> PlatformResult<String> {
    validate_hash(blob_sha256)?;
    validate_ascii(resource_uti, 128, "photokit_resource_uti")?;
    Ok(format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{blob_sha256}\0{resource_uti}\0{pixel_width}\0{pixel_height}\0{SELECTION_POLICY_REVISION}"
            )
            .as_bytes()
        )
    ))
}

pub fn photokit_operation_id(value: &str) -> PlatformResult<OperationId> {
    OperationId::new(
        Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt("photokit_operation_id"))?,
    )
    .map_err(|_| PlatformError::Corrupt("photokit_operation_id"))
}

fn replay_command_receipt_in_connection<T: DeserializeOwned>(
    connection: &rusqlite::Connection,
    request_id: &str,
    command_name: &str,
    envelope_hash: &str,
) -> PlatformResult<Option<T>> {
    let row = connection
        .query_row(
            "SELECT command_name, envelope_hash, response_json
             FROM photokit_command_receipts WHERE request_id = ?1",
            [request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((stored_command, stored_hash, response))
            if stored_command == command_name && stored_hash == envelope_hash =>
        {
            Ok(Some(serde_json::from_str(&response)?))
        }
        Some(_) => Err(PlatformError::Conflict("photokit_request_reused")),
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_command_receipt<T: Serialize>(
    transaction: &Transaction<'_>,
    request_id: &str,
    command_name: &str,
    envelope_hash: &str,
    enrollment_epoch: Option<&str>,
    operation_id: Option<&str>,
    response: &T,
    now_ms: i64,
) -> PlatformResult<()> {
    if transaction
        .query_row(
            "SELECT 1 FROM photokit_command_receipts WHERE request_id = ?1",
            [request_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(PlatformError::Conflict("photokit_request_reused"));
    }
    let response_json = serde_json::to_string(response)?;
    if response_json.len() > 8192 {
        return Err(PlatformError::Corrupt("photokit_receipt_response"));
    }
    transaction.execute(
        "INSERT INTO photokit_command_receipts(
            request_id, command_name, envelope_hash, enrollment_epoch,
            operation_id, response_json, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            request_id,
            command_name,
            envelope_hash,
            enrollment_epoch,
            operation_id,
            response_json,
            now_ms
        ],
    )?;
    Ok(())
}

fn validate_command_name(value: &str) -> PlatformResult<()> {
    if matches!(
        value,
        CONFIGURE_PHOTOKIT_COMMAND | SYNC_PHOTOKIT_COMMAND | DISABLE_PHOTOKIT_COMMAND
    ) {
        Ok(())
    } else {
        Err(PlatformError::InvalidInput("photokit_command_name"))
    }
}

fn validate_envelope_hash(value: &str) -> PlatformResult<()> {
    if value.len() == 64
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(PlatformError::InvalidInput("photokit_envelope_hash"))
    }
}

fn validate_uuid(value: &str, field: &'static str) -> PlatformResult<()> {
    let parsed = Uuid::parse_str(value).map_err(|_| PlatformError::InvalidInput(field))?;
    if parsed.is_nil() || parsed.hyphenated().to_string() != value {
        return Err(PlatformError::InvalidInput(field));
    }
    Ok(())
}

fn validate_key_reference(value: &str) -> PlatformResult<()> {
    validate_ascii(value, 128, "photokit_key_reference")
}

fn validate_ascii(value: &str, maximum: usize, field: &'static str) -> PlatformResult<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(PlatformError::InvalidInput(field));
    }
    Ok(())
}

fn validate_hash(value: &str) -> PlatformResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlatformError::InvalidInput("sha256"));
    }
    Ok(())
}

fn validate_terminal_reason(value: &str) -> PlatformResult<()> {
    if matches!(
        value,
        "enumeration_incomplete"
            | "authorization_not_determined"
            | "authorization_restricted"
            | "authorization_denied"
            | "limited_access"
            | "scope_unavailable"
            | "locator_key_unavailable"
            | "internal"
    ) {
        Ok(())
    } else {
        Err(PlatformError::InvalidInput("photokit_terminal_reason"))
    }
}

fn authorization_to_db(value: PhotoKitAuthorizationV1) -> &'static str {
    match value {
        PhotoKitAuthorizationV1::NotDetermined => "not_determined",
        PhotoKitAuthorizationV1::Restricted => "restricted",
        PhotoKitAuthorizationV1::Denied => "denied",
        PhotoKitAuthorizationV1::Limited => "limited",
        PhotoKitAuthorizationV1::Authorized => "authorized",
    }
}

fn authorization_from_db(value: &str) -> PlatformResult<PhotoKitAuthorizationV1> {
    match value {
        "not_determined" => Ok(PhotoKitAuthorizationV1::NotDetermined),
        "restricted" => Ok(PhotoKitAuthorizationV1::Restricted),
        "denied" => Ok(PhotoKitAuthorizationV1::Denied),
        "limited" => Ok(PhotoKitAuthorizationV1::Limited),
        "authorized" => Ok(PhotoKitAuthorizationV1::Authorized),
        _ => Err(PlatformError::Corrupt("photokit_authorization")),
    }
}

fn trigger_to_db(value: PhotoKitReconcileTriggerV1) -> &'static str {
    match value {
        PhotoKitReconcileTriggerV1::Startup => "startup",
        PhotoKitReconcileTriggerV1::User => "user",
        PhotoKitReconcileTriggerV1::LibraryChange => "library_change",
    }
}

fn trigger_from_db(value: &str) -> PlatformResult<PhotoKitReconcileTriggerV1> {
    match value {
        "startup" => Ok(PhotoKitReconcileTriggerV1::Startup),
        "user" => Ok(PhotoKitReconcileTriggerV1::User),
        "library_change" => Ok(PhotoKitReconcileTriggerV1::LibraryChange),
        _ => Err(PlatformError::Corrupt("photokit_trigger")),
    }
}

fn connector_state_from_db(value: &str) -> PlatformResult<PhotoKitConnectorStateV1> {
    match value {
        "unconfigured" => Ok(PhotoKitConnectorStateV1::Unconfigured),
        "ready" => Ok(PhotoKitConnectorStateV1::Ready),
        "reconciling" => Ok(PhotoKitConnectorStateV1::Reconciling),
        "needs_attention" => Ok(PhotoKitConnectorStateV1::NeedsAttention),
        _ => Err(PlatformError::Corrupt("photokit_connector_state")),
    }
}

fn availability_to_db(value: PhotoKitAvailabilityV1) -> &'static str {
    match value {
        PhotoKitAvailabilityV1::Available => "available",
        PhotoKitAvailabilityV1::Unavailable => "unavailable",
    }
}

fn availability_from_db(value: &str) -> PlatformResult<PhotoKitAvailabilityV1> {
    match value {
        "available" => Ok(PhotoKitAvailabilityV1::Available),
        "unavailable" => Ok(PhotoKitAvailabilityV1::Unavailable),
        _ => Err(PlatformError::Corrupt("photokit_availability")),
    }
}

fn reason_to_db(value: PhotoKitAvailabilityReasonV1) -> &'static str {
    match value {
        PhotoKitAvailabilityReasonV1::Materialized => "materialized",
        PhotoKitAvailabilityReasonV1::Accessible => "accessible",
        PhotoKitAvailabilityReasonV1::AuthorizationNotDetermined => "authorization_not_determined",
        PhotoKitAvailabilityReasonV1::AuthorizationRestricted => "authorization_restricted",
        PhotoKitAvailabilityReasonV1::AuthorizationDenied => "authorization_denied",
        PhotoKitAvailabilityReasonV1::LimitedAccess => "limited_access",
        PhotoKitAvailabilityReasonV1::ScopeUnavailable => "scope_unavailable",
        PhotoKitAvailabilityReasonV1::AssetNotInScope => "asset_not_in_scope",
        PhotoKitAvailabilityReasonV1::IcloudUnavailable => "icloud_unavailable",
        PhotoKitAvailabilityReasonV1::UnsupportedResource => "unsupported_resource",
        PhotoKitAvailabilityReasonV1::TransferFailed => "transfer_failed",
        PhotoKitAvailabilityReasonV1::BlobIntegrityFailed => "blob_integrity_failed",
    }
}

fn reason_from_db(value: &str) -> PlatformResult<PhotoKitAvailabilityReasonV1> {
    match value {
        "materialized" => Ok(PhotoKitAvailabilityReasonV1::Materialized),
        "accessible" => Ok(PhotoKitAvailabilityReasonV1::Accessible),
        "authorization_not_determined" => {
            Ok(PhotoKitAvailabilityReasonV1::AuthorizationNotDetermined)
        }
        "authorization_restricted" => Ok(PhotoKitAvailabilityReasonV1::AuthorizationRestricted),
        "authorization_denied" => Ok(PhotoKitAvailabilityReasonV1::AuthorizationDenied),
        "limited_access" => Ok(PhotoKitAvailabilityReasonV1::LimitedAccess),
        "scope_unavailable" => Ok(PhotoKitAvailabilityReasonV1::ScopeUnavailable),
        "asset_not_in_scope" => Ok(PhotoKitAvailabilityReasonV1::AssetNotInScope),
        "icloud_unavailable" => Ok(PhotoKitAvailabilityReasonV1::IcloudUnavailable),
        "unsupported_resource" => Ok(PhotoKitAvailabilityReasonV1::UnsupportedResource),
        "transfer_failed" => Ok(PhotoKitAvailabilityReasonV1::TransferFailed),
        "blob_integrity_failed" => Ok(PhotoKitAvailabilityReasonV1::BlobIntegrityFailed),
        _ => Err(PlatformError::Corrupt("photokit_availability_reason")),
    }
}
