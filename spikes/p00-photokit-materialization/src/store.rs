use crate::contracts::{
    hex_sha256, AssetSelectionV1, MaterializationClass, OperationRef, OperationSnapshot,
    OperationState, RepresentationPolicy, ResourceDescriptorV1, StartMaterializationV1,
};
use crate::filesystem::PromotedBlob;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS connector_generations (
    generation_id       TEXT PRIMARY KEY,
    connector_instance  TEXT NOT NULL CHECK (length(connector_instance) > 0),
    locator_key_version INTEGER NOT NULL CHECK (locator_key_version > 0),
    state               TEXT NOT NULL CHECK (state IN ('active', 'retired', 'unavailable'))
) STRICT;

CREATE TABLE IF NOT EXISTS materialization_operations (
    operation_id       TEXT PRIMARY KEY,
    client_request_id  TEXT NOT NULL UNIQUE,
    envelope_hash      TEXT NOT NULL CHECK (length(envelope_hash) = 64),
    request_json       TEXT NOT NULL CHECK (json_valid(request_json)),
    state              TEXT NOT NULL CHECK (
        state IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')
    ),
    generation         INTEGER NOT NULL CHECK (generation > 0),
    transferred_bytes  INTEGER NOT NULL DEFAULT 0 CHECK (transferred_bytes >= 0),
    completed_count    INTEGER NOT NULL DEFAULT 0 CHECK (completed_count >= 0),
    total_count        INTEGER NOT NULL CHECK (total_count > 0),
    next_sequence      INTEGER NOT NULL DEFAULT 1 CHECK (next_sequence > 0),
    terminal_sequence  INTEGER,
    created_at_ms      INTEGER NOT NULL,
    CHECK (completed_count <= total_count),
    CHECK (
        (state IN ('succeeded', 'failed', 'cancelled') AND terminal_sequence IS NOT NULL)
        OR
        (state IN ('pending', 'running') AND terminal_sequence IS NULL)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS materialization_items (
    operation_id        TEXT NOT NULL REFERENCES materialization_operations(operation_id)
                        ON DELETE RESTRICT,
    item_index          INTEGER NOT NULL CHECK (item_index >= 0),
    asset_ref           TEXT NOT NULL,
    connector_generation TEXT REFERENCES connector_generations(generation_id)
                         ON DELETE RESTRICT,
    locator_key_version INTEGER NOT NULL CHECK (locator_key_version > 0),
    locator_hmac        TEXT NOT NULL CHECK (length(locator_hmac) = 64),
    locator_ciphertext  TEXT NOT NULL CHECK (length(locator_ciphertext) > 0),
    cloud_key_version   INTEGER,
    cloud_hmac          TEXT,
    cloud_ciphertext    TEXT,
    state               TEXT NOT NULL CHECK (
        state IN ('pending', 'transferring', 'succeeded', 'failed', 'cancelled')
    ),
    request_generation  INTEGER NOT NULL DEFAULT 0 CHECK (request_generation >= 0),
    active_request_id   TEXT,
    resource_json       TEXT CHECK (resource_json IS NULL OR json_valid(resource_json)),
    representation_policy TEXT NOT NULL,
    classification      TEXT,
    progress            REAL,
    staging_filename    TEXT NOT NULL,
    failure_class       TEXT,
    revision_id         TEXT,
    PRIMARY KEY (operation_id, item_index),
    UNIQUE (operation_id, asset_ref)
) STRICT;

CREATE TABLE IF NOT EXISTS materialized_blobs (
    sha256         TEXT PRIMARY KEY CHECK (length(sha256) = 64),
    byte_count     INTEGER NOT NULL CHECK (byte_count > 0),
    relative_path  TEXT NOT NULL UNIQUE,
    created_at_ms  INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS photo_sources (
    source_id             TEXT PRIMARY KEY,
    connector_generation  TEXT REFERENCES connector_generations(generation_id)
                          ON DELETE RESTRICT,
    locator_key_version   INTEGER NOT NULL CHECK (locator_key_version > 0),
    locator_hmac          TEXT NOT NULL CHECK (length(locator_hmac) = 64),
    locator_ciphertext    TEXT NOT NULL CHECK (length(locator_ciphertext) > 0),
    cloud_key_version     INTEGER,
    cloud_hmac            TEXT,
    cloud_ciphertext      TEXT,
    UNIQUE (connector_generation, locator_hmac)
) STRICT;

CREATE TABLE IF NOT EXISTS source_revisions (
    revision_id            TEXT PRIMARY KEY,
    source_id              TEXT NOT NULL REFERENCES photo_sources(source_id) ON DELETE RESTRICT,
    resource_ref           TEXT NOT NULL,
    resource_uti           TEXT NOT NULL,
    representation_policy  TEXT NOT NULL,
    classification         TEXT NOT NULL CHECK (
        classification IN ('local', 'cloud', 'picker_import')
    ),
    blob_sha256            TEXT NOT NULL REFERENCES materialized_blobs(sha256) ON DELETE RESTRICT,
    blob_byte_count        INTEGER NOT NULL CHECK (blob_byte_count > 0),
    operation_id           TEXT NOT NULL REFERENCES materialization_operations(operation_id)
                           ON DELETE RESTRICT,
    retrieved_at_ms        INTEGER NOT NULL,
    provenance_json        TEXT NOT NULL CHECK (json_valid(provenance_json)),
    UNIQUE (source_id, resource_ref, blob_sha256)
) STRICT;

CREATE INDEX IF NOT EXISTS materialization_items_state
    ON materialization_items(operation_id, state, item_index);
CREATE INDEX IF NOT EXISTS source_revisions_blob
    ON source_revisions(blob_sha256);
PRAGMA user_version = 1;
"#;

#[derive(Clone, Debug)]
pub struct MaterializationStore {
    path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceRecord {
    pub schema_version: u32,
    pub connector_instance: String,
    pub connector_generation: String,
    pub locator_key_version: u32,
    pub locator_hmac: String,
    pub cloud_locator_hmac: Option<String>,
    pub resource: ResourceDescriptorV1,
    pub representation_policy: RepresentationPolicy,
    pub classification: MaterializationClass,
    pub blob_sha256: String,
    pub blob_byte_count: u64,
    pub operation_id: String,
    pub retrieved_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevisionRecord {
    pub revision_id: String,
    pub source_id: String,
    pub blob_sha256: String,
    pub operation_id: String,
    pub provenance: ProvenanceRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingItem {
    pub index: usize,
    pub asset: AssetSelectionV1,
    pub staging_filename: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    InsertedRevision,
    ReplayedRevision,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DatabaseAudit {
    pub integrity_check: String,
    pub foreign_key_violations: usize,
    pub operation_count: usize,
    pub connector_generation_count: usize,
    pub blob_count: usize,
    pub source_count: usize,
    pub revision_count: usize,
    pub referenced_blob_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Conflict,
    Fenced,
    BatchLimit,
    InvalidInput,
    NotFound,
    Invariant,
    Sqlite,
    Serialization,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "materialization store failure: {}", self.code())
    }
}

impl Error for StoreError {}

impl StoreError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::Fenced => "fenced",
            Self::BatchLimit => "batch_limit",
            Self::InvalidInput => "invalid_input",
            Self::NotFound => "not_found",
            Self::Invariant => "invariant",
            Self::Sqlite => "sqlite",
            Self::Serialization => "serialization",
        }
    }
}

impl MaterializationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let store = Self {
            path: path.as_ref().to_path_buf(),
        };
        let connection = store.connection()?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| StoreError::Sqlite)?;
        Ok(store)
    }

    pub fn enroll_generation(
        &self,
        generation_id: &str,
        connector_instance: &str,
        locator_key_version: u32,
    ) -> Result<(), StoreError> {
        if generation_id.is_empty() || connector_instance.is_empty() || locator_key_version == 0 {
            return Err(StoreError::InvalidInput);
        }
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "INSERT INTO connector_generations (
                    generation_id, connector_instance, locator_key_version, state
                 ) VALUES (?1, ?2, ?3, 'active')
                 ON CONFLICT(generation_id) DO NOTHING",
                params![generation_id, connector_instance, locator_key_version],
            )
            .map_err(|_| StoreError::Sqlite)?;
        if changed == 0 {
            let exact = connection
                .query_row(
                    "SELECT connector_instance = ?2 AND locator_key_version = ?3
                     FROM connector_generations WHERE generation_id = ?1",
                    params![generation_id, connector_instance, locator_key_version],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| StoreError::Sqlite)?;
            if !exact {
                return Err(StoreError::Conflict);
            }
        }
        Ok(())
    }

    pub fn retire_generation(&self, generation_id: &str) -> Result<(), StoreError> {
        let changed = self
            .connection()?
            .execute(
                "UPDATE connector_generations SET state = 'retired'
                 WHERE generation_id = ?1 AND state = 'active'",
                [generation_id],
            )
            .map_err(|_| StoreError::Sqlite)?;
        if changed != 1 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn start(
        &self,
        request: &StartMaterializationV1,
        created_at_ms: i64,
    ) -> Result<OperationRef, StoreError> {
        request.validate().map_err(|_| StoreError::InvalidInput)?;
        let envelope_hash = request
            .envelope_hash()
            .map_err(|_| StoreError::InvalidInput)?;
        let request_json = serde_json::to_string(request).map_err(|_| StoreError::Serialization)?;
        let operation_id = format!("op-{}", &envelope_hash[..32]);
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Sqlite)?;

        let existing = transaction
            .query_row(
                "SELECT operation_id, envelope_hash
                 FROM materialization_operations WHERE client_request_id = ?1",
                [&request.client_request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| StoreError::Sqlite)?;
        if let Some((existing_id, existing_hash)) = existing {
            if existing_hash == envelope_hash {
                transaction.commit().map_err(|_| StoreError::Sqlite)?;
                return Ok(OperationRef {
                    operation_id: existing_id,
                });
            }
            return Err(StoreError::Conflict);
        }

        for asset in &request.assets {
            if asset.connector_generation.is_empty() {
                continue;
            }
            let generation = transaction
                .query_row(
                    "SELECT locator_key_version, state
                     FROM connector_generations WHERE generation_id = ?1",
                    [&asset.connector_generation],
                    |row| Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|_| StoreError::Sqlite)?
                .ok_or(StoreError::InvalidInput)?;
            if generation.0 != asset.local_locator.key_version || generation.1 != "active" {
                return Err(StoreError::InvalidInput);
            }
        }

        transaction
            .execute(
                "INSERT INTO materialization_operations (
                    operation_id, client_request_id, envelope_hash, request_json, state,
                    generation, transferred_bytes, completed_count, total_count, next_sequence,
                    terminal_sequence, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, 'pending', 1, 0, 0, ?5, 1, NULL, ?6)",
                params![
                    operation_id,
                    request.client_request_id,
                    envelope_hash,
                    request_json,
                    i64::try_from(request.assets.len()).map_err(|_| StoreError::InvalidInput)?,
                    created_at_ms
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        for (index, asset) in request.assets.iter().enumerate() {
            let connector_generation = (!asset.connector_generation.is_empty())
                .then_some(asset.connector_generation.as_str());
            transaction
                .execute(
                    "INSERT INTO materialization_items (
                        operation_id, item_index, asset_ref, connector_generation,
                        locator_key_version, locator_hmac, locator_ciphertext,
                        cloud_key_version, cloud_hmac, cloud_ciphertext,
                        state, request_generation, active_request_id, resource_json,
                        representation_policy, classification, progress,
                        staging_filename, failure_class, revision_id
                     ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                        'pending', 0, NULL, NULL, 'original_primary_v1', NULL, NULL,
                        ?11, NULL, NULL
                     )",
                    params![
                        operation_id,
                        index as i64,
                        asset.asset_ref.as_str(),
                        connector_generation,
                        asset.local_locator.key_version,
                        asset.local_locator.lookup_hmac,
                        asset.local_locator.ciphertext,
                        asset.cloud_locator.as_ref().map(|value| value.key_version),
                        asset
                            .cloud_locator
                            .as_ref()
                            .map(|value| value.lookup_hmac.as_str()),
                        asset
                            .cloud_locator
                            .as_ref()
                            .map(|value| value.ciphertext.as_str()),
                        format!("item-{index:04}.part"),
                    ],
                )
                .map_err(|_| StoreError::Sqlite)?;
        }
        transaction.commit().map_err(|_| StoreError::Sqlite)?;
        Ok(OperationRef { operation_id })
    }

    pub fn status(&self, operation_id: &str) -> Result<OperationSnapshot, StoreError> {
        self.connection()?
            .query_row(
                "SELECT state, generation, completed_count, total_count, terminal_sequence
                 FROM materialization_operations WHERE operation_id = ?1",
                [operation_id],
                |row| {
                    let state: String = row.get(0)?;
                    Ok(OperationSnapshot {
                        operation_id: operation_id.to_owned(),
                        state: parse_operation_state(&state),
                        generation: row.get::<_, i64>(1)? as u64,
                        completed: row.get::<_, i64>(2)? as usize,
                        total: row.get::<_, i64>(3)? as usize,
                        terminal_sequence: row.get::<_, Option<i64>>(4)?.map(|value| value as u64),
                    })
                },
            )
            .optional()
            .map_err(|_| StoreError::Sqlite)?
            .ok_or(StoreError::NotFound)
    }

    pub fn cancel(&self, operation_id: &str) -> Result<OperationSnapshot, StoreError> {
        self.cancel_with_active_requests(operation_id)
            .map(|(snapshot, _)| snapshot)
    }

    pub(crate) fn cancel_with_active_requests(
        &self,
        operation_id: &str,
    ) -> Result<(OperationSnapshot, Vec<String>), StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Sqlite)?;
        let state = transaction
            .query_row(
                "SELECT state FROM materialization_operations WHERE operation_id = ?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| StoreError::Sqlite)?
            .ok_or(StoreError::NotFound)?;
        if matches!(state.as_str(), "succeeded" | "failed" | "cancelled") {
            transaction.commit().map_err(|_| StoreError::Sqlite)?;
            return self
                .status(operation_id)
                .map(|snapshot| (snapshot, Vec::new()));
        }
        let active_requests = {
            let mut statement = transaction
                .prepare(
                    "SELECT active_request_id FROM materialization_items
                     WHERE operation_id = ?1 AND active_request_id IS NOT NULL
                     ORDER BY item_index",
                )
                .map_err(|_| StoreError::Sqlite)?;
            let rows = statement
                .query_map([operation_id], |row| row.get::<_, String>(0))
                .map_err(|_| StoreError::Sqlite)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| StoreError::Sqlite)?;
            rows
        };
        transaction
            .execute(
                "UPDATE materialization_operations
                 SET state = 'cancelled',
                     generation = generation + 1,
                     terminal_sequence = next_sequence,
                     next_sequence = next_sequence + 1
                 WHERE operation_id = ?1",
                [operation_id],
            )
            .map_err(|_| StoreError::Sqlite)?;
        transaction
            .execute(
                "UPDATE materialization_items
                 SET state = 'cancelled', active_request_id = NULL
                 WHERE operation_id = ?1 AND state IN ('pending', 'transferring')",
                [operation_id],
            )
            .map_err(|_| StoreError::Sqlite)?;
        transaction.commit().map_err(|_| StoreError::Sqlite)?;
        self.status(operation_id)
            .map(|snapshot| (snapshot, active_requests))
    }

    pub fn recover(&self, operation_id: &str) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Sqlite)?;
        let state = transaction
            .query_row(
                "SELECT state FROM materialization_operations WHERE operation_id = ?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| StoreError::Sqlite)?
            .ok_or(StoreError::NotFound)?;
        if state != "running" {
            transaction.commit().map_err(|_| StoreError::Sqlite)?;
            return Ok(());
        }
        transaction
            .execute(
                "UPDATE materialization_items
                 SET state = 'pending', progress = NULL, active_request_id = NULL
                 WHERE operation_id = ?1 AND state = 'transferring'",
                [operation_id],
            )
            .map_err(|_| StoreError::Sqlite)?;
        transaction
            .execute(
                "UPDATE materialization_operations
                 SET state = 'pending', generation = generation + 1
                 WHERE operation_id = ?1 AND state = 'running'",
                [operation_id],
            )
            .map_err(|_| StoreError::Sqlite)?;
        transaction.commit().map_err(|_| StoreError::Sqlite)
    }

    pub(crate) fn next_pending(
        &self,
        operation_id: &str,
    ) -> Result<Option<PendingItem>, StoreError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT item_index, asset_ref, connector_generation,
                        locator_key_version, locator_hmac, locator_ciphertext,
                        cloud_key_version, cloud_hmac, cloud_ciphertext, staging_filename
                 FROM materialization_items
                 WHERE operation_id = ?1 AND state = 'pending'
                 ORDER BY item_index LIMIT 1",
                [operation_id],
                |row| {
                    let asset_ref: String = row.get(1)?;
                    Ok(PendingItem {
                        index: row.get::<_, i64>(0)? as usize,
                        asset: AssetSelectionV1 {
                            asset_ref: crate::OpaqueAssetRef::parse(asset_ref).map_err(|_| {
                                rusqlite::Error::InvalidColumnType(
                                    1,
                                    "asset_ref".to_owned(),
                                    rusqlite::types::Type::Text,
                                )
                            })?,
                            connector_generation: row
                                .get::<_, Option<String>>(2)?
                                .unwrap_or_default(),
                            local_locator: crate::ProtectedLocatorV1 {
                                key_version: row.get(3)?,
                                lookup_hmac: row.get(4)?,
                                ciphertext: row.get(5)?,
                            },
                            cloud_locator: match row.get::<_, Option<u32>>(6)? {
                                Some(key_version) => Some(crate::ProtectedLocatorV1 {
                                    key_version,
                                    lookup_hmac: row.get::<_, Option<String>>(7)?.ok_or_else(
                                        || {
                                            rusqlite::Error::InvalidColumnType(
                                                7,
                                                "cloud_hmac".to_owned(),
                                                rusqlite::types::Type::Null,
                                            )
                                        },
                                    )?,
                                    ciphertext: row.get::<_, Option<String>>(8)?.ok_or_else(
                                        || {
                                            rusqlite::Error::InvalidColumnType(
                                                8,
                                                "cloud_ciphertext".to_owned(),
                                                rusqlite::types::Type::Null,
                                            )
                                        },
                                    )?,
                                }),
                                None => None,
                            },
                        },
                        staging_filename: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(|_| StoreError::Sqlite)
    }

    pub(crate) fn begin_item(
        &self,
        operation_id: &str,
        index: usize,
        resource: &ResourceDescriptorV1,
    ) -> Result<(u64, u64), StoreError> {
        let resource_json =
            serde_json::to_string(resource).map_err(|_| StoreError::Serialization)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Sqlite)?;
        let operation_generation = transaction
            .query_row(
                "SELECT generation FROM materialization_operations
                 WHERE operation_id = ?1 AND state IN ('pending', 'running')",
                [operation_id],
                |row| row.get::<_, i64>(0).map(|value| value as u64),
            )
            .optional()
            .map_err(|_| StoreError::Sqlite)?
            .ok_or(StoreError::Fenced)?;
        transaction
            .execute(
                "UPDATE materialization_operations SET state = 'running'
                 WHERE operation_id = ?1 AND state = 'pending'",
                [operation_id],
            )
            .map_err(|_| StoreError::Sqlite)?;
        let changed = transaction
            .execute(
                "UPDATE materialization_items
                 SET state = 'transferring',
                     request_generation = request_generation + 1,
                     active_request_id = NULL,
                     resource_json = ?3,
                     progress = NULL
                 WHERE operation_id = ?1 AND item_index = ?2 AND state = 'pending'",
                params![operation_id, index as i64, resource_json],
            )
            .map_err(|_| StoreError::Sqlite)?;
        if changed != 1 {
            return Err(StoreError::Fenced);
        }
        let request_generation = transaction
            .query_row(
                "SELECT request_generation FROM materialization_items
                 WHERE operation_id = ?1 AND item_index = ?2",
                params![operation_id, index as i64],
                |row| row.get::<_, i64>(0).map(|value| value as u64),
            )
            .map_err(|_| StoreError::Sqlite)?;
        transaction.commit().map_err(|_| StoreError::Sqlite)?;
        Ok((operation_generation, request_generation))
    }

    pub(crate) fn update_progress(
        &self,
        operation_id: &str,
        index: usize,
        operation_generation: u64,
        request_generation: u64,
        progress: f64,
    ) -> Result<(), StoreError> {
        if !progress.is_finite() || !(0.0..=1.0).contains(&progress) {
            return Err(StoreError::InvalidInput);
        }
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "UPDATE materialization_items SET progress = ?5
                 WHERE operation_id = ?1 AND item_index = ?2
                   AND request_generation = ?3
                   AND state = 'transferring'
                   AND (progress IS NULL OR progress <= ?5)
                   AND EXISTS (
                     SELECT 1 FROM materialization_operations
                     WHERE operation_id = ?1 AND generation = ?4 AND state = 'running'
                   )",
                params![
                    operation_id,
                    index as i64,
                    request_generation as i64,
                    operation_generation as i64,
                    progress
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        if changed != 1 {
            return Err(StoreError::Fenced);
        }
        Ok(())
    }

    pub(crate) fn register_active_request(
        &self,
        operation_id: &str,
        index: usize,
        operation_generation: u64,
        request_generation: u64,
        native_request_id: &str,
    ) -> Result<bool, StoreError> {
        if native_request_id.is_empty()
            || native_request_id.len() > 128
            || !native_request_id.is_ascii()
            || native_request_id
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(StoreError::InvalidInput);
        }
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "UPDATE materialization_items SET active_request_id = ?5
                 WHERE operation_id = ?1 AND item_index = ?2
                   AND request_generation = ?3 AND state = 'transferring'
                   AND active_request_id IS NULL
                   AND EXISTS (
                     SELECT 1 FROM materialization_operations
                     WHERE operation_id = ?1 AND generation = ?4 AND state = 'running'
                   )",
                params![
                    operation_id,
                    index as i64,
                    request_generation as i64,
                    operation_generation as i64,
                    native_request_id
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        Ok(changed == 1)
    }

    pub(crate) fn clear_active_request(
        &self,
        operation_id: &str,
        index: usize,
        request_generation: u64,
        native_request_id: &str,
    ) -> Result<(), StoreError> {
        self.connection()?
            .execute(
                "UPDATE materialization_items SET active_request_id = NULL
                 WHERE operation_id = ?1 AND item_index = ?2
                   AND request_generation = ?3 AND active_request_id = ?4",
                params![
                    operation_id,
                    index as i64,
                    request_generation as i64,
                    native_request_id
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        Ok(())
    }

    pub(crate) fn callback_allowed(
        &self,
        operation_id: &str,
        index: usize,
        operation_generation: u64,
        request_generation: u64,
        native_request_id: &str,
    ) -> Result<bool, StoreError> {
        self.connection()?
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM materialization_operations o
                    JOIN materialization_items i ON i.operation_id = o.operation_id
                    WHERE o.operation_id = ?1 AND o.generation = ?2 AND o.state = 'running'
                      AND i.item_index = ?3 AND i.request_generation = ?4
                      AND i.state = 'transferring' AND i.active_request_id = ?5
                 )",
                params![
                    operation_id,
                    operation_generation as i64,
                    index as i64,
                    request_generation as i64,
                    native_request_id
                ],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::Sqlite)
    }

    pub fn active_request_ids(&self, operation_id: &str) -> Result<Vec<String>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT active_request_id FROM materialization_items
                 WHERE operation_id = ?1 AND active_request_id IS NOT NULL
                 ORDER BY item_index",
            )
            .map_err(|_| StoreError::Sqlite)?;
        let rows = statement
            .query_map([operation_id], |row| row.get::<_, String>(0))
            .map_err(|_| StoreError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StoreError::Sqlite)?;
        Ok(rows)
    }

    pub(crate) fn record_transferred_bytes(
        &self,
        operation_id: &str,
        operation_generation: u64,
        byte_count: usize,
        max_batch_bytes: u64,
    ) -> Result<(), StoreError> {
        let byte_count = i64::try_from(byte_count).map_err(|_| StoreError::InvalidInput)?;
        let maximum = i64::try_from(max_batch_bytes).map_err(|_| StoreError::InvalidInput)?;
        let changed = self
            .connection()?
            .execute(
                "UPDATE materialization_operations
                 SET transferred_bytes = transferred_bytes + ?3
                 WHERE operation_id = ?1 AND generation = ?2 AND state = 'running'
                   AND transferred_bytes <= ?4 - ?3",
                params![
                    operation_id,
                    operation_generation as i64,
                    byte_count,
                    maximum
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        if changed != 1 {
            return Err(StoreError::BatchLimit);
        }
        Ok(())
    }

    pub(crate) fn next_request_generation(
        &self,
        operation_id: &str,
        index: usize,
        operation_generation: u64,
    ) -> Result<u64, StoreError> {
        let connection = self.connection()?;
        let changed = connection
            .execute(
                "UPDATE materialization_items
                 SET request_generation = request_generation + 1,
                     progress = NULL, active_request_id = NULL
                 WHERE operation_id = ?1 AND item_index = ?2 AND state = 'transferring'
                   AND EXISTS (
                     SELECT 1 FROM materialization_operations
                     WHERE operation_id = ?1 AND generation = ?3 AND state = 'running'
                   )",
                params![operation_id, index as i64, operation_generation as i64],
            )
            .map_err(|_| StoreError::Sqlite)?;
        if changed != 1 {
            return Err(StoreError::Fenced);
        }
        connection
            .query_row(
                "SELECT request_generation FROM materialization_items
                 WHERE operation_id = ?1 AND item_index = ?2",
                params![operation_id, index as i64],
                |row| row.get::<_, i64>(0).map(|value| value as u64),
            )
            .map_err(|_| StoreError::Sqlite)
    }

    pub(crate) fn fail_item(
        &self,
        operation_id: &str,
        index: usize,
        operation_generation: u64,
        failure_class: &str,
    ) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Sqlite)?;
        let changed = transaction
            .execute(
                "UPDATE materialization_items
                 SET state = 'failed', failure_class = ?4, active_request_id = NULL
                 WHERE operation_id = ?1 AND item_index = ?2
                   AND state IN ('pending', 'transferring')
                   AND EXISTS (
                     SELECT 1 FROM materialization_operations
                     WHERE operation_id = ?1 AND generation = ?3
                       AND state IN ('pending', 'running')
                   )",
                params![
                    operation_id,
                    index as i64,
                    operation_generation as i64,
                    failure_class
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        if changed != 1 {
            return Err(StoreError::Fenced);
        }
        transaction
            .execute(
                "UPDATE materialization_operations
                 SET state = 'failed',
                     terminal_sequence = next_sequence,
                     next_sequence = next_sequence + 1
                 WHERE operation_id = ?1 AND generation = ?2
                   AND state IN ('pending', 'running')",
                params![operation_id, operation_generation as i64],
            )
            .map_err(|_| StoreError::Sqlite)?;
        transaction.commit().map_err(|_| StoreError::Sqlite)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit(
        &self,
        operation_id: &str,
        index: usize,
        operation_generation: u64,
        request_generation: u64,
        asset: &AssetSelectionV1,
        resource: &ResourceDescriptorV1,
        classification: MaterializationClass,
        blob: &PromotedBlob,
        retrieved_at_ms: i64,
    ) -> Result<CommitOutcome, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Sqlite)?;
        let has_stable_connector = !asset.connector_generation.is_empty();
        if has_stable_connector != (classification != MaterializationClass::PickerImport) {
            return Err(StoreError::Invariant);
        }
        let connector_instance = if has_stable_connector {
            transaction
                .query_row(
                    "SELECT connector_instance FROM connector_generations
                     WHERE generation_id = ?1",
                    [&asset.connector_generation],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|_| StoreError::Sqlite)?
        } else {
            String::new()
        };
        let active: bool = transaction
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM materialization_operations o
                    JOIN materialization_items i ON i.operation_id = o.operation_id
                    WHERE o.operation_id = ?1 AND o.generation = ?2 AND o.state = 'running'
                      AND i.item_index = ?3 AND i.request_generation = ?4
                      AND i.state = 'transferring'
                 )",
                params![
                    operation_id,
                    operation_generation as i64,
                    index as i64,
                    request_generation as i64
                ],
                |row| row.get(0),
            )
            .map_err(|_| StoreError::Sqlite)?;
        if !active {
            return Err(StoreError::Fenced);
        }

        let blob_changed = transaction
            .execute(
                "INSERT INTO materialized_blobs (
                    sha256, byte_count, relative_path, created_at_ms
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(sha256) DO NOTHING",
                params![
                    blob.sha256,
                    i64::try_from(blob.byte_count).map_err(|_| StoreError::InvalidInput)?,
                    blob.relative_path,
                    retrieved_at_ms
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        if blob_changed == 0 {
            let exact = transaction
                .query_row(
                    "SELECT byte_count = ?2 AND relative_path = ?3
                     FROM materialized_blobs WHERE sha256 = ?1",
                    params![
                        blob.sha256,
                        i64::try_from(blob.byte_count).map_err(|_| StoreError::InvalidInput)?,
                        blob.relative_path
                    ],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| StoreError::Sqlite)?;
            if !exact {
                return Err(StoreError::Conflict);
            }
        }

        let source_identity = if has_stable_connector {
            format!(
                "{}\0{}",
                asset.connector_generation, asset.local_locator.lookup_hmac
            )
        } else {
            format!(
                "picker_import\0{operation_id}\0{}",
                asset.asset_ref.as_str()
            )
        };
        let source_id = format!("src-{}", &hex_sha256(source_identity.as_bytes())[..32]);
        let connector_generation =
            has_stable_connector.then_some(asset.connector_generation.as_str());
        transaction
            .execute(
                "INSERT INTO photo_sources (
                    source_id, connector_generation, locator_key_version, locator_hmac,
                    locator_ciphertext, cloud_key_version, cloud_hmac, cloud_ciphertext
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT DO NOTHING",
                params![
                    source_id,
                    connector_generation,
                    asset.local_locator.key_version,
                    asset.local_locator.lookup_hmac,
                    asset.local_locator.ciphertext,
                    asset.cloud_locator.as_ref().map(|value| value.key_version),
                    asset
                        .cloud_locator
                        .as_ref()
                        .map(|value| value.lookup_hmac.as_str()),
                    asset
                        .cloud_locator
                        .as_ref()
                        .map(|value| value.ciphertext.as_str()),
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        let persisted_source = transaction
            .query_row(
                "SELECT source_id FROM photo_sources WHERE source_id = ?1",
                [&source_id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| StoreError::Sqlite)?;
        if persisted_source != source_id {
            return Err(StoreError::Invariant);
        }

        let revision_id = format!(
            "rev-{}",
            &hex_sha256(
                format!("{}\0{}\0{}", source_id, resource.resource_ref, blob.sha256).as_bytes()
            )[..32]
        );
        let provenance = ProvenanceRecord {
            schema_version: crate::CONTRACT_SCHEMA_VERSION,
            connector_instance,
            connector_generation: asset.connector_generation.clone(),
            locator_key_version: if has_stable_connector {
                asset.local_locator.key_version
            } else {
                0
            },
            locator_hmac: if has_stable_connector {
                asset.local_locator.lookup_hmac.clone()
            } else {
                String::new()
            },
            cloud_locator_hmac: if has_stable_connector {
                asset
                    .cloud_locator
                    .as_ref()
                    .map(|value| value.lookup_hmac.clone())
            } else {
                None
            },
            resource: resource.clone(),
            representation_policy: RepresentationPolicy::OriginalPrimaryV1,
            classification,
            blob_sha256: blob.sha256.clone(),
            blob_byte_count: blob.byte_count,
            operation_id: operation_id.to_owned(),
            retrieved_at_ms,
        };
        let provenance_json =
            serde_json::to_string(&provenance).map_err(|_| StoreError::Serialization)?;
        let revision_changed = transaction
            .execute(
                "INSERT INTO source_revisions (
                    revision_id, source_id, resource_ref, resource_uti,
                    representation_policy, classification, blob_sha256, blob_byte_count,
                    operation_id, retrieved_at_ms, provenance_json
                 ) VALUES (
                    ?1, ?2, ?3, ?4, 'original_primary_v1', ?5, ?6, ?7, ?8, ?9, ?10
                 )
                 ON CONFLICT(source_id, resource_ref, blob_sha256) DO NOTHING",
                params![
                    revision_id,
                    source_id,
                    resource.resource_ref,
                    resource.uniform_type_identifier,
                    class_name(classification),
                    blob.sha256,
                    i64::try_from(blob.byte_count).map_err(|_| StoreError::InvalidInput)?,
                    operation_id,
                    retrieved_at_ms,
                    provenance_json,
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        let persisted_revision = transaction
            .query_row(
                "SELECT revision_id FROM source_revisions
                 WHERE source_id = ?1 AND resource_ref = ?2 AND blob_sha256 = ?3",
                params![source_id, resource.resource_ref, blob.sha256],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| StoreError::Sqlite)?;

        let item_changed = transaction
            .execute(
                "UPDATE materialization_items
                 SET state = 'succeeded', classification = ?5, progress = 1.0,
                     revision_id = ?6, active_request_id = NULL
                 WHERE operation_id = ?1 AND item_index = ?2
                   AND request_generation = ?3 AND state = 'transferring'
                   AND EXISTS (
                       SELECT 1 FROM materialization_operations
                       WHERE operation_id = ?1 AND generation = ?4 AND state = 'running'
                   )",
                params![
                    operation_id,
                    index as i64,
                    request_generation as i64,
                    operation_generation as i64,
                    class_name(classification),
                    persisted_revision,
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        if item_changed != 1 {
            return Err(StoreError::Fenced);
        }
        transaction
            .execute(
                "UPDATE materialization_operations
                 SET completed_count = completed_count + 1
                 WHERE operation_id = ?1 AND generation = ?2 AND state = 'running'",
                params![operation_id, operation_generation as i64],
            )
            .map_err(|_| StoreError::Sqlite)?;
        transaction
            .execute(
                "UPDATE materialization_operations
                 SET state = 'succeeded',
                     terminal_sequence = next_sequence,
                     next_sequence = next_sequence + 1
                 WHERE operation_id = ?1 AND generation = ?2 AND state = 'running'
                   AND completed_count = total_count",
                params![operation_id, operation_generation as i64],
            )
            .map_err(|_| StoreError::Sqlite)?;
        transaction.commit().map_err(|_| StoreError::Sqlite)?;
        Ok(if revision_changed == 1 {
            CommitOutcome::InsertedRevision
        } else {
            CommitOutcome::ReplayedRevision
        })
    }

    pub fn revisions(&self) -> Result<Vec<RevisionRecord>, StoreError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT revision_id, source_id, blob_sha256, operation_id, provenance_json
                 FROM source_revisions ORDER BY revision_id",
            )
            .map_err(|_| StoreError::Sqlite)?;
        let rows = statement
            .query_map([], |row| {
                let encoded: String = row.get(4)?;
                let provenance = serde_json::from_str(&encoded).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        encoded.len(),
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;
                Ok(RevisionRecord {
                    revision_id: row.get(0)?,
                    source_id: row.get(1)?,
                    blob_sha256: row.get(2)?,
                    operation_id: row.get(3)?,
                    provenance,
                })
            })
            .map_err(|_| StoreError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StoreError::Sqlite)?;
        Ok(rows)
    }

    pub fn audit(&self) -> Result<DatabaseAudit, StoreError> {
        let connection = self.connection()?;
        let integrity_check = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|_| StoreError::Sqlite)?;
        let foreign_key_violations = {
            let mut statement = connection
                .prepare("PRAGMA foreign_key_check")
                .map_err(|_| StoreError::Sqlite)?;
            let count = statement
                .query([])
                .map_err(|_| StoreError::Sqlite)?
                .mapped(|_| Ok(()))
                .count();
            count
        };
        Ok(DatabaseAudit {
            integrity_check,
            foreign_key_violations,
            operation_count: count(&connection, "materialization_operations")?,
            connector_generation_count: count(&connection, "connector_generations")?,
            blob_count: count(&connection, "materialized_blobs")?,
            source_count: count(&connection, "photo_sources")?,
            revision_count: count(&connection, "source_revisions")?,
            referenced_blob_count: connection
                .query_row(
                    "SELECT COUNT(DISTINCT blob_sha256) FROM source_revisions",
                    [],
                    |row| row.get::<_, i64>(0).map(|value| value as usize),
                )
                .map_err(|_| StoreError::Sqlite)?,
        })
    }

    pub fn original_filename_column_count(&self) -> Result<usize, StoreError> {
        self.connection()?
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('photo_sources')
                 WHERE name LIKE '%filename%'",
                [],
                |row| row.get::<_, i64>(0).map(|value| value as usize),
            )
            .map_err(|_| StoreError::Sqlite)
    }

    fn connection(&self) -> Result<Connection, StoreError> {
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| StoreError::Sqlite)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| StoreError::Sqlite)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 PRAGMA fullfsync = ON;
                 PRAGMA checkpoint_fullfsync = ON;
                 PRAGMA trusted_schema = OFF;",
            )
            .map_err(|_| StoreError::Sqlite)?;
        Ok(connection)
    }
}

fn class_name(value: MaterializationClass) -> &'static str {
    match value {
        MaterializationClass::Local => "local",
        MaterializationClass::Cloud => "cloud",
        MaterializationClass::PickerImport => "picker_import",
    }
}

fn parse_operation_state(value: &str) -> OperationState {
    match value {
        "pending" => OperationState::Pending,
        "running" => OperationState::Running,
        "succeeded" => OperationState::Succeeded,
        "failed" => OperationState::Failed,
        "cancelled" => OperationState::Cancelled,
        _ => OperationState::Failed,
    }
}

fn count(connection: &Connection, table: &str) -> Result<usize, StoreError> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    connection
        .query_row(&sql, [], |row| {
            row.get::<_, i64>(0).map(|value| value as usize)
        })
        .map_err(|_| StoreError::Sqlite)
}
