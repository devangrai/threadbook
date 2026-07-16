use crate::database::stable_id;
use crate::gmail_sync::{
    GmailSyncStore, HistoryId, RevisionEffect, SyncBatch, SyncCommit, SyncError, SyncKey,
    GMAIL_RAW_MESSAGE_LIMIT,
};
use crate::imports::{prepare_message_parts, PreparedMimePart};
use crate::{BlobRecord, BlobStore, Database, PlatformError};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use wardrobe_core::{GmailConnectorPortError, GmailConnectorPortErrorKind, GmailSyncSummaryV1};

const EMPTY_MANIFEST_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct PreparedEffect {
    message_id: String,
    history_id: String,
    availability: &'static str,
    reason: &'static str,
    graph_sha256: String,
    blob: Option<BlobRecord>,
    mime_manifest_sha256: String,
    evidence_manifest_sha256: String,
    parts: Vec<PreparedMimePart>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GmailSyncCommandKind {
    Connect,
    Sync,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GmailOperationCommit {
    pub summary: GmailSyncSummaryV1,
    pub commit: SyncCommit,
}

impl Database {
    pub fn initialize_gmail_scope(
        &self,
        account_key: &str,
        credential_locator: &str,
        scope_id: &str,
        scope_fingerprint: &str,
        label_id: &str,
        parser_revision: &str,
        materialization_revision: &str,
        now_ms: i64,
    ) -> Result<(), PlatformError> {
        validate_hash(account_key)?;
        validate_hash(scope_fingerprint)?;
        validate_provider_value(label_id)?;
        validate_revision_name(parser_revision)?;
        validate_revision_name(materialization_revision)?;
        uuid::Uuid::parse_str(scope_id)
            .map_err(|_| PlatformError::InvalidInput("gmail_scope_id"))?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO gmail_accounts(
                account_key, credential_locator, created_at_ms
             ) VALUES (?1, ?2, ?3)
             ON CONFLICT(account_key) DO UPDATE SET
                credential_locator = CASE
                    WHEN gmail_accounts.credential_locator IS NULL
                    THEN excluded.credential_locator
                    ELSE gmail_accounts.credential_locator
                END",
            params![account_key, credential_locator, now_ms],
        )?;
        let stored_locator: String = transaction.query_row(
            "SELECT credential_locator FROM gmail_accounts WHERE account_key = ?1",
            [account_key],
            |row| row.get(0),
        )?;
        if stored_locator != credential_locator {
            return Err(PlatformError::Conflict("gmail_account_credential"));
        }
        transaction.execute(
            "INSERT INTO gmail_scopes(
                scope_id, account_key, scope_fingerprint, label_id, oauth_scope,
                parser_revision, materialization_revision, created_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4,
                'openid https://www.googleapis.com/auth/gmail.readonly',
                ?5, ?6, ?7
             )
             ON CONFLICT(account_key, scope_fingerprint) DO NOTHING",
            params![
                scope_id,
                account_key,
                scope_fingerprint,
                label_id,
                parser_revision,
                materialization_revision,
                now_ms
            ],
        )?;
        let stored: (String, String) = transaction.query_row(
            "SELECT scope_id, label_id FROM gmail_scopes
             WHERE account_key = ?1 AND scope_fingerprint = ?2",
            params![account_key, scope_fingerprint],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if stored != (scope_id.to_owned(), label_id.to_owned()) {
            return Err(PlatformError::Conflict("gmail_scope_identity"));
        }
        transaction.commit()?;
        Ok(())
    }
}

impl GmailSyncStore for Database {
    fn checkpoint(&self, key: &SyncKey) -> Result<Option<String>, SyncError> {
        ensure_scope_key(self, key)?;
        self.connection()
            .map_err(|_| SyncError::Store)?
            .query_row(
                "SELECT history_id FROM gmail_checkpoints WHERE scope_id = ?1",
                [&key.scope_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| SyncError::Store)
    }

    fn known_message_ids(&self, key: &SyncKey) -> Result<Vec<String>, SyncError> {
        ensure_scope_key(self, key)?;
        let connection = self.connection().map_err(|_| SyncError::Store)?;
        let mut statement = connection
            .prepare(
                "SELECT source.gmail_message_id
                 FROM gmail_scope_sources membership
                 JOIN gmail_provider_sources source
                   ON source.provider_source_id = membership.provider_source_id
                 WHERE membership.scope_id = ?1
                 ORDER BY source.gmail_message_id",
            )
            .map_err(|_| SyncError::Store)?;
        let rows = statement
            .query_map([&key.scope_id], |row| row.get::<_, String>(0))
            .map_err(|_| SyncError::Store)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SyncError::Store)?;
        Ok(rows)
    }

    fn commit(&self, key: &SyncKey, batch: &SyncBatch) -> Result<SyncCommit, SyncError> {
        commit_batch(self, key, batch, None).map(|value| value.commit)
    }
}

impl Database {
    #[allow(clippy::too_many_arguments)]
    pub fn commit_gmail_operation(
        &self,
        key: &SyncKey,
        batch: &SyncBatch,
        request_id: &str,
        envelope: &str,
        command: GmailSyncCommandKind,
        account_key: &str,
        scope_id: &str,
    ) -> Result<GmailOperationCommit, GmailConnectorPortError> {
        let context = GmailOperationContext {
            request_id,
            envelope,
            command,
            account_key,
            scope_id,
        };
        commit_batch(self, key, batch, Some(context)).map_err(map_sync_port_error)
    }
}

struct GmailOperationContext<'a> {
    request_id: &'a str,
    envelope: &'a str,
    command: GmailSyncCommandKind,
    account_key: &'a str,
    scope_id: &'a str,
}

fn commit_batch(
    database: &Database,
    key: &SyncKey,
    batch: &SyncBatch,
    operation: Option<GmailOperationContext<'_>>,
) -> Result<GmailOperationCommit, SyncError> {
    ensure_scope_key(database, key)?;
    let prepared = prepare_effects(database, batch)?;
    let now_ms = unix_now_ms().map_err(|_| SyncError::Store)?;
    let mut connection = database.connection().map_err(|_| SyncError::Store)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| SyncError::Store)?;
    compare_checkpoint(&transaction, key, batch.expected_checkpoint.as_deref())?;

    let mut commit = SyncCommit::default();
    for message_id in &batch.discovered_message_ids {
        let (_, inserted) = ensure_provider_source(&transaction, key, message_id, now_ms)?;
        commit.sources_inserted += usize::from(inserted);
    }
    for effect in &prepared {
        let (provider_source_id, inserted) =
            ensure_provider_source(&transaction, key, &effect.message_id, now_ms)?;
        commit.sources_inserted += usize::from(inserted);
        transaction
            .execute(
                "INSERT OR IGNORE INTO gmail_scope_sources(
                    scope_id, provider_source_id, account_key, first_seen_at_ms
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![key.scope_id, provider_source_id, key.account_key, now_ms],
            )
            .map_err(|_| SyncError::Store)?;
        let inserted_revision =
            insert_or_replay_revision(&transaction, &provider_source_id, effect, now_ms)?;
        if inserted_revision {
            commit.revisions_inserted += 1;
        } else {
            commit.revisions_replayed += 1;
        }
        if let Some(operation) = operation.as_ref() {
            let revision_id = stable_id(
                "gmail-revision",
                &format!("{provider_source_id}\0{}", effect.history_id),
            );
            transaction
                .execute(
                    "INSERT OR IGNORE INTO gmail_operation_revisions(request_id, revision_id)
                     VALUES (?1, ?2)",
                    params![operation.request_id, revision_id],
                )
                .map_err(|_| SyncError::Store)?;
        }
    }

    transaction
        .execute(
            "INSERT INTO gmail_checkpoints(scope_id, history_id, updated_at_ms)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(scope_id) DO UPDATE SET
                history_id = excluded.history_id,
                updated_at_ms = excluded.updated_at_ms",
            params![key.scope_id, batch.next_checkpoint.as_str(), now_ms],
        )
        .map_err(|_| SyncError::Store)?;
    if commit.revisions_inserted > 0 {
        transaction
            .execute(
                "UPDATE revision_state
                 SET evidence_generation = evidence_generation + 1
                 WHERE singleton = 1",
                [],
            )
            .map_err(|_| SyncError::Store)?;
    }
    let evidence_generation: i64 = transaction
        .query_row(
            "SELECT evidence_generation FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| SyncError::Store)?;
    commit.evidence_generation =
        u64::try_from(evidence_generation).map_err(|_| SyncError::Store)?;
    let summary = sync_summary(batch, commit)?;

    if let Some(operation) = operation {
        finish_sync_operation(&transaction, &operation, &summary, now_ms)?;
    }
    transaction.commit().map_err(|_| SyncError::Store)?;
    Ok(GmailOperationCommit { summary, commit })
}

fn sync_summary(batch: &SyncBatch, commit: SyncCommit) -> Result<GmailSyncSummaryV1, SyncError> {
    let unavailable = batch
        .effects
        .iter()
        .filter(|effect| matches!(effect, RevisionEffect::Unavailable { .. }))
        .count();
    let available = batch.effects.len().saturating_sub(unavailable);
    let imported = commit.sources_inserted.min(available);
    Ok(GmailSyncSummaryV1 {
        pages_scanned: batch
            .pages
            .try_into()
            .map_err(|_| SyncError::ScopeTooLarge)?,
        unique_messages: batch
            .effects
            .len()
            .try_into()
            .map_err(|_| SyncError::ScopeTooLarge)?,
        messages_imported: imported.try_into().map_err(|_| SyncError::ScopeTooLarge)?,
        messages_updated: available
            .saturating_sub(imported)
            .try_into()
            .map_err(|_| SyncError::ScopeTooLarge)?,
        messages_unavailable: unavailable
            .try_into()
            .map_err(|_| SyncError::ScopeTooLarge)?,
        raw_bytes_read: batch.raw_bytes as u64,
    })
}

fn finish_sync_operation(
    transaction: &Transaction<'_>,
    operation: &GmailOperationContext<'_>,
    summary: &GmailSyncSummaryV1,
    now_ms: i64,
) -> Result<(), SyncError> {
    let (command_name, response) = match operation.command {
        GmailSyncCommandKind::Connect => (
            "connect_gmail_v1",
            serde_json::json!({
                "schema_version": 1,
                "request_id": operation.request_id,
                "status": "connected",
                "user_action": "none",
                "summary": summary,
                "replay_status": "created"
            }),
        ),
        GmailSyncCommandKind::Sync => (
            "sync_gmail_v1",
            serde_json::json!({
                "schema_version": 1,
                "request_id": operation.request_id,
                "status": "connected",
                "user_action": "none",
                "summary": summary,
                "replay_status": "created"
            }),
        ),
    };
    let response_json = serde_json::to_string(&response).map_err(|_| SyncError::Store)?;
    transaction
        .execute(
            "UPDATE gmail_connector_state
             SET status = 'connected', account_key = ?1, scope_id = ?2,
                 revocation_state = NULL, updated_at_ms = ?3
             WHERE singleton = 1",
            params![operation.account_key, operation.scope_id, now_ms],
        )
        .map_err(|_| SyncError::Store)?;
    transaction
        .execute(
            "UPDATE gmail_operations
             SET stage = 'terminal', response_json = ?2, updated_at_ms = ?3
             WHERE request_id = ?1",
            params![operation.request_id, response_json, now_ms],
        )
        .map_err(|_| SyncError::Store)?;
    transaction
        .execute(
            "INSERT INTO command_receipts(
                request_id, command_name, envelope_hash, response_json, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                operation.request_id,
                command_name,
                operation.envelope,
                response_json,
                now_ms
            ],
        )
        .map_err(|_| SyncError::Store)?;
    Ok(())
}

fn map_sync_port_error(error: SyncError) -> GmailConnectorPortError {
    let kind = match error {
        SyncError::InvalidConfiguration => GmailConnectorPortErrorKind::InvalidState,
        SyncError::ScopeTooLarge => GmailConnectorPortErrorKind::ScopeTooLarge,
        SyncError::Authentication => GmailConnectorPortErrorKind::CredentialUnavailable,
        SyncError::Permission => GmailConnectorPortErrorKind::PermissionDenied,
        SyncError::RateLimited
        | SyncError::Quota
        | SyncError::Transport
        | SyncError::Server
        | SyncError::Timeout
        | SyncError::Cancelled => GmailConnectorPortErrorKind::Unavailable,
        SyncError::MalformedRequest | SyncError::MalformedResponse => {
            GmailConnectorPortErrorKind::MalformedProviderOutput
        }
        SyncError::RevisionCollision => GmailConnectorPortErrorKind::DataIntegrity,
        SyncError::CompareAndSwap => GmailConnectorPortErrorKind::Conflict,
        SyncError::Store => GmailConnectorPortErrorKind::Internal,
    };
    GmailConnectorPortError { kind }
}

fn prepare_effects(
    database: &Database,
    batch: &SyncBatch,
) -> Result<Vec<PreparedEffect>, SyncError> {
    let blobs = BlobStore::new(&database.paths);
    let mut seen = BTreeSet::new();
    let mut prepared = Vec::with_capacity(batch.effects.len());
    for effect in &batch.effects {
        let identity = (
            effect.message_id().to_owned(),
            effect.revision().as_str().to_owned(),
        );
        if !seen.insert(identity) {
            return Err(SyncError::RevisionCollision);
        }
        match effect {
            RevisionEffect::Available {
                message_id,
                revision,
                raw,
            } => {
                let parts = prepare_message_parts(raw).map_err(|_| SyncError::MalformedResponse)?;
                let blob = blobs
                    .put(raw, None, GMAIL_RAW_MESSAGE_LIMIT as u64)
                    .map_err(|_| SyncError::Store)?;
                let mime_json =
                    serde_json::to_vec(&parts).map_err(|_| SyncError::MalformedResponse)?;
                let mime_manifest_sha256 = digest(&mime_json);
                let evidence_ordinals = parts
                    .iter()
                    .filter(|part| part.is_image)
                    .map(|part| part.ordinal)
                    .collect::<Vec<_>>();
                let evidence_json = serde_json::to_vec(&evidence_ordinals)
                    .map_err(|_| SyncError::MalformedResponse)?;
                let evidence_manifest_sha256 = digest(&evidence_json);
                let graph_sha256 = digest(
                    format!(
                        "available\0{}\0{}\0{}",
                        blob.sha256, mime_manifest_sha256, evidence_manifest_sha256
                    )
                    .as_bytes(),
                );
                prepared.push(PreparedEffect {
                    message_id: message_id.clone(),
                    history_id: revision.as_str().to_owned(),
                    availability: "available",
                    reason: "materialized",
                    graph_sha256,
                    blob: Some(blob),
                    mime_manifest_sha256,
                    evidence_manifest_sha256,
                    parts,
                });
            }
            RevisionEffect::Unavailable {
                message_id,
                revision,
                reason,
            } => {
                let reason = reason.as_db();
                prepared.push(PreparedEffect {
                    message_id: message_id.clone(),
                    history_id: revision.as_str().to_owned(),
                    availability: "unavailable",
                    reason,
                    graph_sha256: digest(
                        format!("unavailable\0{reason}\0{EMPTY_MANIFEST_SHA256}").as_bytes(),
                    ),
                    blob: None,
                    mime_manifest_sha256: EMPTY_MANIFEST_SHA256.to_owned(),
                    evidence_manifest_sha256: EMPTY_MANIFEST_SHA256.to_owned(),
                    parts: Vec::new(),
                });
            }
        }
    }
    Ok(prepared)
}

fn compare_checkpoint(
    transaction: &Transaction<'_>,
    key: &SyncKey,
    expected: Option<&str>,
) -> Result<(), SyncError> {
    let current = transaction
        .query_row(
            "SELECT history_id FROM gmail_checkpoints WHERE scope_id = ?1",
            [&key.scope_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| SyncError::Store)?;
    if current.as_deref() != expected {
        return Err(SyncError::CompareAndSwap);
    }
    Ok(())
}

fn ensure_provider_source(
    transaction: &Transaction<'_>,
    key: &SyncKey,
    message_id: &str,
    now_ms: i64,
) -> Result<(String, bool), SyncError> {
    validate_provider_value(message_id).map_err(|_| SyncError::MalformedResponse)?;
    let provider_source_id = stable_id(
        "gmail-provider-source",
        &format!("{}\0{message_id}", key.account_key),
    );
    let inserted = transaction
        .execute(
            "INSERT OR IGNORE INTO gmail_provider_sources(
                provider_source_id, account_key, gmail_message_id, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4)",
            params![provider_source_id, key.account_key, message_id, now_ms],
        )
        .map_err(|_| SyncError::Store)?
        == 1;
    let stored: (String, String) = transaction
        .query_row(
            "SELECT account_key, gmail_message_id
             FROM gmail_provider_sources WHERE provider_source_id = ?1",
            [&provider_source_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| SyncError::Store)?;
    if stored != (key.account_key.clone(), message_id.to_owned()) {
        return Err(SyncError::RevisionCollision);
    }
    Ok((provider_source_id, inserted))
}

fn insert_or_replay_revision(
    transaction: &Transaction<'_>,
    provider_source_id: &str,
    effect: &PreparedEffect,
    now_ms: i64,
) -> Result<bool, SyncError> {
    let revision_id = stable_id(
        "gmail-revision",
        &format!("{provider_source_id}\0{}", effect.history_id),
    );
    if let Some(existing) = transaction
        .query_row(
            "SELECT availability, reason, graph_sha256
             FROM gmail_source_revisions
             WHERE provider_source_id = ?1 AND history_id = ?2",
            params![provider_source_id, effect.history_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| SyncError::Store)?
    {
        if existing
            != (
                effect.availability.to_owned(),
                effect.reason.to_owned(),
                effect.graph_sha256.clone(),
            )
            || !materialization_matches(transaction, &revision_id, effect)?
        {
            return Err(SyncError::RevisionCollision);
        }
        advance_head(
            transaction,
            provider_source_id,
            &revision_id,
            &effect.history_id,
            effect.availability,
            now_ms,
        )?;
        return Ok(false);
    }

    transaction
        .execute(
            "INSERT INTO gmail_source_revisions(
                revision_id, provider_source_id, history_id, availability,
                reason, graph_sha256, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                revision_id,
                provider_source_id,
                effect.history_id,
                effect.availability,
                effect.reason,
                effect.graph_sha256,
                now_ms
            ],
        )
        .map_err(|_| SyncError::Store)?;

    let local_source_id = stable_id("gmail-local-source", &revision_id);
    let provenance_id = stable_id("gmail-source-provenance", &revision_id);
    if let Some(blob) = &effect.blob {
        insert_blob(transaction, blob, now_ms)?;
    }
    transaction
        .execute(
            "INSERT INTO local_sources(
                source_id, source_kind, identity_key, canonical_locator,
                raw_sha256, blob_sha256, byte_length, media_type, status,
                no_blob_reason, created_at_ms, updated_at_ms
             ) VALUES (
                ?1, 'eml', ?2, ?3, ?4, ?4, ?5, 'message/rfc822', ?6, ?7, ?8, ?8
             )",
            params![
                local_source_id,
                format!("gmail-revision:{revision_id}"),
                format!("gmail-revision:{revision_id}"),
                effect.blob.as_ref().map(|blob| blob.sha256.as_str()),
                effect.blob.as_ref().map(|blob| blob.byte_length as i64),
                if effect.blob.is_some() {
                    "imported"
                } else {
                    "unavailable"
                },
                if effect.blob.is_some() {
                    None
                } else {
                    Some(effect.reason)
                },
                now_ms
            ],
        )
        .map_err(|_| SyncError::Store)?;
    transaction
        .execute(
            "INSERT INTO source_provenance(
                provenance_id, source_id, request_id, observed_locator,
                raw_sha256, blob_sha256, observed_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
            params![
                provenance_id,
                local_source_id,
                format!("gmail-revision:{revision_id}"),
                format!("gmail-revision:{revision_id}"),
                effect.blob.as_ref().map(|blob| blob.sha256.as_str()),
                now_ms
            ],
        )
        .map_err(|_| SyncError::Store)?;
    insert_parts(transaction, &local_source_id, &effect.parts, now_ms)?;
    transaction
        .execute(
            "INSERT INTO gmail_revision_materializations(
                revision_id, local_source_id, source_provenance_id, blob_sha256,
                mime_manifest_sha256, evidence_manifest_sha256, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                revision_id,
                local_source_id,
                provenance_id,
                effect.blob.as_ref().map(|blob| blob.sha256.as_str()),
                effect.mime_manifest_sha256,
                effect.evidence_manifest_sha256,
                now_ms
            ],
        )
        .map_err(|_| SyncError::Store)?;
    advance_head(
        transaction,
        provider_source_id,
        &revision_id,
        &effect.history_id,
        effect.availability,
        now_ms,
    )?;
    Ok(true)
}

fn materialization_matches(
    transaction: &Transaction<'_>,
    revision_id: &str,
    effect: &PreparedEffect,
) -> Result<bool, SyncError> {
    let expected_blob = effect.blob.as_ref().map(|blob| blob.sha256.as_str());
    let row = transaction
        .query_row(
            "SELECT materialization.local_source_id,
                    materialization.blob_sha256,
                    materialization.mime_manifest_sha256,
                    materialization.evidence_manifest_sha256,
                    source.status, source.no_blob_reason,
                    source.blob_sha256, provenance.blob_sha256
             FROM gmail_revision_materializations materialization
             JOIN local_sources source
               ON source.source_id = materialization.local_source_id
             JOIN source_provenance provenance
               ON provenance.provenance_id = materialization.source_provenance_id
             WHERE materialization.revision_id = ?1",
            [revision_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| SyncError::Store)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let (actual_mime, actual_evidence) =
        actual_materialization_manifests(transaction, &row.0, effect.parts.len())?;
    Ok(row.1.as_deref() == expected_blob
        && row.2 == effect.mime_manifest_sha256
        && row.3 == effect.evidence_manifest_sha256
        && actual_mime == row.2
        && actual_evidence == row.3
        && row.4
            == if effect.blob.is_some() {
                "imported"
            } else {
                "unavailable"
            }
        && row.5.as_deref()
            == if effect.blob.is_some() {
                None
            } else {
                Some(effect.reason)
            }
        && row.6.as_deref() == expected_blob
        && row.7.as_deref() == expected_blob)
}

fn actual_materialization_manifests(
    transaction: &Transaction<'_>,
    source_id: &str,
    expected_part_count: usize,
) -> Result<(String, String), SyncError> {
    let row_limit = i64::try_from(expected_part_count.saturating_add(1))
        .map_err(|_| SyncError::RevisionCollision)?;
    let mut evidence_statement = transaction
        .prepare(
            "SELECT evidence_id, part_id
             FROM evidence
             WHERE source_id = ?1 AND evidence_kind = 'message_attachment'
             ORDER BY part_id, evidence_id
             LIMIT ?2",
        )
        .map_err(|_| SyncError::Store)?;
    let evidence_rows = evidence_statement
        .query_map(params![source_id, row_limit], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(|_| SyncError::Store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SyncError::Store)?;
    let mut image_evidence = evidence_rows
        .into_iter()
        .map(|(evidence_id, part_id)| {
            part_id
                .map(|part_id| (part_id, evidence_id))
                .ok_or(SyncError::RevisionCollision)
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;

    let mut statement = transaction
        .prepare(
            "SELECT part.part_id, part.ordinal, parent.ordinal, parent.source_id,
                    part.content_type, part.content_disposition, part.content_id,
                    part.body_kind, part.decoded_bytes
             FROM mime_parts part
             LEFT JOIN mime_parts parent ON parent.part_id = part.parent_part_id
             WHERE part.source_id = ?1
             ORDER BY part.ordinal
             LIMIT ?2",
        )
        .map_err(|_| SyncError::Store)?;
    let rows = statement
        .query_map(params![source_id, row_limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, i64>(8)?,
            ))
        })
        .map_err(|_| SyncError::Store)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SyncError::Store)?;
    if rows.len() != expected_part_count {
        return Err(SyncError::RevisionCollision);
    }

    let mut parts = Vec::with_capacity(rows.len());
    let mut evidence_ordinals = Vec::new();
    for row in rows {
        let ordinal = usize::try_from(row.1).map_err(|_| SyncError::RevisionCollision)?;
        let parent_ordinal = row
            .2
            .map(|value| usize::try_from(value).map_err(|_| SyncError::RevisionCollision))
            .transpose()?;
        if row.3.as_deref().is_some_and(|parent| parent != source_id)
            || row.0 != stable_id("mime-part", &format!("{source_id}:{ordinal}"))
        {
            return Err(SyncError::RevisionCollision);
        }
        let evidence_id = image_evidence.remove(&row.0);
        let is_image = evidence_id.is_some();
        if let Some(evidence_id) = evidence_id {
            let expected_id = stable_id("evidence", &format!("{source_id}:{}", row.0));
            if evidence_id != expected_id {
                return Err(SyncError::RevisionCollision);
            }
            evidence_ordinals.push(ordinal);
        }
        parts.push(PreparedMimePart {
            ordinal,
            parent_ordinal,
            content_type: row.4,
            disposition: row.5,
            content_id: row.6,
            body_kind: stored_body_kind(&row.7)?,
            decoded_bytes: usize::try_from(row.8).map_err(|_| SyncError::RevisionCollision)?,
            is_image,
        });
    }
    if !image_evidence.is_empty() {
        return Err(SyncError::RevisionCollision);
    }
    let mime_json = serde_json::to_vec(&parts).map_err(|_| SyncError::RevisionCollision)?;
    let evidence_json =
        serde_json::to_vec(&evidence_ordinals).map_err(|_| SyncError::RevisionCollision)?;
    Ok((digest(&mime_json), digest(&evidence_json)))
}

fn stored_body_kind(value: &str) -> Result<&'static str, SyncError> {
    match value {
        "text" => Ok("text"),
        "html" => Ok("html"),
        "binary" => Ok("binary"),
        "multipart" => Ok("multipart"),
        "message" => Ok("message"),
        "empty" => Ok("empty"),
        _ => Err(SyncError::RevisionCollision),
    }
}

fn insert_parts(
    transaction: &Transaction<'_>,
    source_id: &str,
    parts: &[PreparedMimePart],
    now_ms: i64,
) -> Result<(), SyncError> {
    for part in parts {
        let part_id = stable_id("mime-part", &format!("{source_id}:{}", part.ordinal));
        let parent_part_id = part
            .parent_ordinal
            .map(|ordinal| stable_id("mime-part", &format!("{source_id}:{ordinal}")));
        transaction
            .execute(
                "INSERT INTO mime_parts(
                    part_id, source_id, parent_part_id, ordinal, content_type,
                    content_disposition, content_id, body_kind, decoded_bytes
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    part_id,
                    source_id,
                    parent_part_id,
                    part.ordinal as i64,
                    part.content_type,
                    part.disposition,
                    part.content_id,
                    part.body_kind,
                    part.decoded_bytes as i64
                ],
            )
            .map_err(|_| SyncError::Store)?;
        if part.is_image {
            transaction
                .execute(
                    "INSERT INTO evidence(
                        evidence_id, source_id, part_id, evidence_kind, state,
                        created_at_ms, updated_at_ms
                     ) VALUES (?1, ?2, ?3, 'message_attachment', 'unresolved', ?4, ?4)",
                    params![
                        stable_id("evidence", &format!("{source_id}:{part_id}")),
                        source_id,
                        part_id,
                        now_ms
                    ],
                )
                .map_err(|_| SyncError::Store)?;
        }
    }
    Ok(())
}

fn advance_head(
    transaction: &Transaction<'_>,
    provider_source_id: &str,
    revision_id: &str,
    history_id: &str,
    availability: &str,
    now_ms: i64,
) -> Result<(), SyncError> {
    let current = transaction
        .query_row(
            "SELECT revision.history_id
             FROM gmail_source_heads head
             JOIN gmail_source_revisions revision
               ON revision.revision_id = head.head_revision_id
             WHERE head.provider_source_id = ?1",
            [provider_source_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| SyncError::Store)?;
    let should_advance = match current {
        None => true,
        Some(current) => {
            let current = HistoryId::parse(current)?;
            let candidate = HistoryId::parse(history_id.to_owned())?;
            candidate > current
        }
    };
    if should_advance {
        transaction
            .execute(
                "INSERT INTO gmail_source_heads(
                    provider_source_id, head_revision_id, availability, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(provider_source_id) DO UPDATE SET
                    head_revision_id = excluded.head_revision_id,
                    availability = excluded.availability,
                    updated_at_ms = excluded.updated_at_ms",
                params![provider_source_id, revision_id, availability, now_ms],
            )
            .map_err(|_| SyncError::Store)?;
    }
    Ok(())
}

fn insert_blob(
    transaction: &Transaction<'_>,
    blob: &BlobRecord,
    now_ms: i64,
) -> Result<(), SyncError> {
    transaction
        .execute(
            "INSERT OR IGNORE INTO blobs(sha256, byte_length, created_at_ms)
             VALUES (?1, ?2, ?3)",
            params![blob.sha256, blob.byte_length as i64, now_ms],
        )
        .map_err(|_| SyncError::Store)?;
    let length: i64 = transaction
        .query_row(
            "SELECT byte_length FROM blobs WHERE sha256 = ?1",
            [&blob.sha256],
            |row| row.get(0),
        )
        .map_err(|_| SyncError::Store)?;
    if length != blob.byte_length as i64 {
        return Err(SyncError::RevisionCollision);
    }
    Ok(())
}

fn ensure_scope_key(database: &Database, key: &SyncKey) -> Result<(), SyncError> {
    let stored = database
        .connection()
        .map_err(|_| SyncError::Store)?
        .query_row(
            "SELECT account_key, label_id FROM gmail_scopes WHERE scope_id = ?1",
            [&key.scope_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| SyncError::Store)?;
    if stored != Some((key.account_key.clone(), key.label_id.clone())) {
        return Err(SyncError::InvalidConfiguration);
    }
    Ok(())
}

fn validate_hash(value: &str) -> Result<(), PlatformError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlatformError::InvalidInput("gmail_sha256"));
    }
    Ok(())
}

fn validate_provider_value(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(PlatformError::InvalidInput("gmail_provider_value"));
    }
    Ok(())
}

fn validate_revision_name(value: &str) -> Result<(), PlatformError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(PlatformError::InvalidInput("gmail_revision"));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn unix_now_ms() -> Result<i64, PlatformError> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PrivateAppPaths, RevisionEffect, UnavailableReason};

    fn database() -> (tempfile::TempDir, Database, SyncKey) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        let locator = "gmail-test-locator";
        database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO credential_references(
                    locator, credential_id, save_request_id, provider, display_label,
                    status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, 'gmail', 'Gmail', 'active', 1, 1)",
                params![
                    locator,
                    "11111111-1111-4111-8111-111111111111",
                    "22222222-2222-4222-8222-222222222222"
                ],
            )
            .unwrap();
        let key = SyncKey {
            account_key: "a".repeat(64),
            scope_id: "33333333-3333-4333-8333-333333333333".into(),
            label_id: "Label_1".into(),
        };
        database
            .initialize_gmail_scope(
                &key.account_key,
                locator,
                &key.scope_id,
                &"b".repeat(64),
                &key.label_id,
                "bounded-mime-v1",
                "gmail-materialization-v1",
                2,
            )
            .unwrap();
        (temporary, database, key)
    }

    fn seed_sync_operation(database: &Database, request_id: &str, envelope: &str) {
        database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO gmail_operations(
                    request_id, command_name, request_envelope_sha256, stage,
                    created_at_ms, updated_at_ms
                 ) VALUES (?1, 'sync_gmail_v1', ?2, 'syncing', 3, 3)",
                params![request_id, envelope],
            )
            .unwrap();
    }

    #[test]
    fn revisions_own_distinct_graphs_and_future_head_does_not_advance_checkpoint() {
        let (_temporary, database, key) = database();
        let raw =
            b"From: shop@example.com\r\nSubject: receipt\r\nContent-Type: image/png\r\n\r\nraw";
        let batch = SyncBatch {
            mode: crate::SyncMode::Reconciled,
            expected_checkpoint: None,
            next_checkpoint: HistoryId::parse("20").unwrap(),
            discovered_message_ids: vec!["m1".into()],
            effects: vec![RevisionEffect::Available {
                message_id: "m1".into(),
                revision: HistoryId::parse("25").unwrap(),
                raw: raw.to_vec(),
            }],
            pages: 1,
            gateway_calls: 3,
            raw_bytes: raw.len(),
        };
        let committed = database.commit(&key, &batch).unwrap();
        assert_eq!(committed.revisions_inserted, 1);
        assert_eq!(database.checkpoint(&key).unwrap().as_deref(), Some("20"));

        let second = SyncBatch {
            mode: crate::SyncMode::Incremental,
            expected_checkpoint: Some("20".into()),
            next_checkpoint: HistoryId::parse("25").unwrap(),
            discovered_message_ids: vec!["m1".into()],
            effects: vec![RevisionEffect::Unavailable {
                message_id: "m1".into(),
                revision: HistoryId::parse("22").unwrap(),
                reason: UnavailableReason::LabelRemoved,
            }],
            pages: 1,
            gateway_calls: 1,
            raw_bytes: 0,
        };
        database.commit(&key, &second).unwrap();
        let connection = database.connection().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(DISTINCT local_source_id)
                     FROM gmail_revision_materializations",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT revision.history_id
                     FROM gmail_source_heads head
                     JOIN gmail_source_revisions revision
                       ON revision.revision_id = head.head_revision_id",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "25"
        );
    }

    #[test]
    fn collision_and_stale_checkpoint_roll_back_everything() {
        let (_temporary, database, key) = database();
        let first = SyncBatch {
            mode: crate::SyncMode::Reconciled,
            expected_checkpoint: None,
            next_checkpoint: HistoryId::parse("10").unwrap(),
            discovered_message_ids: vec!["m1".into()],
            effects: vec![RevisionEffect::Unavailable {
                message_id: "m1".into(),
                revision: HistoryId::parse("10").unwrap(),
                reason: UnavailableReason::MessageNotFound,
            }],
            pages: 1,
            gateway_calls: 3,
            raw_bytes: 0,
        };
        database.commit(&key, &first).unwrap();
        let collision = SyncBatch {
            expected_checkpoint: Some("10".into()),
            effects: vec![RevisionEffect::Unavailable {
                message_id: "m1".into(),
                revision: HistoryId::parse("10").unwrap(),
                reason: UnavailableReason::MessageDeleted,
            }],
            ..first.clone()
        };
        assert_eq!(
            database.commit(&key, &collision),
            Err(SyncError::RevisionCollision)
        );
        assert_eq!(database.checkpoint(&key).unwrap().as_deref(), Some("10"));

        let stale = SyncBatch {
            expected_checkpoint: Some("9".into()),
            next_checkpoint: HistoryId::parse("11").unwrap(),
            effects: vec![],
            ..first
        };
        assert_eq!(
            database.commit(&key, &stale),
            Err(SyncError::CompareAndSwap)
        );
        assert_eq!(database.checkpoint(&key).unwrap().as_deref(), Some("10"));
    }

    #[test]
    fn operation_receipt_revision_links_and_cursor_commit_atomically() {
        let (_temporary, database, key) = database();
        let request_id = "44444444-4444-4444-8444-444444444444";
        let envelope = &"c".repeat(64);
        seed_sync_operation(&database, request_id, envelope);
        let batch = SyncBatch {
            mode: crate::SyncMode::Reconciled,
            expected_checkpoint: None,
            next_checkpoint: HistoryId::parse("10").unwrap(),
            discovered_message_ids: vec!["m1".into()],
            effects: vec![RevisionEffect::Available {
                message_id: "m1".into(),
                revision: HistoryId::parse("10").unwrap(),
                raw: b"From: shop@example.com\r\n\
                       Subject: receipt\r\n\
                       Content-Type: image/png\r\n\r\nraw"
                    .to_vec(),
            }],
            pages: 1,
            gateway_calls: 3,
            raw_bytes: 82,
        };

        let result = database
            .commit_gmail_operation(
                &key,
                &batch,
                request_id,
                envelope,
                GmailSyncCommandKind::Sync,
                &key.account_key,
                &key.scope_id,
            )
            .unwrap();

        assert_eq!(result.summary.messages_imported, 1);
        let connection = database.connection().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM gmail_operation_revisions
                     WHERE request_id = ?1",
                    [request_id],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM command_receipts
                     WHERE request_id = ?1 AND command_name = 'sync_gmail_v1'",
                    [request_id],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(database.checkpoint(&key).unwrap().as_deref(), Some("10"));
    }

    #[test]
    fn receipt_conflict_rolls_back_cursor_evidence_and_operation_links() {
        let (_temporary, database, key) = database();
        let request_id = "55555555-5555-4555-8555-555555555555";
        let envelope = &"d".repeat(64);
        let raw =
            b"From: shop@example.com\r\nSubject: receipt\r\nContent-Type: image/png\r\n\r\nraw";
        seed_sync_operation(&database, request_id, envelope);
        database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO command_receipts(
                    request_id, command_name, envelope_hash, response_json, created_at_ms
                 ) VALUES (?1, 'conflicting_command', ?2, '{}', 3)",
                params![request_id, envelope],
            )
            .unwrap();
        let batch = SyncBatch {
            mode: crate::SyncMode::Reconciled,
            expected_checkpoint: None,
            next_checkpoint: HistoryId::parse("10").unwrap(),
            discovered_message_ids: vec!["m1".into()],
            effects: vec![RevisionEffect::Available {
                message_id: "m1".into(),
                revision: HistoryId::parse("10").unwrap(),
                raw: raw.to_vec(),
            }],
            pages: 1,
            gateway_calls: 3,
            raw_bytes: raw.len(),
        };

        assert!(database
            .commit_gmail_operation(
                &key,
                &batch,
                request_id,
                envelope,
                GmailSyncCommandKind::Sync,
                &key.account_key,
                &key.scope_id,
            )
            .is_err());

        let connection = database.connection().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM gmail_source_revisions", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT
                       (SELECT COUNT(*) FROM gmail_provider_sources)
                     + (SELECT COUNT(*) FROM gmail_scope_sources)
                     + (SELECT COUNT(*) FROM gmail_revision_materializations)
                     + (SELECT COUNT(*) FROM gmail_source_heads)
                     + (SELECT COUNT(*) FROM local_sources)
                     + (SELECT COUNT(*) FROM source_provenance)
                     + (SELECT COUNT(*) FROM mime_parts)
                     + (SELECT COUNT(*) FROM evidence)
                     + (SELECT COUNT(*) FROM blobs)",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM gmail_operation_revisions",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(database.checkpoint(&key).unwrap(), None);
        assert_eq!(
            connection
                .query_row(
                    "SELECT evidence_generation FROM revision_state WHERE singleton = 1",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn exact_replay_recomputes_manifests_and_rejects_graph_drift() {
        let (_temporary, database, key) = database();
        let raw =
            b"From: shop@example.com\r\nSubject: receipt\r\nContent-Type: image/png\r\n\r\nraw";
        let first = SyncBatch {
            mode: crate::SyncMode::Reconciled,
            expected_checkpoint: None,
            next_checkpoint: HistoryId::parse("10").unwrap(),
            discovered_message_ids: vec!["m1".into()],
            effects: vec![RevisionEffect::Available {
                message_id: "m1".into(),
                revision: HistoryId::parse("10").unwrap(),
                raw: raw.to_vec(),
            }],
            pages: 1,
            gateway_calls: 3,
            raw_bytes: raw.len(),
        };
        database.commit(&key, &first).unwrap();
        let connection = database.connection().unwrap();
        let source_id: String = connection
            .query_row(
                "SELECT local_source_id FROM gmail_revision_materializations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(connection
            .execute(
                "INSERT INTO mime_parts(
                    part_id, source_id, ordinal, content_type, body_kind, decoded_bytes
                 ) VALUES ('blocked-extra', ?1, 999, 'text/plain', 'text', 1)",
                [&source_id],
            )
            .is_err());
        connection
            .execute_batch("DROP TRIGGER gmail_mime_no_insert;")
            .unwrap();
        connection
            .execute(
                "INSERT INTO mime_parts(
                    part_id, source_id, ordinal, content_type, body_kind, decoded_bytes
                 ) VALUES ('drift-extra', ?1, 999, 'text/plain', 'text', 1)",
                [&source_id],
            )
            .unwrap();
        let replay = SyncBatch {
            expected_checkpoint: Some("10".into()),
            ..first
        };

        assert_eq!(
            database.commit(&key, &replay),
            Err(SyncError::RevisionCollision)
        );
        assert_eq!(database.checkpoint(&key).unwrap().as_deref(), Some("10"));
    }
}
