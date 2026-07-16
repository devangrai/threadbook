use crate::contracts::{
    AvailabilityReason, CommitFault, CommitStats, HistoryId, SourceEffect, SourceIdentity,
    StoreError, SyncKey, SyncStore,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS sync_checkpoints (
    account_subject   TEXT NOT NULL CHECK (length(account_subject) > 0),
    provider          TEXT NOT NULL CHECK (length(provider) > 0),
    scope_fingerprint TEXT NOT NULL CHECK (length(scope_fingerprint) > 0),
    cursor            TEXT NOT NULL CHECK (length(cursor) > 0),
    PRIMARY KEY (account_subject, provider, scope_fingerprint)
) STRICT;

CREATE TABLE IF NOT EXISTS sources (
    source_id          TEXT PRIMARY KEY,
    account_subject    TEXT NOT NULL CHECK (length(account_subject) > 0),
    provider           TEXT NOT NULL CHECK (length(provider) > 0),
    provider_source_id TEXT NOT NULL CHECK (length(provider_source_id) > 0),
    available          INTEGER NOT NULL CHECK (available IN (0, 1)),
    current_revision   TEXT NOT NULL CHECK (length(current_revision) > 0),
    UNIQUE (account_subject, provider, provider_source_id)
) STRICT;

CREATE TABLE IF NOT EXISTS source_revisions (
    source_id            TEXT NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
    provider_revision    TEXT NOT NULL CHECK (length(provider_revision) > 0),
    evidence_fingerprint TEXT NOT NULL CHECK (length(evidence_fingerprint) > 0),
    available            INTEGER NOT NULL CHECK (available IN (0, 1)),
    reason               TEXT NOT NULL CHECK (
        reason IN ('materialized', 'history_deletion', 'message_not_found')
    ),
    PRIMARY KEY (source_id, provider_revision)
) STRICT;

CREATE TABLE IF NOT EXISTS source_availability (
    source_id         TEXT NOT NULL,
    provider_revision TEXT NOT NULL,
    available         INTEGER NOT NULL CHECK (available IN (0, 1)),
    reason            TEXT NOT NULL CHECK (
        reason IN ('materialized', 'history_deletion', 'message_not_found')
    ),
    PRIMARY KEY (source_id, provider_revision),
    FOREIGN KEY (source_id, provider_revision)
        REFERENCES source_revisions(source_id, provider_revision) ON DELETE RESTRICT
) STRICT;

PRAGMA user_version = 1;
"#;

#[derive(Clone, Debug)]
pub struct SqliteSyncStore {
    path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DatabaseAudit {
    pub integrity_check: String,
    pub foreign_key_violations: usize,
    pub source_count: usize,
    pub revision_count: usize,
    pub availability_count: usize,
    pub checkpoint_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceRow {
    pub source_id: String,
    pub account_subject: String,
    pub provider_source_id: String,
    pub available: bool,
    pub current_revision: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreSnapshot {
    pub cursor: Option<String>,
    pub sources: Vec<SourceRow>,
    pub revision_count: usize,
    pub availability_count: usize,
}

impl SqliteSyncStore {
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

    pub fn seed_checkpoint(&self, key: &SyncKey, cursor: &str) -> Result<(), StoreError> {
        if !key.valid() || cursor.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        self.connection()?
            .execute(
                "INSERT INTO sync_checkpoints (
                    account_subject, provider, scope_fingerprint, cursor
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(account_subject, provider, scope_fingerprint)
                 DO UPDATE SET cursor = excluded.cursor",
                params![
                    key.account_subject,
                    key.provider,
                    key.scope_fingerprint,
                    cursor
                ],
            )
            .map_err(|_| StoreError::Sqlite)?;
        Ok(())
    }

    pub fn snapshot(&self, key: &SyncKey) -> Result<StoreSnapshot, StoreError> {
        let connection = self.connection()?;
        let cursor = checkpoint_on(&connection, key)?;
        let mut statement = connection
            .prepare(
                "SELECT source_id, account_subject, provider_source_id, available,
                        current_revision
                 FROM sources
                 WHERE account_subject = ?1 AND provider = ?2
                 ORDER BY provider_source_id",
            )
            .map_err(|_| StoreError::Sqlite)?;
        let sources = statement
            .query_map(params![key.account_subject, key.provider], |row| {
                Ok(SourceRow {
                    source_id: row.get(0)?,
                    account_subject: row.get(1)?,
                    provider_source_id: row.get(2)?,
                    available: row.get::<_, i64>(3)? == 1,
                    current_revision: row.get(4)?,
                })
            })
            .map_err(|_| StoreError::Sqlite)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StoreError::Sqlite)?;
        let revision_count = count(&connection, "source_revisions")?;
        let availability_count = count(&connection, "source_availability")?;
        Ok(StoreSnapshot {
            cursor,
            sources,
            revision_count,
            availability_count,
        })
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
            source_count: count(&connection, "sources")?,
            revision_count: count(&connection, "source_revisions")?,
            availability_count: count(&connection, "source_availability")?,
            checkpoint_count: count(&connection, "sync_checkpoints")?,
        })
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
                 PRAGMA trusted_schema = OFF;",
            )
            .map_err(|_| StoreError::Sqlite)?;
        Ok(connection)
    }
}

impl SyncStore for SqliteSyncStore {
    fn checkpoint(&self, key: &SyncKey) -> Result<Option<String>, StoreError> {
        checkpoint_on(&self.connection()?, key)
    }

    fn source_id(&self, identity: &SourceIdentity) -> Result<Option<String>, StoreError> {
        self.connection()?
            .query_row(
                "SELECT source_id FROM sources
                 WHERE account_subject = ?1 AND provider = ?2 AND provider_source_id = ?3",
                params![
                    identity.account_subject,
                    identity.provider,
                    identity.provider_source_id
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StoreError::Sqlite)
    }

    fn commit(
        &self,
        key: &SyncKey,
        expected_cursor: Option<&str>,
        next_cursor: &HistoryId,
        effects: &[SourceEffect],
        fault: CommitFault,
    ) -> Result<CommitStats, StoreError> {
        if fault == CommitFault::BeforeTransaction {
            return Err(StoreError::InterruptedBeforeCommit);
        }
        if !key.valid() {
            return Err(StoreError::InvalidInput);
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| StoreError::Sqlite)?;
        let actual = checkpoint_on(&transaction, key)?;
        if actual.as_deref() != expected_cursor {
            return Err(StoreError::CompareAndSwap);
        }
        if expected_cursor
            .and_then(|cursor| HistoryId::parse(cursor).ok())
            .is_some_and(|cursor| cursor.is_after(next_cursor))
        {
            return Err(StoreError::Invariant);
        }

        let mut stats = CommitStats::default();
        for effect in effects {
            if !effect.identity.valid()
                || effect.identity.account_subject != key.account_subject
                || effect.identity.provider != key.provider
                || effect.evidence_fingerprint.is_empty()
            {
                return Err(StoreError::InvalidInput);
            }
            let source_id = stable_source_id(&effect.identity);
            let existing = transaction
                .query_row(
                    "SELECT source_id, current_revision FROM sources
                     WHERE account_subject = ?1 AND provider = ?2 AND provider_source_id = ?3",
                    params![
                        effect.identity.account_subject,
                        effect.identity.provider,
                        effect.identity.provider_source_id
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()
                .map_err(|_| StoreError::Sqlite)?;
            let current_revision = if let Some((existing_id, revision)) = existing {
                if existing_id != source_id {
                    return Err(StoreError::Invariant);
                }
                Some(revision)
            } else {
                transaction
                    .execute(
                        "INSERT INTO sources (
                            source_id, account_subject, provider, provider_source_id,
                            available, current_revision
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            source_id,
                            effect.identity.account_subject,
                            effect.identity.provider,
                            effect.identity.provider_source_id,
                            effect.available as i64,
                            effect.revision.as_str()
                        ],
                    )
                    .map_err(|_| StoreError::Conflict)?;
                stats.sources_inserted += 1;
                None
            };

            let reason = reason_name(effect.reason);
            let existing_revision = transaction
                .query_row(
                    "SELECT evidence_fingerprint, available, reason
                     FROM source_revisions
                     WHERE source_id = ?1 AND provider_revision = ?2",
                    params![source_id, effect.revision.as_str()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| StoreError::Sqlite)?;
            if let Some((fingerprint, available, stored_reason)) = existing_revision {
                if fingerprint != effect.evidence_fingerprint
                    || available != effect.available as i64
                    || stored_reason != reason
                {
                    return Err(StoreError::Conflict);
                }
                stats.effects_replayed += 1;
            } else {
                transaction
                    .execute(
                        "INSERT INTO source_revisions (
                            source_id, provider_revision, evidence_fingerprint, available, reason
                         ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            source_id,
                            effect.revision.as_str(),
                            effect.evidence_fingerprint,
                            effect.available as i64,
                            reason
                        ],
                    )
                    .map_err(|_| StoreError::Sqlite)?;
                transaction
                    .execute(
                        "INSERT INTO source_availability (
                            source_id, provider_revision, available, reason
                         ) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            source_id,
                            effect.revision.as_str(),
                            effect.available as i64,
                            reason
                        ],
                    )
                    .map_err(|_| StoreError::Sqlite)?;
                stats.revisions_inserted += 1;
            }

            let should_advance = current_revision
                .as_deref()
                .and_then(|value| HistoryId::parse(value).ok())
                .map(|current| effect.revision.is_after(&current))
                .unwrap_or(false);
            if should_advance {
                transaction
                    .execute(
                        "UPDATE sources
                         SET available = ?2, current_revision = ?3
                         WHERE source_id = ?1",
                        params![source_id, effect.available as i64, effect.revision.as_str()],
                    )
                    .map_err(|_| StoreError::Sqlite)?;
            }
        }
        if fault == CommitFault::AfterEffects {
            return Err(StoreError::InterruptedBeforeCommit);
        }

        match expected_cursor {
            Some(expected) => {
                let changed = transaction
                    .execute(
                        "UPDATE sync_checkpoints SET cursor = ?4
                         WHERE account_subject = ?1 AND provider = ?2
                           AND scope_fingerprint = ?3 AND cursor = ?5",
                        params![
                            key.account_subject,
                            key.provider,
                            key.scope_fingerprint,
                            next_cursor.as_str(),
                            expected
                        ],
                    )
                    .map_err(|_| StoreError::Sqlite)?;
                if changed != 1 {
                    return Err(StoreError::CompareAndSwap);
                }
            }
            None => {
                transaction
                    .execute(
                        "INSERT INTO sync_checkpoints (
                            account_subject, provider, scope_fingerprint, cursor
                         ) VALUES (?1, ?2, ?3, ?4)",
                        params![
                            key.account_subject,
                            key.provider,
                            key.scope_fingerprint,
                            next_cursor.as_str()
                        ],
                    )
                    .map_err(|_| StoreError::CompareAndSwap)?;
            }
        }
        if fault == CommitFault::AfterCheckpoint {
            return Err(StoreError::InterruptedBeforeCommit);
        }
        transaction.commit().map_err(|_| StoreError::Sqlite)?;
        if fault == CommitFault::AfterCommit {
            return Err(StoreError::InterruptedAfterCommit);
        }
        Ok(stats)
    }
}

fn checkpoint_on(connection: &Connection, key: &SyncKey) -> Result<Option<String>, StoreError> {
    connection
        .query_row(
            "SELECT cursor FROM sync_checkpoints
             WHERE account_subject = ?1 AND provider = ?2 AND scope_fingerprint = ?3",
            params![key.account_subject, key.provider, key.scope_fingerprint],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| StoreError::Sqlite)
}

fn stable_source_id(identity: &SourceIdentity) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for field in [
        identity.account_subject.as_bytes(),
        identity.provider.as_bytes(),
        identity.provider_source_id.as_bytes(),
    ] {
        for byte in (field.len() as u64)
            .to_be_bytes()
            .iter()
            .chain(field.iter())
        {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("src_{hash:016x}")
}

fn reason_name(reason: AvailabilityReason) -> &'static str {
    match reason {
        AvailabilityReason::Materialized => "materialized",
        AvailabilityReason::HistoryDeletion => "history_deletion",
        AvailabilityReason::MessageNotFound => "message_not_found",
    }
}

fn count(connection: &Connection, table: &str) -> Result<usize, StoreError> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    connection
        .query_row(&sql, [], |row| row.get::<_, i64>(0))
        .map(|value| value as usize)
        .map_err(|_| StoreError::Sqlite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn effect(key: &SyncKey, revision: &str, fingerprint: &str) -> SourceEffect {
        SourceEffect {
            identity: SourceIdentity::new(key, "message"),
            revision: HistoryId::parse(revision).unwrap(),
            available: true,
            reason: AvailabilityReason::Materialized,
            evidence_fingerprint: fingerprint.into(),
        }
    }

    #[test]
    fn compare_and_swap_revision_conflict_and_regression_fail_closed() {
        let temp = TempDir::new().unwrap();
        let store = SqliteSyncStore::open(temp.path().join("store.sqlite")).unwrap();
        let key = SyncKey::gmail("account", "scope");
        store.seed_checkpoint(&key, "10").unwrap();

        assert_eq!(
            store.commit(
                &key,
                Some("stale"),
                &HistoryId::parse("20").unwrap(),
                &[effect(&key, "15", "fp")],
                CommitFault::None,
            ),
            Err(StoreError::CompareAndSwap)
        );
        assert!(store.snapshot(&key).unwrap().sources.is_empty());

        store
            .commit(
                &key,
                Some("10"),
                &HistoryId::parse("20").unwrap(),
                &[effect(&key, "15", "fp")],
                CommitFault::None,
            )
            .unwrap();
        assert_eq!(
            store.commit(
                &key,
                Some("20"),
                &HistoryId::parse("20").unwrap(),
                &[effect(&key, "15", "different")],
                CommitFault::None,
            ),
            Err(StoreError::Conflict)
        );
        assert_eq!(
            store.commit(
                &key,
                Some("20"),
                &HistoryId::parse("19").unwrap(),
                &[],
                CommitFault::None,
            ),
            Err(StoreError::Invariant)
        );
        let snapshot = store.snapshot(&key).unwrap();
        assert_eq!(snapshot.cursor.as_deref(), Some("20"));
        assert_eq!(snapshot.sources.len(), 1);
        assert_eq!(snapshot.revision_count, 1);
        assert_eq!(store.audit().unwrap().foreign_key_violations, 0);
    }
}
