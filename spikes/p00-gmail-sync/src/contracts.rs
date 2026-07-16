use serde::Serialize;
use std::error::Error;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct HistoryId(String);

impl HistoryId {
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidHistoryId> {
        let value = value.into();
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(InvalidHistoryId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_after(&self, other: &Self) -> bool {
        decimal_cmp(self.as_str(), other.as_str()).is_gt()
    }

    pub fn max(self, other: Self) -> Self {
        if other.is_after(&self) {
            other
        } else {
            self
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidHistoryId;

impl fmt::Display for InvalidHistoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("history id is not a nonempty decimal string")
    }
}

impl Error for InvalidHistoryId {}

fn decimal_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left.trim_start_matches('0');
    let right = right.trim_start_matches('0');
    let left = if left.is_empty() { "0" } else { left };
    let right = if right.is_empty() { "0" } else { right };
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SyncKey {
    pub account_subject: String,
    pub provider: String,
    pub scope_fingerprint: String,
}

impl SyncKey {
    pub fn gmail(account_subject: impl Into<String>, scope: impl Into<String>) -> Self {
        Self {
            account_subject: account_subject.into(),
            provider: "gmail".into(),
            scope_fingerprint: scope.into(),
        }
    }

    pub fn valid(&self) -> bool {
        !self.account_subject.is_empty()
            && !self.provider.is_empty()
            && !self.scope_fingerprint.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SourceIdentity {
    pub account_subject: String,
    pub provider: String,
    pub provider_source_id: String,
}

impl SourceIdentity {
    pub fn new(key: &SyncKey, provider_source_id: impl Into<String>) -> Self {
        Self {
            account_subject: key.account_subject.clone(),
            provider: key.provider.clone(),
            provider_source_id: provider_source_id.into(),
        }
    }

    pub fn valid(&self) -> bool {
        !self.account_subject.is_empty()
            && !self.provider.is_empty()
            && !self.provider_source_id.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityReason {
    Materialized,
    HistoryDeletion,
    MessageNotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEffect {
    pub identity: SourceIdentity,
    pub revision: HistoryId,
    pub available: bool,
    pub reason: AvailabilityReason,
    pub evidence_fingerprint: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFault {
    None,
    BeforeTransaction,
    AfterEffects,
    AfterCheckpoint,
    AfterCommit,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CommitStats {
    pub sources_inserted: usize,
    pub revisions_inserted: usize,
    pub effects_replayed: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    CompareAndSwap,
    Conflict,
    InterruptedBeforeCommit,
    InterruptedAfterCommit,
    InvalidInput,
    Invariant,
    Sqlite,
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sync store error: {self:?}")
    }
}

impl Error for StoreError {}

pub trait SyncStore {
    fn checkpoint(&self, key: &SyncKey) -> Result<Option<String>, StoreError>;

    fn source_id(&self, identity: &SourceIdentity) -> Result<Option<String>, StoreError>;

    fn commit(
        &self,
        key: &SyncKey,
        expected_cursor: Option<&str>,
        next_cursor: &HistoryId,
        effects: &[SourceEffect],
        fault: CommitFault,
    ) -> Result<CommitStats, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_ids_are_decimal_strings_with_numeric_ordering() {
        assert!(HistoryId::parse("").is_err());
        assert!(HistoryId::parse("12x").is_err());
        assert!(HistoryId::parse("0009")
            .unwrap()
            .is_after(&HistoryId::parse("8").unwrap()));
        assert!(!HistoryId::parse("09")
            .unwrap()
            .is_after(&HistoryId::parse("9").unwrap()));
        assert!(HistoryId::parse("100000000000000000000")
            .unwrap()
            .is_after(&HistoryId::parse("99999999999999999999").unwrap()));
    }
}
