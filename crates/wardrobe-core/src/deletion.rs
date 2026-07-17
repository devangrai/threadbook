use std::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use crate::validation::{
    parse_timestamp, require_schema_v1, validate_bounded_text, validate_timestamp,
};
use crate::{
    deserialize_schema_version_v1, BackupId, BackupReasonV1, CredentialProviderV1,
    OpenAiRetentionModeV1, PreviewDeletionV1Response, ReplayStatusV1, RequestId, SafeFieldV1,
    Sha256Digest, Validate, ValidationError, MAX_SAFE_INTEGER_V1,
};

pub const MAX_DELETION_RETENTION_REPORTS: usize = 100;
pub const MAX_DELETION_RETENTION_PROVENANCE_CHARS: usize = 128;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, TS)]
pub struct DeletionRunId(#[ts(type = "string")] Uuid);

impl DeletionRunId {
    pub fn new(value: Uuid) -> Result<Self, &'static str> {
        if value.is_nil() {
            Err("UUID must not be nil")
        } else {
            Ok(Self(value))
        }
    }

    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for DeletionRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for DeletionRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.hyphenated())
    }
}

impl Serialize for DeletionRunId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DeletionRunId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DeletionRunIdVisitor;

        impl<'de> Visitor<'de> for DeletionRunIdVisitor {
            type Value = DeletionRunId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a canonical non-nil UUID string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() != 36 {
                    return Err(E::custom("UUID must use canonical hyphenated form"));
                }
                let parsed = Uuid::parse_str(value).map_err(|_| E::custom("invalid UUID"))?;
                if parsed.is_nil() || parsed.hyphenated().to_string() != value {
                    return Err(E::custom("UUID must be canonical and non-nil"));
                }
                Ok(DeletionRunId(parsed))
            }
        }

        deserializer.deserialize_str(DeletionRunIdVisitor)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DeletionConfirmationV1 {
    DeleteActiveLocalData,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DeletionRemotePurposeV1 {
    OutfitRecommendation,
    TryOn,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DeletionRemoteRetentionStatusV1 {
    ProviderDeletionUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DeletionHealthStatusV1 {
    None,
    InProgress,
    Overdue,
    NeedsAttention,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DeletionRevisionSnapshotV1 {
    #[ts(type = "number")]
    pub catalog_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    #[ts(type = "number")]
    pub receipt_revision: u64,
    #[ts(type = "number")]
    pub photo_revision: u64,
    #[ts(type = "number")]
    pub reconciliation_revision: u64,
    #[ts(type = "number")]
    pub outfit_revision: u64,
    #[ts(type = "number")]
    pub try_on_revision: u64,
    #[ts(type = "number")]
    pub photokit_revision: u64,
}

impl Validate for DeletionRevisionSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let revisions = [
            self.catalog_revision,
            self.evidence_generation,
            self.receipt_revision,
            self.photo_revision,
            self.reconciliation_revision,
            self.outfit_revision,
            self.try_on_revision,
            self.photokit_revision,
        ];
        if revisions
            .into_iter()
            .all(|revision| revision < MAX_SAFE_INTEGER_V1)
        {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::DeletionRevisions))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DeletionBackupRetentionV1 {
    pub backup_id: BackupId,
    pub reason: BackupReasonV1,
    pub expires_at: String,
}

impl Validate for DeletionBackupRetentionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_timestamp(&self.expires_at)
            .map_err(|_| ValidationError::new(SafeFieldV1::DeletionRetention))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DeletionRemoteRetentionV1 {
    pub provider: CredentialProviderV1,
    pub purpose: DeletionRemotePurposeV1,
    pub retention_mode: OpenAiRetentionModeV1,
    pub retention_provenance: String,
    pub dispatched_at: String,
    pub policy_expires_at: Option<String>,
    pub status: DeletionRemoteRetentionStatusV1,
}

impl Validate for DeletionRemoteRetentionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.provider != CredentialProviderV1::OpenAi {
            return Err(ValidationError::new(SafeFieldV1::DeletionRetention));
        }
        validate_bounded_text(
            &self.retention_provenance,
            1,
            MAX_DELETION_RETENTION_PROVENANCE_CHARS,
            SafeFieldV1::DeletionRetention,
        )?;
        if !self.retention_provenance.is_ascii()
            || self.retention_provenance.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
            })
        {
            return Err(ValidationError::new(SafeFieldV1::DeletionRetention));
        }
        validate_timestamp(&self.dispatched_at)
            .map_err(|_| ValidationError::new(SafeFieldV1::DeletionRetention))?;
        if let Some(expires_at) = &self.policy_expires_at {
            validate_timestamp(expires_at)
                .map_err(|_| ValidationError::new(SafeFieldV1::DeletionRetention))?;
            if expires_at <= &self.dispatched_at {
                return Err(ValidationError::new(SafeFieldV1::DeletionRetention));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DeletionHealthCountsV1 {
    pub in_progress: u32,
    pub overdue: u32,
    pub needs_attention: u32,
}

impl DeletionHealthCountsV1 {
    fn total(self) -> Option<u32> {
        self.in_progress
            .checked_add(self.overdue)?
            .checked_add(self.needs_attention)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DeletionHealthV1 {
    pub status: DeletionHealthStatusV1,
    pub deadline_at: Option<String>,
    pub counts: DeletionHealthCountsV1,
}

impl DeletionHealthV1 {
    pub const fn none() -> Self {
        Self {
            status: DeletionHealthStatusV1::None,
            deadline_at: None,
            counts: DeletionHealthCountsV1 {
                in_progress: 0,
                overdue: 0,
                needs_attention: 0,
            },
        }
    }
}

impl Validate for DeletionHealthV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let total = self
            .counts
            .total()
            .ok_or_else(|| ValidationError::new(SafeFieldV1::DeletionHealth))?;
        if let Some(deadline_at) = &self.deadline_at {
            validate_timestamp(deadline_at)
                .map_err(|_| ValidationError::new(SafeFieldV1::DeletionHealth))?;
        }

        let valid = match self.status {
            DeletionHealthStatusV1::None => total == 0 && self.deadline_at.is_none(),
            DeletionHealthStatusV1::InProgress => {
                self.counts.in_progress > 0
                    && self.counts.overdue == 0
                    && self.counts.needs_attention == 0
                    && self.deadline_at.is_some()
            }
            DeletionHealthStatusV1::Overdue => {
                self.counts.overdue > 0
                    && self.counts.needs_attention == 0
                    && self.deadline_at.is_some()
            }
            DeletionHealthStatusV1::NeedsAttention => {
                self.counts.needs_attention > 0 && self.deadline_at.is_some()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::DeletionHealth))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ExecuteDeletionV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub preview_snapshot_token: crate::DeletionSnapshotTokenV1,
    pub plan_sha256: Sha256Digest,
    pub expected_revisions: DeletionRevisionSnapshotV1,
    pub confirmation: DeletionConfirmationV1,
}

impl Validate for ExecuteDeletionV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.expected_revisions.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ExecuteDeletionV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub run_id: DeletionRunId,
    pub complete: bool,
    pub accepted_at: String,
    pub deadline_at: String,
    pub completed_at: String,
    #[ts(type = "number")]
    pub deleted_local_record_count: u64,
    #[ts(type = "number")]
    pub deleted_unique_blob_count: u64,
    #[ts(type = "number")]
    pub deleted_unique_blob_bytes: u64,
    #[ts(type = "number")]
    pub retained_shared_blob_count: u64,
    pub backup_retention: Vec<DeletionBackupRetentionV1>,
    pub remote_retention: Vec<DeletionRemoteRetentionV1>,
    pub replay_status: ReplayStatusV1,
}

impl Validate for ExecuteDeletionV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if !self.complete {
            return Err(ValidationError::new(SafeFieldV1::DeletionPlan));
        }
        let accepted_at = parse_timestamp(&self.accepted_at)?;
        let deadline_at = parse_timestamp(&self.deadline_at)?;
        let completed_at = parse_timestamp(&self.completed_at)?;
        if deadline_at <= accepted_at || completed_at < accepted_at {
            return Err(ValidationError::new(SafeFieldV1::Timestamp));
        }
        validate_counts(
            self.deleted_local_record_count,
            self.deleted_unique_blob_count,
            self.deleted_unique_blob_bytes,
            self.retained_shared_blob_count,
        )?;
        validate_retention_reports(&self.backup_retention, &self.remote_retention)
    }
}

impl Validate for PreviewDeletionV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.revisions.validate()?;
        validate_timestamp(&self.prepared_at)?;
        validate_timestamp(&self.expires_at)?;
        if self.expires_at <= self.prepared_at {
            return Err(ValidationError::new(SafeFieldV1::Timestamp));
        }
        validate_counts(
            self.overall_count,
            self.unique_blob_count,
            self.unique_blob_bytes,
            self.retained_shared_blob_count,
        )?;
        validate_retention_reports(&self.backup_retention, &self.remote_retention)?;
        if self.counts.len() != 8
            || self
                .counts
                .iter()
                .any(|count| count.count >= MAX_SAFE_INTEGER_V1)
            || self.first_page.len() > usize::from(crate::MAX_PAGE_SIZE)
        {
            return Err(ValidationError::new(SafeFieldV1::DeletionPlan));
        }
        for item in &self.first_page {
            item.validate()?;
        }
        Ok(())
    }
}

fn validate_counts(
    local_records: u64,
    unique_blobs: u64,
    unique_blob_bytes: u64,
    retained_shared_blobs: u64,
) -> Result<(), ValidationError> {
    if [
        local_records,
        unique_blobs,
        unique_blob_bytes,
        retained_shared_blobs,
    ]
    .into_iter()
    .any(|value| value >= MAX_SAFE_INTEGER_V1)
    {
        Err(ValidationError::new(SafeFieldV1::DeletionPlan))
    } else {
        Ok(())
    }
}

fn validate_retention_reports(
    backup_retention: &[DeletionBackupRetentionV1],
    remote_retention: &[DeletionRemoteRetentionV1],
) -> Result<(), ValidationError> {
    if backup_retention.len() > MAX_DELETION_RETENTION_REPORTS
        || remote_retention.len() > MAX_DELETION_RETENTION_REPORTS
    {
        return Err(ValidationError::new(SafeFieldV1::DeletionRetention));
    }
    for report in backup_retention {
        report.validate()?;
    }
    for report in remote_retention {
        report.validate()?;
    }

    let mut backup_ids = backup_retention
        .iter()
        .map(|report| report.backup_id)
        .collect::<Vec<_>>();
    backup_ids.sort_unstable();
    backup_ids.dedup();
    if backup_ids.len() != backup_retention.len() {
        return Err(ValidationError::new(SafeFieldV1::DeletionRetention));
    }

    if remote_retention
        .iter()
        .enumerate()
        .any(|(index, report)| remote_retention[..index].contains(report))
    {
        return Err(ValidationError::new(SafeFieldV1::DeletionRetention));
    }
    Ok(())
}
