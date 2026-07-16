use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::validation::{require_schema_v1, validate_bounded_text, validate_timestamp};
use crate::{
    deserialize_schema_version_v1, DeletionHealthV1, DiagnosticComponentV1, DiagnosticEventCodeV1,
    DiagnosticOutcomeV1, DiagnosticSeverityV1, ErrorCodeV1, JobKindV1, RequestId, SafeFieldV1,
    Sha256Digest, TryOnFailureCodeV1, TryOnFailureV1, TryOnUserActionV1, UserActionKeyV1, Validate,
    ValidationError, MAX_SAFE_INTEGER_V1, SCHEMA_VERSION_V1,
};

pub const MAX_DIAGNOSTICS_EXPORT_BYTES_V1: u64 = 256 * 1024;
pub const MAX_DIAGNOSTICS_FAILURE_GROUPS_V1: usize = 128;
pub const MAX_DIAGNOSTICS_EVENT_GROUPS_V1: usize = 256;
pub const DIAGNOSTICS_EXPORT_MEDIA_TYPE_V1: &str = "application/json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ExportDiagnosticsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub destination_path: String,
}

impl Validate for ExportDiagnosticsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.destination_path.is_empty()
            || self.destination_path.len() > 4096
            || self.destination_path.as_bytes().contains(&0)
        {
            Err(ValidationError::new(SafeFieldV1::Path))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ExportDiagnosticsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub generated_at: String,
    #[ts(type = "true")]
    pub complete: bool,
    #[ts(type = "\"application/json\"")]
    pub media_type: String,
    #[ts(type = "number")]
    pub byte_length: u64,
    pub sha256: Sha256Digest,
}

impl Validate for ExportDiagnosticsV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_timestamp(&self.generated_at)?;
        if !self.complete
            || self.media_type != DIAGNOSTICS_EXPORT_MEDIA_TYPE_V1
            || self.byte_length == 0
            || self.byte_length > MAX_DIAGNOSTICS_EXPORT_BYTES_V1
        {
            Err(ValidationError::new(SafeFieldV1::Limit))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DiagnosticsHealthStateV1 {
    Ready,
    NeedsAttention,
    NeverRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DiagnosticsCounterNameV1 {
    CatalogItems,
    LocalSources,
    LocalSourcesImported,
    LocalSourcesQuarantined,
    LocalSourcesMissing,
    LocalSourcesUnavailable,
    Evidence,
    EvidenceUnresolved,
    EvidenceDeferred,
    EvidenceAssigned,
    EvidenceRejected,
    ReceiptOrders,
    ReceiptReviewsConfirmed,
    ReceiptReviewsCorrected,
    ReceiptReviewsDeferred,
    ReceiptReviewsRejected,
    PhotoObservations,
    PhotoObservationsNeedsReview,
    PhotoObservationsConfirmed,
    PhotoObservationsReplaced,
    PhotoObservationsDeferred,
    PhotoObservationsRejected,
    Outfits,
    TryOnJobs,
    TryOnJobsQueued,
    TryOnJobsRunning,
    TryOnJobsSucceeded,
    TryOnJobsFailed,
    VerifiedBackups,
    FoundationJobs,
    FoundationJobsPending,
    FoundationJobsRunning,
    FoundationJobsRetryWaiting,
    FoundationJobsSucceeded,
    FoundationJobsFailed,
    DeletionRuns,
    DeletionRunsInProgress,
    DeletionRunsNeedsAttention,
    DeletionRunsComplete,
}

impl DiagnosticsCounterNameV1 {
    pub const ALL: &'static [Self] = &[
        Self::CatalogItems,
        Self::LocalSources,
        Self::LocalSourcesImported,
        Self::LocalSourcesQuarantined,
        Self::LocalSourcesMissing,
        Self::LocalSourcesUnavailable,
        Self::Evidence,
        Self::EvidenceUnresolved,
        Self::EvidenceDeferred,
        Self::EvidenceAssigned,
        Self::EvidenceRejected,
        Self::ReceiptOrders,
        Self::ReceiptReviewsConfirmed,
        Self::ReceiptReviewsCorrected,
        Self::ReceiptReviewsDeferred,
        Self::ReceiptReviewsRejected,
        Self::PhotoObservations,
        Self::PhotoObservationsNeedsReview,
        Self::PhotoObservationsConfirmed,
        Self::PhotoObservationsReplaced,
        Self::PhotoObservationsDeferred,
        Self::PhotoObservationsRejected,
        Self::Outfits,
        Self::TryOnJobs,
        Self::TryOnJobsQueued,
        Self::TryOnJobsRunning,
        Self::TryOnJobsSucceeded,
        Self::TryOnJobsFailed,
        Self::VerifiedBackups,
        Self::FoundationJobs,
        Self::FoundationJobsPending,
        Self::FoundationJobsRunning,
        Self::FoundationJobsRetryWaiting,
        Self::FoundationJobsSucceeded,
        Self::FoundationJobsFailed,
        Self::DeletionRuns,
        Self::DeletionRunsInProgress,
        Self::DeletionRunsNeedsAttention,
        Self::DeletionRunsComplete,
    ];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsCounterV1 {
    pub name: DiagnosticsCounterNameV1,
    #[ts(type = "number")]
    pub value: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
#[ts(tag = "family", rename_all = "snake_case")]
pub enum DiagnosticsJobFailureV1 {
    Foundation {
        kind: JobKindV1,
        code: ErrorCodeV1,
        user_action: UserActionKeyV1,
        #[ts(type = "number")]
        attempt_count: u64,
        #[ts(type = "number")]
        occurrence_count: u64,
    },
    TryOn {
        code: TryOnFailureCodeV1,
        retryable: bool,
        user_action: TryOnUserActionV1,
        #[ts(type = "number")]
        attempt_count: u64,
        #[ts(type = "number")]
        occurrence_count: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsEventCountV1 {
    pub severity: DiagnosticSeverityV1,
    pub component: DiagnosticComponentV1,
    pub event_code: DiagnosticEventCodeV1,
    pub outcome: DiagnosticOutcomeV1,
    #[ts(type = "number")]
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsVersionsV1 {
    #[ts(type = "1")]
    pub export_schema_version: u8,
    pub application_version: String,
    #[ts(type = "number")]
    pub database_schema_version: u32,
    pub migration_prefix_sha256: Sha256Digest,
    #[ts(type = "1")]
    pub diagnostic_event_schema_version: u8,
}

impl Validate for DiagnosticsVersionsV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(&self.application_version, 1, 64, SafeFieldV1::SchemaVersion)?;
        if self.export_schema_version != SCHEMA_VERSION_V1
            || self.database_schema_version == 0
            || self.diagnostic_event_schema_version != SCHEMA_VERSION_V1
        {
            Err(ValidationError::new(SafeFieldV1::SchemaVersion))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsLogSummaryV1 {
    pub status: DiagnosticsHealthStateV1,
    pub event_counts: Vec<DiagnosticsEventCountV1>,
    #[ts(type = "number")]
    pub dropped_since_process_start: u64,
    #[ts(type = "number")]
    pub malformed_line_count: u64,
    #[ts(type = "number")]
    pub truncated_line_count: u64,
}

impl Validate for DiagnosticsLogSummaryV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_total([
            self.dropped_since_process_start,
            self.malformed_line_count,
            self.truncated_line_count,
        ])?;
        if self.event_counts.len() > MAX_DIAGNOSTICS_EVENT_GROUPS_V1 {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        validate_unique_sorted_groups(&self.event_counts, |event| {
            if event.count == 0 || event.count >= MAX_SAFE_INTEGER_V1 {
                return Err(ValidationError::new(SafeFieldV1::Limit));
            }
            Ok(event_group_key(event))
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsHealthV1 {
    pub database_integrity: DiagnosticsHealthStateV1,
    pub foreign_keys: DiagnosticsHealthStateV1,
    pub storage_check: DiagnosticsHealthStateV1,
    pub deletion: DeletionHealthV1,
    pub diagnostic_log: DiagnosticsLogSummaryV1,
}

impl Validate for DiagnosticsHealthV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.database_integrity != DiagnosticsHealthStateV1::Ready
            || self.foreign_keys != DiagnosticsHealthStateV1::Ready
        {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        self.deletion.validate()?;
        self.diagnostic_log.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsExportV1 {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub generated_at: String,
    pub versions: DiagnosticsVersionsV1,
    pub health: DiagnosticsHealthV1,
    pub counters: Vec<DiagnosticsCounterV1>,
    pub job_failures: Vec<DiagnosticsJobFailureV1>,
}

impl Validate for DiagnosticsExportV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_timestamp(&self.generated_at)?;
        self.versions.validate()?;
        self.health.validate()?;

        if self.counters.len() != DiagnosticsCounterNameV1::ALL.len()
            || self
                .counters
                .iter()
                .zip(DiagnosticsCounterNameV1::ALL)
                .any(|(counter, expected)| {
                    counter.name != *expected || counter.value >= MAX_SAFE_INTEGER_V1
                })
        {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }

        if self.job_failures.len() > MAX_DIAGNOSTICS_FAILURE_GROUPS_V1 {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        validate_unique_sorted_groups(&self.job_failures, |failure| {
            if let DiagnosticsJobFailureV1::TryOn {
                code,
                retryable,
                user_action,
                ..
            } = failure
            {
                TryOnFailureV1 {
                    code: *code,
                    retryable: *retryable,
                    user_action: *user_action,
                }
                .validate()?;
            }
            let (attempt_count, occurrence_count) = match failure {
                DiagnosticsJobFailureV1::Foundation {
                    attempt_count,
                    occurrence_count,
                    ..
                }
                | DiagnosticsJobFailureV1::TryOn {
                    attempt_count,
                    occurrence_count,
                    ..
                } => (*attempt_count, *occurrence_count),
            };
            if attempt_count >= MAX_SAFE_INTEGER_V1
                || occurrence_count == 0
                || occurrence_count >= MAX_SAFE_INTEGER_V1
            {
                return Err(ValidationError::new(SafeFieldV1::Limit));
            }
            Ok(failure_group_key(failure))
        })
    }
}

fn validate_bounded_total<const N: usize>(values: [u64; N]) -> Result<(), ValidationError> {
    let total = values.into_iter().try_fold(0_u64, |total, value| {
        if value >= MAX_SAFE_INTEGER_V1 {
            None
        } else {
            total.checked_add(value)
        }
    });
    if total.is_some_and(|value| value < MAX_SAFE_INTEGER_V1) {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::Limit))
    }
}

fn validate_unique_sorted_groups<T>(
    values: &[T],
    key: impl Fn(&T) -> Result<String, ValidationError>,
) -> Result<(), ValidationError> {
    let mut previous = None;
    for value in values {
        let current = key(value)?;
        if previous.as_ref().is_some_and(|value| value >= &current) {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        previous = Some(current);
    }
    Ok(())
}

fn event_group_key(event: &DiagnosticsEventCountV1) -> String {
    format!(
        "{:?}:{:?}:{:?}:{:?}",
        event.severity, event.component, event.event_code, event.outcome
    )
}

fn failure_group_key(failure: &DiagnosticsJobFailureV1) -> String {
    match failure {
        DiagnosticsJobFailureV1::Foundation {
            kind,
            code,
            user_action,
            attempt_count,
            ..
        } => format!("foundation:{kind:?}:{code:?}:{user_action:?}:{attempt_count:020}"),
        DiagnosticsJobFailureV1::TryOn {
            code,
            retryable,
            user_action,
            attempt_count,
            ..
        } => format!("try_on:{code:?}:{retryable}:{user_action:?}:{attempt_count:020}"),
    }
}
