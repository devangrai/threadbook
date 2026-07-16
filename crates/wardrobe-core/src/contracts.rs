use std::fmt;

use serde::de::{Error as _, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use crate::secret::SecretString;
use crate::validation::{
    require_schema_v1, validate_bounded_text, validate_timestamp, Validate, ValidationError,
};

pub const SCHEMA_VERSION_V1: u8 = 1;
pub const MAX_CREDENTIAL_REFERENCES: usize = 32;
pub const MAX_RECENT_JOBS: usize = 50;
pub const MAX_DISPLAY_LABEL_CHARS: usize = 80;
pub const MAX_SECRET_BYTES: usize = 8 * 1024;
pub const MAX_VERSION_CHARS: usize = 64;
pub const STORAGE_CHECK_BYTES: &[u8] = b"wardrobe-storage-check-v1\n";

pub(crate) fn deserialize_schema_version_v1<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u8::deserialize(deserializer)?;
    if version == SCHEMA_VERSION_V1 {
        Ok(version)
    } else {
        Err(D::Error::custom("unsupported schema version"))
    }
}

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, TS)]
        pub struct $name(#[ts(type = "string")] Uuid);

        impl $name {
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

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0.hyphenated())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdVisitor;

                impl<'de> Visitor<'de> for IdVisitor {
                    type Value = $name;

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
                        let parsed =
                            Uuid::parse_str(value).map_err(|_| E::custom("invalid UUID"))?;
                        if parsed.is_nil() || parsed.hyphenated().to_string() != value {
                            return Err(E::custom("UUID must be canonical and non-nil"));
                        }
                        Ok($name(parsed))
                    }
                }

                deserializer.deserialize_str(IdVisitor)
            }
        }
    };
}

uuid_id!(RequestId);
uuid_id!(CredentialId);
uuid_id!(StorageCheckId);
uuid_id!(JobId);
uuid_id!(OperationId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum CredentialProviderV1 {
    Gmail,
    OpenAi,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum CredentialStatusV1 {
    Active,
    PendingSave,
    PendingDelete,
    NeedsAttention,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReplayStatusV1 {
    Created,
    Replayed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum LocalOnlyAuthorityHealthV1 {
    Persisted,
    FailClosedDefault,
    FailClosedUncertain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum StorageStatusV1 {
    Ready,
    NeedsAttention,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum JobKindV1 {
    VerifyBlobV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum JobStatusV1 {
    Pending,
    Running,
    RetryWaiting,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ErrorCodeV1 {
    InvalidRequest,
    UnsupportedSchemaVersion,
    RequestConflict,
    SnapshotExpired,
    InvalidState,
    ProviderUnavailable,
    MalformedProviderOutput,
    CredentialUnavailable,
    StorageUnavailable,
    PermissionDenied,
    DataIntegrity,
    NotFound,
    Internal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum UserActionKeyV1 {
    CorrectRequest,
    StartNewRequest,
    RefreshCatalog,
    RefreshReceipts,
    RestartPaging,
    ReviewInbox,
    ReviewReceipt,
    Retry,
    UnlockKeychain,
    ReviewStorage,
    RestartApplication,
    ConfigureGmail,
    ConnectGmail,
    ConfigurePhotoKit,
    BeginPhotoKitSetup,
    ReviewPhotoLibraryAccess,
    None,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum SafeFieldV1 {
    SchemaVersion,
    RequestId,
    CredentialId,
    Provider,
    DisplayLabel,
    Secret,
    Timestamp,
    Path,
    Limit,
    Cursor,
    SnapshotToken,
    ExpectedCatalogRevision,
    ExpectedReceiptRevision,
    ItemId,
    EvidenceId,
    DecisionId,
    Attributes,
    Collection,
    DeletionTarget,
    DeletionPlan,
    DeletionRevisions,
    DeletionRetention,
    DeletionHealth,
    ReceiptFragment,
    ReceiptCitation,
    ReceiptEvidence,
    ReceiptProviderOutput,
    ReceiptReviewAction,
    ReceiptImageCandidate,
    ReceiptImageAttempt,
    GmailClientId,
    GmailLabelName,
    GmailLimits,
    GmailStatus,
    GmailSummary,
    PhotoKitSetupSession,
    PhotoKitSelectionToken,
    PhotoKitAlbumLabel,
    PhotoKitAlbumCandidates,
    PhotoKitCounts,
    PhotoKitAvailability,
    PhotoKitStatus,
    ExpectedPhotoKitRevision,
    ExpectedLocalOnlyRevision,
    LocalOnlyAuthority,
    RecommendationPrompt,
    RecommendationConstraints,
    RecommendationExclusions,
    RecommendationRetention,
    RecommendationDisclosure,
    RecommendationApproval,
    RecommendationTool,
    RecommendationSnapshot,
    RecommendationProposal,
    RecommendationAssessment,
    RecommendationUsage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CommandErrorV1 {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub code: ErrorCodeV1,
    pub retryable: bool,
    pub user_action: UserActionKeyV1,
    pub field: Option<SafeFieldV1>,
}

impl From<ValidationError> for CommandErrorV1 {
    fn from(error: ValidationError) -> Self {
        let code = if error.field == SafeFieldV1::SchemaVersion {
            ErrorCodeV1::UnsupportedSchemaVersion
        } else {
            ErrorCodeV1::InvalidRequest
        };
        Self {
            schema_version: SCHEMA_VERSION_V1,
            code,
            retryable: false,
            user_action: UserActionKeyV1::CorrectRequest,
            field: Some(error.field),
        }
    }
}

pub type CommandResult<T> = Result<T, CommandErrorV1>;

macro_rules! request_envelope {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            #[serde(deserialize_with = "deserialize_schema_version_v1")]
            #[ts(type = "1")]
            pub schema_version: u8,
            pub request_id: RequestId,
        }

        impl Validate for $name {
            fn validate(&self) -> Result<(), ValidationError> {
                require_schema_v1(self.schema_version)
            }
        }
    };
}

request_envelope!(GetFoundationSnapshotV1Request);
request_envelope!(RunStorageCheckV1Request);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SetLocalOnlyV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub enabled: bool,
    #[ts(type = "number")]
    pub expected_revision: u64,
}

impl Validate for SetLocalOnlyV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.expected_revision < crate::MAX_SAFE_INTEGER_V1 {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::ExpectedLocalOnlyRevision))
        }
    }
}

#[derive(Debug, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SaveCredentialV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub provider: CredentialProviderV1,
    pub display_label: String,
    #[ts(type = "string")]
    pub secret: SecretString,
}

impl Validate for SaveCredentialV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.provider == CredentialProviderV1::Gmail {
            return Err(ValidationError::new(SafeFieldV1::Provider));
        }
        validate_bounded_text(
            &self.display_label,
            1,
            MAX_DISPLAY_LABEL_CHARS,
            SafeFieldV1::DisplayLabel,
        )?;
        if self.secret.is_empty() || self.secret.len_bytes() > MAX_SECRET_BYTES {
            return Err(ValidationError::new(SafeFieldV1::Secret));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DeleteCredentialV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub credential_id: CredentialId,
}

impl Validate for DeleteCredentialV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct FoundationVersionsV1 {
    pub application: String,
    pub database_schema: u32,
    pub job_pipeline: u32,
}

impl Validate for FoundationVersionsV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(
            &self.application,
            1,
            MAX_VERSION_CHARS,
            SafeFieldV1::SchemaVersion,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct LocalSettingsSnapshotV1 {
    pub local_only: bool,
    #[ts(type = "number")]
    pub revision: u64,
    pub authority_health: LocalOnlyAuthorityHealthV1,
    pub storage_status: StorageStatusV1,
    pub deletion_health: crate::DeletionHealthV1,
}

impl Validate for LocalSettingsSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.revision > crate::MAX_SAFE_INTEGER_V1 {
            return Err(ValidationError::new(SafeFieldV1::ExpectedLocalOnlyRevision));
        }
        let authority_is_valid = match self.authority_health {
            LocalOnlyAuthorityHealthV1::Persisted => self.revision > 0,
            LocalOnlyAuthorityHealthV1::FailClosedDefault => self.local_only && self.revision == 0,
            LocalOnlyAuthorityHealthV1::FailClosedUncertain => self.local_only && self.revision > 0,
        };
        if !authority_is_valid {
            return Err(ValidationError::new(SafeFieldV1::LocalOnlyAuthority));
        }
        self.deletion_health.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CredentialReferenceV1 {
    pub credential_id: CredentialId,
    pub provider: CredentialProviderV1,
    pub display_label: String,
    pub status: CredentialStatusV1,
    pub updated_at: String,
}

impl Validate for CredentialReferenceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(
            &self.display_label,
            1,
            MAX_DISPLAY_LABEL_CHARS,
            SafeFieldV1::DisplayLabel,
        )?;
        validate_timestamp(&self.updated_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TerminalFailureV1 {
    pub code: ErrorCodeV1,
    pub user_action: UserActionKeyV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct JobSnapshotV1 {
    pub job_id: JobId,
    pub kind: JobKindV1,
    pub status: JobStatusV1,
    pub attempts: u16,
    pub max_attempts: u16,
    pub updated_at: String,
    pub terminal_failure: Option<TerminalFailureV1>,
}

impl Validate for JobSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_timestamp(&self.updated_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CatalogItemSnapshotV1 {
    pub item_id: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CatalogSnapshotV1 {
    pub items: Vec<CatalogItemSnapshotV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct FoundationSnapshotV1 {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub versions: FoundationVersionsV1,
    pub local_settings: LocalSettingsSnapshotV1,
    pub credential_references: Vec<CredentialReferenceV1>,
    pub recent_jobs: Vec<JobSnapshotV1>,
    pub catalog: CatalogSnapshotV1,
}

impl Validate for FoundationSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.versions.validate()?;
        self.local_settings.validate()?;
        if self.credential_references.len() > MAX_CREDENTIAL_REFERENCES {
            return Err(ValidationError::new(SafeFieldV1::CredentialId));
        }
        if self.recent_jobs.len() > MAX_RECENT_JOBS {
            return Err(ValidationError::new(SafeFieldV1::RequestId));
        }
        for reference in &self.credential_references {
            reference.validate()?;
        }
        for job in &self.recent_jobs {
            job.validate()?;
        }
        if !self.catalog.items.is_empty() {
            return Err(ValidationError::new(SafeFieldV1::RequestId));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GetFoundationSnapshotV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub snapshot: FoundationSnapshotV1,
}

impl Validate for GetFoundationSnapshotV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.snapshot.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SetLocalOnlyV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub local_only: bool,
    #[ts(type = "number")]
    pub revision: u64,
    pub authority_health: LocalOnlyAuthorityHealthV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for SetLocalOnlyV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.revision == 0 || self.revision > crate::MAX_SAFE_INTEGER_V1 {
            return Err(ValidationError::new(SafeFieldV1::ExpectedLocalOnlyRevision));
        }
        if self.authority_health != LocalOnlyAuthorityHealthV1::Persisted {
            return Err(ValidationError::new(SafeFieldV1::LocalOnlyAuthority));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RunStorageCheckV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub check_id: StorageCheckId,
    pub job_id: JobId,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SaveCredentialV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub credential: CredentialReferenceV1,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DeleteCredentialV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub credential_id: CredentialId,
    pub deleted: bool,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DiagnosticSeverityV1 {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DiagnosticComponentV1 {
    Application,
    BlobStore,
    Database,
    JobWorker,
    CredentialStore,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DiagnosticEventCodeV1 {
    CommandCompleted,
    CommandFailed,
    StorageCheckCompleted,
    JobTerminalFailure,
    CredentialReconciled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DiagnosticOutcomeV1 {
    Succeeded,
    Failed,
    Retrying,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticEventV1 {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub timestamp: String,
    pub severity: DiagnosticSeverityV1,
    pub component: DiagnosticComponentV1,
    pub event_code: DiagnosticEventCodeV1,
    pub outcome: DiagnosticOutcomeV1,
    pub operation_id: Option<OperationId>,
}

impl Validate for DiagnosticEventV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_timestamp(&self.timestamp)
    }
}
