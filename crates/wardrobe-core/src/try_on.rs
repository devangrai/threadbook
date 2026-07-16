use std::collections::BTreeSet;
use std::fmt;

use serde::de::{Error as _, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use crate::{
    deserialize_schema_version_v1, BoundedPhotoArtifactBytesV1, CredentialId, EvidenceId,
    ItemAttributesV1, ItemId, OpenAiRetentionDeclarationV1, OutfitId, PageCursorV1,
    PhotoArtifactId, PhotoMediaTypeV1, PhotoSourceRevisionId, ReplayStatusV1, RequestId,
    SafeFieldV1, Sha256Digest, SourceId, Validate, ValidationError, MAX_OUTFIT_MEMBERS,
    MAX_PHOTO_AXIS, MAX_PHOTO_PAGE_SIZE, MAX_PHOTO_PIXELS, MAX_SAFE_INTEGER_V1, SCHEMA_VERSION_V1,
};

pub use crate::model_policy::{TRY_ON_MODEL_V1, TRY_ON_PROVIDER_V1};
pub const TRY_ON_PURPOSE_V1: &str = "outfit_try_on_visualization";
pub const TRY_ON_PROMPT_REVISION_V1: &str = "p08-try-on-prompt-v1";
pub const TRY_ON_DISCLOSURE_REVISION_V1: &str = "p08-openai-image-edits-disclosure-v1";
pub const TRY_ON_PRESENTATION_LABEL_V1: &str =
    "AI visualization. Not an accurate representation of fit or garment construction.";
pub const TRY_ON_OUTPUT_MEDIA_TYPE_V1: &str = "image/png";
pub const TRY_ON_OUTPUT_WIDTH_V1: u32 = 1024;
pub const TRY_ON_OUTPUT_HEIGHT_V1: u32 = 1536;
pub const TRY_ON_MIN_GARMENTS: usize = 2;
pub const TRY_ON_MAX_GARMENTS: usize = MAX_OUTFIT_MEMBERS;
pub const TRY_ON_MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;
pub const TRY_ON_MAX_AGGREGATE_INPUT_BYTES: u64 = 40 * 1024 * 1024;
pub const TRY_ON_MAX_OUTPUT_BYTES: usize = 12 * 1024 * 1024;
pub const TRY_ON_MAX_ATTEMPTS: u8 = 1;

macro_rules! try_on_uuid_id {
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

                impl Visitor<'_> for IdVisitor {
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

try_on_uuid_id!(TryOnApprovalId);
try_on_uuid_id!(TryOnJobId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum TryOnAssetRoleV1 {
    Portrait,
    Garment,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum TryOnJobStateV1 {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum TryOnFailureCodeV1 {
    ModerationBlocked,
    RateLimited,
    ProviderFailure,
    ProviderUnavailable,
    OutcomeUnknown,
    Authentication,
    PermissionDenied,
    RequestRejected,
    ProviderProtocol,
    CredentialUnavailable,
    ApprovalExpired,
    ApprovalConsumed,
    SnapshotStale,
    AssetUnavailable,
    AssetIntegrity,
    OutputMaterializationInterrupted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum TryOnUserActionV1 {
    None,
    StartNewPreview,
    RetryWhenAvailable,
    CheckOpenAiCredential,
    ReviewSourceAssets,
    ReviewProviderStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum TryOnOutputUseClassV1 {
    PresentationOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TryOnPortraitCandidateV1 {
    pub source_revision_id: PhotoSourceRevisionId,
    pub artifact_id: PhotoArtifactId,
    pub captured_at: Option<String>,
    pub media_type: PhotoMediaTypeV1,
    pub width: u32,
    pub height: u32,
    pub bytes_sha256: Sha256Digest,
    pub thumbnail_bytes: BoundedPhotoArtifactBytesV1,
}

impl Validate for TryOnPortraitCandidateV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if !valid_dimensions(self.width, self.height)
            || self
                .captured_at
                .as_deref()
                .is_some_and(|value| !is_bounded_timestamp(value))
            || Sha256Digest::from_bytes(self.thumbnail_bytes.as_slice()) != self.bytes_sha256
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TryOnDisclosureAssetV1 {
    pub ordinal: u8,
    pub role: TryOnAssetRoleV1,
    pub transmitted_filename: String,
    pub portrait_source_revision_id: Option<PhotoSourceRevisionId>,
    pub portrait_artifact_id: Option<PhotoArtifactId>,
    pub item_id: Option<ItemId>,
    pub evidence_id: Option<EvidenceId>,
    pub source_id: Option<SourceId>,
    pub canonical_sha256: Sha256Digest,
    pub media_type: String,
    #[ts(type = "number")]
    pub byte_length: u64,
    pub width: u32,
    pub height: u32,
}

impl Validate for TryOnDisclosureAssetV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let expected_filename = format!("reference-{:02}.png", self.ordinal);
        let portrait_identity_complete =
            self.portrait_source_revision_id.is_some() && self.portrait_artifact_id.is_some();
        let portrait_identity_empty =
            self.portrait_source_revision_id.is_none() && self.portrait_artifact_id.is_none();
        let garment_identity_complete =
            self.item_id.is_some() && self.evidence_id.is_some() && self.source_id.is_some();
        let garment_identity_empty =
            self.item_id.is_none() && self.evidence_id.is_none() && self.source_id.is_none();
        let identity_valid = match self.role {
            TryOnAssetRoleV1::Portrait => portrait_identity_complete && garment_identity_empty,
            TryOnAssetRoleV1::Garment => portrait_identity_empty && garment_identity_complete,
        };
        if identity_valid
            && self.transmitted_filename == expected_filename
            && self.media_type == TRY_ON_OUTPUT_MEDIA_TYPE_V1
            && (1..=TRY_ON_MAX_INPUT_BYTES).contains(&self.byte_length)
            && valid_try_on_input_dimensions(self.width, self.height)
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TryOnRetentionDisclosureV1 {
    pub revision: String,
    pub declaration: OpenAiRetentionDeclarationV1,
    pub images_api_has_application_state_retention: bool,
    pub default_abuse_monitoring_max_days: u8,
    pub model_is_zdr_compatible: bool,
    pub compatibility_is_not_project_enrollment: bool,
    pub csam_input_scanning_applies: bool,
    pub flagged_inputs_may_be_retained_for_review: bool,
}

impl Validate for TryOnRetentionDisclosureV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.declaration.validate()?;
        if self.revision == TRY_ON_DISCLOSURE_REVISION_V1
            && !self.images_api_has_application_state_retention
            && self.default_abuse_monitoring_max_days == 30
            && self.model_is_zdr_compatible
            && self.compatibility_is_not_project_enrollment
            && self.csam_input_scanning_applies
            && self.flagged_inputs_may_be_retained_for_review
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TryOnDisclosureV1 {
    pub provider: String,
    pub model: String,
    pub purpose: String,
    pub prompt_revision: String,
    pub assets: Vec<TryOnDisclosureAssetV1>,
    pub retention: TryOnRetentionDisclosureV1,
}

impl Validate for TryOnDisclosureV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.retention.validate()?;
        if self.provider != TRY_ON_PROVIDER_V1
            || self.model != TRY_ON_MODEL_V1
            || self.purpose != TRY_ON_PURPOSE_V1
            || self.prompt_revision != TRY_ON_PROMPT_REVISION_V1
            || !(TRY_ON_MIN_GARMENTS + 1..=TRY_ON_MAX_GARMENTS + 1).contains(&self.assets.len())
        {
            return Err(invalid());
        }

        let mut item_ids = BTreeSet::new();
        let mut aggregate_bytes = 0_u64;
        for (index, asset) in self.assets.iter().enumerate() {
            asset.validate()?;
            if usize::from(asset.ordinal) != index
                || (index == 0) != (asset.role == TryOnAssetRoleV1::Portrait)
            {
                return Err(invalid());
            }
            if let Some(item_id) = asset.item_id {
                if !item_ids.insert(item_id) {
                    return Err(invalid());
                }
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(asset.byte_length)
                .ok_or_else(invalid)?;
        }
        if aggregate_bytes <= TRY_ON_MAX_AGGREGATE_INPUT_BYTES {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TryOnApprovalV1 {
    pub approval_id: TryOnApprovalId,
    pub outfit_id: OutfitId,
    pub expires_at: String,
    pub single_use: bool,
    pub garment_count: u8,
    pub asset_snapshot_sha256: Sha256Digest,
    #[ts(type = "number")]
    pub outfit_revision: u64,
}

impl Validate for TryOnApprovalV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.single_use
            && is_bounded_timestamp(&self.expires_at)
            && (TRY_ON_MIN_GARMENTS..=TRY_ON_MAX_GARMENTS)
                .contains(&usize::from(self.garment_count))
            && self.outfit_revision > 0
            && self.outfit_revision < MAX_SAFE_INTEGER_V1
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TryOnFailureV1 {
    pub code: TryOnFailureCodeV1,
    pub retryable: bool,
    pub user_action: TryOnUserActionV1,
}

impl Validate for TryOnFailureV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let expected = match self.code {
            TryOnFailureCodeV1::ModerationBlocked => (false, TryOnUserActionV1::ReviewSourceAssets),
            TryOnFailureCodeV1::Cancelled => (false, TryOnUserActionV1::None),
            TryOnFailureCodeV1::RateLimited | TryOnFailureCodeV1::ProviderFailure => {
                (true, TryOnUserActionV1::StartNewPreview)
            }
            TryOnFailureCodeV1::ProviderUnavailable => {
                (true, TryOnUserActionV1::RetryWhenAvailable)
            }
            TryOnFailureCodeV1::OutcomeUnknown => (false, TryOnUserActionV1::ReviewProviderStatus),
            TryOnFailureCodeV1::Authentication
            | TryOnFailureCodeV1::PermissionDenied
            | TryOnFailureCodeV1::CredentialUnavailable => {
                (true, TryOnUserActionV1::CheckOpenAiCredential)
            }
            TryOnFailureCodeV1::RequestRejected
            | TryOnFailureCodeV1::SnapshotStale
            | TryOnFailureCodeV1::AssetUnavailable
            | TryOnFailureCodeV1::AssetIntegrity => (true, TryOnUserActionV1::ReviewSourceAssets),
            TryOnFailureCodeV1::ProviderProtocol
            | TryOnFailureCodeV1::ApprovalExpired
            | TryOnFailureCodeV1::ApprovalConsumed
            | TryOnFailureCodeV1::OutputMaterializationInterrupted => {
                (true, TryOnUserActionV1::StartNewPreview)
            }
        };
        if (self.retryable, self.user_action) == expected {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TryOnJobV1 {
    pub job_id: TryOnJobId,
    pub approval_id: TryOnApprovalId,
    pub outfit_id: OutfitId,
    pub state: TryOnJobStateV1,
    pub attempt_count: u8,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub failure: Option<TryOnFailureV1>,
}

impl Validate for TryOnJobV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.attempt_count > TRY_ON_MAX_ATTEMPTS
            || !is_bounded_timestamp(&self.created_at)
            || !is_bounded_timestamp(&self.updated_at)
            || self
                .completed_at
                .as_deref()
                .is_some_and(|value| !is_bounded_timestamp(value))
        {
            return Err(invalid());
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        let state_valid = match self.state {
            TryOnJobStateV1::Queued => {
                self.attempt_count == 0 && self.completed_at.is_none() && self.failure.is_none()
            }
            TryOnJobStateV1::Running => {
                self.attempt_count == 1 && self.completed_at.is_none() && self.failure.is_none()
            }
            TryOnJobStateV1::Succeeded => {
                self.attempt_count == 1 && self.completed_at.is_some() && self.failure.is_none()
            }
            TryOnJobStateV1::Failed => {
                self.attempt_count <= 1 && self.completed_at.is_some() && self.failure.is_some()
            }
        };
        if state_valid {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, TS)]
#[serde(transparent)]
#[ts(type = "number[]")]
pub struct BoundedTryOnOutputBytesV1(Vec<u8>);

impl BoundedTryOnOutputBytesV1 {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > TRY_ON_MAX_OUTPUT_BYTES {
            Err(invalid())
        } else {
            Ok(Self(bytes))
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<'de> Deserialize<'de> for BoundedTryOnOutputBytesV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::new(bytes).map_err(|_| D::Error::custom("invalid try-on output bytes"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TryOnOutputV1 {
    pub job_id: TryOnJobId,
    pub outfit_id: OutfitId,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
    pub bytes_sha256: Sha256Digest,
    pub bytes: BoundedTryOnOutputBytesV1,
    pub use_class: TryOnOutputUseClassV1,
    pub eligible_as_evidence: bool,
    pub label: String,
    pub created_at: String,
}

impl Validate for TryOnOutputV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.media_type == TRY_ON_OUTPUT_MEDIA_TYPE_V1
            && self.width == TRY_ON_OUTPUT_WIDTH_V1
            && self.height == TRY_ON_OUTPUT_HEIGHT_V1
            && Sha256Digest::from_bytes(self.bytes.as_slice()) == self.bytes_sha256
            && self.use_class == TryOnOutputUseClassV1::PresentationOnly
            && !self.eligible_as_evidence
            && self.label == TRY_ON_PRESENTATION_LABEL_V1
            && is_bounded_timestamp(&self.created_at)
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct TryOnGarmentSourceV1 {
    pub ordinal: u8,
    pub item_id: ItemId,
    #[ts(type = "number")]
    pub item_updated_revision: u64,
    pub attributes: ItemAttributesV1,
    pub evidence_id: EvidenceId,
    pub source_id: SourceId,
    pub media_type: PhotoMediaTypeV1,
    pub width: u32,
    pub height: u32,
    pub bytes_sha256: Sha256Digest,
    pub bytes: BoundedPhotoArtifactBytesV1,
}

impl Validate for TryOnGarmentSourceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.attributes.validate()?;
        if usize::from(self.ordinal) > TRY_ON_MAX_GARMENTS
            || self.ordinal == 0
            || self.item_updated_revision == 0
            || self.item_updated_revision >= MAX_SAFE_INTEGER_V1
            || !valid_dimensions(self.width, self.height)
            || Sha256Digest::from_bytes(self.bytes.as_slice()) != self.bytes_sha256
        {
            Err(invalid())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListTryOnPortraitCandidatesV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListTryOnPortraitCandidatesV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)?;
        if (1..=MAX_PHOTO_PAGE_SIZE).contains(&self.limit) {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PreviewTryOnV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub outfit_id: OutfitId,
    pub portrait_source_revision_id: PhotoSourceRevisionId,
    pub credential_id: CredentialId,
    pub retention: OpenAiRetentionDeclarationV1,
    #[ts(type = "number")]
    pub expected_outfit_revision: u64,
}

impl Validate for PreviewTryOnV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)?;
        self.retention.validate()?;
        if self.expected_outfit_revision > 0 && self.expected_outfit_revision < MAX_SAFE_INTEGER_V1
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SubmitTryOnV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub approval_id: TryOnApprovalId,
}

impl Validate for SubmitTryOnV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GetOutfitTryOnV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub outfit_id: OutfitId,
}

impl Validate for GetOutfitTryOnV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListTryOnPortraitCandidatesV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub candidates: Vec<TryOnPortraitCandidateV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub photo_revision: u64,
    pub next_cursor: Option<PageCursorV1>,
}

impl Validate for ListTryOnPortraitCandidatesV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)?;
        if self.candidates.len() > MAX_PHOTO_PAGE_SIZE as usize
            || self.total_count < self.candidates.len() as u64
            || self.total_count >= MAX_SAFE_INTEGER_V1
            || self.photo_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(invalid());
        }
        let mut revisions = BTreeSet::new();
        let mut artifacts = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if !revisions.insert(candidate.source_revision_id)
                || !artifacts.insert(candidate.artifact_id)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PreviewTryOnV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub disclosure: TryOnDisclosureV1,
    pub approval: TryOnApprovalV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for PreviewTryOnV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)?;
        self.disclosure.validate()?;
        self.approval.validate()?;
        if usize::from(self.approval.garment_count) + 1 == self.disclosure.assets.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SubmitTryOnV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub job: TryOnJobV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for SubmitTryOnV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)?;
        self.job.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GetOutfitTryOnV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub outfit_id: OutfitId,
    pub outfit_name: String,
    pub latest_job: Option<TryOnJobV1>,
    pub output: Option<TryOnOutputV1>,
    pub garment_sources: Vec<TryOnGarmentSourceV1>,
    #[ts(type = "number")]
    pub try_on_revision: u64,
}

impl Validate for GetOutfitTryOnV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)?;
        if !is_bounded_display_name(&self.outfit_name)
            || self.try_on_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(invalid());
        }

        let Some(job) = &self.latest_job else {
            return if self.output.is_none() && self.garment_sources.is_empty() {
                Ok(())
            } else {
                Err(invalid())
            };
        };
        job.validate()?;
        if job.outfit_id != self.outfit_id
            || !(TRY_ON_MIN_GARMENTS..=TRY_ON_MAX_GARMENTS).contains(&self.garment_sources.len())
        {
            return Err(invalid());
        }
        let mut items = BTreeSet::new();
        for (index, source) in self.garment_sources.iter().enumerate() {
            source.validate()?;
            if usize::from(source.ordinal) != index + 1 || !items.insert(source.item_id) {
                return Err(invalid());
            }
        }

        match (&job.state, &self.output) {
            (TryOnJobStateV1::Succeeded, Some(output)) => {
                output.validate()?;
                if output.job_id == job.job_id && output.outfit_id == self.outfit_id {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            (
                TryOnJobStateV1::Queued | TryOnJobStateV1::Running | TryOnJobStateV1::Failed,
                None,
            ) => Ok(()),
            _ => Err(invalid()),
        }
    }
}

fn require_schema(value: u8) -> Result<(), ValidationError> {
    if value == SCHEMA_VERSION_V1 {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::SchemaVersion))
    }
}

fn valid_dimensions(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= MAX_PHOTO_AXIS
        && height <= MAX_PHOTO_AXIS
        && u64::from(width) * u64::from(height) <= MAX_PHOTO_PIXELS
}

fn valid_try_on_input_dimensions(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= 4096
        && height <= 4096
        && u64::from(width) * u64::from(height) <= 16_777_216
}

fn is_bounded_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    let shape_valid = (bytes.len() == 20 || (22..=30).contains(&bytes.len()))
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':')
        && bytes.last() == Some(&b'Z')
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .into_iter()
            .all(|index| bytes.get(index).is_some_and(u8::is_ascii_digit))
        && (bytes.len() == 20
            || (bytes.get(19) == Some(&b'.')
                && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)));
    if !shape_valid {
        return false;
    }
    parse_two_digits(bytes, 5).is_some_and(|value| (1..=12).contains(&value))
        && parse_two_digits(bytes, 8).is_some_and(|value| (1..=31).contains(&value))
        && parse_two_digits(bytes, 11).is_some_and(|value| value <= 23)
        && parse_two_digits(bytes, 14).is_some_and(|value| value <= 59)
        && parse_two_digits(bytes, 17).is_some_and(|value| value <= 59)
}

fn parse_two_digits(bytes: &[u8], offset: usize) -> Option<u8> {
    let high = bytes.get(offset)?.checked_sub(b'0')?;
    let low = bytes.get(offset + 1)?.checked_sub(b'0')?;
    (high <= 9 && low <= 9).then_some(high * 10 + low)
}

fn is_bounded_display_name(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed == value
        && value.chars().count() <= 80
        && !value.chars().any(char::is_control)
}

fn invalid() -> ValidationError {
    ValidationError::new(SafeFieldV1::Attributes)
}
