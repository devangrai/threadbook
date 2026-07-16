use std::fmt;

use serde::de::{Error as _, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use ts_rs::TS;
use uuid::Uuid;

use crate::{
    deserialize_schema_version_v1, ImportRootId, PageCursorV1, ReplayStatusV1, RequestId,
    SafeFieldV1, Sha256Digest, SourceId, Validate, ValidationError, SCHEMA_VERSION_V1,
};

pub const GARMENT_SEGMENTATION_CONTRACT_V1: &str = "garment-segmentation-v1";
pub const LOCAL_PERSON_DETECTION_CONTRACT_V1: &str = "local-person-detection-v1";
pub const APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1: &str =
    "apple-vision-human-rectangles-v1";
pub const PHOTO_PREPROCESSING_REVISION_V1: &str = "canonical-srgb-orientation-v1";
pub const PHOTO_OWNER_PREVIEW_CONTRACT_REVISION_V1: &str = "photo-owner-preview-v1";
pub const PHOTO_QUALITY_GATE_REVISION_V1: &str = "automatic-mask-quality-gate-v1";
pub const PHOTO_ARTIFACT_SCHEMA_REVISION_V1: &str = "photo-artifact-v1";
pub const RECTANGLE_SOURCE_CROP_REVISION_V1: &str = "rectangle-source-crop-v1";
pub const SOURCE_IMAGE_REFERENCE_REVISION_V1: &str = "source-image-reference-v1";
pub const UNAVAILABLE_SEGMENTATION_PROVIDER_ID_V1: &str = "unavailable-local-segmentation";
pub const UNAVAILABLE_SEGMENTATION_PROVIDER_REVISION_V1: &str = "unavailable-local-segmentation-v1";

pub const MAX_PHOTO_SCOPE_MEMBERS: usize = 500;
pub const MAX_PHOTO_PAGE_SIZE: u16 = 100;
pub const MAX_PHOTO_AXIS: u32 = 16_384;
pub const MAX_PHOTO_PIXELS: u64 = 64 * 1024 * 1024;
pub const MAX_PHOTO_ARTIFACT_BYTES: usize = 40 * 1024 * 1024;
pub const MAX_SEGMENTATION_MASKS: usize = 8;
pub const MAX_SEGMENTATION_PROMPT_POINTS: usize = 16;
pub const MAX_PHOTO_PARENT_ARTIFACTS: usize = 16;
pub const MAX_PERSON_INSTANCES_V1: usize = 32;
pub const MAX_PERSON_CONFIDENCE_BASIS_POINTS_V1: u16 = 10_000;
pub const MAX_PROVIDER_IDENTIFIER_CHARS: usize = 128;
pub const MAX_PHOTO_REASON_CODE_CHARS: usize = 80;
pub const MAX_PHOTO_SAFE_INTEGER_V1: u64 = 9_007_199_254_740_991;

macro_rules! photo_uuid_id {
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

photo_uuid_id!(PhotoScopeId);
photo_uuid_id!(PhotoImportScanId);
photo_uuid_id!(PhotoSourceRevisionId);
photo_uuid_id!(PhotoAnalysisRunId);
photo_uuid_id!(PhotoArtifactId);
photo_uuid_id!(PhotoObservationId);
photo_uuid_id!(PhotoReviewDecisionId);
photo_uuid_id!(SegmentationRequestHandle);
photo_uuid_id!(PersonDetectionRequestHandle);
photo_uuid_id!(PhotoPersonDetectionAttemptId);
photo_uuid_id!(PhotoPersonInstanceId);
photo_uuid_id!(PhotoOwnerReviewId);
photo_uuid_id!(PhotoOwnerPreviewId);
photo_uuid_id!(PhotoOwnerDecisionId);

fn invalid(field: SafeFieldV1) -> ValidationError {
    ValidationError::new(field)
}

fn validate_schema(version: u8) -> Result<(), ValidationError> {
    if version == SCHEMA_VERSION_V1 {
        Ok(())
    } else {
        Err(invalid(SafeFieldV1::SchemaVersion))
    }
}

fn validate_safe_u64(value: u64, field: SafeFieldV1) -> Result<(), ValidationError> {
    if value < MAX_PHOTO_SAFE_INTEGER_V1 {
        Ok(())
    } else {
        Err(invalid(field))
    }
}

fn validate_page(limit: u16) -> Result<(), ValidationError> {
    if (1..=MAX_PHOTO_PAGE_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(invalid(SafeFieldV1::Limit))
    }
}

fn validate_identifier(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > MAX_PROVIDER_IDENTIFIER_CHARS
        || !value.is_ascii()
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(invalid(SafeFieldV1::Provider))
    } else {
        Ok(())
    }
}

fn validate_dimensions(width: u32, height: u32) -> Result<(), ValidationError> {
    if width == 0
        || height == 0
        || width > MAX_PHOTO_AXIS
        || height > MAX_PHOTO_AXIS
        || u64::from(width) * u64::from(height) > MAX_PHOTO_PIXELS
    {
        Err(invalid(SafeFieldV1::Attributes))
    } else {
        Ok(())
    }
}

fn validate_unique_ids<T: Copy + Ord>(values: &[T], max: usize) -> Result<(), ValidationError> {
    if values.len() > max {
        return Err(invalid(SafeFieldV1::Collection));
    }
    let mut unique = values.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != values.len() {
        Err(invalid(SafeFieldV1::Collection))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoSourceDispositionV1 {
    Eligible,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoQuarantineReasonV1 {
    SourceUnavailable,
    BlobUnavailable,
    BlobIntegrityFailed,
    MediaTypeRejected,
    ImageDecodeFailed,
    ImageAnimated,
    ImageDimensionLimit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
pub enum PhotoMediaTypeV1 {
    #[serde(rename = "image/jpeg")]
    #[ts(rename = "image/jpeg")]
    ImageJpeg,
    #[serde(rename = "image/png")]
    #[ts(rename = "image/png")]
    ImagePng,
    #[serde(rename = "image/webp")]
    #[ts(rename = "image/webp")]
    ImageWebp,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum SegmentationRequestModeKindV1 {
    Automatic,
    Interactive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum SegmentationCapabilityV1 {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum SegmentationUnavailableReasonV1 {
    ReviewedModelPackAbsent,
    CapabilityDisabled,
    ResourceUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum SegmentationFailureCodeV1 {
    InvalidInput,
    InferenceFailed,
    ResourceLimit,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoSegmentationOutcomeCodeV1 {
    AutomaticMasks,
    InteractiveMasks,
    NoGarment,
    Unavailable,
    Failed,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoArtifactKindV1 {
    RectangleSourceCrop,
    SourceImageReference,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoObservationStateV1 {
    NeedsReview,
    Confirmed,
    Replaced,
    Deferred,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoReviewActionV1 {
    ConfirmCrop,
    ReplaceCrop,
    Defer,
    Reject,
}

impl PhotoReviewActionV1 {
    pub fn resulting_state(self) -> PhotoObservationStateV1 {
        match self {
            Self::ConfirmCrop => PhotoObservationStateV1::Confirmed,
            Self::ReplaceCrop => PhotoObservationStateV1::Replaced,
            Self::Defer => PhotoObservationStateV1::Deferred,
            Self::Reject => PhotoObservationStateV1::Rejected,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoAnalysisRunStateV1 {
    Pending,
    Running,
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PointV1 {
    pub x: u32,
    pub y: u32,
}

impl PointV1 {
    pub fn validate_within(&self, width: u32, height: u32) -> Result<(), ValidationError> {
        validate_dimensions(width, height)?;
        if self.x < width && self.y < height {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RectV1 {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl RectV1 {
    pub fn validate_bounded(&self) -> Result<(), ValidationError> {
        let x_end = self.x.checked_add(self.width);
        let y_end = self.y.checked_add(self.height);
        if self.width > 0
            && self.height > 0
            && x_end.is_some_and(|end| end <= MAX_PHOTO_AXIS)
            && y_end.is_some_and(|end| end <= MAX_PHOTO_AXIS)
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }

    pub fn validate_within(
        &self,
        source_width: u32,
        source_height: u32,
    ) -> Result<(), ValidationError> {
        validate_dimensions(source_width, source_height)?;
        let x_end = self.x.checked_add(self.width);
        let y_end = self.y.checked_add(self.height);
        if self.width > 0
            && self.height > 0
            && x_end.is_some_and(|end| end <= source_width)
            && y_end.is_some_and(|end| end <= source_height)
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct MaskV1 {
    pub width: u32,
    pub height: u32,
    pub packed_bits: Vec<u8>,
    pub confidence: f32,
}

impl MaskV1 {
    pub fn validate_for_dimensions(
        &self,
        expected_width: u32,
        expected_height: u32,
    ) -> Result<(), ValidationError> {
        validate_dimensions(self.width, self.height)?;
        if self.width != expected_width
            || self.height != expected_height
            || !self.confidence.is_finite()
            || !(0.0..=1.0).contains(&self.confidence)
        {
            return Err(invalid(SafeFieldV1::ReceiptProviderOutput));
        }
        let pixels = u64::from(self.width) * u64::from(self.height);
        let expected_bytes = pixels.div_ceil(8) as usize;
        if self.packed_bits.len() != expected_bytes
            || self.packed_bits.iter().all(|byte| *byte == 0)
        {
            return Err(invalid(SafeFieldV1::ReceiptProviderOutput));
        }
        let unused_tail_bits = (expected_bytes as u64 * 8 - pixels) as u8;
        if unused_tail_bits > 0 {
            // Masks are packed most-significant bit first, so unused tail bits are low.
            let unused_mask = (1_u8 << unused_tail_bits) - 1;
            if self
                .packed_bits
                .last()
                .is_some_and(|last| last & unused_mask != 0)
            {
                return Err(invalid(SafeFieldV1::ReceiptProviderOutput));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoSourceRevisionV1 {
    pub source_revision_id: PhotoSourceRevisionId,
    pub source_id: SourceId,
    pub import_root_id: ImportRootId,
    pub completed_scan_id: PhotoImportScanId,
    #[ts(type = "number")]
    pub manifest_generation: u64,
    pub source_identity_key_sha256: Sha256Digest,
    pub provenance_row_sha256: Sha256Digest,
    pub raw_sha256: Option<Sha256Digest>,
    pub blob_sha256: Option<Sha256Digest>,
    #[ts(type = "number")]
    pub byte_length: Option<u64>,
    pub media_type: Option<PhotoMediaTypeV1>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub disposition: PhotoSourceDispositionV1,
    pub quarantine_reason: Option<PhotoQuarantineReasonV1>,
    pub source_revision_sha256: Sha256Digest,
}

impl Validate for PhotoSourceRevisionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_safe_u64(self.manifest_generation, SafeFieldV1::Collection)?;
        let materialized = self.raw_sha256.is_some()
            && self.blob_sha256.is_some()
            && self
                .byte_length
                .is_some_and(|length| length > 0 && length <= MAX_PHOTO_ARTIFACT_BYTES as u64)
            && self.media_type.is_some()
            && self.width.is_some()
            && self.height.is_some();
        let dimensions_valid = self
            .width
            .zip(self.height)
            .is_some_and(|(width, height)| validate_dimensions(width, height).is_ok());
        let valid = match self.disposition {
            PhotoSourceDispositionV1::Eligible => {
                materialized && dimensions_valid && self.quarantine_reason.is_none()
            }
            PhotoSourceDispositionV1::Quarantined => self.quarantine_reason.is_some(),
        };
        if valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoScopeMemberV1 {
    pub ordinal: u16,
    pub source_revision: PhotoSourceRevisionV1,
    pub disposition: PhotoSourceDispositionV1,
    pub leaf_sha256: Sha256Digest,
}

impl Validate for PhotoScopeMemberV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.source_revision.validate()?;
        if self.disposition == self.source_revision.disposition {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoScopeV1 {
    pub scope_id: PhotoScopeId,
    pub import_root_id: ImportRootId,
    pub completed_scan_id: PhotoImportScanId,
    #[ts(type = "number")]
    pub manifest_generation: u64,
    pub member_count: u16,
    pub eligible_count: u16,
    pub quarantined_count: u16,
    pub membership_sha256: Sha256Digest,
}

impl Validate for PhotoScopeV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_safe_u64(self.manifest_generation, SafeFieldV1::Collection)?;
        let total = self
            .eligible_count
            .checked_add(self.quarantined_count)
            .map(usize::from);
        if self.member_count > 0
            && usize::from(self.member_count) <= MAX_PHOTO_SCOPE_MEMBERS
            && total == Some(usize::from(self.member_count))
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Collection))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ImportedPhotoRootV1 {
    pub import_root_id: ImportRootId,
    pub completed_scan_id: PhotoImportScanId,
    #[ts(type = "number")]
    pub manifest_generation: u64,
    pub member_count: u16,
    pub eligible_count: u16,
    pub quarantined_count: u16,
}

impl Validate for ImportedPhotoRootV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let total = self
            .eligible_count
            .checked_add(self.quarantined_count)
            .map(usize::from);
        validate_safe_u64(self.manifest_generation, SafeFieldV1::Collection)?;
        if self.member_count > 0
            && usize::from(self.member_count) <= MAX_PHOTO_SCOPE_MEMBERS
            && total == Some(usize::from(self.member_count))
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Collection))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoArtifactV1 {
    pub artifact_id: PhotoArtifactId,
    pub kind: PhotoArtifactKindV1,
    pub artifact_schema_revision: String,
    pub artifact_revision: String,
    pub scope_id: PhotoScopeId,
    pub source_revision_id: PhotoSourceRevisionId,
    pub source_revision_sha256: Sha256Digest,
    pub input_blob_sha256: Sha256Digest,
    pub media_type: PhotoMediaTypeV1,
    pub source_width: u32,
    pub source_height: u32,
    pub rectangle: Option<RectV1>,
    pub preprocessing_revision: String,
    pub provider_contract_revision: String,
    pub provider_id: String,
    pub provider_revision: String,
    pub model_revision: Option<String>,
    pub request_mode: SegmentationRequestModeKindV1,
    pub prompt_parameters_sha256: Sha256Digest,
    pub quality_gate_revision: String,
    pub quality_approved: bool,
    pub segmentation_outcome: PhotoSegmentationOutcomeCodeV1,
    pub unavailable_reason: Option<SegmentationUnavailableReasonV1>,
    pub failure_code: Option<SegmentationFailureCodeV1>,
    pub parent_artifact_ids: Vec<PhotoArtifactId>,
    pub provenance_sha256: Sha256Digest,
    pub artifact_sha256: Sha256Digest,
}

impl Validate for PhotoArtifactV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_dimensions(self.source_width, self.source_height)?;
        let artifact_revision_valid = match self.kind {
            PhotoArtifactKindV1::RectangleSourceCrop => {
                self.artifact_revision == RECTANGLE_SOURCE_CROP_REVISION_V1
            }
            PhotoArtifactKindV1::SourceImageReference => {
                self.artifact_revision == SOURCE_IMAGE_REFERENCE_REVISION_V1
            }
        };
        validate_identifier(&self.preprocessing_revision)?;
        validate_identifier(&self.provider_id)?;
        validate_identifier(&self.provider_revision)?;
        if let Some(model_revision) = &self.model_revision {
            validate_identifier(model_revision)?;
        }
        validate_unique_ids(&self.parent_artifact_ids, MAX_PHOTO_PARENT_ARTIFACTS)?;
        let shape_valid = match self.kind {
            PhotoArtifactKindV1::RectangleSourceCrop => self.rectangle.is_some_and(|rectangle| {
                rectangle
                    .validate_within(self.source_width, self.source_height)
                    .is_ok()
            }),
            PhotoArtifactKindV1::SourceImageReference => self.rectangle.is_none(),
        };
        let outcome_details_valid = match self.segmentation_outcome {
            PhotoSegmentationOutcomeCodeV1::Unavailable => {
                self.unavailable_reason.is_some() && self.failure_code.is_none()
            }
            PhotoSegmentationOutcomeCodeV1::Failed => {
                self.failure_code.is_some() && self.unavailable_reason.is_none()
            }
            _ => self.unavailable_reason.is_none() && self.failure_code.is_none(),
        };
        // This slice has no approved automatic-mask manifest. Any retained artifact is evidence
        // requiring review, never an automatically approved canonical decision.
        if self.artifact_schema_revision == PHOTO_ARTIFACT_SCHEMA_REVISION_V1
            && artifact_revision_valid
            && self.provider_contract_revision == GARMENT_SEGMENTATION_CONTRACT_V1
            && self.quality_gate_revision == PHOTO_QUALITY_GATE_REVISION_V1
            && shape_valid
            && outcome_details_valid
            && !self.quality_approved
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoReviewDecisionV1 {
    pub decision_id: PhotoReviewDecisionId,
    pub observation_id: PhotoObservationId,
    pub action: PhotoReviewActionV1,
    pub selected_artifact_id: Option<PhotoArtifactId>,
    #[ts(type = "number")]
    pub photo_revision: u64,
}

impl Validate for PhotoReviewDecisionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_safe_u64(self.photo_revision, SafeFieldV1::ExpectedReceiptRevision)?;
        let artifact_valid = match self.action {
            PhotoReviewActionV1::ConfirmCrop | PhotoReviewActionV1::ReplaceCrop => {
                self.selected_artifact_id.is_some()
            }
            PhotoReviewActionV1::Defer | PhotoReviewActionV1::Reject => {
                self.selected_artifact_id.is_none()
            }
        };
        if artifact_valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoReviewHeadV1 {
    pub state: PhotoObservationStateV1,
    pub decision: PhotoReviewDecisionV1,
}

impl Validate for PhotoReviewHeadV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.decision.validate()?;
        if self.state == self.decision.action.resulting_state() {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoObservationV1 {
    pub observation_id: PhotoObservationId,
    pub scope_id: PhotoScopeId,
    pub source_revision_id: PhotoSourceRevisionId,
    pub state: PhotoObservationStateV1,
    pub artifact: PhotoArtifactV1,
    pub review_head: Option<PhotoReviewHeadV1>,
}

impl Validate for PhotoObservationV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.artifact.validate()?;
        let head_valid = match (&self.state, &self.review_head) {
            (PhotoObservationStateV1::NeedsReview, None) => true,
            (state, Some(head)) => {
                head.validate().is_ok()
                    && *state == head.state
                    && head.decision.observation_id == self.observation_id
                    && head
                        .decision
                        .selected_artifact_id
                        .is_none_or(|artifact_id| artifact_id == self.artifact.artifact_id)
            }
            _ => false,
        };
        if head_valid
            && self.scope_id == self.artifact.scope_id
            && self.source_revision_id == self.artifact.source_revision_id
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, TS)]
#[serde(transparent)]
#[ts(type = "number[]")]
pub struct BoundedPhotoArtifactBytesV1(Vec<u8>);

impl BoundedPhotoArtifactBytesV1 {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        if bytes.is_empty() || bytes.len() > MAX_PHOTO_ARTIFACT_BYTES {
            Err(invalid(SafeFieldV1::Attributes))
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

impl<'de> Deserialize<'de> for BoundedPhotoArtifactBytesV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::new(bytes).map_err(|_| D::Error::custom("invalid photo artifact bytes"))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListImportedPhotoRootsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListImportedPhotoRootsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_page(self.limit)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CreatePhotoScopeV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub import_root_id: ImportRootId,
    #[ts(type = "number")]
    pub expected_manifest_generation: u64,
}

impl Validate for CreatePhotoScopeV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(
            self.expected_manifest_generation,
            SafeFieldV1::ExpectedCatalogRevision,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct AnalyzePhotoScopeV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub scope_id: PhotoScopeId,
}

impl Validate for AnalyzePhotoScopeV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DetectPhotoScopePeopleV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub scope_id: PhotoScopeId,
}

impl Validate for DetectPhotoScopePeopleV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListPhotoObservationsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub scope_id: PhotoScopeId,
    pub state: PhotoObservationStateV1,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListPhotoObservationsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_page(self.limit)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReadPhotoArtifactV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub artifact_id: PhotoArtifactId,
}

impl Validate for ReadPhotoArtifactV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PromptPhotoObservationV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub observation_id: PhotoObservationId,
    pub box_rectangle: RectV1,
    pub positive_points: Vec<PointV1>,
    pub negative_points: Vec<PointV1>,
}

impl Validate for PromptPhotoObservationV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        self.box_rectangle.validate_bounded()?;
        validate_prompt_points_bounded(&self.positive_points, &self.negative_points)
    }
}

impl PromptPhotoObservationV1Request {
    pub fn validate_geometry_within(
        &self,
        source_width: u32,
        source_height: u32,
    ) -> Result<(), ValidationError> {
        self.box_rectangle
            .validate_within(source_width, source_height)?;
        validate_prompt_points(
            &self.positive_points,
            &self.negative_points,
            source_width,
            source_height,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReviewPhotoObservationV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub observation_id: PhotoObservationId,
    pub action: PhotoReviewActionV1,
    pub replacement_rectangle: Option<RectV1>,
    #[ts(type = "number")]
    pub expected_photo_revision: u64,
}

impl Validate for ReviewPhotoObservationV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(
            self.expected_photo_revision,
            SafeFieldV1::ExpectedReceiptRevision,
        )?;
        match (self.action, self.replacement_rectangle) {
            (PhotoReviewActionV1::ReplaceCrop, Some(rectangle)) => rectangle.validate_bounded(),
            (PhotoReviewActionV1::ReplaceCrop, None) => Err(invalid(SafeFieldV1::Attributes)),
            (_, None) => Ok(()),
            (_, Some(_)) => Err(invalid(SafeFieldV1::Attributes)),
        }
    }
}

fn validate_prompt_points(
    positive: &[PointV1],
    negative: &[PointV1],
    width: u32,
    height: u32,
) -> Result<(), ValidationError> {
    if positive.len() > MAX_SEGMENTATION_PROMPT_POINTS
        || negative.len() > MAX_SEGMENTATION_PROMPT_POINTS
    {
        return Err(invalid(SafeFieldV1::Collection));
    }
    for point in positive.iter().chain(negative) {
        point.validate_within(width, height)?;
    }
    let mut all = positive
        .iter()
        .map(|point| (*point, true))
        .chain(negative.iter().map(|point| (*point, false)))
        .collect::<Vec<_>>();
    all.sort_by_key(|(point, _)| (point.x, point.y));
    if all.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(invalid(SafeFieldV1::Collection));
    }
    Ok(())
}

fn validate_prompt_points_bounded(
    positive: &[PointV1],
    negative: &[PointV1],
) -> Result<(), ValidationError> {
    validate_prompt_points(positive, negative, MAX_PHOTO_AXIS, MAX_PHOTO_AXIS)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListImportedPhotoRootsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub roots: Vec<ImportedPhotoRootV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub next_cursor: Option<PageCursorV1>,
}

impl Validate for ListImportedPhotoRootsV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(self.total_count, SafeFieldV1::Collection)?;
        validate_safe_u64(self.evidence_generation, SafeFieldV1::Collection)?;
        let mut root_ids = self
            .roots
            .iter()
            .map(|root| root.import_root_id)
            .collect::<Vec<_>>();
        root_ids.sort_unstable();
        root_ids.dedup();
        if root_ids.len() == self.roots.len()
            && self.roots.iter().all(|root| root.validate().is_ok())
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Collection))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CreatePhotoScopeV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub scope: PhotoScopeV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for CreatePhotoScopeV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        self.scope.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct AnalyzePhotoScopeV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub scope_id: PhotoScopeId,
    pub run_id: PhotoAnalysisRunId,
    pub state: PhotoAnalysisRunStateV1,
    pub member_count: u16,
    pub completed_count: u16,
    pub needs_review_count: u16,
    pub skipped_count: u16,
    pub failed_count: u16,
    #[ts(type = "number")]
    pub photo_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for AnalyzePhotoScopeV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(self.photo_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.evidence_generation, SafeFieldV1::Collection)?;
        let terminal = self
            .needs_review_count
            .checked_add(self.skipped_count)
            .and_then(|count| count.checked_add(self.failed_count));
        if self.member_count > 0
            && usize::from(self.member_count) <= MAX_PHOTO_SCOPE_MEMBERS
            && self.completed_count <= self.member_count
            && terminal == Some(self.completed_count)
            && (self.state != PhotoAnalysisRunStateV1::Completed
                || self.completed_count == self.member_count)
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Collection))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DetectPhotoScopePeopleV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub scope_id: PhotoScopeId,
    pub run_id: PhotoAnalysisRunId,
    pub state: PhotoAnalysisRunStateV1,
    pub member_count: u16,
    pub completed_count: u16,
    pub terminal_review_count: u16,
    pub instances_available_count: u16,
    pub no_person_detected_count: u16,
    pub overflow_count: u16,
    pub retryable_failure_count: u16,
    pub permanent_unavailable_count: u16,
    pub skipped_count: u16,
    #[ts(type = "number")]
    pub photo_revision: u64,
    #[ts(type = "number")]
    pub owner_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for DetectPhotoScopePeopleV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(self.photo_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.owner_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.evidence_generation, SafeFieldV1::Collection)?;
        let classified_reviews = self
            .instances_available_count
            .checked_add(self.no_person_detected_count)
            .and_then(|count| count.checked_add(self.overflow_count))
            .and_then(|count| count.checked_add(self.retryable_failure_count))
            .and_then(|count| count.checked_add(self.permanent_unavailable_count));
        let accounted_members = self.terminal_review_count.checked_add(self.skipped_count);
        if self.member_count > 0
            && usize::from(self.member_count) <= MAX_PHOTO_SCOPE_MEMBERS
            && self.completed_count <= self.member_count
            && classified_reviews == Some(self.terminal_review_count)
            && accounted_members == Some(self.completed_count)
            && (self.state != PhotoAnalysisRunStateV1::Completed
                || self.completed_count == self.member_count)
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Collection))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListPhotoObservationsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub scope_id: PhotoScopeId,
    pub state: PhotoObservationStateV1,
    pub observations: Vec<PhotoObservationV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub photo_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub next_cursor: Option<PageCursorV1>,
}

impl Validate for ListPhotoObservationsV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(self.total_count, SafeFieldV1::Collection)?;
        validate_safe_u64(self.photo_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.evidence_generation, SafeFieldV1::Collection)?;
        let mut observation_ids = self
            .observations
            .iter()
            .map(|observation| observation.observation_id)
            .collect::<Vec<_>>();
        observation_ids.sort_unstable();
        observation_ids.dedup();
        if observation_ids.len() == self.observations.len()
            && self.observations.iter().all(|observation| {
                observation.validate().is_ok()
                    && observation.scope_id == self.scope_id
                    && observation.state == self.state
            })
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Collection))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReadPhotoArtifactV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub artifact_id: PhotoArtifactId,
    pub media_type: PhotoMediaTypeV1,
    pub width: u32,
    pub height: u32,
    pub bytes_sha256: Sha256Digest,
    pub bytes: BoundedPhotoArtifactBytesV1,
}

impl Validate for ReadPhotoArtifactV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_dimensions(self.width, self.height)?;
        if Sha256Digest::from_bytes(self.bytes.as_slice()) == self.bytes_sha256 {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PromptPhotoObservationV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub observation: PhotoObservationV1,
    #[ts(type = "number")]
    pub photo_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for PromptPhotoObservationV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(self.photo_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.evidence_generation, SafeFieldV1::Collection)?;
        self.observation.validate()?;
        if self.observation.state == PhotoObservationStateV1::NeedsReview
            && self.observation.review_head.is_none()
            && self.observation.artifact.request_mode == SegmentationRequestModeKindV1::Interactive
            && !self.observation.artifact.quality_approved
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReviewPhotoObservationV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub observation: PhotoObservationV1,
    pub decision: PhotoReviewDecisionV1,
    #[ts(type = "number")]
    pub new_photo_revision: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for ReviewPhotoObservationV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(
            self.new_photo_revision,
            SafeFieldV1::ExpectedReceiptRevision,
        )?;
        self.observation.validate()?;
        self.decision.validate()?;
        if self
            .observation
            .review_head
            .as_ref()
            .map(|head| &head.decision)
            == Some(&self.decision)
            && self.observation.state == self.decision.action.resulting_state()
            && self.decision.photo_revision == self.new_photo_revision
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PersonDetectionTerminalStateV1 {
    SucceededZero,
    SucceededInstances,
    Overflow,
    RetryableFailure,
    PermanentUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PersonDetectionFailureReasonV1 {
    VisionRequestFailed,
    ResourceUnavailable,
    TimedOut,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PersonDetectionUnavailableReasonV1 {
    VisionFrameworkAbsent,
    VisionProcessUnavailable,
    UnsupportedOperatingSystem,
    UnsupportedRequestRevision,
    InvalidProviderOutput,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PersonEvidenceKindV1 {
    AppleVision,
    ManualUserRectangle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoOwnerReviewStateV1 {
    InstancesAvailable,
    NoPersonDetected,
    Overflow,
    RetryableFailure,
    PermanentUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoOwnerActionV1 {
    SelectPerson,
    OwnerAbsent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonDetectionProviderDescriptorV1 {
    pub contract_revision: String,
    pub provider_revision: String,
    pub preprocessing_revision: String,
    pub vision_request_revision: u32,
    pub os_build: String,
    pub vision_framework_build: String,
}

impl Validate for PersonDetectionProviderDescriptorV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.contract_revision != LOCAL_PERSON_DETECTION_CONTRACT_V1
            || self.provider_revision != APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1
            || self.preprocessing_revision != PHOTO_PREPROCESSING_REVISION_V1
            || self.vision_request_revision == 0
        {
            return Err(invalid(SafeFieldV1::Provider));
        }
        validate_identifier(&self.os_build)?;
        validate_identifier(&self.vision_framework_build)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersonDetectionRequestV1 {
    pub contract_revision: String,
    pub request_handle: PersonDetectionRequestHandle,
    pub source_revision_sha256: Sha256Digest,
    pub input_blob_sha256: Sha256Digest,
    pub width: u32,
    pub height: u32,
    pub rgb_row_stride: u32,
    pub pixels: CanonicalSrgbPixelBufferV1,
    pub preprocessing_revision: String,
}

impl Validate for PersonDetectionRequestV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.contract_revision != LOCAL_PERSON_DETECTION_CONTRACT_V1
            || self.preprocessing_revision != PHOTO_PREPROCESSING_REVISION_V1
        {
            return Err(invalid(SafeFieldV1::Provider));
        }
        validate_dimensions(self.width, self.height)?;
        let row_stride = self.width.checked_mul(3);
        let expected_bytes = row_stride
            .and_then(|stride| stride.checked_mul(self.height))
            .and_then(|bytes| usize::try_from(bytes).ok());
        if row_stride == Some(self.rgb_row_stride)
            && expected_bytes == Some(self.pixels.as_bytes().len())
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DetectedPersonRectangleV1 {
    pub rectangle: RectV1,
    pub confidence_basis_points: u16,
}

impl DetectedPersonRectangleV1 {
    fn validate_within(&self, width: u32, height: u32) -> Result<(), ValidationError> {
        self.rectangle.validate_within(width, height)?;
        if self.confidence_basis_points <= MAX_PERSON_CONFIDENCE_BASIS_POINTS_V1 {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::ReceiptProviderOutput))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum PersonDetectionResultV1 {
    SucceededZero,
    SucceededInstances {
        instances: Vec<DetectedPersonRectangleV1>,
    },
    Overflow {
        detected_count: u32,
    },
    RetryableFailure {
        reason: PersonDetectionFailureReasonV1,
    },
    PermanentUnavailable {
        reason: PersonDetectionUnavailableReasonV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonDetectionOutcomeV1 {
    pub contract_revision: String,
    pub request_handle: PersonDetectionRequestHandle,
    pub source_revision_sha256: Sha256Digest,
    pub input_blob_sha256: Sha256Digest,
    pub result: PersonDetectionResultV1,
}

impl PersonDetectionOutcomeV1 {
    pub fn validate_against(
        &self,
        descriptor: &PersonDetectionProviderDescriptorV1,
        request: &PersonDetectionRequestV1,
    ) -> Result<(), ValidationError> {
        descriptor.validate()?;
        request.validate()?;
        if descriptor.preprocessing_revision != request.preprocessing_revision
            || self.contract_revision != LOCAL_PERSON_DETECTION_CONTRACT_V1
            || self.request_handle != request.request_handle
            || self.source_revision_sha256 != request.source_revision_sha256
            || self.input_blob_sha256 != request.input_blob_sha256
        {
            return Err(invalid(SafeFieldV1::ReceiptProviderOutput));
        }
        match &self.result {
            PersonDetectionResultV1::SucceededZero
            | PersonDetectionResultV1::RetryableFailure { .. }
            | PersonDetectionResultV1::PermanentUnavailable { .. } => Ok(()),
            PersonDetectionResultV1::Overflow { detected_count }
                if usize::try_from(*detected_count)
                    .ok()
                    .is_some_and(|count| count > MAX_PERSON_INSTANCES_V1) =>
            {
                Ok(())
            }
            PersonDetectionResultV1::SucceededInstances { instances }
                if (1..=MAX_PERSON_INSTANCES_V1).contains(&instances.len()) =>
            {
                for instance in instances {
                    instance.validate_within(request.width, request.height)?;
                }
                Ok(())
            }
            _ => Err(invalid(SafeFieldV1::ReceiptProviderOutput)),
        }
    }

    pub fn terminal_state(&self) -> PersonDetectionTerminalStateV1 {
        match self.result {
            PersonDetectionResultV1::SucceededZero => PersonDetectionTerminalStateV1::SucceededZero,
            PersonDetectionResultV1::SucceededInstances { .. } => {
                PersonDetectionTerminalStateV1::SucceededInstances
            }
            PersonDetectionResultV1::Overflow { .. } => PersonDetectionTerminalStateV1::Overflow,
            PersonDetectionResultV1::RetryableFailure { .. } => {
                PersonDetectionTerminalStateV1::RetryableFailure
            }
            PersonDetectionResultV1::PermanentUnavailable { .. } => {
                PersonDetectionTerminalStateV1::PermanentUnavailable
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoPersonInstanceV1 {
    pub person_instance_id: PhotoPersonInstanceId,
    pub owner_review_id: PhotoOwnerReviewId,
    pub source_revision_id: PhotoSourceRevisionId,
    pub source_revision_sha256: Sha256Digest,
    pub source_kind: PersonEvidenceKindV1,
    pub rectangle: RectV1,
    pub confidence_basis_points: Option<u16>,
    pub provider_revision: Option<String>,
}

impl Validate for PhotoPersonInstanceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.rectangle.validate_bounded()?;
        match (
            self.source_kind,
            self.confidence_basis_points,
            &self.provider_revision,
        ) {
            (PersonEvidenceKindV1::AppleVision, Some(confidence), Some(provider_revision))
                if confidence <= MAX_PERSON_CONFIDENCE_BASIS_POINTS_V1
                    && provider_revision == APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1 =>
            {
                Ok(())
            }
            (PersonEvidenceKindV1::ManualUserRectangle, None, None) => Ok(()),
            _ => Err(invalid(SafeFieldV1::Attributes)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoOwnerReviewV1 {
    pub owner_review_id: PhotoOwnerReviewId,
    pub source_revision_id: PhotoSourceRevisionId,
    pub source_revision_sha256: Sha256Digest,
    pub preview_id: PhotoOwnerPreviewId,
    pub terminal_attempt_id: PhotoPersonDetectionAttemptId,
    pub terminal_detection_state: PersonDetectionTerminalStateV1,
    pub state: PhotoOwnerReviewStateV1,
    pub instances: Vec<PhotoPersonInstanceV1>,
    pub provider_contract_revision: String,
    pub provider_revision: String,
    pub preprocessing_revision: String,
    pub vision_request_revision: u32,
    pub safe_reason_code: Option<String>,
    #[ts(type = "number")]
    pub detection_revision: u64,
    #[ts(type = "number")]
    pub owner_head_revision: u64,
    #[ts(type = "number")]
    pub photo_revision: u64,
}

impl Validate for PhotoOwnerReviewV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_safe_u64(self.detection_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.owner_head_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.photo_revision, SafeFieldV1::Collection)?;
        if self.detection_revision == 0
            || self.provider_contract_revision != LOCAL_PERSON_DETECTION_CONTRACT_V1
            || self.provider_revision != APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1
            || self.preprocessing_revision != PHOTO_PREPROCESSING_REVISION_V1
            || self.vision_request_revision == 0
            || self.instances.len() > MAX_PERSON_INSTANCES_V1
            || self.instances.iter().any(|instance| {
                instance.validate().is_err()
                    || instance.owner_review_id != self.owner_review_id
                    || instance.source_revision_id != self.source_revision_id
                    || instance.source_revision_sha256 != self.source_revision_sha256
            })
        {
            return Err(invalid(SafeFieldV1::Attributes));
        }
        validate_unique_ids(
            &self
                .instances
                .iter()
                .map(|instance| instance.person_instance_id)
                .collect::<Vec<_>>(),
            MAX_PERSON_INSTANCES_V1,
        )?;
        if let Some(reason) = &self.safe_reason_code {
            if reason.is_empty()
                || reason.len() > MAX_PHOTO_REASON_CODE_CHARS
                || !reason.is_ascii()
                || reason.trim() != reason
                || reason.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(invalid(SafeFieldV1::Attributes));
            }
        }
        let state_valid = match self.state {
            PhotoOwnerReviewStateV1::InstancesAvailable => !self.instances.is_empty(),
            PhotoOwnerReviewStateV1::NoPersonDetected => {
                self.instances.is_empty()
                    && self.terminal_detection_state
                        == PersonDetectionTerminalStateV1::SucceededZero
            }
            PhotoOwnerReviewStateV1::RetryableFailure => {
                self.terminal_detection_state == PersonDetectionTerminalStateV1::RetryableFailure
            }
            PhotoOwnerReviewStateV1::PermanentUnavailable => {
                self.terminal_detection_state
                    == PersonDetectionTerminalStateV1::PermanentUnavailable
            }
            PhotoOwnerReviewStateV1::Overflow => {
                self.terminal_detection_state == PersonDetectionTerminalStateV1::Overflow
            }
        };
        if state_valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoOwnerDecisionV1 {
    pub owner_decision_id: PhotoOwnerDecisionId,
    pub owner_review_id: PhotoOwnerReviewId,
    pub action: PhotoOwnerActionV1,
    pub selected_person_instance_id: Option<PhotoPersonInstanceId>,
    pub supersedes_owner_decision_id: Option<PhotoOwnerDecisionId>,
    #[ts(type = "number")]
    pub detection_revision: u64,
    #[ts(type = "number")]
    pub owner_revision: u64,
    #[ts(type = "number")]
    pub photo_revision: u64,
}

impl Validate for PhotoOwnerDecisionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_safe_u64(self.detection_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.owner_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.photo_revision, SafeFieldV1::Collection)?;
        if self.detection_revision == 0 || self.owner_revision == 0 {
            return Err(invalid(SafeFieldV1::DecisionId));
        }
        match (self.action, self.selected_person_instance_id) {
            (PhotoOwnerActionV1::SelectPerson, Some(_))
            | (PhotoOwnerActionV1::OwnerAbsent, None) => Ok(()),
            _ => Err(invalid(SafeFieldV1::DecisionId)),
        }
    }
}

fn validate_owner_action(
    action: PhotoOwnerActionV1,
    selected_person_instance_id: Option<PhotoPersonInstanceId>,
) -> Result<(), ValidationError> {
    match (action, selected_person_instance_id) {
        (PhotoOwnerActionV1::SelectPerson, Some(_)) | (PhotoOwnerActionV1::OwnerAbsent, None) => {
            Ok(())
        }
        _ => Err(invalid(SafeFieldV1::DecisionId)),
    }
}

fn validate_owner_revisions(
    expected_detection_revision: u64,
    expected_owner_head_revision: u64,
    expected_photo_revision: u64,
) -> Result<(), ValidationError> {
    validate_safe_u64(expected_detection_revision, SafeFieldV1::Collection)?;
    validate_safe_u64(expected_owner_head_revision, SafeFieldV1::Collection)?;
    validate_safe_u64(expected_photo_revision, SafeFieldV1::Collection)?;
    if expected_detection_revision == 0 {
        Err(invalid(SafeFieldV1::Collection))
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListPhotoOwnerReviewsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub state: PhotoOwnerReviewStateV1,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListPhotoOwnerReviewsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_page(self.limit)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReadPhotoOwnerPreviewV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub owner_review_id: PhotoOwnerReviewId,
    pub preview_id: PhotoOwnerPreviewId,
}

impl Validate for ReadPhotoOwnerPreviewV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DecidePhotoOwnerV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub owner_review_id: PhotoOwnerReviewId,
    pub action: PhotoOwnerActionV1,
    pub selected_person_instance_id: Option<PhotoPersonInstanceId>,
    #[ts(type = "number")]
    pub expected_detection_revision: u64,
    #[ts(type = "number")]
    pub expected_owner_head_revision: u64,
    #[ts(type = "number")]
    pub expected_photo_revision: u64,
}

impl Validate for DecidePhotoOwnerV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_owner_action(self.action, self.selected_person_instance_id)?;
        validate_owner_revisions(
            self.expected_detection_revision,
            self.expected_owner_head_revision,
            self.expected_photo_revision,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CorrectPhotoOwnerV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub owner_review_id: PhotoOwnerReviewId,
    pub superseded_owner_decision_id: PhotoOwnerDecisionId,
    pub action: PhotoOwnerActionV1,
    pub selected_person_instance_id: Option<PhotoPersonInstanceId>,
    #[ts(type = "number")]
    pub expected_detection_revision: u64,
    #[ts(type = "number")]
    pub expected_owner_head_revision: u64,
    #[ts(type = "number")]
    pub expected_photo_revision: u64,
}

impl Validate for CorrectPhotoOwnerV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_owner_action(self.action, self.selected_person_instance_id)?;
        validate_owner_revisions(
            self.expected_detection_revision,
            self.expected_owner_head_revision,
            self.expected_photo_revision,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CorrectPhotoPersonDetectionV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub owner_review_id: PhotoOwnerReviewId,
    pub manual_rectangle: RectV1,
    pub expected_terminal_attempt_id: PhotoPersonDetectionAttemptId,
    #[ts(type = "number")]
    pub expected_detection_revision: u64,
    #[ts(type = "number")]
    pub expected_owner_head_revision: u64,
    #[ts(type = "number")]
    pub expected_photo_revision: u64,
}

impl Validate for CorrectPhotoPersonDetectionV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        self.manual_rectangle.validate_bounded()?;
        validate_owner_revisions(
            self.expected_detection_revision,
            self.expected_owner_head_revision,
            self.expected_photo_revision,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RetryPhotoPersonDetectionV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub owner_review_id: PhotoOwnerReviewId,
    pub expected_terminal_attempt_id: PhotoPersonDetectionAttemptId,
    #[ts(type = "number")]
    pub expected_detection_revision: u64,
    #[ts(type = "number")]
    pub expected_owner_head_revision: u64,
    #[ts(type = "number")]
    pub expected_photo_revision: u64,
}

impl Validate for RetryPhotoPersonDetectionV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_owner_revisions(
            self.expected_detection_revision,
            self.expected_owner_head_revision,
            self.expected_photo_revision,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListPhotoOwnerReviewsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub state: PhotoOwnerReviewStateV1,
    pub reviews: Vec<PhotoOwnerReviewV1>,
    pub next_cursor: Option<PageCursorV1>,
    #[ts(type = "number")]
    pub photo_revision: u64,
    #[ts(type = "number")]
    pub owner_revision: u64,
}

impl Validate for ListPhotoOwnerReviewsV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(self.photo_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.owner_revision, SafeFieldV1::Collection)?;
        if self.reviews.len() > MAX_PHOTO_PAGE_SIZE as usize
            || self
                .reviews
                .iter()
                .any(|review| review.validate().is_err() || review.state != self.state)
        {
            return Err(invalid(SafeFieldV1::Collection));
        }
        validate_unique_ids(
            &self
                .reviews
                .iter()
                .map(|review| review.owner_review_id)
                .collect::<Vec<_>>(),
            MAX_PHOTO_PAGE_SIZE as usize,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReadPhotoOwnerPreviewV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub owner_review_id: PhotoOwnerReviewId,
    pub preview_id: PhotoOwnerPreviewId,
    pub media_type: PhotoMediaTypeV1,
    pub width: u32,
    pub height: u32,
    #[ts(type = "number")]
    pub byte_length: u64,
    pub bytes_sha256: Sha256Digest,
    pub bytes: BoundedPhotoArtifactBytesV1,
}

impl Validate for ReadPhotoOwnerPreviewV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_dimensions(self.width, self.height)?;
        if self.byte_length == self.bytes.as_slice().len() as u64
            && Sha256Digest::from_bytes(self.bytes.as_slice()) == self.bytes_sha256
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DecidePhotoOwnerV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub review: PhotoOwnerReviewV1,
    pub decision: PhotoOwnerDecisionV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for DecidePhotoOwnerV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        self.review.validate()?;
        self.decision.validate()?;
        if self.review.owner_review_id == self.decision.owner_review_id
            && self.review.owner_head_revision == self.decision.owner_revision
            && self.review.photo_revision == self.decision.photo_revision
            && self.decision.supersedes_owner_decision_id.is_none()
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::DecisionId))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CorrectPhotoOwnerV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub review: PhotoOwnerReviewV1,
    pub decision: PhotoOwnerDecisionV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for CorrectPhotoOwnerV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        self.review.validate()?;
        self.decision.validate()?;
        if self.review.owner_review_id == self.decision.owner_review_id
            && self.review.owner_head_revision == self.decision.owner_revision
            && self.review.photo_revision == self.decision.photo_revision
            && self.decision.supersedes_owner_decision_id.is_some()
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::DecisionId))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CorrectPhotoPersonDetectionV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub review: PhotoOwnerReviewV1,
    pub instance: PhotoPersonInstanceV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for CorrectPhotoPersonDetectionV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        self.review.validate()?;
        self.instance.validate()?;
        if self.instance.source_kind == PersonEvidenceKindV1::ManualUserRectangle
            && self.instance.owner_review_id == self.review.owner_review_id
            && self.review.instances.contains(&self.instance)
        {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RetryPhotoPersonDetectionV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub owner_review_id: PhotoOwnerReviewId,
    #[ts(type = "number")]
    pub detection_revision: u64,
    #[ts(type = "number")]
    pub owner_revision: u64,
    #[ts(type = "number")]
    pub photo_revision: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for RetryPhotoPersonDetectionV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_u64(self.detection_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.owner_revision, SafeFieldV1::Collection)?;
        validate_safe_u64(self.photo_revision, SafeFieldV1::Collection)?;
        if self.detection_revision == 0 {
            Err(invalid(SafeFieldV1::Collection))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentationProviderDescriptorV1 {
    pub contract_revision: String,
    pub provider_id: String,
    pub provider_revision: String,
    pub model_revision: Option<String>,
    pub preprocessing_revision: String,
    pub automatic_capability: SegmentationCapabilityV1,
    pub interactive_capability: SegmentationCapabilityV1,
    pub maximum_masks: u8,
}

impl Validate for SegmentationProviderDescriptorV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.contract_revision != GARMENT_SEGMENTATION_CONTRACT_V1 {
            return Err(invalid(SafeFieldV1::Provider));
        }
        validate_identifier(&self.provider_id)?;
        validate_identifier(&self.provider_revision)?;
        if let Some(model_revision) = &self.model_revision {
            validate_identifier(model_revision)?;
        }
        validate_identifier(&self.preprocessing_revision)?;
        if (1..=MAX_SEGMENTATION_MASKS as u8).contains(&self.maximum_masks) {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Provider))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SegmentationRequestModeV1 {
    Automatic,
    Interactive {
        box_rectangle: RectV1,
        positive_points: Vec<PointV1>,
        negative_points: Vec<PointV1>,
    },
}

impl SegmentationRequestModeV1 {
    pub fn kind(&self) -> SegmentationRequestModeKindV1 {
        match self {
            Self::Automatic => SegmentationRequestModeKindV1::Automatic,
            Self::Interactive { .. } => SegmentationRequestModeKindV1::Interactive,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CanonicalSrgbPixelBufferV1 {
    bytes: Vec<u8>,
}

impl CanonicalSrgbPixelBufferV1 {
    pub fn new(bytes: Vec<u8>, width: u32, height: u32) -> Result<Self, ValidationError> {
        validate_dimensions(width, height)?;
        let expected = u64::from(width)
            .checked_mul(u64::from(height))
            .and_then(|pixels| pixels.checked_mul(3))
            .and_then(|bytes| usize::try_from(bytes).ok());
        if expected == Some(bytes.len()) {
            Ok(Self { bytes })
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for CanonicalSrgbPixelBufferV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalSrgbPixelBufferV1")
            .field("byte_length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentationRequestV1 {
    pub contract_revision: String,
    pub request_handle: SegmentationRequestHandle,
    pub source_revision_sha256: Sha256Digest,
    pub input_blob_sha256: Sha256Digest,
    pub pixels: CanonicalSrgbPixelBufferV1,
    pub width: u32,
    pub height: u32,
    pub preprocessing_revision: String,
    pub mode: SegmentationRequestModeV1,
}

impl Validate for SegmentationRequestV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.contract_revision != GARMENT_SEGMENTATION_CONTRACT_V1 {
            return Err(invalid(SafeFieldV1::Provider));
        }
        validate_dimensions(self.width, self.height)?;
        validate_identifier(&self.preprocessing_revision)?;
        let expected_bytes = u64::from(self.width) * u64::from(self.height) * 3;
        if usize::try_from(expected_bytes).ok() != Some(self.pixels.as_bytes().len()) {
            return Err(invalid(SafeFieldV1::Attributes));
        }
        match &self.mode {
            SegmentationRequestModeV1::Automatic => Ok(()),
            SegmentationRequestModeV1::Interactive {
                box_rectangle,
                positive_points,
                negative_points,
            } => {
                box_rectangle.validate_within(self.width, self.height)?;
                validate_prompt_points(positive_points, negative_points, self.width, self.height)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum SegmentationResultV1 {
    AutomaticMasks {
        masks: Vec<MaskV1>,
    },
    InteractiveMasks {
        masks: Vec<MaskV1>,
    },
    NoGarment,
    Unavailable {
        reason: SegmentationUnavailableReasonV1,
    },
    Failed {
        code: SegmentationFailureCodeV1,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentationOutcomeV1 {
    pub contract_revision: String,
    pub request_handle: SegmentationRequestHandle,
    pub source_revision_sha256: Sha256Digest,
    pub input_blob_sha256: Sha256Digest,
    pub result: SegmentationResultV1,
}

impl SegmentationOutcomeV1 {
    pub fn unavailable(
        request: &SegmentationRequestV1,
        reason: SegmentationUnavailableReasonV1,
    ) -> Self {
        Self {
            contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
            request_handle: request.request_handle,
            source_revision_sha256: request.source_revision_sha256.clone(),
            input_blob_sha256: request.input_blob_sha256.clone(),
            result: SegmentationResultV1::Unavailable { reason },
        }
    }

    pub fn validate_against(
        &self,
        descriptor: &SegmentationProviderDescriptorV1,
        request: &SegmentationRequestV1,
    ) -> Result<(), ValidationError> {
        descriptor.validate()?;
        request.validate()?;
        if request.preprocessing_revision != descriptor.preprocessing_revision
            || self.contract_revision != GARMENT_SEGMENTATION_CONTRACT_V1
            || self.request_handle != request.request_handle
            || self.source_revision_sha256 != request.source_revision_sha256
            || self.input_blob_sha256 != request.input_blob_sha256
        {
            return Err(invalid(SafeFieldV1::ReceiptProviderOutput));
        }
        let requested_capability = match request.mode {
            SegmentationRequestModeV1::Automatic => descriptor.automatic_capability,
            SegmentationRequestModeV1::Interactive { .. } => descriptor.interactive_capability,
        };
        let masks = match &self.result {
            SegmentationResultV1::AutomaticMasks { masks }
                if matches!(request.mode, SegmentationRequestModeV1::Automatic)
                    && descriptor.automatic_capability == SegmentationCapabilityV1::Available =>
            {
                Some(masks)
            }
            SegmentationResultV1::InteractiveMasks { masks }
                if matches!(request.mode, SegmentationRequestModeV1::Interactive { .. })
                    && descriptor.interactive_capability == SegmentationCapabilityV1::Available =>
            {
                Some(masks)
            }
            SegmentationResultV1::AutomaticMasks { .. }
            | SegmentationResultV1::InteractiveMasks { .. } => {
                return Err(invalid(SafeFieldV1::ReceiptProviderOutput));
            }
            SegmentationResultV1::NoGarment | SegmentationResultV1::Failed { .. }
                if requested_capability == SegmentationCapabilityV1::Available =>
            {
                None
            }
            SegmentationResultV1::Unavailable { .. } => None,
            SegmentationResultV1::NoGarment | SegmentationResultV1::Failed { .. } => {
                return Err(invalid(SafeFieldV1::ReceiptProviderOutput));
            }
        };
        if let Some(masks) = masks {
            if masks.is_empty()
                || masks.len() > MAX_SEGMENTATION_MASKS
                || masks.len() > usize::from(descriptor.maximum_masks)
            {
                return Err(invalid(SafeFieldV1::ReceiptProviderOutput));
            }
            for mask in masks {
                mask.validate_for_dimensions(request.width, request.height)?;
            }
            for (index, mask) in masks.iter().enumerate() {
                if masks[..index]
                    .iter()
                    .any(|prior| prior.packed_bits == mask.packed_bits)
                {
                    return Err(invalid(SafeFieldV1::ReceiptProviderOutput));
                }
            }
        }
        Ok(())
    }
}

pub fn prompt_parameters_sha256_v1(
    mode: &SegmentationRequestModeV1,
) -> Result<Sha256Digest, ValidationError> {
    let bytes = match mode {
        SegmentationRequestModeV1::Automatic => b"automatic-v1".to_vec(),
        SegmentationRequestModeV1::Interactive {
            box_rectangle,
            positive_points,
            negative_points,
        } => {
            let mut bytes = b"interactive-v1".to_vec();
            for value in [
                box_rectangle.x,
                box_rectangle.y,
                box_rectangle.width,
                box_rectangle.height,
            ] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
            bytes.push(positive_points.len() as u8);
            for point in positive_points {
                bytes.extend_from_slice(&point.x.to_be_bytes());
                bytes.extend_from_slice(&point.y.to_be_bytes());
            }
            bytes.push(negative_points.len() as u8);
            for point in negative_points {
                bytes.extend_from_slice(&point.x.to_be_bytes());
                bytes.extend_from_slice(&point.y.to_be_bytes());
            }
            bytes
        }
    };
    Ok(Sha256Digest::parse(format!("{:x}", Sha256::digest(bytes)))
        .expect("SHA-256 formatting is canonical"))
}
