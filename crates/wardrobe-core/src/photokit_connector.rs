use std::fmt;

use serde::de::{Error as _, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use crate::contracts::deserialize_schema_version_v1;
use crate::validation::{require_schema_v1, validate_bounded_text, validate_timestamp};
use crate::{
    OperationId, ReplayStatusV1, RequestId, SafeFieldV1, Validate, ValidationError,
    MAX_SAFE_INTEGER_V1,
};

pub const MAX_PHOTOKIT_ALBUM_CANDIDATES: usize = 100;
pub const MAX_PHOTOKIT_ALBUM_LABEL_CHARS: usize = 80;
pub const MAX_PHOTOKIT_SELECTION_TOKEN_BYTES: usize = 128;
pub const MAX_PHOTOKIT_ASSETS: u16 = 500;
pub const MAX_PHOTOKIT_AVAILABILITY_COUNTS: usize = 12;

macro_rules! photokit_uuid_id {
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

macro_rules! photokit_number_id {
    ($name:ident, $allow_zero:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
        #[serde(transparent)]
        pub struct $name(#[ts(type = "number")] u64);

        impl $name {
            pub fn new(value: u64) -> Result<Self, &'static str> {
                if value >= MAX_SAFE_INTEGER_V1 || (!$allow_zero && value == 0) {
                    Err("numeric identity is outside its safe range")
                } else {
                    Ok(Self(value))
                }
            }

            pub fn get(self) -> u64 {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = u64::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

photokit_uuid_id!(PhotoKitEnrollmentEpochV1);
photokit_uuid_id!(PhotoKitSetupSessionIdV1);
photokit_number_id!(PhotoKitReconciliationFenceV1, false);
photokit_number_id!(PhotoKitMembershipGenerationV1, false);
photokit_number_id!(PhotoKitRevisionV1, true);

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(transparent)]
pub struct PhotoKitSelectionTokenV1(#[ts(type = "string")] String);

impl PhotoKitSelectionTokenV1 {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PHOTOKIT_SELECTION_TOKEN_BYTES
            || !value.is_ascii()
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("selection token must be bounded printable ASCII");
        }
        Ok(Self(value))
    }

    pub fn expose_process_token(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PhotoKitSelectionTokenV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PhotoKitSelectionTokenV1([OPAQUE])")
    }
}

impl<'de> Deserialize<'de> for PhotoKitSelectionTokenV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoKitAuthorizationV1 {
    NotDetermined,
    Restricted,
    Denied,
    Limited,
    Authorized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoKitConnectorStateV1 {
    Unconfigured,
    SetupRequired,
    Ready,
    Reconciling,
    NeedsAttention,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoKitAvailabilityV1 {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoKitAvailabilityReasonV1 {
    Materialized,
    Accessible,
    AuthorizationNotDetermined,
    AuthorizationRestricted,
    AuthorizationDenied,
    LimitedAccess,
    ScopeUnavailable,
    AssetNotInScope,
    IcloudUnavailable,
    UnsupportedResource,
    TransferFailed,
    BlobIntegrityFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum PhotoKitReconcileTriggerV1 {
    Startup,
    User,
    LibraryChange,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoKitAssetCountsV1 {
    pub observed: u16,
    pub available: u16,
    pub unavailable: u16,
}

impl Validate for PhotoKitAssetCountsV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.observed > MAX_PHOTOKIT_ASSETS
            || self.available > MAX_PHOTOKIT_ASSETS
            || self.unavailable > MAX_PHOTOKIT_ASSETS
            || u32::from(self.available) + u32::from(self.unavailable) != u32::from(self.observed)
        {
            return Err(ValidationError::new(SafeFieldV1::PhotoKitCounts));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoKitAvailabilityCountV1 {
    pub availability: PhotoKitAvailabilityV1,
    pub reason: PhotoKitAvailabilityReasonV1,
    pub count: u16,
}

impl Validate for PhotoKitAvailabilityCountV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let reason_matches_state = match self.availability {
            PhotoKitAvailabilityV1::Available => matches!(
                self.reason,
                PhotoKitAvailabilityReasonV1::Materialized
                    | PhotoKitAvailabilityReasonV1::Accessible
            ),
            PhotoKitAvailabilityV1::Unavailable => !matches!(
                self.reason,
                PhotoKitAvailabilityReasonV1::Materialized
                    | PhotoKitAvailabilityReasonV1::Accessible
            ),
        };
        if self.count == 0 || self.count > MAX_PHOTOKIT_ASSETS || !reason_matches_state {
            return Err(ValidationError::new(SafeFieldV1::PhotoKitAvailability));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoKitAlbumCandidateV1 {
    pub selection_token: PhotoKitSelectionTokenV1,
    pub display_label: String,
}

impl Validate for PhotoKitAlbumCandidateV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(
            &self.display_label,
            1,
            MAX_PHOTOKIT_ALBUM_LABEL_CHARS,
            SafeFieldV1::PhotoKitAlbumLabel,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PhotoKitConnectorSnapshotV1 {
    pub state: PhotoKitConnectorStateV1,
    pub authorization: PhotoKitAuthorizationV1,
    pub enrollment_epoch: Option<PhotoKitEnrollmentEpochV1>,
    pub membership_generation: Option<PhotoKitMembershipGenerationV1>,
    pub photokit_revision: PhotoKitRevisionV1,
    pub allow_icloud_downloads: bool,
    pub last_complete_at: Option<String>,
    pub counts: PhotoKitAssetCountsV1,
    pub availability_counts: Vec<PhotoKitAvailabilityCountV1>,
}

impl Validate for PhotoKitConnectorSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.counts.validate()?;
        validate_availability_counts(&self.counts, &self.availability_counts)?;
        if let Some(timestamp) = &self.last_complete_at {
            validate_timestamp(timestamp)?;
        }

        let has_enrollment = self.enrollment_epoch.is_some();
        let has_generation = self.membership_generation.is_some();
        let configured_state = matches!(
            self.state,
            PhotoKitConnectorStateV1::Ready
                | PhotoKitConnectorStateV1::Reconciling
                | PhotoKitConnectorStateV1::NeedsAttention
        );
        if configured_state != has_enrollment
            || (!has_generation
                && (self.last_complete_at.is_some()
                    || self.counts.observed != 0
                    || !self.availability_counts.is_empty()))
            || (has_generation && self.last_complete_at.is_none())
            || (!has_enrollment && self.allow_icloud_downloads)
        {
            return Err(ValidationError::new(SafeFieldV1::PhotoKitStatus));
        }
        Ok(())
    }
}

macro_rules! photokit_request_envelope {
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

photokit_request_envelope!(GetPhotoKitConnectorV1Request);
photokit_request_envelope!(BeginPhotoKitSetupV1Request);
photokit_request_envelope!(SyncPhotoKitV1Request);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ConfigurePhotoKitScopeV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub setup_session_id: PhotoKitSetupSessionIdV1,
    pub selection_token: PhotoKitSelectionTokenV1,
    pub allow_icloud_downloads: bool,
}

impl Validate for ConfigurePhotoKitScopeV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DisablePhotoKitV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub expected_photokit_revision: PhotoKitRevisionV1,
}

impl Validate for DisablePhotoKitV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GetPhotoKitConnectorV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub snapshot: PhotoKitConnectorSnapshotV1,
}

impl Validate for GetPhotoKitConnectorV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.snapshot.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct BeginPhotoKitSetupV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub snapshot: PhotoKitConnectorSnapshotV1,
    pub setup_session_id: Option<PhotoKitSetupSessionIdV1>,
    pub expires_at: Option<String>,
    pub album_candidates: Vec<PhotoKitAlbumCandidateV1>,
    pub replay_status: ReplayStatusV1,
}

impl Validate for BeginPhotoKitSetupV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.snapshot.validate()?;
        if self.album_candidates.len() > MAX_PHOTOKIT_ALBUM_CANDIDATES
            || self
                .album_candidates
                .iter()
                .any(|candidate| candidate.validate().is_err())
            || self
                .album_candidates
                .iter()
                .enumerate()
                .any(|(index, candidate)| {
                    self.album_candidates[..index]
                        .iter()
                        .any(|prior| prior.selection_token == candidate.selection_token)
                })
        {
            return Err(ValidationError::new(SafeFieldV1::PhotoKitAlbumCandidates));
        }
        if let Some(timestamp) = &self.expires_at {
            validate_timestamp(timestamp)?;
        }

        let has_session = self.setup_session_id.is_some();
        if has_session != self.expires_at.is_some()
            || has_session != (self.snapshot.authorization == PhotoKitAuthorizationV1::Authorized)
            || (!has_session && !self.album_candidates.is_empty())
        {
            return Err(ValidationError::new(SafeFieldV1::PhotoKitSetupSession));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ConfigurePhotoKitScopeV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub snapshot: PhotoKitConnectorSnapshotV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for ConfigurePhotoKitScopeV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.snapshot.validate()?;
        if self.snapshot.enrollment_epoch.is_none()
            || !matches!(
                self.snapshot.state,
                PhotoKitConnectorStateV1::Ready | PhotoKitConnectorStateV1::Reconciling
            )
        {
            return Err(ValidationError::new(SafeFieldV1::PhotoKitStatus));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SyncPhotoKitV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub trigger: PhotoKitReconcileTriggerV1,
    pub reconciliation_fence: PhotoKitReconciliationFenceV1,
    pub snapshot: PhotoKitConnectorSnapshotV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for SyncPhotoKitV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.snapshot.validate()?;
        if self.snapshot.enrollment_epoch.is_none()
            || matches!(
                self.snapshot.state,
                PhotoKitConnectorStateV1::Unconfigured | PhotoKitConnectorStateV1::SetupRequired
            )
        {
            return Err(ValidationError::new(SafeFieldV1::PhotoKitStatus));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DisablePhotoKitV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub state: PhotoKitConnectorStateV1,
    pub disabled_enrollment_epoch: PhotoKitEnrollmentEpochV1,
    pub preserved_membership_generation: Option<PhotoKitMembershipGenerationV1>,
    pub photokit_revision: PhotoKitRevisionV1,
    pub preserved_counts: PhotoKitAssetCountsV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for DisablePhotoKitV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.preserved_counts.validate()?;
        if self.state != PhotoKitConnectorStateV1::Unconfigured
            || (self.preserved_membership_generation.is_none()
                && self.preserved_counts.observed != 0)
        {
            return Err(ValidationError::new(SafeFieldV1::PhotoKitStatus));
        }
        Ok(())
    }
}

fn validate_availability_counts(
    counts: &PhotoKitAssetCountsV1,
    availability_counts: &[PhotoKitAvailabilityCountV1],
) -> Result<(), ValidationError> {
    if availability_counts.len() > MAX_PHOTOKIT_AVAILABILITY_COUNTS {
        return Err(ValidationError::new(SafeFieldV1::PhotoKitAvailability));
    }

    let mut available = 0_u32;
    let mut unavailable = 0_u32;
    for (index, entry) in availability_counts.iter().enumerate() {
        entry.validate()?;
        if availability_counts[..index]
            .iter()
            .any(|prior| prior.availability == entry.availability && prior.reason == entry.reason)
        {
            return Err(ValidationError::new(SafeFieldV1::PhotoKitAvailability));
        }
        match entry.availability {
            PhotoKitAvailabilityV1::Available => available += u32::from(entry.count),
            PhotoKitAvailabilityV1::Unavailable => unavailable += u32::from(entry.count),
        }
    }

    if available != u32::from(counts.available) || unavailable != u32::from(counts.unavailable) {
        return Err(ValidationError::new(SafeFieldV1::PhotoKitAvailability));
    }
    Ok(())
}
