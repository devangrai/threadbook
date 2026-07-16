use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{deserialize_schema_version_v1, Sha256Digest, MAX_SAFE_INTEGER_V1};

pub const UPDATE_APPLICATION_ID_V1: &str = "com.devrai.wardrobe";
pub const UPDATE_MANIFEST_SCHEMA_VERSION_V1: u8 = 1;
pub const MAX_UPDATE_ARTIFACT_BYTES_V1: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_UPDATE_IDENTIFIER_CHARS_V1: usize = 128;
pub const MAX_UPDATE_VERSION_CHARS_V1: usize = 64;
pub const MAX_ACCEPTED_DATABASE_LINEAGES_V1: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum UpdateChannelV1 {
    Personal,
    Development,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum UpdateOperatingSystemV1 {
    Macos,
    Linux,
    Windows,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum UpdateArchitectureV1 {
    Aarch64,
    X86_64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum UpdateArtifactKindV1 {
    MacosApplicationArchive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct AcceptedDatabaseLineageV1 {
    #[ts(type = "number")]
    pub schema_version: u32,
    pub migration_prefix_sha256: Sha256Digest,
}

impl AcceptedDatabaseLineageV1 {
    pub fn validate(&self) -> Result<(), UpdateCompatibilityFailureV1> {
        if self.schema_version == 0 {
            Err(UpdateCompatibilityFailureV1::InvalidDatabaseLineage)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct UpdateSigningKeyRangeV1 {
    pub key_id: String,
    #[ts(type = "number")]
    pub minimum_release_sequence: u64,
    #[ts(type = "number")]
    pub maximum_release_sequence: u64,
}

impl UpdateSigningKeyRangeV1 {
    pub fn validate(&self) -> Result<(), UpdateCompatibilityFailureV1> {
        validate_identifier(&self.key_id)
            .map_err(|_| UpdateCompatibilityFailureV1::InvalidKeyId)?;
        if self.minimum_release_sequence == 0
            || self.minimum_release_sequence > self.maximum_release_sequence
            || self.maximum_release_sequence > MAX_SAFE_INTEGER_V1
        {
            return Err(UpdateCompatibilityFailureV1::InvalidSigningKeyRange);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct UpdateManifestV1 {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub application_id: String,
    pub channel: UpdateChannelV1,
    pub key_id: String,
    pub release_id: String,
    #[ts(type = "number")]
    pub release_sequence: u64,
    pub target_version: String,
    pub target_os: UpdateOperatingSystemV1,
    pub target_architecture: UpdateArchitectureV1,
    pub minimum_macos_version: String,
    pub artifact_kind: UpdateArtifactKindV1,
    #[ts(type = "number")]
    pub artifact_length: u64,
    pub artifact_sha256: Sha256Digest,
    pub accepted_source_version_min: String,
    pub accepted_source_version_max: String,
    pub accepted_databases: Vec<AcceptedDatabaseLineageV1>,
    #[ts(type = "number")]
    pub target_database_schema_version: u32,
    pub target_migration_prefix_sha256: Sha256Digest,
    pub required_backup_format_version: u8,
    pub required_asset_manifest_version: u8,
}

impl UpdateManifestV1 {
    pub fn validate(&self) -> Result<(), UpdateCompatibilityFailureV1> {
        if self.schema_version != UPDATE_MANIFEST_SCHEMA_VERSION_V1 {
            return Err(UpdateCompatibilityFailureV1::InvalidSchemaVersion);
        }
        validate_application_id(&self.application_id)?;
        validate_identifier(&self.key_id)
            .map_err(|_| UpdateCompatibilityFailureV1::InvalidKeyId)?;
        validate_identifier(&self.release_id)
            .map_err(|_| UpdateCompatibilityFailureV1::InvalidReleaseId)?;
        if self.release_sequence == 0 || self.release_sequence > MAX_SAFE_INTEGER_V1 {
            return Err(UpdateCompatibilityFailureV1::InvalidReleaseSequence);
        }

        let target_version = NumericVersionV1::parse(&self.target_version)?;
        let source_min = NumericVersionV1::parse(&self.accepted_source_version_min)?;
        let source_max = NumericVersionV1::parse(&self.accepted_source_version_max)?;
        NumericVersionV1::parse(&self.minimum_macos_version)?;
        if source_min > source_max || target_version < source_min {
            return Err(UpdateCompatibilityFailureV1::InvalidSourceVersionRange);
        }

        if self.artifact_length == 0
            || self.artifact_length > MAX_UPDATE_ARTIFACT_BYTES_V1
            || self.artifact_length > MAX_SAFE_INTEGER_V1
        {
            return Err(UpdateCompatibilityFailureV1::InvalidArtifactLength);
        }
        validate_lineages(&self.accepted_databases)?;
        if self.target_database_schema_version == 0 {
            return Err(UpdateCompatibilityFailureV1::InvalidTargetDatabase);
        }
        if self.required_backup_format_version == 0 || self.required_asset_manifest_version == 0 {
            return Err(UpdateCompatibilityFailureV1::InvalidFormatVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct UpdateCompatibilityContext {
    pub application_id: String,
    pub channel: UpdateChannelV1,
    pub application_version: String,
    #[ts(type = "number")]
    pub installed_release_sequence: u64,
    pub operating_system: UpdateOperatingSystemV1,
    pub architecture: UpdateArchitectureV1,
    pub macos_version: String,
    pub database: AcceptedDatabaseLineageV1,
    pub supported_backup_format_version: u8,
    pub supported_asset_manifest_version: u8,
    pub signing_key: UpdateSigningKeyRangeV1,
}

impl UpdateCompatibilityContext {
    pub fn validate(&self) -> Result<(), UpdateCompatibilityFailureV1> {
        validate_application_id(&self.application_id)?;
        if self.application_id != UPDATE_APPLICATION_ID_V1 {
            return Err(UpdateCompatibilityFailureV1::InvalidApplicationId);
        }
        if self.channel != UpdateChannelV1::Personal {
            return Err(UpdateCompatibilityFailureV1::InvalidChannel);
        }
        NumericVersionV1::parse(&self.application_version)?;
        NumericVersionV1::parse(&self.macos_version)?;
        if self.installed_release_sequence == 0
            || self.installed_release_sequence > MAX_SAFE_INTEGER_V1
        {
            return Err(UpdateCompatibilityFailureV1::InvalidReleaseSequence);
        }
        if self.operating_system != UpdateOperatingSystemV1::Macos {
            return Err(UpdateCompatibilityFailureV1::InvalidPlatform);
        }
        self.database.validate()?;
        if self.supported_backup_format_version == 0 || self.supported_asset_manifest_version == 0 {
            return Err(UpdateCompatibilityFailureV1::InvalidFormatVersion);
        }
        self.signing_key.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum UpdateCompatibilityFailureV1 {
    InvalidSchemaVersion,
    InvalidApplicationId,
    InvalidChannel,
    InvalidKeyId,
    InvalidReleaseId,
    InvalidReleaseSequence,
    InvalidVersion,
    InvalidSourceVersionRange,
    InvalidArtifactKind,
    InvalidArtifactLength,
    InvalidDatabaseLineage,
    InvalidTargetDatabase,
    InvalidFormatVersion,
    InvalidSigningKeyRange,
    InvalidPlatform,
    ApplicationMismatch,
    ChannelMismatch,
    PlatformMismatch,
    ArchitectureMismatch,
    MacosVersionUnsupported,
    SourceVersionUnsupported,
    TargetVersionNotNewer,
    ReleaseSequenceDowngrade,
    SigningKeyMismatch,
    SigningKeyOutOfRange,
    DatabaseLineageUnsupported,
    TargetDatabaseDowngrade,
    BackupFormatUnsupported,
    AssetManifestFormatUnsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
#[ts(tag = "status", rename_all = "snake_case")]
pub enum UpdateCompatibilityDecisionV1 {
    Compatible {},
    Rejected {
        reason: UpdateCompatibilityFailureV1,
    },
}

pub fn evaluate_update_compatibility(
    manifest: &UpdateManifestV1,
    context: &UpdateCompatibilityContext,
) -> UpdateCompatibilityDecisionV1 {
    if let Err(reason) = manifest.validate() {
        return rejected(reason);
    }
    if let Err(reason) = context.validate() {
        return rejected(reason);
    }
    if manifest.application_id != context.application_id {
        return rejected(UpdateCompatibilityFailureV1::ApplicationMismatch);
    }
    if manifest.channel != context.channel {
        return rejected(UpdateCompatibilityFailureV1::ChannelMismatch);
    }
    if manifest.target_os != context.operating_system {
        return rejected(UpdateCompatibilityFailureV1::PlatformMismatch);
    }
    if manifest.target_architecture != context.architecture {
        return rejected(UpdateCompatibilityFailureV1::ArchitectureMismatch);
    }

    let minimum_macos_version =
        NumericVersionV1::parse(&manifest.minimum_macos_version).expect("validated manifest");
    let macos_version = NumericVersionV1::parse(&context.macos_version).expect("validated context");
    if macos_version < minimum_macos_version {
        return rejected(UpdateCompatibilityFailureV1::MacosVersionUnsupported);
    }

    let source_version =
        NumericVersionV1::parse(&context.application_version).expect("validated context");
    let source_min =
        NumericVersionV1::parse(&manifest.accepted_source_version_min).expect("validated manifest");
    let source_max =
        NumericVersionV1::parse(&manifest.accepted_source_version_max).expect("validated manifest");
    if source_version < source_min || source_version > source_max {
        return rejected(UpdateCompatibilityFailureV1::SourceVersionUnsupported);
    }
    let target_version =
        NumericVersionV1::parse(&manifest.target_version).expect("validated manifest");
    if target_version <= source_version {
        return rejected(UpdateCompatibilityFailureV1::TargetVersionNotNewer);
    }
    if manifest.release_sequence <= context.installed_release_sequence {
        return rejected(UpdateCompatibilityFailureV1::ReleaseSequenceDowngrade);
    }
    if manifest.key_id != context.signing_key.key_id {
        return rejected(UpdateCompatibilityFailureV1::SigningKeyMismatch);
    }
    if manifest.release_sequence < context.signing_key.minimum_release_sequence
        || manifest.release_sequence > context.signing_key.maximum_release_sequence
    {
        return rejected(UpdateCompatibilityFailureV1::SigningKeyOutOfRange);
    }
    if !manifest
        .accepted_databases
        .iter()
        .any(|lineage| lineage == &context.database)
    {
        return rejected(UpdateCompatibilityFailureV1::DatabaseLineageUnsupported);
    }
    if manifest.target_database_schema_version < context.database.schema_version {
        return rejected(UpdateCompatibilityFailureV1::TargetDatabaseDowngrade);
    }
    if manifest.required_backup_format_version != context.supported_backup_format_version {
        return rejected(UpdateCompatibilityFailureV1::BackupFormatUnsupported);
    }
    if manifest.required_asset_manifest_version != context.supported_asset_manifest_version {
        return rejected(UpdateCompatibilityFailureV1::AssetManifestFormatUnsupported);
    }
    UpdateCompatibilityDecisionV1::Compatible {}
}

fn rejected(reason: UpdateCompatibilityFailureV1) -> UpdateCompatibilityDecisionV1 {
    UpdateCompatibilityDecisionV1::Rejected { reason }
}

fn validate_application_id(value: &str) -> Result<(), UpdateCompatibilityFailureV1> {
    if value.len() > MAX_UPDATE_IDENTIFIER_CHARS_V1
        || value.split('.').count() < 3
        || value.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || !part.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        })
    {
        Err(UpdateCompatibilityFailureV1::InvalidApplicationId)
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > MAX_UPDATE_IDENTIFIER_CHARS_V1
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_lineages(
    lineages: &[AcceptedDatabaseLineageV1],
) -> Result<(), UpdateCompatibilityFailureV1> {
    if lineages.is_empty() || lineages.len() > MAX_ACCEPTED_DATABASE_LINEAGES_V1 {
        return Err(UpdateCompatibilityFailureV1::InvalidDatabaseLineage);
    }
    lineages
        .iter()
        .try_for_each(AcceptedDatabaseLineageV1::validate)?;
    if lineages
        .windows(2)
        .any(|pair| pair[0].schema_version >= pair[1].schema_version)
    {
        return Err(UpdateCompatibilityFailureV1::InvalidDatabaseLineage);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NumericVersionV1 {
    major: u32,
    minor: u32,
    patch: u32,
}

impl NumericVersionV1 {
    fn parse(value: &str) -> Result<Self, UpdateCompatibilityFailureV1> {
        if value.is_empty()
            || value.len() > MAX_UPDATE_VERSION_CHARS_V1
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_digit() || byte == b'.'))
        {
            return Err(UpdateCompatibilityFailureV1::InvalidVersion);
        }
        let mut components = value.split('.');
        let major = parse_version_component(components.next())?;
        let minor = parse_version_component(components.next())?;
        let patch = parse_version_component(components.next())?;
        if components.next().is_some() {
            return Err(UpdateCompatibilityFailureV1::InvalidVersion);
        }
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

fn parse_version_component(component: Option<&str>) -> Result<u32, UpdateCompatibilityFailureV1> {
    let component = component.ok_or(UpdateCompatibilityFailureV1::InvalidVersion)?;
    if component.is_empty() || (component.len() > 1 && component.starts_with('0')) {
        return Err(UpdateCompatibilityFailureV1::InvalidVersion);
    }
    component
        .parse()
        .map_err(|_| UpdateCompatibilityFailureV1::InvalidVersion)
}
