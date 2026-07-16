use crate::blob::sync_directory;
use crate::{
    MaintenanceCoordinator, PlatformError, PrivateAppPaths, StoreLock, BACKUP_FORMAT_VERSION,
};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;
use wardrobe_core::{
    evaluate_update_compatibility, AcceptedDatabaseLineageV1, Sha256Digest, UpdateArchitectureV1,
    UpdateChannelV1, UpdateCompatibilityContext, UpdateCompatibilityDecisionV1,
    UpdateCompatibilityFailureV1, UpdateManifestV1, UpdateOperatingSystemV1,
    UpdateSigningKeyRangeV1, MAX_UPDATE_ARTIFACT_BYTES_V1,
};

const PACKAGE_MAGIC: &[u8; 4] = b"WDU1";
const HEADER_LENGTH: u64 = 4 + 4 + 2 + 8;
const SIGNATURE_LENGTH: usize = 64;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const RECORD_SCHEMA_VERSION: u8 = 1;
const DOMAIN_SEPARATOR: &[u8] = b"WardrobeUpdateManifestV1\0";
const PACKAGE_NAME: &str = "package.wdupdate";
const RECORD_NAME: &str = "record.json";
const RECORD_HASH_NAME: &str = "record.sha256";

include!(concat!(env!("OUT_DIR"), "/wardrobe_build_metadata_v1.rs"));

static STAGING_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateTrustKey {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub minimum_release_sequence: u64,
    pub maximum_release_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedUpdate {
    pub release_id: String,
    pub release_sequence: u64,
    pub target_version: String,
    pub manifest_sha256: String,
    pub package_sha256: String,
    pub artifact_sha256: String,
    pub stage_path: PathBuf,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedUpdateRuntimeContext {
    application_id: String,
    channel: UpdateChannelV1,
    application_version: String,
    installed_release_sequence: u64,
    operating_system: UpdateOperatingSystemV1,
    architecture: UpdateArchitectureV1,
    macos_version: String,
    database: AcceptedDatabaseLineageV1,
    supported_backup_format_version: u8,
    supported_asset_manifest_version: u8,
}

impl TrustedUpdateRuntimeContext {
    fn from_database(database: &crate::Database) -> UpdatePackageResult<Self> {
        let database = database.compatibility_snapshot()?;
        Ok(Self {
            application_id: INSTALLED_UPDATE_APPLICATION_ID_V1.to_owned(),
            channel: UpdateChannelV1::Personal,
            application_version: INSTALLED_UPDATE_APPLICATION_VERSION_V1.to_owned(),
            installed_release_sequence: INSTALLED_UPDATE_RELEASE_SEQUENCE_V1,
            operating_system: UpdateOperatingSystemV1::Macos,
            architecture: current_architecture()?,
            macos_version: current_macos_version()?,
            database: AcceptedDatabaseLineageV1 {
                schema_version: database.schema_version,
                migration_prefix_sha256: Sha256Digest::parse(database.migration_prefix_sha256)
                    .map_err(|_| UpdatePackageError::Invalid("database_migration_prefix"))?,
            },
            supported_backup_format_version: BACKUP_FORMAT_VERSION,
            supported_asset_manifest_version: 1,
        })
    }

    fn compatibility_for(&self, key: &UpdateTrustKey) -> UpdateCompatibilityContext {
        UpdateCompatibilityContext {
            application_id: self.application_id.clone(),
            channel: self.channel,
            application_version: self.application_version.clone(),
            installed_release_sequence: self.installed_release_sequence,
            operating_system: self.operating_system,
            architecture: self.architecture,
            macos_version: self.macos_version.clone(),
            database: self.database.clone(),
            supported_backup_format_version: self.supported_backup_format_version,
            supported_asset_manifest_version: self.supported_asset_manifest_version,
            signing_key: UpdateSigningKeyRangeV1 {
                key_id: key.key_id.clone(),
                minimum_release_sequence: key.minimum_release_sequence,
                maximum_release_sequence: key.maximum_release_sequence,
            },
        }
    }

    pub fn application_version(&self) -> &str {
        &self.application_version
    }

    pub fn architecture(&self) -> UpdateArchitectureV1 {
        self.architecture
    }

    pub fn database(&self) -> &AcceptedDatabaseLineageV1 {
        &self.database
    }
}

#[derive(Debug)]
pub enum UpdatePackageError {
    Conflict(&'static str),
    Incompatible(UpdateCompatibilityFailureV1),
    Invalid(&'static str),
    Platform(PlatformError),
    PublicationOutcomeUnknown,
    SignatureInvalid,
}

impl fmt::Display for UpdatePackageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(code) => write!(formatter, "update conflict: {code}"),
            Self::Incompatible(reason) => write!(formatter, "update incompatible: {reason:?}"),
            Self::Invalid(code) => write!(formatter, "invalid update package: {code}"),
            Self::Platform(error) => write!(formatter, "{error}"),
            Self::PublicationOutcomeUnknown => {
                formatter.write_str("update stage publication outcome unknown")
            }
            Self::SignatureInvalid => formatter.write_str("update signature invalid"),
        }
    }
}

impl Error for UpdatePackageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PlatformError> for UpdatePackageError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<std::io::Error> for UpdatePackageError {
    fn from(error: std::io::Error) -> Self {
        Self::Platform(PlatformError::Io(error))
    }
}

impl From<serde_json::Error> for UpdatePackageError {
    fn from(error: serde_json::Error) -> Self {
        Self::Platform(PlatformError::Json(error))
    }
}

pub type UpdatePackageResult<T> = Result<T, UpdatePackageError>;

#[derive(Clone, Debug)]
pub struct UpdatePackageStager {
    paths: PrivateAppPaths,
    database: crate::Database,
    _store_lock: Arc<StoreLock>,
    trust_keys: Vec<UpdateTrustKey>,
}

#[derive(Debug)]
struct VerifiedPackage {
    file: File,
    identity: FileIdentity,
    manifest: UpdateManifestV1,
    manifest_sha256: String,
    package_sha256: String,
    key_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UpdateStageRecordV1 {
    schema_version: u8,
    operation_id: String,
    envelope_sha256: String,
    release_id: String,
    release_sequence: u64,
    target_version: String,
    manifest_sha256: String,
    package_sha256: String,
    artifact_sha256: String,
    artifact_length: u64,
    key_id: String,
    source_application_version: String,
    source_database_schema_version: u32,
    source_migration_prefix_sha256: String,
    verified_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StageFault {
    None,
    BeforeCopy,
    DuringPackageWrite,
    BeforePackageSync,
    BeforeRecordWrite,
    BeforeStageDirectorySync,
    RenameOutcomeUnknown,
    AfterRename,
    BeforeParentDirectorySync,
}

impl UpdatePackageStager {
    pub fn new(
        database: crate::Database,
        store_lock: Arc<StoreLock>,
        trust_keys: Vec<UpdateTrustKey>,
    ) -> UpdatePackageResult<Self> {
        if !store_lock.protects(&database.paths) {
            return Err(UpdatePackageError::Invalid("store_lock_mismatch"));
        }
        if trust_keys.len() > 16 {
            return Err(UpdatePackageError::Invalid("trust_key_count"));
        }
        for (index, key) in trust_keys.iter().enumerate() {
            validate_trust_key(key)?;
            if trust_keys[..index].iter().any(|existing| {
                existing.key_id == key.key_id
                    && ranges_overlap(
                        existing.minimum_release_sequence,
                        existing.maximum_release_sequence,
                        key.minimum_release_sequence,
                        key.maximum_release_sequence,
                    )
            }) {
                return Err(UpdatePackageError::Invalid("trust_key_overlap"));
            }
        }
        Ok(Self {
            paths: database.paths.clone(),
            database,
            _store_lock: store_lock,
            trust_keys,
        })
    }

    pub fn production_disabled(
        database: crate::Database,
        store_lock: Arc<StoreLock>,
    ) -> UpdatePackageResult<Self> {
        Self::new(database, store_lock, Vec::new())
    }

    pub fn has_trusted_release_key(&self) -> bool {
        !self.trust_keys.is_empty()
    }

    pub fn current_compatibility(&self) -> UpdatePackageResult<TrustedUpdateRuntimeContext> {
        TrustedUpdateRuntimeContext::from_database(&self.database)
    }

    pub fn verify_only(&self, package_path: &Path) -> UpdatePackageResult<StagedUpdate> {
        let _maintenance = MaintenanceCoordinator::global().acquire_shared()?;
        let context = self.current_compatibility()?;
        let verified = self.verify_path(package_path, &context)?;
        Ok(staged_summary(&verified, PathBuf::new(), false))
    }

    pub fn stage(
        &self,
        operation_id: &str,
        package_path: &Path,
        now_ms: i64,
    ) -> UpdatePackageResult<StagedUpdate> {
        self.stage_internal(operation_id, package_path, now_ms, StageFault::None, || {})
    }

    fn stage_internal(
        &self,
        operation_id: &str,
        package_path: &Path,
        now_ms: i64,
        fault: StageFault,
        after_verification: impl FnOnce(),
    ) -> UpdatePackageResult<StagedUpdate> {
        validate_operation_id(operation_id)?;
        if now_ms < 0 {
            return Err(UpdatePackageError::Invalid("verified_at_ms"));
        }
        let _maintenance = MaintenanceCoordinator::global().acquire_shared()?;
        let _guard = STAGING_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| UpdatePackageError::Conflict("update_staging_mutex_poisoned"))?;
        let _process_lock = UpdateStageLock::acquire(&self.paths)?;
        let context = self.current_compatibility()?;
        let mut verified = self.verify_path(package_path, &context)?;
        after_verification();
        let envelope_sha256 = envelope_sha256(operation_id, &verified, &context);

        for stage in self.verified_stage_directories()? {
            let existing = self.verify_stage(&stage, &context)?;
            if existing.record.operation_id == operation_id {
                if existing.record.envelope_sha256 != envelope_sha256
                    || existing.record.package_sha256 != verified.package_sha256
                {
                    return Err(UpdatePackageError::Conflict(
                        "update_operation_envelope_changed",
                    ));
                }
                return Ok(existing.summary(true));
            }
            if existing.record.release_sequence == verified.manifest.release_sequence
                && existing.record.manifest_sha256 != verified.manifest_sha256
            {
                return Err(UpdatePackageError::Conflict(
                    "update_release_sequence_equivocation",
                ));
            }
        }

        let temporary_id = Uuid::new_v4().to_string();
        let temporary = self.paths.update_staging.join(&temporary_id);
        create_private_directory_new(&temporary)?;
        let result = self.publish_stage(
            &temporary,
            operation_id,
            &envelope_sha256,
            &mut verified,
            &context,
            now_ms,
            fault,
        );
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, UpdatePackageError::PublicationOutcomeUnknown))
        {
            let _ = remove_private_stage(&temporary);
            let _ = sync_directory(&self.paths.update_staging);
        }
        result
    }

    pub fn recover(&self) -> UpdatePackageResult<Vec<StagedUpdate>> {
        let _maintenance = MaintenanceCoordinator::global().acquire_shared()?;
        let _guard = STAGING_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| UpdatePackageError::Conflict("update_staging_mutex_poisoned"))?;
        let _process_lock = UpdateStageLock::acquire(&self.paths)?;
        let context = self.current_compatibility()?;
        self.cleanup_temporary_stages()?;
        let mut recovered = Vec::new();
        let mut sequences = Vec::<(u64, String)>::new();
        let mut operations = Vec::<(String, String)>::new();
        for stage in self.verified_stage_directories()? {
            let verified = self.verify_stage(&stage, &context)?;
            if sequences.iter().any(|(sequence, hash)| {
                *sequence == verified.record.release_sequence
                    && hash != &verified.record.manifest_sha256
            }) {
                return Err(UpdatePackageError::Conflict(
                    "update_release_sequence_equivocation",
                ));
            }
            if operations.iter().any(|(operation, envelope)| {
                operation == &verified.record.operation_id
                    && envelope != &verified.record.envelope_sha256
            }) {
                return Err(UpdatePackageError::Conflict(
                    "update_operation_envelope_changed",
                ));
            }
            sequences.push((
                verified.record.release_sequence,
                verified.record.manifest_sha256.clone(),
            ));
            operations.push((
                verified.record.operation_id.clone(),
                verified.record.envelope_sha256.clone(),
            ));
            recovered.push(verified.summary(true));
        }
        recovered.sort_by_key(|stage| stage.release_sequence);
        Ok(recovered)
    }

    fn verify_path(
        &self,
        package_path: &Path,
        context: &TrustedUpdateRuntimeContext,
    ) -> UpdatePackageResult<VerifiedPackage> {
        if !package_path.is_absolute() {
            return Err(UpdatePackageError::Invalid("package_path"));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(package_path)?;
        self.verify_file(file, context)
    }

    fn verify_staged_path(
        &self,
        package_path: &Path,
        context: &TrustedUpdateRuntimeContext,
    ) -> UpdatePackageResult<VerifiedPackage> {
        if !package_path.is_absolute() {
            return Err(UpdatePackageError::Invalid("package_path"));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(package_path)?;
        require_private_file_descriptor(&file)?;
        let verified = self.verify_file(file, context)?;
        require_private_file_descriptor(&verified.file)?;
        Ok(verified)
    }

    fn verify_file(
        &self,
        mut file: File,
        context: &TrustedUpdateRuntimeContext,
    ) -> UpdatePackageResult<VerifiedPackage> {
        let identity = private_regular_file_identity(&file)?;
        if identity.length < HEADER_LENGTH + SIGNATURE_LENGTH as u64 {
            return Err(UpdatePackageError::Invalid("package_length"));
        }

        let mut package_hasher = Sha256::new();
        let mut header = [0_u8; HEADER_LENGTH as usize];
        read_exact_hashed(&mut file, &mut header, &mut package_hasher)?;
        if &header[..4] != PACKAGE_MAGIC {
            return Err(UpdatePackageError::Invalid("package_magic"));
        }
        let manifest_length =
            u32::from_be_bytes(header[4..8].try_into().expect("fixed header")) as usize;
        let signature_length =
            u16::from_be_bytes(header[8..10].try_into().expect("fixed header")) as usize;
        let artifact_length = u64::from_be_bytes(header[10..18].try_into().expect("fixed header"));
        if manifest_length == 0 || manifest_length > MAX_MANIFEST_BYTES {
            return Err(UpdatePackageError::Invalid("manifest_length"));
        }
        if signature_length != SIGNATURE_LENGTH {
            return Err(UpdatePackageError::Invalid("signature_length"));
        }
        if artifact_length == 0 || artifact_length > MAX_UPDATE_ARTIFACT_BYTES_V1 {
            return Err(UpdatePackageError::Invalid("artifact_length"));
        }
        let expected_length = HEADER_LENGTH
            .checked_add(manifest_length as u64)
            .and_then(|value| value.checked_add(signature_length as u64))
            .and_then(|value| value.checked_add(artifact_length))
            .ok_or(UpdatePackageError::Invalid("package_length"))?;
        if identity.length != expected_length {
            return Err(UpdatePackageError::Invalid("package_length"));
        }

        let mut manifest_bytes = vec![0_u8; manifest_length];
        read_exact_hashed(&mut file, &mut manifest_bytes, &mut package_hasher)?;
        let manifest: UpdateManifestV1 = serde_json::from_slice(&manifest_bytes)
            .map_err(|_| UpdatePackageError::Invalid("manifest_json"))?;
        let canonical = canonical_manifest_bytes(&manifest)?;
        if canonical != manifest_bytes {
            return Err(UpdatePackageError::Invalid("manifest_canonical"));
        }
        if manifest.artifact_length != artifact_length {
            return Err(UpdatePackageError::Invalid("artifact_length"));
        }

        let mut signature = [0_u8; SIGNATURE_LENGTH];
        read_exact_hashed(&mut file, &mut signature, &mut package_hasher)?;
        let trust_key = self
            .trust_keys
            .iter()
            .find(|key| {
                key.key_id == manifest.key_id
                    && (key.minimum_release_sequence..=key.maximum_release_sequence)
                        .contains(&manifest.release_sequence)
            })
            .ok_or(UpdatePackageError::SignatureInvalid)?;
        let mut signed = Vec::with_capacity(DOMAIN_SEPARATOR.len() + manifest_bytes.len());
        signed.extend_from_slice(DOMAIN_SEPARATOR);
        signed.extend_from_slice(&manifest_bytes);
        UnparsedPublicKey::new(&ED25519, trust_key.public_key)
            .verify(&signed, &signature)
            .map_err(|_| UpdatePackageError::SignatureInvalid)?;

        let compatibility = context.compatibility_for(trust_key);
        match evaluate_update_compatibility(&manifest, &compatibility) {
            UpdateCompatibilityDecisionV1::Compatible {} => {}
            UpdateCompatibilityDecisionV1::Rejected { reason } => {
                return Err(UpdatePackageError::Incompatible(reason));
            }
        }

        let mut artifact_hasher = Sha256::new();
        let mut remaining = artifact_length;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining != 0 {
            let chunk = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| UpdatePackageError::Invalid("artifact_length"))?;
            read_exact_hashed(&mut file, &mut buffer[..chunk], &mut package_hasher)?;
            artifact_hasher.update(&buffer[..chunk]);
            remaining -= chunk as u64;
        }
        let artifact_sha256 = hex_digest(artifact_hasher.finalize());
        if artifact_sha256 != manifest.artifact_sha256.as_str() {
            return Err(UpdatePackageError::Invalid("artifact_sha256"));
        }
        let after = private_regular_file_identity(&file)?;
        if after != identity {
            return Err(UpdatePackageError::Invalid("package_changed"));
        }
        let manifest_sha256 = hex_digest(Sha256::digest(&manifest_bytes));
        let package_sha256 = hex_digest(package_hasher.finalize());
        file.seek(SeekFrom::Start(0))?;
        Ok(VerifiedPackage {
            file,
            identity,
            manifest,
            manifest_sha256,
            package_sha256,
            key_id: trust_key.key_id.clone(),
        })
    }

    fn publish_stage(
        &self,
        temporary: &Path,
        operation_id: &str,
        envelope_sha256: &str,
        verified: &mut VerifiedPackage,
        context: &TrustedUpdateRuntimeContext,
        now_ms: i64,
        fault: StageFault,
    ) -> UpdatePackageResult<StagedUpdate> {
        if fault == StageFault::BeforeCopy {
            return Err(std::io::Error::other("injected pre-publication failure").into());
        }
        let package_path = temporary.join(PACKAGE_NAME);
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&package_path)?;
        require_private_file_descriptor(&destination)?;
        verified.file.seek(SeekFrom::Start(0))?;
        let copied_hash = if fault == StageFault::DuringPackageWrite {
            copy_hashed_with_limit(&mut verified.file, &mut destination, Some(1))?;
            return Err(injected_failure("package_write").into());
        } else {
            copy_hashed_with_limit(&mut verified.file, &mut destination, None)?
        };
        if fault == StageFault::BeforePackageSync {
            return Err(injected_failure("package_fsync").into());
        }
        destination.sync_all()?;
        require_private_file_descriptor(&destination)?;
        drop(destination);
        if copied_hash != verified.package_sha256 {
            return Err(UpdatePackageError::Invalid("package_changed"));
        }
        let after_copy = private_regular_file_identity(&verified.file)?;
        if after_copy != verified.identity {
            return Err(UpdatePackageError::Invalid("package_changed"));
        }

        let record = UpdateStageRecordV1 {
            schema_version: RECORD_SCHEMA_VERSION,
            operation_id: operation_id.to_owned(),
            envelope_sha256: envelope_sha256.to_owned(),
            release_id: verified.manifest.release_id.clone(),
            release_sequence: verified.manifest.release_sequence,
            target_version: verified.manifest.target_version.clone(),
            manifest_sha256: verified.manifest_sha256.clone(),
            package_sha256: verified.package_sha256.clone(),
            artifact_sha256: verified.manifest.artifact_sha256.as_str().to_owned(),
            artifact_length: verified.manifest.artifact_length,
            key_id: verified.key_id.clone(),
            source_application_version: context.application_version.clone(),
            source_database_schema_version: context.database.schema_version,
            source_migration_prefix_sha256: context
                .database
                .migration_prefix_sha256
                .as_str()
                .to_owned(),
            verified_at_ms: now_ms,
        };
        let record_bytes = canonical_record_bytes(&record)?;
        if fault == StageFault::BeforeRecordWrite {
            return Err(injected_failure("record_write").into());
        }
        write_private_file(&temporary.join(RECORD_NAME), &record_bytes)?;
        write_private_file(
            &temporary.join(RECORD_HASH_NAME),
            format!("{}\n", hex_digest(Sha256::digest(&record_bytes))).as_bytes(),
        )?;
        if fault == StageFault::BeforeStageDirectorySync {
            return Err(injected_failure("stage_directory_fsync").into());
        }
        sync_directory(temporary)?;
        let current_context = self.current_compatibility()?;
        if &current_context != context {
            return Err(UpdatePackageError::Invalid("runtime_compatibility_changed"));
        }
        let reverified = self.verify_staged_path(&package_path, &current_context)?;
        if reverified.package_sha256 != verified.package_sha256
            || reverified.manifest_sha256 != verified.manifest_sha256
        {
            return Err(UpdatePackageError::Invalid("package_changed"));
        }

        let final_path = self.paths.update_verified.join(stage_name(
            record.release_sequence,
            &record.manifest_sha256,
        )?);
        if final_path.exists() {
            return Err(UpdatePackageError::Conflict("update_stage_exists"));
        }
        if fault == StageFault::RenameOutcomeUnknown {
            return Err(UpdatePackageError::PublicationOutcomeUnknown);
        }
        if fs::rename(temporary, &final_path).is_err() {
            return Err(UpdatePackageError::PublicationOutcomeUnknown);
        }
        if fault == StageFault::AfterRename {
            return Err(UpdatePackageError::PublicationOutcomeUnknown);
        }
        if fault == StageFault::BeforeParentDirectorySync {
            return Err(UpdatePackageError::PublicationOutcomeUnknown);
        }
        let staging_sync = sync_directory(&self.paths.update_staging);
        let verified_sync = sync_directory(&self.paths.update_verified);
        if staging_sync.is_err() || verified_sync.is_err() {
            return Err(UpdatePackageError::PublicationOutcomeUnknown);
        }
        match self.verify_stage(&final_path, context) {
            Ok(stage) => Ok(stage.summary(false)),
            Err(_) => Err(UpdatePackageError::PublicationOutcomeUnknown),
        }
    }

    fn verify_stage(
        &self,
        stage: &Path,
        context: &TrustedUpdateRuntimeContext,
    ) -> UpdatePackageResult<VerifiedStage> {
        require_private_directory(stage)?;
        let mut names = fs::read_dir(stage)?
            .map(|entry| {
                entry
                    .map(|value| value.file_name().to_string_lossy().into_owned())
                    .map_err(UpdatePackageError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        if names != [PACKAGE_NAME, RECORD_NAME, RECORD_HASH_NAME] {
            return Err(UpdatePackageError::Invalid("stage_entries"));
        }
        for name in [PACKAGE_NAME, RECORD_NAME, RECORD_HASH_NAME] {
            require_private_file_path(&stage.join(name))?;
        }
        let record_bytes = read_private_bounded(&stage.join(RECORD_NAME), MAX_MANIFEST_BYTES)?;
        let record_hash = read_private_bounded(&stage.join(RECORD_HASH_NAME), 65)?;
        let expected_hash = format!("{}\n", hex_digest(Sha256::digest(&record_bytes)));
        if record_hash != expected_hash.as_bytes() {
            return Err(UpdatePackageError::Invalid("stage_record_sha256"));
        }
        let record: UpdateStageRecordV1 = serde_json::from_slice(&record_bytes)
            .map_err(|_| UpdatePackageError::Invalid("stage_record_json"))?;
        if canonical_record_bytes(&record)? != record_bytes {
            return Err(UpdatePackageError::Invalid("stage_record_canonical"));
        }
        validate_stage_record(&record)?;
        let package_path = stage.join(PACKAGE_NAME);
        let verified = self.verify_staged_path(&package_path, context)?;
        if record.release_id != verified.manifest.release_id
            || record.release_sequence != verified.manifest.release_sequence
            || record.target_version != verified.manifest.target_version
            || record.manifest_sha256 != verified.manifest_sha256
            || record.package_sha256 != verified.package_sha256
            || record.artifact_sha256 != verified.manifest.artifact_sha256.as_str()
            || record.artifact_length != verified.manifest.artifact_length
            || record.key_id != verified.key_id
            || record.source_application_version != context.application_version
            || record.source_database_schema_version != context.database.schema_version
            || record.source_migration_prefix_sha256
                != context.database.migration_prefix_sha256.as_str()
            || record.envelope_sha256 != envelope_sha256(&record.operation_id, &verified, context)
        {
            return Err(UpdatePackageError::Invalid("stage_record_binding"));
        }
        let expected_name = stage_name(record.release_sequence, &record.manifest_sha256)?;
        if stage.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            return Err(UpdatePackageError::Invalid("stage_name"));
        }
        Ok(VerifiedStage {
            path: stage.to_path_buf(),
            record,
        })
    }

    fn verified_stage_directories(&self) -> UpdatePackageResult<Vec<PathBuf>> {
        let mut stages = Vec::new();
        for entry in fs::read_dir(&self.paths.update_verified)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(UpdatePackageError::Invalid("stage_name"));
            };
            if !is_stage_name(name) {
                return Err(UpdatePackageError::Invalid("stage_name"));
            }
            stages.push(entry.path());
        }
        stages.sort();
        Ok(stages)
    }

    fn cleanup_temporary_stages(&self) -> UpdatePackageResult<()> {
        for entry in fs::read_dir(&self.paths.update_staging)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(UpdatePackageError::Invalid("temporary_stage_name"));
            };
            if Uuid::parse_str(name).map(|id| id.to_string()) != Ok(name.to_owned()) {
                return Err(UpdatePackageError::Invalid("temporary_stage_name"));
            }
            remove_private_stage(&entry.path())?;
        }
        sync_directory(&self.paths.update_staging)?;
        Ok(())
    }
}

struct VerifiedStage {
    path: PathBuf,
    record: UpdateStageRecordV1,
}

struct UpdateStageLock {
    file: File,
}

impl UpdateStageLock {
    fn acquire(paths: &PrivateAppPaths) -> UpdatePackageResult<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&paths.update_lock)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != current_uid()
            || metadata.gid() != current_gid()
        {
            return Err(UpdatePackageError::Invalid("update_lock_identity"));
        }
        loop {
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if result == 0 {
                return Ok(Self { file });
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }
}

impl Drop for UpdateStageLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl VerifiedStage {
    fn summary(&self, replayed: bool) -> StagedUpdate {
        StagedUpdate {
            release_id: self.record.release_id.clone(),
            release_sequence: self.record.release_sequence,
            target_version: self.record.target_version.clone(),
            manifest_sha256: self.record.manifest_sha256.clone(),
            package_sha256: self.record.package_sha256.clone(),
            artifact_sha256: self.record.artifact_sha256.clone(),
            stage_path: self.path.clone(),
            replayed,
        }
    }
}

pub fn canonical_manifest_bytes(manifest: &UpdateManifestV1) -> UpdatePackageResult<Vec<u8>> {
    manifest
        .validate()
        .map_err(UpdatePackageError::Incompatible)?;
    Ok(serde_json::to_vec(manifest)?)
}

pub fn update_signature_message(manifest_bytes: &[u8]) -> UpdatePackageResult<Vec<u8>> {
    if manifest_bytes.is_empty() || manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(UpdatePackageError::Invalid("manifest_length"));
    }
    let mut message = Vec::with_capacity(DOMAIN_SEPARATOR.len() + manifest_bytes.len());
    message.extend_from_slice(DOMAIN_SEPARATOR);
    message.extend_from_slice(manifest_bytes);
    Ok(message)
}

pub fn encode_update_package(
    manifest: &UpdateManifestV1,
    signature: &[u8],
    artifact: &[u8],
) -> UpdatePackageResult<Vec<u8>> {
    let manifest_bytes = canonical_manifest_bytes(manifest)?;
    if signature.len() != SIGNATURE_LENGTH {
        return Err(UpdatePackageError::Invalid("signature_length"));
    }
    if artifact.len() as u64 != manifest.artifact_length {
        return Err(UpdatePackageError::Invalid("artifact_length"));
    }
    if hex_digest(Sha256::digest(artifact)) != manifest.artifact_sha256.as_str() {
        return Err(UpdatePackageError::Invalid("artifact_sha256"));
    }
    let mut bytes = Vec::with_capacity(
        HEADER_LENGTH as usize + manifest_bytes.len() + signature.len() + artifact.len(),
    );
    bytes.extend_from_slice(PACKAGE_MAGIC);
    bytes.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&(signature.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&(artifact.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&manifest_bytes);
    bytes.extend_from_slice(signature);
    bytes.extend_from_slice(artifact);
    Ok(bytes)
}

fn staged_summary(verified: &VerifiedPackage, stage_path: PathBuf, replayed: bool) -> StagedUpdate {
    StagedUpdate {
        release_id: verified.manifest.release_id.clone(),
        release_sequence: verified.manifest.release_sequence,
        target_version: verified.manifest.target_version.clone(),
        manifest_sha256: verified.manifest_sha256.clone(),
        package_sha256: verified.package_sha256.clone(),
        artifact_sha256: verified.manifest.artifact_sha256.as_str().to_owned(),
        stage_path,
        replayed,
    }
}

fn validate_trust_key(key: &UpdateTrustKey) -> UpdatePackageResult<()> {
    let range = UpdateSigningKeyRangeV1 {
        key_id: key.key_id.clone(),
        minimum_release_sequence: key.minimum_release_sequence,
        maximum_release_sequence: key.maximum_release_sequence,
    };
    range.validate().map_err(UpdatePackageError::Incompatible)
}

fn ranges_overlap(left_min: u64, left_max: u64, right_min: u64, right_max: u64) -> bool {
    left_min <= right_max && right_min <= left_max
}

fn validate_operation_id(value: &str) -> UpdatePackageResult<()> {
    let parsed = Uuid::parse_str(value).map_err(|_| UpdatePackageError::Invalid("operation_id"))?;
    if parsed.to_string() != value {
        return Err(UpdatePackageError::Invalid("operation_id"));
    }
    Ok(())
}

fn validate_stage_record(record: &UpdateStageRecordV1) -> UpdatePackageResult<()> {
    if record.schema_version != RECORD_SCHEMA_VERSION {
        return Err(UpdatePackageError::Invalid("stage_record_schema"));
    }
    validate_operation_id(&record.operation_id)?;
    for digest in [
        &record.envelope_sha256,
        &record.manifest_sha256,
        &record.package_sha256,
        &record.artifact_sha256,
        &record.source_migration_prefix_sha256,
    ] {
        if !is_sha256(digest) {
            return Err(UpdatePackageError::Invalid("stage_record_digest"));
        }
    }
    if record.release_id.is_empty()
        || record.target_version.is_empty()
        || record.key_id.is_empty()
        || record.source_application_version.is_empty()
        || record.verified_at_ms < 0
    {
        return Err(UpdatePackageError::Invalid("stage_record_value"));
    }
    Ok(())
}

fn canonical_record_bytes(record: &UpdateStageRecordV1) -> UpdatePackageResult<Vec<u8>> {
    validate_stage_record(record)?;
    Ok(serde_json::to_vec(record)?)
}

fn envelope_sha256(
    operation_id: &str,
    verified: &VerifiedPackage,
    context: &TrustedUpdateRuntimeContext,
) -> String {
    let mut digest = Sha256::new();
    for value in [
        "WardrobeUpdateStageEnvelopeV1",
        operation_id,
        &verified.package_sha256,
        &verified.manifest_sha256,
        &context.application_id,
        &context.application_version,
        &context.installed_release_sequence.to_string(),
        &context.database.schema_version.to_string(),
        context.database.migration_prefix_sha256.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    hex_digest(digest.finalize())
}

fn stage_name(release_sequence: u64, manifest_sha256: &str) -> UpdatePackageResult<String> {
    if !is_sha256(manifest_sha256) {
        return Err(UpdatePackageError::Invalid("manifest_sha256"));
    }
    Ok(format!("r{release_sequence:016}-{manifest_sha256}"))
}

fn is_stage_name(name: &str) -> bool {
    let Some((sequence, digest)) = name.strip_prefix('r').and_then(|rest| rest.split_once('-'))
    else {
        return false;
    };
    sequence.len() == 16
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && sequence.parse::<u64>().is_ok()
        && is_sha256(digest)
}

fn private_regular_file_identity(file: &File) -> UpdatePackageResult<FileIdentity> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1
    {
        return Err(UpdatePackageError::Invalid("package_identity"));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

fn require_private_directory(path: &Path) -> UpdatePackageResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != current_uid()
        || metadata.gid() != current_gid()
    {
        return Err(UpdatePackageError::Invalid("stage_directory"));
    }
    Ok(())
}

fn require_private_file_path(path: &Path) -> UpdatePackageResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != current_uid()
        || metadata.gid() != current_gid()
    {
        return Err(UpdatePackageError::Invalid("stage_file_identity"));
    }
    Ok(())
}

fn require_private_file_descriptor(file: &File) -> UpdatePackageResult<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != current_uid()
        || metadata.gid() != current_gid()
    {
        return Err(UpdatePackageError::Invalid("stage_file_identity"));
    }
    Ok(())
}

fn create_private_directory_new(path: &Path) -> UpdatePackageResult<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    require_private_directory(path)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> UpdatePackageResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    require_private_file_descriptor(&file)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    require_private_file_descriptor(&file)?;
    Ok(())
}

fn read_private_bounded(path: &Path, limit: usize) -> UpdatePackageResult<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    require_private_file_descriptor(&file)?;
    let identity = private_regular_file_identity(&file)?;
    if identity.length > limit as u64 {
        return Err(UpdatePackageError::Invalid("stage_file_size"));
    }
    let mut bytes = Vec::with_capacity(identity.length as usize);
    file.read_to_end(&mut bytes)?;
    if private_regular_file_identity(&file)? != identity {
        return Err(UpdatePackageError::Invalid("stage_file_changed"));
    }
    require_private_file_descriptor(&file)?;
    Ok(bytes)
}

fn remove_private_stage(path: &Path) -> UpdatePackageResult<()> {
    require_private_directory(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        require_private_file_path(&entry.path())
            .map_err(|_| UpdatePackageError::Invalid("temporary_stage_entry"))?;
        fs::remove_file(entry.path())?;
    }
    fs::remove_dir(path)?;
    Ok(())
}

fn read_exact_hashed(
    reader: &mut File,
    bytes: &mut [u8],
    digest: &mut Sha256,
) -> UpdatePackageResult<()> {
    reader
        .read_exact(bytes)
        .map_err(|_| UpdatePackageError::Invalid("package_truncated"))?;
    digest.update(bytes);
    Ok(())
}

fn copy_hashed_with_limit(
    source: &mut File,
    destination: &mut File,
    byte_limit: Option<u64>,
) -> UpdatePackageResult<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let remaining = byte_limit
            .map(|limit| limit.saturating_sub(copied))
            .unwrap_or(buffer.len() as u64);
        if remaining == 0 {
            break;
        }
        let chunk = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| UpdatePackageError::Invalid("package_length"))?;
        let read = source.read(&mut buffer[..chunk])?;
        if read == 0 {
            break;
        }
        destination.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
        copied += read as u64;
    }
    Ok(hex_digest(digest.finalize()))
}

fn injected_failure(point: &'static str) -> std::io::Error {
    std::io::Error::other(format!("injected update-stage failure at {point}"))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn current_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn current_gid() -> u32 {
    unsafe { libc::getegid() }
}

fn current_architecture() -> UpdatePackageResult<UpdateArchitectureV1> {
    #[cfg(target_arch = "aarch64")]
    {
        Ok(UpdateArchitectureV1::Aarch64)
    }
    #[cfg(target_arch = "x86_64")]
    {
        Ok(UpdateArchitectureV1::X86_64)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        Err(UpdatePackageError::Invalid("runtime_architecture"))
    }
}

#[cfg(target_os = "macos")]
fn current_macos_version() -> UpdatePackageResult<String> {
    let name = CString::new("kern.osproductversion")
        .map_err(|_| UpdatePackageError::Invalid("runtime_macos_version"))?;
    let mut length = 0_usize;
    let size_result = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::null_mut(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if size_result != 0 || length == 0 || length > 64 {
        return Err(UpdatePackageError::Invalid("runtime_macos_version"));
    }
    let mut bytes = vec![0_u8; length];
    let read_result = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if read_result != 0 || length == 0 || length > bytes.len() {
        return Err(UpdatePackageError::Invalid("runtime_macos_version"));
    }
    bytes.truncate(length);
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| UpdatePackageError::Invalid("runtime_macos_version"))?;
    normalize_numeric_version(&value)
}

#[cfg(not(target_os = "macos"))]
fn current_macos_version() -> UpdatePackageResult<String> {
    Err(UpdatePackageError::Invalid("runtime_operating_system"))
}

fn normalize_numeric_version(value: &str) -> UpdatePackageResult<String> {
    let components = value.split('.').collect::<Vec<_>>();
    if !(2..=3).contains(&components.len())
        || components.iter().any(|component| {
            component.is_empty()
                || !component.bytes().all(|byte| byte.is_ascii_digit())
                || (component.len() > 1 && component.starts_with('0'))
                || component.parse::<u32>().is_err()
        })
    {
        return Err(UpdatePackageError::Invalid("runtime_macos_version"));
    }
    Ok(if components.len() == 2 {
        format!("{}.{}.0", components[0], components[1])
    } else {
        value.to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::sync::{Arc, Barrier};
    use wardrobe_core::{
        Sha256Digest, UpdateArchitectureV1, UpdateArtifactKindV1, UpdateChannelV1,
        UpdateOperatingSystemV1, UPDATE_APPLICATION_ID_V1, UPDATE_MANIFEST_SCHEMA_VERSION_V1,
    };

    fn digest(bytes: &[u8]) -> Sha256Digest {
        Sha256Digest::parse(hex_digest(Sha256::digest(bytes))).unwrap()
    }

    fn fixture() -> (
        tempfile::TempDir,
        UpdatePackageStager,
        TrustedUpdateRuntimeContext,
        Ed25519KeyPair,
        Vec<u8>,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let store_lock = Arc::new(StoreLock::acquire(&paths).unwrap());
        let database = crate::Database::open(&paths, 1_000).unwrap();
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let key_id = "ephemeral-test-key".to_owned();
        let stager = UpdatePackageStager::new(
            database,
            store_lock,
            vec![UpdateTrustKey {
                key_id: key_id.clone(),
                public_key: key.public_key().as_ref().try_into().unwrap(),
                minimum_release_sequence: 2,
                maximum_release_sequence: 10,
            }],
        )
        .unwrap();
        let context = stager.current_compatibility().unwrap();
        (
            temporary,
            stager,
            context,
            key,
            b"signed-app-artifact".to_vec(),
        )
    }

    fn signed_package(
        root: &Path,
        context: &TrustedUpdateRuntimeContext,
        key: &Ed25519KeyPair,
        artifact: &[u8],
        operation_suffix: &str,
    ) -> PathBuf {
        let manifest = valid_manifest(context, artifact, operation_suffix);
        let manifest_bytes = canonical_manifest_bytes(&manifest).unwrap();
        let signature = key.sign(&update_signature_message(&manifest_bytes).unwrap());
        let package = encode_update_package(&manifest, signature.as_ref(), artifact).unwrap();
        let path = root.join(format!("{operation_suffix}.wdupdate"));
        fs::write(&path, package).unwrap();
        path
    }

    fn valid_manifest(
        context: &TrustedUpdateRuntimeContext,
        artifact: &[u8],
        operation_suffix: &str,
    ) -> UpdateManifestV1 {
        UpdateManifestV1 {
            schema_version: UPDATE_MANIFEST_SCHEMA_VERSION_V1,
            application_id: UPDATE_APPLICATION_ID_V1.to_owned(),
            channel: UpdateChannelV1::Personal,
            key_id: "ephemeral-test-key".to_owned(),
            release_id: format!("release-{operation_suffix}"),
            release_sequence: 2,
            target_version: "0.2.0".to_owned(),
            target_os: UpdateOperatingSystemV1::Macos,
            target_architecture: context.architecture,
            minimum_macos_version: "15.0.0".to_owned(),
            artifact_kind: UpdateArtifactKindV1::MacosApplicationArchive,
            artifact_length: artifact.len() as u64,
            artifact_sha256: digest(artifact),
            accepted_source_version_min: context.application_version.clone(),
            accepted_source_version_max: context.application_version.clone(),
            accepted_databases: vec![context.database.clone()],
            target_database_schema_version: context.database.schema_version,
            target_migration_prefix_sha256: context.database.migration_prefix_sha256.clone(),
            required_backup_format_version: 1,
            required_asset_manifest_version: 1,
        }
    }

    fn write_raw_package(
        root: &Path,
        name: &str,
        manifest_bytes: &[u8],
        signature: &[u8],
        artifact: &[u8],
    ) -> PathBuf {
        let mut package = Vec::new();
        package.extend_from_slice(PACKAGE_MAGIC);
        package.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
        package.extend_from_slice(&(signature.len() as u16).to_be_bytes());
        package.extend_from_slice(&(artifact.len() as u64).to_be_bytes());
        package.extend_from_slice(manifest_bytes);
        package.extend_from_slice(signature);
        package.extend_from_slice(artifact);
        let path = root.join(format!("{name}.wdupdate"));
        fs::write(&path, package).unwrap();
        path
    }

    fn mutate_manifest(
        manifest: &UpdateManifestV1,
        mutation: impl FnOnce(&mut UpdateManifestV1),
    ) -> UpdateManifestV1 {
        let mut mutated = manifest.clone();
        mutation(&mut mutated);
        mutated
    }

    #[test]
    fn real_signature_stages_exact_package_and_replays_after_restart() {
        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "valid");
        let operation = Uuid::new_v4().to_string();

        let first = stager
            .stage(&operation, &package, 100)
            .unwrap_or_else(|error| {
                panic!("stage failed: {error:?}; recovery: {:?}", stager.recover())
            });
        assert!(!first.replayed);
        assert_eq!(
            fs::read(first.stage_path.join(PACKAGE_NAME)).unwrap(),
            fs::read(&package).unwrap()
        );

        let recovered = stager.recover().unwrap();
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].replayed);
        let replay = stager.stage(&operation, &package, 101).unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.package_sha256, first.package_sha256);
    }

    #[test]
    fn tampering_and_unsafe_file_identity_fail_without_publication() {
        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "tamper");
        let mut bytes = fs::read(&package).unwrap();
        *bytes.last_mut().unwrap() ^= 0x40;
        fs::write(&package, bytes).unwrap();
        assert!(matches!(
            stager.stage(&Uuid::new_v4().to_string(), &package, 100),
            Err(UpdatePackageError::Invalid("artifact_sha256"))
        ));
        assert_eq!(
            fs::read_dir(&stager.paths.update_verified).unwrap().count(),
            0
        );

        let clean = signed_package(temporary.path(), &context, &key, &artifact, "hardlink");
        let linked = temporary.path().join("linked.wdupdate");
        fs::hard_link(&clean, &linked).unwrap();
        assert!(matches!(
            stager.verify_only(&clean),
            Err(UpdatePackageError::Invalid("package_identity"))
        ));

        let symlink = temporary.path().join("symlink.wdupdate");
        std::os::unix::fs::symlink(&clean, &symlink).unwrap();
        assert!(stager.verify_only(&symlink).is_err());
    }

    #[test]
    fn detached_signature_byte_mutation_is_rejected() {
        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(
            temporary.path(),
            &context,
            &key,
            &artifact,
            "signature-byte",
        );
        let mut bytes = fs::read(&package).unwrap();
        let manifest_length = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        bytes[HEADER_LENGTH as usize + manifest_length] ^= 0x01;
        fs::write(&package, bytes).unwrap();

        assert!(matches!(
            stager.verify_only(&package),
            Err(UpdatePackageError::SignatureInvalid)
        ));
        assert_eq!(
            fs::read_dir(&stager.paths.update_verified).unwrap().count(),
            0
        );
    }

    #[test]
    fn every_signed_manifest_field_mutation_fails_closed() {
        let (temporary, stager, context, key, artifact) = fixture();
        let manifest = valid_manifest(&context, &artifact, "field-binding");
        let canonical = canonical_manifest_bytes(&manifest).unwrap();
        let signature = key.sign(&update_signature_message(&canonical).unwrap());
        let other_architecture = match context.architecture {
            UpdateArchitectureV1::Aarch64 => UpdateArchitectureV1::X86_64,
            UpdateArchitectureV1::X86_64 => UpdateArchitectureV1::Aarch64,
        };
        let mutations = vec![
            (
                "schema-version",
                mutate_manifest(&manifest, |value| value.schema_version = 2),
            ),
            (
                "application-id",
                mutate_manifest(&manifest, |value| {
                    value.application_id = "com.example.wardrobe".to_owned()
                }),
            ),
            (
                "channel",
                mutate_manifest(&manifest, |value| {
                    value.channel = UpdateChannelV1::Development
                }),
            ),
            (
                "key-id",
                mutate_manifest(&manifest, |value| value.key_id = "different-key".to_owned()),
            ),
            (
                "release-id",
                mutate_manifest(&manifest, |value| {
                    value.release_id = "different-release".to_owned()
                }),
            ),
            (
                "release-sequence",
                mutate_manifest(&manifest, |value| value.release_sequence = 3),
            ),
            (
                "target-version",
                mutate_manifest(&manifest, |value| value.target_version = "0.3.0".to_owned()),
            ),
            (
                "target-os",
                mutate_manifest(&manifest, |value| {
                    value.target_os = UpdateOperatingSystemV1::Linux
                }),
            ),
            (
                "target-architecture",
                mutate_manifest(&manifest, |value| {
                    value.target_architecture = other_architecture
                }),
            ),
            (
                "minimum-macos-version",
                mutate_manifest(&manifest, |value| {
                    value.minimum_macos_version = "16.0.0".to_owned()
                }),
            ),
            (
                "artifact-length",
                mutate_manifest(&manifest, |value| value.artifact_length += 1),
            ),
            (
                "artifact-sha256",
                mutate_manifest(&manifest, |value| {
                    value.artifact_sha256 = digest(b"different-artifact")
                }),
            ),
            (
                "source-version-min",
                mutate_manifest(&manifest, |value| {
                    value.accepted_source_version_min = "0.0.9".to_owned()
                }),
            ),
            (
                "source-version-max",
                mutate_manifest(&manifest, |value| {
                    value.accepted_source_version_max = "0.1.1".to_owned()
                }),
            ),
            (
                "accepted-database",
                mutate_manifest(&manifest, |value| {
                    value.accepted_databases[0].migration_prefix_sha256 =
                        digest(b"different-database")
                }),
            ),
            (
                "target-database-schema",
                mutate_manifest(&manifest, |value| value.target_database_schema_version += 1),
            ),
            (
                "target-migration-prefix",
                mutate_manifest(&manifest, |value| {
                    value.target_migration_prefix_sha256 = digest(b"different-target")
                }),
            ),
            (
                "backup-format",
                mutate_manifest(&manifest, |value| value.required_backup_format_version = 2),
            ),
            (
                "asset-manifest-format",
                mutate_manifest(&manifest, |value| value.required_asset_manifest_version = 2),
            ),
        ];

        for (name, mutated) in mutations {
            let bytes = serde_json::to_vec(&mutated).unwrap();
            let path = write_raw_package(
                temporary.path(),
                name,
                &bytes,
                signature.as_ref(),
                &artifact,
            );
            assert!(
                stager.verify_only(&path).is_err(),
                "accepted mutation {name}"
            );
        }

        let artifact_kind = canonical
            .windows(b"macos_application_archive".len())
            .position(|window| window == b"macos_application_archive")
            .unwrap();
        let mut unknown_kind = canonical.clone();
        unknown_kind.splice(
            artifact_kind..artifact_kind + b"macos_application_archive".len(),
            b"unapproved_remote_model".iter().copied(),
        );
        let path = write_raw_package(
            temporary.path(),
            "artifact-kind",
            &unknown_kind,
            signature.as_ref(),
            &artifact,
        );
        assert!(stager.verify_only(&path).is_err());
        assert_eq!(
            fs::read_dir(&stager.paths.update_verified).unwrap().count(),
            0
        );
    }

    #[test]
    fn malformed_framing_and_json_corpus_fails_without_publication() {
        let (temporary, stager, context, key, artifact) = fixture();
        let valid = signed_package(
            temporary.path(),
            &context,
            &key,
            &artifact,
            "framing-source",
        );
        let valid_bytes = fs::read(valid).unwrap();
        let mut cases = vec![("empty", Vec::new())];

        let mut wrong_magic = valid_bytes.clone();
        wrong_magic[..4].copy_from_slice(b"BAD1");
        cases.push(("magic", wrong_magic));

        let mut empty_manifest = valid_bytes.clone();
        empty_manifest[4..8].copy_from_slice(&0_u32.to_be_bytes());
        cases.push(("empty-manifest", empty_manifest));

        let mut oversized_manifest = valid_bytes.clone();
        oversized_manifest[4..8].copy_from_slice(&((MAX_MANIFEST_BYTES as u32) + 1).to_be_bytes());
        cases.push(("oversized-manifest", oversized_manifest));

        let mut wrong_signature = valid_bytes.clone();
        wrong_signature[8..10].copy_from_slice(&63_u16.to_be_bytes());
        cases.push(("signature-length", wrong_signature));

        let mut empty_artifact = valid_bytes.clone();
        empty_artifact[10..18].copy_from_slice(&0_u64.to_be_bytes());
        cases.push(("empty-artifact", empty_artifact));

        let mut oversized_artifact = valid_bytes.clone();
        oversized_artifact[10..18]
            .copy_from_slice(&(MAX_UPDATE_ARTIFACT_BYTES_V1 + 1).to_be_bytes());
        cases.push(("oversized-artifact", oversized_artifact));

        let mut truncated = valid_bytes.clone();
        truncated.pop();
        cases.push(("truncated", truncated));

        let mut trailing = valid_bytes;
        trailing.push(0);
        cases.push(("trailing", trailing));

        for (name, bytes) in cases {
            let path = temporary.path().join(format!("{name}.wdupdate"));
            fs::write(&path, bytes).unwrap();
            assert!(stager.verify_only(&path).is_err(), "accepted corpus {name}");
        }

        let manifest = valid_manifest(&context, &artifact, "json-corpus");
        let canonical = canonical_manifest_bytes(&manifest).unwrap();
        let signature = key.sign(&update_signature_message(&canonical).unwrap());
        for (name, suffix) in [
            ("unknown-field", br#","unexpected":true}"#.as_slice()),
            ("duplicate-field", br#","schema_version":1}"#.as_slice()),
        ] {
            let mut malformed = canonical[..canonical.len() - 1].to_vec();
            malformed.extend_from_slice(suffix);
            let path = write_raw_package(
                temporary.path(),
                name,
                &malformed,
                signature.as_ref(),
                &artifact,
            );
            assert!(stager.verify_only(&path).is_err(), "accepted JSON {name}");
        }
        assert_eq!(
            fs::read_dir(&stager.paths.update_verified).unwrap().count(),
            0
        );
    }

    #[test]
    fn empty_production_keyring_fails_closed() {
        let (temporary, _, context, key, artifact) = fixture();
        let paths = PrivateAppPaths::create(temporary.path().join("disabled")).unwrap();
        let store_lock = Arc::new(StoreLock::acquire(&paths).unwrap());
        let database = crate::Database::open(&paths, 1_000).unwrap();
        let disabled = UpdatePackageStager::production_disabled(database, store_lock).unwrap();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "disabled");
        assert!(!disabled.has_trusted_release_key());
        assert!(matches!(
            disabled.verify_only(&package),
            Err(UpdatePackageError::SignatureInvalid)
        ));
    }

    #[test]
    fn stager_rejects_a_store_lock_for_another_private_root() {
        let temporary = tempfile::tempdir().unwrap();
        let database_paths =
            PrivateAppPaths::create(temporary.path().join("database-root")).unwrap();
        let lock_paths = PrivateAppPaths::create(temporary.path().join("lock-root")).unwrap();
        let database = crate::Database::open(&database_paths, 1_000).unwrap();
        let wrong_lock = Arc::new(StoreLock::acquire(&lock_paths).unwrap());

        assert!(matches!(
            UpdatePackageStager::production_disabled(database, wrong_lock),
            Err(UpdatePackageError::Invalid("store_lock_mismatch"))
        ));
    }

    #[test]
    fn verification_rederives_current_database_lineage() {
        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(
            temporary.path(),
            &context,
            &key,
            &artifact,
            "fresh-database",
        );
        let connection = rusqlite::Connection::open(&stager.database.paths.database).unwrap();
        connection
            .pragma_update(None, "user_version", 12_i64)
            .unwrap();
        drop(connection);

        assert!(matches!(
            stager.verify_only(&package),
            Err(UpdatePackageError::Platform(PlatformError::Corrupt(_)))
        ));
    }

    #[test]
    fn staging_rechecks_database_lineage_before_publication() {
        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "database-race");
        let database_path = stager.database.paths.database.clone();
        let result = stager.stage_internal(
            &Uuid::new_v4().to_string(),
            &package,
            100,
            StageFault::None,
            move || {
                let connection = rusqlite::Connection::open(database_path).unwrap();
                connection
                    .pragma_update(None, "user_version", 12_i64)
                    .unwrap();
            },
        );

        assert!(matches!(
            result,
            Err(UpdatePackageError::Platform(PlatformError::Corrupt(_)))
        ));
        assert_eq!(
            fs::read_dir(&stager.paths.update_staging).unwrap().count(),
            0
        );
        assert_eq!(
            fs::read_dir(&stager.paths.update_verified).unwrap().count(),
            0
        );
    }

    #[test]
    fn staged_files_require_private_descriptor_identity() {
        for (index, file_name) in [PACKAGE_NAME, RECORD_NAME, RECORD_HASH_NAME]
            .into_iter()
            .enumerate()
        {
            let (temporary, stager, context, key, artifact) = fixture();
            let package = signed_package(
                temporary.path(),
                &context,
                &key,
                &artifact,
                &format!("private-file-{index}"),
            );
            let staged = stager
                .stage(&Uuid::new_v4().to_string(), &package, 100)
                .unwrap();
            for expected in [PACKAGE_NAME, RECORD_NAME, RECORD_HASH_NAME] {
                let metadata = fs::symlink_metadata(staged.stage_path.join(expected)).unwrap();
                assert_eq!(metadata.mode() & 0o777, 0o600);
                assert_eq!(metadata.uid(), current_uid());
                assert_eq!(metadata.gid(), current_gid());
                assert_eq!(metadata.nlink(), 1);
            }
            fs::set_permissions(
                staged.stage_path.join(file_name),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(matches!(
                stager.recover(),
                Err(UpdatePackageError::Invalid("stage_file_identity"))
            ));
        }

        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(
            temporary.path(),
            &context,
            &key,
            &artifact,
            "staged-hardlink",
        );
        let staged = stager
            .stage(&Uuid::new_v4().to_string(), &package, 100)
            .unwrap();
        fs::hard_link(
            staged.stage_path.join(PACKAGE_NAME),
            temporary.path().join("retained-hardlink.wdupdate"),
        )
        .unwrap();
        assert!(matches!(
            stager.recover(),
            Err(UpdatePackageError::Invalid("stage_file_identity"))
        ));
    }

    #[test]
    fn signed_equivocation_and_operation_reuse_are_rejected() {
        let (temporary, stager, context, key, artifact) = fixture();
        let first = signed_package(temporary.path(), &context, &key, &artifact, "first");
        let second = signed_package(temporary.path(), &context, &key, &artifact, "second");
        let operation = Uuid::new_v4().to_string();
        stager.stage(&operation, &first, 100).unwrap();

        assert!(matches!(
            stager.stage(&operation, &second, 101),
            Err(UpdatePackageError::Conflict(
                "update_operation_envelope_changed"
            ))
        ));
        assert!(matches!(
            stager.stage(&Uuid::new_v4().to_string(), &second, 102),
            Err(UpdatePackageError::Conflict(
                "update_release_sequence_equivocation"
            ))
        ));
    }

    #[test]
    fn published_stage_tampering_and_trailing_package_data_fail_closed() {
        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "published");
        let stage = stager
            .stage(&Uuid::new_v4().to_string(), &package, 100)
            .unwrap();
        let retained = stage.stage_path.join(PACKAGE_NAME);
        let mut bytes = fs::read(&retained).unwrap();
        *bytes.last_mut().unwrap() ^= 0x80;
        fs::write(&retained, bytes).unwrap();
        assert!(stager.recover().is_err());

        let trailing = signed_package(temporary.path(), &context, &key, &artifact, "trailing");
        let mut bytes = fs::read(&trailing).unwrap();
        bytes.push(0);
        fs::write(&trailing, bytes).unwrap();
        assert!(matches!(
            stager.verify_only(&trailing),
            Err(UpdatePackageError::Invalid("package_length"))
        ));
    }

    #[test]
    fn source_mutation_and_publication_faults_recover_without_false_success() {
        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "mutation");
        let mutation_path = package.clone();
        let result = stager.stage_internal(
            &Uuid::new_v4().to_string(),
            &package,
            100,
            StageFault::None,
            move || {
                let mut bytes = fs::read(&mutation_path).unwrap();
                *bytes.last_mut().unwrap() ^= 0x20;
                fs::write(&mutation_path, bytes).unwrap();
            },
        );
        assert!(matches!(
            result,
            Err(UpdatePackageError::Invalid("package_changed"))
        ));
        assert_eq!(
            fs::read_dir(&stager.paths.update_staging).unwrap().count(),
            0
        );
        assert_eq!(
            fs::read_dir(&stager.paths.update_verified).unwrap().count(),
            0
        );

        for (index, fault) in [
            StageFault::BeforeCopy,
            StageFault::DuringPackageWrite,
            StageFault::BeforePackageSync,
            StageFault::BeforeRecordWrite,
            StageFault::BeforeStageDirectorySync,
        ]
        .into_iter()
        .enumerate()
        {
            let (temporary, stager, context, key, artifact) = fixture();
            let package = signed_package(
                temporary.path(),
                &context,
                &key,
                &artifact,
                &format!("prepublication-{index}"),
            );
            let result =
                stager.stage_internal(&Uuid::new_v4().to_string(), &package, 100, fault, || {});
            assert!(
                matches!(result, Err(UpdatePackageError::Platform(_))),
                "fault {fault:?} reported success"
            );
            assert_eq!(
                fs::read_dir(&stager.paths.update_staging).unwrap().count(),
                0,
                "fault {fault:?} left temporary state"
            );
            assert_eq!(
                fs::read_dir(&stager.paths.update_verified).unwrap().count(),
                0,
                "fault {fault:?} published state"
            );
        }

        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "rename");
        let result = stager.stage_internal(
            &Uuid::new_v4().to_string(),
            &package,
            100,
            StageFault::RenameOutcomeUnknown,
            || {},
        );
        assert!(matches!(
            result,
            Err(UpdatePackageError::PublicationOutcomeUnknown)
        ));
        assert_eq!(
            fs::read_dir(&stager.paths.update_staging).unwrap().count(),
            1
        );
        assert!(stager.recover().unwrap().is_empty());

        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "postrename");
        let result = stager.stage_internal(
            &Uuid::new_v4().to_string(),
            &package,
            100,
            StageFault::AfterRename,
            || {},
        );
        assert!(matches!(
            result,
            Err(UpdatePackageError::PublicationOutcomeUnknown)
        ));
        assert_eq!(stager.recover().unwrap().len(), 1);

        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "parent-sync");
        let result = stager.stage_internal(
            &Uuid::new_v4().to_string(),
            &package,
            100,
            StageFault::BeforeParentDirectorySync,
            || {},
        );
        assert!(matches!(
            result,
            Err(UpdatePackageError::PublicationOutcomeUnknown)
        ));
        assert_eq!(stager.recover().unwrap().len(), 1);
    }

    #[test]
    fn concurrent_exact_staging_serializes_to_one_publication() {
        let (temporary, stager, context, key, artifact) = fixture();
        let package = signed_package(temporary.path(), &context, &key, &artifact, "concurrent");
        let stager = Arc::new(stager);
        let barrier = Arc::new(Barrier::new(2));
        let operation = Uuid::new_v4().to_string();
        let handles = (0..2)
            .map(|index| {
                let stager = Arc::clone(&stager);
                let barrier = Arc::clone(&barrier);
                let operation = operation.clone();
                let package = package.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    stager.stage(&operation, &package, 100 + index)
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(results.iter().filter(|result| result.replayed).count(), 1);
        assert_eq!(results.iter().filter(|result| !result.replayed).count(), 1);
        assert_eq!(
            fs::read_dir(&stager.paths.update_verified).unwrap().count(),
            1
        );
        assert_eq!(stager.recover().unwrap().len(), 1);
    }

    #[test]
    fn update_lock_excludes_a_second_process() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let _lock = UpdateStageLock::acquire(&paths).unwrap();
        let path =
            std::ffi::CString::new(paths.update_lock.as_os_str().as_encoded_bytes()).unwrap();
        let mut pipe_fds = [0_i32; 2];
        assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                libc::close(pipe_fds[0]);
                let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
                let blocked = fd >= 0
                    && libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EWOULDBLOCK);
                let value = u8::from(blocked);
                libc::write(pipe_fds[1], (&value as *const u8).cast(), 1);
                if fd >= 0 {
                    libc::close(fd);
                }
                libc::close(pipe_fds[1]);
                libc::_exit(0);
            }
        }
        unsafe {
            libc::close(pipe_fds[1]);
        }
        let mut value = 0_u8;
        assert_eq!(
            unsafe { libc::read(pipe_fds[0], (&mut value as *mut u8).cast(), 1) },
            1
        );
        unsafe {
            libc::close(pipe_fds[0]);
            libc::waitpid(child, std::ptr::null_mut(), 0);
        }
        assert_eq!(value, 1);
    }
}
