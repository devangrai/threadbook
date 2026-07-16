use crate::{PlatformError, PrivateAppPaths};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use wardrobe_core::{
    LocalOnlyAuthorityHealthV1, ReplayStatusV1, RequestId, SetLocalOnlyV1Request,
    SetLocalOnlyV1Response, MAX_SAFE_INTEGER_V1, SCHEMA_VERSION_V1,
};

const MAX_RECORD_BYTES: usize = 4 * 1024;
const INTENT_LEAF: &str = "transition-intent-v1.json";
const ACTIVE_LEAF: &str = "network-mode-v1.json";
const ACKNOWLEDGMENT_LEAF: &str = "transition-acknowledgment-v1.json";

pub type LocalOnlyStoreResult<T> = Result<T, LocalOnlyStoreError>;

#[derive(Debug)]
pub enum LocalOnlyStoreError {
    Platform(PlatformError),
    PublicationOutcomeUnknown,
}

impl fmt::Display for LocalOnlyStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => error.fmt(formatter),
            Self::PublicationOutcomeUnknown => {
                formatter.write_str("local-only publication outcome is unknown")
            }
        }
    }
}

impl Error for LocalOnlyStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            Self::PublicationOutcomeUnknown => None,
        }
    }
}

impl From<PlatformError> for LocalOnlyStoreError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<std::io::Error> for LocalOnlyStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Platform(PlatformError::Io(error))
    }
}

impl From<serde_json::Error> for LocalOnlyStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Platform(PlatformError::Json(error))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalOnlyModeSnapshot {
    pub local_only: bool,
    pub revision: u64,
    pub authority_health: LocalOnlyAuthorityHealthV1,
}

impl LocalOnlyModeSnapshot {
    fn fail_closed() -> Self {
        Self {
            local_only: true,
            revision: 0,
            authority_health: LocalOnlyAuthorityHealthV1::FailClosedDefault,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalOnlyModeStore {
    root: PathBuf,
    state: Arc<Mutex<StoreState>>,
}

#[derive(Debug, Default)]
struct StoreState {
    uncertain: Option<UncertainPublication>,
    fault_injector: PublicationFaultInjector,
}

#[derive(Clone, Debug)]
struct UncertainPublication {
    prior_revision: u64,
    prior_records: [Vec<u8>; 3],
    target_records: [Vec<u8>; 3],
    request_id: RequestId,
    request_sha256: String,
}

impl UncertainPublication {
    fn recognized_records(&self, root: &Path) -> Option<[Vec<u8>; 3]> {
        let directory = open_private_directory(root).ok()?;
        let records = [
            read_private_record(&directory, INTENT_LEAF).ok()?,
            read_private_record(&directory, ACTIVE_LEAF).ok()?,
            read_private_record(&directory, ACKNOWLEDGMENT_LEAF).ok()?,
        ];
        records
            .iter()
            .zip(self.prior_records.iter().zip(&self.target_records))
            .all(|(actual, (prior, target))| actual == prior || actual == target)
            .then_some(records)
    }
}

impl LocalOnlyModeStore {
    pub fn new(paths: &PrivateAppPaths) -> Self {
        Self {
            root: paths.root.clone(),
            state: Arc::new(Mutex::new(StoreState::default())),
        }
    }

    pub fn load(&self) -> LocalOnlyModeSnapshot {
        let _state = self.lock_state();
        self.load_chain()
            .map(|chain| LocalOnlyModeSnapshot {
                local_only: chain.active.local_only,
                revision: chain.active.revision,
                authority_health: LocalOnlyAuthorityHealthV1::Persisted,
            })
            .unwrap_or_else(|_| LocalOnlyModeSnapshot::fail_closed())
    }

    pub fn set(
        &self,
        request: &SetLocalOnlyV1Request,
    ) -> LocalOnlyStoreResult<SetLocalOnlyV1Response> {
        self.validate_request(request)?;
        let envelope_sha256 = canonical_hash(request)?;
        let mut state = self.lock_state();

        let current = self.load_chain().ok();
        if state.uncertain.as_ref().is_some_and(|uncertain| {
            uncertain.request_id == request.request_id
                && uncertain.request_sha256 != envelope_sha256
        }) {
            return Err(PlatformError::Conflict("local_only_request_id_reused").into());
        }
        if let Some(chain) = current.as_ref() {
            if chain.active.request_id == request.request_id {
                if chain.active.request_sha256 != envelope_sha256 {
                    return Err(PlatformError::Conflict("local_only_request_id_reused").into());
                }
                state.uncertain = None;
                return Ok(response(
                    request.request_id,
                    chain.active.local_only,
                    chain.active.revision,
                    ReplayStatusV1::Replayed,
                ));
            }
        }

        let recognized_uncertain = if current.is_none() {
            state
                .uncertain
                .as_ref()
                .and_then(|uncertain| uncertain.recognized_records(&self.root))
        } else {
            None
        };
        let current_revision = current.as_ref().map_or_else(
            || {
                recognized_uncertain.as_ref().map_or(0, |_| {
                    state
                        .uncertain
                        .as_ref()
                        .expect("recognized records require uncertain state")
                        .prior_revision
                })
            },
            |chain| chain.active.revision,
        );
        if request.expected_revision != current_revision {
            return Err(PlatformError::Conflict("local_only_stale_revision").into());
        }
        let target_revision = current_revision
            .checked_add(1)
            .filter(|revision| *revision <= MAX_SAFE_INTEGER_V1)
            .ok_or(PlatformError::Conflict("local_only_revision_exhausted"))?;

        let transition_nonce = random_hex::<32>()?;
        let intent = TransitionIntentV1::new(
            current_revision,
            target_revision,
            request.enabled,
            request.request_id,
            envelope_sha256.clone(),
            transition_nonce.clone(),
        )?;
        let intent_bytes = canonical_bytes(&intent)?;
        let intent_sha256 = digest_bytes(&intent_bytes);
        let active = ActiveModeV1::new(
            target_revision,
            request.enabled,
            request.request_id,
            envelope_sha256.clone(),
        )?;
        let active_bytes = canonical_bytes(&active)?;
        let active_sha256 = digest_bytes(&active_bytes);
        let acknowledgment = TransitionAcknowledgmentV1::new(
            target_revision,
            transition_nonce,
            intent_sha256,
            active_sha256,
        )?;
        let acknowledgment_bytes = canonical_bytes(&acknowledgment)?;
        let target_records = [
            intent_bytes.clone(),
            active_bytes.clone(),
            acknowledgment_bytes.clone(),
        ];
        let prior_records = current
            .as_ref()
            .map(|chain| chain.records.clone())
            .or(recognized_uncertain);
        let uncertain_publication = prior_records.map(|prior_records| UncertainPublication {
            prior_revision: current_revision,
            prior_records,
            target_records,
            request_id: request.request_id,
            request_sha256: envelope_sha256,
        });

        let directory = open_private_directory(&self.root)?;
        let records = [
            PreparedRecord::create(&directory, INTENT_LEAF, intent_bytes)?,
            PreparedRecord::create(&directory, ACTIVE_LEAF, active_bytes)?,
            PreparedRecord::create(&directory, ACKNOWLEDGMENT_LEAF, acknowledgment_bytes)?,
        ];

        for record in &records {
            validate_target_for_replace(directory.as_raw_fd(), &record.target_leaf)?;
        }
        let mut publication_started = false;
        for (index, record) in records.iter().enumerate() {
            if let Err(error) = record.publish(&directory, index, &mut state.fault_injector) {
                if publication_started || matches!(error, PublishError::Unknown) {
                    state.uncertain = uncertain_publication.clone();
                    return Err(LocalOnlyStoreError::PublicationOutcomeUnknown);
                }
                let PublishError::Before(error) = error else {
                    unreachable!("unknown publication errors are handled above");
                };
                return Err(error.into());
            }
            publication_started = true;
        }

        let loaded = match self.load_chain() {
            Ok(loaded) => loaded,
            Err(_) => {
                state.uncertain = uncertain_publication;
                return Err(LocalOnlyStoreError::PublicationOutcomeUnknown);
            }
        };
        if loaded.active.revision != target_revision
            || loaded.active.request_id != request.request_id
            || loaded.active.local_only != request.enabled
        {
            state.uncertain = uncertain_publication;
            return Err(LocalOnlyStoreError::PublicationOutcomeUnknown);
        }
        state.uncertain = None;
        Ok(response(
            request.request_id,
            request.enabled,
            target_revision,
            ReplayStatusV1::Created,
        ))
    }

    pub fn set_local_only(
        &self,
        request: &SetLocalOnlyV1Request,
    ) -> LocalOnlyStoreResult<SetLocalOnlyV1Response> {
        self.set(request)
    }

    pub fn load_acknowledged_response(
        &self,
        request: &SetLocalOnlyV1Request,
    ) -> Option<SetLocalOnlyV1Response> {
        let mut state = self.lock_state();
        let expected_hash = canonical_hash(request).ok()?;
        let chain = self.load_chain().ok()?;
        if chain.active.request_id != request.request_id
            || chain.active.request_sha256 != expected_hash
            || chain.active.local_only != request.enabled
            || chain.active.revision != request.expected_revision.checked_add(1)?
        {
            return None;
        }
        state.uncertain = None;
        Some(response(
            request.request_id,
            chain.active.local_only,
            chain.active.revision,
            ReplayStatusV1::Created,
        ))
    }

    fn lock_state(&self) -> MutexGuard<'_, StoreState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    fn inject_publication_fault(&self, fault: PublicationFault) {
        self.lock_state().fault_injector.fault = Some(fault);
    }

    fn validate_request(&self, request: &SetLocalOnlyV1Request) -> LocalOnlyStoreResult<()> {
        if request.schema_version != SCHEMA_VERSION_V1 {
            return Err(PlatformError::InvalidInput("schema_version").into());
        }
        if request.expected_revision >= MAX_SAFE_INTEGER_V1 {
            return Err(PlatformError::InvalidInput("expected_revision").into());
        }
        Ok(())
    }

    fn load_chain(&self) -> Result<LoadedChain, PlatformError> {
        let directory = open_private_directory(&self.root)?;
        let intent_bytes = read_private_record(&directory, INTENT_LEAF)?;
        let active_bytes = read_private_record(&directory, ACTIVE_LEAF)?;
        let acknowledgment_bytes = read_private_record(&directory, ACKNOWLEDGMENT_LEAF)?;

        let intent: TransitionIntentV1 = decode_canonical(&intent_bytes)?;
        let active: ActiveModeV1 = decode_canonical(&active_bytes)?;
        let acknowledgment: TransitionAcknowledgmentV1 = decode_canonical(&acknowledgment_bytes)?;
        intent.validate()?;
        active.validate()?;
        acknowledgment.validate()?;

        if intent.target_revision != active.revision
            || intent.local_only != active.local_only
            || intent.request_id != active.request_id
            || intent.request_sha256 != active.request_sha256
            || acknowledgment.revision != active.revision
            || acknowledgment.transition_nonce != intent.transition_nonce
            || acknowledgment.intent_sha256 != digest_bytes(&intent_bytes)
            || acknowledgment.active_sha256 != digest_bytes(&active_bytes)
        {
            return Err(PlatformError::Corrupt("local_only_transition_mismatch"));
        }
        if intent
            .prior_revision
            .checked_add(1)
            .filter(|revision| *revision == intent.target_revision)
            .is_none()
        {
            return Err(PlatformError::Corrupt("local_only_transition_revision"));
        }
        Ok(LoadedChain {
            active,
            records: [intent_bytes, active_bytes, acknowledgment_bytes],
        })
    }
}

fn response(
    request_id: RequestId,
    local_only: bool,
    revision: u64,
    replay_status: ReplayStatusV1,
) -> SetLocalOnlyV1Response {
    SetLocalOnlyV1Response {
        schema_version: SCHEMA_VERSION_V1,
        request_id,
        local_only,
        revision,
        authority_health: LocalOnlyAuthorityHealthV1::Persisted,
        replay_status,
    }
}

struct LoadedChain {
    active: ActiveModeV1,
    records: [Vec<u8>; 3],
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionIntentBodyV1 {
    schema_version: u8,
    prior_revision: u64,
    target_revision: u64,
    local_only: bool,
    request_id: RequestId,
    request_sha256: String,
    transition_nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionIntentV1 {
    schema_version: u8,
    prior_revision: u64,
    target_revision: u64,
    local_only: bool,
    request_id: RequestId,
    request_sha256: String,
    transition_nonce: String,
    checksum_sha256: String,
}

impl TransitionIntentV1 {
    fn new(
        prior_revision: u64,
        target_revision: u64,
        local_only: bool,
        request_id: RequestId,
        request_sha256: String,
        transition_nonce: String,
    ) -> Result<Self, PlatformError> {
        let body = TransitionIntentBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            prior_revision,
            target_revision,
            local_only,
            request_id,
            request_sha256,
            transition_nonce,
        };
        let checksum_sha256 = canonical_hash(&body)?;
        Ok(Self {
            schema_version: body.schema_version,
            prior_revision: body.prior_revision,
            target_revision: body.target_revision,
            local_only: body.local_only,
            request_id: body.request_id,
            request_sha256: body.request_sha256,
            transition_nonce: body.transition_nonce,
            checksum_sha256,
        })
    }

    fn validate(&self) -> Result<(), PlatformError> {
        if self.schema_version != SCHEMA_VERSION_V1
            || self.target_revision == 0
            || self.target_revision > MAX_SAFE_INTEGER_V1
            || self.prior_revision >= self.target_revision
            || !valid_hash(&self.request_sha256)
            || !valid_hash(&self.transition_nonce)
            || !valid_hash(&self.checksum_sha256)
        {
            return Err(PlatformError::Corrupt("local_only_intent"));
        }
        let body = TransitionIntentBodyV1 {
            schema_version: self.schema_version,
            prior_revision: self.prior_revision,
            target_revision: self.target_revision,
            local_only: self.local_only,
            request_id: self.request_id,
            request_sha256: self.request_sha256.clone(),
            transition_nonce: self.transition_nonce.clone(),
        };
        if canonical_hash(&body)? != self.checksum_sha256 {
            return Err(PlatformError::Corrupt("local_only_intent_checksum"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveModeBodyV1 {
    schema_version: u8,
    revision: u64,
    local_only: bool,
    request_id: RequestId,
    request_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveModeV1 {
    schema_version: u8,
    revision: u64,
    local_only: bool,
    request_id: RequestId,
    request_sha256: String,
    checksum_sha256: String,
}

impl ActiveModeV1 {
    fn new(
        revision: u64,
        local_only: bool,
        request_id: RequestId,
        request_sha256: String,
    ) -> Result<Self, PlatformError> {
        let body = ActiveModeBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            revision,
            local_only,
            request_id,
            request_sha256,
        };
        let checksum_sha256 = canonical_hash(&body)?;
        Ok(Self {
            schema_version: body.schema_version,
            revision: body.revision,
            local_only: body.local_only,
            request_id: body.request_id,
            request_sha256: body.request_sha256,
            checksum_sha256,
        })
    }

    fn validate(&self) -> Result<(), PlatformError> {
        if self.schema_version != SCHEMA_VERSION_V1
            || self.revision == 0
            || self.revision > MAX_SAFE_INTEGER_V1
            || !valid_hash(&self.request_sha256)
            || !valid_hash(&self.checksum_sha256)
        {
            return Err(PlatformError::Corrupt("local_only_active"));
        }
        let body = ActiveModeBodyV1 {
            schema_version: self.schema_version,
            revision: self.revision,
            local_only: self.local_only,
            request_id: self.request_id,
            request_sha256: self.request_sha256.clone(),
        };
        if canonical_hash(&body)? != self.checksum_sha256 {
            return Err(PlatformError::Corrupt("local_only_active_checksum"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionAcknowledgmentBodyV1 {
    schema_version: u8,
    revision: u64,
    transition_nonce: String,
    intent_sha256: String,
    active_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionAcknowledgmentV1 {
    schema_version: u8,
    revision: u64,
    transition_nonce: String,
    intent_sha256: String,
    active_sha256: String,
    checksum_sha256: String,
}

impl TransitionAcknowledgmentV1 {
    fn new(
        revision: u64,
        transition_nonce: String,
        intent_sha256: String,
        active_sha256: String,
    ) -> Result<Self, PlatformError> {
        let body = TransitionAcknowledgmentBodyV1 {
            schema_version: SCHEMA_VERSION_V1,
            revision,
            transition_nonce,
            intent_sha256,
            active_sha256,
        };
        let checksum_sha256 = canonical_hash(&body)?;
        Ok(Self {
            schema_version: body.schema_version,
            revision: body.revision,
            transition_nonce: body.transition_nonce,
            intent_sha256: body.intent_sha256,
            active_sha256: body.active_sha256,
            checksum_sha256,
        })
    }

    fn validate(&self) -> Result<(), PlatformError> {
        if self.schema_version != SCHEMA_VERSION_V1
            || self.revision == 0
            || self.revision > MAX_SAFE_INTEGER_V1
            || !valid_hash(&self.transition_nonce)
            || !valid_hash(&self.intent_sha256)
            || !valid_hash(&self.active_sha256)
            || !valid_hash(&self.checksum_sha256)
        {
            return Err(PlatformError::Corrupt("local_only_acknowledgment"));
        }
        let body = TransitionAcknowledgmentBodyV1 {
            schema_version: self.schema_version,
            revision: self.revision,
            transition_nonce: self.transition_nonce.clone(),
            intent_sha256: self.intent_sha256.clone(),
            active_sha256: self.active_sha256.clone(),
        };
        if canonical_hash(&body)? != self.checksum_sha256 {
            return Err(PlatformError::Corrupt("local_only_acknowledgment_checksum"));
        }
        Ok(())
    }
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, PlatformError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(PlatformError::Corrupt("local_only_record_size"));
    }
    Ok(bytes)
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<String, PlatformError> {
    Ok(digest_bytes(&canonical_bytes(value)?))
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, PlatformError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(PlatformError::Corrupt("local_only_record_size"));
    }
    let value = serde_json::from_slice(bytes)?;
    if canonical_bytes(&value)? != bytes {
        return Err(PlatformError::Corrupt("local_only_record_canonical"));
    }
    Ok(value)
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn random_hex<const N: usize>() -> Result<String, PlatformError> {
    let mut bytes = [0_u8; N];
    getrandom::getrandom(&mut bytes).map_err(|_| {
        PlatformError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "secure random source unavailable",
        ))
    })?;
    let mut result = String::with_capacity(N * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(result)
}

fn open_private_directory(root_path: &Path) -> Result<File, PlatformError> {
    let root_path = CString::new(root_path.as_os_str().as_bytes())
        .map_err(|_| PlatformError::Corrupt("local_only_directory"))?;
    let root_descriptor = unsafe {
        libc::open(
            root_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if root_descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let root = unsafe { File::from_raw_fd(root_descriptor) };
    validate_private_directory(&root)?;

    let leaf = c".network-mode";
    let descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    validate_private_directory(&directory)?;
    Ok(directory)
}

fn validate_private_directory(directory: &File) -> Result<(), PlatformError> {
    let metadata = directory.metadata()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
        || metadata.nlink() < 2
    {
        return Err(PlatformError::Corrupt("local_only_directory"));
    }
    Ok(())
}

fn read_private_record(directory: &File, leaf: &str) -> Result<Vec<u8>, PlatformError> {
    let leaf = CString::new(leaf).expect("constant leaf is a C string");
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file.metadata()?;
    let identity = (metadata.dev(), metadata.ino());
    validate_private_file(&file, Some(identity))?;
    let length = metadata.len();
    if length == 0 || length > MAX_RECORD_BYTES as u64 {
        return Err(PlatformError::Corrupt("local_only_record_size"));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    (&file)
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != length as usize || bytes.len() > MAX_RECORD_BYTES {
        return Err(PlatformError::Corrupt("local_only_record_size"));
    }
    validate_private_file(&file, Some(identity))?;
    validate_named_identity(directory.as_raw_fd(), &leaf, Some(identity))?;
    Ok(bytes)
}

fn validate_private_file(
    file: &File,
    expected_identity: Option<(u64, u64)>,
) -> Result<(), PlatformError> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || expected_identity.is_some_and(|identity| identity != (metadata.dev(), metadata.ino()))
    {
        return Err(PlatformError::Corrupt("local_only_record_identity"));
    }
    Ok(())
}

#[derive(Debug, Default)]
struct PublicationFaultInjector {
    #[cfg(test)]
    fault: Option<PublicationFault>,
}

impl PublicationFaultInjector {
    fn before_rename(&mut self, index: usize) -> bool {
        #[cfg(test)]
        if self.fault == Some(PublicationFault::BeforeRename(index)) {
            self.fault = None;
            return true;
        }
        let _ = index;
        false
    }

    fn before_directory_sync(&mut self, index: usize) -> bool {
        #[cfg(test)]
        if self.fault == Some(PublicationFault::BeforeDirectorySync(index)) {
            self.fault = None;
            return true;
        }
        let _ = index;
        false
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PublicationFault {
    BeforeRename(usize),
    BeforeDirectorySync(usize),
}

struct PreparedRecord {
    directory: File,
    temporary_leaf: CString,
    target_leaf: CString,
    bytes: Vec<u8>,
    identity: (u64, u64),
}

impl PreparedRecord {
    fn create(directory: &File, target_leaf: &str, bytes: Vec<u8>) -> Result<Self, PlatformError> {
        let target_leaf = CString::new(target_leaf).expect("constant leaf is a C string");
        let cleanup_directory = directory.try_clone()?;
        for _ in 0..32 {
            let temporary_leaf = CString::new(format!(".mode-{}.tmp", random_hex::<16>()?))
                .expect("hex temporary name is a C string");
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    temporary_leaf.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if descriptor < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(error.into());
            }
            let mut file = unsafe { File::from_raw_fd(descriptor) };
            let identity = {
                let metadata = file.metadata()?;
                (metadata.dev(), metadata.ino())
            };
            let prepared = (|| -> Result<(), PlatformError> {
                if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                validate_private_file(&file, Some(identity))?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                file.seek(SeekFrom::Start(0))?;
                let mut reread = Vec::with_capacity(bytes.len());
                file.read_to_end(&mut reread)?;
                if reread.len() != bytes.len()
                    || Sha256::digest(&reread).as_slice() != Sha256::digest(&bytes).as_slice()
                {
                    return Err(PlatformError::Corrupt("local_only_temporary_verification"));
                }
                validate_named_identity(directory.as_raw_fd(), &temporary_leaf, Some(identity))
            })();
            if let Err(error) = prepared {
                unlink_if_owned(directory.as_raw_fd(), &temporary_leaf, identity);
                return Err(error);
            }
            return Ok(Self {
                directory: cleanup_directory,
                temporary_leaf,
                target_leaf,
                bytes,
                identity,
            });
        }
        Err(PlatformError::Conflict(
            "local_only_temporary_name_exhausted",
        ))
    }

    fn publish(
        &self,
        directory: &File,
        index: usize,
        fault_injector: &mut PublicationFaultInjector,
    ) -> Result<(), PublishError> {
        validate_target_for_replace(directory.as_raw_fd(), &self.target_leaf)
            .map_err(PublishError::Before)?;
        if fault_injector.before_rename(index) {
            return Err(PublishError::Unknown);
        }
        let result = unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                self.temporary_leaf.as_ptr(),
                directory.as_raw_fd(),
                self.target_leaf.as_ptr(),
            )
        };
        if result != 0 {
            return Err(PublishError::Unknown);
        }
        verify_published(
            directory.as_raw_fd(),
            &self.target_leaf,
            self.identity,
            &self.bytes,
        )
        .map_err(|_| PublishError::Unknown)?;
        if fault_injector.before_directory_sync(index) {
            return Err(PublishError::Unknown);
        }
        directory.sync_all().map_err(|_| PublishError::Unknown)
    }
}

impl Drop for PreparedRecord {
    fn drop(&mut self) {
        unlink_if_owned(
            self.directory.as_raw_fd(),
            &self.temporary_leaf,
            self.identity,
        );
    }
}

enum PublishError {
    Before(PlatformError),
    Unknown,
}

fn validate_target_for_replace(parent: RawFd, leaf: &CStr) -> Result<(), PlatformError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent,
            leaf.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(error.into());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_uid != unsafe { libc::geteuid() }
        || (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
    {
        return Err(PlatformError::Corrupt("local_only_target_identity"));
    }
    Ok(())
}

fn validate_named_identity(
    parent: RawFd,
    leaf: &CStr,
    expected_identity: Option<(u64, u64)>,
) -> Result<(), PlatformError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            leaf.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_uid != unsafe { libc::geteuid() }
        || (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
        || expected_identity
            .is_some_and(|identity| identity != (stat.st_dev as u64, stat.st_ino as u64))
    {
        return Err(PlatformError::Corrupt("local_only_record_identity"));
    }
    Ok(())
}

fn verify_published(
    parent: RawFd,
    leaf: &CStr,
    identity: (u64, u64),
    expected: &[u8],
) -> Result<(), PlatformError> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    validate_private_file(&file, Some(identity))?;
    let mut actual = Vec::with_capacity(expected.len());
    file.read_to_end(&mut actual)?;
    if actual.len() != expected.len()
        || Sha256::digest(&actual).as_slice() != Sha256::digest(expected).as_slice()
    {
        return Err(PlatformError::Corrupt("local_only_published_verification"));
    }
    Ok(())
}

fn unlink_if_owned(parent: RawFd, leaf: &CStr, identity: (u64, u64)) {
    if validate_named_identity(parent, leaf, Some(identity)).is_ok() {
        unsafe {
            libc::unlinkat(parent, leaf.as_ptr(), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(enabled: bool, expected_revision: u64) -> SetLocalOnlyV1Request {
        SetLocalOnlyV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            enabled,
            expected_revision,
        }
    }

    fn seeded_store() -> (tempfile::TempDir, LocalOnlyModeStore) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let store = LocalOnlyModeStore::new(&paths);
        let seeded = store.set(&request(false, 0)).unwrap();
        assert_eq!(seeded.revision, 1);
        (temporary, store)
    }

    #[test]
    fn ambiguous_first_rename_with_old_durable_state_is_repairable_at_prior_revision() {
        let (_temporary, store) = seeded_store();
        store.inject_publication_fault(PublicationFault::BeforeRename(0));

        let uncertain = request(true, 1);
        assert!(matches!(
            store.set(&uncertain),
            Err(LocalOnlyStoreError::PublicationOutcomeUnknown)
        ));
        let durable = store.load();
        assert!(!durable.local_only);
        assert_eq!(durable.revision, 1);

        let repaired = store.set(&request(true, 1)).unwrap();
        assert!(repaired.local_only);
        assert_eq!(repaired.revision, 2);
    }

    #[test]
    fn ambiguous_partial_new_generations_are_fail_closed_and_same_process_repairable() {
        for fault in [
            PublicationFault::BeforeRename(1),
            PublicationFault::BeforeRename(2),
            PublicationFault::BeforeDirectorySync(0),
            PublicationFault::BeforeDirectorySync(1),
        ] {
            let (_temporary, store) = seeded_store();
            store.inject_publication_fault(fault);

            assert!(matches!(
                store.set(&request(true, 1)),
                Err(LocalOnlyStoreError::PublicationOutcomeUnknown)
            ));
            let ambiguous = store.load();
            assert!(ambiguous.local_only, "fault {fault:?}");
            assert_eq!(ambiguous.revision, 0, "fault {fault:?}");
            assert_eq!(
                ambiguous.authority_health,
                LocalOnlyAuthorityHealthV1::FailClosedDefault,
                "fault {fault:?}"
            );
            assert!(matches!(
                store.set(&request(true, 0)),
                Err(LocalOnlyStoreError::Platform(PlatformError::Conflict(
                    "local_only_stale_revision"
                )))
            ));

            let repaired = store.set(&request(true, 1)).unwrap();
            assert!(repaired.local_only, "fault {fault:?}");
            assert_eq!(repaired.revision, 2, "fault {fault:?}");
        }
    }

    #[test]
    fn ambiguous_acknowledgment_sync_with_complete_new_state_is_exactly_provable() {
        let (_temporary, store) = seeded_store();
        let uncertain = request(true, 1);
        store.inject_publication_fault(PublicationFault::BeforeDirectorySync(2));

        assert!(matches!(
            store.set(&uncertain),
            Err(LocalOnlyStoreError::PublicationOutcomeUnknown)
        ));
        let durable = store.load();
        assert!(durable.local_only);
        assert_eq!(durable.revision, 2);
        let proven = store.load_acknowledged_response(&uncertain).unwrap();
        assert_eq!(proven.revision, 2);
        assert_eq!(proven.request_id, uncertain.request_id);
    }
}
