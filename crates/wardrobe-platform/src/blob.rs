use crate::{PlatformError, PlatformResult, PrivateAppPaths};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use wardrobe_core::{BlobPort, BlobRecordV1, PortError, PortErrorKind, PortResult, Sha256Digest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobRecord {
    pub sha256: String,
    pub byte_length: u64,
    pub path: PathBuf,
    pub reused: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownLengthBlobLimits {
    pub max_blob_bytes: u64,
    pub max_run_bytes: u64,
    pub max_active_staging_bytes: u64,
    pub max_chunk_bytes: usize,
    pub reserve_free_bytes: u64,
}

impl UnknownLengthBlobLimits {
    pub const PHOTOKIT_V1: Self = Self {
        max_blob_bytes: 40 * 1024 * 1024,
        max_run_bytes: 512 * 1024 * 1024,
        max_active_staging_bytes: 80 * 1024 * 1024,
        max_chunk_bytes: 1024 * 1024,
        reserve_free_bytes: 2 * 1024 * 1024 * 1024,
    };

    fn validate(self) -> PlatformResult<Self> {
        if self.max_blob_bytes == 0
            || self.max_run_bytes < self.max_blob_bytes
            || self.max_active_staging_bytes < self.max_blob_bytes
            || self.max_chunk_bytes == 0
            || self.max_chunk_bytes as u64 > self.max_blob_bytes
        {
            return Err(PlatformError::InvalidInput("blob_stream_limits"));
        }
        Ok(self)
    }
}

#[derive(Debug, Default)]
struct UnknownLengthBudgetState {
    accepted_run_bytes: u64,
    active_hard_allowance: u64,
    active_staging_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct UnknownLengthBlobSession {
    limits: UnknownLengthBlobLimits,
    state: Arc<Mutex<UnknownLengthBudgetState>>,
}

impl UnknownLengthBlobSession {
    pub fn new(limits: UnknownLengthBlobLimits) -> PlatformResult<Self> {
        Ok(Self {
            limits: limits.validate()?,
            state: Arc::new(Mutex::new(UnknownLengthBudgetState::default())),
        })
    }

    pub fn accepted_run_bytes(&self) -> PlatformResult<u64> {
        Ok(self
            .state
            .lock()
            .map_err(|_| PlatformError::Conflict("blob_stream_budget_poisoned"))?
            .accepted_run_bytes)
    }
}

#[derive(Debug)]
struct UnknownLengthBudgetLease {
    session: UnknownLengthBlobSession,
    staged_bytes: u64,
    hard_allowance: u64,
}

impl UnknownLengthBudgetLease {
    fn reserve(session: &UnknownLengthBlobSession, staging: &Path) -> PlatformResult<Self> {
        let mut state = session
            .state
            .lock()
            .map_err(|_| PlatformError::Conflict("blob_stream_budget_poisoned"))?;
        let active = state
            .active_hard_allowance
            .checked_add(session.limits.max_blob_bytes)
            .ok_or(PlatformError::InvalidInput("blob_active_staging_limit"))?;
        if active > session.limits.max_active_staging_bytes {
            return Err(PlatformError::InvalidInput("blob_active_staging_limit"));
        }
        let remaining_allowance = active
            .checked_sub(state.active_staging_bytes)
            .ok_or(PlatformError::Corrupt("blob_stream_budget"))?;
        let required = session
            .limits
            .reserve_free_bytes
            .checked_add(remaining_allowance)
            .ok_or(PlatformError::InvalidInput("blob_free_space"))?;
        if available_bytes(staging)? < required {
            return Err(PlatformError::InvalidInput("blob_free_space"));
        }
        state.active_hard_allowance = active;
        Ok(Self {
            session: session.clone(),
            staged_bytes: 0,
            hard_allowance: session.limits.max_blob_bytes,
        })
    }

    fn accept(&mut self, staging: &Path, bytes: usize) -> PlatformResult<()> {
        if bytes > self.session.limits.max_chunk_bytes {
            return Err(PlatformError::InvalidInput("blob_chunk_too_large"));
        }
        let bytes =
            u64::try_from(bytes).map_err(|_| PlatformError::InvalidInput("blob_stream_length"))?;
        let mut state = self
            .session
            .state
            .lock()
            .map_err(|_| PlatformError::Conflict("blob_stream_budget_poisoned"))?;
        let resource_bytes = self
            .staged_bytes
            .checked_add(bytes)
            .ok_or(PlatformError::InvalidInput("blob_too_large"))?;
        let run_bytes = state
            .accepted_run_bytes
            .checked_add(bytes)
            .ok_or(PlatformError::InvalidInput("blob_run_too_large"))?;
        let active_staging = state
            .active_staging_bytes
            .checked_add(bytes)
            .ok_or(PlatformError::InvalidInput("blob_active_staging_limit"))?;
        if run_bytes > self.session.limits.max_run_bytes {
            return Err(PlatformError::InvalidInput("blob_run_too_large"));
        }
        if resource_bytes > self.session.limits.max_blob_bytes {
            return Err(PlatformError::InvalidInput("blob_too_large"));
        }
        if active_staging > self.session.limits.max_active_staging_bytes {
            return Err(PlatformError::InvalidInput("blob_active_staging_limit"));
        }
        let remaining_allowance = state
            .active_hard_allowance
            .checked_sub(state.active_staging_bytes)
            .ok_or(PlatformError::Corrupt("blob_stream_budget"))?;
        let required = self
            .session
            .limits
            .reserve_free_bytes
            .checked_add(remaining_allowance)
            .ok_or(PlatformError::InvalidInput("blob_free_space"))?;
        if available_bytes(staging)? < required {
            return Err(PlatformError::InvalidInput("blob_free_space"));
        }
        state.accepted_run_bytes = run_bytes;
        state.active_staging_bytes = active_staging;
        self.staged_bytes = resource_bytes;
        Ok(())
    }

    fn release_unused_hard_allowance(&mut self) -> PlatformResult<()> {
        let unused = self
            .hard_allowance
            .checked_sub(self.staged_bytes)
            .ok_or(PlatformError::Corrupt("blob_stream_budget"))?;
        let mut state = self
            .session
            .state
            .lock()
            .map_err(|_| PlatformError::Conflict("blob_stream_budget_poisoned"))?;
        state.active_hard_allowance = state
            .active_hard_allowance
            .checked_sub(unused)
            .ok_or(PlatformError::Corrupt("blob_stream_budget"))?;
        self.hard_allowance = self.staged_bytes;
        Ok(())
    }
}

impl Drop for UnknownLengthBudgetLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.session.state.lock() {
            state.active_hard_allowance = state
                .active_hard_allowance
                .saturating_sub(self.hard_allowance);
            state.active_staging_bytes =
                state.active_staging_bytes.saturating_sub(self.staged_bytes);
        }
    }
}

#[derive(Debug)]
pub struct UnknownLengthBlobSink {
    staging_path: PathBuf,
    staging_directory: PathBuf,
    file: Option<File>,
    digest: Sha256,
    lease: Option<UnknownLengthBudgetLease>,
}

impl UnknownLengthBlobSink {
    pub fn write_chunk(&mut self, bytes: &[u8]) -> PlatformResult<()> {
        self.lease
            .as_mut()
            .ok_or(PlatformError::Conflict("blob_stream_closed"))?
            .accept(&self.staging_directory, bytes.len())?;
        if let Err(error) = self
            .file
            .as_mut()
            .ok_or(PlatformError::Conflict("blob_stream_closed"))?
            .write_all(bytes)
        {
            let lease = self
                .lease
                .as_mut()
                .ok_or(PlatformError::Conflict("blob_stream_closed"))?;
            if let Ok(mut state) = lease.session.state.lock() {
                let bytes = bytes.len() as u64;
                state.accepted_run_bytes = state.accepted_run_bytes.saturating_sub(bytes);
                state.active_staging_bytes = state.active_staging_bytes.saturating_sub(bytes);
                lease.staged_bytes = lease.staged_bytes.saturating_sub(bytes);
            }
            return Err(error.into());
        }
        self.digest.update(bytes);
        Ok(())
    }

    pub fn accepted_bytes(&self) -> u64 {
        self.lease
            .as_ref()
            .map(|lease| lease.staged_bytes)
            .unwrap_or(0)
    }

    pub fn finish(mut self) -> PlatformResult<PreparedBlob> {
        let byte_length = self.accepted_bytes();
        if byte_length == 0 {
            return Err(PlatformError::InvalidInput("blob_stream_empty"));
        }
        let file = self
            .file
            .take()
            .ok_or(PlatformError::Conflict("blob_stream_closed"))?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.mode() & 0o077 != 0
            || metadata.len() != byte_length
        {
            return Err(PlatformError::Corrupt("blob_staging_identity"));
        }
        drop(file);
        sync_directory(&self.staging_directory)?;
        let sha256 = format!("{:x}", self.digest.clone().finalize());
        verify_staged(&self.staging_path, &sha256, byte_length)?;
        self.lease
            .as_mut()
            .ok_or(PlatformError::Conflict("blob_stream_closed"))?
            .release_unused_hard_allowance()?;
        let staging_path = std::mem::take(&mut self.staging_path);
        Ok(PreparedBlob {
            staging_path: Some(staging_path),
            staging_directory: self.staging_directory.clone(),
            sha256,
            byte_length,
            lease: self.lease.take(),
        })
    }
}

impl Drop for UnknownLengthBlobSink {
    fn drop(&mut self) {
        self.file.take();
        match fs::remove_file(&self.staging_path) {
            Ok(()) => {
                let _ = sync_directory(&self.staging_directory);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
}

#[derive(Debug)]
pub struct PreparedBlob {
    staging_path: Option<PathBuf>,
    staging_directory: PathBuf,
    sha256: String,
    byte_length: u64,
    lease: Option<UnknownLengthBudgetLease>,
}

impl PreparedBlob {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn open_read_only(&self) -> PlatformResult<File> {
        let path = self
            .staging_path
            .as_ref()
            .ok_or(PlatformError::Conflict("blob_staging_promoted"))?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.len() != self.byte_length
            || metadata.mode() & 0o077 != 0
        {
            return Err(PlatformError::Corrupt("blob_staging_identity"));
        }
        Ok(file)
    }
}

impl Drop for PreparedBlob {
    fn drop(&mut self) {
        if let Some(path) = self.staging_path.take() {
            match fs::remove_file(path) {
                Ok(()) => {
                    let _ = sync_directory(&self.staging_directory);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {}
            }
        }
        self.lease.take();
    }
}

impl BlobPort for BlobStore {
    fn put_verified(
        &self,
        expected_digest: &Sha256Digest,
        bytes: &[u8],
        max_bytes: u64,
    ) -> PortResult<BlobRecordV1> {
        let record = self
            .put(bytes, Some(expected_digest.as_str()), max_bytes)
            .map_err(port_error)?;
        Ok(BlobRecordV1 {
            digest: Sha256Digest::parse(record.sha256)
                .map_err(|_| PortError::new(PortErrorKind::DataIntegrity))?,
            byte_length: record.byte_length,
        })
    }

    fn verify(&self, expected: &BlobRecordV1) -> PortResult<()> {
        let actual = self.verify(expected.digest.as_str()).map_err(port_error)?;
        if actual.byte_length != expected.byte_length {
            return Err(PortError::new(PortErrorKind::DataIntegrity));
        }
        Ok(())
    }
}

fn port_error(error: PlatformError) -> PortError {
    let kind = match error {
        PlatformError::Conflict(_) => PortErrorKind::Conflict,
        PlatformError::Corrupt(_) => PortErrorKind::DataIntegrity,
        PlatformError::InvalidInput(_) => PortErrorKind::Conflict,
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PortErrorKind::NotFound
        }
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            PortErrorKind::PermissionDenied
        }
        PlatformError::Io(_) => PortErrorKind::Unavailable,
        _ => PortErrorKind::Internal,
    };
    PortError::new(kind)
}

#[derive(Clone, Debug)]
pub struct BlobStore {
    root: PathBuf,
    staging: PathBuf,
}

impl BlobStore {
    pub fn new(paths: &PrivateAppPaths) -> Self {
        Self {
            root: paths.blobs.clone(),
            staging: paths.staging.clone(),
        }
    }

    pub fn put(
        &self,
        bytes: &[u8],
        expected_sha256: Option<&str>,
        max_bytes: u64,
    ) -> PlatformResult<BlobRecord> {
        if bytes.len() as u64 > max_bytes {
            return Err(PlatformError::InvalidInput("blob_too_large"));
        }
        let hash = hex_digest(bytes);
        if expected_sha256.is_some_and(|expected| expected != hash) {
            return Err(PlatformError::Corrupt("blob_expected_hash_mismatch"));
        }

        let destination = self.path_for_hash(&hash)?;
        let parent = destination
            .parent()
            .ok_or(PlatformError::Corrupt("blob_destination_parent"))?;
        create_private_directory(parent)?;

        let staging_path = self.staging.join(format!("{}.part", Uuid::new_v4()));
        let result = self.put_staged(bytes, &hash, &staging_path, &destination);
        if result.is_err() {
            let _ = fs::remove_file(&staging_path);
        }
        result
    }

    pub fn put_reader<R: Read>(
        &self,
        reader: &mut R,
        expected_length: u64,
        max_bytes: u64,
    ) -> PlatformResult<BlobRecord> {
        if expected_length > max_bytes {
            return Err(PlatformError::InvalidInput("blob_too_large"));
        }
        let staging_path = self.staging.join(format!("{}.part", Uuid::new_v4()));
        let result = (|| {
            let mut staging = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&staging_path)?;
            let mut digest = Sha256::new();
            let mut copied = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                copied = copied
                    .checked_add(read as u64)
                    .ok_or(PlatformError::InvalidInput("blob_too_large"))?;
                if copied > max_bytes || copied > expected_length {
                    return Err(PlatformError::InvalidInput("blob_stream_length"));
                }
                digest.update(&buffer[..read]);
                staging.write_all(&buffer[..read])?;
            }
            if copied != expected_length {
                return Err(PlatformError::InvalidInput("blob_stream_length"));
            }
            staging.sync_all()?;
            drop(staging);

            let hash = format!("{:x}", digest.finalize());
            let destination = self.path_for_hash(&hash)?;
            let parent = destination
                .parent()
                .ok_or(PlatformError::Corrupt("blob_destination_parent"))?;
            create_private_directory(parent)?;
            self.promote_staged(&hash, copied, &staging_path, &destination)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&staging_path);
        }
        result
    }

    pub fn begin_unknown_length(
        &self,
        session: &UnknownLengthBlobSession,
    ) -> PlatformResult<UnknownLengthBlobSink> {
        let lease = UnknownLengthBudgetLease::reserve(session, &self.staging)?;
        let staging_path = self.staging.join(format!("{}.part", Uuid::new_v4()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&staging_path)?;
        Ok(UnknownLengthBlobSink {
            staging_path,
            staging_directory: self.staging.clone(),
            file: Some(file),
            digest: Sha256::new(),
            lease: Some(lease),
        })
    }

    pub fn promote_prepared(&self, mut prepared: PreparedBlob) -> PlatformResult<BlobRecord> {
        let staging_path = prepared
            .staging_path
            .as_ref()
            .ok_or(PlatformError::Conflict("blob_staging_promoted"))?;
        verify_staged(staging_path, &prepared.sha256, prepared.byte_length)?;
        let destination = self.path_for_hash(&prepared.sha256)?;
        let parent = destination
            .parent()
            .ok_or(PlatformError::Corrupt("blob_destination_parent"))?;
        create_private_directory(parent)?;
        let record = self.promote_staged(
            &prepared.sha256,
            prepared.byte_length,
            staging_path,
            &destination,
        )?;
        prepared.staging_path.take();
        prepared.lease.take();
        Ok(record)
    }

    pub fn verify(&self, sha256: &str) -> PlatformResult<BlobRecord> {
        let path = self.path_for_hash(sha256)?;
        verify_final(&path, sha256, None).map(|byte_length| BlobRecord {
            sha256: sha256.to_owned(),
            byte_length,
            path,
            reused: true,
        })
    }

    pub fn path_for_hash(&self, sha256: &str) -> PlatformResult<PathBuf> {
        validate_hash(sha256)?;
        Ok(self
            .root
            .join(&sha256[0..2])
            .join(&sha256[2..4])
            .join(sha256))
    }

    fn put_staged(
        &self,
        bytes: &[u8],
        hash: &str,
        staging_path: &Path,
        destination: &Path,
    ) -> PlatformResult<BlobRecord> {
        let mut staging = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(staging_path)?;
        staging.write_all(bytes)?;
        staging.sync_all()?;
        drop(staging);

        self.promote_staged(hash, bytes.len() as u64, staging_path, destination)
    }

    fn promote_staged(
        &self,
        hash: &str,
        expected_length: u64,
        staging_path: &Path,
        destination: &Path,
    ) -> PlatformResult<BlobRecord> {
        let reused = match fs::hard_link(staging_path, destination) {
            Ok(()) => false,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => true,
            Err(error) => return Err(error.into()),
        };

        fs::remove_file(staging_path)?;
        sync_directory(&self.staging)?;
        let byte_length = verify_final(destination, hash, Some(expected_length))?;
        sync_directory(
            destination
                .parent()
                .ok_or(PlatformError::Corrupt("blob_destination_parent"))?,
        )?;

        Ok(BlobRecord {
            sha256: hash.to_owned(),
            byte_length,
            path: destination.to_path_buf(),
            reused,
        })
    }
}

fn available_bytes(path: &Path) -> PlatformResult<u64> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| PlatformError::InvalidInput("blob_staging_path"))?;
    let mut value = MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let value = unsafe { value.assume_init() };
    (value.f_bavail as u64)
        .checked_mul(value.f_frsize as u64)
        .ok_or(PlatformError::Corrupt("blob_free_space"))
}

fn verify_staged(path: &Path, expected_hash: &str, expected_length: u64) -> PlatformResult<()> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() != expected_length
    {
        return Err(PlatformError::Corrupt("blob_staging_identity"));
    }
    let mut digest = Sha256::new();
    let copied = std::io::copy(&mut file, &mut digest)?;
    if copied != expected_length || format!("{:x}", digest.finalize()) != expected_hash {
        return Err(PlatformError::Corrupt("blob_staging_hash"));
    }
    Ok(())
}

fn validate_hash(hash: &str) -> PlatformResult<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlatformError::InvalidInput("sha256"));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn verify_final(
    path: &Path,
    expected_hash: &str,
    expected_length: Option<u64>,
) -> PlatformResult<u64> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(PlatformError::Corrupt("blob_final_identity"));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(PlatformError::Corrupt("blob_final_permissions"));
    }
    if expected_length.is_some_and(|length| length != metadata.len()) {
        return Err(PlatformError::Corrupt("blob_final_length"));
    }

    let mut digest = Sha256::new();
    let copied = std::io::copy(&mut file, &mut digest)?;
    if copied != metadata.len() || format!("{:x}", digest.finalize()) != expected_hash {
        return Err(PlatformError::Corrupt("blob_final_hash"));
    }
    Ok(metadata.len())
}

fn create_private_directory(path: &Path) -> PlatformResult<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(crate) fn sync_directory(path: &Path) -> PlatformResult<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn promotes_reuses_and_reverifies_without_staging_alias() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let store = BlobStore::new(&paths);
        let bytes = b"production storage check";
        let hash = hex_digest(bytes);

        let first = store.put(bytes, Some(&hash), 1024).unwrap();
        assert!(!first.reused);
        assert_eq!(fs::metadata(&first.path).unwrap().nlink(), 1);
        assert_eq!(fs::read_dir(&paths.staging).unwrap().count(), 0);

        let second = store.put(bytes, Some(&hash), 1024).unwrap();
        assert!(second.reused);
        assert_eq!(first.path, second.path);
        assert_eq!(store.verify(&hash).unwrap().byte_length, bytes.len() as u64);
    }

    #[test]
    fn rejects_mismatch_and_corrupt_existing_destination() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let store = BlobStore::new(&paths);
        assert!(matches!(
            store.put(b"bytes", Some(&"0".repeat(64)), 100),
            Err(PlatformError::Corrupt("blob_expected_hash_mismatch"))
        ));

        let record = store.put(b"bytes", None, 100).unwrap();
        fs::set_permissions(&record.path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&record.path, b"changed").unwrap();
        assert!(matches!(
            store.verify(&record.sha256),
            Err(PlatformError::Corrupt("blob_final_hash"))
                | Err(PlatformError::Corrupt("blob_final_length"))
        ));
    }

    #[test]
    fn unknown_length_stream_enforces_bounds_and_promotes_duplicate_content() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let store = BlobStore::new(&paths);
        let limits = UnknownLengthBlobLimits {
            max_blob_bytes: 8,
            max_run_bytes: 16,
            max_active_staging_bytes: 16,
            max_chunk_bytes: 4,
            reserve_free_bytes: 0,
        };
        let session = UnknownLengthBlobSession::new(limits).unwrap();

        let mut first = store.begin_unknown_length(&session).unwrap();
        first.write_chunk(b"1234").unwrap();
        first.write_chunk(b"5678").unwrap();
        assert!(matches!(
            first.write_chunk(b"x"),
            Err(PlatformError::InvalidInput("blob_too_large"))
        ));
        let prepared = first.finish().unwrap();
        assert_eq!(prepared.byte_length(), 8);
        assert_eq!(
            prepared.open_read_only().unwrap().metadata().unwrap().len(),
            8
        );
        let first = store.promote_prepared(prepared).unwrap();
        assert!(!first.reused);

        let mut duplicate = store.begin_unknown_length(&session).unwrap();
        duplicate.write_chunk(b"1234").unwrap();
        duplicate.write_chunk(b"5678").unwrap();
        let duplicate = store.promote_prepared(duplicate.finish().unwrap()).unwrap();
        assert!(duplicate.reused);
        assert_eq!(duplicate.sha256, first.sha256);
        assert_eq!(session.accepted_run_bytes().unwrap(), 16);
        assert_eq!(fs::read_dir(&paths.staging).unwrap().count(), 0);
    }

    #[test]
    fn unknown_length_stream_reserves_hard_allowance_and_cleans_on_drop() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let store = BlobStore::new(&paths);
        let session = UnknownLengthBlobSession::new(UnknownLengthBlobLimits {
            max_blob_bytes: 8,
            max_run_bytes: 12,
            max_active_staging_bytes: 8,
            max_chunk_bytes: 4,
            reserve_free_bytes: 0,
        })
        .unwrap();

        let mut active = store.begin_unknown_length(&session).unwrap();
        assert!(matches!(
            store.begin_unknown_length(&session),
            Err(PlatformError::InvalidInput("blob_active_staging_limit"))
        ));
        assert!(matches!(
            active.write_chunk(b"12345"),
            Err(PlatformError::InvalidInput("blob_chunk_too_large"))
        ));
        active.write_chunk(b"1234").unwrap();
        drop(active);
        assert_eq!(fs::read_dir(&paths.staging).unwrap().count(), 0);

        let mut replacement = store.begin_unknown_length(&session).unwrap();
        replacement.write_chunk(b"5678").unwrap();
        replacement.write_chunk(b"9012").unwrap();
        assert!(matches!(
            replacement.write_chunk(b"x"),
            Err(PlatformError::InvalidInput("blob_run_too_large"))
        ));
        drop(replacement);
        assert_eq!(fs::read_dir(&paths.staging).unwrap().count(), 0);
    }

    #[test]
    fn prepared_blobs_release_unused_allowance_and_retain_staged_accounting() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let store = BlobStore::new(&paths);
        let session = UnknownLengthBlobSession::new(UnknownLengthBlobLimits {
            max_blob_bytes: 8,
            max_run_bytes: 32,
            max_active_staging_bytes: 16,
            max_chunk_bytes: 4,
            reserve_free_bytes: 0,
        })
        .unwrap();

        let mut prepared = Vec::new();
        for byte in [b'a', b'b', b'c'] {
            let mut sink = store.begin_unknown_length(&session).unwrap();
            sink.write_chunk(&[byte; 4]).unwrap();
            prepared.push(sink.finish().unwrap());

            let state = session.state.lock().unwrap();
            let staged = prepared.len() as u64 * 4;
            assert_eq!(state.active_hard_allowance, staged);
            assert_eq!(state.active_staging_bytes, staged);
        }
        assert_eq!(fs::read_dir(&paths.staging).unwrap().count(), 3);
        assert!(matches!(
            store.begin_unknown_length(&session),
            Err(PlatformError::InvalidInput("blob_active_staging_limit"))
        ));

        store.promote_prepared(prepared.remove(0)).unwrap();
        {
            let state = session.state.lock().unwrap();
            assert_eq!(state.active_hard_allowance, 8);
            assert_eq!(state.active_staging_bytes, 8);
        }

        let mut replacement = store.begin_unknown_length(&session).unwrap();
        replacement.write_chunk(b"dddd").unwrap();
        prepared.push(replacement.finish().unwrap());
        drop(prepared);

        let state = session.state.lock().unwrap();
        assert_eq!(state.active_hard_allowance, 0);
        assert_eq!(state.active_staging_bytes, 0);
        assert_eq!(state.accepted_run_bytes, 16);
        assert_eq!(fs::read_dir(&paths.staging).unwrap().count(), 0);
    }
}
