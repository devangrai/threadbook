use crate::contracts::{MaterializationLimits, ResourceDescriptorV1};
use image::ImageFormat;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const HEADER_INSPECTION_LIMIT: usize = 1024 * 1024;

#[derive(Debug)]
pub struct FileStore {
    root_path: PathBuf,
    root: File,
    staging: File,
    blobs: File,
    root_device: u64,
    limits: MaterializationLimits,
    staging_budget: Arc<Mutex<u64>>,
    remaining_transfer_bytes: Arc<Mutex<u64>>,
}

#[derive(Debug)]
pub struct StagedAsset {
    operation: String,
    filename: String,
    directory: File,
    file: File,
    bytes_written: u64,
    hasher: Sha256,
    max_bytes: u64,
    budget: StagingBudgetLease,
    free_space: RemainingTransferLease,
}

#[derive(Debug)]
pub struct ValidatedAsset {
    operation: String,
    filename: String,
    directory: File,
    file: File,
    device: u64,
    inode: u64,
    _budget: StagingBudgetLease,
    pub sha256: String,
    pub byte_count: u64,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

#[derive(Debug)]
pub struct PromotedBlob {
    destination: File,
    device: u64,
    inode: u64,
    pub sha256: String,
    pub byte_count: u64,
    pub relative_path: String,
    pub reused_existing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileStoreError {
    InvalidComponent,
    SymlinkOrType,
    HardLink,
    DeviceChanged,
    AlreadyExists,
    ByteLimit,
    BatchLimit,
    StagingLimit,
    FreeSpace,
    EmptyFile,
    UnsupportedImage,
    ImageBounds,
    AnimatedImage,
    DescriptorMismatch,
    HashCollision,
    IdentityMismatch,
    Io,
}

impl fmt::Display for FileStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "materialization file failure: {}", self.code())
    }
}

impl Error for FileStoreError {}

impl FileStoreError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidComponent => "invalid_component",
            Self::SymlinkOrType => "symlink_or_type",
            Self::HardLink => "hard_link",
            Self::DeviceChanged => "device_changed",
            Self::AlreadyExists => "already_exists",
            Self::ByteLimit => "byte_limit",
            Self::BatchLimit => "batch_limit",
            Self::StagingLimit => "staging_limit",
            Self::FreeSpace => "free_space",
            Self::EmptyFile => "empty_file",
            Self::UnsupportedImage => "unsupported_image",
            Self::ImageBounds => "image_bounds",
            Self::AnimatedImage => "animated_image",
            Self::DescriptorMismatch => "descriptor_mismatch",
            Self::HashCollision => "hash_collision",
            Self::IdentityMismatch => "identity_mismatch",
            Self::Io => "io",
        }
    }
}

impl FileStore {
    pub fn open(
        root_path: impl AsRef<Path>,
        limits: MaterializationLimits,
    ) -> Result<Self, FileStoreError> {
        Self::open_with_expected_device(root_path, limits, None)
    }

    pub fn open_with_expected_device(
        root_path: impl AsRef<Path>,
        limits: MaterializationLimits,
        expected_device: Option<u64>,
    ) -> Result<Self, FileStoreError> {
        let root_path = root_path.as_ref().to_path_buf();
        fs::create_dir_all(&root_path).map_err(|_| FileStoreError::Io)?;
        fs::set_permissions(
            &root_path,
            fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
        )
        .map_err(|_| FileStoreError::Io)?;
        let root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&root_path)
            .map_err(|_| FileStoreError::Io)?;
        let root_metadata = root.metadata().map_err(|_| FileStoreError::Io)?;
        ensure_private_directory(&root_metadata)?;
        let root_device = root_metadata.dev();
        if expected_device.is_some_and(|expected| expected != root_device) {
            return Err(FileStoreError::DeviceChanged);
        }
        let staging = create_or_open_directory(root.as_raw_fd(), "staging", root_device)?;
        let blobs = create_or_open_directory(root.as_raw_fd(), "blobs", root_device)?;
        Ok(Self {
            root_path,
            root,
            staging,
            blobs,
            root_device,
            limits,
            staging_budget: Arc::new(Mutex::new(0)),
            remaining_transfer_bytes: Arc::new(Mutex::new(0)),
        })
    }

    pub fn begin(
        &self,
        operation: &str,
        filename: &str,
        max_bytes: u64,
    ) -> Result<StagedAsset, FileStoreError> {
        validate_component(operation)?;
        validate_component(filename)?;
        if max_bytes == 0 || max_bytes > self.limits.max_resource_bytes {
            return Err(FileStoreError::ByteLimit);
        }
        self.verify_roots()?;
        let free_space = RemainingTransferLease::reserve(
            self.root.try_clone().map_err(|_| FileStoreError::Io)?,
            Arc::clone(&self.remaining_transfer_bytes),
            self.limits.reserve_free_bytes,
            max_bytes,
        )?;
        let directory =
            create_or_open_directory(self.staging.as_raw_fd(), operation, self.root_device)?;
        let file = create_exclusive_file(directory.as_raw_fd(), filename)?;
        let metadata = file.metadata().map_err(|_| FileStoreError::Io)?;
        ensure_staged_file(&metadata, self.root_device)?;
        Ok(StagedAsset {
            operation: operation.to_owned(),
            filename: filename.to_owned(),
            directory,
            file,
            bytes_written: 0,
            hasher: Sha256::new(),
            max_bytes,
            budget: StagingBudgetLease {
                active_bytes: Arc::clone(&self.staging_budget),
                bytes: 0,
                maximum: self.limits.max_active_staging_bytes,
            },
            free_space,
        })
    }

    pub fn validate(
        &self,
        mut staged: StagedAsset,
        descriptor: &ResourceDescriptorV1,
    ) -> Result<ValidatedAsset, FileStoreError> {
        staged.file.flush().map_err(|_| FileStoreError::Io)?;
        staged.file.sync_all().map_err(|_| FileStoreError::Io)?;
        staged
            .directory
            .sync_all()
            .map_err(|_| FileStoreError::Io)?;
        if staged.bytes_written == 0 {
            return Err(FileStoreError::EmptyFile);
        }
        descriptor
            .validate(self.limits)
            .map_err(|_| FileStoreError::ImageBounds)?;
        staged
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| FileStoreError::Io)?;
        let mut header = vec![
            0;
            usize::try_from(staged.bytes_written)
                .unwrap_or(usize::MAX)
                .min(HEADER_INSPECTION_LIMIT)
        ];
        staged
            .file
            .read_exact(&mut header)
            .map_err(|_| FileStoreError::Io)?;
        let format = inspect_header(&header, descriptor)?;
        staged
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| FileStoreError::Io)?;
        let reader = image::ImageReader::with_format(BufReader::new(&mut staged.file), format);
        let (width, height) = reader
            .into_dimensions()
            .map_err(|_| FileStoreError::UnsupportedImage)?;
        validate_dimensions(width, height, descriptor, self.limits)?;
        staged
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| FileStoreError::Io)?;
        let decoded = image::load(BufReader::new(&mut staged.file), format)
            .map_err(|_| FileStoreError::UnsupportedImage)?;
        if decoded.width() != width || decoded.height() != height {
            return Err(FileStoreError::DescriptorMismatch);
        }
        let metadata = staged.file.metadata().map_err(|_| FileStoreError::Io)?;
        ensure_staged_file(&metadata, self.root_device)?;
        let streamed_hash = encode_digest(staged.hasher.finalize());
        let sha256 = sha256_file_descriptor(&staged.file)?;
        if streamed_hash != sha256 || metadata.len() != staged.bytes_written {
            return Err(FileStoreError::DescriptorMismatch);
        }
        Ok(ValidatedAsset {
            operation: staged.operation,
            filename: staged.filename,
            directory: staged.directory,
            file: staged.file,
            device: metadata.dev(),
            inode: metadata.ino(),
            _budget: staged.budget,
            sha256,
            byte_count: staged.bytes_written,
            pixel_width: width,
            pixel_height: height,
        })
    }

    pub fn promote(&self, asset: &ValidatedAsset) -> Result<PromotedBlob, FileStoreError> {
        validate_component(&asset.operation)?;
        validate_component(&asset.filename)?;
        validate_hash(&asset.sha256)?;
        self.verify_roots()?;
        let metadata = asset.file.metadata().map_err(|_| FileStoreError::Io)?;
        if metadata.nlink() != 1 {
            return Err(FileStoreError::HardLink);
        }
        if metadata.dev() != asset.device
            || metadata.ino() != asset.inode
            || metadata.len() != asset.byte_count
            || sha256_file_descriptor(&asset.file)? != asset.sha256
        {
            return Err(FileStoreError::DescriptorMismatch);
        }

        let source = cstring(&asset.filename)?;
        let destination = cstring(&asset.sha256)?;
        let linked = unsafe {
            libc::linkat(
                asset.directory.as_raw_fd(),
                source.as_ptr(),
                self.blobs.as_raw_fd(),
                destination.as_ptr(),
                0,
            )
        };
        let (destination_file, reused_existing) = if linked == 0 {
            let promoted =
                match open_regular(self.blobs.as_raw_fd(), &asset.sha256, self.root_device) {
                    Ok(file) => file,
                    Err(_) => return Err(FileStoreError::IdentityMismatch),
                };
            let source_matches = path_matches_identity(
                asset.directory.as_raw_fd(),
                &asset.filename,
                asset.device,
                asset.inode,
            )
            .unwrap_or(false);
            if verify_identity_and_content(
                &promoted,
                asset.device,
                asset.inode,
                asset.byte_count,
                &asset.sha256,
            )
            .is_err()
                || !source_matches
            {
                return Err(FileStoreError::IdentityMismatch);
            }
            (promoted, false)
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(FileStoreError::Io);
            }
            let existing = open_regular(self.blobs.as_raw_fd(), &asset.sha256, self.root_device)?;
            let metadata = existing.metadata().map_err(|_| FileStoreError::Io)?;
            if metadata.len() != asset.byte_count
                || sha256_file_descriptor(&existing)? != asset.sha256
            {
                return Err(FileStoreError::HashCollision);
            }
            if !path_matches_identity(
                asset.directory.as_raw_fd(),
                &asset.filename,
                asset.device,
                asset.inode,
            )? {
                return Err(FileStoreError::IdentityMismatch);
            }
            (existing, true)
        };
        self.blobs.sync_all().map_err(|_| FileStoreError::Io)?;
        let destination_metadata = destination_file
            .metadata()
            .map_err(|_| FileStoreError::Io)?;
        Ok(PromotedBlob {
            destination: destination_file,
            device: destination_metadata.dev(),
            inode: destination_metadata.ino(),
            sha256: asset.sha256.clone(),
            byte_count: asset.byte_count,
            relative_path: format!("blobs/{}", asset.sha256),
            reused_existing,
        })
    }

    pub fn verify_promoted(&self, blob: &PromotedBlob) -> Result<(), FileStoreError> {
        if verify_identity_and_content(
            &blob.destination,
            blob.device,
            blob.inode,
            blob.byte_count,
            &blob.sha256,
        )
        .is_err()
        {
            return Err(FileStoreError::IdentityMismatch);
        }
        let current = match open_regular(self.blobs.as_raw_fd(), &blob.sha256, self.root_device) {
            Ok(file) => file,
            Err(_) => return Err(FileStoreError::IdentityMismatch),
        };
        if verify_identity_and_content(
            &current,
            blob.device,
            blob.inode,
            blob.byte_count,
            &blob.sha256,
        )
        .is_err()
        {
            return Err(FileStoreError::IdentityMismatch);
        }
        Ok(())
    }

    pub fn root_device(&self) -> u64 {
        self.root_device
    }

    pub fn blob_path(&self, hash: &str) -> Result<PathBuf, FileStoreError> {
        validate_hash(hash)?;
        Ok(self.root_path.join("blobs").join(hash))
    }

    pub fn verify_blob(&self, hash: &str, length: u64) -> Result<(), FileStoreError> {
        validate_hash(hash)?;
        let file = open_regular(self.blobs.as_raw_fd(), hash, self.root_device)?;
        let metadata = file.metadata().map_err(|_| FileStoreError::Io)?;
        if metadata.len() != length || sha256_file_descriptor(&file)? != hash {
            return Err(FileStoreError::HashCollision);
        }
        Ok(())
    }

    fn verify_roots(&self) -> Result<(), FileStoreError> {
        for directory in [&self.root, &self.staging, &self.blobs] {
            let metadata = directory.metadata().map_err(|_| FileStoreError::Io)?;
            ensure_private_directory(&metadata)?;
            if metadata.dev() != self.root_device {
                return Err(FileStoreError::DeviceChanged);
            }
        }
        Ok(())
    }
}

impl StagedAsset {
    pub fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), FileStoreError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if bytes.len() > crate::contracts::MAX_CALLBACK_CHUNK_BYTES {
            return Err(FileStoreError::ByteLimit);
        }
        let next = self
            .bytes_written
            .checked_add(u64::try_from(bytes.len()).map_err(|_| FileStoreError::ByteLimit)?)
            .ok_or(FileStoreError::ByteLimit)?;
        if next > self.max_bytes {
            return Err(FileStoreError::ByteLimit);
        }
        self.free_space.require_available()?;
        self.budget.reserve(bytes.len() as u64)?;
        if self.file.write_all(bytes).is_err() {
            self.budget.release(bytes.len() as u64);
            return Err(FileStoreError::Io);
        }
        self.free_space.consume(bytes.len() as u64);
        self.hasher.update(bytes);
        self.bytes_written = next;
        Ok(())
    }

    pub fn byte_count(&self) -> u64 {
        self.bytes_written
    }
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String, FileStoreError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| FileStoreError::Io)?;
    let metadata = file.metadata().map_err(|_| FileStoreError::Io)?;
    if !metadata.is_file() {
        return Err(FileStoreError::SymlinkOrType);
    }
    sha256_file_descriptor(&file)
}

#[derive(Debug)]
struct StagingBudgetLease {
    active_bytes: Arc<Mutex<u64>>,
    bytes: u64,
    maximum: u64,
}

impl StagingBudgetLease {
    fn reserve(&mut self, bytes: u64) -> Result<(), FileStoreError> {
        let mut active = self.active_bytes.lock().map_err(|_| FileStoreError::Io)?;
        let next = active
            .checked_add(bytes)
            .ok_or(FileStoreError::StagingLimit)?;
        if next > self.maximum {
            return Err(FileStoreError::StagingLimit);
        }
        *active = next;
        self.bytes += bytes;
        Ok(())
    }

    fn release(&mut self, bytes: u64) {
        if let Ok(mut active) = self.active_bytes.lock() {
            *active = active.saturating_sub(bytes);
            self.bytes = self.bytes.saturating_sub(bytes);
        }
    }
}

impl Drop for StagingBudgetLease {
    fn drop(&mut self) {
        self.release(self.bytes);
    }
}

#[derive(Debug)]
struct RemainingTransferLease {
    root: File,
    reserved_bytes: Arc<Mutex<u64>>,
    bytes: u64,
    reserve_free_bytes: u64,
}

impl RemainingTransferLease {
    fn reserve(
        root: File,
        reserved_bytes: Arc<Mutex<u64>>,
        reserve_free_bytes: u64,
        bytes: u64,
    ) -> Result<Self, FileStoreError> {
        let mut reserved = reserved_bytes.lock().map_err(|_| FileStoreError::Io)?;
        let required_transfer_bytes = reserved
            .checked_add(bytes)
            .ok_or(FileStoreError::FreeSpace)?;
        require_available_space(&root, reserve_free_bytes, required_transfer_bytes)?;
        *reserved = required_transfer_bytes;
        drop(reserved);
        Ok(Self {
            root,
            reserved_bytes,
            bytes,
            reserve_free_bytes,
        })
    }

    fn require_available(&self) -> Result<(), FileStoreError> {
        let reserved = self.reserved_bytes.lock().map_err(|_| FileStoreError::Io)?;
        require_available_space(&self.root, self.reserve_free_bytes, *reserved)
    }

    fn consume(&mut self, bytes: u64) {
        if let Ok(mut reserved) = self.reserved_bytes.lock() {
            *reserved = reserved.saturating_sub(bytes);
            self.bytes = self.bytes.saturating_sub(bytes);
        }
    }
}

impl Drop for RemainingTransferLease {
    fn drop(&mut self) {
        self.consume(self.bytes);
    }
}

fn inspect_header(
    header: &[u8],
    descriptor: &ResourceDescriptorV1,
) -> Result<ImageFormat, FileStoreError> {
    let format = image::guess_format(header).map_err(|_| FileStoreError::UnsupportedImage)?;
    match (descriptor.uniform_type_identifier.as_str(), format) {
        ("public.png", ImageFormat::Png) => {
            if header.windows(4).any(|window| window == b"acTL") {
                return Err(FileStoreError::AnimatedImage);
            }
            Ok(format)
        }
        ("public.jpeg", ImageFormat::Jpeg) => Ok(format),
        _ => Err(FileStoreError::DescriptorMismatch),
    }
}

fn validate_dimensions(
    width: u32,
    height: u32,
    descriptor: &ResourceDescriptorV1,
    limits: MaterializationLimits,
) -> Result<(), FileStoreError> {
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(FileStoreError::ImageBounds)?;
    let allocation = pixels.checked_mul(4).ok_or(FileStoreError::ImageBounds)?;
    if width == 0
        || height == 0
        || pixels > limits.max_pixels
        || allocation > limits.max_decode_allocation_bytes
    {
        return Err(FileStoreError::ImageBounds);
    }
    if width != descriptor.pixel_width || height != descriptor.pixel_height {
        return Err(FileStoreError::DescriptorMismatch);
    }
    Ok(())
}

fn ensure_private_directory(metadata: &fs::Metadata) -> Result<(), FileStoreError> {
    if !metadata.is_dir() {
        return Err(FileStoreError::SymlinkOrType);
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(FileStoreError::SymlinkOrType);
    }
    Ok(())
}

fn ensure_staged_file(metadata: &fs::Metadata, device: u64) -> Result<(), FileStoreError> {
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        return Err(FileStoreError::SymlinkOrType);
    }
    if metadata.nlink() != 1 {
        return Err(FileStoreError::HardLink);
    }
    if metadata.dev() != device {
        return Err(FileStoreError::DeviceChanged);
    }
    Ok(())
}

fn create_or_open_directory(
    parent: RawFd,
    name: &str,
    device: u64,
) -> Result<File, FileStoreError> {
    validate_component(name)?;
    let name = cstring(name)?;
    let result = unsafe {
        libc::mkdirat(
            parent,
            name.as_ptr(),
            PRIVATE_DIRECTORY_MODE as libc::mode_t,
        )
    };
    if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        return Err(FileStoreError::Io);
    }
    let directory = open_directory_raw(parent, &name)?;
    let metadata = directory.metadata().map_err(|_| FileStoreError::Io)?;
    ensure_private_directory(&metadata)?;
    if metadata.dev() != device {
        return Err(FileStoreError::DeviceChanged);
    }
    Ok(directory)
}

fn open_directory_raw(parent: RawFd, name: &CString) -> Result<File, FileStoreError> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(FileStoreError::Io);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn create_exclusive_file(parent: RawFd, name: &str) -> Result<File, FileStoreError> {
    let name = cstring(name)?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_RDWR,
            PRIVATE_FILE_MODE as libc::c_uint,
        )
    };
    if fd < 0 {
        return match io::Error::last_os_error().raw_os_error() {
            Some(libc::EEXIST) => Err(FileStoreError::AlreadyExists),
            Some(libc::ELOOP) => Err(FileStoreError::SymlinkOrType),
            _ => Err(FileStoreError::Io),
        };
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_regular(parent: RawFd, name: &str, device: u64) -> Result<File, FileStoreError> {
    validate_component(name)?;
    let name = cstring(name)?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(FileStoreError::Io);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|_| FileStoreError::Io)?;
    if !metadata.is_file() {
        return Err(FileStoreError::SymlinkOrType);
    }
    if metadata.dev() != device {
        return Err(FileStoreError::DeviceChanged);
    }
    Ok(file)
}

fn sha256_file_descriptor(file: &File) -> Result<String, FileStoreError> {
    let mut reader = file.try_clone().map_err(|_| FileStoreError::Io)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| FileStoreError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|_| FileStoreError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(encode_digest(hasher.finalize()))
}

fn encode_digest(digest: impl IntoIterator<Item = u8>) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn verify_identity_and_content(
    file: &File,
    device: u64,
    inode: u64,
    length: u64,
    hash: &str,
) -> Result<(), FileStoreError> {
    let metadata = file.metadata().map_err(|_| FileStoreError::Io)?;
    if metadata.dev() != device
        || metadata.ino() != inode
        || metadata.len() != length
        || sha256_file_descriptor(file)? != hash
    {
        return Err(FileStoreError::IdentityMismatch);
    }
    Ok(())
}

fn path_matches_identity(
    parent: RawFd,
    name: &str,
    device: u64,
    inode: u64,
) -> Result<bool, FileStoreError> {
    let file = open_regular(parent, name, device)?;
    let metadata = file.metadata().map_err(|_| FileStoreError::Io)?;
    Ok(metadata.dev() == device && metadata.ino() == inode)
}

fn require_available_space(
    root: &File,
    reserve_free_bytes: u64,
    required_transfer_bytes: u64,
) -> Result<(), FileStoreError> {
    let mut status = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::fstatvfs(root.as_raw_fd(), status.as_mut_ptr()) };
    if result != 0 {
        return Err(FileStoreError::Io);
    }
    let status = unsafe { status.assume_init() };
    let available = u128::from(status.f_bavail) * u128::from(status.f_frsize);
    if !available_space_preserves_reserve(available, reserve_free_bytes, required_transfer_bytes) {
        return Err(FileStoreError::FreeSpace);
    }
    Ok(())
}

fn available_space_preserves_reserve(
    available_bytes: u128,
    reserve_free_bytes: u64,
    required_transfer_bytes: u64,
) -> bool {
    available_bytes >= u128::from(reserve_free_bytes) + u128::from(required_transfer_bytes)
}

fn validate_component(value: &str) -> Result<(), FileStoreError> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || value.as_bytes().contains(&b'/')
        || value.as_bytes().contains(&0)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(FileStoreError::InvalidComponent);
    }
    Ok(())
}

fn validate_hash(value: &str) -> Result<(), FileStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FileStoreError::InvalidComponent);
    }
    Ok(())
}

fn cstring(value: &str) -> Result<CString, FileStoreError> {
    CString::new(value.as_bytes()).map_err(|_| FileStoreError::InvalidComponent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_space_boundary_includes_remaining_transfer() {
        let reserve = 2 * 1024 * 1024 * 1024;
        let transfer = 512 * 1024 * 1024;
        let required = u128::from(reserve + transfer);

        assert!(available_space_preserves_reserve(
            required, reserve, transfer
        ));
        assert!(!available_space_preserves_reserve(
            required - 1,
            reserve,
            transfer
        ));
        assert!(!available_space_preserves_reserve(
            u128::from(reserve),
            reserve,
            1
        ));

        let written = 128 * 1024 * 1024;
        assert!(available_space_preserves_reserve(
            required - u128::from(written),
            reserve,
            transfer - written
        ));
        assert!(!available_space_preserves_reserve(
            required - u128::from(written) - 1,
            reserve,
            transfer - written
        ));

        let concurrent_transfers = transfer * 2;
        assert!(available_space_preserves_reserve(
            u128::from(reserve + concurrent_transfers),
            reserve,
            concurrent_transfers
        ));
        assert!(!available_space_preserves_reserve(
            u128::from(reserve + concurrent_transfers - 1),
            reserve,
            concurrent_transfers
        ));
    }

    #[test]
    fn rejects_path_components() {
        for value in ["", ".", "..", "/tmp/x", "../x", "x/y", "x\0y"] {
            assert_eq!(
                validate_component(value),
                Err(FileStoreError::InvalidComponent)
            );
        }
        assert_eq!(validate_component("op-1_asset.png"), Ok(()));
    }
}
