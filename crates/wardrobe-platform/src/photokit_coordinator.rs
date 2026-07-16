use crate::{
    photokit_resource_fingerprint, BlobStore, MaintenanceCoordinator, PhotoKitEnrollment,
    PhotoKitFinalizedObservation, PhotoKitKeyError, PhotoKitKeyPort, PhotoKitMaterializationRecord,
    PhotoKitOperation, PhotoKitPublication, PhotoKitRecordedObservation, PhotoKitRepository,
    PlatformError, PlatformResult, PreparedBlob, UnknownLengthBlobSession,
};
use std::fs::File;
use uuid::Uuid;
use wardrobe_core::{
    ConfigurePhotoKitScopeV1Request, ConfigurePhotoKitScopeV1Response, PhotoKitAuthorizationV1,
    PhotoKitAvailabilityReasonV1, PhotoKitAvailabilityV1, PhotoKitReconcileTriggerV1,
};

pub const PHOTOKIT_MAX_ASSETS: usize = 500;
pub const PHOTOKIT_MAX_RESOURCE_BYTES: u64 = 40 * 1024 * 1024;
pub const PHOTOKIT_MAX_RUN_BYTES: u64 = 512 * 1024 * 1024;
pub const PHOTOKIT_MAX_PENDING_CALLBACK_BYTES: u64 = 8 * 1024 * 1024;
pub const PHOTOKIT_MAX_CALLBACK_CHUNK_BYTES: usize = 1024 * 1024;
pub const PHOTOKIT_MAX_CONCURRENT_TRANSFERS: usize = 2;
pub const PHOTOKIT_MAX_PIXELS: u64 = 64_000_000;
pub const PHOTOKIT_MAX_DIMENSION: u32 = 16_384;
pub const PHOTOKIT_MAX_ALBUMS: usize = 100;
pub const PHOTOKIT_SELECTION_POLICY_REVISION: &str = "original-primary-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhotoKitNativeError {
    Unavailable,
    InvalidResponse,
    Cancelled,
    SinkRejected,
    ImageValidation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhotoKitNativeResource {
    pub operation_resource_token: String,
    pub resource_uti: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhotoKitNativeAlbum {
    pub album_locator: String,
    pub label: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhotoKitNativeAsset {
    pub asset_locator: String,
    pub primary_resource: Option<PhotoKitNativeResource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhotoKitEnumerationTerminal {
    Complete,
    Incomplete,
    AlbumUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhotoKitTransferTerminal {
    Complete,
    NetworkAccessRequired,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhotoKitValidatedImage {
    pub pixel_width: u32,
    pub pixel_height: u32,
    pub frame_count: u32,
}

pub trait PhotoKitEnumerationSink {
    fn observe(&mut self, asset: PhotoKitNativeAsset) -> PlatformResult<()>;
}

pub trait PhotoKitNativeByteSink {
    fn write_chunk(&mut self, bytes: &[u8]) -> PlatformResult<()>;
    fn accepted_bytes(&self) -> u64;
}

pub trait PhotoKitNativePort {
    fn authorization(
        &mut self,
        request_authorization: bool,
    ) -> Result<PhotoKitAuthorizationV1, PhotoKitNativeError>;

    fn enumerate_regular_album(
        &mut self,
        album_locator: &str,
        operation: &PhotoKitOperation,
        sink: &mut dyn PhotoKitEnumerationSink,
    ) -> Result<PhotoKitEnumerationTerminal, PhotoKitNativeError>;

    fn list_regular_albums(&mut self) -> Result<Vec<PhotoKitNativeAlbum>, PhotoKitNativeError> {
        Err(PhotoKitNativeError::Unavailable)
    }

    fn transfer_resource(
        &mut self,
        operation: &PhotoKitOperation,
        operation_resource_token: &str,
        network_access_allowed: bool,
        sink: &mut dyn PhotoKitNativeByteSink,
    ) -> Result<PhotoKitTransferTerminal, PhotoKitNativeError>;

    fn validate_image(
        &mut self,
        duplicated_read_only_file: File,
        resource_uti: &str,
    ) -> Result<PhotoKitValidatedImage, PhotoKitNativeError>;
}

#[derive(Debug)]
pub enum PhotoKitCoordinatorError {
    Platform(PlatformError),
    Key(PhotoKitKeyError),
    Native(PhotoKitNativeError),
}

impl From<PlatformError> for PhotoKitCoordinatorError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<PhotoKitKeyError> for PhotoKitCoordinatorError {
    fn from(error: PhotoKitKeyError) -> Self {
        Self::Key(error)
    }
}

impl From<PhotoKitNativeError> for PhotoKitCoordinatorError {
    fn from(error: PhotoKitNativeError) -> Self {
        Self::Native(error)
    }
}

pub struct PhotoKitCoordinator<N, K> {
    repository: PhotoKitRepository,
    blobs: BlobStore,
    native: N,
    keys: K,
}

impl<N, K> PhotoKitCoordinator<N, K>
where
    N: PhotoKitNativePort,
    K: PhotoKitKeyPort,
{
    pub fn new(repository: PhotoKitRepository, native: N, keys: K) -> Self {
        let blobs = BlobStore::new(&repository.database().paths);
        Self {
            repository,
            blobs,
            native,
            keys,
        }
    }

    pub fn repository(&self) -> &PhotoKitRepository {
        &self.repository
    }

    pub fn native(&self) -> &N {
        &self.native
    }

    pub fn native_mut(&mut self) -> &mut N {
        &mut self.native
    }

    pub fn configure_scope(
        &mut self,
        album_locator: &str,
        allow_icloud_downloads: bool,
        now_ms: i64,
    ) -> Result<PhotoKitEnrollment, PhotoKitCoordinatorError> {
        if album_locator.is_empty() || album_locator.len() > 1024 {
            return Err(PlatformError::InvalidInput("photokit_album_locator").into());
        }
        let key_reference = format!("photokit-locator-{}", Uuid::new_v4().hyphenated());
        let pending =
            self.repository
                .reserve_enrollment(&key_reference, allow_icloud_downloads, now_ms)?;
        let root_key = match self.keys.create_root_key(&key_reference) {
            Ok(key) => key,
            Err(error) => {
                self.repository.remove_pending_enrollment(
                    &pending.enrollment_epoch,
                    now_ms,
                    "pending_enrollment_recovery",
                )?;
                return Err(error.into());
            }
        };
        self.repository
            .activate_enrollment(&pending.enrollment_epoch, &root_key, album_locator, now_ms)
            .map_err(Into::into)
    }

    pub fn configure_scope_command(
        &mut self,
        request: &ConfigurePhotoKitScopeV1Request,
        envelope_hash: &str,
        album_locator: &str,
        now_ms: i64,
    ) -> Result<ConfigurePhotoKitScopeV1Response, PhotoKitCoordinatorError> {
        if album_locator.is_empty() || album_locator.len() > 1024 {
            return Err(PlatformError::InvalidInput("photokit_album_locator").into());
        }
        let key_reference = format!("photokit-locator-{}", Uuid::new_v4().hyphenated());
        let pending = self.repository.reserve_enrollment(
            &key_reference,
            request.allow_icloud_downloads,
            now_ms,
        )?;
        let root_key = match self.keys.create_root_key(&key_reference) {
            Ok(key) => key,
            Err(error) => {
                self.repository.remove_pending_enrollment(
                    &pending.enrollment_epoch,
                    now_ms,
                    "pending_enrollment_recovery",
                )?;
                return Err(error.into());
            }
        };
        self.repository
            .activate_enrollment_command(
                &pending.enrollment_epoch,
                &root_key,
                album_locator,
                request,
                envelope_hash,
                now_ms,
            )
            .map_err(Into::into)
    }

    pub fn recover(&mut self, now_ms: i64) -> Result<usize, PhotoKitCoordinatorError> {
        let mut recovered = self.repository.recover_operations(now_ms)?;
        for pending in self.repository.pending_enrollments()? {
            match self.keys.delete_root_key(&pending.key_reference) {
                Ok(()) | Err(PhotoKitKeyError::NotFound) => {
                    self.repository.remove_pending_enrollment(
                        &pending.enrollment_epoch,
                        now_ms,
                        "pending_enrollment_recovery",
                    )?;
                    self.repository
                        .mark_key_cleanup_complete(&pending.key_reference, now_ms)?;
                    recovered += 1;
                }
                Err(_) => {}
            }
        }
        for intent in self.repository.pending_key_cleanup_intents()? {
            match self.keys.delete_root_key(&intent.key_reference) {
                Ok(()) | Err(PhotoKitKeyError::NotFound) => {
                    self.repository
                        .complete_key_cleanup_intent(&intent.intent_id, now_ms)?;
                    recovered += 1;
                }
                Err(error) => {
                    let failure_code = match error {
                        PhotoKitKeyError::Locked => "locked",
                        PhotoKitKeyError::Unavailable => "unavailable",
                        PhotoKitKeyError::Integrity | PhotoKitKeyError::Internal => "internal",
                        PhotoKitKeyError::NotFound => unreachable!(),
                    };
                    self.repository.fail_key_cleanup_intent(
                        &intent.intent_id,
                        failure_code,
                        now_ms,
                    )?;
                }
            }
        }
        Ok(recovered)
    }

    pub fn reconcile(
        &mut self,
        request_id: &str,
        trigger: PhotoKitReconcileTriggerV1,
        now_ms: i64,
    ) -> Result<PhotoKitPublication, PhotoKitCoordinatorError> {
        if let Some(publication) = self.repository.replay_publication(request_id, trigger)? {
            return Ok(publication);
        }
        let authorization = self.native.authorization(false)?;
        let (operation, replayed) =
            self.repository
                .begin_operation(request_id, trigger, authorization, now_ms)?;
        if replayed {
            let snapshot = self.repository.snapshot(authorization)?;
            return Ok(PhotoKitPublication {
                operation_id: operation.operation_id,
                reconciliation_fence: operation.reconciliation_fence,
                membership_generation: snapshot.membership_generation.map(|value| value.get()),
                transitions: 0,
                replayed: true,
                snapshot,
            });
        }
        if authorization != PhotoKitAuthorizationV1::Authorized {
            let (reason, terminal) = authorization_unavailable(authorization);
            return self
                .repository
                .finalize_global_unavailable(
                    &operation,
                    authorization,
                    Some(reason),
                    terminal,
                    now_ms,
                )
                .map_err(Into::into);
        }
        let enrollment = self
            .repository
            .active_enrollment()?
            .ok_or(PlatformError::Conflict("photokit_not_configured"))?;
        if enrollment.enrollment_epoch != operation.enrollment_epoch {
            return Err(PlatformError::Conflict("photokit_stale_fence").into());
        }
        let root_key = match self.keys.load_root_key(&enrollment.key_reference, false) {
            Ok(key) => key,
            Err(_) => {
                return self
                    .repository
                    .finalize_global_unavailable(
                        &operation,
                        authorization,
                        Some(PhotoKitAvailabilityReasonV1::ScopeUnavailable),
                        "locator_key_unavailable",
                        now_ms,
                    )
                    .map_err(Into::into)
            }
        };
        let album_locator = match self
            .repository
            .decrypt_album_locator(&operation.enrollment_epoch, &root_key)
        {
            Ok(locator) => locator,
            Err(_) => {
                return self
                    .repository
                    .finalize_global_unavailable(
                        &operation,
                        authorization,
                        Some(PhotoKitAvailabilityReasonV1::ScopeUnavailable),
                        "locator_key_unavailable",
                        now_ms,
                    )
                    .map_err(Into::into)
            }
        };

        let mut enumeration = EnumerationRecorder {
            repository: &self.repository,
            operation: &operation,
            root_key: &root_key,
            now_ms,
            assets: Vec::new(),
        };
        let terminal =
            match self
                .native
                .enumerate_regular_album(&album_locator, &operation, &mut enumeration)
            {
                Ok(terminal) => terminal,
                Err(_) => {
                    return self
                        .repository
                        .fail_incomplete_operation(&operation, now_ms)
                        .map_err(Into::into)
                }
            };
        let assets = enumeration.assets;
        match terminal {
            PhotoKitEnumerationTerminal::Incomplete => {
                return self
                    .repository
                    .fail_incomplete_operation(&operation, now_ms)
                    .map_err(Into::into)
            }
            PhotoKitEnumerationTerminal::AlbumUnavailable => {
                return self
                    .repository
                    .finalize_global_unavailable(
                        &operation,
                        authorization,
                        Some(PhotoKitAvailabilityReasonV1::ScopeUnavailable),
                        "scope_unavailable",
                        now_ms,
                    )
                    .map_err(Into::into)
            }
            PhotoKitEnumerationTerminal::Complete => {}
        }
        self.repository.mark_materializing(&operation)?;

        let session = UnknownLengthBlobSession::new(crate::UnknownLengthBlobLimits::PHOTOKIT_V1)?;
        let mut prepared = Vec::with_capacity(assets.len());
        for asset in assets {
            prepared.push(self.materialize_asset(
                &operation,
                &enrollment,
                &session,
                asset,
                now_ms,
            )?);
        }

        let _shared = MaintenanceCoordinator::global().acquire_shared()?;
        let mut finalized = Vec::with_capacity(prepared.len());
        for item in prepared {
            finalized.push(match item {
                PreparedObservation::Unavailable { ordinal, reason } => {
                    PhotoKitFinalizedObservation {
                        ordinal,
                        availability: PhotoKitAvailabilityV1::Unavailable,
                        reason,
                        materialization: None,
                    }
                }
                PreparedObservation::Materialized {
                    ordinal,
                    resource_uti,
                    validated,
                    blob,
                } => match self.blobs.promote_prepared(blob) {
                    Ok(blob) => PhotoKitFinalizedObservation {
                        ordinal,
                        availability: PhotoKitAvailabilityV1::Available,
                        reason: PhotoKitAvailabilityReasonV1::Materialized,
                        materialization: Some(PhotoKitMaterializationRecord {
                            resource_fingerprint: photokit_resource_fingerprint(
                                &blob.sha256,
                                &resource_uti,
                                validated.pixel_width,
                                validated.pixel_height,
                            )?,
                            blob,
                            resource_uti,
                            pixel_width: validated.pixel_width,
                            pixel_height: validated.pixel_height,
                        }),
                    },
                    Err(_) => PhotoKitFinalizedObservation {
                        ordinal,
                        availability: PhotoKitAvailabilityV1::Unavailable,
                        reason: PhotoKitAvailabilityReasonV1::BlobIntegrityFailed,
                        materialization: None,
                    },
                },
            });
        }
        self.repository
            .finalize_complete(&operation, authorization, &finalized, now_ms)
            .map_err(Into::into)
    }

    fn materialize_asset(
        &mut self,
        operation: &PhotoKitOperation,
        enrollment: &PhotoKitEnrollment,
        session: &UnknownLengthBlobSession,
        asset: EnumeratedAsset,
        now_ms: i64,
    ) -> Result<PreparedObservation, PhotoKitCoordinatorError> {
        let Some(resource) = asset.resource else {
            self.repository.record_attempt(
                operation,
                asset.record.ordinal,
                0,
                false,
                0,
                "unsupported_resource",
                now_ms,
            )?;
            return Ok(PreparedObservation::Unavailable {
                ordinal: asset.record.ordinal,
                reason: PhotoKitAvailabilityReasonV1::UnsupportedResource,
            });
        };
        if !supported_uti(&resource.resource_uti) {
            self.repository.record_attempt(
                operation,
                asset.record.ordinal,
                0,
                false,
                0,
                "unsupported_resource",
                now_ms,
            )?;
            return Ok(PreparedObservation::Unavailable {
                ordinal: asset.record.ordinal,
                reason: PhotoKitAvailabilityReasonV1::UnsupportedResource,
            });
        }

        let mut first = NativeSink {
            inner: self.blobs.begin_unknown_length(session)?,
        };
        let first_terminal = match self.native.transfer_resource(
            operation,
            &resource.operation_resource_token,
            false,
            &mut first,
        ) {
            Ok(terminal) => terminal,
            Err(_) => {
                let accepted = first.accepted_bytes();
                self.repository.record_attempt(
                    operation,
                    asset.record.ordinal,
                    0,
                    false,
                    accepted,
                    "transfer_failed",
                    now_ms,
                )?;
                return Ok(PreparedObservation::Unavailable {
                    ordinal: asset.record.ordinal,
                    reason: PhotoKitAvailabilityReasonV1::TransferFailed,
                });
            }
        };
        let first_bytes = first.accepted_bytes();
        match first_terminal {
            PhotoKitTransferTerminal::NetworkAccessRequired if first_bytes == 0 => {
                self.repository.record_attempt(
                    operation,
                    asset.record.ordinal,
                    0,
                    false,
                    0,
                    "network_access_required",
                    now_ms,
                )?;
                drop(first);
                if !enrollment.allow_icloud_downloads {
                    return Ok(PreparedObservation::Unavailable {
                        ordinal: asset.record.ordinal,
                        reason: PhotoKitAvailabilityReasonV1::IcloudUnavailable,
                    });
                }
                let mut retry = NativeSink {
                    inner: self.blobs.begin_unknown_length(session)?,
                };
                let retry_terminal = match self.native.transfer_resource(
                    operation,
                    &resource.operation_resource_token,
                    true,
                    &mut retry,
                ) {
                    Ok(terminal) => terminal,
                    Err(_) => {
                        let accepted = retry.accepted_bytes();
                        self.repository.record_attempt(
                            operation,
                            asset.record.ordinal,
                            1,
                            true,
                            accepted,
                            "transfer_failed",
                            now_ms,
                        )?;
                        return Ok(PreparedObservation::Unavailable {
                            ordinal: asset.record.ordinal,
                            reason: PhotoKitAvailabilityReasonV1::TransferFailed,
                        });
                    }
                };
                let retry_bytes = retry.accepted_bytes();
                if retry_terminal != PhotoKitTransferTerminal::Complete || retry_bytes == 0 {
                    self.repository.record_attempt(
                        operation,
                        asset.record.ordinal,
                        1,
                        true,
                        retry_bytes,
                        "transfer_failed",
                        now_ms,
                    )?;
                    return Ok(PreparedObservation::Unavailable {
                        ordinal: asset.record.ordinal,
                        reason: PhotoKitAvailabilityReasonV1::TransferFailed,
                    });
                }
                self.validate_prepared(
                    operation,
                    asset.record.ordinal,
                    resource.resource_uti,
                    retry,
                    1,
                    now_ms,
                )
            }
            PhotoKitTransferTerminal::Complete if first_bytes > 0 => self.validate_prepared(
                operation,
                asset.record.ordinal,
                resource.resource_uti,
                first,
                0,
                now_ms,
            ),
            PhotoKitTransferTerminal::NetworkAccessRequired
            | PhotoKitTransferTerminal::Complete
            | PhotoKitTransferTerminal::Failed => {
                self.repository.record_attempt(
                    operation,
                    asset.record.ordinal,
                    0,
                    false,
                    first_bytes,
                    "transfer_failed",
                    now_ms,
                )?;
                Ok(PreparedObservation::Unavailable {
                    ordinal: asset.record.ordinal,
                    reason: PhotoKitAvailabilityReasonV1::TransferFailed,
                })
            }
        }
    }

    fn validate_prepared(
        &mut self,
        operation: &PhotoKitOperation,
        ordinal: u16,
        resource_uti: String,
        sink: NativeSink,
        attempt_ordinal: u8,
        now_ms: i64,
    ) -> Result<PreparedObservation, PhotoKitCoordinatorError> {
        let bytes = sink.accepted_bytes();
        let prepared = sink.inner.finish()?;
        let descriptor = prepared.open_read_only()?;
        let validated = match self.native.validate_image(descriptor, &resource_uti) {
            Ok(validated)
                if validated.frame_count == 1
                    && validated.pixel_width > 0
                    && validated.pixel_width <= PHOTOKIT_MAX_DIMENSION
                    && validated.pixel_height > 0
                    && validated.pixel_height <= PHOTOKIT_MAX_DIMENSION
                    && u64::from(validated.pixel_width) * u64::from(validated.pixel_height)
                        <= PHOTOKIT_MAX_PIXELS =>
            {
                validated
            }
            _ => {
                self.repository.record_attempt(
                    operation,
                    ordinal,
                    attempt_ordinal,
                    attempt_ordinal == 1,
                    bytes,
                    "blob_integrity_failed",
                    now_ms,
                )?;
                return Ok(PreparedObservation::Unavailable {
                    ordinal,
                    reason: PhotoKitAvailabilityReasonV1::BlobIntegrityFailed,
                });
            }
        };
        self.repository.record_attempt(
            operation,
            ordinal,
            attempt_ordinal,
            attempt_ordinal == 1,
            bytes,
            "materialized",
            now_ms,
        )?;
        Ok(PreparedObservation::Materialized {
            ordinal,
            resource_uti,
            validated,
            blob: prepared,
        })
    }
}

struct NativeSink {
    inner: crate::UnknownLengthBlobSink,
}

impl PhotoKitNativeByteSink for NativeSink {
    fn write_chunk(&mut self, bytes: &[u8]) -> PlatformResult<()> {
        self.inner.write_chunk(bytes)
    }

    fn accepted_bytes(&self) -> u64 {
        self.inner.accepted_bytes()
    }
}

struct EnumerationRecorder<'a> {
    repository: &'a PhotoKitRepository,
    operation: &'a PhotoKitOperation,
    root_key: &'a crate::PhotoKitRootKey,
    now_ms: i64,
    assets: Vec<EnumeratedAsset>,
}

impl PhotoKitEnumerationSink for EnumerationRecorder<'_> {
    fn observe(&mut self, asset: PhotoKitNativeAsset) -> PlatformResult<()> {
        if self.assets.len() >= PHOTOKIT_MAX_ASSETS {
            return Err(PlatformError::InvalidInput("photokit_scope_too_large"));
        }
        validate_native_asset(&asset)?;
        let ordinal = self.assets.len() as u16;
        let record = self.repository.record_observation(
            self.operation,
            self.root_key,
            ordinal,
            &asset.asset_locator,
            asset
                .primary_resource
                .as_ref()
                .map(|resource| resource.resource_uti.as_str()),
            asset.primary_resource.is_some(),
            self.now_ms,
        )?;
        self.assets.push(EnumeratedAsset {
            record,
            resource: asset.primary_resource,
        });
        Ok(())
    }
}

struct EnumeratedAsset {
    record: PhotoKitRecordedObservation,
    resource: Option<PhotoKitNativeResource>,
}

enum PreparedObservation {
    Materialized {
        ordinal: u16,
        resource_uti: String,
        validated: PhotoKitValidatedImage,
        blob: PreparedBlob,
    },
    Unavailable {
        ordinal: u16,
        reason: PhotoKitAvailabilityReasonV1,
    },
}

fn validate_native_asset(asset: &PhotoKitNativeAsset) -> PlatformResult<()> {
    if asset.asset_locator.is_empty() || asset.asset_locator.len() > 1024 {
        return Err(PlatformError::InvalidInput("photokit_asset_locator"));
    }
    if let Some(resource) = &asset.primary_resource {
        if resource.operation_resource_token.is_empty()
            || resource.operation_resource_token.len() > 128
            || !resource.operation_resource_token.is_ascii()
            || resource.resource_uti.is_empty()
            || resource.resource_uti.len() > 128
            || !resource.resource_uti.is_ascii()
        {
            return Err(PlatformError::InvalidInput("photokit_resource"));
        }
    }
    Ok(())
}

fn supported_uti(value: &str) -> bool {
    matches!(
        value,
        "public.jpeg" | "public.png" | "public.heic" | "public.heif"
    )
}

fn authorization_unavailable(
    value: PhotoKitAuthorizationV1,
) -> (PhotoKitAvailabilityReasonV1, &'static str) {
    match value {
        PhotoKitAuthorizationV1::NotDetermined => (
            PhotoKitAvailabilityReasonV1::AuthorizationNotDetermined,
            "authorization_not_determined",
        ),
        PhotoKitAuthorizationV1::Restricted => (
            PhotoKitAvailabilityReasonV1::AuthorizationRestricted,
            "authorization_restricted",
        ),
        PhotoKitAuthorizationV1::Denied => (
            PhotoKitAvailabilityReasonV1::AuthorizationDenied,
            "authorization_denied",
        ),
        PhotoKitAuthorizationV1::Limited => (
            PhotoKitAvailabilityReasonV1::LimitedAccess,
            "limited_access",
        ),
        PhotoKitAuthorizationV1::Authorized => (
            PhotoKitAvailabilityReasonV1::ScopeUnavailable,
            "scope_unavailable",
        ),
    }
}
