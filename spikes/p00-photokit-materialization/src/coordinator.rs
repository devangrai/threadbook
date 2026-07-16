use crate::contracts::{
    CallbackDisposition, CallbackKind, GatewayCancellationPort, GatewayEventV1, GatewayFailure,
    GatewayRequestV1, MaterializationClass, MaterializationLimits, OperationRef, OperationSnapshot,
    OperationState, PhotoAssetGateway, RequestRegistrationPort, StartMaterializationV1,
    TransferKind,
};
use crate::filesystem::{FileStore, FileStoreError, StagedAsset};
use crate::store::{CommitOutcome, MaterializationStore, PendingItem, StoreError};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    None,
    AfterTransferBeforeValidation,
    AfterStagingFsync,
    AfterPromotionBeforeCommit,
    AfterCommit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoordinatorError {
    Contract,
    Gateway(GatewayFailure),
    Filesystem(FileStoreError),
    Store(StoreError),
    Protocol,
    Progress,
    ConcurrentRequestLimit,
    Cancelled,
    InjectedCrash(CrashPoint),
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Contract => "materialization failure: contract",
            Self::Gateway(error) => return error.fmt(formatter),
            Self::Filesystem(error) => return error.fmt(formatter),
            Self::Store(error) => return error.fmt(formatter),
            Self::Protocol => "materialization failure: native_protocol",
            Self::Progress => "materialization failure: progress",
            Self::ConcurrentRequestLimit => "materialization failure: concurrent_request_limit",
            Self::Cancelled => "materialization failure: cancellation",
            Self::InjectedCrash(_) => "materialization failure: injected_crash",
        })
    }
}

impl Error for CoordinatorError {}

impl From<FileStoreError> for CoordinatorError {
    fn from(error: FileStoreError) -> Self {
        Self::Filesystem(error)
    }
}

impl From<StoreError> for CoordinatorError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

pub struct MaterializationCoordinator<G> {
    store: MaterializationStore,
    files: FileStore,
    gateway: G,
    limits: MaterializationLimits,
    cancellation: CancellationHandle,
    request_capacity: RequestCapacity,
}

#[derive(Clone)]
pub struct CancellationHandle {
    store: MaterializationStore,
    gateway: Arc<dyn GatewayCancellationPort>,
}

#[derive(Clone, Debug)]
pub struct RequestCapacity {
    state: Arc<Mutex<usize>>,
    maximum: usize,
}

#[derive(Debug)]
pub struct RequestPermit {
    state: Arc<Mutex<usize>>,
}

struct RequestLifecycle {
    cancellation: CancellationHandle,
    operation_id: String,
    item_index: usize,
    operation_generation: u64,
    request_generation: u64,
    native_request_id: Mutex<Option<String>>,
    terminal: Mutex<bool>,
}

impl CancellationHandle {
    pub fn cancel(&self, operation_id: &str) -> Result<OperationSnapshot, CoordinatorError> {
        let (snapshot, active_requests) = self.store.cancel_with_active_requests(operation_id)?;
        for native_request_id in active_requests {
            self.gateway.cancel(&native_request_id);
        }
        Ok(snapshot)
    }

    pub fn active_request_ids(&self, operation_id: &str) -> Result<Vec<String>, CoordinatorError> {
        self.store
            .active_request_ids(operation_id)
            .map_err(Into::into)
    }
}

impl RequestCapacity {
    pub fn new(maximum: usize) -> Result<Self, CoordinatorError> {
        if maximum == 0 {
            return Err(CoordinatorError::Contract);
        }
        Ok(Self {
            state: Arc::new(Mutex::new(0)),
            maximum,
        })
    }

    pub fn try_acquire(&self) -> Result<RequestPermit, CoordinatorError> {
        let mut active = self.state.lock().map_err(|_| CoordinatorError::Protocol)?;
        if *active >= self.maximum {
            return Err(CoordinatorError::ConcurrentRequestLimit);
        }
        *active += 1;
        Ok(RequestPermit {
            state: Arc::clone(&self.state),
        })
    }
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        if let Ok(mut active) = self.state.lock() {
            *active = active.saturating_sub(1);
        }
    }
}

impl RequestLifecycle {
    fn new(
        cancellation: CancellationHandle,
        operation_id: &str,
        item_index: usize,
        operation_generation: u64,
        request_generation: u64,
    ) -> Self {
        Self {
            cancellation,
            operation_id: operation_id.to_owned(),
            item_index,
            operation_generation,
            request_generation,
            native_request_id: Mutex::new(None),
            terminal: Mutex::new(false),
        }
    }
}

impl RequestRegistrationPort for RequestLifecycle {
    fn register(&self, native_request_id: &str) -> Result<CallbackDisposition, GatewayFailure> {
        let registered = self
            .cancellation
            .store
            .register_active_request(
                &self.operation_id,
                self.item_index,
                self.operation_generation,
                self.request_generation,
                native_request_id,
            )
            .map_err(|_| GatewayFailure::NativeProtocol)?;
        if !registered {
            self.cancellation.gateway.cancel(native_request_id);
            return Ok(CallbackDisposition::CancelImmediately(
                native_request_id.to_owned(),
            ));
        }
        *self
            .native_request_id
            .lock()
            .map_err(|_| GatewayFailure::NativeProtocol)? = Some(native_request_id.to_owned());
        Ok(CallbackDisposition::Accepted)
    }

    fn cancel_operation(&self) -> Result<(), GatewayFailure> {
        self.cancellation
            .cancel(&self.operation_id)
            .map(|_| ())
            .map_err(|_| GatewayFailure::NativeProtocol)
    }

    fn accept_callback(&self, kind: CallbackKind) -> Result<CallbackDisposition, GatewayFailure> {
        let mut terminal = self
            .terminal
            .lock()
            .map_err(|_| GatewayFailure::NativeProtocol)?;
        if *terminal {
            return Ok(CallbackDisposition::IgnoredAfterTerminal);
        }
        let native_request_id = self
            .native_request_id
            .lock()
            .map_err(|_| GatewayFailure::NativeProtocol)?
            .clone();
        let Some(native_request_id) = native_request_id else {
            return Ok(CallbackDisposition::IgnoredCancelled);
        };
        let allowed = self
            .cancellation
            .store
            .callback_allowed(
                &self.operation_id,
                self.item_index,
                self.operation_generation,
                self.request_generation,
                &native_request_id,
            )
            .map_err(|_| GatewayFailure::NativeProtocol)?;
        if !allowed {
            return Ok(CallbackDisposition::IgnoredCancelled);
        }
        if kind == CallbackKind::Completed {
            *terminal = true;
        }
        Ok(CallbackDisposition::Accepted)
    }

    fn complete(&self) -> Result<(), GatewayFailure> {
        let native_request_id = self
            .native_request_id
            .lock()
            .map_err(|_| GatewayFailure::NativeProtocol)?
            .take();
        if let Some(native_request_id) = native_request_id {
            self.cancellation
                .store
                .clear_active_request(
                    &self.operation_id,
                    self.item_index,
                    self.request_generation,
                    &native_request_id,
                )
                .map_err(|_| GatewayFailure::NativeProtocol)?;
        }
        Ok(())
    }
}

impl<G: PhotoAssetGateway> MaterializationCoordinator<G> {
    pub fn new(
        store: MaterializationStore,
        files: FileStore,
        gateway: G,
        limits: MaterializationLimits,
    ) -> Self {
        let cancellation = CancellationHandle {
            store: store.clone(),
            gateway: gateway.cancellation_port(),
        };
        let request_capacity =
            RequestCapacity::new(limits.max_concurrent_requests).expect("validated request limit");
        Self {
            store,
            files,
            gateway,
            limits,
            cancellation,
            request_capacity,
        }
    }

    pub fn start(
        &self,
        request: &StartMaterializationV1,
        created_at_ms: i64,
    ) -> Result<OperationRef, CoordinatorError> {
        if request.assets.len() > self.limits.max_assets {
            return Err(CoordinatorError::Contract);
        }
        self.store.start(request, created_at_ms).map_err(Into::into)
    }

    pub fn status(&self, operation_id: &str) -> Result<OperationSnapshot, CoordinatorError> {
        self.store.status(operation_id).map_err(Into::into)
    }

    pub fn cancel(&mut self, operation_id: &str) -> Result<OperationSnapshot, CoordinatorError> {
        self.cancellation.cancel(operation_id)
    }

    pub fn recover(&mut self, operation_id: &str) -> Result<(), CoordinatorError> {
        self.store.recover(operation_id)?;
        Ok(())
    }

    pub fn run(
        &mut self,
        operation_id: &str,
        retrieved_at_ms: i64,
    ) -> Result<Vec<CommitOutcome>, CoordinatorError> {
        self.run_with_crash(operation_id, retrieved_at_ms, CrashPoint::None)
    }

    pub fn run_with_crash(
        &mut self,
        operation_id: &str,
        retrieved_at_ms: i64,
        crash: CrashPoint,
    ) -> Result<Vec<CommitOutcome>, CoordinatorError> {
        let mut outcomes = Vec::new();
        loop {
            let snapshot = self.store.status(operation_id)?;
            if snapshot.state == OperationState::Succeeded {
                return Ok(outcomes);
            }
            if snapshot.state == OperationState::Cancelled {
                return Err(CoordinatorError::Cancelled);
            }
            if snapshot.state == OperationState::Failed {
                return Err(CoordinatorError::Protocol);
            }
            let Some(item) = self.store.next_pending(operation_id)? else {
                return Err(CoordinatorError::Protocol);
            };
            match self.materialize_item(operation_id, &item, retrieved_at_ms, crash) {
                Ok(outcome) => outcomes.push(outcome),
                Err(CoordinatorError::InjectedCrash(point)) => {
                    return Err(CoordinatorError::InjectedCrash(point));
                }
                Err(error) => {
                    let generation = self
                        .store
                        .status(operation_id)
                        .map(|value| value.generation)
                        .unwrap_or(snapshot.generation);
                    let _ = self.store.fail_item(
                        operation_id,
                        item.index,
                        generation,
                        failure_code(error),
                    );
                    return Err(error);
                }
            }
        }
    }

    pub fn gateway(&self) -> &G {
        &self.gateway
    }

    pub fn gateway_mut(&mut self) -> &mut G {
        &mut self.gateway
    }

    pub fn store(&self) -> &MaterializationStore {
        &self.store
    }

    pub fn files(&self) -> &FileStore {
        &self.files
    }

    pub fn cancellation_handle(&self) -> CancellationHandle {
        self.cancellation.clone()
    }

    fn materialize_item(
        &mut self,
        operation_id: &str,
        item: &PendingItem,
        retrieved_at_ms: i64,
        crash: CrashPoint,
    ) -> Result<CommitOutcome, CoordinatorError> {
        let resource = self
            .gateway
            .select_resource(&item.asset.asset_ref)
            .map_err(CoordinatorError::Gateway)?;
        resource
            .validate(self.limits)
            .map_err(|_| CoordinatorError::Contract)?;
        let (operation_generation, probe_generation) =
            self.store.begin_item(operation_id, item.index, &resource)?;
        let staging_filename = transfer_staging_filename(&item.staging_filename, probe_generation);
        let probe = self.files.begin(
            operation_id,
            &staging_filename,
            self.limits.max_resource_bytes,
        )?;
        let probe_request = GatewayRequestV1 {
            schema_version: crate::CONTRACT_SCHEMA_VERSION,
            operation_id: operation_id.to_owned(),
            asset_ref: item.asset.asset_ref.clone(),
            resource: resource.clone(),
            request_generation: probe_generation,
            kind: TransferKind::ResidencyProbe,
            network_access_allowed: false,
        };
        let probe_lifecycle = RequestLifecycle::new(
            self.cancellation.clone(),
            operation_id,
            item.index,
            operation_generation,
            probe_generation,
        );
        let probe_permit = self.request_capacity.try_acquire()?;
        let probe_events = self
            .gateway
            .request(&probe_request, &probe_lifecycle)
            .map_err(CoordinatorError::Gateway)?;
        let probe_outcome = consume_events(
            probe_events,
            probe_generation,
            probe,
            false,
            &probe_lifecycle,
            |byte_count| {
                self.store.record_transferred_bytes(
                    operation_id,
                    operation_generation,
                    byte_count,
                    self.limits.max_batch_bytes,
                )
            },
            |progress| {
                self.store.update_progress(
                    operation_id,
                    item.index,
                    operation_generation,
                    probe_generation,
                    progress,
                )
            },
        );
        probe_lifecycle
            .complete()
            .map_err(CoordinatorError::Gateway)?;
        drop(probe_permit);
        let probe_outcome = probe_outcome?;

        let (staged, photokit_classification, final_generation) = match probe_outcome {
            TransferOutcome::Success { staged, .. } if staged.byte_count() > 0 => {
                (staged, MaterializationClass::Local, probe_generation)
            }
            TransferOutcome::Failed {
                staged,
                failure: GatewayFailure::NetworkRequired,
                ..
            } if staged.byte_count() == 0 => {
                let cloud_generation = self.store.next_request_generation(
                    operation_id,
                    item.index,
                    operation_generation,
                )?;
                let cloud = staged;
                let cloud_request = GatewayRequestV1 {
                    schema_version: crate::CONTRACT_SCHEMA_VERSION,
                    operation_id: operation_id.to_owned(),
                    asset_ref: item.asset.asset_ref.clone(),
                    resource: resource.clone(),
                    request_generation: cloud_generation,
                    kind: TransferKind::CloudTransfer,
                    network_access_allowed: true,
                };
                let cloud_lifecycle = RequestLifecycle::new(
                    self.cancellation.clone(),
                    operation_id,
                    item.index,
                    operation_generation,
                    cloud_generation,
                );
                let cloud_permit = self.request_capacity.try_acquire()?;
                let cloud_events = self
                    .gateway
                    .request(&cloud_request, &cloud_lifecycle)
                    .map_err(CoordinatorError::Gateway)?;
                let cloud_outcome = consume_events(
                    cloud_events,
                    cloud_generation,
                    cloud,
                    true,
                    &cloud_lifecycle,
                    |byte_count| {
                        self.store.record_transferred_bytes(
                            operation_id,
                            operation_generation,
                            byte_count,
                            self.limits.max_batch_bytes,
                        )
                    },
                    |progress| {
                        self.store.update_progress(
                            operation_id,
                            item.index,
                            operation_generation,
                            cloud_generation,
                            progress,
                        )
                    },
                );
                cloud_lifecycle
                    .complete()
                    .map_err(CoordinatorError::Gateway)?;
                drop(cloud_permit);
                match cloud_outcome? {
                    TransferOutcome::Success {
                        staged,
                        observed_progress: true,
                    } if staged.byte_count() > 0 => {
                        (staged, MaterializationClass::Cloud, cloud_generation)
                    }
                    TransferOutcome::Failed { failure, .. } => {
                        return Err(CoordinatorError::Gateway(failure));
                    }
                    _ => return Err(CoordinatorError::Progress),
                }
            }
            TransferOutcome::Failed { failure, .. } => {
                return Err(CoordinatorError::Gateway(failure));
            }
            _ => return Err(CoordinatorError::Protocol),
        };
        let classification = if item.asset.connector_generation.is_empty() {
            MaterializationClass::PickerImport
        } else {
            photokit_classification
        };

        if crash == CrashPoint::AfterTransferBeforeValidation {
            return Err(CoordinatorError::InjectedCrash(crash));
        }
        let validated = self.files.validate(staged, &resource)?;
        if crash == CrashPoint::AfterStagingFsync {
            return Err(CoordinatorError::InjectedCrash(crash));
        }
        let promoted = self.files.promote(&validated)?;
        if crash == CrashPoint::AfterPromotionBeforeCommit {
            return Err(CoordinatorError::InjectedCrash(crash));
        }
        self.files.verify_promoted(&promoted)?;
        let outcome = self.store.commit(
            operation_id,
            item.index,
            operation_generation,
            final_generation,
            &item.asset,
            &resource,
            classification,
            &promoted,
            retrieved_at_ms,
        )?;
        if crash == CrashPoint::AfterCommit {
            return Err(CoordinatorError::InjectedCrash(crash));
        }
        Ok(outcome)
    }
}

fn transfer_staging_filename(base: &str, generation: u64) -> String {
    format!("{base}.g{generation}")
}

enum TransferOutcome {
    Success {
        staged: StagedAsset,
        observed_progress: bool,
    },
    Failed {
        staged: StagedAsset,
        failure: GatewayFailure,
    },
}

fn consume_events<F>(
    events: Vec<GatewayEventV1>,
    generation: u64,
    mut staged: StagedAsset,
    require_progress: bool,
    lifecycle: &dyn RequestRegistrationPort,
    mut record_bytes: impl FnMut(usize) -> Result<(), StoreError>,
    mut persist_progress: F,
) -> Result<TransferOutcome, CoordinatorError>
where
    F: FnMut(f64) -> Result<(), StoreError>,
{
    let mut started = false;
    let mut terminal = false;
    let mut observed_progress = false;
    let mut last_progress = 0.0_f64;
    let mut result = None;
    let mut cancelled_callbacks = 0_usize;
    for event in events {
        if event.generation() != generation {
            continue;
        }
        let kind = match &event {
            GatewayEventV1::Started { .. } => CallbackKind::Started,
            GatewayEventV1::Chunk { .. } => CallbackKind::Chunk,
            GatewayEventV1::Progress { .. } => CallbackKind::Progress,
            GatewayEventV1::Completed { .. } => CallbackKind::Completed,
        };
        match lifecycle
            .accept_callback(kind)
            .map_err(CoordinatorError::Gateway)?
        {
            CallbackDisposition::Accepted => {}
            CallbackDisposition::IgnoredCancelled
            | CallbackDisposition::IgnoredStale
            | CallbackDisposition::IgnoredAfterTerminal
            | CallbackDisposition::CancelImmediately(_) => {
                cancelled_callbacks += 1;
                continue;
            }
        }
        if terminal {
            return Err(CoordinatorError::Protocol);
        }
        match event {
            GatewayEventV1::Started { .. } if !started => started = true,
            GatewayEventV1::Chunk { bytes, .. } if started => {
                record_bytes(bytes.len())?;
                staged.write_chunk(&bytes)?;
            }
            GatewayEventV1::Progress { fraction, .. } if started => {
                if !fraction.is_finite()
                    || !(0.0..=1.0).contains(&fraction)
                    || fraction < last_progress
                {
                    return Err(CoordinatorError::Progress);
                }
                persist_progress(fraction)?;
                last_progress = fraction;
                observed_progress = true;
            }
            GatewayEventV1::Completed {
                result: completed, ..
            } if started => {
                terminal = true;
                result = Some(completed);
            }
            _ => return Err(CoordinatorError::Protocol),
        }
    }
    if cancelled_callbacks > 0 && result.is_none() {
        return Err(CoordinatorError::Cancelled);
    }
    if !started || !terminal || (require_progress && !observed_progress) {
        return Err(if require_progress {
            CoordinatorError::Progress
        } else {
            CoordinatorError::Protocol
        });
    }
    match result.expect("terminal event sets result") {
        Ok(()) => Ok(TransferOutcome::Success {
            staged,
            observed_progress,
        }),
        Err(failure) => Ok(TransferOutcome::Failed { staged, failure }),
    }
}

fn failure_code(error: CoordinatorError) -> &'static str {
    match error {
        CoordinatorError::Contract => "contract",
        CoordinatorError::Gateway(error) => error.code(),
        CoordinatorError::Filesystem(error) => error.code(),
        CoordinatorError::Store(error) => error.code(),
        CoordinatorError::Protocol => "native_protocol",
        CoordinatorError::Progress => "progress",
        CoordinatorError::ConcurrentRequestLimit => "concurrent_request_limit",
        CoordinatorError::Cancelled => "cancellation",
        CoordinatorError::InjectedCrash(_) => "injected_crash",
    }
}
