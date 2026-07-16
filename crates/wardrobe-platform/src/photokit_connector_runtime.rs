use crate::backup_repository::format_timestamp;
use crate::{
    photokit_operation_id, Database, MacOsPhotoKitKeychain, PhotoKitCoordinator,
    PhotoKitCoordinatorError, PhotoKitKeyError, PhotoKitKeyPort, PhotoKitNativeError,
    PhotoKitNativePort, PhotoKitRepository, PlatformError, ProductionPhotoKitNativePort,
    CONFIGURE_PHOTOKIT_COMMAND, SYNC_PHOTOKIT_COMMAND,
};
use rusqlite::OptionalExtension;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use wardrobe_core::{
    BeginPhotoKitSetupV1Request, BeginPhotoKitSetupV1Response, ConfigurePhotoKitScopeV1Request,
    ConfigurePhotoKitScopeV1Response, DisablePhotoKitV1Request, DisablePhotoKitV1Response,
    GetPhotoKitConnectorV1Request, GetPhotoKitConnectorV1Response, PhotoKitAlbumCandidateV1,
    PhotoKitAuthorizationV1, PhotoKitConnectorPort, PhotoKitConnectorPortError,
    PhotoKitConnectorPortErrorKind, PhotoKitConnectorPortResult, PhotoKitReconcileTriggerV1,
    PhotoKitReconciliationFenceV1, PhotoKitSelectionTokenV1, PhotoKitSetupSessionIdV1,
    ReplayStatusV1, RequestId, SyncPhotoKitV1Request, SyncPhotoKitV1Response, Validate,
    MAX_PHOTOKIT_ALBUM_CANDIDATES, MAX_PHOTOKIT_ALBUM_LABEL_CHARS, SCHEMA_VERSION_V1,
};

const SETUP_SESSION_MILLIS: i64 = 10 * 60 * 1000;
const MAX_SETUP_SESSIONS: usize = 16;
const MAX_BEGIN_REPLAYS: usize = 64;

#[derive(Clone)]
pub struct ProductionPhotoKitConnector {
    runtime: Arc<
        PhotoKitConnectorRuntime<ProductionPhotoKitNativePort, MacOsPhotoKitKeychain, SystemClock>,
    >,
}

impl ProductionPhotoKitConnector {
    pub fn production(database: Database) -> PhotoKitConnectorPortResult<Self> {
        let native = ProductionPhotoKitNativePort::new().map_err(map_native_error)?;
        Ok(Self {
            runtime: Arc::new(PhotoKitConnectorRuntime::new(
                PhotoKitCoordinator::new(
                    PhotoKitRepository::new(database),
                    native,
                    MacOsPhotoKitKeychain,
                ),
                SystemClock,
            )),
        })
    }

    pub fn startup_reconcile(&self) -> PhotoKitConnectorPortResult<Option<SyncPhotoKitV1Response>> {
        self.runtime.startup_reconcile()
    }
}

impl PhotoKitConnectorPort for ProductionPhotoKitConnector {
    fn snapshot(
        &self,
        request: &GetPhotoKitConnectorV1Request,
    ) -> PhotoKitConnectorPortResult<GetPhotoKitConnectorV1Response> {
        self.runtime.snapshot(request)
    }

    fn begin_setup(
        &self,
        request: &BeginPhotoKitSetupV1Request,
    ) -> PhotoKitConnectorPortResult<BeginPhotoKitSetupV1Response> {
        self.runtime.begin_setup(request)
    }

    fn configure_scope(
        &self,
        request: &ConfigurePhotoKitScopeV1Request,
    ) -> PhotoKitConnectorPortResult<ConfigurePhotoKitScopeV1Response> {
        self.runtime.configure_scope(request)
    }

    fn reconcile(
        &self,
        request: &SyncPhotoKitV1Request,
        trigger: PhotoKitReconcileTriggerV1,
    ) -> PhotoKitConnectorPortResult<SyncPhotoKitV1Response> {
        self.runtime.reconcile(request, trigger)
    }

    fn disable(
        &self,
        request: &DisablePhotoKitV1Request,
    ) -> PhotoKitConnectorPortResult<DisablePhotoKitV1Response> {
        self.runtime.disable(request)
    }
}

trait PhotoKitClock: Send + Sync {
    fn now_ms(&self) -> Result<i64, PhotoKitConnectorPortError>;
}

#[derive(Clone, Copy)]
struct SystemClock;

impl PhotoKitClock for SystemClock {
    fn now_ms(&self) -> Result<i64, PhotoKitConnectorPortError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| port_error(PhotoKitConnectorPortErrorKind::Internal))?;
        i64::try_from(elapsed.as_millis())
            .map_err(|_| port_error(PhotoKitConnectorPortErrorKind::Internal))
    }
}

struct PhotoKitConnectorRuntime<N, K, C> {
    state: Mutex<RuntimeState<N, K>>,
    clock: C,
}

struct RuntimeState<N, K> {
    coordinator: PhotoKitCoordinator<N, K>,
    setup: SetupMemory,
}

#[derive(Default)]
struct SetupMemory {
    sessions: HashMap<String, SetupSession>,
    session_order: VecDeque<String>,
    begin_replays: HashMap<String, BeginReplay>,
    begin_order: VecDeque<String>,
    consumed_tokens: HashMap<String, i64>,
}

struct SetupSession {
    expires_at_ms: i64,
    albums_by_token: HashMap<String, String>,
}

struct BeginReplay {
    envelope_hash: String,
    expires_at_ms: i64,
    response: BeginPhotoKitSetupV1Response,
}

struct DurableReceipt<T> {
    enrollment_epoch: Option<String>,
    operation_id: Option<String>,
    operation_request_id: Option<String>,
    operation_enrollment_epoch: Option<String>,
    operation_trigger: Option<String>,
    operation_reconciliation_fence: Option<u64>,
    response: T,
}

#[derive(Serialize)]
struct SyncEnvelope<'a> {
    request: &'a SyncPhotoKitV1Request,
    trigger: PhotoKitReconcileTriggerV1,
}

impl<N, K, C> PhotoKitConnectorRuntime<N, K, C>
where
    N: PhotoKitNativePort + Send,
    K: PhotoKitKeyPort + Send,
    C: PhotoKitClock,
{
    fn new(coordinator: PhotoKitCoordinator<N, K>, clock: C) -> Self {
        Self {
            state: Mutex::new(RuntimeState {
                coordinator,
                setup: SetupMemory::default(),
            }),
            clock,
        }
    }

    fn lock(&self) -> PhotoKitConnectorPortResult<MutexGuard<'_, RuntimeState<N, K>>> {
        self.state
            .lock()
            .map_err(|_| port_error(PhotoKitConnectorPortErrorKind::Internal))
    }

    fn snapshot(
        &self,
        request: &GetPhotoKitConnectorV1Request,
    ) -> PhotoKitConnectorPortResult<GetPhotoKitConnectorV1Response> {
        validate_contract(request)?;
        let mut state = self.lock()?;
        let authorization = state
            .coordinator
            .native_mut()
            .authorization(false)
            .map_err(map_native_error)?;
        if authorization != PhotoKitAuthorizationV1::Authorized {
            state.setup.invalidate_sessions();
        }
        let snapshot = state
            .coordinator
            .repository()
            .snapshot(authorization)
            .map_err(map_platform_error)?;
        Ok(GetPhotoKitConnectorV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            snapshot,
        })
    }

    fn begin_setup(
        &self,
        request: &BeginPhotoKitSetupV1Request,
    ) -> PhotoKitConnectorPortResult<BeginPhotoKitSetupV1Response> {
        validate_contract(request)?;
        let envelope_hash = envelope_hash(request)?;
        let now_ms = self.clock.now_ms()?;
        let mut state = self.lock()?;
        state.setup.expire(now_ms);
        let request_id = request.request_id.to_string();
        if let Some(replay) = state.setup.begin_replays.get(&request_id) {
            if replay.envelope_hash != envelope_hash {
                return Err(port_error(PhotoKitConnectorPortErrorKind::Conflict));
            }
            let mut response = replay.response.clone();
            response.replay_status = ReplayStatusV1::Replayed;
            return Ok(response);
        }

        let authorization = state
            .coordinator
            .native_mut()
            .authorization(true)
            .map_err(map_native_error)?;
        if authorization != PhotoKitAuthorizationV1::Authorized {
            state.setup.invalidate_sessions();
        }
        let snapshot = state
            .coordinator
            .repository()
            .snapshot(authorization)
            .map_err(map_platform_error)?;

        let (setup_session_id, expires_at, album_candidates, replay_expires_at_ms) =
            if authorization == PhotoKitAuthorizationV1::Authorized {
                let albums = state
                    .coordinator
                    .native_mut()
                    .list_regular_albums()
                    .map_err(map_native_error)?;
                if albums.len() > MAX_PHOTOKIT_ALBUM_CANDIDATES {
                    return Err(port_error(PhotoKitConnectorPortErrorKind::DataIntegrity));
                }
                let expires_at_ms = self
                    .clock
                    .now_ms()?
                    .checked_add(SETUP_SESSION_MILLIS)
                    .ok_or_else(|| port_error(PhotoKitConnectorPortErrorKind::Internal))?;
                let session_id = PhotoKitSetupSessionIdV1::new_v4();
                let mut albums_by_token = HashMap::with_capacity(albums.len());
                let mut candidates = Vec::with_capacity(albums.len());
                for album in albums {
                    if album.album_locator.is_empty() || album.album_locator.len() > 1024 {
                        return Err(port_error(PhotoKitConnectorPortErrorKind::DataIntegrity));
                    }
                    let token = loop {
                        let candidate = PhotoKitSelectionTokenV1::new(
                            uuid::Uuid::new_v4().hyphenated().to_string(),
                        )
                        .map_err(|_| port_error(PhotoKitConnectorPortErrorKind::Internal))?;
                        if !albums_by_token.contains_key(candidate.expose_process_token()) {
                            break candidate;
                        }
                    };
                    let candidate = PhotoKitAlbumCandidateV1 {
                        selection_token: token.clone(),
                        display_label: album.label,
                    };
                    if candidate.display_label.chars().count() > MAX_PHOTOKIT_ALBUM_LABEL_CHARS
                        || candidate.validate().is_err()
                    {
                        return Err(port_error(PhotoKitConnectorPortErrorKind::DataIntegrity));
                    }
                    albums_by_token
                        .insert(token.expose_process_token().to_owned(), album.album_locator);
                    candidates.push(candidate);
                }
                state.setup.insert_session(
                    session_id.to_string(),
                    SetupSession {
                        expires_at_ms,
                        albums_by_token,
                    },
                );
                (
                    Some(session_id),
                    Some(format_timestamp(expires_at_ms).map_err(map_platform_error)?),
                    candidates,
                    expires_at_ms,
                )
            } else {
                let replay_expires_at_ms =
                    self.clock
                        .now_ms()?
                        .checked_add(SETUP_SESSION_MILLIS)
                        .ok_or_else(|| port_error(PhotoKitConnectorPortErrorKind::Internal))?;
                (None, None, Vec::new(), replay_expires_at_ms)
            };

        let response = BeginPhotoKitSetupV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            snapshot,
            setup_session_id,
            expires_at,
            album_candidates,
            replay_status: ReplayStatusV1::Created,
        };
        validate_response(&response)?;
        state.setup.insert_begin_replay(
            request_id,
            BeginReplay {
                envelope_hash,
                expires_at_ms: replay_expires_at_ms,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    fn configure_scope(
        &self,
        request: &ConfigurePhotoKitScopeV1Request,
    ) -> PhotoKitConnectorPortResult<ConfigurePhotoKitScopeV1Response> {
        validate_contract(request)?;
        let envelope_hash = envelope_hash(request)?;
        let now_ms = self.clock.now_ms()?;
        let mut state = self.lock()?;
        if let Some(mut response) =
            replay_configure_receipt(state.coordinator.repository(), request, &envelope_hash)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            validate_response(&response)?;
            return Ok(response);
        }

        state.setup.expire(now_ms);
        let token = request.selection_token.expose_process_token();
        if state.setup.consumed_tokens.contains_key(token) {
            return Err(port_error(
                PhotoKitConnectorPortErrorKind::SelectionTokenConsumed,
            ));
        }
        let session_id = request.setup_session_id.to_string();
        let Some(session) = state.setup.sessions.get(&session_id) else {
            return Err(port_error(PhotoKitConnectorPortErrorKind::SessionExpired));
        };
        if session.expires_at_ms <= now_ms {
            state.setup.sessions.remove(&session_id);
            return Err(port_error(PhotoKitConnectorPortErrorKind::SessionExpired));
        }
        if !session.albums_by_token.contains_key(token) {
            return Err(port_error(PhotoKitConnectorPortErrorKind::NotFound));
        }

        let authorization = state
            .coordinator
            .native_mut()
            .authorization(false)
            .map_err(map_native_error)?;
        if authorization != PhotoKitAuthorizationV1::Authorized {
            state.setup.invalidate_sessions();
            return Err(port_error(PhotoKitConnectorPortErrorKind::PermissionDenied));
        }
        let session = state
            .setup
            .sessions
            .remove(&session_id)
            .ok_or_else(|| port_error(PhotoKitConnectorPortErrorKind::SessionExpired))?;
        let album_locator = session
            .albums_by_token
            .get(token)
            .cloned()
            .ok_or_else(|| port_error(PhotoKitConnectorPortErrorKind::NotFound))?;
        state
            .setup
            .consumed_tokens
            .insert(token.to_owned(), session.expires_at_ms);

        let response = state
            .coordinator
            .configure_scope_command(request, &envelope_hash, &album_locator, now_ms)
            .map_err(map_coordinator_error)?;
        validate_response(&response)?;
        let stored =
            replay_configure_receipt(state.coordinator.repository(), request, &envelope_hash)?
                .ok_or_else(data_integrity_error)?;
        if stored != response {
            return Err(data_integrity_error());
        }
        Ok(stored)
    }

    fn reconcile(
        &self,
        request: &SyncPhotoKitV1Request,
        trigger: PhotoKitReconcileTriggerV1,
    ) -> PhotoKitConnectorPortResult<SyncPhotoKitV1Response> {
        validate_contract(request)?;
        let envelope_hash = envelope_hash(&SyncEnvelope { request, trigger })?;
        let now_ms = self.clock.now_ms()?;
        let mut state = self.lock()?;
        if let Some(mut response) = replay_sync_receipt(
            state.coordinator.repository(),
            request,
            trigger,
            &envelope_hash,
        )? {
            response.replay_status = ReplayStatusV1::Replayed;
            validate_response(&response)?;
            return Ok(response);
        }

        let publication = state
            .coordinator
            .reconcile(&request.request_id.to_string(), trigger, now_ms)
            .map_err(map_coordinator_error)?;
        let response = SyncPhotoKitV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            operation_id: photokit_operation_id(&publication.operation_id)
                .map_err(map_platform_error)?,
            trigger,
            reconciliation_fence: PhotoKitReconciliationFenceV1::new(
                publication.reconciliation_fence,
            )
            .map_err(|_| port_error(PhotoKitConnectorPortErrorKind::DataIntegrity))?,
            snapshot: publication.snapshot,
            replay_status: if publication.replayed {
                ReplayStatusV1::Replayed
            } else {
                ReplayStatusV1::Created
            },
        };
        validate_response(&response)?;
        let enrollment_epoch = response
            .snapshot
            .enrollment_epoch
            .map(|value| value.to_string())
            .ok_or_else(|| port_error(PhotoKitConnectorPortErrorKind::DataIntegrity))?;
        let recorded = state
            .coordinator
            .repository()
            .record_command_receipt(
                &request.request_id.to_string(),
                SYNC_PHOTOKIT_COMMAND,
                &envelope_hash,
                Some(&enrollment_epoch),
                Some(&publication.operation_id),
                &response,
                now_ms,
            )
            .map_err(map_platform_error)?;
        validate_response(&recorded)?;
        let stored = replay_sync_receipt(
            state.coordinator.repository(),
            request,
            trigger,
            &envelope_hash,
        )?
        .ok_or_else(data_integrity_error)?;
        if stored != recorded {
            return Err(data_integrity_error());
        }
        Ok(stored)
    }

    fn disable(
        &self,
        request: &DisablePhotoKitV1Request,
    ) -> PhotoKitConnectorPortResult<DisablePhotoKitV1Response> {
        validate_contract(request)?;
        let envelope_hash = envelope_hash(request)?;
        let now_ms = self.clock.now_ms()?;
        let mut state = self.lock()?;
        if let Some(mut response) =
            replay_disable_receipt(state.coordinator.repository(), request, &envelope_hash)?
        {
            state.setup.invalidate_sessions();
            response.replay_status = ReplayStatusV1::Replayed;
            validate_response(&response)?;
            return Ok(response);
        }
        let response = state
            .coordinator
            .repository()
            .disable_command(request, &envelope_hash, now_ms)
            .map_err(map_platform_error)?;
        state.setup.invalidate_sessions();
        validate_response(&response)?;
        let stored =
            replay_disable_receipt(state.coordinator.repository(), request, &envelope_hash)?
                .ok_or_else(data_integrity_error)?;
        if stored != response {
            return Err(data_integrity_error());
        }
        Ok(stored)
    }

    fn startup_reconcile(&self) -> PhotoKitConnectorPortResult<Option<SyncPhotoKitV1Response>> {
        let now_ms = self.clock.now_ms()?;
        {
            let mut state = self.lock()?;
            state
                .coordinator
                .recover(now_ms)
                .map_err(map_coordinator_error)?;
            let authorization = state
                .coordinator
                .native_mut()
                .authorization(false)
                .map_err(map_native_error)?;
            let snapshot = state
                .coordinator
                .repository()
                .snapshot(authorization)
                .map_err(map_platform_error)?;
            if snapshot.enrollment_epoch.is_none() {
                return Ok(None);
            }
        }
        let request = SyncPhotoKitV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
        };
        self.reconcile(&request, PhotoKitReconcileTriggerV1::Startup)
            .map(Some)
    }
}

impl SetupMemory {
    fn expire(&mut self, now_ms: i64) {
        self.sessions
            .retain(|_, session| session.expires_at_ms > now_ms);
        self.begin_replays
            .retain(|_, replay| replay.expires_at_ms > now_ms);
        self.consumed_tokens
            .retain(|_, expires_at_ms| *expires_at_ms > now_ms);
        self.session_order
            .retain(|id| self.sessions.contains_key(id));
        self.begin_order
            .retain(|id| self.begin_replays.contains_key(id));
    }

    fn invalidate_sessions(&mut self) {
        self.sessions.clear();
        self.session_order.clear();
    }

    fn insert_session(&mut self, id: String, session: SetupSession) {
        while self.sessions.len() >= MAX_SETUP_SESSIONS {
            if let Some(oldest) = self.session_order.pop_front() {
                self.sessions.remove(&oldest);
            }
        }
        self.session_order.push_back(id.clone());
        self.sessions.insert(id, session);
    }

    fn insert_begin_replay(&mut self, request_id: String, replay: BeginReplay) {
        while self.begin_replays.len() >= MAX_BEGIN_REPLAYS {
            if let Some(oldest) = self.begin_order.pop_front() {
                self.begin_replays.remove(&oldest);
            }
        }
        self.begin_order.push_back(request_id.clone());
        self.begin_replays.insert(request_id, replay);
    }
}

fn envelope_hash<T: Serialize>(value: &T) -> PhotoKitConnectorPortResult<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| port_error(PhotoKitConnectorPortErrorKind::Internal))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn replay_configure_receipt(
    repository: &PhotoKitRepository,
    request: &ConfigurePhotoKitScopeV1Request,
    expected_envelope_hash: &str,
) -> PhotoKitConnectorPortResult<Option<ConfigurePhotoKitScopeV1Response>> {
    let Some(receipt) = load_durable_receipt::<ConfigurePhotoKitScopeV1Response>(
        repository,
        &request.request_id.to_string(),
        CONFIGURE_PHOTOKIT_COMMAND,
        expected_envelope_hash,
    )?
    else {
        return Ok(None);
    };
    let response = receipt.response;
    validate_response(&response)?;
    let response_enrollment = response
        .snapshot
        .enrollment_epoch
        .map(|value| value.to_string())
        .ok_or_else(data_integrity_error)?;
    if response.request_id != request.request_id
        || response.replay_status != ReplayStatusV1::Created
        || response.snapshot.allow_icloud_downloads != request.allow_icloud_downloads
        || receipt.enrollment_epoch.as_deref() != Some(response_enrollment.as_str())
        || receipt.operation_id.is_some()
        || receipt.operation_request_id.is_some()
        || receipt.operation_enrollment_epoch.is_some()
        || receipt.operation_trigger.is_some()
    {
        return Err(data_integrity_error());
    }
    Ok(Some(response))
}

fn replay_sync_receipt(
    repository: &PhotoKitRepository,
    request: &SyncPhotoKitV1Request,
    trigger: PhotoKitReconcileTriggerV1,
    expected_envelope_hash: &str,
) -> PhotoKitConnectorPortResult<Option<SyncPhotoKitV1Response>> {
    let Some(receipt) = load_durable_receipt::<SyncPhotoKitV1Response>(
        repository,
        &request.request_id.to_string(),
        SYNC_PHOTOKIT_COMMAND,
        expected_envelope_hash,
    )?
    else {
        return Ok(None);
    };
    let response = receipt.response;
    validate_response(&response)?;
    let response_enrollment = response
        .snapshot
        .enrollment_epoch
        .map(|value| value.to_string())
        .ok_or_else(data_integrity_error)?;
    let response_operation = response.operation_id.to_string();
    let request_id = request.request_id.to_string();
    let expected_trigger = trigger_name(trigger);
    let publication = repository
        .replay_publication(&request_id, trigger)
        .map_err(|_| data_integrity_error())?
        .ok_or_else(data_integrity_error)?;
    if response.request_id != request.request_id
        || response.trigger != trigger
        || receipt.enrollment_epoch.as_deref() != Some(response_enrollment.as_str())
        || receipt.operation_id.as_deref() != Some(response_operation.as_str())
        || receipt.operation_request_id.as_deref() != Some(request_id.as_str())
        || receipt.operation_enrollment_epoch.as_deref() != receipt.enrollment_epoch.as_deref()
        || receipt.operation_trigger.as_deref() != Some(expected_trigger)
        || receipt.operation_reconciliation_fence != Some(response.reconciliation_fence.get())
        || publication.operation_id != response_operation
        || publication.reconciliation_fence != response.reconciliation_fence.get()
        || publication.snapshot != response.snapshot
    {
        return Err(data_integrity_error());
    }
    Ok(Some(response))
}

fn replay_disable_receipt(
    repository: &PhotoKitRepository,
    request: &DisablePhotoKitV1Request,
    expected_envelope_hash: &str,
) -> PhotoKitConnectorPortResult<Option<DisablePhotoKitV1Response>> {
    let Some(receipt) = load_durable_receipt::<DisablePhotoKitV1Response>(
        repository,
        &request.request_id.to_string(),
        crate::DISABLE_PHOTOKIT_COMMAND,
        expected_envelope_hash,
    )?
    else {
        return Ok(None);
    };
    let response = receipt.response;
    validate_response(&response)?;
    let response_enrollment = response.disabled_enrollment_epoch.to_string();
    if response.request_id != request.request_id
        || response.replay_status != ReplayStatusV1::Created
        || response.photokit_revision.get() <= request.expected_photokit_revision.get()
        || receipt.enrollment_epoch.as_deref() != Some(response_enrollment.as_str())
        || receipt.operation_id.is_some()
        || receipt.operation_request_id.is_some()
        || receipt.operation_enrollment_epoch.is_some()
        || receipt.operation_trigger.is_some()
    {
        return Err(data_integrity_error());
    }
    Ok(Some(response))
}

fn load_durable_receipt<T: DeserializeOwned>(
    repository: &PhotoKitRepository,
    request_id: &str,
    expected_command: &str,
    expected_envelope_hash: &str,
) -> PhotoKitConnectorPortResult<Option<DurableReceipt<T>>> {
    let connection = repository
        .database()
        .connection()
        .map_err(map_platform_error)?;
    let row = connection
        .query_row(
            "SELECT receipt.command_name, receipt.envelope_hash,
                    receipt.enrollment_epoch, receipt.operation_id,
                    receipt.response_json, operation.request_id,
                    operation.enrollment_epoch, operation.trigger_kind,
                    operation.reconciliation_fence
             FROM photokit_command_receipts receipt
             LEFT JOIN photokit_operations operation
               ON operation.operation_id = receipt.operation_id
             WHERE receipt.request_id = ?1",
            [request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(|error| map_platform_error(PlatformError::Sqlite(error)))?;
    let Some((
        command,
        envelope_hash,
        enrollment_epoch,
        operation_id,
        response_json,
        operation_request_id,
        operation_enrollment_epoch,
        operation_trigger,
        operation_reconciliation_fence,
    )) = row
    else {
        return Ok(None);
    };
    if command != expected_command || envelope_hash != expected_envelope_hash {
        return Err(port_error(PhotoKitConnectorPortErrorKind::Conflict));
    }
    let response = serde_json::from_str(&response_json).map_err(|_| data_integrity_error())?;
    Ok(Some(DurableReceipt {
        enrollment_epoch,
        operation_id,
        operation_request_id,
        operation_enrollment_epoch,
        operation_trigger,
        operation_reconciliation_fence: operation_reconciliation_fence
            .and_then(|value| u64::try_from(value).ok()),
        response,
    }))
}

const fn trigger_name(trigger: PhotoKitReconcileTriggerV1) -> &'static str {
    match trigger {
        PhotoKitReconcileTriggerV1::Startup => "startup",
        PhotoKitReconcileTriggerV1::User => "user",
        PhotoKitReconcileTriggerV1::LibraryChange => "library_change",
    }
}

fn validate_contract<T: Validate>(value: &T) -> PhotoKitConnectorPortResult<()> {
    value
        .validate()
        .map_err(|_| port_error(PhotoKitConnectorPortErrorKind::DataIntegrity))
}

const fn data_integrity_error() -> PhotoKitConnectorPortError {
    port_error(PhotoKitConnectorPortErrorKind::DataIntegrity)
}

fn validate_response<T: Validate>(value: &T) -> PhotoKitConnectorPortResult<()> {
    value
        .validate()
        .map_err(|_| port_error(PhotoKitConnectorPortErrorKind::DataIntegrity))
}

fn map_coordinator_error(error: PhotoKitCoordinatorError) -> PhotoKitConnectorPortError {
    match error {
        PhotoKitCoordinatorError::Platform(error) => map_platform_error(error),
        PhotoKitCoordinatorError::Key(error) => map_key_error(error),
        PhotoKitCoordinatorError::Native(error) => map_native_error(error),
    }
}

fn map_platform_error(error: PlatformError) -> PhotoKitConnectorPortError {
    let kind = match error {
        PlatformError::Conflict("photokit_not_configured") => {
            PhotoKitConnectorPortErrorKind::InvalidState
        }
        PlatformError::Conflict(_) => PhotoKitConnectorPortErrorKind::Conflict,
        PlatformError::Corrupt(_) => PhotoKitConnectorPortErrorKind::DataIntegrity,
        PlatformError::InvalidInput("photokit_scope_too_large")
        | PlatformError::InvalidInput("photokit_observation_ordinal") => {
            PhotoKitConnectorPortErrorKind::ScopeTooLarge
        }
        PlatformError::InvalidInput(_) => PhotoKitConnectorPortErrorKind::DataIntegrity,
        PlatformError::Keychain(_) => PhotoKitConnectorPortErrorKind::CredentialUnavailable,
        PlatformError::Unsupported(_) => PhotoKitConnectorPortErrorKind::Unavailable,
        PlatformError::Io(_)
        | PlatformError::Json(_)
        | PlatformError::LeaseLost
        | PlatformError::Sqlite(_) => PhotoKitConnectorPortErrorKind::Internal,
    };
    port_error(kind)
}

fn map_key_error(error: PhotoKitKeyError) -> PhotoKitConnectorPortError {
    let kind = match error {
        PhotoKitKeyError::NotFound | PhotoKitKeyError::Locked | PhotoKitKeyError::Unavailable => {
            PhotoKitConnectorPortErrorKind::CredentialUnavailable
        }
        PhotoKitKeyError::Integrity => PhotoKitConnectorPortErrorKind::DataIntegrity,
        PhotoKitKeyError::Internal => PhotoKitConnectorPortErrorKind::Internal,
    };
    port_error(kind)
}

fn map_native_error(error: PhotoKitNativeError) -> PhotoKitConnectorPortError {
    let kind = match error {
        PhotoKitNativeError::Unavailable | PhotoKitNativeError::Cancelled => {
            PhotoKitConnectorPortErrorKind::Unavailable
        }
        PhotoKitNativeError::InvalidResponse | PhotoKitNativeError::ImageValidation => {
            PhotoKitConnectorPortErrorKind::DataIntegrity
        }
        PhotoKitNativeError::SinkRejected => PhotoKitConnectorPortErrorKind::ScopeTooLarge,
    };
    port_error(kind)
}

const fn port_error(kind: PhotoKitConnectorPortErrorKind) -> PhotoKitConnectorPortError {
    PhotoKitConnectorPortError::new(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PhotoKitEnumerationSink, PhotoKitEnumerationTerminal, PhotoKitNativeAlbum,
        PhotoKitNativeAsset, PhotoKitNativeByteSink, PhotoKitNativeResource, PhotoKitRootKey,
        PhotoKitTransferTerminal, PhotoKitValidatedImage, PrivateAppPaths,
    };
    use rusqlite::Connection;
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::sync::atomic::{AtomicI64, Ordering};

    #[derive(Clone)]
    struct TestClock(Arc<AtomicI64>);

    impl TestClock {
        fn new(now_ms: i64) -> Self {
            Self(Arc::new(AtomicI64::new(now_ms)))
        }

        fn set(&self, now_ms: i64) {
            self.0.store(now_ms, Ordering::SeqCst);
        }
    }

    impl PhotoKitClock for TestClock {
        fn now_ms(&self) -> Result<i64, PhotoKitConnectorPortError> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Clone, Default)]
    struct TestKeys {
        values: Arc<Mutex<BTreeMap<String, [u8; 32]>>>,
    }

    impl PhotoKitKeyPort for TestKeys {
        fn create_root_key(
            &self,
            key_reference: &str,
        ) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
            let bytes = [0x3c; 32];
            self.values
                .lock()
                .unwrap()
                .insert(key_reference.to_owned(), bytes);
            Ok(PhotoKitRootKey::from_bytes(bytes))
        }

        fn load_root_key(
            &self,
            key_reference: &str,
            allow_authentication_ui: bool,
        ) -> Result<PhotoKitRootKey, PhotoKitKeyError> {
            assert!(!allow_authentication_ui);
            self.values
                .lock()
                .unwrap()
                .get(key_reference)
                .copied()
                .map(PhotoKitRootKey::from_bytes)
                .ok_or(PhotoKitKeyError::NotFound)
        }

        fn delete_root_key(&self, key_reference: &str) -> Result<(), PhotoKitKeyError> {
            self.values.lock().unwrap().remove(key_reference);
            Ok(())
        }
    }

    struct TestNative {
        authorization: PhotoKitAuthorizationV1,
        albums: Vec<PhotoKitNativeAlbum>,
        assets: Vec<PhotoKitNativeAsset>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl TestNative {
        fn authorized(calls: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                authorization: PhotoKitAuthorizationV1::Authorized,
                albums: vec![PhotoKitNativeAlbum {
                    album_locator: "native-album-private".to_owned(),
                    label: "Private Album".to_owned(),
                }],
                assets: Vec::new(),
                calls,
            }
        }
    }

    impl PhotoKitNativePort for TestNative {
        fn authorization(
            &mut self,
            request_authorization: bool,
        ) -> Result<PhotoKitAuthorizationV1, PhotoKitNativeError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("authorization:{request_authorization}"));
            Ok(self.authorization)
        }

        fn list_regular_albums(&mut self) -> Result<Vec<PhotoKitNativeAlbum>, PhotoKitNativeError> {
            self.calls.lock().unwrap().push("list".to_owned());
            Ok(self.albums.clone())
        }

        fn enumerate_regular_album(
            &mut self,
            album_locator: &str,
            _operation: &crate::PhotoKitOperation,
            sink: &mut dyn PhotoKitEnumerationSink,
        ) -> Result<PhotoKitEnumerationTerminal, PhotoKitNativeError> {
            assert_eq!(album_locator, "native-album-private");
            self.calls.lock().unwrap().push("enumerate".to_owned());
            for asset in self.assets.clone() {
                sink.observe(asset)
                    .map_err(|_| PhotoKitNativeError::SinkRejected)?;
            }
            Ok(PhotoKitEnumerationTerminal::Complete)
        }

        fn transfer_resource(
            &mut self,
            _operation: &crate::PhotoKitOperation,
            operation_resource_token: &str,
            network_access_allowed: bool,
            sink: &mut dyn PhotoKitNativeByteSink,
        ) -> Result<PhotoKitTransferTerminal, PhotoKitNativeError> {
            assert_eq!(operation_resource_token, "operation-resource-token");
            assert!(!network_access_allowed);
            sink.write_chunk(b"bounded-image")
                .map_err(|_| PhotoKitNativeError::SinkRejected)?;
            Ok(PhotoKitTransferTerminal::Complete)
        }

        fn validate_image(
            &mut self,
            duplicated_read_only_file: File,
            resource_uti: &str,
        ) -> Result<PhotoKitValidatedImage, PhotoKitNativeError> {
            assert_eq!(resource_uti, "public.jpeg");
            assert_eq!(
                duplicated_read_only_file.metadata().unwrap().len(),
                b"bounded-image".len() as u64
            );
            Ok(PhotoKitValidatedImage {
                pixel_width: 1,
                pixel_height: 1,
                frame_count: 1,
            })
        }
    }

    type TestRuntime = PhotoKitConnectorRuntime<TestNative, TestKeys, TestClock>;

    fn runtime(
        with_asset: bool,
    ) -> (
        tempfile::TempDir,
        PrivateAppPaths,
        Arc<TestRuntime>,
        TestClock,
        Arc<Mutex<Vec<String>>>,
    ) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut native = TestNative::authorized(calls.clone());
        if with_asset {
            native.assets.push(PhotoKitNativeAsset {
                asset_locator: "native-asset-private".to_owned(),
                primary_resource: Some(PhotoKitNativeResource {
                    operation_resource_token: "operation-resource-token".to_owned(),
                    resource_uti: "public.jpeg".to_owned(),
                }),
            });
        }
        let clock = TestClock::new(10_000);
        let runtime = Arc::new(PhotoKitConnectorRuntime::new(
            PhotoKitCoordinator::new(
                PhotoKitRepository::new(database),
                native,
                TestKeys::default(),
            ),
            clock.clone(),
        ));
        (temporary, paths, runtime, clock, calls)
    }

    fn begin_request() -> BeginPhotoKitSetupV1Request {
        BeginPhotoKitSetupV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
        }
    }

    fn begin(
        runtime: &TestRuntime,
    ) -> (
        BeginPhotoKitSetupV1Request,
        PhotoKitSetupSessionIdV1,
        PhotoKitSelectionTokenV1,
    ) {
        let request = begin_request();
        let response = runtime.begin_setup(&request).unwrap();
        (
            request,
            response.setup_session_id.unwrap(),
            response.album_candidates[0].selection_token.clone(),
        )
    }

    fn configure_request(
        session: PhotoKitSetupSessionIdV1,
        token: PhotoKitSelectionTokenV1,
    ) -> ConfigurePhotoKitScopeV1Request {
        ConfigurePhotoKitScopeV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            setup_session_id: session,
            selection_token: token,
            allow_icloud_downloads: false,
        }
    }

    fn configure(runtime: &TestRuntime) -> ConfigurePhotoKitScopeV1Response {
        let (_, session, token) = begin(runtime);
        runtime
            .configure_scope(&configure_request(session, token))
            .unwrap()
    }

    fn mutate_receipt_response(
        paths: &PrivateAppPaths,
        request_id: RequestId,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) {
        let connection = Connection::open(&paths.database).unwrap();
        connection
            .execute_batch("DROP TRIGGER photokit_command_receipts_no_update;")
            .unwrap();
        let response_json: String = connection
            .query_row(
                "SELECT response_json FROM photokit_command_receipts WHERE request_id = ?1",
                [request_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        let mut response: serde_json::Value = serde_json::from_str(&response_json).unwrap();
        mutate(&mut response);
        connection
            .execute(
                "UPDATE photokit_command_receipts SET response_json = ?2 WHERE request_id = ?1",
                rusqlite::params![request_id.to_string(), response.to_string()],
            )
            .unwrap();
    }

    fn mutate_receipt_metadata(
        paths: &PrivateAppPaths,
        request_id: RequestId,
        enrollment_epoch: Option<&str>,
        operation_id: Option<&str>,
    ) {
        let connection = Connection::open(&paths.database).unwrap();
        connection
            .execute_batch("DROP TRIGGER photokit_command_receipts_no_update;")
            .unwrap();
        connection
            .execute(
                "UPDATE photokit_command_receipts
                 SET enrollment_epoch = ?2, operation_id = ?3
                 WHERE request_id = ?1",
                rusqlite::params![request_id.to_string(), enrollment_epoch, operation_id],
            )
            .unwrap();
    }

    fn assert_data_integrity<T: std::fmt::Debug>(result: PhotoKitConnectorPortResult<T>) {
        assert_eq!(
            result.unwrap_err().kind,
            PhotoKitConnectorPortErrorKind::DataIntegrity
        );
    }

    #[test]
    fn setup_replay_is_bounded_and_sessions_expire() {
        let (_temporary, _paths, runtime, clock, calls) = runtime(false);
        let (request, session, token) = begin(&runtime);
        let replay = runtime.begin_setup(&request).unwrap();
        assert_eq!(replay.replay_status, ReplayStatusV1::Replayed);
        assert_eq!(calls.lock().unwrap().len(), 2);

        clock.set(10_000 + SETUP_SESSION_MILLIS + 1);
        let error = runtime
            .configure_scope(&configure_request(session, token))
            .unwrap_err();
        assert_eq!(error.kind, PhotoKitConnectorPortErrorKind::SessionExpired);
    }

    #[test]
    fn configure_consumes_tokens_replays_exactly_and_rejects_changed_envelopes() {
        let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
        let (_begin_request, session, token) = begin(&runtime);
        let request = configure_request(session, token.clone());
        let created = runtime.configure_scope(&request).unwrap();
        let replay = runtime.configure_scope(&request).unwrap();
        assert_eq!(replay.replay_status, ReplayStatusV1::Replayed);
        assert_eq!(created.snapshot, replay.snapshot);

        let consumed = runtime
            .configure_scope(&ConfigurePhotoKitScopeV1Request {
                request_id: RequestId::new_v4(),
                ..request.clone()
            })
            .unwrap_err();
        assert_eq!(
            consumed.kind,
            PhotoKitConnectorPortErrorKind::SelectionTokenConsumed
        );

        let conflict = runtime
            .configure_scope(&ConfigurePhotoKitScopeV1Request {
                allow_icloud_downloads: true,
                ..request.clone()
            })
            .unwrap_err();
        assert_eq!(conflict.kind, PhotoKitConnectorPortErrorKind::Conflict);

        let connection = Connection::open(paths.database).unwrap();
        let receipt: String = connection
            .query_row(
                "SELECT response_json FROM photokit_command_receipts
                 WHERE request_id = ?1",
                [request.request_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!receipt.contains(token.expose_process_token()));
        assert!(!receipt.contains("Private Album"));
        assert!(!receipt.contains("native-album-private"));
    }

    #[test]
    fn configure_receipt_replay_rejects_tampered_response_and_metadata() {
        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
            let (_begin_request, session, token) = begin(&runtime);
            let request = configure_request(session, token);
            runtime.configure_scope(&request).unwrap();
            mutate_receipt_response(&paths, request.request_id, |response| {
                response["request_id"] = serde_json::Value::String(RequestId::new_v4().to_string());
            });
            assert_data_integrity(runtime.configure_scope(&request));
        }

        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
            let (_begin_request, session, token) = begin(&runtime);
            let request = configure_request(session, token);
            let configured = runtime.configure_scope(&request).unwrap();
            let other_enrollment = uuid::Uuid::new_v4().hyphenated().to_string();
            mutate_receipt_response(&paths, request.request_id, |response| {
                response["snapshot"]["enrollment_epoch"] =
                    serde_json::Value::String(other_enrollment.clone());
            });
            assert_ne!(
                configured.snapshot.enrollment_epoch.unwrap().to_string(),
                other_enrollment
            );
            assert_data_integrity(runtime.configure_scope(&request));
        }

        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
            let (_begin_request, session, token) = begin(&runtime);
            let request = configure_request(session, token);
            let configured = runtime.configure_scope(&request).unwrap();
            let enrollment = configured.snapshot.enrollment_epoch.unwrap().to_string();
            let unexpected_operation = uuid::Uuid::new_v4().hyphenated().to_string();
            mutate_receipt_metadata(
                &paths,
                request.request_id,
                Some(&enrollment),
                Some(&unexpected_operation),
            );
            assert_data_integrity(runtime.configure_scope(&request));
        }
    }

    #[test]
    fn authorization_change_invalidates_setup_without_prompting() {
        let (_temporary, _paths, runtime, _clock, calls) = runtime(false);
        let (_begin_request, session, token) = begin(&runtime);
        runtime
            .state
            .lock()
            .unwrap()
            .coordinator
            .native_mut()
            .authorization = PhotoKitAuthorizationV1::Denied;
        let request = configure_request(session, token);
        let denied = runtime.configure_scope(&request).unwrap_err();
        assert_eq!(
            denied.kind,
            PhotoKitConnectorPortErrorKind::PermissionDenied
        );
        assert_eq!(
            calls.lock().unwrap().last().map(String::as_str),
            Some("authorization:false")
        );

        runtime
            .state
            .lock()
            .unwrap()
            .coordinator
            .native_mut()
            .authorization = PhotoKitAuthorizationV1::Authorized;
        let expired = runtime
            .configure_scope(&ConfigurePhotoKitScopeV1Request {
                request_id: RequestId::new_v4(),
                ..request
            })
            .unwrap_err();
        assert_eq!(expired.kind, PhotoKitConnectorPortErrorKind::SessionExpired);
    }

    #[test]
    fn sync_receipts_replay_without_native_work_and_conflict_on_trigger_change() {
        let (_temporary, _paths, runtime, _clock, calls) = runtime(false);
        configure(&runtime);
        let request = SyncPhotoKitV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
        };
        let created = runtime
            .reconcile(&request, PhotoKitReconcileTriggerV1::User)
            .unwrap();
        let native_calls = calls.lock().unwrap().len();
        let replay = runtime
            .reconcile(&request, PhotoKitReconcileTriggerV1::User)
            .unwrap();
        assert_eq!(replay.replay_status, ReplayStatusV1::Replayed);
        assert_eq!(created.operation_id, replay.operation_id);
        assert_eq!(calls.lock().unwrap().len(), native_calls);

        let conflict = runtime
            .reconcile(&request, PhotoKitReconcileTriggerV1::Startup)
            .unwrap_err();
        assert_eq!(conflict.kind, PhotoKitConnectorPortErrorKind::Conflict);
    }

    #[test]
    fn sync_recovers_a_terminal_publication_when_receipt_recording_was_interrupted() {
        let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
        configure(&runtime);
        let request = SyncPhotoKitV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
        };
        runtime
            .state
            .lock()
            .unwrap()
            .coordinator
            .reconcile(
                &request.request_id.to_string(),
                PhotoKitReconcileTriggerV1::User,
                10_000,
            )
            .unwrap();

        let recovered = runtime
            .reconcile(&request, PhotoKitReconcileTriggerV1::User)
            .unwrap();
        assert_eq!(recovered.replay_status, ReplayStatusV1::Replayed);
        let replay = runtime
            .reconcile(&request, PhotoKitReconcileTriggerV1::User)
            .unwrap();
        assert_eq!(replay.replay_status, ReplayStatusV1::Replayed);
        assert_eq!(recovered.operation_id, replay.operation_id);
        assert_eq!(
            Connection::open(paths.database)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM photokit_command_receipts
                     WHERE request_id = ?1",
                    [request.request_id.to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn sync_receipt_replay_rejects_tampered_response_and_metadata() {
        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
            configure(&runtime);
            let request = SyncPhotoKitV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
            };
            runtime
                .reconcile(&request, PhotoKitReconcileTriggerV1::User)
                .unwrap();
            mutate_receipt_response(&paths, request.request_id, |response| {
                response["trigger"] = serde_json::Value::String("startup".to_owned());
            });
            assert_data_integrity(runtime.reconcile(&request, PhotoKitReconcileTriggerV1::User));
        }

        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
            configure(&runtime);
            let request = SyncPhotoKitV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
            };
            runtime
                .reconcile(&request, PhotoKitReconcileTriggerV1::User)
                .unwrap();
            mutate_receipt_response(&paths, request.request_id, |response| {
                let fence = response["reconciliation_fence"].as_u64().unwrap();
                response["reconciliation_fence"] = serde_json::Value::from(fence + 1);
            });
            assert_data_integrity(runtime.reconcile(&request, PhotoKitReconcileTriggerV1::User));
        }

        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(true);
            configure(&runtime);
            let request = SyncPhotoKitV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
            };
            runtime
                .reconcile(&request, PhotoKitReconcileTriggerV1::User)
                .unwrap();
            mutate_receipt_response(&paths, request.request_id, |response| {
                let generation = response["snapshot"]["membership_generation"]
                    .as_u64()
                    .unwrap();
                response["snapshot"]["membership_generation"] =
                    serde_json::Value::from(generation + 1);
            });
            assert_data_integrity(runtime.reconcile(&request, PhotoKitReconcileTriggerV1::User));
        }

        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(true);
            configure(&runtime);
            let request = SyncPhotoKitV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
            };
            runtime
                .reconcile(&request, PhotoKitReconcileTriggerV1::User)
                .unwrap();
            mutate_receipt_response(&paths, request.request_id, |response| {
                response["snapshot"]["counts"] = serde_json::json!({
                    "observed": 0,
                    "available": 0,
                    "unavailable": 0
                });
                response["snapshot"]["availability_counts"] = serde_json::json!([]);
            });
            assert_data_integrity(runtime.reconcile(&request, PhotoKitReconcileTriggerV1::User));
        }

        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
            let configured = configure(&runtime);
            let request = SyncPhotoKitV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
            };
            runtime
                .reconcile(&request, PhotoKitReconcileTriggerV1::User)
                .unwrap();
            let enrollment = configured.snapshot.enrollment_epoch.unwrap().to_string();
            let other_operation = uuid::Uuid::new_v4().hyphenated().to_string();
            mutate_receipt_metadata(
                &paths,
                request.request_id,
                Some(&enrollment),
                Some(&other_operation),
            );
            assert_data_integrity(runtime.reconcile(&request, PhotoKitReconcileTriggerV1::User));
        }
    }

    #[test]
    fn disable_is_revision_cas_and_preserves_generation_and_materialization() {
        let (_temporary, paths, runtime, _clock, _calls) = runtime(true);
        configure(&runtime);
        let sync = runtime
            .reconcile(
                &SyncPhotoKitV1Request {
                    schema_version: SCHEMA_VERSION_V1,
                    request_id: RequestId::new_v4(),
                },
                PhotoKitReconcileTriggerV1::User,
            )
            .unwrap();
        assert_eq!(sync.snapshot.counts.available, 1);
        let connection = Connection::open(&paths.database).unwrap();
        let before: (i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM photokit_membership_generations),
                    (SELECT COUNT(*) FROM photokit_materializations)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        let request = DisablePhotoKitV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            expected_photokit_revision: sync.snapshot.photokit_revision,
        };
        let disabled = runtime.disable(&request).unwrap();
        assert_eq!(disabled.preserved_counts.observed, 1);
        assert_eq!(
            disabled.preserved_membership_generation,
            sync.snapshot.membership_generation
        );
        assert_eq!(
            disabled.photokit_revision.get(),
            request.expected_photokit_revision.get() + 1
        );
        let after: (i64, i64, String) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM photokit_membership_generations),
                    (SELECT COUNT(*) FROM photokit_materializations),
                    (SELECT state FROM photokit_enrollments
                     WHERE enrollment_epoch = ?1)",
                [disabled.disabled_enrollment_epoch.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((after.0, after.1), before);
        assert_eq!(after.2, "inactive");

        let replay = runtime.disable(&request).unwrap();
        assert_eq!(replay.replay_status, ReplayStatusV1::Replayed);
        let conflict = runtime
            .disable(&DisablePhotoKitV1Request {
                expected_photokit_revision: disabled.photokit_revision,
                ..request
            })
            .unwrap_err();
        assert_eq!(conflict.kind, PhotoKitConnectorPortErrorKind::Conflict);
    }

    #[test]
    fn disable_receipt_replay_rejects_tampered_response_and_metadata() {
        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
            let configured = configure(&runtime);
            let request = DisablePhotoKitV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                expected_photokit_revision: configured.snapshot.photokit_revision,
            };
            runtime.disable(&request).unwrap();
            mutate_receipt_response(&paths, request.request_id, |response| {
                response["request_id"] = serde_json::Value::String(RequestId::new_v4().to_string());
            });
            assert_data_integrity(runtime.disable(&request));
        }

        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
            let configured = configure(&runtime);
            let request = DisablePhotoKitV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                expected_photokit_revision: configured.snapshot.photokit_revision,
            };
            runtime.disable(&request).unwrap();
            let other_enrollment = uuid::Uuid::new_v4().hyphenated().to_string();
            mutate_receipt_metadata(&paths, request.request_id, Some(&other_enrollment), None);
            assert_data_integrity(runtime.disable(&request));
        }

        {
            let (_temporary, paths, runtime, _clock, _calls) = runtime(false);
            let configured = configure(&runtime);
            let request = DisablePhotoKitV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                expected_photokit_revision: configured.snapshot.photokit_revision,
            };
            let disabled = runtime.disable(&request).unwrap();
            let enrollment = disabled.disabled_enrollment_epoch.to_string();
            let unexpected_operation = uuid::Uuid::new_v4().hyphenated().to_string();
            mutate_receipt_metadata(
                &paths,
                request.request_id,
                Some(&enrollment),
                Some(&unexpected_operation),
            );
            assert_data_integrity(runtime.disable(&request));
        }
    }

    #[test]
    fn snapshot_and_startup_reconcile_never_request_authorization() {
        let (_temporary, _paths, runtime, _clock, calls) = runtime(false);
        let unconfigured = runtime.startup_reconcile().unwrap();
        assert!(unconfigured.is_none());
        assert!(calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| call != "authorization:true"));

        configure(&runtime);
        calls.lock().unwrap().clear();
        runtime
            .snapshot(&GetPhotoKitConnectorV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
            })
            .unwrap();
        let startup = runtime.startup_reconcile().unwrap().unwrap();
        assert_eq!(startup.trigger, PhotoKitReconcileTriggerV1::Startup);
        assert!(calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| call.starts_with("authorization:"))
            .all(|call| call == "authorization:false"));
    }

    #[test]
    fn connector_is_thread_safe_for_concurrent_snapshots() {
        let (_temporary, _paths, runtime, _clock, calls) = runtime(false);
        let mut threads = Vec::new();
        for _ in 0..12 {
            let runtime = runtime.clone();
            threads.push(std::thread::spawn(move || {
                runtime
                    .snapshot(&GetPhotoKitConnectorV1Request {
                        schema_version: SCHEMA_VERSION_V1,
                        request_id: RequestId::new_v4(),
                    })
                    .unwrap()
                    .snapshot
            }));
        }
        for thread in threads {
            assert_eq!(
                thread.join().unwrap().state,
                wardrobe_core::PhotoKitConnectorStateV1::Unconfigured
            );
        }
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.as_str() == "authorization:false")
                .count(),
            12
        );
    }
}
