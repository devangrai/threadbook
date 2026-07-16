use crate::{
    PhotoKitEnumerationSink, PhotoKitEnumerationTerminal, PhotoKitNativeAlbum,
    PhotoKitNativeByteSink, PhotoKitNativeError, PhotoKitNativePort, PhotoKitOperation,
    PhotoKitValidatedImage,
};
use std::fs::File;
use wardrobe_core::PhotoKitAuthorizationV1;

#[cfg(all(target_os = "macos", feature = "photokit-native"))]
mod macos {
    use super::*;
    use crate::{
        PhotoKitNativeAsset, PhotoKitNativeResource, PHOTOKIT_MAX_ALBUMS, PHOTOKIT_MAX_ASSETS,
        PHOTOKIT_MAX_CALLBACK_CHUNK_BYTES, PHOTOKIT_MAX_RESOURCE_BYTES,
        PHOTOKIT_SELECTION_POLICY_REVISION,
    };
    use serde_json::{json, Map, Value};
    use std::collections::BTreeSet;
    use std::os::fd::IntoRawFd;
    use std::os::raw::c_int;
    use std::ptr;
    use std::slice;
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    const ABI_VERSION: u32 = 1;
    const MAX_CONTROL_BYTES: usize = 65_536;
    const MAX_BINARY_BYTES: usize = 1_048_576;
    const BINARY_HEADER_BYTES: usize = 80;
    const NEXT_TIMEOUT_MS: u32 = 1_000;
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10 * 60);
    const QUIESCE_TIMEOUT_MS: u32 = 10_000;

    const STATUS_OK: i32 = 0;
    const STATUS_TIMEOUT: i32 = 1;
    const STATUS_CLOSED: i32 = 2;
    const STATUS_INVALID: i32 = 3;
    const STATUS_BUSY: i32 = 4;

    const FRAME_CONTROL: u32 = 1;
    const FRAME_BINARY: u32 = 2;

    #[repr(C)]
    struct NativeFrameHeader {
        abi_version: u32,
        kind: u32,
        sequence: u64,
        length: usize,
    }

    enum NativeHandle {}

    extern "C" {
        fn wk_photokit_create_v1(requested_abi: u32, out_handle: *mut *mut NativeHandle) -> i32;
        fn wk_photokit_send_v1(handle: *mut NativeHandle, bytes: *const u8, length: usize) -> i32;
        fn wk_photokit_next_v1(
            handle: *mut NativeHandle,
            timeout_ms: u32,
            out_frame: *mut *mut NativeFrameHeader,
        ) -> i32;
        fn wk_photokit_frame_free_v1(frame: *mut NativeFrameHeader);
        fn wk_photokit_quiesce_v1(handle: *mut NativeHandle, timeout_ms: u32) -> i32;
        fn wk_photokit_destroy_v1(handle: *mut *mut NativeHandle) -> i32;
        fn wk_photokit_validate_image_fd_v1(
            duplicated_read_only_fd: c_int,
            uti: *const u8,
            uti_length: usize,
            out_width: *mut u32,
            out_height: *mut u32,
            out_frame_count: *mut u32,
        ) -> i32;
    }

    #[derive(Clone, Copy)]
    enum CommandKind {
        InspectAuthorization,
        RequestAuthorization,
        ListAlbums,
        EnumerateAlbum,
        StreamResource,
    }

    impl CommandKind {
        fn wire_name(self) -> &'static str {
            match self {
                Self::InspectAuthorization => "inspect_authorization",
                Self::RequestAuthorization => "request_authorization",
                Self::ListAlbums => "list_albums",
                Self::EnumerateAlbum => "enumerate_album",
                Self::StreamResource => "stream_resource",
            }
        }
    }

    #[derive(Clone)]
    struct RequestIdentity {
        operation_id: Uuid,
        enrollment_epoch: Uuid,
        reconciliation_fence: u64,
        generation: u64,
        request_sequence: u64,
    }

    impl RequestIdentity {
        fn synthetic(request_sequence: u64) -> Self {
            Self {
                operation_id: Uuid::new_v4(),
                enrollment_epoch: Uuid::new_v4(),
                reconciliation_fence: 1,
                generation: 1,
                request_sequence,
            }
        }

        fn for_operation(
            operation: &PhotoKitOperation,
            request_sequence: u64,
        ) -> Result<Self, PhotoKitNativeError> {
            let operation_id = parse_canonical_uuid(&operation.operation_id)?;
            let enrollment_epoch = parse_canonical_uuid(&operation.enrollment_epoch)?;
            if operation.reconciliation_fence == 0 || operation.proposed_membership_generation == 0
            {
                return Err(PhotoKitNativeError::InvalidResponse);
            }
            Ok(Self {
                operation_id,
                enrollment_epoch,
                reconciliation_fence: operation.reconciliation_fence,
                generation: operation.proposed_membership_generation,
                request_sequence,
            })
        }
    }

    struct WorkerRequest {
        bytes: Vec<u8>,
        kind: CommandKind,
        identity: RequestIdentity,
        events: SyncSender<WorkerMessage>,
    }

    enum WorkerCommand {
        Request(WorkerRequest),
        Shutdown,
    }

    enum WorkerMessage {
        Event(NativeEvent),
        Finished(Result<(), PhotoKitNativeError>),
    }

    enum NativeEvent {
        Authorization(PhotoKitAuthorizationV1),
        Album(PhotoKitNativeAlbum),
        Asset(PhotoKitNativeAsset),
        Binary(Vec<u8>),
        Progress,
        Terminal(TerminalEvent),
    }

    enum TerminalEvent {
        Completed,
        Albums { count: usize, truncated: bool },
        Assets { count: usize },
        Resource { bytes: u64, resource_token: String },
        Failed(String),
    }

    struct OwnedHandle {
        raw: *mut NativeHandle,
        next_frame_sequence: u64,
    }

    impl OwnedHandle {
        fn create() -> Result<Self, PhotoKitNativeError> {
            let mut raw = ptr::null_mut();
            let status = unsafe { wk_photokit_create_v1(ABI_VERSION, &mut raw) };
            if status != STATUS_OK || raw.is_null() {
                return Err(status_error(status));
            }
            Ok(Self {
                raw,
                next_frame_sequence: 1,
            })
        }

        fn send(&mut self, request: WorkerRequest) -> bool {
            let result = self.pump(&request);
            let successful = result.is_ok();
            let delivered = request.events.send(WorkerMessage::Finished(result)).is_ok();
            successful && delivered
        }

        fn pump(&mut self, request: &WorkerRequest) -> Result<(), PhotoKitNativeError> {
            if request.bytes.is_empty() || request.bytes.len() > MAX_CONTROL_BYTES {
                return Err(PhotoKitNativeError::InvalidResponse);
            }
            let status = unsafe {
                wk_photokit_send_v1(self.raw, request.bytes.as_ptr(), request.bytes.len())
            };
            if status != STATUS_OK {
                return Err(status_error(status));
            }

            let deadline = Instant::now() + REQUEST_TIMEOUT;
            let mut next_chunk_index = 0_u64;
            loop {
                if Instant::now() >= deadline {
                    self.cancel(&request.identity);
                    return Err(PhotoKitNativeError::Cancelled);
                }
                let frame = match self.next()? {
                    Some(frame) => frame,
                    None => continue,
                };
                let event = match frame.kind {
                    FRAME_CONTROL => decode_control(&frame.bytes, request.kind, &request.identity)?,
                    FRAME_BINARY => {
                        if !matches!(request.kind, CommandKind::StreamResource) {
                            return Err(PhotoKitNativeError::InvalidResponse);
                        }
                        let payload =
                            decode_binary(&frame.bytes, &request.identity, next_chunk_index)?;
                        next_chunk_index = next_chunk_index
                            .checked_add(1)
                            .ok_or(PhotoKitNativeError::InvalidResponse)?;
                        NativeEvent::Binary(payload)
                    }
                    _ => return Err(PhotoKitNativeError::InvalidResponse),
                };
                let terminal = matches!(event, NativeEvent::Terminal(_));
                if request.events.send(WorkerMessage::Event(event)).is_err() {
                    self.cancel(&request.identity);
                    return Err(PhotoKitNativeError::Cancelled);
                }
                if terminal {
                    return Ok(());
                }
            }
        }

        fn next(&mut self) -> Result<Option<RawFrame>, PhotoKitNativeError> {
            let mut raw = ptr::null_mut();
            let status = unsafe { wk_photokit_next_v1(self.raw, NEXT_TIMEOUT_MS, &mut raw) };
            match status {
                STATUS_TIMEOUT => {
                    if !raw.is_null() {
                        unsafe { wk_photokit_frame_free_v1(raw) };
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    Ok(None)
                }
                STATUS_OK => {
                    if raw.is_null() {
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    let owned = OwnedFrame(raw);
                    let header = unsafe { &*owned.0 };
                    if std::mem::size_of::<NativeFrameHeader>() != 24
                        || header.abi_version != ABI_VERSION
                        || header.sequence != self.next_frame_sequence
                        || !matches!(header.kind, FRAME_CONTROL | FRAME_BINARY)
                    {
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    let maximum = if header.kind == FRAME_CONTROL {
                        MAX_CONTROL_BYTES
                    } else {
                        MAX_BINARY_BYTES
                    };
                    if header.length == 0 || header.length > maximum {
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    self.next_frame_sequence = self
                        .next_frame_sequence
                        .checked_add(1)
                        .ok_or(PhotoKitNativeError::InvalidResponse)?;
                    let bytes = unsafe {
                        let start =
                            (owned.0 as *const u8).add(std::mem::size_of::<NativeFrameHeader>());
                        slice::from_raw_parts(start, header.length).to_vec()
                    };
                    Ok(Some(RawFrame {
                        kind: header.kind,
                        bytes,
                    }))
                }
                _ => {
                    if !raw.is_null() {
                        unsafe { wk_photokit_frame_free_v1(raw) };
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    Err(status_error(status))
                }
            }
        }

        fn cancel(&mut self, identity: &RequestIdentity) {
            let bytes = encode_command(InternalCommandKind::Cancel, identity, Map::new());
            if let Ok(bytes) = bytes {
                let _ = unsafe { wk_photokit_send_v1(self.raw, bytes.as_ptr(), bytes.len()) };
            }
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if self.raw.is_null() {
                return;
            }
            let quiesced = unsafe { wk_photokit_quiesce_v1(self.raw, QUIESCE_TIMEOUT_MS) };
            if quiesced != STATUS_OK {
                return;
            }
            let _ = unsafe { wk_photokit_destroy_v1(&mut self.raw) };
        }
    }

    struct OwnedFrame(*mut NativeFrameHeader);

    impl Drop for OwnedFrame {
        fn drop(&mut self) {
            unsafe { wk_photokit_frame_free_v1(self.0) };
        }
    }

    struct RawFrame {
        kind: u32,
        bytes: Vec<u8>,
    }

    enum InternalCommandKind {
        Public(CommandKind),
        Cancel,
    }

    impl From<CommandKind> for InternalCommandKind {
        fn from(value: CommandKind) -> Self {
            Self::Public(value)
        }
    }

    pub struct MacOsPhotoKitNativePort {
        commands: mpsc::Sender<WorkerCommand>,
        worker: Option<JoinHandle<()>>,
        next_request_sequence: u64,
    }

    impl MacOsPhotoKitNativePort {
        pub fn new() -> Result<Self, PhotoKitNativeError> {
            let (commands, requests) = mpsc::channel();
            let (ready_tx, ready_rx) = mpsc::sync_channel(1);
            let worker = thread::Builder::new()
                .name("wardrobe-photokit-native".to_owned())
                .spawn(move || {
                    let handle = OwnedHandle::create();
                    match handle {
                        Ok(mut handle) => {
                            let _ = ready_tx.send(Ok(()));
                            while let Ok(command) = requests.recv() {
                                match command {
                                    WorkerCommand::Request(request) => {
                                        if !handle.send(request) {
                                            break;
                                        }
                                    }
                                    WorkerCommand::Shutdown => break,
                                }
                            }
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error));
                        }
                    }
                })
                .map_err(|_| PhotoKitNativeError::Unavailable)?;
            ready_rx
                .recv()
                .map_err(|_| PhotoKitNativeError::Unavailable)??;
            Ok(Self {
                commands,
                worker: Some(worker),
                next_request_sequence: 1,
            })
        }

        fn next_sequence(&mut self) -> Result<u64, PhotoKitNativeError> {
            let current = self.next_request_sequence;
            self.next_request_sequence = current
                .checked_add(1)
                .ok_or(PhotoKitNativeError::InvalidResponse)?;
            Ok(current)
        }

        fn synthetic_identity(&mut self) -> Result<RequestIdentity, PhotoKitNativeError> {
            Ok(RequestIdentity::synthetic(self.next_sequence()?))
        }

        fn operation_identity(
            &mut self,
            operation: &PhotoKitOperation,
        ) -> Result<RequestIdentity, PhotoKitNativeError> {
            RequestIdentity::for_operation(operation, self.next_sequence()?)
        }

        fn start(
            &self,
            kind: CommandKind,
            identity: RequestIdentity,
            fields: Map<String, Value>,
        ) -> Result<Receiver<WorkerMessage>, PhotoKitNativeError> {
            let bytes = encode_command(kind.into(), &identity, fields)?;
            let (events, receiver) = mpsc::sync_channel(2);
            self.commands
                .send(WorkerCommand::Request(WorkerRequest {
                    bytes,
                    kind,
                    identity,
                    events,
                }))
                .map_err(|_| PhotoKitNativeError::Unavailable)?;
            Ok(receiver)
        }
    }

    impl Drop for MacOsPhotoKitNativePort {
        fn drop(&mut self) {
            let _ = self.commands.send(WorkerCommand::Shutdown);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    impl PhotoKitNativePort for MacOsPhotoKitNativePort {
        fn authorization(
            &mut self,
            request_authorization: bool,
        ) -> Result<PhotoKitAuthorizationV1, PhotoKitNativeError> {
            let kind = if request_authorization {
                CommandKind::RequestAuthorization
            } else {
                CommandKind::InspectAuthorization
            };
            let identity = self.synthetic_identity()?;
            let receiver = self.start(kind, identity, Map::new())?;
            let mut authorization = None;
            let mut terminal = false;
            receive_all(receiver, |event| match event {
                NativeEvent::Authorization(value) if authorization.is_none() => {
                    authorization = Some(value);
                    Ok(())
                }
                NativeEvent::Terminal(TerminalEvent::Completed) if !terminal => {
                    terminal = true;
                    Ok(())
                }
                NativeEvent::Terminal(TerminalEvent::Failed(_)) => {
                    Err(PhotoKitNativeError::Unavailable)
                }
                _ => Err(PhotoKitNativeError::InvalidResponse),
            })?;
            if !terminal {
                return Err(PhotoKitNativeError::InvalidResponse);
            }
            authorization.ok_or(PhotoKitNativeError::InvalidResponse)
        }

        fn list_regular_albums(&mut self) -> Result<Vec<PhotoKitNativeAlbum>, PhotoKitNativeError> {
            let identity = self.synthetic_identity()?;
            let receiver = self.start(CommandKind::ListAlbums, identity, Map::new())?;
            let mut albums = Vec::new();
            let mut terminal = None;
            receive_all(receiver, |event| match event {
                NativeEvent::Album(album) if terminal.is_none() => {
                    if albums.len() >= PHOTOKIT_MAX_ALBUMS {
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    albums.push(album);
                    Ok(())
                }
                NativeEvent::Terminal(TerminalEvent::Albums { count, truncated })
                    if terminal.is_none() =>
                {
                    terminal = Some((count, truncated));
                    Ok(())
                }
                NativeEvent::Terminal(TerminalEvent::Failed(_)) => {
                    Err(PhotoKitNativeError::Unavailable)
                }
                _ => Err(PhotoKitNativeError::InvalidResponse),
            })?;
            let (count, _truncated) = terminal.ok_or(PhotoKitNativeError::InvalidResponse)?;
            if count != albums.len() {
                return Err(PhotoKitNativeError::InvalidResponse);
            }
            Ok(albums)
        }

        fn enumerate_regular_album(
            &mut self,
            album_locator: &str,
            operation: &PhotoKitOperation,
            sink: &mut dyn PhotoKitEnumerationSink,
        ) -> Result<PhotoKitEnumerationTerminal, PhotoKitNativeError> {
            validate_bounded_text(album_locator, 512)?;
            let identity = self.operation_identity(operation)?;
            let mut fields = Map::new();
            fields.insert(
                "album_identifier".to_owned(),
                Value::String(album_locator.to_owned()),
            );
            let receiver = self.start(CommandKind::EnumerateAlbum, identity, fields)?;
            let mut observed = 0_usize;
            let mut terminal = None;
            let mut asset_locators = BTreeSet::new();
            let mut resource_tokens = BTreeSet::new();
            receive_all(receiver, |event| match event {
                NativeEvent::Asset(asset) if terminal.is_none() => {
                    if observed >= PHOTOKIT_MAX_ASSETS {
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    if !asset_locators.insert(asset.asset_locator.clone())
                        || asset.primary_resource.as_ref().is_some_and(|resource| {
                            !resource_tokens.insert(resource.operation_resource_token.clone())
                        })
                    {
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    sink.observe(asset)
                        .map_err(|_| PhotoKitNativeError::SinkRejected)?;
                    observed += 1;
                    Ok(())
                }
                NativeEvent::Terminal(TerminalEvent::Assets { count }) if terminal.is_none() => {
                    terminal = Some(if count == observed {
                        PhotoKitEnumerationTerminal::Complete
                    } else {
                        PhotoKitEnumerationTerminal::Incomplete
                    });
                    Ok(())
                }
                NativeEvent::Terminal(TerminalEvent::Failed(reason)) => {
                    terminal = Some(if reason == "scope_unavailable" {
                        PhotoKitEnumerationTerminal::AlbumUnavailable
                    } else {
                        PhotoKitEnumerationTerminal::Incomplete
                    });
                    Ok(())
                }
                _ => Err(PhotoKitNativeError::InvalidResponse),
            })?;
            terminal.ok_or(PhotoKitNativeError::InvalidResponse)
        }

        fn transfer_resource(
            &mut self,
            operation: &PhotoKitOperation,
            operation_resource_token: &str,
            network_access_allowed: bool,
            sink: &mut dyn PhotoKitNativeByteSink,
        ) -> Result<crate::PhotoKitTransferTerminal, PhotoKitNativeError> {
            validate_resource_token(operation_resource_token)?;
            let identity = self.operation_identity(operation)?;
            let mut fields = Map::new();
            fields.insert(
                "resource_token".to_owned(),
                Value::String(operation_resource_token.to_owned()),
            );
            fields.insert(
                "allow_network".to_owned(),
                Value::Bool(network_access_allowed),
            );
            let receiver = self.start(CommandKind::StreamResource, identity, fields)?;
            let mut terminal = None;
            receive_all(receiver, |event| match event {
                NativeEvent::Binary(bytes) if terminal.is_none() => {
                    let before = sink.accepted_bytes();
                    sink.write_chunk(&bytes)
                        .map_err(|_| PhotoKitNativeError::SinkRejected)?;
                    let after = sink.accepted_bytes();
                    if before.checked_add(bytes.len() as u64) != Some(after)
                        || after > PHOTOKIT_MAX_RESOURCE_BYTES
                    {
                        return Err(PhotoKitNativeError::SinkRejected);
                    }
                    Ok(())
                }
                NativeEvent::Progress if network_access_allowed && terminal.is_none() => Ok(()),
                NativeEvent::Terminal(TerminalEvent::Resource {
                    bytes,
                    resource_token,
                }) if terminal.is_none() => {
                    if bytes != sink.accepted_bytes() || resource_token != operation_resource_token
                    {
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    terminal = Some(crate::PhotoKitTransferTerminal::Complete);
                    Ok(())
                }
                NativeEvent::Terminal(TerminalEvent::Failed(reason)) if terminal.is_none() => {
                    terminal = Some(
                        if reason == "network_access_required" && sink.accepted_bytes() == 0 {
                            crate::PhotoKitTransferTerminal::NetworkAccessRequired
                        } else {
                            crate::PhotoKitTransferTerminal::Failed
                        },
                    );
                    Ok(())
                }
                _ => Err(PhotoKitNativeError::InvalidResponse),
            })?;
            terminal.ok_or(PhotoKitNativeError::InvalidResponse)
        }

        fn validate_image(
            &mut self,
            duplicated_read_only_file: File,
            resource_uti: &str,
        ) -> Result<PhotoKitValidatedImage, PhotoKitNativeError> {
            if !supported_uti(resource_uti) {
                return Err(PhotoKitNativeError::ImageValidation);
            }
            let descriptor = duplicated_read_only_file.into_raw_fd();
            let mut width = 0_u32;
            let mut height = 0_u32;
            let mut frame_count = 0_u32;
            let status = unsafe {
                wk_photokit_validate_image_fd_v1(
                    descriptor,
                    resource_uti.as_ptr(),
                    resource_uti.len(),
                    &mut width,
                    &mut height,
                    &mut frame_count,
                )
            };
            if status != STATUS_OK {
                return Err(PhotoKitNativeError::ImageValidation);
            }
            if width == 0 || height == 0 || frame_count != 1 {
                return Err(PhotoKitNativeError::ImageValidation);
            }
            Ok(PhotoKitValidatedImage {
                pixel_width: width,
                pixel_height: height,
                frame_count,
            })
        }
    }

    fn receive_all(
        receiver: Receiver<WorkerMessage>,
        mut consume: impl FnMut(NativeEvent) -> Result<(), PhotoKitNativeError>,
    ) -> Result<(), PhotoKitNativeError> {
        while let Ok(message) = receiver.recv() {
            match message {
                WorkerMessage::Event(event) => consume(event)?,
                WorkerMessage::Finished(result) => return result,
            }
        }
        Err(PhotoKitNativeError::Unavailable)
    }

    fn encode_command(
        kind: InternalCommandKind,
        identity: &RequestIdentity,
        fields: Map<String, Value>,
    ) -> Result<Vec<u8>, PhotoKitNativeError> {
        let command = match kind {
            InternalCommandKind::Public(kind) => kind.wire_name(),
            InternalCommandKind::Cancel => "cancel_operation",
        };
        let mut value = json!({
            "protocol_version": ABI_VERSION,
            "command": command,
            "operation_id": identity.operation_id.hyphenated().to_string(),
            "enrollment_epoch": identity.enrollment_epoch.hyphenated().to_string(),
            "reconciliation_fence": identity.reconciliation_fence,
            "generation": identity.generation,
            "sequence": identity.request_sequence,
        });
        let object = value
            .as_object_mut()
            .ok_or(PhotoKitNativeError::InvalidResponse)?;
        for (key, value) in fields {
            if object.insert(key, value).is_some() {
                return Err(PhotoKitNativeError::InvalidResponse);
            }
        }
        let bytes = serde_json::to_vec(&value).map_err(|_| PhotoKitNativeError::InvalidResponse)?;
        if bytes.is_empty() || bytes.len() > MAX_CONTROL_BYTES {
            return Err(PhotoKitNativeError::InvalidResponse);
        }
        Ok(bytes)
    }

    fn decode_control(
        bytes: &[u8],
        kind: CommandKind,
        identity: &RequestIdentity,
    ) -> Result<NativeEvent, PhotoKitNativeError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| PhotoKitNativeError::InvalidResponse)?;
        let object = value
            .as_object()
            .ok_or(PhotoKitNativeError::InvalidResponse)?;
        validate_control_identity(object, identity)?;
        let event = bounded_string(object, "event", 64)?;
        match event {
            "authorization" => {
                exact_keys(object, &["status"])?;
                if !matches!(
                    kind,
                    CommandKind::InspectAuthorization | CommandKind::RequestAuthorization
                ) {
                    return Err(PhotoKitNativeError::InvalidResponse);
                }
                let authorization = match bounded_string(object, "status", 32)? {
                    "not_determined" => PhotoKitAuthorizationV1::NotDetermined,
                    "restricted" => PhotoKitAuthorizationV1::Restricted,
                    "denied" => PhotoKitAuthorizationV1::Denied,
                    "limited" => PhotoKitAuthorizationV1::Limited,
                    "authorized" => PhotoKitAuthorizationV1::Authorized,
                    _ => return Err(PhotoKitNativeError::InvalidResponse),
                };
                Ok(NativeEvent::Authorization(authorization))
            }
            "album" => {
                exact_keys(object, &["album_identifier", "label"])?;
                if !matches!(kind, CommandKind::ListAlbums) {
                    return Err(PhotoKitNativeError::InvalidResponse);
                }
                Ok(NativeEvent::Album(PhotoKitNativeAlbum {
                    album_locator: bounded_string(object, "album_identifier", 512)?.to_owned(),
                    label: bounded_string(object, "label", 512)?.to_owned(),
                }))
            }
            "asset" => {
                if !matches!(kind, CommandKind::EnumerateAlbum) {
                    return Err(PhotoKitNativeError::InvalidResponse);
                }
                let supported = object
                    .get("supported")
                    .and_then(Value::as_bool)
                    .ok_or(PhotoKitNativeError::InvalidResponse)?;
                let asset_locator = bounded_string(object, "asset_identifier", 512)?.to_owned();
                if bounded_string(object, "selection_policy", 64)?
                    != PHOTOKIT_SELECTION_POLICY_REVISION
                {
                    return Err(PhotoKitNativeError::InvalidResponse);
                }
                let primary_resource = if supported {
                    exact_keys(
                        object,
                        &[
                            "asset_identifier",
                            "selection_policy",
                            "supported",
                            "resource_token",
                            "uti",
                        ],
                    )?;
                    let token = bounded_string(object, "resource_token", 128)?;
                    validate_resource_token(token)?;
                    let uti = bounded_string(object, "uti", 128)?;
                    if !supported_uti(uti) {
                        return Err(PhotoKitNativeError::InvalidResponse);
                    }
                    Some(PhotoKitNativeResource {
                        operation_resource_token: token.to_owned(),
                        resource_uti: uti.to_owned(),
                    })
                } else {
                    exact_keys(
                        object,
                        &[
                            "asset_identifier",
                            "selection_policy",
                            "supported",
                            "reason",
                        ],
                    )?;
                    validate_reason(bounded_string(object, "reason", 64)?)?;
                    None
                };
                Ok(NativeEvent::Asset(PhotoKitNativeAsset {
                    asset_locator,
                    primary_resource,
                }))
            }
            "resource_progress" => {
                exact_keys(object, &["percent"])?;
                if !matches!(kind, CommandKind::StreamResource)
                    || object.get("percent").and_then(Value::as_u64).unwrap_or(101) > 100
                {
                    return Err(PhotoKitNativeError::InvalidResponse);
                }
                Ok(NativeEvent::Progress)
            }
            "operation_terminal" => decode_terminal(object, kind),
            _ => Err(PhotoKitNativeError::InvalidResponse),
        }
    }

    fn decode_terminal(
        object: &Map<String, Value>,
        kind: CommandKind,
    ) -> Result<NativeEvent, PhotoKitNativeError> {
        let status = bounded_string(object, "status", 16)?;
        if status == "failed" {
            exact_keys(object, &["status", "reason"])?;
            let reason = bounded_string(object, "reason", 64)?;
            validate_reason(reason)?;
            return Ok(NativeEvent::Terminal(TerminalEvent::Failed(
                reason.to_owned(),
            )));
        }
        if status != "completed" {
            return Err(PhotoKitNativeError::InvalidResponse);
        }
        let terminal = match kind {
            CommandKind::InspectAuthorization | CommandKind::RequestAuthorization => {
                exact_keys(object, &["status"])?;
                TerminalEvent::Completed
            }
            CommandKind::ListAlbums => {
                exact_keys(object, &["status", "album_count", "truncated"])?;
                let count = exact_usize(object, "album_count", PHOTOKIT_MAX_ALBUMS)?;
                let truncated = object
                    .get("truncated")
                    .and_then(Value::as_bool)
                    .ok_or(PhotoKitNativeError::InvalidResponse)?;
                TerminalEvent::Albums { count, truncated }
            }
            CommandKind::EnumerateAlbum => {
                exact_keys(object, &["status", "asset_count"])?;
                TerminalEvent::Assets {
                    count: exact_usize(object, "asset_count", PHOTOKIT_MAX_ASSETS)?,
                }
            }
            CommandKind::StreamResource => {
                exact_keys(
                    object,
                    &["status", "bytes", "materialization", "resource_token"],
                )?;
                let bytes = object
                    .get("bytes")
                    .and_then(Value::as_u64)
                    .filter(|value| *value > 0 && *value <= PHOTOKIT_MAX_RESOURCE_BYTES)
                    .ok_or(PhotoKitNativeError::InvalidResponse)?;
                if !matches!(
                    bounded_string(object, "materialization", 16)?,
                    "local" | "cloud"
                ) {
                    return Err(PhotoKitNativeError::InvalidResponse);
                }
                let resource_token = bounded_string(object, "resource_token", 128)?.to_owned();
                validate_resource_token(&resource_token)?;
                TerminalEvent::Resource {
                    bytes,
                    resource_token,
                }
            }
        };
        Ok(NativeEvent::Terminal(terminal))
    }

    fn validate_control_identity(
        object: &Map<String, Value>,
        identity: &RequestIdentity,
    ) -> Result<(), PhotoKitNativeError> {
        if object.get("protocol_version").and_then(Value::as_u64) != Some(1)
            || bounded_string(object, "operation_id", 36)?
                != identity.operation_id.hyphenated().to_string()
            || bounded_string(object, "enrollment_epoch", 36)?
                != identity.enrollment_epoch.hyphenated().to_string()
            || object.get("reconciliation_fence").and_then(Value::as_u64)
                != Some(identity.reconciliation_fence)
            || object.get("generation").and_then(Value::as_u64) != Some(identity.generation)
            || object.get("sequence").and_then(Value::as_u64) != Some(identity.request_sequence)
        {
            return Err(PhotoKitNativeError::InvalidResponse);
        }
        Ok(())
    }

    fn exact_keys(
        object: &Map<String, Value>,
        event_fields: &[&str],
    ) -> Result<(), PhotoKitNativeError> {
        let mut expected: BTreeSet<&str> = [
            "protocol_version",
            "event",
            "operation_id",
            "enrollment_epoch",
            "reconciliation_fence",
            "generation",
            "sequence",
        ]
        .into_iter()
        .collect();
        expected.extend(event_fields.iter().copied());
        let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        if actual != expected {
            return Err(PhotoKitNativeError::InvalidResponse);
        }
        Ok(())
    }

    fn decode_binary(
        bytes: &[u8],
        identity: &RequestIdentity,
        expected_chunk_index: u64,
    ) -> Result<Vec<u8>, PhotoKitNativeError> {
        if bytes.len() <= BINARY_HEADER_BYTES
            || bytes.len() > MAX_BINARY_BYTES
            || bytes[0..4] != [0x57, 0x4b, 0x50, 0x42]
            || read_u32(bytes, 4) != Some(ABI_VERSION)
            || read_u32(bytes, 8) != Some(BINARY_HEADER_BYTES as u32)
            || read_u32(bytes, 12) != Some(0)
            || read_u64(bytes, 16) != Some(identity.request_sequence)
            || read_u64(bytes, 24) != Some(identity.reconciliation_fence)
            || read_u64(bytes, 32) != Some(identity.generation)
            || read_u64(bytes, 40) != Some(expected_chunk_index)
            || bytes.get(48..64) != Some(identity.operation_id.as_bytes())
            || bytes.get(64..80) != Some(identity.enrollment_epoch.as_bytes())
        {
            return Err(PhotoKitNativeError::InvalidResponse);
        }
        let payload = &bytes[BINARY_HEADER_BYTES..];
        if payload.is_empty() || payload.len() > PHOTOKIT_MAX_CALLBACK_CHUNK_BYTES {
            return Err(PhotoKitNativeError::InvalidResponse);
        }
        Ok(payload.to_vec())
    }

    fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    }

    fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            bytes.get(offset..offset + 8)?.try_into().ok()?,
        ))
    }

    fn bounded_string<'a>(
        object: &'a Map<String, Value>,
        key: &str,
        maximum: usize,
    ) -> Result<&'a str, PhotoKitNativeError> {
        let value = object
            .get(key)
            .and_then(Value::as_str)
            .ok_or(PhotoKitNativeError::InvalidResponse)?;
        validate_bounded_text(value, maximum)?;
        Ok(value)
    }

    fn exact_usize(
        object: &Map<String, Value>,
        key: &str,
        maximum: usize,
    ) -> Result<usize, PhotoKitNativeError> {
        object
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value <= maximum)
            .ok_or(PhotoKitNativeError::InvalidResponse)
    }

    fn validate_bounded_text(value: &str, maximum: usize) -> Result<(), PhotoKitNativeError> {
        if value.is_empty() || value.len() > maximum || value.as_bytes().contains(&0) {
            return Err(PhotoKitNativeError::InvalidResponse);
        }
        Ok(())
    }

    fn validate_resource_token(value: &str) -> Result<(), PhotoKitNativeError> {
        validate_bounded_text(value, 128)?;
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(PhotoKitNativeError::InvalidResponse);
        }
        Ok(())
    }

    fn validate_reason(value: &str) -> Result<(), PhotoKitNativeError> {
        if matches!(
            value,
            "authorization_unavailable"
                | "scope_unavailable"
                | "scope_too_large"
                | "invalid"
                | "invalid_album"
                | "invalid_asset"
                | "internal"
                | "resource_limit"
                | "resource_unavailable"
                | "network_access_required"
                | "partial_transfer"
                | "transfer_failed"
                | "empty_resource"
                | "cancelled"
                | "queue_limit"
                | "invalid_progress"
                | "not_still_image"
                | "live_photo"
                | "burst"
                | "empty_resource_set"
                | "ambiguous_resource_set"
                | "unsupported_resource"
                | "unsupported_type"
        ) {
            Ok(())
        } else {
            Err(PhotoKitNativeError::InvalidResponse)
        }
    }

    fn supported_uti(value: &str) -> bool {
        matches!(
            value,
            "public.jpeg" | "public.png" | "public.heic" | "public.heif"
        )
    }

    fn parse_canonical_uuid(value: &str) -> Result<Uuid, PhotoKitNativeError> {
        let parsed = Uuid::parse_str(value).map_err(|_| PhotoKitNativeError::InvalidResponse)?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != value {
            return Err(PhotoKitNativeError::InvalidResponse);
        }
        Ok(parsed)
    }

    fn status_error(status: i32) -> PhotoKitNativeError {
        match status {
            STATUS_CLOSED => PhotoKitNativeError::Unavailable,
            STATUS_INVALID | STATUS_BUSY => PhotoKitNativeError::InvalidResponse,
            _ => PhotoKitNativeError::Unavailable,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn identity() -> RequestIdentity {
            RequestIdentity {
                operation_id: Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
                enrollment_epoch: Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
                reconciliation_fence: 7,
                generation: 9,
                request_sequence: 11,
            }
        }

        fn asset_event() -> Value {
            json!({
                "protocol_version": 1,
                "event": "asset",
                "operation_id": "11111111-1111-4111-8111-111111111111",
                "enrollment_epoch": "22222222-2222-4222-8222-222222222222",
                "reconciliation_fence": 7,
                "generation": 9,
                "sequence": 11,
                "asset_identifier": "asset-private-id",
                "selection_policy": "original-primary-v1",
                "supported": true,
                "resource_token": "aaaaaaaa-1111-4111-8111-111111111111",
                "uti": "public.heic"
            })
        }

        #[test]
        fn strict_asset_decoder_accepts_only_tokenized_frozen_policy() {
            let bytes = serde_json::to_vec(&asset_event()).unwrap();
            let event = decode_control(&bytes, CommandKind::EnumerateAlbum, &identity()).unwrap();
            match event {
                NativeEvent::Asset(asset) => {
                    let resource = asset.primary_resource.unwrap();
                    assert_eq!(
                        resource.operation_resource_token,
                        "aaaaaaaa-1111-4111-8111-111111111111"
                    );
                    assert_eq!(resource.resource_uti, "public.heic");
                }
                _ => panic!("unexpected event"),
            }

            let mut wrong_policy = asset_event();
            wrong_policy["selection_policy"] = json!("original_primary_v1");
            assert!(decode_control(
                &serde_json::to_vec(&wrong_policy).unwrap(),
                CommandKind::EnumerateAlbum,
                &identity()
            )
            .is_err());

            let mut avif = asset_event();
            avif["uti"] = json!("public.avif");
            assert!(decode_control(
                &serde_json::to_vec(&avif).unwrap(),
                CommandKind::EnumerateAlbum,
                &identity()
            )
            .is_err());
        }

        #[test]
        fn strict_control_decoder_rejects_unknown_fields_and_identity_drift() {
            let mut unknown = asset_event();
            unknown["framework_error"] = json!("private");
            assert!(decode_control(
                &serde_json::to_vec(&unknown).unwrap(),
                CommandKind::EnumerateAlbum,
                &identity()
            )
            .is_err());

            let mut stale = asset_event();
            stale["generation"] = json!(10);
            assert!(decode_control(
                &serde_json::to_vec(&stale).unwrap(),
                CommandKind::EnumerateAlbum,
                &identity()
            )
            .is_err());
        }

        #[test]
        fn binary_decoder_requires_exact_identity_and_chunk_sequence() {
            let identity = identity();
            let mut bytes = vec![0_u8; BINARY_HEADER_BYTES + 3];
            bytes[0..4].copy_from_slice(b"WKPB");
            bytes[4..8].copy_from_slice(&ABI_VERSION.to_le_bytes());
            bytes[8..12].copy_from_slice(&(BINARY_HEADER_BYTES as u32).to_le_bytes());
            bytes[16..24].copy_from_slice(&identity.request_sequence.to_le_bytes());
            bytes[24..32].copy_from_slice(&identity.reconciliation_fence.to_le_bytes());
            bytes[32..40].copy_from_slice(&identity.generation.to_le_bytes());
            bytes[40..48].copy_from_slice(&3_u64.to_le_bytes());
            bytes[48..64].copy_from_slice(identity.operation_id.as_bytes());
            bytes[64..80].copy_from_slice(identity.enrollment_epoch.as_bytes());
            bytes[80..].copy_from_slice(&[1, 2, 3]);

            assert_eq!(decode_binary(&bytes, &identity, 3).unwrap(), [1, 2, 3]);
            assert!(decode_binary(&bytes, &identity, 4).is_err());
            bytes[24] ^= 1;
            assert!(decode_binary(&bytes, &identity, 3).is_err());
        }
    }
}

#[cfg(all(target_os = "macos", feature = "photokit-native"))]
pub use macos::MacOsPhotoKitNativePort;

#[cfg(not(all(target_os = "macos", feature = "photokit-native")))]
pub struct MacOsPhotoKitNativePort;

#[cfg(not(all(target_os = "macos", feature = "photokit-native")))]
impl MacOsPhotoKitNativePort {
    pub fn new() -> Result<Self, PhotoKitNativeError> {
        Err(PhotoKitNativeError::Unavailable)
    }
}

#[cfg(not(all(target_os = "macos", feature = "photokit-native")))]
impl PhotoKitNativePort for MacOsPhotoKitNativePort {
    fn authorization(
        &mut self,
        _request_authorization: bool,
    ) -> Result<PhotoKitAuthorizationV1, PhotoKitNativeError> {
        Err(PhotoKitNativeError::Unavailable)
    }

    fn list_regular_albums(&mut self) -> Result<Vec<PhotoKitNativeAlbum>, PhotoKitNativeError> {
        Err(PhotoKitNativeError::Unavailable)
    }

    fn enumerate_regular_album(
        &mut self,
        _album_locator: &str,
        _operation: &PhotoKitOperation,
        _sink: &mut dyn PhotoKitEnumerationSink,
    ) -> Result<PhotoKitEnumerationTerminal, PhotoKitNativeError> {
        Err(PhotoKitNativeError::Unavailable)
    }

    fn transfer_resource(
        &mut self,
        _operation: &PhotoKitOperation,
        _operation_resource_token: &str,
        _network_access_allowed: bool,
        _sink: &mut dyn PhotoKitNativeByteSink,
    ) -> Result<crate::PhotoKitTransferTerminal, PhotoKitNativeError> {
        Err(PhotoKitNativeError::Unavailable)
    }

    fn validate_image(
        &mut self,
        _duplicated_read_only_file: File,
        _resource_uti: &str,
    ) -> Result<PhotoKitValidatedImage, PhotoKitNativeError> {
        Err(PhotoKitNativeError::Unavailable)
    }
}

pub type ProductionPhotoKitNativePort = MacOsPhotoKitNativePort;
