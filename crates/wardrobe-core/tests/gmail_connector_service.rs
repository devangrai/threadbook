use std::cell::{Cell, RefCell};

use wardrobe_core::*;

const CLIENT_ID: &str = "1234567890-desktop.apps.googleusercontent.com";

#[derive(Default)]
struct Connector {
    calls: RefCell<Vec<&'static str>>,
    error: Cell<Option<GmailConnectorPortErrorKind>>,
    wrong_request_id: Cell<bool>,
    wrong_status: Cell<bool>,
}

impl Connector {
    fn request_id(&self, expected: RequestId) -> RequestId {
        if self.wrong_request_id.get() {
            RequestId::new_v4()
        } else {
            expected
        }
    }

    fn fail<T>(&self) -> GmailConnectorPortResult<T> {
        Err(GmailConnectorPortError::new(self.error.get().unwrap()))
    }
}

impl GmailConnectorPort for Connector {
    fn get_gmail_connector(
        &self,
        request: &GetGmailConnectorV1Request,
    ) -> GmailConnectorPortResult<GetGmailConnectorV1Response> {
        self.calls.borrow_mut().push("get");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(GetGmailConnectorV1Response {
            schema_version: 1,
            request_id: self.request_id(request.request_id),
            settings: Some(settings()),
            status: GmailConnectorStatusV1::Disconnected,
            user_action: UserActionKeyV1::ConnectGmail,
        })
    }

    fn save_gmail_settings(
        &self,
        request: &SaveGmailSettingsV1Request,
    ) -> GmailConnectorPortResult<SaveGmailSettingsV1Response> {
        self.calls.borrow_mut().push("save");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(SaveGmailSettingsV1Response {
            schema_version: 1,
            request_id: self.request_id(request.request_id),
            settings: GmailConnectorSettingsV1 {
                provider_profile: GmailProviderProfileV1::Google,
                oauth_client_id: request.client_id.clone(),
                label_name: request.label_name.clone(),
                limits: request.limits.clone(),
            },
            status: GmailConnectorStatusV1::Disconnected,
            user_action: UserActionKeyV1::ConnectGmail,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn connect_gmail(
        &self,
        request: &ConnectGmailV1Request,
    ) -> GmailConnectorPortResult<ConnectGmailV1Response> {
        self.calls.borrow_mut().push("connect");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(ConnectGmailV1Response {
            schema_version: 1,
            request_id: self.request_id(request.request_id),
            status: if self.wrong_status.get() {
                GmailConnectorStatusV1::Disconnected
            } else {
                GmailConnectorStatusV1::Connected
            },
            user_action: UserActionKeyV1::None,
            summary: summary(),
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn sync_gmail(
        &self,
        request: &SyncGmailV1Request,
    ) -> GmailConnectorPortResult<SyncGmailV1Response> {
        self.calls.borrow_mut().push("sync");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(SyncGmailV1Response {
            schema_version: 1,
            request_id: self.request_id(request.request_id),
            status: GmailConnectorStatusV1::Connected,
            user_action: UserActionKeyV1::None,
            summary: summary(),
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn disconnect_gmail(
        &self,
        request: &DisconnectGmailV1Request,
    ) -> GmailConnectorPortResult<DisconnectGmailV1Response> {
        self.calls.borrow_mut().push("disconnect");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(DisconnectGmailV1Response {
            schema_version: 1,
            request_id: self.request_id(request.request_id),
            status: GmailConnectorStatusV1::Disconnected,
            user_action: UserActionKeyV1::ConnectGmail,
            revocation_outcome: GmailRevocationOutcomeV1::Failed,
            replay_status: ReplayStatusV1::Created,
        })
    }
}

fn limits() -> GmailConnectorLimitsV1 {
    GmailConnectorLimitsV1 {
        page_size: 50,
        max_pages: 5,
        max_unique_messages: 100,
        max_total_raw_bytes: 1024 * 1024,
    }
}

fn settings() -> GmailConnectorSettingsV1 {
    GmailConnectorSettingsV1 {
        provider_profile: GmailProviderProfileV1::Google,
        oauth_client_id: CLIENT_ID.to_owned(),
        label_name: "Wardrobe Receipts".to_owned(),
        limits: limits(),
    }
}

fn summary() -> GmailSyncSummaryV1 {
    GmailSyncSummaryV1 {
        pages_scanned: 1,
        unique_messages: 1,
        messages_imported: 1,
        messages_updated: 0,
        messages_unavailable: 0,
        raw_bytes_read: 256,
    }
}

fn envelope<T>(build: impl FnOnce(RequestId) -> T) -> T {
    build(RequestId::new_v4())
}

#[test]
fn service_validates_then_dispatches_every_gmail_command() {
    let service = ApplicationService::new((), (), ()).with_gmail_connector(Connector::default());

    service
        .get_gmail_connector_v1(envelope(|request_id| GetGmailConnectorV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap();
    service
        .save_gmail_settings_v1(envelope(|request_id| SaveGmailSettingsV1Request {
            schema_version: 1,
            request_id,
            client_id: CLIENT_ID.to_owned(),
            label_name: "Wardrobe Receipts".to_owned(),
            limits: limits(),
        }))
        .unwrap();
    service
        .connect_gmail_v1(envelope(|request_id| ConnectGmailV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap();
    service
        .sync_gmail_v1(envelope(|request_id| SyncGmailV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap();
    let disconnected = service
        .disconnect_gmail_v1(envelope(|request_id| DisconnectGmailV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap();

    assert_eq!(
        service.gmail_connector().calls.borrow().as_slice(),
        ["get", "save", "connect", "sync", "disconnect"]
    );
    assert_eq!(
        disconnected.revocation_outcome,
        GmailRevocationOutcomeV1::Failed
    );
}

#[test]
fn malformed_request_ids_and_statuses_from_port_fail_closed() {
    let service = ApplicationService::new((), (), ()).with_gmail_connector(Connector::default());
    service.gmail_connector().wrong_request_id.set(true);

    let error = service
        .sync_gmail_v1(envelope(|request_id| SyncGmailV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::DataIntegrity);

    service.gmail_connector().wrong_request_id.set(false);
    service.gmail_connector().wrong_status.set(true);
    let error = service
        .connect_gmail_v1(envelope(|request_id| ConnectGmailV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::DataIntegrity);
}

#[test]
fn invalid_requests_never_reach_the_connector() {
    let service = ApplicationService::new((), (), ()).with_gmail_connector(Connector::default());
    let error = service
        .save_gmail_settings_v1(envelope(|request_id| SaveGmailSettingsV1Request {
            schema_version: 1,
            request_id,
            client_id: "not-a-client-id".to_owned(),
            label_name: "Wardrobe Receipts".to_owned(),
            limits: limits(),
        }))
        .unwrap_err();

    assert_eq!(error.field, Some(SafeFieldV1::GmailClientId));
    assert!(service.gmail_connector().calls.borrow().is_empty());
}

#[test]
fn gmail_port_errors_map_to_safe_command_errors() {
    let cases = [
        (
            GmailConnectorPortErrorKind::Unavailable,
            ErrorCodeV1::ProviderUnavailable,
            true,
            UserActionKeyV1::Retry,
        ),
        (
            GmailConnectorPortErrorKind::Conflict,
            ErrorCodeV1::RequestConflict,
            false,
            UserActionKeyV1::StartNewRequest,
        ),
        (
            GmailConnectorPortErrorKind::Busy,
            ErrorCodeV1::InvalidState,
            true,
            UserActionKeyV1::Retry,
        ),
        (
            GmailConnectorPortErrorKind::InvalidState,
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::ConnectGmail,
        ),
        (
            GmailConnectorPortErrorKind::PermissionDenied,
            ErrorCodeV1::PermissionDenied,
            false,
            UserActionKeyV1::ConnectGmail,
        ),
        (
            GmailConnectorPortErrorKind::CredentialUnavailable,
            ErrorCodeV1::CredentialUnavailable,
            true,
            UserActionKeyV1::UnlockKeychain,
        ),
        (
            GmailConnectorPortErrorKind::ScopeTooLarge,
            ErrorCodeV1::InvalidRequest,
            false,
            UserActionKeyV1::ConfigureGmail,
        ),
        (
            GmailConnectorPortErrorKind::MalformedProviderOutput,
            ErrorCodeV1::MalformedProviderOutput,
            false,
            UserActionKeyV1::Retry,
        ),
        (
            GmailConnectorPortErrorKind::DataIntegrity,
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::RestartApplication,
        ),
        (
            GmailConnectorPortErrorKind::NotFound,
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::CorrectRequest,
        ),
        (
            GmailConnectorPortErrorKind::Internal,
            ErrorCodeV1::Internal,
            true,
            UserActionKeyV1::Retry,
        ),
    ];

    for (kind, code, retryable, action) in cases {
        let connector = Connector::default();
        connector.error.set(Some(kind));
        let service = ApplicationService::new((), (), ()).with_gmail_connector(connector);
        let error = service
            .sync_gmail_v1(envelope(|request_id| SyncGmailV1Request {
                schema_version: 1,
                request_id,
            }))
            .unwrap_err();
        assert_eq!(error.code, code, "{kind:?}");
        assert_eq!(error.retryable, retryable, "{kind:?}");
        assert_eq!(error.user_action, action, "{kind:?}");
    }
}
