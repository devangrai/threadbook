use std::cell::{Cell, RefCell};

use wardrobe_core::*;

#[derive(Default)]
struct Connector {
    calls: RefCell<Vec<&'static str>>,
    error: Cell<Option<PhotoKitConnectorPortErrorKind>>,
    wrong_request_id: Cell<bool>,
    wrong_trigger: Cell<bool>,
    wrong_consent: Cell<bool>,
}

impl Connector {
    fn response_request_id(&self, expected: RequestId) -> RequestId {
        if self.wrong_request_id.get() {
            RequestId::new_v4()
        } else {
            expected
        }
    }

    fn fail<T>(&self) -> PhotoKitConnectorPortResult<T> {
        Err(PhotoKitConnectorPortError::new(self.error.get().unwrap()))
    }
}

impl PhotoKitConnectorPort for Connector {
    fn snapshot(
        &self,
        request: &GetPhotoKitConnectorV1Request,
    ) -> PhotoKitConnectorPortResult<GetPhotoKitConnectorV1Response> {
        self.calls.borrow_mut().push("snapshot");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(GetPhotoKitConnectorV1Response {
            schema_version: 1,
            request_id: self.response_request_id(request.request_id),
            snapshot: unconfigured_snapshot(0),
        })
    }

    fn begin_setup(
        &self,
        request: &BeginPhotoKitSetupV1Request,
    ) -> PhotoKitConnectorPortResult<BeginPhotoKitSetupV1Response> {
        self.calls.borrow_mut().push("begin_setup");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(BeginPhotoKitSetupV1Response {
            schema_version: 1,
            request_id: self.response_request_id(request.request_id),
            snapshot: PhotoKitConnectorSnapshotV1 {
                authorization: PhotoKitAuthorizationV1::Authorized,
                state: PhotoKitConnectorStateV1::SetupRequired,
                ..unconfigured_snapshot(0)
            },
            setup_session_id: Some(PhotoKitSetupSessionIdV1::new_v4()),
            expires_at: Some("2026-07-15T20:40:00Z".to_owned()),
            album_candidates: vec![PhotoKitAlbumCandidateV1 {
                selection_token: PhotoKitSelectionTokenV1::new("selection-token").unwrap(),
                display_label: "Fixture Album".to_owned(),
            }],
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn configure_scope(
        &self,
        request: &ConfigurePhotoKitScopeV1Request,
    ) -> PhotoKitConnectorPortResult<ConfigurePhotoKitScopeV1Response> {
        self.calls.borrow_mut().push("configure_scope");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(ConfigurePhotoKitScopeV1Response {
            schema_version: 1,
            request_id: self.response_request_id(request.request_id),
            snapshot: configured_snapshot(
                1,
                if self.wrong_consent.get() {
                    !request.allow_icloud_downloads
                } else {
                    request.allow_icloud_downloads
                },
            ),
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn reconcile(
        &self,
        request: &SyncPhotoKitV1Request,
        trigger: PhotoKitReconcileTriggerV1,
    ) -> PhotoKitConnectorPortResult<SyncPhotoKitV1Response> {
        self.calls.borrow_mut().push("reconcile");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(SyncPhotoKitV1Response {
            schema_version: 1,
            request_id: self.response_request_id(request.request_id),
            operation_id: OperationId::new_v4(),
            trigger: if self.wrong_trigger.get() {
                PhotoKitReconcileTriggerV1::Startup
            } else {
                trigger
            },
            reconciliation_fence: PhotoKitReconciliationFenceV1::new(1).unwrap(),
            snapshot: configured_snapshot(2, false),
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn disable(
        &self,
        request: &DisablePhotoKitV1Request,
    ) -> PhotoKitConnectorPortResult<DisablePhotoKitV1Response> {
        self.calls.borrow_mut().push("disable");
        if self.error.get().is_some() {
            return self.fail();
        }
        Ok(DisablePhotoKitV1Response {
            schema_version: 1,
            request_id: self.response_request_id(request.request_id),
            state: PhotoKitConnectorStateV1::Unconfigured,
            disabled_enrollment_epoch: PhotoKitEnrollmentEpochV1::new_v4(),
            preserved_membership_generation: None,
            photokit_revision: PhotoKitRevisionV1::new(
                request.expected_photokit_revision.get() + 1,
            )
            .unwrap(),
            preserved_counts: counts(0, 0, 0),
            replay_status: ReplayStatusV1::Created,
        })
    }
}

fn counts(observed: u16, available: u16, unavailable: u16) -> PhotoKitAssetCountsV1 {
    PhotoKitAssetCountsV1 {
        observed,
        available,
        unavailable,
    }
}

fn unconfigured_snapshot(revision: u64) -> PhotoKitConnectorSnapshotV1 {
    PhotoKitConnectorSnapshotV1 {
        state: PhotoKitConnectorStateV1::Unconfigured,
        authorization: PhotoKitAuthorizationV1::NotDetermined,
        enrollment_epoch: None,
        membership_generation: None,
        photokit_revision: PhotoKitRevisionV1::new(revision).unwrap(),
        allow_icloud_downloads: false,
        last_complete_at: None,
        counts: counts(0, 0, 0),
        availability_counts: vec![],
    }
}

fn configured_snapshot(revision: u64, allow_icloud_downloads: bool) -> PhotoKitConnectorSnapshotV1 {
    PhotoKitConnectorSnapshotV1 {
        state: PhotoKitConnectorStateV1::Ready,
        authorization: PhotoKitAuthorizationV1::Authorized,
        enrollment_epoch: Some(PhotoKitEnrollmentEpochV1::new_v4()),
        membership_generation: None,
        photokit_revision: PhotoKitRevisionV1::new(revision).unwrap(),
        allow_icloud_downloads,
        last_complete_at: None,
        counts: counts(0, 0, 0),
        availability_counts: vec![],
    }
}

fn request<T>(build: impl FnOnce(RequestId) -> T) -> T {
    build(RequestId::new_v4())
}

#[test]
fn service_validates_and_dispatches_all_photokit_operations() {
    let service = ApplicationService::new((), (), ()).with_photokit_connector(Connector::default());

    service
        .get_photokit_connector_v1(request(|request_id| GetPhotoKitConnectorV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap();
    service
        .begin_photokit_setup_v1(request(|request_id| BeginPhotoKitSetupV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap();
    service
        .configure_photokit_scope_v1(request(|request_id| ConfigurePhotoKitScopeV1Request {
            schema_version: 1,
            request_id,
            setup_session_id: PhotoKitSetupSessionIdV1::new_v4(),
            selection_token: PhotoKitSelectionTokenV1::new("selection-token").unwrap(),
            allow_icloud_downloads: true,
        }))
        .unwrap();
    let sync = service
        .sync_photokit_v1(request(|request_id| SyncPhotoKitV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap();
    service
        .disable_photokit_v1(request(|request_id| DisablePhotoKitV1Request {
            schema_version: 1,
            request_id,
            expected_photokit_revision: PhotoKitRevisionV1::new(2).unwrap(),
        }))
        .unwrap();

    assert_eq!(sync.trigger, PhotoKitReconcileTriggerV1::User);
    assert_eq!(
        service.photokit_connector().calls.borrow().as_slice(),
        [
            "snapshot",
            "begin_setup",
            "configure_scope",
            "reconcile",
            "disable"
        ]
    );
}

#[test]
fn invalid_requests_do_not_reach_photokit_connector() {
    let service = ApplicationService::new((), (), ()).with_photokit_connector(Connector::default());
    let error = service
        .sync_photokit_v1(request(|request_id| SyncPhotoKitV1Request {
            schema_version: 2,
            request_id,
        }))
        .unwrap_err();

    assert_eq!(error.code, ErrorCodeV1::UnsupportedSchemaVersion);
    assert_eq!(error.field, Some(SafeFieldV1::SchemaVersion));
    assert!(service.photokit_connector().calls.borrow().is_empty());
}

#[test]
fn malformed_photokit_port_responses_fail_closed() {
    let service = ApplicationService::new((), (), ()).with_photokit_connector(Connector::default());
    service.photokit_connector().wrong_request_id.set(true);
    let error = service
        .get_photokit_connector_v1(request(|request_id| GetPhotoKitConnectorV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::DataIntegrity);

    service.photokit_connector().wrong_request_id.set(false);
    service.photokit_connector().wrong_trigger.set(true);
    let error = service
        .sync_photokit_v1(request(|request_id| SyncPhotoKitV1Request {
            schema_version: 1,
            request_id,
        }))
        .unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::DataIntegrity);

    service.photokit_connector().wrong_trigger.set(false);
    service.photokit_connector().wrong_consent.set(true);
    let error = service
        .configure_photokit_scope_v1(request(|request_id| ConfigurePhotoKitScopeV1Request {
            schema_version: 1,
            request_id,
            setup_session_id: PhotoKitSetupSessionIdV1::new_v4(),
            selection_token: PhotoKitSelectionTokenV1::new("selection-token").unwrap(),
            allow_icloud_downloads: true,
        }))
        .unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::DataIntegrity);
}

#[test]
fn photokit_port_errors_map_to_safe_command_errors() {
    let cases = [
        (
            PhotoKitConnectorPortErrorKind::Unavailable,
            ErrorCodeV1::ProviderUnavailable,
            true,
            UserActionKeyV1::Retry,
            None,
        ),
        (
            PhotoKitConnectorPortErrorKind::Conflict,
            ErrorCodeV1::RequestConflict,
            false,
            UserActionKeyV1::StartNewRequest,
            None,
        ),
        (
            PhotoKitConnectorPortErrorKind::Busy,
            ErrorCodeV1::InvalidState,
            true,
            UserActionKeyV1::Retry,
            None,
        ),
        (
            PhotoKitConnectorPortErrorKind::InvalidState,
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::ConfigurePhotoKit,
            None,
        ),
        (
            PhotoKitConnectorPortErrorKind::PermissionDenied,
            ErrorCodeV1::PermissionDenied,
            false,
            UserActionKeyV1::ReviewPhotoLibraryAccess,
            None,
        ),
        (
            PhotoKitConnectorPortErrorKind::CredentialUnavailable,
            ErrorCodeV1::CredentialUnavailable,
            true,
            UserActionKeyV1::UnlockKeychain,
            None,
        ),
        (
            PhotoKitConnectorPortErrorKind::ScopeTooLarge,
            ErrorCodeV1::InvalidRequest,
            false,
            UserActionKeyV1::ConfigurePhotoKit,
            Some(SafeFieldV1::PhotoKitCounts),
        ),
        (
            PhotoKitConnectorPortErrorKind::SessionExpired,
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::BeginPhotoKitSetup,
            Some(SafeFieldV1::PhotoKitSetupSession),
        ),
        (
            PhotoKitConnectorPortErrorKind::SelectionTokenConsumed,
            ErrorCodeV1::InvalidState,
            false,
            UserActionKeyV1::BeginPhotoKitSetup,
            Some(SafeFieldV1::PhotoKitSelectionToken),
        ),
        (
            PhotoKitConnectorPortErrorKind::DataIntegrity,
            ErrorCodeV1::DataIntegrity,
            false,
            UserActionKeyV1::RestartApplication,
            None,
        ),
        (
            PhotoKitConnectorPortErrorKind::NotFound,
            ErrorCodeV1::NotFound,
            false,
            UserActionKeyV1::ConfigurePhotoKit,
            None,
        ),
        (
            PhotoKitConnectorPortErrorKind::Internal,
            ErrorCodeV1::Internal,
            true,
            UserActionKeyV1::Retry,
            None,
        ),
    ];

    for (kind, code, retryable, action, field) in cases {
        let connector = Connector::default();
        connector.error.set(Some(kind));
        let service = ApplicationService::new((), (), ()).with_photokit_connector(connector);
        let error = service
            .sync_photokit_v1(request(|request_id| SyncPhotoKitV1Request {
                schema_version: 1,
                request_id,
            }))
            .unwrap_err();
        assert_eq!(error.code, code, "{kind:?}");
        assert_eq!(error.retryable, retryable, "{kind:?}");
        assert_eq!(error.user_action, action, "{kind:?}");
        assert_eq!(error.field, field, "{kind:?}");
    }
}
