use crate::contracts::{
    GatewayCancellationPort, GatewayEventV1, GatewayFailure, GatewayRequestV1, OpaqueAssetRef,
    PhotoAssetGateway, RequestRegistrationPort, ResourceDescriptorV1, TransferKind,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GatewayCall {
    Select {
        asset_ref: String,
    },
    Request {
        asset_ref: String,
        resource_ref: String,
        generation: u64,
        kind: TransferKind,
        network_access_allowed: bool,
    },
    Register {
        native_request_id: String,
    },
    Delivered {
        event_count: usize,
        progress_callbacks: usize,
        accepted_bytes: usize,
        terminal_completions: usize,
    },
    Cancel {
        native_request_id: String,
    },
}

#[derive(Clone, Debug)]
pub enum ScriptStep {
    CancelBeforeRegistration,
    CancelAfterRegistration,
    Select {
        asset_ref: String,
        result: Result<ResourceDescriptorV1, GatewayFailure>,
    },
    Request {
        asset_ref: String,
        resource_ref: String,
        kind: TransferKind,
        network_access_allowed: bool,
        events: Result<Vec<GatewayEventV1>, GatewayFailure>,
    },
}

#[derive(Debug)]
pub struct ScriptedPhotoAssetGateway {
    steps: VecDeque<ScriptStep>,
    calls: Arc<Mutex<Vec<GatewayCall>>>,
}

struct ScriptedCancellationPort {
    calls: Arc<Mutex<Vec<GatewayCall>>>,
}

impl ScriptedPhotoAssetGateway {
    pub fn new(steps: impl IntoIterator<Item = ScriptStep>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn calls(&self) -> Vec<GatewayCall> {
        self.calls.lock().expect("script calls lock").clone()
    }

    pub fn assert_exhausted(&self) {
        assert!(self.steps.is_empty(), "script has unconsumed steps");
    }
}

impl PhotoAssetGateway for ScriptedPhotoAssetGateway {
    fn select_resource(
        &mut self,
        asset: &OpaqueAssetRef,
    ) -> Result<ResourceDescriptorV1, GatewayFailure> {
        self.calls
            .lock()
            .expect("script calls lock")
            .push(GatewayCall::Select {
                asset_ref: asset.as_str().to_owned(),
            });
        match self.steps.pop_front() {
            Some(ScriptStep::Select { asset_ref, result }) if asset_ref == asset.as_str() => result,
            _ => Err(GatewayFailure::NativeProtocol),
        }
    }

    fn request(
        &mut self,
        request: &GatewayRequestV1,
        lifecycle: &dyn RequestRegistrationPort,
    ) -> Result<Vec<GatewayEventV1>, GatewayFailure> {
        if matches!(
            self.steps.front(),
            Some(ScriptStep::CancelBeforeRegistration)
        ) {
            self.steps.pop_front();
            lifecycle.cancel_operation()?;
        }
        self.calls
            .lock()
            .expect("script calls lock")
            .push(GatewayCall::Request {
                asset_ref: request.asset_ref.as_str().to_owned(),
                resource_ref: request.resource.resource_ref.clone(),
                generation: request.request_generation,
                kind: request.kind,
                network_access_allowed: request.network_access_allowed,
            });
        let native_request_id = format!(
            "native-{}-{}",
            request.request_generation,
            self.calls.lock().expect("script calls lock").len()
        );
        self.calls
            .lock()
            .expect("script calls lock")
            .push(GatewayCall::Register {
                native_request_id: native_request_id.clone(),
            });
        lifecycle.register(&native_request_id)?;
        if matches!(
            self.steps.front(),
            Some(ScriptStep::CancelAfterRegistration)
        ) {
            self.steps.pop_front();
            lifecycle.cancel_operation()?;
        }
        match self.steps.pop_front() {
            Some(ScriptStep::Request {
                asset_ref,
                resource_ref,
                kind,
                network_access_allowed,
                events,
            }) if asset_ref == request.asset_ref.as_str()
                && resource_ref == request.resource.resource_ref
                && kind == request.kind
                && network_access_allowed == request.network_access_allowed =>
            {
                if let Ok(delivered) = &events {
                    self.calls
                        .lock()
                        .expect("script calls lock")
                        .push(GatewayCall::Delivered {
                            event_count: delivered.len(),
                            progress_callbacks: delivered
                                .iter()
                                .filter(|event| matches!(event, GatewayEventV1::Progress { .. }))
                                .count(),
                            accepted_bytes: delivered
                                .iter()
                                .map(|event| match event {
                                    GatewayEventV1::Chunk { bytes, .. } => bytes.len(),
                                    _ => 0,
                                })
                                .sum(),
                            terminal_completions: delivered
                                .iter()
                                .filter(|event| matches!(event, GatewayEventV1::Completed { .. }))
                                .count(),
                        });
                }
                events
            }
            _ => Err(GatewayFailure::NativeProtocol),
        }
    }

    fn cancellation_port(&self) -> Arc<dyn GatewayCancellationPort> {
        Arc::new(ScriptedCancellationPort {
            calls: Arc::clone(&self.calls),
        })
    }
}

impl GatewayCancellationPort for ScriptedCancellationPort {
    fn cancel(&self, native_request_id: &str) {
        self.calls
            .lock()
            .expect("script calls lock")
            .push(GatewayCall::Cancel {
                native_request_id: native_request_id.to_owned(),
            });
    }
}
