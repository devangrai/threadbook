use crate::approval::{ApprovalError, ApprovalReceipt, DisclosurePreview, ProjectRetention};
use crate::audit::{AuditIdentifier, AuditStatus, RequestAuditEnvelope, TransmittedFields};
use crate::cost::{estimate_completed_cost, CostError, RateCard};
use crate::parser::{parse_response, Failure, FailureKind, ProviderOutcome};
use crate::request::{build_responses_request, ENDPOINT, REGION_MODE, SERVICE_TIER};
use crate::sanitize::{sha256_hex, PreparedEvidence};
use crate::transport::{OutboundRequest, ResponsesTransport, TransportError};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct ProviderConfig {
    retention: ProjectRetention,
    rate_card: RateCard,
    current_date: String,
}

impl ProviderConfig {
    pub fn new(
        retention: ProjectRetention,
        rate_card: RateCard,
        current_date: impl Into<String>,
    ) -> Result<Self, ProviderFactoryError> {
        let current_date = current_date.into();
        rate_card.validate_for(
            crate::request::MODEL,
            SERVICE_TIER,
            REGION_MODE,
            &current_date,
        )?;
        Ok(Self {
            retention,
            rate_card,
            current_date,
        })
    }

    pub fn retention(&self) -> &ProjectRetention {
        &self.retention
    }

    pub fn rate_card(&self) -> &RateCard {
        &self.rate_card
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancellation {
    Active,
    Cancelled,
}

#[derive(Debug)]
pub struct ApprovedExtractionRequest {
    pub logical_operation_id: String,
    pub evidence: PreparedEvidence,
    pub approval: ApprovalReceipt,
    pub cancellation: Cancellation,
}

impl ApprovedExtractionRequest {
    pub fn new(
        logical_operation_id: impl Into<String>,
        evidence: PreparedEvidence,
        approval: ApprovalReceipt,
    ) -> Self {
        Self {
            logical_operation_id: logical_operation_id.into(),
            evidence,
            approval,
            cancellation: Cancellation::Active,
        }
    }

    pub fn cancelled(mut self) -> Self {
        self.cancellation = Cancellation::Cancelled;
        self
    }
}

#[derive(Clone, Debug)]
pub struct ProviderExchange {
    pub audit: RequestAuditEnvelope,
    pub outcome: ProviderOutcome,
}

pub struct ReceiptEvidenceProvider<T: ResponsesTransport> {
    transport: T,
    config: ProviderConfig,
    attempt_ledger: Mutex<AttemptLedger>,
}

#[derive(Default)]
struct AttemptLedger {
    operation_fingerprints: BTreeMap<String, String>,
    consumed_approvals: BTreeSet<String>,
}

impl<T: ResponsesTransport> ReceiptEvidenceProvider<T> {
    pub fn new(transport: T, config: ProviderConfig) -> Self {
        Self {
            transport,
            config,
            attempt_ledger: Mutex::new(AttemptLedger::default()),
        }
    }

    pub fn disclosure_preview(
        &self,
        evidence: &PreparedEvidence,
    ) -> Result<DisclosurePreview, ApprovalError> {
        DisclosurePreview::build(
            evidence,
            &self.config.retention,
            &self.config.rate_card,
            &self.config.current_date,
        )
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn extract(&self, request: ApprovedExtractionRequest) -> ProviderExchange {
        let operation_hash = sha256_hex(request.logical_operation_id.as_bytes());
        let mut audit = RequestAuditEnvelope::base(
            self.config.retention.clone(),
            operation_hash,
            AuditStatus::LocalInvalidApproval,
        );

        if !valid_operation_id(&request.logical_operation_id) {
            return exchange_failure(audit, FailureKind::InvalidApproval);
        }
        if request.cancellation == Cancellation::Cancelled {
            audit.status = AuditStatus::LocalCancellation;
            return exchange_failure(audit, FailureKind::Cancellation);
        }
        let preview = match self.disclosure_preview(&request.evidence) {
            Ok(preview) => preview,
            Err(_) => return exchange_failure(audit, FailureKind::InvalidApproval),
        };
        if !request.approval.matches(&preview) {
            return exchange_failure(audit, FailureKind::InvalidApproval);
        }

        let operation_key = request.logical_operation_id.clone();
        let approval_reference = request.approval.approval_reference().to_owned();
        {
            let mut ledger = self
                .attempt_ledger
                .lock()
                .expect("provider attempt ledger lock poisoned");
            if ledger.operation_fingerprints.contains_key(&operation_key)
                || ledger.consumed_approvals.contains(&approval_reference)
            {
                audit.status = AuditStatus::LocalConflict;
                return exchange_failure(audit, FailureKind::RequestConflict);
            }
            ledger
                .operation_fingerprints
                .insert(operation_key, preview.request_fingerprint().to_owned());
            ledger.consumed_approvals.insert(approval_reference.clone());
        }

        let client_request_id = client_request_id(
            &request.logical_operation_id,
            preview.request_fingerprint(),
            &approval_reference,
        );
        audit.approval_reference = Some(approval_reference);
        audit.input_hash = Some(request.evidence.input_hash().to_owned());
        audit.parent_hashes = request
            .evidence
            .text()
            .map(|text| vec![text.sha256().to_owned()])
            .unwrap_or_default();
        audit.parent_hashes.extend(
            request
                .evidence
                .crops()
                .iter()
                .map(|crop| crop.sha256().to_owned()),
        );
        audit.request_fingerprint = Some(preview.request_fingerprint().to_owned());
        audit.transmitted = TransmittedFields::from_evidence(&request.evidence);
        audit.client_request_id = AuditIdentifier::available(client_request_id.clone());
        audit.provider_request_id = AuditIdentifier::unavailable("response_header_not_received");
        audit.response_id = AuditIdentifier::unavailable("response_body_not_received");
        audit.attempt_count = 1;

        let outbound = OutboundRequest {
            endpoint: ENDPOINT.to_owned(),
            client_request_id,
            body: build_responses_request(&request.evidence),
        };
        let started = Instant::now();
        let response = match self.transport.send(&outbound) {
            Ok(response) => response,
            Err(error) => {
                audit.latency_millis = elapsed_millis(started);
                let (status, kind, cost_reason) = match error {
                    TransportError::Timeout => (
                        AuditStatus::TimeoutRemoteOutcomeUnknown,
                        FailureKind::TimeoutRemoteOutcomeUnknown,
                        "remote_outcome_and_cost_unknown",
                    ),
                    _ => (
                        AuditStatus::TransportFailure,
                        FailureKind::Transport,
                        "provider_usage_unavailable",
                    ),
                };
                audit.status = status;
                audit.cost_unknown_reason = Some(cost_reason.to_owned());
                return exchange_failure(audit, kind);
            }
        };
        audit.latency_millis = elapsed_millis(started);
        audit.provider_request_id = audited_header_id(response.header("x-request-id"));

        let parsed = parse_response(&response, request.evidence.source_ids());
        audit.returned_model = parsed.returned_model.clone();
        audit.response_id = parsed
            .response_id
            .clone()
            .map(AuditIdentifier::available)
            .unwrap_or_else(|| AuditIdentifier::unavailable("not_available_from_valid_response"));
        audit.usage = parsed.usage;
        if let Some(usage) = parsed.usage {
            match estimate_completed_cost(
                &self.config.rate_card,
                usage,
                SERVICE_TIER,
                REGION_MODE,
                &self.config.current_date,
            ) {
                Ok(cost) => audit.cost = Some(cost),
                Err(_) => {
                    audit.status = AuditStatus::ProtocolViolation;
                    audit.cost_unknown_reason = Some("cost_calculation_failed".to_owned());
                    return exchange_failure(audit, FailureKind::CostUnavailable);
                }
            }
        } else {
            audit.cost_unknown_reason = Some("provider_usage_unavailable".to_owned());
        }
        audit.status = status_for_outcome(&parsed.outcome);
        ProviderExchange {
            audit,
            outcome: parsed.outcome,
        }
    }
}

fn exchange_failure(audit: RequestAuditEnvelope, kind: FailureKind) -> ProviderExchange {
    ProviderExchange {
        audit,
        outcome: ProviderOutcome::Failure(Failure::new(kind, false)),
    }
}

fn status_for_outcome(outcome: &ProviderOutcome) -> AuditStatus {
    match outcome {
        ProviderOutcome::Success(_) => AuditStatus::Success,
        ProviderOutcome::Refusal(_) => AuditStatus::Refusal,
        ProviderOutcome::Failure(failure) => match failure.kind {
            FailureKind::InvalidApproval => AuditStatus::LocalInvalidApproval,
            FailureKind::Cancellation => AuditStatus::LocalCancellation,
            FailureKind::RequestConflict => AuditStatus::LocalConflict,
            FailureKind::TimeoutRemoteOutcomeUnknown => AuditStatus::TimeoutRemoteOutcomeUnknown,
            FailureKind::Transport => AuditStatus::TransportFailure,
            FailureKind::Authentication => AuditStatus::AuthenticationFailure,
            FailureKind::RateLimit => AuditStatus::RateLimited,
            FailureKind::Provider5xx => AuditStatus::ProviderFailure,
            FailureKind::ClientHttp => AuditStatus::ClientHttpFailure,
            FailureKind::IncompleteResponse => AuditStatus::Incomplete,
            FailureKind::ProtocolViolation | FailureKind::CostUnavailable => {
                AuditStatus::ProtocolViolation
            }
            FailureKind::MalformedJson => AuditStatus::MalformedJson,
            FailureKind::SchemaViolation => AuditStatus::SchemaViolation,
            FailureKind::SourceReferenceViolation => AuditStatus::SourceReferenceViolation,
        },
    }
}

fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
}

fn client_request_id(operation_id: &str, fingerprint: &str, approval: &str) -> String {
    let digest = sha256_hex(
        [
            b"p00-client-request-v1\0".as_slice(),
            operation_id.as_bytes(),
            b"\0",
            fingerprint.as_bytes(),
            b"\0",
            approval.as_bytes(),
        ]
        .concat()
        .as_slice(),
    );
    format!("p00-{}", &digest[..48])
}

fn audited_header_id(value: Option<&str>) -> AuditIdentifier {
    match value {
        None => AuditIdentifier::unavailable("response_header_missing"),
        Some(value)
            if !value.is_empty()
                && value.len() <= 512
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii() && !byte.is_ascii_control()) =>
        {
            AuditIdentifier::available(value.to_owned())
        }
        Some(_) => AuditIdentifier::unavailable("response_header_invalid"),
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderFactoryError {
    Cost(CostError),
}

impl From<CostError> for ProviderFactoryError {
    fn from(value: CostError) -> Self {
        Self::Cost(value)
    }
}

impl fmt::Display for ProviderFactoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "provider configuration failed: {self:?}")
    }
}

impl Error for ProviderFactoryError {}
