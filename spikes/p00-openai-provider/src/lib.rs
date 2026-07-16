pub mod approval;
pub mod audit;
pub mod cost;
pub mod model;
pub mod parser;
pub mod provider;
pub mod request;
pub mod sanitize;
pub mod synthetic;
pub mod transport;

pub use approval::{
    ApprovalDecision, ApprovalError, ApprovalReceipt, DisclosurePreview, ProjectRetention,
    RetentionMode,
};
pub use audit::{
    AuditIdentifier, AuditStatus, MediaAudit, RequestAuditEnvelope, TransmittedFields,
};
pub use cost::{
    aggregate_attempt_cost, estimate_completed_cost, estimate_preflight_ceiling, CostBreakdown,
    CostError, ImageTokenPolicy, RateCard, Usage,
};
pub use model::{
    receipt_observation_schema, EvidenceInteger, EvidenceString, GarmentLineObservation,
    ReceiptObservationV1,
};
pub use parser::{Failure, FailureKind, ProviderOutcome, Refusal, Success};
pub use provider::{
    ApprovedExtractionRequest, Cancellation, ProviderConfig, ProviderExchange,
    ProviderFactoryError, ReceiptEvidenceProvider,
};
pub use request::{
    build_responses_request, CONNECT_TIMEOUT_MILLIS, ENDPOINT, MAX_OUTPUT_TOKENS, MODEL,
    PREPROCESSOR_VERSION, PROMPT_VERSION, SCHEMA_VERSION, TOTAL_DEADLINE_MILLIS,
};
pub use sanitize::{
    CropDetail, CropInput, CropMime, PreparedEvidence, ReceiptLineTextInput, ReceiptTextInput,
    SanitizationError, SanitizedCrop, SanitizedReceiptText,
};
pub use transport::{
    FakeStep, FakeTransport, HttpResponse, OutboundRequest, ResponsesTransport, TransportError,
};

#[cfg(feature = "live-canary")]
pub use transport::ReqwestTransport;
