use crate::approval::ProjectRetention;
use crate::cost::{CostBreakdown, Usage};
use crate::request::{
    CACHE_MODE, CONNECT_TIMEOUT_MILLIS, ENDPOINT, MAX_OUTPUT_TOKENS, MODEL, PREPROCESSOR_VERSION,
    PROMPT_VERSION, REGION_MODE, SCHEMA_VERSION, SERVICE_TIER,
};
use crate::sanitize::PreparedEvidence;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditIdentifier {
    pub value: Option<String>,
    pub unavailable_reason: Option<String>,
}

impl AuditIdentifier {
    pub fn available(value: String) -> Self {
        Self {
            value: Some(value),
            unavailable_reason: None,
        }
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            value: None,
            unavailable_reason: Some(reason.into()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    LocalInvalidApproval,
    LocalCancellation,
    LocalConflict,
    Success,
    Refusal,
    TimeoutRemoteOutcomeUnknown,
    TransportFailure,
    AuthenticationFailure,
    RateLimited,
    ProviderFailure,
    ClientHttpFailure,
    Incomplete,
    ProtocolViolation,
    MalformedJson,
    SchemaViolation,
    SourceReferenceViolation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaAudit {
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub byte_count: usize,
    pub base64_byte_count: usize,
    pub detail: String,
    pub sha256: String,
    pub metadata_stripped: bool,
    pub face_free: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmittedFields {
    pub request_field_names: Vec<String>,
    pub receipt_field_names: Vec<String>,
    pub sanitized_text_bytes: usize,
    pub sanitized_text_sha256: Option<String>,
    pub media: Vec<MediaAudit>,
}

impl TransmittedFields {
    pub fn none() -> Self {
        Self {
            request_field_names: Vec::new(),
            receipt_field_names: Vec::new(),
            sanitized_text_bytes: 0,
            sanitized_text_sha256: None,
            media: Vec::new(),
        }
    }

    pub fn from_evidence(evidence: &PreparedEvidence) -> Self {
        Self {
            request_field_names: [
                "model",
                "store",
                "background",
                "tools",
                "conversation",
                "previous_response_id",
                "input",
                "text.format",
                "reasoning.effort",
                "prompt_cache_options.mode",
                "service_tier",
                "max_output_tokens",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            receipt_field_names: evidence
                .text()
                .map(|text| text.field_names())
                .unwrap_or_default(),
            sanitized_text_bytes: evidence
                .text()
                .map(|text| text.rendered().len())
                .unwrap_or(0),
            sanitized_text_sha256: evidence.text().map(|text| text.sha256().to_owned()),
            media: evidence
                .crops()
                .iter()
                .map(|crop| MediaAudit {
                    mime: crop.mime().as_str().to_owned(),
                    width: crop.width(),
                    height: crop.height(),
                    byte_count: crop.bytes().len(),
                    base64_byte_count: crop.base64_byte_count(),
                    detail: crop.detail().as_str().to_owned(),
                    sha256: crop.sha256().to_owned(),
                    metadata_stripped: true,
                    face_free: true,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAuditEnvelope {
    pub purpose: String,
    pub approval_reference: Option<String>,
    pub logical_operation_id_hash: String,
    pub provider: String,
    pub endpoint: String,
    pub requested_model: String,
    pub returned_model: Option<String>,
    pub prompt_version: String,
    pub prompt_hash: String,
    pub schema_version: String,
    pub schema_hash: String,
    pub preprocessor_version: String,
    pub preprocessor_hash: String,
    pub input_hash: Option<String>,
    pub parent_hashes: Vec<String>,
    pub request_fingerprint: Option<String>,
    pub transmitted: TransmittedFields,
    pub store: bool,
    pub cache_mode: String,
    pub cache_breakpoint_count: u8,
    pub service_tier: String,
    pub region: String,
    pub max_output_tokens: u32,
    pub connect_timeout_millis: u64,
    pub total_deadline_millis: u64,
    pub attempt_count: u8,
    pub automatic_timeout_retries: u8,
    pub retention: ProjectRetention,
    pub retention_disclosure_revision: String,
    pub default_abuse_monitoring_max_days: u8,
    pub image_manual_review_exception: bool,
    pub prompt_cache_ttl_minimum_default: String,
    pub prompt_cache_may_retain_longer: bool,
    pub no_breakpoints_no_cache_reads_or_writes: bool,
    pub client_request_id: AuditIdentifier,
    pub provider_request_id: AuditIdentifier,
    pub response_id: AuditIdentifier,
    pub latency_millis: u64,
    pub status: AuditStatus,
    pub usage: Option<Usage>,
    pub cost: Option<CostBreakdown>,
    pub cost_unknown_reason: Option<String>,
}

impl RequestAuditEnvelope {
    pub(crate) fn base(
        retention: ProjectRetention,
        operation_hash: String,
        status: AuditStatus,
    ) -> Self {
        Self {
            purpose: "receipt_evidence_extraction".to_owned(),
            approval_reference: None,
            logical_operation_id_hash: operation_hash,
            provider: "openai".to_owned(),
            endpoint: ENDPOINT.to_owned(),
            requested_model: MODEL.to_owned(),
            returned_model: None,
            prompt_version: PROMPT_VERSION.to_owned(),
            prompt_hash: crate::request::prompt_hash(),
            schema_version: SCHEMA_VERSION.to_owned(),
            schema_hash: crate::request::schema_hash(),
            preprocessor_version: PREPROCESSOR_VERSION.to_owned(),
            preprocessor_hash: crate::request::preprocessor_hash(),
            input_hash: None,
            parent_hashes: Vec::new(),
            request_fingerprint: None,
            transmitted: TransmittedFields::none(),
            store: false,
            cache_mode: CACHE_MODE.to_owned(),
            cache_breakpoint_count: 0,
            service_tier: SERVICE_TIER.to_owned(),
            region: REGION_MODE.to_owned(),
            max_output_tokens: MAX_OUTPUT_TOKENS,
            connect_timeout_millis: CONNECT_TIMEOUT_MILLIS,
            total_deadline_millis: crate::request::TOTAL_DEADLINE_MILLIS,
            attempt_count: 0,
            automatic_timeout_retries: 0,
            retention,
            retention_disclosure_revision: crate::approval::RETENTION_DISCLOSURE_REVISION
                .to_owned(),
            default_abuse_monitoring_max_days: 30,
            image_manual_review_exception: true,
            prompt_cache_ttl_minimum_default: "30m".to_owned(),
            prompt_cache_may_retain_longer: true,
            no_breakpoints_no_cache_reads_or_writes: true,
            client_request_id: AuditIdentifier::unavailable("no_remote_attempt"),
            provider_request_id: AuditIdentifier::unavailable("no_remote_attempt"),
            response_id: AuditIdentifier::unavailable("no_remote_attempt"),
            latency_millis: 0,
            status,
            usage: None,
            cost: None,
            cost_unknown_reason: None,
        }
    }
}
