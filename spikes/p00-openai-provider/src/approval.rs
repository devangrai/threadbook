use crate::cost::{estimate_preflight_ceiling, CostBreakdown, CostError, RateCard};
use crate::request::{
    preprocessor_hash, prompt_hash, request_fingerprint, schema_hash, CACHE_MODE,
    MAX_OUTPUT_TOKENS, MODEL, PREPROCESSOR_VERSION, PROMPT_VERSION, REGION_MODE, SCHEMA_VERSION,
    SERVICE_TIER,
};
use crate::sanitize::{sha256_hex, PreparedEvidence};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

pub const RETENTION_DISCLOSURE_REVISION: &str = "openai-data-boundary-2026-07-14-v2";
static APPROVAL_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionMode {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "default")]
    Default,
    #[serde(rename = "MAM")]
    Mam,
    #[serde(rename = "ZDR")]
    Zdr,
}

impl RetentionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Default => "default",
            Self::Mam => "MAM",
            Self::Zdr => "ZDR",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectRetention {
    pub mode: RetentionMode,
    pub provenance: String,
}

impl ProjectRetention {
    pub fn new(mode: RetentionMode, provenance: impl Into<String>) -> Result<Self, ApprovalError> {
        let provenance = provenance.into();
        if provenance.is_empty()
            || provenance.len() > 128
            || !provenance.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
        {
            return Err(ApprovalError::InvalidRetentionProvenance);
        }
        Ok(Self { mode, provenance })
    }

    pub fn binding_hash(&self) -> String {
        sha256_hex(
            &serde_json::to_vec(self).expect("validated retention declaration must serialize"),
        )
    }
}

#[derive(Debug)]
pub struct DisclosurePreview {
    preview_hash: String,
    rendered: String,
    request_fingerprint: String,
    cost_ceiling: CostBreakdown,
}

impl DisclosurePreview {
    pub fn build(
        evidence: &PreparedEvidence,
        retention: &ProjectRetention,
        rate_card: &RateCard,
        on_date: &str,
    ) -> Result<Self, ApprovalError> {
        let cost_ceiling = estimate_preflight_ceiling(
            rate_card,
            evidence.crops(),
            SERVICE_TIER,
            REGION_MODE,
            on_date,
        )?;
        let retention_hash = retention.binding_hash();
        let request_fingerprint = request_fingerprint(evidence, &retention_hash);
        let crop_metadata = evidence
            .crops()
            .iter()
            .map(|crop| {
                json!({
                    "source_id": crop.source_id(),
                    "mime": crop.mime().as_str(),
                    "width": crop.width(),
                    "height": crop.height(),
                    "byte_count": crop.bytes().len(),
                    "base64_byte_count": crop.base64_byte_count(),
                    "detail": crop.detail().as_str(),
                    "sha256": crop.sha256(),
                    "face_free": true,
                    "metadata_stripped": true,
                    "surroundings_minimized": true
                })
            })
            .collect::<Vec<_>>();
        let binding = json!({
            "purpose": "receipt_evidence_extraction",
            "provider": "openai",
            "model": MODEL,
            "retention": retention,
            "retention_disclosure_revision": RETENTION_DISCLOSURE_REVISION,
            "store": false,
            "store_false_is_not_zdr": true,
            "abuse_monitoring_retention_up_to_days": 30,
            "image_manual_review_exception_disclosed": true,
            "prompt_cache_ttl_minimum_default": "30m",
            "prompt_cache_may_retain_longer": true,
            "cache_mode": CACHE_MODE,
            "cache_breakpoints": [],
            "no_breakpoints_no_cache_reads_or_writes": true,
            "service_tier": SERVICE_TIER,
            "region": REGION_MODE,
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "attempt_ceiling": 1,
            "automatic_timeout_retry": false,
            "prompt_version": PROMPT_VERSION,
            "prompt_hash": prompt_hash(),
            "schema_version": SCHEMA_VERSION,
            "schema_hash": schema_hash(),
            "preprocessor_version": PREPROCESSOR_VERSION,
            "preprocessor_hash": preprocessor_hash(),
            "input_hash": evidence.input_hash(),
            "text_hash": evidence.text().map(|text| text.sha256()),
            "crops": crop_metadata,
            "request_fingerprint": request_fingerprint,
            "cost_ceiling_micro_usd": cost_ceiling.estimated_micro_usd,
            "rate_card_id": cost_ceiling.rate_card_id
        });
        let preview_hash =
            sha256_hex(&serde_json::to_vec(&binding).expect("disclosure binding must serialize"));
        let exact_text = evidence
            .text()
            .map(|text| text.rendered())
            .unwrap_or("(no receipt text submitted)");
        let rendered = format!(
            "Purpose: receipt evidence extraction\n\
             Provider/model: OpenAI {MODEL}\n\
             Exact sanitized text:\n{exact_text}\n\
             Crop metadata: {}\n\
             Retention mode/provenance: {} / {}\n\
             store=false; not a ZDR claim; abuse monitoring may retain content up to 30 days.\n\
             Images may be retained for safety review under the disclosed exception.\n\
             GPT-5.6 prompt-cache ttl 30m is the minimum and default; OpenAI may retain cached \
             prefixes longer. Explicit mode with no breakpoints means this request performs no \
             prompt-cache reads or writes.\n\
             Cost ceiling: {} micro-USD using rate card {}\n\
             Attempts: 1; automatic timeout retries: 0",
            serde_json::to_string(&binding["crops"])
                .expect("crop disclosure metadata must serialize"),
            retention.mode.as_str(),
            retention.provenance,
            cost_ceiling.estimated_micro_usd,
            cost_ceiling.rate_card_id
        );
        Ok(Self {
            preview_hash,
            rendered,
            request_fingerprint,
            cost_ceiling,
        })
    }

    pub fn preview_hash(&self) -> &str {
        &self.preview_hash
    }

    pub fn rendered(&self) -> &str {
        &self.rendered
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    pub fn cost_ceiling(&self) -> &CostBreakdown {
        &self.cost_ceiling
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    Affirmed,
    NoAction,
    Dismissed,
    Cancelled,
}

#[derive(Debug)]
pub struct ApprovalReceipt {
    preview_hash: String,
    approval_reference: String,
}

impl ApprovalReceipt {
    pub fn confirm(preview_hash: &str, decision: ApprovalDecision) -> Result<Self, ApprovalError> {
        if decision != ApprovalDecision::Affirmed {
            return Err(ApprovalError::NotAffirmed);
        }
        if preview_hash.len() != 64
            || !preview_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ApprovalError::InvalidPreviewHash);
        }
        let sequence = APPROVAL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            preview_hash: preview_hash.to_owned(),
            approval_reference: sha256_hex(
                [
                    b"p00-approval-v2\0".as_slice(),
                    preview_hash.as_bytes(),
                    &sequence.to_be_bytes(),
                ]
                .concat()
                .as_slice(),
            ),
        })
    }

    pub(crate) fn matches(&self, preview: &DisclosurePreview) -> bool {
        self.preview_hash == preview.preview_hash
    }

    pub fn approval_reference(&self) -> &str {
        &self.approval_reference
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    NotAffirmed,
    InvalidPreviewHash,
    InvalidRetentionProvenance,
    Cost(CostError),
}

impl From<CostError> for ApprovalError {
    fn from(value: CostError) -> Self {
        Self::Cost(value)
    }
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "approval failed: {self:?}")
    }
}

impl Error for ApprovalError {}
