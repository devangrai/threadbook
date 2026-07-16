use std::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use ts_rs::TS;
use uuid::Uuid;

use crate::validation::{require_schema_v1, validate_bounded_text, validate_timestamp};
use crate::{
    deserialize_schema_version_v1, PageCursorV1, ReplayStatusV1, RequestId, SafeFieldV1,
    Sha256Digest, SourceId, Validate, ValidationError, MAX_SAFE_INTEGER_V1,
};

pub const RECEIPT_EXTRACTION_SCHEMA_V1: &str = "receipt-extraction-v1";
pub const RECEIPT_EXTRACTION_SCHEMA_SHA256_V1: &str =
    "ae4ed0f35de10510c963262954537a970eb4bdfa4d0c2c812a82e26f26a5450f";
pub const MAX_RECEIPT_FRAGMENTS: usize = 200;
pub const MAX_RECEIPT_FRAGMENT_BYTES: usize = 32 * 1024;
pub const MAX_RECEIPT_TEXT_BYTES: usize = 128 * 1024;
pub const MAX_RECEIPT_CITATIONS: usize = 8;
pub const MAX_RECEIPT_CITATION_BYTES: usize = 512;
pub const MAX_RECEIPT_LINE_ITEMS: usize = 100;
pub const MAX_RECEIPT_QUANTITY: u64 = 10_000;
pub const MAX_RECEIPT_TEXT_CHARS: usize = 512;
pub const MAX_RECEIPT_ATTRIBUTE_CHARS: usize = 160;
pub const MAX_RECEIPT_PROVIDER_VALUE_CHARS: usize = 128;
pub const MAX_RECEIPT_METADATA_CHARS: usize = 512;

const ISO_4217_CODES: &str = "
AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BOV BRL BSD BTN BWP
BYN BZD CAD CDF CHE CHF CHW CLF CLP CNY COP COU CRC CUC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB
EUR FJD FKP GBP GEL GHS GIP GMD GNF GTQ GYD HKD HNL HRK HTG HUF IDR ILS INR IQD IRR ISK JMD JOD
JPY KES KGS KHR KMF KPW KRW KWD KYD KZT LAK LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU
MUR MVR MWK MXN MXV MYR MZN NAD NGN NIO NOK NPR NZD OMR PAB PEN PGK PHP PKR PLN PYG QAR RON RSD
RUB RWF SAR SBD SCR SDG SEK SGD SHP SLE SOS SRD SSP STN SVC SYP SZL THB TJS TMT TND TOP TRY TTD
TWD TZS UAH UGX USD USN UYI UYU UYW UZS VED VES VND VUV WST XAF XAG XAU XBA XBB XBC XBD XCD XDR
XOF XPD XPF XPT XSU XTS XUA XXX YER ZAR ZMW ZWG
";

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

macro_rules! receipt_uuid_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, TS)]
        pub struct $name(#[ts(type = "string")] Uuid);

        impl $name {
            pub fn new(value: Uuid) -> Result<Self, &'static str> {
                if value.is_nil() {
                    Err("UUID must not be nil")
                } else {
                    Ok(Self(value))
                }
            }

            pub fn new_v4() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, formatter)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}", self.0.hyphenated())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdVisitor;

                impl<'de> Visitor<'de> for IdVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a canonical non-nil UUID string")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        if value.len() != 36 {
                            return Err(E::custom("UUID must use canonical hyphenated form"));
                        }
                        let parsed =
                            Uuid::parse_str(value).map_err(|_| E::custom("invalid UUID"))?;
                        if parsed.is_nil() || parsed.hyphenated().to_string() != value {
                            return Err(E::custom("UUID must be canonical and non-nil"));
                        }
                        Ok($name(parsed))
                    }
                }

                deserializer.deserialize_str(IdVisitor)
            }
        }
    };
}

receipt_uuid_id!(ReceiptParseId);
receipt_uuid_id!(ReceiptFragmentId);
receipt_uuid_id!(ReceiptExtractionRunId);
receipt_uuid_id!(ReceiptOrderEvidenceId);
receipt_uuid_id!(ReceiptOrderLineId);
receipt_uuid_id!(ReceiptVariantEvidenceId);
receipt_uuid_id!(ReceiptReviewDecisionId);
receipt_uuid_id!(ReceiptImageCandidateId);
receipt_uuid_id!(ReceiptImageAttemptId);
receipt_uuid_id!(ReceiptRemoteImageId);

pub const MAX_RECEIPT_IMAGE_CANDIDATES: usize = 32;
pub const MAX_RECEIPT_IMAGE_HOST_BYTES: usize = 253;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptImageCandidateEligibilityV1 {
    Eligible,
    Blocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptImageAttemptOutcomeV1 {
    Succeeded,
    PolicyRejected,
    TransportFailed,
    ResponseRejected,
    Ambiguous,
    InProgress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptImageFailureCodeV1 {
    DeadlineExceeded,
    InvalidUrl,
    SchemeRejected,
    UserInfoRejected,
    IpLiteralRejected,
    PortRejected,
    HostMismatch,
    DnsFailed,
    DnsAnswerLimit,
    AddressRejected,
    ClientBuildFailed,
    TransportFailed,
    RedirectLocationRejected,
    RedirectCrossHost,
    RedirectLimit,
    HttpStatusRejected,
    HeaderLimit,
    ContentLengthRejected,
    BodyLimit,
    MediaTypeRejected,
    MagicMismatch,
    StructureRejected,
    DimensionsRejected,
    DecodeFailed,
    DerivativeLimit,
    BlockingTaskFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptImageAttemptSummaryV1 {
    pub attempt_id: ReceiptImageAttemptId,
    pub outcome: ReceiptImageAttemptOutcomeV1,
    pub failure_code: Option<ReceiptImageFailureCodeV1>,
}

impl Validate for ReceiptImageAttemptSummaryV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let valid = match self.outcome {
            ReceiptImageAttemptOutcomeV1::Succeeded | ReceiptImageAttemptOutcomeV1::InProgress => {
                self.failure_code.is_none()
            }
            _ => self.failure_code.is_some(),
        };
        if valid {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::ReceiptImageAttempt))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptImageCandidateSummaryV1 {
    pub candidate_id: ReceiptImageCandidateId,
    pub source_id: SourceId,
    pub display_host: String,
    pub candidate_url_sha256: Sha256Digest,
    pub eligibility: ReceiptImageCandidateEligibilityV1,
    pub latest_attempt: Option<ReceiptImageAttemptSummaryV1>,
}

impl Validate for ReceiptImageCandidateSummaryV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(
            &self.display_host,
            1,
            MAX_RECEIPT_IMAGE_HOST_BYTES,
            SafeFieldV1::ReceiptImageCandidate,
        )?;
        if !self.display_host.is_ascii()
            || self
                .display_host
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptImageCandidate));
        }
        if let Some(attempt) = &self.latest_attempt {
            attempt.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRemoteImageV1 {
    pub image_id: ReceiptRemoteImageId,
    pub source_blob_sha256: Sha256Digest,
    #[ts(type = "number")]
    pub source_byte_length: u64,
    pub source_media_type: String,
    pub display_blob_sha256: Sha256Digest,
    #[ts(type = "number")]
    pub display_byte_length: u64,
    pub display_media_type: String,
    pub width: u32,
    pub height: u32,
    pub policy_revision: String,
    pub decoder_revision: String,
    pub derivative_revision: String,
}

impl Validate for ReceiptRemoteImageV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.source_byte_length == 0
            || self.source_byte_length > 8 * 1024 * 1024
            || self.display_byte_length == 0
            || self.display_byte_length > 68 * 1024 * 1024
            || !matches!(
                self.source_media_type.as_str(),
                "image/jpeg" | "image/png" | "image/webp"
            )
            || self.display_media_type != "image/png"
            || !(32..=4096).contains(&self.width)
            || !(32..=4096).contains(&self.height)
            || u64::from(self.width) * u64::from(self.height) > 16_777_216
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptImageCandidate));
        }
        for revision in [
            &self.policy_revision,
            &self.decoder_revision,
            &self.derivative_revision,
        ] {
            validate_bounded_text(revision, 1, 128, SafeFieldV1::ReceiptImageCandidate)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptFragmentKindV1 {
    PlainText,
    SanitizedHtml,
    AttachmentMetadata,
    CidMetadata,
}

impl ReceiptFragmentKindV1 {
    fn canonical_name(self) -> &'static str {
        match self {
            Self::PlainText => "plain_text",
            Self::SanitizedHtml => "sanitized_html",
            Self::AttachmentMetadata => "attachment_metadata",
            Self::CidMetadata => "cid_metadata",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptEventKindV1 {
    Purchase,
    Exchange,
    Return,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptStateV1 {
    Unanalyzed,
    NeedsReview,
    Confirmed,
    Corrected,
    Deferred,
    Rejected,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptReviewActionV1 {
    Confirm,
    Correct,
    Reject,
    Defer,
}

impl ReceiptReviewActionV1 {
    pub fn state(self) -> ReceiptStateV1 {
        match self {
            Self::Confirm => ReceiptStateV1::Confirmed,
            Self::Correct => ReceiptStateV1::Corrected,
            Self::Reject => ReceiptStateV1::Rejected,
            Self::Defer => ReceiptStateV1::Deferred,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
pub enum ReceiptExtractionSchemaV1 {
    #[serde(rename = "receipt-extraction-v1")]
    #[ts(rename = "receipt-extraction-v1")]
    V1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptFragmentMetadataV1 {
    pub content_type: String,
    pub disposition: Option<String>,
    pub safe_filename: Option<String>,
    pub content_id: Option<String>,
    #[ts(type = "number | null")]
    pub decoded_length: Option<u64>,
    pub content_sha256: Option<Sha256Digest>,
}

impl Validate for ReceiptFragmentMetadataV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(
            &self.content_type,
            1,
            MAX_RECEIPT_ATTRIBUTE_CHARS,
            SafeFieldV1::ReceiptFragment,
        )?;
        for value in [
            self.disposition.as_deref(),
            self.safe_filename.as_deref(),
            self.content_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_bounded_text(
                value,
                1,
                MAX_RECEIPT_METADATA_CHARS,
                SafeFieldV1::ReceiptFragment,
            )?;
        }
        if self
            .decoded_length
            .is_some_and(|length| length > MAX_SAFE_INTEGER_V1)
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptFragment));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptFragmentV1 {
    pub fragment_id: ReceiptFragmentId,
    pub ordinal: u16,
    pub kind: ReceiptFragmentKindV1,
    pub text: String,
    pub content_sha256: Sha256Digest,
    pub metadata: Option<ReceiptFragmentMetadataV1>,
}

impl Validate for ReceiptFragmentV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.text.is_empty()
            || self.text.len() > MAX_RECEIPT_FRAGMENT_BYTES
            || self.text.contains('\0')
            || self.content_sha256 != Sha256Digest::from_bytes(self.text.as_bytes())
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptFragment));
        }
        let metadata_shape_is_valid = match self.kind {
            ReceiptFragmentKindV1::PlainText | ReceiptFragmentKindV1::SanitizedHtml => {
                self.metadata.is_none()
            }
            ReceiptFragmentKindV1::AttachmentMetadata => self.metadata.is_some(),
            ReceiptFragmentKindV1::CidMetadata => self
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.content_id.is_some()),
        };
        if !metadata_shape_is_valid {
            return Err(ValidationError::new(SafeFieldV1::ReceiptFragment));
        }
        if let Some(metadata) = &self.metadata {
            metadata.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ParsedReceiptEvidenceV1 {
    pub parse_id: ReceiptParseId,
    pub source_id: SourceId,
    pub raw_blob_sha256: Sha256Digest,
    pub parser_revision: String,
    pub sanitizer_revision: String,
    pub canonical_input_sha256: Sha256Digest,
    pub fragments: Vec<ReceiptFragmentV1>,
}

impl ParsedReceiptEvidenceV1 {
    pub fn compute_canonical_input_sha256(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"parsed-receipt-evidence-v1\0");
        hasher.update(self.source_id.to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(self.raw_blob_sha256.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(self.parser_revision.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.sanitizer_revision.as_bytes());
        hasher.update(b"\0");
        for fragment in &self.fragments {
            hasher.update(fragment.ordinal.to_be_bytes());
            hasher.update(fragment.kind.canonical_name().as_bytes());
            hasher.update(b"\0");
            hasher.update(fragment.fragment_id.to_string().as_bytes());
            hasher.update(b"\0");
            hasher.update(fragment.content_sha256.as_str().as_bytes());
            hasher.update(b"\0");
            hasher.update((fragment.text.len() as u64).to_be_bytes());
            hasher.update(fragment.text.as_bytes());
            hasher.update(b"\0");
        }
        Sha256Digest::parse(format!("{:x}", hasher.finalize()))
            .expect("SHA-256 formatter always returns a valid digest")
    }

    fn fragment(&self, fragment_id: ReceiptFragmentId) -> Option<&ReceiptFragmentV1> {
        self.fragments
            .iter()
            .find(|fragment| fragment.fragment_id == fragment_id)
    }

    pub fn validate_citation(&self, citation: &FragmentCitationV1) -> Result<(), ValidationError> {
        let fragment = self
            .fragment(citation.fragment_id)
            .ok_or_else(|| ValidationError::new(SafeFieldV1::ReceiptCitation))?;
        let start = citation.byte_start as usize;
        let end = citation.byte_end as usize;
        if start >= end
            || end > fragment.text.len()
            || end - start > MAX_RECEIPT_CITATION_BYTES
            || !fragment.text.is_char_boundary(start)
            || !fragment.text.is_char_boundary(end)
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptCitation));
        }
        if citation.quote_sha256 != Sha256Digest::from_bytes(&fragment.text.as_bytes()[start..end])
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptCitation));
        }
        Ok(())
    }
}

impl Validate for ParsedReceiptEvidenceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(
            &self.parser_revision,
            1,
            MAX_RECEIPT_PROVIDER_VALUE_CHARS,
            SafeFieldV1::ReceiptFragment,
        )?;
        validate_bounded_text(
            &self.sanitizer_revision,
            1,
            MAX_RECEIPT_PROVIDER_VALUE_CHARS,
            SafeFieldV1::ReceiptFragment,
        )?;
        if self.fragments.is_empty() || self.fragments.len() > MAX_RECEIPT_FRAGMENTS {
            return Err(ValidationError::new(SafeFieldV1::ReceiptFragment));
        }
        let mut total_bytes = 0_usize;
        let mut ids = Vec::with_capacity(self.fragments.len());
        for (expected_ordinal, fragment) in self.fragments.iter().enumerate() {
            fragment.validate()?;
            if usize::from(fragment.ordinal) != expected_ordinal {
                return Err(ValidationError::new(SafeFieldV1::ReceiptFragment));
            }
            total_bytes = total_bytes
                .checked_add(fragment.text.len())
                .ok_or_else(|| ValidationError::new(SafeFieldV1::ReceiptFragment))?;
            ids.push(fragment.fragment_id);
        }
        ids.sort_unstable();
        ids.dedup();
        if ids.len() != self.fragments.len()
            || total_bytes > MAX_RECEIPT_TEXT_BYTES
            || self.canonical_input_sha256 != self.compute_canonical_input_sha256()
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptFragment));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct FragmentCitationV1 {
    pub fragment_id: ReceiptFragmentId,
    pub byte_start: u32,
    pub byte_end: u32,
    pub quote_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStringV1 {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub value: Option<String>,
    pub citations: Vec<FragmentCitationV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct EvidenceU64V1 {
    #[serde(deserialize_with = "deserialize_required_option")]
    #[ts(type = "number | null")]
    pub value: Option<u64>,
    pub citations: Vec<FragmentCitationV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEventKindV1 {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub value: Option<ReceiptEventKindV1>,
    pub citations: Vec<FragmentCitationV1>,
}

fn validate_evidence_shape<T>(
    value: &Option<T>,
    citations: &[FragmentCitationV1],
) -> Result<(), ValidationError> {
    let valid_count = (1..=MAX_RECEIPT_CITATIONS).contains(&citations.len());
    if (value.is_some() && !valid_count) || (value.is_none() && !citations.is_empty()) {
        return Err(ValidationError::new(SafeFieldV1::ReceiptCitation));
    }
    let mut unique = citations.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() != citations.len() {
        return Err(ValidationError::new(SafeFieldV1::ReceiptCitation));
    }
    Ok(())
}

fn validate_citations(
    parsed: &ParsedReceiptEvidenceV1,
    citations: &[FragmentCitationV1],
) -> Result<(), ValidationError> {
    for citation in citations {
        parsed.validate_citation(citation)?;
    }
    Ok(())
}

impl EvidenceStringV1 {
    fn validate_with_limit(&self, max_chars: usize) -> Result<(), ValidationError> {
        validate_evidence_shape(&self.value, &self.citations)?;
        if let Some(value) = &self.value {
            validate_bounded_text(value, 1, max_chars, SafeFieldV1::ReceiptEvidence)?;
        }
        Ok(())
    }

    fn validate_against(
        &self,
        parsed: &ParsedReceiptEvidenceV1,
        max_chars: usize,
    ) -> Result<(), ValidationError> {
        self.validate_with_limit(max_chars)?;
        validate_citations(parsed, &self.citations)
    }
}

impl Validate for EvidenceStringV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.validate_with_limit(MAX_RECEIPT_TEXT_CHARS)
    }
}

impl EvidenceU64V1 {
    fn validate_with_max(&self, max: u64) -> Result<(), ValidationError> {
        validate_evidence_shape(&self.value, &self.citations)?;
        if self.value.is_some_and(|value| value > max) {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        Ok(())
    }

    fn validate_against_max(
        &self,
        parsed: &ParsedReceiptEvidenceV1,
        max: u64,
    ) -> Result<(), ValidationError> {
        self.validate_with_max(max)?;
        validate_citations(parsed, &self.citations)
    }

    fn validate_quantity_against(
        &self,
        parsed: &ParsedReceiptEvidenceV1,
    ) -> Result<(), ValidationError> {
        if self.value == Some(0) {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        self.validate_against_max(parsed, MAX_RECEIPT_QUANTITY)
    }

    fn validate_quantity(&self) -> Result<(), ValidationError> {
        if self.value == Some(0) {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        self.validate_with_max(MAX_RECEIPT_QUANTITY)
    }
}

impl Validate for EvidenceU64V1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.validate_with_max(MAX_SAFE_INTEGER_V1)
    }
}

impl EvidenceEventKindV1 {
    fn validate_against(&self, parsed: &ParsedReceiptEvidenceV1) -> Result<(), ValidationError> {
        self.validate()?;
        validate_citations(parsed, &self.citations)
    }
}

impl Validate for EvidenceEventKindV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_evidence_shape(&self.value, &self.citations)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptVariantExtractionV1 {
    pub brand: EvidenceStringV1,
    pub sku: EvidenceStringV1,
    pub size: EvidenceStringV1,
    pub color: EvidenceStringV1,
}

impl ReceiptVariantExtractionV1 {
    fn validate_against(&self, parsed: &ParsedReceiptEvidenceV1) -> Result<(), ValidationError> {
        for field in [&self.brand, &self.sku, &self.size, &self.color] {
            field.validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        }
        Ok(())
    }
}

impl Validate for ReceiptVariantExtractionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        for field in [&self.brand, &self.sku, &self.size, &self.color] {
            field.validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptLineItemExtractionV1 {
    pub description: EvidenceStringV1,
    pub event_kind: EvidenceEventKindV1,
    pub quantity: EvidenceU64V1,
    pub unit_price_minor: EvidenceU64V1,
    pub variant: ReceiptVariantExtractionV1,
}

impl ReceiptLineItemExtractionV1 {
    fn validate_against(&self, parsed: &ParsedReceiptEvidenceV1) -> Result<(), ValidationError> {
        self.description
            .validate_against(parsed, MAX_RECEIPT_TEXT_CHARS)?;
        self.event_kind.validate_against(parsed)?;
        self.quantity.validate_quantity_against(parsed)?;
        self.unit_price_minor
            .validate_against_max(parsed, MAX_SAFE_INTEGER_V1)?;
        self.variant.validate_against(parsed)
    }
}

impl Validate for ReceiptLineItemExtractionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.description
            .validate_with_limit(MAX_RECEIPT_TEXT_CHARS)?;
        self.event_kind.validate()?;
        self.quantity.validate_quantity()?;
        self.unit_price_minor
            .validate_with_max(MAX_SAFE_INTEGER_V1)?;
        self.variant.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptExtractionV1 {
    pub schema_version: ReceiptExtractionSchemaV1,
    pub merchant: EvidenceStringV1,
    pub order_identifier: EvidenceStringV1,
    pub purchase_date: EvidenceStringV1,
    pub currency: EvidenceStringV1,
    pub line_items: Vec<ReceiptLineItemExtractionV1>,
}

impl ReceiptExtractionV1 {
    pub fn validate_against(
        &self,
        parsed: &ParsedReceiptEvidenceV1,
    ) -> Result<(), ValidationError> {
        self.validate()?;
        self.merchant
            .validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.order_identifier
            .validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.purchase_date
            .validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.currency
            .validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        for line in &self.line_items {
            line.validate_against(parsed)?;
        }
        Ok(())
    }
}

impl Validate for ReceiptExtractionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.merchant
            .validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.order_identifier
            .validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.purchase_date
            .validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.currency
            .validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        if let Some(date) = &self.purchase_date.value {
            validate_iso_date(date)?;
        }
        if let Some(currency) = &self.currency.value {
            validate_currency(currency)?;
        }
        if self.line_items.is_empty() || self.line_items.len() > MAX_RECEIPT_LINE_ITEMS {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        for line in &self.line_items {
            line.validate()?;
        }
        Ok(())
    }
}

fn validate_iso_date(value: &str) -> Result<(), ValidationError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
    }
    let year = value[0..4]
        .parse::<u16>()
        .map_err(|_| ValidationError::new(SafeFieldV1::ReceiptEvidence))?;
    let month = value[5..7]
        .parse::<u8>()
        .map_err(|_| ValidationError::new(SafeFieldV1::ReceiptEvidence))?;
    let day = value[8..10]
        .parse::<u8>()
        .map_err(|_| ValidationError::new(SafeFieldV1::ReceiptEvidence))?;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > max_day {
        return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
    }
    Ok(())
}

fn validate_currency(value: &str) -> Result<(), ValidationError> {
    if value.len() == 3
        && value.bytes().all(|byte| byte.is_ascii_uppercase())
        && ISO_4217_CODES
            .split_ascii_whitespace()
            .any(|code| code == value)
    {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::ReceiptEvidence))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptProviderParametersV1 {
    pub deterministic: bool,
    pub temperature_milli: u16,
    pub locale: Option<String>,
}

impl Validate for ReceiptProviderParametersV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if !self.deterministic || self.temperature_milli != 0 {
            return Err(ValidationError::new(SafeFieldV1::ReceiptProviderOutput));
        }
        if let Some(locale) = &self.locale {
            validate_bounded_text(
                locale,
                1,
                MAX_RECEIPT_PROVIDER_VALUE_CHARS,
                SafeFieldV1::ReceiptProviderOutput,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptProcessingMetadataV1 {
    pub provider_id: String,
    pub provider_revision: String,
    pub extraction_schema: String,
    pub extraction_schema_sha256: Sha256Digest,
    pub ruleset_revision: String,
    pub ruleset_sha256: Sha256Digest,
    pub parameters: ReceiptProviderParametersV1,
    pub canonical_input_sha256: Sha256Digest,
    pub parent_source_id: SourceId,
    pub parent_source_sha256: Sha256Digest,
    pub fragment_sha256: Vec<Sha256Digest>,
}

impl ReceiptProcessingMetadataV1 {
    pub fn validate_against(
        &self,
        parsed: &ParsedReceiptEvidenceV1,
    ) -> Result<(), ValidationError> {
        self.validate()?;
        let expected_schema_hash =
            Sha256Digest::parse(RECEIPT_EXTRACTION_SCHEMA_SHA256_V1.to_owned())
                .map_err(|_| ValidationError::new(SafeFieldV1::ReceiptProviderOutput))?;
        let expected_fragments = parsed
            .fragments
            .iter()
            .map(|fragment| fragment.content_sha256.clone())
            .collect::<Vec<_>>();
        if self.extraction_schema != RECEIPT_EXTRACTION_SCHEMA_V1
            || self.extraction_schema_sha256 != expected_schema_hash
            || self.canonical_input_sha256 != parsed.canonical_input_sha256
            || self.parent_source_id != parsed.source_id
            || self.parent_source_sha256 != parsed.raw_blob_sha256
            || self.fragment_sha256 != expected_fragments
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptProviderOutput));
        }
        Ok(())
    }
}

impl Validate for ReceiptProcessingMetadataV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        for value in [
            &self.provider_id,
            &self.provider_revision,
            &self.extraction_schema,
            &self.ruleset_revision,
        ] {
            validate_bounded_text(
                value,
                1,
                MAX_RECEIPT_PROVIDER_VALUE_CHARS,
                SafeFieldV1::ReceiptProviderOutput,
            )?;
        }
        self.parameters.validate()?;
        if self.fragment_sha256.is_empty() || self.fragment_sha256.len() > MAX_RECEIPT_FRAGMENTS {
            return Err(ValidationError::new(SafeFieldV1::ReceiptProviderOutput));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptExtractionEnvelopeV1 {
    pub processing: ReceiptProcessingMetadataV1,
    pub output: ReceiptExtractionV1,
}

impl ReceiptExtractionEnvelopeV1 {
    pub fn validate_against(
        &self,
        parsed: &ParsedReceiptEvidenceV1,
    ) -> Result<(), ValidationError> {
        parsed.validate()?;
        self.processing.validate_against(parsed)?;
        self.output.validate_against(parsed)
    }
}

impl Validate for ReceiptExtractionEnvelopeV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.processing.validate()?;
        self.output.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CorrectedReceiptVariantV1 {
    pub variant_evidence_id: ReceiptVariantEvidenceId,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub brand: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub sku: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub size: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub color: Option<String>,
}

impl Validate for CorrectedReceiptVariantV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        for value in [
            self.brand.as_deref(),
            self.sku.as_deref(),
            self.size.as_deref(),
            self.color.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_bounded_text(
                value,
                1,
                MAX_RECEIPT_ATTRIBUTE_CHARS,
                SafeFieldV1::ReceiptEvidence,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CorrectedReceiptOrderLineV1 {
    pub order_line_id: ReceiptOrderLineId,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub description: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub event_kind: Option<ReceiptEventKindV1>,
    #[serde(deserialize_with = "deserialize_required_option")]
    #[ts(type = "number | null")]
    pub quantity: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    #[ts(type = "number | null")]
    pub unit_price_minor: Option<u64>,
    pub variant: CorrectedReceiptVariantV1,
}

impl Validate for CorrectedReceiptOrderLineV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(description) = &self.description {
            validate_bounded_text(
                description,
                1,
                MAX_RECEIPT_TEXT_CHARS,
                SafeFieldV1::ReceiptEvidence,
            )?;
        }
        if self
            .quantity
            .is_some_and(|quantity| quantity == 0 || quantity > MAX_RECEIPT_QUANTITY)
            || self
                .unit_price_minor
                .is_some_and(|price| price > MAX_SAFE_INTEGER_V1)
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        self.variant.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CorrectedReceiptOrderV1 {
    pub order_evidence_id: ReceiptOrderEvidenceId,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub merchant: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub order_identifier: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub purchase_date: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub currency: Option<String>,
    pub line_items: Vec<CorrectedReceiptOrderLineV1>,
}

impl Validate for CorrectedReceiptOrderV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        for value in [self.merchant.as_deref(), self.order_identifier.as_deref()]
            .into_iter()
            .flatten()
        {
            validate_bounded_text(
                value,
                1,
                MAX_RECEIPT_ATTRIBUTE_CHARS,
                SafeFieldV1::ReceiptEvidence,
            )?;
        }
        if let Some(date) = &self.purchase_date {
            validate_iso_date(date)?;
        }
        if let Some(currency) = &self.currency {
            validate_currency(currency)?;
        }
        if self.line_items.is_empty() || self.line_items.len() > MAX_RECEIPT_LINE_ITEMS {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        let mut line_ids = Vec::with_capacity(self.line_items.len());
        let mut variant_ids = Vec::with_capacity(self.line_items.len());
        for line in &self.line_items {
            line.validate()?;
            line_ids.push(line.order_line_id);
            variant_ids.push(line.variant.variant_evidence_id);
        }
        line_ids.sort_unstable();
        line_ids.dedup();
        variant_ids.sort_unstable();
        variant_ids.dedup();
        if line_ids.len() != self.line_items.len() || variant_ids.len() != self.line_items.len() {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptReviewDecisionV1 {
    pub decision_id: ReceiptReviewDecisionId,
    pub order_evidence_id: ReceiptOrderEvidenceId,
    pub action: ReceiptReviewActionV1,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub corrected_order: Option<CorrectedReceiptOrderV1>,
    #[ts(type = "number")]
    pub receipt_revision: u64,
    pub created_at: String,
}

impl Validate for ReceiptReviewDecisionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_timestamp(&self.created_at)?;
        if self.receipt_revision == 0 || self.receipt_revision > MAX_SAFE_INTEGER_V1 {
            return Err(ValidationError::new(SafeFieldV1::ExpectedReceiptRevision));
        }
        match (&self.action, &self.corrected_order) {
            (ReceiptReviewActionV1::Correct, Some(corrected)) => {
                corrected.validate()?;
                if corrected.order_evidence_id != self.order_evidence_id {
                    return Err(ValidationError::new(SafeFieldV1::ReceiptReviewAction));
                }
            }
            (ReceiptReviewActionV1::Correct, None)
            | (ReceiptReviewActionV1::Confirm, Some(_))
            | (ReceiptReviewActionV1::Reject, Some(_))
            | (ReceiptReviewActionV1::Defer, Some(_)) => {
                return Err(ValidationError::new(SafeFieldV1::ReceiptReviewAction));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptReviewHeadV1 {
    pub state: ReceiptStateV1,
    pub decision: ReceiptReviewDecisionV1,
}

impl Validate for ReceiptReviewHeadV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.decision.validate()?;
        if self.state != self.decision.action.state() {
            return Err(ValidationError::new(SafeFieldV1::ReceiptReviewAction));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptVariantEvidenceV1 {
    pub variant_evidence_id: ReceiptVariantEvidenceId,
    pub brand: EvidenceStringV1,
    pub sku: EvidenceStringV1,
    pub size: EvidenceStringV1,
    pub color: EvidenceStringV1,
}

impl ReceiptVariantEvidenceV1 {
    fn validate_against(&self, parsed: &ParsedReceiptEvidenceV1) -> Result<(), ValidationError> {
        for field in [&self.brand, &self.sku, &self.size, &self.color] {
            field.validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        }
        Ok(())
    }
}

impl Validate for ReceiptVariantEvidenceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        for field in [&self.brand, &self.sku, &self.size, &self.color] {
            field.validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptOrderLineV1 {
    pub order_line_id: ReceiptOrderLineId,
    pub line_number: u16,
    pub description: EvidenceStringV1,
    pub event_kind: EvidenceEventKindV1,
    pub quantity: EvidenceU64V1,
    pub unit_price_minor: EvidenceU64V1,
    pub variant: ReceiptVariantEvidenceV1,
}

impl ReceiptOrderLineV1 {
    fn validate_against(&self, parsed: &ParsedReceiptEvidenceV1) -> Result<(), ValidationError> {
        self.description
            .validate_against(parsed, MAX_RECEIPT_TEXT_CHARS)?;
        self.event_kind.validate_against(parsed)?;
        self.quantity.validate_quantity_against(parsed)?;
        self.unit_price_minor
            .validate_against_max(parsed, MAX_SAFE_INTEGER_V1)?;
        self.variant.validate_against(parsed)
    }
}

impl Validate for ReceiptOrderLineV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.description
            .validate_with_limit(MAX_RECEIPT_TEXT_CHARS)?;
        self.event_kind.validate()?;
        self.quantity.validate_quantity()?;
        self.unit_price_minor
            .validate_with_max(MAX_SAFE_INTEGER_V1)?;
        self.variant.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptOrderEvidenceV1 {
    pub order_evidence_id: ReceiptOrderEvidenceId,
    pub extraction_run_id: ReceiptExtractionRunId,
    pub source_id: SourceId,
    pub parse_id: ReceiptParseId,
    pub merchant: EvidenceStringV1,
    pub order_identifier: EvidenceStringV1,
    pub purchase_date: EvidenceStringV1,
    pub currency: EvidenceStringV1,
    pub line_items: Vec<ReceiptOrderLineV1>,
    pub review_head: Option<ReceiptReviewHeadV1>,
}

impl ReceiptOrderEvidenceV1 {
    pub fn state(&self) -> ReceiptStateV1 {
        self.review_head
            .as_ref()
            .map_or(ReceiptStateV1::NeedsReview, |head| head.state)
    }

    pub fn validate_against(
        &self,
        parsed: &ParsedReceiptEvidenceV1,
    ) -> Result<(), ValidationError> {
        self.validate()?;
        if self.source_id != parsed.source_id || self.parse_id != parsed.parse_id {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        self.merchant
            .validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.order_identifier
            .validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.purchase_date
            .validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.currency
            .validate_against(parsed, MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        for line in &self.line_items {
            line.validate_against(parsed)?;
        }
        Ok(())
    }

    pub fn matches_extraction(&self, extraction: &ReceiptExtractionV1) -> bool {
        self.merchant == extraction.merchant
            && self.order_identifier == extraction.order_identifier
            && self.purchase_date == extraction.purchase_date
            && self.currency == extraction.currency
            && self.line_items.len() == extraction.line_items.len()
            && self
                .line_items
                .iter()
                .zip(&extraction.line_items)
                .all(|(stored, extracted)| {
                    stored.description == extracted.description
                        && stored.event_kind == extracted.event_kind
                        && stored.quantity == extracted.quantity
                        && stored.unit_price_minor == extracted.unit_price_minor
                        && stored.variant.brand == extracted.variant.brand
                        && stored.variant.sku == extracted.variant.sku
                        && stored.variant.size == extracted.variant.size
                        && stored.variant.color == extracted.variant.color
                })
    }
}

impl Validate for ReceiptOrderEvidenceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.merchant
            .validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.order_identifier
            .validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.purchase_date
            .validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        self.currency
            .validate_with_limit(MAX_RECEIPT_ATTRIBUTE_CHARS)?;
        if let Some(date) = &self.purchase_date.value {
            validate_iso_date(date)?;
        }
        if let Some(currency) = &self.currency.value {
            validate_currency(currency)?;
        }
        if self.line_items.is_empty() || self.line_items.len() > MAX_RECEIPT_LINE_ITEMS {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        let mut line_ids = Vec::with_capacity(self.line_items.len());
        let mut variant_ids = Vec::with_capacity(self.line_items.len());
        for (index, line) in self.line_items.iter().enumerate() {
            line.validate()?;
            if usize::from(line.line_number) != index + 1 {
                return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
            }
            line_ids.push(line.order_line_id);
            variant_ids.push(line.variant.variant_evidence_id);
        }
        line_ids.sort_unstable();
        line_ids.dedup();
        variant_ids.sort_unstable();
        variant_ids.dedup();
        if line_ids.len() != self.line_items.len() || variant_ids.len() != self.line_items.len() {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        if let Some(head) = &self.review_head {
            head.validate()?;
            if head.decision.order_evidence_id != self.order_evidence_id {
                return Err(ValidationError::new(SafeFieldV1::ReceiptReviewAction));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSummaryV1 {
    pub source_id: SourceId,
    pub state: ReceiptStateV1,
    pub order_evidence_id: Option<ReceiptOrderEvidenceId>,
    pub merchant: Option<String>,
    pub line_item_count: u16,
    pub processing: Option<ReceiptProcessingMetadataV1>,
    pub review_head: Option<ReceiptReviewHeadV1>,
}

impl Validate for ReceiptSummaryV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Some(merchant) = &self.merchant {
            validate_bounded_text(
                merchant,
                1,
                MAX_RECEIPT_ATTRIBUTE_CHARS,
                SafeFieldV1::ReceiptEvidence,
            )?;
        }
        if let Some(processing) = &self.processing {
            processing.validate()?;
        }
        if let Some(head) = &self.review_head {
            head.validate()?;
        }
        let shape_is_valid = match self.state {
            ReceiptStateV1::Unanalyzed | ReceiptStateV1::Failed => {
                self.order_evidence_id.is_none()
                    && self.line_item_count == 0
                    && self.review_head.is_none()
            }
            ReceiptStateV1::NeedsReview => {
                self.order_evidence_id.is_some()
                    && self.line_item_count > 0
                    && self.review_head.is_none()
            }
            state => {
                self.order_evidence_id.is_some()
                    && self.line_item_count > 0
                    && self
                        .review_head
                        .as_ref()
                        .is_some_and(|head| head.state == state)
            }
        };
        if shape_is_valid {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::ReceiptEvidence))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListReceiptsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub state: ReceiptStateV1,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListReceiptsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if (1..=100).contains(&self.limit) {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::Limit))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeReceiptV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub source_id: SourceId,
}

impl Validate for AnalyzeReceiptV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReviewReceiptV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub order_evidence_id: ReceiptOrderEvidenceId,
    pub action: ReceiptReviewActionV1,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub corrected_order: Option<CorrectedReceiptOrderV1>,
    #[ts(type = "number")]
    pub expected_receipt_revision: u64,
}

impl Validate for ReviewReceiptV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.expected_receipt_revision >= MAX_SAFE_INTEGER_V1 {
            return Err(ValidationError::new(SafeFieldV1::ExpectedReceiptRevision));
        }
        match (&self.action, &self.corrected_order) {
            (ReceiptReviewActionV1::Correct, Some(corrected)) => {
                corrected.validate()?;
                if corrected.order_evidence_id != self.order_evidence_id {
                    return Err(ValidationError::new(SafeFieldV1::ReceiptReviewAction));
                }
            }
            (ReceiptReviewActionV1::Correct, None)
            | (ReceiptReviewActionV1::Confirm, Some(_))
            | (ReceiptReviewActionV1::Reject, Some(_))
            | (ReceiptReviewActionV1::Defer, Some(_)) => {
                return Err(ValidationError::new(SafeFieldV1::ReceiptReviewAction));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListReceiptsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub receipts: Vec<ReceiptSummaryV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub receipt_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub next_cursor: Option<PageCursorV1>,
}

impl Validate for ListReceiptsV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_revision(self.receipt_revision)?;
        validate_revision(self.evidence_generation)?;
        for receipt in &self.receipts {
            receipt.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeReceiptV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub parsed: ParsedReceiptEvidenceV1,
    pub order: ReceiptOrderEvidenceV1,
    pub processing: ReceiptProcessingMetadataV1,
    pub state: ReceiptStateV1,
    #[ts(type = "number")]
    pub receipt_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for AnalyzeReceiptV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.parsed.validate()?;
        self.processing.validate_against(&self.parsed)?;
        self.order.validate_against(&self.parsed)?;
        validate_revision(self.receipt_revision)?;
        validate_revision(self.evidence_generation)?;
        if self.state != self.order.state() {
            return Err(ValidationError::new(SafeFieldV1::ReceiptEvidence));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReviewReceiptV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub order: ReceiptOrderEvidenceV1,
    pub decision: ReceiptReviewDecisionV1,
    #[ts(type = "number")]
    pub new_receipt_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for ReviewReceiptV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.order.validate()?;
        self.decision.validate()?;
        validate_revision(self.new_receipt_revision)?;
        validate_revision(self.evidence_generation)?;
        let head_matches = self
            .order
            .review_head
            .as_ref()
            .is_some_and(|head| head.decision == self.decision);
        if self.order.order_evidence_id != self.decision.order_evidence_id || !head_matches {
            return Err(ValidationError::new(SafeFieldV1::ReceiptReviewAction));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListReceiptImageCandidatesV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub source_id: SourceId,
}

impl Validate for ListReceiptImageCandidatesV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListReceiptImageCandidatesV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub source_id: SourceId,
    pub candidates: Vec<ReceiptImageCandidateSummaryV1>,
    pub omitted_count: u16,
}

impl Validate for ListReceiptImageCandidatesV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.candidates.len() > MAX_RECEIPT_IMAGE_CANDIDATES {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        for candidate in &self.candidates {
            if candidate.source_id != self.source_id {
                return Err(ValidationError::new(SafeFieldV1::ReceiptImageCandidate));
            }
            candidate.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ApproveAndFetchReceiptImageV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub candidate_id: ReceiptImageCandidateId,
    pub approved_display_host: String,
    pub candidate_url_sha256: Sha256Digest,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub prior_attempt_id: Option<ReceiptImageAttemptId>,
}

impl Validate for ApproveAndFetchReceiptImageV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_bounded_text(
            &self.approved_display_host,
            1,
            MAX_RECEIPT_IMAGE_HOST_BYTES,
            SafeFieldV1::ReceiptImageCandidate,
        )?;
        if !self.approved_display_host.is_ascii()
            || self
                .approved_display_host
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptImageCandidate));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ApproveAndFetchReceiptImageV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub candidate_id: ReceiptImageCandidateId,
    pub attempt_id: ReceiptImageAttemptId,
    pub outcome: ReceiptImageAttemptOutcomeV1,
    pub failure_code: Option<ReceiptImageFailureCodeV1>,
    pub artifact: Option<ReceiptRemoteImageV1>,
    pub replay_status: ReplayStatusV1,
}

impl Validate for ApproveAndFetchReceiptImageV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        let valid = match self.outcome {
            ReceiptImageAttemptOutcomeV1::Succeeded => {
                self.failure_code.is_none() && self.artifact.is_some()
            }
            ReceiptImageAttemptOutcomeV1::InProgress => {
                self.failure_code.is_none() && self.artifact.is_none()
            }
            _ => self.failure_code.is_some() && self.artifact.is_none(),
        };
        if !valid {
            return Err(ValidationError::new(SafeFieldV1::ReceiptImageAttempt));
        }
        if let Some(artifact) = &self.artifact {
            artifact.validate()?;
        }
        Ok(())
    }
}

fn validate_revision(revision: u64) -> Result<(), ValidationError> {
    if revision <= MAX_SAFE_INTEGER_V1 {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::ExpectedReceiptRevision))
    }
}
