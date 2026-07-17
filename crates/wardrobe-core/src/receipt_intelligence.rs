use std::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use ts_rs::TS;
use uuid::Uuid;

use crate::validation::{parse_timestamp, require_schema_v1, validate_timestamp};
use crate::{
    deserialize_schema_version_v1, CredentialId, OpenAiRetentionDeclarationV1,
    OpenAiRetentionModeV1, PageCursorV1, ReceiptOrderEvidenceId, ReceiptReviewHeadV1,
    ReplayStatusV1, RequestId, SafeFieldV1, Sha256Digest, SourceId, Validate, ValidationError,
    MAX_PAGE_SIZE, MAX_SAFE_INTEGER_V1,
};

pub const RECEIPT_INTELLIGENCE_PROVIDER_V1: &str = "openai";
pub const RECEIPT_INTELLIGENCE_MODEL_V1: &str = "gpt-5.6-sol";
pub const RECEIPT_INTELLIGENCE_PURPOSE_V1: &str = "receipt_intelligence";
pub const RECEIPT_INTELLIGENCE_PROMPT_REVISION_V1: &str = "receipt-intelligence-prompt-v1";
pub const RECEIPT_INTELLIGENCE_SCHEMA_REVISION_V1: &str = "receipt-intelligence-v1";
pub const RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1: &str = "receipt-intelligence-projection-v1";
pub const RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1: &str = "receipt-intelligence-parameters-v1";
pub const RECEIPT_INTELLIGENCE_RETENTION_REVISION_V1: &str = "p11-openai-responses-retention-v1";

pub const MAX_RECEIPT_INTELLIGENCE_FRAGMENTS_V1: u16 = 64;
pub const MAX_RECEIPT_INTELLIGENCE_FRAGMENT_BYTES_V1: u32 = 16 * 1024;
pub const MAX_RECEIPT_INTELLIGENCE_TEXT_BYTES_V1: u32 = 128 * 1024;
pub const MAX_RECEIPT_INTELLIGENCE_SERIALIZED_REQUEST_BYTES_V1: u32 = 256 * 1024;
pub const MAX_RECEIPT_INTELLIGENCE_REQUEST_BYTES_V1: u32 = 256 * 1024;
pub const MAX_RECEIPT_INTELLIGENCE_RESPONSE_BYTES_V1: u32 = 2 * 1024 * 1024;
pub const MAX_RECEIPT_INTELLIGENCE_OUTPUT_TOKENS_V1: u32 = 4_000;
pub const RECEIPT_INTELLIGENCE_TIMEOUT_MILLIS_V1: u32 = 60_000;
pub const MAX_RECEIPT_INTELLIGENCE_ATTEMPTS_V1: u8 = 1;
pub const MAX_RECEIPT_INTELLIGENCE_PROVIDER_ID_CHARS_V1: usize = 128;

fn invalid() -> ValidationError {
    ValidationError::new(SafeFieldV1::ReceiptProviderOutput)
}

const URI_SCHEMES_WITHOUT_AUTHORITY: &[&[u8]] = &[
    b"bitcoin",
    b"blob",
    b"cid",
    b"data",
    b"facetime",
    b"facetime-audio",
    b"file",
    b"ftp",
    b"ftps",
    b"geo",
    b"http",
    b"https",
    b"intent",
    b"javascript",
    b"ldap",
    b"ldaps",
    b"magnet",
    b"mailto",
    b"market",
    b"mid",
    b"news",
    b"nntp",
    b"sip",
    b"sips",
    b"sms",
    b"smsto",
    b"sftp",
    b"ssh",
    b"tel",
    b"urn",
    b"vbscript",
    b"webcal",
    b"ws",
    b"wss",
];

const COMMON_OR_RESERVED_TLDS: &[&[u8]] = &[
    b"ai",
    b"app",
    b"au",
    b"biz",
    b"boutique",
    b"br",
    b"ca",
    b"cc",
    b"ch",
    b"clothing",
    b"cloud",
    b"cn",
    b"co",
    b"com",
    b"de",
    b"dev",
    b"dk",
    b"edu",
    b"email",
    b"es",
    b"eu",
    b"example",
    b"fashion",
    b"fi",
    b"fr",
    b"gov",
    b"hk",
    b"ie",
    b"in",
    b"info",
    b"invalid",
    b"io",
    b"it",
    b"jp",
    b"kr",
    b"ly",
    b"me",
    b"mx",
    b"net",
    b"nl",
    b"no",
    b"nz",
    b"online",
    b"org",
    b"sale",
    b"se",
    b"sg",
    b"shoes",
    b"shop",
    b"site",
    b"store",
    b"tech",
    b"test",
    b"tv",
    b"uk",
    b"us",
    b"website",
    b"xyz",
];

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn is_scheme_character(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'+' | b'-' | b'.')
}

fn contains_uri_scheme(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        let starts_at_boundary = index == 0 || !is_scheme_character(bytes[index - 1]);
        if starts_at_boundary && bytes[index].is_ascii_alphabetic() {
            let start = index;
            let mut end = index + 1;
            while end < bytes.len() && end - start <= 32 && is_scheme_character(bytes[end]) {
                end += 1;
            }
            if end < bytes.len()
                && end - start <= 32
                && bytes[end] == b':'
                && bytes
                    .get(end + 1)
                    .is_some_and(|value| !value.is_ascii_whitespace())
            {
                let scheme = &bytes[start..end];
                let has_authority = bytes.get(end + 1..end + 3) == Some(b"//");
                let known_opaque_scheme = URI_SCHEMES_WITHOUT_AUTHORITY
                    .iter()
                    .any(|known| ascii_eq_ignore_case(scheme, known));
                let namespaced_scheme = scheme
                    .iter()
                    .any(|value| matches!(value, b'+' | b'-' | b'.'));
                if has_authority || known_opaque_scheme || namespaced_scheme {
                    return true;
                }
            }
        }
        index += 1;
    }
    false
}

fn is_hostname_character(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'.')
}

fn valid_hostname_label(label: &[u8]) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label[0].is_ascii_alphanumeric()
        && label[label.len() - 1].is_ascii_alphanumeric()
        && label
            .iter()
            .all(|value| value.is_ascii_alphanumeric() || *value == b'-')
}

fn is_known_tld(tld: &[u8]) -> bool {
    (tld.len() >= 4
        && ascii_eq_ignore_case(&tld[..4], b"xn--")
        && tld[4..].iter().all(u8::is_ascii_alphanumeric))
        || COMMON_OR_RESERVED_TLDS
            .iter()
            .any(|known| ascii_eq_ignore_case(tld, known))
}

fn has_url_tail(bytes: &[u8], hostname_end: usize) -> bool {
    match bytes.get(hostname_end) {
        Some(b'/' | b'?' | b'#') => true,
        Some(b':') => bytes.get(hostname_end + 1).is_some_and(u8::is_ascii_digit),
        _ => false,
    }
}

fn is_ipv4_address(labels: &[&[u8]]) -> bool {
    labels.len() == 4
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 3
                && label.iter().all(u8::is_ascii_digit)
                && std::str::from_utf8(label)
                    .ok()
                    .and_then(|value| value.parse::<u8>().ok())
                    .is_some()
        })
}

fn contains_bare_web_address(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        let starts_at_boundary = bytes[index].is_ascii_alphanumeric()
            && (index == 0 || !is_hostname_character(bytes[index - 1]));
        if !starts_at_boundary {
            index += 1;
            continue;
        }

        let start = index;
        let mut end = start + 1;
        while end < bytes.len() && is_hostname_character(bytes[end]) {
            end += 1;
        }
        let mut hostname_end = end;
        while hostname_end > start && bytes[hostname_end - 1] == b'.' {
            hostname_end -= 1;
        }
        let hostname = &bytes[start..hostname_end];
        let labels = hostname.split(|value| *value == b'.').collect::<Vec<_>>();
        let preceded_by_at = start > 0 && bytes[start - 1] == b'@';
        let protocol_relative = start >= 2 && bytes.get(start - 2..start) == Some(b"//");
        let url_tail = has_url_tail(bytes, hostname_end);

        if labels.len() >= 2
            && labels.iter().all(|label| valid_hostname_label(label))
            && (!preceded_by_at || url_tail)
        {
            let tld = labels[labels.len() - 1];
            let alphabetic_tld = tld.len() >= 2 && tld.iter().all(u8::is_ascii_alphabetic);
            let www_prefixed = ascii_eq_ignore_case(labels[0], b"www");
            if is_ipv4_address(&labels)
                || is_known_tld(tld)
                || protocol_relative
                || (www_prefixed && alphabetic_tld)
                || (alphabetic_tld && url_tail)
            {
                return true;
            }
        }

        if ascii_eq_ignore_case(hostname, b"localhost") && url_tail {
            return true;
        }
        index = end.max(index + 1);
    }
    false
}

fn contains_url_or_uri(text: &str) -> bool {
    let bytes = text.as_bytes();
    contains_uri_scheme(bytes) || contains_bare_web_address(bytes)
}

macro_rules! receipt_intelligence_uuid_id {
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

                impl Visitor<'_> for IdVisitor {
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

receipt_intelligence_uuid_id!(ReceiptIntelligenceApprovalId);
receipt_intelligence_uuid_id!(ReceiptIntelligenceAttemptId);
receipt_intelligence_uuid_id!(ReceiptIntelligenceClassificationId);
receipt_intelligence_uuid_id!(ReceiptIntelligenceAuditId);
receipt_intelligence_uuid_id!(ReceiptIntelligenceSourceRevisionId);
receipt_intelligence_uuid_id!(ReceiptSourceAuthorityId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptIntelligenceClassificationV1 {
    ApparelOrder,
    ApparelLifecycleUpdate,
    Unrelated,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptIntelligenceAttemptStateV1 {
    NotSent,
    Dispatched,
    Completed,
    Refused,
    Failed,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptIntelligenceReasoningEffortV1 {
    Low,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptIntelligenceFailureCodeV1 {
    ApprovalExpired,
    ApprovalConsumed,
    ConsentMismatch,
    BoundExceeded,
    LocalOnly,
    ReleaseEvidenceUnavailable,
    OutboundAuthorityUnavailable,
    CredentialUnavailable,
    RetentionDeclarationStale,
    SourceUnavailable,
    SourceRevisionChanged,
    ProviderAuthentication,
    ProviderRateLimited,
    ProviderUnavailable,
    ProviderProtocol,
    ProviderOutputInvalid,
    CitationInvalid,
    PersistenceFailed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptIntelligenceUserActionV1 {
    None,
    StartNewPreview,
    CheckOpenAiCredential,
    ReviewRetentionSettings,
    RetryWhenAvailable,
    ReviewSource,
    ReviewProviderStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptIntelligenceAvailabilityReasonV1 {
    LocalOnly,
    ReleaseEvidenceUnavailable,
    OutboundAuthorityUnavailable,
    CredentialUnavailable,
    RetentionDeclarationUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptSourceAuthorityKindV1 {
    UserReviewed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligencePreparationBoundsV1 {
    pub max_fragment_count: u16,
    pub max_fragment_bytes: u32,
    pub max_aggregate_text_bytes: u32,
    pub max_serialized_request_bytes: u32,
}

impl ReceiptIntelligencePreparationBoundsV1 {
    pub const fn production() -> Self {
        Self {
            max_fragment_count: MAX_RECEIPT_INTELLIGENCE_FRAGMENTS_V1,
            max_fragment_bytes: MAX_RECEIPT_INTELLIGENCE_FRAGMENT_BYTES_V1,
            max_aggregate_text_bytes: MAX_RECEIPT_INTELLIGENCE_TEXT_BYTES_V1,
            max_serialized_request_bytes: MAX_RECEIPT_INTELLIGENCE_SERIALIZED_REQUEST_BYTES_V1,
        }
    }
}

impl Validate for ReceiptIntelligencePreparationBoundsV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self == &Self::production() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceExecutionBoundsV1 {
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub max_output_tokens: u32,
    pub timeout_millis: u32,
    pub max_attempts: u8,
}

impl ReceiptIntelligenceExecutionBoundsV1 {
    pub const fn production() -> Self {
        Self {
            max_request_bytes: MAX_RECEIPT_INTELLIGENCE_REQUEST_BYTES_V1,
            max_response_bytes: MAX_RECEIPT_INTELLIGENCE_RESPONSE_BYTES_V1,
            max_output_tokens: MAX_RECEIPT_INTELLIGENCE_OUTPUT_TOKENS_V1,
            timeout_millis: RECEIPT_INTELLIGENCE_TIMEOUT_MILLIS_V1,
            max_attempts: MAX_RECEIPT_INTELLIGENCE_ATTEMPTS_V1,
        }
    }
}

impl Validate for ReceiptIntelligenceExecutionBoundsV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self == &Self::production() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceProjectionFragmentV1 {
    pub fragment_ref: String,
    pub text: String,
}

impl ReceiptIntelligenceProjectionFragmentV1 {
    fn validate_at(
        &self,
        ordinal: usize,
        bounds: &ReceiptIntelligencePreparationBoundsV1,
    ) -> Result<(), ValidationError> {
        let expected_handle = format!("fragment-{ordinal:04}");
        if self.fragment_ref != expected_handle
            || self.text.is_empty()
            || self.text.trim().is_empty()
            || self.text.len() > bounds.max_fragment_bytes as usize
            || self
                .text
                .chars()
                .any(|value| value.is_control() && !matches!(value, '\n' | '\t'))
            || contains_url_or_uri(&self.text)
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceProjectionV1 {
    pub revision: String,
    pub fragments: Vec<ReceiptIntelligenceProjectionFragmentV1>,
}

impl ReceiptIntelligenceProjectionV1 {
    pub fn aggregate_text_bytes(&self) -> u32 {
        self.fragments
            .iter()
            .map(|fragment| fragment.text.len() as u32)
            .sum()
    }

    pub fn sha256(&self) -> Sha256Digest {
        let mut digest = Sha256::new();
        hash_part(&mut digest, self.revision.as_bytes());
        hash_part(&mut digest, &(self.fragments.len() as u64).to_be_bytes());
        for fragment in &self.fragments {
            hash_part(&mut digest, fragment.fragment_ref.as_bytes());
            hash_part(&mut digest, fragment.text.as_bytes());
        }
        Sha256Digest::parse(format!("{:x}", digest.finalize()))
            .expect("SHA-256 implementation must return lowercase hexadecimal")
    }

    pub fn fragment_sha256(&self) -> Vec<Sha256Digest> {
        self.fragments
            .iter()
            .map(|fragment| Sha256Digest::from_bytes(fragment.text.as_bytes()))
            .collect()
    }

    pub fn validate_with(
        &self,
        bounds: &ReceiptIntelligencePreparationBoundsV1,
    ) -> Result<(), ValidationError> {
        bounds.validate()?;
        if self.revision != RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1
            || self.fragments.is_empty()
            || self.fragments.len() > bounds.max_fragment_count as usize
            || self.aggregate_text_bytes() > bounds.max_aggregate_text_bytes
        {
            return Err(invalid());
        }
        for (ordinal, fragment) in self.fragments.iter().enumerate() {
            fragment.validate_at(ordinal, bounds)?;
        }
        Ok(())
    }
}

impl Validate for ReceiptIntelligenceProjectionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.validate_with(&ReceiptIntelligencePreparationBoundsV1::production())
    }
}

fn hash_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceRetentionDisclosureV1 {
    pub revision: String,
    pub declaration: OpenAiRetentionDeclarationV1,
    pub local_provider_payload_retained: bool,
    pub store: bool,
    pub store_false_is_not_organization_zdr: bool,
    pub default_abuse_monitoring_max_days: u8,
    pub safety_review_exceptions_apply: bool,
}

impl ReceiptIntelligenceRetentionDisclosureV1 {
    pub fn for_declaration(declaration: OpenAiRetentionDeclarationV1) -> Self {
        Self {
            revision: RECEIPT_INTELLIGENCE_RETENTION_REVISION_V1.to_owned(),
            declaration,
            local_provider_payload_retained: false,
            store: false,
            store_false_is_not_organization_zdr: true,
            default_abuse_monitoring_max_days: 30,
            safety_review_exceptions_apply: true,
        }
    }
}

impl Validate for ReceiptIntelligenceRetentionDisclosureV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.declaration.validate()?;
        if self.revision == RECEIPT_INTELLIGENCE_RETENTION_REVISION_V1
            && self.declaration.mode != OpenAiRetentionModeV1::Unknown
            && !self.local_provider_payload_retained
            && !self.store
            && self.store_false_is_not_organization_zdr
            && self.default_abuse_monitoring_max_days == 30
            && self.safety_review_exceptions_apply
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceDisclosureV1 {
    pub provider: String,
    pub model: String,
    pub purpose: String,
    pub projection: ReceiptIntelligenceProjectionV1,
    pub aggregate_text_bytes: u32,
    pub raw_mime_disclosed: bool,
    pub headers_disclosed: bool,
    pub urls_disclosed: bool,
    pub filenames_disclosed: bool,
    pub attachment_metadata_disclosed: bool,
    pub cid_metadata_disclosed: bool,
    pub internal_identifiers_disclosed: bool,
    pub hashes_disclosed: bool,
    pub credentials_disclosed: bool,
    pub image_bytes_disclosed: bool,
    pub retention: ReceiptIntelligenceRetentionDisclosureV1,
    pub preparation_bounds: ReceiptIntelligencePreparationBoundsV1,
    pub execution_bounds: ReceiptIntelligenceExecutionBoundsV1,
}

impl Validate for ReceiptIntelligenceDisclosureV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.preparation_bounds.validate()?;
        self.execution_bounds.validate()?;
        self.projection.validate_with(&self.preparation_bounds)?;
        self.retention.validate()?;
        if self.provider == RECEIPT_INTELLIGENCE_PROVIDER_V1
            && self.model == RECEIPT_INTELLIGENCE_MODEL_V1
            && self.purpose == RECEIPT_INTELLIGENCE_PURPOSE_V1
            && self.aggregate_text_bytes == self.projection.aggregate_text_bytes()
            && !self.raw_mime_disclosed
            && !self.headers_disclosed
            && !self.urls_disclosed
            && !self.filenames_disclosed
            && !self.attachment_metadata_disclosed
            && !self.cid_metadata_disclosed
            && !self.internal_identifiers_disclosed
            && !self.hashes_disclosed
            && !self.credentials_disclosed
            && !self.image_bytes_disclosed
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceConsentEnvelopeV1 {
    pub source_id: SourceId,
    pub source_revision_id: ReceiptIntelligenceSourceRevisionId,
    pub source_revision_sha256: Sha256Digest,
    pub disclosed_fragment_sha256: Vec<Sha256Digest>,
    pub projection_sha256: Sha256Digest,
    pub serialized_request_sha256: Sha256Digest,
    pub serialized_request_bytes: u32,
    pub credential_id: CredentialId,
    pub provider: String,
    pub model: String,
    pub prompt_revision: String,
    pub schema_revision: String,
    pub projection_revision: String,
    pub parameter_revision: String,
    pub retention: ReceiptIntelligenceRetentionDisclosureV1,
    pub preparation_bounds: ReceiptIntelligencePreparationBoundsV1,
    pub execution_bounds: ReceiptIntelligenceExecutionBoundsV1,
    pub expires_at: String,
}

impl ReceiptIntelligenceConsentEnvelopeV1 {
    pub fn validate_against(
        &self,
        disclosure: &ReceiptIntelligenceDisclosureV1,
    ) -> Result<(), ValidationError> {
        self.validate()?;
        disclosure.validate()?;
        if self.provider == disclosure.provider
            && self.model == disclosure.model
            && self.projection_revision == disclosure.projection.revision
            && self.projection_sha256 == disclosure.projection.sha256()
            && self.disclosed_fragment_sha256 == disclosure.projection.fragment_sha256()
            && self.retention == disclosure.retention
            && self.preparation_bounds == disclosure.preparation_bounds
            && self.execution_bounds == disclosure.execution_bounds
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

impl Validate for ReceiptIntelligenceConsentEnvelopeV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.retention.validate()?;
        self.preparation_bounds.validate()?;
        self.execution_bounds.validate()?;
        validate_timestamp(&self.expires_at)?;
        if self.disclosed_fragment_sha256.is_empty()
            || self.disclosed_fragment_sha256.len()
                > self.preparation_bounds.max_fragment_count as usize
            || self.serialized_request_bytes == 0
            || self.serialized_request_bytes > self.preparation_bounds.max_serialized_request_bytes
            || self.serialized_request_bytes > self.execution_bounds.max_request_bytes
            || self.provider != RECEIPT_INTELLIGENCE_PROVIDER_V1
            || self.model != RECEIPT_INTELLIGENCE_MODEL_V1
            || self.prompt_revision != RECEIPT_INTELLIGENCE_PROMPT_REVISION_V1
            || self.schema_revision != RECEIPT_INTELLIGENCE_SCHEMA_REVISION_V1
            || self.projection_revision != RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1
            || self.parameter_revision != RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligencePreviewV1 {
    pub disclosure: ReceiptIntelligenceDisclosureV1,
    pub consent_envelope: ReceiptIntelligenceConsentEnvelopeV1,
}

impl Validate for ReceiptIntelligencePreviewV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.consent_envelope.validate_against(&self.disclosure)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceConsentV1 {
    pub affirmative: bool,
    pub preview: ReceiptIntelligencePreviewV1,
}

impl Validate for ReceiptIntelligenceConsentV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if !self.affirmative {
            return Err(invalid());
        }
        self.preview.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PreviewReceiptIntelligenceV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub source_id: SourceId,
}

impl Validate for PreviewReceiptIntelligenceV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PreviewReceiptIntelligenceV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub preview: ReceiptIntelligencePreviewV1,
}

impl Validate for PreviewReceiptIntelligenceV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.preview.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RequestReceiptIntelligenceV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub consent: ReceiptIntelligenceConsentV1,
}

impl Validate for RequestReceiptIntelligenceV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.consent.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceReservationV1 {
    pub approval_id: ReceiptIntelligenceApprovalId,
    pub attempt_id: ReceiptIntelligenceAttemptId,
    pub source_id: SourceId,
    pub source_revision_id: ReceiptIntelligenceSourceRevisionId,
    pub state: ReceiptIntelligenceAttemptStateV1,
    pub single_use: bool,
    pub approval_created_at: String,
    pub approval_consumed_at: String,
    pub expires_at: String,
}

impl Validate for ReceiptIntelligenceReservationV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let created = parse_timestamp(&self.approval_created_at)?;
        let consumed = parse_timestamp(&self.approval_consumed_at)?;
        let expires = parse_timestamp(&self.expires_at)?;
        if self.state == ReceiptIntelligenceAttemptStateV1::NotSent
            && self.single_use
            && created == consumed
            && consumed < expires
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceProviderParametersV1 {
    pub revision: String,
    pub store: bool,
    pub background: bool,
    pub tools_enabled: bool,
    pub previous_response_id_present: bool,
    pub strict_schema: bool,
    pub reasoning_effort: ReceiptIntelligenceReasoningEffortV1,
    pub max_output_tokens: u32,
    pub timeout_millis: u32,
    pub max_attempts: u8,
}

impl Validate for ReceiptIntelligenceProviderParametersV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.revision == RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1
            && !self.store
            && !self.background
            && !self.tools_enabled
            && !self.previous_response_id_present
            && self.strict_schema
            && self.reasoning_effort == ReceiptIntelligenceReasoningEffortV1::Low
            && self.max_output_tokens == MAX_RECEIPT_INTELLIGENCE_OUTPUT_TOKENS_V1
            && self.timeout_millis == RECEIPT_INTELLIGENCE_TIMEOUT_MILLIS_V1
            && self.max_attempts == MAX_RECEIPT_INTELLIGENCE_ATTEMPTS_V1
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceUsageV1 {
    pub request_bytes: u32,
    pub response_bytes: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
    pub reasoning_tokens: u32,
    pub cached_input_tokens: u32,
    pub attempts: u8,
}

impl ReceiptIntelligenceUsageV1 {
    pub fn validate_with(
        &self,
        bounds: &ReceiptIntelligenceExecutionBoundsV1,
    ) -> Result<(), ValidationError> {
        bounds.validate()?;
        if self.request_bytes > 0
            && self.request_bytes <= bounds.max_request_bytes
            && self.response_bytes <= bounds.max_response_bytes
            && self.output_tokens <= bounds.max_output_tokens
            && self.total_tokens == self.input_tokens.saturating_add(self.output_tokens)
            && self.reasoning_tokens <= self.output_tokens
            && self.cached_input_tokens <= self.input_tokens
            && self.attempts == 1
            && self.attempts <= bounds.max_attempts
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

impl Validate for ReceiptIntelligenceUsageV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.validate_with(&ReceiptIntelligenceExecutionBoundsV1::production())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceAuditV1 {
    pub audit_id: ReceiptIntelligenceAuditId,
    pub attempt_id: ReceiptIntelligenceAttemptId,
    pub source_id: SourceId,
    pub source_revision_id: ReceiptIntelligenceSourceRevisionId,
    pub source_revision_sha256: Sha256Digest,
    pub projection_sha256: Sha256Digest,
    pub serialized_request_sha256: Sha256Digest,
    pub response_sha256: Option<Sha256Digest>,
    pub provider: String,
    pub model: String,
    pub provider_request_id: Option<String>,
    pub response_id: Option<String>,
    pub prompt_revision: String,
    pub schema_revision: String,
    pub projection_revision: String,
    pub retention_provenance: String,
    pub parameters: ReceiptIntelligenceProviderParametersV1,
    pub execution_bounds: ReceiptIntelligenceExecutionBoundsV1,
    pub usage: ReceiptIntelligenceUsageV1,
    pub dispatched_at: String,
    pub finished_at: String,
}

impl Validate for ReceiptIntelligenceAuditV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.parameters.validate()?;
        self.execution_bounds.validate()?;
        self.usage.validate_with(&self.execution_bounds)?;
        if !bounded_identifier(
            &self.retention_provenance,
            MAX_RECEIPT_INTELLIGENCE_PROVIDER_ID_CHARS_V1,
        ) || self.provider != RECEIPT_INTELLIGENCE_PROVIDER_V1
            || self.model != RECEIPT_INTELLIGENCE_MODEL_V1
            || self.prompt_revision != RECEIPT_INTELLIGENCE_PROMPT_REVISION_V1
            || self.schema_revision != RECEIPT_INTELLIGENCE_SCHEMA_REVISION_V1
            || self.projection_revision != RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1
        {
            return Err(invalid());
        }
        for value in [
            self.provider_request_id.as_deref(),
            self.response_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !bounded_identifier(value, MAX_RECEIPT_INTELLIGENCE_PROVIDER_ID_CHARS_V1) {
                return Err(invalid());
            }
        }
        if parse_timestamp(&self.dispatched_at)? <= parse_timestamp(&self.finished_at)? {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

fn bounded_identifier(value: &str, max_chars: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_chars
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceClassificationEvidenceV1 {
    pub classification_id: ReceiptIntelligenceClassificationId,
    pub attempt_id: ReceiptIntelligenceAttemptId,
    pub source_id: SourceId,
    pub source_revision_id: ReceiptIntelligenceSourceRevisionId,
    pub classification: ReceiptIntelligenceClassificationV1,
    pub order_evidence_id: Option<ReceiptOrderEvidenceId>,
    pub created_at: String,
}

impl Validate for ReceiptIntelligenceClassificationEvidenceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_timestamp(&self.created_at)?;
        let graph_shape_is_valid = match self.classification {
            ReceiptIntelligenceClassificationV1::ApparelOrder
            | ReceiptIntelligenceClassificationV1::ApparelLifecycleUpdate => {
                self.order_evidence_id.is_some()
            }
            ReceiptIntelligenceClassificationV1::Unrelated
            | ReceiptIntelligenceClassificationV1::Ambiguous => self.order_evidence_id.is_none(),
        };
        if graph_shape_is_valid {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceFailureV1 {
    pub code: ReceiptIntelligenceFailureCodeV1,
    pub retryable: bool,
    pub user_action: ReceiptIntelligenceUserActionV1,
}

impl Validate for ReceiptIntelligenceFailureV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.retryable {
            Err(invalid())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
#[ts(tag = "outcome", rename_all = "snake_case")]
pub enum ReceiptIntelligenceOutcomeV1 {
    Reserved {
        reservation: ReceiptIntelligenceReservationV1,
    },
    Dispatched {
        attempt_id: ReceiptIntelligenceAttemptId,
        dispatched_at: String,
    },
    Completed {
        classification: ReceiptIntelligenceClassificationEvidenceV1,
        audit: ReceiptIntelligenceAuditV1,
    },
    Refused {
        attempt_id: ReceiptIntelligenceAttemptId,
        audit: ReceiptIntelligenceAuditV1,
    },
    Failed {
        attempt_id: ReceiptIntelligenceAttemptId,
        failure: ReceiptIntelligenceFailureV1,
        audit: Option<ReceiptIntelligenceAuditV1>,
    },
    OutcomeUnknown {
        attempt_id: ReceiptIntelligenceAttemptId,
        audit: Option<ReceiptIntelligenceAuditV1>,
    },
}

impl ReceiptIntelligenceOutcomeV1 {
    pub const fn state(&self) -> ReceiptIntelligenceAttemptStateV1 {
        match self {
            Self::Reserved { .. } => ReceiptIntelligenceAttemptStateV1::NotSent,
            Self::Dispatched { .. } => ReceiptIntelligenceAttemptStateV1::Dispatched,
            Self::Completed { .. } => ReceiptIntelligenceAttemptStateV1::Completed,
            Self::Refused { .. } => ReceiptIntelligenceAttemptStateV1::Refused,
            Self::Failed { .. } => ReceiptIntelligenceAttemptStateV1::Failed,
            Self::OutcomeUnknown { .. } => ReceiptIntelligenceAttemptStateV1::OutcomeUnknown,
        }
    }
}

impl Validate for ReceiptIntelligenceOutcomeV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Reserved { reservation } => reservation.validate(),
            Self::Dispatched { dispatched_at, .. } => validate_timestamp(dispatched_at),
            Self::Completed {
                classification,
                audit,
            } => {
                classification.validate()?;
                audit.validate()?;
                if classification.attempt_id == audit.attempt_id
                    && classification.source_id == audit.source_id
                    && classification.source_revision_id == audit.source_revision_id
                {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            Self::Refused { attempt_id, audit } => {
                audit.validate()?;
                if attempt_id == &audit.attempt_id {
                    Ok(())
                } else {
                    Err(invalid())
                }
            }
            Self::Failed {
                attempt_id,
                failure,
                audit,
            } => {
                failure.validate()?;
                if let Some(audit) = audit {
                    audit.validate()?;
                    if attempt_id != &audit.attempt_id {
                        return Err(invalid());
                    }
                }
                Ok(())
            }
            Self::OutcomeUnknown { attempt_id, audit } => {
                if let Some(audit) = audit {
                    audit.validate()?;
                    if attempt_id != &audit.attempt_id {
                        return Err(invalid());
                    }
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RequestReceiptIntelligenceV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub outcome: ReceiptIntelligenceOutcomeV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for RequestReceiptIntelligenceV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.outcome.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListReceiptIntelligenceV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub state: Option<ReceiptIntelligenceAttemptStateV1>,
    pub classification: Option<ReceiptIntelligenceClassificationV1>,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListReceiptIntelligenceV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if (1..=MAX_PAGE_SIZE).contains(&self.limit) {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::Limit))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceSummaryV1 {
    pub attempt_id: ReceiptIntelligenceAttemptId,
    pub approval_id: ReceiptIntelligenceApprovalId,
    pub source_id: SourceId,
    pub source_revision_id: ReceiptIntelligenceSourceRevisionId,
    pub state: ReceiptIntelligenceAttemptStateV1,
    pub classification: Option<ReceiptIntelligenceClassificationEvidenceV1>,
    pub failure: Option<ReceiptIntelligenceFailureV1>,
    pub audit: Option<ReceiptIntelligenceAuditV1>,
    pub created_at: String,
    pub updated_at: String,
}

impl Validate for ReceiptIntelligenceSummaryV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let created = parse_timestamp(&self.created_at)?;
        let updated = parse_timestamp(&self.updated_at)?;
        if created > updated {
            return Err(invalid());
        }
        if let Some(classification) = &self.classification {
            classification.validate()?;
            if classification.attempt_id != self.attempt_id
                || classification.source_id != self.source_id
                || classification.source_revision_id != self.source_revision_id
            {
                return Err(invalid());
            }
        }
        if let Some(failure) = &self.failure {
            failure.validate()?;
        }
        if let Some(audit) = &self.audit {
            audit.validate()?;
            if audit.attempt_id != self.attempt_id || audit.source_id != self.source_id {
                return Err(invalid());
            }
            if audit.source_revision_id != self.source_revision_id {
                return Err(invalid());
            }
        }
        let valid_shape = match self.state {
            ReceiptIntelligenceAttemptStateV1::NotSent
            | ReceiptIntelligenceAttemptStateV1::Dispatched => {
                self.classification.is_none() && self.failure.is_none() && self.audit.is_none()
            }
            ReceiptIntelligenceAttemptStateV1::Completed => {
                self.classification.is_some() && self.failure.is_none() && self.audit.is_some()
            }
            ReceiptIntelligenceAttemptStateV1::Refused => {
                self.classification.is_none() && self.failure.is_none() && self.audit.is_some()
            }
            ReceiptIntelligenceAttemptStateV1::Failed => {
                self.classification.is_none() && self.failure.is_some()
            }
            ReceiptIntelligenceAttemptStateV1::OutcomeUnknown => {
                self.classification.is_none() && self.failure.is_none()
            }
        };
        if valid_shape {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListReceiptIntelligenceV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub availability: ReceiptIntelligenceAvailabilityV1,
    pub attempts: Vec<ReceiptIntelligenceSummaryV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub receipt_intelligence_revision: u64,
    pub next_cursor: Option<PageCursorV1>,
}

impl Validate for ListReceiptIntelligenceV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.availability.validate()?;
        if self.attempts.len() > MAX_PAGE_SIZE as usize
            || self.total_count < self.attempts.len() as u64
            || self.total_count >= MAX_SAFE_INTEGER_V1
            || self.receipt_intelligence_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(invalid());
        }
        self.attempts.iter().try_for_each(Validate::validate)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSourceAuthorityV1 {
    pub authority_id: ReceiptSourceAuthorityId,
    pub source_id: SourceId,
    pub kind: ReceiptSourceAuthorityKindV1,
    pub order_evidence_id: ReceiptOrderEvidenceId,
    pub review_decision_id: crate::ReceiptReviewDecisionId,
    pub review_head: ReceiptReviewHeadV1,
    #[ts(type = "number")]
    pub authority_revision: u64,
    pub advanced_at: String,
}

impl Validate for ReceiptSourceAuthorityV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.review_head.validate()?;
        validate_timestamp(&self.advanced_at)?;
        if self.kind == ReceiptSourceAuthorityKindV1::UserReviewed
            && self.order_evidence_id == self.review_head.decision.order_evidence_id
            && self.review_decision_id == self.review_head.decision.decision_id
            && self.authority_revision > 0
            && self.authority_revision < MAX_SAFE_INTEGER_V1
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptIntelligenceAvailabilityV1 {
    pub available: bool,
    pub reason: Option<ReceiptIntelligenceAvailabilityReasonV1>,
    pub offline_receipt_analysis_available: bool,
    pub existing_wardrobe_access_available: bool,
}

impl Validate for ReceiptIntelligenceAvailabilityV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.offline_receipt_analysis_available
            && self.existing_wardrobe_access_available
            && self.available == self.reason.is_none()
        {
            Ok(())
        } else {
            Err(invalid())
        }
    }
}
