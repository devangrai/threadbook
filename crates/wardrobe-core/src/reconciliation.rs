use std::fmt;

use serde::de::{Error as _, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use crate::{
    deserialize_schema_version_v1, ItemId, PageCursorV1, PhotoArtifactId, PhotoObservationId,
    PhotoOwnerDecisionId, PhotoPersonInstanceId, PhotoReviewDecisionId, ReplayStatusV1, RequestId,
    SafeFieldV1, Sha256Digest, Validate, ValidationError, MAX_SAFE_INTEGER_V1, SCHEMA_VERSION_V1,
};

pub const RECONCILIATION_RETRIEVAL_REVISION_V1: &str = "local-reconciliation-v1";
pub const LOCAL_VISUAL_FEATURE_EXTRACTOR_ID_V1: &str = "local-visual-features";
pub const LOCAL_VISUAL_FEATURE_EXTRACTOR_REVISION_V1: &str = "local-visual-features-v1";
pub const LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_ID_V1: &str = "local-reconciliation";
pub const LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_REVISION_V1: &str = "local-reconciliation-v1";

pub const MAX_RECONCILIATION_CANDIDATES: usize = 7;
pub const MAX_RECONCILIATION_RANKED_CANDIDATES: u8 = 6;
pub const MAX_CANDIDATE_EVIDENCE: usize = 8;
pub const MAX_RECONCILIATION_DISPLAY_NAME_CHARS: usize = 120;
pub const MAX_RECONCILIATION_DETAIL_CHARS: usize = 240;
pub const MAX_RECONCILIATION_REVISION_CHARS: usize = 128;
pub const MAX_RECONCILIATION_VALUE_CODE_CHARS: usize = 64;
pub const MAX_RECONCILIATION_PAGE_SIZE_V2: u16 = 100;
pub const MAX_RECONCILIATION_AUTHORITY_REASON_CHARS_V2: usize = 80;

pub const EVIDENCE_VALUE_MEASURED_V1: &str = "measured";
pub const EVIDENCE_VALUE_CATALOG_IMAGE_ABSENT_V1: &str = "catalog_image_absent";
pub const EVIDENCE_VALUE_CATALOG_IMAGE_UNAVAILABLE_V1: &str = "catalog_image_unavailable";
pub const EVIDENCE_VALUE_CATALOG_IMAGE_CORRUPT_V1: &str = "catalog_image_corrupt";
pub const EVIDENCE_VALUE_RECEIPT_CONFIRMED_V1: &str = "receipt_confirmed";
pub const EVIDENCE_VALUE_RECEIPT_CORRECTED_V1: &str = "receipt_corrected";
pub const EVIDENCE_VALUE_EVENT_PURCHASE_V1: &str = "event_purchase";
pub const EVIDENCE_VALUE_EVENT_EXCHANGE_V1: &str = "event_exchange";
pub const EVIDENCE_VALUE_EVENT_RETURN_V1: &str = "event_return";
pub const EVIDENCE_VALUE_EVENT_UNKNOWN_V1: &str = "event_unknown";
pub const EVIDENCE_VALUE_PURCHASE_BEFORE_OBSERVATION_V1: &str = "purchase_before_observation";
pub const EVIDENCE_VALUE_PURCHASE_AFTER_OBSERVATION_V1: &str = "purchase_after_observation";
pub const EVIDENCE_VALUE_PURCHASE_DATE_UNKNOWN_V1: &str = "purchase_date_unknown";
pub const EVIDENCE_VALUE_EXTRACTED_RECEIPT_V1: &str = "extracted_receipt";
pub const EVIDENCE_VALUE_CORRECTED_UNCHANGED_V1: &str = "corrected_unchanged";
pub const EVIDENCE_VALUE_CORRECTED_CHANGED_V1: &str = "corrected_changed";
pub const EVIDENCE_VALUE_CORRECTED_UNKNOWN_V1: &str = "corrected_unknown";

macro_rules! reconciliation_uuid_id {
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

reconciliation_uuid_id!(ReconciliationCaseId);
reconciliation_uuid_id!(ReconciliationCandidateId);
reconciliation_uuid_id!(ReconciliationEvidenceId);
reconciliation_uuid_id!(ReconciliationDecisionId);
reconciliation_uuid_id!(ReconciliationEvidenceSourceId);

fn invalid(field: SafeFieldV1) -> ValidationError {
    ValidationError::new(field)
}

fn validate_schema(version: u8) -> Result<(), ValidationError> {
    if version == SCHEMA_VERSION_V1 {
        Ok(())
    } else {
        Err(invalid(SafeFieldV1::SchemaVersion))
    }
}

fn deserialize_schema_version_v2<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let value = u8::deserialize(deserializer)?;
    if value == 2 {
        Ok(value)
    } else {
        Err(D::Error::custom("unsupported schema version"))
    }
}

fn validate_schema_v2(version: u8) -> Result<(), ValidationError> {
    if version == 2 {
        Ok(())
    } else {
        Err(invalid(SafeFieldV1::SchemaVersion))
    }
}

fn validate_safe_revision(value: u64, field: SafeFieldV1) -> Result<(), ValidationError> {
    if value < MAX_SAFE_INTEGER_V1 {
        Ok(())
    } else {
        Err(invalid(field))
    }
}

fn validate_nonzero_revision(value: u64, field: SafeFieldV1) -> Result<(), ValidationError> {
    validate_safe_revision(value, field)?;
    if value == 0 {
        Err(invalid(field))
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, max_chars: usize, field: SafeFieldV1) -> Result<(), ValidationError> {
    let chars = value.chars().count();
    if chars == 0
        || chars > max_chars
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(invalid(field))
    } else {
        Ok(())
    }
}

fn validate_revision_text(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > MAX_RECONCILIATION_REVISION_CHARS
        || !value.is_ascii()
        || value.trim() != value
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        Err(invalid(SafeFieldV1::Attributes))
    } else {
        Ok(())
    }
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
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
        return Err(invalid(SafeFieldV1::Timestamp));
    }
    let year = value[0..4].parse::<u32>().ok();
    let month = value[5..7].parse::<u32>().ok();
    let day = value[8..10].parse::<u32>().ok();
    let max_day = match (year, month) {
        (Some(year), Some(2)) if is_leap_year(year) => 29,
        (Some(_), Some(2)) => 28,
        (Some(_), Some(4 | 6 | 9 | 11)) => 30,
        (Some(_), Some(1 | 3 | 5 | 7 | 8 | 10 | 12)) => 31,
        _ => 0,
    };
    if year.is_some_and(|year| year > 0) && day.is_some_and(|day| (1..=max_day).contains(&day)) {
        Ok(())
    } else {
        Err(invalid(SafeFieldV1::Timestamp))
    }
}

fn validate_iso_timestamp(value: &str) -> Result<(), ValidationError> {
    if value.len() < 20 || value.len() > 40 || !value.is_ascii() {
        return Err(invalid(SafeFieldV1::Timestamp));
    }
    let bytes = value.as_bytes();
    if bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[11..13].iter().any(|byte| !byte.is_ascii_digit())
        || bytes[14..16].iter().any(|byte| !byte.is_ascii_digit())
        || bytes[17..19].iter().any(|byte| !byte.is_ascii_digit())
    {
        return Err(invalid(SafeFieldV1::Timestamp));
    }
    validate_iso_date(&value[..10])?;
    let hour = value[11..13].parse::<u8>().ok();
    let minute = value[14..16].parse::<u8>().ok();
    let second = value[17..19].parse::<u8>().ok();
    if hour.is_none_or(|value| value > 23)
        || minute.is_none_or(|value| value > 59)
        || second.is_none_or(|value| value > 59)
    {
        return Err(invalid(SafeFieldV1::Timestamp));
    }

    let mut suffix = &value[19..];
    if let Some(fraction) = suffix.strip_prefix('.') {
        let fraction_length = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if fraction_length == 0 {
            return Err(invalid(SafeFieldV1::Timestamp));
        }
        suffix = &fraction[fraction_length..];
    }
    let timezone_valid = suffix == "Z"
        || (suffix.len() == 6
            && matches!(suffix.as_bytes()[0], b'+' | b'-')
            && suffix.as_bytes()[3] == b':'
            && suffix.as_bytes()[1..3].iter().all(u8::is_ascii_digit)
            && suffix.as_bytes()[4..6].iter().all(u8::is_ascii_digit)
            && suffix[1..3]
                .parse::<u8>()
                .ok()
                .is_some_and(|value| value <= 23)
            && suffix[4..6]
                .parse::<u8>()
                .ok()
                .is_some_and(|value| value <= 59));
    if timezone_valid {
        Ok(())
    } else {
        Err(invalid(SafeFieldV1::Timestamp))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum IdentityRelationV1 {
    VisualSimilarity,
    SameProductVariant,
    SamePhysicalItem,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum CandidateEvidencePolarityV1 {
    Supporting,
    Contradictory,
    Neutral,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum CandidateEvidenceFeatureV1 {
    DifferenceHashDistance,
    MeanColorDistance,
    CatalogImageStatus,
    ReceiptReviewState,
    ReceiptEventKind,
    PurchaseChronology,
    ExtractedReceiptProvenance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum CandidateEvidenceSourceKindV1 {
    PhotoArtifact,
    CatalogImageEvidence,
    CatalogDecision,
    ReceiptField,
    ReceiptReviewDecision,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[ts(tag = "kind", rename_all = "snake_case")]
pub enum ReconciliationCandidateTargetV1 {
    NoMatch {},
    WardrobeItem {
        item_id: ItemId,
    },
    ReceiptLine {
        order_line_id: crate::ReceiptOrderLineId,
        variant_evidence_id: crate::ReceiptVariantEvidenceId,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReconciliationCandidateDateKindV1 {
    CatalogCreated,
    Purchase,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationCandidateDateV1 {
    pub kind: ReconciliationCandidateDateKindV1,
    pub value: String,
}

impl Validate for ReconciliationCandidateDateV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        match self.kind {
            ReconciliationCandidateDateKindV1::CatalogCreated => {
                validate_iso_timestamp(&self.value)
            }
            ReconciliationCandidateDateKindV1::Purchase => validate_iso_date(&self.value),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidenceV1 {
    pub evidence_id: ReconciliationEvidenceId,
    pub polarity: CandidateEvidencePolarityV1,
    pub relation: IdentityRelationV1,
    pub feature: CandidateEvidenceFeatureV1,
    pub source_kind: CandidateEvidenceSourceKindV1,
    pub source_id: ReconciliationEvidenceSourceId,
    pub source_revision: String,
    pub input_sha256: Vec<Sha256Digest>,
    pub extractor_id: String,
    pub extractor_revision: String,
    pub value_code: String,
    pub measured_value: Option<u16>,
}

impl CandidateEvidenceV1 {
    fn valid_visual_extractor(&self) -> bool {
        self.extractor_id == LOCAL_VISUAL_FEATURE_EXTRACTOR_ID_V1
            && self.extractor_revision == LOCAL_VISUAL_FEATURE_EXTRACTOR_REVISION_V1
    }

    fn valid_receipt_extractor(&self) -> bool {
        self.extractor_id == LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_ID_V1
            && self.extractor_revision == LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_REVISION_V1
    }
}

impl Validate for CandidateEvidenceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_revision_text(&self.source_revision)?;
        validate_revision_text(&self.extractor_id)?;
        validate_revision_text(&self.extractor_revision)?;
        validate_text(
            &self.value_code,
            MAX_RECONCILIATION_VALUE_CODE_CHARS,
            SafeFieldV1::Attributes,
        )?;
        if !(1..=2).contains(&self.input_sha256.len()) {
            return Err(invalid(SafeFieldV1::Collection));
        }

        let valid = match self.feature {
            CandidateEvidenceFeatureV1::DifferenceHashDistance => {
                let measured = self.measured_value.filter(|value| *value <= 64);
                self.relation == IdentityRelationV1::VisualSimilarity
                    && matches!(
                        self.source_kind,
                        CandidateEvidenceSourceKindV1::PhotoArtifact
                            | CandidateEvidenceSourceKindV1::CatalogImageEvidence
                    )
                    && self.input_sha256.len() == 2
                    && self.valid_visual_extractor()
                    && self.value_code == EVIDENCE_VALUE_MEASURED_V1
                    && measured.is_some()
                    && self.polarity
                        == match measured.unwrap() {
                            0..=8 => CandidateEvidencePolarityV1::Supporting,
                            9..=23 => CandidateEvidencePolarityV1::Neutral,
                            _ => CandidateEvidencePolarityV1::Contradictory,
                        }
            }
            CandidateEvidenceFeatureV1::MeanColorDistance => {
                let measured = self.measured_value.filter(|value| *value <= 765);
                self.relation == IdentityRelationV1::VisualSimilarity
                    && matches!(
                        self.source_kind,
                        CandidateEvidenceSourceKindV1::PhotoArtifact
                            | CandidateEvidenceSourceKindV1::CatalogImageEvidence
                    )
                    && self.input_sha256.len() == 2
                    && self.valid_visual_extractor()
                    && self.value_code == EVIDENCE_VALUE_MEASURED_V1
                    && measured.is_some()
                    && self.polarity
                        == match measured.unwrap() {
                            0..=48 => CandidateEvidencePolarityV1::Supporting,
                            49..=191 => CandidateEvidencePolarityV1::Neutral,
                            _ => CandidateEvidencePolarityV1::Contradictory,
                        }
            }
            CandidateEvidenceFeatureV1::CatalogImageStatus => {
                self.relation == IdentityRelationV1::VisualSimilarity
                    && matches!(
                        self.source_kind,
                        CandidateEvidenceSourceKindV1::CatalogImageEvidence
                            | CandidateEvidenceSourceKindV1::CatalogDecision
                    )
                    && self.valid_visual_extractor()
                    && self.measured_value.is_none()
                    && self.polarity == CandidateEvidencePolarityV1::Neutral
                    && matches!(
                        self.value_code.as_str(),
                        EVIDENCE_VALUE_CATALOG_IMAGE_ABSENT_V1
                            | EVIDENCE_VALUE_CATALOG_IMAGE_UNAVAILABLE_V1
                            | EVIDENCE_VALUE_CATALOG_IMAGE_CORRUPT_V1
                    )
            }
            CandidateEvidenceFeatureV1::ReceiptReviewState => {
                self.relation == IdentityRelationV1::SameProductVariant
                    && self.source_kind == CandidateEvidenceSourceKindV1::ReceiptReviewDecision
                    && self.valid_receipt_extractor()
                    && self.measured_value.is_none()
                    && self.polarity == CandidateEvidencePolarityV1::Neutral
                    && matches!(
                        self.value_code.as_str(),
                        EVIDENCE_VALUE_RECEIPT_CONFIRMED_V1 | EVIDENCE_VALUE_RECEIPT_CORRECTED_V1
                    )
            }
            CandidateEvidenceFeatureV1::ReceiptEventKind => {
                self.relation == IdentityRelationV1::SameProductVariant
                    && self.source_kind == CandidateEvidenceSourceKindV1::ReceiptField
                    && self.valid_receipt_extractor()
                    && self.measured_value.is_none()
                    && matches!(
                        (self.value_code.as_str(), self.polarity),
                        (
                            EVIDENCE_VALUE_EVENT_RETURN_V1,
                            CandidateEvidencePolarityV1::Contradictory
                        ) | (
                            EVIDENCE_VALUE_EVENT_PURCHASE_V1
                                | EVIDENCE_VALUE_EVENT_EXCHANGE_V1
                                | EVIDENCE_VALUE_EVENT_UNKNOWN_V1,
                            CandidateEvidencePolarityV1::Neutral
                        )
                    )
            }
            CandidateEvidenceFeatureV1::PurchaseChronology => {
                self.relation == IdentityRelationV1::SameProductVariant
                    && self.source_kind == CandidateEvidenceSourceKindV1::ReceiptField
                    && self.valid_receipt_extractor()
                    && self.measured_value.is_none()
                    && matches!(
                        (self.value_code.as_str(), self.polarity),
                        (
                            EVIDENCE_VALUE_PURCHASE_AFTER_OBSERVATION_V1,
                            CandidateEvidencePolarityV1::Contradictory
                        ) | (
                            EVIDENCE_VALUE_PURCHASE_BEFORE_OBSERVATION_V1
                                | EVIDENCE_VALUE_PURCHASE_DATE_UNKNOWN_V1,
                            CandidateEvidencePolarityV1::Neutral
                        )
                    )
            }
            CandidateEvidenceFeatureV1::ExtractedReceiptProvenance => {
                self.relation == IdentityRelationV1::SameProductVariant
                    && self.source_kind == CandidateEvidenceSourceKindV1::ReceiptField
                    && self.valid_receipt_extractor()
                    && self.measured_value.is_none()
                    && self.polarity == CandidateEvidencePolarityV1::Neutral
                    && matches!(
                        self.value_code.as_str(),
                        EVIDENCE_VALUE_EXTRACTED_RECEIPT_V1
                            | EVIDENCE_VALUE_CORRECTED_UNCHANGED_V1
                            | EVIDENCE_VALUE_CORRECTED_CHANGED_V1
                            | EVIDENCE_VALUE_CORRECTED_UNKNOWN_V1
                    )
            }
        };
        if valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationCandidateV1 {
    pub candidate_id: ReconciliationCandidateId,
    pub target: ReconciliationCandidateTargetV1,
    pub proposed_relation: Option<IdentityRelationV1>,
    pub observed_relations: Vec<IdentityRelationV1>,
    pub rank: Option<u8>,
    pub display_name: String,
    pub detail: String,
    pub date: Option<ReconciliationCandidateDateV1>,
    pub evidence: Vec<CandidateEvidenceV1>,
}

impl ReconciliationCandidateV1 {
    pub fn is_no_match(&self) -> bool {
        matches!(self.target, ReconciliationCandidateTargetV1::NoMatch {})
    }
}

impl Validate for ReconciliationCandidateV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text(
            &self.display_name,
            MAX_RECONCILIATION_DISPLAY_NAME_CHARS,
            SafeFieldV1::Attributes,
        )?;
        validate_text(
            &self.detail,
            MAX_RECONCILIATION_DETAIL_CHARS,
            SafeFieldV1::Attributes,
        )?;
        if let Some(date) = &self.date {
            date.validate()?;
        }
        if self.evidence.len() > MAX_CANDIDATE_EVIDENCE {
            return Err(invalid(SafeFieldV1::Collection));
        }
        let mut evidence_ids = self
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_id)
            .collect::<Vec<_>>();
        evidence_ids.sort_unstable();
        evidence_ids.dedup();
        if evidence_ids.len() != self.evidence.len()
            || self
                .evidence
                .iter()
                .any(|evidence| evidence.validate().is_err())
        {
            return Err(invalid(SafeFieldV1::Collection));
        }
        let observed_valid = self.observed_relations.len() <= 1
            && self
                .observed_relations
                .iter()
                .all(|relation| *relation == IdentityRelationV1::VisualSimilarity);
        let has_visual_measurement = self.evidence.iter().any(|evidence| {
            matches!(
                evidence.feature,
                CandidateEvidenceFeatureV1::DifferenceHashDistance
                    | CandidateEvidenceFeatureV1::MeanColorDistance
            )
        });
        let observed_visual_similarity =
            self.observed_relations == [IdentityRelationV1::VisualSimilarity];
        let shape_valid =
            match self.target {
                ReconciliationCandidateTargetV1::NoMatch {} => {
                    self.proposed_relation.is_none()
                        && self.observed_relations.is_empty()
                        && self.rank.is_none()
                        && self.date.is_none()
                        && self.evidence.is_empty()
                }
                ReconciliationCandidateTargetV1::WardrobeItem { .. } => {
                    self.proposed_relation == Some(IdentityRelationV1::SamePhysicalItem)
                        && self.rank.is_some_and(|rank| {
                            (1..=MAX_RECONCILIATION_RANKED_CANDIDATES).contains(&rank)
                        })
                        && self.date.as_ref().is_none_or(|date| {
                            date.kind == ReconciliationCandidateDateKindV1::CatalogCreated
                        })
                        && self.evidence.iter().all(|evidence| {
                            matches!(
                                evidence.relation,
                                IdentityRelationV1::VisualSimilarity
                                    | IdentityRelationV1::SamePhysicalItem
                            )
                        })
                }
                ReconciliationCandidateTargetV1::ReceiptLine { .. } => {
                    self.proposed_relation == Some(IdentityRelationV1::SameProductVariant)
                        && self.rank.is_some_and(|rank| {
                            (1..=MAX_RECONCILIATION_RANKED_CANDIDATES).contains(&rank)
                        })
                        && self.observed_relations.is_empty()
                        && self.date.as_ref().is_none_or(|date| {
                            date.kind == ReconciliationCandidateDateKindV1::Purchase
                        })
                        && self.evidence.iter().all(|evidence| {
                            evidence.relation == IdentityRelationV1::SameProductVariant
                        })
                }
            };
        if observed_valid && observed_visual_similarity == has_visual_measurement && shape_valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReconciliationOutcomeV1 {
    SameItem,
    SameVariant,
    Different,
    NoMatch,
    Unresolved,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationDecisionV1 {
    pub decision_id: ReconciliationDecisionId,
    pub case_id: ReconciliationCaseId,
    pub outcome: ReconciliationOutcomeV1,
    pub selected_candidate_id: Option<ReconciliationCandidateId>,
    #[ts(type = "number")]
    pub case_revision: u64,
}

impl ReconciliationDecisionV1 {
    pub fn validate_for_case(&self, case: &ReconciliationCaseV1) -> Result<(), ValidationError> {
        self.validate()?;
        if self.case_id != case.case_id || self.case_revision != case.case_revision {
            return Err(invalid(SafeFieldV1::DecisionId));
        }
        let selected = self.selected_candidate_id.and_then(|candidate_id| {
            case.candidates
                .iter()
                .find(|candidate| candidate.candidate_id == candidate_id)
        });
        let valid = match self.outcome {
            ReconciliationOutcomeV1::SameItem => selected.is_some_and(|candidate| {
                matches!(
                    candidate.target,
                    ReconciliationCandidateTargetV1::WardrobeItem { .. }
                ) && candidate.proposed_relation == Some(IdentityRelationV1::SamePhysicalItem)
            }),
            ReconciliationOutcomeV1::SameVariant => selected.is_some_and(|candidate| {
                matches!(
                    candidate.target,
                    ReconciliationCandidateTargetV1::ReceiptLine { .. }
                ) && candidate.proposed_relation == Some(IdentityRelationV1::SameProductVariant)
            }),
            ReconciliationOutcomeV1::Different => selected.is_some_and(|candidate| {
                !candidate.is_no_match() && candidate.proposed_relation.is_some()
            }),
            ReconciliationOutcomeV1::NoMatch => {
                selected.is_some_and(ReconciliationCandidateV1::is_no_match)
            }
            ReconciliationOutcomeV1::Unresolved => selected.is_none(),
        };
        if valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::DecisionId))
        }
    }
}

impl Validate for ReconciliationDecisionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_nonzero_revision(self.case_revision, SafeFieldV1::ExpectedCatalogRevision)?;
        let selection_valid = match self.outcome {
            ReconciliationOutcomeV1::Unresolved => self.selected_candidate_id.is_none(),
            _ => self.selected_candidate_id.is_some(),
        };
        if selection_valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::DecisionId))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationCaseV1 {
    pub case_id: ReconciliationCaseId,
    pub observation_id: PhotoObservationId,
    pub artifact_id: PhotoArtifactId,
    pub artifact_sha256: Sha256Digest,
    pub observation_date: String,
    pub retrieval_revision: String,
    pub candidates: Vec<ReconciliationCandidateV1>,
    pub leading_candidate_id: ReconciliationCandidateId,
    pub decision_head: Option<ReconciliationDecisionV1>,
    #[ts(type = "number")]
    pub case_revision: u64,
}

impl ReconciliationCaseV1 {
    pub fn candidate(
        &self,
        candidate_id: ReconciliationCandidateId,
    ) -> Option<&ReconciliationCandidateV1> {
        self.candidates
            .iter()
            .find(|candidate| candidate.candidate_id == candidate_id)
    }
}

impl Validate for ReconciliationCaseV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_iso_timestamp(&self.observation_date)?;
        validate_nonzero_revision(self.case_revision, SafeFieldV1::ExpectedCatalogRevision)?;
        if self.retrieval_revision != RECONCILIATION_RETRIEVAL_REVISION_V1
            || !(1..=MAX_RECONCILIATION_CANDIDATES).contains(&self.candidates.len())
            || self
                .candidates
                .iter()
                .any(|candidate| candidate.validate().is_err())
        {
            return Err(invalid(SafeFieldV1::Collection));
        }

        let mut candidate_ids = self
            .candidates
            .iter()
            .map(|candidate| candidate.candidate_id)
            .collect::<Vec<_>>();
        candidate_ids.sort_unstable();
        candidate_ids.dedup();
        let mut targets = self
            .candidates
            .iter()
            .map(|candidate| candidate.target.clone())
            .collect::<Vec<_>>();
        targets.sort_unstable();
        targets.dedup();
        if candidate_ids.len() != self.candidates.len() || targets.len() != self.candidates.len() {
            return Err(invalid(SafeFieldV1::Collection));
        }

        let no_match_count = self
            .candidates
            .iter()
            .filter(|candidate| candidate.is_no_match())
            .count();
        let ranked = self
            .candidates
            .iter()
            .filter(|candidate| !candidate.is_no_match())
            .collect::<Vec<_>>();
        let ranks = ranked
            .iter()
            .map(|candidate| candidate.rank.unwrap())
            .collect::<Vec<_>>();
        let expected_ranks = (1..=ranked.len() as u8).collect::<Vec<_>>();
        let no_match_is_last = self
            .candidates
            .last()
            .is_some_and(ReconciliationCandidateV1::is_no_match);
        let expected_leading = ranked
            .first()
            .copied()
            .or_else(|| self.candidates.last())
            .map(|candidate| candidate.candidate_id);
        if no_match_count != 1
            || !no_match_is_last
            || ranks != expected_ranks
            || expected_leading != Some(self.leading_candidate_id)
        {
            return Err(invalid(SafeFieldV1::Collection));
        }
        if let Some(decision) = &self.decision_head {
            decision.validate_for_case(self)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OpenReconciliationCaseV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub observation_id: PhotoObservationId,
    pub selected_artifact_id: PhotoArtifactId,
    #[ts(type = "number")]
    pub expected_photo_revision: u64,
}

impl Validate for OpenReconciliationCaseV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_revision(
            self.expected_photo_revision,
            SafeFieldV1::ExpectedReceiptRevision,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DecideReconciliationCaseV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub case_id: ReconciliationCaseId,
    pub outcome: ReconciliationOutcomeV1,
    pub selected_candidate_id: Option<ReconciliationCandidateId>,
    #[ts(type = "number")]
    pub expected_case_revision: u64,
}

impl Validate for DecideReconciliationCaseV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_nonzero_revision(
            self.expected_case_revision,
            SafeFieldV1::ExpectedCatalogRevision,
        )?;
        let selection_valid = match self.outcome {
            ReconciliationOutcomeV1::Unresolved => self.selected_candidate_id.is_none(),
            _ => self.selected_candidate_id.is_some(),
        };
        if selection_valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::DecisionId))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OpenReconciliationCaseV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub case: ReconciliationCaseV1,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    #[ts(type = "number")]
    pub reconciliation_revision: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for OpenReconciliationCaseV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_safe_revision(self.evidence_generation, SafeFieldV1::Collection)?;
        validate_nonzero_revision(
            self.reconciliation_revision,
            SafeFieldV1::ExpectedCatalogRevision,
        )?;
        self.case.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DecideReconciliationCaseV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub case: ReconciliationCaseV1,
    pub decision: ReconciliationDecisionV1,
    #[ts(type = "number")]
    pub reconciliation_revision: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for DecideReconciliationCaseV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_nonzero_revision(
            self.reconciliation_revision,
            SafeFieldV1::ExpectedCatalogRevision,
        )?;
        self.case.validate()?;
        self.decision.validate_for_case(&self.case)?;
        if self.case.decision_head.as_ref() == Some(&self.decision) {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::DecisionId))
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReconciliationAuthorityStateV2 {
    OpenEligible,
    OpenStale,
    OpenIneligible,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReconciliationAuthorityReasonV2 {
    CurrentAuthority,
    LegacyOwnerUnverified,
    OwnerDecisionStale,
    CropDecisionStale,
    OwnerEvidenceMismatch,
    PersonEvidenceMismatch,
    CropEvidenceMismatch,
    SourceEvidenceMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReconciliationCaseStateFilterV2 {
    All,
    OpenEligible,
    OpenStale,
    OpenIneligible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationCaseV2 {
    pub case_id: ReconciliationCaseId,
    pub observation_id: PhotoObservationId,
    pub artifact_id: PhotoArtifactId,
    pub artifact_sha256: Sha256Digest,
    pub observation_date: String,
    pub retrieval_revision: String,
    pub candidates: Vec<ReconciliationCandidateV1>,
    pub leading_candidate_id: ReconciliationCandidateId,
    pub decision_head: Option<ReconciliationDecisionV1>,
    #[ts(type = "number")]
    pub case_revision: u64,
    pub owner_decision_id: Option<PhotoOwnerDecisionId>,
    pub person_instance_id: Option<PhotoPersonInstanceId>,
    pub owner_evidence_sha256: Option<Sha256Digest>,
    #[ts(type = "number")]
    pub owner_revision: Option<u64>,
    pub crop_decision_id: PhotoReviewDecisionId,
    #[ts(type = "number")]
    pub crop_revision: u64,
    pub source_revision_sha256: Sha256Digest,
    pub authority_state: ReconciliationAuthorityStateV2,
    pub authority_reason: ReconciliationAuthorityReasonV2,
    #[ts(type = "number")]
    pub created_at_ms: u64,
}

impl ReconciliationCaseV2 {
    pub fn as_v1(&self) -> ReconciliationCaseV1 {
        ReconciliationCaseV1 {
            case_id: self.case_id,
            observation_id: self.observation_id,
            artifact_id: self.artifact_id,
            artifact_sha256: self.artifact_sha256.clone(),
            observation_date: self.observation_date.clone(),
            retrieval_revision: self.retrieval_revision.clone(),
            candidates: self.candidates.clone(),
            leading_candidate_id: self.leading_candidate_id,
            decision_head: self.decision_head.clone(),
            case_revision: self.case_revision,
        }
    }

    pub fn matches_filter(&self, filter: ReconciliationCaseStateFilterV2) -> bool {
        match filter {
            ReconciliationCaseStateFilterV2::All => true,
            ReconciliationCaseStateFilterV2::OpenEligible => {
                self.authority_state == ReconciliationAuthorityStateV2::OpenEligible
            }
            ReconciliationCaseStateFilterV2::OpenStale => {
                self.authority_state == ReconciliationAuthorityStateV2::OpenStale
            }
            ReconciliationCaseStateFilterV2::OpenIneligible => {
                self.authority_state == ReconciliationAuthorityStateV2::OpenIneligible
            }
        }
    }
}

impl Validate for ReconciliationCaseV2 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.as_v1().validate()?;
        validate_safe_revision(self.created_at_ms, SafeFieldV1::Timestamp)?;
        let owner_pin_count = [
            self.owner_decision_id.is_some(),
            self.person_instance_id.is_some(),
            self.owner_evidence_sha256.is_some(),
            self.owner_revision.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if !matches!(owner_pin_count, 0 | 4) {
            return Err(invalid(SafeFieldV1::Attributes));
        }
        if let Some(revision) = self.owner_revision {
            validate_nonzero_revision(revision, SafeFieldV1::ExpectedCatalogRevision)?;
        }
        validate_nonzero_revision(self.crop_revision, SafeFieldV1::ExpectedReceiptRevision)?;
        let authority_valid = match (self.authority_state, self.authority_reason) {
            (
                ReconciliationAuthorityStateV2::OpenEligible,
                ReconciliationAuthorityReasonV2::CurrentAuthority,
            ) => owner_pin_count == 4,
            (
                ReconciliationAuthorityStateV2::OpenIneligible,
                ReconciliationAuthorityReasonV2::LegacyOwnerUnverified,
            ) => owner_pin_count == 0,
            (ReconciliationAuthorityStateV2::OpenStale, reason) => matches!(
                reason,
                ReconciliationAuthorityReasonV2::OwnerDecisionStale
                    | ReconciliationAuthorityReasonV2::CropDecisionStale
                    | ReconciliationAuthorityReasonV2::OwnerEvidenceMismatch
                    | ReconciliationAuthorityReasonV2::PersonEvidenceMismatch
                    | ReconciliationAuthorityReasonV2::CropEvidenceMismatch
                    | ReconciliationAuthorityReasonV2::SourceEvidenceMismatch
            ),
            (ReconciliationAuthorityStateV2::OpenIneligible, reason) => matches!(
                reason,
                ReconciliationAuthorityReasonV2::OwnerEvidenceMismatch
                    | ReconciliationAuthorityReasonV2::PersonEvidenceMismatch
                    | ReconciliationAuthorityReasonV2::CropEvidenceMismatch
                    | ReconciliationAuthorityReasonV2::SourceEvidenceMismatch
            ),
            _ => false,
        };
        if authority_valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OpenReconciliationCaseV2Request {
    #[serde(deserialize_with = "deserialize_schema_version_v2")]
    #[ts(type = "2")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub observation_id: PhotoObservationId,
    pub selected_artifact_id: PhotoArtifactId,
    #[ts(type = "number")]
    pub expected_photo_revision: u64,
    #[ts(type = "number")]
    pub expected_owner_revision: u64,
}

impl Validate for OpenReconciliationCaseV2Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema_v2(self.schema_version)?;
        validate_safe_revision(
            self.expected_photo_revision,
            SafeFieldV1::ExpectedReceiptRevision,
        )?;
        validate_nonzero_revision(
            self.expected_owner_revision,
            SafeFieldV1::ExpectedCatalogRevision,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DecideReconciliationCaseV2Request {
    #[serde(deserialize_with = "deserialize_schema_version_v2")]
    #[ts(type = "2")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub case_id: ReconciliationCaseId,
    pub outcome: ReconciliationOutcomeV1,
    pub selected_candidate_id: Option<ReconciliationCandidateId>,
    #[ts(type = "number")]
    pub expected_case_revision: u64,
    #[ts(type = "number")]
    pub expected_owner_revision: u64,
    #[ts(type = "number")]
    pub expected_photo_revision: u64,
    #[ts(type = "number")]
    pub expected_reconciliation_revision: u64,
}

impl Validate for DecideReconciliationCaseV2Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema_v2(self.schema_version)?;
        for revision in [
            self.expected_case_revision,
            self.expected_owner_revision,
            self.expected_reconciliation_revision,
        ] {
            validate_nonzero_revision(revision, SafeFieldV1::ExpectedCatalogRevision)?;
        }
        validate_safe_revision(
            self.expected_photo_revision,
            SafeFieldV1::ExpectedReceiptRevision,
        )?;
        let selection_valid = match self.outcome {
            ReconciliationOutcomeV1::Unresolved => self.selected_candidate_id.is_none(),
            _ => self.selected_candidate_id.is_some(),
        };
        if selection_valid {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::DecisionId))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListReconciliationCasesV2Request {
    #[serde(deserialize_with = "deserialize_schema_version_v2")]
    #[ts(type = "2")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub observation_id: PhotoObservationId,
    pub state: ReconciliationCaseStateFilterV2,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListReconciliationCasesV2Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema_v2(self.schema_version)?;
        if (1..=MAX_RECONCILIATION_PAGE_SIZE_V2).contains(&self.limit) {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Limit))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OpenReconciliationCaseV2Response {
    #[serde(deserialize_with = "deserialize_schema_version_v2")]
    #[ts(type = "2")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub case: ReconciliationCaseV2,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    #[ts(type = "number")]
    pub photo_revision: u64,
    #[ts(type = "number")]
    pub owner_revision: u64,
    #[ts(type = "number")]
    pub reconciliation_revision: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for OpenReconciliationCaseV2Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema_v2(self.schema_version)?;
        validate_safe_revision(self.evidence_generation, SafeFieldV1::Collection)?;
        validate_safe_revision(self.photo_revision, SafeFieldV1::ExpectedReceiptRevision)?;
        validate_nonzero_revision(self.owner_revision, SafeFieldV1::ExpectedCatalogRevision)?;
        validate_nonzero_revision(
            self.reconciliation_revision,
            SafeFieldV1::ExpectedCatalogRevision,
        )?;
        self.case.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DecideReconciliationCaseV2Response {
    #[serde(deserialize_with = "deserialize_schema_version_v2")]
    #[ts(type = "2")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub case: ReconciliationCaseV2,
    pub decision: ReconciliationDecisionV1,
    #[ts(type = "number")]
    pub photo_revision: u64,
    #[ts(type = "number")]
    pub owner_revision: u64,
    #[ts(type = "number")]
    pub reconciliation_revision: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for DecideReconciliationCaseV2Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema_v2(self.schema_version)?;
        validate_safe_revision(self.photo_revision, SafeFieldV1::ExpectedReceiptRevision)?;
        validate_nonzero_revision(self.owner_revision, SafeFieldV1::ExpectedCatalogRevision)?;
        validate_nonzero_revision(
            self.reconciliation_revision,
            SafeFieldV1::ExpectedCatalogRevision,
        )?;
        self.case.validate()?;
        self.decision.validate_for_case(&self.case.as_v1())?;
        if self.case.decision_head.as_ref() == Some(&self.decision) {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::DecisionId))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListReconciliationCasesV2Response {
    #[serde(deserialize_with = "deserialize_schema_version_v2")]
    #[ts(type = "2")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub observation_id: PhotoObservationId,
    pub state: ReconciliationCaseStateFilterV2,
    pub cases: Vec<ReconciliationCaseV2>,
    pub next_cursor: Option<PageCursorV1>,
    #[ts(type = "number")]
    pub photo_revision: u64,
    #[ts(type = "number")]
    pub owner_revision: u64,
    #[ts(type = "number")]
    pub reconciliation_revision: u64,
}

impl Validate for ListReconciliationCasesV2Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema_v2(self.schema_version)?;
        validate_safe_revision(self.photo_revision, SafeFieldV1::ExpectedReceiptRevision)?;
        validate_nonzero_revision(self.owner_revision, SafeFieldV1::ExpectedCatalogRevision)?;
        validate_nonzero_revision(
            self.reconciliation_revision,
            SafeFieldV1::ExpectedCatalogRevision,
        )?;
        if self.cases.len() > MAX_RECONCILIATION_PAGE_SIZE_V2 as usize
            || self.cases.iter().any(|case| {
                case.validate().is_err()
                    || case.observation_id != self.observation_id
                    || !case.matches_filter(self.state)
            })
        {
            return Err(invalid(SafeFieldV1::Collection));
        }
        let ordered = self.cases.windows(2).all(|pair| {
            (pair[0].created_at_ms, pair[0].case_id) > (pair[1].created_at_ms, pair[1].case_id)
        });
        let mut ids = self
            .cases
            .iter()
            .map(|case| case.case_id)
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        if ordered && ids.len() == self.cases.len() {
            Ok(())
        } else {
            Err(invalid(SafeFieldV1::Collection))
        }
    }
}
