use std::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use time::{Date, Month};
use ts_rs::TS;
use uuid::Uuid;

use crate::validation::{require_schema_v1, validate_bounded_text, validate_timestamp};
use crate::{
    deserialize_schema_version_v1, CatalogItemV1, DecisionKindV1, DecisionSnapshotV1, EvidenceId,
    FragmentCitationV1, ItemAttributesV1, ItemId, PageCursorV1, ReceiptEventKindV1,
    ReceiptOrderEvidenceId, ReceiptOrderLineId, ReceiptPortResult, ReceiptReviewActionV1,
    ReceiptReviewDecisionId, ReceiptSourceAuthorityId, ReplayStatusV1, RequestId, SafeFieldV1,
    Sha256Digest, SourceId, Validate, ValidationError, MAX_PAGE_SIZE, MAX_RECEIPT_ATTRIBUTE_CHARS,
    MAX_RECEIPT_CITATIONS, MAX_RECEIPT_QUANTITY, MAX_RECEIPT_TEXT_CHARS, MAX_SAFE_INTEGER_V1,
};

pub const RECEIPT_PURCHASE_UNIT_IDENTITY_VERSION_V1: &str = "receipt-purchase-unit-v1";
pub const RECEIPT_PURCHASE_UNIT_PROMOTION_REVISION_INCREMENT_V1: u64 = 1;
pub const MAX_RECEIPT_PURCHASE_UNIT_EXCLUSIONS_V1: usize = MAX_PAGE_SIZE as usize;

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn validate_iso_date(value: &str) -> Result<(), ValidationError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7) && !byte.is_ascii_digit())
    {
        return Err(ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit));
    }
    let year = value[0..4]
        .parse::<i32>()
        .map_err(|_| ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit))?;
    let month = value[5..7]
        .parse::<u8>()
        .ok()
        .and_then(|month| Month::try_from(month).ok())
        .ok_or_else(|| ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit))?;
    let day = value[8..10]
        .parse::<u8>()
        .map_err(|_| ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit))?;
    if year == 0 || Date::from_calendar_date(year, month, day).is_err() {
        return Err(ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit));
    }
    Ok(())
}

fn validate_currency(value: &str) -> Result<(), ValidationError> {
    if value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit))
    }
}

macro_rules! promotion_uuid_id {
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

promotion_uuid_id!(ReceiptPurchaseUnitId);
promotion_uuid_id!(ReceiptPromotionId);
promotion_uuid_id!(ReceiptAuthoritySnapshotId);

impl ReceiptPurchaseUnitId {
    pub fn derive_v1(
        order_line_id: ReceiptOrderLineId,
        unit_ordinal: u32,
    ) -> Result<Self, &'static str> {
        if u64::from(unit_ordinal) >= MAX_RECEIPT_QUANTITY {
            return Err("purchase unit ordinal is out of range");
        }
        let mut hasher = Sha256::new();
        hasher.update(RECEIPT_PURCHASE_UNIT_IDENTITY_VERSION_V1.as_bytes());
        hasher.update([0]);
        hasher.update(order_line_id.as_uuid().as_bytes());
        hasher.update(unit_ordinal.to_be_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x80;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Self::new(Uuid::from_bytes(bytes))
    }

    pub fn from_order_line_v1(
        order_line_id: ReceiptOrderLineId,
        unit_ordinal: u32,
    ) -> Result<Self, &'static str> {
        Self::derive_v1(order_line_id, unit_ordinal)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptPurchaseUnitStatusFilterV1 {
    Available,
    Promoted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptPurchaseUnitExclusionReasonV1 {
    ReviewRequired,
    Rejected,
    Deferred,
    NonPurchase,
    UnknownEventKind,
    UnknownQuantity,
    SupersededAuthority,
    UserDeleted,
    AuthorityChangedResolutionRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptPromotionConfirmationV1 {
    CreateOneWardrobeItem,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ReceiptPromotionCategoryAuthorityV1 {
    UserSelected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[ts(tag = "kind", rename_all = "snake_case")]
pub enum ReceiptPurchaseUnitFieldProvenanceV1 {
    ReceiptCitations {
        citations: Vec<FragmentCitationV1>,
    },
    UserCorrection {
        review_decision_id: ReceiptReviewDecisionId,
    },
    UnknownReceiptField,
}

impl Validate for ReceiptPurchaseUnitFieldProvenanceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if let Self::ReceiptCitations { citations } = self {
            if citations.is_empty() || citations.len() > MAX_RECEIPT_CITATIONS {
                return Err(ValidationError::new(
                    SafeFieldV1::ReceiptPurchaseUnitProvenance,
                ));
            }
            let mut unique = citations.clone();
            unique.sort();
            unique.dedup();
            if unique.len() != citations.len() {
                return Err(ValidationError::new(
                    SafeFieldV1::ReceiptPurchaseUnitProvenance,
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPurchaseUnitValuesV1 {
    #[serde(deserialize_with = "deserialize_required_option")]
    pub merchant: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub order_identifier: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub purchase_date: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub currency: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub description: Option<String>,
    pub event_kind: ReceiptEventKindV1,
    #[ts(type = "number")]
    pub quantity: u64,
    #[serde(deserialize_with = "deserialize_required_option")]
    #[ts(type = "number | null")]
    pub unit_price_minor: Option<u64>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub brand: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub sku: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub size: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub color: Option<String>,
}

impl Validate for ReceiptPurchaseUnitValuesV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.event_kind != ReceiptEventKindV1::Purchase
            || self.quantity == 0
            || self.quantity > MAX_RECEIPT_QUANTITY
            || self
                .unit_price_minor
                .is_some_and(|value| value >= MAX_SAFE_INTEGER_V1)
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit));
        }
        for value in [self.merchant.as_deref(), self.order_identifier.as_deref()]
            .into_iter()
            .flatten()
        {
            validate_bounded_text(
                value,
                1,
                MAX_RECEIPT_ATTRIBUTE_CHARS,
                SafeFieldV1::ReceiptPurchaseUnit,
            )?;
        }
        if let Some(purchase_date) = &self.purchase_date {
            validate_iso_date(purchase_date)?;
        }
        if let Some(currency) = &self.currency {
            validate_currency(currency)?;
        }
        if let Some(description) = &self.description {
            validate_bounded_text(
                description,
                1,
                MAX_RECEIPT_TEXT_CHARS,
                SafeFieldV1::ReceiptPurchaseUnit,
            )?;
        }
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
                SafeFieldV1::ReceiptPurchaseUnit,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPurchaseUnitProvenanceV1 {
    pub merchant: ReceiptPurchaseUnitFieldProvenanceV1,
    pub order_identifier: ReceiptPurchaseUnitFieldProvenanceV1,
    pub purchase_date: ReceiptPurchaseUnitFieldProvenanceV1,
    pub currency: ReceiptPurchaseUnitFieldProvenanceV1,
    pub description: ReceiptPurchaseUnitFieldProvenanceV1,
    pub event_kind: ReceiptPurchaseUnitFieldProvenanceV1,
    pub quantity: ReceiptPurchaseUnitFieldProvenanceV1,
    pub unit_price_minor: ReceiptPurchaseUnitFieldProvenanceV1,
    pub brand: ReceiptPurchaseUnitFieldProvenanceV1,
    pub sku: ReceiptPurchaseUnitFieldProvenanceV1,
    pub size: ReceiptPurchaseUnitFieldProvenanceV1,
    pub color: ReceiptPurchaseUnitFieldProvenanceV1,
}

impl ReceiptPurchaseUnitProvenanceV1 {
    fn validate_field(
        value_is_known: bool,
        provenance: &ReceiptPurchaseUnitFieldProvenanceV1,
    ) -> Result<(), ValidationError> {
        provenance.validate()?;
        if value_is_known
            && matches!(
                provenance,
                ReceiptPurchaseUnitFieldProvenanceV1::UnknownReceiptField
            )
        {
            return Err(ValidationError::new(
                SafeFieldV1::ReceiptPurchaseUnitProvenance,
            ));
        }
        if !value_is_known
            && matches!(
                provenance,
                ReceiptPurchaseUnitFieldProvenanceV1::ReceiptCitations { .. }
            )
        {
            return Err(ValidationError::new(
                SafeFieldV1::ReceiptPurchaseUnitProvenance,
            ));
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        values: &ReceiptPurchaseUnitValuesV1,
        review_decision_id: ReceiptReviewDecisionId,
        review_action: ReceiptReviewActionV1,
    ) -> Result<(), ValidationError> {
        for (known, provenance) in [
            (values.merchant.is_some(), &self.merchant),
            (values.order_identifier.is_some(), &self.order_identifier),
            (values.purchase_date.is_some(), &self.purchase_date),
            (values.currency.is_some(), &self.currency),
            (values.description.is_some(), &self.description),
            (true, &self.event_kind),
            (true, &self.quantity),
            (values.unit_price_minor.is_some(), &self.unit_price_minor),
            (values.brand.is_some(), &self.brand),
            (values.sku.is_some(), &self.sku),
            (values.size.is_some(), &self.size),
            (values.color.is_some(), &self.color),
        ] {
            Self::validate_field(known, provenance)?;
            if let ReceiptPurchaseUnitFieldProvenanceV1::UserCorrection {
                review_decision_id: field_decision_id,
            } = provenance
            {
                if *field_decision_id != review_decision_id
                    || review_action == ReceiptReviewActionV1::Confirm
                {
                    return Err(ValidationError::new(
                        SafeFieldV1::ReceiptPurchaseUnitProvenance,
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPurchaseUnitAuthorityV1 {
    pub authority_id: ReceiptSourceAuthorityId,
    pub source_id: SourceId,
    pub order_evidence_id: ReceiptOrderEvidenceId,
    pub review_decision_id: ReceiptReviewDecisionId,
    pub review_action: ReceiptReviewActionV1,
    #[ts(type = "number")]
    pub authority_revision: u64,
    #[ts(type = "number")]
    pub receipt_revision: u64,
}

impl Validate for ReceiptPurchaseUnitAuthorityV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if !matches!(
            self.review_action,
            ReceiptReviewActionV1::Confirm | ReceiptReviewActionV1::Correct
        ) || self.authority_revision == 0
            || self.authority_revision >= MAX_SAFE_INTEGER_V1
            || self.receipt_revision == 0
            || self.receipt_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(
                SafeFieldV1::ReceiptPurchaseUnitAuthority,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(tag = "status", rename_all = "snake_case")]
#[ts(tag = "status", rename_all = "snake_case")]
pub enum ReceiptPurchaseUnitStatusV1 {
    Available,
    Promoted {
        promotion_id: ReceiptPromotionId,
        item_id: ItemId,
        evidence_id: EvidenceId,
        decision_id: crate::DecisionId,
    },
}

impl ReceiptPurchaseUnitStatusV1 {
    pub fn filter(&self) -> ReceiptPurchaseUnitStatusFilterV1 {
        match self {
            Self::Available => ReceiptPurchaseUnitStatusFilterV1::Available,
            Self::Promoted { .. } => ReceiptPurchaseUnitStatusFilterV1::Promoted,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPurchaseUnitV1 {
    pub purchase_unit_id: ReceiptPurchaseUnitId,
    pub order_line_id: ReceiptOrderLineId,
    pub unit_ordinal: u32,
    #[ts(type = "number")]
    pub authoritative_quantity: u64,
    pub values: ReceiptPurchaseUnitValuesV1,
    pub provenance: ReceiptPurchaseUnitProvenanceV1,
    pub authority: ReceiptPurchaseUnitAuthorityV1,
    // CAS revision for this physical unit. A new promotion advances it exactly once.
    #[ts(type = "number")]
    pub purchase_unit_revision: u64,
    pub unit_snapshot_sha256: Sha256Digest,
    #[ts(type = "number")]
    pub catalog_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub status: ReceiptPurchaseUnitStatusV1,
}

impl Validate for ReceiptPurchaseUnitV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.values.validate()?;
        self.authority.validate()?;
        self.provenance.validate_against(
            &self.values,
            self.authority.review_decision_id,
            self.authority.review_action,
        )?;
        let expected_id = ReceiptPurchaseUnitId::derive_v1(self.order_line_id, self.unit_ordinal)
            .map_err(|_| ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit))?;
        if self.purchase_unit_id != expected_id
            || self.authoritative_quantity != self.values.quantity
            || u64::from(self.unit_ordinal) >= self.authoritative_quantity
            || self.purchase_unit_revision == 0
            || self.purchase_unit_revision >= MAX_SAFE_INTEGER_V1
            || self.catalog_revision >= MAX_SAFE_INTEGER_V1
            || self.evidence_generation >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPurchaseUnitExclusionV1 {
    pub source_id: SourceId,
    pub order_evidence_id: Option<ReceiptOrderEvidenceId>,
    pub order_line_id: Option<ReceiptOrderLineId>,
    pub unit_ordinal: Option<u32>,
    pub reason: ReceiptPurchaseUnitExclusionReasonV1,
}

impl Validate for ReceiptPurchaseUnitExclusionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.unit_ordinal.is_some() && self.order_line_id.is_none() {
            return Err(ValidationError::new(
                SafeFieldV1::ReceiptPurchaseUnitExclusion,
            ));
        }
        if self
            .unit_ordinal
            .is_some_and(|ordinal| u64::from(ordinal) >= MAX_RECEIPT_QUANTITY)
        {
            return Err(ValidationError::new(
                SafeFieldV1::ReceiptPurchaseUnitExclusion,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPurchaseUnitSnapshotV1 {
    #[ts(type = "number")]
    pub receipt_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    #[ts(type = "number")]
    pub catalog_revision: u64,
}

impl Validate for ReceiptPurchaseUnitSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.receipt_revision < MAX_SAFE_INTEGER_V1
            && self.evidence_generation < MAX_SAFE_INTEGER_V1
            && self.catalog_revision < MAX_SAFE_INTEGER_V1
        {
            Ok(())
        } else {
            Err(ValidationError::new(
                SafeFieldV1::ReceiptPurchaseUnitSnapshot,
            ))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListReceiptPurchaseUnitsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub source_id: Option<SourceId>,
    pub status: Option<ReceiptPurchaseUnitStatusFilterV1>,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListReceiptPurchaseUnitsV1Request {
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
pub struct ListReceiptPurchaseUnitsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub units: Vec<ReceiptPurchaseUnitV1>,
    pub exclusions: Vec<ReceiptPurchaseUnitExclusionV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub total_exclusion_count: u64,
    pub snapshot: ReceiptPurchaseUnitSnapshotV1,
    pub next_cursor: Option<PageCursorV1>,
}

impl Validate for ListReceiptPurchaseUnitsV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.snapshot.validate()?;
        if self.units.len() > MAX_PAGE_SIZE as usize
            || self.exclusions.len() > MAX_RECEIPT_PURCHASE_UNIT_EXCLUSIONS_V1
            || self.total_count < self.units.len() as u64
            || self.total_exclusion_count < self.exclusions.len() as u64
            || self.total_count >= MAX_SAFE_INTEGER_V1
            || self.total_exclusion_count >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptPurchaseUnit));
        }
        self.units.iter().try_for_each(Validate::validate)?;
        self.exclusions.iter().try_for_each(Validate::validate)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAuthoritySnapshotV1 {
    pub authority_snapshot_id: ReceiptAuthoritySnapshotId,
    pub authority: ReceiptPurchaseUnitAuthorityV1,
    pub order_line_id: ReceiptOrderLineId,
    pub values: ReceiptPurchaseUnitValuesV1,
    pub provenance: ReceiptPurchaseUnitProvenanceV1,
    pub snapshot_sha256: Sha256Digest,
    pub created_at: String,
}

impl Validate for ReceiptAuthoritySnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.authority.validate()?;
        self.values.validate()?;
        self.provenance.validate_against(
            &self.values,
            self.authority.review_decision_id,
            self.authority.review_action,
        )?;
        validate_timestamp(&self.created_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPromotionV1 {
    pub promotion_id: ReceiptPromotionId,
    pub purchase_unit_id: ReceiptPurchaseUnitId,
    pub order_line_id: ReceiptOrderLineId,
    pub unit_ordinal: u32,
    pub item_id: ItemId,
    pub evidence_id: EvidenceId,
    pub decision_id: crate::DecisionId,
    pub authority_snapshot_id: ReceiptAuthoritySnapshotId,
    pub request_id: RequestId,
    pub promoted_at: String,
}

impl Validate for ReceiptPromotionV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.purchase_unit_id
            != ReceiptPurchaseUnitId::derive_v1(self.order_line_id, self.unit_ordinal)
                .map_err(|_| ValidationError::new(SafeFieldV1::ReceiptPromotion))?
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptPromotion));
        }
        validate_timestamp(&self.promoted_at)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PromoteReceiptPurchaseUnitV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub purchase_unit_id: ReceiptPurchaseUnitId,
    // Displayed unit revision. A successful new promotion returns this value plus one.
    #[ts(type = "number")]
    pub expected_purchase_unit_revision: u64,
    pub expected_unit_snapshot_sha256: Sha256Digest,
    pub expected_authority_id: ReceiptSourceAuthorityId,
    #[ts(type = "number")]
    pub expected_authority_revision: u64,
    #[ts(type = "number")]
    pub expected_receipt_revision: u64,
    pub expected_review_decision_id: ReceiptReviewDecisionId,
    #[ts(type = "number")]
    pub expected_catalog_revision: u64,
    pub confirmation: ReceiptPromotionConfirmationV1,
    pub category_authority: ReceiptPromotionCategoryAuthorityV1,
    pub attributes: ItemAttributesV1,
}

impl Validate for PromoteReceiptPurchaseUnitV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.attributes.validate()?;
        if self.confirmation != ReceiptPromotionConfirmationV1::CreateOneWardrobeItem {
            return Err(ValidationError::new(
                SafeFieldV1::ReceiptPromotionConfirmation,
            ));
        }
        if self.category_authority != ReceiptPromotionCategoryAuthorityV1::UserSelected {
            return Err(ValidationError::new(
                SafeFieldV1::ReceiptPromotionConfirmation,
            ));
        }
        if self.expected_purchase_unit_revision == 0
            || self.expected_purchase_unit_revision >= MAX_SAFE_INTEGER_V1
            || self.expected_authority_revision == 0
            || self.expected_authority_revision >= MAX_SAFE_INTEGER_V1
            || self.expected_receipt_revision == 0
            || self.expected_receipt_revision >= MAX_SAFE_INTEGER_V1
            || self.expected_catalog_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(
                SafeFieldV1::ReceiptPurchaseUnitSnapshot,
            ));
        }
        Ok(())
    }
}

impl PromoteReceiptPurchaseUnitV1Request {
    pub fn resulting_purchase_unit_revision(&self) -> Option<u64> {
        self.expected_purchase_unit_revision
            .checked_add(RECEIPT_PURCHASE_UNIT_PROMOTION_REVISION_INCREMENT_V1)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PromoteReceiptPurchaseUnitV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub unit: ReceiptPurchaseUnitV1,
    pub item: CatalogItemV1,
    pub authority_snapshot: ReceiptAuthoritySnapshotV1,
    pub promotion: ReceiptPromotionV1,
    pub decision: DecisionSnapshotV1,
    #[ts(type = "number")]
    pub new_catalog_revision: u64,
    #[ts(type = "number")]
    pub new_evidence_generation: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for PromoteReceiptPurchaseUnitV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.unit.validate()?;
        self.item.validate()?;
        self.authority_snapshot.validate()?;
        self.promotion.validate()?;
        self.decision.validate()?;
        let status_links_match = matches!(
            self.unit.status,
            ReceiptPurchaseUnitStatusV1::Promoted {
                promotion_id,
                item_id,
                evidence_id,
                decision_id,
            } if promotion_id == self.promotion.promotion_id
                && item_id == self.item.item_id
                && evidence_id == self.promotion.evidence_id
                && decision_id == self.decision.decision_id
        );
        if !status_links_match
            || self.promotion.purchase_unit_id != self.unit.purchase_unit_id
            || self.promotion.order_line_id != self.unit.order_line_id
            || self.promotion.unit_ordinal != self.unit.unit_ordinal
            || self.promotion.item_id != self.item.item_id
            || self.promotion.decision_id != self.decision.decision_id
            || self.promotion.authority_snapshot_id != self.authority_snapshot.authority_snapshot_id
            || self.promotion.request_id != self.request_id
            || self.authority_snapshot.authority != self.unit.authority
            || self.authority_snapshot.order_line_id != self.unit.order_line_id
            || self.authority_snapshot.values != self.unit.values
            || self.authority_snapshot.provenance != self.unit.provenance
            || self.decision.kind != DecisionKindV1::PromoteReceiptPurchaseUnit
            || self.decision.reversible
            || self.decision.compensates_decision_id.is_some()
            || self.decision.affected_item_ids != [self.item.item_id]
            || self.decision.affected_evidence_ids != [self.promotion.evidence_id]
            || self.item.last_decision_id != self.decision.decision_id
            || self.item.evidence_ids != [self.promotion.evidence_id]
            || self.new_catalog_revision == 0
            || self.new_catalog_revision >= MAX_SAFE_INTEGER_V1
            || self.new_evidence_generation == 0
            || self.new_evidence_generation >= MAX_SAFE_INTEGER_V1
            || self.unit.catalog_revision != self.new_catalog_revision
            || self.unit.evidence_generation != self.new_evidence_generation
        {
            return Err(ValidationError::new(SafeFieldV1::ReceiptPromotion));
        }
        Ok(())
    }
}

pub trait ReceiptPromotionPort {
    fn list_receipt_purchase_units(
        &self,
        request: &ListReceiptPurchaseUnitsV1Request,
    ) -> ReceiptPortResult<ListReceiptPurchaseUnitsV1Response>;

    // Implementations replay terminal commands before current-state checks. New commands perform
    // all authority, eligibility, unit snapshot, and catalog CAS checks and writes atomically,
    // advancing the purchase-unit revision exactly once for the available-to-promoted transition.
    // Exact replay returns that stored post-promotion revision without another increment.
    fn promote_receipt_purchase_unit(
        &self,
        request: &PromoteReceiptPurchaseUnitV1Request,
    ) -> ReceiptPortResult<PromoteReceiptPurchaseUnitV1Response>;
}
