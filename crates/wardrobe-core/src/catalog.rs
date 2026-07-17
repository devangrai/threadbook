use std::fmt;

use serde::de::{Error as _, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use crate::validation::{require_schema_v1, validate_bounded_text};
use crate::{
    deserialize_schema_version_v1, ReplayStatusV1, RequestId, SafeFieldV1, Validate,
    ValidationError,
};

pub const MAX_IMPORT_PATHS: usize = 32;
pub const MAX_PATH_CHARS: usize = 4096;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_ITEM_NAME_CHARS: usize = 80;
pub const MAX_ITEM_ATTRIBUTE_CHARS: usize = 80;
pub const MAX_ITEM_NOTES_CHARS: usize = 1_000;
pub const MAX_ITEM_TAGS: usize = 32;
pub const MAX_EVIDENCE_PER_MUTATION: usize = 32;
pub const MAX_ITEMS_PER_MUTATION: usize = 32;
pub const MAX_DECISION_AFFECTED_ITEMS: usize = MAX_ITEMS_PER_MUTATION + 1;
pub const MAX_CURSOR_CHARS: usize = 512;
pub const MAX_SNAPSHOT_TOKEN_CHARS: usize = 256;
pub const MAX_PROVENANCE_LABEL_CHARS: usize = 240;
pub const MAX_DIAGNOSTIC_CODE_CHARS: usize = 80;
pub const MAX_SAFE_INTEGER_V1: u64 = 9_007_199_254_740_991;

macro_rules! catalog_uuid_id {
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

catalog_uuid_id!(ImportRootId);
catalog_uuid_id!(SourceId);
catalog_uuid_id!(EvidenceId);
catalog_uuid_id!(QuarantineId);
catalog_uuid_id!(ItemId);
catalog_uuid_id!(DecisionId);

macro_rules! opaque_string {
    ($name:ident, $max:expr, $field:expr) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: String) -> Result<Self, ValidationError> {
                validate_opaque(&value, $max, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(|_| D::Error::custom("invalid opaque value"))
            }
        }
    };
}

opaque_string!(PageCursorV1, MAX_CURSOR_CHARS, SafeFieldV1::Cursor);
opaque_string!(
    DeletionSnapshotTokenV1,
    MAX_SNAPSHOT_TOKEN_CHARS,
    SafeFieldV1::SnapshotToken
);

fn validate_opaque(
    value: &str,
    max_chars: usize,
    field: SafeFieldV1,
) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.chars().count() > max_chars
        || !value.is_ascii()
        || value.chars().any(char::is_control)
    {
        return Err(ValidationError::new(field));
    }
    Ok(())
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn validate_path(path: &str) -> Result<(), ValidationError> {
    if path.is_empty()
        || path.chars().count() > MAX_PATH_CHARS
        || path.chars().any(char::is_control)
        || !path.starts_with('/')
    {
        return Err(ValidationError::new(SafeFieldV1::Path));
    }
    Ok(())
}

fn validate_expected_revision(revision: u64) -> Result<(), ValidationError> {
    if revision < MAX_SAFE_INTEGER_V1 {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::ExpectedCatalogRevision))
    }
}

fn validate_page(limit: u16) -> Result<(), ValidationError> {
    if (1..=MAX_PAGE_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::Limit))
    }
}

fn validate_unique<T: Copy + Ord>(
    values: &[T],
    min: usize,
    max: usize,
    field: SafeFieldV1,
) -> Result<(), ValidationError> {
    if values.len() < min || values.len() > max {
        return Err(ValidationError::new(field));
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != values.len() {
        return Err(ValidationError::new(field));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ImportSourceKindV1 {
    PhotoFolder,
    ImageFile,
    EmlFile,
    MboxFile,
    MboxMessage,
    MimePart,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum SourceAvailabilityV1 {
    Present,
    Missing,
    Unavailable,
    Incomplete,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum EvidenceKindV1 {
    Image,
    MessageAttachment,
    ReceiptPurchaseUnit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum EvidenceStateV1 {
    Unresolved,
    Deferred,
    Assigned,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum InboxStateV1 {
    Unresolved,
    Deferred,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum EvidenceDecisionActionV1 {
    Assign,
    Reject,
    Defer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ItemCategoryV1 {
    Top,
    Bottom,
    Dress,
    Outerwear,
    Shoes,
    Accessory,
    Underwear,
    Activewear,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DecisionKindV1 {
    SaveItem,
    DecideEvidence,
    MergeItems,
    SplitItem,
    PromoteReceiptPurchaseUnit,
    Undo,
}

impl DecisionKindV1 {
    pub const fn allows_generic_undo(self) -> bool {
        !matches!(self, Self::PromoteReceiptPurchaseUnit)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DeletionTargetKindV1 {
    ImportRoot,
    Source,
    Item,
    PurchaseUnit,
    ReceiptPurchaseUnitEvidence,
    #[serde(rename = "photokit_enrollment")]
    #[ts(rename = "photokit_enrollment")]
    PhotoKitEnrollment,
    #[serde(rename = "photokit_asset")]
    #[ts(rename = "photokit_asset")]
    PhotoKitAsset,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum DeletionDependencyClassV1 {
    Originals,
    Derivatives,
    SourceRecords,
    EvidenceRecords,
    DecisionRecords,
    RemoteReferences,
    RetainedSharedBlobs,
    RetainedSharedRecords,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ItemAttributesV1 {
    pub display_name: String,
    pub category: ItemCategoryV1,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub subcategory: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub brand: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub primary_color: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub size: Option<String>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub notes: Option<String>,
    pub tags: Vec<String>,
}

impl Validate for ItemAttributesV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(
            &self.display_name,
            1,
            MAX_ITEM_NAME_CHARS,
            SafeFieldV1::Attributes,
        )?;
        for value in [
            self.subcategory.as_deref(),
            self.brand.as_deref(),
            self.primary_color.as_deref(),
            self.size.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_bounded_text(value, 1, MAX_ITEM_ATTRIBUTE_CHARS, SafeFieldV1::Attributes)?;
        }
        if let Some(notes) = &self.notes {
            validate_bounded_text(notes, 1, MAX_ITEM_NOTES_CHARS, SafeFieldV1::Attributes)?;
        }
        if self.tags.len() > MAX_ITEM_TAGS {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        let mut tags = self.tags.clone();
        for tag in &tags {
            validate_bounded_text(tag, 1, MAX_ITEM_ATTRIBUTE_CHARS, SafeFieldV1::Collection)?;
        }
        tags.sort();
        tags.dedup();
        if tags.len() != self.tags.len() {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotV1 {
    pub source_id: SourceId,
    pub import_root_id: Option<ImportRootId>,
    pub parent_source_id: Option<SourceId>,
    pub kind: ImportSourceKindV1,
    pub availability: SourceAvailabilityV1,
    pub provenance_label: String,
    pub raw_blob_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSnapshotV1 {
    pub evidence_id: EvidenceId,
    pub source: SourceSnapshotV1,
    pub kind: EvidenceKindV1,
    pub state: EvidenceStateV1,
    pub assigned_item_id: Option<ItemId>,
    pub review_label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct QuarantineSnapshotV1 {
    pub quarantine_id: QuarantineId,
    pub source: SourceSnapshotV1,
    pub code: String,
    pub raw_blob_preserved: bool,
    pub no_blob_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CatalogItemV1 {
    pub item_id: ItemId,
    pub attributes: ItemAttributesV1,
    pub evidence_ids: Vec<EvidenceId>,
    pub last_decision_id: DecisionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DecisionSnapshotV1 {
    pub decision_id: DecisionId,
    pub kind: DecisionKindV1,
    pub affected_item_ids: Vec<ItemId>,
    pub affected_evidence_ids: Vec<EvidenceId>,
    pub compensates_decision_id: Option<DecisionId>,
    pub reversible: bool,
}

impl DecisionSnapshotV1 {
    pub fn allows_generic_undo(&self) -> bool {
        self.reversible && self.kind.allows_generic_undo()
    }
}

impl Validate for DecisionSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_unique(
            &self.affected_item_ids,
            0,
            MAX_DECISION_AFFECTED_ITEMS,
            SafeFieldV1::ItemId,
        )?;
        validate_unique(
            &self.affected_evidence_ids,
            0,
            MAX_EVIDENCE_PER_MUTATION,
            SafeFieldV1::EvidenceId,
        )?;
        if (self.kind == DecisionKindV1::Undo) != self.compensates_decision_id.is_some() {
            return Err(ValidationError::new(SafeFieldV1::DecisionId));
        }
        if self.kind == DecisionKindV1::PromoteReceiptPurchaseUnit && self.reversible {
            return Err(ValidationError::new(SafeFieldV1::DecisionId));
        }
        Ok(())
    }
}

impl Validate for SourceSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(
            &self.provenance_label,
            1,
            MAX_PROVENANCE_LABEL_CHARS,
            SafeFieldV1::Path,
        )?;
        if let Some(digest) = &self.raw_blob_sha256 {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ValidationError::new(SafeFieldV1::Attributes));
            }
        }
        Ok(())
    }
}

impl Validate for EvidenceSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.source.validate()?;
        validate_bounded_text(
            &self.review_label,
            1,
            MAX_PROVENANCE_LABEL_CHARS,
            SafeFieldV1::Attributes,
        )?;
        let assignment_is_valid = match self.state {
            EvidenceStateV1::Assigned => self.assigned_item_id.is_some(),
            EvidenceStateV1::Unresolved | EvidenceStateV1::Deferred | EvidenceStateV1::Rejected => {
                self.assigned_item_id.is_none()
            }
        };
        if assignment_is_valid {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::ItemId))
        }
    }
}

impl Validate for QuarantineSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.source.validate()?;
        validate_bounded_text(
            &self.code,
            1,
            MAX_DIAGNOSTIC_CODE_CHARS,
            SafeFieldV1::Attributes,
        )?;
        if let Some(reason) = &self.no_blob_reason {
            validate_bounded_text(
                reason,
                1,
                MAX_DIAGNOSTIC_CODE_CHARS,
                SafeFieldV1::Attributes,
            )?;
        }
        if self.raw_blob_preserved == self.no_blob_reason.is_some() {
            return Err(ValidationError::new(SafeFieldV1::Attributes));
        }
        Ok(())
    }
}

impl Validate for CatalogItemV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.attributes.validate()?;
        validate_unique(
            &self.evidence_ids,
            0,
            MAX_EVIDENCE_PER_MUTATION,
            SafeFieldV1::EvidenceId,
        )
    }
}

impl Validate for DeletionPlanItemV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_bounded_text(
            &self.record_id,
            1,
            MAX_PROVENANCE_LABEL_CHARS,
            SafeFieldV1::DeletionTarget,
        )?;
        validate_bounded_text(
            &self.display_label,
            1,
            MAX_PROVENANCE_LABEL_CHARS,
            SafeFieldV1::DeletionTarget,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ImportSummaryV1 {
    pub import_root_id: Option<ImportRootId>,
    pub source_id: Option<SourceId>,
    pub imported: u32,
    pub reused: u32,
    pub quarantined: u32,
    pub skipped: u32,
    pub unavailable: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DeletionClassCountV1 {
    pub class: DeletionDependencyClassV1,
    pub count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DeletionPlanItemV1 {
    pub class: DeletionDependencyClassV1,
    pub record_id: String,
    pub display_label: String,
    pub retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SplitGroupV1 {
    pub attributes: ItemAttributesV1,
    pub evidence_ids: Vec<EvidenceId>,
}

impl Validate for SplitGroupV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.attributes.validate()?;
        validate_unique(
            &self.evidence_ids,
            1,
            MAX_EVIDENCE_PER_MUTATION,
            SafeFieldV1::EvidenceId,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ImportLocalSourcesV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub paths: Vec<String>,
}

impl Validate for ImportLocalSourcesV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.paths.is_empty() || self.paths.len() > MAX_IMPORT_PATHS {
            return Err(ValidationError::new(SafeFieldV1::Path));
        }
        for path in &self.paths {
            validate_path(path)?;
        }
        let mut paths = self.paths.clone();
        paths.sort();
        paths.dedup();
        if paths.len() != self.paths.len() {
            return Err(ValidationError::new(SafeFieldV1::Path));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RefreshImportRootsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub import_root_ids: Vec<ImportRootId>,
}

impl Validate for RefreshImportRootsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_unique(
            &self.import_root_ids,
            1,
            MAX_IMPORT_PATHS,
            SafeFieldV1::Collection,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListCatalogV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListCatalogV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_page(self.limit)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListInboxV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub state: InboxStateV1,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListInboxV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_page(self.limit)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SaveItemV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub item_id: Option<ItemId>,
    pub attributes: ItemAttributesV1,
    pub evidence_ids: Vec<EvidenceId>,
    #[ts(type = "number")]
    pub expected_catalog_revision: u64,
}

impl Validate for SaveItemV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.attributes.validate()?;
        validate_unique(
            &self.evidence_ids,
            0,
            MAX_EVIDENCE_PER_MUTATION,
            SafeFieldV1::EvidenceId,
        )?;
        validate_expected_revision(self.expected_catalog_revision)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DecideEvidenceV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub evidence_id: EvidenceId,
    pub action: EvidenceDecisionActionV1,
    pub item_id: Option<ItemId>,
    #[ts(type = "number")]
    pub expected_catalog_revision: u64,
}

impl Validate for DecideEvidenceV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        let assignment_is_valid = match self.action {
            EvidenceDecisionActionV1::Assign => self.item_id.is_some(),
            EvidenceDecisionActionV1::Reject | EvidenceDecisionActionV1::Defer => {
                self.item_id.is_none()
            }
        };
        if assignment_is_valid {
            validate_expected_revision(self.expected_catalog_revision)
        } else {
            Err(ValidationError::new(SafeFieldV1::ItemId))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct MergeItemsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub item_ids: Vec<ItemId>,
    pub target_attributes: ItemAttributesV1,
    #[ts(type = "number")]
    pub expected_catalog_revision: u64,
}

impl Validate for MergeItemsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.target_attributes.validate()?;
        validate_unique(
            &self.item_ids,
            2,
            MAX_ITEMS_PER_MUTATION,
            SafeFieldV1::ItemId,
        )?;
        validate_expected_revision(self.expected_catalog_revision)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SplitItemV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub item_id: ItemId,
    pub groups: Vec<SplitGroupV1>,
    #[ts(type = "number")]
    pub expected_catalog_revision: u64,
}

impl Validate for SplitItemV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if self.groups.len() < 2 || self.groups.len() > MAX_ITEMS_PER_MUTATION {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        let mut all_evidence = Vec::new();
        for group in &self.groups {
            group.validate()?;
            all_evidence.extend_from_slice(&group.evidence_ids);
        }
        validate_unique(
            &all_evidence,
            2,
            MAX_EVIDENCE_PER_MUTATION,
            SafeFieldV1::EvidenceId,
        )?;
        validate_expected_revision(self.expected_catalog_revision)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct UndoDecisionV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub decision_id: DecisionId,
    #[ts(type = "number")]
    pub expected_catalog_revision: u64,
}

impl Validate for UndoDecisionV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_expected_revision(self.expected_catalog_revision)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PreviewDeletionV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub target_kind: DeletionTargetKindV1,
    pub target_id: String,
    pub limit: u16,
}

impl Validate for PreviewDeletionV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_page(self.limit)?;
        let parsed = Uuid::parse_str(&self.target_id)
            .map_err(|_| ValidationError::new(SafeFieldV1::DeletionTarget))?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != self.target_id {
            return Err(ValidationError::new(SafeFieldV1::DeletionTarget));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListDeletionPlanItemsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub preview_snapshot_token: DeletionSnapshotTokenV1,
    pub class: DeletionDependencyClassV1,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListDeletionPlanItemsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_page(self.limit)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ImportLocalSourcesV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub summaries: Vec<ImportSummaryV1>,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RefreshImportRootsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub summaries: Vec<ImportSummaryV1>,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListCatalogV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub items: Vec<CatalogItemV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub catalog_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub next_cursor: Option<PageCursorV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListInboxV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub evidence: Vec<EvidenceSnapshotV1>,
    pub quarantines: Vec<QuarantineSnapshotV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub catalog_revision: u64,
    #[ts(type = "number")]
    pub evidence_generation: u64,
    pub next_cursor: Option<PageCursorV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SaveItemV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub item: CatalogItemV1,
    pub decision: DecisionSnapshotV1,
    #[ts(type = "number")]
    pub new_catalog_revision: u64,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DecideEvidenceV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub evidence: EvidenceSnapshotV1,
    pub decision: DecisionSnapshotV1,
    #[ts(type = "number")]
    pub new_catalog_revision: u64,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct MergeItemsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub item: CatalogItemV1,
    pub decision: DecisionSnapshotV1,
    #[ts(type = "number")]
    pub new_catalog_revision: u64,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SplitItemV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub items: Vec<CatalogItemV1>,
    pub decision: DecisionSnapshotV1,
    #[ts(type = "number")]
    pub new_catalog_revision: u64,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct UndoDecisionV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub restored_items: Vec<CatalogItemV1>,
    pub decision: DecisionSnapshotV1,
    #[ts(type = "number")]
    pub new_catalog_revision: u64,
    pub replay_status: ReplayStatusV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PreviewDeletionV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub preview_snapshot_token: DeletionSnapshotTokenV1,
    pub plan_sha256: crate::Sha256Digest,
    pub prepared_at: String,
    pub expires_at: String,
    pub revisions: crate::DeletionRevisionSnapshotV1,
    pub counts: Vec<DeletionClassCountV1>,
    #[ts(type = "number")]
    pub overall_count: u64,
    #[ts(type = "number")]
    pub retained_shared_blob_count: u64,
    #[ts(type = "number")]
    pub unique_blob_count: u64,
    #[ts(type = "number")]
    pub unique_blob_bytes: u64,
    pub backup_retention: Vec<crate::DeletionBackupRetentionV1>,
    pub remote_retention: Vec<crate::DeletionRemoteRetentionV1>,
    pub first_class: DeletionDependencyClassV1,
    pub first_page: Vec<DeletionPlanItemV1>,
    pub next_cursor: Option<PageCursorV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListDeletionPlanItemsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub preview_snapshot_token: DeletionSnapshotTokenV1,
    pub class: DeletionDependencyClassV1,
    pub items: Vec<DeletionPlanItemV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    pub next_cursor: Option<PageCursorV1>,
}
