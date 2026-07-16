use std::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use crate::{
    deserialize_schema_version_v1, BoundedPhotoArtifactBytesV1, EvidenceId, ItemAttributesV1,
    ItemId, PageCursorV1, ReplayStatusV1, RequestId, SafeFieldV1, Sha256Digest, SourceId, Validate,
    ValidationError, MAX_PAGE_SIZE, MAX_SAFE_INTEGER_V1, SCHEMA_VERSION_V1,
};

pub const MAX_OUTFIT_NAME_CHARS: usize = 80;
pub const MIN_OUTFIT_MEMBERS: usize = 2;
pub const MAX_OUTFIT_MEMBERS: usize = 8;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, TS)]
pub struct OutfitId(#[ts(type = "string")] Uuid);

impl OutfitId {
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
}

impl fmt::Debug for OutfitId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for OutfitId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0.hyphenated())
    }
}

impl Serialize for OutfitId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OutfitId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IdVisitor;

        impl Visitor<'_> for IdVisitor {
            type Value = OutfitId;

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
                let parsed = Uuid::parse_str(value).map_err(|_| E::custom("invalid UUID"))?;
                if parsed.is_nil() || parsed.hyphenated().to_string() != value {
                    return Err(E::custom("UUID must be canonical and non-nil"));
                }
                Ok(OutfitId(parsed))
            }
        }

        deserializer.deserialize_str(IdVisitor)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitAssetStateV1 {
    Available,
    MetadataOnly,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitAssetBindingV1 {
    pub state: OutfitAssetStateV1,
    pub evidence_id: Option<EvidenceId>,
    pub source_id: Option<SourceId>,
    pub blob_sha256: Option<Sha256Digest>,
    pub media_type: Option<String>,
    #[ts(type = "number | null")]
    pub byte_length: Option<u64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

impl Validate for OutfitAssetBindingV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let complete = self.evidence_id.is_some()
            && self.source_id.is_some()
            && self.blob_sha256.is_some()
            && matches!(
                self.media_type.as_deref(),
                Some("image/jpeg" | "image/png" | "image/webp")
            )
            && self.byte_length.is_some_and(|value| value > 0)
            && self.width.is_some_and(|value| value > 0)
            && self.height.is_some_and(|value| value > 0);
        let empty = self.evidence_id.is_none()
            && self.source_id.is_none()
            && self.blob_sha256.is_none()
            && self.media_type.is_none()
            && self.byte_length.is_none()
            && self.width.is_none()
            && self.height.is_none();
        if (self.state == OutfitAssetStateV1::Available && complete)
            || (self.state != OutfitAssetStateV1::Available && (complete || empty))
        {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitMemberV1 {
    pub ordinal: u8,
    pub item_id: ItemId,
    #[ts(type = "number")]
    pub item_updated_revision: u64,
    pub attributes: ItemAttributesV1,
    pub asset: OutfitAssetBindingV1,
}

impl Validate for OutfitMemberV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if usize::from(self.ordinal) >= MAX_OUTFIT_MEMBERS
            || self.item_updated_revision == 0
            || self.item_updated_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        self.attributes.validate()?;
        self.asset.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitV1 {
    pub outfit_id: OutfitId,
    pub name: String,
    pub members: Vec<OutfitMemberV1>,
    #[ts(type = "number")]
    pub created_outfit_revision: u64,
}

impl Validate for OutfitV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_name(&self.name)?;
        if !(MIN_OUTFIT_MEMBERS..=MAX_OUTFIT_MEMBERS).contains(&self.members.len())
            || self.created_outfit_revision == 0
            || self.created_outfit_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        let mut item_ids = self
            .members
            .iter()
            .map(|value| value.item_id)
            .collect::<Vec<_>>();
        item_ids.sort_unstable();
        item_ids.dedup();
        if item_ids.len() != self.members.len() {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        for (ordinal, member) in self.members.iter().enumerate() {
            member.validate()?;
            if usize::from(member.ordinal) != ordinal {
                return Err(ValidationError::new(SafeFieldV1::Collection));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitCollageMemberV1 {
    pub member: OutfitMemberV1,
    pub bytes: Option<BoundedPhotoArtifactBytesV1>,
}

impl Validate for OutfitCollageMemberV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.member.validate()?;
        if self.bytes.is_some() == (self.member.asset.state == OutfitAssetStateV1::Available) {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::Attributes))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CreateManualOutfitV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub name: String,
    pub item_ids: Vec<ItemId>,
    #[ts(type = "number")]
    pub expected_catalog_revision: u64,
    #[ts(type = "number")]
    pub expected_outfit_revision: u64,
}

impl Validate for CreateManualOutfitV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_name(&self.name)?;
        if !(MIN_OUTFIT_MEMBERS..=MAX_OUTFIT_MEMBERS).contains(&self.item_ids.len())
            || self.expected_catalog_revision >= MAX_SAFE_INTEGER_V1
            || self.expected_outfit_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        let mut unique = self.item_ids.clone();
        unique.sort_unstable();
        unique.dedup();
        if unique.len() == self.item_ids.len() {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::Collection))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListOutfitsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub cursor: Option<PageCursorV1>,
    pub limit: u16,
}

impl Validate for ListOutfitsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        if (1..=MAX_PAGE_SIZE).contains(&self.limit) {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::Limit))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GetOutfitCollageV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub outfit_id: OutfitId,
}

impl Validate for GetOutfitCollageV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct CreateManualOutfitV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub outfit: OutfitV1,
    #[ts(type = "number")]
    pub outfit_revision: u64,
    pub replay_status: ReplayStatusV1,
}

impl Validate for CreateManualOutfitV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        self.outfit.validate()?;
        if self.outfit.created_outfit_revision == self.outfit_revision {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::Collection))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListOutfitsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub outfits: Vec<OutfitV1>,
    #[ts(type = "number")]
    pub total_count: u64,
    #[ts(type = "number")]
    pub outfit_revision: u64,
    pub next_cursor: Option<PageCursorV1>,
}

impl Validate for ListOutfitsV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        if self.outfits.len() > MAX_PAGE_SIZE as usize
            || self.total_count < self.outfits.len() as u64
            || self.outfit_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        self.outfits.iter().try_for_each(Validate::validate)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GetOutfitCollageV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub outfit_id: OutfitId,
    pub name: String,
    pub members: Vec<OutfitCollageMemberV1>,
    #[ts(type = "number")]
    pub outfit_revision: u64,
}

impl Validate for GetOutfitCollageV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_schema(self.schema_version)?;
        validate_name(&self.name)?;
        if !(MIN_OUTFIT_MEMBERS..=MAX_OUTFIT_MEMBERS).contains(&self.members.len())
            || self.outfit_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::Collection));
        }
        for (ordinal, member) in self.members.iter().enumerate() {
            member.validate()?;
            if usize::from(member.member.ordinal) != ordinal {
                return Err(ValidationError::new(SafeFieldV1::Collection));
            }
        }
        Ok(())
    }
}

fn validate_schema(value: u8) -> Result<(), ValidationError> {
    if value == SCHEMA_VERSION_V1 {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::SchemaVersion))
    }
}

fn validate_name(value: &str) -> Result<(), ValidationError> {
    if value.trim() == value
        && !value.is_empty()
        && value.chars().count() <= MAX_OUTFIT_NAME_CHARS
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::Attributes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ItemCategoryV1;

    fn item() -> ItemAttributesV1 {
        ItemAttributesV1 {
            display_name: "White shirt".to_owned(),
            category: ItemCategoryV1::Top,
            subcategory: None,
            brand: None,
            primary_color: Some("White".to_owned()),
            size: None,
            notes: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn create_contract_rejects_duplicate_members_and_untrimmed_names() {
        let id = ItemId::new_v4();
        let mut request = CreateManualOutfitV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            name: "Date".to_owned(),
            item_ids: vec![id, id],
            expected_catalog_revision: 0,
            expected_outfit_revision: 0,
        };
        assert!(request.validate().is_err());
        request.item_ids[1] = ItemId::new_v4();
        request.name = " Date ".to_owned();
        assert!(request.validate().is_err());
    }

    #[test]
    fn collage_requires_bytes_only_for_available_pinned_assets() {
        let metadata = OutfitCollageMemberV1 {
            member: OutfitMemberV1 {
                ordinal: 0,
                item_id: ItemId::new_v4(),
                item_updated_revision: 1,
                attributes: item(),
                asset: OutfitAssetBindingV1 {
                    state: OutfitAssetStateV1::MetadataOnly,
                    evidence_id: None,
                    source_id: None,
                    blob_sha256: None,
                    media_type: None,
                    byte_length: None,
                    width: None,
                    height: None,
                },
            },
            bytes: None,
        };
        assert!(metadata.validate().is_ok());
        let mut malformed = metadata;
        malformed.bytes = Some(BoundedPhotoArtifactBytesV1::new(vec![1]).unwrap());
        assert!(malformed.validate().is_err());
    }
}
