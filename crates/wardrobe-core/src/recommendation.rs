use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use ts_rs::TS;
use uuid::Uuid;

use crate::{
    deserialize_schema_version_v1, CredentialId, ItemCategoryV1, ItemId, OutfitId, RequestId,
    SafeFieldV1, Validate, ValidationError, MAX_SAFE_INTEGER_V1, SCHEMA_VERSION_V1,
};

pub const OUTFIT_RECOMMENDATION_SCHEMA_REVISION_V1: &str = "outfit-recommendation-schema-v1";
pub const OUTFIT_COMPATIBILITY_REVISION_V1: &str = "outfit-compatibility-v1";
pub const OUTFIT_CAPABILITY_REVISION_V1: &str = "outfit-capability-v1";
pub const OUTFIT_TOOL_CONTRACT_REVISION_V1: &str = "outfit-tool-contract-v1";
pub const OUTFIT_RETENTION_DISCLOSURE_REVISION_V1: &str =
    "openai-outfit-data-boundary-2026-07-15-v1";
pub use crate::model_policy::{OUTFIT_RECOMMENDATION_MODEL_V1, OUTFIT_RECOMMENDATION_PROVIDER_V1};
pub const OUTFIT_RECOMMENDATION_CACHE_MODE_V1: &str = "explicit";
pub const OUTFIT_UNSATISFIABLE_CAVEAT_V1: &str =
    "Your confirmed wardrobe cannot satisfy this constraint.";

pub const MIN_RECOMMENDATION_ITEMS: usize = 2;
pub const MAX_RECOMMENDATION_ITEMS: usize = 8;
pub const MAX_RECOMMENDATION_PROPOSALS: u8 = 3;
pub const MAX_RECOMMENDATION_PROMPT_CHARS: usize = 2_000;
pub const MAX_RECOMMENDATION_NAME_CHARS: usize = 80;
pub const MAX_RECOMMENDATION_RATIONALE_CHARS: usize = 600;
pub const MAX_RECOMMENDATION_CAVEAT_CHARS: usize = 240;
pub const MAX_RECOMMENDATION_CAVEATS: usize = 8;
pub const MAX_RECOMMENDATION_EXCLUSIONS: usize = 64;
pub const MAX_RECOMMENDATION_SNAPSHOT_ITEMS: usize = 1_024;
pub const MAX_RECOMMENDATION_TOOL_RESULTS: u16 = 100;
pub const MAX_RECOMMENDATION_QUERY_CHARS: usize = 160;
pub const MAX_RETENTION_PROVENANCE_CHARS: usize = 128;
pub const MAX_RECOMMENDATION_PROVIDER_IDENTIFIER_CHARS: usize = 128;
pub const MIN_RECOMMENDATION_TEMPERATURE_C: i16 = -50;
pub const MAX_RECOMMENDATION_TEMPERATURE_C: i16 = 60;
pub const MAX_RESPONSES_CALLS_V1: u8 = 4;
pub const MAX_OUTFIT_TOOL_CALLS_V1: u8 = 12;
pub const MAX_OUTFIT_TRANSCRIPT_BYTES_V1: u32 = 512 * 1024;

macro_rules! recommendation_uuid_id {
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

recommendation_uuid_id!(OutfitRecommendationApprovalId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitOccasionV1 {
    Casual,
    Date,
    Work,
    Formal,
    Active,
    Travel,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitPrecipitationV1 {
    None,
    Rain,
    Snow,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
pub enum OpenAiRetentionModeV1 {
    #[serde(rename = "unknown")]
    #[ts(rename = "unknown")]
    Unknown,
    #[serde(rename = "default")]
    #[ts(rename = "default")]
    Default,
    #[serde(rename = "MAM")]
    #[ts(rename = "MAM")]
    Mam,
    #[serde(rename = "ZDR")]
    #[ts(rename = "ZDR")]
    Zdr,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
pub enum OutfitCapabilityTagV1 {
    #[serde(rename = "weather:rain")]
    #[ts(rename = "weather:rain")]
    WeatherRain,
    #[serde(rename = "weather:snow")]
    #[ts(rename = "weather:snow")]
    WeatherSnow,
    #[serde(rename = "insulation:cold")]
    #[ts(rename = "insulation:cold")]
    InsulationCold,
}

impl OutfitCapabilityTagV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WeatherRain => "weather:rain",
            Self::WeatherSnow => "weather:snow",
            Self::InsulationCold => "insulation:cold",
        }
    }
}

pub fn allowlisted_outfit_capability_tags(tags: &[String]) -> Vec<OutfitCapabilityTagV1> {
    let mut allowed = tags
        .iter()
        .filter_map(|tag| match tag.as_str() {
            "weather:rain" => Some(OutfitCapabilityTagV1::WeatherRain),
            "weather:snow" => Some(OutfitCapabilityTagV1::WeatherSnow),
            "insulation:cold" => Some(OutfitCapabilityTagV1::InsulationCold),
            _ => None,
        })
        .collect::<Vec<_>>();
    allowed.sort_unstable();
    allowed.dedup();
    allowed
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OpenAiRetentionDeclarationV1 {
    pub mode: OpenAiRetentionModeV1,
    pub provenance: String,
}

impl Validate for OpenAiRetentionDeclarationV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if is_bounded_identifier(&self.provenance, MAX_RETENTION_PROVENANCE_CHARS) {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RecommendationRetention))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OpenAiRetentionDisclosureV1 {
    pub revision: String,
    pub declaration: OpenAiRetentionDeclarationV1,
    pub store: bool,
    pub store_false_is_not_zdr: bool,
    pub default_abuse_monitoring_max_days: u8,
    pub safety_review_exceptions_apply: bool,
    pub prompt_cache_mode: String,
    pub prompt_cache_breakpoint_count: u8,
    pub prompt_cache_ttl_minimum_default: String,
    pub prompt_cache_may_retain_longer: bool,
    pub no_breakpoints_no_cache_reads_or_writes: bool,
}

impl OpenAiRetentionDisclosureV1 {
    pub fn for_declaration(declaration: OpenAiRetentionDeclarationV1) -> Self {
        Self {
            revision: OUTFIT_RETENTION_DISCLOSURE_REVISION_V1.to_owned(),
            declaration,
            store: false,
            store_false_is_not_zdr: true,
            default_abuse_monitoring_max_days: 30,
            safety_review_exceptions_apply: true,
            prompt_cache_mode: OUTFIT_RECOMMENDATION_CACHE_MODE_V1.to_owned(),
            prompt_cache_breakpoint_count: 0,
            prompt_cache_ttl_minimum_default: "30m".to_owned(),
            prompt_cache_may_retain_longer: true,
            no_breakpoints_no_cache_reads_or_writes: true,
        }
    }
}

impl Validate for OpenAiRetentionDisclosureV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.declaration.validate()?;
        if self.revision == OUTFIT_RETENTION_DISCLOSURE_REVISION_V1
            && !self.store
            && self.store_false_is_not_zdr
            && self.default_abuse_monitoring_max_days == 30
            && self.safety_review_exceptions_apply
            && self.prompt_cache_mode == OUTFIT_RECOMMENDATION_CACHE_MODE_V1
            && self.prompt_cache_breakpoint_count == 0
            && self.prompt_cache_ttl_minimum_default == "30m"
            && self.prompt_cache_may_retain_longer
            && self.no_breakpoints_no_cache_reads_or_writes
        {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RecommendationRetention))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitRecommendationConstraintsV1 {
    pub occasion: Option<OutfitOccasionV1>,
    pub temperature_c: Option<i16>,
    pub precipitation: Option<OutfitPrecipitationV1>,
}

impl Validate for OutfitRecommendationConstraintsV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.temperature_c.is_some_and(|value| {
            !(MIN_RECOMMENDATION_TEMPERATURE_C..=MAX_RECOMMENDATION_TEMPERATURE_C).contains(&value)
        }) {
            Err(ValidationError::new(SafeFieldV1::RecommendationConstraints))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitRecommendationEnvelopeV1 {
    pub prompt: String,
    pub credential_id: CredentialId,
    pub constraints: OutfitRecommendationConstraintsV1,
    pub excluded_item_ids: Vec<ItemId>,
    pub requested_proposal_count: u8,
    #[ts(type = "number")]
    pub expected_catalog_revision: u64,
    #[ts(type = "number")]
    pub expected_outfit_revision: u64,
    pub retention: OpenAiRetentionDeclarationV1,
}

impl Validate for OutfitRecommendationEnvelopeV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text(
            &self.prompt,
            1,
            MAX_RECOMMENDATION_PROMPT_CHARS,
            SafeFieldV1::RecommendationPrompt,
        )?;
        self.constraints.validate()?;
        validate_unique_ids(
            &self.excluded_item_ids,
            0,
            MAX_RECOMMENDATION_EXCLUSIONS,
            SafeFieldV1::RecommendationExclusions,
        )?;
        if !(1..=MAX_RECOMMENDATION_PROPOSALS).contains(&self.requested_proposal_count)
            || self.expected_catalog_revision >= MAX_SAFE_INTEGER_V1
            || self.expected_outfit_revision >= MAX_SAFE_INTEGER_V1
        {
            return Err(ValidationError::new(SafeFieldV1::RecommendationConstraints));
        }
        self.retention.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PreviewOutfitRecommendationV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub envelope: OutfitRecommendationEnvelopeV1,
}

impl Validate for PreviewOutfitRecommendationV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)?;
        self.envelope.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RequestOutfitRecommendationV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub approval_id: OutfitRecommendationApprovalId,
    pub envelope: OutfitRecommendationEnvelopeV1,
}

impl Validate for RequestOutfitRecommendationV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)?;
        self.envelope.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitDisclosureFieldClassV1 {
    Prompt,
    ExplicitConstraints,
    ExcludedItemIds,
    ItemIds,
    DisplayNames,
    Categories,
    PrimaryColors,
    Brands,
    CapabilityTags,
    WearHistory,
    StylePreferences,
    SavedOutfitMembership,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitRecommendationDisclosureV1 {
    pub provider: String,
    pub model: String,
    pub purpose: String,
    pub disclosed_field_classes: Vec<OutfitDisclosureFieldClassV1>,
    pub photos_disclosed: bool,
    pub email_disclosed: bool,
    pub paths_disclosed: bool,
    pub notes_disclosed: bool,
    pub sizes_disclosed: bool,
    pub evidence_metadata_disclosed: bool,
    pub retention: OpenAiRetentionDisclosureV1,
}

impl Validate for OutfitRecommendationDisclosureV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.retention.validate()?;
        let mut fields = self.disclosed_field_classes.clone();
        fields.sort_by_key(|value| *value as u8);
        fields.dedup();
        if self.provider == OUTFIT_RECOMMENDATION_PROVIDER_V1
            && self.model == OUTFIT_RECOMMENDATION_MODEL_V1
            && self.purpose == "outfit_recommendation"
            && fields.len() == self.disclosed_field_classes.len()
            && !fields.is_empty()
            && !self.photos_disclosed
            && !self.email_disclosed
            && !self.paths_disclosed
            && !self.notes_disclosed
            && !self.sizes_disclosed
            && !self.evidence_metadata_disclosed
        {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RecommendationDisclosure))
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitRecommendationProviderStatusV1 {
    Ready,
    CredentialUnavailable,
    NetworkUnavailable,
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitRecommendationApprovalV1 {
    pub approval_id: OutfitRecommendationApprovalId,
    pub expires_at: String,
    pub single_use: bool,
    #[ts(type = "number")]
    pub catalog_revision: u64,
    #[ts(type = "number")]
    pub outfit_revision: u64,
}

impl Validate for OutfitRecommendationApprovalV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.single_use
            && self.catalog_revision < MAX_SAFE_INTEGER_V1
            && self.outfit_revision < MAX_SAFE_INTEGER_V1
            && is_bounded_timestamp(&self.expires_at)
        {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RecommendationApproval))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct PreviewOutfitRecommendationV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub provider_status: OutfitRecommendationProviderStatusV1,
    pub disclosure: OutfitRecommendationDisclosureV1,
    pub approval: OutfitRecommendationApprovalV1,
}

impl Validate for PreviewOutfitRecommendationV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema(self.schema_version)?;
        self.disclosure.validate()?;
        self.approval.validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum ToolCapabilityV1 {
    ReadOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitToolNameV1 {
    SearchConfirmedWardrobe,
    SearchWearHistory,
    GetStylePreferences,
    ListSavedOutfits,
}

impl OutfitToolNameV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SearchConfirmedWardrobe => "search_confirmed_wardrobe",
            Self::SearchWearHistory => "search_wear_history",
            Self::GetStylePreferences => "get_style_preferences",
            Self::ListSavedOutfits => "list_saved_outfits",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitToolDefinitionV1 {
    pub name: OutfitToolNameV1,
    pub capability: ToolCapabilityV1,
    pub strict: bool,
    pub contract_revision: String,
    pub maximum_results: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitToolRegistryV1 {
    pub tools: Vec<OutfitToolDefinitionV1>,
    pub maximum_response_calls: u8,
    pub maximum_tool_calls: u8,
    pub maximum_transcript_bytes: u32,
}

impl OutfitToolRegistryV1 {
    pub fn production() -> Self {
        Self {
            tools: [
                OutfitToolNameV1::SearchConfirmedWardrobe,
                OutfitToolNameV1::SearchWearHistory,
                OutfitToolNameV1::GetStylePreferences,
                OutfitToolNameV1::ListSavedOutfits,
            ]
            .into_iter()
            .map(|name| OutfitToolDefinitionV1 {
                name,
                capability: ToolCapabilityV1::ReadOnly,
                strict: true,
                contract_revision: OUTFIT_TOOL_CONTRACT_REVISION_V1.to_owned(),
                maximum_results: MAX_RECOMMENDATION_TOOL_RESULTS,
            })
            .collect(),
            maximum_response_calls: MAX_RESPONSES_CALLS_V1,
            maximum_tool_calls: MAX_OUTFIT_TOOL_CALLS_V1,
            maximum_transcript_bytes: MAX_OUTFIT_TRANSCRIPT_BYTES_V1,
        }
    }
}

impl Default for OutfitToolRegistryV1 {
    fn default() -> Self {
        Self::production()
    }
}

impl Validate for OutfitToolRegistryV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let expected = Self::production();
        if self == &expected {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RecommendationTool))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SearchConfirmedWardrobeV1Arguments {
    pub query: Option<String>,
    pub categories: Vec<ItemCategoryV1>,
    pub capability_tags: Vec<OutfitCapabilityTagV1>,
    pub limit: u16,
}

impl Validate for SearchConfirmedWardrobeV1Arguments {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_optional_query(&self.query)?;
        validate_unique_values(&self.categories, 0, 9)?;
        validate_unique_values(&self.capability_tags, 0, 3)?;
        validate_tool_limit(self.limit)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SearchWearHistoryV1Arguments {
    pub item_ids: Vec<ItemId>,
    pub limit: u16,
}

impl Validate for SearchWearHistoryV1Arguments {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_unique_ids(
            &self.item_ids,
            0,
            MAX_RECOMMENDATION_EXCLUSIONS,
            SafeFieldV1::RecommendationTool,
        )?;
        validate_tool_limit(self.limit)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GetStylePreferencesV1Arguments {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ListSavedOutfitsV1Arguments {
    pub query: Option<String>,
    pub limit: u16,
}

impl Validate for ListSavedOutfitsV1Arguments {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_optional_query(&self.query)?;
        validate_tool_limit(self.limit)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(tag = "tool", content = "arguments", rename_all = "snake_case")]
#[ts(tag = "tool", content = "arguments", rename_all = "snake_case")]
pub enum OutfitToolArgumentsV1 {
    SearchConfirmedWardrobe(SearchConfirmedWardrobeV1Arguments),
    SearchWearHistory(SearchWearHistoryV1Arguments),
    GetStylePreferences(GetStylePreferencesV1Arguments),
    ListSavedOutfits(ListSavedOutfitsV1Arguments),
}

impl Validate for OutfitToolArgumentsV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::SearchConfirmedWardrobe(value) => value.validate(),
            Self::SearchWearHistory(value) => value.validate(),
            Self::GetStylePreferences(_) => Ok(()),
            Self::ListSavedOutfits(value) => value.validate(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitToolWardrobeItemV1 {
    pub item_id: ItemId,
    pub display_name: String,
    pub category: ItemCategoryV1,
    pub primary_color: Option<String>,
    pub brand: Option<String>,
    pub capability_tags: Vec<OutfitCapabilityTagV1>,
}

impl Validate for OutfitToolWardrobeItemV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text(&self.display_name, 1, 80, SafeFieldV1::RecommendationTool)?;
        for value in [self.primary_color.as_deref(), self.brand.as_deref()]
            .into_iter()
            .flatten()
        {
            validate_text(value, 1, 80, SafeFieldV1::RecommendationTool)?;
        }
        validate_unique_values(&self.capability_tags, 0, 3)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitWearRecordV1 {
    pub item_id: ItemId,
    pub worn_on: String,
}

impl Validate for OutfitWearRecordV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.worn_on.len() == 10
            && self
                .worn_on
                .bytes()
                .enumerate()
                .all(|(index, byte)| match index {
                    4 | 7 => byte == b'-',
                    _ => byte.is_ascii_digit(),
                })
        {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RecommendationTool))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitStylePreferenceV1 {
    pub preference: String,
}

impl Validate for OutfitStylePreferenceV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text(
            &self.preference,
            1,
            MAX_RECOMMENDATION_CAVEAT_CHARS,
            SafeFieldV1::RecommendationTool,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitToolSavedOutfitV1 {
    pub outfit_id: OutfitId,
    pub name: String,
    pub item_ids: Vec<ItemId>,
}

impl Validate for OutfitToolSavedOutfitV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text(
            &self.name,
            1,
            MAX_RECOMMENDATION_NAME_CHARS,
            SafeFieldV1::RecommendationTool,
        )?;
        validate_unique_ids(
            &self.item_ids,
            MIN_RECOMMENDATION_ITEMS,
            MAX_RECOMMENDATION_ITEMS,
            SafeFieldV1::RecommendationTool,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitToolDataStatusV1 {
    Ready,
    NotConfigured,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(tag = "tool", content = "result", rename_all = "snake_case")]
#[ts(tag = "tool", content = "result", rename_all = "snake_case")]
pub enum OutfitToolResultV1 {
    SearchConfirmedWardrobe {
        items: Vec<OutfitToolWardrobeItemV1>,
    },
    SearchWearHistory {
        status: OutfitToolDataStatusV1,
        records: Vec<OutfitWearRecordV1>,
    },
    GetStylePreferences {
        status: OutfitToolDataStatusV1,
        preferences: Vec<OutfitStylePreferenceV1>,
    },
    ListSavedOutfits {
        outfits: Vec<OutfitToolSavedOutfitV1>,
    },
}

impl Validate for OutfitToolResultV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::SearchConfirmedWardrobe { items } => {
                validate_result_count(items.len())?;
                validate_unique_ids(
                    &items.iter().map(|item| item.item_id).collect::<Vec<_>>(),
                    0,
                    MAX_RECOMMENDATION_TOOL_RESULTS as usize,
                    SafeFieldV1::RecommendationTool,
                )?;
                items.iter().try_for_each(Validate::validate)
            }
            Self::SearchWearHistory { status, records } => {
                validate_configured_collection(*status, records.len())?;
                validate_result_count(records.len())?;
                records.iter().try_for_each(Validate::validate)
            }
            Self::GetStylePreferences {
                status,
                preferences,
            } => {
                validate_configured_collection(*status, preferences.len())?;
                validate_result_count(preferences.len())?;
                preferences.iter().try_for_each(Validate::validate)
            }
            Self::ListSavedOutfits { outfits } => {
                validate_result_count(outfits.len())?;
                outfits.iter().try_for_each(Validate::validate)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitRecommendationSnapshotItemV1 {
    pub item_id: ItemId,
    #[ts(type = "number")]
    pub item_revision: u64,
    pub active: bool,
    pub category: ItemCategoryV1,
    pub capability_tags: Vec<OutfitCapabilityTagV1>,
}

impl Validate for OutfitRecommendationSnapshotItemV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.item_revision == 0 || self.item_revision >= MAX_SAFE_INTEGER_V1 {
            return Err(ValidationError::new(SafeFieldV1::RecommendationSnapshot));
        }
        validate_unique_values(&self.capability_tags, 0, 3)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitRecommendationSnapshotV1 {
    #[ts(type = "number")]
    pub catalog_revision: u64,
    #[ts(type = "number")]
    pub outfit_revision: u64,
    pub capability_revision: String,
    pub items: Vec<OutfitRecommendationSnapshotItemV1>,
}

impl Validate for OutfitRecommendationSnapshotV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.catalog_revision >= MAX_SAFE_INTEGER_V1
            || self.outfit_revision >= MAX_SAFE_INTEGER_V1
            || self.capability_revision != OUTFIT_CAPABILITY_REVISION_V1
            || self.items.len() > MAX_RECOMMENDATION_SNAPSHOT_ITEMS
        {
            return Err(ValidationError::new(SafeFieldV1::RecommendationSnapshot));
        }
        validate_unique_ids(
            &self
                .items
                .iter()
                .map(|item| item.item_id)
                .collect::<Vec<_>>(),
            0,
            MAX_RECOMMENDATION_SNAPSHOT_ITEMS,
            SafeFieldV1::RecommendationSnapshot,
        )?;
        self.items.iter().try_for_each(Validate::validate)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitConstraintKindV1 {
    Occasion,
    Temperature,
    Precipitation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitConstraintStatusV1 {
    Satisfied,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitUnresolvedReasonV1 {
    WardrobeCannotSatisfy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitConstraintAssessmentV1 {
    pub constraint: OutfitConstraintKindV1,
    pub status: OutfitConstraintStatusV1,
    pub reason: Option<OutfitUnresolvedReasonV1>,
    pub caveat: Option<String>,
}

impl Validate for OutfitConstraintAssessmentV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        match (self.status, self.reason, self.caveat.as_deref()) {
            (OutfitConstraintStatusV1::Satisfied, None, None) => Ok(()),
            (
                OutfitConstraintStatusV1::Unresolved,
                Some(OutfitUnresolvedReasonV1::WardrobeCannotSatisfy),
                Some(OUTFIT_UNSATISFIABLE_CAVEAT_V1),
            ) => Ok(()),
            _ => Err(ValidationError::new(SafeFieldV1::RecommendationAssessment)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitProposalV1 {
    pub name: String,
    pub item_ids: Vec<ItemId>,
    pub rationale: String,
    pub caveats: Vec<String>,
    pub unresolved_constraints: Vec<OutfitConstraintAssessmentV1>,
    pub constraint_assessment: Vec<OutfitConstraintAssessmentV1>,
}

impl Validate for OutfitProposalV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_text(
            &self.name,
            1,
            MAX_RECOMMENDATION_NAME_CHARS,
            SafeFieldV1::RecommendationProposal,
        )?;
        validate_text(
            &self.rationale,
            1,
            MAX_RECOMMENDATION_RATIONALE_CHARS,
            SafeFieldV1::RecommendationProposal,
        )?;
        validate_unique_ids(
            &self.item_ids,
            MIN_RECOMMENDATION_ITEMS,
            MAX_RECOMMENDATION_ITEMS,
            SafeFieldV1::RecommendationProposal,
        )?;
        validate_unique_text(
            &self.caveats,
            MAX_RECOMMENDATION_CAVEATS,
            MAX_RECOMMENDATION_CAVEAT_CHARS,
        )?;
        validate_assessment_shape(&self.unresolved_constraints, true)?;
        validate_assessment_shape(&self.constraint_assessment, false)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct StructuredOutfitRecommendationV1 {
    pub schema_revision: String,
    pub compatibility_revision: String,
    pub capability_revision: String,
    #[ts(type = "number")]
    pub catalog_revision: u64,
    #[ts(type = "number")]
    pub outfit_revision: u64,
    pub proposals: Vec<OutfitProposalV1>,
}

impl Validate for StructuredOutfitRecommendationV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_revision != OUTFIT_RECOMMENDATION_SCHEMA_REVISION_V1
            || self.compatibility_revision != OUTFIT_COMPATIBILITY_REVISION_V1
            || self.capability_revision != OUTFIT_CAPABILITY_REVISION_V1
            || self.catalog_revision >= MAX_SAFE_INTEGER_V1
            || self.outfit_revision >= MAX_SAFE_INTEGER_V1
            || self.proposals.is_empty()
            || self.proposals.len() > MAX_RECOMMENDATION_PROPOSALS as usize
        {
            return Err(ValidationError::new(SafeFieldV1::RecommendationProposal));
        }
        self.proposals.iter().try_for_each(Validate::validate)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ValidatedOutfitRecommendationV1 {
    pub schema_revision: String,
    pub compatibility_revision: String,
    pub capability_revision: String,
    #[ts(type = "number")]
    pub catalog_revision: u64,
    #[ts(type = "number")]
    pub outfit_revision: u64,
    pub proposals: Vec<OutfitProposalV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitProposalValidationErrorV1 {
    InvalidContract,
    StaleCatalogRevision,
    StaleOutfitRevision,
    UnknownItem,
    InactiveItem,
    DuplicateItem,
    ExcludedItem,
    IncompatibleItems,
    SatisfiableConstraintUnmet,
    InvalidUnresolvedConstraint,
    ConstraintAssessmentMismatch,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum OutfitRecommendationFailureCodeV1 {
    ApprovalExpired,
    ApprovalMismatch,
    ApprovalConsumed,
    CredentialUnavailable,
    ProviderUnavailable,
    Authentication,
    RateLimited,
    ProviderFailure,
    OutcomeUnknown,
    Incomplete,
    Refused,
    MalformedOutput,
    ToolProtocol,
    ToolLimit,
    Grounding,
    Constraint,
    Stale,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitRecommendationUsageV1 {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub reasoning_tokens: u32,
    pub response_calls: u8,
    pub tool_calls: u8,
    pub prompt_cache_read_tokens: u32,
    pub prompt_cache_write_tokens: u32,
}

impl Validate for OutfitRecommendationUsageV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.response_calls > MAX_RESPONSES_CALLS_V1
            || self.tool_calls > MAX_OUTFIT_TOOL_CALLS_V1
        {
            Err(ValidationError::new(SafeFieldV1::RecommendationUsage))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct OutfitRecommendationAuditV1 {
    pub provider: String,
    pub model: String,
    pub provider_request_id: Option<String>,
    pub response_id: Option<String>,
    pub retention: OpenAiRetentionDisclosureV1,
    pub reported_cache_usage: bool,
    pub usage: OutfitRecommendationUsageV1,
}

impl Validate for OutfitRecommendationAuditV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.retention.validate()?;
        self.usage.validate()?;
        for value in [
            self.provider_request_id.as_deref(),
            self.response_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !is_bounded_identifier(value, MAX_RECOMMENDATION_PROVIDER_IDENTIFIER_CHARS) {
                return Err(ValidationError::new(SafeFieldV1::RecommendationUsage));
            }
        }
        if self.provider == OUTFIT_RECOMMENDATION_PROVIDER_V1
            && self.model == OUTFIT_RECOMMENDATION_MODEL_V1
            && self.reported_cache_usage
                == (self.usage.prompt_cache_read_tokens != 0
                    || self.usage.prompt_cache_write_tokens != 0)
        {
            Ok(())
        } else {
            Err(ValidationError::new(SafeFieldV1::RecommendationUsage))
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[ts(tag = "outcome", rename_all = "snake_case")]
pub enum OutfitRecommendationOutcomeV1 {
    Completed {
        recommendation: ValidatedOutfitRecommendationV1,
        audit: OutfitRecommendationAuditV1,
    },
    Refused {
        audit: OutfitRecommendationAuditV1,
    },
    Failed {
        code: OutfitRecommendationFailureCodeV1,
        retryable: bool,
        audit: Option<OutfitRecommendationAuditV1>,
    },
    HistoricalStale {
        catalog_changed: bool,
        outfit_changed: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RequestOutfitRecommendationV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub outcome: OutfitRecommendationOutcomeV1,
}

pub fn validate_outfit_proposal_v1(
    envelope: &OutfitRecommendationEnvelopeV1,
    snapshot: &OutfitRecommendationSnapshotV1,
    result: &StructuredOutfitRecommendationV1,
) -> Result<ValidatedOutfitRecommendationV1, OutfitProposalValidationErrorV1> {
    envelope
        .validate()
        .map_err(|_| OutfitProposalValidationErrorV1::InvalidContract)?;
    snapshot
        .validate()
        .map_err(|_| OutfitProposalValidationErrorV1::InvalidContract)?;
    result
        .validate()
        .map_err(|_| OutfitProposalValidationErrorV1::InvalidContract)?;

    if envelope.expected_catalog_revision != snapshot.catalog_revision
        || result.catalog_revision != snapshot.catalog_revision
    {
        return Err(OutfitProposalValidationErrorV1::StaleCatalogRevision);
    }
    if envelope.expected_outfit_revision != snapshot.outfit_revision
        || result.outfit_revision != snapshot.outfit_revision
    {
        return Err(OutfitProposalValidationErrorV1::StaleOutfitRevision);
    }
    if result.proposals.len() != usize::from(envelope.requested_proposal_count) {
        return Err(OutfitProposalValidationErrorV1::InvalidContract);
    }

    let item_by_id = snapshot
        .items
        .iter()
        .map(|item| (item.item_id, item))
        .collect::<BTreeMap<_, _>>();
    let exclusions = envelope
        .excluded_item_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let eligible = snapshot
        .items
        .iter()
        .filter(|item| item.active && !exclusions.contains(&item.item_id))
        .collect::<Vec<_>>();

    let mut validated = Vec::with_capacity(result.proposals.len());
    for proposal in &result.proposals {
        let mut seen = BTreeSet::new();
        let mut selected = Vec::with_capacity(proposal.item_ids.len());
        for item_id in &proposal.item_ids {
            if !seen.insert(*item_id) {
                return Err(OutfitProposalValidationErrorV1::DuplicateItem);
            }
            let item = item_by_id
                .get(item_id)
                .copied()
                .ok_or(OutfitProposalValidationErrorV1::UnknownItem)?;
            if !item.active {
                return Err(OutfitProposalValidationErrorV1::InactiveItem);
            }
            if exclusions.contains(item_id) {
                return Err(OutfitProposalValidationErrorV1::ExcludedItem);
            }
            selected.push(item);
        }

        if !coherent_base(&selected) {
            return Err(OutfitProposalValidationErrorV1::IncompatibleItems);
        }

        let recomputed =
            recompute_constraint_assessment(&envelope.constraints, &eligible, &selected)?;
        if proposal.constraint_assessment != recomputed {
            return Err(OutfitProposalValidationErrorV1::ConstraintAssessmentMismatch);
        }
        let unresolved = recomputed
            .iter()
            .filter(|assessment| assessment.status == OutfitConstraintStatusV1::Unresolved)
            .cloned()
            .collect::<Vec<_>>();
        if proposal.unresolved_constraints != unresolved {
            return Err(OutfitProposalValidationErrorV1::InvalidUnresolvedConstraint);
        }
        if unresolved.iter().any(|assessment| {
            assessment
                .caveat
                .as_deref()
                .is_some_and(|caveat| !proposal.caveats.iter().any(|value| value == caveat))
        }) {
            return Err(OutfitProposalValidationErrorV1::InvalidUnresolvedConstraint);
        }
        validated.push(proposal.clone());
    }

    Ok(ValidatedOutfitRecommendationV1 {
        schema_revision: result.schema_revision.clone(),
        compatibility_revision: result.compatibility_revision.clone(),
        capability_revision: result.capability_revision.clone(),
        catalog_revision: result.catalog_revision,
        outfit_revision: result.outfit_revision,
        proposals: validated,
    })
}

fn recompute_constraint_assessment(
    constraints: &OutfitRecommendationConstraintsV1,
    eligible: &[&OutfitRecommendationSnapshotItemV1],
    selected: &[&OutfitRecommendationSnapshotItemV1],
) -> Result<Vec<OutfitConstraintAssessmentV1>, OutfitProposalValidationErrorV1> {
    let mut result = Vec::new();
    for constraint in explicit_constraint_kinds(constraints) {
        if constraint_met(constraint, constraints, selected) {
            result.push(satisfied_assessment(constraint));
        } else if constraint_satisfiable(constraint, constraints, eligible) {
            return Err(OutfitProposalValidationErrorV1::SatisfiableConstraintUnmet);
        } else {
            result.push(unresolved_assessment(constraint));
        }
    }
    Ok(result)
}

fn explicit_constraint_kinds(
    constraints: &OutfitRecommendationConstraintsV1,
) -> Vec<OutfitConstraintKindV1> {
    let mut result = Vec::with_capacity(3);
    if constraints.occasion.is_some() {
        result.push(OutfitConstraintKindV1::Occasion);
    }
    if constraints.temperature_c.is_some() {
        result.push(OutfitConstraintKindV1::Temperature);
    }
    if constraints.precipitation.is_some() {
        result.push(OutfitConstraintKindV1::Precipitation);
    }
    result
}

fn satisfied_assessment(constraint: OutfitConstraintKindV1) -> OutfitConstraintAssessmentV1 {
    OutfitConstraintAssessmentV1 {
        constraint,
        status: OutfitConstraintStatusV1::Satisfied,
        reason: None,
        caveat: None,
    }
}

fn unresolved_assessment(constraint: OutfitConstraintKindV1) -> OutfitConstraintAssessmentV1 {
    OutfitConstraintAssessmentV1 {
        constraint,
        status: OutfitConstraintStatusV1::Unresolved,
        reason: Some(OutfitUnresolvedReasonV1::WardrobeCannotSatisfy),
        caveat: Some(OUTFIT_UNSATISFIABLE_CAVEAT_V1.to_owned()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ItemSignature {
    category: ItemCategoryV1,
    rain: bool,
    snow: bool,
    cold: bool,
}

impl Ord for ItemSignature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            category_code(self.category),
            self.rain,
            self.snow,
            self.cold,
        )
            .cmp(&(
                category_code(other.category),
                other.rain,
                other.snow,
                other.cold,
            ))
    }
}

impl PartialOrd for ItemSignature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ItemSignature {
    fn from_item(item: &OutfitRecommendationSnapshotItemV1) -> Self {
        Self {
            category: item.category,
            rain: item
                .capability_tags
                .contains(&OutfitCapabilityTagV1::WeatherRain),
            snow: item
                .capability_tags
                .contains(&OutfitCapabilityTagV1::WeatherSnow),
            cold: item
                .capability_tags
                .contains(&OutfitCapabilityTagV1::InsulationCold),
        }
    }
}

fn constraint_satisfiable(
    target: OutfitConstraintKindV1,
    constraints: &OutfitRecommendationConstraintsV1,
    eligible: &[&OutfitRecommendationSnapshotItemV1],
) -> bool {
    let mut signatures = Vec::<ItemSignature>::new();
    for item in eligible {
        let signature = ItemSignature::from_item(item);
        if !signatures.contains(&signature) {
            signatures.push(signature);
        }
    }
    signatures.sort_unstable();

    let empty = vec![None];
    let options = |category| {
        let mut result = empty.clone();
        result.extend(
            signatures
                .iter()
                .filter(|value| value.category == category)
                .copied()
                .map(Some),
        );
        result
    };
    let required = |category| {
        signatures
            .iter()
            .filter(|value| value.category == category)
            .copied()
            .collect::<Vec<_>>()
    };
    let dresses = required(ItemCategoryV1::Dress);
    let tops = required(ItemCategoryV1::Top);
    let bottoms = required(ItemCategoryV1::Bottom);
    let activewear = required(ItemCategoryV1::Activewear);
    let outerwear = options(ItemCategoryV1::Outerwear);
    let shoes = options(ItemCategoryV1::Shoes);

    let mut bases = Vec::<Vec<ItemSignature>>::new();
    bases.extend(dresses.into_iter().map(|value| vec![value]));
    for top in tops {
        for bottom in &bottoms {
            bases.push(vec![top, *bottom]);
        }
    }
    bases.extend(activewear.into_iter().map(|value| vec![value]));

    for base in bases {
        for outer in &outerwear {
            for shoe in &shoes {
                let mut candidate = base.clone();
                if let Some(value) = outer {
                    candidate.push(*value);
                }
                if let Some(value) = shoe {
                    candidate.push(*value);
                }
                if candidate.len() < MIN_RECOMMENDATION_ITEMS {
                    continue;
                }
                if signature_constraints_met(target, constraints, &candidate) {
                    return true;
                }
            }
        }
    }
    false
}

fn signature_constraints_met(
    target: OutfitConstraintKindV1,
    constraints: &OutfitRecommendationConstraintsV1,
    selected: &[ItemSignature],
) -> bool {
    explicit_constraint_kinds(constraints)
        .into_iter()
        .all(|kind| kind == target || signature_constraint_met(kind, constraints, selected))
        && signature_constraint_met(target, constraints, selected)
}

fn signature_constraint_met(
    kind: OutfitConstraintKindV1,
    constraints: &OutfitRecommendationConstraintsV1,
    selected: &[ItemSignature],
) -> bool {
    match kind {
        OutfitConstraintKindV1::Occasion => constraints.occasion.is_none_or(|occasion| {
            occasion_met(occasion, selected.iter().map(|item| item.category))
        }),
        OutfitConstraintKindV1::Temperature => {
            constraints.temperature_c.is_none_or(|temperature| {
                temperature_met(
                    temperature,
                    selected.iter().map(|item| (item.category, item.cold)),
                )
            })
        }
        OutfitConstraintKindV1::Precipitation => {
            constraints.precipitation.is_none_or(|precipitation| {
                precipitation_met(
                    precipitation,
                    selected
                        .iter()
                        .map(|item| (item.category, item.rain, item.snow)),
                )
            })
        }
    }
}

fn constraint_met(
    kind: OutfitConstraintKindV1,
    constraints: &OutfitRecommendationConstraintsV1,
    selected: &[&OutfitRecommendationSnapshotItemV1],
) -> bool {
    match kind {
        OutfitConstraintKindV1::Occasion => constraints.occasion.is_none_or(|occasion| {
            occasion_met(occasion, selected.iter().map(|item| item.category))
        }),
        OutfitConstraintKindV1::Temperature => {
            constraints.temperature_c.is_none_or(|temperature| {
                temperature_met(
                    temperature,
                    selected.iter().map(|item| {
                        (
                            item.category,
                            item.capability_tags
                                .contains(&OutfitCapabilityTagV1::InsulationCold),
                        )
                    }),
                )
            })
        }
        OutfitConstraintKindV1::Precipitation => {
            constraints.precipitation.is_none_or(|precipitation| {
                precipitation_met(
                    precipitation,
                    selected.iter().map(|item| {
                        (
                            item.category,
                            item.capability_tags
                                .contains(&OutfitCapabilityTagV1::WeatherRain),
                            item.capability_tags
                                .contains(&OutfitCapabilityTagV1::WeatherSnow),
                        )
                    }),
                )
            })
        }
    }
}

fn occasion_met(
    occasion: OutfitOccasionV1,
    categories: impl Iterator<Item = ItemCategoryV1>,
) -> bool {
    let categories = categories.collect::<Vec<_>>();
    let coherent = coherent_categories(&categories);
    let active = categories.contains(&ItemCategoryV1::Activewear);
    let shoes = categories.contains(&ItemCategoryV1::Shoes);
    let dress = categories.contains(&ItemCategoryV1::Dress);
    let separates =
        categories.contains(&ItemCategoryV1::Top) && categories.contains(&ItemCategoryV1::Bottom);
    match occasion {
        OutfitOccasionV1::Casual | OutfitOccasionV1::Date => coherent,
        OutfitOccasionV1::Work => coherent && !active && shoes,
        OutfitOccasionV1::Formal => (dress || separates) && shoes && !active,
        OutfitOccasionV1::Active => active && coherent && shoes,
        OutfitOccasionV1::Travel => coherent && shoes,
    }
}

fn temperature_met(temperature: i16, items: impl Iterator<Item = (ItemCategoryV1, bool)>) -> bool {
    let items = items.collect::<Vec<_>>();
    let has_outerwear = items
        .iter()
        .any(|(category, _)| *category == ItemCategoryV1::Outerwear);
    let has_shoes = items
        .iter()
        .any(|(category, _)| *category == ItemCategoryV1::Shoes);
    let has_cold = items.iter().any(|(_, cold)| *cold);
    match temperature {
        ..=0 => {
            has_shoes
                && items
                    .iter()
                    .any(|(category, cold)| *category == ItemCategoryV1::Outerwear && *cold)
        }
        1..=10 => has_outerwear,
        11..=27 => true,
        28.. => !has_outerwear && !has_cold,
    }
}

fn precipitation_met(
    precipitation: OutfitPrecipitationV1,
    items: impl Iterator<Item = (ItemCategoryV1, bool, bool)>,
) -> bool {
    let items = items.collect::<Vec<_>>();
    let has_shoes = items
        .iter()
        .any(|(category, _, _)| *category == ItemCategoryV1::Shoes);
    match precipitation {
        OutfitPrecipitationV1::None => true,
        OutfitPrecipitationV1::Rain => {
            has_shoes
                && items.iter().any(|(category, rain, _)| {
                    matches!(category, ItemCategoryV1::Outerwear | ItemCategoryV1::Shoes) && *rain
                })
        }
        OutfitPrecipitationV1::Snow => {
            items
                .iter()
                .any(|(category, _, snow)| *category == ItemCategoryV1::Outerwear && *snow)
                && items
                    .iter()
                    .any(|(category, _, snow)| *category == ItemCategoryV1::Shoes && *snow)
        }
    }
}

fn coherent_base(selected: &[&OutfitRecommendationSnapshotItemV1]) -> bool {
    coherent_categories(
        &selected
            .iter()
            .map(|item| item.category)
            .collect::<Vec<_>>(),
    )
}

fn coherent_categories(categories: &[ItemCategoryV1]) -> bool {
    let count = |target| categories.iter().filter(|value| **value == target).count();
    if count(ItemCategoryV1::Dress) > 1
        || count(ItemCategoryV1::Top) > 1
        || count(ItemCategoryV1::Bottom) > 1
        || count(ItemCategoryV1::Activewear) > 1
        || count(ItemCategoryV1::Outerwear) > 1
        || count(ItemCategoryV1::Shoes) > 1
        || count(ItemCategoryV1::Accessory) > 4
        || count(ItemCategoryV1::Underwear) > 0
        || count(ItemCategoryV1::Other) > 0
    {
        return false;
    }
    let dress = count(ItemCategoryV1::Dress);
    let top = count(ItemCategoryV1::Top);
    let bottom = count(ItemCategoryV1::Bottom);
    let active = count(ItemCategoryV1::Activewear);
    (dress == 1 && top == 0 && bottom == 0 && active == 0)
        || (dress == 0 && top == 1 && bottom == 1 && active == 0)
        || (dress == 0 && top == 0 && bottom == 0 && active == 1)
}

fn validate_assessment_shape(
    values: &[OutfitConstraintAssessmentV1],
    unresolved_only: bool,
) -> Result<(), ValidationError> {
    if values.len() > 3 {
        return Err(ValidationError::new(SafeFieldV1::RecommendationAssessment));
    }
    let mut kinds = BTreeSet::new();
    for value in values {
        value.validate()?;
        if !kinds.insert(value.constraint)
            || (unresolved_only && value.status != OutfitConstraintStatusV1::Unresolved)
        {
            return Err(ValidationError::new(SafeFieldV1::RecommendationAssessment));
        }
    }
    Ok(())
}

fn validate_optional_query(value: &Option<String>) -> Result<(), ValidationError> {
    if let Some(value) = value {
        validate_text(
            value,
            1,
            MAX_RECOMMENDATION_QUERY_CHARS,
            SafeFieldV1::RecommendationTool,
        )?;
    }
    Ok(())
}

fn validate_tool_limit(value: u16) -> Result<(), ValidationError> {
    if (1..=MAX_RECOMMENDATION_TOOL_RESULTS).contains(&value) {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::RecommendationTool))
    }
}

fn validate_result_count(value: usize) -> Result<(), ValidationError> {
    if value <= MAX_RECOMMENDATION_TOOL_RESULTS as usize {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::RecommendationTool))
    }
}

fn validate_configured_collection(
    status: OutfitToolDataStatusV1,
    count: usize,
) -> Result<(), ValidationError> {
    if status == OutfitToolDataStatusV1::NotConfigured && count != 0 {
        Err(ValidationError::new(SafeFieldV1::RecommendationTool))
    } else {
        Ok(())
    }
}

fn validate_unique_values<T: Copy + Eq>(
    values: &[T],
    min: usize,
    max: usize,
) -> Result<(), ValidationError> {
    if values.len() < min || values.len() > max {
        return Err(ValidationError::new(SafeFieldV1::RecommendationTool));
    }
    for (index, value) in values.iter().enumerate() {
        if values[..index].contains(value) {
            return Err(ValidationError::new(SafeFieldV1::RecommendationTool));
        }
    }
    Ok(())
}

fn validate_unique_ids<T: Copy + Ord>(
    values: &[T],
    min: usize,
    max: usize,
    field: SafeFieldV1,
) -> Result<(), ValidationError> {
    if values.len() < min || values.len() > max {
        return Err(ValidationError::new(field));
    }
    let mut unique = values.to_vec();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() == values.len() {
        Ok(())
    } else {
        Err(ValidationError::new(field))
    }
}

fn validate_unique_text(
    values: &[String],
    max_values: usize,
    max_chars: usize,
) -> Result<(), ValidationError> {
    if values.len() > max_values {
        return Err(ValidationError::new(SafeFieldV1::RecommendationProposal));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(value, 1, max_chars, SafeFieldV1::RecommendationProposal)?;
        if !unique.insert(value) {
            return Err(ValidationError::new(SafeFieldV1::RecommendationProposal));
        }
    }
    Ok(())
}

fn validate_text(
    value: &str,
    min_chars: usize,
    max_chars: usize,
    field: SafeFieldV1,
) -> Result<(), ValidationError> {
    let count = value.chars().count();
    if (min_chars..=max_chars).contains(&count)
        && value.trim() == value
        && !value.chars().any(char::is_control)
    {
        Ok(())
    } else {
        Err(ValidationError::new(field))
    }
}

fn is_bounded_identifier(value: &str, max_chars: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_chars
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn is_bounded_timestamp(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 40
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'-' | b':' | b'.' | b'+' | b'T' | b'Z')
        })
}

const fn category_code(value: ItemCategoryV1) -> u8 {
    match value {
        ItemCategoryV1::Top => 0,
        ItemCategoryV1::Bottom => 1,
        ItemCategoryV1::Dress => 2,
        ItemCategoryV1::Outerwear => 3,
        ItemCategoryV1::Shoes => 4,
        ItemCategoryV1::Accessory => 5,
        ItemCategoryV1::Underwear => 6,
        ItemCategoryV1::Activewear => 7,
        ItemCategoryV1::Other => 8,
    }
}

fn require_schema(value: u8) -> Result<(), ValidationError> {
    if value == SCHEMA_VERSION_V1 {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::SchemaVersion))
    }
}
