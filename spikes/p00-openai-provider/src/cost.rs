use crate::request::{MAX_OUTPUT_TOKENS, MODEL};
use crate::sanitize::{CropDetail, SanitizedCrop};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

const TOKENS_PER_RATE_UNIT: u128 = 1_000_000;
const BASIS_POINTS: u128 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageTokenPolicy {
    pub low_detail_tokens: u64,
    pub high_detail_base_tokens: u64,
    pub high_detail_tile_tokens: u64,
    pub high_detail_tile_pixels: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateCard {
    pub rate_card_id: String,
    pub approved: bool,
    pub approved_at: String,
    pub valid_from: String,
    pub valid_through: String,
    pub currency: String,
    pub model_revision: String,
    pub uncached_input_micro_usd_per_million: u64,
    pub cached_input_micro_usd_per_million: u64,
    pub output_micro_usd_per_million: u64,
    pub cache_write_multiplier_milli: u32,
    pub max_text_input_tokens: u64,
    pub image_tokens: ImageTokenPolicy,
    pub service_tier_uplift_bps: BTreeMap<String, u32>,
    pub region_uplift_bps: BTreeMap<String, u32>,
    pub calculation_revision: String,
}

impl RateCard {
    pub fn validate_for(
        &self,
        model: &str,
        service_tier: &str,
        region: &str,
        on_date: &str,
    ) -> Result<(), CostError> {
        if !self.approved {
            return Err(CostError::UnapprovedRateCard);
        }
        if self.model_revision != model || model != MODEL {
            return Err(CostError::ModelMismatch);
        }
        if self.currency != "USD"
            || !safe_id(&self.rate_card_id)
            || !safe_id(&self.calculation_revision)
            || !valid_date(&self.approved_at)
            || !valid_date(&self.valid_from)
            || !valid_date(&self.valid_through)
            || !valid_date(on_date)
        {
            return Err(CostError::InvalidRateCard);
        }
        if on_date < self.valid_from.as_str() || on_date > self.valid_through.as_str() {
            return Err(CostError::StaleRateCard);
        }
        if self.cache_write_multiplier_milli != 1_250 {
            return Err(CostError::InvalidCacheWriteMultiplier);
        }
        if self.max_text_input_tokens == 0
            || self.image_tokens.low_detail_tokens == 0
            || self.image_tokens.high_detail_tile_pixels == 0
        {
            return Err(CostError::InvalidRateCard);
        }
        if !self.service_tier_uplift_bps.contains_key(service_tier) {
            return Err(CostError::UnknownServiceTier);
        }
        if !self.region_uplift_bps.contains_key(region) {
            return Err(CostError::UnknownRegion);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub cache_write_tokens: u64,
    pub output_tokens: u64,
    pub reasoning_tokens: u64,
    pub total_tokens: u64,
}

impl Usage {
    pub fn validate(self) -> Result<(), CostError> {
        let classified_input = self
            .cached_input_tokens
            .checked_add(self.cache_write_tokens)
            .ok_or(CostError::Overflow)?;
        if classified_input > self.input_tokens
            || self.reasoning_tokens > self.output_tokens
            || self
                .input_tokens
                .checked_add(self.output_tokens)
                .ok_or(CostError::Overflow)?
                != self.total_tokens
        {
            return Err(CostError::InvalidUsage);
        }
        Ok(())
    }

    pub fn uncached_input_tokens(self) -> Result<u64, CostError> {
        self.validate()?;
        self.input_tokens
            .checked_sub(self.cached_input_tokens)
            .and_then(|value| value.checked_sub(self.cache_write_tokens))
            .ok_or(CostError::InvalidUsage)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostBreakdown {
    pub rate_card_id: String,
    pub calculation_revision: String,
    pub model_revision: String,
    pub service_tier: String,
    pub region: String,
    pub uncached_input_micro_usd: u64,
    pub cached_input_micro_usd: u64,
    pub cache_write_micro_usd: u64,
    pub output_micro_usd: u64,
    pub pre_uplift_micro_usd: u64,
    pub service_tier_uplift_bps: u32,
    pub region_uplift_bps: u32,
    pub estimated_micro_usd: u64,
}

pub fn estimate_completed_cost(
    rate_card: &RateCard,
    usage: Usage,
    service_tier: &str,
    region: &str,
    on_date: &str,
) -> Result<CostBreakdown, CostError> {
    rate_card.validate_for(MODEL, service_tier, region, on_date)?;
    let uncached_tokens = usage.uncached_input_tokens()?;
    let uncached = token_cost(
        uncached_tokens,
        rate_card.uncached_input_micro_usd_per_million,
    )?;
    let cached = token_cost(
        usage.cached_input_tokens,
        rate_card.cached_input_micro_usd_per_million,
    )?;
    let cache_write_rate = checked_ceil_div(
        u128::from(rate_card.uncached_input_micro_usd_per_million)
            .checked_mul(u128::from(rate_card.cache_write_multiplier_milli))
            .ok_or(CostError::Overflow)?,
        1_000,
    )?;
    let cache_write = token_cost_u128(usage.cache_write_tokens, cache_write_rate)?;
    let output = token_cost(usage.output_tokens, rate_card.output_micro_usd_per_million)?;
    finish_breakdown(
        rate_card,
        service_tier,
        region,
        uncached,
        cached,
        cache_write,
        output,
    )
}

pub fn estimate_preflight_ceiling(
    rate_card: &RateCard,
    crops: &[SanitizedCrop],
    service_tier: &str,
    region: &str,
    on_date: &str,
) -> Result<CostBreakdown, CostError> {
    rate_card.validate_for(MODEL, service_tier, region, on_date)?;
    let image_tokens = crops.iter().try_fold(0u64, |total, crop| {
        total
            .checked_add(image_tokens(&rate_card.image_tokens, crop)?)
            .ok_or(CostError::Overflow)
    })?;
    let input_tokens = rate_card
        .max_text_input_tokens
        .checked_add(image_tokens)
        .ok_or(CostError::Overflow)?;
    let usage = Usage {
        input_tokens,
        output_tokens: u64::from(MAX_OUTPUT_TOKENS),
        total_tokens: input_tokens
            .checked_add(u64::from(MAX_OUTPUT_TOKENS))
            .ok_or(CostError::Overflow)?,
        ..Usage::default()
    };
    estimate_completed_cost(rate_card, usage, service_tier, region, on_date)
}

pub fn aggregate_attempt_cost(
    attempts: impl IntoIterator<Item = Option<u64>>,
) -> Result<Option<u64>, CostError> {
    let mut total = 0u64;
    for attempt in attempts {
        let Some(attempt) = attempt else {
            return Ok(None);
        };
        total = total.checked_add(attempt).ok_or(CostError::Overflow)?;
    }
    Ok(Some(total))
}

fn image_tokens(policy: &ImageTokenPolicy, crop: &SanitizedCrop) -> Result<u64, CostError> {
    match crop.detail() {
        CropDetail::Low => Ok(policy.low_detail_tokens),
        CropDetail::High => {
            let tile = u64::from(policy.high_detail_tile_pixels);
            let across = checked_ceil_div(u128::from(crop.width()), u128::from(tile))?;
            let down = checked_ceil_div(u128::from(crop.height()), u128::from(tile))?;
            let tiled = across
                .checked_mul(down)
                .and_then(|tiles| tiles.checked_mul(u128::from(policy.high_detail_tile_tokens)))
                .and_then(|tokens| tokens.checked_add(u128::from(policy.high_detail_base_tokens)))
                .ok_or(CostError::Overflow)?;
            u64::try_from(tiled).map_err(|_| CostError::Overflow)
        }
    }
}

fn token_cost(tokens: u64, micro_usd_per_million: u64) -> Result<u64, CostError> {
    token_cost_u128(tokens, u128::from(micro_usd_per_million))
}

fn token_cost_u128(tokens: u64, micro_usd_per_million: u128) -> Result<u64, CostError> {
    let numerator = u128::from(tokens)
        .checked_mul(micro_usd_per_million)
        .ok_or(CostError::Overflow)?;
    let value = checked_ceil_div(numerator, TOKENS_PER_RATE_UNIT)?;
    u64::try_from(value).map_err(|_| CostError::Overflow)
}

#[allow(clippy::too_many_arguments)]
fn finish_breakdown(
    rate_card: &RateCard,
    service_tier: &str,
    region: &str,
    uncached: u64,
    cached: u64,
    cache_write: u64,
    output: u64,
) -> Result<CostBreakdown, CostError> {
    let pre_uplift = uncached
        .checked_add(cached)
        .and_then(|value| value.checked_add(cache_write))
        .and_then(|value| value.checked_add(output))
        .ok_or(CostError::Overflow)?;
    let service_bps = *rate_card
        .service_tier_uplift_bps
        .get(service_tier)
        .ok_or(CostError::UnknownServiceTier)?;
    let region_bps = *rate_card
        .region_uplift_bps
        .get(region)
        .ok_or(CostError::UnknownRegion)?;
    let with_service = apply_uplift(pre_uplift, service_bps)?;
    let estimated = apply_uplift(with_service, region_bps)?;
    Ok(CostBreakdown {
        rate_card_id: rate_card.rate_card_id.clone(),
        calculation_revision: rate_card.calculation_revision.clone(),
        model_revision: rate_card.model_revision.clone(),
        service_tier: service_tier.to_owned(),
        region: region.to_owned(),
        uncached_input_micro_usd: uncached,
        cached_input_micro_usd: cached,
        cache_write_micro_usd: cache_write,
        output_micro_usd: output,
        pre_uplift_micro_usd: pre_uplift,
        service_tier_uplift_bps: service_bps,
        region_uplift_bps: region_bps,
        estimated_micro_usd: estimated,
    })
}

fn apply_uplift(value: u64, uplift_bps: u32) -> Result<u64, CostError> {
    let multiplier = BASIS_POINTS
        .checked_add(u128::from(uplift_bps))
        .ok_or(CostError::Overflow)?;
    let numerator = u128::from(value)
        .checked_mul(multiplier)
        .ok_or(CostError::Overflow)?;
    u64::try_from(checked_ceil_div(numerator, BASIS_POINTS)?).map_err(|_| CostError::Overflow)
}

fn checked_ceil_div(numerator: u128, denominator: u128) -> Result<u128, CostError> {
    if denominator == 0 {
        return Err(CostError::InvalidRateCard);
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or(CostError::Overflow)
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CostError {
    UnapprovedRateCard,
    ModelMismatch,
    InvalidRateCard,
    StaleRateCard,
    InvalidCacheWriteMultiplier,
    UnknownServiceTier,
    UnknownRegion,
    InvalidUsage,
    Overflow,
}

impl fmt::Display for CostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "cost calculation failed: {self:?}")
    }
}

impl Error for CostError {}
