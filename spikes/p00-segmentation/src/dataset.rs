use crate::contract::{
    InferenceMode, InferenceRequest, Mask, PixelBuffer, Rect, RequestHandle, TargetPersonContext,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

pub const GENERATOR_REVISION: &str = "seg-synth-v1-public-contract";
pub const CASE_COUNT: usize = 256;
pub const TRUTH_INSTANCE_COUNT: usize = 320;
pub const TARGET_POSITIVE_CASES: usize = 160;
pub const FULL_POSITIVE_CASES: usize = 64;
pub const TARGET_NEGATIVE_CASES: usize = 16;
pub const FULL_NEGATIVE_CASES: usize = 16;
pub const IMAGE_WIDTH: u32 = 1_024;
pub const IMAGE_HEIGHT: u32 = 1_024;
pub const MAX_TRUTHS_PER_CASE: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseScope {
    TargetPerson,
    FullImage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GarmentCategory {
    Top,
    Bottom,
    OnePiece,
    Outerwear,
    Layered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStratum {
    Standard,
    SmallVisibleArea,
    Occlusion,
    HolesThinStructures,
    LowContrast,
    PatternedBoundary,
    EdgeTruncation,
    MultiPersonOverlap,
    FlatLay,
    Isolated,
}

pub const ALL_STRATA: [ChallengeStratum; 10] = [
    ChallengeStratum::Standard,
    ChallengeStratum::SmallVisibleArea,
    ChallengeStratum::Occlusion,
    ChallengeStratum::HolesThinStructures,
    ChallengeStratum::LowContrast,
    ChallengeStratum::PatternedBoundary,
    ChallengeStratum::EdgeTruncation,
    ChallengeStratum::MultiPersonOverlap,
    ChallengeStratum::FlatLay,
    ChallengeStratum::Isolated,
];

const ALL_CATEGORIES: [GarmentCategory; 5] = [
    GarmentCategory::Top,
    GarmentCategory::Bottom,
    GarmentCategory::OnePiece,
    GarmentCategory::Outerwear,
    GarmentCategory::Layered,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthFixture {
    pub truth_index: usize,
    pub category: GarmentCategory,
    pub stratum: ChallengeStratum,
    pub rectangle: Rect,
}

impl TruthFixture {
    pub fn mask(&self) -> Mask {
        Mask::from_rect(IMAGE_WIDTH, IMAGE_HEIGHT, 1.0, self.rectangle)
            .expect("public fixture rectangles are valid")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticCase {
    pub ordinal: usize,
    pub scope: CaseScope,
    pub target_context: Option<Rect>,
    pub truths: Vec<TruthFixture>,
}

impl SyntheticCase {
    pub fn oracle_masks(&self) -> Vec<Mask> {
        self.truths.iter().map(TruthFixture::mask).collect()
    }

    pub fn provider_request(
        &self,
        request_handle: RequestHandle,
    ) -> Result<InferenceRequest, DatasetError> {
        let mode = match (self.scope, self.target_context) {
            (CaseScope::TargetPerson, Some(rectangle)) => InferenceMode::TargetPerson {
                context: TargetPersonContext {
                    rectangle,
                    person_mask: None,
                },
            },
            (CaseScope::FullImage, None) => InferenceMode::FullImage,
            _ => return Err(DatasetError::InvalidScopeContext),
        };
        let pixels = PixelBuffer::new(IMAGE_WIDTH, IMAGE_HEIGHT, self.generate_srgb())
            .map_err(|_| DatasetError::InvalidGeneratedPixels)?;
        InferenceRequest::new(request_handle, pixels, mode)
            .map_err(|_| DatasetError::InvalidGeneratedRequest)
    }

    pub fn generate_srgb(&self) -> Vec<u8> {
        let mut pixels = vec![236; IMAGE_WIDTH as usize * IMAGE_HEIGHT as usize * 3];
        for (fixture_index, truth) in self.truths.iter().enumerate() {
            let color = [
                31u8.wrapping_add((self.ordinal as u8).wrapping_mul(17)),
                67u8.wrapping_add((truth.truth_index as u8).wrapping_mul(29)),
                101u8.wrapping_add((fixture_index as u8).wrapping_mul(43)),
            ];
            for y in truth.rectangle.y..truth.rectangle.y + truth.rectangle.height {
                for x in truth.rectangle.x..truth.rectangle.x + truth.rectangle.width {
                    let offset = (y as usize * IMAGE_WIDTH as usize + x as usize) * 3;
                    pixels[offset..offset + 3].copy_from_slice(&color);
                }
            }
        }
        pixels
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticDataset {
    pub generator_revision: String,
    pub width: u32,
    pub height: u32,
    pub cases: Vec<SyntheticCase>,
}

impl SyntheticDataset {
    pub fn public_contract() -> Self {
        let mut truth_ordinal = 0usize;
        let mut cases = Vec::with_capacity(CASE_COUNT);
        for ordinal in 0..CASE_COUNT {
            let (scope, truth_count) = case_shape(ordinal);
            let target_context = (scope == CaseScope::TargetPerson).then_some(Rect {
                x: 128,
                y: 64,
                width: 768,
                height: 896,
            });
            let mut truths = Vec::with_capacity(truth_count);
            for local_index in 0..truth_count {
                truths.push(TruthFixture {
                    truth_index: local_index,
                    category: ALL_CATEGORIES[truth_ordinal % ALL_CATEGORIES.len()],
                    stratum: ALL_STRATA[truth_ordinal % ALL_STRATA.len()],
                    rectangle: fixture_rectangle(ordinal, local_index, scope),
                });
                truth_ordinal += 1;
            }
            cases.push(SyntheticCase {
                ordinal,
                scope,
                target_context,
                truths,
            });
        }
        let dataset = Self {
            generator_revision: GENERATOR_REVISION.into(),
            width: IMAGE_WIDTH,
            height: IMAGE_HEIGHT,
            cases,
        };
        debug_assert_eq!(dataset.validate(), Ok(()));
        dataset
    }

    pub fn validate(&self) -> Result<(), DatasetError> {
        if self.generator_revision != GENERATOR_REVISION {
            return Err(DatasetError::GeneratorRevision);
        }
        if self.width != IMAGE_WIDTH || self.height != IMAGE_HEIGHT {
            return Err(DatasetError::Dimensions);
        }
        if self.cases.len() != CASE_COUNT {
            return Err(DatasetError::CaseCount);
        }

        let mut scope_positive = BTreeMap::new();
        let mut scope_negative = BTreeMap::new();
        let mut strata = BTreeMap::new();
        let mut categories = BTreeMap::new();
        let mut truths = 0usize;

        for (ordinal, case) in self.cases.iter().enumerate() {
            if case.ordinal != ordinal || case.truths.len() > MAX_TRUTHS_PER_CASE {
                return Err(DatasetError::CaseShape);
            }
            match (case.scope, case.target_context) {
                (CaseScope::TargetPerson, Some(rectangle)) => {
                    rectangle
                        .validate_within(self.width, self.height)
                        .map_err(|_| DatasetError::InvalidScopeContext)?;
                }
                (CaseScope::FullImage, None) => {}
                _ => return Err(DatasetError::InvalidScopeContext),
            }
            let expected = case_shape(ordinal);
            if (case.scope, case.truths.len()) != expected {
                return Err(DatasetError::CaseShape);
            }
            let bucket = if case.truths.is_empty() {
                &mut scope_negative
            } else {
                &mut scope_positive
            };
            *bucket.entry(case.scope).or_insert(0usize) += 1;
            for (truth_index, truth) in case.truths.iter().enumerate() {
                if truth.truth_index != truth_index {
                    return Err(DatasetError::TruthIndex);
                }
                truth
                    .rectangle
                    .validate_within(self.width, self.height)
                    .map_err(|_| DatasetError::TruthRectangle)?;
                *strata.entry(truth.stratum).or_insert(0usize) += 1;
                *categories.entry(truth.category).or_insert(0usize) += 1;
                truths += 1;
            }
        }

        if truths != TRUTH_INSTANCE_COUNT {
            return Err(DatasetError::TruthCount);
        }
        if scope_positive.get(&CaseScope::TargetPerson) != Some(&TARGET_POSITIVE_CASES)
            || scope_positive.get(&CaseScope::FullImage) != Some(&FULL_POSITIVE_CASES)
            || scope_negative.get(&CaseScope::TargetPerson) != Some(&TARGET_NEGATIVE_CASES)
            || scope_negative.get(&CaseScope::FullImage) != Some(&FULL_NEGATIVE_CASES)
        {
            return Err(DatasetError::StrataCounts);
        }
        if ALL_STRATA
            .iter()
            .any(|stratum| strata.get(stratum) != Some(&(TRUTH_INSTANCE_COUNT / ALL_STRATA.len())))
            || ALL_CATEGORIES.iter().any(|category| {
                categories.get(category) != Some(&(TRUTH_INSTANCE_COUNT / ALL_CATEGORIES.len()))
            })
        {
            return Err(DatasetError::StrataCounts);
        }
        Ok(())
    }

    pub fn truth_instances(&self) -> usize {
        self.cases.iter().map(|case| case.truths.len()).sum()
    }

    pub fn provider_visible_hash_count(&self) -> usize {
        0
    }
}

fn case_shape(ordinal: usize) -> (CaseScope, usize) {
    match ordinal {
        0..=79 => (CaseScope::TargetPerson, 2),
        80..=159 => (CaseScope::TargetPerson, 1),
        160..=175 => (CaseScope::FullImage, 2),
        176..=223 => (CaseScope::FullImage, 1),
        224..=239 => (CaseScope::TargetPerson, 0),
        240..=255 => (CaseScope::FullImage, 0),
        _ => unreachable!("dataset ordinal is bounded"),
    }
}

fn fixture_rectangle(ordinal: usize, local_index: usize, scope: CaseScope) -> Rect {
    let variant = (ordinal * 13 + local_index * 7) as u32;
    let (base_x, base_y) = match (scope, local_index) {
        (CaseScope::TargetPerson, 0) => (224, 184),
        (CaseScope::TargetPerson, _) => (536, 480),
        (CaseScope::FullImage, 0) => (96, 128),
        (CaseScope::FullImage, _) => (592, 544),
    };
    Rect {
        x: base_x + variant % 24,
        y: base_y + (variant / 3) % 24,
        width: 176 + variant % 32,
        height: 224 + (variant / 5) % 32,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DatasetError {
    GeneratorRevision,
    Dimensions,
    CaseCount,
    TruthCount,
    CaseShape,
    TruthIndex,
    TruthRectangle,
    InvalidScopeContext,
    StrataCounts,
    InvalidGeneratedPixels,
    InvalidGeneratedRequest,
}

impl fmt::Display for DatasetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for DatasetError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_contract_has_exact_counts_and_strata() {
        let dataset = SyntheticDataset::public_contract();
        assert_eq!(dataset.validate(), Ok(()));
        assert_eq!(dataset.cases.len(), 256);
        assert_eq!(dataset.truth_instances(), 320);
        assert_eq!(dataset.provider_visible_hash_count(), 0);
        assert!(dataset
            .cases
            .iter()
            .all(|case| case.truths.len() <= MAX_TRUTHS_PER_CASE));
    }

    #[test]
    fn generated_pixels_and_oracles_are_deterministic_without_committed_images() {
        let dataset = SyntheticDataset::public_contract();
        let case = &dataset.cases[17];
        assert_eq!(case.generate_srgb(), case.generate_srgb());
        assert_eq!(case.oracle_masks(), case.oracle_masks());
        let request = case
            .provider_request(RequestHandle::parse("random-handle-001").unwrap())
            .unwrap();
        assert_eq!(request.pixels.width(), IMAGE_WIDTH);
        assert_eq!(request.pixels.height(), IMAGE_HEIGHT);
    }

    #[test]
    fn mutations_of_contract_fields_are_rejected() {
        let dataset = SyntheticDataset::public_contract();

        let mut changed = dataset.clone();
        changed.generator_revision.push_str("-mutated");
        assert_eq!(changed.validate(), Err(DatasetError::GeneratorRevision));

        let mut changed = dataset.clone();
        changed.cases.pop();
        assert_eq!(changed.validate(), Err(DatasetError::CaseCount));

        let mut changed = dataset.clone();
        changed.cases[0].truths.pop();
        assert_eq!(changed.validate(), Err(DatasetError::CaseShape));

        let mut changed = dataset;
        changed.cases[240].scope = CaseScope::TargetPerson;
        assert_eq!(changed.validate(), Err(DatasetError::InvalidScopeContext));
    }
}
