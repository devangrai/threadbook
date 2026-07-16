use crate::contract::{ContractError, Mask, MAX_PROVIDER_MASKS};
use crate::dataset::MAX_TRUTHS_PER_CASE;
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rational {
    numerator: u128,
    denominator: u128,
}

impl Rational {
    pub const ZERO: Self = Self {
        numerator: 0,
        denominator: 1,
    };

    pub fn new(numerator: u128, denominator: u128) -> Result<Self, MetricError> {
        if denominator == 0 {
            return Err(MetricError::ZeroDenominator);
        }
        let divisor = gcd(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    pub fn numerator(self) -> u128 {
        self.numerator
    }

    pub fn denominator(self) -> u128 {
        self.denominator
    }

    pub fn checked_add(self, other: Self) -> Result<Self, MetricError> {
        let common = gcd(self.denominator, other.denominator);
        let left_scale = other.denominator / common;
        let right_scale = self.denominator / common;
        let numerator = self
            .numerator
            .checked_mul(left_scale)
            .and_then(|left| {
                other
                    .numerator
                    .checked_mul(right_scale)
                    .and_then(|right| left.checked_add(right))
            })
            .ok_or(MetricError::ArithmeticOverflow)?;
        let denominator = self
            .denominator
            .checked_mul(left_scale)
            .ok_or(MetricError::ArithmeticOverflow)?;
        Self::new(numerator, denominator)
    }

    pub fn as_f64(self) -> f64 {
        self.numerator as f64 / self.denominator as f64
    }
}

impl Ord for Rational {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_fractions(
            self.numerator,
            self.denominator,
            other.numerator,
            other.denominator,
        )
    }
}

impl PartialOrd for Rational {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matching {
    pub pairs: Vec<(usize, usize)>,
    pub total_iou: Rational,
}

impl Matching {
    pub fn cardinality(&self) -> usize {
        self.pairs.len()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseScore {
    pub recall_matching: Matching,
    pub quality_assignment: Matching,
    pub truth_count: usize,
    pub prediction_count: usize,
}

pub fn exact_mask_iou(left: &Mask, right: &Mask) -> Result<Rational, MetricError> {
    left.validate().map_err(MetricError::InvalidMask)?;
    right.validate().map_err(MetricError::InvalidMask)?;
    if left.width != right.width || left.height != right.height {
        return Err(MetricError::DimensionMismatch);
    }
    let mut intersection = 0u128;
    let mut union = 0u128;
    for (left_byte, right_byte) in left.bits.iter().zip(&right.bits) {
        intersection += (left_byte & right_byte).count_ones() as u128;
        union += (left_byte | right_byte).count_ones() as u128;
    }
    Rational::new(intersection, union)
}

pub fn score_case(truths: &[Mask], predictions: &[Mask]) -> Result<CaseScore, MetricError> {
    if truths.len() > MAX_TRUTHS_PER_CASE || predictions.len() > MAX_PROVIDER_MASKS {
        return Err(MetricError::CardinalityBound);
    }
    validate_collection(truths)?;
    validate_collection(predictions)?;
    if let (Some(truth), Some(prediction)) = (truths.first(), predictions.first()) {
        if truth.width != prediction.width || truth.height != prediction.height {
            return Err(MetricError::DimensionMismatch);
        }
    }

    let matrix = build_matrix(truths, predictions)?;
    Ok(CaseScore {
        recall_matching: recall_matching_from_ious(&matrix)?,
        quality_assignment: max_total_iou_from_ious(&matrix)?,
        truth_count: truths.len(),
        prediction_count: predictions.len(),
    })
}

pub fn recall_matching_from_ious(matrix: &[Vec<Rational>]) -> Result<Matching, MetricError> {
    let prediction_count = validate_matrix(matrix)?;
    let target_max = matrix.len().min(prediction_count);
    let mut candidates = Vec::new();
    for cardinality in (0..=target_max).rev() {
        enumerate_matchings(
            matrix,
            Some(Rational::new(1, 2)?),
            cardinality,
            0,
            &mut vec![false; prediction_count],
            &mut Vec::new(),
            Rational::ZERO,
            &mut candidates,
        )?;
        if !candidates.is_empty() {
            break;
        }
    }
    select_best(candidates)
}

pub fn max_total_iou_from_ious(matrix: &[Vec<Rational>]) -> Result<Matching, MetricError> {
    let prediction_count = validate_matrix(matrix)?;
    let cardinality = matrix.len().min(prediction_count);
    let mut candidates = Vec::new();
    enumerate_matchings(
        matrix,
        None,
        cardinality,
        0,
        &mut vec![false; prediction_count],
        &mut Vec::new(),
        Rational::ZERO,
        &mut candidates,
    )?;
    select_best(candidates)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregateMetrics {
    pub cases: usize,
    pub truths: usize,
    pub emitted_masks: usize,
    pub recall_matches: usize,
    pub quality_iou_sum: Rational,
    pub negative_cases: usize,
    pub negative_cases_with_masks: usize,
    pub processing_failures: usize,
}

impl AggregateMetrics {
    pub fn recall(&self) -> Rational {
        ratio_or(self.recall_matches, self.truths, Rational::ZERO)
    }

    pub fn precision(&self) -> Rational {
        ratio_or(
            self.recall_matches,
            self.emitted_masks,
            Rational::new(1, 1).expect("constant denominator"),
        )
    }

    pub fn mean_iou(&self) -> Rational {
        if self.truths == 0 {
            return Rational::ZERO;
        }
        Rational::new(
            self.quality_iou_sum.numerator,
            self.quality_iou_sum.denominator * self.truths as u128,
        )
        .expect("bounded metric denominator")
    }

    pub fn unmatched_predictions(&self) -> usize {
        self.emitted_masks.saturating_sub(self.recall_matches)
    }

    pub fn negative_false_positive_rate(&self) -> Rational {
        ratio_or(
            self.negative_cases_with_masks,
            self.negative_cases,
            Rational::ZERO,
        )
    }

    pub fn evaluate_automatic_gates(&self) -> GateReport {
        let recall = self.recall();
        let precision = self.precision();
        let mean_iou = self.mean_iou();
        let negative_false_positive_rate = self.negative_false_positive_rate();
        GateReport {
            recall_pass: recall >= Rational::new(85, 100).expect("constant"),
            precision_pass: precision >= Rational::new(80, 100).expect("constant"),
            mean_iou_pass: mean_iou >= Rational::new(65, 100).expect("constant"),
            unmatched_predictions_pass: self
                .unmatched_predictions()
                .checked_mul(4)
                .is_some_and(|unmatched| unmatched <= self.cases),
            negative_false_positive_pass: negative_false_positive_rate
                <= Rational::new(5, 100).expect("constant"),
            failure_rate_pass: self
                .processing_failures
                .checked_mul(100)
                .is_some_and(|failures| failures <= self.cases),
            recall,
            precision,
            mean_iou,
            negative_false_positive_rate,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateReport {
    pub recall_pass: bool,
    pub precision_pass: bool,
    pub mean_iou_pass: bool,
    pub unmatched_predictions_pass: bool,
    pub negative_false_positive_pass: bool,
    pub failure_rate_pass: bool,
    pub recall: Rational,
    pub precision: Rational,
    pub mean_iou: Rational,
    pub negative_false_positive_rate: Rational,
}

impl GateReport {
    pub fn passes(&self) -> bool {
        self.recall_pass
            && self.precision_pass
            && self.mean_iou_pass
            && self.unmatched_predictions_pass
            && self.negative_false_positive_pass
            && self.failure_rate_pass
    }
}

fn build_matrix(truths: &[Mask], predictions: &[Mask]) -> Result<Vec<Vec<Rational>>, MetricError> {
    truths
        .iter()
        .map(|truth| {
            predictions
                .iter()
                .map(|prediction| exact_mask_iou(truth, prediction))
                .collect()
        })
        .collect()
}

fn validate_collection(masks: &[Mask]) -> Result<(), MetricError> {
    for (index, mask) in masks.iter().enumerate() {
        mask.validate().map_err(MetricError::InvalidMask)?;
        if masks[..index].iter().any(|prior| prior.bits == mask.bits) {
            return Err(MetricError::DuplicateMask);
        }
    }
    Ok(())
}

fn validate_matrix(matrix: &[Vec<Rational>]) -> Result<usize, MetricError> {
    if matrix.len() > MAX_TRUTHS_PER_CASE {
        return Err(MetricError::CardinalityBound);
    }
    let prediction_count = matrix.first().map_or(0, Vec::len);
    if prediction_count > MAX_PROVIDER_MASKS
        || matrix.iter().any(|row| row.len() != prediction_count)
    {
        return Err(MetricError::MalformedMatrix);
    }
    Ok(prediction_count)
}

#[allow(clippy::too_many_arguments)]
fn enumerate_matchings(
    matrix: &[Vec<Rational>],
    threshold: Option<Rational>,
    target_cardinality: usize,
    truth_index: usize,
    used_predictions: &mut [bool],
    pairs: &mut Vec<(usize, usize)>,
    total: Rational,
    candidates: &mut Vec<Matching>,
) -> Result<(), MetricError> {
    if pairs.len() > target_cardinality {
        return Ok(());
    }
    if truth_index == matrix.len() {
        if pairs.len() == target_cardinality {
            candidates.push(Matching {
                pairs: pairs.clone(),
                total_iou: total,
            });
        }
        return Ok(());
    }
    let remaining_truths = matrix.len() - truth_index;
    if pairs.len() + remaining_truths < target_cardinality {
        return Ok(());
    }

    if pairs.len() + remaining_truths > target_cardinality {
        enumerate_matchings(
            matrix,
            threshold,
            target_cardinality,
            truth_index + 1,
            used_predictions,
            pairs,
            total,
            candidates,
        )?;
    }
    for prediction_index in 0..used_predictions.len() {
        let iou = matrix[truth_index][prediction_index];
        if used_predictions[prediction_index] || threshold.is_some_and(|minimum| iou < minimum) {
            continue;
        }
        used_predictions[prediction_index] = true;
        pairs.push((truth_index, prediction_index));
        enumerate_matchings(
            matrix,
            threshold,
            target_cardinality,
            truth_index + 1,
            used_predictions,
            pairs,
            total.checked_add(iou)?,
            candidates,
        )?;
        pairs.pop();
        used_predictions[prediction_index] = false;
    }
    Ok(())
}

fn select_best(mut candidates: Vec<Matching>) -> Result<Matching, MetricError> {
    if candidates.is_empty() {
        return Err(MetricError::NoAssignment);
    }
    candidates.sort_by(|left, right| {
        right
            .total_iou
            .cmp(&left.total_iou)
            .then_with(|| left.pairs.cmp(&right.pairs))
    });
    Ok(candidates.remove(0))
}

fn ratio_or(numerator: usize, denominator: usize, default: Rational) -> Rational {
    if denominator == 0 {
        default
    } else {
        Rational::new(numerator as u128, denominator as u128).expect("nonzero usize denominator")
    }
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left.max(1)
}

fn compare_fractions(
    mut left_numerator: u128,
    mut left_denominator: u128,
    mut right_numerator: u128,
    mut right_denominator: u128,
) -> Ordering {
    let mut reversed = false;
    loop {
        let left_integer = left_numerator / left_denominator;
        let right_integer = right_numerator / right_denominator;
        if left_integer != right_integer {
            let order = left_integer.cmp(&right_integer);
            return if reversed { order.reverse() } else { order };
        }

        let left_remainder = left_numerator % left_denominator;
        let right_remainder = right_numerator % right_denominator;
        match (left_remainder == 0, right_remainder == 0) {
            (true, true) => return Ordering::Equal,
            (true, false) => {
                return if reversed {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (false, true) => {
                return if reversed {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (false, false) => {
                left_numerator = left_denominator;
                left_denominator = left_remainder;
                right_numerator = right_denominator;
                right_denominator = right_remainder;
                reversed = !reversed;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetricError {
    InvalidMask(ContractError),
    DimensionMismatch,
    DuplicateMask,
    CardinalityBound,
    MalformedMatrix,
    ZeroDenominator,
    ArithmeticOverflow,
    NoAssignment,
}

impl fmt::Display for MetricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for MetricError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::Rect;

    fn r(numerator: u128, denominator: u128) -> Rational {
        Rational::new(numerator, denominator).unwrap()
    }

    #[test]
    fn computes_exact_mask_iou() {
        let left = Mask::from_rect(
            4,
            1,
            1.0,
            Rect {
                x: 0,
                y: 0,
                width: 3,
                height: 1,
            },
        )
        .unwrap();
        let right = Mask::from_rect(
            4,
            1,
            1.0,
            Rect {
                x: 1,
                y: 0,
                width: 3,
                height: 1,
            },
        )
        .unwrap();
        assert_eq!(exact_mask_iou(&left, &right).unwrap(), r(1, 2));
    }

    #[test]
    fn recall_maximizes_cardinality_before_total_iou() {
        let matrix = vec![vec![r(3, 5), r(1, 2)], vec![r(1, 2), r(0, 1)]];
        let matching = recall_matching_from_ious(&matrix).unwrap();
        assert_eq!(matching.pairs, vec![(0, 1), (1, 0)]);
        assert_eq!(matching.total_iou, r(1, 1));
    }

    #[test]
    fn quality_uses_separate_max_total_assignment() {
        let matrix = vec![vec![r(9, 10), r(8, 10)], vec![r(8, 10), r(1, 10)]];
        let matching = max_total_iou_from_ious(&matrix).unwrap();
        assert_eq!(matching.pairs, vec![(0, 1), (1, 0)]);
        assert_eq!(matching.total_iou, r(8, 5));
    }

    #[test]
    fn exact_threshold_and_lexical_ties_are_stable() {
        let matrix = vec![vec![r(1, 2), r(1, 2)], vec![r(1, 2), r(1, 2)]];
        assert_eq!(
            recall_matching_from_ious(&matrix).unwrap().pairs,
            vec![(0, 0), (1, 1)]
        );
        let below = vec![vec![r(499_999, 1_000_000)]];
        assert_eq!(recall_matching_from_ious(&below).unwrap().cardinality(), 0);
    }

    #[test]
    fn rational_comparison_does_not_overflow_cross_products() {
        let large = r(u128::MAX - 2, u128::MAX - 1);
        let smaller = r(u128::MAX - 3, u128::MAX - 2);
        assert!(large > smaller);
    }

    #[test]
    fn quality_and_precision_thresholds_are_inclusive_but_flooding_is_rejected() {
        let at_boundary = AggregateMetrics {
            cases: 100,
            truths: 100,
            emitted_masks: 100,
            recall_matches: 85,
            quality_iou_sum: r(65, 1),
            negative_cases: 20,
            negative_cases_with_masks: 1,
            processing_failures: 1,
        };
        let report = at_boundary.evaluate_automatic_gates();
        assert!(report.recall_pass);
        assert!(report.precision_pass);
        assert!(report.mean_iou_pass);
        assert!(report.negative_false_positive_pass);
        assert!(report.failure_rate_pass);

        let flooded = AggregateMetrics {
            emitted_masks: 126,
            ..at_boundary
        };
        let report = flooded.evaluate_automatic_gates();
        assert!(!report.unmatched_predictions_pass);
        assert!(!report.precision_pass);
        assert!(!report.passes());
    }

    #[test]
    fn zero_prediction_precision_is_one_but_recall_fails() {
        let metrics = AggregateMetrics {
            cases: 1,
            truths: 1,
            emitted_masks: 0,
            recall_matches: 0,
            quality_iou_sum: Rational::ZERO,
            negative_cases: 0,
            negative_cases_with_masks: 0,
            processing_failures: 0,
        };
        assert_eq!(metrics.precision(), r(1, 1));
        assert!(!metrics.evaluate_automatic_gates().recall_pass);
    }
}
