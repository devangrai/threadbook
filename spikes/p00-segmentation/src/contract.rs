use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

pub const CONTRACT_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROVIDER_MASKS: usize = 8;
pub const MAX_MASKS: usize = MAX_PROVIDER_MASKS;
pub const MAX_PIXELS: u64 = 40_000_000;
pub const MAX_AXIS: u32 = 8_192;
pub const MAX_DEADLINE_MS: u64 = 10_000;
pub const MAX_INTERACTIVE_POINTS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn validate_within(&self, width: u32, height: u32) -> Result<(), ContractError> {
        if self.width == 0 || self.height == 0 {
            return Err(ContractError::EmptyRectangle);
        }
        let right = self
            .x
            .checked_add(self.width)
            .ok_or(ContractError::DimensionOverflow)?;
        let bottom = self
            .y
            .checked_add(self.height)
            .ok_or(ContractError::DimensionOverflow)?;
        if right > width || bottom > height {
            return Err(ContractError::RectangleOutOfBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PixelBuffer {
    width: u32,
    height: u32,
    srgb: Vec<u8>,
}

impl PixelBuffer {
    pub fn new(width: u32, height: u32, srgb: Vec<u8>) -> Result<Self, ContractError> {
        let pixels = checked_pixels(width, height)?;
        let expected = pixels
            .checked_mul(3)
            .ok_or(ContractError::DimensionOverflow)?;
        let expected = usize::try_from(expected).map_err(|_| ContractError::DimensionOverflow)?;
        if srgb.len() != expected {
            return Err(ContractError::PixelLength {
                expected,
                actual: srgb.len(),
            });
        }
        Ok(Self {
            width,
            height,
            srgb,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn as_srgb(&self) -> &[u8] {
        &self.srgb
    }

    pub fn into_srgb(self) -> Vec<u8> {
        self.srgb
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestHandle(String);

impl RequestHandle {
    pub fn parse(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        if !(16..=64).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b'\\')
        {
            return Err(ContractError::InvalidRequestHandle);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TargetPersonContext {
    pub rectangle: Rect,
    pub person_mask: Option<Mask>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PromptPoint {
    pub x: u32,
    pub y: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum InferenceMode {
    FullImage,
    TargetPerson {
        context: TargetPersonContext,
    },
    Interactive {
        user_box: Rect,
        positive_points: Vec<PromptPoint>,
        negative_points: Vec<PromptPoint>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct InferenceRequest {
    pub schema_version: u32,
    pub request_handle: RequestHandle,
    pub pixels: PixelBuffer,
    pub mode: InferenceMode,
}

impl InferenceRequest {
    pub fn new(
        request_handle: RequestHandle,
        pixels: PixelBuffer,
        mode: InferenceMode,
    ) -> Result<Self, ContractError> {
        let request = Self {
            schema_version: CONTRACT_SCHEMA_VERSION,
            request_handle,
            pixels,
            mode,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchema(self.schema_version));
        }
        let width = self.pixels.width();
        let height = self.pixels.height();
        match &self.mode {
            InferenceMode::FullImage => {}
            InferenceMode::TargetPerson { context } => {
                context.rectangle.validate_within(width, height)?;
                if let Some(mask) = &context.person_mask {
                    mask.validate_dimensions(width, height)?;
                }
            }
            InferenceMode::Interactive {
                user_box,
                positive_points,
                negative_points,
            } => {
                user_box.validate_within(width, height)?;
                if positive_points.len() + negative_points.len() > MAX_INTERACTIVE_POINTS {
                    return Err(ContractError::TooManyPromptPoints);
                }
                for point in positive_points.iter().chain(negative_points) {
                    if point.x >= width || point.y >= height {
                        return Err(ContractError::PromptPointOutOfBounds);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mask {
    pub width: u32,
    pub height: u32,
    pub confidence: f64,
    pub bits: Vec<u8>,
}

impl Mask {
    pub fn new(
        width: u32,
        height: u32,
        confidence: f64,
        bits: Vec<u8>,
    ) -> Result<Self, ContractError> {
        let mask = Self {
            width,
            height,
            confidence,
            bits,
        };
        mask.validate()?;
        Ok(mask)
    }

    pub fn from_rect(
        width: u32,
        height: u32,
        confidence: f64,
        rectangle: Rect,
    ) -> Result<Self, ContractError> {
        rectangle.validate_within(width, height)?;
        let pixels = checked_pixels(width, height)?;
        let byte_len = packed_len(pixels)?;
        let mut bits = vec![0; byte_len];
        for y in rectangle.y..rectangle.y + rectangle.height {
            for x in rectangle.x..rectangle.x + rectangle.width {
                let index = u64::from(y) * u64::from(width) + u64::from(x);
                set_bit(&mut bits, index);
            }
        }
        Self::new(width, height, confidence, bits)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let pixels = checked_pixels(self.width, self.height)?;
        let expected = packed_len(pixels)?;
        if self.bits.len() != expected {
            return Err(ContractError::MaskLength {
                expected,
                actual: self.bits.len(),
            });
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Err(ContractError::InvalidConfidence);
        }
        if pixels % 8 != 0 {
            let used = (pixels % 8) as u8;
            let unused_mask = !((1u8 << used) - 1);
            if self.bits.last().copied().unwrap_or_default() & unused_mask != 0 {
                return Err(ContractError::NonCanonicalTailBits);
            }
        }
        if self.area() == 0 {
            return Err(ContractError::EmptyMask);
        }
        Ok(())
    }

    pub fn validate_dimensions(&self, width: u32, height: u32) -> Result<(), ContractError> {
        self.validate()?;
        if self.width != width || self.height != height {
            return Err(ContractError::MaskDimensionMismatch);
        }
        Ok(())
    }

    pub fn area(&self) -> u64 {
        self.bits
            .iter()
            .map(|byte| u64::from(byte.count_ones()))
            .sum()
    }

    pub fn contains(&self, x: u32, y: u32) -> bool {
        if x >= self.width || y >= self.height {
            return false;
        }
        let index = u64::from(y) * u64::from(self.width) + u64::from(x);
        bit(&self.bits, index)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deadline {
    milliseconds: u64,
}

impl Deadline {
    pub fn from_millis(milliseconds: u64) -> Result<Self, ContractError> {
        if milliseconds == 0 || milliseconds > MAX_DEADLINE_MS {
            return Err(ContractError::InvalidDeadline);
        }
        Ok(Self { milliseconds })
    }

    pub fn as_millis(self) -> u64 {
        self.milliseconds
    }
}

#[derive(Debug, Default)]
pub struct Cancellation(AtomicBool);

impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputePolicy {
    CpuOnly,
    CpuAndGpu,
    All,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub schema_version: u32,
    pub provider_id: String,
    pub revision: String,
    pub backend: String,
    pub maximum_output_cardinality: usize,
    pub model_hash: Option<String>,
    pub runtime_hash: String,
    pub adapter_hash: String,
    pub preprocess_hash: String,
    pub postprocess_hash: String,
    pub sandbox_profile_hash: String,
    pub license_approval_id: Option<String>,
}

impl ProviderDescriptor {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedSchema(self.schema_version));
        }
        for value in [
            &self.provider_id,
            &self.revision,
            &self.backend,
            &self.runtime_hash,
            &self.adapter_hash,
            &self.preprocess_hash,
            &self.postprocess_hash,
            &self.sandbox_profile_hash,
        ] {
            if value.is_empty() {
                return Err(ContractError::EmptyDescriptorField);
            }
        }
        if self.maximum_output_cardinality == 0 || self.maximum_output_cardinality > MAX_MASKS {
            return Err(ContractError::TooManyMasks);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedLocalPack {
    pub inventory_hash: String,
    pub root_is_read_only: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProviderPreparation {
    Ready,
    Unavailable { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Decode,
    Model,
    Output,
    Deadline,
    Resource,
    Sandbox,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum SegmentationOutcome {
    Masks { masks: Vec<Mask> },
    NoGarment,
    FallbackMask { mask: Mask, needs_review: bool },
    FallbackCrop { rectangle: Rect, needs_review: bool },
    Unavailable { reason: String },
    Cancelled,
    Failed { kind: FailureKind, detail: String },
}

pub fn validate_outcome(
    outcome: &SegmentationOutcome,
    request: &InferenceRequest,
) -> Result<(), ContractError> {
    request.validate()?;
    match outcome {
        SegmentationOutcome::Masks { masks } => {
            if masks.is_empty() {
                return Err(ContractError::ZeroMaskOutcome);
            }
            if masks.len() > MAX_PROVIDER_MASKS {
                return Err(ContractError::TooManyMasks);
            }
            for (index, mask) in masks.iter().enumerate() {
                mask.validate_dimensions(request.pixels.width(), request.pixels.height())?;
                if masks[..index].iter().any(|prior| prior.bits == mask.bits) {
                    return Err(ContractError::DuplicateMask);
                }
            }
        }
        SegmentationOutcome::FallbackMask { mask, needs_review } => {
            if !needs_review {
                return Err(ContractError::FallbackReviewRequired);
            }
            mask.validate_dimensions(request.pixels.width(), request.pixels.height())?;
        }
        SegmentationOutcome::FallbackCrop {
            rectangle,
            needs_review,
        } => {
            if !needs_review {
                return Err(ContractError::FallbackReviewRequired);
            }
            rectangle.validate_within(request.pixels.width(), request.pixels.height())?;
        }
        SegmentationOutcome::Unavailable { reason }
        | SegmentationOutcome::Failed { detail: reason, .. } => {
            if reason.is_empty() {
                return Err(ContractError::EmptyOutcomeReason);
            }
        }
        SegmentationOutcome::NoGarment | SegmentationOutcome::Cancelled => {}
    }
    Ok(())
}

pub trait GarmentSegmentationProvider {
    fn describe(&self) -> ProviderDescriptor;
    fn prepare(&mut self, pack: &VerifiedLocalPack, policy: ComputePolicy) -> ProviderPreparation;
    fn segment(
        &mut self,
        request: &InferenceRequest,
        deadline: Deadline,
        cancellation: &Cancellation,
    ) -> SegmentationOutcome;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractError {
    UnsupportedSchema(u32),
    EmptyDimensions,
    AxisTooLarge,
    TooManyPixels,
    DimensionOverflow,
    PixelLength { expected: usize, actual: usize },
    EmptyRectangle,
    RectangleOutOfBounds,
    InvalidRequestHandle,
    TooManyPromptPoints,
    PromptPointOutOfBounds,
    MaskLength { expected: usize, actual: usize },
    InvalidConfidence,
    NonCanonicalTailBits,
    EmptyMask,
    MaskDimensionMismatch,
    InvalidDeadline,
    EmptyDescriptorField,
    ZeroMaskOutcome,
    TooManyMasks,
    DuplicateMask,
    FallbackReviewRequired,
    EmptyOutcomeReason,
}

impl fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ContractError {}

fn checked_pixels(width: u32, height: u32) -> Result<u64, ContractError> {
    if width == 0 || height == 0 {
        return Err(ContractError::EmptyDimensions);
    }
    if width > MAX_AXIS || height > MAX_AXIS {
        return Err(ContractError::AxisTooLarge);
    }
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ContractError::DimensionOverflow)?;
    if pixels > MAX_PIXELS {
        return Err(ContractError::TooManyPixels);
    }
    Ok(pixels)
}

fn packed_len(pixels: u64) -> Result<usize, ContractError> {
    let bytes = pixels
        .checked_add(7)
        .ok_or(ContractError::DimensionOverflow)?
        / 8;
    usize::try_from(bytes).map_err(|_| ContractError::DimensionOverflow)
}

fn bit(bits: &[u8], index: u64) -> bool {
    bits[(index / 8) as usize] & (1 << (index % 8)) != 0
}

fn set_bit(bits: &mut [u8], index: u64) {
    bits[(index / 8) as usize] |= 1 << (index % 8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> InferenceRequest {
        InferenceRequest::new(
            RequestHandle::parse("request-handle-01").unwrap(),
            PixelBuffer::new(4, 4, vec![0; 48]).unwrap(),
            InferenceMode::FullImage,
        )
        .unwrap()
    }

    #[test]
    fn rejects_malicious_dimensions_before_buffer_length() {
        assert_eq!(
            PixelBuffer::new(u32::MAX, 2, Vec::new()),
            Err(ContractError::AxisTooLarge)
        );
        assert_eq!(
            PixelBuffer::new(8_192, 8_192, Vec::new()),
            Err(ContractError::TooManyPixels)
        );
        assert!(matches!(
            PixelBuffer::new(4, 4, vec![0; 47]),
            Err(ContractError::PixelLength { .. })
        ));
    }

    #[test]
    fn rejects_noncanonical_and_empty_masks() {
        assert_eq!(
            Mask::new(3, 3, 1.0, vec![0, 0]),
            Err(ContractError::EmptyMask)
        );
        assert_eq!(
            Mask::new(3, 3, 1.0, vec![1, 0b1000_0000]),
            Err(ContractError::NonCanonicalTailBits)
        );
        assert_eq!(
            Mask::new(1, 1, f64::NAN, vec![1]),
            Err(ContractError::InvalidConfidence)
        );
        assert_eq!(
            Mask::new(1, 1, f64::INFINITY, vec![1]),
            Err(ContractError::InvalidConfidence)
        );
    }

    #[test]
    fn validates_all_outcome_shapes() {
        let request = request();
        let mask = Mask::from_rect(
            4,
            4,
            0.9,
            Rect {
                x: 1,
                y: 1,
                width: 2,
                height: 2,
            },
        )
        .unwrap();
        let outcomes = [
            SegmentationOutcome::Masks { masks: vec![mask] },
            SegmentationOutcome::NoGarment,
            SegmentationOutcome::FallbackMask {
                mask: Mask::from_rect(
                    4,
                    4,
                    1.0,
                    Rect {
                        x: 1,
                        y: 1,
                        width: 2,
                        height: 2,
                    },
                )
                .unwrap(),
                needs_review: true,
            },
            SegmentationOutcome::FallbackCrop {
                rectangle: Rect {
                    x: 0,
                    y: 0,
                    width: 4,
                    height: 4,
                },
                needs_review: true,
            },
            SegmentationOutcome::Unavailable {
                reason: "not supported".into(),
            },
            SegmentationOutcome::Cancelled,
            SegmentationOutcome::Failed {
                kind: FailureKind::Model,
                detail: "model rejected input".into(),
            },
        ];
        for outcome in outcomes {
            validate_outcome(&outcome, &request).unwrap();
        }
    }

    #[test]
    fn accepts_eight_provider_masks_and_rejects_nine() {
        let request = request();
        let masks = (0..9)
            .map(|index| {
                Mask::from_rect(
                    4,
                    4,
                    1.0,
                    Rect {
                        x: index % 4,
                        y: index / 4,
                        width: 1,
                        height: 1,
                    },
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        assert_eq!(MAX_PROVIDER_MASKS, 8);
        assert_eq!(
            validate_outcome(
                &SegmentationOutcome::Masks {
                    masks: masks[..8].to_vec(),
                },
                &request,
            ),
            Ok(())
        );
        assert_eq!(
            validate_outcome(&SegmentationOutcome::Masks { masks }, &request),
            Err(ContractError::TooManyMasks)
        );
    }

    #[test]
    fn rejects_zero_duplicate_and_wrong_size_masks() {
        let request = request();
        let mask = Mask::from_rect(
            4,
            4,
            1.0,
            Rect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
        )
        .unwrap();
        assert_eq!(
            validate_outcome(&SegmentationOutcome::Masks { masks: Vec::new() }, &request),
            Err(ContractError::ZeroMaskOutcome)
        );
        assert_eq!(
            validate_outcome(
                &SegmentationOutcome::Masks {
                    masks: vec![mask.clone(), mask]
                },
                &request
            ),
            Err(ContractError::DuplicateMask)
        );
        let wrong = Mask::from_rect(
            2,
            2,
            1.0,
            Rect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
        )
        .unwrap();
        assert_eq!(
            validate_outcome(&SegmentationOutcome::Masks { masks: vec![wrong] }, &request),
            Err(ContractError::MaskDimensionMismatch)
        );
    }

    #[test]
    fn rejects_fallback_results_without_review() {
        let request = request();
        let mask = Mask::from_rect(
            4,
            4,
            1.0,
            Rect {
                x: 1,
                y: 1,
                width: 2,
                height: 2,
            },
        )
        .unwrap();
        assert_eq!(
            validate_outcome(
                &SegmentationOutcome::FallbackMask {
                    mask,
                    needs_review: false,
                },
                &request,
            ),
            Err(ContractError::FallbackReviewRequired)
        );
        assert_eq!(
            validate_outcome(
                &SegmentationOutcome::FallbackCrop {
                    rectangle: Rect {
                        x: 0,
                        y: 0,
                        width: 4,
                        height: 4,
                    },
                    needs_review: false,
                },
                &request,
            ),
            Err(ContractError::FallbackReviewRequired)
        );
    }

    #[test]
    fn bounds_deadline_rectangles_handles_and_prompts() {
        assert_eq!(
            Deadline::from_millis(0),
            Err(ContractError::InvalidDeadline)
        );
        assert_eq!(
            Deadline::from_millis(MAX_DEADLINE_MS).unwrap().as_millis(),
            10_000
        );
        assert_eq!(
            Deadline::from_millis(MAX_DEADLINE_MS + 1),
            Err(ContractError::InvalidDeadline)
        );
        assert!(RequestHandle::parse("../hidden/label").is_err());
        assert_eq!(
            Rect {
                x: u32::MAX,
                y: 0,
                width: 2,
                height: 1
            }
            .validate_within(10, 10),
            Err(ContractError::DimensionOverflow)
        );
    }
}
