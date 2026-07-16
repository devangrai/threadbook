use crate::contract::{ContractError, Mask, PixelBuffer, Rect, SegmentationOutcome};
use std::collections::VecDeque;
use std::error::Error;
use std::fmt;

pub const FALLBACK_ID: &str = "rectangle_uniform_background_v1";

pub fn rectangle_uniform_background_v1(pixels: &PixelBuffer) -> SegmentationOutcome {
    let uniform = UniformBackgroundFallback::new(UniformBackgroundConfig::default())
        .expect("default fallback configuration is valid");
    match uniform.segment(pixels) {
        UniformBackgroundResult::Mask(mask) => SegmentationOutcome::FallbackMask {
            mask,
            needs_review: true,
        },
        UniformBackgroundResult::Unavailable(_) => RectangleFallback::source_image(pixels),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RectangleFallback;

impl RectangleFallback {
    pub fn confirmed_crop(
        pixels: &PixelBuffer,
        rectangle: Rect,
    ) -> Result<SegmentationOutcome, FallbackError> {
        rectangle
            .validate_within(pixels.width(), pixels.height())
            .map_err(FallbackError::Contract)?;
        Ok(SegmentationOutcome::FallbackCrop {
            rectangle,
            needs_review: true,
        })
    }

    pub fn source_image(pixels: &PixelBuffer) -> SegmentationOutcome {
        SegmentationOutcome::FallbackCrop {
            rectangle: Rect {
                x: 0,
                y: 0,
                width: pixels.width(),
                height: pixels.height(),
            },
            needs_review: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UniformBackgroundConfig {
    pub channel_tolerance: u8,
    pub minimum_foreground_permyriad: u16,
    pub maximum_foreground_permyriad: u16,
}

impl Default for UniformBackgroundConfig {
    fn default() -> Self {
        Self {
            channel_tolerance: 12,
            minimum_foreground_permyriad: 100,
            maximum_foreground_permyriad: 8_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum UniformBackgroundResult {
    Mask(Mask),
    Unavailable(UniformUnavailable),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniformUnavailable {
    InvalidConfiguration,
    NonUniformCorners,
    NoForeground,
    ForegroundArea,
    ForegroundTouchesEdge,
    MultipleForegroundComponents,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UniformBackgroundFallback {
    config: UniformBackgroundConfig,
}

impl UniformBackgroundFallback {
    pub fn new(config: UniformBackgroundConfig) -> Result<Self, FallbackError> {
        if config.minimum_foreground_permyriad == 0
            || config.minimum_foreground_permyriad >= config.maximum_foreground_permyriad
            || config.maximum_foreground_permyriad > 10_000
        {
            return Err(FallbackError::InvalidConfiguration);
        }
        Ok(Self { config })
    }

    pub fn segment(&self, pixels: &PixelBuffer) -> UniformBackgroundResult {
        let width = pixels.width() as usize;
        let height = pixels.height() as usize;
        let corners = [
            rgb(pixels, 0, 0),
            rgb(pixels, width - 1, 0),
            rgb(pixels, 0, height - 1),
            rgb(pixels, width - 1, height - 1),
        ];
        let background = [
            (corners.iter().map(|color| u16::from(color[0])).sum::<u16>() / 4) as u8,
            (corners.iter().map(|color| u16::from(color[1])).sum::<u16>() / 4) as u8,
            (corners.iter().map(|color| u16::from(color[2])).sum::<u16>() / 4) as u8,
        ];
        if corners
            .iter()
            .any(|color| !within(*color, background, self.config.channel_tolerance))
        {
            return UniformBackgroundResult::Unavailable(UniformUnavailable::NonUniformCorners);
        }

        let mut background_pixels = vec![false; width * height];
        let mut queue = VecDeque::new();
        for x in 0..width {
            enqueue_background(
                pixels,
                background,
                self.config.channel_tolerance,
                x,
                0,
                width,
                &mut background_pixels,
                &mut queue,
            );
            enqueue_background(
                pixels,
                background,
                self.config.channel_tolerance,
                x,
                height - 1,
                width,
                &mut background_pixels,
                &mut queue,
            );
        }
        for y in 0..height {
            enqueue_background(
                pixels,
                background,
                self.config.channel_tolerance,
                0,
                y,
                width,
                &mut background_pixels,
                &mut queue,
            );
            enqueue_background(
                pixels,
                background,
                self.config.channel_tolerance,
                width - 1,
                y,
                width,
                &mut background_pixels,
                &mut queue,
            );
        }
        while let Some((x, y)) = queue.pop_front() {
            for (next_x, next_y) in neighbors(x, y, width, height) {
                enqueue_background(
                    pixels,
                    background,
                    self.config.channel_tolerance,
                    next_x,
                    next_y,
                    width,
                    &mut background_pixels,
                    &mut queue,
                );
            }
        }

        let foreground_count = background_pixels.iter().filter(|value| !**value).count();
        if foreground_count == 0 {
            return UniformBackgroundResult::Unavailable(UniformUnavailable::NoForeground);
        }
        let total = width * height;
        let scaled = foreground_count * 10_000;
        if scaled < total * usize::from(self.config.minimum_foreground_permyriad)
            || scaled > total * usize::from(self.config.maximum_foreground_permyriad)
        {
            return UniformBackgroundResult::Unavailable(UniformUnavailable::ForegroundArea);
        }
        if (0..width).any(|x| !background_pixels[x] || !background_pixels[(height - 1) * width + x])
            || (0..height)
                .any(|y| !background_pixels[y * width] || !background_pixels[y * width + width - 1])
        {
            return UniformBackgroundResult::Unavailable(UniformUnavailable::ForegroundTouchesEdge);
        }
        if foreground_components(&background_pixels, width, height) != 1 {
            return UniformBackgroundResult::Unavailable(
                UniformUnavailable::MultipleForegroundComponents,
            );
        }

        let mut bits = vec![0u8; total.div_ceil(8)];
        for (index, is_background) in background_pixels.iter().enumerate() {
            if !is_background {
                bits[index / 8] |= 1 << (index % 8);
            }
        }
        let mask = Mask::new(pixels.width(), pixels.height(), 1.0, bits)
            .expect("validated foreground always forms a canonical nonempty mask");
        UniformBackgroundResult::Mask(mask)
    }
}

fn rgb(pixels: &PixelBuffer, x: usize, y: usize) -> [u8; 3] {
    let offset = (y * pixels.width() as usize + x) * 3;
    let bytes = pixels.as_srgb();
    [bytes[offset], bytes[offset + 1], bytes[offset + 2]]
}

fn within(left: [u8; 3], right: [u8; 3], tolerance: u8) -> bool {
    left.into_iter()
        .zip(right)
        .all(|(left, right)| left.abs_diff(right) <= tolerance)
}

#[allow(clippy::too_many_arguments)]
fn enqueue_background(
    pixels: &PixelBuffer,
    background: [u8; 3],
    tolerance: u8,
    x: usize,
    y: usize,
    width: usize,
    visited: &mut [bool],
    queue: &mut VecDeque<(usize, usize)>,
) {
    let index = y * width + x;
    if !visited[index] && within(rgb(pixels, x, y), background, tolerance) {
        visited[index] = true;
        queue.push_back((x, y));
    }
}

fn neighbors(
    x: usize,
    y: usize,
    width: usize,
    height: usize,
) -> impl Iterator<Item = (usize, usize)> {
    let left = x.checked_sub(1).map(|next| (next, y));
    let up = y.checked_sub(1).map(|next| (x, next));
    let right = (x + 1 < width).then_some((x + 1, y));
    let down = (y + 1 < height).then_some((x, y + 1));
    [left, up, right, down].into_iter().flatten()
}

fn foreground_components(background: &[bool], width: usize, height: usize) -> usize {
    let mut visited = vec![false; background.len()];
    let mut components = 0;
    for start in 0..background.len() {
        if background[start] || visited[start] {
            continue;
        }
        components += 1;
        let mut queue = VecDeque::from([(start % width, start / width)]);
        visited[start] = true;
        while let Some((x, y)) = queue.pop_front() {
            for (next_x, next_y) in neighbors(x, y, width, height) {
                let index = next_y * width + next_x;
                if !background[index] && !visited[index] {
                    visited[index] = true;
                    queue.push_back((next_x, next_y));
                }
            }
        }
    }
    components
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FallbackError {
    InvalidConfiguration,
    Contract(ContractError),
}

impl fmt::Display for FallbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for FallbackError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(
        width: u32,
        height: u32,
        background: [u8; 3],
        rectangles: &[(Rect, [u8; 3])],
    ) -> PixelBuffer {
        let mut bytes = vec![0; width as usize * height as usize * 3];
        for pixel in bytes.chunks_exact_mut(3) {
            pixel.copy_from_slice(&background);
        }
        for (rectangle, color) in rectangles {
            for y in rectangle.y..rectangle.y + rectangle.height {
                for x in rectangle.x..rectangle.x + rectangle.width {
                    let offset = (y as usize * width as usize + x as usize) * 3;
                    bytes[offset..offset + 3].copy_from_slice(color);
                }
            }
        }
        PixelBuffer::new(width, height, bytes).unwrap()
    }

    #[test]
    fn rectangle_and_source_fallbacks_always_require_review() {
        let pixels = image(10, 10, [240; 3], &[]);
        let crop = RectangleFallback::confirmed_crop(
            &pixels,
            Rect {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
        )
        .unwrap();
        assert!(matches!(
            crop,
            SegmentationOutcome::FallbackCrop {
                needs_review: true,
                ..
            }
        ));
        assert!(matches!(
            RectangleFallback::source_image(&pixels),
            SegmentationOutcome::FallbackCrop {
                needs_review: true,
                ..
            }
        ));
    }

    #[test]
    fn composed_fallback_returns_a_reviewed_mask_or_reviewed_source_crop() {
        let foreground = image(
            20,
            20,
            [240; 3],
            &[(
                Rect {
                    x: 5,
                    y: 5,
                    width: 10,
                    height: 10,
                },
                [20, 80, 140],
            )],
        );
        assert!(matches!(
            rectangle_uniform_background_v1(&foreground),
            SegmentationOutcome::FallbackMask {
                needs_review: true,
                ..
            }
        ));

        let uniform = image(20, 20, [240; 3], &[]);
        assert_eq!(
            rectangle_uniform_background_v1(&uniform),
            RectangleFallback::source_image(&uniform)
        );
    }

    #[test]
    fn uniform_background_has_two_deterministic_success_cases() {
        let fallback = UniformBackgroundFallback::new(Default::default()).unwrap();
        let first = image(
            20,
            20,
            [245; 3],
            &[(
                Rect {
                    x: 5,
                    y: 4,
                    width: 10,
                    height: 12,
                },
                [20, 80, 140],
            )],
        );
        let second = image(
            20,
            20,
            [12, 14, 16],
            &[(
                Rect {
                    x: 6,
                    y: 6,
                    width: 8,
                    height: 8,
                },
                [180, 90, 40],
            )],
        );
        for pixels in [first, second] {
            let one = fallback.segment(&pixels);
            let two = fallback.segment(&pixels);
            assert_eq!(one, two);
            assert!(matches!(one, UniformBackgroundResult::Mask(_)));
        }
    }

    #[test]
    fn uniform_background_has_three_fail_closed_cases() {
        let fallback = UniformBackgroundFallback::new(Default::default()).unwrap();
        let no_foreground = image(20, 20, [240; 3], &[]);
        assert_eq!(
            fallback.segment(&no_foreground),
            UniformBackgroundResult::Unavailable(UniformUnavailable::NoForeground)
        );

        let edge = image(
            20,
            20,
            [240; 3],
            &[(
                Rect {
                    x: 0,
                    y: 5,
                    width: 8,
                    height: 8,
                },
                [10; 3],
            )],
        );
        assert_eq!(
            fallback.segment(&edge),
            UniformBackgroundResult::Unavailable(UniformUnavailable::ForegroundTouchesEdge)
        );

        let split = image(
            20,
            20,
            [240; 3],
            &[
                (
                    Rect {
                        x: 3,
                        y: 3,
                        width: 4,
                        height: 4,
                    },
                    [10; 3],
                ),
                (
                    Rect {
                        x: 13,
                        y: 13,
                        width: 4,
                        height: 4,
                    },
                    [20; 3],
                ),
            ],
        );
        assert_eq!(
            fallback.segment(&split),
            UniformBackgroundResult::Unavailable(UniformUnavailable::MultipleForegroundComponents)
        );
    }
}
