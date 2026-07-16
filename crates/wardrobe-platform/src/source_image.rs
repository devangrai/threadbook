use crate::{BlobStore, PlatformError, PlatformResult};
use image::codecs::png::{PngDecoder, PngEncoder};
use image::codecs::webp::WebPDecoder;
use image::{
    imageops, DynamicImage, GenericImageView, ImageDecoder, ImageEncoder, ImageFormat, ImageReader,
    Limits, RgbImage, RgbaImage,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufReader, Cursor};
use wardrobe_core::{
    CanonicalSrgbPixelBufferV1, PhotoMediaTypeV1, PhotoQuarantineReasonV1,
    MAX_PHOTO_ARTIFACT_BYTES, MAX_PHOTO_AXIS, MAX_PHOTO_PIXELS,
};

const MAX_DECODE_ALLOC: u64 = MAX_PHOTO_PIXELS * 4;
pub(crate) const MAX_TRY_ON_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_TRY_ON_INPUT_AXIS: u32 = 4096;
pub(crate) const MAX_TRY_ON_INPUT_PIXELS: u64 = 16_777_216;

#[derive(Clone, Debug)]
pub(crate) struct VerifiedSourceImage {
    pub bytes: Vec<u8>,
    pub media_type: PhotoMediaTypeV1,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanonicalTryOnPng {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub width: u32,
    pub height: u32,
}

impl VerifiedSourceImage {
    pub fn canonical_pixels(&self) -> PlatformResult<CanonicalSrgbPixelBufferV1> {
        let image = decode_canonical(&self.bytes, image_format(self.media_type))
            .map_err(|_| PlatformError::Corrupt("photo_image_decode"))?;
        let (width, height) = image.dimensions();
        if width != self.width || height != self.height {
            return Err(PlatformError::Corrupt("photo_image_dimensions_changed"));
        }
        CanonicalSrgbPixelBufferV1::new(image.into_rgb8().into_raw(), width, height)
            .map_err(|_| PlatformError::Corrupt("photo_pixel_buffer"))
    }

    pub(crate) fn canonical_rgba8(&self) -> PlatformResult<RgbaImage> {
        let image = decode_canonical(&self.bytes, image_format(self.media_type))
            .map_err(|_| PlatformError::Corrupt("reconciliation_image_decode"))?;
        let (width, height) = image.dimensions();
        if width != self.width || height != self.height {
            return Err(PlatformError::Corrupt(
                "reconciliation_image_dimensions_changed",
            ));
        }
        Ok(image.into_rgba8())
    }
}

pub(crate) fn canonical_try_on_png(
    store: &BlobStore,
    parent_sha256: &str,
    parent_length: u64,
) -> PlatformResult<CanonicalTryOnPng> {
    let source = verify_source_image(store, parent_sha256, parent_length)
        .map_err(|_| PlatformError::Corrupt("try_on_parent_image"))?;
    if source.width > MAX_TRY_ON_INPUT_AXIS
        || source.height > MAX_TRY_ON_INPUT_AXIS
        || u64::from(source.width) * u64::from(source.height) > MAX_TRY_ON_INPUT_PIXELS
    {
        return Err(PlatformError::InvalidInput("try_on_image_dimensions"));
    }
    let rgba = source
        .canonical_rgba8()
        .map_err(|_| PlatformError::Corrupt("try_on_image_decode"))?;
    let mut bytes = Vec::new();
    PngEncoder::new(&mut bytes)
        .write_image(
            rgba.as_raw(),
            source.width,
            source.height,
            image::ExtendedColorType::Rgba8,
        )
        .map_err(|_| PlatformError::Corrupt("try_on_png_encode"))?;
    if bytes.is_empty() || bytes.len() > MAX_TRY_ON_INPUT_BYTES {
        return Err(PlatformError::InvalidInput("try_on_image_size"));
    }
    Ok(CanonicalTryOnPng {
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        bytes,
        width: source.width,
        height: source.height,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalVisualFeaturesV1 {
    pub difference_hash: u64,
    pub mean_rgb: [u8; 3],
}

impl LocalVisualFeaturesV1 {
    pub(crate) fn distances(self, other: Self) -> (u8, u16) {
        let hash_distance = (self.difference_hash ^ other.difference_hash).count_ones() as u8;
        let color_distance = self
            .mean_rgb
            .into_iter()
            .zip(other.mean_rgb)
            .map(|(left, right)| u16::from(left.abs_diff(right)))
            .sum();
        (hash_distance, color_distance)
    }
}

pub(crate) fn extract_local_visual_features_v1(
    image: &VerifiedSourceImage,
    rectangle: (u32, u32, u32, u32),
) -> PlatformResult<LocalVisualFeaturesV1> {
    let rgba = image.canonical_rgba8()?;
    local_visual_features_from_rgba(&rgba, rectangle)
}

fn local_visual_features_from_rgba(
    rgba: &RgbaImage,
    (x, y, width, height): (u32, u32, u32, u32),
) -> PlatformResult<LocalVisualFeaturesV1> {
    if width == 0
        || height == 0
        || x.checked_add(width)
            .is_none_or(|right| right > rgba.width())
        || y.checked_add(height)
            .is_none_or(|bottom| bottom > rgba.height())
    {
        return Err(PlatformError::Corrupt("reconciliation_image_rectangle"));
    }

    let cropped = imageops::crop_imm(rgba, x, y, width, height);
    let mut composited = RgbImage::new(width, height);
    for ((_, _, source), target) in cropped.pixels().zip(composited.pixels_mut()) {
        let alpha = u32::from(source[3]);
        for channel in 0..3 {
            let sample = u32::from(source[channel]);
            target[channel] = ((sample * alpha + 255 * (255 - alpha) + 127) / 255) as u8;
        }
    }

    let resized = imageops::resize(&composited, 9, 8, imageops::FilterType::Triangle);
    local_visual_features_from_9x8(&resized)
}

fn local_visual_features_from_9x8(image: &RgbImage) -> PlatformResult<LocalVisualFeaturesV1> {
    if image.dimensions() != (9, 8) {
        return Err(PlatformError::Corrupt("reconciliation_feature_dimensions"));
    }
    let mut grayscale = [0_u8; 72];
    let mut sums = [0_u32; 3];
    for (index, pixel) in image.pixels().enumerate() {
        let red = u32::from(pixel[0]);
        let green = u32::from(pixel[1]);
        let blue = u32::from(pixel[2]);
        grayscale[index] = ((77 * red + 150 * green + 29 * blue + 128) >> 8) as u8;
        sums[0] += red;
        sums[1] += green;
        sums[2] += blue;
    }

    let mut difference_hash = 0_u64;
    for y in 0..8 {
        for x in 0..8 {
            if grayscale[y * 9 + x] > grayscale[y * 9 + x + 1] {
                difference_hash |= 1_u64 << (y * 8 + x);
            }
        }
    }
    let mean_rgb = sums.map(|sum| ((sum + 36) / 72) as u8);
    Ok(LocalVisualFeaturesV1 {
        difference_hash,
        mean_rgb,
    })
}

pub(crate) fn verify_source_image(
    store: &BlobStore,
    sha256: &str,
    expected_length: u64,
) -> Result<VerifiedSourceImage, PhotoQuarantineReasonV1> {
    if expected_length == 0 || expected_length > MAX_PHOTO_ARTIFACT_BYTES as u64 {
        return Err(PhotoQuarantineReasonV1::ImageDimensionLimit);
    }
    let record = store.verify(sha256).map_err(|error| match error {
        PlatformError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound => {
            PhotoQuarantineReasonV1::BlobUnavailable
        }
        _ => PhotoQuarantineReasonV1::BlobIntegrityFailed,
    })?;
    if record.byte_length != expected_length {
        return Err(PhotoQuarantineReasonV1::BlobIntegrityFailed);
    }
    let bytes = fs::read(&record.path).map_err(|_| PhotoQuarantineReasonV1::BlobUnavailable)?;
    if bytes.len() as u64 != expected_length || format!("{:x}", Sha256::digest(&bytes)) != sha256 {
        return Err(PhotoQuarantineReasonV1::BlobIntegrityFailed);
    }

    let format =
        image::guess_format(&bytes).map_err(|_| PhotoQuarantineReasonV1::MediaTypeRejected)?;
    let media_type = match format {
        ImageFormat::Jpeg => PhotoMediaTypeV1::ImageJpeg,
        ImageFormat::Png => {
            let decoder = PngDecoder::new(Cursor::new(&bytes))
                .map_err(|_| PhotoQuarantineReasonV1::ImageDecodeFailed)?;
            if decoder
                .is_apng()
                .map_err(|_| PhotoQuarantineReasonV1::ImageDecodeFailed)?
            {
                return Err(PhotoQuarantineReasonV1::ImageAnimated);
            }
            PhotoMediaTypeV1::ImagePng
        }
        ImageFormat::WebP => {
            let decoder = WebPDecoder::new(Cursor::new(&bytes))
                .map_err(|_| PhotoQuarantineReasonV1::ImageDecodeFailed)?;
            if decoder.has_animation() {
                return Err(PhotoQuarantineReasonV1::ImageAnimated);
            }
            PhotoMediaTypeV1::ImageWebp
        }
        _ => return Err(PhotoQuarantineReasonV1::MediaTypeRejected),
    };

    let image =
        decode_canonical(&bytes, format).map_err(|_| PhotoQuarantineReasonV1::ImageDecodeFailed)?;
    let (width, height) = image.dimensions();
    if width == 0
        || height == 0
        || width > MAX_PHOTO_AXIS
        || height > MAX_PHOTO_AXIS
        || u64::from(width) * u64::from(height) > MAX_PHOTO_PIXELS
    {
        return Err(PhotoQuarantineReasonV1::ImageDimensionLimit);
    }

    Ok(VerifiedSourceImage {
        bytes,
        media_type,
        width,
        height,
    })
}

fn decode_canonical(bytes: &[u8], format: ImageFormat) -> image::ImageResult<DynamicImage> {
    let mut reader = ImageReader::with_format(BufReader::new(Cursor::new(bytes)), format);
    reader.limits(image_limits());
    let mut decoder = reader.into_decoder()?;
    let orientation = decoder.orientation()?;
    let mut image = DynamicImage::from_decoder(decoder)?;
    image.apply_orientation(orientation);
    Ok(image)
}

fn image_limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_PHOTO_AXIS);
    limits.max_image_height = Some(MAX_PHOTO_AXIS);
    limits.max_alloc = Some(MAX_DECODE_ALLOC);
    limits
}

fn image_format(media_type: PhotoMediaTypeV1) -> ImageFormat {
    match media_type {
        PhotoMediaTypeV1::ImageJpeg => ImageFormat::Jpeg,
        PhotoMediaTypeV1::ImagePng => ImageFormat::Png,
        PhotoMediaTypeV1::ImageWebp => ImageFormat::WebP,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgb;

    #[test]
    fn local_features_lock_bit_direction_equality_and_mean_rounding() {
        let mut image = RgbImage::new(9, 8);
        for (x, _, pixel) in image.enumerate_pixels_mut() {
            let value = 80_u8.saturating_sub(x as u8 * 10);
            *pixel = Rgb([value, value, value]);
        }
        let features = local_visual_features_from_9x8(&image).unwrap();
        assert_eq!(features.difference_hash, u64::MAX);
        assert_eq!(features.mean_rgb, [40, 40, 40]);

        for pixel in image.pixels_mut() {
            *pixel = Rgb([1, 0, 0]);
        }
        let equality = local_visual_features_from_9x8(&image).unwrap();
        assert_eq!(equality.difference_hash, 0);
        assert_eq!(equality.mean_rgb, [1, 0, 0]);
    }

    #[test]
    fn local_features_composite_alpha_onto_opaque_white() {
        let transparent = RgbaImage::from_pixel(9, 8, image::Rgba([0, 0, 0, 0]));
        let transparent_features =
            local_visual_features_from_rgba(&transparent, (0, 0, 9, 8)).unwrap();
        assert_eq!(transparent_features.mean_rgb, [255, 255, 255]);
        assert_eq!(transparent_features.difference_hash, 0);

        let half_alpha = RgbaImage::from_pixel(9, 8, image::Rgba([0, 0, 0, 128]));
        let half_alpha_features =
            local_visual_features_from_rgba(&half_alpha, (0, 0, 9, 8)).unwrap();
        assert_eq!(half_alpha_features.mean_rgb, [127, 127, 127]);
    }

    #[test]
    fn try_on_canonical_png_is_metadata_free_and_deterministic() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = crate::PrivateAppPaths::create(temporary.path()).unwrap();
        let store = BlobStore::new(&paths);
        let source = RgbaImage::from_pixel(3, 2, image::Rgba([12, 34, 56, 255]));
        let mut encoded = Vec::new();
        PngEncoder::new(&mut encoded)
            .write_image(
                source.as_raw(),
                source.width(),
                source.height(),
                image::ExtendedColorType::Rgba8,
            )
            .unwrap();
        let parent = store
            .put(&encoded, None, MAX_PHOTO_ARTIFACT_BYTES as u64)
            .unwrap();

        let first = canonical_try_on_png(&store, &parent.sha256, parent.byte_length).unwrap();
        let second = canonical_try_on_png(&store, &parent.sha256, parent.byte_length).unwrap();
        assert_eq!(first, second);
        assert_eq!((first.width, first.height), (3, 2));
        assert_eq!(format!("{:x}", Sha256::digest(&first.bytes)), first.sha256);
    }

    #[test]
    fn local_feature_distances_are_bounded_integer_metrics() {
        let left = LocalVisualFeaturesV1 {
            difference_hash: 0,
            mean_rgb: [0, 10, 255],
        };
        let right = LocalVisualFeaturesV1 {
            difference_hash: u64::MAX,
            mean_rgb: [255, 30, 0],
        };
        assert_eq!(left.distances(right), (64, 530));
    }
}
