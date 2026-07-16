use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::codecs::webp::WebPEncoder;
use image::{ColorType, GenericImageView, ImageEncoder, ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::io::Cursor;

pub const MAX_SANITIZED_TEXT_BYTES: usize = 32 * 1024;
pub const MAX_CROPS: usize = 4;
pub const MAX_CROP_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_AGGREGATE_CROP_BYTES: usize = 12 * 1024 * 1024;
pub const MAX_CROP_AXIS: u32 = 2048;
pub const MAX_CROP_PIXELS: u64 = 4_194_304;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiptTextInput {
    pub merchant: Option<String>,
    pub purchase_date: Option<String>,
    pub currency: Option<String>,
    pub line_items: Vec<ReceiptLineTextInput>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiptLineTextInput {
    pub description: Option<String>,
    pub brand: Option<String>,
    pub category: Option<String>,
    pub color: Option<String>,
    pub size: Option<String>,
    pub quantity: Option<u32>,
    pub unit_price_minor: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SanitizedReceiptText {
    merchant: Option<String>,
    purchase_date: Option<String>,
    currency: Option<String>,
    line_items: Vec<SanitizedReceiptLine>,
    #[serde(skip)]
    rendered: String,
    #[serde(skip)]
    sha256: String,
    #[serde(skip)]
    source_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct SanitizedReceiptLine {
    description: Option<String>,
    brand: Option<String>,
    category: Option<String>,
    color: Option<String>,
    size: Option<String>,
    quantity: Option<u32>,
    unit_price_minor: Option<u64>,
}

impl SanitizedReceiptText {
    pub fn sanitize(input: ReceiptTextInput) -> Result<Self, SanitizationError> {
        if input.line_items.len() > 100 {
            return Err(SanitizationError::TooManyLineItems);
        }

        let merchant = sanitize_free_text(input.merchant, "merchant", 160)?;
        let purchase_date = input
            .purchase_date
            .map(|value| {
                if valid_iso_date(&value) {
                    Ok(value)
                } else {
                    Err(SanitizationError::InvalidDate)
                }
            })
            .transpose()?;
        let currency = input
            .currency
            .map(|value| {
                if value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
                    Ok(value)
                } else {
                    Err(SanitizationError::InvalidCurrency)
                }
            })
            .transpose()?;

        let mut line_items = Vec::with_capacity(input.line_items.len());
        for line in input.line_items {
            if line.quantity == Some(0) || line.quantity.is_some_and(|quantity| quantity > 10_000) {
                return Err(SanitizationError::InvalidQuantity);
            }
            if line
                .unit_price_minor
                .is_some_and(|price| price > 100_000_000)
            {
                return Err(SanitizationError::InvalidPrice);
            }
            line_items.push(SanitizedReceiptLine {
                description: sanitize_free_text(line.description, "description", 256)?,
                brand: sanitize_free_text(line.brand, "brand", 120)?,
                category: sanitize_free_text(line.category, "category", 80)?,
                color: sanitize_free_text(line.color, "color", 80)?,
                size: sanitize_free_text(line.size, "size", 48)?,
                quantity: line.quantity,
                unit_price_minor: line.unit_price_minor,
            });
        }

        if merchant.is_none()
            && purchase_date.is_none()
            && currency.is_none()
            && line_items.is_empty()
        {
            return Err(SanitizationError::EmptyEvidence);
        }

        #[derive(Serialize)]
        struct WireText<'a> {
            merchant: &'a Option<String>,
            purchase_date: &'a Option<String>,
            currency: &'a Option<String>,
            line_items: &'a [SanitizedReceiptLine],
        }

        let rendered = serde_json::to_string(&WireText {
            merchant: &merchant,
            purchase_date: &purchase_date,
            currency: &currency,
            line_items: &line_items,
        })
        .map_err(|_| SanitizationError::Serialization)?;
        if rendered.len() > MAX_SANITIZED_TEXT_BYTES {
            return Err(SanitizationError::TextTooLarge);
        }

        let mut source_ids = BTreeSet::new();
        if merchant.is_some() {
            source_ids.insert("text.merchant".to_owned());
        }
        if purchase_date.is_some() {
            source_ids.insert("text.purchase_date".to_owned());
        }
        if currency.is_some() {
            source_ids.insert("text.currency".to_owned());
        }
        for (index, line) in line_items.iter().enumerate() {
            for (name, present) in [
                ("description", line.description.is_some()),
                ("brand", line.brand.is_some()),
                ("category", line.category.is_some()),
                ("color", line.color.is_some()),
                ("size", line.size.is_some()),
                ("quantity", line.quantity.is_some()),
                ("unit_price_minor", line.unit_price_minor.is_some()),
            ] {
                if present {
                    source_ids.insert(format!("text.line_items.{index}.{name}"));
                }
            }
        }

        Ok(Self {
            merchant,
            purchase_date,
            currency,
            line_items,
            sha256: sha256_hex(rendered.as_bytes()),
            rendered,
            source_ids,
        })
    }

    pub fn rendered(&self) -> &str {
        &self.rendered
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn field_names(&self) -> Vec<String> {
        self.source_ids
            .iter()
            .filter_map(|source| source.strip_prefix("text.").map(str::to_owned))
            .collect()
    }

    pub fn source_ids(&self) -> &BTreeSet<String> {
        &self.source_ids
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CropDetail {
    Low,
    High,
}

impl CropDetail {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CropMime {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/webp")]
    Webp,
}

impl CropMime {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CropInput {
    pub source_id: String,
    pub bytes: Vec<u8>,
    pub mime: CropMime,
    pub detail: CropDetail,
    pub face_free: bool,
    pub surroundings_minimized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedCrop {
    source_id: String,
    bytes: Vec<u8>,
    mime: CropMime,
    detail: CropDetail,
    width: u32,
    height: u32,
    sha256: String,
}

impl SanitizedCrop {
    pub fn sanitize(input: CropInput) -> Result<Self, SanitizationError> {
        if !valid_source_id(&input.source_id) {
            return Err(SanitizationError::InvalidSourceId);
        }
        if !input.face_free || !input.surroundings_minimized {
            return Err(SanitizationError::MissingCropSafetyAttestation);
        }
        if input.bytes.is_empty() || input.bytes.len() > MAX_CROP_BYTES {
            return Err(SanitizationError::CropByteLimit);
        }

        let (bytes, width, height) = normalize_image(&input.bytes, input.mime)?;
        let pixels = u64::from(width)
            .checked_mul(u64::from(height))
            .ok_or(SanitizationError::CropDimensionLimit)?;
        if width == 0
            || height == 0
            || width > MAX_CROP_AXIS
            || height > MAX_CROP_AXIS
            || pixels > MAX_CROP_PIXELS
        {
            return Err(SanitizationError::CropDimensionLimit);
        }
        if bytes.len() > MAX_CROP_BYTES {
            return Err(SanitizationError::CropByteLimit);
        }

        Ok(Self {
            source_id: input.source_id,
            sha256: sha256_hex(&bytes),
            bytes,
            mime: input.mime,
            detail: input.detail,
            width,
            height,
        })
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn mime(&self) -> CropMime {
        self.mime
    }

    pub fn detail(&self) -> CropDetail {
        self.detail
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn base64_byte_count(&self) -> usize {
        base64_encoded_len(self.bytes.len()).expect("sanitized crop length cannot overflow")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PreparedEvidence {
    text: Option<SanitizedReceiptText>,
    crops: Vec<SanitizedCrop>,
    source_ids: BTreeSet<String>,
    input_hash: String,
}

impl PreparedEvidence {
    pub fn new(
        text: Option<SanitizedReceiptText>,
        crops: Vec<SanitizedCrop>,
    ) -> Result<Self, SanitizationError> {
        if text.is_none() && crops.is_empty() {
            return Err(SanitizationError::EmptyEvidence);
        }
        if crops.len() > MAX_CROPS {
            return Err(SanitizationError::TooManyCrops);
        }
        let aggregate_base64 = crops.iter().try_fold(0usize, |total, crop| {
            total
                .checked_add(
                    base64_encoded_len(crop.bytes.len())
                        .ok_or(SanitizationError::AggregateCropByteLimit)?,
                )
                .ok_or(SanitizationError::AggregateCropByteLimit)
        })?;
        if aggregate_base64 > MAX_AGGREGATE_CROP_BYTES {
            return Err(SanitizationError::AggregateCropByteLimit);
        }

        let mut source_ids = text
            .as_ref()
            .map(|text| text.source_ids.clone())
            .unwrap_or_default();
        for crop in &crops {
            if !source_ids.insert(crop.source_id.clone()) {
                return Err(SanitizationError::DuplicateSourceId);
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(b"p00-prepared-evidence-v1\0");
        if let Some(text) = &text {
            hasher.update(text.sha256.as_bytes());
        }
        for crop in &crops {
            hasher.update(crop.source_id.as_bytes());
            hasher.update([0]);
            hasher.update(crop.sha256.as_bytes());
            hasher.update([crop.detail as u8]);
        }

        Ok(Self {
            text,
            crops,
            source_ids,
            input_hash: hex_digest(hasher.finalize().as_slice()),
        })
    }

    pub fn text(&self) -> Option<&SanitizedReceiptText> {
        self.text.as_ref()
    }

    pub fn crops(&self) -> &[SanitizedCrop] {
        &self.crops
    }

    pub fn source_ids(&self) -> &BTreeSet<String> {
        &self.source_ids
    }

    pub fn input_hash(&self) -> &str {
        &self.input_hash
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SanitizationError {
    EmptyEvidence,
    ProhibitedText,
    FieldTooLong,
    InvalidDate,
    InvalidCurrency,
    InvalidQuantity,
    InvalidPrice,
    TooManyLineItems,
    TextTooLarge,
    Serialization,
    InvalidSourceId,
    MissingCropSafetyAttestation,
    CropByteLimit,
    CropDimensionLimit,
    UnsupportedImage,
    MalformedImage,
    ImageMetadataPresent,
    AnimatedImage,
    MimeMismatch,
    TooManyCrops,
    AggregateCropByteLimit,
    DuplicateSourceId,
}

impl fmt::Display for SanitizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "evidence sanitization failed: {self:?}")
    }
}

impl Error for SanitizationError {}

fn sanitize_free_text(
    value: Option<String>,
    _field: &'static str,
    max_chars: usize,
) -> Result<Option<String>, SanitizationError> {
    value
        .map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(SanitizationError::ProhibitedText);
            }
            if trimmed.chars().count() > max_chars {
                return Err(SanitizationError::FieldTooLong);
            }
            let lower = trimmed.to_ascii_lowercase();
            let prohibited = trimmed.chars().any(char::is_control)
                || trimmed.contains(['<', '>'])
                || trimmed.contains('@')
                || lower.contains("http://")
                || lower.contains("https://")
                || lower.contains("www.")
                || lower.contains("authorization:")
                || lower.contains("cookie:")
                || lower.contains("tracking:")
                || looks_like_sensitive_number(trimmed);
            if prohibited {
                return Err(SanitizationError::ProhibitedText);
            }
            Ok(trimmed.to_owned())
        })
        .transpose()
}

fn looks_like_sensitive_number(value: &str) -> bool {
    let mut digits = 0usize;
    for character in value.chars() {
        if character.is_ascii_digit() {
            digits += 1;
            if digits >= 10 {
                return true;
            }
        } else if !matches!(character, ' ' | '-' | '(' | ')' | '.') {
            digits = 0;
        }
    }
    false
}

fn valid_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let year = value[0..4].parse::<u32>().ok();
    let month = value[5..7].parse::<u32>().ok();
    let day = value[8..10].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day)) = (year, month, day) else {
        return false;
    };
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        _ => return false,
    };
    day > 0 && day <= max_day
}

fn valid_source_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn normalize_image(bytes: &[u8], mime: CropMime) -> Result<(Vec<u8>, u32, u32), SanitizationError> {
    let format = image::guess_format(bytes).map_err(|_| SanitizationError::UnsupportedImage)?;
    if format != image_format(mime) {
        return Err(SanitizationError::MimeMismatch);
    }

    let dimensions = ImageReader::with_format(Cursor::new(bytes), format)
        .into_dimensions()
        .map_err(|_| SanitizationError::MalformedImage)?;
    validate_dimensions(dimensions.0, dimensions.1)?;

    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_CROP_AXIS);
    limits.max_image_height = Some(MAX_CROP_AXIS);
    limits.max_alloc = Some(64 * 1024 * 1024);
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(limits);
    let decoded = reader
        .decode()
        .map_err(|_| SanitizationError::MalformedImage)?;
    if decoded.dimensions() != dimensions {
        return Err(SanitizationError::MalformedImage);
    }

    let mut normalized = Vec::new();
    match mime {
        CropMime::Png => {
            let pixels = decoded.to_rgba8();
            PngEncoder::new(&mut normalized)
                .write_image(
                    pixels.as_raw(),
                    dimensions.0,
                    dimensions.1,
                    ColorType::Rgba8.into(),
                )
                .map_err(|_| SanitizationError::MalformedImage)?;
        }
        CropMime::Jpeg => {
            let pixels = decoded.to_rgb8();
            JpegEncoder::new_with_quality(&mut normalized, 90)
                .encode(
                    pixels.as_raw(),
                    dimensions.0,
                    dimensions.1,
                    ColorType::Rgb8.into(),
                )
                .map_err(|_| SanitizationError::MalformedImage)?;
        }
        CropMime::Webp => {
            let pixels = decoded.to_rgba8();
            WebPEncoder::new_lossless(&mut normalized)
                .encode(
                    pixels.as_raw(),
                    dimensions.0,
                    dimensions.1,
                    ColorType::Rgba8.into(),
                )
                .map_err(|_| SanitizationError::MalformedImage)?;
        }
    }
    Ok((normalized, dimensions.0, dimensions.1))
}

fn image_format(mime: CropMime) -> ImageFormat {
    match mime {
        CropMime::Png => ImageFormat::Png,
        CropMime::Jpeg => ImageFormat::Jpeg,
        CropMime::Webp => ImageFormat::WebP,
    }
}

fn validate_dimensions(width: u32, height: u32) -> Result<(), SanitizationError> {
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(SanitizationError::CropDimensionLimit)?;
    if width == 0
        || height == 0
        || width > MAX_CROP_AXIS
        || height > MAX_CROP_AXIS
        || pixels > MAX_CROP_PIXELS
    {
        return Err(SanitizationError::CropDimensionLimit);
    }
    Ok(())
}

fn base64_encoded_len(byte_count: usize) -> Option<usize> {
    byte_count.checked_add(2)?.checked_div(3)?.checked_mul(4)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes).as_slice())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_crop(byte_count: usize, source_id: &str) -> SanitizedCrop {
        SanitizedCrop {
            source_id: source_id.to_owned(),
            bytes: vec![0; byte_count],
            mime: CropMime::Png,
            detail: CropDetail::Low,
            width: 1,
            height: 1,
            sha256: sha256_hex(source_id.as_bytes()),
        }
    }

    #[test]
    fn dates_are_calendar_valid() {
        assert!(valid_iso_date("2024-02-29"));
        assert!(!valid_iso_date("2025-02-29"));
        assert!(!valid_iso_date("2025-13-01"));
    }

    #[test]
    fn source_ids_are_narrow_ascii() {
        assert!(valid_source_id("crop.synthetic-1"));
        assert!(!valid_source_id("../crop"));
        assert!(!valid_source_id("crop/one"));
    }

    #[test]
    fn aggregate_limit_counts_base64_bytes_not_raw_bytes() {
        let three_mebibytes = 3 * 1024 * 1024;
        let at_limit = vec![
            synthetic_crop(three_mebibytes, "crop.one"),
            synthetic_crop(three_mebibytes, "crop.two"),
            synthetic_crop(three_mebibytes, "crop.three"),
        ];
        assert_eq!(
            at_limit
                .iter()
                .map(SanitizedCrop::base64_byte_count)
                .sum::<usize>(),
            MAX_AGGREGATE_CROP_BYTES
        );
        assert!(PreparedEvidence::new(None, at_limit).is_ok());

        let over_limit = vec![
            synthetic_crop(three_mebibytes + 1, "crop.one"),
            synthetic_crop(three_mebibytes, "crop.two"),
            synthetic_crop(three_mebibytes, "crop.three"),
        ];
        assert_eq!(
            over_limit
                .iter()
                .map(|crop| crop.bytes.len())
                .sum::<usize>(),
            9 * 1024 * 1024 + 1
        );
        assert_eq!(
            PreparedEvidence::new(None, over_limit).unwrap_err(),
            SanitizationError::AggregateCropByteLimit
        );
    }
}
