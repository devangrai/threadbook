use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use image::codecs::png::PngDecoder;
use image::{ImageDecoder, ImageFormat, ImageReader, Limits};
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use reqwest::multipart::{Form, Part};
use reqwest::{redirect::Policy, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufReader, Cursor};
#[cfg(test)]
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use url::Url;
use wardrobe_core::SecretString;

pub const OPENAI_IMAGE_EDITS_ENDPOINT: &str = "https://api.openai.com/v1/images/edits";
pub const OPENAI_IMAGE_EDITS_MODEL: &str = "gpt-image-2";
pub const OPENAI_IMAGE_EDITS_PROMPT_REVISION: &str = "p08-try-on-v1";
pub const OPENAI_IMAGE_EDITS_PROMPT: &str = "Create a photorealistic outfit visualization of the person in the first reference image wearing all garments shown in the remaining reference images. Preserve the person's identity and the garments' visible colors, patterns, materials, and construction. Do not add, remove, or substitute garments. Use a natural full-body portrait composition.";
pub const OPENAI_IMAGE_EDITS_SIZE: &str = "1024x1536";
pub const OPENAI_IMAGE_EDITS_QUALITY: &str = "low";
pub const OPENAI_IMAGE_EDITS_OUTPUT_FORMAT: &str = "png";

pub const OPENAI_IMAGE_MIN_GARMENTS: usize = 2;
pub const OPENAI_IMAGE_MAX_GARMENTS: usize = 8;
pub const OPENAI_IMAGE_REFERENCE_LIMIT_BYTES: usize = 8 * 1024 * 1024;
pub const OPENAI_IMAGE_REFERENCES_LIMIT_BYTES: usize = 40 * 1024 * 1024;
pub const OPENAI_IMAGE_REQUEST_LIMIT_BYTES: usize = 41 * 1024 * 1024;
pub const OPENAI_IMAGE_RESPONSE_LIMIT_BYTES: usize = 20 * 1024 * 1024;
pub const OPENAI_IMAGE_ERROR_RESPONSE_LIMIT_BYTES: usize = 64 * 1024;
pub const OPENAI_IMAGE_OUTPUT_LIMIT_BYTES: usize = 12 * 1024 * 1024;
pub const OPENAI_IMAGE_AXIS_LIMIT: u32 = 4096;
pub const OPENAI_IMAGE_PIXEL_LIMIT: u64 = 16_777_216;
pub const OPENAI_IMAGE_RESPONSE_HEADER_LIMIT: usize = 64;
pub const OPENAI_IMAGE_RESPONSE_HEADER_BYTES_LIMIT: usize = 32 * 1024;
pub const OPENAI_IMAGE_RESPONSE_HEADER_VALUE_LIMIT: usize = 8 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(150);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_API_KEY_BYTES: usize = 16 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 256;
const MAX_RETAINED_HEADER_VALUE_BYTES: usize = 256;
const OUTPUT_WIDTH: u32 = 1024;
const OUTPUT_HEIGHT: u32 = 1536;
const MAX_IMAGE_DECODE_ALLOCATION: u64 = 80 * 1024 * 1024;

const RETAINED_RESPONSE_HEADERS: &[&str] = &[
    "openai-processing-ms",
    "openai-version",
    "x-ratelimit-limit-requests",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-reset-requests",
];

#[derive(Clone, Copy)]
pub struct OpenAiImageEditsRequest<'a> {
    pub portrait_png: &'a [u8],
    pub garment_pngs: &'a [&'a [u8]],
}

impl fmt::Debug for OpenAiImageEditsRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiImageEditsRequest")
            .field("portrait_png", &"[REDACTED]")
            .field("garment_count", &self.garment_pngs.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct OpenAiImageEditsHttpTransport {
    client: reqwest::Client,
    endpoint: Url,
}

impl fmt::Debug for OpenAiImageEditsHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiImageEditsHttpTransport")
            .field("endpoint", &self.endpoint)
            .field("model", &OPENAI_IMAGE_EDITS_MODEL)
            .field("prompt_revision", &OPENAI_IMAGE_EDITS_PROMPT_REVISION)
            .finish_non_exhaustive()
    }
}

impl OpenAiImageEditsHttpTransport {
    pub fn production() -> Result<Self, OpenAiImageEditsError> {
        Self::build(
            Url::parse(OPENAI_IMAGE_EDITS_ENDPOINT)
                .map_err(|_| error_not_sent(OpenAiImageEditsErrorDetail::ClientConfiguration))?,
            None,
            TransportTimeouts {
                connect: CONNECT_TIMEOUT,
                read: READ_TIMEOUT,
                total: TOTAL_TIMEOUT,
            },
        )
    }

    #[cfg(test)]
    pub fn for_test(
        origin: Url,
        certificate: reqwest::Certificate,
        socket: SocketAddr,
    ) -> Result<Self, OpenAiImageEditsError> {
        Self::for_test_with_timeouts(
            origin,
            certificate,
            socket,
            ImageEditsTestTimeouts {
                connect: Duration::from_secs(2),
                read: Duration::from_secs(2),
                total: Duration::from_secs(3),
            },
        )
    }

    #[cfg(test)]
    pub fn for_test_with_timeouts(
        origin: Url,
        certificate: reqwest::Certificate,
        socket: SocketAddr,
        timeouts: ImageEditsTestTimeouts,
    ) -> Result<Self, OpenAiImageEditsError> {
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(error_not_sent(
                OpenAiImageEditsErrorDetail::ClientConfiguration,
            ));
        }
        let host = origin
            .host_str()
            .ok_or_else(|| error_not_sent(OpenAiImageEditsErrorDetail::ClientConfiguration))?
            .to_owned();
        let endpoint = origin
            .join("v1/images/edits")
            .map_err(|_| error_not_sent(OpenAiImageEditsErrorDetail::ClientConfiguration))?;
        Self::build(
            endpoint,
            Some((certificate, host, socket)),
            TransportTimeouts {
                connect: timeouts.connect,
                read: timeouts.read,
                total: timeouts.total,
            },
        )
    }

    fn build(
        endpoint: Url,
        #[cfg(test)] test_tls: Option<(reqwest::Certificate, String, SocketAddr)>,
        #[cfg(not(test))] _test_tls: Option<()>,
        timeouts: TransportTimeouts,
    ) -> Result<Self, OpenAiImageEditsError> {
        if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
            return Err(error_not_sent(
                OpenAiImageEditsErrorDetail::ClientConfiguration,
            ));
        }
        let builder = reqwest::Client::builder()
            .default_headers(HeaderMap::new())
            .retry(reqwest::retry::never())
            .redirect(Policy::none())
            .referer(false)
            .no_proxy()
            .https_only(true)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(timeouts.connect)
            .read_timeout(timeouts.read)
            .timeout(timeouts.total);
        #[cfg(test)]
        let builder = if let Some((certificate, host, socket)) = test_tls {
            builder
                .tls_certs_only(vec![certificate])
                .resolve(&host, socket)
        } else {
            builder
        };
        let client = builder
            .build()
            .map_err(|_| error_not_sent(OpenAiImageEditsErrorDetail::ClientConfiguration))?;
        Ok(Self { client, endpoint })
    }

    pub async fn generate(
        &self,
        api_key: &SecretString,
        request: OpenAiImageEditsRequest<'_>,
    ) -> Result<OpenAiImageEditsOutput, OpenAiImageEditsError> {
        validate_api_key(api_key)?;
        validate_request(request)?;
        let form = build_form(request)?;

        let started = Instant::now();
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(ACCEPT, "application/json")
            .bearer_auth(api_key.expose_secret())
            .multipart(form)
            .send()
            .await
            .map_err(map_send_error)?;

        validate_response_headers(response.headers())?;
        let mut metadata = response_metadata(&response, started)?;
        validate_json_content_type(response.headers(), response.status(), metadata.clone())?;
        let status = response.status();

        if !status.is_success() {
            if response
                .content_length()
                .is_some_and(|length| length > OPENAI_IMAGE_ERROR_RESPONSE_LIMIT_BYTES as u64)
            {
                return Err(error_responded(
                    OpenAiImageEditsFailureKind::ProviderProtocol,
                    OpenAiImageEditsErrorDetail::ResponseTooLarge,
                    Some(status.as_u16()),
                    Some(metadata),
                ));
            }
            let body = read_bounded_body(
                response,
                OPENAI_IMAGE_ERROR_RESPONSE_LIMIT_BYTES,
                Some(status.as_u16()),
                Some(metadata.clone()),
            )
            .await?;
            metadata.response_bytes = body.len();
            let json: Value = serde_json::from_slice(&body).map_err(|_| {
                error_responded(
                    OpenAiImageEditsFailureKind::ProviderProtocol,
                    OpenAiImageEditsErrorDetail::MalformedResponseJson,
                    Some(status.as_u16()),
                    Some(metadata.clone()),
                )
            })?;
            let kind = if exact_moderation_blocked(&json) {
                OpenAiImageEditsFailureKind::ModerationBlocked
            } else {
                classify_status(status)
            };
            return Err(error_responded(
                kind,
                OpenAiImageEditsErrorDetail::HttpStatus,
                Some(status.as_u16()),
                Some(metadata),
            ));
        }

        if response
            .content_length()
            .is_some_and(|length| length > OPENAI_IMAGE_RESPONSE_LIMIT_BYTES as u64)
        {
            return Err(error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::ResponseTooLarge,
                Some(status.as_u16()),
                Some(metadata),
            ));
        }
        let body = read_bounded_body(
            response,
            OPENAI_IMAGE_RESPONSE_LIMIT_BYTES,
            Some(status.as_u16()),
            Some(metadata.clone()),
        )
        .await?;
        metadata.response_bytes = body.len();
        let response: ImageEditsResponse = serde_json::from_slice(&body).map_err(|_| {
            error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::MalformedResponseJson,
                Some(status.as_u16()),
                Some(metadata.clone()),
            )
        })?;
        if response.data.len() != 1 {
            return Err(error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::InvalidImageResultCount,
                Some(status.as_u16()),
                Some(metadata),
            ));
        }
        let encoded = &response.data[0].b64_json;
        if encoded.is_empty() || encoded.len() > OPENAI_IMAGE_OUTPUT_LIMIT_BYTES.div_ceil(3) * 4 {
            return Err(error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::OutputTooLarge,
                Some(status.as_u16()),
                Some(metadata),
            ));
        }
        let png = STANDARD.decode(encoded).map_err(|_| {
            error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::InvalidBase64,
                Some(status.as_u16()),
                Some(metadata.clone()),
            )
        })?;
        if png.len() > OPENAI_IMAGE_OUTPUT_LIMIT_BYTES {
            return Err(error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::OutputTooLarge,
                Some(status.as_u16()),
                Some(metadata),
            ));
        }
        validate_png(&png, Some((OUTPUT_WIDTH, OUTPUT_HEIGHT)), false).map_err(|detail| {
            error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                detail,
                Some(status.as_u16()),
                Some(metadata.clone()),
            )
        })?;

        Ok(OpenAiImageEditsOutput { png, metadata })
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub struct ImageEditsTestTimeouts {
    pub connect: Duration,
    pub read: Duration,
    pub total: Duration,
}

#[derive(Clone, Copy)]
struct TransportTimeouts {
    connect: Duration,
    read: Duration,
    total: Duration,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpenAiImageEditsOutput {
    pub png: Vec<u8>,
    pub metadata: OpenAiImageEditsResponseMetadata,
}

impl fmt::Debug for OpenAiImageEditsOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiImageEditsOutput")
            .field("png", &"[REDACTED]")
            .field("metadata", &self.metadata)
            .finish()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OpenAiImageEditsResponseMetadata {
    pub request_id: Option<String>,
    pub retained_headers: BTreeMap<String, String>,
    pub status: u16,
    pub latency_ms: u64,
    pub response_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiImageEditsFailureKind {
    ModerationBlocked,
    RateLimited,
    ProviderFailure,
    ProviderUnavailable,
    OutcomeUnknown,
    Authentication,
    PermissionDenied,
    RequestRejected,
    ProviderProtocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiImageEditsDispatch {
    NotSent,
    Responded,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiImageEditsErrorDetail {
    ClientConfiguration,
    InvalidCredential,
    ReferenceCount,
    ReferenceEmpty,
    ReferenceTooLarge,
    AggregateReferencesTooLarge,
    InvalidPng,
    AnimatedPng,
    ReferenceMetadata,
    ImageDimensionLimit,
    RequestTooLarge,
    TransportConnect,
    TransportExecution,
    ConnectTimeout,
    AttemptTimeout,
    ResponseRead,
    ResponseReadTimeout,
    ResponseHeaderCount,
    ResponseHeaderBytes,
    ResponseHeaderValue,
    InvalidResponseHeaders,
    UnsupportedMediaType,
    HttpStatus,
    ResponseTooLarge,
    MalformedResponseJson,
    InvalidImageResultCount,
    InvalidBase64,
    OutputTooLarge,
    InvalidOutputDimensions,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAiImageEditsError {
    pub kind: OpenAiImageEditsFailureKind,
    pub dispatch: OpenAiImageEditsDispatch,
    pub detail: OpenAiImageEditsErrorDetail,
    pub status: Option<u16>,
    pub metadata: Option<OpenAiImageEditsResponseMetadata>,
}

impl OpenAiImageEditsError {
    pub fn outcome_is_unknown(&self) -> bool {
        self.dispatch == OpenAiImageEditsDispatch::Unknown
            || self.kind == OpenAiImageEditsFailureKind::OutcomeUnknown
    }

    pub fn failed_before_send(&self) -> bool {
        self.dispatch == OpenAiImageEditsDispatch::NotSent
    }
}

impl fmt::Display for OpenAiImageEditsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "OpenAI image edits operation failed: {:?}/{:?}/{:?}",
            self.kind, self.dispatch, self.detail
        )
    }
}

impl std::error::Error for OpenAiImageEditsError {}

#[derive(Deserialize)]
struct ImageEditsResponse {
    data: Vec<ImageEditsData>,
}

#[derive(Deserialize)]
struct ImageEditsData {
    b64_json: String,
}

fn validate_api_key(api_key: &SecretString) -> Result<(), OpenAiImageEditsError> {
    let value = api_key.expose_secret();
    if value.is_empty()
        || value.len() > MAX_API_KEY_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(error_not_sent(
            OpenAiImageEditsErrorDetail::InvalidCredential,
        ));
    }
    Ok(())
}

fn validate_request(request: OpenAiImageEditsRequest<'_>) -> Result<(), OpenAiImageEditsError> {
    if !(OPENAI_IMAGE_MIN_GARMENTS..=OPENAI_IMAGE_MAX_GARMENTS)
        .contains(&request.garment_pngs.len())
    {
        return Err(error_not_sent(OpenAiImageEditsErrorDetail::ReferenceCount));
    }
    let references =
        std::iter::once(request.portrait_png).chain(request.garment_pngs.iter().copied());
    let mut aggregate = 0_usize;
    for bytes in references {
        if bytes.is_empty() {
            return Err(error_not_sent(OpenAiImageEditsErrorDetail::ReferenceEmpty));
        }
        if bytes.len() > OPENAI_IMAGE_REFERENCE_LIMIT_BYTES {
            return Err(error_not_sent(
                OpenAiImageEditsErrorDetail::ReferenceTooLarge,
            ));
        }
        aggregate = aggregate.saturating_add(bytes.len());
        if aggregate > OPENAI_IMAGE_REFERENCES_LIMIT_BYTES {
            return Err(error_not_sent(
                OpenAiImageEditsErrorDetail::AggregateReferencesTooLarge,
            ));
        }
        validate_png(bytes, None, true).map_err(error_not_sent)?;
    }
    Ok(())
}

fn build_form(request: OpenAiImageEditsRequest<'_>) -> Result<Form, OpenAiImageEditsError> {
    let mut form = Form::new()
        .text("model", OPENAI_IMAGE_EDITS_MODEL)
        .text("prompt", OPENAI_IMAGE_EDITS_PROMPT);
    for (index, bytes) in std::iter::once(request.portrait_png)
        .chain(request.garment_pngs.iter().copied())
        .enumerate()
    {
        let filename = format!("reference-{index:02}.png");
        let part = Part::bytes(bytes.to_vec())
            .file_name(filename)
            .mime_str("image/png")
            .map_err(|_| error_not_sent(OpenAiImageEditsErrorDetail::ClientConfiguration))?;
        form = form.part("image[]", part);
    }
    form = form
        .text("size", OPENAI_IMAGE_EDITS_SIZE)
        .text("quality", OPENAI_IMAGE_EDITS_QUALITY)
        .text("output_format", OPENAI_IMAGE_EDITS_OUTPUT_FORMAT);

    let body_length = multipart_body_length_upper_bound(form.boundary(), request);
    if body_length > OPENAI_IMAGE_REQUEST_LIMIT_BYTES {
        return Err(error_not_sent(OpenAiImageEditsErrorDetail::RequestTooLarge));
    }
    Ok(form)
}

fn multipart_body_length_upper_bound(
    boundary: &str,
    request: OpenAiImageEditsRequest<'_>,
) -> usize {
    let mut length = 0_usize;
    for (name, value) in [
        ("model", OPENAI_IMAGE_EDITS_MODEL),
        ("prompt", OPENAI_IMAGE_EDITS_PROMPT),
    ] {
        length = length.saturating_add(multipart_part_length(
            boundary,
            name,
            None,
            None,
            value.len(),
        ));
    }
    for (index, bytes) in std::iter::once(request.portrait_png)
        .chain(request.garment_pngs.iter().copied())
        .enumerate()
    {
        length = length.saturating_add(multipart_part_length(
            boundary,
            "image[]",
            Some(&format!("reference-{index:02}.png")),
            Some("image/png"),
            bytes.len(),
        ));
    }
    for (name, value) in [
        ("size", OPENAI_IMAGE_EDITS_SIZE),
        ("quality", OPENAI_IMAGE_EDITS_QUALITY),
        ("output_format", OPENAI_IMAGE_EDITS_OUTPUT_FORMAT),
    ] {
        length = length.saturating_add(multipart_part_length(
            boundary,
            name,
            None,
            None,
            value.len(),
        ));
    }
    length
        .saturating_add(2)
        .saturating_add(boundary.len())
        .saturating_add(4)
}

fn multipart_part_length(
    boundary: &str,
    name: &str,
    filename: Option<&str>,
    media_type: Option<&str>,
    value_length: usize,
) -> usize {
    let mut length = 2_usize
        .saturating_add(boundary.len())
        .saturating_add(2)
        .saturating_add("Content-Disposition: form-data; name=\"".len())
        .saturating_add(name.len())
        .saturating_add(1);
    if let Some(filename) = filename {
        length = length
            .saturating_add("; filename=\"".len())
            .saturating_add(filename.len())
            .saturating_add(1);
    }
    if let Some(media_type) = media_type {
        length = length
            .saturating_add("\r\nContent-Type: ".len())
            .saturating_add(media_type.len());
    }
    length
        .saturating_add(4)
        .saturating_add(value_length)
        .saturating_add(2)
}

fn validate_png(
    bytes: &[u8],
    expected_dimensions: Option<(u32, u32)>,
    require_metadata_free: bool,
) -> Result<(), OpenAiImageEditsErrorDetail> {
    validate_png_container(bytes, require_metadata_free)?;
    if image::guess_format(bytes).map_err(|_| OpenAiImageEditsErrorDetail::InvalidPng)?
        != ImageFormat::Png
    {
        return Err(OpenAiImageEditsErrorDetail::InvalidPng);
    }
    let decoder =
        PngDecoder::new(Cursor::new(bytes)).map_err(|_| OpenAiImageEditsErrorDetail::InvalidPng)?;
    if decoder
        .is_apng()
        .map_err(|_| OpenAiImageEditsErrorDetail::InvalidPng)?
    {
        return Err(OpenAiImageEditsErrorDetail::AnimatedPng);
    }
    let (width, height) = decoder.dimensions();
    if width == 0
        || height == 0
        || width > OPENAI_IMAGE_AXIS_LIMIT
        || height > OPENAI_IMAGE_AXIS_LIMIT
        || u64::from(width).saturating_mul(u64::from(height)) > OPENAI_IMAGE_PIXEL_LIMIT
    {
        return Err(OpenAiImageEditsErrorDetail::ImageDimensionLimit);
    }
    if expected_dimensions.is_some_and(|expected| expected != (width, height)) {
        return Err(OpenAiImageEditsErrorDetail::InvalidOutputDimensions);
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(OPENAI_IMAGE_AXIS_LIMIT);
    limits.max_image_height = Some(OPENAI_IMAGE_AXIS_LIMIT);
    limits.max_alloc = Some(MAX_IMAGE_DECODE_ALLOCATION);
    let mut reader = ImageReader::with_format(BufReader::new(Cursor::new(bytes)), ImageFormat::Png);
    reader.limits(limits);
    reader
        .decode()
        .map_err(|_| OpenAiImageEditsErrorDetail::InvalidPng)?;
    Ok(())
}

fn validate_png_container(
    bytes: &[u8],
    require_metadata_free: bool,
) -> Result<(), OpenAiImageEditsErrorDetail> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if !bytes.starts_with(SIGNATURE) {
        return Err(OpenAiImageEditsErrorDetail::InvalidPng);
    }
    let mut offset = SIGNATURE.len();
    let mut first = true;
    loop {
        let header_end = offset
            .checked_add(8)
            .ok_or(OpenAiImageEditsErrorDetail::InvalidPng)?;
        if header_end > bytes.len() {
            return Err(OpenAiImageEditsErrorDetail::InvalidPng);
        }
        let chunk_length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .map_err(|_| OpenAiImageEditsErrorDetail::InvalidPng)?,
        ) as usize;
        let chunk_type = &bytes[offset + 4..offset + 8];
        if first && (chunk_type != b"IHDR" || chunk_length != 13) {
            return Err(OpenAiImageEditsErrorDetail::InvalidPng);
        }
        first = false;
        if chunk_type == b"acTL" {
            return Err(OpenAiImageEditsErrorDetail::AnimatedPng);
        }
        if require_metadata_free && !matches!(chunk_type, b"IHDR" | b"PLTE" | b"IDAT" | b"IEND") {
            return Err(OpenAiImageEditsErrorDetail::ReferenceMetadata);
        }
        let chunk_end = header_end
            .checked_add(chunk_length)
            .and_then(|value| value.checked_add(4))
            .ok_or(OpenAiImageEditsErrorDetail::InvalidPng)?;
        if chunk_end > bytes.len() {
            return Err(OpenAiImageEditsErrorDetail::InvalidPng);
        }
        if chunk_type == b"IEND" {
            if chunk_length != 0 || chunk_end != bytes.len() {
                return Err(OpenAiImageEditsErrorDetail::InvalidPng);
            }
            return Ok(());
        }
        offset = chunk_end;
    }
}

fn validate_response_headers(headers: &HeaderMap) -> Result<(), OpenAiImageEditsError> {
    let mut count = 0_usize;
    let mut aggregate = 0_usize;
    for (name, value) in headers {
        count = count.saturating_add(1);
        if count > OPENAI_IMAGE_RESPONSE_HEADER_LIMIT {
            return Err(error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::ResponseHeaderCount,
                None,
                None,
            ));
        }
        if value.as_bytes().len() > OPENAI_IMAGE_RESPONSE_HEADER_VALUE_LIMIT {
            return Err(error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::ResponseHeaderValue,
                None,
                None,
            ));
        }
        aggregate = aggregate
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len());
        if aggregate > OPENAI_IMAGE_RESPONSE_HEADER_BYTES_LIMIT {
            return Err(error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::ResponseHeaderBytes,
                None,
                None,
            ));
        }
    }
    Ok(())
}

fn validate_json_content_type(
    headers: &HeaderMap,
    status: StatusCode,
    metadata: OpenAiImageEditsResponseMetadata,
) -> Result<(), OpenAiImageEditsError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values.next().ok_or_else(|| {
        error_responded(
            OpenAiImageEditsFailureKind::ProviderProtocol,
            OpenAiImageEditsErrorDetail::UnsupportedMediaType,
            Some(status.as_u16()),
            Some(metadata.clone()),
        )
    })?;
    if values.next().is_some() {
        return Err(error_responded(
            OpenAiImageEditsFailureKind::ProviderProtocol,
            OpenAiImageEditsErrorDetail::InvalidResponseHeaders,
            Some(status.as_u16()),
            Some(metadata),
        ));
    }
    let value = value.to_str().map_err(|_| {
        error_responded(
            OpenAiImageEditsFailureKind::ProviderProtocol,
            OpenAiImageEditsErrorDetail::InvalidResponseHeaders,
            Some(status.as_u16()),
            Some(metadata.clone()),
        )
    })?;
    if !value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("application/json")
    {
        return Err(error_responded(
            OpenAiImageEditsFailureKind::ProviderProtocol,
            OpenAiImageEditsErrorDetail::UnsupportedMediaType,
            Some(status.as_u16()),
            Some(metadata),
        ));
    }
    Ok(())
}

fn response_metadata(
    response: &reqwest::Response,
    started: Instant,
) -> Result<OpenAiImageEditsResponseMetadata, OpenAiImageEditsError> {
    let headers = response.headers();
    let status = response.status().as_u16();
    let request_id = retained_header(headers, "x-request-id", MAX_REQUEST_ID_BYTES, status)?;
    let mut retained_headers = BTreeMap::new();
    for name in RETAINED_RESPONSE_HEADERS {
        if let Some(value) =
            retained_header(headers, name, MAX_RETAINED_HEADER_VALUE_BYTES, status)?
        {
            retained_headers.insert((*name).to_owned(), value);
        }
    }
    Ok(OpenAiImageEditsResponseMetadata {
        request_id,
        retained_headers,
        status,
        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        response_bytes: 0,
    })
}

fn retained_header(
    headers: &HeaderMap,
    name: &'static str,
    limit: usize,
    status: u16,
) -> Result<Option<String>, OpenAiImageEditsError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(error_responded(
            OpenAiImageEditsFailureKind::ProviderProtocol,
            OpenAiImageEditsErrorDetail::InvalidResponseHeaders,
            Some(status),
            None,
        ));
    }
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > limit || !bytes.iter().all(|byte| byte.is_ascii_graphic())
    {
        return Err(error_responded(
            OpenAiImageEditsFailureKind::ProviderProtocol,
            OpenAiImageEditsErrorDetail::InvalidResponseHeaders,
            Some(status),
            None,
        ));
    }
    let value = value.to_str().map_err(|_| {
        error_responded(
            OpenAiImageEditsFailureKind::ProviderProtocol,
            OpenAiImageEditsErrorDetail::InvalidResponseHeaders,
            Some(status),
            None,
        )
    })?;
    Ok(Some(value.to_owned()))
}

fn classify_status(status: StatusCode) -> OpenAiImageEditsFailureKind {
    match status {
        StatusCode::UNAUTHORIZED => OpenAiImageEditsFailureKind::Authentication,
        StatusCode::FORBIDDEN => OpenAiImageEditsFailureKind::PermissionDenied,
        StatusCode::TOO_MANY_REQUESTS => OpenAiImageEditsFailureKind::RateLimited,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT => {
            OpenAiImageEditsFailureKind::ProviderUnavailable
        }
        status if status.is_server_error() => OpenAiImageEditsFailureKind::ProviderFailure,
        status if status.is_client_error() => OpenAiImageEditsFailureKind::RequestRejected,
        _ => OpenAiImageEditsFailureKind::ProviderProtocol,
    }
}

fn exact_moderation_blocked(json: &Value) -> bool {
    json.get("error")
        .and_then(Value::as_object)
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
        == Some("moderation_blocked")
}

fn map_send_error(error: reqwest::Error) -> OpenAiImageEditsError {
    if error.is_timeout() {
        if error.is_connect() {
            return error_not_sent_with_kind(
                OpenAiImageEditsFailureKind::ProviderUnavailable,
                OpenAiImageEditsErrorDetail::ConnectTimeout,
            );
        }
        return error_unknown(OpenAiImageEditsErrorDetail::AttemptTimeout, None, None);
    }
    if error.is_connect() {
        error_not_sent_with_kind(
            OpenAiImageEditsFailureKind::ProviderUnavailable,
            OpenAiImageEditsErrorDetail::TransportConnect,
        )
    } else {
        error_unknown(OpenAiImageEditsErrorDetail::TransportExecution, None, None)
    }
}

async fn read_bounded_body(
    mut response: reqwest::Response,
    limit: usize,
    status: Option<u16>,
    metadata: Option<OpenAiImageEditsResponseMetadata>,
) -> Result<Vec<u8>, OpenAiImageEditsError> {
    let mut body = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(|error| {
            error_unknown(
                if error.is_timeout() {
                    OpenAiImageEditsErrorDetail::ResponseReadTimeout
                } else {
                    OpenAiImageEditsErrorDetail::ResponseRead
                },
                status,
                metadata.clone(),
            )
        })?;
        let Some(chunk) = chunk else {
            return Ok(body);
        };
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(error_responded(
                OpenAiImageEditsFailureKind::ProviderProtocol,
                OpenAiImageEditsErrorDetail::ResponseTooLarge,
                status,
                metadata,
            ));
        }
        body.extend_from_slice(&chunk);
    }
}

fn error_not_sent(detail: OpenAiImageEditsErrorDetail) -> OpenAiImageEditsError {
    let kind = match detail {
        OpenAiImageEditsErrorDetail::InvalidCredential => {
            OpenAiImageEditsFailureKind::Authentication
        }
        OpenAiImageEditsErrorDetail::ClientConfiguration => {
            OpenAiImageEditsFailureKind::ProviderProtocol
        }
        _ => OpenAiImageEditsFailureKind::RequestRejected,
    };
    error_not_sent_with_kind(kind, detail)
}

fn error_not_sent_with_kind(
    kind: OpenAiImageEditsFailureKind,
    detail: OpenAiImageEditsErrorDetail,
) -> OpenAiImageEditsError {
    OpenAiImageEditsError {
        kind,
        dispatch: OpenAiImageEditsDispatch::NotSent,
        detail,
        status: None,
        metadata: None,
    }
}

fn error_responded(
    kind: OpenAiImageEditsFailureKind,
    detail: OpenAiImageEditsErrorDetail,
    status: Option<u16>,
    metadata: Option<OpenAiImageEditsResponseMetadata>,
) -> OpenAiImageEditsError {
    OpenAiImageEditsError {
        kind,
        dispatch: OpenAiImageEditsDispatch::Responded,
        detail,
        status,
        metadata,
    }
}

fn error_unknown(
    detail: OpenAiImageEditsErrorDetail,
    status: Option<u16>,
    metadata: Option<OpenAiImageEditsResponseMetadata>,
) -> OpenAiImageEditsError {
    OpenAiImageEditsError {
        kind: OpenAiImageEditsFailureKind::OutcomeUnknown,
        dispatch: OpenAiImageEditsDispatch::Unknown,
        detail,
        status,
        metadata,
    }
}
