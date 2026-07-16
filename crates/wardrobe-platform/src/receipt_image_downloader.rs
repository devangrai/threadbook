use hickory_resolver::TokioResolver;
use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::{GenericImageView, ImageEncoder, ImageFormat, ImageReader, Limits};
use ipnet::IpNet;
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use reqwest::{redirect::Policy, StatusCode};
use std::future::Future;
use std::io::{Cursor, Write};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::{OnceCell, Semaphore};
use tokio::time::{timeout_at, Instant as TokioInstant};
use url::{Host, Url};
use wardrobe_core::Sha256Digest;
pub use wardrobe_core::{
    ReceiptImageDownloadV1, ReceiptImageDownloader, ReceiptImageFailureCodeV1,
    ReceiptImageHopProvenanceV1,
};

pub const RECEIPT_IMAGE_POLICY_REVISION: &str = "receipt-image-network-policy-v1";
pub const RECEIPT_IMAGE_DECODER_REVISION: &str = "image-0.25.10-v1";
pub const RECEIPT_IMAGE_DERIVATIVE_REVISION: &str = "png-rgba8-best-paeth-v1";
pub const MAX_RECEIPT_IMAGE_ENCODED_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_RECEIPT_IMAGE_DECODED_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RECEIPT_IMAGE_DERIVATIVE_BYTES: usize = 68 * 1024 * 1024;
pub const MAX_RECEIPT_IMAGE_AXIS: u32 = 4_096;
pub const MIN_RECEIPT_IMAGE_AXIS: u32 = 32;
pub const MAX_RECEIPT_IMAGE_PIXELS: u64 = 16_777_216;
pub const MAX_RECEIPT_IMAGE_HEADERS: usize = 64;
pub const MAX_RECEIPT_IMAGE_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_RECEIPT_IMAGE_REDIRECTS: usize = 3;
pub const MAX_RECEIPT_IMAGE_DNS_ANSWERS: usize = 16;
pub const RECEIPT_IMAGE_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(10);

pub trait ReceiptImageResolver: Clone + Send + Sync + 'static {
    fn lookup_ip(
        &self,
        host: &str,
    ) -> impl Future<Output = Result<Vec<SocketAddr>, ReceiptImageFailureCodeV1>> + Send;
}

#[derive(Clone)]
pub struct HickorySystemResolver {
    resolver: Arc<OnceCell<TokioResolver>>,
}

impl HickorySystemResolver {
    pub fn from_system_config() -> Result<Self, ReceiptImageFailureCodeV1> {
        Ok(Self {
            resolver: Arc::new(OnceCell::new()),
        })
    }
}

impl ReceiptImageResolver for HickorySystemResolver {
    async fn lookup_ip(&self, host: &str) -> Result<Vec<SocketAddr>, ReceiptImageFailureCodeV1> {
        let resolver = self
            .resolver
            .get_or_try_init(|| async {
                let builder = TokioResolver::builder_tokio()
                    .map_err(|_| ReceiptImageFailureCodeV1::DnsFailed)?;
                builder
                    .build()
                    .map_err(|_| ReceiptImageFailureCodeV1::DnsFailed)
            })
            .await?;
        let lookup = resolver
            .lookup_ip(host)
            .await
            .map_err(|_| ReceiptImageFailureCodeV1::DnsFailed)?;
        Ok(lookup
            .iter()
            .map(|address| SocketAddr::new(address, 443))
            .collect())
    }
}

pub trait ReceiptImageAddressPolicy: Clone + Send + Sync + 'static {
    fn validate(&self, addresses: &[SocketAddr]) -> Result<(), ReceiptImageFailureCodeV1>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SealedProductionAddressPolicy {
    _sealed: (),
}

impl SealedProductionAddressPolicy {
    pub const fn new() -> Self {
        Self { _sealed: () }
    }

    pub fn permits(address: IpAddr) -> bool {
        !is_special_address(address)
    }
}

impl ReceiptImageAddressPolicy for SealedProductionAddressPolicy {
    fn validate(&self, addresses: &[SocketAddr]) -> Result<(), ReceiptImageFailureCodeV1> {
        if addresses.is_empty()
            || addresses.len() > MAX_RECEIPT_IMAGE_DNS_ANSWERS
            || addresses
                .iter()
                .any(|address| address.port() != 443 || !Self::permits(address.ip()))
        {
            Err(ReceiptImageFailureCodeV1::AddressRejected)
        } else {
            Ok(())
        }
    }
}

pub trait ReceiptImageClock: Clone + Send + Sync + 'static {
    fn now(&self) -> Instant;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl ReceiptImageClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptImageDownloadRequestV1 {
    pub normalized_url: String,
    pub approved_display_host: String,
    pub deadline: Instant,
}

#[derive(Clone)]
pub struct ReqwestReceiptImageDownloader<R, C, P> {
    resolver: R,
    clock: C,
    address_policy: P,
    additional_roots: Vec<reqwest::Certificate>,
}

pub type ProductionReceiptImageDownloader = ReqwestReceiptImageDownloader<
    HickorySystemResolver,
    SystemClock,
    SealedProductionAddressPolicy,
>;

impl ProductionReceiptImageDownloader {
    pub fn from_system_config() -> Result<Self, ReceiptImageFailureCodeV1> {
        Ok(Self::new(
            HickorySystemResolver::from_system_config()?,
            SystemClock,
            SealedProductionAddressPolicy::new(),
        ))
    }
}

impl<R, C, P> ReqwestReceiptImageDownloader<R, C, P>
where
    R: ReceiptImageResolver,
    C: ReceiptImageClock,
    P: ReceiptImageAddressPolicy,
{
    pub fn new(resolver: R, clock: C, address_policy: P) -> Self {
        Self {
            resolver,
            clock,
            address_policy,
            additional_roots: Vec::new(),
        }
    }

    #[doc(hidden)]
    pub fn with_additional_root_certificate(mut self, certificate: reqwest::Certificate) -> Self {
        self.additional_roots.push(certificate);
        self
    }

    pub async fn download(
        &self,
        normalized_url: String,
        approved_display_host: String,
    ) -> Result<ReceiptImageDownloadV1, ReceiptImageFailureCodeV1> {
        let deadline = self
            .clock
            .now()
            .checked_add(RECEIPT_IMAGE_DOWNLOAD_TIMEOUT)
            .ok_or(ReceiptImageFailureCodeV1::DeadlineExceeded)?;
        self.download_with_deadline(ReceiptImageDownloadRequestV1 {
            normalized_url,
            approved_display_host,
            deadline,
        })
        .await
    }

    pub async fn download_with_deadline(
        &self,
        request: ReceiptImageDownloadRequestV1,
    ) -> Result<ReceiptImageDownloadV1, ReceiptImageFailureCodeV1> {
        ensure_before_deadline(&self.clock, request.deadline)?;
        let deadline = TokioInstant::from_std(request.deadline);
        let approved_host = normalize_approved_host(&request.approved_display_host)?;
        let mut current = validate_network_url(&request.normalized_url)?;
        if network_host(&current)? != approved_host {
            return Err(ReceiptImageFailureCodeV1::HostMismatch);
        }

        let mut hops = Vec::with_capacity(MAX_RECEIPT_IMAGE_REDIRECTS + 1);
        for redirect_count in 0..=MAX_RECEIPT_IMAGE_REDIRECTS {
            ensure_before_deadline(&self.clock, request.deadline)?;
            let host = network_host(&current)?;
            if host != approved_host {
                return Err(ReceiptImageFailureCodeV1::RedirectCrossHost);
            }

            let socket_addresses = timeout_at(deadline, self.resolver.lookup_ip(&host))
                .await
                .map_err(|_| ReceiptImageFailureCodeV1::DeadlineExceeded)??;
            if socket_addresses.is_empty() || socket_addresses.len() > MAX_RECEIPT_IMAGE_DNS_ANSWERS
            {
                return Err(ReceiptImageFailureCodeV1::DnsAnswerLimit);
            }
            self.address_policy.validate(&socket_addresses)?;
            let mut socket_addresses = socket_addresses;
            socket_addresses.sort_unstable();
            socket_addresses.dedup();

            ensure_before_deadline(&self.clock, request.deadline)?;
            let remaining = request
                .deadline
                .checked_duration_since(self.clock.now())
                .ok_or(ReceiptImageFailureCodeV1::DeadlineExceeded)?;
            let connect_timeout = remaining.min(Duration::from_secs(3));
            let mut builder = reqwest::Client::builder()
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
                .connect_timeout(connect_timeout)
                .resolve_to_addrs(&host, &socket_addresses);
            if !self.additional_roots.is_empty() {
                builder = builder.tls_certs_only(self.additional_roots.clone());
            }
            let client = builder
                .build()
                .map_err(|_| ReceiptImageFailureCodeV1::ClientBuildFailed)?;
            ensure_before_deadline(&self.clock, request.deadline)?;

            let response = timeout_at(
                deadline,
                client
                    .get(current.clone())
                    .header(ACCEPT, "image/webp,image/png,image/jpeg")
                    .send(),
            )
            .await
            .map_err(|_| ReceiptImageFailureCodeV1::DeadlineExceeded)?
            .map_err(|_| ReceiptImageFailureCodeV1::TransportFailed)?;
            ensure_header_bounds(response.headers())?;

            let status = response.status();
            hops.push(ReceiptImageHopProvenanceV1 {
                ordinal: u8::try_from(hops.len())
                    .map_err(|_| ReceiptImageFailureCodeV1::RedirectLimit)?,
                host_sha256: Sha256Digest::from_bytes(host.as_bytes()),
                url_sha256: Sha256Digest::from_bytes(current.as_str().as_bytes()),
                pinned_addresses: socket_addresses
                    .iter()
                    .map(|address| format!("{}", address.ip()))
                    .collect(),
                http_status: status.as_u16(),
            });
            if is_redirect(status) {
                if redirect_count == MAX_RECEIPT_IMAGE_REDIRECTS {
                    return Err(ReceiptImageFailureCodeV1::RedirectLimit);
                }
                let location = single_bounded_header(response.headers(), LOCATION, 2_048)?
                    .ok_or(ReceiptImageFailureCodeV1::RedirectLocationRejected)?;
                let mut next = current
                    .join(location)
                    .map_err(|_| ReceiptImageFailureCodeV1::RedirectLocationRejected)?;
                next.set_fragment(None);
                validate_network_url(next.as_str())?;
                if network_host(&next)? != approved_host {
                    return Err(ReceiptImageFailureCodeV1::RedirectCrossHost);
                }
                current = next;
                continue;
            }
            if status != StatusCode::OK {
                return Err(ReceiptImageFailureCodeV1::HttpStatusRejected);
            }

            let media_type = parse_media_type(response.headers())?;
            let declared_length = parse_content_length(response.headers())?;
            if declared_length.is_some_and(|length| length > MAX_RECEIPT_IMAGE_ENCODED_BYTES as u64)
            {
                return Err(ReceiptImageFailureCodeV1::BodyLimit);
            }
            let mut response = response;
            let mut source_bytes =
                Vec::with_capacity(declared_length.unwrap_or(0).min(64 * 1024) as usize);
            while let Some(chunk) = timeout_at(deadline, response.chunk())
                .await
                .map_err(|_| ReceiptImageFailureCodeV1::DeadlineExceeded)?
                .map_err(|_| ReceiptImageFailureCodeV1::TransportFailed)?
            {
                if source_bytes.len().saturating_add(chunk.len()) > MAX_RECEIPT_IMAGE_ENCODED_BYTES
                {
                    return Err(ReceiptImageFailureCodeV1::BodyLimit);
                }
                source_bytes.extend_from_slice(&chunk);
            }
            if declared_length.is_some_and(|length| length != source_bytes.len() as u64) {
                return Err(ReceiptImageFailureCodeV1::ContentLengthRejected);
            }
            let format = detect_and_match_format(&source_bytes, &media_type)?;
            validate_image_structure(&source_bytes, format, deadline).await?;
            let (display_png_bytes, width, height) =
                decode_and_derive(source_bytes.clone(), format, deadline).await?;
            let source_sha256 = Sha256Digest::from_bytes(&source_bytes);
            let display_sha256 = Sha256Digest::from_bytes(&display_png_bytes);
            return Ok(ReceiptImageDownloadV1 {
                source_bytes,
                source_sha256,
                source_media_type: media_type,
                display_png_bytes,
                display_sha256,
                width,
                height,
                final_url_sha256: Sha256Digest::from_bytes(current.as_str().as_bytes()),
                declared_length,
                hops,
                policy_revision: RECEIPT_IMAGE_POLICY_REVISION.to_owned(),
                decoder_revision: RECEIPT_IMAGE_DECODER_REVISION.to_owned(),
                derivative_revision: RECEIPT_IMAGE_DERIVATIVE_REVISION.to_owned(),
            });
        }
        Err(ReceiptImageFailureCodeV1::RedirectLimit)
    }
}

impl<R, C, P> ReceiptImageDownloader for ReqwestReceiptImageDownloader<R, C, P>
where
    R: ReceiptImageResolver,
    C: ReceiptImageClock,
    P: ReceiptImageAddressPolicy,
{
    async fn download(
        &self,
        normalized_url: String,
        approved_display_host: String,
    ) -> Result<ReceiptImageDownloadV1, ReceiptImageFailureCodeV1> {
        ReqwestReceiptImageDownloader::download(self, normalized_url, approved_display_host).await
    }
}

fn normalize_approved_host(value: &str) -> Result<String, ReceiptImageFailureCodeV1> {
    let normalized = value.to_ascii_lowercase();
    let normalized = normalized.trim_end_matches('.');
    if normalized.is_empty()
        || normalized.len() > 253
        || !normalized.is_ascii()
        || normalized.parse::<IpAddr>().is_ok()
        || normalized.contains(['/', '@', ':'])
    {
        return Err(ReceiptImageFailureCodeV1::HostMismatch);
    }
    Ok(normalized.to_owned())
}

fn validate_network_url(value: &str) -> Result<Url, ReceiptImageFailureCodeV1> {
    if value.len() > 2_048 {
        return Err(ReceiptImageFailureCodeV1::InvalidUrl);
    }
    let mut url = Url::parse(value).map_err(|_| ReceiptImageFailureCodeV1::InvalidUrl)?;
    if url.scheme() != "https" {
        return Err(ReceiptImageFailureCodeV1::SchemeRejected);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ReceiptImageFailureCodeV1::UserInfoRejected);
    }
    match url.host() {
        Some(Host::Domain(_)) => {}
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => {
            return Err(ReceiptImageFailureCodeV1::IpLiteralRejected);
        }
        None => return Err(ReceiptImageFailureCodeV1::InvalidUrl),
    }
    if url.port().is_some_and(|port| port != 443) || url.port_or_known_default() != Some(443) {
        return Err(ReceiptImageFailureCodeV1::PortRejected);
    }
    url.set_fragment(None);
    Ok(url)
}

fn network_host(url: &Url) -> Result<String, ReceiptImageFailureCodeV1> {
    match url.host() {
        Some(Host::Domain(host)) => {
            let host = host.to_ascii_lowercase();
            let host = host.trim_end_matches('.');
            if host.is_empty() || host.len() > 253 || !host.is_ascii() {
                Err(ReceiptImageFailureCodeV1::InvalidUrl)
            } else {
                Ok(host.to_owned())
            }
        }
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => Err(ReceiptImageFailureCodeV1::IpLiteralRejected),
        None => Err(ReceiptImageFailureCodeV1::InvalidUrl),
    }
}

fn ensure_before_deadline<C: ReceiptImageClock>(
    clock: &C,
    deadline: Instant,
) -> Result<(), ReceiptImageFailureCodeV1> {
    if clock.now() < deadline {
        Ok(())
    } else {
        Err(ReceiptImageFailureCodeV1::DeadlineExceeded)
    }
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
}

fn ensure_header_bounds(headers: &HeaderMap) -> Result<(), ReceiptImageFailureCodeV1> {
    if headers.len() > MAX_RECEIPT_IMAGE_HEADERS {
        return Err(ReceiptImageFailureCodeV1::HeaderLimit);
    }
    let mut aggregate = 0_usize;
    for (name, value) in headers {
        aggregate = aggregate
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .ok_or(ReceiptImageFailureCodeV1::HeaderLimit)?;
        if aggregate > MAX_RECEIPT_IMAGE_HEADER_BYTES {
            return Err(ReceiptImageFailureCodeV1::HeaderLimit);
        }
    }
    Ok(())
}

fn single_bounded_header(
    headers: &HeaderMap,
    name: reqwest::header::HeaderName,
    max_bytes: usize,
) -> Result<Option<&str>, ReceiptImageFailureCodeV1> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || value.as_bytes().len() > max_bytes {
        return Err(ReceiptImageFailureCodeV1::HeaderLimit);
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| ReceiptImageFailureCodeV1::HeaderLimit)
}

fn parse_content_length(headers: &HeaderMap) -> Result<Option<u64>, ReceiptImageFailureCodeV1> {
    let Some(value) = single_bounded_header(headers, CONTENT_LENGTH, 32)
        .map_err(|_| ReceiptImageFailureCodeV1::ContentLengthRejected)?
    else {
        return Ok(None);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ReceiptImageFailureCodeV1::ContentLengthRejected);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| ReceiptImageFailureCodeV1::ContentLengthRejected)
}

fn parse_media_type(headers: &HeaderMap) -> Result<String, ReceiptImageFailureCodeV1> {
    let value = single_bounded_header(headers, CONTENT_TYPE, 128)?
        .ok_or(ReceiptImageFailureCodeV1::MediaTypeRejected)?;
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if matches!(
        media_type.as_str(),
        "image/jpeg" | "image/png" | "image/webp"
    ) {
        Ok(media_type)
    } else {
        Err(ReceiptImageFailureCodeV1::MediaTypeRejected)
    }
}

fn detect_and_match_format(
    bytes: &[u8],
    media_type: &str,
) -> Result<ImageFormat, ReceiptImageFailureCodeV1> {
    let format = if bytes.starts_with(&[0xff, 0xd8]) {
        ImageFormat::Jpeg
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        ImageFormat::Png
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        ImageFormat::WebP
    } else {
        return Err(ReceiptImageFailureCodeV1::MagicMismatch);
    };
    let matches = matches!(
        (media_type, format),
        ("image/jpeg", ImageFormat::Jpeg)
            | ("image/png", ImageFormat::Png)
            | ("image/webp", ImageFormat::WebP)
    );
    if matches {
        Ok(format)
    } else {
        Err(ReceiptImageFailureCodeV1::MagicMismatch)
    }
}

async fn validate_image_structure(
    bytes: &[u8],
    format: ImageFormat,
    deadline: TokioInstant,
) -> Result<(), ReceiptImageFailureCodeV1> {
    match format {
        ImageFormat::Jpeg => validate_jpeg(bytes, deadline).await,
        ImageFormat::Png => validate_png(bytes, deadline).await,
        ImageFormat::WebP => validate_webp(bytes, deadline).await,
        _ => Err(ReceiptImageFailureCodeV1::StructureRejected),
    }
}

async fn validate_jpeg(
    bytes: &[u8],
    deadline: TokioInstant,
) -> Result<(), ReceiptImageFailureCodeV1> {
    if bytes.len() < 4 || !bytes.starts_with(&[0xff, 0xd8]) {
        return Err(ReceiptImageFailureCodeV1::StructureRejected);
    }
    let mut offset = 2_usize;
    let mut saw_sof = false;
    let mut saw_sos = false;
    let mut yielded_at = 0_usize;
    while offset < bytes.len() {
        cooperative_checkpoint(offset, &mut yielded_at, deadline).await?;
        if bytes[offset] != 0xff {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        while offset < bytes.len() && bytes[offset] == 0xff {
            offset += 1;
        }
        let marker = *bytes
            .get(offset)
            .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
        offset += 1;
        if marker == 0xd9 {
            return if saw_sof && saw_sos && offset == bytes.len() {
                Ok(())
            } else {
                Err(ReceiptImageFailureCodeV1::StructureRejected)
            };
        }
        if marker == 0xd8 || marker == 0x00 || (0xd0..=0xd7).contains(&marker) {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        let length = read_be_u16(bytes, offset)? as usize;
        if length < 2 {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        let payload_start = offset
            .checked_add(2)
            .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
        let segment_end = offset
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
        let is_sof = matches!(
            marker,
            0xc0 | 0xc1
                | 0xc2
                | 0xc3
                | 0xc5
                | 0xc6
                | 0xc7
                | 0xc9
                | 0xca
                | 0xcb
                | 0xcd
                | 0xce
                | 0xcf
        );
        if is_sof {
            if saw_sof {
                return Err(ReceiptImageFailureCodeV1::StructureRejected);
            }
            saw_sof = true;
        }
        if marker == 0xe2
            && bytes
                .get(payload_start..segment_end)
                .is_some_and(|payload| payload.starts_with(b"MPF\0"))
        {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        offset = segment_end;
        if marker == 0xda {
            saw_sos = true;
            loop {
                cooperative_checkpoint(offset, &mut yielded_at, deadline).await?;
                let byte = *bytes
                    .get(offset)
                    .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
                if byte != 0xff {
                    offset += 1;
                    continue;
                }
                let mut next = offset + 1;
                while bytes.get(next) == Some(&0xff) {
                    next += 1;
                }
                match bytes.get(next).copied() {
                    Some(0x00) => offset = next + 1,
                    Some(0xd0..=0xd7) => offset = next + 1,
                    Some(_) => break,
                    None => return Err(ReceiptImageFailureCodeV1::StructureRejected),
                }
            }
        }
    }
    Err(ReceiptImageFailureCodeV1::StructureRejected)
}

async fn validate_png(
    bytes: &[u8],
    deadline: TokioInstant,
) -> Result<(), ReceiptImageFailureCodeV1> {
    if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err(ReceiptImageFailureCodeV1::StructureRejected);
    }
    let mut offset = 8_usize;
    let mut chunks = 0_usize;
    let mut saw_ihdr = false;
    let mut saw_idat = false;
    let mut idat_ended = false;
    let mut yielded_at = 0_usize;
    while offset < bytes.len() {
        cooperative_checkpoint(offset, &mut yielded_at, deadline).await?;
        chunks += 1;
        if chunks > 4_096 {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        let length = read_be_u32(bytes, offset)? as usize;
        let kind_start = offset
            .checked_add(4)
            .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
        let data_start = kind_start
            .checked_add(4)
            .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
        let data_end = data_start
            .checked_add(length)
            .filter(|end| end.saturating_add(4) <= bytes.len())
            .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
        let end = data_end + 4;
        let kind = &bytes[kind_start..data_start];
        let expected_crc = read_be_u32(bytes, data_end)?;
        if png_crc32(&bytes[kind_start..data_end]) != expected_crc {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        if chunks == 1 {
            if kind != b"IHDR" || length != 13 {
                return Err(ReceiptImageFailureCodeV1::StructureRejected);
            }
            saw_ihdr = true;
        } else if kind == b"IHDR" {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        if matches!(kind, b"acTL" | b"fcTL" | b"fdAT") {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        if kind == b"IDAT" {
            if idat_ended {
                return Err(ReceiptImageFailureCodeV1::StructureRejected);
            }
            saw_idat = true;
        } else if saw_idat && kind != b"IEND" {
            idat_ended = true;
        }
        if kind == b"IEND" {
            return if saw_ihdr && saw_idat && length == 0 && end == bytes.len() {
                Ok(())
            } else {
                Err(ReceiptImageFailureCodeV1::StructureRejected)
            };
        }
        offset = end;
    }
    Err(ReceiptImageFailureCodeV1::StructureRejected)
}

async fn validate_webp(
    bytes: &[u8],
    deadline: TokioInstant,
) -> Result<(), ReceiptImageFailureCodeV1> {
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return Err(ReceiptImageFailureCodeV1::StructureRejected);
    }
    let riff_size = read_le_u32(bytes, 4)? as usize;
    if riff_size.checked_add(8) != Some(bytes.len()) {
        return Err(ReceiptImageFailureCodeV1::StructureRejected);
    }
    let mut offset = 12_usize;
    let mut chunks = 0_usize;
    let mut image_payloads = 0_usize;
    let mut vp8x = false;
    let mut yielded_at = 0_usize;
    while offset < bytes.len() {
        cooperative_checkpoint(offset, &mut yielded_at, deadline).await?;
        chunks += 1;
        if chunks > 4_096 || offset.saturating_add(8) > bytes.len() {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        let kind = &bytes[offset..offset + 4];
        let length = read_le_u32(bytes, offset + 4)? as usize;
        let data_start = offset + 8;
        let data_end = data_start
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
        if matches!(kind, b"ANIM" | b"ANMF") {
            return Err(ReceiptImageFailureCodeV1::StructureRejected);
        }
        if kind == b"VP8X" {
            if vp8x || length != 10 || bytes[data_start] & 0x02 != 0 {
                return Err(ReceiptImageFailureCodeV1::StructureRejected);
            }
            vp8x = true;
        }
        if matches!(kind, b"VP8 " | b"VP8L") {
            image_payloads += 1;
            if image_payloads > 1 {
                return Err(ReceiptImageFailureCodeV1::StructureRejected);
            }
        }
        offset = data_end
            .checked_add(length & 1)
            .filter(|end| *end <= bytes.len())
            .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
    }
    if offset == bytes.len() && image_payloads == 1 {
        Ok(())
    } else {
        Err(ReceiptImageFailureCodeV1::StructureRejected)
    }
}

async fn cooperative_checkpoint(
    offset: usize,
    yielded_at: &mut usize,
    deadline: TokioInstant,
) -> Result<(), ReceiptImageFailureCodeV1> {
    if TokioInstant::now() >= deadline {
        return Err(ReceiptImageFailureCodeV1::DeadlineExceeded);
    }
    if offset.saturating_sub(*yielded_at) >= 64 * 1024 {
        tokio::task::yield_now().await;
        *yielded_at = offset;
        if TokioInstant::now() >= deadline {
            return Err(ReceiptImageFailureCodeV1::DeadlineExceeded);
        }
    }
    Ok(())
}

async fn decode_and_derive(
    source: Vec<u8>,
    format: ImageFormat,
    deadline: TokioInstant,
) -> Result<(Vec<u8>, u32, u32), ReceiptImageFailureCodeV1> {
    let semaphore = decode_semaphore();
    let permit = timeout_at(deadline, Arc::clone(semaphore).acquire_owned())
        .await
        .map_err(|_| ReceiptImageFailureCodeV1::DeadlineExceeded)?
        .map_err(|_| ReceiptImageFailureCodeV1::BlockingTaskFailed)?;
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        decode_and_derive_blocking(source, format)
    });
    timeout_at(deadline, task)
        .await
        .map_err(|_| ReceiptImageFailureCodeV1::DeadlineExceeded)?
        .map_err(|_| ReceiptImageFailureCodeV1::BlockingTaskFailed)?
}

fn decode_and_derive_blocking(
    source: Vec<u8>,
    format: ImageFormat,
) -> Result<(Vec<u8>, u32, u32), ReceiptImageFailureCodeV1> {
    let mut reader = ImageReader::with_format(Cursor::new(source), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_RECEIPT_IMAGE_AXIS);
    limits.max_image_height = Some(MAX_RECEIPT_IMAGE_AXIS);
    limits.max_alloc = Some(MAX_RECEIPT_IMAGE_DECODED_BYTES);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|_| ReceiptImageFailureCodeV1::DecodeFailed)?;
    let (width, height) = image.dimensions();
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(ReceiptImageFailureCodeV1::DimensionsRejected)?;
    let decoded_bytes = pixels
        .checked_mul(4)
        .ok_or(ReceiptImageFailureCodeV1::DimensionsRejected)?;
    if !(MIN_RECEIPT_IMAGE_AXIS..=MAX_RECEIPT_IMAGE_AXIS).contains(&width)
        || !(MIN_RECEIPT_IMAGE_AXIS..=MAX_RECEIPT_IMAGE_AXIS).contains(&height)
        || pixels > MAX_RECEIPT_IMAGE_PIXELS
        || decoded_bytes > MAX_RECEIPT_IMAGE_DECODED_BYTES
    {
        return Err(ReceiptImageFailureCodeV1::DimensionsRejected);
    }
    let rgba = image.into_rgba8();
    let mut output = BoundedWriter::new(MAX_RECEIPT_IMAGE_DERIVATIVE_BYTES);
    PngEncoder::new_with_quality(&mut output, CompressionType::Best, FilterType::Paeth)
        .write_image(&rgba, width, height, image::ExtendedColorType::Rgba8)
        .map_err(|_| ReceiptImageFailureCodeV1::DerivativeLimit)?;
    Ok((output.into_inner(), width, height))
}

fn decode_semaphore() -> &'static Arc<Semaphore> {
    static DECODE_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    DECODE_SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(2)))
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > self.limit {
            return Err(std::io::Error::other("bounded image derivative exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn read_be_u16(bytes: &[u8], offset: usize) -> Result<u16, ReceiptImageFailureCodeV1> {
    let value: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .and_then(|value| value.try_into().ok())
        .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
    Ok(u16::from_be_bytes(value))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, ReceiptImageFailureCodeV1> {
    let value: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|value| value.try_into().ok())
        .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
    Ok(u32::from_be_bytes(value))
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Result<u32, ReceiptImageFailureCodeV1> {
    let value: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|value| value.try_into().ok())
        .ok_or(ReceiptImageFailureCodeV1::StructureRejected)?;
    Ok(u32::from_le_bytes(value))
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn is_special_address(address: IpAddr) -> bool {
    const V4_DENY: &[&str] = &[
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ];
    const V6_DENY: &[&str] = &[
        "::/128",
        "::/96",
        "::1/128",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    ];
    let denied = match address {
        IpAddr::V4(_) => V4_DENY,
        IpAddr::V6(_) => V6_DENY,
    };
    if denied.iter().any(|network| {
        IpNet::from_str(network)
            .map(|network| network.contains(&address))
            .unwrap_or(true)
    }) {
        return true;
    }
    matches!(
        address,
        IpAddr::V4(address)
            if address.octets() == [168, 63, 129, 16]
                || address.octets() == [100, 100, 100, 200]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_with_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let pixels = vec![0x7f_u8; 32 * 32 * 4];
        let mut png = Vec::new();
        PngEncoder::new_with_quality(&mut png, CompressionType::Best, FilterType::Paeth)
            .write_image(&pixels, 32, 32, image::ExtendedColorType::Rgba8)
            .unwrap();
        let insert_at = 8 + 4 + 4 + 13 + 4;
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(payload);
        let mut crc_input = kind.to_vec();
        crc_input.extend_from_slice(payload);
        chunk.extend_from_slice(&png_crc32(&crc_input).to_be_bytes());
        png.splice(insert_at..insert_at, chunk);
        png
    }

    fn png_chunk_kinds(bytes: &[u8]) -> Vec<[u8; 4]> {
        let mut offset = 8_usize;
        let mut kinds = Vec::new();
        while offset + 12 <= bytes.len() {
            let length = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
            kinds.push(bytes[offset + 4..offset + 8].try_into().unwrap());
            offset += 12 + length;
        }
        kinds
    }

    #[test]
    fn production_policy_rejects_special_ranges_and_allows_global_unicast() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.100.100.200",
            "127.0.0.1",
            "168.63.129.16",
            "169.254.169.254",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2001:db8::1",
            "2002:0808:0808::1",
            "fd00:ec2::254",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!SealedProductionAddressPolicy::permits(
                address.parse().unwrap()
            ));
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(SealedProductionAddressPolicy::permits(
                address.parse().unwrap()
            ));
        }
    }

    #[tokio::test]
    async fn structural_validators_reject_trailing_and_animated_payloads() {
        let deadline = TokioInstant::now() + Duration::from_secs(1);
        assert_eq!(
            validate_jpeg(&[0xff, 0xd8, 0xff, 0xd9, 0], deadline).await,
            Err(ReceiptImageFailureCodeV1::StructureRejected)
        );

        let mut animated_webp = b"RIFF\0\0\0\0WEBPANIM\0\0\0\0".to_vec();
        let size = (animated_webp.len() - 8) as u32;
        animated_webp[4..8].copy_from_slice(&size.to_le_bytes());
        assert_eq!(
            validate_webp(&animated_webp, deadline).await,
            Err(ReceiptImageFailureCodeV1::StructureRejected)
        );
    }

    #[tokio::test]
    async fn valid_png_derivative_is_deterministic_and_metadata_free() {
        let source = png_with_chunk(b"tEXt", b"comment\0private");
        let deadline = TokioInstant::now() + Duration::from_secs(2);
        validate_png(&source, deadline).await.unwrap();
        let first = decode_and_derive(source.clone(), ImageFormat::Png, deadline)
            .await
            .unwrap();
        let second = decode_and_derive(source, ImageFormat::Png, deadline)
            .await
            .unwrap();
        assert_eq!(first, second);
        assert_eq!((first.1, first.2), (32, 32));
        let kinds = png_chunk_kinds(&first.0);
        assert_eq!(kinds.first(), Some(b"IHDR"));
        assert_eq!(kinds.last(), Some(b"IEND"));
        assert!(kinds[1..kinds.len() - 1].iter().all(|kind| kind == b"IDAT"));
    }

    #[tokio::test]
    async fn png_validator_rejects_apng_control_chunks() {
        let source = png_with_chunk(b"acTL", &[0, 0, 0, 1, 0, 0, 0, 0]);
        let deadline = TokioInstant::now() + Duration::from_secs(1);
        assert_eq!(
            validate_png(&source, deadline).await,
            Err(ReceiptImageFailureCodeV1::StructureRejected)
        );
    }
}
