#[path = "../src/try_on_http.rs"]
mod try_on_http;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use image::codecs::png::PngEncoder;
use image::{ColorType, ImageEncoder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use try_on_http::{
    ImageEditsTestTimeouts, OpenAiImageEditsDispatch, OpenAiImageEditsErrorDetail,
    OpenAiImageEditsFailureKind, OpenAiImageEditsHttpTransport, OpenAiImageEditsRequest,
    OPENAI_IMAGE_EDITS_ENDPOINT, OPENAI_IMAGE_EDITS_MODEL, OPENAI_IMAGE_EDITS_OUTPUT_FORMAT,
    OPENAI_IMAGE_EDITS_PROMPT, OPENAI_IMAGE_EDITS_QUALITY, OPENAI_IMAGE_EDITS_SIZE,
    OPENAI_IMAGE_ERROR_RESPONSE_LIMIT_BYTES, OPENAI_IMAGE_REFERENCE_LIMIT_BYTES,
    OPENAI_IMAGE_RESPONSE_HEADER_BYTES_LIMIT, OPENAI_IMAGE_RESPONSE_HEADER_LIMIT,
    OPENAI_IMAGE_RESPONSE_HEADER_VALUE_LIMIT, OPENAI_IMAGE_RESPONSE_LIMIT_BYTES,
};
use url::Url;
use wardrobe_core::SecretString;

#[test]
fn production_transport_is_fixed_to_openai_image_edits() {
    let transport = OpenAiImageEditsHttpTransport::production().unwrap();
    let diagnostic = format!("{transport:?}");

    assert_eq!(
        OPENAI_IMAGE_EDITS_ENDPOINT,
        "https://api.openai.com/v1/images/edits"
    );
    assert_eq!(OPENAI_IMAGE_EDITS_MODEL, "gpt-image-2");
    assert!(diagnostic.contains("api.openai.com"));
    assert!(diagnostic.contains("/v1/images/edits"));
    assert!(!diagnostic.contains("api_key"));
}

#[tokio::test]
async fn concrete_tls_transport_sends_fixed_ordered_multipart_and_validates_output() {
    let output_png = png(1024, 1536, [20, 40, 60, 255]);
    let response = success_response(&output_png);
    let fixture = TlsFixture::start(response).await;
    let transport = fixture.transport().unwrap();
    let portrait = png(2, 3, [255, 0, 0, 255]);
    let garment_one = png(3, 2, [0, 255, 0, 255]);
    let garment_two = png(4, 2, [0, 0, 255, 255]);
    let garments: [&[u8]; 2] = [&garment_one, &garment_two];

    let result = transport
        .generate(
            &SecretString::new("sk-test-secret-sentinel".to_owned()),
            OpenAiImageEditsRequest {
                portrait_png: &portrait,
                garment_pngs: &garments,
            },
        )
        .await
        .unwrap();
    let wire = fixture.finish().await;

    assert_eq!(result.png, output_png);
    assert_eq!(result.metadata.request_id.as_deref(), Some("req_image_123"));
    assert!(!format!("{result:?}").contains("iVBOR"));
    assert!(wire.head.starts_with("POST /v1/images/edits HTTP/1.1\r\n"));
    assert!(wire
        .head
        .contains("\r\nauthorization: Bearer sk-test-secret-sentinel\r\n"));
    assert!(wire.head.contains("\r\naccept: application/json\r\n"));
    assert!(!wire.head.to_ascii_lowercase().contains("accept-encoding:"));

    let parts = multipart_parts(&wire);
    assert_eq!(parts.len(), 8);
    assert_text_part(&parts[0], "model", OPENAI_IMAGE_EDITS_MODEL);
    assert_text_part(&parts[1], "prompt", OPENAI_IMAGE_EDITS_PROMPT);
    assert_image_part(&parts[2], "reference-00.png", &portrait);
    assert_image_part(&parts[3], "reference-01.png", &garment_one);
    assert_image_part(&parts[4], "reference-02.png", &garment_two);
    assert_text_part(&parts[5], "size", OPENAI_IMAGE_EDITS_SIZE);
    assert_text_part(&parts[6], "quality", OPENAI_IMAGE_EDITS_QUALITY);
    assert_text_part(&parts[7], "output_format", OPENAI_IMAGE_EDITS_OUTPUT_FORMAT);

    let rendered = String::from_utf8_lossy(&wire.body);
    for forbidden in [
        "portrait.png",
        "item_id",
        "source_id",
        "credential_id",
        "retention",
        "/Users/",
    ] {
        assert!(!rendered.contains(forbidden), "leaked {forbidden}");
    }
}

#[tokio::test]
async fn invalid_credentials_references_and_counts_fail_before_network_io() {
    let portrait = png(2, 2, [1, 2, 3, 255]);
    let garment = png(2, 2, [4, 5, 6, 255]);

    for (secret, request, detail) in [
        (
            "bad secret",
            OpenAiImageEditsRequest {
                portrait_png: &portrait,
                garment_pngs: &[&garment, &garment],
            },
            OpenAiImageEditsErrorDetail::InvalidCredential,
        ),
        (
            "sk-test",
            OpenAiImageEditsRequest {
                portrait_png: &portrait,
                garment_pngs: &[&garment],
            },
            OpenAiImageEditsErrorDetail::ReferenceCount,
        ),
        (
            "sk-test",
            OpenAiImageEditsRequest {
                portrait_png: b"not-a-png",
                garment_pngs: &[&garment, &garment],
            },
            OpenAiImageEditsErrorDetail::InvalidPng,
        ),
    ] {
        let fixture = TlsFixture::listening().await;
        let error = fixture
            .transport()
            .unwrap()
            .generate(&SecretString::new(secret.to_owned()), request)
            .await
            .unwrap_err();
        assert_eq!(error.dispatch, OpenAiImageEditsDispatch::NotSent);
        assert_eq!(error.detail, detail);
        assert!(error.failed_before_send());
        fixture.assert_no_connection().await;
    }

    let fixture = TlsFixture::listening().await;
    let oversized = vec![0_u8; OPENAI_IMAGE_REFERENCE_LIMIT_BYTES + 1];
    let error = fixture
        .transport()
        .unwrap()
        .generate(
            &SecretString::new("sk-test".to_owned()),
            OpenAiImageEditsRequest {
                portrait_png: &oversized,
                garment_pngs: &[&garment, &garment],
            },
        )
        .await
        .unwrap_err();
    assert_eq!(error.detail, OpenAiImageEditsErrorDetail::ReferenceTooLarge);
    assert!(error.failed_before_send());
    fixture.assert_no_connection().await;

    let animated = insert_chunk_after_ihdr(&portrait, b"acTL", &[0; 8]);
    let metadata = insert_chunk_after_ihdr(&portrait, b"tEXt", b"private=sentinel");
    let oversized_axis = png(4097, 1, [1, 2, 3, 255]);
    for (reference, detail) in [
        (animated, OpenAiImageEditsErrorDetail::AnimatedPng),
        (metadata, OpenAiImageEditsErrorDetail::ReferenceMetadata),
        (
            oversized_axis,
            OpenAiImageEditsErrorDetail::ImageDimensionLimit,
        ),
    ] {
        let fixture = TlsFixture::listening().await;
        let error = fixture
            .transport()
            .unwrap()
            .generate(
                &SecretString::new("sk-test".to_owned()),
                OpenAiImageEditsRequest {
                    portrait_png: &reference,
                    garment_pngs: &[&garment, &garment],
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.detail, detail);
        assert!(error.failed_before_send());
        fixture.assert_no_connection().await;
    }
}

#[tokio::test]
async fn aggregate_reference_limit_fails_before_building_or_sending_multipart() {
    let large = noisy_png(1900, 1000);
    assert!(large.len() < OPENAI_IMAGE_REFERENCE_LIMIT_BYTES);
    assert!(large.len() * 6 > try_on_http::OPENAI_IMAGE_REFERENCES_LIMIT_BYTES);
    let garments: [&[u8]; 5] = [&large, &large, &large, &large, &large];
    let fixture = TlsFixture::listening().await;

    let error = fixture
        .transport()
        .unwrap()
        .generate(
            &SecretString::new("sk-test".to_owned()),
            OpenAiImageEditsRequest {
                portrait_png: &large,
                garment_pngs: &garments,
            },
        )
        .await
        .unwrap_err();

    assert_eq!(
        error.detail,
        OpenAiImageEditsErrorDetail::AggregateReferencesTooLarge
    );
    assert!(error.failed_before_send());
    fixture.assert_no_connection().await;
}

#[tokio::test]
async fn exact_moderation_code_and_http_statuses_use_the_allowlisted_taxonomy() {
    let cases = [
        (
            400,
            json!({"error":{"code":"moderation_blocked","message":"body-sentinel"}}),
            OpenAiImageEditsFailureKind::ModerationBlocked,
        ),
        (
            400,
            json!({"error":{"code":"moderation_blocked_extra"}}),
            OpenAiImageEditsFailureKind::RequestRejected,
        ),
        (
            401,
            json!({"error":{"code":"invalid_api_key"}}),
            OpenAiImageEditsFailureKind::Authentication,
        ),
        (
            403,
            json!({"error":{"code":"forbidden"}}),
            OpenAiImageEditsFailureKind::PermissionDenied,
        ),
        (
            429,
            json!({"error":{"code":"rate_limit"}}),
            OpenAiImageEditsFailureKind::RateLimited,
        ),
        (
            500,
            json!({"error":{"code":"server_error"}}),
            OpenAiImageEditsFailureKind::ProviderFailure,
        ),
        (
            503,
            json!({"error":{"code":"unavailable"}}),
            OpenAiImageEditsFailureKind::ProviderUnavailable,
        ),
    ];

    for (status, body, expected) in cases {
        let fixture = TlsFixture::start(ResponseSpec::json(
            status,
            serde_json::to_vec(&body).unwrap(),
        ))
        .await;
        let error = generate_valid(fixture.transport().unwrap())
            .await
            .unwrap_err();
        fixture.finish().await;
        assert_eq!(error.kind, expected);
        assert_eq!(error.dispatch, OpenAiImageEditsDispatch::Responded);
        assert_eq!(error.status, Some(status));
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("body-sentinel"));
        assert!(!diagnostic.contains("sk-test-secret"));
    }
}

#[tokio::test]
async fn malformed_success_payloads_are_provider_protocol_failures() {
    for (body, expected) in [
        (
            br#"{"data":[]}"#.to_vec(),
            OpenAiImageEditsErrorDetail::InvalidImageResultCount,
        ),
        (
            br#"{"data":[{"b64_json":"%%%"}]}"#.to_vec(),
            OpenAiImageEditsErrorDetail::InvalidBase64,
        ),
        (
            serde_json::to_vec(&json!({
                "data":[{"b64_json": STANDARD.encode(b"not-a-png")}]
            }))
            .unwrap(),
            OpenAiImageEditsErrorDetail::InvalidPng,
        ),
        (
            serde_json::to_vec(&json!({
                "data":[{"b64_json": STANDARD.encode(png(1, 1, [1, 1, 1, 255]))}]
            }))
            .unwrap(),
            OpenAiImageEditsErrorDetail::InvalidOutputDimensions,
        ),
    ] {
        let fixture = TlsFixture::start(ResponseSpec::json(200, body)).await;
        let error = generate_valid(fixture.transport().unwrap())
            .await
            .unwrap_err();
        fixture.finish().await;
        assert_eq!(error.kind, OpenAiImageEditsFailureKind::ProviderProtocol);
        assert_eq!(error.detail, expected);
        assert_eq!(error.dispatch, OpenAiImageEditsDispatch::Responded);
    }
}

#[tokio::test]
async fn declared_success_and_error_body_limits_are_enforced_without_reading_content() {
    for (status, length) in [
        (200, OPENAI_IMAGE_RESPONSE_LIMIT_BYTES + 1),
        (400, OPENAI_IMAGE_ERROR_RESPONSE_LIMIT_BYTES + 1),
    ] {
        let fixture = TlsFixture::start(ResponseSpec {
            status,
            headers: vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Content-Length".to_owned(), length.to_string()),
            ],
            body_parts: Vec::new(),
            pause_before_headers: None,
            pause_after_headers: None,
        })
        .await;
        let error = generate_valid(fixture.transport().unwrap())
            .await
            .unwrap_err();
        fixture.finish().await;
        assert_eq!(error.detail, OpenAiImageEditsErrorDetail::ResponseTooLarge);
        assert_eq!(error.kind, OpenAiImageEditsFailureKind::ProviderProtocol);
    }
}

#[tokio::test]
async fn response_header_count_is_bounded() {
    let mut headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
    for index in 0..OPENAI_IMAGE_RESPONSE_HEADER_LIMIT {
        headers.push((format!("X-Fixture-{index}"), "x".to_owned()));
    }
    let fixture = TlsFixture::start(ResponseSpec {
        status: 200,
        headers,
        body_parts: vec![br#"{}"#.to_vec()],
        pause_before_headers: None,
        pause_after_headers: None,
    })
    .await;
    let error = generate_valid(fixture.transport().unwrap())
        .await
        .unwrap_err();
    fixture.finish().await;
    assert_eq!(
        error.detail,
        OpenAiImageEditsErrorDetail::ResponseHeaderCount
    );
    assert_eq!(error.kind, OpenAiImageEditsFailureKind::ProviderProtocol);

    for (headers, detail) in [
        (
            vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                (
                    "X-Oversized".to_owned(),
                    "x".repeat(OPENAI_IMAGE_RESPONSE_HEADER_VALUE_LIMIT + 1),
                ),
            ],
            OpenAiImageEditsErrorDetail::ResponseHeaderValue,
        ),
        (
            (0..5)
                .map(|index| {
                    (
                        format!("X-Aggregate-{index}"),
                        "x".repeat((OPENAI_IMAGE_RESPONSE_HEADER_BYTES_LIMIT / 5) + 1),
                    )
                })
                .chain(std::iter::once((
                    "Content-Type".to_owned(),
                    "application/json".to_owned(),
                )))
                .collect(),
            OpenAiImageEditsErrorDetail::ResponseHeaderBytes,
        ),
    ] {
        let fixture = TlsFixture::start(ResponseSpec {
            status: 200,
            headers,
            body_parts: vec![br#"{}"#.to_vec()],
            pause_before_headers: None,
            pause_after_headers: None,
        })
        .await;
        let error = generate_valid(fixture.transport().unwrap())
            .await
            .unwrap_err();
        fixture.finish().await;
        assert_eq!(error.detail, detail);
    }
}

#[tokio::test]
async fn streamed_error_limit_media_type_and_redirect_fail_closed() {
    let first = vec![b' '; OPENAI_IMAGE_ERROR_RESPONSE_LIMIT_BYTES];
    let fixture = TlsFixture::start(ResponseSpec {
        status: 400,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
        ],
        body_parts: vec![chunk(&first), chunk(b"x"), b"0\r\n\r\n".to_vec()],
        pause_before_headers: None,
        pause_after_headers: None,
    })
    .await;
    let error = generate_valid(fixture.transport().unwrap())
        .await
        .unwrap_err();
    fixture.finish().await;
    assert_eq!(error.detail, OpenAiImageEditsErrorDetail::ResponseTooLarge);
    assert_eq!(error.kind, OpenAiImageEditsFailureKind::ProviderProtocol);

    let fixture = TlsFixture::start(ResponseSpec {
        status: 200,
        headers: vec![
            ("Content-Type".to_owned(), "text/plain".to_owned()),
            ("Content-Length".to_owned(), "2".to_owned()),
        ],
        body_parts: vec![br#"{}"#.to_vec()],
        pause_before_headers: None,
        pause_after_headers: None,
    })
    .await;
    let error = generate_valid(fixture.transport().unwrap())
        .await
        .unwrap_err();
    fixture.finish().await;
    assert_eq!(
        error.detail,
        OpenAiImageEditsErrorDetail::UnsupportedMediaType
    );

    let fixture = TlsFixture::start(ResponseSpec {
        status: 302,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Length".to_owned(), "2".to_owned()),
            (
                "Location".to_owned(),
                "https://other.invalid/v1/images/edits".to_owned(),
            ),
        ],
        body_parts: vec![br#"{}"#.to_vec()],
        pause_before_headers: None,
        pause_after_headers: None,
    })
    .await;
    let error = generate_valid(fixture.transport().unwrap())
        .await
        .unwrap_err();
    fixture.finish().await;
    assert_eq!(error.kind, OpenAiImageEditsFailureKind::ProviderProtocol);
    assert_eq!(error.status, Some(302));
    assert_eq!(error.dispatch, OpenAiImageEditsDispatch::Responded);
}

#[tokio::test]
async fn closed_socket_is_a_safe_pre_send_provider_unavailable_failure() {
    let fixture = TlsFixture::closed().await;
    let error = generate_valid(fixture.transport().unwrap())
        .await
        .unwrap_err();

    assert_eq!(error.kind, OpenAiImageEditsFailureKind::ProviderUnavailable);
    assert_eq!(error.dispatch, OpenAiImageEditsDispatch::NotSent);
    assert_eq!(error.detail, OpenAiImageEditsErrorDetail::TransportConnect);
    assert!(error.failed_before_send());
    assert!(!error.outcome_is_unknown());
}

#[tokio::test]
async fn post_send_read_timeout_is_an_ambiguous_outcome() {
    let fixture = TlsFixture::start(ResponseSpec {
        status: 200,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Length".to_owned(), "2".to_owned()),
        ],
        body_parts: vec![br#"{}"#.to_vec()],
        pause_before_headers: None,
        pause_after_headers: Some(Duration::from_millis(1200)),
    })
    .await;
    let transport = fixture
        .transport_with_timeouts(ImageEditsTestTimeouts {
            connect: Duration::from_secs(1),
            read: Duration::from_millis(500),
            total: Duration::from_secs(2),
        })
        .unwrap();
    let error = generate_valid(transport).await.unwrap_err();
    fixture.finish().await;

    assert_eq!(error.kind, OpenAiImageEditsFailureKind::OutcomeUnknown);
    assert_eq!(error.dispatch, OpenAiImageEditsDispatch::Unknown);
    assert_eq!(
        error.detail,
        OpenAiImageEditsErrorDetail::ResponseReadTimeout
    );
    assert!(error.outcome_is_unknown());
    assert!(!error.failed_before_send());
}

async fn generate_valid(
    transport: OpenAiImageEditsHttpTransport,
) -> Result<try_on_http::OpenAiImageEditsOutput, try_on_http::OpenAiImageEditsError> {
    let portrait = png(2, 2, [1, 2, 3, 255]);
    let garment_one = png(2, 2, [4, 5, 6, 255]);
    let garment_two = png(2, 2, [7, 8, 9, 255]);
    let garments: [&[u8]; 2] = [&garment_one, &garment_two];
    transport
        .generate(
            &SecretString::new("sk-test-secret".to_owned()),
            OpenAiImageEditsRequest {
                portrait_png: &portrait,
                garment_pngs: &garments,
            },
        )
        .await
}

fn success_response(output_png: &[u8]) -> ResponseSpec {
    let body = serde_json::to_vec(&json!({
        "created": 1,
        "data": [{"b64_json": STANDARD.encode(output_png)}],
        "usage": {"total_tokens": 1}
    }))
    .unwrap();
    let mut response = ResponseSpec::json(200, body);
    response
        .headers
        .push(("X-Request-Id".to_owned(), "req_image_123".to_owned()));
    response
}

fn png(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
    let mut pixels = vec![0_u8; width as usize * height as usize * 4];
    for pixel in pixels.chunks_exact_mut(4) {
        pixel.copy_from_slice(&color);
    }
    let mut encoded = Vec::new();
    PngEncoder::new(&mut encoded)
        .write_image(&pixels, width, height, ColorType::Rgba8.into())
        .unwrap();
    encoded
}

fn noisy_png(width: u32, height: u32) -> Vec<u8> {
    let mut state = 0x1234_5678_u32;
    let mut pixels = vec![0_u8; width as usize * height as usize * 4];
    for byte in &mut pixels {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *byte = (state >> 24) as u8;
    }
    let mut encoded = Vec::new();
    PngEncoder::new(&mut encoded)
        .write_image(&pixels, width, height, ColorType::Rgba8.into())
        .unwrap();
    encoded
}

fn insert_chunk_after_ihdr(png: &[u8], chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let ihdr_end = 8 + 4 + 4 + 13 + 4;
    let mut result = Vec::with_capacity(png.len() + data.len() + 12);
    result.extend_from_slice(&png[..ihdr_end]);
    result.extend_from_slice(&(data.len() as u32).to_be_bytes());
    result.extend_from_slice(chunk_type);
    result.extend_from_slice(data);
    result.extend_from_slice(&[0; 4]);
    result.extend_from_slice(&png[ihdr_end..]);
    result
}

fn chunk(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = format!("{:x}\r\n", bytes.len()).into_bytes();
    encoded.extend_from_slice(bytes);
    encoded.extend_from_slice(b"\r\n");
    encoded
}

struct MultipartPart {
    headers: String,
    body: Vec<u8>,
}

fn multipart_parts(wire: &CapturedRequest) -> Vec<MultipartPart> {
    let content_type = wire
        .head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-type: ")
                .map(str::to_owned)
        })
        .unwrap();
    assert!(content_type.starts_with("multipart/form-data; boundary="));
    let boundary = content_type.split_once("boundary=").unwrap().1;
    let marker = format!("--{boundary}").into_bytes();
    split_bytes(&wire.body, &marker)
        .into_iter()
        .filter_map(|segment| {
            let segment = segment.strip_prefix(b"\r\n")?;
            if segment.starts_with(b"--") {
                return None;
            }
            let segment = segment.strip_suffix(b"\r\n").unwrap_or(segment);
            let split = find_subslice(segment, b"\r\n\r\n")?;
            Some(MultipartPart {
                headers: String::from_utf8(segment[..split].to_vec()).unwrap(),
                body: segment[split + 4..].to_vec(),
            })
        })
        .collect()
}

fn assert_text_part(part: &MultipartPart, name: &str, value: &str) {
    assert_eq!(
        part.headers,
        format!("Content-Disposition: form-data; name=\"{name}\"")
    );
    assert_eq!(part.body, value.as_bytes());
}

fn assert_image_part(part: &MultipartPart, filename: &str, expected: &[u8]) {
    assert_eq!(
        part.headers,
        format!(
            "Content-Disposition: form-data; name=\"image[]\"; filename=\"{filename}\"\r\nContent-Type: image/png"
        )
    );
    assert_eq!(part.body, expected);
}

fn split_bytes<'a>(bytes: &'a [u8], delimiter: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut remainder = bytes;
    while let Some(index) = find_subslice(remainder, delimiter) {
        parts.push(&remainder[..index]);
        remainder = &remainder[index + delimiter.len()..];
    }
    parts.push(remainder);
    parts
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

struct ResponseSpec {
    status: u16,
    headers: Vec<(String, String)>,
    body_parts: Vec<Vec<u8>>,
    pause_before_headers: Option<Duration>,
    pause_after_headers: Option<Duration>,
}

impl ResponseSpec {
    fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Content-Length".to_owned(), body.len().to_string()),
            ],
            body_parts: vec![body],
            pause_before_headers: None,
            pause_after_headers: None,
        }
    }
}

struct CapturedRequest {
    head: String,
    body: Vec<u8>,
}

struct TlsFixture {
    socket: SocketAddr,
    listener: Option<TcpListener>,
    server: Option<tokio::task::JoinHandle<CapturedRequest>>,
}

impl TlsFixture {
    async fn listening() -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socket = listener.local_addr().unwrap();
        Self {
            socket,
            listener: Some(listener),
            server: None,
        }
    }

    async fn closed() -> Self {
        let mut fixture = Self::listening().await;
        drop(fixture.listener.take());
        let socket = fixture.socket;
        drop(fixture);
        Self {
            socket,
            listener: None,
            server: None,
        }
    }

    async fn start(spec: ResponseSpec) -> Self {
        let mut fixture = Self::listening().await;
        let listener = fixture.listener.take().unwrap();
        let server_config = fixture_server_config();
        fixture.server = Some(tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
                .unwrap();
            let request = read_request(&mut stream).await;
            if let Some(pause) = spec.pause_before_headers {
                tokio::time::sleep(pause).await;
            }
            let reason = match spec.status {
                200 => "OK",
                400 => "Bad Request",
                401 => "Unauthorized",
                403 => "Forbidden",
                429 => "Too Many Requests",
                500 => "Internal Server Error",
                503 => "Service Unavailable",
                _ => "Fixture",
            };
            let mut head = format!("HTTP/1.1 {} {}\r\n", spec.status, reason);
            for (name, value) in spec.headers {
                head.push_str(&name);
                head.push_str(": ");
                head.push_str(&value);
                head.push_str("\r\n");
            }
            head.push_str("Connection: close\r\n\r\n");
            stream.write_all(head.as_bytes()).await.unwrap();
            if let Some(pause) = spec.pause_after_headers {
                tokio::time::sleep(pause).await;
            }
            for part in spec.body_parts {
                if stream.write_all(&part).await.is_err() {
                    break;
                }
            }
            let _ = stream.shutdown().await;
            request
        }));
        fixture
    }

    fn transport(
        &self,
    ) -> Result<OpenAiImageEditsHttpTransport, try_on_http::OpenAiImageEditsError> {
        OpenAiImageEditsHttpTransport::for_test(
            self.origin(),
            fixture_root_certificate(),
            self.socket,
        )
    }

    fn transport_with_timeouts(
        &self,
        timeouts: ImageEditsTestTimeouts,
    ) -> Result<OpenAiImageEditsHttpTransport, try_on_http::OpenAiImageEditsError> {
        OpenAiImageEditsHttpTransport::for_test_with_timeouts(
            self.origin(),
            fixture_root_certificate(),
            self.socket,
            timeouts,
        )
    }

    fn origin(&self) -> Url {
        Url::parse(&format!("https://fixture.invalid:{}/", self.socket.port())).unwrap()
    }

    async fn finish(mut self) -> CapturedRequest {
        self.server.take().unwrap().await.unwrap()
    }

    async fn assert_no_connection(self) {
        let listener = self.listener.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
}

async fn read_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> CapturedRequest {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
    }
    let head_end = find_subslice(&request, b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8(request[..head_end].to_vec()).unwrap();
    let content_length = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap();
    assert!(content_length <= try_on_http::OPENAI_IMAGE_REQUEST_LIMIT_BYTES);
    while request.len() - head_end < content_length {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
    }
    CapturedRequest {
        head,
        body: request[head_end..head_end + content_length].to_vec(),
    }
}

fn fixture_server_config() -> rustls::ServerConfig {
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(fixture_der("FIXTURE_LEAF_CERT_DER"))],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture_der(
                "FIXTURE_LEAF_KEY_DER",
            ))),
        )
        .unwrap()
}

fn fixture_root_certificate() -> reqwest::Certificate {
    reqwest::Certificate::from_der(&fixture_der("FIXTURE_CERT_DER")).unwrap()
}

fn fixture_der(name: &str) -> Vec<u8> {
    let source = include_str!("receipt_image_downloader.rs");
    let marker = format!("const {name}: &str = \"");
    let start = source.find(&marker).unwrap() + marker.len();
    let end = source[start..].find("\";").unwrap() + start;
    STANDARD.decode(&source[start..end]).unwrap()
}
