#[path = "../src/outfit_recommendation_http.rs"]
mod outfit_recommendation_http;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use outfit_recommendation_http::{
    OpenAiHeaderLimitKind, OpenAiHttpStatusKind, OpenAiOutcomeUnknownKind,
    OpenAiResponsesHttpError, OpenAiResponsesHttpTransport, OpenAiTimeoutKind,
    TestTransportTimeouts, OPENAI_REQUEST_LIMIT_BYTES, OPENAI_RESPONSES_ENDPOINT,
    OPENAI_RESPONSE_HEADER_BYTES_LIMIT, OPENAI_RESPONSE_HEADER_LIMIT,
    OPENAI_RESPONSE_HEADER_VALUE_LIMIT, OPENAI_RESPONSE_LIMIT_BYTES,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use url::Url;
use wardrobe_core::SecretString;

#[test]
fn production_transport_is_fixed_to_the_openai_responses_endpoint() {
    let transport = OpenAiResponsesHttpTransport::production().unwrap();
    let diagnostic = format!("{transport:?}");

    assert_eq!(
        OPENAI_RESPONSES_ENDPOINT,
        "https://api.openai.com/v1/responses"
    );
    assert!(diagnostic.contains("api.openai.com"));
    assert!(diagnostic.contains("v1/responses"));
    assert!(!diagnostic.contains("api_key"));
}

#[tokio::test]
async fn concrete_transport_posts_bounded_json_and_retains_only_allowlisted_metadata() {
    let fixture = TlsFixture::start(ResponseSpec::json(
        200,
        [
            ("X-Request-Id", "req_test_123"),
            ("OpenAI-Processing-Ms", "17"),
            ("OpenAI-Version", "2026-07-01"),
            ("X-Ratelimit-Remaining-Requests", "99"),
            ("Set-Cookie", "private=sentinel"),
            ("X-Arbitrary", "must-not-be-retained"),
        ],
        br#"{"id":"resp_123","output":[]}"#.to_vec(),
    ))
    .await;
    let transport = fixture.transport().unwrap();
    let secret = SecretString::new("sk-test-secret-sentinel".to_owned());
    let request = json!({
        "model": "gpt-5.6-sol",
        "store": false,
        "include": ["reasoning.encrypted_content"]
    });

    let response = transport.send(&secret, &request).await.unwrap();
    let wire = fixture.finish().await;

    assert_eq!(response.json["id"], "resp_123");
    assert_eq!(
        response.metadata.request_id.as_deref(),
        Some("req_test_123")
    );
    assert_eq!(
        response
            .metadata
            .retained_headers
            .get("openai-processing-ms")
            .map(String::as_str),
        Some("17")
    );
    assert_eq!(
        response
            .metadata
            .retained_headers
            .get("x-ratelimit-remaining-requests")
            .map(String::as_str),
        Some("99")
    );
    assert!(!format!("{response:?}").contains("resp_123"));
    assert!(!format!("{response:?}").contains("private=sentinel"));
    assert!(wire.starts_with("POST /v1/responses HTTP/1.1\r\n"));
    assert!(wire.contains("\r\nhost: fixture.invalid:"));
    assert!(wire.contains("\r\nauthorization: Bearer sk-test-secret-sentinel\r\n"));
    assert!(wire.contains("\r\naccept: application/json\r\n"));
    assert!(wire.contains("\r\ncontent-type: application/json\r\n"));
    assert!(!wire.to_ascii_lowercase().contains("\r\naccept-encoding:"));
    assert_eq!(
        request_body(&wire),
        serde_json::to_string(&request).unwrap()
    );
}

#[tokio::test]
async fn request_limit_and_invalid_secret_fail_before_network_io() {
    let fixture = TlsFixture::listening().await;
    let transport = fixture.transport().unwrap();
    let secret = SecretString::new("sk-test".to_owned());
    let oversized = Value::String("x".repeat(OPENAI_REQUEST_LIMIT_BYTES));
    assert_eq!(
        transport.send(&secret, &oversized).await,
        Err(OpenAiResponsesHttpError::RequestTooLarge {
            limit_bytes: OPENAI_REQUEST_LIMIT_BYTES
        })
    );
    assert_eq!(
        transport
            .send(&SecretString::new("bad secret".to_owned()), &json!({}))
            .await,
        Err(OpenAiResponsesHttpError::InvalidCredential)
    );
    fixture.assert_no_connection().await;
}

#[tokio::test]
async fn status_is_typed_without_retaining_provider_body_or_secret() {
    let fixture = TlsFixture::start(ResponseSpec::json(
        429,
        [("X-Request-Id", "req_rate_limited")],
        br#"{"error":{"message":"provider-body-sentinel"}}"#.to_vec(),
    ))
    .await;
    let transport = fixture.transport().unwrap();
    let secret = SecretString::new("sk-secret-sentinel".to_owned());
    let error = transport.send(&secret, &json!({})).await.unwrap_err();
    let wire = fixture.finish().await;

    assert!(wire.contains("authorization: Bearer sk-secret-sentinel"));
    assert!(matches!(
        error,
        OpenAiResponsesHttpError::HttpStatus {
            kind: OpenAiHttpStatusKind::RateLimited,
            status: 429,
            ref metadata,
        } if metadata.request_id.as_deref() == Some("req_rate_limited")
    ));
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("provider-body-sentinel"));
    assert!(!diagnostic.contains("sk-secret-sentinel"));
}

#[tokio::test]
async fn redirect_is_not_followed_and_is_a_typed_status() {
    let fixture = TlsFixture::start(ResponseSpec::new(
        302,
        [
            ("Content-Type", "application/json"),
            ("Location", "https://other.invalid/v1/responses"),
        ],
        br#"{}"#.to_vec(),
    ))
    .await;
    let error = fixture
        .transport()
        .unwrap()
        .send(&SecretString::new("sk-test".to_owned()), &json!({}))
        .await
        .unwrap_err();
    fixture.finish().await;

    assert!(matches!(
        error,
        OpenAiResponsesHttpError::HttpStatus {
            kind: OpenAiHttpStatusKind::Unexpected,
            status: 302,
            ..
        }
    ));
}

#[tokio::test]
async fn media_type_and_json_are_validated_without_exposing_raw_bodies() {
    let fixture = TlsFixture::start(ResponseSpec::new(
        200,
        [("Content-Type", "text/plain")],
        b"raw-media-sentinel".to_vec(),
    ))
    .await;
    let error = fixture
        .transport()
        .unwrap()
        .send(&SecretString::new("sk-test".to_owned()), &json!({}))
        .await
        .unwrap_err();
    fixture.finish().await;
    assert_eq!(error, OpenAiResponsesHttpError::UnsupportedMediaType);
    assert!(!format!("{error:?}").contains("raw-media-sentinel"));

    let fixture = TlsFixture::start(ResponseSpec::json(
        200,
        [],
        b"malformed-json-sentinel".to_vec(),
    ))
    .await;
    let error = fixture
        .transport()
        .unwrap()
        .send(&SecretString::new("sk-test".to_owned()), &json!({}))
        .await
        .unwrap_err();
    fixture.finish().await;
    assert_eq!(error, OpenAiResponsesHttpError::MalformedResponseJson);
    assert!(!format!("{error:?}").contains("malformed-json-sentinel"));
}

#[tokio::test]
async fn declared_and_streamed_response_body_limits_are_enforced() {
    let fixture = TlsFixture::start(ResponseSpec {
        status: 200,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            (
                "Content-Length".to_owned(),
                (OPENAI_RESPONSE_LIMIT_BYTES + 1).to_string(),
            ),
        ],
        body_parts: Vec::new(),
        pause_after_headers: None,
    })
    .await;
    let error = fixture
        .transport()
        .unwrap()
        .send(&SecretString::new("sk-test".to_owned()), &json!({}))
        .await
        .unwrap_err();
    fixture.finish().await;
    assert_eq!(
        error,
        OpenAiResponsesHttpError::ResponseTooLarge {
            limit_bytes: OPENAI_RESPONSE_LIMIT_BYTES
        }
    );

    let first = vec![b' '; OPENAI_RESPONSE_LIMIT_BYTES];
    let fixture = TlsFixture::start(ResponseSpec {
        status: 200,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Transfer-Encoding".to_owned(), "chunked".to_owned()),
        ],
        body_parts: vec![chunk(&first), chunk(b"x"), b"0\r\n\r\n".to_vec()],
        pause_after_headers: None,
    })
    .await;
    let error = fixture
        .transport()
        .unwrap()
        .send(&SecretString::new("sk-test".to_owned()), &json!({}))
        .await
        .unwrap_err();
    fixture.finish().await;
    assert_eq!(
        error,
        OpenAiResponsesHttpError::ResponseTooLarge {
            limit_bytes: OPENAI_RESPONSE_LIMIT_BYTES
        }
    );
}

#[tokio::test]
async fn response_header_count_value_and_aggregate_limits_are_enforced() {
    let mut count_headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
    for index in 0..OPENAI_RESPONSE_HEADER_LIMIT {
        count_headers.push((format!("X-Fixture-{index}"), "x".to_owned()));
    }
    assert_header_limit(count_headers, OpenAiHeaderLimitKind::Count).await;

    assert_header_limit(
        vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            (
                "X-Oversized".to_owned(),
                "x".repeat(OPENAI_RESPONSE_HEADER_VALUE_LIMIT + 1),
            ),
        ],
        OpenAiHeaderLimitKind::ValueBytes,
    )
    .await;

    let mut aggregate_headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
    for index in 0..5 {
        aggregate_headers.push((
            format!("X-Aggregate-{index}"),
            "x".repeat((OPENAI_RESPONSE_HEADER_BYTES_LIMIT / 5) + 1),
        ));
    }
    assert_header_limit(aggregate_headers, OpenAiHeaderLimitKind::AggregateBytes).await;
}

#[tokio::test]
async fn retained_header_values_are_unique_visible_and_tightly_bounded() {
    for headers in [
        vec![
            ("Content-Type", "application/json"),
            ("X-Request-Id", "one"),
            ("X-Request-Id", "two"),
        ],
        vec![("Content-Type", "application/json"), ("X-Request-Id", "")],
    ] {
        let fixture = TlsFixture::start(ResponseSpec::new(200, headers, br#"{}"#.to_vec())).await;
        let error = fixture
            .transport()
            .unwrap()
            .send(&SecretString::new("sk-test".to_owned()), &json!({}))
            .await
            .unwrap_err();
        fixture.finish().await;
        assert_eq!(error, OpenAiResponsesHttpError::InvalidResponseHeaders);
    }
}

#[tokio::test]
async fn read_timeout_is_typed_as_outcome_unknown() {
    let fixture = TlsFixture::start(ResponseSpec {
        status: 200,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Length".to_owned(), "2".to_owned()),
        ],
        body_parts: vec![br#"{}"#.to_vec()],
        pause_after_headers: Some(Duration::from_secs(3)),
    })
    .await;
    let transport = fixture
        .transport_with_timeouts(TestTransportTimeouts {
            connect: Duration::from_secs(1),
            read: Duration::from_secs(1),
            total: Duration::from_secs(5),
        })
        .unwrap();
    let error = transport
        .send(&SecretString::new("sk-test".to_owned()), &json!({}))
        .await
        .unwrap_err();
    fixture.finish().await;

    assert_eq!(
        error,
        OpenAiResponsesHttpError::Timeout {
            kind: OpenAiTimeoutKind::ResponseRead,
            outcome_unknown: true,
        }
    );
    assert!(error.outcome_is_unknown());
}

#[tokio::test]
async fn truncated_response_is_an_audit_safe_unknown_outcome() {
    let fixture = TlsFixture::start(ResponseSpec {
        status: 200,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Content-Length".to_owned(), "100".to_owned()),
        ],
        body_parts: vec![b"{".to_vec()],
        pause_after_headers: None,
    })
    .await;
    let error = fixture
        .transport()
        .unwrap()
        .send(&SecretString::new("sk-test".to_owned()), &json!({}))
        .await
        .unwrap_err();
    fixture.finish().await;

    assert_eq!(
        error,
        OpenAiResponsesHttpError::OutcomeUnknown {
            kind: OpenAiOutcomeUnknownKind::ResponseRead,
        }
    );
    assert!(error.outcome_is_unknown());
}

async fn assert_header_limit(headers: Vec<(String, String)>, kind: OpenAiHeaderLimitKind) {
    let fixture = TlsFixture::start(ResponseSpec {
        status: 200,
        headers,
        body_parts: vec![br#"{}"#.to_vec()],
        pause_after_headers: None,
    })
    .await;
    let error = fixture
        .transport()
        .unwrap()
        .send(&SecretString::new("sk-test".to_owned()), &json!({}))
        .await
        .unwrap_err();
    fixture.finish().await;
    assert_eq!(
        error,
        OpenAiResponsesHttpError::ResponseHeaderLimit { kind }
    );
}

fn chunk(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = format!("{:x}\r\n", bytes.len()).into_bytes();
    encoded.extend_from_slice(bytes);
    encoded.extend_from_slice(b"\r\n");
    encoded
}

fn request_body(request: &str) -> &str {
    request.split_once("\r\n\r\n").unwrap().1
}

struct ResponseSpec {
    status: u16,
    headers: Vec<(String, String)>,
    body_parts: Vec<Vec<u8>>,
    pause_after_headers: Option<Duration>,
}

impl ResponseSpec {
    fn new<'a>(
        status: u16,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            body_parts: vec![body],
            pause_after_headers: None,
        }
    }

    fn json<'a>(
        status: u16,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        body: Vec<u8>,
    ) -> Self {
        let mut spec = Self::new(status, headers, body);
        spec.headers
            .push(("Content-Type".to_owned(), "application/json".to_owned()));
        let body_len = spec.body_parts.iter().map(Vec::len).sum::<usize>();
        spec.headers
            .push(("Content-Length".to_owned(), body_len.to_string()));
        spec
    }
}

struct TlsFixture {
    socket: SocketAddr,
    listener: Option<TcpListener>,
    server: Option<tokio::task::JoinHandle<String>>,
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
            let reason = match spec.status {
                200 => "OK",
                302 => "Found",
                429 => "Too Many Requests",
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
            String::from_utf8(request).unwrap()
        }));
        fixture
    }

    fn transport(&self) -> Result<OpenAiResponsesHttpTransport, OpenAiResponsesHttpError> {
        OpenAiResponsesHttpTransport::for_test(
            self.origin(),
            fixture_root_certificate(),
            self.socket,
        )
    }

    fn transport_with_timeouts(
        &self,
        timeouts: TestTransportTimeouts,
    ) -> Result<OpenAiResponsesHttpTransport, OpenAiResponsesHttpError> {
        OpenAiResponsesHttpTransport::for_test_with_timeouts(
            self.origin(),
            fixture_root_certificate(),
            self.socket,
            timeouts,
        )
    }

    fn origin(&self) -> Url {
        Url::parse(&format!("https://fixture.invalid:{}/", self.socket.port())).unwrap()
    }

    async fn finish(mut self) -> String {
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
) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
        assert!(request.len() <= OPENAI_REQUEST_LIMIT_BYTES + 16 * 1024);
    }
    let head_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let content_length = String::from_utf8_lossy(&request[..head_end])
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    while request.len() - head_end < content_length {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
    }
    request
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
