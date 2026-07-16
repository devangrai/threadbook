use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use reqwest::{redirect::Policy, StatusCode};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use url::Url;
use wardrobe_core::SecretString;

pub const OPENAI_RESPONSES_ENDPOINT: &str = "https://api.openai.com/v1/responses";
pub const OPENAI_REQUEST_LIMIT_BYTES: usize = 256 * 1024;
pub const OPENAI_RESPONSE_LIMIT_BYTES: usize = 2 * 1024 * 1024;
pub const OPENAI_RESPONSE_HEADER_LIMIT: usize = 64;
pub const OPENAI_RESPONSE_HEADER_BYTES_LIMIT: usize = 32 * 1024;
pub const OPENAI_RESPONSE_HEADER_VALUE_LIMIT: usize = 8 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_API_KEY_BYTES: usize = 16 * 1024;
const MAX_RETAINED_HEADER_VALUE_BYTES: usize = 256;
const MAX_REQUEST_ID_BYTES: usize = 256;

const RETAINED_RESPONSE_HEADERS: &[&str] = &[
    "openai-processing-ms",
    "openai-version",
    "x-ratelimit-limit-requests",
    "x-ratelimit-limit-tokens",
    "x-ratelimit-remaining-requests",
    "x-ratelimit-remaining-tokens",
    "x-ratelimit-reset-requests",
    "x-ratelimit-reset-tokens",
];

#[derive(Clone)]
pub struct OpenAiResponsesHttpTransport {
    client: reqwest::Client,
    endpoint: Url,
}

impl fmt::Debug for OpenAiResponsesHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiResponsesHttpTransport")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl OpenAiResponsesHttpTransport {
    pub fn production() -> Result<Self, OpenAiResponsesHttpError> {
        Self::build(
            Url::parse(OPENAI_RESPONSES_ENDPOINT)
                .map_err(|_| OpenAiResponsesHttpError::ClientConfiguration)?,
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
    ) -> Result<Self, OpenAiResponsesHttpError> {
        Self::for_test_with_timeouts(
            origin,
            certificate,
            socket,
            TestTransportTimeouts {
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
        timeouts: TestTransportTimeouts,
    ) -> Result<Self, OpenAiResponsesHttpError> {
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(OpenAiResponsesHttpError::ClientConfiguration);
        }
        let host = origin
            .host_str()
            .ok_or(OpenAiResponsesHttpError::ClientConfiguration)?
            .to_owned();
        let endpoint = origin
            .join("v1/responses")
            .map_err(|_| OpenAiResponsesHttpError::ClientConfiguration)?;
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
        test_tls: Option<(reqwest::Certificate, String, SocketAddr)>,
        timeouts: TransportTimeouts,
    ) -> Result<Self, OpenAiResponsesHttpError> {
        if endpoint.scheme() != "https" || endpoint.host_str().is_none() {
            return Err(OpenAiResponsesHttpError::ClientConfiguration);
        }
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
            .connect_timeout(timeouts.connect)
            .read_timeout(timeouts.read)
            .timeout(timeouts.total);
        if let Some((certificate, host, socket)) = test_tls {
            builder = builder
                .tls_certs_only(vec![certificate])
                .resolve(&host, socket);
        }
        let client = builder
            .build()
            .map_err(|_| OpenAiResponsesHttpError::ClientConfiguration)?;
        Ok(Self { client, endpoint })
    }

    pub async fn send(
        &self,
        api_key: &SecretString,
        request: &Value,
    ) -> Result<OpenAiJsonResponse, OpenAiResponsesHttpError> {
        validate_api_key(api_key)?;
        let body = serde_json::to_vec(request)
            .map_err(|_| OpenAiResponsesHttpError::InvalidRequestJson)?;
        if body.len() > OPENAI_REQUEST_LIMIT_BYTES {
            return Err(OpenAiResponsesHttpError::RequestTooLarge {
                limit_bytes: OPENAI_REQUEST_LIMIT_BYTES,
            });
        }

        let started = Instant::now();
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .bearer_auth(api_key.expose_secret())
            .body(body)
            .send()
            .await
            .map_err(map_send_error)?;

        validate_response_headers(response.headers())?;
        let metadata = response_metadata(&response, started)?;
        validate_json_content_type(response.headers())?;
        let status = response.status();
        if !status.is_success() {
            return Err(OpenAiResponsesHttpError::HttpStatus {
                kind: classify_status(status),
                status: status.as_u16(),
                metadata,
            });
        }

        if response
            .content_length()
            .is_some_and(|length| length > OPENAI_RESPONSE_LIMIT_BYTES as u64)
        {
            return Err(OpenAiResponsesHttpError::ResponseTooLarge {
                limit_bytes: OPENAI_RESPONSE_LIMIT_BYTES,
            });
        }

        let body = read_bounded_body(response).await?;
        let mut metadata = metadata;
        metadata.response_bytes = body.len();
        let json = serde_json::from_slice(&body)
            .map_err(|_| OpenAiResponsesHttpError::MalformedResponseJson)?;
        Ok(OpenAiJsonResponse { json, metadata })
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub struct TestTransportTimeouts {
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
pub struct OpenAiJsonResponse {
    pub json: Value,
    pub metadata: OpenAiResponseMetadata,
}

impl fmt::Debug for OpenAiJsonResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiJsonResponse")
            .field("json", &"[REDACTED]")
            .field("metadata", &self.metadata)
            .finish()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OpenAiResponseMetadata {
    pub request_id: Option<String>,
    pub retained_headers: BTreeMap<String, String>,
    pub status: u16,
    pub latency_ms: u64,
    pub response_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiHttpStatusKind {
    Authentication,
    Permission,
    RateLimited,
    RequestRejected,
    ProviderFailure,
    Unexpected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiTimeoutKind {
    Connect,
    Attempt,
    ResponseRead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiOutcomeUnknownKind {
    RequestExecution,
    ResponseRead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenAiHeaderLimitKind {
    Count,
    AggregateBytes,
    ValueBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenAiResponsesHttpError {
    ClientConfiguration,
    InvalidCredential,
    InvalidRequestJson,
    RequestTooLarge {
        limit_bytes: usize,
    },
    TransportBeforeSend,
    Timeout {
        kind: OpenAiTimeoutKind,
        outcome_unknown: bool,
    },
    OutcomeUnknown {
        kind: OpenAiOutcomeUnknownKind,
    },
    ResponseHeaderLimit {
        kind: OpenAiHeaderLimitKind,
    },
    InvalidResponseHeaders,
    UnsupportedMediaType,
    HttpStatus {
        kind: OpenAiHttpStatusKind,
        status: u16,
        metadata: OpenAiResponseMetadata,
    },
    ResponseTooLarge {
        limit_bytes: usize,
    },
    MalformedResponseJson,
}

impl OpenAiResponsesHttpError {
    pub fn outcome_is_unknown(&self) -> bool {
        matches!(
            self,
            Self::OutcomeUnknown { .. }
                | Self::Timeout {
                    outcome_unknown: true,
                    ..
                }
        )
    }
}

impl fmt::Display for OpenAiResponsesHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenAI Responses HTTP operation failed: ")?;
        match self {
            Self::ClientConfiguration => formatter.write_str("client_configuration"),
            Self::InvalidCredential => formatter.write_str("invalid_credential"),
            Self::InvalidRequestJson => formatter.write_str("invalid_request_json"),
            Self::RequestTooLarge { .. } => formatter.write_str("request_too_large"),
            Self::TransportBeforeSend => formatter.write_str("transport_before_send"),
            Self::Timeout { kind, .. } => write!(formatter, "timeout_{kind:?}"),
            Self::OutcomeUnknown { kind } => write!(formatter, "outcome_unknown_{kind:?}"),
            Self::ResponseHeaderLimit { kind } => {
                write!(formatter, "response_header_limit_{kind:?}")
            }
            Self::InvalidResponseHeaders => formatter.write_str("invalid_response_headers"),
            Self::UnsupportedMediaType => formatter.write_str("unsupported_media_type"),
            Self::HttpStatus { kind, status, .. } => {
                write!(formatter, "http_status_{kind:?}_{status}")
            }
            Self::ResponseTooLarge { .. } => formatter.write_str("response_too_large"),
            Self::MalformedResponseJson => formatter.write_str("malformed_response_json"),
        }
    }
}

impl std::error::Error for OpenAiResponsesHttpError {}

fn validate_api_key(api_key: &SecretString) -> Result<(), OpenAiResponsesHttpError> {
    let value = api_key.expose_secret();
    if value.is_empty()
        || value.len() > MAX_API_KEY_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(OpenAiResponsesHttpError::InvalidCredential);
    }
    Ok(())
}

fn validate_response_headers(headers: &HeaderMap) -> Result<(), OpenAiResponsesHttpError> {
    let mut count = 0_usize;
    let mut aggregate = 0_usize;
    for (name, value) in headers {
        count = count.saturating_add(1);
        if count > OPENAI_RESPONSE_HEADER_LIMIT {
            return Err(OpenAiResponsesHttpError::ResponseHeaderLimit {
                kind: OpenAiHeaderLimitKind::Count,
            });
        }
        if value.as_bytes().len() > OPENAI_RESPONSE_HEADER_VALUE_LIMIT {
            return Err(OpenAiResponsesHttpError::ResponseHeaderLimit {
                kind: OpenAiHeaderLimitKind::ValueBytes,
            });
        }
        aggregate = aggregate
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len());
        if aggregate > OPENAI_RESPONSE_HEADER_BYTES_LIMIT {
            return Err(OpenAiResponsesHttpError::ResponseHeaderLimit {
                kind: OpenAiHeaderLimitKind::AggregateBytes,
            });
        }
    }
    Ok(())
}

fn validate_json_content_type(headers: &HeaderMap) -> Result<(), OpenAiResponsesHttpError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values
        .next()
        .ok_or(OpenAiResponsesHttpError::UnsupportedMediaType)?;
    if values.next().is_some() {
        return Err(OpenAiResponsesHttpError::InvalidResponseHeaders);
    }
    let value = value
        .to_str()
        .map_err(|_| OpenAiResponsesHttpError::InvalidResponseHeaders)?;
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(OpenAiResponsesHttpError::UnsupportedMediaType);
    }
    Ok(())
}

fn response_metadata(
    response: &reqwest::Response,
    started: Instant,
) -> Result<OpenAiResponseMetadata, OpenAiResponsesHttpError> {
    let headers = response.headers();
    let request_id = retained_header(headers, "x-request-id", MAX_REQUEST_ID_BYTES)?;
    let mut retained_headers = BTreeMap::new();
    for name in RETAINED_RESPONSE_HEADERS {
        if let Some(value) = retained_header(headers, name, MAX_RETAINED_HEADER_VALUE_BYTES)? {
            retained_headers.insert((*name).to_owned(), value);
        }
    }
    Ok(OpenAiResponseMetadata {
        request_id,
        retained_headers,
        status: response.status().as_u16(),
        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        response_bytes: 0,
    })
}

fn retained_header(
    headers: &HeaderMap,
    name: &'static str,
    limit: usize,
) -> Result<Option<String>, OpenAiResponsesHttpError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(OpenAiResponsesHttpError::InvalidResponseHeaders);
    }
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > limit || !bytes.iter().all(|byte| byte.is_ascii_graphic())
    {
        return Err(OpenAiResponsesHttpError::InvalidResponseHeaders);
    }
    let value = value
        .to_str()
        .map_err(|_| OpenAiResponsesHttpError::InvalidResponseHeaders)?;
    Ok(Some(value.to_owned()))
}

fn classify_status(status: StatusCode) -> OpenAiHttpStatusKind {
    match status {
        StatusCode::UNAUTHORIZED => OpenAiHttpStatusKind::Authentication,
        StatusCode::FORBIDDEN => OpenAiHttpStatusKind::Permission,
        StatusCode::TOO_MANY_REQUESTS => OpenAiHttpStatusKind::RateLimited,
        status if status.is_client_error() => OpenAiHttpStatusKind::RequestRejected,
        status if status.is_server_error() => OpenAiHttpStatusKind::ProviderFailure,
        _ => OpenAiHttpStatusKind::Unexpected,
    }
}

fn map_send_error(error: reqwest::Error) -> OpenAiResponsesHttpError {
    if error.is_timeout() {
        let connect = error.is_connect();
        return OpenAiResponsesHttpError::Timeout {
            kind: if connect {
                OpenAiTimeoutKind::Connect
            } else {
                OpenAiTimeoutKind::Attempt
            },
            outcome_unknown: !connect,
        };
    }
    if error.is_connect() {
        OpenAiResponsesHttpError::TransportBeforeSend
    } else {
        OpenAiResponsesHttpError::OutcomeUnknown {
            kind: OpenAiOutcomeUnknownKind::RequestExecution,
        }
    }
}

async fn read_bounded_body(
    mut response: reqwest::Response,
) -> Result<Vec<u8>, OpenAiResponsesHttpError> {
    let mut body = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(map_body_error)?;
        let Some(chunk) = chunk else {
            return Ok(body);
        };
        if body.len().saturating_add(chunk.len()) > OPENAI_RESPONSE_LIMIT_BYTES {
            return Err(OpenAiResponsesHttpError::ResponseTooLarge {
                limit_bytes: OPENAI_RESPONSE_LIMIT_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }
}

fn map_body_error(error: reqwest::Error) -> OpenAiResponsesHttpError {
    if error.is_timeout() {
        OpenAiResponsesHttpError::Timeout {
            kind: OpenAiTimeoutKind::ResponseRead,
            outcome_unknown: true,
        }
    } else {
        OpenAiResponsesHttpError::OutcomeUnknown {
            kind: OpenAiOutcomeUnknownKind::ResponseRead,
        }
    }
}
