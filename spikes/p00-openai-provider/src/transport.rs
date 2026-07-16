use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub struct OutboundRequest {
    pub endpoint: String,
    pub client_request_id: String,
    pub body: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json(
        status: u16,
        headers: impl IntoIterator<Item = (String, String)>,
        body: Value,
    ) -> Self {
        Self {
            status,
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect(),
            body: serde_json::to_vec(&body).expect("fake JSON response must serialize"),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Timeout,
    Connect,
    Dns,
    Tls,
    RequestBody,
    ResponseTooLarge,
    ResponseBody,
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "provider transport failed: {self:?}")
    }
}

impl Error for TransportError {}

pub trait ResponsesTransport: Send + Sync {
    fn send(&self, request: &OutboundRequest) -> Result<HttpResponse, TransportError>;
}

#[derive(Clone, Debug)]
pub enum FakeStep {
    Response(HttpResponse),
    Error(TransportError),
}

#[derive(Debug)]
pub struct FakeTransport {
    steps: Mutex<VecDeque<FakeStep>>,
    requests: Mutex<Vec<OutboundRequest>>,
}

impl FakeTransport {
    pub fn new(steps: impl IntoIterator<Item = FakeStep>) -> Self {
        Self {
            steps: Mutex::new(steps.into_iter().collect()),
            requests: Mutex::new(Vec::new()),
        }
    }

    pub fn requests(&self) -> Vec<OutboundRequest> {
        self.requests
            .lock()
            .expect("fake transport request lock poisoned")
            .clone()
    }

    pub fn assert_exhausted(&self) {
        assert!(
            self.steps
                .lock()
                .expect("fake transport script lock poisoned")
                .is_empty(),
            "fake transport has unconsumed steps"
        );
    }
}

impl ResponsesTransport for FakeTransport {
    fn send(&self, request: &OutboundRequest) -> Result<HttpResponse, TransportError> {
        self.requests
            .lock()
            .expect("fake transport request lock poisoned")
            .push(request.clone());
        match self
            .steps
            .lock()
            .expect("fake transport script lock poisoned")
            .pop_front()
            .expect("fake transport received an unexpected request")
        {
            FakeStep::Response(response) => Ok(response),
            FakeStep::Error(error) => Err(error),
        }
    }
}

#[cfg(feature = "live-canary")]
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

#[cfg(feature = "live-canary")]
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
    api_key: SecretApiKey,
}

#[cfg(feature = "live-canary")]
struct SecretApiKey(String);

#[cfg(feature = "live-canary")]
impl ReqwestTransport {
    pub fn from_env() -> Result<Self, ReqwestTransportConfigurationError> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .map_err(|_| ReqwestTransportConfigurationError::MissingApiKey)?;
        if api_key.is_empty() || api_key.chars().any(char::is_whitespace) {
            return Err(ReqwestTransportConfigurationError::InvalidApiKey);
        }
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(
                crate::request::CONNECT_TIMEOUT_MILLIS,
            ))
            .timeout(std::time::Duration::from_millis(
                crate::request::TOTAL_DEADLINE_MILLIS,
            ))
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| ReqwestTransportConfigurationError::Client)?;
        Ok(Self {
            client,
            api_key: SecretApiKey(api_key),
        })
    }
}

#[cfg(feature = "live-canary")]
impl ResponsesTransport for ReqwestTransport {
    fn send(&self, request: &OutboundRequest) -> Result<HttpResponse, TransportError> {
        use std::io::Read;

        let response = self
            .client
            .post(&request.endpoint)
            .bearer_auth(&self.api_key.0)
            .header("X-Client-Request-Id", &request.client_request_id)
            .json(&request.body)
            .send()
            .map_err(classify_reqwest_error)?;

        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES)
        {
            return Err(TransportError::ResponseTooLarge);
        }
        let status = response.status().as_u16();
        let mut headers = BTreeMap::new();
        for name in ["x-request-id", "retry-after"] {
            if let Some(value) = response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
            {
                headers.insert(name.to_owned(), value.to_owned());
            }
        }
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| TransportError::ResponseBody)?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(TransportError::ResponseTooLarge);
        }
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

#[cfg(feature = "live-canary")]
fn classify_reqwest_error(error: reqwest::Error) -> TransportError {
    if error.is_timeout() {
        TransportError::Timeout
    } else if error.is_connect() {
        TransportError::Connect
    } else if error.is_builder() {
        TransportError::RequestBody
    } else {
        TransportError::ResponseBody
    }
}

#[cfg(feature = "live-canary")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReqwestTransportConfigurationError {
    MissingApiKey,
    InvalidApiKey,
    Client,
}

#[cfg(feature = "live-canary")]
impl fmt::Display for ReqwestTransportConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("live transport configuration is unavailable")
    }
}

#[cfg(feature = "live-canary")]
impl Error for ReqwestTransportConfigurationError {}
