use crate::gmail_sync::{
    GatewayError, GmailGateway, HistoryEvent, HistoryEventKind, HistoryPage, MessagePage,
    RawGmailMessage,
};
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use reqwest::header::{HeaderMap, ACCEPT, CONTENT_TYPE};
use reqwest::{redirect::Policy, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Instant};
use url::Url;
use wardrobe_core::SecretString;
use zeroize::{Zeroize, Zeroizing};

pub const GOOGLE_OAUTH_SCOPE: &str = "openid https://www.googleapis.com/auth/gmail.readonly";
const HTTP_ATTEMPTS: usize = 3;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const TOKEN_BODY_CAP: usize = 64 * 1024;
const USERINFO_BODY_CAP: usize = 64 * 1024;
const LABELS_BODY_CAP: usize = 1024 * 1024;
const PAGE_BODY_CAP: usize = 2 * 1024 * 1024;
const RAW_JSON_BODY_CAP: usize = 36 * 1024 * 1024;

#[derive(Clone)]
struct GoogleEndpoints {
    authorization: Url,
    token: Url,
    revocation: Url,
    userinfo: Url,
    gmail_api: Url,
}

impl GoogleEndpoints {
    fn production() -> Self {
        Self {
            authorization: Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
                .expect("fixed authorization URL"),
            token: Url::parse("https://oauth2.googleapis.com/token").expect("fixed token URL"),
            revocation: Url::parse("https://oauth2.googleapis.com/revoke")
                .expect("fixed revocation URL"),
            userinfo: Url::parse("https://openidconnect.googleapis.com/v1/userinfo")
                .expect("fixed userinfo URL"),
            gmail_api: Url::parse("https://gmail.googleapis.com/gmail/v1/")
                .expect("fixed Gmail API URL"),
        }
    }
}

#[derive(Clone)]
pub struct GoogleHttpClient {
    client: reqwest::Client,
    endpoints: GoogleEndpoints,
}

impl fmt::Debug for GoogleHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GoogleHttpClient")
    }
}

impl GoogleHttpClient {
    pub fn production() -> Result<Self, GoogleHttpError> {
        let client = reqwest::Client::builder()
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
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| GoogleHttpError::Client)?;
        Ok(Self {
            client,
            endpoints: GoogleEndpoints::production(),
        })
    }

    #[cfg(test)]
    fn for_test(
        origin: Url,
        certificate: reqwest::Certificate,
        socket: SocketAddr,
    ) -> Result<Self, GoogleHttpError> {
        if origin.scheme() != "https" || origin.host_str().is_none() {
            return Err(GoogleHttpError::Client);
        }
        let client = reqwest::Client::builder()
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
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .tls_certs_only(vec![certificate])
            .resolve("fixture.invalid", socket)
            .build()
            .map_err(|_| GoogleHttpError::Client)?;
        let endpoint = |path: &str| origin.join(path).map_err(|_| GoogleHttpError::Client);
        Ok(Self {
            client,
            endpoints: GoogleEndpoints {
                authorization: endpoint("authorize")?,
                token: endpoint("token")?,
                revocation: endpoint("revoke")?,
                userinfo: endpoint("userinfo")?,
                gmail_api: endpoint("gmail/v1/")?,
            },
        })
    }

    pub async fn exchange_authorization_code(
        &self,
        client_id: &str,
        code: &SecretString,
        redirect_uri: &str,
        verifier: &SecretString,
    ) -> Result<OAuthTokenSet, GoogleHttpError> {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer
            .append_pair("client_id", client_id)
            .append_pair("code", code.expose_secret())
            .append_pair("code_verifier", verifier.expose_secret())
            .append_pair("grant_type", "authorization_code")
            .append_pair("redirect_uri", redirect_uri);
        let body = Zeroizing::new(serializer.finish());
        let response: TokenResponse = self
            .request_json(
                Method::POST,
                self.endpoints.token.clone(),
                Some(body.as_bytes()),
                None,
                TOKEN_BODY_CAP,
                false,
            )
            .await?;
        let refresh = response
            .refresh_token
            .filter(|value| !value.is_empty())
            .ok_or(GoogleHttpError::MalformedResponse)?;
        validate_token(&response.access_token)?;
        validate_token(&refresh)?;
        Ok(OAuthTokenSet {
            access_token: SecretString::new(response.access_token),
            refresh_token: SecretString::new(refresh),
        })
    }

    pub async fn refresh_access_token(
        &self,
        client_id: &str,
        refresh_token: &SecretString,
    ) -> Result<RefreshedToken, GoogleHttpError> {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer
            .append_pair("client_id", client_id)
            .append_pair("refresh_token", refresh_token.expose_secret())
            .append_pair("grant_type", "refresh_token");
        let body = Zeroizing::new(serializer.finish());
        let response: TokenResponse = self
            .request_json(
                Method::POST,
                self.endpoints.token.clone(),
                Some(body.as_bytes()),
                None,
                TOKEN_BODY_CAP,
                false,
            )
            .await?;
        validate_token(&response.access_token)?;
        if response
            .refresh_token
            .as_ref()
            .is_some_and(|value| validate_token(value).is_err())
        {
            return Err(GoogleHttpError::MalformedResponse);
        }
        Ok(RefreshedToken {
            access_token: SecretString::new(response.access_token),
            rotated_refresh_token: response.refresh_token.map(SecretString::new),
        })
    }

    pub async fn revoke(
        &self,
        refresh_token: &SecretString,
    ) -> Result<RevocationResult, GoogleHttpError> {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("token", refresh_token.expose_secret());
        let body = Zeroizing::new(serializer.finish());
        let response = self
            .request(
                Method::POST,
                self.endpoints.revocation.clone(),
                Some(body.as_bytes()),
                None,
                TOKEN_BODY_CAP,
                false,
            )
            .await?;
        match response.status {
            StatusCode::OK => Ok(RevocationResult::Succeeded),
            StatusCode::BAD_REQUEST => Ok(RevocationResult::AlreadyInvalid),
            _ => Err(map_status(response.status)),
        }
    }

    pub async fn user_subject(
        &self,
        access_token: &SecretString,
    ) -> Result<String, GoogleHttpError> {
        let response: UserInfoResponse = self
            .request_json(
                Method::GET,
                self.endpoints.userinfo.clone(),
                None,
                Some(access_token),
                USERINFO_BODY_CAP,
                true,
            )
            .await?;
        if response.sub.is_empty() || response.sub.len() > 256 || !response.sub.is_ascii() {
            return Err(GoogleHttpError::MalformedResponse);
        }
        Ok(response.sub)
    }

    async fn request_json<T: DeserializeOwned>(
        &self,
        method: Method,
        url: Url,
        body: Option<&[u8]>,
        access_token: Option<&SecretString>,
        cap: usize,
        retry_read: bool,
    ) -> Result<T, GoogleHttpError> {
        let response = self
            .request(method, url, body, access_token, cap, retry_read)
            .await?;
        if !response.status.is_success() {
            return Err(map_status(response.status));
        }
        serde_json::from_slice(&response.body).map_err(|_| GoogleHttpError::MalformedResponse)
    }

    async fn request(
        &self,
        method: Method,
        url: Url,
        body: Option<&[u8]>,
        access_token: Option<&SecretString>,
        cap: usize,
        retry_read: bool,
    ) -> Result<CappedResponse, GoogleHttpError> {
        let operation_deadline = Instant::now() + OPERATION_TIMEOUT;
        for attempt in 0..HTTP_ATTEMPTS {
            let mut request = self
                .client
                .request(method.clone(), url.clone())
                .header(ACCEPT, "application/json");
            if body.is_some() {
                request = request.header(CONTENT_TYPE, "application/x-www-form-urlencoded");
            }
            if let Some(token) = access_token {
                request = request.bearer_auth(token.expose_secret());
            }
            if let Some(body) = body {
                request = request.body(body.to_vec());
            }
            let response = match timeout_at_operation(operation_deadline, request.send()).await {
                Ok(response) => response,
                Err(error @ GoogleHttpError::Transport)
                    if retry_read && attempt + 1 < HTTP_ATTEMPTS =>
                {
                    let _ = error;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let status = response.status();
            if retry_read
                && attempt + 1 < HTTP_ATTEMPTS
                && (status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error())
            {
                continue;
            }
            let body = read_capped(response, cap).await?;
            return Ok(CappedResponse { status, body });
        }
        Err(GoogleHttpError::Transport)
    }
}

pub struct OAuthTokenSet {
    pub access_token: SecretString,
    pub refresh_token: SecretString,
}

pub struct RefreshedToken {
    pub access_token: SecretString,
    pub rotated_refresh_token: Option<SecretString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationResult {
    Succeeded,
    AlreadyInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GoogleHttpError {
    Client,
    Authentication,
    Permission,
    RateLimited,
    Quota,
    Transport,
    Server,
    Timeout,
    MalformedRequest,
    MalformedResponse,
    BodyTooLarge,
}

impl fmt::Display for GoogleHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Google HTTP operation failed: {self:?}")
    }
}

impl std::error::Error for GoogleHttpError {}

pub struct PendingPkceAuthorization {
    listener: TcpListener,
    state: Zeroizing<String>,
    verifier: Zeroizing<String>,
    callback_path: String,
    redirect_uri: String,
    authorization_url: Url,
}

impl fmt::Debug for PendingPkceAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingPkceAuthorization([REDACTED])")
    }
}

impl PendingPkceAuthorization {
    pub async fn bind(client_id: &str, http: &GoogleHttpClient) -> Result<Self, GoogleHttpError> {
        validate_client_id(client_id)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| GoogleHttpError::Client)?;
        let port = listener
            .local_addr()
            .map_err(|_| GoogleHttpError::Client)?
            .port();
        let state = Zeroizing::new(random_urlsafe(32)?);
        let verifier = Zeroizing::new(random_urlsafe(32)?);
        let callback_path = format!("/oauth2/callback/{}", random_urlsafe(16)?);
        let redirect_uri = format!("http://127.0.0.1:{port}{callback_path}");
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut authorization_url = http.endpoints.authorization.clone();
        authorization_url
            .query_pairs_mut()
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", GOOGLE_OAUTH_SCOPE)
            .append_pair("state", &state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent");
        Ok(Self {
            listener,
            state,
            verifier,
            callback_path,
            redirect_uri,
            authorization_url,
        })
    }

    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub async fn wait_for_code(mut self) -> Result<(SecretString, SecretString), GoogleHttpError> {
        let result = timeout(Duration::from_secs(180), async {
            let (mut stream, peer) = self
                .listener
                .accept()
                .await
                .map_err(|_| GoogleHttpError::Transport)?;
            if !is_loopback(peer) {
                return Err(GoogleHttpError::MalformedRequest);
            }
            let mut request = Vec::with_capacity(1024);
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream
                    .read(&mut buffer)
                    .await
                    .map_err(|_| GoogleHttpError::Transport)?;
                if read == 0 || request.len() + read > 8192 {
                    return Err(GoogleHttpError::MalformedRequest);
                }
                request.extend_from_slice(&buffer[..read]);
            }
            let request_text =
                std::str::from_utf8(&request).map_err(|_| GoogleHttpError::MalformedRequest)?;
            let request_line = request_text
                .split("\r\n")
                .next()
                .ok_or(GoogleHttpError::MalformedRequest)?;
            let mut fields = request_line.split(' ');
            if fields.next() != Some("GET") || fields.next_back() != Some("HTTP/1.1") {
                return Err(GoogleHttpError::MalformedRequest);
            }
            let target = fields.next().ok_or(GoogleHttpError::MalformedRequest)?;
            if fields.next().is_some() {
                return Err(GoogleHttpError::MalformedRequest);
            }
            let callback = Url::parse(&format!("http://127.0.0.1{target}"))
                .map_err(|_| GoogleHttpError::MalformedRequest)?;
            if callback.path() != self.callback_path {
                return Err(GoogleHttpError::MalformedRequest);
            }
            let mut code = None;
            let mut state = None;
            for (name, value) in callback.query_pairs() {
                match name.as_ref() {
                    "code" if code.is_none() => code = Some(value.into_owned()),
                    "state" if state.is_none() => state = Some(value.into_owned()),
                    "code" | "state" => return Err(GoogleHttpError::MalformedRequest),
                    _ => {}
                }
            }
            if state.as_deref() != Some(self.state.as_str()) {
                return Err(GoogleHttpError::MalformedRequest);
            }
            let code = code
                .filter(|value| !value.is_empty() && value.len() <= 4096)
                .ok_or(GoogleHttpError::MalformedRequest)?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\
                      Cache-Control: no-store\r\nContent-Length: 24\r\nConnection: close\r\n\r\n\
                      Authorization complete.",
                )
                .await
                .map_err(|_| GoogleHttpError::Transport)?;
            stream
                .shutdown()
                .await
                .map_err(|_| GoogleHttpError::Transport)?;
            Ok((
                SecretString::new(code),
                SecretString::new(std::mem::take(&mut *self.verifier)),
            ))
        })
        .await
        .map_err(|_| GoogleHttpError::Timeout)?;
        self.state.zeroize();
        result
    }
}

pub struct GoogleGmailGateway {
    http: GoogleHttpClient,
    access_token: SecretString,
    label_id: String,
}

impl GoogleGmailGateway {
    pub fn new(http: GoogleHttpClient, access_token: SecretString, label_id: String) -> Self {
        Self {
            http,
            access_token,
            label_id,
        }
    }

    pub async fn resolve_label_id(
        http: &GoogleHttpClient,
        access_token: &SecretString,
        label_name: &str,
    ) -> Result<String, GoogleHttpError> {
        let url = gmail_url(&http.endpoints, "users/me/labels")?;
        let response: LabelsResponse = http
            .request_json(
                Method::GET,
                url,
                None,
                Some(access_token),
                LABELS_BODY_CAP,
                true,
            )
            .await?;
        let mut matches = response
            .labels
            .into_iter()
            .filter(|label| label.name == label_name);
        let label = matches.next().ok_or(GoogleHttpError::MalformedRequest)?;
        if matches.next().is_some() {
            return Err(GoogleHttpError::MalformedResponse);
        }
        validate_provider_value(&label.id)?;
        Ok(label.id)
    }
}

impl GmailGateway for GoogleGmailGateway {
    async fn profile_history_id(&mut self) -> Result<String, GatewayError> {
        let url = gmail_url(&self.http.endpoints, "users/me/profile").map_err(map_gateway)?;
        let response: ProfileResponse = self
            .http
            .request_json(
                Method::GET,
                url,
                None,
                Some(&self.access_token),
                USERINFO_BODY_CAP,
                true,
            )
            .await
            .map_err(map_gateway)?;
        Ok(response.history_id)
    }

    async fn list_messages(
        &mut self,
        label_id: &str,
        page_token: Option<&str>,
        page_size: usize,
    ) -> Result<MessagePage, GatewayError> {
        if label_id != self.label_id {
            return Err(GatewayError::MalformedRequest);
        }
        let mut url = gmail_url(&self.http.endpoints, "users/me/messages").map_err(map_gateway)?;
        url.query_pairs_mut()
            .append_pair("labelIds", label_id)
            .append_pair("maxResults", &page_size.to_string());
        if let Some(token) = page_token {
            url.query_pairs_mut().append_pair("pageToken", token);
        }
        let response: MessagesResponse = self
            .http
            .request_json(
                Method::GET,
                url,
                None,
                Some(&self.access_token),
                PAGE_BODY_CAP,
                true,
            )
            .await
            .map_err(map_gateway)?;
        Ok(MessagePage {
            message_ids: response
                .messages
                .into_iter()
                .map(|message| message.id)
                .collect(),
            next_page_token: response.next_page_token,
        })
    }

    async fn get_message(&mut self, message_id: &str) -> Result<RawGmailMessage, GatewayError> {
        validate_provider_value(message_id).map_err(map_gateway)?;
        let mut url = gmail_url(
            &self.http.endpoints,
            &format!("users/me/messages/{message_id}"),
        )
        .map_err(map_gateway)?;
        url.query_pairs_mut().append_pair("format", "raw");
        let response = self
            .http
            .request(
                Method::GET,
                url,
                None,
                Some(&self.access_token),
                RAW_JSON_BODY_CAP,
                true,
            )
            .await
            .map_err(map_gateway)?;
        if response.status == StatusCode::NOT_FOUND {
            return Err(GatewayError::MessageNotFound);
        }
        if !response.status.is_success() {
            return Err(map_gateway(map_status(response.status)));
        }
        let response: RawMessageResponse =
            serde_json::from_slice(&response.body).map_err(|_| GatewayError::MalformedResponse)?;
        if response.raw.len() > RAW_JSON_BODY_CAP {
            return Err(GatewayError::MalformedResponse);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(response.raw.as_bytes())
            .or_else(|_| URL_SAFE.decode(response.raw.as_bytes()))
            .map_err(|_| GatewayError::MalformedResponse)?;
        if raw.len() > crate::GMAIL_RAW_MESSAGE_LIMIT {
            return Err(GatewayError::MalformedResponse);
        }
        Ok(RawGmailMessage {
            id: response.id,
            history_id: response.history_id,
            label_ids: response.label_ids,
            raw,
        })
    }

    async fn list_history(
        &mut self,
        start_history_id: &str,
        label_id: &str,
        page_token: Option<&str>,
        page_size: usize,
    ) -> Result<HistoryPage, GatewayError> {
        if label_id != self.label_id {
            return Err(GatewayError::MalformedRequest);
        }
        let mut url = gmail_url(&self.http.endpoints, "users/me/history").map_err(map_gateway)?;
        url.query_pairs_mut()
            .append_pair("startHistoryId", start_history_id)
            .append_pair("labelId", label_id)
            .append_pair("maxResults", &page_size.to_string())
            .append_pair(
                "historyTypes",
                "messageAdded,labelAdded,labelRemoved,messageDeleted",
            );
        if let Some(token) = page_token {
            url.query_pairs_mut().append_pair("pageToken", token);
        }
        let response = self
            .http
            .request(
                Method::GET,
                url,
                None,
                Some(&self.access_token),
                PAGE_BODY_CAP,
                true,
            )
            .await
            .map_err(map_gateway)?;
        if response.status == StatusCode::NOT_FOUND && is_not_found_error(&response.body) {
            return Err(GatewayError::HistoryNotFound);
        }
        if !response.status.is_success() {
            return Err(map_gateway(map_status(response.status)));
        }
        let response: HistoryResponse =
            serde_json::from_slice(&response.body).map_err(|_| GatewayError::MalformedResponse)?;
        let mut events = Vec::new();
        for record in response.history {
            for event in record.messages_added {
                events.push(HistoryEvent {
                    history_id: record.id.clone(),
                    message_id: event.message.id,
                    kind: HistoryEventKind::MessageAdded,
                });
            }
            for event in record.labels_added {
                if event.label_ids.iter().any(|label| label == label_id) {
                    events.push(HistoryEvent {
                        history_id: record.id.clone(),
                        message_id: event.message.id,
                        kind: HistoryEventKind::ScopedLabelAdded,
                    });
                }
            }
            for event in record.labels_removed {
                if event.label_ids.iter().any(|label| label == label_id) {
                    events.push(HistoryEvent {
                        history_id: record.id.clone(),
                        message_id: event.message.id,
                        kind: HistoryEventKind::ScopedLabelRemoved,
                    });
                }
            }
            for event in record.messages_deleted {
                events.push(HistoryEvent {
                    history_id: record.id.clone(),
                    message_id: event.message.id,
                    kind: HistoryEventKind::MessageDeleted,
                });
            }
        }
        Ok(HistoryPage {
            events,
            next_page_token: response.next_page_token,
            mailbox_history_id: response.history_id,
        })
    }
}

pub fn gmail_account_key(subject: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"wardrobe.gmail.account.v1");
    digest.update(subject.as_bytes());
    format!("{:x}", digest.finalize())
}

fn gmail_url(endpoints: &GoogleEndpoints, path: &str) -> Result<Url, GoogleHttpError> {
    if path.starts_with('/') || path.contains("..") {
        return Err(GoogleHttpError::MalformedRequest);
    }
    endpoints
        .gmail_api
        .join(path)
        .map_err(|_| GoogleHttpError::MalformedRequest)
}

struct CappedResponse {
    status: StatusCode,
    body: Vec<u8>,
}

async fn read_capped(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, GoogleHttpError> {
    if response
        .content_length()
        .is_some_and(|length| length > cap as u64)
    {
        return Err(GoogleHttpError::BodyTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| GoogleHttpError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(GoogleHttpError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn timeout_at_operation<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = Result<T, reqwest::Error>>,
) -> Result<T, GoogleHttpError> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| GoogleHttpError::Timeout)?
        .map_err(|_| GoogleHttpError::Transport)
}

fn map_status(status: StatusCode) -> GoogleHttpError {
    match status {
        StatusCode::UNAUTHORIZED => GoogleHttpError::Authentication,
        StatusCode::FORBIDDEN => GoogleHttpError::Permission,
        StatusCode::TOO_MANY_REQUESTS => GoogleHttpError::RateLimited,
        status if status.is_server_error() => GoogleHttpError::Server,
        _ => GoogleHttpError::MalformedRequest,
    }
}

fn map_gateway(error: GoogleHttpError) -> GatewayError {
    match error {
        GoogleHttpError::Authentication => GatewayError::Authentication,
        GoogleHttpError::Permission => GatewayError::Permission,
        GoogleHttpError::RateLimited => GatewayError::RateLimited,
        GoogleHttpError::Quota => GatewayError::Quota,
        GoogleHttpError::Transport | GoogleHttpError::Client => GatewayError::Transport,
        GoogleHttpError::Server => GatewayError::Server,
        GoogleHttpError::Timeout => GatewayError::Timeout,
        GoogleHttpError::MalformedRequest => GatewayError::MalformedRequest,
        GoogleHttpError::MalformedResponse | GoogleHttpError::BodyTooLarge => {
            GatewayError::MalformedResponse
        }
    }
}

fn validate_token(value: &str) -> Result<(), GoogleHttpError> {
    if value.is_empty() || value.len() > 16 * 1024 || value.bytes().any(|byte| byte < b' ') {
        return Err(GoogleHttpError::MalformedResponse);
    }
    Ok(())
}

fn validate_client_id(value: &str) -> Result<(), GoogleHttpError> {
    let prefix = value
        .strip_suffix(".apps.googleusercontent.com")
        .unwrap_or_default();
    if prefix.is_empty()
        || value.len() > 256
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(GoogleHttpError::MalformedRequest);
    }
    Ok(())
}

fn validate_provider_value(value: &str) -> Result<(), GoogleHttpError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(GoogleHttpError::MalformedResponse);
    }
    Ok(())
}

fn random_urlsafe(length: usize) -> Result<String, GoogleHttpError> {
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    bytes.truncate(length);
    let encoded = URL_SAFE_NO_PAD.encode(&bytes);
    bytes.zeroize();
    Ok(encoded)
}

fn is_loopback(address: SocketAddr) -> bool {
    address.ip().is_loopback()
}

fn is_not_found_error(body: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Envelope {
        error: ProviderError,
    }
    #[derive(Deserialize)]
    struct ProviderError {
        status: String,
    }
    serde_json::from_slice::<Envelope>(body).is_ok_and(|value| value.error.status == "NOT_FOUND")
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct UserInfoResponse {
    sub: String,
}

#[derive(Deserialize)]
struct ProfileResponse {
    #[serde(rename = "historyId")]
    history_id: String,
}

#[derive(Deserialize)]
struct Label {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct LabelsResponse {
    #[serde(default)]
    labels: Vec<Label>,
}

#[derive(Deserialize)]
struct MessageRef {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessagesResponse {
    #[serde(default)]
    messages: Vec<MessageRef>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawMessageResponse {
    id: String,
    history_id: String,
    #[serde(default)]
    label_ids: Vec<String>,
    raw: String,
}

#[derive(Deserialize)]
struct HistoryMessage {
    message: MessageRef,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryLabel {
    message: MessageRef,
    #[serde(default)]
    label_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryRecord {
    id: String,
    #[serde(default)]
    messages_added: Vec<HistoryMessage>,
    #[serde(default)]
    messages_deleted: Vec<HistoryMessage>,
    #[serde(default)]
    labels_added: Vec<HistoryLabel>,
    #[serde(default)]
    labels_removed: Vec<HistoryLabel>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryResponse {
    #[serde(default)]
    history: Vec<HistoryRecord>,
    next_page_token: Option<String>,
    history_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn account_key_is_stable_and_subject_is_not_retained() {
        let subject = "provider-subject-sentinel";
        let key = gmail_account_key(subject);
        assert_eq!(key.len(), 64);
        assert!(!key.contains(subject));
        assert_eq!(key, gmail_account_key(subject));
    }

    #[tokio::test]
    async fn loopback_pkce_requires_exact_path_state_and_one_code() {
        let http = GoogleHttpClient {
            client: reqwest::Client::new(),
            endpoints: GoogleEndpoints::production(),
        };
        let pending = PendingPkceAuthorization::bind("client.apps.googleusercontent.com", &http)
            .await
            .unwrap();
        let callback = Url::parse(pending.redirect_uri()).unwrap();
        let state = pending
            .authorization_url()
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1
            .into_owned();
        let task = tokio::spawn(pending.wait_for_code());
        let mut stream =
            tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, callback.port().unwrap()))
                .await
                .unwrap();
        stream
            .write_all(
                format!(
                    "GET {}?code=authorization-code&state={} HTTP/1.1\r\n\
                     Host: 127.0.0.1\r\nConnection: close\r\n\r\n",
                    callback.path(),
                    state
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let (code, verifier) = task.await.unwrap().unwrap();
        assert_eq!(code.expose_secret(), "authorization-code");
        assert!(verifier.len_bytes() >= 43);
    }

    #[tokio::test]
    async fn local_tls_drives_token_userinfo_and_gmail_adapter() {
        let root_der = fixture_der("FIXTURE_CERT_DER");
        let leaf_der = fixture_der("FIXTURE_LEAF_CERT_DER");
        let key_der = fixture_der("FIXTURE_LEAF_KEY_DER");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(leaf_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socket = listener.local_addr().unwrap();
        let responses = [
            r#"{"access_token":"access-sentinel","refresh_token":"rotated-sentinel"}"#,
            r#"{"sub":"subject-sentinel"}"#,
            r#"{"labels":[{"id":"Label_1","name":"Wardrobe Receipts"}]}"#,
            r#"{"historyId":"10"}"#,
            r#"{"messages":[{"id":"m1"}]}"#,
            r#"{"id":"m1","historyId":"11","labelIds":["Label_1"],"raw":"U3ViamVjdDogcmVjZWlwdA0KDQpib2R5"}"#,
            r#"{"history":[{"id":"12","labelsRemoved":[{"message":{"id":"m1"},"labelIds":["Label_1"]}]}],"historyId":"12"}"#,
        ];
        let server = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let mut requests = Vec::new();
            for response in responses {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 2048];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut buffer).await.unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&buffer[..read]);
                    assert!(request.len() <= 16 * 1024);
                }
                let content_length = String::from_utf8_lossy(&request)
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while request
                    .split(|byte| *byte == b'\r')
                    .next_back()
                    .map_or(0, |tail| tail.len())
                    < content_length
                {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                }
                let wire = String::from_utf8_lossy(&request).into_owned();
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                );
                stream.write_all(headers.as_bytes()).await.unwrap();
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
                requests.push(wire);
            }
            requests
        });

        let origin = Url::parse(&format!("https://fixture.invalid:{}/", socket.port())).unwrap();
        let certificate = reqwest::Certificate::from_der(&root_der).unwrap();
        let http = GoogleHttpClient::for_test(origin, certificate, socket).unwrap();
        let refresh = SecretString::new("refresh-sentinel".into());
        let refreshed = http
            .refresh_access_token("client.apps.googleusercontent.com", &refresh)
            .await
            .unwrap();
        assert_eq!(refreshed.access_token.expose_secret(), "access-sentinel");
        assert_eq!(
            refreshed
                .rotated_refresh_token
                .as_ref()
                .unwrap()
                .expose_secret(),
            "rotated-sentinel"
        );
        assert_eq!(
            http.user_subject(&refreshed.access_token).await.unwrap(),
            "subject-sentinel"
        );
        let label = GoogleGmailGateway::resolve_label_id(
            &http,
            &refreshed.access_token,
            "Wardrobe Receipts",
        )
        .await
        .unwrap();
        let mut gateway = GoogleGmailGateway::new(http, refreshed.access_token, label.clone());
        assert_eq!(gateway.profile_history_id().await.unwrap(), "10");
        assert_eq!(
            gateway
                .list_messages(&label, None, 50)
                .await
                .unwrap()
                .message_ids,
            ["m1"]
        );
        assert_eq!(
            gateway.get_message("m1").await.unwrap().raw,
            b"Subject: receipt\r\n\r\nbody"
        );
        assert_eq!(
            gateway
                .list_history("10", &label, None, 50)
                .await
                .unwrap()
                .events[0]
                .kind,
            HistoryEventKind::ScopedLabelRemoved
        );
        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("POST /token HTTP/1.1\r\n"));
        assert!(requests[0].contains("refresh_token=refresh-sentinel"));
        assert!(requests[1].starts_with("GET /userinfo HTTP/1.1\r\n"));
        assert!(requests[1]
            .to_ascii_lowercase()
            .contains("authorization: bearer access-sentinel"));
        assert!(requests[6].contains("startHistoryId=10"));
        assert!(requests[6].contains("labelId=Label_1"));
    }

    fn fixture_der(name: &str) -> Vec<u8> {
        let source = include_str!("../tests/receipt_image_downloader.rs");
        let marker = format!("const {name}: &str = \"");
        let start = source.find(&marker).unwrap() + marker.len();
        let end = source[start..].find("\";").unwrap() + start;
        base64::engine::general_purpose::STANDARD
            .decode(&source[start..end])
            .unwrap()
    }
}
