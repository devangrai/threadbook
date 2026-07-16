use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::contracts::deserialize_schema_version_v1;
use crate::validation::{require_schema_v1, validate_bounded_text};
use crate::{ReplayStatusV1, RequestId, SafeFieldV1, UserActionKeyV1, Validate, ValidationError};

pub const MAX_GMAIL_OAUTH_CLIENT_ID_BYTES: usize = 256;
pub const MAX_GMAIL_LABEL_NAME_CHARS: usize = 80;
pub const MAX_GMAIL_PAGE_SIZE: u16 = 100;
pub const MAX_GMAIL_PAGES: u8 = 10;
pub const MAX_GMAIL_UNIQUE_MESSAGES: u16 = 200;
pub const MAX_GMAIL_TOTAL_RAW_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum GmailProviderProfileV1 {
    Google,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum GmailConnectorStatusV1 {
    NotConfigured,
    Disconnected,
    Connecting,
    Connected,
    Syncing,
    Disconnecting,
    NeedsAttention,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum GmailRevocationOutcomeV1 {
    Succeeded,
    AlreadyInvalid,
    Failed,
    NotAttemptedLocalOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GmailConnectorLimitsV1 {
    pub page_size: u16,
    pub max_pages: u8,
    pub max_unique_messages: u16,
    #[ts(type = "number")]
    pub max_total_raw_bytes: u64,
}

impl Validate for GmailConnectorLimitsV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        if !(1..=MAX_GMAIL_PAGE_SIZE).contains(&self.page_size)
            || !(1..=MAX_GMAIL_PAGES).contains(&self.max_pages)
            || !(1..=MAX_GMAIL_UNIQUE_MESSAGES).contains(&self.max_unique_messages)
            || !(1..=MAX_GMAIL_TOTAL_RAW_BYTES).contains(&self.max_total_raw_bytes)
        {
            return Err(ValidationError::new(SafeFieldV1::GmailLimits));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GmailConnectorSettingsV1 {
    pub provider_profile: GmailProviderProfileV1,
    pub oauth_client_id: String,
    pub label_name: String,
    pub limits: GmailConnectorLimitsV1,
}

impl Validate for GmailConnectorSettingsV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        validate_oauth_client_id(&self.oauth_client_id)?;
        validate_bounded_text(
            &self.label_name,
            1,
            MAX_GMAIL_LABEL_NAME_CHARS,
            SafeFieldV1::GmailLabelName,
        )?;
        self.limits.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GmailSyncSummaryV1 {
    pub pages_scanned: u8,
    pub unique_messages: u16,
    pub messages_imported: u16,
    pub messages_updated: u16,
    pub messages_unavailable: u16,
    #[ts(type = "number")]
    pub raw_bytes_read: u64,
}

impl Validate for GmailSyncSummaryV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        let terminal_messages = u32::from(self.messages_imported)
            + u32::from(self.messages_updated)
            + u32::from(self.messages_unavailable);
        if self.pages_scanned > MAX_GMAIL_PAGES
            || self.unique_messages > MAX_GMAIL_UNIQUE_MESSAGES
            || self.messages_imported > MAX_GMAIL_UNIQUE_MESSAGES
            || self.messages_updated > MAX_GMAIL_UNIQUE_MESSAGES
            || self.messages_unavailable > MAX_GMAIL_UNIQUE_MESSAGES
            || terminal_messages > u32::from(self.unique_messages)
            || self.raw_bytes_read > MAX_GMAIL_TOTAL_RAW_BYTES
        {
            return Err(ValidationError::new(SafeFieldV1::GmailSummary));
        }
        Ok(())
    }
}

macro_rules! gmail_request_envelope {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            #[serde(deserialize_with = "deserialize_schema_version_v1")]
            #[ts(type = "1")]
            pub schema_version: u8,
            pub request_id: RequestId,
        }

        impl Validate for $name {
            fn validate(&self) -> Result<(), ValidationError> {
                require_schema_v1(self.schema_version)
            }
        }
    };
}

gmail_request_envelope!(GetGmailConnectorV1Request);
gmail_request_envelope!(ConnectGmailV1Request);
gmail_request_envelope!(SyncGmailV1Request);
gmail_request_envelope!(DisconnectGmailV1Request);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SaveGmailSettingsV1Request {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub client_id: String,
    pub label_name: String,
    pub limits: GmailConnectorLimitsV1,
}

impl Validate for SaveGmailSettingsV1Request {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_oauth_client_id(&self.client_id)?;
        validate_bounded_text(
            &self.label_name,
            1,
            MAX_GMAIL_LABEL_NAME_CHARS,
            SafeFieldV1::GmailLabelName,
        )?;
        self.limits.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct GetGmailConnectorV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub settings: Option<GmailConnectorSettingsV1>,
    pub status: GmailConnectorStatusV1,
    pub user_action: UserActionKeyV1,
}

impl Validate for GetGmailConnectorV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        if let Some(settings) = &self.settings {
            settings.validate()?;
        }
        validate_status(self.status, self.user_action, self.settings.is_some())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SaveGmailSettingsV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub settings: GmailConnectorSettingsV1,
    pub status: GmailConnectorStatusV1,
    pub user_action: UserActionKeyV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for SaveGmailSettingsV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        self.settings.validate()?;
        validate_terminal_status(
            self.status,
            GmailConnectorStatusV1::Disconnected,
            self.user_action,
            UserActionKeyV1::ConnectGmail,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ConnectGmailV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub status: GmailConnectorStatusV1,
    pub user_action: UserActionKeyV1,
    pub summary: GmailSyncSummaryV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for ConnectGmailV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_terminal_status(
            self.status,
            GmailConnectorStatusV1::Connected,
            self.user_action,
            UserActionKeyV1::None,
        )?;
        self.summary.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SyncGmailV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub status: GmailConnectorStatusV1,
    pub user_action: UserActionKeyV1,
    pub summary: GmailSyncSummaryV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for SyncGmailV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_terminal_status(
            self.status,
            GmailConnectorStatusV1::Connected,
            self.user_action,
            UserActionKeyV1::None,
        )?;
        self.summary.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DisconnectGmailV1Response {
    #[serde(deserialize_with = "deserialize_schema_version_v1")]
    #[ts(type = "1")]
    pub schema_version: u8,
    pub request_id: RequestId,
    pub status: GmailConnectorStatusV1,
    pub user_action: UserActionKeyV1,
    pub revocation_outcome: GmailRevocationOutcomeV1,
    pub replay_status: ReplayStatusV1,
}

impl Validate for DisconnectGmailV1Response {
    fn validate(&self) -> Result<(), ValidationError> {
        require_schema_v1(self.schema_version)?;
        validate_terminal_status(
            self.status,
            GmailConnectorStatusV1::Disconnected,
            self.user_action,
            UserActionKeyV1::ConnectGmail,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GmailConnectorPortErrorKind {
    Unavailable,
    Conflict,
    Busy,
    InvalidState,
    PermissionDenied,
    CredentialUnavailable,
    ScopeTooLarge,
    MalformedProviderOutput,
    DataIntegrity,
    NotFound,
    Internal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GmailConnectorPortError {
    pub kind: GmailConnectorPortErrorKind,
}

impl GmailConnectorPortError {
    pub const fn new(kind: GmailConnectorPortErrorKind) -> Self {
        Self { kind }
    }
}

pub type GmailConnectorPortResult<T> = Result<T, GmailConnectorPortError>;

pub trait GmailConnectorPort {
    fn get_gmail_connector(
        &self,
        request: &GetGmailConnectorV1Request,
    ) -> GmailConnectorPortResult<GetGmailConnectorV1Response>;

    fn save_gmail_settings(
        &self,
        request: &SaveGmailSettingsV1Request,
    ) -> GmailConnectorPortResult<SaveGmailSettingsV1Response>;

    fn connect_gmail(
        &self,
        request: &ConnectGmailV1Request,
    ) -> GmailConnectorPortResult<ConnectGmailV1Response>;

    fn sync_gmail(
        &self,
        request: &SyncGmailV1Request,
    ) -> GmailConnectorPortResult<SyncGmailV1Response>;

    fn disconnect_gmail(
        &self,
        request: &DisconnectGmailV1Request,
    ) -> GmailConnectorPortResult<DisconnectGmailV1Response>;
}

fn validate_oauth_client_id(value: &str) -> Result<(), ValidationError> {
    const SUFFIX: &str = ".apps.googleusercontent.com";

    let prefix = value.strip_suffix(SUFFIX).unwrap_or_default();
    if value.is_empty()
        || value.len() > MAX_GMAIL_OAUTH_CLIENT_ID_BYTES
        || !value.is_ascii()
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
        || prefix.is_empty()
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ValidationError::new(SafeFieldV1::GmailClientId));
    }
    Ok(())
}

fn validate_status(
    status: GmailConnectorStatusV1,
    action: UserActionKeyV1,
    has_settings: bool,
) -> Result<(), ValidationError> {
    let valid = match status {
        GmailConnectorStatusV1::NotConfigured => {
            !has_settings && action == UserActionKeyV1::ConfigureGmail
        }
        GmailConnectorStatusV1::Disconnected => {
            has_settings && action == UserActionKeyV1::ConnectGmail
        }
        GmailConnectorStatusV1::Connecting
        | GmailConnectorStatusV1::Connected
        | GmailConnectorStatusV1::Syncing => has_settings && action == UserActionKeyV1::None,
        GmailConnectorStatusV1::Disconnecting => {
            has_settings
                && matches!(
                    action,
                    UserActionKeyV1::Retry | UserActionKeyV1::UnlockKeychain
                )
        }
        GmailConnectorStatusV1::NeedsAttention => {
            matches!(
                action,
                UserActionKeyV1::Retry
                    | UserActionKeyV1::UnlockKeychain
                    | UserActionKeyV1::ConnectGmail
                    | UserActionKeyV1::RestartApplication
            )
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::GmailStatus))
    }
}

fn validate_terminal_status(
    status: GmailConnectorStatusV1,
    expected_status: GmailConnectorStatusV1,
    action: UserActionKeyV1,
    expected_action: UserActionKeyV1,
) -> Result<(), ValidationError> {
    if status == expected_status && action == expected_action {
        Ok(())
    } else {
        Err(ValidationError::new(SafeFieldV1::GmailStatus))
    }
}
