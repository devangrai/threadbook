use crate::gmail_http::{
    gmail_account_key, GoogleGmailGateway, GoogleHttpClient, GoogleHttpError,
    PendingPkceAuthorization, RevocationResult,
};
use crate::gmail_repository::GmailSyncCommandKind;
use crate::{
    Database, GmailHistoryCoordinator, MacOsKeychain, SyncBatch, SyncError, SyncKey, SyncLimits,
};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::time::Duration;
use uuid::Uuid;
use wardrobe_core::{
    ConnectGmailV1Request, ConnectGmailV1Response, CredentialLocator, CredentialPort,
    DisconnectGmailV1Request, DisconnectGmailV1Response, GetGmailConnectorV1Request,
    GetGmailConnectorV1Response, GmailConnectorLimitsV1, GmailConnectorPort,
    GmailConnectorPortError, GmailConnectorPortErrorKind, GmailConnectorPortResult,
    GmailConnectorSettingsV1, GmailConnectorStatusV1, GmailProviderProfileV1,
    GmailRevocationOutcomeV1, ReplayStatusV1, RequestId, SaveGmailSettingsV1Request,
    SaveGmailSettingsV1Response, SecretString, SyncGmailV1Request, SyncGmailV1Response,
    UserActionKeyV1, SCHEMA_VERSION_V1,
};

const PARSER_REVISION: &str = "bounded-mime-v1";
const MATERIALIZATION_REVISION: &str = "gmail-materialization-v1";

pub trait GmailCredentialStore: Clone + Send + Sync + 'static {
    fn put_refresh(
        &self,
        locator: &CredentialLocator,
        secret: &SecretString,
    ) -> Result<(), GmailConnectorPortError>;
    fn get_refresh(
        &self,
        locator: &CredentialLocator,
    ) -> Result<Option<SecretString>, GmailConnectorPortError>;
    fn delete_refresh(&self, locator: &CredentialLocator) -> Result<(), GmailConnectorPortError>;
}

impl GmailCredentialStore for MacOsKeychain {
    fn put_refresh(
        &self,
        locator: &CredentialLocator,
        secret: &SecretString,
    ) -> Result<(), GmailConnectorPortError> {
        self.put(locator, secret).map_err(map_credential_error)
    }

    fn get_refresh(
        &self,
        locator: &CredentialLocator,
    ) -> Result<Option<SecretString>, GmailConnectorPortError> {
        match self.get_exact(locator) {
            Ok(secret) => Ok(Some(secret)),
            Err(error) if error.kind == wardrobe_core::PortErrorKind::NotFound => Ok(None),
            Err(error) => Err(map_credential_error(error)),
        }
    }

    fn delete_refresh(&self, locator: &CredentialLocator) -> Result<(), GmailConnectorPortError> {
        match self.delete(locator) {
            Ok(()) => Ok(()),
            Err(error) if error.kind == wardrobe_core::PortErrorKind::NotFound => Ok(()),
            Err(error) => Err(map_credential_error(error)),
        }
    }
}

#[derive(Clone)]
pub struct ProductionGmailConnector<C = MacOsKeychain> {
    database: Database,
    credentials: C,
    http: GoogleHttpClient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GmailDisconnectCompletion {
    AttemptRevocation,
    SkipRevocationNotAttemptedLocalOnly,
}

impl ProductionGmailConnector<MacOsKeychain> {
    pub fn production(database: Database) -> GmailConnectorPortResult<Self> {
        Ok(Self {
            database,
            credentials: MacOsKeychain,
            http: GoogleHttpClient::production().map_err(map_http_error)?,
        })
    }
}

impl<C> ProductionGmailConnector<C>
where
    C: GmailCredentialStore,
{
    #[cfg(test)]
    fn with_adapters(database: Database, credentials: C, http: GoogleHttpClient) -> Self {
        Self {
            database,
            credentials,
            http,
        }
    }

    fn settings(&self) -> GmailConnectorPortResult<Option<GmailConnectorSettingsV1>> {
        self.database
            .connection()
            .map_err(|_| internal())?
            .query_row(
                "SELECT oauth_client_id, label_name, page_size, max_pages,
                        max_unique_messages, max_total_raw_bytes
                 FROM gmail_connector_settings WHERE singleton = 1",
                [],
                |row| {
                    Ok(GmailConnectorSettingsV1 {
                        provider_profile: GmailProviderProfileV1::Google,
                        oauth_client_id: row.get(0)?,
                        label_name: row.get(1)?,
                        limits: GmailConnectorLimitsV1 {
                            page_size: row.get::<_, i64>(2)? as u16,
                            max_pages: row.get::<_, i64>(3)? as u8,
                            max_unique_messages: row.get::<_, i64>(4)? as u16,
                            max_total_raw_bytes: row.get::<_, i64>(5)? as u64,
                        },
                    })
                },
            )
            .optional()
            .map_err(|_| internal())
    }

    fn state(&self) -> GmailConnectorPortResult<(GmailConnectorStatusV1, UserActionKeyV1)> {
        let connection = self.database.connection().map_err(|_| internal())?;
        let status: String = connection
            .query_row(
                "SELECT status FROM gmail_connector_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| internal())?;
        let durable_gmail_credentials: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM credential_references WHERE provider = 'gmail'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| internal())?;
        let unexpected_connected_credentials: i64 = connection
            .query_row(
                "SELECT COUNT(*)
                 FROM credential_references reference
                 WHERE reference.provider = 'gmail'
                   AND NOT EXISTS (
                     SELECT 1
                     FROM gmail_connector_state state
                     JOIN gmail_accounts account
                       ON account.account_key = state.account_key
                     WHERE state.singleton = 1 AND state.status = 'connected'
                       AND account.credential_locator = reference.locator
                   )",
                [],
                |row| row.get(0),
            )
            .map_err(|_| internal())?;
        Ok(match status.as_str() {
            "disconnected" if durable_gmail_credentials > 0 => (
                GmailConnectorStatusV1::NeedsAttention,
                UserActionKeyV1::UnlockKeychain,
            ),
            "disconnected" if self.settings()?.is_none() => (
                GmailConnectorStatusV1::NotConfigured,
                UserActionKeyV1::ConfigureGmail,
            ),
            "disconnected" => (
                GmailConnectorStatusV1::Disconnected,
                UserActionKeyV1::ConnectGmail,
            ),
            "connecting" if durable_gmail_credentials > 0 => (
                GmailConnectorStatusV1::NeedsAttention,
                UserActionKeyV1::UnlockKeychain,
            ),
            "connecting" => (GmailConnectorStatusV1::Connecting, UserActionKeyV1::None),
            "connected"
                if durable_gmail_credentials == 0 || unexpected_connected_credentials > 0 =>
            {
                (
                    GmailConnectorStatusV1::NeedsAttention,
                    UserActionKeyV1::UnlockKeychain,
                )
            }
            "connected" => (GmailConnectorStatusV1::Connected, UserActionKeyV1::None),
            "disconnecting" => (
                GmailConnectorStatusV1::Disconnecting,
                UserActionKeyV1::UnlockKeychain,
            ),
            _ => return Err(data_integrity()),
        })
    }

    fn replay<T: DeserializeOwned>(
        &self,
        request_id: &str,
        command: &str,
        envelope: &str,
    ) -> GmailConnectorPortResult<Option<T>> {
        let row = self
            .database
            .connection()
            .map_err(|_| internal())?
            .query_row(
                "SELECT command_name, envelope_hash, response_json
                 FROM command_receipts WHERE request_id = ?1",
                [request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| internal())?;
        match row {
            None => Ok(None),
            Some((stored_command, stored_envelope, json))
                if stored_command == command && stored_envelope == envelope =>
            {
                serde_json::from_str(&json)
                    .map(Some)
                    .map_err(|_| data_integrity())
            }
            Some(_) => Err(conflict()),
        }
    }

    fn collect_sync_once(
        &self,
        account_key: String,
        scope_id: String,
        label_id: String,
        settings: &GmailConnectorSettingsV1,
        access_token: SecretString,
    ) -> Result<SyncBatch, SyncError> {
        let limits = SyncLimits {
            page_size: settings.limits.page_size as usize,
            max_pages: settings.limits.max_pages as usize,
            max_unique_messages: settings.limits.max_unique_messages as usize,
            max_total_raw_bytes: settings.limits.max_total_raw_bytes as usize,
            max_gateway_calls: settings.limits.max_unique_messages as usize
                + settings.limits.max_pages as usize
                + 4,
            max_scan_attempts: 2,
            operation_timeout: Duration::from_secs(60),
        };
        let database = self.database.clone();
        let http = self.http.clone();
        let key = SyncKey {
            account_key,
            scope_id,
            label_id: label_id.clone(),
        };
        run_sync_async(move || async move {
            let mut gateway = GoogleGmailGateway::new(http, access_token, label_id);
            let coordinator = GmailHistoryCoordinator::new(limits)?;
            coordinator.collect(&mut gateway, &database, &key).await
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_sync_with_auth_retry(
        &self,
        account_key: String,
        scope_id: String,
        label_id: String,
        settings: &GmailConnectorSettingsV1,
        access_token: SecretString,
        locator: &CredentialLocator,
    ) -> GmailConnectorPortResult<SyncBatch> {
        match self.collect_sync_once(
            account_key.clone(),
            scope_id.clone(),
            label_id.clone(),
            settings,
            access_token,
        ) {
            Ok(batch) => Ok(batch),
            Err(SyncError::Authentication) => {
                let refresh = self
                    .credentials
                    .get_refresh(locator)?
                    .ok_or_else(credential_unavailable)?;
                let http = self.http.clone();
                let client_id = settings.oauth_client_id.clone();
                let refreshed = run_async(move || async move {
                    http.refresh_access_token(&client_id, &refresh)
                        .await
                        .map_err(map_http_error)
                })?;
                if let Some(rotated) = refreshed.rotated_refresh_token {
                    self.credentials.put_refresh(locator, &rotated)?;
                }
                self.collect_sync_once(
                    account_key,
                    scope_id,
                    label_id,
                    settings,
                    refreshed.access_token,
                )
                .map_err(map_sync_error)
            }
            Err(error) => Err(map_sync_error(error)),
        }
    }

    fn active(&self) -> GmailConnectorPortResult<(String, String, String, CredentialLocator)> {
        let row = self
            .database
            .connection()
            .map_err(|_| internal())?
            .query_row(
                "SELECT state.account_key, state.scope_id, scope.label_id,
                        account.credential_locator
                 FROM gmail_connector_state state
                 JOIN gmail_scopes scope ON scope.scope_id = state.scope_id
                 JOIN gmail_accounts account ON account.account_key = state.account_key
                 WHERE state.singleton = 1 AND state.status = 'connected'
                   AND EXISTS (
                     SELECT 1 FROM credential_references reference
                     WHERE reference.provider = 'gmail'
                       AND reference.locator = account.credential_locator
                   )
                   AND NOT EXISTS (
                     SELECT 1 FROM credential_references reference
                     WHERE reference.provider = 'gmail'
                       AND reference.locator <> account.credential_locator
                   )",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| internal())?
            .ok_or_else(invalid_state)?;
        let locator = CredentialLocator::new(row.3).map_err(|_| data_integrity())?;
        Ok((row.0, row.1, row.2, locator))
    }

    pub fn recover_with_revocation(&self) -> GmailConnectorPortResult<()> {
        self.recover_startup(GmailDisconnectCompletion::AttemptRevocation)
    }

    pub fn recover_local_state(&self) -> GmailConnectorPortResult<()> {
        self.recover_startup(GmailDisconnectCompletion::SkipRevocationNotAttemptedLocalOnly)
    }

    fn recover_startup(
        &self,
        disconnect_completion: GmailDisconnectCompletion,
    ) -> GmailConnectorPortResult<()> {
        let operation = self
            .database
            .connection()
            .map_err(|_| internal())?
            .query_row(
                "SELECT request_id, command_name, request_envelope_sha256
                 FROM gmail_operations WHERE stage <> 'terminal'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| data_integrity())?;

        match operation {
            Some((request_id, command, _)) if command == "connect_gmail_v1" => {
                let locator = credential_locator_for_request(&self.database, &request_id)?;
                if let Some(locator) = locator {
                    match disconnect_completion {
                        GmailDisconnectCompletion::AttemptRevocation => cleanup_failed_connect(
                            &self.database,
                            &self.credentials,
                            &self.http,
                            &request_id,
                            &locator,
                        ),
                        GmailDisconnectCompletion::SkipRevocationNotAttemptedLocalOnly => {
                            cleanup_failed_connect_local(
                                &self.database,
                                &self.credentials,
                                &request_id,
                                &locator,
                            )
                        }
                    }
                } else {
                    abort_connect(&self.database, &request_id)
                }
            }
            Some((request_id, command, _)) if command == "sync_gmail_v1" => {
                delete_incomplete_sync_operation(&self.database, &request_id)
            }
            Some((request_id, command, envelope)) if command == "disconnect_gmail_v1" => {
                self.resume_disconnect(&request_id, &envelope, disconnect_completion)
            }
            Some(_) => Err(data_integrity()),
            None => Ok(()),
        }?;
        self.cleanup_legacy_credentials()
    }

    fn cleanup_legacy_credentials(&self) -> GmailConnectorPortResult<()> {
        let active_locator = self
            .database
            .connection()
            .map_err(|_| internal())?
            .query_row(
                "SELECT account.credential_locator
                 FROM gmail_connector_state state
                 JOIN gmail_accounts account ON account.account_key = state.account_key
                 WHERE state.singleton = 1 AND state.status = 'connected'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| data_integrity())?;
        delete_gmail_credentials_except(
            &self.database,
            &self.credentials,
            active_locator.as_deref(),
        )
    }

    fn resume_disconnect(
        &self,
        request_id: &str,
        envelope: &str,
        completion: GmailDisconnectCompletion,
    ) -> GmailConnectorPortResult<()> {
        self.complete_disconnect(request_id, envelope, completion)
            .map(|_| ())
    }

    fn complete_disconnect(
        &self,
        request_id: &str,
        envelope: &str,
        completion: GmailDisconnectCompletion,
    ) -> GmailConnectorPortResult<DisconnectGmailV1Response> {
        let (account_key, locator_text) = disconnect_identity(&self.database, request_id)?;
        let locator = CredentialLocator::new(locator_text).map_err(|_| data_integrity())?;
        let revocation = match stored_disconnect_revocation(&self.database, request_id)? {
            Some(outcome) => outcome,
            None => {
                let outcome = match completion {
                    GmailDisconnectCompletion::AttemptRevocation => {
                        attempt_revocation(&self.credentials, &self.http, &locator)?
                    }
                    GmailDisconnectCompletion::SkipRevocationNotAttemptedLocalOnly => {
                        GmailRevocationOutcomeV1::NotAttemptedLocalOnly
                    }
                };
                persist_disconnect_revocation(&self.database, request_id, outcome)?;
                outcome
            }
        };
        delete_all_gmail_credentials(&self.database, &self.credentials)?;
        let request_uuid = Uuid::parse_str(request_id).map_err(|_| data_integrity())?;
        let response = DisconnectGmailV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new(request_uuid).map_err(|_| data_integrity())?,
            status: GmailConnectorStatusV1::Disconnected,
            user_action: UserActionKeyV1::ConnectGmail,
            revocation_outcome: revocation,
            replay_status: ReplayStatusV1::Created,
        };
        finalize_disconnect(
            &self.database,
            &account_key,
            request_id,
            "disconnect_gmail_v1",
            envelope,
            &response,
        )?;
        Ok(response)
    }

    pub fn disconnect_gmail_with_completion(
        &self,
        request: &DisconnectGmailV1Request,
        completion: GmailDisconnectCompletion,
    ) -> GmailConnectorPortResult<DisconnectGmailV1Response> {
        let request_id = request.request_id.to_string();
        let command = "disconnect_gmail_v1";
        let envelope = envelope(request)?;
        if let Some(mut replay) =
            self.replay::<DisconnectGmailV1Response>(&request_id, command, &envelope)?
        {
            replay.replay_status = ReplayStatusV1::Replayed;
            return Ok(replay);
        }
        let (account_key, _scope_id, _label_id, locator) = self.active()?;
        begin_disconnect(
            &self.database,
            &request_id,
            command,
            &envelope,
            &account_key,
            &locator,
        )?;
        self.complete_disconnect(&request_id, &envelope, completion)
    }
}

impl<C> GmailConnectorPort for ProductionGmailConnector<C>
where
    C: GmailCredentialStore,
{
    fn get_gmail_connector(
        &self,
        request: &GetGmailConnectorV1Request,
    ) -> GmailConnectorPortResult<GetGmailConnectorV1Response> {
        let (status, user_action) = self.state()?;
        Ok(GetGmailConnectorV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            settings: self.settings()?,
            status,
            user_action,
        })
    }

    fn save_gmail_settings(
        &self,
        request: &SaveGmailSettingsV1Request,
    ) -> GmailConnectorPortResult<SaveGmailSettingsV1Response> {
        let request_id = request.request_id.to_string();
        let envelope = envelope(request)?;
        if let Some(mut replay) = self.replay::<SaveGmailSettingsV1Response>(
            &request_id,
            "save_gmail_settings_v1",
            &envelope,
        )? {
            replay.replay_status = ReplayStatusV1::Replayed;
            return Ok(replay);
        }
        if self.state()?.0 != GmailConnectorStatusV1::Disconnected
            && self.state()?.0 != GmailConnectorStatusV1::NotConfigured
        {
            return Err(invalid_state());
        }
        let now = now_ms()?;
        let settings = GmailConnectorSettingsV1 {
            provider_profile: GmailProviderProfileV1::Google,
            oauth_client_id: request.client_id.clone(),
            label_name: request.label_name.clone(),
            limits: request.limits.clone(),
        };
        let response = SaveGmailSettingsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            settings: settings.clone(),
            status: GmailConnectorStatusV1::Disconnected,
            user_action: UserActionKeyV1::ConnectGmail,
            replay_status: ReplayStatusV1::Created,
        };
        let json = serde_json::to_string(&response).map_err(|_| internal())?;
        let mut connection = self.database.connection().map_err(|_| internal())?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| internal())?;
        transaction
            .execute(
                "INSERT INTO gmail_connector_settings(
                    singleton, oauth_client_id, label_name, page_size, max_pages,
                    max_unique_messages, max_total_raw_bytes, updated_at_ms
                 ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(singleton) DO UPDATE SET
                    oauth_client_id = excluded.oauth_client_id,
                    label_name = excluded.label_name,
                    page_size = excluded.page_size,
                    max_pages = excluded.max_pages,
                    max_unique_messages = excluded.max_unique_messages,
                    max_total_raw_bytes = excluded.max_total_raw_bytes,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    settings.oauth_client_id,
                    settings.label_name,
                    settings.limits.page_size,
                    settings.limits.max_pages,
                    settings.limits.max_unique_messages,
                    settings.limits.max_total_raw_bytes as i64,
                    now
                ],
            )
            .map_err(|_| internal())?;
        transaction
            .execute(
                "INSERT INTO command_receipts(
                    request_id, command_name, envelope_hash, response_json, created_at_ms
                 ) VALUES (?1, 'save_gmail_settings_v1', ?2, ?3, ?4)",
                params![request_id, envelope, json, now],
            )
            .map_err(|_| internal())?;
        transaction.commit().map_err(|_| internal())?;
        Ok(response)
    }

    fn connect_gmail(
        &self,
        request: &ConnectGmailV1Request,
    ) -> GmailConnectorPortResult<ConnectGmailV1Response> {
        let request_id = request.request_id.to_string();
        let command = "connect_gmail_v1";
        let envelope = envelope(request)?;
        if let Some(mut replay) =
            self.replay::<ConnectGmailV1Response>(&request_id, command, &envelope)?
        {
            replay.replay_status = ReplayStatusV1::Replayed;
            return Ok(replay);
        }
        let settings = self.settings()?.ok_or_else(invalid_state)?;
        if self.state()?.0 != GmailConnectorStatusV1::Disconnected {
            return Err(invalid_state());
        }
        begin_operation(
            &self.database,
            &request_id,
            command,
            &envelope,
            "authorizing",
        )?;

        let http = self.http.clone();
        let client_id = settings.oauth_client_id.clone();
        let label_name = settings.label_name.clone();
        let authorized = run_async(move || async move {
            let pending = PendingPkceAuthorization::bind(&client_id, &http)
                .await
                .map_err(map_http_error)?;
            let redirect_uri = pending.redirect_uri().to_owned();
            open_browser(pending.authorization_url().as_str())?;
            let (code, verifier) = pending.wait_for_code().await.map_err(map_http_error)?;
            let tokens = http
                .exchange_authorization_code(&client_id, &code, &redirect_uri, &verifier)
                .await
                .map_err(map_http_error)?;
            let subject = http
                .user_subject(&tokens.access_token)
                .await
                .map_err(map_http_error)?;
            let label_id =
                GoogleGmailGateway::resolve_label_id(&http, &tokens.access_token, &label_name)
                    .await
                    .map_err(map_http_error)?;
            Ok((tokens, gmail_account_key(&subject), label_id))
        });
        let (tokens, account_key, label_id) = match authorized {
            Ok(value) => value,
            Err(error) => {
                abort_connect(&self.database, &request_id)?;
                return Err(error);
            }
        };

        let locator = CredentialLocator::new(format!("gmail-refresh-{}", Uuid::new_v4()))
            .map_err(|_| internal())?;
        reserve_credential(&self.database, &request_id, &locator)?;
        if let Err(error) = self
            .credentials
            .put_refresh(&locator, &tokens.refresh_token)
        {
            let http = self.http.clone();
            let refresh = tokens.refresh_token;
            let _ = run_async(move || async move {
                let _ = http.revoke(&refresh).await;
                Ok::<(), GmailConnectorPortError>(())
            });
            cleanup_failed_connect(
                &self.database,
                &self.credentials,
                &self.http,
                &request_id,
                &locator,
            )?;
            return Err(error);
        }
        let result = (|| {
            activate_credential(&self.database, &locator)?;
            let scope_fingerprint = scope_fingerprint(&label_id);
            let scope_id = stable_uuid(
                "gmail-scope",
                &format!("{account_key}\0{scope_fingerprint}"),
            );
            self.database
                .initialize_gmail_scope(
                    &account_key,
                    locator.expose_locator(),
                    &scope_id,
                    &scope_fingerprint,
                    &label_id,
                    PARSER_REVISION,
                    MATERIALIZATION_REVISION,
                    now_ms()?,
                )
                .map_err(|_| data_integrity())?;
            mark_operation_syncing(&self.database, &request_id)?;
            let batch = self.collect_sync_with_auth_retry(
                account_key.clone(),
                scope_id.clone(),
                label_id.clone(),
                &settings,
                tokens.access_token,
                &locator,
            )?;
            let key = SyncKey {
                account_key: account_key.clone(),
                scope_id: scope_id.clone(),
                label_id,
            };
            let committed = self.database.commit_gmail_operation(
                &key,
                &batch,
                &request_id,
                &envelope,
                GmailSyncCommandKind::Connect,
                &account_key,
                &scope_id,
            )?;
            Ok(ConnectGmailV1Response {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request.request_id,
                status: GmailConnectorStatusV1::Connected,
                user_action: UserActionKeyV1::None,
                summary: committed.summary,
                replay_status: ReplayStatusV1::Created,
            })
        })();
        if result.is_err() {
            let _ = cleanup_failed_connect(
                &self.database,
                &self.credentials,
                &self.http,
                &request_id,
                &locator,
            );
        }
        result
    }

    fn sync_gmail(
        &self,
        request: &SyncGmailV1Request,
    ) -> GmailConnectorPortResult<SyncGmailV1Response> {
        let request_id = request.request_id.to_string();
        let command = "sync_gmail_v1";
        let envelope = envelope(request)?;
        if let Some(mut replay) =
            self.replay::<SyncGmailV1Response>(&request_id, command, &envelope)?
        {
            replay.replay_status = ReplayStatusV1::Replayed;
            return Ok(replay);
        }
        let settings = self.settings()?.ok_or_else(invalid_state)?;
        let (account_key, scope_id, label_id, locator) = self.active()?;
        begin_operation(&self.database, &request_id, command, &envelope, "syncing")?;
        let result = (|| {
            let refresh = self
                .credentials
                .get_refresh(&locator)?
                .ok_or_else(credential_unavailable)?;
            let http = self.http.clone();
            let client_id = settings.oauth_client_id.clone();
            let refreshed = run_async(move || async move {
                http.refresh_access_token(&client_id, &refresh)
                    .await
                    .map_err(map_http_error)
            })?;
            if let Some(rotated) = refreshed.rotated_refresh_token {
                self.credentials.put_refresh(&locator, &rotated)?;
            }
            let batch = self.collect_sync_with_auth_retry(
                account_key.clone(),
                scope_id.clone(),
                label_id.clone(),
                &settings,
                refreshed.access_token,
                &locator,
            )?;
            let key = SyncKey {
                account_key: account_key.clone(),
                scope_id: scope_id.clone(),
                label_id,
            };
            let committed = self.database.commit_gmail_operation(
                &key,
                &batch,
                &request_id,
                &envelope,
                GmailSyncCommandKind::Sync,
                &account_key,
                &scope_id,
            )?;
            Ok(SyncGmailV1Response {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request.request_id,
                status: GmailConnectorStatusV1::Connected,
                user_action: UserActionKeyV1::None,
                summary: committed.summary,
                replay_status: ReplayStatusV1::Created,
            })
        })();
        if result.is_err() {
            let _ = abort_sync(&self.database, &request_id);
        }
        result
    }

    fn disconnect_gmail(
        &self,
        request: &DisconnectGmailV1Request,
    ) -> GmailConnectorPortResult<DisconnectGmailV1Response> {
        self.disconnect_gmail_with_completion(request, GmailDisconnectCompletion::AttemptRevocation)
    }
}

fn begin_operation(
    database: &Database,
    request_id: &str,
    command: &str,
    envelope: &str,
    stage: &str,
) -> GmailConnectorPortResult<()> {
    let now = now_ms()?;
    let mut connection = database.connection().map_err(|_| internal())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| internal())?;
    if transaction
        .query_row(
            "SELECT 1 FROM gmail_operations WHERE request_id = ?1",
            [request_id],
            |_| Ok(()),
        )
        .optional()
        .map_err(|_| internal())?
        .is_some()
    {
        return Err(conflict());
    }
    transaction
        .execute(
            "INSERT INTO gmail_operations(
                request_id, command_name, request_envelope_sha256, stage,
                created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![request_id, command, envelope, stage, now],
        )
        .map_err(map_busy_sql)?;
    if command == "connect_gmail_v1" {
        transaction
            .execute(
                "UPDATE gmail_connector_state
                 SET status = 'connecting', updated_at_ms = ?1 WHERE singleton = 1",
                [now],
            )
            .map_err(|_| internal())?;
        transaction
            .execute(
                "INSERT INTO gmail_oauth_attempts(
                    attempt_id, request_id, status, created_at_ms
                 ) VALUES (?1, ?2, 'pending', ?3)",
                params![
                    stable_uuid("gmail-oauth-attempt", request_id),
                    request_id,
                    now
                ],
            )
            .map_err(|_| internal())?;
    }
    transaction.commit().map_err(|_| internal())
}

fn begin_disconnect(
    database: &Database,
    request_id: &str,
    command: &str,
    envelope: &str,
    account_key: &str,
    locator: &CredentialLocator,
) -> GmailConnectorPortResult<()> {
    let now = now_ms()?;
    let mut connection = database.connection().map_err(|_| internal())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| internal())?;
    transaction
        .execute(
            "INSERT INTO gmail_operations(
                request_id, command_name, request_envelope_sha256, stage,
                created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, 'revocation_pending', ?4, ?4)",
            params![request_id, command, envelope, now],
        )
        .map_err(map_busy_sql)?;
    transaction
        .execute(
            "UPDATE gmail_connector_state
             SET status = 'disconnecting', revocation_state = 'pending',
                 updated_at_ms = ?1 WHERE singleton = 1",
            [now],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "INSERT INTO gmail_disconnect_stages(
                request_id, account_key, credential_locator, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4)",
            params![request_id, account_key, locator.expose_locator(), now],
        )
        .map_err(|_| internal())?;
    transaction.commit().map_err(|_| internal())
}

fn mark_operation_syncing(database: &Database, request_id: &str) -> GmailConnectorPortResult<()> {
    let changed = database
        .connection()
        .map_err(|_| internal())?
        .execute(
            "UPDATE gmail_operations SET stage = 'syncing', updated_at_ms = ?2
             WHERE request_id = ?1 AND stage = 'credential_reserved'",
            params![request_id, now_ms()?],
        )
        .map_err(|_| internal())?;
    if changed == 1 {
        Ok(())
    } else {
        Err(data_integrity())
    }
}

fn abort_sync(database: &Database, request_id: &str) -> GmailConnectorPortResult<()> {
    delete_incomplete_sync_operation(database, request_id)
}

fn delete_incomplete_sync_operation(
    database: &Database,
    request_id: &str,
) -> GmailConnectorPortResult<()> {
    let mut connection = database.connection().map_err(|_| internal())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| internal())?;
    let authorized = transaction
        .execute(
            "INSERT INTO domain_mutation_authority(entity_kind,key_json)
             SELECT 'gmail_operation_cleanup',json_array(request_id)
             FROM gmail_operations
             WHERE request_id=?1 AND command_name='sync_gmail_v1' AND stage<>'terminal'",
            [request_id],
        )
        .map_err(|_| internal())?;
    let deleted = transaction
        .execute(
            "DELETE FROM gmail_operations
             WHERE request_id=?1 AND command_name='sync_gmail_v1' AND stage<>'terminal'",
            [request_id],
        )
        .map_err(|_| internal())?;
    let cleared = transaction
        .execute(
            "DELETE FROM domain_mutation_authority
             WHERE entity_kind='gmail_operation_cleanup' AND key_json=json_array(?1)",
            [request_id],
        )
        .map_err(|_| internal())?;
    if authorized != deleted || cleared != authorized {
        return Err(data_integrity());
    }
    transaction.commit().map_err(|_| internal())
}

fn attempt_revocation<C: GmailCredentialStore>(
    credentials: &C,
    http: &GoogleHttpClient,
    locator: &CredentialLocator,
) -> GmailConnectorPortResult<GmailRevocationOutcomeV1> {
    let Some(refresh) = credentials.get_refresh(locator)? else {
        return Ok(GmailRevocationOutcomeV1::Failed);
    };
    let http = http.clone();
    Ok(
        match run_async(move || async move { http.revoke(&refresh).await.map_err(map_http_error) })
        {
            Ok(RevocationResult::Succeeded) => GmailRevocationOutcomeV1::Succeeded,
            Ok(RevocationResult::AlreadyInvalid) => GmailRevocationOutcomeV1::AlreadyInvalid,
            Err(_) => GmailRevocationOutcomeV1::Failed,
        },
    )
}

fn stored_disconnect_revocation(
    database: &Database,
    request_id: &str,
) -> GmailConnectorPortResult<Option<GmailRevocationOutcomeV1>> {
    let stored = database
        .connection()
        .map_err(|_| internal())?
        .query_row(
            "SELECT revocation_result
             FROM gmail_disconnect_stages WHERE request_id = ?1",
            [request_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .map_err(|_| data_integrity())?;
    stored
        .map(|value| match value.as_str() {
            "succeeded" => Ok(GmailRevocationOutcomeV1::Succeeded),
            "already_invalid" => Ok(GmailRevocationOutcomeV1::AlreadyInvalid),
            "failed" => Ok(GmailRevocationOutcomeV1::Failed),
            "not_attempted_local_only" => Ok(GmailRevocationOutcomeV1::NotAttemptedLocalOnly),
            _ => Err(data_integrity()),
        })
        .transpose()
}

fn persist_disconnect_revocation(
    database: &Database,
    request_id: &str,
    outcome: GmailRevocationOutcomeV1,
) -> GmailConnectorPortResult<()> {
    let now = now_ms()?;
    let value = match outcome {
        GmailRevocationOutcomeV1::Succeeded => "succeeded",
        GmailRevocationOutcomeV1::AlreadyInvalid => "already_invalid",
        GmailRevocationOutcomeV1::Failed => "failed",
        GmailRevocationOutcomeV1::NotAttemptedLocalOnly => "not_attempted_local_only",
    };
    let mut connection = database.connection().map_err(|_| internal())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| internal())?;
    let stored = transaction
        .query_row(
            "SELECT revocation_result
             FROM gmail_disconnect_stages WHERE request_id = ?1",
            [request_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .map_err(|_| data_integrity())?;
    match stored.as_deref() {
        Some(stored) if stored != value => return Err(data_integrity()),
        Some(_) => {}
        None => {
            let changed = transaction
                .execute(
                    "UPDATE gmail_disconnect_stages
                     SET revocation_result = ?2, updated_at_ms = ?3
                     WHERE request_id = ?1 AND revocation_result IS NULL",
                    params![request_id, value, now],
                )
                .map_err(|_| internal())?;
            if changed != 1 {
                return Err(data_integrity());
            }
        }
    }
    let changed = transaction
        .execute(
            "UPDATE gmail_operations
             SET stage = 'credential_delete_pending', updated_at_ms = ?2
             WHERE request_id = ?1
               AND stage IN ('revocation_pending', 'credential_delete_pending')",
            params![request_id, now],
        )
        .map_err(|_| internal())?;
    if changed != 1 {
        return Err(data_integrity());
    }
    transaction.commit().map_err(|_| internal())
}

fn finalize_disconnect(
    database: &Database,
    account_key: &str,
    request_id: &str,
    command: &str,
    envelope: &str,
    response: &DisconnectGmailV1Response,
) -> GmailConnectorPortResult<()> {
    let now = now_ms()?;
    let json = serde_json::to_string(response).map_err(|_| internal())?;
    let mut connection = database.connection().map_err(|_| internal())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| internal())?;
    let remaining_credentials: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM credential_references WHERE provider = 'gmail'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| internal())?;
    if remaining_credentials != 0 {
        return Err(credential_unavailable());
    }
    let expected_revocation = match response.revocation_outcome {
        GmailRevocationOutcomeV1::Succeeded => "succeeded",
        GmailRevocationOutcomeV1::AlreadyInvalid => "already_invalid",
        GmailRevocationOutcomeV1::Failed => "failed",
        GmailRevocationOutcomeV1::NotAttemptedLocalOnly => "not_attempted_local_only",
    };
    let durable_revocation: Option<String> = transaction
        .query_row(
            "SELECT revocation_result FROM gmail_disconnect_stages
             WHERE request_id = ?1",
            [request_id],
            |row| row.get(0),
        )
        .map_err(|_| data_integrity())?;
    if durable_revocation.as_deref() != Some(expected_revocation) {
        return Err(data_integrity());
    }
    transaction
        .execute(
            "DELETE FROM gmail_checkpoints
             WHERE scope_id IN (
                SELECT scope_id FROM gmail_scopes WHERE account_key = ?1
             )",
            [account_key],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "UPDATE gmail_accounts SET credential_locator = NULL WHERE account_key = ?1",
            [account_key],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "UPDATE gmail_connector_state
             SET status = 'disconnected', account_key = NULL, scope_id = NULL,
                 revocation_state = NULL, updated_at_ms = ?1 WHERE singleton = 1",
            [now],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "UPDATE gmail_disconnect_stages
             SET credential_deleted = 1, updated_at_ms = ?2
             WHERE request_id = ?1",
            params![request_id, now],
        )
        .map_err(|_| internal())?;
    let changed = transaction
        .execute(
            "UPDATE gmail_operations SET stage = 'terminal', response_json = ?2,
                    updated_at_ms = ?3
             WHERE request_id = ?1 AND stage = 'credential_delete_pending'",
            params![request_id, json, now],
        )
        .map_err(|_| internal())?;
    if changed != 1 {
        return Err(data_integrity());
    }
    transaction
        .execute(
            "INSERT INTO command_receipts(
                request_id, command_name, envelope_hash, response_json, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![request_id, command, envelope, json, now],
        )
        .map_err(|_| internal())?;
    transaction.commit().map_err(|_| internal())
}

fn reserve_credential(
    database: &Database,
    request_id: &str,
    locator: &CredentialLocator,
) -> GmailConnectorPortResult<()> {
    let now = now_ms()?;
    let mut connection = database.connection().map_err(|_| internal())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| internal())?;
    transaction
        .execute(
            "INSERT INTO credential_references(
                locator, credential_id, save_request_id, provider, display_label,
                status, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, 'gmail', 'Gmail', 'pending_save', ?4, ?4)",
            params![
                locator.expose_locator(),
                Uuid::new_v4().to_string(),
                request_id,
                now
            ],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "UPDATE gmail_oauth_attempts
             SET status = 'exchanged', completed_at_ms = ?2
             WHERE request_id = ?1 AND status = 'pending'",
            params![request_id, now],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "UPDATE gmail_operations
             SET stage = 'credential_reserved', updated_at_ms = ?2
             WHERE request_id = ?1 AND command_name = 'connect_gmail_v1'",
            params![request_id, now],
        )
        .map_err(|_| internal())?;
    transaction.commit().map_err(|_| internal())
}

fn activate_credential(
    database: &Database,
    locator: &CredentialLocator,
) -> GmailConnectorPortResult<()> {
    database
        .connection()
        .map_err(|_| internal())?
        .execute(
            "UPDATE credential_references SET status = 'active', updated_at_ms = ?2
             WHERE locator = ?1 AND status = 'pending_save'",
            params![locator.expose_locator(), now_ms()?],
        )
        .map_err(|_| internal())?;
    Ok(())
}

fn cleanup_failed_connect<C: GmailCredentialStore>(
    database: &Database,
    credentials: &C,
    http: &GoogleHttpClient,
    request_id: &str,
    locator: &CredentialLocator,
) -> GmailConnectorPortResult<()> {
    if let Ok(Some(refresh)) = credentials.get_refresh(locator) {
        let http = http.clone();
        let _ = run_async(move || async move {
            let _ = http.revoke(&refresh).await;
            Ok::<(), GmailConnectorPortError>(())
        });
    }
    credentials.delete_refresh(locator)?;
    let mut connection = database.connection().map_err(|_| internal())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| internal())?;
    transaction
        .execute(
            "DELETE FROM credential_references WHERE locator = ?1 AND provider = 'gmail'",
            [locator.expose_locator()],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "UPDATE gmail_accounts SET credential_locator = NULL
             WHERE credential_locator = ?1",
            [locator.expose_locator()],
        )
        .map_err(|_| internal())?;
    abort_connect_transaction(&transaction, request_id, now_ms()?)?;
    transaction.commit().map_err(|_| internal())
}

fn cleanup_failed_connect_local<C: GmailCredentialStore>(
    database: &Database,
    credentials: &C,
    request_id: &str,
    locator: &CredentialLocator,
) -> GmailConnectorPortResult<()> {
    credentials.delete_refresh(locator)?;
    let mut connection = database.connection().map_err(|_| internal())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| internal())?;
    transaction
        .execute(
            "DELETE FROM credential_references WHERE locator = ?1 AND provider = 'gmail'",
            [locator.expose_locator()],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "UPDATE gmail_accounts SET credential_locator = NULL
             WHERE credential_locator = ?1",
            [locator.expose_locator()],
        )
        .map_err(|_| internal())?;
    abort_connect_transaction(&transaction, request_id, now_ms()?)?;
    transaction.commit().map_err(|_| internal())
}

fn abort_connect(database: &Database, request_id: &str) -> GmailConnectorPortResult<()> {
    let mut connection = database.connection().map_err(|_| internal())?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| internal())?;
    abort_connect_transaction(&transaction, request_id, now_ms()?)?;
    transaction.commit().map_err(|_| internal())
}

fn abort_connect_transaction(
    transaction: &rusqlite::Transaction<'_>,
    request_id: &str,
    now: i64,
) -> GmailConnectorPortResult<()> {
    transaction
        .execute(
            "UPDATE gmail_oauth_attempts
             SET status = 'failed', completed_at_ms = ?2
             WHERE request_id = ?1 AND status IN ('pending', 'exchanged')",
            params![request_id, now],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "UPDATE gmail_operations
             SET stage = 'terminal', response_json = '{\"interrupted\":true}',
                 updated_at_ms = ?2
             WHERE request_id = ?1 AND command_name = 'connect_gmail_v1'
               AND stage <> 'terminal'",
            params![request_id, now],
        )
        .map_err(|_| internal())?;
    transaction
        .execute(
            "UPDATE gmail_connector_state SET status = 'disconnected',
                    updated_at_ms = ?1 WHERE singleton = 1",
            [now],
        )
        .map_err(|_| internal())?;
    Ok(())
}

fn gmail_credential_locators(database: &Database) -> GmailConnectorPortResult<Vec<String>> {
    let connection = database.connection().map_err(|_| internal())?;
    let mut statement = connection
        .prepare(
            "SELECT locator FROM credential_references
             WHERE provider = 'gmail' ORDER BY created_at_ms, locator LIMIT 256",
        )
        .map_err(|_| internal())?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| internal())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| internal())?;
    Ok(rows)
}

fn delete_all_gmail_credentials<C: GmailCredentialStore>(
    database: &Database,
    credentials: &C,
) -> GmailConnectorPortResult<()> {
    delete_gmail_credentials_except(database, credentials, None)
}

fn delete_gmail_credentials_except<C: GmailCredentialStore>(
    database: &Database,
    credentials: &C,
    retained_locator: Option<&str>,
) -> GmailConnectorPortResult<()> {
    for locator_text in gmail_credential_locators(database)? {
        if retained_locator == Some(locator_text.as_str()) {
            continue;
        }
        let locator = CredentialLocator::new(locator_text.clone()).map_err(|_| data_integrity())?;
        credentials.delete_refresh(&locator)?;
        database
            .connection()
            .map_err(|_| internal())?
            .execute(
                "DELETE FROM credential_references
                 WHERE locator = ?1 AND provider = 'gmail'",
                [locator_text],
            )
            .map_err(|_| internal())?;
    }
    let remaining: i64 = database
        .connection()
        .map_err(|_| internal())?
        .query_row(
            "SELECT COUNT(*) FROM credential_references
             WHERE provider = 'gmail' AND (?1 IS NULL OR locator <> ?1)",
            [retained_locator],
            |row| row.get(0),
        )
        .map_err(|_| internal())?;
    if remaining == 0 {
        Ok(())
    } else {
        Err(credential_unavailable())
    }
}

fn credential_locator_for_request(
    database: &Database,
    request_id: &str,
) -> GmailConnectorPortResult<Option<CredentialLocator>> {
    database
        .connection()
        .map_err(|_| internal())?
        .query_row(
            "SELECT locator FROM credential_references
             WHERE save_request_id = ?1 AND provider = 'gmail'",
            [request_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| internal())?
        .map(CredentialLocator::new)
        .transpose()
        .map_err(|_| data_integrity())
}

fn disconnect_identity(
    database: &Database,
    request_id: &str,
) -> GmailConnectorPortResult<(String, String)> {
    if let Some(row) = database
        .connection()
        .map_err(|_| internal())?
        .query_row(
            "SELECT account_key, credential_locator
             FROM gmail_disconnect_stages WHERE request_id = ?1",
            [request_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| internal())?
    {
        return Ok(row);
    }
    database
        .connection()
        .map_err(|_| internal())?
        .query_row(
            "SELECT state.account_key, account.credential_locator
             FROM gmail_connector_state state
             JOIN gmail_accounts account ON account.account_key = state.account_key
             WHERE state.singleton = 1
               AND state.status IN ('connected', 'disconnecting')",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .map_err(|_| data_integrity())
}

fn scope_fingerprint(label_id: &str) -> String {
    digest(
        format!(
            "{}\0{label_id}\0{PARSER_REVISION}\0{MATERIALIZATION_REVISION}",
            crate::GOOGLE_OAUTH_SCOPE
        )
        .as_bytes(),
    )
}

fn stable_uuid(namespace: &str, value: &str) -> String {
    let hash = Sha256::digest(format!("{namespace}\0{value}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn envelope<T: serde::Serialize>(request: &T) -> GmailConnectorPortResult<String> {
    serde_json::to_vec(request)
        .map(|bytes| digest(&bytes))
        .map_err(|_| internal())
}

fn run_async<T, F, Fut>(factory: F) -> GmailConnectorPortResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = GmailConnectorPortResult<T>> + 'static,
{
    std::thread::Builder::new()
        .name("wardrobe-gmail-operation".into())
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| internal())?
                .block_on(factory())
        })
        .map_err(|_| internal())?
        .join()
        .map_err(|_| internal())?
}

fn run_sync_async<T, F, Fut>(factory: F) -> Result<T, SyncError>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, SyncError>> + 'static,
{
    std::thread::Builder::new()
        .name("wardrobe-gmail-sync".into())
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| SyncError::Store)?
                .block_on(factory())
        })
        .map_err(|_| SyncError::Store)?
        .join()
        .map_err(|_| SyncError::Store)?
}

#[cfg(target_os = "macos")]
fn open_browser(url: &str) -> GmailConnectorPortResult<()> {
    let status = std::process::Command::new("/usr/bin/open")
        .arg(url)
        .status()
        .map_err(|_| unavailable())?;
    if status.success() {
        Ok(())
    } else {
        Err(unavailable())
    }
}

#[cfg(not(target_os = "macos"))]
fn open_browser(_url: &str) -> GmailConnectorPortResult<()> {
    Err(unavailable())
}

fn now_ms() -> GmailConnectorPortResult<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| internal())?;
    i64::try_from(duration.as_millis()).map_err(|_| internal())
}

fn map_credential_error(error: wardrobe_core::PortError) -> GmailConnectorPortError {
    match error.kind {
        wardrobe_core::PortErrorKind::PermissionDenied
        | wardrobe_core::PortErrorKind::Unavailable => credential_unavailable(),
        wardrobe_core::PortErrorKind::NotFound => credential_unavailable(),
        wardrobe_core::PortErrorKind::DataIntegrity => data_integrity(),
        _ => internal(),
    }
}

fn map_http_error(error: GoogleHttpError) -> GmailConnectorPortError {
    match error {
        GoogleHttpError::Permission => permission_denied(),
        GoogleHttpError::MalformedRequest | GoogleHttpError::MalformedResponse => {
            malformed_provider()
        }
        GoogleHttpError::BodyTooLarge => scope_too_large(),
        GoogleHttpError::Authentication => credential_unavailable(),
        _ => unavailable(),
    }
}

fn map_sync_error(error: SyncError) -> GmailConnectorPortError {
    match error {
        SyncError::ScopeTooLarge => scope_too_large(),
        SyncError::Permission => permission_denied(),
        SyncError::Authentication => credential_unavailable(),
        SyncError::MalformedRequest | SyncError::MalformedResponse => malformed_provider(),
        SyncError::RevisionCollision => data_integrity(),
        SyncError::CompareAndSwap => conflict(),
        SyncError::InvalidConfiguration => invalid_state(),
        SyncError::RateLimited
        | SyncError::Quota
        | SyncError::Transport
        | SyncError::Server
        | SyncError::Timeout
        | SyncError::Cancelled => unavailable(),
        SyncError::Store => internal(),
    }
}

fn map_busy_sql(error: rusqlite::Error) -> GmailConnectorPortError {
    if matches!(
        error,
        rusqlite::Error::SqliteFailure(ref code, _)
            if code.code == rusqlite::ErrorCode::ConstraintViolation
    ) {
        GmailConnectorPortError::new(GmailConnectorPortErrorKind::Busy)
    } else {
        internal()
    }
}

const fn unavailable() -> GmailConnectorPortError {
    GmailConnectorPortError::new(GmailConnectorPortErrorKind::Unavailable)
}
const fn conflict() -> GmailConnectorPortError {
    GmailConnectorPortError::new(GmailConnectorPortErrorKind::Conflict)
}
const fn invalid_state() -> GmailConnectorPortError {
    GmailConnectorPortError::new(GmailConnectorPortErrorKind::InvalidState)
}
const fn permission_denied() -> GmailConnectorPortError {
    GmailConnectorPortError::new(GmailConnectorPortErrorKind::PermissionDenied)
}
const fn credential_unavailable() -> GmailConnectorPortError {
    GmailConnectorPortError::new(GmailConnectorPortErrorKind::CredentialUnavailable)
}
const fn scope_too_large() -> GmailConnectorPortError {
    GmailConnectorPortError::new(GmailConnectorPortErrorKind::ScopeTooLarge)
}
const fn malformed_provider() -> GmailConnectorPortError {
    GmailConnectorPortError::new(GmailConnectorPortErrorKind::MalformedProviderOutput)
}
const fn data_integrity() -> GmailConnectorPortError {
    GmailConnectorPortError::new(GmailConnectorPortErrorKind::DataIntegrity)
}
const fn internal() -> GmailConnectorPortError {
    GmailConnectorPortError::new(GmailConnectorPortErrorKind::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateAppPaths;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use wardrobe_core::{CredentialPort, PortResult, RequestId, Validate};

    #[derive(Clone, Default)]
    struct MemoryCredentials(Arc<Mutex<BTreeMap<String, String>>>);

    impl GmailCredentialStore for MemoryCredentials {
        fn put_refresh(
            &self,
            locator: &CredentialLocator,
            secret: &SecretString,
        ) -> Result<(), GmailConnectorPortError> {
            self.0.lock().unwrap().insert(
                locator.expose_locator().to_owned(),
                secret.expose_secret().to_owned(),
            );
            Ok(())
        }

        fn get_refresh(
            &self,
            locator: &CredentialLocator,
        ) -> Result<Option<SecretString>, GmailConnectorPortError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .get(locator.expose_locator())
                .cloned()
                .map(SecretString::new))
        }

        fn delete_refresh(
            &self,
            locator: &CredentialLocator,
        ) -> Result<(), GmailConnectorPortError> {
            self.0.lock().unwrap().remove(locator.expose_locator());
            Ok(())
        }
    }

    #[derive(Default)]
    struct ControlledCredentialState {
        secrets: BTreeMap<String, String>,
        put_calls: usize,
        get_failures_remaining: usize,
        delete_failures_remaining: usize,
        get_calls: usize,
        contains_calls: usize,
        delete_calls: usize,
    }

    #[derive(Clone, Default)]
    struct ControlledCredentials(Arc<Mutex<ControlledCredentialState>>);

    impl GmailCredentialStore for ControlledCredentials {
        fn put_refresh(
            &self,
            locator: &CredentialLocator,
            secret: &SecretString,
        ) -> Result<(), GmailConnectorPortError> {
            let mut state = self.0.lock().unwrap();
            state.put_calls += 1;
            state.secrets.insert(
                locator.expose_locator().to_owned(),
                secret.expose_secret().to_owned(),
            );
            Ok(())
        }

        fn get_refresh(
            &self,
            locator: &CredentialLocator,
        ) -> Result<Option<SecretString>, GmailConnectorPortError> {
            let mut state = self.0.lock().unwrap();
            state.get_calls += 1;
            if state.get_failures_remaining > 0 {
                state.get_failures_remaining -= 1;
                return Err(credential_unavailable());
            }
            Ok(state
                .secrets
                .get(locator.expose_locator())
                .cloned()
                .map(SecretString::new))
        }

        fn delete_refresh(
            &self,
            locator: &CredentialLocator,
        ) -> Result<(), GmailConnectorPortError> {
            let mut state = self.0.lock().unwrap();
            state.delete_calls += 1;
            if state.delete_failures_remaining > 0 {
                state.delete_failures_remaining -= 1;
                return Err(credential_unavailable());
            }
            state.secrets.remove(locator.expose_locator());
            Ok(())
        }
    }

    impl CredentialPort for ControlledCredentials {
        fn put(&self, locator: &CredentialLocator, secret: &SecretString) -> PortResult<()> {
            let mut state = self.0.lock().unwrap();
            state.put_calls += 1;
            state.secrets.insert(
                locator.expose_locator().to_owned(),
                secret.expose_secret().to_owned(),
            );
            Ok(())
        }

        fn get(&self, locator: &CredentialLocator) -> PortResult<SecretString> {
            let mut state = self.0.lock().unwrap();
            state.get_calls += 1;
            state
                .secrets
                .get(locator.expose_locator())
                .cloned()
                .map(SecretString::new)
                .ok_or_else(|| {
                    wardrobe_core::PortError::new(wardrobe_core::PortErrorKind::NotFound)
                })
        }

        fn contains(&self, locator: &CredentialLocator) -> PortResult<bool> {
            let mut state = self.0.lock().unwrap();
            state.contains_calls += 1;
            Ok(state.secrets.contains_key(locator.expose_locator()))
        }

        fn delete(&self, locator: &CredentialLocator) -> PortResult<()> {
            let mut state = self.0.lock().unwrap();
            state.delete_calls += 1;
            state.secrets.remove(locator.expose_locator());
            Ok(())
        }
    }

    fn connector() -> ProductionGmailConnector<MemoryCredentials> {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.keep();
        let paths = PrivateAppPaths::create(root.join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        ProductionGmailConnector::with_adapters(
            database,
            MemoryCredentials::default(),
            GoogleHttpClient::production().unwrap(),
        )
    }

    fn controlled_connector(
        delete_failures: usize,
    ) -> ProductionGmailConnector<ControlledCredentials> {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.keep();
        let paths = PrivateAppPaths::create(root.join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        let credentials = ControlledCredentials::default();
        credentials.0.lock().unwrap().delete_failures_remaining = delete_failures;
        ProductionGmailConnector::with_adapters(
            database,
            credentials,
            GoogleHttpClient::production().unwrap(),
        )
    }

    fn seed_connected<C: GmailCredentialStore>(
        connector: &ProductionGmailConnector<C>,
        locator: &CredentialLocator,
    ) -> (String, String) {
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO credential_references(
                    locator, credential_id, save_request_id, provider, display_label,
                    status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, 'gmail', 'Gmail', 'active', 1, 1)",
                params![
                    locator.expose_locator(),
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string()
                ],
            )
            .unwrap();
        let account_key = "a".repeat(64);
        let scope_id = "44444444-4444-4444-8444-444444444444".to_owned();
        connector
            .database
            .initialize_gmail_scope(
                &account_key,
                locator.expose_locator(),
                &scope_id,
                &"b".repeat(64),
                "Label_1",
                PARSER_REVISION,
                MATERIALIZATION_REVISION,
                2,
            )
            .unwrap();
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "UPDATE gmail_connector_state
                 SET status = 'connected', account_key = ?1, scope_id = ?2
                 WHERE singleton = 1",
                params![account_key, scope_id],
            )
            .unwrap();
        (account_key, scope_id)
    }

    #[test]
    fn settings_are_atomic_replayable_and_editable_only_while_disconnected() {
        let connector = connector();
        let request = SaveGmailSettingsV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
            client_id: "client.apps.googleusercontent.com".into(),
            label_name: "Wardrobe Receipts".into(),
            limits: GmailConnectorLimitsV1 {
                page_size: 50,
                max_pages: 4,
                max_unique_messages: 100,
                max_total_raw_bytes: 50 * 1024 * 1024,
            },
        };
        let created = connector.save_gmail_settings(&request).unwrap();
        assert_eq!(created.replay_status, ReplayStatusV1::Created);
        let replayed = connector.save_gmail_settings(&request).unwrap();
        assert_eq!(replayed.replay_status, ReplayStatusV1::Replayed);
        replayed.validate().unwrap();
        let state = connector
            .get_gmail_connector(&GetGmailConnectorV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
            })
            .unwrap();
        assert_eq!(state.status, GmailConnectorStatusV1::Disconnected);
        assert_eq!(state.settings.unwrap().label_name, "Wardrobe Receipts");
    }

    #[test]
    fn production_construction_does_not_automatically_recover() {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        let request_id = RequestId::new_v4().to_string();
        begin_operation(
            &database,
            &request_id,
            "connect_gmail_v1",
            &"7".repeat(64),
            "authorizing",
        )
        .unwrap();

        let _connector = ProductionGmailConnector::production(database.clone()).unwrap();

        assert_eq!(
            database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT stage FROM gmail_operations WHERE request_id = ?1",
                    [&request_id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "authorizing"
        );
        assert_eq!(
            database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT status FROM gmail_connector_state WHERE singleton = 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "connecting"
        );
    }

    #[test]
    fn startup_deletes_legacy_gmail_locators_before_reporting_disconnected() {
        let connector = connector();
        let locator = CredentialLocator::new("legacy-gmail-locator".into()).unwrap();
        connector
            .credentials
            .put_refresh(&locator, &SecretString::new("legacy-secret".into()))
            .unwrap();
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO credential_references(
                    locator, credential_id, save_request_id, provider, display_label,
                    status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, 'gmail', 'Legacy Gmail', 'active', 1, 1)",
                params![
                    locator.expose_locator(),
                    "11111111-1111-4111-8111-111111111111",
                    "22222222-2222-4222-8222-222222222222"
                ],
            )
            .unwrap();

        connector.recover_with_revocation().unwrap();

        assert!(connector
            .credentials
            .get_refresh(&locator)
            .unwrap()
            .is_none());
        assert_eq!(
            gmail_credential_locators(&connector.database).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            connector.state().unwrap().0,
            GmailConnectorStatusV1::NotConfigured
        );
    }

    #[test]
    fn startup_aborts_interrupted_connect_after_exact_locator_cleanup() {
        let connector = connector();
        let request_id = RequestId::new_v4().to_string();
        let envelope = "a".repeat(64);
        begin_operation(
            &connector.database,
            &request_id,
            "connect_gmail_v1",
            &envelope,
            "authorizing",
        )
        .unwrap();
        let locator = CredentialLocator::new("pending-gmail-locator".into()).unwrap();
        reserve_credential(&connector.database, &request_id, &locator).unwrap();

        connector.recover_with_revocation().unwrap();

        let connection = connector.database.connection().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM gmail_operations", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT stage FROM gmail_operations WHERE request_id = ?1",
                    [&request_id],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "terminal"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM gmail_oauth_attempts WHERE request_id = ?1",
                    [&request_id],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "failed"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM gmail_connector_state WHERE singleton = 1",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "disconnected"
        );
        assert!(gmail_credential_locators(&connector.database)
            .unwrap()
            .is_empty());
        assert_eq!(
            begin_operation(
                &connector.database,
                &request_id,
                "connect_gmail_v1",
                &envelope,
                "authorizing",
            )
            .unwrap_err()
            .kind,
            GmailConnectorPortErrorKind::Conflict
        );
    }

    #[test]
    fn startup_finishes_interrupted_disconnect_and_preserves_evidence() {
        let connector = connector();
        let locator = CredentialLocator::new("disconnect-gmail-locator".into()).unwrap();
        let credential_request = RequestId::new_v4().to_string();
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO credential_references(
                    locator, credential_id, save_request_id, provider, display_label,
                    status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, 'gmail', 'Gmail', 'active', 1, 1)",
                params![
                    locator.expose_locator(),
                    "33333333-3333-4333-8333-333333333333",
                    credential_request
                ],
            )
            .unwrap();
        let account_key = "a".repeat(64);
        let scope_id = "44444444-4444-4444-8444-444444444444";
        connector
            .database
            .initialize_gmail_scope(
                &account_key,
                locator.expose_locator(),
                scope_id,
                &"b".repeat(64),
                "Label_1",
                PARSER_REVISION,
                MATERIALIZATION_REVISION,
                2,
            )
            .unwrap();
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO local_sources(
                    source_id, source_kind, identity_key, canonical_locator,
                    status, no_blob_reason, created_at_ms, updated_at_ms
                 ) VALUES (
                    '55555555-5555-4555-8555-555555555555', 'folder_image',
                    'disconnect-evidence', '/synthetic/disconnect.png',
                    'unavailable', 'synthetic', 2, 2
                 )",
                [],
            )
            .unwrap();
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO evidence(
                    evidence_id, source_id, evidence_kind, state,
                    created_at_ms, updated_at_ms
                 ) VALUES (
                    '66666666-6666-4666-8666-666666666666',
                    '55555555-5555-4555-8555-555555555555',
                    'image', 'unresolved', 2, 2
                 )",
                [],
            )
            .unwrap();
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "UPDATE gmail_connector_state
                 SET status = 'connected', account_key = ?1, scope_id = ?2
                 WHERE singleton = 1",
                params![account_key, scope_id],
            )
            .unwrap();
        let evidence_before: i64 = connector
            .database
            .connection()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
            .unwrap();
        let request_id = RequestId::new_v4().to_string();
        let envelope = "c".repeat(64);
        begin_disconnect(
            &connector.database,
            &request_id,
            "disconnect_gmail_v1",
            &envelope,
            &account_key,
            &locator,
        )
        .unwrap();
        persist_disconnect_revocation(
            &connector.database,
            &request_id,
            GmailRevocationOutcomeV1::Failed,
        )
        .unwrap();

        connector.recover_with_revocation().unwrap();

        let connection = connector.database.connection().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM gmail_connector_state WHERE singleton = 1",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            "disconnected"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM evidence", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            evidence_before
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM command_receipts WHERE request_id = ?1",
                    [request_id],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
    }

    #[test]
    fn locked_keychain_pauses_disconnect_before_revocation_or_deletion() {
        let connector = controlled_connector(0);
        let locator = CredentialLocator::new("locked-keychain-locator".into()).unwrap();
        connector
            .credentials
            .put_refresh(&locator, &SecretString::new("refresh-secret".into()))
            .unwrap();
        connector
            .credentials
            .0
            .lock()
            .unwrap()
            .get_failures_remaining = 1;
        let (account_key, _) = seed_connected(&connector, &locator);
        let request_id = RequestId::new_v4().to_string();
        begin_disconnect(
            &connector.database,
            &request_id,
            "disconnect_gmail_v1",
            &"f".repeat(64),
            &account_key,
            &locator,
        )
        .unwrap();

        let error = connector.recover_with_revocation().unwrap_err();

        assert_eq!(
            error.kind,
            GmailConnectorPortErrorKind::CredentialUnavailable
        );
        let connection = connector.database.connection().unwrap();
        let stage: (String, Option<String>, i64) = connection
            .query_row(
                "SELECT operation.stage, disconnect.revocation_result,
                        disconnect.credential_deleted
                 FROM gmail_operations operation
                 JOIN gmail_disconnect_stages disconnect
                   ON disconnect.request_id = operation.request_id
                 WHERE operation.request_id = ?1",
                [&request_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stage, ("revocation_pending".into(), None, 0));
        assert_eq!(
            connector
                .credentials
                .get_refresh(&locator)
                .unwrap()
                .unwrap()
                .expose_secret(),
            "refresh-secret"
        );
        assert_eq!(connector.credentials.0.lock().unwrap().delete_calls, 0);
    }

    #[test]
    fn startup_removes_legacy_locator_without_deleting_connected_credential() {
        let connector = connector();
        let active = CredentialLocator::new("active-gmail-locator".into()).unwrap();
        connector
            .credentials
            .put_refresh(&active, &SecretString::new("active-secret".into()))
            .unwrap();
        seed_connected(&connector, &active);
        let legacy = CredentialLocator::new("connected-legacy-locator".into()).unwrap();
        connector
            .credentials
            .put_refresh(&legacy, &SecretString::new("legacy-secret".into()))
            .unwrap();
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO credential_references(
                    locator, credential_id, save_request_id, provider, display_label,
                    status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, 'gmail', 'Legacy Gmail', 'active', 2, 2)",
                params![
                    legacy.expose_locator(),
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string()
                ],
            )
            .unwrap();

        connector.recover_with_revocation().unwrap();

        assert!(connector
            .credentials
            .get_refresh(&active)
            .unwrap()
            .is_some());
        assert!(connector
            .credentials
            .get_refresh(&legacy)
            .unwrap()
            .is_none());
        assert_eq!(
            gmail_credential_locators(&connector.database).unwrap(),
            vec![active.expose_locator().to_owned()]
        );
        assert_eq!(
            connector.state().unwrap().0,
            GmailConnectorStatusV1::Connected
        );
    }

    #[test]
    fn startup_retries_credential_deletion_without_repeating_durable_revocation() {
        let connector = controlled_connector(1);
        let locator = CredentialLocator::new("disconnect-retry-locator".into()).unwrap();
        connector
            .credentials
            .put_refresh(&locator, &SecretString::new("refresh-secret".into()))
            .unwrap();
        let (account_key, _) = seed_connected(&connector, &locator);
        let request_id = RequestId::new_v4().to_string();
        let envelope = "d".repeat(64);
        begin_disconnect(
            &connector.database,
            &request_id,
            "disconnect_gmail_v1",
            &envelope,
            &account_key,
            &locator,
        )
        .unwrap();
        persist_disconnect_revocation(
            &connector.database,
            &request_id,
            GmailRevocationOutcomeV1::Succeeded,
        )
        .unwrap();

        let error = connector.recover_with_revocation().unwrap_err();
        assert_eq!(
            error.kind,
            GmailConnectorPortErrorKind::CredentialUnavailable
        );
        assert_eq!(
            connector.state().unwrap(),
            (
                GmailConnectorStatusV1::Disconnecting,
                UserActionKeyV1::UnlockKeychain
            )
        );
        let durable: (String, String) = connector
            .database
            .connection()
            .unwrap()
            .query_row(
                "SELECT operation.stage, stage.revocation_result
                 FROM gmail_operations operation
                 JOIN gmail_disconnect_stages stage
                   ON stage.request_id = operation.request_id
                 WHERE operation.request_id = ?1",
                [&request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            durable,
            ("credential_delete_pending".into(), "succeeded".into())
        );

        connector.recover_with_revocation().unwrap();

        let credential_state = connector.credentials.0.lock().unwrap();
        assert_eq!(credential_state.get_calls, 0);
        assert_eq!(credential_state.delete_calls, 2);
        drop(credential_state);
        let response_json: String = connector
            .database
            .connection()
            .unwrap()
            .query_row(
                "SELECT response_json FROM gmail_operations WHERE request_id = ?1",
                [&request_id],
                |row| row.get(0),
            )
            .unwrap();
        let response: DisconnectGmailV1Response = serde_json::from_str(&response_json).unwrap();
        assert_eq!(
            response.revocation_outcome,
            GmailRevocationOutcomeV1::Succeeded
        );
        assert_eq!(
            connector.state().unwrap().0,
            GmailConnectorStatusV1::NotConfigured
        );
    }

    #[test]
    fn startup_discards_interrupted_sync_without_changing_connected_state() {
        let connector = connector();
        let locator = CredentialLocator::new("sync-recovery-locator".into()).unwrap();
        let (account_key, scope_id) = seed_connected(&connector, &locator);
        let request_id = RequestId::new_v4().to_string();
        begin_operation(
            &connector.database,
            &request_id,
            "sync_gmail_v1",
            &"e".repeat(64),
            "syncing",
        )
        .unwrap();

        connector.recover_with_revocation().unwrap();

        let connection = connector.database.connection().unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM gmail_operations WHERE request_id = ?1",
                    [&request_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT account_key, scope_id FROM gmail_connector_state
                     WHERE singleton = 1 AND status = 'connected'",
                    [],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            (account_key, scope_id)
        );
    }

    #[test]
    fn local_only_disconnect_records_exact_outcome_without_secret_read_or_http() {
        let connector = controlled_connector(0);
        let locator = CredentialLocator::new("local-only-disconnect-locator".into()).unwrap();
        connector
            .credentials
            .put_refresh(&locator, &SecretString::new("refresh-secret".into()))
            .unwrap();
        seed_connected(&connector, &locator);
        let request = DisconnectGmailV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: RequestId::new_v4(),
        };

        let response = connector
            .disconnect_gmail_with_completion(
                &request,
                GmailDisconnectCompletion::SkipRevocationNotAttemptedLocalOnly,
            )
            .unwrap();

        assert_eq!(
            response.revocation_outcome,
            GmailRevocationOutcomeV1::NotAttemptedLocalOnly
        );
        let credential_state = connector.credentials.0.lock().unwrap();
        assert_eq!(credential_state.get_calls, 0);
        assert_eq!(credential_state.delete_calls, 1);
        assert!(credential_state.secrets.is_empty());
        drop(credential_state);
        let durable: (String, i64) = connector
            .database
            .connection()
            .unwrap()
            .query_row(
                "SELECT revocation_result, credential_deleted
                 FROM gmail_disconnect_stages WHERE request_id = ?1",
                [request.request_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(durable, ("not_attempted_local_only".into(), 1));
    }

    #[test]
    fn local_recovery_finishes_interrupted_disconnect_without_secret_read_or_http() {
        let connector = controlled_connector(0);
        let locator = CredentialLocator::new("local-recovery-locator".into()).unwrap();
        connector
            .credentials
            .put_refresh(&locator, &SecretString::new("refresh-secret".into()))
            .unwrap();
        let (account_key, _) = seed_connected(&connector, &locator);
        let request_id = RequestId::new_v4().to_string();
        let envelope = "9".repeat(64);
        begin_disconnect(
            &connector.database,
            &request_id,
            "disconnect_gmail_v1",
            &envelope,
            &account_key,
            &locator,
        )
        .unwrap();

        connector.recover_local_state().unwrap();

        let credential_state = connector.credentials.0.lock().unwrap();
        assert_eq!(credential_state.get_calls, 0);
        assert_eq!(credential_state.delete_calls, 1);
        drop(credential_state);
        let response_json: String = connector
            .database
            .connection()
            .unwrap()
            .query_row(
                "SELECT response_json FROM gmail_operations WHERE request_id = ?1",
                [&request_id],
                |row| row.get(0),
            )
            .unwrap();
        let response: DisconnectGmailV1Response = serde_json::from_str(&response_json).unwrap();
        assert_eq!(
            response.revocation_outcome,
            GmailRevocationOutcomeV1::NotAttemptedLocalOnly
        );
    }

    #[test]
    fn restored_disconnect_is_inert_through_local_startup_recovery() {
        let temporary = tempfile::tempdir().unwrap();
        let source_paths = PrivateAppPaths::create(temporary.path().join("source")).unwrap();
        let source_database = Database::open(&source_paths, 1).unwrap();
        let source_connector = ProductionGmailConnector::with_adapters(
            source_database.clone(),
            ControlledCredentials::default(),
            GoogleHttpClient::production().unwrap(),
        );
        let locator = CredentialLocator::new("restored-current-locator".into()).unwrap();
        let (account_key, scope_id) = seed_connected(&source_connector, &locator);
        source_database
            .connection()
            .unwrap()
            .execute(
                "INSERT INTO gmail_checkpoints(scope_id, history_id, updated_at_ms)
                 VALUES (?1, '4242', 3)",
                [&scope_id],
            )
            .unwrap();
        let request_id = RequestId::new_v4().to_string();
        begin_disconnect(
            &source_database,
            &request_id,
            "disconnect_gmail_v1",
            &"a".repeat(64),
            &account_key,
            &locator,
        )
        .unwrap();
        source_database
            .connection()
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();

        let restored_paths = PrivateAppPaths::create(temporary.path().join("restored")).unwrap();
        crate::database::stage_restore_database(
            &source_paths.database,
            &restored_paths.database,
            20,
        )
        .unwrap();
        let restored_database = Database::open(&restored_paths, 21).unwrap();
        let checkpoint_before: (String, i64) = restored_database
            .connection()
            .unwrap()
            .query_row(
                "SELECT history_id, updated_at_ms FROM gmail_checkpoints
                 WHERE scope_id = ?1",
                [&scope_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let operation_before: (String, String) = restored_database
            .connection()
            .unwrap()
            .query_row(
                "SELECT stage, response_json FROM gmail_operations
                 WHERE request_id = ?1",
                [&request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let disconnect_before: (Option<String>, i64, i64) = restored_database
            .connection()
            .unwrap()
            .query_row(
                "SELECT revocation_result, credential_deleted, updated_at_ms
                 FROM gmail_disconnect_stages WHERE request_id = ?1",
                [&request_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            operation_before,
            (
                "terminal".into(),
                "{\"interrupted\":true,\"reason\":\"restore_interrupted\"}".into()
            )
        );
        assert_eq!(
            gmail_credential_locators(&restored_database).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            restored_database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT credential_locator FROM gmail_accounts
                     WHERE account_key = ?1",
                    [&account_key],
                    |row| row.get::<_, Option<String>>(0),
                )
                .unwrap(),
            None
        );

        let credentials = ControlledCredentials::default();
        credentials.0.lock().unwrap().secrets.insert(
            locator.expose_locator().to_owned(),
            "current-installation-secret".into(),
        );
        restored_database
            .reconcile_credentials(&credentials, 22)
            .unwrap();
        let connector = ProductionGmailConnector::with_adapters(
            restored_database.clone(),
            credentials.clone(),
            GoogleHttpClient::production().unwrap(),
        );
        connector.recover_local_state().unwrap();

        let credential_state = credentials.0.lock().unwrap();
        assert_eq!(credential_state.put_calls, 0);
        assert_eq!(credential_state.get_calls, 0);
        assert_eq!(credential_state.contains_calls, 0);
        assert_eq!(credential_state.delete_calls, 0);
        assert_eq!(
            credential_state
                .secrets
                .get(locator.expose_locator())
                .map(String::as_str),
            Some("current-installation-secret")
        );
        drop(credential_state);
        assert_eq!(
            restored_database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT history_id, updated_at_ms FROM gmail_checkpoints
                     WHERE scope_id = ?1",
                    [&scope_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                )
                .unwrap(),
            checkpoint_before
        );
        assert_eq!(
            restored_database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT stage, response_json FROM gmail_operations
                     WHERE request_id = ?1",
                    [&request_id],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .unwrap(),
            operation_before
        );
        assert_eq!(
            restored_database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT revocation_result, credential_deleted, updated_at_ms
                     FROM gmail_disconnect_stages WHERE request_id = ?1",
                    [&request_id],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .unwrap(),
            disconnect_before
        );
        assert_eq!(
            restored_database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM command_receipts WHERE request_id = ?1",
                    [&request_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn revocation_outcome_compare_and_set_rejects_semantic_change() {
        let connector = connector();
        let locator = CredentialLocator::new("revocation-cas-locator".into()).unwrap();
        let (account_key, _) = seed_connected(&connector, &locator);
        let request_id = RequestId::new_v4().to_string();
        begin_disconnect(
            &connector.database,
            &request_id,
            "disconnect_gmail_v1",
            &"8".repeat(64),
            &account_key,
            &locator,
        )
        .unwrap();
        persist_disconnect_revocation(
            &connector.database,
            &request_id,
            GmailRevocationOutcomeV1::NotAttemptedLocalOnly,
        )
        .unwrap();
        persist_disconnect_revocation(
            &connector.database,
            &request_id,
            GmailRevocationOutcomeV1::NotAttemptedLocalOnly,
        )
        .unwrap();

        let error = persist_disconnect_revocation(
            &connector.database,
            &request_id,
            GmailRevocationOutcomeV1::Failed,
        )
        .unwrap_err();

        assert_eq!(error.kind, GmailConnectorPortErrorKind::DataIntegrity);
        assert_eq!(
            stored_disconnect_revocation(&connector.database, &request_id).unwrap(),
            Some(GmailRevocationOutcomeV1::NotAttemptedLocalOnly)
        );
    }

    #[test]
    fn source_less_disconnect_finalization_is_rejected() {
        let connector = connector();
        let locator = CredentialLocator::new("source-less-finalization-locator".into()).unwrap();
        let (account_key, _) = seed_connected(&connector, &locator);
        let request_id = RequestId::new_v4();
        let request_id_text = request_id.to_string();
        let envelope = "6".repeat(64);
        begin_disconnect(
            &connector.database,
            &request_id_text,
            "disconnect_gmail_v1",
            &envelope,
            &account_key,
            &locator,
        )
        .unwrap();
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "DELETE FROM credential_references
                 WHERE locator = ?1 AND provider = 'gmail'",
                [locator.expose_locator()],
            )
            .unwrap();
        connector
            .database
            .connection()
            .unwrap()
            .execute(
                "DELETE FROM gmail_disconnect_stages WHERE request_id = ?1",
                [&request_id_text],
            )
            .unwrap();
        let response = DisconnectGmailV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id,
            status: GmailConnectorStatusV1::Disconnected,
            user_action: UserActionKeyV1::ConnectGmail,
            revocation_outcome: GmailRevocationOutcomeV1::Failed,
            replay_status: ReplayStatusV1::Created,
        };

        let error = finalize_disconnect(
            &connector.database,
            &account_key,
            &request_id_text,
            "disconnect_gmail_v1",
            &envelope,
            &response,
        )
        .unwrap_err();

        assert_eq!(error.kind, GmailConnectorPortErrorKind::DataIntegrity);
        assert_eq!(
            connector
                .database
                .connection()
                .unwrap()
                .query_row(
                    "SELECT stage FROM gmail_operations WHERE request_id = ?1",
                    [&request_id_text],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            "revocation_pending"
        );
    }
}
