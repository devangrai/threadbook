use crate::receipt_intelligence_repository::{
    ReceiptIntelligenceAttemptState, ReceiptIntelligenceClassification as RepositoryClassification,
};
use crate::{
    build_receipt_intelligence_request, Database, MacOsKeychain, OpenAiReceiptIntelligenceProvider,
    PlatformError, PlatformResult, ReceiptIntelligenceAuditMetadata, ReceiptIntelligenceBounds,
    ReceiptIntelligenceConsentReservation, ReceiptIntelligenceFragment,
    ReceiptIntelligenceOutcome as ProviderOutcome, ReceiptIntelligenceProviderError,
    ReceiptIntelligenceRequest,
};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::pin::Pin;
use time::{format_description::well_known::Rfc3339, Date, Month, OffsetDateTime};
use wardrobe_core::{
    CredentialId, CredentialLocator, CredentialPort, ListReceiptIntelligenceV1Request,
    ListReceiptIntelligenceV1Response, OpenAiRetentionDeclarationV1, OpenAiRetentionModeV1,
    PreviewReceiptIntelligenceV1Request, PreviewReceiptIntelligenceV1Response,
    ReceiptIntelligenceConsentEnvelopeV1, ReceiptIntelligenceDisclosureV1,
    ReceiptIntelligenceExecutionBoundsV1, ReceiptIntelligencePreparationBoundsV1,
    ReceiptIntelligencePreviewV1, ReceiptIntelligenceProjectionFragmentV1,
    ReceiptIntelligenceProjectionV1, ReceiptIntelligenceRetentionDisclosureV1,
    ReceiptIntelligenceSourceRevisionId, RequestReceiptIntelligenceV1Request,
    RequestReceiptIntelligenceV1Response, SecretString, Sha256Digest, Validate,
    RECEIPT_INTELLIGENCE_MODEL_V1, RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1,
    RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1, RECEIPT_INTELLIGENCE_PROMPT_REVISION_V1,
    RECEIPT_INTELLIGENCE_PROVIDER_V1, RECEIPT_INTELLIGENCE_PURPOSE_V1,
    RECEIPT_INTELLIGENCE_SCHEMA_REVISION_V1, SCHEMA_VERSION_V1,
};

const APPROVAL_LIFETIME_MS: i64 = 10 * 60 * 1_000;
const RETENTION_DECLARATION_PREFIX: &str = "openai-api-data-controls-";
const RETENTION_DECLARATION_MAX_AGE_DAYS: i64 = 90;
const RETENTION_DECLARATION_PROVENANCE_V1: &str = "openai-api-data-controls-2026-07-16";

pub trait ReceiptIntelligenceCredentialStore: Send + Sync {
    fn get_receipt_intelligence_secret(
        &self,
        locator: &CredentialLocator,
    ) -> Result<SecretString, PlatformError>;
}

impl ReceiptIntelligenceCredentialStore for MacOsKeychain {
    fn get_receipt_intelligence_secret(
        &self,
        locator: &CredentialLocator,
    ) -> Result<SecretString, PlatformError> {
        self.get(locator).map_err(|error| match error.kind {
            wardrobe_core::PortErrorKind::NotFound => PlatformError::Keychain("not_found"),
            wardrobe_core::PortErrorKind::PermissionDenied => {
                PlatformError::Keychain("permission_denied")
            }
            wardrobe_core::PortErrorKind::Unavailable => PlatformError::Keychain("unavailable"),
            wardrobe_core::PortErrorKind::DataIntegrity => {
                PlatformError::Keychain("data_integrity")
            }
            wardrobe_core::PortErrorKind::Conflict => PlatformError::Keychain("conflict"),
            wardrobe_core::PortErrorKind::Internal => PlatformError::Keychain("internal"),
        })
    }
}

pub trait ReceiptIntelligenceProviderPort: Send + Sync {
    fn analyze_receipt_intelligence<'a>(
        &'a self,
        api_key: &'a SecretString,
        request: &'a ReceiptIntelligenceRequest,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ProviderOutcome, ReceiptIntelligenceProviderError>>
                + Send
                + 'a,
        >,
    >;
}

impl ReceiptIntelligenceProviderPort for OpenAiReceiptIntelligenceProvider {
    fn analyze_receipt_intelligence<'a>(
        &'a self,
        api_key: &'a SecretString,
        request: &'a ReceiptIntelligenceRequest,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ProviderOutcome, ReceiptIntelligenceProviderError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(self.analyze(api_key, request))
    }
}

#[derive(Clone)]
pub struct ReceiptIntelligenceCoordinator<C = MacOsKeychain, P = OpenAiReceiptIntelligenceProvider>
{
    database: Database,
    credentials: C,
    provider: P,
}

impl ReceiptIntelligenceCoordinator<MacOsKeychain, OpenAiReceiptIntelligenceProvider> {
    pub fn production(database: Database) -> PlatformResult<Self> {
        let provider = OpenAiReceiptIntelligenceProvider::production()
            .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_provider"))?;
        Ok(Self::new(database, MacOsKeychain, provider))
    }
}

impl<C, P> ReceiptIntelligenceCoordinator<C, P>
where
    C: ReceiptIntelligenceCredentialStore,
    P: ReceiptIntelligenceProviderPort,
{
    pub fn new(database: Database, credentials: C, provider: P) -> Self {
        Self {
            database,
            credentials,
            provider,
        }
    }

    pub fn preview(
        &self,
        request: PreviewReceiptIntelligenceV1Request,
    ) -> PlatformResult<PreviewReceiptIntelligenceV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_preview"))?;
        let context = self
            .database
            .receipt_intelligence_preview_context(&request.source_id.to_string())?;
        let source_revision_id = ReceiptIntelligenceSourceRevisionId::new(
            uuid::Uuid::parse_str(&context.source_revision_id)
                .map_err(|_| PlatformError::Corrupt("receipt_intelligence_source_revision_id"))?,
        )
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_source_revision_id"))?;
        let source_revision_sha256 = Sha256Digest::parse(context.source_revision_sha256)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_source_revision_sha256"))?;
        let credential_id = CredentialId::new(
            uuid::Uuid::parse_str(&context.credential_id)
                .map_err(|_| PlatformError::Corrupt("receipt_intelligence_credential_id"))?,
        )
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_credential_id"))?;
        let preparation_bounds = ReceiptIntelligencePreparationBoundsV1::production();
        let execution_bounds = ReceiptIntelligenceExecutionBoundsV1::production();
        let now_ms = unix_now_ms()?;
        let retention_declaration = OpenAiRetentionDeclarationV1 {
            mode: OpenAiRetentionModeV1::Default,
            provenance: RETENTION_DECLARATION_PROVENANCE_V1.to_owned(),
        };
        ensure_retention_declaration_current(&retention_declaration.provenance, now_ms)?;
        let bounds = repository_bounds(&preparation_bounds, &execution_bounds);
        let stored = self.database.preview_receipt_intelligence(
            &request.request_id.to_string(),
            &source_revision_id.to_string(),
            bounds,
        )?;
        if stored.local_source_id != request.source_id.to_string()
            || stored.source_revision_sha256 != source_revision_sha256.as_str()
        {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_source_revision_changed",
            ));
        }

        let projection = ReceiptIntelligenceProjectionV1 {
            revision: RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1.to_owned(),
            fragments: stored
                .fragments
                .iter()
                .map(|fragment| ReceiptIntelligenceProjectionFragmentV1 {
                    fragment_ref: fragment.handle.clone(),
                    text: fragment.visible_text.clone(),
                })
                .collect(),
        };
        let provider_request = provider_request(&source_revision_id.to_string(), &projection)?;
        let serialized = serde_json::to_vec(&provider_request)?;
        if serialized.len() > preparation_bounds.max_serialized_request_bytes as usize
            || serialized.len() > execution_bounds.max_request_bytes as usize
        {
            return Err(PlatformError::InvalidInput(
                "receipt_intelligence_serialized_request_bytes",
            ));
        }
        let retention =
            ReceiptIntelligenceRetentionDisclosureV1::for_declaration(retention_declaration);
        let disclosure = ReceiptIntelligenceDisclosureV1 {
            provider: RECEIPT_INTELLIGENCE_PROVIDER_V1.to_owned(),
            model: RECEIPT_INTELLIGENCE_MODEL_V1.to_owned(),
            purpose: RECEIPT_INTELLIGENCE_PURPOSE_V1.to_owned(),
            aggregate_text_bytes: projection.aggregate_text_bytes(),
            projection,
            raw_mime_disclosed: false,
            headers_disclosed: false,
            urls_disclosed: false,
            filenames_disclosed: false,
            attachment_metadata_disclosed: false,
            cid_metadata_disclosed: false,
            internal_identifiers_disclosed: false,
            hashes_disclosed: false,
            credentials_disclosed: false,
            image_bytes_disclosed: false,
            retention: retention.clone(),
            preparation_bounds,
            execution_bounds,
        };
        let expires_at_ms = now_ms
            .checked_add(APPROVAL_LIFETIME_MS)
            .ok_or(PlatformError::Corrupt("receipt_intelligence_expiry"))?;
        let consent_envelope = ReceiptIntelligenceConsentEnvelopeV1 {
            source_id: request.source_id,
            source_revision_id,
            source_revision_sha256,
            disclosed_fragment_sha256: disclosure.projection.fragment_sha256(),
            projection_sha256: disclosure.projection.sha256(),
            serialized_request_sha256: Sha256Digest::from_bytes(&serialized),
            serialized_request_bytes: u32::try_from(serialized.len()).map_err(|_| {
                PlatformError::InvalidInput("receipt_intelligence_serialized_request_bytes")
            })?,
            credential_id,
            provider: RECEIPT_INTELLIGENCE_PROVIDER_V1.to_owned(),
            model: RECEIPT_INTELLIGENCE_MODEL_V1.to_owned(),
            prompt_revision: RECEIPT_INTELLIGENCE_PROMPT_REVISION_V1.to_owned(),
            schema_revision: RECEIPT_INTELLIGENCE_SCHEMA_REVISION_V1.to_owned(),
            projection_revision: RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1.to_owned(),
            parameter_revision: RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1.to_owned(),
            retention,
            preparation_bounds: disclosure.preparation_bounds.clone(),
            execution_bounds: disclosure.execution_bounds.clone(),
            expires_at: timestamp(expires_at_ms)?,
        };
        let response = PreviewReceiptIntelligenceV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            preview: ReceiptIntelligencePreviewV1 {
                disclosure,
                consent_envelope,
            },
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_preview"))?;
        Ok(response)
    }

    pub async fn request(
        &self,
        request: RequestReceiptIntelligenceV1Request,
    ) -> PlatformResult<RequestReceiptIntelligenceV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_request"))?;
        if let Some(response) = self.terminal_replay(&request)? {
            return Ok(response);
        }
        let command_sha256 = hash_json(&request)?;
        let now_ms = unix_now_ms()?;
        let preview = &request.consent.preview;
        let envelope = &preview.consent_envelope;
        ensure_retention_declaration_current(&envelope.retention.declaration.provenance, now_ms)?;
        let stored = self.database.preview_receipt_intelligence(
            &request.request_id.to_string(),
            &envelope.source_revision_id.to_string(),
            repository_bounds(&envelope.preparation_bounds, &envelope.execution_bounds),
        )?;
        ensure_preview_unchanged(preview, &stored)?;
        let parameters_sha256 = hash_json(&(
            RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1,
            &envelope.execution_bounds,
        ))?;
        let reservation = ReceiptIntelligenceConsentReservation {
            request_id: request.request_id.to_string(),
            command_sha256,
            source_revision_id: envelope.source_revision_id.to_string(),
            source_revision_sha256: envelope.source_revision_sha256.as_str().to_owned(),
            preview_binding_sha256: stored.preview_binding_sha256.clone(),
            fragment_set_sha256: stored.fragment_set_sha256.clone(),
            projection_sha256: envelope.projection_sha256.as_str().to_owned(),
            serialized_request_sha256: envelope.serialized_request_sha256.as_str().to_owned(),
            serialized_request_bytes: envelope.serialized_request_bytes,
            credential_id: envelope.credential_id.to_string(),
            provider: envelope.provider.clone(),
            model: envelope.model.clone(),
            retention_mode: retention_mode(envelope.retention.declaration.mode).to_owned(),
            retention_provenance: envelope.retention.declaration.provenance.clone(),
            prompt_revision: envelope.prompt_revision.clone(),
            schema_revision: envelope.schema_revision.clone(),
            projection_revision: envelope.projection_revision.clone(),
            parameters_sha256,
            bounds: repository_bounds(&envelope.preparation_bounds, &envelope.execution_bounds),
            expires_at_ms: parse_timestamp(&envelope.expires_at)?,
        };
        let reserved = self
            .database
            .reserve_receipt_intelligence(&reservation, now_ms)?;
        if reserved.replayed && reserved.state != ReceiptIntelligenceAttemptState::NotSent {
            return self.database.receipt_intelligence_response(
                request.request_id,
                &reserved.attempt_id,
                true,
            );
        }

        let provider_request = ReceiptIntelligenceRequest {
            parent_source_revision: envelope.source_revision_id.to_string(),
            fragments: preview
                .disclosure
                .projection
                .fragments
                .iter()
                .map(|fragment| ReceiptIntelligenceFragment {
                    fragment_ref: fragment.fragment_ref.clone(),
                    text: fragment.text.clone(),
                })
                .collect(),
        };
        let actual_serialized = serde_json::to_vec(
            &build_receipt_intelligence_request(&provider_request).map_err(map_provider_error)?,
        )?;
        if Sha256Digest::from_bytes(&actual_serialized) != envelope.serialized_request_sha256
            || actual_serialized.len() as u32 != envelope.serialized_request_bytes
        {
            self.database.fail_receipt_intelligence(
                &reserved.attempt_id,
                crate::ReceiptIntelligenceFailureCode::ConsentMismatch,
                unix_now_ms()?,
            )?;
            return Err(PlatformError::Conflict(
                "receipt_intelligence_request_changed",
            ));
        }
        let locator_text = match self
            .database
            .receipt_intelligence_credential_locator(&reserved.attempt_id, now_ms)
        {
            Ok(locator) => locator,
            Err(error) => {
                let failure = match &error {
                    PlatformError::Conflict("receipt_intelligence_approval_expired") => {
                        crate::ReceiptIntelligenceFailureCode::ApprovalExpired
                    }
                    _ => crate::ReceiptIntelligenceFailureCode::CredentialUnavailable,
                };
                self.database.fail_receipt_intelligence(
                    &reserved.attempt_id,
                    failure,
                    unix_now_ms()?,
                )?;
                return self.database.receipt_intelligence_response(
                    request.request_id,
                    &reserved.attempt_id,
                    reserved.replayed,
                );
            }
        };
        let locator = CredentialLocator::new(locator_text)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_credential_locator"))?;
        let secret = match self.credentials.get_receipt_intelligence_secret(&locator) {
            Ok(secret) => secret,
            Err(error) => {
                self.database.fail_receipt_intelligence(
                    &reserved.attempt_id,
                    crate::ReceiptIntelligenceFailureCode::CredentialUnavailable,
                    unix_now_ms()?,
                )?;
                return Err(error);
            }
        };
        let dispatched_at_ms = unix_now_ms()?;
        self.database
            .mark_receipt_intelligence_dispatched(&reserved.attempt_id, dispatched_at_ms)?;
        let outcome = self
            .provider
            .analyze_receipt_intelligence(&secret, &provider_request)
            .await;
        drop(secret);
        let finished_at_ms = unix_now_ms()?;
        let completion = match outcome {
            Ok(ProviderOutcome::Completed { output, audit }) => {
                let metadata = audit_metadata(&audit, dispatched_at_ms);
                let classification = repository_classification(output.classification);
                if matches!(
                    classification,
                    RepositoryClassification::Unrelated | RepositoryClassification::Ambiguous
                ) {
                    self.database.complete_receipt_intelligence_without_order(
                        &reserved.attempt_id,
                        classification,
                        &metadata,
                        finished_at_ms,
                    )
                } else {
                    self.database.complete_receipt_intelligence_with_order(
                        &reserved.attempt_id,
                        classification,
                        &output,
                        &metadata,
                        finished_at_ms,
                    )
                }
            }
            Ok(ProviderOutcome::Refused { audit }) => self.database.refuse_receipt_intelligence(
                &reserved.attempt_id,
                &audit_metadata(&audit, dispatched_at_ms),
                finished_at_ms,
            ),
            Ok(ProviderOutcome::Incomplete { .. }) => self.database.fail_receipt_intelligence(
                &reserved.attempt_id,
                crate::ReceiptIntelligenceFailureCode::ProviderOutputInvalid,
                finished_at_ms,
            ),
            Err(error) if provider_outcome_unknown(&error) => self
                .database
                .mark_receipt_intelligence_outcome_unknown(&reserved.attempt_id, finished_at_ms),
            Err(error) => self.database.fail_receipt_intelligence(
                &reserved.attempt_id,
                provider_failure_code(&error),
                finished_at_ms,
            ),
        };
        if let Err(error) = completion {
            self.database.fail_receipt_intelligence(
                &reserved.attempt_id,
                publication_failure_code(&error),
                finished_at_ms,
            )?;
        }
        self.database
            .receipt_intelligence_response(request.request_id, &reserved.attempt_id, false)
    }

    pub fn list(
        &self,
        request: ListReceiptIntelligenceV1Request,
    ) -> PlatformResult<ListReceiptIntelligenceV1Response> {
        self.list_at(request, unix_now_ms()?)
    }

    pub fn terminal_replay(
        &self,
        request: &RequestReceiptIntelligenceV1Request,
    ) -> PlatformResult<Option<RequestReceiptIntelligenceV1Response>> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_request"))?;
        let command_sha256 = hash_json(request)?;
        let Some(replayed) = self.database.preflight_receipt_intelligence_replay(
            &request.request_id.to_string(),
            &command_sha256,
        )?
        else {
            return Ok(None);
        };
        if replayed.state == ReceiptIntelligenceAttemptState::NotSent {
            return Ok(None);
        }
        self.database
            .receipt_intelligence_response(request.request_id, &replayed.attempt_id, true)
            .map(Some)
    }

    fn list_at(
        &self,
        request: ListReceiptIntelligenceV1Request,
        now_ms: i64,
    ) -> PlatformResult<ListReceiptIntelligenceV1Response> {
        let mut response = self.database.list_receipt_intelligence_response(&request)?;
        if ensure_retention_declaration_current(RETENTION_DECLARATION_PROVENANCE_V1, now_ms)
            .is_err()
        {
            response.availability = wardrobe_core::ReceiptIntelligenceAvailabilityV1 {
                available: false,
                reason: Some(
                    wardrobe_core::ReceiptIntelligenceAvailabilityReasonV1::RetentionDeclarationUnavailable,
                ),
                offline_receipt_analysis_available: true,
                existing_wardrobe_access_available: true,
            };
        }
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_list_response"))?;
        Ok(response)
    }

    pub fn recover(&self) -> PlatformResult<Vec<String>> {
        self.database
            .recover_receipt_intelligence_attempts(unix_now_ms()?)
    }
}

fn provider_request(
    parent_source_revision: &str,
    projection: &ReceiptIntelligenceProjectionV1,
) -> PlatformResult<serde_json::Value> {
    let request = ReceiptIntelligenceRequest {
        parent_source_revision: parent_source_revision.to_owned(),
        fragments: projection
            .fragments
            .iter()
            .map(|fragment| ReceiptIntelligenceFragment {
                fragment_ref: fragment.fragment_ref.clone(),
                text: fragment.text.clone(),
            })
            .collect(),
    };
    build_receipt_intelligence_request(&request).map_err(map_provider_error)
}

fn ensure_preview_unchanged(
    preview: &ReceiptIntelligencePreviewV1,
    stored: &crate::ReceiptIntelligencePreview,
) -> PlatformResult<()> {
    preview
        .validate()
        .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_preview"))?;
    let envelope = &preview.consent_envelope;
    if stored.local_source_id != envelope.source_id.to_string()
        || stored.source_revision_sha256 != envelope.source_revision_sha256.as_str()
        || stored.projection_sha256 != envelope.projection_sha256.as_str()
        || stored.fragments.len() != preview.disclosure.projection.fragments.len()
    {
        return Err(PlatformError::Conflict(
            "receipt_intelligence_preview_changed",
        ));
    }
    Ok(())
}

fn repository_bounds(
    preparation: &ReceiptIntelligencePreparationBoundsV1,
    execution: &ReceiptIntelligenceExecutionBoundsV1,
) -> ReceiptIntelligenceBounds {
    ReceiptIntelligenceBounds {
        max_fragment_count: u32::from(preparation.max_fragment_count),
        max_fragment_bytes: preparation.max_fragment_bytes,
        max_aggregate_text_bytes: preparation.max_aggregate_text_bytes,
        max_serialized_request_bytes: preparation.max_serialized_request_bytes,
        max_request_bytes: execution.max_request_bytes,
        max_response_bytes: execution.max_response_bytes,
        max_output_tokens: execution.max_output_tokens,
        timeout_ms: execution.timeout_millis,
        max_attempts: execution.max_attempts,
    }
}

fn audit_metadata(
    audit: &crate::ReceiptIntelligenceAudit,
    dispatched_at_ms: i64,
) -> ReceiptIntelligenceAuditMetadata {
    ReceiptIntelligenceAuditMetadata {
        response_sha256: None,
        provider_request_id: audit.provider_request_id.clone(),
        response_id: Some(audit.response_id.clone()),
        request_bytes: audit.usage.request_bytes,
        response_bytes: audit.usage.response_bytes,
        input_tokens: audit.usage.input_tokens,
        output_tokens: audit.usage.output_tokens,
        total_tokens: audit.usage.total_tokens,
        reasoning_tokens: audit.usage.reasoning_tokens,
        cached_input_tokens: audit.usage.cached_input_tokens,
        attempt_count: audit.usage.attempts,
        dispatched_at_ms,
    }
}

fn repository_classification(
    classification: crate::receipt_intelligence_provider::ReceiptIntelligenceClassification,
) -> RepositoryClassification {
    match classification {
        crate::receipt_intelligence_provider::ReceiptIntelligenceClassification::ApparelOrder => {
            RepositoryClassification::ApparelOrder
        }
        crate::receipt_intelligence_provider::ReceiptIntelligenceClassification::ApparelLifecycleUpdate => {
            RepositoryClassification::ApparelLifecycle
        }
        crate::receipt_intelligence_provider::ReceiptIntelligenceClassification::Unrelated => {
            RepositoryClassification::Unrelated
        }
        crate::receipt_intelligence_provider::ReceiptIntelligenceClassification::Ambiguous => {
            RepositoryClassification::Ambiguous
        }
    }
}

fn map_provider_error(_error: ReceiptIntelligenceProviderError) -> PlatformError {
    PlatformError::InvalidInput("receipt_intelligence_provider_request")
}

fn provider_outcome_unknown(error: &ReceiptIntelligenceProviderError) -> bool {
    matches!(
        error,
        ReceiptIntelligenceProviderError::Transport(error) if error.outcome_is_unknown()
    )
}

fn provider_failure_code(
    error: &ReceiptIntelligenceProviderError,
) -> crate::ReceiptIntelligenceFailureCode {
    use crate::outfit_recommendation_http::{OpenAiHttpStatusKind, OpenAiResponsesHttpError};
    match error {
        ReceiptIntelligenceProviderError::Transport(OpenAiResponsesHttpError::HttpStatus {
            kind: OpenAiHttpStatusKind::Authentication | OpenAiHttpStatusKind::Permission,
            ..
        }) => crate::ReceiptIntelligenceFailureCode::ProviderAuthentication,
        ReceiptIntelligenceProviderError::Transport(OpenAiResponsesHttpError::HttpStatus {
            kind: OpenAiHttpStatusKind::RateLimited,
            ..
        }) => crate::ReceiptIntelligenceFailureCode::ProviderRateLimited,
        ReceiptIntelligenceProviderError::Transport(_) => {
            crate::ReceiptIntelligenceFailureCode::ProviderUnavailable
        }
        ReceiptIntelligenceProviderError::InvalidCitation => {
            crate::ReceiptIntelligenceFailureCode::CitationInvalid
        }
        ReceiptIntelligenceProviderError::Protocol => {
            crate::ReceiptIntelligenceFailureCode::ProviderProtocol
        }
        _ => crate::ReceiptIntelligenceFailureCode::ProviderOutputInvalid,
    }
}

fn publication_failure_code(error: &PlatformError) -> crate::ReceiptIntelligenceFailureCode {
    match error {
        PlatformError::InvalidInput("receipt_intelligence_citation") => {
            crate::ReceiptIntelligenceFailureCode::CitationInvalid
        }
        PlatformError::InvalidInput("receipt_intelligence_provider_output")
        | PlatformError::InvalidInput("receipt_intelligence_order")
        | PlatformError::Conflict("receipt_intelligence_source_revision_changed")
        | PlatformError::Conflict("receipt_intelligence_parse_changed") => {
            crate::ReceiptIntelligenceFailureCode::ProviderOutputInvalid
        }
        _ => crate::ReceiptIntelligenceFailureCode::PersistenceFailed,
    }
}

fn retention_mode(mode: OpenAiRetentionModeV1) -> &'static str {
    match mode {
        OpenAiRetentionModeV1::Unknown => "unknown",
        OpenAiRetentionModeV1::Default => "default",
        OpenAiRetentionModeV1::Mam => "MAM",
        OpenAiRetentionModeV1::Zdr => "ZDR",
    }
}

fn ensure_retention_declaration_current(provenance: &str, now_ms: i64) -> PlatformResult<()> {
    let date = provenance
        .strip_prefix(RETENTION_DECLARATION_PREFIX)
        .ok_or(PlatformError::Conflict(
            "receipt_intelligence_retention_declaration_stale",
        ))?;
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(PlatformError::Conflict(
            "receipt_intelligence_retention_declaration_stale",
        ));
    }
    let parse = |range: std::ops::Range<usize>| -> PlatformResult<u16> {
        std::str::from_utf8(&bytes[range])
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or(PlatformError::Conflict(
                "receipt_intelligence_retention_declaration_stale",
            ))
    };
    let year = i32::from(parse(0..4)?);
    let month = u8::try_from(parse(5..7)?)
        .map_err(|_| PlatformError::Conflict("receipt_intelligence_retention_declaration_stale"))?;
    let day = u8::try_from(parse(8..10)?)
        .map_err(|_| PlatformError::Conflict("receipt_intelligence_retention_declaration_stale"))?;
    let declared = Date::from_calendar_date(
        year,
        Month::try_from(month).map_err(|_| {
            PlatformError::Conflict("receipt_intelligence_retention_declaration_stale")
        })?,
        day,
    )
    .map_err(|_| PlatformError::Conflict("receipt_intelligence_retention_declaration_stale"))?;
    let now = OffsetDateTime::from_unix_timestamp_nanos(i128::from(now_ms) * 1_000_000)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_timestamp"))?
        .date();
    let age = (now - declared).whole_days();
    if !(0..=RETENTION_DECLARATION_MAX_AGE_DAYS).contains(&age) {
        return Err(PlatformError::Conflict(
            "receipt_intelligence_retention_declaration_stale",
        ));
    }
    Ok(())
}

fn hash_json<T: serde::Serialize + ?Sized>(value: &T) -> PlatformResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn timestamp(value_ms: i64) -> PlatformResult<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value_ms) * 1_000_000)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_timestamp"))?
        .format(&Rfc3339)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_timestamp"))
}

fn parse_timestamp(value: &str) -> PlatformResult<i64> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_expiry"))?;
    i64::try_from(parsed.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_expiry"))
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

#[cfg(test)]
#[path = "receipt_intelligence_coordinator_tests.rs"]
mod tests;
