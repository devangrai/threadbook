use crate::database::stable_id;
use crate::{Database, PlatformError, PlatformResult};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;
use wardrobe_core::{
    ListReceiptIntelligenceV1Request, ListReceiptIntelligenceV1Response, PageCursorV1,
    ReceiptIntelligenceApprovalId, ReceiptIntelligenceAttemptId, ReceiptIntelligenceAuditId,
    ReceiptIntelligenceAuditV1, ReceiptIntelligenceAvailabilityReasonV1,
    ReceiptIntelligenceAvailabilityV1, ReceiptIntelligenceClassificationEvidenceV1,
    ReceiptIntelligenceClassificationId, ReceiptIntelligenceClassificationV1,
    ReceiptIntelligenceExecutionBoundsV1, ReceiptIntelligenceFailureCodeV1,
    ReceiptIntelligenceFailureV1, ReceiptIntelligenceOutcomeV1,
    ReceiptIntelligenceProviderParametersV1, ReceiptIntelligenceReasoningEffortV1,
    ReceiptIntelligenceReservationV1, ReceiptIntelligenceSourceRevisionId,
    ReceiptIntelligenceSummaryV1, ReceiptIntelligenceUsageV1, ReceiptIntelligenceUserActionV1,
    ReceiptOrderEvidenceId, ReplayStatusV1, RequestId, RequestReceiptIntelligenceV1Response,
    Sha256Digest, SourceId, Validate, RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1,
    SCHEMA_VERSION_V1,
};

const APPROVAL_LIFETIME_MS: i64 = 10 * 60 * 1_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ReceiptIntelligenceBounds {
    pub max_fragment_count: u32,
    pub max_fragment_bytes: u32,
    pub max_aggregate_text_bytes: u32,
    pub max_serialized_request_bytes: u32,
    pub max_request_bytes: u32,
    pub max_response_bytes: u32,
    pub max_output_tokens: u32,
    pub timeout_ms: u32,
    pub max_attempts: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReceiptIntelligencePreviewFragment {
    pub handle: String,
    pub visible_text: String,
    pub byte_length: u32,
    pub(crate) content_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReceiptIntelligencePreview {
    pub source_revision_id: String,
    pub local_source_id: String,
    pub parse_id: String,
    pub source_revision_sha256: String,
    pub fragments: Vec<ReceiptIntelligencePreviewFragment>,
    pub aggregate_text_bytes: u32,
    pub serialized_projection_bytes: u32,
    pub fragment_set_sha256: String,
    pub projection_sha256: String,
    pub preview_binding_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptIntelligencePreviewContext {
    pub source_revision_id: String,
    pub source_revision_sha256: String,
    pub credential_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReceiptIntelligenceConsentReservation {
    pub request_id: String,
    pub command_sha256: String,
    pub source_revision_id: String,
    pub source_revision_sha256: String,
    pub preview_binding_sha256: String,
    pub fragment_set_sha256: String,
    pub projection_sha256: String,
    pub serialized_request_sha256: String,
    pub serialized_request_bytes: u32,
    pub credential_id: String,
    pub provider: String,
    pub model: String,
    pub retention_mode: String,
    pub retention_provenance: String,
    pub prompt_revision: String,
    pub schema_revision: String,
    pub projection_revision: String,
    pub parameters_sha256: String,
    pub bounds: ReceiptIntelligenceBounds,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptIntelligenceAuditMetadata {
    pub response_sha256: Option<String>,
    pub provider_request_id: Option<String>,
    pub response_id: Option<String>,
    pub request_bytes: u32,
    pub response_bytes: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
    pub reasoning_tokens: u32,
    pub cached_input_tokens: u32,
    pub attempt_count: u8,
    pub dispatched_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptIntelligenceAttemptState {
    NotSent,
    Dispatched,
    Completed,
    Refused,
    Failed,
    OutcomeUnknown,
}

impl ReceiptIntelligenceAttemptState {
    fn parse(value: &str) -> PlatformResult<Self> {
        match value {
            "not_sent" => Ok(Self::NotSent),
            "dispatched" => Ok(Self::Dispatched),
            "completed" => Ok(Self::Completed),
            "refused" => Ok(Self::Refused),
            "failed" => Ok(Self::Failed),
            "outcome_unknown" => Ok(Self::OutcomeUnknown),
            _ => Err(PlatformError::Corrupt("receipt_intelligence_attempt_state")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptIntelligenceClassification {
    ApparelOrder,
    ApparelLifecycle,
    Unrelated,
    Ambiguous,
}

impl ReceiptIntelligenceClassification {
    fn as_db(self) -> &'static str {
        match self {
            Self::ApparelOrder => "apparel_order",
            Self::ApparelLifecycle => "apparel_lifecycle_update",
            Self::Unrelated => "unrelated",
            Self::Ambiguous => "ambiguous",
        }
    }

    fn parse(value: &str) -> PlatformResult<Self> {
        match value {
            "apparel_order" => Ok(Self::ApparelOrder),
            "apparel_lifecycle_update" => Ok(Self::ApparelLifecycle),
            "unrelated" => Ok(Self::Unrelated),
            "ambiguous" => Ok(Self::Ambiguous),
            _ => Err(PlatformError::Corrupt(
                "receipt_intelligence_classification",
            )),
        }
    }

    fn publishes_order(self) -> bool {
        matches!(self, Self::ApparelOrder | Self::ApparelLifecycle)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptIntelligenceFailureCode {
    ApprovalExpired,
    ApprovalConsumed,
    ConsentMismatch,
    BoundExceeded,
    LocalOnly,
    ReleaseEvidenceUnavailable,
    OutboundAuthorityUnavailable,
    CredentialUnavailable,
    RetentionDeclarationStale,
    SourceUnavailable,
    SourceRevisionChanged,
    ProviderAuthentication,
    ProviderRateLimited,
    ProviderUnavailable,
    ProviderProtocol,
    ProviderOutputInvalid,
    CitationInvalid,
    PersistenceFailed,
    Cancelled,
}

impl ReceiptIntelligenceFailureCode {
    fn as_db(self) -> &'static str {
        match self {
            Self::ApprovalExpired => "approval_expired",
            Self::ApprovalConsumed => "approval_consumed",
            Self::ConsentMismatch => "consent_mismatch",
            Self::BoundExceeded => "bound_exceeded",
            Self::LocalOnly => "local_only",
            Self::ReleaseEvidenceUnavailable => "release_evidence_unavailable",
            Self::OutboundAuthorityUnavailable => "outbound_authority_unavailable",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::RetentionDeclarationStale => "retention_declaration_stale",
            Self::SourceUnavailable => "source_unavailable",
            Self::SourceRevisionChanged => "source_revision_changed",
            Self::ProviderAuthentication => "provider_authentication",
            Self::ProviderRateLimited => "provider_rate_limited",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderProtocol => "provider_protocol",
            Self::ProviderOutputInvalid => "provider_output_invalid",
            Self::CitationInvalid => "citation_invalid",
            Self::PersistenceFailed => "persistence_failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedReceiptIntelligenceAttempt {
    pub approval_id: String,
    pub attempt_id: String,
    pub state: ReceiptIntelligenceAttemptState,
    pub replayed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptIntelligenceListEntry {
    pub approval_id: String,
    pub attempt_id: String,
    pub source_revision_id: String,
    pub local_source_id: String,
    pub state: ReceiptIntelligenceAttemptState,
    pub classification: Option<ReceiptIntelligenceClassification>,
    pub order_evidence_id: Option<String>,
    pub failure_code: Option<String>,
    pub audit: Option<ReceiptIntelligenceAuditRecord>,
    pub created_at_ms: i64,
    pub finalized_at_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptIntelligenceAuditRecord {
    pub audit_id: String,
    pub source_revision_sha256: String,
    pub projection_sha256: String,
    pub serialized_request_sha256: String,
    pub response_sha256: Option<String>,
    pub provider_request_id: Option<String>,
    pub response_id: Option<String>,
    pub request_bytes: u32,
    pub response_bytes: u32,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
    pub reasoning_tokens: u32,
    pub cached_input_tokens: u32,
    pub dispatched_at_ms: i64,
    pub finished_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptSourceAuthorityHead {
    pub local_source_id: String,
    pub authority_id: String,
    pub order_evidence_id: String,
    pub review_decision_id: String,
    pub receipt_revision: u64,
    pub authority_revision: u64,
}

impl Database {
    pub fn receipt_intelligence_preview_context(
        &self,
        local_source_id: &str,
    ) -> PlatformResult<ReceiptIntelligencePreviewContext> {
        validate_uuid(local_source_id, "receipt_intelligence_local_source_id")?;
        let connection = self.connection()?;
        let (source_revision_id, source_revision_sha256): (String, String) = connection
            .query_row(
                "SELECT revision.revision_id, revision.graph_sha256
                 FROM gmail_revision_materializations materialization
                 JOIN gmail_source_revisions revision
                   ON revision.revision_id = materialization.revision_id
                 JOIN local_sources source
                   ON source.source_id = materialization.local_source_id
                 WHERE materialization.local_source_id = ?1
                   AND materialization.blob_sha256 IS NOT NULL
                   AND revision.availability = 'available'
                   AND source.status = 'imported'
                 ORDER BY materialization.created_at_ms DESC, revision.revision_id DESC
                 LIMIT 1",
                [local_source_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(PlatformError::Conflict(
                "receipt_intelligence_source_unavailable",
            ))?;
        let credential_id: String = connection
            .query_row(
                "SELECT credential_id
                 FROM credential_references
                 WHERE provider = 'open_ai' AND status = 'active'
                 ORDER BY updated_at_ms DESC, credential_id DESC
                 LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(PlatformError::Conflict(
                "receipt_intelligence_credential_unavailable",
            ))?;
        Ok(ReceiptIntelligencePreviewContext {
            source_revision_id,
            source_revision_sha256,
            credential_id,
        })
    }

    pub fn preview_receipt_intelligence(
        &self,
        request_id: &str,
        source_revision_id: &str,
        bounds: ReceiptIntelligenceBounds,
    ) -> PlatformResult<ReceiptIntelligencePreview> {
        validate_uuid(request_id, "receipt_intelligence_request_id")?;
        validate_uuid(
            source_revision_id,
            "receipt_intelligence_source_revision_id",
        )?;
        validate_bounds(bounds)?;
        let connection = self.connection()?;
        read_preview(&connection, request_id, source_revision_id, bounds)
    }

    pub fn reserve_receipt_intelligence(
        &self,
        reservation: &ReceiptIntelligenceConsentReservation,
        now_ms: i64,
    ) -> PlatformResult<ReservedReceiptIntelligenceAttempt> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(existing) = replay_reservation(
            &transaction,
            &reservation.request_id,
            &reservation.command_sha256,
        )? {
            transaction.commit()?;
            return Ok(existing);
        }
        validate_reservation(reservation, now_ms)?;

        let preview = read_preview(
            &transaction,
            &reservation.request_id,
            &reservation.source_revision_id,
            reservation.bounds,
        )?;
        if preview.preview_binding_sha256 != reservation.preview_binding_sha256
            || preview.fragment_set_sha256 != reservation.fragment_set_sha256
            || preview.source_revision_sha256 != reservation.source_revision_sha256
            || preview.projection_sha256 != reservation.projection_sha256
        {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_preview_changed",
            ));
        }
        require_active_credential(&transaction, &reservation.credential_id)?;

        let approval_id = stable_id("receipt-intelligence-approval", &reservation.request_id);
        let attempt_id = stable_id("receipt-intelligence-attempt", &reservation.request_id);
        transaction.execute(
            "INSERT INTO receipt_intelligence_approvals(
                approval_id, request_id, envelope_sha256,
                preview_binding_sha256, source_revision_id, local_source_id,
                source_revision_sha256, fragment_set_sha256, projection_sha256,
                serialized_request_sha256, serialized_request_bytes,
                credential_id, provider, model,
                retention_mode, retention_provenance, prompt_revision,
                schema_revision, projection_revision, parameters_sha256,
                max_fragment_count, max_fragment_bytes,
                max_aggregate_text_bytes, max_serialized_request_bytes,
                max_request_bytes,
                max_response_bytes, max_output_tokens, timeout_ms, max_attempts,
                expires_at_ms, consumed_request_id, consumed_at_ms, created_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23,
                ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?2, ?31, ?31
             )",
            params![
                approval_id,
                reservation.request_id,
                reservation.command_sha256,
                reservation.preview_binding_sha256,
                reservation.source_revision_id,
                preview.local_source_id,
                reservation.source_revision_sha256,
                reservation.fragment_set_sha256,
                reservation.projection_sha256,
                reservation.serialized_request_sha256,
                i64::from(reservation.serialized_request_bytes),
                reservation.credential_id,
                reservation.provider,
                reservation.model,
                reservation.retention_mode,
                reservation.retention_provenance,
                reservation.prompt_revision,
                reservation.schema_revision,
                reservation.projection_revision,
                reservation.parameters_sha256,
                i64::from(reservation.bounds.max_fragment_count),
                i64::from(reservation.bounds.max_fragment_bytes),
                i64::from(reservation.bounds.max_aggregate_text_bytes),
                i64::from(reservation.bounds.max_serialized_request_bytes),
                i64::from(reservation.bounds.max_request_bytes),
                i64::from(reservation.bounds.max_response_bytes),
                i64::from(reservation.bounds.max_output_tokens),
                i64::from(reservation.bounds.timeout_ms),
                i64::from(reservation.bounds.max_attempts),
                reservation.expires_at_ms,
                now_ms,
            ],
        )?;
        transaction.execute(
            "INSERT INTO receipt_intelligence_attempts(
                attempt_id, request_id, approval_id, envelope_sha256,
                source_revision_id, local_source_id, state, failure_code,
                input_tokens, output_tokens, attempt_count, created_at_ms,
                dispatched_at_ms, finalized_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, 'not_sent', NULL,
                NULL, NULL, 1, ?7, NULL, NULL
             )",
            params![
                attempt_id,
                reservation.request_id,
                approval_id,
                reservation.command_sha256,
                reservation.source_revision_id,
                preview.local_source_id,
                now_ms,
            ],
        )?;
        advance_receipt_intelligence_revision(&transaction)?;
        transaction.commit()?;
        Ok(ReservedReceiptIntelligenceAttempt {
            approval_id,
            attempt_id,
            state: ReceiptIntelligenceAttemptState::NotSent,
            replayed: false,
        })
    }

    pub fn preflight_receipt_intelligence_replay(
        &self,
        request_id: &str,
        command_sha256: &str,
    ) -> PlatformResult<Option<ReservedReceiptIntelligenceAttempt>> {
        validate_uuid(request_id, "receipt_intelligence_request_id")?;
        validate_hash(command_sha256, "receipt_intelligence_command_sha256")?;
        let connection = self.connection()?;
        replay_reservation(&connection, request_id, command_sha256)
    }

    pub fn receipt_intelligence_credential_locator(
        &self,
        attempt_id: &str,
        now_ms: i64,
    ) -> PlatformResult<String> {
        validate_uuid(attempt_id, "receipt_intelligence_attempt_id")?;
        let connection = self.connection()?;
        let context = connection
            .query_row(
                "SELECT attempt.state, approval.expires_at_ms,
                        credential.locator, credential.provider, credential.status
                 FROM receipt_intelligence_attempts attempt
                 JOIN receipt_intelligence_approvals approval
                   ON approval.approval_id = attempt.approval_id
                 LEFT JOIN credential_references credential
                   ON credential.credential_id = approval.credential_id
                 WHERE attempt.attempt_id = ?1",
                [attempt_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::Conflict(
                "receipt_intelligence_credential_unavailable",
            ))?;
        if context.0 != "not_sent" {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_attempt_already_authorized",
            ));
        }
        if context.1 < now_ms {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_approval_expired",
            ));
        }
        match (context.2, context.3.as_deref(), context.4.as_deref()) {
            (Some(locator), Some("open_ai"), Some("active")) => Ok(locator),
            _ => Err(PlatformError::Conflict(
                "receipt_intelligence_credential_unavailable",
            )),
        }
    }

    pub fn mark_receipt_intelligence_dispatched(
        &self,
        attempt_id: &str,
        now_ms: i64,
    ) -> PlatformResult<()> {
        validate_uuid(attempt_id, "receipt_intelligence_attempt_id")?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, expires_at_ms, credential_active): (String, i64, bool) = transaction
            .query_row(
                "SELECT attempt.state, approval.expires_at_ms, EXISTS(
                    SELECT 1
                    FROM credential_references credential
                    WHERE credential.credential_id = approval.credential_id
                      AND credential.provider = 'open_ai'
                      AND credential.status = 'active'
                 )
                 FROM receipt_intelligence_attempts attempt
                 JOIN receipt_intelligence_approvals approval
                   ON approval.approval_id = attempt.approval_id
                 WHERE attempt.attempt_id = ?1",
                [attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput(
                "receipt_intelligence_attempt_id",
            ))?;
        if state != "not_sent" {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_attempt_already_authorized",
            ));
        }
        if expires_at_ms < now_ms {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_approval_expired",
            ));
        }
        if !credential_active {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_credential_unavailable",
            ));
        }
        let changed = transaction.execute(
            "UPDATE receipt_intelligence_attempts
             SET state = 'dispatched', dispatched_at_ms = ?2
             WHERE attempt_id = ?1 AND state = 'not_sent'",
            params![attempt_id, now_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_attempt_already_authorized",
            ));
        }
        advance_receipt_intelligence_revision(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn fail_receipt_intelligence(
        &self,
        attempt_id: &str,
        code: ReceiptIntelligenceFailureCode,
        now_ms: i64,
    ) -> PlatformResult<()> {
        validate_uuid(attempt_id, "receipt_intelligence_attempt_id")?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE receipt_intelligence_attempts
             SET state = 'failed', failure_code = ?2, finalized_at_ms = ?3
             WHERE attempt_id = ?1 AND state IN ('not_sent', 'dispatched')",
            params![attempt_id, code.as_db(), now_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_attempt_terminal",
            ));
        }
        advance_receipt_intelligence_revision(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn refuse_receipt_intelligence(
        &self,
        attempt_id: &str,
        audit: &ReceiptIntelligenceAuditMetadata,
        now_ms: i64,
    ) -> PlatformResult<()> {
        finalize_dispatched(self, attempt_id, "refused", "refused", audit, now_ms)
    }

    pub fn mark_receipt_intelligence_outcome_unknown(
        &self,
        attempt_id: &str,
        now_ms: i64,
    ) -> PlatformResult<()> {
        validate_uuid(attempt_id, "receipt_intelligence_attempt_id")?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE receipt_intelligence_attempts
             SET state = 'outcome_unknown', failure_code = 'outcome_unknown',
                 finalized_at_ms = ?2
             WHERE attempt_id = ?1 AND state = 'dispatched'",
            params![attempt_id, now_ms],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_attempt_not_dispatched",
            ));
        }
        advance_receipt_intelligence_revision(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn complete_receipt_intelligence_without_order(
        &self,
        attempt_id: &str,
        classification: ReceiptIntelligenceClassification,
        audit: &ReceiptIntelligenceAuditMetadata,
        now_ms: i64,
    ) -> PlatformResult<()> {
        if classification.publishes_order() {
            return Err(PlatformError::InvalidInput(
                "receipt_intelligence_classification",
            ));
        }
        self.complete_receipt_intelligence_with_publication(
            attempt_id,
            classification,
            audit,
            now_ms,
            |_| Ok(None),
        )
    }

    pub(crate) fn complete_receipt_intelligence_with_publication<F>(
        &self,
        attempt_id: &str,
        classification: ReceiptIntelligenceClassification,
        audit: &ReceiptIntelligenceAuditMetadata,
        now_ms: i64,
        publish: F,
    ) -> PlatformResult<()>
    where
        F: FnOnce(&Transaction<'_>) -> PlatformResult<Option<String>>,
    {
        validate_uuid(attempt_id, "receipt_intelligence_attempt_id")?;
        validate_audit_metadata(audit, now_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, source_revision_id, local_source_id): (String, String, String) = transaction
            .query_row(
                "SELECT state, source_revision_id, local_source_id
                 FROM receipt_intelligence_attempts WHERE attempt_id = ?1",
                [attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput(
                "receipt_intelligence_attempt_id",
            ))?;
        if state != "dispatched" {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_attempt_not_dispatched",
            ));
        }
        ensure_approved_preview_is_current(&transaction, attempt_id)?;

        let authority_before = authority_snapshot(&transaction, &local_source_id)?;
        let catalog_revision_before: i64 = transaction.query_row(
            "SELECT catalog_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let review_count_before = source_review_count(&transaction, &local_source_id)?;
        let order_evidence_id = publish(&transaction)?;
        if classification.publishes_order() != order_evidence_id.is_some() {
            return Err(PlatformError::InvalidInput(
                "receipt_intelligence_publication",
            ));
        }
        if let Some(order_id) = &order_evidence_id {
            validate_uuid(order_id, "receipt_intelligence_order_evidence_id")?;
            let belongs_to_source: bool = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1
                    FROM receipt_orders receipt_order
                    JOIN receipt_extraction_runs run
                      ON run.run_id = receipt_order.run_id
                    JOIN receipt_parses parse ON parse.parse_id = run.parse_id
                    WHERE receipt_order.order_evidence_id = ?1
                      AND parse.source_id = ?2
                 )",
                params![order_id, local_source_id],
                |row| row.get(0),
            )?;
            if !belongs_to_source {
                return Err(PlatformError::Conflict(
                    "receipt_intelligence_order_source_changed",
                ));
            }
        }
        if authority_snapshot(&transaction, &local_source_id)? != authority_before
            || source_review_count(&transaction, &local_source_id)? != review_count_before
            || transaction.query_row(
                "SELECT catalog_revision FROM revision_state WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0),
            )? != catalog_revision_before
        {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_publication_authority",
            ));
        }

        insert_audit(&transaction, attempt_id, audit, now_ms)?;
        let classification_id = stable_id("receipt-intelligence-classification", attempt_id);
        transaction.execute(
            "INSERT INTO receipt_intelligence_classifications(
                classification_id, attempt_id, source_revision_id,
                local_source_id, classification, order_evidence_id, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                classification_id,
                attempt_id,
                source_revision_id,
                local_source_id,
                classification.as_db(),
                order_evidence_id,
                now_ms,
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE receipt_intelligence_attempts
             SET state = 'completed', input_tokens = ?2, output_tokens = ?3,
                 finalized_at_ms = ?4
             WHERE attempt_id = ?1 AND state = 'dispatched'",
            params![
                attempt_id,
                i64::from(audit.input_tokens),
                i64::from(audit.output_tokens),
                now_ms
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict(
                "receipt_intelligence_attempt_not_dispatched",
            ));
        }
        advance_receipt_intelligence_revision(&transaction)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn recover_receipt_intelligence_attempts(
        &self,
        now_ms: i64,
    ) -> PlatformResult<Vec<String>> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let recovered = transaction.execute(
            "UPDATE receipt_intelligence_attempts
             SET state = 'outcome_unknown', failure_code = 'outcome_unknown',
                 finalized_at_ms = ?1
             WHERE state = 'dispatched'",
            [now_ms],
        )?;
        let mut statement = transaction.prepare(
            "SELECT attempt_id
             FROM receipt_intelligence_attempts
             WHERE state = 'not_sent'
             ORDER BY created_at_ms, attempt_id",
        )?;
        let resumable = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if recovered > 0 {
            advance_receipt_intelligence_revision(&transaction)?;
        }
        transaction.commit()?;
        Ok(resumable)
    }

    pub fn list_receipt_intelligence(
        &self,
        before: Option<(i64, &str)>,
        limit: usize,
    ) -> PlatformResult<Vec<ReceiptIntelligenceListEntry>> {
        if limit == 0 || limit > 100 {
            return Err(PlatformError::InvalidInput(
                "receipt_intelligence_list_limit",
            ));
        }
        if let Some((_, attempt_id)) = before {
            validate_uuid(attempt_id, "receipt_intelligence_list_cursor")?;
        }
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT
                attempt.approval_id, attempt.attempt_id, attempt.source_revision_id,
                attempt.local_source_id, attempt.state,
                classification.classification,
                classification.order_evidence_id, attempt.failure_code,
                attempt.created_at_ms, attempt.finalized_at_ms
             FROM receipt_intelligence_attempts attempt
             LEFT JOIN receipt_intelligence_classifications classification
               ON classification.attempt_id = attempt.attempt_id
             WHERE (
                ?1 IS NULL
                OR attempt.created_at_ms < ?1
                OR (attempt.created_at_ms = ?1 AND attempt.attempt_id < ?2)
             )
             ORDER BY attempt.created_at_ms DESC, attempt.attempt_id DESC
             LIMIT ?3",
        )?;
        let (before_ms, before_id) = before
            .map(|(created_at_ms, attempt_id)| (Some(created_at_ms), attempt_id))
            .unwrap_or((None, ""));
        let rows = statement
            .query_map(
                params![before_ms, before_id, i64::try_from(limit).unwrap_or(100)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        rows.into_iter()
            .map(
                |(
                    approval_id,
                    attempt_id,
                    source_revision_id,
                    local_source_id,
                    state,
                    classification,
                    order_evidence_id,
                    failure_code,
                    created_at_ms,
                    finalized_at_ms,
                )| {
                    let audit = load_audit(&connection, &attempt_id)?;
                    Ok(ReceiptIntelligenceListEntry {
                        approval_id,
                        attempt_id,
                        source_revision_id,
                        local_source_id,
                        state: ReceiptIntelligenceAttemptState::parse(&state)?,
                        classification: classification
                            .as_deref()
                            .map(ReceiptIntelligenceClassification::parse)
                            .transpose()?,
                        order_evidence_id,
                        failure_code,
                        audit,
                        created_at_ms,
                        finalized_at_ms,
                    })
                },
            )
            .collect()
    }

    pub fn list_receipt_intelligence_response(
        &self,
        request: &ListReceiptIntelligenceV1Request,
    ) -> PlatformResult<ListReceiptIntelligenceV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_list"))?;
        let before = request
            .cursor
            .as_ref()
            .map(|cursor| parse_list_cursor(cursor.as_str()))
            .transpose()?;
        let connection = self.connection()?;
        let credential_available: bool = connection.query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM credential_references
                WHERE provider = 'open_ai' AND status = 'active'
            )",
            [],
            |row| row.get(0),
        )?;
        let state_filter = request.state.map(attempt_state_db);
        let classification_filter = request.classification.map(classification_db);
        let total_count: i64 = connection.query_row(
            "SELECT COUNT(*)
             FROM receipt_intelligence_attempts attempt
             LEFT JOIN receipt_intelligence_classifications classification
               ON classification.attempt_id = attempt.attempt_id
             WHERE (?1 IS NULL OR attempt.state = ?1)
               AND (?2 IS NULL OR classification.classification = ?2)",
            params![state_filter, classification_filter],
            |row| row.get(0),
        )?;
        let mut statement = connection.prepare(
            "SELECT attempt.approval_id, attempt.attempt_id,
                    attempt.source_revision_id, attempt.local_source_id,
                    attempt.created_at_ms, attempt.finalized_at_ms
             FROM receipt_intelligence_attempts attempt
             LEFT JOIN receipt_intelligence_classifications classification
               ON classification.attempt_id = attempt.attempt_id
             WHERE (?1 IS NULL OR attempt.state = ?1)
               AND (?2 IS NULL OR classification.classification = ?2)
               AND (
                    ?3 IS NULL
                    OR attempt.created_at_ms < ?3
                    OR (attempt.created_at_ms = ?3 AND attempt.attempt_id < ?4)
               )
             ORDER BY attempt.created_at_ms DESC, attempt.attempt_id DESC
             LIMIT ?5",
        )?;
        let (before_ms, before_id) = before
            .as_ref()
            .map(|(created_at_ms, attempt_id)| (Some(*created_at_ms), attempt_id.as_str()))
            .unwrap_or((None, ""));
        let rows = statement
            .query_map(
                params![
                    state_filter,
                    classification_filter,
                    before_ms,
                    before_id,
                    i64::from(request.limit) + 1,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let has_more = rows.len() > usize::from(request.limit);
        let visible = rows
            .into_iter()
            .take(usize::from(request.limit))
            .collect::<Vec<_>>();
        let mut attempts = Vec::with_capacity(visible.len());
        for (
            approval_id,
            attempt_id_text,
            source_revision_id_text,
            source_id_text,
            created_at_ms,
            finalized_at_ms,
        ) in &visible
        {
            let response =
                self.receipt_intelligence_response(request.request_id, attempt_id_text, false)?;
            let attempt_id = parse_attempt_id(attempt_id_text)?;
            let source_id = parse_source_id(source_id_text)?;
            let source_revision_id = parse_source_revision_id(source_revision_id_text)?;
            let (state, classification, failure, audit) = match response.outcome {
                ReceiptIntelligenceOutcomeV1::Reserved { .. } => (
                    wardrobe_core::ReceiptIntelligenceAttemptStateV1::NotSent,
                    None,
                    None,
                    None,
                ),
                ReceiptIntelligenceOutcomeV1::Dispatched { .. } => (
                    wardrobe_core::ReceiptIntelligenceAttemptStateV1::Dispatched,
                    None,
                    None,
                    None,
                ),
                ReceiptIntelligenceOutcomeV1::Completed {
                    classification,
                    audit,
                } => (
                    wardrobe_core::ReceiptIntelligenceAttemptStateV1::Completed,
                    Some(classification),
                    None,
                    Some(audit),
                ),
                ReceiptIntelligenceOutcomeV1::Refused { audit, .. } => (
                    wardrobe_core::ReceiptIntelligenceAttemptStateV1::Refused,
                    None,
                    None,
                    Some(audit),
                ),
                ReceiptIntelligenceOutcomeV1::Failed { failure, audit, .. } => (
                    wardrobe_core::ReceiptIntelligenceAttemptStateV1::Failed,
                    None,
                    Some(failure),
                    audit,
                ),
                ReceiptIntelligenceOutcomeV1::OutcomeUnknown { audit, .. } => (
                    wardrobe_core::ReceiptIntelligenceAttemptStateV1::OutcomeUnknown,
                    None,
                    None,
                    audit,
                ),
            };
            attempts.push(ReceiptIntelligenceSummaryV1 {
                attempt_id,
                approval_id: parse_approval_id(approval_id)?,
                source_id,
                source_revision_id,
                state,
                classification,
                failure,
                audit,
                created_at: timestamp_from_ms(*created_at_ms)?,
                updated_at: timestamp_from_ms(finalized_at_ms.unwrap_or(*created_at_ms))?,
            });
        }
        let next_cursor = if has_more {
            visible
                .last()
                .map(|(_, attempt_id, _, _, created_at_ms, _)| {
                    PageCursorV1::new(format!("{created_at_ms}:{attempt_id}"))
                        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_cursor"))
                })
                .transpose()?
        } else {
            None
        };
        let revision: i64 = connection.query_row(
            "SELECT receipt_intelligence_revision
             FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let response = ListReceiptIntelligenceV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            availability: ReceiptIntelligenceAvailabilityV1 {
                available: credential_available,
                reason: (!credential_available)
                    .then_some(ReceiptIntelligenceAvailabilityReasonV1::CredentialUnavailable),
                offline_receipt_analysis_available: true,
                existing_wardrobe_access_available: true,
            },
            attempts,
            total_count: u64::try_from(total_count)
                .map_err(|_| PlatformError::Corrupt("receipt_intelligence_total"))?,
            receipt_intelligence_revision: u64::try_from(revision)
                .map_err(|_| PlatformError::Corrupt("receipt_intelligence_revision"))?,
            next_cursor,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_list_response"))?;
        Ok(response)
    }

    pub fn receipt_source_authority_head(
        &self,
        local_source_id: &str,
    ) -> PlatformResult<Option<ReceiptSourceAuthorityHead>> {
        validate_uuid(local_source_id, "receipt_intelligence_local_source_id")?;
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT authority_id, order_evidence_id, review_decision_id,
                        receipt_revision, authority_revision
                 FROM receipt_source_authority_heads
                 WHERE local_source_id = ?1",
                [local_source_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(
                    authority_id,
                    order_evidence_id,
                    review_decision_id,
                    receipt_revision,
                    authority_revision,
                )| {
                    Ok(ReceiptSourceAuthorityHead {
                        local_source_id: local_source_id.to_owned(),
                        authority_id,
                        order_evidence_id,
                        review_decision_id,
                        receipt_revision: u64::try_from(receipt_revision).map_err(|_| {
                            PlatformError::Corrupt("receipt_source_authority_revision")
                        })?,
                        authority_revision: u64::try_from(authority_revision).map_err(|_| {
                            PlatformError::Corrupt("receipt_source_authority_revision")
                        })?,
                    })
                },
            )
            .transpose()
    }

    pub fn receipt_intelligence_response(
        &self,
        request_id: RequestId,
        attempt_id: &str,
        replayed: bool,
    ) -> PlatformResult<RequestReceiptIntelligenceV1Response> {
        validate_uuid(attempt_id, "receipt_intelligence_attempt_id")?;
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT
                    attempt.approval_id, attempt.source_revision_id,
                    attempt.local_source_id, attempt.state, attempt.failure_code,
                    attempt.created_at_ms, attempt.dispatched_at_ms,
                    attempt.finalized_at_ms,
                    approval.created_at_ms, approval.consumed_at_ms,
                    approval.expires_at_ms,
                    classification.classification_id,
                    classification.classification,
                    classification.order_evidence_id,
                    classification.created_at_ms
                 FROM receipt_intelligence_attempts attempt
                 JOIN receipt_intelligence_approvals approval
                   ON approval.approval_id = attempt.approval_id
                 LEFT JOIN receipt_intelligence_classifications classification
                   ON classification.attempt_id = attempt.attempt_id
                 WHERE attempt.attempt_id = ?1",
                [attempt_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<String>>(13)?,
                        row.get::<_, Option<i64>>(14)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput(
                "receipt_intelligence_attempt_id",
            ))?;
        let (
            approval_id,
            source_revision_id,
            local_source_id,
            state,
            failure_code,
            created_at_ms,
            dispatched_at_ms,
            finalized_at_ms,
            approval_created_at_ms,
            approval_consumed_at_ms,
            expires_at_ms,
            classification_id,
            classification,
            order_evidence_id,
            classification_created_at_ms,
        ) = row;
        let attempt_id = parse_attempt_id(attempt_id)?;
        let approval_id = parse_approval_id(&approval_id)?;
        let source_revision_id = parse_source_revision_id(&source_revision_id)?;
        let source_id = parse_source_id(&local_source_id)?;
        let audit = load_core_audit(&connection, attempt_id, source_id, source_revision_id)?;
        let outcome = match ReceiptIntelligenceAttemptState::parse(&state)? {
            ReceiptIntelligenceAttemptState::NotSent => ReceiptIntelligenceOutcomeV1::Reserved {
                reservation: ReceiptIntelligenceReservationV1 {
                    approval_id,
                    attempt_id,
                    source_id,
                    source_revision_id,
                    state: wardrobe_core::ReceiptIntelligenceAttemptStateV1::NotSent,
                    single_use: true,
                    approval_created_at: timestamp_from_ms(approval_created_at_ms)?,
                    approval_consumed_at: timestamp_from_ms(approval_consumed_at_ms)?,
                    expires_at: timestamp_from_ms(expires_at_ms)?,
                },
            },
            ReceiptIntelligenceAttemptState::Dispatched => {
                ReceiptIntelligenceOutcomeV1::Dispatched {
                    attempt_id,
                    dispatched_at: timestamp_from_ms(
                        dispatched_at_ms
                            .ok_or(PlatformError::Corrupt("receipt_intelligence_dispatched_at"))?,
                    )?,
                }
            }
            ReceiptIntelligenceAttemptState::Completed => {
                let classification = ReceiptIntelligenceClassificationEvidenceV1 {
                    classification_id: parse_classification_id(
                        classification_id.as_deref().ok_or(PlatformError::Corrupt(
                            "receipt_intelligence_classification_id",
                        ))?,
                    )?,
                    attempt_id,
                    source_id,
                    source_revision_id,
                    classification: core_classification(classification.as_deref().ok_or(
                        PlatformError::Corrupt("receipt_intelligence_classification"),
                    )?)?,
                    order_evidence_id: order_evidence_id
                        .as_deref()
                        .map(parse_order_id)
                        .transpose()?,
                    created_at: timestamp_from_ms(classification_created_at_ms.ok_or(
                        PlatformError::Corrupt("receipt_intelligence_classification_timestamp"),
                    )?)?,
                };
                ReceiptIntelligenceOutcomeV1::Completed {
                    classification,
                    audit: audit
                        .ok_or(PlatformError::Corrupt("receipt_intelligence_audit_missing"))?,
                }
            }
            ReceiptIntelligenceAttemptState::Refused => ReceiptIntelligenceOutcomeV1::Refused {
                attempt_id,
                audit: audit.ok_or(PlatformError::Corrupt("receipt_intelligence_audit_missing"))?,
            },
            ReceiptIntelligenceAttemptState::Failed => ReceiptIntelligenceOutcomeV1::Failed {
                attempt_id,
                failure: core_failure(
                    failure_code
                        .as_deref()
                        .ok_or(PlatformError::Corrupt("receipt_intelligence_failure_code"))?,
                )?,
                audit,
            },
            ReceiptIntelligenceAttemptState::OutcomeUnknown => {
                ReceiptIntelligenceOutcomeV1::OutcomeUnknown { attempt_id, audit }
            }
        };
        let response = RequestReceiptIntelligenceV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id,
            outcome,
            replay_status: if replayed {
                ReplayStatusV1::Replayed
            } else {
                ReplayStatusV1::Created
            },
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_response"))?;
        let _ = (created_at_ms, finalized_at_ms);
        Ok(response)
    }
}

fn load_core_audit(
    connection: &rusqlite::Connection,
    attempt_id: ReceiptIntelligenceAttemptId,
    source_id: SourceId,
    source_revision_id: ReceiptIntelligenceSourceRevisionId,
) -> PlatformResult<Option<ReceiptIntelligenceAuditV1>> {
    let row = connection
        .query_row(
            "SELECT
                audit.audit_id, audit.source_revision_sha256,
                audit.projection_sha256, audit.serialized_request_sha256,
                audit.response_sha256, audit.provider, audit.model,
                audit.provider_request_id, audit.response_id,
                audit.prompt_revision, audit.schema_revision,
                audit.projection_revision, audit.retention_provenance,
                approval.max_request_bytes, approval.max_response_bytes,
                approval.max_output_tokens, approval.timeout_ms,
                approval.max_attempts,
                audit.request_bytes, audit.response_bytes,
                audit.input_tokens, audit.output_tokens, audit.total_tokens,
                audit.reasoning_tokens, audit.cached_input_tokens,
                audit.attempt_count, audit.dispatched_at_ms,
                audit.finished_at_ms
             FROM receipt_intelligence_audits audit
             JOIN receipt_intelligence_attempts attempt
               ON attempt.attempt_id = audit.attempt_id
             JOIN receipt_intelligence_approvals approval
               ON approval.approval_id = attempt.approval_id
             WHERE audit.attempt_id = ?1",
            [attempt_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                    row.get::<_, i64>(17)?,
                    row.get::<_, i64>(18)?,
                    row.get::<_, i64>(19)?,
                    row.get::<_, i64>(20)?,
                    row.get::<_, i64>(21)?,
                    row.get::<_, i64>(22)?,
                    row.get::<_, i64>(23)?,
                    row.get::<_, i64>(24)?,
                    row.get::<_, i64>(25)?,
                    row.get::<_, i64>(26)?,
                    row.get::<_, i64>(27)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            audit_id,
            source_revision_sha256,
            projection_sha256,
            serialized_request_sha256,
            response_sha256,
            provider,
            model,
            provider_request_id,
            response_id,
            prompt_revision,
            schema_revision,
            projection_revision,
            retention_provenance,
            max_request_bytes,
            max_response_bytes,
            max_output_tokens,
            timeout_ms,
            max_attempts,
            request_bytes,
            response_bytes,
            input_tokens,
            output_tokens,
            total_tokens,
            reasoning_tokens,
            cached_input_tokens,
            attempt_count,
            dispatched_at_ms,
            finished_at_ms,
        )| {
            let execution_bounds = ReceiptIntelligenceExecutionBoundsV1 {
                max_request_bytes: bounded_u32(
                    max_request_bytes,
                    "receipt_intelligence_max_request_bytes",
                )?,
                max_response_bytes: bounded_u32(
                    max_response_bytes,
                    "receipt_intelligence_max_response_bytes",
                )?,
                max_output_tokens: bounded_u32(
                    max_output_tokens,
                    "receipt_intelligence_max_output_tokens",
                )?,
                timeout_millis: bounded_u32(timeout_ms, "receipt_intelligence_timeout")?,
                max_attempts: u8::try_from(max_attempts)
                    .map_err(|_| PlatformError::Corrupt("receipt_intelligence_attempts"))?,
            };
            Ok(ReceiptIntelligenceAuditV1 {
                audit_id: parse_audit_id(&audit_id)?,
                attempt_id,
                source_id,
                source_revision_id,
                source_revision_sha256: parse_sha256(&source_revision_sha256)?,
                projection_sha256: parse_sha256(&projection_sha256)?,
                serialized_request_sha256: parse_sha256(&serialized_request_sha256)?,
                response_sha256: response_sha256.as_deref().map(parse_sha256).transpose()?,
                provider,
                model,
                provider_request_id,
                response_id,
                prompt_revision,
                schema_revision,
                projection_revision,
                retention_provenance,
                parameters: ReceiptIntelligenceProviderParametersV1 {
                    revision: RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1.to_owned(),
                    store: false,
                    background: false,
                    tools_enabled: false,
                    previous_response_id_present: false,
                    strict_schema: true,
                    reasoning_effort: ReceiptIntelligenceReasoningEffortV1::Low,
                    max_output_tokens: execution_bounds.max_output_tokens,
                    timeout_millis: execution_bounds.timeout_millis,
                    max_attempts: execution_bounds.max_attempts,
                },
                execution_bounds,
                usage: ReceiptIntelligenceUsageV1 {
                    request_bytes: bounded_u32(
                        request_bytes,
                        "receipt_intelligence_request_bytes",
                    )?,
                    response_bytes: bounded_u32(
                        response_bytes,
                        "receipt_intelligence_response_bytes",
                    )?,
                    input_tokens: bounded_u32(input_tokens, "receipt_intelligence_input_tokens")?,
                    output_tokens: bounded_u32(
                        output_tokens,
                        "receipt_intelligence_output_tokens",
                    )?,
                    total_tokens: bounded_u32(total_tokens, "receipt_intelligence_total_tokens")?,
                    reasoning_tokens: bounded_u32(
                        reasoning_tokens,
                        "receipt_intelligence_reasoning_tokens",
                    )?,
                    cached_input_tokens: bounded_u32(
                        cached_input_tokens,
                        "receipt_intelligence_cached_input_tokens",
                    )?,
                    attempts: u8::try_from(attempt_count)
                        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_attempts"))?,
                },
                dispatched_at: timestamp_from_ms(dispatched_at_ms)?,
                finished_at: timestamp_from_ms(finished_at_ms)?,
            })
        },
    )
    .transpose()
}

fn core_classification(value: &str) -> PlatformResult<ReceiptIntelligenceClassificationV1> {
    match ReceiptIntelligenceClassification::parse(value)? {
        ReceiptIntelligenceClassification::ApparelOrder => {
            Ok(ReceiptIntelligenceClassificationV1::ApparelOrder)
        }
        ReceiptIntelligenceClassification::ApparelLifecycle => {
            Ok(ReceiptIntelligenceClassificationV1::ApparelLifecycleUpdate)
        }
        ReceiptIntelligenceClassification::Unrelated => {
            Ok(ReceiptIntelligenceClassificationV1::Unrelated)
        }
        ReceiptIntelligenceClassification::Ambiguous => {
            Ok(ReceiptIntelligenceClassificationV1::Ambiguous)
        }
    }
}

fn core_failure(value: &str) -> PlatformResult<ReceiptIntelligenceFailureV1> {
    use ReceiptIntelligenceFailureCodeV1 as Code;
    use ReceiptIntelligenceUserActionV1 as Action;
    let (code, user_action) = match value {
        "approval_expired" => (Code::ApprovalExpired, Action::StartNewPreview),
        "approval_consumed" => (Code::ApprovalConsumed, Action::StartNewPreview),
        "consent_mismatch" => (Code::ConsentMismatch, Action::StartNewPreview),
        "bound_exceeded" => (Code::BoundExceeded, Action::ReviewSource),
        "local_only" => (Code::LocalOnly, Action::RetryWhenAvailable),
        "release_evidence_unavailable" => {
            (Code::ReleaseEvidenceUnavailable, Action::RetryWhenAvailable)
        }
        "outbound_authority_unavailable" => (
            Code::OutboundAuthorityUnavailable,
            Action::RetryWhenAvailable,
        ),
        "credential_unavailable" => (Code::CredentialUnavailable, Action::CheckOpenAiCredential),
        "retention_declaration_stale" => (
            Code::RetentionDeclarationStale,
            Action::ReviewRetentionSettings,
        ),
        "source_unavailable" => (Code::SourceUnavailable, Action::ReviewSource),
        "source_revision_changed" => (Code::SourceRevisionChanged, Action::StartNewPreview),
        "provider_authentication" => (Code::ProviderAuthentication, Action::CheckOpenAiCredential),
        "provider_rate_limited" => (Code::ProviderRateLimited, Action::RetryWhenAvailable),
        "provider_unavailable" => (Code::ProviderUnavailable, Action::RetryWhenAvailable),
        "provider_protocol" => (Code::ProviderProtocol, Action::ReviewProviderStatus),
        "provider_output_invalid" => (Code::ProviderOutputInvalid, Action::ReviewProviderStatus),
        "citation_invalid" => (Code::CitationInvalid, Action::ReviewProviderStatus),
        "persistence_failed" => (Code::PersistenceFailed, Action::RetryWhenAvailable),
        "cancelled" => (Code::Cancelled, Action::None),
        _ => return Err(PlatformError::Corrupt("receipt_intelligence_failure_code")),
    };
    Ok(ReceiptIntelligenceFailureV1 {
        code,
        retryable: false,
        user_action,
    })
}

fn parse_approval_id(value: &str) -> PlatformResult<ReceiptIntelligenceApprovalId> {
    ReceiptIntelligenceApprovalId::new(parse_uuid(value, "receipt_intelligence_approval_id")?)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_approval_id"))
}

fn parse_attempt_id(value: &str) -> PlatformResult<ReceiptIntelligenceAttemptId> {
    ReceiptIntelligenceAttemptId::new(parse_uuid(value, "receipt_intelligence_attempt_id")?)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_attempt_id"))
}

fn parse_classification_id(value: &str) -> PlatformResult<ReceiptIntelligenceClassificationId> {
    ReceiptIntelligenceClassificationId::new(parse_uuid(
        value,
        "receipt_intelligence_classification_id",
    )?)
    .map_err(|_| PlatformError::Corrupt("receipt_intelligence_classification_id"))
}

fn parse_audit_id(value: &str) -> PlatformResult<ReceiptIntelligenceAuditId> {
    ReceiptIntelligenceAuditId::new(parse_uuid(value, "receipt_intelligence_audit_id")?)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_audit_id"))
}

fn parse_source_revision_id(value: &str) -> PlatformResult<ReceiptIntelligenceSourceRevisionId> {
    ReceiptIntelligenceSourceRevisionId::new(parse_uuid(
        value,
        "receipt_intelligence_source_revision_id",
    )?)
    .map_err(|_| PlatformError::Corrupt("receipt_intelligence_source_revision_id"))
}

fn parse_source_id(value: &str) -> PlatformResult<SourceId> {
    SourceId::new(parse_uuid(value, "receipt_intelligence_source_id")?)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_source_id"))
}

fn parse_order_id(value: &str) -> PlatformResult<ReceiptOrderEvidenceId> {
    ReceiptOrderEvidenceId::new(parse_uuid(value, "receipt_intelligence_order_id")?)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_order_id"))
}

fn parse_sha256(value: &str) -> PlatformResult<Sha256Digest> {
    Sha256Digest::parse(value.to_owned())
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_sha256"))
}

fn parse_uuid(value: &str, field: &'static str) -> PlatformResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt(field))
}

fn timestamp_from_ms(value: i64) -> PlatformResult<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value) * 1_000_000)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_timestamp"))?
        .format(&Rfc3339)
        .map_err(|_| PlatformError::Corrupt("receipt_intelligence_timestamp"))
}

fn parse_list_cursor(value: &str) -> PlatformResult<(i64, String)> {
    let (created_at_ms, attempt_id) = value
        .split_once(':')
        .ok_or(PlatformError::InvalidInput("receipt_intelligence_cursor"))?;
    let created_at_ms = created_at_ms
        .parse::<i64>()
        .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_cursor"))?;
    if created_at_ms < 0 {
        return Err(PlatformError::InvalidInput("receipt_intelligence_cursor"));
    }
    validate_uuid(attempt_id, "receipt_intelligence_cursor")?;
    Ok((created_at_ms, attempt_id.to_owned()))
}

fn attempt_state_db(state: wardrobe_core::ReceiptIntelligenceAttemptStateV1) -> &'static str {
    match state {
        wardrobe_core::ReceiptIntelligenceAttemptStateV1::NotSent => "not_sent",
        wardrobe_core::ReceiptIntelligenceAttemptStateV1::Dispatched => "dispatched",
        wardrobe_core::ReceiptIntelligenceAttemptStateV1::Completed => "completed",
        wardrobe_core::ReceiptIntelligenceAttemptStateV1::Refused => "refused",
        wardrobe_core::ReceiptIntelligenceAttemptStateV1::Failed => "failed",
        wardrobe_core::ReceiptIntelligenceAttemptStateV1::OutcomeUnknown => "outcome_unknown",
    }
}

fn classification_db(classification: ReceiptIntelligenceClassificationV1) -> &'static str {
    match classification {
        ReceiptIntelligenceClassificationV1::ApparelOrder => "apparel_order",
        ReceiptIntelligenceClassificationV1::ApparelLifecycleUpdate => "apparel_lifecycle_update",
        ReceiptIntelligenceClassificationV1::Unrelated => "unrelated",
        ReceiptIntelligenceClassificationV1::Ambiguous => "ambiguous",
    }
}

fn ensure_approved_preview_is_current(
    transaction: &Transaction<'_>,
    attempt_id: &str,
) -> PlatformResult<()> {
    let context = transaction
        .query_row(
            "SELECT
                approval.request_id, approval.source_revision_id,
                approval.preview_binding_sha256,
                approval.max_fragment_count, approval.max_fragment_bytes,
                approval.max_aggregate_text_bytes,
                approval.max_serialized_request_bytes,
                approval.max_request_bytes, approval.max_response_bytes,
                approval.max_output_tokens, approval.timeout_ms,
                approval.max_attempts
             FROM receipt_intelligence_attempts attempt
             JOIN receipt_intelligence_approvals approval
               ON approval.approval_id = attempt.approval_id
             WHERE attempt.attempt_id = ?1",
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput(
            "receipt_intelligence_attempt_id",
        ))?;
    let bounds = ReceiptIntelligenceBounds {
        max_fragment_count: u32::try_from(context.3)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_bounds"))?,
        max_fragment_bytes: u32::try_from(context.4)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_bounds"))?,
        max_aggregate_text_bytes: u32::try_from(context.5)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_bounds"))?,
        max_serialized_request_bytes: u32::try_from(context.6)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_bounds"))?,
        max_request_bytes: u32::try_from(context.7)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_bounds"))?,
        max_response_bytes: u32::try_from(context.8)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_bounds"))?,
        max_output_tokens: u32::try_from(context.9)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_bounds"))?,
        timeout_ms: u32::try_from(context.10)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_bounds"))?,
        max_attempts: u8::try_from(context.11)
            .map_err(|_| PlatformError::Corrupt("receipt_intelligence_bounds"))?,
    };
    let current = read_preview(transaction, &context.0, &context.1, bounds)?;
    if current.preview_binding_sha256 != context.2 {
        return Err(PlatformError::Conflict(
            "receipt_intelligence_source_revision_changed",
        ));
    }
    Ok(())
}

fn read_preview(
    connection: &rusqlite::Connection,
    request_id: &str,
    source_revision_id: &str,
    bounds: ReceiptIntelligenceBounds,
) -> PlatformResult<ReceiptIntelligencePreview> {
    let (local_source_id, source_revision_sha256): (String, String) = connection
        .query_row(
            "SELECT materialization.local_source_id,
                    revision.graph_sha256
             FROM gmail_source_revisions revision
             JOIN gmail_revision_materializations materialization
               ON materialization.revision_id = revision.revision_id
             JOIN local_sources source
               ON source.source_id = materialization.local_source_id
             WHERE revision.revision_id = ?1
               AND revision.availability = 'available'
               AND materialization.blob_sha256 IS NOT NULL
               AND source.status = 'imported'",
            [source_revision_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(PlatformError::Conflict(
            "receipt_intelligence_source_unavailable",
        ))?;
    validate_hash(
        &source_revision_sha256,
        "receipt_intelligence_source_revision_sha256",
    )?;
    let parse_id: String = connection
        .query_row(
            "SELECT parse_id
             FROM receipt_parses
             WHERE source_id = ?1
             ORDER BY created_at_ms DESC, parse_id DESC
             LIMIT 1",
            [&local_source_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(PlatformError::Conflict(
            "receipt_intelligence_parse_unavailable",
        ))?;
    let mut statement = connection.prepare(
        "SELECT ordinal, content_text, content_sha256, byte_length
         FROM receipt_fragments
         WHERE parse_id = ?1
           AND fragment_kind IN ('plain_text', 'sanitized_html')
         ORDER BY ordinal, fragment_id",
    )?;
    let rows = statement
        .query_map([&parse_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.is_empty() {
        return Err(PlatformError::Conflict(
            "receipt_intelligence_visible_text_unavailable",
        ));
    }
    if rows.len() > bounds.max_fragment_count as usize {
        return Err(PlatformError::InvalidInput(
            "receipt_intelligence_fragment_count",
        ));
    }
    let mut aggregate = 0_u64;
    let mut fragments = Vec::with_capacity(rows.len());
    for (projection_ordinal, (_source_ordinal, visible_text, content_sha256, byte_length)) in
        rows.into_iter().enumerate()
    {
        validate_hash(&content_sha256, "receipt_intelligence_fragment_sha256")?;
        let actual_sha256 = format!("{:x}", Sha256::digest(visible_text.as_bytes()));
        if actual_sha256 != content_sha256 {
            return Err(PlatformError::Corrupt(
                "receipt_intelligence_fragment_sha256",
            ));
        }
        let actual_length = visible_text.len() as u64;
        if i64::try_from(actual_length).ok() != Some(byte_length) {
            return Err(PlatformError::Corrupt(
                "receipt_intelligence_fragment_length",
            ));
        }
        if actual_length > u64::from(bounds.max_fragment_bytes) {
            return Err(PlatformError::InvalidInput(
                "receipt_intelligence_fragment_bytes",
            ));
        }
        let lower = visible_text.to_ascii_lowercase();
        if visible_text.trim().is_empty()
            || visible_text
                .chars()
                .any(|value| value.is_control() && !matches!(value, '\n' | '\t'))
            || ["http://", "https://", "www."]
                .iter()
                .any(|sentinel| lower.contains(sentinel))
        {
            return Err(PlatformError::InvalidInput(
                "receipt_intelligence_visible_text",
            ));
        }
        aggregate = aggregate
            .checked_add(actual_length)
            .ok_or(PlatformError::InvalidInput(
                "receipt_intelligence_aggregate_text_bytes",
            ))?;
        if aggregate > u64::from(bounds.max_aggregate_text_bytes) {
            return Err(PlatformError::InvalidInput(
                "receipt_intelligence_aggregate_text_bytes",
            ));
        }
        fragments.push(ReceiptIntelligencePreviewFragment {
            handle: format!("fragment-{projection_ordinal:04}"),
            visible_text,
            byte_length: u32::try_from(actual_length)
                .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_fragment_bytes"))?,
            content_sha256,
        });
    }
    let projection = serde_json::json!({
        "revision": "receipt-intelligence-projection-v1",
        "fragments": fragments
            .iter()
            .map(|fragment| {
                serde_json::json!({
                    "fragment_ref": fragment.handle,
                    "text": fragment.visible_text,
                })
            })
            .collect::<Vec<_>>(),
    });
    let serialized_projection_bytes = serde_json::to_vec(&projection)?.len();
    if serialized_projection_bytes > bounds.max_serialized_request_bytes as usize {
        return Err(PlatformError::InvalidInput(
            "receipt_intelligence_serialized_request_bytes",
        ));
    }
    let fragment_set_sha256 = hash_json(
        &fragments
            .iter()
            .map(|fragment| {
                (
                    fragment.handle.as_str(),
                    fragment.content_sha256.as_str(),
                    fragment.byte_length,
                )
            })
            .collect::<Vec<_>>(),
    )?;
    let projection_sha256 = hash_projection(&fragments);
    let preview_binding_sha256 = hash_json(&(
        request_id,
        source_revision_id,
        &local_source_id,
        &parse_id,
        &source_revision_sha256,
        &fragment_set_sha256,
        &projection_sha256,
        &projection,
        bounds,
    ))?;
    Ok(ReceiptIntelligencePreview {
        source_revision_id: source_revision_id.to_owned(),
        local_source_id,
        parse_id,
        source_revision_sha256,
        fragments,
        aggregate_text_bytes: u32::try_from(aggregate).map_err(|_| {
            PlatformError::InvalidInput("receipt_intelligence_aggregate_text_bytes")
        })?,
        serialized_projection_bytes: u32::try_from(serialized_projection_bytes)
            .map_err(|_| PlatformError::InvalidInput("receipt_intelligence_request_bytes"))?,
        fragment_set_sha256,
        projection_sha256,
        preview_binding_sha256,
    })
}

fn replay_reservation(
    connection: &rusqlite::Connection,
    request_id: &str,
    command_sha256: &str,
) -> PlatformResult<Option<ReservedReceiptIntelligenceAttempt>> {
    let row = connection
        .query_row(
            "SELECT attempt.approval_id, attempt.attempt_id, attempt.state,
                    attempt.envelope_sha256
             FROM receipt_intelligence_attempts attempt
             WHERE attempt.request_id = ?1",
            [request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((approval_id, attempt_id, state, stored_hash)) = row else {
        return Ok(None);
    };
    if stored_hash != command_sha256 {
        return Err(PlatformError::Conflict(
            "receipt_intelligence_command_changed",
        ));
    }
    Ok(Some(ReservedReceiptIntelligenceAttempt {
        approval_id,
        attempt_id,
        state: ReceiptIntelligenceAttemptState::parse(&state)?,
        replayed: true,
    }))
}

fn load_audit(
    connection: &rusqlite::Connection,
    attempt_id: &str,
) -> PlatformResult<Option<ReceiptIntelligenceAuditRecord>> {
    let row = connection
        .query_row(
            "SELECT
                audit_id, source_revision_sha256, projection_sha256,
                serialized_request_sha256, response_sha256,
                provider_request_id, response_id, request_bytes,
                response_bytes, input_tokens, output_tokens, total_tokens,
                reasoning_tokens, cached_input_tokens, dispatched_at_ms,
                finished_at_ms
             FROM receipt_intelligence_audits
             WHERE attempt_id = ?1",
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                    row.get::<_, i64>(13)?,
                    row.get::<_, i64>(14)?,
                    row.get::<_, i64>(15)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            audit_id,
            source_revision_sha256,
            projection_sha256,
            serialized_request_sha256,
            response_sha256,
            provider_request_id,
            response_id,
            request_bytes,
            response_bytes,
            input_tokens,
            output_tokens,
            total_tokens,
            reasoning_tokens,
            cached_input_tokens,
            dispatched_at_ms,
            finished_at_ms,
        )| {
            Ok(ReceiptIntelligenceAuditRecord {
                audit_id,
                source_revision_sha256,
                projection_sha256,
                serialized_request_sha256,
                response_sha256,
                provider_request_id,
                response_id,
                request_bytes: bounded_u32(request_bytes, "receipt_intelligence_request_bytes")?,
                response_bytes: bounded_u32(response_bytes, "receipt_intelligence_response_bytes")?,
                input_tokens: bounded_u32(input_tokens, "receipt_intelligence_input_tokens")?,
                output_tokens: bounded_u32(output_tokens, "receipt_intelligence_output_tokens")?,
                total_tokens: bounded_u32(total_tokens, "receipt_intelligence_total_tokens")?,
                reasoning_tokens: bounded_u32(
                    reasoning_tokens,
                    "receipt_intelligence_reasoning_tokens",
                )?,
                cached_input_tokens: bounded_u32(
                    cached_input_tokens,
                    "receipt_intelligence_cached_input_tokens",
                )?,
                dispatched_at_ms,
                finished_at_ms,
            })
        },
    )
    .transpose()
}

fn finalize_dispatched(
    database: &Database,
    attempt_id: &str,
    state: &str,
    failure_code: &str,
    audit: &ReceiptIntelligenceAuditMetadata,
    now_ms: i64,
) -> PlatformResult<()> {
    validate_uuid(attempt_id, "receipt_intelligence_attempt_id")?;
    validate_audit_metadata(audit, now_ms)?;
    let mut connection = database.connection()?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    insert_audit(&transaction, attempt_id, audit, now_ms)?;
    let changed = transaction.execute(
        "UPDATE receipt_intelligence_attempts
         SET state = ?2, failure_code = ?3, input_tokens = ?4,
             output_tokens = ?5, finalized_at_ms = ?6
         WHERE attempt_id = ?1 AND state = 'dispatched'",
        params![
            attempt_id,
            state,
            failure_code,
            i64::from(audit.input_tokens),
            i64::from(audit.output_tokens),
            now_ms,
        ],
    )?;
    if changed != 1 {
        return Err(PlatformError::Conflict(
            "receipt_intelligence_attempt_not_dispatched",
        ));
    }
    advance_receipt_intelligence_revision(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn insert_audit(
    transaction: &Transaction<'_>,
    attempt_id: &str,
    audit: &ReceiptIntelligenceAuditMetadata,
    now_ms: i64,
) -> PlatformResult<()> {
    let audit_id = stable_id("receipt-intelligence-audit", attempt_id);
    let inserted = transaction.execute(
        "INSERT INTO receipt_intelligence_audits(
            audit_id, attempt_id, source_revision_id, local_source_id,
            source_revision_sha256, projection_sha256,
            serialized_request_sha256, response_sha256, provider, model,
            provider_request_id, response_id, prompt_revision, schema_revision,
            projection_revision, retention_provenance, parameters_sha256,
            request_bytes, response_bytes, input_tokens, output_tokens,
            total_tokens, reasoning_tokens, cached_input_tokens, attempt_count,
            dispatched_at_ms, finished_at_ms
         )
         SELECT
            ?2, attempt.attempt_id, attempt.source_revision_id,
            attempt.local_source_id, approval.source_revision_sha256,
            approval.projection_sha256, approval.serialized_request_sha256,
            ?3, approval.provider, approval.model, ?4, ?5,
            approval.prompt_revision, approval.schema_revision,
            approval.projection_revision, approval.retention_provenance,
            approval.parameters_sha256, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
            attempt.dispatched_at_ms, ?14
         FROM receipt_intelligence_attempts attempt
         JOIN receipt_intelligence_approvals approval
           ON approval.approval_id = attempt.approval_id
         WHERE attempt.attempt_id = ?1
           AND attempt.state = 'dispatched'
           AND attempt.dispatched_at_ms = ?15",
        params![
            attempt_id,
            audit_id,
            audit.response_sha256,
            audit.provider_request_id,
            audit.response_id,
            i64::from(audit.request_bytes),
            i64::from(audit.response_bytes),
            i64::from(audit.input_tokens),
            i64::from(audit.output_tokens),
            i64::from(audit.total_tokens),
            i64::from(audit.reasoning_tokens),
            i64::from(audit.cached_input_tokens),
            i64::from(audit.attempt_count),
            now_ms,
            audit.dispatched_at_ms,
        ],
    )?;
    if inserted != 1 {
        return Err(PlatformError::Conflict(
            "receipt_intelligence_audit_attempt_changed",
        ));
    }
    Ok(())
}

fn validate_audit_metadata(
    audit: &ReceiptIntelligenceAuditMetadata,
    now_ms: i64,
) -> PlatformResult<()> {
    if let Some(hash) = &audit.response_sha256 {
        validate_hash(hash, "receipt_intelligence_response_sha256")?;
    }
    for value in [
        audit.provider_request_id.as_deref(),
        audit.response_id.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(PlatformError::InvalidInput(
                "receipt_intelligence_provider_identifier",
            ));
        }
    }
    if audit.request_bytes == 0
        || audit.total_tokens != audit.input_tokens.saturating_add(audit.output_tokens)
        || audit.reasoning_tokens > audit.output_tokens
        || audit.cached_input_tokens > audit.input_tokens
        || audit.attempt_count != 1
        || audit.dispatched_at_ms < 0
        || now_ms < audit.dispatched_at_ms
    {
        return Err(PlatformError::InvalidInput("receipt_intelligence_audit"));
    }
    Ok(())
}

fn authority_snapshot(
    transaction: &Transaction<'_>,
    local_source_id: &str,
) -> PlatformResult<Option<(String, String, String, i64, i64)>> {
    transaction
        .query_row(
            "SELECT authority_id, order_evidence_id, review_decision_id,
                    receipt_revision, authority_revision
             FROM receipt_source_authority_heads
             WHERE local_source_id = ?1",
            [local_source_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(PlatformError::from)
}

fn source_review_count(
    transaction: &Transaction<'_>,
    local_source_id: &str,
) -> PlatformResult<i64> {
    Ok(transaction.query_row(
        "SELECT COUNT(*)
         FROM receipt_review_decisions decision
         JOIN receipt_orders receipt_order
           ON receipt_order.order_evidence_id = decision.order_evidence_id
         JOIN receipt_extraction_runs run ON run.run_id = receipt_order.run_id
         JOIN receipt_parses parse ON parse.parse_id = run.parse_id
         WHERE parse.source_id = ?1",
        [local_source_id],
        |row| row.get(0),
    )?)
}

fn require_active_credential(
    transaction: &Transaction<'_>,
    credential_id: &str,
) -> PlatformResult<()> {
    let active: bool = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM credential_references
            WHERE credential_id = ?1
              AND provider = 'open_ai'
              AND status = 'active'
         )",
        [credential_id],
        |row| row.get(0),
    )?;
    if active {
        Ok(())
    } else {
        Err(PlatformError::Conflict(
            "receipt_intelligence_credential_unavailable",
        ))
    }
}

fn validate_reservation(
    reservation: &ReceiptIntelligenceConsentReservation,
    now_ms: i64,
) -> PlatformResult<()> {
    validate_uuid(&reservation.request_id, "receipt_intelligence_request_id")?;
    validate_uuid(
        &reservation.source_revision_id,
        "receipt_intelligence_source_revision_id",
    )?;
    validate_uuid(
        &reservation.credential_id,
        "receipt_intelligence_credential_id",
    )?;
    for (value, field) in [
        (
            &reservation.command_sha256,
            "receipt_intelligence_command_sha256",
        ),
        (
            &reservation.preview_binding_sha256,
            "receipt_intelligence_preview_binding_sha256",
        ),
        (
            &reservation.fragment_set_sha256,
            "receipt_intelligence_fragment_set_sha256",
        ),
        (
            &reservation.parameters_sha256,
            "receipt_intelligence_parameters_sha256",
        ),
        (
            &reservation.source_revision_sha256,
            "receipt_intelligence_source_revision_sha256",
        ),
        (
            &reservation.projection_sha256,
            "receipt_intelligence_projection_sha256",
        ),
        (
            &reservation.serialized_request_sha256,
            "receipt_intelligence_serialized_request_sha256",
        ),
    ] {
        validate_hash(value, field)?;
    }
    if reservation.provider != "openai" {
        return Err(PlatformError::InvalidInput("receipt_intelligence_provider"));
    }
    validate_ascii_revision(&reservation.model, "receipt_intelligence_model")?;
    validate_ascii_revision(
        &reservation.prompt_revision,
        "receipt_intelligence_prompt_revision",
    )?;
    validate_ascii_revision(
        &reservation.schema_revision,
        "receipt_intelligence_schema_revision",
    )?;
    validate_ascii_revision(
        &reservation.projection_revision,
        "receipt_intelligence_projection_revision",
    )?;
    if !matches!(
        reservation.retention_mode.as_str(),
        "unknown" | "default" | "MAM" | "ZDR"
    ) {
        return Err(PlatformError::InvalidInput(
            "receipt_intelligence_retention_mode",
        ));
    }
    let retention_bytes = reservation.retention_provenance.as_bytes();
    if retention_bytes.is_empty()
        || retention_bytes.len() > 128
        || !retention_bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(PlatformError::InvalidInput(
            "receipt_intelligence_retention_provenance",
        ));
    }
    validate_bounds(reservation.bounds)?;
    if reservation.serialized_request_bytes == 0
        || reservation.serialized_request_bytes > reservation.bounds.max_serialized_request_bytes
        || reservation.serialized_request_bytes > reservation.bounds.max_request_bytes
    {
        return Err(PlatformError::InvalidInput(
            "receipt_intelligence_serialized_request_bytes",
        ));
    }
    let latest_expiry =
        now_ms
            .checked_add(APPROVAL_LIFETIME_MS)
            .ok_or(PlatformError::InvalidInput(
                "receipt_intelligence_approval_expiry",
            ))?;
    if now_ms < 0 || reservation.expires_at_ms < now_ms || reservation.expires_at_ms > latest_expiry
    {
        return Err(PlatformError::InvalidInput(
            "receipt_intelligence_approval_expiry",
        ));
    }
    Ok(())
}

fn validate_bounds(bounds: ReceiptIntelligenceBounds) -> PlatformResult<()> {
    if bounds.max_fragment_count == 0
        || bounds.max_fragment_count > 200
        || bounds.max_fragment_bytes == 0
        || bounds.max_fragment_bytes > 32_768
        || bounds.max_aggregate_text_bytes == 0
        || bounds.max_aggregate_text_bytes > 1_048_576
        || bounds.max_serialized_request_bytes == 0
        || bounds.max_serialized_request_bytes > 2_097_152
        || bounds.max_request_bytes == 0
        || bounds.max_request_bytes > 2_097_152
        || bounds.max_response_bytes == 0
        || bounds.max_response_bytes > 2_097_152
        || bounds.max_output_tokens == 0
        || bounds.max_output_tokens > 65_536
        || bounds.timeout_ms == 0
        || bounds.timeout_ms > 300_000
        || bounds.max_attempts != 1
    {
        return Err(PlatformError::InvalidInput("receipt_intelligence_bounds"));
    }
    Ok(())
}

fn validate_uuid(value: &str, field: &'static str) -> PlatformResult<()> {
    let parsed = Uuid::parse_str(value).map_err(|_| PlatformError::InvalidInput(field))?;
    if parsed.is_nil() {
        return Err(PlatformError::InvalidInput(field));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &'static str) -> PlatformResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlatformError::InvalidInput(field));
    }
    Ok(())
}

fn validate_ascii_revision(value: &str, field: &'static str) -> PlatformResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(PlatformError::InvalidInput(field));
    }
    Ok(())
}

fn advance_receipt_intelligence_revision(transaction: &Transaction<'_>) -> PlatformResult<()> {
    let changed = transaction.execute(
        "UPDATE revision_state
         SET receipt_intelligence_revision = receipt_intelligence_revision + 1
         WHERE singleton = 1
           AND receipt_intelligence_revision < 9007199254740990",
        [],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PlatformError::Corrupt(
            "receipt_intelligence_revision_exhausted",
        ))
    }
}

fn bounded_u32(value: i64, field: &'static str) -> PlatformResult<u32> {
    u32::try_from(value).map_err(|_| PlatformError::Corrupt(field))
}

fn hash_projection(fragments: &[ReceiptIntelligencePreviewFragment]) -> String {
    fn hash_part(digest: &mut Sha256, value: &[u8]) {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }

    let mut digest = Sha256::new();
    hash_part(
        &mut digest,
        b"receipt-intelligence-projection-v1".as_slice(),
    );
    hash_part(&mut digest, &(fragments.len() as u64).to_be_bytes());
    for fragment in fragments {
        hash_part(&mut digest, fragment.handle.as_bytes());
        hash_part(&mut digest, fragment.visible_text.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn hash_json<T: Serialize + ?Sized>(value: &T) -> PlatformResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

#[cfg(test)]
#[path = "receipt_intelligence_repository_tests.rs"]
mod tests;
