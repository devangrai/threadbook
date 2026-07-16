use crate::database::stable_id;
use crate::{Database, PlatformError, PlatformResult};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;
use wardrobe_core::{
    allowlisted_outfit_capability_tags, CredentialLocator, ItemAttributesV1, ItemId,
    OpenAiRetentionDeclarationV1, OpenAiRetentionDisclosureV1, OpenAiRetentionModeV1,
    OutfitDisclosureFieldClassV1, OutfitId, OutfitRecommendationApprovalId,
    OutfitRecommendationApprovalV1, OutfitRecommendationAuditV1, OutfitRecommendationDisclosureV1,
    OutfitRecommendationFailureCodeV1, OutfitRecommendationOutcomeV1,
    OutfitRecommendationProviderStatusV1, OutfitRecommendationSnapshotItemV1,
    OutfitRecommendationSnapshotV1, OutfitToolSavedOutfitV1, OutfitToolWardrobeItemV1,
    PreviewOutfitRecommendationV1Request, PreviewOutfitRecommendationV1Response, RequestId,
    RequestOutfitRecommendationV1Request, RequestOutfitRecommendationV1Response,
    StructuredOutfitRecommendationV1, Validate, ValidatedOutfitRecommendationV1,
    OUTFIT_CAPABILITY_REVISION_V1, OUTFIT_COMPATIBILITY_REVISION_V1,
    OUTFIT_RECOMMENDATION_MODEL_V1, OUTFIT_RECOMMENDATION_PROVIDER_V1,
    OUTFIT_RECOMMENDATION_SCHEMA_REVISION_V1, OUTFIT_RETENTION_DISCLOSURE_REVISION_V1,
    SCHEMA_VERSION_V1,
};

const PREVIEW_COMMAND: &str = "preview_outfit_recommendation_v1";
pub const OUTFIT_RECOMMENDATION_PROMPT_REVISION_V1: &str = "p07-outfit-prompt-v1";
const APPROVAL_LIFETIME_MS: i64 = 10 * 60 * 1_000;

#[derive(Clone, Debug)]
pub struct OutfitRecommendationToolSnapshot {
    pub validation: OutfitRecommendationSnapshotV1,
    pub wardrobe_items: Vec<OutfitToolWardrobeItemV1>,
    pub saved_outfits: Vec<OutfitToolSavedOutfitV1>,
}

#[derive(Clone, Debug)]
pub struct ReservedOutfitRecommendation {
    pub attempt_id: String,
    pub request: RequestOutfitRecommendationV1Request,
    pub credential_locator: CredentialLocator,
    pub snapshot: OutfitRecommendationToolSnapshot,
}

#[derive(Clone, Debug)]
pub enum OutfitRecommendationRequestPlan {
    Execute(ReservedOutfitRecommendation),
    Replay(RequestOutfitRecommendationV1Response),
}

impl Database {
    pub fn preview_outfit_recommendation(
        &self,
        request: &PreviewOutfitRecommendationV1Request,
        now_ms: i64,
    ) -> PlatformResult<PreviewOutfitRecommendationV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("recommendation_preview"))?;
        let request_hash = hash_json(&request.envelope)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(response) = replay_preview(&transaction, request, &request_hash)? {
            transaction.commit()?;
            return Ok(response);
        }
        let (catalog_revision, outfit_revision) = current_revisions(&transaction)?;
        if catalog_revision != request.envelope.expected_catalog_revision
            || outfit_revision != request.envelope.expected_outfit_revision
        {
            return Err(PlatformError::Conflict("recommendation_revision_changed"));
        }
        require_active_openai_credential(
            &transaction,
            &request.envelope.credential_id.to_string(),
        )?;

        let approval_id_text = stable_id(
            "outfit-recommendation-approval",
            &request.request_id.to_string(),
        );
        let approval_id = OutfitRecommendationApprovalId::new(
            Uuid::parse_str(&approval_id_text)
                .map_err(|_| PlatformError::Corrupt("recommendation_approval_id"))?,
        )
        .map_err(|_| PlatformError::Corrupt("recommendation_approval_id"))?;
        let expires_at_ms = now_ms
            .checked_add(APPROVAL_LIFETIME_MS)
            .ok_or(PlatformError::Corrupt("recommendation_expiry"))?;
        let response = PreviewOutfitRecommendationV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            provider_status: OutfitRecommendationProviderStatusV1::Ready,
            disclosure: disclosure(request.envelope.retention.clone()),
            approval: OutfitRecommendationApprovalV1 {
                approval_id,
                expires_at: timestamp(expires_at_ms)?,
                single_use: true,
                catalog_revision,
                outfit_revision,
            },
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("recommendation_preview_response"))?;
        transaction.execute(
            "INSERT INTO outfit_recommendation_approvals(
                approval_id, preview_request_id, request_hash, credential_id,
                catalog_revision, outfit_revision, retention_mode,
                retention_provenance, disclosure_revision, expires_at_ms,
                consumed_request_id, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11)",
            params![
                approval_id_text,
                request.request_id.to_string(),
                request_hash,
                request.envelope.credential_id.to_string(),
                catalog_revision as i64,
                outfit_revision as i64,
                retention_mode_db(request.envelope.retention.mode),
                request.envelope.retention.provenance,
                OUTFIT_RETENTION_DISCLOSURE_REVISION_V1,
                expires_at_ms,
                now_ms,
            ],
        )?;
        transaction.execute(
            "INSERT INTO command_receipts(
                request_id, command_name, envelope_hash, response_json, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                request.request_id.to_string(),
                PREVIEW_COMMAND,
                request_hash,
                serde_json::to_string(&response)?,
                now_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(response)
    }

    pub fn reserve_outfit_recommendation(
        &self,
        request: &RequestOutfitRecommendationV1Request,
        now_ms: i64,
    ) -> PlatformResult<OutfitRecommendationRequestPlan> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("recommendation_request"))?;
        let request_hash = hash_json(&request.envelope)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(response) = replay_attempt(&transaction, request.request_id, &request_hash)? {
            transaction.commit()?;
            return Ok(OutfitRecommendationRequestPlan::Replay(response));
        }
        let (catalog_revision, outfit_revision) = current_revisions(&transaction)?;
        if catalog_revision != request.envelope.expected_catalog_revision
            || outfit_revision != request.envelope.expected_outfit_revision
        {
            return Err(PlatformError::Conflict("recommendation_revision_changed"));
        }
        let approval = transaction
            .query_row(
                "SELECT request_hash, credential_id, catalog_revision,
                        outfit_revision, retention_mode, retention_provenance,
                        expires_at_ms, consumed_request_id
                 FROM outfit_recommendation_approvals WHERE approval_id = ?1",
                [request.approval_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::Conflict("recommendation_approval_missing"))?;
        if approval.0 != request_hash
            || approval.1 != request.envelope.credential_id.to_string()
            || approval.2 != catalog_revision as i64
            || approval.3 != outfit_revision as i64
            || approval.4 != retention_mode_db(request.envelope.retention.mode)
            || approval.5 != request.envelope.retention.provenance
        {
            return Err(PlatformError::Conflict("recommendation_approval_mismatch"));
        }
        if approval.7.is_some() {
            return Err(PlatformError::Conflict("recommendation_approval_consumed"));
        }
        if approval.6 < now_ms {
            return Err(PlatformError::Conflict("recommendation_approval_expired"));
        }
        let locator = require_active_openai_credential(
            &transaction,
            &request.envelope.credential_id.to_string(),
        )?;
        let snapshot = load_snapshot(&transaction)?;
        if snapshot.validation.catalog_revision != catalog_revision
            || snapshot.validation.outfit_revision != outfit_revision
        {
            return Err(PlatformError::Conflict("recommendation_revision_changed"));
        }
        let snapshot_hash = hash_json(&snapshot_hash_input(&snapshot))?;
        let attempt_id = stable_id(
            "outfit-recommendation-attempt",
            &request.request_id.to_string(),
        );
        transaction.execute(
            "UPDATE outfit_recommendation_approvals
             SET consumed_request_id = ?1
             WHERE approval_id = ?2 AND consumed_request_id IS NULL",
            params![
                request.request_id.to_string(),
                request.approval_id.to_string()
            ],
        )?;
        transaction.execute(
            "INSERT INTO outfit_recommendation_attempts(
                attempt_id, request_id, approval_id, request_hash, credential_id,
                state, catalog_revision, outfit_revision, input_hash,
                tool_snapshot_hash, provider, model, prompt_revision,
                schema_revision, compatibility_revision, retention_mode,
                retention_provenance, provider_request_id, provider_response_id,
                usage_json, audit_json, terminal_response_json,
                validated_response_json, failure_code, created_at_ms, finalized_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, 'reserved', ?6, ?7, ?8, ?9,
                'openai', ?10, ?11, ?12, ?13, ?14, ?15,
                NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?16, NULL
             )",
            params![
                attempt_id,
                request.request_id.to_string(),
                request.approval_id.to_string(),
                request_hash,
                request.envelope.credential_id.to_string(),
                catalog_revision as i64,
                outfit_revision as i64,
                hash_json(&request.envelope.prompt)?,
                snapshot_hash,
                OUTFIT_RECOMMENDATION_MODEL_V1,
                OUTFIT_RECOMMENDATION_PROMPT_REVISION_V1,
                OUTFIT_RECOMMENDATION_SCHEMA_REVISION_V1,
                OUTFIT_COMPATIBILITY_REVISION_V1,
                retention_mode_db(request.envelope.retention.mode),
                request.envelope.retention.provenance,
                now_ms,
            ],
        )?;
        transaction.commit()?;
        Ok(OutfitRecommendationRequestPlan::Execute(
            ReservedOutfitRecommendation {
                attempt_id,
                request: request.clone(),
                credential_locator: locator,
                snapshot,
            },
        ))
    }

    pub(crate) fn authorize_outfit_recommendation_transport_start(
        &self,
        attempt_id: &str,
        now_ms: i64,
    ) -> PlatformResult<bool> {
        let mut connection = self.connection()?;
        // This writer lock serializes the active check with credential inactivation.
        // Committing it is the transport-start authority point.
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, credential_active): (String, bool) = transaction
            .query_row(
                "SELECT attempts.state, EXISTS(
                    SELECT 1 FROM credential_references AS credentials
                    WHERE credentials.credential_id = attempts.credential_id
                      AND credentials.provider = 'open_ai'
                      AND credentials.status = 'active'
                 )
                 FROM outfit_recommendation_attempts AS attempts
                 WHERE attempts.attempt_id = ?1",
                [attempt_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("recommendation_attempt"))?;
        if state != "reserved" {
            return Err(PlatformError::Conflict(
                "recommendation_attempt_not_reserved",
            ));
        }
        if credential_active {
            let changed = transaction.execute(
                "UPDATE outfit_recommendation_attempts
                 SET transport_started_at_ms = COALESCE(transport_started_at_ms, ?2)
                 WHERE attempt_id = ?1 AND state = 'reserved'",
                params![attempt_id, now_ms],
            )?;
            if changed != 1 {
                return Err(PlatformError::Conflict(
                    "recommendation_attempt_not_reserved",
                ));
            }
        }
        transaction.commit()?;
        Ok(credential_active)
    }

    pub fn finalize_outfit_recommendation(
        &self,
        attempt_id: &str,
        mut response: RequestOutfitRecommendationV1Response,
        now_ms: i64,
    ) -> PlatformResult<RequestOutfitRecommendationV1Response> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, request_id, catalog_revision, outfit_revision): (String, String, i64, i64) =
            transaction
                .query_row(
                    "SELECT state, request_id, catalog_revision, outfit_revision
                     FROM outfit_recommendation_attempts WHERE attempt_id = ?1",
                    [attempt_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?
                .ok_or(PlatformError::InvalidInput("recommendation_attempt"))?;
        if state != "reserved" {
            let stored: String = transaction.query_row(
                "SELECT terminal_response_json
                 FROM outfit_recommendation_attempts WHERE attempt_id = ?1",
                [attempt_id],
                |row| row.get(0),
            )?;
            return Ok(serde_json::from_str(&stored)?);
        }
        if response.request_id.to_string() != request_id {
            return Err(PlatformError::Conflict("recommendation_request_changed"));
        }
        let (live_catalog, live_outfit) = current_revisions(&transaction)?;
        if live_catalog != catalog_revision as u64 || live_outfit != outfit_revision as u64 {
            response.outcome = OutfitRecommendationOutcomeV1::HistoricalStale {
                catalog_changed: live_catalog != catalog_revision as u64,
                outfit_changed: live_outfit != outfit_revision as u64,
            };
        }
        let terminal = terminal_parts(&response);
        let validated_json = match &response.outcome {
            OutfitRecommendationOutcomeV1::Completed { recommendation, .. } => {
                Some(serde_json::to_string(recommendation)?)
            }
            _ => None,
        };
        transaction.execute(
            "UPDATE outfit_recommendation_attempts
             SET state = ?2, provider_request_id = ?3, provider_response_id = ?4,
                 usage_json = ?5, audit_json = ?6, terminal_response_json = ?7,
                 validated_response_json = ?8, failure_code = ?9, finalized_at_ms = ?10
             WHERE attempt_id = ?1 AND state = 'reserved'",
            params![
                attempt_id,
                terminal.state,
                terminal.provider_request_id,
                terminal.provider_response_id,
                terminal.usage_json,
                terminal.audit_json,
                serde_json::to_string(&response)?,
                validated_json,
                terminal.failure_code,
                now_ms,
            ],
        )?;
        if let OutfitRecommendationOutcomeV1::Completed { recommendation, .. } = &response.outcome {
            insert_recommendation_members(&transaction, attempt_id, recommendation)?;
        }
        transaction.commit()?;
        Ok(response)
    }

    pub fn recover_reserved_outfit_recommendations(&self, now_ms: i64) -> PlatformResult<usize> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement = transaction.prepare(
            "SELECT attempt_id, request_id FROM outfit_recommendation_attempts
             WHERE state = 'reserved' ORDER BY created_at_ms, attempt_id",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for (attempt_id, request_id) in &rows {
            let response = RequestOutfitRecommendationV1Response {
                schema_version: SCHEMA_VERSION_V1,
                request_id: parse_request_id(request_id)?,
                outcome: OutfitRecommendationOutcomeV1::Failed {
                    code: OutfitRecommendationFailureCodeV1::OutcomeUnknown,
                    retryable: false,
                    audit: None,
                },
            };
            transaction.execute(
                "UPDATE outfit_recommendation_attempts
                 SET state = 'outcome_unknown', terminal_response_json = ?2,
                     failure_code = 'outcome_unknown', finalized_at_ms = ?3
                 WHERE attempt_id = ?1 AND state = 'reserved'",
                params![attempt_id, serde_json::to_string(&response)?, now_ms],
            )?;
        }
        transaction.commit()?;
        Ok(rows.len())
    }
}

fn replay_preview(
    transaction: &Transaction<'_>,
    request: &PreviewOutfitRecommendationV1Request,
    request_hash: &str,
) -> PlatformResult<Option<PreviewOutfitRecommendationV1Response>> {
    let row = transaction
        .query_row(
            "SELECT command_name, envelope_hash, response_json
             FROM command_receipts WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    match row {
        Some((command, envelope, response))
            if command == PREVIEW_COMMAND && envelope == request_hash =>
        {
            Ok(Some(serde_json::from_str(&response)?))
        }
        Some(_) => Err(PlatformError::Conflict("command_envelope_changed")),
        None => Ok(None),
    }
}

fn replay_attempt(
    transaction: &Transaction<'_>,
    request_id: RequestId,
    request_hash: &str,
) -> PlatformResult<Option<RequestOutfitRecommendationV1Response>> {
    let row = transaction
        .query_row(
            "SELECT request_hash, state, catalog_revision, outfit_revision,
                    terminal_response_json
             FROM outfit_recommendation_attempts WHERE request_id = ?1",
            [request_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_hash, state, catalog_revision, outfit_revision, response)) = row else {
        return Ok(None);
    };
    if stored_hash != request_hash {
        return Err(PlatformError::Conflict("command_envelope_changed"));
    }
    if state == "reserved" {
        return Err(PlatformError::Conflict(
            "recommendation_attempt_in_progress",
        ));
    }
    let response = response.ok_or(PlatformError::Corrupt("recommendation_terminal_response"))?;
    let stored: RequestOutfitRecommendationV1Response = serde_json::from_str(&response)?;
    if matches!(
        stored.outcome,
        OutfitRecommendationOutcomeV1::Completed { .. }
    ) {
        let (live_catalog, live_outfit) = current_revisions(transaction)?;
        if live_catalog != catalog_revision as u64 || live_outfit != outfit_revision as u64 {
            return Ok(Some(RequestOutfitRecommendationV1Response {
                schema_version: SCHEMA_VERSION_V1,
                request_id,
                outcome: OutfitRecommendationOutcomeV1::HistoricalStale {
                    catalog_changed: live_catalog != catalog_revision as u64,
                    outfit_changed: live_outfit != outfit_revision as u64,
                },
            }));
        }
    }
    Ok(Some(stored))
}

fn current_revisions(transaction: &Transaction<'_>) -> PlatformResult<(u64, u64)> {
    let values: (i64, i64) = transaction.query_row(
        "SELECT catalog_revision, outfit_revision
         FROM revision_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((
        u64::try_from(values.0).map_err(|_| PlatformError::Corrupt("catalog_revision"))?,
        u64::try_from(values.1).map_err(|_| PlatformError::Corrupt("outfit_revision"))?,
    ))
}

fn require_active_openai_credential(
    transaction: &Transaction<'_>,
    credential_id: &str,
) -> PlatformResult<CredentialLocator> {
    let locator = transaction
        .query_row(
            "SELECT locator FROM credential_references
             WHERE credential_id = ?1 AND provider = 'open_ai' AND status = 'active'",
            [credential_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .ok_or(PlatformError::Conflict(
            "recommendation_credential_unavailable",
        ))?;
    CredentialLocator::new(locator)
        .map_err(|_| PlatformError::Corrupt("recommendation_credential_locator"))
}

fn load_snapshot(
    transaction: &Transaction<'_>,
) -> PlatformResult<OutfitRecommendationToolSnapshot> {
    let (catalog_revision, outfit_revision) = current_revisions(transaction)?;
    let mut statement = transaction.prepare(
        "SELECT item_id, attributes_json, updated_revision, active
         FROM catalog_items ORDER BY item_id LIMIT 1025",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() > 1024 {
        return Err(PlatformError::Unsupported(
            "recommendation_snapshot_too_large",
        ));
    }
    let mut validation_items = Vec::with_capacity(rows.len());
    let mut wardrobe_items = Vec::new();
    for (item_id, attributes_json, updated_revision, active) in rows {
        let item_id = parse_item_id(&item_id)?;
        let attributes: ItemAttributesV1 = serde_json::from_str(&attributes_json)?;
        attributes
            .validate()
            .map_err(|_| PlatformError::Corrupt("recommendation_item_attributes"))?;
        let capability_tags = allowlisted_outfit_capability_tags(&attributes.tags);
        validation_items.push(OutfitRecommendationSnapshotItemV1 {
            item_id,
            item_revision: u64::try_from(updated_revision)
                .map_err(|_| PlatformError::Corrupt("item_revision"))?,
            active: active == 1,
            category: attributes.category,
            capability_tags: capability_tags.clone(),
        });
        if active == 1 {
            wardrobe_items.push(OutfitToolWardrobeItemV1 {
                item_id,
                display_name: attributes.display_name,
                category: attributes.category,
                primary_color: attributes.primary_color,
                brand: attributes.brand,
                capability_tags,
            });
        }
    }
    let validation = OutfitRecommendationSnapshotV1 {
        catalog_revision,
        outfit_revision,
        capability_revision: OUTFIT_CAPABILITY_REVISION_V1.to_owned(),
        items: validation_items,
    };
    validation
        .validate()
        .map_err(|_| PlatformError::Corrupt("recommendation_snapshot"))?;
    let saved_outfits = load_saved_outfits(transaction)?;
    Ok(OutfitRecommendationToolSnapshot {
        validation,
        wardrobe_items,
        saved_outfits,
    })
}

fn load_saved_outfits(
    transaction: &Transaction<'_>,
) -> PlatformResult<Vec<OutfitToolSavedOutfitV1>> {
    let mut statement = transaction.prepare(
        "SELECT outfit_id, name FROM outfits
         ORDER BY created_outfit_revision DESC, outfit_id LIMIT 100",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(outfit_id, name)| {
            let mut members = transaction.prepare(
                "SELECT item_id FROM outfit_members
                 WHERE outfit_id = ?1 ORDER BY ordinal",
            )?;
            let item_ids = members
                .query_map([&outfit_id], |row| row.get::<_, String>(0))?
                .map(|value| parse_item_id(&value?))
                .collect::<PlatformResult<Vec<_>>>()?;
            let value = OutfitToolSavedOutfitV1 {
                outfit_id: OutfitId::new(
                    Uuid::parse_str(&outfit_id).map_err(|_| PlatformError::Corrupt("outfit_id"))?,
                )
                .map_err(|_| PlatformError::Corrupt("outfit_id"))?,
                name,
                item_ids,
            };
            value
                .validate()
                .map_err(|_| PlatformError::Corrupt("saved_outfit"))?;
            Ok(value)
        })
        .collect()
}

fn insert_recommendation_members(
    transaction: &Transaction<'_>,
    attempt_id: &str,
    recommendation: &ValidatedOutfitRecommendationV1,
) -> PlatformResult<()> {
    for (proposal_ordinal, proposal) in recommendation.proposals.iter().enumerate() {
        transaction.execute(
            "INSERT INTO outfit_recommendation_proposals(
                attempt_id, ordinal, proposal_name
             ) VALUES (?1, ?2, ?3)",
            params![attempt_id, proposal_ordinal as i64, proposal.name],
        )?;
        for (member_ordinal, item_id) in proposal.item_ids.iter().enumerate() {
            transaction.execute(
                "INSERT INTO outfit_recommendation_members(
                    attempt_id, proposal_ordinal, member_ordinal, item_id
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    attempt_id,
                    proposal_ordinal as i64,
                    member_ordinal as i64,
                    item_id.to_string(),
                ],
            )?;
        }
    }
    Ok(())
}

struct TerminalParts {
    state: &'static str,
    provider_request_id: Option<String>,
    provider_response_id: Option<String>,
    usage_json: Option<String>,
    audit_json: Option<String>,
    failure_code: Option<&'static str>,
}

fn terminal_parts(response: &RequestOutfitRecommendationV1Response) -> TerminalParts {
    match &response.outcome {
        OutfitRecommendationOutcomeV1::Completed { audit, .. } => {
            from_audit("completed", audit, None)
        }
        OutfitRecommendationOutcomeV1::Refused { audit } => {
            from_audit("refused", audit, Some("refused"))
        }
        OutfitRecommendationOutcomeV1::Failed { code, audit, .. } => {
            let state = if *code == OutfitRecommendationFailureCodeV1::OutcomeUnknown {
                "outcome_unknown"
            } else if *code == OutfitRecommendationFailureCodeV1::Stale {
                "stale"
            } else {
                "failed"
            };
            let mut parts = audit
                .as_ref()
                .map(|value| from_audit(state, value, Some(failure_code_db(*code))))
                .unwrap_or(TerminalParts {
                    state,
                    provider_request_id: None,
                    provider_response_id: None,
                    usage_json: None,
                    audit_json: None,
                    failure_code: Some(failure_code_db(*code)),
                });
            parts.state = state;
            parts
        }
        OutfitRecommendationOutcomeV1::HistoricalStale { .. } => TerminalParts {
            state: "stale",
            provider_request_id: None,
            provider_response_id: None,
            usage_json: None,
            audit_json: None,
            failure_code: Some("stale"),
        },
    }
}

fn from_audit(
    state: &'static str,
    audit: &OutfitRecommendationAuditV1,
    failure_code: Option<&'static str>,
) -> TerminalParts {
    TerminalParts {
        state,
        provider_request_id: audit.provider_request_id.clone(),
        provider_response_id: audit.response_id.clone(),
        usage_json: serde_json::to_string(&audit.usage).ok(),
        audit_json: serde_json::to_string(audit).ok(),
        failure_code,
    }
}

fn failure_code_db(code: OutfitRecommendationFailureCodeV1) -> &'static str {
    match code {
        OutfitRecommendationFailureCodeV1::ApprovalExpired => "approval_expired",
        OutfitRecommendationFailureCodeV1::ApprovalMismatch => "approval_mismatch",
        OutfitRecommendationFailureCodeV1::ApprovalConsumed => "approval_consumed",
        OutfitRecommendationFailureCodeV1::CredentialUnavailable => "credential_unavailable",
        OutfitRecommendationFailureCodeV1::ProviderUnavailable => "provider_unavailable",
        OutfitRecommendationFailureCodeV1::Authentication => "authentication",
        OutfitRecommendationFailureCodeV1::RateLimited => "rate_limited",
        OutfitRecommendationFailureCodeV1::ProviderFailure => "provider_failure",
        OutfitRecommendationFailureCodeV1::OutcomeUnknown => "outcome_unknown",
        OutfitRecommendationFailureCodeV1::Incomplete => "incomplete",
        OutfitRecommendationFailureCodeV1::Refused => "refused",
        OutfitRecommendationFailureCodeV1::MalformedOutput => "malformed_output",
        OutfitRecommendationFailureCodeV1::ToolProtocol => "tool_protocol",
        OutfitRecommendationFailureCodeV1::ToolLimit => "tool_limit",
        OutfitRecommendationFailureCodeV1::Grounding => "grounding",
        OutfitRecommendationFailureCodeV1::Constraint => "constraint",
        OutfitRecommendationFailureCodeV1::Stale => "stale",
    }
}

fn disclosure(retention: OpenAiRetentionDeclarationV1) -> OutfitRecommendationDisclosureV1 {
    OutfitRecommendationDisclosureV1 {
        provider: OUTFIT_RECOMMENDATION_PROVIDER_V1.to_owned(),
        model: OUTFIT_RECOMMENDATION_MODEL_V1.to_owned(),
        purpose: "outfit_recommendation".to_owned(),
        disclosed_field_classes: vec![
            OutfitDisclosureFieldClassV1::Prompt,
            OutfitDisclosureFieldClassV1::ExplicitConstraints,
            OutfitDisclosureFieldClassV1::ExcludedItemIds,
            OutfitDisclosureFieldClassV1::ItemIds,
            OutfitDisclosureFieldClassV1::DisplayNames,
            OutfitDisclosureFieldClassV1::Categories,
            OutfitDisclosureFieldClassV1::PrimaryColors,
            OutfitDisclosureFieldClassV1::Brands,
            OutfitDisclosureFieldClassV1::CapabilityTags,
            OutfitDisclosureFieldClassV1::WearHistory,
            OutfitDisclosureFieldClassV1::StylePreferences,
            OutfitDisclosureFieldClassV1::SavedOutfitMembership,
        ],
        photos_disclosed: false,
        email_disclosed: false,
        paths_disclosed: false,
        notes_disclosed: false,
        sizes_disclosed: false,
        evidence_metadata_disclosed: false,
        retention: OpenAiRetentionDisclosureV1::for_declaration(retention),
    }
}

fn snapshot_hash_input(snapshot: &OutfitRecommendationToolSnapshot) -> impl Serialize + '_ {
    (
        &snapshot.validation,
        &snapshot.wardrobe_items,
        &snapshot.saved_outfits,
    )
}

fn hash_json(value: &impl Serialize) -> PlatformResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn retention_mode_db(mode: OpenAiRetentionModeV1) -> &'static str {
    match mode {
        OpenAiRetentionModeV1::Unknown => "unknown",
        OpenAiRetentionModeV1::Default => "default",
        OpenAiRetentionModeV1::Mam => "MAM",
        OpenAiRetentionModeV1::Zdr => "ZDR",
    }
}

fn timestamp(value_ms: i64) -> PlatformResult<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(value_ms) * 1_000_000)
        .map_err(|_| PlatformError::Corrupt("recommendation_timestamp"))?
        .format(&Rfc3339)
        .map_err(|_| PlatformError::Corrupt("recommendation_timestamp"))
}

fn parse_request_id(value: &str) -> PlatformResult<RequestId> {
    RequestId::new(Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt("request_id"))?)
        .map_err(|_| PlatformError::Corrupt("request_id"))
}

fn parse_item_id(value: &str) -> PlatformResult<ItemId> {
    ItemId::new(Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt("item_id"))?)
        .map_err(|_| PlatformError::Corrupt("item_id"))
}

#[allow(dead_code)]
fn _assert_structured_contract(_: &StructuredOutfitRecommendationV1) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateAppPaths;
    use wardrobe_core::{
        CatalogPort, CredentialId, DeletionTargetKindV1, OpenAiRetentionModeV1,
        OutfitConstraintAssessmentV1, OutfitConstraintKindV1, OutfitConstraintStatusV1,
        OutfitOccasionV1, OutfitProposalV1, OutfitRecommendationConstraintsV1,
        OutfitRecommendationEnvelopeV1, OutfitRecommendationUsageV1, PreviewDeletionV1Request,
    };

    const CREDENTIAL_ID: &str = "11111111-1111-4111-8111-111111111111";
    const TOP_ID: &str = "22222222-2222-4222-8222-222222222222";
    const BOTTOM_ID: &str = "33333333-3333-4333-8333-333333333333";

    fn setup() -> (tempfile::TempDir, Database, OutfitRecommendationEnvelopeV1) {
        let temporary = tempfile::tempdir().unwrap();
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let database = Database::open(&paths, 1).unwrap();
        database
            .connection()
            .unwrap()
            .execute_batch(
                "INSERT INTO credential_references(
                    locator, credential_id, save_request_id, provider, display_label,
                    status, created_at_ms, updated_at_ms
                 ) VALUES (
                    '44444444-4444-4444-8444-444444444444',
                    '11111111-1111-4111-8111-111111111111',
                    '55555555-5555-4555-8555-555555555555',
                    'open_ai', 'OpenAI', 'active', 1, 1
                 );
                 INSERT INTO catalog_items(
                    item_id, display_name, attributes_json, active,
                    created_revision, updated_revision
                 ) VALUES
                 (
                    '22222222-2222-4222-8222-222222222222', 'White tee',
                    '{\"display_name\":\"White tee\",\"category\":\"top\",\"subcategory\":null,\"brand\":null,\"primary_color\":\"White\",\"size\":null,\"notes\":null,\"tags\":[\"private:user-tag\"]}',
                    1, 1, 1
                 ),
                 (
                    '33333333-3333-4333-8333-333333333333', 'Black jeans',
                    '{\"display_name\":\"Black jeans\",\"category\":\"bottom\",\"subcategory\":null,\"brand\":null,\"primary_color\":\"Black\",\"size\":null,\"notes\":null,\"tags\":[]}',
                    1, 1, 1
                 );
                 UPDATE revision_state SET catalog_revision = 1 WHERE singleton = 1;",
            )
            .unwrap();
        let envelope = OutfitRecommendationEnvelopeV1 {
            prompt: "A casual dinner outfit".to_owned(),
            credential_id: CredentialId::new(Uuid::parse_str(CREDENTIAL_ID).unwrap()).unwrap(),
            constraints: OutfitRecommendationConstraintsV1 {
                occasion: Some(OutfitOccasionV1::Casual),
                temperature_c: None,
                precipitation: None,
            },
            excluded_item_ids: Vec::new(),
            requested_proposal_count: 1,
            expected_catalog_revision: 1,
            expected_outfit_revision: 0,
            retention: OpenAiRetentionDeclarationV1 {
                mode: OpenAiRetentionModeV1::Unknown,
                provenance: "user_declared".to_owned(),
            },
        };
        (temporary, database, envelope)
    }

    fn preview(
        database: &Database,
        envelope: OutfitRecommendationEnvelopeV1,
        now_ms: i64,
    ) -> PreviewOutfitRecommendationV1Response {
        database
            .preview_outfit_recommendation(
                &PreviewOutfitRecommendationV1Request {
                    schema_version: 1,
                    request_id: RequestId::new_v4(),
                    envelope,
                },
                now_ms,
            )
            .unwrap()
    }

    fn request(
        envelope: OutfitRecommendationEnvelopeV1,
        approval_id: OutfitRecommendationApprovalId,
    ) -> RequestOutfitRecommendationV1Request {
        RequestOutfitRecommendationV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            approval_id,
            envelope,
        }
    }

    fn completed(
        request_id: RequestId,
        envelope: &OutfitRecommendationEnvelopeV1,
    ) -> RequestOutfitRecommendationV1Response {
        let recommendation = ValidatedOutfitRecommendationV1 {
            schema_revision: OUTFIT_RECOMMENDATION_SCHEMA_REVISION_V1.to_owned(),
            compatibility_revision: OUTFIT_COMPATIBILITY_REVISION_V1.to_owned(),
            capability_revision: OUTFIT_CAPABILITY_REVISION_V1.to_owned(),
            catalog_revision: envelope.expected_catalog_revision,
            outfit_revision: envelope.expected_outfit_revision,
            proposals: vec![OutfitProposalV1 {
                name: "Dinner basics".to_owned(),
                item_ids: vec![
                    parse_item_id(TOP_ID).unwrap(),
                    parse_item_id(BOTTOM_ID).unwrap(),
                ],
                rationale: "A simple grounded combination.".to_owned(),
                caveats: Vec::new(),
                unresolved_constraints: Vec::new(),
                constraint_assessment: vec![OutfitConstraintAssessmentV1 {
                    constraint: OutfitConstraintKindV1::Occasion,
                    status: OutfitConstraintStatusV1::Satisfied,
                    reason: None,
                    caveat: None,
                }],
            }],
        };
        let audit = OutfitRecommendationAuditV1 {
            provider: OUTFIT_RECOMMENDATION_PROVIDER_V1.to_owned(),
            model: OUTFIT_RECOMMENDATION_MODEL_V1.to_owned(),
            provider_request_id: Some("req_test".to_owned()),
            response_id: Some("resp_test".to_owned()),
            retention: OpenAiRetentionDisclosureV1::for_declaration(envelope.retention.clone()),
            reported_cache_usage: false,
            usage: OutfitRecommendationUsageV1 {
                input_tokens: 10,
                output_tokens: 10,
                reasoning_tokens: 2,
                response_calls: 2,
                tool_calls: 1,
                prompt_cache_read_tokens: 0,
                prompt_cache_write_tokens: 0,
            },
        };
        RequestOutfitRecommendationV1Response {
            schema_version: 1,
            request_id,
            outcome: OutfitRecommendationOutcomeV1::Completed {
                recommendation,
                audit,
            },
        }
    }

    #[test]
    fn approval_is_single_use_and_terminal_response_replays_without_locator_retention() {
        let (_temporary, database, envelope) = setup();
        let approval = preview(&database, envelope.clone(), 10);
        let request = request(envelope.clone(), approval.approval.approval_id);
        let reservation = match database
            .reserve_outfit_recommendation(&request, 11)
            .unwrap()
        {
            OutfitRecommendationRequestPlan::Execute(value) => value,
            OutfitRecommendationRequestPlan::Replay(_) => panic!("unexpected replay"),
        };
        assert!(reservation
            .snapshot
            .wardrobe_items
            .iter()
            .all(|item| item.capability_tags.is_empty()));
        let response = completed(request.request_id, &envelope);
        database
            .finalize_outfit_recommendation(&reservation.attempt_id, response.clone(), 12)
            .unwrap();
        database
            .connection()
            .unwrap()
            .execute(
                "DELETE FROM credential_references WHERE credential_id = ?1",
                [CREDENTIAL_ID],
            )
            .unwrap();

        let replay = database
            .reserve_outfit_recommendation(&request, 13)
            .unwrap();
        assert!(matches!(
            replay,
            OutfitRecommendationRequestPlan::Replay(RequestOutfitRecommendationV1Response {
                outcome: OutfitRecommendationOutcomeV1::Completed { .. },
                ..
            })
        ));
        let changed_request = RequestOutfitRecommendationV1Request {
            request_id: RequestId::new_v4(),
            ..request
        };
        assert!(matches!(
            database.reserve_outfit_recommendation(&changed_request, 13),
            Err(PlatformError::Conflict("recommendation_approval_consumed"))
        ));
        let connection = database.connection().unwrap();
        let locator_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM outfit_recommendation_attempts
                 WHERE credential_id = ?1",
                [CREDENTIAL_ID],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(locator_count, 1);
        let leaked_locator: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM outfit_recommendation_attempts
                 WHERE terminal_response_json LIKE '%44444444-4444-4444-8444-444444444444%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(leaked_locator, 0);
    }

    #[test]
    fn completed_replay_hides_proposal_after_catalog_or_outfit_revision_change() {
        for column in ["catalog_revision", "outfit_revision"] {
            let (_temporary, database, envelope) = setup();
            let approval = preview(&database, envelope.clone(), 10);
            let request = request(envelope.clone(), approval.approval.approval_id);
            let reservation = match database
                .reserve_outfit_recommendation(&request, 11)
                .unwrap()
            {
                OutfitRecommendationRequestPlan::Execute(value) => value,
                _ => panic!("unexpected replay"),
            };
            database
                .finalize_outfit_recommendation(
                    &reservation.attempt_id,
                    completed(request.request_id, &envelope),
                    12,
                )
                .unwrap();
            database
                .connection()
                .unwrap()
                .execute(
                    &format!(
                        "UPDATE revision_state SET {column} = {column} + 1 WHERE singleton = 1"
                    ),
                    [],
                )
                .unwrap();
            let replay = database
                .reserve_outfit_recommendation(&request, 13)
                .unwrap();
            match replay {
                OutfitRecommendationRequestPlan::Replay(
                    RequestOutfitRecommendationV1Response {
                        outcome:
                            OutfitRecommendationOutcomeV1::HistoricalStale {
                                catalog_changed,
                                outfit_changed,
                            },
                        ..
                    },
                ) => {
                    assert_eq!(catalog_changed, column == "catalog_revision");
                    assert_eq!(outfit_changed, column == "outfit_revision");
                }
                _ => panic!("stale proposal was exposed"),
            }
        }
    }

    #[test]
    fn restart_recovery_marks_reserved_attempt_outcome_unknown_without_resend() {
        let (temporary, database, envelope) = setup();
        let approval = preview(&database, envelope.clone(), 10);
        let request = request(envelope, approval.approval.approval_id);
        assert!(matches!(
            database
                .reserve_outfit_recommendation(&request, 11)
                .unwrap(),
            OutfitRecommendationRequestPlan::Execute(_)
        ));
        drop(database);
        let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
        let restarted = Database::open(&paths, 12).unwrap();
        assert_eq!(
            restarted
                .recover_reserved_outfit_recommendations(12)
                .unwrap(),
            1
        );
        assert!(matches!(
            restarted
                .reserve_outfit_recommendation(&request, 13)
                .unwrap(),
            OutfitRecommendationRequestPlan::Replay(RequestOutfitRecommendationV1Response {
                outcome: OutfitRecommendationOutcomeV1::Failed {
                    code: OutfitRecommendationFailureCodeV1::OutcomeUnknown,
                    retryable: false,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn item_dependency_closure_includes_normalized_members_and_stored_response_owner() {
        let (_temporary, database, envelope) = setup();
        let approval = preview(&database, envelope.clone(), 10);
        let request = request(envelope.clone(), approval.approval.approval_id);
        let reservation = match database
            .reserve_outfit_recommendation(&request, 11)
            .unwrap()
        {
            OutfitRecommendationRequestPlan::Execute(value) => value,
            _ => panic!("unexpected replay"),
        };
        database
            .finalize_outfit_recommendation(
                &reservation.attempt_id,
                completed(request.request_id, &envelope),
                12,
            )
            .unwrap();
        let preview = database
            .preview_deletion(&PreviewDeletionV1Request {
                schema_version: 1,
                request_id: RequestId::new_v4(),
                target_kind: DeletionTargetKindV1::Item,
                target_id: TOP_ID.to_owned(),
                limit: 100,
            })
            .unwrap();
        let connection = database.connection().unwrap();
        let labels = connection
            .prepare(
                "SELECT entity_id FROM deletion_preview_items
                 WHERE snapshot_token = ?1
                 ORDER BY entity_id",
            )
            .unwrap()
            .query_map([preview.preview_snapshot_token.as_str()], |row| {
                row.get::<_, String>(0)
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(labels
            .iter()
            .any(|value| value.starts_with("outfit_recommendation_member:")));
        assert!(labels
            .iter()
            .any(|value| value.starts_with("outfit_recommendation_attempt:")));
        assert!(labels
            .iter()
            .any(|value| value.starts_with("outfit_recommendation_approval:")));
    }
}
