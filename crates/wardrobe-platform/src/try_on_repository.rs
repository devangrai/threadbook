use crate::database::stable_id;
use crate::source_image::{canonical_try_on_png, verify_source_image};
use crate::{BlobStore, Database, PlatformError, PlatformResult, PrivateAppPaths};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use wardrobe_core::{
    BoundedPhotoArtifactBytesV1, BoundedTryOnOutputBytesV1, CredentialLocator,
    GetOutfitTryOnV1Request, GetOutfitTryOnV1Response, ItemAttributesV1,
    ListTryOnPortraitCandidatesV1Request, ListTryOnPortraitCandidatesV1Response,
    OpenAiRetentionModeV1, PageCursorV1, PhotoMediaTypeV1, PreviewTryOnV1Request,
    PreviewTryOnV1Response, ReplayStatusV1, Sha256Digest, SubmitTryOnV1Request,
    SubmitTryOnV1Response, TryOnApprovalV1, TryOnAssetRoleV1, TryOnDisclosureAssetV1,
    TryOnDisclosureV1, TryOnFailureCodeV1, TryOnFailureV1, TryOnGarmentSourceV1, TryOnJobStateV1,
    TryOnJobV1, TryOnOutputUseClassV1, TryOnOutputV1, TryOnPortraitCandidateV1,
    TryOnRetentionDisclosureV1, TryOnUserActionV1, Validate, SCHEMA_VERSION_V1,
    TRY_ON_DISCLOSURE_REVISION_V1, TRY_ON_MAX_AGGREGATE_INPUT_BYTES, TRY_ON_MODEL_V1,
    TRY_ON_OUTPUT_HEIGHT_V1, TRY_ON_OUTPUT_MEDIA_TYPE_V1, TRY_ON_OUTPUT_WIDTH_V1,
    TRY_ON_PRESENTATION_LABEL_V1, TRY_ON_PROMPT_REVISION_V1, TRY_ON_PROVIDER_V1, TRY_ON_PURPOSE_V1,
};

const PREVIEW_COMMAND: &str = "preview_try_on_v1";
const SUBMIT_COMMAND: &str = "submit_try_on_v1";
const PIPELINE_REVISION: &str = "p08-try-on-pipeline-v1";
const LABEL_REVISION: &str = "p08-try-on-label-v1";
const APPROVAL_LIFETIME_MS: i64 = 10 * 60 * 1_000;

#[derive(Clone, Debug)]
pub struct PreparedTryOnAsset {
    pub ordinal: u8,
    pub role: TryOnAssetRoleV1,
    pub png_bytes: Vec<u8>,
    pub canonical_sha256: String,
}

#[derive(Clone, Debug)]
pub struct ClaimedTryOnJob {
    pub job_id: String,
    pub attempt_id: String,
    pub fence: i64,
    pub assets: Vec<PreparedTryOnAsset>,
}

impl Database {
    pub fn list_try_on_portrait_candidates(
        &self,
        request: &ListTryOnPortraitCandidatesV1Request,
    ) -> PlatformResult<ListTryOnPortraitCandidatesV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("try_on_portrait_list"))?;
        let connection = self.connection()?;
        let photo_revision: i64 = connection.query_row(
            "SELECT photo_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let offset = parse_cursor(request.cursor.as_ref(), photo_revision as u64)?;
        let total_count: i64 = connection.query_row(
            "SELECT COUNT(DISTINCT artifact.source_revision_id)
             FROM photo_artifacts artifact
             JOIN photo_source_revisions revision
               ON revision.source_revision_id = artifact.source_revision_id
             WHERE revision.disposition = 'eligible'
               AND revision.blob_sha256 IS NOT NULL
               AND revision.byte_length IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        let mut statement = connection.prepare(
            "SELECT artifact.artifact_id, artifact.source_revision_id,
                    revision.blob_sha256, revision.byte_length
             FROM photo_artifacts artifact
             JOIN photo_source_revisions revision
               ON revision.source_revision_id = artifact.source_revision_id
             WHERE revision.disposition = 'eligible'
               AND revision.blob_sha256 IS NOT NULL
               AND revision.byte_length IS NOT NULL
               AND artifact.artifact_id = (
                    SELECT MIN(candidate.artifact_id)
                    FROM photo_artifacts candidate
                    WHERE candidate.source_revision_id = artifact.source_revision_id
               )
             ORDER BY artifact.source_revision_id
             LIMIT ?1 OFFSET ?2",
        )?;
        let rows = statement
            .query_map(params![i64::from(request.limit), offset as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let store = BlobStore::new(&self.paths);
        let mut candidates = Vec::with_capacity(rows.len());
        for (artifact_id, source_revision_id, blob_sha256, byte_length) in rows {
            let source = verify_source_image(&store, &blob_sha256, to_u64(byte_length)?)
                .map_err(|_| PlatformError::Corrupt("try_on_portrait_source"))?;
            canonical_try_on_png(&store, &blob_sha256, byte_length as u64)?;
            candidates.push(TryOnPortraitCandidateV1 {
                source_revision_id: parse_id(&source_revision_id)?,
                artifact_id: parse_id(&artifact_id)?,
                captured_at: None,
                media_type: source.media_type,
                width: source.width,
                height: source.height,
                bytes_sha256: Sha256Digest::from_bytes(&source.bytes),
                thumbnail_bytes: BoundedPhotoArtifactBytesV1::new(source.bytes)
                    .map_err(|_| PlatformError::Corrupt("try_on_portrait_bytes"))?,
            });
        }
        let next_offset = offset + candidates.len() as u64;
        let response = ListTryOnPortraitCandidatesV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            candidates,
            total_count: total_count as u64,
            photo_revision: photo_revision as u64,
            next_cursor: if next_offset < total_count as u64 {
                Some(make_cursor(photo_revision as u64, next_offset)?)
            } else {
                None
            },
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("try_on_portrait_response"))?;
        Ok(response)
    }

    pub fn preview_try_on(
        &self,
        request: &PreviewTryOnV1Request,
        now_ms: i64,
    ) -> PlatformResult<PreviewTryOnV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("try_on_preview"))?;
        let envelope_hash = hash_json(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) = replay::<PreviewTryOnV1Response, _>(
            &transaction,
            PREVIEW_COMMAND,
            request,
            &envelope_hash,
        )? {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let outfit_revision: i64 = transaction.query_row(
            "SELECT outfit_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if outfit_revision != request.expected_outfit_revision as i64 {
            return Err(PlatformError::Conflict("try_on_outfit_revision"));
        }
        require_active_credential(&transaction, &request.credential_id.to_string())?;
        let (outfit_name, outfit_created_revision): (String, i64) = transaction
            .query_row(
                "SELECT name, created_outfit_revision FROM outfits WHERE outfit_id = ?1",
                [request.outfit_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("try_on_outfit"))?;
        let store = BlobStore::new(&self.paths);
        let mut assets = vec![load_portrait_asset(
            &transaction,
            &store,
            &request.portrait_source_revision_id.to_string(),
        )?];
        assets.extend(load_garment_assets(
            &transaction,
            &store,
            &request.outfit_id.to_string(),
        )?);
        let aggregate = assets.iter().try_fold(0_u64, |total, asset| {
            total
                .checked_add(asset.canonical_byte_length as u64)
                .ok_or(PlatformError::InvalidInput("try_on_aggregate_size"))
        })?;
        if aggregate > TRY_ON_MAX_AGGREGATE_INPUT_BYTES {
            return Err(PlatformError::InvalidInput("try_on_aggregate_size"));
        }
        let asset_snapshot_sha256 = hash_json(
            &assets
                .iter()
                .map(SnapshotAsset::approval_binding)
                .collect::<Vec<_>>(),
        )?;
        let disclosure_assets = assets
            .iter()
            .map(SnapshotAsset::disclosure)
            .collect::<PlatformResult<Vec<_>>>()?;
        let expires_at_ms = now_ms
            .checked_add(APPROVAL_LIFETIME_MS)
            .ok_or(PlatformError::Corrupt("try_on_expiry"))?;
        let approval_id = stable_id("try-on-approval", &request.request_id.to_string());
        let response = PreviewTryOnV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            disclosure: TryOnDisclosureV1 {
                provider: TRY_ON_PROVIDER_V1.to_owned(),
                model: TRY_ON_MODEL_V1.to_owned(),
                purpose: TRY_ON_PURPOSE_V1.to_owned(),
                prompt_revision: TRY_ON_PROMPT_REVISION_V1.to_owned(),
                assets: disclosure_assets,
                retention: TryOnRetentionDisclosureV1 {
                    revision: TRY_ON_DISCLOSURE_REVISION_V1.to_owned(),
                    declaration: request.retention.clone(),
                    images_api_has_application_state_retention: false,
                    default_abuse_monitoring_max_days: 30,
                    model_is_zdr_compatible: true,
                    compatibility_is_not_project_enrollment: true,
                    csam_input_scanning_applies: true,
                    flagged_inputs_may_be_retained_for_review: true,
                },
            },
            approval: TryOnApprovalV1 {
                approval_id: parse_id(&approval_id)?,
                outfit_id: request.outfit_id,
                expires_at: timestamp(expires_at_ms)?,
                single_use: true,
                garment_count: (assets.len() - 1) as u8,
                asset_snapshot_sha256: Sha256Digest::parse(asset_snapshot_sha256.clone())
                    .map_err(|_| PlatformError::Corrupt("try_on_snapshot_hash"))?,
                outfit_revision: outfit_revision as u64,
            },
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("try_on_preview_response"))?;
        transaction.execute(
            "INSERT INTO try_on_approvals(
                approval_id, preview_request_id, envelope_hash, outfit_id, outfit_name,
                outfit_created_revision, expected_outfit_revision, credential_id,
                provider, model, prompt_revision, disclosure_revision, retention_mode,
                retention_provenance, asset_snapshot_sha256, garment_count,
                expires_at_ms, consumed_request_id, created_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'openai', 'gpt-image-2',
                ?9, ?10, ?11, ?12, ?13, ?14, ?15, NULL, ?16
             )",
            params![
                approval_id,
                request.request_id.to_string(),
                envelope_hash,
                request.outfit_id.to_string(),
                outfit_name,
                outfit_created_revision,
                outfit_revision,
                request.credential_id.to_string(),
                TRY_ON_PROMPT_REVISION_V1,
                TRY_ON_DISCLOSURE_REVISION_V1,
                retention_mode(request.retention.mode),
                request.retention.provenance,
                asset_snapshot_sha256,
                assets.len() as i64 - 1,
                expires_at_ms,
                now_ms,
            ],
        )?;
        for asset in &assets {
            asset.insert(&transaction, &approval_id)?;
        }
        store_receipt(
            &transaction,
            PREVIEW_COMMAND,
            request,
            &response,
            &envelope_hash,
            now_ms,
        )?;
        transaction.execute(
            "UPDATE revision_state SET try_on_revision = try_on_revision + 1
             WHERE singleton = 1",
            [],
        )?;
        transaction.commit()?;
        Ok(response)
    }

    pub fn submit_try_on(
        &self,
        request: &SubmitTryOnV1Request,
        now_ms: i64,
    ) -> PlatformResult<SubmitTryOnV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("try_on_submit"))?;
        let envelope_hash = hash_json(request)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) = replay::<SubmitTryOnV1Response, _>(
            &transaction,
            SUBMIT_COMMAND,
            request,
            &envelope_hash,
        )? {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let approval: (String, String, i64, i64, Option<String>) = transaction
            .query_row(
                "SELECT outfit_id, credential_id, expected_outfit_revision,
                        expires_at_ms, consumed_request_id
                 FROM try_on_approvals WHERE approval_id = ?1",
                [request.approval_id.to_string()],
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
            .optional()?
            .ok_or(PlatformError::Conflict("try_on_approval_missing"))?;
        if approval.4.is_some() {
            return Err(PlatformError::Conflict("try_on_approval_consumed"));
        }
        if approval.3 < now_ms {
            return Err(PlatformError::Conflict("try_on_approval_expired"));
        }
        let outfit_revision: i64 = transaction.query_row(
            "SELECT outfit_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if outfit_revision != approval.2 {
            return Err(PlatformError::Conflict("try_on_outfit_revision"));
        }
        require_active_credential(&transaction, &approval.1)?;
        let job_id = stable_id("try-on-job", &request.request_id.to_string());
        let response = SubmitTryOnV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            job: TryOnJobV1 {
                job_id: parse_id(&job_id)?,
                approval_id: request.approval_id,
                outfit_id: parse_id(&approval.0)?,
                state: TryOnJobStateV1::Queued,
                attempt_count: 0,
                created_at: timestamp(now_ms)?,
                updated_at: timestamp(now_ms)?,
                completed_at: None,
                failure: None,
            },
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("try_on_submit_response"))?;
        transaction.execute(
            "UPDATE try_on_approvals SET consumed_request_id = ?1
             WHERE approval_id = ?2 AND consumed_request_id IS NULL",
            params![
                request.request_id.to_string(),
                request.approval_id.to_string()
            ],
        )?;
        transaction.execute(
            "INSERT INTO try_on_jobs(
                job_id, request_id, approval_id, envelope_hash, pipeline_revision,
                state, available_at_ms, attempt_count, retry_limit, fence,
                lease_owner, lease_expires_at_ms, terminal_attempt_id, failure_code,
                retryable, user_action, created_at_ms, updated_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, 'queued', ?6, 0, 0, 0,
                NULL, NULL, NULL, NULL, 0, NULL, ?6, ?6
             )",
            params![
                job_id,
                request.request_id.to_string(),
                request.approval_id.to_string(),
                envelope_hash,
                PIPELINE_REVISION,
                now_ms,
            ],
        )?;
        store_receipt(
            &transaction,
            SUBMIT_COMMAND,
            request,
            &response,
            &envelope_hash,
            now_ms,
        )?;
        transaction.execute(
            "UPDATE revision_state SET try_on_revision = try_on_revision + 1
             WHERE singleton = 1",
            [],
        )?;
        transaction.commit()?;
        Ok(response)
    }

    pub fn get_outfit_try_on(
        &self,
        request: &GetOutfitTryOnV1Request,
    ) -> PlatformResult<GetOutfitTryOnV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("try_on_get"))?;
        let connection = self.connection()?;
        let outfit_name: String = connection
            .query_row(
                "SELECT name FROM outfits WHERE outfit_id = ?1",
                [request.outfit_id.to_string()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("try_on_outfit"))?;
        let try_on_revision: i64 = connection.query_row(
            "SELECT try_on_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        let job_id = connection
            .query_row(
                "SELECT job.job_id FROM try_on_jobs job
                 JOIN try_on_approvals approval ON approval.approval_id = job.approval_id
                 WHERE approval.outfit_id = ?1
                 ORDER BY job.created_at_ms DESC, job.job_id DESC LIMIT 1",
                [request.outfit_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let (latest_job, output, garment_sources) = if let Some(job_id) = job_id {
            (
                Some(load_job(&connection, &job_id)?),
                load_output(&connection, &self.paths, &job_id)?,
                load_garment_sources(&connection, &self.paths, &job_id)?,
            )
        } else {
            (None, None, Vec::new())
        };
        let response = GetOutfitTryOnV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            outfit_id: request.outfit_id,
            outfit_name,
            latest_job,
            output,
            garment_sources,
            try_on_revision: try_on_revision as u64,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("try_on_get_response"))?;
        Ok(response)
    }

    pub fn recover_try_on_jobs(&self, now_ms: i64) -> PlatformResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT job.job_id, attempt.attempt_id, attempt.fence, attempt.state,
                        attempt.output_sha256, attempt.output_byte_length
                 FROM try_on_jobs job JOIN try_on_attempts attempt ON attempt.job_id = job.job_id
                 WHERE job.state = 'running'",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        for (job_id, attempt_id, fence, state, output_sha256, output_length) in rows {
            match state.as_str() {
                "prepared" => {
                    let changed = transaction.execute(
                        "UPDATE try_on_jobs SET state = 'queued', attempt_count = 0,
                            lease_owner = NULL, lease_expires_at_ms = NULL, updated_at_ms = ?1
                         WHERE job_id = ?2 AND state = 'running' AND fence = ?3",
                        params![now_ms, job_id, fence],
                    )?;
                    if changed != 1 {
                        return Err(PlatformError::LeaseLost);
                    }
                }
                "dispatched" => fail_job(
                    &transaction,
                    &job_id,
                    &attempt_id,
                    fence,
                    TryOnFailureCodeV1::OutcomeUnknown,
                    now_ms,
                )?,
                "materializing" => {
                    let promoted =
                        output_sha256
                            .as_deref()
                            .zip(output_length)
                            .and_then(|(hash, length)| {
                                BlobStore::new(&self.paths)
                                    .verify(hash)
                                    .ok()
                                    .filter(|record| record.byte_length == length as u64)
                            });
                    if let Some(record) = promoted {
                        transaction.execute(
                            "INSERT OR IGNORE INTO blobs(sha256, byte_length, created_at_ms)
                             VALUES (?1, ?2, ?3)",
                            params![record.sha256, record.byte_length as i64, now_ms],
                        )?;
                        finalize_promoted_output(
                            &transaction,
                            &job_id,
                            &attempt_id,
                            fence,
                            output_sha256.as_deref().unwrap(),
                            output_length.unwrap(),
                            now_ms,
                        )?;
                    } else {
                        fail_job(
                            &transaction,
                            &job_id,
                            &attempt_id,
                            fence,
                            TryOnFailureCodeV1::OutputMaterializationInterrupted,
                            now_ms,
                        )?;
                    }
                }
                _ => return Err(PlatformError::Corrupt("try_on_attempt_state")),
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn claim_try_on_job(
        &self,
        owner: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> PlatformResult<Option<ClaimedTryOnJob>> {
        if owner.is_empty() || owner.len() > 128 || lease_ms <= 0 {
            return Err(PlatformError::InvalidInput("try_on_claim"));
        }
        loop {
            let mut connection = self.connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row = transaction
                .query_row(
                    "SELECT job_id, approval_id, fence FROM try_on_jobs
                 WHERE state = 'queued' AND available_at_ms <= ?1
                 ORDER BY available_at_ms, created_at_ms, job_id LIMIT 1",
                    [now_ms],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .optional()?;
            let Some((job_id, approval_id, prior_fence)) = row else {
                transaction.commit()?;
                return Ok(None);
            };
            let fence = prior_fence
                .checked_add(1)
                .ok_or(PlatformError::Corrupt("try_on_fence"))?;
            let lease_expires = now_ms
                .checked_add(lease_ms)
                .ok_or(PlatformError::Corrupt("try_on_lease"))?;
            transaction.execute(
                "UPDATE try_on_jobs SET state = 'running', attempt_count = 1,
                fence = ?1, lease_owner = ?2, lease_expires_at_ms = ?3, updated_at_ms = ?4
             WHERE job_id = ?5 AND state = 'queued'",
                params![fence, owner, lease_expires, now_ms, job_id],
            )?;
            let attempt_id = stable_id("try-on-attempt", &job_id);
            transaction.execute(
                "INSERT INTO try_on_attempts(
                attempt_id, job_id, attempt_ordinal, fence, state, provider_request_id,
                audit_json, output_sha256, output_byte_length, output_width, output_height,
                failure_code, retryable, user_action, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, 1, ?3, 'prepared', NULL, NULL, NULL, NULL, NULL, NULL,
                       NULL, 0, NULL, ?4, ?4)
             ON CONFLICT(job_id) DO UPDATE SET fence = excluded.fence, state = 'prepared',
                provider_request_id = NULL, audit_json = NULL, output_sha256 = NULL,
                output_byte_length = NULL, output_width = NULL, output_height = NULL,
                failure_code = NULL, retryable = 0, user_action = NULL,
                updated_at_ms = excluded.updated_at_ms",
                params![attempt_id, job_id, fence, now_ms],
            )?;
            let assets = match prepare_assets(&transaction, &self.paths, &approval_id) {
                Ok(assets) => assets,
                Err(error) => {
                    fail_job(
                        &transaction,
                        &job_id,
                        &attempt_id,
                        fence,
                        asset_failure_code(&error),
                        now_ms,
                    )?;
                    transaction.commit()?;
                    continue;
                }
            };
            transaction.commit()?;
            return Ok(Some(ClaimedTryOnJob {
                job_id,
                attempt_id,
                fence,
                assets,
            }));
        }
    }

    pub fn authorize_try_on_transport(
        &self,
        claim: &ClaimedTryOnJob,
        now_ms: i64,
    ) -> PlatformResult<CredentialLocator> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let locator = transaction
            .query_row(
                "SELECT credential.locator FROM try_on_jobs job
                 JOIN try_on_approvals approval ON approval.approval_id = job.approval_id
                 JOIN credential_references credential
                   ON credential.credential_id = approval.credential_id
                 JOIN try_on_attempts attempt ON attempt.job_id = job.job_id
                 WHERE job.job_id = ?1 AND job.state = 'running' AND job.fence = ?2
                   AND attempt.attempt_id = ?3 AND attempt.fence = ?2
                   AND attempt.state = 'prepared' AND credential.provider = 'open_ai'
                   AND credential.status = 'active'",
                params![claim.job_id, claim.fence, claim.attempt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(PlatformError::Conflict("try_on_transport_authority"))?;
        transaction.execute(
            "UPDATE try_on_attempts SET state = 'dispatched', updated_at_ms = ?1
             WHERE attempt_id = ?2 AND state = 'prepared' AND fence = ?3",
            params![now_ms, claim.attempt_id, claim.fence],
        )?;
        transaction.commit()?;
        CredentialLocator::new(locator)
            .map_err(|_| PlatformError::Corrupt("try_on_credential_locator"))
    }

    pub fn mark_try_on_transport_started(
        &self,
        claim: &ClaimedTryOnJob,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let audit_json = serde_json::to_string(&serde_json::json!({
            "transport_started_at_ms": now_ms,
            "automatic_retry": false
        }))?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE try_on_attempts SET audit_json = ?1, updated_at_ms = ?2
             WHERE attempt_id = ?3 AND job_id = ?4 AND fence = ?5
               AND state = 'dispatched' AND audit_json IS NULL",
            params![
                audit_json,
                now_ms,
                claim.attempt_id,
                claim.job_id,
                claim.fence
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::LeaseLost);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn clear_try_on_transport_started(
        &self,
        claim: &ClaimedTryOnJob,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE try_on_attempts SET audit_json = NULL, updated_at_ms = ?1
             WHERE attempt_id = ?2 AND job_id = ?3 AND fence = ?4
               AND state = 'dispatched' AND audit_json IS NOT NULL",
            params![now_ms, claim.attempt_id, claim.job_id, claim.fence],
        )?;
        if changed != 1 {
            return Err(PlatformError::LeaseLost);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn begin_try_on_output(
        &self,
        claim: &ClaimedTryOnJob,
        png_bytes: &[u8],
        audit_json: &str,
        now_ms: i64,
    ) -> PlatformResult<String> {
        let hash = format!("{:x}", Sha256::digest(png_bytes));
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE try_on_attempts SET state = 'materializing', audit_json = ?1,
                output_sha256 = ?2, output_byte_length = ?3, output_width = 1024,
                output_height = 1536, updated_at_ms = ?4
             WHERE attempt_id = ?5 AND job_id = ?6 AND fence = ?7 AND state = 'dispatched'",
            params![
                audit_json,
                hash,
                png_bytes.len() as i64,
                now_ms,
                claim.attempt_id,
                claim.job_id,
                claim.fence
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::LeaseLost);
        }
        transaction.commit()?;
        Ok(hash)
    }

    pub fn finalize_try_on_output(
        &self,
        claim: &ClaimedTryOnJob,
        png_bytes: &[u8],
        expected_sha256: &str,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let record = BlobStore::new(&self.paths).put(
            png_bytes,
            Some(expected_sha256),
            wardrobe_core::TRY_ON_MAX_OUTPUT_BYTES as u64,
        )?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT OR IGNORE INTO blobs(sha256, byte_length, created_at_ms)
             VALUES (?1, ?2, ?3)",
            params![record.sha256, record.byte_length as i64, now_ms],
        )?;
        finalize_promoted_output(
            &transaction,
            &claim.job_id,
            &claim.attempt_id,
            claim.fence,
            &record.sha256,
            record.byte_length as i64,
            now_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn fail_try_on_job(
        &self,
        claim: &ClaimedTryOnJob,
        code: TryOnFailureCodeV1,
        now_ms: i64,
    ) -> PlatformResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        fail_job(
            &transaction,
            &claim.job_id,
            &claim.attempt_id,
            claim.fence,
            code,
            now_ms,
        )?;
        transaction.commit()?;
        Ok(())
    }
}

#[derive(Clone)]
struct SnapshotAsset {
    ordinal: u8,
    role: TryOnAssetRoleV1,
    source_revision_id: Option<String>,
    artifact_id: Option<String>,
    item_id: Option<String>,
    evidence_id: Option<String>,
    source_id: Option<String>,
    item_updated_revision: Option<i64>,
    attributes_json: Option<String>,
    parent_blob_sha256: String,
    parent_media_type: String,
    parent_byte_length: i64,
    parent_width: i64,
    parent_height: i64,
    canonical_sha256: String,
    canonical_byte_length: i64,
    canonical_width: i64,
    canonical_height: i64,
}

#[derive(Serialize)]
struct ApprovalAssetBinding {
    ordinal: u8,
    role: &'static str,
    source_revision_id: Option<String>,
    item_id: Option<String>,
    evidence_id: Option<String>,
    source_id: Option<String>,
    item_updated_revision: Option<i64>,
    attributes_json: Option<String>,
    parent_blob_sha256: String,
    parent_media_type: String,
    parent_byte_length: i64,
    parent_width: i64,
    parent_height: i64,
    canonical_sha256: String,
    canonical_byte_length: i64,
    canonical_width: i64,
    canonical_height: i64,
}

impl SnapshotAsset {
    fn approval_binding(&self) -> ApprovalAssetBinding {
        ApprovalAssetBinding {
            ordinal: self.ordinal,
            role: role_db(self.role),
            source_revision_id: self.source_revision_id.clone(),
            item_id: self.item_id.clone(),
            evidence_id: self.evidence_id.clone(),
            source_id: self.source_id.clone(),
            item_updated_revision: self.item_updated_revision,
            attributes_json: self.attributes_json.clone(),
            parent_blob_sha256: self.parent_blob_sha256.clone(),
            parent_media_type: self.parent_media_type.clone(),
            parent_byte_length: self.parent_byte_length,
            parent_width: self.parent_width,
            parent_height: self.parent_height,
            canonical_sha256: self.canonical_sha256.clone(),
            canonical_byte_length: self.canonical_byte_length,
            canonical_width: self.canonical_width,
            canonical_height: self.canonical_height,
        }
    }

    fn disclosure(&self) -> PlatformResult<TryOnDisclosureAssetV1> {
        Ok(TryOnDisclosureAssetV1 {
            ordinal: self.ordinal,
            role: self.role,
            transmitted_filename: format!("reference-{:02}.png", self.ordinal),
            portrait_source_revision_id: self
                .source_revision_id
                .as_deref()
                .map(parse_id)
                .transpose()?,
            portrait_artifact_id: self.artifact_id.as_deref().map(parse_id).transpose()?,
            item_id: self.item_id.as_deref().map(parse_id).transpose()?,
            evidence_id: self.evidence_id.as_deref().map(parse_id).transpose()?,
            source_id: self.source_id.as_deref().map(parse_id).transpose()?,
            canonical_sha256: Sha256Digest::parse(self.canonical_sha256.clone())
                .map_err(|_| PlatformError::Corrupt("try_on_canonical_hash"))?,
            media_type: TRY_ON_OUTPUT_MEDIA_TYPE_V1.to_owned(),
            byte_length: self.canonical_byte_length as u64,
            width: self.canonical_width as u32,
            height: self.canonical_height as u32,
        })
    }

    fn insert(&self, transaction: &Transaction<'_>, approval_id: &str) -> PlatformResult<()> {
        transaction.execute(
            "INSERT INTO try_on_assets(
                approval_id, asset_ordinal, role, source_revision_id, item_id, evidence_id,
                source_id, item_updated_revision, attributes_json, parent_blob_sha256,
                parent_media_type, parent_byte_length, parent_width, parent_height,
                canonical_png_sha256, canonical_byte_length, canonical_width, canonical_height
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                       ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                approval_id,
                i64::from(self.ordinal),
                role_db(self.role),
                self.source_revision_id,
                self.item_id,
                self.evidence_id,
                self.source_id,
                self.item_updated_revision,
                self.attributes_json,
                self.parent_blob_sha256,
                self.parent_media_type,
                self.parent_byte_length,
                self.parent_width,
                self.parent_height,
                self.canonical_sha256,
                self.canonical_byte_length,
                self.canonical_width,
                self.canonical_height,
            ],
        )?;
        Ok(())
    }
}

fn load_portrait_asset(
    transaction: &Transaction<'_>,
    store: &BlobStore,
    source_revision_id: &str,
) -> PlatformResult<SnapshotAsset> {
    let row: (String, String, i64, String, i64, i64) = transaction
        .query_row(
            "SELECT artifact.artifact_id, revision.blob_sha256, revision.byte_length,
                    revision.media_type, revision.width, revision.height
             FROM photo_source_revisions revision
             JOIN photo_artifacts artifact
               ON artifact.source_revision_id = revision.source_revision_id
             WHERE revision.source_revision_id = ?1 AND revision.disposition = 'eligible'
               AND revision.blob_sha256 IS NOT NULL
             ORDER BY artifact.artifact_id LIMIT 1",
            [source_revision_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::Conflict("try_on_portrait_unavailable"))?;
    snapshot_asset(
        store,
        0,
        TryOnAssetRoleV1::Portrait,
        Some(source_revision_id.to_owned()),
        Some(row.0),
        None,
        None,
        None,
        None,
        None,
        row.1,
        row.2,
        row.3,
        row.4,
        row.5,
    )
}

fn load_garment_assets(
    transaction: &Transaction<'_>,
    store: &BlobStore,
    outfit_id: &str,
) -> PlatformResult<Vec<SnapshotAsset>> {
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT ordinal, item_id, evidence_id, source_id, item_updated_revision,
                    attributes_json, blob_sha256, media_type, byte_length, width, height
             FROM outfit_members WHERE outfit_id = ?1 AND asset_state = 'available'
             ORDER BY ordinal",
        )?;
        let rows = statement
            .query_map([outfit_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let total: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM outfit_members WHERE outfit_id = ?1",
        [outfit_id],
        |row| row.get(0),
    )?;
    if rows.len() != total as usize || !(2..=8).contains(&rows.len()) {
        return Err(PlatformError::Conflict("try_on_garment_unavailable"));
    }
    rows.into_iter()
        .map(|row| {
            snapshot_asset(
                store,
                row.0 as u8 + 1,
                TryOnAssetRoleV1::Garment,
                None,
                None,
                Some(row.1),
                Some(row.2),
                Some(row.3),
                Some(row.4),
                Some(row.5),
                row.6,
                row.8,
                row.7,
                row.9,
                row.10,
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn snapshot_asset(
    store: &BlobStore,
    ordinal: u8,
    role: TryOnAssetRoleV1,
    source_revision_id: Option<String>,
    artifact_id: Option<String>,
    item_id: Option<String>,
    evidence_id: Option<String>,
    source_id: Option<String>,
    item_updated_revision: Option<i64>,
    attributes_json: Option<String>,
    parent_blob_sha256: String,
    parent_byte_length: i64,
    parent_media_type: String,
    parent_width: i64,
    parent_height: i64,
) -> PlatformResult<SnapshotAsset> {
    let canonical = canonical_try_on_png(store, &parent_blob_sha256, to_u64(parent_byte_length)?)?;
    Ok(SnapshotAsset {
        ordinal,
        role,
        source_revision_id,
        artifact_id,
        item_id,
        evidence_id,
        source_id,
        item_updated_revision,
        attributes_json,
        parent_blob_sha256,
        parent_media_type,
        parent_byte_length,
        parent_width,
        parent_height,
        canonical_sha256: canonical.sha256,
        canonical_byte_length: canonical.bytes.len() as i64,
        canonical_width: i64::from(canonical.width),
        canonical_height: i64::from(canonical.height),
    })
}

fn prepare_assets(
    transaction: &Transaction<'_>,
    paths: &PrivateAppPaths,
    approval_id: &str,
) -> PlatformResult<Vec<PreparedTryOnAsset>> {
    let expected_snapshot: String = transaction.query_row(
        "SELECT asset_snapshot_sha256 FROM try_on_approvals WHERE approval_id = ?1",
        [approval_id],
        |row| row.get(0),
    )?;
    let current_snapshot = hash_json(&load_approval_asset_bindings(transaction, approval_id)?)?;
    if current_snapshot != expected_snapshot {
        return Err(PlatformError::Conflict("try_on_snapshot_stale"));
    }
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT asset_ordinal, role, parent_blob_sha256, parent_byte_length,
                    canonical_png_sha256, canonical_byte_length,
                    canonical_width, canonical_height
             FROM try_on_assets WHERE approval_id = ?1 ORDER BY asset_ordinal",
        )?;
        let rows = statement
            .query_map([approval_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let store = BlobStore::new(paths);
    rows.into_iter()
        .map(|row| {
            let canonical = canonical_try_on_png(&store, &row.2, to_u64(row.3)?)?;
            if canonical.sha256 != row.4
                || canonical.bytes.len() as i64 != row.5
                || i64::from(canonical.width) != row.6
                || i64::from(canonical.height) != row.7
            {
                return Err(PlatformError::Conflict("try_on_snapshot_stale"));
            }
            Ok(PreparedTryOnAsset {
                ordinal: row.0 as u8,
                role: parse_role(&row.1)?,
                png_bytes: canonical.bytes,
                canonical_sha256: canonical.sha256,
            })
        })
        .collect()
}

fn load_approval_asset_bindings(
    transaction: &Transaction<'_>,
    approval_id: &str,
) -> PlatformResult<Vec<ApprovalAssetBinding>> {
    let mut statement = transaction.prepare(
        "SELECT asset_ordinal, role, source_revision_id, item_id, evidence_id, source_id,
                item_updated_revision, attributes_json, parent_blob_sha256, parent_media_type,
                parent_byte_length, parent_width, parent_height, canonical_png_sha256,
                canonical_byte_length, canonical_width, canonical_height
         FROM try_on_assets WHERE approval_id = ?1 ORDER BY asset_ordinal",
    )?;
    let bindings = statement
        .query_map([approval_id], |row| {
            let role = row.get::<_, String>(1)?;
            Ok((
                row.get::<_, i64>(0)?,
                role,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, i64>(11)?,
                row.get::<_, i64>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, i64>(14)?,
                row.get::<_, i64>(15)?,
                row.get::<_, i64>(16)?,
            ))
        })?
        .map(|row| {
            let row = row?;
            Ok(ApprovalAssetBinding {
                ordinal: u8::try_from(row.0)
                    .map_err(|_| PlatformError::Corrupt("try_on_asset_ordinal"))?,
                role: role_db(parse_role(&row.1)?),
                source_revision_id: row.2,
                item_id: row.3,
                evidence_id: row.4,
                source_id: row.5,
                item_updated_revision: row.6,
                attributes_json: row.7,
                parent_blob_sha256: row.8,
                parent_media_type: row.9,
                parent_byte_length: row.10,
                parent_width: row.11,
                parent_height: row.12,
                canonical_sha256: row.13,
                canonical_byte_length: row.14,
                canonical_width: row.15,
                canonical_height: row.16,
            })
        })
        .collect();
    bindings
}

fn load_job(connection: &rusqlite::Connection, job_id: &str) -> PlatformResult<TryOnJobV1> {
    let row: (String, String, String, i64, i64, i64, Option<String>) = connection.query_row(
        "SELECT approval.approval_id, approval.outfit_id, job.state, job.attempt_count,
                job.created_at_ms, job.updated_at_ms, job.failure_code
         FROM try_on_jobs job
         JOIN try_on_approvals approval ON approval.approval_id = job.approval_id
         WHERE job.job_id = ?1",
        [job_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        },
    )?;
    let state = parse_job_state(&row.2)?;
    let job = TryOnJobV1 {
        job_id: parse_id(job_id)?,
        approval_id: parse_id(&row.0)?,
        outfit_id: parse_id(&row.1)?,
        state,
        attempt_count: row.3 as u8,
        created_at: timestamp(row.4)?,
        updated_at: timestamp(row.5)?,
        completed_at: matches!(state, TryOnJobStateV1::Succeeded | TryOnJobStateV1::Failed)
            .then(|| timestamp(row.5))
            .transpose()?,
        failure: row
            .6
            .as_deref()
            .map(parse_failure_code)
            .transpose()?
            .map(failure_contract)
            .transpose()?,
    };
    job.validate()
        .map_err(|_| PlatformError::Corrupt("try_on_job_contract"))?;
    Ok(job)
}

fn load_output(
    connection: &rusqlite::Connection,
    paths: &PrivateAppPaths,
    job_id: &str,
) -> PlatformResult<Option<TryOnOutputV1>> {
    let row = connection.query_row(
        "SELECT approval.outfit_id, output.blob_sha256, output.byte_length, output.created_at_ms
         FROM try_on_outputs output
         JOIN try_on_jobs job ON job.job_id = output.job_id
         JOIN try_on_approvals approval ON approval.approval_id = job.approval_id
         WHERE output.job_id = ?1",
        [job_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?)),
    ).optional()?;
    let Some((outfit_id, sha256, length, created_at)) = row else {
        return Ok(None);
    };
    let record = BlobStore::new(paths).verify(&sha256)?;
    if record.byte_length != length as u64 {
        return Err(PlatformError::Corrupt("try_on_output_length"));
    }
    let bytes = fs::read(record.path)?;
    let image = image::load_from_memory_with_format(&bytes, image::ImageFormat::Png)
        .map_err(|_| PlatformError::Corrupt("try_on_output_png"))?;
    if image.width() != TRY_ON_OUTPUT_WIDTH_V1 || image.height() != TRY_ON_OUTPUT_HEIGHT_V1 {
        return Err(PlatformError::Corrupt("try_on_output_dimensions"));
    }
    Ok(Some(TryOnOutputV1 {
        job_id: parse_id(job_id)?,
        outfit_id: parse_id(&outfit_id)?,
        media_type: TRY_ON_OUTPUT_MEDIA_TYPE_V1.to_owned(),
        width: TRY_ON_OUTPUT_WIDTH_V1,
        height: TRY_ON_OUTPUT_HEIGHT_V1,
        bytes_sha256: Sha256Digest::parse(sha256)
            .map_err(|_| PlatformError::Corrupt("try_on_output_hash"))?,
        bytes: BoundedTryOnOutputBytesV1::new(bytes)
            .map_err(|_| PlatformError::Corrupt("try_on_output_bytes"))?,
        use_class: TryOnOutputUseClassV1::PresentationOnly,
        eligible_as_evidence: false,
        label: TRY_ON_PRESENTATION_LABEL_V1.to_owned(),
        created_at: timestamp(created_at)?,
    }))
}

fn load_garment_sources(
    connection: &rusqlite::Connection,
    paths: &PrivateAppPaths,
    job_id: &str,
) -> PlatformResult<Vec<TryOnGarmentSourceV1>> {
    let rows = {
        let mut statement = connection.prepare(
            "SELECT asset.asset_ordinal, asset.item_id, asset.item_updated_revision,
                    asset.attributes_json, asset.evidence_id, asset.source_id,
                    asset.parent_blob_sha256, asset.parent_media_type,
                    asset.parent_byte_length, asset.parent_width, asset.parent_height
             FROM try_on_assets asset
             JOIN try_on_jobs job ON job.approval_id = asset.approval_id
             WHERE job.job_id = ?1 AND asset.role = 'garment'
             ORDER BY asset.asset_ordinal",
        )?;
        let rows = statement
            .query_map([job_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    let store = BlobStore::new(paths);
    rows.into_iter()
        .map(|row| {
            let source = verify_source_image(&store, &row.6, to_u64(row.8)?)
                .map_err(|_| PlatformError::Corrupt("try_on_garment_source"))?;
            if media_type_db(source.media_type) != row.7
                || i64::from(source.width) != row.9
                || i64::from(source.height) != row.10
            {
                return Err(PlatformError::Corrupt("try_on_garment_changed"));
            }
            Ok(TryOnGarmentSourceV1 {
                ordinal: row.0 as u8,
                item_id: parse_id(&row.1)?,
                item_updated_revision: row.2 as u64,
                attributes: serde_json::from_str::<ItemAttributesV1>(&row.3)?,
                evidence_id: parse_id(&row.4)?,
                source_id: parse_id(&row.5)?,
                media_type: source.media_type,
                width: source.width,
                height: source.height,
                bytes_sha256: Sha256Digest::from_bytes(&source.bytes),
                bytes: BoundedPhotoArtifactBytesV1::new(source.bytes)
                    .map_err(|_| PlatformError::Corrupt("try_on_garment_bytes"))?,
            })
        })
        .collect()
}

fn finalize_promoted_output(
    transaction: &Transaction<'_>,
    job_id: &str,
    attempt_id: &str,
    fence: i64,
    sha256: &str,
    byte_length: i64,
    now_ms: i64,
) -> PlatformResult<()> {
    let asset_snapshot: String = transaction.query_row(
        "SELECT approval.asset_snapshot_sha256 FROM try_on_jobs job
         JOIN try_on_approvals approval ON approval.approval_id = job.approval_id
         WHERE job.job_id = ?1",
        [job_id],
        |row| row.get(0),
    )?;
    let provenance_json = serde_json::to_string(&serde_json::json!({
        "provider": TRY_ON_PROVIDER_V1,
        "model": TRY_ON_MODEL_V1,
        "prompt_revision": TRY_ON_PROMPT_REVISION_V1,
        "asset_snapshot_sha256": asset_snapshot,
        "size": "1024x1536",
        "quality": "low",
        "output_format": "png"
    }))?;
    let provenance_sha256 = format!("{:x}", Sha256::digest(provenance_json.as_bytes()));
    transaction.execute(
        "INSERT OR IGNORE INTO try_on_outputs(
            output_id, job_id, blob_sha256, media_type, byte_length, width, height,
            provenance_json, provenance_sha256, label_revision, use_class,
            eligible_as_evidence, created_at_ms
         ) VALUES (?1, ?2, ?3, 'image/png', ?4, 1024, 1536, ?5, ?6, ?7,
                   'presentation_only', 0, ?8)",
        params![
            stable_id("try-on-output", job_id),
            job_id,
            sha256,
            byte_length,
            provenance_json,
            provenance_sha256,
            LABEL_REVISION,
            now_ms
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE try_on_attempts SET state = 'succeeded', updated_at_ms = ?1
         WHERE attempt_id = ?2 AND state = 'materializing'
           AND fence = ?3 AND output_sha256 = ?4 AND output_byte_length = ?5",
        params![now_ms, attempt_id, fence, sha256, byte_length],
    )?;
    if changed != 1 {
        return Err(PlatformError::LeaseLost);
    }
    let changed = transaction.execute(
        "UPDATE try_on_jobs SET state = 'succeeded', terminal_attempt_id = ?1,
            lease_owner = NULL, lease_expires_at_ms = NULL, updated_at_ms = ?2
         WHERE job_id = ?3 AND state = 'running' AND fence = ?4",
        params![attempt_id, now_ms, job_id, fence],
    )?;
    if changed != 1 {
        return Err(PlatformError::LeaseLost);
    }
    transaction.execute(
        "UPDATE revision_state SET try_on_revision = try_on_revision + 1 WHERE singleton = 1",
        [],
    )?;
    Ok(())
}

fn fail_job(
    transaction: &Transaction<'_>,
    job_id: &str,
    attempt_id: &str,
    fence: i64,
    code: TryOnFailureCodeV1,
    now_ms: i64,
) -> PlatformResult<()> {
    let failure = failure_contract(code)?;
    let code_text = failure_code_db(code);
    let action = user_action_db(failure.user_action);
    let changed = transaction.execute(
        "UPDATE try_on_attempts SET state = 'failed', failure_code = ?1,
            retryable = ?2, user_action = ?3, updated_at_ms = ?4
         WHERE attempt_id = ?5 AND state IN ('prepared', 'dispatched', 'materializing')
           AND fence = ?6",
        params![
            code_text,
            i64::from(failure.retryable),
            action,
            now_ms,
            attempt_id,
            fence
        ],
    )?;
    if changed != 1 {
        return Err(PlatformError::LeaseLost);
    }
    let changed = transaction.execute(
        "UPDATE try_on_jobs SET state = 'failed', terminal_attempt_id = ?1,
            failure_code = ?2, retryable = ?3, user_action = ?4,
            lease_owner = NULL, lease_expires_at_ms = NULL, updated_at_ms = ?5
         WHERE job_id = ?6 AND state IN ('queued', 'running') AND fence = ?7",
        params![
            attempt_id,
            code_text,
            i64::from(failure.retryable),
            action,
            now_ms,
            job_id,
            fence
        ],
    )?;
    if changed != 1 {
        return Err(PlatformError::LeaseLost);
    }
    transaction.execute(
        "UPDATE revision_state SET try_on_revision = try_on_revision + 1 WHERE singleton = 1",
        [],
    )?;
    Ok(())
}

fn replay<R: DeserializeOwned, Q: Serialize>(
    transaction: &Transaction<'_>,
    command: &str,
    request: &Q,
    envelope_hash: &str,
) -> PlatformResult<Option<R>> {
    let row = transaction
        .query_row(
            "SELECT command_name, envelope_hash, response_json
         FROM command_receipts WHERE request_id = ?1",
            [request_id(request)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((stored_command, stored_hash, response_json)) = row else {
        return Ok(None);
    };
    if stored_command != command || stored_hash != envelope_hash {
        return Err(PlatformError::Conflict("try_on_request_reuse"));
    }
    Ok(Some(serde_json::from_str(&response_json)?))
}

fn store_receipt<Q: Serialize, R: Serialize>(
    transaction: &Transaction<'_>,
    command: &str,
    request: &Q,
    response: &R,
    envelope_hash: &str,
    now_ms: i64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO command_receipts(
            request_id, command_name, envelope_hash, response_json, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            request_id(request)?,
            command,
            envelope_hash,
            serde_json::to_string(response)?,
            now_ms
        ],
    )?;
    Ok(())
}

fn require_active_credential(
    transaction: &Transaction<'_>,
    credential_id: &str,
) -> PlatformResult<()> {
    transaction
        .query_row(
            "SELECT 1 FROM credential_references
         WHERE credential_id = ?1 AND provider = 'open_ai' AND status = 'active'",
            [credential_id],
            |_| Ok(()),
        )
        .optional()?
        .ok_or(PlatformError::Conflict("try_on_credential_unavailable"))
}

fn asset_failure_code(error: &PlatformError) -> TryOnFailureCodeV1 {
    match error {
        PlatformError::Conflict("try_on_snapshot_stale") => TryOnFailureCodeV1::SnapshotStale,
        PlatformError::Io(_) => TryOnFailureCodeV1::AssetUnavailable,
        _ => TryOnFailureCodeV1::AssetIntegrity,
    }
}

fn failure_contract(code: TryOnFailureCodeV1) -> PlatformResult<TryOnFailureV1> {
    let (retryable, user_action) = match code {
        TryOnFailureCodeV1::ModerationBlocked => (false, TryOnUserActionV1::ReviewSourceAssets),
        TryOnFailureCodeV1::Cancelled => (false, TryOnUserActionV1::None),
        TryOnFailureCodeV1::RateLimited | TryOnFailureCodeV1::ProviderFailure => {
            (true, TryOnUserActionV1::StartNewPreview)
        }
        TryOnFailureCodeV1::ProviderUnavailable => (true, TryOnUserActionV1::RetryWhenAvailable),
        TryOnFailureCodeV1::OutcomeUnknown => (false, TryOnUserActionV1::ReviewProviderStatus),
        TryOnFailureCodeV1::Authentication
        | TryOnFailureCodeV1::PermissionDenied
        | TryOnFailureCodeV1::CredentialUnavailable => {
            (true, TryOnUserActionV1::CheckOpenAiCredential)
        }
        TryOnFailureCodeV1::RequestRejected
        | TryOnFailureCodeV1::SnapshotStale
        | TryOnFailureCodeV1::AssetUnavailable
        | TryOnFailureCodeV1::AssetIntegrity => (true, TryOnUserActionV1::ReviewSourceAssets),
        TryOnFailureCodeV1::ProviderProtocol
        | TryOnFailureCodeV1::ApprovalExpired
        | TryOnFailureCodeV1::ApprovalConsumed
        | TryOnFailureCodeV1::OutputMaterializationInterrupted => {
            (true, TryOnUserActionV1::StartNewPreview)
        }
    };
    let failure = TryOnFailureV1 {
        code,
        retryable,
        user_action,
    };
    failure
        .validate()
        .map_err(|_| PlatformError::Corrupt("try_on_failure_contract"))?;
    Ok(failure)
}

fn parse_job_state(value: &str) -> PlatformResult<TryOnJobStateV1> {
    match value {
        "queued" => Ok(TryOnJobStateV1::Queued),
        "running" => Ok(TryOnJobStateV1::Running),
        "succeeded" => Ok(TryOnJobStateV1::Succeeded),
        "failed" => Ok(TryOnJobStateV1::Failed),
        _ => Err(PlatformError::Corrupt("try_on_job_state")),
    }
}

fn parse_role(value: &str) -> PlatformResult<TryOnAssetRoleV1> {
    match value {
        "portrait" => Ok(TryOnAssetRoleV1::Portrait),
        "garment" => Ok(TryOnAssetRoleV1::Garment),
        _ => Err(PlatformError::Corrupt("try_on_asset_role")),
    }
}

fn role_db(value: TryOnAssetRoleV1) -> &'static str {
    match value {
        TryOnAssetRoleV1::Portrait => "portrait",
        TryOnAssetRoleV1::Garment => "garment",
    }
}

fn parse_failure_code(value: &str) -> PlatformResult<TryOnFailureCodeV1> {
    match value {
        "moderation_blocked" => Ok(TryOnFailureCodeV1::ModerationBlocked),
        "rate_limited" => Ok(TryOnFailureCodeV1::RateLimited),
        "provider_failure" => Ok(TryOnFailureCodeV1::ProviderFailure),
        "provider_unavailable" => Ok(TryOnFailureCodeV1::ProviderUnavailable),
        "outcome_unknown" => Ok(TryOnFailureCodeV1::OutcomeUnknown),
        "authentication" => Ok(TryOnFailureCodeV1::Authentication),
        "permission_denied" => Ok(TryOnFailureCodeV1::PermissionDenied),
        "request_rejected" => Ok(TryOnFailureCodeV1::RequestRejected),
        "provider_protocol" => Ok(TryOnFailureCodeV1::ProviderProtocol),
        "credential_unavailable" => Ok(TryOnFailureCodeV1::CredentialUnavailable),
        "approval_expired" => Ok(TryOnFailureCodeV1::ApprovalExpired),
        "approval_consumed" => Ok(TryOnFailureCodeV1::ApprovalConsumed),
        "source_stale" => Ok(TryOnFailureCodeV1::SnapshotStale),
        "asset_unavailable" => Ok(TryOnFailureCodeV1::AssetUnavailable),
        "asset_integrity" => Ok(TryOnFailureCodeV1::AssetIntegrity),
        "output_materialization_interrupted" => {
            Ok(TryOnFailureCodeV1::OutputMaterializationInterrupted)
        }
        "cancelled" => Ok(TryOnFailureCodeV1::Cancelled),
        _ => Err(PlatformError::Corrupt("try_on_failure_code")),
    }
}

fn failure_code_db(value: TryOnFailureCodeV1) -> &'static str {
    match value {
        TryOnFailureCodeV1::ModerationBlocked => "moderation_blocked",
        TryOnFailureCodeV1::RateLimited => "rate_limited",
        TryOnFailureCodeV1::ProviderFailure => "provider_failure",
        TryOnFailureCodeV1::ProviderUnavailable => "provider_unavailable",
        TryOnFailureCodeV1::OutcomeUnknown => "outcome_unknown",
        TryOnFailureCodeV1::Authentication => "authentication",
        TryOnFailureCodeV1::PermissionDenied => "permission_denied",
        TryOnFailureCodeV1::RequestRejected => "request_rejected",
        TryOnFailureCodeV1::ProviderProtocol => "provider_protocol",
        TryOnFailureCodeV1::CredentialUnavailable => "credential_unavailable",
        TryOnFailureCodeV1::ApprovalExpired => "approval_expired",
        TryOnFailureCodeV1::ApprovalConsumed => "approval_consumed",
        TryOnFailureCodeV1::SnapshotStale => "source_stale",
        TryOnFailureCodeV1::AssetUnavailable => "asset_unavailable",
        TryOnFailureCodeV1::AssetIntegrity => "asset_integrity",
        TryOnFailureCodeV1::OutputMaterializationInterrupted => {
            "output_materialization_interrupted"
        }
        TryOnFailureCodeV1::Cancelled => "cancelled",
    }
}

fn user_action_db(value: TryOnUserActionV1) -> &'static str {
    match value {
        TryOnUserActionV1::None => "none",
        TryOnUserActionV1::StartNewPreview => "start_new_preview",
        TryOnUserActionV1::RetryWhenAvailable => "retry_when_available",
        TryOnUserActionV1::CheckOpenAiCredential => "check_open_ai_credential",
        TryOnUserActionV1::ReviewSourceAssets => "review_source_assets",
        TryOnUserActionV1::ReviewProviderStatus => "review_provider_status",
    }
}

fn retention_mode(value: OpenAiRetentionModeV1) -> &'static str {
    match value {
        OpenAiRetentionModeV1::Unknown => "unknown",
        OpenAiRetentionModeV1::Default => "default",
        OpenAiRetentionModeV1::Mam => "MAM",
        OpenAiRetentionModeV1::Zdr => "ZDR",
    }
}

fn media_type_db(value: PhotoMediaTypeV1) -> &'static str {
    match value {
        PhotoMediaTypeV1::ImageJpeg => "image/jpeg",
        PhotoMediaTypeV1::ImagePng => "image/png",
        PhotoMediaTypeV1::ImageWebp => "image/webp",
    }
}

fn parse_id<T: DeserializeOwned>(value: &str) -> PlatformResult<T> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|_| PlatformError::Corrupt("try_on_id"))
}

fn request_id<Q: Serialize>(request: &Q) -> PlatformResult<String> {
    serde_json::to_value(request)?
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(PlatformError::Corrupt("try_on_request_id"))
}

fn hash_json(value: &impl Serialize) -> PlatformResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn timestamp(milliseconds: i64) -> PlatformResult<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(milliseconds) * 1_000_000)
        .map_err(|_| PlatformError::Corrupt("try_on_timestamp"))?
        .format(&Rfc3339)
        .map_err(|_| PlatformError::Corrupt("try_on_timestamp"))
}

fn to_u64(value: i64) -> PlatformResult<u64> {
    u64::try_from(value).map_err(|_| PlatformError::Corrupt("try_on_integer"))
}

fn parse_cursor(cursor: Option<&PageCursorV1>, revision: u64) -> PlatformResult<u64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let (stored_revision, offset) = cursor
        .as_str()
        .split_once(':')
        .ok_or(PlatformError::InvalidInput("try_on_cursor"))?;
    if stored_revision.parse::<u64>().ok() != Some(revision) {
        return Err(PlatformError::Conflict("try_on_cursor_expired"));
    }
    offset
        .parse()
        .map_err(|_| PlatformError::InvalidInput("try_on_cursor"))
}

fn make_cursor(revision: u64, offset: u64) -> PlatformResult<PageCursorV1> {
    PageCursorV1::new(format!("{revision}:{offset}"))
        .map_err(|_| PlatformError::Corrupt("try_on_cursor"))
}
