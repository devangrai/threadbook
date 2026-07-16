use crate::database::stable_id;
use crate::source_image::{verify_source_image, VerifiedSourceImage};
use crate::{BlobStore, Database, PlatformError, PlatformResult};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use wardrobe_core::{
    prompt_parameters_sha256_v1, BoundedPhotoArtifactBytesV1,
    ConformingGarmentSegmentationProviderV1, ConformingLocalPersonDetectionProviderV1,
    CorrectPhotoOwnerV1Request, CorrectPhotoOwnerV1Response, CorrectPhotoPersonDetectionV1Request,
    CorrectPhotoPersonDetectionV1Response, DecidePhotoOwnerV1Request, DecidePhotoOwnerV1Response,
    DetectPhotoScopePeopleV1Request, DetectPhotoScopePeopleV1Response, DetectedPersonRectangleV1,
    GarmentSegmentationProvider, ListPhotoOwnerReviewsV1Request, ListPhotoOwnerReviewsV1Response,
    LocalPersonDetectionProviderV1, PageCursorV1, PersonDetectionFailureReasonV1,
    PersonDetectionOutcomeV1, PersonDetectionProviderDescriptorV1,
    PersonDetectionProviderErrorKind, PersonDetectionRequestHandle, PersonDetectionRequestV1,
    PersonDetectionResultV1, PersonDetectionTerminalStateV1, PersonDetectionUnavailableReasonV1,
    PersonEvidenceKindV1, PhotoAnalysisRunId, PhotoAnalysisRunStateV1, PhotoArtifactKindV1,
    PhotoMediaTypeV1, PhotoOwnerActionV1, PhotoOwnerDecisionId, PhotoOwnerDecisionV1,
    PhotoOwnerPreviewId, PhotoOwnerReviewId, PhotoOwnerReviewStateV1, PhotoOwnerReviewV1,
    PhotoPersonDetectionAttemptId, PhotoPersonInstanceId, PhotoPersonInstanceV1,
    PhotoSourceRevisionId, ReadPhotoOwnerPreviewV1Request, ReadPhotoOwnerPreviewV1Response, RectV1,
    ReplayStatusV1, RetryPhotoPersonDetectionV1Request, RetryPhotoPersonDetectionV1Response,
    SegmentationOutcomeV1, SegmentationProviderDescriptorV1, SegmentationRequestHandle,
    SegmentationRequestModeV1, SegmentationRequestV1, SegmentationResultV1,
    SegmentationUnavailableReasonV1, Sha256Digest, UnavailableGarmentSegmentationProviderV1,
    Validate, APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1, GARMENT_SEGMENTATION_CONTRACT_V1,
    LOCAL_PERSON_DETECTION_CONTRACT_V1, MAX_PERSON_INSTANCES_V1, PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
    PHOTO_OWNER_PREVIEW_CONTRACT_REVISION_V1, PHOTO_PREPROCESSING_REVISION_V1,
    PHOTO_QUALITY_GATE_REVISION_V1, RECTANGLE_SOURCE_CROP_REVISION_V1, SCHEMA_VERSION_V1,
    UNAVAILABLE_SEGMENTATION_PROVIDER_ID_V1, UNAVAILABLE_SEGMENTATION_PROVIDER_REVISION_V1,
};

const DETECT_COMMAND: &str = "detect_photo_scope_people_v1";
const DECIDE_OWNER_COMMAND: &str = "decide_photo_owner_v1";
const CORRECT_OWNER_COMMAND: &str = "correct_photo_owner_v1";
const CORRECT_PERSON_COMMAND: &str = "correct_photo_person_detection_v1";
const RETRY_PERSON_COMMAND: &str = "retry_photo_person_detection_v1";
const DETECTION_LEASE_MS: i64 = 60_000;
const OWNER_WORK_LEASE_MS: i64 = 60_000;
const DETECTION_ATTEMPT_LIMIT: i64 = 3;
const OWNER_WORK_QUALITY_GATE_REVISION: &str = "owner-selected-rectangle-v1";

#[derive(Debug)]
struct DetectionWork {
    attempt_id: String,
    run_id: String,
    scope_id: String,
    member_ordinal: i64,
    source_revision_id: String,
    source_revision_sha256: String,
    blob_sha256: String,
    byte_length: u64,
    media_type: PhotoMediaTypeV1,
    width: u32,
    height: u32,
    generation: i64,
    attempt_count: i64,
    fence: i64,
    request_handle: String,
}

#[derive(Debug)]
struct OwnerWork {
    owner_decision_id: String,
    owner_review_id: String,
    person_instance_id: String,
    owner_revision: i64,
    request_id: String,
    scope_id: String,
    member_ordinal: i64,
    source_revision_id: String,
    source_revision_sha256: String,
    blob_sha256: String,
    byte_length: u64,
    media_type: PhotoMediaTypeV1,
    width: u32,
    height: u32,
    rectangle: RectV1,
    fence: i64,
}

#[derive(Serialize)]
struct DetectionEvidence<'a> {
    detection_attempt_id: &'a str,
    source_revision_id: &'a str,
    generation: i64,
    attempt_count: i64,
    descriptor: &'a PersonDetectionProviderDescriptorV1,
    outcome: &'a PersonDetectionOutcomeV1,
}

#[derive(Serialize)]
struct PersonInstanceEvidence<'a> {
    owner_review_id: &'a str,
    source_revision_id: &'a str,
    detection_attempt_id: Option<&'a str>,
    correction_id: Option<&'a str>,
    source_kind: &'a str,
    instance_ordinal: i64,
    rectangle: RectV1,
    confidence_basis_points: Option<u16>,
}

#[derive(Serialize)]
struct OwnerObservationEvidence<'a> {
    observation_id: &'a str,
    artifact_id: &'a str,
    source_revision_id: &'a str,
    source_revision_sha256: &'a str,
    owner_review_id: &'a str,
    owner_decision_id: &'a str,
    person_instance_id: &'a str,
    person_evidence_sha256: &'a str,
    owner_revision: i64,
}

#[derive(Serialize)]
struct OwnerArtifactProvenance<'a> {
    artifact_schema_revision: &'static str,
    artifact_revision: &'static str,
    artifact_id: &'a str,
    parent_scope_id: &'a str,
    member_ordinal: i64,
    parent_source_revision_id: &'a str,
    parent_source_revision_sha256: &'a str,
    input_blob_sha256: &'a str,
    input_media_type: &'static str,
    source_width: u32,
    source_height: u32,
    rectangle: Option<RectV1>,
    preprocessing_revision: &'a str,
    provider_contract_revision: &'a str,
    provider_id: &'a str,
    provider_revision: &'a str,
    model_revision: &'a Option<String>,
    request_mode: &'static str,
    prompt_parameters_sha256: &'a str,
    quality_gate_revision: &'static str,
    quality_gate_result: &'static str,
    segmentation_outcome: &'static str,
    unavailable_reason: Option<&'static str>,
    failure_code: Option<&'static str>,
    parent_artifact_ids: &'a [String],
}

impl Database {
    pub(crate) fn detect_photo_scope_people_repository(
        &self,
        request: &DetectPhotoScopePeopleV1Request,
        provider: &dyn LocalPersonDetectionProviderV1,
    ) -> PlatformResult<DetectPhotoScopePeopleV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("person_detection_request"))?;
        let provider = ConformingLocalPersonDetectionProviderV1::new(provider)
            .map_err(|_| PlatformError::Corrupt("person_detection_descriptor"))?;
        let descriptor = provider.describe();
        let run_id = self.prepare_person_detection_run(request, &descriptor)?;
        let lease_owner = format!("person-detection-{}", Uuid::new_v4());

        while let Some(work) = self.claim_person_detection_work(&run_id, &lease_owner)? {
            let image = self.load_detection_image(&work)?;
            let pixels = image.canonical_pixels()?;
            let detection_request = PersonDetectionRequestV1 {
                contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
                request_handle: parse_person_request_handle(&work.request_handle)?,
                source_revision_sha256: parse_digest(&work.source_revision_sha256)?,
                input_blob_sha256: parse_digest(&work.blob_sha256)?,
                width: work.width,
                height: work.height,
                rgb_row_stride: work
                    .width
                    .checked_mul(3)
                    .ok_or(PlatformError::Corrupt("person_detection_stride"))?,
                pixels,
                preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            };
            let outcome = match provider.detect_people(&detection_request) {
                Ok(outcome) => outcome,
                Err(error) => provider_error_outcome(&detection_request, error.kind),
            };
            outcome
                .validate_against(&descriptor, &detection_request)
                .map_err(|_| PlatformError::Corrupt("person_detection_outcome"))?;
            drop(detection_request);
            self.publish_person_detection(&work, &descriptor, &outcome, &lease_owner)?;
        }

        self.finish_person_detection_run(request, &run_id)
    }

    pub(crate) fn list_photo_owner_reviews_repository(
        &self,
        request: &ListPhotoOwnerReviewsV1Request,
    ) -> PlatformResult<ListPhotoOwnerReviewsV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("owner_review_list_request"))?;
        let connection = self.connection()?;
        let (photo_revision, owner_revision, _) = owner_revision_values(&connection)?;
        let after = parse_owner_review_cursor(
            request.cursor.as_ref(),
            request.state,
            photo_revision,
            owner_revision,
        )?;
        let state = owner_review_state_db(request.state);
        let (after_updated_at, after_review_id) = after
            .as_ref()
            .map(|value| (Some(value.0), Some(value.1.as_str())))
            .unwrap_or((None, None));
        let mut statement = connection.prepare(
            "SELECT owner_review_id
             FROM photo_owner_reviews
             WHERE state = ?1
               AND (
                   ?2 IS NULL
                   OR updated_at_ms > ?2
                   OR (updated_at_ms = ?2 AND owner_review_id > ?3)
               )
             ORDER BY updated_at_ms, owner_review_id
             LIMIT ?4",
        )?;
        let ids = statement
            .query_map(
                params![
                    state,
                    after_updated_at,
                    after_review_id,
                    i64::from(request.limit) + 1
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = ids.len() > usize::from(request.limit);
        let page_ids = ids
            .into_iter()
            .take(usize::from(request.limit))
            .collect::<Vec<_>>();
        let reviews = page_ids
            .iter()
            .map(|id| load_owner_review(&connection, id))
            .collect::<PlatformResult<Vec<_>>>()?;
        let next_cursor = if has_more {
            let last_id = page_ids
                .last()
                .ok_or(PlatformError::Corrupt("owner_review_page"))?;
            let updated_at_ms = connection.query_row(
                "SELECT updated_at_ms FROM photo_owner_reviews
                 WHERE owner_review_id = ?1",
                [last_id],
                |row| row.get::<_, i64>(0),
            )?;
            Some(make_owner_review_cursor(
                request.state,
                photo_revision,
                owner_revision,
                updated_at_ms,
                last_id,
            )?)
        } else {
            None
        };
        let response = ListPhotoOwnerReviewsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            state: request.state,
            reviews,
            next_cursor,
            photo_revision,
            owner_revision,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("owner_review_list_response"))?;
        Ok(response)
    }

    pub(crate) fn read_photo_owner_preview_repository(
        &self,
        request: &ReadPhotoOwnerPreviewV1Request,
    ) -> PlatformResult<ReadPhotoOwnerPreviewV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("owner_preview_request"))?;
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT preview.blob_sha256, preview.byte_length,
                        preview.media_type, preview.width, preview.height,
                        preview.source_revision_sha256
                 FROM photo_owner_reviews review
                 JOIN photo_owner_preview_references preview
                   ON preview.preview_id = review.preview_id
                  AND preview.source_revision_id = review.source_revision_id
                 JOIN photo_source_revisions source
                   ON source.source_revision_id = preview.source_revision_id
                  AND source.source_revision_sha256 =
                      preview.source_revision_sha256
                  AND source.blob_sha256 = preview.blob_sha256
                  AND source.byte_length = preview.byte_length
                  AND source.media_type = preview.media_type
                  AND source.width = preview.width
                  AND source.height = preview.height
                 WHERE review.owner_review_id = ?1
                   AND preview.preview_id = ?2
                   AND preview.preview_revision = ?3",
                params![
                    request.owner_review_id.to_string(),
                    request.preview_id.to_string(),
                    PHOTO_OWNER_PREVIEW_CONTRACT_REVISION_V1
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("owner_preview_id"))?;
        drop(connection);
        parse_digest(&row.5)?;
        let expected_length = to_u64(row.1, "owner_preview_length")?;
        let expected_media_type = media_type_from_db(&row.2)?;
        let expected_width = to_u32(row.3, "owner_preview_width")?;
        let expected_height = to_u32(row.4, "owner_preview_height")?;
        let image = verify_source_image(&BlobStore::new(&self.paths), &row.0, expected_length)
            .map_err(|_| PlatformError::Corrupt("owner_preview_blob"))?;
        if image.media_type != expected_media_type
            || image.width != expected_width
            || image.height != expected_height
            || image.bytes.len() as u64 != expected_length
        {
            return Err(PlatformError::Corrupt("owner_preview_metadata"));
        }
        let bytes_sha256 = Sha256Digest::from_bytes(&image.bytes);
        if bytes_sha256.as_str() != row.0 {
            return Err(PlatformError::Corrupt("owner_preview_hash"));
        }
        let response = ReadPhotoOwnerPreviewV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            owner_review_id: request.owner_review_id,
            preview_id: request.preview_id,
            media_type: image.media_type,
            width: image.width,
            height: image.height,
            byte_length: expected_length,
            bytes_sha256,
            bytes: BoundedPhotoArtifactBytesV1::new(image.bytes)
                .map_err(|_| PlatformError::Corrupt("owner_preview_bytes"))?,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("owner_preview_response"))?;
        Ok(response)
    }

    pub(crate) fn decide_photo_owner_repository(
        &self,
        request: &DecidePhotoOwnerV1Request,
    ) -> PlatformResult<DecidePhotoOwnerV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("owner_decision_request"))?;
        let (response, selected) = self.write_owner_decision(
            DECIDE_OWNER_COMMAND,
            request,
            None,
            request.owner_review_id,
            request.action,
            request.selected_person_instance_id,
            request.expected_detection_revision,
            request.expected_owner_head_revision,
            request.expected_photo_revision,
        )?;
        if selected && response.replay_status == ReplayStatusV1::Created {
            self.process_specific_owner_work(
                &response.decision.owner_decision_id.to_string(),
                &UnavailableGarmentSegmentationProviderV1,
            )?;
        }
        Ok(response)
    }

    pub(crate) fn correct_photo_owner_repository(
        &self,
        request: &CorrectPhotoOwnerV1Request,
    ) -> PlatformResult<CorrectPhotoOwnerV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("owner_correction_request"))?;
        let (base, selected) = self.write_owner_decision(
            CORRECT_OWNER_COMMAND,
            request,
            Some(request.superseded_owner_decision_id),
            request.owner_review_id,
            request.action,
            request.selected_person_instance_id,
            request.expected_detection_revision,
            request.expected_owner_head_revision,
            request.expected_photo_revision,
        )?;
        let response = CorrectPhotoOwnerV1Response {
            schema_version: base.schema_version,
            request_id: base.request_id,
            review: base.review,
            decision: base.decision,
            replay_status: base.replay_status,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("owner_correction_response"))?;
        if selected && response.replay_status == ReplayStatusV1::Created {
            self.process_specific_owner_work(
                &response.decision.owner_decision_id.to_string(),
                &UnavailableGarmentSegmentationProviderV1,
            )?;
        }
        Ok(response)
    }

    pub(crate) fn correct_photo_person_detection_repository(
        &self,
        request: &CorrectPhotoPersonDetectionV1Request,
    ) -> PlatformResult<CorrectPhotoPersonDetectionV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("person_correction_request"))?;
        let now_ms = unix_now_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) = replay::<_, CorrectPhotoPersonDetectionV1Response>(
            &transaction,
            CORRECT_PERSON_COMMAND,
            request,
        )? {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let review_id = request.owner_review_id.to_string();
        let row = transaction
            .query_row(
                "SELECT review.source_revision_id, review.detection_attempt_id,
                        review.detection_revision, review.state,
                        preview.width, preview.height,
                        COALESCE(head.owner_revision, 0)
                 FROM photo_owner_reviews review
                 JOIN photo_owner_preview_references preview
                   ON preview.preview_id = review.preview_id
                 LEFT JOIN photo_owner_heads head
                   ON head.source_revision_id = review.source_revision_id
                 WHERE review.owner_review_id = ?1",
                [&review_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("owner_review_id"))?;
        let (photo_revision, _, _) = owner_revision_values(&transaction)?;
        if row.1 != request.expected_terminal_attempt_id.to_string()
            || to_u64(row.2, "detection_revision")? != request.expected_detection_revision
            || to_u64(row.6, "owner_revision")? != request.expected_owner_head_revision
            || photo_revision != request.expected_photo_revision
            || !matches!(
                row.3.as_str(),
                "no_person_detected" | "overflow" | "retryable_failure" | "permanent_unavailable"
            )
        {
            return Err(PlatformError::Conflict("person_correction_stale"));
        }
        request
            .manual_rectangle
            .validate_within(
                to_u32(row.4, "owner_preview_width")?,
                to_u32(row.5, "owner_preview_height")?,
            )
            .map_err(|_| PlatformError::InvalidInput("manual_person_rectangle"))?;
        let instance_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM photo_person_instances
             WHERE owner_review_id = ?1",
            [&review_id],
            |row| row.get(0),
        )?;
        if instance_count >= MAX_PERSON_INSTANCES_V1 as i64 {
            return Err(PlatformError::InvalidInput("person_instance_limit"));
        }
        let ordinal: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(instance_ordinal), -1) + 1
             FROM photo_person_instances
             WHERE owner_review_id = ?1
               AND source_kind = 'manual_user_rectangle'",
            [&review_id],
            |row| row.get(0),
        )?;
        let request_id = request.request_id.to_string();
        let correction_id = stable_id("photo-person-correction", &request_id);
        let instance_id = stable_id("photo-person-instance", &correction_id);
        let new_detection_revision = request
            .expected_detection_revision
            .checked_add(1)
            .ok_or(PlatformError::InvalidInput("detection_revision"))?;
        let new_photo_revision = request
            .expected_photo_revision
            .checked_add(1)
            .ok_or(PlatformError::InvalidInput("photo_revision"))?;
        transaction.execute(
            "INSERT INTO photo_detection_corrections(
                correction_id, owner_review_id, source_revision_id, request_id,
                expected_detection_revision, detection_revision,
                expected_owner_revision, expected_photo_revision,
                photo_revision, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                correction_id,
                review_id,
                row.0,
                request_id,
                request.expected_detection_revision as i64,
                new_detection_revision as i64,
                request.expected_owner_head_revision as i64,
                request.expected_photo_revision as i64,
                new_photo_revision as i64,
                now_ms
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE photo_owner_reviews
             SET state = 'instances_available',
                 detection_revision = ?2, updated_at_ms = ?3
             WHERE owner_review_id = ?1
               AND detection_attempt_id = ?4
               AND detection_revision = ?5
               AND state = ?6",
            params![
                review_id,
                new_detection_revision as i64,
                now_ms,
                row.1,
                row.2,
                row.3
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict("person_correction_stale"));
        }
        let evidence_sha256 = canonical_hash(
            b"wardrobe.photo.person-instance.v1",
            &PersonInstanceEvidence {
                owner_review_id: &review_id,
                source_revision_id: &row.0,
                detection_attempt_id: None,
                correction_id: Some(&correction_id),
                source_kind: "manual_user_rectangle",
                instance_ordinal: ordinal,
                rectangle: request.manual_rectangle,
                confidence_basis_points: None,
            },
        )?;
        insert_person_instance(
            &transaction,
            &instance_id,
            &review_id,
            &row.0,
            None,
            Some(&correction_id),
            "manual_user_rectangle",
            ordinal,
            request.manual_rectangle,
            None,
            &evidence_sha256,
            now_ms,
        )?;
        let revisions_changed = transaction.execute(
            "UPDATE revision_state
             SET photo_revision = ?2
             WHERE singleton = 1 AND photo_revision = ?1",
            params![
                request.expected_photo_revision as i64,
                new_photo_revision as i64
            ],
        )?;
        if revisions_changed != 1 {
            return Err(PlatformError::Conflict("photo_revision_changed"));
        }
        let review = load_owner_review(&transaction, &review_id)?;
        let instance = review
            .instances
            .iter()
            .find(|instance| instance.person_instance_id.to_string() == instance_id)
            .cloned()
            .ok_or(PlatformError::Corrupt("manual_person_instance"))?;
        let response = CorrectPhotoPersonDetectionV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            review,
            instance,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("person_correction_response"))?;
        store_receipt(
            &transaction,
            CORRECT_PERSON_COMMAND,
            request,
            &response,
            now_ms,
        )?;
        for (kind, id) in [
            ("detection_correction", correction_id.as_str()),
            ("person_instance", instance_id.as_str()),
        ] {
            link_owner_command_entity(&transaction, &request_id, kind, id)?;
        }
        transaction.commit()?;
        Ok(response)
    }

    pub(crate) fn retry_photo_person_detection_repository(
        &self,
        request: &RetryPhotoPersonDetectionV1Request,
    ) -> PlatformResult<RetryPhotoPersonDetectionV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("person_retry_request"))?;
        let now_ms = unix_now_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) = replay::<_, RetryPhotoPersonDetectionV1Response>(
            &transaction,
            RETRY_PERSON_COMMAND,
            request,
        )? {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let review_id = request.owner_review_id.to_string();
        let row = transaction
            .query_row(
                "SELECT review.scope_id, review.member_ordinal,
                        review.source_revision_id, review.detection_attempt_id,
                        review.detection_revision, review.state,
                        attempt.run_id, attempt.source_revision_sha256,
                        attempt.input_blob_sha256, attempt.attempt_count,
                        attempt.contract_revision, attempt.provider_revision,
                        attempt.preprocessing_revision,
                        attempt.vision_request_revision, attempt.os_build,
                        attempt.vision_framework_build,
                        COALESCE(head.owner_revision, 0)
                 FROM photo_owner_reviews review
                 JOIN photo_person_detection_attempts attempt
                   ON attempt.detection_attempt_id =
                      review.detection_attempt_id
                 LEFT JOIN photo_owner_heads head
                   ON head.source_revision_id = review.source_revision_id
                 WHERE review.owner_review_id = ?1",
                [&review_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, String>(14)?,
                        row.get::<_, String>(15)?,
                        row.get::<_, i64>(16)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("owner_review_id"))?;
        let (photo_revision, _, _) = owner_revision_values(&transaction)?;
        let retryable = row.5 == "retryable_failure" && row.9 >= DETECTION_ATTEMPT_LIMIT;
        let unavailable = row.5 == "permanent_unavailable";
        if row.3 != request.expected_terminal_attempt_id.to_string()
            || to_u64(row.4, "detection_revision")? != request.expected_detection_revision
            || to_u64(row.16, "owner_revision")? != request.expected_owner_head_revision
            || photo_revision != request.expected_photo_revision
            || (!retryable && !unavailable)
            || row.16 != 0
        {
            return Err(PlatformError::Conflict("person_retry_stale"));
        }
        let active_generation: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM photo_person_detection_attempts
             WHERE scope_id = ?1 AND member_ordinal = ?2
               AND source_revision_id = ?3
               AND state IN ('pending', 'running')",
            params![row.0, row.1, row.2],
            |row| row.get(0),
        )?;
        if active_generation != 0 {
            return Err(PlatformError::Conflict("person_generation_active"));
        }
        let generation: i64 = transaction.query_row(
            "SELECT MAX(generation) + 1
             FROM photo_person_detection_attempts
             WHERE scope_id = ?1 AND member_ordinal = ?2
               AND source_revision_id = ?3",
            params![row.0, row.1, row.2],
            |row| row.get(0),
        )?;
        let request_id = request.request_id.to_string();
        let attempt_id = stable_id(
            "photo-person-detection-attempt",
            &format!("{}:{}:{}", row.6, row.2, generation),
        );
        transaction.execute(
            "INSERT INTO photo_person_detection_attempts(
                detection_attempt_id, run_id, scope_id, member_ordinal,
                source_revision_id, source_revision_sha256, input_blob_sha256,
                generation, request_id, contract_revision, provider_revision,
                preprocessing_revision, vision_request_revision, os_build,
                vision_framework_build, state, attempt_count, fence,
                created_at_ms, updated_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, 'pending', 0, 0, ?16, ?16
             )",
            params![
                attempt_id, row.6, row.0, row.1, row.2, row.7, row.8, generation, request_id,
                row.10, row.11, row.12, row.13, row.14, row.15, now_ms
            ],
        )?;
        let new_detection_revision = request
            .expected_detection_revision
            .checked_add(1)
            .ok_or(PlatformError::InvalidInput("detection_revision"))?;
        let new_photo_revision = request
            .expected_photo_revision
            .checked_add(1)
            .ok_or(PlatformError::InvalidInput("photo_revision"))?;
        let changed = transaction.execute(
            "UPDATE photo_owner_reviews
             SET detection_attempt_id = ?2, state = 'detecting',
                 detection_revision = ?3, updated_at_ms = ?4
             WHERE owner_review_id = ?1
               AND detection_attempt_id = ?5
               AND detection_revision = ?6
               AND state = ?7",
            params![
                review_id,
                attempt_id,
                new_detection_revision as i64,
                now_ms,
                row.3,
                row.4,
                row.5
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict("person_retry_stale"));
        }
        transaction.execute(
            "UPDATE photo_person_detection_runs
             SET state = 'running', completed_count = completed_count - 1,
                 completed_at_ms = NULL, updated_at_ms = ?2
             WHERE run_id = ?1 AND completed_count > 0",
            params![row.6, now_ms],
        )?;
        let revisions_changed = transaction.execute(
            "UPDATE revision_state
             SET photo_revision = ?2
             WHERE singleton = 1 AND photo_revision = ?1",
            params![
                request.expected_photo_revision as i64,
                new_photo_revision as i64
            ],
        )?;
        if revisions_changed != 1 {
            return Err(PlatformError::Conflict("photo_revision_changed"));
        }
        let response = RetryPhotoPersonDetectionV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            owner_review_id: request.owner_review_id,
            detection_revision: new_detection_revision,
            owner_revision: request.expected_owner_head_revision,
            photo_revision: new_photo_revision,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("person_retry_response"))?;
        store_receipt(
            &transaction,
            RETRY_PERSON_COMMAND,
            request,
            &response,
            now_ms,
        )?;
        link_owner_command_entity(&transaction, &request_id, "detection_attempt", &attempt_id)?;
        transaction.commit()?;
        Ok(response)
    }

    pub fn process_photo_owner_work(
        &self,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PlatformResult<u64> {
        let provider = ConformingGarmentSegmentationProviderV1::new(provider)
            .map_err(|_| PlatformError::Corrupt("owner_segmentation_descriptor"))?;
        require_unavailable_segmentation_descriptor(&provider.describe())?;
        let lease_owner = format!("photo-owner-work-{}", Uuid::new_v4());
        let mut completed = 0_u64;
        while let Some(work) = self.claim_owner_work(None, &lease_owner)? {
            self.invoke_and_publish_owner_work(&work, &provider, &lease_owner)?;
            completed = completed
                .checked_add(1)
                .ok_or(PlatformError::Corrupt("owner_work_count"))?;
        }
        Ok(completed)
    }

    fn process_specific_owner_work(
        &self,
        owner_decision_id: &str,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PlatformResult<()> {
        let provider = ConformingGarmentSegmentationProviderV1::new(provider)
            .map_err(|_| PlatformError::Corrupt("owner_segmentation_descriptor"))?;
        require_unavailable_segmentation_descriptor(&provider.describe())?;
        let lease_owner = format!("photo-owner-work-{}", Uuid::new_v4());
        if let Some(work) = self.claim_owner_work(Some(owner_decision_id), &lease_owner)? {
            self.invoke_and_publish_owner_work(&work, &provider, &lease_owner)?;
        }
        Ok(())
    }

    fn invoke_and_publish_owner_work(
        &self,
        work: &OwnerWork,
        provider: &dyn GarmentSegmentationProvider,
        lease_owner: &str,
    ) -> PlatformResult<()> {
        let image = verify_source_image(
            &BlobStore::new(&self.paths),
            &work.blob_sha256,
            work.byte_length,
        )
        .map_err(|_| PlatformError::Corrupt("owner_work_source"))?;
        if image.media_type != work.media_type
            || image.width != work.width
            || image.height != work.height
        {
            return Err(PlatformError::Corrupt("owner_work_source_metadata"));
        }
        let mode = SegmentationRequestModeV1::Interactive {
            box_rectangle: work.rectangle,
            positive_points: Vec::new(),
            negative_points: Vec::new(),
        };
        let attempt_id = stable_id("photo-owner-segmentation-attempt", &work.owner_decision_id);
        let request = SegmentationRequestV1 {
            contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
            request_handle: parse_segmentation_request_handle(&stable_id(
                "photo-owner-segmentation-request",
                &attempt_id,
            ))?,
            source_revision_sha256: parse_digest(&work.source_revision_sha256)?,
            input_blob_sha256: parse_digest(&work.blob_sha256)?,
            pixels: image.canonical_pixels()?,
            width: work.width,
            height: work.height,
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            mode,
        };
        let outcome = provider
            .segment(&request)
            .map_err(|_| PlatformError::Corrupt("owner_segmentation_invocation"))?;
        if outcome.result
            != (SegmentationResultV1::Unavailable {
                reason: SegmentationUnavailableReasonV1::ReviewedModelPackAbsent,
            })
        {
            return Err(PlatformError::Corrupt(
                "owner_segmentation_must_be_unavailable",
            ));
        }
        self.publish_owner_work(work, &provider.describe(), &request, &outcome, lease_owner)
    }

    fn prepare_person_detection_run(
        &self,
        request: &DetectPhotoScopePeopleV1Request,
        descriptor: &PersonDetectionProviderDescriptorV1,
    ) -> PlatformResult<String> {
        let now_ms = unix_now_ms()?;
        let request_id = request.request_id.to_string();
        let envelope = envelope_hash(request)?;
        let scope_id = request.scope_id.to_string();
        let run_id = stable_id(
            "photo-person-detection-run",
            &format!(
                "{scope_id}:{}:{}:{}:{}:{}",
                descriptor.provider_revision,
                descriptor.preprocessing_revision,
                descriptor.vision_request_revision,
                descriptor.os_build,
                descriptor.vision_framework_build
            ),
        );
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((command, stored_envelope, response_json)) = transaction
            .query_row(
                "SELECT command_name, envelope_hash, response_json
                 FROM command_receipts WHERE request_id = ?1",
                [&request_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
        {
            if command != DETECT_COMMAND || stored_envelope != envelope {
                return Err(PlatformError::Conflict("command_envelope_changed"));
            }
            if response_json != "{}" {
                let _: DetectPhotoScopePeopleV1Response = serde_json::from_str(&response_json)?;
                transaction.commit()?;
                return Ok(run_id);
            }
        } else {
            transaction.execute(
                "INSERT INTO command_receipts(
                    request_id, command_name, envelope_hash,
                    response_json, created_at_ms
                 ) VALUES (?1, ?2, ?3, '{}', ?4)",
                params![request_id, DETECT_COMMAND, envelope, now_ms],
            )?;
        }
        let scope_counts = transaction
            .query_row(
                "SELECT member_count, eligible_count
                 FROM photo_scopes WHERE scope_id = ?1",
                [&scope_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("photo_scope_id"))?;
        let existing = transaction
            .query_row(
                "SELECT run_id FROM photo_person_detection_runs
                 WHERE scope_id = ?1
                   AND contract_revision = ?2
                   AND provider_revision = ?3
                   AND preprocessing_revision = ?4
                   AND vision_request_revision = ?5
                   AND os_build = ?6
                   AND vision_framework_build = ?7",
                params![
                    scope_id,
                    descriptor.contract_revision,
                    descriptor.provider_revision,
                    descriptor.preprocessing_revision,
                    i64::from(descriptor.vision_request_revision),
                    descriptor.os_build,
                    descriptor.vision_framework_build
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_run_id) = existing {
            link_owner_command_entity(
                &transaction,
                &request_id,
                "detection_run",
                &existing_run_id,
            )?;
            transaction.commit()?;
            return Ok(existing_run_id);
        }
        let skipped = scope_counts.0 - scope_counts.1;
        let completed = scope_counts.1 == 0;
        transaction.execute(
            "INSERT INTO photo_person_detection_runs(
                run_id, request_id, request_envelope_sha256, scope_id,
                contract_revision, provider_revision, preprocessing_revision,
                vision_request_revision, os_build, vision_framework_build,
                state, member_count, completed_count,
                created_at_ms, updated_at_ms, completed_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?14, ?15
             )",
            params![
                run_id,
                request_id,
                envelope,
                scope_id,
                descriptor.contract_revision,
                descriptor.provider_revision,
                descriptor.preprocessing_revision,
                i64::from(descriptor.vision_request_revision),
                descriptor.os_build,
                descriptor.vision_framework_build,
                if completed { "completed" } else { "pending" },
                scope_counts.0,
                skipped,
                now_ms,
                if completed { Some(now_ms) } else { None }
            ],
        )?;
        link_owner_command_entity(&transaction, &request_id, "detection_run", &run_id)?;
        let mut statement = transaction.prepare(
            "SELECT member.member_ordinal, member.source_revision_id,
                    revision.source_revision_sha256, revision.blob_sha256
             FROM photo_scope_members member
             JOIN photo_source_revisions revision
               ON revision.source_revision_id = member.source_revision_id
             WHERE member.scope_id = ?1 AND member.disposition = 'eligible'
             ORDER BY member.member_ordinal",
        )?;
        let members = statement
            .query_map([&scope_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        for (ordinal, source_revision_id, source_revision_sha256, blob_sha256) in members {
            let attempt_id = stable_id(
                "photo-person-detection-attempt",
                &format!("{run_id}:{source_revision_id}:1"),
            );
            transaction.execute(
                "INSERT INTO photo_person_detection_attempts(
                    detection_attempt_id, run_id, scope_id, member_ordinal,
                    source_revision_id, source_revision_sha256,
                    input_blob_sha256, generation, request_id,
                    contract_revision, provider_revision,
                    preprocessing_revision, vision_request_revision,
                    os_build, vision_framework_build, state,
                    attempt_count, fence, created_at_ms, updated_at_ms
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, NULL,
                    ?8, ?9, ?10, ?11, ?12, ?13, 'pending',
                    0, 0, ?14, ?14
                 )",
                params![
                    attempt_id,
                    run_id,
                    scope_id,
                    ordinal,
                    source_revision_id,
                    source_revision_sha256,
                    blob_sha256,
                    descriptor.contract_revision,
                    descriptor.provider_revision,
                    descriptor.preprocessing_revision,
                    i64::from(descriptor.vision_request_revision),
                    descriptor.os_build,
                    descriptor.vision_framework_build,
                    now_ms
                ],
            )?;
            link_owner_command_entity(&transaction, &request_id, "detection_attempt", &attempt_id)?;
        }
        transaction.commit()?;
        Ok(run_id)
    }

    fn claim_person_detection_work(
        &self,
        run_id: &str,
        lease_owner: &str,
    ) -> PlatformResult<Option<DetectionWork>> {
        let now_ms = unix_now_ms()?;
        let lease_expires_at_ms = now_ms
            .checked_add(DETECTION_LEASE_MS)
            .ok_or(PlatformError::Corrupt("person_detection_lease"))?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = transaction
            .query_row(
                "SELECT attempt.detection_attempt_id, attempt.scope_id,
                        attempt.member_ordinal, attempt.source_revision_id,
                        attempt.source_revision_sha256,
                        attempt.input_blob_sha256, revision.byte_length,
                        revision.media_type, revision.width, revision.height,
                        attempt.generation, attempt.attempt_count, attempt.fence
                 FROM photo_person_detection_attempts attempt
                 JOIN photo_source_revisions revision
                   ON revision.source_revision_id =
                      attempt.source_revision_id
                 WHERE attempt.run_id = ?1
                   AND (
                       attempt.state = 'pending'
                       OR (
                           attempt.state = 'running'
                           AND attempt.lease_expires_at_ms <= ?2
                       )
                   )
                 ORDER BY attempt.member_ordinal, attempt.generation
                 LIMIT 1",
                params![run_id, now_ms],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, i64>(12)?,
                    ))
                },
            )
            .optional()?;
        let Some(row) = candidate else {
            transaction.commit()?;
            return Ok(None);
        };
        let fence = row.12 + 1;
        let changed = transaction.execute(
            "UPDATE photo_person_detection_attempts
             SET state = 'running', attempt_count = attempt_count + 1,
                 fence = ?2, lease_owner = ?3,
                 lease_expires_at_ms = ?4, updated_at_ms = ?5
             WHERE detection_attempt_id = ?1 AND fence = ?6
               AND (
                   state = 'pending'
                   OR (state = 'running' AND lease_expires_at_ms <= ?5)
               )",
            params![
                row.0,
                fence,
                lease_owner,
                lease_expires_at_ms,
                now_ms,
                row.12
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::LeaseLost);
        }
        transaction.execute(
            "UPDATE photo_person_detection_runs
             SET state = 'running', updated_at_ms = ?2
             WHERE run_id = ?1 AND state <> 'completed'",
            params![run_id, now_ms],
        )?;
        transaction.commit()?;
        Ok(Some(DetectionWork {
            attempt_id: row.0.clone(),
            run_id: run_id.to_owned(),
            scope_id: row.1,
            member_ordinal: row.2,
            source_revision_id: row.3,
            source_revision_sha256: row.4,
            blob_sha256: row.5,
            byte_length: to_u64(row.6, "person_blob_length")?,
            media_type: media_type_from_db(&row.7)?,
            width: to_u32(row.8, "person_width")?,
            height: to_u32(row.9, "person_height")?,
            generation: row.10,
            attempt_count: row.11 + 1,
            fence,
            request_handle: stable_id("photo-person-detection-request", &row.0),
        }))
    }

    fn load_detection_image(&self, work: &DetectionWork) -> PlatformResult<VerifiedSourceImage> {
        let image = verify_source_image(
            &BlobStore::new(&self.paths),
            &work.blob_sha256,
            work.byte_length,
        )
        .map_err(|_| PlatformError::Corrupt("person_detection_source"))?;
        if image.media_type != work.media_type
            || image.width != work.width
            || image.height != work.height
        {
            return Err(PlatformError::Corrupt("person_detection_source_metadata"));
        }
        Ok(image)
    }

    fn publish_person_detection(
        &self,
        work: &DetectionWork,
        descriptor: &PersonDetectionProviderDescriptorV1,
        outcome: &PersonDetectionOutcomeV1,
        lease_owner: &str,
    ) -> PlatformResult<()> {
        let now_ms = unix_now_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let valid_claim = transaction
            .query_row(
                "SELECT 1 FROM photo_person_detection_attempts
                 WHERE detection_attempt_id = ?1 AND state = 'running'
                   AND fence = ?2 AND lease_owner = ?3",
                params![work.attempt_id, work.fence, lease_owner],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !valid_claim {
            return Err(PlatformError::LeaseLost);
        }
        if matches!(
            outcome.result,
            PersonDetectionResultV1::RetryableFailure { .. }
        ) && work.attempt_count < DETECTION_ATTEMPT_LIMIT
        {
            transaction.execute(
                "UPDATE photo_person_detection_attempts
                 SET state = 'pending', lease_owner = NULL,
                     lease_expires_at_ms = NULL, updated_at_ms = ?4
                 WHERE detection_attempt_id = ?1 AND fence = ?2
                   AND lease_owner = ?3 AND state = 'running'",
                params![work.attempt_id, work.fence, lease_owner, now_ms],
            )?;
            transaction.commit()?;
            return Ok(());
        }
        let (attempt_state, review_state, detected_count, terminal_reason) =
            detection_storage_state(&outcome.result);
        let evidence_sha256 = canonical_hash(
            b"wardrobe.photo.person-detection-attempt.v1",
            &DetectionEvidence {
                detection_attempt_id: &work.attempt_id,
                source_revision_id: &work.source_revision_id,
                generation: work.generation,
                attempt_count: work.attempt_count,
                descriptor,
                outcome,
            },
        )?;
        let changed = transaction.execute(
            "UPDATE photo_person_detection_attempts
             SET state = ?4, detected_count = ?5, terminal_reason = ?6,
                 evidence_sha256 = ?7, lease_owner = NULL,
                 lease_expires_at_ms = NULL, completed_at_ms = ?8,
                 updated_at_ms = ?8
             WHERE detection_attempt_id = ?1 AND fence = ?2
               AND lease_owner = ?3 AND state = 'running'",
            params![
                work.attempt_id,
                work.fence,
                lease_owner,
                attempt_state,
                detected_count,
                terminal_reason,
                evidence_sha256.as_str(),
                now_ms
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::LeaseLost);
        }
        let existing_review = transaction
            .query_row(
                "SELECT owner_review_id, detection_revision
                 FROM photo_owner_reviews
                 WHERE scope_id = ?1 AND member_ordinal = ?2
                   AND source_revision_id = ?3",
                params![work.scope_id, work.member_ordinal, work.source_revision_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let command_request_id = transaction.query_row(
            "SELECT COALESCE(attempt.request_id, run.request_id)
             FROM photo_person_detection_attempts attempt
             JOIN photo_person_detection_runs run
               ON run.run_id = attempt.run_id
             WHERE attempt.detection_attempt_id = ?1",
            [&work.attempt_id],
            |row| row.get::<_, String>(0),
        )?;
        let (review_id, review_revision) =
            if let Some((review_id, detection_revision)) = existing_review {
                let new_revision = detection_revision + 1;
                let updated = transaction.execute(
                    "UPDATE photo_owner_reviews
                     SET state = ?2, detection_revision = ?3,
                         updated_at_ms = ?4
                     WHERE owner_review_id = ?1
                       AND detection_attempt_id = ?5
                       AND state = 'detecting'
                       AND detection_revision = ?6",
                    params![
                        review_id,
                        review_state,
                        new_revision,
                        now_ms,
                        work.attempt_id,
                        detection_revision
                    ],
                )?;
                if updated != 1 {
                    return Err(PlatformError::LeaseLost);
                }
                (review_id, new_revision)
            } else {
                let preview_id = stable_id(
                    "photo-owner-preview",
                    &format!("{}:{}", work.scope_id, work.source_revision_id),
                );
                let review_id = stable_id(
                    "photo-owner-review",
                    &format!("{}:{}", work.scope_id, work.source_revision_id),
                );
                transaction.execute(
                    "INSERT INTO photo_owner_preview_references(
                        preview_id, source_revision_id,
                        source_revision_sha256, blob_sha256, byte_length,
                        media_type, width, height, preview_revision,
                        created_at_ms
                     ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
                     )",
                    params![
                        preview_id,
                        work.source_revision_id,
                        work.source_revision_sha256,
                        work.blob_sha256,
                        work.byte_length as i64,
                        media_type_db(work.media_type),
                        i64::from(work.width),
                        i64::from(work.height),
                        PHOTO_OWNER_PREVIEW_CONTRACT_REVISION_V1,
                        now_ms
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO photo_owner_reviews(
                        owner_review_id, scope_id, member_ordinal,
                        source_revision_id, detection_attempt_id, preview_id,
                        detection_revision, state, created_at_ms, updated_at_ms
                     ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?8
                     )",
                    params![
                        review_id,
                        work.scope_id,
                        work.member_ordinal,
                        work.source_revision_id,
                        work.attempt_id,
                        preview_id,
                        review_state,
                        now_ms
                    ],
                )?;
                link_owner_command_entity(
                    &transaction,
                    &command_request_id,
                    "owner_preview",
                    &preview_id,
                )?;
                link_owner_command_entity(
                    &transaction,
                    &command_request_id,
                    "owner_review",
                    &review_id,
                )?;
                (review_id, 1)
            };
        if let PersonDetectionResultV1::SucceededInstances { instances } = &outcome.result {
            for (ordinal, instance) in instances.iter().enumerate() {
                insert_detected_person_instance(
                    &transaction,
                    &review_id,
                    &work.source_revision_id,
                    &work.attempt_id,
                    ordinal as i64,
                    instance,
                    now_ms,
                    &command_request_id,
                )?;
            }
        }
        let completed_count: i64 = transaction.query_row(
            "SELECT completed_count + 1
             FROM photo_person_detection_runs WHERE run_id = ?1",
            [&work.run_id],
            |row| row.get(0),
        )?;
        let member_count: i64 = transaction.query_row(
            "SELECT member_count
             FROM photo_person_detection_runs WHERE run_id = ?1",
            [&work.run_id],
            |row| row.get(0),
        )?;
        transaction.execute(
            "UPDATE photo_person_detection_runs
             SET completed_count = ?2, state = ?3,
                 updated_at_ms = ?4, completed_at_ms = ?5
             WHERE run_id = ?1",
            params![
                work.run_id,
                completed_count,
                if completed_count == member_count {
                    "completed"
                } else {
                    "running"
                },
                now_ms,
                if completed_count == member_count {
                    Some(now_ms)
                } else {
                    None
                }
            ],
        )?;
        transaction.execute(
            "UPDATE revision_state
             SET evidence_generation = evidence_generation + 1
             WHERE singleton = 1",
            [],
        )?;
        link_owner_command_entity(
            &transaction,
            &command_request_id,
            "detection_attempt",
            &work.attempt_id,
        )?;
        let _ = review_revision;
        transaction.commit()?;
        Ok(())
    }

    fn finish_person_detection_run(
        &self,
        request: &DetectPhotoScopePeopleV1Request,
        run_id: &str,
    ) -> PlatformResult<DetectPhotoScopePeopleV1Response> {
        let now_ms = unix_now_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((command, envelope, response_json)) = transaction
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
            .optional()?
        {
            if command != DETECT_COMMAND || envelope != envelope_hash(request)? {
                return Err(PlatformError::Conflict("command_envelope_changed"));
            }
            if response_json != "{}" {
                let mut response: DetectPhotoScopePeopleV1Response =
                    serde_json::from_str(&response_json)?;
                response.replay_status = ReplayStatusV1::Replayed;
                transaction.commit()?;
                return Ok(response);
            }
        }
        let (state, member_count, completed_count): (String, i64, i64) = transaction.query_row(
            "SELECT state, member_count, completed_count
                 FROM photo_person_detection_runs WHERE run_id = ?1",
            [run_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let skipped_count: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM photo_scope_members
             WHERE scope_id = ?1 AND disposition = 'quarantined'",
            [request.scope_id.to_string()],
            |row| row.get(0),
        )?;
        let counts = transaction.query_row(
            "SELECT
                SUM(CASE WHEN review.state = 'instances_available' THEN 1 ELSE 0 END),
                SUM(CASE WHEN review.state = 'no_person_detected' THEN 1 ELSE 0 END),
                SUM(CASE WHEN review.state = 'overflow' THEN 1 ELSE 0 END),
                SUM(CASE WHEN review.state = 'retryable_failure' THEN 1 ELSE 0 END),
                SUM(CASE WHEN review.state = 'permanent_unavailable' THEN 1 ELSE 0 END)
             FROM photo_owner_reviews review
             JOIN photo_person_detection_attempts attempt
               ON attempt.detection_attempt_id = review.detection_attempt_id
             WHERE attempt.run_id = ?1",
            [run_id],
            |row| {
                Ok((
                    row.get::<_, Option<i64>>(0)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(1)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(2)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(3)?.unwrap_or(0),
                    row.get::<_, Option<i64>>(4)?.unwrap_or(0),
                ))
            },
        )?;
        let terminal_review_count = counts.0 + counts.1 + counts.2 + counts.3 + counts.4;
        let (photo_revision, owner_revision, evidence_generation) =
            owner_revision_values(&transaction)?;
        let response = DetectPhotoScopePeopleV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            scope_id: request.scope_id,
            run_id: parse_analysis_run_id(run_id)?,
            state: if state == "completed" {
                PhotoAnalysisRunStateV1::Completed
            } else {
                PhotoAnalysisRunStateV1::Running
            },
            member_count: to_u16(member_count, "person_member_count")?,
            completed_count: to_u16(completed_count, "person_completed_count")?,
            terminal_review_count: to_u16(terminal_review_count, "person_terminal_review_count")?,
            instances_available_count: to_u16(counts.0, "person_instances_count")?,
            no_person_detected_count: to_u16(counts.1, "person_zero_count")?,
            overflow_count: to_u16(counts.2, "person_overflow_count")?,
            retryable_failure_count: to_u16(counts.3, "person_retryable_count")?,
            permanent_unavailable_count: to_u16(counts.4, "person_unavailable_count")?,
            skipped_count: to_u16(skipped_count, "person_skipped_count")?,
            photo_revision,
            owner_revision,
            evidence_generation,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("person_detection_response"))?;
        if state == "completed" {
            transaction.execute(
                "UPDATE command_receipts
                 SET response_json = ?2
                 WHERE request_id = ?1",
                params![
                    request.request_id.to_string(),
                    serde_json::to_string(&response)?
                ],
            )?;
            transaction.execute(
                "UPDATE photo_person_detection_runs
                 SET updated_at_ms = MAX(updated_at_ms, ?2)
                 WHERE run_id = ?1",
                params![run_id, now_ms],
            )?;
        }
        transaction.commit()?;
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_owner_decision<Q: Serialize>(
        &self,
        command: &str,
        request: &Q,
        superseded: Option<PhotoOwnerDecisionId>,
        owner_review_id: PhotoOwnerReviewId,
        action: PhotoOwnerActionV1,
        selected_person_instance_id: Option<PhotoPersonInstanceId>,
        expected_detection_revision: u64,
        expected_owner_revision: u64,
        expected_photo_revision: u64,
    ) -> PlatformResult<(DecidePhotoOwnerV1Response, bool)> {
        let now_ms = unix_now_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if command == DECIDE_OWNER_COMMAND {
            if let Some(mut response) =
                replay::<_, DecidePhotoOwnerV1Response>(&transaction, command, request)?
            {
                response.replay_status = ReplayStatusV1::Replayed;
                transaction.commit()?;
                return Ok((response, action == PhotoOwnerActionV1::SelectPerson));
            }
        } else if let Some(mut response) =
            replay::<_, CorrectPhotoOwnerV1Response>(&transaction, command, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            let base = DecidePhotoOwnerV1Response {
                schema_version: response.schema_version,
                request_id: response.request_id,
                review: response.review,
                decision: response.decision,
                replay_status: response.replay_status,
            };
            transaction.commit()?;
            return Ok((base, action == PhotoOwnerActionV1::SelectPerson));
        }
        let review_id = owner_review_id.to_string();
        let review_row = transaction
            .query_row(
                "SELECT source_revision_id, scope_id, member_ordinal,
                        detection_revision, state
                 FROM photo_owner_reviews WHERE owner_review_id = ?1",
                [&review_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("owner_review_id"))?;
        let current_head = transaction
            .query_row(
                "SELECT owner_decision_id, owner_revision
                 FROM photo_owner_heads WHERE source_revision_id = ?1",
                [&review_row.0],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let current_owner_revision = current_head.as_ref().map_or(0, |head| head.1);
        let (photo_revision, _, _) = owner_revision_values(&transaction)?;
        let superseded_matches = match (superseded, current_head.as_ref()) {
            (None, None) => true,
            (Some(expected), Some(current)) => expected.to_string() == current.0,
            _ => false,
        };
        if to_u64(review_row.3, "detection_revision")? != expected_detection_revision
            || to_u64(current_owner_revision, "owner_revision")? != expected_owner_revision
            || photo_revision != expected_photo_revision
            || !superseded_matches
        {
            return Err(PlatformError::Conflict("owner_decision_stale"));
        }
        if action == PhotoOwnerActionV1::SelectPerson {
            if review_row.4 != "instances_available" {
                return Err(PlatformError::InvalidInput("owner_person_unavailable"));
            }
            let selected = selected_person_instance_id
                .ok_or(PlatformError::InvalidInput("selected_person_instance_id"))?;
            let belongs = transaction
                .query_row(
                    "SELECT 1 FROM photo_person_instances
                     WHERE person_instance_id = ?1
                       AND owner_review_id = ?2
                       AND source_revision_id = ?3",
                    params![selected.to_string(), review_id, review_row.0],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !belongs {
                return Err(PlatformError::InvalidInput("selected_person_instance_id"));
            }
        } else if selected_person_instance_id.is_some() {
            return Err(PlatformError::InvalidInput("selected_person_instance_id"));
        }
        let request_id = request_id_from_json(request)?;
        let decision_id = stable_id("photo-owner-decision", &request_id);
        let new_owner_revision = expected_owner_revision
            .checked_add(1)
            .ok_or(PlatformError::InvalidInput("owner_revision"))?;
        let new_photo_revision = expected_photo_revision
            .checked_add(1)
            .ok_or(PlatformError::InvalidInput("photo_revision"))?;
        let action_db = owner_action_db(action);
        let selected_id = selected_person_instance_id.map(|id| id.to_string());
        transaction.execute(
            "INSERT INTO photo_owner_decisions(
                owner_decision_id, owner_review_id, source_revision_id,
                request_id, action, selected_person_instance_id,
                expected_detection_revision, expected_owner_revision,
                owner_revision, expected_photo_revision, photo_revision,
                superseded_owner_decision_id, created_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13
             )",
            params![
                decision_id,
                review_id,
                review_row.0,
                request_id,
                action_db,
                selected_id,
                expected_detection_revision as i64,
                expected_owner_revision as i64,
                new_owner_revision as i64,
                expected_photo_revision as i64,
                new_photo_revision as i64,
                superseded.map(|id| id.to_string()),
                now_ms
            ],
        )?;
        let head_changed = if current_head.is_some() {
            transaction.execute(
                "UPDATE photo_owner_heads
                 SET owner_review_id = ?2, owner_decision_id = ?3,
                     action = ?4, selected_person_instance_id = ?5,
                     owner_revision = ?6, photo_revision = ?7,
                     updated_at_ms = ?8
                 WHERE source_revision_id = ?1
                   AND owner_decision_id = ?9
                   AND owner_revision = ?10",
                params![
                    review_row.0,
                    review_id,
                    decision_id,
                    action_db,
                    selected_id,
                    new_owner_revision as i64,
                    new_photo_revision as i64,
                    now_ms,
                    current_head.as_ref().map(|head| head.0.as_str()),
                    expected_owner_revision as i64
                ],
            )?
        } else {
            transaction.execute(
                "INSERT INTO photo_owner_heads(
                    source_revision_id, owner_review_id, owner_decision_id,
                    action, selected_person_instance_id, owner_revision,
                    photo_revision, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    review_row.0,
                    review_id,
                    decision_id,
                    action_db,
                    selected_id,
                    new_owner_revision as i64,
                    new_photo_revision as i64,
                    now_ms
                ],
            )?
        };
        if head_changed != 1 {
            return Err(PlatformError::Conflict("owner_decision_stale"));
        }
        if let Some(old) = superseded {
            transaction.execute(
                "UPDATE photo_owner_work_claims
                 SET state = 'stale', lease_owner = NULL,
                     lease_expires_at_ms = NULL, updated_at_ms = ?2
                 WHERE owner_decision_id = ?1
                   AND state IN ('pending', 'running')",
                params![old.to_string(), now_ms],
            )?;
        }
        if action == PhotoOwnerActionV1::SelectPerson {
            transaction.execute(
                "INSERT INTO photo_owner_work_claims(
                    owner_decision_id, state, attempt_count, fence,
                    lease_owner, lease_expires_at_ms,
                    created_at_ms, updated_at_ms
                 ) VALUES (?1, 'pending', 0, 0, NULL, NULL, ?2, ?2)",
                params![decision_id, now_ms],
            )?;
            ensure_owner_analysis_support(
                &transaction,
                &request_id,
                &review_row.1,
                review_row.2,
                &review_row.0,
                now_ms,
            )?;
        }
        let revision_changed = transaction.execute(
            "UPDATE revision_state
             SET photo_revision = ?2, owner_revision = owner_revision + 1
             WHERE singleton = 1 AND photo_revision = ?1",
            params![expected_photo_revision as i64, new_photo_revision as i64],
        )?;
        if revision_changed != 1 {
            return Err(PlatformError::Conflict("photo_revision_changed"));
        }
        let review = load_owner_review(&transaction, &review_id)?;
        let decision = PhotoOwnerDecisionV1 {
            owner_decision_id: parse_owner_decision_id(&decision_id)?,
            owner_review_id,
            action,
            selected_person_instance_id,
            supersedes_owner_decision_id: superseded,
            detection_revision: expected_detection_revision,
            owner_revision: new_owner_revision,
            photo_revision: new_photo_revision,
        };
        let response = DecidePhotoOwnerV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: parse_request_id(&request_id)?,
            review,
            decision,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .or_else(|_| {
                if superseded.is_some() {
                    Ok(())
                } else {
                    Err(wardrobe_core::ValidationError::new(
                        wardrobe_core::SafeFieldV1::DecisionId,
                    ))
                }
            })
            .map_err(|_| PlatformError::Corrupt("owner_decision_response"))?;
        if command == DECIDE_OWNER_COMMAND {
            store_receipt(&transaction, command, request, &response, now_ms)?;
        } else {
            let correction_response = CorrectPhotoOwnerV1Response {
                schema_version: response.schema_version,
                request_id: response.request_id,
                review: response.review.clone(),
                decision: response.decision.clone(),
                replay_status: response.replay_status,
            };
            correction_response
                .validate()
                .map_err(|_| PlatformError::Corrupt("owner_correction_response"))?;
            store_receipt(&transaction, command, request, &correction_response, now_ms)?;
        }
        link_owner_command_entity(&transaction, &request_id, "owner_decision", &decision_id)?;
        if action == PhotoOwnerActionV1::SelectPerson {
            link_owner_command_entity(&transaction, &request_id, "owner_work", &decision_id)?;
        }
        transaction.commit()?;
        Ok((response, action == PhotoOwnerActionV1::SelectPerson))
    }

    fn claim_owner_work(
        &self,
        requested_decision_id: Option<&str>,
        lease_owner: &str,
    ) -> PlatformResult<Option<OwnerWork>> {
        let now_ms = unix_now_ms()?;
        let expires_at_ms = now_ms
            .checked_add(OWNER_WORK_LEASE_MS)
            .ok_or(PlatformError::Corrupt("owner_work_lease"))?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        loop {
            let row = transaction
                .query_row(
                    "SELECT work.owner_decision_id, decision.owner_review_id,
                            decision.selected_person_instance_id,
                            decision.owner_revision, decision.request_id,
                            review.scope_id, review.member_ordinal,
                            decision.source_revision_id,
                            source.source_revision_sha256,
                            source.blob_sha256, source.byte_length,
                            source.media_type, source.width, source.height,
                            person.rectangle_x, person.rectangle_y,
                            person.rectangle_width, person.rectangle_height,
                            work.fence
                     FROM photo_owner_work_claims work
                     JOIN photo_owner_decisions decision
                       ON decision.owner_decision_id =
                          work.owner_decision_id
                     JOIN photo_owner_reviews review
                       ON review.owner_review_id = decision.owner_review_id
                     JOIN photo_source_revisions source
                       ON source.source_revision_id =
                          decision.source_revision_id
                     JOIN photo_person_instances person
                       ON person.person_instance_id =
                          decision.selected_person_instance_id
                      AND person.owner_review_id =
                          decision.owner_review_id
                     WHERE (?1 IS NULL OR work.owner_decision_id = ?1)
                       AND (
                           work.state = 'pending'
                           OR (
                               work.state = 'running'
                               AND work.lease_expires_at_ms <= ?2
                           )
                       )
                     ORDER BY work.created_at_ms, work.owner_decision_id
                     LIMIT 1",
                    params![requested_decision_id, now_ms],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, String>(7)?,
                            row.get::<_, String>(8)?,
                            row.get::<_, String>(9)?,
                            row.get::<_, i64>(10)?,
                            row.get::<_, String>(11)?,
                            row.get::<_, i64>(12)?,
                            row.get::<_, i64>(13)?,
                            row.get::<_, i64>(14)?,
                            row.get::<_, i64>(15)?,
                            row.get::<_, i64>(16)?,
                            row.get::<_, i64>(17)?,
                            row.get::<_, i64>(18)?,
                        ))
                    },
                )
                .optional()?;
            let Some(row) = row else {
                transaction.commit()?;
                return Ok(None);
            };
            let current = transaction
                .query_row(
                    "SELECT 1 FROM photo_owner_heads
                     WHERE source_revision_id = ?1
                       AND owner_decision_id = ?2
                       AND selected_person_instance_id = ?3
                       AND owner_revision = ?4
                       AND action = 'select_person'",
                    params![row.7, row.0, row.2, row.3],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !current {
                transaction.execute(
                    "UPDATE photo_owner_work_claims
                     SET state = 'stale', lease_owner = NULL,
                         lease_expires_at_ms = NULL, updated_at_ms = ?2
                     WHERE owner_decision_id = ?1",
                    params![row.0, now_ms],
                )?;
                if requested_decision_id.is_some() {
                    transaction.commit()?;
                    return Ok(None);
                }
                continue;
            }
            let fence = row.18 + 1;
            let changed = transaction.execute(
                "UPDATE photo_owner_work_claims
                 SET state = 'running', attempt_count = attempt_count + 1,
                     fence = ?2, lease_owner = ?3,
                     lease_expires_at_ms = ?4, updated_at_ms = ?5
                 WHERE owner_decision_id = ?1 AND fence = ?6
                   AND (
                       state = 'pending'
                       OR (
                           state = 'running'
                           AND lease_expires_at_ms <= ?5
                       )
                   )",
                params![row.0, fence, lease_owner, expires_at_ms, now_ms, row.18],
            )?;
            if changed != 1 {
                return Err(PlatformError::LeaseLost);
            }
            transaction.commit()?;
            return Ok(Some(OwnerWork {
                owner_decision_id: row.0,
                owner_review_id: row.1,
                person_instance_id: row.2,
                owner_revision: row.3,
                request_id: row.4,
                scope_id: row.5,
                member_ordinal: row.6,
                source_revision_id: row.7,
                source_revision_sha256: row.8,
                blob_sha256: row.9,
                byte_length: to_u64(row.10, "owner_work_blob_length")?,
                media_type: media_type_from_db(&row.11)?,
                width: to_u32(row.12, "owner_work_width")?,
                height: to_u32(row.13, "owner_work_height")?,
                rectangle: RectV1 {
                    x: to_u32(row.14, "owner_person_rectangle")?,
                    y: to_u32(row.15, "owner_person_rectangle")?,
                    width: to_u32(row.16, "owner_person_rectangle")?,
                    height: to_u32(row.17, "owner_person_rectangle")?,
                },
                fence,
            }));
        }
    }

    fn publish_owner_work(
        &self,
        work: &OwnerWork,
        descriptor: &SegmentationProviderDescriptorV1,
        request: &SegmentationRequestV1,
        outcome: &SegmentationOutcomeV1,
        lease_owner: &str,
    ) -> PlatformResult<()> {
        let now_ms = unix_now_ms()?;
        let attempt_id = stable_id("photo-owner-segmentation-attempt", &work.owner_decision_id);
        let request_handle = request.request_handle.to_string();
        let artifact_id = stable_id("photo-owner-artifact", &work.owner_decision_id);
        let observation_id = stable_id("photo-owner-observation", &work.owner_decision_id);
        let mode = SegmentationRequestModeV1::Interactive {
            box_rectangle: work.rectangle,
            positive_points: Vec::new(),
            negative_points: Vec::new(),
        };
        let prompt_hash = prompt_parameters_sha256_v1(&mode)
            .map_err(|_| PlatformError::Corrupt("owner_prompt_hash"))?;
        let response_sha256 = Sha256Digest::from_bytes(&serde_json::to_vec(outcome)?);
        let provenance_json = serde_json::to_string(&OwnerArtifactProvenance {
            artifact_schema_revision: PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
            artifact_revision: RECTANGLE_SOURCE_CROP_REVISION_V1,
            artifact_id: &artifact_id,
            parent_scope_id: &work.scope_id,
            member_ordinal: work.member_ordinal,
            parent_source_revision_id: &work.source_revision_id,
            parent_source_revision_sha256: &work.source_revision_sha256,
            input_blob_sha256: &work.blob_sha256,
            input_media_type: media_type_db(work.media_type),
            source_width: work.width,
            source_height: work.height,
            rectangle: Some(work.rectangle),
            preprocessing_revision: &descriptor.preprocessing_revision,
            provider_contract_revision: &descriptor.contract_revision,
            provider_id: &descriptor.provider_id,
            provider_revision: &descriptor.provider_revision,
            model_revision: &descriptor.model_revision,
            request_mode: "interactive",
            prompt_parameters_sha256: prompt_hash.as_str(),
            quality_gate_revision: PHOTO_QUALITY_GATE_REVISION_V1,
            quality_gate_result: "not_applicable",
            segmentation_outcome: "unavailable",
            unavailable_reason: Some("reviewed_model_pack_absent"),
            failure_code: None,
            parent_artifact_ids: &[],
        })?;
        let provenance_sha256 = Sha256Digest::from_bytes(provenance_json.as_bytes());
        let artifact_sha256 = crate::photo_repository::artifact_hash(
            &provenance_sha256,
            PhotoArtifactKindV1::RectangleSourceCrop,
            Some(work.rectangle),
        )?;
        let request_envelope_sha256 = envelope_hash(&serde_json::json!({
            "owner_decision_id": work.owner_decision_id,
            "source_revision_sha256": work.source_revision_sha256,
            "input_blob_sha256": work.blob_sha256,
            "prompt_parameters_sha256": prompt_hash.as_str(),
            "provider_id": descriptor.provider_id,
            "provider_revision": descriptor.provider_revision
        }))?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let valid_claim = transaction
            .query_row(
                "SELECT 1 FROM photo_owner_work_claims work
                 JOIN photo_owner_heads head
                   ON head.owner_decision_id = work.owner_decision_id
                 WHERE work.owner_decision_id = ?1
                   AND work.state = 'running'
                   AND work.fence = ?2
                   AND work.lease_owner = ?3
                   AND head.source_revision_id = ?4
                   AND head.owner_review_id = ?5
                   AND head.selected_person_instance_id = ?6
                   AND head.owner_revision = ?7
                   AND head.action = 'select_person'",
                params![
                    work.owner_decision_id,
                    work.fence,
                    lease_owner,
                    work.source_revision_id,
                    work.owner_review_id,
                    work.person_instance_id,
                    work.owner_revision
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !valid_claim {
            transaction.execute(
                "UPDATE photo_owner_work_claims
                 SET state = 'stale', lease_owner = NULL,
                     lease_expires_at_ms = NULL, updated_at_ms = ?2
                 WHERE owner_decision_id = ?1
                   AND state = 'running' AND fence = ?3
                   AND lease_owner = ?4",
                params![work.owner_decision_id, now_ms, work.fence, lease_owner],
            )?;
            transaction.commit()?;
            return Ok(());
        }
        let run_id = owner_analysis_run_id(&work.scope_id);
        transaction.execute(
            "INSERT INTO photo_segmentation_attempts(
                attempt_id, request_handle, run_id, scope_id,
                member_ordinal, source_revision_id,
                source_revision_sha256, disposition, claim_fence,
                request_mode, input_blob_sha256,
                provider_contract_revision, provider_id,
                provider_revision, model_revision,
                preprocessing_revision, prompt_parameters_sha256,
                request_envelope_sha256, provider_invoked, created_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'eligible', ?8,
                'interactive', ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, 1, ?17
             )",
            params![
                attempt_id,
                request_handle,
                run_id,
                work.scope_id,
                work.member_ordinal,
                work.source_revision_id,
                work.source_revision_sha256,
                work.fence,
                work.blob_sha256,
                descriptor.contract_revision,
                descriptor.provider_id,
                descriptor.provider_revision,
                descriptor.model_revision,
                descriptor.preprocessing_revision,
                prompt_hash.as_str(),
                request_envelope_sha256,
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO photo_segmentation_outcomes(
                attempt_id, outcome, unavailable_reason, failure_code,
                rejection_code, mask_count, quality_gate_result,
                response_sha256, completed_at_ms
             ) VALUES (
                ?1, 'unavailable', 'reviewed_model_pack_absent',
                NULL, NULL, 0, 'not_applicable', ?2, ?3
             )",
            params![attempt_id, response_sha256.as_str(), now_ms],
        )?;
        transaction.execute(
            "INSERT INTO photo_artifacts(
                artifact_id, attempt_id, scope_id, member_ordinal,
                source_revision_id, source_revision_sha256,
                input_blob_sha256, artifact_kind, media_type,
                source_width, source_height, rectangle_x, rectangle_y,
                rectangle_width, rectangle_height,
                artifact_schema_revision, artifact_revision,
                preprocessing_revision, provider_contract_revision,
                provider_id, provider_revision, model_revision,
                request_mode, prompt_parameters_sha256,
                quality_gate_revision, quality_approved,
                segmentation_outcome, unavailable_reason, failure_code,
                provenance_json, provenance_sha256, artifact_sha256,
                created_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                'rectangle_source_crop', ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21,
                'interactive', ?22, ?23, 0, 'unavailable',
                'reviewed_model_pack_absent', NULL, ?24, ?25, ?26, ?27
             )",
            params![
                artifact_id,
                attempt_id,
                work.scope_id,
                work.member_ordinal,
                work.source_revision_id,
                work.source_revision_sha256,
                work.blob_sha256,
                media_type_db(work.media_type),
                i64::from(work.width),
                i64::from(work.height),
                i64::from(work.rectangle.x),
                i64::from(work.rectangle.y),
                i64::from(work.rectangle.width),
                i64::from(work.rectangle.height),
                PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
                RECTANGLE_SOURCE_CROP_REVISION_V1,
                descriptor.preprocessing_revision,
                descriptor.contract_revision,
                descriptor.provider_id,
                descriptor.provider_revision,
                descriptor.model_revision,
                prompt_hash.as_str(),
                PHOTO_QUALITY_GATE_REVISION_V1,
                provenance_json,
                provenance_sha256.as_str(),
                artifact_sha256.as_str(),
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO photo_observations(
                observation_id, scope_id, member_ordinal,
                source_revision_id, initial_attempt_id,
                initial_artifact_id, initial_state, created_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, 'needs_review', ?7
             )",
            params![
                observation_id,
                work.scope_id,
                work.member_ordinal,
                work.source_revision_id,
                attempt_id,
                artifact_id,
                now_ms
            ],
        )?;
        let person_evidence_sha256: String = transaction.query_row(
            "SELECT evidence_sha256 FROM photo_person_instances
             WHERE person_instance_id = ?1",
            [&work.person_instance_id],
            |row| row.get(0),
        )?;
        let owner_evidence_sha256 = canonical_hash(
            b"wardrobe.photo.observation-owner-link.v1",
            &OwnerObservationEvidence {
                observation_id: &observation_id,
                artifact_id: &artifact_id,
                source_revision_id: &work.source_revision_id,
                source_revision_sha256: &work.source_revision_sha256,
                owner_review_id: &work.owner_review_id,
                owner_decision_id: &work.owner_decision_id,
                person_instance_id: &work.person_instance_id,
                person_evidence_sha256: &person_evidence_sha256,
                owner_revision: work.owner_revision,
            },
        )?;
        transaction.execute(
            "INSERT INTO photo_observation_owner_links(
                observation_id, scope_id, source_revision_id,
                owner_review_id, owner_decision_id, person_instance_id,
                owner_revision, evidence_sha256, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                observation_id,
                work.scope_id,
                work.source_revision_id,
                work.owner_review_id,
                work.owner_decision_id,
                work.person_instance_id,
                work.owner_revision,
                owner_evidence_sha256.as_str(),
                now_ms
            ],
        )?;
        transaction.execute(
            "UPDATE photo_owner_work_claims
             SET state = 'terminal', lease_owner = NULL,
                 lease_expires_at_ms = NULL, updated_at_ms = ?4
             WHERE owner_decision_id = ?1 AND state = 'running'
               AND fence = ?2 AND lease_owner = ?3",
            params![work.owner_decision_id, work.fence, lease_owner, now_ms],
        )?;
        let prior_claim_state: String = transaction.query_row(
            "SELECT state FROM photo_analysis_member_claims
             WHERE run_id = ?1 AND member_ordinal = ?2",
            params![run_id, work.member_ordinal],
            |row| row.get(0),
        )?;
        transaction.execute(
            "UPDATE photo_analysis_member_claims
             SET state = 'terminal', attempt_count = attempt_count + 1,
                 fence = MAX(fence, ?3), lease_owner = NULL,
                 lease_expires_at_ms = NULL, updated_at_ms = ?4
             WHERE run_id = ?1 AND member_ordinal = ?2",
            params![run_id, work.member_ordinal, work.fence, now_ms],
        )?;
        if prior_claim_state != "terminal" {
            transaction.execute(
                "UPDATE photo_analysis_runs
                 SET terminal_member_count = terminal_member_count + 1,
                     updated_at_ms = ?2
                 WHERE run_id = ?1",
                params![run_id, now_ms],
            )?;
        }
        transaction.execute(
            "UPDATE revision_state
             SET evidence_generation = evidence_generation + 1
             WHERE singleton = 1",
            [],
        )?;
        for (kind, id) in [
            ("segmentation_attempt", attempt_id.as_str()),
            ("artifact", artifact_id.as_str()),
            ("observation", observation_id.as_str()),
        ] {
            link_photo_command_entity(&transaction, &work.request_id, kind, id)?;
        }
        link_owner_command_entity(
            &transaction,
            &work.request_id,
            "observation_owner_link",
            &observation_id,
        )?;
        transaction.commit()?;
        Ok(())
    }
}

fn provider_error_outcome(
    request: &PersonDetectionRequestV1,
    kind: PersonDetectionProviderErrorKind,
) -> PersonDetectionOutcomeV1 {
    let result = match kind {
        PersonDetectionProviderErrorKind::Internal => PersonDetectionResultV1::RetryableFailure {
            reason: PersonDetectionFailureReasonV1::ResourceUnavailable,
        },
        PersonDetectionProviderErrorKind::InvalidRequest
        | PersonDetectionProviderErrorKind::MalformedOutput => {
            PersonDetectionResultV1::PermanentUnavailable {
                reason: PersonDetectionUnavailableReasonV1::InvalidProviderOutput,
            }
        }
    };
    PersonDetectionOutcomeV1 {
        contract_revision: LOCAL_PERSON_DETECTION_CONTRACT_V1.to_owned(),
        request_handle: request.request_handle,
        source_revision_sha256: request.source_revision_sha256.clone(),
        input_blob_sha256: request.input_blob_sha256.clone(),
        result,
    }
}

fn detection_storage_state(
    result: &PersonDetectionResultV1,
) -> (&'static str, &'static str, Option<i64>, &'static str) {
    match result {
        PersonDetectionResultV1::SucceededZero => (
            "succeeded_zero",
            "no_person_detected",
            Some(0),
            "vision_completed",
        ),
        PersonDetectionResultV1::SucceededInstances { instances } => (
            "succeeded_instances",
            "instances_available",
            Some(instances.len() as i64),
            "vision_completed",
        ),
        PersonDetectionResultV1::Overflow { detected_count } => (
            "overflow",
            "overflow",
            Some(i64::from(*detected_count)),
            "output_overflow",
        ),
        PersonDetectionResultV1::RetryableFailure { .. } => (
            "retryable_failure",
            "retryable_failure",
            None,
            "vision_transient",
        ),
        PersonDetectionResultV1::PermanentUnavailable { reason } => (
            "permanent_unavailable",
            "permanent_unavailable",
            None,
            if *reason == PersonDetectionUnavailableReasonV1::InvalidProviderOutput {
                "invalid_provider_output"
            } else {
                "vision_unavailable"
            },
        ),
    }
}

fn insert_detected_person_instance(
    transaction: &Transaction<'_>,
    review_id: &str,
    source_revision_id: &str,
    attempt_id: &str,
    ordinal: i64,
    instance: &DetectedPersonRectangleV1,
    now_ms: i64,
    request_id: &str,
) -> PlatformResult<()> {
    let instance_id = stable_id("photo-person-instance", &format!("{attempt_id}:{ordinal}"));
    let evidence_sha256 = canonical_hash(
        b"wardrobe.photo.person-instance.v1",
        &PersonInstanceEvidence {
            owner_review_id: review_id,
            source_revision_id,
            detection_attempt_id: Some(attempt_id),
            correction_id: None,
            source_kind: "apple_vision",
            instance_ordinal: ordinal,
            rectangle: instance.rectangle,
            confidence_basis_points: Some(instance.confidence_basis_points),
        },
    )?;
    insert_person_instance(
        transaction,
        &instance_id,
        review_id,
        source_revision_id,
        Some(attempt_id),
        None,
        "apple_vision",
        ordinal,
        instance.rectangle,
        Some(instance.confidence_basis_points),
        &evidence_sha256,
        now_ms,
    )?;
    link_owner_command_entity(transaction, request_id, "person_instance", &instance_id)
}

#[allow(clippy::too_many_arguments)]
fn insert_person_instance(
    transaction: &Transaction<'_>,
    instance_id: &str,
    review_id: &str,
    source_revision_id: &str,
    attempt_id: Option<&str>,
    correction_id: Option<&str>,
    source_kind: &str,
    ordinal: i64,
    rectangle: RectV1,
    confidence: Option<u16>,
    evidence_sha256: &Sha256Digest,
    now_ms: i64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO photo_person_instances(
            person_instance_id, owner_review_id, source_revision_id,
            detection_attempt_id, correction_id, source_kind,
            instance_ordinal, rectangle_x, rectangle_y,
            rectangle_width, rectangle_height, confidence_basis_points,
            evidence_sha256, created_at_ms
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
         )",
        params![
            instance_id,
            review_id,
            source_revision_id,
            attempt_id,
            correction_id,
            source_kind,
            ordinal,
            i64::from(rectangle.x),
            i64::from(rectangle.y),
            i64::from(rectangle.width),
            i64::from(rectangle.height),
            confidence.map(i64::from),
            evidence_sha256.as_str(),
            now_ms
        ],
    )?;
    Ok(())
}

fn load_owner_review(
    connection: &Connection,
    owner_review_id: &str,
) -> PlatformResult<PhotoOwnerReviewV1> {
    let row = connection
        .query_row(
            "SELECT review.source_revision_id,
                    source.source_revision_sha256, review.preview_id,
                    review.detection_attempt_id, attempt.state,
                    review.state, attempt.contract_revision,
                    attempt.provider_revision,
                    attempt.preprocessing_revision,
                    attempt.vision_request_revision,
                    attempt.terminal_reason, review.detection_revision,
                    COALESCE(head.owner_revision, 0)
             FROM photo_owner_reviews review
             JOIN photo_person_detection_attempts attempt
               ON attempt.detection_attempt_id =
                  review.detection_attempt_id
             JOIN photo_source_revisions source
               ON source.source_revision_id = review.source_revision_id
             LEFT JOIN photo_owner_heads head
               ON head.source_revision_id = review.source_revision_id
             WHERE review.owner_review_id = ?1",
            [owner_review_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("owner_review_id"))?;
    let mut statement = connection.prepare(
        "SELECT person_instance_id, source_kind, rectangle_x,
                rectangle_y, rectangle_width, rectangle_height,
                confidence_basis_points
         FROM photo_person_instances
         WHERE owner_review_id = ?1
         ORDER BY source_kind, instance_ordinal, person_instance_id",
    )?;
    let raw_instances = statement
        .query_map([owner_review_id], |instance| {
            Ok((
                instance.get::<_, String>(0)?,
                instance.get::<_, String>(1)?,
                instance.get::<_, i64>(2)?,
                instance.get::<_, i64>(3)?,
                instance.get::<_, i64>(4)?,
                instance.get::<_, i64>(5)?,
                instance.get::<_, Option<i64>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let source_revision_id = parse_source_revision_id(&row.0)?;
    let source_revision_sha256 = parse_digest(&row.1)?;
    let instances = raw_instances
        .into_iter()
        .map(|instance| {
            let source_kind = match instance.1.as_str() {
                "apple_vision" => PersonEvidenceKindV1::AppleVision,
                "manual_user_rectangle" => PersonEvidenceKindV1::ManualUserRectangle,
                _ => return Err(PlatformError::Corrupt("person_evidence_kind")),
            };
            let confidence_basis_points = instance
                .6
                .map(|value| to_u16(value, "person_confidence"))
                .transpose()?;
            Ok(PhotoPersonInstanceV1 {
                person_instance_id: parse_person_instance_id(&instance.0)?,
                owner_review_id: parse_owner_review_id(owner_review_id)?,
                source_revision_id,
                source_revision_sha256: source_revision_sha256.clone(),
                source_kind,
                rectangle: RectV1 {
                    x: to_u32(instance.2, "person_rectangle")?,
                    y: to_u32(instance.3, "person_rectangle")?,
                    width: to_u32(instance.4, "person_rectangle")?,
                    height: to_u32(instance.5, "person_rectangle")?,
                },
                confidence_basis_points,
                provider_revision: if source_kind == PersonEvidenceKindV1::AppleVision {
                    Some(APPLE_VISION_PERSON_DETECTION_PROVIDER_REVISION_V1.to_owned())
                } else {
                    None
                },
            })
        })
        .collect::<PlatformResult<Vec<_>>>()?;
    let (photo_revision, _, _) = owner_revision_values(connection)?;
    let terminal_state = detection_terminal_state_from_db(&row.4)?;
    let state = owner_review_state_from_db(&row.5)?;
    let review = PhotoOwnerReviewV1 {
        owner_review_id: parse_owner_review_id(owner_review_id)?,
        source_revision_id,
        source_revision_sha256,
        preview_id: parse_owner_preview_id(&row.2)?,
        terminal_attempt_id: parse_detection_attempt_id(&row.3)?,
        terminal_detection_state: terminal_state,
        state,
        instances,
        provider_contract_revision: row.6,
        provider_revision: row.7,
        preprocessing_revision: row.8,
        vision_request_revision: to_u32(row.9, "vision_request_revision")?,
        safe_reason_code: row.10.filter(|reason| reason != "vision_completed"),
        detection_revision: to_u64(row.11, "detection_revision")?,
        owner_head_revision: to_u64(row.12, "owner_revision")?,
        photo_revision,
    };
    review
        .validate()
        .map_err(|_| PlatformError::Corrupt("owner_review_contract"))?;
    Ok(review)
}

fn ensure_owner_analysis_support(
    transaction: &Transaction<'_>,
    request_id: &str,
    scope_id: &str,
    member_ordinal: i64,
    source_revision_id: &str,
    now_ms: i64,
) -> PlatformResult<()> {
    let run_id = owner_analysis_run_id(scope_id);
    if transaction
        .query_row(
            "SELECT 1 FROM photo_analysis_runs WHERE run_id = ?1",
            [&run_id],
            |_| Ok(()),
        )
        .optional()?
        .is_none()
    {
        let eligible_count: i64 = transaction.query_row(
            "SELECT eligible_count FROM photo_scopes WHERE scope_id = ?1",
            [scope_id],
            |row| row.get(0),
        )?;
        transaction.execute(
            "INSERT INTO photo_analysis_runs(
                run_id, request_id, request_envelope_sha256, scope_id,
                provider_contract_revision, provider_id,
                provider_revision, model_revision,
                preprocessing_revision, quality_gate_revision,
                state, eligible_member_count, terminal_member_count,
                created_at_ms, updated_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9,
                'pending', ?10, 0, ?11, ?11
             )",
            params![
                run_id,
                request_id,
                format!(
                    "{:x}",
                    Sha256::digest(format!("owner-selected-work:{scope_id}").as_bytes())
                ),
                scope_id,
                GARMENT_SEGMENTATION_CONTRACT_V1,
                UNAVAILABLE_SEGMENTATION_PROVIDER_ID_V1,
                UNAVAILABLE_SEGMENTATION_PROVIDER_REVISION_V1,
                PHOTO_PREPROCESSING_REVISION_V1,
                OWNER_WORK_QUALITY_GATE_REVISION,
                eligible_count,
                now_ms
            ],
        )?;
        link_photo_command_entity(transaction, request_id, "run", &run_id)?;
    }
    transaction.execute(
        "INSERT OR IGNORE INTO photo_analysis_member_claims(
            run_id, scope_id, member_ordinal, source_revision_id,
            disposition, state, attempt_count, fence,
            lease_owner, lease_expires_at_ms, created_at_ms, updated_at_ms
         ) VALUES (
            ?1, ?2, ?3, ?4, 'eligible', 'pending', 0, 0,
            NULL, NULL, ?5, ?5
         )",
        params![run_id, scope_id, member_ordinal, source_revision_id, now_ms],
    )?;
    Ok(())
}

fn require_unavailable_segmentation_descriptor(
    descriptor: &SegmentationProviderDescriptorV1,
) -> PlatformResult<()> {
    if descriptor.contract_revision == GARMENT_SEGMENTATION_CONTRACT_V1
        && descriptor.provider_id == UNAVAILABLE_SEGMENTATION_PROVIDER_ID_V1
        && descriptor.provider_revision == UNAVAILABLE_SEGMENTATION_PROVIDER_REVISION_V1
        && descriptor.model_revision.is_none()
        && descriptor.preprocessing_revision == PHOTO_PREPROCESSING_REVISION_V1
    {
        Ok(())
    } else {
        Err(PlatformError::InvalidInput("owner_segmentation_provider"))
    }
}

fn owner_analysis_run_id(scope_id: &str) -> String {
    stable_id(
        "photo-owner-analysis-run",
        &format!("{scope_id}:{OWNER_WORK_QUALITY_GATE_REVISION}"),
    )
}

fn owner_revision_values(connection: &Connection) -> PlatformResult<(u64, u64, u64)> {
    let row = connection.query_row(
        "SELECT photo_revision, owner_revision, evidence_generation
         FROM revision_state WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        },
    )?;
    Ok((
        to_u64(row.0, "photo_revision")?,
        to_u64(row.1, "owner_revision")?,
        to_u64(row.2, "evidence_generation")?,
    ))
}

fn replay<Q: Serialize, R: DeserializeOwned>(
    transaction: &Transaction<'_>,
    command: &str,
    request: &Q,
) -> PlatformResult<Option<R>> {
    let request_id = request_id_from_json(request)?;
    let expected_envelope = envelope_hash(request)?;
    let row = transaction
        .query_row(
            "SELECT command_name, envelope_hash, response_json
             FROM command_receipts WHERE request_id = ?1",
            [&request_id],
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
        Some((stored_command, stored_envelope, response))
            if stored_command == command && stored_envelope == expected_envelope =>
        {
            Ok(Some(serde_json::from_str(&response)?))
        }
        Some(_) => Err(PlatformError::Conflict("command_envelope_changed")),
        None => Ok(None),
    }
}

fn store_receipt<Q: Serialize, R: Serialize>(
    transaction: &Transaction<'_>,
    command: &str,
    request: &Q,
    response: &R,
    now_ms: i64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO command_receipts(
            request_id, command_name, envelope_hash,
            response_json, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            request_id_from_json(request)?,
            command,
            envelope_hash(request)?,
            serde_json::to_string(response)?,
            now_ms
        ],
    )?;
    Ok(())
}

fn request_id_from_json<Q: Serialize>(request: &Q) -> PlatformResult<String> {
    serde_json::to_value(request)?
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(PlatformError::Corrupt("owner_request_id"))
}

fn envelope_hash<Q: Serialize>(request: &Q) -> PlatformResult<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(request)?)
    ))
}

fn canonical_hash<T: Serialize>(domain: &[u8], value: &T) -> PlatformResult<Sha256Digest> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(serde_json::to_vec(value)?);
    Sha256Digest::parse(format!("{:x}", digest.finalize()))
        .map_err(|_| PlatformError::Corrupt("owner_canonical_hash"))
}

fn link_owner_command_entity(
    transaction: &Transaction<'_>,
    request_id: &str,
    kind: &str,
    entity_id: &str,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT OR IGNORE INTO photo_owner_command_entities(
            request_id, entity_kind, entity_id
         ) VALUES (?1, ?2, ?3)",
        params![request_id, kind, entity_id],
    )?;
    Ok(())
}

fn link_photo_command_entity(
    transaction: &Transaction<'_>,
    request_id: &str,
    kind: &str,
    entity_id: &str,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT OR IGNORE INTO photo_command_entities(
            request_id, entity_kind, entity_id
         ) VALUES (?1, ?2, ?3)",
        params![request_id, kind, entity_id],
    )?;
    Ok(())
}

fn parse_owner_review_cursor(
    cursor: Option<&PageCursorV1>,
    state: PhotoOwnerReviewStateV1,
    photo_revision: u64,
    owner_revision: u64,
) -> PlatformResult<Option<(i64, String)>> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let prefix = format!(
        "photo-owner-reviews.{}.{}.{}.",
        owner_review_state_db(state),
        photo_revision,
        owner_revision
    );
    let value = cursor
        .as_str()
        .strip_prefix(&prefix)
        .ok_or(PlatformError::Conflict("snapshot_expired"))?;
    let (updated_at, review_id) = value
        .split_once('.')
        .ok_or(PlatformError::InvalidInput("owner_review_cursor"))?;
    let updated_at = updated_at
        .parse::<i64>()
        .map_err(|_| PlatformError::InvalidInput("owner_review_cursor"))?;
    parse_owner_review_id(review_id)?;
    Ok(Some((updated_at, review_id.to_owned())))
}

fn make_owner_review_cursor(
    state: PhotoOwnerReviewStateV1,
    photo_revision: u64,
    owner_revision: u64,
    updated_at_ms: i64,
    review_id: &str,
) -> PlatformResult<PageCursorV1> {
    PageCursorV1::new(format!(
        "photo-owner-reviews.{}.{}.{}.{}.{}",
        owner_review_state_db(state),
        photo_revision,
        owner_revision,
        updated_at_ms,
        review_id
    ))
    .map_err(|_| PlatformError::Corrupt("owner_review_cursor"))
}

fn owner_review_state_db(state: PhotoOwnerReviewStateV1) -> &'static str {
    match state {
        PhotoOwnerReviewStateV1::InstancesAvailable => "instances_available",
        PhotoOwnerReviewStateV1::NoPersonDetected => "no_person_detected",
        PhotoOwnerReviewStateV1::Overflow => "overflow",
        PhotoOwnerReviewStateV1::RetryableFailure => "retryable_failure",
        PhotoOwnerReviewStateV1::PermanentUnavailable => "permanent_unavailable",
    }
}

fn owner_review_state_from_db(value: &str) -> PlatformResult<PhotoOwnerReviewStateV1> {
    match value {
        "instances_available" => Ok(PhotoOwnerReviewStateV1::InstancesAvailable),
        "no_person_detected" => Ok(PhotoOwnerReviewStateV1::NoPersonDetected),
        "overflow" => Ok(PhotoOwnerReviewStateV1::Overflow),
        "retryable_failure" => Ok(PhotoOwnerReviewStateV1::RetryableFailure),
        "permanent_unavailable" => Ok(PhotoOwnerReviewStateV1::PermanentUnavailable),
        _ => Err(PlatformError::Corrupt("owner_review_state")),
    }
}

fn detection_terminal_state_from_db(value: &str) -> PlatformResult<PersonDetectionTerminalStateV1> {
    match value {
        "succeeded_zero" => Ok(PersonDetectionTerminalStateV1::SucceededZero),
        "succeeded_instances" => Ok(PersonDetectionTerminalStateV1::SucceededInstances),
        "overflow" => Ok(PersonDetectionTerminalStateV1::Overflow),
        "retryable_failure" => Ok(PersonDetectionTerminalStateV1::RetryableFailure),
        "permanent_unavailable" => Ok(PersonDetectionTerminalStateV1::PermanentUnavailable),
        _ => Err(PlatformError::Corrupt("person_detection_state")),
    }
}

fn owner_action_db(value: PhotoOwnerActionV1) -> &'static str {
    match value {
        PhotoOwnerActionV1::SelectPerson => "select_person",
        PhotoOwnerActionV1::OwnerAbsent => "owner_absent",
    }
}

fn media_type_db(value: PhotoMediaTypeV1) -> &'static str {
    match value {
        PhotoMediaTypeV1::ImageJpeg => "image/jpeg",
        PhotoMediaTypeV1::ImagePng => "image/png",
        PhotoMediaTypeV1::ImageWebp => "image/webp",
    }
}

fn media_type_from_db(value: &str) -> PlatformResult<PhotoMediaTypeV1> {
    match value {
        "image/jpeg" => Ok(PhotoMediaTypeV1::ImageJpeg),
        "image/png" => Ok(PhotoMediaTypeV1::ImagePng),
        "image/webp" => Ok(PhotoMediaTypeV1::ImageWebp),
        _ => Err(PlatformError::Corrupt("photo_media_type")),
    }
}

fn parse_uuid(value: &str, field: &'static str) -> PlatformResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt(field))
}

fn parse_request_id(value: &str) -> PlatformResult<wardrobe_core::RequestId> {
    wardrobe_core::RequestId::new(parse_uuid(value, "request_id")?)
        .map_err(|_| PlatformError::Corrupt("request_id"))
}

fn parse_digest(value: &str) -> PlatformResult<Sha256Digest> {
    Sha256Digest::parse(value.to_owned()).map_err(|_| PlatformError::Corrupt("photo_sha256"))
}

fn parse_analysis_run_id(value: &str) -> PlatformResult<PhotoAnalysisRunId> {
    PhotoAnalysisRunId::new(parse_uuid(value, "person_run_id")?)
        .map_err(|_| PlatformError::Corrupt("person_run_id"))
}

fn parse_source_revision_id(value: &str) -> PlatformResult<PhotoSourceRevisionId> {
    PhotoSourceRevisionId::new(parse_uuid(value, "source_revision_id")?)
        .map_err(|_| PlatformError::Corrupt("source_revision_id"))
}

fn parse_owner_review_id(value: &str) -> PlatformResult<PhotoOwnerReviewId> {
    PhotoOwnerReviewId::new(parse_uuid(value, "owner_review_id")?)
        .map_err(|_| PlatformError::Corrupt("owner_review_id"))
}

fn parse_owner_preview_id(value: &str) -> PlatformResult<PhotoOwnerPreviewId> {
    PhotoOwnerPreviewId::new(parse_uuid(value, "owner_preview_id")?)
        .map_err(|_| PlatformError::Corrupt("owner_preview_id"))
}

fn parse_detection_attempt_id(value: &str) -> PlatformResult<PhotoPersonDetectionAttemptId> {
    PhotoPersonDetectionAttemptId::new(parse_uuid(value, "detection_attempt_id")?)
        .map_err(|_| PlatformError::Corrupt("detection_attempt_id"))
}

fn parse_person_instance_id(value: &str) -> PlatformResult<PhotoPersonInstanceId> {
    PhotoPersonInstanceId::new(parse_uuid(value, "person_instance_id")?)
        .map_err(|_| PlatformError::Corrupt("person_instance_id"))
}

fn parse_owner_decision_id(value: &str) -> PlatformResult<PhotoOwnerDecisionId> {
    PhotoOwnerDecisionId::new(parse_uuid(value, "owner_decision_id")?)
        .map_err(|_| PlatformError::Corrupt("owner_decision_id"))
}

fn parse_person_request_handle(value: &str) -> PlatformResult<PersonDetectionRequestHandle> {
    PersonDetectionRequestHandle::new(parse_uuid(value, "person_request_handle")?)
        .map_err(|_| PlatformError::Corrupt("person_request_handle"))
}

fn parse_segmentation_request_handle(value: &str) -> PlatformResult<SegmentationRequestHandle> {
    SegmentationRequestHandle::new(parse_uuid(value, "segmentation_request_handle")?)
        .map_err(|_| PlatformError::Corrupt("segmentation_request_handle"))
}

fn to_u64(value: i64, field: &'static str) -> PlatformResult<u64> {
    u64::try_from(value).map_err(|_| PlatformError::Corrupt(field))
}

fn to_u32(value: i64, field: &'static str) -> PlatformResult<u32> {
    u32::try_from(value).map_err(|_| PlatformError::Corrupt(field))
}

fn to_u16(value: i64, field: &'static str) -> PlatformResult<u16> {
    u16::try_from(value).map_err(|_| PlatformError::Corrupt(field))
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}
