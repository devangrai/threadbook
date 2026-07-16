use crate::catalog_repository::complete_blob_owner_count;
use crate::database::stable_id;
use crate::source_image::{verify_source_image, VerifiedSourceImage};
use crate::{BlobStore, Database, PlatformError, PlatformResult};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use wardrobe_core::{
    AnalyzePhotoScopeV1Request, AnalyzePhotoScopeV1Response, BoundedPhotoArtifactBytesV1,
    ConformingGarmentSegmentationProviderV1, CorrectPhotoOwnerV1Request,
    CorrectPhotoOwnerV1Response, CorrectPhotoPersonDetectionV1Request,
    CorrectPhotoPersonDetectionV1Response, CreatePhotoScopeV1Request, CreatePhotoScopeV1Response,
    DecidePhotoOwnerV1Request, DecidePhotoOwnerV1Response, DetectPhotoScopePeopleV1Request,
    DetectPhotoScopePeopleV1Response, GarmentSegmentationProvider, ImportedPhotoRootV1,
    ListImportedPhotoRootsV1Request, ListImportedPhotoRootsV1Response,
    ListPhotoObservationsV1Request, ListPhotoObservationsV1Response,
    ListPhotoOwnerReviewsV1Request, ListPhotoOwnerReviewsV1Response,
    LocalPersonDetectionProviderV1, PageCursorV1, PhotoAnalysisPort, PhotoAnalysisPortError,
    PhotoAnalysisPortErrorKind, PhotoAnalysisPortResult, PhotoAnalysisRunId,
    PhotoAnalysisRunStateV1, PhotoArtifactId, PhotoArtifactKindV1, PhotoArtifactV1,
    PhotoImportScanId, PhotoMediaTypeV1, PhotoObservationId, PhotoObservationStateV1,
    PhotoObservationV1, PhotoQuarantineReasonV1, PhotoReviewActionV1, PhotoReviewDecisionId,
    PhotoReviewDecisionV1, PhotoReviewHeadV1, PhotoScopeId, PhotoScopeV1,
    PhotoSegmentationOutcomeCodeV1, PhotoSourceDispositionV1, PhotoSourceRevisionId,
    PhotoSourceRevisionV1, PromptPhotoObservationV1Request, PromptPhotoObservationV1Response,
    ReadPhotoArtifactV1Request, ReadPhotoArtifactV1Response, ReadPhotoOwnerPreviewV1Request,
    ReadPhotoOwnerPreviewV1Response, RectV1, ReplayStatusV1, RetryPhotoPersonDetectionV1Request,
    RetryPhotoPersonDetectionV1Response, ReviewPhotoObservationV1Request,
    ReviewPhotoObservationV1Response, SegmentationFailureCodeV1, SegmentationOutcomeV1,
    SegmentationProviderDescriptorV1, SegmentationProviderErrorKind, SegmentationRequestHandle,
    SegmentationRequestModeKindV1, SegmentationRequestModeV1, SegmentationRequestV1,
    SegmentationResultV1, SegmentationUnavailableReasonV1, Sha256Digest, SourceId, Validate,
    GARMENT_SEGMENTATION_CONTRACT_V1, MAX_PHOTO_SCOPE_MEMBERS, PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
    PHOTO_PREPROCESSING_REVISION_V1, PHOTO_QUALITY_GATE_REVISION_V1,
    RECTANGLE_SOURCE_CROP_REVISION_V1, SCHEMA_VERSION_V1, SOURCE_IMAGE_REFERENCE_REVISION_V1,
};

const CREATE_SCOPE_COMMAND: &str = "create_photo_scope_v1";
const ANALYZE_SCOPE_COMMAND: &str = "analyze_photo_scope_v1";
const PROMPT_COMMAND: &str = "prompt_photo_observation_v1";
const REVIEW_COMMAND: &str = "review_photo_observation_v1";
const SCOPE_SCHEMA_REVISION: &str = "photo-scope-v1";
const CLAIM_LEASE_MS: i64 = 60_000;

pub(crate) fn augment_photo_deletion_closure(
    connection: &Connection,
    snapshot_token: &str,
    source_ids: &BTreeSet<String>,
    try_on_approval_ids: &BTreeSet<String>,
) -> PlatformResult<()> {
    let mut revision_ids = BTreeSet::new();
    for source_id in source_ids {
        extend_photo_set(
            connection,
            "SELECT source_revision_id FROM photo_source_revisions WHERE source_id = ?1",
            source_id,
            &mut revision_ids,
        )?;
    }

    let mut scope_ids = BTreeSet::new();
    for revision_id in &revision_ids {
        extend_photo_set(
            connection,
            "SELECT scope_id FROM photo_scope_members WHERE source_revision_id = ?1",
            revision_id,
            &mut scope_ids,
        )?;
    }
    if scope_ids.is_empty() {
        return Ok(());
    }
    for scope_id in scope_ids.clone() {
        extend_photo_set(
            connection,
            "SELECT source_revision_id FROM photo_scope_members WHERE scope_id = ?1",
            &scope_id,
            &mut revision_ids,
        )?;
    }

    let mut run_ids = BTreeSet::new();
    let mut attempt_ids = BTreeSet::new();
    let mut artifact_ids = BTreeSet::new();
    let mut observation_ids = BTreeSet::new();
    let mut decision_ids = BTreeSet::new();
    let mut detection_run_ids = BTreeSet::new();
    let mut detection_attempt_ids = BTreeSet::new();
    let mut owner_preview_ids = BTreeSet::new();
    let mut owner_review_ids = BTreeSet::new();
    let mut detection_correction_ids = BTreeSet::new();
    let mut person_instance_ids = BTreeSet::new();
    let mut owner_decision_ids = BTreeSet::new();
    let mut request_ids = BTreeSet::new();
    for scope_id in &scope_ids {
        extend_photo_set(
            connection,
            "SELECT run_id FROM photo_analysis_runs WHERE scope_id = ?1",
            scope_id,
            &mut run_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT artifact_id FROM photo_artifacts WHERE scope_id = ?1",
            scope_id,
            &mut artifact_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT observation_id FROM photo_observations WHERE scope_id = ?1",
            scope_id,
            &mut observation_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT request_id FROM photo_scopes WHERE scope_id = ?1",
            scope_id,
            &mut request_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT run_id FROM photo_person_detection_runs WHERE scope_id = ?1",
            scope_id,
            &mut detection_run_ids,
        )?;
    }
    for run_id in &run_ids {
        extend_photo_set(
            connection,
            "SELECT attempt_id FROM photo_segmentation_attempts WHERE run_id = ?1",
            run_id,
            &mut attempt_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT request_id FROM photo_analysis_runs WHERE run_id = ?1",
            run_id,
            &mut request_ids,
        )?;
    }
    for observation_id in &observation_ids {
        extend_photo_set(
            connection,
            "SELECT decision_id FROM photo_review_decisions WHERE observation_id = ?1",
            observation_id,
            &mut decision_ids,
        )?;
    }
    for decision_id in &decision_ids {
        extend_photo_set(
            connection,
            "SELECT request_id FROM photo_review_decisions WHERE decision_id = ?1",
            decision_id,
            &mut request_ids,
        )?;
    }
    for revision_id in &revision_ids {
        extend_photo_set(
            connection,
            "SELECT detection_attempt_id
             FROM photo_person_detection_attempts
             WHERE source_revision_id = ?1",
            revision_id,
            &mut detection_attempt_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT preview_id FROM photo_owner_preview_references
             WHERE source_revision_id = ?1",
            revision_id,
            &mut owner_preview_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT owner_review_id FROM photo_owner_reviews
             WHERE source_revision_id = ?1",
            revision_id,
            &mut owner_review_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT owner_decision_id FROM photo_owner_decisions
             WHERE source_revision_id = ?1",
            revision_id,
            &mut owner_decision_ids,
        )?;
    }
    for review_id in &owner_review_ids {
        extend_photo_set(
            connection,
            "SELECT correction_id FROM photo_detection_corrections
             WHERE owner_review_id = ?1",
            review_id,
            &mut detection_correction_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT person_instance_id FROM photo_person_instances
             WHERE owner_review_id = ?1",
            review_id,
            &mut person_instance_ids,
        )?;
    }
    for owner_decision_id in &owner_decision_ids {
        extend_photo_set(
            connection,
            "SELECT request_id FROM photo_owner_decisions
             WHERE owner_decision_id = ?1",
            owner_decision_id,
            &mut request_ids,
        )?;
    }
    for correction_id in &detection_correction_ids {
        extend_photo_set(
            connection,
            "SELECT request_id FROM photo_detection_corrections
             WHERE correction_id = ?1",
            correction_id,
            &mut request_ids,
        )?;
    }
    for attempt_id in &detection_attempt_ids {
        extend_photo_set(
            connection,
            "SELECT run_id FROM photo_person_detection_attempts
             WHERE detection_attempt_id = ?1",
            attempt_id,
            &mut detection_run_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT request_id FROM photo_person_detection_attempts
             WHERE detection_attempt_id = ?1 AND request_id IS NOT NULL",
            attempt_id,
            &mut request_ids,
        )?;
    }
    for run_id in &detection_run_ids {
        extend_photo_set(
            connection,
            "SELECT detection_attempt_id
             FROM photo_person_detection_attempts
             WHERE run_id = ?1",
            run_id,
            &mut detection_attempt_ids,
        )?;
        extend_photo_set(
            connection,
            "SELECT request_id FROM photo_person_detection_runs
             WHERE run_id = ?1",
            run_id,
            &mut request_ids,
        )?;
    }
    close_photo_owner_command_entities(
        connection,
        &mut request_ids,
        &mut detection_run_ids,
        &mut detection_attempt_ids,
        &mut owner_preview_ids,
        &mut owner_review_ids,
        &mut detection_correction_ids,
        &mut person_instance_ids,
        &mut owner_decision_ids,
        &mut observation_ids,
    )?;
    for (kind, ids) in [
        ("scope", &scope_ids),
        ("source_revision", &revision_ids),
        ("run", &run_ids),
        ("segmentation_attempt", &attempt_ids),
        ("artifact", &artifact_ids),
        ("observation", &observation_ids),
        ("review_decision", &decision_ids),
    ] {
        for id in ids {
            let mut statement = connection.prepare(
                "SELECT request_id FROM photo_command_entities
                 WHERE entity_kind = ?1 AND entity_id = ?2",
            )?;
            request_ids.extend(
                statement
                    .query_map(params![kind, id], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
    }

    for scope_id in &scope_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "source_records",
            &format!("photo_scope:{scope_id}"),
        )?;
        let mut members = connection.prepare(
            "SELECT member_ordinal FROM photo_scope_members
             WHERE scope_id = ?1 ORDER BY member_ordinal",
        )?;
        for ordinal in members
            .query_map([scope_id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "source_records",
                &format!("photo_scope_member:{scope_id}:{ordinal}"),
            )?;
        }
    }
    for revision_id in &revision_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "source_records",
            &format!("photo_source_revision:{revision_id}"),
        )?;
    }
    for run_id in &run_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "evidence_records",
            &format!("photo_analysis_run:{run_id}"),
        )?;
        let mut claims = connection.prepare(
            "SELECT member_ordinal FROM photo_analysis_member_claims
             WHERE run_id = ?1 ORDER BY member_ordinal",
        )?;
        for ordinal in claims
            .query_map([run_id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "evidence_records",
                &format!("photo_analysis_member_claim:{run_id}:{ordinal}"),
            )?;
        }
    }
    for attempt_id in &attempt_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "evidence_records",
            &format!("photo_segmentation_attempt:{attempt_id}"),
        )?;
        if connection
            .query_row(
                "SELECT 1 FROM photo_segmentation_outcomes WHERE attempt_id = ?1",
                [attempt_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "evidence_records",
                &format!("photo_segmentation_outcome:{attempt_id}"),
            )?;
        }
    }
    for artifact_id in &artifact_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "evidence_records",
            &format!("photo_artifact:{artifact_id}"),
        )?;
        let mut parents = connection.prepare(
            "SELECT parent_ordinal FROM photo_artifact_parents
             WHERE artifact_id = ?1 ORDER BY parent_ordinal",
        )?;
        for ordinal in parents
            .query_map([artifact_id], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "evidence_records",
                &format!("photo_artifact_parent:{artifact_id}:{ordinal}"),
            )?;
        }
    }
    for observation_id in &observation_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "evidence_records",
            &format!("photo_observation:{observation_id}"),
        )?;
        if connection
            .query_row(
                "SELECT 1 FROM photo_review_heads WHERE observation_id = ?1",
                [observation_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "evidence_records",
                &format!("photo_review_head:{observation_id}"),
            )?;
        }
        if connection
            .query_row(
                "SELECT 1 FROM photo_observation_owner_links
                 WHERE observation_id = ?1",
                [observation_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "decision_records",
                &format!("photo_observation_owner_link:{observation_id}"),
            )?;
        }
    }
    for decision_id in &decision_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "decision_records",
            &format!("photo_review_decision:{decision_id}"),
        )?;
    }
    for attempt_id in &detection_attempt_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "evidence_records",
            &format!("photo_person_detection_attempt:{attempt_id}"),
        )?;
    }
    for run_id in &detection_run_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "evidence_records",
            &format!("photo_person_detection_run:{run_id}"),
        )?;
    }
    for preview_id in &owner_preview_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "evidence_records",
            &format!("photo_owner_preview:{preview_id}"),
        )?;
    }
    for review_id in &owner_review_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "decision_records",
            &format!("photo_owner_review:{review_id}"),
        )?;
    }
    for correction_id in &detection_correction_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "decision_records",
            &format!("photo_detection_correction:{correction_id}"),
        )?;
    }
    for person_id in &person_instance_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "evidence_records",
            &format!("photo_person_instance:{person_id}"),
        )?;
    }
    for owner_decision_id in &owner_decision_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "decision_records",
            &format!("photo_owner_decision:{owner_decision_id}"),
        )?;
        if connection
            .query_row(
                "SELECT 1 FROM photo_owner_work_claims
                 WHERE owner_decision_id = ?1",
                [owner_decision_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "evidence_records",
                &format!("photo_owner_work:{owner_decision_id}"),
            )?;
        }
    }
    for revision_id in &revision_ids {
        if connection
            .query_row(
                "SELECT 1 FROM photo_owner_heads WHERE source_revision_id = ?1",
                [revision_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "decision_records",
                &format!("photo_owner_head:{revision_id}"),
            )?;
        }
    }
    for request_id in &request_ids {
        insert_photo_preview(
            connection,
            snapshot_token,
            "decision_records",
            &format!("photo_command_receipt:{request_id}"),
        )?;
        let mut entities = connection.prepare(
            "SELECT entity_kind, entity_id FROM photo_command_entities
             WHERE request_id = ?1 ORDER BY entity_kind, entity_id",
        )?;
        for (kind, id) in entities
            .query_map([request_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "decision_records",
                &format!("photo_command_entity:{request_id}:{kind}:{id}"),
            )?;
        }
        let mut owner_entities = connection.prepare(
            "SELECT entity_kind, entity_id FROM photo_owner_command_entities
             WHERE request_id = ?1 ORDER BY entity_kind, entity_id",
        )?;
        for (kind, id) in owner_entities
            .query_map([request_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            insert_photo_preview(
                connection,
                snapshot_token,
                "decision_records",
                &format!("photo_owner_command_entity:{request_id}:{kind}:{id}"),
            )?;
        }
    }

    materialize_photo_blob_rows(
        connection,
        snapshot_token,
        source_ids,
        &revision_ids,
        &attempt_ids,
        &artifact_ids,
        &detection_attempt_ids,
        &owner_preview_ids,
        try_on_approval_ids,
    )
}

fn extend_photo_set(
    connection: &Connection,
    sql: &str,
    value: &str,
    output: &mut BTreeSet<String>,
) -> PlatformResult<()> {
    let mut statement = connection.prepare(sql)?;
    output.extend(
        statement
            .query_map([value], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn close_photo_owner_command_entities(
    connection: &Connection,
    request_ids: &mut BTreeSet<String>,
    detection_run_ids: &mut BTreeSet<String>,
    detection_attempt_ids: &mut BTreeSet<String>,
    owner_preview_ids: &mut BTreeSet<String>,
    owner_review_ids: &mut BTreeSet<String>,
    detection_correction_ids: &mut BTreeSet<String>,
    person_instance_ids: &mut BTreeSet<String>,
    owner_decision_ids: &mut BTreeSet<String>,
    observation_ids: &mut BTreeSet<String>,
) -> PlatformResult<()> {
    loop {
        let before = (
            request_ids.len(),
            detection_run_ids.len(),
            detection_attempt_ids.len(),
            owner_preview_ids.len(),
            owner_review_ids.len(),
            detection_correction_ids.len(),
            person_instance_ids.len(),
            owner_decision_ids.len(),
            observation_ids.len(),
        );

        for (kind, ids) in [
            ("detection_run", &*detection_run_ids),
            ("detection_attempt", &*detection_attempt_ids),
            ("owner_preview", &*owner_preview_ids),
            ("owner_review", &*owner_review_ids),
            ("detection_correction", &*detection_correction_ids),
            ("person_instance", &*person_instance_ids),
            ("owner_decision", &*owner_decision_ids),
            ("owner_work", &*owner_decision_ids),
            ("observation_owner_link", &*observation_ids),
        ] {
            for id in ids {
                let mut statement = connection.prepare(
                    "SELECT request_id FROM photo_owner_command_entities
                     WHERE entity_kind = ?1 AND entity_id = ?2",
                )?;
                request_ids.extend(
                    statement
                        .query_map(params![kind, id], |row| row.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
        }

        for request_id in request_ids.clone() {
            let mut statement = connection.prepare(
                "SELECT entity_kind, entity_id
                 FROM photo_owner_command_entities
                 WHERE request_id = ?1",
            )?;
            let entities = statement
                .query_map([&request_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (kind, id) in entities {
                match kind.as_str() {
                    "detection_run" => {
                        detection_run_ids.insert(id);
                    }
                    "detection_attempt" => {
                        detection_attempt_ids.insert(id);
                    }
                    "owner_preview" => {
                        owner_preview_ids.insert(id);
                    }
                    "owner_review" => {
                        owner_review_ids.insert(id);
                    }
                    "detection_correction" => {
                        detection_correction_ids.insert(id);
                    }
                    "person_instance" => {
                        person_instance_ids.insert(id);
                    }
                    "owner_decision" | "owner_work" => {
                        owner_decision_ids.insert(id);
                    }
                    "observation_owner_link" => {
                        observation_ids.insert(id);
                    }
                    _ => return Err(PlatformError::Corrupt("photo_owner_command_entity_kind")),
                }
            }
        }

        let after = (
            request_ids.len(),
            detection_run_ids.len(),
            detection_attempt_ids.len(),
            owner_preview_ids.len(),
            owner_review_ids.len(),
            detection_correction_ids.len(),
            person_instance_ids.len(),
            owner_decision_ids.len(),
            observation_ids.len(),
        );
        if after == before {
            return Ok(());
        }
    }
}

fn insert_photo_preview(
    connection: &Connection,
    token: &str,
    class: &str,
    id: &str,
) -> PlatformResult<()> {
    connection.execute(
        "INSERT OR IGNORE INTO deletion_preview_items(
            snapshot_token, dependency_class, entity_id, sort_key
         ) VALUES (?1, ?2, ?3, ?3)",
        params![token, class, id],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::close_photo_owner_command_entities;
    use rusqlite::Connection;
    use std::collections::BTreeSet;

    #[test]
    fn owner_command_entity_closure_reverse_traverses_to_a_fixed_point() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE photo_owner_command_entities(
                    request_id TEXT NOT NULL,
                    entity_kind TEXT NOT NULL,
                    entity_id TEXT NOT NULL
                 );
                 INSERT INTO photo_owner_command_entities VALUES
                    ('request-1', 'detection_run', 'run-1'),
                    ('request-1', 'detection_attempt', 'attempt-1'),
                    ('request-2', 'detection_attempt', 'attempt-1'),
                    ('request-2', 'owner_review', 'review-1'),
                    ('request-3', 'owner_review', 'review-1'),
                    ('request-3', 'person_instance', 'person-1'),
                    ('request-4', 'person_instance', 'person-1'),
                    ('request-4', 'owner_work', 'decision-1'),
                    ('request-5', 'owner_decision', 'decision-1'),
                    ('request-5', 'observation_owner_link', 'observation-1');",
            )
            .unwrap();

        let mut request_ids = BTreeSet::new();
        let mut detection_run_ids = BTreeSet::from(["run-1".to_owned()]);
        let mut detection_attempt_ids = BTreeSet::new();
        let mut owner_preview_ids = BTreeSet::new();
        let mut owner_review_ids = BTreeSet::new();
        let mut detection_correction_ids = BTreeSet::new();
        let mut person_instance_ids = BTreeSet::new();
        let mut owner_decision_ids = BTreeSet::new();
        let mut observation_ids = BTreeSet::new();

        close_photo_owner_command_entities(
            &connection,
            &mut request_ids,
            &mut detection_run_ids,
            &mut detection_attempt_ids,
            &mut owner_preview_ids,
            &mut owner_review_ids,
            &mut detection_correction_ids,
            &mut person_instance_ids,
            &mut owner_decision_ids,
            &mut observation_ids,
        )
        .unwrap();

        assert_eq!(request_ids.len(), 5);
        assert!(detection_attempt_ids.contains("attempt-1"));
        assert!(owner_review_ids.contains("review-1"));
        assert!(person_instance_ids.contains("person-1"));
        assert!(owner_decision_ids.contains("decision-1"));
        assert!(observation_ids.contains("observation-1"));
    }
}

fn materialize_photo_blob_rows(
    connection: &Connection,
    snapshot_token: &str,
    source_ids: &BTreeSet<String>,
    revision_ids: &BTreeSet<String>,
    attempt_ids: &BTreeSet<String>,
    artifact_ids: &BTreeSet<String>,
    detection_attempt_ids: &BTreeSet<String>,
    owner_preview_ids: &BTreeSet<String>,
    try_on_approval_ids: &BTreeSet<String>,
) -> PlatformResult<()> {
    let mut candidates = BTreeMap::<String, &'static str>::new();
    let mut closed = BTreeMap::<String, i64>::new();
    for source_id in source_ids {
        for (sql, class) in [
            (
                "SELECT blob_sha256 FROM local_sources
                 WHERE source_id = ?1 AND blob_sha256 IS NOT NULL",
                "originals",
            ),
            (
                "SELECT blob_sha256 FROM source_provenance
                 WHERE source_id = ?1 AND blob_sha256 IS NOT NULL",
                "originals",
            ),
            (
                "SELECT blob_sha256 FROM derivatives WHERE source_id = ?1",
                "derivatives",
            ),
        ] {
            collect_photo_blob_refs(
                connection,
                sql,
                source_id,
                class,
                &mut candidates,
                &mut closed,
            )?;
        }
    }
    for revision_id in revision_ids {
        collect_photo_blob_refs(
            connection,
            "SELECT blob_sha256 FROM photo_source_revisions
             WHERE source_revision_id = ?1 AND blob_sha256 IS NOT NULL",
            revision_id,
            "originals",
            &mut candidates,
            &mut closed,
        )?;
    }
    for attempt_id in attempt_ids {
        collect_photo_blob_refs(
            connection,
            "SELECT input_blob_sha256 FROM photo_segmentation_attempts
             WHERE attempt_id = ?1 AND input_blob_sha256 IS NOT NULL",
            attempt_id,
            "originals",
            &mut candidates,
            &mut closed,
        )?;
    }
    for artifact_id in artifact_ids {
        collect_photo_blob_refs(
            connection,
            "SELECT input_blob_sha256 FROM photo_artifacts WHERE artifact_id = ?1",
            artifact_id,
            "originals",
            &mut candidates,
            &mut closed,
        )?;
    }
    for detection_attempt_id in detection_attempt_ids {
        collect_photo_blob_refs(
            connection,
            "SELECT input_blob_sha256 FROM photo_person_detection_attempts
             WHERE detection_attempt_id = ?1",
            detection_attempt_id,
            "originals",
            &mut candidates,
            &mut closed,
        )?;
    }
    for preview_id in owner_preview_ids {
        collect_photo_blob_refs(
            connection,
            "SELECT blob_sha256 FROM photo_owner_preview_references
             WHERE preview_id = ?1",
            preview_id,
            "originals",
            &mut candidates,
            &mut closed,
        )?;
    }
    for approval_id in try_on_approval_ids {
        collect_photo_blob_refs(
            connection,
            "SELECT parent_blob_sha256 FROM try_on_assets WHERE approval_id = ?1",
            approval_id,
            "originals",
            &mut candidates,
            &mut closed,
        )?;
        collect_photo_blob_refs(
            connection,
            "SELECT output.blob_sha256
             FROM try_on_outputs output
             JOIN try_on_jobs job ON job.job_id = output.job_id
             WHERE job.approval_id = ?1",
            approval_id,
            "derivatives",
            &mut candidates,
            &mut closed,
        )?;
    }
    let mut receipt_attempt_ids = BTreeSet::new();
    for source_id in source_ids {
        extend_photo_set(
            connection,
            "SELECT attempt.attempt_id
             FROM receipt_image_attempts attempt
             JOIN receipt_image_candidates candidate
               ON candidate.candidate_id = attempt.candidate_id
             WHERE candidate.source_id = ?1",
            source_id,
            &mut receipt_attempt_ids,
        )?;
    }
    for attempt_id in receipt_attempt_ids {
        for (sql, class) in [
            (
                "SELECT source_blob_sha256 FROM receipt_remote_images
                 WHERE attempt_id = ?1
                 UNION ALL
                 SELECT source_blob_sha256 FROM receipt_image_materialization_intents
                 WHERE attempt_id = ?1",
                "originals",
            ),
            (
                "SELECT display_blob_sha256 FROM receipt_remote_images
                 WHERE attempt_id = ?1
                 UNION ALL
                 SELECT display_blob_sha256 FROM receipt_image_materialization_intents
                 WHERE attempt_id = ?1",
                "derivatives",
            ),
            (
                "SELECT blob_sha256 FROM provenance
                 WHERE source_locator = 'attempt:' || ?1 || ':source'
                   AND source_kind = 'receipt_remote_image_source'",
                "originals",
            ),
            (
                "SELECT blob_sha256 FROM provenance
                 WHERE source_locator = 'attempt:' || ?1 || ':display'
                   AND source_kind = 'receipt_remote_image_display'",
                "derivatives",
            ),
        ] {
            collect_photo_blob_refs(
                connection,
                sql,
                &attempt_id,
                class,
                &mut candidates,
                &mut closed,
            )?;
        }
    }

    for (hash, owned_class) in candidates {
        let already_removable = connection
            .query_row(
                "SELECT 1 FROM deletion_preview_items
                 WHERE snapshot_token = ?1 AND entity_id = ?2
                   AND dependency_class IN ('originals', 'derivatives')
                 LIMIT 1",
                params![snapshot_token, hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if already_removable {
            continue;
        }
        let owners = complete_blob_owner_count(connection, &hash)?;
        let closed_count = closed.get(&hash).copied().unwrap_or(0);
        connection.execute(
            "DELETE FROM deletion_preview_items
             WHERE snapshot_token = ?1 AND entity_id = ?2
               AND dependency_class IN (
                    'originals', 'derivatives', 'retained_shared_blobs'
               )",
            params![snapshot_token, hash],
        )?;
        let class = if owners > closed_count {
            "retained_shared_blobs"
        } else {
            owned_class
        };
        insert_photo_preview(connection, snapshot_token, class, &hash)?;
    }
    Ok(())
}

fn collect_photo_blob_refs(
    connection: &Connection,
    sql: &str,
    value: &str,
    class: &'static str,
    candidates: &mut BTreeMap<String, &'static str>,
    closed: &mut BTreeMap<String, i64>,
) -> PlatformResult<()> {
    let mut statement = connection.prepare(sql)?;
    for hash in statement
        .query_map([value], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?
    {
        candidates
            .entry(hash.clone())
            .and_modify(|current| {
                if class == "originals" {
                    *current = class;
                }
            })
            .or_insert(class);
        *closed.entry(hash).or_default() += 1;
    }
    Ok(())
}

#[derive(Debug)]
struct SourceRow {
    source_id: String,
    identity_key: String,
    status: String,
    raw_sha256: Option<String>,
    blob_sha256: Option<String>,
    byte_length: Option<i64>,
    provenance_id: String,
    provenance_request_id: String,
    provenance_raw_sha256: Option<String>,
    provenance_blob_sha256: Option<String>,
    provenance_observed_at_ms: i64,
}

#[derive(Debug)]
struct InspectedMember {
    source_revision: PhotoSourceRevisionV1,
    provenance_id: String,
    leaf_sha256: Sha256Digest,
}

#[derive(Serialize)]
struct ProvenanceHashRecord<'a> {
    provenance_id: &'a str,
    source_id: &'a str,
    request_id: &'a str,
    raw_sha256: &'a Option<String>,
    blob_sha256: &'a Option<String>,
    observed_at_ms: i64,
}

#[derive(Serialize)]
struct SourceRevisionHashRecord<'a> {
    schema_revision: &'static str,
    source_id: &'a str,
    root_id: &'a str,
    scan_id: &'a str,
    manifest_generation: u64,
    source_identity_key_sha256: &'a str,
    provenance_row_sha256: &'a str,
    raw_sha256: Option<&'a str>,
    blob_sha256: Option<&'a str>,
    byte_length: Option<u64>,
    media_type: Option<&'static str>,
    width: Option<u32>,
    height: Option<u32>,
    disposition: &'static str,
    quarantine_reason: Option<&'static str>,
}

#[derive(Serialize)]
struct MemberLeafHashRecord<'a> {
    schema_revision: &'static str,
    ordinal: u16,
    source_revision_id: &'a str,
    source_revision_sha256: &'a str,
    disposition: &'static str,
}

#[derive(Serialize)]
struct MembershipHashRecord<'a> {
    schema_revision: &'static str,
    root_id: &'a str,
    scan_id: &'a str,
    manifest_generation: u64,
    member_count: usize,
    leaf_sha256: Vec<&'a str>,
}

impl PhotoAnalysisPort for Database {
    fn list_imported_photo_roots(
        &self,
        request: &ListImportedPhotoRootsV1Request,
    ) -> PhotoAnalysisPortResult<ListImportedPhotoRootsV1Response> {
        self.list_imported_photo_roots_impl(request)
            .map_err(photo_port_error)
    }

    fn create_photo_scope(
        &self,
        request: &CreatePhotoScopeV1Request,
    ) -> PhotoAnalysisPortResult<CreatePhotoScopeV1Response> {
        self.create_photo_scope_impl(request)
            .map_err(photo_port_error)
    }

    fn analyze_photo_scope(
        &self,
        request: &AnalyzePhotoScopeV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PhotoAnalysisPortResult<AnalyzePhotoScopeV1Response> {
        self.analyze_photo_scope_impl(request, provider)
            .map_err(photo_port_error)
    }

    fn detect_photo_scope_people(
        &self,
        request: &DetectPhotoScopePeopleV1Request,
        provider: &dyn LocalPersonDetectionProviderV1,
    ) -> PhotoAnalysisPortResult<DetectPhotoScopePeopleV1Response> {
        self.detect_photo_scope_people_repository(request, provider)
            .map_err(photo_port_error)
    }

    fn list_photo_observations(
        &self,
        request: &ListPhotoObservationsV1Request,
    ) -> PhotoAnalysisPortResult<ListPhotoObservationsV1Response> {
        self.list_photo_observations_impl(request)
            .map_err(photo_port_error)
    }

    fn read_photo_artifact(
        &self,
        request: &ReadPhotoArtifactV1Request,
    ) -> PhotoAnalysisPortResult<ReadPhotoArtifactV1Response> {
        self.read_photo_artifact_impl(request)
            .map_err(photo_port_error)
    }

    fn prompt_photo_observation(
        &self,
        request: &PromptPhotoObservationV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PhotoAnalysisPortResult<PromptPhotoObservationV1Response> {
        self.prompt_photo_observation_impl(request, provider)
            .map_err(photo_port_error)
    }

    fn review_photo_observation(
        &self,
        request: &ReviewPhotoObservationV1Request,
    ) -> PhotoAnalysisPortResult<ReviewPhotoObservationV1Response> {
        self.review_photo_observation_impl(request)
            .map_err(photo_port_error)
    }

    fn list_photo_owner_reviews(
        &self,
        request: &ListPhotoOwnerReviewsV1Request,
    ) -> PhotoAnalysisPortResult<ListPhotoOwnerReviewsV1Response> {
        self.list_photo_owner_reviews_repository(request)
            .map_err(photo_port_error)
    }

    fn read_photo_owner_preview(
        &self,
        request: &ReadPhotoOwnerPreviewV1Request,
    ) -> PhotoAnalysisPortResult<ReadPhotoOwnerPreviewV1Response> {
        self.read_photo_owner_preview_repository(request)
            .map_err(photo_port_error)
    }

    fn decide_photo_owner(
        &self,
        request: &DecidePhotoOwnerV1Request,
    ) -> PhotoAnalysisPortResult<DecidePhotoOwnerV1Response> {
        self.decide_photo_owner_repository(request)
            .map_err(photo_port_error)
    }

    fn correct_photo_owner(
        &self,
        request: &CorrectPhotoOwnerV1Request,
    ) -> PhotoAnalysisPortResult<CorrectPhotoOwnerV1Response> {
        self.correct_photo_owner_repository(request)
            .map_err(photo_port_error)
    }

    fn correct_photo_person_detection(
        &self,
        request: &CorrectPhotoPersonDetectionV1Request,
    ) -> PhotoAnalysisPortResult<CorrectPhotoPersonDetectionV1Response> {
        self.correct_photo_person_detection_repository(request)
            .map_err(photo_port_error)
    }

    fn retry_photo_person_detection(
        &self,
        request: &RetryPhotoPersonDetectionV1Request,
    ) -> PhotoAnalysisPortResult<RetryPhotoPersonDetectionV1Response> {
        self.retry_photo_person_detection_repository(request)
            .map_err(photo_port_error)
    }
}

impl Database {
    fn list_imported_photo_roots_impl(
        &self,
        request: &ListImportedPhotoRootsV1Request,
    ) -> PlatformResult<ListImportedPhotoRootsV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("photo_roots_request"))?;
        let connection = self.connection()?;
        let evidence_generation = revision_values(&connection)?.1;
        let after = parse_roots_cursor(request.cursor.as_ref(), evidence_generation)?;
        let store = BlobStore::new(&self.paths);
        let mut statement = connection.prepare(
            "SELECT root.root_id, scan.scan_id, root.manifest_generation
             FROM import_roots root
             JOIN import_scans scan
               ON scan.root_id = root.root_id
              AND scan.generation = root.manifest_generation
             WHERE root.status = 'available'
               AND root.manifest_generation > 0
               AND scan.status = 'completed'
               AND scan.completed_at_ms IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM import_scans unfinished
                   WHERE unfinished.root_id = root.root_id
                     AND unfinished.status IN ('running', 'incomplete')
               )
             ORDER BY root.root_id",
        )?;
        let candidates = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut all = Vec::new();
        for (root_id, scan_id, generation) in candidates {
            let members = inspect_members(
                &connection,
                &store,
                &root_id,
                &scan_id,
                to_u64(generation, "manifest_generation")?,
                false,
            )?;
            if members.is_empty() || members.len() > MAX_PHOTO_SCOPE_MEMBERS {
                continue;
            }
            let eligible_count = members
                .iter()
                .filter(|member| {
                    member.source_revision.disposition == PhotoSourceDispositionV1::Eligible
                })
                .count();
            all.push(ImportedPhotoRootV1 {
                import_root_id: parse_import_root_id(&root_id)?,
                completed_scan_id: parse_scan_id(&scan_id)?,
                manifest_generation: generation as u64,
                member_count: members.len() as u16,
                eligible_count: eligible_count as u16,
                quarantined_count: (members.len() - eligible_count) as u16,
            });
        }
        let total_count = all.len() as u64;
        let remaining = all
            .into_iter()
            .filter(|root| {
                after
                    .as_deref()
                    .is_none_or(|after| root.import_root_id.to_string().as_str() > after)
            })
            .collect::<Vec<_>>();
        let has_more = remaining.len() > usize::from(request.limit);
        let page = remaining
            .into_iter()
            .take(usize::from(request.limit))
            .collect::<Vec<_>>();
        let next_cursor = if has_more {
            page.last()
                .map(|root| make_roots_cursor(evidence_generation, root.import_root_id))
                .transpose()?
        } else {
            None
        };
        let response = ListImportedPhotoRootsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            roots: page,
            total_count,
            evidence_generation,
            next_cursor,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("photo_roots_response"))?;
        Ok(response)
    }

    fn create_photo_scope_impl(
        &self,
        request: &CreatePhotoScopeV1Request,
    ) -> PlatformResult<CreatePhotoScopeV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("photo_scope_request"))?;
        let now_ms = unix_now_ms()?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, CreatePhotoScopeV1Response>(&transaction, CREATE_SCOPE_COMMAND, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }

        let root_id = request.import_root_id.to_string();
        let generation = i64::try_from(request.expected_manifest_generation)
            .map_err(|_| PlatformError::InvalidInput("manifest_generation"))?;
        if let Some((
            scope_id,
            scan_id,
            member_count,
            eligible_count,
            quarantined_count,
            membership_sha256,
        )) = transaction
            .query_row(
                "SELECT scope_id, scan_id, member_count, eligible_count,
                        quarantined_count, membership_sha256
                 FROM photo_scopes
                 WHERE root_id = ?1 AND manifest_generation = ?2",
                params![root_id, generation],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?
        {
            let response = CreatePhotoScopeV1Response {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request.request_id,
                scope: PhotoScopeV1 {
                    scope_id: parse_scope_id(&scope_id)?,
                    import_root_id: request.import_root_id,
                    completed_scan_id: parse_scan_id(&scan_id)?,
                    manifest_generation: request.expected_manifest_generation,
                    member_count: to_u16(member_count, "photo_member_count")?,
                    eligible_count: to_u16(eligible_count, "photo_eligible_count")?,
                    quarantined_count: to_u16(quarantined_count, "photo_quarantined_count")?,
                    membership_sha256: parse_digest(&membership_sha256)?,
                },
                replay_status: ReplayStatusV1::Created,
            };
            response
                .validate()
                .map_err(|_| PlatformError::Corrupt("photo_scope_response"))?;
            store_receipt(
                &transaction,
                CREATE_SCOPE_COMMAND,
                request,
                &response,
                now_ms,
            )?;
            link_command_entity(
                &transaction,
                &request.request_id.to_string(),
                "scope",
                &scope_id,
            )?;
            transaction.commit()?;
            return Ok(response);
        }
        let scan_id = transaction
            .query_row(
                "SELECT scan.scan_id
                 FROM import_roots root
                 JOIN import_scans scan
                   ON scan.root_id = root.root_id
                  AND scan.generation = root.manifest_generation
                 WHERE root.root_id = ?1
                   AND root.status = 'available'
                   AND root.manifest_generation = ?2
                   AND scan.status = 'completed'
                   AND scan.completed_at_ms IS NOT NULL
                   AND NOT EXISTS (
                       SELECT 1 FROM import_scans unfinished
                       WHERE unfinished.root_id = root.root_id
                         AND unfinished.status IN ('running', 'incomplete')
                   )",
                params![root_id, generation],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(PlatformError::Conflict("photo_generation_stale"))?;

        let store = BlobStore::new(&self.paths);
        let mut members = inspect_members(
            &transaction,
            &store,
            &root_id,
            &scan_id,
            request.expected_manifest_generation,
            true,
        )?;
        if members.is_empty() {
            return Err(PlatformError::InvalidInput("photo_scope_empty"));
        }
        if members.len() > MAX_PHOTO_SCOPE_MEMBERS {
            return Err(PlatformError::InvalidInput("photo_scope_member_limit"));
        }

        let scope_id = stable_id("photo-scope", &request.request_id.to_string());
        for (ordinal, member) in members.iter_mut().enumerate() {
            let revision_id = stable_id(
                "photo-source-revision",
                &format!("{scope_id}:{}", member.source_revision.source_id),
            );
            member.source_revision.source_revision_id = parse_source_revision_id(&revision_id)?;
            member.leaf_sha256 = member_leaf_hash(ordinal as u16, &member.source_revision)?;
        }
        let membership_sha256 = membership_hash(
            &root_id,
            &scan_id,
            request.expected_manifest_generation,
            &members,
        )?;
        let eligible_count = members
            .iter()
            .filter(|member| {
                member.source_revision.disposition == PhotoSourceDispositionV1::Eligible
            })
            .count();
        let scope = PhotoScopeV1 {
            scope_id: parse_scope_id(&scope_id)?,
            import_root_id: request.import_root_id,
            completed_scan_id: parse_scan_id(&scan_id)?,
            manifest_generation: request.expected_manifest_generation,
            member_count: members.len() as u16,
            eligible_count: eligible_count as u16,
            quarantined_count: (members.len() - eligible_count) as u16,
            membership_sha256,
        };
        scope
            .validate()
            .map_err(|_| PlatformError::Corrupt("photo_scope_contract"))?;
        let response = CreatePhotoScopeV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            scope: scope.clone(),
            replay_status: ReplayStatusV1::Created,
        };
        store_receipt(
            &transaction,
            CREATE_SCOPE_COMMAND,
            request,
            &response,
            now_ms,
        )?;
        transaction.execute(
            "INSERT INTO photo_scopes(
                scope_id, request_id, root_id, scan_id, manifest_generation,
                scope_schema_revision, member_count, eligible_count,
                quarantined_count, membership_sha256, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                scope_id,
                request.request_id.to_string(),
                root_id,
                scan_id,
                generation,
                SCOPE_SCHEMA_REVISION,
                members.len() as i64,
                eligible_count as i64,
                (members.len() - eligible_count) as i64,
                scope.membership_sha256.as_str(),
                now_ms
            ],
        )?;
        link_command_entity(
            &transaction,
            &request.request_id.to_string(),
            "scope",
            &scope_id,
        )?;
        for (ordinal, member) in members.iter().enumerate() {
            insert_source_revision(&transaction, member, &root_id, &scan_id, generation, now_ms)?;
            transaction.execute(
                "INSERT INTO photo_scope_members(
                    scope_id, member_ordinal, source_revision_id, root_id, scan_id,
                    manifest_generation, disposition, leaf_sha256
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    scope_id,
                    ordinal as i64,
                    member.source_revision.source_revision_id.to_string(),
                    root_id,
                    scan_id,
                    generation,
                    disposition_db(member.source_revision.disposition),
                    member.leaf_sha256.as_str()
                ],
            )?;
            link_command_entity(
                &transaction,
                &request.request_id.to_string(),
                "source_revision",
                &member.source_revision.source_revision_id.to_string(),
            )?;
        }
        transaction.commit()?;
        Ok(response)
    }

    fn analyze_photo_scope_impl(
        &self,
        request: &AnalyzePhotoScopeV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PlatformResult<AnalyzePhotoScopeV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("photo_analysis_request"))?;
        let conforming = ConformingGarmentSegmentationProviderV1::new(provider)
            .map_err(|_| PlatformError::Corrupt("segmentation_provider_descriptor"))?;
        let descriptor = conforming.describe();
        if descriptor.preprocessing_revision != PHOTO_PREPROCESSING_REVISION_V1 {
            return Err(PlatformError::InvalidInput(
                "segmentation_preprocessing_revision",
            ));
        }
        let run_id = self.prepare_analysis_run(request, &descriptor)?;
        let owner = format!("photo-analysis-{}", Uuid::new_v4());

        while let Some(work) = self.claim_analysis_member(&run_id, &owner)? {
            let image = self.load_verified_work_image(&work)?;
            let mode = SegmentationRequestModeV1::Automatic;
            let prompt_hash = wardrobe_core::prompt_parameters_sha256_v1(&mode)
                .map_err(|_| PlatformError::Corrupt("photo_prompt_hash"))?;
            let segmentation_request = SegmentationRequestV1 {
                contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
                request_handle: parse_request_handle(&work.request_handle)?,
                source_revision_sha256: parse_digest(&work.source_revision_sha256)?,
                input_blob_sha256: parse_digest(&work.blob_sha256)?,
                pixels: image.canonical_pixels()?,
                width: image.width,
                height: image.height,
                preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
                mode,
            };
            let terminal = terminal_outcome(
                conforming.segment(&segmentation_request),
                &descriptor,
                &segmentation_request,
            )?;
            self.finalize_analysis_member(
                request,
                &work,
                &descriptor,
                &prompt_hash,
                terminal,
                image.media_type,
                image.width,
                image.height,
                &owner,
            )?;
        }
        self.finish_analysis_run(request, &run_id)
    }

    fn prepare_analysis_run(
        &self,
        request: &AnalyzePhotoScopeV1Request,
        descriptor: &SegmentationProviderDescriptorV1,
    ) -> PlatformResult<String> {
        let now_ms = unix_now_ms()?;
        let envelope = envelope_hash(request)?;
        let request_id = request.request_id.to_string();
        let scope_id = request.scope_id.to_string();
        let run_id = stable_id(
            "photo-analysis-run",
            &format!(
                "{scope_id}:{}:{}:{}:{}",
                descriptor.provider_id,
                descriptor.provider_revision,
                descriptor.model_revision.as_deref().unwrap_or(""),
                descriptor.preprocessing_revision
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
            if command != ANALYZE_SCOPE_COMMAND || stored_envelope != envelope {
                return Err(PlatformError::Conflict("command_envelope_changed"));
            }
            if response_json != "{}" {
                let _: AnalyzePhotoScopeV1Response = serde_json::from_str(&response_json)?;
                transaction.commit()?;
                return Ok(run_id);
            }
        } else {
            transaction.execute(
                "INSERT INTO command_receipts(
                    request_id, command_name, envelope_hash, response_json, created_at_ms
                 ) VALUES (?1, ?2, ?3, '{}', ?4)",
                params![request_id, ANALYZE_SCOPE_COMMAND, envelope, now_ms],
            )?;
        }

        let scope_counts = transaction
            .query_row(
                "SELECT member_count, eligible_count FROM photo_scopes WHERE scope_id = ?1",
                [&scope_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("photo_scope_id"))?;
        let existing = transaction
            .query_row(
                "SELECT request_id, request_envelope_sha256
                 FROM photo_analysis_runs WHERE run_id = ?1",
                [&run_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if let Some((stored_request, stored_envelope)) = existing {
            if stored_request.is_empty() || stored_envelope.is_empty() {
                return Err(PlatformError::Corrupt("photo_analysis_run_identity"));
            }
            link_command_entity(&transaction, &request_id, "run", &run_id)?;
            transaction.commit()?;
            return Ok(run_id);
        }
        transaction.execute(
            "INSERT INTO photo_analysis_runs(
                run_id, request_id, request_envelope_sha256, scope_id,
                provider_contract_revision, provider_id, provider_revision,
                model_revision, preprocessing_revision, quality_gate_revision,
                state, eligible_member_count, terminal_member_count,
                created_at_ms, updated_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                'pending', ?11, 0, ?12, ?12
             )",
            params![
                run_id,
                request_id,
                envelope,
                scope_id,
                descriptor.contract_revision,
                descriptor.provider_id,
                descriptor.provider_revision,
                descriptor.model_revision,
                descriptor.preprocessing_revision,
                PHOTO_QUALITY_GATE_REVISION_V1,
                scope_counts.1,
                now_ms
            ],
        )?;
        link_command_entity(&transaction, &request_id, "run", &run_id)?;
        let mut statement = transaction.prepare(
            "SELECT member_ordinal, source_revision_id, disposition
             FROM photo_scope_members WHERE scope_id = ?1 ORDER BY member_ordinal",
        )?;
        let members = statement
            .query_map([&scope_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        if members.len() as i64 != scope_counts.0 {
            return Err(PlatformError::Corrupt("photo_scope_member_count"));
        }
        for (ordinal, source_revision_id, disposition) in members {
            let quarantined = disposition == "quarantined";
            transaction.execute(
                "INSERT INTO photo_analysis_member_claims(
                    run_id, scope_id, member_ordinal, source_revision_id,
                    disposition, state, attempt_count, fence, lease_owner,
                    lease_expires_at_ms, created_at_ms, updated_at_ms
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, NULL, NULL, ?8, ?8
                 )",
                params![
                    run_id,
                    scope_id,
                    ordinal,
                    source_revision_id,
                    disposition,
                    if quarantined { "terminal" } else { "pending" },
                    if quarantined { 1 } else { 0 },
                    now_ms
                ],
            )?;
            if quarantined {
                insert_quarantined_outcome(
                    &transaction,
                    &request_id,
                    &run_id,
                    &scope_id,
                    ordinal,
                    &source_revision_id,
                    descriptor,
                    now_ms,
                )?;
            }
        }
        transaction.commit()?;
        Ok(run_id)
    }

    fn claim_analysis_member(
        &self,
        run_id: &str,
        owner: &str,
    ) -> PlatformResult<Option<AnalysisWork>> {
        let now_ms = unix_now_ms()?;
        let lease_expires = now_ms
            .checked_add(CLAIM_LEASE_MS)
            .ok_or(PlatformError::Corrupt("photo_claim_lease"))?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = transaction
            .query_row(
                "SELECT claim.scope_id, claim.member_ordinal, claim.source_revision_id,
                        revision.source_revision_sha256, revision.blob_sha256,
                        revision.byte_length, revision.media_type, revision.width,
                        revision.height, claim.fence
                 FROM photo_analysis_member_claims claim
                 JOIN photo_source_revisions revision
                   ON revision.source_revision_id = claim.source_revision_id
                 WHERE claim.run_id = ?1
                   AND claim.disposition = 'eligible'
                   AND (
                       claim.state = 'pending'
                       OR (claim.state = 'running' AND claim.lease_expires_at_ms <= ?2)
                   )
                 ORDER BY claim.member_ordinal
                 LIMIT 1",
                params![run_id, now_ms],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, i64>(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            scope_id,
            ordinal,
            source_revision_id,
            source_revision_sha256,
            blob_sha256,
            byte_length,
            media_type,
            width,
            height,
            prior_fence,
        )) = candidate
        else {
            transaction.commit()?;
            return Ok(None);
        };
        let fence = prior_fence + 1;
        let changed = transaction.execute(
            "UPDATE photo_analysis_member_claims
             SET state = 'running', attempt_count = attempt_count + 1,
                 fence = ?4, lease_owner = ?5, lease_expires_at_ms = ?6,
                 updated_at_ms = ?7
             WHERE run_id = ?1 AND member_ordinal = ?2
               AND source_revision_id = ?3
               AND fence = ?8
               AND (state = 'pending'
                    OR (state = 'running' AND lease_expires_at_ms <= ?7))",
            params![
                run_id,
                ordinal,
                source_revision_id,
                fence,
                owner,
                lease_expires,
                now_ms,
                prior_fence
            ],
        )?;
        if changed != 1 {
            return Err(PlatformError::LeaseLost);
        }
        transaction.execute(
            "UPDATE photo_analysis_runs
             SET state = 'running', updated_at_ms = ?2
             WHERE run_id = ?1 AND state <> 'completed'",
            params![run_id, now_ms],
        )?;
        transaction.commit()?;
        let attempt_id = stable_id(
            "photo-segmentation-attempt",
            &format!("{run_id}:{ordinal}:automatic"),
        );
        Ok(Some(AnalysisWork {
            run_id: run_id.to_owned(),
            scope_id,
            member_ordinal: ordinal,
            source_revision_id,
            source_revision_sha256,
            blob_sha256,
            byte_length: to_u64(byte_length, "photo_blob_length")?,
            media_type: media_type_from_db(&media_type)?,
            width: to_u32(width, "photo_width")?,
            height: to_u32(height, "photo_height")?,
            fence,
            attempt_id: attempt_id.clone(),
            request_handle: stable_id("photo-segmentation-request", &attempt_id),
        }))
    }

    fn load_verified_work_image(&self, work: &AnalysisWork) -> PlatformResult<VerifiedSourceImage> {
        let image = verify_source_image(
            &BlobStore::new(&self.paths),
            &work.blob_sha256,
            work.byte_length,
        )
        .map_err(|_| PlatformError::Corrupt("photo_source_reverification"))?;
        if image.media_type != work.media_type
            || image.width != work.width
            || image.height != work.height
        {
            return Err(PlatformError::Corrupt("photo_source_revision_changed"));
        }
        Ok(image)
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_analysis_member(
        &self,
        request: &AnalyzePhotoScopeV1Request,
        work: &AnalysisWork,
        descriptor: &SegmentationProviderDescriptorV1,
        prompt_hash: &Sha256Digest,
        terminal: TerminalOutcome,
        media_type: PhotoMediaTypeV1,
        width: u32,
        height: u32,
        owner: &str,
    ) -> PlatformResult<()> {
        let now_ms = unix_now_ms()?;
        let artifact_id = stable_id("photo-artifact", &work.attempt_id);
        let observation_id = stable_id(
            "photo-observation",
            &format!("{}:{}", work.scope_id, work.member_ordinal),
        );
        let rectangle = RectV1 {
            x: 0,
            y: 0,
            width,
            height,
        };
        let provenance = make_artifact_provenance(
            &artifact_id,
            &work.scope_id,
            work.member_ordinal,
            &work.source_revision_id,
            &work.source_revision_sha256,
            &work.blob_sha256,
            media_type,
            width,
            height,
            Some(rectangle),
            descriptor,
            SegmentationRequestModeKindV1::Automatic,
            prompt_hash,
            &terminal,
            &[],
        )?;
        let artifact_hash = artifact_hash(
            &provenance.sha256,
            PhotoArtifactKindV1::RectangleSourceCrop,
            Some(rectangle),
        )?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let valid_claim = transaction
            .query_row(
                "SELECT 1 FROM photo_analysis_member_claims
                 WHERE run_id = ?1 AND member_ordinal = ?2
                   AND source_revision_id = ?3 AND state = 'running'
                   AND fence = ?4 AND lease_owner = ?5",
                params![
                    work.run_id,
                    work.member_ordinal,
                    work.source_revision_id,
                    work.fence,
                    owner
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !valid_claim {
            return Err(PlatformError::LeaseLost);
        }
        if transaction
            .query_row(
                "SELECT 1 FROM photo_segmentation_outcomes WHERE attempt_id = ?1",
                [&work.attempt_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(PlatformError::LeaseLost);
        }
        insert_segmentation_attempt(
            &transaction,
            work,
            descriptor,
            "automatic",
            prompt_hash,
            &envelope_hash(&AutomaticAttemptEnvelope {
                source_revision_sha256: &work.source_revision_sha256,
                input_blob_sha256: &work.blob_sha256,
                prompt_parameters_sha256: prompt_hash.as_str(),
                provider_id: &descriptor.provider_id,
                provider_revision: &descriptor.provider_revision,
            })?,
            now_ms,
        )?;
        insert_terminal_outcome(&transaction, &work.attempt_id, &terminal, now_ms)?;
        insert_artifact(
            &transaction,
            &artifact_id,
            &work.attempt_id,
            &work.scope_id,
            work.member_ordinal,
            &work.source_revision_id,
            &work.source_revision_sha256,
            &work.blob_sha256,
            PhotoArtifactKindV1::RectangleSourceCrop,
            media_type,
            width,
            height,
            Some(rectangle),
            descriptor,
            SegmentationRequestModeKindV1::Automatic,
            prompt_hash,
            &terminal,
            &provenance,
            &artifact_hash,
            now_ms,
        )?;
        transaction.execute(
            "INSERT INTO photo_observations(
                observation_id, scope_id, member_ordinal, source_revision_id,
                initial_attempt_id, initial_artifact_id, initial_state, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'needs_review', ?7)",
            params![
                observation_id,
                work.scope_id,
                work.member_ordinal,
                work.source_revision_id,
                work.attempt_id,
                artifact_id,
                now_ms
            ],
        )?;
        transaction.execute(
            "UPDATE photo_analysis_member_claims
             SET state = 'terminal', lease_owner = NULL, lease_expires_at_ms = NULL,
                 updated_at_ms = ?5
             WHERE run_id = ?1 AND member_ordinal = ?2
               AND source_revision_id = ?3 AND fence = ?4",
            params![
                work.run_id,
                work.member_ordinal,
                work.source_revision_id,
                work.fence,
                now_ms
            ],
        )?;
        transaction.execute(
            "UPDATE photo_analysis_runs
             SET terminal_member_count = terminal_member_count + 1,
                 updated_at_ms = ?2
             WHERE run_id = ?1",
            params![work.run_id, now_ms],
        )?;
        transaction.execute(
            "UPDATE revision_state
             SET evidence_generation = evidence_generation + 1 WHERE singleton = 1",
            [],
        )?;
        let request_id = request.request_id.to_string();
        for (kind, id) in [
            ("segmentation_attempt", work.attempt_id.as_str()),
            ("artifact", artifact_id.as_str()),
            ("observation", observation_id.as_str()),
        ] {
            link_command_entity(&transaction, &request_id, kind, id)?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn finish_analysis_run(
        &self,
        request: &AnalyzePhotoScopeV1Request,
        run_id: &str,
    ) -> PlatformResult<AnalyzePhotoScopeV1Response> {
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
            if command != ANALYZE_SCOPE_COMMAND || envelope != envelope_hash(request)? {
                return Err(PlatformError::Conflict("command_envelope_changed"));
            }
            if response_json != "{}" {
                let mut response: AnalyzePhotoScopeV1Response =
                    serde_json::from_str(&response_json)?;
                response.replay_status = ReplayStatusV1::Replayed;
                transaction.commit()?;
                return Ok(response);
            }
        }
        let (member_count, eligible_count, terminal_eligible): (i64, i64, i64) = transaction
            .query_row(
                "SELECT scope.member_count, run.eligible_member_count,
                        run.terminal_member_count
                 FROM photo_analysis_runs run
                 JOIN photo_scopes scope ON scope.scope_id = run.scope_id
                 WHERE run.run_id = ?1",
                [run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
        let terminal_total: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM photo_analysis_member_claims
             WHERE run_id = ?1 AND state = 'terminal'",
            [run_id],
            |row| row.get(0),
        )?;
        let skipped: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM photo_analysis_member_claims
             WHERE run_id = ?1 AND state = 'terminal' AND disposition = 'quarantined'",
            [run_id],
            |row| row.get(0),
        )?;
        let needs_review: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM photo_observations observation
             JOIN photo_analysis_member_claims claim
               ON claim.scope_id = observation.scope_id
              AND claim.member_ordinal = observation.member_ordinal
             WHERE claim.run_id = ?1",
            [run_id],
            |row| row.get(0),
        )?;
        let failed = terminal_total - skipped - needs_review;
        let completed = terminal_total == member_count && terminal_eligible == eligible_count;
        if completed {
            transaction.execute(
                "UPDATE photo_analysis_runs
                 SET state = 'completed', completed_at_ms = ?2, updated_at_ms = ?2
                 WHERE run_id = ?1 AND state <> 'completed'",
                params![run_id, now_ms],
            )?;
        }
        let (photo_revision, evidence_generation) = revision_values(&transaction)?;
        let response = AnalyzePhotoScopeV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            scope_id: request.scope_id,
            run_id: parse_run_id(run_id)?,
            state: if completed {
                PhotoAnalysisRunStateV1::Completed
            } else {
                PhotoAnalysisRunStateV1::Running
            },
            member_count: to_u16(member_count, "photo_member_count")?,
            completed_count: to_u16(terminal_total, "photo_terminal_count")?,
            needs_review_count: to_u16(needs_review, "photo_needs_review_count")?,
            skipped_count: to_u16(skipped, "photo_skipped_count")?,
            failed_count: to_u16(failed, "photo_failed_count")?,
            photo_revision,
            evidence_generation,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("photo_analysis_response"))?;
        if completed {
            transaction.execute(
                "UPDATE command_receipts SET response_json = ?2 WHERE request_id = ?1",
                params![
                    request.request_id.to_string(),
                    serde_json::to_string(&response)?
                ],
            )?;
        }
        transaction.commit()?;
        Ok(response)
    }
}

fn load_observation(
    connection: &Connection,
    observation_id: &str,
    artifact_override: Option<&str>,
) -> PlatformResult<PhotoObservationV1> {
    let (scope_id, source_revision_id, initial_artifact_id): (String, String, String) = connection
        .query_row(
            "SELECT scope_id, source_revision_id, initial_artifact_id
             FROM photo_observations WHERE observation_id = ?1",
            [observation_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("photo_observation_id"))?;
    let head = connection
        .query_row(
            "SELECT head.current_artifact_id, head.state, decision.decision_id,
                    decision.action, decision.selected_artifact_id,
                    decision.photo_revision
             FROM photo_review_heads head
             JOIN photo_review_decisions decision
               ON decision.decision_id = head.decision_id
             WHERE head.observation_id = ?1",
            [observation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    if artifact_override.is_some() && head.is_some() {
        return Err(PlatformError::Conflict("photo_review_head_exists"));
    }
    let artifact_id = if let Some(artifact_id) = artifact_override {
        artifact_id.to_owned()
    } else if let Some((current_artifact_id, ..)) = &head {
        current_artifact_id.clone()
    } else {
        connection
            .query_row(
                "SELECT artifact_id FROM photo_artifacts
                 WHERE scope_id = ?1 AND source_revision_id = ?2
                 ORDER BY created_at_ms DESC, artifact_id DESC LIMIT 1",
                params![scope_id, source_revision_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or(initial_artifact_id)
    };
    let artifact = load_artifact(connection, &artifact_id)?;
    let (state, review_head) =
        if let Some((_, state, decision_id, action, selected_artifact_id, photo_revision)) = head {
            let state = observation_state_from_db(&state)?;
            let decision = PhotoReviewDecisionV1 {
                decision_id: parse_decision_id(&decision_id)?,
                observation_id: parse_observation_id(observation_id)?,
                action: review_action_from_db(&action)?,
                selected_artifact_id: selected_artifact_id
                    .as_deref()
                    .map(parse_artifact_id)
                    .transpose()?,
                photo_revision: to_u64(photo_revision, "photo_revision")?,
            };
            (state, Some(PhotoReviewHeadV1 { state, decision }))
        } else {
            (PhotoObservationStateV1::NeedsReview, None)
        };
    let observation = PhotoObservationV1 {
        observation_id: parse_observation_id(observation_id)?,
        scope_id: parse_scope_id(&scope_id)?,
        source_revision_id: parse_source_revision_id(&source_revision_id)?,
        state,
        artifact,
        review_head,
    };
    observation
        .validate()
        .map_err(|_| PlatformError::Corrupt("photo_observation_contract"))?;
    Ok(observation)
}

fn load_artifact(connection: &Connection, artifact_id: &str) -> PlatformResult<PhotoArtifactV1> {
    #[allow(clippy::type_complexity)]
    let row: (
        String,
        String,
        String,
        String,
        String,
        String,
        i64,
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        i64,
        String,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
    ) = connection
        .query_row(
            "SELECT artifact_kind, scope_id, source_revision_id,
                    source_revision_sha256, input_blob_sha256, media_type,
                    source_width, source_height, rectangle_x, rectangle_y,
                    rectangle_width, rectangle_height, artifact_schema_revision,
                    artifact_revision, preprocessing_revision,
                    provider_contract_revision, provider_id, model_revision,
                    provider_revision, request_mode, prompt_parameters_sha256,
                    quality_approved, segmentation_outcome, unavailable_reason,
                    failure_code, provenance_json, provenance_sha256,
                    artifact_sha256
             FROM photo_artifacts WHERE artifact_id = ?1",
            [artifact_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                    row.get(21)?,
                    row.get(22)?,
                    row.get(23)?,
                    row.get(24)?,
                    row.get(25)?,
                    row.get(26)?,
                    row.get(27)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("photo_artifact_id"))?;
    if Sha256Digest::from_bytes(row.25.as_bytes()).as_str() != row.26 {
        return Err(PlatformError::Corrupt("photo_artifact_provenance_hash"));
    }
    let provenance_value: serde_json::Value = serde_json::from_str(&row.25)?;
    reject_sensitive_provenance_keys(&provenance_value)?;
    let kind = artifact_kind_from_db(&row.0)?;
    let rectangle = match (row.8, row.9, row.10, row.11) {
        (Some(x), Some(y), Some(width), Some(height)) => Some(RectV1 {
            x: to_u32(x, "artifact_rectangle")?,
            y: to_u32(y, "artifact_rectangle")?,
            width: to_u32(width, "artifact_rectangle")?,
            height: to_u32(height, "artifact_rectangle")?,
        }),
        (None, None, None, None) => None,
        _ => return Err(PlatformError::Corrupt("photo_artifact_rectangle")),
    };
    let expected_artifact_hash = artifact_hash(&parse_digest(&row.26)?, kind, rectangle)?;
    if expected_artifact_hash.as_str() != row.27 {
        return Err(PlatformError::Corrupt("photo_artifact_hash"));
    }
    let mut parent_statement = connection.prepare(
        "SELECT parent_artifact_id FROM photo_artifact_parents
         WHERE artifact_id = ?1 ORDER BY parent_ordinal",
    )?;
    let parent_artifact_ids = parent_statement
        .query_map([artifact_id], |row| row.get::<_, String>(0))?
        .map(|value| {
            value
                .map_err(PlatformError::from)
                .and_then(|id| parse_artifact_id(&id))
        })
        .collect::<PlatformResult<Vec<_>>>()?;
    let artifact = PhotoArtifactV1 {
        artifact_id: parse_artifact_id(artifact_id)?,
        kind,
        artifact_schema_revision: row.12,
        artifact_revision: row.13,
        scope_id: parse_scope_id(&row.1)?,
        source_revision_id: parse_source_revision_id(&row.2)?,
        source_revision_sha256: parse_digest(&row.3)?,
        input_blob_sha256: parse_digest(&row.4)?,
        media_type: media_type_from_db(&row.5)?,
        source_width: to_u32(row.6, "photo_width")?,
        source_height: to_u32(row.7, "photo_height")?,
        rectangle,
        preprocessing_revision: row.14,
        provider_contract_revision: row.15,
        provider_id: row.16,
        provider_revision: row.18,
        model_revision: row.17,
        request_mode: request_mode_from_db(&row.19)?,
        prompt_parameters_sha256: parse_digest(&row.20)?,
        quality_gate_revision: PHOTO_QUALITY_GATE_REVISION_V1.to_owned(),
        quality_approved: row.21 != 0,
        segmentation_outcome: outcome_from_db(&row.22)?,
        unavailable_reason: row
            .23
            .as_deref()
            .map(unavailable_reason_from_db)
            .transpose()?,
        failure_code: row.24.as_deref().map(failure_code_from_db).transpose()?,
        parent_artifact_ids,
        provenance_sha256: parse_digest(&row.26)?,
        artifact_sha256: parse_digest(&row.27)?,
    };
    artifact
        .validate()
        .map_err(|_| PlatformError::Corrupt("photo_artifact_contract"))?;
    Ok(artifact)
}

fn reject_sensitive_provenance_keys(value: &serde_json::Value) -> PlatformResult<()> {
    const DENIED: &[&str] = &[
        "path",
        "filename",
        "pixels",
        "pixel_bytes",
        "free_text",
        "prompt_text",
        "locator",
    ];
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if DENIED.contains(&key.as_str()) {
                    return Err(PlatformError::Corrupt("photo_provenance_sensitive_field"));
                }
                reject_sensitive_provenance_keys(value)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                reject_sensitive_provenance_keys(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn insert_parent_edge(
    transaction: &Transaction<'_>,
    artifact_id: &str,
    ordinal: i64,
    parent_artifact_id: &str,
    scope_id: &str,
    source_revision_id: &str,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO photo_artifact_parents(
            artifact_id, parent_ordinal, parent_artifact_id, scope_id,
            source_revision_id, relationship
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'derived_from')",
        params![
            artifact_id,
            ordinal,
            parent_artifact_id,
            scope_id,
            source_revision_id
        ],
    )?;
    Ok(())
}

fn member_ordinal_for_artifact(connection: &Connection, artifact_id: &str) -> PlatformResult<i64> {
    Ok(connection.query_row(
        "SELECT member_ordinal FROM photo_artifacts WHERE artifact_id = ?1",
        [artifact_id],
        |row| row.get(0),
    )?)
}

fn descriptor_from_artifact(artifact: &PhotoArtifactV1) -> SegmentationProviderDescriptorV1 {
    SegmentationProviderDescriptorV1 {
        contract_revision: artifact.provider_contract_revision.clone(),
        provider_id: artifact.provider_id.clone(),
        provider_revision: artifact.provider_revision.clone(),
        model_revision: artifact.model_revision.clone(),
        preprocessing_revision: artifact.preprocessing_revision.clone(),
        automatic_capability: wardrobe_core::SegmentationCapabilityV1::Unavailable,
        interactive_capability: wardrobe_core::SegmentationCapabilityV1::Unavailable,
        maximum_masks: wardrobe_core::MAX_SEGMENTATION_MASKS as u8,
    }
}

fn terminal_from_artifact(artifact: &PhotoArtifactV1) -> TerminalOutcome {
    TerminalOutcome {
        code: artifact.segmentation_outcome,
        unavailable_reason: artifact.unavailable_reason,
        failure_code: artifact.failure_code,
        rejection_code: if artifact.segmentation_outcome == PhotoSegmentationOutcomeCodeV1::Rejected
        {
            Some("review_replacement")
        } else {
            None
        },
        mask_count: if matches!(
            artifact.segmentation_outcome,
            PhotoSegmentationOutcomeCodeV1::AutomaticMasks
                | PhotoSegmentationOutcomeCodeV1::InteractiveMasks
        ) {
            1
        } else {
            0
        },
        quality_gate_result: if artifact.segmentation_outcome
            == PhotoSegmentationOutcomeCodeV1::AutomaticMasks
        {
            "rejected"
        } else if artifact.segmentation_outcome == PhotoSegmentationOutcomeCodeV1::Rejected {
            "disabled"
        } else {
            "not_applicable"
        },
        response_sha256: None,
    }
}

fn replacement_prompt_hash(rectangle: RectV1) -> PlatformResult<Sha256Digest> {
    canonical_hash(
        b"wardrobe.photo.review-replacement.v1",
        &serde_json::json!({
            "x": rectangle.x,
            "y": rectangle.y,
            "width": rectangle.width,
            "height": rectangle.height
        }),
    )
}

#[derive(Debug)]
struct AnalysisWork {
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
    fence: i64,
    attempt_id: String,
    request_handle: String,
}

#[derive(Serialize)]
struct AutomaticAttemptEnvelope<'a> {
    source_revision_sha256: &'a str,
    input_blob_sha256: &'a str,
    prompt_parameters_sha256: &'a str,
    provider_id: &'a str,
    provider_revision: &'a str,
}

#[derive(Clone, Debug)]
struct TerminalOutcome {
    code: PhotoSegmentationOutcomeCodeV1,
    unavailable_reason: Option<SegmentationUnavailableReasonV1>,
    failure_code: Option<SegmentationFailureCodeV1>,
    rejection_code: Option<&'static str>,
    mask_count: usize,
    quality_gate_result: &'static str,
    response_sha256: Option<Sha256Digest>,
}

#[derive(Serialize)]
struct ArtifactProvenanceRecord<'a> {
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
    quality_gate_result: &'a str,
    segmentation_outcome: &'static str,
    unavailable_reason: Option<&'static str>,
    failure_code: Option<&'static str>,
    parent_artifact_ids: &'a [String],
}

struct CanonicalProvenance {
    json: String,
    sha256: Sha256Digest,
}

#[allow(clippy::too_many_arguments)]
fn make_artifact_provenance(
    artifact_id: &str,
    scope_id: &str,
    member_ordinal: i64,
    source_revision_id: &str,
    source_revision_sha256: &str,
    blob_sha256: &str,
    media_type: PhotoMediaTypeV1,
    width: u32,
    height: u32,
    rectangle: Option<RectV1>,
    descriptor: &SegmentationProviderDescriptorV1,
    request_mode: SegmentationRequestModeKindV1,
    prompt_hash: &Sha256Digest,
    terminal: &TerminalOutcome,
    parent_artifact_ids: &[String],
) -> PlatformResult<CanonicalProvenance> {
    let record = ArtifactProvenanceRecord {
        artifact_schema_revision: PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
        artifact_revision: if rectangle.is_some() {
            RECTANGLE_SOURCE_CROP_REVISION_V1
        } else {
            SOURCE_IMAGE_REFERENCE_REVISION_V1
        },
        artifact_id,
        parent_scope_id: scope_id,
        member_ordinal,
        parent_source_revision_id: source_revision_id,
        parent_source_revision_sha256: source_revision_sha256,
        input_blob_sha256: blob_sha256,
        input_media_type: media_type_db(media_type),
        source_width: width,
        source_height: height,
        rectangle,
        preprocessing_revision: &descriptor.preprocessing_revision,
        provider_contract_revision: &descriptor.contract_revision,
        provider_id: &descriptor.provider_id,
        provider_revision: &descriptor.provider_revision,
        model_revision: &descriptor.model_revision,
        request_mode: request_mode_db(request_mode),
        prompt_parameters_sha256: prompt_hash.as_str(),
        quality_gate_revision: PHOTO_QUALITY_GATE_REVISION_V1,
        quality_gate_result: terminal.quality_gate_result,
        segmentation_outcome: outcome_db(terminal.code),
        unavailable_reason: terminal.unavailable_reason.map(unavailable_reason_db),
        failure_code: terminal.failure_code.map(failure_code_db),
        parent_artifact_ids,
    };
    let json = serde_json::to_string(&record)?;
    let sha256 = Sha256Digest::from_bytes(json.as_bytes());
    Ok(CanonicalProvenance { json, sha256 })
}

pub(crate) fn artifact_hash(
    provenance_sha256: &Sha256Digest,
    kind: PhotoArtifactKindV1,
    rectangle: Option<RectV1>,
) -> PlatformResult<Sha256Digest> {
    #[derive(Serialize)]
    struct Record<'a> {
        artifact_schema_revision: &'static str,
        artifact_kind: &'static str,
        provenance_sha256: &'a str,
        rectangle: Option<RectV1>,
    }
    canonical_hash(
        b"wardrobe.photo.artifact.v1",
        &Record {
            artifact_schema_revision: PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
            artifact_kind: artifact_kind_db(kind),
            provenance_sha256: provenance_sha256.as_str(),
            rectangle,
        },
    )
}

fn terminal_outcome(
    result: Result<SegmentationOutcomeV1, wardrobe_core::SegmentationProviderError>,
    _descriptor: &SegmentationProviderDescriptorV1,
    _request: &SegmentationRequestV1,
) -> PlatformResult<TerminalOutcome> {
    match result {
        Ok(outcome) => {
            let response_sha256 = Some(Sha256Digest::from_bytes(&serde_json::to_vec(&outcome)?));
            let terminal = match outcome.result {
                SegmentationResultV1::AutomaticMasks { masks } => TerminalOutcome {
                    code: PhotoSegmentationOutcomeCodeV1::AutomaticMasks,
                    unavailable_reason: None,
                    failure_code: None,
                    rejection_code: None,
                    mask_count: masks.len(),
                    quality_gate_result: "rejected",
                    response_sha256,
                },
                SegmentationResultV1::InteractiveMasks { masks } => TerminalOutcome {
                    code: PhotoSegmentationOutcomeCodeV1::InteractiveMasks,
                    unavailable_reason: None,
                    failure_code: None,
                    rejection_code: None,
                    mask_count: masks.len(),
                    quality_gate_result: "not_applicable",
                    response_sha256,
                },
                SegmentationResultV1::NoGarment => TerminalOutcome {
                    code: PhotoSegmentationOutcomeCodeV1::NoGarment,
                    unavailable_reason: None,
                    failure_code: None,
                    rejection_code: None,
                    mask_count: 0,
                    quality_gate_result: "not_applicable",
                    response_sha256,
                },
                SegmentationResultV1::Unavailable { reason } => TerminalOutcome {
                    code: PhotoSegmentationOutcomeCodeV1::Unavailable,
                    unavailable_reason: Some(reason),
                    failure_code: None,
                    rejection_code: None,
                    mask_count: 0,
                    quality_gate_result: "not_applicable",
                    response_sha256,
                },
                SegmentationResultV1::Failed { code } => TerminalOutcome {
                    code: PhotoSegmentationOutcomeCodeV1::Failed,
                    unavailable_reason: None,
                    failure_code: Some(code),
                    rejection_code: None,
                    mask_count: 0,
                    quality_gate_result: "not_applicable",
                    response_sha256,
                },
            };
            Ok(terminal)
        }
        Err(error) => Ok(match error.kind {
            SegmentationProviderErrorKind::InvalidRequest => TerminalOutcome {
                code: PhotoSegmentationOutcomeCodeV1::Failed,
                unavailable_reason: None,
                failure_code: Some(SegmentationFailureCodeV1::InvalidInput),
                rejection_code: None,
                mask_count: 0,
                quality_gate_result: "not_applicable",
                response_sha256: None,
            },
            SegmentationProviderErrorKind::MalformedOutput => TerminalOutcome {
                code: PhotoSegmentationOutcomeCodeV1::Rejected,
                unavailable_reason: None,
                failure_code: None,
                rejection_code: Some("provider_output_invalid"),
                mask_count: 0,
                quality_gate_result: "disabled",
                response_sha256: None,
            },
            SegmentationProviderErrorKind::Internal => TerminalOutcome {
                code: PhotoSegmentationOutcomeCodeV1::Failed,
                unavailable_reason: None,
                failure_code: Some(SegmentationFailureCodeV1::InferenceFailed),
                rejection_code: None,
                mask_count: 0,
                quality_gate_result: "not_applicable",
                response_sha256: None,
            },
        }),
    }
}

fn insert_segmentation_attempt(
    transaction: &Transaction<'_>,
    work: &AnalysisWork,
    descriptor: &SegmentationProviderDescriptorV1,
    request_mode: &str,
    prompt_hash: &Sha256Digest,
    request_envelope_sha256: &str,
    now_ms: i64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO photo_segmentation_attempts(
            attempt_id, request_handle, run_id, scope_id, member_ordinal,
            source_revision_id, source_revision_sha256, disposition, claim_fence,
            request_mode, input_blob_sha256, provider_contract_revision,
            provider_id, provider_revision, model_revision, preprocessing_revision,
            prompt_parameters_sha256, request_envelope_sha256, provider_invoked,
            created_at_ms
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'eligible', ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, 1, ?18
         )",
        params![
            work.attempt_id,
            work.request_handle,
            work.run_id,
            work.scope_id,
            work.member_ordinal,
            work.source_revision_id,
            work.source_revision_sha256,
            work.fence,
            request_mode,
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
    Ok(())
}

fn insert_terminal_outcome(
    transaction: &Transaction<'_>,
    attempt_id: &str,
    terminal: &TerminalOutcome,
    now_ms: i64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO photo_segmentation_outcomes(
            attempt_id, outcome, unavailable_reason, failure_code, rejection_code,
            mask_count, quality_gate_result, response_sha256, completed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            attempt_id,
            outcome_db(terminal.code),
            terminal.unavailable_reason.map(unavailable_reason_db),
            terminal.failure_code.map(failure_code_db),
            terminal.rejection_code,
            terminal.mask_count as i64,
            terminal.quality_gate_result,
            terminal.response_sha256.as_ref().map(Sha256Digest::as_str),
            now_ms
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_artifact(
    transaction: &Transaction<'_>,
    artifact_id: &str,
    attempt_id: &str,
    scope_id: &str,
    member_ordinal: i64,
    source_revision_id: &str,
    source_revision_sha256: &str,
    blob_sha256: &str,
    kind: PhotoArtifactKindV1,
    media_type: PhotoMediaTypeV1,
    width: u32,
    height: u32,
    rectangle: Option<RectV1>,
    descriptor: &SegmentationProviderDescriptorV1,
    request_mode: SegmentationRequestModeKindV1,
    prompt_hash: &Sha256Digest,
    terminal: &TerminalOutcome,
    provenance: &CanonicalProvenance,
    artifact_sha256: &Sha256Digest,
    now_ms: i64,
) -> PlatformResult<()> {
    let (x, y, rectangle_width, rectangle_height) = rectangle
        .map(|value| {
            (
                Some(i64::from(value.x)),
                Some(i64::from(value.y)),
                Some(i64::from(value.width)),
                Some(i64::from(value.height)),
            )
        })
        .unwrap_or((None, None, None, None));
    transaction.execute(
        "INSERT INTO photo_artifacts(
            artifact_id, attempt_id, scope_id, member_ordinal, source_revision_id,
            source_revision_sha256, input_blob_sha256, artifact_kind, media_type,
            source_width, source_height, rectangle_x, rectangle_y, rectangle_width,
            rectangle_height, artifact_schema_revision, artifact_revision,
            preprocessing_revision, provider_contract_revision, provider_id,
            provider_revision, model_revision, request_mode, prompt_parameters_sha256,
            quality_gate_revision, quality_approved, segmentation_outcome,
            unavailable_reason, failure_code, provenance_json, provenance_sha256,
            artifact_sha256, created_at_ms
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, 0,
            ?26, ?27, ?28, ?29, ?30, ?31, ?32
         )",
        params![
            artifact_id,
            attempt_id,
            scope_id,
            member_ordinal,
            source_revision_id,
            source_revision_sha256,
            blob_sha256,
            artifact_kind_db(kind),
            media_type_db(media_type),
            i64::from(width),
            i64::from(height),
            x,
            y,
            rectangle_width,
            rectangle_height,
            PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
            if rectangle.is_some() {
                RECTANGLE_SOURCE_CROP_REVISION_V1
            } else {
                SOURCE_IMAGE_REFERENCE_REVISION_V1
            },
            descriptor.preprocessing_revision,
            descriptor.contract_revision,
            descriptor.provider_id,
            descriptor.provider_revision,
            descriptor.model_revision,
            request_mode_db(request_mode),
            prompt_hash.as_str(),
            PHOTO_QUALITY_GATE_REVISION_V1,
            outcome_db(terminal.code),
            terminal.unavailable_reason.map(unavailable_reason_db),
            terminal.failure_code.map(failure_code_db),
            provenance.json,
            provenance.sha256.as_str(),
            artifact_sha256.as_str(),
            now_ms
        ],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_quarantined_outcome(
    transaction: &Transaction<'_>,
    request_id: &str,
    run_id: &str,
    scope_id: &str,
    ordinal: i64,
    source_revision_id: &str,
    descriptor: &SegmentationProviderDescriptorV1,
    now_ms: i64,
) -> PlatformResult<()> {
    let attempt_id = stable_id(
        "photo-segmentation-attempt",
        &format!("{run_id}:{ordinal}:quarantined"),
    );
    let request_handle = stable_id("photo-segmentation-request", &attempt_id);
    let source_revision_sha256: String = transaction.query_row(
        "SELECT source_revision_sha256 FROM photo_source_revisions
         WHERE source_revision_id = ?1",
        [source_revision_id],
        |row| row.get(0),
    )?;
    let prompt_hash = canonical_hash(
        b"wardrobe.photo.quarantined-skip.v1",
        &serde_json::json!({"source_revision_sha256": source_revision_sha256}),
    )?;
    let request_envelope = canonical_hash(
        b"wardrobe.photo.quarantined-attempt.v1",
        &serde_json::json!({
            "run_id": run_id,
            "member_ordinal": ordinal,
            "source_revision_id": source_revision_id
        }),
    )?;
    transaction.execute(
        "INSERT INTO photo_segmentation_attempts(
            attempt_id, request_handle, run_id, scope_id, member_ordinal,
            source_revision_id, source_revision_sha256, disposition, claim_fence,
            request_mode, input_blob_sha256, provider_contract_revision,
            provider_id, provider_revision, model_revision, preprocessing_revision,
            prompt_parameters_sha256, request_envelope_sha256, provider_invoked,
            created_at_ms
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'quarantined', 1,
            'quarantined_skip', NULL, ?8, ?9, ?10, ?11, ?12, ?13, ?14, 0, ?15
         )",
        params![
            attempt_id,
            request_handle,
            run_id,
            scope_id,
            ordinal,
            source_revision_id,
            source_revision_sha256,
            descriptor.contract_revision,
            descriptor.provider_id,
            descriptor.provider_revision,
            descriptor.model_revision,
            descriptor.preprocessing_revision,
            prompt_hash.as_str(),
            request_envelope.as_str(),
            now_ms
        ],
    )?;
    transaction.execute(
        "INSERT INTO photo_segmentation_outcomes(
            attempt_id, outcome, mask_count, quality_gate_result, completed_at_ms
         ) VALUES (?1, 'skipped_quarantined', 0, 'not_applicable', ?2)",
        params![attempt_id, now_ms],
    )?;
    link_command_entity(transaction, request_id, "segmentation_attempt", &attempt_id)
}

impl Database {
    fn list_photo_observations_impl(
        &self,
        request: &ListPhotoObservationsV1Request,
    ) -> PlatformResult<ListPhotoObservationsV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("photo_observation_list_request"))?;
        let connection = self.connection()?;
        let (photo_revision, evidence_generation) = revision_values(&connection)?;
        let after = parse_observation_cursor(
            request.cursor.as_ref(),
            request.state,
            photo_revision,
            evidence_generation,
        )?;
        let state = observation_state_db(request.state);
        let scope_id = request.scope_id.to_string();
        let total_count: i64 = connection.query_row(
            "SELECT COUNT(*)
             FROM photo_observations observation
             LEFT JOIN photo_review_heads head
               ON head.observation_id = observation.observation_id
             WHERE observation.scope_id = ?1
               AND COALESCE(head.state, observation.initial_state) = ?2",
            params![scope_id, state],
            |row| row.get(0),
        )?;
        let mut statement = connection.prepare(
            "SELECT observation.observation_id
             FROM photo_observations observation
             LEFT JOIN photo_review_heads head
               ON head.observation_id = observation.observation_id
             WHERE observation.scope_id = ?1
               AND COALESCE(head.state, observation.initial_state) = ?2
               AND (?3 IS NULL OR observation.observation_id > ?3)
             ORDER BY observation.observation_id
             LIMIT ?4",
        )?;
        let mut ids = statement
            .query_map(
                params![
                    scope_id,
                    state,
                    after.as_deref(),
                    i64::from(request.limit) + 1
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = ids.len() > usize::from(request.limit);
        ids.truncate(usize::from(request.limit));
        let observations = ids
            .iter()
            .map(|id| load_observation(&connection, id, None))
            .collect::<PlatformResult<Vec<_>>>()?;
        let next_cursor = if has_more {
            observations
                .last()
                .map(|observation| {
                    make_observation_cursor(
                        request.state,
                        photo_revision,
                        evidence_generation,
                        observation.observation_id,
                    )
                })
                .transpose()?
        } else {
            None
        };
        let response = ListPhotoObservationsV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            scope_id: request.scope_id,
            state: request.state,
            observations,
            total_count: to_u64(total_count, "photo_observation_count")?,
            photo_revision,
            evidence_generation,
            next_cursor,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("photo_observation_list_response"))?;
        Ok(response)
    }

    fn read_photo_artifact_impl(
        &self,
        request: &ReadPhotoArtifactV1Request,
    ) -> PlatformResult<ReadPhotoArtifactV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("photo_artifact_read_request"))?;
        let connection = self.connection()?;
        let artifact = load_artifact(&connection, &request.artifact_id.to_string())?;
        let expected_length: i64 = connection.query_row(
            "SELECT byte_length FROM photo_source_revisions
             WHERE source_revision_id = ?1 AND blob_sha256 = ?2",
            params![
                artifact.source_revision_id.to_string(),
                artifact.input_blob_sha256.as_str()
            ],
            |row| row.get(0),
        )?;
        let image = verify_source_image(
            &BlobStore::new(&self.paths),
            artifact.input_blob_sha256.as_str(),
            to_u64(expected_length, "photo_blob_length")?,
        )
        .map_err(|_| PlatformError::Corrupt("photo_artifact_source_reverification"))?;
        if image.media_type != artifact.media_type
            || image.width != artifact.source_width
            || image.height != artifact.source_height
        {
            return Err(PlatformError::Corrupt("photo_artifact_source_changed"));
        }
        let response = ReadPhotoArtifactV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            artifact_id: request.artifact_id,
            media_type: image.media_type,
            width: image.width,
            height: image.height,
            bytes_sha256: Sha256Digest::from_bytes(&image.bytes),
            bytes: BoundedPhotoArtifactBytesV1::new(image.bytes)
                .map_err(|_| PlatformError::Corrupt("photo_artifact_bytes"))?,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("photo_artifact_read_response"))?;
        Ok(response)
    }

    fn prompt_photo_observation_impl(
        &self,
        request: &PromptPhotoObservationV1Request,
        provider: &dyn GarmentSegmentationProvider,
    ) -> PlatformResult<PromptPhotoObservationV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("photo_prompt_request"))?;
        {
            let mut connection = self.connection()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some(mut response) = replay::<_, PromptPhotoObservationV1Response>(
                &transaction,
                PROMPT_COMMAND,
                request,
            )? {
                response.replay_status = ReplayStatusV1::Replayed;
                transaction.commit()?;
                return Ok(response);
            }
            transaction.commit()?;
        }
        let conforming = ConformingGarmentSegmentationProviderV1::new(provider)
            .map_err(|_| PlatformError::Corrupt("segmentation_provider_descriptor"))?;
        let descriptor = conforming.describe();
        if descriptor.preprocessing_revision != PHOTO_PREPROCESSING_REVISION_V1 {
            return Err(PlatformError::InvalidInput(
                "segmentation_preprocessing_revision",
            ));
        }
        let observation_id = request.observation_id.to_string();
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT observation.scope_id, observation.member_ordinal,
                        observation.source_revision_id,
                        revision.source_revision_sha256, revision.blob_sha256,
                        revision.byte_length, revision.media_type, revision.width,
                        revision.height, claim.run_id, claim.fence,
                        (
                            SELECT artifact.artifact_id
                            FROM photo_artifacts artifact
                            WHERE artifact.scope_id = observation.scope_id
                              AND artifact.source_revision_id =
                                  observation.source_revision_id
                            ORDER BY artifact.created_at_ms DESC,
                                     artifact.artifact_id DESC
                            LIMIT 1
                        )
                 FROM photo_observations observation
                 JOIN photo_source_revisions revision
                   ON revision.source_revision_id = observation.source_revision_id
                 JOIN photo_analysis_member_claims claim
                   ON claim.scope_id = observation.scope_id
                  AND claim.member_ordinal = observation.member_ordinal
                 WHERE observation.observation_id = ?1
                   AND claim.state = 'terminal'
                   AND NOT EXISTS (
                       SELECT 1 FROM photo_review_heads head
                       WHERE head.observation_id = observation.observation_id
                   )",
                [&observation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::Conflict("photo_observation_not_promptable"))?;
        drop(connection);
        let (
            scope_id,
            member_ordinal,
            source_revision_id,
            source_revision_sha256,
            blob_sha256,
            byte_length,
            media_type,
            width,
            height,
            run_id,
            fence,
            parent_artifact_id,
        ) = row;
        let width = to_u32(width, "photo_width")?;
        let height = to_u32(height, "photo_height")?;
        request
            .validate_geometry_within(width, height)
            .map_err(|_| PlatformError::InvalidInput("photo_prompt_geometry"))?;
        let work = AnalysisWork {
            run_id,
            scope_id: scope_id.clone(),
            member_ordinal,
            source_revision_id: source_revision_id.clone(),
            source_revision_sha256,
            blob_sha256,
            byte_length: to_u64(byte_length, "photo_blob_length")?,
            media_type: media_type_from_db(&media_type)?,
            width,
            height,
            fence,
            attempt_id: stable_id(
                "photo-segmentation-attempt",
                &format!("interactive:{}", request.request_id),
            ),
            request_handle: stable_id(
                "photo-segmentation-request",
                &request.request_id.to_string(),
            ),
        };
        let image = self.load_verified_work_image(&work)?;
        let mode = SegmentationRequestModeV1::Interactive {
            box_rectangle: request.box_rectangle,
            positive_points: request.positive_points.clone(),
            negative_points: request.negative_points.clone(),
        };
        let prompt_hash = wardrobe_core::prompt_parameters_sha256_v1(&mode)
            .map_err(|_| PlatformError::Corrupt("photo_prompt_hash"))?;
        let provider_request = SegmentationRequestV1 {
            contract_revision: GARMENT_SEGMENTATION_CONTRACT_V1.to_owned(),
            request_handle: parse_request_handle(&work.request_handle)?,
            source_revision_sha256: parse_digest(&work.source_revision_sha256)?,
            input_blob_sha256: parse_digest(&work.blob_sha256)?,
            pixels: image.canonical_pixels()?,
            width,
            height,
            preprocessing_revision: PHOTO_PREPROCESSING_REVISION_V1.to_owned(),
            mode,
        };
        let terminal = terminal_outcome(
            conforming.segment(&provider_request),
            &descriptor,
            &provider_request,
        )?;
        let now_ms = unix_now_ms()?;
        let artifact_id = stable_id("photo-artifact", &work.attempt_id);
        let parents = vec![parent_artifact_id.clone()];
        let provenance = make_artifact_provenance(
            &artifact_id,
            &scope_id,
            member_ordinal,
            &source_revision_id,
            &work.source_revision_sha256,
            &work.blob_sha256,
            image.media_type,
            width,
            height,
            Some(request.box_rectangle),
            &descriptor,
            SegmentationRequestModeKindV1::Interactive,
            &prompt_hash,
            &terminal,
            &parents,
        )?;
        let artifact_sha256 = artifact_hash(
            &provenance.sha256,
            PhotoArtifactKindV1::RectangleSourceCrop,
            Some(request.box_rectangle),
        )?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if transaction
            .query_row(
                "SELECT 1 FROM photo_review_heads WHERE observation_id = ?1",
                [&observation_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(PlatformError::Conflict("photo_review_head_exists"));
        }
        insert_segmentation_attempt(
            &transaction,
            &work,
            &descriptor,
            "interactive",
            &prompt_hash,
            &envelope_hash(request)?,
            now_ms,
        )?;
        insert_terminal_outcome(&transaction, &work.attempt_id, &terminal, now_ms)?;
        insert_artifact(
            &transaction,
            &artifact_id,
            &work.attempt_id,
            &scope_id,
            member_ordinal,
            &source_revision_id,
            &work.source_revision_sha256,
            &work.blob_sha256,
            PhotoArtifactKindV1::RectangleSourceCrop,
            image.media_type,
            width,
            height,
            Some(request.box_rectangle),
            &descriptor,
            SegmentationRequestModeKindV1::Interactive,
            &prompt_hash,
            &terminal,
            &provenance,
            &artifact_sha256,
            now_ms,
        )?;
        insert_parent_edge(
            &transaction,
            &artifact_id,
            0,
            &parent_artifact_id,
            &scope_id,
            &source_revision_id,
        )?;
        transaction.execute(
            "UPDATE revision_state
             SET evidence_generation = evidence_generation + 1 WHERE singleton = 1",
            [],
        )?;
        let (photo_revision, evidence_generation) = revision_values(&transaction)?;
        let observation = load_observation(&transaction, &observation_id, Some(&artifact_id))?;
        let response = PromptPhotoObservationV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            observation,
            photo_revision,
            evidence_generation,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("photo_prompt_response"))?;
        store_receipt(&transaction, PROMPT_COMMAND, request, &response, now_ms)?;
        for (kind, id) in [
            ("segmentation_attempt", work.attempt_id.as_str()),
            ("artifact", artifact_id.as_str()),
        ] {
            link_command_entity(&transaction, &request.request_id.to_string(), kind, id)?;
        }
        transaction.commit()?;
        Ok(response)
    }

    fn review_photo_observation_impl(
        &self,
        request: &ReviewPhotoObservationV1Request,
    ) -> PlatformResult<ReviewPhotoObservationV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("photo_review_request"))?;
        let now_ms = unix_now_ms()?;
        let observation_id = request.observation_id.to_string();
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, ReviewPhotoObservationV1Response>(&transaction, REVIEW_COMMAND, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let current_revision: i64 = transaction.query_row(
            "SELECT photo_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if to_u64(current_revision, "photo_revision")? != request.expected_photo_revision {
            return Err(PlatformError::Conflict("photo_revision_changed"));
        }
        let (scope_id, source_revision_id, current_artifact_id) = transaction
            .query_row(
                "SELECT observation.scope_id, observation.source_revision_id,
                        COALESCE(
                            head.current_artifact_id,
                            (
                                SELECT artifact.artifact_id
                                FROM photo_artifacts artifact
                                WHERE artifact.scope_id = observation.scope_id
                                  AND artifact.source_revision_id =
                                      observation.source_revision_id
                                ORDER BY artifact.created_at_ms DESC,
                                         artifact.artifact_id DESC
                                LIMIT 1
                            )
                        )
                 FROM photo_observations observation
                 LEFT JOIN photo_review_heads head
                   ON head.observation_id = observation.observation_id
                 WHERE observation.observation_id = ?1",
                [&observation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(PlatformError::InvalidInput("photo_observation_id"))?;
        let selected_artifact_id = if request.action == PhotoReviewActionV1::ReplaceCrop {
            let rectangle = request
                .replacement_rectangle
                .ok_or(PlatformError::InvalidInput("replacement_rectangle"))?;
            let parent = load_artifact(&transaction, &current_artifact_id)?;
            rectangle
                .validate_within(parent.source_width, parent.source_height)
                .map_err(|_| PlatformError::InvalidInput("replacement_rectangle"))?;
            let descriptor = descriptor_from_artifact(&parent);
            let terminal = terminal_from_artifact(&parent);
            let prompt_hash = replacement_prompt_hash(rectangle)?;
            let artifact_id =
                stable_id("photo-artifact", &format!("review:{}", request.request_id));
            let parents = vec![current_artifact_id.clone()];
            let provenance = make_artifact_provenance(
                &artifact_id,
                &scope_id,
                member_ordinal_for_artifact(&transaction, &current_artifact_id)?,
                &source_revision_id,
                parent.source_revision_sha256.as_str(),
                parent.input_blob_sha256.as_str(),
                parent.media_type,
                parent.source_width,
                parent.source_height,
                Some(rectangle),
                &descriptor,
                parent.request_mode,
                &prompt_hash,
                &terminal,
                &parents,
            )?;
            let hash = artifact_hash(
                &provenance.sha256,
                PhotoArtifactKindV1::RectangleSourceCrop,
                Some(rectangle),
            )?;
            let (attempt_id, member_ordinal): (String, i64) = transaction.query_row(
                "SELECT attempt_id, member_ordinal FROM photo_artifacts WHERE artifact_id = ?1",
                [&current_artifact_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            insert_artifact(
                &transaction,
                &artifact_id,
                &attempt_id,
                &scope_id,
                member_ordinal,
                &source_revision_id,
                parent.source_revision_sha256.as_str(),
                parent.input_blob_sha256.as_str(),
                PhotoArtifactKindV1::RectangleSourceCrop,
                parent.media_type,
                parent.source_width,
                parent.source_height,
                Some(rectangle),
                &descriptor,
                parent.request_mode,
                &prompt_hash,
                &terminal,
                &provenance,
                &hash,
                now_ms,
            )?;
            insert_parent_edge(
                &transaction,
                &artifact_id,
                0,
                &current_artifact_id,
                &scope_id,
                &source_revision_id,
            )?;
            link_command_entity(
                &transaction,
                &request.request_id.to_string(),
                "artifact",
                &artifact_id,
            )?;
            Some(artifact_id)
        } else if request.action == PhotoReviewActionV1::ConfirmCrop {
            Some(current_artifact_id.clone())
        } else {
            None
        };
        let new_revision = request
            .expected_photo_revision
            .checked_add(1)
            .ok_or(PlatformError::Conflict("photo_revision_changed"))?;
        let changed = transaction.execute(
            "UPDATE revision_state SET photo_revision = ?2
             WHERE singleton = 1 AND photo_revision = ?1",
            params![request.expected_photo_revision as i64, new_revision as i64],
        )?;
        if changed != 1 {
            return Err(PlatformError::Conflict("photo_revision_changed"));
        }
        let decision_id = stable_id("photo-review-decision", &request.request_id.to_string());
        transaction.execute(
            "INSERT INTO photo_review_decisions(
                decision_id, observation_id, scope_id, source_revision_id,
                request_id, action, selected_artifact_id, expected_photo_revision,
                photo_revision, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                decision_id,
                observation_id,
                scope_id,
                source_revision_id,
                request.request_id.to_string(),
                review_action_db(request.action),
                selected_artifact_id,
                request.expected_photo_revision as i64,
                new_revision as i64,
                now_ms
            ],
        )?;
        let head_artifact_id = selected_artifact_id
            .as_deref()
            .unwrap_or(&current_artifact_id);
        transaction.execute(
            "INSERT INTO photo_review_heads(
                observation_id, scope_id, source_revision_id, decision_id,
                current_artifact_id, state, photo_revision, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(observation_id) DO UPDATE SET
                decision_id = excluded.decision_id,
                current_artifact_id = excluded.current_artifact_id,
                state = excluded.state,
                photo_revision = excluded.photo_revision,
                updated_at_ms = excluded.updated_at_ms",
            params![
                observation_id,
                scope_id,
                source_revision_id,
                decision_id,
                head_artifact_id,
                observation_state_db(request.action.resulting_state()),
                new_revision as i64,
                now_ms
            ],
        )?;
        let decision = PhotoReviewDecisionV1 {
            decision_id: parse_decision_id(&decision_id)?,
            observation_id: request.observation_id,
            action: request.action,
            selected_artifact_id: selected_artifact_id
                .as_deref()
                .map(parse_artifact_id)
                .transpose()?,
            photo_revision: new_revision,
        };
        let observation = load_observation(&transaction, &observation_id, None)?;
        let response = ReviewPhotoObservationV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            observation,
            decision,
            new_photo_revision: new_revision,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("photo_review_response"))?;
        store_receipt(&transaction, REVIEW_COMMAND, request, &response, now_ms)?;
        link_command_entity(
            &transaction,
            &request.request_id.to_string(),
            "review_decision",
            &decision_id,
        )?;
        transaction.commit()?;
        Ok(response)
    }
}
fn inspect_members(
    connection: &Connection,
    store: &BlobStore,
    root_id: &str,
    scan_id: &str,
    generation: u64,
    hash_revisions: bool,
) -> PlatformResult<Vec<InspectedMember>> {
    let mut statement = connection.prepare(
        "SELECT source.source_id, source.identity_key, source.status,
                source.raw_sha256, source.blob_sha256, source.byte_length,
                provenance.provenance_id, provenance.request_id,
                provenance.raw_sha256, provenance.blob_sha256,
                provenance.observed_at_ms
         FROM local_sources source
         JOIN source_provenance provenance
           ON provenance.provenance_id = (
               SELECT selected.provenance_id
               FROM source_provenance selected
               WHERE selected.source_id = source.source_id
               ORDER BY selected.observed_at_ms DESC, selected.provenance_id DESC
               LIMIT 1
           )
         WHERE source.root_id = ?1
           AND source.source_kind = 'folder_image'
           AND source.manifest_generation = ?2
           AND source.status <> 'missing'
         ORDER BY source.source_id",
    )?;
    let rows = statement
        .query_map(params![root_id, generation as i64], |row| {
            Ok(SourceRow {
                source_id: row.get(0)?,
                identity_key: row.get(1)?,
                status: row.get(2)?,
                raw_sha256: row.get(3)?,
                blob_sha256: row.get(4)?,
                byte_length: row.get(5)?,
                provenance_id: row.get(6)?,
                provenance_request_id: row.get(7)?,
                provenance_raw_sha256: row.get(8)?,
                provenance_blob_sha256: row.get(9)?,
                provenance_observed_at_ms: row.get(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut members = Vec::with_capacity(rows.len());
    for row in rows {
        members.push(inspect_member(
            store,
            row,
            root_id,
            scan_id,
            generation,
            hash_revisions,
        )?);
    }
    Ok(members)
}

fn inspect_member(
    store: &BlobStore,
    row: SourceRow,
    root_id: &str,
    scan_id: &str,
    generation: u64,
    hash_revision: bool,
) -> PlatformResult<InspectedMember> {
    let identity_hash = Sha256Digest::from_bytes(row.identity_key.as_bytes());
    let provenance_hash = canonical_hash(
        b"wardrobe.photo.source-provenance.v1",
        &ProvenanceHashRecord {
            provenance_id: &row.provenance_id,
            source_id: &row.source_id,
            request_id: &row.provenance_request_id,
            raw_sha256: &row.provenance_raw_sha256,
            blob_sha256: &row.provenance_blob_sha256,
            observed_at_ms: row.provenance_observed_at_ms,
        },
    )?;
    let parsed_raw = row
        .raw_sha256
        .as_deref()
        .and_then(|value| Sha256Digest::parse(value.to_owned()).ok());
    let parsed_blob = row
        .blob_sha256
        .as_deref()
        .and_then(|value| Sha256Digest::parse(value.to_owned()).ok());
    let parsed_length = row
        .byte_length
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0);

    let inspection = match (
        row.status.as_str(),
        parsed_raw.as_ref(),
        parsed_blob.as_ref(),
        parsed_length,
    ) {
        ("imported", Some(_), Some(blob), Some(length)) => {
            verify_source_image(store, blob.as_str(), length)
        }
        ("imported", _, _, _) => Err(PhotoQuarantineReasonV1::BlobUnavailable),
        _ => Err(PhotoQuarantineReasonV1::SourceUnavailable),
    };
    let (disposition, quarantine_reason, media_type, width, height) = match inspection {
        Ok(image) => (
            PhotoSourceDispositionV1::Eligible,
            None,
            Some(image.media_type),
            Some(image.width),
            Some(image.height),
        ),
        Err(reason) => (
            PhotoSourceDispositionV1::Quarantined,
            Some(reason),
            None,
            None,
            None,
        ),
    };
    let materialized_pair = parsed_blob.zip(parsed_length);
    let (blob_sha256, byte_length) = materialized_pair
        .map(|(hash, length)| (Some(hash), Some(length)))
        .unwrap_or((None, None));
    let mut revision = PhotoSourceRevisionV1 {
        source_revision_id: PhotoSourceRevisionId::new_v4(),
        source_id: parse_source_id(&row.source_id)?,
        import_root_id: parse_import_root_id(root_id)?,
        completed_scan_id: parse_scan_id(scan_id)?,
        manifest_generation: generation,
        source_identity_key_sha256: identity_hash,
        provenance_row_sha256: provenance_hash,
        raw_sha256: parsed_raw,
        blob_sha256,
        byte_length,
        media_type,
        width,
        height,
        disposition,
        quarantine_reason,
        source_revision_sha256: Sha256Digest::from_bytes(b"pending"),
    };
    if hash_revision {
        revision.source_revision_sha256 = source_revision_hash(&revision)?;
    }
    Ok(InspectedMember {
        source_revision: revision,
        provenance_id: row.provenance_id,
        leaf_sha256: Sha256Digest::from_bytes(b"pending"),
    })
}

fn source_revision_hash(revision: &PhotoSourceRevisionV1) -> PlatformResult<Sha256Digest> {
    let source_id = revision.source_id.to_string();
    let root_id = revision.import_root_id.to_string();
    let scan_id = revision.completed_scan_id.to_string();
    canonical_hash(
        b"wardrobe.photo.source-revision.v1",
        &SourceRevisionHashRecord {
            schema_revision: "photo-source-revision-v1",
            source_id: &source_id,
            root_id: &root_id,
            scan_id: &scan_id,
            manifest_generation: revision.manifest_generation,
            source_identity_key_sha256: revision.source_identity_key_sha256.as_str(),
            provenance_row_sha256: revision.provenance_row_sha256.as_str(),
            raw_sha256: revision.raw_sha256.as_ref().map(Sha256Digest::as_str),
            blob_sha256: revision.blob_sha256.as_ref().map(Sha256Digest::as_str),
            byte_length: revision.byte_length,
            media_type: revision.media_type.map(media_type_db),
            width: revision.width,
            height: revision.height,
            disposition: disposition_db(revision.disposition),
            quarantine_reason: revision.quarantine_reason.map(quarantine_reason_db),
        },
    )
}

fn member_leaf_hash(
    ordinal: u16,
    revision: &PhotoSourceRevisionV1,
) -> PlatformResult<Sha256Digest> {
    canonical_hash(
        b"wardrobe.photo.scope-member.v1",
        &MemberLeafHashRecord {
            schema_revision: "photo-scope-member-v1",
            ordinal,
            source_revision_id: &revision.source_revision_id.to_string(),
            source_revision_sha256: revision.source_revision_sha256.as_str(),
            disposition: disposition_db(revision.disposition),
        },
    )
}

fn membership_hash(
    root_id: &str,
    scan_id: &str,
    generation: u64,
    members: &[InspectedMember],
) -> PlatformResult<Sha256Digest> {
    canonical_hash(
        b"wardrobe.photo.scope-membership.v1",
        &MembershipHashRecord {
            schema_revision: SCOPE_SCHEMA_REVISION,
            root_id,
            scan_id,
            manifest_generation: generation,
            member_count: members.len(),
            leaf_sha256: members
                .iter()
                .map(|member| member.leaf_sha256.as_str())
                .collect(),
        },
    )
}

fn insert_source_revision(
    transaction: &Transaction<'_>,
    member: &InspectedMember,
    root_id: &str,
    scan_id: &str,
    generation: i64,
    now_ms: i64,
) -> PlatformResult<()> {
    let revision = &member.source_revision;
    revision
        .validate()
        .map_err(|_| PlatformError::Corrupt("photo_source_revision_contract"))?;
    transaction.execute(
        "INSERT INTO photo_source_revisions(
            source_revision_id, source_id, source_provenance_id, root_id, scan_id,
            manifest_generation, source_identity_key_sha256, provenance_row_sha256,
            raw_sha256, blob_sha256, byte_length, media_type, width, height,
            disposition, quarantine_reason, source_revision_sha256, created_at_ms
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18
         )",
        params![
            revision.source_revision_id.to_string(),
            revision.source_id.to_string(),
            member.provenance_id,
            root_id,
            scan_id,
            generation,
            revision.source_identity_key_sha256.as_str(),
            revision.provenance_row_sha256.as_str(),
            revision.raw_sha256.as_ref().map(Sha256Digest::as_str),
            revision.blob_sha256.as_ref().map(Sha256Digest::as_str),
            revision.byte_length.map(|value| value as i64),
            revision.media_type.map(media_type_db),
            revision.width.map(i64::from),
            revision.height.map(i64::from),
            disposition_db(revision.disposition),
            revision.quarantine_reason.map(quarantine_reason_db),
            revision.source_revision_sha256.as_str(),
            now_ms
        ],
    )?;
    Ok(())
}

fn canonical_hash<T: Serialize>(domain: &[u8], value: &T) -> PlatformResult<Sha256Digest> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(serde_json::to_vec(value)?);
    Sha256Digest::parse(format!("{:x}", digest.finalize()))
        .map_err(|_| PlatformError::Corrupt("photo_canonical_hash"))
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
            request_id, command_name, envelope_hash, response_json, created_at_ms
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
        .ok_or(PlatformError::Corrupt("photo_request_id"))
}

fn envelope_hash<Q: Serialize>(request: &Q) -> PlatformResult<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(request)?)
    ))
}

fn link_command_entity(
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

fn revision_values(connection: &Connection) -> PlatformResult<(u64, u64)> {
    let values: (i64, i64) = connection.query_row(
        "SELECT photo_revision, evidence_generation
         FROM revision_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((
        to_u64(values.0, "photo_revision")?,
        to_u64(values.1, "evidence_generation")?,
    ))
}

fn parse_roots_cursor(
    cursor: Option<&PageCursorV1>,
    evidence_generation: u64,
) -> PlatformResult<Option<String>> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let prefix = format!("photo-roots.{evidence_generation}.");
    let root_id = cursor
        .as_str()
        .strip_prefix(&prefix)
        .ok_or(PlatformError::Conflict("snapshot_expired"))?;
    parse_import_root_id(root_id)?;
    Ok(Some(root_id.to_owned()))
}

fn make_roots_cursor(
    evidence_generation: u64,
    root_id: wardrobe_core::ImportRootId,
) -> PlatformResult<PageCursorV1> {
    PageCursorV1::new(format!("photo-roots.{evidence_generation}.{root_id}"))
        .map_err(|_| PlatformError::Corrupt("photo_roots_cursor"))
}

fn parse_observation_cursor(
    cursor: Option<&PageCursorV1>,
    state: PhotoObservationStateV1,
    photo_revision: u64,
    evidence_generation: u64,
) -> PlatformResult<Option<String>> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let prefix = format!(
        "photo-observations.{}.{}.{}.",
        observation_state_db(state),
        photo_revision,
        evidence_generation
    );
    let observation_id = cursor
        .as_str()
        .strip_prefix(&prefix)
        .ok_or(PlatformError::Conflict("snapshot_expired"))?;
    parse_observation_id(observation_id)?;
    Ok(Some(observation_id.to_owned()))
}

fn make_observation_cursor(
    state: PhotoObservationStateV1,
    photo_revision: u64,
    evidence_generation: u64,
    observation_id: PhotoObservationId,
) -> PlatformResult<PageCursorV1> {
    PageCursorV1::new(format!(
        "photo-observations.{}.{}.{}.{}",
        observation_state_db(state),
        photo_revision,
        evidence_generation,
        observation_id
    ))
    .map_err(|_| PlatformError::Corrupt("photo_observation_cursor"))
}

fn photo_port_error(error: PlatformError) -> PhotoAnalysisPortError {
    let kind = match error {
        PlatformError::Conflict("snapshot_expired" | "photo_generation_stale") => {
            PhotoAnalysisPortErrorKind::SnapshotExpired
        }
        PlatformError::Conflict(_) | PlatformError::LeaseLost => {
            PhotoAnalysisPortErrorKind::Conflict
        }
        PlatformError::InvalidInput(_) | PlatformError::Unsupported(_) => {
            PhotoAnalysisPortErrorKind::InvalidState
        }
        PlatformError::Corrupt(_) => PhotoAnalysisPortErrorKind::DataIntegrity,
        PlatformError::Io(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            PhotoAnalysisPortErrorKind::PermissionDenied
        }
        PlatformError::Io(ref error) if error.kind() == std::io::ErrorKind::NotFound => {
            PhotoAnalysisPortErrorKind::NotFound
        }
        PlatformError::Io(_) => PhotoAnalysisPortErrorKind::Unavailable,
        _ => PhotoAnalysisPortErrorKind::Internal,
    };
    PhotoAnalysisPortError::new(kind)
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

fn parse_digest(value: &str) -> PlatformResult<Sha256Digest> {
    Sha256Digest::parse(value.to_owned()).map_err(|_| PlatformError::Corrupt("photo_sha256"))
}

fn parse_uuid(value: &str, field: &'static str) -> PlatformResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt(field))
}

fn parse_import_root_id(value: &str) -> PlatformResult<wardrobe_core::ImportRootId> {
    wardrobe_core::ImportRootId::new(parse_uuid(value, "import_root_id")?)
        .map_err(|_| PlatformError::Corrupt("import_root_id"))
}

fn parse_source_id(value: &str) -> PlatformResult<SourceId> {
    SourceId::new(parse_uuid(value, "source_id")?).map_err(|_| PlatformError::Corrupt("source_id"))
}

fn parse_scan_id(value: &str) -> PlatformResult<PhotoImportScanId> {
    PhotoImportScanId::new(parse_uuid(value, "photo_scan_id")?)
        .map_err(|_| PlatformError::Corrupt("photo_scan_id"))
}

fn parse_scope_id(value: &str) -> PlatformResult<PhotoScopeId> {
    PhotoScopeId::new(parse_uuid(value, "photo_scope_id")?)
        .map_err(|_| PlatformError::Corrupt("photo_scope_id"))
}

fn parse_source_revision_id(value: &str) -> PlatformResult<PhotoSourceRevisionId> {
    PhotoSourceRevisionId::new(parse_uuid(value, "photo_source_revision_id")?)
        .map_err(|_| PlatformError::Corrupt("photo_source_revision_id"))
}

fn parse_run_id(value: &str) -> PlatformResult<PhotoAnalysisRunId> {
    PhotoAnalysisRunId::new(parse_uuid(value, "photo_run_id")?)
        .map_err(|_| PlatformError::Corrupt("photo_run_id"))
}

fn parse_artifact_id(value: &str) -> PlatformResult<PhotoArtifactId> {
    PhotoArtifactId::new(parse_uuid(value, "photo_artifact_id")?)
        .map_err(|_| PlatformError::Corrupt("photo_artifact_id"))
}

fn parse_observation_id(value: &str) -> PlatformResult<PhotoObservationId> {
    PhotoObservationId::new(parse_uuid(value, "photo_observation_id")?)
        .map_err(|_| PlatformError::Corrupt("photo_observation_id"))
}

fn parse_decision_id(value: &str) -> PlatformResult<PhotoReviewDecisionId> {
    PhotoReviewDecisionId::new(parse_uuid(value, "photo_decision_id")?)
        .map_err(|_| PlatformError::Corrupt("photo_decision_id"))
}

fn parse_request_handle(value: &str) -> PlatformResult<SegmentationRequestHandle> {
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

fn disposition_db(value: PhotoSourceDispositionV1) -> &'static str {
    match value {
        PhotoSourceDispositionV1::Eligible => "eligible",
        PhotoSourceDispositionV1::Quarantined => "quarantined",
    }
}

fn quarantine_reason_db(value: PhotoQuarantineReasonV1) -> &'static str {
    match value {
        PhotoQuarantineReasonV1::SourceUnavailable => "source_unavailable",
        PhotoQuarantineReasonV1::BlobUnavailable => "blob_unavailable",
        PhotoQuarantineReasonV1::BlobIntegrityFailed => "blob_integrity_failed",
        PhotoQuarantineReasonV1::MediaTypeRejected => "media_type_rejected",
        PhotoQuarantineReasonV1::ImageDecodeFailed => "image_decode_failed",
        PhotoQuarantineReasonV1::ImageAnimated => "image_animated",
        PhotoQuarantineReasonV1::ImageDimensionLimit => "image_dimension_limit",
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

fn request_mode_db(value: SegmentationRequestModeKindV1) -> &'static str {
    match value {
        SegmentationRequestModeKindV1::Automatic => "automatic",
        SegmentationRequestModeKindV1::Interactive => "interactive",
    }
}

fn request_mode_from_db(value: &str) -> PlatformResult<SegmentationRequestModeKindV1> {
    match value {
        "automatic" => Ok(SegmentationRequestModeKindV1::Automatic),
        "interactive" => Ok(SegmentationRequestModeKindV1::Interactive),
        _ => Err(PlatformError::Corrupt("photo_request_mode")),
    }
}

fn outcome_db(value: PhotoSegmentationOutcomeCodeV1) -> &'static str {
    match value {
        PhotoSegmentationOutcomeCodeV1::AutomaticMasks => "automatic_masks",
        PhotoSegmentationOutcomeCodeV1::InteractiveMasks => "interactive_masks",
        PhotoSegmentationOutcomeCodeV1::NoGarment => "no_garment",
        PhotoSegmentationOutcomeCodeV1::Unavailable => "unavailable",
        PhotoSegmentationOutcomeCodeV1::Failed => "failed",
        PhotoSegmentationOutcomeCodeV1::Rejected => "rejected",
    }
}

fn outcome_from_db(value: &str) -> PlatformResult<PhotoSegmentationOutcomeCodeV1> {
    match value {
        "automatic_masks" => Ok(PhotoSegmentationOutcomeCodeV1::AutomaticMasks),
        "interactive_masks" => Ok(PhotoSegmentationOutcomeCodeV1::InteractiveMasks),
        "no_garment" => Ok(PhotoSegmentationOutcomeCodeV1::NoGarment),
        "unavailable" => Ok(PhotoSegmentationOutcomeCodeV1::Unavailable),
        "failed" => Ok(PhotoSegmentationOutcomeCodeV1::Failed),
        "rejected" => Ok(PhotoSegmentationOutcomeCodeV1::Rejected),
        _ => Err(PlatformError::Corrupt("photo_segmentation_outcome")),
    }
}

fn unavailable_reason_db(value: SegmentationUnavailableReasonV1) -> &'static str {
    match value {
        SegmentationUnavailableReasonV1::ReviewedModelPackAbsent => "reviewed_model_pack_absent",
        SegmentationUnavailableReasonV1::CapabilityDisabled => "capability_disabled",
        SegmentationUnavailableReasonV1::ResourceUnavailable => "resource_unavailable",
    }
}

fn unavailable_reason_from_db(value: &str) -> PlatformResult<SegmentationUnavailableReasonV1> {
    match value {
        "reviewed_model_pack_absent" => {
            Ok(SegmentationUnavailableReasonV1::ReviewedModelPackAbsent)
        }
        "capability_disabled" => Ok(SegmentationUnavailableReasonV1::CapabilityDisabled),
        "resource_unavailable" => Ok(SegmentationUnavailableReasonV1::ResourceUnavailable),
        _ => Err(PlatformError::Corrupt(
            "photo_segmentation_unavailable_reason",
        )),
    }
}

fn failure_code_db(value: SegmentationFailureCodeV1) -> &'static str {
    match value {
        SegmentationFailureCodeV1::InvalidInput => "invalid_input",
        SegmentationFailureCodeV1::InferenceFailed => "inference_failed",
        SegmentationFailureCodeV1::ResourceLimit => "resource_limit",
        SegmentationFailureCodeV1::TimedOut => "timed_out",
    }
}

fn failure_code_from_db(value: &str) -> PlatformResult<SegmentationFailureCodeV1> {
    match value {
        "invalid_input" => Ok(SegmentationFailureCodeV1::InvalidInput),
        "inference_failed" => Ok(SegmentationFailureCodeV1::InferenceFailed),
        "resource_limit" => Ok(SegmentationFailureCodeV1::ResourceLimit),
        "timed_out" => Ok(SegmentationFailureCodeV1::TimedOut),
        _ => Err(PlatformError::Corrupt("photo_segmentation_failure_code")),
    }
}

fn artifact_kind_db(value: PhotoArtifactKindV1) -> &'static str {
    match value {
        PhotoArtifactKindV1::RectangleSourceCrop => "rectangle_source_crop",
        PhotoArtifactKindV1::SourceImageReference => "source_image_reference",
    }
}

fn artifact_kind_from_db(value: &str) -> PlatformResult<PhotoArtifactKindV1> {
    match value {
        "rectangle_source_crop" => Ok(PhotoArtifactKindV1::RectangleSourceCrop),
        "source_image_reference" => Ok(PhotoArtifactKindV1::SourceImageReference),
        _ => Err(PlatformError::Corrupt("photo_artifact_kind")),
    }
}

fn observation_state_db(value: PhotoObservationStateV1) -> &'static str {
    match value {
        PhotoObservationStateV1::NeedsReview => "needs_review",
        PhotoObservationStateV1::Confirmed => "confirmed",
        PhotoObservationStateV1::Replaced => "replaced",
        PhotoObservationStateV1::Deferred => "deferred",
        PhotoObservationStateV1::Rejected => "rejected",
    }
}

fn observation_state_from_db(value: &str) -> PlatformResult<PhotoObservationStateV1> {
    match value {
        "needs_review" => Ok(PhotoObservationStateV1::NeedsReview),
        "confirmed" => Ok(PhotoObservationStateV1::Confirmed),
        "replaced" => Ok(PhotoObservationStateV1::Replaced),
        "deferred" => Ok(PhotoObservationStateV1::Deferred),
        "rejected" => Ok(PhotoObservationStateV1::Rejected),
        _ => Err(PlatformError::Corrupt("photo_observation_state")),
    }
}

fn review_action_db(value: PhotoReviewActionV1) -> &'static str {
    match value {
        PhotoReviewActionV1::ConfirmCrop => "confirm_crop",
        PhotoReviewActionV1::ReplaceCrop => "replace_crop",
        PhotoReviewActionV1::Defer => "defer",
        PhotoReviewActionV1::Reject => "reject",
    }
}

fn review_action_from_db(value: &str) -> PlatformResult<PhotoReviewActionV1> {
    match value {
        "confirm_crop" => Ok(PhotoReviewActionV1::ConfirmCrop),
        "replace_crop" => Ok(PhotoReviewActionV1::ReplaceCrop),
        "defer" => Ok(PhotoReviewActionV1::Defer),
        "reject" => Ok(PhotoReviewActionV1::Reject),
        _ => Err(PlatformError::Corrupt("photo_review_action")),
    }
}
