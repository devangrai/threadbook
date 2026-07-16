use crate::database::stable_id;
use crate::source_image::{
    extract_local_visual_features_v1, verify_source_image, LocalVisualFeaturesV1,
};
use crate::{BlobStore, Database, PlatformError, PlatformResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;
use wardrobe_core::{
    CandidateEvidenceFeatureV1, CandidateEvidencePolarityV1, CandidateEvidenceSourceKindV1,
    CandidateEvidenceV1, CorrectedReceiptOrderV1, DecideReconciliationCaseV1Request,
    DecideReconciliationCaseV1Response, DecideReconciliationCaseV2Request,
    DecideReconciliationCaseV2Response, IdentityRelationV1, ItemAttributesV1, ItemId,
    ListReconciliationCasesV2Request, ListReconciliationCasesV2Response,
    OpenReconciliationCaseV1Request, OpenReconciliationCaseV1Response,
    OpenReconciliationCaseV2Request, OpenReconciliationCaseV2Response, PageCursorV1,
    PhotoArtifactId, PhotoArtifactKindV1, PhotoMediaTypeV1, PhotoObservationId,
    PhotoOwnerDecisionId, PhotoPersonInstanceId, PhotoReviewDecisionId, ReceiptEventKindV1,
    ReceiptOrderLineId, ReceiptVariantEvidenceId, ReconciliationAuthorityReasonV2,
    ReconciliationAuthorityStateV2, ReconciliationCandidateDateKindV1,
    ReconciliationCandidateDateV1, ReconciliationCandidateId, ReconciliationCandidateTargetV1,
    ReconciliationCandidateV1, ReconciliationCaseId, ReconciliationCaseStateFilterV2,
    ReconciliationCaseV1, ReconciliationCaseV2, ReconciliationDecisionId, ReconciliationDecisionV1,
    ReconciliationEvidenceId, ReconciliationEvidenceSourceId, ReconciliationOutcomeV1,
    ReconciliationPort, ReconciliationPortError, ReconciliationPortErrorKind,
    ReconciliationPortResult, ReplayStatusV1, Sha256Digest, Validate,
    EVIDENCE_VALUE_CATALOG_IMAGE_ABSENT_V1, EVIDENCE_VALUE_CATALOG_IMAGE_CORRUPT_V1,
    EVIDENCE_VALUE_CATALOG_IMAGE_UNAVAILABLE_V1, EVIDENCE_VALUE_CORRECTED_CHANGED_V1,
    EVIDENCE_VALUE_CORRECTED_UNCHANGED_V1, EVIDENCE_VALUE_CORRECTED_UNKNOWN_V1,
    EVIDENCE_VALUE_EVENT_EXCHANGE_V1, EVIDENCE_VALUE_EVENT_PURCHASE_V1,
    EVIDENCE_VALUE_EVENT_RETURN_V1, EVIDENCE_VALUE_EVENT_UNKNOWN_V1,
    EVIDENCE_VALUE_EXTRACTED_RECEIPT_V1, EVIDENCE_VALUE_MEASURED_V1,
    EVIDENCE_VALUE_PURCHASE_AFTER_OBSERVATION_V1, EVIDENCE_VALUE_PURCHASE_BEFORE_OBSERVATION_V1,
    EVIDENCE_VALUE_PURCHASE_DATE_UNKNOWN_V1, EVIDENCE_VALUE_RECEIPT_CONFIRMED_V1,
    EVIDENCE_VALUE_RECEIPT_CORRECTED_V1, LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_ID_V1,
    LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_REVISION_V1, LOCAL_VISUAL_FEATURE_EXTRACTOR_ID_V1,
    LOCAL_VISUAL_FEATURE_EXTRACTOR_REVISION_V1, PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
    PHOTO_PREPROCESSING_REVISION_V1, RECONCILIATION_RETRIEVAL_REVISION_V1,
    RECTANGLE_SOURCE_CROP_REVISION_V1, SCHEMA_VERSION_V1, SOURCE_IMAGE_REFERENCE_REVISION_V1,
};

const OPEN_COMMAND: &str = "open_reconciliation_case_v1";
const DECIDE_COMMAND: &str = "decide_reconciliation_case_v1";
const OPEN_V2_COMMAND: &str = "open_reconciliation_case_v2";
const DECIDE_V2_COMMAND: &str = "decide_reconciliation_case_v2";
const RECONCILIATION_SCHEMA_VERSION_V2: u8 = 2;
const RECONCILIATION_CURSOR_VERSION_V2: u8 = 1;
const MAX_POOL_SIZE: i64 = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Revisions {
    catalog: u64,
    evidence_generation: u64,
    receipt: u64,
    photo: u64,
    owner: u64,
    reconciliation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PhotoPin {
    observation_id: String,
    artifact_id: String,
    scope_id: String,
    source_revision_id: String,
    source_revision_sha256: String,
    photo_decision_id: String,
    photo_revision: u64,
    owner_decision_id: String,
    person_instance_id: String,
    owner_revision: u64,
    owner_evidence_sha256: String,
    observation_created_at_ms: i64,
    blob_sha256: String,
    byte_length: u64,
    media_type: PhotoMediaTypeV1,
    width: u32,
    height: u32,
    artifact_kind: PhotoArtifactKindV1,
    rectangle: (u32, u32, u32, u32),
    artifact_revision: String,
    preprocessing_revision: String,
    provenance_json: String,
    provenance_sha256: String,
    artifact_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogImageSnapshot {
    evidence_id: String,
    assigned_revision: u64,
    blob_sha256: Option<String>,
    provenance_sha256: String,
    byte_length: Option<u64>,
    media_type: Option<PhotoMediaTypeV1>,
    source_status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogSnapshot {
    item_id: String,
    attributes_json: String,
    updated_revision: u64,
    creation_decision_id: String,
    creation_revision: u64,
    creation_at_ms: i64,
    image: Option<CatalogImageSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct FieldSnapshot {
    field_id: String,
    value_kind: String,
    value_text: Option<String>,
    value_integer: Option<u64>,
    is_known: bool,
    citations: Vec<(String, u32, u32, String)>,
}

impl FieldSnapshot {
    fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&serde_json::to_vec(self).expect("field snapshot serializes"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReceiptSnapshot {
    order_id: String,
    order_line_id: String,
    variant_id: String,
    order_created_at_ms: i64,
    review_decision_id: String,
    review_action: String,
    reviewed_order_json: Option<String>,
    receipt_revision: u64,
    output_sha256: String,
    provider_revision: String,
    merchant_field: FieldSnapshot,
    purchase_date_field: FieldSnapshot,
    description_field: FieldSnapshot,
    event_field: FieldSnapshot,
    authoritative_merchant: Option<String>,
    authoritative_purchase_date: Option<String>,
    authoritative_description: Option<String>,
    authoritative_event: Option<ReceiptEventKindV1>,
    authoritative_brand: Option<String>,
    authoritative_sku: Option<String>,
    authoritative_size: Option<String>,
    authoritative_color: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProposalSnapshot {
    revisions: Revisions,
    pin: PhotoPin,
    catalog: Vec<CatalogSnapshot>,
    receipts: Vec<ReceiptSnapshot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationCursorV2 {
    cursor_version: u8,
    schema_version: u8,
    observation_id: String,
    state: String,
    photo_revision: u64,
    owner_revision: u64,
    reconciliation_revision: u64,
    last_created_at_ms: u64,
    last_case_id: String,
}

#[derive(Serialize)]
struct AuthorityPersonEvidence<'a> {
    owner_review_id: &'a str,
    source_revision_id: &'a str,
    detection_attempt_id: Option<&'a str>,
    correction_id: Option<&'a str>,
    source_kind: &'a str,
    instance_ordinal: i64,
    rectangle: wardrobe_core::RectV1,
    confidence_basis_points: Option<u16>,
}

#[derive(Serialize)]
struct AuthorityOwnerEvidence<'a> {
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

#[derive(Clone, Debug)]
struct RankedCandidate {
    candidate: ReconciliationCandidateV1,
    visual_sort: Option<(u8, u16)>,
    updated_revision: u64,
    target_id: String,
    receipt_is_return: bool,
    receipt_date: Option<String>,
    receipt_created_at_ms: i64,
}

impl ReconciliationPort for Database {
    fn open_reconciliation_case(
        &self,
        request: &OpenReconciliationCaseV1Request,
    ) -> ReconciliationPortResult<OpenReconciliationCaseV1Response> {
        self.open_reconciliation_case_impl(request)
            .map_err(reconciliation_port_error)
    }

    fn decide_reconciliation_case(
        &self,
        request: &DecideReconciliationCaseV1Request,
    ) -> ReconciliationPortResult<DecideReconciliationCaseV1Response> {
        self.decide_reconciliation_case_impl(request)
            .map_err(reconciliation_port_error)
    }

    fn open_reconciliation_case_v2(
        &self,
        request: &OpenReconciliationCaseV2Request,
    ) -> ReconciliationPortResult<OpenReconciliationCaseV2Response> {
        self.open_reconciliation_case_v2_impl(request)
            .map_err(reconciliation_port_error)
    }

    fn decide_reconciliation_case_v2(
        &self,
        request: &DecideReconciliationCaseV2Request,
    ) -> ReconciliationPortResult<DecideReconciliationCaseV2Response> {
        self.decide_reconciliation_case_v2_impl(request)
            .map_err(reconciliation_port_error)
    }

    fn list_reconciliation_cases_v2(
        &self,
        request: &ListReconciliationCasesV2Request,
    ) -> ReconciliationPortResult<ListReconciliationCasesV2Response> {
        self.list_reconciliation_cases_v2_impl(request)
            .map_err(reconciliation_port_error)
    }
}

impl Database {
    fn open_reconciliation_case_impl(
        &self,
        request: &OpenReconciliationCaseV1Request,
    ) -> PlatformResult<OpenReconciliationCaseV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("reconciliation_open_request"))?;
        if let Some(mut response) =
            replay_read::<_, OpenReconciliationCaseV1Response>(self, OPEN_COMMAND, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            return Ok(response);
        }

        let snapshot = self.load_proposal_snapshot(request)?;
        let mut candidates = self.build_candidates(&snapshot)?;
        let case_id = reconciliation_case_id(&snapshot.pin);
        let no_match_id = stable_id("reconciliation-candidate", &format!("{case_id}:no-match"));
        candidates.push(ReconciliationCandidateV1 {
            candidate_id: parse_candidate_id(&no_match_id)?,
            target: ReconciliationCandidateTargetV1::NoMatch {},
            proposed_relation: None,
            observed_relations: Vec::new(),
            rank: None,
            display_name: "No match".to_owned(),
            detail: "Keep this photo observation unmatched".to_owned(),
            date: None,
            evidence: Vec::new(),
        });
        let leading_id = candidates[0].candidate_id;
        let observation_date = timestamp_from_ms(snapshot.pin.observation_created_at_ms)?;
        let now_ms = unix_now_ms()?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, OpenReconciliationCaseV1Response>(&transaction, OPEN_COMMAND, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let current = load_proposal_snapshot_from_connection(&transaction, request)?;
        let mut expected = snapshot.clone();
        expected.revisions.reconciliation = current.revisions.reconciliation;
        if current != expected {
            return Err(PlatformError::Conflict(
                "reconciliation_candidate_snapshot_changed",
            ));
        }

        let existing = transaction
            .query_row(
                "SELECT case_id FROM reconciliation_cases
                 WHERE observation_id = ?1 AND artifact_id = ?2
                   AND photo_decision_id = ?3
                   AND owner_decision_id = ?4
                   AND retrieval_revision = ?5",
                params![
                    snapshot.pin.observation_id,
                    snapshot.pin.artifact_id,
                    snapshot.pin.photo_decision_id,
                    snapshot.pin.owner_decision_id,
                    RECONCILIATION_RETRIEVAL_REVISION_V1
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_case_id) = existing {
            let revision = advance_reconciliation_revision(&transaction)?;
            let case = load_case(&transaction, &existing_case_id)?;
            let response = OpenReconciliationCaseV1Response {
                schema_version: SCHEMA_VERSION_V1,
                request_id: request.request_id,
                case,
                evidence_generation: current.revisions.evidence_generation,
                reconciliation_revision: revision,
                replay_status: ReplayStatusV1::Created,
            };
            response
                .validate()
                .map_err(|_| PlatformError::Corrupt("reconciliation_open_response"))?;
            store_receipt(&transaction, OPEN_COMMAND, request, &response, now_ms)?;
            link_command_entity(
                &transaction,
                &request.request_id.to_string(),
                "case",
                &existing_case_id,
                revision,
            )?;
            transaction.commit()?;
            return Ok(response);
        }

        let revision = advance_reconciliation_revision(&transaction)?;
        transaction.execute(
            "INSERT INTO reconciliation_cases(
                case_id, observation_id, artifact_id, scope_id,
                source_revision_id, source_revision_sha256, artifact_sha256,
                photo_decision_id, photo_revision, owner_decision_id,
                person_instance_id, owner_revision, owner_evidence_sha256,
                catalog_revision, receipt_revision, retrieval_revision, observation_date,
                leading_candidate_id, no_match_candidate_id, case_revision,
                reconciliation_revision, created_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, 1, ?20, ?21
             )",
            params![
                case_id,
                snapshot.pin.observation_id,
                snapshot.pin.artifact_id,
                snapshot.pin.scope_id,
                snapshot.pin.source_revision_id,
                snapshot.pin.source_revision_sha256,
                snapshot.pin.artifact_sha256,
                snapshot.pin.photo_decision_id,
                snapshot.pin.photo_revision as i64,
                snapshot.pin.owner_decision_id,
                snapshot.pin.person_instance_id,
                snapshot.pin.owner_revision as i64,
                snapshot.pin.owner_evidence_sha256,
                snapshot.revisions.catalog as i64,
                snapshot.revisions.receipt as i64,
                RECONCILIATION_RETRIEVAL_REVISION_V1,
                observation_date,
                leading_id.to_string(),
                no_match_id,
                revision as i64,
                now_ms
            ],
        )?;
        for candidate in &candidates {
            insert_candidate(&transaction, &case_id, candidate, revision, now_ms)?;
        }
        let case = load_case(&transaction, &case_id)?;
        let response = OpenReconciliationCaseV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            case,
            evidence_generation: snapshot.revisions.evidence_generation,
            reconciliation_revision: revision,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("reconciliation_open_response"))?;
        store_receipt(&transaction, OPEN_COMMAND, request, &response, now_ms)?;
        link_command_entity(
            &transaction,
            &request.request_id.to_string(),
            "case",
            &case_id,
            revision,
        )?;
        transaction.commit()?;
        Ok(response)
    }

    fn decide_reconciliation_case_impl(
        &self,
        request: &DecideReconciliationCaseV1Request,
    ) -> PlatformResult<DecideReconciliationCaseV1Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("reconciliation_decision_request"))?;
        if let Some(mut response) =
            replay_read::<_, DecideReconciliationCaseV1Response>(self, DECIDE_COMMAND, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            return Ok(response);
        }
        let now_ms = unix_now_ms()?;
        let case_id = request.case_id.to_string();
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, DecideReconciliationCaseV1Response>(&transaction, DECIDE_COMMAND, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let current_case_v2 = load_case_v2(&transaction, &case_id)?;
        require_current_authority(&current_case_v2)?;
        let current_case = current_case_v2.as_v1();
        if current_case.case_revision != request.expected_case_revision {
            return Err(PlatformError::Conflict("reconciliation_case_revision"));
        }
        validate_requested_outcome(&current_case, request)?;
        let case_revision = request
            .expected_case_revision
            .checked_add(1)
            .ok_or(PlatformError::Conflict("reconciliation_case_revision"))?;
        let revision = advance_reconciliation_revision(&transaction)?;
        let decision_id = stable_id("reconciliation-decision", &request.request_id.to_string());
        transaction.execute(
            "INSERT INTO reconciliation_decisions(
                decision_id, case_id, request_id, outcome,
                selected_candidate_id, expected_case_revision, case_revision,
                reconciliation_revision, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                decision_id,
                case_id,
                request.request_id.to_string(),
                outcome_db(request.outcome),
                request.selected_candidate_id.map(|id| id.to_string()),
                request.expected_case_revision as i64,
                case_revision as i64,
                revision as i64,
                now_ms
            ],
        )?;
        transaction.execute(
            "INSERT INTO reconciliation_decision_heads(
                case_id, decision_id, case_revision,
                reconciliation_revision, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(case_id) DO UPDATE SET
                decision_id = excluded.decision_id,
                case_revision = excluded.case_revision,
                reconciliation_revision = excluded.reconciliation_revision,
                updated_at_ms = excluded.updated_at_ms",
            params![
                case_id,
                decision_id,
                case_revision as i64,
                revision as i64,
                now_ms
            ],
        )?;
        let case = load_case(&transaction, &case_id)?;
        let decision = case
            .decision_head
            .clone()
            .ok_or(PlatformError::Corrupt("reconciliation_decision_head"))?;
        let response = DecideReconciliationCaseV1Response {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request.request_id,
            case,
            decision,
            reconciliation_revision: revision,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("reconciliation_decision_response"))?;
        store_receipt(&transaction, DECIDE_COMMAND, request, &response, now_ms)?;
        link_command_entity(
            &transaction,
            &request.request_id.to_string(),
            "decision",
            &decision_id,
            revision,
        )?;
        transaction.commit()?;
        Ok(response)
    }

    fn open_reconciliation_case_v2_impl(
        &self,
        request: &OpenReconciliationCaseV2Request,
    ) -> PlatformResult<OpenReconciliationCaseV2Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("reconciliation_open_request"))?;
        if let Some(mut response) =
            replay_read::<_, OpenReconciliationCaseV2Response>(self, OPEN_V2_COMMAND, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            return Ok(response);
        }

        let snapshot = self.load_proposal_snapshot_v2(request)?;
        let mut candidates = self.build_candidates(&snapshot)?;
        let case_id = reconciliation_case_id(&snapshot.pin);
        let no_match_id = stable_id("reconciliation-candidate", &format!("{case_id}:no-match"));
        candidates.push(ReconciliationCandidateV1 {
            candidate_id: parse_candidate_id(&no_match_id)?,
            target: ReconciliationCandidateTargetV1::NoMatch {},
            proposed_relation: None,
            observed_relations: Vec::new(),
            rank: None,
            display_name: "No match".to_owned(),
            detail: "Keep this photo observation unmatched".to_owned(),
            date: None,
            evidence: Vec::new(),
        });
        let leading_id = candidates[0].candidate_id;
        let observation_date = timestamp_from_ms(snapshot.pin.observation_created_at_ms)?;
        let now_ms = unix_now_ms()?;

        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) =
            replay::<_, OpenReconciliationCaseV2Response>(&transaction, OPEN_V2_COMMAND, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let current = load_proposal_snapshot_v2_from_connection(&transaction, request)?;
        let mut expected = snapshot.clone();
        expected.revisions.reconciliation = current.revisions.reconciliation;
        if current != expected {
            return Err(PlatformError::Conflict(
                "reconciliation_candidate_snapshot_changed",
            ));
        }

        let existing = find_existing_case(&transaction, &snapshot.pin)?;
        let revision = advance_reconciliation_revision(&transaction)?;
        if existing.is_none() {
            transaction.execute(
                "INSERT INTO reconciliation_cases(
                    case_id, observation_id, artifact_id, scope_id,
                    source_revision_id, source_revision_sha256, artifact_sha256,
                    photo_decision_id, photo_revision, owner_decision_id,
                    person_instance_id, owner_revision, owner_evidence_sha256,
                    catalog_revision, receipt_revision, retrieval_revision,
                    observation_date, leading_candidate_id, no_match_candidate_id,
                    case_revision, reconciliation_revision, created_at_ms
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                    ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, 1, ?20, ?21
                 )",
                params![
                    case_id,
                    snapshot.pin.observation_id,
                    snapshot.pin.artifact_id,
                    snapshot.pin.scope_id,
                    snapshot.pin.source_revision_id,
                    snapshot.pin.source_revision_sha256,
                    snapshot.pin.artifact_sha256,
                    snapshot.pin.photo_decision_id,
                    snapshot.pin.photo_revision as i64,
                    snapshot.pin.owner_decision_id,
                    snapshot.pin.person_instance_id,
                    snapshot.pin.owner_revision as i64,
                    snapshot.pin.owner_evidence_sha256,
                    snapshot.revisions.catalog as i64,
                    snapshot.revisions.receipt as i64,
                    RECONCILIATION_RETRIEVAL_REVISION_V1,
                    observation_date,
                    leading_id.to_string(),
                    no_match_id,
                    revision as i64,
                    now_ms
                ],
            )?;
            for candidate in &candidates {
                insert_candidate(&transaction, &case_id, candidate, revision, now_ms)?;
            }
        }
        let stored_case_id = existing.as_deref().unwrap_or(&case_id);
        let case = load_case_v2(&transaction, stored_case_id)?;
        require_current_authority(&case)?;
        let response = OpenReconciliationCaseV2Response {
            schema_version: RECONCILIATION_SCHEMA_VERSION_V2,
            request_id: request.request_id,
            case,
            evidence_generation: current.revisions.evidence_generation,
            photo_revision: current.revisions.photo,
            owner_revision: current.revisions.owner,
            reconciliation_revision: revision,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("reconciliation_open_response"))?;
        store_receipt(&transaction, OPEN_V2_COMMAND, request, &response, now_ms)?;
        link_command_entity(
            &transaction,
            &request.request_id.to_string(),
            "case",
            stored_case_id,
            revision,
        )?;
        transaction.commit()?;
        Ok(response)
    }

    fn decide_reconciliation_case_v2_impl(
        &self,
        request: &DecideReconciliationCaseV2Request,
    ) -> PlatformResult<DecideReconciliationCaseV2Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("reconciliation_decision_request"))?;
        if let Some(mut response) =
            replay_read::<_, DecideReconciliationCaseV2Response>(self, DECIDE_V2_COMMAND, request)?
        {
            response.replay_status = ReplayStatusV1::Replayed;
            return Ok(response);
        }
        let now_ms = unix_now_ms()?;
        let case_id = request.case_id.to_string();
        let mut connection = self.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(mut response) = replay::<_, DecideReconciliationCaseV2Response>(
            &transaction,
            DECIDE_V2_COMMAND,
            request,
        )? {
            response.replay_status = ReplayStatusV1::Replayed;
            transaction.commit()?;
            return Ok(response);
        }
        let revisions = load_revisions(&transaction)?;
        if revisions.photo != request.expected_photo_revision {
            return Err(PlatformError::Conflict("photo_revision_changed"));
        }
        if revisions.owner != request.expected_owner_revision {
            return Err(PlatformError::Conflict("owner_revision_changed"));
        }
        if revisions.reconciliation != request.expected_reconciliation_revision {
            return Err(PlatformError::Conflict("reconciliation_revision_changed"));
        }
        let current_case = load_case_v2(&transaction, &case_id)?;
        require_current_authority(&current_case)?;
        if current_case.case_revision != request.expected_case_revision {
            return Err(PlatformError::Conflict("reconciliation_case_revision"));
        }
        validate_requested_outcome_values(
            &current_case.as_v1(),
            request.case_id,
            request.outcome,
            request.selected_candidate_id,
            request.expected_case_revision,
        )?;
        let case_revision = request
            .expected_case_revision
            .checked_add(1)
            .ok_or(PlatformError::Conflict("reconciliation_case_revision"))?;
        let revision = advance_reconciliation_revision(&transaction)?;
        let decision_id = stable_id("reconciliation-decision", &request.request_id.to_string());
        insert_reconciliation_decision(
            &transaction,
            &decision_id,
            &case_id,
            &request.request_id.to_string(),
            request.outcome,
            request.selected_candidate_id,
            request.expected_case_revision,
            case_revision,
            revision,
            now_ms,
        )?;
        let case = load_case_v2(&transaction, &case_id)?;
        require_current_authority(&case)?;
        let decision = case
            .decision_head
            .clone()
            .ok_or(PlatformError::Corrupt("reconciliation_decision_head"))?;
        let response = DecideReconciliationCaseV2Response {
            schema_version: RECONCILIATION_SCHEMA_VERSION_V2,
            request_id: request.request_id,
            case,
            decision,
            photo_revision: revisions.photo,
            owner_revision: revisions.owner,
            reconciliation_revision: revision,
            replay_status: ReplayStatusV1::Created,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("reconciliation_decision_response"))?;
        store_receipt(&transaction, DECIDE_V2_COMMAND, request, &response, now_ms)?;
        link_command_entity(
            &transaction,
            &request.request_id.to_string(),
            "decision",
            &decision_id,
            revision,
        )?;
        transaction.commit()?;
        Ok(response)
    }

    fn list_reconciliation_cases_v2_impl(
        &self,
        request: &ListReconciliationCasesV2Request,
    ) -> PlatformResult<ListReconciliationCasesV2Response> {
        request
            .validate()
            .map_err(|_| PlatformError::InvalidInput("reconciliation_list_request"))?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let revisions = load_revisions(&transaction)?;
        let cursor = parse_reconciliation_cursor(request, &revisions)?;
        let observation_id = request.observation_id.to_string();
        let mut statement = transaction.prepare(
            "SELECT case_id, created_at_ms
             FROM reconciliation_cases
             WHERE observation_id = ?1
               AND (
                 ?2 IS NULL
                 OR created_at_ms < ?2
                 OR (created_at_ms = ?2 AND case_id < ?3)
               )
             ORDER BY created_at_ms DESC, case_id DESC",
        )?;
        let (last_created_at_ms, last_case_id) = cursor
            .as_ref()
            .map(|cursor| {
                (
                    Some(cursor.last_created_at_ms as i64),
                    Some(cursor.last_case_id.as_str()),
                )
            })
            .unwrap_or((None, None));
        let rows = statement.query_map(
            params![observation_id, last_created_at_ms, last_case_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?;
        let mut cases = Vec::with_capacity(usize::from(request.limit));
        let mut has_more = false;
        for row in rows {
            let (case_id, _) = row?;
            let case = load_case_v2(&transaction, &case_id)?;
            if !case.matches_filter(request.state) {
                continue;
            }
            if cases.len() == usize::from(request.limit) {
                has_more = true;
                break;
            }
            cases.push(case);
        }
        let next_cursor = if has_more {
            cases
                .last()
                .map(|case| make_reconciliation_cursor(request, &revisions, case))
                .transpose()?
        } else {
            None
        };
        let response = ListReconciliationCasesV2Response {
            schema_version: RECONCILIATION_SCHEMA_VERSION_V2,
            request_id: request.request_id,
            observation_id: request.observation_id,
            state: request.state,
            cases,
            next_cursor,
            photo_revision: revisions.photo,
            owner_revision: revisions.owner,
            reconciliation_revision: revisions.reconciliation,
        };
        response
            .validate()
            .map_err(|_| PlatformError::Corrupt("reconciliation_list_response"))?;
        drop(statement);
        transaction.commit()?;
        Ok(response)
    }

    fn load_proposal_snapshot(
        &self,
        request: &OpenReconciliationCaseV1Request,
    ) -> PlatformResult<ProposalSnapshot> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let snapshot = load_proposal_snapshot_from_connection(&transaction, request)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    fn load_proposal_snapshot_v2(
        &self,
        request: &OpenReconciliationCaseV2Request,
    ) -> PlatformResult<ProposalSnapshot> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let snapshot = load_proposal_snapshot_v2_from_connection(&transaction, request)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    fn build_candidates(
        &self,
        snapshot: &ProposalSnapshot,
    ) -> PlatformResult<Vec<ReconciliationCandidateV1>> {
        verify_photo_pin(&snapshot.pin)?;
        let store = BlobStore::new(&self.paths);
        let photo =
            verify_source_image(&store, &snapshot.pin.blob_sha256, snapshot.pin.byte_length)
                .map_err(|_| PlatformError::Corrupt("reconciliation_photo_blob"))?;
        if photo.media_type != snapshot.pin.media_type
            || photo.width != snapshot.pin.width
            || photo.height != snapshot.pin.height
        {
            return Err(PlatformError::Corrupt("reconciliation_photo_dimensions"));
        }
        let photo_features = extract_local_visual_features_v1(&photo, snapshot.pin.rectangle)?;
        let artifact_digest = parse_digest(&snapshot.pin.artifact_sha256)?;
        let observation_date = timestamp_from_ms(snapshot.pin.observation_created_at_ms)?;
        let mut wardrobe = snapshot
            .catalog
            .iter()
            .map(|item| {
                build_wardrobe_candidate(
                    &store,
                    &snapshot.pin,
                    item,
                    photo_features,
                    &artifact_digest,
                )
            })
            .collect::<PlatformResult<Vec<_>>>()?;
        wardrobe.sort_by(|left, right| {
            match (left.visual_sort, right.visual_sort) {
                (Some(left), Some(right)) => left.cmp(&right),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
            .then_with(|| right.updated_revision.cmp(&left.updated_revision))
            .then_with(|| left.target_id.cmp(&right.target_id))
        });
        wardrobe.truncate(3);
        let mut receipts = snapshot
            .receipts
            .iter()
            .map(|receipt| {
                build_receipt_candidate(receipt, &snapshot.pin.artifact_id, &observation_date)
            })
            .collect::<PlatformResult<Vec<_>>>()?;
        receipts.sort_by(|left, right| {
            left.receipt_is_return
                .cmp(&right.receipt_is_return)
                .then_with(|| right.receipt_date.cmp(&left.receipt_date))
                .then_with(|| left.receipt_created_at_ms.cmp(&right.receipt_created_at_ms))
                .then_with(|| left.target_id.cmp(&right.target_id))
        });
        receipts.truncate(3);
        wardrobe.extend(receipts);
        for (index, ranked) in wardrobe.iter_mut().enumerate() {
            ranked.candidate.rank = Some((index + 1) as u8);
        }
        Ok(wardrobe
            .into_iter()
            .map(|ranked| ranked.candidate)
            .collect())
    }
}

fn load_proposal_snapshot_from_connection(
    connection: &Connection,
    request: &OpenReconciliationCaseV1Request,
) -> PlatformResult<ProposalSnapshot> {
    let revisions = load_revisions(connection)?;
    if revisions.photo != request.expected_photo_revision {
        return Err(PlatformError::Conflict("photo_revision_changed"));
    }
    Ok(ProposalSnapshot {
        revisions,
        pin: load_photo_pin(
            connection,
            &request.observation_id.to_string(),
            &request.selected_artifact_id.to_string(),
        )?,
        catalog: load_catalog_snapshots(connection)?,
        receipts: load_receipt_snapshots(connection)?,
    })
}

fn load_proposal_snapshot_v2_from_connection(
    connection: &Connection,
    request: &OpenReconciliationCaseV2Request,
) -> PlatformResult<ProposalSnapshot> {
    let revisions = load_revisions(connection)?;
    if revisions.photo != request.expected_photo_revision {
        return Err(PlatformError::Conflict("photo_revision_changed"));
    }
    if revisions.owner != request.expected_owner_revision {
        return Err(PlatformError::Conflict("owner_revision_changed"));
    }
    Ok(ProposalSnapshot {
        revisions,
        pin: load_photo_pin(
            connection,
            &request.observation_id.to_string(),
            &request.selected_artifact_id.to_string(),
        )?,
        catalog: load_catalog_snapshots(connection)?,
        receipts: load_receipt_snapshots(connection)?,
    })
}

fn load_revisions(connection: &Connection) -> PlatformResult<Revisions> {
    let values = connection.query_row(
        "SELECT catalog_revision, evidence_generation, receipt_revision,
                photo_revision, owner_revision, reconciliation_revision
         FROM revision_state WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        },
    )?;
    Ok(Revisions {
        catalog: to_u64(values.0, "catalog_revision")?,
        evidence_generation: to_u64(values.1, "evidence_generation")?,
        receipt: to_u64(values.2, "receipt_revision")?,
        photo: to_u64(values.3, "photo_revision")?,
        owner: to_u64(values.4, "owner_revision")?,
        reconciliation: to_u64(values.5, "reconciliation_revision")?,
    })
}

fn load_photo_pin(
    connection: &Connection,
    observation_id: &str,
    artifact_id: &str,
) -> PlatformResult<PhotoPin> {
    let row = connection
        .query_row(
            "SELECT observation.scope_id, observation.source_revision_id,
                    observation.created_at_ms, head.decision_id,
                    head.photo_revision, artifact.source_revision_sha256,
                    artifact.input_blob_sha256, source.byte_length,
                    artifact.media_type, artifact.source_width,
                    artifact.source_height, artifact.artifact_kind,
                    artifact.rectangle_x, artifact.rectangle_y,
                    artifact.rectangle_width, artifact.rectangle_height,
                    artifact.artifact_revision, artifact.preprocessing_revision,
                    artifact.provenance_json, artifact.provenance_sha256,
                    artifact.artifact_sha256, owner_link.owner_decision_id,
                    owner_link.person_instance_id, owner_link.owner_revision,
                    owner_link.evidence_sha256
             FROM photo_observations observation
             JOIN photo_review_heads head
               ON head.observation_id = observation.observation_id
             JOIN photo_artifacts artifact
               ON artifact.artifact_id = head.current_artifact_id
              AND artifact.scope_id = observation.scope_id
              AND artifact.source_revision_id = observation.source_revision_id
             JOIN photo_source_revisions source
               ON source.source_revision_id = observation.source_revision_id
             JOIN photo_observation_owner_links owner_link
               ON owner_link.observation_id = observation.observation_id
              AND owner_link.scope_id = observation.scope_id
              AND owner_link.source_revision_id = observation.source_revision_id
             JOIN photo_owner_heads owner_head
               ON owner_head.source_revision_id = observation.source_revision_id
              AND owner_head.owner_decision_id = owner_link.owner_decision_id
              AND owner_head.selected_person_instance_id =
                  owner_link.person_instance_id
              AND owner_head.owner_revision = owner_link.owner_revision
              AND owner_head.action = 'select_person'
             WHERE observation.observation_id = ?1
               AND head.current_artifact_id = ?2
               AND head.state IN ('confirmed', 'replaced')
               AND source.disposition = 'eligible'",
            params![observation_id, artifact_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Option<i64>>(14)?,
                    row.get::<_, Option<i64>>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, String>(17)?,
                    row.get::<_, String>(18)?,
                    row.get::<_, String>(19)?,
                    row.get::<_, String>(20)?,
                    row.get::<_, String>(21)?,
                    row.get::<_, String>(22)?,
                    row.get::<_, i64>(23)?,
                    row.get::<_, String>(24)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput(
            "reconciliation_photo_review_state",
        ))?;
    let width = to_u32(row.9, "photo_width")?;
    let height = to_u32(row.10, "photo_height")?;
    let artifact_kind = artifact_kind_from_db(&row.11)?;
    let rectangle = match artifact_kind {
        PhotoArtifactKindV1::RectangleSourceCrop => (
            optional_u32(row.12, "photo_rectangle_x")?,
            optional_u32(row.13, "photo_rectangle_y")?,
            optional_u32(row.14, "photo_rectangle_width")?,
            optional_u32(row.15, "photo_rectangle_height")?,
        ),
        PhotoArtifactKindV1::SourceImageReference => (0, 0, width, height),
    };
    if source_revision_hash(connection, &row.1)?.as_str() != row.5 {
        return Err(PlatformError::Corrupt(
            "reconciliation_photo_source_revision_hash",
        ));
    }
    Ok(PhotoPin {
        observation_id: observation_id.to_owned(),
        artifact_id: artifact_id.to_owned(),
        scope_id: row.0,
        source_revision_id: row.1,
        observation_created_at_ms: row.2,
        photo_decision_id: row.3,
        photo_revision: to_u64(row.4, "photo_revision")?,
        owner_decision_id: row.21,
        person_instance_id: row.22,
        owner_revision: to_u64(row.23, "owner_revision")?,
        owner_evidence_sha256: row.24,
        source_revision_sha256: row.5,
        blob_sha256: row.6,
        byte_length: to_u64(row.7, "photo_byte_length")?,
        media_type: media_type_from_db(&row.8)?,
        width,
        height,
        artifact_kind,
        rectangle,
        artifact_revision: row.16,
        preprocessing_revision: row.17,
        provenance_json: row.18,
        provenance_sha256: row.19,
        artifact_sha256: row.20,
    })
}

fn source_revision_hash(
    connection: &Connection,
    source_revision_id: &str,
) -> PlatformResult<Sha256Digest> {
    let row = connection.query_row(
        "SELECT source_id, root_id, scan_id, manifest_generation,
                source_identity_key_sha256, provenance_row_sha256,
                raw_sha256, blob_sha256, byte_length, media_type,
                width, height, disposition, quarantine_reason
         FROM photo_source_revisions WHERE source_revision_id = ?1",
        [source_revision_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<i64>>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, Option<String>>(13)?,
            ))
        },
    )?;
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
        media_type: Option<&'a str>,
        width: Option<u32>,
        height: Option<u32>,
        disposition: &'a str,
        quarantine_reason: Option<&'a str>,
    }
    canonical_hash(
        b"wardrobe.photo.source-revision.v1",
        &SourceRevisionHashRecord {
            schema_revision: "photo-source-revision-v1",
            source_id: &row.0,
            root_id: &row.1,
            scan_id: &row.2,
            manifest_generation: to_u64(row.3, "photo_manifest_generation")?,
            source_identity_key_sha256: &row.4,
            provenance_row_sha256: &row.5,
            raw_sha256: row.6.as_deref(),
            blob_sha256: row.7.as_deref(),
            byte_length: row
                .8
                .map(|value| to_u64(value, "photo_byte_length"))
                .transpose()?,
            media_type: row.9.as_deref(),
            width: row
                .10
                .map(|value| to_u32(value, "photo_width"))
                .transpose()?,
            height: row
                .11
                .map(|value| to_u32(value, "photo_height"))
                .transpose()?,
            disposition: &row.12,
            quarantine_reason: row.13.as_deref(),
        },
    )
}

fn verify_photo_pin(pin: &PhotoPin) -> PlatformResult<()> {
    if pin.preprocessing_revision != PHOTO_PREPROCESSING_REVISION_V1
        || pin.artifact_revision
            != match pin.artifact_kind {
                PhotoArtifactKindV1::RectangleSourceCrop => RECTANGLE_SOURCE_CROP_REVISION_V1,
                PhotoArtifactKindV1::SourceImageReference => SOURCE_IMAGE_REFERENCE_REVISION_V1,
            }
        || format!("{:x}", Sha256::digest(pin.provenance_json.as_bytes())) != pin.provenance_sha256
    {
        return Err(PlatformError::Corrupt("reconciliation_photo_provenance"));
    }
    #[derive(Serialize)]
    struct ArtifactHashRecord<'a> {
        artifact_schema_revision: &'static str,
        artifact_kind: &'static str,
        provenance_sha256: &'a str,
        rectangle: Option<wardrobe_core::RectV1>,
    }
    let rectangle = match pin.artifact_kind {
        PhotoArtifactKindV1::RectangleSourceCrop => Some(wardrobe_core::RectV1 {
            x: pin.rectangle.0,
            y: pin.rectangle.1,
            width: pin.rectangle.2,
            height: pin.rectangle.3,
        }),
        PhotoArtifactKindV1::SourceImageReference => None,
    };
    let expected = canonical_hash(
        b"wardrobe.photo.artifact.v1",
        &ArtifactHashRecord {
            artifact_schema_revision: PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
            artifact_kind: artifact_kind_db(pin.artifact_kind),
            provenance_sha256: &pin.provenance_sha256,
            rectangle,
        },
    )?;
    if expected.as_str() != pin.artifact_sha256 {
        return Err(PlatformError::Corrupt("reconciliation_photo_artifact_hash"));
    }
    Ok(())
}

fn load_catalog_snapshots(connection: &Connection) -> PlatformResult<Vec<CatalogSnapshot>> {
    let mut statement = connection.prepare(
        "SELECT item.item_id, item.attributes_json, item.updated_revision,
                decision.decision_id, decision.catalog_revision,
                decision.created_at_ms
         FROM catalog_items item
         JOIN decision_entities entity
           ON entity.entity_kind = 'item' AND entity.entity_id = item.item_id
         JOIN catalog_decisions decision
           ON decision.decision_id = entity.decision_id
         WHERE item.active = 1
           AND decision.catalog_revision = (
             SELECT MIN(inner_decision.catalog_revision)
             FROM decision_entities inner_entity
             JOIN catalog_decisions inner_decision
               ON inner_decision.decision_id = inner_entity.decision_id
             WHERE inner_entity.entity_kind = 'item'
               AND inner_entity.entity_id = item.item_id
           )
         ORDER BY item.updated_revision DESC, item.item_id LIMIT ?1",
    )?;
    let rows = statement
        .query_map([MAX_POOL_SIZE], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|row| {
            let attributes: ItemAttributesV1 = serde_json::from_str(&row.1)
                .map_err(|_| PlatformError::Corrupt("catalog_attributes"))?;
            attributes
                .validate()
                .map_err(|_| PlatformError::Corrupt("catalog_attributes"))?;
            Ok(CatalogSnapshot {
                image: load_catalog_image(connection, &row.0)?,
                item_id: row.0,
                attributes_json: row.1,
                updated_revision: to_u64(row.2, "catalog_revision")?,
                creation_decision_id: row.3,
                creation_revision: to_u64(row.4, "catalog_revision")?,
                creation_at_ms: row.5,
            })
        })
        .collect()
}

fn load_catalog_image(
    connection: &Connection,
    item_id: &str,
) -> PlatformResult<Option<CatalogImageSnapshot>> {
    connection
        .query_row(
            "SELECT evidence.evidence_id, assignment.assigned_revision,
                    source.blob_sha256, source.raw_sha256,
                    source.byte_length, source.media_type, source.status
             FROM item_evidence assignment
             JOIN evidence ON evidence.evidence_id = assignment.evidence_id
             JOIN local_sources source ON source.source_id = evidence.source_id
             WHERE assignment.item_id = ?1
               AND evidence.evidence_kind = 'image'
               AND evidence.state = 'assigned'
             ORDER BY assignment.assigned_revision DESC,
                      evidence.updated_at_ms DESC, evidence.evidence_id DESC
             LIMIT 1",
            [item_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            let provenance_sha256 = row.2.clone().or(row.3).unwrap_or_else(|| {
                format!("{:x}", Sha256::digest(format!("catalog-image:{}", row.0)))
            });
            Ok(CatalogImageSnapshot {
                evidence_id: row.0,
                assigned_revision: to_u64(row.1, "catalog_revision")?,
                blob_sha256: row.2,
                provenance_sha256,
                byte_length: row
                    .4
                    .map(|value| to_u64(value, "catalog_image_length"))
                    .transpose()?,
                media_type: row
                    .5
                    .as_deref()
                    .and_then(|value| media_type_from_db(value).ok()),
                source_status: row.6,
            })
        })
        .transpose()
}

fn load_receipt_snapshots(connection: &Connection) -> PlatformResult<Vec<ReceiptSnapshot>> {
    let mut statement = connection.prepare(
        "SELECT orders.order_evidence_id, line.order_line_id,
                variant.variant_evidence_id, orders.created_at_ms,
                decision.review_decision_id, decision.action,
                decision.reviewed_order_json, decision.receipt_revision,
                run.output_sha256, run.provider_revision
         FROM receipt_review_heads head
         JOIN receipt_review_decisions decision
           ON decision.review_decision_id = head.review_decision_id
         JOIN receipt_orders orders
           ON orders.order_evidence_id = head.order_evidence_id
         JOIN receipt_extraction_runs run ON run.run_id = orders.run_id
         JOIN receipt_order_lines line
           ON line.order_evidence_id = orders.order_evidence_id
         JOIN receipt_variant_evidence variant
           ON variant.order_line_id = line.order_line_id
         LEFT JOIN receipt_fields purchase
           ON purchase.order_evidence_id = orders.order_evidence_id
          AND purchase.field_name = 'purchase_date'
         LEFT JOIN receipt_fields event
           ON event.order_line_id = line.order_line_id
          AND event.field_name = 'event_kind'
         WHERE decision.action IN ('confirm', 'correct')
           AND run.status = 'succeeded'
         ORDER BY
           CASE COALESCE(
             CASE WHEN decision.action = 'correct'
                  THEN json_extract(
                    decision.reviewed_order_json,
                    '$.line_items[' || line.ordinal || '].event_kind'
                  )
                  ELSE event.value_text END, ''
           ) WHEN 'return' THEN 1 ELSE 0 END,
           COALESCE(
             CASE WHEN decision.action = 'correct'
                  THEN json_extract(decision.reviewed_order_json, '$.purchase_date')
                  ELSE purchase.value_text END, ''
           ) DESC,
           orders.created_at_ms, line.order_line_id
         LIMIT ?1",
    )?;
    let rows = statement
        .query_map([MAX_POOL_SIZE], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut corrected_cache = BTreeMap::new();
    let mut snapshots = Vec::with_capacity(rows.len());
    for row in rows {
        let merchant = load_field(connection, "order", &row.0, "merchant")?;
        let purchase_date = load_field(connection, "order", &row.0, "purchase_date")?;
        let description = load_field(connection, "line", &row.1, "description")?;
        let event = load_field(connection, "line", &row.1, "event_kind")?;
        let brand = load_field(connection, "variant", &row.2, "brand")?;
        let sku = load_field(connection, "variant", &row.2, "sku")?;
        let size = load_field(connection, "variant", &row.2, "size")?;
        let color = load_field(connection, "variant", &row.2, "color")?;
        if row.5 == "correct" && !corrected_cache.contains_key(&row.0) {
            let json = row
                .6
                .as_ref()
                .ok_or(PlatformError::Corrupt("corrected_receipt_missing"))?;
            let corrected: CorrectedReceiptOrderV1 = serde_json::from_str(json)
                .map_err(|_| PlatformError::Corrupt("corrected_receipt_json"))?;
            corrected
                .validate()
                .map_err(|_| PlatformError::Corrupt("corrected_receipt_validation"))?;
            validate_corrected_receipt_ids(connection, &row.0, &corrected)?;
            corrected_cache.insert(row.0.clone(), corrected);
        }
        let corrected = corrected_cache.get(&row.0);
        let corrected_line = corrected.and_then(|order| {
            order
                .line_items
                .iter()
                .find(|line| line.order_line_id.to_string() == row.1)
        });
        if corrected.is_some() && corrected_line.is_none() {
            return Err(PlatformError::Corrupt("corrected_receipt_line_id"));
        }
        snapshots.push(ReceiptSnapshot {
            order_id: row.0,
            order_line_id: row.1,
            variant_id: row.2,
            order_created_at_ms: row.3,
            review_decision_id: row.4,
            review_action: row.5,
            reviewed_order_json: row.6,
            receipt_revision: to_u64(row.7, "receipt_revision")?,
            output_sha256: row.8,
            provider_revision: row.9,
            authoritative_merchant: corrected
                .map(|order| order.merchant.clone())
                .unwrap_or_else(|| merchant.value_text.clone()),
            authoritative_purchase_date: corrected
                .map(|order| order.purchase_date.clone())
                .unwrap_or_else(|| purchase_date.value_text.clone()),
            authoritative_description: corrected_line
                .map(|line| line.description.clone())
                .unwrap_or_else(|| description.value_text.clone()),
            authoritative_event: corrected_line
                .map(|line| line.event_kind)
                .unwrap_or_else(|| event.value_text.as_deref().and_then(event_kind_from_db)),
            authoritative_brand: corrected_line
                .map(|line| line.variant.brand.clone())
                .unwrap_or_else(|| brand.value_text.clone()),
            authoritative_sku: corrected_line
                .map(|line| line.variant.sku.clone())
                .unwrap_or_else(|| sku.value_text.clone()),
            authoritative_size: corrected_line
                .map(|line| line.variant.size.clone())
                .unwrap_or_else(|| size.value_text.clone()),
            authoritative_color: corrected_line
                .map(|line| line.variant.color.clone())
                .unwrap_or_else(|| color.value_text.clone()),
            merchant_field: merchant,
            purchase_date_field: purchase_date,
            description_field: description,
            event_field: event,
        });
    }
    Ok(snapshots)
}

fn load_field(
    connection: &Connection,
    owner_kind: &str,
    owner_id: &str,
    field_name: &str,
) -> PlatformResult<FieldSnapshot> {
    let owner_column = match owner_kind {
        "order" => "order_evidence_id",
        "line" => "order_line_id",
        "variant" => "variant_evidence_id",
        _ => return Err(PlatformError::Corrupt("receipt_field_owner")),
    };
    let sql = format!(
        "SELECT field_id, value_kind, value_text, value_integer, is_known
         FROM receipt_fields WHERE {owner_column} = ?1 AND field_name = ?2"
    );
    let row = connection
        .query_row(&sql, params![owner_id, field_name], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .optional()?
        .ok_or(PlatformError::Corrupt("receipt_field_missing"))?;
    let mut citations = connection.prepare(
        "SELECT fragment_id, byte_start, byte_end, quote_sha256
         FROM receipt_field_citations WHERE field_id = ?1
         ORDER BY citation_ordinal",
    )?;
    let citations = citations
        .query_map([&row.0], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .map(|row| {
            let row = row?;
            Ok((
                row.0,
                to_u32(row.1, "receipt_citation")?,
                to_u32(row.2, "receipt_citation")?,
                row.3,
            ))
        })
        .collect::<PlatformResult<Vec<_>>>()?;
    Ok(FieldSnapshot {
        field_id: row.0,
        value_kind: row.1,
        value_text: row.2,
        value_integer: row
            .3
            .map(|value| to_u64(value, "receipt_field_value"))
            .transpose()?,
        is_known: row.4 == 1,
        citations,
    })
}

fn validate_corrected_receipt_ids(
    connection: &Connection,
    order_id: &str,
    corrected: &CorrectedReceiptOrderV1,
) -> PlatformResult<()> {
    if corrected.order_evidence_id.to_string() != order_id {
        return Err(PlatformError::Corrupt("corrected_receipt_order_id"));
    }
    let mut statement = connection.prepare(
        "SELECT line.order_line_id, variant.variant_evidence_id
         FROM receipt_order_lines line
         JOIN receipt_variant_evidence variant
           ON variant.order_line_id = line.order_line_id
         WHERE line.order_evidence_id = ?1 ORDER BY line.ordinal",
    )?;
    let stored = statement
        .query_map([order_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let corrected_ids = corrected
        .line_items
        .iter()
        .map(|line| {
            (
                line.order_line_id.to_string(),
                line.variant.variant_evidence_id.to_string(),
            )
        })
        .collect::<Vec<_>>();
    if stored != corrected_ids {
        return Err(PlatformError::Corrupt("corrected_receipt_entity_ids"));
    }
    Ok(())
}

fn build_wardrobe_candidate(
    store: &BlobStore,
    pin: &PhotoPin,
    item: &CatalogSnapshot,
    photo_features: LocalVisualFeaturesV1,
    artifact_digest: &Sha256Digest,
) -> PlatformResult<RankedCandidate> {
    let attributes: ItemAttributesV1 = serde_json::from_str(&item.attributes_json)
        .map_err(|_| PlatformError::Corrupt("catalog_attributes"))?;
    let candidate_id = stable_id(
        "reconciliation-candidate",
        &format!(
            "{}:{}:item:{}",
            pin.observation_id, pin.artifact_id, item.item_id
        ),
    );
    let mut evidence = Vec::new();
    let mut observed_relations = Vec::new();
    let mut visual_sort = None;
    match &item.image {
        None => evidence.push(catalog_status_evidence(
            &candidate_id,
            &item.creation_decision_id,
            &item.creation_revision.to_string(),
            Sha256Digest::from_bytes(item.attributes_json.as_bytes()),
            EVIDENCE_VALUE_CATALOG_IMAGE_ABSENT_V1,
            CandidateEvidenceSourceKindV1::CatalogDecision,
        )?),
        Some(image) => {
            let source_digest = parse_digest(&image.provenance_sha256)?;
            let status = match (
                image.source_status.as_str(),
                image.blob_sha256.as_deref(),
                image.byte_length,
            ) {
                ("imported", Some(blob_sha256), Some(byte_length)) => {
                    match verify_source_image(store, blob_sha256, byte_length) {
                        Ok(local_image)
                            if image
                                .media_type
                                .is_none_or(|expected| expected == local_image.media_type) =>
                        {
                            match extract_local_visual_features_v1(
                                &local_image,
                                (0, 0, local_image.width, local_image.height),
                            ) {
                                Ok(features) => {
                                    let (hash_distance, color_distance) =
                                        photo_features.distances(features);
                                    visual_sort = Some((hash_distance, color_distance));
                                    observed_relations.push(IdentityRelationV1::VisualSimilarity);
                                    evidence.push(measured_visual_evidence(
                                        &candidate_id,
                                        image,
                                        CandidateEvidenceFeatureV1::DifferenceHashDistance,
                                        u16::from(hash_distance),
                                        artifact_digest,
                                    )?);
                                    evidence.push(measured_visual_evidence(
                                        &candidate_id,
                                        image,
                                        CandidateEvidenceFeatureV1::MeanColorDistance,
                                        color_distance,
                                        artifact_digest,
                                    )?);
                                    None
                                }
                                Err(_) => Some(EVIDENCE_VALUE_CATALOG_IMAGE_CORRUPT_V1),
                            }
                        }
                        Err(wardrobe_core::PhotoQuarantineReasonV1::BlobUnavailable) => {
                            Some(EVIDENCE_VALUE_CATALOG_IMAGE_UNAVAILABLE_V1)
                        }
                        Ok(_) | Err(_) => Some(EVIDENCE_VALUE_CATALOG_IMAGE_CORRUPT_V1),
                    }
                }
                _ => Some(EVIDENCE_VALUE_CATALOG_IMAGE_UNAVAILABLE_V1),
            };
            if let Some(value_code) = status {
                evidence.push(catalog_status_evidence(
                    &candidate_id,
                    &image.evidence_id,
                    &format!("assigned-revision-{}", image.assigned_revision),
                    source_digest,
                    value_code,
                    CandidateEvidenceSourceKindV1::CatalogImageEvidence,
                )?);
            }
        }
    }
    let candidate = ReconciliationCandidateV1 {
        candidate_id: parse_candidate_id(&candidate_id)?,
        target: ReconciliationCandidateTargetV1::WardrobeItem {
            item_id: parse_item_id(&item.item_id)?,
        },
        proposed_relation: Some(IdentityRelationV1::SamePhysicalItem),
        observed_relations,
        rank: Some(1),
        display_name: attributes.display_name.clone(),
        detail: bounded_text(&catalog_detail(&attributes), 240),
        date: Some(ReconciliationCandidateDateV1 {
            kind: ReconciliationCandidateDateKindV1::CatalogCreated,
            value: timestamp_from_ms(item.creation_at_ms)?,
        }),
        evidence,
    };
    candidate
        .validate()
        .map_err(|_| PlatformError::Corrupt("reconciliation_catalog_candidate"))?;
    Ok(RankedCandidate {
        candidate,
        visual_sort,
        updated_revision: item.updated_revision,
        target_id: item.item_id.clone(),
        receipt_is_return: false,
        receipt_date: None,
        receipt_created_at_ms: 0,
    })
}

fn measured_visual_evidence(
    candidate_id: &str,
    image: &CatalogImageSnapshot,
    feature: CandidateEvidenceFeatureV1,
    measured: u16,
    artifact_digest: &Sha256Digest,
) -> PlatformResult<CandidateEvidenceV1> {
    let polarity = match feature {
        CandidateEvidenceFeatureV1::DifferenceHashDistance => match measured {
            0..=8 => CandidateEvidencePolarityV1::Supporting,
            9..=23 => CandidateEvidencePolarityV1::Neutral,
            _ => CandidateEvidencePolarityV1::Contradictory,
        },
        CandidateEvidenceFeatureV1::MeanColorDistance => match measured {
            0..=48 => CandidateEvidencePolarityV1::Supporting,
            49..=191 => CandidateEvidencePolarityV1::Neutral,
            _ => CandidateEvidencePolarityV1::Contradictory,
        },
        _ => return Err(PlatformError::Corrupt("reconciliation_visual_feature")),
    };
    let evidence_id = stable_id(
        "reconciliation-evidence",
        &format!("{candidate_id}:{}", feature_db(feature)),
    );
    Ok(CandidateEvidenceV1 {
        evidence_id: parse_evidence_id(&evidence_id)?,
        polarity,
        relation: IdentityRelationV1::VisualSimilarity,
        feature,
        source_kind: CandidateEvidenceSourceKindV1::CatalogImageEvidence,
        source_id: parse_source_id(&image.evidence_id)?,
        source_revision: format!("assigned-revision-{}", image.assigned_revision),
        input_sha256: vec![
            artifact_digest.clone(),
            parse_digest(
                image
                    .blob_sha256
                    .as_deref()
                    .ok_or(PlatformError::Corrupt("catalog_image_hash"))?,
            )?,
        ],
        extractor_id: LOCAL_VISUAL_FEATURE_EXTRACTOR_ID_V1.to_owned(),
        extractor_revision: LOCAL_VISUAL_FEATURE_EXTRACTOR_REVISION_V1.to_owned(),
        value_code: EVIDENCE_VALUE_MEASURED_V1.to_owned(),
        measured_value: Some(measured),
    })
}

fn catalog_status_evidence(
    candidate_id: &str,
    source_id: &str,
    source_revision: &str,
    input_sha256: Sha256Digest,
    value_code: &str,
    source_kind: CandidateEvidenceSourceKindV1,
) -> PlatformResult<CandidateEvidenceV1> {
    let evidence_id = stable_id(
        "reconciliation-evidence",
        &format!("{candidate_id}:catalog-image-status"),
    );
    Ok(CandidateEvidenceV1 {
        evidence_id: parse_evidence_id(&evidence_id)?,
        polarity: CandidateEvidencePolarityV1::Neutral,
        relation: IdentityRelationV1::VisualSimilarity,
        feature: CandidateEvidenceFeatureV1::CatalogImageStatus,
        source_kind,
        source_id: parse_source_id(source_id)?,
        source_revision: source_revision.to_owned(),
        input_sha256: vec![input_sha256],
        extractor_id: LOCAL_VISUAL_FEATURE_EXTRACTOR_ID_V1.to_owned(),
        extractor_revision: LOCAL_VISUAL_FEATURE_EXTRACTOR_REVISION_V1.to_owned(),
        value_code: value_code.to_owned(),
        measured_value: None,
    })
}

fn build_receipt_candidate(
    receipt: &ReceiptSnapshot,
    artifact_id: &str,
    observation_date: &str,
) -> PlatformResult<RankedCandidate> {
    let candidate_id = stable_id(
        "reconciliation-candidate",
        &format!("{artifact_id}:receipt-line:{}", receipt.order_line_id),
    );
    let output_digest = parse_digest(&receipt.output_sha256)?;
    let reviewed_digest = receipt
        .reviewed_order_json
        .as_ref()
        .map(|json| Sha256Digest::from_bytes(json.as_bytes()));
    let source_revision = receipt_source_revision(receipt);
    let mut review_inputs = vec![output_digest];
    if let Some(digest) = &reviewed_digest {
        review_inputs.push(digest.clone());
    }
    let mut evidence = vec![receipt_evidence(
        &candidate_id,
        CandidateEvidenceFeatureV1::ReceiptReviewState,
        CandidateEvidencePolarityV1::Neutral,
        CandidateEvidenceSourceKindV1::ReceiptReviewDecision,
        &receipt.review_decision_id,
        &source_revision,
        review_inputs,
        if receipt.review_action == "correct" {
            EVIDENCE_VALUE_RECEIPT_CORRECTED_V1
        } else {
            EVIDENCE_VALUE_RECEIPT_CONFIRMED_V1
        },
    )?];
    let event_code = match receipt.authoritative_event {
        Some(ReceiptEventKindV1::Purchase) => EVIDENCE_VALUE_EVENT_PURCHASE_V1,
        Some(ReceiptEventKindV1::Exchange) => EVIDENCE_VALUE_EVENT_EXCHANGE_V1,
        Some(ReceiptEventKindV1::Return) => EVIDENCE_VALUE_EVENT_RETURN_V1,
        None => EVIDENCE_VALUE_EVENT_UNKNOWN_V1,
    };
    evidence.push(receipt_evidence(
        &candidate_id,
        CandidateEvidenceFeatureV1::ReceiptEventKind,
        if receipt.authoritative_event == Some(ReceiptEventKindV1::Return) {
            CandidateEvidencePolarityV1::Contradictory
        } else {
            CandidateEvidencePolarityV1::Neutral
        },
        CandidateEvidenceSourceKindV1::ReceiptField,
        &receipt.event_field.field_id,
        &source_revision,
        field_inputs(&receipt.event_field, reviewed_digest.as_ref()),
        event_code,
    )?);
    let observation_day = &observation_date[..10];
    let chronology_code = match receipt.authoritative_purchase_date.as_deref() {
        Some(date) if date > observation_day => EVIDENCE_VALUE_PURCHASE_AFTER_OBSERVATION_V1,
        Some(_) => EVIDENCE_VALUE_PURCHASE_BEFORE_OBSERVATION_V1,
        None => EVIDENCE_VALUE_PURCHASE_DATE_UNKNOWN_V1,
    };
    evidence.push(receipt_evidence(
        &candidate_id,
        CandidateEvidenceFeatureV1::PurchaseChronology,
        if chronology_code == EVIDENCE_VALUE_PURCHASE_AFTER_OBSERVATION_V1 {
            CandidateEvidencePolarityV1::Contradictory
        } else {
            CandidateEvidencePolarityV1::Neutral
        },
        CandidateEvidenceSourceKindV1::ReceiptField,
        &receipt.purchase_date_field.field_id,
        &source_revision,
        field_inputs(&receipt.purchase_date_field, reviewed_digest.as_ref()),
        chronology_code,
    )?);
    let provenance_code = if receipt.review_action != "correct" {
        EVIDENCE_VALUE_EXTRACTED_RECEIPT_V1
    } else {
        match (
            receipt.description_field.value_text.as_ref(),
            receipt.authoritative_description.as_ref(),
        ) {
            (_, None) => EVIDENCE_VALUE_CORRECTED_UNKNOWN_V1,
            (Some(extracted), Some(corrected)) if extracted == corrected => {
                EVIDENCE_VALUE_CORRECTED_UNCHANGED_V1
            }
            _ => EVIDENCE_VALUE_CORRECTED_CHANGED_V1,
        }
    };
    evidence.push(receipt_evidence(
        &candidate_id,
        CandidateEvidenceFeatureV1::ExtractedReceiptProvenance,
        CandidateEvidencePolarityV1::Neutral,
        CandidateEvidenceSourceKindV1::ReceiptField,
        &receipt.description_field.field_id,
        &source_revision,
        field_inputs(&receipt.description_field, reviewed_digest.as_ref()),
        provenance_code,
    )?);
    let candidate = ReconciliationCandidateV1 {
        candidate_id: parse_candidate_id(&candidate_id)?,
        target: ReconciliationCandidateTargetV1::ReceiptLine {
            order_line_id: parse_order_line_id(&receipt.order_line_id)?,
            variant_evidence_id: parse_variant_id(&receipt.variant_id)?,
        },
        proposed_relation: Some(IdentityRelationV1::SameProductVariant),
        observed_relations: Vec::new(),
        rank: Some(1),
        display_name: bounded_text(
            receipt
                .authoritative_description
                .as_deref()
                .unwrap_or("Receipt item"),
            120,
        ),
        detail: bounded_text(&receipt_detail(receipt), 240),
        date: receipt.authoritative_purchase_date.clone().map(|value| {
            ReconciliationCandidateDateV1 {
                kind: ReconciliationCandidateDateKindV1::Purchase,
                value,
            }
        }),
        evidence,
    };
    candidate
        .validate()
        .map_err(|_| PlatformError::Corrupt("reconciliation_receipt_candidate"))?;
    Ok(RankedCandidate {
        candidate,
        visual_sort: None,
        updated_revision: 0,
        target_id: receipt.order_line_id.clone(),
        receipt_is_return: receipt.authoritative_event == Some(ReceiptEventKindV1::Return),
        receipt_date: receipt.authoritative_purchase_date.clone(),
        receipt_created_at_ms: receipt.order_created_at_ms,
    })
}

#[allow(clippy::too_many_arguments)]
fn receipt_evidence(
    candidate_id: &str,
    feature: CandidateEvidenceFeatureV1,
    polarity: CandidateEvidencePolarityV1,
    source_kind: CandidateEvidenceSourceKindV1,
    source_id: &str,
    source_revision: &str,
    input_sha256: Vec<Sha256Digest>,
    value_code: &str,
) -> PlatformResult<CandidateEvidenceV1> {
    let evidence_id = stable_id(
        "reconciliation-evidence",
        &format!("{candidate_id}:{}", feature_db(feature)),
    );
    Ok(CandidateEvidenceV1 {
        evidence_id: parse_evidence_id(&evidence_id)?,
        polarity,
        relation: IdentityRelationV1::SameProductVariant,
        feature,
        source_kind,
        source_id: parse_source_id(source_id)?,
        source_revision: source_revision.to_owned(),
        input_sha256,
        extractor_id: LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_ID_V1.to_owned(),
        extractor_revision: LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_REVISION_V1.to_owned(),
        value_code: value_code.to_owned(),
        measured_value: None,
    })
}

fn field_inputs(field: &FieldSnapshot, reviewed: Option<&Sha256Digest>) -> Vec<Sha256Digest> {
    let mut inputs = vec![field.digest()];
    if let Some(reviewed) = reviewed {
        inputs.push(reviewed.clone());
    }
    inputs
}

fn receipt_source_revision(receipt: &ReceiptSnapshot) -> String {
    let exact = format!(
        "receipt-revision-{}:{}",
        receipt.receipt_revision, receipt.provider_revision
    );
    if exact.len() <= 128 && exact.is_ascii() {
        exact
    } else {
        format!(
            "receipt-revision-{}:provider-sha256-{:x}",
            receipt.receipt_revision,
            Sha256::digest(receipt.provider_revision.as_bytes())
        )
    }
}

fn catalog_detail(attributes: &ItemAttributesV1) -> String {
    let mut parts = vec![format!("{:?}", attributes.category).to_lowercase()];
    parts.extend(
        [
            attributes.brand.as_deref(),
            attributes.primary_color.as_deref(),
            attributes.size.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(ToOwned::to_owned),
    );
    parts.join(" | ")
}

fn receipt_detail(receipt: &ReceiptSnapshot) -> String {
    let parts = [
        receipt.authoritative_merchant.as_deref(),
        receipt.authoritative_brand.as_deref(),
        receipt.authoritative_color.as_deref(),
        receipt.authoritative_size.as_deref(),
        receipt.authoritative_sku.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if parts.is_empty() {
        "Reviewed receipt evidence".to_owned()
    } else {
        parts.join(" | ")
    }
}

fn bounded_text(value: &str, max_chars: usize) -> String {
    let bounded = value.chars().take(max_chars).collect::<String>();
    let trimmed = bounded.trim();
    if trimmed.is_empty() {
        "Unknown".to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn insert_candidate(
    transaction: &Transaction<'_>,
    case_id: &str,
    candidate: &ReconciliationCandidateV1,
    revision: u64,
    now_ms: i64,
) -> PlatformResult<()> {
    let (target_kind, item_id, line_id, variant_id) = match &candidate.target {
        ReconciliationCandidateTargetV1::NoMatch {} => ("no_match", None, None, None),
        ReconciliationCandidateTargetV1::WardrobeItem { item_id } => {
            ("wardrobe_item", Some(item_id.to_string()), None, None)
        }
        ReconciliationCandidateTargetV1::ReceiptLine {
            order_line_id,
            variant_evidence_id,
        } => (
            "receipt_line",
            None,
            Some(order_line_id.to_string()),
            Some(variant_evidence_id.to_string()),
        ),
    };
    let (date_kind, date_value) = candidate
        .date
        .as_ref()
        .map(|date| (Some(date_kind_db(date.kind)), Some(date.value.as_str())))
        .unwrap_or((None, None));
    transaction.execute(
        "INSERT INTO reconciliation_candidates(
            candidate_id, case_id, target_kind, target_item_id,
            target_order_line_id, target_variant_evidence_id,
            proposed_relation, rank, display_name, detail,
            date_kind, date_value, reconciliation_revision, created_at_ms
         ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
         )",
        params![
            candidate.candidate_id.to_string(),
            case_id,
            target_kind,
            item_id,
            line_id,
            variant_id,
            candidate.proposed_relation.map(relation_db),
            candidate.rank.map(i64::from),
            candidate.display_name,
            candidate.detail,
            date_kind,
            date_value,
            revision as i64,
            now_ms
        ],
    )?;
    for evidence in &candidate.evidence {
        transaction.execute(
            "INSERT INTO reconciliation_candidate_evidence(
                evidence_id, candidate_id, polarity, relation, feature,
                source_kind, source_id, source_revision, extractor_id,
                extractor_revision, value_code, measured_value,
                reconciliation_revision, created_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
             )",
            params![
                evidence.evidence_id.to_string(),
                candidate.candidate_id.to_string(),
                polarity_db(evidence.polarity),
                relation_db(evidence.relation),
                feature_db(evidence.feature),
                source_kind_db(evidence.source_kind),
                evidence.source_id.to_string(),
                evidence.source_revision,
                evidence.extractor_id,
                evidence.extractor_revision,
                evidence.value_code,
                evidence.measured_value.map(i64::from),
                revision as i64,
                now_ms
            ],
        )?;
        for (ordinal, hash) in evidence.input_sha256.iter().enumerate() {
            transaction.execute(
                "INSERT INTO reconciliation_evidence_input_hashes(
                    evidence_id, input_ordinal, input_sha256,
                    reconciliation_revision
                 ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    evidence.evidence_id.to_string(),
                    ordinal as i64,
                    hash.as_str(),
                    revision as i64
                ],
            )?;
        }
    }
    Ok(())
}

fn reconciliation_case_id(pin: &PhotoPin) -> String {
    stable_id(
        "reconciliation-case",
        &format!(
            "{}:{}:{}:{}:{}",
            pin.observation_id,
            pin.artifact_id,
            pin.photo_decision_id,
            pin.owner_decision_id,
            RECONCILIATION_RETRIEVAL_REVISION_V1
        ),
    )
}

fn find_existing_case(connection: &Connection, pin: &PhotoPin) -> PlatformResult<Option<String>> {
    Ok(connection
        .query_row(
            "SELECT case_id FROM reconciliation_cases
             WHERE observation_id = ?1 AND artifact_id = ?2
               AND photo_decision_id = ?3
               AND owner_decision_id = ?4
               AND retrieval_revision = ?5",
            params![
                pin.observation_id,
                pin.artifact_id,
                pin.photo_decision_id,
                pin.owner_decision_id,
                RECONCILIATION_RETRIEVAL_REVISION_V1
            ],
            |row| row.get(0),
        )
        .optional()?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthorityChecks {
    legacy_owner_unverified: bool,
    source_evidence_matches: bool,
    owner_evidence_matches: bool,
    person_evidence_matches: bool,
    crop_evidence_matches: bool,
    owner_is_current: bool,
    crop_is_current: bool,
}

fn classify_authority(
    checks: AuthorityChecks,
) -> (
    ReconciliationAuthorityStateV2,
    ReconciliationAuthorityReasonV2,
) {
    if checks.legacy_owner_unverified {
        return (
            ReconciliationAuthorityStateV2::OpenIneligible,
            ReconciliationAuthorityReasonV2::LegacyOwnerUnverified,
        );
    }
    for (matches, reason) in [
        (
            checks.source_evidence_matches,
            ReconciliationAuthorityReasonV2::SourceEvidenceMismatch,
        ),
        (
            checks.person_evidence_matches,
            ReconciliationAuthorityReasonV2::PersonEvidenceMismatch,
        ),
        (
            checks.owner_evidence_matches,
            ReconciliationAuthorityReasonV2::OwnerEvidenceMismatch,
        ),
        (
            checks.crop_evidence_matches,
            ReconciliationAuthorityReasonV2::CropEvidenceMismatch,
        ),
    ] {
        if !matches {
            return (ReconciliationAuthorityStateV2::OpenIneligible, reason);
        }
    }
    if !checks.owner_is_current {
        return (
            ReconciliationAuthorityStateV2::OpenStale,
            ReconciliationAuthorityReasonV2::OwnerDecisionStale,
        );
    }
    if !checks.crop_is_current {
        return (
            ReconciliationAuthorityStateV2::OpenStale,
            ReconciliationAuthorityReasonV2::CropDecisionStale,
        );
    }
    (
        ReconciliationAuthorityStateV2::OpenEligible,
        ReconciliationAuthorityReasonV2::CurrentAuthority,
    )
}

fn load_case(connection: &Connection, case_id: &str) -> PlatformResult<ReconciliationCaseV1> {
    let row = connection
        .query_row(
            "SELECT observation_id, artifact_id, artifact_sha256,
                    observation_date, retrieval_revision,
                    leading_candidate_id,
                    COALESCE(head.case_revision, reconciliation_case.case_revision)
             FROM reconciliation_cases reconciliation_case
             LEFT JOIN reconciliation_decision_heads head
               ON head.case_id = reconciliation_case.case_id
             WHERE reconciliation_case.case_id = ?1",
            [case_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("reconciliation_case_id"))?;
    let case = ReconciliationCaseV1 {
        case_id: parse_case_id(case_id)?,
        observation_id: parse_observation_id(&row.0)?,
        artifact_id: parse_artifact_id(&row.1)?,
        artifact_sha256: parse_digest(&row.2)?,
        observation_date: row.3,
        retrieval_revision: row.4,
        candidates: load_candidates(connection, case_id)?,
        leading_candidate_id: parse_candidate_id(&row.5)?,
        decision_head: load_decision_head(connection, case_id)?,
        case_revision: to_u64(row.6, "reconciliation_case_revision")?,
    };
    case.validate()
        .map_err(|_| PlatformError::Corrupt("reconciliation_case"))?;
    Ok(case)
}

fn load_case_v2(connection: &Connection, case_id: &str) -> PlatformResult<ReconciliationCaseV2> {
    let row = connection
        .query_row(
            "SELECT observation_id, artifact_id, scope_id, source_revision_id,
                    source_revision_sha256, artifact_sha256, photo_decision_id,
                    photo_revision, owner_decision_id, person_instance_id,
                    owner_revision, owner_evidence_sha256, observation_date,
                    retrieval_revision, leading_candidate_id,
                    COALESCE(head.case_revision, reconciliation_case.case_revision),
                    reconciliation_case.created_at_ms
             FROM reconciliation_cases reconciliation_case
             LEFT JOIN reconciliation_decision_heads head
               ON head.case_id = reconciliation_case.case_id
             WHERE reconciliation_case.case_id = ?1",
            [case_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, String>(14)?,
                    row.get::<_, i64>(15)?,
                    row.get::<_, i64>(16)?,
                ))
            },
        )
        .optional()?
        .ok_or(PlatformError::InvalidInput("reconciliation_case_id"))?;
    let owner_revision = row
        .10
        .map(|value| to_u64(value, "owner_revision"))
        .transpose()?;
    let (authority_state, authority_reason) = derive_authority(
        connection,
        AuthorityPins {
            observation_id: &row.0,
            artifact_id: &row.1,
            scope_id: &row.2,
            source_revision_id: &row.3,
            source_revision_sha256: &row.4,
            artifact_sha256: &row.5,
            photo_decision_id: &row.6,
            photo_revision: to_u64(row.7, "photo_revision")?,
            owner_decision_id: row.8.as_deref(),
            person_instance_id: row.9.as_deref(),
            owner_revision,
            owner_evidence_sha256: row.11.as_deref(),
        },
    )?;
    let case = ReconciliationCaseV2 {
        case_id: parse_case_id(case_id)?,
        observation_id: parse_observation_id(&row.0)?,
        artifact_id: parse_artifact_id(&row.1)?,
        artifact_sha256: parse_digest(&row.5)?,
        observation_date: row.12,
        retrieval_revision: row.13,
        candidates: load_candidates(connection, case_id)?,
        leading_candidate_id: parse_candidate_id(&row.14)?,
        decision_head: load_decision_head(connection, case_id)?,
        case_revision: to_u64(row.15, "reconciliation_case_revision")?,
        owner_decision_id: row.8.as_deref().map(parse_owner_decision_id).transpose()?,
        person_instance_id: row.9.as_deref().map(parse_person_instance_id).transpose()?,
        owner_evidence_sha256: row.11.as_deref().map(parse_digest).transpose()?,
        owner_revision,
        crop_decision_id: parse_photo_review_decision_id(&row.6)?,
        crop_revision: to_u64(row.7, "photo_revision")?,
        source_revision_sha256: parse_digest(&row.4)?,
        authority_state,
        authority_reason,
        created_at_ms: to_u64(row.16, "reconciliation_created_at_ms")?,
    };
    case.validate()
        .map_err(|_| PlatformError::Corrupt("reconciliation_case"))?;
    Ok(case)
}

struct AuthorityPins<'a> {
    observation_id: &'a str,
    artifact_id: &'a str,
    scope_id: &'a str,
    source_revision_id: &'a str,
    source_revision_sha256: &'a str,
    artifact_sha256: &'a str,
    photo_decision_id: &'a str,
    photo_revision: u64,
    owner_decision_id: Option<&'a str>,
    person_instance_id: Option<&'a str>,
    owner_revision: Option<u64>,
    owner_evidence_sha256: Option<&'a str>,
}

fn derive_authority(
    connection: &Connection,
    pins: AuthorityPins<'_>,
) -> PlatformResult<(
    ReconciliationAuthorityStateV2,
    ReconciliationAuthorityReasonV2,
)> {
    let owner_group = (
        pins.owner_decision_id,
        pins.person_instance_id,
        pins.owner_revision,
        pins.owner_evidence_sha256,
    );
    let (owner_decision_id, person_instance_id, owner_revision, owner_evidence_sha256) =
        match owner_group {
            (None, None, None, None) => {
                return Ok(classify_authority(AuthorityChecks {
                    legacy_owner_unverified: true,
                    source_evidence_matches: true,
                    owner_evidence_matches: true,
                    person_evidence_matches: true,
                    crop_evidence_matches: true,
                    owner_is_current: false,
                    crop_is_current: false,
                }))
            }
            (Some(decision), Some(person), Some(revision), Some(evidence)) => {
                (decision, person, revision, evidence)
            }
            _ => {
                return Ok(classify_authority(AuthorityChecks {
                    legacy_owner_unverified: false,
                    source_evidence_matches: true,
                    owner_evidence_matches: false,
                    person_evidence_matches: true,
                    crop_evidence_matches: true,
                    owner_is_current: false,
                    crop_is_current: false,
                }))
            }
        };

    let source_evidence_matches = source_revision_hash(connection, pins.source_revision_id)?
        .as_str()
        == pins.source_revision_sha256;
    let owner_link = connection
        .query_row(
            "SELECT owner_review_id, owner_decision_id, person_instance_id,
                    owner_revision, evidence_sha256
             FROM photo_observation_owner_links
             WHERE observation_id = ?1 AND scope_id = ?2
               AND source_revision_id = ?3",
            params![pins.observation_id, pins.scope_id, pins.source_revision_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let owner_link_matches = owner_link.as_ref().is_some_and(|link| {
        link.1 == owner_decision_id
            && link.2 == person_instance_id
            && u64::try_from(link.3).ok() == Some(owner_revision)
            && link.4 == owner_evidence_sha256
            && parse_digest(&link.4).is_ok()
    });
    let owner_review_id = owner_link.as_ref().map(|link| link.0.as_str());
    let owner_decision = connection
        .query_row(
            "SELECT owner_review_id, source_revision_id, action,
                    selected_person_instance_id, owner_revision
             FROM photo_owner_decisions WHERE owner_decision_id = ?1",
            [owner_decision_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let owner_decision_matches = owner_decision.as_ref().is_some_and(|decision| {
        owner_review_id == Some(decision.0.as_str())
            && decision.1 == pins.source_revision_id
            && decision.2 == "select_person"
            && decision.3.as_deref() == Some(person_instance_id)
            && u64::try_from(decision.4).ok() == Some(owner_revision)
    });
    let person = connection
        .query_row(
            "SELECT owner_review_id, source_revision_id, detection_attempt_id,
                    correction_id, source_kind, instance_ordinal,
                    rectangle_x, rectangle_y, rectangle_width, rectangle_height,
                    confidence_basis_points, evidence_sha256
             FROM photo_person_instances WHERE person_instance_id = ?1",
            [person_instance_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .optional()?;
    let person_evidence_matches = if let Some(person) = person.as_ref() {
        let confidence_basis_points = person
            .10
            .map(|value| {
                u16::try_from(value)
                    .map_err(|_| PlatformError::Corrupt("person_confidence_basis_points"))
            })
            .transpose()?;
        let expected_person_evidence = canonical_hash(
            b"wardrobe.photo.person-instance.v1",
            &AuthorityPersonEvidence {
                owner_review_id: &person.0,
                source_revision_id: &person.1,
                detection_attempt_id: person.2.as_deref(),
                correction_id: person.3.as_deref(),
                source_kind: &person.4,
                instance_ordinal: person.5,
                rectangle: wardrobe_core::RectV1 {
                    x: to_u32(person.6, "person_rectangle_x")?,
                    y: to_u32(person.7, "person_rectangle_y")?,
                    width: to_u32(person.8, "person_rectangle_width")?,
                    height: to_u32(person.9, "person_rectangle_height")?,
                },
                confidence_basis_points,
            },
        )?;
        person.1 == pins.source_revision_id && expected_person_evidence.as_str() == person.11
    } else {
        false
    };
    let owner_hash_matches = match (owner_link.as_ref(), person.as_ref()) {
        (Some(link), Some(person)) => {
            canonical_hash(
                b"wardrobe.photo.observation-owner-link.v1",
                &AuthorityOwnerEvidence {
                    observation_id: pins.observation_id,
                    artifact_id: pins.artifact_id,
                    source_revision_id: pins.source_revision_id,
                    source_revision_sha256: pins.source_revision_sha256,
                    owner_review_id: &link.0,
                    owner_decision_id,
                    person_instance_id,
                    person_evidence_sha256: &person.11,
                    owner_revision: i64::try_from(owner_revision)
                        .map_err(|_| PlatformError::Corrupt("owner_revision"))?,
                },
            )?
            .as_str()
                == owner_evidence_sha256
        }
        _ => false,
    };

    let artifact = connection
        .query_row(
            "SELECT source_revision_id, source_revision_sha256, artifact_sha256,
                    artifact_kind, rectangle_x, rectangle_y, rectangle_width,
                    rectangle_height, artifact_revision, preprocessing_revision,
                    provenance_json, provenance_sha256
             FROM photo_artifacts WHERE artifact_id = ?1",
            [pins.artifact_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                ))
            },
        )
        .optional()?;
    let artifact_matches = artifact
        .as_ref()
        .map(|artifact| -> PlatformResult<bool> {
            if artifact.0 != pins.source_revision_id
                || artifact.1 != pins.source_revision_sha256
                || artifact.2 != pins.artifact_sha256
                || artifact.9 != PHOTO_PREPROCESSING_REVISION_V1
                || format!("{:x}", Sha256::digest(artifact.10.as_bytes())) != artifact.11
            {
                return Ok(false);
            }
            let kind = artifact_kind_from_db(&artifact.3)?;
            let rectangle = match kind {
                PhotoArtifactKindV1::RectangleSourceCrop => Some(wardrobe_core::RectV1 {
                    x: optional_u32(artifact.4, "photo_rectangle_x")?,
                    y: optional_u32(artifact.5, "photo_rectangle_y")?,
                    width: optional_u32(artifact.6, "photo_rectangle_width")?,
                    height: optional_u32(artifact.7, "photo_rectangle_height")?,
                }),
                PhotoArtifactKindV1::SourceImageReference => {
                    if [artifact.4, artifact.5, artifact.6, artifact.7]
                        .into_iter()
                        .any(|value| value.is_some())
                    {
                        return Ok(false);
                    }
                    None
                }
            };
            let expected_revision = match kind {
                PhotoArtifactKindV1::RectangleSourceCrop => RECTANGLE_SOURCE_CROP_REVISION_V1,
                PhotoArtifactKindV1::SourceImageReference => SOURCE_IMAGE_REFERENCE_REVISION_V1,
            };
            if artifact.8 != expected_revision {
                return Ok(false);
            }
            #[derive(Serialize)]
            struct ArtifactHashRecord<'a> {
                artifact_schema_revision: &'static str,
                artifact_kind: &'static str,
                provenance_sha256: &'a str,
                rectangle: Option<wardrobe_core::RectV1>,
            }
            Ok(canonical_hash(
                b"wardrobe.photo.artifact.v1",
                &ArtifactHashRecord {
                    artifact_schema_revision: PHOTO_ARTIFACT_SCHEMA_REVISION_V1,
                    artifact_kind: artifact_kind_db(kind),
                    provenance_sha256: &artifact.11,
                    rectangle,
                },
            )?
            .as_str()
                == pins.artifact_sha256)
        })
        .transpose()?
        .unwrap_or(false);
    let crop_decision_matches = connection
        .query_row(
            "SELECT observation_id, scope_id, source_revision_id, action,
                    selected_artifact_id, photo_revision
             FROM photo_review_decisions WHERE decision_id = ?1",
            [pins.photo_decision_id],
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
        .optional()?
        .is_some_and(|decision| {
            decision.0 == pins.observation_id
                && decision.1 == pins.scope_id
                && decision.2 == pins.source_revision_id
                && matches!(decision.3.as_str(), "confirm_crop" | "replace_crop")
                && decision.4.as_deref() == Some(pins.artifact_id)
                && u64::try_from(decision.5).ok() == Some(pins.photo_revision)
        });
    let owner_is_current = connection
        .query_row(
            "SELECT 1 FROM photo_owner_heads
             WHERE source_revision_id = ?1
               AND owner_decision_id = ?2
               AND action = 'select_person'
               AND selected_person_instance_id = ?3
               AND owner_revision = ?4",
            params![
                pins.source_revision_id,
                owner_decision_id,
                person_instance_id,
                owner_revision as i64
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let crop_is_current = connection
        .query_row(
            "SELECT 1 FROM photo_review_heads
             WHERE observation_id = ?1 AND scope_id = ?2
               AND source_revision_id = ?3 AND decision_id = ?4
               AND current_artifact_id = ?5
               AND state IN ('confirmed', 'replaced')
               AND photo_revision = ?6",
            params![
                pins.observation_id,
                pins.scope_id,
                pins.source_revision_id,
                pins.photo_decision_id,
                pins.artifact_id,
                pins.photo_revision as i64
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some();

    Ok(classify_authority(AuthorityChecks {
        legacy_owner_unverified: false,
        source_evidence_matches,
        owner_evidence_matches: owner_link_matches && owner_decision_matches && owner_hash_matches,
        person_evidence_matches,
        crop_evidence_matches: artifact_matches && crop_decision_matches,
        owner_is_current,
        crop_is_current,
    }))
}

fn require_current_authority(case: &ReconciliationCaseV2) -> PlatformResult<()> {
    if case.authority_state == ReconciliationAuthorityStateV2::OpenEligible
        && case.authority_reason == ReconciliationAuthorityReasonV2::CurrentAuthority
    {
        Ok(())
    } else {
        Err(PlatformError::Conflict(
            "reconciliation_authority_not_current",
        ))
    }
}

fn load_candidates(
    connection: &Connection,
    case_id: &str,
) -> PlatformResult<Vec<ReconciliationCandidateV1>> {
    let mut statement = connection.prepare(
        "SELECT candidate_id, target_kind, target_item_id,
                target_order_line_id, target_variant_evidence_id,
                proposed_relation, rank, display_name, detail,
                date_kind, date_value
         FROM reconciliation_candidates WHERE case_id = ?1
         ORDER BY CASE WHEN rank IS NULL THEN 1 ELSE 0 END, rank, candidate_id",
    )?;
    let rows = statement
        .query_map([case_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, Option<String>>(10)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|row| {
            let target = match row.1.as_str() {
                "no_match" => ReconciliationCandidateTargetV1::NoMatch {},
                "wardrobe_item" => ReconciliationCandidateTargetV1::WardrobeItem {
                    item_id: parse_item_id(required(row.2.as_deref(), "reconciliation_target")?)?,
                },
                "receipt_line" => ReconciliationCandidateTargetV1::ReceiptLine {
                    order_line_id: parse_order_line_id(required(
                        row.3.as_deref(),
                        "reconciliation_target",
                    )?)?,
                    variant_evidence_id: parse_variant_id(required(
                        row.4.as_deref(),
                        "reconciliation_target",
                    )?)?,
                },
                _ => return Err(PlatformError::Corrupt("reconciliation_target")),
            };
            let date = row
                .9
                .as_deref()
                .zip(row.10)
                .map(|(kind, value)| -> PlatformResult<_> {
                    Ok(ReconciliationCandidateDateV1 {
                        kind: date_kind_from_db(kind)?,
                        value,
                    })
                })
                .transpose()?;
            Ok(ReconciliationCandidateV1 {
                candidate_id: parse_candidate_id(&row.0)?,
                target,
                proposed_relation: row.5.as_deref().map(relation_from_db).transpose()?,
                observed_relations: if has_visual_measurement(connection, &row.0)? {
                    vec![IdentityRelationV1::VisualSimilarity]
                } else {
                    Vec::new()
                },
                rank: row
                    .6
                    .map(|rank| {
                        u8::try_from(rank)
                            .map_err(|_| PlatformError::Corrupt("reconciliation_rank"))
                    })
                    .transpose()?,
                display_name: row.7,
                detail: row.8,
                date,
                evidence: load_candidate_evidence(connection, &row.0)?,
            })
        })
        .collect()
}

fn has_visual_measurement(connection: &Connection, candidate_id: &str) -> PlatformResult<bool> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM reconciliation_candidate_evidence
             WHERE candidate_id = ?1
               AND feature IN ('difference_hash_distance', 'mean_color_distance')
             LIMIT 1",
            [candidate_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn load_candidate_evidence(
    connection: &Connection,
    candidate_id: &str,
) -> PlatformResult<Vec<CandidateEvidenceV1>> {
    let mut statement = connection.prepare(
        "SELECT evidence_id, polarity, relation, feature, source_kind,
                source_id, source_revision, extractor_id,
                extractor_revision, value_code, measured_value
         FROM reconciliation_candidate_evidence
         WHERE candidate_id = ?1 ORDER BY feature, evidence_id",
    )?;
    let rows = statement
        .query_map([candidate_id], |row| {
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
                row.get::<_, String>(9)?,
                row.get::<_, Option<i64>>(10)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|row| {
            let mut hashes = connection.prepare(
                "SELECT input_sha256 FROM reconciliation_evidence_input_hashes
                 WHERE evidence_id = ?1 ORDER BY input_ordinal",
            )?;
            let input_sha256 = hashes
                .query_map([&row.0], |row| row.get::<_, String>(0))?
                .map(|value| parse_digest(&value?))
                .collect::<PlatformResult<Vec<_>>>()?;
            Ok(CandidateEvidenceV1 {
                evidence_id: parse_evidence_id(&row.0)?,
                polarity: polarity_from_db(&row.1)?,
                relation: relation_from_db(&row.2)?,
                feature: feature_from_db(&row.3)?,
                source_kind: source_kind_from_db(&row.4)?,
                source_id: parse_source_id(&row.5)?,
                source_revision: row.6,
                input_sha256,
                extractor_id: row.7,
                extractor_revision: row.8,
                value_code: row.9,
                measured_value: row
                    .10
                    .map(|value| {
                        u16::try_from(value)
                            .map_err(|_| PlatformError::Corrupt("reconciliation_measurement"))
                    })
                    .transpose()?,
            })
        })
        .collect()
}

fn load_decision_head(
    connection: &Connection,
    case_id: &str,
) -> PlatformResult<Option<ReconciliationDecisionV1>> {
    connection
        .query_row(
            "SELECT decision.decision_id, decision.outcome,
                    decision.selected_candidate_id, decision.case_revision
             FROM reconciliation_decision_heads head
             JOIN reconciliation_decisions decision
               ON decision.decision_id = head.decision_id
             WHERE head.case_id = ?1",
            [case_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(ReconciliationDecisionV1 {
                decision_id: parse_decision_id(&row.0)?,
                case_id: parse_case_id(case_id)?,
                outcome: outcome_from_db(&row.1)?,
                selected_candidate_id: row.2.as_deref().map(parse_candidate_id).transpose()?,
                case_revision: to_u64(row.3, "reconciliation_case_revision")?,
            })
        })
        .transpose()
}

fn validate_requested_outcome(
    case: &ReconciliationCaseV1,
    request: &DecideReconciliationCaseV1Request,
) -> PlatformResult<()> {
    validate_requested_outcome_values(
        case,
        request.case_id,
        request.outcome,
        request.selected_candidate_id,
        request.expected_case_revision,
    )
}

fn validate_requested_outcome_values(
    case: &ReconciliationCaseV1,
    case_id: ReconciliationCaseId,
    outcome: ReconciliationOutcomeV1,
    selected_candidate_id: Option<ReconciliationCandidateId>,
    expected_case_revision: u64,
) -> PlatformResult<()> {
    let mut prospective = case.clone();
    prospective.case_revision = expected_case_revision
        .checked_add(1)
        .ok_or(PlatformError::Conflict("reconciliation_case_revision"))?;
    ReconciliationDecisionV1 {
        decision_id: ReconciliationDecisionId::new_v4(),
        case_id,
        outcome,
        selected_candidate_id,
        case_revision: prospective.case_revision,
    }
    .validate_for_case(&prospective)
    .map_err(|_| PlatformError::InvalidInput("reconciliation_outcome"))
}

#[allow(clippy::too_many_arguments)]
fn insert_reconciliation_decision(
    transaction: &Transaction<'_>,
    decision_id: &str,
    case_id: &str,
    request_id: &str,
    outcome: ReconciliationOutcomeV1,
    selected_candidate_id: Option<ReconciliationCandidateId>,
    expected_case_revision: u64,
    case_revision: u64,
    reconciliation_revision: u64,
    now_ms: i64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO reconciliation_decisions(
            decision_id, case_id, request_id, outcome,
            selected_candidate_id, expected_case_revision, case_revision,
            reconciliation_revision, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            decision_id,
            case_id,
            request_id,
            outcome_db(outcome),
            selected_candidate_id.map(|id| id.to_string()),
            expected_case_revision as i64,
            case_revision as i64,
            reconciliation_revision as i64,
            now_ms
        ],
    )?;
    transaction.execute(
        "INSERT INTO reconciliation_decision_heads(
            case_id, decision_id, case_revision,
            reconciliation_revision, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(case_id) DO UPDATE SET
            decision_id = excluded.decision_id,
            case_revision = excluded.case_revision,
            reconciliation_revision = excluded.reconciliation_revision,
            updated_at_ms = excluded.updated_at_ms",
        params![
            case_id,
            decision_id,
            case_revision as i64,
            reconciliation_revision as i64,
            now_ms
        ],
    )?;
    Ok(())
}

fn make_reconciliation_cursor(
    request: &ListReconciliationCasesV2Request,
    revisions: &Revisions,
    last: &ReconciliationCaseV2,
) -> PlatformResult<PageCursorV1> {
    encode_reconciliation_cursor(&ReconciliationCursorV2 {
        cursor_version: RECONCILIATION_CURSOR_VERSION_V2,
        schema_version: request.schema_version,
        observation_id: request.observation_id.to_string(),
        state: reconciliation_filter_db(request.state).to_owned(),
        photo_revision: revisions.photo,
        owner_revision: revisions.owner,
        reconciliation_revision: revisions.reconciliation,
        last_created_at_ms: last.created_at_ms,
        last_case_id: last.case_id.to_string(),
    })
}

fn encode_reconciliation_cursor(cursor: &ReconciliationCursorV2) -> PlatformResult<PageCursorV1> {
    let payload = serde_json::to_vec(cursor)?;
    let encoded = URL_SAFE_NO_PAD.encode(&payload);
    let digest = reconciliation_cursor_digest(&payload);
    PageCursorV1::new(format!("{encoded}.{digest}"))
        .map_err(|_| PlatformError::Corrupt("reconciliation_cursor"))
}

fn parse_reconciliation_cursor(
    request: &ListReconciliationCasesV2Request,
    revisions: &Revisions,
) -> PlatformResult<Option<ReconciliationCursorV2>> {
    let Some(encoded_cursor) = request.cursor.as_ref() else {
        return Ok(None);
    };
    let (encoded, supplied_digest) = encoded_cursor
        .as_str()
        .split_once('.')
        .ok_or(PlatformError::InvalidInput("reconciliation_cursor"))?;
    if encoded.is_empty()
        || supplied_digest.len() != 64
        || supplied_digest
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit())
    {
        return Err(PlatformError::InvalidInput("reconciliation_cursor"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PlatformError::InvalidInput("reconciliation_cursor"))?;
    if reconciliation_cursor_digest(&payload) != supplied_digest {
        return Err(PlatformError::InvalidInput("reconciliation_cursor"));
    }
    let cursor: ReconciliationCursorV2 = serde_json::from_slice(&payload)
        .map_err(|_| PlatformError::InvalidInput("reconciliation_cursor"))?;
    if cursor.cursor_version != RECONCILIATION_CURSOR_VERSION_V2
        || cursor.schema_version != request.schema_version
        || cursor.observation_id != request.observation_id.to_string()
        || cursor.state != reconciliation_filter_db(request.state)
        || parse_case_id(&cursor.last_case_id).is_err()
        || cursor.last_created_at_ms > 9_007_199_254_740_990
    {
        return Err(PlatformError::InvalidInput("reconciliation_cursor"));
    }
    if cursor.photo_revision != revisions.photo
        || cursor.owner_revision != revisions.owner
        || cursor.reconciliation_revision != revisions.reconciliation
    {
        return Err(PlatformError::Conflict("snapshot_expired"));
    }
    Ok(Some(cursor))
}

fn reconciliation_cursor_digest(payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"wardrobe.reconciliation.cursor.v2");
    digest.update([0]);
    digest.update(payload);
    format!("{:x}", digest.finalize())
}

fn reconciliation_filter_db(filter: ReconciliationCaseStateFilterV2) -> &'static str {
    match filter {
        ReconciliationCaseStateFilterV2::All => "all",
        ReconciliationCaseStateFilterV2::OpenEligible => "open_eligible",
        ReconciliationCaseStateFilterV2::OpenStale => "open_stale",
        ReconciliationCaseStateFilterV2::OpenIneligible => "open_ineligible",
    }
}

fn advance_reconciliation_revision(transaction: &Transaction<'_>) -> PlatformResult<u64> {
    let value: Option<i64> = transaction
        .query_row(
            "UPDATE revision_state
             SET reconciliation_revision = reconciliation_revision + 1
             WHERE singleton = 1
               AND reconciliation_revision < 9007199254740990
             RETURNING reconciliation_revision",
            [],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| to_u64(value, "reconciliation_revision"))
        .transpose()?
        .ok_or(PlatformError::Conflict("reconciliation_revision"))
}

fn replay_read<Q: Serialize, R: DeserializeOwned>(
    database: &Database,
    command: &str,
    request: &Q,
) -> PlatformResult<Option<R>> {
    replay_connection(&database.connection()?, command, request)
}

fn replay<Q: Serialize, R: DeserializeOwned>(
    transaction: &Transaction<'_>,
    command: &str,
    request: &Q,
) -> PlatformResult<Option<R>> {
    replay_connection(transaction, command, request)
}

fn replay_connection<Q: Serialize, R: DeserializeOwned>(
    connection: &Connection,
    command: &str,
    request: &Q,
) -> PlatformResult<Option<R>> {
    let request_id = request_id_from_json(request)?;
    let envelope = envelope_hash(request)?;
    let row = connection
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
            if stored_command == command && stored_envelope == envelope =>
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

fn link_command_entity(
    transaction: &Transaction<'_>,
    request_id: &str,
    kind: &str,
    entity_id: &str,
    revision: u64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO reconciliation_command_entities(
            request_id, entity_kind, entity_id, reconciliation_revision
         ) VALUES (?1, ?2, ?3, ?4)",
        params![request_id, kind, entity_id, revision as i64],
    )?;
    Ok(())
}

pub(crate) fn augment_reconciliation_deletion_closure(
    connection: &Connection,
    snapshot_token: &str,
    source_ids: &BTreeSet<String>,
    item_ids: &BTreeSet<String>,
) -> PlatformResult<()> {
    let mut case_ids = BTreeSet::new();
    for source_id in source_ids {
        extend_set(
            connection,
            "SELECT reconciliation_case.case_id
             FROM reconciliation_cases reconciliation_case
             JOIN photo_source_revisions revision
               ON revision.source_revision_id =
                  reconciliation_case.source_revision_id
             WHERE revision.source_id = ?1
             UNION
             SELECT candidate.case_id
             FROM reconciliation_candidates candidate
             JOIN receipt_order_lines line
               ON line.order_line_id = candidate.target_order_line_id
             JOIN receipt_orders orders
               ON orders.order_evidence_id = line.order_evidence_id
             JOIN receipt_extraction_runs run ON run.run_id = orders.run_id
             JOIN receipt_parses parse ON parse.parse_id = run.parse_id
             WHERE candidate.target_kind = 'receipt_line'
               AND parse.source_id = ?1",
            source_id,
            &mut case_ids,
        )?;
    }
    for item_id in item_ids {
        extend_set(
            connection,
            "SELECT case_id FROM reconciliation_candidates
             WHERE target_kind = 'wardrobe_item' AND target_item_id = ?1",
            item_id,
            &mut case_ids,
        )?;
    }
    for case_id in case_ids {
        insert_preview(
            connection,
            snapshot_token,
            "evidence_records",
            &format!("reconciliation_case:{case_id}"),
        )?;
        let candidate_ids =
            query_strings(connection, "SELECT candidate_id FROM reconciliation_candidates WHERE case_id = ?1 ORDER BY candidate_id", &case_id)?;
        for candidate_id in candidate_ids {
            insert_preview(
                connection,
                snapshot_token,
                "evidence_records",
                &format!("reconciliation_candidate:{candidate_id}"),
            )?;
            let evidence_ids = query_strings(
                connection,
                "SELECT evidence_id FROM reconciliation_candidate_evidence
                 WHERE candidate_id = ?1 ORDER BY evidence_id",
                &candidate_id,
            )?;
            for evidence_id in evidence_ids {
                insert_preview(
                    connection,
                    snapshot_token,
                    "evidence_records",
                    &format!("reconciliation_evidence:{evidence_id}"),
                )?;
                let mut hashes = connection.prepare(
                    "SELECT input_ordinal FROM reconciliation_evidence_input_hashes
                     WHERE evidence_id = ?1 ORDER BY input_ordinal",
                )?;
                for ordinal in hashes
                    .query_map([&evidence_id], |row| row.get::<_, i64>(0))?
                    .collect::<Result<Vec<_>, _>>()?
                {
                    insert_preview(
                        connection,
                        snapshot_token,
                        "evidence_records",
                        &format!("reconciliation_evidence_hash:{evidence_id}:{ordinal}"),
                    )?;
                }
            }
        }
        let decision_ids = query_strings(
            connection,
            "SELECT decision_id FROM reconciliation_decisions
             WHERE case_id = ?1 ORDER BY case_revision",
            &case_id,
        )?;
        for decision_id in &decision_ids {
            insert_preview(
                connection,
                snapshot_token,
                "decision_records",
                &format!("reconciliation_decision:{decision_id}"),
            )?;
        }
        if connection
            .query_row(
                "SELECT 1 FROM reconciliation_decision_heads WHERE case_id = ?1",
                [&case_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            insert_preview(
                connection,
                snapshot_token,
                "decision_records",
                &format!("reconciliation_decision_head:{case_id}"),
            )?;
        }
        let mut requests = connection.prepare(
            "SELECT request_id, entity_kind, entity_id
             FROM reconciliation_command_entities
             WHERE (entity_kind = 'case' AND entity_id = ?1)
                OR (entity_kind = 'decision' AND entity_id IN (
                    SELECT decision_id FROM reconciliation_decisions
                    WHERE case_id = ?1
                ))
             ORDER BY request_id, entity_kind, entity_id",
        )?;
        for (request_id, kind, entity_id) in requests
            .query_map([&case_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
        {
            insert_preview(
                connection,
                snapshot_token,
                "decision_records",
                &format!("reconciliation_command_receipt:{request_id}"),
            )?;
            insert_preview(
                connection,
                snapshot_token,
                "decision_records",
                &format!("reconciliation_command_entity:{request_id}:{kind}:{entity_id}"),
            )?;
        }
    }
    Ok(())
}

fn extend_set(
    connection: &Connection,
    sql: &str,
    value: &str,
    output: &mut BTreeSet<String>,
) -> PlatformResult<()> {
    output.extend(query_strings(connection, sql, value)?);
    Ok(())
}

fn query_strings(connection: &Connection, sql: &str, value: &str) -> PlatformResult<Vec<String>> {
    let mut statement = connection.prepare(sql)?;
    let values = statement
        .query_map([value], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(values)
}

fn insert_preview(
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

fn request_id_from_json<Q: Serialize>(request: &Q) -> PlatformResult<String> {
    serde_json::to_value(request)?
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(PlatformError::Corrupt("reconciliation_request_id"))
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
        .map_err(|_| PlatformError::Corrupt("reconciliation_canonical_hash"))
}

fn timestamp_from_ms(value: i64) -> PlatformResult<String> {
    let nanoseconds = i128::from(value)
        .checked_mul(1_000_000)
        .ok_or(PlatformError::Corrupt("timestamp_range"))?;
    time::OffsetDateTime::from_unix_timestamp_nanos(nanoseconds)
        .map_err(|_| PlatformError::Corrupt("timestamp_range"))?
        .format(&Rfc3339)
        .map_err(|_| PlatformError::Corrupt("timestamp_format"))
}

fn unix_now_ms() -> PlatformResult<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| PlatformError::Corrupt("system_clock"))?;
    i64::try_from(duration.as_millis()).map_err(|_| PlatformError::Corrupt("system_clock"))
}

fn required<'a>(value: Option<&'a str>, field: &'static str) -> PlatformResult<&'a str> {
    value.ok_or(PlatformError::Corrupt(field))
}

fn optional_u32(value: Option<i64>, field: &'static str) -> PlatformResult<u32> {
    to_u32(value.ok_or(PlatformError::Corrupt(field))?, field)
}

fn parse_uuid(value: &str, field: &'static str) -> PlatformResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| PlatformError::Corrupt(field))
}

macro_rules! parse_id {
    ($fn_name:ident, $type:ty, $field:literal) => {
        fn $fn_name(value: &str) -> PlatformResult<$type> {
            <$type>::new(parse_uuid(value, $field)?).map_err(|_| PlatformError::Corrupt($field))
        }
    };
}

parse_id!(
    parse_case_id,
    ReconciliationCaseId,
    "reconciliation_case_id"
);
parse_id!(
    parse_candidate_id,
    ReconciliationCandidateId,
    "reconciliation_candidate_id"
);
parse_id!(
    parse_evidence_id,
    ReconciliationEvidenceId,
    "reconciliation_evidence_id"
);
parse_id!(
    parse_decision_id,
    ReconciliationDecisionId,
    "reconciliation_decision_id"
);
parse_id!(
    parse_source_id,
    ReconciliationEvidenceSourceId,
    "reconciliation_evidence_source_id"
);
parse_id!(parse_item_id, ItemId, "item_id");
parse_id!(
    parse_order_line_id,
    ReceiptOrderLineId,
    "receipt_order_line_id"
);
parse_id!(
    parse_variant_id,
    ReceiptVariantEvidenceId,
    "receipt_variant_id"
);
parse_id!(
    parse_observation_id,
    PhotoObservationId,
    "photo_observation_id"
);
parse_id!(parse_artifact_id, PhotoArtifactId, "photo_artifact_id");
parse_id!(
    parse_owner_decision_id,
    PhotoOwnerDecisionId,
    "photo_owner_decision_id"
);
parse_id!(
    parse_person_instance_id,
    PhotoPersonInstanceId,
    "photo_person_instance_id"
);
parse_id!(
    parse_photo_review_decision_id,
    PhotoReviewDecisionId,
    "photo_review_decision_id"
);

fn parse_digest(value: &str) -> PlatformResult<Sha256Digest> {
    Sha256Digest::parse(value.to_owned()).map_err(|_| PlatformError::Corrupt("sha256"))
}

fn to_u64(value: i64, field: &'static str) -> PlatformResult<u64> {
    u64::try_from(value).map_err(|_| PlatformError::Corrupt(field))
}

fn to_u32(value: i64, field: &'static str) -> PlatformResult<u32> {
    u32::try_from(value).map_err(|_| PlatformError::Corrupt(field))
}

fn media_type_from_db(value: &str) -> PlatformResult<PhotoMediaTypeV1> {
    match value {
        "image/jpeg" => Ok(PhotoMediaTypeV1::ImageJpeg),
        "image/png" => Ok(PhotoMediaTypeV1::ImagePng),
        "image/webp" => Ok(PhotoMediaTypeV1::ImageWebp),
        _ => Err(PlatformError::Corrupt("photo_media_type")),
    }
}

fn artifact_kind_from_db(value: &str) -> PlatformResult<PhotoArtifactKindV1> {
    match value {
        "rectangle_source_crop" => Ok(PhotoArtifactKindV1::RectangleSourceCrop),
        "source_image_reference" => Ok(PhotoArtifactKindV1::SourceImageReference),
        _ => Err(PlatformError::Corrupt("photo_artifact_kind")),
    }
}

fn artifact_kind_db(value: PhotoArtifactKindV1) -> &'static str {
    match value {
        PhotoArtifactKindV1::RectangleSourceCrop => "rectangle_source_crop",
        PhotoArtifactKindV1::SourceImageReference => "source_image_reference",
    }
}

fn event_kind_from_db(value: &str) -> Option<ReceiptEventKindV1> {
    match value {
        "purchase" => Some(ReceiptEventKindV1::Purchase),
        "exchange" => Some(ReceiptEventKindV1::Exchange),
        "return" => Some(ReceiptEventKindV1::Return),
        _ => None,
    }
}

fn relation_db(value: IdentityRelationV1) -> &'static str {
    match value {
        IdentityRelationV1::VisualSimilarity => "visual_similarity",
        IdentityRelationV1::SameProductVariant => "same_product_variant",
        IdentityRelationV1::SamePhysicalItem => "same_physical_item",
    }
}

fn relation_from_db(value: &str) -> PlatformResult<IdentityRelationV1> {
    match value {
        "visual_similarity" => Ok(IdentityRelationV1::VisualSimilarity),
        "same_product_variant" => Ok(IdentityRelationV1::SameProductVariant),
        "same_physical_item" => Ok(IdentityRelationV1::SamePhysicalItem),
        _ => Err(PlatformError::Corrupt("reconciliation_relation")),
    }
}

fn polarity_db(value: CandidateEvidencePolarityV1) -> &'static str {
    match value {
        CandidateEvidencePolarityV1::Supporting => "supporting",
        CandidateEvidencePolarityV1::Contradictory => "contradictory",
        CandidateEvidencePolarityV1::Neutral => "neutral",
    }
}

fn polarity_from_db(value: &str) -> PlatformResult<CandidateEvidencePolarityV1> {
    match value {
        "supporting" => Ok(CandidateEvidencePolarityV1::Supporting),
        "contradictory" => Ok(CandidateEvidencePolarityV1::Contradictory),
        "neutral" => Ok(CandidateEvidencePolarityV1::Neutral),
        _ => Err(PlatformError::Corrupt("reconciliation_polarity")),
    }
}

fn feature_db(value: CandidateEvidenceFeatureV1) -> &'static str {
    match value {
        CandidateEvidenceFeatureV1::DifferenceHashDistance => "difference_hash_distance",
        CandidateEvidenceFeatureV1::MeanColorDistance => "mean_color_distance",
        CandidateEvidenceFeatureV1::CatalogImageStatus => "catalog_image_status",
        CandidateEvidenceFeatureV1::ReceiptReviewState => "receipt_review_state",
        CandidateEvidenceFeatureV1::ReceiptEventKind => "receipt_event_kind",
        CandidateEvidenceFeatureV1::PurchaseChronology => "purchase_chronology",
        CandidateEvidenceFeatureV1::ExtractedReceiptProvenance => "extracted_receipt_provenance",
    }
}

fn feature_from_db(value: &str) -> PlatformResult<CandidateEvidenceFeatureV1> {
    match value {
        "difference_hash_distance" => Ok(CandidateEvidenceFeatureV1::DifferenceHashDistance),
        "mean_color_distance" => Ok(CandidateEvidenceFeatureV1::MeanColorDistance),
        "catalog_image_status" => Ok(CandidateEvidenceFeatureV1::CatalogImageStatus),
        "receipt_review_state" => Ok(CandidateEvidenceFeatureV1::ReceiptReviewState),
        "receipt_event_kind" => Ok(CandidateEvidenceFeatureV1::ReceiptEventKind),
        "purchase_chronology" => Ok(CandidateEvidenceFeatureV1::PurchaseChronology),
        "extracted_receipt_provenance" => {
            Ok(CandidateEvidenceFeatureV1::ExtractedReceiptProvenance)
        }
        _ => Err(PlatformError::Corrupt("reconciliation_feature")),
    }
}

fn source_kind_db(value: CandidateEvidenceSourceKindV1) -> &'static str {
    match value {
        CandidateEvidenceSourceKindV1::PhotoArtifact => "photo_artifact",
        CandidateEvidenceSourceKindV1::CatalogImageEvidence => "catalog_image_evidence",
        CandidateEvidenceSourceKindV1::CatalogDecision => "catalog_decision",
        CandidateEvidenceSourceKindV1::ReceiptField => "receipt_field",
        CandidateEvidenceSourceKindV1::ReceiptReviewDecision => "receipt_review_decision",
    }
}

fn source_kind_from_db(value: &str) -> PlatformResult<CandidateEvidenceSourceKindV1> {
    match value {
        "photo_artifact" => Ok(CandidateEvidenceSourceKindV1::PhotoArtifact),
        "catalog_image_evidence" => Ok(CandidateEvidenceSourceKindV1::CatalogImageEvidence),
        "catalog_decision" => Ok(CandidateEvidenceSourceKindV1::CatalogDecision),
        "receipt_field" => Ok(CandidateEvidenceSourceKindV1::ReceiptField),
        "receipt_review_decision" => Ok(CandidateEvidenceSourceKindV1::ReceiptReviewDecision),
        _ => Err(PlatformError::Corrupt("reconciliation_source_kind")),
    }
}

fn date_kind_db(value: ReconciliationCandidateDateKindV1) -> &'static str {
    match value {
        ReconciliationCandidateDateKindV1::CatalogCreated => "catalog_created",
        ReconciliationCandidateDateKindV1::Purchase => "purchase",
    }
}

fn date_kind_from_db(value: &str) -> PlatformResult<ReconciliationCandidateDateKindV1> {
    match value {
        "catalog_created" => Ok(ReconciliationCandidateDateKindV1::CatalogCreated),
        "purchase" => Ok(ReconciliationCandidateDateKindV1::Purchase),
        _ => Err(PlatformError::Corrupt("reconciliation_date_kind")),
    }
}

fn outcome_db(value: ReconciliationOutcomeV1) -> &'static str {
    match value {
        ReconciliationOutcomeV1::SameItem => "same_item",
        ReconciliationOutcomeV1::SameVariant => "same_variant",
        ReconciliationOutcomeV1::Different => "different",
        ReconciliationOutcomeV1::NoMatch => "no_match",
        ReconciliationOutcomeV1::Unresolved => "unresolved",
    }
}

fn outcome_from_db(value: &str) -> PlatformResult<ReconciliationOutcomeV1> {
    match value {
        "same_item" => Ok(ReconciliationOutcomeV1::SameItem),
        "same_variant" => Ok(ReconciliationOutcomeV1::SameVariant),
        "different" => Ok(ReconciliationOutcomeV1::Different),
        "no_match" => Ok(ReconciliationOutcomeV1::NoMatch),
        "unresolved" => Ok(ReconciliationOutcomeV1::Unresolved),
        _ => Err(PlatformError::Corrupt("reconciliation_outcome")),
    }
}

fn reconciliation_port_error(error: PlatformError) -> ReconciliationPortError {
    let kind = match error {
        PlatformError::Conflict("snapshot_expired") => ReconciliationPortErrorKind::SnapshotExpired,
        PlatformError::Conflict(_) | PlatformError::LeaseLost => {
            ReconciliationPortErrorKind::Conflict
        }
        PlatformError::InvalidInput("reconciliation_outcome")
        | PlatformError::InvalidInput("reconciliation_photo_review_state") => {
            ReconciliationPortErrorKind::InvalidState
        }
        PlatformError::InvalidInput(_) => ReconciliationPortErrorKind::NotFound,
        PlatformError::Corrupt(_) | PlatformError::Json(_) => {
            ReconciliationPortErrorKind::DataIntegrity
        }
        PlatformError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            ReconciliationPortErrorKind::PermissionDenied
        }
        PlatformError::Io(_) | PlatformError::Sqlite(_) => ReconciliationPortErrorKind::Unavailable,
        _ => ReconciliationPortErrorKind::Internal,
    };
    ReconciliationPortError::new(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wardrobe_core::RequestId;

    fn current_checks() -> AuthorityChecks {
        AuthorityChecks {
            legacy_owner_unverified: false,
            source_evidence_matches: true,
            owner_evidence_matches: true,
            person_evidence_matches: true,
            crop_evidence_matches: true,
            owner_is_current: true,
            crop_is_current: true,
        }
    }

    #[test]
    fn authority_classification_is_fail_closed_and_preserves_stale_history() {
        assert_eq!(
            classify_authority(current_checks()),
            (
                ReconciliationAuthorityStateV2::OpenEligible,
                ReconciliationAuthorityReasonV2::CurrentAuthority
            )
        );

        let mut checks = current_checks();
        checks.owner_is_current = false;
        assert_eq!(
            classify_authority(checks),
            (
                ReconciliationAuthorityStateV2::OpenStale,
                ReconciliationAuthorityReasonV2::OwnerDecisionStale
            )
        );

        let mut checks = current_checks();
        checks.crop_is_current = false;
        assert_eq!(
            classify_authority(checks),
            (
                ReconciliationAuthorityStateV2::OpenStale,
                ReconciliationAuthorityReasonV2::CropDecisionStale
            )
        );

        for (mut checks, reason) in [
            {
                let mut checks = current_checks();
                checks.source_evidence_matches = false;
                (
                    checks,
                    ReconciliationAuthorityReasonV2::SourceEvidenceMismatch,
                )
            },
            {
                let mut checks = current_checks();
                checks.owner_evidence_matches = false;
                (
                    checks,
                    ReconciliationAuthorityReasonV2::OwnerEvidenceMismatch,
                )
            },
            {
                let mut checks = current_checks();
                checks.person_evidence_matches = false;
                (
                    checks,
                    ReconciliationAuthorityReasonV2::PersonEvidenceMismatch,
                )
            },
            {
                let mut checks = current_checks();
                checks.crop_evidence_matches = false;
                (
                    checks,
                    ReconciliationAuthorityReasonV2::CropEvidenceMismatch,
                )
            },
        ] {
            checks.owner_is_current = false;
            assert_eq!(
                classify_authority(checks),
                (ReconciliationAuthorityStateV2::OpenIneligible, reason)
            );
        }

        let mut checks = current_checks();
        checks.legacy_owner_unverified = true;
        assert_eq!(
            classify_authority(checks),
            (
                ReconciliationAuthorityStateV2::OpenIneligible,
                ReconciliationAuthorityReasonV2::LegacyOwnerUnverified
            )
        );
    }

    fn list_request(
        observation_id: PhotoObservationId,
        state: ReconciliationCaseStateFilterV2,
        cursor: Option<PageCursorV1>,
    ) -> ListReconciliationCasesV2Request {
        ListReconciliationCasesV2Request {
            schema_version: RECONCILIATION_SCHEMA_VERSION_V2,
            request_id: RequestId::new_v4(),
            observation_id,
            state,
            cursor,
            limit: 20,
        }
    }

    fn cursor_revisions() -> Revisions {
        Revisions {
            catalog: 3,
            evidence_generation: 4,
            receipt: 5,
            photo: 6,
            owner: 7,
            reconciliation: 8,
        }
    }

    #[test]
    fn reconciliation_cursor_is_hash_bound_to_snapshot_observation_and_filter() {
        let observation_id = PhotoObservationId::new_v4();
        let request = list_request(
            observation_id,
            ReconciliationCaseStateFilterV2::OpenEligible,
            None,
        );
        let expected = ReconciliationCursorV2 {
            cursor_version: RECONCILIATION_CURSOR_VERSION_V2,
            schema_version: RECONCILIATION_SCHEMA_VERSION_V2,
            observation_id: observation_id.to_string(),
            state: "open_eligible".to_owned(),
            photo_revision: 6,
            owner_revision: 7,
            reconciliation_revision: 8,
            last_created_at_ms: 123,
            last_case_id: ReconciliationCaseId::new_v4().to_string(),
        };
        let encoded = encode_reconciliation_cursor(&expected).unwrap();
        let mut with_cursor = request.clone();
        with_cursor.cursor = Some(encoded.clone());
        assert_eq!(
            parse_reconciliation_cursor(&with_cursor, &cursor_revisions()).unwrap(),
            Some(expected)
        );

        let mut cross_filter = with_cursor.clone();
        cross_filter.state = ReconciliationCaseStateFilterV2::OpenStale;
        assert!(matches!(
            parse_reconciliation_cursor(&cross_filter, &cursor_revisions()),
            Err(PlatformError::InvalidInput("reconciliation_cursor"))
        ));

        let mut cross_observation = with_cursor.clone();
        cross_observation.observation_id = PhotoObservationId::new_v4();
        assert!(matches!(
            parse_reconciliation_cursor(&cross_observation, &cursor_revisions()),
            Err(PlatformError::InvalidInput("reconciliation_cursor"))
        ));

        let mut newer = cursor_revisions();
        newer.owner += 1;
        assert!(matches!(
            parse_reconciliation_cursor(&with_cursor, &newer),
            Err(PlatformError::Conflict("snapshot_expired"))
        ));

        let mut tampered = encoded.as_str().to_owned();
        let final_byte = tampered.pop().unwrap();
        tampered.push(if final_byte == '0' { '1' } else { '0' });
        with_cursor.cursor = Some(PageCursorV1::new(tampered).unwrap());
        assert!(matches!(
            parse_reconciliation_cursor(&with_cursor, &cursor_revisions()),
            Err(PlatformError::InvalidInput("reconciliation_cursor"))
        ));
    }

    #[test]
    fn deferred_case_edges_allow_candidate_first_graph_deletion() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE cases(
                    case_id TEXT PRIMARY KEY,
                    leading_candidate_id TEXT NOT NULL,
                    no_match_candidate_id TEXT NOT NULL,
                    UNIQUE(case_id, leading_candidate_id),
                    UNIQUE(case_id, no_match_candidate_id),
                    FOREIGN KEY(case_id, leading_candidate_id)
                      REFERENCES candidates(case_id, candidate_id)
                      ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
                    FOREIGN KEY(case_id, no_match_candidate_id)
                      REFERENCES candidates(case_id, candidate_id)
                      ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
                 );
                 CREATE TABLE candidates(
                    candidate_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL
                      REFERENCES cases(case_id) ON DELETE RESTRICT,
                    UNIQUE(case_id, candidate_id)
                 );
                 BEGIN;
                 INSERT INTO cases VALUES ('case', 'leading', 'no-match');
                 INSERT INTO candidates VALUES ('leading', 'case');
                 INSERT INTO candidates VALUES ('no-match', 'case');
                 COMMIT;",
            )
            .unwrap();

        let transaction = connection.transaction().unwrap();
        transaction
            .execute("DELETE FROM candidates WHERE case_id = 'case'", [])
            .unwrap();
        transaction
            .execute("DELETE FROM cases WHERE case_id = 'case'", [])
            .unwrap();
        transaction.commit().unwrap();

        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM cases", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM candidates", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
    }
}
