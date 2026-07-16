use std::cell::Cell;

use wardrobe_core::*;

fn no_match_case(
    observation_id: PhotoObservationId,
    artifact_id: PhotoArtifactId,
) -> ReconciliationCaseV1 {
    let candidate = ReconciliationCandidateV1 {
        candidate_id: ReconciliationCandidateId::new_v4(),
        target: ReconciliationCandidateTargetV1::NoMatch {},
        proposed_relation: None,
        observed_relations: vec![],
        rank: None,
        display_name: "No match".to_owned(),
        detail: "No local candidates".to_owned(),
        date: None,
        evidence: vec![],
    };
    ReconciliationCaseV1 {
        case_id: ReconciliationCaseId::new_v4(),
        observation_id,
        artifact_id,
        artifact_sha256: Sha256Digest::from_bytes(b"artifact"),
        observation_date: "2026-07-15T05:00:00Z".to_owned(),
        retrieval_revision: RECONCILIATION_RETRIEVAL_REVISION_V1.to_owned(),
        leading_candidate_id: candidate.candidate_id,
        candidates: vec![candidate],
        decision_head: None,
        case_revision: 1,
    }
}

fn no_match_case_v2(
    observation_id: PhotoObservationId,
    artifact_id: PhotoArtifactId,
) -> ReconciliationCaseV2 {
    let case = no_match_case(observation_id, artifact_id);
    ReconciliationCaseV2 {
        case_id: case.case_id,
        observation_id: case.observation_id,
        artifact_id: case.artifact_id,
        artifact_sha256: case.artifact_sha256,
        observation_date: case.observation_date,
        retrieval_revision: case.retrieval_revision,
        candidates: case.candidates,
        leading_candidate_id: case.leading_candidate_id,
        decision_head: case.decision_head,
        case_revision: case.case_revision,
        owner_decision_id: Some(PhotoOwnerDecisionId::new_v4()),
        person_instance_id: Some(PhotoPersonInstanceId::new_v4()),
        owner_evidence_sha256: Some(Sha256Digest::from_bytes(b"owner evidence")),
        owner_revision: Some(2),
        crop_decision_id: PhotoReviewDecisionId::new_v4(),
        crop_revision: 4,
        source_revision_sha256: Sha256Digest::from_bytes(b"source revision"),
        authority_state: ReconciliationAuthorityStateV2::OpenEligible,
        authority_reason: ReconciliationAuthorityReasonV2::CurrentAuthority,
        created_at_ms: 1_700_000_000_000,
    }
}

struct Repository {
    open_calls: Cell<u32>,
    decide_calls: Cell<u32>,
    v2_calls: [Cell<u32>; 3],
    corrupt_open: bool,
    error: Option<ReconciliationPortError>,
}

impl Repository {
    fn working() -> Self {
        Self {
            open_calls: Cell::new(0),
            decide_calls: Cell::new(0),
            v2_calls: std::array::from_fn(|_| Cell::new(0)),
            corrupt_open: false,
            error: None,
        }
    }
}

impl ReconciliationPort for Repository {
    fn open_reconciliation_case(
        &self,
        request: &OpenReconciliationCaseV1Request,
    ) -> ReconciliationPortResult<OpenReconciliationCaseV1Response> {
        self.open_calls.set(self.open_calls.get() + 1);
        if let Some(error) = self.error {
            return Err(error);
        }
        let artifact_id = if self.corrupt_open {
            PhotoArtifactId::new_v4()
        } else {
            request.selected_artifact_id
        };
        Ok(OpenReconciliationCaseV1Response {
            schema_version: 1,
            request_id: request.request_id,
            case: no_match_case(request.observation_id, artifact_id),
            evidence_generation: 9,
            reconciliation_revision: 1,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn decide_reconciliation_case(
        &self,
        request: &DecideReconciliationCaseV1Request,
    ) -> ReconciliationPortResult<DecideReconciliationCaseV1Response> {
        self.decide_calls.set(self.decide_calls.get() + 1);
        if let Some(error) = self.error {
            return Err(error);
        }
        let observation_id = PhotoObservationId::new_v4();
        let artifact_id = PhotoArtifactId::new_v4();
        let mut case = no_match_case(observation_id, artifact_id);
        case.case_id = request.case_id;
        case.case_revision = request.expected_case_revision + 1;
        case.candidates[0].candidate_id = request.selected_candidate_id.unwrap();
        case.leading_candidate_id = case.candidates[0].candidate_id;
        let decision = ReconciliationDecisionV1 {
            decision_id: ReconciliationDecisionId::new_v4(),
            case_id: request.case_id,
            outcome: request.outcome,
            selected_candidate_id: request.selected_candidate_id,
            case_revision: case.case_revision,
        };
        case.decision_head = Some(decision.clone());
        Ok(DecideReconciliationCaseV1Response {
            schema_version: 1,
            request_id: request.request_id,
            case,
            decision,
            reconciliation_revision: 2,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn open_reconciliation_case_v2(
        &self,
        request: &OpenReconciliationCaseV2Request,
    ) -> ReconciliationPortResult<OpenReconciliationCaseV2Response> {
        self.v2_calls[0].set(self.v2_calls[0].get() + 1);
        Ok(OpenReconciliationCaseV2Response {
            schema_version: 2,
            request_id: request.request_id,
            case: no_match_case_v2(request.observation_id, request.selected_artifact_id),
            evidence_generation: 9,
            photo_revision: request.expected_photo_revision,
            owner_revision: request.expected_owner_revision,
            reconciliation_revision: 3,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn decide_reconciliation_case_v2(
        &self,
        request: &DecideReconciliationCaseV2Request,
    ) -> ReconciliationPortResult<DecideReconciliationCaseV2Response> {
        self.v2_calls[1].set(self.v2_calls[1].get() + 1);
        let mut case = no_match_case_v2(PhotoObservationId::new_v4(), PhotoArtifactId::new_v4());
        case.case_id = request.case_id;
        case.case_revision = request.expected_case_revision + 1;
        case.owner_revision = Some(request.expected_owner_revision);
        case.candidates[0].candidate_id = request.selected_candidate_id.unwrap();
        case.leading_candidate_id = case.candidates[0].candidate_id;
        let decision = ReconciliationDecisionV1 {
            decision_id: ReconciliationDecisionId::new_v4(),
            case_id: request.case_id,
            outcome: request.outcome,
            selected_candidate_id: request.selected_candidate_id,
            case_revision: case.case_revision,
        };
        case.decision_head = Some(decision.clone());
        Ok(DecideReconciliationCaseV2Response {
            schema_version: 2,
            request_id: request.request_id,
            case,
            decision,
            photo_revision: request.expected_photo_revision,
            owner_revision: request.expected_owner_revision,
            reconciliation_revision: request.expected_reconciliation_revision + 1,
            replay_status: ReplayStatusV1::Created,
        })
    }

    fn list_reconciliation_cases_v2(
        &self,
        request: &ListReconciliationCasesV2Request,
    ) -> ReconciliationPortResult<ListReconciliationCasesV2Response> {
        self.v2_calls[2].set(self.v2_calls[2].get() + 1);
        Ok(ListReconciliationCasesV2Response {
            schema_version: 2,
            request_id: request.request_id,
            observation_id: request.observation_id,
            state: request.state,
            cases: vec![no_match_case_v2(
                request.observation_id,
                PhotoArtifactId::new_v4(),
            )],
            next_cursor: None,
            photo_revision: 4,
            owner_revision: 2,
            reconciliation_revision: 3,
        })
    }
}

#[test]
fn service_opens_and_decides_through_the_reconciliation_port() {
    let observation_id = PhotoObservationId::new_v4();
    let artifact_id = PhotoArtifactId::new_v4();
    let service = ApplicationService::new(Repository::working(), (), ());

    let opened = service
        .open_reconciliation_case_v1(OpenReconciliationCaseV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            observation_id,
            selected_artifact_id: artifact_id,
            expected_photo_revision: 4,
        })
        .unwrap();
    assert_eq!(opened.case.observation_id, observation_id);
    assert_eq!(service.database().open_calls.get(), 1);

    let no_match_id = opened.case.candidates[0].candidate_id;
    let decided = service
        .decide_reconciliation_case_v1(DecideReconciliationCaseV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            case_id: opened.case.case_id,
            outcome: ReconciliationOutcomeV1::NoMatch,
            selected_candidate_id: Some(no_match_id),
            expected_case_revision: opened.case.case_revision,
        })
        .unwrap();
    assert_eq!(decided.case.decision_head.as_ref(), Some(&decided.decision));
    assert_eq!(service.database().decide_calls.get(), 1);
}

#[test]
fn invalid_requests_are_rejected_before_calling_the_port() {
    let service = ApplicationService::new(Repository::working(), (), ());
    let error = service
        .decide_reconciliation_case_v1(DecideReconciliationCaseV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            case_id: ReconciliationCaseId::new_v4(),
            outcome: ReconciliationOutcomeV1::Unresolved,
            selected_candidate_id: Some(ReconciliationCandidateId::new_v4()),
            expected_case_revision: 1,
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::InvalidRequest);
    assert_eq!(service.database().decide_calls.get(), 0);
}

#[test]
fn malformed_port_responses_fail_closed() {
    let repository = Repository {
        corrupt_open: true,
        ..Repository::working()
    };
    let service = ApplicationService::new(repository, (), ());
    let error = service
        .open_reconciliation_case_v1(OpenReconciliationCaseV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            observation_id: PhotoObservationId::new_v4(),
            selected_artifact_id: PhotoArtifactId::new_v4(),
            expected_photo_revision: 4,
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::DataIntegrity);
}

#[test]
fn reconciliation_port_errors_map_to_stable_command_errors() {
    let repository = Repository {
        error: Some(ReconciliationPortError::new(
            ReconciliationPortErrorKind::Conflict,
        )),
        ..Repository::working()
    };
    let service = ApplicationService::new(repository, (), ());
    let error = service
        .open_reconciliation_case_v1(OpenReconciliationCaseV1Request {
            schema_version: 1,
            request_id: RequestId::new_v4(),
            observation_id: PhotoObservationId::new_v4(),
            selected_artifact_id: PhotoArtifactId::new_v4(),
            expected_photo_revision: 4,
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCodeV1::RequestConflict);
    assert!(error.retryable);
}

#[test]
fn service_forwards_and_checks_reconciliation_v2_commands() {
    let service = ApplicationService::new(Repository::working(), (), ());
    let observation_id = PhotoObservationId::new_v4();
    let artifact_id = PhotoArtifactId::new_v4();
    let opened = service
        .open_reconciliation_case_v2(OpenReconciliationCaseV2Request {
            schema_version: 2,
            request_id: RequestId::new_v4(),
            observation_id,
            selected_artifact_id: artifact_id,
            expected_photo_revision: 4,
            expected_owner_revision: 2,
        })
        .unwrap();
    let no_match_id = opened.case.candidates[0].candidate_id;
    service
        .decide_reconciliation_case_v2(DecideReconciliationCaseV2Request {
            schema_version: 2,
            request_id: RequestId::new_v4(),
            case_id: opened.case.case_id,
            outcome: ReconciliationOutcomeV1::NoMatch,
            selected_candidate_id: Some(no_match_id),
            expected_case_revision: opened.case.case_revision,
            expected_owner_revision: 2,
            expected_photo_revision: 4,
            expected_reconciliation_revision: 3,
        })
        .unwrap();
    service
        .list_reconciliation_cases_v2(ListReconciliationCasesV2Request {
            schema_version: 2,
            request_id: RequestId::new_v4(),
            observation_id,
            state: ReconciliationCaseStateFilterV2::OpenEligible,
            cursor: None,
            limit: 10,
        })
        .unwrap();
    assert_eq!(
        service
            .database()
            .v2_calls
            .each_ref()
            .map(|call| call.get()),
        [1; 3]
    );
}
