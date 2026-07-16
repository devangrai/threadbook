use serde_json::json;
use wardrobe_core::*;

fn digest(label: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(label)
}

fn visual_evidence(
    feature: CandidateEvidenceFeatureV1,
    measured_value: u16,
    polarity: CandidateEvidencePolarityV1,
) -> CandidateEvidenceV1 {
    CandidateEvidenceV1 {
        evidence_id: ReconciliationEvidenceId::new_v4(),
        polarity,
        relation: IdentityRelationV1::VisualSimilarity,
        feature,
        source_kind: CandidateEvidenceSourceKindV1::CatalogImageEvidence,
        source_id: ReconciliationEvidenceSourceId::new_v4(),
        source_revision: "catalog-revision-4".to_owned(),
        input_sha256: vec![digest(b"photo"), digest(b"catalog")],
        extractor_id: LOCAL_VISUAL_FEATURE_EXTRACTOR_ID_V1.to_owned(),
        extractor_revision: LOCAL_VISUAL_FEATURE_EXTRACTOR_REVISION_V1.to_owned(),
        value_code: EVIDENCE_VALUE_MEASURED_V1.to_owned(),
        measured_value: Some(measured_value),
    }
}

fn receipt_evidence() -> CandidateEvidenceV1 {
    CandidateEvidenceV1 {
        evidence_id: ReconciliationEvidenceId::new_v4(),
        polarity: CandidateEvidencePolarityV1::Contradictory,
        relation: IdentityRelationV1::SameProductVariant,
        feature: CandidateEvidenceFeatureV1::ReceiptEventKind,
        source_kind: CandidateEvidenceSourceKindV1::ReceiptField,
        source_id: ReconciliationEvidenceSourceId::new_v4(),
        source_revision: "receipt-revision-7".to_owned(),
        input_sha256: vec![digest(b"receipt-field")],
        extractor_id: LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_ID_V1.to_owned(),
        extractor_revision: LOCAL_RECEIPT_EVIDENCE_EXTRACTOR_REVISION_V1.to_owned(),
        value_code: EVIDENCE_VALUE_EVENT_RETURN_V1.to_owned(),
        measured_value: None,
    }
}

fn wardrobe_candidate(rank: u8) -> ReconciliationCandidateV1 {
    ReconciliationCandidateV1 {
        candidate_id: ReconciliationCandidateId::new_v4(),
        target: ReconciliationCandidateTargetV1::WardrobeItem {
            item_id: ItemId::new_v4(),
        },
        proposed_relation: Some(IdentityRelationV1::SamePhysicalItem),
        observed_relations: vec![IdentityRelationV1::VisualSimilarity],
        rank: Some(rank),
        display_name: "Blue shirt".to_owned(),
        detail: "Wardrobe item".to_owned(),
        date: Some(ReconciliationCandidateDateV1 {
            kind: ReconciliationCandidateDateKindV1::CatalogCreated,
            value: "2026-07-14T10:30:00Z".to_owned(),
        }),
        evidence: vec![
            visual_evidence(
                CandidateEvidenceFeatureV1::DifferenceHashDistance,
                8,
                CandidateEvidencePolarityV1::Supporting,
            ),
            visual_evidence(
                CandidateEvidenceFeatureV1::MeanColorDistance,
                49,
                CandidateEvidencePolarityV1::Neutral,
            ),
        ],
    }
}

fn receipt_candidate(rank: u8) -> ReconciliationCandidateV1 {
    ReconciliationCandidateV1 {
        candidate_id: ReconciliationCandidateId::new_v4(),
        target: ReconciliationCandidateTargetV1::ReceiptLine {
            order_line_id: ReceiptOrderLineId::new_v4(),
            variant_evidence_id: ReceiptVariantEvidenceId::new_v4(),
        },
        proposed_relation: Some(IdentityRelationV1::SameProductVariant),
        observed_relations: vec![],
        rank: Some(rank),
        display_name: "Blue shirt purchase".to_owned(),
        detail: "Reviewed receipt line".to_owned(),
        date: Some(ReconciliationCandidateDateV1 {
            kind: ReconciliationCandidateDateKindV1::Purchase,
            value: "2026-07-13".to_owned(),
        }),
        evidence: vec![receipt_evidence()],
    }
}

fn no_match_candidate() -> ReconciliationCandidateV1 {
    ReconciliationCandidateV1 {
        candidate_id: ReconciliationCandidateId::new_v4(),
        target: ReconciliationCandidateTargetV1::NoMatch {},
        proposed_relation: None,
        observed_relations: vec![],
        rank: None,
        display_name: "No match".to_owned(),
        detail: "None of these candidates".to_owned(),
        date: None,
        evidence: vec![],
    }
}

fn case() -> ReconciliationCaseV1 {
    let wardrobe = wardrobe_candidate(1);
    let leading_candidate_id = wardrobe.candidate_id;
    ReconciliationCaseV1 {
        case_id: ReconciliationCaseId::new_v4(),
        observation_id: PhotoObservationId::new_v4(),
        artifact_id: PhotoArtifactId::new_v4(),
        artifact_sha256: digest(b"artifact"),
        observation_date: "2026-07-15T05:00:00Z".to_owned(),
        retrieval_revision: RECONCILIATION_RETRIEVAL_REVISION_V1.to_owned(),
        candidates: vec![wardrobe, receipt_candidate(2), no_match_candidate()],
        leading_candidate_id,
        decision_head: None,
        case_revision: 1,
    }
}

fn case_v2(authority_state: ReconciliationAuthorityStateV2) -> ReconciliationCaseV2 {
    let case = case();
    let pinned = authority_state != ReconciliationAuthorityStateV2::OpenIneligible;
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
        owner_decision_id: pinned.then(PhotoOwnerDecisionId::new_v4),
        person_instance_id: pinned.then(PhotoPersonInstanceId::new_v4),
        owner_evidence_sha256: pinned.then(|| digest(b"owner evidence")),
        owner_revision: pinned.then_some(3),
        crop_decision_id: PhotoReviewDecisionId::new_v4(),
        crop_revision: 4,
        source_revision_sha256: digest(b"source revision"),
        authority_state,
        authority_reason: match authority_state {
            ReconciliationAuthorityStateV2::OpenEligible => {
                ReconciliationAuthorityReasonV2::CurrentAuthority
            }
            ReconciliationAuthorityStateV2::OpenStale => {
                ReconciliationAuthorityReasonV2::OwnerDecisionStale
            }
            ReconciliationAuthorityStateV2::OpenIneligible => {
                ReconciliationAuthorityReasonV2::LegacyOwnerUnverified
            }
        },
        created_at_ms: 1_700_000_000_000,
    }
}

#[test]
fn requests_and_targets_decode_strictly() {
    let request = json!({
        "schema_version": 1,
        "request_id": RequestId::new_v4(),
        "observation_id": PhotoObservationId::new_v4(),
        "selected_artifact_id": PhotoArtifactId::new_v4(),
        "expected_photo_revision": 4
    });
    assert!(serde_json::from_value::<OpenReconciliationCaseV1Request>(request.clone()).is_ok());

    let mut unknown = request.clone();
    unknown["provider_id"] = json!("remote-model");
    assert!(serde_json::from_value::<OpenReconciliationCaseV1Request>(unknown).is_err());

    let mut wrong_version = request;
    wrong_version["schema_version"] = json!(2);
    assert!(serde_json::from_value::<OpenReconciliationCaseV1Request>(wrong_version).is_err());

    let target = json!({"kind": "no_match", "item_id": ItemId::new_v4()});
    assert!(serde_json::from_value::<ReconciliationCandidateTargetV1>(target).is_err());
}

#[test]
fn identity_relations_are_distinct_and_bound_to_candidate_targets() {
    assert_ne!(
        serde_json::to_string(&IdentityRelationV1::VisualSimilarity).unwrap(),
        serde_json::to_string(&IdentityRelationV1::SameProductVariant).unwrap()
    );
    assert_ne!(
        IdentityRelationV1::SameProductVariant,
        IdentityRelationV1::SamePhysicalItem
    );

    let mut wardrobe = wardrobe_candidate(1);
    assert!(wardrobe.validate().is_ok());
    wardrobe.proposed_relation = Some(IdentityRelationV1::SameProductVariant);
    assert!(wardrobe.validate().is_err());

    let mut receipt = receipt_candidate(1);
    receipt.observed_relations = vec![IdentityRelationV1::VisualSimilarity];
    assert!(receipt.validate().is_err());

    let mut unsupported_observation = wardrobe_candidate(1);
    unsupported_observation.evidence.clear();
    assert!(unsupported_observation.validate().is_err());
}

#[test]
fn evidence_enforces_versions_sources_values_and_distance_polarity() {
    let supporting = visual_evidence(
        CandidateEvidenceFeatureV1::DifferenceHashDistance,
        8,
        CandidateEvidencePolarityV1::Supporting,
    );
    let neutral = visual_evidence(
        CandidateEvidenceFeatureV1::DifferenceHashDistance,
        9,
        CandidateEvidencePolarityV1::Neutral,
    );
    let contradictory = visual_evidence(
        CandidateEvidenceFeatureV1::DifferenceHashDistance,
        24,
        CandidateEvidencePolarityV1::Contradictory,
    );
    assert!(supporting.validate().is_ok());
    assert!(neutral.validate().is_ok());
    assert!(contradictory.validate().is_ok());

    let mut wrong_polarity = contradictory;
    wrong_polarity.polarity = CandidateEvidencePolarityV1::Supporting;
    assert!(wrong_polarity.validate().is_err());

    let mut missing_parent = supporting;
    missing_parent.input_sha256.clear();
    assert!(missing_parent.validate().is_err());

    let mut free_form_value = receipt_evidence();
    free_form_value.value_code = "model_says_probably_same".to_owned();
    assert!(free_form_value.validate().is_err());
}

#[test]
fn case_requires_contiguous_ranks_and_exactly_one_trailing_no_match() {
    let valid = case();
    assert!(valid.validate().is_ok());

    let mut missing_no_match = valid.clone();
    missing_no_match.candidates.pop();
    assert!(missing_no_match.validate().is_err());

    let mut duplicate_no_match = valid.clone();
    duplicate_no_match.candidates.push(no_match_candidate());
    assert!(duplicate_no_match.validate().is_err());

    let mut skipped_rank = valid.clone();
    skipped_rank.candidates[1].rank = Some(3);
    assert!(skipped_rank.validate().is_err());

    let mut wrong_leader = valid;
    wrong_leader.leading_candidate_id = wrong_leader.candidates[1].candidate_id;
    assert!(wrong_leader.validate().is_err());
}

#[test]
fn all_five_outcomes_have_non_overlapping_selection_rules() {
    let mut case = case();
    let wardrobe_id = case.candidates[0].candidate_id;
    let receipt_id = case.candidates[1].candidate_id;
    let no_match_id = case.candidates[2].candidate_id;

    for (outcome, selected_candidate_id) in [
        (ReconciliationOutcomeV1::SameItem, Some(wardrobe_id)),
        (ReconciliationOutcomeV1::SameVariant, Some(receipt_id)),
        (ReconciliationOutcomeV1::Different, Some(wardrobe_id)),
        (ReconciliationOutcomeV1::NoMatch, Some(no_match_id)),
        (ReconciliationOutcomeV1::Unresolved, None),
    ] {
        let decision = ReconciliationDecisionV1 {
            decision_id: ReconciliationDecisionId::new_v4(),
            case_id: case.case_id,
            outcome,
            selected_candidate_id,
            case_revision: case.case_revision,
        };
        assert!(
            decision.validate_for_case(&case).is_ok(),
            "rejected {outcome:?}"
        );
    }

    for (outcome, selected_candidate_id) in [
        (ReconciliationOutcomeV1::SameItem, Some(receipt_id)),
        (ReconciliationOutcomeV1::SameVariant, Some(wardrobe_id)),
        (ReconciliationOutcomeV1::Different, Some(no_match_id)),
        (ReconciliationOutcomeV1::NoMatch, Some(wardrobe_id)),
        (ReconciliationOutcomeV1::Unresolved, Some(no_match_id)),
    ] {
        let decision = ReconciliationDecisionV1 {
            decision_id: ReconciliationDecisionId::new_v4(),
            case_id: case.case_id,
            outcome,
            selected_candidate_id,
            case_revision: case.case_revision,
        };
        assert!(
            decision.validate_for_case(&case).is_err(),
            "accepted {outcome:?}"
        );
    }

    let decision = ReconciliationDecisionV1 {
        decision_id: ReconciliationDecisionId::new_v4(),
        case_id: case.case_id,
        outcome: ReconciliationOutcomeV1::NoMatch,
        selected_candidate_id: Some(no_match_id),
        case_revision: case.case_revision,
    };
    case.decision_head = Some(decision);
    assert!(case.validate().is_ok());
}

#[test]
fn v1_case_wire_shape_remains_owner_agnostic() {
    let encoded = serde_json::to_value(case()).unwrap();
    let object = encoded.as_object().unwrap();
    assert!(!object.contains_key("owner_decision_id"));
    assert!(!object.contains_key("person_instance_id"));
    assert!(!object.contains_key("authority_state"));
}

#[test]
fn v2_requests_are_strict_and_require_owner_revisions() {
    let request = json!({
        "schema_version": 2,
        "request_id": RequestId::new_v4(),
        "observation_id": PhotoObservationId::new_v4(),
        "selected_artifact_id": PhotoArtifactId::new_v4(),
        "expected_photo_revision": 4,
        "expected_owner_revision": 2
    });
    assert!(serde_json::from_value::<OpenReconciliationCaseV2Request>(request.clone()).is_ok());

    let mut v1 = request.clone();
    v1["schema_version"] = json!(1);
    assert!(serde_json::from_value::<OpenReconciliationCaseV2Request>(v1).is_err());

    let mut unknown = request;
    unknown["owner_name"] = json!("Alice");
    assert!(serde_json::from_value::<OpenReconciliationCaseV2Request>(unknown).is_err());
}

#[test]
fn v2_cases_require_complete_pin_groups_and_truthful_authority_states() {
    let eligible = case_v2(ReconciliationAuthorityStateV2::OpenEligible);
    assert!(eligible.validate().is_ok());

    let legacy = case_v2(ReconciliationAuthorityStateV2::OpenIneligible);
    assert!(legacy.validate().is_ok());

    let mut partial = eligible.clone();
    partial.owner_evidence_sha256 = None;
    assert!(partial.validate().is_err());

    let mut false_eligible = legacy;
    false_eligible.authority_state = ReconciliationAuthorityStateV2::OpenEligible;
    false_eligible.authority_reason = ReconciliationAuthorityReasonV2::CurrentAuthority;
    assert!(false_eligible.validate().is_err());
}

#[test]
fn v2_list_responses_enforce_filter_observation_and_descending_keyset_order() {
    let observation_id = PhotoObservationId::new_v4();
    let mut newest = case_v2(ReconciliationAuthorityStateV2::OpenEligible);
    newest.observation_id = observation_id;
    newest.created_at_ms = 20;
    let mut oldest = case_v2(ReconciliationAuthorityStateV2::OpenEligible);
    oldest.observation_id = observation_id;
    oldest.created_at_ms = 10;
    let mut response = ListReconciliationCasesV2Response {
        schema_version: 2,
        request_id: RequestId::new_v4(),
        observation_id,
        state: ReconciliationCaseStateFilterV2::OpenEligible,
        cases: vec![newest, oldest],
        next_cursor: None,
        photo_revision: 5,
        owner_revision: 3,
        reconciliation_revision: 7,
    };
    assert!(response.validate().is_ok());

    response.cases.reverse();
    assert!(response.validate().is_err());
}
