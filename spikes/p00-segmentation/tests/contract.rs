use p00_segmentation::candidate::{
    CandidateAvailability, CandidateRegistry, CandidateRole, AUTOMATIC_CANDIDATE_ID,
};
use p00_segmentation::contract::{validate_outcome, RequestHandle, SegmentationOutcome};
use p00_segmentation::dataset::{CaseScope, SyntheticDataset};
use p00_segmentation::fallback::rectangle_uniform_background_v1;

#[test]
fn composed_fallback_exercises_real_corpus_paths_end_to_end() {
    let dataset = SyntheticDataset::public_contract();
    dataset.validate().unwrap();

    let registry = CandidateRegistry::reviewed_state();
    registry.validate().unwrap();
    let slot = &registry.candidates[0];
    assert_eq!(slot.candidate_id, AUTOMATIC_CANDIDATE_ID);
    assert_eq!(slot.role, CandidateRole::PlannedProviderSlot);
    assert_eq!(slot.availability, CandidateAvailability::Unavailable);
    assert_eq!(slot.source_locator, None);
    assert_eq!(slot.model_revision, None);
    assert_eq!(slot.license_decision, None);
    assert_eq!(slot.measurements, None);

    let cases = [
        (80, CaseScope::TargetPerson, true),
        (176, CaseScope::FullImage, true),
        (224, CaseScope::TargetPerson, false),
        (240, CaseScope::FullImage, false),
    ];

    for (ordinal, expected_scope, has_garment) in cases {
        let case = &dataset.cases[ordinal];
        assert_eq!(case.scope, expected_scope);
        assert_eq!(!case.truths.is_empty(), has_garment);

        let request = case
            .provider_request(RequestHandle::parse(format!("fallback-case-{ordinal:04}")).unwrap())
            .unwrap();
        let first = rectangle_uniform_background_v1(&request.pixels);
        let second = rectangle_uniform_background_v1(&request.pixels);

        assert_eq!(first, second);
        validate_outcome(&first, &request).unwrap();
        match (has_garment, first) {
            (true, SegmentationOutcome::FallbackMask { mask, needs_review }) => {
                assert!(needs_review);
                assert_eq!(mask.width, request.pixels.width());
                assert_eq!(mask.height, request.pixels.height());
                mask.validate().unwrap();
            }
            (
                false,
                SegmentationOutcome::FallbackCrop {
                    rectangle,
                    needs_review,
                },
            ) => {
                assert!(needs_review);
                assert_eq!(rectangle.x, 0);
                assert_eq!(rectangle.y, 0);
                assert_eq!(rectangle.width, request.pixels.width());
                assert_eq!(rectangle.height, request.pixels.height());
            }
            (_, outcome) => panic!("unexpected fallback outcome for case {ordinal}: {outcome:?}"),
        }
    }
}
