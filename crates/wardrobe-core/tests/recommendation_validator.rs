use wardrobe_core::*;

#[derive(Clone)]
struct FixtureItem {
    id: ItemId,
    category: ItemCategoryV1,
    tags: Vec<OutfitCapabilityTagV1>,
}

impl FixtureItem {
    fn new(category: ItemCategoryV1, tags: &[OutfitCapabilityTagV1]) -> Self {
        Self {
            id: ItemId::new_v4(),
            category,
            tags: tags.to_vec(),
        }
    }

    fn snapshot(&self) -> OutfitRecommendationSnapshotItemV1 {
        OutfitRecommendationSnapshotItemV1 {
            item_id: self.id,
            item_revision: 1,
            active: true,
            category: self.category,
            capability_tags: self.tags.clone(),
        }
    }
}

fn envelope(
    constraints: OutfitRecommendationConstraintsV1,
    exclusions: Vec<ItemId>,
) -> OutfitRecommendationEnvelopeV1 {
    OutfitRecommendationEnvelopeV1 {
        prompt: "Choose a grounded outfit".to_owned(),
        credential_id: CredentialId::new_v4(),
        constraints,
        excluded_item_ids: exclusions,
        requested_proposal_count: 1,
        expected_catalog_revision: 9,
        expected_outfit_revision: 4,
        retention: OpenAiRetentionDeclarationV1 {
            mode: OpenAiRetentionModeV1::Default,
            provenance: "test-fixture-v1".to_owned(),
        },
    }
}

fn snapshot(items: &[FixtureItem]) -> OutfitRecommendationSnapshotV1 {
    OutfitRecommendationSnapshotV1 {
        catalog_revision: 9,
        outfit_revision: 4,
        capability_revision: OUTFIT_CAPABILITY_REVISION_V1.to_owned(),
        items: items.iter().map(FixtureItem::snapshot).collect(),
    }
}

fn satisfied(kind: OutfitConstraintKindV1) -> OutfitConstraintAssessmentV1 {
    OutfitConstraintAssessmentV1 {
        constraint: kind,
        status: OutfitConstraintStatusV1::Satisfied,
        reason: None,
        caveat: None,
    }
}

fn unresolved(kind: OutfitConstraintKindV1) -> OutfitConstraintAssessmentV1 {
    OutfitConstraintAssessmentV1 {
        constraint: kind,
        status: OutfitConstraintStatusV1::Unresolved,
        reason: Some(OutfitUnresolvedReasonV1::WardrobeCannotSatisfy),
        caveat: Some(OUTFIT_UNSATISFIABLE_CAVEAT_V1.to_owned()),
    }
}

fn result(
    item_ids: Vec<ItemId>,
    assessment: Vec<OutfitConstraintAssessmentV1>,
) -> StructuredOutfitRecommendationV1 {
    let unresolved_constraints = assessment
        .iter()
        .filter(|value| value.status == OutfitConstraintStatusV1::Unresolved)
        .cloned()
        .collect::<Vec<_>>();
    let caveats = if unresolved_constraints.is_empty() {
        vec![]
    } else {
        vec![OUTFIT_UNSATISFIABLE_CAVEAT_V1.to_owned()]
    };
    StructuredOutfitRecommendationV1 {
        schema_revision: OUTFIT_RECOMMENDATION_SCHEMA_REVISION_V1.to_owned(),
        compatibility_revision: OUTFIT_COMPATIBILITY_REVISION_V1.to_owned(),
        capability_revision: OUTFIT_CAPABILITY_REVISION_V1.to_owned(),
        catalog_revision: 9,
        outfit_revision: 4,
        proposals: vec![OutfitProposalV1 {
            name: "Grounded option".to_owned(),
            item_ids,
            rationale: "Every item comes from the immutable snapshot.".to_owned(),
            caveats,
            unresolved_constraints,
            constraint_assessment: assessment,
        }],
    }
}

fn validate(
    constraints: OutfitRecommendationConstraintsV1,
    items: &[FixtureItem],
    selected: &[&FixtureItem],
    assessment: Vec<OutfitConstraintAssessmentV1>,
) -> Result<ValidatedOutfitRecommendationV1, OutfitProposalValidationErrorV1> {
    let envelope = envelope(constraints, vec![]);
    let snapshot = snapshot(items);
    let result = result(selected.iter().map(|item| item.id).collect(), assessment);
    validate_outfit_proposal_v1(&envelope, &snapshot, &result)
}

#[test]
fn every_supported_occasion_has_deterministic_rules() {
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let bottom = FixtureItem::new(ItemCategoryV1::Bottom, &[]);
    let dress = FixtureItem::new(ItemCategoryV1::Dress, &[]);
    let shoes = FixtureItem::new(ItemCategoryV1::Shoes, &[]);
    let activewear = FixtureItem::new(ItemCategoryV1::Activewear, &[]);
    let items = vec![
        top.clone(),
        bottom.clone(),
        dress.clone(),
        shoes.clone(),
        activewear.clone(),
    ];

    let cases = [
        (OutfitOccasionV1::Casual, vec![&top, &bottom]),
        (OutfitOccasionV1::Date, vec![&top, &bottom]),
        (OutfitOccasionV1::Work, vec![&top, &bottom, &shoes]),
        (OutfitOccasionV1::Formal, vec![&dress, &shoes]),
        (OutfitOccasionV1::Active, vec![&activewear, &shoes]),
        (OutfitOccasionV1::Travel, vec![&top, &bottom, &shoes]),
    ];
    for (occasion, selected) in cases {
        let constraints = OutfitRecommendationConstraintsV1 {
            occasion: Some(occasion),
            temperature_c: None,
            precipitation: None,
        };
        assert!(
            validate(
                constraints,
                &items,
                &selected,
                vec![satisfied(OutfitConstraintKindV1::Occasion)]
            )
            .is_ok(),
            "rejected {occasion:?}"
        );
    }
}

#[test]
fn every_temperature_band_has_deterministic_rules() {
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let bottom = FixtureItem::new(ItemCategoryV1::Bottom, &[]);
    let cold_outer = FixtureItem::new(
        ItemCategoryV1::Outerwear,
        &[OutfitCapabilityTagV1::InsulationCold],
    );
    let shoes = FixtureItem::new(ItemCategoryV1::Shoes, &[]);
    let items = vec![
        top.clone(),
        bottom.clone(),
        cold_outer.clone(),
        shoes.clone(),
    ];

    let cases = [
        (-50, vec![&top, &bottom, &cold_outer, &shoes]),
        (0, vec![&top, &bottom, &cold_outer, &shoes]),
        (1, vec![&top, &bottom, &cold_outer]),
        (10, vec![&top, &bottom, &cold_outer]),
        (11, vec![&top, &bottom]),
        (27, vec![&top, &bottom]),
        (28, vec![&top, &bottom]),
        (60, vec![&top, &bottom]),
    ];
    for (temperature_c, selected) in cases {
        let constraints = OutfitRecommendationConstraintsV1 {
            occasion: None,
            temperature_c: Some(temperature_c),
            precipitation: None,
        };
        assert!(
            validate(
                constraints,
                &items,
                &selected,
                vec![satisfied(OutfitConstraintKindV1::Temperature)]
            )
            .is_ok(),
            "rejected {temperature_c} C"
        );
    }
}

#[test]
fn every_precipitation_value_has_deterministic_rules() {
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let bottom = FixtureItem::new(ItemCategoryV1::Bottom, &[]);
    let rain_shoes = FixtureItem::new(ItemCategoryV1::Shoes, &[OutfitCapabilityTagV1::WeatherRain]);
    let snow_outer = FixtureItem::new(
        ItemCategoryV1::Outerwear,
        &[OutfitCapabilityTagV1::WeatherSnow],
    );
    let snow_shoes = FixtureItem::new(ItemCategoryV1::Shoes, &[OutfitCapabilityTagV1::WeatherSnow]);
    let items = vec![
        top.clone(),
        bottom.clone(),
        rain_shoes.clone(),
        snow_outer.clone(),
        snow_shoes.clone(),
    ];
    let cases = [
        (OutfitPrecipitationV1::None, vec![&top, &bottom]),
        (
            OutfitPrecipitationV1::Rain,
            vec![&top, &bottom, &rain_shoes],
        ),
        (
            OutfitPrecipitationV1::Snow,
            vec![&top, &bottom, &snow_outer, &snow_shoes],
        ),
    ];
    for (precipitation, selected) in cases {
        let constraints = OutfitRecommendationConstraintsV1 {
            occasion: None,
            temperature_c: None,
            precipitation: Some(precipitation),
        };
        assert!(
            validate(
                constraints,
                &items,
                &selected,
                vec![satisfied(OutfitConstraintKindV1::Precipitation)]
            )
            .is_ok(),
            "rejected {precipitation:?}"
        );
    }
}

#[test]
fn unknown_inactive_duplicate_excluded_and_stale_ids_fail_closed() {
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let bottom = FixtureItem::new(ItemCategoryV1::Bottom, &[]);
    let items = vec![top.clone(), bottom.clone()];
    let constraints = OutfitRecommendationConstraintsV1 {
        occasion: None,
        temperature_c: None,
        precipitation: None,
    };
    let base_envelope = envelope(constraints.clone(), vec![]);
    let base_snapshot = snapshot(&items);

    let unknown = result(vec![top.id, ItemId::new_v4()], vec![]);
    assert_eq!(
        validate_outfit_proposal_v1(&base_envelope, &base_snapshot, &unknown),
        Err(OutfitProposalValidationErrorV1::UnknownItem)
    );

    let mut inactive_snapshot = base_snapshot.clone();
    inactive_snapshot.items[1].active = false;
    let inactive = result(vec![top.id, bottom.id], vec![]);
    assert_eq!(
        validate_outfit_proposal_v1(&base_envelope, &inactive_snapshot, &inactive),
        Err(OutfitProposalValidationErrorV1::InactiveItem)
    );

    let duplicate = result(vec![top.id, top.id], vec![]);
    assert_eq!(
        validate_outfit_proposal_v1(&base_envelope, &base_snapshot, &duplicate),
        Err(OutfitProposalValidationErrorV1::InvalidContract)
    );

    let excluded_envelope = envelope(constraints, vec![bottom.id]);
    let excluded = result(vec![top.id, bottom.id], vec![]);
    assert_eq!(
        validate_outfit_proposal_v1(&excluded_envelope, &base_snapshot, &excluded),
        Err(OutfitProposalValidationErrorV1::ExcludedItem)
    );

    let mut stale_catalog = result(vec![top.id, bottom.id], vec![]);
    stale_catalog.catalog_revision += 1;
    assert_eq!(
        validate_outfit_proposal_v1(&base_envelope, &base_snapshot, &stale_catalog),
        Err(OutfitProposalValidationErrorV1::StaleCatalogRevision)
    );

    let mut stale_outfit = result(vec![top.id, bottom.id], vec![]);
    stale_outfit.outfit_revision += 1;
    assert_eq!(
        validate_outfit_proposal_v1(&base_envelope, &base_snapshot, &stale_outfit),
        Err(OutfitProposalValidationErrorV1::StaleOutfitRevision)
    );
}

#[test]
fn incompatible_categories_and_hard_availability_have_no_caveat_path() {
    let dress = FixtureItem::new(ItemCategoryV1::Dress, &[]);
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let items = vec![dress.clone(), top.clone()];
    assert_eq!(
        validate(
            OutfitRecommendationConstraintsV1 {
                occasion: None,
                temperature_c: None,
                precipitation: None,
            },
            &items,
            &[&dress, &top],
            vec![]
        ),
        Err(OutfitProposalValidationErrorV1::IncompatibleItems)
    );
}

#[test]
fn satisfiable_constraint_cannot_be_reported_unresolved() {
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let bottom = FixtureItem::new(ItemCategoryV1::Bottom, &[]);
    let shoes = FixtureItem::new(ItemCategoryV1::Shoes, &[]);
    let items = vec![top.clone(), bottom.clone(), shoes];
    let constraints = OutfitRecommendationConstraintsV1 {
        occasion: Some(OutfitOccasionV1::Work),
        temperature_c: None,
        precipitation: None,
    };
    assert_eq!(
        validate(
            constraints,
            &items,
            &[&top, &bottom],
            vec![unresolved(OutfitConstraintKindV1::Occasion)]
        ),
        Err(OutfitProposalValidationErrorV1::SatisfiableConstraintUnmet)
    );
}

#[test]
fn unsatisfiable_constraint_requires_exact_reason_and_caveat() {
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let bottom = FixtureItem::new(ItemCategoryV1::Bottom, &[]);
    let items = vec![top.clone(), bottom.clone()];
    let constraints = OutfitRecommendationConstraintsV1 {
        occasion: Some(OutfitOccasionV1::Work),
        temperature_c: None,
        precipitation: None,
    };
    assert!(validate(
        constraints.clone(),
        &items,
        &[&top, &bottom],
        vec![unresolved(OutfitConstraintKindV1::Occasion)]
    )
    .is_ok());

    let request = envelope(constraints, vec![]);
    let snapshot = snapshot(&items);
    let mut missing_caveat = result(
        vec![top.id, bottom.id],
        vec![unresolved(OutfitConstraintKindV1::Occasion)],
    );
    missing_caveat.proposals[0].caveats.clear();
    assert_eq!(
        validate_outfit_proposal_v1(&request, &snapshot, &missing_caveat),
        Err(OutfitProposalValidationErrorV1::InvalidUnresolvedConstraint)
    );
}

#[test]
fn assessment_must_exactly_match_local_recomputation() {
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let bottom = FixtureItem::new(ItemCategoryV1::Bottom, &[]);
    let items = vec![top.clone(), bottom.clone()];
    let constraints = OutfitRecommendationConstraintsV1 {
        occasion: Some(OutfitOccasionV1::Date),
        temperature_c: Some(20),
        precipitation: None,
    };
    assert_eq!(
        validate(
            constraints,
            &items,
            &[&top, &bottom],
            vec![
                satisfied(OutfitConstraintKindV1::Temperature),
                satisfied(OutfitConstraintKindV1::Occasion),
            ]
        ),
        Err(OutfitProposalValidationErrorV1::ConstraintAssessmentMismatch)
    );
}

#[test]
fn exclusions_are_removed_from_satisfiability_search() {
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let bottom = FixtureItem::new(ItemCategoryV1::Bottom, &[]);
    let shoes = FixtureItem::new(ItemCategoryV1::Shoes, &[]);
    let items = vec![top.clone(), bottom.clone(), shoes.clone()];
    let constraints = OutfitRecommendationConstraintsV1 {
        occasion: Some(OutfitOccasionV1::Work),
        temperature_c: None,
        precipitation: None,
    };
    let request = envelope(constraints, vec![shoes.id]);
    let snapshot = snapshot(&items);
    let proposal = result(
        vec![top.id, bottom.id],
        vec![unresolved(OutfitConstraintKindV1::Occasion)],
    );
    assert!(validate_outfit_proposal_v1(&request, &snapshot, &proposal).is_ok());
}

#[test]
fn combined_constraints_are_checked_against_each_other_for_satisfiability() {
    let top = FixtureItem::new(ItemCategoryV1::Top, &[]);
    let bottom = FixtureItem::new(ItemCategoryV1::Bottom, &[]);
    let cold_outer = FixtureItem::new(
        ItemCategoryV1::Outerwear,
        &[OutfitCapabilityTagV1::InsulationCold],
    );
    let rain_shoes = FixtureItem::new(ItemCategoryV1::Shoes, &[OutfitCapabilityTagV1::WeatherRain]);
    let items = vec![
        top.clone(),
        bottom.clone(),
        cold_outer.clone(),
        rain_shoes.clone(),
    ];
    let constraints = OutfitRecommendationConstraintsV1 {
        occasion: Some(OutfitOccasionV1::Travel),
        temperature_c: Some(0),
        precipitation: Some(OutfitPrecipitationV1::Rain),
    };
    assert!(validate(
        constraints,
        &items,
        &[&top, &bottom, &cold_outer, &rain_shoes],
        vec![
            satisfied(OutfitConstraintKindV1::Occasion),
            satisfied(OutfitConstraintKindV1::Temperature),
            satisfied(OutfitConstraintKindV1::Precipitation),
        ]
    )
    .is_ok());
}
