ALTER TABLE revision_state
ADD COLUMN reconciliation_revision INTEGER NOT NULL DEFAULT 0
CHECK (reconciliation_revision BETWEEN 0 AND 9007199254740990);

ALTER TABLE deletion_previews
ADD COLUMN reconciliation_revision INTEGER NOT NULL DEFAULT 0
CHECK (reconciliation_revision BETWEEN 0 AND 9007199254740990);

CREATE UNIQUE INDEX reconciliation_receipt_variant_line_idx
    ON receipt_variant_evidence(variant_evidence_id, order_line_id);
CREATE UNIQUE INDEX reconciliation_photo_decision_artifact_idx
    ON photo_review_decisions(
        decision_id, observation_id, selected_artifact_id, photo_revision
    );

CREATE TABLE reconciliation_cases (
    case_id TEXT PRIMARY KEY CHECK (
        length(case_id) = 36
        AND case_id <> '00000000-0000-0000-0000-000000000000'
    ),
    observation_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    source_revision_id TEXT NOT NULL,
    source_revision_sha256 TEXT NOT NULL CHECK (
        length(source_revision_sha256) = 64
        AND source_revision_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_sha256 TEXT NOT NULL CHECK (
        length(artifact_sha256) = 64
        AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    photo_decision_id TEXT NOT NULL,
    photo_revision INTEGER NOT NULL CHECK (
        photo_revision BETWEEN 1 AND 9007199254740990
    ),
    catalog_revision INTEGER NOT NULL CHECK (
        catalog_revision BETWEEN 0 AND 9007199254740990
    ),
    receipt_revision INTEGER NOT NULL CHECK (
        receipt_revision BETWEEN 0 AND 9007199254740990
    ),
    retrieval_revision TEXT NOT NULL CHECK (
        length(retrieval_revision) BETWEEN 1 AND 128
        AND retrieval_revision NOT GLOB '*[^ -~]*'
    ),
    observation_date TEXT NOT NULL CHECK (
        length(observation_date) BETWEEN 1 AND 64
        AND observation_date NOT GLOB '*[^ -~]*'
    ),
    leading_candidate_id TEXT NOT NULL,
    no_match_candidate_id TEXT NOT NULL,
    case_revision INTEGER NOT NULL CHECK (case_revision = 1),
    reconciliation_revision INTEGER NOT NULL UNIQUE CHECK (
        reconciliation_revision BETWEEN 1 AND 9007199254740990
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(observation_id, artifact_id, retrieval_revision),
    UNIQUE(case_id, observation_id, artifact_id),
    UNIQUE(case_id, leading_candidate_id),
    UNIQUE(case_id, no_match_candidate_id),
    FOREIGN KEY(observation_id, scope_id, source_revision_id)
        REFERENCES photo_observations(
            observation_id, scope_id, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(artifact_id, scope_id, source_revision_id)
        REFERENCES photo_artifacts(
            artifact_id, scope_id, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(
        photo_decision_id, observation_id, artifact_id, photo_revision
    ) REFERENCES photo_review_decisions(
        decision_id, observation_id, selected_artifact_id, photo_revision
    ) ON DELETE RESTRICT,
    FOREIGN KEY(case_id, leading_candidate_id)
        REFERENCES reconciliation_candidates(case_id, candidate_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(case_id, no_match_candidate_id)
        REFERENCES reconciliation_candidates(case_id, candidate_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE reconciliation_candidates (
    candidate_id TEXT PRIMARY KEY CHECK (
        length(candidate_id) = 36
        AND candidate_id <> '00000000-0000-0000-0000-000000000000'
    ),
    case_id TEXT NOT NULL
        REFERENCES reconciliation_cases(case_id) ON DELETE RESTRICT,
    target_kind TEXT NOT NULL CHECK (
        target_kind IN ('no_match', 'wardrobe_item', 'receipt_line')
    ),
    target_item_id TEXT
        REFERENCES catalog_items(item_id) ON DELETE RESTRICT,
    target_order_line_id TEXT
        REFERENCES receipt_order_lines(order_line_id) ON DELETE RESTRICT,
    target_variant_evidence_id TEXT
        REFERENCES receipt_variant_evidence(variant_evidence_id)
        ON DELETE RESTRICT,
    proposed_relation TEXT CHECK (
        proposed_relation IS NULL
        OR proposed_relation IN (
            'same_product_variant', 'same_physical_item'
        )
    ),
    rank INTEGER CHECK (rank IS NULL OR rank BETWEEN 1 AND 6),
    display_name TEXT NOT NULL CHECK (
        length(display_name) BETWEEN 1 AND 120
    ),
    detail TEXT NOT NULL CHECK (
        length(detail) BETWEEN 1 AND 240
    ),
    date_kind TEXT CHECK (
        date_kind IS NULL OR date_kind IN ('catalog_created', 'purchase')
    ),
    date_value TEXT CHECK (
        date_value IS NULL
        OR (
            length(date_value) BETWEEN 1 AND 64
            AND date_value NOT GLOB '*[^ -~]*'
        )
    ),
    reconciliation_revision INTEGER NOT NULL CHECK (
        reconciliation_revision BETWEEN 1 AND 9007199254740990
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK ((date_kind IS NULL) = (date_value IS NULL)),
    CHECK (
        (target_kind = 'no_match'
            AND target_item_id IS NULL
            AND target_order_line_id IS NULL
            AND target_variant_evidence_id IS NULL
            AND proposed_relation IS NULL
            AND rank IS NULL)
        OR
        (target_kind = 'wardrobe_item'
            AND target_item_id IS NOT NULL
            AND target_order_line_id IS NULL
            AND target_variant_evidence_id IS NULL
            AND proposed_relation = 'same_physical_item'
            AND rank IS NOT NULL)
        OR
        (target_kind = 'receipt_line'
            AND target_item_id IS NULL
            AND target_order_line_id IS NOT NULL
            AND target_variant_evidence_id IS NOT NULL
            AND proposed_relation = 'same_product_variant'
            AND rank IS NOT NULL)
    ),
    UNIQUE(case_id, candidate_id),
    UNIQUE(case_id, rank),
    FOREIGN KEY(target_variant_evidence_id, target_order_line_id)
        REFERENCES receipt_variant_evidence(
            variant_evidence_id, order_line_id
        ) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX reconciliation_candidates_no_match_idx
    ON reconciliation_candidates(case_id)
    WHERE target_kind = 'no_match';
CREATE UNIQUE INDEX reconciliation_candidates_item_idx
    ON reconciliation_candidates(case_id, target_item_id)
    WHERE target_kind = 'wardrobe_item';
CREATE UNIQUE INDEX reconciliation_candidates_receipt_idx
    ON reconciliation_candidates(
        case_id, target_order_line_id, target_variant_evidence_id
    ) WHERE target_kind = 'receipt_line';

CREATE TABLE reconciliation_candidate_evidence (
    evidence_id TEXT PRIMARY KEY CHECK (
        length(evidence_id) = 36
        AND evidence_id <> '00000000-0000-0000-0000-000000000000'
    ),
    candidate_id TEXT NOT NULL
        REFERENCES reconciliation_candidates(candidate_id) ON DELETE RESTRICT,
    polarity TEXT NOT NULL CHECK (
        polarity IN ('supporting', 'contradictory', 'neutral')
    ),
    relation TEXT NOT NULL CHECK (
        relation IN (
            'visual_similarity', 'same_product_variant',
            'same_physical_item'
        )
    ),
    feature TEXT NOT NULL CHECK (
        feature IN (
            'difference_hash_distance', 'mean_color_distance',
            'catalog_image_status', 'receipt_review_state',
            'receipt_event_kind', 'purchase_chronology',
            'extracted_receipt_provenance'
        )
    ),
    source_kind TEXT NOT NULL CHECK (
        source_kind IN (
            'photo_artifact', 'catalog_image_evidence',
            'catalog_decision', 'receipt_field',
            'receipt_review_decision'
        )
    ),
    source_id TEXT NOT NULL CHECK (
        length(source_id) = 36
        AND source_id <> '00000000-0000-0000-0000-000000000000'
    ),
    source_revision TEXT NOT NULL CHECK (
        length(source_revision) BETWEEN 1 AND 128
        AND source_revision NOT GLOB '*[^ -~]*'
    ),
    extractor_id TEXT NOT NULL CHECK (
        length(extractor_id) BETWEEN 1 AND 128
        AND extractor_id NOT GLOB '*[^ -~]*'
    ),
    extractor_revision TEXT NOT NULL CHECK (
        length(extractor_revision) BETWEEN 1 AND 128
        AND extractor_revision NOT GLOB '*[^ -~]*'
    ),
    value_code TEXT NOT NULL CHECK (
        value_code IN (
            'measured', 'catalog_image_absent', 'catalog_image_unavailable',
            'catalog_image_corrupt', 'receipt_confirmed',
            'receipt_corrected', 'event_purchase',
            'event_exchange', 'event_return', 'event_unknown',
            'purchase_before_observation', 'purchase_after_observation',
            'purchase_date_unknown', 'extracted_receipt',
            'corrected_unchanged', 'corrected_changed',
            'corrected_unknown'
        )
    ),
    measured_value INTEGER CHECK (
        measured_value IS NULL OR measured_value BETWEEN 0 AND 765
    ),
    reconciliation_revision INTEGER NOT NULL CHECK (
        reconciliation_revision BETWEEN 1 AND 9007199254740990
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        (feature = 'difference_hash_distance'
            AND relation = 'visual_similarity'
            AND measured_value BETWEEN 0 AND 64
            AND (
                (measured_value <= 8
                    AND polarity = 'supporting'
                    AND value_code = 'measured')
                OR
                (measured_value BETWEEN 9 AND 23
                    AND polarity = 'neutral'
                    AND value_code = 'measured')
                OR
                (measured_value BETWEEN 24 AND 64
                    AND polarity = 'contradictory'
                    AND value_code = 'measured')
            ))
        OR
        (feature = 'mean_color_distance'
            AND relation = 'visual_similarity'
            AND measured_value BETWEEN 0 AND 765
            AND (
                (measured_value <= 48
                    AND polarity = 'supporting'
                    AND value_code = 'measured')
                OR
                (measured_value BETWEEN 49 AND 191
                    AND polarity = 'neutral'
                    AND value_code = 'measured')
                OR
                (measured_value BETWEEN 192 AND 765
                    AND polarity = 'contradictory'
                    AND value_code = 'measured')
            ))
        OR
        (feature = 'catalog_image_status'
            AND relation = 'visual_similarity'
            AND polarity = 'neutral'
            AND measured_value IS NULL
            AND value_code IN (
                'catalog_image_absent', 'catalog_image_unavailable',
                'catalog_image_corrupt'
            ))
        OR
        (feature = 'receipt_review_state'
            AND relation = 'same_product_variant'
            AND polarity = 'neutral'
            AND measured_value IS NULL
            AND value_code IN ('receipt_confirmed', 'receipt_corrected'))
        OR
        (feature = 'receipt_event_kind'
            AND relation = 'same_product_variant'
            AND measured_value IS NULL
            AND (
                (polarity = 'neutral'
                    AND value_code IN (
                        'event_purchase', 'event_exchange',
                        'event_unknown'
                    ))
                OR
                (polarity = 'contradictory'
                    AND value_code = 'event_return')
            ))
        OR
        (feature = 'purchase_chronology'
            AND relation = 'same_product_variant'
            AND measured_value IS NULL
            AND (
                (polarity = 'neutral'
                    AND value_code IN (
                        'purchase_before_observation',
                        'purchase_date_unknown'
                    ))
                OR
                (polarity = 'contradictory'
                    AND value_code = 'purchase_after_observation')
            ))
        OR
        (feature = 'extracted_receipt_provenance'
            AND relation = 'same_product_variant'
            AND polarity = 'neutral'
            AND measured_value IS NULL
            AND value_code IN (
                'extracted_receipt', 'corrected_unchanged',
                'corrected_changed', 'corrected_unknown'
            ))
    ),
    UNIQUE(
        candidate_id, feature, source_kind, source_id, source_revision
    ),
    UNIQUE(candidate_id, evidence_id)
) STRICT;

CREATE TABLE reconciliation_evidence_input_hashes (
    evidence_id TEXT NOT NULL
        REFERENCES reconciliation_candidate_evidence(evidence_id)
        ON DELETE RESTRICT,
    input_ordinal INTEGER NOT NULL CHECK (input_ordinal IN (0, 1)),
    input_sha256 TEXT NOT NULL CHECK (
        length(input_sha256) = 64
        AND input_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    reconciliation_revision INTEGER NOT NULL CHECK (
        reconciliation_revision BETWEEN 1 AND 9007199254740990
    ),
    PRIMARY KEY(evidence_id, input_ordinal),
    UNIQUE(evidence_id, input_sha256)
) STRICT;

CREATE TABLE reconciliation_decisions (
    decision_id TEXT PRIMARY KEY CHECK (
        length(decision_id) = 36
        AND decision_id <> '00000000-0000-0000-0000-000000000000'
    ),
    case_id TEXT NOT NULL
        REFERENCES reconciliation_cases(case_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    outcome TEXT NOT NULL CHECK (
        outcome IN (
            'same_item', 'same_variant', 'different',
            'no_match', 'unresolved'
        )
    ),
    selected_candidate_id TEXT,
    expected_case_revision INTEGER NOT NULL CHECK (
        expected_case_revision BETWEEN 1 AND 9007199254740989
    ),
    case_revision INTEGER NOT NULL CHECK (
        case_revision BETWEEN 2 AND 9007199254740990
        AND case_revision = expected_case_revision + 1
    ),
    reconciliation_revision INTEGER NOT NULL UNIQUE CHECK (
        reconciliation_revision BETWEEN 1 AND 9007199254740990
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        (outcome = 'unresolved' AND selected_candidate_id IS NULL)
        OR (outcome <> 'unresolved' AND selected_candidate_id IS NOT NULL)
    ),
    UNIQUE(case_id, case_revision),
    UNIQUE(decision_id, case_id, case_revision),
    FOREIGN KEY(case_id, selected_candidate_id)
        REFERENCES reconciliation_candidates(case_id, candidate_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE reconciliation_decision_heads (
    case_id TEXT PRIMARY KEY
        REFERENCES reconciliation_cases(case_id) ON DELETE RESTRICT,
    decision_id TEXT NOT NULL UNIQUE
        REFERENCES reconciliation_decisions(decision_id) ON DELETE RESTRICT,
    case_revision INTEGER NOT NULL CHECK (
        case_revision BETWEEN 2 AND 9007199254740990
    ),
    reconciliation_revision INTEGER NOT NULL CHECK (
        reconciliation_revision BETWEEN 1 AND 9007199254740990
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    UNIQUE(case_id, decision_id, case_revision),
    FOREIGN KEY(decision_id, case_id, case_revision)
        REFERENCES reconciliation_decisions(
            decision_id, case_id, case_revision
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE reconciliation_command_entities (
    request_id TEXT NOT NULL
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('case', 'decision')),
    entity_id TEXT NOT NULL CHECK (
        length(entity_id) = 36
        AND entity_id <> '00000000-0000-0000-0000-000000000000'
    ),
    reconciliation_revision INTEGER NOT NULL CHECK (
        reconciliation_revision BETWEEN 1 AND 9007199254740990
    ),
    PRIMARY KEY(request_id, entity_kind, entity_id)
) STRICT;

CREATE INDEX reconciliation_cases_observation_idx
    ON reconciliation_cases(observation_id, artifact_id, case_id);
CREATE INDEX reconciliation_cases_source_revision_idx
    ON reconciliation_cases(source_revision_id, case_id);
CREATE INDEX reconciliation_candidates_case_rank_idx
    ON reconciliation_candidates(case_id, rank, candidate_id);
CREATE INDEX reconciliation_candidates_item_target_idx
    ON reconciliation_candidates(target_item_id, case_id)
    WHERE target_kind = 'wardrobe_item';
CREATE INDEX reconciliation_candidates_receipt_target_idx
    ON reconciliation_candidates(target_order_line_id, case_id)
    WHERE target_kind = 'receipt_line';
CREATE INDEX reconciliation_evidence_candidate_idx
    ON reconciliation_candidate_evidence(
        candidate_id, polarity, feature, evidence_id
    );
CREATE INDEX reconciliation_decisions_case_idx
    ON reconciliation_decisions(case_id, case_revision, decision_id);
CREATE INDEX reconciliation_command_entities_entity_idx
    ON reconciliation_command_entities(
        entity_kind, entity_id, request_id
    );

CREATE TRIGGER reconciliation_decisions_validate_insert
BEFORE INSERT ON reconciliation_decisions
WHEN NOT (
    (NEW.outcome = 'unresolved' AND NEW.selected_candidate_id IS NULL)
    OR
    (NEW.outcome = 'same_item' AND EXISTS (
        SELECT 1 FROM reconciliation_candidates candidate
        WHERE candidate.case_id = NEW.case_id
          AND candidate.candidate_id = NEW.selected_candidate_id
          AND candidate.target_kind = 'wardrobe_item'
          AND candidate.proposed_relation = 'same_physical_item'
    ))
    OR
    (NEW.outcome = 'same_variant' AND EXISTS (
        SELECT 1 FROM reconciliation_candidates candidate
        WHERE candidate.case_id = NEW.case_id
          AND candidate.candidate_id = NEW.selected_candidate_id
          AND candidate.target_kind = 'receipt_line'
          AND candidate.proposed_relation = 'same_product_variant'
    ))
    OR
    (NEW.outcome = 'different' AND EXISTS (
        SELECT 1 FROM reconciliation_candidates candidate
        WHERE candidate.case_id = NEW.case_id
          AND candidate.candidate_id = NEW.selected_candidate_id
          AND candidate.target_kind <> 'no_match'
    ))
    OR
    (NEW.outcome = 'no_match' AND EXISTS (
        SELECT 1 FROM reconciliation_cases reconciliation_case
        JOIN reconciliation_candidates candidate
          ON candidate.case_id = reconciliation_case.case_id
         AND candidate.candidate_id =
             reconciliation_case.no_match_candidate_id
        WHERE reconciliation_case.case_id = NEW.case_id
          AND candidate.candidate_id = NEW.selected_candidate_id
          AND candidate.target_kind = 'no_match'
    ))
)
BEGIN
    SELECT RAISE(ABORT, 'reconciliation decision is invalid');
END;

CREATE TRIGGER reconciliation_decision_heads_validate_insert
BEFORE INSERT ON reconciliation_decision_heads
WHEN NOT EXISTS (
    SELECT 1 FROM reconciliation_decisions decision
    WHERE decision.decision_id = NEW.decision_id
      AND decision.case_id = NEW.case_id
      AND decision.case_revision = NEW.case_revision
      AND decision.reconciliation_revision = NEW.reconciliation_revision
)
BEGIN
    SELECT RAISE(ABORT, 'reconciliation decision head is invalid');
END;

CREATE TRIGGER reconciliation_decision_heads_validate_update
BEFORE UPDATE ON reconciliation_decision_heads
WHEN NEW.case_id <> OLD.case_id
    OR NEW.case_revision <= OLD.case_revision
    OR NEW.reconciliation_revision <= OLD.reconciliation_revision
    OR NEW.updated_at_ms < OLD.updated_at_ms
    OR NOT EXISTS (
        SELECT 1 FROM reconciliation_decisions decision
        WHERE decision.decision_id = NEW.decision_id
          AND decision.case_id = NEW.case_id
          AND decision.case_revision = NEW.case_revision
          AND decision.reconciliation_revision =
              NEW.reconciliation_revision
    )
BEGIN
    SELECT RAISE(ABORT, 'reconciliation decision head is invalid');
END;

CREATE TRIGGER reconciliation_command_entities_validate_insert
BEFORE INSERT ON reconciliation_command_entities
WHEN (
    NEW.entity_kind = 'case'
    AND NOT EXISTS (
        SELECT 1 FROM reconciliation_cases reconciliation_case
        WHERE reconciliation_case.case_id = NEW.entity_id
    )
) OR (
    NEW.entity_kind = 'decision'
    AND NOT EXISTS (
        SELECT 1 FROM reconciliation_decisions decision
        WHERE decision.decision_id = NEW.entity_id
          AND decision.reconciliation_revision =
              NEW.reconciliation_revision
    )
)
BEGIN
    SELECT RAISE(ABORT, 'reconciliation command entity is invalid');
END;

CREATE TRIGGER reconciliation_cases_no_update
BEFORE UPDATE ON reconciliation_cases
BEGIN
    SELECT RAISE(ABORT, 'reconciliation cases are immutable');
END;
CREATE TRIGGER reconciliation_cases_no_delete
BEFORE DELETE ON reconciliation_cases
BEGIN
    SELECT RAISE(ABORT, 'reconciliation cases are immutable');
END;
CREATE TRIGGER reconciliation_candidates_no_update
BEFORE UPDATE ON reconciliation_candidates
BEGIN
    SELECT RAISE(ABORT, 'reconciliation candidates are immutable');
END;
CREATE TRIGGER reconciliation_candidates_no_delete
BEFORE DELETE ON reconciliation_candidates
BEGIN
    SELECT RAISE(ABORT, 'reconciliation candidates are immutable');
END;
CREATE TRIGGER reconciliation_candidate_evidence_no_update
BEFORE UPDATE ON reconciliation_candidate_evidence
BEGIN
    SELECT RAISE(ABORT, 'reconciliation evidence is immutable');
END;
CREATE TRIGGER reconciliation_candidate_evidence_no_delete
BEFORE DELETE ON reconciliation_candidate_evidence
BEGIN
    SELECT RAISE(ABORT, 'reconciliation evidence is immutable');
END;
CREATE TRIGGER reconciliation_evidence_hashes_no_update
BEFORE UPDATE ON reconciliation_evidence_input_hashes
BEGIN
    SELECT RAISE(ABORT, 'reconciliation evidence hashes are immutable');
END;
CREATE TRIGGER reconciliation_evidence_hashes_no_delete
BEFORE DELETE ON reconciliation_evidence_input_hashes
BEGIN
    SELECT RAISE(ABORT, 'reconciliation evidence hashes are immutable');
END;
CREATE TRIGGER reconciliation_decisions_no_update
BEFORE UPDATE ON reconciliation_decisions
BEGIN
    SELECT RAISE(ABORT, 'reconciliation decisions are append-only');
END;
CREATE TRIGGER reconciliation_decisions_no_delete
BEFORE DELETE ON reconciliation_decisions
BEGIN
    SELECT RAISE(ABORT, 'reconciliation decisions are append-only');
END;
CREATE TRIGGER reconciliation_decision_heads_no_delete
BEFORE DELETE ON reconciliation_decision_heads
BEGIN
    SELECT RAISE(ABORT, 'reconciliation decision heads cannot be deleted');
END;
CREATE TRIGGER reconciliation_command_entities_no_update
BEFORE UPDATE ON reconciliation_command_entities
BEGIN
    SELECT RAISE(ABORT, 'reconciliation command links are append-only');
END;
CREATE TRIGGER reconciliation_command_entities_no_delete
BEFORE DELETE ON reconciliation_command_entities
BEGIN
    SELECT RAISE(ABORT, 'reconciliation command links are append-only');
END;
