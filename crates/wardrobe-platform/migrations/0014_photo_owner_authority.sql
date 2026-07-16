PRAGMA legacy_alter_table = ON;

ALTER TABLE revision_state
ADD COLUMN owner_revision INTEGER NOT NULL DEFAULT 0
CHECK (owner_revision BETWEEN 0 AND 9007199254740990);

CREATE TABLE photo_person_detection_runs (
    run_id TEXT PRIMARY KEY CHECK (
        length(run_id) = 36
        AND run_id <> '00000000-0000-0000-0000-000000000000'
    ),
    request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    request_envelope_sha256 TEXT NOT NULL CHECK (
        length(request_envelope_sha256) = 64
        AND request_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    scope_id TEXT NOT NULL
        REFERENCES photo_scopes(scope_id) ON DELETE RESTRICT,
    contract_revision TEXT NOT NULL CHECK (
        length(contract_revision) BETWEEN 1 AND 128
        AND contract_revision NOT GLOB '*[^ -~]*'
    ),
    provider_revision TEXT NOT NULL CHECK (
        length(provider_revision) BETWEEN 1 AND 128
        AND provider_revision NOT GLOB '*[^ -~]*'
    ),
    preprocessing_revision TEXT NOT NULL CHECK (
        length(preprocessing_revision) BETWEEN 1 AND 128
        AND preprocessing_revision NOT GLOB '*[^ -~]*'
    ),
    vision_request_revision INTEGER NOT NULL CHECK (
        vision_request_revision BETWEEN 1 AND 2147483647
    ),
    os_build TEXT NOT NULL CHECK (
        length(os_build) BETWEEN 1 AND 128
        AND os_build NOT GLOB '*[^ -~]*'
    ),
    vision_framework_build TEXT NOT NULL CHECK (
        length(vision_framework_build) BETWEEN 1 AND 128
        AND vision_framework_build NOT GLOB '*[^ -~]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'completed')),
    member_count INTEGER NOT NULL CHECK (member_count BETWEEN 1 AND 500),
    completed_count INTEGER NOT NULL DEFAULT 0 CHECK (
        completed_count BETWEEN 0 AND 500
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    completed_at_ms INTEGER CHECK (
        completed_at_ms IS NULL OR completed_at_ms >= created_at_ms
    ),
    CHECK (completed_count <= member_count),
    CHECK (
        (state = 'completed'
            AND completed_count = member_count
            AND completed_at_ms IS NOT NULL)
        OR
        (state <> 'completed' AND completed_at_ms IS NULL)
    ),
    UNIQUE(
        scope_id, contract_revision, provider_revision,
        preprocessing_revision, vision_request_revision,
        os_build, vision_framework_build
    ),
    UNIQUE(run_id, scope_id)
) STRICT;

CREATE TABLE photo_person_detection_attempts (
    detection_attempt_id TEXT PRIMARY KEY CHECK (
        length(detection_attempt_id) = 36
        AND detection_attempt_id <> '00000000-0000-0000-0000-000000000000'
    ),
    run_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    member_ordinal INTEGER NOT NULL CHECK (
        member_ordinal BETWEEN 0 AND 499
    ),
    source_revision_id TEXT NOT NULL,
    source_revision_sha256 TEXT NOT NULL CHECK (
        length(source_revision_sha256) = 64
        AND source_revision_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    input_blob_sha256 TEXT NOT NULL
        REFERENCES blobs(sha256) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (
        generation BETWEEN 1 AND 9007199254740990
    ),
    request_id TEXT
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    contract_revision TEXT NOT NULL CHECK (
        length(contract_revision) BETWEEN 1 AND 128
        AND contract_revision NOT GLOB '*[^ -~]*'
    ),
    provider_revision TEXT NOT NULL CHECK (
        length(provider_revision) BETWEEN 1 AND 128
        AND provider_revision NOT GLOB '*[^ -~]*'
    ),
    preprocessing_revision TEXT NOT NULL CHECK (
        length(preprocessing_revision) BETWEEN 1 AND 128
        AND preprocessing_revision NOT GLOB '*[^ -~]*'
    ),
    vision_request_revision INTEGER NOT NULL CHECK (
        vision_request_revision BETWEEN 1 AND 2147483647
    ),
    os_build TEXT NOT NULL CHECK (
        length(os_build) BETWEEN 1 AND 128
        AND os_build NOT GLOB '*[^ -~]*'
    ),
    vision_framework_build TEXT NOT NULL CHECK (
        length(vision_framework_build) BETWEEN 1 AND 128
        AND vision_framework_build NOT GLOB '*[^ -~]*'
    ),
    state TEXT NOT NULL CHECK (
        state IN (
            'pending', 'running', 'succeeded_zero', 'succeeded_instances',
            'overflow', 'retryable_failure', 'permanent_unavailable'
        )
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (
        attempt_count BETWEEN 0 AND 1000
    ),
    fence INTEGER NOT NULL DEFAULT 0 CHECK (
        fence BETWEEN 0 AND 9007199254740990
    ),
    lease_owner TEXT CHECK (
        lease_owner IS NULL
        OR (
            length(lease_owner) BETWEEN 1 AND 128
            AND lease_owner NOT GLOB '*[^ -~]*'
        )
    ),
    lease_expires_at_ms INTEGER,
    detected_count INTEGER CHECK (
        detected_count IS NULL
        OR detected_count BETWEEN 0 AND 2147483647
    ),
    terminal_reason TEXT CHECK (
        terminal_reason IS NULL
        OR terminal_reason IN (
            'vision_completed', 'output_overflow', 'vision_transient',
            'vision_unavailable', 'invalid_provider_output'
        )
    ),
    evidence_sha256 TEXT CHECK (
        evidence_sha256 IS NULL
        OR (
            length(evidence_sha256) = 64
            AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    completed_at_ms INTEGER CHECK (
        completed_at_ms IS NULL OR completed_at_ms >= created_at_ms
    ),
    UNIQUE(scope_id, member_ordinal, source_revision_id, generation),
    UNIQUE(run_id, scope_id, member_ordinal, source_revision_id, generation),
    UNIQUE(detection_attempt_id, scope_id, member_ordinal, source_revision_id),
    FOREIGN KEY(run_id, scope_id)
        REFERENCES photo_person_detection_runs(run_id, scope_id)
        ON DELETE RESTRICT,
    CHECK (
        (state = 'pending'
            AND attempt_count = 0
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL
            AND detected_count IS NULL
            AND terminal_reason IS NULL
            AND evidence_sha256 IS NULL
            AND completed_at_ms IS NULL)
        OR
        (state = 'running'
            AND attempt_count BETWEEN 1 AND 1000
            AND fence > 0
            AND lease_owner IS NOT NULL
            AND lease_expires_at_ms > updated_at_ms
            AND detected_count IS NULL
            AND terminal_reason IS NULL
            AND evidence_sha256 IS NULL
            AND completed_at_ms IS NULL)
        OR
        (state = 'succeeded_zero'
            AND detected_count = 0
            AND terminal_reason = 'vision_completed'
            AND evidence_sha256 IS NOT NULL
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL
            AND completed_at_ms IS NOT NULL)
        OR
        (state = 'succeeded_instances'
            AND detected_count BETWEEN 1 AND 32
            AND terminal_reason = 'vision_completed'
            AND evidence_sha256 IS NOT NULL
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL
            AND completed_at_ms IS NOT NULL)
        OR
        (state = 'overflow'
            AND detected_count > 32
            AND terminal_reason = 'output_overflow'
            AND evidence_sha256 IS NOT NULL
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL
            AND completed_at_ms IS NOT NULL)
        OR
        (state = 'retryable_failure'
            AND detected_count IS NULL
            AND terminal_reason = 'vision_transient'
            AND evidence_sha256 IS NOT NULL
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL
            AND completed_at_ms IS NOT NULL)
        OR
        (state = 'permanent_unavailable'
            AND detected_count IS NULL
            AND terminal_reason IN (
                'vision_unavailable', 'invalid_provider_output'
            )
            AND evidence_sha256 IS NOT NULL
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL
            AND completed_at_ms IS NOT NULL)
    ),
    FOREIGN KEY(scope_id, member_ordinal, source_revision_id)
        REFERENCES photo_scope_members(
            scope_id, member_ordinal, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(
        source_revision_id, source_revision_sha256, input_blob_sha256
    ) REFERENCES photo_source_revisions(
        source_revision_id, source_revision_sha256, blob_sha256
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_owner_preview_references (
    preview_id TEXT PRIMARY KEY CHECK (
        length(preview_id) = 36
        AND preview_id <> '00000000-0000-0000-0000-000000000000'
    ),
    source_revision_id TEXT NOT NULL,
    source_revision_sha256 TEXT NOT NULL CHECK (
        length(source_revision_sha256) = 64
        AND source_revision_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    blob_sha256 TEXT NOT NULL
        REFERENCES blobs(sha256) ON DELETE RESTRICT,
    byte_length INTEGER NOT NULL CHECK (
        byte_length BETWEEN 1 AND 41943040
    ),
    media_type TEXT NOT NULL CHECK (
        media_type IN ('image/jpeg', 'image/png', 'image/webp')
    ),
    width INTEGER NOT NULL CHECK (width BETWEEN 1 AND 16384),
    height INTEGER NOT NULL CHECK (height BETWEEN 1 AND 16384),
    preview_revision TEXT NOT NULL CHECK (
        length(preview_revision) BETWEEN 1 AND 128
        AND preview_revision NOT GLOB '*[^ -~]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(
        source_revision_id, source_revision_sha256, blob_sha256,
        byte_length, media_type, width, height
    ),
    FOREIGN KEY(
        source_revision_id, source_revision_sha256, blob_sha256,
        media_type, width, height
    ) REFERENCES photo_source_revisions(
        source_revision_id, source_revision_sha256, blob_sha256,
        media_type, width, height
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_owner_reviews (
    owner_review_id TEXT PRIMARY KEY CHECK (
        length(owner_review_id) = 36
        AND owner_review_id <> '00000000-0000-0000-0000-000000000000'
    ),
    scope_id TEXT NOT NULL,
    member_ordinal INTEGER NOT NULL CHECK (
        member_ordinal BETWEEN 0 AND 499
    ),
    source_revision_id TEXT NOT NULL,
    detection_attempt_id TEXT NOT NULL UNIQUE,
    preview_id TEXT NOT NULL UNIQUE
        REFERENCES photo_owner_preview_references(preview_id)
        ON DELETE RESTRICT,
    detection_revision INTEGER NOT NULL CHECK (
        detection_revision BETWEEN 1 AND 9007199254740990
    ),
    state TEXT NOT NULL CHECK (
        state IN (
            'detecting', 'instances_available', 'no_person_detected', 'overflow',
            'retryable_failure', 'permanent_unavailable'
        )
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    UNIQUE(owner_review_id, source_revision_id),
    UNIQUE(owner_review_id, source_revision_id, detection_revision),
    FOREIGN KEY(
        detection_attempt_id, scope_id, member_ordinal, source_revision_id
    ) REFERENCES photo_person_detection_attempts(
        detection_attempt_id, scope_id, member_ordinal, source_revision_id
    ) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id, member_ordinal, source_revision_id)
        REFERENCES photo_scope_members(
            scope_id, member_ordinal, source_revision_id
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_detection_corrections (
    correction_id TEXT PRIMARY KEY CHECK (
        length(correction_id) = 36
        AND correction_id <> '00000000-0000-0000-0000-000000000000'
    ),
    owner_review_id TEXT NOT NULL,
    source_revision_id TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    expected_detection_revision INTEGER NOT NULL CHECK (
        expected_detection_revision BETWEEN 1 AND 9007199254740989
    ),
    detection_revision INTEGER NOT NULL CHECK (
        detection_revision = expected_detection_revision + 1
    ),
    expected_owner_revision INTEGER NOT NULL CHECK (
        expected_owner_revision BETWEEN 0 AND 9007199254740990
    ),
    expected_photo_revision INTEGER NOT NULL CHECK (
        expected_photo_revision BETWEEN 0 AND 9007199254740989
    ),
    photo_revision INTEGER NOT NULL UNIQUE CHECK (
        photo_revision = expected_photo_revision + 1
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(correction_id, owner_review_id, source_revision_id),
    FOREIGN KEY(owner_review_id, source_revision_id)
        REFERENCES photo_owner_reviews(owner_review_id, source_revision_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_person_instances (
    person_instance_id TEXT PRIMARY KEY CHECK (
        length(person_instance_id) = 36
        AND person_instance_id <> '00000000-0000-0000-0000-000000000000'
    ),
    owner_review_id TEXT NOT NULL,
    source_revision_id TEXT NOT NULL,
    detection_attempt_id TEXT,
    correction_id TEXT,
    source_kind TEXT NOT NULL CHECK (
        source_kind IN ('apple_vision', 'manual_user_rectangle')
    ),
    instance_ordinal INTEGER NOT NULL CHECK (
        instance_ordinal BETWEEN 0 AND 31
    ),
    rectangle_x INTEGER NOT NULL CHECK (rectangle_x BETWEEN 0 AND 16383),
    rectangle_y INTEGER NOT NULL CHECK (rectangle_y BETWEEN 0 AND 16383),
    rectangle_width INTEGER NOT NULL CHECK (
        rectangle_width BETWEEN 1 AND 16384
    ),
    rectangle_height INTEGER NOT NULL CHECK (
        rectangle_height BETWEEN 1 AND 16384
    ),
    confidence_basis_points INTEGER CHECK (
        confidence_basis_points IS NULL
        OR confidence_basis_points BETWEEN 0 AND 10000
    ),
    evidence_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(evidence_sha256) = 64
        AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        (source_kind = 'apple_vision'
            AND detection_attempt_id IS NOT NULL
            AND correction_id IS NULL
            AND confidence_basis_points IS NOT NULL)
        OR
        (source_kind = 'manual_user_rectangle'
            AND detection_attempt_id IS NULL
            AND correction_id IS NOT NULL
            AND confidence_basis_points IS NULL)
    ),
    UNIQUE(owner_review_id, instance_ordinal, source_kind),
    UNIQUE(person_instance_id, owner_review_id, source_revision_id),
    FOREIGN KEY(owner_review_id, source_revision_id)
        REFERENCES photo_owner_reviews(owner_review_id, source_revision_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(detection_attempt_id)
        REFERENCES photo_person_detection_attempts(detection_attempt_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(correction_id, owner_review_id, source_revision_id)
        REFERENCES photo_detection_corrections(
            correction_id, owner_review_id, source_revision_id
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_owner_decisions (
    owner_decision_id TEXT PRIMARY KEY CHECK (
        length(owner_decision_id) = 36
        AND owner_decision_id <> '00000000-0000-0000-0000-000000000000'
    ),
    owner_review_id TEXT NOT NULL,
    source_revision_id TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    action TEXT NOT NULL CHECK (
        action IN ('select_person', 'owner_absent')
    ),
    selected_person_instance_id TEXT,
    expected_detection_revision INTEGER NOT NULL CHECK (
        expected_detection_revision BETWEEN 1 AND 9007199254740990
    ),
    expected_owner_revision INTEGER NOT NULL CHECK (
        expected_owner_revision BETWEEN 0 AND 9007199254740989
    ),
    owner_revision INTEGER NOT NULL CHECK (
        owner_revision = expected_owner_revision + 1
    ),
    expected_photo_revision INTEGER NOT NULL CHECK (
        expected_photo_revision BETWEEN 0 AND 9007199254740989
    ),
    photo_revision INTEGER NOT NULL UNIQUE CHECK (
        photo_revision = expected_photo_revision + 1
    ),
    superseded_owner_decision_id TEXT
        REFERENCES photo_owner_decisions(owner_decision_id)
        ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        (action = 'select_person' AND selected_person_instance_id IS NOT NULL)
        OR
        (action = 'owner_absent' AND selected_person_instance_id IS NULL)
    ),
    CHECK (
        (expected_owner_revision = 0
            AND superseded_owner_decision_id IS NULL)
        OR
        (expected_owner_revision > 0
            AND superseded_owner_decision_id IS NOT NULL)
    ),
    UNIQUE(
        owner_decision_id, owner_review_id, source_revision_id,
        selected_person_instance_id, owner_revision
    ),
    FOREIGN KEY(
        owner_review_id, source_revision_id, expected_detection_revision
    ) REFERENCES photo_owner_reviews(
        owner_review_id, source_revision_id, detection_revision
    ) ON DELETE RESTRICT,
    FOREIGN KEY(
        selected_person_instance_id, owner_review_id, source_revision_id
    ) REFERENCES photo_person_instances(
        person_instance_id, owner_review_id, source_revision_id
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_owner_heads (
    source_revision_id TEXT PRIMARY KEY,
    owner_review_id TEXT NOT NULL,
    owner_decision_id TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL CHECK (
        action IN ('select_person', 'owner_absent')
    ),
    selected_person_instance_id TEXT,
    owner_revision INTEGER NOT NULL CHECK (
        owner_revision BETWEEN 1 AND 9007199254740990
    ),
    photo_revision INTEGER NOT NULL UNIQUE CHECK (
        photo_revision BETWEEN 1 AND 9007199254740990
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK (
        (action = 'select_person' AND selected_person_instance_id IS NOT NULL)
        OR
        (action = 'owner_absent' AND selected_person_instance_id IS NULL)
    ),
    UNIQUE(
        owner_decision_id, owner_review_id, source_revision_id,
        selected_person_instance_id, owner_revision
    ),
    FOREIGN KEY(
        owner_decision_id, owner_review_id, source_revision_id,
        selected_person_instance_id, owner_revision
    ) REFERENCES photo_owner_decisions(
        owner_decision_id, owner_review_id, source_revision_id,
        selected_person_instance_id, owner_revision
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_owner_work_claims (
    owner_decision_id TEXT PRIMARY KEY
        REFERENCES photo_owner_decisions(owner_decision_id)
        ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'running', 'terminal', 'stale')
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (
        attempt_count BETWEEN 0 AND 1000
    ),
    fence INTEGER NOT NULL DEFAULT 0 CHECK (
        fence BETWEEN 0 AND 9007199254740990
    ),
    lease_owner TEXT CHECK (
        lease_owner IS NULL
        OR (
            length(lease_owner) BETWEEN 1 AND 128
            AND lease_owner NOT GLOB '*[^ -~]*'
        )
    ),
    lease_expires_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    CHECK (
        (state = 'running'
            AND fence > 0
            AND lease_owner IS NOT NULL
            AND lease_expires_at_ms > updated_at_ms)
        OR
        (state <> 'running'
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL)
    )
) STRICT;

-- Existing observations are immutable history. Rebuild only to remove the
-- legacy one-observation-per-source uniqueness constraints; owner authority is
-- carried by the immutable link table below.
ALTER TABLE photo_observations RENAME TO p04_photo_observations_legacy;
CREATE TABLE photo_observations (
    observation_id TEXT PRIMARY KEY CHECK (
        length(observation_id) = 36
        AND observation_id <> '00000000-0000-0000-0000-000000000000'
    ),
    scope_id TEXT NOT NULL,
    member_ordinal INTEGER NOT NULL CHECK (
        member_ordinal BETWEEN 0 AND 499
    ),
    source_revision_id TEXT NOT NULL,
    initial_attempt_id TEXT NOT NULL,
    initial_artifact_id TEXT NOT NULL UNIQUE,
    initial_state TEXT NOT NULL CHECK (initial_state = 'needs_review'),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(observation_id, scope_id, source_revision_id),
    FOREIGN KEY(scope_id, member_ordinal, source_revision_id)
        REFERENCES photo_scope_members(
            scope_id, member_ordinal, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(
        initial_artifact_id, scope_id, member_ordinal,
        source_revision_id, initial_attempt_id
    ) REFERENCES photo_artifacts(
        artifact_id, scope_id, member_ordinal,
        source_revision_id, attempt_id
    ) ON DELETE RESTRICT
) STRICT;
INSERT INTO photo_observations
SELECT * FROM p04_photo_observations_legacy;
DROP TABLE p04_photo_observations_legacy;
CREATE INDEX photo_observations_scope_idx
    ON photo_observations(scope_id, created_at_ms, observation_id);
CREATE TRIGGER photo_observations_no_update
BEFORE UPDATE ON photo_observations
BEGIN SELECT RAISE(ABORT, 'photo observations are immutable'); END;

CREATE TABLE photo_observation_owner_links (
    observation_id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    source_revision_id TEXT NOT NULL,
    owner_review_id TEXT NOT NULL,
    owner_decision_id TEXT NOT NULL UNIQUE,
    person_instance_id TEXT NOT NULL,
    owner_revision INTEGER NOT NULL CHECK (
        owner_revision BETWEEN 1 AND 9007199254740990
    ),
    evidence_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(evidence_sha256) = 64
        AND evidence_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(
        observation_id, scope_id, source_revision_id,
        owner_decision_id, person_instance_id, owner_revision
    ),
    FOREIGN KEY(observation_id, scope_id, source_revision_id)
        REFERENCES photo_observations(
            observation_id, scope_id, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(
        owner_decision_id, owner_review_id, source_revision_id,
        person_instance_id, owner_revision
    ) REFERENCES photo_owner_decisions(
        owner_decision_id, owner_review_id, source_revision_id,
        selected_person_instance_id, owner_revision
    ) ON DELETE RESTRICT
) STRICT;

-- Add an immutable all-null legacy pin group to cases. New cases must carry the
-- complete group; migrated cases never receive fabricated owner data.
ALTER TABLE reconciliation_cases RENAME TO p04_reconciliation_cases_legacy;
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
    owner_decision_id TEXT,
    person_instance_id TEXT,
    owner_revision INTEGER CHECK (
        owner_revision IS NULL
        OR owner_revision BETWEEN 1 AND 9007199254740990
    ),
    owner_evidence_sha256 TEXT CHECK (
        owner_evidence_sha256 IS NULL
        OR (
            length(owner_evidence_sha256) = 64
            AND owner_evidence_sha256 NOT GLOB '*[^0-9a-f]*'
        )
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
    CHECK (
        (owner_decision_id IS NULL
            AND person_instance_id IS NULL
            AND owner_revision IS NULL
            AND owner_evidence_sha256 IS NULL)
        OR
        (owner_decision_id IS NOT NULL
            AND person_instance_id IS NOT NULL
            AND owner_revision IS NOT NULL
            AND owner_evidence_sha256 IS NOT NULL)
    ),
    UNIQUE(
        observation_id, artifact_id, photo_decision_id,
        owner_decision_id, retrieval_revision
    ),
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
    FOREIGN KEY(
        observation_id, scope_id, source_revision_id,
        owner_decision_id, person_instance_id, owner_revision
    ) REFERENCES photo_observation_owner_links(
        observation_id, scope_id, source_revision_id,
        owner_decision_id, person_instance_id, owner_revision
    ) ON DELETE RESTRICT,
    FOREIGN KEY(case_id, leading_candidate_id)
        REFERENCES reconciliation_candidates(case_id, candidate_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(case_id, no_match_candidate_id)
        REFERENCES reconciliation_candidates(case_id, candidate_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
) STRICT;
INSERT INTO reconciliation_cases(
    case_id, observation_id, artifact_id, scope_id, source_revision_id,
    source_revision_sha256, artifact_sha256, photo_decision_id,
    photo_revision, owner_decision_id, person_instance_id, owner_revision,
    owner_evidence_sha256, catalog_revision, receipt_revision,
    retrieval_revision, observation_date, leading_candidate_id,
    no_match_candidate_id, case_revision, reconciliation_revision,
    created_at_ms
)
SELECT
    case_id, observation_id, artifact_id, scope_id, source_revision_id,
    source_revision_sha256, artifact_sha256, photo_decision_id,
    photo_revision, NULL, NULL, NULL, NULL, catalog_revision,
    receipt_revision, retrieval_revision, observation_date,
    leading_candidate_id, no_match_candidate_id, case_revision,
    reconciliation_revision, created_at_ms
FROM p04_reconciliation_cases_legacy;
DROP TABLE p04_reconciliation_cases_legacy;
CREATE INDEX reconciliation_cases_observation_idx
    ON reconciliation_cases(observation_id, artifact_id, case_id);
CREATE INDEX reconciliation_cases_source_revision_idx
    ON reconciliation_cases(source_revision_id, case_id);
CREATE TRIGGER reconciliation_cases_no_update
BEFORE UPDATE ON reconciliation_cases
BEGIN SELECT RAISE(ABORT, 'reconciliation cases are immutable'); END;

CREATE TABLE photo_owner_command_entities (
    request_id TEXT NOT NULL
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    entity_kind TEXT NOT NULL CHECK (
        entity_kind IN (
            'detection_run', 'detection_attempt', 'owner_preview', 'owner_review',
            'detection_correction', 'person_instance', 'owner_decision',
            'owner_work', 'observation_owner_link'
        )
    ),
    entity_id TEXT NOT NULL CHECK (
        length(entity_id) = 36
        AND entity_id <> '00000000-0000-0000-0000-000000000000'
    ),
    PRIMARY KEY(request_id, entity_kind, entity_id)
) STRICT;

CREATE INDEX photo_detection_attempts_source_idx
    ON photo_person_detection_attempts(
        source_revision_id, generation, detection_attempt_id
    );
CREATE INDEX photo_owner_reviews_state_idx
    ON photo_owner_reviews(state, updated_at_ms, owner_review_id);
CREATE INDEX photo_person_instances_review_idx
    ON photo_person_instances(
        owner_review_id, instance_ordinal, person_instance_id
    );
CREATE INDEX photo_owner_decisions_source_idx
    ON photo_owner_decisions(
        source_revision_id, owner_revision, owner_decision_id
    );
CREATE INDEX photo_owner_work_state_idx
    ON photo_owner_work_claims(state, updated_at_ms, owner_decision_id);
CREATE INDEX photo_owner_command_entities_entity_idx
    ON photo_owner_command_entities(entity_kind, entity_id, request_id);

CREATE TRIGGER photo_owner_reviews_validate_insert
BEFORE INSERT ON photo_owner_reviews
WHEN NOT EXISTS (
    SELECT 1 FROM photo_person_detection_attempts attempt
    WHERE attempt.detection_attempt_id = NEW.detection_attempt_id
      AND attempt.scope_id = NEW.scope_id
      AND attempt.member_ordinal = NEW.member_ordinal
      AND attempt.source_revision_id = NEW.source_revision_id
      AND (
          (attempt.state = 'succeeded_instances'
              AND NEW.state = 'instances_available')
          OR
          (attempt.state = 'succeeded_zero'
              AND NEW.state = 'no_person_detected')
          OR
          (attempt.state = 'overflow' AND NEW.state = 'overflow')
          OR
          (attempt.state = 'retryable_failure'
              AND NEW.state = 'retryable_failure')
          OR
          (attempt.state = 'permanent_unavailable'
              AND NEW.state = 'permanent_unavailable')
      )
)
BEGIN SELECT RAISE(ABORT, 'owner review does not match detection attempt'); END;
CREATE TRIGGER photo_owner_reviews_validate_update
BEFORE UPDATE ON photo_owner_reviews
WHEN
    NEW.owner_review_id <> OLD.owner_review_id
    OR NEW.scope_id <> OLD.scope_id
    OR NEW.member_ordinal <> OLD.member_ordinal
    OR NEW.source_revision_id <> OLD.source_revision_id
    OR NEW.preview_id <> OLD.preview_id
    OR NEW.created_at_ms <> OLD.created_at_ms
    OR NEW.detection_revision <> OLD.detection_revision + 1
    OR NEW.updated_at_ms < OLD.updated_at_ms
    OR NOT (
        (NEW.detection_attempt_id <> OLD.detection_attempt_id
            AND NEW.state = 'detecting'
            AND EXISTS (
                SELECT 1 FROM photo_person_detection_attempts attempt
                WHERE attempt.detection_attempt_id = NEW.detection_attempt_id
                  AND attempt.scope_id = NEW.scope_id
                  AND attempt.member_ordinal = NEW.member_ordinal
                  AND attempt.source_revision_id = NEW.source_revision_id
                  AND attempt.state = 'pending'
            ))
        OR
        (NEW.detection_attempt_id = OLD.detection_attempt_id
            AND OLD.state = 'detecting'
            AND EXISTS (
                SELECT 1 FROM photo_person_detection_attempts attempt
                WHERE attempt.detection_attempt_id = NEW.detection_attempt_id
                  AND attempt.scope_id = NEW.scope_id
                  AND attempt.member_ordinal = NEW.member_ordinal
                  AND attempt.source_revision_id = NEW.source_revision_id
                  AND (
                      (attempt.state = 'succeeded_instances'
                          AND NEW.state = 'instances_available')
                      OR
                      (attempt.state = 'succeeded_zero'
                          AND NEW.state = 'no_person_detected')
                      OR
                      (attempt.state = 'overflow'
                          AND NEW.state = 'overflow')
                      OR
                      (attempt.state = 'retryable_failure'
                          AND NEW.state = 'retryable_failure')
                      OR
                      (attempt.state = 'permanent_unavailable'
                          AND NEW.state = 'permanent_unavailable')
                  )
            ))
        OR
        (NEW.detection_attempt_id = OLD.detection_attempt_id
            AND OLD.state IN (
                'no_person_detected', 'overflow',
                'retryable_failure', 'permanent_unavailable'
            )
            AND NEW.state = 'instances_available'
            AND EXISTS (
                SELECT 1 FROM photo_detection_corrections correction
                WHERE correction.owner_review_id = NEW.owner_review_id
                  AND correction.source_revision_id = NEW.source_revision_id
                  AND correction.detection_revision = NEW.detection_revision
            ))
    )
BEGIN SELECT RAISE(ABORT, 'invalid owner review transition'); END;
CREATE TRIGGER photo_previews_no_update
BEFORE UPDATE ON photo_owner_preview_references
BEGIN SELECT RAISE(ABORT, 'owner previews are immutable'); END;
CREATE TRIGGER photo_detection_corrections_no_update
BEFORE UPDATE ON photo_detection_corrections
BEGIN SELECT RAISE(ABORT, 'detection corrections are immutable'); END;
CREATE TRIGGER photo_person_instances_no_update
BEFORE UPDATE ON photo_person_instances
BEGIN SELECT RAISE(ABORT, 'person instances are immutable'); END;
CREATE TRIGGER photo_person_instances_validate_insert
BEFORE INSERT ON photo_person_instances
WHEN NOT EXISTS (
    SELECT 1
    FROM photo_owner_reviews review
    JOIN photo_owner_preview_references preview
      ON preview.preview_id = review.preview_id
    WHERE review.owner_review_id = NEW.owner_review_id
      AND review.source_revision_id = NEW.source_revision_id
      AND NEW.rectangle_x + NEW.rectangle_width <= preview.width
      AND NEW.rectangle_y + NEW.rectangle_height <= preview.height
      AND (
          (NEW.source_kind = 'apple_vision'
              AND NEW.detection_attempt_id = review.detection_attempt_id)
          OR
          (NEW.source_kind = 'manual_user_rectangle'
              AND EXISTS (
                  SELECT 1 FROM photo_detection_corrections correction
                  WHERE correction.correction_id = NEW.correction_id
                    AND correction.owner_review_id = NEW.owner_review_id
                    AND correction.source_revision_id = NEW.source_revision_id
                    AND correction.detection_revision =
                        review.detection_revision
              ))
      )
)
BEGIN SELECT RAISE(ABORT, 'person instance is outside owner preview'); END;
CREATE TRIGGER photo_owner_decisions_no_update
BEFORE UPDATE ON photo_owner_decisions
BEGIN SELECT RAISE(ABORT, 'owner decisions are immutable'); END;
CREATE TRIGGER photo_owner_work_validate_insert
BEFORE INSERT ON photo_owner_work_claims
WHEN NOT EXISTS (
    SELECT 1
    FROM photo_owner_decisions decision
    JOIN photo_owner_heads head
      ON head.owner_decision_id = decision.owner_decision_id
    WHERE decision.owner_decision_id = NEW.owner_decision_id
      AND decision.action = 'select_person'
      AND head.action = 'select_person'
)
BEGIN SELECT RAISE(ABORT, 'owner work requires current selected owner'); END;
CREATE TRIGGER photo_observation_owner_links_no_update
BEFORE UPDATE ON photo_observation_owner_links
BEGIN SELECT RAISE(ABORT, 'observation owner links are immutable'); END;

CREATE TRIGGER hd_photo_person_detection_runs
BEFORE DELETE ON photo_person_detection_runs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_person_detection_runs'
          AND entry.key_json = json_array(OLD.run_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_person_detection_attempts
BEFORE DELETE ON photo_person_detection_attempts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_person_detection_attempts'
          AND entry.key_json = json_array(OLD.detection_attempt_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_owner_preview_references
BEFORE DELETE ON photo_owner_preview_references
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_owner_preview_references'
          AND entry.key_json = json_array(OLD.preview_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_owner_reviews
BEFORE DELETE ON photo_owner_reviews
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_owner_reviews'
          AND entry.key_json = json_array(OLD.owner_review_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_detection_corrections
BEFORE DELETE ON photo_detection_corrections
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_detection_corrections'
          AND entry.key_json = json_array(OLD.correction_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_person_instances
BEFORE DELETE ON photo_person_instances
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_person_instances'
          AND entry.key_json = json_array(OLD.person_instance_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_owner_decisions
BEFORE DELETE ON photo_owner_decisions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_owner_decisions'
          AND entry.key_json = json_array(OLD.owner_decision_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_owner_heads
BEFORE DELETE ON photo_owner_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_owner_heads'
          AND entry.key_json = json_array(OLD.source_revision_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_owner_work_claims
BEFORE DELETE ON photo_owner_work_claims
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_owner_work_claims'
          AND entry.key_json = json_array(OLD.owner_decision_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_observation_owner_links
BEFORE DELETE ON photo_observation_owner_links
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_observation_owner_links'
          AND entry.key_json = json_array(OLD.observation_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_owner_command_entities
BEFORE DELETE ON photo_owner_command_entities
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_owner_command_entities'
          AND entry.key_json =
              json_array(OLD.request_id, OLD.entity_kind, OLD.entity_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_photo_observations
BEFORE DELETE ON photo_observations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'photo_observations'
          AND entry.key_json = json_array(OLD.observation_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_reconciliation_cases
BEFORE DELETE ON reconciliation_cases
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries entry
          ON entry.snapshot_token = authority.snapshot_token
         AND entry.epoch = authority.epoch
        WHERE entry.entity_kind = 'reconciliation_cases'
          AND entry.key_json = json_array(OLD.case_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

PRAGMA legacy_alter_table = OFF;
