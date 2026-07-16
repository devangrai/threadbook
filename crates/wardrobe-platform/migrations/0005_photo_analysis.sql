ALTER TABLE revision_state
ADD COLUMN photo_revision INTEGER NOT NULL DEFAULT 0
CHECK (photo_revision >= 0);

ALTER TABLE deletion_previews
ADD COLUMN photo_revision INTEGER NOT NULL DEFAULT 0
CHECK (photo_revision >= 0);

CREATE UNIQUE INDEX photo_import_scans_identity_idx
    ON import_scans(scan_id, root_id, generation);
CREATE UNIQUE INDEX photo_local_sources_root_idx
    ON local_sources(source_id, root_id);
CREATE UNIQUE INDEX photo_source_provenance_source_idx
    ON source_provenance(provenance_id, source_id);

CREATE TABLE photo_scopes (
    scope_id TEXT PRIMARY KEY CHECK (
        length(scope_id) = 36
        AND scope_id <> '00000000-0000-0000-0000-000000000000'
    ),
    request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    root_id TEXT NOT NULL
        REFERENCES import_roots(root_id) ON DELETE RESTRICT,
    scan_id TEXT NOT NULL,
    manifest_generation INTEGER NOT NULL CHECK (
        manifest_generation BETWEEN 1 AND 9007199254740990
    ),
    scope_schema_revision TEXT NOT NULL CHECK (
        length(scope_schema_revision) BETWEEN 1 AND 128
        AND scope_schema_revision NOT GLOB '*[^ -~]*'
    ),
    member_count INTEGER NOT NULL CHECK (member_count BETWEEN 1 AND 500),
    eligible_count INTEGER NOT NULL CHECK (eligible_count BETWEEN 0 AND 500),
    quarantined_count INTEGER NOT NULL CHECK (
        quarantined_count BETWEEN 0 AND 500
    ),
    membership_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(membership_sha256) = 64
        AND membership_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (eligible_count + quarantined_count = member_count),
    UNIQUE(root_id, manifest_generation),
    UNIQUE(scope_id, root_id, scan_id, manifest_generation),
    FOREIGN KEY(scan_id, root_id, manifest_generation)
        REFERENCES import_scans(scan_id, root_id, generation)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_source_revisions (
    source_revision_id TEXT PRIMARY KEY CHECK (
        length(source_revision_id) = 36
        AND source_revision_id <> '00000000-0000-0000-0000-000000000000'
    ),
    source_id TEXT NOT NULL,
    source_provenance_id TEXT NOT NULL,
    root_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    manifest_generation INTEGER NOT NULL CHECK (
        manifest_generation BETWEEN 1 AND 9007199254740990
    ),
    source_identity_key_sha256 TEXT NOT NULL CHECK (
        length(source_identity_key_sha256) = 64
        AND source_identity_key_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    provenance_row_sha256 TEXT NOT NULL CHECK (
        length(provenance_row_sha256) = 64
        AND provenance_row_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    raw_sha256 TEXT CHECK (
        raw_sha256 IS NULL
        OR (
            length(raw_sha256) = 64
            AND raw_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    blob_sha256 TEXT REFERENCES blobs(sha256) ON DELETE RESTRICT,
    byte_length INTEGER CHECK (
        byte_length IS NULL OR byte_length BETWEEN 1 AND 41943040
    ),
    media_type TEXT CHECK (
        media_type IS NULL
        OR media_type IN ('image/jpeg', 'image/png', 'image/webp')
    ),
    width INTEGER CHECK (width IS NULL OR width BETWEEN 1 AND 16384),
    height INTEGER CHECK (height IS NULL OR height BETWEEN 1 AND 16384),
    disposition TEXT NOT NULL CHECK (
        disposition IN ('eligible', 'quarantined')
    ),
    quarantine_reason TEXT CHECK (
        quarantine_reason IS NULL
        OR quarantine_reason IN (
            'source_unavailable', 'blob_unavailable', 'blob_integrity_failed',
            'media_type_rejected', 'image_decode_failed', 'image_animated',
            'image_dimension_limit'
        )
    ),
    source_revision_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(source_revision_sha256) = 64
        AND source_revision_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK ((blob_sha256 IS NULL) = (byte_length IS NULL)),
    CHECK ((width IS NULL) = (height IS NULL)),
    CHECK (
        width IS NULL
        OR (
            CAST(width AS INTEGER) * CAST(height AS INTEGER) <= 67108864
        )
    ),
    CHECK (
        (disposition = 'eligible'
            AND raw_sha256 IS NOT NULL
            AND blob_sha256 IS NOT NULL
            AND byte_length IS NOT NULL
            AND media_type IS NOT NULL
            AND width IS NOT NULL
            AND height IS NOT NULL
            AND quarantine_reason IS NULL)
        OR
        (disposition = 'quarantined' AND quarantine_reason IS NOT NULL)
    ),
    UNIQUE(source_id, scan_id, manifest_generation),
    UNIQUE(source_revision_id, disposition),
    UNIQUE(
        source_revision_id, root_id, scan_id, manifest_generation, disposition
    ),
    UNIQUE(source_revision_id, source_revision_sha256, blob_sha256),
    UNIQUE(
        source_revision_id, source_revision_sha256, blob_sha256,
        media_type, width, height
    ),
    FOREIGN KEY(source_id, root_id)
        REFERENCES local_sources(source_id, root_id) ON DELETE RESTRICT,
    FOREIGN KEY(source_provenance_id, source_id)
        REFERENCES source_provenance(provenance_id, source_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(scan_id, root_id, manifest_generation)
        REFERENCES import_scans(scan_id, root_id, generation)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_scope_members (
    scope_id TEXT NOT NULL,
    member_ordinal INTEGER NOT NULL CHECK (
        member_ordinal BETWEEN 0 AND 499
    ),
    source_revision_id TEXT NOT NULL,
    root_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    manifest_generation INTEGER NOT NULL CHECK (
        manifest_generation BETWEEN 1 AND 9007199254740990
    ),
    disposition TEXT NOT NULL CHECK (
        disposition IN ('eligible', 'quarantined')
    ),
    leaf_sha256 TEXT NOT NULL CHECK (
        length(leaf_sha256) = 64
        AND leaf_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY(scope_id, member_ordinal),
    UNIQUE(scope_id, source_revision_id),
    UNIQUE(scope_id, leaf_sha256),
    UNIQUE(scope_id, member_ordinal, source_revision_id),
    UNIQUE(scope_id, member_ordinal, source_revision_id, disposition),
    FOREIGN KEY(scope_id, root_id, scan_id, manifest_generation)
        REFERENCES photo_scopes(
            scope_id, root_id, scan_id, manifest_generation
        ) ON DELETE RESTRICT,
    FOREIGN KEY(
        source_revision_id, root_id, scan_id,
        manifest_generation, disposition
    ) REFERENCES photo_source_revisions(
        source_revision_id, root_id, scan_id,
        manifest_generation, disposition
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_analysis_runs (
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
    provider_contract_revision TEXT NOT NULL CHECK (
        length(provider_contract_revision) BETWEEN 1 AND 128
        AND provider_contract_revision NOT GLOB '*[^ -~]*'
    ),
    provider_id TEXT NOT NULL CHECK (
        length(provider_id) BETWEEN 1 AND 128
        AND provider_id NOT GLOB '*[^ -~]*'
    ),
    provider_revision TEXT NOT NULL CHECK (
        length(provider_revision) BETWEEN 1 AND 128
        AND provider_revision NOT GLOB '*[^ -~]*'
    ),
    model_revision TEXT CHECK (
        model_revision IS NULL
        OR (
            length(model_revision) BETWEEN 1 AND 128
            AND model_revision NOT GLOB '*[^ -~]*'
        )
    ),
    preprocessing_revision TEXT NOT NULL CHECK (
        length(preprocessing_revision) BETWEEN 1 AND 128
        AND preprocessing_revision NOT GLOB '*[^ -~]*'
    ),
    quality_gate_revision TEXT NOT NULL CHECK (
        length(quality_gate_revision) BETWEEN 1 AND 128
        AND quality_gate_revision NOT GLOB '*[^ -~]*'
    ),
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'completed')),
    eligible_member_count INTEGER NOT NULL CHECK (
        eligible_member_count BETWEEN 0 AND 500
    ),
    terminal_member_count INTEGER NOT NULL DEFAULT 0 CHECK (
        terminal_member_count BETWEEN 0 AND 500
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    completed_at_ms INTEGER,
    CHECK (terminal_member_count <= eligible_member_count),
    CHECK (
        (state = 'completed'
            AND terminal_member_count = eligible_member_count
            AND completed_at_ms IS NOT NULL
            AND completed_at_ms >= created_at_ms)
        OR
        (state <> 'completed' AND completed_at_ms IS NULL)
    ),
    UNIQUE(run_id, scope_id)
) STRICT;

CREATE UNIQUE INDEX photo_analysis_runs_natural_idx
    ON photo_analysis_runs(
        scope_id, provider_contract_revision, provider_id, provider_revision,
        COALESCE(model_revision, ''), preprocessing_revision,
        quality_gate_revision
    );

CREATE TABLE photo_analysis_member_claims (
    run_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    member_ordinal INTEGER NOT NULL CHECK (
        member_ordinal BETWEEN 0 AND 499
    ),
    source_revision_id TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (
        disposition IN ('eligible', 'quarantined')
    ),
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'terminal')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (
        attempt_count BETWEEN 0 AND 1000
    ),
    fence INTEGER NOT NULL DEFAULT 0 CHECK (fence BETWEEN 0 AND 1000),
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
    PRIMARY KEY(run_id, member_ordinal),
    UNIQUE(run_id, scope_id, member_ordinal),
    UNIQUE(run_id, scope_id, member_ordinal, source_revision_id),
    CHECK (
        (state = 'running'
            AND fence > 0
            AND lease_owner IS NOT NULL
            AND lease_expires_at_ms IS NOT NULL
            AND lease_expires_at_ms > updated_at_ms)
        OR
        (state IN ('pending', 'terminal')
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL)
    ),
    CHECK (state <> 'terminal' OR disposition = 'quarantined' OR attempt_count > 0),
    FOREIGN KEY(run_id, scope_id)
        REFERENCES photo_analysis_runs(run_id, scope_id) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id, member_ordinal, source_revision_id, disposition)
        REFERENCES photo_scope_members(
            scope_id, member_ordinal, source_revision_id, disposition
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_segmentation_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (
        length(attempt_id) = 36
        AND attempt_id <> '00000000-0000-0000-0000-000000000000'
    ),
    request_handle TEXT NOT NULL UNIQUE CHECK (
        length(request_handle) = 36
        AND request_handle <> '00000000-0000-0000-0000-000000000000'
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
    disposition TEXT NOT NULL CHECK (
        disposition IN ('eligible', 'quarantined')
    ),
    claim_fence INTEGER NOT NULL CHECK (claim_fence BETWEEN 1 AND 1000),
    request_mode TEXT NOT NULL CHECK (
        request_mode IN ('automatic', 'interactive', 'quarantined_skip')
    ),
    input_blob_sha256 TEXT
        REFERENCES blobs(sha256) ON DELETE RESTRICT,
    provider_contract_revision TEXT NOT NULL CHECK (
        length(provider_contract_revision) BETWEEN 1 AND 128
        AND provider_contract_revision NOT GLOB '*[^ -~]*'
    ),
    provider_id TEXT NOT NULL CHECK (
        length(provider_id) BETWEEN 1 AND 128
        AND provider_id NOT GLOB '*[^ -~]*'
    ),
    provider_revision TEXT NOT NULL CHECK (
        length(provider_revision) BETWEEN 1 AND 128
        AND provider_revision NOT GLOB '*[^ -~]*'
    ),
    model_revision TEXT CHECK (
        model_revision IS NULL
        OR (
            length(model_revision) BETWEEN 1 AND 128
            AND model_revision NOT GLOB '*[^ -~]*'
        )
    ),
    preprocessing_revision TEXT NOT NULL CHECK (
        length(preprocessing_revision) BETWEEN 1 AND 128
        AND preprocessing_revision NOT GLOB '*[^ -~]*'
    ),
    prompt_parameters_sha256 TEXT NOT NULL CHECK (
        length(prompt_parameters_sha256) = 64
        AND prompt_parameters_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    request_envelope_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(request_envelope_sha256) = 64
        AND request_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    provider_invoked INTEGER NOT NULL CHECK (provider_invoked IN (0, 1)),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        (disposition = 'eligible'
            AND request_mode IN ('automatic', 'interactive')
            AND input_blob_sha256 IS NOT NULL
            AND provider_invoked = 1)
        OR
        (disposition = 'quarantined'
            AND request_mode = 'quarantined_skip'
            AND input_blob_sha256 IS NULL
            AND provider_invoked = 0)
    ),
    UNIQUE(attempt_id, scope_id, member_ordinal, source_revision_id),
    UNIQUE(attempt_id, request_mode),
    FOREIGN KEY(run_id, scope_id, member_ordinal, source_revision_id)
        REFERENCES photo_analysis_member_claims(
            run_id, scope_id, member_ordinal, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id, member_ordinal, source_revision_id, disposition)
        REFERENCES photo_scope_members(
            scope_id, member_ordinal, source_revision_id, disposition
        ) ON DELETE RESTRICT,
    FOREIGN KEY(
        source_revision_id, source_revision_sha256, input_blob_sha256
    ) REFERENCES photo_source_revisions(
        source_revision_id, source_revision_sha256, blob_sha256
    ) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX photo_segmentation_attempts_automatic_idx
    ON photo_segmentation_attempts(
        scope_id, member_ordinal, provider_contract_revision, provider_id,
        provider_revision, COALESCE(model_revision, ''),
        input_blob_sha256, preprocessing_revision
    )
    WHERE request_mode = 'automatic';

CREATE TABLE photo_segmentation_outcomes (
    attempt_id TEXT PRIMARY KEY
        REFERENCES photo_segmentation_attempts(attempt_id) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK (
        outcome IN (
            'automatic_masks', 'interactive_masks', 'no_garment',
            'unavailable', 'failed', 'rejected', 'skipped_quarantined'
        )
    ),
    unavailable_reason TEXT CHECK (
        unavailable_reason IS NULL
        OR unavailable_reason IN (
            'reviewed_model_pack_absent', 'capability_disabled',
            'resource_unavailable'
        )
    ),
    failure_code TEXT CHECK (
        failure_code IS NULL
        OR failure_code IN (
            'invalid_input', 'inference_failed', 'resource_limit', 'timed_out'
        )
    ),
    rejection_code TEXT CHECK (
        rejection_code IS NULL
        OR (
            length(rejection_code) BETWEEN 1 AND 80
            AND rejection_code NOT GLOB '*[^a-z0-9_]*'
        )
    ),
    mask_count INTEGER NOT NULL DEFAULT 0 CHECK (mask_count BETWEEN 0 AND 8),
    quality_gate_result TEXT NOT NULL CHECK (
        quality_gate_result IN ('not_applicable', 'disabled', 'rejected')
    ),
    response_sha256 TEXT CHECK (
        response_sha256 IS NULL
        OR (
            length(response_sha256) = 64
            AND response_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    completed_at_ms INTEGER NOT NULL CHECK (completed_at_ms >= 0),
    CHECK (
        (outcome = 'unavailable'
            AND unavailable_reason IS NOT NULL
            AND failure_code IS NULL
            AND rejection_code IS NULL
            AND mask_count = 0)
        OR
        (outcome = 'failed'
            AND unavailable_reason IS NULL
            AND failure_code IS NOT NULL
            AND rejection_code IS NULL
            AND mask_count = 0)
        OR
        (outcome = 'rejected'
            AND unavailable_reason IS NULL
            AND failure_code IS NULL
            AND rejection_code IS NOT NULL)
        OR
        (outcome IN ('automatic_masks', 'interactive_masks')
            AND unavailable_reason IS NULL
            AND failure_code IS NULL
            AND rejection_code IS NULL
            AND mask_count BETWEEN 1 AND 8)
        OR
        (outcome IN ('no_garment', 'skipped_quarantined')
            AND unavailable_reason IS NULL
            AND failure_code IS NULL
            AND rejection_code IS NULL
            AND mask_count = 0)
    ),
    CHECK (
        (outcome = 'automatic_masks'
            AND quality_gate_result = 'rejected')
        OR
        (outcome = 'rejected'
            AND quality_gate_result IN ('disabled', 'rejected'))
        OR
        (outcome NOT IN ('automatic_masks', 'rejected')
            AND quality_gate_result = 'not_applicable')
    ),
    UNIQUE(attempt_id, outcome)
) STRICT;

CREATE TABLE photo_artifacts (
    artifact_id TEXT PRIMARY KEY CHECK (
        length(artifact_id) = 36
        AND artifact_id <> '00000000-0000-0000-0000-000000000000'
    ),
    attempt_id TEXT NOT NULL,
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
    artifact_kind TEXT NOT NULL CHECK (
        artifact_kind IN ('rectangle_source_crop', 'source_image_reference')
    ),
    media_type TEXT NOT NULL CHECK (
        media_type IN ('image/jpeg', 'image/png', 'image/webp')
    ),
    source_width INTEGER NOT NULL CHECK (
        source_width BETWEEN 1 AND 16384
    ),
    source_height INTEGER NOT NULL CHECK (
        source_height BETWEEN 1 AND 16384
    ),
    rectangle_x INTEGER,
    rectangle_y INTEGER,
    rectangle_width INTEGER,
    rectangle_height INTEGER,
    artifact_schema_revision TEXT NOT NULL CHECK (
        length(artifact_schema_revision) BETWEEN 1 AND 128
        AND artifact_schema_revision NOT GLOB '*[^ -~]*'
    ),
    artifact_revision TEXT NOT NULL CHECK (
        length(artifact_revision) BETWEEN 1 AND 128
        AND artifact_revision NOT GLOB '*[^ -~]*'
    ),
    preprocessing_revision TEXT NOT NULL CHECK (
        length(preprocessing_revision) BETWEEN 1 AND 128
        AND preprocessing_revision NOT GLOB '*[^ -~]*'
    ),
    provider_contract_revision TEXT NOT NULL CHECK (
        length(provider_contract_revision) BETWEEN 1 AND 128
        AND provider_contract_revision NOT GLOB '*[^ -~]*'
    ),
    provider_id TEXT NOT NULL CHECK (
        length(provider_id) BETWEEN 1 AND 128
        AND provider_id NOT GLOB '*[^ -~]*'
    ),
    provider_revision TEXT NOT NULL CHECK (
        length(provider_revision) BETWEEN 1 AND 128
        AND provider_revision NOT GLOB '*[^ -~]*'
    ),
    model_revision TEXT CHECK (
        model_revision IS NULL
        OR (
            length(model_revision) BETWEEN 1 AND 128
            AND model_revision NOT GLOB '*[^ -~]*'
        )
    ),
    request_mode TEXT NOT NULL CHECK (
        request_mode IN ('automatic', 'interactive')
    ),
    prompt_parameters_sha256 TEXT NOT NULL CHECK (
        length(prompt_parameters_sha256) = 64
        AND prompt_parameters_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    quality_gate_revision TEXT NOT NULL CHECK (
        length(quality_gate_revision) BETWEEN 1 AND 128
        AND quality_gate_revision NOT GLOB '*[^ -~]*'
    ),
    quality_approved INTEGER NOT NULL CHECK (quality_approved = 0),
    segmentation_outcome TEXT NOT NULL CHECK (
        segmentation_outcome IN (
            'automatic_masks', 'interactive_masks', 'no_garment',
            'unavailable', 'failed', 'rejected'
        )
    ),
    unavailable_reason TEXT CHECK (
        unavailable_reason IS NULL
        OR unavailable_reason IN (
            'reviewed_model_pack_absent', 'capability_disabled',
            'resource_unavailable'
        )
    ),
    failure_code TEXT CHECK (
        failure_code IS NULL
        OR failure_code IN (
            'invalid_input', 'inference_failed', 'resource_limit', 'timed_out'
        )
    ),
    provenance_json TEXT NOT NULL CHECK (
        json_valid(provenance_json)
        AND length(CAST(provenance_json AS BLOB)) BETWEEN 2 AND 32768
    ),
    provenance_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(provenance_sha256) = 64
        AND provenance_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(artifact_sha256) = 64
        AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        CAST(source_width AS INTEGER) * CAST(source_height AS INTEGER)
            <= 67108864
    ),
    CHECK (
        (artifact_kind = 'rectangle_source_crop'
            AND rectangle_x IS NOT NULL
            AND rectangle_y IS NOT NULL
            AND rectangle_width IS NOT NULL
            AND rectangle_height IS NOT NULL
            AND rectangle_x >= 0
            AND rectangle_y >= 0
            AND rectangle_width > 0
            AND rectangle_height > 0
            AND rectangle_x + rectangle_width <= source_width
            AND rectangle_y + rectangle_height <= source_height)
        OR
        (artifact_kind = 'source_image_reference'
            AND rectangle_x IS NULL
            AND rectangle_y IS NULL
            AND rectangle_width IS NULL
            AND rectangle_height IS NULL)
    ),
    CHECK (
        (segmentation_outcome = 'unavailable'
            AND unavailable_reason IS NOT NULL
            AND failure_code IS NULL)
        OR
        (segmentation_outcome = 'failed'
            AND unavailable_reason IS NULL
            AND failure_code IS NOT NULL)
        OR
        (segmentation_outcome NOT IN ('unavailable', 'failed')
            AND unavailable_reason IS NULL
            AND failure_code IS NULL)
    ),
    UNIQUE(
        artifact_id, scope_id, member_ordinal,
        source_revision_id, attempt_id
    ),
    UNIQUE(artifact_id, scope_id, source_revision_id),
    FOREIGN KEY(scope_id, member_ordinal, source_revision_id)
        REFERENCES photo_scope_members(
            scope_id, member_ordinal, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(attempt_id, scope_id, member_ordinal, source_revision_id)
        REFERENCES photo_segmentation_attempts(
            attempt_id, scope_id, member_ordinal, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(attempt_id, request_mode)
        REFERENCES photo_segmentation_attempts(attempt_id, request_mode)
        ON DELETE RESTRICT,
    FOREIGN KEY(attempt_id, segmentation_outcome)
        REFERENCES photo_segmentation_outcomes(attempt_id, outcome)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(
        source_revision_id, source_revision_sha256, input_blob_sha256,
        media_type, source_width, source_height
    ) REFERENCES photo_source_revisions(
        source_revision_id, source_revision_sha256, blob_sha256,
        media_type, width, height
    ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_artifact_parents (
    artifact_id TEXT NOT NULL,
    parent_ordinal INTEGER NOT NULL CHECK (parent_ordinal BETWEEN 0 AND 15),
    parent_artifact_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    source_revision_id TEXT NOT NULL,
    relationship TEXT NOT NULL CHECK (relationship = 'derived_from'),
    PRIMARY KEY(artifact_id, parent_ordinal),
    UNIQUE(artifact_id, parent_artifact_id),
    CHECK (artifact_id <> parent_artifact_id),
    FOREIGN KEY(artifact_id, scope_id, source_revision_id)
        REFERENCES photo_artifacts(
            artifact_id, scope_id, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(parent_artifact_id, scope_id, source_revision_id)
        REFERENCES photo_artifacts(
            artifact_id, scope_id, source_revision_id
        ) ON DELETE RESTRICT
) STRICT;

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
    UNIQUE(scope_id, member_ordinal),
    UNIQUE(scope_id, source_revision_id),
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

CREATE TABLE photo_review_decisions (
    decision_id TEXT PRIMARY KEY CHECK (
        length(decision_id) = 36
        AND decision_id <> '00000000-0000-0000-0000-000000000000'
    ),
    observation_id TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    source_revision_id TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    action TEXT NOT NULL CHECK (
        action IN ('confirm_crop', 'replace_crop', 'defer', 'reject')
    ),
    selected_artifact_id TEXT,
    expected_photo_revision INTEGER NOT NULL CHECK (
        expected_photo_revision BETWEEN 0 AND 9007199254740989
    ),
    photo_revision INTEGER NOT NULL UNIQUE CHECK (
        photo_revision BETWEEN 1 AND 9007199254740990
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (photo_revision = expected_photo_revision + 1),
    CHECK (
        (action IN ('confirm_crop', 'replace_crop')
            AND selected_artifact_id IS NOT NULL)
        OR
        (action IN ('defer', 'reject') AND selected_artifact_id IS NULL)
    ),
    UNIQUE(
        decision_id, observation_id, scope_id,
        source_revision_id, photo_revision
    ),
    FOREIGN KEY(observation_id, scope_id, source_revision_id)
        REFERENCES photo_observations(
            observation_id, scope_id, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(selected_artifact_id, scope_id, source_revision_id)
        REFERENCES photo_artifacts(
            artifact_id, scope_id, source_revision_id
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_review_heads (
    observation_id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL,
    source_revision_id TEXT NOT NULL,
    decision_id TEXT NOT NULL UNIQUE
        REFERENCES photo_review_decisions(decision_id) ON DELETE RESTRICT,
    current_artifact_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('confirmed', 'replaced', 'deferred', 'rejected')
    ),
    photo_revision INTEGER NOT NULL UNIQUE CHECK (
        photo_revision BETWEEN 1 AND 9007199254740990
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    UNIQUE(observation_id, scope_id, source_revision_id),
    FOREIGN KEY(observation_id, scope_id, source_revision_id)
        REFERENCES photo_observations(
            observation_id, scope_id, source_revision_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(current_artifact_id, scope_id, source_revision_id)
        REFERENCES photo_artifacts(
            artifact_id, scope_id, source_revision_id
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photo_command_entities (
    request_id TEXT NOT NULL
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    entity_kind TEXT NOT NULL CHECK (
        entity_kind IN (
            'scope', 'source_revision', 'run', 'segmentation_attempt',
            'artifact', 'observation', 'review_decision'
        )
    ),
    entity_id TEXT NOT NULL CHECK (length(entity_id) = 36),
    PRIMARY KEY(request_id, entity_kind, entity_id)
) STRICT;

CREATE INDEX photo_source_revisions_source_idx
    ON photo_source_revisions(source_id, manifest_generation, source_revision_id);
CREATE INDEX photo_source_revisions_blob_idx
    ON photo_source_revisions(blob_sha256, source_revision_id);
CREATE INDEX photo_scope_members_revision_idx
    ON photo_scope_members(source_revision_id, scope_id, member_ordinal);
CREATE INDEX photo_analysis_runs_scope_idx
    ON photo_analysis_runs(scope_id, created_at_ms, run_id);
CREATE INDEX photo_analysis_claims_ready_idx
    ON photo_analysis_member_claims(run_id, state, member_ordinal);
CREATE INDEX photo_analysis_claims_expired_idx
    ON photo_analysis_member_claims(lease_expires_at_ms, run_id, member_ordinal)
    WHERE state = 'running';
CREATE INDEX photo_segmentation_attempts_member_idx
    ON photo_segmentation_attempts(
        scope_id, member_ordinal, created_at_ms, attempt_id
    );
CREATE INDEX photo_artifacts_source_idx
    ON photo_artifacts(source_revision_id, created_at_ms, artifact_id);
CREATE INDEX photo_artifact_parents_parent_idx
    ON photo_artifact_parents(parent_artifact_id, artifact_id);
CREATE INDEX photo_observations_scope_idx
    ON photo_observations(scope_id, created_at_ms, observation_id);
CREATE INDEX photo_review_decisions_observation_idx
    ON photo_review_decisions(observation_id, photo_revision);
CREATE INDEX photo_review_heads_state_idx
    ON photo_review_heads(state, photo_revision, observation_id);
CREATE INDEX photo_command_entities_entity_idx
    ON photo_command_entities(entity_kind, entity_id, request_id);

CREATE TRIGGER photo_scopes_no_update
BEFORE UPDATE ON photo_scopes
BEGIN
    SELECT RAISE(ABORT, 'photo scopes are immutable');
END;

CREATE TRIGGER photo_scopes_no_delete
BEFORE DELETE ON photo_scopes
BEGIN
    SELECT RAISE(ABORT, 'photo scopes are immutable');
END;

CREATE TRIGGER photo_source_revisions_no_update
BEFORE UPDATE ON photo_source_revisions
BEGIN
    SELECT RAISE(ABORT, 'photo source revisions are immutable');
END;

CREATE TRIGGER photo_source_revisions_no_delete
BEFORE DELETE ON photo_source_revisions
BEGIN
    SELECT RAISE(ABORT, 'photo source revisions are immutable');
END;

CREATE TRIGGER photo_scope_members_no_update
BEFORE UPDATE ON photo_scope_members
BEGIN
    SELECT RAISE(ABORT, 'photo scope members are immutable');
END;

CREATE TRIGGER photo_scope_members_no_delete
BEFORE DELETE ON photo_scope_members
BEGIN
    SELECT RAISE(ABORT, 'photo scope members are immutable');
END;

CREATE TRIGGER photo_analysis_runs_validate_update
BEFORE UPDATE ON photo_analysis_runs
WHEN NEW.run_id <> OLD.run_id
    OR NEW.request_id <> OLD.request_id
    OR NEW.request_envelope_sha256 <> OLD.request_envelope_sha256
    OR NEW.scope_id <> OLD.scope_id
    OR NEW.provider_contract_revision <> OLD.provider_contract_revision
    OR NEW.provider_id <> OLD.provider_id
    OR NEW.provider_revision <> OLD.provider_revision
    OR NEW.model_revision IS NOT OLD.model_revision
    OR NEW.preprocessing_revision <> OLD.preprocessing_revision
    OR NEW.quality_gate_revision <> OLD.quality_gate_revision
    OR NEW.eligible_member_count <> OLD.eligible_member_count
    OR NEW.terminal_member_count < OLD.terminal_member_count
    OR NEW.created_at_ms <> OLD.created_at_ms
    OR NEW.updated_at_ms < OLD.updated_at_ms
    OR OLD.state = 'completed'
    OR (OLD.state = 'running' AND NEW.state = 'pending')
BEGIN
    SELECT RAISE(ABORT, 'photo analysis run update is invalid');
END;

CREATE TRIGGER photo_analysis_runs_no_delete
BEFORE DELETE ON photo_analysis_runs
BEGIN
    SELECT RAISE(ABORT, 'photo analysis runs cannot be deleted');
END;

CREATE TRIGGER photo_analysis_claims_validate_update
BEFORE UPDATE ON photo_analysis_member_claims
WHEN NEW.run_id <> OLD.run_id
    OR NEW.scope_id <> OLD.scope_id
    OR NEW.member_ordinal <> OLD.member_ordinal
    OR NEW.source_revision_id <> OLD.source_revision_id
    OR NEW.disposition <> OLD.disposition
    OR NEW.attempt_count < OLD.attempt_count
    OR NEW.fence < OLD.fence
    OR NEW.created_at_ms <> OLD.created_at_ms
    OR NEW.updated_at_ms < OLD.updated_at_ms
    OR OLD.state = 'terminal'
BEGIN
    SELECT RAISE(ABORT, 'photo member claim update is invalid');
END;

CREATE TRIGGER photo_analysis_claims_no_delete
BEFORE DELETE ON photo_analysis_member_claims
BEGIN
    SELECT RAISE(ABORT, 'photo member claims cannot be deleted');
END;

CREATE TRIGGER photo_segmentation_attempts_no_update
BEFORE UPDATE ON photo_segmentation_attempts
BEGIN
    SELECT RAISE(ABORT, 'photo segmentation attempts are immutable');
END;

CREATE TRIGGER photo_segmentation_attempts_no_delete
BEFORE DELETE ON photo_segmentation_attempts
BEGIN
    SELECT RAISE(ABORT, 'photo segmentation attempts are immutable');
END;

CREATE TRIGGER photo_segmentation_outcomes_no_update
BEFORE UPDATE ON photo_segmentation_outcomes
BEGIN
    SELECT RAISE(ABORT, 'photo segmentation outcomes are immutable');
END;

CREATE TRIGGER photo_segmentation_outcomes_no_delete
BEFORE DELETE ON photo_segmentation_outcomes
BEGIN
    SELECT RAISE(ABORT, 'photo segmentation outcomes are immutable');
END;

CREATE TRIGGER photo_artifacts_no_update
BEFORE UPDATE ON photo_artifacts
BEGIN
    SELECT RAISE(ABORT, 'photo artifacts are immutable');
END;

CREATE TRIGGER photo_artifacts_no_delete
BEFORE DELETE ON photo_artifacts
BEGIN
    SELECT RAISE(ABORT, 'photo artifacts are immutable');
END;

CREATE TRIGGER photo_artifact_parents_no_update
BEFORE UPDATE ON photo_artifact_parents
BEGIN
    SELECT RAISE(ABORT, 'photo artifact parents are immutable');
END;

CREATE TRIGGER photo_artifact_parents_no_delete
BEFORE DELETE ON photo_artifact_parents
BEGIN
    SELECT RAISE(ABORT, 'photo artifact parents are immutable');
END;

CREATE TRIGGER photo_observations_no_update
BEFORE UPDATE ON photo_observations
BEGIN
    SELECT RAISE(ABORT, 'photo observations are immutable');
END;

CREATE TRIGGER photo_observations_no_delete
BEFORE DELETE ON photo_observations
BEGIN
    SELECT RAISE(ABORT, 'photo observations are immutable');
END;

CREATE TRIGGER photo_review_decisions_no_update
BEFORE UPDATE ON photo_review_decisions
BEGIN
    SELECT RAISE(ABORT, 'photo review decisions are append-only');
END;

CREATE TRIGGER photo_review_decisions_no_delete
BEFORE DELETE ON photo_review_decisions
BEGIN
    SELECT RAISE(ABORT, 'photo review decisions are append-only');
END;

CREATE TRIGGER photo_review_heads_validate_insert
BEFORE INSERT ON photo_review_heads
WHEN NOT EXISTS (
        SELECT 1
        FROM photo_review_decisions decision
        WHERE decision.decision_id = NEW.decision_id
          AND decision.observation_id = NEW.observation_id
          AND decision.scope_id = NEW.scope_id
          AND decision.source_revision_id = NEW.source_revision_id
          AND decision.photo_revision = NEW.photo_revision
          AND (
              (decision.action = 'confirm_crop'
                  AND NEW.state = 'confirmed'
                  AND decision.selected_artifact_id = NEW.current_artifact_id)
              OR
              (decision.action = 'replace_crop'
                  AND NEW.state = 'replaced'
                  AND decision.selected_artifact_id = NEW.current_artifact_id)
              OR (decision.action = 'defer' AND NEW.state = 'deferred')
              OR (decision.action = 'reject' AND NEW.state = 'rejected')
          )
    )
BEGIN
    SELECT RAISE(ABORT, 'photo review head is invalid');
END;

CREATE TRIGGER photo_review_heads_validate_update
BEFORE UPDATE ON photo_review_heads
WHEN NEW.observation_id <> OLD.observation_id
    OR NEW.scope_id <> OLD.scope_id
    OR NEW.source_revision_id <> OLD.source_revision_id
    OR NEW.photo_revision <= OLD.photo_revision
    OR NEW.updated_at_ms < OLD.updated_at_ms
    OR NOT EXISTS (
        SELECT 1
        FROM photo_review_decisions decision
        WHERE decision.decision_id = NEW.decision_id
          AND decision.observation_id = NEW.observation_id
          AND decision.scope_id = NEW.scope_id
          AND decision.source_revision_id = NEW.source_revision_id
          AND decision.photo_revision = NEW.photo_revision
          AND (
              (decision.action = 'confirm_crop'
                  AND NEW.state = 'confirmed'
                  AND decision.selected_artifact_id = NEW.current_artifact_id)
              OR
              (decision.action = 'replace_crop'
                  AND NEW.state = 'replaced'
                  AND decision.selected_artifact_id = NEW.current_artifact_id)
              OR (decision.action = 'defer' AND NEW.state = 'deferred')
              OR (decision.action = 'reject' AND NEW.state = 'rejected')
          )
    )
BEGIN
    SELECT RAISE(ABORT, 'photo review head is invalid');
END;

CREATE TRIGGER photo_review_heads_no_delete
BEFORE DELETE ON photo_review_heads
BEGIN
    SELECT RAISE(ABORT, 'photo review heads cannot be deleted');
END;

CREATE TRIGGER photo_command_entities_no_update
BEFORE UPDATE ON photo_command_entities
BEGIN
    SELECT RAISE(ABORT, 'photo command entity links are append-only');
END;

CREATE TRIGGER photo_command_entities_no_delete
BEFORE DELETE ON photo_command_entities
BEGIN
    SELECT RAISE(ABORT, 'photo command entity links are append-only');
END;
