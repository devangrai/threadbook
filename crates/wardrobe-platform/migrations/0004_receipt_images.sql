ALTER TABLE receipt_command_entities RENAME TO receipt_command_entities_v3;

CREATE TABLE receipt_command_entities (
    request_id TEXT NOT NULL
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    entity_kind TEXT NOT NULL CHECK (
        entity_kind IN (
            'source', 'parse', 'order', 'review_decision',
            'image_candidate', 'image_approval', 'image_attempt', 'remote_image'
        )
    ),
    entity_id TEXT NOT NULL,
    PRIMARY KEY(request_id, entity_kind, entity_id)
) STRICT;

INSERT INTO receipt_command_entities(request_id, entity_kind, entity_id)
SELECT request_id, entity_kind, entity_id
FROM receipt_command_entities_v3;

DROP TABLE receipt_command_entities_v3;

CREATE INDEX receipt_command_entities_entity_idx
    ON receipt_command_entities(entity_kind, entity_id, request_id);

CREATE UNIQUE INDEX receipt_parses_id_source_idx
    ON receipt_parses(parse_id, source_id);

CREATE TABLE receipt_image_candidates (
    candidate_id TEXT PRIMARY KEY CHECK (length(candidate_id) = 36),
    parse_id TEXT NOT NULL
        REFERENCES receipt_parses(parse_id) ON DELETE RESTRICT,
    source_id TEXT NOT NULL
        REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    part_ordinal INTEGER NOT NULL CHECK (part_ordinal BETWEEN 0 AND 199),
    occurrence_count INTEGER NOT NULL CHECK (
        occurrence_count BETWEEN 1 AND 65535
    ),
    normalized_url TEXT NOT NULL CHECK (
        length(CAST(normalized_url AS BLOB)) BETWEEN 1 AND 2048
        AND normalized_url NOT GLOB '*[^ -~]*'
    ),
    display_host TEXT NOT NULL CHECK (
        length(CAST(display_host AS BLOB)) BETWEEN 1 AND 253
        AND display_host NOT GLOB '*[^ -~]*'
    ),
    candidate_url_sha256 TEXT NOT NULL CHECK (
        length(candidate_url_sha256) = 64
        AND candidate_url_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    eligibility TEXT NOT NULL CHECK (eligibility IN ('eligible', 'blocked')),
    policy_block_code TEXT CHECK (
        policy_block_code IS NULL
        OR (
            length(policy_block_code) BETWEEN 1 AND 64
            AND policy_block_code NOT GLOB '*[^a-z0-9_]*'
        )
    ),
    created_at_ms INTEGER NOT NULL,
    CHECK (
        (eligibility = 'eligible' AND policy_block_code IS NULL)
        OR (eligibility = 'blocked' AND policy_block_code IS NOT NULL)
    ),
    UNIQUE(parse_id, part_ordinal, candidate_url_sha256),
    UNIQUE(candidate_id, source_id),
    UNIQUE(candidate_id, candidate_url_sha256),
    UNIQUE(candidate_id, candidate_url_sha256, display_host),
    FOREIGN KEY(parse_id, source_id)
        REFERENCES receipt_parses(parse_id, source_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE receipt_image_candidate_overflow (
    parse_id TEXT PRIMARY KEY
        REFERENCES receipt_parses(parse_id) ON DELETE RESTRICT,
    omitted_count INTEGER NOT NULL CHECK (omitted_count BETWEEN 1 AND 65535),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE receipt_image_approvals (
    approval_id TEXT PRIMARY KEY CHECK (length(approval_id) = 36),
    request_id TEXT NOT NULL UNIQUE,
    candidate_id TEXT NOT NULL
        REFERENCES receipt_image_candidates(candidate_id) ON DELETE RESTRICT,
    approved_display_host TEXT NOT NULL CHECK (
        length(CAST(approved_display_host AS BLOB)) BETWEEN 1 AND 253
        AND approved_display_host NOT GLOB '*[^ -~]*'
    ),
    approved_url_sha256 TEXT NOT NULL CHECK (
        length(approved_url_sha256) = 64
        AND approved_url_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    prior_attempt_id TEXT
        REFERENCES receipt_image_attempts(attempt_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    approved_at_ms INTEGER NOT NULL,
    UNIQUE(approval_id, candidate_id),
    UNIQUE(request_id, candidate_id),
    FOREIGN KEY(candidate_id, approved_url_sha256, approved_display_host)
        REFERENCES receipt_image_candidates(
            candidate_id, candidate_url_sha256, display_host
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE receipt_image_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (length(attempt_id) = 36),
    candidate_id TEXT NOT NULL
        REFERENCES receipt_image_candidates(candidate_id) ON DELETE RESTRICT,
    approval_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    request_envelope_sha256 TEXT NOT NULL CHECK (
        length(request_envelope_sha256) = 64
        AND request_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    prior_attempt_id TEXT
        REFERENCES receipt_image_attempts(attempt_id) ON DELETE RESTRICT,
    download_token_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(download_token_sha256) = 64
        AND download_token_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    staging_nonce TEXT NOT NULL UNIQUE CHECK (
        length(staging_nonce) BETWEEN 16 AND 128
        AND staging_nonce NOT GLOB '*[^A-Za-z0-9_-]*'
    ),
    policy_revision TEXT NOT NULL CHECK (
        length(policy_revision) BETWEEN 1 AND 128
    ),
    deadline_at_ms INTEGER NOT NULL,
    settlement_until_ms INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    CHECK (deadline_at_ms >= created_at_ms),
    CHECK (settlement_until_ms >= deadline_at_ms),
    UNIQUE(attempt_id, candidate_id),
    UNIQUE(approval_id, candidate_id),
    FOREIGN KEY(approval_id, candidate_id)
        REFERENCES receipt_image_approvals(approval_id, candidate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(request_id, candidate_id)
        REFERENCES receipt_image_approvals(request_id, candidate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(prior_attempt_id, candidate_id)
        REFERENCES receipt_image_attempts(attempt_id, candidate_id)
        ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX receipt_image_attempt_first_idx
    ON receipt_image_attempts(candidate_id)
    WHERE prior_attempt_id IS NULL;

CREATE UNIQUE INDEX receipt_image_attempt_successor_idx
    ON receipt_image_attempts(prior_attempt_id)
    WHERE prior_attempt_id IS NOT NULL;

CREATE TABLE receipt_image_attempt_outcomes (
    attempt_id TEXT PRIMARY KEY
        REFERENCES receipt_image_attempts(attempt_id) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK (
        outcome IN (
            'succeeded', 'policy_rejected', 'transport_failed',
            'response_rejected', 'ambiguous'
        )
    ),
    failure_code TEXT CHECK (
        failure_code IS NULL
        OR (
            length(failure_code) BETWEEN 1 AND 64
            AND failure_code NOT GLOB '*[^a-z0-9_]*'
        )
    ),
    response_json TEXT NOT NULL CHECK (
        json_valid(response_json)
        AND length(CAST(response_json AS BLOB)) <= 32768
    ),
    completed_at_ms INTEGER NOT NULL,
    CHECK (
        (outcome = 'succeeded' AND failure_code IS NULL)
        OR (outcome <> 'succeeded' AND failure_code IS NOT NULL)
    )
) STRICT;

CREATE TABLE receipt_image_hops (
    attempt_id TEXT NOT NULL
        REFERENCES receipt_image_attempts(attempt_id) ON DELETE RESTRICT,
    hop_ordinal INTEGER NOT NULL CHECK (hop_ordinal BETWEEN 0 AND 3),
    url_sha256 TEXT NOT NULL CHECK (
        length(url_sha256) = 64 AND url_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    host_sha256 TEXT NOT NULL CHECK (
        length(host_sha256) = 64 AND host_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    pinned_addresses_json TEXT NOT NULL CHECK (
        json_valid(pinned_addresses_json)
        AND length(CAST(pinned_addresses_json AS BLOB)) <= 2048
    ),
    http_status INTEGER CHECK (http_status IS NULL OR http_status BETWEEN 100 AND 599),
    PRIMARY KEY(attempt_id, hop_ordinal)
) STRICT;

CREATE TABLE receipt_image_materialization_intents (
    intent_id TEXT PRIMARY KEY CHECK (length(intent_id) = 36),
    attempt_id TEXT NOT NULL UNIQUE
        REFERENCES receipt_image_attempts(attempt_id) ON DELETE RESTRICT,
    source_staging_name TEXT NOT NULL UNIQUE CHECK (
        length(source_staging_name) BETWEEN 1 AND 160
        AND source_staging_name NOT GLOB '*[^A-Za-z0-9_.-]*'
        AND source_staging_name NOT IN ('.', '..')
    ),
    display_staging_name TEXT NOT NULL UNIQUE CHECK (
        length(display_staging_name) BETWEEN 1 AND 160
        AND display_staging_name NOT GLOB '*[^A-Za-z0-9_.-]*'
        AND display_staging_name NOT IN ('.', '..')
    ),
    source_blob_sha256 TEXT NOT NULL CHECK (
        length(source_blob_sha256) = 64
        AND source_blob_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_byte_length INTEGER NOT NULL CHECK (
        source_byte_length BETWEEN 1 AND 8388608
    ),
    display_blob_sha256 TEXT NOT NULL CHECK (
        length(display_blob_sha256) = 64
        AND display_blob_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    display_byte_length INTEGER NOT NULL CHECK (
        display_byte_length BETWEEN 1 AND 71303168
    ),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE receipt_remote_images (
    image_id TEXT PRIMARY KEY CHECK (length(image_id) = 36),
    candidate_id TEXT NOT NULL
        REFERENCES receipt_image_candidates(candidate_id) ON DELETE RESTRICT,
    attempt_id TEXT NOT NULL UNIQUE,
    source_blob_sha256 TEXT NOT NULL
        REFERENCES blobs(sha256) ON DELETE RESTRICT,
    source_byte_length INTEGER NOT NULL CHECK (
        source_byte_length BETWEEN 1 AND 8388608
    ),
    source_media_type TEXT NOT NULL CHECK (
        source_media_type IN ('image/jpeg', 'image/png', 'image/webp')
    ),
    display_blob_sha256 TEXT NOT NULL
        REFERENCES blobs(sha256) ON DELETE RESTRICT,
    display_byte_length INTEGER NOT NULL CHECK (
        display_byte_length BETWEEN 1 AND 71303168
    ),
    display_media_type TEXT NOT NULL CHECK (display_media_type = 'image/png'),
    width INTEGER NOT NULL CHECK (width BETWEEN 32 AND 4096),
    height INTEGER NOT NULL CHECK (height BETWEEN 32 AND 4096),
    candidate_url_sha256 TEXT NOT NULL CHECK (
        length(candidate_url_sha256) = 64
        AND candidate_url_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    final_url_sha256 TEXT NOT NULL CHECK (
        length(final_url_sha256) = 64
        AND final_url_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    declared_byte_length INTEGER CHECK (
        declared_byte_length IS NULL
        OR declared_byte_length BETWEEN 1 AND 8388608
    ),
    observed_byte_length INTEGER NOT NULL CHECK (
        observed_byte_length BETWEEN 1 AND 8388608
    ),
    http_status INTEGER NOT NULL CHECK (http_status = 200),
    policy_revision TEXT NOT NULL CHECK (
        length(policy_revision) BETWEEN 1 AND 128
    ),
    decoder_revision TEXT NOT NULL CHECK (
        length(decoder_revision) BETWEEN 1 AND 128
    ),
    derivative_revision TEXT NOT NULL CHECK (
        length(derivative_revision) BETWEEN 1 AND 128
    ),
    parent_parse_sha256 TEXT NOT NULL CHECK (
        length(parent_parse_sha256) = 64
        AND parent_parse_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    parent_source_sha256 TEXT NOT NULL CHECK (
        length(parent_source_sha256) = 64
        AND parent_source_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    provenance_json TEXT NOT NULL CHECK (
        json_valid(provenance_json)
        AND length(CAST(provenance_json AS BLOB)) <= 32768
    ),
    created_at_ms INTEGER NOT NULL,
    CHECK (width * height <= 16777216),
    UNIQUE(image_id, candidate_id),
    FOREIGN KEY(attempt_id, candidate_id)
        REFERENCES receipt_image_attempts(attempt_id, candidate_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(candidate_id, candidate_url_sha256)
        REFERENCES receipt_image_candidates(candidate_id, candidate_url_sha256)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX receipt_image_candidates_source_idx
    ON receipt_image_candidates(source_id, part_ordinal, candidate_id);
CREATE INDEX receipt_image_candidates_parse_idx
    ON receipt_image_candidates(parse_id, part_ordinal, candidate_id);
CREATE INDEX receipt_image_attempts_candidate_idx
    ON receipt_image_attempts(candidate_id, created_at_ms, attempt_id);
CREATE INDEX receipt_image_outcomes_completed_idx
    ON receipt_image_attempt_outcomes(completed_at_ms, attempt_id);
CREATE INDEX receipt_remote_images_candidate_idx
    ON receipt_remote_images(candidate_id, created_at_ms, image_id);
CREATE INDEX receipt_remote_images_source_blob_idx
    ON receipt_remote_images(source_blob_sha256, image_id);
CREATE INDEX receipt_remote_images_display_blob_idx
    ON receipt_remote_images(display_blob_sha256, image_id);
CREATE INDEX receipt_image_intents_source_blob_idx
    ON receipt_image_materialization_intents(source_blob_sha256, intent_id);
CREATE INDEX receipt_image_intents_display_blob_idx
    ON receipt_image_materialization_intents(display_blob_sha256, intent_id);

CREATE TRIGGER receipt_image_candidates_no_update
BEFORE UPDATE ON receipt_image_candidates
BEGIN
    SELECT RAISE(ABORT, 'receipt image candidates are immutable');
END;

CREATE TRIGGER receipt_image_candidates_no_delete
BEFORE DELETE ON receipt_image_candidates
BEGIN
    SELECT RAISE(ABORT, 'receipt image candidates are immutable');
END;

CREATE TRIGGER receipt_image_candidate_overflow_no_update
BEFORE UPDATE ON receipt_image_candidate_overflow
BEGIN
    SELECT RAISE(ABORT, 'receipt image candidate overflow is immutable');
END;

CREATE TRIGGER receipt_image_candidate_overflow_no_delete
BEFORE DELETE ON receipt_image_candidate_overflow
BEGIN
    SELECT RAISE(ABORT, 'receipt image candidate overflow is immutable');
END;

CREATE TRIGGER receipt_image_approvals_no_update
BEFORE UPDATE ON receipt_image_approvals
BEGIN
    SELECT RAISE(ABORT, 'receipt image approvals are append-only');
END;

CREATE TRIGGER receipt_image_approvals_no_delete
BEFORE DELETE ON receipt_image_approvals
BEGIN
    SELECT RAISE(ABORT, 'receipt image approvals are append-only');
END;

CREATE TRIGGER receipt_image_attempts_no_update
BEFORE UPDATE ON receipt_image_attempts
BEGIN
    SELECT RAISE(ABORT, 'receipt image attempts are append-only');
END;

CREATE TRIGGER receipt_image_attempts_no_delete
BEFORE DELETE ON receipt_image_attempts
BEGIN
    SELECT RAISE(ABORT, 'receipt image attempts are append-only');
END;

CREATE TRIGGER receipt_image_attempt_outcomes_no_update
BEFORE UPDATE ON receipt_image_attempt_outcomes
BEGIN
    SELECT RAISE(ABORT, 'receipt image attempt outcomes are append-only');
END;

CREATE TRIGGER receipt_image_attempt_outcomes_no_delete
BEFORE DELETE ON receipt_image_attempt_outcomes
BEGIN
    SELECT RAISE(ABORT, 'receipt image attempt outcomes are append-only');
END;

CREATE TRIGGER receipt_image_hops_no_update
BEFORE UPDATE ON receipt_image_hops
BEGIN
    SELECT RAISE(ABORT, 'receipt image hops are append-only');
END;

CREATE TRIGGER receipt_image_hops_no_delete
BEFORE DELETE ON receipt_image_hops
BEGIN
    SELECT RAISE(ABORT, 'receipt image hops are append-only');
END;

CREATE TRIGGER receipt_image_materialization_intents_no_update
BEFORE UPDATE ON receipt_image_materialization_intents
BEGIN
    SELECT RAISE(ABORT, 'receipt image materialization intents are append-only');
END;

CREATE TRIGGER receipt_image_materialization_intents_no_delete
BEFORE DELETE ON receipt_image_materialization_intents
BEGIN
    SELECT RAISE(ABORT, 'receipt image materialization intents are append-only');
END;

CREATE TRIGGER receipt_remote_images_no_update
BEFORE UPDATE ON receipt_remote_images
BEGIN
    SELECT RAISE(ABORT, 'receipt remote images are immutable');
END;

CREATE TRIGGER receipt_remote_images_no_delete
BEFORE DELETE ON receipt_remote_images
BEGIN
    SELECT RAISE(ABORT, 'receipt remote images are immutable');
END;
