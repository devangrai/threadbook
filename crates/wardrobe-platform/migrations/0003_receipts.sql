ALTER TABLE revision_state
ADD COLUMN receipt_revision INTEGER NOT NULL DEFAULT 0
CHECK (receipt_revision >= 0);

DROP INDEX evidence_state_idx;
ALTER TABLE item_evidence RENAME TO item_evidence_v2;
ALTER TABLE evidence RENAME TO evidence_v2;

CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    part_id TEXT REFERENCES mime_parts(part_id) ON DELETE RESTRICT,
    evidence_kind TEXT NOT NULL CHECK (
        evidence_kind IN ('image', 'message_attachment', 'receipt_order_line')
    ),
    state TEXT NOT NULL CHECK (state IN ('unresolved', 'assigned', 'rejected', 'deferred')),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    UNIQUE(source_id, part_id, evidence_kind)
) STRICT;

INSERT INTO evidence(
    evidence_id, source_id, part_id, evidence_kind, state, created_at_ms, updated_at_ms
)
SELECT evidence_id, source_id, part_id, evidence_kind, state, created_at_ms, updated_at_ms
FROM evidence_v2;

CREATE TABLE item_evidence (
    item_id TEXT NOT NULL REFERENCES catalog_items(item_id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL UNIQUE REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    assigned_revision INTEGER NOT NULL CHECK (assigned_revision > 0),
    PRIMARY KEY(item_id, evidence_id)
) STRICT;

INSERT INTO item_evidence(item_id, evidence_id, assigned_revision)
SELECT item_id, evidence_id, assigned_revision
FROM item_evidence_v2;

DROP TABLE item_evidence_v2;
DROP TABLE evidence_v2;

CREATE INDEX evidence_state_idx ON evidence(state, created_at_ms, evidence_id);

CREATE TABLE receipt_parses (
    parse_id TEXT PRIMARY KEY CHECK (length(parse_id) = 36),
    source_id TEXT NOT NULL REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    raw_sha256 TEXT NOT NULL CHECK (length(raw_sha256) = 64),
    parser_revision TEXT NOT NULL CHECK (length(parser_revision) BETWEEN 1 AND 128),
    sanitizer_revision TEXT NOT NULL CHECK (length(sanitizer_revision) BETWEEN 1 AND 128),
    canonical_input_sha256 TEXT NOT NULL CHECK (length(canonical_input_sha256) = 64),
    created_at_ms INTEGER NOT NULL,
    UNIQUE(source_id, raw_sha256, parser_revision, sanitizer_revision)
) STRICT;

CREATE TABLE receipt_fragments (
    fragment_id TEXT PRIMARY KEY CHECK (length(fragment_id) = 36),
    parse_id TEXT NOT NULL REFERENCES receipt_parses(parse_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 199),
    fragment_kind TEXT NOT NULL CHECK (
        fragment_kind IN (
            'plain_text', 'sanitized_html', 'attachment_metadata', 'cid_metadata'
        )
    ),
    content_text TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    metadata_json TEXT CHECK (metadata_json IS NULL OR json_valid(metadata_json)),
    byte_length INTEGER NOT NULL CHECK (byte_length BETWEEN 0 AND 32768),
    CHECK (length(CAST(content_text AS BLOB)) = byte_length),
    CHECK (
        (fragment_kind IN ('plain_text', 'sanitized_html') AND metadata_json IS NULL)
        OR
        (fragment_kind IN ('attachment_metadata', 'cid_metadata')
            AND metadata_json IS NOT NULL)
    ),
    UNIQUE(parse_id, ordinal),
    UNIQUE(parse_id, fragment_id)
) STRICT;

CREATE TABLE receipt_extraction_runs (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) = 36),
    parse_id TEXT NOT NULL REFERENCES receipt_parses(parse_id) ON DELETE RESTRICT,
    provider_id TEXT NOT NULL CHECK (length(provider_id) BETWEEN 1 AND 128),
    provider_revision TEXT NOT NULL CHECK (length(provider_revision) BETWEEN 1 AND 128),
    schema_version TEXT NOT NULL CHECK (length(schema_version) BETWEEN 1 AND 128),
    schema_sha256 TEXT NOT NULL CHECK (length(schema_sha256) = 64),
    ruleset_revision TEXT NOT NULL CHECK (length(ruleset_revision) BETWEEN 1 AND 128),
    ruleset_sha256 TEXT NOT NULL CHECK (length(ruleset_sha256) = 64),
    parameters_json TEXT NOT NULL CHECK (json_valid(parameters_json)),
    canonical_input_sha256 TEXT NOT NULL CHECK (length(canonical_input_sha256) = 64),
    parent_source_sha256 TEXT NOT NULL CHECK (length(parent_source_sha256) = 64),
    parent_fragment_hashes_json TEXT NOT NULL CHECK (json_valid(parent_fragment_hashes_json)),
    envelope_json TEXT CHECK (envelope_json IS NULL OR json_valid(envelope_json)),
    output_json TEXT CHECK (output_json IS NULL OR json_valid(output_json)),
    output_sha256 TEXT CHECK (output_sha256 IS NULL OR length(output_sha256) = 64),
    status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed')),
    error_code TEXT CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    created_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    CHECK (
        (status = 'pending' AND envelope_json IS NULL AND output_json IS NULL
            AND output_sha256 IS NULL AND error_code IS NULL AND completed_at_ms IS NULL)
        OR
        (status = 'succeeded' AND envelope_json IS NOT NULL AND output_json IS NOT NULL
            AND output_sha256 IS NOT NULL AND error_code IS NULL
            AND completed_at_ms IS NOT NULL)
        OR
        (status = 'failed' AND envelope_json IS NULL AND output_json IS NULL
            AND output_sha256 IS NULL AND error_code IS NOT NULL
            AND completed_at_ms IS NOT NULL)
    ),
    UNIQUE(
        parse_id, provider_id, provider_revision, schema_version, schema_sha256,
        ruleset_revision, ruleset_sha256, parameters_json, canonical_input_sha256
    )
) STRICT;

CREATE TABLE receipt_orders (
    order_evidence_id TEXT PRIMARY KEY CHECK (length(order_evidence_id) = 36),
    run_id TEXT NOT NULL UNIQUE
        REFERENCES receipt_extraction_runs(run_id) ON DELETE RESTRICT,
    line_count INTEGER NOT NULL CHECK (line_count BETWEEN 1 AND 100),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE receipt_order_lines (
    order_line_id TEXT PRIMARY KEY CHECK (length(order_line_id) = 36),
    order_evidence_id TEXT NOT NULL
        REFERENCES receipt_orders(order_evidence_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 99),
    event_kind TEXT CHECK (
        event_kind IS NULL OR event_kind IN ('purchase', 'exchange', 'return')
    ),
    evidence_id TEXT UNIQUE REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(order_evidence_id, ordinal)
) STRICT;

CREATE TABLE receipt_variant_evidence (
    variant_evidence_id TEXT PRIMARY KEY CHECK (length(variant_evidence_id) = 36),
    order_line_id TEXT NOT NULL UNIQUE
        REFERENCES receipt_order_lines(order_line_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE receipt_fields (
    field_id TEXT PRIMARY KEY CHECK (length(field_id) = 36),
    order_evidence_id TEXT REFERENCES receipt_orders(order_evidence_id) ON DELETE RESTRICT,
    order_line_id TEXT REFERENCES receipt_order_lines(order_line_id) ON DELETE RESTRICT,
    variant_evidence_id TEXT
        REFERENCES receipt_variant_evidence(variant_evidence_id) ON DELETE RESTRICT,
    field_name TEXT NOT NULL CHECK (
        field_name IN (
            'merchant', 'order_identifier', 'purchase_date', 'currency',
            'description', 'event_kind', 'quantity', 'unit_price_minor',
            'brand', 'sku', 'size', 'color'
        )
    ),
    value_kind TEXT NOT NULL CHECK (value_kind IN ('string', 'enum', 'u64')),
    value_text TEXT,
    value_integer INTEGER,
    is_known INTEGER NOT NULL CHECK (is_known IN (0, 1)),
    created_at_ms INTEGER NOT NULL,
    CHECK (
        (order_evidence_id IS NOT NULL)
        + (order_line_id IS NOT NULL)
        + (variant_evidence_id IS NOT NULL) = 1
    ),
    CHECK (
        (is_known = 0 AND value_text IS NULL AND value_integer IS NULL)
        OR
        (is_known = 1 AND value_kind IN ('string', 'enum')
            AND value_text IS NOT NULL AND value_integer IS NULL)
        OR
        (is_known = 1 AND value_kind = 'u64'
            AND value_text IS NULL AND value_integer IS NOT NULL
            AND value_integer >= 0)
    ),
    UNIQUE(order_evidence_id, field_name),
    UNIQUE(order_line_id, field_name),
    UNIQUE(variant_evidence_id, field_name)
) STRICT;

CREATE TABLE receipt_field_citations (
    citation_id TEXT PRIMARY KEY CHECK (length(citation_id) = 36),
    field_id TEXT NOT NULL REFERENCES receipt_fields(field_id) ON DELETE RESTRICT,
    citation_ordinal INTEGER NOT NULL CHECK (citation_ordinal BETWEEN 0 AND 7),
    fragment_id TEXT NOT NULL
        REFERENCES receipt_fragments(fragment_id) ON DELETE RESTRICT,
    byte_start INTEGER NOT NULL CHECK (byte_start >= 0),
    byte_end INTEGER NOT NULL CHECK (
        byte_end > byte_start AND byte_end - byte_start <= 512
    ),
    quote_sha256 TEXT NOT NULL CHECK (length(quote_sha256) = 64),
    UNIQUE(field_id, citation_ordinal),
    UNIQUE(field_id, fragment_id, byte_start, byte_end)
) STRICT;

CREATE TABLE receipt_review_decisions (
    review_decision_id TEXT PRIMARY KEY CHECK (length(review_decision_id) = 36),
    order_evidence_id TEXT NOT NULL
        REFERENCES receipt_orders(order_evidence_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL UNIQUE,
    action TEXT NOT NULL CHECK (action IN ('confirm', 'correct', 'reject', 'defer')),
    reviewed_order_json TEXT CHECK (
        reviewed_order_json IS NULL OR json_valid(reviewed_order_json)
    ),
    receipt_revision INTEGER NOT NULL UNIQUE CHECK (receipt_revision > 0),
    created_at_ms INTEGER NOT NULL,
    CHECK (
        (action = 'correct' AND reviewed_order_json IS NOT NULL)
        OR (action <> 'correct' AND reviewed_order_json IS NULL)
    )
) STRICT;

CREATE TABLE receipt_review_heads (
    order_evidence_id TEXT PRIMARY KEY
        REFERENCES receipt_orders(order_evidence_id) ON DELETE RESTRICT,
    review_decision_id TEXT NOT NULL UNIQUE
        REFERENCES receipt_review_decisions(review_decision_id) ON DELETE RESTRICT,
    receipt_revision INTEGER NOT NULL CHECK (receipt_revision > 0),
    updated_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE receipt_command_entities (
    request_id TEXT NOT NULL
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    entity_kind TEXT NOT NULL CHECK (
        entity_kind IN ('source', 'parse', 'order', 'review_decision')
    ),
    entity_id TEXT NOT NULL,
    PRIMARY KEY(request_id, entity_kind, entity_id)
) STRICT;

CREATE INDEX receipt_parses_source_idx
    ON receipt_parses(source_id, created_at_ms, parse_id);
CREATE INDEX receipt_fragments_parse_idx
    ON receipt_fragments(parse_id, ordinal);
CREATE INDEX receipt_runs_parse_idx
    ON receipt_extraction_runs(parse_id, created_at_ms, run_id);
CREATE INDEX receipt_orders_created_idx
    ON receipt_orders(created_at_ms DESC, order_evidence_id DESC);
CREATE INDEX receipt_lines_order_idx
    ON receipt_order_lines(order_evidence_id, ordinal);
CREATE INDEX receipt_fields_order_idx
    ON receipt_fields(order_evidence_id, field_name);
CREATE INDEX receipt_fields_line_idx
    ON receipt_fields(order_line_id, field_name);
CREATE INDEX receipt_fields_variant_idx
    ON receipt_fields(variant_evidence_id, field_name);
CREATE INDEX receipt_citations_field_idx
    ON receipt_field_citations(field_id, citation_ordinal);
CREATE INDEX receipt_reviews_order_idx
    ON receipt_review_decisions(order_evidence_id, receipt_revision);
CREATE INDEX receipt_command_entities_entity_idx
    ON receipt_command_entities(entity_kind, entity_id, request_id);

CREATE TRIGGER receipt_parses_no_update
BEFORE UPDATE ON receipt_parses
BEGIN
    SELECT RAISE(ABORT, 'receipt parses are immutable');
END;

CREATE TRIGGER receipt_parses_no_delete
BEFORE DELETE ON receipt_parses
BEGIN
    SELECT RAISE(ABORT, 'receipt parses are immutable');
END;

CREATE TRIGGER receipt_fragments_no_update
BEFORE UPDATE ON receipt_fragments
BEGIN
    SELECT RAISE(ABORT, 'receipt fragments are immutable');
END;

CREATE TRIGGER receipt_fragments_no_delete
BEFORE DELETE ON receipt_fragments
BEGIN
    SELECT RAISE(ABORT, 'receipt fragments are immutable');
END;

CREATE TRIGGER receipt_runs_terminal_no_update
BEFORE UPDATE ON receipt_extraction_runs
WHEN OLD.status <> 'pending'
    OR NEW.run_id <> OLD.run_id
    OR NEW.parse_id <> OLD.parse_id
    OR NEW.provider_id <> OLD.provider_id
    OR NEW.provider_revision <> OLD.provider_revision
    OR NEW.schema_version <> OLD.schema_version
    OR NEW.schema_sha256 <> OLD.schema_sha256
    OR NEW.ruleset_revision <> OLD.ruleset_revision
    OR NEW.ruleset_sha256 <> OLD.ruleset_sha256
    OR NEW.parameters_json <> OLD.parameters_json
    OR NEW.canonical_input_sha256 <> OLD.canonical_input_sha256
    OR NEW.parent_source_sha256 <> OLD.parent_source_sha256
    OR NEW.parent_fragment_hashes_json <> OLD.parent_fragment_hashes_json
    OR NEW.created_at_ms <> OLD.created_at_ms
    OR NEW.status = 'pending'
BEGIN
    SELECT RAISE(ABORT, 'receipt extraction runs are immutable');
END;

CREATE TRIGGER receipt_runs_no_delete
BEFORE DELETE ON receipt_extraction_runs
BEGIN
    SELECT RAISE(ABORT, 'receipt extraction runs are immutable');
END;

CREATE TRIGGER receipt_orders_no_update
BEFORE UPDATE ON receipt_orders
BEGIN
    SELECT RAISE(ABORT, 'receipt orders are immutable');
END;

CREATE TRIGGER receipt_orders_no_delete
BEFORE DELETE ON receipt_orders
BEGIN
    SELECT RAISE(ABORT, 'receipt orders are immutable');
END;

CREATE TRIGGER receipt_order_lines_no_update
BEFORE UPDATE ON receipt_order_lines
BEGIN
    SELECT RAISE(ABORT, 'receipt order lines are immutable');
END;

CREATE TRIGGER receipt_order_lines_no_delete
BEFORE DELETE ON receipt_order_lines
BEGIN
    SELECT RAISE(ABORT, 'receipt order lines are immutable');
END;

CREATE TRIGGER receipt_variants_no_update
BEFORE UPDATE ON receipt_variant_evidence
BEGIN
    SELECT RAISE(ABORT, 'receipt variants are immutable');
END;

CREATE TRIGGER receipt_variants_no_delete
BEFORE DELETE ON receipt_variant_evidence
BEGIN
    SELECT RAISE(ABORT, 'receipt variants are immutable');
END;

CREATE TRIGGER receipt_fields_no_update
BEFORE UPDATE ON receipt_fields
BEGIN
    SELECT RAISE(ABORT, 'receipt fields are immutable');
END;

CREATE TRIGGER receipt_fields_no_delete
BEFORE DELETE ON receipt_fields
BEGIN
    SELECT RAISE(ABORT, 'receipt fields are immutable');
END;

CREATE TRIGGER receipt_citations_no_update
BEFORE UPDATE ON receipt_field_citations
BEGIN
    SELECT RAISE(ABORT, 'receipt citations are immutable');
END;

CREATE TRIGGER receipt_citations_no_delete
BEFORE DELETE ON receipt_field_citations
BEGIN
    SELECT RAISE(ABORT, 'receipt citations are immutable');
END;

CREATE TRIGGER receipt_review_decisions_no_update
BEFORE UPDATE ON receipt_review_decisions
BEGIN
    SELECT RAISE(ABORT, 'receipt review decisions are append-only');
END;

CREATE TRIGGER receipt_review_decisions_no_delete
BEFORE DELETE ON receipt_review_decisions
BEGIN
    SELECT RAISE(ABORT, 'receipt review decisions are append-only');
END;

CREATE TRIGGER receipt_review_heads_validate_insert
BEFORE INSERT ON receipt_review_heads
WHEN NOT EXISTS (
    SELECT 1
    FROM receipt_review_decisions decision
    WHERE decision.review_decision_id = NEW.review_decision_id
      AND decision.order_evidence_id = NEW.order_evidence_id
      AND decision.receipt_revision = NEW.receipt_revision
)
BEGIN
    SELECT RAISE(ABORT, 'receipt review head is invalid');
END;

CREATE TRIGGER receipt_review_heads_validate_update
BEFORE UPDATE ON receipt_review_heads
WHEN NEW.order_evidence_id <> OLD.order_evidence_id
    OR NEW.receipt_revision <= OLD.receipt_revision
    OR NOT EXISTS (
        SELECT 1
        FROM receipt_review_decisions decision
        WHERE decision.review_decision_id = NEW.review_decision_id
          AND decision.order_evidence_id = NEW.order_evidence_id
          AND decision.receipt_revision = NEW.receipt_revision
    )
BEGIN
    SELECT RAISE(ABORT, 'receipt review head is invalid');
END;
