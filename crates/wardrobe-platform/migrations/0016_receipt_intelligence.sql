ALTER TABLE revision_state
ADD COLUMN receipt_intelligence_revision INTEGER NOT NULL DEFAULT 0
CHECK (receipt_intelligence_revision >= 0);

CREATE TABLE receipt_intelligence_approvals (
    approval_id TEXT PRIMARY KEY CHECK (
        length(approval_id) = 36
        AND approval_id <> '00000000-0000-0000-0000-000000000000'
    ),
    request_id TEXT NOT NULL UNIQUE CHECK (
        length(request_id) = 36
        AND request_id <> '00000000-0000-0000-0000-000000000000'
    ),
    envelope_sha256 TEXT NOT NULL CHECK (
        length(envelope_sha256) = 64
        AND envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    preview_binding_sha256 TEXT NOT NULL CHECK (
        length(preview_binding_sha256) = 64
        AND preview_binding_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_revision_id TEXT NOT NULL
        REFERENCES gmail_source_revisions(revision_id) ON DELETE RESTRICT,
    local_source_id TEXT NOT NULL
        REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    source_revision_sha256 TEXT NOT NULL CHECK (
        length(source_revision_sha256) = 64
        AND source_revision_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    fragment_set_sha256 TEXT NOT NULL CHECK (
        length(fragment_set_sha256) = 64
        AND fragment_set_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    projection_sha256 TEXT NOT NULL CHECK (
        length(projection_sha256) = 64
        AND projection_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    serialized_request_sha256 TEXT NOT NULL CHECK (
        length(serialized_request_sha256) = 64
        AND serialized_request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    serialized_request_bytes INTEGER NOT NULL CHECK (
        serialized_request_bytes BETWEEN 1 AND 2097152
    ),
    credential_id TEXT NOT NULL
        REFERENCES credential_references(credential_id) ON DELETE RESTRICT,
    provider TEXT NOT NULL CHECK (provider = 'openai'),
    model TEXT NOT NULL CHECK (
        length(model) BETWEEN 1 AND 128
        AND model NOT GLOB '*[^ -~]*'
    ),
    retention_mode TEXT NOT NULL CHECK (
        retention_mode IN ('unknown', 'default', 'MAM', 'ZDR')
    ),
    retention_provenance TEXT NOT NULL CHECK (
        length(retention_provenance) BETWEEN 1 AND 128
        AND retention_provenance NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    prompt_revision TEXT NOT NULL CHECK (
        length(prompt_revision) BETWEEN 1 AND 128
        AND prompt_revision NOT GLOB '*[^ -~]*'
    ),
    schema_revision TEXT NOT NULL CHECK (
        length(schema_revision) BETWEEN 1 AND 128
        AND schema_revision NOT GLOB '*[^ -~]*'
    ),
    projection_revision TEXT NOT NULL CHECK (
        length(projection_revision) BETWEEN 1 AND 128
        AND projection_revision NOT GLOB '*[^ -~]*'
    ),
    parameters_sha256 TEXT NOT NULL CHECK (
        length(parameters_sha256) = 64
        AND parameters_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    max_fragment_count INTEGER NOT NULL CHECK (
        max_fragment_count BETWEEN 1 AND 200
    ),
    max_fragment_bytes INTEGER NOT NULL CHECK (
        max_fragment_bytes BETWEEN 1 AND 32768
    ),
    max_aggregate_text_bytes INTEGER NOT NULL CHECK (
        max_aggregate_text_bytes BETWEEN 1 AND 1048576
    ),
    max_serialized_request_bytes INTEGER NOT NULL CHECK (
        max_serialized_request_bytes BETWEEN 1 AND 2097152
    ),
    max_request_bytes INTEGER NOT NULL CHECK (
        max_request_bytes BETWEEN 1 AND 2097152
    ),
    max_response_bytes INTEGER NOT NULL CHECK (
        max_response_bytes BETWEEN 1 AND 2097152
    ),
    max_output_tokens INTEGER NOT NULL CHECK (
        max_output_tokens BETWEEN 1 AND 65536
    ),
    timeout_ms INTEGER NOT NULL CHECK (timeout_ms BETWEEN 1 AND 300000),
    max_attempts INTEGER NOT NULL CHECK (max_attempts = 1),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    consumed_request_id TEXT NOT NULL UNIQUE CHECK (
        consumed_request_id = request_id
    ),
    consumed_at_ms INTEGER NOT NULL CHECK (consumed_at_ms >= 0),
    created_at_ms INTEGER NOT NULL CHECK (
        created_at_ms >= 0 AND created_at_ms = consumed_at_ms
    ),
    CHECK (expires_at_ms >= created_at_ms),
    CHECK (
        serialized_request_bytes <= max_serialized_request_bytes
        AND serialized_request_bytes <= max_request_bytes
    ),
    UNIQUE(approval_id, source_revision_id, local_source_id)
) STRICT;

CREATE TABLE receipt_intelligence_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (
        length(attempt_id) = 36
        AND attempt_id <> '00000000-0000-0000-0000-000000000000'
    ),
    request_id TEXT NOT NULL UNIQUE CHECK (
        length(request_id) = 36
        AND request_id <> '00000000-0000-0000-0000-000000000000'
    ),
    approval_id TEXT NOT NULL UNIQUE,
    envelope_sha256 TEXT NOT NULL CHECK (
        length(envelope_sha256) = 64
        AND envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_revision_id TEXT NOT NULL,
    local_source_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN (
            'not_sent', 'dispatched', 'completed', 'refused',
            'failed', 'outcome_unknown'
        )
    ),
    failure_code TEXT CHECK (
        failure_code IS NULL OR failure_code IN (
            'approval_expired', 'approval_consumed', 'consent_mismatch',
            'bound_exceeded', 'local_only', 'release_evidence_unavailable',
            'outbound_authority_unavailable', 'credential_unavailable',
            'retention_declaration_stale', 'source_unavailable',
            'source_revision_changed', 'provider_authentication',
            'provider_rate_limited', 'provider_unavailable',
            'provider_protocol', 'provider_output_invalid',
            'citation_invalid', 'persistence_failed', 'cancelled',
            'refused', 'outcome_unknown'
        )
    ),
    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
    attempt_count INTEGER NOT NULL DEFAULT 1 CHECK (attempt_count = 1),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    dispatched_at_ms INTEGER CHECK (
        dispatched_at_ms IS NULL OR dispatched_at_ms >= created_at_ms
    ),
    finalized_at_ms INTEGER CHECK (
        finalized_at_ms IS NULL OR finalized_at_ms >= created_at_ms
    ),
    FOREIGN KEY(approval_id, source_revision_id, local_source_id)
        REFERENCES receipt_intelligence_approvals(
            approval_id, source_revision_id, local_source_id
        ) ON DELETE RESTRICT,
    CHECK (
        (state = 'not_sent' AND failure_code IS NULL
            AND dispatched_at_ms IS NULL AND finalized_at_ms IS NULL)
        OR
        (state = 'dispatched' AND failure_code IS NULL
            AND dispatched_at_ms IS NOT NULL AND finalized_at_ms IS NULL)
        OR
        (state = 'completed' AND failure_code IS NULL
            AND dispatched_at_ms IS NOT NULL AND finalized_at_ms IS NOT NULL)
        OR
        (state = 'refused' AND failure_code = 'refused'
            AND dispatched_at_ms IS NOT NULL AND finalized_at_ms IS NOT NULL)
        OR
        (state = 'failed' AND failure_code IS NOT NULL
            AND failure_code NOT IN ('refused', 'outcome_unknown')
            AND finalized_at_ms IS NOT NULL)
        OR
        (state = 'outcome_unknown' AND failure_code = 'outcome_unknown'
            AND dispatched_at_ms IS NOT NULL AND finalized_at_ms IS NOT NULL)
    ),
    CHECK (
        state IN ('completed', 'refused')
        OR (input_tokens IS NULL AND output_tokens IS NULL)
    )
) STRICT;

CREATE TABLE receipt_intelligence_audits (
    audit_id TEXT PRIMARY KEY CHECK (
        length(audit_id) = 36
        AND audit_id <> '00000000-0000-0000-0000-000000000000'
    ),
    attempt_id TEXT NOT NULL UNIQUE
        REFERENCES receipt_intelligence_attempts(attempt_id) ON DELETE RESTRICT,
    source_revision_id TEXT NOT NULL
        REFERENCES gmail_source_revisions(revision_id) ON DELETE RESTRICT,
    local_source_id TEXT NOT NULL
        REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    source_revision_sha256 TEXT NOT NULL CHECK (
        length(source_revision_sha256) = 64
        AND source_revision_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    projection_sha256 TEXT NOT NULL CHECK (
        length(projection_sha256) = 64
        AND projection_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    serialized_request_sha256 TEXT NOT NULL CHECK (
        length(serialized_request_sha256) = 64
        AND serialized_request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    response_sha256 TEXT CHECK (
        response_sha256 IS NULL OR (
            length(response_sha256) = 64
            AND response_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    provider TEXT NOT NULL CHECK (provider = 'openai'),
    model TEXT NOT NULL CHECK (
        length(model) BETWEEN 1 AND 128
        AND model NOT GLOB '*[^ -~]*'
    ),
    provider_request_id TEXT CHECK (
        provider_request_id IS NULL OR (
            length(provider_request_id) BETWEEN 1 AND 128
            AND provider_request_id NOT GLOB '*[^A-Za-z0-9._:-]*'
        )
    ),
    response_id TEXT CHECK (
        response_id IS NULL OR (
            length(response_id) BETWEEN 1 AND 128
            AND response_id NOT GLOB '*[^A-Za-z0-9._:-]*'
        )
    ),
    prompt_revision TEXT NOT NULL CHECK (
        length(prompt_revision) BETWEEN 1 AND 128
        AND prompt_revision NOT GLOB '*[^ -~]*'
    ),
    schema_revision TEXT NOT NULL CHECK (
        length(schema_revision) BETWEEN 1 AND 128
        AND schema_revision NOT GLOB '*[^ -~]*'
    ),
    projection_revision TEXT NOT NULL CHECK (
        length(projection_revision) BETWEEN 1 AND 128
        AND projection_revision NOT GLOB '*[^ -~]*'
    ),
    retention_provenance TEXT NOT NULL CHECK (
        length(retention_provenance) BETWEEN 1 AND 128
        AND retention_provenance NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    parameters_sha256 TEXT NOT NULL CHECK (
        length(parameters_sha256) = 64
        AND parameters_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    request_bytes INTEGER NOT NULL CHECK (
        request_bytes BETWEEN 1 AND 2097152
    ),
    response_bytes INTEGER NOT NULL CHECK (
        response_bytes BETWEEN 0 AND 2097152
    ),
    input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
    total_tokens INTEGER NOT NULL CHECK (
        total_tokens = input_tokens + output_tokens
    ),
    reasoning_tokens INTEGER NOT NULL CHECK (
        reasoning_tokens BETWEEN 0 AND output_tokens
    ),
    cached_input_tokens INTEGER NOT NULL CHECK (
        cached_input_tokens BETWEEN 0 AND input_tokens
    ),
    attempt_count INTEGER NOT NULL CHECK (attempt_count = 1),
    dispatched_at_ms INTEGER NOT NULL CHECK (dispatched_at_ms >= 0),
    finished_at_ms INTEGER NOT NULL CHECK (
        finished_at_ms >= dispatched_at_ms
    )
) STRICT;

CREATE TABLE receipt_intelligence_classifications (
    classification_id TEXT PRIMARY KEY CHECK (
        length(classification_id) = 36
        AND classification_id <> '00000000-0000-0000-0000-000000000000'
    ),
    attempt_id TEXT NOT NULL UNIQUE
        REFERENCES receipt_intelligence_attempts(attempt_id) ON DELETE RESTRICT,
    source_revision_id TEXT NOT NULL
        REFERENCES gmail_source_revisions(revision_id) ON DELETE RESTRICT,
    local_source_id TEXT NOT NULL
        REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    classification TEXT NOT NULL CHECK (
        classification IN (
            'apparel_order', 'apparel_lifecycle_update', 'unrelated', 'ambiguous'
        )
    ),
    order_evidence_id TEXT UNIQUE
        REFERENCES receipt_orders(order_evidence_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        (classification IN ('apparel_order', 'apparel_lifecycle_update')
            AND order_evidence_id IS NOT NULL)
        OR
        (classification IN ('unrelated', 'ambiguous')
            AND order_evidence_id IS NULL)
    )
) STRICT;

CREATE TABLE receipt_source_authority_heads (
    local_source_id TEXT PRIMARY KEY
        REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    authority_id TEXT NOT NULL UNIQUE CHECK (
        length(authority_id) = 36
        AND authority_id <> '00000000-0000-0000-0000-000000000000'
    ),
    authority_kind TEXT NOT NULL CHECK (authority_kind = 'user_reviewed'),
    order_evidence_id TEXT NOT NULL UNIQUE
        REFERENCES receipt_orders(order_evidence_id) ON DELETE RESTRICT,
    review_decision_id TEXT NOT NULL UNIQUE
        REFERENCES receipt_review_decisions(review_decision_id) ON DELETE RESTRICT,
    receipt_revision INTEGER NOT NULL CHECK (receipt_revision > 0),
    authority_revision INTEGER NOT NULL CHECK (authority_revision > 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

INSERT INTO receipt_source_authority_heads(
    local_source_id, authority_id, authority_kind, order_evidence_id,
    review_decision_id, receipt_revision, authority_revision, updated_at_ms
)
SELECT
    parse.source_id,
    head.review_decision_id,
    'user_reviewed',
    head.order_evidence_id,
    head.review_decision_id,
    head.receipt_revision,
    head.receipt_revision,
    head.updated_at_ms
FROM receipt_review_heads head
JOIN receipt_orders receipt_order
  ON receipt_order.order_evidence_id = head.order_evidence_id
JOIN receipt_extraction_runs run ON run.run_id = receipt_order.run_id
JOIN receipt_parses parse ON parse.parse_id = run.parse_id
WHERE NOT EXISTS (
    SELECT 1
    FROM receipt_review_heads newer_head
    JOIN receipt_orders newer_order
      ON newer_order.order_evidence_id = newer_head.order_evidence_id
    JOIN receipt_extraction_runs newer_run
      ON newer_run.run_id = newer_order.run_id
    JOIN receipt_parses newer_parse
      ON newer_parse.parse_id = newer_run.parse_id
    WHERE newer_parse.source_id = parse.source_id
      AND newer_head.receipt_revision > head.receipt_revision
);

CREATE INDEX receipt_intelligence_approvals_source_idx
    ON receipt_intelligence_approvals(
        local_source_id, created_at_ms DESC, approval_id DESC
    );
CREATE INDEX receipt_intelligence_attempts_source_idx
    ON receipt_intelligence_attempts(
        local_source_id, created_at_ms DESC, attempt_id DESC
    );
CREATE INDEX receipt_intelligence_attempts_recovery_idx
    ON receipt_intelligence_attempts(state, created_at_ms, attempt_id)
    WHERE state IN ('not_sent', 'dispatched');
CREATE INDEX receipt_intelligence_classifications_source_idx
    ON receipt_intelligence_classifications(
        local_source_id, created_at_ms DESC, classification_id DESC
    );
CREATE INDEX receipt_intelligence_audits_source_idx
    ON receipt_intelligence_audits(
        local_source_id, finished_at_ms DESC, audit_id DESC
    );

CREATE TRIGGER receipt_intelligence_approvals_no_update
BEFORE UPDATE ON receipt_intelligence_approvals
BEGIN
    SELECT RAISE(ABORT, 'receipt intelligence approvals are immutable');
END;

CREATE TRIGGER receipt_intelligence_attempts_state_transition
BEFORE UPDATE ON receipt_intelligence_attempts
WHEN NEW.attempt_id IS NOT OLD.attempt_id
    OR NEW.request_id IS NOT OLD.request_id
    OR NEW.approval_id IS NOT OLD.approval_id
    OR NEW.envelope_sha256 IS NOT OLD.envelope_sha256
    OR NEW.source_revision_id IS NOT OLD.source_revision_id
    OR NEW.local_source_id IS NOT OLD.local_source_id
    OR NEW.attempt_count IS NOT OLD.attempt_count
    OR NEW.created_at_ms IS NOT OLD.created_at_ms
    OR OLD.state IN ('completed', 'refused', 'failed', 'outcome_unknown')
    OR (
        OLD.state = 'not_sent'
        AND NEW.state NOT IN ('dispatched', 'failed')
    )
    OR (
        OLD.state = 'dispatched'
        AND NEW.state NOT IN (
            'completed', 'refused', 'failed', 'outcome_unknown'
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid receipt intelligence attempt transition');
END;

CREATE TRIGGER receipt_intelligence_audits_validate_insert
BEFORE INSERT ON receipt_intelligence_audits
WHEN NOT EXISTS (
    SELECT 1
    FROM receipt_intelligence_attempts attempt
    JOIN receipt_intelligence_approvals approval
      ON approval.approval_id = attempt.approval_id
    WHERE attempt.attempt_id = NEW.attempt_id
      AND attempt.state = 'dispatched'
      AND attempt.source_revision_id = NEW.source_revision_id
      AND attempt.local_source_id = NEW.local_source_id
      AND approval.source_revision_sha256 = NEW.source_revision_sha256
      AND approval.projection_sha256 = NEW.projection_sha256
      AND approval.serialized_request_sha256 = NEW.serialized_request_sha256
      AND approval.provider = NEW.provider
      AND approval.model = NEW.model
      AND approval.prompt_revision = NEW.prompt_revision
      AND approval.schema_revision = NEW.schema_revision
      AND approval.projection_revision = NEW.projection_revision
      AND approval.retention_provenance = NEW.retention_provenance
      AND approval.parameters_sha256 = NEW.parameters_sha256
      AND NEW.request_bytes <= approval.max_request_bytes
      AND NEW.response_bytes <= approval.max_response_bytes
      AND NEW.output_tokens <= approval.max_output_tokens
      AND NEW.attempt_count <= approval.max_attempts
)
BEGIN
    SELECT RAISE(ABORT, 'invalid receipt intelligence audit');
END;

CREATE TRIGGER receipt_intelligence_audits_no_update
BEFORE UPDATE ON receipt_intelligence_audits
BEGIN
    SELECT RAISE(ABORT, 'receipt intelligence audits are immutable');
END;

CREATE TRIGGER receipt_intelligence_classifications_validate_insert
BEFORE INSERT ON receipt_intelligence_classifications
WHEN NOT EXISTS (
    SELECT 1
    FROM receipt_intelligence_attempts attempt
    WHERE attempt.attempt_id = NEW.attempt_id
      AND attempt.state = 'dispatched'
      AND attempt.source_revision_id = NEW.source_revision_id
      AND attempt.local_source_id = NEW.local_source_id
)
OR (
    NEW.order_evidence_id IS NOT NULL
    AND NOT EXISTS (
        SELECT 1
        FROM receipt_orders receipt_order
        JOIN receipt_extraction_runs run ON run.run_id = receipt_order.run_id
        JOIN receipt_parses parse ON parse.parse_id = run.parse_id
        WHERE receipt_order.order_evidence_id = NEW.order_evidence_id
          AND parse.source_id = NEW.local_source_id
    )
)
BEGIN
    SELECT RAISE(ABORT, 'invalid receipt intelligence classification');
END;

CREATE TRIGGER receipt_intelligence_attempt_completed_has_classification
BEFORE UPDATE OF state ON receipt_intelligence_attempts
WHEN NEW.state = 'completed'
AND (
    NOT EXISTS (
        SELECT 1
        FROM receipt_intelligence_classifications classification
        WHERE classification.attempt_id = NEW.attempt_id
    )
    OR NOT EXISTS (
        SELECT 1
        FROM receipt_intelligence_audits audit
        WHERE audit.attempt_id = NEW.attempt_id
    )
)
BEGIN
    SELECT RAISE(ABORT, 'completed receipt intelligence attempt is incomplete');
END;

CREATE TRIGGER receipt_intelligence_attempt_refused_has_audit
BEFORE UPDATE OF state ON receipt_intelligence_attempts
WHEN NEW.state = 'refused'
AND NOT EXISTS (
    SELECT 1
    FROM receipt_intelligence_audits audit
    WHERE audit.attempt_id = NEW.attempt_id
)
BEGIN
    SELECT RAISE(ABORT, 'refused receipt intelligence attempt has no audit');
END;

CREATE TRIGGER receipt_intelligence_classifications_no_update
BEFORE UPDATE ON receipt_intelligence_classifications
BEGIN
    SELECT RAISE(ABORT, 'receipt intelligence classifications are immutable');
END;

CREATE TRIGGER receipt_source_authority_heads_validate_insert
BEFORE INSERT ON receipt_source_authority_heads
WHEN NOT EXISTS (
    SELECT 1
    FROM receipt_review_decisions decision
    JOIN receipt_orders receipt_order
      ON receipt_order.order_evidence_id = decision.order_evidence_id
    JOIN receipt_extraction_runs run ON run.run_id = receipt_order.run_id
    JOIN receipt_parses parse ON parse.parse_id = run.parse_id
    WHERE decision.review_decision_id = NEW.review_decision_id
      AND decision.order_evidence_id = NEW.order_evidence_id
      AND decision.receipt_revision = NEW.receipt_revision
      AND parse.source_id = NEW.local_source_id
)
BEGIN
    SELECT RAISE(ABORT, 'invalid receipt source authority head');
END;

CREATE TRIGGER receipt_source_authority_heads_validate_update
BEFORE UPDATE ON receipt_source_authority_heads
WHEN NEW.local_source_id IS NOT OLD.local_source_id
    OR NEW.receipt_revision <= OLD.receipt_revision
    OR NEW.authority_revision <= OLD.authority_revision
    OR NEW.authority_kind <> 'user_reviewed'
    OR NOT EXISTS (
        SELECT 1
        FROM receipt_review_decisions decision
        JOIN receipt_orders receipt_order
          ON receipt_order.order_evidence_id = decision.order_evidence_id
        JOIN receipt_extraction_runs run ON run.run_id = receipt_order.run_id
        JOIN receipt_parses parse ON parse.parse_id = run.parse_id
        WHERE decision.review_decision_id = NEW.review_decision_id
          AND decision.order_evidence_id = NEW.order_evidence_id
          AND decision.receipt_revision = NEW.receipt_revision
          AND parse.source_id = NEW.local_source_id
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid receipt source authority head');
END;

CREATE TRIGGER hd_receipt_intelligence_audits
BEFORE DELETE ON receipt_intelligence_audits
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'receipt_intelligence_audits'
          AND planned.key_json = json_array(OLD.audit_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

CREATE TRIGGER hd_receipt_intelligence_approvals
BEFORE DELETE ON receipt_intelligence_approvals
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'receipt_intelligence_approvals'
          AND planned.key_json = json_array(OLD.approval_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

CREATE TRIGGER hd_receipt_intelligence_attempts
BEFORE DELETE ON receipt_intelligence_attempts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'receipt_intelligence_attempts'
          AND planned.key_json = json_array(OLD.attempt_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

CREATE TRIGGER hd_receipt_intelligence_classifications
BEFORE DELETE ON receipt_intelligence_classifications
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'receipt_intelligence_classifications'
          AND planned.key_json = json_array(OLD.classification_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

CREATE TRIGGER hd_receipt_source_authority_heads
BEFORE DELETE ON receipt_source_authority_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'receipt_source_authority_heads'
          AND planned.key_json = json_array(OLD.local_source_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
