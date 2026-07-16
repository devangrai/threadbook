CREATE TABLE outfit_recommendation_approvals (
    approval_id TEXT PRIMARY KEY CHECK (
        length(approval_id) = 36
        AND approval_id <> '00000000-0000-0000-0000-000000000000'
    ),
    preview_request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
    credential_id TEXT NOT NULL CHECK (
        length(credential_id) BETWEEN 1 AND 128
        AND credential_id = trim(credential_id)
        AND credential_id NOT GLOB '*[^ -~]*'
    ),
    catalog_revision INTEGER NOT NULL CHECK (
        catalog_revision BETWEEN 0 AND 9007199254740990
    ),
    outfit_revision INTEGER NOT NULL CHECK (
        outfit_revision BETWEEN 0 AND 9007199254740990
    ),
    retention_mode TEXT NOT NULL CHECK (
        retention_mode IN ('unknown', 'default', 'MAM', 'ZDR')
    ),
    retention_provenance TEXT NOT NULL CHECK (
        length(retention_provenance) BETWEEN 1 AND 128
        AND retention_provenance = trim(retention_provenance)
        AND retention_provenance NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    disclosure_revision TEXT NOT NULL CHECK (
        length(disclosure_revision) BETWEEN 1 AND 80
        AND disclosure_revision NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    consumed_request_id TEXT UNIQUE,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (expires_at_ms >= created_at_ms)
) STRICT;

CREATE INDEX outfit_recommendation_approvals_expiry_idx
    ON outfit_recommendation_approvals(expires_at_ms, approval_id)
    WHERE consumed_request_id IS NULL;

CREATE TABLE outfit_recommendation_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (
        length(attempt_id) = 36
        AND attempt_id <> '00000000-0000-0000-0000-000000000000'
    ),
    request_id TEXT NOT NULL UNIQUE,
    approval_id TEXT NOT NULL UNIQUE
        REFERENCES outfit_recommendation_approvals(approval_id) ON DELETE RESTRICT,
    request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
    credential_id TEXT NOT NULL CHECK (
        length(credential_id) BETWEEN 1 AND 128
        AND credential_id = trim(credential_id)
        AND credential_id NOT GLOB '*[^ -~]*'
    ),
    state TEXT NOT NULL CHECK (
        state IN (
            'reserved', 'completed', 'refused', 'failed',
            'outcome_unknown', 'stale'
        )
    ),
    catalog_revision INTEGER NOT NULL CHECK (
        catalog_revision BETWEEN 0 AND 9007199254740990
    ),
    outfit_revision INTEGER NOT NULL CHECK (
        outfit_revision BETWEEN 0 AND 9007199254740990
    ),
    input_hash TEXT NOT NULL CHECK (length(input_hash) = 64),
    tool_snapshot_hash TEXT NOT NULL CHECK (length(tool_snapshot_hash) = 64),
    provider TEXT NOT NULL CHECK (provider = 'openai'),
    model TEXT NOT NULL CHECK (
        length(model) BETWEEN 1 AND 80
        AND model NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    prompt_revision TEXT NOT NULL CHECK (
        length(prompt_revision) BETWEEN 1 AND 80
        AND prompt_revision NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    schema_revision TEXT NOT NULL CHECK (
        length(schema_revision) BETWEEN 1 AND 80
        AND schema_revision NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    compatibility_revision TEXT NOT NULL CHECK (
        length(compatibility_revision) BETWEEN 1 AND 80
        AND compatibility_revision NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    retention_mode TEXT NOT NULL CHECK (
        retention_mode IN ('unknown', 'default', 'MAM', 'ZDR')
    ),
    retention_provenance TEXT NOT NULL CHECK (
        length(retention_provenance) BETWEEN 1 AND 128
        AND retention_provenance NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    provider_request_id TEXT CHECK (
        provider_request_id IS NULL
        OR (
            length(provider_request_id) BETWEEN 1 AND 128
            AND provider_request_id NOT GLOB '*[^A-Za-z0-9._:-]*'
        )
    ),
    provider_response_id TEXT CHECK (
        provider_response_id IS NULL
        OR (
            length(provider_response_id) BETWEEN 1 AND 128
            AND provider_response_id NOT GLOB '*[^A-Za-z0-9._:-]*'
        )
    ),
    usage_json TEXT CHECK (usage_json IS NULL OR json_valid(usage_json)),
    audit_json TEXT CHECK (audit_json IS NULL OR json_valid(audit_json)),
    terminal_response_json TEXT CHECK (
        terminal_response_json IS NULL OR json_valid(terminal_response_json)
    ),
    validated_response_json TEXT CHECK (
        validated_response_json IS NULL OR json_valid(validated_response_json)
    ),
    failure_code TEXT CHECK (
        failure_code IS NULL
        OR (
            length(failure_code) BETWEEN 1 AND 80
            AND failure_code NOT GLOB '*[^a-z0-9_]*'
        )
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    finalized_at_ms INTEGER CHECK (
        finalized_at_ms IS NULL OR finalized_at_ms >= created_at_ms
    ),
    CHECK (
        (
            state = 'reserved'
            AND finalized_at_ms IS NULL
            AND terminal_response_json IS NULL
            AND validated_response_json IS NULL
            AND failure_code IS NULL
        )
        OR (
            state = 'completed'
            AND finalized_at_ms IS NOT NULL
            AND terminal_response_json IS NOT NULL
            AND validated_response_json IS NOT NULL
            AND failure_code IS NULL
        )
        OR (
            state IN ('refused', 'failed', 'outcome_unknown', 'stale')
            AND finalized_at_ms IS NOT NULL
            AND terminal_response_json IS NOT NULL
            AND validated_response_json IS NULL
            AND failure_code IS NOT NULL
        )
    )
) STRICT;

CREATE INDEX outfit_recommendation_attempts_state_idx
    ON outfit_recommendation_attempts(state, created_at_ms, attempt_id);

CREATE TABLE outfit_recommendation_proposals (
    attempt_id TEXT NOT NULL
        REFERENCES outfit_recommendation_attempts(attempt_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 2),
    proposal_name TEXT NOT NULL CHECK (
        length(proposal_name) BETWEEN 1 AND 80
        AND proposal_name = trim(proposal_name)
    ),
    PRIMARY KEY(attempt_id, ordinal)
) STRICT;

CREATE TABLE outfit_recommendation_members (
    attempt_id TEXT NOT NULL,
    proposal_ordinal INTEGER NOT NULL CHECK (proposal_ordinal BETWEEN 0 AND 2),
    member_ordinal INTEGER NOT NULL CHECK (member_ordinal BETWEEN 0 AND 7),
    item_id TEXT NOT NULL REFERENCES catalog_items(item_id) ON DELETE RESTRICT,
    PRIMARY KEY(attempt_id, proposal_ordinal, member_ordinal),
    UNIQUE(attempt_id, proposal_ordinal, item_id),
    FOREIGN KEY(attempt_id, proposal_ordinal)
        REFERENCES outfit_recommendation_proposals(attempt_id, ordinal)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX outfit_recommendation_members_item_idx
    ON outfit_recommendation_members(item_id, attempt_id, proposal_ordinal);

CREATE TRIGGER outfit_recommendation_approvals_no_delete
BEFORE DELETE ON outfit_recommendation_approvals
BEGIN
    SELECT RAISE(ABORT, 'recommendation approvals are immutable');
END;

CREATE TRIGGER outfit_recommendation_approvals_limited_update
BEFORE UPDATE ON outfit_recommendation_approvals
WHEN
    OLD.approval_id <> NEW.approval_id
    OR OLD.preview_request_id <> NEW.preview_request_id
    OR OLD.request_hash <> NEW.request_hash
    OR OLD.credential_id <> NEW.credential_id
    OR OLD.catalog_revision <> NEW.catalog_revision
    OR OLD.outfit_revision <> NEW.outfit_revision
    OR OLD.retention_mode <> NEW.retention_mode
    OR OLD.retention_provenance <> NEW.retention_provenance
    OR OLD.disclosure_revision <> NEW.disclosure_revision
    OR OLD.expires_at_ms <> NEW.expires_at_ms
    OR OLD.created_at_ms <> NEW.created_at_ms
    OR OLD.consumed_request_id IS NOT NULL
    OR NEW.consumed_request_id IS NULL
BEGIN
    SELECT RAISE(ABORT, 'recommendation approval update is not permitted');
END;

CREATE TRIGGER outfit_recommendation_attempts_no_delete
BEFORE DELETE ON outfit_recommendation_attempts
BEGIN
    SELECT RAISE(ABORT, 'recommendation attempts are immutable');
END;

CREATE TRIGGER outfit_recommendation_attempts_limited_update
BEFORE UPDATE ON outfit_recommendation_attempts
WHEN
    OLD.state <> 'reserved'
    OR NEW.state = 'reserved'
    OR OLD.attempt_id <> NEW.attempt_id
    OR OLD.request_id <> NEW.request_id
    OR OLD.approval_id <> NEW.approval_id
    OR OLD.request_hash <> NEW.request_hash
    OR OLD.credential_id <> NEW.credential_id
    OR OLD.catalog_revision <> NEW.catalog_revision
    OR OLD.outfit_revision <> NEW.outfit_revision
    OR OLD.input_hash <> NEW.input_hash
    OR OLD.tool_snapshot_hash <> NEW.tool_snapshot_hash
    OR OLD.provider <> NEW.provider
    OR OLD.model <> NEW.model
    OR OLD.prompt_revision <> NEW.prompt_revision
    OR OLD.schema_revision <> NEW.schema_revision
    OR OLD.compatibility_revision <> NEW.compatibility_revision
    OR OLD.retention_mode <> NEW.retention_mode
    OR OLD.retention_provenance <> NEW.retention_provenance
    OR OLD.created_at_ms <> NEW.created_at_ms
BEGIN
    SELECT RAISE(ABORT, 'recommendation attempt update is not permitted');
END;

CREATE TRIGGER outfit_recommendation_proposals_no_update
BEFORE UPDATE ON outfit_recommendation_proposals
BEGIN
    SELECT RAISE(ABORT, 'recommendation proposals are immutable');
END;

CREATE TRIGGER outfit_recommendation_members_no_update
BEFORE UPDATE ON outfit_recommendation_members
BEGIN
    SELECT RAISE(ABORT, 'recommendation members are immutable');
END;
