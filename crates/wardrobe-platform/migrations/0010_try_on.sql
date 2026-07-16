ALTER TABLE revision_state
ADD COLUMN try_on_revision INTEGER NOT NULL DEFAULT 0
CHECK (try_on_revision BETWEEN 0 AND 9007199254740990);

ALTER TABLE deletion_previews
ADD COLUMN outfit_revision INTEGER NOT NULL DEFAULT 0
CHECK (outfit_revision BETWEEN 0 AND 9007199254740990);

ALTER TABLE deletion_previews
ADD COLUMN try_on_revision INTEGER NOT NULL DEFAULT 0
CHECK (try_on_revision BETWEEN 0 AND 9007199254740990);

CREATE TABLE try_on_approvals (
    approval_id TEXT PRIMARY KEY CHECK (
        length(approval_id) = 36
        AND approval_id <> '00000000-0000-0000-0000-000000000000'
    ),
    preview_request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    envelope_hash TEXT NOT NULL CHECK (length(envelope_hash) = 64),
    outfit_id TEXT NOT NULL CHECK (length(outfit_id) = 36),
    outfit_name TEXT NOT NULL CHECK (
        length(outfit_name) BETWEEN 1 AND 80
        AND outfit_name = trim(outfit_name)
    ),
    outfit_created_revision INTEGER NOT NULL CHECK (
        outfit_created_revision BETWEEN 1 AND 9007199254740990
    ),
    expected_outfit_revision INTEGER NOT NULL CHECK (
        expected_outfit_revision BETWEEN 0 AND 9007199254740990
    ),
    credential_id TEXT NOT NULL CHECK (
        length(credential_id) BETWEEN 1 AND 128
        AND credential_id = trim(credential_id)
        AND credential_id NOT GLOB '*[^ -~]*'
    ),
    provider TEXT NOT NULL CHECK (provider = 'openai'),
    model TEXT NOT NULL CHECK (model = 'gpt-image-2'),
    prompt_revision TEXT NOT NULL CHECK (
        length(prompt_revision) BETWEEN 1 AND 80
        AND prompt_revision NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    disclosure_revision TEXT NOT NULL CHECK (
        length(disclosure_revision) BETWEEN 1 AND 80
        AND disclosure_revision NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    retention_mode TEXT NOT NULL CHECK (
        retention_mode IN ('unknown', 'default', 'MAM', 'ZDR')
    ),
    retention_provenance TEXT NOT NULL CHECK (
        length(retention_provenance) BETWEEN 1 AND 128
        AND retention_provenance = trim(retention_provenance)
        AND retention_provenance NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    asset_snapshot_sha256 TEXT NOT NULL CHECK (
        length(asset_snapshot_sha256) = 64
    ),
    garment_count INTEGER NOT NULL CHECK (garment_count BETWEEN 2 AND 8),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    consumed_request_id TEXT UNIQUE,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (expires_at_ms >= created_at_ms)
) STRICT;

CREATE INDEX try_on_approvals_expiry_idx
    ON try_on_approvals(expires_at_ms, approval_id)
    WHERE consumed_request_id IS NULL;
CREATE INDEX try_on_approvals_outfit_idx
    ON try_on_approvals(outfit_id, created_at_ms, approval_id);

CREATE TABLE try_on_assets (
    approval_id TEXT NOT NULL
        REFERENCES try_on_approvals(approval_id) ON DELETE RESTRICT,
    asset_ordinal INTEGER NOT NULL CHECK (asset_ordinal BETWEEN 0 AND 8),
    role TEXT NOT NULL CHECK (role IN ('portrait', 'garment')),
    source_revision_id TEXT,
    item_id TEXT,
    evidence_id TEXT,
    source_id TEXT,
    item_updated_revision INTEGER,
    attributes_json TEXT CHECK (
        attributes_json IS NULL OR json_valid(attributes_json)
    ),
    parent_blob_sha256 TEXT NOT NULL
        REFERENCES blobs(sha256) ON DELETE RESTRICT,
    parent_media_type TEXT NOT NULL CHECK (
        parent_media_type IN ('image/jpeg', 'image/png', 'image/webp')
    ),
    parent_byte_length INTEGER NOT NULL CHECK (
        parent_byte_length BETWEEN 1 AND 41943040
    ),
    parent_width INTEGER NOT NULL CHECK (parent_width BETWEEN 1 AND 16384),
    parent_height INTEGER NOT NULL CHECK (parent_height BETWEEN 1 AND 16384),
    canonical_png_sha256 TEXT NOT NULL CHECK (
        length(canonical_png_sha256) = 64
    ),
    canonical_byte_length INTEGER NOT NULL CHECK (
        canonical_byte_length BETWEEN 1 AND 8388608
    ),
    canonical_width INTEGER NOT NULL CHECK (canonical_width BETWEEN 1 AND 4096),
    canonical_height INTEGER NOT NULL CHECK (canonical_height BETWEEN 1 AND 4096),
    PRIMARY KEY(approval_id, asset_ordinal),
    CHECK (
        (
            role = 'portrait'
            AND asset_ordinal = 0
            AND source_revision_id IS NOT NULL
            AND item_id IS NULL
            AND evidence_id IS NULL
            AND source_id IS NULL
            AND item_updated_revision IS NULL
            AND attributes_json IS NULL
        )
        OR
        (
            role = 'garment'
            AND asset_ordinal BETWEEN 1 AND 8
            AND source_revision_id IS NULL
            AND item_id IS NOT NULL
            AND evidence_id IS NOT NULL
            AND source_id IS NOT NULL
            AND item_updated_revision BETWEEN 1 AND 9007199254740990
            AND attributes_json IS NOT NULL
        )
    )
) STRICT;

CREATE INDEX try_on_assets_parent_blob_idx
    ON try_on_assets(parent_blob_sha256, approval_id);
CREATE INDEX try_on_assets_source_revision_idx
    ON try_on_assets(source_revision_id, approval_id)
    WHERE source_revision_id IS NOT NULL;
CREATE INDEX try_on_assets_source_idx
    ON try_on_assets(source_id, approval_id)
    WHERE source_id IS NOT NULL;
CREATE INDEX try_on_assets_item_idx
    ON try_on_assets(item_id, approval_id)
    WHERE item_id IS NOT NULL;

CREATE TABLE try_on_jobs (
    job_id TEXT PRIMARY KEY CHECK (
        length(job_id) = 36
        AND job_id <> '00000000-0000-0000-0000-000000000000'
    ),
    request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    approval_id TEXT NOT NULL UNIQUE
        REFERENCES try_on_approvals(approval_id) ON DELETE RESTRICT,
    envelope_hash TEXT NOT NULL CHECK (length(envelope_hash) = 64),
    pipeline_revision TEXT NOT NULL CHECK (
        length(pipeline_revision) BETWEEN 1 AND 80
        AND pipeline_revision NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    state TEXT NOT NULL CHECK (
        state IN ('queued', 'running', 'succeeded', 'failed')
    ),
    available_at_ms INTEGER NOT NULL CHECK (available_at_ms >= 0),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 1),
    retry_limit INTEGER NOT NULL DEFAULT 0 CHECK (retry_limit = 0),
    fence INTEGER NOT NULL DEFAULT 0 CHECK (fence >= 0),
    lease_owner TEXT,
    lease_expires_at_ms INTEGER,
    terminal_attempt_id TEXT,
    failure_code TEXT CHECK (
        failure_code IS NULL OR failure_code IN (
            'moderation_blocked', 'rate_limited', 'provider_failure',
            'provider_unavailable', 'outcome_unknown', 'authentication',
            'permission_denied', 'request_rejected', 'provider_protocol',
            'credential_unavailable', 'approval_expired', 'approval_consumed',
            'source_stale', 'asset_unavailable', 'asset_integrity',
            'output_materialization_interrupted', 'cancelled'
        )
    ),
    retryable INTEGER NOT NULL DEFAULT 0 CHECK (retryable IN (0, 1)),
    user_action TEXT CHECK (
        user_action IS NULL
        OR (
            length(user_action) BETWEEN 1 AND 80
            AND user_action NOT GLOB '*[^a-z0-9_]*'
        )
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    CHECK (
        (
            state = 'running'
            AND lease_owner IS NOT NULL
            AND lease_expires_at_ms IS NOT NULL
            AND terminal_attempt_id IS NULL
            AND failure_code IS NULL
        )
        OR
        (
            state = 'queued'
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL
            AND terminal_attempt_id IS NULL
            AND failure_code IS NULL
        )
        OR
        (
            state = 'succeeded'
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL
            AND terminal_attempt_id IS NOT NULL
            AND failure_code IS NULL
        )
        OR
        (
            state = 'failed'
            AND lease_owner IS NULL
            AND lease_expires_at_ms IS NULL
            AND terminal_attempt_id IS NOT NULL
            AND failure_code IS NOT NULL
        )
    )
) STRICT;

CREATE INDEX try_on_jobs_ready_idx
    ON try_on_jobs(available_at_ms, created_at_ms, job_id)
    WHERE state = 'queued';
CREATE INDEX try_on_jobs_lease_idx
    ON try_on_jobs(lease_expires_at_ms, job_id)
    WHERE state = 'running';

CREATE TABLE try_on_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (
        length(attempt_id) = 36
        AND attempt_id <> '00000000-0000-0000-0000-000000000000'
    ),
    job_id TEXT NOT NULL UNIQUE
        REFERENCES try_on_jobs(job_id) ON DELETE RESTRICT,
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal = 1),
    fence INTEGER NOT NULL CHECK (fence > 0),
    state TEXT NOT NULL CHECK (
        state IN (
            'prepared', 'dispatched', 'materializing',
            'succeeded', 'failed', 'abandoned'
        )
    ),
    provider_request_id TEXT CHECK (
        provider_request_id IS NULL
        OR (
            length(provider_request_id) BETWEEN 1 AND 128
            AND provider_request_id NOT GLOB '*[^A-Za-z0-9._:-]*'
        )
    ),
    audit_json TEXT CHECK (audit_json IS NULL OR json_valid(audit_json)),
    output_sha256 TEXT CHECK (
        output_sha256 IS NULL OR length(output_sha256) = 64
    ),
    output_byte_length INTEGER CHECK (
        output_byte_length IS NULL
        OR output_byte_length BETWEEN 1 AND 12582912
    ),
    output_width INTEGER CHECK (
        output_width IS NULL OR output_width = 1024
    ),
    output_height INTEGER CHECK (
        output_height IS NULL OR output_height = 1536
    ),
    failure_code TEXT,
    retryable INTEGER NOT NULL DEFAULT 0 CHECK (retryable IN (0, 1)),
    user_action TEXT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    CHECK (
        (state = 'materializing'
            AND output_sha256 IS NOT NULL
            AND output_byte_length IS NOT NULL
            AND output_width = 1024
            AND output_height = 1536
            AND failure_code IS NULL)
        OR
        (state = 'succeeded'
            AND output_sha256 IS NOT NULL
            AND output_byte_length IS NOT NULL
            AND output_width = 1024
            AND output_height = 1536
            AND failure_code IS NULL)
        OR
        (state IN ('failed', 'abandoned') AND failure_code IS NOT NULL)
        OR
        (state IN ('prepared', 'dispatched')
            AND output_sha256 IS NULL
            AND output_byte_length IS NULL
            AND output_width IS NULL
            AND output_height IS NULL
            AND failure_code IS NULL)
    )
) STRICT;

CREATE TABLE try_on_outputs (
    output_id TEXT PRIMARY KEY CHECK (
        length(output_id) = 36
        AND output_id <> '00000000-0000-0000-0000-000000000000'
    ),
    job_id TEXT NOT NULL UNIQUE
        REFERENCES try_on_jobs(job_id) ON DELETE RESTRICT,
    blob_sha256 TEXT NOT NULL
        REFERENCES blobs(sha256) ON DELETE RESTRICT,
    media_type TEXT NOT NULL CHECK (media_type = 'image/png'),
    byte_length INTEGER NOT NULL CHECK (byte_length BETWEEN 1 AND 12582912),
    width INTEGER NOT NULL CHECK (width = 1024),
    height INTEGER NOT NULL CHECK (height = 1536),
    provenance_json TEXT NOT NULL CHECK (json_valid(provenance_json)),
    provenance_sha256 TEXT NOT NULL CHECK (length(provenance_sha256) = 64),
    label_revision TEXT NOT NULL CHECK (
        length(label_revision) BETWEEN 1 AND 80
        AND label_revision NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    use_class TEXT NOT NULL CHECK (use_class = 'presentation_only'),
    eligible_as_evidence INTEGER NOT NULL CHECK (eligible_as_evidence = 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

CREATE INDEX try_on_outputs_blob_idx
    ON try_on_outputs(blob_sha256, output_id);
