CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    applied_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE command_receipts (
    request_id TEXT PRIMARY KEY,
    command_name TEXT NOT NULL,
    envelope_hash TEXT NOT NULL CHECK (length(envelope_hash) = 64),
    response_json TEXT NOT NULL CHECK (json_valid(response_json)),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE settings (
    setting_key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL CHECK (json_valid(value_json)),
    updated_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE credential_references (
    locator TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL UNIQUE,
    save_request_id TEXT NOT NULL UNIQUE,
    delete_request_id TEXT UNIQUE,
    provider TEXT NOT NULL,
    display_label TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending_save', 'active', 'pending_delete', 'save_failed')),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE blobs (
    sha256 TEXT PRIMARY KEY CHECK (length(sha256) = 64),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE provenance (
    provenance_id TEXT PRIMARY KEY,
    blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256) ON DELETE RESTRICT,
    source_kind TEXT NOT NULL,
    source_locator TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(blob_sha256, source_kind, source_locator)
) STRICT;

CREATE TABLE storage_checks (
    check_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE REFERENCES command_receipts(request_id) DEFERRABLE INITIALLY DEFERRED,
    blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE jobs (
    job_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind = 'verify_blob_v1'),
    payload_version INTEGER NOT NULL CHECK (payload_version = 1),
    payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
    input_hash TEXT NOT NULL CHECK (length(input_hash) = 64),
    pipeline_version TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
    available_at_ms INTEGER NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    retry_limit INTEGER NOT NULL CHECK (retry_limit >= 0),
    backoff_ms INTEGER NOT NULL CHECK (backoff_ms >= 0),
    fence INTEGER NOT NULL DEFAULT 0 CHECK (fence >= 0),
    lease_owner TEXT,
    lease_expires_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    CHECK (
        (state = 'running' AND lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
        OR
        (state IN ('queued', 'succeeded', 'failed') AND lease_owner IS NULL AND lease_expires_at_ms IS NULL)
    )
) STRICT;

CREATE TABLE job_dependencies (
    job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE RESTRICT,
    depends_on_job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE RESTRICT,
    PRIMARY KEY(job_id, depends_on_job_id),
    CHECK(job_id <> depends_on_job_id)
) STRICT;

CREATE TABLE job_failures (
    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE RESTRICT,
    failure_code TEXT NOT NULL,
    user_action_key TEXT NOT NULL,
    retryable INTEGER NOT NULL CHECK (retryable IN (0, 1)),
    failed_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE job_results (
    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE RESTRICT,
    result_hash TEXT NOT NULL CHECK (length(result_hash) = 64),
    result_json TEXT NOT NULL CHECK (json_valid(result_json)),
    winning_owner TEXT NOT NULL,
    winning_fence INTEGER NOT NULL CHECK (winning_fence > 0),
    committed_at_ms INTEGER NOT NULL
) STRICT;

CREATE INDEX jobs_ready_idx ON jobs(available_at_ms, created_at_ms, job_id)
    WHERE state = 'queued';
CREATE INDEX jobs_expired_idx ON jobs(lease_expires_at_ms, job_id)
    WHERE state = 'running';
CREATE INDEX jobs_activity_idx ON jobs(updated_at_ms DESC, job_id);
CREATE INDEX credentials_activity_idx
    ON credential_references(updated_at_ms DESC, credential_id);
