CREATE TABLE gmail_connector_settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    oauth_client_id TEXT NOT NULL CHECK (
        length(oauth_client_id) BETWEEN 1 AND 256
        AND oauth_client_id NOT GLOB '*[^ -~]*'
        AND oauth_client_id GLOB '*.apps.googleusercontent.com'
    ),
    label_name TEXT NOT NULL CHECK (
        length(label_name) BETWEEN 1 AND 80
        AND label_name = trim(label_name)
        AND label_name NOT GLOB '*[[:cntrl:]]*'
    ),
    page_size INTEGER NOT NULL CHECK (page_size BETWEEN 1 AND 100),
    max_pages INTEGER NOT NULL CHECK (max_pages BETWEEN 1 AND 10),
    max_unique_messages INTEGER NOT NULL CHECK (
        max_unique_messages BETWEEN 1 AND 200
    ),
    max_total_raw_bytes INTEGER NOT NULL CHECK (
        max_total_raw_bytes BETWEEN 1 AND 104857600
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

CREATE TABLE gmail_accounts (
    account_key TEXT PRIMARY KEY CHECK (
        length(account_key) = 64
        AND account_key NOT GLOB '*[^0-9a-f]*'
    ),
    credential_locator TEXT UNIQUE,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

CREATE TABLE gmail_scopes (
    scope_id TEXT PRIMARY KEY CHECK (
        length(scope_id) = 36
        AND scope_id <> '00000000-0000-0000-0000-000000000000'
    ),
    account_key TEXT NOT NULL
        REFERENCES gmail_accounts(account_key) ON DELETE RESTRICT,
    scope_fingerprint TEXT NOT NULL CHECK (
        length(scope_fingerprint) = 64
        AND scope_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    label_id TEXT NOT NULL CHECK (
        length(CAST(label_id AS BLOB)) BETWEEN 1 AND 256
        AND label_id NOT GLOB '*[^ -~]*'
    ),
    oauth_scope TEXT NOT NULL CHECK (
        oauth_scope =
        'openid https://www.googleapis.com/auth/gmail.readonly'
    ),
    parser_revision TEXT NOT NULL CHECK (
        length(parser_revision) BETWEEN 1 AND 128
        AND parser_revision NOT GLOB '*[^ -~]*'
    ),
    materialization_revision TEXT NOT NULL CHECK (
        length(materialization_revision) BETWEEN 1 AND 128
        AND materialization_revision NOT GLOB '*[^ -~]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(account_key, scope_fingerprint),
    UNIQUE(scope_id, account_key)
) STRICT;

CREATE TABLE gmail_checkpoints (
    scope_id TEXT PRIMARY KEY
        REFERENCES gmail_scopes(scope_id) ON DELETE RESTRICT,
    history_id TEXT NOT NULL CHECK (
        length(history_id) BETWEEN 1 AND 64
        AND history_id NOT GLOB '*[^0-9]*'
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

CREATE TABLE gmail_provider_sources (
    provider_source_id TEXT PRIMARY KEY CHECK (
        length(provider_source_id) = 36
        AND provider_source_id <> '00000000-0000-0000-0000-000000000000'
    ),
    account_key TEXT NOT NULL
        REFERENCES gmail_accounts(account_key) ON DELETE RESTRICT,
    gmail_message_id TEXT NOT NULL CHECK (
        length(CAST(gmail_message_id AS BLOB)) BETWEEN 1 AND 256
        AND gmail_message_id NOT GLOB '*[^ -~]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(account_key, gmail_message_id),
    UNIQUE(provider_source_id, account_key)
) STRICT;

CREATE TABLE gmail_scope_sources (
    scope_id TEXT NOT NULL,
    provider_source_id TEXT NOT NULL,
    account_key TEXT NOT NULL,
    first_seen_at_ms INTEGER NOT NULL CHECK (first_seen_at_ms >= 0),
    PRIMARY KEY(scope_id, provider_source_id),
    FOREIGN KEY(scope_id, account_key)
        REFERENCES gmail_scopes(scope_id, account_key) ON DELETE RESTRICT,
    FOREIGN KEY(provider_source_id, account_key)
        REFERENCES gmail_provider_sources(provider_source_id, account_key)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE gmail_source_revisions (
    revision_id TEXT PRIMARY KEY CHECK (
        length(revision_id) = 36
        AND revision_id <> '00000000-0000-0000-0000-000000000000'
    ),
    provider_source_id TEXT NOT NULL
        REFERENCES gmail_provider_sources(provider_source_id) ON DELETE RESTRICT,
    history_id TEXT NOT NULL CHECK (
        length(history_id) BETWEEN 1 AND 64
        AND history_id NOT GLOB '*[^0-9]*'
    ),
    availability TEXT NOT NULL CHECK (
        availability IN ('available', 'unavailable')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'materialized', 'label_removed', 'message_deleted',
            'message_not_found', 'label_absent_after_fetch'
        )
    ),
    graph_sha256 TEXT NOT NULL CHECK (
        length(graph_sha256) = 64
        AND graph_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    CHECK (
        (availability = 'available' AND reason = 'materialized')
        OR
        (availability = 'unavailable' AND reason <> 'materialized')
    ),
    UNIQUE(provider_source_id, history_id),
    UNIQUE(revision_id, provider_source_id),
    UNIQUE(revision_id, availability)
) STRICT;

CREATE TABLE gmail_revision_materializations (
    revision_id TEXT PRIMARY KEY
        REFERENCES gmail_source_revisions(revision_id) ON DELETE RESTRICT,
    local_source_id TEXT NOT NULL UNIQUE
        REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    source_provenance_id TEXT NOT NULL UNIQUE
        REFERENCES source_provenance(provenance_id) ON DELETE RESTRICT,
    blob_sha256 TEXT REFERENCES blobs(sha256) ON DELETE RESTRICT,
    mime_manifest_sha256 TEXT NOT NULL CHECK (
        length(mime_manifest_sha256) = 64
        AND mime_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    evidence_manifest_sha256 TEXT NOT NULL CHECK (
        length(evidence_manifest_sha256) = 64
        AND evidence_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

CREATE TABLE gmail_source_heads (
    provider_source_id TEXT PRIMARY KEY
        REFERENCES gmail_provider_sources(provider_source_id) ON DELETE RESTRICT,
    head_revision_id TEXT NOT NULL UNIQUE,
    availability TEXT NOT NULL CHECK (
        availability IN ('available', 'unavailable')
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    FOREIGN KEY(head_revision_id, provider_source_id)
        REFERENCES gmail_source_revisions(revision_id, provider_source_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(head_revision_id, availability)
        REFERENCES gmail_source_revisions(revision_id, availability)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE gmail_connector_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    status TEXT NOT NULL CHECK (
        status IN ('disconnected', 'connecting', 'connected', 'disconnecting')
    ),
    account_key TEXT REFERENCES gmail_accounts(account_key) ON DELETE RESTRICT,
    scope_id TEXT REFERENCES gmail_scopes(scope_id) ON DELETE RESTRICT,
    revocation_state TEXT CHECK (
        revocation_state IS NULL
        OR revocation_state IN ('pending', 'succeeded', 'already_invalid', 'failed')
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK (
        (status = 'disconnected' AND account_key IS NULL AND scope_id IS NULL)
        OR
        (status = 'connecting' AND scope_id IS NULL)
        OR
        (status IN ('connected', 'disconnecting')
            AND account_key IS NOT NULL AND scope_id IS NOT NULL)
    )
) STRICT;
INSERT INTO gmail_connector_state(
    singleton, status, account_key, scope_id, revocation_state, updated_at_ms
) VALUES (1, 'disconnected', NULL, NULL, NULL, 0);

CREATE TABLE gmail_operations (
    request_id TEXT PRIMARY KEY,
    command_name TEXT NOT NULL CHECK (
        command_name IN (
            'connect_gmail_v1', 'sync_gmail_v1', 'disconnect_gmail_v1'
        )
    ),
    request_envelope_sha256 TEXT NOT NULL CHECK (
        length(request_envelope_sha256) = 64
        AND request_envelope_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    stage TEXT NOT NULL CHECK (
        stage IN (
            'authorizing', 'credential_reserved', 'syncing',
            'revocation_pending', 'credential_delete_pending', 'terminal'
        )
    ),
    response_json TEXT CHECK (
        response_json IS NULL
        OR (
            json_valid(response_json)
            AND length(CAST(response_json AS BLOB)) <= 32768
        )
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    CHECK ((stage = 'terminal') = (response_json IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX gmail_operations_active_idx
    ON gmail_operations((1)) WHERE stage <> 'terminal';

CREATE TABLE gmail_operation_revisions (
    request_id TEXT NOT NULL
        REFERENCES gmail_operations(request_id) ON DELETE RESTRICT,
    revision_id TEXT NOT NULL
        REFERENCES gmail_source_revisions(revision_id) ON DELETE RESTRICT,
    PRIMARY KEY(request_id, revision_id)
) STRICT;

CREATE TABLE gmail_oauth_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (
        length(attempt_id) = 36
        AND attempt_id <> '00000000-0000-0000-0000-000000000000'
    ),
    request_id TEXT NOT NULL UNIQUE
        REFERENCES gmail_operations(request_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'exchanged', 'failed', 'expired')
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    completed_at_ms INTEGER,
    CHECK ((status = 'pending') = (completed_at_ms IS NULL))
) STRICT;

CREATE TABLE gmail_disconnect_stages (
    request_id TEXT PRIMARY KEY
        REFERENCES gmail_operations(request_id) ON DELETE RESTRICT,
    account_key TEXT NOT NULL
        REFERENCES gmail_accounts(account_key) ON DELETE RESTRICT,
    credential_locator TEXT NOT NULL,
    revocation_result TEXT CHECK (
        revocation_result IS NULL
        OR revocation_result IN ('succeeded', 'already_invalid', 'failed')
    ),
    credential_deleted INTEGER NOT NULL DEFAULT 0 CHECK (
        credential_deleted IN (0, 1)
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

CREATE INDEX gmail_scope_sources_provider_idx
    ON gmail_scope_sources(provider_source_id, scope_id);
CREATE INDEX gmail_revisions_provider_idx
    ON gmail_source_revisions(provider_source_id, history_id);
CREATE INDEX gmail_operation_revisions_revision_idx
    ON gmail_operation_revisions(revision_id, request_id);

CREATE TRIGGER gmail_revisions_no_update
BEFORE UPDATE ON gmail_source_revisions
BEGIN
    SELECT RAISE(ABORT, 'gmail revisions are append-only');
END;

CREATE TRIGGER gmail_revisions_no_delete
BEFORE DELETE ON gmail_source_revisions
BEGIN
    SELECT RAISE(ABORT, 'gmail revisions are append-only');
END;

CREATE TRIGGER gmail_materializations_no_update
BEFORE UPDATE ON gmail_revision_materializations
BEGIN
    SELECT RAISE(ABORT, 'gmail materializations are append-only');
END;

CREATE TRIGGER gmail_materializations_no_delete
BEFORE DELETE ON gmail_revision_materializations
BEGIN
    SELECT RAISE(ABORT, 'gmail materializations are append-only');
END;

CREATE TRIGGER gmail_materialization_shape_insert
BEFORE INSERT ON gmail_revision_materializations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM gmail_source_revisions revision
        JOIN local_sources source ON source.source_id = NEW.local_source_id
        JOIN source_provenance provenance
          ON provenance.provenance_id = NEW.source_provenance_id
         AND provenance.source_id = source.source_id
        WHERE revision.revision_id = NEW.revision_id
          AND (
            (revision.availability = 'available'
              AND NEW.blob_sha256 IS NOT NULL
              AND source.blob_sha256 = NEW.blob_sha256
              AND provenance.blob_sha256 = NEW.blob_sha256
              AND source.status = 'imported'
              AND source.no_blob_reason IS NULL)
            OR
            (revision.availability = 'unavailable'
              AND NEW.blob_sha256 IS NULL
              AND source.blob_sha256 IS NULL
              AND provenance.blob_sha256 IS NULL
              AND source.status = 'unavailable'
              AND source.no_blob_reason = revision.reason)
          )
    ) THEN RAISE(ABORT, 'gmail materialization shape mismatch') END;
END;

CREATE TRIGGER gmail_local_sources_no_update
BEFORE UPDATE ON local_sources
WHEN EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE local_source_id = OLD.source_id
)
BEGIN
    SELECT RAISE(ABORT, 'gmail local sources are immutable');
END;

CREATE TRIGGER gmail_local_sources_no_delete
BEFORE DELETE ON local_sources
WHEN EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE local_source_id = OLD.source_id
)
BEGIN
    SELECT RAISE(ABORT, 'gmail local sources are immutable');
END;

CREATE TRIGGER gmail_provenance_no_update
BEFORE UPDATE ON source_provenance
WHEN EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE source_provenance_id = OLD.provenance_id
)
BEGIN
    SELECT RAISE(ABORT, 'gmail provenance is immutable');
END;

CREATE TRIGGER gmail_provenance_no_delete
BEFORE DELETE ON source_provenance
WHEN EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE source_provenance_id = OLD.provenance_id
)
BEGIN
    SELECT RAISE(ABORT, 'gmail provenance is immutable');
END;

CREATE TRIGGER gmail_mime_no_update
BEFORE UPDATE ON mime_parts
WHEN EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE local_source_id = OLD.source_id
)
BEGIN
    SELECT RAISE(ABORT, 'gmail MIME rows are immutable');
END;

CREATE TRIGGER gmail_mime_no_insert
BEFORE INSERT ON mime_parts
WHEN EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE local_source_id = NEW.source_id
)
BEGIN
    SELECT RAISE(ABORT, 'gmail MIME rows are immutable');
END;

CREATE TRIGGER gmail_mime_no_delete
BEFORE DELETE ON mime_parts
WHEN EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE local_source_id = OLD.source_id
)
BEGIN
    SELECT RAISE(ABORT, 'gmail MIME rows are immutable');
END;

CREATE TRIGGER gmail_evidence_graph_no_update
BEFORE UPDATE ON evidence
WHEN EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE local_source_id = OLD.source_id
)
AND (
    NEW.evidence_id IS NOT OLD.evidence_id
    OR NEW.source_id IS NOT OLD.source_id
    OR NEW.part_id IS NOT OLD.part_id
    OR NEW.evidence_kind IS NOT OLD.evidence_kind
    OR NEW.created_at_ms IS NOT OLD.created_at_ms
)
BEGIN
    SELECT RAISE(ABORT, 'gmail evidence graph is immutable');
END;

CREATE TRIGGER gmail_evidence_no_insert
BEFORE INSERT ON evidence
WHEN NEW.evidence_kind = 'message_attachment'
AND EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE local_source_id = NEW.source_id
)
BEGIN
    SELECT RAISE(ABORT, 'gmail evidence graph is immutable');
END;

CREATE TRIGGER gmail_evidence_no_delete
BEFORE DELETE ON evidence
WHEN EXISTS (
    SELECT 1 FROM gmail_revision_materializations
    WHERE local_source_id = OLD.source_id
)
BEGIN
    SELECT RAISE(ABORT, 'gmail evidence graph is immutable');
END;
