CREATE TABLE import_roots (
    root_id TEXT PRIMARY KEY,
    canonical_path TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('available', 'unavailable', 'incomplete')),
    manifest_generation INTEGER NOT NULL DEFAULT 0 CHECK (manifest_generation >= 0),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    UNIQUE(device_id, file_id)
) STRICT;

CREATE TABLE import_scans (
    scan_id TEXT PRIMARY KEY,
    root_id TEXT NOT NULL REFERENCES import_roots(root_id) ON DELETE RESTRICT,
    generation INTEGER NOT NULL CHECK (generation > 0),
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'unavailable', 'incomplete')),
    imported_count INTEGER NOT NULL DEFAULT 0 CHECK (imported_count >= 0),
    reused_count INTEGER NOT NULL DEFAULT 0 CHECK (reused_count >= 0),
    quarantined_count INTEGER NOT NULL DEFAULT 0 CHECK (quarantined_count >= 0),
    skipped_count INTEGER NOT NULL DEFAULT 0 CHECK (skipped_count >= 0),
    started_at_ms INTEGER NOT NULL,
    completed_at_ms INTEGER,
    UNIQUE(root_id, generation)
) STRICT;

CREATE TABLE local_sources (
    source_id TEXT PRIMARY KEY,
    root_id TEXT REFERENCES import_roots(root_id) ON DELETE RESTRICT,
    parent_source_id TEXT REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    source_kind TEXT NOT NULL CHECK (
        source_kind IN ('folder_image', 'eml', 'mbox', 'mbox_message')
    ),
    identity_key TEXT NOT NULL,
    canonical_locator TEXT NOT NULL,
    device_id INTEGER,
    file_id INTEGER,
    raw_sha256 TEXT,
    blob_sha256 TEXT REFERENCES blobs(sha256) ON DELETE RESTRICT,
    byte_length INTEGER CHECK (byte_length IS NULL OR byte_length >= 0),
    byte_start INTEGER CHECK (byte_start IS NULL OR byte_start >= 0),
    byte_end INTEGER CHECK (
        byte_end IS NULL OR (byte_start IS NOT NULL AND byte_end >= byte_start)
    ),
    occurrence_ordinal INTEGER CHECK (
        occurrence_ordinal IS NULL OR occurrence_ordinal >= 0
    ),
    media_type TEXT,
    status TEXT NOT NULL CHECK (
        status IN ('imported', 'quarantined', 'missing', 'unavailable')
    ),
    no_blob_reason TEXT,
    manifest_generation INTEGER CHECK (
        manifest_generation IS NULL OR manifest_generation >= 0
    ),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    CHECK (
        (blob_sha256 IS NOT NULL AND no_blob_reason IS NULL)
        OR (blob_sha256 IS NULL AND no_blob_reason IS NOT NULL)
    ),
    UNIQUE(source_kind, identity_key)
) STRICT;

CREATE TABLE source_provenance (
    provenance_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL,
    observed_locator TEXT NOT NULL,
    raw_sha256 TEXT,
    blob_sha256 TEXT REFERENCES blobs(sha256) ON DELETE RESTRICT,
    observed_at_ms INTEGER NOT NULL,
    UNIQUE(source_id, request_id)
) STRICT;

CREATE TABLE quarantine_records (
    quarantine_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL UNIQUE REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    reason_code TEXT NOT NULL,
    diagnostic_count INTEGER NOT NULL DEFAULT 1 CHECK (
        diagnostic_count BETWEEN 1 AND 1000
    ),
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE mime_parts (
    part_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    parent_part_id TEXT REFERENCES mime_parts(part_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    content_type TEXT NOT NULL,
    content_disposition TEXT,
    content_id TEXT,
    body_kind TEXT NOT NULL CHECK (
        body_kind IN ('text', 'html', 'binary', 'multipart', 'message', 'empty')
    ),
    decoded_bytes INTEGER NOT NULL CHECK (decoded_bytes >= 0),
    UNIQUE(source_id, ordinal)
) STRICT;

CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    part_id TEXT REFERENCES mime_parts(part_id) ON DELETE RESTRICT,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('image', 'message_attachment')),
    state TEXT NOT NULL CHECK (state IN ('unresolved', 'assigned', 'rejected', 'deferred')),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    UNIQUE(source_id, part_id, evidence_kind)
) STRICT;

CREATE TABLE revision_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    catalog_revision INTEGER NOT NULL CHECK (catalog_revision >= 0),
    evidence_generation INTEGER NOT NULL CHECK (evidence_generation >= 0)
) STRICT;
INSERT INTO revision_state(singleton, catalog_revision, evidence_generation)
VALUES (1, 0, 0);

CREATE TABLE catalog_items (
    item_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 80),
    attributes_json TEXT NOT NULL CHECK (json_valid(attributes_json)),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_revision INTEGER NOT NULL CHECK (created_revision > 0),
    updated_revision INTEGER NOT NULL CHECK (updated_revision >= created_revision)
) STRICT;

CREATE TABLE item_evidence (
    item_id TEXT NOT NULL REFERENCES catalog_items(item_id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL UNIQUE REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    assigned_revision INTEGER NOT NULL CHECK (assigned_revision > 0),
    PRIMARY KEY(item_id, evidence_id)
) STRICT;

CREATE TABLE catalog_decisions (
    decision_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    decision_kind TEXT NOT NULL CHECK (
        decision_kind IN ('save', 'assign', 'reject', 'defer', 'merge', 'split', 'undo')
    ),
    catalog_revision INTEGER NOT NULL UNIQUE CHECK (catalog_revision > 0),
    forward_json TEXT NOT NULL CHECK (json_valid(forward_json)),
    inverse_json TEXT NOT NULL CHECK (json_valid(inverse_json)),
    compensates_decision_id TEXT REFERENCES catalog_decisions(decision_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE decision_entities (
    decision_id TEXT NOT NULL REFERENCES catalog_decisions(decision_id) ON DELETE RESTRICT,
    entity_kind TEXT NOT NULL CHECK (entity_kind IN ('item', 'evidence')),
    entity_id TEXT NOT NULL,
    PRIMARY KEY(decision_id, entity_kind, entity_id)
) STRICT;

CREATE TABLE derivatives (
    derivative_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    blob_sha256 TEXT NOT NULL REFERENCES blobs(sha256) ON DELETE RESTRICT,
    derivative_kind TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(source_id, derivative_kind)
) STRICT;

CREATE TABLE remote_references (
    remote_reference_id TEXT PRIMARY KEY,
    source_id TEXT REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    item_id TEXT REFERENCES catalog_items(item_id) ON DELETE RESTRICT,
    provider TEXT NOT NULL,
    remote_locator TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    CHECK ((source_id IS NOT NULL) <> (item_id IS NOT NULL)),
    UNIQUE(provider, remote_locator)
) STRICT;

CREATE TRIGGER catalog_decisions_no_update
BEFORE UPDATE ON catalog_decisions
BEGIN
    SELECT RAISE(ABORT, 'catalog_decisions are append-only');
END;

CREATE TRIGGER catalog_decisions_no_delete
BEFORE DELETE ON catalog_decisions
BEGIN
    SELECT RAISE(ABORT, 'catalog_decisions are append-only');
END;

CREATE TABLE deletion_previews (
    snapshot_token TEXT PRIMARY KEY,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('import_root', 'source', 'item')),
    target_id TEXT NOT NULL,
    catalog_revision INTEGER NOT NULL,
    evidence_generation INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
) STRICT;

CREATE TABLE deletion_preview_items (
    snapshot_token TEXT NOT NULL REFERENCES deletion_previews(snapshot_token) ON DELETE RESTRICT,
    dependency_class TEXT NOT NULL CHECK (
        dependency_class IN (
            'originals', 'derivatives', 'source_records', 'evidence_records',
            'decision_records', 'remote_references', 'retained_shared_blobs'
        )
    ),
    entity_id TEXT NOT NULL,
    sort_key TEXT NOT NULL,
    PRIMARY KEY(snapshot_token, dependency_class, entity_id)
) STRICT;

CREATE INDEX import_sources_root_manifest_idx
    ON local_sources(root_id, manifest_generation, source_id);
CREATE INDEX import_sources_parent_idx
    ON local_sources(parent_source_id, source_id);
CREATE INDEX import_sources_blob_idx
    ON local_sources(blob_sha256, source_id);
CREATE INDEX evidence_state_idx ON evidence(state, created_at_ms, evidence_id);
CREATE INDEX catalog_items_page_idx
    ON catalog_items(active, display_name, item_id);
CREATE INDEX decisions_entities_idx
    ON decision_entities(entity_kind, entity_id, decision_id);
CREATE INDEX deletion_preview_page_idx
    ON deletion_preview_items(snapshot_token, dependency_class, sort_key, entity_id);
