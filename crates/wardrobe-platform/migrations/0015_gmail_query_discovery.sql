PRAGMA legacy_alter_table = ON;

ALTER TABLE gmail_connector_settings RENAME TO gmail_connector_settings_v1;

CREATE TABLE gmail_connector_settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    oauth_client_id TEXT NOT NULL CHECK (
        length(oauth_client_id) BETWEEN 1 AND 256
        AND oauth_client_id NOT GLOB '*[^ -~]*'
        AND oauth_client_id GLOB '*.apps.googleusercontent.com'
    ),
    discovery_kind TEXT NOT NULL CHECK (
        discovery_kind IN ('search', 'label')
    ),
    discovery_value TEXT NOT NULL CHECK (
        length(CAST(discovery_value AS BLOB)) BETWEEN 1 AND 2048
        AND discovery_value NOT GLOB '*[[:cntrl:]]*'
        AND (
            discovery_kind = 'search'
            OR (
                length(discovery_value) <= 80
                AND discovery_value = trim(discovery_value)
            )
        )
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

INSERT INTO gmail_connector_settings(
    singleton, oauth_client_id, discovery_kind, discovery_value, page_size,
    max_pages, max_unique_messages, max_total_raw_bytes, updated_at_ms
)
SELECT
    singleton, oauth_client_id, 'label', label_name, page_size, max_pages,
    max_unique_messages, max_total_raw_bytes, updated_at_ms
FROM gmail_connector_settings_v1;

DROP TABLE gmail_connector_settings_v1;

ALTER TABLE gmail_scopes ADD COLUMN discovery_kind TEXT NOT NULL
    DEFAULT 'label' CHECK (discovery_kind IN ('search', 'label'));
ALTER TABLE gmail_scopes ADD COLUMN discovery_value TEXT NOT NULL
    DEFAULT 'legacy-label' CHECK (
        length(CAST(discovery_value AS BLOB)) BETWEEN 1 AND 2048
        AND discovery_value NOT GLOB '*[[:cntrl:]]*'
    );

UPDATE gmail_scopes
SET discovery_value = label_id
WHERE discovery_kind = 'label';

UPDATE gmail_scopes
SET discovery_value = (
    SELECT discovery_value
    FROM gmail_connector_settings
    WHERE singleton = 1
)
WHERE scope_id = (
    SELECT scope_id
    FROM gmail_connector_state
    WHERE singleton = 1
)
AND EXISTS (
    SELECT 1
    FROM gmail_connector_settings
    WHERE singleton = 1
);

ALTER TABLE gmail_source_revisions
RENAME TO p10_gmail_source_revisions_legacy;

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
    UNIQUE(revision_id, provider_source_id),
    UNIQUE(revision_id, availability)
) STRICT;

INSERT INTO gmail_source_revisions(
    revision_id, provider_source_id, history_id, availability,
    reason, graph_sha256, created_at_ms
)
SELECT
    revision_id, provider_source_id, history_id, availability,
    reason, graph_sha256, created_at_ms
FROM p10_gmail_source_revisions_legacy;

DROP TABLE p10_gmail_source_revisions_legacy;

CREATE UNIQUE INDEX gmail_available_revisions_provider_history_idx
    ON gmail_source_revisions(provider_source_id, history_id)
    WHERE availability = 'available';

CREATE INDEX gmail_revisions_provider_idx
    ON gmail_source_revisions(provider_source_id, history_id);

CREATE TRIGGER gmail_revisions_no_update
BEFORE UPDATE ON gmail_source_revisions
BEGIN
    SELECT RAISE(ABORT, 'gmail revisions are append-only');
END;

CREATE TRIGGER hd_gmail_source_revisions
BEFORE DELETE ON gmail_source_revisions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'gmail_source_revisions'
          AND planned.key_json = json_array(OLD.revision_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

CREATE TABLE gmail_scope_availability_observations (
    scope_id TEXT NOT NULL,
    provider_source_id TEXT NOT NULL,
    account_key TEXT NOT NULL,
    history_id TEXT NOT NULL CHECK (
        length(history_id) BETWEEN 1 AND 64
        AND history_id NOT GLOB '*[^0-9]*'
    ),
    available_revision_id TEXT,
    availability TEXT NOT NULL CHECK (
        availability IN ('available', 'unavailable')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'materialized', 'label_removed', 'message_deleted',
            'message_not_found', 'label_absent_after_fetch'
        )
    ),
    observed_at_ms INTEGER NOT NULL CHECK (observed_at_ms >= 0),
    PRIMARY KEY(scope_id, provider_source_id, history_id),
    UNIQUE(scope_id, provider_source_id, history_id, availability),
    FOREIGN KEY(scope_id, provider_source_id)
        REFERENCES gmail_scope_sources(scope_id, provider_source_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(scope_id, account_key)
        REFERENCES gmail_scopes(scope_id, account_key) ON DELETE RESTRICT,
    FOREIGN KEY(provider_source_id, account_key)
        REFERENCES gmail_provider_sources(provider_source_id, account_key)
        ON DELETE RESTRICT,
    FOREIGN KEY(available_revision_id, provider_source_id)
        REFERENCES gmail_source_revisions(revision_id, provider_source_id)
        ON DELETE RESTRICT,
    CHECK (
        (
            availability = 'available'
            AND reason = 'materialized'
            AND available_revision_id IS NOT NULL
        )
        OR
        (
            availability = 'unavailable'
            AND reason <> 'materialized'
            AND available_revision_id IS NULL
        )
    )
) STRICT;

CREATE TABLE gmail_scope_availability_heads (
    scope_id TEXT NOT NULL,
    provider_source_id TEXT NOT NULL,
    account_key TEXT NOT NULL,
    head_history_id TEXT NOT NULL CHECK (
        length(head_history_id) BETWEEN 1 AND 64
        AND head_history_id NOT GLOB '*[^0-9]*'
    ),
    availability TEXT NOT NULL CHECK (
        availability IN ('available', 'unavailable')
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    PRIMARY KEY(scope_id, provider_source_id),
    FOREIGN KEY(scope_id, provider_source_id, head_history_id)
        REFERENCES gmail_scope_availability_observations(
            scope_id, provider_source_id, history_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY(
        scope_id, provider_source_id, head_history_id, availability
    ) REFERENCES gmail_scope_availability_observations(
        scope_id, provider_source_id, history_id, availability
    ) ON DELETE RESTRICT,
    FOREIGN KEY(scope_id, account_key)
        REFERENCES gmail_scopes(scope_id, account_key) ON DELETE RESTRICT,
    FOREIGN KEY(provider_source_id, account_key)
        REFERENCES gmail_provider_sources(provider_source_id, account_key)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX gmail_scope_availability_observations_provider_idx
    ON gmail_scope_availability_observations(
        provider_source_id, scope_id, history_id
    );

INSERT INTO gmail_scope_availability_observations(
    scope_id, provider_source_id, account_key, history_id,
    available_revision_id, availability, reason, observed_at_ms
)
SELECT
    membership.scope_id,
    membership.provider_source_id,
    membership.account_key,
    revision.history_id,
    CASE
        WHEN revision.availability = 'available' THEN revision.revision_id
        ELSE NULL
    END,
    revision.availability,
    revision.reason,
    revision.created_at_ms
FROM gmail_scope_sources membership
JOIN gmail_source_revisions revision
  ON revision.provider_source_id = membership.provider_source_id;

INSERT INTO gmail_scope_availability_heads(
    scope_id, provider_source_id, account_key, head_history_id,
    availability, updated_at_ms
)
SELECT
    membership.scope_id,
    membership.provider_source_id,
    membership.account_key,
    revision.history_id,
    head.availability,
    head.updated_at_ms
FROM gmail_scope_sources membership
JOIN gmail_source_heads head
  ON head.provider_source_id = membership.provider_source_id
JOIN gmail_source_revisions revision
  ON revision.revision_id = head.head_revision_id;

DROP TRIGGER hd_gmail_source_heads;

DELETE FROM gmail_source_heads;

WITH available_revisions AS (
    SELECT
        revision.provider_source_id,
        revision.revision_id,
        revision.history_id,
        revision.created_at_ms,
        row_number() OVER (
            PARTITION BY revision.provider_source_id
            ORDER BY
                length(
                    CASE
                        WHEN ltrim(revision.history_id, '0') = '' THEN '0'
                        ELSE ltrim(revision.history_id, '0')
                    END
                ) DESC,
                CASE
                    WHEN ltrim(revision.history_id, '0') = '' THEN '0'
                    ELSE ltrim(revision.history_id, '0')
                END DESC,
                revision.revision_id DESC
        ) AS position
    FROM gmail_source_revisions revision
    JOIN gmail_revision_materializations materialization
      ON materialization.revision_id = revision.revision_id
    WHERE revision.availability = 'available'
      AND materialization.blob_sha256 IS NOT NULL
)
INSERT INTO gmail_source_heads(
    provider_source_id, head_revision_id, availability, updated_at_ms
)
SELECT
    provider_source_id, revision_id, 'available', created_at_ms
FROM available_revisions
WHERE position = 1;

CREATE TRIGGER hd_gmail_source_heads
BEFORE DELETE ON gmail_source_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'gmail_source_heads'
          AND planned.key_json = json_array(OLD.provider_source_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

CREATE TRIGGER gmail_scope_availability_observations_no_update
BEFORE UPDATE ON gmail_scope_availability_observations
BEGIN
    SELECT RAISE(ABORT, 'gmail scope availability observations are append-only');
END;

CREATE TRIGGER hd_gmail_scope_availability_observations
BEFORE DELETE ON gmail_scope_availability_observations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind =
              'gmail_scope_availability_observations'
          AND planned.key_json =
              json_array(
                  OLD.scope_id,
                  OLD.provider_source_id,
                  OLD.history_id
              )
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

CREATE TRIGGER hd_gmail_scope_availability_heads
BEFORE DELETE ON gmail_scope_availability_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'gmail_scope_availability_heads'
          AND planned.key_json =
              json_array(OLD.scope_id, OLD.provider_source_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

CREATE TABLE gmail_request_reservations (
    request_id TEXT PRIMARY KEY,
    command_name TEXT NOT NULL CHECK (
        command_name IN (
            'save_gmail_settings_v1',
            'save_gmail_settings_v2',
            'connect_gmail_v1',
            'sync_gmail_v1',
            'disconnect_gmail_v1'
        )
    ),
    envelope_hash TEXT NOT NULL CHECK (
        length(envelope_hash) = 64
        AND envelope_hash NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

CREATE TEMP TABLE p10_gmail_request_identity_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;

INSERT INTO p10_gmail_request_identity_guard(valid)
SELECT 0
FROM gmail_operations operation
JOIN command_receipts receipt
  ON receipt.request_id = operation.request_id
WHERE operation.command_name <> receipt.command_name
   OR operation.request_envelope_sha256 <> receipt.envelope_hash;

DROP TABLE p10_gmail_request_identity_guard;

INSERT INTO gmail_request_reservations(
    request_id, command_name, envelope_hash, created_at_ms
)
SELECT
    request_id, command_name, request_envelope_sha256, created_at_ms
FROM gmail_operations;

INSERT INTO gmail_request_reservations(
    request_id, command_name, envelope_hash, created_at_ms
)
SELECT
    receipt.request_id,
    receipt.command_name,
    receipt.envelope_hash,
    receipt.created_at_ms
FROM command_receipts receipt
WHERE receipt.command_name IN (
    'save_gmail_settings_v1',
    'save_gmail_settings_v2',
    'connect_gmail_v1',
    'sync_gmail_v1',
    'disconnect_gmail_v1'
)
AND NOT EXISTS (
    SELECT 1
    FROM gmail_request_reservations reservation
    WHERE reservation.request_id = receipt.request_id
);

CREATE TRIGGER gmail_request_reservations_no_update
BEFORE UPDATE ON gmail_request_reservations
BEGIN
    SELECT RAISE(ABORT, 'gmail request reservations are immutable');
END;

CREATE TRIGGER gmail_request_reservations_no_delete
BEFORE DELETE ON gmail_request_reservations
BEGIN
    SELECT RAISE(ABORT, 'gmail request reservations are durable');
END;

PRAGMA legacy_alter_table = OFF;
