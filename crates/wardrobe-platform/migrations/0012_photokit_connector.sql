ALTER TABLE revision_state
ADD COLUMN photokit_revision INTEGER NOT NULL DEFAULT 0
CHECK (photokit_revision BETWEEN 0 AND 9007199254740990);

-- deletion_previews has a target-kind CHECK, so adding PhotoKit targets requires
-- a table rebuild. Preserve the dependent page rows while the parent is empty.
CREATE TEMP TABLE p06_deletion_previews AS
SELECT * FROM deletion_previews;
CREATE TEMP TABLE p06_deletion_preview_items AS
SELECT * FROM deletion_preview_items;
DELETE FROM deletion_preview_items;
DELETE FROM deletion_previews;
DROP INDEX deletion_preview_page_idx;
DROP TABLE deletion_previews;
CREATE TABLE deletion_previews (
    snapshot_token TEXT PRIMARY KEY,
    target_kind TEXT NOT NULL CHECK (
        target_kind IN (
            'import_root', 'source', 'item',
            'photokit_enrollment', 'photokit_asset'
        )
    ),
    target_id TEXT NOT NULL,
    catalog_revision INTEGER NOT NULL,
    evidence_generation INTEGER NOT NULL,
    photo_revision INTEGER NOT NULL DEFAULT 0 CHECK (photo_revision >= 0),
    reconciliation_revision INTEGER NOT NULL DEFAULT 0
        CHECK (reconciliation_revision BETWEEN 0 AND 9007199254740990),
    outfit_revision INTEGER NOT NULL DEFAULT 0
        CHECK (outfit_revision BETWEEN 0 AND 9007199254740990),
    try_on_revision INTEGER NOT NULL DEFAULT 0
        CHECK (try_on_revision BETWEEN 0 AND 9007199254740990),
    photokit_revision INTEGER NOT NULL DEFAULT 0
        CHECK (photokit_revision BETWEEN 0 AND 9007199254740990),
    created_at_ms INTEGER NOT NULL
) STRICT;
INSERT INTO deletion_previews(
    snapshot_token, target_kind, target_id, catalog_revision,
    evidence_generation, photo_revision, reconciliation_revision,
    outfit_revision, try_on_revision, photokit_revision, created_at_ms
)
SELECT
    snapshot_token, target_kind, target_id, catalog_revision,
    evidence_generation, photo_revision, reconciliation_revision,
    outfit_revision, try_on_revision, 0, created_at_ms
FROM p06_deletion_previews;
INSERT INTO deletion_preview_items
SELECT * FROM p06_deletion_preview_items;
CREATE INDEX deletion_preview_page_idx
    ON deletion_preview_items(
        snapshot_token, dependency_class, sort_key, entity_id
    );
DROP TABLE p06_deletion_preview_items;
DROP TABLE p06_deletion_previews;

ALTER TABLE deletion_runs
ADD COLUMN photokit_revision INTEGER NOT NULL DEFAULT 0
CHECK (photokit_revision BETWEEN 0 AND 9007199254740990);

-- deletion_plans is the durable deletion snapshot and also has a target-kind
-- CHECK. Empty and restore the complete bookkeeping closure so existing plans
-- and completed run receipts survive the parent rebuild with foreign keys on.
CREATE TEMP TABLE p06_deletion_plans AS SELECT * FROM deletion_plans;
CREATE TEMP TABLE p06_deletion_plan_entries AS
SELECT * FROM deletion_plan_entries;
CREATE TEMP TABLE p06_deletion_plan_backup AS
SELECT * FROM deletion_plan_backup_retention;
CREATE TEMP TABLE p06_deletion_plan_remote AS
SELECT * FROM deletion_plan_remote_retention;
CREATE TEMP TABLE p06_deletion_runs AS SELECT * FROM deletion_runs;
CREATE TEMP TABLE p06_deletion_run_blobs AS SELECT * FROM deletion_run_blobs;
CREATE TEMP TABLE p06_deletion_run_backup AS
SELECT * FROM deletion_run_backup_retention;
CREATE TEMP TABLE p06_deletion_run_remote AS
SELECT * FROM deletion_run_remote_retention;
CREATE TEMP TABLE p06_deletion_receipts AS
SELECT * FROM deletion_execution_receipts;
CREATE TEMP TABLE p06_deletion_authority AS
SELECT * FROM deletion_execution_authority;

DROP TRIGGER deletion_receipts_no_delete;
DELETE FROM deletion_execution_authority;
DELETE FROM deletion_execution_receipts;
DELETE FROM deletion_run_blobs;
DELETE FROM deletion_run_backup_retention;
DELETE FROM deletion_run_remote_retention;
DELETE FROM deletion_runs;
DELETE FROM deletion_plan_entries;
DELETE FROM deletion_plan_backup_retention;
DELETE FROM deletion_plan_remote_retention;
DELETE FROM deletion_plans;
DROP TRIGGER deletion_plans_no_update;
DROP TABLE deletion_plans;

CREATE TABLE deletion_plans (
    snapshot_token TEXT PRIMARY KEY,
    epoch TEXT NOT NULL REFERENCES store_authority_epoch(epoch) ON DELETE RESTRICT,
    target_kind TEXT NOT NULL CHECK (
        target_kind IN (
            'import_root', 'source', 'item',
            'photokit_enrollment', 'photokit_asset'
        )
    ),
    target_id TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK (
        length(plan_sha256) = 64
        AND plan_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    catalog_revision INTEGER NOT NULL CHECK (catalog_revision >= 0),
    evidence_generation INTEGER NOT NULL CHECK (evidence_generation >= 0),
    receipt_revision INTEGER NOT NULL CHECK (receipt_revision >= 0),
    photo_revision INTEGER NOT NULL CHECK (photo_revision >= 0),
    reconciliation_revision INTEGER NOT NULL CHECK (reconciliation_revision >= 0),
    outfit_revision INTEGER NOT NULL CHECK (outfit_revision >= 0),
    try_on_revision INTEGER NOT NULL CHECK (try_on_revision >= 0),
    photokit_revision INTEGER NOT NULL DEFAULT 0
        CHECK (photokit_revision BETWEEN 0 AND 9007199254740990),
    prepared_at_ms INTEGER NOT NULL CHECK (prepared_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > prepared_at_ms),
    unique_blob_count INTEGER NOT NULL CHECK (unique_blob_count >= 0),
    unique_blob_bytes INTEGER NOT NULL CHECK (unique_blob_bytes >= 0),
    retained_shared_blob_count INTEGER NOT NULL
        CHECK (retained_shared_blob_count >= 0)
) STRICT;
INSERT INTO deletion_plans(
    snapshot_token, epoch, target_kind, target_id, plan_sha256,
    catalog_revision, evidence_generation, receipt_revision, photo_revision,
    reconciliation_revision, outfit_revision, try_on_revision,
    photokit_revision, prepared_at_ms, expires_at_ms, unique_blob_count,
    unique_blob_bytes, retained_shared_blob_count
)
SELECT
    snapshot_token, epoch, target_kind, target_id, plan_sha256,
    catalog_revision, evidence_generation, receipt_revision, photo_revision,
    reconciliation_revision, outfit_revision, try_on_revision,
    0, prepared_at_ms, expires_at_ms, unique_blob_count,
    unique_blob_bytes, retained_shared_blob_count
FROM p06_deletion_plans;
CREATE UNIQUE INDEX deletion_plans_token_epoch_idx
    ON deletion_plans(snapshot_token, epoch);
CREATE TRIGGER deletion_plans_no_update BEFORE UPDATE ON deletion_plans
BEGIN SELECT RAISE(ABORT, 'deletion plans are immutable'); END;

INSERT INTO deletion_plan_entries SELECT * FROM p06_deletion_plan_entries;
INSERT INTO deletion_plan_backup_retention SELECT * FROM p06_deletion_plan_backup;
INSERT INTO deletion_plan_remote_retention SELECT * FROM p06_deletion_plan_remote;
INSERT INTO deletion_runs SELECT * FROM p06_deletion_runs;
INSERT INTO deletion_run_blobs SELECT * FROM p06_deletion_run_blobs;
INSERT INTO deletion_run_backup_retention SELECT * FROM p06_deletion_run_backup;
INSERT INTO deletion_run_remote_retention SELECT * FROM p06_deletion_run_remote;
INSERT INTO deletion_execution_receipts SELECT * FROM p06_deletion_receipts;
INSERT INTO deletion_execution_authority SELECT * FROM p06_deletion_authority;
CREATE TRIGGER deletion_receipts_no_delete
BEFORE DELETE ON deletion_execution_receipts
BEGIN SELECT RAISE(ABORT, 'deletion receipts are immutable'); END;

DROP TABLE p06_deletion_authority;
DROP TABLE p06_deletion_receipts;
DROP TABLE p06_deletion_run_remote;
DROP TABLE p06_deletion_run_backup;
DROP TABLE p06_deletion_run_blobs;
DROP TABLE p06_deletion_runs;
DROP TABLE p06_deletion_plan_remote;
DROP TABLE p06_deletion_plan_backup;
DROP TABLE p06_deletion_plan_entries;
DROP TABLE p06_deletion_plans;

-- Restore and connector recovery need narrowly scoped authority to remove only
-- provisional operation state. Hard-deletion authority remains separate.
CREATE TEMP TABLE p06_domain_mutation_authority AS
SELECT * FROM domain_mutation_authority;
DROP TABLE domain_mutation_authority;
CREATE TABLE domain_mutation_authority (
    entity_kind TEXT NOT NULL CHECK (
        entity_kind IN (
            'item_evidence', 'gmail_operation_cleanup',
            'photokit_operation_cleanup', 'photokit_key_cleanup_restore'
        )
    ),
    key_json TEXT NOT NULL CHECK (
        json_valid(key_json)
        AND json_type(key_json) = 'array'
        AND length(key_json) <= 1024
    ),
    PRIMARY KEY(entity_kind, key_json)
) STRICT;
INSERT INTO domain_mutation_authority
SELECT * FROM p06_domain_mutation_authority;
DROP TABLE p06_domain_mutation_authority;

CREATE TABLE photokit_enrollments (
    enrollment_epoch TEXT PRIMARY KEY CHECK (
        length(enrollment_epoch) = 36
        AND substr(enrollment_epoch, 9, 1) = '-'
        AND substr(enrollment_epoch, 14, 1) = '-'
        AND substr(enrollment_epoch, 19, 1) = '-'
        AND substr(enrollment_epoch, 24, 1) = '-'
        AND enrollment_epoch = lower(enrollment_epoch)
        AND enrollment_epoch NOT GLOB '*[^0-9a-f-]*'
        AND enrollment_epoch <> '00000000-0000-0000-0000-000000000000'
    ),
    key_reference TEXT NOT NULL UNIQUE CHECK (
        length(key_reference) BETWEEN 1 AND 128
        AND key_reference NOT GLOB '*[^ -~]*'
    ),
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'active', 'inactive')
    ),
    allow_icloud_downloads INTEGER NOT NULL CHECK (
        allow_icloud_downloads IN (0, 1)
    ),
    operation_fence INTEGER NOT NULL DEFAULT 0 CHECK (
        operation_fence BETWEEN 0 AND 9007199254740990
    ),
    active_membership_generation INTEGER CHECK (
        active_membership_generation IS NULL
        OR active_membership_generation BETWEEN 1 AND 9007199254740990
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    activated_at_ms INTEGER CHECK (
        activated_at_ms IS NULL OR activated_at_ms >= created_at_ms
    ),
    inactivated_at_ms INTEGER CHECK (
        inactivated_at_ms IS NULL OR inactivated_at_ms >= created_at_ms
    ),
    CHECK (
        (state = 'pending'
            AND activated_at_ms IS NULL
            AND inactivated_at_ms IS NULL)
        OR
        (state = 'active'
            AND activated_at_ms IS NOT NULL
            AND inactivated_at_ms IS NULL)
        OR
        (state = 'inactive'
            AND activated_at_ms IS NOT NULL
            AND inactivated_at_ms IS NOT NULL)
    )
) STRICT;

CREATE TABLE photokit_connector_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    state TEXT NOT NULL CHECK (
        state IN ('unconfigured', 'ready', 'reconciling', 'needs_attention')
    ),
    authorization TEXT NOT NULL CHECK (
        authorization IN (
            'not_determined', 'restricted', 'denied', 'limited', 'authorized'
        )
    ),
    active_enrollment_epoch TEXT
        REFERENCES photokit_enrollments(enrollment_epoch) ON DELETE RESTRICT,
    active_membership_generation INTEGER CHECK (
        active_membership_generation IS NULL
        OR active_membership_generation BETWEEN 1 AND 9007199254740990
    ),
    observed_count INTEGER NOT NULL DEFAULT 0 CHECK (
        observed_count BETWEEN 0 AND 500
    ),
    available_count INTEGER NOT NULL DEFAULT 0 CHECK (
        available_count BETWEEN 0 AND 500
    ),
    unavailable_count INTEGER NOT NULL DEFAULT 0 CHECK (
        unavailable_count BETWEEN 0 AND 500
    ),
    last_complete_at_ms INTEGER CHECK (
        last_complete_at_ms IS NULL OR last_complete_at_ms >= 0
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK (available_count + unavailable_count = observed_count),
    CHECK (
        (state = 'unconfigured'
            AND active_enrollment_epoch IS NULL
            AND active_membership_generation IS NULL
            AND observed_count = 0
            AND last_complete_at_ms IS NULL)
        OR
        (state <> 'unconfigured' AND active_enrollment_epoch IS NOT NULL)
    ),
    CHECK (
        (active_membership_generation IS NULL
            AND last_complete_at_ms IS NULL
            AND observed_count = 0)
        OR
        (active_membership_generation IS NOT NULL
            AND last_complete_at_ms IS NOT NULL)
    )
) STRICT;
INSERT INTO photokit_connector_state(
    singleton, state, authorization, updated_at_ms
) VALUES (1, 'unconfigured', 'not_determined', 0);

CREATE TABLE photokit_locator_records (
    locator_id TEXT PRIMARY KEY CHECK (length(locator_id) = 36),
    enrollment_epoch TEXT NOT NULL
        REFERENCES photokit_enrollments(enrollment_epoch) ON DELETE RESTRICT,
    operation_id TEXT,
    record_kind TEXT NOT NULL CHECK (record_kind IN ('album', 'asset')),
    stable_row_id TEXT NOT NULL CHECK (length(stable_row_id) = 36),
    key_version INTEGER NOT NULL CHECK (key_version = 1),
    lookup_hmac BLOB NOT NULL CHECK (length(lookup_hmac) = 32),
    nonce BLOB NOT NULL UNIQUE CHECK (length(nonce) = 24),
    ciphertext BLOB NOT NULL CHECK (length(ciphertext) BETWEEN 17 AND 1040),
    finalized INTEGER NOT NULL CHECK (finalized IN (0, 1)),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(enrollment_epoch, record_kind, lookup_hmac),
    UNIQUE(enrollment_epoch, record_kind, stable_row_id),
    CHECK (
        (record_kind = 'album' AND operation_id IS NULL AND finalized = 1)
        OR record_kind = 'asset'
    )
) STRICT;

CREATE TABLE photokit_assets (
    asset_id TEXT PRIMARY KEY CHECK (length(asset_id) = 36),
    enrollment_epoch TEXT NOT NULL
        REFERENCES photokit_enrollments(enrollment_epoch) ON DELETE RESTRICT,
    locator_id TEXT NOT NULL UNIQUE
        REFERENCES photokit_locator_records(locator_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(enrollment_epoch, asset_id)
) STRICT;

CREATE TABLE photokit_operations (
    operation_id TEXT PRIMARY KEY CHECK (length(operation_id) = 36),
    request_id TEXT NOT NULL UNIQUE CHECK (length(request_id) = 36),
    enrollment_epoch TEXT NOT NULL
        REFERENCES photokit_enrollments(enrollment_epoch) ON DELETE RESTRICT,
    -- This is a captured fencing token, not a live parent reference. Restore
    -- rotates the singleton epoch while preserving completed operation history.
    store_authority_epoch TEXT NOT NULL CHECK (
        length(store_authority_epoch) = 32
        AND store_authority_epoch NOT GLOB '*[^0-9a-f]*'
    ),
    reconciliation_fence INTEGER NOT NULL CHECK (
        reconciliation_fence BETWEEN 1 AND 9007199254740990
    ),
    proposed_membership_generation INTEGER NOT NULL CHECK (
        proposed_membership_generation BETWEEN 1 AND 9007199254740990
    ),
    trigger_kind TEXT NOT NULL CHECK (
        trigger_kind IN ('startup', 'user', 'library_change')
    ),
    state TEXT NOT NULL CHECK (
        state IN (
            'enumerating', 'materializing', 'complete', 'failed',
            'interrupted', 'stale'
        )
    ),
    terminal_reason TEXT CHECK (
        terminal_reason IS NULL
        OR terminal_reason IN (
            'enumeration_incomplete', 'authorization_not_determined',
            'authorization_restricted', 'authorization_denied',
            'limited_access', 'scope_unavailable', 'locator_key_unavailable',
            'restore_interrupted', 'stale_fence', 'internal'
        )
    ),
    observed_count INTEGER NOT NULL DEFAULT 0 CHECK (
        observed_count BETWEEN 0 AND 500
    ),
    accepted_bytes INTEGER NOT NULL DEFAULT 0 CHECK (
        accepted_bytes BETWEEN 0 AND 536870912
    ),
    started_at_ms INTEGER NOT NULL CHECK (started_at_ms >= 0),
    finished_at_ms INTEGER CHECK (
        finished_at_ms IS NULL OR finished_at_ms >= started_at_ms
    ),
    terminal_publication_json TEXT CHECK (
        terminal_publication_json IS NULL
        OR (
            json_valid(terminal_publication_json)
            AND length(terminal_publication_json) <= 16384
        )
    ),
    UNIQUE(enrollment_epoch, reconciliation_fence),
    CHECK (
        (state IN ('enumerating', 'materializing')
            AND terminal_reason IS NULL
            AND finished_at_ms IS NULL
            AND terminal_publication_json IS NULL)
        OR
        (state = 'complete'
            AND terminal_reason IS NULL
            AND finished_at_ms IS NOT NULL
            AND terminal_publication_json IS NOT NULL)
        OR
        (state = 'failed'
            AND terminal_reason IS NOT NULL
            AND finished_at_ms IS NOT NULL
            AND terminal_publication_json IS NOT NULL)
        OR
        (state IN ('interrupted', 'stale')
            AND terminal_reason IS NOT NULL
            AND finished_at_ms IS NOT NULL
            AND terminal_publication_json IS NULL)
    ),
    CHECK (
        terminal_publication_json IS NULL
        OR (
            json_type(terminal_publication_json, '$.operation_id') IS 'text'
            AND json_extract(terminal_publication_json, '$.operation_id')
                IS operation_id
            AND json_type(
                terminal_publication_json, '$.reconciliation_fence'
            ) IS 'integer'
            AND json_extract(
                terminal_publication_json, '$.reconciliation_fence'
            ) IS reconciliation_fence
            AND json_type(terminal_publication_json, '$.replayed') IS 'false'
            AND json_type(
                terminal_publication_json, '$.snapshot.enrollment_epoch'
            ) IS 'text'
            AND json_extract(
                terminal_publication_json, '$.snapshot.enrollment_epoch'
            ) IS enrollment_epoch
            AND (
                json_type(
                    terminal_publication_json, '$.membership_generation'
                ) IS 'integer'
                OR json_type(
                    terminal_publication_json, '$.membership_generation'
                ) IS 'null'
            )
            AND (
                json_type(
                    terminal_publication_json,
                    '$.snapshot.membership_generation'
                ) IS 'integer'
                OR json_type(
                    terminal_publication_json,
                    '$.snapshot.membership_generation'
                ) IS 'null'
            )
            AND json_extract(
                terminal_publication_json, '$.membership_generation'
            ) IS json_extract(
                terminal_publication_json,
                '$.snapshot.membership_generation'
            )
            AND (
                state <> 'complete'
                OR (
                    json_type(
                        terminal_publication_json, '$.membership_generation'
                    ) IS 'integer'
                    AND json_extract(
                        terminal_publication_json, '$.membership_generation'
                    ) IS proposed_membership_generation
                    AND json_extract(
                        terminal_publication_json,
                        '$.snapshot.membership_generation'
                    ) IS proposed_membership_generation
                )
            )
        )
    )
) STRICT;

CREATE TABLE photokit_operation_observations (
    operation_id TEXT NOT NULL
        REFERENCES photokit_operations(operation_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 499),
    asset_id TEXT NOT NULL CHECK (length(asset_id) = 36),
    locator_id TEXT NOT NULL
        REFERENCES photokit_locator_records(locator_id) ON DELETE RESTRICT,
    resource_uti TEXT CHECK (
        resource_uti IS NULL
        OR (
            length(resource_uti) BETWEEN 1 AND 128
            AND resource_uti NOT GLOB '*[^ -~]*'
        )
    ),
    resource_state TEXT NOT NULL CHECK (
        resource_state IN ('supported', 'unsupported')
    ),
    PRIMARY KEY(operation_id, ordinal),
    UNIQUE(operation_id, asset_id),
    UNIQUE(operation_id, locator_id)
) STRICT;

CREATE TABLE photokit_materialization_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (length(attempt_id) = 36),
    operation_id TEXT NOT NULL
        REFERENCES photokit_operations(operation_id) ON DELETE RESTRICT,
    observation_ordinal INTEGER NOT NULL,
    attempt_ordinal INTEGER NOT NULL CHECK (attempt_ordinal IN (0, 1)),
    network_access_allowed INTEGER NOT NULL CHECK (
        network_access_allowed IN (0, 1)
    ),
    accepted_bytes INTEGER NOT NULL CHECK (
        accepted_bytes BETWEEN 0 AND 41943040
    ),
    result TEXT NOT NULL CHECK (
        result IN (
            'materialized', 'network_access_required', 'icloud_unavailable',
            'unsupported_resource', 'transfer_failed', 'blob_integrity_failed'
        )
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(operation_id, observation_ordinal, attempt_ordinal),
    FOREIGN KEY(operation_id, observation_ordinal)
        REFERENCES photokit_operation_observations(operation_id, ordinal)
        ON DELETE RESTRICT
) STRICT;

CREATE TABLE photokit_membership_generations (
    enrollment_epoch TEXT NOT NULL
        REFERENCES photokit_enrollments(enrollment_epoch) ON DELETE RESTRICT,
    membership_generation INTEGER NOT NULL CHECK (
        membership_generation BETWEEN 1 AND 9007199254740990
    ),
    operation_id TEXT NOT NULL UNIQUE
        REFERENCES photokit_operations(operation_id) ON DELETE RESTRICT,
    observed_count INTEGER NOT NULL CHECK (observed_count BETWEEN 0 AND 500),
    available_count INTEGER NOT NULL CHECK (available_count BETWEEN 0 AND 500),
    unavailable_count INTEGER NOT NULL CHECK (
        unavailable_count BETWEEN 0 AND 500
    ),
    completed_at_ms INTEGER NOT NULL CHECK (completed_at_ms >= 0),
    PRIMARY KEY(enrollment_epoch, membership_generation),
    CHECK (available_count + unavailable_count = observed_count)
) STRICT;

CREATE TABLE photokit_materializations (
    materialization_id TEXT PRIMARY KEY CHECK (length(materialization_id) = 36),
    asset_id TEXT NOT NULL
        REFERENCES photokit_assets(asset_id) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL
        REFERENCES photokit_operations(operation_id) ON DELETE RESTRICT,
    resource_fingerprint TEXT NOT NULL CHECK (
        length(resource_fingerprint) = 64
        AND resource_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    blob_sha256 TEXT NOT NULL
        REFERENCES blobs(sha256) ON DELETE RESTRICT,
    byte_length INTEGER NOT NULL CHECK (
        byte_length BETWEEN 1 AND 41943040
    ),
    resource_uti TEXT NOT NULL CHECK (
        resource_uti IN (
            'public.jpeg', 'public.png', 'public.heic', 'public.heif'
        )
    ),
    pixel_width INTEGER NOT NULL CHECK (pixel_width BETWEEN 1 AND 16384),
    pixel_height INTEGER NOT NULL CHECK (pixel_height BETWEEN 1 AND 16384),
    selection_policy_revision TEXT NOT NULL CHECK (
        selection_policy_revision = 'original-primary-v1'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(asset_id, resource_fingerprint)
) STRICT;

CREATE TABLE photokit_availability_revisions (
    revision_id TEXT PRIMARY KEY CHECK (length(revision_id) = 36),
    asset_id TEXT NOT NULL
        REFERENCES photokit_assets(asset_id) ON DELETE RESTRICT,
    enrollment_epoch TEXT NOT NULL
        REFERENCES photokit_enrollments(enrollment_epoch) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL
        REFERENCES photokit_operations(operation_id) ON DELETE RESTRICT,
    membership_generation INTEGER,
    availability TEXT NOT NULL CHECK (
        availability IN ('available', 'unavailable')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'materialized', 'accessible', 'authorization_not_determined',
            'authorization_restricted', 'authorization_denied',
            'limited_access', 'scope_unavailable', 'asset_not_in_scope',
            'icloud_unavailable', 'unsupported_resource', 'transfer_failed',
            'blob_integrity_failed'
        )
    ),
    materialization_id TEXT
        REFERENCES photokit_materializations(materialization_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    FOREIGN KEY(enrollment_epoch, membership_generation)
        REFERENCES photokit_membership_generations(
            enrollment_epoch, membership_generation
        ) ON DELETE RESTRICT,
    CHECK (
        (availability = 'available'
            AND reason IN ('materialized', 'accessible'))
        OR
        (availability = 'unavailable'
            AND reason NOT IN ('materialized', 'accessible'))
    ),
    CHECK (
        (reason = 'materialized' AND materialization_id IS NOT NULL)
        OR
        (reason <> 'materialized')
    )
) STRICT;

CREATE TABLE photokit_availability_heads (
    asset_id TEXT PRIMARY KEY
        REFERENCES photokit_assets(asset_id) ON DELETE RESTRICT,
    revision_id TEXT NOT NULL UNIQUE
        REFERENCES photokit_availability_revisions(revision_id) ON DELETE RESTRICT,
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

CREATE TABLE photokit_generation_members (
    enrollment_epoch TEXT NOT NULL,
    membership_generation INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 499),
    asset_id TEXT NOT NULL
        REFERENCES photokit_assets(asset_id) ON DELETE RESTRICT,
    revision_id TEXT NOT NULL
        REFERENCES photokit_availability_revisions(revision_id) ON DELETE RESTRICT,
    PRIMARY KEY(enrollment_epoch, membership_generation, ordinal),
    UNIQUE(enrollment_epoch, membership_generation, asset_id),
    FOREIGN KEY(enrollment_epoch, membership_generation)
        REFERENCES photokit_membership_generations(
            enrollment_epoch, membership_generation
        ) ON DELETE RESTRICT
) STRICT;

CREATE TABLE photokit_command_receipts (
    request_id TEXT PRIMARY KEY CHECK (length(request_id) = 36),
    command_name TEXT NOT NULL CHECK (
        command_name IN (
            'configure_photokit_scope_v1', 'sync_photokit_v1',
            'disable_photokit_v1'
        )
    ),
    envelope_hash TEXT NOT NULL CHECK (
        length(envelope_hash) = 64
        AND envelope_hash NOT GLOB '*[^0-9a-f]*'
    ),
    enrollment_epoch TEXT,
    operation_id TEXT,
    response_json TEXT NOT NULL CHECK (
        json_valid(response_json) AND length(response_json) <= 8192
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

CREATE TABLE photokit_key_cleanup_intents (
    intent_id TEXT PRIMARY KEY CHECK (length(intent_id) = 36),
    deletion_run_id TEXT
        REFERENCES deletion_runs(run_id) ON DELETE RESTRICT,
    enrollment_epoch TEXT NOT NULL CHECK (length(enrollment_epoch) = 36),
    key_reference TEXT NOT NULL UNIQUE CHECK (
        length(key_reference) BETWEEN 1 AND 128
        AND key_reference NOT GLOB '*[^ -~]*'
    ),
    reason TEXT NOT NULL CHECK (
        reason IN (
            'final_key_owner', 'pending_enrollment_recovery',
            'incomplete_enrollment_restore'
        )
    ),
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete')),
    failure_code TEXT CHECK (
        failure_code IS NULL
        OR failure_code IN ('locked', 'unavailable', 'internal')
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    last_attempt_at_ms INTEGER CHECK (
        last_attempt_at_ms IS NULL OR last_attempt_at_ms >= created_at_ms
    ),
    completed_at_ms INTEGER CHECK (
        completed_at_ms IS NULL OR completed_at_ms >= created_at_ms
    ),
    CHECK (
        (state = 'pending' AND completed_at_ms IS NULL)
        OR
        (state = 'complete'
            AND completed_at_ms IS NOT NULL
            AND failure_code IS NULL)
    )
) STRICT;

CREATE TABLE deletion_plan_photokit_key_cleanup (
    snapshot_token TEXT NOT NULL,
    epoch TEXT NOT NULL,
    enrollment_epoch TEXT NOT NULL CHECK (length(enrollment_epoch) = 36),
    key_reference TEXT NOT NULL CHECK (
        length(key_reference) BETWEEN 1 AND 128
        AND key_reference NOT GLOB '*[^ -~]*'
    ),
    PRIMARY KEY(snapshot_token, enrollment_epoch),
    FOREIGN KEY(snapshot_token, epoch)
        REFERENCES deletion_plans(snapshot_token, epoch) ON DELETE RESTRICT
) STRICT;

CREATE INDEX photokit_operations_recovery_idx
    ON photokit_operations(state, started_at_ms, operation_id);
CREATE INDEX photokit_observations_operation_idx
    ON photokit_operation_observations(operation_id, ordinal);
CREATE INDEX photokit_materializations_blob_idx
    ON photokit_materializations(blob_sha256, materialization_id);
CREATE INDEX photokit_revisions_asset_idx
    ON photokit_availability_revisions(asset_id, created_at_ms, revision_id);
CREATE INDEX photokit_cleanup_pending_idx
    ON photokit_key_cleanup_intents(state, created_at_ms, intent_id);

CREATE TRIGGER photokit_enrollments_limited_update
BEFORE UPDATE ON photokit_enrollments
WHEN
    OLD.enrollment_epoch <> NEW.enrollment_epoch
    OR OLD.key_reference <> NEW.key_reference
    OR OLD.allow_icloud_downloads <> NEW.allow_icloud_downloads
    OR OLD.created_at_ms <> NEW.created_at_ms
    OR OLD.state = 'inactive'
    OR (OLD.state = 'pending' AND NEW.state NOT IN ('pending', 'active'))
    OR (OLD.state = 'active' AND NEW.state NOT IN ('active', 'inactive'))
BEGIN
    SELECT RAISE(ABORT, 'photokit enrollment update is not permitted');
END;

CREATE TRIGGER photokit_locator_records_limited_update
BEFORE UPDATE ON photokit_locator_records
WHEN
    OLD.locator_id <> NEW.locator_id
    OR OLD.enrollment_epoch <> NEW.enrollment_epoch
    OR OLD.operation_id IS NOT NEW.operation_id
    OR OLD.record_kind <> NEW.record_kind
    OR OLD.stable_row_id <> NEW.stable_row_id
    OR OLD.key_version <> NEW.key_version
    OR OLD.lookup_hmac <> NEW.lookup_hmac
    OR OLD.nonce <> NEW.nonce
    OR OLD.ciphertext <> NEW.ciphertext
    OR OLD.created_at_ms <> NEW.created_at_ms
    OR NOT (OLD.finalized = 0 AND NEW.finalized = 1)
BEGIN
    SELECT RAISE(ABORT, 'photokit locator update is not permitted');
END;

CREATE TRIGGER photokit_operations_initial_state
BEFORE INSERT ON photokit_operations
WHEN NEW.state <> 'enumerating'
BEGIN
    SELECT RAISE(ABORT, 'photokit operation must start enumerating');
END;

CREATE TRIGGER photokit_operations_limited_update
BEFORE UPDATE ON photokit_operations
WHEN
    OLD.operation_id <> NEW.operation_id
    OR OLD.request_id <> NEW.request_id
    OR OLD.enrollment_epoch <> NEW.enrollment_epoch
    OR OLD.store_authority_epoch <> NEW.store_authority_epoch
    OR OLD.reconciliation_fence <> NEW.reconciliation_fence
    OR OLD.proposed_membership_generation <> NEW.proposed_membership_generation
    OR OLD.trigger_kind <> NEW.trigger_kind
    OR OLD.started_at_ms <> NEW.started_at_ms
    OR (
        OLD.state <> NEW.state
        AND NOT (
            (OLD.state = 'enumerating'
                AND NEW.state IN (
                    'materializing', 'failed', 'interrupted', 'stale'
                ))
            OR
            (OLD.state = 'materializing'
                AND NEW.state IN (
                    'complete', 'failed', 'interrupted', 'stale'
                ))
        )
    )
    OR (
        OLD.terminal_publication_json IS NOT NEW.terminal_publication_json
        AND NOT (
            OLD.terminal_publication_json IS NULL
            AND NEW.terminal_publication_json IS NOT NULL
            AND OLD.state IN ('enumerating', 'materializing')
            AND NEW.state IN ('complete', 'failed')
        )
    )
    OR OLD.state IN ('complete', 'failed', 'interrupted', 'stale')
BEGIN
    SELECT RAISE(ABORT, 'photokit operation update is not permitted');
END;

CREATE TRIGGER photokit_materialization_attempts_no_update
BEFORE UPDATE ON photokit_materialization_attempts
BEGIN SELECT RAISE(ABORT, 'photokit attempts are immutable'); END;
CREATE TRIGGER photokit_operation_observations_no_update
BEFORE UPDATE ON photokit_operation_observations
BEGIN SELECT RAISE(ABORT, 'photokit observations are immutable'); END;
CREATE TRIGGER photokit_generations_no_update
BEFORE UPDATE ON photokit_membership_generations
BEGIN SELECT RAISE(ABORT, 'photokit generations are immutable'); END;
CREATE TRIGGER photokit_generation_members_no_update
BEFORE UPDATE ON photokit_generation_members
BEGIN SELECT RAISE(ABORT, 'photokit generation members are immutable'); END;
CREATE TRIGGER photokit_assets_no_update
BEFORE UPDATE ON photokit_assets
BEGIN SELECT RAISE(ABORT, 'photokit assets are immutable'); END;
CREATE TRIGGER photokit_materializations_no_update
BEFORE UPDATE ON photokit_materializations
BEGIN SELECT RAISE(ABORT, 'photokit materializations are immutable'); END;
CREATE TRIGGER photokit_revisions_no_update
BEFORE UPDATE ON photokit_availability_revisions
BEGIN SELECT RAISE(ABORT, 'photokit revisions are immutable'); END;
CREATE TRIGGER photokit_command_receipts_no_update
BEFORE UPDATE ON photokit_command_receipts
BEGIN SELECT RAISE(ABORT, 'photokit receipts are immutable'); END;
CREATE TRIGGER hd_photokit_command_receipts
BEFORE DELETE ON photokit_command_receipts
WHEN NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_command_receipts'
      AND entry.key_json = json_array(OLD.request_id)
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER photokit_observations_guard_delete
BEFORE DELETE ON photokit_operation_observations
WHEN NOT EXISTS (
    SELECT 1 FROM photokit_operations operation
    WHERE operation.operation_id = OLD.operation_id
      AND operation.state IN ('failed', 'interrupted', 'stale')
)
AND NOT EXISTS (
    SELECT 1 FROM domain_mutation_authority authority
    WHERE authority.entity_kind = 'photokit_operation_cleanup'
      AND authority.key_json = json_array(OLD.operation_id)
)
AND NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_operation_observations'
      AND entry.key_json = json_array(OLD.operation_id, OLD.ordinal)
)
BEGIN SELECT RAISE(ABORT, 'photokit observation deletion is not permitted'); END;

CREATE TRIGGER photokit_locator_records_guard_delete
BEFORE DELETE ON photokit_locator_records
WHEN OLD.finalized = 1
AND NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_locator_records'
      AND entry.key_json = json_array(OLD.locator_id)
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER photokit_enrollments_guard_delete
BEFORE DELETE ON photokit_enrollments
WHEN OLD.state <> 'pending'
AND NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_enrollments'
      AND entry.key_json = json_array(OLD.enrollment_epoch)
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER hd_photokit_assets
BEFORE DELETE ON photokit_assets
WHEN NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_assets'
      AND entry.key_json = json_array(OLD.asset_id)
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER hd_photokit_operations
BEFORE DELETE ON photokit_operations
WHEN NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_operations'
      AND entry.key_json = json_array(OLD.operation_id)
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER photokit_attempts_guard_delete
BEFORE DELETE ON photokit_materialization_attempts
WHEN NOT EXISTS (
    SELECT 1 FROM photokit_operations operation
    WHERE operation.operation_id = OLD.operation_id
      AND operation.state IN ('failed', 'interrupted', 'stale')
)
AND NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_materialization_attempts'
      AND entry.key_json = json_array(OLD.attempt_id)
)
BEGIN SELECT RAISE(ABORT, 'photokit attempt deletion is not permitted'); END;

CREATE TRIGGER hd_photokit_generations
BEFORE DELETE ON photokit_membership_generations
WHEN NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_membership_generations'
      AND entry.key_json =
          json_array(OLD.enrollment_epoch, OLD.membership_generation)
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER hd_photokit_materializations
BEFORE DELETE ON photokit_materializations
WHEN NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_materializations'
      AND entry.key_json = json_array(OLD.materialization_id)
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER hd_photokit_revisions
BEFORE DELETE ON photokit_availability_revisions
WHEN NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_availability_revisions'
      AND entry.key_json = json_array(OLD.revision_id)
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER hd_photokit_heads
BEFORE DELETE ON photokit_availability_heads
WHEN NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_availability_heads'
      AND entry.key_json = json_array(OLD.asset_id)
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER hd_photokit_generation_members
BEFORE DELETE ON photokit_generation_members
WHEN NOT EXISTS (
    SELECT 1
    FROM deletion_execution_authority authority
    JOIN deletion_plan_entries entry
      ON entry.snapshot_token = authority.snapshot_token
     AND entry.epoch = authority.epoch
    WHERE entry.entity_kind = 'photokit_generation_members'
      AND entry.key_json = json_array(
          OLD.enrollment_epoch, OLD.membership_generation, OLD.ordinal
      )
)
BEGIN SELECT RAISE(ABORT, 'hard deletion authority required'); END;

CREATE TRIGGER photokit_key_cleanup_limited_update
BEFORE UPDATE ON photokit_key_cleanup_intents
WHEN
    OLD.intent_id <> NEW.intent_id
    OR (
        OLD.deletion_run_id IS NOT NEW.deletion_run_id
        AND NOT EXISTS (
            SELECT 1 FROM domain_mutation_authority authority
            WHERE authority.entity_kind = 'photokit_key_cleanup_restore'
              AND authority.key_json = json_array(OLD.intent_id)
        )
    )
    OR OLD.enrollment_epoch <> NEW.enrollment_epoch
    OR OLD.key_reference <> NEW.key_reference
    OR OLD.reason <> NEW.reason
    OR OLD.created_at_ms <> NEW.created_at_ms
    OR OLD.state = 'complete'
BEGIN
    SELECT RAISE(ABORT, 'photokit key cleanup update is not permitted');
END;
CREATE TRIGGER photokit_key_cleanup_no_delete
BEFORE DELETE ON photokit_key_cleanup_intents
BEGIN SELECT RAISE(ABORT, 'photokit key cleanup intents are durable'); END;
CREATE TRIGGER deletion_plan_photokit_key_cleanup_no_update
BEFORE UPDATE ON deletion_plan_photokit_key_cleanup
BEGIN SELECT RAISE(ABORT, 'deletion key cleanup actions are immutable'); END;
