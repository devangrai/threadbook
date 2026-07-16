ALTER TABLE outfit_recommendation_attempts
    ADD COLUMN transport_started_at_ms INTEGER
    CHECK (
        transport_started_at_ms IS NULL
        OR transport_started_at_ms >= created_at_ms
    );

DROP TRIGGER outfit_recommendation_attempts_limited_update;
CREATE TRIGGER outfit_recommendation_attempts_limited_update
BEFORE UPDATE ON outfit_recommendation_attempts
WHEN
    OLD.state <> 'reserved'
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
    OR (
        NEW.state = 'reserved'
        AND (
            OLD.transport_started_at_ms IS NOT NULL
            OR NEW.transport_started_at_ms IS NULL
            OR OLD.provider_request_id IS NOT NEW.provider_request_id
            OR OLD.provider_response_id IS NOT NEW.provider_response_id
            OR OLD.usage_json IS NOT NEW.usage_json
            OR OLD.audit_json IS NOT NEW.audit_json
            OR OLD.terminal_response_json IS NOT NEW.terminal_response_json
            OR OLD.validated_response_json IS NOT NEW.validated_response_json
            OR OLD.failure_code IS NOT NEW.failure_code
            OR OLD.finalized_at_ms IS NOT NEW.finalized_at_ms
        )
    )
    OR (
        NEW.state <> 'reserved'
        AND OLD.transport_started_at_ms IS NOT NEW.transport_started_at_ms
    )
BEGIN
    SELECT RAISE(ABORT, 'recommendation attempt update is not permitted');
END;

CREATE TABLE store_authority_epoch (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    epoch TEXT NOT NULL UNIQUE CHECK (length(epoch) = 32 AND epoch NOT GLOB '*[^0-9a-f]*')
) STRICT;
INSERT INTO store_authority_epoch(singleton, epoch) VALUES (1, lower(hex(randomblob(16))));

CREATE TABLE deletion_plans (
    snapshot_token TEXT PRIMARY KEY,
    epoch TEXT NOT NULL REFERENCES store_authority_epoch(epoch) ON DELETE RESTRICT,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('import_root', 'source', 'item')),
    target_id TEXT NOT NULL,
    plan_sha256 TEXT NOT NULL CHECK (length(plan_sha256) = 64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'),
    catalog_revision INTEGER NOT NULL CHECK (catalog_revision >= 0),
    evidence_generation INTEGER NOT NULL CHECK (evidence_generation >= 0),
    receipt_revision INTEGER NOT NULL CHECK (receipt_revision >= 0),
    photo_revision INTEGER NOT NULL CHECK (photo_revision >= 0),
    reconciliation_revision INTEGER NOT NULL CHECK (reconciliation_revision >= 0),
    outfit_revision INTEGER NOT NULL CHECK (outfit_revision >= 0),
    try_on_revision INTEGER NOT NULL CHECK (try_on_revision >= 0),
    prepared_at_ms INTEGER NOT NULL CHECK (prepared_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > prepared_at_ms),
    unique_blob_count INTEGER NOT NULL CHECK (unique_blob_count >= 0),
    unique_blob_bytes INTEGER NOT NULL CHECK (unique_blob_bytes >= 0),
    retained_shared_blob_count INTEGER NOT NULL CHECK (retained_shared_blob_count >= 0)
) STRICT;

CREATE TABLE deletion_plan_entries (
    snapshot_token TEXT NOT NULL REFERENCES deletion_plans(snapshot_token) ON DELETE RESTRICT,
    epoch TEXT NOT NULL,
    entity_kind TEXT NOT NULL CHECK (length(entity_kind) BETWEEN 1 AND 64),
    key_json TEXT NOT NULL CHECK (json_valid(key_json) AND json_type(key_json) = 'array' AND length(key_json) <= 1024),
    delete_rank INTEGER NOT NULL CHECK (delete_rank BETWEEN 1 AND 1000),
    PRIMARY KEY(snapshot_token, entity_kind, key_json),
    FOREIGN KEY(snapshot_token, epoch) REFERENCES deletion_plans(snapshot_token, epoch) ON DELETE RESTRICT
) STRICT;
CREATE UNIQUE INDEX deletion_plans_token_epoch_idx ON deletion_plans(snapshot_token, epoch);
CREATE INDEX deletion_plan_entries_order_idx
    ON deletion_plan_entries(snapshot_token, delete_rank, entity_kind, key_json);

CREATE TABLE deletion_plan_backup_retention (
    snapshot_token TEXT NOT NULL REFERENCES deletion_plans(snapshot_token) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 999),
    backup_id TEXT NOT NULL CHECK (length(backup_id) = 36),
    reason TEXT NOT NULL CHECK (reason IN ('manual', 'scheduled', 'pre_upgrade', 'pre_restore')),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms >= 0),
    PRIMARY KEY(snapshot_token, ordinal),
    UNIQUE(snapshot_token, backup_id)
) STRICT;

CREATE TABLE deletion_plan_remote_retention (
    snapshot_token TEXT NOT NULL REFERENCES deletion_plans(snapshot_token) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 999),
    provider TEXT NOT NULL CHECK (length(provider) BETWEEN 1 AND 64),
    purpose TEXT NOT NULL CHECK (length(purpose) BETWEEN 1 AND 64),
    retention_mode TEXT NOT NULL CHECK (length(retention_mode) BETWEEN 1 AND 64),
    retention_provenance TEXT NOT NULL CHECK (length(retention_provenance) BETWEEN 1 AND 128),
    dispatched_at_ms INTEGER NOT NULL CHECK (dispatched_at_ms >= 0),
    policy_expires_at_ms INTEGER CHECK (policy_expires_at_ms IS NULL OR policy_expires_at_ms >= dispatched_at_ms),
    status TEXT NOT NULL CHECK (status = 'provider_deletion_unavailable'),
    PRIMARY KEY(snapshot_token, ordinal)
) STRICT;

CREATE TABLE deletion_runs (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) = 36),
    epoch TEXT NOT NULL,
    snapshot_token TEXT,
    request_id TEXT NOT NULL,
    request_json TEXT NOT NULL CHECK (json_valid(request_json) AND length(request_json) <= 4096),
    envelope_hash TEXT NOT NULL CHECK (length(envelope_hash) = 64 AND envelope_hash NOT GLOB '*[^0-9a-f]*'),
    plan_sha256 TEXT NOT NULL CHECK (length(plan_sha256) = 64 AND plan_sha256 NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL CHECK (state IN ('in_progress', 'needs_attention', 'complete')),
    accepted_at_ms INTEGER NOT NULL CHECK (accepted_at_ms >= 0),
    deadline_at_ms INTEGER NOT NULL CHECK (deadline_at_ms > accepted_at_ms),
    completed_at_ms INTEGER,
    deleted_record_count INTEGER NOT NULL DEFAULT 0 CHECK (deleted_record_count >= 0),
    deleted_blob_count INTEGER NOT NULL DEFAULT 0 CHECK (deleted_blob_count >= 0),
    deleted_blob_bytes INTEGER NOT NULL DEFAULT 0 CHECK (deleted_blob_bytes >= 0),
    retained_shared_blob_count INTEGER NOT NULL DEFAULT 0 CHECK (retained_shared_blob_count >= 0),
    UNIQUE(epoch, request_id),
    FOREIGN KEY(snapshot_token, epoch) REFERENCES deletion_plans(snapshot_token, epoch) ON DELETE RESTRICT,
    CHECK (
        (state = 'complete') = (completed_at_ms IS NOT NULL)
        AND (state = 'complete') = (snapshot_token IS NULL)
    )
) STRICT;

CREATE TABLE deletion_run_blobs (
    run_id TEXT NOT NULL REFERENCES deletion_runs(run_id) ON DELETE RESTRICT,
    epoch TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    PRIMARY KEY(run_id, sha256)
) STRICT;

CREATE TABLE deletion_run_backup_retention (
    run_id TEXT NOT NULL REFERENCES deletion_runs(run_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL,
    backup_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    PRIMARY KEY(run_id, ordinal)
) STRICT;

CREATE TABLE deletion_run_remote_retention (
    run_id TEXT NOT NULL REFERENCES deletion_runs(run_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL,
    provider TEXT NOT NULL,
    purpose TEXT NOT NULL,
    retention_mode TEXT NOT NULL,
    retention_provenance TEXT NOT NULL,
    dispatched_at_ms INTEGER NOT NULL,
    policy_expires_at_ms INTEGER,
    status TEXT NOT NULL CHECK (status = 'provider_deletion_unavailable'),
    PRIMARY KEY(run_id, ordinal)
) STRICT;

CREATE TABLE deletion_execution_receipts (
    epoch TEXT NOT NULL,
    request_id TEXT NOT NULL,
    envelope_hash TEXT NOT NULL CHECK (length(envelope_hash) = 64),
    run_id TEXT NOT NULL UNIQUE REFERENCES deletion_runs(run_id) ON DELETE RESTRICT,
    response_json TEXT NOT NULL CHECK (json_valid(response_json)),
    completed_at_ms INTEGER NOT NULL,
    PRIMARY KEY(epoch, request_id)
) STRICT;

CREATE TABLE deletion_execution_authority (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    epoch TEXT NOT NULL,
    run_id TEXT NOT NULL UNIQUE REFERENCES deletion_runs(run_id) ON DELETE RESTRICT,
    snapshot_token TEXT NOT NULL,
    FOREIGN KEY(snapshot_token, epoch) REFERENCES deletion_plans(snapshot_token, epoch) ON DELETE RESTRICT
) STRICT;

CREATE TABLE domain_mutation_authority (
    entity_kind TEXT NOT NULL CHECK (
        entity_kind IN ('item_evidence', 'gmail_operation_cleanup')
    ),
    key_json TEXT NOT NULL CHECK (
        json_valid(key_json)
        AND json_type(key_json) = 'array'
        AND length(key_json) <= 1024
    ),
    PRIMARY KEY(entity_kind, key_json)
) STRICT;

CREATE TRIGGER deletion_plans_no_update BEFORE UPDATE ON deletion_plans
BEGIN SELECT RAISE(ABORT, 'deletion plans are immutable'); END;
CREATE TRIGGER deletion_plan_entries_no_update BEFORE UPDATE ON deletion_plan_entries
BEGIN SELECT RAISE(ABORT, 'deletion plans are immutable'); END;
CREATE TRIGGER deletion_plan_backup_no_update BEFORE UPDATE ON deletion_plan_backup_retention
BEGIN SELECT RAISE(ABORT, 'deletion plans are immutable'); END;
CREATE TRIGGER deletion_plan_remote_no_update BEFORE UPDATE ON deletion_plan_remote_retention
BEGIN SELECT RAISE(ABORT, 'deletion plans are immutable'); END;
CREATE TRIGGER deletion_authority_no_update BEFORE UPDATE ON deletion_execution_authority
BEGIN SELECT RAISE(ABORT, 'deletion authority is immutable'); END;
CREATE TRIGGER deletion_receipts_no_update BEFORE UPDATE ON deletion_execution_receipts
BEGIN SELECT RAISE(ABORT, 'deletion receipts are immutable'); END;
CREATE TRIGGER deletion_receipts_no_delete BEFORE DELETE ON deletion_execution_receipts
BEGIN SELECT RAISE(ABORT, 'deletion receipts are immutable'); END;

DROP TRIGGER catalog_decisions_no_delete;
DROP TRIGGER receipt_parses_no_delete;
DROP TRIGGER receipt_fragments_no_delete;
DROP TRIGGER receipt_runs_no_delete;
DROP TRIGGER receipt_orders_no_delete;
DROP TRIGGER receipt_order_lines_no_delete;
DROP TRIGGER receipt_variants_no_delete;
DROP TRIGGER receipt_fields_no_delete;
DROP TRIGGER receipt_citations_no_delete;
DROP TRIGGER receipt_review_decisions_no_delete;
DROP TRIGGER receipt_image_candidates_no_delete;
DROP TRIGGER receipt_image_candidate_overflow_no_delete;
DROP TRIGGER receipt_image_approvals_no_delete;
DROP TRIGGER receipt_image_attempts_no_delete;
DROP TRIGGER receipt_image_attempt_outcomes_no_delete;
DROP TRIGGER receipt_image_hops_no_delete;
DROP TRIGGER receipt_image_materialization_intents_no_delete;
DROP TRIGGER receipt_remote_images_no_delete;
DROP TRIGGER photo_scopes_no_delete;
DROP TRIGGER photo_source_revisions_no_delete;
DROP TRIGGER photo_scope_members_no_delete;
DROP TRIGGER photo_analysis_runs_no_delete;
DROP TRIGGER photo_analysis_claims_no_delete;
DROP TRIGGER photo_segmentation_attempts_no_delete;
DROP TRIGGER photo_segmentation_outcomes_no_delete;
DROP TRIGGER photo_artifacts_no_delete;
DROP TRIGGER photo_artifact_parents_no_delete;
DROP TRIGGER photo_observations_no_delete;
DROP TRIGGER photo_review_decisions_no_delete;
DROP TRIGGER photo_review_heads_no_delete;
DROP TRIGGER photo_command_entities_no_delete;
DROP TRIGGER reconciliation_cases_no_delete;
DROP TRIGGER reconciliation_candidates_no_delete;
DROP TRIGGER reconciliation_candidate_evidence_no_delete;
DROP TRIGGER reconciliation_evidence_hashes_no_delete;
DROP TRIGGER reconciliation_decisions_no_delete;
DROP TRIGGER reconciliation_decision_heads_no_delete;
DROP TRIGGER reconciliation_command_entities_no_delete;
DROP TRIGGER gmail_revisions_no_delete;
DROP TRIGGER gmail_materializations_no_delete;
DROP TRIGGER gmail_local_sources_no_delete;
DROP TRIGGER gmail_provenance_no_delete;
DROP TRIGGER gmail_mime_no_delete;
DROP TRIGGER gmail_evidence_no_delete;
DROP TRIGGER outfit_recommendation_approvals_no_delete;
DROP TRIGGER outfit_recommendation_attempts_no_delete;

-- Every domain delete is denied unless the active run contains this exact old key.
CREATE TRIGGER hd_import_roots BEFORE DELETE ON import_roots BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='import_roots' AND p.key_json=json_array(OLD.root_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_import_scans BEFORE DELETE ON import_scans BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='import_scans' AND p.key_json=json_array(OLD.scan_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_local_sources BEFORE DELETE ON local_sources BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='local_sources' AND p.key_json=json_array(OLD.source_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_source_provenance BEFORE DELETE ON source_provenance BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='source_provenance' AND p.key_json=json_array(OLD.provenance_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_quarantine_records BEFORE DELETE ON quarantine_records BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='quarantine_records' AND p.key_json=json_array(OLD.quarantine_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_mime_parts BEFORE DELETE ON mime_parts BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='mime_parts' AND p.key_json=json_array(OLD.part_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_evidence BEFORE DELETE ON evidence BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='evidence' AND p.key_json=json_array(OLD.evidence_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_catalog_items BEFORE DELETE ON catalog_items BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='catalog_items' AND p.key_json=json_array(OLD.item_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_item_evidence BEFORE DELETE ON item_evidence BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='item_evidence' AND p.key_json=json_array(OLD.item_id,OLD.evidence_id)) AND NOT EXISTS (SELECT 1 FROM domain_mutation_authority a WHERE a.entity_kind='item_evidence' AND a.key_json=json_array(OLD.item_id,OLD.evidence_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_catalog_decisions BEFORE DELETE ON catalog_decisions BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='catalog_decisions' AND p.key_json=json_array(OLD.decision_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_decision_entities BEFORE DELETE ON decision_entities BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='decision_entities' AND p.key_json=json_array(OLD.decision_id,OLD.entity_kind,OLD.entity_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_derivatives BEFORE DELETE ON derivatives BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='derivatives' AND p.key_json=json_array(OLD.derivative_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_remote_references BEFORE DELETE ON remote_references BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='remote_references' AND p.key_json=json_array(OLD.remote_reference_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_storage_checks BEFORE DELETE ON storage_checks BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='storage_checks' AND p.key_json=json_array(OLD.check_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_jobs BEFORE DELETE ON jobs BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='jobs' AND p.key_json=json_array(OLD.job_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_job_dependencies BEFORE DELETE ON job_dependencies BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='job_dependencies' AND p.key_json=json_array(OLD.job_id,OLD.depends_on_job_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_job_results BEFORE DELETE ON job_results BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='job_results' AND p.key_json=json_array(OLD.job_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_job_failures BEFORE DELETE ON job_failures BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='job_failures' AND p.key_json=json_array(OLD.job_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_provenance BEFORE DELETE ON provenance BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='provenance' AND p.key_json=json_array(OLD.provenance_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_command_receipts BEFORE DELETE ON command_receipts BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='command_receipts' AND p.key_json=json_array(OLD.request_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_parses BEFORE DELETE ON receipt_parses BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_parses' AND p.key_json=json_array(OLD.parse_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_fragments BEFORE DELETE ON receipt_fragments BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_fragments' AND p.key_json=json_array(OLD.fragment_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_extraction_runs BEFORE DELETE ON receipt_extraction_runs BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_extraction_runs' AND p.key_json=json_array(OLD.run_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_orders BEFORE DELETE ON receipt_orders BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_orders' AND p.key_json=json_array(OLD.order_evidence_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_order_lines BEFORE DELETE ON receipt_order_lines BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_order_lines' AND p.key_json=json_array(OLD.order_line_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_variant_evidence BEFORE DELETE ON receipt_variant_evidence BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_variant_evidence' AND p.key_json=json_array(OLD.variant_evidence_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_fields BEFORE DELETE ON receipt_fields BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_fields' AND p.key_json=json_array(OLD.field_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_field_citations BEFORE DELETE ON receipt_field_citations BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_field_citations' AND p.key_json=json_array(OLD.citation_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_review_decisions BEFORE DELETE ON receipt_review_decisions BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_review_decisions' AND p.key_json=json_array(OLD.review_decision_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_review_heads BEFORE DELETE ON receipt_review_heads BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_review_heads' AND p.key_json=json_array(OLD.order_evidence_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_command_entities BEFORE DELETE ON receipt_command_entities BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_command_entities' AND p.key_json=json_array(OLD.request_id,OLD.entity_kind,OLD.entity_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_image_candidates BEFORE DELETE ON receipt_image_candidates BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_image_candidates' AND p.key_json=json_array(OLD.candidate_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_image_candidate_overflow BEFORE DELETE ON receipt_image_candidate_overflow BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_image_candidate_overflow' AND p.key_json=json_array(OLD.parse_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_image_approvals BEFORE DELETE ON receipt_image_approvals BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_image_approvals' AND p.key_json=json_array(OLD.approval_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_image_attempts BEFORE DELETE ON receipt_image_attempts BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_image_attempts' AND p.key_json=json_array(OLD.attempt_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_image_attempt_outcomes BEFORE DELETE ON receipt_image_attempt_outcomes BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_image_attempt_outcomes' AND p.key_json=json_array(OLD.attempt_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_image_hops BEFORE DELETE ON receipt_image_hops BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_image_hops' AND p.key_json=json_array(OLD.attempt_id,OLD.hop_ordinal)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_image_materialization_intents BEFORE DELETE ON receipt_image_materialization_intents BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_image_materialization_intents' AND p.key_json=json_array(OLD.intent_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_receipt_remote_images BEFORE DELETE ON receipt_remote_images BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='receipt_remote_images' AND p.key_json=json_array(OLD.image_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_scopes BEFORE DELETE ON photo_scopes BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_scopes' AND p.key_json=json_array(OLD.scope_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_scope_members BEFORE DELETE ON photo_scope_members BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_scope_members' AND p.key_json=json_array(OLD.scope_id,OLD.member_ordinal)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_source_revisions BEFORE DELETE ON photo_source_revisions BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_source_revisions' AND p.key_json=json_array(OLD.source_revision_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_analysis_runs BEFORE DELETE ON photo_analysis_runs BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_analysis_runs' AND p.key_json=json_array(OLD.run_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_analysis_member_claims BEFORE DELETE ON photo_analysis_member_claims BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_analysis_member_claims' AND p.key_json=json_array(OLD.run_id,OLD.member_ordinal)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_segmentation_attempts BEFORE DELETE ON photo_segmentation_attempts BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_segmentation_attempts' AND p.key_json=json_array(OLD.attempt_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_segmentation_outcomes BEFORE DELETE ON photo_segmentation_outcomes BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_segmentation_outcomes' AND p.key_json=json_array(OLD.attempt_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_artifacts BEFORE DELETE ON photo_artifacts BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_artifacts' AND p.key_json=json_array(OLD.artifact_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_artifact_parents BEFORE DELETE ON photo_artifact_parents BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_artifact_parents' AND p.key_json=json_array(OLD.artifact_id,OLD.parent_ordinal)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_observations BEFORE DELETE ON photo_observations BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_observations' AND p.key_json=json_array(OLD.observation_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_review_decisions BEFORE DELETE ON photo_review_decisions BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_review_decisions' AND p.key_json=json_array(OLD.decision_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_review_heads BEFORE DELETE ON photo_review_heads BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_review_heads' AND p.key_json=json_array(OLD.observation_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_photo_command_entities BEFORE DELETE ON photo_command_entities BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='photo_command_entities' AND p.key_json=json_array(OLD.request_id,OLD.entity_kind,OLD.entity_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_reconciliation_cases BEFORE DELETE ON reconciliation_cases BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='reconciliation_cases' AND p.key_json=json_array(OLD.case_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_reconciliation_candidates BEFORE DELETE ON reconciliation_candidates BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='reconciliation_candidates' AND p.key_json=json_array(OLD.candidate_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_reconciliation_candidate_evidence BEFORE DELETE ON reconciliation_candidate_evidence BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='reconciliation_candidate_evidence' AND p.key_json=json_array(OLD.evidence_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_reconciliation_evidence_input_hashes BEFORE DELETE ON reconciliation_evidence_input_hashes BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='reconciliation_evidence_input_hashes' AND p.key_json=json_array(OLD.evidence_id,OLD.input_ordinal)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_reconciliation_decisions BEFORE DELETE ON reconciliation_decisions BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='reconciliation_decisions' AND p.key_json=json_array(OLD.decision_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_reconciliation_decision_heads BEFORE DELETE ON reconciliation_decision_heads BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='reconciliation_decision_heads' AND p.key_json=json_array(OLD.case_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_reconciliation_command_entities BEFORE DELETE ON reconciliation_command_entities BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='reconciliation_command_entities' AND p.key_json=json_array(OLD.request_id,OLD.entity_kind,OLD.entity_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_gmail_provider_sources BEFORE DELETE ON gmail_provider_sources BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='gmail_provider_sources' AND p.key_json=json_array(OLD.provider_source_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_gmail_source_revisions BEFORE DELETE ON gmail_source_revisions BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='gmail_source_revisions' AND p.key_json=json_array(OLD.revision_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_gmail_source_heads BEFORE DELETE ON gmail_source_heads BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='gmail_source_heads' AND p.key_json=json_array(OLD.provider_source_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_gmail_revision_materializations BEFORE DELETE ON gmail_revision_materializations BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='gmail_revision_materializations' AND p.key_json=json_array(OLD.revision_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_gmail_scope_sources BEFORE DELETE ON gmail_scope_sources BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='gmail_scope_sources' AND p.key_json=json_array(OLD.scope_id,OLD.provider_source_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_gmail_operations BEFORE DELETE ON gmail_operations BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='gmail_operations' AND p.key_json=json_array(OLD.request_id)) AND NOT EXISTS (SELECT 1 FROM domain_mutation_authority a WHERE a.entity_kind='gmail_operation_cleanup' AND a.key_json=json_array(OLD.request_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_gmail_operation_revisions BEFORE DELETE ON gmail_operation_revisions BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='gmail_operation_revisions' AND p.key_json=json_array(OLD.request_id,OLD.revision_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_outfits BEFORE DELETE ON outfits BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='outfits' AND p.key_json=json_array(OLD.outfit_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_outfit_members BEFORE DELETE ON outfit_members BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='outfit_members' AND p.key_json=json_array(OLD.outfit_id,OLD.ordinal)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_outfit_recommendation_approvals BEFORE DELETE ON outfit_recommendation_approvals BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='outfit_recommendation_approvals' AND p.key_json=json_array(OLD.approval_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_outfit_recommendation_attempts BEFORE DELETE ON outfit_recommendation_attempts BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='outfit_recommendation_attempts' AND p.key_json=json_array(OLD.attempt_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_outfit_recommendation_proposals BEFORE DELETE ON outfit_recommendation_proposals BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='outfit_recommendation_proposals' AND p.key_json=json_array(OLD.attempt_id,OLD.ordinal)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_outfit_recommendation_members BEFORE DELETE ON outfit_recommendation_members BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='outfit_recommendation_members' AND p.key_json=json_array(OLD.attempt_id,OLD.proposal_ordinal,OLD.member_ordinal)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_try_on_approvals BEFORE DELETE ON try_on_approvals BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='try_on_approvals' AND p.key_json=json_array(OLD.approval_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_try_on_assets BEFORE DELETE ON try_on_assets BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='try_on_assets' AND p.key_json=json_array(OLD.approval_id,OLD.asset_ordinal)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_try_on_jobs BEFORE DELETE ON try_on_jobs BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='try_on_jobs' AND p.key_json=json_array(OLD.job_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_try_on_attempts BEFORE DELETE ON try_on_attempts BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='try_on_attempts' AND p.key_json=json_array(OLD.attempt_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_try_on_outputs BEFORE DELETE ON try_on_outputs BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='try_on_outputs' AND p.key_json=json_array(OLD.output_id)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
CREATE TRIGGER hd_blobs BEFORE DELETE ON blobs BEGIN SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM deletion_execution_authority a JOIN deletion_plan_entries p ON p.snapshot_token=a.snapshot_token AND p.epoch=a.epoch WHERE p.entity_kind='blobs' AND p.key_json=json_array(OLD.sha256)) THEN RAISE(ABORT,'hard deletion authority required') END; END;
