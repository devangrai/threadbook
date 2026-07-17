PRAGMA legacy_alter_table = ON;

-- Extend evidence without retargeting populated dependent foreign keys.
ALTER TABLE evidence RENAME TO p12_evidence_v16;
CREATE TABLE evidence (
    evidence_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    part_id TEXT REFERENCES mime_parts(part_id) ON DELETE RESTRICT,
    evidence_kind TEXT NOT NULL CHECK (
        evidence_kind IN (
            'image', 'message_attachment', 'receipt_order_line',
            'receipt_purchase_unit'
        )
    ),
    state TEXT NOT NULL CHECK (
        state IN ('unresolved', 'assigned', 'rejected', 'deferred')
    ),
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    UNIQUE(source_id, part_id, evidence_kind)
) STRICT;
INSERT INTO evidence(
    evidence_id, source_id, part_id, evidence_kind, state,
    created_at_ms, updated_at_ms
)
SELECT
    evidence_id, source_id, part_id, evidence_kind, state,
    created_at_ms, updated_at_ms
FROM p12_evidence_v16;
DROP TABLE p12_evidence_v16;
CREATE INDEX evidence_state_idx
    ON evidence(state, created_at_ms, evidence_id);
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
CREATE TRIGGER hd_evidence
BEFORE DELETE ON evidence
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'evidence'
          AND planned.key_json = json_array(OLD.evidence_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

-- Promotion is an explicit irreversible catalog decision.
ALTER TABLE catalog_decisions RENAME TO p12_catalog_decisions_v16;
CREATE TABLE catalog_decisions (
    decision_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    decision_kind TEXT NOT NULL CHECK (
        decision_kind IN (
            'save', 'assign', 'reject', 'defer', 'merge', 'split', 'undo',
            'promote_receipt_purchase_unit'
        )
    ),
    catalog_revision INTEGER NOT NULL UNIQUE CHECK (catalog_revision > 0),
    forward_json TEXT NOT NULL CHECK (json_valid(forward_json)),
    inverse_json TEXT NOT NULL CHECK (json_valid(inverse_json)),
    compensates_decision_id TEXT
        REFERENCES catalog_decisions(decision_id) ON DELETE RESTRICT,
    created_at_ms INTEGER NOT NULL
) STRICT;
INSERT INTO catalog_decisions(
    decision_id, request_id, decision_kind, catalog_revision,
    forward_json, inverse_json, compensates_decision_id, created_at_ms
)
SELECT
    decision_id, request_id, decision_kind, catalog_revision,
    forward_json, inverse_json, compensates_decision_id, created_at_ms
FROM p12_catalog_decisions_v16
ORDER BY catalog_revision;
DROP TABLE p12_catalog_decisions_v16;
CREATE TRIGGER catalog_decisions_no_update
BEFORE UPDATE ON catalog_decisions
BEGIN
    SELECT RAISE(ABORT, 'catalog_decisions are append-only');
END;
CREATE TRIGGER hd_catalog_decisions
BEFORE DELETE ON catalog_decisions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'catalog_decisions'
          AND planned.key_json = json_array(OLD.decision_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

-- Both preview and durable plan targets are closed domains.
ALTER TABLE deletion_preview_items
RENAME TO p12_deletion_preview_items_v16;
ALTER TABLE deletion_previews RENAME TO p12_deletion_previews_v16;
CREATE TABLE deletion_previews (
    snapshot_token TEXT PRIMARY KEY,
    target_kind TEXT NOT NULL CHECK (
        target_kind IN (
            'import_root', 'source', 'item',
            'photokit_enrollment', 'photokit_asset',
            'purchase_unit', 'receipt_purchase_unit_evidence'
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
CREATE TABLE deletion_preview_items (
    snapshot_token TEXT NOT NULL
        REFERENCES deletion_previews(snapshot_token) ON DELETE RESTRICT,
    dependency_class TEXT NOT NULL CHECK (
        dependency_class IN (
            'originals', 'derivatives', 'source_records', 'evidence_records',
            'decision_records', 'remote_references', 'retained_shared_blobs',
            'retained_shared_records'
        )
    ),
    entity_id TEXT NOT NULL,
    sort_key TEXT NOT NULL,
    PRIMARY KEY(snapshot_token, dependency_class, entity_id)
) STRICT;
INSERT INTO deletion_previews
SELECT * FROM p12_deletion_previews_v16;
INSERT INTO deletion_preview_items
SELECT * FROM p12_deletion_preview_items_v16;
DROP TABLE p12_deletion_preview_items_v16;
DROP TABLE p12_deletion_previews_v16;
CREATE INDEX deletion_preview_page_idx
    ON deletion_preview_items(
        snapshot_token, dependency_class, sort_key, entity_id
    );

ALTER TABLE deletion_plans RENAME TO p12_deletion_plans_v16;
CREATE TABLE deletion_plans (
    snapshot_token TEXT PRIMARY KEY,
    epoch TEXT NOT NULL
        REFERENCES store_authority_epoch(epoch) ON DELETE RESTRICT,
    target_kind TEXT NOT NULL CHECK (
        target_kind IN (
            'import_root', 'source', 'item',
            'photokit_enrollment', 'photokit_asset',
            'purchase_unit', 'receipt_purchase_unit_evidence'
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
    reconciliation_revision INTEGER NOT NULL CHECK (
        reconciliation_revision >= 0
    ),
    outfit_revision INTEGER NOT NULL CHECK (outfit_revision >= 0),
    try_on_revision INTEGER NOT NULL CHECK (try_on_revision >= 0),
    photokit_revision INTEGER NOT NULL DEFAULT 0 CHECK (
        photokit_revision BETWEEN 0 AND 9007199254740990
    ),
    prepared_at_ms INTEGER NOT NULL CHECK (prepared_at_ms >= 0),
    expires_at_ms INTEGER NOT NULL CHECK (expires_at_ms > prepared_at_ms),
    unique_blob_count INTEGER NOT NULL CHECK (unique_blob_count >= 0),
    unique_blob_bytes INTEGER NOT NULL CHECK (unique_blob_bytes >= 0),
    retained_shared_blob_count INTEGER NOT NULL CHECK (
        retained_shared_blob_count >= 0
    )
) STRICT;
INSERT INTO deletion_plans
SELECT * FROM p12_deletion_plans_v16;
DROP TABLE p12_deletion_plans_v16;
CREATE UNIQUE INDEX deletion_plans_token_epoch_idx
    ON deletion_plans(snapshot_token, epoch);
CREATE TRIGGER deletion_plans_no_update
BEFORE UPDATE ON deletion_plans
BEGIN
    SELECT RAISE(ABORT, 'deletion plans are immutable');
END;

ALTER TABLE receipt_command_entities
RENAME TO p12_receipt_command_entities_v16;
CREATE TABLE receipt_command_entities (
    request_id TEXT NOT NULL
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    entity_kind TEXT NOT NULL CHECK (
        entity_kind IN (
            'source', 'parse', 'order', 'review_decision',
            'image_candidate', 'image_approval', 'image_attempt', 'remote_image',
            'purchase_unit', 'authority_snapshot', 'promotion',
            'purchase_unit_deletion'
        )
    ),
    entity_id TEXT NOT NULL,
    PRIMARY KEY(request_id, entity_kind, entity_id)
) STRICT;
INSERT INTO receipt_command_entities
SELECT * FROM p12_receipt_command_entities_v16;
DROP TABLE p12_receipt_command_entities_v16;
CREATE INDEX receipt_command_entities_entity_idx
    ON receipt_command_entities(entity_kind, entity_id, request_id);
CREATE TRIGGER hd_receipt_command_entities
BEFORE DELETE ON receipt_command_entities
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'receipt_command_entities'
          AND planned.key_json = json_array(
              OLD.request_id, OLD.entity_kind, OLD.entity_id
          )
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

CREATE TABLE receipt_authority_snapshots (
    authority_snapshot_id TEXT PRIMARY KEY CHECK (
        length(authority_snapshot_id) = 36
        AND authority_snapshot_id = lower(authority_snapshot_id)
        AND authority_snapshot_id NOT GLOB '*[^0-9a-f-]*'
        AND authority_snapshot_id <> '00000000-0000-0000-0000-000000000000'
    ),
    authority_id TEXT NOT NULL CHECK (
        length(authority_id) = 36
        AND authority_id = lower(authority_id)
        AND authority_id NOT GLOB '*[^0-9a-f-]*'
        AND authority_id <> '00000000-0000-0000-0000-000000000000'
    ),
    local_source_id TEXT NOT NULL
        REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    order_evidence_id TEXT NOT NULL
        REFERENCES receipt_orders(order_evidence_id) ON DELETE RESTRICT,
    order_line_id TEXT NOT NULL
        REFERENCES receipt_order_lines(order_line_id) ON DELETE RESTRICT,
    review_decision_id TEXT NOT NULL
        REFERENCES receipt_review_decisions(review_decision_id) ON DELETE RESTRICT,
    review_action TEXT NOT NULL CHECK (review_action IN ('confirm', 'correct')),
    receipt_revision INTEGER NOT NULL CHECK (
        receipt_revision BETWEEN 1 AND 9007199254740990
    ),
    authority_revision INTEGER NOT NULL CHECK (
        authority_revision BETWEEN 1 AND 9007199254740990
    ),
    values_json TEXT NOT NULL CHECK (
        json_valid(values_json)
        AND json_type(values_json) = 'object'
        AND length(values_json) BETWEEN 2 AND 131072
    ),
    provenance_json TEXT NOT NULL CHECK (
        json_valid(provenance_json)
        AND json_type(provenance_json) = 'object'
        AND length(provenance_json) BETWEEN 2 AND 131072
    ),
    snapshot_sha256 TEXT NOT NULL CHECK (
        length(snapshot_sha256) = 64
        AND snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(
        local_source_id, authority_id, authority_revision, order_line_id
    ),
    UNIQUE(authority_snapshot_id, order_line_id)
) STRICT;

CREATE TABLE receipt_purchase_unit_promotions (
    promotion_id TEXT NOT NULL UNIQUE CHECK (
        length(promotion_id) = 36
        AND promotion_id = lower(promotion_id)
        AND promotion_id NOT GLOB '*[^0-9a-f-]*'
        AND promotion_id <> '00000000-0000-0000-0000-000000000000'
    ),
    purchase_unit_id TEXT NOT NULL UNIQUE CHECK (
        length(purchase_unit_id) = 36
        AND purchase_unit_id = lower(purchase_unit_id)
        AND purchase_unit_id NOT GLOB '*[^0-9a-f-]*'
        AND purchase_unit_id <> '00000000-0000-0000-0000-000000000000'
    ),
    identity_version TEXT NOT NULL CHECK (
        identity_version = 'receipt-purchase-unit-v1'
    ),
    order_line_id TEXT NOT NULL
        REFERENCES receipt_order_lines(order_line_id) ON DELETE RESTRICT,
    unit_ordinal INTEGER NOT NULL CHECK (unit_ordinal BETWEEN 0 AND 9999),
    authoritative_quantity INTEGER NOT NULL CHECK (
        authoritative_quantity BETWEEN 1 AND 10000
    ),
    purchase_unit_revision INTEGER NOT NULL CHECK (
        purchase_unit_revision BETWEEN 1 AND 9007199254740990
    ),
    unit_snapshot_sha256 TEXT NOT NULL CHECK (
        length(unit_snapshot_sha256) = 64
        AND unit_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    authority_snapshot_id TEXT NOT NULL
        REFERENCES receipt_authority_snapshots(authority_snapshot_id)
        ON DELETE RESTRICT,
    item_id TEXT NOT NULL UNIQUE
        REFERENCES catalog_items(item_id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL UNIQUE
        REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    decision_id TEXT NOT NULL UNIQUE
        REFERENCES catalog_decisions(decision_id) ON DELETE RESTRICT,
    request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT,
    catalog_revision INTEGER NOT NULL UNIQUE CHECK (
        catalog_revision BETWEEN 1 AND 9007199254740990
    ),
    evidence_generation INTEGER NOT NULL CHECK (
        evidence_generation BETWEEN 1 AND 9007199254740990
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    PRIMARY KEY(order_line_id, unit_ordinal),
    FOREIGN KEY(authority_snapshot_id, order_line_id)
        REFERENCES receipt_authority_snapshots(
            authority_snapshot_id, order_line_id
        ) ON DELETE RESTRICT,
    CHECK (unit_ordinal < authoritative_quantity)
) STRICT;

CREATE TABLE receipt_purchase_unit_deletions (
    purchase_unit_id TEXT PRIMARY KEY CHECK (
        length(purchase_unit_id) = 36
        AND purchase_unit_id = lower(purchase_unit_id)
        AND purchase_unit_id NOT GLOB '*[^0-9a-f-]*'
        AND purchase_unit_id <> '00000000-0000-0000-0000-000000000000'
    ),
    identity_version TEXT NOT NULL CHECK (
        identity_version = 'receipt-purchase-unit-v1'
    ),
    local_source_id TEXT NOT NULL
        REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    authority_id TEXT NOT NULL CHECK (
        length(authority_id) = 36
        AND authority_id = lower(authority_id)
        AND authority_id NOT GLOB '*[^0-9a-f-]*'
        AND authority_id <> '00000000-0000-0000-0000-000000000000'
    ),
    authority_revision INTEGER NOT NULL CHECK (
        authority_revision BETWEEN 1 AND 9007199254740990
    ),
    order_evidence_id TEXT NOT NULL
        REFERENCES receipt_orders(order_evidence_id) ON DELETE RESTRICT,
    order_line_id TEXT NOT NULL
        REFERENCES receipt_order_lines(order_line_id) ON DELETE RESTRICT,
    unit_ordinal INTEGER NOT NULL CHECK (unit_ordinal BETWEEN 0 AND 9999),
    deletion_request_id TEXT NOT NULL UNIQUE CHECK (
        length(deletion_request_id) = 36
        AND deletion_request_id = lower(deletion_request_id)
        AND deletion_request_id NOT GLOB '*[^0-9a-f-]*'
        AND deletion_request_id <> '00000000-0000-0000-0000-000000000000'
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0),
    UNIQUE(order_line_id, unit_ordinal)
) STRICT;

CREATE INDEX receipt_authority_snapshots_source_idx
    ON receipt_authority_snapshots(
        local_source_id, authority_revision DESC, authority_snapshot_id
    );
CREATE INDEX receipt_authority_snapshots_order_idx
    ON receipt_authority_snapshots(
        order_evidence_id, order_line_id, authority_snapshot_id
    );
CREATE INDEX receipt_purchase_unit_promotions_snapshot_idx
    ON receipt_purchase_unit_promotions(
        authority_snapshot_id, order_line_id, unit_ordinal
    );
CREATE INDEX receipt_purchase_unit_deletions_source_idx
    ON receipt_purchase_unit_deletions(
        local_source_id, authority_id, authority_revision,
        order_line_id, unit_ordinal
    );

CREATE TRIGGER receipt_authority_snapshots_validate_insert
BEFORE INSERT ON receipt_authority_snapshots
WHEN NOT EXISTS (
    SELECT 1
    FROM receipt_review_decisions decision
    JOIN receipt_orders receipt_order
      ON receipt_order.order_evidence_id = decision.order_evidence_id
    JOIN receipt_order_lines receipt_line
      ON receipt_line.order_evidence_id = receipt_order.order_evidence_id
    JOIN receipt_extraction_runs run ON run.run_id = receipt_order.run_id
    JOIN receipt_parses parse ON parse.parse_id = run.parse_id
    WHERE decision.review_decision_id = NEW.review_decision_id
      AND decision.order_evidence_id = NEW.order_evidence_id
      AND receipt_line.order_line_id = NEW.order_line_id
      AND decision.action = NEW.review_action
      AND decision.receipt_revision = NEW.receipt_revision
      AND parse.source_id = NEW.local_source_id
)
BEGIN
    SELECT RAISE(ABORT, 'invalid receipt authority snapshot');
END;
CREATE TRIGGER receipt_authority_snapshots_no_update
BEFORE UPDATE ON receipt_authority_snapshots
BEGIN
    SELECT RAISE(ABORT, 'receipt authority snapshots are immutable');
END;

CREATE TRIGGER receipt_purchase_unit_promotions_validate_insert
BEFORE INSERT ON receipt_purchase_unit_promotions
WHEN NOT EXISTS (
    SELECT 1
    FROM receipt_authority_snapshots snapshot
    JOIN receipt_order_lines receipt_line
      ON receipt_line.order_evidence_id = snapshot.order_evidence_id
    JOIN evidence unit_evidence
      ON unit_evidence.evidence_id = NEW.evidence_id
    JOIN catalog_decisions decision
      ON decision.decision_id = NEW.decision_id
    JOIN command_receipts receipt ON receipt.request_id = NEW.request_id
    WHERE snapshot.authority_snapshot_id = NEW.authority_snapshot_id
      AND receipt_line.order_line_id = NEW.order_line_id
      AND unit_evidence.source_id = snapshot.local_source_id
      AND unit_evidence.part_id IS NULL
      AND unit_evidence.evidence_kind = 'receipt_purchase_unit'
      AND unit_evidence.state = 'assigned'
      AND decision.request_id = NEW.request_id
      AND decision.decision_kind = 'promote_receipt_purchase_unit'
      AND decision.catalog_revision = NEW.catalog_revision
      AND receipt.command_name = 'promote_receipt_purchase_unit_v1'
)
BEGIN
    SELECT RAISE(ABORT, 'invalid receipt purchase unit promotion');
END;
CREATE TRIGGER receipt_purchase_unit_promotions_no_update
BEFORE UPDATE ON receipt_purchase_unit_promotions
BEGIN
    SELECT RAISE(ABORT, 'receipt purchase unit promotions are immutable');
END;

CREATE TRIGGER receipt_purchase_unit_deletions_validate_insert
BEFORE INSERT ON receipt_purchase_unit_deletions
WHEN NOT EXISTS (
    SELECT 1
    FROM receipt_order_lines receipt_line
    JOIN receipt_orders receipt_order
      ON receipt_order.order_evidence_id = receipt_line.order_evidence_id
    JOIN receipt_extraction_runs run ON run.run_id = receipt_order.run_id
    JOIN receipt_parses parse ON parse.parse_id = run.parse_id
    WHERE receipt_line.order_line_id = NEW.order_line_id
      AND receipt_line.order_evidence_id = NEW.order_evidence_id
      AND parse.source_id = NEW.local_source_id
)
BEGIN
    SELECT RAISE(ABORT, 'invalid receipt purchase unit deletion');
END;
CREATE TRIGGER receipt_purchase_unit_deletions_no_update
BEFORE UPDATE ON receipt_purchase_unit_deletions
BEGIN
    SELECT RAISE(ABORT, 'receipt purchase unit deletions are immutable');
END;

CREATE TRIGGER hd_receipt_authority_snapshots
BEFORE DELETE ON receipt_authority_snapshots
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'receipt_authority_snapshots'
          AND planned.key_json = json_array(OLD.authority_snapshot_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_receipt_purchase_unit_promotions
BEFORE DELETE ON receipt_purchase_unit_promotions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'receipt_purchase_unit_promotions'
          AND planned.key_json = json_array(
              OLD.order_line_id, OLD.unit_ordinal
          )
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;
CREATE TRIGGER hd_receipt_purchase_unit_deletions
BEFORE DELETE ON receipt_purchase_unit_deletions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM deletion_execution_authority authority
        JOIN deletion_plan_entries planned
          ON planned.snapshot_token = authority.snapshot_token
         AND planned.epoch = authority.epoch
        WHERE planned.entity_kind = 'receipt_purchase_unit_deletions'
          AND planned.key_json = json_array(OLD.purchase_unit_id)
    ) THEN RAISE(ABORT, 'hard deletion authority required') END;
END;

PRAGMA legacy_alter_table = OFF;
