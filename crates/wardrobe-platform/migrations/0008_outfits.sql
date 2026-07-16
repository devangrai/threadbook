ALTER TABLE revision_state
ADD COLUMN outfit_revision INTEGER NOT NULL DEFAULT 0
CHECK (outfit_revision BETWEEN 0 AND 9007199254740990);

CREATE TABLE outfits (
    outfit_id TEXT PRIMARY KEY CHECK (
        length(outfit_id) = 36
        AND outfit_id <> '00000000-0000-0000-0000-000000000000'
    ),
    request_id TEXT NOT NULL UNIQUE
        REFERENCES command_receipts(request_id) ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    name TEXT NOT NULL CHECK (
        length(name) BETWEEN 1 AND 80
        AND name = trim(name)
        AND name NOT GLOB '*[^ -~]*'
    ),
    created_outfit_revision INTEGER NOT NULL UNIQUE CHECK (
        created_outfit_revision BETWEEN 1 AND 9007199254740990
    ),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
) STRICT;

CREATE TABLE outfit_members (
    outfit_id TEXT NOT NULL REFERENCES outfits(outfit_id) ON DELETE RESTRICT,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 7),
    item_id TEXT NOT NULL REFERENCES catalog_items(item_id) ON DELETE RESTRICT,
    item_updated_revision INTEGER NOT NULL CHECK (
        item_updated_revision BETWEEN 1 AND 9007199254740990
    ),
    attributes_json TEXT NOT NULL CHECK (json_valid(attributes_json)),
    asset_state TEXT NOT NULL CHECK (
        asset_state IN ('available', 'metadata_only')
    ),
    evidence_id TEXT REFERENCES evidence(evidence_id) ON DELETE RESTRICT,
    source_id TEXT REFERENCES local_sources(source_id) ON DELETE RESTRICT,
    blob_sha256 TEXT REFERENCES blobs(sha256) ON DELETE RESTRICT,
    media_type TEXT CHECK (
        media_type IS NULL
        OR media_type IN ('image/jpeg', 'image/png', 'image/webp')
    ),
    byte_length INTEGER CHECK (
        byte_length IS NULL OR byte_length BETWEEN 1 AND 41943040
    ),
    width INTEGER CHECK (width IS NULL OR width BETWEEN 1 AND 16384),
    height INTEGER CHECK (height IS NULL OR height BETWEEN 1 AND 16384),
    PRIMARY KEY(outfit_id, ordinal),
    UNIQUE(outfit_id, item_id),
    CHECK (
        (
            asset_state = 'available'
            AND evidence_id IS NOT NULL
            AND source_id IS NOT NULL
            AND blob_sha256 IS NOT NULL
            AND media_type IS NOT NULL
            AND byte_length IS NOT NULL
            AND width IS NOT NULL
            AND height IS NOT NULL
        )
        OR (
            asset_state = 'metadata_only'
            AND evidence_id IS NULL
            AND source_id IS NULL
            AND blob_sha256 IS NULL
            AND media_type IS NULL
            AND byte_length IS NULL
            AND width IS NULL
            AND height IS NULL
        )
    )
) STRICT;

CREATE INDEX outfit_members_item_idx
    ON outfit_members(item_id, outfit_id, ordinal);
CREATE INDEX outfit_members_source_idx
    ON outfit_members(source_id, outfit_id, ordinal)
    WHERE source_id IS NOT NULL;
CREATE INDEX outfit_members_blob_idx
    ON outfit_members(blob_sha256, outfit_id, ordinal)
    WHERE blob_sha256 IS NOT NULL;

CREATE TRIGGER outfits_no_update
BEFORE UPDATE ON outfits
BEGIN
    SELECT RAISE(ABORT, 'outfits are immutable');
END;

CREATE TRIGGER outfit_members_no_update
BEFORE UPDATE ON outfit_members
BEGIN
    SELECT RAISE(ABORT, 'outfit members are immutable');
END;
