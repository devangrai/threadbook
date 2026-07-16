ALTER TABLE gmail_disconnect_stages
RENAME TO gmail_disconnect_stages_v12;

CREATE TABLE gmail_disconnect_stages (
    request_id TEXT PRIMARY KEY
        REFERENCES gmail_operations(request_id) ON DELETE RESTRICT,
    account_key TEXT NOT NULL
        REFERENCES gmail_accounts(account_key) ON DELETE RESTRICT,
    credential_locator TEXT NOT NULL,
    revocation_result TEXT CHECK (
        revocation_result IS NULL
        OR revocation_result IN (
            'succeeded',
            'already_invalid',
            'failed',
            'not_attempted_local_only'
        )
    ),
    credential_deleted INTEGER NOT NULL DEFAULT 0 CHECK (
        credential_deleted IN (0, 1)
    ),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
) STRICT;

INSERT INTO gmail_disconnect_stages(
    request_id,
    account_key,
    credential_locator,
    revocation_result,
    credential_deleted,
    updated_at_ms
)
SELECT
    request_id,
    account_key,
    credential_locator,
    revocation_result,
    credential_deleted,
    updated_at_ms
FROM gmail_disconnect_stages_v12;

DROP TABLE gmail_disconnect_stages_v12;
