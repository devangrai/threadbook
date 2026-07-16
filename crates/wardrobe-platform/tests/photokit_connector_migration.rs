use rusqlite::{params, Connection};
use serde_json::json;
use wardrobe_platform::{
    Database, PrivateAppPaths, PHOTOKIT_ASSET_TARGET_KIND, PHOTOKIT_ENROLLMENT_TARGET_KIND,
    PHOTOKIT_FINAL_KEY_CLEANUP_TABLE, PHOTOKIT_SCHEMA_TABLES,
};

#[test]
fn v12_photokit_schema_is_strict_restrictive_and_extends_deletion_snapshots() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    Database::open(&paths, 1).unwrap();
    let connection = Connection::open(&paths.database).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();

    assert_eq!(
        connection
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        14
    );
    for table in PHOTOKIT_SCHEMA_TABLES {
        assert_eq!(
            connection
                .query_row(
                    "SELECT strict FROM pragma_table_list WHERE name = ?1",
                    [table],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "{table} must be STRICT"
        );
    }
    assert_eq!(PHOTOKIT_SCHEMA_TABLES.len(), 14);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*)
                 FROM pragma_table_list tables
                 JOIN pragma_foreign_key_list(tables.name) foreign_keys
                 WHERE tables.name LIKE 'photokit_%'
                   AND foreign_keys.on_delete <> 'RESTRICT'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
    for table in [
        "revision_state",
        "deletion_previews",
        "deletion_plans",
        "deletion_runs",
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info(?1)
                     WHERE name = 'photokit_revision'",
                    [table],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1,
            "{table} must pin photokit_revision"
        );
    }

    for (ordinal, target) in [PHOTOKIT_ENROLLMENT_TARGET_KIND, PHOTOKIT_ASSET_TARGET_KIND]
        .into_iter()
        .enumerate()
    {
        connection
            .execute(
                "INSERT INTO deletion_previews(
                    snapshot_token, target_kind, target_id,
                    catalog_revision, evidence_generation, created_at_ms
                 ) VALUES (?1, ?2, ?3, 0, 0, 2)",
                params![
                    format!("photokit-target-{ordinal}"),
                    target,
                    format!("target-{ordinal}")
                ],
            )
            .unwrap();
    }
    assert!(connection
        .execute(
            "INSERT INTO deletion_previews(
                snapshot_token, target_kind, target_id,
                catalog_revision, evidence_generation, created_at_ms
             ) VALUES ('bad-target', 'unknown', 'target', 0, 0, 2)",
            [],
        )
        .is_err());
    assert_eq!(
        PHOTOKIT_FINAL_KEY_CLEANUP_TABLE,
        "photokit_key_cleanup_intents"
    );
    assert_eq!(
        connection
            .query_row("PRAGMA foreign_key_check", [], |_| Ok(1_i64))
            .optional()
            .unwrap(),
        None
    );
}

use rusqlite::OptionalExtension;

fn terminal_publication(
    operation_id: &str,
    enrollment_epoch: &str,
    fence: u64,
    generation: Option<u64>,
    replayed: bool,
) -> String {
    json!({
        "operation_id": operation_id,
        "reconciliation_fence": fence,
        "membership_generation": generation,
        "transitions": 0,
        "replayed": replayed,
        "snapshot": {
            "enrollment_epoch": enrollment_epoch,
            "membership_generation": generation
        }
    })
    .to_string()
}

#[test]
fn v12_operation_state_and_terminal_publication_constraints_reject_tampering() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    Database::open(&paths, 1).unwrap();
    let connection = Connection::open(&paths.database).unwrap();
    let enrollment_epoch = "11111111-1111-4111-8111-111111111111";
    connection
        .execute(
            "INSERT INTO photokit_enrollments(
                enrollment_epoch, key_reference, state,
                allow_icloud_downloads, created_at_ms, activated_at_ms
             ) VALUES (?1, 'test-key', 'active', 0, 1, 1)",
            [enrollment_epoch],
        )
        .unwrap();

    let operation_id = "22222222-2222-4222-8222-222222222222";
    connection
        .execute(
            "INSERT INTO photokit_operations(
                operation_id, request_id, enrollment_epoch,
                store_authority_epoch, reconciliation_fence,
                proposed_membership_generation, trigger_kind, state,
                started_at_ms
             ) VALUES (
                ?1, '33333333-3333-4333-8333-333333333333', ?2,
                (SELECT epoch FROM store_authority_epoch WHERE singleton = 1),
                1, 1, 'user', 'enumerating', 2
             )",
            params![operation_id, enrollment_epoch],
        )
        .unwrap();
    let valid_complete = terminal_publication(operation_id, enrollment_epoch, 1, Some(1), false);
    assert!(connection
        .execute(
            "UPDATE photokit_operations
             SET state = 'complete', finished_at_ms = 3,
                 terminal_publication_json = ?2
             WHERE operation_id = ?1",
            params![operation_id, valid_complete],
        )
        .is_err());
    connection
        .execute(
            "UPDATE photokit_operations SET state = 'materializing'
             WHERE operation_id = ?1",
            [operation_id],
        )
        .unwrap();

    let wrong_generation = terminal_publication(operation_id, enrollment_epoch, 1, Some(2), false);
    assert!(connection
        .execute(
            "UPDATE photokit_operations
             SET state = 'complete', finished_at_ms = 3,
                 terminal_publication_json = ?2
             WHERE operation_id = ?1",
            params![operation_id, wrong_generation],
        )
        .is_err());
    connection
        .execute(
            "UPDATE photokit_operations
             SET state = 'complete', finished_at_ms = 3,
                 terminal_publication_json = ?2
             WHERE operation_id = ?1",
            params![operation_id, valid_complete],
        )
        .unwrap();
    assert!(connection
        .execute(
            "UPDATE photokit_operations SET observed_count = 1
             WHERE operation_id = ?1",
            [operation_id],
        )
        .is_err());

    connection
        .execute(
            "INSERT INTO photokit_operations(
                operation_id, request_id, enrollment_epoch,
                store_authority_epoch, reconciliation_fence,
                proposed_membership_generation, trigger_kind, state,
                started_at_ms
             ) VALUES (
                '44444444-4444-4444-8444-444444444444',
                '55555555-5555-4555-8555-555555555555', ?1,
                (SELECT epoch FROM store_authority_epoch WHERE singleton = 1),
                2, 2, 'user', 'enumerating', 4
             )",
            [enrollment_epoch],
        )
        .unwrap();
    assert!(connection
        .execute(
            "UPDATE photokit_operations
             SET state = 'failed', terminal_reason = 'internal',
                 finished_at_ms = 5
             WHERE operation_id = '44444444-4444-4444-8444-444444444444'",
            [],
        )
        .is_err());

    let interrupted_publication = terminal_publication(
        "66666666-6666-4666-8666-666666666666",
        enrollment_epoch,
        3,
        None,
        false,
    );
    connection
        .execute(
            "INSERT INTO photokit_operations(
                operation_id, request_id, enrollment_epoch,
                store_authority_epoch, reconciliation_fence,
                proposed_membership_generation, trigger_kind, state,
                started_at_ms
             ) VALUES (
                '66666666-6666-4666-8666-666666666666',
                '77777777-7777-4777-8777-777777777777', ?1,
                (SELECT epoch FROM store_authority_epoch WHERE singleton = 1),
                3, 3, 'startup', 'enumerating', 6
             )",
            [enrollment_epoch],
        )
        .unwrap();
    assert!(connection
        .execute(
            "UPDATE photokit_operations
             SET state = 'interrupted', terminal_reason = 'restore_interrupted',
                 finished_at_ms = 7, terminal_publication_json = ?2
             WHERE operation_id = ?1",
            params![
                "66666666-6666-4666-8666-666666666666",
                interrupted_publication
            ],
        )
        .is_err());

    let replayed_publication = terminal_publication(
        "88888888-8888-4888-8888-888888888888",
        enrollment_epoch,
        4,
        Some(4),
        true,
    );
    connection
        .execute(
            "INSERT INTO photokit_operations(
                operation_id, request_id, enrollment_epoch,
                store_authority_epoch, reconciliation_fence,
                proposed_membership_generation, trigger_kind, state,
                started_at_ms
             ) VALUES (
                '88888888-8888-4888-8888-888888888888',
                '99999999-9999-4999-8999-999999999999', ?1,
                (SELECT epoch FROM store_authority_epoch WHERE singleton = 1),
                4, 4, 'startup', 'enumerating', 8
             )",
            [enrollment_epoch],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE photokit_operations SET state = 'materializing'
             WHERE operation_id = '88888888-8888-4888-8888-888888888888'",
            [],
        )
        .unwrap();
    assert!(connection
        .execute(
            "UPDATE photokit_operations
             SET state = 'complete', finished_at_ms = 9,
                 terminal_publication_json = ?2
             WHERE operation_id = ?1",
            params!["88888888-8888-4888-8888-888888888888", replayed_publication],
        )
        .is_err());

    let failed_operation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    connection
        .execute(
            "INSERT INTO photokit_operations(
                operation_id, request_id, enrollment_epoch,
                store_authority_epoch, reconciliation_fence,
                proposed_membership_generation, trigger_kind, state,
                started_at_ms
             ) VALUES (
                ?1, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', ?2,
                (SELECT epoch FROM store_authority_epoch WHERE singleton = 1),
                5, 5, 'user', 'enumerating', 10
             )",
            params![failed_operation_id, enrollment_epoch],
        )
        .unwrap();
    let valid_failed = terminal_publication(failed_operation_id, enrollment_epoch, 5, None, false);
    connection
        .execute(
            "UPDATE photokit_operations
             SET state = 'failed', terminal_reason = 'internal',
                 finished_at_ms = 11, terminal_publication_json = ?2
             WHERE operation_id = ?1",
            params![failed_operation_id, valid_failed],
        )
        .unwrap();

    assert!(connection
        .execute(
            "INSERT INTO photokit_operations(
                operation_id, request_id, enrollment_epoch,
                store_authority_epoch, reconciliation_fence,
                proposed_membership_generation, trigger_kind, state,
                terminal_reason, started_at_ms, finished_at_ms
             ) VALUES (
                'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
                'dddddddd-dddd-4ddd-8ddd-dddddddddddd', ?1,
                (SELECT epoch FROM store_authority_epoch WHERE singleton = 1),
                6, 6, 'user', 'stale', 'stale_fence', 12, 13
             )",
            [enrollment_epoch],
        )
        .is_err());
}
