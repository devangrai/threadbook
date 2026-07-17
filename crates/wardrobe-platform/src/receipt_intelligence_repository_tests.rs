use super::*;
use crate::PrivateAppPaths;
use rusqlite::params;

const SOURCE: &str = "16000000-0000-4000-8000-000000000001";
const PROVENANCE: &str = "16000000-0000-4000-8000-000000000002";
const PROVIDER_SOURCE: &str = "16000000-0000-4000-8000-000000000003";
const SOURCE_REVISION: &str = "16000000-0000-4000-8000-000000000004";
const PARSE: &str = "16000000-0000-4000-8000-000000000005";
const FRAGMENT: &str = "16000000-0000-4000-8000-000000000006";
const METADATA_FRAGMENT: &str = "16000000-0000-4000-8000-000000000007";
const CREDENTIAL: &str = "16000000-0000-4000-8000-000000000008";
const REQUEST_1: &str = "16000000-0000-4000-8000-000000000009";
const REQUEST_2: &str = "16000000-0000-4000-8000-000000000010";
const REQUEST_3: &str = "16000000-0000-4000-8000-000000000011";

fn hash(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn bounds() -> ReceiptIntelligenceBounds {
    ReceiptIntelligenceBounds {
        max_fragment_count: 64,
        max_fragment_bytes: 16 * 1024,
        max_aggregate_text_bytes: 128 * 1024,
        max_serialized_request_bytes: 256 * 1024,
        max_request_bytes: 256 * 1024,
        max_response_bytes: 2 * 1024 * 1024,
        max_output_tokens: 4_000,
        timeout_ms: 60_000,
        max_attempts: 1,
    }
}

fn fixture() -> (tempfile::TempDir, PrivateAppPaths, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let database = Database::open(&paths, 1).unwrap();
    let connection = database.connection().unwrap();
    let blob = hash(b"synthetic gmail message");
    let visible = "Order 42\nBlue linen shirt\nTotal USD 45.00";
    connection
        .execute(
            "INSERT INTO blobs(sha256,byte_length,created_at_ms) VALUES(?1,23,1)",
            [&blob],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO local_sources(
            source_id,source_kind,identity_key,canonical_locator,raw_sha256,
            blob_sha256,byte_length,status,no_blob_reason,created_at_ms,updated_at_ms
         ) VALUES(?1,'eml','p11-message','gmail:p11',?2,?2,23,'imported',NULL,1,1)",
            params![SOURCE, blob],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO source_provenance(
            provenance_id,source_id,request_id,observed_locator,raw_sha256,
            blob_sha256,observed_at_ms
         ) VALUES(?1,?2,'p11-import','gmail:p11',?3,?3,1)",
            params![PROVENANCE, SOURCE, blob],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO gmail_accounts(account_key,created_at_ms) VALUES(?1,1)",
            ["a".repeat(64)],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO gmail_provider_sources(
            provider_source_id,account_key,gmail_message_id,created_at_ms
         ) VALUES(?1,?2,'p11-message',1)",
            params![PROVIDER_SOURCE, "a".repeat(64)],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO gmail_source_revisions(
            revision_id,provider_source_id,history_id,availability,reason,
            graph_sha256,created_at_ms
         ) VALUES(?1,?2,'1','available','materialized',?3,1)",
            params![SOURCE_REVISION, PROVIDER_SOURCE, hash(b"revision graph")],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO gmail_revision_materializations(
            revision_id,local_source_id,source_provenance_id,blob_sha256,
            mime_manifest_sha256,evidence_manifest_sha256,created_at_ms
         ) VALUES(?1,?2,?3,?4,?5,?6,1)",
            params![
                SOURCE_REVISION,
                SOURCE,
                PROVENANCE,
                blob,
                hash(b"mime"),
                hash(b"evidence")
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_parses(
            parse_id,source_id,raw_sha256,parser_revision,sanitizer_revision,
            canonical_input_sha256,created_at_ms
         ) VALUES(?1,?2,?3,'parser-v1','sanitizer-v1',?4,1)",
            params![PARSE, SOURCE, blob, hash(b"canonical")],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_fragments(
            fragment_id,parse_id,ordinal,fragment_kind,content_text,
            content_sha256,metadata_json,byte_length
         ) VALUES(?1,?2,4,'plain_text',?3,?4,NULL,?5)",
            params![
                FRAGMENT,
                PARSE,
                visible,
                hash(visible.as_bytes()),
                visible.len() as i64
            ],
        )
        .unwrap();
    let metadata = "secret-filename.pdf";
    connection
        .execute(
            "INSERT INTO receipt_fragments(
            fragment_id,parse_id,ordinal,fragment_kind,content_text,
            content_sha256,metadata_json,byte_length
         ) VALUES(?1,?2,5,'attachment_metadata',?3,?4,'{}',?5)",
            params![
                METADATA_FRAGMENT,
                PARSE,
                metadata,
                hash(metadata.as_bytes()),
                metadata.len() as i64
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO credential_references(
            locator,credential_id,save_request_id,provider,display_label,status,
            created_at_ms,updated_at_ms
         ) VALUES('p11-keychain-ref',?1,'p11-save','open_ai','OpenAI','active',1,1)",
            [CREDENTIAL],
        )
        .unwrap();
    drop(connection);
    (temporary, paths, database)
}

fn consent(
    database: &Database,
    request_id: &str,
    now_ms: i64,
) -> ReceiptIntelligenceConsentReservation {
    let preview = database
        .preview_receipt_intelligence(request_id, SOURCE_REVISION, bounds())
        .unwrap();
    ReceiptIntelligenceConsentReservation {
        request_id: request_id.into(),
        command_sha256: hash(format!("command:{request_id}").as_bytes()),
        source_revision_id: SOURCE_REVISION.into(),
        source_revision_sha256: preview.source_revision_sha256,
        preview_binding_sha256: preview.preview_binding_sha256,
        fragment_set_sha256: preview.fragment_set_sha256,
        projection_sha256: preview.projection_sha256,
        serialized_request_sha256: hash(b"strict request"),
        serialized_request_bytes: 1024,
        credential_id: CREDENTIAL.into(),
        provider: "openai".into(),
        model: "gpt-5.6-sol".into(),
        retention_mode: "default".into(),
        retention_provenance: "openai-default-2026-07".into(),
        prompt_revision: "receipt-intelligence-prompt-v1".into(),
        schema_revision: "receipt-intelligence-v1".into(),
        projection_revision: "receipt-intelligence-projection-v1".into(),
        parameters_sha256: hash(b"parameters"),
        bounds: bounds(),
        expires_at_ms: now_ms + 60_000,
    }
}

fn audit(dispatched_at_ms: i64) -> ReceiptIntelligenceAuditMetadata {
    ReceiptIntelligenceAuditMetadata {
        response_sha256: Some(hash(b"response")),
        provider_request_id: Some("req_p11".into()),
        response_id: Some("resp_p11".into()),
        request_bytes: 1024,
        response_bytes: 512,
        input_tokens: 120,
        output_tokens: 40,
        total_tokens: 160,
        reasoning_tokens: 10,
        cached_input_tokens: 0,
        attempt_count: 1,
        dispatched_at_ms,
    }
}

#[test]
fn pure_preview_and_atomic_exact_reservation() {
    let (_temporary, _paths, database) = fixture();
    let preview = database
        .preview_receipt_intelligence(REQUEST_1, SOURCE_REVISION, bounds())
        .unwrap();
    assert_eq!(preview.fragments.len(), 1);
    assert_eq!(preview.fragments[0].handle, "fragment-0000");
    assert!(!preview.fragments[0]
        .visible_text
        .contains("secret-filename"));
    let connection = database.connection().unwrap();
    assert_eq!(
        table_count(&connection, "receipt_intelligence_approvals"),
        0
    );
    assert_eq!(table_count(&connection, "receipt_intelligence_attempts"), 0);
    drop(connection);

    let approved = consent(&database, REQUEST_1, 100);
    let created = database
        .reserve_receipt_intelligence(&approved, 100)
        .unwrap();
    let replayed = database
        .reserve_receipt_intelligence(&approved, 101)
        .unwrap();
    assert_eq!(created.attempt_id, replayed.attempt_id);
    assert!(replayed.replayed);
    let replayed_after_expiry = database
        .reserve_receipt_intelligence(&approved, approved.expires_at_ms + 1)
        .unwrap();
    assert_eq!(created.attempt_id, replayed_after_expiry.attempt_id);
    assert!(replayed_after_expiry.replayed);
    let mut changed = approved;
    changed.model = "changed".into();
    changed.command_sha256 = hash(b"changed command");
    assert!(matches!(
        database.reserve_receipt_intelligence(&changed, 102),
        Err(PlatformError::Conflict(
            "receipt_intelligence_command_changed"
        ))
    ));
    let connection = database.connection().unwrap();
    assert_eq!(
        table_count(&connection, "receipt_intelligence_approvals"),
        1
    );
    assert_eq!(table_count(&connection, "receipt_intelligence_attempts"), 1);
}

#[test]
fn preview_rejects_fragment_content_hash_mismatch() {
    let (_temporary, _paths, database) = fixture();
    let connection = database.connection().unwrap();
    connection
        .execute("DROP TRIGGER receipt_fragments_no_update", [])
        .unwrap();
    connection
        .execute(
            "UPDATE receipt_fragments
             SET content_sha256 = ?1
             WHERE fragment_id = ?2",
            params!["0".repeat(64), FRAGMENT],
        )
        .unwrap();

    assert!(matches!(
        database.preview_receipt_intelligence(REQUEST_1, SOURCE_REVISION, bounds()),
        Err(PlatformError::Corrupt(
            "receipt_intelligence_fragment_sha256"
        ))
    ));
}

#[test]
fn preflight_replay_is_read_only_and_compares_exact_command_identity() {
    let (_temporary, _paths, database) = fixture();
    let approved = consent(&database, REQUEST_1, 100);
    let created = database
        .reserve_receipt_intelligence(&approved, 100)
        .unwrap();
    let replayed = database
        .preflight_receipt_intelligence_replay(REQUEST_1, &approved.command_sha256)
        .unwrap()
        .unwrap();
    assert_eq!(replayed.attempt_id, created.attempt_id);
    assert!(replayed.replayed);
    assert!(matches!(
        database.preflight_receipt_intelligence_replay(REQUEST_1, &hash(b"changed command"),),
        Err(PlatformError::Conflict(
            "receipt_intelligence_command_changed"
        ))
    ));
    assert_eq!(
        table_count(
            &database.connection().unwrap(),
            "receipt_intelligence_attempts"
        ),
        1
    );
}

#[test]
fn publication_rejects_a_parse_created_after_approval() {
    let (_temporary, _paths, database) = fixture();
    let attempt = database
        .reserve_receipt_intelligence(&consent(&database, REQUEST_1, 100), 100)
        .unwrap();
    database
        .mark_receipt_intelligence_dispatched(&attempt.attempt_id, 200)
        .unwrap();

    let parse = "16000000-0000-4000-8000-000000000030";
    let fragment = "16000000-0000-4000-8000-000000000031";
    let visible = "Order 42\nBlue linen shirt\nTotal USD 45.00";
    let connection = database.connection().unwrap();
    connection
        .execute(
            "INSERT INTO receipt_parses(
                parse_id,source_id,raw_sha256,parser_revision,sanitizer_revision,
                canonical_input_sha256,created_at_ms
             )
             SELECT ?1,source_id,raw_sha256,'parser-v2',sanitizer_revision,
                    ?2,2
             FROM receipt_parses WHERE parse_id=?3",
            params![parse, hash(b"new canonical parse"), PARSE],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_fragments(
                fragment_id,parse_id,ordinal,fragment_kind,content_text,
                content_sha256,metadata_json,byte_length
             ) VALUES(?1,?2,4,'plain_text',?3,?4,NULL,?5)",
            params![
                fragment,
                parse,
                visible,
                hash(visible.as_bytes()),
                visible.len() as i64
            ],
        )
        .unwrap();
    drop(connection);

    let result = database.complete_receipt_intelligence_with_publication(
        &attempt.attempt_id,
        ReceiptIntelligenceClassification::ApparelOrder,
        &audit(200),
        300,
        |_| panic!("publication must not run for a changed parse"),
    );
    assert!(matches!(
        result,
        Err(PlatformError::Conflict(
            "receipt_intelligence_source_revision_changed"
        ))
    ));
    assert_eq!(
        table_count(
            &database.connection().unwrap(),
            "receipt_intelligence_classifications"
        ),
        0
    );
}

#[test]
fn restart_recovery_and_unrelated_classification_are_durable() {
    let (_temporary, paths, database) = fixture();
    let not_sent = database
        .reserve_receipt_intelligence(&consent(&database, REQUEST_1, 100), 100)
        .unwrap();
    let dispatched = database
        .reserve_receipt_intelligence(&consent(&database, REQUEST_2, 100), 100)
        .unwrap();
    database
        .mark_receipt_intelligence_dispatched(&dispatched.attempt_id, 200)
        .unwrap();
    drop(database);
    let reopened = Database::open(&paths, 300).unwrap();
    assert_eq!(
        reopened.recover_receipt_intelligence_attempts(300).unwrap(),
        vec![not_sent.attempt_id]
    );
    assert!(reopened
        .list_receipt_intelligence(None, 10)
        .unwrap()
        .iter()
        .any(|entry| {
            entry.attempt_id == dispatched.attempt_id
                && entry.state == ReceiptIntelligenceAttemptState::OutcomeUnknown
        }));

    let unrelated = reopened
        .reserve_receipt_intelligence(&consent(&reopened, REQUEST_3, 400), 400)
        .unwrap();
    reopened
        .mark_receipt_intelligence_dispatched(&unrelated.attempt_id, 500)
        .unwrap();
    reopened
        .complete_receipt_intelligence_without_order(
            &unrelated.attempt_id,
            ReceiptIntelligenceClassification::Unrelated,
            &audit(500),
            600,
        )
        .unwrap();
    let listed = reopened.list_receipt_intelligence(None, 10).unwrap();
    let completed = listed
        .iter()
        .find(|entry| entry.attempt_id == unrelated.attempt_id)
        .unwrap();
    assert_eq!(
        completed.classification,
        Some(ReceiptIntelligenceClassification::Unrelated)
    );
    assert!(completed.audit.is_some());
    assert_eq!(
        table_count(&reopened.connection().unwrap(), "receipt_orders"),
        0
    );
}

#[test]
fn list_availability_uses_active_credential_reference_without_secret_access() {
    let (_temporary, _paths, database) = fixture();
    let request = ListReceiptIntelligenceV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: RequestId::new_v4(),
        state: None,
        classification: None,
        cursor: None,
        limit: 20,
    };

    let available = database
        .list_receipt_intelligence_response(&request)
        .unwrap();
    assert!(available.availability.available);
    assert_eq!(available.availability.reason, None);

    database
        .connection()
        .unwrap()
        .execute(
            "DELETE FROM credential_references WHERE credential_id = ?1",
            [CREDENTIAL],
        )
        .unwrap();
    let unavailable = database
        .list_receipt_intelligence_response(&request)
        .unwrap();
    assert!(!unavailable.availability.available);
    assert_eq!(
        unavailable.availability.reason,
        Some(ReceiptIntelligenceAvailabilityReasonV1::CredentialUnavailable)
    );
    assert!(unavailable.availability.offline_receipt_analysis_available);
    assert!(unavailable.availability.existing_wardrobe_access_available);
}

#[test]
fn publication_is_atomic_and_reanalysis_preserves_review_authority() {
    let (_temporary, _paths, database) = fixture();
    let attempt = database
        .reserve_receipt_intelligence(&consent(&database, REQUEST_1, 100), 100)
        .unwrap();
    database
        .mark_receipt_intelligence_dispatched(&attempt.attempt_id, 200)
        .unwrap();
    let run = "16000000-0000-4000-8000-000000000020";
    let order = "16000000-0000-4000-8000-000000000021";
    let result = database.complete_receipt_intelligence_with_publication(
        &attempt.attempt_id,
        ReceiptIntelligenceClassification::ApparelOrder,
        &audit(200),
        300,
        |transaction| {
            insert_order(transaction, run, order, 300)?;
            transaction.execute(
                "UPDATE revision_state SET catalog_revision=catalog_revision+1 WHERE singleton=1",
                [],
            )?;
            Ok(Some(order.into()))
        },
    );
    assert!(matches!(
        result,
        Err(PlatformError::Conflict(
            "receipt_intelligence_publication_authority"
        ))
    ));
    let connection = database.connection().unwrap();
    assert_eq!(table_count(&connection, "receipt_orders"), 0);
    assert_eq!(table_count(&connection, "receipt_intelligence_audits"), 0);
    drop(connection);

    database
        .complete_receipt_intelligence_with_publication(
            &attempt.attempt_id,
            ReceiptIntelligenceClassification::ApparelOrder,
            &audit(200),
            301,
            |transaction| {
                insert_order(transaction, run, order, 301)?;
                Ok(Some(order.into()))
            },
        )
        .unwrap();
    let decision = "16000000-0000-4000-8000-000000000022";
    let connection = database.connection().unwrap();
    connection
        .execute(
            "INSERT INTO receipt_review_decisions(
            review_decision_id,order_evidence_id,request_id,action,
            reviewed_order_json,receipt_revision,created_at_ms
         ) VALUES(?1,?2,'p11-review','confirm',NULL,1,310)",
            params![decision, order],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_review_heads(
            order_evidence_id,review_decision_id,receipt_revision,updated_at_ms
         ) VALUES(?1,?2,1,310)",
            params![order, decision],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_source_authority_heads(
            local_source_id,authority_id,authority_kind,order_evidence_id,
            review_decision_id,receipt_revision,authority_revision,updated_at_ms
         ) VALUES(?1,?2,'user_reviewed',?3,?2,1,1,310)",
            params![SOURCE, decision, order],
        )
        .unwrap();
    drop(connection);
    let authority = database.receipt_source_authority_head(SOURCE).unwrap();
    let second = database
        .reserve_receipt_intelligence(&consent(&database, REQUEST_2, 400), 400)
        .unwrap();
    database
        .mark_receipt_intelligence_dispatched(&second.attempt_id, 500)
        .unwrap();
    database
        .complete_receipt_intelligence_without_order(
            &second.attempt_id,
            ReceiptIntelligenceClassification::Ambiguous,
            &audit(500),
            600,
        )
        .unwrap();
    assert_eq!(
        database.receipt_source_authority_head(SOURCE).unwrap(),
        authority
    );
}

fn insert_order(
    transaction: &Transaction<'_>,
    run: &str,
    order: &str,
    now_ms: i64,
) -> PlatformResult<()> {
    transaction.execute(
        "INSERT INTO receipt_extraction_runs(
            run_id,parse_id,provider_id,provider_revision,schema_version,
            schema_sha256,ruleset_revision,ruleset_sha256,parameters_json,
            canonical_input_sha256,parent_source_sha256,
            parent_fragment_hashes_json,status,created_at_ms
         ) VALUES(
            ?1,?2,'openai','gpt-5.6-sol','receipt-intelligence-v1',?3,
            'receipt-intelligence-prompt-v1',?4,'{}',?5,?6,'[]','pending',?7
         )",
        params![
            run,
            PARSE,
            hash(b"schema"),
            hash(b"rules"),
            hash(b"canonical"),
            hash(b"parent"),
            now_ms
        ],
    )?;
    transaction.execute(
        "INSERT INTO receipt_orders(order_evidence_id,run_id,line_count,created_at_ms)
         VALUES(?1,?2,1,?3)",
        params![order, run, now_ms],
    )?;
    Ok(())
}

fn table_count(connection: &rusqlite::Connection, table: &str) -> i64 {
    connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}
