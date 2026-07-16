use image::codecs::png::{CompressionType, FilterType, PngEncoder};
use image::{ExtendedColorType, ImageEncoder};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::fs;
use wardrobe_core::{
    ApproveAndFetchReceiptImageV1Request, CatalogPort, ImportLocalSourcesV1Request,
    ListReceiptImageCandidatesV1Request, ReceiptImageAttemptOutcomeV1, ReceiptImageAttemptPlanV1,
    ReceiptImageDownloadV1, ReceiptImageFailureCodeV1, ReceiptImageHopProvenanceV1, ReceiptPort,
    RequestId, Sha256Digest, SCHEMA_VERSION_V1,
};
use wardrobe_platform::{Database, PrivateAppPaths};

fn request_id() -> RequestId {
    RequestId::new_v4()
}

fn receipt_eml() -> &'static [u8] {
    b"From: orders@example.invalid\r\n\
MIME-Version: 1.0\r\n\
Content-Type: text/html; charset=utf-8\r\n\r\n\
<html><body><p>Order 100</p>\
<img src=\"https://cdn.example.invalid/products/shirt.png?size=large#hero\">\
</body></html>\r\n"
}

fn setup() -> (
    tempfile::TempDir,
    PrivateAppPaths,
    Database,
    wardrobe_core::SourceId,
) {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let database = Database::open(&paths, 1).unwrap();
    let eml = temporary.path().join("receipt.eml");
    fs::write(&eml, receipt_eml()).unwrap();
    let imported = database
        .import_local_sources(&ImportLocalSourcesV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            paths: vec![eml.to_string_lossy().into_owned()],
        })
        .unwrap();
    let source_id = imported.summaries[0].source_id.unwrap();
    (temporary, paths, database, source_id)
}

fn list(
    database: &Database,
    source_id: wardrobe_core::SourceId,
) -> wardrobe_core::ListReceiptImageCandidatesV1Response {
    database
        .list_receipt_image_candidates(&ListReceiptImageCandidatesV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(),
            source_id,
        })
        .unwrap()
}

fn approval(
    candidate: &wardrobe_core::ReceiptImageCandidateSummaryV1,
    prior_attempt_id: Option<wardrobe_core::ReceiptImageAttemptId>,
) -> ApproveAndFetchReceiptImageV1Request {
    ApproveAndFetchReceiptImageV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(),
        candidate_id: candidate.candidate_id,
        approved_display_host: candidate.display_host.clone(),
        candidate_url_sha256: candidate.candidate_url_sha256.clone(),
        prior_attempt_id,
    }
}

fn test_png() -> Vec<u8> {
    let pixels = vec![0x7f; 32 * 32 * 4];
    let mut output = Vec::new();
    PngEncoder::new_with_quality(&mut output, CompressionType::Best, FilterType::Adaptive)
        .write_image(&pixels, 32, 32, ExtendedColorType::Rgba8)
        .unwrap();
    output
}

fn successful_download(bytes: Vec<u8>) -> ReceiptImageDownloadV1 {
    let digest = Sha256Digest::from_bytes(&bytes);
    ReceiptImageDownloadV1 {
        source_bytes: bytes.clone(),
        source_sha256: digest.clone(),
        source_media_type: "image/png".to_owned(),
        display_png_bytes: bytes,
        display_sha256: digest,
        width: 32,
        height: 32,
        final_url_sha256: Sha256Digest::from_bytes(
            b"https://cdn.example.invalid:443/products/shirt.png?size=large",
        ),
        declared_length: None,
        hops: vec![ReceiptImageHopProvenanceV1 {
            ordinal: 0,
            host_sha256: Sha256Digest::from_bytes(b"cdn.example.invalid"),
            url_sha256: Sha256Digest::from_bytes(
                b"https://cdn.example.invalid:443/products/shirt.png?size=large",
            ),
            pinned_addresses: vec!["203.0.113.10".to_owned()],
            http_status: 200,
        }],
        policy_revision: "receipt-image-network-policy-v1".to_owned(),
        decoder_revision: "image-0.25.10-v1".to_owned(),
        derivative_revision: "png-rgba8-best-paeth-v1".to_owned(),
    }
}

#[test]
fn candidate_backfill_is_idempotent_and_list_never_exposes_the_url() {
    let (_temporary, paths, database, source_id) = setup();

    let first = list(&database, source_id);
    let second = list(&database, source_id);
    assert_eq!(first.candidates.len(), 1);
    assert_eq!(first.candidates, second.candidates);
    assert_eq!(first.candidates[0].display_host, "cdn.example.invalid");
    assert_eq!(first.omitted_count, 0);
    assert!(!serde_json::to_string(&first)
        .unwrap()
        .contains("/products/shirt.png"));

    let connection = Connection::open(paths.database).unwrap();
    let stored: (String, i64) = connection
        .query_row(
            "SELECT normalized_url, occurrence_count FROM receipt_image_candidates",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        stored.0,
        "https://cdn.example.invalid:443/products/shirt.png?size=large"
    );
    assert_eq!(stored.1, 1);
}

#[test]
fn exact_replay_never_reissues_a_plan_and_non_ambiguous_attempts_cannot_be_followed() {
    let (_temporary, _paths, database, source_id) = setup();
    let candidate = list(&database, source_id).candidates.remove(0);
    let request = approval(&candidate, None);
    let (attempt_id, token) = match database.prepare_image_attempt(&request).unwrap() {
        ReceiptImageAttemptPlanV1::Download {
            attempt_id,
            download_token,
            ..
        } => (attempt_id, download_token),
        ReceiptImageAttemptPlanV1::Replay(_) => panic!("first call must create an attempt"),
    };
    match database.prepare_image_attempt(&request).unwrap() {
        ReceiptImageAttemptPlanV1::Replay(response) => {
            assert_eq!(response.outcome, ReceiptImageAttemptOutcomeV1::InProgress);
        }
        ReceiptImageAttemptPlanV1::Download { .. } => panic!("replay returned a download token"),
    }

    let premature = approval(&candidate, Some(attempt_id));
    assert!(database.prepare_image_attempt(&premature).is_err());

    let failed = database
        .finalize_image_attempt(
            &request,
            attempt_id,
            &token,
            Err(ReceiptImageFailureCodeV1::TransportFailed),
        )
        .unwrap();
    assert_eq!(
        failed.outcome,
        ReceiptImageAttemptOutcomeV1::TransportFailed
    );
    match database.prepare_image_attempt(&request).unwrap() {
        ReceiptImageAttemptPlanV1::Replay(response) => {
            assert_eq!(
                response.outcome,
                ReceiptImageAttemptOutcomeV1::TransportFailed
            );
        }
        ReceiptImageAttemptPlanV1::Download { .. } => panic!("terminal replay retried"),
    }
    let after_failure = approval(&candidate, Some(attempt_id));
    assert!(database.prepare_image_attempt(&after_failure).is_err());
}

#[test]
fn only_latest_durable_ambiguous_attempt_can_have_one_successor() {
    let (_temporary, paths, database, source_id) = setup();
    let candidate = list(&database, source_id).candidates.remove(0);
    let original = approval(&candidate, None);
    let attempt_id = wardrobe_core::ReceiptImageAttemptId::new_v4();
    let approval_id = uuid::Uuid::new_v4().hyphenated().to_string();
    let envelope = serde_json::to_vec(&original).unwrap();
    let envelope_sha256 = format!("{:x}", Sha256::digest(&envelope));
    drop(database);

    let connection = Connection::open(&paths.database).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_image_approvals(
                approval_id, request_id, candidate_id, approved_display_host,
                approved_url_sha256, prior_attempt_id, approved_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, 1)",
            params![
                approval_id,
                original.request_id.to_string(),
                candidate.candidate_id.to_string(),
                original.approved_display_host,
                original.candidate_url_sha256.as_str()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_image_attempts(
                attempt_id, candidate_id, approval_id, request_id,
                request_envelope_sha256, prior_attempt_id, download_token_sha256,
                staging_nonce, policy_revision, deadline_at_ms,
                settlement_until_ms, created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, 2, 3, 1)",
            params![
                attempt_id.to_string(),
                candidate.candidate_id.to_string(),
                approval_id,
                original.request_id.to_string(),
                envelope_sha256,
                "a".repeat(64),
                "ambiguous_fixture_01",
                "receipt-image-network-policy-v1"
            ],
        )
        .unwrap();
    drop(connection);

    let restarted = Database::open(&paths, 20).unwrap();
    let latest = list(&restarted, source_id).candidates[0]
        .latest_attempt
        .clone()
        .unwrap();
    assert_eq!(latest.attempt_id, attempt_id);
    assert_eq!(latest.outcome, ReceiptImageAttemptOutcomeV1::Ambiguous);

    let successor = approval(&candidate, Some(attempt_id));
    let successor_id = match restarted.prepare_image_attempt(&successor).unwrap() {
        ReceiptImageAttemptPlanV1::Download { attempt_id, .. } => attempt_id,
        ReceiptImageAttemptPlanV1::Replay(_) => panic!("fresh successor was replayed"),
    };
    let branch = approval(&candidate, Some(attempt_id));
    assert!(restarted.prepare_image_attempt(&branch).is_err());
    let chained_while_pending = approval(&candidate, Some(successor_id));
    assert!(restarted
        .prepare_image_attempt(&chained_while_pending)
        .is_err());
}

#[test]
fn successful_finalization_commits_blobs_intent_provenance_and_terminal_replay() {
    let (_temporary, paths, database, source_id) = setup();
    let candidate = list(&database, source_id).candidates.remove(0);
    let request = approval(&candidate, None);
    let (attempt_id, token) = match database.prepare_image_attempt(&request).unwrap() {
        ReceiptImageAttemptPlanV1::Download {
            attempt_id,
            download_token,
            ..
        } => (attempt_id, download_token),
        ReceiptImageAttemptPlanV1::Replay(_) => panic!("first call must create an attempt"),
    };
    let response = database
        .finalize_image_attempt(
            &request,
            attempt_id,
            &token,
            Ok(successful_download(test_png())),
        )
        .unwrap();
    assert_eq!(response.outcome, ReceiptImageAttemptOutcomeV1::Succeeded);
    let artifact = response.artifact.unwrap();
    assert!(paths
        .blobs
        .join(&artifact.source_blob_sha256.as_str()[0..2])
        .join(&artifact.source_blob_sha256.as_str()[2..4])
        .join(artifact.source_blob_sha256.as_str())
        .is_file());
    assert_eq!(fs::read_dir(&paths.staging).unwrap().count(), 0);

    let connection = Connection::open(&paths.database).unwrap();
    for table in [
        "receipt_image_materialization_intents",
        "receipt_remote_images",
        "receipt_image_attempt_outcomes",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "{table}");
    }
    let provenance_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provenance
             WHERE source_kind LIKE 'receipt_remote_image_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(provenance_count, 2);
    let leaked: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM command_receipts
             WHERE response_json LIKE '%/products/shirt.png%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(leaked, 0);

    match database.prepare_image_attempt(&request).unwrap() {
        ReceiptImageAttemptPlanV1::Replay(replay) => {
            assert_eq!(replay.outcome, ReceiptImageAttemptOutcomeV1::Succeeded);
        }
        ReceiptImageAttemptPlanV1::Download { .. } => panic!("success replay retried"),
    }
}
