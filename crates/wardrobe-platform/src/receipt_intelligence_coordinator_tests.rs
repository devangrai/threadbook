use super::*;
use crate::outfit_recommendation_http::{
    OpenAiResponsesHttpError, OpenAiResponsesHttpTransport, OPENAI_REQUEST_LIMIT_BYTES,
};
use crate::receipt_intelligence_provider::{
    OpenAiReceiptIntelligenceProvider, ReceiptIntelligenceAudit, ReceiptIntelligenceCitation,
    ReceiptIntelligenceClassification, ReceiptIntelligenceEventEvidence,
    ReceiptIntelligenceEventKind, ReceiptIntelligenceExtraction, ReceiptIntelligenceLineItem,
    ReceiptIntelligenceOutput, ReceiptIntelligenceProvenance, ReceiptIntelligenceStringEvidence,
    ReceiptIntelligenceU64Evidence, ReceiptIntelligenceUsage, ReceiptIntelligenceVariant,
    RECEIPT_INTELLIGENCE_MAX_OUTPUT_TOKENS,
};
use crate::receipt_parser::parse_receipt_bundle_v1;
use crate::receipt_repository::persist_parse;
use crate::PrivateAppPaths;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rusqlite::params;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{json, Value};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use url::Url;
use wardrobe_core::{
    CredentialProviderV1, ReceiptIntelligenceExecutionBoundsV1, ReceiptIntelligenceOutcomeV1,
    ReceiptIntelligencePreparationBoundsV1, ReceiptPort, ReceiptReviewActionV1, RequestId,
    ReviewReceiptV1Request, SCHEMA_VERSION_V1,
};

const SOURCE: &str = "17000000-0000-4000-8000-000000000001";
const PROVENANCE: &str = "17000000-0000-4000-8000-000000000002";
const PROVIDER_SOURCE: &str = "17000000-0000-4000-8000-000000000003";
const SOURCE_REVISION: &str = "17000000-0000-4000-8000-000000000004";
const CREDENTIAL: &str = "17000000-0000-4000-8000-000000000005";
const PREVIEW_REQUEST: &str = "17000000-0000-4000-8000-000000000006";
const EXECUTE_REQUEST: &str = "17000000-0000-4000-8000-000000000007";
const REVIEW_REQUEST: &str = "17000000-0000-4000-8000-000000000008";
const CHANGED_PREVIEW_REQUEST: &str = "17000000-0000-4000-8000-000000000009";

const BODY: &str = "Order confirmed\nMerchant: Alpine Co\nOrder: A-19\nDate: 2026-07-15\nItem: Trail Tee\nQty: 2\nPrice: $24.50 USD\nSize: M\nSKU: TT-1";

#[derive(Clone)]
struct FakeCredentialStore {
    observed: Arc<Mutex<Vec<String>>>,
}

impl ReceiptIntelligenceCredentialStore for FakeCredentialStore {
    fn get_receipt_intelligence_secret(
        &self,
        locator: &CredentialLocator,
    ) -> Result<SecretString, PlatformError> {
        self.observed
            .lock()
            .unwrap()
            .push(locator.expose_locator().to_owned());
        Ok(SecretString::new("sk-test-only".to_owned()))
    }
}

#[derive(Clone)]
struct FixtureProvider {
    output: ReceiptIntelligenceOutput,
    observed: Arc<Mutex<u32>>,
}

impl ReceiptIntelligenceProviderPort for FixtureProvider {
    fn analyze_receipt_intelligence<'a>(
        &'a self,
        _api_key: &'a SecretString,
        _request: &'a ReceiptIntelligenceRequest,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ProviderOutcome, ReceiptIntelligenceProviderError>>
                + Send
                + 'a,
        >,
    > {
        *self.observed.lock().unwrap() += 1;
        let output = self.output.clone();
        Box::pin(async move {
            Ok(ProviderOutcome::Completed {
                output,
                audit: ReceiptIntelligenceAudit {
                    provenance: ReceiptIntelligenceProvenance {
                        provider: "openai",
                        model: "gpt-5.6-sol",
                        prompt_revision: "receipt-intelligence-prompt-v1",
                        schema_revision: "receipt-intelligence-v1",
                        projection_revision: "receipt-intelligence-projection-v1",
                        parameter_revision: "receipt-intelligence-parameters-v1",
                        parent_source_revision: SOURCE_REVISION.to_owned(),
                    },
                    provider_request_id: Some("req_fixture".to_owned()),
                    response_id: "resp_fixture".to_owned(),
                    usage: ReceiptIntelligenceUsage {
                        request_bytes: 2_048,
                        response_bytes: 1_024,
                        input_tokens: 100,
                        output_tokens: 50,
                        total_tokens: 150,
                        reasoning_tokens: 10,
                        cached_input_tokens: 0,
                        attempts: 1,
                    },
                },
            })
        })
    }
}

#[tokio::test]
async fn gmail_source_to_validated_order_review_is_atomic_and_catalog_free() {
    let (_temporary, database) = fixture();
    let observed = Arc::new(Mutex::new(Vec::new()));
    let tls_fixture =
        ReceiptIntelligenceTlsFixture::start(completed_response(fixture_output())).await;
    let coordinator = ReceiptIntelligenceCoordinator::new(
        database.clone(),
        FakeCredentialStore {
            observed: Arc::clone(&observed),
        },
        OpenAiReceiptIntelligenceProvider::new(tls_fixture.transport().unwrap()),
    );
    let preview = coordinator
        .preview(PreviewReceiptIntelligenceV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(PREVIEW_REQUEST),
            source_id: source_id(SOURCE),
        })
        .unwrap();
    assert_eq!(preview.preview.disclosure.projection.fragments.len(), 1);
    assert_eq!(
        preview.preview.disclosure.preparation_bounds,
        ReceiptIntelligencePreparationBoundsV1::production()
    );
    assert_eq!(
        preview.preview.disclosure.execution_bounds,
        ReceiptIntelligenceExecutionBoundsV1::production()
    );
    let expected_projection = preview.preview.disclosure.projection.clone();

    let response = coordinator
        .request(RequestReceiptIntelligenceV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(EXECUTE_REQUEST),
            consent: wardrobe_core::ReceiptIntelligenceConsentV1 {
                affirmative: true,
                preview: preview.preview,
            },
        })
        .await
        .unwrap();
    let order_id = match response.outcome {
        ReceiptIntelligenceOutcomeV1::Completed { classification, .. } => {
            assert_eq!(
                classification.classification,
                wardrobe_core::ReceiptIntelligenceClassificationV1::ApparelOrder
            );
            classification.order_evidence_id.unwrap()
        }
        outcome => panic!("unexpected outcome: {outcome:?}"),
    };
    assert_eq!(observed.lock().unwrap().as_slice(), ["p11-keychain-ref"]);
    let wire = tls_fixture.finish().await;
    let body = request_json(&wire);
    assert!(wire.starts_with("POST /v1/responses HTTP/1.1\r\n"));
    assert_eq!(body["model"], RECEIPT_INTELLIGENCE_MODEL_V1);
    assert_eq!(body["store"], false);
    assert_eq!(body["background"], false);
    assert_eq!(body["tools"], json!([]));
    assert_eq!(body["reasoning"], json!({"effort": "low"}));
    assert_eq!(body["service_tier"], "default");
    assert_eq!(
        body["max_output_tokens"],
        RECEIPT_INTELLIGENCE_MAX_OUTPUT_TOKENS
    );
    for forbidden in [
        "previous_response_id",
        "conversation",
        "include",
        "tool_choice",
        "parallel_tool_calls",
        "prompt_cache_options",
    ] {
        assert!(
            body.get(forbidden).is_none(),
            "unexpected stateful Responses field {forbidden}"
        );
    }
    assert_eq!(body["text"]["format"]["type"], "json_schema");
    assert_eq!(body["text"]["format"]["name"], "receipt_intelligence_v1");
    assert_eq!(body["text"]["format"]["strict"], true);
    assert_eq!(
        body["text"]["format"]["schema"]["additionalProperties"],
        false
    );
    assert_eq!(body["input"][0]["role"], "developer");
    assert_eq!(body["input"][1]["role"], "user");
    let projection: Value =
        serde_json::from_str(body["input"][1]["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(
        projection["projection_revision"],
        RECEIPT_INTELLIGENCE_PROJECTION_REVISION_V1
    );
    assert_eq!(
        projection["fragments"][0]["fragment_ref"],
        expected_projection.fragments[0].fragment_ref
    );
    assert_eq!(
        projection["fragments"][0]["text"],
        expected_projection.fragments[0].text
    );
    let serialized_body = serde_json::to_string(&body).unwrap();
    assert!(!serialized_body.contains(SOURCE_REVISION));
    assert!(!serialized_body.contains("sk-test-only"));

    let connection = database.connection().unwrap();
    for (table, expected) in [
        ("receipt_orders", 1_i64),
        ("receipt_order_lines", 1),
        ("receipt_variant_evidence", 1),
        ("receipt_fields", 12),
        ("receipt_intelligence_classifications", 1),
        ("catalog_items", 0),
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, expected, "{table}");
    }
    let receipt_revision: i64 = connection
        .query_row(
            "SELECT receipt_revision FROM revision_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);

    let reviewed = database
        .review_receipt_and_append_decision(&ReviewReceiptV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(REVIEW_REQUEST),
            order_evidence_id: order_id,
            action: ReceiptReviewActionV1::Confirm,
            corrected_order: None,
            expected_receipt_revision: receipt_revision as u64,
        })
        .unwrap();
    assert_eq!(reviewed.decision.action, ReceiptReviewActionV1::Confirm);
    let authority = database
        .receipt_source_authority_head(SOURCE)
        .unwrap()
        .unwrap();
    assert_eq!(authority.order_evidence_id, order_id.to_string());
    assert_eq!(
        authority.review_decision_id,
        reviewed.decision.decision_id.to_string()
    );
    let catalog_count: i64 = database
        .connection()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM catalog_items", [], |row| row.get(0))
        .unwrap();
    assert_eq!(catalog_count, 0);
}

#[tokio::test]
async fn publication_validation_failure_is_terminal_and_atomic() {
    let (_temporary, database) = fixture();
    let mut output = fixture_output();
    output.extraction.as_mut().unwrap().merchant.citations[0].quote =
        "not present in the source".to_owned();
    let coordinator = ReceiptIntelligenceCoordinator::new(
        database.clone(),
        FakeCredentialStore {
            observed: Arc::new(Mutex::new(Vec::new())),
        },
        FixtureProvider {
            output,
            observed: Arc::new(Mutex::new(0)),
        },
    );
    let preview = coordinator
        .preview(PreviewReceiptIntelligenceV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(PREVIEW_REQUEST),
            source_id: source_id(SOURCE),
        })
        .unwrap();
    let response = coordinator
        .request(RequestReceiptIntelligenceV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(EXECUTE_REQUEST),
            consent: wardrobe_core::ReceiptIntelligenceConsentV1 {
                affirmative: true,
                preview: preview.preview,
            },
        })
        .await
        .unwrap();
    match response.outcome {
        ReceiptIntelligenceOutcomeV1::Failed { failure, .. } => {
            assert_eq!(
                failure.code,
                wardrobe_core::ReceiptIntelligenceFailureCodeV1::CitationInvalid
            );
        }
        outcome => panic!("unexpected outcome: {outcome:?}"),
    }
    let connection = database.connection().unwrap();
    for table in [
        "receipt_orders",
        "receipt_intelligence_classifications",
        "receipt_intelligence_audits",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

#[tokio::test]
async fn completed_exact_replay_precedes_retention_source_and_external_checks() {
    let (_temporary, database) = fixture();
    let credential_observed = Arc::new(Mutex::new(Vec::new()));
    let provider_observed = Arc::new(Mutex::new(0));
    let coordinator = ReceiptIntelligenceCoordinator::new(
        database.clone(),
        FakeCredentialStore {
            observed: Arc::clone(&credential_observed),
        },
        FixtureProvider {
            output: fixture_output(),
            observed: Arc::clone(&provider_observed),
        },
    );
    let preview = coordinator
        .preview(PreviewReceiptIntelligenceV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(PREVIEW_REQUEST),
            source_id: source_id(SOURCE),
        })
        .unwrap();
    let mut exact_request = RequestReceiptIntelligenceV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(EXECUTE_REQUEST),
        consent: wardrobe_core::ReceiptIntelligenceConsentV1 {
            affirmative: true,
            preview: preview.preview,
        },
    };
    exact_request
        .consent
        .preview
        .disclosure
        .retention
        .declaration
        .provenance = "openai-api-data-controls-2020-01-01".to_owned();
    exact_request.consent.preview.consent_envelope.retention =
        exact_request.consent.preview.disclosure.retention.clone();
    exact_request.validate().unwrap();

    let envelope = &exact_request.consent.preview.consent_envelope;
    let stored = database
        .preview_receipt_intelligence(
            &exact_request.request_id.to_string(),
            &envelope.source_revision_id.to_string(),
            repository_bounds(&envelope.preparation_bounds, &envelope.execution_bounds),
        )
        .unwrap();
    let reservation = ReceiptIntelligenceConsentReservation {
        request_id: exact_request.request_id.to_string(),
        command_sha256: hash_json(&exact_request).unwrap(),
        source_revision_id: envelope.source_revision_id.to_string(),
        source_revision_sha256: envelope.source_revision_sha256.as_str().to_owned(),
        preview_binding_sha256: stored.preview_binding_sha256,
        fragment_set_sha256: stored.fragment_set_sha256,
        projection_sha256: envelope.projection_sha256.as_str().to_owned(),
        serialized_request_sha256: envelope.serialized_request_sha256.as_str().to_owned(),
        serialized_request_bytes: envelope.serialized_request_bytes,
        credential_id: envelope.credential_id.to_string(),
        provider: envelope.provider.clone(),
        model: envelope.model.clone(),
        retention_mode: retention_mode(envelope.retention.declaration.mode).to_owned(),
        retention_provenance: envelope.retention.declaration.provenance.clone(),
        prompt_revision: envelope.prompt_revision.clone(),
        schema_revision: envelope.schema_revision.clone(),
        projection_revision: envelope.projection_revision.clone(),
        parameters_sha256: hash_json(&(
            RECEIPT_INTELLIGENCE_PARAMETER_REVISION_V1,
            &envelope.execution_bounds,
        ))
        .unwrap(),
        bounds: repository_bounds(&envelope.preparation_bounds, &envelope.execution_bounds),
        expires_at_ms: parse_timestamp(&envelope.expires_at).unwrap(),
    };
    let reserved_at_ms = reservation.expires_at_ms - APPROVAL_LIFETIME_MS;
    let dispatched_at_ms = reserved_at_ms + 1;
    let completed_at_ms = dispatched_at_ms + 1;
    let attempt = database
        .reserve_receipt_intelligence(&reservation, reserved_at_ms)
        .unwrap();
    database
        .mark_receipt_intelligence_dispatched(&attempt.attempt_id, dispatched_at_ms)
        .unwrap();
    database
        .complete_receipt_intelligence_without_order(
            &attempt.attempt_id,
            RepositoryClassification::Ambiguous,
            &ReceiptIntelligenceAuditMetadata {
                response_sha256: None,
                provider_request_id: Some("req_replay".to_owned()),
                response_id: Some("resp_replay".to_owned()),
                request_bytes: 2_048,
                response_bytes: 1_024,
                input_tokens: 100,
                output_tokens: 50,
                total_tokens: 150,
                reasoning_tokens: 10,
                cached_input_tokens: 0,
                attempt_count: 1,
                dispatched_at_ms,
            },
            completed_at_ms,
        )
        .unwrap();

    insert_changed_parse(&database);
    let changed_preview = coordinator
        .preview(PreviewReceiptIntelligenceV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(CHANGED_PREVIEW_REQUEST),
            source_id: source_id(SOURCE),
        })
        .unwrap();
    database
        .connection()
        .unwrap()
        .execute(
            "UPDATE credential_references SET status='pending_delete' WHERE credential_id=?1",
            [CREDENTIAL],
        )
        .unwrap();

    let preflight = coordinator
        .terminal_replay(&exact_request)
        .unwrap()
        .expect("completed command should replay before external checks");
    assert_eq!(
        preflight.replay_status,
        wardrobe_core::ReplayStatusV1::Replayed
    );
    let replay = coordinator.request(exact_request).await.unwrap();
    assert_eq!(
        replay.replay_status,
        wardrobe_core::ReplayStatusV1::Replayed
    );
    assert!(matches!(
        replay.outcome,
        ReceiptIntelligenceOutcomeV1::Completed { .. }
    ));

    let changed_request = RequestReceiptIntelligenceV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(EXECUTE_REQUEST),
        consent: wardrobe_core::ReceiptIntelligenceConsentV1 {
            affirmative: true,
            preview: changed_preview.preview,
        },
    };
    changed_request.validate().unwrap();
    assert!(matches!(
        coordinator.request(changed_request).await,
        Err(PlatformError::Conflict(
            "receipt_intelligence_command_changed"
        ))
    ));
    assert!(credential_observed.lock().unwrap().is_empty());
    assert_eq!(*provider_observed.lock().unwrap(), 0);
}

#[tokio::test]
async fn terminal_replay_lookup_returns_only_terminal_exact_commands() {
    let (_temporary, database) = fixture();
    let coordinator = ReceiptIntelligenceCoordinator::new(
        database.clone(),
        FakeCredentialStore {
            observed: Arc::new(Mutex::new(Vec::new())),
        },
        FixtureProvider {
            output: fixture_output(),
            observed: Arc::new(Mutex::new(0)),
        },
    );
    let preview = coordinator
        .preview(PreviewReceiptIntelligenceV1Request {
            schema_version: SCHEMA_VERSION_V1,
            request_id: request_id(PREVIEW_REQUEST),
            source_id: source_id(SOURCE),
        })
        .unwrap();
    let request = RequestReceiptIntelligenceV1Request {
        schema_version: SCHEMA_VERSION_V1,
        request_id: request_id(EXECUTE_REQUEST),
        consent: wardrobe_core::ReceiptIntelligenceConsentV1 {
            affirmative: true,
            preview: preview.preview,
        },
    };

    assert!(coordinator.terminal_replay(&request).unwrap().is_none());
}

#[test]
fn retention_declaration_has_a_closed_freshness_window() {
    let declared = Date::from_calendar_date(2026, Month::July, 16)
        .unwrap()
        .midnight()
        .assume_utc()
        .unix_timestamp()
        * 1_000;
    ensure_retention_declaration_current("openai-api-data-controls-2026-07-16", declared).unwrap();
    assert!(ensure_retention_declaration_current(
        "openai-api-data-controls-2026-07-16",
        declared + 90 * 86_400_000,
    )
    .is_ok());
    assert!(matches!(
        ensure_retention_declaration_current(
            "openai-api-data-controls-2026-07-16",
            declared + 91 * 86_400_000,
        ),
        Err(PlatformError::Conflict(
            "receipt_intelligence_retention_declaration_stale"
        ))
    ));
    assert!(ensure_retention_declaration_current(
        "openai-api-data-controls-2026-07-16",
        declared - 86_400_000,
    )
    .is_err());
}

#[tokio::test]
async fn list_reports_stale_retention_as_unavailable() {
    let (_temporary, database) = fixture();
    let coordinator = ReceiptIntelligenceCoordinator::new(
        database,
        FakeCredentialStore {
            observed: Arc::new(Mutex::new(Vec::new())),
        },
        FixtureProvider {
            output: fixture_output(),
            observed: Arc::new(Mutex::new(0)),
        },
    );
    let declared = Date::from_calendar_date(2026, Month::July, 16)
        .unwrap()
        .midnight()
        .assume_utc()
        .unix_timestamp()
        * 1_000;
    let response = coordinator
        .list_at(
            ListReceiptIntelligenceV1Request {
                schema_version: SCHEMA_VERSION_V1,
                request_id: RequestId::new_v4(),
                state: None,
                classification: None,
                cursor: None,
                limit: 20,
            },
            declared + 91 * 86_400_000,
        )
        .unwrap();

    assert!(!response.availability.available);
    assert_eq!(
        response.availability.reason,
        Some(
            wardrobe_core::ReceiptIntelligenceAvailabilityReasonV1::RetentionDeclarationUnavailable
        )
    );
    assert!(response.availability.offline_receipt_analysis_available);
    assert!(response.availability.existing_wardrobe_access_available);
}

fn fixture() -> (tempfile::TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let paths = PrivateAppPaths::create(temporary.path().join("app")).unwrap();
    let database = Database::open(&paths, 1).unwrap();
    let raw = format!(
        "From: orders@example.test\r\nSubject: Order confirmed\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{BODY}"
    );
    let blob = format!("{:x}", Sha256::digest(raw.as_bytes()));
    let revision_hash = format!("{:x}", Sha256::digest(b"revision graph"));
    let connection = database.connection().unwrap();
    connection
        .execute(
            "INSERT INTO blobs(sha256,byte_length,created_at_ms) VALUES(?1,?2,1)",
            params![blob, raw.len() as i64],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO local_sources(
                source_id,source_kind,identity_key,canonical_locator,raw_sha256,
                blob_sha256,byte_length,status,no_blob_reason,created_at_ms,updated_at_ms
             ) VALUES(?1,'eml','p11-coordinator','gmail:p11-coordinator',?2,?2,?3,
                'imported',NULL,1,1)",
            params![SOURCE, blob, raw.len() as i64],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO source_provenance(
                provenance_id,source_id,request_id,observed_locator,raw_sha256,
                blob_sha256,observed_at_ms
             ) VALUES(?1,?2,'p11-coordinator-import','gmail:p11-coordinator',?3,?3,1)",
            params![PROVENANCE, SOURCE, blob],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO gmail_accounts(account_key,created_at_ms) VALUES(?1,1)",
            ["b".repeat(64)],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO gmail_provider_sources(
                provider_source_id,account_key,gmail_message_id,created_at_ms
             ) VALUES(?1,?2,'p11-coordinator',1)",
            params![PROVIDER_SOURCE, "b".repeat(64)],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO gmail_source_revisions(
                revision_id,provider_source_id,history_id,availability,reason,
                graph_sha256,created_at_ms
             ) VALUES(?1,?2,'1','available','materialized',?3,1)",
            params![SOURCE_REVISION, PROVIDER_SOURCE, revision_hash],
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
                format!("{:x}", Sha256::digest(b"mime")),
                format!("{:x}", Sha256::digest(b"evidence"))
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO credential_references(
                locator,credential_id,save_request_id,provider,display_label,status,
                created_at_ms,updated_at_ms
             ) VALUES('p11-keychain-ref',?1,'p11-coordinator-save','open_ai',
                'OpenAI','active',1,1)",
            [CREDENTIAL],
        )
        .unwrap();
    drop(connection);

    let bundle = parse_receipt_bundle_v1(source_id(SOURCE), raw.as_bytes()).unwrap();
    let mut connection = database.connection().unwrap();
    let transaction = connection.transaction().unwrap();
    persist_parse(&transaction, &bundle.evidence, 1).unwrap();
    transaction.commit().unwrap();
    (temporary, database)
}

fn fixture_output() -> ReceiptIntelligenceOutput {
    ReceiptIntelligenceOutput {
        schema_revision: "receipt-intelligence-v1".to_owned(),
        classification: ReceiptIntelligenceClassification::ApparelOrder,
        classification_citations: citations("Order confirmed"),
        extraction: Some(ReceiptIntelligenceExtraction {
            merchant: string_evidence("Alpine Co", "Alpine Co"),
            order_identifier: string_evidence("A-19", "A-19"),
            purchase_date: string_evidence("2026-07-15", "2026-07-15"),
            currency: string_evidence("USD", "USD"),
            line_items: vec![ReceiptIntelligenceLineItem {
                description: string_evidence("Trail Tee", "Trail Tee"),
                event_kind: ReceiptIntelligenceEventEvidence {
                    value: Some(ReceiptIntelligenceEventKind::Purchase),
                    citations: citations("Order confirmed"),
                },
                quantity: ReceiptIntelligenceU64Evidence {
                    value: Some(2),
                    citations: citations("Qty: 2"),
                },
                unit_price_minor: ReceiptIntelligenceU64Evidence {
                    value: Some(2450),
                    citations: citations("$24.50"),
                },
                variant: ReceiptIntelligenceVariant {
                    brand: unknown_string(),
                    sku: string_evidence("TT-1", "TT-1"),
                    size: string_evidence("M", "Size: M"),
                    color: unknown_string(),
                },
            }],
        }),
    }
}

fn insert_changed_parse(database: &Database) {
    const CHANGED_PARSE: &str = "17000000-0000-4000-8000-000000000010";
    const CHANGED_FRAGMENT: &str = "17000000-0000-4000-8000-000000000011";
    let changed_body = "Changed receipt parse";
    let connection = database.connection().unwrap();
    connection
        .execute(
            "INSERT INTO receipt_parses(
                parse_id,source_id,raw_sha256,parser_revision,sanitizer_revision,
                canonical_input_sha256,created_at_ms
             )
             SELECT ?1,source_id,raw_sha256,'parser-changed',sanitizer_revision,?2,2
             FROM receipt_parses
             WHERE source_id=?3
             ORDER BY created_at_ms DESC,parse_id DESC
             LIMIT 1",
            params![
                CHANGED_PARSE,
                format!("{:x}", Sha256::digest(b"changed canonical input")),
                SOURCE
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO receipt_fragments(
                fragment_id,parse_id,ordinal,fragment_kind,content_text,
                content_sha256,metadata_json,byte_length
             ) VALUES(?1,?2,0,'plain_text',?3,?4,NULL,?5)",
            params![
                CHANGED_FRAGMENT,
                CHANGED_PARSE,
                changed_body,
                format!("{:x}", Sha256::digest(changed_body.as_bytes())),
                changed_body.len() as i64
            ],
        )
        .unwrap();
}

fn string_evidence(value: &str, quote: &str) -> ReceiptIntelligenceStringEvidence {
    ReceiptIntelligenceStringEvidence {
        value: Some(value.to_owned()),
        citations: citations(quote),
    }
}

fn unknown_string() -> ReceiptIntelligenceStringEvidence {
    ReceiptIntelligenceStringEvidence {
        value: None,
        citations: Vec::new(),
    }
}

fn citations(quote: &str) -> Vec<ReceiptIntelligenceCitation> {
    vec![ReceiptIntelligenceCitation {
        fragment_ref: "fragment-0000".to_owned(),
        quote: quote.to_owned(),
    }]
}

fn request_id(value: &str) -> RequestId {
    RequestId::new(uuid::Uuid::parse_str(value).unwrap()).unwrap()
}

fn source_id(value: &str) -> wardrobe_core::SourceId {
    wardrobe_core::SourceId::new(uuid::Uuid::parse_str(value).unwrap()).unwrap()
}

fn completed_response(output: ReceiptIntelligenceOutput) -> Value {
    json!({
        "id": "resp_coordinator_fixture",
        "model": RECEIPT_INTELLIGENCE_MODEL_V1,
        "status": "completed",
        "output": [{
            "id": "msg_coordinator_fixture",
            "type": "message",
            "role": "assistant",
            "status": "completed",
            "content": [{"type": "output_text", "text": serde_json::to_string(&output).unwrap()}]
        }],
        "usage": {
            "input_tokens": 100,
            "output_tokens": 50,
            "total_tokens": 150,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 10}
        }
    })
}

fn request_json(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}

struct ReceiptIntelligenceTlsFixture {
    socket: SocketAddr,
    server: tokio::task::JoinHandle<String>,
}

impl ReceiptIntelligenceTlsFixture {
    async fn start(response: Value) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socket = listener.local_addr().unwrap();
        let server_config = fixture_server_config();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = TlsAcceptor::from(Arc::new(server_config))
                .accept(stream)
                .await
                .unwrap();
            let request = read_request(&mut stream).await;
            let body = serde_json::to_vec(&response).unwrap();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nX-Request-Id: req_coordinator_fixture\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            let _ = stream.shutdown().await;
            String::from_utf8(request).unwrap()
        });
        Self { socket, server }
    }

    fn transport(&self) -> Result<OpenAiResponsesHttpTransport, OpenAiResponsesHttpError> {
        OpenAiResponsesHttpTransport::for_test(
            Url::parse(&format!("https://fixture.invalid:{}/", self.socket.port())).unwrap(),
            fixture_root_certificate(),
            self.socket,
        )
    }

    async fn finish(self) -> String {
        self.server.await.unwrap()
    }
}

async fn read_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
        assert!(request.len() <= OPENAI_REQUEST_LIMIT_BYTES + 16 * 1024);
    }
    let head_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let content_length = String::from_utf8_lossy(&request[..head_end])
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    while request.len() - head_end < content_length {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
        assert!(request.len() <= OPENAI_REQUEST_LIMIT_BYTES + 16 * 1024);
    }
    request
}

fn fixture_server_config() -> rustls::ServerConfig {
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(fixture_der("FIXTURE_LEAF_CERT_DER"))],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture_der(
                "FIXTURE_LEAF_KEY_DER",
            ))),
        )
        .unwrap()
}

fn fixture_root_certificate() -> reqwest::Certificate {
    reqwest::Certificate::from_der(&fixture_der("FIXTURE_CERT_DER")).unwrap()
}

fn fixture_der(name: &str) -> Vec<u8> {
    let source = include_str!("../tests/receipt_image_downloader.rs");
    let marker = format!("const {name}: &str = \"");
    let start = source.find(&marker).unwrap() + marker.len();
    let end = source[start..].find("\";").unwrap() + start;
    STANDARD.decode(&source[start..end]).unwrap()
}

#[allow(dead_code)]
fn _provider_marker(_: CredentialProviderV1) {}
