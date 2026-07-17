use serde_json::json;
use wardrobe_core::*;

const REQUEST_ID: &str = "a5b238c1-df7e-4ec8-8330-abe67f7ad536";
const CLIENT_ID: &str = "1234567890-desktop_client.apps.googleusercontent.com";

fn limits() -> GmailConnectorLimitsV1 {
    GmailConnectorLimitsV1 {
        page_size: 100,
        max_pages: 10,
        max_unique_messages: 200,
        max_total_raw_bytes: 100 * 1024 * 1024,
    }
}

fn save_request() -> SaveGmailSettingsV1Request {
    SaveGmailSettingsV1Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        client_id: CLIENT_ID.to_owned(),
        label_name: "Wardrobe Receipts".to_owned(),
        limits: limits(),
    }
}

fn save_v2_value(discovery_scope: serde_json::Value) -> serde_json::Value {
    json!({
        "schema_version": 2,
        "request_id": REQUEST_ID,
        "client_id": CLIENT_ID,
        "discovery_scope": discovery_scope,
        "limits": {
            "page_size": 50,
            "max_pages": 5,
            "max_unique_messages": 100,
            "max_total_raw_bytes": 1048576
        }
    })
}

#[test]
fn gmail_requests_and_nested_values_reject_unknown_fields() {
    let envelopes = [
        json!({"schema_version": 1, "request_id": REQUEST_ID, "extra": true}),
        json!({"schema_version": 1, "request_id": REQUEST_ID, "extra": true}),
        json!({"schema_version": 1, "request_id": REQUEST_ID, "extra": true}),
        json!({"schema_version": 1, "request_id": REQUEST_ID, "extra": true}),
    ];
    assert!(serde_json::from_value::<GetGmailConnectorV1Request>(envelopes[0].clone()).is_err());
    assert!(serde_json::from_value::<ConnectGmailV1Request>(envelopes[1].clone()).is_err());
    assert!(serde_json::from_value::<SyncGmailV1Request>(envelopes[2].clone()).is_err());
    assert!(serde_json::from_value::<DisconnectGmailV1Request>(envelopes[3].clone()).is_err());

    let request = json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "client_id": CLIENT_ID,
        "label_name": "Wardrobe Receipts",
        "limits": {
            "page_size": 50,
            "max_pages": 5,
            "max_unique_messages": 100,
            "max_total_raw_bytes": 1048576,
            "extra": 1
        }
    });
    assert!(serde_json::from_value::<SaveGmailSettingsV1Request>(request).is_err());
}

#[test]
fn gmail_v2_discovery_scopes_have_exact_strict_tagged_wire_shapes() {
    let search = json!({"kind": "search", "query": "from:orders@example.com"});
    let label = json!({"kind": "label", "label_name": "Wardrobe Receipts"});

    let search_scope = serde_json::from_value::<GmailDiscoveryScopeV2>(search.clone()).unwrap();
    let label_scope = serde_json::from_value::<GmailDiscoveryScopeV2>(label.clone()).unwrap();
    assert_eq!(
        search_scope,
        GmailDiscoveryScopeV2::Search {
            query: "from:orders@example.com".to_owned()
        }
    );
    assert_eq!(
        label_scope,
        GmailDiscoveryScopeV2::Label {
            label_name: "Wardrobe Receipts".to_owned()
        }
    );
    assert_eq!(serde_json::to_value(search_scope).unwrap(), search);
    assert_eq!(serde_json::to_value(label_scope).unwrap(), label);

    for invalid in [
        json!({"kind": "search", "query": "from:orders@example.com", "label_name": "Receipts"}),
        json!({"kind": "label", "label_name": "Receipts", "query": "from:orders@example.com"}),
        json!({"kind": "search", "query": "from:orders@example.com", "extra": true}),
        json!({"kind": "unknown", "query": "from:orders@example.com"}),
        json!({"query": "from:orders@example.com"}),
        json!({"kind": "search"}),
        json!({"kind": "label"}),
    ] {
        assert!(
            serde_json::from_value::<GmailDiscoveryScopeV2>(invalid.clone()).is_err(),
            "accepted {invalid}"
        );
    }
}

#[test]
fn gmail_v2_requests_settings_and_responses_reject_unknown_fields() {
    let mut request = save_v2_value(json!({
        "kind": "search",
        "query": "from:orders@example.com"
    }));
    request["extra"] = json!(true);
    assert!(serde_json::from_value::<SaveGmailSettingsV2Request>(request).is_err());

    let settings = json!({
        "provider_profile": "google",
        "oauth_client_id": CLIENT_ID,
        "discovery_scope": {
            "kind": "label",
            "label_name": "Wardrobe Receipts"
        },
        "limits": {
            "page_size": 50,
            "max_pages": 5,
            "max_unique_messages": 100,
            "max_total_raw_bytes": 1048576
        },
        "extra": true
    });
    assert!(serde_json::from_value::<GmailConnectorSettingsV2>(settings).is_err());

    let get = json!({
        "schema_version": 2,
        "request_id": REQUEST_ID,
        "extra": true
    });
    assert!(serde_json::from_value::<GetGmailConnectorV2Request>(get).is_err());

    let response = json!({
        "schema_version": 2,
        "request_id": REQUEST_ID,
        "settings": null,
        "status": "not_configured",
        "user_action": "configure_gmail",
        "extra": true
    });
    assert!(serde_json::from_value::<GetGmailConnectorV2Response>(response).is_err());
}

#[test]
fn gmail_search_queries_use_utf8_byte_boundaries_and_reject_controls() {
    for query in [
        "x".to_owned(),
        " ".to_owned(),
        "x".repeat(MAX_GMAIL_QUERY_BYTES),
        "\u{00e9}".repeat(MAX_GMAIL_QUERY_BYTES / 2),
    ] {
        assert!(
            GmailDiscoveryScopeV2::Search {
                query: query.clone()
            }
            .validate()
            .is_ok(),
            "rejected {} bytes",
            query.len()
        );
    }

    for query in [
        String::new(),
        "x".repeat(MAX_GMAIL_QUERY_BYTES + 1),
        "\u{00e9}".repeat(MAX_GMAIL_QUERY_BYTES / 2 + 1),
    ] {
        assert_eq!(
            GmailDiscoveryScopeV2::Search { query }
                .validate()
                .unwrap_err()
                .field,
            SafeFieldV1::GmailQuery
        );
    }

    for control in ['\0', '\t', '\n', '\r', '\u{007f}', '\u{0085}'] {
        let query = format!("from:orders{control}after:2026/01/01");
        assert_eq!(
            GmailDiscoveryScopeV2::Search { query }
                .validate()
                .unwrap_err()
                .field,
            SafeFieldV1::GmailQuery,
            "accepted U+{:04X}",
            u32::from(control)
        );
    }
}

#[test]
fn gmail_search_query_whitespace_is_preserved_without_normalization() {
    let query = "  from:orders@example.com  subject:\"Order ready\"  ";
    let value = save_v2_value(json!({"kind": "search", "query": query}));
    let request: SaveGmailSettingsV2Request = serde_json::from_value(value).unwrap();

    assert!(request.validate().is_ok());
    assert_eq!(
        request.discovery_scope,
        GmailDiscoveryScopeV2::Search {
            query: query.to_owned()
        }
    );
    assert_eq!(
        serde_json::to_value(request).unwrap()["discovery_scope"]["query"],
        json!(query)
    );
}

#[test]
fn gmail_v2_schema_versions_are_strict_at_decode_and_validation() {
    for schema_version in [0, 1, 3, u8::MAX] {
        let mut save = save_v2_value(json!({
            "kind": "label",
            "label_name": "Wardrobe Receipts"
        }));
        save["schema_version"] = json!(schema_version);
        assert!(
            serde_json::from_value::<SaveGmailSettingsV2Request>(save).is_err(),
            "accepted schema {schema_version}"
        );

        let get = json!({
            "schema_version": schema_version,
            "request_id": REQUEST_ID
        });
        assert!(
            serde_json::from_value::<GetGmailConnectorV2Request>(get).is_err(),
            "accepted schema {schema_version}"
        );

        let response = json!({
            "schema_version": schema_version,
            "request_id": REQUEST_ID,
            "settings": null,
            "status": "not_configured",
            "user_action": "configure_gmail"
        });
        assert!(
            serde_json::from_value::<GetGmailConnectorV2Response>(response).is_err(),
            "accepted response schema {schema_version}"
        );
    }

    let request = SaveGmailSettingsV2Request {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        client_id: CLIENT_ID.to_owned(),
        discovery_scope: GmailDiscoveryScopeV2::Label {
            label_name: "Wardrobe Receipts".to_owned(),
        },
        limits: limits(),
    };
    assert_eq!(
        request.validate().unwrap_err().field,
        SafeFieldV1::SchemaVersion
    );
}

#[test]
fn gmail_settings_accept_only_google_desktop_client_ids_and_bounded_labels() {
    assert!(save_request().validate().is_ok());

    for invalid in [
        "",
        "desktop-client",
        ".apps.googleusercontent.com",
        "desktop client.apps.googleusercontent.com",
        "desktop.client.apps.googleusercontent.com",
        "desktop.apps.googleusercontent.com.example",
    ] {
        let mut request = save_request();
        request.client_id = invalid.to_owned();
        assert_eq!(
            request.validate().unwrap_err().field,
            SafeFieldV1::GmailClientId,
            "accepted {invalid:?}"
        );
    }

    let mut request = save_request();
    request.client_id = format!(
        "{}.apps.googleusercontent.com",
        "x".repeat(MAX_GMAIL_OAUTH_CLIENT_ID_BYTES)
    );
    assert_eq!(
        request.validate().unwrap_err().field,
        SafeFieldV1::GmailClientId
    );

    for invalid in ["", " Wardrobe Receipts", "Wardrobe\nReceipts"] {
        let mut request = save_request();
        request.label_name = invalid.to_owned();
        assert_eq!(
            request.validate().unwrap_err().field,
            SafeFieldV1::GmailLabelName
        );
    }
}

#[test]
fn every_gmail_limit_is_closed_and_nonzero() {
    let valid = [
        GmailConnectorLimitsV1 {
            page_size: 1,
            max_pages: 1,
            max_unique_messages: 1,
            max_total_raw_bytes: 1,
        },
        limits(),
    ];
    assert!(valid.into_iter().all(|value| value.validate().is_ok()));

    let invalid = [
        GmailConnectorLimitsV1 {
            page_size: 0,
            ..limits()
        },
        GmailConnectorLimitsV1 {
            page_size: MAX_GMAIL_PAGE_SIZE + 1,
            ..limits()
        },
        GmailConnectorLimitsV1 {
            max_pages: 0,
            ..limits()
        },
        GmailConnectorLimitsV1 {
            max_pages: MAX_GMAIL_PAGES + 1,
            ..limits()
        },
        GmailConnectorLimitsV1 {
            max_unique_messages: 0,
            ..limits()
        },
        GmailConnectorLimitsV1 {
            max_unique_messages: MAX_GMAIL_UNIQUE_MESSAGES + 1,
            ..limits()
        },
        GmailConnectorLimitsV1 {
            max_total_raw_bytes: 0,
            ..limits()
        },
        GmailConnectorLimitsV1 {
            max_total_raw_bytes: MAX_GMAIL_TOTAL_RAW_BYTES + 1,
            ..limits()
        },
    ];
    for value in invalid {
        assert_eq!(
            value.validate().unwrap_err().field,
            SafeFieldV1::GmailLimits
        );
    }
}

#[test]
fn summaries_and_status_actions_are_validated() {
    let mut summary = GmailSyncSummaryV1 {
        pages_scanned: 2,
        unique_messages: 3,
        messages_imported: 1,
        messages_updated: 1,
        messages_unavailable: 1,
        raw_bytes_read: 512,
    };
    assert!(summary.validate().is_ok());
    summary.messages_unavailable = 2;
    assert_eq!(
        summary.validate().unwrap_err().field,
        SafeFieldV1::GmailSummary
    );

    let invalid_status = GetGmailConnectorV1Response {
        schema_version: 1,
        request_id: RequestId::new_v4(),
        settings: None,
        status: GmailConnectorStatusV1::Disconnected,
        user_action: UserActionKeyV1::ConnectGmail,
    };
    assert_eq!(
        invalid_status.validate().unwrap_err().field,
        SafeFieldV1::GmailStatus
    );
}

#[test]
fn raw_gmail_credentials_are_rejected_as_provider_input() {
    let request: SaveCredentialV1Request = serde_json::from_value(json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "provider": "gmail",
        "display_label": "Gmail",
        "secret": "must-not-be-persisted"
    }))
    .unwrap();

    assert_eq!(request.validate().unwrap_err().field, SafeFieldV1::Provider);
}

#[test]
fn local_only_revocation_outcome_has_an_exact_distinct_wire_value() {
    assert_eq!(
        serde_json::to_value(GmailRevocationOutcomeV1::NotAttemptedLocalOnly).unwrap(),
        json!("not_attempted_local_only")
    );
    assert_eq!(
        serde_json::from_value::<GmailRevocationOutcomeV1>(json!("not_attempted_local_only"))
            .unwrap(),
        GmailRevocationOutcomeV1::NotAttemptedLocalOnly
    );
    assert!(typescript_bindings().contains(
        "\"succeeded\" | \"already_invalid\" | \"failed\" | \"not_attempted_local_only\""
    ));
}

#[test]
fn gmail_types_are_in_generated_typescript_declarations() {
    let bindings = typescript_bindings();
    for name in [
        "GmailConnectorLimitsV1",
        "GmailConnectorSettingsV1",
        "GmailConnectorSettingsV2",
        "GmailDiscoveryScopeV2",
        "GetGmailConnectorV1Request",
        "GetGmailConnectorV2Request",
        "SaveGmailSettingsV1Request",
        "SaveGmailSettingsV2Request",
        "GetGmailConnectorV2Response",
        "SaveGmailSettingsV2Response",
        "ConnectGmailV1Response",
        "SyncGmailV1Response",
        "DisconnectGmailV1Response",
    ] {
        assert!(bindings.contains(name), "missing {name}");
    }
    assert!(bindings.contains(r#""kind": "search""#));
    assert!(bindings.contains(r#""kind": "label""#));
    assert!(bindings.contains("query: string"));
    assert!(bindings.contains("label_name: string"));
    assert!(bindings.contains("schema_version: 2"));
}

#[test]
fn gmail_v1_label_contract_remains_wire_compatible() {
    let request = save_request();
    let value = serde_json::to_value(&request).unwrap();

    assert_eq!(value["schema_version"], json!(1));
    assert_eq!(value["client_id"], json!(CLIENT_ID));
    assert_eq!(value["label_name"], json!("Wardrobe Receipts"));
    assert!(value.get("discovery_scope").is_none());
    assert_eq!(
        serde_json::from_value::<SaveGmailSettingsV1Request>(value).unwrap(),
        request
    );
}
