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
        "GetGmailConnectorV1Request",
        "SaveGmailSettingsV1Request",
        "ConnectGmailV1Response",
        "SyncGmailV1Response",
        "DisconnectGmailV1Response",
    ] {
        assert!(bindings.contains(name), "missing {name}");
    }
}
