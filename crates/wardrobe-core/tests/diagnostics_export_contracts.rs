use serde_json::json;
use wardrobe_core::{
    DeletionHealthV1, DiagnosticComponentV1, DiagnosticEventCodeV1, DiagnosticOutcomeV1,
    DiagnosticSeverityV1, DiagnosticsCounterNameV1, DiagnosticsCounterV1, DiagnosticsEventCountV1,
    DiagnosticsExportV1, DiagnosticsHealthStateV1, DiagnosticsHealthV1, DiagnosticsJobFailureV1,
    DiagnosticsLogSummaryV1, DiagnosticsVersionsV1, ErrorCodeV1, ExportDiagnosticsV1Request,
    ExportDiagnosticsV1Response, JobKindV1, SafeFieldV1, Sha256Digest, UserActionKeyV1, Validate,
    DIAGNOSTICS_EXPORT_MEDIA_TYPE_V1, MAX_SAFE_INTEGER_V1,
};

const REQUEST_ID: &str = "f371ec3d-b0e1-4aac-9694-93cce7e04de1";

#[test]
fn export_request_is_strict_and_response_is_path_free() {
    let request: ExportDiagnosticsV1Request = serde_json::from_value(json!({
        "schema_version": 1,
        "request_id": REQUEST_ID,
        "destination_path": "/Users/test/Downloads/wardrobe-diagnostics.json"
    }))
    .unwrap();
    request.validate().unwrap();

    let mut unknown = serde_json::to_value(&request).unwrap();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("include_raw_logs".to_owned(), json!(true));
    assert!(serde_json::from_value::<ExportDiagnosticsV1Request>(unknown).is_err());

    let response = ExportDiagnosticsV1Response {
        schema_version: 1,
        request_id: request.request_id,
        generated_at: "2026-07-15T18:20:00Z".to_owned(),
        complete: true,
        media_type: DIAGNOSTICS_EXPORT_MEDIA_TYPE_V1.to_owned(),
        byte_length: 512,
        sha256: Sha256Digest::parse("a".repeat(64)).unwrap(),
    };
    response.validate().unwrap();
    let encoded = serde_json::to_value(response).unwrap();
    for forbidden in [
        "destination",
        "destination_path",
        "filename",
        "content",
        "credential",
    ] {
        assert!(encoded.get(forbidden).is_none());
    }
}

#[test]
fn export_request_rejects_oversized_and_nul_destinations() {
    for destination_path in ["x".repeat(4097), "bad\0name.json".to_owned()] {
        let request = ExportDiagnosticsV1Request {
            schema_version: 1,
            request_id: serde_json::from_str(&format!("\"{REQUEST_ID}\"")).unwrap(),
            destination_path,
        };
        assert_eq!(request.validate().unwrap_err().field, SafeFieldV1::Path);
    }
}

#[test]
fn report_requires_fixed_counters_and_sorted_bounded_groups() {
    let mut report = sample_report();
    report.validate().unwrap();

    report.job_failures.push(report.job_failures[0].clone());
    assert_eq!(
        report.validate().unwrap_err().field,
        SafeFieldV1::Collection
    );
    report.job_failures.pop();

    report.health.diagnostic_log.event_counts[0].count = MAX_SAFE_INTEGER_V1;
    assert_eq!(report.validate().unwrap_err().field, SafeFieldV1::Limit);
    report.health.diagnostic_log.event_counts[0].count = 1;

    report.counters.pop();
    assert_eq!(
        report.validate().unwrap_err().field,
        SafeFieldV1::Collection
    );

    let mut encoded = serde_json::to_value(sample_report()).unwrap();
    encoded["job_failures"][0]
        .as_object_mut()
        .unwrap()
        .insert("private_detail".to_owned(), json!("must be rejected"));
    assert!(serde_json::from_value::<DiagnosticsExportV1>(encoded).is_err());

    let mut invalid_try_on = sample_report();
    invalid_try_on.job_failures = vec![DiagnosticsJobFailureV1::TryOn {
        code: wardrobe_core::TryOnFailureCodeV1::RateLimited,
        retryable: false,
        user_action: wardrobe_core::TryOnUserActionV1::None,
        attempt_count: 1,
        occurrence_count: 1,
    }];
    assert!(invalid_try_on.validate().is_err());
}

fn sample_report() -> DiagnosticsExportV1 {
    DiagnosticsExportV1 {
        schema_version: 1,
        generated_at: "2026-07-15T18:20:00Z".to_owned(),
        versions: DiagnosticsVersionsV1 {
            export_schema_version: 1,
            application_version: "0.1.0".to_owned(),
            database_schema_version: 11,
            migration_prefix_sha256: Sha256Digest::parse("b".repeat(64)).unwrap(),
            diagnostic_event_schema_version: 1,
        },
        health: DiagnosticsHealthV1 {
            database_integrity: DiagnosticsHealthStateV1::Ready,
            foreign_keys: DiagnosticsHealthStateV1::Ready,
            storage_check: DiagnosticsHealthStateV1::NeverRun,
            deletion: DeletionHealthV1::none(),
            diagnostic_log: DiagnosticsLogSummaryV1 {
                status: DiagnosticsHealthStateV1::Ready,
                event_counts: vec![DiagnosticsEventCountV1 {
                    severity: DiagnosticSeverityV1::Error,
                    component: DiagnosticComponentV1::Database,
                    event_code: DiagnosticEventCodeV1::CommandFailed,
                    outcome: DiagnosticOutcomeV1::Failed,
                    count: 1,
                }],
                dropped_since_process_start: 0,
                malformed_line_count: 0,
                truncated_line_count: 0,
            },
        },
        counters: DiagnosticsCounterNameV1::ALL
            .iter()
            .copied()
            .map(|name| DiagnosticsCounterV1 { name, value: 0 })
            .collect(),
        job_failures: vec![DiagnosticsJobFailureV1::Foundation {
            kind: JobKindV1::VerifyBlobV1,
            code: ErrorCodeV1::NotFound,
            user_action: UserActionKeyV1::ReviewStorage,
            attempt_count: 1,
            occurrence_count: 1,
        }],
    }
}
