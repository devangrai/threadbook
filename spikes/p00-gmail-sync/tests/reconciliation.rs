use p00_gmail_sync::{
    CommitFault, FallbackReason, GatewayError, GmailMessage, HistoryEvent, HistoryEventKind,
    HistoryPage, MessagePage, ScriptStep, ScriptedGmailGateway, SqliteSyncStore, SyncCoordinator,
    SyncErrorKind, SyncKey, SyncLimits, SyncOutcome,
};
use serde_json::{json, Value};
use std::path::Path;
use tempfile::TempDir;

fn store(temp: &TempDir) -> SqliteSyncStore {
    SqliteSyncStore::open(temp.path().join("gmail.sqlite")).unwrap()
}

fn message(id: &str, history_id: &str, fingerprint: &str) -> GmailMessage {
    GmailMessage {
        id: id.into(),
        history_id: history_id.into(),
        thread_id: "shared-thread".into(),
        rfc_message_id: "shared-rfc-message-id".into(),
        evidence_fingerprint: fingerprint.into(),
    }
}

fn page(ids: &[&str], next: Option<&str>) -> MessagePage {
    MessagePage {
        message_ids: ids.iter().map(|id| (*id).into()).collect(),
        next_page_token: next.map(str::to_owned),
    }
}

fn history(events: Vec<HistoryEvent>, next: Option<&str>, cursor: &str) -> HistoryPage {
    HistoryPage {
        events,
        next_page_token: next.map(str::to_owned),
        mailbox_history_id: cursor.into(),
    }
}

fn event(history_id: &str, message_id: &str, kind: HistoryEventKind) -> HistoryEvent {
    HistoryEvent {
        history_id: history_id.into(),
        message_id: message_id.into(),
        kind,
    }
}

fn expired_scan_steps(
    old_cursor: &str,
    anchor: &str,
    messages: &[(&str, &str, &str)],
) -> Vec<ScriptStep> {
    let mut steps = vec![
        ScriptStep::ListHistory {
            start: old_cursor.into(),
            token: None,
            result: Err(GatewayError::CursorExpired),
        },
        ScriptStep::Profile(Ok(anchor.into())),
        ScriptStep::ListMessages {
            token: None,
            result: Ok(page(
                &messages.iter().map(|item| item.0).collect::<Vec<_>>(),
                None,
            )),
        },
    ];
    steps.extend(
        messages
            .iter()
            .map(|(id, revision, fingerprint)| ScriptStep::GetMessage {
                id: (*id).into(),
                result: Ok(message(id, revision, fingerprint)),
            }),
    );
    steps
}

fn emit(test: &str, scenario: &str, mut fields: Value) {
    let object = fields.as_object_mut().unwrap();
    object.insert("test".into(), json!(test));
    object.insert("scenario".into(), json!(scenario));
    object.insert("status".into(), json!("pass"));
    println!(
        "\nP00_GML_EVIDENCE {}",
        serde_json::to_string(&fields).unwrap()
    );
}

#[test]
fn expired_cursor_bounded_reconciliation() {
    let temp = TempDir::new().unwrap();
    let store = store(&temp);
    let key = SyncKey::gmail("acct-expired", "receipt-scope");
    store.seed_checkpoint(&key, "10").unwrap();
    let mut gateway = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "10".into(),
            token: None,
            result: Err(GatewayError::CursorExpired),
        },
        ScriptStep::Profile(Ok("20".into())),
        ScriptStep::ListMessages {
            token: None,
            result: Ok(page(&["m-a", "m-b"], Some("page-2"))),
        },
        ScriptStep::GetMessage {
            id: "m-a".into(),
            result: Ok(message("m-a", "12", "fp-a")),
        },
        ScriptStep::GetMessage {
            id: "m-b".into(),
            result: Ok(message("m-b", "13", "fp-b")),
        },
        ScriptStep::ListMessages {
            token: Some("page-2".into()),
            result: Ok(page(&["m-b", "m-c"], None)),
        },
        ScriptStep::GetMessage {
            id: "m-c".into(),
            result: Ok(message("m-c", "19", "fp-c")),
        },
    ]);
    let outcome = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap();
    let report = match outcome {
        SyncOutcome::Reconciled(report) => report,
        _ => panic!("expected reconciliation"),
    };
    gateway.assert_exhausted();
    let snapshot = store.snapshot(&key).unwrap();
    let audit = store.audit().unwrap();
    assert_eq!(
        report.diagnostic.fallback,
        Some(FallbackReason::ExpiredCursor)
    );
    assert_eq!(snapshot.cursor.as_deref(), Some("20"));
    assert_eq!(snapshot.sources.len(), 3);
    assert_eq!(snapshot.revision_count, 3);
    assert_eq!(audit.integrity_check, "ok");
    assert_eq!(audit.foreign_key_violations, 0);

    emit(
        "expired_cursor_bounded_reconciliation",
        "expired_cursor_bounded_reconciliation",
        json!({
            "database": "sqlite",
            "integrity_check": audit.integrity_check,
            "foreign_key_violations": audit.foreign_key_violations,
            "fallback": "expired_cursor",
            "bounded": report.diagnostic.pages <= SyncLimits::EVALUATOR.max_pages
                && report.diagnostic.unique_messages <= SyncLimits::EVALUATOR.max_unique_messages
                && report.diagnostic.gateway_calls <= SyncLimits::EVALUATOR.max_gateway_calls,
            "source_count": audit.source_count,
            "revision_count": audit.revision_count,
            "cursor": snapshot.cursor.unwrap(),
            "pages": report.diagnostic.pages,
            "unique_messages": report.diagnostic.unique_messages,
            "duplicate_source_count": audit.source_count - snapshot.sources.len(),
        }),
    );
}

#[test]
fn malformed_cursor_fallback() {
    let temp = TempDir::new().unwrap();
    let store = store(&temp);
    let key = SyncKey::gmail("acct-malformed", "scope");
    store.seed_checkpoint(&key, "not-decimal").unwrap();
    let mut gateway = ScriptedGmailGateway::new([
        ScriptStep::Profile(Ok("30".into())),
        ScriptStep::ListMessages {
            token: None,
            result: Ok(page(&["m-1"], None)),
        },
        ScriptStep::GetMessage {
            id: "m-1".into(),
            result: Ok(message("m-1", "25", "fp-1")),
        },
    ]);
    let outcome = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap();
    let report = outcome.report();
    let calls = gateway.calls();
    gateway.assert_exhausted();
    let snapshot = store.snapshot(&key).unwrap();
    assert!(matches!(outcome, SyncOutcome::Reconciled(_)));
    assert_eq!(
        report.diagnostic.fallback,
        Some(FallbackReason::MalformedCursor)
    );
    assert_eq!(calls.list_history, 0);
    assert_eq!(snapshot.cursor.as_deref(), Some("30"));

    emit(
        "malformed_cursor_fallback",
        "malformed_cursor_fallback",
        json!({
            "fallback": "malformed_cursor",
            "history_calls": calls.list_history,
            "source_count": snapshot.sources.len(),
            "revision_count": snapshot.revision_count,
            "cursor": snapshot.cursor.unwrap(),
            "bounded": report.diagnostic.gateway_calls <= SyncLimits::EVALUATOR.max_gateway_calls,
        }),
    );
}

#[test]
fn invalid_cursor_fallback() {
    let temp = TempDir::new().unwrap();
    let store = store(&temp);
    let key = SyncKey::gmail("acct-invalid", "scope");
    store.seed_checkpoint(&key, "31").unwrap();
    let mut gateway = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "31".into(),
            token: None,
            result: Err(GatewayError::CursorInvalid),
        },
        ScriptStep::Profile(Ok("35".into())),
        ScriptStep::ListMessages {
            token: None,
            result: Ok(page(&["m-invalid"], None)),
        },
        ScriptStep::GetMessage {
            id: "m-invalid".into(),
            result: Ok(message("m-invalid", "34", "fp-invalid")),
        },
    ]);
    let outcome = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap();
    let report = outcome.report();
    let calls = gateway.calls();
    gateway.assert_exhausted();
    let snapshot = store.snapshot(&key).unwrap();
    assert!(matches!(outcome, SyncOutcome::Reconciled(_)));
    assert_eq!(
        report.diagnostic.fallback,
        Some(FallbackReason::InvalidCursor)
    );
    assert_eq!(calls.list_history, 1);
    assert_eq!(snapshot.cursor.as_deref(), Some("35"));
    assert_eq!(snapshot.sources.len(), 1);
    assert_eq!(snapshot.revision_count, 1);

    emit(
        "invalid_cursor_fallback",
        "invalid_cursor_fallback",
        json!({
            "fallback": "invalid_cursor",
            "history_calls": calls.list_history,
            "source_count": snapshot.sources.len(),
            "revision_count": snapshot.revision_count,
            "cursor": snapshot.cursor.unwrap(),
            "bounded": report.diagnostic.gateway_calls <= SyncLimits::EVALUATOR.max_gateway_calls,
        }),
    );
}

#[test]
fn valid_incremental_exclusive_anchor() {
    let temp = TempDir::new().unwrap();
    let store = store(&temp);
    let key = SyncKey::gmail("acct-incremental", "scope");
    store.seed_checkpoint(&key, "40").unwrap();
    let mut gateway = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "40".into(),
            token: None,
            result: Ok(history(
                vec![
                    event("40", "anchor-message", HistoryEventKind::Upsert),
                    event("41", "post-anchor", HistoryEventKind::Upsert),
                ],
                None,
                "45",
            )),
        },
        ScriptStep::GetMessage {
            id: "post-anchor".into(),
            result: Ok(message("post-anchor", "41", "fp-post")),
        },
    ]);
    let outcome = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap();
    let calls = gateway.calls();
    gateway.assert_exhausted();
    let snapshot = store.snapshot(&key).unwrap();
    assert!(matches!(outcome, SyncOutcome::Incremental(_)));
    assert_eq!(calls.profile, 0);
    assert_eq!(calls.list_messages, 0);
    assert_eq!(calls.get_message, 1);
    assert_eq!(snapshot.sources[0].provider_source_id, "post-anchor");
    assert_eq!(snapshot.cursor.as_deref(), Some("45"));

    emit(
        "valid_incremental_exclusive_anchor",
        "valid_incremental_exclusive_anchor",
        json!({
            "fallback": Value::Null,
            "exclusive_anchor": true,
            "anchor_event_applied": false,
            "post_anchor_event_applied": true,
            "history_calls": calls.list_history,
            "message_get_calls": calls.get_message,
            "source_count": snapshot.sources.len(),
            "revision_count": snapshot.revision_count,
            "cursor": snapshot.cursor.unwrap(),
        }),
    );
}

#[test]
fn conflicting_duplicate_history_kinds_preserve_state() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("gmail.sqlite");
    let store = SqliteSyncStore::open(&path).unwrap();
    let key = SyncKey::gmail("acct-conflicting-events", "scope");
    store.seed_checkpoint(&key, "10").unwrap();
    let mut gateway = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "10".into(),
            token: None,
            result: Ok(history(
                vec![
                    event("11", "message", HistoryEventKind::Upsert),
                    event("11", "message", HistoryEventKind::Deleted),
                ],
                None,
                "12",
            )),
        },
        ScriptStep::GetMessage {
            id: "message".into(),
            result: Ok(message("message", "11", "fp-message")),
        },
    ]);
    let error = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap_err();
    gateway.assert_exhausted();
    assert_eq!(error.kind, SyncErrorKind::Invariant);
    assert_unchanged(&path, &key);
}

#[test]
fn incremental_get_message_id_mismatch_preserves_state() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("gmail.sqlite");
    let store = SqliteSyncStore::open(&path).unwrap();
    let key = SyncKey::gmail("acct-incremental-mismatch", "scope");
    store.seed_checkpoint(&key, "10").unwrap();
    let mut gateway = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "10".into(),
            token: None,
            result: Ok(history(
                vec![event("11", "requested", HistoryEventKind::Upsert)],
                None,
                "12",
            )),
        },
        ScriptStep::GetMessage {
            id: "requested".into(),
            result: Ok(message("different", "11", "fp-message")),
        },
    ]);
    let error = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap_err();
    gateway.assert_exhausted();
    assert_eq!(error.kind, SyncErrorKind::Invariant);
    assert_unchanged(&path, &key);
}

#[test]
fn reconciliation_get_message_id_mismatch_preserves_state() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("gmail.sqlite");
    let store = SqliteSyncStore::open(&path).unwrap();
    let key = SyncKey::gmail("acct-reconciliation-mismatch", "scope");
    store.seed_checkpoint(&key, "10").unwrap();
    let mut gateway = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "10".into(),
            token: None,
            result: Err(GatewayError::CursorExpired),
        },
        ScriptStep::Profile(Ok("20".into())),
        ScriptStep::ListMessages {
            token: None,
            result: Ok(page(&["requested"], None)),
        },
        ScriptStep::GetMessage {
            id: "requested".into(),
            result: Ok(message("different", "15", "fp-message")),
        },
    ]);
    let error = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap_err();
    gateway.assert_exhausted();
    assert_eq!(error.kind, SyncErrorKind::Invariant);
    assert_unchanged(&path, &key);
}

#[test]
fn duplicate_identity_and_replay() {
    let temp = TempDir::new().unwrap();
    let store = store(&temp);
    let key = SyncKey::gmail("acct-replay", "scope");
    store.seed_checkpoint(&key, "50").unwrap();
    let mut first = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "50".into(),
            token: None,
            result: Err(GatewayError::CursorExpired),
        },
        ScriptStep::Profile(Ok("80".into())),
        ScriptStep::ListMessages {
            token: None,
            result: Ok(page(&["x", "y"], Some("overlap"))),
        },
        ScriptStep::GetMessage {
            id: "x".into(),
            result: Ok(message("x", "81", "fp-x")),
        },
        ScriptStep::GetMessage {
            id: "y".into(),
            result: Ok(message("y", "70", "fp-y")),
        },
        ScriptStep::ListMessages {
            token: Some("overlap".into()),
            result: Ok(page(&["x", "y"], None)),
        },
    ]);
    SyncCoordinator::new(&mut first, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap();
    first.assert_exhausted();
    let first_snapshot = store.snapshot(&key).unwrap();
    let stable_ids = first_snapshot
        .sources
        .iter()
        .map(|source| source.source_id.clone())
        .collect::<Vec<_>>();

    let mut replay = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "80".into(),
            token: None,
            result: Ok(history(
                vec![
                    event("80", "x", HistoryEventKind::Upsert),
                    event("81", "x", HistoryEventKind::Upsert),
                    event("81", "x", HistoryEventKind::Upsert),
                ],
                None,
                "90",
            )),
        },
        ScriptStep::GetMessage {
            id: "x".into(),
            result: Ok(message("x", "81", "fp-x")),
        },
    ]);
    let replay_outcome = SyncCoordinator::new(&mut replay, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap();
    replay.assert_exhausted();

    let mut complete_replay = ScriptedGmailGateway::new(expired_scan_steps(
        "90",
        "100",
        &[("x", "81", "fp-x"), ("y", "70", "fp-y")],
    ));
    let complete_outcome =
        SyncCoordinator::new(&mut complete_replay, &store, SyncLimits::EVALUATOR)
            .sync(&key)
            .unwrap();
    complete_replay.assert_exhausted();
    let final_snapshot = store.snapshot(&key).unwrap();
    assert_eq!(final_snapshot.sources.len(), 2);
    assert_eq!(final_snapshot.revision_count, 2);
    assert_eq!(final_snapshot.cursor.as_deref(), Some("100"));
    assert_eq!(
        stable_ids,
        final_snapshot
            .sources
            .iter()
            .map(|source| source.source_id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(replay_outcome.report().commit.effects_replayed, 1);
    assert_eq!(complete_outcome.report().commit.effects_replayed, 2);

    emit(
        "duplicate_identity_and_replay",
        "duplicate_identity_and_replay",
        json!({
            "stable_source_ids": true,
            "duplicate_source_count": 0,
            "source_count": final_snapshot.sources.len(),
            "revision_count": final_snapshot.revision_count,
            "replayed_effects": replay_outcome.report().commit.effects_replayed
                + complete_outcome.report().commit.effects_replayed,
            "cursor": final_snapshot.cursor.unwrap(),
            "monotonic_terminal_cursor": true,
            "scan_history_race_replayed": true,
        }),
    );
}

fn assert_unchanged(path: &Path, key: &SyncKey) {
    let reopened = SqliteSyncStore::open(path).unwrap();
    let snapshot = reopened.snapshot(key).unwrap();
    assert_eq!(snapshot.cursor.as_deref(), Some("10"));
    assert!(snapshot.sources.is_empty());
    assert_eq!(snapshot.revision_count, 0);
}

#[test]
fn bounds_and_non_cursor_failures_preserve_state() {
    let mut bound_cases = 0;

    let run_bound = |steps: Vec<ScriptStep>, limits: SyncLimits| {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("gmail.sqlite");
        let store = SqliteSyncStore::open(&path).unwrap();
        let key = SyncKey::gmail("acct-bounds", "scope");
        store.seed_checkpoint(&key, "10").unwrap();
        let mut gateway = ScriptedGmailGateway::new(steps);
        let error = SyncCoordinator::new(&mut gateway, &store, limits)
            .sync(&key)
            .unwrap_err();
        assert_eq!(error.kind, SyncErrorKind::IncompleteBoundExceeded);
        assert_unchanged(&path, &key);
    };

    let mut page_limit = SyncLimits::EVALUATOR;
    page_limit.max_pages = 1;
    run_bound(
        vec![
            ScriptStep::ListHistory {
                start: "10".into(),
                token: None,
                result: Err(GatewayError::CursorExpired),
            },
            ScriptStep::Profile(Ok("20".into())),
            ScriptStep::ListMessages {
                token: None,
                result: Ok(page(&[], Some("next"))),
            },
        ],
        page_limit,
    );
    bound_cases += 1;

    let mut unique_limit = SyncLimits::EVALUATOR;
    unique_limit.max_unique_messages = 1;
    run_bound(
        vec![
            ScriptStep::ListHistory {
                start: "10".into(),
                token: None,
                result: Err(GatewayError::CursorExpired),
            },
            ScriptStep::Profile(Ok("20".into())),
            ScriptStep::ListMessages {
                token: None,
                result: Ok(page(&["a", "b"], None)),
            },
            ScriptStep::GetMessage {
                id: "a".into(),
                result: Ok(message("a", "15", "fp-a")),
            },
        ],
        unique_limit,
    );
    bound_cases += 1;

    let mut call_limit = SyncLimits::EVALUATOR;
    call_limit.max_gateway_calls = 2;
    run_bound(
        vec![
            ScriptStep::ListHistory {
                start: "10".into(),
                token: None,
                result: Err(GatewayError::CursorExpired),
            },
            ScriptStep::Profile(Ok("20".into())),
        ],
        call_limit,
    );
    bound_cases += 1;

    run_bound(
        vec![
            ScriptStep::ListHistory {
                start: "10".into(),
                token: None,
                result: Err(GatewayError::CursorExpired),
            },
            ScriptStep::Profile(Err(GatewayError::ReconciliationRestart)),
            ScriptStep::Profile(Err(GatewayError::ReconciliationRestart)),
        ],
        SyncLimits::EVALUATOR,
    );
    bound_cases += 1;

    let failures = [
        (GatewayError::Cancelled, SyncErrorKind::Cancelled),
        (GatewayError::Transient, SyncErrorKind::Transient),
        (GatewayError::Quota, SyncErrorKind::Quota),
        (GatewayError::Authentication, SyncErrorKind::Authentication),
        (GatewayError::Permission, SyncErrorKind::Permission),
        (GatewayError::RateLimited, SyncErrorKind::RateLimited),
        (
            GatewayError::MalformedRequest,
            SyncErrorKind::MalformedRequest,
        ),
    ];
    for (gateway_error, expected) in failures {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("gmail.sqlite");
        let store = SqliteSyncStore::open(&path).unwrap();
        let key = SyncKey::gmail("acct-errors", "scope");
        store.seed_checkpoint(&key, "10").unwrap();
        let mut gateway = ScriptedGmailGateway::new([ScriptStep::ListHistory {
            start: "10".into(),
            token: None,
            result: Err(gateway_error),
        }]);
        let error = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
            .sync(&key)
            .unwrap_err();
        assert_eq!(error.kind, expected);
        assert_eq!(error.diagnostic.fallback, None);
        assert_unchanged(&path, &key);
    }

    emit(
        "bounds_and_non_cursor_failures_preserve_state",
        "bounds_and_non_cursor_failures_preserve_state",
        json!({
            "bound_cases": bound_cases,
            "non_cursor_failure_cases": failures.len(),
            "page_bound_rejected": true,
            "unique_message_bound_rejected": true,
            "gateway_call_bound_rejected": true,
            "scan_attempt_bound_rejected": true,
            "cancellation_preserved_state": true,
            "non_cursor_fallback_count": 0,
            "preserved_state": true,
        }),
    );
}

#[test]
fn interruption_atomicity() {
    let faults = [
        CommitFault::BeforeTransaction,
        CommitFault::AfterEffects,
        CommitFault::AfterCheckpoint,
        CommitFault::AfterCommit,
    ];
    let mut old_state_cases = 0;
    let mut new_state_cases = 0;
    for fault in faults {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("gmail.sqlite");
        let store = SqliteSyncStore::open(&path).unwrap();
        let key = SyncKey::gmail("acct-interrupt", "scope");
        store.seed_checkpoint(&key, "10").unwrap();
        let mut gateway =
            ScriptedGmailGateway::new(expired_scan_steps("10", "20", &[("m", "15", "fp")]));
        let error = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
            .sync_with_fault(&key, fault)
            .unwrap_err();
        assert!(matches!(
            error.kind,
            SyncErrorKind::Cancelled | SyncErrorKind::Store
        ));
        drop(store);

        let reopened = SqliteSyncStore::open(&path).unwrap();
        let snapshot = reopened.snapshot(&key).unwrap();
        if fault == CommitFault::AfterCommit {
            assert_eq!(snapshot.cursor.as_deref(), Some("20"));
            assert_eq!(snapshot.sources.len(), 1);
            assert_eq!(snapshot.revision_count, 1);
            new_state_cases += 1;

            let mut replay = ScriptedGmailGateway::new([ScriptStep::ListHistory {
                start: "20".into(),
                token: None,
                result: Ok(history(vec![], None, "20")),
            }]);
            SyncCoordinator::new(&mut replay, &reopened, SyncLimits::EVALUATOR)
                .sync(&key)
                .unwrap();
            assert_eq!(reopened.snapshot(&key).unwrap().revision_count, 1);
        } else {
            assert_eq!(snapshot.cursor.as_deref(), Some("10"));
            assert!(snapshot.sources.is_empty());
            assert_eq!(snapshot.revision_count, 0);
            old_state_cases += 1;
        }
        assert_eq!(reopened.audit().unwrap().integrity_check, "ok");
    }

    emit(
        "interruption_atomicity",
        "interruption_atomicity",
        json!({
            "fault_boundaries": faults.len(),
            "complete_old_state_cases": old_state_cases,
            "complete_new_state_cases": new_state_cases,
            "partial_state_cases": 0,
            "fresh_connection_oracle": true,
            "after_commit_replay_duplicate_revisions": 0,
            "atomic_cursor_and_effects": true,
        }),
    );
}

#[test]
fn identity_deletion_and_reappearance() {
    let temp = TempDir::new().unwrap();
    let store = store(&temp);
    let key_a = SyncKey::gmail("account-a", "scope");
    let key_b = SyncKey::gmail("account-b", "scope");
    let identity_fixture_a = message("same-message", "10", "equal-content");
    let identity_fixture_b = message("other-message", "11", "equal-content");
    assert_ne!(identity_fixture_a.id, identity_fixture_b.id);
    assert_eq!(identity_fixture_a.thread_id, identity_fixture_b.thread_id);
    assert_eq!(
        identity_fixture_a.rfc_message_id,
        identity_fixture_b.rfc_message_id
    );
    assert_eq!(
        identity_fixture_a.evidence_fingerprint,
        identity_fixture_b.evidence_fingerprint
    );

    let mut account_a = ScriptedGmailGateway::new([
        ScriptStep::Profile(Ok("15".into())),
        ScriptStep::ListMessages {
            token: None,
            result: Ok(page(&["same-message", "other-message"], None)),
        },
        ScriptStep::GetMessage {
            id: "same-message".into(),
            result: Ok(identity_fixture_a),
        },
        ScriptStep::GetMessage {
            id: "other-message".into(),
            result: Ok(identity_fixture_b),
        },
    ]);
    SyncCoordinator::new(&mut account_a, &store, SyncLimits::EVALUATOR)
        .sync(&key_a)
        .unwrap();
    let before = store.snapshot(&key_a).unwrap();
    let stable_id = before
        .sources
        .iter()
        .find(|source| source.provider_source_id == "same-message")
        .unwrap()
        .source_id
        .clone();

    let mut account_b = ScriptedGmailGateway::new([
        ScriptStep::Profile(Ok("15".into())),
        ScriptStep::ListMessages {
            token: None,
            result: Ok(page(&["same-message"], None)),
        },
        ScriptStep::GetMessage {
            id: "same-message".into(),
            result: Ok(message("same-message", "10", "equal-content")),
        },
    ]);
    SyncCoordinator::new(&mut account_b, &store, SyncLimits::EVALUATOR)
        .sync(&key_b)
        .unwrap();

    let mut deletion = ScriptedGmailGateway::new([ScriptStep::ListHistory {
        start: "15".into(),
        token: None,
        result: Ok(history(
            vec![event("20", "same-message", HistoryEventKind::Deleted)],
            None,
            "20",
        )),
    }]);
    SyncCoordinator::new(&mut deletion, &store, SyncLimits::EVALUATOR)
        .sync(&key_a)
        .unwrap();
    let deleted = store.snapshot(&key_a).unwrap();
    assert!(
        !deleted
            .sources
            .iter()
            .find(|source| source.provider_source_id == "same-message")
            .unwrap()
            .available
    );

    let mut not_found = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "20".into(),
            token: None,
            result: Ok(history(
                vec![event("25", "other-message", HistoryEventKind::Upsert)],
                None,
                "25",
            )),
        },
        ScriptStep::GetMessage {
            id: "other-message".into(),
            result: Err(GatewayError::MessageNotFound),
        },
    ]);
    let not_found_outcome = SyncCoordinator::new(&mut not_found, &store, SyncLimits::EVALUATOR)
        .sync(&key_a)
        .unwrap();
    assert_eq!(not_found_outcome.report().diagnostic.fallback, None);

    let mut reappearance = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "25".into(),
            token: None,
            result: Ok(history(
                vec![event("30", "same-message", HistoryEventKind::Upsert)],
                None,
                "30",
            )),
        },
        ScriptStep::GetMessage {
            id: "same-message".into(),
            result: Ok(message("same-message", "30", "equal-content")),
        },
    ]);
    SyncCoordinator::new(&mut reappearance, &store, SyncLimits::EVALUATOR)
        .sync(&key_a)
        .unwrap();
    let final_a = store.snapshot(&key_a).unwrap();
    let final_b = store.snapshot(&key_b).unwrap();
    let reappeared = final_a
        .sources
        .iter()
        .find(|source| source.provider_source_id == "same-message")
        .unwrap();
    assert_eq!(reappeared.source_id, stable_id);
    assert!(reappeared.available);
    assert_ne!(reappeared.source_id, final_b.sources[0].source_id);
    assert_eq!(final_a.sources.len(), 2);

    emit(
        "identity_deletion_and_reappearance",
        "identity_deletion_and_reappearance",
        json!({
            "same_account_distinct_message_sources": 2,
            "cross_account_distinct_sources": true,
            "thread_id_identity_collapse": false,
            "rfc_message_id_identity_collapse": false,
            "content_identity_collapse": false,
            "stable_source_id_after_reappearance": true,
            "explicit_deletion_observed": true,
            "message_not_found_observed_without_fallback": true,
            "available_after_reappearance": reappeared.available,
            "source_count": final_a.sources.len() + final_b.sources.len(),
            "revision_count": store.audit().unwrap().revision_count,
        }),
    );
}

#[test]
fn diagnostic_sentinel_redaction() {
    let sentinels = [
        "ACCOUNT_SENTINEL_7f31",
        "MESSAGE_SENTINEL_14bb",
        "987654321987654321",
        "PAGE_TOKEN_SENTINEL_2c91",
        "QUERY_SENTINEL_81ad",
        "HEADER_SENTINEL_33e0",
        "FILENAME_SENTINEL_f9a2",
        "URL_SENTINEL_09ce",
        "BODY_SENTINEL_a7d4",
        "CREDENTIAL_SENTINEL_558e",
        "THREAD_SENTINEL_6d20",
    ];
    let temp = TempDir::new().unwrap();
    let store = store(&temp);
    let key = SyncKey::gmail(sentinels[0], sentinels[4]);
    store.seed_checkpoint(&key, "10").unwrap();
    let sentinel_message = GmailMessage {
        id: sentinels[1].into(),
        history_id: "12".into(),
        thread_id: sentinels[10].into(),
        rfc_message_id: sentinels[5].into(),
        evidence_fingerprint: format!(
            "{}:{}:{}:{}:{}:{}",
            sentinels[5], sentinels[6], sentinels[7], sentinels[8], sentinels[9], sentinels[4]
        ),
    };
    let mut gateway = ScriptedGmailGateway::new([
        ScriptStep::ListHistory {
            start: "10".into(),
            token: None,
            result: Err(GatewayError::CursorExpired),
        },
        ScriptStep::Profile(Ok(sentinels[2].into())),
        ScriptStep::ListMessages {
            token: None,
            result: Ok(page(&[sentinels[1]], Some(sentinels[3]))),
        },
        ScriptStep::GetMessage {
            id: sentinels[1].into(),
            result: Ok(sentinel_message),
        },
        ScriptStep::ListMessages {
            token: Some(sentinels[3].into()),
            result: Ok(page(&[], None)),
        },
    ]);
    let success = SyncCoordinator::new(&mut gateway, &store, SyncLimits::EVALUATOR)
        .sync(&key)
        .unwrap();

    let error_key = SyncKey::gmail("redacted-error-account", "redacted-error-scope");
    store.seed_checkpoint(&error_key, "20").unwrap();
    let mut failing = ScriptedGmailGateway::new([ScriptStep::ListHistory {
        start: "20".into(),
        token: None,
        result: Err(GatewayError::Quota),
    }]);
    let failure = SyncCoordinator::new(&mut failing, &store, SyncLimits::EVALUATOR)
        .sync(&error_key)
        .unwrap_err();
    let evidence_artifact = json!({
        "test": "diagnostic_sentinel_redaction",
        "scenario": "diagnostic_sentinel_redaction",
        "status": "pass",
        "sentinel_count": sentinels.len(),
        "leaked_sentinel_count": 0,
        "success_diagnostic_bounded": true,
        "failure_diagnostic_bounded": true,
    });
    let diagnostic_artifacts = format!(
        "{}\n{}\n{:?}\n{}\n{}",
        serde_json::to_string(&success.report().diagnostic).unwrap(),
        serde_json::to_string(&failure.diagnostic).unwrap(),
        failure,
        failure,
        serde_json::to_string(&evidence_artifact).unwrap(),
    );
    for sentinel in sentinels {
        assert!(
            !diagnostic_artifacts.contains(sentinel),
            "diagnostic leaked a prohibited sentinel"
        );
    }
    assert!(success.report().diagnostic.gateway_calls <= SyncLimits::EVALUATOR.max_gateway_calls);
    assert!(failure.diagnostic.gateway_calls <= SyncLimits::EVALUATOR.max_gateway_calls);

    emit(
        "diagnostic_sentinel_redaction",
        "diagnostic_sentinel_redaction",
        evidence_artifact,
    );
}
