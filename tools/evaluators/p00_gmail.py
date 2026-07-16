"""Fail-closed runtime evidence evaluator for P00 Gmail reconciliation."""

from __future__ import annotations

import datetime as dt
import base64
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any
from urllib.parse import quote


REQUIREMENT_ID = "P00-GML-001"
EVIDENCE_PREFIX = "P00_GML_EVIDENCE "
TEST_COMMAND = [
    "cargo",
    "test",
    "-p",
    "p00-gmail-sync",
    "--test",
    "reconciliation",
    "--",
    "--nocapture",
    "--test-threads=1",
]

EXPIRED = "expired_cursor_bounded_reconciliation"
MALFORMED = "malformed_cursor_fallback"
INVALID = "invalid_cursor_fallback"
INCREMENTAL = "valid_incremental_exclusive_anchor"
DUPLICATES = "duplicate_identity_and_replay"
FAILURES = "bounds_and_non_cursor_failures_preserve_state"
INTERRUPTION = "interruption_atomicity"
IDENTITY = "identity_deletion_and_reappearance"
REDACTION = "diagnostic_sentinel_redaction"

EXPECTED_SCENARIOS = (
    EXPIRED,
    MALFORMED,
    INVALID,
    INCREMENTAL,
    DUPLICATES,
    FAILURES,
    INTERRUPTION,
    IDENTITY,
    REDACTION,
)

KNOWN_SENTINELS = (
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
)

SQLITE_ORACLES: dict[str, Any] = {
    "database": "sqlite",
    "integrity_check": "ok",
    "foreign_key_violations": 0,
}
COMMON_ORACLES: dict[str, Any] = {"status": "pass"}

# These are test-fixture oracles, not source markers. Every value must be
# emitted by the executed reconciliation integration test.
EXPECTED_RECORD_VALUES: dict[str, dict[str, Any]] = {
    EXPIRED: {
        **COMMON_ORACLES,
        **SQLITE_ORACLES,
        "test": EXPIRED,
        "fallback": "expired_cursor",
        "bounded": True,
        "source_count": 3,
        "revision_count": 3,
        "cursor": "20",
        "pages": 2,
        "unique_messages": 3,
        "duplicate_source_count": 0,
    },
    MALFORMED: {
        **COMMON_ORACLES,
        "test": MALFORMED,
        "fallback": "malformed_cursor",
        "history_calls": 0,
        "source_count": 1,
        "revision_count": 1,
        "cursor": "30",
        "bounded": True,
    },
    INVALID: {
        **COMMON_ORACLES,
        "test": INVALID,
        "fallback": "invalid_cursor",
        "history_calls": 1,
        "source_count": 1,
        "revision_count": 1,
        "cursor": "35",
        "bounded": True,
    },
    INCREMENTAL: {
        **COMMON_ORACLES,
        "test": INCREMENTAL,
        "fallback": None,
        "exclusive_anchor": True,
        "anchor_event_applied": False,
        "post_anchor_event_applied": True,
        "history_calls": 1,
        "message_get_calls": 1,
        "source_count": 1,
        "revision_count": 1,
        "cursor": "45",
    },
    DUPLICATES: {
        **COMMON_ORACLES,
        "test": DUPLICATES,
        "stable_source_ids": True,
        "duplicate_source_count": 0,
        "source_count": 2,
        "revision_count": 2,
        "replayed_effects": 3,
        "cursor": "100",
        "monotonic_terminal_cursor": True,
        "scan_history_race_replayed": True,
    },
    FAILURES: {
        **COMMON_ORACLES,
        "test": FAILURES,
        "bound_cases": 4,
        "non_cursor_failure_cases": 7,
        "page_bound_rejected": True,
        "unique_message_bound_rejected": True,
        "gateway_call_bound_rejected": True,
        "scan_attempt_bound_rejected": True,
        "cancellation_preserved_state": True,
        "non_cursor_fallback_count": 0,
        "preserved_state": True,
    },
    INTERRUPTION: {
        **COMMON_ORACLES,
        "test": INTERRUPTION,
        "fault_boundaries": 4,
        "complete_old_state_cases": 3,
        "complete_new_state_cases": 1,
        "partial_state_cases": 0,
        "fresh_connection_oracle": True,
        "after_commit_replay_duplicate_revisions": 0,
        "atomic_cursor_and_effects": True,
    },
    IDENTITY: {
        **COMMON_ORACLES,
        "test": IDENTITY,
        "same_account_distinct_message_sources": 2,
        "cross_account_distinct_sources": True,
        "thread_id_identity_collapse": False,
        "rfc_message_id_identity_collapse": False,
        "content_identity_collapse": False,
        "stable_source_id_after_reappearance": True,
        "explicit_deletion_observed": True,
        "message_not_found_observed_without_fallback": True,
        "available_after_reappearance": True,
        "source_count": 3,
        "revision_count": 6,
    },
    REDACTION: {
        **COMMON_ORACLES,
        "test": REDACTION,
        "sentinel_count": len(KNOWN_SENTINELS),
        "leaked_sentinel_count": 0,
        "success_diagnostic_bounded": True,
        "failure_diagnostic_bounded": True,
    },
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def parse_runtime_evidence(
    output: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for line in output.splitlines():
        occurrences = line.count(EVIDENCE_PREFIX)
        if occurrences == 0:
            continue
        if occurrences != 1 or not line.startswith(EVIDENCE_PREFIX):
            errors.append("Gmail runtime evidence is not exactly line-framed")
            continue
        payload_text = line.removeprefix(EVIDENCE_PREFIX)
        try:
            payload = json.loads(payload_text)
        except (json.JSONDecodeError, UnicodeError):
            errors.append("Gmail runtime evidence contains malformed JSON")
            continue
        if not isinstance(payload, dict):
            errors.append("Gmail runtime evidence record is not an object")
            continue
        scenario = payload.get("scenario")
        if not isinstance(scenario, str) or not scenario:
            errors.append("Gmail runtime evidence has no string scenario")
            continue
        if scenario in records:
            errors.append(f"Gmail runtime evidence repeats scenario {scenario}")
            continue
        records[scenario] = payload
    return records, errors


def _exact_value(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    return actual == expected


def validate_records(records: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    expected_names = set(EXPECTED_SCENARIOS)
    actual_names = set(records)
    missing = expected_names - actual_names
    unexpected = actual_names - expected_names
    if missing:
        errors.append("missing runtime scenarios: " + ", ".join(sorted(missing)))
    if unexpected:
        errors.append(
            "unexpected runtime scenarios: " + ", ".join(sorted(unexpected))
        )

    for scenario in EXPECTED_SCENARIOS:
        record = records.get(scenario)
        if record is None:
            continue
        expected = EXPECTED_RECORD_VALUES[scenario]
        expected_keys = {"scenario", *expected}
        actual_keys = set(record)
        missing_keys = expected_keys - actual_keys
        unexpected_keys = actual_keys - expected_keys
        if missing_keys:
            errors.append(
                f"{scenario}: missing fields " + ", ".join(sorted(missing_keys))
            )
        if unexpected_keys:
            errors.append(
                f"{scenario}: unexpected fields "
                + ", ".join(sorted(unexpected_keys))
            )
        if record.get("scenario") != scenario:
            errors.append(f"{scenario}: scenario identity is invalid")
        for field, value in expected.items():
            if not _exact_value(record.get(field), value):
                errors.append(f"{scenario}: expected {field}={value!r}")
    return errors


def sentinel_variants(sentinel: str) -> set[bytes]:
    raw = sentinel.encode("ascii")
    json_escaped = json.dumps(sentinel, ensure_ascii=True)[1:-1].encode("ascii")
    return {
        raw,
        json_escaped,
        quote(sentinel, safe="").encode("ascii"),
        base64.b64encode(raw),
        raw.hex().encode("ascii"),
    }


def sentinel_findings(data: bytes, location: str) -> list[str]:
    findings: list[str] = []
    for sentinel in KNOWN_SENTINELS:
        if any(variant in data for variant in sentinel_variants(sentinel)):
            findings.append(f"known diagnostic sentinel leaked in {location}")
    return findings


def scan_artifacts(evidence_dir: Path) -> list[str]:
    errors: list[str] = []
    if not evidence_dir.exists():
        return errors
    for path in sorted(evidence_dir.rglob("*")):
        relative = path.relative_to(evidence_dir)
        errors.extend(
            sentinel_findings(
                relative.as_posix().encode("utf-8", "surrogateescape"),
                "artifact relative path",
            )
        )
        for component in relative.parts:
            errors.extend(
                sentinel_findings(
                    component.encode("utf-8", "surrogateescape"),
                    "artifact path component",
                )
            )
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError as error:
            errors.append(
                f"cannot scan evaluator artifact {path.name}: {error}"
            )
            continue
        errors.extend(sentinel_findings(data, "artifact contents"))
    return list(dict.fromkeys(errors))


def validate_runtime_evidence(
    exit_code: int,
    output: str,
    artifact_dir: Path | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records, errors = parse_runtime_evidence(output)
    if exit_code != 0:
        errors.append("Gmail reconciliation test command failed")
    errors.extend(validate_records(records))
    errors.extend(sentinel_findings(output.encode("utf-8"), "test output"))
    if artifact_dir is not None:
        errors.extend(scan_artifacts(artifact_dir))
    return records, errors


def public_summary(records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    errors = validate_records(records)
    if errors:
        raise ValueError("cannot summarize invalid Gmail runtime evidence")
    expired = records[EXPIRED]
    malformed = records[MALFORMED]
    invalid = records[INVALID]
    incremental = records[INCREMENTAL]
    duplicates = records[DUPLICATES]
    failures = records[FAILURES]
    interruption = records[INTERRUPTION]
    identity = records[IDENTITY]
    redaction = records[REDACTION]
    return {
        "database": expired["database"],
        "reconciliation_fallbacks": sum(
            record["fallback"]
            in {"expired_cursor", "malformed_cursor", "invalid_cursor"}
            for record in (expired, malformed, invalid)
        ),
        "bounded_reconciliation": (
            expired["bounded"] and malformed["bounded"] and invalid["bounded"]
        ),
        "expired_cursor_source_count": expired["source_count"],
        "expired_cursor_revision_count": expired["revision_count"],
        "expired_cursor_pages": expired["pages"],
        "expired_cursor_unique_messages": expired["unique_messages"],
        "malformed_cursor_history_calls": malformed["history_calls"],
        "invalid_cursor_history_calls": invalid["history_calls"],
        "exclusive_history_anchor": incremental["exclusive_anchor"],
        "duplicate_source_records": duplicates["duplicate_source_count"],
        "duplicate_revisions": interruption[
            "after_commit_replay_duplicate_revisions"
        ],
        "replayed_effects": duplicates["replayed_effects"],
        "bound_cases": failures["bound_cases"],
        "non_cursor_failure_cases": failures["non_cursor_failure_cases"],
        "non_cursor_fallbacks": failures["non_cursor_fallback_count"],
        "incomplete_state_preserved": failures["preserved_state"],
        "interruption_atomic": interruption["atomic_cursor_and_effects"],
        "stable_identity_reappeared": identity[
            "stable_source_id_after_reappearance"
        ],
        "explicit_deletion_observed": identity[
            "explicit_deletion_observed"
        ],
        "diagnostic_sentinels_scanned": redaction["sentinel_count"],
        "diagnostic_sentinel_leaks": redaction["leaked_sentinel_count"],
        "scenario_count": len(records),
    }


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    if REQUIREMENT_ID not in selected:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    passing_path = evidence_dir / f"{REQUIREMENT_ID}.json"
    passing_path.unlink(missing_ok=True)

    launch_error: str | None = None
    try:
        result = subprocess.run(
            TEST_COMMAND,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError:
        launch_error = "Gmail reconciliation test command could not start"
        result = subprocess.CompletedProcess(TEST_COMMAND, 127, "")
    records, errors = validate_runtime_evidence(
        result.returncode,
        result.stdout,
        evidence_dir,
    )
    if launch_error is not None:
        errors.append(launch_error)
    diagnostics: dict[str, Any] = {
        "errors": errors,
        "runtime_record_count": len(records),
        "runtime_scenarios": sorted(records),
        "test_command": TEST_COMMAND,
        "test_exit_code": result.returncode,
        "test_output_sha256": hashlib.sha256(
            result.stdout.encode("utf-8")
        ).hexdigest(),
    }
    diagnostics_text = json.dumps(diagnostics, indent=2, sort_keys=True) + "\n"
    diagnostic_findings = sentinel_findings(
        diagnostics_text.encode("utf-8"),
        "prospective evaluator diagnostics",
    )
    if diagnostic_findings:
        errors.extend(diagnostic_findings)
        diagnostics["errors"] = errors
        diagnostics_text = json.dumps(
            diagnostics, indent=2, sort_keys=True
        ) + "\n"
        if sentinel_findings(
            diagnostics_text.encode("utf-8"),
            "redacted evaluator diagnostics",
        ):
            diagnostics_text = json.dumps(
                {
                    "errors": [
                        "known diagnostic sentinel leaked; "
                        "diagnostics fully redacted"
                    ],
                    "test_command": TEST_COMMAND,
                    "test_exit_code": result.returncode,
                },
                indent=2,
                sort_keys=True,
            ) + "\n"

    (evidence_dir / "p00-gmail-diagnostics.json").write_text(
        diagnostics_text,
        encoding="utf-8",
    )
    if errors:
        for error in errors:
            print(f"P00 Gmail evaluation: {error}")
        return 1

    payload = {
        "requirement_id": REQUIREMENT_ID,
        "status": "pass",
        "test": "tools.evaluators.p00_gmail.evaluate",
        "recorded_at": utc_now(),
        "details": {
            "diagnostics": "p00-gmail-diagnostics.json",
            "public_summary": public_summary(records),
        },
    }
    payload_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    final_findings = sentinel_findings(
        payload_text.encode("utf-8"),
        "prospective passing evidence",
    )
    if final_findings:
        for error in final_findings:
            print(f"P00 Gmail evaluation: {error}")
        return 1
    passing_path.write_text(payload_text, encoding="utf-8")
    return 0
