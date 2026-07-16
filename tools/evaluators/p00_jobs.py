"""Evidence evaluator for P00 durable job recovery."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import re
import subprocess
from typing import Any


REQUIRED_SOURCE_MARKERS = {
    "immediate transactions": "TransactionBehavior::Immediate",
    "expired lease recovery": "lease_expires_at_ms <= ?1",
    "monotonic fencing": "fence = fence + 1",
    "fenced completion": "AND fence = ?3",
    "unexpired completion": "AND lease_expires_at_ms > ?4",
    "strict schema": ") STRICT;",
    "WAL mode": "PRAGMA journal_mode = WAL",
    "full synchronization": '"synchronous", "FULL"',
}
REQUIRED_TEST_MARKERS = {
    "committed lease crash": "sigkill_after_committed_lease_recovers_at_exact_expiry_once",
    "pre-claim-commit crash": "sigkill_before_claim_commit_rolls_back_attempt_and_fence",
    "pre-completion-commit crash": "sigkill_after_result_insert_before_commit_rolls_back_output_and_state",
    "post-commit crash": "sigkill_after_completion_commit_does_not_rerun_or_duplicate_output",
    "stale fence": "reassigned_job_rejects_stale_fence_without_suppressing_winner",
    "process-tree cleanup": "timeout_cleanup_kills_and_reaps_the_complete_process_group",
    "real SIGKILL": "libc::SIGKILL",
    "separate process group": ".process_group(0)",
}
SINGLE_OUTPUT_ORACLE = re.compile(
    r'assert_fresh_oracle\(\s*&inspection,\s*"succeeded",.*?,\s*1,\s*0\s*\);',
    re.DOTALL,
)
EXPECTED_SINGLE_OUTPUT_ORACLES = 5
EVIDENCE_PREFIX = "P00_JOB_EVIDENCE "
TEST_COMMAND = [
    "cargo",
    "test",
    "-p",
    "p00-durable-jobs",
    "--test",
    "crash_recovery",
    "--",
    "--nocapture",
    "--test-threads=1",
]
CRASH_SCENARIOS = {
    "committed_lease_exact_expiry_recovery":
        "sigkill_after_committed_lease_recovers_at_exact_expiry_once",
    "claim_precommit_rollback":
        "sigkill_before_claim_commit_rolls_back_attempt_and_fence",
    "result_insert_precommit_rollback":
        "sigkill_after_result_insert_before_commit_rolls_back_output_and_state",
    "completion_postcommit_no_rerun":
        "sigkill_after_completion_commit_does_not_rerun_or_duplicate_output",
}
STALE_SCENARIO = "stale_and_fabricated_lease_rejection"
CLEANUP_SCENARIO = "timeout_process_group_cleanup"
EXPECTED_SCENARIOS = {
    **CRASH_SCENARIOS,
    STALE_SCENARIO: "reassigned_job_rejects_stale_fence_without_suppressing_winner",
    CLEANUP_SCENARIO: "timeout_cleanup_kills_and_reaps_the_complete_process_group",
}
EXPECTED_WINNERS = {
    "committed_lease_exact_expiry_recovery": ("worker-b", 2),
    "claim_precommit_rollback": ("worker-b", 1),
    "result_insert_precommit_rollback": ("worker-b", 2),
    "completion_postcommit_no_rerun": ("worker-a", 1),
    STALE_SCENARIO: ("worker-b", 2),
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def validate_sources(sqlite_source: str, recovery_tests: str) -> list[str]:
    errors = [
        f"missing durable-job contract: {name}"
        for name, marker in REQUIRED_SOURCE_MARKERS.items()
        if marker not in sqlite_source
    ]
    errors.extend(
        f"missing crash verification: {name}"
        for name, marker in REQUIRED_TEST_MARKERS.items()
        if marker not in recovery_tests
    )
    if ":memory:" in recovery_tests or "open_in_memory" in recovery_tests:
        errors.append("crash recovery must use an on-disk SQLite database")
    oracle_count = len(SINGLE_OUTPUT_ORACLE.findall(recovery_tests))
    if oracle_count != EXPECTED_SINGLE_OUTPUT_ORACLES:
        errors.append(
            "crash recovery must retain "
            f"{EXPECTED_SINGLE_OUTPUT_ORACLES} fresh-process single-output oracles "
            f"(found {oracle_count})"
        )
    return errors


def parse_runtime_evidence(output: str) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for line in output.splitlines():
        if EVIDENCE_PREFIX not in line:
            continue
        payload_text = line.split(EVIDENCE_PREFIX, 1)[1]
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError:
            errors.append("durable-job runtime evidence contains malformed JSON")
            continue
        if not isinstance(payload, dict) or not isinstance(payload.get("scenario"), str):
            errors.append("durable-job runtime evidence has no scenario")
            continue
        scenario = payload["scenario"]
        if scenario in records:
            errors.append(f"durable-job runtime evidence repeats scenario {scenario}")
            continue
        records[scenario] = payload
    return records, errors


def validate_runtime_evidence(
    exit_code: int, output: str
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records, errors = parse_runtime_evidence(output)
    if exit_code != 0:
        errors.append("durable-job crash-recovery test command failed")

    missing = set(EXPECTED_SCENARIOS) - set(records)
    unexpected = set(records) - set(EXPECTED_SCENARIOS)
    if missing:
        errors.append("missing runtime scenarios: " + ", ".join(sorted(missing)))
    if unexpected:
        errors.append("unexpected runtime scenarios: " + ", ".join(sorted(unexpected)))

    for scenario, expected_test in EXPECTED_SCENARIOS.items():
        record = records.get(scenario)
        if record is None:
            continue
        if record.get("test") != expected_test or record.get("status") != "pass":
            errors.append(f"{scenario}: test identity or status is invalid")

    for scenario, (owner, fence) in EXPECTED_WINNERS.items():
        record = records.get(scenario)
        if record is None:
            continue
        expected = {
            "database": "sqlite",
            "journal_mode": "wal",
            "synchronous": 2,
            "integrity_check": "ok",
            "foreign_key_violations": 0,
            "result_count": 1,
            "winning_owner": owner,
            "winning_fence": fence,
            "fresh_process_oracle": True,
        }
        for field, value in expected.items():
            if record.get(field) != value:
                errors.append(f"{scenario}: expected {field}={value!r}")

    for scenario in CRASH_SCENARIOS:
        record = records.get(scenario)
        if record is not None and record.get("recovery_process") != "sigkill":
            errors.append(f"{scenario}: recovery process was not SIGKILL")

    stale = records.get(STALE_SCENARIO)
    if stale is not None:
        for field in (
            "stale_fence_rejected",
            "fabricated_owner_rejected",
            "fabricated_fence_rejected",
        ):
            if stale.get(field) is not True:
                errors.append(f"{STALE_SCENARIO}: {field} was not proven")

    cleanup = records.get(CLEANUP_SCENARIO)
    if cleanup is not None:
        if cleanup.get("recovery_process") != "sigkill":
            errors.append(f"{CLEANUP_SCENARIO}: recovery process was not SIGKILL")
        if cleanup.get("process_tree_cleanup") is not True:
            errors.append(f"{CLEANUP_SCENARIO}: process tree cleanup was not proven")
    return records, errors


def public_summary(records: dict[str, dict[str, Any]]) -> dict[str, Any]:
    database_records = [records[scenario] for scenario in EXPECTED_WINNERS]
    crash_records = [records[scenario] for scenario in CRASH_SCENARIOS]
    return {
        "database": next(iter({record["database"] for record in database_records})),
        "journal_mode": next(
            iter({record["journal_mode"] for record in database_records})
        ),
        "synchronous": (
            "full"
            if {record["synchronous"] for record in database_records} == {2}
            else "unexpected"
        ),
        "recovery_process": next(
            iter({record["recovery_process"] for record in crash_records})
        ),
        "crash_scenarios": len(crash_records),
        "fencing": records[STALE_SCENARIO]["stale_fence_rejected"],
        "exactly_once_scope": (
            "sqlite-local-committed-effects"
            if {record["result_count"] for record in database_records} == {1}
            else "unproven"
        ),
        "process_tree_cleanup": records[CLEANUP_SCENARIO][
            "process_tree_cleanup"
        ],
    }


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    if "P00-JOB-001" not in selected:
        return 0
    sqlite_path = root / "spikes/p00-durable-jobs/src/sqlite.rs"
    tests_path = root / "spikes/p00-durable-jobs/tests/crash_recovery.rs"
    errors: list[str] = []
    if not sqlite_path.is_file() or not tests_path.is_file():
        errors.append("durable-job spike sources are missing")
        sqlite_source = ""
        recovery_tests = ""
    else:
        sqlite_source = sqlite_path.read_text(encoding="utf-8")
        recovery_tests = tests_path.read_text(encoding="utf-8")
        errors.extend(validate_sources(sqlite_source, recovery_tests))

    result = subprocess.run(
        TEST_COMMAND,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    runtime_records, runtime_errors = validate_runtime_evidence(
        result.returncode, result.stdout
    )
    errors.extend(runtime_errors)

    diagnostics: dict[str, Any] = {
        "errors": errors,
        "test_command": TEST_COMMAND,
        "test_exit_code": result.returncode,
        "test_output": result.stdout,
        "runtime_records": runtime_records,
    }
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "p00-job-diagnostics.json").write_text(
        json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if errors:
        for error in errors:
            print(f"P00 job evaluation: {error}")
        return 1

    payload = {
        "requirement_id": "P00-JOB-001",
        "status": "pass",
        "test": "tools.evaluators.p00_jobs.evaluate",
        "recorded_at": utc_now(),
        "details": {
            "diagnostics": "p00-job-diagnostics.json",
            "public_summary": public_summary(runtime_records),
        },
    }
    (evidence_dir / "P00-JOB-001.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0
