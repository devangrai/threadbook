from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import harness
from tools.evaluators import p00_gmail
from tools.evaluators import run as evaluator_run


def valid_records() -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for scenario, expected in p00_gmail.EXPECTED_RECORD_VALUES.items():
        records[scenario] = {"scenario": scenario, **copy.deepcopy(expected)}
    return records


def output_for(records: dict[str, dict[str, object]]) -> str:
    return "\n".join(
        p00_gmail.EVIDENCE_PREFIX
        + json.dumps(records[scenario], sort_keys=True)
        for scenario in p00_gmail.EXPECTED_SCENARIOS
        if scenario in records
    )


def mutated_value(value: object) -> object:
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if isinstance(value, str):
        return value + "-mutated"
    if value is None:
        return "unexpected-fallback"
    raise AssertionError(f"no mutation for {value!r}")


class GmailRuntimeEvidenceTests(unittest.TestCase):
    def test_accepts_all_exact_scenarios_and_derives_runtime_summary(self) -> None:
        records, errors = p00_gmail.validate_runtime_evidence(
            0, output_for(valid_records())
        )
        self.assertEqual([], errors)
        self.assertEqual(
            {
                "database": "sqlite",
                "reconciliation_fallbacks": 3,
                "bounded_reconciliation": True,
                "expired_cursor_source_count": 3,
                "expired_cursor_revision_count": 3,
                "expired_cursor_pages": 2,
                "expired_cursor_unique_messages": 3,
                "malformed_cursor_history_calls": 0,
                "invalid_cursor_history_calls": 1,
                "exclusive_history_anchor": True,
                "duplicate_source_records": 0,
                "duplicate_revisions": 0,
                "replayed_effects": 3,
                "bound_cases": 4,
                "non_cursor_failure_cases": 7,
                "non_cursor_fallbacks": 0,
                "incomplete_state_preserved": True,
                "interruption_atomic": True,
                "stable_identity_reappeared": True,
                "explicit_deletion_observed": True,
                "diagnostic_sentinels_scanned": 11,
                "diagnostic_sentinel_leaks": 0,
                "scenario_count": 9,
            },
            p00_gmail.public_summary(records),
        )

    def test_rejects_independent_mutation_of_every_exact_oracle(self) -> None:
        baseline = valid_records()
        for scenario, expected in p00_gmail.EXPECTED_RECORD_VALUES.items():
            for field, value in expected.items():
                with self.subTest(scenario=scenario, field=field):
                    records = copy.deepcopy(baseline)
                    records[scenario][field] = mutated_value(value)
                    _, errors = p00_gmail.validate_runtime_evidence(
                        0, output_for(records)
                    )
                    self.assertTrue(errors)
                with self.subTest(scenario=scenario, missing_field=field):
                    records = copy.deepcopy(baseline)
                    del records[scenario][field]
                    _, errors = p00_gmail.validate_runtime_evidence(
                        0, output_for(records)
                    )
                    self.assertTrue(errors)

    def test_rejects_each_missing_scenario(self) -> None:
        for scenario in p00_gmail.EXPECTED_SCENARIOS:
            with self.subTest(scenario=scenario):
                records = valid_records()
                del records[scenario]
                _, errors = p00_gmail.validate_runtime_evidence(
                    0, output_for(records)
                )
                self.assertTrue(errors)

    def test_rejects_duplicate_unexpected_malformed_and_unframed_records(
        self,
    ) -> None:
        output = output_for(valid_records())
        first_line = output.splitlines()[0]
        unexpected = {
            "scenario": "unapproved_scenario",
            "test": "unapproved_scenario",
            "status": "pass",
        }
        cases = (
            output + "\n" + first_line,
            output
            + "\n"
            + p00_gmail.EVIDENCE_PREFIX
            + json.dumps(unexpected),
            output + "\n" + p00_gmail.EVIDENCE_PREFIX + "{",
            output + "\nprefix " + first_line,
            output + "\n" + p00_gmail.EVIDENCE_PREFIX + "[]",
            output + "\n" + p00_gmail.EVIDENCE_PREFIX + '{"status":"pass"}',
        )
        for mutated in cases:
            with self.subTest(suffix=mutated[-80:]):
                _, errors = p00_gmail.validate_runtime_evidence(0, mutated)
                self.assertTrue(errors)

    def test_rejects_nonzero_command_and_unexpected_record_field(self) -> None:
        records = valid_records()
        records[p00_gmail.EXPIRED]["unvalidated_claim"] = True
        _, field_errors = p00_gmail.validate_runtime_evidence(
            0, output_for(records)
        )
        _, command_errors = p00_gmail.validate_runtime_evidence(
            9, output_for(valid_records())
        )
        self.assertTrue(field_errors)
        self.assertTrue(command_errors)

    def test_rejects_changed_stable_source_identity(self) -> None:
        records = valid_records()
        records[p00_gmail.IDENTITY][
            "stable_source_id_after_reappearance"
        ] = False
        _, errors = p00_gmail.validate_runtime_evidence(
            0, output_for(records)
        )
        self.assertTrue(errors)

    def test_summary_refuses_unvalidated_records(self) -> None:
        records = valid_records()
        records[p00_gmail.FAILURES]["non_cursor_fallback_count"] = 1
        with self.assertRaises(ValueError):
            p00_gmail.public_summary(records)


class GmailSentinelTests(unittest.TestCase):
    def test_rejects_every_known_sentinel_in_output(self) -> None:
        output = output_for(valid_records())
        for sentinel in p00_gmail.KNOWN_SENTINELS:
            for variant in p00_gmail.sentinel_variants(sentinel):
                with self.subTest(sentinel=sentinel, variant=variant):
                    _, errors = p00_gmail.validate_runtime_evidence(
                        0, output + "\nleak=" + variant.decode("ascii")
                    )
                    self.assertTrue(
                        any("sentinel leaked" in error for error in errors)
                    )

    def test_rejects_every_known_sentinel_in_artifacts(self) -> None:
        output = output_for(valid_records())
        for sentinel in p00_gmail.KNOWN_SENTINELS:
            for variant in p00_gmail.sentinel_variants(sentinel):
                with self.subTest(sentinel=sentinel, variant=variant):
                    with tempfile.TemporaryDirectory() as directory:
                        artifact = Path(directory) / "nested" / "artifact.bin"
                        artifact.parent.mkdir()
                        artifact.write_bytes(b"\x00" + variant)
                        _, errors = p00_gmail.validate_runtime_evidence(
                            0, output, Path(directory)
                        )
                    self.assertTrue(
                        any("sentinel leaked" in error for error in errors)
                    )

    def test_rejects_every_sentinel_variant_only_in_artifact_path(self) -> None:
        for sentinel in p00_gmail.KNOWN_SENTINELS:
            for variant in p00_gmail.sentinel_variants(sentinel):
                with self.subTest(sentinel=sentinel, variant=variant):
                    with tempfile.TemporaryDirectory() as directory:
                        root = Path(directory)
                        artifact = root / variant.decode("ascii")
                        artifact.parent.mkdir(parents=True, exist_ok=True)
                        artifact.write_bytes(b"safe artifact contents")
                        errors = p00_gmail.scan_artifacts(root)
                    self.assertTrue(
                        any("sentinel leaked" in error for error in errors)
                    )

    def test_artifact_scan_fails_closed_on_unreadable_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "vanished"
            with mock.patch.object(
                Path,
                "read_bytes",
                side_effect=OSError("fixture read failure"),
            ):
                path.write_text("safe", encoding="utf-8")
                errors = p00_gmail.scan_artifacts(Path(directory))
        self.assertTrue(any("cannot scan" in error for error in errors))


class GmailEvaluatorIntegrationTests(unittest.TestCase):
    def completed_process(
        self, returncode: int = 0, stdout: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            p00_gmail.TEST_COMMAND,
            returncode,
            stdout if stdout is not None else output_for(valid_records()),
        )

    @mock.patch("tools.evaluators.p00_gmail.subprocess.run")
    def test_runs_exact_command_and_writes_validated_evidence(
        self, run: mock.Mock
    ) -> None:
        run.return_value = self.completed_process()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            result = p00_gmail.evaluate(
                root, evidence, {p00_gmail.REQUIREMENT_ID}
            )
            payload = json.loads(
                (evidence / "P00-GML-001.json").read_text(encoding="utf-8")
            )
        self.assertEqual(0, result)
        run.assert_called_once_with(
            p00_gmail.TEST_COMMAND,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual("pass", payload["status"])
        self.assertEqual(
            9, payload["details"]["public_summary"]["scenario_count"]
        )
        self.assertEqual(
            payload["details"]["public_summary"],
            harness.sanitize_public_summary(
                payload["details"]["public_summary"],
                context="Gmail evaluator test",
            ),
        )

    @mock.patch("tools.evaluators.p00_gmail.subprocess.run")
    def test_failure_removes_stale_pass_and_redacts_sentinel(
        self, run: mock.Mock
    ) -> None:
        sentinel = p00_gmail.KNOWN_SENTINELS[0]
        run.return_value = self.completed_process(
            stdout=output_for(valid_records()) + "\n" + sentinel
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            passing = evidence / "P00-GML-001.json"
            passing.write_text('{"status":"pass"}', encoding="utf-8")
            result = p00_gmail.evaluate(
                root, evidence, {p00_gmail.REQUIREMENT_ID}
            )
            diagnostics = (
                evidence / "p00-gmail-diagnostics.json"
            ).read_text(encoding="utf-8")
            passing_exists = passing.exists()
        self.assertEqual(1, result)
        self.assertFalse(passing_exists)
        self.assertNotIn(sentinel, diagnostics)

    @mock.patch("tools.evaluators.p00_gmail.subprocess.run")
    def test_failure_redacts_sentinel_inside_parsed_record(
        self, run: mock.Mock
    ) -> None:
        sentinel = p00_gmail.KNOWN_SENTINELS[1]
        records = valid_records()
        records[p00_gmail.EXPIRED]["unvalidated_claim"] = sentinel
        run.return_value = self.completed_process(stdout=output_for(records))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            result = p00_gmail.evaluate(
                root, evidence, {p00_gmail.REQUIREMENT_ID}
            )
            diagnostics = (
                evidence / "p00-gmail-diagnostics.json"
            ).read_bytes()
        self.assertEqual(1, result)
        self.assertNotIn(sentinel.encode("ascii"), diagnostics)

    @mock.patch("tools.evaluators.p00_gmail.subprocess.run")
    def test_ignores_unselected_requirement(self, run: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = p00_gmail.evaluate(
                Path(directory), Path(directory) / "evidence", set()
            )
        self.assertEqual(0, result)
        run.assert_not_called()

    @mock.patch("tools.evaluators.p00_gmail.subprocess.run")
    def test_command_launch_error_fails_closed(self, run: mock.Mock) -> None:
        run.side_effect = OSError("cargo unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            result = p00_gmail.evaluate(
                root, evidence, {p00_gmail.REQUIREMENT_ID}
            )
            passing_exists = (evidence / "P00-GML-001.json").exists()
            diagnostics_exists = (
                evidence / "p00-gmail-diagnostics.json"
            ).exists()
        self.assertEqual(1, result)
        self.assertFalse(passing_exists)
        self.assertTrue(diagnostics_exists)


class GmailDispatcherTests(unittest.TestCase):
    @mock.patch("tools.evaluators.run.p00_gmail.evaluate", return_value=0)
    def test_dispatcher_registers_gmail_requirement(
        self, evaluate: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence_dir = root / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {
                        "selected_requirement_ids": [
                            p00_gmail.REQUIREMENT_ID
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                "os.environ",
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                },
                clear=False,
            ):
                result = evaluator_run.main()
        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT,
            evidence_dir,
            {p00_gmail.REQUIREMENT_ID},
        )


if __name__ == "__main__":
    unittest.main()
