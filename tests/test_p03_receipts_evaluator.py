from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p03_receipts
from tools.evaluators import run as evaluator_run


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def copy(path: str, root: Path) -> None:
    destination = root / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPOSITORY_ROOT / path, destination)


def write_valid_fixture(root: Path) -> None:
    copy("fixtures/receipts/v1/manifest.json", root)
    for relative in p03_receipts.SOURCE_FILES:
        copy(relative, root)


def quality_report(**overrides: object) -> dict[str, object]:
    report: dict[str, object] = {
        "schema_version": 1,
        "status": "pass",
        "test_name": (
            "frozen_corpus_has_full_recall_valid_citations_and_no_"
            "unsupported_fabrication"
        ),
        "corpus_sha256": p03_receipts.APPROVED_CORPUS_SHA256,
        "message_count": 24,
        "coverage_count": 12,
        "matched_lines": 48,
        "gold_lines": 48,
        "manifest_gold_lines": 48,
        "recall": 1.0,
        "spurious_lines": 0,
        "unsupported_field_failures": 0,
        "citation_failures": 0,
        "parser_revision": "mail-parser-0.11.5/receipt-parser-v1",
        "sanitizer_revision": "html5ever-0.38/receipt-sanitizer-v1",
        "provider_id": "local-deterministic-receipt-provider",
        "provider_revision": "local-deterministic-receipt-provider-v1",
        "schema_revision": "receipt-extraction-v1",
        "ruleset_revision": "explicit-receipt-evidence-rules-v1",
    }
    report.update(overrides)
    return report


def command_result(
    returncode: int = 0,
    *,
    output: bytes = b"bounded test output",
    timed_out: bool = False,
    output_limit_exceeded: bool = False,
    launch_failed: bool = False,
) -> p03_receipts.CommandResult:
    return p03_receipts.CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=10,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        launch_failed=launch_failed,
        captured_output=output,
    )


def successful_command(
    command: list[str],
    **_: object,
) -> p03_receipts.CommandResult:
    if command[-1] == "tools/evaluators/p03_quality_report.py":
        output = json.dumps(quality_report()).encode("utf-8")
        return command_result(output=output)
    return command_result()


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class CorpusValidationTests(unittest.TestCase):
    @mock.patch("tools.evaluators.p03_receipts.run_bounded_command")
    def test_wrong_corpus_hash_fails_before_any_command(
        self,
        run: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            manifest = root / "fixtures/receipts/v1/manifest.json"
            manifest.write_bytes(manifest.read_bytes() + b"\n")
            evidence = root / "evidence"

            result = p03_receipts.evaluate(
                root, evidence, set(p03_receipts.REQUIREMENT_IDS)
            )
            diagnostics = read_json(
                evidence / p03_receipts.DIAGNOSTICS_NAME
            )

        self.assertEqual(1, result)
        run.assert_not_called()
        self.assertEqual("fail", diagnostics["status"])
        self.assertFalse(diagnostics["pass_evidence_written"])

    @mock.patch("tools.evaluators.p03_receipts.run_bounded_command")
    def test_lowered_threshold_fails_before_any_command(
        self,
        run: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            with mock.patch.object(
                p03_receipts, "MIN_ITEM_RECALL", 0.94
            ):
                result = p03_receipts.evaluate(
                    root,
                    root / "evidence",
                    set(p03_receipts.REQUIREMENT_IDS),
                )

        self.assertEqual(1, result)
        run.assert_not_called()

    def test_manifest_preflight_proves_24_48_and_required_coverage(self) -> None:
        result = p03_receipts.validate_corpus(REPOSITORY_ROOT)

        self.assertEqual((), result.errors)
        self.assertEqual(24, result.message_count)
        self.assertEqual(48, result.labeled_line_count)
        self.assertEqual(
            p03_receipts.REQUIRED_COVERAGE, set(result.coverage)
        )


class SourceValidationTests(unittest.TestCase):
    def test_current_production_contract_is_complete(self) -> None:
        result = p03_receipts.validate_source_contract(REPOSITORY_ROOT)

        self.assertTrue(
            all(not messages for messages in result.errors.values())
        )
        self.assertEqual(
            set(p03_receipts.P03_COMMANDS),
            set(p03_receipts.P03_COMMANDS) & set(result.registered_commands),
        )
        self.assertTrue(result.production_provider_wired)
        self.assertTrue(result.production_network_free)
        self.assertTrue(result.production_transport_isolated)
        self.assertEqual(
            64, len(result.migration_sha256["0003_receipts"])
        )

    def test_missing_command_acl_and_real_provider_fail_closed(self) -> None:
        mutations = (
            (
                "command",
                "src-tauri/src/lib.rs",
                "list_receipts_v1",
                "list_receipts_missing_v1",
            ),
            (
                "acl",
                "src-tauri/capabilities/main.json",
                "allow-analyze-receipt-v1",
                "allow-analyze-receipt-missing-v1",
            ),
            (
                "provider",
                "src-tauri/src/lib.rs",
                ".with_receipt_provider(LocalDeterministicReceiptProviderV1::new())",
                "",
            ),
        )
        for name, relative, before, after in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_valid_fixture(root)
                path = root / relative
                text = path.read_text(encoding="utf-8")
                self.assertIn(before, text)
                path.write_text(text.replace(before, after), encoding="utf-8")

                result = p03_receipts.validate_source_contract(root)

                self.assertTrue(
                    any(result.errors[requirement] for requirement in result.errors)
                )

    def test_provider_network_capability_and_bad_v3_checksum_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            provider = root / "crates/wardrobe-platform/src/receipt_provider.rs"
            provider.write_text(
                "fn forbidden_network() { let _ = reqwest::Client::new(); }\n"
                + provider.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            write(
                root
                / "crates/wardrobe-platform/migrations/0003_receipts.sha256",
                "0" * 64 + "\n",
            )

            result = p03_receipts.validate_source_contract(root)

        self.assertTrue(result.errors["P03-SAF-001"])
        self.assertTrue(result.errors["P03-QLT-001"])
        self.assertFalse(result.production_network_free)


class QualityReportTests(unittest.TestCase):
    def result_for(self, value: object) -> p03_receipts.CommandResult:
        return command_result(output=json.dumps(value).encode("utf-8"))

    def test_accepts_strict_machine_readable_report(self) -> None:
        report, error = p03_receipts.parse_quality_report(
            self.result_for(quality_report())
        )

        self.assertIsNone(error)
        self.assertEqual(48, report["matched_lines"])  # type: ignore[index]

    def test_rejects_malformed_or_incomplete_quality_reports(self) -> None:
        malformed = command_result(output=b"not json")
        report, error = p03_receipts.parse_quality_report(malformed)
        self.assertIsNone(report)
        self.assertIn("malformed", error or "")

        for mutation in (
            {"recall": 0.94, "matched_lines": 45},
            {"unsupported_field_failures": 1},
            {"citation_failures": 1},
            {"spurious_lines": 1},
            {"corpus_sha256": "0" * 64},
        ):
            with self.subTest(mutation=mutation):
                report, error = p03_receipts.parse_quality_report(
                    self.result_for(quality_report(**mutation))
                )
                self.assertIsNone(report)
                self.assertIsNotNone(error)


class BoundedCommandTests(unittest.TestCase):
    def test_timeout_and_output_bounds_are_enforced(self) -> None:
        with mock.patch.object(p03_receipts, "MAX_OUTPUT_BYTES", 32):
            output = p03_receipts.run_bounded_command(
                [sys.executable, "-c", "print('x' * 256)"],
                cwd=REPOSITORY_ROOT,
                env=os.environ.copy(),
                timeout_seconds=5,
                capture_output=True,
            )
        self.assertTrue(output.output_limit_exceeded)
        self.assertLessEqual(len(output.captured_output), 32)

        timeout = p03_receipts.run_bounded_command(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            cwd=REPOSITORY_ROOT,
            env=os.environ.copy(),
            timeout_seconds=0.05,
        )
        self.assertTrue(timeout.timed_out)


class EvaluatorTests(unittest.TestCase):
    @mock.patch(
        "tools.evaluators.p03_receipts.run_bounded_command",
        side_effect=successful_command,
    )
    def test_success_emits_standard_bounded_evidence(
        self,
        run: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            evidence = root / "evidence"

            result = p03_receipts.evaluate(
                root, evidence, set(p03_receipts.REQUIREMENT_IDS)
            )

            self.assertEqual(0, result)
            self.assertEqual(len(p03_receipts.COMMAND_CHECKS), run.call_count)
            for requirement in p03_receipts.REQUIREMENT_IDS:
                payload = read_json(evidence / f"{requirement}.json")
                self.assertEqual("pass", payload["status"])
                self.assertEqual(requirement, payload["requirement_id"])
                self.assertTrue(payload["test"])
                self.assertTrue(payload["recorded_at"])
                summary = payload["details"]["public_summary"]  # type: ignore[index]
                self.assertTrue(summary)
                self.assertTrue(
                    all(
                        value is None
                        or isinstance(value, (str, int, float, bool))
                        for value in summary.values()  # type: ignore[union-attr]
                    )
                )
            diagnostics = read_json(
                evidence / p03_receipts.DIAGNOSTICS_NAME
            )
            self.assertEqual("pass", diagnostics["status"])
            self.assertTrue(diagnostics["pass_evidence_written"])
            self.assertEqual(
                1.0,
                diagnostics["quality_report"]["recall"],  # type: ignore[index]
            )
            self.assertNotIn(str(root), json.dumps(diagnostics))

    def _assert_runtime_failure(
        self,
        failed_result: p03_receipts.CommandResult,
    ) -> None:
        calls = 0

        def run(command: list[str], **_: object) -> p03_receipts.CommandResult:
            nonlocal calls
            calls += 1
            if command[-1] == "tools/evaluators/p03_quality_report.py":
                return command_result(
                    output=json.dumps(quality_report()).encode("utf-8")
                )
            if calls == 2:
                return failed_result
            return command_result()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            evidence = root / "evidence"
            evidence.mkdir()
            for requirement in p03_receipts.REQUIREMENT_IDS:
                write(
                    evidence / f"{requirement}.json",
                    '{"status":"stale"}',
                )
            with mock.patch(
                "tools.evaluators.p03_receipts.run_bounded_command",
                side_effect=run,
            ):
                result = p03_receipts.evaluate(
                    root,
                    evidence,
                    set(p03_receipts.REQUIREMENT_IDS),
                )

            self.assertEqual(1, result)
            self.assertFalse(
                any(
                    (evidence / f"{requirement}.json").exists()
                    for requirement in p03_receipts.REQUIREMENT_IDS
                )
            )
            diagnostics = read_json(
                evidence / p03_receipts.DIAGNOSTICS_NAME
            )
            self.assertEqual("fail", diagnostics["status"])
            self.assertFalse(diagnostics["pass_evidence_written"])

    def test_command_failure_timeout_and_output_bound_emit_no_partial_pass(
        self,
    ) -> None:
        cases = (
            command_result(returncode=101),
            command_result(returncode=-15, timed_out=True),
            command_result(
                returncode=-15,
                output_limit_exceeded=True,
            ),
        )
        for result in cases:
            with self.subTest(result=result):
                self._assert_runtime_failure(result)

    @mock.patch(
        "tools.evaluators.p03_receipts.run_bounded_command"
    )
    def test_malformed_quality_report_cleans_stale_evidence(
        self,
        run: mock.Mock,
    ) -> None:
        run.return_value = command_result(output=b"{}")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            evidence = root / "evidence"
            evidence.mkdir()
            write(
                evidence / "P03-QLT-001.json",
                '{"status":"stale"}',
            )

            result = p03_receipts.evaluate(
                root, evidence, {"P03-QLT-001"}
            )

            self.assertEqual(1, result)
            self.assertFalse((evidence / "P03-QLT-001.json").exists())
            diagnostics = read_json(
                evidence / p03_receipts.DIAGNOSTICS_NAME
            )
            self.assertTrue(
                any(
                    "quality report" in error
                    for error in diagnostics["errors"]  # type: ignore[union-attr]
                )
            )

    @mock.patch("tools.evaluators.p03_receipts.run_bounded_command")
    def test_unselected_does_nothing(self, run: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = p03_receipts.evaluate(root, root / "evidence", set())
        self.assertEqual(0, result)
        run.assert_not_called()


class DispatcherTests(unittest.TestCase):
    @mock.patch(
        "tools.evaluators.run.p03_receipts.evaluate",
        return_value=0,
    )
    def test_dispatcher_routes_p03_requirements(
        self,
        evaluate: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence_dir = root / "evidence"
            run_dir.mkdir()
            selected = ["P03-MIM-001", "P03-QLT-001"]
            write(
                run_dir / "requirements.json",
                json.dumps({"selected_requirement_ids": selected}),
            )
            with mock.patch.dict(
                os.environ,
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                },
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT, evidence_dir, set(selected)
        )


if __name__ == "__main__":
    unittest.main()
