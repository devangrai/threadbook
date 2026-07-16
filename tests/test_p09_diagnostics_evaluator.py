from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p09_diagnostics
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def command_result(output: bytes = b"test result: ok") -> CommandResult:
    return CommandResult(
        returncode=0,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


class P09DiagnosticsEvaluatorTests(unittest.TestCase):
    def test_current_packet_and_source_are_valid(self) -> None:
        packet = p09_diagnostics.validate_packet(ROOT)
        source = p09_diagnostics.validate_source(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual((), source.errors)
        self.assertEqual(len(p09_diagnostics.SOURCE_FILES), source.file_count)
        self.assertEqual(64, len(packet.sha256))
        self.assertEqual(64, len(source.sha256))

    def test_source_validation_rejects_legacy_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in p09_diagnostics.SOURCE_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / relative).read_bytes())
            path = root / "crates/wardrobe-core/src/diagnostics_backend.rs"
            path.write_text(
                path.read_text() + "\nstruct DiagnosticsPublicationStatusV1;\n"
            )

            source = p09_diagnostics.validate_source(root)

        self.assertTrue(any("legacy diagnostics" in item for item in source.errors))

    def test_success_writes_pass_and_truthful_deferred_evidence(self) -> None:
        smoke = (
            b"running 1 test\n"
            b"diagnostics_export_uses_real_sqlite_log_and_atomic_filesystem_path\n"
            b"test result: ok\n"
        )

        def result_for(command: list[str], **_: object) -> CommandResult:
            return command_result(smoke if "wardrobe-desktop" in command else b"ok")

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with mock.patch.object(
                p09_diagnostics,
                "run_bounded_command",
                side_effect=result_for,
            ):
                result = p09_diagnostics.evaluate(
                    ROOT, evidence, {"P09-DIA-001"}
                )

            self.assertEqual(0, result)
            self.assertEqual(
                {
                    *(f"{item}.json" for item in p09_diagnostics.REQUIREMENT_IDS),
                    p09_diagnostics.DIAGNOSTICS_NAME,
                },
                {path.name for path in evidence.iterdir()},
            )
            for requirement in p09_diagnostics.DEFERRED_REQUIREMENT_IDS:
                payload = json.loads(
                    (evidence / f"{requirement}.json").read_text()
                )
                self.assertEqual("deferred", payload["status"])
                summary = payload["details"]["public_summary"]
                self.assertFalse(summary["feature_enabled"])
                self.assertEqual("deferred_not_passed", summary["acceptance_claim"])

    def test_failure_removes_stale_pass_evidence(self) -> None:
        failed = CommandResult(
            returncode=1,
            output_sha256="0" * 64,
            output_bytes=0,
            duration_ms=1,
        )
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P09-DIA-001.json"
            stale.write_text("{}")
            with mock.patch.object(
                p09_diagnostics,
                "run_bounded_command",
                return_value=failed,
            ):
                result = p09_diagnostics.evaluate(
                    ROOT, evidence, {"P09-DIA-001"}
                )

            self.assertEqual(1, result)
            self.assertFalse(stale.exists())
            diagnostics = json.loads(
                (evidence / p09_diagnostics.DIAGNOSTICS_NAME).read_text()
            )
            self.assertEqual("fail", diagnostics["status"])

    @mock.patch("tools.evaluators.run.p09_diagnostics.evaluate", return_value=0)
    def test_runner_dispatches_diagnostics(self, evaluate: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": ["P09-DIA-001"]})
            )
            with mock.patch.dict(
                "os.environ",
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence),
                },
                clear=False,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(ROOT, evidence, {"P09-DIA-001"})
