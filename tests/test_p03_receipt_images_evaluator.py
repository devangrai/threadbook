from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p03_receipt_images
from tools.evaluators import run as evaluator_run


ROOT = Path(__file__).resolve().parents[1]


def successful_result() -> p03_receipt_images.CommandResult:
    output = b"bounded output"
    return p03_receipt_images.CommandResult(
        returncode=0,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
    )


class DispatcherTests(unittest.TestCase):
    def test_dispatches_image_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence_dir = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": ["P03-IMG-001"]}),
                encoding="utf-8",
            )
            with (
                mock.patch.dict(
                    "os.environ",
                    {
                        "HARNESS_RUN_DIR": str(run_dir),
                        "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                    },
                    clear=False,
                ),
                mock.patch.object(
                    evaluator_run.p03_receipt_images,
                    "evaluate",
                    return_value=0,
                ) as evaluate,
            ):
                result = evaluator_run.main()
        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            ROOT, evidence_dir, {"P03-IMG-001"}
        )


class EvaluatorTests(unittest.TestCase):
    def test_current_source_contract_is_complete(self) -> None:
        result = p03_receipt_images.validate_source_contract(ROOT)
        self.assertEqual((), result.errors)
        self.assertTrue(result.production_downloader_wired)
        self.assertTrue(result.production_transport_isolated)
        self.assertEqual(64, len(result.migration_sha256))

    def test_missing_source_fails_without_running_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            with mock.patch.object(
                p03_receipt_images, "run_bounded_command"
            ) as command:
                result = p03_receipt_images.evaluate(
                    root, evidence, {"P03-IMG-001"}
                )
            diagnostics = json.loads(
                (evidence / p03_receipt_images.DIAGNOSTICS_NAME).read_text()
            )
        self.assertEqual(1, result)
        command.assert_not_called()
        self.assertEqual("fail", diagnostics["status"])

    def test_command_failure_removes_stale_pass_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P03-IMG-001.json"
            stale.write_text("{}", encoding="utf-8")
            validation = p03_receipt_images.SourceValidation(
                errors=(),
                source_sha256="a" * 64,
                migration_sha256="b" * 64,
                registered_commands=p03_receipt_images.COMMANDS,
                acl_permissions=(),
                production_downloader_wired=True,
                production_transport_isolated=True,
            )
            failed = p03_receipt_images.CommandResult(
                returncode=1,
                output_sha256="c" * 64,
                output_bytes=0,
                duration_ms=1,
            )
            with (
                mock.patch.object(
                    p03_receipt_images,
                    "validate_source_contract",
                    return_value=validation,
                ),
                mock.patch.object(
                    p03_receipt_images,
                    "run_bounded_command",
                    return_value=failed,
                ),
            ):
                result = p03_receipt_images.evaluate(
                    ROOT, evidence, {"P03-IMG-001"}
                )
        self.assertEqual(1, result)
        self.assertFalse(stale.exists())

    def test_success_writes_hashed_bounded_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            validation = p03_receipt_images.SourceValidation(
                errors=(),
                source_sha256="a" * 64,
                migration_sha256="b" * 64,
                registered_commands=p03_receipt_images.COMMANDS,
                acl_permissions=(),
                production_downloader_wired=True,
                production_transport_isolated=True,
            )
            with (
                mock.patch.object(
                    p03_receipt_images,
                    "validate_source_contract",
                    return_value=validation,
                ),
                mock.patch.object(
                    p03_receipt_images,
                    "run_bounded_command",
                    return_value=successful_result(),
                ),
            ):
                result = p03_receipt_images.evaluate(
                    ROOT, evidence, {"P03-IMG-001"}
                )
            value = json.loads(
                (evidence / "P03-IMG-001.json").read_text()
            )
        self.assertEqual(0, result)
        self.assertEqual("pass", value["status"])
        self.assertEqual(
            len(p03_receipt_images.COMMAND_CHECKS),
            len(value["details"]["checks"]),
        )


if __name__ == "__main__":
    unittest.main()
