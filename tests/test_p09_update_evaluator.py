from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p09_update
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def command_result() -> CommandResult:
    output = b"test result: ok\n"
    return CommandResult(
        returncode=0,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


def smoke_report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "pass",
        "real_ed25519": True,
        "canonical_manifest_verified": True,
        "valid_package_staged": True,
        "exact_signed_package_retained": True,
        "staged_package_reverified": True,
        "artifact_tamper_rejected": True,
        "manifest_tamper_rejected": True,
        "noncanonical_manifest_rejected": True,
        "database_unchanged": True,
        "database_lineage_unchanged": True,
        "live_data_tree_unchanged": True,
        "production_keyring_empty": True,
        "network_sandbox_enforced": True,
        "install_feature_enabled": False,
        "acceptance_claim": "deferred_not_passed",
        "deferred_limitation": "genuine installation is absent",
    }


class P09UpdateEvaluatorTests(unittest.TestCase):
    def test_current_packet_source_and_bundle_are_valid(self) -> None:
        packet = p09_update.validate_packet(ROOT)
        source = p09_update.validate_source(ROOT)
        bundle = p09_update.validate_bundle(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual((), source.errors)
        self.assertEqual((), bundle.errors)
        self.assertEqual(len(p09_update.SOURCE_FILES), source.count)

    def test_smoke_rejects_an_installation_overclaim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "smoke.json"
            report = smoke_report()
            report["install_feature_enabled"] = True
            report["acceptance_claim"] = "passed"
            path.write_text(json.dumps(report))

            errors, _ = p09_update.validate_smoke(path)

        self.assertTrue(any("enabled deferred installer" in item for item in errors))
        self.assertTrue(any("overstated" in item for item in errors))

    def test_success_writes_pass_system_and_deferred_update_evidence(self) -> None:
        def run(command: list[str], **kwargs: object) -> CommandResult:
            if "--example" in command:
                environment = kwargs["env"]
                assert isinstance(environment, dict)
                Path(environment["P09_UPDATE_SMOKE_REPORT"]).write_text(
                    json.dumps(smoke_report())
                )
            return command_result()

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with mock.patch.object(
                p09_update, "run_bounded_command", side_effect=run
            ):
                result = p09_update.evaluate(ROOT, evidence, {"P09-UPG-001"})

            self.assertEqual(0, result)
            update = json.loads((evidence / "P09-UPG-001.json").read_text())
            self.assertEqual("deferred", update["status"])
            summary = update["details"]["public_summary"]
            self.assertFalse(summary["feature_enabled"])
            self.assertEqual("deferred_not_passed", summary["acceptance_claim"])
            system = json.loads((evidence / "SYS-SEC-001.json").read_text())
            self.assertEqual("pass", system["status"])

    def test_failure_removes_stale_pass_evidence(self) -> None:
        failed = CommandResult(
            returncode=1,
            output_sha256="0" * 64,
            output_bytes=0,
            duration_ms=1,
        )
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P09-UPG-001.json"
            stale.write_text("{}")
            with mock.patch.object(
                p09_update, "run_bounded_command", return_value=failed
            ):
                result = p09_update.evaluate(ROOT, evidence, {"P09-UPG-001"})

            self.assertEqual(1, result)
            self.assertFalse(stale.exists())
            diagnostics = json.loads(
                (evidence / p09_update.DIAGNOSTICS_NAME).read_text()
            )
            self.assertEqual("fail", diagnostics["status"])

    @mock.patch("tools.evaluators.run.p09_update.evaluate", return_value=0)
    def test_runner_dispatches_update(self, evaluate: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": ["P09-UPG-001"]})
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
        evaluate.assert_called_once_with(ROOT, evidence, {"P09-UPG-001"})
