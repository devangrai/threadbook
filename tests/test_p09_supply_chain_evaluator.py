from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p09_supply_chain
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def command_result(returncode: int = 0) -> CommandResult:
    output = (
        "OK\n"
        "test result: ok\n"
        "generated_remote_model_bindings_match_the_reviewed_release_policy\n"
        + "\n".join(p09_supply_chain.EXPECTED_RELEASE_TESTS)
        + "\n"
        + p09_supply_chain.EXPECTED_STARTUP_TEST
    ).encode()
    return CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


def packet_validation(
    errors: tuple[str, ...] = (),
) -> p09_supply_chain.PacketValidation:
    return p09_supply_chain.PacketValidation(errors, "a" * 64, {"packet": "b" * 64})


def source_validation() -> p09_supply_chain.SourceValidation:
    return p09_supply_chain.SourceValidation(
        (),
        "c" * 64,
        {"source": "d" * 64},
        18,
    )


def manifest_validation() -> p09_supply_chain.ManifestValidation:
    return p09_supply_chain.ManifestValidation(
        (),
        "e" * 64,
        599,
        599,
        10,
        0,
    )


def bundle_validation() -> p09_supply_chain.BundleValidation:
    return p09_supply_chain.BundleValidation((), "f" * 64, 8, "e" * 64)


def smoke_validation(
    errors: tuple[str, ...] = (),
) -> p09_supply_chain.SmokeValidation:
    return p09_supply_chain.SmokeValidation(
        errors,
        "1" * 64,
        "f" * 64,
        hashlib.sha256(
            p09_supply_chain.p09_supply_chain_smoke.SANDBOX_PROFILE.encode()
        ).hexdigest(),
    )


def smoke_report() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "pass",
        "platform": "macos",
        "network_control_passed": True,
        "network_sandbox_enforced": True,
        "sandbox_profile_sha256": hashlib.sha256(
            p09_supply_chain.p09_supply_chain_smoke.SANDBOX_PROFILE.encode()
        ).hexdigest(),
        "supply_check_passed": True,
        "installed_tree_check_passed": True,
        "startup_gate_verified": True,
        "canonical_manifest_verified": True,
        "bundled_manifest_exact": True,
        "generated_manifest_sha256": "e" * 64,
        "bundled_manifest_sha256": "e" * 64,
        "bundle_sha256": "f" * 64,
        "bundle_file_count": 8,
        "dependency_count": 599,
        "license_count": 599,
        "model_artifact_count": 0,
        "local_segmentation_availability": "unavailable",
        "remote_model_code_allowed": False,
        "private_credentials_used": False,
        "developer_id_signed": False,
        "notarized": False,
        "clean_machine_certified": False,
        "acceptance_claim": "focused_supply_chain_packet_passed",
        "scope_limitation": (
            "Developer ID signing, notarization, clean-machine certification, "
            "and whole-bundle authenticity are outside this packet."
        ),
    }


class P09SupplyChainEvaluatorTests(unittest.TestCase):
    def test_current_packet_source_and_generated_manifest_are_valid(self) -> None:
        packet = p09_supply_chain.validate_packet(ROOT)
        source = p09_supply_chain.validate_source(ROOT)
        manifest = p09_supply_chain.validate_generated_manifest(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual((), source.errors)
        self.assertEqual((), manifest.errors)
        self.assertGreater(manifest.dependency_count, 0)
        self.assertEqual(manifest.dependency_count, manifest.license_count)
        self.assertEqual(0, manifest.model_artifact_count)

    def test_packet_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                *p09_supply_chain.EXPECTED_PACKET_HASHES,
                p09_supply_chain.STATE_FILE,
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            proposal = root / p09_supply_chain.PACKET_DIR / "proposal.md"
            proposal.write_text(
                proposal.read_text(encoding="utf-8") + "\nmutation\n",
                encoding="utf-8",
            )

            validation = p09_supply_chain.validate_packet(root)

        self.assertTrue(
            any("proposal.md" in error for error in validation.errors),
            validation.errors,
        )

    def test_manifest_rejects_remote_code_and_license_projection_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = json.loads(
                (ROOT / p09_supply_chain.MANIFEST_RELATIVE).read_text(encoding="utf-8")
            )
            for relative in current["input_hashes"]:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            metadata = root / "release/wardrobe-build-metadata-v1.json"
            if not metadata.exists():
                metadata.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(
                    ROOT / "release/wardrobe-build-metadata-v1.json",
                    metadata,
                )
            current["models"]["remote_model_code_allowed"] = True
            current["licenses"][0]["license"] = "drifted"
            generated = root / p09_supply_chain.MANIFEST_RELATIVE
            generated.parent.mkdir(parents=True, exist_ok=True)
            generated.write_text(
                json.dumps(current, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            validation = p09_supply_chain.validate_generated_manifest(root)

        self.assertTrue(
            any("license inventory" in error for error in validation.errors)
        )
        self.assertTrue(
            any("prohibited-code truth" in error for error in validation.errors)
        )

    def test_smoke_rejects_signing_overclaim_and_release_state_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "smoke.json"
            report = smoke_report()
            report["developer_id_signed"] = True
            report["bundle_sha256"] = "0" * 64
            path.write_text(json.dumps(report), encoding="utf-8")

            validation = p09_supply_chain.validate_smoke(
                path,
                manifest_validation(),
                bundle_validation(),
            )

        self.assertTrue(
            any(
                "overstated developer_id_signed" in error for error in validation.errors
            )
        )
        self.assertTrue(
            any("current release state" in error for error in validation.errors)
        )

    def test_success_writes_non_deferred_supply_and_system_evidence(self) -> None:
        def run(command: list[str], **kwargs: object) -> CommandResult:
            if "tools/p09_supply_chain_smoke.py" in command:
                report = Path(command[command.index("--report") + 1])
                report.write_text(json.dumps(smoke_report()), encoding="utf-8")
            return command_result()

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p09_supply_chain,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p09_supply_chain,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p09_supply_chain,
                    "validate_generated_manifest",
                    return_value=manifest_validation(),
                ),
                mock.patch.object(
                    p09_supply_chain,
                    "validate_bundle",
                    return_value=bundle_validation(),
                ),
                mock.patch.object(
                    p09_supply_chain,
                    "validate_smoke",
                    return_value=smoke_validation(),
                ),
                mock.patch.object(
                    p09_supply_chain,
                    "run_bounded_command",
                    side_effect=run,
                ),
            ):
                result = p09_supply_chain.evaluate(
                    ROOT,
                    evidence,
                    {"P09-SUP-001"},
                )

            self.assertEqual(0, result)
            supply = json.loads(
                (evidence / "P09-SUP-001.json").read_text(encoding="utf-8")
            )
            self.assertEqual("pass", supply["status"])
            summary = supply["details"]["public_summary"]
            self.assertEqual(
                "focused_supply_chain_packet_passed",
                summary["acceptance_claim"],
            )
            self.assertFalse(summary["remote_model_code_allowed"])
            self.assertFalse(summary["developer_id_signed"])
            system = json.loads(
                (evidence / "SYS-SEC-001.json").read_text(encoding="utf-8")
            )
            self.assertEqual("pass", system["status"])

    def test_failure_removes_stale_pass_and_smoke_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P09-SUP-001.json"
            stale.write_text("{}", encoding="utf-8")
            stale_smoke = evidence / p09_supply_chain.SMOKE_NAME
            stale_smoke.write_text('{"status":"pass"}', encoding="utf-8")
            with (
                mock.patch.object(
                    p09_supply_chain,
                    "validate_packet",
                    return_value=packet_validation(("packet changed",)),
                ),
                mock.patch.object(
                    p09_supply_chain,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p09_supply_chain,
                    "validate_generated_manifest",
                    return_value=manifest_validation(),
                ),
            ):
                result = p09_supply_chain.evaluate(
                    ROOT,
                    evidence,
                    {"P09-SUP-001"},
                )

            self.assertEqual(1, result)
            self.assertFalse(stale.exists())
            self.assertFalse(stale_smoke.exists())
            diagnostics = json.loads(
                (evidence / p09_supply_chain.DIAGNOSTICS_NAME).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual("fail", diagnostics["status"])

    @mock.patch(
        "tools.evaluators.run.p09_supply_chain.evaluate",
        return_value=0,
    )
    def test_runner_dispatches_supply_chain(self, evaluate: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": ["P09-SUP-001"]}),
                encoding="utf-8",
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
        evaluate.assert_called_once_with(
            ROOT,
            evidence,
            {"P09-SUP-001"},
        )


if __name__ == "__main__":
    unittest.main()
