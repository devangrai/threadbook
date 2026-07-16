from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from tools import p09_acceptance_smoke as smoke
from tools.evaluators import p09_acceptance as evaluator
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]
SOURCE_FINGERPRINT = "1" * 64
APPLICATION = {
    "bundle_sha256": "2" * 64,
    "bundle_file_count": 12,
    "bundle_bytes": 4096,
    "bundle_budget_bytes": smoke.PACKAGE_SIZE_BUDGET_BYTES,
    "executable_sha256": "3" * 64,
    "supply_manifest_sha256": "4" * 64,
    "migration_prefix_sha256": "5" * 64,
}


def copy_files(root: Path, relatives: object) -> None:
    for relative in relatives:
        destination = root / str(relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / str(relative), destination)


def command_record(
    command: smoke.CommandSpec,
) -> dict[str, object]:
    output = b"focused acceptance check passed\n"
    return {
        "command": list(command.logical),
        "duration_ns": 1,
        "executable_sha256": "6" * 64,
        "exit_code": 0,
        "output_bytes": len(output),
        "output_limit_exceeded": False,
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "timed_out": False,
    }


def acceptance_payload() -> dict[str, object]:
    suite_specs = smoke._suite_specs(ROOT, ROOT / "acceptance-work")
    return {
        "schema_version": 1,
        "artifact_kind": "p09_release_evidence",
        "profile": "personal_mvp",
        "run_id": smoke.RUN_ID,
        "created_at": "2026-07-16T06:27:00+00:00",
        "overall_status": "pass",
        "source_fingerprint": SOURCE_FINGERPRINT,
        "git_revision": "0" * 40,
        "working_tree_status_sha256": "7" * 64,
        "packet_hashes": {
            "proposal.md": evaluator.EXPECTED_PACKET_HASHES[
                f"{evaluator.PACKET_DIR}/proposal.md"
            ],
            "requirements.json": evaluator.EXPECTED_PACKET_HASHES[
                f"{evaluator.PACKET_DIR}/requirements.json"
            ],
            "review.md": evaluator.EXPECTED_PACKET_HASHES[
                f"{evaluator.PACKET_DIR}/review.md"
            ],
        },
        "platform": {
            "system": smoke.platform.system(),
            "release": smoke.platform.release(),
            "machine": smoke.platform.machine(),
        },
        "application": copy.deepcopy(APPLICATION),
        "suites": [
            {
                "name": specification.name,
                "status": "pass",
                "budget_ns": specification.budget_seconds * 1_000_000_000,
                "duration_ns": 1,
                "commands": [
                    command_record(command)
                    for command in specification.commands
                ],
            }
            for specification in suite_specs
        ],
        "packaged_workflow": {
            "report_sha256": "8" * 64,
            "bundle_sha256": APPLICATION["bundle_sha256"],
            "executable_sha256": "9" * 64,
            "collage_sha256": "b" * 64,
            "network_denied_for_process_tree": True,
            "accessibility_automation_used": True,
            "browser_mock_used": False,
        },
        "supply_chain": {
            "report_sha256": "c" * 64,
            "bundle_sha256": APPLICATION["bundle_sha256"],
            "manifest_sha256": "d" * 64,
            "dependency_count": 1,
            "license_count": 1,
            "model_artifact_count": 0,
            "network_sandbox_enforced": True,
            "remote_model_code_allowed": False,
        },
        "requirements": smoke._requirements(),
        "limitations": smoke._limitations(),
        "local_signature": {
            "kind": "macos_adhoc_codesign",
            "whole_bundle_integrity": True,
            "external_signer_identity": False,
        },
        "privacy": {
            "raw_command_output_included": False,
            "absolute_host_paths_included": False,
            "private_credentials_used": False,
            "personal_source_content_included": False,
            "browser_mock_used_for_packaged_e2e": False,
        },
    }


def validation(payload: dict[str, object]) -> smoke.BundleValidation:
    encoded = smoke.canonical_json(payload)
    return smoke.BundleValidation(
        payload=payload,
        payload_sha256=hashlib.sha256(encoded).hexdigest(),
        tree_sha256="e" * 64,
        file_count=len(smoke.EXPECTED_BUNDLE_FILES),
        total_bytes=len(encoded),
    )


def command_result(returncode: int = 0) -> CommandResult:
    output = b'{"status":"pass"}\n'
    return CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


class P09AcceptanceEvaluatorTests(unittest.TestCase):
    def payload_errors(self, payload: dict[str, object]) -> list[str]:
        with (
            mock.patch.object(
                evaluator,
                "source_fingerprint",
                return_value=SOURCE_FINGERPRINT,
            ),
            mock.patch.object(
                smoke,
                "_application_identity",
                return_value=APPLICATION,
            ),
        ):
            return evaluator._validate_payload(ROOT, validation(payload))

    def validate_bundle_payload(self, payload: dict[str, object]) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "fixture.bundle"
            payload_path = bundle / smoke.PAYLOAD_RELATIVE
            payload_path.parent.mkdir(parents=True)
            payload_path.write_bytes(smoke.canonical_json(payload))
            with (
                mock.patch.object(smoke, "_verify_codesign"),
                mock.patch.object(
                    smoke,
                    "_bounded_bundle_tree",
                    return_value=("f" * 64, 1, payload_path.stat().st_size),
                ),
            ):
                smoke.validate_bundle(bundle)

    def test_frozen_packet_contract_accepts_only_approved_bytes_and_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_files(
                root,
                (*evaluator.EXPECTED_PACKET_HASHES, evaluator.STATE_FILE),
            )
            state_path = root / evaluator.STATE_FILE
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["status"] = "BUILT"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            errors, packet_sha256 = evaluator.validate_packet(root)
            self.assertEqual([], errors)
            self.assertRegex(packet_sha256, r"^[0-9a-f]{64}$")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_files(
                root,
                (*evaluator.EXPECTED_PACKET_HASHES, evaluator.STATE_FILE),
            )
            proposal = root / evaluator.PACKET_DIR / "proposal.md"
            proposal.write_bytes(proposal.read_bytes() + b"\nmutation\n")
            errors, _ = evaluator.validate_packet(root)
            self.assertIn(
                f"frozen packet hash changed: {evaluator.PACKET_DIR}/proposal.md",
                errors,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_files(
                root,
                (*evaluator.EXPECTED_PACKET_HASHES, evaluator.STATE_FILE),
            )
            state_path = root / evaluator.STATE_FILE
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["review"]["decision"] = "REJECT"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            errors, _ = evaluator.validate_packet(root)
            self.assertIn(
                "P09 acceptance packet is not independently approved",
                errors,
            )

    def test_source_validation_requires_complete_safe_contract(self) -> None:
        errors, source_sha256, count = evaluator.validate_source(ROOT)
        self.assertEqual([], errors)
        self.assertEqual(len(evaluator.REQUIRED_SOURCE_FILES), count)
        self.assertRegex(source_sha256, r"^[0-9a-f]{64}$")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_files(root, evaluator.REQUIRED_SOURCE_FILES)
            missing = evaluator.REQUIRED_SOURCE_FILES[-1]
            (root / missing).unlink()
            smoke_path = root / "tools/p09_acceptance_smoke.py"
            smoke_path.write_text(
                smoke_path.read_text(encoding="utf-8").replace(
                    "Signature=adhoc",
                    "Signature=changed",
                ),
                encoding="utf-8",
            )

            errors, _, count = evaluator.validate_source(root)

        self.assertIn(
            f"required P09 acceptance source is unreadable or unsafe: {missing}",
            errors,
        )
        self.assertIn("P09 acceptance source contract is incomplete", errors)
        self.assertEqual(len(evaluator.REQUIRED_SOURCE_FILES) - 1, count)

    def test_payload_rejects_suite_command_and_private_path_drift(self) -> None:
        self.assertEqual([], self.payload_errors(acceptance_payload()))

        mutations: list[tuple[str, dict[str, object], str]] = []
        missing_suite = acceptance_payload()
        missing_suite["suites"].pop()
        mutations.append(
            ("suite inventory", missing_suite, "suite inventory is not exact")
        )

        over_budget = acceptance_payload()
        over_budget["suites"][0]["duration_ns"] = (
            over_budget["suites"][0]["budget_ns"] + 1
        )
        mutations.append(
            ("suite budget", over_budget, "suite result is invalid")
        )

        extra_command_field = acceptance_payload()
        extra_command_field["suites"][0]["commands"][0]["raw_output"] = "secret"
        mutations.append(
            ("command shape", extra_command_field, "command result is invalid")
        )

        private_path = acceptance_payload()
        private_path["suites"][0]["commands"][0]["command"] = [
            "python3",
            str(Path.home() / "private-check.py"),
        ]
        mutations.append(
            ("private path", private_path, "command result is invalid")
        )

        for name, payload, expected in mutations:
            with self.subTest(name=name):
                self.assertTrue(
                    any(expected in error for error in self.payload_errors(payload))
                )

    def test_payload_rejects_untruthful_limitations_and_privacy(self) -> None:
        limitation = acceptance_payload()
        limitation["limitations"][0]["feature_enabled"] = True
        with self.assertRaisesRegex(smoke.AcceptanceFailure, "limitations"):
            self.validate_bundle_payload(limitation)

        privacy = acceptance_payload()
        privacy["privacy"]["private_credentials_used"] = True
        self.assertIn(
            "signed acceptance privacy declaration is invalid",
            self.payload_errors(privacy),
        )

    def test_existing_owned_output_rejects_run_before_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            existing = evidence / smoke.BUNDLE_NAME
            existing.mkdir()
            runner = mock.Mock()
            with (
                mock.patch.object(
                    evaluator,
                    "validate_packet",
                    return_value=([], "a" * 64),
                ),
                mock.patch.object(
                    evaluator,
                    "validate_source",
                    return_value=([], "b" * 64, 1),
                ),
                mock.patch.object(evaluator, "run_bounded_command", runner),
            ):
                result = evaluator.evaluate(
                    ROOT,
                    evidence,
                    {"P09-ACC-001"},
                )

            diagnostic = json.loads(
                (evidence / evaluator.DIAGNOSTICS_NAME).read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(1, result)
        runner.assert_not_called()
        self.assertEqual("fail", diagnostic["status"])
        self.assertIn(
            "P09 acceptance output inventory is not empty",
            diagnostic["failures"],
        )

    @unittest.skipUnless(
        sys.platform == "darwin"
        and smoke.CODESIGN.is_file()
        and os.access(smoke.CODESIGN, os.X_OK),
        "requires macOS /usr/bin/codesign",
    )
    def test_success_emits_fourteen_records_from_real_adhoc_bundle(self) -> None:
        payload = acceptance_payload()

        def run(command: list[str], **kwargs: object) -> CommandResult:
            self.assertEqual(
                [sys.executable, str(ROOT / "tools/p09_acceptance_smoke.py")],
                command,
            )
            smoke._publish_bundle(Path(kwargs["env"]["HARNESS_EVIDENCE_DIR"]), payload)
            return command_result()

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    evaluator,
                    "source_fingerprint",
                    return_value=SOURCE_FINGERPRINT,
                ),
                mock.patch.object(
                    smoke,
                    "_application_identity",
                    return_value=APPLICATION,
                ),
                mock.patch.object(
                    evaluator,
                    "run_bounded_command",
                    side_effect=run,
                ),
            ):
                result = evaluator.evaluate(
                    ROOT,
                    evidence,
                    {"P09-ACC-001"},
                )

            routing = evidence / smoke.ROUTING_DIRECTORY_NAME
            records = [
                json.loads((routing / f"{requirement_id}.json").read_text())
                for requirement_id in smoke.REQUIREMENT_IDS
            ]
            validated = smoke.validate_bundle(evidence / smoke.BUNDLE_NAME)
            diagnostic = json.loads(
                (routing / evaluator.DIAGNOSTICS_NAME).read_text(
                    encoding="utf-8"
                )
            )

        self.assertEqual(0, result)
        self.assertEqual(smoke.MAX_REQUIREMENTS, len(records))
        self.assertEqual(set(smoke.REQUIREMENT_IDS), {
            record["requirement_id"] for record in records
        })
        self.assertTrue(all(record["status"] == "pass" for record in records))
        self.assertEqual("pass", diagnostic["status"])
        self.assertEqual(payload, validated.payload)

    def test_runner_failure_emits_diagnostic_and_no_pass_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    evaluator,
                    "validate_packet",
                    return_value=([], "a" * 64),
                ),
                mock.patch.object(
                    evaluator,
                    "validate_source",
                    return_value=([], "b" * 64, 1),
                ),
                mock.patch.object(
                    evaluator,
                    "run_bounded_command",
                    return_value=command_result(returncode=1),
                ),
            ):
                result = evaluator.evaluate(
                    ROOT,
                    evidence,
                    {"P09-ACC-001"},
                )

            diagnostic = json.loads(
                (evidence / evaluator.DIAGNOSTICS_NAME).read_text(
                    encoding="utf-8"
                )
            )
            pass_records = [
                evidence / f"{requirement_id}.json"
                for requirement_id in smoke.REQUIREMENT_IDS
                if (evidence / f"{requirement_id}.json").exists()
            ]

        self.assertEqual(1, result)
        self.assertEqual([], pass_records)
        self.assertEqual("fail", diagnostic["status"])
        self.assertIn("P09 acceptance runner failed", diagnostic["failures"])

    def test_routing_publication_failure_leaves_no_passing_records(self) -> None:
        payload = acceptance_payload()

        def run(command: list[str], **kwargs: object) -> CommandResult:
            smoke._publish_bundle(
                Path(kwargs["env"]["HARNESS_EVIDENCE_DIR"]),
                payload,
            )
            return command_result()

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            original_write = evaluator._write_bounded
            calls = 0

            def fail_fifth_write(path: Path, value: dict[str, object]) -> None:
                nonlocal calls
                calls += 1
                if calls == 5:
                    raise OSError("injected routing write failure")
                original_write(path, value)

            with (
                mock.patch.object(
                    evaluator,
                    "source_fingerprint",
                    return_value=SOURCE_FINGERPRINT,
                ),
                mock.patch.object(
                    smoke,
                    "_application_identity",
                    return_value=APPLICATION,
                ),
                mock.patch.object(
                    evaluator,
                    "run_bounded_command",
                    side_effect=run,
                ),
                mock.patch.object(
                    evaluator,
                    "_write_bounded",
                    side_effect=fail_fifth_write,
                ),
            ):
                result = evaluator.evaluate(
                    ROOT,
                    evidence,
                    {"P09-ACC-001"},
                )

            routing = evidence / smoke.ROUTING_DIRECTORY_NAME
            routing_exists = routing.exists()
            direct_records = [
                evidence / f"{requirement_id}.json"
                for requirement_id in smoke.REQUIREMENT_IDS
                if (evidence / f"{requirement_id}.json").exists()
            ]
            temporary = list(
                evidence.glob(f".{smoke.ROUTING_DIRECTORY_NAME}.*")
            )

        self.assertEqual(1, result)
        self.assertFalse(routing_exists)
        self.assertEqual([], direct_records)
        self.assertEqual([], temporary)


if __name__ == "__main__":
    unittest.main()
