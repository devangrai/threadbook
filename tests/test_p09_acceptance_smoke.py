from __future__ import annotations

import copy
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

from tools import p09_acceptance_smoke as smoke


def acceptance_payload() -> dict[str, object]:
    root = Path(__file__).resolve().parents[1]
    suite_specs = smoke._suite_specs(root, root / "acceptance-work")

    def command_record(
        command: smoke.CommandSpec,
    ) -> dict[str, object]:
        return {
            "command": list(command.logical),
            "duration_ns": 1,
            "executable_sha256": "6" * 64,
            "exit_code": 0,
            "output_bytes": 1,
            "output_limit_exceeded": False,
            "output_sha256": "7" * 64,
            "timed_out": False,
        }

    return {
        "schema_version": 1,
        "artifact_kind": "p09_release_evidence",
        "profile": "personal_mvp",
        "run_id": smoke.RUN_ID,
        "created_at": "2026-07-16T06:27:00+00:00",
        "overall_status": "pass",
        "source_fingerprint": "1" * 64,
        "git_revision": "2" * 40,
        "working_tree_status_sha256": "3" * 64,
        "packet_hashes": {
            "proposal.md": "4" * 64,
            "requirements.json": "5" * 64,
            "review.md": "6" * 64,
        },
        "platform": {
            "system": smoke.platform.system(),
            "release": smoke.platform.release(),
            "machine": smoke.platform.machine(),
        },
        "application": {
            "bundle_sha256": "8" * 64,
            "bundle_file_count": 12,
            "bundle_bytes": 4096,
            "bundle_budget_bytes": smoke.PACKAGE_SIZE_BUDGET_BYTES,
            "executable_sha256": "9" * 64,
            "supply_manifest_sha256": "a" * 64,
            "migration_prefix_sha256": "b" * 64,
        },
        "suites": [
            {
                "name": name,
                "status": "pass",
                "budget_ns": specification.budget_seconds * 1_000_000_000,
                "duration_ns": 1,
                "commands": [
                    command_record(command)
                    for command in specification.commands
                ],
            }
            for name, specification in zip(
                smoke.EXPECTED_SUITE_NAMES,
                suite_specs,
                strict=True,
            )
        ],
        "packaged_workflow": {
            "report_sha256": "c" * 64,
            "bundle_sha256": "8" * 64,
            "executable_sha256": "d" * 64,
            "collage_sha256": "e" * 64,
            "network_denied_for_process_tree": True,
            "accessibility_automation_used": True,
            "browser_mock_used": False,
        },
        "supply_chain": {
            "report_sha256": "f" * 64,
            "bundle_sha256": "8" * 64,
            "manifest_sha256": "0" * 64,
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


def outcome(
    output: bytes = b"required marker\n",
    *,
    returncode: int = 0,
    timed_out: bool = False,
    output_limit_exceeded: bool = False,
    launch_failed: bool = False,
) -> smoke.CommandOutcome:
    return smoke.CommandOutcome(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ns=123,
        captured_output=output,
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        launch_failed=launch_failed,
    )


class P09AcceptanceSmokeTests(unittest.TestCase):
    def command(self, *markers: str) -> smoke.CommandSpec:
        return smoke.CommandSpec(
            logical=("python3", "tools/focused-check.py"),
            actual=(str(Path(sys.executable).resolve()), "unused"),
            required_markers=markers,
        )

    def validate_payload(self, payload: dict[str, object]) -> None:
        self.validate_payload_bytes(smoke.canonical_json(payload))

    def validate_payload_bytes(self, data: bytes) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "fixture.bundle"
            payload_path = bundle / smoke.PAYLOAD_RELATIVE
            payload_path.parent.mkdir(parents=True)
            payload_path.write_bytes(data)
            with (
                mock.patch.object(smoke, "_verify_codesign"),
                mock.patch.object(
                    smoke,
                    "_bounded_bundle_tree",
                    return_value=("1" * 64, 1, payload_path.stat().st_size),
                ),
            ):
                smoke.validate_bundle(bundle)

    def test_canonical_json_is_stable_ascii_and_rejects_nan(self) -> None:
        value = {"z": 3, "a": "\N{SNOWMAN}", "nested": {"b": 2, "a": 1}}

        self.assertEqual(
            b'{"a":"\\u2603","nested":{"a":1,"b":2},"z":3}\n',
            smoke.canonical_json(value),
        )
        self.assertEqual(smoke.canonical_json(value), smoke.canonical_json(value))
        with self.assertRaises(ValueError):
            smoke.canonical_json({"value": float("nan")})
        noncanonical = smoke.canonical_json(acceptance_payload()).replace(
            b'":',
            b'": ',
        )
        with self.assertRaisesRegex(
            smoke.AcceptanceFailure,
            "not canonical JSON",
        ):
            self.validate_payload_bytes(noncanonical)

    def test_logical_commands_reject_absolute_and_embedded_private_paths(
        self,
    ) -> None:
        private_argument = f"--output={Path.home()}/private/report.json"
        for command in (
            ("python3", "/tmp/focused-check.py"),
            ("python3", private_argument),
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    smoke.AcceptanceFailure,
                    "private path",
                ):
                    smoke._validate_logical_command(command)

    def test_run_suite_records_marker_verified_injected_runner(self) -> None:
        specification = smoke.SuiteSpec(
            "focused",
            2,
            (self.command("required marker"),),
        )
        calls: list[float] = []

        def runner(
            command: smoke.CommandSpec,
            root: Path,
            environment: dict[str, str],
            timeout_seconds: float,
        ) -> smoke.CommandOutcome:
            self.assertEqual(specification.commands[0], command)
            self.assertEqual(Path.cwd(), root)
            self.assertEqual({"CARGO_NET_OFFLINE": "true"}, environment)
            self.assertGreater(timeout_seconds, 0)
            self.assertLessEqual(timeout_seconds, 2)
            calls.append(timeout_seconds)
            return outcome()

        record = smoke.run_suite(
            specification,
            Path.cwd(),
            {"CARGO_NET_OFFLINE": "true"},
            runner,
        )

        self.assertEqual(1, len(calls))
        self.assertEqual("pass", record["status"])
        self.assertEqual(2_000_000_000, record["budget_ns"])
        self.assertEqual(
            ["python3", "tools/focused-check.py"],
            record["commands"][0]["command"],
        )

    def test_cargo_proxy_executes_as_cargo_not_rustup(self) -> None:
        root = Path(__file__).resolve().parents[1]
        command = smoke._cargo_command(
            root,
            ("--version",),
            "cargo",
        )

        self.assertEqual("cargo", Path(command.actual[0]).name)
        result = smoke.run_command(
            command,
            root,
            smoke.clean_environment(),
            10,
        )

        self.assertEqual(0, result.returncode)
        self.assertIn(b"cargo", result.captured_output)
        self.assertFalse(result.cleanup_failed)

    def test_run_suite_rejects_missing_markers_and_runner_failures(self) -> None:
        specification = smoke.SuiteSpec(
            "focused",
            2,
            (self.command("required marker"),),
        )
        failures = (
            outcome(b"wrong marker\n"),
            outcome(returncode=1),
            outcome(timed_out=True),
            outcome(output_limit_exceeded=True),
            outcome(launch_failed=True),
        )
        for result in failures:
            with self.subTest(result=result):
                runner = mock.Mock(return_value=result)
                with self.assertRaisesRegex(
                    smoke.AcceptanceFailure,
                    "focused: command failed",
                ):
                    smoke.run_suite(
                        specification,
                        Path.cwd(),
                        {},
                        runner,
                    )
                runner.assert_called_once()

    def test_run_suite_enforces_budget_before_and_after_runner(self) -> None:
        specification = smoke.SuiteSpec(
            "focused",
            1,
            (self.command(),),
        )
        runner = mock.Mock(return_value=outcome())
        with mock.patch.object(
            smoke.time,
            "monotonic_ns",
            side_effect=(0, 1_000_000_001),
        ):
            with self.assertRaisesRegex(
                smoke.AcceptanceFailure,
                "performance budget exceeded",
            ):
                smoke.run_suite(specification, Path.cwd(), {}, runner)
        runner.assert_not_called()

        with mock.patch.object(
            smoke.time,
            "monotonic_ns",
            side_effect=(0, 0, 1_000_000_001),
        ):
            with self.assertRaisesRegex(
                smoke.AcceptanceFailure,
                "performance budget exceeded",
            ):
                smoke.run_suite(specification, Path.cwd(), {}, runner)
        runner.assert_called_once()

    def test_limitations_are_truthful_exact_and_strictly_validated(self) -> None:
        expected = [
            {
                "id": identifier,
                "feature_enabled": False,
                "acceptance_claim": "deferred_not_passed",
                "deferred_limitation": limitation,
            }
            for identifier, limitation in smoke.LIMITATIONS
        ]
        self.assertEqual(expected, smoke._limitations())
        self.validate_payload(acceptance_payload())

        mutations = []
        wrong_id = acceptance_payload()
        wrong_id["limitations"][0]["id"] = "unknown_limitation"
        mutations.append(wrong_id)
        reordered = acceptance_payload()
        reordered["limitations"].reverse()
        mutations.append(reordered)
        falsely_enabled = acceptance_payload()
        falsely_enabled["limitations"][0]["feature_enabled"] = True
        mutations.append(falsely_enabled)
        false_pass = acceptance_payload()
        false_pass["limitations"][0]["acceptance_claim"] = "pass"
        mutations.append(false_pass)

        for payload in mutations:
            with self.subTest(limitations=payload["limitations"]):
                with self.assertRaisesRegex(
                    smoke.AcceptanceFailure,
                    "limitations",
                ):
                    self.validate_payload(payload)

    def test_requirement_decisions_are_closed_and_strictly_validated(self) -> None:
        expected = [
            {
                "requirement_id": requirement_id,
                "status": "pass",
                "test": (
                    "p09_acceptance::"
                    "locally_signed_personal_mvp_release_bundle"
                ),
            }
            for requirement_id in smoke.REQUIREMENT_IDS
        ]
        self.assertEqual(expected, smoke._requirements())
        self.validate_payload(acceptance_payload())

        mutations = []
        failed = acceptance_payload()
        failed["requirements"][0]["status"] = "fail"
        mutations.append(failed)
        duplicate = acceptance_payload()
        duplicate["requirements"][1] = copy.deepcopy(
            duplicate["requirements"][0]
        )
        mutations.append(duplicate)

        for payload in mutations:
            with self.subTest(requirements=payload["requirements"]):
                with self.assertRaisesRegex(
                    smoke.AcceptanceFailure,
                    "requirement decisions",
                ):
                    self.validate_payload(payload)

    def test_payload_rejects_unknown_fields_false_metadata_and_private_paths(
        self,
    ) -> None:
        mutations: list[dict[str, object]] = []
        extra_top_level = acceptance_payload()
        extra_top_level["raw_output"] = "not allowed"
        mutations.append(extra_top_level)

        extra_requirement = acceptance_payload()
        extra_requirement["requirements"][0]["source_path"] = "forged"
        mutations.append(extra_requirement)

        false_test = acceptance_payload()
        false_test["requirements"][0]["test"] = "forged::pass"
        mutations.append(false_test)

        false_limitation = acceptance_payload()
        false_limitation["limitations"][0][
            "deferred_limitation"
        ] = "Actually externally certified."
        mutations.append(false_limitation)

        private_path = acceptance_payload()
        private_path["platform"]["release"] = str(
            Path.home() / "private" / "report.json"
        )
        mutations.append(private_path)

        file_uri = acceptance_payload()
        file_uri["platform"]["release"] = (
            "file:///Users/alice/private/report.json"
        )
        mutations.append(file_uri)

        fake_command = acceptance_payload()
        fake_command["suites"][0]["commands"][0]["command"] = [
            "python3",
            "tools/fake-pass.py",
        ]
        mutations.append(fake_command)

        enlarged_budget = acceptance_payload()
        enlarged_budget["suites"][0]["budget_ns"] = 10**18
        mutations.append(enlarged_budget)

        opaque_token = acceptance_payload()
        opaque_token["suites"][0]["commands"][0]["command"][-1] = (
            "--token=correct-horse-battery-staple"
        )
        mutations.append(opaque_token)

        for payload in mutations:
            with self.subTest(payload=payload):
                with self.assertRaises(smoke.AcceptanceFailure):
                    self.validate_payload(payload)

    def test_real_timeout_kills_descendant_holding_stdout(self) -> None:
        child_code = "import time; time.sleep(60)"
        parent_code = (
            "import subprocess,sys,time;"
            "child=subprocess.Popen([sys.executable,'-c',"
            f"{child_code!r}]);"
            "print(child.pid,flush=True);time.sleep(60)"
        )
        command = smoke.CommandSpec(
            logical=("python3", "tools/timeout-fixture.py"),
            actual=(str(Path(sys.executable).resolve()), "-c", parent_code),
            required_markers=(),
        )

        started = time.monotonic()
        result = smoke.run_command(command, Path.cwd(), os.environ.copy(), 0.2)
        elapsed = time.monotonic() - started
        child_pid = int(result.captured_output.decode("ascii").strip())

        self.assertTrue(result.timed_out)
        self.assertFalse(result.cleanup_failed)
        self.assertLess(elapsed, 5)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail("timed-out descendant process is still running")

    def test_existing_destination_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            destination = evidence / smoke.BUNDLE_NAME
            destination.mkdir()
            sentinel = destination / "sentinel"
            sentinel.write_bytes(b"existing evidence")

            with self.assertRaisesRegex(
                smoke.AcceptanceFailure,
                "already exists",
            ):
                smoke._publish_bundle(evidence, acceptance_payload())

            self.assertEqual(b"existing evidence", sentinel.read_bytes())
            self.assertEqual([destination], list(evidence.iterdir()))


@unittest.skipUnless(
    sys.platform == "darwin"
    and smoke.CODESIGN.is_file()
    and os.access(smoke.CODESIGN, os.X_OK),
    "requires macOS /usr/bin/codesign",
)
class P09AcceptanceMacOSBundleTests(unittest.TestCase):
    def publish(self, evidence: Path) -> smoke.BundleValidation:
        return smoke._publish_bundle(evidence, acceptance_payload())

    def test_real_adhoc_publication_passes_strict_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            published = self.publish(evidence)
            bundle = evidence / smoke.BUNDLE_NAME
            validated = smoke.validate_bundle(bundle)

            self.assertEqual(smoke.RUN_ID, validated.payload["run_id"])
            self.assertEqual(published, validated)
            self.assertEqual(smoke.EXPECTED_BUNDLE_FILES, {
                str(path.relative_to(bundle))
                for path in bundle.rglob("*")
                if path.is_file()
            })

    def test_payload_and_signature_mutations_are_rejected(self) -> None:
        for relative in (smoke.PAYLOAD_RELATIVE, smoke.SIGNATURE_RELATIVE):
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as directory:
                    evidence = Path(directory)
                    self.publish(evidence)
                    bundle = evidence / smoke.BUNDLE_NAME
                    target = bundle / relative
                    original = target.read_bytes()
                    target.write_bytes(bytes((original[0] ^ 1,)) + original[1:])

                    with self.assertRaises(smoke.AcceptanceFailure):
                        smoke.validate_bundle(bundle)


if __name__ == "__main__":
    unittest.main()
