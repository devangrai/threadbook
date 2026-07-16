from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools import harness
from tools.evaluators import p04_people


ROOT = Path(__file__).resolve().parents[1]


def copy(relative: str, root: Path) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, destination)


def write_valid_fixture(root: Path) -> None:
    for relative in p04_people.EXPECTED_PACKET_HASHES:
        copy(relative, root)
    copy(p04_people.STATE_FILE, root)
    for relative in p04_people.SOURCE_FILES:
        copy(relative, root)


def command_result(
    returncode: int = 0,
    output: bytes = b"running 1 test\n",
) -> p04_people.CommandResult:
    return p04_people.CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


def packet_validation() -> p04_people.PacketValidation:
    return p04_people.PacketValidation(
        errors=(),
        packet_sha256="a" * 64,
        hashes={"packet": "b" * 64},
    )


def source_validation() -> p04_people.SourceValidation:
    return p04_people.SourceValidation(
        errors=(),
        source_sha256="c" * 64,
        migration_sha256="d" * 64,
        registered_commands=p04_people.PEOPLE_COMMANDS,
        acl_permissions=tuple(
            "allow-" + command.replace("_", "-")
            for command in p04_people.PEOPLE_COMMANDS
        ),
        native_abi_valid=True,
        vision_framework_linked=True,
        ui_flow_complete=True,
        segmentation_disabled=True,
        model_pack_files=(),
        approval_files=(),
    )


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class PacketValidationTests(unittest.TestCase):
    def test_current_packet_is_frozen_and_approved(self) -> None:
        result = p04_people.validate_packet(ROOT)

        self.assertEqual((), result.errors)
        self.assertEqual(64, len(result.packet_sha256))

    def test_tampered_proposal_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in p04_people.EXPECTED_PACKET_HASHES:
                copy(relative, root)
            copy(p04_people.STATE_FILE, root)
            proposal = root / p04_people.PACKET_DIR / "proposal.md"
            proposal.write_text(
                proposal.read_text(encoding="utf-8") + "\ntampered\n",
                encoding="utf-8",
            )

            result = p04_people.validate_packet(root)

        self.assertTrue(
            any("frozen packet hash changed" in error for error in result.errors)
        )


class SourceValidationTests(unittest.TestCase):
    def test_current_people_owner_source_contract_is_complete(self) -> None:
        result = p04_people.validate_source_contract(ROOT)

        self.assertEqual((), result.errors)
        self.assertEqual(set(p04_people.PEOPLE_COMMANDS), set(result.registered_commands))
        self.assertTrue(result.native_abi_valid)
        self.assertTrue(result.vision_framework_linked)
        self.assertTrue(result.ui_flow_complete)
        self.assertTrue(result.segmentation_disabled)
        self.assertEqual((), result.model_pack_files)
        self.assertEqual(64, len(result.migration_sha256))

    def test_migration_native_and_command_tampering_fail_closed(self) -> None:
        mutations = (
            (
                "migration",
                p04_people.MIGRATION_FILE,
                "CREATE TABLE photo_owner_heads",
                "CREATE TABLE removed_owner_heads",
            ),
            (
                "native_abi",
                "native/photokit/Sources/WardrobePhotoKitObjC/include/wardrobe_photokit.h",
                "WK_PERSON_DETECTION_REQUEST_V1_SIZE",
                "WK_PERSON_DETECTION_REQUEST_REMOVED_SIZE",
            ),
            (
                "tauri_command",
                "src-tauri/build.rs",
                '"correct_photo_owner_v1"',
                '"correct_photo_owner_missing_v1"',
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

                result = p04_people.validate_source_contract(root)

                self.assertTrue(result.errors)

    def test_distributed_segmentation_model_cannot_be_deferred_as_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            model = root / "assets/models/garment-segmentation.onnx"
            model.parent.mkdir(parents=True)
            model.write_bytes(b"model")

            result = p04_people.validate_source_contract(root)

        self.assertFalse(result.segmentation_disabled)
        self.assertIn(
            "assets/models/garment-segmentation.onnx",
            result.model_pack_files,
        )


class EvaluatorTests(unittest.TestCase):
    def test_failed_check_removes_all_stale_acceptance_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            for requirement in p04_people.REQUIREMENT_IDS:
                (evidence / f"{requirement}.json").write_text(
                    '{"status":"stale"}',
                    encoding="utf-8",
                )
            with (
                mock.patch.object(
                    p04_people,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p04_people,
                    "validate_source_contract",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p04_people,
                    "run_bounded_command",
                    return_value=command_result(1),
                ),
            ):
                result = p04_people.evaluate(
                    ROOT,
                    evidence,
                    set(p04_people.REQUIREMENT_IDS),
                )

            diagnostic = read_json(evidence / p04_people.DIAGNOSTICS_NAME)
            self.assertEqual(1, result)
            self.assertEqual("fail", diagnostic["status"])
            self.assertFalse(diagnostic["evidence_written"])
            self.assertFalse(
                any(
                    (evidence / f"{requirement}.json").exists()
                    for requirement in p04_people.REQUIREMENT_IDS
                )
            )

    def test_success_writes_real_pass_and_exact_deferred_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p04_people,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p04_people,
                    "validate_source_contract",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p04_people,
                    "run_bounded_command",
                    return_value=command_result(),
                ) as run,
            ):
                result = p04_people.evaluate(
                    ROOT,
                    evidence,
                    set(p04_people.REQUIREMENT_IDS),
                )

            self.assertEqual(0, result)
            self.assertEqual(len(p04_people.COMMAND_CHECKS), run.call_count)
            for requirement in p04_people.REQUIREMENT_IDS:
                path = evidence / f"{requirement}.json"
                payload = read_json(path)
                self.assertLessEqual(path.stat().st_size, p04_people.MAX_ARTIFACT_BYTES)
                self.assertEqual(requirement, payload["requirement_id"])
                summary = payload["details"]["public_summary"]  # type: ignore[index]
                if requirement in p04_people.DEFERRED_REQUIREMENT_IDS:
                    self.assertEqual("deferred", payload["status"])
                    self.assertEqual(
                        {
                            "feature_enabled",
                            "acceptance_claim",
                            "deferred_limitation",
                        },
                        set(summary),  # type: ignore[arg-type]
                    )
                    self.assertIs(False, summary["feature_enabled"])  # type: ignore[index]
                    self.assertEqual(
                        "deferred_not_passed",
                        summary["acceptance_claim"],  # type: ignore[index]
                    )
                    self.assertTrue(summary["deferred_limitation"])  # type: ignore[index]
                else:
                    self.assertEqual("pass", payload["status"])
                    self.assertEqual(
                        "local_requirement_passed",
                        summary["acceptance_claim"],  # type: ignore[index]
                    )
            diagnostic = read_json(evidence / p04_people.DIAGNOSTICS_NAME)
            self.assertEqual("pass", diagnostic["status"])
            self.assertTrue(diagnostic["evidence_written"])
            self.assertNotIn(str(ROOT), json.dumps(diagnostic))

    def test_partial_atomic_publication_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            original = p04_people._write_bounded_json
            calls = 0

            def fail_second(path: Path, value: dict[str, object]) -> None:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("injected")
                original(path, value)

            with (
                mock.patch.object(
                    p04_people,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p04_people,
                    "validate_source_contract",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p04_people,
                    "run_bounded_command",
                    return_value=command_result(),
                ),
                mock.patch.object(
                    p04_people,
                    "_write_bounded_json",
                    side_effect=fail_second,
                ),
                self.assertRaises(OSError),
            ):
                p04_people.evaluate(
                    ROOT,
                    evidence,
                    set(p04_people.REQUIREMENT_IDS),
                )

            self.assertEqual([], list(evidence.iterdir()))

    def test_zero_rust_tests_cannot_pass(self) -> None:
        check = next(
            check for check in p04_people.COMMAND_CHECKS if check.require_rust_test
        )

        error = p04_people._command_error(
            check,
            command_result(output=b"running 0 tests\n"),
        )

        self.assertIn("matched no Rust tests", error or "")

    def test_unselected_requirements_do_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(p04_people, "run_bounded_command") as run:
                result = p04_people.evaluate(ROOT, Path(directory), set())

        self.assertEqual(0, result)
        run.assert_not_called()


class RoutingTests(unittest.TestCase):
    def test_harness_routes_pass_and_deferred_requirements_once(self) -> None:
        expected = (Path("tools/evaluators/p04_people.py"),)

        self.assertEqual(
            expected,
            harness.evaluator_sidecars(list(p04_people.EXPECTED_SELECTION)),
        )
        self.assertEqual(
            expected,
            harness.evaluator_sidecars(["P04-QLT-001", "P04-PERF-001"]),
        )

    def test_main_rejects_missing_harness_routing_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"HARNESS_RUN_DIR": "", "HARNESS_EVIDENCE_DIR": ""},
            clear=False,
        ):
            result = p04_people.main()

        self.assertEqual(2, result)


if __name__ == "__main__":
    unittest.main()
