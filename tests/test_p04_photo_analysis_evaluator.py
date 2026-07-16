from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p04_photo_analysis
from tools.evaluators import run as evaluator_run


ROOT = Path(__file__).resolve().parents[1]


def copy(relative: str, root: Path) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, destination)


def write_valid_fixture(root: Path) -> None:
    for relative in p04_photo_analysis.EXPECTED_PACKET_HASHES:
        copy(relative, root)
    copy(p04_photo_analysis.STATE_FILE, root)
    for relative in p04_photo_analysis.SOURCE_FILES:
        copy(relative, root)


def command_result(
    returncode: int = 0,
    output: bytes = b"running 1 test\n",
) -> p04_photo_analysis.CommandResult:
    return p04_photo_analysis.CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


def packet_validation() -> p04_photo_analysis.PacketValidation:
    return p04_photo_analysis.PacketValidation(
        errors=(),
        packet_sha256="a" * 64,
        hashes={"packet": "b" * 64},
    )


def source_validation() -> p04_photo_analysis.SourceValidation:
    return p04_photo_analysis.SourceValidation(
        errors=(),
        source_sha256="c" * 64,
        migration_sha256="d" * 64,
        registered_commands=p04_photo_analysis.PHOTO_COMMANDS,
        acl_permissions=tuple(
            "allow-" + command.replace("_", "-")
            for command in p04_photo_analysis.PHOTO_COMMANDS
        ),
        production_provider_wired=True,
        automatic_masks_disabled=True,
        production_network_free=True,
        production_transport_isolated=True,
        playwright_specs=("apps/desktop-ui/e2e/photo-analysis.spec.ts",),
    )


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class PacketValidationTests(unittest.TestCase):
    def test_current_packet_is_frozen_and_approved(self) -> None:
        result = p04_photo_analysis.validate_packet(ROOT)

        self.assertEqual((), result.errors)
        self.assertEqual(64, len(result.packet_sha256))

    def test_changed_proposal_fails_packet_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in p04_photo_analysis.EXPECTED_PACKET_HASHES:
                copy(relative, root)
            copy(p04_photo_analysis.STATE_FILE, root)
            proposal = (
                root
                / p04_photo_analysis.PACKET_DIR
                / "proposal.md"
            )
            proposal.write_text(
                proposal.read_text(encoding="utf-8") + "\nchanged\n",
                encoding="utf-8",
            )

            result = p04_photo_analysis.validate_packet(root)

        self.assertTrue(result.errors)


class SourceValidationTests(unittest.TestCase):
    def test_current_source_contract_is_complete(self) -> None:
        result = p04_photo_analysis.validate_source_contract(ROOT)

        self.assertEqual((), result.errors)
        self.assertEqual(
            set(p04_photo_analysis.PHOTO_COMMANDS),
            set(result.registered_commands),
        )
        self.assertTrue(result.production_provider_wired)
        self.assertTrue(result.automatic_masks_disabled)
        self.assertTrue(result.production_network_free)
        self.assertTrue(result.production_transport_isolated)
        self.assertEqual(64, len(result.migration_sha256))

    def test_missing_dispatcher_source_acl_and_provider_wiring_fail_closed(
        self,
    ) -> None:
        mutations = (
            (
                "dispatcher",
                "src-tauri/src/lib.rs",
                "            create_photo_scope_v1,\n",
                "            create_photo_scope_missing_v1,\n",
                False,
            ),
            (
                "source",
                "crates/wardrobe-platform/src/photo_repository.rs",
                "",
                "",
                True,
            ),
            (
                "acl",
                "src-tauri/capabilities/main.json",
                "allow-analyze-photo-scope-v1",
                "allow-analyze-photo-scope-missing-v1",
                False,
            ),
            (
                "provider",
                "src-tauri/src/lib.rs",
                (
                    ".with_garment_segmentation_provider("
                    "UnavailableGarmentSegmentationProviderV1)"
                ),
                "",
                False,
            ),
        )
        for name, relative, before, after, remove in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_valid_fixture(root)
                path = root / relative
                if remove:
                    path.unlink()
                else:
                    text = path.read_text(encoding="utf-8")
                    self.assertIn(before, text)
                    path.write_text(
                        text.replace(before, after, 1),
                        encoding="utf-8",
                    )

                result = p04_photo_analysis.validate_source_contract(root)

                self.assertTrue(result.errors)

    def test_automatic_mask_approval_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            photo = root / "crates/wardrobe-core/src/photo_analysis.rs"
            text = photo.read_text(encoding="utf-8")
            self.assertIn("!self.quality_approved", text)
            photo.write_text(
                text.replace(
                    "!self.quality_approved",
                    "self.quality_approved",
                    1,
                ),
                encoding="utf-8",
            )

            result = p04_photo_analysis.validate_source_contract(root)

        self.assertFalse(result.automatic_masks_disabled)
        self.assertTrue(
            any("automatic-mask approval" in error for error in result.errors)
        )

    def test_local_dialog_dependency_is_allowed_but_unknown_ui_dependency_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)

            accepted = p04_photo_analysis.validate_source_contract(root)
            self.assertTrue(accepted.production_network_free)

            manifest = root / "apps/desktop-ui/package.json"
            value = json.loads(manifest.read_text(encoding="utf-8"))
            dependencies = value["dependencies"]
            self.assertIn("@tauri-apps/plugin-dialog", dependencies)
            dependencies["unreviewed-ui-client"] = "1.0.0"
            manifest.write_text(
                json.dumps(value, indent=2) + "\n",
                encoding="utf-8",
            )

            rejected = p04_photo_analysis.validate_source_contract(root)

        self.assertFalse(rejected.production_network_free)
        self.assertTrue(
            any(
                "model, network, or credential dependency" in error
                for error in rejected.errors
            )
        )


class EvaluatorTests(unittest.TestCase):
    def test_stale_pass_evidence_is_removed_before_failed_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            for requirement in p04_photo_analysis.REQUIREMENT_IDS:
                (evidence / f"{requirement}.json").write_text(
                    '{"status":"stale"}',
                    encoding="utf-8",
                )
            with (
                mock.patch.object(
                    p04_photo_analysis,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p04_photo_analysis,
                    "validate_source_contract",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p04_photo_analysis,
                    "run_bounded_command",
                    return_value=command_result(1),
                ),
            ):
                result = p04_photo_analysis.evaluate(
                    ROOT,
                    evidence,
                    set(p04_photo_analysis.REQUIREMENT_IDS),
                )

            diagnostics = read_json(
                evidence / p04_photo_analysis.DIAGNOSTICS_NAME
            )
            self.assertEqual(1, result)
            self.assertEqual("fail", diagnostics["status"])
            self.assertFalse(diagnostics["pass_evidence_written"])
            self.assertFalse(
                any(
                    (evidence / f"{requirement}.json").exists()
                    for requirement in p04_photo_analysis.REQUIREMENT_IDS
                )
            )

    def test_success_writes_four_hashed_bounded_evidence_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p04_photo_analysis,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p04_photo_analysis,
                    "validate_source_contract",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p04_photo_analysis,
                    "run_bounded_command",
                    return_value=command_result(),
                ) as run,
            ):
                result = p04_photo_analysis.evaluate(
                    ROOT,
                    evidence,
                    set(p04_photo_analysis.REQUIREMENT_IDS),
                )

            self.assertEqual(0, result)
            self.assertEqual(len(p04_photo_analysis.COMMAND_CHECKS), run.call_count)
            for requirement in p04_photo_analysis.REQUIREMENT_IDS:
                path = evidence / f"{requirement}.json"
                payload = read_json(path)
                self.assertLessEqual(
                    path.stat().st_size,
                    p04_photo_analysis.MAX_ARTIFACT_BYTES,
                )
                self.assertEqual("pass", payload["status"])
                self.assertEqual(requirement, payload["requirement_id"])
                details = payload["details"]
                self.assertRegex(
                    details["verification_sha256"],  # type: ignore[index]
                    r"^[0-9a-f]{64}$",
                )
            diagnostics = read_json(
                evidence / p04_photo_analysis.DIAGNOSTICS_NAME
            )
            self.assertEqual("pass", diagnostics["status"])
            self.assertTrue(diagnostics["pass_evidence_written"])
            self.assertNotIn(str(ROOT), json.dumps(diagnostics))

    def test_unselected_requirements_do_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                p04_photo_analysis, "run_bounded_command"
            ) as run:
                result = p04_photo_analysis.evaluate(
                    ROOT, Path(directory), set()
                )
        self.assertEqual(0, result)
        run.assert_not_called()

    def test_zero_repository_or_desktop_tests_cannot_pass(self) -> None:
        check = next(
            check
            for check in p04_photo_analysis.COMMAND_CHECKS
            if check.name == "platform_photo_repository"
        )

        error = p04_photo_analysis._command_error(
            check,
            command_result(output=b"running 0 tests\n"),
        )

        self.assertIn("matched no Rust tests", error or "")


class DispatcherTests(unittest.TestCase):
    def test_dispatcher_routes_exact_p04_requirement_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence_dir = root / "evidence"
            run_dir.mkdir()
            selected = sorted(p04_photo_analysis.REQUIREMENT_IDS)
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": selected}),
                encoding="utf-8",
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "HARNESS_RUN_DIR": str(run_dir),
                        "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                    },
                    clear=False,
                ),
                mock.patch.object(
                    evaluator_run.p04_photo_analysis,
                    "evaluate",
                    return_value=0,
                ) as evaluate,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(ROOT, evidence_dir, set(selected))


if __name__ == "__main__":
    unittest.main()
