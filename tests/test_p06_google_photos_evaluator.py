from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p06_google_photos
from tools.evaluators import run as evaluator_run
from tools.evaluators.p06_photokit import AppIdentity


ROOT = Path(__file__).resolve().parents[1]


def source_validation(
    errors: tuple[str, ...] = (),
) -> p06_google_photos.SourceValidation:
    return p06_google_photos.SourceValidation(errors, "b" * 64, 20)


def app_identity() -> AppIdentity:
    return AppIdentity(
        bundle_id="com.devrai.wardrobe",
        info_plist_sha256="1" * 64,
        executable_sha256="2" * 64,
        bundle_sha256="3" * 64,
        designated_requirement_sha256="4" * 64,
    )


def decoded_registries() -> dict[str, str]:
    return {
        relative: (ROOT / relative).read_text(encoding="utf-8")
        for relative in p06_google_photos.REQUIRED_SOURCE_FILES
        if (ROOT / relative).suffix in {".rs", ".ts", ".tsx", ".json"}
        or relative == "Makefile"
    }


class P06GooglePhotosEvaluatorTests(unittest.TestCase):
    def test_current_packet_source_and_exact_package_are_valid(self) -> None:
        packet = p06_google_photos.validate_packet(ROOT)
        source = p06_google_photos.validate_source(ROOT)
        identity, package, errors = p06_google_photos.inspect_package(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual((), source.errors)
        self.assertIsNotNone(identity)
        self.assertEqual([], errors)
        self.assertEqual(
            len(p06_google_photos.EXPECTED_COMMANDS),
            package["packaged_command_count"],
        )

    def test_structural_registries_reject_renamed_activation_surfaces(self) -> None:
        decoded = decoded_registries()
        self.assertEqual([], p06_google_photos._structural_errors(decoded))

        cases = (
            (
                "src-tauri/src/local_only.rs",
                "    OpenAiTryOn,\n",
                "    OpenAiTryOn,\n    HiddenPicker,\n",
                "outbound capability",
            ),
            (
                "src-tauri/src/lib.rs",
                "            export_diagnostics_v1\n",
                "            hidden_picker_v1,\n            export_diagnostics_v1\n",
                "production command",
            ),
            (
                "apps/desktop-ui/src/App.tsx",
                '  { id: "settings", label: "Settings" },\n',
                '  { id: "hidden", label: "Cloud" },\n'
                '  { id: "settings", label: "Settings" },\n',
                "navigation",
            ),
            (
                "apps/desktop-ui/src/OutfitsWorkspace.tsx",
                "import.meta.env.VITE_WARDROBE_TRY_ON_RELEASE",
                "import.meta.env.VITE_WARDROBE_HIDDEN_RELEASE",
                "release-variable",
            ),
        )
        for relative, old, new, expected in cases:
            with self.subTest(relative=relative):
                changed = dict(decoded)
                self.assertIn(old, changed[relative])
                changed[relative] = changed[relative].replace(old, new, 1)
                self.assertTrue(
                    any(
                        expected in error
                        for error in p06_google_photos._structural_errors(changed)
                    )
                )

    def test_source_scan_rejects_known_picker_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in p06_google_photos._source_paths(ROOT):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((ROOT / relative).read_bytes())
            target = root / "apps/desktop-ui/src/App.tsx"
            target.write_text(
                target.read_text(encoding="utf-8")
                + '\nconst hidden = "photoslibrary.googleapis.com";\n',
                encoding="utf-8",
            )

            source = p06_google_photos.validate_source(root)

        self.assertTrue(
            any("Google Photos production marker" in error for error in source.errors)
        )

    def test_package_scan_rejects_marker_and_nonregular_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "target/release/bundle/macos/Wardrobe.app"
            executable = app / "Contents/MacOS/wardrobe-desktop"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(
                b"\0".join(
                    command.encode()
                    for command in p06_google_photos.EXPECTED_COMMANDS
                )
                + b"\0google_photos"
            )
            with mock.patch.object(
                p06_google_photos,
                "_evaluated_app_identity",
                return_value=(app_identity(), {}, []),
            ):
                _, _, errors = p06_google_photos.inspect_package(root)
            self.assertTrue(any("content marker" in error for error in errors))

            executable.write_bytes(
                b"\0".join(
                    command.encode()
                    for command in p06_google_photos.EXPECTED_COMMANDS
                )
            )
            link = app / "Contents/Resources/link"
            link.parent.mkdir(parents=True)
            link.symlink_to(executable)
            with mock.patch.object(
                p06_google_photos,
                "_evaluated_app_identity",
                return_value=(app_identity(), {}, []),
            ):
                _, _, errors = p06_google_photos.inspect_package(root)
            self.assertTrue(any("unsafe non-regular" in error for error in errors))

    def test_success_writes_truthful_disabled_deferred_evidence(self) -> None:
        package = {
            "identity_checks": {},
            "app_file_count": 4,
            "app_bytes": 100,
            "packaged_command_count": len(p06_google_photos.EXPECTED_COMMANDS),
        }
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P06-GPH-001.json"
            stale.write_text('{"status":"pass"}', encoding="utf-8")
            with (
                mock.patch.object(
                    p06_google_photos,
                    "validate_packet",
                    return_value=p06_google_photos.PacketValidation((), "a" * 64),
                ),
                mock.patch.object(
                    p06_google_photos,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p06_google_photos,
                    "inspect_package",
                    return_value=(app_identity(), package, []),
                ),
            ):
                result = p06_google_photos.evaluate(
                    ROOT,
                    evidence,
                    set(p06_google_photos.REQUIREMENT_IDS),
                )

            self.assertEqual(0, result)
            payload = json.loads(stale.read_text(encoding="utf-8"))
            summary = payload["details"]["public_summary"]
            self.assertEqual("deferred", payload["status"])
            self.assertIs(False, summary["feature_enabled"])
            self.assertIs(False, summary["google_photos_picker_enabled"])
            self.assertEqual("deferred_not_passed", summary["acceptance_claim"])
            self.assertTrue(summary["deferred_limitation"])

    def test_failure_writes_only_diagnostics_and_removes_stale_pass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P06-GPH-001.json"
            stale.write_text('{"status":"pass"}', encoding="utf-8")
            with (
                mock.patch.object(
                    p06_google_photos,
                    "validate_packet",
                    return_value=p06_google_photos.PacketValidation(
                        ("packet changed",),
                        "a" * 64,
                    ),
                ),
                mock.patch.object(
                    p06_google_photos,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p06_google_photos,
                    "inspect_package",
                    return_value=(app_identity(), {}, []),
                ),
            ):
                result = p06_google_photos.evaluate(
                    ROOT,
                    evidence,
                    set(p06_google_photos.REQUIREMENT_IDS),
                )

            self.assertEqual(1, result)
            self.assertFalse(stale.exists())
            self.assertEqual(
                {p06_google_photos.DIAGNOSTICS_NAME},
                {path.name for path in evidence.iterdir()},
            )

    def test_dispatcher_routes_google_photos_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence = root / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {
                        "selected_requirement_ids": sorted(
                            p06_google_photos.REQUIREMENT_IDS
                        )
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "HARNESS_RUN_DIR": str(run_dir),
                        "HARNESS_EVIDENCE_DIR": str(evidence),
                    },
                    clear=False,
                ),
                mock.patch.object(
                    evaluator_run.p06_google_photos,
                    "evaluate",
                    return_value=0,
                ) as evaluate,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT,
            evidence,
            set(p06_google_photos.REQUIREMENT_IDS),
        )


if __name__ == "__main__":
    unittest.main()
