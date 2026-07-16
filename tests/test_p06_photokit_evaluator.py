from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p06_photokit
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def packet_validation() -> p06_photokit.PacketValidation:
    return p06_photokit.PacketValidation((), "a" * 64, {"packet": "b" * 64})


def command_check(
    name: str,
    *,
    rust: bool = False,
    live: bool = False,
) -> p06_photokit.CommandCheck:
    return p06_photokit.CommandCheck(
        name,
        ("test-command", name),
        require_rust_test=rust,
        live_smoke=live,
    )


def source_validation(
    *,
    errors: tuple[str, ...] = (),
    live: bool = True,
) -> p06_photokit.SourceValidation:
    return p06_photokit.SourceValidation(
        errors,
        "c" * 64,
        {"source.rs": "d" * 64},
        24,
        "e" * 64,
        (
            command_check("core", rust=True),
            command_check("platform", rust=True),
            command_check("tauri", rust=True),
            command_check("swift"),
            command_check("ui"),
        ),
        command_check("live", live=True) if live else None,
        3,
        4,
        2,
    )


def app_identity() -> p06_photokit.AppIdentity:
    return p06_photokit.AppIdentity(
        bundle_id=p06_photokit.EXPECTED_BUNDLE_ID,
        info_plist_sha256="1" * 64,
        executable_sha256="2" * 64,
        bundle_sha256="4" * 64,
        designated_requirement_sha256="3" * 64,
    )


def live_record(nonce: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event": "exact_package_missed_change",
        "run_id": p06_photokit.RUN_ID,
        "challenge_nonce": nonce,
        "packet_sha256": "a" * 64,
        "source_sha256": "c" * 64,
        "exact_package": True,
        "same_package_relaunched": True,
        "bundle_id": p06_photokit.EXPECTED_BUNDLE_ID,
        "info_plist_sha256": "1" * 64,
        "executable_sha256": "2" * 64,
        "bundle_sha256": "4" * 64,
        "designated_requirement_sha256": "3" * 64,
        "fixture_sha256": list(p06_photokit.P00_FIXTURE_HASHES),
        "native_callbacks": True,
        "tcc_authorized": True,
        "dedicated_fixture_album": True,
        "operator_removal_completed": True,
        "initial_complete_generation": True,
        "startup_reconciled": True,
        "asset_not_in_scope_delta": 1,
        "membership_generation_delta": 1,
        "photokit_revision_delta": 1,
        "available_before": 2,
        "unavailable_after": 1,
        "blob_count_before": 2,
        "blob_count_after": 2,
        "synthetic_decision_preserved": True,
        "raw_identifiers_emitted": False,
        "personal_metadata_emitted": False,
    }


def command_result(output: bytes = b"ok", *, returncode: int = 0) -> CommandResult:
    return CommandResult(
        returncode,
        hashlib.sha256(output).hexdigest(),
        len(output),
        1,
        captured_output=output,
    )


class P06PhotoKitEvaluatorTests(unittest.TestCase):
    def test_current_frozen_packet_is_valid(self) -> None:
        packet = p06_photokit.validate_packet(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual(set(p06_photokit.EXPECTED_PACKET_HASHES), set(packet.hashes))
        self.assertEqual(64, len(packet.packet_sha256))

    def test_packet_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (*p06_photokit.EXPECTED_PACKET_HASHES, p06_photokit.STATE_FILE):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            proposal = root / p06_photokit.PACKET_DIR / "proposal.md"
            proposal.write_text(proposal.read_text() + "\nmutation\n")

            packet = p06_photokit.validate_packet(root)

        self.assertTrue(any("proposal.md" in error for error in packet.errors))

    def test_built_packet_retains_approved_review_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (*p06_photokit.EXPECTED_PACKET_HASHES, p06_photokit.STATE_FILE):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            state_path = root / p06_photokit.STATE_FILE
            state = json.loads(state_path.read_text())
            state["status"] = "BUILT"
            state_path.write_text(json.dumps(state))

            packet = p06_photokit.validate_packet(root)

        self.assertEqual((), packet.errors)

    def test_focused_tests_require_all_compiled_layers_and_coverage(self) -> None:
        coverage = """
            photokit startup missed asset_not_in_scope authorization scope icloud
            unavailable atomic fence store_authority canonical preserve decision
            deletion restore key production swift scripted
        """
        tests = (
            p06_photokit.RustTest(
                "crates/wardrobe-core/tests/photokit.rs",
                "wardrobe-core",
                "test",
                "photokit",
                "photokit_core",
                coverage,
            ),
            p06_photokit.RustTest(
                "crates/wardrobe-platform/tests/photokit.rs",
                "wardrobe-platform",
                "test",
                "photokit",
                "photokit_repository",
                coverage,
            ),
            p06_photokit.RustTest(
                "src-tauri/src/lib.rs",
                "wardrobe-desktop",
                "lib",
                "lib",
                "photokit_production",
                coverage,
            ),
        )

        checks, errors = p06_photokit._focused_checks(
            tests,
            ("native/photokit/Tests/PhotoKitTests.swift",),
            ("src/PhotoKitConnectorSettings.test.tsx",),
        )
        self.assertEqual([], errors)
        self.assertEqual(3, sum(check.require_rust_test for check in checks))
        rust_checks = [check for check in checks if check.require_rust_test]
        self.assertIn("--exact", rust_checks[0].command)
        self.assertNotIn("--exact", rust_checks[2].command)

        _, errors = p06_photokit._focused_checks(
            tests[:-1],
            ("native/photokit/Tests/PhotoKitTests.swift",),
            ("src/PhotoKitConnectorSettings.test.tsx",),
        )
        self.assertTrue(any("Tauri" in error for error in errors))

    def test_focused_discovery_uses_named_scope_and_explicit_cross_domain_tests(
        self,
    ) -> None:
        unrelated = p06_photokit.RustTest(
            "crates/wardrobe-platform/src/person_detection_native.rs",
            "wardrobe-platform",
            "lib",
            "lib",
            "unavailable_descriptor_and_fallback_are_conforming",
            "an unrelated bridge test mentions photokit in its body",
        )
        cross_domain = p06_photokit.RustTest(
            "crates/wardrobe-platform/src/catalog_repository.rs",
            "wardrobe-platform",
            "lib",
            "lib",
            "deletion_schema_classification_covers_every_phase_table_and_blob_fk",
            "cross-domain closure",
        )
        named = p06_photokit.RustTest(
            "crates/wardrobe-platform/tests/photokit_connector_repository.rs",
            "wardrobe-platform",
            "test",
            "photokit_connector_repository",
            "startup_reconciles",
            "focused body",
        )

        self.assertFalse(p06_photokit._is_photokit_test(unrelated))
        self.assertTrue(p06_photokit._is_photokit_test(cross_domain))
        self.assertTrue(p06_photokit._is_photokit_test(named))

    def test_feature_gated_native_platform_test_enables_photokit_feature(self) -> None:
        native_test = p06_photokit.RustTest(
            "crates/wardrobe-platform/src/photokit_native.rs",
            "wardrobe-platform",
            "lib",
            "lib",
            "binary_decoder_requires_exact_identity_and_chunk_sequence",
            "photokit",
        )
        real_adapter_test = p06_photokit.RustTest(
            "crates/wardrobe-platform/tests/photokit_native_adapter.rs",
            "wardrobe-platform",
            "test",
            "photokit_native_adapter",
            "production_adapter_uses_real_abi_and_transfers_descriptor_ownership",
            "photokit",
        )
        fallback_adapter_test = p06_photokit.RustTest(
            "crates/wardrobe-platform/tests/photokit_native_adapter.rs",
            "wardrobe-platform",
            "test",
            "photokit_native_adapter",
            "production_adapter_requires_native_feature_or_macos",
            "photokit",
        )

        native_command = p06_photokit._rust_test_check(native_test).command
        real_adapter_command = p06_photokit._rust_test_check(
            real_adapter_test
        ).command
        fallback_adapter_command = p06_photokit._rust_test_check(
            fallback_adapter_test
        ).command

        for command in (native_command, real_adapter_command):
            self.assertIn(
                ("--features", "photokit-native"),
                tuple(zip(command, command[1:])),
            )
        self.assertNotIn("--features", fallback_adapter_command)

    def test_marker_validation_keeps_production_scopes_separate(self) -> None:
        decoded = {
            "crates/wardrobe-core/src/lib.rs": "",
            "crates/wardrobe-platform/src/lib.rs": "",
            "crates/wardrobe-platform/migrations/0012_photokit_connector.sql": "",
            "native/photokit/Sources/Bridge.swift": "",
            "src-tauri/src/lib.rs": "",
            "src-tauri/build.rs": "",
            "src-tauri/capabilities/main.json": "",
            "src-tauri/Info.plist": "",
            "apps/desktop-ui/src/Fake.test.tsx": " ".join(
                p06_photokit.PHOTOKIT_COMMANDS
            ),
        }

        errors = p06_photokit._marker_errors(decoded)

        self.assertTrue(
            any("UI command is not wired" in error for error in errors),
            errors,
        )
        self.assertTrue(
            any("Tauri command is not registered" in error for error in errors),
            errors,
        )

    def test_live_record_requires_exact_nonce_bound_package_proof(self) -> None:
        record = live_record("f" * 64)
        self.assertEqual(
            [],
            p06_photokit._validate_live_record(
                record,
                nonce="f" * 64,
                packet_sha256="a" * 64,
                source_sha256="c" * 64,
                app_identity=app_identity(),
            ),
        )

        record["native_callbacks"] = False
        errors = p06_photokit._validate_live_record(
            record,
            nonce="f" * 64,
            packet_sha256="a" * 64,
            source_sha256="c" * 64,
            app_identity=app_identity(),
        )
        self.assertTrue(any("native_callbacks" in error for error in errors))

    def test_live_record_rejects_each_evaluator_owned_identity_mismatch(self) -> None:
        for field in app_identity().as_dict():
            with self.subTest(field=field):
                record = live_record("f" * 64)
                record[field] = (
                    "com.example.changed"
                    if field == "bundle_id"
                    else "9" * 64
                )
                errors = p06_photokit._validate_live_record(
                    record,
                    nonce="f" * 64,
                    packet_sha256="a" * 64,
                    source_sha256="c" * 64,
                    app_identity=app_identity(),
                )
                self.assertTrue(
                    any(field in error for error in errors),
                    errors,
                )

    def test_evaluator_identity_fails_closed_on_strict_signature_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "target/release/bundle/macos/Wardrobe.app"
            executable = app / "Contents/MacOS/Wardrobe"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"executable")
            (app / "Contents/Info.plist").write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleIdentifier": p06_photokit.EXPECTED_BUNDLE_ID,
                        "CFBundleExecutable": "Wardrobe",
                        "NSPhotoLibraryUsageDescription": p06_photokit.EXPECTED_USAGE,
                    }
                )
            )
            with mock.patch.object(
                p06_photokit,
                "run_bounded_command",
                side_effect=(
                    command_result(b"invalid", returncode=1),
                    command_result(b"designated => identifier test\n"),
                ),
            ):
                identity, checks, errors = p06_photokit._evaluated_app_identity(
                    root, {}
                )

        self.assertIsNone(identity)
        self.assertIn("strict_app_code_signature", checks)
        self.assertTrue(any("strict" in error for error in errors), errors)

    def test_evaluator_computes_all_challenged_app_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "target/release/bundle/macos/Wardrobe.app"
            executable = app / "Contents/MacOS/Wardrobe"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"exact executable")
            info_bytes = plistlib.dumps(
                {
                    "CFBundleIdentifier": p06_photokit.EXPECTED_BUNDLE_ID,
                    "CFBundleExecutable": "Wardrobe",
                    "NSPhotoLibraryUsageDescription": p06_photokit.EXPECTED_USAGE,
                }
            )
            (app / "Contents/Info.plist").write_bytes(info_bytes)
            requirement = b"designated => identifier com.devrai.wardrobe"
            with mock.patch.object(
                p06_photokit,
                "run_bounded_command",
                side_effect=(
                    command_result(),
                    command_result(
                        b"Executable=/private/path\n# " + requirement + b"\n"
                    ),
                ),
            ):
                identity, checks, errors = p06_photokit._evaluated_app_identity(
                    root, {}
                )

            self.assertEqual([], errors)
            self.assertIsNotNone(identity)
            assert identity is not None
            self.assertEqual(
                hashlib.sha256(info_bytes).hexdigest(),
                identity.info_plist_sha256,
            )
            self.assertEqual(
                hashlib.sha256(b"exact executable").hexdigest(),
                identity.executable_sha256,
            )
            self.assertEqual(
                p06_photokit._bundle_sha256(app),
                identity.bundle_sha256,
            )
            self.assertEqual(
                hashlib.sha256(requirement).hexdigest(),
                identity.designated_requirement_sha256,
            )
            self.assertEqual(
                {"strict_app_code_signature", "designated_app_requirement"},
                set(checks),
            )

    def test_bundle_aggregate_changes_when_package_content_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Wardrobe.app"
            content = bundle / "Contents/Resources/value"
            content.parent.mkdir(parents=True)
            content.write_bytes(b"before")
            before = p06_photokit._bundle_sha256(bundle)
            content.write_bytes(b"after")
            after = p06_photokit._bundle_sha256(bundle)

        self.assertNotEqual(before, after)

    def test_success_executes_one_live_smoke_and_writes_bounded_evidence(self) -> None:
        source = source_validation()

        def execute(command: list[str], **kwargs: object) -> CommandResult:
            if command[-1] == "live":
                challenge = json.loads(
                    kwargs["env"][p06_photokit.LIVE_CHALLENGE_ENV]  # type: ignore[index]
                )
                for field, expected in app_identity().as_dict().items():
                    self.assertEqual(expected, challenge[field])
                output = (
                    p06_photokit.LIVE_PREFIX
                    + json.dumps(live_record(challenge["challenge_nonce"]))
                    + "\n"
                ).encode()
                return command_result(output)
            if command[-1] in {"core", "platform", "tauri"}:
                return command_result(b"running 1 test\n")
            return command_result()

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p06_photokit, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(
                    p06_photokit, "validate_source", return_value=source
                ),
                mock.patch.object(
                    p06_photokit,
                    "_evaluated_app_identity",
                    return_value=(app_identity(), {}, []),
                ),
                mock.patch.object(
                    p06_photokit, "run_bounded_command", side_effect=execute
                ) as run,
            ):
                result = p06_photokit.evaluate(
                    ROOT, evidence, set(p06_photokit.REQUIREMENT_IDS)
                )

            self.assertEqual(0, result)
            self.assertEqual(len(p06_photokit.command_checks(source)), run.call_count)
            self.assertEqual(
                {
                    *(f"{item}.json" for item in p06_photokit.REQUIREMENT_IDS),
                    p06_photokit.DIAGNOSTICS_NAME,
                },
                {path.name for path in evidence.iterdir()},
            )
            diagnostics = json.loads(
                (evidence / p06_photokit.DIAGNOSTICS_NAME).read_text()
            )
            self.assertEqual(1, diagnostics["exact_package_live_smoke_count"])
            self.assertTrue(diagnostics["real_native_callbacks"])
            self.assertFalse(diagnostics["developer_id_signed"])
            for requirement in p06_photokit.REQUIREMENT_IDS:
                payload = json.loads((evidence / f"{requirement}.json").read_text())
                self.assertEqual("pass", payload["status"])
                self.assertLess(
                    (evidence / f"{requirement}.json").stat().st_size,
                    p06_photokit.MAX_ARTIFACT_BYTES,
                )

    def test_absent_live_runner_fails_closed_without_running_commands(self) -> None:
        source = source_validation(
            errors=("exactly one checked-in live runner is required",),
            live=False,
        )
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P06-PHO-001.json"
            stale.write_text('{"status":"pass"}')
            with (
                mock.patch.object(
                    p06_photokit, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(
                    p06_photokit, "validate_source", return_value=source
                ),
                mock.patch.object(
                    p06_photokit,
                    "_evaluated_app_identity",
                    return_value=(app_identity(), {}, []),
                ),
                mock.patch.object(p06_photokit, "run_bounded_command") as run,
            ):
                result = p06_photokit.evaluate(
                    ROOT, evidence, set(p06_photokit.REQUIREMENT_IDS)
                )

            self.assertEqual(1, result)
            run.assert_not_called()
            self.assertFalse(stale.exists())
            diagnostics = json.loads(
                (evidence / p06_photokit.DIAGNOSTICS_NAME).read_text()
            )
            self.assertEqual("fail", diagnostics["status"])
            self.assertFalse(diagnostics["pass_evidence_written"])

    def test_live_gate_precedes_focused_checks_without_duplicate_regressions(
        self,
    ) -> None:
        source = source_validation()

        checks = p06_photokit.command_checks(source)

        self.assertTrue(checks[0].live_smoke)
        self.assertTrue(all(not check.live_smoke for check in checks[1:]))
        self.assertFalse(
            any(check.name.startswith("phase_") for check in source.focused_checks)
        )

    def test_live_output_must_be_exactly_one_record(self) -> None:
        source = source_validation()

        def execute(command: list[str], **_: object) -> CommandResult:
            if command[-1] == "live":
                return command_result(b"operator log\n")
            if command[-1] in {"core", "platform", "tauri"}:
                return command_result(b"running 1 test\n")
            return command_result()

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p06_photokit, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(
                    p06_photokit, "validate_source", return_value=source
                ),
                mock.patch.object(
                    p06_photokit,
                    "_evaluated_app_identity",
                    return_value=(app_identity(), {}, []),
                ),
                mock.patch.object(
                    p06_photokit, "run_bounded_command", side_effect=execute
                ),
            ):
                result = p06_photokit.evaluate(
                    ROOT, evidence, set(p06_photokit.REQUIREMENT_IDS)
                )

            self.assertEqual(1, result)
            diagnostics = json.loads(
                (evidence / p06_photokit.DIAGNOSTICS_NAME).read_text()
            )
            self.assertTrue(
                any("exactly one framed" in error for error in diagnostics["failures"])
            )

    def test_partial_evidence_is_removed_after_atomic_write_failure(self) -> None:
        source = source_validation()

        def execute(command: list[str], **kwargs: object) -> CommandResult:
            if command[-1] == "live":
                challenge = json.loads(
                    kwargs["env"][p06_photokit.LIVE_CHALLENGE_ENV]  # type: ignore[index]
                )
                return command_result(
                    (
                        p06_photokit.LIVE_PREFIX
                        + json.dumps(live_record(challenge["challenge_nonce"]))
                        + "\n"
                    ).encode()
                )
            return command_result(
                b"running 1 test\n"
                if command[-1] in {"core", "platform", "tauri"}
                else b"ok"
            )

        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            original = p06_photokit._write_bounded_json
            writes = 0

            def fail_second(path: Path, value: dict[str, object]) -> None:
                nonlocal writes
                writes += 1
                if writes == 2:
                    raise OSError("injected write failure")
                original(path, value)

            with (
                mock.patch.object(
                    p06_photokit, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(
                    p06_photokit, "validate_source", return_value=source
                ),
                mock.patch.object(
                    p06_photokit,
                    "_evaluated_app_identity",
                    return_value=(app_identity(), {}, []),
                ),
                mock.patch.object(
                    p06_photokit, "run_bounded_command", side_effect=execute
                ),
                mock.patch.object(
                    p06_photokit,
                    "_write_bounded_json",
                    side_effect=fail_second,
                ),
            ):
                with self.assertRaisesRegex(OSError, "injected"):
                    p06_photokit.evaluate(
                        ROOT, evidence, set(p06_photokit.REQUIREMENT_IDS)
                    )

            self.assertFalse(any(evidence.iterdir()))

    def test_dispatcher_registers_only_photo_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence = root / "evidence"
            run_dir.mkdir()
            selected = set(p06_photokit.REQUIREMENT_IDS)
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": sorted(selected)})
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
                    evaluator_run.p06_photokit, "evaluate", return_value=0
                ) as evaluate,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(evaluator_run.ROOT, evidence, selected)


if __name__ == "__main__":
    unittest.main()
