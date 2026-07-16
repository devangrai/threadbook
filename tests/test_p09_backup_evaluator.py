from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p09_backup
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def copy(relative: str, root: Path) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, destination)


def packet_validation() -> p09_backup.PacketValidation:
    return p09_backup.PacketValidation(
        errors=(),
        packet_sha256="a" * 64,
        hashes={"requirements": "b" * 64},
    )


def source_validation(
    *,
    has_tauri: bool = True,
    has_ui: bool = True,
) -> p09_backup.SourceValidation:
    return p09_backup.SourceValidation(
        errors=(),
        source_sha256="c" * 64,
        source_file_count=12,
        restart_smoke_target="platform-test:backup_restore_restart",
        restart_smoke_filter="compiled_backend_restart_smoke",
        has_tauri=has_tauri,
        has_ui=has_ui,
        manifest_sensitive_field_count=0,
        evidence_sensitive_field_count=0,
    )


def command_result(
    *,
    returncode: int = 0,
    output: bytes = b"running 1 test\n",
) -> CommandResult:
    return CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


class P09BackupEvaluatorTests(unittest.TestCase):
    def test_current_frozen_packet_is_valid(self) -> None:
        packet = p09_backup.validate_packet(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual(set(p09_backup.EXPECTED_PACKET_HASHES), set(packet.hashes))
        self.assertEqual(64, len(packet.packet_sha256))

    def test_packet_validation_rejects_changed_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                *p09_backup.EXPECTED_PACKET_HASHES,
                p09_backup.STATE_FILE,
            ):
                copy(relative, root)
            proposal = root / p09_backup.PACKET_DIR / "proposal.md"
            proposal.write_text(
                proposal.read_text(encoding="utf-8") + "\nchanged\n",
                encoding="utf-8",
            )

            packet = p09_backup.validate_packet(root)

        self.assertTrue(
            any("proposal.md" in error for error in packet.errors),
            packet.errors,
        )

    def test_source_schema_scan_rejects_secrets_paths_and_content(self) -> None:
        source = """
        struct BackupManifestV1 {
            pub source_path: String,
            pub credential: String,
            pub source_content: String,
        }
        struct BackupEvidenceV1 {
            pub image_bytes: Vec<u8>,
        }
        """

        self.assertEqual(
            ("credential", "source_content", "source_path"),
            p09_backup._sensitive_schema_fields(source, "Manifest"),
        )
        self.assertEqual(
            ("image_bytes",),
            p09_backup._sensitive_schema_fields(source, "Evidence"),
        )

    def test_restart_smoke_must_be_rust_sqlite_filesystem_not_browser_mock(
        self,
    ) -> None:
        invalid = {
            "crates/wardrobe-platform/tests/backup_restore.rs": """
                #[test]
                fn restart_backup_restore() {
                    playwright();
                    mock_invoke();
                }
            """
        }
        valid = {
            "crates/wardrobe-platform/tests/backup_restore.rs": """
                #[test]
                fn compiled_backend_restart_smoke() {
                    let temporary = tempfile::tempdir().unwrap();
                    std::fs::write(temporary.path().join("catalog.sqlite3"), b"sqlite");
                    restore_backup_after_restart();
                }
            """
        }

        target, test_filter, errors = p09_backup._restart_smoke(ROOT, invalid)
        self.assertEqual(("", ""), (target, test_filter))
        self.assertTrue(errors)

        target, test_filter, errors = p09_backup._restart_smoke(ROOT, valid)
        self.assertEqual("platform-test:backup_restore", target)
        self.assertEqual("compiled_backend_restart_smoke", test_filter)
        self.assertEqual([], errors)

    def test_success_writes_all_system_and_packet_evidence_with_primitives(
        self,
    ) -> None:
        source = source_validation()
        checks = p09_backup.command_checks(source)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p09_backup,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p09_backup,
                    "validate_source",
                    return_value=source,
                ),
                mock.patch.object(
                    p09_backup,
                    "run_bounded_command",
                    return_value=command_result(),
                ) as run,
            ):
                result = p09_backup.evaluate(
                    ROOT,
                    evidence,
                    set(p09_backup.TRIGGER_REQUIREMENT_IDS),
                )

            self.assertEqual(0, result)
            self.assertEqual(len(checks), run.call_count)
            self.assertEqual(
                {
                    *(f"{item}.json" for item in p09_backup.REQUIREMENT_IDS),
                    p09_backup.DIAGNOSTICS_NAME,
                },
                {path.name for path in evidence.iterdir()},
            )
            for requirement in p09_backup.REQUIREMENT_IDS:
                path = evidence / f"{requirement}.json"
                payload = json.loads(path.read_text(encoding="utf-8"))
                summary = payload["details"]["public_summary"]
                self.assertLessEqual(
                    path.stat().st_size,
                    p09_backup.MAX_ARTIFACT_BYTES,
                )
                self.assertTrue(
                    all(
                        isinstance(value, (str, bool, int, float))
                        for value in summary.values()
                    )
                )
                if requirement in p09_backup.DEFERRED_REQUIREMENT_IDS:
                    self.assertEqual("deferred", payload["status"])
                    self.assertFalse(summary["feature_enabled"])
                    self.assertEqual(
                        "deferred_not_passed",
                        summary["acceptance_claim"],
                    )
                else:
                    self.assertEqual("pass", payload["status"])
            diagnostics = json.loads(
                (evidence / p09_backup.DIAGNOSTICS_NAME).read_text()
            )
            self.assertTrue(diagnostics["compiled_backend_restart_smoke"])
            self.assertFalse(diagnostics["packaged_app_tested"])
            self.assertFalse(diagnostics["offline_network_disabled_tested"])
            self.assertNotIn(str(ROOT), json.dumps(diagnostics))

    def test_stale_evidence_is_removed_when_command_fails(self) -> None:
        failed = command_result(returncode=1, output=b"failed")
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            for requirement in p09_backup.REQUIREMENT_IDS:
                (evidence / f"{requirement}.json").write_text(
                    '{"status":"pass"}',
                    encoding="utf-8",
                )
            stale_temp = (
                evidence
                / f".{next(iter(p09_backup.REQUIREMENT_IDS))}.json.old.tmp"
            )
            stale_temp.write_text("partial", encoding="utf-8")
            with (
                mock.patch.object(
                    p09_backup,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p09_backup,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p09_backup,
                    "run_bounded_command",
                    return_value=failed,
                ),
            ):
                result = p09_backup.evaluate(
                    ROOT,
                    evidence,
                    set(p09_backup.TRIGGER_REQUIREMENT_IDS),
                )

            self.assertEqual(1, result)
            self.assertEqual(
                {p09_backup.DIAGNOSTICS_NAME},
                {path.name for path in evidence.iterdir()},
            )
            diagnostics = json.loads(
                (evidence / p09_backup.DIAGNOSTICS_NAME).read_text()
            )
            self.assertTrue(
                any("failed" in failure for failure in diagnostics["failures"])
            )

    def test_malformed_and_unbounded_evidence_records_are_rejected(self) -> None:
        valid_summary = {
            "feature_enabled": True,
            "acceptance_claim": "focused_local_requirement_passed",
        }
        record = {
            "schema_version": 1,
            "requirement_id": "P09-BKP-001",
            "status": "pass",
            "test": "test",
            "recorded_at": "2026-07-15T00:00:00+00:00",
            "details": {
                "checks_passed": 1,
                "compiled_restart_smoke": True,
                "verification_sha256": "a" * 64,
                "public_summary": valid_summary,
            },
        }
        p09_backup._validate_evidence_record(record)

        malformed = dict(record)
        malformed["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "malformed"):
            p09_backup._validate_evidence_record(malformed)

        unbounded = {
            **record,
            "details": {
                **record["details"],
                "public_summary": {"nested": ["not", "a", "primitive"]},
            },
        }
        with self.assertRaisesRegex(ValueError, "bounded primitives"):
            p09_backup._validate_evidence_record(unbounded)

        with self.assertRaisesRegex(ValueError, "size limit"):
            p09_backup._bounded_json_bytes(
                {"value": "x" * p09_backup.MAX_ARTIFACT_BYTES}
            )

    def test_partial_evidence_is_removed_after_atomic_write_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            original = p09_backup._write_bounded_json
            writes = 0

            def fail_second(
                path: Path,
                value: dict[str, object],
            ) -> None:
                nonlocal writes
                writes += 1
                if writes == 2:
                    raise OSError("injected write failure")
                original(path, value)

            with (
                mock.patch.object(
                    p09_backup,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p09_backup,
                    "validate_source",
                    return_value=source_validation(has_tauri=False, has_ui=False),
                ),
                mock.patch.object(
                    p09_backup,
                    "run_bounded_command",
                    return_value=command_result(),
                ),
                mock.patch.object(
                    p09_backup,
                    "_write_bounded_json",
                    side_effect=fail_second,
                ),
            ):
                with self.assertRaisesRegex(OSError, "injected"):
                    p09_backup.evaluate(
                        ROOT,
                        evidence,
                        set(p09_backup.TRIGGER_REQUIREMENT_IDS),
                    )

            self.assertFalse(any(evidence.iterdir()))

    def test_dispatcher_registers_p09_packet_triggers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence = root / "evidence"
            run_dir.mkdir()
            selected = set(p09_backup.TRIGGER_REQUIREMENT_IDS)
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": sorted(selected)}),
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
                    evaluator_run.p09_backup,
                    "evaluate",
                    return_value=0,
                ) as evaluate,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(evaluator_run.ROOT, evidence, selected)


if __name__ == "__main__":
    unittest.main()
