from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p05_reconciliation
from tools.evaluators import run as evaluator_run


ROOT = Path(__file__).resolve().parents[1]


def copy(relative: str, root: Path) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, destination)


def write_valid_fixture(root: Path) -> None:
    for relative in p05_reconciliation.EXPECTED_PACKET_HASHES:
        copy(relative, root)
    copy(p05_reconciliation.STATE_FILE, root)
    for relative in p05_reconciliation.SOURCE_FILES:
        copy(relative, root)


def command_result(
    returncode: int = 0,
    output: bytes = b"running 1 test\n",
) -> p05_reconciliation.CommandResult:
    return p05_reconciliation.CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


def packet_validation() -> p05_reconciliation.PacketValidation:
    return p05_reconciliation.PacketValidation(
        errors=(),
        packet_sha256="a" * 64,
        hashes={"packet": "b" * 64},
    )


def source_validation() -> p05_reconciliation.SourceValidation:
    return p05_reconciliation.SourceValidation(
        errors=(),
        source_sha256="c" * 64,
        migration_sha256="d" * 64,
        registered_commands=p05_reconciliation.RECONCILIATION_COMMANDS,
        acl_permissions=tuple(
            "allow-" + command.replace("_", "-")
            for command in p05_reconciliation.RECONCILIATION_COMMANDS
        ),
        schema_tables=(
            "reconciliation_cases",
            "reconciliation_candidates",
        ),
        production_local_only=True,
        automatic_acceptance_disabled=True,
        deletion_targets_unchanged=True,
        production_transport_isolated=True,
        playwright_specs=("apps/desktop-ui/e2e/reconciliation.spec.ts",),
    )


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class PacketValidationTests(unittest.TestCase):
    def test_current_packet_is_frozen_and_approved(self) -> None:
        result = p05_reconciliation.validate_packet(ROOT)

        self.assertEqual((), result.errors)
        self.assertEqual(64, len(result.packet_sha256))

    def test_packet_tampering_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in p05_reconciliation.EXPECTED_PACKET_HASHES:
                copy(relative, root)
            copy(p05_reconciliation.STATE_FILE, root)
            proposal = root / p05_reconciliation.PACKET_DIR / "proposal.md"
            proposal.write_text(
                proposal.read_text(encoding="utf-8") + "\nchanged\n",
                encoding="utf-8",
            )

            result = p05_reconciliation.validate_packet(root)

        self.assertTrue(result.errors)


class SourceValidationTests(unittest.TestCase):
    def test_current_source_contract_is_complete(self) -> None:
        result = p05_reconciliation.validate_source_contract(ROOT)

        self.assertEqual((), result.errors)
        self.assertEqual(
            p05_reconciliation.RECONCILIATION_COMMANDS,
            result.registered_commands,
        )
        self.assertTrue(result.production_local_only)
        self.assertTrue(result.automatic_acceptance_disabled)
        self.assertTrue(result.deletion_targets_unchanged)
        self.assertTrue(result.production_transport_isolated)
        self.assertEqual(64, len(result.migration_sha256))

    def test_source_tampering_fails_closed(self) -> None:
        mutations = (
            (
                "repository",
                "crates/wardrobe-platform/src/reconciliation_repository.rs",
                None,
                None,
            ),
            (
                "dispatcher",
                "src-tauri/src/lib.rs",
                "            open_reconciliation_case_v1,\n",
                "            open_reconciliation_case_missing_v1,\n",
            ),
            (
                "acl",
                "src-tauri/capabilities/main.json",
                "allow-decide-reconciliation-case-v1",
                "allow-decide-reconciliation-case-missing-v1",
            ),
            (
                "deletion target",
                "crates/wardrobe-core/src/catalog.rs",
                "    PhotoKitAsset,\n}",
                "    PhotoKitAsset,\n    ReconciliationCase,\n}",
            ),
        )
        for name, relative, before, after in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_valid_fixture(root)
                path = root / relative
                if before is None:
                    path.unlink()
                else:
                    text = path.read_text(encoding="utf-8")
                    self.assertIn(before, text)
                    path.write_text(
                        text.replace(before, after, 1),
                        encoding="utf-8",
                    )

                result = p05_reconciliation.validate_source_contract(root)

                self.assertTrue(result.errors)


class EvaluatorTests(unittest.TestCase):
    def test_stale_evidence_is_cleared_before_a_failed_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            for requirement in p05_reconciliation.REQUIREMENT_IDS:
                (evidence / f"{requirement}.json").write_text(
                    '{"status":"stale"}',
                    encoding="utf-8",
                )
            with (
                mock.patch.object(
                    p05_reconciliation,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p05_reconciliation,
                    "validate_source_contract",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p05_reconciliation,
                    "run_bounded_command",
                    return_value=command_result(1),
                ),
            ):
                result = p05_reconciliation.evaluate(
                    ROOT,
                    evidence,
                    set(p05_reconciliation.REQUIREMENT_IDS),
                )

            diagnostics = read_json(
                evidence / p05_reconciliation.DIAGNOSTICS_NAME
            )
            self.assertEqual(1, result)
            self.assertEqual("fail", diagnostics["status"])
            self.assertFalse(diagnostics["pass_evidence_written"])
            self.assertFalse(
                any(
                    (evidence / f"{requirement}.json").exists()
                    for requirement in p05_reconciliation.REQUIREMENT_IDS
                )
            )

    def test_wrong_requirement_set_fails_without_running_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            selected = set(p05_reconciliation.REQUIREMENT_IDS)
            selected.remove("P05-REV-001")
            with (
                mock.patch.object(
                    p05_reconciliation,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p05_reconciliation,
                    "run_bounded_command",
                ) as run,
            ):
                result = p05_reconciliation.evaluate(
                    ROOT,
                    evidence,
                    selected,
                )

            diagnostics = read_json(
                evidence / p05_reconciliation.DIAGNOSTICS_NAME
            )
            self.assertEqual(1, result)
            self.assertTrue(
                any(
                    "exactly match" in failure
                    for failure in diagnostics["failures"]  # type: ignore[union-attr]
                )
            )
            run.assert_not_called()

    def test_success_atomically_writes_only_five_bounded_evidence_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p05_reconciliation,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p05_reconciliation,
                    "validate_source_contract",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p05_reconciliation,
                    "run_bounded_command",
                    return_value=command_result(),
                ) as run,
            ):
                result = p05_reconciliation.evaluate(
                    ROOT,
                    evidence,
                    set(p05_reconciliation.REQUIREMENT_IDS),
                )

            self.assertEqual(0, result)
            self.assertEqual(len(p05_reconciliation.COMMAND_CHECKS), run.call_count)
            self.assertEqual(
                {
                    *(f"{requirement}.json"
                      for requirement in p05_reconciliation.REQUIREMENT_IDS),
                    p05_reconciliation.DIAGNOSTICS_NAME,
                },
                {path.name for path in evidence.iterdir()},
            )
            for requirement in p05_reconciliation.REQUIREMENT_IDS:
                path = evidence / f"{requirement}.json"
                payload = read_json(path)
                self.assertLessEqual(
                    path.stat().st_size,
                    p05_reconciliation.MAX_ARTIFACT_BYTES,
                )
                self.assertEqual("pass", payload["status"])
                self.assertEqual(requirement, payload["requirement_id"])
                summary = payload["details"]["public_summary"]  # type: ignore[index]
                self.assertEqual("personal_mvp", summary["profile"])
                self.assertEqual("deferred", summary["model_adjudication"])
                self.assertEqual(
                    "deferred",
                    summary["calibration_and_automatic_acceptance"],
                )
                self.assertEqual("deferred", summary["provider_credentials"])
                self.assertEqual("deferred", summary["notarization"])
                self.assertEqual(
                    "deferred",
                    summary["clean_machine_certification"],
                )
            diagnostics = read_json(
                evidence / p05_reconciliation.DIAGNOSTICS_NAME
            )
            self.assertEqual("pass", diagnostics["status"])
            self.assertTrue(diagnostics["pass_evidence_written"])
            self.assertNotIn(str(ROOT), json.dumps(diagnostics))

    def test_partial_pass_evidence_is_removed_if_atomic_write_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            original = p05_reconciliation._write_bounded_json
            writes = 0

            def fail_second_write(
                path: Path,
                value: dict[str, object],
            ) -> None:
                nonlocal writes
                writes += 1
                if writes == 2:
                    raise OSError("injected atomic write failure")
                original(path, value)

            with (
                mock.patch.object(
                    p05_reconciliation,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p05_reconciliation,
                    "validate_source_contract",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p05_reconciliation,
                    "run_bounded_command",
                    return_value=command_result(),
                ),
                mock.patch.object(
                    p05_reconciliation,
                    "_write_bounded_json",
                    side_effect=fail_second_write,
                ),
            ):
                with self.assertRaises(OSError):
                    p05_reconciliation.evaluate(
                        ROOT,
                        evidence,
                        set(p05_reconciliation.REQUIREMENT_IDS),
                    )

            self.assertFalse(any(evidence.iterdir()))

    def test_every_rust_check_must_report_at_least_one_test(self) -> None:
        for check in p05_reconciliation.COMMAND_CHECKS:
            if not check.require_rust_test:
                continue
            with self.subTest(check=check.name):
                error = p05_reconciliation._command_error(
                    check,
                    command_result(output=b"running 0 tests\n"),
                )
                self.assertIn("matched no Rust tests", error or "")


class DispatcherTests(unittest.TestCase):
    def test_dispatcher_routes_exact_p05_requirement_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence_dir = root / "evidence"
            run_dir.mkdir()
            selected = sorted(p05_reconciliation.REQUIREMENT_IDS)
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
                    evaluator_run.p05_reconciliation,
                    "evaluate",
                    return_value=0,
                ) as evaluate,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(ROOT, evidence_dir, set(selected))


if __name__ == "__main__":
    unittest.main()
