from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p09_deletion
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def copy(relative: str, root: Path) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, destination)


def packet_validation() -> p09_deletion.PacketValidation:
    return p09_deletion.PacketValidation(
        errors=(),
        packet_sha256="a" * 64,
        hashes={"requirements": "b" * 64},
    )


def command_check(
    name: str,
    *,
    smoke: bool = False,
) -> p09_deletion.CommandCheck:
    return p09_deletion.CommandCheck(
        name=name,
        command=("test-command", name),
        require_rust_test=True,
        compiled_deletion_smoke=smoke,
    )


def source_validation() -> p09_deletion.SourceValidation:
    return p09_deletion.SourceValidation(
        errors=(),
        source_sha256="c" * 64,
        source_hashes={"source.rs": "d" * 64},
        source_file_count=20,
        migration_sha256="e" * 64,
        schema_table_count=110,
        blob_owner_count=17,
        focused_checks=(
            command_check("core"),
            command_check("platform"),
            command_check("tauri"),
            p09_deletion.CommandCheck(
                "ui",
                ("npm", "test"),
            ),
        ),
        smoke_check=command_check("smoke", smoke=True),
        has_tauri=True,
        has_ui=True,
    )


def command_result(
    *,
    returncode: int = 0,
    output: bytes = b"running 1 test\n",
    output_limit_exceeded: bool = False,
) -> CommandResult:
    return CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        output_limit_exceeded=output_limit_exceeded,
        captured_output=output,
    )


def rust_test(
    name: str,
    body: str,
    *,
    package: str = "wardrobe-platform",
    target_kind: str = "test",
) -> p09_deletion.RustTest:
    prefix = {
        "wardrobe-core": "crates/wardrobe-core/tests",
        "wardrobe-platform": "crates/wardrobe-platform/tests",
        "wardrobe-desktop": "src-tauri/src",
    }[package]
    return p09_deletion.RustTest(
        relative=f"{prefix}/hard_deletion.rs",
        package=package,
        target_kind=target_kind,
        target_name="hard_deletion",
        name=name,
        body=body,
    )


class P09DeletionEvaluatorTests(unittest.TestCase):
    def test_rust_contract_type_names_are_recognized_as_deletion_tests(self) -> None:
        test = p09_deletion.RustTest(
            relative="crates/wardrobe-core/tests/deletion_contracts.rs",
            package="wardrobe-core",
            target_kind="test",
            target_name="deletion_contracts",
            name="strict_execution_contract",
            body="let request: ExecuteDeletionV1Request = build_request();",
        )

        self.assertTrue(p09_deletion._is_deletion_test(test))

    def test_current_frozen_packet_is_valid(self) -> None:
        packet = p09_deletion.validate_packet(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual(
            set(p09_deletion.EXPECTED_PACKET_HASHES),
            set(packet.hashes),
        )
        self.assertEqual(64, len(packet.packet_sha256))

    def test_packet_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                *p09_deletion.EXPECTED_PACKET_HASHES,
                p09_deletion.STATE_FILE,
            ):
                copy(relative, root)
            proposal = root / p09_deletion.PACKET_DIR / "proposal.md"
            proposal.write_text(
                proposal.read_text(encoding="utf-8") + "\nmutated\n",
                encoding="utf-8",
            )

            packet = p09_deletion.validate_packet(root)

        self.assertTrue(
            any("proposal.md" in error for error in packet.errors),
            packet.errors,
        )

    def test_schema_inventory_detects_every_table_and_semantic_blob_owner(
        self,
    ) -> None:
        tables, owners = p09_deletion._schema_inventory(
            {
                "0001.sql": """
                    CREATE TABLE blobs(sha256 TEXT PRIMARY KEY);
                    CREATE TABLE sources(
                        source_id TEXT PRIMARY KEY,
                        blob_sha256 TEXT REFERENCES blobs(sha256)
                    );
                    CREATE TABLE semantic_outputs(
                        output_id TEXT PRIMARY KEY,
                        output_blob_sha256 TEXT
                    );
                    CREATE TABLE settings(setting_key TEXT PRIMARY KEY);
                """,
            }
        )

        self.assertEqual(
            {"blobs", "semantic_outputs", "settings", "sources"},
            tables,
        )
        self.assertEqual({"semantic_outputs", "sources"}, owners)
        mutated_inventory = "blobs sources settings"
        missing = tables - set(mutated_inventory.split())
        self.assertEqual({"semantic_outputs"}, missing)
        self.assertTrue(owners & missing)

    def test_exactly_one_real_compiled_smoke_and_no_browser_mock(self) -> None:
        coverage = """
            execute_deletion_v1();
            schema inventory blob;
            trigger authority key;
            stale replay;
            crash restart trash;
            shared blob;
            backup_retention remote_retention;
            store_lock restore sanitize;
        """
        valid_smoke = rust_test(
            "hard_deletion_restart_residual_smoke",
            """
                execute_deletion_v1();
                let temporary = tempfile::tempdir().unwrap();
                Database::open(temporary.path().join("catalog.sqlite3"));
                std::fs::read(temporary.path());
                restart();
                residual_scan();
                deletion_trash();
                shared_blob();
                backup_retention();
                remote_retention();
                set_test_drain_fault();
                database.execute_deletion(&request);
                response.validate();
            """,
        )
        tests = (
            rust_test(
                "hard_deletion_contract",
                "execute_deletion_v1();",
                package="wardrobe-core",
            ),
            rust_test("hard_deletion_repository", coverage),
            rust_test(
                "hard_deletion_command",
                "execute_deletion_v1();",
                package="wardrobe-desktop",
                target_kind="lib",
            ),
            valid_smoke,
        )

        checks, smoke, errors = p09_deletion._focused_checks(
            tests,
            ("src/P02Workspace.test.tsx",),
        )

        self.assertEqual([], errors)
        self.assertIsNotNone(smoke)
        self.assertTrue(smoke.compiled_deletion_smoke)
        self.assertTrue(checks)

        browser_smoke = rust_test(
            "hard_deletion_restart_residual_smoke",
            valid_smoke.body + "\nplaywright(); mock_invoke();",
        )
        _, smoke, errors = p09_deletion._focused_checks(
            (*tests[:-1], browser_smoke),
            ("src/P02Workspace.test.tsx",),
        )
        self.assertIsNone(smoke)
        self.assertTrue(any("exactly one" in error for error in errors))

        _, smoke, errors = p09_deletion._focused_checks(
            (*tests, valid_smoke),
            ("src/P02Workspace.test.tsx",),
        )
        self.assertIsNone(smoke)
        self.assertTrue(any("exactly one" in error for error in errors))

    def test_trigger_authority_requires_exact_table_and_old_row_key(self) -> None:
        valid = """
            CREATE TRIGGER hd_sources BEFORE DELETE ON sources BEGIN
              SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM deletion_execution_authority a
                JOIN deletion_plan_entries p
                  ON p.snapshot_token=a.snapshot_token
                WHERE p.entity_kind='sources'
                  AND p.key_json=json_array(OLD.source_id)
              ) THEN RAISE(ABORT,'authority required') END;
            END;
            CREATE TRIGGER hd_blobs BEFORE DELETE ON blobs BEGIN
              SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM deletion_execution_authority a
                JOIN deletion_plan_entries p
                  ON p.snapshot_token=a.snapshot_token
                WHERE p.entity_kind='blobs'
                  AND p.key_json=json_array(OLD.sha256)
              ) THEN RAISE(ABORT,'authority required') END;
            END;
        """
        errors, count = p09_deletion._trigger_authority_errors(
            valid,
            {"sources"},
        )
        self.assertEqual([], errors)
        self.assertEqual(2, count)

        mutated = valid.replace(
            "p.key_json=json_array(OLD.source_id)",
            "p.key_json=p.key_json",
        )
        errors, _ = p09_deletion._trigger_authority_errors(
            mutated,
            {"sources"},
        )
        self.assertTrue(any("sources" in error for error in errors))

    def test_success_writes_all_required_evidence_with_primitive_summaries(
        self,
    ) -> None:
        source = source_validation()
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p09_deletion,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p09_deletion,
                    "validate_source",
                    return_value=source,
                ),
                mock.patch.object(
                    p09_deletion,
                    "run_bounded_command",
                    return_value=command_result(),
                ) as run,
            ):
                result = p09_deletion.evaluate(
                    ROOT,
                    evidence,
                    set(p09_deletion.TRIGGER_REQUIREMENT_IDS),
                )

            self.assertEqual(0, result)
            self.assertEqual(len(p09_deletion.command_checks(source)), run.call_count)
            self.assertEqual(
                {
                    *(
                        f"{requirement}.json"
                        for requirement in p09_deletion.REQUIREMENT_IDS
                    ),
                    p09_deletion.DIAGNOSTICS_NAME,
                },
                {path.name for path in evidence.iterdir()},
            )
            for requirement in p09_deletion.REQUIREMENT_IDS:
                payload = json.loads(
                    (evidence / f"{requirement}.json").read_text(encoding="utf-8")
                )
                summary = payload["details"]["public_summary"]
                self.assertTrue(
                    all(
                        isinstance(value, (str, bool, int, float))
                        for value in summary.values()
                    )
                )
                self.assertFalse(summary["signed_packaged_app_tested"])
                self.assertFalse(summary["aggregate_accessibility_tested"])
                if requirement in p09_deletion.DEFERRED_REQUIREMENT_IDS:
                    self.assertEqual("deferred", payload["status"])
                    self.assertFalse(summary["feature_enabled"])
                    self.assertEqual(
                        "deferred_not_passed",
                        summary["acceptance_claim"],
                    )
                else:
                    self.assertEqual("pass", payload["status"])
            diagnostics = json.loads(
                (evidence / p09_deletion.DIAGNOSTICS_NAME).read_text()
            )
            self.assertTrue(diagnostics["compiled_backend_deletion_smoke"])
            self.assertFalse(diagnostics["browser_mock_deletion_smoke"])
            self.assertNotIn(str(ROOT), json.dumps(diagnostics))

    def test_failure_removes_stale_evidence_and_temporary_files(self) -> None:
        failed = command_result(returncode=1, output=b"failed")
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            for requirement in p09_deletion.REQUIREMENT_IDS:
                (evidence / f"{requirement}.json").write_text(
                    '{"status":"pass"}',
                    encoding="utf-8",
                )
            stale_temp = (
                evidence / f".{next(iter(p09_deletion.REQUIREMENT_IDS))}.json.old.tmp"
            )
            stale_temp.write_text("partial", encoding="utf-8")
            with (
                mock.patch.object(
                    p09_deletion,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p09_deletion,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p09_deletion,
                    "run_bounded_command",
                    return_value=failed,
                ),
            ):
                result = p09_deletion.evaluate(
                    ROOT,
                    evidence,
                    set(p09_deletion.TRIGGER_REQUIREMENT_IDS),
                )

            self.assertEqual(1, result)
            self.assertEqual(
                {p09_deletion.DIAGNOSTICS_NAME},
                {path.name for path in evidence.iterdir()},
            )

    def test_unbounded_command_output_fails_closed(self) -> None:
        unbounded = command_result(output_limit_exceeded=True)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p09_deletion,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p09_deletion,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p09_deletion,
                    "run_bounded_command",
                    return_value=unbounded,
                ),
            ):
                result = p09_deletion.evaluate(
                    ROOT,
                    evidence,
                    set(p09_deletion.TRIGGER_REQUIREMENT_IDS),
                )

            diagnostics = json.loads(
                (evidence / p09_deletion.DIAGNOSTICS_NAME).read_text()
            )
            self.assertEqual(1, result)
            self.assertTrue(
                any("output bound" in failure for failure in diagnostics["failures"])
            )
            self.assertFalse(diagnostics["pass_evidence_written"])

    def test_unbounded_or_nested_public_summary_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "bounded primitives"):
            p09_deletion._validate_public_summary({"nested": ["not allowed"]})
        with self.assertRaisesRegex(ValueError, "invalid string"):
            p09_deletion._validate_public_summary(
                {"value": "x" * (p09_deletion.MAX_PUBLIC_STRING_BYTES + 1)}
            )
        with self.assertRaisesRegex(ValueError, "size limit"):
            p09_deletion._bounded_json_bytes(
                {"value": "x" * p09_deletion.MAX_ARTIFACT_BYTES}
            )

    def test_partial_evidence_is_removed_after_atomic_write_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            original = p09_deletion._write_bounded_json
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
                    p09_deletion,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p09_deletion,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p09_deletion,
                    "run_bounded_command",
                    return_value=command_result(),
                ),
                mock.patch.object(
                    p09_deletion,
                    "_write_bounded_json",
                    side_effect=fail_second,
                ),
            ):
                with self.assertRaisesRegex(OSError, "injected"):
                    p09_deletion.evaluate(
                        ROOT,
                        evidence,
                        set(p09_deletion.TRIGGER_REQUIREMENT_IDS),
                    )

            self.assertFalse(any(evidence.iterdir()))

    def test_dispatcher_registers_p09_deletion_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence = root / "evidence"
            run_dir.mkdir()
            selected = set(p09_deletion.TRIGGER_REQUIREMENT_IDS)
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
                    evaluator_run.p09_deletion,
                    "evaluate",
                    return_value=0,
                ) as evaluate,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(evaluator_run.ROOT, evidence, selected)


if __name__ == "__main__":
    unittest.main()
