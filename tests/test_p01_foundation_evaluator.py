from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p01_foundation
from tools.evaluators import run as evaluator_run


def command_result(returncode: int = 0) -> p01_foundation.CommandResult:
    return p01_foundation.CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(b"test output").hexdigest(),
        output_bytes=64,
        duration_ms=10,
    )


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_valid_fixture(root: Path) -> None:
    migration = "CREATE TABLE foundation(id INTEGER PRIMARY KEY) STRICT;\n"
    migration_hash = hashlib.sha256(migration.encode("utf-8")).hexdigest()
    files = {
        "Cargo.toml": """
[workspace]
members = ["crates/wardrobe-core", "crates/wardrobe-platform", "src-tauri"]
""",
        "package.json": '{"workspaces":["apps/desktop-ui"]}',
        "crates/wardrobe-core/Cargo.toml": """
[package]
name = "wardrobe-core"
[dependencies]
ts-rs = "11"
""",
        "crates/wardrobe-core/src/bin/generate-bindings.rs": """
fn generate() {
    let names = ["get_foundation_snapshot_v1", "run_storage_check_v1",
        "save_credential_v1", "delete_credential_v1"];
}
""",
        "crates/wardrobe-core/src/contracts.rs": """
struct Request { schema_version: u8 }
""",
        "crates/wardrobe-core/src/service.rs": """
fn get_foundation_snapshot_v1() {}
fn run_storage_check_v1() {}
fn save_credential_v1() {}
fn delete_credential_v1() {}
""",
        "apps/desktop-ui/src/generated/contracts.ts": """
export type Request = { schema_version: number }
""",
        "crates/wardrobe-platform/Cargo.toml": """
[package]
name = "wardrobe-platform"
[target.'cfg(target_os = "macos")'.dependencies]
security-framework = "3"
security-framework-sys = "2"
""",
        "crates/wardrobe-platform/src/blob.rs": """
use sha2::Sha256;
fn store() { create_new(); O_NOFOLLOW; hard_link(); remove_file(); sync_all(); }
""",
        "crates/wardrobe-platform/src/credential.rs": """
struct MacOsKeychain;
const SERVICE: &str = "com.devrai.wardrobe.credentials";
fn keychain() {
    set_generic_password(); get_generic_password(); delete_generic_password();
}
""",
        "crates/wardrobe-platform/src/database.rs": """
const SQL: &str = include_str!("../migrations/0001_foundation.sql");
const SHA: &str = include_str!("../migrations/0001_foundation.sha256");
fn migrate() { TransactionBehavior::Immediate; Backup; integrity_check; foreign_key_check; }
fn jobs() {
    idempotency_key; input_hash; pipeline_version; retry_limit; lease_owner; fence;
    job_failures; user_action_key;
}
""",
        "crates/wardrobe-platform/src/diagnostics.rs": """
struct DiagnosticEventV1;
const MAX_LINE_BYTES: usize = 4096;
const MAX_FILE_BYTES: usize = 1048576;
""",
        "crates/wardrobe-platform/src/worker.rs": """
struct PlatformJobQueue;
fn fail() { permanent_failure(); }
""",
        "crates/wardrobe-platform/migrations/0001_foundation.sql": migration,
        "crates/wardrobe-platform/migrations/0001_foundation.sha256": (
            migration_hash + "\n"
        ),
        "src-tauri/Cargo.toml": """
[package]
name = "wardrobe-desktop"
[dependencies]
wardrobe-core = { path = "../crates/wardrobe-core" }
wardrobe-platform = { path = "../crates/wardrobe-platform" }
""",
        "src-tauri/src/lib.rs": """
use wardrobe_core::ApplicationService;
use wardrobe_platform::MacOsKeychain;
fn commands() {
    get_foundation_snapshot_v1();
    run_storage_check_v1();
    save_credential_v1();
    delete_credential_v1();
}
""",
        "src-tauri/capabilities/main.json": json.dumps(
            {
                "permissions": [
                    "allow-get-foundation-snapshot-v1",
                    "allow-run-storage-check-v1",
                    "allow-save-credential-v1",
                    "allow-delete-credential-v1",
                ]
            }
        ),
        "src-tauri/tauri.conf.json": json.dumps(
            {
                "build": {"frontendDist": "../apps/desktop-ui/dist"},
                "app": {"security": {"csp": "object-src 'none'"}},
            }
        ),
        "apps/desktop-ui/package.json": (
            '{"scripts":{"build":"vite build","test":"vitest"}}'
        ),
        "apps/desktop-ui/src/App.tsx": (
            "const labels = ['Wardrobe', 'Activity', 'Settings'];"
        ),
        "apps/desktop-ui/src/foundation-bridge.ts": """
const commands = [
  "get_foundation_snapshot_v1", "run_storage_check_v1",
  "save_credential_v1", "delete_credential_v1"
];
""",
    }
    for relative, text in files.items():
        write(root / relative, text)


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class SourceValidationTests(unittest.TestCase):
    def test_accepts_realistic_source_fixture_and_checks_migration_hash(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            result = p01_foundation.validate_source_contract(root)
            self.assertTrue(
                all(not messages for messages in result.errors.values())
            )
            self.assertTrue(result.security_framework_wired)
            self.assertFalse(result.plaintext_fallback_present)
            self.assertEqual(64, len(result.migration_sha256 or ""))

            write(
                root
                / "crates/wardrobe-platform/migrations/0001_foundation.sha256",
                "0" * 64 + "\n",
            )
            result = p01_foundation.validate_source_contract(root)
            self.assertTrue(
                any(
                    "checksum" in error
                    for error in result.errors["P01-DBS-001"]
                )
            )

    def test_rejects_plaintext_fallback_and_missing_desktop_wiring(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            credential = (
                root / "crates/wardrobe-platform/src/credential.rs"
            )
            credential.write_text(
                credential.read_text(encoding="utf-8")
                + "\nstruct FileCredential;\n",
                encoding="utf-8",
            )
            write(root / "src-tauri/src/lib.rs", "fn commands() {}\n")
            result = p01_foundation.validate_source_contract(root)
            self.assertTrue(result.plaintext_fallback_present)
            self.assertTrue(result.errors["P01-SEC-001"])
            self.assertTrue(result.errors["P01-ARC-001"])


class EvaluatorTests(unittest.TestCase):
    @mock.patch("tools.evaluators.p01_foundation.run_bounded_command")
    def test_success_emits_all_evidence_and_truthful_security_state(
        self,
        run: mock.Mock,
    ) -> None:
        run.return_value = command_result()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            evidence = root / "evidence"
            result = p01_foundation.evaluate(
                root, evidence, set(p01_foundation.REQUIREMENT_IDS)
            )

            self.assertEqual(0, result)
            self.assertEqual(len(p01_foundation.COMMAND_CHECKS), run.call_count)
            for requirement in p01_foundation.REQUIREMENT_IDS:
                payload = read_json(evidence / f"{requirement}.json")
                self.assertEqual("pass", payload["status"])
            security = read_json(evidence / "P01-SEC-001.json")
            summary = security["details"]["public_summary"]
            self.assertEqual(
                "p01_foundation::focused_production_verification",
                security["test"],
            )
            self.assertTrue(security["recorded_at"])
            self.assertEqual("macos_security_framework", summary["credential_store"])
            self.assertFalse(summary["plaintext_fallback"])
            self.assertEqual(
                "deferred/not_run", summary["keychain_live_test"]
            )
            diagnostics = read_json(
                evidence / p01_foundation.DIAGNOSTICS_NAME
            )
            self.assertEqual("pass", diagnostics["status"])
            self.assertEqual(
                "deferred/not_run",
                diagnostics["security"]["keychain_live_test"],
            )

    @mock.patch("tools.evaluators.p01_foundation.run_bounded_command")
    def test_command_failure_removes_stale_and_writes_no_partial_pass(
        self,
        run: mock.Mock,
    ) -> None:
        results = [command_result() for _ in p01_foundation.COMMAND_CHECKS]
        results[1] = command_result(returncode=101)
        run.side_effect = results
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            evidence = root / "evidence"
            evidence.mkdir()
            for requirement in p01_foundation.REQUIREMENT_IDS:
                write(
                    evidence / f"{requirement}.json",
                    '{"status":"stale"}',
                )

            result = p01_foundation.evaluate(
                root, evidence, set(p01_foundation.REQUIREMENT_IDS)
            )

            self.assertEqual(1, result)
            self.assertFalse(
                any(
                    (evidence / f"{requirement}.json").exists()
                    for requirement in p01_foundation.REQUIREMENT_IDS
                )
            )
            diagnostics = read_json(
                evidence / p01_foundation.DIAGNOSTICS_NAME
            )
            self.assertEqual("fail", diagnostics["status"])
            self.assertFalse(diagnostics["pass_evidence_written"])

    @mock.patch("tools.evaluators.p01_foundation.run_bounded_command")
    def test_failed_optional_live_keychain_is_deferred_not_claimed(
        self,
        run: mock.Mock,
    ) -> None:
        run.side_effect = [
            command_result(),
            command_result(),
            command_result(),
            command_result(returncode=101),
        ]
        selected = {"P01-SEC-001"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_fixture(root)
            evidence = root / "evidence"
            with mock.patch.dict(
                os.environ, {"P01_LIVE_KEYCHAIN": "1"}
            ):
                result = p01_foundation.evaluate(root, evidence, selected)
            payload = read_json(evidence / "P01-SEC-001.json")
            diagnostics = read_json(
                evidence / p01_foundation.DIAGNOSTICS_NAME
            )

        self.assertEqual(0, result)
        self.assertEqual(
            "deferred/attempted_not_proven",
            payload["details"]["public_summary"]["keychain_live_test"],
        )
        self.assertEqual(
            "deferred/attempted_not_proven",
            diagnostics["security"]["keychain_live_test"],
        )
        self.assertTrue(
            diagnostics["public_summary"]
            if "public_summary" in diagnostics
            else diagnostics["deferred_limitations"]
        )

    @mock.patch("tools.evaluators.p01_foundation.run_bounded_command")
    def test_unselected_does_nothing(self, run: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = p01_foundation.evaluate(root, root / "evidence", set())
            self.assertEqual(0, result)
            self.assertFalse((root / "evidence").exists())
        run.assert_not_called()


class DispatcherTests(unittest.TestCase):
    @mock.patch(
        "tools.evaluators.run.p01_foundation.evaluate",
        return_value=0,
    )
    def test_dispatcher_routes_p01_requirements(
        self,
        evaluate: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence_dir = root / "evidence"
            run_dir.mkdir()
            selected = ["P01-ARC-001", "P01-OFF-001"]
            write(
                run_dir / "requirements.json",
                json.dumps({"selected_requirement_ids": selected}),
            )
            with mock.patch.dict(
                os.environ,
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                },
            ):
                result = evaluator_run.main()
        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT, evidence_dir, set(selected)
        )


if __name__ == "__main__":
    unittest.main()
