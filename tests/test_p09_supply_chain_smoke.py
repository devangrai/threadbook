from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import p09_supply_chain_smoke as smoke


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def release_fixture(root: Path) -> dict[str, object]:
    hashed_input = root / "Cargo.lock"
    hashed_input.write_bytes(b"version = 4\n")
    dependency = {
        "ecosystem": "cargo",
        "install_script": False,
        "integrity": "1" * 64,
        "license": "MIT",
        "name": "example",
        "roles": ["runtime"],
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "targets": ["aarch64-apple-darwin", "x86_64-apple-darwin"],
        "version": "1.0.0",
    }
    manifest: dict[str, object] = {
        "counts": {
            "dependencies": 1,
            "licenses": 1,
            "model_artifacts": 0,
        },
        "dependencies": [dependency],
        "input_hashes": {
            "Cargo.lock": hashlib.sha256(hashed_input.read_bytes()).hexdigest()
        },
        "licenses": [
            {
                "ecosystem": "cargo",
                "license": "MIT",
                "name": "example",
                "source": dependency["source"],
                "version": "1.0.0",
            }
        ],
        "models": {
            "artifacts": [],
            "local_providers": {"segmentation": {"availability": "unavailable"}},
            "prohibitions": smoke.PROHIBITIONS,
            "remote_model_code_allowed": False,
            "remote_services": smoke.REMOTE_SERVICES,
            "root": "assets/model-artifacts",
        },
        "release": {
            "application_id": "com.devrai.wardrobe",
            "application_version": "0.1.0",
            "release_sequence": 1,
            "schema_version": 1,
        },
        "schema_version": 1,
        "targets": ["aarch64-apple-darwin", "x86_64-apple-darwin"],
    }
    generated = root / smoke.MANIFEST_RELATIVE
    generated.parent.mkdir(parents=True)
    generated.write_bytes(canonical_json(manifest))
    bundle = root / smoke.BUNDLE_RELATIVE
    bundled = bundle / smoke.BUNDLE_MANIFEST_RELATIVE
    bundled.parent.mkdir(parents=True)
    bundled.write_bytes(generated.read_bytes())
    executable = bundle / "Contents/MacOS/wardrobe-desktop"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"Mach-O fixture")
    executable.chmod(0o755)
    return manifest


class P09SupplyChainSmokeTests(unittest.TestCase):
    def test_release_state_requires_exact_canonical_bundled_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_fixture(root)
            state = smoke.verify_release_state(root)

            self.assertEqual(1, state["dependency_count"])
            self.assertEqual(1, state["license_count"])
            self.assertEqual(0, state["model_artifact_count"])

            bundled = root / smoke.BUNDLE_RELATIVE / smoke.BUNDLE_MANIFEST_RELATIVE
            bundled.write_bytes(bundled.read_bytes() + b" ")
            with self.assertRaisesRegex(smoke.SmokeFailure, "differs"):
                smoke.verify_release_state(root)

    def test_manifest_rejects_noncanonical_and_nonempty_or_remote_code_truth(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = release_fixture(root)
            generated = root / smoke.MANIFEST_RELATIVE
            generated.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(smoke.SmokeFailure, "not canonical"):
                smoke.validate_manifest(root)

            models = manifest["models"]
            assert isinstance(models, dict)
            models["remote_model_code_allowed"] = True
            generated.write_bytes(canonical_json(manifest))
            with self.assertRaisesRegex(smoke.SmokeFailure, "model truth"):
                smoke.validate_manifest(root)

            models["remote_model_code_allowed"] = False
            generated.write_bytes(canonical_json(manifest))
            model = root / "assets/model-artifacts/segmenter.onnx"
            model.parent.mkdir(parents=True)
            model.write_bytes(b"unlisted")
            with self.assertRaisesRegex(smoke.SmokeFailure, "files on disk"):
                smoke.validate_manifest(root)

    def test_resource_scan_rejects_model_executable_and_private_key_payloads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_fixture(root)
            resources = root / smoke.BUNDLE_RELATIVE / "Contents/Resources"

            model = resources / "segmenter.onnx"
            model.write_bytes(b"model")
            with self.assertRaisesRegex(smoke.SmokeFailure, "model-shaped"):
                smoke.hash_and_scan_bundle(root / smoke.BUNDLE_RELATIVE)
            model.unlink()

            executable = resources / "helper"
            executable.write_bytes(b"helper")
            executable.chmod(0o755)
            with self.assertRaisesRegex(smoke.SmokeFailure, "executable"):
                smoke.hash_and_scan_bundle(root / smoke.BUNDLE_RELATIVE)
            executable.unlink()

            key = resources / "secret.txt"
            key.write_bytes(b"-----BEGIN PRIVATE KEY-----\n")
            with self.assertRaisesRegex(smoke.SmokeFailure, "private key"):
                smoke.hash_and_scan_bundle(root / smoke.BUNDLE_RELATIVE)

    def test_child_runs_real_checks_and_records_truthful_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_fixture(root)
            report = root / "evidence/smoke.json"
            commands: list[tuple[str, ...]] = []

            def runner(
                command: tuple[str, ...],
                cwd: Path,
                environment: dict[str, str],
            ) -> bytes:
                self.assertEqual(root, cwd)
                self.assertEqual("true", environment["CARGO_NET_OFFLINE"])
                self.assertNotIn("OPENAI_API_KEY", environment)
                commands.append(tuple(command))
                if command[0] == "cargo":
                    return (
                        b"running 4 tests\n"
                        b"test release_manifest_exact ... ok\n"
                        b"test release_manifest_failure_prevents_private_path_and_state_initialization ... ok\n"
                        b"test result: ok. 4 passed\n"
                    )
                return b"checked\n"

            with mock.patch.object(smoke, "require_network_denied") as denied:
                smoke.run_child(root, report, 43123, runner=runner)

            denied.assert_called_once_with(43123)
            self.assertEqual(
                ["check", "check-installed"],
                [command[-1] for command in commands[:2]],
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual("pass", payload["status"])
            self.assertTrue(payload["startup_gate_verified"])
            self.assertFalse(payload["remote_model_code_allowed"])
            self.assertFalse(payload["developer_id_signed"])
            self.assertEqual(
                "focused_supply_chain_packet_passed",
                payload["acceptance_claim"],
            )

    def test_parent_uses_sandbox_exec_and_removes_stale_report_on_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "smoke.json"
            report.write_text('{"status":"pass"}', encoding="utf-8")
            sandbox = root / "sandbox-exec"
            sandbox.write_bytes(b"fixture")
            observed: list[str] = []

            def failed(
                command: list[str], **kwargs: object
            ) -> subprocess.CompletedProcess[bytes]:
                del kwargs
                observed.extend(command)
                return subprocess.CompletedProcess(command, 1, b"denied child failed")

            server = mock.Mock()
            server.server_address = ("127.0.0.1", 43123)
            with (
                mock.patch.object(smoke.sys, "platform", "darwin"),
                mock.patch.object(smoke, "SANDBOX_EXECUTABLE", sandbox),
                mock.patch.object(
                    smoke.http.server,
                    "ThreadingHTTPServer",
                    return_value=server,
                ),
                mock.patch.object(smoke, "network_probe") as control,
                mock.patch.object(smoke.subprocess, "run", side_effect=failed),
            ):
                with self.assertRaisesRegex(smoke.SmokeFailure, "sandboxed"):
                    smoke.run_smoke(root, report)

            self.assertFalse(report.exists())
            control.assert_called_once_with(43123)
            self.assertEqual(str(sandbox), observed[0])
            self.assertIn(smoke.SANDBOX_PROFILE, observed)


if __name__ == "__main__":
    unittest.main()
