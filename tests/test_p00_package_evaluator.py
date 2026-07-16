from __future__ import annotations

import copy
import os
from pathlib import Path
import plistlib
import tempfile
import time
import unittest

from tools.evaluators import p00_package


def valid_config() -> dict:
    return {
        "build": {
            "frontendDist": "../apps/desktop-ui/dist",
            "devUrl": "http://localhost:1420",
        },
        "app": {
            "security": {
                "capabilities": ["main"],
                "csp": p00_package.EXPECTED_CSP,
            }
        },
    }


def valid_capability() -> dict:
    return {
        "identifier": "main",
        "windows": ["main"],
        "permissions": ["allow-get-runtime-info"],
    }


class SecurityConfigTests(unittest.TestCase):
    def test_accepts_exact_security_policy(self) -> None:
        self.assertEqual(
            [],
            p00_package.validate_security_config(
                valid_config(), valid_capability()
            ),
        )

    def test_rejects_permissive_csp(self) -> None:
        config = valid_config()
        config["app"]["security"]["csp"] = "default-src *"
        self.assertTrue(
            p00_package.validate_security_config(config, valid_capability())
        )

    def test_rejects_excess_capability(self) -> None:
        capability = valid_capability()
        capability["permissions"].append("opener:default")
        self.assertTrue(
            p00_package.validate_security_config(valid_config(), capability)
        )

    def test_rejects_missing_or_core_capability(self) -> None:
        for permissions in ([], ["core:default"]):
            capability = valid_capability()
            capability["permissions"] = permissions
            self.assertTrue(
                p00_package.validate_security_config(
                    valid_config(),
                    capability,
                )
            )

    def test_rejects_remote_navigation_or_ipc(self) -> None:
        config = copy.deepcopy(valid_config())
        config["build"]["frontendDist"] = "https://example.com"
        config["app"]["security"]["dangerousRemoteDomainIpcAccess"] = [
            {"scheme": "https", "domain": "example.com"}
        ]
        errors = p00_package.validate_security_config(config, valid_capability())
        self.assertGreaterEqual(len(errors), 2)

    def test_requires_direct_navigation_policy_wiring(self) -> None:
        valid_source = """
        .on_navigation(|_webview, url| is_allowed_navigation(url))
        """
        permissive_source = """
        .on_navigation(|_webview, _url| true)
        """
        self.assertEqual(
            [],
            p00_package.validate_navigation_policy_source(valid_source),
        )
        self.assertTrue(
            p00_package.validate_navigation_policy_source(permissive_source)
        )

    def test_requires_single_command_app_acl(self) -> None:
        valid_source = """
        AppManifest::new().commands(&["get_runtime_info"])
        """
        invalid_source = """
        AppManifest::new().commands(&["get_runtime_info", "open_file"])
        """
        self.assertEqual(
            [],
            p00_package.validate_app_acl_source(valid_source),
        )
        self.assertTrue(p00_package.validate_app_acl_source(invalid_source))

    def test_requires_exact_generated_app_permission(self) -> None:
        manifests = {
            "__app-acl__": {
                "permissions": {
                    "allow-get-runtime-info": {
                        "commands": {
                            "allow": ["get_runtime_info"],
                            "deny": [],
                        }
                    },
                    "deny-get-runtime-info": {
                        "commands": {
                            "allow": [],
                            "deny": ["get_runtime_info"],
                        }
                    },
                }
            }
        }
        self.assertEqual(
            [],
            p00_package.validate_generated_app_acl(manifests),
        )
        manifests["__app-acl__"]["permissions"]["allow-open-file"] = {
            "commands": {"allow": ["open_file"], "deny": []}
        }
        self.assertTrue(p00_package.validate_generated_app_acl(manifests))


class InventoryTests(unittest.TestCase):
    def test_rejects_forbidden_dependency(self) -> None:
        self.assertTrue(
            p00_package.validate_dependency_names(["serde", "pytorch-runtime"])
        )

    def test_rejects_forbidden_bundle_file(self) -> None:
        records = [{"path": "Resources/model.safetensors", "type": "data"}]
        self.assertTrue(p00_package.validate_bundle_records(records))

    def test_rejects_incomplete_bundle_inventory(self) -> None:
        self.assertTrue(p00_package.validate_bundle_records([]))


class BinaryValidationTests(unittest.TestCase):
    def test_resolves_executable_from_bundle_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Wardrobe.app"
            macos = bundle / "Contents/MacOS"
            macos.mkdir(parents=True)
            executable = macos / "wardrobe-desktop"
            executable.write_bytes(b"fixture")
            with (bundle / "Contents/Info.plist").open("wb") as handle:
                plistlib.dump(
                    {"CFBundleExecutable": "wardrobe-desktop"},
                    handle,
                )

            resolved, errors = p00_package.bundle_executable(bundle)

        self.assertEqual([], errors)
        self.assertEqual(executable, resolved)

    def test_rejects_wrong_architecture(self) -> None:
        self.assertTrue(
            p00_package.validate_architecture(
                "Mach-O 64-bit executable x86_64"
            )
        )

    def test_rejects_invalid_signature(self) -> None:
        self.assertTrue(
            p00_package.validate_signature(1, "code object is not signed")
        )

    def test_rejects_non_ad_hoc_signature(self) -> None:
        details = "Signature size=9000\nAuthority=Developer ID Application: Example"
        self.assertTrue(p00_package.validate_ad_hoc_signature(0, details))

    def write_smoke_executable(self, root: Path, body: str) -> Path:
        executable = root / "smoke"
        executable.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        executable.chmod(0o755)
        return executable

    def test_runtime_smoke_accepts_exact_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = self.write_smoke_executable(
                Path(directory),
                f"echo '{p00_package.RUNTIME_READY_MARKER}'",
            )
            output, errors = p00_package.run_runtime_smoke(
                executable,
                timeout_seconds=1,
            )
        self.assertEqual([], errors)
        self.assertIn(p00_package.RUNTIME_READY_MARKER, output)

    def test_runtime_smoke_rejects_similar_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = self.write_smoke_executable(
                Path(directory),
                f"echo '{p00_package.RUNTIME_READY_MARKER} extra'",
            )
            _, errors = p00_package.run_runtime_smoke(
                executable,
                timeout_seconds=1,
            )
        self.assertTrue(errors)

    def test_runtime_smoke_times_out_and_reaps_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = self.write_smoke_executable(
                Path(directory),
                "sleep 2",
            )
            _, errors = p00_package.run_runtime_smoke(
                executable,
                timeout_seconds=0.05,
            )
        self.assertTrue(any("timed out" in error for error in errors))

    def test_runtime_smoke_terminates_emitter_and_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = self.write_smoke_executable(
                root,
                (
                    "sleep 30 &\n"
                    "child=$!\n"
                    "echo \"$$ $child\" > pids\n"
                    f"echo '{p00_package.RUNTIME_READY_MARKER}'\n"
                    "wait"
                ),
            )
            _, errors = p00_package.run_runtime_smoke(
                executable,
                timeout_seconds=1,
            )
            process_ids = [
                int(value)
                for value in (root / "pids").read_text(encoding="utf-8").split()
            ]

            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and any(
                self.process_exists(process_id) for process_id in process_ids
            ):
                time.sleep(0.05)

        self.assertEqual([], errors)
        self.assertTrue(
            all(not self.process_exists(process_id) for process_id in process_ids)
        )

    def process_exists(self, process_id: int) -> bool:
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return False
        return True


class PhaseGateTests(unittest.TestCase):
    def write_valid_gate_fixture(self, root: Path) -> None:
        (root / "docs/phase-reports").mkdir(parents=True)
        (root / "docs/adr").mkdir(parents=True)
        (root / "specs/phases").mkdir(parents=True)
        (root / "docs/phase-reports/P00.md").write_text(
            """# P00

| Requirement | Status | Evidence or blocker |
|---|---|---|
| `P00-PKG-001` | BLOCKED | Credentials unavailable; see ADR 0001 |
| `P00-SEG-001` | NOT_STARTED | Pending |
""",
            encoding="utf-8",
        )
        (root / "docs/adr/0001-desktop-packaging.md").write_text(
            """# ADR 0001

Status: Accepted

Developer ID Application
notarytool
clean supported Mac
P00-PKG-001

## Fallback: P00-PKG-001

- Failed condition: Credentials unavailable.
- Accepted fallback: Use an ad-hoc local package.
- Owner action: Provide credentials.
- Unblock evidence: Validate a notarized build on a clean Mac.
""",
            encoding="utf-8",
        )
        (root / "specs/phases/P00-feasibility.md").write_text(
            """### P00-PKG-001: Package
### P00-SEG-001: Segment
""",
            encoding="utf-8",
        )

    def block_segmentation(self, root: Path, detail: str) -> None:
        report_path = root / "docs/phase-reports/P00.md"
        report = report_path.read_text(encoding="utf-8")
        report_path.write_text(
            report.replace(
                "| `P00-SEG-001` | NOT_STARTED | Pending |",
                f"| `P00-SEG-001` | BLOCKED | {detail} |",
            ),
            encoding="utf-8",
        )

    def test_accepts_structured_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_valid_gate_fixture(root)
            self.assertEqual([], p00_package.validate_phase_gate(root))

    def test_rejects_blocked_spike_without_adr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_valid_gate_fixture(root)
            self.block_segmentation(root, "No provider passed")
            errors = p00_package.validate_phase_gate(root)
            self.assertTrue(any("has no ADR reference" in item for item in errors))

    def test_rejects_missing_or_unaccepted_adr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_valid_gate_fixture(root)
            self.block_segmentation(root, "See ADR 0002")
            missing_errors = p00_package.validate_phase_gate(root)
            self.assertTrue(
                any("does not resolve one ADR 0002" in item for item in missing_errors)
            )

            (root / "docs/adr/0002-segmentation.md").write_text(
                """Status: Proposed

## Fallback: P00-SEG-001
- Failed condition: No provider passed.
- Accepted fallback: Use manual masks.
- Owner action: Curate data.
- Unblock evidence: Pass the benchmark.
""",
                encoding="utf-8",
            )
            proposed_errors = p00_package.validate_phase_gate(root)
            self.assertTrue(any("ADR 0002 is not accepted" in item for item in proposed_errors))

    def test_rejects_adr_without_structured_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_valid_gate_fixture(root)
            self.block_segmentation(root, "See ADR 0002")
            adr_path = root / "docs/adr/0002-segmentation.md"
            adr_path.write_text(
                "Status: Accepted\n\nP00-SEG-001 cannot proceed.\n",
                encoding="utf-8",
            )
            errors = p00_package.validate_phase_gate(root)
            self.assertTrue(any("lacks fallback section" in item for item in errors))

    def test_rejects_incomplete_phase_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs/phase-reports").mkdir(parents=True)
            (root / "docs/adr").mkdir(parents=True)
            (root / "specs/phases").mkdir(parents=True)
            (root / "docs/phase-reports/P00.md").write_text(
                "| `P00-PKG-001` | PASSED | wrong |\n",
                encoding="utf-8",
            )
            (root / "docs/adr/0001-desktop-packaging.md").write_text(
                "Status: Proposed\n",
                encoding="utf-8",
            )
            (root / "specs/phases/P00-feasibility.md").write_text(
                "### P00-PKG-001: Package\n",
                encoding="utf-8",
            )

            self.assertTrue(p00_package.validate_phase_gate(root))


if __name__ == "__main__":
    unittest.main()
