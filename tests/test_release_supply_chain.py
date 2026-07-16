from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import release_supply_chain as supply


REPO = Path(__file__).resolve().parents[1]


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.policy = json.loads((REPO / supply.POLICY_PATH).read_text(encoding="utf-8"))
        self.policy["cargo"]["targets"] = [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
        ]
        self.policy["npm"]["install_script_allowlist"] = [
            {"name": "esbuild", "version": "1.2.3"}
        ]
        self.policy["swift"]["package_path"] = "native/photokit"
        self.policy["models"]["root"] = "assets/model-artifacts"
        self.write_policy()

        write_json(
            root / "release/wardrobe-build-metadata-v1.json",
            {
                "schema_version": 1,
                "application_id": "com.example.fixture",
                "application_version": "1.0.0",
                "release_sequence": 1,
            },
        )
        (root / "Cargo.toml").write_text("[workspace]\nmembers=[]\n", encoding="utf-8")
        (root / "native/photokit").mkdir(parents=True, exist_ok=True)
        (root / "native/photokit/Package.swift").write_text(
            "// swift-tools-version: 5.10\n", encoding="utf-8"
        )
        self.policy["swift"]["manifest_sha256"] = hashlib.sha256(
            (root / "native/photokit/Package.swift").read_bytes()
        ).hexdigest()
        self.write_policy()
        write_json(
            root / "package.json",
            {
                "name": "fixture",
                "version": "1.0.0",
                "license": "UNLICENSED",
                "private": True,
            },
        )
        write_json(
            root / "apps/ui/package.json",
            {
                "name": "@wardrobe/ui",
                "version": "1.0.0",
                "license": "UNLICENSED",
                "private": True,
            },
        )
        self.lock = {
            "name": "fixture",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {
                    "name": "fixture",
                    "version": "1.0.0",
                    "license": "UNLICENSED",
                },
                "apps/ui": {
                    "name": "@wardrobe/ui",
                    "version": "1.0.0",
                    "license": "UNLICENSED",
                },
                "node_modules/@wardrobe/ui": {
                    "resolved": "apps/ui",
                    "link": True,
                },
                "node_modules/esbuild": {
                    "version": "1.2.3",
                    "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-1.2.3.tgz",
                    "integrity": "sha512-YWJj",
                    "license": "MIT",
                    "hasInstallScript": True,
                },
            },
        }
        self.write_npm_lock()
        self.cargo_lock = {
            "version": 4,
            "package": [
                {"name": "wardrobe-desktop", "version": "1.0.0"},
                {
                    "name": "arm-only",
                    "version": "1.0.0",
                    "source": supply.CARGO_REGISTRY,
                    "checksum": "1" * 64,
                },
                {
                    "name": "x86-only",
                    "version": "1.0.0",
                    "source": supply.CARGO_REGISTRY,
                    "checksum": "2" * 64,
                },
            ],
        }
        self.write_cargo_lock()

    def write_policy(self) -> None:
        write_json(self.root / supply.POLICY_PATH, self.policy)

    def write_npm_lock(self) -> None:
        write_json(self.root / "package-lock.json", self.lock)

    def write_cargo_lock(self) -> None:
        lines = ["version = 4", ""]
        for package in self.cargo_lock["package"]:
            lines.extend(
                [
                    "[[package]]",
                    f'name = "{package["name"]}"',
                    f'version = "{package["version"]}"',
                ]
            )
            if "source" in package:
                lines.append(f'source = "{package["source"]}"')
            if "checksum" in package:
                lines.append(f'checksum = "{package["checksum"]}"')
            lines.append("")
        (self.root / "Cargo.lock").write_text("\n".join(lines), encoding="utf-8")

    def metadata(self, target: str) -> dict[str, object]:
        root_id = f"path+file://{self.root}/#wardrobe-desktop@1.0.0"
        dep_name = "arm-only" if target.startswith("aarch64") else "x86-only"
        dep_id = f"{supply.CARGO_REGISTRY}#{dep_name}@1.0.0"
        return {
            "packages": [
                {
                    "id": root_id,
                    "name": "wardrobe-desktop",
                    "version": "1.0.0",
                    "license": "UNLICENSED",
                    "source": None,
                    "manifest_path": str(self.root / "Cargo.toml"),
                },
                {
                    "id": dep_id,
                    "name": dep_name,
                    "version": "1.0.0",
                    "license": "MIT",
                    "source": supply.CARGO_REGISTRY,
                    "manifest_path": f"/cargo/registry/{dep_name}/Cargo.toml",
                },
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": root_id,
                        "deps": [
                            {
                                "name": dep_name,
                                "pkg": dep_id,
                                "dep_kinds": [{"kind": None, "target": None}],
                            }
                        ],
                    },
                    {"id": dep_id, "deps": []},
                ]
            },
            "version": 1,
            "workspace_root": str(self.root),
        }

    def runner(self, command: list[str] | tuple[str, ...], cwd: Path) -> str:
        if command[:2] == ["cargo", "metadata"]:
            target = command[command.index("--filter-platform") + 1]
            return json.dumps(self.metadata(target))
        if command[:3] == ["swift", "package", "dump-package"]:
            return json.dumps({"dependencies": []})
        if command[:3] == ["npm", "ls", "--all"]:
            return json.dumps({"name": "fixture", "version": "1.0.0", "problems": []})
        raise AssertionError(f"unexpected command: {command} in {cwd}")

    def install(self) -> None:
        remote = self.root / "node_modules/esbuild"
        remote.mkdir(parents=True)
        write_json(
            remote / "package.json",
            {"name": "esbuild", "version": "1.2.3", "license": "MIT"},
        )
        executable = remote / "bin/esbuild"
        executable.parent.mkdir()
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        bin_dir = self.root / "node_modules/.bin"
        bin_dir.mkdir()
        (bin_dir / "esbuild").symlink_to("../esbuild/bin/esbuild")
        workspace = self.root / "node_modules/@wardrobe"
        workspace.mkdir()
        (workspace / "ui").symlink_to("../../apps/ui")


class SupplyChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = Fixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_deterministic_manifest_and_both_cargo_target_closures(self) -> None:
        first, first_bytes = supply.build_manifest(
            self.root, runner=self.fixture.runner, scan_sources=False
        )
        second, second_bytes = supply.build_manifest(
            self.root, runner=self.fixture.runner, scan_sources=False
        )
        self.assertEqual(first, second)
        self.assertEqual(first_bytes, second_bytes)
        self.assertTrue(first_bytes.endswith(b"\n"))
        self.assertNotIn(str(self.root).encode(), first_bytes)
        entries = {(item["name"], tuple(item["targets"])) for item in first["dependencies"]}
        self.assertIn(("arm-only", ("aarch64-apple-darwin",)), entries)
        self.assertIn(("x86-only", ("x86_64-apple-darwin",)), entries)

    def test_cargo_checksum_license_and_source_fail_closed(self) -> None:
        cases = ("missing_checksum", "wrong_checksum", "missing_license", "wrong_source")
        for case in cases:
            with self.subTest(case=case):
                fixture = Fixture(self.root)
                if case == "missing_checksum":
                    fixture.cargo_lock["package"][1].pop("checksum")
                    fixture.write_cargo_lock()
                elif case == "wrong_checksum":
                    fixture.cargo_lock["package"][1]["checksum"] = "Z" * 64
                    fixture.write_cargo_lock()
                original_metadata = fixture.metadata

                def metadata(target: str) -> dict[str, object]:
                    result = original_metadata(target)
                    if target.startswith("aarch64") and case == "missing_license":
                        result["packages"][1]["license"] = ""
                    if target.startswith("aarch64") and case == "wrong_source":
                        result["packages"][1]["source"] = "git+https://example.invalid/repo"
                    return result

                fixture.metadata = metadata  # type: ignore[method-assign]
                with self.assertRaises(supply.SupplyChainError):
                    supply.build_manifest(
                        self.root, runner=fixture.runner, scan_sources=False
                    )
                shutil.rmtree(self.root)
                self.root.mkdir()

    def test_npm_sri_license_source_and_script_allowlist_fail_closed(self) -> None:
        mutations = {
            "sri": lambda record: record.update(integrity="not-sri"),
            "license": lambda record: record.pop("license"),
            "source": lambda record: record.update(
                resolved="https://evil.invalid/esbuild-1.2.3.tgz"
            ),
            "script": lambda record: record.update(version="9.9.9"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                fixture = Fixture(self.root)
                mutate(fixture.lock["packages"]["node_modules/esbuild"])
                fixture.write_npm_lock()
                with self.assertRaises(supply.SupplyChainError):
                    supply._npm_inventory(self.root, supply.load_policy(self.root))
                shutil.rmtree(self.root)
                self.root.mkdir()

    def test_workspace_link_is_contained_and_unsafe_link_is_rejected(self) -> None:
        entries, _, _ = supply._npm_inventory(
            self.root, supply.load_policy(self.root)
        )
        self.assertIn("@wardrobe/ui", {item["name"] for item in entries})
        self.fixture.lock["packages"]["node_modules/@wardrobe/ui"]["resolved"] = "../escape"
        self.fixture.write_npm_lock()
        with self.assertRaisesRegex(supply.SupplyChainError, "contained|escapes"):
            supply._npm_inventory(self.root, supply.load_policy(self.root))

    def test_check_installed_allows_workspace_and_bin_links(self) -> None:
        self.fixture.install()
        supply.check_installed(
            self.root,
            runner=self.fixture.runner,
            host_os="darwin",
            host_cpu="arm64",
        )

    def test_check_installed_rejects_identity_symlink_and_tree_drift(self) -> None:
        self.fixture.install()
        write_json(
            self.root / "node_modules/esbuild/package.json",
            {"name": "esbuild", "version": "9.9.9"},
        )
        with self.assertRaisesRegex(supply.SupplyChainError, "identity drift"):
            supply.check_installed(
                self.root,
                runner=self.fixture.runner,
                host_os="darwin",
                host_cpu="arm64",
            )

        shutil.rmtree(self.root / "node_modules")
        self.fixture.install()
        shutil.rmtree(self.root / "node_modules/esbuild")
        (self.root / "remote-target").mkdir()
        (self.root / "node_modules/esbuild").symlink_to("../remote-target")
        with self.assertRaisesRegex(supply.SupplyChainError, "root is a symlink"):
            supply.check_installed(
                self.root,
                runner=self.fixture.runner,
                host_os="darwin",
                host_cpu="arm64",
            )

        shutil.rmtree(self.root / "node_modules")
        self.fixture.install()

        def bad_tree(command: list[str], cwd: Path) -> str:
            if command[:3] == ["npm", "ls", "--all"]:
                return json.dumps({"problems": ["extraneous: drift@1.0.0"]})
            return self.fixture.runner(command, cwd)

        with self.assertRaisesRegex(supply.SupplyChainError, "extraneous"):
            supply.check_installed(
                self.root, runner=bad_tree, host_os="darwin", host_cpu="arm64"
            )

    def test_model_inventory_empty_hash_tamper_symlink_and_executable(self) -> None:
        policy = supply.load_policy(self.root)
        self.assertEqual(supply._model_inventory(self.root, policy), [])

        artifact = self.root / "assets/model-artifacts/segmenter.onnx"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"reviewed model")
        with self.assertRaisesRegex(supply.SupplyChainError, "unlisted"):
            supply._model_inventory(self.root, policy)
        self.fixture.policy["models"]["artifacts"] = [
            {
                "execution_class": "data",
                "length": artifact.stat().st_size,
                "path": "segmenter.onnx",
                "provider": "fixture",
                "revision": "v1",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ]
        self.fixture.write_policy()
        policy = supply.load_policy(self.root)
        self.assertEqual(len(supply._model_inventory(self.root, policy)), 1)

        artifact.write_bytes(b"tampered")
        with self.assertRaisesRegex(supply.SupplyChainError, "hash/length"):
            supply._model_inventory(self.root, policy)

        artifact.unlink()
        target = self.root / "target-model"
        target.write_bytes(b"reviewed model")
        artifact.symlink_to(target)
        with self.assertRaisesRegex(supply.SupplyChainError, "symlink"):
            supply._model_inventory(self.root, policy)

        artifact.unlink()
        artifact.write_bytes(b"reviewed model")
        artifact.chmod(0o700)
        with self.assertRaisesRegex(supply.SupplyChainError, "executable"):
            supply._model_inventory(self.root, policy)

    def test_policy_unknown_fields_are_rejected(self) -> None:
        self.fixture.policy["models"]["remote_services"]["outfit_recommendation"][
            "temperature"
        ] = 0
        self.fixture.write_policy()
        with self.assertRaisesRegex(supply.SupplyChainError, "unknown"):
            supply.load_policy(self.root)

    def test_swift_manifest_drift_fails_before_executable_inspection(self) -> None:
        (self.root / "native/photokit/Package.swift").write_text(
            "// changed executable manifest\n", encoding="utf-8"
        )
        commands: list[tuple[str, ...]] = []

        def runner(command: list[str], cwd: Path) -> str:
            del cwd
            commands.append(tuple(command))
            return "{}"

        with self.assertRaisesRegex(supply.SupplyChainError, "reviewed policy hash"):
            supply.build_manifest(self.root, runner=runner, scan_sources=False)
        self.assertEqual([], commands)

    def test_source_prohibition_is_tight_and_excludes_openai_adapter(self) -> None:
        source = self.root / "crates/wardrobe-core/src/provider.rs"
        source.parent.mkdir(parents=True)
        source.write_text(
            'const ENDPOINT: &str = "https://api.openai.com/v1/responses";\n',
            encoding="utf-8",
        )
        supply.scan_productions_sources(self.root)
        source.write_text('let enabled = "trust_remote_code";\n', encoding="utf-8")
        with self.assertRaisesRegex(supply.SupplyChainError, "remote model code"):
            supply.scan_productions_sources(self.root)

    def test_source_scan_rejects_symlinks_and_oversized_files(self) -> None:
        source_root = self.root / "crates/wardrobe-core/src"
        source_root.mkdir(parents=True)
        target = self.root / "unreviewed.rs"
        target.write_text('let enabled = "trust_remote_code";\n', encoding="utf-8")
        linked = source_root / "linked.rs"
        linked.symlink_to(target)
        with self.assertRaisesRegex(supply.SupplyChainError, "source symlink"):
            supply.scan_productions_sources(self.root)

        linked.unlink()
        (source_root / "oversized.rs").write_bytes(b"x" * (4 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(supply.SupplyChainError, "exceeds scan bound"):
            supply.scan_productions_sources(self.root)

    def test_every_advertised_production_build_forces_clean_offline_install(self) -> None:
        package = json.loads((REPO / "package.json").read_text(encoding="utf-8"))
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")

        self.assertEqual("make production-bundle", package["scripts"]["desktop:build"])
        self.assertIn("production-bundle: npm-clean-install", makefile)
        self.assertIn("npm ci --offline --ignore-scripts", makefile)
        self.assertIn("./node_modules/.bin/tauri build", makefile)

    def test_check_rejects_stale_generated_bytes(self) -> None:
        _, expected = supply.build_manifest(
            self.root, runner=self.fixture.runner, scan_sources=True
        )
        output = self.root / supply.OUTPUT_PATH
        output.parent.mkdir(parents=True)
        output.write_bytes(expected)
        supply.check(self.root, runner=self.fixture.runner)
        output.write_bytes(expected + b" ")
        with self.assertRaisesRegex(supply.SupplyChainError, "stale"):
            supply.check(self.root, runner=self.fixture.runner)

    def test_atomic_prepublication_failure_preserves_prior_file(self) -> None:
        output = self.root / "generated/manifest.json"
        output.parent.mkdir()
        output.write_bytes(b"prior\n")
        with mock.patch.object(supply.os, "replace", side_effect=OSError("injected")):
            with self.assertRaisesRegex(supply.SupplyChainError, "before rename"):
                supply.atomic_publish(output, b"next\n")
        self.assertEqual(output.read_bytes(), b"prior\n")
        self.assertEqual(list(output.parent.glob("*.tmp")), [])

    def test_atomic_parent_fsync_failure_reports_uncertainty(self) -> None:
        output = self.root / "generated/manifest.json"
        output.parent.mkdir()
        with mock.patch.object(
            supply.os, "fsync", side_effect=[None, OSError("injected")]
        ):
            with self.assertRaisesRegex(supply.SupplyChainError, "uncertain after rename"):
                supply.atomic_publish(output, b"published\n")
        self.assertEqual(output.read_bytes(), b"published\n")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
