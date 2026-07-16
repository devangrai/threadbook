#!/usr/bin/env python3
"""Generate and verify Wardrobe's deterministic release supply-chain manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
from collections import deque
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import unquote, urlparse


POLICY_PATH = "release/supply-chain-policy-v1.json"
OUTPUT_PATH = "release/generated/supply-chain-manifest-v1.json"
CARGO_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXACT_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9A-Za-z-]+)+$")
MODEL_SUFFIXES = {
    ".bin",
    ".ckpt",
    ".dylib",
    ".gguf",
    ".mlmodel",
    ".mlpackage",
    ".onnx",
    ".pt",
    ".pth",
    ".safetensors",
    ".so",
    ".tflite",
    ".wasm",
}
FORBIDDEN_SOURCE_MARKERS = {
    "from_pretrained(": "runtime model acquisition",
    "hf_hub::": "Hugging Face runtime",
    "hf_hub_download(": "runtime model acquisition",
    "huggingface.co/": "Hugging Face model hub",
    "huggingface_hub": "Hugging Face runtime",
    "model-plugin": "dynamic model plugin loading",
    "model_plugin": "dynamic model plugin loading",
    "onnxruntime": "unapproved model runtime",
    "ort::session": "unapproved model runtime",
    "snapshot_download(": "runtime model acquisition",
    "torch.hub": "runtime model acquisition",
    "transformers::": "unapproved model runtime",
    "trust_remote_code": "remote model code",
    "wasmer::": "unapproved executable model runtime",
    "wasmtime::": "unapproved executable model runtime",
}
PRODUCTION_SOURCE_ROOTS = (
    "Cargo.toml",
    "package.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/scripts",
    "apps/desktop-ui/src",
    "crates/wardrobe-core/Cargo.toml",
    "crates/wardrobe-core/build.rs",
    "crates/wardrobe-core/src",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/build.rs",
    "crates/wardrobe-platform/src",
    "native/photokit/Package.swift",
    "native/photokit/Sources",
    "src-tauri/Cargo.toml",
    "src-tauri/build.rs",
    "src-tauri/src",
)


class SupplyChainError(RuntimeError):
    """A deterministic supply-chain validation failure."""


CommandRunner = Callable[[Sequence[str], Path], str]


def _run_command(command: Sequence[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
        )
    except OSError as exc:
        raise SupplyChainError(f"cannot execute {command[0]}: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise SupplyChainError(
            f"{' '.join(command)} failed with status {result.returncode}: {detail}"
        )
    return result.stdout


def _read_json(path: Path, label: str) -> Any:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SupplyChainError(f"invalid {label} at {path}: {exc}") from exc
    return value


def _read_toml(path: Path, label: str) -> Any:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SupplyChainError(f"invalid {label} at {path}: {exc}") from exc


def _expect_keys(value: Any, expected: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SupplyChainError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        unknown = sorted(actual - expected)
        missing = sorted(expected - actual)
        raise SupplyChainError(
            f"{label} fields do not match closed schema; "
            f"unknown={unknown}, missing={missing}"
        )
    return value


def _expect_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SupplyChainError(f"{label} must be a nonempty string")
    return value


def _safe_relative(value: Any, label: str, *, allow_dot: bool = False) -> str:
    text = _expect_string(value, label)
    pure = PurePosixPath(text)
    if (
        pure.is_absolute()
        or "\\" in text
        or ".." in pure.parts
        or (not allow_dot and text in {"", "."})
    ):
        raise SupplyChainError(f"{label} must be a contained relative POSIX path")
    return text


def _contained(root: Path, candidate: Path, label: str) -> Path:
    root_real = root.resolve()
    try:
        candidate_real = candidate.resolve(strict=False)
        candidate_real.relative_to(root_real)
    except (OSError, ValueError) as exc:
        raise SupplyChainError(f"{label} escapes repository: {candidate}") from exc
    return candidate_real


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise SupplyChainError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def load_policy(repo: Path) -> Mapping[str, Any]:
    policy = _expect_keys(
        _read_json(repo / POLICY_PATH, "supply-chain policy"),
        {
            "schema_version",
            "release_metadata_path",
            "cargo",
            "npm",
            "swift",
            "models",
        },
        "policy",
    )
    if policy["schema_version"] != 1:
        raise SupplyChainError("policy.schema_version must be 1")
    _safe_relative(policy["release_metadata_path"], "policy.release_metadata_path")

    cargo = _expect_keys(
        policy["cargo"],
        {
            "allowed_dependency_kinds",
            "first_party_license",
            "lockfile_path",
            "manifest_path",
            "registry_source",
            "root_package",
            "targets",
        },
        "policy.cargo",
    )
    for key in ("lockfile_path", "manifest_path"):
        _safe_relative(cargo[key], f"policy.cargo.{key}")
    if cargo["root_package"] != "wardrobe-desktop":
        raise SupplyChainError("policy.cargo.root_package must be wardrobe-desktop")
    if cargo["registry_source"] != CARGO_REGISTRY:
        raise SupplyChainError("policy.cargo.registry_source must be crates.io")
    if cargo["first_party_license"] != "UNLICENSED":
        raise SupplyChainError("policy.cargo.first_party_license must be UNLICENSED")
    if cargo["allowed_dependency_kinds"] != ["build", "normal"]:
        raise SupplyChainError(
            "policy.cargo.allowed_dependency_kinds must be ['build', 'normal']"
        )
    if cargo["targets"] != ["aarch64-apple-darwin", "x86_64-apple-darwin"]:
        raise SupplyChainError("policy.cargo.targets must contain both reviewed targets")

    npm = _expect_keys(
        policy["npm"],
        {"install_script_allowlist", "lockfile_path", "registry_base_url"},
        "policy.npm",
    )
    _safe_relative(npm["lockfile_path"], "policy.npm.lockfile_path")
    if npm["registry_base_url"] != "https://registry.npmjs.org/":
        raise SupplyChainError("policy.npm.registry_base_url is not reviewed")
    allowlist: list[tuple[str, str]] = []
    if not isinstance(npm["install_script_allowlist"], list):
        raise SupplyChainError("policy.npm.install_script_allowlist must be an array")
    for index, item in enumerate(npm["install_script_allowlist"]):
        entry = _expect_keys(
            item, {"name", "version"}, f"policy.npm.install_script_allowlist[{index}]"
        )
        allowlist.append(
            (
                _expect_string(entry["name"], f"install allowlist name {index}"),
                _expect_string(entry["version"], f"install allowlist version {index}"),
            )
        )
    if allowlist != sorted(set(allowlist)):
        raise SupplyChainError("npm install-script allowlist must be sorted and unique")

    swift = _expect_keys(
        policy["swift"],
        {"allow_external_dependencies", "manifest_sha256", "package_path"},
        "policy.swift",
    )
    swift_package_path = _safe_relative(
        swift["package_path"], "policy.swift.package_path"
    )
    if swift["allow_external_dependencies"] is not False:
        raise SupplyChainError("external Swift dependencies must remain prohibited")
    if not isinstance(swift["manifest_sha256"], str) or not SHA256_RE.fullmatch(
        swift["manifest_sha256"]
    ):
        raise SupplyChainError("policy.swift.manifest_sha256 must be SHA-256")
    swift_manifest = repo / swift_package_path / "Package.swift"
    if _sha256(swift_manifest) != swift["manifest_sha256"]:
        raise SupplyChainError(
            "Swift package manifest differs from the reviewed policy hash"
        )

    models = _expect_keys(
        policy["models"],
        {
            "artifacts",
            "local_providers",
            "prohibitions",
            "remote_model_code_allowed",
            "remote_services",
            "root",
        },
        "policy.models",
    )
    _safe_relative(models["root"], "policy.models.root")
    local = _expect_keys(
        models["local_providers"], {"segmentation"}, "policy.models.local_providers"
    )
    segmentation = _expect_keys(
        local["segmentation"], {"availability"}, "policy.models.local_providers.segmentation"
    )
    if segmentation["availability"] != "unavailable":
        raise SupplyChainError("local segmentation provider must be unavailable")
    expected_services = {
        "outfit_recommendation": ("openai", "gpt-5.6-sol"),
        "try_on_visualization": ("openai", "gpt-image-2"),
    }
    services = _expect_keys(
        models["remote_services"],
        set(expected_services),
        "policy.models.remote_services",
    )
    for purpose, (provider, model) in expected_services.items():
        service = _expect_keys(
            services[purpose],
            {"downloads_code", "model", "provider"},
            f"policy.models.remote_services.{purpose}",
        )
        if (
            service["provider"] != provider
            or service["model"] != model
            or service["downloads_code"] is not False
        ):
            raise SupplyChainError(f"remote service {purpose} is not the reviewed binding")
    if models["remote_model_code_allowed"] is not False:
        raise SupplyChainError("remote model code must remain prohibited")
    if models["prohibitions"] != [
        "dynamic_model_plugins",
        "executable_model_artifacts",
        "remote_model_code",
        "runtime_model_downloads",
    ]:
        raise SupplyChainError("policy.models.prohibitions is not the reviewed set")
    if not isinstance(models["artifacts"], list):
        raise SupplyChainError("policy.models.artifacts must be an array")
    paths: list[str] = []
    for index, item in enumerate(models["artifacts"]):
        artifact = _expect_keys(
            item,
            {"execution_class", "length", "path", "provider", "revision", "sha256"},
            f"policy.models.artifacts[{index}]",
        )
        paths.append(_safe_relative(artifact["path"], f"model artifact path {index}"))
        if type(artifact["length"]) is not int or artifact["length"] < 0:
            raise SupplyChainError(f"model artifact length {index} must be nonnegative")
        if not isinstance(artifact["sha256"], str) or not SHA256_RE.fullmatch(
            artifact["sha256"]
        ):
            raise SupplyChainError(f"model artifact sha256 {index} is invalid")
        for key in ("provider", "revision"):
            _expect_string(artifact[key], f"model artifact {key} {index}")
        if artifact["execution_class"] != "data":
            raise SupplyChainError("model artifact execution_class must be data")
    if paths != sorted(set(paths)):
        raise SupplyChainError("model artifact paths must be sorted and unique")
    return policy


def _release_identity(repo: Path, policy: Mapping[str, Any]) -> Mapping[str, Any]:
    path = repo / policy["release_metadata_path"]
    metadata = _expect_keys(
        _read_json(path, "release metadata"),
        {"application_id", "application_version", "release_sequence", "schema_version"},
        "release metadata",
    )
    if metadata["schema_version"] != 1:
        raise SupplyChainError("release metadata schema_version must be 1")
    _expect_string(metadata["application_id"], "release application_id")
    _expect_string(metadata["application_version"], "release application_version")
    if type(metadata["release_sequence"]) is not int or metadata["release_sequence"] < 1:
        raise SupplyChainError("release_sequence must be a positive integer")
    return metadata


def _cargo_lock_index(repo: Path, policy: Mapping[str, Any]) -> dict[tuple[str, str, str], str]:
    lock_path = repo / policy["cargo"]["lockfile_path"]
    lock = _read_toml(lock_path, "Cargo.lock")
    if set(lock) - {"version", "package", "metadata", "patch", "root"}:
        raise SupplyChainError("Cargo.lock has unsupported top-level fields")
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise SupplyChainError("Cargo.lock package array is missing")
    result: dict[tuple[str, str, str], str] = {}
    for index, package in enumerate(packages):
        if not isinstance(package, dict):
            raise SupplyChainError(f"Cargo.lock package {index} is not an object")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if source is None:
            continue
        if source != policy["cargo"]["registry_source"]:
            raise SupplyChainError(f"unsupported Cargo source for {name} {version}: {source}")
        checksum = package.get("checksum")
        if not isinstance(checksum, str) or not SHA256_RE.fullmatch(checksum):
            raise SupplyChainError(f"invalid Cargo checksum for {name} {version}")
        key = (str(name), str(version), source)
        if key in result:
            raise SupplyChainError(f"duplicate Cargo.lock package identity: {key}")
        result[key] = checksum
    return result


def _cargo_metadata_for_target(
    repo: Path,
    policy: Mapping[str, Any],
    target: str,
    runner: CommandRunner,
) -> Mapping[str, Any]:
    output = runner(
        [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--filter-platform",
            target,
            "--format-version",
            "1",
            "--manifest-path",
            policy["cargo"]["manifest_path"],
        ],
        repo,
    )
    try:
        metadata = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SupplyChainError(f"cargo metadata returned invalid JSON for {target}") from exc
    if not isinstance(metadata, dict):
        raise SupplyChainError(f"cargo metadata for {target} must be an object")
    required = {"packages", "resolve", "version", "workspace_root"}
    missing = sorted(required - set(metadata))
    if missing:
        raise SupplyChainError(f"cargo metadata for {target} is missing fields: {missing}")
    return metadata


def _cargo_inventory(
    repo: Path,
    policy: Mapping[str, Any],
    runner: CommandRunner,
) -> tuple[list[dict[str, Any]], set[str]]:
    lock = _cargo_lock_index(repo, policy)
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    manifest_paths: set[str] = set()
    for target in policy["cargo"]["targets"]:
        metadata = _cargo_metadata_for_target(repo, policy, target, runner)
        packages = metadata["packages"]
        resolve = metadata["resolve"]
        if not isinstance(packages, list) or not isinstance(resolve, dict):
            raise SupplyChainError(f"malformed cargo metadata for {target}")
        by_id = {package["id"]: package for package in packages}
        nodes = {node["id"]: node for node in resolve.get("nodes", [])}
        roots = [
            package["id"]
            for package in packages
            if package.get("name") == policy["cargo"]["root_package"]
        ]
        if len(roots) != 1:
            raise SupplyChainError(
                f"expected one Cargo root {policy['cargo']['root_package']}, got {len(roots)}"
            )
        roles_by_id: dict[str, set[str]] = {roots[0]: {"runtime"}}
        queue: deque[str] = deque([roots[0]])
        while queue:
            package_id = queue.popleft()
            node = nodes.get(package_id)
            if node is None:
                raise SupplyChainError(f"Cargo resolve node missing for {package_id}")
            parent_roles = roles_by_id[package_id]
            for dependency in node.get("deps", []):
                child_id = dependency.get("pkg")
                kinds: set[str] = set()
                for item in dependency.get("dep_kinds", []):
                    kind = item.get("kind") or "normal"
                    if kind == "dev":
                        continue
                    if kind not in policy["cargo"]["allowed_dependency_kinds"]:
                        raise SupplyChainError(f"unsupported Cargo dependency kind: {kind}")
                    kinds.add(kind)
                child_roles: set[str] = set()
                if "normal" in kinds:
                    child_roles.update(parent_roles)
                if "build" in kinds:
                    child_roles.add("build")
                if not child_roles:
                    continue
                before = roles_by_id.setdefault(child_id, set())
                new = child_roles - before
                if new:
                    before.update(new)
                    queue.append(child_id)

        for package_id, roles in roles_by_id.items():
            package = by_id.get(package_id)
            if package is None:
                raise SupplyChainError(f"Cargo package missing for {package_id}")
            name = _expect_string(package.get("name"), "Cargo package name")
            version = _expect_string(package.get("version"), f"Cargo version for {name}")
            license_value = package.get("license")
            if not isinstance(license_value, str) or not license_value.strip():
                raise SupplyChainError(f"missing Cargo license for {name} {version}")
            source_value = package.get("source")
            manifest = Path(_expect_string(package.get("manifest_path"), "manifest_path"))
            if source_value is None:
                manifest_real = _contained(repo, manifest, f"Cargo manifest for {name}")
                if license_value != policy["cargo"]["first_party_license"]:
                    raise SupplyChainError(
                        f"first-party Cargo license for {name} must be "
                        f"{policy['cargo']['first_party_license']}"
                    )
                try:
                    relative_dir = manifest_real.parent.relative_to(repo.resolve()).as_posix()
                    relative_manifest = manifest_real.relative_to(repo.resolve()).as_posix()
                except ValueError as exc:
                    raise SupplyChainError(f"Cargo path package escapes repository: {name}") from exc
                source = f"path:{relative_dir or '.'}"
                integrity = None
                manifest_paths.add(relative_manifest)
            else:
                if source_value != policy["cargo"]["registry_source"]:
                    raise SupplyChainError(
                        f"unsupported Cargo source for {name} {version}: {source_value}"
                    )
                source = source_value
                integrity = lock.get((name, version, source_value))
                if integrity is None:
                    raise SupplyChainError(
                        f"Cargo.lock exact checksum missing for {name} {version}"
                    )
            key = ("cargo", name, version, source)
            entry = merged.setdefault(
                key,
                {
                    "ecosystem": "cargo",
                    "name": name,
                    "version": version,
                    "source": source,
                    "integrity": integrity,
                    "license": license_value,
                    "roles": set(),
                    "targets": set(),
                    "install_script": False,
                },
            )
            if entry["integrity"] != integrity or entry["license"] != license_value:
                raise SupplyChainError(f"inconsistent Cargo identity for {name} {version}")
            entry["roles"].update(roles)
            entry["targets"].add(target)
    return _finalize_entries(merged.values()), manifest_paths


def _npm_name_from_path(package_path: str) -> str:
    if "node_modules/" not in package_path:
        raise SupplyChainError(f"cannot infer npm package name from {package_path}")
    suffix = package_path.rsplit("node_modules/", 1)[1]
    parts = suffix.split("/")
    return "/".join(parts[:2]) if suffix.startswith("@") else parts[0]


def _exact_npm_version(value: Any, label: str) -> str:
    version = _expect_string(value, label)
    if (
        not EXACT_VERSION_RE.fullmatch(version)
        or version.startswith(("v", "=", "~", "^", ">", "<"))
        or any(token in version for token in ("*", "://", "git+", "file:", "workspace:"))
    ):
        raise SupplyChainError(f"{label} is not an exact version: {version}")
    return version


def _validate_npm_registry_url(value: Any, base: str, label: str) -> str:
    url = _expect_string(value, label)
    parsed = urlparse(url)
    base_parsed = urlparse(base)
    if (
        parsed.scheme != "https"
        or parsed.netloc != base_parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.endswith(".tgz")
        or not parsed.path.startswith("/")
    ):
        raise SupplyChainError(f"{label} is not a canonical npm registry HTTPS URL: {url}")
    return url


def _validate_sri(value: Any, label: str) -> str:
    sri = _expect_string(value, label)
    tokens = sri.split()
    if not tokens or any(
        re.fullmatch(r"(?:sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}", token) is None
        for token in tokens
    ):
        raise SupplyChainError(f"{label} is not valid SRI")
    return sri


def _load_npm_lock(repo: Path, policy: Mapping[str, Any]) -> Mapping[str, Any]:
    lock = _expect_keys(
        _read_json(repo / policy["npm"]["lockfile_path"], "package-lock.json"),
        {"lockfileVersion", "name", "packages", "requires", "version"},
        "package-lock.json",
    )
    if lock["lockfileVersion"] != 3:
        raise SupplyChainError("package-lock.json lockfileVersion must be 3")
    if not isinstance(lock["packages"], dict):
        raise SupplyChainError("package-lock.json packages must be an object")
    return lock


def _npm_applicable(package: Mapping[str, Any], os_name: str, cpu: str) -> bool:
    def accepts(value: Any, candidate: str) -> bool:
        if value is None:
            return True
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise SupplyChainError("npm os/cpu constraints must be string arrays")
        positives = {item for item in value if not item.startswith("!")}
        negatives = {item[1:] for item in value if item.startswith("!")}
        return candidate not in negatives and (not positives or candidate in positives)

    return accepts(package.get("os"), os_name) and accepts(package.get("cpu"), cpu)


def _npm_targets(package: Mapping[str, Any], targets: Sequence[str]) -> list[str]:
    result = []
    for target in targets:
        cpu = "arm64" if target.startswith("aarch64-") else "x64"
        if _npm_applicable(package, "darwin", cpu):
            result.append(target)
    return result


def _npm_inventory(
    repo: Path, policy: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], set[str], Mapping[str, Any]]:
    lock = _load_npm_lock(repo, policy)
    packages = lock["packages"]
    allowlist = {
        (entry["name"], entry["version"])
        for entry in policy["npm"]["install_script_allowlist"]
    }
    observed_scripts: set[tuple[str, str]] = set()
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    manifest_paths: set[str] = set()
    links: dict[str, str] = {}
    for package_path, raw in packages.items():
        if not isinstance(package_path, str) or not isinstance(raw, dict):
            raise SupplyChainError("package-lock package records must be objects")
        if raw.get("link") is True:
            link_keys = set(raw)
            if link_keys != {"link", "resolved"}:
                raise SupplyChainError(f"npm link {package_path} has unsupported fields")
            target = _safe_relative(raw["resolved"], f"npm link target {package_path}")
            _contained(repo, repo / target, f"npm link {package_path}")
            if target not in packages:
                raise SupplyChainError(f"npm link target is not a lock package: {target}")
            links[package_path] = target
            continue

        if package_path == "":
            name = _expect_string(raw.get("name"), "root npm package name")
            version = _exact_npm_version(raw.get("version"), f"npm version for {name}")
            source = "path:."
            manifest_path = "package.json"
        elif not package_path.startswith("node_modules/") and "/node_modules/" not in package_path:
            name = _expect_string(raw.get("name"), f"workspace npm name {package_path}")
            version = _exact_npm_version(
                raw.get("version"), f"npm version for workspace {name}"
            )
            _safe_relative(package_path, f"workspace package path {package_path}")
            source = f"path:{package_path}"
            manifest_path = f"{package_path}/package.json"
        else:
            name = _npm_name_from_path(package_path)
            version = _exact_npm_version(raw.get("version"), f"npm version for {name}")
            source = _validate_npm_registry_url(
                raw.get("resolved"),
                policy["npm"]["registry_base_url"],
                f"npm source for {name} {version}",
            )
            manifest_path = ""
        license_value = raw.get("license")
        if not isinstance(license_value, str) or not license_value.strip():
            raise SupplyChainError(f"missing npm license for {name} {version}")
        local = source.startswith("path:")
        if local and license_value != policy["cargo"]["first_party_license"]:
            raise SupplyChainError(
                f"first-party npm license for {name} must be "
                f"{policy['cargo']['first_party_license']}"
            )
        integrity = (
            None
            if local
            else _validate_sri(raw.get("integrity"), f"npm integrity for {name} {version}")
        )
        install_script = raw.get("hasInstallScript", False)
        if type(install_script) is not bool:
            raise SupplyChainError(f"hasInstallScript for {name} must be boolean")
        if install_script:
            observed_scripts.add((name, version))
            if (name, version) not in allowlist:
                raise SupplyChainError(
                    f"npm install script is not allowlisted: {name}@{version}"
                )
        roles = {"build"} if raw.get("dev") is True else {"runtime"}
        targets = _npm_targets(raw, policy["cargo"]["targets"])
        key = ("npm", name, version, source)
        entry = merged.setdefault(
            key,
            {
                "ecosystem": "npm",
                "name": name,
                "version": version,
                "source": source,
                "integrity": integrity,
                "license": license_value,
                "roles": set(),
                "targets": set(),
                "install_script": install_script,
            },
        )
        if (
            entry["integrity"] != integrity
            or entry["license"] != license_value
            or entry["install_script"] != install_script
        ):
            raise SupplyChainError(f"inconsistent npm identity for {name} {version}")
        entry["roles"].update(roles)
        entry["targets"].update(targets)
        if manifest_path:
            path = repo / manifest_path
            if not path.is_file():
                raise SupplyChainError(f"npm package manifest is missing: {manifest_path}")
            manifest = _read_json(path, f"npm manifest {manifest_path}")
            if not isinstance(manifest, dict):
                raise SupplyChainError(f"npm manifest must be an object: {manifest_path}")
            if manifest.get("name") != name or manifest.get("version") != version:
                raise SupplyChainError(f"npm manifest identity drift: {manifest_path}")
            if manifest.get("license") != license_value:
                raise SupplyChainError(f"npm manifest license drift: {manifest_path}")
            manifest_paths.add(manifest_path)
    if observed_scripts != allowlist:
        unused = sorted(allowlist - observed_scripts)
        raise SupplyChainError(f"npm install-script allowlist contains stale entries: {unused}")
    for link_path, target in links.items():
        if not link_path.startswith("node_modules/") and "/node_modules/" not in link_path:
            raise SupplyChainError(f"npm link is outside node_modules: {link_path}")
        target_record = packages[target]
        expected_name = _npm_name_from_path(link_path)
        if target_record.get("name") != expected_name:
            raise SupplyChainError(f"npm workspace link identity mismatch: {link_path}")
    return _finalize_entries(merged.values()), manifest_paths, lock


def _finalize_entries(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for original in entries:
        entry = dict(original)
        entry["roles"] = sorted(entry["roles"])
        entry["targets"] = sorted(entry["targets"])
        result.append(entry)
    result.sort(
        key=lambda item: (
            item["ecosystem"],
            item["name"],
            item["version"],
            item["source"],
        )
    )
    return result


def _swift_check(repo: Path, policy: Mapping[str, Any], runner: CommandRunner) -> None:
    package_root = repo / policy["swift"]["package_path"]
    output = runner(["swift", "package", "dump-package"], package_root)
    try:
        description = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SupplyChainError("swift package dump-package returned invalid JSON") from exc
    if not isinstance(description, dict):
        raise SupplyChainError("Swift package description must be an object")
    dependencies = description.get("dependencies")
    if dependencies != []:
        raise SupplyChainError("external Swift package dependencies are prohibited")


def _model_inventory(repo: Path, policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    model_root = repo / policy["models"]["root"]
    expected = {item["path"]: item for item in policy["models"]["artifacts"]}
    observed: dict[str, dict[str, Any]] = {}
    if model_root.is_symlink():
        raise SupplyChainError("model artifact root must not be a symlink")
    if model_root.exists():
        if not model_root.is_dir():
            raise SupplyChainError("model artifact root must be a directory")
        for current, dirnames, filenames in os.walk(model_root, followlinks=False):
            current_path = Path(current)
            for dirname in list(dirnames):
                child = current_path / dirname
                if child.is_symlink():
                    raise SupplyChainError(f"model directory symlink is prohibited: {child}")
            for filename in filenames:
                path = current_path / filename
                relative = path.relative_to(model_root).as_posix()
                if path.is_symlink():
                    raise SupplyChainError(f"model artifact symlink is prohibited: {relative}")
                try:
                    mode = path.stat().st_mode
                except OSError as exc:
                    raise SupplyChainError(f"cannot stat model artifact {relative}: {exc}") from exc
                if not stat.S_ISREG(mode):
                    raise SupplyChainError(f"model artifact must be regular: {relative}")
                if mode & 0o111:
                    raise SupplyChainError(f"executable model artifact is prohibited: {relative}")
                reviewed = expected.get(relative)
                if reviewed is None:
                    raise SupplyChainError(f"unlisted model artifact: {relative}")
                length = path.stat().st_size
                digest = _sha256(path)
                if length != reviewed["length"] or digest != reviewed["sha256"]:
                    raise SupplyChainError(f"model artifact hash/length mismatch: {relative}")
                observed[relative] = dict(reviewed)
    missing = sorted(set(expected) - set(observed))
    if missing:
        raise SupplyChainError(f"reviewed model artifacts are missing: {missing}")
    return [observed[path] for path in sorted(observed)]


def _iter_production_files(repo: Path) -> Iterable[Path]:
    seen: set[Path] = set()
    for relative in PRODUCTION_SOURCE_ROOTS:
        root = repo / relative
        if root.is_symlink():
            raise SupplyChainError(f"production source symlink is prohibited: {relative}")
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            discovered = []
            for path in root.rglob("*"):
                path_relative = path.relative_to(repo).as_posix()
                if path.is_symlink():
                    raise SupplyChainError(
                        f"production source symlink is prohibited: {path_relative}"
                    )
                parts = {part.lower() for part in path.relative_to(root).parts}
                if (
                    path.is_file()
                    and "test" not in parts
                    and "tests" not in parts
                    and ".test." not in path.name.lower()
                    and ".spec." not in path.name.lower()
                    and "_test." not in path.name.lower()
                    and not path.name.lower().startswith("test_")
                    and not path.name.lower().endswith("_tests.rs")
                    and path.name.lower() != "tests.rs"
                ):
                    discovered.append(path)
            candidates = discovered
        else:
            continue
        for path in candidates:
            if path not in seen:
                seen.add(path)
                yield path


def scan_productions_sources(repo: Path) -> None:
    model_root = (repo / "assets/model-artifacts").resolve(strict=False)
    for path in _iter_production_files(repo):
        try:
            relative = path.relative_to(repo).as_posix()
            data = path.read_bytes()
        except OSError as exc:
            raise SupplyChainError(f"cannot scan production source {path}: {exc}") from exc
        if path.suffix.lower() in MODEL_SUFFIXES:
            try:
                path.resolve(strict=False).relative_to(model_root)
            except ValueError:
                raise SupplyChainError(f"model-like production artifact outside policy root: {relative}")
        if len(data) > 4 * 1024 * 1024:
            raise SupplyChainError(f"production source exceeds scan bound: {relative}")
        text = data.decode("utf-8", errors="ignore").lower()
        for marker, reason in FORBIDDEN_SOURCE_MARKERS.items():
            if marker in text:
                raise SupplyChainError(
                    f"forbidden {reason} marker {marker!r} in {relative}"
                )


def _input_hashes(repo: Path, paths: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in sorted(set(paths)):
        _safe_relative(relative, f"input hash path {relative}", allow_dot=True)
        path = repo / relative
        if not path.is_file() or path.is_symlink():
            raise SupplyChainError(f"hashed input must be a regular non-symlink file: {relative}")
        result[relative] = _sha256(path)
    return result


def build_manifest(
    repo: Path,
    *,
    runner: CommandRunner = _run_command,
    scan_sources: bool = True,
) -> tuple[dict[str, Any], bytes]:
    repo = repo.resolve()
    policy = load_policy(repo)
    release = _release_identity(repo, policy)
    cargo_entries, cargo_manifests = _cargo_inventory(repo, policy, runner)
    npm_entries, npm_manifests, _ = _npm_inventory(repo, policy)
    _swift_check(repo, policy, runner)
    models = _model_inventory(repo, policy)
    if scan_sources:
        scan_productions_sources(repo)
    dependencies = sorted(
        cargo_entries + npm_entries,
        key=lambda item: (
            item["ecosystem"],
            item["name"],
            item["version"],
            item["source"],
        ),
    )
    identities = [
        (item["ecosystem"], item["name"], item["version"], item["source"])
        for item in dependencies
    ]
    if len(identities) != len(set(identities)):
        raise SupplyChainError("duplicate dependency identity")
    licenses = [
        {
            "ecosystem": item["ecosystem"],
            "license": item["license"],
            "name": item["name"],
            "source": item["source"],
            "version": item["version"],
        }
        for item in dependencies
    ]
    input_paths = {
        POLICY_PATH,
        policy["release_metadata_path"],
        policy["cargo"]["lockfile_path"],
        policy["npm"]["lockfile_path"],
        f"{policy['swift']['package_path']}/Package.swift",
        *cargo_manifests,
        *npm_manifests,
    }
    manifest = {
        "counts": {
            "dependencies": len(dependencies),
            "licenses": len(licenses),
            "model_artifacts": len(models),
        },
        "dependencies": dependencies,
        "input_hashes": _input_hashes(repo, input_paths),
        "licenses": licenses,
        "models": {
            "artifacts": models,
            "local_providers": policy["models"]["local_providers"],
            "prohibitions": policy["models"]["prohibitions"],
            "remote_model_code_allowed": policy["models"]["remote_model_code_allowed"],
            "remote_services": policy["models"]["remote_services"],
            "root": policy["models"]["root"],
        },
        "release": release,
        "schema_version": 1,
        "targets": policy["cargo"]["targets"],
    }
    encoded = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")
    return manifest, encoded


def atomic_publish(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = -1
    temporary: Path | None = None
    renamed = False
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        renamed = True
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if not renamed and temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if renamed:
            raise SupplyChainError(
                f"manifest publication outcome is uncertain after rename: {exc}"
            ) from exc
        raise SupplyChainError(f"manifest publication failed before rename: {exc}") from exc


def generate(repo: Path, *, runner: CommandRunner = _run_command) -> dict[str, Any]:
    manifest, encoded = build_manifest(repo, runner=runner)
    atomic_publish(repo / OUTPUT_PATH, encoded)
    return manifest


def check(repo: Path, *, runner: CommandRunner = _run_command) -> dict[str, Any]:
    manifest, expected = build_manifest(repo, runner=runner)
    output = repo / OUTPUT_PATH
    try:
        actual = output.read_bytes()
    except OSError as exc:
        raise SupplyChainError(f"generated supply-chain manifest is missing: {exc}") from exc
    if actual != expected:
        raise SupplyChainError("generated supply-chain manifest is stale or noncanonical")
    return manifest


def _host_cpu() -> str:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    if machine in {"x86_64", "amd64"}:
        return "x64"
    raise SupplyChainError(f"unsupported npm host CPU: {machine}")


def _validate_safe_bin_link(repo: Path, path: Path) -> None:
    target = _contained(repo, path.resolve(strict=False), f"npm bin link {path}")
    if not target.is_file():
        raise SupplyChainError(f"npm bin link target is not a file: {path}")


def check_installed(
    repo: Path,
    *,
    runner: CommandRunner = _run_command,
    host_os: str | None = None,
    host_cpu: str | None = None,
) -> None:
    repo = repo.resolve()
    policy = load_policy(repo)
    _, _, lock = _npm_inventory(repo, policy)
    packages = lock["packages"]
    host_os = host_os or ("darwin" if sys.platform == "darwin" else sys.platform)
    host_cpu = host_cpu or _host_cpu()
    workspace_links: dict[Path, Path] = {}
    for package_path, record in packages.items():
        if not isinstance(record, dict):
            raise SupplyChainError(f"invalid npm lock record: {package_path}")
        root = repo / package_path
        if record.get("link") is True:
            expected_target = _contained(
                repo, repo / record["resolved"], f"npm workspace link {package_path}"
            )
            workspace_links[root] = expected_target
            if not root.is_symlink():
                raise SupplyChainError(f"npm workspace link is missing: {package_path}")
            actual_target = _contained(
                repo, root.resolve(strict=False), f"installed npm workspace {package_path}"
            )
            if actual_target != expected_target:
                raise SupplyChainError(f"npm workspace link target drift: {package_path}")
            target_record = packages[record["resolved"]]
            manifest = _read_json(actual_target / "package.json", "installed workspace manifest")
            if (
                manifest.get("name") != target_record.get("name")
                or manifest.get("version") != target_record.get("version")
            ):
                raise SupplyChainError(f"installed npm workspace identity drift: {package_path}")
            continue
        if package_path == "" or (
            not package_path.startswith("node_modules/")
            and "/node_modules/" not in package_path
        ):
            continue
        if not _npm_applicable(record, host_os, host_cpu):
            continue
        if root.is_symlink():
            raise SupplyChainError(f"remote npm package root is a symlink: {package_path}")
        if not root.is_dir():
            raise SupplyChainError(f"host-applicable npm package is missing: {package_path}")
        manifest = _read_json(root / "package.json", f"installed npm package {package_path}")
        expected_name = _npm_name_from_path(package_path)
        if (
            manifest.get("name") != expected_name
            or manifest.get("version") != record.get("version")
        ):
            raise SupplyChainError(f"installed npm package identity drift: {package_path}")
        for current, dirnames, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            for child_name in [*dirnames, *filenames]:
                child = current_path / child_name
                if child.is_symlink():
                    if ".bin" in child.parts:
                        _validate_safe_bin_link(repo, child)
                    else:
                        raise SupplyChainError(
                            f"symlink inside remote npm package is prohibited: "
                            f"{child.relative_to(repo)}"
                        )
    node_modules = repo / "node_modules"
    if node_modules.is_dir():
        for path in node_modules.rglob("*"):
            if not path.is_symlink():
                continue
            if path in workspace_links:
                continue
            if ".bin" in path.parts:
                _validate_safe_bin_link(repo, path)
                continue
            raise SupplyChainError(f"undeclared npm symlink is prohibited: {path.relative_to(repo)}")
    output = runner(["npm", "ls", "--all", "--json"], repo)
    try:
        tree = json.loads(output)
    except json.JSONDecodeError as exc:
        raise SupplyChainError("npm ls returned invalid JSON") from exc
    if not isinstance(tree, dict):
        raise SupplyChainError("npm ls tree must be an object")
    problems = tree.get("problems", [])
    if problems:
        raise SupplyChainError(f"npm installed tree is invalid or extraneous: {problems}")


def _summary(manifest: Mapping[str, Any]) -> str:
    counts = manifest["counts"]
    return (
        f"dependencies={counts['dependencies']} licenses={counts['licenses']} "
        f"model_artifacts={counts['model_artifacts']}"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("command", choices=("generate", "check", "check-installed"))
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            manifest = generate(args.repo)
            print(f"generated {OUTPUT_PATH}: {_summary(manifest)}")
        elif args.command == "check":
            manifest = check(args.repo)
            print(f"checked {OUTPUT_PATH}: {_summary(manifest)}")
        else:
            check_installed(args.repo)
            print("checked installed npm tree")
    except SupplyChainError as exc:
        print(f"release supply-chain check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
