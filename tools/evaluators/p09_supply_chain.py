"""Fail-closed evaluator for the approved P09 supply-chain packet."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Any

from tools import p09_supply_chain_smoke
from tools.evaluators.p03_receipts import (
    CommandResult,
    run_bounded_command,
    write_atomic_json,
)


SYSTEM_REQUIREMENT_IDS = frozenset(
    {
        "SYS-ARC-001",
        "SYS-DAT-001",
        "SYS-DAT-002",
        "SYS-DEC-001",
        "SYS-REL-001",
        "SYS-REL-002",
        "SYS-SEC-001",
        "SYS-SEC-002",
        "SYS-PRV-001",
        "SYS-OBS-001",
        "SYS-DEL-001",
        "SYS-UPG-001",
        "SYS-A11Y-001",
    }
)
TRIGGER_REQUIREMENT_IDS = frozenset({"P09-SUP-001"})
REQUIREMENT_IDS = SYSTEM_REQUIREMENT_IDS | TRIGGER_REQUIREMENT_IDS
DEFERRED_REQUIREMENT_IDS: frozenset[str] = frozenset()

RUN_ID = "20260716T051436Z-a13cbc8a"
PACKET_DIR = f"artifacts/harness/P09/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p09-supply-chain-evaluator.json"
SMOKE_NAME = "p09-supply-chain-smoke.json"
MANIFEST_RELATIVE = "release/generated/supply-chain-manifest-v1.json"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024
COMMAND_TIMEOUT_SECONDS = 20 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P09-hardening.md": (
        "b88c11b3f97bf7936f19cc6f6e187268eeb0c6a6c11f12de17ed2edf36455846"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "88745b5f11c10f50450e2e0df0ebee5c9315d81cbf08c615b9301b1423a7e916"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "53b62cc0a14ac4e0c732e0be3b83647bb3ec4463086a278ecec4fa7a15268c0e"
    ),
    f"{PACKET_DIR}/review.md": (
        "94db5dc2f9cceec62871a3c3d6bfb76752d62f37ae983caf2790b34ab9e0feac"
    ),
}

SOURCE_FILES = (
    "Cargo.lock",
    "Makefile",
    "package-lock.json",
    "package.json",
    "release/supply-chain-policy-v1.json",
    "release/wardrobe-build-metadata-v1.json",
    MANIFEST_RELATIVE,
    "tools/release_supply_chain.py",
    "tests/test_release_supply_chain.py",
    "crates/wardrobe-core/build.rs",
    "crates/wardrobe-core/src/model_policy.rs",
    "crates/wardrobe-core/tests/model_policy_bindings.rs",
    "crates/wardrobe-platform/build.rs",
    "src-tauri/Cargo.toml",
    "src-tauri/tauri.conf.json",
    "src-tauri/src/release_manifest.rs",
    "src-tauri/src/lib.rs",
    "tools/p09_supply_chain_smoke.py",
    "tests/test_p09_supply_chain_smoke.py",
    "tools/evaluators/p09_supply_chain.py",
    "tests/test_p09_supply_chain_evaluator.py",
)

EXPECTED_RELEASE_TESTS = (
    "accepts_exact_compiled_and_bundled_manifest",
    "rejects_missing_and_tampered_manifest",
    "rejects_noncanonical_or_open_json_even_when_expected_bytes_match",
    "rejects_wrong_release_identity_even_when_expected_bytes_match",
    "rejects_undeclared_model_and_executable_resources",
    "verifies_declared_model_hash_and_length",
)
EXPECTED_STARTUP_TEST = (
    "release_manifest_failure_prevents_private_path_and_state_initialization"
)


@dataclass(frozen=True)
class PacketValidation:
    errors: tuple[str, ...]
    sha256: str
    hashes: dict[str, str]


@dataclass(frozen=True)
class SourceValidation:
    errors: tuple[str, ...]
    sha256: str
    hashes: dict[str, str]
    file_count: int


@dataclass(frozen=True)
class ManifestValidation:
    errors: tuple[str, ...]
    sha256: str
    dependency_count: int
    license_count: int
    input_hash_count: int
    model_artifact_count: int


@dataclass(frozen=True)
class BundleValidation:
    errors: tuple[str, ...]
    sha256: str
    file_count: int
    manifest_sha256: str


@dataclass(frozen=True)
class SmokeValidation:
    errors: tuple[str, ...]
    sha256: str
    bundle_sha256: str
    sandbox_profile_sha256: str


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]
    output_markers: tuple[str, ...] = ()


COMMAND_CHECKS = (
    CommandCheck("current_packaged_build", ("make", "build")),
    CommandCheck(
        "release_supply_check",
        (sys.executable, "tools/release_supply_chain.py", "check"),
    ),
    CommandCheck(
        "installed_tree_check",
        (sys.executable, "tools/release_supply_chain.py", "check-installed"),
    ),
    CommandCheck(
        "focused_python_supply_chain",
        (
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_release_supply_chain.py",
        ),
        ("OK",),
    ),
    CommandCheck(
        "focused_core_model_policy",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-core",
            "--offline",
            "--test",
            "model_policy_bindings",
        ),
        ("generated_remote_model_bindings_match_the_reviewed_release_policy",),
    ),
    CommandCheck(
        "focused_desktop_release_manifest",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-desktop",
            "--offline",
            "release_manifest",
            "--",
            "--test-threads=1",
        ),
        (*EXPECTED_RELEASE_TESTS, EXPECTED_STARTUP_TEST),
    ),
)
PHASE_REGRESSION = CommandCheck("phase_boundary_regression", ("make", "test"))

SMOKE_REQUIRED_TRUE = (
    "network_control_passed",
    "network_sandbox_enforced",
    "supply_check_passed",
    "installed_tree_check_passed",
    "startup_gate_verified",
    "canonical_manifest_verified",
    "bundled_manifest_exact",
)
SMOKE_REQUIRED_FALSE = (
    "remote_model_code_allowed",
    "private_credentials_used",
    "developer_id_signed",
    "notarized",
    "clean_machine_certified",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path, limit: int = MAX_SOURCE_BYTES) -> bytes | None:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            return None
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def _json_object(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _aggregate(contents: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for relative, data in sorted(contents.items()):
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def validate_packet(root: Path) -> PacketValidation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    for relative, expected in EXPECTED_PACKET_HASHES.items():
        data = _read(root / relative)
        if data is None:
            errors.append(f"frozen packet file is unreadable or oversized: {relative}")
            continue
        contents[relative] = data
        hashes[relative] = _sha256(data)
        if hashes[relative] != expected:
            errors.append(f"frozen packet hash changed: {relative}")

    requirements = _json_object(contents.get(f"{PACKET_DIR}/requirements.json", b""))
    rows = requirements.get("requirements")
    evidenced = (
        {
            row.get("id")
            for row in rows
            if isinstance(row, dict) and row.get("evidence_required") is True
        }
        if isinstance(rows, list)
        else set()
    )
    selected = requirements.get("selected_requirement_ids")
    if (
        requirements.get("phase") != "P09"
        or selected != ["P09-SUP-001"]
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("frozen P09 supply-chain requirement contract is invalid")

    state_data = _read(root / STATE_FILE)
    state = _json_object(state_data or b"")
    review = state.get("review")
    spec_hashes = state.get("spec_hashes")
    if state_data is None:
        errors.append("approved packet state is unreadable or oversized")
    elif (
        state.get("phase") != "P09"
        or state.get("run_id") != RUN_ID
        or state.get("status")
        not in {"APPROVED", "BUILT", "EVALUATED", "EVALUATION_FAILED"}
        or state.get("selected_requirement_ids") != selected
        or not isinstance(review, dict)
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash")
        != EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"]
        or not isinstance(spec_hashes, dict)
        or spec_hashes.get("specs/system.md")
        != EXPECTED_PACKET_HASHES["specs/system.md"]
        or spec_hashes.get("specs/phases/P09-hardening.md")
        != EXPECTED_PACKET_HASHES["specs/phases/P09-hardening.md"]
    ):
        errors.append("P09 supply-chain packet is not independently approved")

    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(errors="replace")
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append("approved P09 supply-chain review decision is missing")
    return PacketValidation(
        tuple(dict.fromkeys(errors)),
        _aggregate(contents),
        hashes,
    )


def validate_source(root: Path) -> SourceValidation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    texts: dict[str, str] = {}
    for relative in SOURCE_FILES:
        data = _read(root / relative)
        if data is None:
            errors.append(f"supply-chain source is unreadable or oversized: {relative}")
            continue
        contents[relative] = data
        try:
            texts[relative] = data.decode()
        except UnicodeDecodeError:
            errors.append(f"supply-chain source is not UTF-8: {relative}")

    try:
        tauri_config = json.loads(texts.get("src-tauri/tauri.conf.json", ""))
        resources = tauri_config["bundle"]["resources"]
    except (json.JSONDecodeError, KeyError, TypeError):
        errors.append("Tauri resource configuration is invalid")
    else:
        if not isinstance(resources, dict) or resources.get(
            "../release/generated/supply-chain-manifest-v1.json"
        ) != ("release/supply-chain-manifest-v1.json"):
            errors.append(
                "generated supply-chain manifest is not a fixed Tauri resource"
            )

    verifier = texts.get("src-tauri/src/release_manifest.rs", "")
    for test_name in EXPECTED_RELEASE_TESTS:
        if f"fn {test_name}(" not in verifier:
            errors.append(f"focused Rust release-manifest test is missing: {test_name}")
    for term in (
        'include_bytes!("../../release/generated/supply-chain-manifest-v1.json")',
        "verify_bundled_release_manifest",
        "serde(deny_unknown_fields)",
        "remote_model_code_allowed",
        "unavailable",
        "is_executable_resource",
        "Sha256Digest::from_bytes",
    ):
        if term not in verifier:
            errors.append(f"release-manifest verifier boundary is missing: {term}")
    for forbidden in (
        "reqwest::",
        "std::process",
        "Database::",
        "PrivateAppPaths",
        "MacOsKeychain",
    ):
        if forbidden in verifier:
            errors.append(
                f"release-manifest verifier reaches forbidden capability: {forbidden}"
            )

    desktop = texts.get("src-tauri/src/lib.rs", "")
    if (
        "fn initialize_after_release_manifest" not in desktop
        or f"fn {EXPECTED_STARTUP_TEST}(" not in desktop
    ):
        errors.append("executable startup ordering gate or its focused test is missing")
    start = desktop.find("fn initialize_tauri_state")
    end = desktop.find("#[tauri::command]", start)
    startup = desktop[start:end] if start >= 0 and end > start else ""
    manifest_index = startup.find("initialize_after_release_manifest")
    private_index = startup.find("app_data_dir")
    helper_start = desktop.find("fn initialize_after_release_manifest")
    helper_end = desktop.find("#[tauri::command]", helper_start)
    helper = (
        desktop[helper_start:helper_end]
        if helper_start >= 0 and helper_end > helper_start
        else ""
    )
    if (
        not startup
        or manifest_index < 0
        or private_index < 0
        or manifest_index >= private_index
        or "release_manifest_invalid" not in startup
        or "verify_bundled_release_manifest" not in helper
        or helper.find("verify_bundled_release_manifest") >= helper.find("initialize()")
    ):
        errors.append(
            "release manifest is not verified before resolving private application paths"
        )

    supply = texts.get("tools/release_supply_chain.py", "")
    for term in (
        '"generate", "check", "check-installed"',
        "--locked",
        "--offline",
        "cargo metadata",
        "npm installed tree is invalid or extraneous",
        "remote model code must remain prohibited",
        "manifest publication outcome is uncertain after rename",
    ):
        if term not in supply:
            errors.append(f"release supply-chain boundary is missing: {term}")
    platform_build = texts.get("crates/wardrobe-platform/build.rs", "")
    if "--disable-sandbox" in supply or "--disable-sandbox" in platform_build:
        errors.append("production SwiftPM execution disables its manifest sandbox")

    try:
        policy = json.loads(texts.get("release/supply-chain-policy-v1.json", ""))
        swift_policy = policy["swift"]
        swift_manifest = root / swift_policy["package_path"] / "Package.swift"
        reviewed_swift_hash = swift_policy["manifest_sha256"]
    except (json.JSONDecodeError, KeyError, TypeError):
        errors.append("reviewed Swift manifest policy is invalid")
    else:
        swift_bytes = _read(swift_manifest)
        if (
            swift_bytes is None
            or not isinstance(reviewed_swift_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", reviewed_swift_hash) is None
            or _sha256(swift_bytes) != reviewed_swift_hash
        ):
            errors.append("executable Swift manifest is not bound to reviewed bytes")

    package = _json_object(
        texts.get("package.json", "").encode()
    )
    makefile = texts.get("Makefile", "")
    if (
        package.get("scripts", {}).get("desktop:build") != "make production-bundle"
        or "production-bundle: npm-clean-install" not in makefile
        or "npm ci --offline --ignore-scripts" not in makefile
        or "./node_modules/.bin/tauri build" not in makefile
    ):
        errors.append("an advertised production bundle path bypasses clean npm install")
    return SourceValidation(
        tuple(dict.fromkeys(errors)),
        _aggregate(contents),
        {relative: _sha256(data) for relative, data in contents.items()},
        len(contents),
    )


def _safe_relative(root: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    pure = PurePosixPath(value)
    if pure.is_absolute() or "\\" in value or ".." in pure.parts:
        return None
    candidate = (root / value).resolve(strict=False)
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def validate_generated_manifest(root: Path) -> ManifestValidation:
    path = root / MANIFEST_RELATIVE
    data = _read(path)
    if data is None:
        return ManifestValidation(
            ("generated supply-chain manifest is unreadable or oversized",),
            "",
            0,
            0,
            0,
            0,
        )
    errors: list[str] = []
    manifest = _json_object(data)
    canonical = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()
    if canonical != data:
        errors.append("generated supply-chain manifest is not canonical")
    if set(manifest) != {
        "counts",
        "dependencies",
        "input_hashes",
        "licenses",
        "models",
        "release",
        "schema_version",
        "targets",
    }:
        errors.append("generated supply-chain manifest schema is not closed")

    dependencies = manifest.get("dependencies")
    licenses = manifest.get("licenses")
    input_hashes = manifest.get("input_hashes")
    models = manifest.get("models")
    counts = manifest.get("counts")
    dependencies = dependencies if isinstance(dependencies, list) else []
    licenses = licenses if isinstance(licenses, list) else []
    input_hashes = input_hashes if isinstance(input_hashes, dict) else {}
    models = models if isinstance(models, dict) else {}
    model_artifacts = models.get("artifacts")
    model_artifacts = model_artifacts if isinstance(model_artifacts, list) else []
    expected_counts = {
        "dependencies": len(dependencies),
        "licenses": len(licenses),
        "model_artifacts": len(model_artifacts),
    }
    if manifest.get("schema_version") != 1 or counts != expected_counts:
        errors.append("generated supply-chain manifest counts are invalid")
    if not dependencies or len(licenses) != len(dependencies):
        errors.append("dependency and license inventory is incomplete")
    if manifest.get("targets") != [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    ]:
        errors.append("reviewed macOS target inventory changed")

    identities: list[tuple[str, str, str, str]] = []
    projected_licenses: list[dict[str, str]] = []
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict) or set(dependency) != {
            "ecosystem",
            "install_script",
            "integrity",
            "license",
            "name",
            "roles",
            "source",
            "targets",
            "version",
        }:
            errors.append(f"dependency record {index} is not closed")
            continue
        ecosystem = dependency.get("ecosystem")
        name = dependency.get("name")
        version = dependency.get("version")
        source = dependency.get("source")
        license_value = dependency.get("license")
        roles = dependency.get("roles")
        targets = dependency.get("targets")
        integrity = dependency.get("integrity")
        if (
            ecosystem not in {"cargo", "npm"}
            or not all(
                isinstance(value, str) and value
                for value in (name, version, source, license_value)
            )
            or not isinstance(dependency.get("install_script"), bool)
            or not isinstance(roles, list)
            or roles != sorted(set(roles))
            or not roles
            or not set(roles) <= {"build", "runtime"}
            or not isinstance(targets, list)
            or targets != sorted(set(targets))
            or not set(targets) <= {"aarch64-apple-darwin", "x86_64-apple-darwin"}
            or ecosystem == "cargo"
            and not targets
        ):
            errors.append(f"dependency record {index} is invalid")
            continue
        assert isinstance(source, str)
        if source.startswith("path:"):
            relative = source.removeprefix("path:")
            if integrity is not None or _safe_relative(root, relative) is None:
                errors.append(f"path dependency record {index} is invalid")
        elif ecosystem == "cargo":
            if (
                source != "registry+https://github.com/rust-lang/crates.io-index"
                or not isinstance(integrity, str)
                or re.fullmatch(r"[0-9a-f]{64}", integrity) is None
            ):
                errors.append(f"Cargo dependency record {index} is not pinned")
        elif (
            not source.startswith("https://registry.npmjs.org/")
            or not isinstance(integrity, str)
            or re.fullmatch(
                r"(?:sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}"
                r"(?: (?:sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2})*",
                integrity,
            )
            is None
        ):
            errors.append(f"npm dependency record {index} is not pinned")
        identity = (ecosystem, name, version, source)
        identities.append(identity)  # type: ignore[arg-type]
        projected_licenses.append(
            {
                "ecosystem": ecosystem,
                "license": license_value,
                "name": name,
                "source": source,
                "version": version,
            }
        )
    if identities != sorted(set(identities)):
        errors.append("dependency identities are not sorted and unique")
    if licenses != projected_licenses:
        errors.append("license inventory is not the exact dependency projection")

    for relative, expected in input_hashes.items():
        candidate = _safe_relative(root, relative)
        if (
            candidate is None
            or not isinstance(expected, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
            or candidate.is_symlink()
            or not candidate.is_file()
        ):
            errors.append(f"manifest input hash record is invalid: {relative}")
        elif p09_supply_chain_smoke.sha256_file(candidate) != expected:
            errors.append(f"manifest input hash drift: {relative}")
    if not input_hashes:
        errors.append("manifest input hash inventory is empty")

    if (
        set(models)
        != {
            "artifacts",
            "local_providers",
            "prohibitions",
            "remote_model_code_allowed",
            "remote_services",
            "root",
        }
        or model_artifacts
        or models.get("local_providers")
        != {"segmentation": {"availability": "unavailable"}}
        or models.get("prohibitions") != p09_supply_chain_smoke.PROHIBITIONS
        or models.get("remote_model_code_allowed") is not False
        or models.get("remote_services") != p09_supply_chain_smoke.REMOTE_SERVICES
        or models.get("root") != "assets/model-artifacts"
    ):
        errors.append(
            "model inventory does not prove empty/unavailable prohibited-code truth"
        )
    model_root = root / "assets/model-artifacts"
    try:
        model_root_drift = model_root.is_symlink() or (
            model_root.exists() and any(model_root.rglob("*"))
        )
    except OSError:
        model_root_drift = True
    if model_root_drift:
        errors.append("empty model inventory does not match the repository model root")

    metadata = _json_object(
        _read(root / "release/wardrobe-build-metadata-v1.json") or b""
    )
    if manifest.get("release") != metadata:
        errors.append("manifest release identity differs from canonical build metadata")
    return ManifestValidation(
        tuple(dict.fromkeys(errors)),
        _sha256(data),
        len(dependencies),
        len(licenses),
        len(input_hashes),
        len(model_artifacts),
    )


def validate_bundle(root: Path, manifest: ManifestValidation) -> BundleValidation:
    bundle = root / p09_supply_chain_smoke.BUNDLE_RELATIVE
    path = bundle / p09_supply_chain_smoke.BUNDLE_MANIFEST_RELATIVE
    generated = _read(root / MANIFEST_RELATIVE)
    bundled = _read(path)
    errors: list[str] = []
    if generated is None or bundled is None:
        errors.append("generated or bundled supply-chain manifest is unreadable")
    elif generated != bundled:
        errors.append(
            "bundled supply-chain manifest differs from canonical generated bytes"
        )
    elif _sha256(bundled) != manifest.sha256:
        errors.append("bundled supply-chain manifest hash is inconsistent")
    try:
        bundle_sha256, file_count = p09_supply_chain_smoke.hash_and_scan_bundle(bundle)
    except (OSError, p09_supply_chain_smoke.SmokeFailure) as error:
        errors.append(f"application bundle supply-chain scan failed: {error}")
        bundle_sha256, file_count = "", 0
    return BundleValidation(
        tuple(dict.fromkeys(errors)),
        bundle_sha256,
        file_count,
        _sha256(bundled) if bundled is not None else "",
    )


def validate_smoke(
    path: Path,
    manifest: ManifestValidation,
    bundle: BundleValidation,
) -> SmokeValidation:
    data = _read(path, MAX_ARTIFACT_BYTES)
    if data is None:
        return SmokeValidation(
            ("P09 supply-chain smoke report is missing or oversized",),
            "",
            "",
            "",
        )
    report = _json_object(data)
    expected_fields = {
        "schema_version",
        "status",
        "platform",
        "network_control_passed",
        "network_sandbox_enforced",
        "sandbox_profile_sha256",
        "supply_check_passed",
        "installed_tree_check_passed",
        "startup_gate_verified",
        "canonical_manifest_verified",
        "bundled_manifest_exact",
        "generated_manifest_sha256",
        "bundled_manifest_sha256",
        "bundle_sha256",
        "bundle_file_count",
        "dependency_count",
        "license_count",
        "model_artifact_count",
        "local_segmentation_availability",
        "remote_model_code_allowed",
        "private_credentials_used",
        "developer_id_signed",
        "notarized",
        "clean_machine_certified",
        "acceptance_claim",
        "scope_limitation",
    }
    errors: list[str] = []
    if set(report) != expected_fields:
        errors.append("P09 supply-chain smoke report schema is not strict and complete")
    if (
        report.get("schema_version") != 1
        or report.get("status") != "pass"
        or report.get("platform") != "macos"
    ):
        errors.append("P09 supply-chain smoke report identity is invalid")
    for field in SMOKE_REQUIRED_TRUE:
        if report.get(field) is not True:
            errors.append(f"P09 supply-chain smoke did not establish {field}")
    for field in SMOKE_REQUIRED_FALSE:
        if report.get(field) is not False:
            errors.append(f"P09 supply-chain smoke overstated {field}")
    if (
        report.get("generated_manifest_sha256") != manifest.sha256
        or report.get("bundled_manifest_sha256") != manifest.sha256
        or report.get("bundle_sha256") != bundle.sha256
        or report.get("bundle_file_count") != bundle.file_count
        or report.get("dependency_count") != manifest.dependency_count
        or report.get("license_count") != manifest.license_count
        or report.get("model_artifact_count") != 0
        or report.get("local_segmentation_availability") != "unavailable"
    ):
        errors.append(
            "P09 supply-chain smoke evidence differs from current release state"
        )
    expected_sandbox_hash = _sha256(p09_supply_chain_smoke.SANDBOX_PROFILE.encode())
    if report.get("sandbox_profile_sha256") != expected_sandbox_hash:
        errors.append("P09 supply-chain smoke used an unexpected sandbox profile")
    if report.get("acceptance_claim") != "focused_supply_chain_packet_passed":
        errors.append("P09 supply-chain smoke did not claim exactly the focused packet")
    limitation = report.get("scope_limitation")
    if (
        not isinstance(limitation, str)
        or len(limitation.encode()) > 256
        or "signing" not in limitation.lower()
        or "notarization" not in limitation.lower()
        or "clean-machine" not in limitation.lower()
    ):
        errors.append("P09 supply-chain smoke scope limitation is invalid")
    return SmokeValidation(
        tuple(dict.fromkeys(errors)),
        _sha256(data),
        report.get("bundle_sha256", ""),
        report.get("sandbox_profile_sha256", ""),
    )


def _command_summary(result: CommandResult) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "output_sha256": result.output_sha256,
        "output_bytes": result.output_bytes,
        "duration_ms": result.duration_ms,
        "timed_out": result.timed_out,
        "output_limit_exceeded": result.output_limit_exceeded,
        "launch_failed": result.launch_failed,
    }


def _command_error(check: CommandCheck, result: CommandResult) -> str | None:
    if (
        result.returncode != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.launch_failed
    ):
        return f"{check.name} failed or exceeded evaluator bounds"
    if check.output_markers:
        output = result.captured_output.decode(errors="replace")
        missing = [marker for marker in check.output_markers if marker not in output]
        if missing or (check.command[0] == "cargo" and "test result: ok" not in output):
            return f"{check.name} did not execute the required focused tests"
    return None


def _write(path: Path, value: dict[str, Any]) -> None:
    data = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P09 supply-chain evaluator artifact exceeds size bound")
    write_atomic_json(path, value)


def _remove_outputs(evidence_dir: Path) -> None:
    for requirement in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
    for name in (DIAGNOSTICS_NAME, SMOKE_NAME):
        (evidence_dir / name).unlink(missing_ok=True)


def clean_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "ALL_PROXY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "HARNESS_EVIDENCE_DIR",
        "HARNESS_RUN_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NPM_TOKEN",
        "NODE_AUTH_TOKEN",
        "OPENAI_API_KEY",
        "TAURI_SIGNING_PRIVATE_KEY",
        "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
        "http_proxy",
        "https_proxy",
        "npm_config_proxy",
        "npm_config_https_proxy",
        "npm_config_registry",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "npm_config_offline": "true",
            "npm_config_ignore_scripts": "true",
        }
    )
    return environment


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    if not (selected & TRIGGER_REQUIREMENT_IDS):
        return 0
    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_outputs(evidence_dir)
    recorded_at = utc_now()
    packet = validate_packet(root)
    source = validate_source(root)
    manifest = validate_generated_manifest(root)
    bundle = BundleValidation((), "", 0, "")
    smoke = SmokeValidation((), "", "", "")
    failures = [*packet.errors, *source.errors, *manifest.errors]
    checks: dict[str, dict[str, Any]] = {}
    environment = clean_environment()

    if selected & TRIGGER_REQUIREMENT_IDS != TRIGGER_REQUIREMENT_IDS:
        failures.append("selected P09 supply-chain requirement ID is incomplete")
    if not failures:
        for check in COMMAND_CHECKS:
            result = run_bounded_command(
                list(check.command),
                cwd=root,
                env=environment,
                timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                capture_output=bool(check.output_markers),
            )
            checks[check.name] = _command_summary(result)
            error = _command_error(check, result)
            if error:
                failures.append(error)
                break

    if not failures:
        manifest = validate_generated_manifest(root)
        failures.extend(manifest.errors)
    if not failures:
        bundle = validate_bundle(root, manifest)
        failures.extend(bundle.errors)

    smoke_path = evidence_dir / SMOKE_NAME
    if not failures:
        result = run_bounded_command(
            [
                sys.executable,
                "tools/p09_supply_chain_smoke.py",
                "--repo",
                str(root),
                "--report",
                str(smoke_path),
            ],
            cwd=root,
            env=environment,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        )
        checks["denied_network_macos_smoke"] = _command_summary(result)
        if (
            result.returncode != 0
            or result.timed_out
            or result.output_limit_exceeded
            or result.launch_failed
        ):
            failures.append("denied_network_macos_smoke failed")
        else:
            smoke = validate_smoke(smoke_path, manifest, bundle)
            failures.extend(smoke.errors)

    if not failures:
        result = run_bounded_command(
            list(PHASE_REGRESSION.command),
            cwd=root,
            env=environment,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        )
        checks[PHASE_REGRESSION.name] = _command_summary(result)
        error = _command_error(PHASE_REGRESSION, result)
        if error:
            failures.append(error)

    diagnostics = {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "recorded_at": recorded_at,
        "selected_requirement_ids": sorted(selected & TRIGGER_REQUIREMENT_IDS),
        "failures": list(dict.fromkeys(failures)),
        "packet_sha256": packet.sha256,
        "packet_hashes": packet.hashes,
        "source_sha256": source.sha256,
        "source_hashes": source.hashes,
        "source_file_count": source.file_count,
        "manifest_sha256": manifest.sha256,
        "dependency_count": manifest.dependency_count,
        "license_count": manifest.license_count,
        "input_hash_count": manifest.input_hash_count,
        "model_artifact_count": manifest.model_artifact_count,
        "bundle_sha256": bundle.sha256,
        "bundle_file_count": bundle.file_count,
        "smoke_sha256": smoke.sha256,
        "sandbox_profile_sha256": smoke.sandbox_profile_sha256,
        "checks": checks,
        "remote_model_code_allowed": False,
        "local_segmentation_availability": "unavailable",
        "developer_id_signed": False,
        "notarized": False,
        "clean_machine_certified": False,
        "focused_packet_passed": not failures,
        "pass_evidence_written": not failures,
    }
    if failures:
        smoke_path.unlink(missing_ok=True)
        _write(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    verification_sha256 = _sha256(
        json.dumps(
            {
                "packet_sha256": packet.sha256,
                "source_sha256": source.sha256,
                "manifest_sha256": manifest.sha256,
                "bundle_sha256": bundle.sha256,
                "smoke_sha256": smoke.sha256,
                "checks": checks,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    for requirement in sorted(REQUIREMENT_IDS):
        _write(
            evidence_dir / f"{requirement}.json",
            {
                "schema_version": 1,
                "requirement_id": requirement,
                "status": "pass",
                "test": "p09_supply_chain::focused_release_packet",
                "recorded_at": recorded_at,
                "details": {
                    "verification_sha256": verification_sha256,
                    "public_summary": {
                        "profile": "personal_mvp",
                        "packet_sha256": packet.sha256,
                        "manifest_sha256": manifest.sha256,
                        "bundle_sha256": bundle.sha256,
                        "checks_passed": len(checks),
                        "dependency_count": manifest.dependency_count,
                        "license_count": manifest.license_count,
                        "model_artifact_count": 0,
                        "local_segmentation_availability": "unavailable",
                        "remote_model_code_allowed": False,
                        "network_sandbox_enforced": True,
                        "developer_id_signed": False,
                        "notarized": False,
                        "clean_machine_certified": False,
                        "acceptance_claim": "focused_supply_chain_packet_passed",
                        "scope_limitation": (
                            "Signing, notarization, clean-machine certification, "
                            "and whole-bundle authenticity are outside this packet."
                        ),
                    },
                },
            },
        )
    _write(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    return 0
