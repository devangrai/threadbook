"""Fail-closed evaluator for the approved P09 update-gate packet."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

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
TRIGGER_REQUIREMENT_IDS = frozenset({"P09-UPG-001"})
REQUIREMENT_IDS = SYSTEM_REQUIREMENT_IDS | TRIGGER_REQUIREMENT_IDS
DEFERRED_REQUIREMENT_IDS = TRIGGER_REQUIREMENT_IDS

RUN_ID = "20260716T035356Z-e4f09fe2"
PACKET_DIR = f"artifacts/harness/P09/{RUN_ID}"
DIAGNOSTICS_NAME = "p09-update-evaluator.json"
SMOKE_NAME = "p09-update-smoke.json"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024
MAX_BUNDLE_FILES = 4096
MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 20 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P09-hardening.md": (
        "b88c11b3f97bf7936f19cc6f6e187268eeb0c6a6c11f12de17ed2edf36455846"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "ef924b2a3d30014b5f4492c8e1aad307bb9fe958c87e8cdda6f749de8849b4da"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "37fba8c1e4c36bb6c646b0b41a50ce8fe7afe1467cede7b41ad9d773461bac82"
    ),
    f"{PACKET_DIR}/review.md": (
        "5877d58498cc6554d1f3a7d5f9a7df77fed23bf83f7d850d5fdf99033107db56"
    ),
}

SOURCE_FILES = (
    "Cargo.lock",
    "crates/wardrobe-core/src/lib.rs",
    "crates/wardrobe-core/src/update.rs",
    "crates/wardrobe-core/tests/update_contracts.rs",
    "release/wardrobe-build-metadata-v1.json",
    "crates/wardrobe-platform/build.rs",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/examples/p09_update_smoke.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/paths.rs",
    "crates/wardrobe-platform/src/update_package.rs",
    "crates/wardrobe-platform/tests/build_metadata.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "src-tauri/src/lib.rs",
)

COMMAND_CHECKS = (
    (
        "current_packaged_build",
        ("make", "build"),
    ),
    (
        "core_update_contracts",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-core",
            "--offline",
            "--test",
            "update_contracts",
        ),
    ),
    (
        "platform_update_package",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "update_package",
            "--lib",
            "--",
            "--test-threads=1",
        ),
    ),
    (
        "platform_build_metadata",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--test",
            "build_metadata",
        ),
    ),
    (
        "phase_boundary_regression",
        ("make", "test"),
    ),
)


@dataclass(frozen=True)
class Validation:
    errors: tuple[str, ...]
    sha256: str
    count: int


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read(path: Path, limit: int = MAX_SOURCE_BYTES) -> bytes | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def _aggregate(contents: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name, data in sorted(contents.items()):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def validate_packet(root: Path) -> Validation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    for relative, expected in EXPECTED_PACKET_HASHES.items():
        data = _read(root / relative)
        if data is None:
            errors.append(f"packet file unreadable or oversized: {relative}")
            continue
        contents[relative] = data
        if hashlib.sha256(data).hexdigest() != expected:
            errors.append(f"packet hash mismatch: {relative}")
    return Validation(tuple(errors), _aggregate(contents), len(contents))


def validate_source(root: Path) -> Validation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    texts: dict[str, str] = {}
    for relative in SOURCE_FILES:
        data = _read(root / relative)
        if data is None:
            errors.append(f"source file unreadable or oversized: {relative}")
            continue
        contents[relative] = data
        try:
            texts[relative] = data.decode()
        except UnicodeDecodeError:
            errors.append(f"source file is not UTF-8: {relative}")

    joined = "\n".join(texts.values())
    for term in (
        'ring = "=0.17.14"',
        "WardrobeUpdateManifestV1",
        "UpdatePackageStager",
        "production_disabled",
        "SQLITE_OPEN_READ_ONLY",
        "immutable",
        "StoreLock",
        "acquire_shared",
        "runtime_compatibility_changed",
        "O_NOFOLLOW",
        "ED25519",
        "SignatureInvalid",
        "update_release_sequence_equivocation",
        "PublicationOutcomeUnknown",
        "package.wdupdate",
        "wardrobe_build_metadata_v1.rs",
        "INSTALLED_UPDATE_RELEASE_SEQUENCE_V1",
        "database_lineage_unchanged",
        "deferred_not_passed",
    ):
        if term not in joined:
            errors.append(f"required update boundary missing: {term}")

    desktop_registration = (
        texts.get("src-tauri/build.rs", "")
        + texts.get("src-tauri/capabilities/main.json", "")
        + texts.get("src-tauri/src/lib.rs", "")
    )
    for forbidden in (
        "verify_and_stage_update_v1",
        "install_update_v1",
        "tauri_plugin_updater",
        "Command::new(",
    ):
        if forbidden in desktop_registration:
            errors.append(f"disabled update capability is exposed: {forbidden}")

    platform = texts.get("crates/wardrobe-platform/src/update_package.rs", "")
    production_platform = platform.split("#[cfg(test)]", 1)[0]
    for forbidden in ("reqwest::", "std::process::", "Database::open(", "BackupRepository"):
        if forbidden in production_platform:
            errors.append(f"update stager reaches forbidden capability: {forbidden}")

    return Validation(tuple(errors), _aggregate(contents), len(contents))


def validate_bundle(root: Path) -> Validation:
    bundle = root / "target/release/bundle/macos/Wardrobe.app"
    if not bundle.is_dir():
        return Validation(("packaged application missing",), "", 0)
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    count = 0
    total_bytes = 0
    for path in sorted(bundle.rglob("*")):
        metadata = path.lstat()
        if path.is_symlink():
            errors.append(f"symlink in packaged application: {path.relative_to(bundle)}")
            continue
        if not stat.S_ISREG(metadata.st_mode):
            continue
        count += 1
        if count > MAX_BUNDLE_FILES:
            errors.append("packaged application file count exceeds bound")
            break
        relative = str(path.relative_to(bundle))
        total_bytes += metadata.st_size
        if total_bytes > MAX_BUNDLE_BYTES:
            errors.append("packaged application bytes exceed bound")
            break
        if path.suffix.lower() in {".pem", ".pk8", ".key"}:
            errors.append(f"private-key-shaped bundle entry: {relative}")
        digest = hashlib.sha256()
        marker_window = b""
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                scanned = marker_window + chunk
                if b"-----BEGIN PRIVATE KEY-----" in scanned:
                    errors.append(f"private key marker in bundle: {relative}")
                marker_window = scanned[-32:]
        contents[relative] = digest.digest()
    return Validation(tuple(errors), _aggregate(contents), count)


def validate_smoke(path: Path) -> tuple[list[str], dict[str, Any]]:
    data = _read(path, MAX_ARTIFACT_BYTES)
    if data is None:
        return ["update smoke report missing or oversized"], {}
    try:
        report = json.loads(data)
    except json.JSONDecodeError:
        return ["update smoke report is not JSON"], {}
    required_true = (
        "real_ed25519",
        "canonical_manifest_verified",
        "valid_package_staged",
        "exact_signed_package_retained",
        "staged_package_reverified",
        "artifact_tamper_rejected",
        "manifest_tamper_rejected",
        "noncanonical_manifest_rejected",
        "database_unchanged",
        "database_lineage_unchanged",
        "live_data_tree_unchanged",
        "production_keyring_empty",
    )
    errors = [
        f"update smoke did not prove {field}"
        for field in required_true
        if report.get(field) is not True
    ]
    if report.get("schema_version") != 1 or report.get("status") != "pass":
        errors.append("update smoke status invalid")
    if report.get("network_sandbox_enforced") is not True:
        errors.append("update smoke did not run under denied-network sandbox")
    if report.get("install_feature_enabled") is not False:
        errors.append("update smoke enabled deferred installer")
    if report.get("acceptance_claim") != "deferred_not_passed":
        errors.append("update smoke overstated installation acceptance")
    return errors, report


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


def _write(path: Path, value: dict[str, Any]) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("update evaluator artifact exceeds bound")
    write_atomic_json(path, value)


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    if not (selected & TRIGGER_REQUIREMENT_IDS):
        return 0
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for requirement in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
    for name in (DIAGNOSTICS_NAME, SMOKE_NAME):
        (evidence_dir / name).unlink(missing_ok=True)

    packet = validate_packet(root)
    source = validate_source(root)
    bundle = Validation((), "", 0)
    failures = [*packet.errors, *source.errors]
    checks: dict[str, dict[str, Any]] = {}
    environment = os.environ.copy()
    for name in (
        "HARNESS_RUN_DIR",
        "HARNESS_EVIDENCE_DIR",
        "OPENAI_API_KEY",
        "TAURI_SIGNING_PRIVATE_KEY",
        "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
    ):
        environment.pop(name, None)

    if not failures:
        for name, command in COMMAND_CHECKS:
            result = run_bounded_command(
                list(command),
                cwd=root,
                env=environment,
                timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            )
            checks[name] = _command_summary(result)
            if (
                result.returncode != 0
                or result.timed_out
                or result.output_limit_exceeded
                or result.launch_failed
            ):
                failures.append(f"{name} failed")
                break
    if not failures:
        bundle = validate_bundle(root)
        failures.extend(bundle.errors)

    smoke_path = evidence_dir / SMOKE_NAME
    smoke_report: dict[str, Any] = {}
    if not failures:
        smoke_environment = environment.copy()
        smoke_environment["P09_UPDATE_SMOKE_REPORT"] = str(smoke_path)
        smoke_environment["P09_UPDATE_NETWORK_SANDBOX"] = "1"
        result = run_bounded_command(
            [
                "/usr/bin/sandbox-exec",
                "-p",
                "(version 1)(allow default)(deny network*)",
                "cargo",
                "run",
                "-p",
                "wardrobe-platform",
                "--offline",
                "--example",
                "p09_update_smoke",
                "--quiet",
            ],
            cwd=root,
            env=smoke_environment,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            capture_output=True,
        )
        checks["phase_update_smoke"] = _command_summary(result)
        if (
            result.returncode != 0
            or result.timed_out
            or result.output_limit_exceeded
            or result.launch_failed
        ):
            failures.append("phase_update_smoke failed")
        else:
            smoke_errors, smoke_report = validate_smoke(smoke_path)
            failures.extend(smoke_errors)

    recorded_at = utc_now()
    diagnostics = {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "recorded_at": recorded_at,
        "failures": list(dict.fromkeys(failures)),
        "packet_sha256": packet.sha256,
        "source_sha256": source.sha256,
        "bundle_sha256": bundle.sha256,
        "checks": checks,
        "install_feature_enabled": False,
        "developer_id_signed": False,
        "notarized": False,
        "clean_machine_certified": False,
        "acceptance_claim": "deferred_not_passed",
    }
    if failures:
        smoke_path.unlink(missing_ok=True)
        _write(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    for requirement in sorted(REQUIREMENT_IDS):
        deferred = requirement in DEFERRED_REQUIREMENT_IDS
        public_summary: dict[str, Any] = {
            "packet_sha256": packet.sha256,
            "source_sha256": source.sha256,
            "bundle_sha256": bundle.sha256,
            "source_file_count": source.count,
            "bundle_file_count": bundle.count,
            "checks_passed": len(checks),
            "real_ed25519": smoke_report["real_ed25519"],
            "production_keyring_empty": smoke_report["production_keyring_empty"],
        }
        if deferred:
            public_summary.update(
                {
                    "feature_enabled": False,
                    "acceptance_claim": "deferred_not_passed",
                    "deferred_limitation": (
                        "Genuine two-version installation and pre-mutation "
                        "reverification are not implemented."
                    ),
                }
            )
        else:
            public_summary.update(
                {
                    "feature_enabled": True,
                    "acceptance_claim": "focused_local_requirement_passed",
                }
            )
        _write(
            evidence_dir / f"{requirement}.json",
            {
                "schema_version": 1,
                "requirement_id": requirement,
                "status": "deferred" if deferred else "pass",
                "test": (
                    "p09_update::deferred_installer"
                    if deferred
                    else "p09_update::verified_update_gate_regression"
                ),
                "recorded_at": recorded_at,
                "details": {"public_summary": public_summary},
            },
        )
    _write(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    return 0
