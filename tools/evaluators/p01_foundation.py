"""Fail-closed personal-MVP evaluator for the P01 platform foundation."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import signal
import subprocess
import time
import tomllib
from typing import Any


REQUIREMENT_IDS = frozenset(
    {
        "P01-ARC-001",
        "P01-DAT-001",
        "P01-DBS-001",
        "P01-JOB-001",
        "P01-JOB-002",
        "P01-SEC-001",
        "P01-OBS-001",
        "P01-OFF-001",
    }
)

MAX_OUTPUT_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 10 * 60
DIAGNOSTICS_NAME = "p01-foundation-diagnostics.json"


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]
    requirements: frozenset[str]


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output_sha256: str
    output_bytes: int
    duration_ms: int
    output_limit_exceeded: bool = False
    timed_out: bool = False
    launch_failed: bool = False


@dataclass(frozen=True)
class SourceValidation:
    errors: dict[str, tuple[str, ...]]
    source_sha256: str
    migration_sha256: str | None
    security_framework_wired: bool
    plaintext_fallback_present: bool


COMMAND_CHECKS = (
    CommandCheck(
        "core_tests",
        ("cargo", "test", "-p", "wardrobe-core"),
        frozenset({"P01-ARC-001", "P01-SEC-001"}),
    ),
    CommandCheck(
        "platform_tests",
        ("cargo", "test", "-p", "wardrobe-platform"),
        frozenset(
            {
                "P01-DAT-001",
                "P01-DBS-001",
                "P01-JOB-001",
                "P01-JOB-002",
                "P01-SEC-001",
                "P01-OBS-001",
                "P01-OFF-001",
            }
        ),
    ),
    CommandCheck(
        "desktop_tests",
        ("cargo", "test", "-p", "wardrobe-desktop"),
        frozenset({"P01-ARC-001", "P01-SEC-001", "P01-OFF-001"}),
    ),
    CommandCheck(
        "ui_tests",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "--run",
        ),
        frozenset({"P01-ARC-001", "P01-JOB-002", "P01-OFF-001"}),
    ),
    CommandCheck(
        "ui_build",
        ("npm", "--workspace", "@wardrobe/desktop-ui", "run", "build"),
        frozenset({"P01-OFF-001"}),
    ),
)

LIVE_KEYCHAIN_CHECK = CommandCheck(
    "live_keychain",
    (
        "cargo",
        "test",
        "-p",
        "wardrobe-platform",
        "real_keychain_round_trip",
        "--",
        "--ignored",
    ),
    frozenset({"P01-SEC-001"}),
)

SOURCE_FILES = (
    "Cargo.toml",
    "package.json",
    "crates/wardrobe-core/Cargo.toml",
    "crates/wardrobe-core/src/bin/generate-bindings.rs",
    "crates/wardrobe-core/src/contracts.rs",
    "crates/wardrobe-core/src/service.rs",
    "apps/desktop-ui/src/generated/contracts.ts",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/src/blob.rs",
    "crates/wardrobe-platform/src/credential.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/diagnostics.rs",
    "crates/wardrobe-platform/src/worker.rs",
    "crates/wardrobe-platform/migrations/0001_foundation.sql",
    "crates/wardrobe-platform/migrations/0001_foundation.sha256",
    "src-tauri/Cargo.toml",
    "src-tauri/src/lib.rs",
    "src-tauri/capabilities/main.json",
    "src-tauri/tauri.conf.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/src/App.tsx",
    "apps/desktop-ui/src/foundation-bridge.ts",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        if process.poll() is None:
            process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=3)


def run_bounded_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
) -> CommandResult:
    """Run a command while retaining only bounded, non-content metadata."""
    digest = hashlib.sha256()
    output_bytes = 0
    timed_out = False
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        return CommandResult(
            returncode=127,
            output_sha256=hashlib.sha256(b"").hexdigest(),
            output_bytes=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            launch_failed=True,
        )

    assert process.stdout is not None
    deadline = started + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 and process.poll() is None:
            timed_out = True
            _terminate(process)
        readable, _, _ = select.select(
            [process.stdout],
            [],
            [],
            0 if process.poll() is not None else min(0.25, max(remaining, 0)),
        )
        if readable:
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if chunk:
                output_bytes += len(chunk)
                digest.update(chunk)
                continue
        if process.poll() is not None:
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if chunk:
                output_bytes += len(chunk)
                digest.update(chunk)
                continue
            break
    process.stdout.close()
    return CommandResult(
        returncode=process.returncode,
        output_sha256=digest.hexdigest(),
        output_bytes=output_bytes,
        duration_ms=int((time.monotonic() - started) * 1000),
        output_limit_exceeded=output_bytes > MAX_OUTPUT_BYTES,
        timed_out=timed_out,
    )


def _read_sources(root: Path) -> tuple[dict[str, bytes], list[str], str]:
    sources: dict[str, bytes] = {}
    errors: list[str] = []
    digest = hashlib.sha256()
    for relative in SOURCE_FILES:
        path = root / relative
        try:
            data = path.read_bytes()
        except OSError:
            errors.append(f"required production file is unreadable: {relative}")
            continue
        if len(data) > MAX_SOURCE_BYTES:
            errors.append(f"required production file exceeds size bound: {relative}")
            continue
        sources[relative] = data
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return sources, errors, digest.hexdigest()


def _text(sources: dict[str, bytes], relative: str) -> str:
    try:
        return sources[relative].decode("utf-8")
    except (KeyError, UnicodeDecodeError):
        return ""


def _add(
    errors: dict[str, list[str]],
    requirements: set[str] | frozenset[str],
    condition: bool,
    message: str,
) -> None:
    if condition:
        return
    for requirement in requirements:
        errors[requirement].append(message)


def validate_source_contract(root: Path) -> SourceValidation:
    sources, read_errors, source_sha256 = _read_sources(root)
    errors = {requirement: [] for requirement in REQUIREMENT_IDS}
    for error in read_errors:
        for requirement in REQUIREMENT_IDS:
            errors[requirement].append(error)

    def parsed_toml(relative: str) -> dict[str, Any]:
        try:
            return tomllib.loads(_text(sources, relative))
        except (tomllib.TOMLDecodeError, ValueError):
            return {}

    def parsed_json(relative: str) -> dict[str, Any]:
        try:
            value = json.loads(_text(sources, relative))
        except (json.JSONDecodeError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    workspace = parsed_toml("Cargo.toml")
    members = workspace.get("workspace", {}).get("members", [])
    _add(
        errors,
        REQUIREMENT_IDS,
        isinstance(members, list)
        and {"crates/wardrobe-core", "crates/wardrobe-platform", "src-tauri"}
        <= set(members),
        "workspace does not compose the core, platform, and desktop crates",
    )

    core_manifest = parsed_toml("crates/wardrobe-core/Cargo.toml")
    core_dependencies = core_manifest.get("dependencies", {})
    contracts = _text(sources, "crates/wardrobe-core/src/contracts.rs")
    service = _text(sources, "crates/wardrobe-core/src/service.rs")
    generator = _text(
        sources, "crates/wardrobe-core/src/bin/generate-bindings.rs"
    )
    generated = _text(
        sources, "apps/desktop-ui/src/generated/contracts.ts"
    )
    _add(
        errors,
        {"P01-ARC-001"},
        "ts-rs" in core_dependencies
        and "schema_version" in contracts
        and "generate" in generator.lower()
        and "schema_version" in generated,
        "typed command bindings are not generated from the Rust contract",
    )
    for command in (
        "get_foundation_snapshot_v1",
        "run_storage_check_v1",
        "save_credential_v1",
        "delete_credential_v1",
    ):
        _add(
            errors,
            {"P01-ARC-001"},
            command in service,
            f"typed Rust contract is missing {command}",
        )

    platform_manifest = parsed_toml("crates/wardrobe-platform/Cargo.toml")
    mac_dependencies = (
        platform_manifest.get("target", {})
        .get("cfg(target_os = \"macos\")", {})
        .get("dependencies", {})
    )
    credential = _text(
        sources, "crates/wardrobe-platform/src/credential.rs"
    )
    credential_production = credential.split("#[cfg(test)]", 1)[0]
    security_framework_wired = (
        "security-framework" in mac_dependencies
        and "security-framework-sys" in mac_dependencies
        and "MacOsKeychain" in credential_production
        and "set_generic_password" in credential_production
        and "get_generic_password" in credential_production
        and "delete_generic_password" in credential_production
        and "com.devrai.wardrobe.credentials" in credential_production
    )
    fallback_markers = (
        "PlaintextCredential",
        "FileCredential",
        "InMemoryCredential",
        "write_secret",
        "secret_file",
    )
    plaintext_fallback_present = any(
        marker in credential_production for marker in fallback_markers
    ) or "std::fs" in credential_production
    _add(
        errors,
        {"P01-SEC-001"},
        security_framework_wired,
        "production credential adapter is not wired to macOS Security Framework",
    )
    _add(
        errors,
        {"P01-SEC-001"},
        not plaintext_fallback_present,
        "production credential adapter contains a plaintext fallback",
    )

    blob = _text(sources, "crates/wardrobe-platform/src/blob.rs")
    _add(
        errors,
        {"P01-DAT-001"},
        all(
            marker in blob
            for marker in (
                "Sha256",
                "create_new",
                "O_NOFOLLOW",
                "hard_link",
                "remove_file",
                "sync_all",
            )
        ),
        "blob adapter lacks verified no-follow atomic promotion",
    )

    migration_path = (
        "crates/wardrobe-platform/migrations/0001_foundation.sql"
    )
    checksum_path = (
        "crates/wardrobe-platform/migrations/0001_foundation.sha256"
    )
    migration_bytes = sources.get(migration_path)
    migration_sha256 = (
        hashlib.sha256(migration_bytes).hexdigest()
        if migration_bytes is not None
        else None
    )
    checksum = _text(sources, checksum_path).strip()
    database = _text(sources, "crates/wardrobe-platform/src/database.rs")
    _add(
        errors,
        {"P01-DBS-001"},
        migration_sha256 is not None
        and checksum == migration_sha256
        and len(checksum) == 64,
        "migration checksum does not match the checked-in SQL bytes",
    )
    _add(
        errors,
        {"P01-DBS-001"},
        all(
            marker in database
            for marker in (
                "TransactionBehavior::Immediate",
                "include_str!(\"../migrations/0001_foundation.sql\")",
                "include_str!(\"../migrations/0001_foundation.sha256\")",
                "Backup",
                "integrity_check",
                "foreign_key_check",
            )
        ),
        "database adapter lacks checksummed transactional migration wiring",
    )

    worker = _text(sources, "crates/wardrobe-platform/src/worker.rs")
    _add(
        errors,
        {"P01-JOB-001"},
        all(
            marker in database
            for marker in (
                "idempotency_key",
                "input_hash",
                "pipeline_version",
                "retry_limit",
                "lease_owner",
                "fence",
            )
        )
        and "PlatformJobQueue" in worker,
        "durable job persistence or worker composition is incomplete",
    )
    _add(
        errors,
        {"P01-JOB-002"},
        "job_failures" in database
        and "user_action_key" in database
        and "permanent_failure" in worker,
        "terminal job failures are not durably actionable",
    )

    diagnostics = _text(
        sources, "crates/wardrobe-platform/src/diagnostics.rs"
    )
    _add(
        errors,
        {"P01-OBS-001"},
        all(
            marker in diagnostics
            for marker in (
                "DiagnosticEventV1",
                "MAX_LINE_BYTES",
                "MAX_FILE_BYTES",
            )
        ),
        "diagnostics are not structured and bounded",
    )

    desktop_manifest = parsed_toml("src-tauri/Cargo.toml")
    desktop_dependencies = desktop_manifest.get("dependencies", {})
    desktop = _text(sources, "src-tauri/src/lib.rs")
    _add(
        errors,
        {"P01-ARC-001", "P01-SEC-001", "P01-OFF-001"},
        "wardrobe-core" in desktop_dependencies
        and "wardrobe-platform" in desktop_dependencies
        and "ApplicationService" in desktop
        and "MacOsKeychain" in desktop,
        "desktop does not compose the production core and platform adapters",
    )
    for command in (
        "get_foundation_snapshot_v1",
        "run_storage_check_v1",
        "save_credential_v1",
        "delete_credential_v1",
    ):
        _add(
            errors,
            {"P01-ARC-001", "P01-OFF-001"},
            command in desktop,
            f"desktop command wiring is missing {command}",
        )

    capability = parsed_json("src-tauri/capabilities/main.json")
    permissions = capability.get("permissions", [])
    expected_permissions = {
        "allow-get-foundation-snapshot-v1",
        "allow-run-storage-check-v1",
        "allow-save-credential-v1",
        "allow-delete-credential-v1",
    }
    _add(
        errors,
        {"P01-ARC-001", "P01-OFF-001"},
        isinstance(permissions, list)
        and expected_permissions <= set(permissions),
        "desktop capability does not allow exactly the foundation workflow",
    )

    tauri_config = parsed_json("src-tauri/tauri.conf.json")
    build_config = tauri_config.get("build", {})
    security_config = tauri_config.get("app", {}).get("security", {})
    _add(
        errors,
        {"P01-OFF-001"},
        build_config.get("frontendDist") == "../apps/desktop-ui/dist"
        and "object-src 'none'" in str(security_config.get("csp", "")),
        "offline desktop shell or restrictive content policy is missing",
    )

    root_package = parsed_json("package.json")
    ui_package = parsed_json("apps/desktop-ui/package.json")
    bridge = _text(sources, "apps/desktop-ui/src/foundation-bridge.ts")
    app = _text(sources, "apps/desktop-ui/src/App.tsx")
    _add(
        errors,
        {"P01-OFF-001"},
        "apps/desktop-ui" in root_package.get("workspaces", [])
        and {"build", "test"} <= set(ui_package.get("scripts", {}))
        and all(
            label in app for label in ("Wardrobe", "Activity", "Settings")
        )
        and all(
            command in bridge
            for command in (
                "get_foundation_snapshot_v1",
                "run_storage_check_v1",
                "save_credential_v1",
                "delete_credential_v1",
            )
        ),
        "offline UI does not expose the complete local foundation workflow",
    )

    return SourceValidation(
        errors={
            requirement: tuple(dict.fromkeys(messages))
            for requirement, messages in errors.items()
        },
        source_sha256=source_sha256,
        migration_sha256=migration_sha256,
        security_framework_wired=security_framework_wired,
        plaintext_fallback_present=plaintext_fallback_present,
    )


def _result_summary(result: CommandResult) -> dict[str, Any]:
    return {
        "exit_code": result.returncode,
        "output_sha256": result.output_sha256,
        "output_bytes": result.output_bytes,
        "duration_ms": result.duration_ms,
        "output_limit_exceeded": result.output_limit_exceeded,
        "timed_out": result.timed_out,
        "launch_failed": result.launch_failed,
    }


def _command_error(check: CommandCheck, result: CommandResult) -> str | None:
    if result.launch_failed:
        return f"{check.name} could not start"
    if result.timed_out:
        return f"{check.name} timed out"
    if result.output_limit_exceeded:
        return f"{check.name} exceeded the output bound"
    if result.returncode != 0:
        return f"{check.name} failed"
    return None


def _json_bytes(value: dict[str, Any]) -> bytes:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P01 evaluator artifact exceeds size limit")
    return data


def write_atomic_json(path: Path, value: dict[str, Any]) -> None:
    data = _json_bytes(value)
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short evaluator artifact write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _remove_stale_outputs(evidence_dir: Path) -> None:
    for requirement in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
    (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)


def _live_status(requested: bool, result: CommandResult | None) -> str:
    if not requested:
        return "deferred/not_run"
    if result is not None and _command_error(LIVE_KEYCHAIN_CHECK, result) is None:
        return "passed"
    return "deferred/attempted_not_proven"


def _public_summary(
    requirement: str,
    live_status: str,
    migration_sha256: str | None,
) -> dict[str, Any]:
    common: dict[str, Any] = {
        "profile": "personal_mvp",
        "verification": "focused production tests and source wiring passed",
    }
    if requirement == "P01-SEC-001":
        common.update(
            {
                "credential_store": "macos_security_framework",
                "plaintext_fallback": False,
                "keychain_live_test": live_status,
                "live_limitation_deferred": live_status != "passed",
            }
        )
    elif requirement == "P01-DBS-001":
        common["migration_sha256"] = migration_sha256
    elif requirement == "P01-OFF-001":
        common["smoke_scope"] = "platform_e2e_desktop_tests_ui_build"
        common["gui_network_certification"] = "deferred"
    return common


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(evidence_dir)
    source = validate_source_contract(root)
    environment = os.environ.copy()

    command_results: dict[str, CommandResult] = {}
    relevant_checks = [
        check for check in COMMAND_CHECKS if check.requirements & requested
    ]
    for check in relevant_checks:
        command_results[check.name] = run_bounded_command(
            list(check.command),
            cwd=root,
            env=environment,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        )

    live_requested = (
        "P01-SEC-001" in requested
        and environment.get("P01_LIVE_KEYCHAIN") == "1"
    )
    live_result: CommandResult | None = None
    if live_requested:
        live_result = run_bounded_command(
            list(LIVE_KEYCHAIN_CHECK.command),
            cwd=root,
            env=environment,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        )
    live_status = _live_status(live_requested, live_result)

    errors: list[str] = []
    requirement_checks: dict[str, list[str]] = {
        requirement: [] for requirement in sorted(requested)
    }
    for requirement in sorted(requested):
        for error in source.errors[requirement]:
            errors.append(f"{requirement}: {error}")
        requirement_checks[requirement].append("production_source_contract")
    for check in relevant_checks:
        result = command_results[check.name]
        error = _command_error(check, result)
        for requirement in sorted(check.requirements & requested):
            requirement_checks[requirement].append(check.name)
            if error:
                errors.append(f"{requirement}: {error}")
    errors = list(dict.fromkeys(errors))

    deferred_limitations: list[str] = []
    if "P01-SEC-001" in requested and live_status != "passed":
        deferred_limitations.append(
            "live login Keychain round trip was not proven in this session"
        )
    if "P01-OFF-001" in requested:
        deferred_limitations.append(
            "GUI network-denial and clean-machine certification are deferred"
        )

    diagnostics: dict[str, Any] = {
        "schema_version": 1,
        "phase": "P01",
        "status": "fail" if errors else "pass",
        "evaluated_at": utc_now(),
        "selected_requirement_ids": sorted(requested),
        "errors": errors,
        "deferred_limitations": deferred_limitations,
        "source_contract_sha256": source.source_sha256,
        "migration_sha256": source.migration_sha256,
        "commands": {
            name: _result_summary(result)
            for name, result in sorted(command_results.items())
        },
        "requirement_checks": requirement_checks,
        "security": {
            "security_framework_wired": source.security_framework_wired,
            "plaintext_fallback_present": source.plaintext_fallback_present,
            "keychain_live_test": live_status,
            "live_command": (
                _result_summary(live_result) if live_result is not None else None
            ),
        },
        "pass_evidence_written": not errors,
    }
    write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    if errors:
        for error in errors:
            print(f"P01 foundation evaluation: {error}")
        return 1

    payloads = {
        requirement: {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": "pass",
            "test": "p01_foundation::focused_production_verification",
            "recorded_at": diagnostics["evaluated_at"],
            "details": {
                "evaluator": "tools/evaluators/p01_foundation.py",
                "checks": requirement_checks[requirement],
                "public_summary": _public_summary(
                    requirement,
                    live_status,
                    source.migration_sha256,
                ),
            },
        }
        for requirement in sorted(requested)
    }
    for payload in payloads.values():
        _json_bytes(payload)
    for requirement, payload in payloads.items():
        write_atomic_json(evidence_dir / f"{requirement}.json", payload)
    print(
        "P01 foundation evaluation: all selected focused checks passed; "
        f"live Keychain check {live_status}"
    )
    return 0
