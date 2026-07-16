"""Fail-closed personal-MVP evaluator for P02 manual catalog and imports."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import subprocess
import time
import tomllib
from typing import Any


REQUIREMENT_IDS = frozenset(
    {
        "P02-IMP-001",
        "P02-IMP-002",
        "P02-IMP-003",
        "P02-CAT-001",
        "P02-CAT-002",
        "P02-REV-001",
        "P02-SAF-001",
        "P02-DEL-001",
    }
)

P02_COMMANDS = (
    "import_local_sources_v1",
    "refresh_import_roots_v1",
    "list_catalog_v1",
    "list_inbox_v1",
    "save_item_v1",
    "decide_evidence_v1",
    "merge_items_v1",
    "split_item_v1",
    "undo_decision_v1",
    "preview_deletion_v1",
    "list_deletion_plan_items_v1",
)

P02_COMMAND_REQUIREMENTS = {
    "import_local_sources_v1": frozenset(
        {"P02-IMP-001", "P02-IMP-002", "P02-IMP-003", "P02-SAF-001"}
    ),
    "refresh_import_roots_v1": frozenset(
        {"P02-IMP-001", "P02-IMP-002", "P02-IMP-003"}
    ),
    "list_catalog_v1": frozenset({"P02-CAT-001", "P02-CAT-002"}),
    "list_inbox_v1": frozenset({"P02-REV-001", "P02-SAF-001"}),
    "save_item_v1": frozenset({"P02-CAT-001"}),
    "decide_evidence_v1": frozenset({"P02-CAT-001", "P02-REV-001"}),
    "merge_items_v1": frozenset({"P02-CAT-002"}),
    "split_item_v1": frozenset({"P02-CAT-002"}),
    "undo_decision_v1": frozenset({"P02-CAT-002"}),
    "preview_deletion_v1": frozenset({"P02-DEL-001"}),
    "list_deletion_plan_items_v1": frozenset({"P02-DEL-001"}),
}

MAX_OUTPUT_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 96 * 1024
COMMAND_TIMEOUT_SECONDS = 10 * 60
DIAGNOSTICS_NAME = "p02-manual-catalog-diagnostics.json"


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
    migration_sha256: dict[str, str]
    registered_commands: tuple[str, ...]
    acl_permissions: tuple[str, ...]
    production_transport_isolated: bool


UI_REQUIREMENTS = frozenset(
    {"P02-CAT-001", "P02-CAT-002", "P02-REV-001", "P02-DEL-001"}
)

COMMAND_CHECKS = (
    CommandCheck(
        "core_tests",
        ("cargo", "test", "-p", "wardrobe-core", "--offline"),
        REQUIREMENT_IDS,
    ),
    CommandCheck(
        "bindings_drift",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-core",
            "generated_bindings_are_current",
            "--offline",
        ),
        REQUIREMENT_IDS,
    ),
    CommandCheck(
        "platform_tests",
        ("cargo", "test", "-p", "wardrobe-platform", "--offline"),
        REQUIREMENT_IDS,
    ),
    CommandCheck(
        "desktop_tests",
        ("cargo", "test", "-p", "wardrobe-desktop", "--offline"),
        REQUIREMENT_IDS,
    ),
    CommandCheck(
        "ui_tests",
        ("npm", "--workspace", "@wardrobe/desktop-ui", "test"),
        UI_REQUIREMENTS,
    ),
    CommandCheck(
        "playwright_e2e",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "test:e2e",
        ),
        UI_REQUIREMENTS,
    ),
    CommandCheck(
        "ui_production_build",
        ("npm", "--workspace", "@wardrobe/desktop-ui", "run", "build"),
        REQUIREMENT_IDS,
    ),
    CommandCheck(
        "production_transport_exclusion",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "check:production-transport",
        ),
        frozenset({"P02-REV-001"}),
    ),
)

SOURCE_FILES = (
    "Cargo.lock",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/src/contracts.rs",
    "crates/wardrobe-core/src/service.rs",
    "crates/wardrobe-core/src/bin/generate-bindings.rs",
    "apps/desktop-ui/src/generated/contracts.ts",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/imports.rs",
    "crates/wardrobe-platform/src/catalog_repository.rs",
    "crates/wardrobe-platform/migrations/0001_foundation.sql",
    "crates/wardrobe-platform/migrations/0001_foundation.sha256",
    "crates/wardrobe-platform/migrations/0002_manual_catalog.sql",
    "crates/wardrobe-platform/migrations/0002_manual_catalog.sha256",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/vite.config.ts",
    "apps/desktop-ui/scripts/check-production-transport.mjs",
    "apps/desktop-ui/src/invoke-transport.ts",
    "apps/desktop-ui/src/e2e/invoke-transport.ts",
    "apps/desktop-ui/src/catalog-bridge.ts",
    "apps/desktop-ui/e2e/manual-catalog.spec.ts",
    "apps/desktop-ui/playwright.config.ts",
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
    """Run a command while retaining only bounded, content-free metadata."""
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


def _toml(text: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _json(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _dependency_version(manifest: dict[str, Any], name: str) -> str | None:
    dependency = manifest.get("dependencies", {}).get(name)
    if isinstance(dependency, str):
        return dependency
    if isinstance(dependency, dict):
        version = dependency.get("version")
        return version if isinstance(version, str) else None
    return None


def _locked_version(lock: dict[str, Any], name: str) -> str | None:
    packages = lock.get("package", [])
    matches = [
        package.get("version")
        for package in packages
        if isinstance(package, dict) and package.get("name") == name
    ]
    return matches[0] if len(matches) == 1 and isinstance(matches[0], str) else None


def validate_source_contract(root: Path) -> SourceValidation:
    sources, read_errors, source_sha256 = _read_sources(root)
    errors = {requirement: [] for requirement in REQUIREMENT_IDS}
    for error in read_errors:
        for requirement in REQUIREMENT_IDS:
            errors[requirement].append(error)

    contracts = _text(sources, "crates/wardrobe-core/src/contracts.rs")
    service = _text(sources, "crates/wardrobe-core/src/service.rs")
    bindings = _text(sources, "crates/wardrobe-core/src/bindings.rs")
    generated = _text(sources, "apps/desktop-ui/src/generated/contracts.ts")
    generator = _text(
        sources, "crates/wardrobe-core/src/bin/generate-bindings.rs"
    )
    for command in P02_COMMANDS:
        _add(
            errors,
            REQUIREMENT_IDS,
            command in service,
            f"core service is missing {command}",
        )
    _add(
        errors,
        REQUIREMENT_IDS,
        "generated_bindings_are_current" in bindings
        and "typescript_bindings" in generator
        and "// @generated by wardrobe-core." in generated
        and "deny_unknown_fields" in contracts,
        "Rust contract generation or strict request decoding is incomplete",
    )

    platform_manifest = _toml(
        _text(sources, "crates/wardrobe-platform/Cargo.toml")
    )
    lock = _toml(_text(sources, "Cargo.lock"))
    _add(
        errors,
        {"P02-IMP-001", "P02-IMP-002", "P02-SAF-001"},
        _dependency_version(platform_manifest, "image") == "=0.25.10"
        and _dependency_version(platform_manifest, "mail-parser") == "=0.11.5"
        and _locked_version(lock, "image") == "0.25.10"
        and _locked_version(lock, "mail-parser") == "0.11.5",
        "image and mail-parser dependencies are not exactly pinned",
    )

    imports = _text(sources, "crates/wardrobe-platform/src/imports.rs")
    _add(
        errors,
        {"P02-IMP-001", "P02-IMP-003", "P02-SAF-001"},
        all(
            marker in imports
            for marker in (
                "O_NOFOLLOW",
                "source_provenance",
                "quarantine",
                "ImageReader",
                "Limits",
            )
        ),
        "folder/image import does not expose bounded no-follow provenance handling",
    )
    _add(
        errors,
        {"P02-IMP-002", "P02-SAF-001"},
        all(
            marker in imports
            for marker in (
                "MessageParser",
                "Sha256::digest(raw)",
                "occurrences.entry(hash.clone())",
                "mime",
                "mbox",
            )
        ),
        "EML/MBOX import does not expose raw-first bounded MIME handling",
    )

    catalog = _text(
        sources, "crates/wardrobe-platform/src/catalog_repository.rs"
    )
    _add(
        errors,
        {"P02-CAT-001", "P02-CAT-002", "P02-REV-001", "P02-DEL-001"},
        all(
            marker in catalog
            for marker in (
                "TransactionBehavior::Immediate",
                "catalog_revision",
                "expected_catalog_revision",
                "append_compensating_undo",
                "preview_deletion",
                "list_deletion_plan_items",
            )
        ),
        "catalog repository lacks CAS decisions, undo, or deletion preview",
    )
    _add(
        errors,
        {"P02-CAT-001", "P02-CAT-002"},
        "production_import_catalog_restart_undo_and_deletion_smoke" in catalog,
        "production import/catalog restart smoke test is missing",
    )

    migration_hashes: dict[str, str] = {}
    migration_ok = True
    for stem in ("0001_foundation", "0002_manual_catalog"):
        sql_name = f"crates/wardrobe-platform/migrations/{stem}.sql"
        checksum_name = (
            f"crates/wardrobe-platform/migrations/{stem}.sha256"
        )
        sql = sources.get(sql_name)
        actual = hashlib.sha256(sql).hexdigest() if sql is not None else ""
        expected = _text(sources, checksum_name).strip()
        migration_hashes[stem] = actual
        migration_ok = (
            migration_ok
            and len(actual) == 64
            and actual == expected
            and re.fullmatch(r"[0-9a-f]{64}", expected) is not None
        )
    database = _text(sources, "crates/wardrobe-platform/src/database.rs")
    first = database.find("version: 1")
    second = database.find("version: 2")
    migration_ok = (
        migration_ok
        and 0 <= first < second
        and 'include_str!("../migrations/0001_foundation.sql")' in database
        and 'include_str!("../migrations/0002_manual_catalog.sql")' in database
        and "validate_migration_source" in database
        and "verify_applied_migrations" in database
        and "source_database_sha256" in database
        and "backup_sha256" in database
    )
    _add(
        errors,
        REQUIREMENT_IDS,
        migration_ok,
        "ordered migration manifest or checked-in checksums are invalid",
    )

    desktop = _text(sources, "src-tauri/src/lib.rs")
    build_rs = _text(sources, "src-tauri/build.rs")
    direct_commands = re.findall(
        r"#\[tauri::command\]\s*(?:pub\s+)?fn\s+([a-z0-9_]+)",
        desktop,
    )
    macro_commands: list[str] = []
    if (
        "macro_rules! catalog_command" in desktop
        and "#[tauri::command]" in desktop
    ):
        macro_commands = re.findall(
            r"catalog_command!\(\s*([a-z0-9_]+)\s*,",
            desktop,
        )
    registered_commands = tuple(
        dict.fromkeys([*direct_commands, *macro_commands])
    )
    capability = _json(_text(sources, "src-tauri/capabilities/main.json"))
    permissions_value = capability.get("permissions", [])
    acl_permissions = tuple(
        permission
        for permission in permissions_value
        if isinstance(permission, str)
    ) if isinstance(permissions_value, list) else ()
    for command in P02_COMMANDS:
        permission = "allow-" + command.replace("_", "-")
        _add(
            errors,
            P02_COMMAND_REQUIREMENTS[command],
            command in registered_commands
            and command in build_rs
            and command in desktop
            and permission in acl_permissions,
            f"desktop command or ACL registration is missing {command}",
        )
    forbidden_delete_commands = {
        "hard_delete_v1",
        "execute_deletion_v1",
        "confirm_deletion_v1",
        "delete_item_v1",
        "delete_source_v1",
        "delete_evidence_v1",
    }
    _add(
        errors,
        {"P02-DEL-001"},
        not (forbidden_delete_commands & set(registered_commands))
        and not (forbidden_delete_commands & set(P02_COMMANDS)),
        "P02 exposes a hard-delete command",
    )

    ui_package = _json(_text(sources, "apps/desktop-ui/package.json"))
    scripts = ui_package.get("scripts", {})
    vite = _text(sources, "apps/desktop-ui/vite.config.ts")
    production_transport = _text(
        sources, "apps/desktop-ui/src/invoke-transport.ts"
    )
    e2e_transport = _text(
        sources, "apps/desktop-ui/src/e2e/invoke-transport.ts"
    )
    exclusion = _text(
        sources, "apps/desktop-ui/scripts/check-production-transport.mjs"
    )
    production_transport_isolated = (
        isinstance(scripts, dict)
        and {"build", "test", "test:e2e", "check:production-transport"}
        <= set(scripts)
        and 'mode === "e2e"' in vite
        and 'process.env.WARDROBE_E2E !== "1"' in vite
        and "@tauri-apps/api/core" in production_transport
        and "__WARDROBE_E2E_TRANSPORT__" not in production_transport
        and "__WARDROBE_E2E_TRANSPORT__" in e2e_transport
        and "__WARDROBE_E2E_TRANSPORT__" in exclusion
        and "WARDROBE_E2E" in exclusion
    )
    _add(
        errors,
        {"P02-REV-001"},
        production_transport_isolated,
        "test-only invoke transport is not isolated from production",
    )

    bridge = _text(sources, "apps/desktop-ui/src/catalog-bridge.ts")
    for command in P02_COMMANDS:
        _add(
            errors,
            UI_REQUIREMENTS,
            command in bridge,
            f"typed UI bridge is missing {command}",
        )
    e2e = _text(sources, "apps/desktop-ui/e2e/manual-catalog.spec.ts")
    playwright = _text(sources, "apps/desktop-ui/playwright.config.ts")
    _add(
        errors,
        UI_REQUIREMENTS,
        all(
            marker in e2e
            for marker in (
                "AxeBuilder",
                "serious",
                "critical",
                "p02-desktop.png",
                "p02-mobile.png",
                "setViewportSize",
                "expected_catalog_revision",
            )
        )
        and "Desktop Chrome" in playwright,
        "Playwright workflow lacks desktop/mobile, axe, or revision coverage",
    )

    return SourceValidation(
        errors={
            requirement: tuple(dict.fromkeys(messages))
            for requirement, messages in errors.items()
        },
        source_sha256=source_sha256,
        migration_sha256=migration_hashes,
        registered_commands=registered_commands,
        acl_permissions=acl_permissions,
        production_transport_isolated=production_transport_isolated,
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
        raise ValueError("P02 evaluator artifact exceeds size limit")
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


def _public_summary(
    requirement: str,
    source: SourceValidation,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "profile": "personal_mvp",
        "verification": "focused production checks and phase smoke passed",
        "hard_delete_available": False,
    }
    if requirement.startswith("P02-IMP") or requirement == "P02-SAF-001":
        summary["importers"] = "folder,eml,mbox"
        summary["parser_dependencies"] = "image=0.25.10,mail-parser=0.11.5"
    if requirement in {"P02-CAT-001", "P02-CAT-002"}:
        summary["decision_model"] = "append_only_cas_with_compensating_undo"
    if requirement == "P02-REV-001":
        summary["browser_smoke"] = "desktop_mobile_axe"
        summary["production_transport_isolated"] = (
            source.production_transport_isolated
        )
    if requirement == "P02-DEL-001":
        summary["deletion_scope"] = "read_only_paged_preview"
    return summary


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(evidence_dir)
    source = validate_source_contract(root)
    environment = os.environ.copy()

    relevant_checks = [
        check for check in COMMAND_CHECKS if check.requirements & requested
    ]
    command_results: dict[str, CommandResult] = {}
    for check in relevant_checks:
        command_results[check.name] = run_bounded_command(
            list(check.command),
            cwd=root,
            env=environment,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
        )

    errors: list[str] = []
    requirement_checks: dict[str, list[str]] = {
        requirement: ["production_source_contract"]
        for requirement in sorted(requested)
    }
    for requirement in sorted(requested):
        for error in source.errors[requirement]:
            errors.append(f"{requirement}: {error}")
    for check in relevant_checks:
        result = command_results[check.name]
        error = _command_error(check, result)
        for requirement in sorted(check.requirements & requested):
            requirement_checks[requirement].append(check.name)
            if error:
                errors.append(f"{requirement}: {error}")
    errors = list(dict.fromkeys(errors))
    recorded_at = utc_now()

    diagnostics: dict[str, Any] = {
        "schema_version": 1,
        "phase": "P02",
        "status": "fail" if errors else "pass",
        "evaluated_at": recorded_at,
        "selected_requirement_ids": sorted(requested),
        "errors": errors,
        "source_contract_sha256": source.source_sha256,
        "migration_sha256": source.migration_sha256,
        "registered_p02_commands": sorted(
            set(P02_COMMANDS) & set(source.registered_commands)
        ),
        "registered_p02_acl_permissions": sorted(
            permission
            for permission in source.acl_permissions
            if permission
            in {"allow-" + command.replace("_", "-") for command in P02_COMMANDS}
        ),
        "production_transport_isolated": source.production_transport_isolated,
        "commands": {
            name: _result_summary(result)
            for name, result in sorted(command_results.items())
        },
        "requirement_checks": requirement_checks,
        "deferred_limitations": [
            "HEIC, watch folders, and hard-deletion execution are deferred",
            "packaged GUI and clean-machine certification are deferred",
        ],
        "pass_evidence_written": not errors,
    }
    write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    if errors:
        for error in errors:
            print(f"P02 manual catalog evaluation: {error}")
        return 1

    payloads = {
        requirement: {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": "pass",
            "test": "p02_manual_catalog::focused_production_verification",
            "recorded_at": recorded_at,
            "details": {
                "evaluator": "tools/evaluators/p02_manual_catalog.py",
                "checks": requirement_checks[requirement],
                "public_summary": _public_summary(requirement, source),
            },
        }
        for requirement in sorted(requested)
    }
    for payload in payloads.values():
        _json_bytes(payload)
    for requirement, payload in payloads.items():
        write_atomic_json(evidence_dir / f"{requirement}.json", payload)
    print("P02 manual catalog evaluation: all selected focused checks passed")
    return 0
