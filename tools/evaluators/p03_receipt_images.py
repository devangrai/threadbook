"""Fail-closed evaluator for the P03 receipt-image personal-MVP packet."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib
from typing import Any

from tools.evaluators.p03_receipts import (
    CommandResult,
    run_bounded_command,
    write_atomic_json,
)


REQUIREMENT_IDS = frozenset({"P03-IMG-001"})
DIAGNOSTICS_NAME = "p03-receipt-images-diagnostics.json"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 96 * 1024
COMMAND_TIMEOUT_SECONDS = 10 * 60

COMMANDS = (
    "list_receipt_image_candidates_v1",
    "approve_and_fetch_receipt_image_v1",
)


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class SourceValidation:
    errors: tuple[str, ...]
    source_sha256: str
    migration_sha256: str
    registered_commands: tuple[str, ...]
    acl_permissions: tuple[str, ...]
    production_downloader_wired: bool
    production_transport_isolated: bool


COMMAND_CHECKS = (
    CommandCheck(
        "core_receipt_image_contracts",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "--test",
            "receipt_image_contracts",
        ),
    ),
    CommandCheck(
        "core_receipt_image_service",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "--test",
            "receipt_image_service",
        ),
    ),
    CommandCheck(
        "platform_receipt_image_downloader",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--test",
            "receipt_image_downloader",
        ),
    ),
    CommandCheck(
        "platform_receipt_image_repository",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--test",
            "receipt_image_repository",
        ),
    ),
    CommandCheck(
        "desktop_receipt_image_smoke",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-desktop",
            "receipt_image_commands_preserve_explicit_network_authority_and_diagnostic_secrecy",
        ),
    ),
    CommandCheck(
        "ui_receipt_image_tests",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "src/ReceiptsWorkspace.test.tsx",
            "src/receipt-bridge.test.ts",
        ),
    ),
    CommandCheck(
        "ui_receipt_image_smoke",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "test:e2e",
            "--",
            "receipt-images.spec.ts",
        ),
    ),
    CommandCheck(
        "ui_production_build",
        ("npm", "--workspace", "@wardrobe/desktop-ui", "run", "build"),
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
    ),
)

SOURCE_FILES = (
    "Cargo.lock",
    "crates/wardrobe-core/src/receipt.rs",
    "crates/wardrobe-core/src/ports.rs",
    "crates/wardrobe-core/src/service.rs",
    "crates/wardrobe-core/src/bindings.rs",
    "apps/desktop-ui/src/generated/contracts.ts",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/receipt_parser.rs",
    "crates/wardrobe-platform/src/receipt_image_downloader.rs",
    "crates/wardrobe-platform/src/receipt_repository.rs",
    "crates/wardrobe-platform/migrations/0004_receipt_images.sql",
    "crates/wardrobe-platform/migrations/0004_receipt_images.sha256",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/src/invoke-transport.ts",
    "apps/desktop-ui/src/e2e/invoke-transport.ts",
    "apps/desktop-ui/src/receipt-bridge.ts",
    "apps/desktop-ui/src/ReceiptsWorkspace.tsx",
    "apps/desktop-ui/e2e/receipt-images.spec.ts",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read_sources(root: Path) -> tuple[dict[str, bytes], list[str], str]:
    sources: dict[str, bytes] = {}
    errors: list[str] = []
    digest = hashlib.sha256()
    for relative in SOURCE_FILES:
        try:
            data = (root / relative).read_bytes()
        except OSError:
            errors.append(f"required production file is unreadable: {relative}")
            continue
        if len(data) > MAX_SOURCE_BYTES:
            errors.append(f"required production file exceeds size bound: {relative}")
            continue
        sources[relative] = data
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return sources, errors, digest.hexdigest()


def _text(sources: dict[str, bytes], relative: str) -> str:
    try:
        return sources[relative].decode("utf-8")
    except (KeyError, UnicodeDecodeError):
        return ""


def _toml(text: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _dependency(
    manifest: dict[str, Any], name: str
) -> str | dict[str, Any] | None:
    dependencies = manifest.get("dependencies")
    return dependencies.get(name) if isinstance(dependencies, dict) else None


def validate_source_contract(root: Path) -> SourceValidation:
    sources, errors, source_sha256 = _read_sources(root)
    receipt = _text(sources, "crates/wardrobe-core/src/receipt.rs")
    ports = _text(sources, "crates/wardrobe-core/src/ports.rs")
    service = _text(sources, "crates/wardrobe-core/src/service.rs")
    bindings = _text(sources, "crates/wardrobe-core/src/bindings.rs")
    generated = _text(sources, "apps/desktop-ui/src/generated/contracts.ts")
    parser = _text(sources, "crates/wardrobe-platform/src/receipt_parser.rs")
    downloader = _text(
        sources, "crates/wardrobe-platform/src/receipt_image_downloader.rs"
    )
    repository = _text(
        sources, "crates/wardrobe-platform/src/receipt_repository.rs"
    )
    database = _text(sources, "crates/wardrobe-platform/src/database.rs")
    platform_lib = _text(sources, "crates/wardrobe-platform/src/lib.rs")
    desktop = _text(sources, "src-tauri/src/lib.rs")
    build_rs = _text(sources, "src-tauri/build.rs")
    bridge = _text(sources, "apps/desktop-ui/src/receipt-bridge.ts")
    workspace = _text(sources, "apps/desktop-ui/src/ReceiptsWorkspace.tsx")
    e2e = _text(sources, "apps/desktop-ui/e2e/receipt-images.spec.ts")

    for marker in (
        "ReceiptImageCandidateSummaryV1",
        "ApproveAndFetchReceiptImageV1Request",
        "ReceiptRemoteImageV1",
        "ReceiptImageFailureCodeV1",
    ):
        if marker not in receipt:
            errors.append(f"core image contract is missing {marker}")
    if receipt.count("deny_unknown_fields") < 12:
        errors.append("strict receipt-image contracts are incomplete")
    if "ReceiptImageDownloader" not in ports or not all(
        command in service for command in COMMANDS
    ):
        errors.append("receipt-image ports or service methods are incomplete")
    if (
        "generated_bindings_are_current" not in bindings
        or not all(
            marker in generated
            for marker in (
                "ListReceiptImageCandidatesV1Request",
                "ApproveAndFetchReceiptImageV1Request",
                "ApproveAndFetchReceiptImageV1Response",
            )
        )
    ):
        errors.append("receipt-image TypeScript bindings are incomplete")

    sql = sources.get(
        "crates/wardrobe-platform/migrations/0004_receipt_images.sql", b""
    )
    migration_sha256 = hashlib.sha256(sql).hexdigest()
    recorded = _text(
        sources,
        "crates/wardrobe-platform/migrations/0004_receipt_images.sha256",
    ).strip()
    if (
        not sql
        or recorded != migration_sha256
        or re.fullmatch(r"[0-9a-f]{64}", recorded) is None
        or 'include_str!("../migrations/0004_receipt_images.sql")' not in database
        or "version: 4" not in database
        or "target_schema_version" not in database
    ):
        errors.append("checksummed ordered v4 migration is incomplete")

    manifest = _toml(_text(sources, "crates/wardrobe-platform/Cargo.toml"))
    reqwest = _dependency(manifest, "reqwest")
    hickory = _dependency(manifest, "hickory-resolver")
    tokio = _dependency(manifest, "tokio")
    if not (
        isinstance(reqwest, dict)
        and reqwest.get("version") == "=0.13.4"
        and reqwest.get("default-features") is False
        and "rustls" in reqwest.get("features", [])
        and isinstance(hickory, dict)
        and hickory.get("version") == "=0.26.1"
        and isinstance(tokio, dict)
    ):
        errors.append("locked async reqwest/rustls/Hickory dependencies are invalid")

    required_downloader_markers = (
        "SealedProductionAddressPolicy",
        "HickorySystemResolver",
        "retry::never",
        "Policy::none",
        "no_proxy",
        "https_only",
        "resolve_to_addrs",
        "spawn_blocking",
        "timeout_at",
        "RedirectCrossHost",
        "MPF",
        "acTL",
        "ANIM",
    )
    if not all(marker in downloader for marker in required_downloader_markers):
        errors.append("production downloader policy or structural validators are incomplete")
    production_prefix = downloader.split("#[cfg(test)]", 1)[0]
    if any(
        marker in production_prefix
        for marker in ("MockDownloader", "FixtureAddressPolicy", "TestResolver")
    ):
        errors.append("test transport or fixture address policy entered production code")
    if any(
        pattern in downloader
        for pattern in (
            "format!(\"{error",
            "format!(\"{:?}\", error",
            "error.to_string()",
            "error.source()",
        )
    ):
        errors.append("third-party downloader errors may expose URL-bearing details")
    if not all(
        marker in parser
        for marker in (
            "ReceiptImageCandidateInputV1",
            "MAX_RECEIPT_IMAGE_CANDIDATES",
        )
    ):
        errors.append("inert bounded image-candidate extraction is incomplete")
    if not all(
        marker in repository
        for marker in (
            "prepare_image_attempt",
            "TransactionBehavior::Immediate",
            "ambiguous",
            "receipt_image_materialization_intents",
        )
    ):
        errors.append("durable approval, replay, or materialization intent logic is incomplete")

    desktop_production = desktop.split("#[cfg(test)]", 1)[0]
    direct_commands = re.findall(
        r"#\[tauri::command\]\s*(?:pub\s+)?async\s+fn\s+([a-z0-9_]+)",
        desktop_production,
    )
    registered_commands = tuple(dict.fromkeys(direct_commands))
    try:
        capability = json.loads(
            _text(sources, "src-tauri/capabilities/main.json")
        )
    except json.JSONDecodeError:
        capability = {}
    permissions = capability.get("permissions", [])
    acl_permissions = tuple(
        value for value in permissions if isinstance(value, str)
    ) if isinstance(permissions, list) else ()
    for command in COMMANDS:
        permission = "allow-" + command.replace("_", "-")
        if not (
            command in desktop_production
            and command in build_rs
            and permission in acl_permissions
        ):
            errors.append(f"desktop command or ACL registration is missing {command}")

    production_downloader_wired = (
        "pub type ProductionReceiptImageDownloader" in downloader
        and "ReqwestReceiptImageDownloader" in downloader
        and "HickorySystemResolver" in downloader
        and "SealedProductionAddressPolicy" in downloader
        and "pub use receipt_image_downloader::*" in platform_lib
        and "ProductionReceiptImageDownloader::from_system_config()" in desktop_production
        and "with_receipt_image_downloader" in desktop_production
    )
    if not production_downloader_wired:
        errors.append("sealed production downloader is not wired")

    production_transport = _text(
        sources, "apps/desktop-ui/src/invoke-transport.ts"
    )
    e2e_transport = _text(
        sources, "apps/desktop-ui/src/e2e/invoke-transport.ts"
    )
    production_transport_isolated = (
        "@tauri-apps/api/core" in production_transport
        and "__WARDROBE_E2E_TRANSPORT__" not in production_transport
        and "__WARDROBE_E2E_TRANSPORT__" in e2e_transport
    )
    if not (
        production_transport_isolated
        and all(command in bridge for command in COMMANDS)
        and "Download image from" in workspace
        and "Start new attempt" in workspace
        and "<img" not in workspace
        and all(
            marker in e2e
            for marker in ("AxeBuilder", "receipt image", "setViewportSize")
        )
    ):
        errors.append("inert approval UI, smoke, or transport isolation is incomplete")

    return SourceValidation(
        errors=tuple(dict.fromkeys(errors)),
        source_sha256=source_sha256,
        migration_sha256=migration_sha256,
        registered_commands=registered_commands,
        acl_permissions=acl_permissions,
        production_downloader_wired=production_downloader_wired,
        production_transport_isolated=production_transport_isolated,
    )


def _result_summary(result: CommandResult) -> dict[str, Any]:
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
    if result.launch_failed:
        return f"{check.name} could not launch"
    if result.timed_out:
        return f"{check.name} timed out"
    if result.output_limit_exceeded:
        return f"{check.name} exceeded its output bound"
    if result.returncode != 0:
        return f"{check.name} failed"
    return None


def _remove_stale_outputs(evidence_dir: Path) -> None:
    for name in ("P03-IMG-001.json", DIAGNOSTICS_NAME):
        try:
            (evidence_dir / name).unlink()
        except FileNotFoundError:
            pass


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0
    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(evidence_dir)
    source = validate_source_contract(root)
    command_summaries: dict[str, dict[str, Any]] = {}
    failures = list(source.errors)
    if not failures:
        environment = os.environ.copy()
        environment.pop("HARNESS_RUN_DIR", None)
        environment.pop("HARNESS_EVIDENCE_DIR", None)
        for check in COMMAND_CHECKS:
            result = run_bounded_command(
                list(check.command),
                cwd=root,
                env=environment,
                timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            )
            command_summaries[check.name] = _result_summary(result)
            error = _command_error(check, result)
            if error:
                failures.append(error)
                break

    passed = not failures
    generated_at = utc_now()
    if passed:
        evidence = {
            "schema_version": 1,
            "requirement_id": "P03-IMG-001",
            "status": "pass",
            "test": "p03_receipt_images::focused_production_verification",
            "recorded_at": generated_at,
            "details": {
                "evaluator": "tools/evaluators/p03_receipt_images.py",
                "checks": command_summaries,
                "public_summary": {
                    "profile": "personal_mvp",
                    "verification": "focused receipt-image production checks passed",
                    "source_sha256": source.source_sha256,
                    "migration_sha256": source.migration_sha256,
                    "production_downloader_wired": source.production_downloader_wired,
                    "production_transport_isolated": source.production_transport_isolated,
                    "network_policy": "https_same_host_pinned_public_addresses",
                    "external_internet_certification": "deferred",
                    "clean_machine_certification": "deferred",
                },
            },
        }
        encoded = json.dumps(
            evidence, sort_keys=True, separators=(",", ":")
        ).encode()
        if len(encoded) > MAX_ARTIFACT_BYTES:
            failures.append("pass evidence exceeds artifact bound")
            passed = False
        else:
            write_atomic_json(evidence_dir / "P03-IMG-001.json", evidence)

    diagnostics = {
        "schema_version": 1,
        "status": "pass" if passed else "fail",
        "generated_at": generated_at,
        "failures": failures,
        "source_sha256": source.source_sha256,
        "migration_sha256": source.migration_sha256,
        "registered_commands": list(source.registered_commands),
        "acl_permissions": list(source.acl_permissions),
        "production_downloader_wired": source.production_downloader_wired,
        "production_transport_isolated": source.production_transport_isolated,
        "checks": command_summaries,
        "pass_evidence_written": passed,
    }
    write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    if not passed:
        try:
            (evidence_dir / "P03-IMG-001.json").unlink()
        except FileNotFoundError:
            pass
    return 0 if passed else 1
