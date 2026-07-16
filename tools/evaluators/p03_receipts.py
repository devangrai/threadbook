"""Fail-closed evaluator for the approved P03 receipt-only vertical."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import signal
import subprocess
import sys
import time
import tomllib
from typing import Any


REQUIREMENT_IDS = frozenset(
    {
        "P03-MIM-001",
        "P03-ORD-001",
        "P03-AI-001",
        "P03-AI-002",
        "P03-SAF-001",
        "P03-QLT-001",
    }
)
P03_COMMANDS = (
    "list_receipts_v1",
    "analyze_receipt_v1",
    "review_receipt_v1",
)
APPROVED_CORPUS_SHA256 = (
    "a13dc0d6a28308ab01232b800f23a77119479cde4fe9db44f05a3102a69a5cac"
)
MIN_ITEM_RECALL = 0.95
EXPECTED_MESSAGES = 24
EXPECTED_GOLD_LINES = 48
REQUIRED_COVERAGE = frozenset(
    {
        "plain_text",
        "html_table",
        "html_list",
        "multipart_alternative",
        "cid_metadata",
        "attachment_metadata",
        "purchase",
        "exchange",
        "return",
        "missing_fields",
        "repeated_quantities",
        "injection_text",
    }
)

MAX_OUTPUT_BYTES = 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_CORPUS_BYTES = 96 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024
COMMAND_TIMEOUT_SECONDS = 10 * 60
DIAGNOSTICS_NAME = "p03-receipts-diagnostics.json"

EXPECTED_REPORT_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "test_name",
        "corpus_sha256",
        "message_count",
        "coverage_count",
        "matched_lines",
        "gold_lines",
        "manifest_gold_lines",
        "recall",
        "spurious_lines",
        "unsupported_field_failures",
        "citation_failures",
        "parser_revision",
        "sanitizer_revision",
        "provider_id",
        "provider_revision",
        "schema_revision",
        "ruleset_revision",
    }
)


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]
    requirements: frozenset[str]
    quality_report: bool = False


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output_sha256: str
    output_bytes: int
    duration_ms: int
    output_limit_exceeded: bool = False
    timed_out: bool = False
    launch_failed: bool = False
    captured_output: bytes = b""


@dataclass(frozen=True)
class CorpusValidation:
    errors: tuple[str, ...]
    sha256: str
    revision: str | None
    message_count: int
    labeled_line_count: int
    coverage: tuple[str, ...]


@dataclass(frozen=True)
class SourceValidation:
    errors: dict[str, tuple[str, ...]]
    source_sha256: str
    migration_sha256: dict[str, str]
    registered_commands: tuple[str, ...]
    acl_permissions: tuple[str, ...]
    production_provider_wired: bool
    production_network_free: bool
    production_transport_isolated: bool


ALL = REQUIREMENT_IDS
UI = frozenset({"P03-ORD-001", "P03-AI-002", "P03-SAF-001"})
COMMAND_CHECKS = (
    CommandCheck(
        "frozen_corpus_quality",
        (
            sys.executable,
            "tools/evaluators/p03_quality_report.py",
        ),
        ALL,
        quality_report=True,
    ),
    CommandCheck(
        "core_receipt_contracts",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-core",
            "--offline",
            "--test",
            "receipt_contracts",
        ),
        ALL,
    ),
    CommandCheck(
        "core_receipt_service",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-core",
            "--offline",
            "--test",
            "receipt_service",
        ),
        ALL,
    ),
    CommandCheck(
        "platform_receipt_tests",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "receipt_",
        ),
        ALL,
    ),
    CommandCheck(
        "migration_v3_matrix",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "database::tests",
        ),
        ALL,
    ),
    CommandCheck(
        "deletion_classification",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "deletion_",
        ),
        ALL,
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
        ALL,
    ),
    CommandCheck(
        "tauri_receipt_smoke",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-desktop",
            "receipt_commands_use_real_backend_restart_replay_and_structured_failures",
            "--offline",
        ),
        ALL,
    ),
    CommandCheck(
        "ui_receipt_tests",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "src/ReceiptsWorkspace.test.tsx",
            "src/receipt-bridge.test.ts",
            "src/receipt-model.test.ts",
        ),
        UI,
    ),
    CommandCheck(
        "playwright_receipts_axe",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "test:e2e",
            "--",
            "receipts.spec.ts",
        ),
        UI,
    ),
    CommandCheck(
        "ui_production_build",
        ("npm", "--workspace", "@wardrobe/desktop-ui", "run", "build"),
        ALL,
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
        ALL,
    ),
)

SOURCE_FILES = (
    "crates/wardrobe-core/src/receipt.rs",
    "crates/wardrobe-core/src/ports.rs",
    "crates/wardrobe-core/src/service.rs",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/src/bin/generate-bindings.rs",
    "apps/desktop-ui/src/generated/contracts.ts",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/receipt_parser.rs",
    "crates/wardrobe-platform/src/receipt_provider.rs",
    "crates/wardrobe-platform/src/receipt_repository.rs",
    "crates/wardrobe-platform/src/catalog_repository.rs",
    "crates/wardrobe-platform/migrations/0001_foundation.sql",
    "crates/wardrobe-platform/migrations/0001_foundation.sha256",
    "crates/wardrobe-platform/migrations/0002_manual_catalog.sql",
    "crates/wardrobe-platform/migrations/0002_manual_catalog.sha256",
    "crates/wardrobe-platform/migrations/0003_receipts.sql",
    "crates/wardrobe-platform/migrations/0003_receipts.sha256",
    "src-tauri/Cargo.toml",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/vite.config.ts",
    "apps/desktop-ui/scripts/check-production-transport.mjs",
    "apps/desktop-ui/src/invoke-transport.ts",
    "apps/desktop-ui/src/e2e/invoke-transport.ts",
    "apps/desktop-ui/src/receipt-bridge.ts",
    "apps/desktop-ui/e2e/receipts.spec.ts",
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
    capture_output: bool = False,
) -> CommandResult:
    """Run a command while retaining bounded, content-free metadata."""
    digest = hashlib.sha256()
    captured = bytearray()
    output_bytes = 0
    timed_out = False
    output_limit_exceeded = False
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
                if capture_output and len(captured) < MAX_OUTPUT_BYTES:
                    remaining_capture = MAX_OUTPUT_BYTES - len(captured)
                    captured.extend(chunk[:remaining_capture])
                if output_bytes > MAX_OUTPUT_BYTES:
                    output_limit_exceeded = True
                    if process.poll() is None:
                        _terminate(process)
                continue
        if process.poll() is not None:
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if chunk:
                output_bytes += len(chunk)
                digest.update(chunk)
                if capture_output and len(captured) < MAX_OUTPUT_BYTES:
                    remaining_capture = MAX_OUTPUT_BYTES - len(captured)
                    captured.extend(chunk[:remaining_capture])
                if output_bytes > MAX_OUTPUT_BYTES:
                    output_limit_exceeded = True
                continue
            break
    process.stdout.close()
    return CommandResult(
        returncode=process.returncode,
        output_sha256=digest.hexdigest(),
        output_bytes=output_bytes,
        duration_ms=int((time.monotonic() - started) * 1000),
        output_limit_exceeded=output_limit_exceeded,
        timed_out=timed_out,
        captured_output=bytes(captured),
    )


def validate_corpus(root: Path) -> CorpusValidation:
    path = root / "fixtures/receipts/v1/manifest.json"
    errors: list[str] = []
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_CORPUS_BYTES + 1)
    except OSError:
        return CorpusValidation(
            ("approved corpus manifest is unreadable",),
            "",
            None,
            0,
            0,
            (),
        )
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > MAX_CORPUS_BYTES:
        errors.append("approved corpus manifest exceeds size bound")
    if digest != APPROVED_CORPUS_SHA256:
        errors.append("approved corpus SHA-256 does not match")
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        value = {}
        errors.append("approved corpus manifest is malformed")

    corpus = value.get("corpus", {}) if isinstance(value, dict) else {}
    messages = value.get("messages", []) if isinstance(value, dict) else []
    if not isinstance(corpus, dict) or not isinstance(messages, list):
        corpus = {}
        messages = []
        errors.append("approved corpus structure is invalid")
    revision = corpus.get("revision")
    revision = revision if isinstance(revision, str) else None
    declared_messages = corpus.get("message_count")
    declared_lines = corpus.get("labeled_line_count")
    actual_lines = 0
    coverage: set[str] = set()
    message_ids: set[str] = set()
    line_ids: set[str] = set()
    structure_ok = True
    for message in messages:
        if not isinstance(message, dict):
            structure_ok = False
            continue
        message_id = message.get("message_id")
        eml = message.get("eml")
        message_coverage = message.get("coverage")
        expected = message.get("expected")
        lines = expected.get("lines") if isinstance(expected, dict) else None
        if (
            not isinstance(message_id, str)
            or not isinstance(eml, str)
            or not isinstance(message_coverage, list)
            or not all(isinstance(item, str) for item in message_coverage)
            or not isinstance(lines, list)
        ):
            structure_ok = False
            continue
        if message_id in message_ids or len(eml.encode("utf-8")) > 16384:
            structure_ok = False
        message_ids.add(message_id)
        coverage.update(message_coverage)
        actual_lines += len(lines)
        for line in lines:
            line_id = line.get("line_id") if isinstance(line, dict) else None
            if not isinstance(line_id, str) or line_id in line_ids:
                structure_ok = False
            else:
                line_ids.add(line_id)
    if (
        declared_messages != EXPECTED_MESSAGES
        or len(messages) != EXPECTED_MESSAGES
    ):
        errors.append("approved corpus does not contain exactly 24 messages")
    if declared_lines != EXPECTED_GOLD_LINES or actual_lines != EXPECTED_GOLD_LINES:
        errors.append("approved corpus does not contain exactly 48 labeled lines")
    missing_coverage = REQUIRED_COVERAGE - coverage
    if missing_coverage:
        errors.append("approved corpus required coverage is incomplete")
    if not structure_ok:
        errors.append("approved corpus messages or line identities are invalid")
    if MIN_ITEM_RECALL != 0.95:
        errors.append("P03 minimum item recall constant is not exactly 0.95")
    return CorpusValidation(
        tuple(dict.fromkeys(errors)),
        digest,
        revision,
        len(messages),
        actual_lines,
        tuple(sorted(coverage)),
    )


def _read_sources(root: Path) -> tuple[dict[str, bytes], list[str], str]:
    sources: dict[str, bytes] = {}
    errors: list[str] = []
    digest = hashlib.sha256()
    for relative in SOURCE_FILES:
        path = root / relative
        try:
            with path.open("rb") as handle:
                data = handle.read(MAX_SOURCE_BYTES + 1)
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


def _json_object(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _toml_object(text: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _production_dependency_names(manifest: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    dependencies = manifest.get("dependencies")
    if isinstance(dependencies, dict):
        names.update(dependencies)
    targets = manifest.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            target_dependencies = target.get("dependencies")
            if isinstance(target_dependencies, dict):
                names.update(target_dependencies)
    return names


def validate_source_contract(root: Path) -> SourceValidation:
    sources, read_errors, source_sha256 = _read_sources(root)
    errors = {requirement: [] for requirement in REQUIREMENT_IDS}
    for error in read_errors:
        for requirement in REQUIREMENT_IDS:
            errors[requirement].append(error)

    receipt = _text(sources, "crates/wardrobe-core/src/receipt.rs")
    ports = _text(sources, "crates/wardrobe-core/src/ports.rs")
    service = _text(sources, "crates/wardrobe-core/src/service.rs")
    bindings = _text(sources, "crates/wardrobe-core/src/bindings.rs")
    generator = _text(
        sources, "crates/wardrobe-core/src/bin/generate-bindings.rs"
    )
    generated = _text(sources, "apps/desktop-ui/src/generated/contracts.ts")
    _add(
        errors,
        ALL,
        all(command in service for command in P03_COMMANDS)
        and "ReceiptEvidenceProvider" in ports
        and receipt.count("deny_unknown_fields") >= 10
        and "FragmentCitationV1" in receipt
        and "quote_sha256" in receipt,
        "strict receipt domain/provider contracts are incomplete",
    )
    _add(
        errors,
        {"P03-AI-001", "P03-AI-002", "P03-QLT-001"},
        '"receipt-extraction-v1"' in receipt
        and all(
            marker in _text(
                sources,
                "crates/wardrobe-platform/src/receipt_provider.rs",
            )
            for marker in (
                '"local-deterministic-receipt-provider"',
                '"local-deterministic-receipt-provider-v1"',
                '"explicit-receipt-evidence-rules-v1"',
            )
        ),
        "receipt provider/schema revision contract is incomplete",
    )
    _add(
        errors,
        ALL,
        "generated_bindings_are_current" in bindings
        and "typescript_bindings" in generator
        and "// @generated by wardrobe-core." in generated
        and all(
            type_name in generated
            for type_name in (
                "ListReceiptsV1Request",
                "AnalyzeReceiptV1Request",
                "ReviewReceiptV1Request",
            )
        ),
        "receipt TypeScript binding generation is incomplete",
    )

    migration_hashes: dict[str, str] = {}
    migration_ok = True
    for stem in (
        "0001_foundation",
        "0002_manual_catalog",
        "0003_receipts",
    ):
        sql_name = f"crates/wardrobe-platform/migrations/{stem}.sql"
        checksum_name = f"crates/wardrobe-platform/migrations/{stem}.sha256"
        sql = sources.get(sql_name)
        actual = hashlib.sha256(sql).hexdigest() if sql is not None else ""
        expected = _text(sources, checksum_name).strip()
        migration_hashes[stem] = actual
        migration_ok = (
            migration_ok
            and actual == expected
            and re.fullmatch(r"[0-9a-f]{64}", expected) is not None
        )
    database = _text(sources, "crates/wardrobe-platform/src/database.rs")
    positions = [database.find(f"version: {version}") for version in (1, 2, 3)]
    migration_ok = (
        migration_ok
        and positions[0] >= 0
        and positions == sorted(positions)
        and 'include_str!("../migrations/0003_receipts.sql")' in database
        and "for migration in MIGRATIONS" in database
        and "apply_migration" in database
        and "create_verified_backup" in database
        and "source_schema_version" in database
        and "target_schema_version" in database
        and "source_database_sha256" in database
        and "backup_sha256" in database
        and "verify_applied_migrations" in database
    )
    _add(
        errors,
        ALL,
        migration_ok,
        "ordered checksummed v3 migration or verified backup contract is invalid",
    )

    parser = _text(sources, "crates/wardrobe-platform/src/receipt_parser.rs")
    provider = _text(sources, "crates/wardrobe-platform/src/receipt_provider.rs")
    repository = _text(
        sources, "crates/wardrobe-platform/src/receipt_repository.rs"
    )
    catalog = _text(
        sources, "crates/wardrobe-platform/src/catalog_repository.rs"
    )
    platform_lib = _text(sources, "crates/wardrobe-platform/src/lib.rs")
    _add(
        errors,
        {"P03-MIM-001", "P03-AI-001", "P03-SAF-001"},
        all(
            marker in parser
            for marker in (
                "mail-parser-0.11.5/receipt-parser-v1",
                "html5ever-0.38/receipt-sanitizer-v1",
                "AttachmentMetadata",
                "CidMetadata",
                "canonical_input_sha256",
            )
        ),
        "production MIME parser/sanitizer contract is incomplete",
    )
    _add(
        errors,
        {"P03-ORD-001", "P03-AI-001", "P03-AI-002", "P03-SAF-001"},
        all(
            marker in repository
            for marker in (
                "persist_order_graph",
                "receipt_review_decisions",
                "receipt_review_heads",
                "TransactionBehavior::Immediate",
                "validate_against",
            )
        )
        and "receipt_command_entities" in catalog,
        "receipt persistence, review authority, or deletion closure is incomplete",
    )

    platform_manifest = _toml_object(
        _text(sources, "crates/wardrobe-platform/Cargo.toml")
    )
    forbidden_dependencies = {
        "openai",
        "async-openai",
    }
    dependency_names = _production_dependency_names(platform_manifest)
    production_provider_prefix = provider.split("#[cfg(test)]", 1)[0]
    production_network_free = (
        not (dependency_names & forbidden_dependencies)
        and not any(
            marker in production_provider_prefix
            for marker in (
                "std::net",
                "TcpStream",
                "UdpSocket",
                "reqwest",
                "hyper::",
                "Command::new",
                "OpenAI",
                "TestProvider",
                "MockProvider",
                "ScriptedProvider",
            )
        )
        and "no-tools-network-filesystem-callbacks" in production_provider_prefix
    )
    _add(
        errors,
        {"P03-SAF-001"},
        production_network_free,
        "production receipt provider has network, tool, or test-provider capability",
    )

    desktop = _text(sources, "src-tauri/src/lib.rs")
    build_rs = _text(sources, "src-tauri/build.rs")
    desktop_production = desktop.split("#[cfg(test)]", 1)[0]
    direct_commands = re.findall(
        r"#\[tauri::command\]\s*(?:pub\s+)?fn\s+([a-z0-9_]+)",
        desktop_production,
    )
    macro_commands = re.findall(
        r"catalog_command!\(\s*([a-z0-9_]+)\s*,",
        desktop_production,
    )
    registered_commands = tuple(
        dict.fromkeys([*direct_commands, *macro_commands])
    )
    capability = _json_object(
        _text(sources, "src-tauri/capabilities/main.json")
    )
    permissions_value = capability.get("permissions", [])
    acl_permissions = (
        tuple(item for item in permissions_value if isinstance(item, str))
        if isinstance(permissions_value, list)
        else ()
    )
    for command in P03_COMMANDS:
        permission = "allow-" + command.replace("_", "-")
        _add(
            errors,
            ALL,
            command in registered_commands
            and command in build_rs
            and command in desktop_production
            and permission in acl_permissions,
            f"desktop command or ACL registration is missing {command}",
        )
    production_provider_wired = (
        "LocalDeterministicReceiptProviderV1" in platform_lib
        and "LocalDeterministicReceiptProviderV1" in desktop_production
        and ".with_receipt_provider(LocalDeterministicReceiptProviderV1::new())"
        in desktop_production
        and "TestProvider" not in desktop_production
        and "MockProvider" not in desktop_production
        and "ScriptedProvider" not in desktop_production
    )
    _add(
        errors,
        ALL,
        production_provider_wired,
        "real local receipt provider is not wired in the production constructor",
    )

    ui_package = _json_object(
        _text(sources, "apps/desktop-ui/package.json")
    )
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
    )
    bridge = _text(sources, "apps/desktop-ui/src/receipt-bridge.ts")
    e2e = _text(sources, "apps/desktop-ui/e2e/receipts.spec.ts")
    _add(
        errors,
        UI,
        production_transport_isolated
        and all(command in bridge for command in P03_COMMANDS)
        and all(
            marker in e2e
            for marker in (
                "AxeBuilder",
                "serious",
                "critical",
                "setViewportSize",
                "review_receipt_v1",
                "p03-receipts-mobile.png",
            )
        ),
        "receipt UI bridge, axe workflow, or production transport isolation is incomplete",
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
        production_provider_wired=production_provider_wired,
        production_network_free=production_network_free,
        production_transport_isolated=production_transport_isolated,
    )


def parse_quality_report(result: CommandResult) -> tuple[dict[str, Any] | None, str | None]:
    if not result.captured_output or len(result.captured_output) > 4096:
        return None, "quality report is missing or exceeds its bound"
    try:
        report = json.loads(result.captured_output)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "quality report is malformed"
    if not isinstance(report, dict) or set(report) != EXPECTED_REPORT_KEYS:
        return None, "quality report schema is invalid"
    integer_fields = (
        "message_count",
        "coverage_count",
        "matched_lines",
        "gold_lines",
        "manifest_gold_lines",
        "spurious_lines",
        "unsupported_field_failures",
        "citation_failures",
    )
    if any(
        not isinstance(report[field], int) or isinstance(report[field], bool)
        for field in integer_fields
    ):
        return None, "quality report integer fields are invalid"
    recall = report["recall"]
    if (
        not isinstance(recall, (int, float))
        or isinstance(recall, bool)
        or not math.isfinite(float(recall))
    ):
        return None, "quality report recall is invalid"
    expected_strings = {
        "status": "pass",
        "test_name": (
            "frozen_corpus_has_full_recall_valid_citations_and_no_"
            "unsupported_fabrication"
        ),
        "corpus_sha256": APPROVED_CORPUS_SHA256,
        "parser_revision": "mail-parser-0.11.5/receipt-parser-v1",
        "sanitizer_revision": "html5ever-0.38/receipt-sanitizer-v1",
        "provider_id": "local-deterministic-receipt-provider",
        "provider_revision": "local-deterministic-receipt-provider-v1",
        "schema_revision": "receipt-extraction-v1",
        "ruleset_revision": "explicit-receipt-evidence-rules-v1",
    }
    if report["schema_version"] != 1 or any(
        report[key] != value for key, value in expected_strings.items()
    ):
        return None, "quality report identity or revision fields are invalid"
    if (
        report["message_count"] != EXPECTED_MESSAGES
        or report["coverage_count"] < len(REQUIRED_COVERAGE)
        or report["gold_lines"] != EXPECTED_GOLD_LINES
        or report["manifest_gold_lines"] != EXPECTED_GOLD_LINES
        or not 0 <= report["matched_lines"] <= report["gold_lines"]
        or report["spurious_lines"] != 0
        or report["unsupported_field_failures"] != 0
        or report["citation_failures"] != 0
        or float(recall) < MIN_ITEM_RECALL
        or not math.isclose(
            float(recall),
            report["matched_lines"] / report["gold_lines"],
            rel_tol=0.0,
            abs_tol=0.00005,
        )
    ):
        return None, "quality report does not satisfy the approved thresholds"
    return report, None


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
        raise ValueError("P03 evaluator artifact exceeds size limit")
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
    corpus: CorpusValidation,
    source: SourceValidation,
    report: dict[str, Any],
) -> dict[str, str | int | float | bool | None]:
    summary: dict[str, str | int | float | bool | None] = {
        "profile": "personal_mvp",
        "verification": "focused receipt-only production checks passed",
        "corpus_sha256": corpus.sha256,
        "corpus_revision": corpus.revision,
        "message_count": report["message_count"],
        "gold_lines": report["gold_lines"],
        "matched_lines": report["matched_lines"],
        "item_recall": report["recall"],
        "minimum_item_recall": MIN_ITEM_RECALL,
        "spurious_lines": report["spurious_lines"],
        "unsupported_field_failures": report["unsupported_field_failures"],
        "citation_failures": report["citation_failures"],
        "provider_id": report["provider_id"],
        "provider_revision": report["provider_revision"],
    }
    if requirement == "P03-MIM-001":
        summary["parser_revision"] = report["parser_revision"]
        summary["sanitizer_revision"] = report["sanitizer_revision"]
    if requirement == "P03-AI-001":
        summary["schema_revision"] = report["schema_revision"]
        summary["ruleset_revision"] = report["ruleset_revision"]
    if requirement == "P03-SAF-001":
        summary["production_network_free"] = source.production_network_free
        summary["remote_image_retrieval"] = "deferred/not_claimed"
    if requirement == "P03-ORD-001":
        summary["identity_model"] = "order_line_variant_catalog_separate"
    return summary


def _diagnostics(
    *,
    requested: set[str],
    errors: list[str],
    corpus: CorpusValidation,
    source: SourceValidation | None,
    command_results: dict[str, CommandResult],
    requirement_checks: dict[str, list[str]],
    report: dict[str, Any] | None,
    recorded_at: str,
    pass_evidence_written: bool,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "phase": "P03",
        "status": "fail" if errors else "pass",
        "evaluated_at": recorded_at,
        "selected_requirement_ids": sorted(requested),
        "errors": errors,
        "corpus": {
            "sha256": corpus.sha256,
            "revision": corpus.revision,
            "message_count": corpus.message_count,
            "labeled_line_count": corpus.labeled_line_count,
            "coverage_count": len(corpus.coverage),
        },
        "source_contract_sha256": (
            source.source_sha256 if source is not None else None
        ),
        "migration_sha256": (
            source.migration_sha256 if source is not None else {}
        ),
        "registered_p03_commands": (
            sorted(set(P03_COMMANDS) & set(source.registered_commands))
            if source is not None
            else []
        ),
        "registered_p03_acl_permissions": (
            sorted(
                permission
                for permission in source.acl_permissions
                if permission
                in {
                    "allow-" + command.replace("_", "-")
                    for command in P03_COMMANDS
                }
            )
            if source is not None
            else []
        ),
        "production_provider_wired": (
            source.production_provider_wired if source is not None else False
        ),
        "production_network_free": (
            source.production_network_free if source is not None else False
        ),
        "production_transport_isolated": (
            source.production_transport_isolated
            if source is not None
            else False
        ),
        "quality_report": report,
        "commands": {
            name: _result_summary(result)
            for name, result in sorted(command_results.items())
        },
        "requirement_checks": requirement_checks,
        "deferred_limitations": [
            "P03-IMG-001, image downloading, remote providers, and networking are not claimed",
            "hard-delete execution, packaged GUI, and clean-machine certification are deferred",
        ],
        "pass_evidence_written": pass_evidence_written,
    }


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(evidence_dir)
    recorded_at = utc_now()
    corpus = validate_corpus(root)
    requirement_checks = {
        requirement: ["approved_corpus_preflight"]
        for requirement in sorted(requested)
    }
    if corpus.errors:
        errors = [
            f"{requirement}: {error}"
            for requirement in sorted(requested)
            for error in corpus.errors
        ]
        diagnostics = _diagnostics(
            requested=requested,
            errors=errors,
            corpus=corpus,
            source=None,
            command_results={},
            requirement_checks=requirement_checks,
            report=None,
            recorded_at=recorded_at,
            pass_evidence_written=False,
        )
        write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        for error in errors:
            print(f"P03 receipts evaluation: {error}")
        return 1

    source = validate_source_contract(root)
    relevant_checks = [
        check for check in COMMAND_CHECKS if check.requirements & requested
    ]
    environment = os.environ.copy()
    command_results: dict[str, CommandResult] = {}
    for check in relevant_checks:
        command_results[check.name] = run_bounded_command(
            list(check.command),
            cwd=root,
            env=environment,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            capture_output=check.quality_report,
        )

    errors: list[str] = []
    for requirement in sorted(requested):
        requirement_checks[requirement].append("production_source_contract")
        for error in source.errors[requirement]:
            errors.append(f"{requirement}: {error}")
    for check in relevant_checks:
        result = command_results[check.name]
        error = _command_error(check, result)
        for requirement in sorted(check.requirements & requested):
            requirement_checks[requirement].append(check.name)
            if error:
                errors.append(f"{requirement}: {error}")

    quality_result = command_results.get("frozen_corpus_quality")
    report: dict[str, Any] | None = None
    if quality_result is not None and _command_error(
        COMMAND_CHECKS[0], quality_result
    ) is None:
        report, report_error = parse_quality_report(quality_result)
        if report_error:
            for requirement in sorted(requested):
                errors.append(f"{requirement}: {report_error}")
    elif quality_result is None:
        for requirement in sorted(requested):
            errors.append(f"{requirement}: quality report command is missing")

    errors = list(dict.fromkeys(errors))
    if errors or report is None:
        if report is None and not errors:
            errors.append("P03-QLT-001: quality report was not proven")
        diagnostics = _diagnostics(
            requested=requested,
            errors=errors,
            corpus=corpus,
            source=source,
            command_results=command_results,
            requirement_checks=requirement_checks,
            report=report,
            recorded_at=recorded_at,
            pass_evidence_written=False,
        )
        write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        for error in errors:
            print(f"P03 receipts evaluation: {error}")
        return 1

    payloads = {
        requirement: {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": "pass",
            "test": "p03_receipts::focused_production_verification",
            "recorded_at": recorded_at,
            "details": {
                "evaluator": "tools/evaluators/p03_receipts.py",
                "checks": requirement_checks[requirement],
                "public_summary": _public_summary(
                    requirement, corpus, source, report
                ),
            },
        }
        for requirement in sorted(requested)
    }
    for payload in payloads.values():
        _json_bytes(payload)
    written: list[Path] = []
    try:
        for requirement, payload in payloads.items():
            path = evidence_dir / f"{requirement}.json"
            write_atomic_json(path, payload)
            written.append(path)
        diagnostics = _diagnostics(
            requested=requested,
            errors=[],
            corpus=corpus,
            source=source,
            command_results=command_results,
            requirement_checks=requirement_checks,
            report=report,
            recorded_at=recorded_at,
            pass_evidence_written=True,
        )
        write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)
        raise
    print("P03 receipts evaluation: all selected focused checks passed")
    return 0
