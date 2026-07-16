"""Fail-closed evaluator for the approved P09 hard-deletion packet."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
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
TRIGGER_REQUIREMENT_IDS = frozenset({"P09-DEL-001"})
REQUIREMENT_IDS = SYSTEM_REQUIREMENT_IDS | TRIGGER_REQUIREMENT_IDS
DEFERRED_REQUIREMENT_IDS = frozenset({"SYS-REL-002", "SYS-A11Y-001"})

RUN_ID = "20260715T114615Z-7fa2c310"
PACKET_DIR = f"artifacts/harness/P09/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p09-deletion-diagnostics.json"
MIGRATION_FILE = "crates/wardrobe-platform/migrations/0011_hard_deletion.sql"
MIGRATION_CHECKSUM_FILE = (
    "crates/wardrobe-platform/migrations/0011_hard_deletion.sha256"
)
INVENTORY_FILE = "crates/wardrobe-platform/src/deletion_repository.rs"

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILES = 512
MAX_ARTIFACT_BYTES = 128 * 1024
MAX_PUBLIC_SUMMARY_FIELDS = 32
MAX_PUBLIC_STRING_BYTES = 256
MAX_FOCUSED_RUST_TESTS = 24
COMMAND_TIMEOUT_SECONDS = 20 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P09-hardening.md": (
        "b88c11b3f97bf7936f19cc6f6e187268eeb0c6a6c11f12de17ed2edf36455846"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "20510180ee642f557f1c67a37c5f031754a18e7b01fcd2c05a98c7d64c21b5ca"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "9de89e6c91dc514eceb63cf33f08929cf06a771b23ab909c903b5e6a3b869590"
    ),
    f"{PACKET_DIR}/review.md": (
        "4f2298d6b29179afa38e6c82d28bfa67644242f02e2b0babd5c6ad5166ad479f"
    ),
}

SOURCE_BASE_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "crates/wardrobe-core/Cargo.toml",
    "crates/wardrobe-core/src/lib.rs",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/src/deletion.rs",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/maintenance.rs",
    "crates/wardrobe-platform/src/paths.rs",
    "crates/wardrobe-platform/src/restore_repository.rs",
    INVENTORY_FILE,
    MIGRATION_FILE,
    MIGRATION_CHECKSUM_FILE,
    "src-tauri/Cargo.toml",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/src/P02Workspace.tsx",
    "apps/desktop-ui/src/P02Workspace.test.tsx",
    "apps/desktop-ui/src/catalog-bridge.ts",
    "apps/desktop-ui/src/catalog-bridge.test.ts",
    "apps/desktop-ui/src/generated/contracts.ts",
)
SOURCE_SEARCH_ROOTS = (
    "crates/wardrobe-core/src",
    "crates/wardrobe-core/tests",
    "crates/wardrobe-platform/src",
    "crates/wardrobe-platform/tests",
    "crates/wardrobe-platform/migrations",
    "src-tauri/src",
    "src-tauri/permissions",
    "apps/desktop-ui/src",
    "apps/desktop-ui/e2e",
)
SOURCE_SUFFIXES = frozenset({".rs", ".sql", ".sha256", ".ts", ".tsx", ".json", ".toml"})

CONTRACT_MARKERS = (
    "execute_deletion_v1",
    "ExecuteDeletionV1Response",
    "delete_active_local_data",
    "preview_snapshot_token",
    "plan_sha256",
    "expected_revisions",
)
RETENTION_MARKERS = (
    "backup_retention",
    "remote_retention",
    "provider_deletion_unavailable",
)
SAFETY_MARKERS = (
    "DeletionEntityKind",
    "BEGIN IMMEDIATE",
    "snapshot_expired",
    "deletion-trash",
    "retained_shared",
    "store_authority_epoch",
)
LOCK_RESTORE_MARKERS = (
    ".wardrobe.lock",
    "O_NOFOLLOW",
    "acquire_exclusive",
    "restore",
    "sanit",
)
TEST_COVERAGE_GROUPS = (
    ("schema", "inventory", "blob"),
    ("trigger", "authority", "key"),
    ("stale", "replay"),
    ("crash", "restart", "trash"),
    ("shared", "blob"),
    ("backup_retention", "remote_retention"),
    ("store_lock", "restore", "sanit"),
)
FORBIDDEN_BROWSER_SMOKE_MARKERS = (
    "playwright",
    "webdriver",
    "mock_invoke",
    "mockipc",
    "browser mock",
    "page.route",
)


@dataclass(frozen=True)
class PacketValidation:
    errors: tuple[str, ...]
    packet_sha256: str
    hashes: dict[str, str]


@dataclass(frozen=True)
class RustTest:
    relative: str
    package: str
    target_kind: str
    target_name: str
    name: str
    body: str


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]
    require_rust_test: bool = False
    compiled_deletion_smoke: bool = False


@dataclass(frozen=True)
class SourceValidation:
    errors: tuple[str, ...]
    source_sha256: str
    source_hashes: dict[str, str]
    source_file_count: int
    migration_sha256: str
    schema_table_count: int
    blob_owner_count: int
    focused_checks: tuple[CommandCheck, ...]
    smoke_check: CommandCheck | None
    has_tauri: bool
    has_ui: bool


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bounded(path: Path) -> bytes | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_SOURCE_BYTES + 1)
    except OSError:
        return None
    return data if len(data) <= MAX_SOURCE_BYTES else None


def _json_object(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def validate_packet(root: Path) -> PacketValidation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
    aggregate = hashlib.sha256()
    for relative, expected in EXPECTED_PACKET_HASHES.items():
        data = _read_bounded(root / relative)
        if data is None:
            errors.append(f"frozen packet file is unreadable or oversized: {relative}")
            continue
        contents[relative] = data
        actual = _sha256(data)
        hashes[relative] = actual
        if actual != expected:
            errors.append(f"frozen packet hash changed: {relative}")
        aggregate.update(relative.encode())
        aggregate.update(b"\0")
        aggregate.update(data)
        aggregate.update(b"\0")

    state_data = _read_bounded(root / STATE_FILE)
    state = _json_object(state_data or b"")
    if state_data is None:
        errors.append(f"approved packet state is unreadable or oversized: {STATE_FILE}")

    requirements = _json_object(contents.get(f"{PACKET_DIR}/requirements.json", b""))
    selected = requirements.get("selected_requirement_ids")
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
    if (
        requirements.get("phase") != "P09"
        or selected != sorted(TRIGGER_REQUIREMENT_IDS)
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("frozen P09 deletion requirement contract is invalid")

    review = state.get("review")
    if (
        state.get("phase") != "P09"
        or state.get("run_id") != RUN_ID
        or state.get("status")
        not in {"APPROVED", "BUILT", "EVALUATED", "EVALUATION_FAILED"}
        or state.get("selected_requirement_ids") != selected
        or not isinstance(review, dict)
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash")
        != EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"]
        or state.get("spec_hashes", {}).get("specs/system.md")
        != EXPECTED_PACKET_HASHES["specs/system.md"]
        or state.get("spec_hashes", {}).get("specs/phases/P09-hardening.md")
        != EXPECTED_PACKET_HASHES["specs/phases/P09-hardening.md"]
    ):
        errors.append("P09 deletion packet is not independently approved")

    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(errors="replace")
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append("approved P09 deletion review decision is missing")

    return PacketValidation(
        errors=tuple(dict.fromkeys(errors)),
        packet_sha256=aggregate.hexdigest(),
        hashes=hashes,
    )


def _source_paths(root: Path) -> tuple[str, ...]:
    paths = set(SOURCE_BASE_FILES)
    for relative_root in SOURCE_SEARCH_ROOTS:
        search_root = root / relative_root
        if not search_root.is_dir():
            continue
        try:
            for path in search_root.rglob("*"):
                if path.is_file() and path.suffix in SOURCE_SUFFIXES:
                    paths.add(path.relative_to(root).as_posix())
        except OSError:
            continue
    return tuple(sorted(paths))


def _sql_table_blocks(sql: str) -> dict[str, str]:
    blocks: dict[str, str] = {}
    pattern = re.compile(
        r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
        r"[`\"\[]?(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)[`\"\]]?\s*\(",
        re.IGNORECASE,
    )
    for match in pattern.finditer(sql):
        depth = 1
        index = match.end()
        quote = ""
        while index < len(sql) and depth:
            character = sql[index]
            if quote:
                if character == quote and sql[index - 1] != "\\":
                    quote = ""
            elif character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            index += 1
        if depth == 0:
            blocks[match.group("name").lower()] = sql[match.end() : index - 1]
    return blocks


def _schema_inventory(
    migration_sources: dict[str, str],
) -> tuple[set[str], set[str]]:
    tables: set[str] = set()
    blob_owners: set[str] = set()
    blob_column = re.compile(
        r"\b(?:[a-z][a-z0-9_]*_)?blob_sha256\b",
        re.IGNORECASE,
    )
    for text in migration_sources.values():
        for table, body in _sql_table_blocks(text).items():
            tables.add(table)
            if re.search(
                r"\bREFERENCES\s+blobs\s*\(", body, re.IGNORECASE
            ) or blob_column.search(body):
                blob_owners.add(table)
    return tables, blob_owners


def _trigger_authority_errors(
    migration: str,
    blob_owners: set[str],
) -> tuple[list[str], int]:
    errors: list[str] = []
    pattern = re.compile(
        r"\bCREATE\s+TRIGGER\s+hd_[a-zA-Z0-9_]+\s+"
        r"BEFORE\s+DELETE\s+ON\s+(?P<table>[a-zA-Z_][a-zA-Z0-9_]*)"
        r"\s+BEGIN(?P<body>.*?)END\s*;",
        re.IGNORECASE | re.DOTALL,
    )
    trigger_tables: set[str] = set()
    for match in pattern.finditer(migration):
        table = match.group("table").lower()
        body = match.group("body")
        lower = body.lower()
        trigger_tables.add(table)
        exact_kind = re.search(
            rf"\bp\.entity_kind\s*=\s*'{re.escape(table)}'",
            body,
            re.IGNORECASE,
        )
        exact_key = re.search(
            r"\bp\.key_json\s*=\s*json_array\s*\(\s*OLD\."
            r"[a-zA-Z_][a-zA-Z0-9_]*(?:\s*,\s*OLD\."
            r"[a-zA-Z_][a-zA-Z0-9_]*)*\s*\)",
            body,
            re.IGNORECASE,
        )
        if (
            "deletion_execution_authority" not in lower
            or "deletion_plan_entries" not in lower
            or exact_kind is None
            or exact_key is None
        ):
            errors.append(f"hard-delete trigger lacks exact row authority: {table}")

    domain_blob_owners = {
        table for table in blob_owners if not table.startswith("deletion_")
    }
    missing_blob_triggers = sorted(domain_blob_owners - trigger_tables)
    if missing_blob_triggers or "blobs" not in trigger_tables:
        errors.append("exact row-key triggers do not cover every blob owner")
    if not trigger_tables:
        errors.append("exact row-key hard-delete triggers are missing")
    return errors, len(trigger_tables)


def _rust_tests(sources: dict[str, str]) -> tuple[RustTest, ...]:
    pattern = re.compile(
        r"(?m)^\s*#\[(?:(?:tokio|async_std)::)?test[^\]]*\]\s*"
        r"(?:async\s+)?fn\s+(?P<name>[a-zA-Z0-9_]+)\s*\("
    )
    tests: list[RustTest] = []
    for relative, text in sources.items():
        if not relative.endswith(".rs"):
            continue
        matches = list(pattern.finditer(text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            if relative.startswith("crates/wardrobe-core/tests/"):
                package = "wardrobe-core"
                target_kind = "test"
            elif relative.startswith("crates/wardrobe-core/src/"):
                package = "wardrobe-core"
                target_kind = "lib"
            elif relative.startswith("crates/wardrobe-platform/tests/"):
                package = "wardrobe-platform"
                target_kind = "test"
            elif relative.startswith("crates/wardrobe-platform/src/"):
                package = "wardrobe-platform"
                target_kind = "lib"
            elif relative.startswith("src-tauri/"):
                package = "wardrobe-desktop"
                target_kind = "lib"
            else:
                continue
            tests.append(
                RustTest(
                    relative=relative,
                    package=package,
                    target_kind=target_kind,
                    target_name=Path(relative).stem,
                    name=match.group("name"),
                    body=text[match.start() : end],
                )
            )
    return tuple(tests)


def _rust_test_check(
    test: RustTest,
    *,
    name: str,
    compiled_smoke: bool = False,
) -> CommandCheck:
    target = ("--test", test.target_name) if test.target_kind == "test" else ("--lib",)
    exact = ("--exact",) if test.target_kind == "test" else ()
    return CommandCheck(
        name=name,
        command=(
            "cargo",
            "test",
            "--offline",
            "-p",
            test.package,
            *target,
            test.name,
            "--",
            *exact,
            "--test-threads=1",
        ),
        require_rust_test=True,
        compiled_deletion_smoke=compiled_smoke,
    )


def _is_deletion_test(test: RustTest) -> bool:
    lower = f"{test.name}\n{test.body}".lower()
    return (
        "execute_deletion_v1" in lower
        or "executedeletionv1" in lower
        or "hard_deletion" in lower
        or "deletion_run" in lower
        or "deletion_authority" in lower
        or "deletion-trash" in lower
    )


def _is_compiled_smoke(test: RustTest) -> bool:
    lower = f"{test.name}\n{test.body}".lower()
    return (
        test.package in {"wardrobe-platform", "wardrobe-desktop"}
        and _is_deletion_test(test)
        and "restart" in lower
        and (
            "sqlite" in lower or "database::open" in lower or "catalog.sqlite3" in lower
        )
        and any(marker in lower for marker in ("tempdir", "temp_dir", "std::fs"))
        and any(marker in lower for marker in ("residual", "trash", "absent"))
        and "shared" in lower
        and "backup" in lower
        and "remote" in lower
        and "execute_deletion(&request)" in lower
        and "set_test_drain_fault" in lower
        and "response.validate()" in lower
        and "let run_id = simulate_crash_after_relational_commit" not in lower
        and not any(marker in lower for marker in FORBIDDEN_BROWSER_SMOKE_MARKERS)
    )


def _focused_checks(
    tests: tuple[RustTest, ...],
    ui_test_files: tuple[str, ...],
) -> tuple[tuple[CommandCheck, ...], CommandCheck | None, list[str]]:
    errors: list[str] = []
    smoke_tests = tuple(test for test in tests if _is_compiled_smoke(test))
    smoke_check: CommandCheck | None = None
    if len(smoke_tests) != 1:
        errors.append(
            "exactly one compiled real SQLite/filesystem deletion restart smoke is required"
        )
    else:
        smoke_check = _rust_test_check(
            smoke_tests[0],
            name="compiled_backend_deletion_restart_residual_smoke",
            compiled_smoke=True,
        )

    relevant = tuple(test for test in tests if _is_deletion_test(test))
    core = tuple(test for test in relevant if test.package == "wardrobe-core")
    platform = tuple(
        test
        for test in relevant
        if test.package == "wardrobe-platform" and test not in smoke_tests
    )
    tauri = tuple(test for test in relevant if test.package == "wardrobe-desktop")
    if not core:
        errors.append("focused core hard-deletion contract tests are missing")
    if not platform:
        errors.append("focused platform hard-deletion tests are missing")
    if not tauri:
        errors.append("focused Tauri hard-deletion command tests are missing")
    if not ui_test_files:
        errors.append("focused UI hard-deletion tests are missing")

    platform_test_text = "\n".join(test.body.lower() for test in platform + smoke_tests)
    for group in TEST_COVERAGE_GROUPS:
        if not all(marker in platform_test_text for marker in group):
            errors.append("focused hard-deletion tests do not cover " + "/".join(group))

    selected = (*core, *platform, *tauri)
    if len(selected) > MAX_FOCUSED_RUST_TESTS:
        errors.append("focused hard-deletion Rust test inventory is unbounded")
        selected = selected[:MAX_FOCUSED_RUST_TESTS]
    checks = [
        _rust_test_check(test, name=f"focused_{test.package}_{test.name}")
        for test in selected
    ]
    if ui_test_files:
        checks.append(
            CommandCheck(
                "ui_hard_deletion",
                (
                    "npm",
                    "--workspace",
                    "@wardrobe/desktop-ui",
                    "test",
                    "--",
                    "--run",
                    *ui_test_files,
                ),
            )
        )
        checks.append(
            CommandCheck(
                "ui_production_build",
                ("npm", "--workspace", "@wardrobe/desktop-ui", "run", "build"),
            )
        )
    return tuple(checks), smoke_check, errors


def validate_source(root: Path) -> SourceValidation:
    errors: list[str] = []
    decoded: dict[str, str] = {}
    hashes: dict[str, str] = {}
    aggregate = hashlib.sha256()
    total_bytes = 0
    source_paths = _source_paths(root)
    if len(source_paths) > MAX_SOURCE_FILES:
        errors.append("P09 deletion source inventory exceeds file bound")
        source_paths = source_paths[:MAX_SOURCE_FILES]
    for relative in source_paths:
        data = _read_bounded(root / relative)
        if data is None:
            if relative in SOURCE_BASE_FILES:
                errors.append(
                    f"required P09 deletion source is unreadable or oversized: {relative}"
                )
            continue
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_SOURCE_BYTES:
            errors.append("P09 deletion source inventory exceeds byte bound")
            break
        digest = _sha256(data)
        hashes[relative] = digest
        aggregate.update(relative.encode())
        aggregate.update(b"\0")
        aggregate.update(data)
        aggregate.update(b"\0")
        try:
            decoded[relative] = data.decode()
        except UnicodeDecodeError:
            errors.append(f"required P09 deletion source is not UTF-8: {relative}")

    joined = "\n".join(decoded.values())
    for label, markers in (
        ("strict execute contract", CONTRACT_MARKERS),
        ("separate backup and remote retention reporting", RETENTION_MARKERS),
        ("hard-deletion safety", SAFETY_MARKERS),
        ("store lock and restore sanitization", LOCK_RESTORE_MARKERS),
    ):
        if any(marker not in joined for marker in markers):
            errors.append(f"P09 {label} source markers are incomplete")

    migration = decoded.get(MIGRATION_FILE, "")
    migration_sha256 = hashes.get(MIGRATION_FILE, "")
    checksum = decoded.get(MIGRATION_CHECKSUM_FILE, "").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", checksum) or checksum != migration_sha256:
        errors.append("P09 hard-deletion migration checksum is invalid")

    migration_sources = {
        relative: text
        for relative, text in decoded.items()
        if relative.startswith("crates/wardrobe-platform/migrations/")
        and relative.endswith(".sql")
    }
    tables, blob_owners = _schema_inventory(migration_sources)
    inventory = decoded.get(INVENTORY_FILE, "")
    missing_tables = sorted(
        table
        for table in tables
        if not re.search(rf"\b{re.escape(table)}\b", inventory)
    )
    missing_blob_owners = sorted(
        table
        for table in blob_owners
        if not re.search(rf"\b{re.escape(table)}\b", inventory)
    )
    if not tables or missing_tables:
        errors.append("static deletion inventory does not cover every current table")
    if not blob_owners or missing_blob_owners:
        errors.append("static deletion inventory does not cover every blob owner")
    if (
        "DeletionEntityKind" not in inventory
        or "OLD." not in migration
        or "deletion_authority" not in migration.lower()
        or not re.search(
            r"\b(?:entity_key|canonical_key|row_key|key_json)\b",
            migration,
        )
    ):
        errors.append("exact row-key trigger authority is not statically established")
    trigger_errors, _ = _trigger_authority_errors(migration, blob_owners)
    errors.extend(trigger_errors)

    tests = _rust_tests(decoded)
    ui_test_files = tuple(
        sorted(
            relative.removeprefix("apps/desktop-ui/")
            for relative, text in decoded.items()
            if relative.startswith("apps/desktop-ui/")
            and relative.endswith((".test.ts", ".test.tsx"))
            and "execute_deletion_v1" in text
            and "backup_retention" in text
            and "remote_retention" in text
        )
    )
    focused, smoke, focus_errors = _focused_checks(tests, ui_test_files)
    errors.extend(focus_errors)

    has_tauri = "execute_deletion_v1" in decoded.get(
        "src-tauri/src/lib.rs", ""
    ) and any(
        "execute_deletion_v1" in text
        for relative, text in decoded.items()
        if relative.startswith("src-tauri/permissions/")
    )
    has_ui = bool(ui_test_files) and "execute_deletion_v1" in joined
    if not has_tauri:
        errors.append("P09 Tauri hard-deletion command wiring is missing")
    if not has_ui:
        errors.append("P09 hard-deletion UI wiring is missing")

    return SourceValidation(
        errors=tuple(dict.fromkeys(errors)),
        source_sha256=aggregate.hexdigest(),
        source_hashes=hashes,
        source_file_count=len(decoded),
        migration_sha256=migration_sha256,
        schema_table_count=len(tables),
        blob_owner_count=len(blob_owners),
        focused_checks=focused,
        smoke_check=smoke,
        has_tauri=has_tauri,
        has_ui=has_ui,
    )


def command_checks(source: SourceValidation) -> tuple[CommandCheck, ...]:
    if source.smoke_check is None:
        return source.focused_checks
    return (*source.focused_checks, source.smoke_check)


def _result_summary(result: CommandResult) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "output_sha256": result.output_sha256,
        "output_bytes": result.output_bytes,
        "duration_ms": result.duration_ms,
        "timed_out": result.timed_out,
        "launch_failed": result.launch_failed,
        "output_limit_exceeded": result.output_limit_exceeded,
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
    if check.require_rust_test:
        output = result.captured_output.decode("utf-8", errors="replace")
        counts = [
            int(value) for value in re.findall(r"\brunning\s+(\d+)\s+tests?\b", output)
        ]
        if not counts or max(counts) < 1:
            return f"{check.name} matched no Rust tests"
        if check.compiled_deletion_smoke and sum(counts) != 1:
            return f"{check.name} must execute exactly one Rust test"
    return None


def _validate_public_summary(value: Any) -> dict[str, str | bool | int | float]:
    if not isinstance(value, dict) or len(value) > MAX_PUBLIC_SUMMARY_FIELDS:
        raise ValueError("public_summary must be a bounded object")
    validated: dict[str, str | bool | int | float] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
            raise ValueError("public_summary has an invalid key")
        if isinstance(item, str):
            if (
                not item
                or "\n" in item
                or len(item.encode("utf-8")) > MAX_PUBLIC_STRING_BYTES
            ):
                raise ValueError("public_summary has an invalid string")
        elif isinstance(item, bool):
            pass
        elif isinstance(item, (int, float)) and not isinstance(item, complex):
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError("public_summary has a non-finite number")
            if abs(item) > 9_007_199_254_740_991:
                raise ValueError("public_summary has an unbounded number")
        else:
            raise ValueError("public_summary values must be bounded primitives")
        validated[key] = item
    return validated


def _validate_evidence_record(value: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "requirement_id",
        "status",
        "test",
        "recorded_at",
        "details",
    }
    details = value.get("details")
    test_name = value.get("test")
    recorded_at = value.get("recorded_at")
    if (
        set(value) != required
        or value.get("schema_version") != 1
        or value.get("requirement_id") not in REQUIREMENT_IDS
        or value.get("status") not in {"pass", "deferred"}
        or not isinstance(test_name, str)
        or not test_name
        or "\n" in test_name
        or len(test_name.encode("utf-8")) > 256
        or not isinstance(recorded_at, str)
        or not recorded_at
        or "\n" in recorded_at
        or len(recorded_at.encode("utf-8")) > 64
        or not isinstance(details, dict)
        or set(details)
        != {
            "checks_passed",
            "compiled_deletion_smoke",
            "verification_sha256",
            "public_summary",
        }
        or not isinstance(details["checks_passed"], int)
        or isinstance(details["checks_passed"], bool)
        or not 0 <= details["checks_passed"] <= 32
        or not isinstance(details["compiled_deletion_smoke"], bool)
        or not re.fullmatch(r"[0-9a-f]{64}", details["verification_sha256"])
    ):
        raise ValueError("malformed P09 deletion evidence record")
    summary = _validate_public_summary(details["public_summary"])
    if value["status"] == "deferred" and (
        summary.get("feature_enabled") is not False
        or summary.get("acceptance_claim") != "deferred_not_passed"
        or not isinstance(summary.get("deferred_limitation"), str)
    ):
        raise ValueError("malformed deferred P09 deletion evidence record")


def _bounded_json_bytes(value: dict[str, Any]) -> bytes:
    data = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P09 deletion evaluator artifact exceeds size limit")
    return data


def _write_bounded_json(path: Path, value: dict[str, Any]) -> None:
    _bounded_json_bytes(value)
    write_atomic_json(path, value)


def _remove_stale_outputs(evidence_dir: Path) -> None:
    names = {f"{requirement}.json" for requirement in REQUIREMENT_IDS}
    names.add(DIAGNOSTICS_NAME)
    for name in names:
        (evidence_dir / name).unlink(missing_ok=True)
        for temporary in evidence_dir.glob(f".{name}.*.tmp"):
            temporary.unlink(missing_ok=True)


def _verification_hash(
    requirement: str,
    packet: PacketValidation,
    source: SourceValidation,
    checks: dict[str, dict[str, Any]],
) -> str:
    value = {
        "requirement_id": requirement,
        "packet_sha256": packet.packet_sha256,
        "source_sha256": source.source_sha256,
        "migration_sha256": source.migration_sha256,
        "checks": checks,
    }
    return _sha256(_bounded_json_bytes(value))


def _public_summary(
    requirement: str,
    packet: PacketValidation,
    source: SourceValidation,
    check_count: int,
) -> dict[str, str | bool | int | float]:
    common: dict[str, str | bool | int | float] = {
        "profile": "personal_mvp",
        "packet_sha256": packet.packet_sha256,
        "source_sha256": source.source_sha256,
        "migration_sha256": source.migration_sha256,
        "checks_passed": check_count,
        "compiled_backend_deletion_smoke": True,
        "actual_sqlite": True,
        "actual_filesystem": True,
        "browser_mock_used_for_deletion_smoke": False,
        "schema_table_count": source.schema_table_count,
        "blob_owner_count": source.blob_owner_count,
        "exact_row_key_authority": True,
        "stale_replay_crash_covered": True,
        "shared_blob_covered": True,
        "separate_retention_reporting": True,
        "store_lock_restore_sanitization": True,
        "signed_packaged_app_tested": False,
        "offline_network_disabled_tested": False,
        "aggregate_accessibility_tested": False,
    }
    if requirement in DEFERRED_REQUIREMENT_IDS:
        limitation = (
            "No signed packaged network-disabled offline acceptance was run."
            if requirement == "SYS-REL-002"
            else "Packet UI checks do not establish aggregate core-workflow accessibility."
        )
        return _validate_public_summary(
            {
                **common,
                "feature_enabled": False,
                "acceptance_claim": "deferred_not_passed",
                "deferred_limitation": limitation,
            }
        )
    return _validate_public_summary(
        {
            **common,
            "feature_enabled": True,
            "acceptance_claim": "focused_local_requirement_passed",
        }
    )


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    if not (selected & TRIGGER_REQUIREMENT_IDS):
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(evidence_dir)
    recorded_at = utc_now()
    packet = validate_packet(root)
    source: SourceValidation | None = None
    checks: dict[str, dict[str, Any]] = {}
    failures = list(packet.errors)
    compiled_deletion_smoke = False

    if selected & TRIGGER_REQUIREMENT_IDS != TRIGGER_REQUIREMENT_IDS:
        failures.append("selected P09 deletion requirement ID is incomplete")
    if not failures:
        source = validate_source(root)
        failures.extend(source.errors)

    if not failures and source is not None:
        environment = os.environ.copy()
        environment.pop("HARNESS_RUN_DIR", None)
        environment.pop("HARNESS_EVIDENCE_DIR", None)
        environment.pop("OPENAI_API_KEY", None)
        for check in command_checks(source):
            result = run_bounded_command(
                list(check.command),
                cwd=root,
                env=environment,
                timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                capture_output=check.require_rust_test,
            )
            checks[check.name] = _result_summary(result)
            error = _command_error(check, result)
            if error:
                failures.append(error)
                break
            if check.compiled_deletion_smoke:
                compiled_deletion_smoke = True
        if not failures and not compiled_deletion_smoke:
            failures.append("compiled-backend deletion restart smoke did not execute")

    diagnostics = {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "recorded_at": recorded_at,
        "selected_requirement_ids": sorted(selected & TRIGGER_REQUIREMENT_IDS),
        "evidence_requirement_count": len(REQUIREMENT_IDS),
        "failures": list(dict.fromkeys(failures)),
        "packet_sha256": packet.packet_sha256,
        "packet_hashes": packet.hashes,
        "source_sha256": source.source_sha256 if source else "",
        "source_hashes": source.source_hashes if source else {},
        "source_file_count": source.source_file_count if source else 0,
        "migration_sha256": source.migration_sha256 if source else "",
        "schema_table_count": source.schema_table_count if source else 0,
        "blob_owner_count": source.blob_owner_count if source else 0,
        "checks": checks,
        "compiled_backend_deletion_smoke": compiled_deletion_smoke,
        "browser_mock_deletion_smoke": False,
        "signed_packaged_app_tested": False,
        "offline_network_disabled_tested": False,
        "aggregate_accessibility_tested": False,
        "deferred_requirement_count": len(DEFERRED_REQUIREMENT_IDS),
        "pass_evidence_written": not failures,
    }
    if failures or source is None:
        _write_bounded_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    payloads: dict[str, dict[str, Any]] = {}
    for requirement in sorted(REQUIREMENT_IDS):
        deferred = requirement in DEFERRED_REQUIREMENT_IDS
        payload = {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": "deferred" if deferred else "pass",
            "test": (
                "p09_deletion::disabled_unestablished_acceptance"
                if deferred
                else "p09_deletion::focused_hard_deletion_verification"
            ),
            "recorded_at": recorded_at,
            "details": {
                "checks_passed": len(checks),
                "compiled_deletion_smoke": compiled_deletion_smoke,
                "verification_sha256": _verification_hash(
                    requirement, packet, source, checks
                ),
                "public_summary": _public_summary(
                    requirement, packet, source, len(checks)
                ),
            },
        }
        _validate_evidence_record(payload)
        _bounded_json_bytes(payload)
        payloads[requirement] = payload

    _bounded_json_bytes(diagnostics)
    written: list[Path] = []
    try:
        for requirement, payload in payloads.items():
            path = evidence_dir / f"{requirement}.json"
            _write_bounded_json(path, payload)
            written.append(path)
        _write_bounded_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)
        raise
    return 0
