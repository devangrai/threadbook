"""Fail-closed evaluator for the approved P09 backup and restore packet."""

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
TRIGGER_REQUIREMENT_IDS = frozenset({"P09-BKP-001", "P09-RST-001"})
REQUIREMENT_IDS = SYSTEM_REQUIREMENT_IDS | TRIGGER_REQUIREMENT_IDS
DEFERRED_REQUIREMENT_IDS = frozenset(
    {"SYS-REL-002", "SYS-DEL-001", "SYS-A11Y-001"}
)

RUN_ID = "20260715T110300Z-c4ac8dfe"
PACKET_DIR = f"artifacts/harness/P09/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p09-backup-diagnostics.json"

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024
MAX_PUBLIC_SUMMARY_FIELDS = 32
MAX_PUBLIC_STRING_BYTES = 256
COMMAND_TIMEOUT_SECONDS = 20 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P09-hardening.md": (
        "b88c11b3f97bf7936f19cc6f6e187268eeb0c6a6c11f12de17ed2edf36455846"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "eb3a4b66a0ef35ae3a46d88cbdeb0911c9e2e215a73ec75280ac05ec78abe2cb"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "d0dc939cd016a13c4a2dee722a059d728cac03e04a839514dfbc25570f46f590"
    ),
    f"{PACKET_DIR}/review.md": (
        "b440c80b99c963973e2d9c0edba138fe7540c383495151ae7ccae27acb2f069f"
    ),
}

SOURCE_BASE_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "crates/wardrobe-core/Cargo.toml",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/src/lib.rs",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/paths.rs",
)
SOURCE_SEARCH_ROOTS = (
    "crates/wardrobe-core/src",
    "crates/wardrobe-core/tests",
    "crates/wardrobe-platform/src",
    "crates/wardrobe-platform/tests",
    "src-tauri",
    "apps/desktop-ui/src",
    "apps/desktop-ui/e2e",
)
SOURCE_SUFFIXES = frozenset({".rs", ".ts", ".tsx", ".json", ".toml"})
SOURCE_NAME_TERMS = ("backup", "restore", "storage", "setting")

SENSITIVE_FIELD_TERMS = frozenset(
    {
        "access_token",
        "api_key",
        "credential",
        "credentials",
        "file_path",
        "filename",
        "image_bytes",
        "model_payload",
        "personal_path",
        "prompt",
        "refresh_token",
        "secret",
        "source_content",
        "source_path",
    }
)


@dataclass(frozen=True)
class PacketValidation:
    errors: tuple[str, ...]
    packet_sha256: str
    hashes: dict[str, str]


@dataclass(frozen=True)
class SourceValidation:
    errors: tuple[str, ...]
    source_sha256: str
    source_file_count: int
    restart_smoke_target: str
    restart_smoke_filter: str
    has_tauri: bool
    has_ui: bool
    manifest_sensitive_field_count: int
    evidence_sensitive_field_count: int


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]
    require_rust_test: bool = False
    compiled_restart_smoke: bool = False


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

    requirements = _json_object(
        contents.get(f"{PACKET_DIR}/requirements.json", b"")
    )
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
        errors.append("frozen P09 requirement contract is invalid")

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
        errors.append("P09 packet is not independently approved")

    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(
        errors="replace"
    )
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append("approved P09 review decision is missing")

    return PacketValidation(
        tuple(dict.fromkeys(errors)),
        aggregate.hexdigest(),
        hashes,
    )


def _source_paths(root: Path) -> tuple[str, ...]:
    paths = set(SOURCE_BASE_FILES)
    for relative_root in SOURCE_SEARCH_ROOTS:
        search_root = root / relative_root
        if not search_root.is_dir():
            continue
        try:
            candidates = search_root.rglob("*")
            for path in candidates:
                if (
                    path.is_file()
                    and path.suffix in SOURCE_SUFFIXES
                    and any(term in path.name.lower() for term in SOURCE_NAME_TERMS)
                ):
                    paths.add(path.relative_to(root).as_posix())
        except OSError:
            continue
    for relative in (
        "src-tauri/src/lib.rs",
        "src-tauri/build.rs",
        "src-tauri/capabilities/main.json",
        "apps/desktop-ui/package.json",
        "apps/desktop-ui/src/App.tsx",
        "apps/desktop-ui/src/generated/contracts.ts",
        "apps/desktop-ui/src/styles.css",
    ):
        if (root / relative).is_file():
            paths.add(relative)
    return tuple(sorted(paths))


def _named_struct_bodies(text: str, name_term: str) -> tuple[str, ...]:
    pattern = re.compile(
        rf"\bstruct\s+\w*{re.escape(name_term)}\w*\s*\{{(?P<body>.*?)\n\s*\}}",
        re.IGNORECASE | re.DOTALL,
    )
    return tuple(match.group("body") for match in pattern.finditer(text))


def _sensitive_schema_fields(text: str, name_term: str) -> tuple[str, ...]:
    fields: set[str] = set()
    for body in _named_struct_bodies(text, name_term):
        for line in body.splitlines():
            match = re.match(
                r"\s*(?:pub(?:\([^)]*\))?\s+)?([a-z][a-z0-9_]*)\s*:",
                line,
            )
            if match and (
                match.group(1) in SENSITIVE_FIELD_TERMS
                or match.group(1).endswith("_path")
                or match.group(1).endswith("_content")
                or match.group(1).endswith("_bytes")
            ):
                fields.add(match.group(1))
    return tuple(sorted(fields))


def _restart_smoke(
    root: Path,
    sources: dict[str, str],
) -> tuple[str, str, list[str]]:
    del root
    errors: list[str] = []
    candidates: list[tuple[str, str]] = []
    for relative, text in sources.items():
        lower = text.lower()
        if (
            relative.endswith(".rs")
            and (
                relative.startswith("crates/wardrobe-platform/tests/")
                or relative.startswith("crates/wardrobe-platform/src/")
                or relative.startswith("src-tauri/tests/")
                or relative.startswith("src-tauri/src/")
            )
            and "backup" in lower
            and "restore" in lower
            and "restart" in lower
        ):
            candidates.append((relative, text))
    if not candidates:
        return "", "", ["compiled-backend backup/restore restart smoke is missing"]

    test_pattern = re.compile(
        r"(?m)^\s*#\[(?:(?:tokio|async_std)::)?test[^\]]*\]\s*"
        r"(?:async\s+)?fn\s+"
        r"(?P<name>[a-zA-Z0-9_]+)\s*\("
    )
    for relative, text in candidates:
        matches = list(test_pattern.finditer(text))
        for index, match in enumerate(matches):
            if "restart" not in match.group("name").lower():
                continue
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            test_text = text[match.start() : end].lower()
            if "backup" not in test_text or "restore" not in test_text:
                continue
            actual_sqlite = (
                "sqlite" in test_text
                or "catalog.sqlite3" in test_text
                or "database::open" in test_text
            )
            actual_filesystem = (
                "tempdir" in test_text
                or "temp_dir" in test_text
                or "std::fs" in test_text
                or "filesystem" in test_text
            )
            forbidden_mock = any(
                marker in test_text
                for marker in (
                    "playwright",
                    "webdriver",
                    "mock_invoke",
                    "mockipc",
                    "browser mock",
                )
            )
            if not actual_sqlite or not actual_filesystem or forbidden_mock:
                continue
            if relative.startswith("crates/wardrobe-platform/tests/"):
                target = f"platform-test:{Path(relative).stem}"
            elif relative.startswith("crates/wardrobe-platform/src/"):
                target = "platform-lib"
            elif relative.startswith("src-tauri/tests/"):
                target = f"desktop-test:{Path(relative).stem}"
            else:
                target = "desktop-lib"
            return target, match.group("name"), []

    errors.append(
        "restart smoke must use the compiled Rust backend with actual SQLite and filesystem state"
    )
    return "", "", errors


def validate_source(root: Path) -> SourceValidation:
    errors: list[str] = []
    decoded: dict[str, str] = {}
    aggregate = hashlib.sha256()
    source_paths = _source_paths(root)
    for relative in source_paths:
        data = _read_bounded(root / relative)
        if data is None:
            errors.append(f"required P09 source is unreadable or oversized: {relative}")
            continue
        aggregate.update(relative.encode())
        aggregate.update(b"\0")
        aggregate.update(data)
        aggregate.update(b"\0")
        try:
            decoded[relative] = data.decode()
        except UnicodeDecodeError:
            errors.append(f"required P09 source is not UTF-8: {relative}")

    joined = "\n".join(decoded.values())
    required_markers = (
        "create_backup_v1",
        "list_backups_v1",
        "prepare_restore_v1",
        "BackupRecordV1",
        "asset_manifest_version",
        "backup_repository",
        "restore_repository",
        "restore-request",
    )
    missing_markers = [marker for marker in required_markers if marker not in joined]
    if missing_markers:
        errors.append("P09 backup/restore source contract is incomplete")

    manifest_fields = _sensitive_schema_fields(joined, "Manifest")
    evidence_fields = _sensitive_schema_fields(joined, "Evidence")
    if manifest_fields:
        errors.append("backup manifest exposes secret, path, or source-content fields")
    if evidence_fields:
        errors.append("backup evidence exposes secret, path, or source-content fields")

    security_markers = (
        "deny_unknown_fields",
        "manifest.sha256",
        "integrity_check",
        "foreign_key_check",
        "O_NOFOLLOW",
        "fsync",
    )
    if any(marker not in joined for marker in security_markers):
        errors.append("P09 strict manifest or filesystem verification is incomplete")
    sidecar_family = (
        ("-wal" in joined and "-shm" in joined and "database_family" in joined)
        or ("catalog.sqlite3-wal" in joined and "catalog.sqlite3-shm" in joined)
    )
    phase_groups = (
        ("requested", "Requested"),
        ("assets_installed", "AssetsInstalled"),
        ("live_quarantined", "LiveQuarantined"),
        ("database_installed", "DatabaseInstalled"),
        ("validated", "Validated"),
        ("committed", "Committed"),
    )
    if not sidecar_family or any(
        not any(spelling in joined for spelling in spellings)
        for spellings in phase_groups
    ):
        errors.append("P09 durable database-family restore phases are incomplete")

    restart_target, restart_filter, restart_errors = _restart_smoke(
        root, decoded
    )
    errors.extend(restart_errors)
    has_tauri = any(
        relative.startswith("src-tauri/") and "backup" in text.lower()
        for relative, text in decoded.items()
    )
    has_ui = any(
        relative.startswith("apps/desktop-ui/")
        and ("backup" in text.lower() or "restore" in text.lower())
        for relative, text in decoded.items()
    )
    if not has_tauri:
        errors.append("P09 Tauri backup/restore command wiring is missing")
    if not has_ui:
        errors.append("P09 backup/restore UI wiring is missing")

    return SourceValidation(
        errors=tuple(dict.fromkeys(errors)),
        source_sha256=aggregate.hexdigest(),
        source_file_count=len(decoded),
        restart_smoke_target=restart_target,
        restart_smoke_filter=restart_filter,
        has_tauri=has_tauri,
        has_ui=has_ui,
        manifest_sensitive_field_count=len(manifest_fields),
        evidence_sensitive_field_count=len(evidence_fields),
    )


def command_checks(source: SourceValidation) -> tuple[CommandCheck, ...]:
    restart_parts: tuple[str, ...]
    exact_parts: tuple[str, ...]
    if source.restart_smoke_target.startswith("platform-test:"):
        restart_parts = (
            "-p",
            "wardrobe-platform",
            "--test",
            source.restart_smoke_target.partition(":")[2],
        )
        exact_parts = ("--exact",)
    elif source.restart_smoke_target == "platform-lib":
        restart_parts = ("-p", "wardrobe-platform", "--lib")
        exact_parts = ()
    elif source.restart_smoke_target.startswith("desktop-test:"):
        restart_parts = (
            "-p",
            "wardrobe-desktop",
            "--test",
            source.restart_smoke_target.partition(":")[2],
        )
        exact_parts = ("--exact",)
    else:
        restart_parts = ("-p", "wardrobe-desktop", "--lib")
        exact_parts = ()

    checks = [
        CommandCheck(
            "core_backup_contracts",
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "wardrobe-core",
                "backup",
                "--",
                "--test-threads=1",
            ),
            require_rust_test=True,
        ),
        CommandCheck(
            "platform_backup_repository",
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "wardrobe-platform",
                "backup",
                "--",
                "--test-threads=1",
            ),
            require_rust_test=True,
        ),
        CommandCheck(
            "platform_restore_repository",
            (
                "cargo",
                "test",
                "--offline",
                "-p",
                "wardrobe-platform",
                "restore",
                "--",
                "--test-threads=1",
            ),
            require_rust_test=True,
        ),
        CommandCheck(
            "compiled_backend_restart_smoke",
            (
                "cargo",
                "test",
                "--offline",
                *restart_parts,
                source.restart_smoke_filter,
                "--",
                *exact_parts,
                "--test-threads=1",
            ),
            require_rust_test=True,
            compiled_restart_smoke=True,
        ),
    ]
    if source.has_tauri:
        checks.append(
            CommandCheck(
                "tauri_backup_commands",
                (
                    "cargo",
                    "test",
                    "--offline",
                    "-p",
                    "wardrobe-desktop",
                    "--lib",
                    "backup",
                    "--",
                    "--test-threads=1",
                ),
                require_rust_test=True,
            )
        )
    if source.has_ui:
        checks.extend(
            (
                CommandCheck(
                    "ui_backup_restore",
                    (
                        "npm",
                        "--workspace",
                        "@wardrobe/desktop-ui",
                        "test",
                        "--",
                        "--run",
                        "backup",
                        "restore",
                    ),
                ),
                CommandCheck(
                    "ui_production_build",
                    ("npm", "--workspace", "@wardrobe/desktop-ui", "run", "build"),
                ),
            )
        )
    return tuple(checks)


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
            int(value)
            for value in re.findall(r"\brunning\s+(\d+)\s+tests?\b", output)
        ]
        if not counts or max(counts) < 1:
            return f"{check.name} matched no Rust tests"
        if check.compiled_restart_smoke and sum(counts) != 1:
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
    if set(value) != required:
        raise ValueError("malformed P09 evidence record")
    requirement = value.get("requirement_id")
    details = value.get("details")
    test_name = value.get("test")
    recorded_at = value.get("recorded_at")
    if (
        value.get("schema_version") != 1
        or requirement not in REQUIREMENT_IDS
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
        or set(details) != {
            "checks_passed",
            "compiled_restart_smoke",
            "verification_sha256",
            "public_summary",
        }
        or not isinstance(details["checks_passed"], int)
        or isinstance(details["checks_passed"], bool)
        or not 0 <= details["checks_passed"] <= 32
        or not isinstance(details["compiled_restart_smoke"], bool)
        or not re.fullmatch(r"[0-9a-f]{64}", details["verification_sha256"])
    ):
        raise ValueError("malformed P09 evidence record")
    summary = _validate_public_summary(details["public_summary"])
    if value["status"] == "deferred" and (
        summary.get("feature_enabled") is not False
        or summary.get("acceptance_claim") != "deferred_not_passed"
        or not isinstance(summary.get("deferred_limitation"), str)
    ):
        raise ValueError("malformed deferred P09 evidence record")


def _bounded_json_bytes(value: dict[str, Any]) -> bytes:
    data = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P09 evaluator artifact exceeds size limit")
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
        "checks_passed": check_count,
        "compiled_backend_restart_smoke": True,
        "actual_sqlite": True,
        "actual_filesystem": True,
        "browser_mock_used_for_restart_smoke": False,
        "manifest_sensitive_fields": source.manifest_sensitive_field_count,
        "evidence_sensitive_fields": source.evidence_sensitive_field_count,
        "packaged_app_tested": False,
        "offline_network_disabled_tested": False,
    }
    if requirement in DEFERRED_REQUIREMENT_IDS:
        limitation = (
            "No packaged network-disabled offline acceptance was run."
            if requirement == "SYS-REL-002"
            else "No packaged manual keyboard and screen-reader review was run."
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
    compiled_restart_smoke = False

    if selected & TRIGGER_REQUIREMENT_IDS != TRIGGER_REQUIREMENT_IDS:
        failures.append("selected P09 requirement IDs must include backup and restore")
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
            if check.compiled_restart_smoke:
                compiled_restart_smoke = True
        if not failures and not compiled_restart_smoke:
            failures.append("compiled-backend restart smoke did not execute")

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
        "source_file_count": source.source_file_count if source else 0,
        "checks": checks,
        "compiled_backend_restart_smoke": compiled_restart_smoke,
        "browser_mock_restart_smoke": False,
        "packaged_app_tested": False,
        "offline_network_disabled_tested": False,
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
                "p09_backup::disabled_production_acceptance"
                if deferred
                else "p09_backup::focused_backup_restore_verification"
            ),
            "recorded_at": recorded_at,
            "details": {
                "checks_passed": len(checks),
                "compiled_restart_smoke": compiled_restart_smoke,
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
