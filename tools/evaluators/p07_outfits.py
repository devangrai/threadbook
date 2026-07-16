"""Fail-closed evaluator for the approved P07 manual-outfits vertical."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from tools.evaluators.p03_receipts import run_bounded_command, write_atomic_json


REQUIREMENT_IDS = frozenset({"P07-COL-001", "P07-OFF-001"})
RUN_ID = "20260715T080623Z-0aacabda"
PACKET_DIR = Path("artifacts/harness/P07") / RUN_ID
DIAGNOSTICS_NAME = "p07-outfits-diagnostics.json"
MAX_ARTIFACT_BYTES = 128 * 1024
TIMEOUT_SECONDS = 15 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P07-outfits.md": (
        "4c48e8c17e7ec7041c0f04563a3f415375d9f1701600ea64d5c16d55fb0f11a8"
    ),
    str(PACKET_DIR / "requirements.json"): (
        "bbfc5bc967042bcb96bd732a7fa7eedb63dcbd4feae665ce30a201312c110fb1"
    ),
    str(PACKET_DIR / "proposal.md"): (
        "e58bb10b11e1d4f6278955a272adea1d7cc9aed0790fe97d2afd4837651a3e0e"
    ),
    str(PACKET_DIR / "review.md"): (
        "b036ed9b2ad2267945febb698792a96acf74b37f0b2edf823bd749a1989edd71"
    ),
}

OUTFIT_COMMANDS = (
    "create_manual_outfit_v1",
    "list_outfits_v1",
    "get_outfit_collage_v1",
)

SOURCE_FILES = (
    "crates/wardrobe-core/src/outfit.rs",
    "crates/wardrobe-core/src/lib.rs",
    "crates/wardrobe-core/src/ports.rs",
    "crates/wardrobe-core/src/service.rs",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/outfit_repository.rs",
    "crates/wardrobe-platform/migrations/0008_outfits.sql",
    "crates/wardrobe-platform/migrations/0008_outfits.sha256",
    "crates/wardrobe-platform/tests/outfit_repository.rs",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/src/generated/contracts.ts",
    "apps/desktop-ui/src/invoke-transport.ts",
    "apps/desktop-ui/src/outfit-bridge.ts",
    "apps/desktop-ui/src/outfit-bridge.test.ts",
    "apps/desktop-ui/src/OutfitsWorkspace.tsx",
    "apps/desktop-ui/src/OutfitsWorkspace.test.tsx",
    "apps/desktop-ui/src/App.tsx",
    "apps/desktop-ui/src/styles.css",
    "apps/desktop-ui/e2e/outfits.spec.ts",
    "apps/desktop-ui/playwright.config.ts",
)

COMMAND_CHECKS = (
    (
        "core_outfit_contracts",
        ["cargo", "test", "--offline", "-p", "wardrobe-core", "outfit"],
    ),
    (
        "platform_outfit_repository",
        [
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--test",
            "outfit_repository",
        ],
    ),
    (
        "desktop_outfit_restart",
        [
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-desktop",
            "outfit_commands_use_real_local_state_and_preserve_collage_across_restart",
        ],
    ),
    (
        "generated_bindings",
        [
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "generated_bindings_are_current",
        ],
    ),
    (
        "ui_outfits",
        [
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "--run",
            "OutfitsWorkspace.test.tsx",
            "outfit-bridge.test.ts",
        ],
    ),
    (
        "ui_production_build",
        ["npm", "--workspace", "@wardrobe/desktop-ui", "run", "build"],
    ),
    (
        "production_transport",
        [
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "check:production-transport",
        ],
    ),
    (
        "offline_playwright",
        [
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "test:e2e",
            "--",
            "outfits.spec.ts",
        ],
    ),
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read(path: Path, limit: int = 4 * 1024 * 1024) -> bytes | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return data if len(data) <= limit else None


def validate_packet(root: Path) -> tuple[list[str], str]:
    errors: list[str] = []
    hashes: list[str] = []
    for relative, expected in EXPECTED_PACKET_HASHES.items():
        data = _read(root / relative)
        if data is None:
            errors.append(f"missing or oversized packet file: {relative}")
            continue
        actual = _sha256(data)
        hashes.append(f"{relative}:{actual}")
        if actual != expected:
            errors.append(f"packet hash mismatch: {relative}")
    try:
        state = json.loads((root / PACKET_DIR / "state.json").read_text())
        requirements = json.loads(
            (root / PACKET_DIR / "requirements.json").read_text()
        )
    except (OSError, json.JSONDecodeError):
        state = {}
        requirements = {}
    selected = requirements.get("selected_requirement_ids", [])
    if (
        requirements.get("phase") != "P07"
        or set(selected) != set(REQUIREMENT_IDS)
        or len(selected) != len(REQUIREMENT_IDS)
    ):
        errors.append("frozen P07 requirement selection is invalid")
    if (
        state.get("phase") != "P07"
        or state.get("run_id") != RUN_ID
        or state.get("review", {}).get("decision") != "APPROVE"
        or state.get("review", {}).get("proposal_hash")
        != EXPECTED_PACKET_HASHES[str(PACKET_DIR / "proposal.md")]
        or state.get("selected_requirement_ids") != selected
    ):
        errors.append("P07 packet is not independently approved")
    return errors, _sha256("\n".join(sorted(hashes)).encode())


def validate_source(root: Path) -> tuple[list[str], str, str]:
    errors: list[str] = []
    source_hashes: list[str] = []
    texts: dict[str, str] = {}
    for relative in SOURCE_FILES:
        data = _read(root / relative)
        if data is None:
            errors.append(f"missing or oversized source file: {relative}")
            continue
        source_hashes.append(f"{relative}:{_sha256(data)}")
        try:
            texts[relative] = data.decode()
        except UnicodeDecodeError:
            errors.append(f"non-text source file: {relative}")

    migration_data = _read(
        root / "crates/wardrobe-platform/migrations/0008_outfits.sql"
    ) or b""
    expected_checksum = (
        _read(
            root / "crates/wardrobe-platform/migrations/0008_outfits.sha256",
            256,
        )
        or b""
    ).decode().strip()
    migration_hash = _sha256(migration_data)
    if migration_hash != expected_checksum:
        errors.append("v8 migration checksum mismatch")

    tauri = texts.get("src-tauri/src/lib.rs", "")
    build = texts.get("src-tauri/build.rs", "")
    capability = texts.get("src-tauri/capabilities/main.json", "")
    for command in OUTFIT_COMMANDS:
        if command not in tauri or command not in build:
            errors.append(f"desktop command not registered: {command}")
        permission = "allow-" + command.replace("_", "-")
        if permission not in capability:
            errors.append(f"desktop permission missing: {permission}")

    repository = texts.get(
        "crates/wardrobe-platform/src/outfit_repository.rs", ""
    )
    migration = texts.get(
        "crates/wardrobe-platform/migrations/0008_outfits.sql", ""
    )
    workspace = texts.get("apps/desktop-ui/src/OutfitsWorkspace.tsx", "")
    smoke = texts.get("apps/desktop-ui/e2e/outfits.spec.ts", "")
    required_fragments = {
        "atomic outfit creation": "TransactionBehavior::Immediate",
        "dual revision comparison": "expected_outfit_revision",
        "immutable blob verification": "verify_pinned_asset",
        "explicit unavailable asset state": "OutfitAssetStateV1::Unavailable",
        "durable command replay": "command_receipts",
        "object URL creation": "URL.createObjectURL",
        "object URL cleanup": "URL.revokeObjectURL",
    }
    combined = "\n".join((repository, workspace))
    for label, fragment in required_fragments.items():
        if fragment not in combined:
            errors.append(f"missing {label}")
    for table in ("outfits", "outfit_members"):
        if f"CREATE TABLE {table}" not in migration:
            errors.append(f"v8 table missing: {table}")
    for trigger in ("outfits_no_update", "outfit_members_no_update"):
        if f"CREATE TRIGGER {trigger}" not in migration:
            errors.append(f"v8 immutability trigger missing: {trigger}")
    if smoke.count("test(") != 1:
        errors.append("P07 smoke must contain exactly one test")
    if "page.route" not in smoke or "route.abort" not in smoke:
        errors.append("P07 smoke does not enforce offline operation")
    if "AxeBuilder" not in smoke or "scrollWidth" not in smoke:
        errors.append("P07 smoke lacks accessibility or mobile overflow checks")

    production = "\n".join(
        texts.get(relative, "")
        for relative in (
            "crates/wardrobe-core/src/outfit.rs",
            "crates/wardrobe-platform/src/outfit_repository.rs",
            "apps/desktop-ui/src/outfit-bridge.ts",
            "apps/desktop-ui/src/OutfitsWorkspace.tsx",
        )
    ).lower()
    for forbidden in ("reqwest", "https://", "openai", "gmail"):
        if forbidden in production:
            errors.append(f"manual outfit path contains remote dependency: {forbidden}")

    return (
        errors,
        _sha256("\n".join(sorted(source_hashes)).encode()),
        migration_hash,
    )


def _write_bounded(path: Path, payload: dict[str, Any]) -> None:
    if len(json.dumps(payload, sort_keys=True).encode()) > MAX_ARTIFACT_BYTES:
        raise ValueError("P07 evaluator artifact exceeds limit")
    write_atomic_json(path, payload)


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for requirement in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
    (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)

    failures, packet_hash = validate_packet(root)
    source_hash = ""
    migration_hash = ""
    checks: dict[str, dict[str, Any]] = {}
    if selected != set(REQUIREMENT_IDS):
        failures.append("selected P07 requirement IDs must exactly match approved set")
    if not failures:
        source_failures, source_hash, migration_hash = validate_source(root)
        failures.extend(source_failures)

    if not failures:
        environment = os.environ.copy()
        environment.pop("HARNESS_RUN_DIR", None)
        environment.pop("HARNESS_EVIDENCE_DIR", None)
        for name, command in COMMAND_CHECKS:
            result = run_bounded_command(
                command,
                cwd=root,
                env=environment,
                timeout_seconds=TIMEOUT_SECONDS,
            )
            checks[name] = {
                "returncode": result.returncode,
                "output_sha256": result.output_sha256,
                "output_bytes": result.output_bytes,
                "duration_ms": result.duration_ms,
            }
            if (
                result.returncode != 0
                or result.timed_out
                or result.launch_failed
                or result.output_limit_exceeded
            ):
                failures.append(f"focused check failed: {name}")
                break

    recorded_at = (
        dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    )
    diagnostics = {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "recorded_at": recorded_at,
        "failures": failures,
        "checks": checks,
        "pass_evidence_written": not failures,
    }
    if failures:
        _write_bounded(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    summary = {
        "profile": "personal_mvp",
        "packet_sha256": packet_hash,
        "source_sha256": source_hash,
        "migration_sha256": migration_hash,
        "reasoning_provider": "not_used",
        "live_external_credentials": "not_required",
        "notarization": "deferred",
        "clean_machine_certification": "deferred",
    }
    written: list[Path] = []
    try:
        for requirement in sorted(requested):
            path = evidence_dir / f"{requirement}.json"
            _write_bounded(
                path,
                {
                    "schema_version": 1,
                    "requirement_id": requirement,
                    "status": "pass",
                    "test": "p07_outfits::focused_production_verification",
                    "recorded_at": recorded_at,
                    "details": {
                        "checks": list(checks),
                        "verification_sha256": _sha256(
                            f"{requirement}:{packet_hash}:{source_hash}".encode()
                        ),
                        "public_summary": summary,
                    },
                },
            )
            written.append(path)
        _write_bounded(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        raise
    return 0
