"""Fail-closed evaluator for the approved P06 Gmail connector vertical."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from tools.evaluators.p03_receipts import run_bounded_command, write_atomic_json


REQUIREMENT_IDS = frozenset(
    {"P06-GML-001", "P06-GML-002", "P06-AUT-001", "P06-AUT-002"}
)
RUN_ID = "20260715T064635Z-3004a19f"
PACKET_DIR = Path("artifacts/harness/P06") / RUN_ID
DIAGNOSTICS_NAME = "p06-connectors-diagnostics.json"
MAX_ARTIFACT_BYTES = 128 * 1024
TIMEOUT_SECONDS = 15 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P06-connectors.md": (
        "bf9c3e727015e0e1a9eb2f27655a8b263997d7f06cbf9e63753fe3cb42792f19"
    ),
    str(PACKET_DIR / "requirements.json"): (
        "6861d8d84055b65bc016e5802888356ec91fde036d14bbd867dee6fe9bad7245"
    ),
    str(PACKET_DIR / "proposal.md"): (
        "5d35d894bddea090445cf811cc0fc1461c77b6dba43cc883fb54a15639a71385"
    ),
    str(PACKET_DIR / "review.md"): (
        "fb53b33d7f046606a5db80ade21cf267dc51432c2de110092195c25f5669e76a"
    ),
}

GMAIL_COMMANDS = (
    "get_gmail_connector_v1",
    "save_gmail_settings_v1",
    "connect_gmail_v1",
    "sync_gmail_v1",
    "disconnect_gmail_v1",
)

SOURCE_FILES = (
    "crates/wardrobe-core/src/gmail_connector.rs",
    "crates/wardrobe-core/src/service.rs",
    "crates/wardrobe-core/tests/gmail_connector_contracts.rs",
    "crates/wardrobe-core/tests/gmail_connector_service.rs",
    "crates/wardrobe-platform/src/credential.rs",
    "crates/wardrobe-platform/src/gmail_connector.rs",
    "crates/wardrobe-platform/src/gmail_http.rs",
    "crates/wardrobe-platform/src/gmail_repository.rs",
    "crates/wardrobe-platform/src/gmail_sync.rs",
    "crates/wardrobe-platform/migrations/0007_gmail_connector.sql",
    "crates/wardrobe-platform/migrations/0007_gmail_connector.sha256",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/src/GmailConnectorSettings.tsx",
    "apps/desktop-ui/src/gmail-connector-bridge.ts",
    "apps/desktop-ui/src/App.tsx",
    "apps/desktop-ui/e2e/gmail-connector.spec.ts",
)

COMMAND_CHECKS = (
    (
        "core_contracts",
        [
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "--test",
            "gmail_connector_contracts",
            "--test",
            "gmail_connector_service",
        ],
    ),
    (
        "platform_connector",
        [
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "gmail_",
        ],
    ),
    (
        "desktop_compile",
        ["cargo", "check", "--offline", "-p", "wardrobe-desktop"],
    ),
    (
        "ui_connector",
        [
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "--run",
            "GmailConnectorSettings.test.tsx",
            "gmail-connector-bridge.test.ts",
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
    except (OSError, json.JSONDecodeError):
        state = {}
    if state.get("review", {}).get("decision") != "APPROVE":
        errors.append("P06 packet is not approved")
    if set(state.get("selected_requirement_ids", [])) != set(REQUIREMENT_IDS):
        errors.append("P06 packet requirement set changed")
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

    migration = root / "crates/wardrobe-platform/migrations/0007_gmail_connector.sql"
    checksum = root / "crates/wardrobe-platform/migrations/0007_gmail_connector.sha256"
    migration_data = _read(migration) or b""
    expected_checksum = (_read(checksum, 256) or b"").decode().strip()
    migration_hash = _sha256(migration_data)
    if migration_hash != expected_checksum:
        errors.append("v7 migration checksum mismatch")

    tauri = texts.get("src-tauri/src/lib.rs", "")
    build = texts.get("src-tauri/build.rs", "")
    capability = texts.get("src-tauri/capabilities/main.json", "")
    for command in GMAIL_COMMANDS:
        if command not in tauri or command not in build:
            errors.append(f"desktop command not registered: {command}")
        permission = "allow-" + command.replace("_", "-")
        if permission not in capability:
            errors.append(f"desktop permission missing: {permission}")

    connector = texts.get("crates/wardrobe-platform/src/gmail_connector.rs", "")
    repository = texts.get("crates/wardrobe-platform/src/gmail_repository.rs", "")
    http = texts.get("crates/wardrobe-platform/src/gmail_http.rs", "")
    migration_text = texts.get(
        "crates/wardrobe-platform/migrations/0007_gmail_connector.sql", ""
    )
    app = texts.get("apps/desktop-ui/src/App.tsx", "")
    smoke = texts.get("apps/desktop-ui/e2e/gmail-connector.spec.ts", "")
    required_fragments = {
        "production connector wiring": "ProductionGmailConnector::production",
        "durable revocation stage": "credential_delete_pending",
        "connect interruption tombstone": '\\"interrupted\\":true',
        "manifest recomputation": "actual_materialization_manifests",
        "atomic sync transaction": "TransactionBehavior::Immediate",
        "Keychain exact read": "get_exact",
    }
    combined = "\n".join((tauri, connector, repository))
    for label, fragment in required_fragments.items():
        if fragment not in combined:
            errors.append(f"missing {label}")
    for endpoint in (
        "https://oauth2.googleapis.com/token",
        "https://oauth2.googleapis.com/revoke",
        "https://gmail.googleapis.com",
    ):
        if endpoint not in http:
            errors.append(f"fixed Google endpoint missing: {endpoint}")
    for table in (
        "gmail_provider_sources",
        "gmail_source_revisions",
        "gmail_revision_materializations",
        "gmail_operations",
        "gmail_disconnect_stages",
    ):
        if f"CREATE TABLE {table}" not in migration_text:
            errors.append(f"v7 table missing: {table}")
    if '<option value="gmail">' in app:
        errors.append("raw Gmail secret ingress remains in the generic credential UI")
    if smoke.count("test(") != 1:
        errors.append("P06 smoke must contain exactly one test")
    if "Gmail purchase: Linen overshirt" not in smoke:
        errors.append("P06 smoke does not verify imported evidence preservation")

    return (
        errors,
        _sha256("\n".join(sorted(source_hashes)).encode()),
        migration_hash,
    )


def _write_bounded(path: Path, payload: dict[str, Any]) -> None:
    if len(json.dumps(payload, sort_keys=True).encode()) > MAX_ARTIFACT_BYTES:
        raise ValueError("P06 evaluator artifact exceeds limit")
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
        failures.append("selected P06 requirement IDs must exactly match approved set")
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
        "live_google_credentials": "deferred",
        "consent_screen_verification": "deferred",
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
                    "test": "p06_connectors::focused_production_verification",
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
