"""Fail-closed evaluator for the approved P08 try-on vertical."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from tools.evaluators.p03_receipts import (
    CommandResult,
    run_bounded_command,
    write_atomic_json,
)


REQUIREMENT_IDS = frozenset(
    {
        "P08-EXP-001",
        "P08-LBL-001",
        "P08-SRC-001",
        "P08-EVD-001",
        "P08-ERR-001",
        "P08-PRV-001",
        "P08-QLT-001",
    }
)
LOCAL_REQUIREMENT_IDS = REQUIREMENT_IDS - {"P08-QLT-001"}
QUALITY_REQUIREMENT_ID = "P08-QLT-001"

RUN_ID = "20260715T095103Z-6fcfb33f"
PACKET_DIR = f"artifacts/harness/P08/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p08-try-on-diagnostics.json"
MIGRATION_FILE = "crates/wardrobe-platform/migrations/0010_try_on.sql"
MIGRATION_CHECKSUM_FILE = (
    "crates/wardrobe-platform/migrations/0010_try_on.sha256"
)

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024
COMMAND_TIMEOUT_SECONDS = 15 * 60
LIVE_CANARY_TIMEOUT_SECONDS = 4 * 60

LIVE_CANARY_OPT_IN_ENV = "WARDROBE_P08_LIVE_CANARY"
LIVE_CANARY_COMMAND_ENV = "WARDROBE_P08_LIVE_CANARY_COMMAND_JSON"
LIVE_CANARY_OPT_IN_TOKEN = "run-one-production-call"
LIVE_CANARY_NAME = "p08_openai_try_on"
LIVE_CANARY_ADAPTER = "OpenAiImageEditsHttpTransport::production"
LIVE_CANARY_ENDPOINT = "https://api.openai.com/v1/images/edits"
LIVE_CANARY_MODEL = "gpt-image-2"

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P08-try-on.md": (
        "2bdf1c8cad49f75a7434b89dd150877b965b63842194c87abb671af39d274d2d"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "65fbee3684a079c77892e94eeea661ad5612b4e492a04e21f69b32a8bf244c25"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "869f362fe78d35b4c30a69aeca6d25e8be1c23bd7a77e0605014aaeb80d963f0"
    ),
    f"{PACKET_DIR}/review.md": (
        "988e029e473c64cae1094bb34c4ca3cd52f47be17537eff48971bf58b59d353e"
    ),
}
SOURCE_FILES = (
    "crates/wardrobe-core/src/lib.rs",
    "crates/wardrobe-core/src/try_on.rs",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/tests/try_on_contracts.rs",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/source_image.rs",
    "crates/wardrobe-platform/src/catalog_repository.rs",
    "crates/wardrobe-platform/src/try_on_http.rs",
    "crates/wardrobe-platform/src/try_on_renderer.rs",
    "crates/wardrobe-platform/src/try_on_repository.rs",
    MIGRATION_FILE,
    MIGRATION_CHECKSUM_FILE,
    "crates/wardrobe-platform/tests/try_on_http.rs",
    "crates/wardrobe-platform/tests/try_on_repository.rs",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/playwright.config.ts",
    "apps/desktop-ui/scripts/check-production-transport.mjs",
    "apps/desktop-ui/src/generated/contracts.ts",
    "apps/desktop-ui/src/OutfitsWorkspace.tsx",
    "apps/desktop-ui/src/TryOnPanel.tsx",
    "apps/desktop-ui/src/TryOnPanel.test.tsx",
    "apps/desktop-ui/src/try-on-bridge.ts",
    "apps/desktop-ui/src/try-on-bridge.test.ts",
    "apps/desktop-ui/src/vite-env.d.ts",
    "apps/desktop-ui/e2e/outfits.spec.ts",
)


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]


COMMAND_CHECKS = (
    CommandCheck(
        "core_try_on_contracts",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "--test",
            "try_on_contracts",
        ),
    ),
    CommandCheck(
        "try_on_repository",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--test",
            "try_on_repository",
        ),
    ),
    CommandCheck(
        "openai_image_edits_protocol",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--test",
            "try_on_http",
            "--",
            "--test-threads=1",
        ),
    ),
    CommandCheck(
        "try_on_source_canonicalization",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "try_on_canonical_png",
        ),
    ),
    CommandCheck(
        "try_on_deletion_schema",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "deletion_schema_classification_covers_every_phase_table_and_blob_fk",
        ),
    ),
    CommandCheck(
        "desktop_try_on_gate_and_scheduler",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-desktop",
            "--lib",
            "try_on",
        ),
    ),
    CommandCheck(
        "generated_bindings",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "generated_bindings_are_current",
        ),
    ),
    CommandCheck(
        "ui_try_on",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "--run",
            "TryOnPanel.test.tsx",
            "try-on-bridge.test.ts",
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
    CommandCheck(
        "try_on_playwright",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "test:e2e",
            "--",
            "outfits.spec.ts",
        ),
    ),
)


@dataclass(frozen=True)
class PacketValidation:
    errors: tuple[str, ...]
    packet_sha256: str


@dataclass(frozen=True)
class SourceValidation:
    errors: tuple[str, ...]
    source_sha256: str
    migration_sha256: str


@dataclass(frozen=True)
class CanaryOutcome:
    errors: tuple[str, ...]
    status: str
    acceptance_claim: str
    feature_enabled: bool
    production_adapter_calls: int
    deferred_limitation: str | None
    command_result: CommandResult | None = None

    def public_summary(self) -> dict[str, Any]:
        summary: dict[str, Any] = {
            "status": self.status,
            "feature_enabled": self.feature_enabled,
            "acceptance_claim": self.acceptance_claim,
            "production_adapter_calls": self.production_adapter_calls,
            "required_production_adapter_calls": 1,
            "provider": "openai",
            "model": LIVE_CANARY_MODEL,
        }
        if self.deferred_limitation is not None:
            summary["deferred_limitation"] = self.deferred_limitation
        return summary


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_packet(root: Path) -> PacketValidation:
    errors: list[str] = []
    aggregate = hashlib.sha256()
    contents: dict[str, bytes] = {}
    for relative, expected_hash in EXPECTED_PACKET_HASHES.items():
        data = _read_bounded(root / relative)
        if data is None:
            errors.append(f"frozen packet file is unreadable or oversized: {relative}")
            continue
        contents[relative] = data
        if _sha256(data) != expected_hash:
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
        requirements.get("phase") != "P08"
        or not isinstance(selected, list)
        or set(selected) != REQUIREMENT_IDS
        or len(selected) != len(REQUIREMENT_IDS)
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("frozen P08 requirement selection is invalid")

    review = state.get("review")
    proposal_hash = EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"]
    if (
        state.get("phase") != "P08"
        or state.get("run_id") != RUN_ID
        or state.get("status")
        not in {"APPROVED", "BUILT", "EVALUATED", "EVALUATION_FAILED"}
        or state.get("selected_requirement_ids") != selected
        or not isinstance(review, dict)
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash") != proposal_hash
    ):
        errors.append("P08 packet is not independently approved")

    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(
        errors="replace"
    )
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append("approved P08 review decision is missing")

    return PacketValidation(tuple(dict.fromkeys(errors)), aggregate.hexdigest())


def validate_source(root: Path) -> SourceValidation:
    errors: list[str] = []
    sources: dict[str, bytes] = {}
    aggregate = hashlib.sha256()
    for relative in SOURCE_FILES:
        data = _read_bounded(root / relative)
        if data is None:
            errors.append(f"required P08 file is unreadable: {relative}")
            continue
        sources[relative] = data
        aggregate.update(relative.encode())
        aggregate.update(b"\0")
        aggregate.update(data)
        aggregate.update(b"\0")

    def text(relative: str) -> str:
        try:
            return sources[relative].decode()
        except (KeyError, UnicodeDecodeError):
            return ""

    migration_data = sources.get(MIGRATION_FILE, b"")
    migration_sha256 = _sha256(migration_data)
    if text(MIGRATION_CHECKSUM_FILE).strip() != migration_sha256:
        errors.append("v10 try-on migration checksum mismatch")

    core = text("crates/wardrobe-core/src/try_on.rs")
    contracts = text("crates/wardrobe-core/tests/try_on_contracts.rs")
    repository = text("crates/wardrobe-platform/src/try_on_repository.rs")
    repository_test = text("crates/wardrobe-platform/tests/try_on_repository.rs")
    http = text("crates/wardrobe-platform/src/try_on_http.rs")
    http_test = text("crates/wardrobe-platform/tests/try_on_http.rs")
    renderer = text("crates/wardrobe-platform/src/try_on_renderer.rs")
    migration = text(MIGRATION_FILE)
    deletion = text("crates/wardrobe-platform/src/catalog_repository.rs")
    desktop = text("src-tauri/src/lib.rs")
    build = text("src-tauri/build.rs")
    capabilities = text("src-tauri/capabilities/main.json")
    workspace = text("apps/desktop-ui/src/OutfitsWorkspace.tsx")
    panel = text("apps/desktop-ui/src/TryOnPanel.tsx")
    panel_test = text("apps/desktop-ui/src/TryOnPanel.test.tsx")
    smoke = text("apps/desktop-ui/e2e/outfits.spec.ts")

    core_markers = (
        "TRY_ON_PRESENTATION_LABEL_V1",
        "TryOnOutputUseClassV1::PresentationOnly",
        "eligible_as_evidence",
        "PreviewTryOnV1Request",
        "SubmitTryOnV1Request",
        "GetOutfitTryOnV1Request",
    )
    if any(marker not in core for marker in core_markers):
        errors.append("P08 core contracts are incomplete")
    if (
        "output_is_hash_checked_labeled_and_presentation_only" not in contracts
        or "get_response_keeps_ordered_real_sources_beside_matching_output"
        not in contracts
    ):
        errors.append("P08 label, source, and evidence contract tests are incomplete")

    repository_markers = (
        "TransactionBehavior::Immediate",
        "authorize_try_on_transport",
        "recover_try_on_jobs",
        "begin_try_on_output",
        "finalize_try_on_output",
        "presentation_only",
        "eligible_as_evidence: false",
    )
    if any(marker not in repository for marker in repository_markers):
        errors.append("durable P08 queue or presentation-only storage is incomplete")
    if (
        "real_try_on_queue_is_explicit_restart_safe_and_credential_authorized"
        not in repository_test
    ):
        errors.append("P08 durable queue integration test is missing")

    transport_markers = (
        LIVE_CANARY_ENDPOINT,
        'OPENAI_IMAGE_EDITS_MODEL: &str = "gpt-image-2"',
        "reqwest::retry::never()",
        "redirect(Policy::none())",
        ".no_proxy()",
        "OPENAI_IMAGE_REQUEST_LIMIT_BYTES",
        "OPENAI_IMAGE_RESPONSE_LIMIT_BYTES",
    )
    if (
        any(marker not in http for marker in transport_markers)
        or "MacOsKeychain.get_exact" not in renderer
        or "OpenAiImageEditsHttpTransport::production" not in renderer
    ):
        errors.append("fixed production OpenAI image-edits adapter is incomplete")
    if (
        "concrete_tls_transport_sends_fixed_ordered_multipart_and_validates_output"
        not in http_test
        or "post_send_read_timeout_is_an_ambiguous_outcome" not in http_test
    ):
        errors.append("P08 local TLS provider coverage is incomplete")

    for table in (
        "try_on_approvals",
        "try_on_assets",
        "try_on_jobs",
        "try_on_attempts",
        "try_on_outputs",
    ):
        if f"CREATE TABLE {table}" not in migration:
            errors.append(f"v10 table missing: {table}")
    if (
        "use_class TEXT NOT NULL CHECK (use_class = 'presentation_only')"
        not in migration
        or "eligible_as_evidence INTEGER NOT NULL CHECK (eligible_as_evidence = 0)"
        not in migration
        or "augment_try_on_deletion_closure" not in deletion
    ):
        errors.append("P08 evidence exclusion or deletion closure is incomplete")

    commands = (
        "list_try_on_portrait_candidates_v1",
        "preview_try_on_v1",
        "submit_try_on_v1",
        "get_outfit_try_on_v1",
    )
    for command in commands:
        if command not in desktop or command not in build:
            errors.append(f"desktop try-on command not registered: {command}")
        permission = "allow-" + command.replace("_", "-")
        if permission not in capabilities:
            errors.append(f"desktop try-on permission missing: {permission}")

    release_markers = (
        'option_env!("WARDROBE_TRY_ON_RELEASE")',
        'const TRY_ON_RELEASE_TOKEN: &str = "experimental"',
        "value == Some(TRY_ON_RELEASE_TOKEN)",
    )
    if (
        any(marker not in desktop for marker in release_markers)
        or 'VITE_WARDROBE_TRY_ON_RELEASE === "experimental"' not in workspace
    ):
        errors.append("experimental P08 release gate is incomplete")

    label = (
        "AI visualization. Not an accurate representation of fit or garment "
        "construction."
    )
    if (
        label not in panel
        or label not in panel_test
        or "Images sent to OpenAI" not in panel_test
        or "Real source garments" not in panel
    ):
        errors.append("P08 disclosure, label, or real-source UI is incomplete")
    if (
        smoke.count("test(") != 1
        or "page.route" not in smoke
        or "route.abort" not in smoke
        or "AxeBuilder" not in smoke
        or "scrollWidth" not in smoke
        or 'command === "submit_try_on_v1"' not in smoke
        or "toHaveLength(1)" not in smoke
    ):
        errors.append("P08 offline accessibility smoke is incomplete")

    return SourceValidation(
        tuple(dict.fromkeys(errors)),
        aggregate.hexdigest(),
        migration_sha256,
    )


def _bounded_json_bytes(value: dict[str, Any]) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P08 evaluator artifact exceeds size limit")
    return data


def _write_bounded_json(path: Path, value: dict[str, Any]) -> None:
    _bounded_json_bytes(value)
    write_atomic_json(path, value)


def _remove_stale_outputs(evidence_dir: Path) -> None:
    for requirement in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
    (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)


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


def _command_failed(result: CommandResult) -> bool:
    return (
        result.returncode != 0
        or result.timed_out
        or result.launch_failed
        or result.output_limit_exceeded
    )


def _deferred_canary() -> CanaryOutcome:
    return CanaryOutcome(
        errors=(),
        status="deferred",
        acceptance_claim="deferred_not_passed",
        feature_enabled=False,
        production_adapter_calls=0,
        deferred_limitation=(
            "No explicit P08 live-canary opt-in and structured production-adapter "
            "command were supplied; no OpenAI request was made."
        ),
    )


def _canary_command(environment: dict[str, str]) -> tuple[str, ...] | None:
    encoded = environment.get(LIVE_CANARY_COMMAND_ENV)
    if encoded is None:
        return None
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        return ()
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 32
        or any(
            not isinstance(part, str)
            or not 1 <= len(part) <= 512
            or "\0" in part
            for part in value
        )
    ):
        return ()
    return tuple(value)


def evaluate_live_canary(
    root: Path,
    environment: dict[str, str],
) -> CanaryOutcome:
    if environment.get(LIVE_CANARY_OPT_IN_ENV) != LIVE_CANARY_OPT_IN_TOKEN:
        return _deferred_canary()

    command = _canary_command(environment)
    if not command:
        return CanaryOutcome(
            errors=("explicit P08 live canary has no valid structured command",),
            status="fail",
            acceptance_claim="not_passed",
            feature_enabled=False,
            production_adapter_calls=0,
            deferred_limitation=None,
        )

    result = run_bounded_command(
        list(command),
        cwd=root,
        env=environment,
        timeout_seconds=LIVE_CANARY_TIMEOUT_SECONDS,
        capture_output=True,
    )
    errors: list[str] = []
    if _command_failed(result):
        errors.append("explicit P08 live canary command failed")
    record = _json_object(result.captured_output)
    expected = {
        "schema_version": 1,
        "canary": LIVE_CANARY_NAME,
        "adapter": LIVE_CANARY_ADAPTER,
        "endpoint": LIVE_CANARY_ENDPOINT,
        "model": LIVE_CANARY_MODEL,
        "production_adapter_calls": 1,
        "response_contract_valid": True,
        "fixture_contains_personal_data": False,
    }
    if any(record.get(key) != value for key, value in expected.items()):
        errors.append("explicit P08 live canary result contract is invalid")
    fixture_hash = record.get("fixture_sha256")
    if (
        not isinstance(fixture_hash, str)
        or len(fixture_hash) != 64
        or any(character not in "0123456789abcdef" for character in fixture_hash)
    ):
        errors.append("explicit P08 live canary fixture hash is invalid")

    return CanaryOutcome(
        errors=tuple(dict.fromkeys(errors)),
        status="fail" if errors else "pass",
        acceptance_claim="not_passed" if errors else "live_canary_passed",
        feature_enabled=not errors,
        production_adapter_calls=0 if errors else 1,
        deferred_limitation=None,
        command_result=result,
    )


def _quality_summary(canary: CanaryOutcome) -> dict[str, Any]:
    return {
        "profile": "personal_mvp",
        "release_channel": "experimental",
        "feature_enabled": False,
        "acceptance_claim": "deferred_not_passed",
        "deferred_limitation": (
            "The approved blinded identity, garment-detail, and misleading-output "
            "study has not been supplied; non-experimental availability is disabled."
        ),
        "human_evaluation_cases": 0,
        "production_adapter_calls": canary.production_adapter_calls,
        "live_canary_status": canary.status,
        "live_canary_acceptance_claim": canary.acceptance_claim,
    }


def _verification_hash(
    requirement: str,
    packet: PacketValidation,
    source: SourceValidation,
    checks: dict[str, dict[str, Any]],
    canary: CanaryOutcome,
) -> str:
    value = {
        "requirement_id": requirement,
        "packet_sha256": packet.packet_sha256,
        "source_sha256": source.source_sha256,
        "migration_sha256": source.migration_sha256,
        "checks": checks,
        "live_canary": canary.public_summary(),
    }
    return _sha256(_bounded_json_bytes(value))


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(evidence_dir)
    recorded_at = utc_now()
    packet = validate_packet(root)
    source: SourceValidation | None = None
    failures = list(packet.errors)
    checks: dict[str, dict[str, Any]] = {}
    canary = _deferred_canary()

    if not failures:
        source = validate_source(root)
        failures.extend(source.errors)

    environment = os.environ.copy()
    environment.pop("HARNESS_RUN_DIR", None)
    environment.pop("HARNESS_EVIDENCE_DIR", None)
    environment.pop("OPENAI_API_KEY", None)
    if not failures:
        for check in COMMAND_CHECKS:
            result = run_bounded_command(
                list(check.command),
                cwd=root,
                env=environment,
                timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            )
            checks[check.name] = _result_summary(result)
            if _command_failed(result):
                failures.append(f"focused check failed: {check.name}")
                break

    if not failures:
        canary_environment = os.environ.copy()
        canary_environment.pop("HARNESS_RUN_DIR", None)
        canary_environment.pop("HARNESS_EVIDENCE_DIR", None)
        canary = evaluate_live_canary(root, canary_environment)
        failures.extend(canary.errors)

    diagnostics = {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "recorded_at": recorded_at,
        "selected_requirement_ids": sorted(requested),
        "failures": list(dict.fromkeys(failures)),
        "checks": checks,
        "packet_sha256": packet.packet_sha256,
        "source_sha256": source.source_sha256 if source else "",
        "migration_sha256": source.migration_sha256 if source else "",
        "live_openai_canary": canary.public_summary(),
        "live_canary_command": (
            _result_summary(canary.command_result)
            if canary.command_result is not None
            else None
        ),
        "quality_study": _quality_summary(canary),
        "production_adapter_calls": canary.production_adapter_calls,
        "deferred_requirement_ids": (
            [QUALITY_REQUIREMENT_ID]
            if QUALITY_REQUIREMENT_ID in requested
            else []
        ),
        "pass_evidence_written": not failures,
    }
    if failures or source is None:
        _write_bounded_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    payloads: dict[str, dict[str, Any]] = {}
    for requirement in sorted(requested):
        if requirement == QUALITY_REQUIREMENT_ID:
            status = "deferred"
            test = "p08_try_on::experimental_quality_gate"
            public_summary = _quality_summary(canary)
        else:
            status = "pass"
            test = "p08_try_on::focused_local_verification"
            public_summary = {
                "profile": "personal_mvp",
                "release_channel": "experimental",
                "feature_enabled": False,
                "acceptance_claim": "local_requirement_passed",
                "production_adapter_calls": canary.production_adapter_calls,
                "live_canary_status": canary.status,
                "live_canary_acceptance_claim": canary.acceptance_claim,
                "quality_study_status": "deferred",
                "quality_acceptance_claim": "deferred_not_passed",
            }
        payloads[requirement] = {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": status,
            "test": test,
            "recorded_at": recorded_at,
            "details": {
                "evaluator": "tools/evaluators/p08_try_on.py",
                "checks": list(checks),
                "verification_sha256": _verification_hash(
                    requirement, packet, source, checks, canary
                ),
                "public_summary": public_summary,
            },
        }
        _bounded_json_bytes(payloads[requirement])

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
