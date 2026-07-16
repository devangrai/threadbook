"""Fail-closed evaluator for the approved P07 outfit-recommendation vertical."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from tools.evaluators.p03_receipts import run_bounded_command, write_atomic_json


REQUIREMENT_IDS = frozenset(
    {
        "P07-TOL-001",
        "P07-AI-001",
        "P07-VAL-001",
        "P07-GRD-001",
        "P07-CNS-001",
    }
)
LOCAL_REQUIREMENT_IDS = frozenset({"P07-TOL-001", "P07-VAL-001"})
LIVE_REQUIREMENT_IDS = REQUIREMENT_IDS - LOCAL_REQUIREMENT_IDS

RUN_ID = "20260715T084434Z-17bb8ee3"
PACKET_DIR = f"artifacts/harness/P07/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p07-recommendations-diagnostics.json"
FIXTURE_FILE = "fixtures/p07-outfit-evaluation-v1.json"
FIXTURE_CHECKSUM_FILE = "fixtures/p07-outfit-evaluation-v1.sha256"
MIGRATION_FILE = (
    "crates/wardrobe-platform/migrations/0009_outfit_recommendations.sql"
)
MIGRATION_CHECKSUM_FILE = (
    "crates/wardrobe-platform/migrations/0009_outfit_recommendations.sha256"
)

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024
COMMAND_TIMEOUT_SECONDS = 15 * 60
REQUIRED_LIVE_CASES = 500

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P07-outfits.md": (
        "4c48e8c17e7ec7041c0f04563a3f415375d9f1701600ea64d5c16d55fb0f11a8"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "a6ee851fa5e410b868867a0657d6a7a4feb7edc7e1e1d9d73ed2b19303a8b98e"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "a7c7876e5cbe866937ec326b7fd807991f6d00dfdd9d385b042748b16753231f"
    ),
    f"{PACKET_DIR}/review.md": (
        "dcea4023916920bd9967c23996f7512bf02f87b917e55ea4108d873751a284b6"
    ),
}

EXPECTED_FIXTURE_SHA256 = (
    "479020c9abcf173d136e5dfe8e369bb32f9cc902523b6e5be8858e0ff4bcc317"
)

SOURCE_FILES = (
    "Cargo.lock",
    "crates/wardrobe-core/Cargo.toml",
    "crates/wardrobe-core/build.rs",
    "crates/wardrobe-core/src/lib.rs",
    "crates/wardrobe-core/src/model_policy.rs",
    "crates/wardrobe-core/src/recommendation.rs",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/src/bin/generate-bindings.rs",
    "crates/wardrobe-core/tests/recommendation_contracts.rs",
    "crates/wardrobe-core/tests/recommendation_validator.rs",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/catalog_repository.rs",
    "crates/wardrobe-platform/src/outfit_recommendation_http.rs",
    "crates/wardrobe-platform/src/outfit_recommendation_provider.rs",
    "crates/wardrobe-platform/src/outfit_recommendation_repository.rs",
    "crates/wardrobe-platform/src/outfit_recommender.rs",
    MIGRATION_FILE,
    MIGRATION_CHECKSUM_FILE,
    "crates/wardrobe-platform/tests/outfit_recommendation_http.rs",
    "crates/wardrobe-platform/tests/outfit_recommendation_provider.rs",
    FIXTURE_FILE,
    FIXTURE_CHECKSUM_FILE,
    "src-tauri/Cargo.toml",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/playwright.config.ts",
    "apps/desktop-ui/scripts/check-production-transport.mjs",
    "apps/desktop-ui/src/generated/contracts.ts",
    "apps/desktop-ui/src/invoke-transport.ts",
    "apps/desktop-ui/src/vite-env.d.ts",
    "apps/desktop-ui/src/outfit-recommendation-bridge.ts",
    "apps/desktop-ui/src/outfit-recommendation-bridge.test.ts",
    "apps/desktop-ui/src/OutfitRecommendationPanel.tsx",
    "apps/desktop-ui/src/OutfitRecommendationPanel.test.tsx",
    "apps/desktop-ui/src/OutfitsWorkspace.tsx",
    "apps/desktop-ui/src/App.tsx",
    "apps/desktop-ui/e2e/outfits.spec.ts",
    "release/supply-chain-policy-v1.json",
)


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]


COMMAND_CHECKS = (
    CommandCheck(
        "core_recommendation_contracts",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "--test",
            "recommendation_contracts",
        ),
    ),
    CommandCheck(
        "core_recommendation_validator",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "--test",
            "recommendation_validator",
        ),
    ),
    CommandCheck(
        "production_adapter_protocol",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--test",
            "outfit_recommendation_provider",
            "--",
            "--test-threads=1",
        ),
    ),
    CommandCheck(
        "production_http_boundaries",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--test",
            "outfit_recommendation_http",
            "--",
            "--test-threads=1",
        ),
    ),
    CommandCheck(
        "recommendation_repository_and_migration",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "outfit_recommendation",
        ),
    ),
    CommandCheck(
        "desktop_recommendation_commands",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-desktop",
            "recommendation",
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
        "ui_recommendations",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "--run",
            "OutfitRecommendationPanel.test.tsx",
            "outfit-recommendation-bridge.test.ts",
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
        "outfit_recommendation_playwright",
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
    fixture_sha256: str
    fixture_case_count: int


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
        actual_hash = _sha256(data)
        if actual_hash != expected_hash:
            errors.append(f"frozen packet hash changed: {relative}")
        aggregate.update(relative.encode())
        aggregate.update(b"\0")
        aggregate.update(data)
        aggregate.update(b"\0")

    state_data = _read_bounded(root / STATE_FILE)
    if state_data is None:
        errors.append(f"approved packet state is unreadable or oversized: {STATE_FILE}")
        state = {}
    else:
        state = _json_object(state_data)

    requirements = _json_object(
        contents.get(f"{PACKET_DIR}/requirements.json", b"")
    )
    selected = requirements.get("selected_requirement_ids")
    requirement_rows = requirements.get("requirements")
    evidenced = (
        {
            row.get("id")
            for row in requirement_rows
            if isinstance(row, dict) and row.get("evidence_required") is True
        }
        if isinstance(requirement_rows, list)
        else set()
    )
    if (
        requirements.get("phase") != "P07"
        or not isinstance(selected, list)
        or set(selected) != REQUIREMENT_IDS
        or len(selected) != len(REQUIREMENT_IDS)
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("frozen P07 recommendation requirement selection is invalid")

    review = state.get("review")
    if (
        state.get("phase") != "P07"
        or state.get("run_id") != RUN_ID
        or state.get("status")
        not in {"APPROVED", "BUILT", "EVALUATED", "EVALUATION_FAILED"}
        or state.get("selected_requirement_ids") != selected
        or not isinstance(review, dict)
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash")
        != EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"]
    ):
        errors.append("P07 recommendation packet is not independently approved")

    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(
        errors="replace"
    )
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append("approved P07 recommendation review decision is missing")

    return PacketValidation(tuple(dict.fromkeys(errors)), aggregate.hexdigest())


def validate_source(root: Path) -> SourceValidation:
    errors: list[str] = []
    sources: dict[str, bytes] = {}
    aggregate = hashlib.sha256()
    for relative in SOURCE_FILES:
        data = _read_bounded(root / relative)
        if data is None:
            errors.append(f"required P07 recommendation file is unreadable: {relative}")
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

    fixture_data = sources.get(FIXTURE_FILE, b"")
    fixture_sha256 = _sha256(fixture_data)
    fixture = _json_object(fixture_data)
    checksum = text(FIXTURE_CHECKSUM_FILE).strip()
    wardrobes = fixture.get("wardrobe_seeds")
    prompts = fixture.get("prompt_templates")
    constraints = fixture.get("constraint_variants")
    fixture_case_count = fixture.get("case_count")
    calculated_case_count = (
        len(wardrobes) * len(prompts) * len(constraints)
        if all(isinstance(value, list) for value in (wardrobes, prompts, constraints))
        else 0
    )
    if (
        fixture_sha256 != EXPECTED_FIXTURE_SHA256
        or checksum != EXPECTED_FIXTURE_SHA256
        or fixture.get("schema_version") != 1
        or fixture.get("evaluation_revision") != "p07-outfit-evaluation-v1"
        or fixture.get("all_cases_satisfiable") is not True
        or fixture_case_count != REQUIRED_LIVE_CASES
        or calculated_case_count != REQUIRED_LIVE_CASES
        or fixture.get("grounding_gate", {}).get(
            "maximum_accepted_invented_item_ids"
        )
        != 0
        or fixture.get("constraint_gate", {}).get("minimum_successful_cases")
        != 490
        or fixture.get("constraint_gate", {}).get("minimum_ratio") != 0.98
    ):
        errors.append("frozen 500-case P07 evaluation definition is invalid")

    migration_data = sources.get(MIGRATION_FILE, b"")
    migration_sha256 = _sha256(migration_data)
    if text(MIGRATION_CHECKSUM_FILE).strip() != migration_sha256:
        errors.append("v9 recommendation migration checksum mismatch")

    core = text("crates/wardrobe-core/src/recommendation.rs")
    contracts_test = text(
        "crates/wardrobe-core/tests/recommendation_contracts.rs"
    )
    validator_test = text(
        "crates/wardrobe-core/tests/recommendation_validator.rs"
    )
    provider = text(
        "crates/wardrobe-platform/src/outfit_recommendation_provider.rs"
    )
    http = text("crates/wardrobe-platform/src/outfit_recommendation_http.rs")
    recommender = text("crates/wardrobe-platform/src/outfit_recommender.rs")
    repository = text(
        "crates/wardrobe-platform/src/outfit_recommendation_repository.rs"
    )
    desktop = text("src-tauri/src/lib.rs")
    build = text("src-tauri/build.rs")
    capabilities = text("src-tauri/capabilities/main.json")
    core_build = text("crates/wardrobe-core/build.rs")
    model_module = text("crates/wardrobe-core/src/model_policy.rs")
    release_policy = _json_object(
        sources.get("release/supply-chain-policy-v1.json", b"")
    )
    models = release_policy.get("models")
    remote_services = models.get("remote_services") if isinstance(models, dict) else None
    recommendation_service = (
        remote_services.get("outfit_recommendation")
        if isinstance(remote_services, dict)
        else None
    )

    tool_names = (
        "search_confirmed_wardrobe",
        "search_wear_history",
        "get_style_preferences",
        "list_saved_outfits",
    )
    if (
        "OutfitToolRegistryV1" not in core
        or "ToolCapabilityV1::ReadOnly" not in core
        or any(name not in core or name not in contracts_test for name in tool_names)
        or "tool_registry_is_exactly_four_read_only_strict_functions"
        not in contracts_test
    ):
        errors.append("read-only outfit tool contract is incomplete")

    validator_markers = (
        "validate_outfit_proposal_v1",
        "UnknownItem",
        "InactiveItem",
        "ExcludedItem",
        "StaleCatalogRevision",
        "StaleOutfitRevision",
        "IncompatibleItems",
    )
    if any(marker not in core for marker in validator_markers) or (
        "unknown_inactive_duplicate_excluded_and_stale_ids_fail_closed"
        not in validator_test
    ):
        errors.append("local outfit proposal validation is incomplete")

    provider_markers = (
        "validate_outfit_proposal_v1",
        "MAX_RESPONSES_CALLS_V1",
        "MAX_OUTFIT_TOOL_CALLS_V1",
        "prompt_cache_options",
        "reasoning.encrypted_content",
    )
    if (
        any(marker not in provider for marker in provider_markers)
        or "https://api.openai.com/v1/responses" not in http
        or recommendation_service
        != {
            "downloads_code": False,
            "model": "gpt-5.6-sol",
            "provider": "openai",
        }
        or "OUTFIT_RECOMMENDATION_MODEL_V1" not in core_build
        or "OUTFIT_RECOMMENDATION_PROVIDER_V1" not in core_build
        or 'include!(concat!(env!("OUT_DIR"), "/release_model_policy.rs"))'
        not in model_module
        or "pub use crate::model_policy" not in core
        or "ProductionOutfitRecommender" not in recommender
    ):
        errors.append("production recommendation adapter wiring is incomplete")

    cache_audit_markers = (
        "UsageAddError::CachePolicyViolation",
        "reported_cache_usage:",
        "prompt_cache_read_tokens:",
        "prompt_cache_write_tokens:",
    )
    if (
        any(marker not in provider for marker in cache_audit_markers)
        or "self.reported_cache_usage"
        not in core
        or "self.usage.prompt_cache_read_tokens != 0" not in core
        or "self.usage.prompt_cache_write_tokens != 0" not in core
    ):
        errors.append("cache-policy violation audit retention is incomplete")

    release_token = "credentialed-live"
    workspace = text("apps/desktop-ui/src/OutfitsWorkspace.tsx")
    if (
        "option_env!(\"WARDROBE_REMOTE_RECOMMENDATIONS_RELEASE\")" not in desktop
        or "RemoteRecommendationReleaseGate" not in desktop
        or release_token not in desktop
        or "VITE_WARDROBE_REMOTE_RECOMMENDATIONS_RELEASE" not in workspace
        or release_token not in workspace
    ):
        errors.append("deferred remote recommendation release gate is incomplete")

    if (
        "authorize_outfit_recommendation_transport_start" not in recommender
        or "authorize_outfit_recommendation_transport_start" not in repository
        or "TransactionBehavior::Immediate" not in repository
        or "credentials.status = 'active'" not in repository
    ):
        errors.append("credential-authorized transport-start gate is incomplete")

    for command in (
        "preview_outfit_recommendation_v1",
        "request_outfit_recommendation_v1",
    ):
        permission = "allow-" + command.replace("_", "-")
        if command not in desktop or command not in build:
            errors.append(f"desktop recommendation command not registered: {command}")
        if permission not in capabilities:
            errors.append(f"desktop recommendation permission missing: {permission}")

    return SourceValidation(
        tuple(dict.fromkeys(errors)),
        aggregate.hexdigest(),
        migration_sha256,
        fixture_sha256,
        fixture_case_count if isinstance(fixture_case_count, int) else 0,
    )


def _bounded_json_bytes(value: dict[str, Any]) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P07 recommendation evaluator artifact exceeds size limit")
    return data


def _write_bounded_json(path: Path, value: dict[str, Any]) -> None:
    _bounded_json_bytes(value)
    write_atomic_json(path, value)


def _remove_stale_outputs(evidence_dir: Path) -> None:
    for requirement in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
    (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)


def _result_summary(result: Any) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "output_sha256": result.output_sha256,
        "output_bytes": result.output_bytes,
        "duration_ms": result.duration_ms,
        "timed_out": result.timed_out,
        "launch_failed": result.launch_failed,
        "output_limit_exceeded": result.output_limit_exceeded,
    }


def _command_failed(result: Any) -> bool:
    return (
        result.returncode != 0
        or result.timed_out
        or result.launch_failed
        or result.output_limit_exceeded
    )


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
        "fixture_sha256": source.fixture_sha256,
        "checks": checks,
    }
    return _sha256(_bounded_json_bytes(value))


def _deferred_limitation() -> str:
    return (
        "No approved live credentialed run made 500 real calls through the "
        "production OpenAI adapter on the frozen synthetic evaluation set."
    )


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

    if not failures:
        source = validate_source(root)
        failures.extend(source.errors)

    if not failures:
        environment = os.environ.copy()
        environment.pop("HARNESS_RUN_DIR", None)
        environment.pop("HARNESS_EVIDENCE_DIR", None)
        environment.pop("OPENAI_API_KEY", None)
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

    diagnostics = {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "recorded_at": recorded_at,
        "selected_requirement_ids": sorted(requested),
        "failures": list(dict.fromkeys(failures)),
        "checks": checks,
        "packet_sha256": packet.packet_sha256,
        "source_sha256": source.source_sha256 if source else "",
        "fixture_sha256": source.fixture_sha256 if source else "",
        "fixture_case_count": source.fixture_case_count if source else 0,
        "production_adapter_calls": 0,
        "deferred_requirement_ids": sorted(requested & LIVE_REQUIREMENT_IDS),
        "pass_evidence_written": not failures,
    }
    if failures or source is None:
        _write_bounded_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    payloads: dict[str, dict[str, Any]] = {}
    for requirement in sorted(requested):
        common_summary = {
            "profile": "personal_mvp",
            "feature_enabled": False,
            "live_credentials_available": False,
            "production_adapter_calls": 0,
            "required_production_adapter_calls": REQUIRED_LIVE_CASES,
            "fixture_sha256": source.fixture_sha256,
        }
        if requirement in LIVE_REQUIREMENT_IDS:
            status = "deferred"
            test = "p07_recommendations::live_production_adapter_gate"
            public_summary = {
                **common_summary,
                "acceptance_claim": "deferred_not_passed",
                "deferred_limitation": _deferred_limitation(),
            }
        else:
            status = "pass"
            test = "p07_recommendations::focused_local_verification"
            public_summary = {
                **common_summary,
                "acceptance_claim": "local_requirement_passed",
                "deferred_limitation": _deferred_limitation(),
            }
        payloads[requirement] = {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": status,
            "test": test,
            "recorded_at": recorded_at,
            "details": {
                "evaluator": "tools/evaluators/p07_recommendations.py",
                "checks": list(checks),
                "verification_sha256": _verification_hash(
                    requirement, packet, source, checks
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
