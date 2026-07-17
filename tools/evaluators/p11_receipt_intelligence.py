"""Fail-closed evaluator for the approved P11 receipt-intelligence packet."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from tools.evaluators.p03_receipts import (
    CommandResult,
    run_bounded_command,
    write_atomic_json,
)


REQUIREMENT_IDS = frozenset(
    {
        "P11-AI-001",
        "P11-AI-002",
        "P11-ATM-001",
        "P11-AUT-001",
        "P11-BND-001",
        "P11-BND-002",
        "P11-CIT-001",
        "P11-CLS-001",
        "P11-CLS-002",
        "P11-DEC-001",
        "P11-E2E-001",
        "P11-GAT-001",
        "P11-PRV-001",
        "P11-REL-001",
        "P11-REL-002",
        "P11-SAF-001",
        "P11-SEC-001",
        "P11-UI-001",
        "P11-UI-002",
    }
)
RUN_ID = "20260716T212140Z-b027b95e"
PACKET_DIR = f"artifacts/harness/P11/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
SPEC_FILE = "specs/phases/P11-receipt-intelligence.md"
EVALUATOR_FILE = "tools/evaluators/p11_receipt_intelligence.py"
MIGRATION_FILE = "crates/wardrobe-platform/migrations/0016_receipt_intelligence.sql"
MIGRATION_CHECKSUM_FILE = (
    "crates/wardrobe-platform/migrations/0016_receipt_intelligence.sha256"
)
DIAGNOSTICS_NAME = "p11-receipt-intelligence-diagnostics.json"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024
COMMAND_TIMEOUT_SECONDS = 30 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    SPEC_FILE: (
        "e559ff6bcddf2d6546a50fbce22315b210c617c1454a3340ebcbd4619cb73c66"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "42c1c1a182b82571b49b926f679e56f1eb3b8fe6f7bdbb987013ada71ed98bb3"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "ab85491e61c17dbd465655e6e21dc087f079de4b7e58784a0637215847904d04"
    ),
    f"{PACKET_DIR}/review.md": (
        "f35b29c4ac6b72cd76612b0aff2c1341de4db6e6bdf5846d050fa9cadb3161a6"
    ),
}

CORE = frozenset(
    {
        "P11-AI-002",
        "P11-AUT-001",
        "P11-BND-001",
        "P11-BND-002",
        "P11-CLS-001",
        "P11-CLS-002",
        "P11-GAT-001",
        "P11-PRV-001",
        "P11-REL-001",
        "P11-REL-002",
        "P11-UI-001",
        "P11-UI-002",
    }
)
PROVIDER = frozenset(
    {
        "P11-AI-001",
        "P11-AI-002",
        "P11-BND-002",
        "P11-CIT-001",
        "P11-CLS-001",
        "P11-PRV-001",
        "P11-SAF-001",
        "P11-SEC-001",
    }
)
REPOSITORY = frozenset(
    {
        "P11-ATM-001",
        "P11-AUT-001",
        "P11-BND-001",
        "P11-CLS-002",
        "P11-DEC-001",
        "P11-E2E-001",
        "P11-PRV-001",
        "P11-REL-001",
        "P11-REL-002",
    }
)
TAURI = frozenset(
    {
        "P11-AUT-001",
        "P11-E2E-001",
        "P11-GAT-001",
        "P11-REL-001",
        "P11-REL-002",
        "P11-SEC-001",
        "P11-UI-001",
        "P11-UI-002",
    }
)
UI = frozenset(
    {
        "P11-AUT-001",
        "P11-GAT-001",
        "P11-PRV-001",
        "P11-UI-001",
        "P11-UI-002",
    }
)
COORDINATOR = frozenset(
    {
        "P11-ATM-001",
        "P11-AUT-001",
        "P11-BND-002",
        "P11-CIT-001",
        "P11-E2E-001",
        "P11-GAT-001",
        "P11-REL-001",
        "P11-REL-002",
        "P11-SEC-001",
    }
)
VERTICAL = REQUIREMENT_IDS


@dataclass(frozen=True)
class PacketValidation:
    errors: tuple[str, ...]
    sha256: str


@dataclass(frozen=True)
class SourceValidation:
    errors: dict[str, tuple[str, ...]]
    sha256: str
    migration_sha256: str
    file_count: int


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]
    requirements: frozenset[str]
    output_markers: tuple[str, ...] = ()
    success_marker: str | None = None
    reject_zero_tests: bool = False


CORE_TESTS = (
    "preview_consent_and_commands_are_strict_v1_contracts",
    "provider_projection_has_only_opaque_handles_and_visible_text",
    "every_preparation_bound_is_closed_and_fails_one_over",
    "consent_binds_every_disclosed_fragment_and_configured_bound",
    "all_execution_bounds_and_stateless_parameters_are_exact",
    "retention_and_disclosure_fail_closed",
    "receipt_intelligence_types_are_exported_to_typescript",
    "classification_requires_graphs_only_for_apparel_evidence",
    "all_attempt_states_have_closed_safe_shapes",
    "consent_reservation_is_atomic_expiring_and_single_use",
    "list_summaries_preserve_classification_and_content_free_attempt_state",
    "source_authority_is_explicitly_user_reviewed_and_order_bound",
    "availability_keeps_offline_receipts_and_wardrobe_access_enabled",
)
PROVIDER_TESTS = (
    "exact_stateless_request_uses_strict_schema_and_structured_untrusted_fragments",
    "completed_protocol_exposes_all_four_classifications_explicitly",
    "labeled_provider_fixtures_cover_receipt_classification_domains",
    "refusal_and_incomplete_are_safe_distinct_outcomes",
    "strict_decoding_rejects_unknown_missing_and_inconsistent_output",
    "numeric_citations_reject_one_valid_and_one_unrelated_exact_quote",
    "event_citations_reject_one_valid_and_one_unrelated_exact_quote",
    "numeric_and_event_fields_accept_multiple_supporting_citations",
    "string_citations_reject_incidental_substrings_and_word_suffixes",
    "string_citations_accept_exact_and_allowlisted_field_normalizations",
    "exact_quote_references_must_resolve_once_in_the_named_opaque_fragment",
    "output_token_and_usage_bounds_fail_closed",
    "structured_output_byte_and_line_item_bounds_fail_closed",
    "invalid_request_bounds_fail_before_transport",
)
REPOSITORY_TESTS = (
    "pure_preview_and_atomic_exact_reservation",
    "preview_rejects_fragment_content_hash_mismatch",
    "preflight_replay_is_read_only_and_compares_exact_command_identity",
    "restart_recovery_and_unrelated_classification_are_durable",
    "list_availability_uses_active_credential_reference_without_secret_access",
    "publication_is_atomic_and_reanalysis_preserves_review_authority",
)
COORDINATOR_TESTS = (
    "gmail_source_to_validated_order_review_is_atomic_and_catalog_free",
    "completed_exact_replay_precedes_retention_source_and_external_checks",
    "terminal_replay_lookup_returns_only_terminal_exact_commands",
    "list_reports_stale_retention_as_unavailable",
)

COMMAND_CHECKS = (
    CommandCheck(
        "focused_core",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-core",
            "--offline",
            "--test",
            "receipt_intelligence_contracts",
            "--test",
            "receipt_intelligence_states",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        CORE,
        CORE_TESTS,
        "test result: ok",
        True,
    ),
    CommandCheck(
        "focused_provider",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--test",
            "receipt_intelligence_provider",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        PROVIDER,
        PROVIDER_TESTS,
        "test result: ok",
        True,
    ),
    CommandCheck(
        "focused_repository",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "receipt_intelligence_repository::tests::",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        REPOSITORY,
        REPOSITORY_TESTS,
        "test result: ok",
        True,
    ),
    CommandCheck(
        "focused_coordinator",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "receipt_intelligence_coordinator::tests::",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        COORDINATOR,
        COORDINATOR_TESTS,
        "test result: ok",
        True,
    ),
    CommandCheck(
        "focused_tauri",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-desktop",
            "--offline",
            "receipt_intelligence_",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        TAURI,
        (
            "receipt_intelligence_commands",
            "receipt_intelligence_packaged_disabled_state_smoke",
            "receipt_intelligence_availability_override_is_truthful_and_ordered",
            "receipt_intelligence_terminal_replay_precedes_remote_gates",
            "receipt_intelligence_release_requires_exact_evaluator_revision",
        ),
        "test result: ok",
        True,
    ),
    CommandCheck(
        "focused_ui",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "src/ReceiptIntelligencePanel.test.tsx",
            "src/receipt-intelligence-bridge.test.ts",
        ),
        UI,
        (
            "src/ReceiptIntelligencePanel.test.tsx",
            "src/receipt-intelligence-bridge.test.ts",
        ),
        "Test Files  2 passed",
    ),
    CommandCheck(
        "packaged_disabled_state",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-desktop",
            "--offline",
            "receipt_intelligence_packaged_disabled_state_smoke",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        frozenset({"P11-GAT-001"}),
        ("receipt_intelligence_packaged_disabled_state_smoke",),
        "test result: ok",
        True,
    ),
    CommandCheck(
        "vertical_smoke",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "receipt_intelligence_coordinator::tests::gmail_source_to_validated_order_review_is_atomic_and_catalog_free",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        frozenset({"P11-E2E-001"}),
        ("gmail_source_to_validated_order_review_is_atomic_and_catalog_free",),
        "test result: ok",
        True,
    ),
    CommandCheck(
        "ui_preview_review_smoke",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "test:e2e",
            "--",
            "receipt-intelligence.spec.ts",
            "--reporter=list",
        ),
        frozenset({"P11-UI-001", "P11-UI-002", "P11-E2E-001"}),
        (
            "OpenAI receipt availability is truthful and preserves saved status",
            "OpenAI receipt preview, cancellation, approval, and review handoff",
        ),
        "2 passed",
    ),
    CommandCheck(
        "focused_evaluator_tests",
        (
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_p11_receipt_intelligence_evaluator.py",
        ),
        VERTICAL,
        success_marker="OK",
    ),
    CommandCheck(
        "regression_make_test",
        ("make", "test"),
        VERTICAL,
    ),
    CommandCheck(
        "make_check",
        ("make", "check"),
        VERTICAL,
    ),
    CommandCheck(
        "diff_check",
        ("git", "diff", "--check"),
        VERTICAL,
    ),
)

SOURCE_REQUIREMENTS = {
    "crates/wardrobe-core/src/receipt_intelligence.rs": CORE | PROVIDER,
    "crates/wardrobe-core/build.rs": frozenset(
        {"P11-AI-001", "P11-GAT-001", "P11-SEC-001"}
    ),
    "crates/wardrobe-core/src/lib.rs": CORE,
    "crates/wardrobe-core/src/bindings.rs": CORE | UI,
    "crates/wardrobe-core/src/service.rs": CORE | TAURI,
    "crates/wardrobe-core/tests/receipt_intelligence_contracts.rs": CORE,
    "crates/wardrobe-core/tests/receipt_intelligence_states.rs": CORE,
    "crates/wardrobe-platform/src/receipt_intelligence_provider.rs": PROVIDER,
    "crates/wardrobe-platform/tests/receipt_intelligence_provider.rs": PROVIDER,
    "crates/wardrobe-platform/src/receipt_intelligence_coordinator.rs": COORDINATOR,
    "crates/wardrobe-platform/src/receipt_intelligence_coordinator_tests.rs": COORDINATOR,
    "crates/wardrobe-platform/src/receipt_intelligence_repository.rs": REPOSITORY,
    "crates/wardrobe-platform/src/receipt_intelligence_repository_tests.rs": REPOSITORY,
    "crates/wardrobe-platform/src/receipt_repository.rs": REPOSITORY
    | frozenset({"P11-CIT-001"}),
    "crates/wardrobe-platform/src/database.rs": REPOSITORY
    | frozenset({"P11-GAT-001"}),
    "crates/wardrobe-platform/src/deletion_repository.rs": frozenset(
        {"P11-ATM-001", "P11-PRV-001", "P11-SEC-001"}
    ),
    "crates/wardrobe-platform/src/lib.rs": COORDINATOR | REPOSITORY,
    MIGRATION_FILE: REPOSITORY | frozenset({"P11-GAT-001"}),
    MIGRATION_CHECKSUM_FILE: REPOSITORY | frozenset({"P11-GAT-001"}),
    "src-tauri/src/lib.rs": TAURI,
    "src-tauri/src/local_only.rs": frozenset({"P11-GAT-001", "P11-SEC-001"}),
    "src-tauri/src/release_manifest.rs": TAURI | frozenset({"P11-GAT-001"}),
    "release/supply-chain-policy-v1.json": frozenset(
        {"P11-AI-001", "P11-GAT-001", "P11-SEC-001"}
    ),
    "release/generated/supply-chain-manifest-v1.json": frozenset(
        {"P11-AI-001", "P11-GAT-001", "P11-SEC-001"}
    ),
    "tools/release_supply_chain.py": frozenset(
        {"P11-AI-001", "P11-GAT-001", "P11-SEC-001"}
    ),
    "tests/test_release_supply_chain.py": frozenset(
        {"P11-AI-001", "P11-GAT-001", "P11-SEC-001"}
    ),
    EVALUATOR_FILE: REQUIREMENT_IDS,
    "src-tauri/build.rs": TAURI,
    "src-tauri/capabilities/main.json": TAURI,
    "apps/desktop-ui/src/ReceiptIntelligencePanel.tsx": UI,
    "apps/desktop-ui/src/ReceiptIntelligencePanel.test.tsx": UI,
    "apps/desktop-ui/src/receipt-intelligence-bridge.ts": UI | TAURI,
    "apps/desktop-ui/src/receipt-intelligence-bridge.test.ts": UI,
    "apps/desktop-ui/e2e/receipt-intelligence.spec.ts": UI
    | frozenset({"P11-E2E-001"}),
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read(path: Path) -> bytes | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_SOURCE_BYTES + 1)
    except OSError:
        return None
    return data if len(data) <= MAX_SOURCE_BYTES else None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _aggregate(contents: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name, data in sorted(contents.items()):
        digest.update(name.encode())
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _json_object(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeError):
        return {}
    return value if isinstance(value, dict) else {}


def validate_packet(root: Path) -> PacketValidation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    for relative, expected in EXPECTED_PACKET_HASHES.items():
        data = _read(root / relative)
        if data is None:
            errors.append(f"approved packet file unreadable or oversized: {relative}")
            continue
        contents[relative] = data
        if _sha256(data) != expected:
            errors.append(f"approved packet hash mismatch: {relative}")

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
        requirements.get("schema_version") != 1
        or requirements.get("phase") != "P11"
        or not isinstance(selected, list)
        or set(selected) != REQUIREMENT_IDS
        or len(selected) != len(REQUIREMENT_IDS)
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("approved P11 requirement selection is not exact")

    state_data = _read(root / STATE_FILE)
    state = _json_object(state_data or b"")
    review = state.get("review")
    expected_spec_hashes = {
        "specs/system.md": EXPECTED_PACKET_HASHES["specs/system.md"],
        SPEC_FILE: EXPECTED_PACKET_HASHES[SPEC_FILE],
    }
    if state_data is None:
        errors.append("approved P11 state is unreadable or oversized")
    if (
        state.get("schema_version") != 1
        or state.get("phase") != "P11"
        or state.get("run_id") != RUN_ID
        or state.get("status")
        not in {
            "APPROVED",
            "BUILT",
            "BUILD_FAILED",
            "EVALUATED",
            "EVALUATION_FAILED",
        }
        or state.get("selected_requirement_ids") != selected
        or state.get("spec_hashes") != expected_spec_hashes
        or state.get("build_command") != ["make", "build"]
        or state.get("evaluate_command") != ["make", "test"]
        or not isinstance(review, dict)
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash")
        != EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"]
        or not isinstance(review.get("reviewer"), str)
        or not review.get("reviewer")
        or not isinstance(review.get("reviewed_at"), str)
        or not review.get("reviewed_at")
    ):
        errors.append("P11 packet is not independently approved")

    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(
        errors="replace"
    )
    if (
        "Status: APPROVED" not in review_text
        or "\nAPPROVE\n" not in review_text
        or not isinstance(review, dict)
        or f"Reviewer: {review.get('reviewer', '')}" not in review_text
        or f"Reviewed at: {review.get('reviewed_at', '')}" not in review_text
    ):
        errors.append("approved P11 review decision is missing or inconsistent")

    return PacketValidation(tuple(dict.fromkeys(errors)), _aggregate(contents))


def validate_source(root: Path) -> SourceValidation:
    errors: dict[str, list[str]] = {requirement: [] for requirement in REQUIREMENT_IDS}
    contents: dict[str, bytes] = {}
    texts: dict[str, str] = {}
    for relative, requirements in SOURCE_REQUIREMENTS.items():
        data = _read(root / relative)
        if data is None:
            for requirement in requirements:
                errors[requirement].append(
                    f"required P11 artifact unreadable or oversized: {relative}"
                )
            continue
        contents[relative] = data
        try:
            texts[relative] = data.decode()
        except UnicodeDecodeError:
            for requirement in requirements:
                errors[requirement].append(
                    f"required P11 artifact is not UTF-8: {relative}"
                )

    def require(relative: str, requirements: frozenset[str], *markers: str) -> None:
        source = texts.get(relative, "")
        for marker in markers:
            if marker not in source:
                for requirement in requirements:
                    errors[requirement].append(
                        f"P11 invariant missing from {relative}: {marker}"
                    )

    require(
        "crates/wardrobe-core/src/receipt_intelligence.rs",
        CORE | PROVIDER,
        'RECEIPT_INTELLIGENCE_MODEL_V1: &str = "gpt-5.6-sol"',
        "ReceiptIntelligencePreparationBoundsV1",
        "ReceiptIntelligenceExecutionBoundsV1",
        "ReceiptIntelligenceAttemptStateV1",
        "ReceiptIntelligenceClassificationV1",
        "store_false_is_not_organization_zdr",
        "#[serde(deny_unknown_fields)]",
    )
    require(
        "crates/wardrobe-core/build.rs",
        frozenset({"P11-AI-001", "P11-GAT-001", "P11-SEC-001"}),
        "openai_receipt_intelligence",
        "evaluator_sha256",
        "receipt-intelligence-prompt-v1",
        "receipt-intelligence-v1",
        "receipt-intelligence-projection-v1",
        "p11-openai-responses-retention-v1",
    )
    require(
        "crates/wardrobe-platform/src/receipt_intelligence_provider.rs",
        PROVIDER,
        "build_receipt_intelligence_request",
        '"store": false',
        '"background": false',
        '"tools": []',
        '"json_schema"',
        "InvalidCitation",
        "RECEIPT_INTELLIGENCE_MAX_OUTPUT_TOKENS",
        "StringEvidenceField",
        "strip_allowlisted_field_separator",
    )
    require(
        "crates/wardrobe-platform/src/receipt_intelligence_coordinator.rs",
        COORDINATOR,
        "ReceiptIntelligenceCoordinator",
        "ReceiptIntelligenceCredentialStore",
        "get_receipt_intelligence_secret",
        "reserve_receipt_intelligence",
        "mark_receipt_intelligence_dispatched",
        "mark_receipt_intelligence_outcome_unknown",
        "provider_outcome_unknown",
        "terminal_replay",
        "RetentionDeclarationUnavailable",
    )
    require(
        "crates/wardrobe-platform/src/receipt_intelligence_repository.rs",
        REPOSITORY,
        "preview_receipt_intelligence",
        "reserve_receipt_intelligence",
        "mark_receipt_intelligence_dispatched",
        "mark_receipt_intelligence_outcome_unknown",
        "complete_receipt_intelligence_with_publication",
        "recover_receipt_intelligence_attempts",
        "receipt_source_authority_head",
        "Sha256::digest(visible_text.as_bytes())",
    )
    require(
        "crates/wardrobe-platform/src/receipt_repository.rs",
        REPOSITORY | frozenset({"P11-CIT-001"}),
        "complete_receipt_intelligence_with_order",
        "publish_receipt_intelligence_order",
    )
    require(
        "crates/wardrobe-platform/src/database.rs",
        REPOSITORY | frozenset({"P11-GAT-001"}),
        "MIGRATION_0016_SQL",
        "0016_receipt_intelligence.sql",
    )
    require(
        "crates/wardrobe-platform/src/deletion_repository.rs",
        frozenset({"P11-ATM-001", "P11-PRV-001", "P11-SEC-001"}),
        '"receipt_intelligence_approvals"',
        '"receipt_intelligence_attempts"',
        '"receipt_intelligence_audits"',
        '"receipt_intelligence_classifications"',
    )
    require(
        "crates/wardrobe-platform/src/lib.rs",
        COORDINATOR | REPOSITORY,
        "mod receipt_intelligence_coordinator;",
        "mod receipt_intelligence_provider;",
        "mod receipt_intelligence_repository;",
        "pub use receipt_intelligence_coordinator::*;",
    )
    require(
        MIGRATION_FILE,
        REPOSITORY,
        "CREATE TABLE receipt_intelligence_approvals",
        "CREATE TABLE receipt_intelligence_attempts",
        "CREATE TABLE receipt_intelligence_classifications",
        "receipt_intelligence_attempts_state_transition",
        "receipt_source_authority_heads",
    )
    migration_hash = _sha256(contents.get(MIGRATION_FILE, b""))
    if texts.get(MIGRATION_CHECKSUM_FILE, "").strip() != migration_hash:
        for requirement in REPOSITORY | frozenset({"P11-GAT-001"}):
            errors[requirement].append("receipt-intelligence migration checksum mismatch")

    for name in CORE_TESTS:
        require(
            (
                "crates/wardrobe-core/tests/receipt_intelligence_contracts.rs"
                if name
                in {
                    "preview_consent_and_commands_are_strict_v1_contracts",
                    "provider_projection_has_only_opaque_handles_and_visible_text",
                    "every_preparation_bound_is_closed_and_fails_one_over",
                    "consent_binds_every_disclosed_fragment_and_configured_bound",
                    "all_execution_bounds_and_stateless_parameters_are_exact",
                    "retention_and_disclosure_fail_closed",
                    "receipt_intelligence_types_are_exported_to_typescript",
                }
                else "crates/wardrobe-core/tests/receipt_intelligence_states.rs"
            ),
            CORE,
            f"fn {name}",
        )
    for name in PROVIDER_TESTS:
        require(
            "crates/wardrobe-platform/tests/receipt_intelligence_provider.rs",
            PROVIDER,
            f"async fn {name}",
        )
    for name in REPOSITORY_TESTS:
        require(
            "crates/wardrobe-platform/src/receipt_intelligence_repository_tests.rs",
            REPOSITORY,
            f"fn {name}",
        )
    for name in COORDINATOR_TESTS:
        require(
            "crates/wardrobe-platform/src/receipt_intelligence_coordinator_tests.rs",
            COORDINATOR,
            f"async fn {name}",
        )
    require(
        "crates/wardrobe-platform/src/receipt_intelligence_coordinator_tests.rs",
        COORDINATOR,
        "OpenAiReceiptIntelligenceProvider",
        "OpenAiResponsesHttpTransport",
        "request_json(&wire)",
    )

    require(
        "src-tauri/src/lib.rs",
        TAURI,
        "preview_receipt_intelligence_v1",
        "request_receipt_intelligence_v1",
        "list_receipt_intelligence_v1",
        "receipt_intelligence_commands",
        "receipt_intelligence_packaged_disabled_state_smoke",
        "receipt_intelligence_availability_override_is_truthful_and_ordered",
        "receipt_intelligence_terminal_replay_precedes_remote_gates",
    )
    require(
        "src-tauri/src/release_manifest.rs",
        TAURI | frozenset({"P11-GAT-001"}),
        "EXPECTED_RECEIPT_INTELLIGENCE_EVALUATOR_SHA256",
        "service.evaluator_sha256 == EXPECTED_RECEIPT_INTELLIGENCE_EVALUATOR_SHA256",
        "receipt_intelligence_release_requires_exact_evaluator_revision",
    )
    require(
        "src-tauri/src/local_only.rs",
        frozenset({"P11-GAT-001", "P11-SEC-001"}),
        "OpenAiReceiptIntelligence",
        "OutboundCapability",
    )
    for relative in (
        "release/supply-chain-policy-v1.json",
        "release/generated/supply-chain-manifest-v1.json",
        "tools/release_supply_chain.py",
        "tests/test_release_supply_chain.py",
    ):
        require(
            relative,
            frozenset({"P11-AI-001", "P11-GAT-001", "P11-SEC-001"}),
            "openai_receipt_intelligence",
            "evaluator_sha256",
            "receipt-intelligence-prompt-v1",
            "receipt-intelligence-v1",
            "receipt-intelligence-projection-v1",
            "p11-openai-responses-retention-v1",
        )
    evaluator_sha256 = _sha256(contents.get(EVALUATOR_FILE, b""))
    for relative in (
        "crates/wardrobe-core/build.rs",
        "release/supply-chain-policy-v1.json",
        "release/generated/supply-chain-manifest-v1.json",
        "src-tauri/src/release_manifest.rs",
        "tools/release_supply_chain.py",
        "tests/test_release_supply_chain.py",
    ):
        require(
            relative,
            frozenset({"P11-AI-001", "P11-GAT-001", "P11-SEC-001"}),
            evaluator_sha256,
        )
    require(
        "src-tauri/build.rs",
        TAURI,
        '"preview_receipt_intelligence_v1"',
        '"request_receipt_intelligence_v1"',
        '"list_receipt_intelligence_v1"',
    )
    require(
        "src-tauri/capabilities/main.json",
        TAURI,
        "allow-preview-receipt-intelligence-v1",
        "allow-request-receipt-intelligence-v1",
        "allow-list-receipt-intelligence-v1",
    )
    require(
        "apps/desktop-ui/src/ReceiptIntelligencePanel.tsx",
        UI,
        "Analyze with OpenAI",
        "store:false",
        "organization-level Zero Data",
        "outcome_unknown",
    )
    require(
        "apps/desktop-ui/src/receipt-intelligence-bridge.ts",
        UI | TAURI,
        "preview_receipt_intelligence_v1",
        "request_receipt_intelligence_v1",
        "list_receipt_intelligence_v1",
    )
    require(
        "apps/desktop-ui/src/ReceiptIntelligencePanel.test.tsx",
        UI,
        "shows the exact accessible disclosure",
        "executes only after approval",
        "keeps remote analysis disabled",
        "release_evidence_unavailable",
        "credential_unavailable",
    )
    require(
        "apps/desktop-ui/e2e/receipt-intelligence.spec.ts",
        UI | frozenset({"P11-E2E-001"}),
        "OpenAI receipt availability is truthful and preserves saved status",
        "OpenAI receipt preview, cancellation, approval, and review handoff",
        "AxeBuilder",
    )

    return SourceValidation(
        {
            requirement: tuple(dict.fromkeys(messages))
            for requirement, messages in errors.items()
        },
        _aggregate(contents),
        migration_hash,
        len(contents),
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
    if (
        result.returncode != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.launch_failed
    ):
        return f"P11 check failed: {check.name}"
    output = result.captured_output.decode(errors="replace")
    executed_test_counts = tuple(
        int(count) for count in re.findall(r"^running (\d+) tests?$", output, re.MULTILINE)
    )
    if (
        (
            check.reject_zero_tests
            and not any(count > 0 for count in executed_test_counts)
        )
        or any(marker not in output for marker in check.output_markers)
        or (
            check.success_marker is not None
            and check.success_marker not in output
        )
    ):
        return f"P11 check did not prove its expected scope: {check.name}"
    return None


def _live_canary_summary() -> dict[str, Any]:
    return {
        "status": "deferred",
        "acceptance_claim": "deferred_not_passed",
        "provider": "openai",
        "model": "gpt-5.6-sol",
        "production_provider_calls": 0,
        "external_credentials_used": False,
        "deferred_limitation": (
            "The opt-in live OpenAI canary is outside local P11 acceptance; "
            "no credential was read and no provider request was made."
        ),
    }


def _write_bounded(path: Path, value: dict[str, Any]) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P11 evaluator artifact exceeds size bound")
    write_atomic_json(path, value)


def _remove_outputs(evidence_dir: Path) -> None:
    for requirement in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
    (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)


def _verification_hash(
    requirement: str,
    packet: PacketValidation,
    source: SourceValidation,
    checks: dict[str, dict[str, Any]],
) -> str:
    value = {
        "requirement_id": requirement,
        "approved_packet_run_id": RUN_ID,
        "packet_sha256": packet.sha256,
        "source_sha256": source.sha256,
        "migration_sha256": source.migration_sha256,
        "checks": checks,
        "live_canary": _live_canary_summary(),
    }
    return _sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_outputs(evidence_dir)
    recorded_at = utc_now()
    packet = validate_packet(root)
    source = validate_source(root)
    failures = list(packet.errors)
    for requirement in sorted(requested):
        failures.extend(source.errors[requirement])

    checks: dict[str, dict[str, Any]] = {}
    environment = os.environ.copy()
    for name in (
        "HARNESS_RUN_DIR",
        "HARNESS_EVIDENCE_DIR",
        "OPENAI_API_KEY",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
        "P11_LIVE_CANARY",
        "P11_LIVE_CANARY_COMMAND",
    ):
        environment.pop(name, None)

    if not failures:
        for check in COMMAND_CHECKS:
            if not (check.requirements & requested):
                continue
            result = run_bounded_command(
                list(check.command),
                cwd=root,
                env=environment,
                timeout_seconds=COMMAND_TIMEOUT_SECONDS,
                capture_output=True,
            )
            checks[check.name] = _result_summary(result)
            error = _command_error(check, result)
            if error:
                failures.append(error)
                break

    diagnostics = {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "recorded_at": recorded_at,
        "selected_requirement_ids": sorted(requested),
        "failures": list(dict.fromkeys(failures)),
        "approved_packet_run_id": RUN_ID,
        "packet_sha256": packet.sha256,
        "source_sha256": source.sha256,
        "migration_sha256": source.migration_sha256,
        "source_file_count": source.file_count,
        "checks": checks,
        "live_openai_canary": _live_canary_summary(),
        "verification_scope": (
            "focused_local_packaged_disabled_vertical_and_regression_checks"
        ),
        "pass_evidence_written": not failures,
    }
    if failures:
        _write_bounded(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    payloads: dict[str, dict[str, Any]] = {}
    for requirement in sorted(requested):
        requirement_checks = {
            check.name: checks[check.name]
            for check in COMMAND_CHECKS
            if requirement in check.requirements and check.name in checks
        }
        payloads[requirement] = {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": "pass",
            "test": "p11_receipt_intelligence::focused_local_verification",
            "recorded_at": recorded_at,
            "details": {
                "evaluator": "tools/evaluators/p11_receipt_intelligence.py",
                "approved_packet_run_id": RUN_ID,
                "checks": list(requirement_checks),
                "verification_sha256": _verification_hash(
                    requirement, packet, source, requirement_checks
                ),
                "public_summary": {
                    "acceptance_claim": "focused_local_requirement_passed",
                    "checks_passed": len(requirement_checks),
                    "live_openai_canary_status": "deferred",
                    "live_openai_canary_acceptance_claim": "deferred_not_passed",
                    "live_openai_canary_external_credentials_used": False,
                    "live_openai_canary_production_provider_calls": 0,
                    "packaged_disabled_state_coverage": (
                        "packaged_disabled_state" in requirement_checks
                    ),
                    "vertical_smoke_coverage": (
                        "vertical_smoke" in requirement_checks
                    ),
                    "external_credentials_used": False,
                    "production_provider_calls": 0,
                },
            },
        }

    written: list[Path] = []
    try:
        for requirement, payload in payloads.items():
            path = evidence_dir / f"{requirement}.json"
            _write_bounded(path, payload)
            written.append(path)
        _write_bounded(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)
        raise
    return 0
