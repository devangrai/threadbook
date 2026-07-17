"""Fail-closed evaluator for the approved P12 receipt-promotion packet."""

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
        "P12-PRJ-001",
        "P12-IDN-001",
        "P12-PRV-001",
        "P12-AUT-001",
        "P12-CAS-001",
        "P12-ATM-001",
        "P12-REL-001",
        "P12-DEC-001",
        "P12-DEL-001",
        "P12-UPG-001",
        "P12-UI-001",
        "P12-E2E-001",
    }
)
RUN_ID = "20260717T012423Z-64b81c09"
PACKET_DIR = f"artifacts/harness/P12/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
SPEC_FILE = "specs/phases/P12-receipt-promotion.md"
EVALUATOR_FILE = "tools/evaluators/p12_receipt_promotion.py"
EVALUATOR_TEST_FILE = "tests/test_p12_receipt_promotion_evaluator.py"
MIGRATION_FILE = (
    "crates/wardrobe-platform/migrations/"
    "0017_receipt_purchase_unit_promotion.sql"
)
MIGRATION_CHECKSUM_FILE = (
    "crates/wardrobe-platform/migrations/"
    "0017_receipt_purchase_unit_promotion.sha256"
)
EXPECTED_MIGRATION_SHA256 = (
    "cbcaf139c7b266ec89c5fd2edadd0c695196d720333bcefe584268cd9389d210"
)
MANUAL_REVIEW_NAME = "p12-manual-keyboard-review.json"
DIAGNOSTICS_NAME = "p12-receipt-promotion-diagnostics.json"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_MANUAL_REVIEW_BYTES = 32 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024
FOCUSED_TIMEOUT_SECONDS = 15 * 60
REGRESSION_TIMEOUT_SECONDS = 30 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    SPEC_FILE: (
        "4d69050e29ef43d0371e19a6bbc1512eb1bd13482c97321b3f88dc2e98fd3be4"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "094312a15a97971d4a8411f3d86ebe34a35c91b63bdca159f21ea19a41e7f04f"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "1ee4b119a126082def2f1b579645a11e216bcb1bc304bc95c2988013a21a7ff0"
    ),
    f"{PACKET_DIR}/review.md": (
        "f7562fe0079dc65515b13ff914ba56f4f19978538d1c3ce08787cc7f88720478"
    ),
}

# These values are deliberately assembled so the evaluator source itself does not
# contain a forbidden value. Tests and runtime checks use the exported bytes.
FORBIDDEN_SENTINELS = (
    b"p12-secret-" + b"sentinel",
    b"p12-personal-" + b"sentinel",
    b"p12-receipt-quote-" + b"sentinel",
    b"p12-canonical-item-" + b"sentinel",
)

CORE = frozenset(
    {
        "P12-IDN-001",
        "P12-PRV-001",
        "P12-AUT-001",
        "P12-DEL-001",
    }
)
REPOSITORY = frozenset(
    {
        "P12-PRJ-001",
        "P12-PRV-001",
        "P12-CAS-001",
        "P12-ATM-001",
        "P12-REL-001",
        "P12-DEC-001",
        "P12-DEL-001",
        "P12-E2E-001",
    }
)
MIGRATION = frozenset({"P12-UPG-001", "P12-DEL-001"})
TAURI = frozenset(
    {"P12-AUT-001", "P12-REL-001", "P12-UI-001", "P12-E2E-001"}
)
UI = frozenset({"P12-PRV-001", "P12-AUT-001", "P12-UI-001", "P12-E2E-001"})
VERTICAL = REQUIREMENT_IDS

CORE_TESTS = (
    "purchase_unit_contracts_are_strict_distinct_and_snapshot_bound",
    "promotion_requires_affirmative_user_authority",
    "promotion_decision_is_irreversible",
    "deletion_contracts_cover_unit_evidence_and_shared_records",
)
REPOSITORY_TESTS = (
    "projection_expands_only_current_user_reviewed_purchases",
    "promotion_is_atomic_replayable_and_cas_bound",
    "changed_line_ids_require_resolution_before_second_promotion",
    "unit_deletion_tombstones_survive_restart_and_preserve_siblings",
    "changed_line_ids_after_each_deletion_target_remain_blocked_until_source_deletion",
    "four_deletion_targets_have_directional_complete_closure",
    "promotion_undo_is_rejected_before_revision_or_write",
)
MIGRATION_TESTS = (
    "migration_0017_preserves_populated_v16_and_reopens",
    "interrupted_migration_0017_restores_v16_pragmas_and_foreign_keys",
)
TAURI_TESTS = ("receipt_purchase_unit_commands_use_real_local_state_across_restart",)
UI_TESTS = (
    "shows reviewed provenance and requires one item confirmation",
    "preserves the draft and focuses a live conflict summary",
    "navigates through the success link to the created catalog item",
)
PLAYWRIGHT_TESTS = (
    "keyboard-only reviewed receipt promotion survives restart at 390px",
)
EVALUATOR_TESTS = (
    "test_packet_tampering_is_rejected_for_every_pinned_file",
    "test_source_migration_and_forbidden_sentinel_tampering_fail_closed",
    "test_missing_named_command_marker_fails_without_pass_evidence",
    "test_command_failure_stops_checks_and_removes_stale_evidence",
    "test_runtime_sentinel_fails_and_never_enters_diagnostics",
    "test_evidence_publication_rolls_back_on_any_write_failure",
    "test_success_emits_one_record_per_requirement_and_diagnostics",
)
MANUAL_STEP_IDS = (
    "open-reviewed-receipt-with-keyboard",
    "inspect-unit-provenance-with-screen-reader",
    "cancel-and-reopen-one-item-dialog",
    "retain-draft-and-focus-conflict-summary",
    "activate-success-link-to-catalog",
    "verify-promoted-state-after-restart",
)


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
class ManualReviewValidation:
    errors: tuple[str, ...]
    sha256: str
    reviewer: str | None
    reviewed_at: str | None


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]
    requirements: frozenset[str]
    output_markers: tuple[str, ...] = ()
    success_marker: str | None = None
    reject_zero_tests: bool = False
    timeout_seconds: float = FOCUSED_TIMEOUT_SECONDS


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
            "receipt_promotion_contracts",
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
        "focused_repository",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "receipt_promotion_repository_tests::",
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
        "focused_migration",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "migration_0017_",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        MIGRATION,
        MIGRATION_TESTS,
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
            "receipt_purchase_unit_commands_use_real_local_state_across_restart",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        TAURI,
        TAURI_TESTS,
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
            "src/ReceiptPurchaseUnits.test.tsx",
            "src/receipt-promotion-bridge.test.ts",
        ),
        UI,
        (
            "src/ReceiptPurchaseUnits.test.tsx",
            "src/receipt-promotion-bridge.test.ts",
        ),
        "Test Files  2 passed",
    ),
    CommandCheck(
        "focused_playwright",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "test:e2e",
            "--",
            "receipt-promotion.spec.ts",
            "--reporter=list",
        ),
        frozenset({"P12-UI-001", "P12-E2E-001"}),
        PLAYWRIGHT_TESTS,
        "1 passed",
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
            "test_p12_receipt_promotion_evaluator.py",
        ),
        VERTICAL,
        success_marker="OK",
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
    CommandCheck(
        "regression_make_test",
        ("make", "test"),
        VERTICAL,
        timeout_seconds=REGRESSION_TIMEOUT_SECONDS,
    ),
)

SOURCE_REQUIREMENTS = {
    "crates/wardrobe-core/src/receipt_promotion.rs": CORE
    | frozenset({"P12-PRJ-001", "P12-CAS-001", "P12-REL-001"}),
    "crates/wardrobe-core/src/catalog.rs": frozenset(
        {"P12-AUT-001", "P12-DEL-001"}
    ),
    "crates/wardrobe-core/src/service.rs": TAURI | REPOSITORY,
    "crates/wardrobe-core/src/bindings.rs": CORE | UI,
    "crates/wardrobe-core/src/lib.rs": CORE,
    "crates/wardrobe-core/tests/receipt_promotion_contracts.rs": CORE,
    "crates/wardrobe-platform/src/receipt_promotion_repository.rs": REPOSITORY,
    "crates/wardrobe-platform/src/receipt_promotion_repository_tests.rs": REPOSITORY,
    "crates/wardrobe-platform/src/catalog_repository.rs": frozenset(
        {"P12-DEL-001", "P12-DEC-001"}
    ),
    "crates/wardrobe-platform/src/deletion_repository.rs": frozenset(
        {"P12-DEL-001", "P12-DEC-001"}
    ),
    "crates/wardrobe-platform/src/backup_repository.rs": frozenset(
        {"P12-DEL-001", "P12-UPG-001"}
    ),
    "crates/wardrobe-platform/src/database.rs": MIGRATION,
    "crates/wardrobe-platform/src/lib.rs": REPOSITORY,
    MIGRATION_FILE: MIGRATION,
    MIGRATION_CHECKSUM_FILE: MIGRATION,
    "src-tauri/src/lib.rs": TAURI,
    "src-tauri/build.rs": TAURI,
    "src-tauri/capabilities/main.json": TAURI,
    "src-tauri/permissions/autogenerated/list_receipt_purchase_units_v1.toml": TAURI,
    "src-tauri/permissions/autogenerated/promote_receipt_purchase_unit_v1.toml": TAURI,
    "apps/desktop-ui/src/ReceiptsWorkspace.tsx": UI,
    "apps/desktop-ui/src/ReceiptPurchaseUnits.tsx": UI,
    "apps/desktop-ui/src/ReceiptPurchaseUnits.test.tsx": UI,
    "apps/desktop-ui/src/receipt-promotion-bridge.ts": UI | TAURI,
    "apps/desktop-ui/src/receipt-promotion-bridge.test.ts": UI,
    "apps/desktop-ui/src/generated/contracts.ts": UI | CORE,
    "apps/desktop-ui/e2e/receipt-promotion.spec.ts": frozenset(
        {"P12-UI-001", "P12-E2E-001"}
    ),
    EVALUATOR_FILE: VERTICAL,
    EVALUATOR_TEST_FILE: VERTICAL,
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read(path: Path, limit: int = MAX_SOURCE_BYTES) -> bytes | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


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


def _has_forbidden_sentinel(data: bytes) -> bool:
    return any(sentinel in data for sentinel in FORBIDDEN_SENTINELS)


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
        or requirements.get("phase") != "P12"
        or not isinstance(selected, list)
        or set(selected) != REQUIREMENT_IDS
        or len(selected) != len(REQUIREMENT_IDS)
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("approved P12 requirement selection is not exact")

    state_data = _read(root / STATE_FILE)
    state = _json_object(state_data or b"")
    review = state.get("review")
    expected_spec_hashes = {
        "specs/system.md": EXPECTED_PACKET_HASHES["specs/system.md"],
        SPEC_FILE: EXPECTED_PACKET_HASHES[SPEC_FILE],
    }
    if state_data is None:
        errors.append("approved P12 state is unreadable or oversized")
    if (
        state.get("schema_version") != 1
        or state.get("phase") != "P12"
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
        errors.append("P12 packet is not independently approved")

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
        errors.append("approved P12 review decision is missing or inconsistent")

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
                    f"required P12 artifact unreadable or oversized: {relative}"
                )
            continue
        contents[relative] = data
        if _has_forbidden_sentinel(data):
            for requirement in requirements:
                errors[requirement].append(
                    f"forbidden P12 sentinel found in required source: {relative}"
                )
        try:
            texts[relative] = data.decode()
        except UnicodeDecodeError:
            for requirement in requirements:
                errors[requirement].append(
                    f"required P12 artifact is not UTF-8: {relative}"
                )

    def require(relative: str, requirements: frozenset[str], *markers: str) -> None:
        source = texts.get(relative, "")
        for marker in markers:
            if marker not in source:
                for requirement in requirements:
                    errors[requirement].append(
                        f"P12 invariant missing from {relative}: {marker}"
                    )

    require(
        "crates/wardrobe-core/src/receipt_promotion.rs",
        CORE | frozenset({"P12-PRJ-001", "P12-CAS-001", "P12-REL-001"}),
        "ReceiptPurchaseUnitId",
        "ReceiptPromotionId",
        "ReceiptAuthoritySnapshotId",
        "ReceiptPurchaseUnitExclusionReasonV1",
        "ReceiptPurchaseUnitFieldProvenanceV1",
        "ListReceiptPurchaseUnitsV1Request",
        "PromoteReceiptPurchaseUnitV1Request",
        "ReceiptPromotionConfirmationV1",
        "#[serde(deny_unknown_fields)]",
    )
    require(
        "crates/wardrobe-core/src/catalog.rs",
        frozenset({"P12-AUT-001", "P12-DEL-001"}),
        "ReceiptPurchaseUnit",
        "PromoteReceiptPurchaseUnit",
        "PurchaseUnit",
        "ReceiptPurchaseUnitEvidence",
        "RetainedSharedRecords",
        "allows_generic_undo",
    )
    require(
        "crates/wardrobe-core/src/service.rs",
        TAURI | REPOSITORY,
        "pub fn list_receipt_purchase_units_v1",
        "pub fn promote_receipt_purchase_unit_v1",
    )
    require(
        "crates/wardrobe-core/src/bindings.rs",
        CORE | UI,
        "ReceiptPurchaseUnitId::decl()",
        "ListReceiptPurchaseUnitsV1Request::decl()",
        "ListReceiptPurchaseUnitsV1Response::decl()",
        "PromoteReceiptPurchaseUnitV1Request::decl()",
        "PromoteReceiptPurchaseUnitV1Response::decl()",
    )
    require(
        "crates/wardrobe-core/src/lib.rs",
        CORE,
        "mod receipt_promotion;",
        "pub use receipt_promotion::*;",
    )
    for name in CORE_TESTS:
        require(
            "crates/wardrobe-core/tests/receipt_promotion_contracts.rs",
            CORE,
            f"fn {name}",
        )

    require(
        "crates/wardrobe-platform/src/receipt_promotion_repository.rs",
        REPOSITORY,
        "transaction_with_behavior(TransactionBehavior::Immediate)",
        "replay::<_, PromoteReceiptPurchaseUnitV1Response>",
        "receipt_authority_snapshots",
        "receipt_purchase_unit_promotions",
        "receipt_purchase_unit_deletions",
        "DecisionKindV1::PromoteReceiptPurchaseUnit",
        "reversible: false",
        "store_receipt(",
    )
    for name in REPOSITORY_TESTS:
        require(
            "crates/wardrobe-platform/src/receipt_promotion_repository_tests.rs",
            REPOSITORY,
            f"fn {name}",
        )
    require(
        "crates/wardrobe-platform/src/catalog_repository.rs",
        frozenset({"P12-DEL-001", "P12-DEC-001"}),
        "DeletionTargetKindV1::PurchaseUnit",
        "DeletionTargetKindV1::ReceiptPurchaseUnitEvidence",
        "DeletionDependencyClassV1::RetainedSharedRecords",
        "receipt_purchase_unit_deletions",
        "receipt_purchase_unit_promotions",
        "receipt_authority_snapshots",
    )
    require(
        "crates/wardrobe-platform/src/deletion_repository.rs",
        frozenset({"P12-DEL-001", "P12-DEC-001"}),
        'ReceiptAuthoritySnapshots => "receipt_authority_snapshots"',
        'ReceiptPurchaseUnitPromotions => "receipt_purchase_unit_promotions"',
        'ReceiptPurchaseUnitDeletions => "receipt_purchase_unit_deletions"',
        "DeletionTargetKindV1::PurchaseUnit",
        "DeletionTargetKindV1::ReceiptPurchaseUnitEvidence",
    )
    require(
        "crates/wardrobe-platform/src/backup_repository.rs",
        frozenset({"P12-DEL-001", "P12-UPG-001"}),
        "DeletionTargetKindV1::PurchaseUnit",
        "DeletionTargetKindV1::ReceiptPurchaseUnitEvidence",
        "receipt_purchase_unit_deletions",
    )
    require(
        "crates/wardrobe-platform/src/lib.rs",
        REPOSITORY,
        "mod receipt_promotion_repository;",
        "mod receipt_promotion_repository_tests;",
    )
    require(
        "crates/wardrobe-platform/src/database.rs",
        MIGRATION,
        "MIGRATION_0017_SQL",
        "MIGRATION_0017_SHA256",
        "version: 17",
    )
    for name in MIGRATION_TESTS:
        require(
            "crates/wardrobe-platform/src/database.rs",
            MIGRATION,
            f"fn {name}",
        )
    require(
        MIGRATION_FILE,
        MIGRATION,
        "PRAGMA legacy_alter_table = ON",
        "CREATE TABLE receipt_authority_snapshots",
        "CREATE TABLE receipt_purchase_unit_promotions",
        "CREATE TABLE receipt_purchase_unit_deletions",
        "receipt_purchase_unit_promotions_no_update",
        "receipt_purchase_unit_deletions_no_update",
        "PRAGMA legacy_alter_table = OFF",
        ") STRICT;",
    )
    migration_hash = _sha256(contents.get(MIGRATION_FILE, b""))
    if (
        migration_hash != EXPECTED_MIGRATION_SHA256
        or texts.get(MIGRATION_CHECKSUM_FILE, "").strip()
        != EXPECTED_MIGRATION_SHA256
    ):
        for requirement in MIGRATION:
            errors[requirement].append(
                "receipt-promotion migration checksum mismatch"
            )

    require(
        "src-tauri/src/lib.rs",
        TAURI,
        '"list_receipt_purchase_units_v1"',
        '"promote_receipt_purchase_unit_v1"',
        "handle_list_receipt_purchase_units",
        "handle_promote_receipt_purchase_unit",
        "list_receipt_purchase_units_v1,",
        "promote_receipt_purchase_unit_v1,",
        "fn classify_command",
        f"fn {TAURI_TESTS[0]}",
    )
    require(
        "src-tauri/build.rs",
        TAURI,
        '"list_receipt_purchase_units_v1"',
        '"promote_receipt_purchase_unit_v1"',
    )
    require(
        "src-tauri/capabilities/main.json",
        TAURI,
        "allow-list-receipt-purchase-units-v1",
        "allow-promote-receipt-purchase-unit-v1",
    )
    require(
        "src-tauri/permissions/autogenerated/list_receipt_purchase_units_v1.toml",
        TAURI,
        "allow-list-receipt-purchase-units-v1",
        'commands.allow = ["list_receipt_purchase_units_v1"]',
        "deny-list-receipt-purchase-units-v1",
        'commands.deny = ["list_receipt_purchase_units_v1"]',
    )
    require(
        "src-tauri/permissions/autogenerated/promote_receipt_purchase_unit_v1.toml",
        TAURI,
        "allow-promote-receipt-purchase-unit-v1",
        'commands.allow = ["promote_receipt_purchase_unit_v1"]',
        "deny-promote-receipt-purchase-unit-v1",
        'commands.deny = ["promote_receipt_purchase_unit_v1"]',
    )

    require(
        "apps/desktop-ui/src/ReceiptsWorkspace.tsx",
        UI,
        'from "./ReceiptPurchaseUnits"',
        "<ReceiptPurchaseUnits",
    )
    require(
        "apps/desktop-ui/src/ReceiptPurchaseUnits.tsx",
        UI,
        "Purchase units",
        "Add to wardrobe",
        "Create one wardrobe item",
        'role="dialog"',
        'aria-live="assertive"',
        "conflictRef.current?.focus()",
        "successRef.current?.focus()",
    )
    for name in UI_TESTS:
        require(
            "apps/desktop-ui/src/ReceiptPurchaseUnits.test.tsx",
            UI,
            name,
        )
    require(
        "apps/desktop-ui/src/receipt-promotion-bridge.ts",
        UI | TAURI,
        '"list_receipt_purchase_units_v1"',
        '"promote_receipt_purchase_unit_v1"',
        'confirmation: "create_one_wardrobe_item"',
        'category_authority: "user_selected"',
    )
    require(
        "apps/desktop-ui/src/receipt-promotion-bridge.test.ts",
        UI,
        "uses snapshot-bound generated list and promotion contracts",
        "list_receipt_purchase_units_v1",
        "promote_receipt_purchase_unit_v1",
    )
    require(
        "apps/desktop-ui/src/generated/contracts.ts",
        UI | CORE,
        "ListReceiptPurchaseUnitsV1Request",
        "ListReceiptPurchaseUnitsV1Response",
        "PromoteReceiptPurchaseUnitV1Request",
        "PromoteReceiptPurchaseUnitV1Response",
    )
    require(
        "apps/desktop-ui/e2e/receipt-promotion.spec.ts",
        frozenset({"P12-UI-001", "P12-E2E-001"}),
        PLAYWRIGHT_TESTS[0],
        "AxeBuilder",
        "width: 390",
        'page.keyboard.press("Tab")',
        'page.keyboard.press("Shift+Tab")',
        'page.keyboard.press("Enter")',
        'page.keyboard.press("Space")',
        'page.keyboard.press("Escape")',
        "expectNoHorizontalOverflow",
        "replayLastPromotion",
    )
    for name in EVALUATOR_TESTS:
        require(
            EVALUATOR_TEST_FILE,
            VERTICAL,
            f"def {name}",
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


def validate_manual_review(
    evidence_dir: Path, source_sha256: str
) -> ManualReviewValidation:
    path = evidence_dir / MANUAL_REVIEW_NAME
    data = _read(path, MAX_MANUAL_REVIEW_BYTES)
    errors: list[str] = []
    if data is None:
        return ManualReviewValidation(
            ("P12 manual keyboard review is unreadable, missing, or oversized",),
            "",
            None,
            None,
        )
    if _has_forbidden_sentinel(data):
        errors.append("P12 manual keyboard review contains a forbidden sentinel")
    value = _json_object(data)
    reviewer = value.get("reviewer")
    reviewed_at = value.get("reviewed_at")
    viewport = value.get("tested_viewport")
    steps = value.get("steps")
    if set(value) != {
        "schema_version",
        "reviewer",
        "reviewed_at",
        "build_fingerprint",
        "tested_viewport",
        "steps",
    }:
        errors.append("P12 manual keyboard review fields are not exact")
    if (
        value.get("schema_version") != 1
        or not isinstance(reviewer, str)
        or re.fullmatch(r"reviewer-[a-z0-9-]{3,96}", reviewer) is None
        or value.get("build_fingerprint") != source_sha256
        or viewport != {"width": 390, "height": 844}
    ):
        errors.append("P12 manual keyboard review identity or build binding is invalid")
    try:
        timestamp = dt.datetime.fromisoformat(
            reviewed_at.replace("Z", "+00:00")
            if isinstance(reviewed_at, str)
            else ""
        )
        if timestamp.utcoffset() != dt.timedelta(0):
            raise ValueError
    except (TypeError, ValueError):
        errors.append("P12 manual keyboard review timestamp is not UTC")
    if (
        not isinstance(steps, list)
        or len(steps) != len(MANUAL_STEP_IDS)
        or any(
            not isinstance(step, dict)
            or set(step) != {"id", "result"}
            or step.get("id") != expected
            or step.get("result") != "pass"
            for step, expected in zip(
                steps if isinstance(steps, list) else (), MANUAL_STEP_IDS
            )
        )
    ):
        errors.append("P12 manual keyboard review steps are not exact passes")
    return ManualReviewValidation(
        tuple(dict.fromkeys(errors)),
        _sha256(data),
        reviewer if isinstance(reviewer, str) else None,
        reviewed_at if isinstance(reviewed_at, str) else None,
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
    if _has_forbidden_sentinel(result.captured_output):
        return f"P12 check emitted a forbidden sentinel: {check.name}"
    if (
        result.returncode != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.launch_failed
    ):
        return f"P12 check failed: {check.name}"
    output = result.captured_output.decode(errors="replace")
    executed_test_counts = tuple(
        int(count)
        for count in re.findall(r"^running (\d+) tests?$", output, re.MULTILINE)
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
        return f"P12 check did not prove its expected scope: {check.name}"
    return None


def _write_bounded(path: Path, value: dict[str, Any]) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P12 evaluator artifact exceeds size bound")
    if _has_forbidden_sentinel(data):
        raise ValueError("P12 evaluator artifact contains a forbidden sentinel")
    write_atomic_json(path, value)


def _remove_outputs(evidence_dir: Path) -> None:
    for requirement in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
    (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)


def _verification_hash(
    requirement: str,
    packet: PacketValidation,
    source: SourceValidation,
    manual: ManualReviewValidation,
    checks: dict[str, dict[str, Any]],
) -> str:
    value = {
        "requirement_id": requirement,
        "approved_packet_run_id": RUN_ID,
        "packet_sha256": packet.sha256,
        "source_sha256": source.sha256,
        "migration_sha256": source.migration_sha256,
        "manual_review_sha256": manual.sha256,
        "checks": checks,
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
    manual = validate_manual_review(evidence_dir, source.sha256)
    failures = list(packet.errors)
    failures.extend(manual.errors)
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
        "GOOGLE_CLIENT_SECRET",
        "GMAIL_CLIENT_SECRET",
        "P12_FORBIDDEN_SECRET_SENTINEL",
        "P12_FORBIDDEN_PERSONAL_SENTINEL",
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
                timeout_seconds=check.timeout_seconds,
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
        "manual_review_sha256": manual.sha256,
        "manual_review_valid": not manual.errors,
        "checks": checks,
        "verification_scope": (
            "focused_core_repository_migration_tauri_ui_playwright_evaluator_"
            "and_phase_regression"
        ),
        "external_credentials_used": False,
        "remote_calls_permitted": False,
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
            "test": "p12_receipt_promotion::focused_local_verification",
            "recorded_at": recorded_at,
            "details": {
                "evaluator": EVALUATOR_FILE,
                "approved_packet_run_id": RUN_ID,
                "checks": list(requirement_checks),
                "verification_sha256": _verification_hash(
                    requirement, packet, source, manual, requirement_checks
                ),
                "public_summary": {
                    "acceptance_claim": "focused_local_requirement_passed",
                    "checks_passed": len(requirement_checks),
                    "manual_keyboard_review": "pass",
                    "manual_keyboard_review_sha256": manual.sha256,
                    "external_credentials_used": False,
                    "production_remote_calls": 0,
                },
            },
        }

    written: list[Path] = []
    try:
        for requirement, payload in payloads.items():
            path = evidence_dir / f"{requirement}.json"
            _write_bounded(path, payload)
            written.append(path)
        diagnostics_path = evidence_dir / DIAGNOSTICS_NAME
        _write_bounded(diagnostics_path, diagnostics)
        written.append(diagnostics_path)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        for requirement in REQUIREMENT_IDS:
            (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
        (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)
        raise
    return 0
