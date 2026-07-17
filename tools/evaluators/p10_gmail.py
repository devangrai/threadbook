"""Fail-closed evaluator for the approved P10 Gmail packets."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from tools.evaluators.p03_receipts import (
    CommandResult,
    run_bounded_command,
    write_atomic_json,
)


PACKET_1_REQUIREMENT_IDS = frozenset(
    {"P10-GML-001", "P10-GML-002", "P10-GML-003", "P10-AUT-001"}
)
PACKET_2_REQUIREMENT_IDS = frozenset(
    {
        "P10-GML-004",
        "P10-GML-005",
        "P10-GML-006",
        "P10-GML-007",
        "P10-GML-008",
        "P10-GML-009",
    }
)
PACKET_3_REQUIREMENT_IDS = frozenset({"P10-GML-010", "P10-UI-001"})
REQUIREMENT_IDS = (
    PACKET_1_REQUIREMENT_IDS | PACKET_2_REQUIREMENT_IDS | PACKET_3_REQUIREMENT_IDS
)
RUN_ID = "20260716T192959Z-cd549a04"
PACKET_DIR = f"artifacts/harness/P10/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
PACKET_2_RUN_ID = "20260716T193215Z-c2a10929"
PACKET_3_RUN_ID = "20260716T194203Z-14e7bed0"
DIAGNOSTICS_NAME = "p10-gmail-diagnostics.json"
MIGRATION_FILE = "crates/wardrobe-platform/migrations/0015_gmail_query_discovery.sql"
MIGRATION_CHECKSUM_FILE = (
    "crates/wardrobe-platform/migrations/0015_gmail_query_discovery.sha256"
)
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024
COMMAND_TIMEOUT_SECONDS = 15 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P10-gmail-wardrobe.md": (
        "a37caed761091ab4536867049e2615724e1da396c1fa937ab4e214014a41f6dd"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "b7c9214e4eed707fdbe733b61f776ff3bd1cdf0f969e4328b23ca5bef1aec71d"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "d2816e431fd7b7cea10cc3c2b87333a746b2d10cd301ef754eb4c8bb3a0d1b5f"
    ),
    f"{PACKET_DIR}/review.md": (
        "520b7dfcaaead3b4d6de0809d65570987e83e8196073076975bdff71900de2c8"
    ),
}


@dataclass(frozen=True)
class ApprovedPacket:
    run_id: str
    owned_requirement_ids: frozenset[str]
    selected_requirement_ids: frozenset[str]
    expected_hashes: dict[str, str]

    @property
    def packet_dir(self) -> str:
        return f"artifacts/harness/P10/{self.run_id}"

    @property
    def state_file(self) -> str:
        return f"{self.packet_dir}/state.json"


APPROVED_PACKETS = {
    RUN_ID: ApprovedPacket(
        RUN_ID,
        PACKET_1_REQUIREMENT_IDS,
        PACKET_1_REQUIREMENT_IDS,
        EXPECTED_PACKET_HASHES,
    ),
    PACKET_2_RUN_ID: ApprovedPacket(
        PACKET_2_RUN_ID,
        PACKET_2_REQUIREMENT_IDS,
        PACKET_2_REQUIREMENT_IDS,
        {
            "specs/system.md": EXPECTED_PACKET_HASHES["specs/system.md"],
            "specs/phases/P10-gmail-wardrobe.md": EXPECTED_PACKET_HASHES[
                "specs/phases/P10-gmail-wardrobe.md"
            ],
            f"artifacts/harness/P10/{PACKET_2_RUN_ID}/requirements.json": (
                "076931d55179c89260d34116af3d218de1043ec1442d8318f8b81f204500d5b2"
            ),
            f"artifacts/harness/P10/{PACKET_2_RUN_ID}/proposal.md": (
                "83a2c06f84f7cc1f72d8e58292e2cafc5d57d6317a9fea18746b3f5148c70236"
            ),
            f"artifacts/harness/P10/{PACKET_2_RUN_ID}/review.md": (
                "fa820e937962af2823a39512d0df3beb1e40e4ce8ccd3d5ac271de121a954471"
            ),
        },
    ),
    PACKET_3_RUN_ID: ApprovedPacket(
        PACKET_3_RUN_ID,
        PACKET_3_REQUIREMENT_IDS,
        PACKET_3_REQUIREMENT_IDS,
        {
            "specs/system.md": EXPECTED_PACKET_HASHES["specs/system.md"],
            "specs/phases/P10-gmail-wardrobe.md": EXPECTED_PACKET_HASHES[
                "specs/phases/P10-gmail-wardrobe.md"
            ],
            f"artifacts/harness/P10/{PACKET_3_RUN_ID}/requirements.json": (
                "f1b95dd9c6c28d6e3686c7a03badd69954dbf0393fb11727b829eef40afb844d"
            ),
            f"artifacts/harness/P10/{PACKET_3_RUN_ID}/proposal.md": (
                "27b5738fa8463f88a3eb21f11f935d8b9dbfbf41aacaa3cf89cc79fc414a340b"
            ),
            f"artifacts/harness/P10/{PACKET_3_RUN_ID}/review.md": (
                "46c9ef9d16d2a0e58dcf8eb186d3024af2fbd18dccc285d92961b7c194b65b73"
            ),
        },
    ),
}
REQUIREMENT_PACKET_RUN = {
    requirement: packet.run_id
    for packet in APPROVED_PACKETS.values()
    for requirement in packet.owned_requirement_ids
}

SOURCE_REQUIREMENTS = {
    "crates/wardrobe-core/src/gmail_connector.rs": {
        "P10-GML-001",
    },
    "crates/wardrobe-core/src/bindings.rs": {"P10-GML-001"},
    "crates/wardrobe-core/src/service.rs": {"P10-GML-001"},
    "crates/wardrobe-core/tests/gmail_connector_contracts.rs": {
        "P10-GML-001",
    },
    "crates/wardrobe-platform/src/database.rs": {"P10-GML-002"},
    MIGRATION_FILE: {"P10-GML-002", "P10-GML-010"},
    MIGRATION_CHECKSUM_FILE: {"P10-GML-002", "P10-GML-010"},
    "crates/wardrobe-platform/src/gmail_sync.rs": {
        "P10-GML-002",
        "P10-GML-004",
        "P10-GML-005",
        "P10-GML-006",
        "P10-GML-009",
    },
    "crates/wardrobe-platform/src/gmail_connector.rs": {
        "P10-GML-002",
        "P10-GML-003",
        "P10-GML-008",
        "P10-GML-009",
        "P10-GML-010",
    },
    "crates/wardrobe-platform/src/gmail_repository.rs": {
        "P10-GML-003",
        "P10-GML-005",
        "P10-GML-006",
        "P10-GML-007",
        "P10-GML-008",
        "P10-GML-009",
    },
    "crates/wardrobe-platform/src/gmail_http.rs": {
        "P10-GML-004",
        "P10-GML-009",
        "P10-AUT-001",
    },
    "crates/wardrobe-platform/src/blob.rs": {
        "P10-GML-005",
        "P10-GML-008",
    },
    "crates/wardrobe-platform/src/deletion_repository.rs": {"P10-GML-009"},
    "apps/desktop-ui/src/GmailConnectorSettings.tsx": {"P10-UI-001"},
    "apps/desktop-ui/src/GmailConnectorSettings.test.tsx": {"P10-UI-001"},
    "apps/desktop-ui/src/generated/contracts.ts": {"P10-UI-001"},
    "apps/desktop-ui/src/gmail-connector-bridge.test.ts": {
        "P10-GML-010",
        "P10-UI-001",
    },
    "apps/desktop-ui/e2e/gmail-connector.spec.ts": {"P10-UI-001"},
    "src-tauri/src/lib.rs": {"P10-UI-001"},
    "src-tauri/capabilities/main.json": {"P10-UI-001"},
    "src-tauri/permissions/autogenerated/get_gmail_connector_v2.toml": {"P10-UI-001"},
    "src-tauri/permissions/autogenerated/save_gmail_settings_v2.toml": {"P10-UI-001"},
}


@dataclass(frozen=True)
class PacketValidation:
    errors: tuple[str, ...]
    sha256: str
    run_ids: tuple[str, ...] = ()


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
    test_names: tuple[str, ...]
    requirements: frozenset[str]
    success_marker: str = "test result: ok"


COMMAND_CHECKS = (
    CommandCheck(
        "v2_discovery_contract",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-core",
            "--offline",
            "--test",
            "gmail_connector_contracts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        (
            "gmail_v2_discovery_scopes_have_exact_strict_tagged_wire_shapes",
            "gmail_v2_requests_settings_and_responses_reject_unknown_fields",
            "gmail_search_queries_use_utf8_byte_boundaries_and_reject_controls",
            "gmail_search_query_whitespace_is_preserved_without_normalization",
            "gmail_v2_schema_versions_are_strict_at_decode_and_validation",
        ),
        frozenset({"P10-GML-001"}),
    ),
    CommandCheck(
        "legacy_settings_migration",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "migration_0015_preserves_populated_v14_gmail_state_and_reopens",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("migration_0015_preserves_populated_v14_gmail_state_and_reopens",),
        frozenset({"P10-GML-002"}),
    ),
    CommandCheck(
        "legacy_expired_cursor_regression",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "expired_history_reconciles_listed_union_known_unlisted_once",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("expired_history_reconciles_listed_union_known_unlisted_once",),
        frozenset({"P10-GML-002", "P10-GML-009"}),
    ),
    CommandCheck(
        "search_scope_identity",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "gmail_scope_identity_is_versioned_and_byte_exact",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("gmail_scope_identity_is_versioned_and_byte_exact",),
        frozenset({"P10-GML-003"}),
    ),
    CommandCheck(
        "gmail_read_only_authority",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "gmail_authority_is_exact_and_read_only",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("gmail_authority_is_exact_and_read_only",),
        frozenset({"P10-AUT-001"}),
    ),
    CommandCheck(
        "search_http_query",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "local_tls_drives_token_userinfo_and_gmail_adapter",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("local_tls_drives_token_userinfo_and_gmail_adapter",),
        frozenset({"P10-GML-004"}),
    ),
    CommandCheck(
        "search_pagination_and_deduplication",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "search_pagination_and_repeated_revisions_publish_once_to_real_repository",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("search_pagination_and_repeated_revisions_publish_once_to_real_repository",),
        frozenset({"P10-GML-004", "P10-GML-006"}),
    ),
    CommandCheck(
        "search_atomic_failures",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "search_limit_and_raw_fetch_failures_preserve_real_repository_atomically",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("search_limit_and_raw_fetch_failures_preserve_real_repository_atomically",),
        frozenset({"P10-GML-005"}),
    ),
    CommandCheck(
        "search_coordinator_boundaries",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "gmail_sync::tests::search_",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        (
            "search_exhausts_pages_deduplicates_and_ignores_known_unlisted_sources",
            "search_boundaries_and_late_raw_failure_never_commit",
            "search_runs_a_complete_scan_every_time_and_retains_unlisted_known_messages",
            "search_accepts_exact_byte_and_call_limits_and_rejects_one_over_atomically",
            "search_rejects_token_cycles_timeouts_and_vanished_listed_messages_atomically",
            "search_persistence_failure_does_not_publish_a_batch",
        ),
        frozenset(
            {
                "P10-GML-004",
                "P10-GML-005",
                "P10-GML-007",
                "P10-GML-009",
            }
        ),
    ),
    CommandCheck(
        "search_atomic_publication_restart",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "interrupted_publication_is_removed_on_reopen_and_retry_succeeds",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("interrupted_publication_is_removed_on_reopen_and_retry_succeeds",),
        frozenset({"P10-GML-005", "P10-GML-008"}),
    ),
    CommandCheck(
        "search_committed_blob_recovery",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "committed_cleanup_failure_returns_success_and_recovers_manifest",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("committed_cleanup_failure_returns_success_and_recovers_manifest",),
        frozenset({"P10-GML-008"}),
    ),
    CommandCheck(
        "search_preexisting_blob_rollback",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "failed_publication_never_removes_preexisting_same_hash_blob",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("failed_publication_never_removes_preexisting_same_hash_blob",),
        frozenset({"P10-GML-005"}),
    ),
    CommandCheck(
        "search_first_scope_rollback",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "first_scope_and_account_roll_back_with_failed_publication",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("first_scope_and_account_roll_back_with_failed_publication",),
        frozenset({"P10-GML-005"}),
    ),
    CommandCheck(
        "search_blob_rollback_serialization",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "operation_rollback_serializes_same_hash_importer_before_removal",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("operation_rollback_serializes_same_hash_importer_before_removal",),
        frozenset({"P10-GML-005", "P10-GML-008"}),
    ),
    CommandCheck(
        "search_result_retention",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "later_search_scan_retains_sources_absent_from_current_results",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("later_search_scan_retains_sources_absent_from_current_results",),
        frozenset({"P10-GML-007"}),
    ),
    CommandCheck(
        "search_restart_operation",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "startup_reopens_and_discards_interrupted_sync_without_losing_evidence",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("startup_reopens_and_discards_interrupted_sync_without_losing_evidence",),
        frozenset({"P10-GML-008"}),
    ),
    CommandCheck(
        "search_label_mode_separation",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "label_removal_does_not_hide_overlapping_search_scope",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("label_removal_does_not_hide_overlapping_search_scope",),
        frozenset({"P10-GML-009"}),
    ),
    CommandCheck(
        "search_http_mode_separation",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "discovery_modes_reject_cross_mode_listing_and_history_calls",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("discovery_modes_reject_cross_mode_listing_and_history_calls",),
        frozenset({"P10-GML-009"}),
    ),
    CommandCheck(
        "search_deletion_inventory",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "gmail_scope_availability_rows_are_guarded_and_planned_with_membership",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("gmail_scope_availability_rows_are_guarded_and_planned_with_membership",),
        frozenset({"P10-GML-009"}),
    ),
    CommandCheck(
        "sync_command_replay",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "completed_sync_replay_is_write_free_and_cross_command_reuse_conflicts",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("completed_sync_replay_is_write_free_and_cross_command_reuse_conflicts",),
        frozenset({"P10-GML-010"}),
    ),
    CommandCheck(
        "connect_command_replay",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "terminal_connect_replay_is_provider_keychain_and_write_free",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("terminal_connect_replay_is_provider_keychain_and_write_free",),
        frozenset({"P10-GML-010"}),
    ),
    CommandCheck(
        "request_reservation_restart",
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-platform",
            "--offline",
            "--lib",
            "cleaned_up_request_reservation_conflicts_after_restart",
            "--",
            "--nocapture",
            "--test-threads=1",
        ),
        ("cleaned_up_request_reservation_conflicts_after_restart",),
        frozenset({"P10-GML-010"}),
    ),
    CommandCheck(
        "gmail_settings_ui",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "GmailConnectorSettings.test.tsx",
            "gmail-connector-bridge.test.ts",
        ),
        (
            "src/GmailConnectorSettings.test.tsx",
            "src/gmail-connector-bridge.test.ts",
        ),
        frozenset({"P10-UI-001"}),
        "Test Files  2 passed",
    ),
    CommandCheck(
        "gmail_ui_smoke",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "test:e2e",
            "--",
            "gmail-connector.spec.ts",
            "--reporter=list",
        ),
        ("Gmail settings UI persists through reload and retains imported evidence",),
        frozenset({"P10-UI-001"}),
        "1 passed",
    ),
)


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


def validate_packet(root: Path, run_id: str = RUN_ID) -> PacketValidation:
    packet = APPROVED_PACKETS.get(run_id)
    if packet is None:
        return PacketValidation(
            (f"unregistered approved P10 packet: {run_id}",),
            _sha256(b""),
            (),
        )
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    for relative, expected in packet.expected_hashes.items():
        data = _read(root / relative)
        if data is None:
            errors.append(f"approved packet file unreadable or oversized: {relative}")
            continue
        contents[relative] = data
        if _sha256(data) != expected:
            errors.append(f"approved packet hash mismatch: {relative}")

    requirements = _json_object(
        contents.get(f"{packet.packet_dir}/requirements.json", b"")
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
        requirements.get("phase") != "P10"
        or not isinstance(selected, list)
        or set(selected) != packet.selected_requirement_ids
        or len(selected) != len(packet.selected_requirement_ids)
        or evidenced != packet.selected_requirement_ids
    ):
        errors.append(f"approved P10 requirement selection is not exact: {run_id}")

    state_data = _read(root / packet.state_file)
    state = _json_object(state_data or b"")
    review = state.get("review")
    if state_data is None:
        errors.append(f"approved P10 state is unreadable or oversized: {run_id}")
    proposal_path = f"{packet.packet_dir}/proposal.md"
    if (
        state.get("phase") != "P10"
        or state.get("run_id") != run_id
        or state.get("status")
        not in {
            "APPROVED",
            "BUILT",
            "BUILD_FAILED",
            "EVALUATED",
            "EVALUATION_FAILED",
        }
        or state.get("selected_requirement_ids") != selected
        or not isinstance(review, dict)
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash") != packet.expected_hashes[proposal_path]
    ):
        errors.append(f"P10 packet is not independently approved: {run_id}")

    review_text = contents.get(f"{packet.packet_dir}/review.md", b"").decode(
        errors="replace"
    )
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append(f"approved P10 review decision is missing: {run_id}")
    return PacketValidation(
        tuple(dict.fromkeys(errors)),
        _aggregate(contents),
        (run_id,),
    )


def validate_packets(root: Path, selected: set[str]) -> PacketValidation:
    run_ids = sorted(
        {
            REQUIREMENT_PACKET_RUN[requirement]
            for requirement in selected & REQUIREMENT_IDS
        }
    )
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    for run_id in run_ids:
        validation = validate_packet(root, run_id)
        errors.extend(validation.errors)
        contents[run_id] = validation.sha256.encode()
    return PacketValidation(
        tuple(dict.fromkeys(errors)),
        _aggregate(contents),
        tuple(run_ids),
    )


def _function_body(source: str, name: str) -> str:
    match = re.search(
        rf"\bfn\s+{re.escape(name)}(?:\s*<[^>{{}}]*>)?\s*\([^)]*\)[^{{]*\{{",
        source,
    )
    if match is None:
        return ""
    start = match.end() - 1
    depth = 0
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    return ""


def _gmail_api_get_errors(source: str) -> list[str]:
    errors: list[str] = []
    starts = [
        match.start()
        for match in re.finditer(r"\blet(?:\s+mut)?\s+url\s*=\s*gmail_url\(", source)
    ]
    if len(starts) < 4:
        errors.append("Gmail API path allowlist is missing concrete calls")
        return errors
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(source)
        requests = [
            position
            for position in (
                source.find(".request_json(", start, end),
                source.find(".request(", start, end),
            )
            if position >= 0
        ]
        if not requests:
            errors.append("Gmail API URL is not followed by a bounded request")
            continue
        request = min(requests)
        window = source[start : min(request + 256, end)]
        if "Method::GET" not in window:
            errors.append("Gmail API request is not GET-only")
    gmail_paths = set(re.findall(r'"(users/me/[^"]+)"', source))
    allowed = {
        "users/me/labels",
        "users/me/profile",
        "users/me/messages",
        "users/me/messages/{message_id}",
        "users/me/history",
    }
    unexpected = gmail_paths - allowed
    if unexpected:
        errors.append(
            "Gmail API path outside read-only allowlist: "
            + ", ".join(sorted(unexpected))
        )
    return errors


def validate_source(root: Path) -> SourceValidation:
    errors: dict[str, list[str]] = {requirement: [] for requirement in REQUIREMENT_IDS}
    contents: dict[str, bytes] = {}
    texts: dict[str, str] = {}
    for relative, requirements in SOURCE_REQUIREMENTS.items():
        data = _read(root / relative)
        if data is None:
            for requirement in requirements:
                errors[requirement].append(
                    f"required production/test artifact unreadable: {relative}"
                )
            continue
        contents[relative] = data
        try:
            texts[relative] = data.decode()
        except UnicodeDecodeError:
            for requirement in requirements:
                errors[requirement].append(
                    f"required artifact is not UTF-8: {relative}"
                )

    def text(relative: str) -> str:
        return texts.get(relative, "")

    core = text("crates/wardrobe-core/src/gmail_connector.rs")
    bindings = text("crates/wardrobe-core/src/bindings.rs")
    service = text("crates/wardrobe-core/src/service.rs")
    contract_tests = text("crates/wardrobe-core/tests/gmail_connector_contracts.rs")
    required_core = (
        '#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]',
        "Search { query: String }",
        "Label { label_name: String }",
        "MAX_GMAIL_QUERY_BYTES: usize = 2048",
        "value.len() > MAX_GMAIL_QUERY_BYTES",
        "value.chars().any(char::is_control)",
        "SaveGmailSettingsV2Request",
        "GetGmailConnectorV2Response",
    )
    if any(marker not in core for marker in required_core):
        errors["P10-GML-001"].append("strict V2 Gmail discovery contract is incomplete")
    for marker in (
        "GmailDiscoveryScopeV2::decl()",
        "SaveGmailSettingsV2Request::decl()",
        "GetGmailConnectorV2Response::decl()",
    ):
        if marker not in bindings:
            errors["P10-GML-001"].append(f"V2 binding export missing: {marker}")
    if (
        "save_gmail_settings_v2" not in service
        or "response.settings.discovery_scope != request.discovery_scope" not in service
    ):
        errors["P10-GML-001"].append(
            "V2 service boundary does not preserve exact scope"
        )
    contract_test_markers = {
        "gmail_v2_discovery_scopes_have_exact_strict_tagged_wire_shapes": (
            "GmailDiscoveryScopeV2",
            "serde_json",
            "search",
            "label",
            "label_name",
        ),
        "gmail_v2_requests_settings_and_responses_reject_unknown_fields": (
            "SaveGmailSettingsV2Request",
            "GetGmailConnectorV2Response",
            "extra",
        ),
        "gmail_search_queries_use_utf8_byte_boundaries_and_reject_controls": (
            "MAX_GMAIL_QUERY_BYTES",
            "GmailQuery",
            "control",
        ),
        "gmail_search_query_whitespace_is_preserved_without_normalization": (
            "query",
            "serde_json",
            "validate",
        ),
        "gmail_v2_schema_versions_are_strict_at_decode_and_validation": (
            "schema_version",
            "SaveGmailSettingsV2Request",
            "SchemaVersion",
        ),
    }
    if any(
        not (body := _function_body(contract_tests, name))
        or any(marker not in body for marker in markers)
        for name, markers in contract_test_markers.items()
    ):
        errors["P10-GML-001"].append(
            "focused strict V2 discovery contract test is absent or incomplete"
        )

    migration = text(MIGRATION_FILE)
    migration_hash = _sha256(contents.get(MIGRATION_FILE, b""))
    if text(MIGRATION_CHECKSUM_FILE).strip() != migration_hash:
        errors["P10-GML-002"].append("Gmail migration 0015 checksum mismatch")
        errors["P10-GML-010"].append("Gmail migration 0015 checksum mismatch")
    for marker in (
        "ALTER TABLE gmail_connector_settings RENAME TO gmail_connector_settings_v1",
        "SELECT\n    singleton, oauth_client_id, 'label', label_name",
        "ALTER TABLE gmail_scopes ADD COLUMN discovery_kind",
        "UPDATE gmail_scopes\nSET discovery_value = label_id",
    ):
        if marker not in migration:
            errors["P10-GML-002"].append(
                f"legacy migration invariant missing: {marker}"
            )
    for forbidden in (
        "DROP TABLE gmail_scopes",
        "DELETE FROM gmail_scopes",
        "UPDATE gmail_connector_state",
        "UPDATE gmail_checkpoints",
        "UPDATE gmail_accounts",
    ):
        if forbidden in migration:
            errors["P10-GML-002"].append(
                f"legacy Gmail durable state is rewritten: {forbidden}"
            )
    database = text("crates/wardrobe-platform/src/database.rs")
    migration_test = _function_body(
        database,
        "migration_0015_preserves_populated_v14_gmail_state_and_reopens",
    )
    if not migration_test or any(
        marker not in migration_test
        for marker in (
            "discovery_kind",
            "history_id",
            "credential_locator",
            "account_key",
            "label_id",
            "connected",
        )
    ):
        errors["P10-GML-002"].append(
            "populated V14-to-V15 Gmail preservation test is absent or incomplete"
        )
    sync = text("crates/wardrobe-platform/src/gmail_sync.rs")
    if not _function_body(
        sync, "expired_history_reconciles_listed_union_known_unlisted_once"
    ):
        errors["P10-GML-002"].append("legacy expired-cursor regression test is missing")
    for marker in (
        "CREATE TABLE gmail_request_reservations",
        "gmail_request_reservations_no_update",
        "gmail_request_reservations_no_delete",
    ):
        if marker not in migration:
            errors["P10-GML-010"].append(
                f"durable Gmail request reservation invariant missing: {marker}"
            )

    connector = text("crates/wardrobe-platform/src/gmail_connector.rs")
    repository = text("crates/wardrobe-platform/src/gmail_repository.rs")
    identity_body = _function_body(connector, "scope_fingerprint")
    identity_markers = (
        'discovery_kind == "label"',
        "storage_scope_key",
        "gmail-search-scope-v2",
        "GOOGLE_OAUTH_SCOPE",
        "PARSER_REVISION",
        "MATERIALIZATION_REVISION",
        "account_key",
        "discovery_value",
    )
    if not identity_body or any(
        marker not in identity_body for marker in identity_markers
    ):
        errors["P10-GML-003"].append(
            "versioned search identity or unchanged legacy identity is incomplete"
        )
    if (
        "initialize_gmail_scope_v2" not in repository
        or "discovery_kind" not in repository
        or "discovery_value" not in repository
    ):
        errors["P10-GML-003"].append("search identity is not durably constrained")
    identity_test = _function_body(
        connector,
        "gmail_scope_identity_is_versioned_and_byte_exact",
    )
    if not identity_test or any(
        marker not in identity_test
        for marker in (
            "scope_fingerprint",
            "account",
            "query",
            "GOOGLE_OAUTH_SCOPE",
        )
    ):
        errors["P10-GML-003"].append(
            "focused tuple-field and query-byte identity test is absent or incomplete"
        )

    focused_rust_tests = {
        "P10-GML-004": (
            (
                sync,
                "search_pagination_and_repeated_revisions_publish_once_to_real_repository",
            ),
            (
                sync,
                "search_exhausts_pages_deduplicates_and_ignores_known_unlisted_sources",
            ),
            (
                text("crates/wardrobe-platform/src/gmail_http.rs"),
                "local_tls_drives_token_userinfo_and_gmail_adapter",
            ),
        ),
        "P10-GML-005": (
            (
                sync,
                "search_limit_and_raw_fetch_failures_preserve_real_repository_atomically",
            ),
            (
                repository,
                "interrupted_publication_is_removed_on_reopen_and_retry_succeeds",
            ),
            (
                sync,
                "search_accepts_exact_byte_and_call_limits_and_rejects_one_over_atomically",
            ),
            (
                sync,
                "search_rejects_token_cycles_timeouts_and_vanished_listed_messages_atomically",
            ),
            (
                repository,
                "failed_publication_never_removes_preexisting_same_hash_blob",
            ),
            (
                repository,
                "first_scope_and_account_roll_back_with_failed_publication",
            ),
            (
                text("crates/wardrobe-platform/src/blob.rs"),
                "operation_rollback_serializes_same_hash_importer_before_removal",
            ),
        ),
        "P10-GML-006": (
            (
                sync,
                "search_pagination_and_repeated_revisions_publish_once_to_real_repository",
            ),
        ),
        "P10-GML-007": (
            (
                sync,
                "search_runs_a_complete_scan_every_time_and_retains_unlisted_known_messages",
            ),
            (
                repository,
                "later_search_scan_retains_sources_absent_from_current_results",
            ),
        ),
        "P10-GML-008": (
            (
                repository,
                "interrupted_publication_is_removed_on_reopen_and_retry_succeeds",
            ),
            (
                connector,
                "startup_reopens_and_discards_interrupted_sync_without_losing_evidence",
            ),
            (
                repository,
                "committed_cleanup_failure_returns_success_and_recovers_manifest",
            ),
        ),
        "P10-GML-009": (
            (sync, "expired_history_reconciles_listed_union_known_unlisted_once"),
            (
                text("crates/wardrobe-platform/src/gmail_http.rs"),
                "discovery_modes_reject_cross_mode_listing_and_history_calls",
            ),
            (repository, "label_removal_does_not_hide_overlapping_search_scope"),
            (
                text("crates/wardrobe-platform/src/deletion_repository.rs"),
                "gmail_scope_availability_rows_are_guarded_and_planned_with_membership",
            ),
        ),
        "P10-GML-010": (
            (
                connector,
                "completed_sync_replay_is_write_free_and_cross_command_reuse_conflicts",
            ),
            (
                connector,
                "terminal_connect_replay_is_provider_keychain_and_write_free",
            ),
            (
                connector,
                "cleaned_up_request_reservation_conflicts_after_restart",
            ),
        ),
    }
    for requirement, tests in focused_rust_tests.items():
        for source, name in tests:
            if not _function_body(source, name):
                errors[requirement].append(
                    f"focused P10A regression test is missing: {name}"
                )
    reservation_body = _function_body(connector, "reserve_request")
    if not reservation_body or any(
        marker not in reservation_body
        for marker in (
            "gmail_request_reservations",
            "command_receipts",
            "RequestReservation::Replayed",
            "RequestReservation::Pending",
            "RequestReservation::New",
        )
    ):
        errors["P10-GML-010"].append(
            "durable request reservation and terminal replay boundary is incomplete"
        )

    http = text("crates/wardrobe-platform/src/gmail_http.rs")
    exact_scope = (
        "pub const GOOGLE_OAUTH_SCOPE: &str = "
        '"openid https://www.googleapis.com/auth/gmail.readonly";'
    )
    if http.count(exact_scope) != 1:
        errors["P10-AUT-001"].append(
            "OAuth authority is not the exact approved scope string"
        )
    if '.append_pair("scope", GOOGLE_OAUTH_SCOPE)' not in http:
        errors["P10-AUT-001"].append(
            "OAuth request does not use the reviewed scope constant"
        )
    errors["P10-AUT-001"].extend(_gmail_api_get_errors(http))
    authority_test = _function_body(connector, "gmail_authority_is_exact_and_read_only")
    if not authority_test or any(
        marker not in authority_test
        for marker in (
            "GOOGLE_OAUTH_SCOPE",
            "gmail.readonly",
            "Method::GET",
            "users/me/messages",
        )
    ):
        errors["P10-AUT-001"].append(
            "focused OAuth and Gmail method/path allowlist test is absent or incomplete"
        )

    ui = text("apps/desktop-ui/src/GmailConnectorSettings.tsx")
    ui_tests = text("apps/desktop-ui/src/GmailConnectorSettings.test.tsx")
    bridge_tests = text("apps/desktop-ui/src/gmail-connector-bridge.test.ts")
    smoke = text("apps/desktop-ui/e2e/gmail-connector.spec.ts")
    for marker in (
        "Gmail search",
        "Existing label",
        "completely reconciles every result",
        "Previously imported messages stay in",
        "Sync bounds",
    ):
        if marker not in ui:
            errors["P10-UI-001"].append(f"Gmail disclosure is missing: {marker}")
    for marker in (
        "saves settings before enabling the explicit connect action",
        "preserves exact search text through keyboard mode changes and save",
        "renders migrated label settings as the distinct label-history mode",
    ):
        if marker not in ui_tests:
            errors["P10-UI-001"].append(f"focused Gmail UI test is missing: {marker}")
    if "sends exact search query bytes without UI normalization" not in bridge_tests:
        errors["P10-UI-001"].append("exact-query bridge regression is missing")
    for marker in (
        "Gmail settings UI persists through reload and retains imported evidence",
        "Fixture-only UI smoke",
        "Enable personal live",
        "page.reload()",
        "Disconnect",
        "AxeBuilder",
    ):
        if marker not in smoke:
            errors["P10-UI-001"].append(
                f"Gmail UI smoke invariant is missing: {marker}"
            )

    desktop = text("src-tauri/src/lib.rs")
    capabilities = text("src-tauri/capabilities/main.json")
    generated_contracts = text("apps/desktop-ui/src/generated/contracts.ts")
    for marker in ("get_gmail_connector_v2", "save_gmail_settings_v2"):
        if desktop.count(marker) < 2:
            errors["P10-UI-001"].append(
                f"typed Gmail V2 desktop boundary is incomplete: {marker}"
            )
    for marker in (
        "handle_get_gmail_connector_v2",
        "handle_save_gmail_settings_v2",
    ):
        if marker not in desktop:
            errors["P10-UI-001"].append(
                f"typed Gmail V2 desktop boundary is incomplete: {marker}"
            )
    for marker in (
        "allow-get-gmail-connector-v2",
        "allow-save-gmail-settings-v2",
    ):
        if marker not in capabilities:
            errors["P10-UI-001"].append(f"Gmail V2 capability is missing: {marker}")
    for relative, command in (
        (
            "src-tauri/permissions/autogenerated/get_gmail_connector_v2.toml",
            'commands.allow = ["get_gmail_connector_v2"]',
        ),
        (
            "src-tauri/permissions/autogenerated/save_gmail_settings_v2.toml",
            'commands.allow = ["save_gmail_settings_v2"]',
        ),
    ):
        if command not in text(relative):
            errors["P10-UI-001"].append(
                f"Gmail V2 generated permission is missing: {relative}"
            )
    for marker in (
        "GetGmailConnectorV2Request",
        "SaveGmailSettingsV2Request",
        "GmailDiscoveryScopeV2",
        "max_total_raw_bytes",
    ):
        if marker not in generated_contracts:
            errors["P10-UI-001"].append(
                f"generated Gmail V2 TypeScript contract is missing: {marker}"
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
        return f"focused check failed: {check.name}"
    output = result.captured_output.decode(errors="replace")
    if (
        "running 0 tests" in output
        or any(test_name not in output for test_name in check.test_names)
        or check.success_marker not in output
    ):
        return f"focused check did not execute every named test: {check.name}"
    return None


def _write_bounded(path: Path, value: dict[str, Any]) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P10 Gmail evaluator artifact exceeds size bound")
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
        "approved_packet_run_id": REQUIREMENT_PACKET_RUN[requirement],
        "validated_packet_run_ids": packet.run_ids,
        "packet_sha256": packet.sha256,
        "source_sha256": source.sha256,
        "migration_sha256": source.migration_sha256,
        "checks": checks,
        "live_gmail_access": False,
        "external_credentials_used": False,
        "packaged_tauri_coverage": False,
    }
    return _sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_outputs(evidence_dir)
    recorded_at = utc_now()
    packet = validate_packets(root, requested)
    source = validate_source(root)
    failures = list(packet.errors)
    for requirement in sorted(requested):
        failures.extend(source.errors[requirement])

    checks: dict[str, dict[str, Any]] = {}
    environment = os.environ.copy()
    environment.pop("HARNESS_RUN_DIR", None)
    environment.pop("HARNESS_EVIDENCE_DIR", None)
    environment.pop("GOOGLE_CLIENT_SECRET", None)
    environment.pop("GOOGLE_REFRESH_TOKEN", None)
    environment.pop("GMAIL_ACCESS_TOKEN", None)
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
        "approved_packet_run_ids": list(packet.run_ids),
        "packet_sha256": packet.sha256,
        "source_sha256": source.sha256,
        "migration_sha256": source.migration_sha256,
        "source_file_count": source.file_count,
        "checks": checks,
        "live_gmail_access": False,
        "external_credentials_used": False,
        "packaged_tauri_coverage": False,
        "playwright_scope": (
            "vite_transport_fixture_only"
            if "P10-UI-001" in requested
            else "not_selected"
        ),
        "verification_scope": "focused_local_contracts_and_tests",
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
            "test": "p10_gmail::focused_local_verification",
            "recorded_at": recorded_at,
            "details": {
                "evaluator": "tools/evaluators/p10_gmail.py",
                "approved_packet_run_id": REQUIREMENT_PACKET_RUN[requirement],
                "checks": list(requirement_checks),
                "verification_sha256": _verification_hash(
                    requirement, packet, source, requirement_checks
                ),
                "public_summary": {
                    "acceptance_claim": "focused_local_requirement_passed",
                    "live_gmail_access": False,
                    "external_credentials_used": False,
                    "packaged_tauri_coverage": False,
                    "playwright_scope": (
                        "vite_transport_fixture_only"
                        if requirement == "P10-UI-001"
                        else "not_applicable"
                    ),
                    "verification_scope": "focused_local_contracts_and_tests",
                    "checks_passed": len(requirement_checks),
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
