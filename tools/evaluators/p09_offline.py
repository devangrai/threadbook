"""Fail-closed evaluator for the approved P09 local-only packet."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import sys
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.evaluators.p03_receipts import (
    CommandResult,
    run_bounded_command,
    write_atomic_json,
)
from tools.harness import source_fingerprint


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
TRIGGER_REQUIREMENT_IDS = frozenset({"P09-OFF-001"})
REQUIREMENT_IDS = SYSTEM_REQUIREMENT_IDS | TRIGGER_REQUIREMENT_IDS
DEFERRED_REQUIREMENT_IDS = TRIGGER_REQUIREMENT_IDS

RUN_ID = "20260716T000410Z-e46bd166"
PACKET_DIR = f"artifacts/harness/P09/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p09-offline-evaluator.json"
SMOKE_REPORT_ENV = "P09_OFFLINE_SMOKE_REPORT"
BUNDLE_RELATIVE = Path("target/release/bundle/macos/Wardrobe.app")

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILES = 512
MAX_SMOKE_REPORT_BYTES = 64 * 1024
MAX_SMOKE_SIDECAR_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_FILES = 4096
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
        "5b540a47896231fdd9ea626b686f47044a3b5cd2311584904fe8b653259a0bea"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "2819fdf18aa7ef43688932d264e849b373525221d12360de98fa3ebed1048b16"
    ),
    f"{PACKET_DIR}/review.md": (
        "aad2d258dcd2aa86b1e81845f1a871bdfa578f4304d6f199c09b9bd679270699"
    ),
}

OUTBOUND_COMMAND_CAPABILITIES = {
    "connect_gmail_v1": "GmailAuthorize",
    "sync_gmail_v1": "GmailSync",
    "approve_and_fetch_receipt_image_v1": "ReceiptImageFetch",
    "begin_photokit_setup_v1": "PhotoKitMaterialize",
    "configure_photokit_scope_v1": "PhotoKitMaterialize",
    "sync_photokit_v1": "PhotoKitMaterialize",
    "preview_outfit_recommendation_v1": "OpenAiRecommendation",
    "request_outfit_recommendation_v1": "OpenAiRecommendation",
    "preview_try_on_v1": "OpenAiTryOn",
    "submit_try_on_v1": "OpenAiTryOn",
}
LOCAL_CLEANUP_COMMANDS = frozenset(
    {
        "delete_credential_v1",
        "disconnect_gmail_v1",
        "disable_photokit_v1",
    }
)
LOCAL_COMMANDS = frozenset(
    {
        "get_foundation_snapshot_v1",
        "set_local_only_v1",
        "run_storage_check_v1",
        "create_backup_v1",
        "list_backups_v1",
        "prepare_restore_v1",
        "save_credential_v1",
        "import_local_sources_v1",
        "refresh_import_roots_v1",
        "list_catalog_v1",
        "list_inbox_v1",
        "create_manual_outfit_v1",
        "list_outfits_v1",
        "get_outfit_collage_v1",
        "list_try_on_portrait_candidates_v1",
        "get_outfit_try_on_v1",
        "save_item_v1",
        "decide_evidence_v1",
        "merge_items_v1",
        "split_item_v1",
        "undo_decision_v1",
        "preview_deletion_v1",
        "list_deletion_plan_items_v1",
        "execute_deletion_v1",
        "list_receipts_v1",
        "analyze_receipt_v1",
        "review_receipt_v1",
        "list_receipt_image_candidates_v1",
        "list_imported_photo_roots_v1",
        "create_photo_scope_v1",
        "analyze_photo_scope_v1",
        "list_photo_observations_v1",
        "read_photo_artifact_v1",
        "prompt_photo_observation_v1",
        "review_photo_observation_v1",
        "open_reconciliation_case_v1",
        "decide_reconciliation_case_v1",
        "get_gmail_connector_v1",
        "save_gmail_settings_v1",
        "get_photokit_connector_v1",
        "export_diagnostics_v1",
    }
)
EXPECTED_COMMANDS = (
    frozenset(OUTBOUND_COMMAND_CAPABILITIES)
    | LOCAL_CLEANUP_COMMANDS
    | LOCAL_COMMANDS
)
EXPECTED_CAPABILITIES = frozenset(
    {
        "GmailAuthorize",
        "GmailSync",
        "GmailRevoke",
        "ReceiptImageFetch",
        "PhotoKitMaterialize",
        "OpenAiRecommendation",
        "OpenAiTryOn",
    }
)

MIGRATION_FILE = (
    "crates/wardrobe-platform/migrations/0013_local_only_disconnect.sql"
)
MIGRATION_CHECKSUM_FILE = (
    "crates/wardrobe-platform/migrations/0013_local_only_disconnect.sha256"
)
REQUIRED_SOURCE_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "crates/wardrobe-core/src/contracts.rs",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/tests/local_only_contracts.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/local_only.rs",
    "crates/wardrobe-platform/src/paths.rs",
    "crates/wardrobe-platform/src/gmail_connector.rs",
    "crates/wardrobe-platform/src/gmail_repository.rs",
    "crates/wardrobe-platform/src/restore_repository.rs",
    "crates/wardrobe-platform/tests/local_only_store.rs",
    MIGRATION_FILE,
    MIGRATION_CHECKSUM_FILE,
    "src-tauri/src/local_only.rs",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "src-tauri/permissions/autogenerated/set_local_only_v1.toml",
    "apps/desktop-ui/src/generated/contracts.ts",
    "apps/desktop-ui/src/foundation-bridge.ts",
    "apps/desktop-ui/src/foundation-bridge.test.ts",
    "apps/desktop-ui/src/LocalOnlySettings.tsx",
    "apps/desktop-ui/src/LocalOnlySettings.test.tsx",
    "apps/desktop-ui/src/App.tsx",
    "apps/desktop-ui/src/App.test.tsx",
    "tools/p09_offline_smoke.py",
    "tests/test_p09_offline_smoke.py",
)
REQUIRED_UI_SCENARIOS = {
    "apps/desktop-ui/src/App.test.tsx": (
        "keeps credential removal reachable while local-only blocks credential setup"
    ),
    "apps/desktop-ui/src/GmailConnectorSettings.test.tsx": (
        "denies outbound actions while keeping local disconnect reachable"
    ),
    "apps/desktop-ui/src/PhotoKitConnectorSettings.test.tsx": (
        "blocks setup and sync while keeping local disable reachable"
    ),
}
SOURCE_SEARCH_ROOTS = (
    "crates/wardrobe-core/src",
    "crates/wardrobe-core/tests",
    "crates/wardrobe-platform/src",
    "crates/wardrobe-platform/tests",
    "crates/wardrobe-platform/migrations",
    "src-tauri/src",
    "src-tauri/permissions",
    "apps/desktop-ui/src",
)
SOURCE_SUFFIXES = frozenset(
    {".rs", ".sql", ".sha256", ".ts", ".tsx", ".json", ".toml"}
)

FORBIDDEN_ACCEPTANCE_MARKERS = (
    "playwright",
    "webdriver",
    "mock_invoke",
    "mockipc",
    "browser mock",
    "page.route",
)
PIXEL_MAGIC = b"WDRBPIX1"
MEMBER_PIXEL_MAGIC = b"WDRBMEM1"
FIXTURE_RGB = ((227, 28, 61), (0, 168, 120))
FIXTURE_DIGESTS = (
    "68d0b42bbcbfe4a86b64c43fb15cbb88df19994604d1fcdd21196c1f8feb716b",
    "f3e25057c2571bb3b159110e800260582df2d6f984be9c67ced8fd1ed685b1dc",
)
FIXTURE_DIGEST_RGB = dict(zip(FIXTURE_DIGESTS, FIXTURE_RGB, strict=True))
FIXTURE_PIXEL_MIN_COUNT = 32
FIXTURE_CHANNEL_TOLERANCE = 24


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
    backend_smoke: bool = False


@dataclass(frozen=True)
class SourceValidation:
    errors: tuple[str, ...]
    source_sha256: str
    source_hashes: dict[str, str]
    source_file_count: int
    registered_command_count: int
    outbound_command_count: int
    local_cleanup_command_count: int
    capability_count: int
    focused_checks: tuple[CommandCheck, ...]


@dataclass(frozen=True)
class SmokeValidation:
    errors: tuple[str, ...]
    report_sha256: str
    bundle_sha256: str
    executable_sha256: str
    sandbox_profile_sha256: str
    collage_sha256: str
    source_digest_count: int
    developer_id_signed: bool
    notarized: bool
    clean_machine_certified: bool


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_bounded(path: Path, limit: int = MAX_SOURCE_BYTES) -> bytes | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def _json_object(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _aggregate_hash(contents: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for relative, data in sorted(contents.items()):
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def validate_packet(root: Path) -> PacketValidation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    hashes: dict[str, str] = {}
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
        errors.append("frozen P09 offline requirement contract is invalid")

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
        errors.append("P09 offline packet is not independently approved")

    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(
        errors="replace"
    )
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append("approved P09 offline review decision is missing")

    return PacketValidation(
        errors=tuple(dict.fromkeys(errors)),
        packet_sha256=_aggregate_hash(contents),
        hashes=hashes,
    )


def _balanced_body(text: str, start: int, opening: str, closing: str) -> str | None:
    depth = 1
    index = start
    quote = ""
    escaped = False
    while index < len(text):
        character = text[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
        elif character in {'"', "'"}:
            quote = character
        elif character == opening:
            depth += 1
        elif character == closing:
            depth -= 1
            if depth == 0:
                return text[start:index]
        index += 1
    return None


def parse_registered_commands(text: str) -> tuple[str, ...]:
    marker = re.search(r"\btauri::generate_handler!\s*\[", text)
    if marker is None:
        return ()
    body = _balanced_body(text, marker.end(), "[", "]")
    if body is None:
        return ()
    return tuple(
        match.group(0)
        for match in re.finditer(r"\b[a-z][a-z0-9_]*_v1\b", body)
    )


def parse_enum_variants(text: str, enum_name: str) -> tuple[str, ...]:
    marker = re.search(
        rf"\benum\s+{re.escape(enum_name)}(?:\s*<[^>]+>)?\s*\{{",
        text,
    )
    if marker is None:
        return ()
    body = _balanced_body(text, marker.end(), "{", "}")
    if body is None:
        return ()
    variants: list[str] = []
    for item in body.split(","):
        match = re.match(r"\s*(?:#\[[^\]]+\]\s*)*([A-Z][A-Za-z0-9_]*)", item)
        if match:
            variants.append(match.group(1))
    return tuple(variants)


def classify_registered_commands(
    commands: tuple[str, ...],
) -> tuple[dict[str, str], tuple[str, ...]]:
    errors: list[str] = []
    if len(commands) != len(set(commands)):
        errors.append("Tauri command registration contains duplicates")
    command_set = set(commands)
    missing = sorted(EXPECTED_COMMANDS - command_set)
    unknown = sorted(command_set - EXPECTED_COMMANDS)
    if missing:
        errors.append("registered command inventory is missing: " + ", ".join(missing))
    if unknown:
        errors.append(
            "registered command has no closed local-only classification: "
            + ", ".join(unknown)
        )
    classification = {
        command: (
            "outbound"
            if command in OUTBOUND_COMMAND_CAPABILITIES
            else "local_cleanup"
            if command in LOCAL_CLEANUP_COMMANDS
            else "local"
        )
        for command in commands
        if command in EXPECTED_COMMANDS
    }
    return classification, tuple(errors)


def _source_paths(root: Path) -> tuple[str, ...]:
    paths = set(REQUIRED_SOURCE_FILES)
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
                package, target_kind = "wardrobe-core", "test"
            elif relative.startswith("crates/wardrobe-core/src/"):
                package, target_kind = "wardrobe-core", "lib"
            elif relative.startswith("crates/wardrobe-platform/tests/"):
                package, target_kind = "wardrobe-platform", "test"
            elif relative.startswith("crates/wardrobe-platform/src/"):
                package, target_kind = "wardrobe-platform", "lib"
            elif relative.startswith("src-tauri/"):
                package, target_kind = "wardrobe-desktop", "lib"
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
    backend_smoke: bool = False,
) -> CommandCheck:
    target = ("--test", test.target_name) if test.target_kind == "test" else ("--lib",)
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
            "--test-threads=1",
        ),
        require_rust_test=True,
        backend_smoke=backend_smoke,
    )


REQUIRED_FOCUSED_RUST_TESTS = (
    (
        "closed_command_classification",
        "wardrobe-desktop",
        "every_registered_command_has_one_closed_network_classification",
        False,
    ),
    (
        "closed_capability_denial",
        "wardrobe-desktop",
        "local_only_denies_every_closed_capability",
        False,
    ),
    (
        "revocation_drain",
        "wardrobe-desktop",
        "transition_drains_revocation_and_blocks_new_work",
        False,
    ),
    (
        "durable_mode_transition",
        "wardrobe-desktop",
        "default_authority_is_fail_closed_and_mode_transitions_are_durable",
        False,
    ),
    (
        "uncertain_authority_revision",
        "wardrobe-desktop",
        "uncertain_publication_is_fail_closed_at_the_repairable_prior_revision",
        False,
    ),
    (
        "uncertain_old_generation_repair",
        "wardrobe-platform",
        "ambiguous_first_rename_with_old_durable_state_is_repairable_at_prior_revision",
        False,
    ),
    (
        "uncertain_partial_generation_repair",
        "wardrobe-platform",
        "ambiguous_partial_new_generations_are_fail_closed_and_same_process_repairable",
        False,
    ),
    (
        "uncertain_new_generation_proof",
        "wardrobe-platform",
        "ambiguous_acknowledgment_sync_with_complete_new_state_is_exactly_provable",
        False,
    ),
    (
        "startup_scheduler_denial",
        "wardrobe-desktop",
        "local_only_startup_and_scheduler_do_not_claim_outbound_work",
        False,
    ),
    (
        "gmail_no_secret_or_transport",
        "wardrobe-platform",
        "local_only_disconnect_records_exact_outcome_without_secret_read_or_http",
        False,
    ),
    (
        "gmail_local_recovery",
        "wardrobe-platform",
        "local_recovery_finishes_interrupted_disconnect_without_secret_read_or_http",
        False,
    ),
    (
        "gmail_outcome_cas",
        "wardrobe-platform",
        "revocation_outcome_compare_and_set_rejects_semantic_change",
        False,
    ),
    (
        "migration_v12_to_v13",
        "wardrobe-platform",
        "migration_0013_preserves_v12_disconnect_rows_and_extends_one_outcome_domain",
        False,
    ),
    (
        "migration_v13_rollback",
        "wardrobe-platform",
        "interrupted_migration_0013_rolls_back_to_complete_v12",
        False,
    ),
    (
        "restore_disconnect_detachment",
        "wardrobe-platform",
        "restore_normalization_detaches_pending_gmail_disconnect_recovery",
        False,
    ),
    (
        "restore_startup_keychain_inert",
        "wardrobe-platform",
        "restored_disconnect_is_inert_through_local_startup_recovery",
        False,
    ),
    (
        "personal_live_authorized_wrappers",
        "wardrobe-desktop",
        "personal_live_authorized_wrappers_dispatch_to_inner_adapters_without_network",
        False,
    ),
    (
        "personal_live_receipt_regression",
        "wardrobe-desktop",
        "receipt_image_commands_preserve_explicit_network_authority_and_diagnostic_secrecy",
        False,
    ),
    (
        "personal_live_receipt_transport",
        "wardrobe-platform",
        "real_reqwest_rustls_download_uses_the_pinned_fixture_socket",
        False,
    ),
    (
        "backend_local_workflow_restart_smoke",
        "wardrobe-desktop",
        "local_only_import_review_outfit_collage_restart_smoke",
        True,
    ),
)


def _focused_checks(
    tests: tuple[RustTest, ...],
    ui_test_files: tuple[str, ...],
) -> tuple[tuple[CommandCheck, ...], list[str]]:
    errors: list[str] = []
    checks: list[CommandCheck] = []

    core = [
        test
        for test in tests
        if test.package == "wardrobe-core"
        and test.target_name == "local_only_contracts"
        and "local_only" in f"{test.name}\n{test.body}".lower()
    ]
    store = [
        test
        for test in tests
        if test.package == "wardrobe-platform"
        and test.target_name == "local_only_store"
        and "local_only" in f"{test.name}\n{test.body}".lower()
    ]
    if not core:
        errors.append("focused core local-only contract tests are missing")
    else:
        target = core[0].target_name
        checks.append(
            CommandCheck(
                "core_local_only_contract_suite",
                (
                    "cargo",
                    "test",
                    "--offline",
                    "-p",
                    "wardrobe-core",
                    "--test",
                    target,
                    "--",
                    "--test-threads=1",
                ),
            )
        )
    if not store:
        errors.append("focused platform local-only store tests are missing")
    else:
        target = store[0].target_name
        checks.append(
            CommandCheck(
                "platform_local_only_store_suite",
                (
                    "cargo",
                    "test",
                    "--offline",
                    "-p",
                    "wardrobe-platform",
                    "--test",
                    target,
                    "--",
                    "--test-threads=1",
                ),
            )
        )

    for label, package, test_name, backend_smoke in REQUIRED_FOCUSED_RUST_TESTS:
        candidates = [
            test
            for test in tests
            if test.package == package and test.name == test_name
        ]
        if len(candidates) != 1:
            errors.append(
                f"required focused Rust test is missing or ambiguous: {test_name}"
            )
            continue
        test = candidates[0]
        if any(
            marker in f"{test.name}\n{test.body}".lower()
            for marker in FORBIDDEN_ACCEPTANCE_MARKERS
        ):
            errors.append(f"focused Rust test uses a forbidden acceptance path: {test_name}")
            continue
        checks.append(
            _rust_test_check(
                test,
                name=label,
                backend_smoke=backend_smoke,
            )
        )

    if not ui_test_files:
        errors.append("focused UI local-only gating tests are missing")
    else:
        checks.append(
            CommandCheck(
                "ui_local_only_gating",
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
                "ui_generated_contract_production_build",
                ("npm", "--workspace", "@wardrobe/desktop-ui", "run", "build"),
            )
        )

    for test_name in (
        "catalog_commands_run_the_real_import_review_and_deletion_path",
        "outfit_commands_use_real_local_state_and_preserve_collage_across_restart",
    ):
        checks.append(
            CommandCheck(
                f"phase_boundary_{test_name}",
                (
                    "cargo",
                    "test",
                    "--offline",
                    "-p",
                    "wardrobe-desktop",
                    "--lib",
                    test_name,
                    "--",
                    "--test-threads=1",
                ),
                require_rust_test=True,
            )
        )
    return tuple(checks), errors


def validate_source(root: Path) -> SourceValidation:
    errors: list[str] = []
    decoded: dict[str, str] = {}
    hashes: dict[str, str] = {}
    contents: dict[str, bytes] = {}
    total_bytes = 0
    source_paths = _source_paths(root)
    if len(source_paths) > MAX_SOURCE_FILES:
        errors.append("P09 offline source inventory exceeds file bound")
        source_paths = source_paths[:MAX_SOURCE_FILES]
    for relative in source_paths:
        data = _read_bounded(root / relative)
        if data is None:
            if relative in REQUIRED_SOURCE_FILES:
                errors.append(
                    f"required P09 offline source is unreadable or oversized: {relative}"
                )
            continue
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_SOURCE_BYTES:
            errors.append("P09 offline source inventory exceeds byte bound")
            break
        contents[relative] = data
        hashes[relative] = _sha256(data)
        try:
            decoded[relative] = data.decode()
        except UnicodeDecodeError:
            errors.append(f"required P09 offline source is not UTF-8: {relative}")

    tauri = decoded.get("src-tauri/src/lib.rs", "")
    commands = parse_registered_commands(tauri)
    classification, classification_errors = classify_registered_commands(commands)
    errors.extend(classification_errors)

    authority = decoded.get("src-tauri/src/local_only.rs", "")
    capabilities = parse_enum_variants(authority, "OutboundCapability")
    if len(capabilities) != len(set(capabilities)):
        errors.append("outbound capability enum contains duplicates")
    if set(capabilities) != EXPECTED_CAPABILITIES:
        errors.append("outbound capability enum is not closed and exhaustive")

    required_runtime_markers = (
        "OutboundAuthority",
        "OutboundLease",
        "begin_transition",
        "PublicationOutcomeUnknown",
        "set_local_only_v1",
        "provider_unavailable",
        "not_attempted_local_only",
        "recover_local_state",
        "recover_with_revocation",
    )
    runtime_text = "\n".join(
        text
        for relative, text in decoded.items()
        if relative.startswith(("src-tauri/", "crates/wardrobe-platform/"))
    )
    for marker in required_runtime_markers:
        if marker not in runtime_text:
            errors.append(f"required local-only runtime boundary is missing: {marker}")

    adapter_markers = {
        "gmail": (
            "AuthorizedGmailConnector",
            "acquire(OutboundCapability::GmailAuthorize)",
            "acquire(OutboundCapability::GmailSync)",
            "acquire(OutboundCapability::GmailRevoke)",
        ),
        "receipt_image": (
            "AuthorizedReceiptImageDownloader",
            "acquire(OutboundCapability::ReceiptImageFetch)",
        ),
        "photokit": (
            "AuthorizedPhotoKitConnector",
            "acquire(OutboundCapability::PhotoKitMaterialize)",
        ),
        "recommendation": (
            "AuthorizedOutfitRecommender",
            "acquire(OutboundCapability::OpenAiRecommendation)",
        ),
        "try_on": (
            "AuthorizedTryOnRenderer",
            "acquire(OutboundCapability::OpenAiTryOn)",
        ),
    }
    normalized_tauri = re.sub(r"\s+", "", tauri)
    for label, markers in adapter_markers.items():
        if any(
            re.sub(r"\s+", "", marker) not in normalized_tauri
            for marker in markers
        ):
            errors.append(f"{label} transport boundary does not require an outbound lease")

    migration = decoded.get(MIGRATION_FILE, "")
    checksum = decoded.get(MIGRATION_CHECKSUM_FILE, "").strip()
    if (
        not re.fullmatch(r"[0-9a-f]{64}", checksum)
        or checksum != hashes.get(MIGRATION_FILE)
    ):
        errors.append("P09 local-only migration checksum is invalid")
    for marker in (
        "gmail_disconnect_stages",
        "not_attempted_local_only",
        "CHECK",
    ):
        if marker not in migration:
            errors.append(f"P09 local-only migration boundary is missing: {marker}")

    generated = decoded.get("apps/desktop-ui/src/generated/contracts.ts", "")
    for marker in (
        "LocalOnlyAuthorityHealthV1",
        "SetLocalOnlyV1Request",
        "SetLocalOnlyV1Response",
        "revision:",
        "authority_health:",
    ):
        if marker not in generated:
            errors.append(f"generated local-only contract is missing: {marker}")

    capability = decoded.get("src-tauri/capabilities/main.json", "")
    permission = decoded.get(
        "src-tauri/permissions/autogenerated/set_local_only_v1.toml", ""
    )
    build = decoded.get("src-tauri/build.rs", "")
    if "allow-set-local-only-v1" not in capability:
        errors.append("main capability does not allow set_local_only_v1")
    if "set_local_only_v1" not in permission or "set_local_only_v1" not in build:
        errors.append("generated set_local_only_v1 registration is incomplete")

    ui_text = "\n".join(
        text
        for relative, text in decoded.items()
        if relative.startswith("apps/desktop-ui/src/")
    )
    for marker in (
        "LocalOnlySettings",
        "setLocalOnly",
        "Enable personal live",
        "authorityHealth",
        "deleteCredential",
        "disconnect",
        "PhotoKitConnectorSettings",
    ):
        if marker not in ui_text:
            errors.append(f"local-only UI gating boundary is missing: {marker}")
    for relative, scenario in REQUIRED_UI_SCENARIOS.items():
        if scenario not in decoded.get(relative, ""):
            errors.append(
                f"required local-only cleanup UI scenario is missing: {relative}"
            )

    tests = _rust_tests(decoded)
    ui_test_files = tuple(
        sorted(
            relative.removeprefix("apps/desktop-ui/")
            for relative, text in decoded.items()
            if relative.endswith((".test.ts", ".test.tsx"))
            and (
                "localonly" in text.lower().replace("_", "")
                or "local-only" in text.lower()
                or "local only" in text.lower()
            )
        )
    )
    focused_checks, focus_errors = _focused_checks(tests, ui_test_files)
    errors.extend(focus_errors)

    return SourceValidation(
        errors=tuple(dict.fromkeys(errors)),
        source_sha256=_aggregate_hash(contents),
        source_hashes=hashes,
        source_file_count=len(contents),
        registered_command_count=len(commands),
        outbound_command_count=sum(
            value == "outbound" for value in classification.values()
        ),
        local_cleanup_command_count=sum(
            value == "local_cleanup" for value in classification.values()
        ),
        capability_count=len(capabilities),
        focused_checks=focused_checks,
    )


SMOKE_BOOLEAN_FIELDS = (
    "production_bundle",
    "sandbox_denied_network_for_process_and_children",
    "accessibility_automation_used",
    "native_file_chooser_used",
    "manual_import_passed",
    "inbox_review_passed",
    "catalog_confirm_edit_reload_passed",
    "manual_outfit_passed",
    "collage_before_restart_passed",
    "collage_after_restart_passed",
    "remote_controls_blocked",
    "local_deletion_control_reachable",
    "database_blob_residual_scan_passed",
)
SMOKE_HASH_FIELDS = (
    "bundle_sha256",
    "executable_sha256",
    "sandbox_profile_sha256",
    "accessibility_transcript_sha256",
    "residual_scan_sha256",
    "sandbox_log_sha256",
    "collage_before_sha256",
    "collage_after_sha256",
)
SMOKE_SIDECARS = {
    "sandbox_profile_sha256": ("deny-network.sb", 4096),
    "accessibility_transcript_sha256": (
        "accessibility.txt",
        1024 * 1024,
    ),
    "residual_scan_sha256": ("residual-scan.json", 64 * 1024),
    "sandbox_log_sha256": ("sandbox.log", 1024 * 1024),
    "collage_before_sha256": (
        "collage-before.pixels",
        MAX_SMOKE_SIDECAR_BYTES,
    ),
    "collage_after_sha256": (
        "collage-after.pixels",
        MAX_SMOKE_SIDECAR_BYTES,
    ),
}


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_app_bundle(bundle: Path) -> tuple[str, int, tuple[str, ...]]:
    errors: list[str] = []
    digest = hashlib.sha256()
    try:
        metadata = bundle.lstat()
    except OSError:
        metadata = None
    if metadata is None or not stat.S_ISDIR(metadata.st_mode):
        return "", 0, ("production macOS application bundle is missing",)

    try:
        paths = sorted(bundle.rglob("*"))
    except OSError:
        return "", 0, ("production macOS application bundle is unreadable",)
    if len(paths) > MAX_BUNDLE_FILES:
        return "", 0, ("production macOS application bundle inventory is unbounded",)

    file_count = 0
    for path in paths:
        relative = path.relative_to(bundle).as_posix()
        try:
            metadata = path.lstat()
        except OSError:
            errors.append(f"application bundle entry is unreadable: {relative}")
            continue
        digest.update(relative.encode())
        digest.update(b"\0")
        if stat.S_ISREG(metadata.st_mode):
            file_count += 1
            try:
                digest.update(bytes.fromhex(_hash_file(path)))
            except OSError:
                errors.append(f"application bundle file is unreadable: {relative}")
        elif stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(path)
            except OSError:
                errors.append(f"application bundle link is unreadable: {relative}")
                continue
            digest.update(b"symlink\0")
            digest.update(target.encode())
        elif not stat.S_ISDIR(metadata.st_mode):
            errors.append(f"application bundle entry has an unsafe type: {relative}")
        digest.update(b"\0")
    if file_count == 0:
        errors.append("production macOS application bundle has no files")
    return digest.hexdigest(), file_count, tuple(errors)


def _bundle_executable(bundle: Path) -> tuple[Path | None, str | None]:
    plist_path = bundle / "Contents/Info.plist"
    try:
        with plist_path.open("rb") as handle:
            metadata = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException):
        return None, "production application Info.plist is invalid"
    name = metadata.get("CFBundleExecutable")
    if not isinstance(name, str) or not name:
        return None, "production application executable identity is missing"
    executable = bundle / "Contents/MacOS" / name
    try:
        executable_metadata = executable.lstat()
    except OSError:
        executable_metadata = None
    if executable_metadata is None or not stat.S_ISREG(executable_metadata.st_mode):
        return None, "production application executable is missing or unsafe"
    return executable, None


def _read_regular_sidecar(path: Path, limit: int) -> bytes | None:
    try:
        metadata = path.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > limit
    ):
        return None
    return _read_bounded(path, limit)


def _canonical_member_pixel_error(
    data: bytes,
    label: str,
    expected_rgb: tuple[int, int, int],
) -> str | None:
    header_length = len(PIXEL_MAGIC) + 9
    if not data.startswith(PIXEL_MAGIC) or len(data) < header_length:
        return f"{label} member pixels are invalid"
    width, height, channels = struct.unpack(
        ">IIB", data[len(PIXEL_MAGIC) : header_length]
    )
    if (
        not 32 <= width <= 8192
        or not 32 <= height <= 8192
        or channels not in {1, 2, 3, 4}
        or len(data) != header_length + width * height * channels
    ):
        return f"{label} member pixel dimensions are invalid"
    pixels = data[header_length:]
    unique: set[bytes] = set()
    for offset in range(0, len(pixels), channels):
        unique.add(pixels[offset : offset + channels])
        if len(unique) >= 16:
            break
    if len(unique) < 2:
        return f"{label} member pixels are blank or degenerate"
    if channels < 3:
        return f"{label} member pixels cannot prove fixture rendering"
    count = sum(
        all(
            abs(pixels[offset + channel] - expected_rgb[channel])
            <= FIXTURE_CHANNEL_TOLERANCE
            for channel in range(3)
        )
        for offset in range(0, len(pixels), channels)
    )
    minimum_count = max(FIXTURE_PIXEL_MIN_COUNT, width * height // 2)
    maximum_count = width * height * 9 // 10
    if count < minimum_count or count > maximum_count:
        return f"{label} member pixels do not match the pinned source digest"
    return None


def _member_pixel_sidecar(
    data: bytes,
    label: str,
) -> tuple[str | None, tuple[tuple[int, str], ...]]:
    offset = len(MEMBER_PIXEL_MAGIC)
    if (
        not data.startswith(MEMBER_PIXEL_MAGIC)
        or len(data) < offset + 1
        or data[offset] != 2
    ):
        return f"{label} member pixel sidecar is invalid", ()
    offset += 1
    records: list[tuple[int, str]] = []
    for _index in range(2):
        header_size = struct.calcsize(">B32sI")
        if len(data) < offset + header_size:
            return f"{label} member pixel record is truncated", ()
        ordinal, digest_bytes, length = struct.unpack(
            ">B32sI", data[offset : offset + header_size]
        )
        offset += header_size
        if length > MAX_SMOKE_SIDECAR_BYTES or len(data) < offset + length:
            return f"{label} member pixel record length is invalid", ()
        digest = digest_bytes.hex()
        expected_rgb = FIXTURE_DIGEST_RGB.get(digest)
        if expected_rgb is None:
            return f"{label} member pixel digest is not a reviewed fixture", ()
        error = _canonical_member_pixel_error(
            data[offset : offset + length],
            f"{label} ordinal {ordinal}",
            expected_rgb,
        )
        if error:
            return error, ()
        records.append((ordinal, digest))
        offset += length
    if (
        offset != len(data)
        or [record[0] for record in records] != [0, 1]
        or {record[1] for record in records} != set(FIXTURE_DIGESTS)
    ):
        return f"{label} member pixel records are not closed and ordered", ()
    return None, tuple(records)


def _validate_smoke_sidecars(
    report_path: Path,
    report: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    sidecar_dir = report_path.parent / "offline-smoke"
    expected_names = {name for name, _limit in SMOKE_SIDECARS.values()}
    try:
        actual_entries = tuple(sidecar_dir.iterdir())
    except OSError:
        actual_entries = ()
    actual_names = {
        entry.name
        for entry in actual_entries
        if entry.is_file() and not entry.is_symlink()
    }
    if (
        actual_names != expected_names
        or len(actual_entries) != len(expected_names)
    ):
        errors.append("packaged-app smoke sidecar inventory is not exact")
    contents: dict[str, bytes] = {}
    for field, (name, limit) in SMOKE_SIDECARS.items():
        data = _read_regular_sidecar(sidecar_dir / name, limit)
        if data is None:
            errors.append(f"packaged-app smoke sidecar is missing or unsafe: {name}")
            continue
        contents[field] = data
        if _sha256(data) != report.get(field):
            errors.append(f"packaged-app smoke sidecar hash changed: {name}")

    profile = contents.get("sandbox_profile_sha256")
    if profile is not None and profile != (
        b"(version 1)\n(allow default)\n(deny network*)\n"
    ):
        errors.append("packaged-app smoke sandbox profile is not exact")

    transcript = contents.get("accessibility_transcript_sha256")
    if transcript is not None:
        try:
            transcript_text = transcript.decode()
        except UnicodeDecodeError:
            errors.append("packaged-app accessibility transcript is not UTF-8")
        else:
            for marker in (
                "FIRST_COLLAGE",
                "SECOND_COLLAGE",
                "SETTINGS",
                "Saved wardrobe collage",
                "Local only",
                "Network mode",
                "Preview deletion",
                "Not configured",
                "Disconnect remains available",
                "Existing credentials can still be removed",
            ):
                if marker not in transcript_text:
                    errors.append(
                        "packaged-app accessibility transcript is missing: "
                        + marker
                    )

    residual_member_records: tuple[tuple[int, str], ...] | None = None
    residual_data = contents.get("residual_scan_sha256")
    if residual_data is not None:
        residual = _json_object(residual_data)
        expected_fields = {
            "schema_version",
            "integrity_check",
            "foreign_key_violation_count",
            "database_schema_version",
            "source_digests",
            "verified_blob_digests",
            "active_item_count",
            "assigned_evidence_count",
            "outfit_count",
            "outfit_member_digests",
            "outbound_attempt_record_count",
            "log_tree_sha256",
            "collage_contract_sha256",
        }
        source_digests = residual.get("source_digests")
        verified_digests = residual.get("verified_blob_digests")
        source_digests_valid = (
            isinstance(source_digests, list)
            and len(source_digests) == 2
            and all(
                isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                for value in source_digests
            )
            and len(set(source_digests)) == 2
        )
        verified_digests_valid = isinstance(verified_digests, list) and all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in verified_digests
        )
        member_digests = residual.get("outfit_member_digests")
        member_digests_valid = (
            isinstance(member_digests, list)
            and len(member_digests) == 2
            and all(
                isinstance(row, dict)
                and set(row) == {"ordinal", "blob_sha256"}
                and isinstance(row["ordinal"], int)
                and not isinstance(row["ordinal"], bool)
                and row["ordinal"] == index
                and isinstance(row["blob_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["blob_sha256"]) is not None
                for index, row in enumerate(member_digests)
            )
        )
        if member_digests_valid:
            residual_member_records = tuple(
                (row["ordinal"], row["blob_sha256"])
                for row in member_digests
            )
            member_digests_valid = (
                {row[1] for row in residual_member_records}
                == set(FIXTURE_DIGESTS)
            )
        if (
            set(residual) != expected_fields
            or residual.get("schema_version") != 1
            or residual.get("integrity_check") != "ok"
            or residual.get("foreign_key_violation_count") != 0
            or residual.get("database_schema_version") != 13
            or residual.get("active_item_count") != 2
            or residual.get("assigned_evidence_count") != 2
            or residual.get("outfit_count") != 1
            or residual.get("outbound_attempt_record_count") != 0
            or not source_digests_valid
            or not verified_digests_valid
            or not member_digests_valid
            or not set(source_digests).issubset(set(verified_digests))
            or set(source_digests) != set(FIXTURE_DIGESTS)
            or not isinstance(residual.get("log_tree_sha256"), str)
            or not re.fullmatch(
                r"[0-9a-f]{64}", residual.get("log_tree_sha256", "")
            )
            or not isinstance(residual.get("collage_contract_sha256"), str)
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                residual.get("collage_contract_sha256", ""),
            )
        ):
            errors.append("packaged-app residual scan contract is invalid")

    sandbox_log = contents.get("sandbox_log_sha256")
    if sandbox_log is not None:
        log_text = sandbox_log.decode(errors="replace")
        control = re.search(r"network-child-control returncode=(\d+)", log_text)
        denied = re.search(r"network-child-denied returncode=(\d+)", log_text)
        if (
            control is None
            or control.group(1) != "0"
            or denied is None
            or denied.group(1) == "0"
        ):
            errors.append("packaged-app sandbox process-tree proof is invalid")

    before = contents.get("collage_before_sha256")
    after = contents.get("collage_after_sha256")
    before_records: tuple[tuple[int, str], ...] = ()
    after_records: tuple[tuple[int, str], ...] = ()
    if before is not None:
        error, before_records = _member_pixel_sidecar(before, "before-restart")
        if error:
            errors.append(error)
    if after is not None:
        error, after_records = _member_pixel_sidecar(after, "after-restart")
        if error:
            errors.append(error)
    if residual_member_records is not None and (
        before_records != residual_member_records
        or after_records != residual_member_records
    ):
        errors.append(
            "packaged-app rendered member pixels do not match residual digest order"
        )
    if before is not None and after is not None and before != after:
        errors.append("packaged-app rendered collage pixels changed after restart")
    return errors


def validate_smoke_report(
    path: Path | None,
    *,
    root: Path | None = None,
) -> SmokeValidation:
    if path is None:
        return SmokeValidation(
            (f"{SMOKE_REPORT_ENV} must name the packaged-app smoke report",),
            "",
            "",
            "",
            "",
            "",
            0,
            False,
            False,
            False,
        )
    try:
        metadata = path.lstat()
    except OSError:
        metadata = None
    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        return SmokeValidation(
            ("packaged-app smoke report must be a regular non-symlink file",),
            "",
            "",
            "",
            "",
            "",
            0,
            False,
            False,
            False,
        )
    data = _read_bounded(path, MAX_SMOKE_REPORT_BYTES)
    if data is None:
        return SmokeValidation(
            ("packaged-app smoke report is unreadable or oversized",),
            "",
            "",
            "",
            "",
            "",
            0,
            False,
            False,
            False,
        )
    report = _json_object(data)
    errors: list[str] = []
    required_fields = {
        "schema_version",
        "status",
        "artifact_kind",
        "packaging_identity",
        "process_exit_status",
        "restart_count",
        "source_digest_count",
        "outbound_attempt_record_count",
        "developer_id_signed",
        "notarized",
        "clean_machine_certified",
        "signed_acceptance_claim",
        "connector_cleanup_controls_applicable",
        "source_fingerprint",
        *SMOKE_BOOLEAN_FIELDS,
        *SMOKE_HASH_FIELDS,
    }
    if set(report) != required_fields:
        errors.append("packaged-app smoke report fields are not strict and complete")
    if (
        report.get("schema_version") != 1
        or report.get("status") != "pass"
        or report.get("artifact_kind") != "macos_app"
        or report.get("packaging_identity") != "ad_hoc_development_host"
    ):
        errors.append("packaged-app smoke report identity is invalid")
    for field in SMOKE_BOOLEAN_FIELDS:
        if report.get(field) is not True:
            errors.append(f"packaged-app smoke did not establish {field}")
    if report.get("connector_cleanup_controls_applicable") is not False:
        errors.append(
            "fresh-profile packaged smoke must not claim connector cleanup controls"
        )
    if not isinstance(report.get("source_fingerprint"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", report.get("source_fingerprint", "")
    ):
        errors.append("packaged-app smoke source fingerprint is invalid")
    for field in SMOKE_HASH_FIELDS:
        if not isinstance(report.get(field), str) or not re.fullmatch(
            r"[0-9a-f]{64}", report[field]
        ):
            errors.append(f"packaged-app smoke hash is invalid: {field}")
    for field, minimum in (
        ("process_exit_status", 0),
        ("restart_count", 1),
        ("source_digest_count", 2),
        ("outbound_attempt_record_count", 0),
    ):
        value = report.get(field)
        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(f"packaged-app smoke count is invalid: {field}")
        elif field in {"process_exit_status", "outbound_attempt_record_count"}:
            if value != minimum:
                errors.append(f"packaged-app smoke requires {field}={minimum}")
        elif value < minimum:
            errors.append(f"packaged-app smoke requires {field}>={minimum}")
    if report.get("collage_before_sha256") != report.get("collage_after_sha256"):
        errors.append("packaged-app smoke collage hashes are not deterministic")
    for field in (
        "developer_id_signed",
        "notarized",
        "clean_machine_certified",
    ):
        if report.get(field) is not False:
            errors.append(f"ad-hoc smoke may not claim {field}")
    if report.get("signed_acceptance_claim") != "deferred_not_passed":
        errors.append("ad-hoc smoke may not claim signed release acceptance")
    rendered = data.decode(errors="replace").lower()
    if any(marker in rendered for marker in FORBIDDEN_ACCEPTANCE_MARKERS):
        errors.append("packaged-app acceptance report references a browser/mock path")
    errors.extend(_validate_smoke_sidecars(path, report))
    if root is not None:
        try:
            current_source_fingerprint = source_fingerprint()
        except RuntimeError:
            errors.append("packaged-app smoke source fingerprint cannot be verified")
        else:
            if report.get("source_fingerprint") != current_source_fingerprint:
                errors.append(
                    "packaged-app smoke was not run against the current source"
                )
        bundle = root / BUNDLE_RELATIVE
        bundle_sha256, _, bundle_errors = hash_app_bundle(bundle)
        errors.extend(bundle_errors)
        if bundle_sha256 != report.get("bundle_sha256"):
            errors.append("packaged-app smoke bundle hash does not match production")
        executable, executable_error = _bundle_executable(bundle)
        if executable_error:
            errors.append(executable_error)
        else:
            try:
                executable_sha256 = _hash_file(executable)
            except OSError:
                errors.append("production application executable is unreadable")
            else:
                if executable_sha256 != report.get("executable_sha256"):
                    errors.append(
                        "packaged-app smoke executable hash does not match production"
                    )

    return SmokeValidation(
        errors=tuple(dict.fromkeys(errors)),
        report_sha256=_sha256(data),
        bundle_sha256=report.get("bundle_sha256", ""),
        executable_sha256=report.get("executable_sha256", ""),
        sandbox_profile_sha256=report.get("sandbox_profile_sha256", ""),
        collage_sha256=report.get("collage_before_sha256", ""),
        source_digest_count=(
            report.get("source_digest_count")
            if isinstance(report.get("source_digest_count"), int)
            and not isinstance(report.get("source_digest_count"), bool)
            else 0
        ),
        developer_id_signed=report.get("developer_id_signed") is True,
        notarized=report.get("notarized") is True,
        clean_machine_certified=report.get("clean_machine_certified") is True,
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
    if result.returncode != 0:
        return f"{check.name} failed"
    if result.timed_out or result.output_limit_exceeded or result.launch_failed:
        return f"{check.name} did not complete within evaluator bounds"
    if check.require_rust_test:
        output = result.captured_output.decode(errors="replace")
        if check.command[-3] not in output or "test result: ok" not in output:
            return f"{check.name} did not execute the required Rust test"
    return None


def _validate_public_summary(value: Any) -> dict[str, str | bool | int | float]:
    if not isinstance(value, dict) or len(value) > MAX_PUBLIC_SUMMARY_FIELDS:
        raise ValueError("public_summary is not a bounded object")
    validated: dict[str, str | bool | int | float] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key):
            raise ValueError("public_summary has an invalid key")
        if isinstance(item, str):
            if (
                not item
                or "\n" in item
                or len(item.encode()) > MAX_PUBLIC_STRING_BYTES
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


def _bounded_json_bytes(value: dict[str, Any]) -> bytes:
    data = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P09 offline evaluator artifact exceeds size limit")
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
    smoke: SmokeValidation,
    checks: dict[str, dict[str, Any]],
) -> str:
    return _sha256(
        _bounded_json_bytes(
            {
                "requirement_id": requirement,
                "packet_sha256": packet.packet_sha256,
                "source_sha256": source.source_sha256,
                "smoke_report_sha256": smoke.report_sha256,
                "checks": checks,
            }
        )
    )


def _public_summary(
    requirement: str,
    packet: PacketValidation,
    source: SourceValidation,
    smoke: SmokeValidation,
    check_count: int,
) -> dict[str, str | bool | int | float]:
    common: dict[str, str | bool | int | float] = {
        "profile": "personal_mvp",
        "packet_sha256": packet.packet_sha256,
        "source_sha256": source.source_sha256,
        "smoke_report_sha256": smoke.report_sha256,
        "checks_passed": check_count,
        "registered_command_count": source.registered_command_count,
        "outbound_command_count": source.outbound_command_count,
        "local_cleanup_command_count": source.local_cleanup_command_count,
        "capability_count": source.capability_count,
        "functional_ad_hoc_package_passed": True,
        "network_denied_for_process_tree": True,
        "outbound_attempt_record_count": 0,
        "source_digest_count": smoke.source_digest_count,
        "deterministic_collage": True,
        "browser_mock_used_for_acceptance": False,
        "developer_id_signed": smoke.developer_id_signed,
        "notarized": smoke.notarized,
        "clean_machine_certified": smoke.clean_machine_certified,
    }
    if requirement in DEFERRED_REQUIREMENT_IDS:
        return _validate_public_summary(
            {
                **common,
                "feature_enabled": False,
                "acceptance_claim": "deferred_not_passed",
                "deferred_limitation": (
                    "Developer ID signing, notarization, and clean-machine "
                    "release acceptance were not established."
                ),
            }
        )
    return _validate_public_summary(
        {
            **common,
            "feature_enabled": True,
            "acceptance_claim": (
                "functional_ad_hoc_package_passed"
                if requirement == "SYS-REL-002"
                else "focused_local_requirement_passed"
            ),
        }
    )


def evaluate(
    root: Path,
    evidence_dir: Path,
    selected: set[str],
    *,
    smoke_report_path: Path | None = None,
) -> int:
    if not (selected & TRIGGER_REQUIREMENT_IDS):
        return 0
    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(evidence_dir)
    recorded_at = utc_now()
    packet = validate_packet(root)
    source: SourceValidation | None = None
    smoke: SmokeValidation | None = None
    failures = list(packet.errors)
    checks: dict[str, dict[str, Any]] = {}
    backend_smoke_count = 0

    if selected & TRIGGER_REQUIREMENT_IDS != TRIGGER_REQUIREMENT_IDS:
        failures.append("selected P09 offline requirement ID is incomplete")
    if not failures:
        source = validate_source(root)
        failures.extend(source.errors)
    if not failures:
        if smoke_report_path is None:
            value = os.environ.get(SMOKE_REPORT_ENV)
            smoke_report_path = Path(value) if value else None
        smoke = validate_smoke_report(smoke_report_path, root=root)
        failures.extend(smoke.errors)

    if not failures and source is not None:
        environment = os.environ.copy()
        for key in (
            "HARNESS_RUN_DIR",
            "HARNESS_EVIDENCE_DIR",
            "OPENAI_API_KEY",
            "GMAIL_CLIENT_SECRET",
        ):
            environment.pop(key, None)
        for check in source.focused_checks:
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
            backend_smoke_count += int(check.backend_smoke)
    if not failures and backend_smoke_count != 1:
        failures.append("exactly one backend local workflow smoke must execute")

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
        "registered_command_count": source.registered_command_count if source else 0,
        "outbound_command_count": source.outbound_command_count if source else 0,
        "local_cleanup_command_count": (
            source.local_cleanup_command_count if source else 0
        ),
        "capability_count": source.capability_count if source else 0,
        "checks": checks,
        "backend_local_workflow_smoke_count": backend_smoke_count,
        "packaged_app_smoke_validated": smoke is not None and not smoke.errors,
        "smoke_report_sha256": smoke.report_sha256 if smoke else "",
        "bundle_sha256": smoke.bundle_sha256 if smoke else "",
        "executable_sha256": smoke.executable_sha256 if smoke else "",
        "sandbox_profile_sha256": smoke.sandbox_profile_sha256 if smoke else "",
        "collage_sha256": smoke.collage_sha256 if smoke else "",
        "browser_mock_acceptance": False,
        "developer_id_signed": smoke.developer_id_signed if smoke else False,
        "notarized": smoke.notarized if smoke else False,
        "clean_machine_certified": (
            smoke.clean_machine_certified if smoke else False
        ),
        "signed_acceptance_claim": "deferred_not_passed",
        "deferred_requirement_count": len(DEFERRED_REQUIREMENT_IDS),
        "pass_evidence_written": not failures,
    }
    if failures or source is None or smoke is None:
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
                "p09_offline::signed_clean_machine_acceptance_deferred"
                if deferred
                else "p09_offline::focused_functional_offline_verification"
            ),
            "recorded_at": recorded_at,
            "details": {
                "checks_passed": len(checks),
                "backend_local_workflow_smoke": backend_smoke_count == 1,
                "packaged_app_smoke_validated": True,
                "verification_sha256": _verification_hash(
                    requirement, packet, source, smoke, checks
                ),
                "public_summary": _public_summary(
                    requirement, packet, source, smoke, len(checks)
                ),
            },
        }
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


def main() -> int:
    run_dir = os.environ.get("HARNESS_RUN_DIR")
    evidence_dir = os.environ.get("HARNESS_EVIDENCE_DIR")
    if not run_dir or not evidence_dir:
        print(
            "HARNESS_RUN_DIR and HARNESS_EVIDENCE_DIR are required",
            file=sys.stderr,
        )
        return 2
    try:
        snapshot = json.loads(
            (Path(run_dir) / "requirements.json").read_text(encoding="utf-8")
        )
        selected = set(snapshot["selected_requirement_ids"])
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
        print(f"cannot read harness requirement snapshot: {error}", file=sys.stderr)
        return 2
    return evaluate(
        REPOSITORY_ROOT,
        Path(evidence_dir),
        selected,
    )


if __name__ == "__main__":
    raise SystemExit(main())
