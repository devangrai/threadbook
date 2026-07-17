"""Fail-closed evaluator for the approved P04 people and owner packet."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.evaluators.p03_receipts import (  # noqa: E402
    CommandResult,
    run_bounded_command,
    write_atomic_json,
)


RUN_ID = "20260716T080942Z-897a520d"
PACKET_DIR = f"artifacts/harness/P04/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p04-people-diagnostics.json"

PASS_REQUIREMENT_IDS = frozenset({"P04-PER-001", "P04-OWN-001"})
DEFERRED_REQUIREMENT_IDS = frozenset({"P04-QLT-001", "P04-PERF-001"})
REQUIREMENT_IDS = PASS_REQUIREMENT_IDS | DEFERRED_REQUIREMENT_IDS
EXPECTED_SELECTION = (
    "P04-OWN-001",
    "P04-PER-001",
    "P04-PERF-001",
    "P04-QLT-001",
)

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 96 * 1024
COMMAND_TIMEOUT_SECONDS = 15 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P04-photo-analysis.md": (
        "3fb58a5c42f5c15763d31fe629aafeaba58117b03550ad1742bc939db1d25390"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "859a0ff5720d0fafad455e760068ff16cad62722beafcae8ec29b879aab9476b"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "eac67a64c44a42e3dde5d9a7b7e931eae1bffd3a56b9afc6fe779ede8472b0a4"
    ),
    f"{PACKET_DIR}/review.md": (
        "1e821fe80b7c8654e177983e865a78d97173c76186c7256fbb7a0cba6871ca6f"
    ),
}

MIGRATION_FILE = (
    "crates/wardrobe-platform/migrations/0014_photo_owner_authority.sql"
)
MIGRATION_CHECKSUM_FILE = (
    "crates/wardrobe-platform/migrations/0014_photo_owner_authority.sha256"
)

PEOPLE_COMMANDS = (
    "detect_photo_scope_people_v1",
    "list_photo_owner_reviews_v1",
    "read_photo_owner_preview_v1",
    "decide_photo_owner_v1",
    "correct_photo_owner_v1",
    "correct_photo_person_detection_v1",
    "retry_photo_person_detection_v1",
)

SOURCE_FILES = (
    "Cargo.lock",
    "tools/evaluators/p04_people.py",
    "tests/test_p04_people_evaluator.py",
    "crates/wardrobe-core/Cargo.toml",
    "crates/wardrobe-core/src/photo_analysis.rs",
    "crates/wardrobe-core/src/ports.rs",
    "crates/wardrobe-core/src/service.rs",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/src/bin/generate-bindings.rs",
    "crates/wardrobe-core/tests/photo_analysis_contracts.rs",
    "crates/wardrobe-core/tests/photo_analysis_provider.rs",
    "crates/wardrobe-core/tests/photo_analysis_service.rs",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/build.rs",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/photo_repository.rs",
    "crates/wardrobe-platform/src/person_repository.rs",
    "crates/wardrobe-platform/src/person_detection_native.rs",
    "crates/wardrobe-platform/tests/person_detection_repository.rs",
    "crates/wardrobe-platform/src/deletion_repository.rs",
    "crates/wardrobe-platform/src/reconciliation_repository.rs",
    "crates/wardrobe-platform/src/restore_repository.rs",
    MIGRATION_FILE,
    MIGRATION_CHECKSUM_FILE,
    "native/photokit/Package.swift",
    "native/photokit/Sources/WardrobePhotoKit/PersonDetection.swift",
    "native/photokit/Sources/WardrobePhotoKitObjC/include/wardrobe_photokit.h",
    "native/photokit/Tests/CABIHeaderTests.c",
    "native/photokit/Tests/RustLinkSmoke.rs",
    "native/photokit/Tests/WardrobePhotoKitTests/PersonDetectionTests.swift",
    "native/photokit/Tests/Fixtures/PersonDetection/ATTRIBUTION.md",
    "native/photokit/Tests/Fixtures/PersonDetection/building.jpg",
    "native/photokit/Tests/Fixtures/PersonDetection/basketball1.png",
    "native/photokit/Tests/Fixtures/PersonDetection/basketball2.png",
    "native/photokit/scripts/test-native.sh",
    "src-tauri/Cargo.toml",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/src/generated/contracts.ts",
    "apps/desktop-ui/src/PhotoAnalysisWorkspace.tsx",
    "apps/desktop-ui/src/OwnerReviewWorkspace.tsx",
    "apps/desktop-ui/src/OwnerReviewWorkspace.test.tsx",
    "apps/desktop-ui/src/owner-review-bridge.ts",
    "apps/desktop-ui/src/owner-review-bridge.test.ts",
    "apps/desktop-ui/src/owner-review-model.ts",
    "apps/desktop-ui/src/owner-review-model.test.ts",
    "apps/desktop-ui/e2e/photo-analysis.spec.ts",
)

MODEL_SUFFIXES = (
    ".mlmodel",
    ".mlmodelc",
    ".mlpackage",
    ".onnx",
    ".safetensors",
    ".tflite",
    ".pt",
    ".pth",
)
SCAN_ROOTS = ("assets", "release", "crates", "src-tauri", "apps/desktop-ui")
SCAN_EXCLUDED_DIRECTORIES = {
    ".build",
    "dist",
    "node_modules",
    "target",
    "test-results",
}


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]
    require_rust_test: bool = False


COMMAND_CHECKS = (
    CommandCheck(
        "core_people_owner_contracts",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "--test",
            "photo_analysis_contracts",
            "--test",
            "photo_analysis_provider",
            "--test",
            "photo_analysis_service",
        ),
        require_rust_test=True,
    ),
    CommandCheck(
        "migration_v14_strict_schema",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--lib",
            "database::tests::fresh_v14_schema_is_strict_restrictive_and_append_only",
            "--",
            "--exact",
        ),
        require_rust_test=True,
    ),
    CommandCheck(
        "migration_v14_post_commit_recovery",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--lib",
            "database::tests::post_commit_failpoints_restore_exact_managed_pre_upgrade_database",
            "--",
            "--exact",
        ),
        require_rust_test=True,
    ),
    CommandCheck(
        "migration_v14_legacy_history",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--lib",
            "database::tests::migration_0014_preserves_populated_v13_reconciliation_history_without_owner_fabrication",
            "--",
            "--exact",
        ),
        require_rust_test=True,
    ),
    CommandCheck(
        "platform_person_native_adapter",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--lib",
            "person_detection_native::tests",
        ),
        require_rust_test=True,
    ),
    CommandCheck(
        "platform_process_unavailable_recovery",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--test",
            "person_detection_repository",
        ),
        require_rust_test=True,
    ),
    CommandCheck(
        "native_vision_abi_and_fixtures",
        ("bash", "native/photokit/scripts/test-native.sh"),
    ),
    CommandCheck(
        "generated_bindings_drift",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-core",
            "generated_bindings_are_current",
        ),
        require_rust_test=True,
    ),
    CommandCheck(
        "ui_owner_review",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "src/owner-review-bridge.test.ts",
            "src/owner-review-model.test.ts",
            "src/OwnerReviewWorkspace.test.tsx",
            "src/PhotoAnalysisWorkspace.test.tsx",
        ),
    ),
    CommandCheck(
        "ui_production_build",
        ("npm", "--workspace", "@wardrobe/desktop-ui", "run", "build"),
    ),
    CommandCheck(
        "ui_people_owner_playwright",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "run",
            "test:e2e",
            "--",
            "photo-analysis.spec.ts",
        ),
    ),
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
    migration_sha256: str
    registered_commands: tuple[str, ...]
    acl_permissions: tuple[str, ...]
    native_abi_valid: bool
    vision_framework_linked: bool
    ui_flow_complete: bool
    segmentation_disabled: bool
    model_pack_files: tuple[str, ...]
    approval_files: tuple[str, ...]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, limit: int = MAX_SOURCE_BYTES) -> bytes | None:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > limit
        ):
            return None
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


def _aggregate(contents: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for relative, data in sorted(contents.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def validate_packet(root: Path) -> PacketValidation:
    errors: list[str] = []
    hashes: dict[str, str] = {}
    contents: dict[str, bytes] = {}
    for relative, expected_hash in EXPECTED_PACKET_HASHES.items():
        data = _read_regular(root / relative)
        if data is None:
            errors.append(f"frozen packet file is unreadable or unsafe: {relative}")
            continue
        actual_hash = _sha256(data)
        hashes[relative] = actual_hash
        contents[relative] = data
        if actual_hash != expected_hash:
            errors.append(f"frozen packet hash changed: {relative}")

    requirements = _json_object(
        contents.get(f"{PACKET_DIR}/requirements.json", b"")
    )
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
    selected = requirements.get("selected_requirement_ids")
    if (
        requirements.get("phase") != "P04"
        or requirements.get("git_revision")
        != "8a8d99f2f6313a11d12cc1aefcf45dd2789614f8"
        or selected != list(EXPECTED_SELECTION)
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("frozen P04 people requirement selection is invalid")

    state_data = _read_regular(root / STATE_FILE)
    state = _json_object(state_data or b"")
    if state_data is None:
        errors.append(f"approved packet state is unreadable or unsafe: {STATE_FILE}")
    else:
        hashes[STATE_FILE] = _sha256(state_data)
    review = state.get("review")
    if (
        state.get("phase") != "P04"
        or state.get("run_id") != RUN_ID
        or state.get("status")
        not in {"APPROVED", "BUILT", "EVALUATED", "EVALUATION_FAILED"}
        or state.get("selected_requirement_ids") != list(EXPECTED_SELECTION)
        or not isinstance(review, dict)
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash")
        != EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"]
        or not isinstance(review.get("reviewer"), str)
        or not review.get("reviewer")
        or state.get("spec_hashes")
        != {
            "specs/phases/P04-photo-analysis.md": EXPECTED_PACKET_HASHES[
                "specs/phases/P04-photo-analysis.md"
            ],
            "specs/system.md": EXPECTED_PACKET_HASHES["specs/system.md"],
        }
    ):
        errors.append("P04 people packet is not independently approved")
    if state.get("status") in {"BUILT", "EVALUATED", "EVALUATION_FAILED"}:
        build = state.get("build")
        if (
            not isinstance(build, dict)
            or build.get("exit_code") != 0
            or not isinstance(build.get("source_fingerprint"), str)
            or re.fullmatch(r"[0-9a-f]{64}", build["source_fingerprint"]) is None
        ):
            errors.append("P04 people packet has no valid successful build record")

    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(
        "utf-8", errors="replace"
    )
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append("approved P04 people review decision is missing")

    return PacketValidation(
        errors=tuple(dict.fromkeys(errors)),
        packet_sha256=_aggregate(contents),
        hashes=hashes,
    )


def _read_sources(root: Path) -> tuple[dict[str, bytes], list[str], str]:
    contents: dict[str, bytes] = {}
    errors: list[str] = []
    for relative in SOURCE_FILES:
        data = _read_regular(root / relative)
        if data is None:
            errors.append(f"required P04 people source is unreadable or unsafe: {relative}")
        else:
            contents[relative] = data
    return contents, errors, _aggregate(contents)


def _text(contents: dict[str, bytes], relative: str) -> str:
    try:
        return contents[relative].decode("utf-8")
    except (KeyError, UnicodeDecodeError):
        return ""


def _block(text: str, start: str, end: str) -> str:
    start_index = text.find(start)
    if start_index < 0:
        return ""
    end_index = text.find(end, start_index + len(start))
    return text[start_index:] if end_index < 0 else text[start_index:end_index]


def _scan_segmentation_distribution(
    root: Path,
) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
    model_files: list[str] = []
    approval_files: list[str] = []
    approvals_empty = True
    for relative_root in SCAN_ROOTS:
        base = root / relative_root
        if not base.is_dir():
            continue
        try:
            for directory, names, files in os.walk(base, followlinks=False):
                names[:] = [
                    name
                    for name in names
                    if name not in SCAN_EXCLUDED_DIRECTORIES
                ]
                current = Path(directory)
                for name in names:
                    if name.lower().endswith(MODEL_SUFFIXES):
                        model_files.append(
                            (current / name).relative_to(root).as_posix()
                        )
                for name in files:
                    path = current / name
                    lowered = name.lower()
                    if lowered.endswith(MODEL_SUFFIXES):
                        model_files.append(path.relative_to(root).as_posix())
                    if (
                        "approval" not in lowered
                        or ("segment" not in lowered and "mask" not in lowered)
                    ):
                        continue
                    relative = path.relative_to(root).as_posix()
                    approval_files.append(relative)
                    data = _read_regular(path)
                    if data is None:
                        approvals_empty = False
                        continue
                    if path.suffix.lower() == ".json":
                        try:
                            value = json.loads(data)
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            approvals_empty = False
                        else:
                            approvals_empty = (
                                approvals_empty
                                and value in ({}, [], {"approvals": []})
                            )
                    else:
                        text = data.decode("utf-8", errors="replace")
                        approvals_empty = approvals_empty and not re.search(
                            r"(?i)(approved|enabled)\s*[:=]\s*(true|1)",
                            text,
                        )
        except OSError:
            approvals_empty = False
    return (
        tuple(sorted(set(model_files))),
        tuple(sorted(set(approval_files))),
        approvals_empty,
    )


def validate_source_contract(root: Path) -> SourceValidation:
    contents, errors, source_sha256 = _read_sources(root)
    core = _text(contents, "crates/wardrobe-core/src/photo_analysis.rs")
    ports = _text(contents, "crates/wardrobe-core/src/ports.rs")
    service = _text(contents, "crates/wardrobe-core/src/service.rs")
    bindings = _text(contents, "crates/wardrobe-core/src/bindings.rs")
    generated = _text(contents, "apps/desktop-ui/src/generated/contracts.ts")
    core_tests = "\n".join(
        _text(contents, relative)
        for relative in (
            "crates/wardrobe-core/tests/photo_analysis_contracts.rs",
            "crates/wardrobe-core/tests/photo_analysis_provider.rs",
            "crates/wardrobe-core/tests/photo_analysis_service.rs",
        )
    )
    required_core_markers = (
        "PersonDetectionProviderDescriptorV1",
        "PersonDetectionRequestV1",
        "PersonDetectionOutcomeV1",
        "PhotoOwnerReviewV1",
        "DecidePhotoOwnerV1Request",
        "CorrectPhotoOwnerV1Request",
        "CorrectPhotoPersonDetectionV1Request",
        "RetryPhotoPersonDetectionV1Request",
    )
    required_test_markers = (
        "person_detection_terminal_classes_enforce_cardinality_and_geometry",
        "owner_commands_are_strict_and_actions_have_exact_selection_shapes",
        "missed_person_correction_requires_full_revision_envelope",
        "service_forwards_and_checks_all_owner_authority_apis",
    )
    if (
        any(marker not in core and marker not in ports for marker in required_core_markers)
        or any(command not in service for command in PEOPLE_COMMANDS)
        or "ConformingLocalPersonDetectionProviderV1" not in ports
        or any(marker not in core_tests for marker in required_test_markers)
    ):
        errors.append("P04 person detection or owner authority contracts are incomplete")
    if (
        "generated_bindings_are_current" not in bindings
        or any(
            marker not in generated
            for marker in (
                "DetectPhotoScopePeopleV1Request",
                "PhotoOwnerReviewV1",
                "DecidePhotoOwnerV1Request",
                "CorrectPhotoPersonDetectionV1Request",
            )
        )
    ):
        errors.append("P04 people generated bindings are incomplete")

    migration = contents.get(MIGRATION_FILE, b"")
    migration_sha256 = _sha256(migration)
    migration_text = _text(contents, MIGRATION_FILE)
    database = _text(contents, "crates/wardrobe-platform/src/database.rs")
    required_tables = (
        "photo_person_detection_runs",
        "photo_person_detection_attempts",
        "photo_owner_preview_references",
        "photo_owner_reviews",
        "photo_person_instances",
        "photo_owner_decisions",
        "photo_owner_heads",
        "photo_owner_work_claims",
        "photo_observation_owner_links",
        "photo_owner_command_entities",
    )
    if (
        _text(contents, MIGRATION_CHECKSUM_FILE).strip() != migration_sha256
        or re.fullmatch(r"[0-9a-f]{64}", migration_sha256) is None
        or any(f"CREATE TABLE {table}" not in migration_text for table in required_tables)
        or 'include_str!("../migrations/0014_photo_owner_authority.sql")'
        not in database
        or 'include_str!("../migrations/0014_photo_owner_authority.sha256")'
        not in database
        or "version: 14" not in database
        or "post_commit_failpoints_restore_exact_managed_pre_upgrade_database"
        not in database
        or "fresh_schema_is_strict_restrictive_and_append_only"
        not in database
        or "migration_0014_preserves_populated_v13_reconciliation_history_without_owner_fabrication"
        not in database
    ):
        errors.append("checksummed v14 migration or recovery coverage is incomplete")

    platform_lib = _text(contents, "crates/wardrobe-platform/src/lib.rs")
    repository = _text(contents, "crates/wardrobe-platform/src/person_repository.rs")
    adapter = _text(
        contents, "crates/wardrobe-platform/src/person_detection_native.rs"
    )
    deletion = _text(contents, "crates/wardrobe-platform/src/deletion_repository.rs")
    if (
        "mod person_repository;" not in platform_lib
        or "MacOsVisionPersonDetectionProviderV1" not in platform_lib
        or "TransactionBehavior::Immediate" not in repository
        or "ConformingLocalPersonDetectionProviderV1" not in repository
        or "provider_invoked" not in repository
        or "photo_observation_owner_links" not in repository
        or "owner_decision_stale" not in repository
        or "wk_detect_people_rgb_v1" not in adapter
        or any(table not in deletion for table in required_tables)
    ):
        errors.append("platform people repository, fencing, or deletion closure is incomplete")

    header = _text(
        contents,
        "native/photokit/Sources/WardrobePhotoKitObjC/include/wardrobe_photokit.h",
    )
    c_abi_test = _text(contents, "native/photokit/Tests/CABIHeaderTests.c")
    swift = _text(
        contents, "native/photokit/Sources/WardrobePhotoKit/PersonDetection.swift"
    )
    swift_test = _text(
        contents,
        "native/photokit/Tests/WardrobePhotoKitTests/PersonDetectionTests.swift",
    )
    native_script = _text(contents, "native/photokit/scripts/test-native.sh")
    native_abi_valid = all(
        marker in header and marker in c_abi_test
        for marker in (
            "WK_PERSON_DETECTION_REQUEST_V1_SIZE",
            "WK_PERSON_RECT_V1_SIZE",
            "WK_PERSON_DETECTION_METADATA_V1_SIZE",
            "wk_detect_people_rgb_v1",
        )
    ) and all(
        marker in swift_test
        for marker in (
            "testPersonDetectionLayoutsMatchCABI",
            "testMalformedRequestsZeroOutputsAndNeverWriteRectangles",
            "testOverflowIsBoundedAndReturnsNoPartialRectangles",
        )
    )
    vision_framework_linked = (
        "VNDetectHumanRectanglesRequest()" in swift
        and "VNDetectHumanRectanglesRequestRevision2" in swift
        and "upperBodyOnly = false" in swift
        and '.linkedFramework("Vision")'
        in _text(contents, "native/photokit/Package.swift")
        and "_wk_detect_people_rgb_v1" in native_script
        and "VNDetectHumanRectanglesRequest" in native_script
        and "testReviewedOpenCVFixturesThroughProductionCABI" in swift_test
    )
    forbidden_identity_markers = (
        "VNDetectFace",
        "PHAssetCollectionSubtypeSmartAlbumPeople",
        "CNContact",
        "face embedding",
        "identity inference",
    )
    if (
        not native_abi_valid
        or not vision_framework_linked
        or any(marker in swift or marker in adapter for marker in forbidden_identity_markers)
    ):
        errors.append("native local Vision ABI, fixture execution, or identity exclusion is incomplete")

    desktop = _text(contents, "src-tauri/src/lib.rs").split("#[cfg(test)]", 1)[0]
    build_rs = _text(contents, "src-tauri/build.rs")
    capability = _json_object(
        contents.get("src-tauri/capabilities/main.json", b"")
    )
    permissions_value = capability.get("permissions")
    acl_permissions = tuple(
        permission
        for permission in permissions_value
        if isinstance(permission, str)
    ) if isinstance(permissions_value, list) else ()
    handler = _block(desktop, ".invoke_handler(tauri::generate_handler![", "])")
    registered_commands = tuple(
        command for command in PEOPLE_COMMANDS if command in handler
    )
    for command in PEOPLE_COMMANDS:
        permission = "allow-" + command.replace("_", "-")
        if (
            command not in registered_commands
            or f'"{command}"' not in build_rs
            or permission not in acl_permissions
        ):
            errors.append(f"Tauri people command or ACL is missing: {command}")

    bridge = _text(contents, "apps/desktop-ui/src/owner-review-bridge.ts")
    workspace = _text(contents, "apps/desktop-ui/src/OwnerReviewWorkspace.tsx")
    photo_workspace = _text(
        contents, "apps/desktop-ui/src/PhotoAnalysisWorkspace.tsx"
    )
    ui_tests = "\n".join(
        _text(contents, relative)
        for relative in (
            "apps/desktop-ui/src/OwnerReviewWorkspace.test.tsx",
            "apps/desktop-ui/src/owner-review-bridge.test.ts",
            "apps/desktop-ui/src/owner-review-model.test.ts",
            "apps/desktop-ui/e2e/photo-analysis.spec.ts",
        )
    )
    ui_flow_complete = (
        all(command in bridge for command in PEOPLE_COMMANDS)
        and "OwnerReviewWorkspace" in photo_workspace
        and all(
            marker in workspace
            for marker in (
                "This is me",
                "I'm not in this photo",
                "Person missed",
            )
        )
        and all(
            marker in ui_tests
            for marker in (
                "This is me",
                "Person missed",
                "owner_absent",
                "correct_photo_owner_v1",
            )
        )
        and "AxeBuilder" in _text(
            contents, "apps/desktop-ui/e2e/photo-analysis.spec.ts"
        )
    )
    if not ui_flow_complete:
        errors.append("owner review UI, command bridge, or workflow tests are incomplete")

    model_pack_files, approval_files, approvals_empty = (
        _scan_segmentation_distribution(root)
    )
    segmentation_production = "\n".join((ports, repository, desktop))
    false_claim_markers = (
        "segmentation_recall_certified",
        "segmentation_iou_certified",
        "segmentation_warm_p95_certified",
        "segmentation_peak_memory_certified",
    )
    segmentation_disabled = (
        "UnavailableGarmentSegmentationProviderV1" in ports
        and "ReviewedModelPackAbsent" in ports
        and "model_revision: None" in ports
        and desktop.count(
            ".with_garment_segmentation_provider("
            "UnavailableGarmentSegmentationProviderV1)"
        )
        == 1
        and "'reviewed_model_pack_absent'" in repository
        and "quality_approved" in repository
        and not model_pack_files
        and approvals_empty
        and not any(marker in segmentation_production for marker in false_claim_markers)
    )
    if not segmentation_disabled:
        errors.append("segmentation model, approval, or certification is not truthfully disabled")

    return SourceValidation(
        errors=tuple(dict.fromkeys(errors)),
        source_sha256=source_sha256,
        migration_sha256=migration_sha256,
        registered_commands=registered_commands,
        acl_permissions=acl_permissions,
        native_abi_valid=native_abi_valid,
        vision_framework_linked=vision_framework_linked,
        ui_flow_complete=ui_flow_complete,
        segmentation_disabled=segmentation_disabled,
        model_pack_files=model_pack_files,
        approval_files=approval_files,
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
    return None


def _bounded_json_bytes(value: dict[str, Any]) -> bytes:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P04 people evaluator artifact exceeds size limit")
    return data


def _write_bounded_json(path: Path, value: dict[str, Any]) -> None:
    _bounded_json_bytes(value)
    write_atomic_json(path, value)


def _remove_stale_outputs(evidence_dir: Path) -> None:
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
        "packet_sha256": packet.packet_sha256,
        "source_sha256": source.source_sha256,
        "migration_sha256": source.migration_sha256,
        "checks": checks,
        "segmentation_disabled": source.segmentation_disabled,
    }
    return _sha256(_bounded_json_bytes(value))


def _public_summary(requirement: str) -> dict[str, Any]:
    if requirement == "P04-QLT-001":
        return {
            "feature_enabled": False,
            "acceptance_claim": "deferred_not_passed",
            "deferred_limitation": (
                "Automatic garment segmentation and its approved Mac dataset "
                "evaluation are unavailable; no recall or mask-IoU threshold is claimed."
            ),
        }
    if requirement == "P04-PERF-001":
        return {
            "feature_enabled": False,
            "acceptance_claim": "deferred_not_passed",
            "deferred_limitation": (
                "The local segmentation model pack is disabled; no warm-p95 "
                "latency or peak-memory benchmark has been accepted."
            ),
        }
    return {
        "feature_enabled": True,
        "acceptance_claim": "local_requirement_passed",
        "person_detection_provider": "apple_vision_human_rectangles_v1",
        "identity_assignment": False,
        "owner_confirmation_required": True,
        "automatic_segmentation_enabled": False,
    }


def _diagnostics(
    *,
    requested: set[str],
    failures: list[str],
    packet: PacketValidation,
    source: SourceValidation | None,
    checks: dict[str, dict[str, Any]],
    recorded_at: str,
    evidence_written: bool,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "run_id": RUN_ID,
        "recorded_at": recorded_at,
        "status": "fail" if failures else "pass",
        "selected_requirement_ids": sorted(requested),
        "failures": list(dict.fromkeys(failures)),
        "packet_sha256": packet.packet_sha256,
        "packet_hashes": packet.hashes,
        "source_sha256": source.source_sha256 if source else "",
        "migration_sha256": source.migration_sha256 if source else "",
        "registered_commands": list(source.registered_commands) if source else [],
        "native_abi_valid": source.native_abi_valid if source else False,
        "vision_framework_linked": (
            source.vision_framework_linked if source else False
        ),
        "ui_flow_complete": source.ui_flow_complete if source else False,
        "segmentation_disabled": (
            source.segmentation_disabled if source else False
        ),
        "model_pack_files": list(source.model_pack_files) if source else [],
        "approval_files": list(source.approval_files) if source else [],
        "checks": checks,
        "deferred_requirement_ids": sorted(
            requested & DEFERRED_REQUIREMENT_IDS
        ),
        "evidence_written": evidence_written,
    }


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    try:
        evidence_metadata = evidence_dir.lstat()
    except OSError:
        return 1
    if not stat.S_ISDIR(evidence_metadata.st_mode) or evidence_dir.is_symlink():
        return 1
    _remove_stale_outputs(evidence_dir)

    recorded_at = utc_now()
    packet = validate_packet(root)
    source: SourceValidation | None = None
    checks: dict[str, dict[str, Any]] = {}
    failures = list(packet.errors)

    if not failures:
        source = validate_source_contract(root)
        failures.extend(source.errors)

    if not failures:
        environment = os.environ.copy()
        environment.pop("HARNESS_RUN_DIR", None)
        environment.pop("HARNESS_EVIDENCE_DIR", None)
        for check in COMMAND_CHECKS:
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

    if failures or source is None:
        diagnostic = _diagnostics(
            requested=requested,
            failures=failures,
            packet=packet,
            source=source,
            checks=checks,
            recorded_at=recorded_at,
            evidence_written=False,
        )
        try:
            _write_bounded_json(evidence_dir / DIAGNOSTICS_NAME, diagnostic)
        except (OSError, ValueError):
            pass
        return 1

    payloads: dict[str, dict[str, Any]] = {}
    for requirement in sorted(requested):
        status = "deferred" if requirement in DEFERRED_REQUIREMENT_IDS else "pass"
        payloads[requirement] = {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": status,
            "test": (
                "p04_people::disabled_segmentation_limitation"
                if status == "deferred"
                else "p04_people::focused_local_people_owner_verification"
            ),
            "recorded_at": recorded_at,
            "details": {
                "evaluator": "tools/evaluators/p04_people.py",
                "verification_sha256": _verification_hash(
                    requirement, packet, source, checks
                ),
                "checks": list(checks),
                "public_summary": _public_summary(requirement),
            },
        }
        _bounded_json_bytes(payloads[requirement])

    diagnostic = _diagnostics(
        requested=requested,
        failures=[],
        packet=packet,
        source=source,
        checks=checks,
        recorded_at=recorded_at,
        evidence_written=True,
    )
    _bounded_json_bytes(diagnostic)
    written: list[Path] = []
    try:
        for requirement, payload in payloads.items():
            path = evidence_dir / f"{requirement}.json"
            _write_bounded_json(path, payload)
            written.append(path)
        diagnostic_path = evidence_dir / DIAGNOSTICS_NAME
        _write_bounded_json(diagnostic_path, diagnostic)
        written.append(diagnostic_path)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        for requirement in REQUIREMENT_IDS:
            (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
        (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)
        raise
    return 0


def main() -> int:
    run_dir_value = os.environ.get("HARNESS_RUN_DIR")
    evidence_dir_value = os.environ.get("HARNESS_EVIDENCE_DIR")
    if not run_dir_value or not evidence_dir_value:
        print(
            "HARNESS_RUN_DIR and HARNESS_EVIDENCE_DIR are required",
            file=sys.stderr,
        )
        return 2
    run_dir = Path(run_dir_value)
    expected_run_dir = REPOSITORY_ROOT / PACKET_DIR
    try:
        if run_dir.resolve(strict=True) != expected_run_dir.resolve(strict=True):
            print("P04 people evaluator received the wrong run directory", file=sys.stderr)
            return 2
        snapshot = _json_object(
            _read_regular(run_dir / "requirements.json") or b""
        )
    except OSError:
        print("P04 people requirements snapshot is unreadable", file=sys.stderr)
        return 2
    selected = snapshot.get("selected_requirement_ids")
    if selected != list(EXPECTED_SELECTION):
        print("P04 people requirement selection is invalid", file=sys.stderr)
        return 2
    result = evaluate(REPOSITORY_ROOT, Path(evidence_dir_value), set(selected))
    if result:
        print("P04 people evaluation failed", file=sys.stderr)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
