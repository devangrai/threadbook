"""Fail-closed evaluator for the approved P06 PhotoKit connector packet."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import stat
import sys
from typing import Any

from tools.evaluators.p03_receipts import (
    CommandResult,
    run_bounded_command,
    write_atomic_json,
)


REQUIREMENT_IDS = frozenset({"P06-PHO-001", "P06-PHO-002"})
RUN_ID = "20260716T105025Z-10b259e2"
PACKET_DIR = f"artifacts/harness/P06/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p06-photokit-diagnostics.json"

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILES = 512
MAX_FOCUSED_RUST_TESTS = 48
MAX_ARTIFACT_BYTES = 128 * 1024
MAX_APP_FILES = 4096
MAX_APP_BYTES = 2 * 1024 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 30 * 60
LIVE_TIMEOUT_SECONDS = 45 * 60
APP_INSPECTION_TIMEOUT_SECONDS = 60

LIVE_PREFIX = "P06_PHOTOKIT_LIVE "
LIVE_CHALLENGE_ENV = "P06_PHOTOKIT_CHALLENGE_JSON"
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
EXPECTED_BUNDLE_ID = "com.devrai.wardrobe"
EXPECTED_USAGE = (
    "Wardrobe uses your Photos library to let you select an album and import "
    "its original images into your private local wardrobe."
)

P00_FIXTURE_HASHES = (
    "0a954174688fa3cf1fd32faa5601e6a7978b5fda3b90a470fac6fbce9686cf34",
    "78b167d1451183a20b6ea88c3a4701d59335699aa2c947ead7282c31edff35a5",
)

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P06-connectors.md": (
        "bf9c3e727015e0e1a9eb2f27655a8b263997d7f06cbf9e63753fe3cb42792f19"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "68f527d8ac87dc8440efabb4f36d6e8af8c203bc656d06dc3be1bde9478dd666"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "3bf8c969b55f98a241e4f4ad93972fd6a2cc26ce01df0ee462cb76ea7bb8d3b3"
    ),
    f"{PACKET_DIR}/review.md": (
        "e6c14c27fd29b4dda49e3fd88d396f31d8b90ded90bff8154c8e67553776c252"
    ),
}

SOURCE_BASE_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "crates/wardrobe-core/Cargo.toml",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/src/contracts.rs",
    "crates/wardrobe-core/src/lib.rs",
    "crates/wardrobe-core/src/photokit_connector.rs",
    "crates/wardrobe-core/src/ports.rs",
    "crates/wardrobe-core/src/service.rs",
    "crates/wardrobe-core/tests/photokit_contracts.rs",
    "crates/wardrobe-core/tests/photokit_service.rs",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/build.rs",
    "crates/wardrobe-platform/src/blob.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/deletion_repository.rs",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/restore_repository.rs",
    "crates/wardrobe-platform/migrations/0012_photokit_connector.sql",
    "crates/wardrobe-platform/migrations/0012_photokit_connector.sha256",
    "native/photokit/Package.swift",
    "native/photokit/Sources/WardrobePhotoKitObjC/include/wardrobe_photokit.h",
    "src-tauri/Cargo.toml",
    "src-tauri/Info.plist",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "src-tauri/src/lib.rs",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/src/App.tsx",
    "apps/desktop-ui/src/generated/contracts.ts",
)

SOURCE_SEARCH_ROOTS = (
    "crates/wardrobe-core/src",
    "crates/wardrobe-core/tests",
    "crates/wardrobe-platform/src",
    "crates/wardrobe-platform/tests",
    "crates/wardrobe-platform/migrations",
    "native/photokit/Sources",
    "native/photokit/Tests",
    "src-tauri/src",
    "src-tauri/permissions",
    "apps/desktop-ui/src",
)
SOURCE_SUFFIXES = frozenset(
    {".rs", ".sql", ".sha256", ".swift", ".m", ".h", ".ts", ".tsx", ".json", ".toml"}
)

PHOTOKIT_COMMANDS = (
    "get_photokit_connector_v1",
    "begin_photokit_setup_v1",
    "configure_photokit_scope_v1",
    "sync_photokit_v1",
    "disable_photokit_v1",
)
NATIVE_ABI_MARKERS = (
    "wk_photokit_create_v1",
    "wk_photokit_send_v1",
    "wk_photokit_next_v1",
    "wk_photokit_frame_free_v1",
    "wk_photokit_quiesce_v1",
    "wk_photokit_destroy_v1",
    "wk_photokit_validate_image_fd_v1",
)
MIGRATION_TABLES = (
    "photokit_connector_state",
    "photokit_enrollments",
    "photokit_assets",
    "photokit_operations",
    "photokit_operation_observations",
    "photokit_membership_generations",
    "photokit_generation_members",
    "photokit_materialization_attempts",
    "photokit_materializations",
    "photokit_availability_revisions",
    "photokit_availability_heads",
    "photokit_command_receipts",
    "photokit_key_cleanup_intents",
)
LIVE_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "event",
        "run_id",
        "challenge_nonce",
        "packet_sha256",
        "source_sha256",
        "exact_package",
        "same_package_relaunched",
        "bundle_id",
        "info_plist_sha256",
        "executable_sha256",
        "bundle_sha256",
        "designated_requirement_sha256",
        "fixture_sha256",
        "native_callbacks",
        "tcc_authorized",
        "dedicated_fixture_album",
        "operator_removal_completed",
        "initial_complete_generation",
        "startup_reconciled",
        "asset_not_in_scope_delta",
        "membership_generation_delta",
        "photokit_revision_delta",
        "available_before",
        "unavailable_after",
        "blob_count_before",
        "blob_count_after",
        "synthetic_decision_preserved",
        "raw_identifiers_emitted",
        "personal_metadata_emitted",
    }
)


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
    live_smoke: bool = False


@dataclass(frozen=True)
class AppIdentity:
    bundle_id: str
    info_plist_sha256: str
    executable_sha256: str
    bundle_sha256: str
    designated_requirement_sha256: str

    def as_dict(self) -> dict[str, str]:
        return {
            "bundle_id": self.bundle_id,
            "info_plist_sha256": self.info_plist_sha256,
            "executable_sha256": self.executable_sha256,
            "bundle_sha256": self.bundle_sha256,
            "designated_requirement_sha256": self.designated_requirement_sha256,
        }


@dataclass(frozen=True)
class SourceValidation:
    errors: tuple[str, ...]
    source_sha256: str
    source_hashes: dict[str, str]
    source_file_count: int
    migration_sha256: str
    focused_checks: tuple[CommandCheck, ...]
    live_check: CommandCheck | None
    rust_test_count: int
    swift_test_file_count: int
    ui_test_file_count: int


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_sha256(path: Path, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise OSError
        copied = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            copied += len(chunk)
            if copied > max_bytes:
                raise OSError
            digest.update(chunk)
        if copied != metadata.st_size:
            raise OSError
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _read_regular_bounded(path: Path, *, max_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise OSError
        data = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, max_bytes + 1)):
            data.extend(chunk)
            if len(data) > max_bytes:
                raise OSError
        if len(data) != metadata.st_size:
            raise OSError
        return bytes(data)
    finally:
        os.close(descriptor)


def _digest_part(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _bundle_sha256(bundle: Path) -> str:
    if bundle.is_symlink() or not bundle.is_dir():
        raise OSError
    records: list[tuple[str, Path, os.stat_result]] = []
    pending = [bundle]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                metadata = entry.stat(follow_symlinks=False)
                relative = path.relative_to(bundle).as_posix()
                records.append((relative, path, metadata))
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
                elif not (
                    stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                ):
                    raise OSError
                if len(records) > MAX_APP_FILES:
                    raise OSError

    digest = hashlib.sha256()
    total_bytes = 0
    for relative, path, metadata in sorted(records):
        _digest_part(digest, relative.encode("utf-8"))
        _digest_part(digest, stat.S_IMODE(metadata.st_mode).to_bytes(4, "big"))
        if stat.S_ISDIR(metadata.st_mode):
            _digest_part(digest, b"directory")
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path).encode("utf-8")
            if len(target) > 4096:
                raise OSError
            _digest_part(digest, b"symlink")
            _digest_part(digest, target)
        else:
            total_bytes += metadata.st_size
            if total_bytes > MAX_APP_BYTES:
                raise OSError
            _digest_part(digest, b"file")
            _digest_part(digest, metadata.st_size.to_bytes(8, "big"))
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_dev != metadata.st_dev
                    or opened.st_ino != metadata.st_ino
                    or opened.st_size != metadata.st_size
                ):
                    raise OSError
                copied = 0
                while chunk := os.read(descriptor, 1024 * 1024):
                    copied += len(chunk)
                    digest.update(chunk)
                if copied != opened.st_size:
                    raise OSError
            finally:
                os.close(descriptor)
    return digest.hexdigest()


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
        actual = _sha256(data)
        contents[relative] = data
        hashes[relative] = actual
        if actual != expected:
            errors.append(f"frozen packet hash changed: {relative}")

    requirements_data = contents.get(f"{PACKET_DIR}/requirements.json", b"")
    requirements = _json_object(requirements_data)
    selected = requirements.get("selected_requirement_ids")
    requirement_rows = requirements.get("requirements")
    evidenced = {
        row.get("id")
        for row in requirement_rows
        if isinstance(row, dict) and row.get("evidence_required") is True
    } if isinstance(requirement_rows, list) else set()
    if (
        requirements.get("phase") != "P06"
        or not isinstance(selected, list)
        or set(selected) != REQUIREMENT_IDS
    ):
        errors.append("frozen P06 PhotoKit packet selection is invalid")
    if evidenced != REQUIREMENT_IDS:
        errors.append("frozen P06 PhotoKit evidence requirement set is invalid")

    state_data = _read_bounded(root / STATE_FILE)
    state = _json_object(state_data or b"")
    review = state.get("review") if isinstance(state.get("review"), dict) else {}
    spec_hashes = (
        state.get("spec_hashes")
        if isinstance(state.get("spec_hashes"), dict)
        else {}
    )
    state_selected = state.get("selected_requirement_ids")
    if (
        state.get("run_id") != RUN_ID
        or state.get("phase") != "P06"
        or state.get("status")
        not in {"APPROVED", "BUILD_FAILED", "BUILT", "EVALUATED", "EVALUATION_FAILED"}
        or not isinstance(state_selected, list)
        or set(state_selected) != REQUIREMENT_IDS
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash") != EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"]
        or spec_hashes.get("specs/system.md")
        != EXPECTED_PACKET_HASHES["specs/system.md"]
        or spec_hashes.get("specs/phases/P06-connectors.md")
        != EXPECTED_PACKET_HASHES["specs/phases/P06-connectors.md"]
    ):
        errors.append("P06 PhotoKit packet approval state is invalid")
    review_text = contents.get(f"{PACKET_DIR}/review.md", b"")
    if b"Status: APPROVED" not in review_text or b"\nAPPROVE\n" not in review_text:
        errors.append("P06 PhotoKit independent review approval is missing")

    return PacketValidation(
        tuple(dict.fromkeys(errors)),
        _aggregate_hash(contents),
        hashes,
    )


def _source_paths(root: Path) -> tuple[str, ...]:
    paths = set(SOURCE_BASE_FILES)
    for relative_root in SOURCE_SEARCH_ROOTS:
        directory = root / relative_root
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
                paths.add(path.relative_to(root).as_posix())
    paths.update(
        path.relative_to(root).as_posix()
        for path in _discover_live_runners(root)
    )
    return tuple(sorted(paths))


def _group_text(decoded: dict[str, str], prefixes: tuple[str, ...]) -> str:
    return "\n".join(
        text
        for relative, text in decoded.items()
        if any(relative.startswith(prefix) for prefix in prefixes)
    )


def _require_markers(
    errors: list[str],
    label: str,
    text: str,
    markers: tuple[str, ...],
) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        errors.append(f"P06 PhotoKit {label} markers are incomplete")


def _marker_errors(decoded: dict[str, str]) -> list[str]:
    errors: list[str] = []
    core = _group_text(
        decoded,
        ("crates/wardrobe-core/src/",),
    )
    platform = _group_text(
        decoded,
        ("crates/wardrobe-platform/src/",),
    )
    native = _group_text(
        decoded,
        ("native/photokit/Sources/", "native/photokit/Package.swift"),
    )
    migration = decoded.get(
        "crates/wardrobe-platform/migrations/0012_photokit_connector.sql", ""
    )
    tauri_lib = decoded.get("src-tauri/src/lib.rs", "")
    tauri_build = decoded.get("src-tauri/build.rs", "")
    platform_build = decoded.get("crates/wardrobe-platform/build.rs", "")
    tauri_capability = decoded.get("src-tauri/capabilities/main.json", "")
    tauri = "\n".join(
        (
            tauri_lib,
            tauri_build,
            platform_build,
            tauri_capability,
            decoded.get("src-tauri/Info.plist", ""),
        )
    )
    ui = "\n".join(
        text
        for relative, text in decoded.items()
        if relative.startswith("apps/desktop-ui/src/")
        and not relative.endswith((".test.ts", ".test.tsx"))
    )
    deletion = "\n".join(
        (
            decoded.get("crates/wardrobe-core/src/deletion.rs", ""),
            decoded.get("crates/wardrobe-core/src/catalog.rs", ""),
            decoded.get("crates/wardrobe-platform/src/deletion_repository.rs", ""),
            migration,
        )
    )
    restore = "\n".join(
        (
            decoded.get("crates/wardrobe-platform/src/database.rs", ""),
            decoded.get("crates/wardrobe-platform/src/restore_repository.rs", ""),
            migration,
        )
    )

    _require_markers(
        errors,
        "domain contract",
        core,
        (
            "PhotoKitConnectorPort",
            "PhotoKitEnrollmentEpochV1",
            "PhotoKitReconciliationFenceV1",
            "PhotoKitMembershipGenerationV1",
            "PhotoKitRevisionV1",
            "PhotoKitReconcileTriggerV1",
            "AssetNotInScope",
        ),
    )
    _require_markers(errors, "native C ABI", native, NATIVE_ABI_MARKERS)
    _require_markers(
        errors,
        "native PhotoKit implementation",
        native,
        (
            "PHAssetCollection",
            "PHAssetResourceManager",
            "isNetworkAccessAllowed",
            "requestAuthorization",
            "ImageIO",
            "Photos",
            "PhotosUI",
        ),
    )
    _require_markers(
        errors,
        "repository atomicity",
        platform + migration,
        (
            "store_authority_epoch",
            "photokit_revision",
            "operation_fence",
            "membership_generation",
            "asset_not_in_scope",
            "icloud_unavailable",
            "TransactionBehavior::Immediate",
        ),
    )
    for table in MIGRATION_TABLES:
        if f"CREATE TABLE {table}" not in migration:
            errors.append(f"P06 PhotoKit migration table is missing: {table}")
    for command in PHOTOKIT_COMMANDS:
        if command not in tauri_lib or command not in tauri_build:
            errors.append(f"P06 PhotoKit Tauri command is not registered: {command}")
        permission = "allow-" + command.replace("_", "-")
        if permission not in tauri_capability:
            errors.append(f"P06 PhotoKit Tauri permission is missing: {permission}")
        if command not in ui:
            errors.append(f"P06 PhotoKit UI command is not wired: {command}")
    _require_markers(
        errors,
        "Tauri production bridge",
        tauri,
        (
            "NSPhotoLibraryUsageDescription",
            "WardrobePhotoKit",
            "PhotoKitReconcileTriggerV1::Startup",
        ),
    )
    if "ScriptedPhotoKit" in tauri or "MockPhotoKit" in tauri:
        errors.append("scripted PhotoKit provider is reachable from production Tauri wiring")
    _require_markers(
        errors,
        "UI",
        ui,
        (
            "Apple Photos",
            "allow_icloud_downloads",
            "Sync now",
            "PhotoKitConnectorSnapshotV1",
        ),
    )
    _require_markers(
        errors,
        "deletion closure",
        deletion,
        (
            "photokit_enrollment",
            "photokit_asset",
            "photokit_materializations",
            "photokit_key_cleanup_intents",
            "photokit_revision",
        ),
    )
    _require_markers(
        errors,
        "restore normalization",
        restore,
        (
            "normalize_restored_photokit_state",
            "store_authority_epoch",
            "photokit_operations",
            "interrupted",
            "photokit_operation_observations",
            "photokit_key_cleanup_intents",
        ),
    )
    _require_markers(
        errors,
        "locator protection",
        platform + migration,
        (
            "XChaCha20Poly1305",
            "Hmac",
            "hkdf_expand",
            "key_reference",
            "photokit_locator_records",
            "lookup_hmac",
            "nonce BLOB",
            "ciphertext BLOB",
        ),
    )
    return list(dict.fromkeys(errors))


def _rust_tests(decoded: dict[str, str]) -> tuple[RustTest, ...]:
    pattern = re.compile(
        r"(?m)^\s*#\[(?:(?:tokio|async_std)::)?test[^\]]*\]\s*"
        r"(?:async\s+)?fn\s+(?P<name>[A-Za-z0-9_]+)\s*\("
    )
    tests: list[RustTest] = []
    for relative, text in decoded.items():
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
                    relative,
                    package,
                    target_kind,
                    Path(relative).stem,
                    match.group("name"),
                    text[match.start() : end],
                )
            )
    return tuple(tests)


def _is_photokit_test(test: RustTest) -> bool:
    named_scope = f"{Path(test.relative).name}\n{test.name}".lower()
    if "photokit" in named_scope:
        return True
    return test.name in {
        "deletion_schema_classification_covers_every_phase_table_and_blob_fk",
        "hard_deletion_compiled_sqlite_filesystem_restart_residual_smoke",
        "restored_pending_deletion_detaches_and_preserves_key_cleanup_intent",
    }


def _rust_test_check(test: RustTest) -> CommandCheck:
    target = ("--test", test.target_name) if test.target_kind == "test" else ("--lib",)
    feature_arguments = (
        ("--features", "photokit-native")
        if (
            test.package == "wardrobe-platform"
            and (
                test.relative
                == "crates/wardrobe-platform/src/photokit_native.rs"
                or (
                    test.relative
                    == "crates/wardrobe-platform/tests/photokit_native_adapter.rs"
                    and test.name
                    == "production_adapter_uses_real_abi_and_transfers_descriptor_ownership"
                )
            )
        )
        else ()
    )
    runner_arguments = (
        ("--", "--exact", "--test-threads=1")
        if test.target_kind == "test"
        else ("--", "--test-threads=1")
    )
    return CommandCheck(
        name=f"focused_{test.package}_{test.name}",
        command=(
            "cargo",
            "test",
            "--offline",
            "-p",
            test.package,
            *feature_arguments,
            *target,
            test.name,
            *runner_arguments,
        ),
        require_rust_test=True,
    )


def _discover_live_runners(root: Path) -> tuple[Path, ...]:
    candidates: list[Path] = []
    for relative_root in ("tools", "scripts", "native/photokit/scripts"):
        directory = root / relative_root
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            name = path.name.lower().replace("-", "_")
            if (
                path.is_file()
                and path.suffix.lower() in {".py", ".sh"}
                and "p06" in name
                and "photokit" in name
                and ("live" in name or "smoke" in name)
                and path.name != "p06_photokit.py"
            ):
                candidates.append(path)
    return tuple(sorted(set(candidates)))


def _live_runner_check(root: Path) -> tuple[CommandCheck | None, list[str]]:
    errors: list[str] = []
    runners = _discover_live_runners(root)
    if len(runners) != 1:
        return None, [
            "exactly one checked-in P06 exact-package live PhotoKit runner is required"
        ]
    runner = runners[0]
    try:
        metadata = runner.lstat()
        text = runner.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None, ["P06 live PhotoKit runner is unreadable"]
    if runner.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        errors.append("P06 live PhotoKit runner is not a regular checked-in file")
    for marker in (
        LIVE_PREFIX.strip(),
        LIVE_CHALLENGE_ENV,
        "Wardrobe.app",
        "Info.plist",
        "codesign",
        "executable_sha256",
        "asset_not_in_scope",
        "startup_reconciled",
        "native_callbacks",
        "synthetic_decision_preserved",
    ):
        if marker not in text:
            errors.append(f"P06 live PhotoKit runner lacks required marker: {marker}")
    if errors:
        return None, errors
    relative = runner.relative_to(root).as_posix()
    command = (
        (sys.executable, relative)
        if runner.suffix.lower() == ".py"
        else ("/bin/bash", relative)
    )
    return CommandCheck("exact_package_live_photokit_smoke", command, live_smoke=True), []


def _focused_checks(
    tests: tuple[RustTest, ...],
    swift_test_files: tuple[str, ...],
    ui_test_files: tuple[str, ...],
) -> tuple[tuple[CommandCheck, ...], list[str]]:
    errors: list[str] = []
    relevant = tuple(test for test in tests if _is_photokit_test(test))
    for package, label in (
        ("wardrobe-core", "core"),
        ("wardrobe-platform", "platform"),
        ("wardrobe-desktop", "Tauri"),
    ):
        if not any(test.package == package for test in relevant):
            errors.append(f"focused compiled {label} PhotoKit tests are missing")

    coverage = "\n".join(test.body.lower() for test in relevant)
    for label, alternatives in (
        ("startup missed-change", ("startup", "missed", "asset_not_in_scope")),
        ("unavailable transitions", ("authorization", "scope", "icloud", "unavailable")),
        ("atomic fencing", ("atomic", "fence", "store_authority")),
        ("canonical preservation", ("canonical", "preserv", "decision")),
        ("deletion and restore", ("deletion", "restore", "key")),
        ("production native construction", ("production", "swift", "scripted")),
    ):
        if not all(marker in coverage for marker in alternatives):
            errors.append(f"focused compiled PhotoKit tests lack {label} coverage")

    if len(relevant) > MAX_FOCUSED_RUST_TESTS:
        errors.append("focused compiled PhotoKit Rust test inventory is unbounded")
        relevant = relevant[:MAX_FOCUSED_RUST_TESTS]
    if not swift_test_files:
        errors.append("focused compiled native Swift PhotoKit tests are missing")
    if not ui_test_files:
        errors.append("focused PhotoKit UI tests are missing")

    checks = [_rust_test_check(test) for test in relevant]
    if swift_test_files:
        checks.append(
            CommandCheck(
                "focused_native_swift_photokit",
                ("swift", "test", "--package-path", "native/photokit"),
            )
        )
    if ui_test_files:
        checks.append(
            CommandCheck(
                "focused_ui_photokit",
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
    return tuple(checks), errors


def validate_source(root: Path) -> SourceValidation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    decoded: dict[str, str] = {}
    total_bytes = 0
    source_paths = _source_paths(root)
    if len(source_paths) > MAX_SOURCE_FILES:
        errors.append("P06 PhotoKit source inventory exceeds file bound")
        source_paths = source_paths[:MAX_SOURCE_FILES]
    for relative in source_paths:
        data = _read_bounded(root / relative)
        if data is None:
            if relative in SOURCE_BASE_FILES:
                errors.append(
                    f"required P06 PhotoKit source is unreadable or oversized: {relative}"
                )
            continue
        total_bytes += len(data)
        if total_bytes > MAX_TOTAL_SOURCE_BYTES:
            errors.append("P06 PhotoKit source inventory exceeds byte bound")
            break
        contents[relative] = data
        try:
            decoded[relative] = data.decode()
        except UnicodeDecodeError:
            errors.append(f"P06 PhotoKit source is not UTF-8: {relative}")

    errors.extend(_marker_errors(decoded))
    migration_relative = (
        "crates/wardrobe-platform/migrations/0012_photokit_connector.sql"
    )
    checksum_relative = (
        "crates/wardrobe-platform/migrations/0012_photokit_connector.sha256"
    )
    migration_sha256 = _sha256(contents.get(migration_relative, b""))
    checksum = decoded.get(checksum_relative, "").strip()
    if not LOWER_SHA256.fullmatch(checksum) or checksum != migration_sha256:
        errors.append("P06 PhotoKit migration checksum is invalid")

    tests = _rust_tests(decoded)
    swift_test_files = tuple(
        sorted(
            relative
            for relative, text in decoded.items()
            if relative.startswith("native/photokit/Tests/")
            and relative.endswith(".swift")
            and ("func test" in text or "@Test" in text)
        )
    )
    ui_test_files = tuple(
        sorted(
            relative.removeprefix("apps/desktop-ui/")
            for relative, text in decoded.items()
            if relative.startswith("apps/desktop-ui/src/")
            and relative.endswith((".test.ts", ".test.tsx"))
            and "photokit" in text.lower()
        )
    )
    focused, focused_errors = _focused_checks(tests, swift_test_files, ui_test_files)
    errors.extend(focused_errors)
    live_check, live_errors = _live_runner_check(root)
    errors.extend(live_errors)

    hashes = {relative: _sha256(data) for relative, data in contents.items()}
    return SourceValidation(
        tuple(dict.fromkeys(errors)),
        _aggregate_hash(contents),
        hashes,
        len(contents),
        migration_sha256,
        focused,
        live_check,
        sum(1 for test in tests if _is_photokit_test(test)),
        len(swift_test_files),
        len(ui_test_files),
    )


def command_checks(source: SourceValidation) -> tuple[CommandCheck, ...]:
    if source.live_check is None:
        return source.focused_checks
    return (source.live_check, *source.focused_checks)


def _inspection_failure(result: CommandResult, label: str) -> str | None:
    if result.launch_failed:
        return f"{label} could not launch"
    if result.timed_out:
        return f"{label} timed out"
    if result.output_limit_exceeded:
        return f"{label} exceeded its output bound"
    if result.returncode != 0:
        return f"{label} failed"
    return None


def _designated_requirement_sha256(output: bytes) -> str:
    try:
        lines = []
        for raw_line in output.decode("utf-8").splitlines():
            line = raw_line.strip()
            if line.startswith("# "):
                line = line[2:]
            if line.startswith("designated =>"):
                lines.append(line)
    except UnicodeDecodeError:
        raise ValueError from None
    if len(lines) != 1:
        raise ValueError
    return _sha256(lines[0].encode())


def _evaluated_app_identity(
    root: Path,
    environment: dict[str, str],
) -> tuple[AppIdentity | None, dict[str, dict[str, Any]], list[str]]:
    bundle = root / "target" / "release" / "bundle" / "macos" / "Wardrobe.app"
    errors: list[str] = []
    checks: dict[str, dict[str, Any]] = {}
    try:
        bundle_metadata = bundle.lstat()
        if not stat.S_ISDIR(bundle_metadata.st_mode) or bundle.is_symlink():
            raise OSError
        info_path = bundle / "Contents" / "Info.plist"
        info_bytes = _read_regular_bounded(
            info_path, max_bytes=MAX_SOURCE_BYTES
        )
        info = plistlib.loads(info_bytes)
        if not isinstance(info, dict):
            raise ValueError
        bundle_id = info.get("CFBundleIdentifier")
        executable_name = info.get("CFBundleExecutable")
        if (
            bundle_id != EXPECTED_BUNDLE_ID
            or info.get("NSPhotoLibraryUsageDescription") != EXPECTED_USAGE
            or not isinstance(executable_name, str)
            or not executable_name
            or Path(executable_name).name != executable_name
        ):
            raise ValueError
        executable = bundle / "Contents" / "MacOS" / executable_name
        executable_metadata = executable.lstat()
        if (
            not stat.S_ISREG(executable_metadata.st_mode)
            or stat.S_ISLNK(executable_metadata.st_mode)
        ):
            raise OSError
        info_hash = _sha256(info_bytes)
        executable_hash = _file_sha256(executable, max_bytes=MAX_APP_BYTES)
        bundle_hash = _bundle_sha256(bundle)
    except (OSError, UnicodeError, ValueError, plistlib.InvalidFileException):
        return None, checks, ["evaluated Wardrobe.app package identity is invalid"]

    verify = run_bounded_command(
        [
            "/usr/bin/codesign",
            "--verify",
            "--deep",
            "--strict",
            "--verbose=4",
            str(bundle),
        ],
        cwd=root,
        env=environment,
        timeout_seconds=APP_INSPECTION_TIMEOUT_SECONDS,
        capture_output=False,
    )
    checks["strict_app_code_signature"] = _result_summary(verify)
    failure = _inspection_failure(verify, "strict Wardrobe.app code-signature verification")
    if failure is not None:
        errors.append(failure)

    requirement = run_bounded_command(
        ["/usr/bin/codesign", "-d", "-r-", str(bundle)],
        cwd=root,
        env=environment,
        timeout_seconds=APP_INSPECTION_TIMEOUT_SECONDS,
        capture_output=True,
    )
    checks["designated_app_requirement"] = _result_summary(requirement)
    failure = _inspection_failure(requirement, "Wardrobe.app designated requirement")
    requirement_hash = ""
    if failure is not None:
        errors.append(failure)
    else:
        try:
            requirement_hash = _designated_requirement_sha256(
                requirement.captured_output
            )
        except ValueError:
            errors.append("Wardrobe.app designated requirement is invalid")
    if errors:
        return None, checks, errors
    return (
        AppIdentity(
            bundle_id=bundle_id,
            info_plist_sha256=info_hash,
            executable_sha256=executable_hash,
            bundle_sha256=bundle_hash,
            designated_requirement_sha256=requirement_hash,
        ),
        checks,
        [],
    )


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


def _parse_live_record(output: bytes) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError:
        return None, ["P06 live PhotoKit evidence is not UTF-8"]
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0].startswith(LIVE_PREFIX):
        return None, ["P06 live PhotoKit evidence must be exactly one framed record"]
    try:
        value = json.loads(lines[0].removeprefix(LIVE_PREFIX))
    except json.JSONDecodeError:
        return None, ["P06 live PhotoKit evidence is malformed"]
    if not isinstance(value, dict):
        errors.append("P06 live PhotoKit evidence is not an object")
        return None, errors
    return value, errors


def _validate_live_record(
    record: dict[str, Any],
    *,
    nonce: str,
    packet_sha256: str,
    source_sha256: str,
    app_identity: AppIdentity,
) -> list[str]:
    errors: list[str] = []
    if set(record) != LIVE_RECORD_FIELDS:
        return ["P06 live PhotoKit evidence fields are not exact"]
    expected = {
        "schema_version": 1,
        "event": "exact_package_missed_change",
        "run_id": RUN_ID,
        "challenge_nonce": nonce,
        "packet_sha256": packet_sha256,
        "source_sha256": source_sha256,
        **app_identity.as_dict(),
        "exact_package": True,
        "same_package_relaunched": True,
        "fixture_sha256": list(P00_FIXTURE_HASHES),
        "native_callbacks": True,
        "tcc_authorized": True,
        "dedicated_fixture_album": True,
        "operator_removal_completed": True,
        "initial_complete_generation": True,
        "startup_reconciled": True,
        "asset_not_in_scope_delta": 1,
        "available_before": 2,
        "unavailable_after": 1,
        "blob_count_before": 2,
        "blob_count_after": 2,
        "synthetic_decision_preserved": True,
        "raw_identifiers_emitted": False,
        "personal_metadata_emitted": False,
    }
    for field, expected_value in expected.items():
        if type(record.get(field)) is not type(expected_value) or record.get(field) != expected_value:
            errors.append(f"P06 live PhotoKit evidence field is invalid: {field}")
    for field in ("membership_generation_delta", "photokit_revision_delta"):
        value = record.get(field)
        if type(value) is not int or not 1 <= value <= 1_000_000:
            errors.append(f"P06 live PhotoKit revision delta is invalid: {field}")
    return list(dict.fromkeys(errors))


def _command_errors(
    check: CommandCheck,
    result: CommandResult,
    *,
    nonce: str,
    packet_sha256: str,
    source_sha256: str,
    app_identity: AppIdentity,
) -> list[str]:
    if result.launch_failed:
        return [f"{check.name} could not launch"]
    if result.timed_out:
        return [f"{check.name} timed out"]
    if result.output_limit_exceeded:
        return [f"{check.name} exceeded its output bound"]
    if result.returncode != 0:
        return [f"{check.name} failed"]
    if check.require_rust_test:
        output = result.captured_output.decode("utf-8", errors="replace")
        counts = [
            int(value) for value in re.findall(r"\brunning\s+(\d+)\s+tests?\b", output)
        ]
        if not counts or sum(counts) != 1:
            return [f"{check.name} must execute exactly one compiled Rust test"]
    if check.live_smoke:
        record, errors = _parse_live_record(result.captured_output)
        if record is not None:
            errors.extend(
                _validate_live_record(
                    record,
                    nonce=nonce,
                    packet_sha256=packet_sha256,
                    source_sha256=source_sha256,
                    app_identity=app_identity,
                )
            )
        return errors
    return []


def _bounded_json_bytes(value: dict[str, Any]) -> bytes:
    data = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P06 PhotoKit evaluator artifact exceeds size limit")
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
    return _sha256(
        _bounded_json_bytes(
            {
                "requirement_id": requirement,
                "packet_sha256": packet.packet_sha256,
                "source_sha256": source.source_sha256,
                "migration_sha256": source.migration_sha256,
                "checks": checks,
            }
        )
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
    app_identity: AppIdentity | None = None
    failures = list(packet.errors)
    checks: dict[str, dict[str, Any]] = {}
    live_smoke_count = 0

    if requested != REQUIREMENT_IDS:
        failures.append("selected P06 PhotoKit requirement set is incomplete")
    if not failures:
        source = validate_source(root)
        failures.extend(source.errors)

    environment = os.environ.copy()
    for name in (
        "HARNESS_RUN_DIR",
        "HARNESS_EVIDENCE_DIR",
        "OPENAI_API_KEY",
        LIVE_CHALLENGE_ENV,
    ):
        environment.pop(name, None)
    if not failures and source is not None:
        app_identity, identity_checks, identity_errors = _evaluated_app_identity(
            root, environment
        )
        checks.update(identity_checks)
        failures.extend(identity_errors)

    nonce = secrets.token_hex(32)
    if not failures and source is not None and app_identity is not None:
        environment[LIVE_CHALLENGE_ENV] = json.dumps(
            {
                "schema_version": 1,
                "run_id": RUN_ID,
                "challenge_nonce": nonce,
                "packet_sha256": packet.packet_sha256,
                "source_sha256": source.source_sha256,
                "fixture_sha256": list(P00_FIXTURE_HASHES),
                **app_identity.as_dict(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        for check in command_checks(source):
            result = run_bounded_command(
                list(check.command),
                cwd=root,
                env=environment,
                timeout_seconds=(
                    LIVE_TIMEOUT_SECONDS if check.live_smoke else COMMAND_TIMEOUT_SECONDS
                ),
                capture_output=check.require_rust_test or check.live_smoke,
            )
            checks[check.name] = _result_summary(result)
            command_failures = _command_errors(
                check,
                result,
                nonce=nonce,
                packet_sha256=packet.packet_sha256,
                source_sha256=source.source_sha256,
                app_identity=app_identity,
            )
            if command_failures:
                failures.extend(command_failures)
                break
            live_smoke_count += int(check.live_smoke)
    if not failures and live_smoke_count != 1:
        failures.append("exactly one exact-package live PhotoKit smoke must execute")

    diagnostics = {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "recorded_at": recorded_at,
        "selected_requirement_ids": sorted(requested),
        "failures": list(dict.fromkeys(failures)),
        "packet_sha256": packet.packet_sha256,
        "packet_hashes": packet.hashes,
        "source_sha256": source.source_sha256 if source else "",
        "source_hashes": source.source_hashes if source else {},
        "source_file_count": source.source_file_count if source else 0,
        "migration_sha256": source.migration_sha256 if source else "",
        "focused_rust_test_count": source.rust_test_count if source else 0,
        "swift_test_file_count": source.swift_test_file_count if source else 0,
        "ui_test_file_count": source.ui_test_file_count if source else 0,
        "checks": checks,
        "exact_package_live_smoke_count": live_smoke_count,
        "real_native_callbacks": live_smoke_count == 1 and not failures,
        "scripted_native_live_smoke": False,
        "developer_id_signed": False,
        "notarized": False,
        "clean_machine_certified": False,
        "pass_evidence_written": not failures,
    }
    if failures or source is None:
        _write_bounded_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    payloads: dict[str, dict[str, Any]] = {}
    for requirement in sorted(REQUIREMENT_IDS):
        payload = {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": "pass",
            "test": "p06_photokit::focused_and_exact_package_live_verification",
            "recorded_at": recorded_at,
            "details": {
                "checks_passed": len(checks),
                "exact_package_live_smoke": True,
                "verification_sha256": _verification_hash(
                    requirement, packet, source, checks
                ),
                "public_summary": {
                    "profile": "personal_mvp",
                    "packet_sha256": packet.packet_sha256,
                    "source_sha256": source.source_sha256,
                    "migration_sha256": source.migration_sha256,
                    "focused_rust_test_count": source.rust_test_count,
                    "swift_test_file_count": source.swift_test_file_count,
                    "ui_test_file_count": source.ui_test_file_count,
                    "exact_package_live_smoke": True,
                    "real_native_callbacks": True,
                    "startup_missed_change_verified": True,
                    "unavailable_preserves_canonical_state": True,
                    "scripted_native_live_smoke": False,
                    "developer_id_signed": False,
                    "notarized": False,
                    "clean_machine_certified": False,
                    "acceptance_claim": "focused_and_live_requirement_passed",
                },
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


if __name__ == "__main__":
    raise SystemExit(2)
