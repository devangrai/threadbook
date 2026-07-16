"""Fail-closed disabled-feature evaluator for P06 Google Photos Picker."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from tools.evaluators.p03_receipts import write_atomic_json
from tools.evaluators.p06_photokit import AppIdentity, _evaluated_app_identity


REQUIREMENT_IDS = frozenset({"P06-GPH-001"})
RUN_ID = "20260716T120148Z-a5f92440"
PACKET_DIR = Path("artifacts/harness/P06") / RUN_ID
STATE_FILE = PACKET_DIR / "state.json"
DIAGNOSTICS_NAME = "p06-google-photos-diagnostics.json"
MAX_SOURCE_FILES = 512
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
MAX_APP_FILES = 4096
MAX_APP_FILE_BYTES = 512 * 1024 * 1024
MAX_APP_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P06-connectors.md": (
        "bf9c3e727015e0e1a9eb2f27655a8b263997d7f06cbf9e63753fe3cb42792f19"
    ),
    str(PACKET_DIR / "requirements.json"): (
        "2085e9a73587281cf1155dc8f037ab7c55f2119dc91db83338ea158efdaec490"
    ),
    str(PACKET_DIR / "proposal.md"): (
        "e1c32e83486053bd5721802dc79566935669b7f4c9e857cf62d3a27517a5ba3e"
    ),
    str(PACKET_DIR / "review.md"): (
        "73ff6673d8f318ce201a0230ba7570073fffa4a3337a741e2e2cfd2f4d3fb447"
    ),
}

EXPECTED_COMMANDS = (
    "get_foundation_snapshot_v1",
    "set_local_only_v1",
    "run_storage_check_v1",
    "create_backup_v1",
    "list_backups_v1",
    "prepare_restore_v1",
    "save_credential_v1",
    "delete_credential_v1",
    "import_local_sources_v1",
    "refresh_import_roots_v1",
    "list_catalog_v1",
    "list_inbox_v1",
    "create_manual_outfit_v1",
    "list_outfits_v1",
    "get_outfit_collage_v1",
    "preview_outfit_recommendation_v1",
    "request_outfit_recommendation_v1",
    "list_try_on_portrait_candidates_v1",
    "preview_try_on_v1",
    "submit_try_on_v1",
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
    "approve_and_fetch_receipt_image_v1",
    "list_imported_photo_roots_v1",
    "create_photo_scope_v1",
    "detect_photo_scope_people_v1",
    "list_photo_owner_reviews_v1",
    "read_photo_owner_preview_v1",
    "decide_photo_owner_v1",
    "correct_photo_owner_v1",
    "correct_photo_person_detection_v1",
    "retry_photo_person_detection_v1",
    "analyze_photo_scope_v1",
    "list_photo_observations_v1",
    "read_photo_artifact_v1",
    "prompt_photo_observation_v1",
    "review_photo_observation_v1",
    "open_reconciliation_case_v1",
    "decide_reconciliation_case_v1",
    "open_reconciliation_case_v2",
    "decide_reconciliation_case_v2",
    "list_reconciliation_cases_v2",
    "get_gmail_connector_v1",
    "save_gmail_settings_v1",
    "connect_gmail_v1",
    "sync_gmail_v1",
    "disconnect_gmail_v1",
    "get_photokit_connector_v1",
    "begin_photokit_setup_v1",
    "configure_photokit_scope_v1",
    "sync_photokit_v1",
    "disable_photokit_v1",
    "export_diagnostics_v1",
)
EXPECTED_OUTBOUND_CAPABILITIES = (
    "GmailAuthorize",
    "GmailSync",
    "GmailRevoke",
    "ReceiptImageFetch",
    "PhotoKitMaterialize",
    "OpenAiRecommendation",
    "OpenAiTryOn",
)
EXPECTED_VIEWS = (
    "wardrobe",
    "inbox",
    "receipts",
    "photos",
    "outfits",
    "activity",
    "settings",
)
EXPECTED_SOURCE_KINDS = (
    "photo_folder",
    "image_file",
    "eml_file",
    "mbox_file",
    "mbox_message",
    "mime_part",
)
EXPECTED_RELEASE_VARIABLES = (
    "WARDROBE_REMOTE_RECOMMENDATIONS_RELEASE",
    "WARDROBE_TRY_ON_RELEASE",
    "VITE_WARDROBE_REMOTE_RECOMMENDATIONS_RELEASE",
    "VITE_WARDROBE_TRY_ON_RELEASE",
)
EXPECTED_DIALOG_PERMISSIONS = ("dialog:allow-open", "dialog:allow-save")

REQUIRED_SOURCE_FILES = (
    "Makefile",
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "crates/wardrobe-core/src/catalog.rs",
    "crates/wardrobe-core/src/contracts.rs",
    "src-tauri/Cargo.toml",
    "src-tauri/src/lib.rs",
    "src-tauri/src/local_only.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/src/App.tsx",
    "apps/desktop-ui/src/OutfitsWorkspace.tsx",
    "apps/desktop-ui/src/generated/contracts.ts",
)
SOURCE_ROOTS = (
    "crates/wardrobe-core/src",
    "crates/wardrobe-platform/src",
    "crates/wardrobe-platform/migrations",
    "src-tauri/src",
    "src-tauri/permissions",
    "apps/desktop-ui/src",
)
SOURCE_SUFFIXES = frozenset(
    {".rs", ".sql", ".json", ".toml", ".ts", ".tsx", ".lock"}
)
FORBIDDEN_MARKERS = (
    re.compile(rb"google[\s_-]*photos", re.IGNORECASE),
    re.compile(rb"googlephotos", re.IGNORECASE),
    re.compile(rb"photoslibrary\.googleapis\.com", re.IGNORECASE),
    re.compile(rb"photos[\s_-]*picker", re.IGNORECASE),
)


@dataclass(frozen=True)
class PacketValidation:
    errors: tuple[str, ...]
    packet_sha256: str


@dataclass(frozen=True)
class SourceValidation:
    errors: tuple[str, ...]
    source_sha256: str
    source_file_count: int


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, *, max_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise ValueError("unsafe or oversized file")
        data = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, max_bytes + 1)):
            data.extend(chunk)
            if len(data) > max_bytes:
                raise ValueError("oversized file")
        if len(data) != metadata.st_size:
            raise ValueError("file changed while reading")
        return bytes(data)
    finally:
        os.close(descriptor)


def _aggregate(contents: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for relative, data in sorted(contents.items()):
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def _json_object(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def validate_packet(root: Path) -> PacketValidation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    for relative, expected in EXPECTED_PACKET_HASHES.items():
        try:
            data = _read_regular(root / relative, max_bytes=MAX_SOURCE_BYTES)
        except (OSError, ValueError):
            errors.append(f"frozen packet file is unreadable: {relative}")
            continue
        contents[relative] = data
        if _sha256(data) != expected:
            errors.append(f"frozen packet hash changed: {relative}")

    requirements = _json_object(
        contents.get(str(PACKET_DIR / "requirements.json"), b"")
    )
    rows = requirements.get("requirements")
    selected = requirements.get("selected_requirement_ids")
    evidenced = {
        row.get("id")
        for row in rows
        if isinstance(row, dict) and row.get("evidence_required") is True
    } if isinstance(rows, list) else set()
    if (
        requirements.get("phase") != "P06"
        or not isinstance(selected, list)
        or set(selected) != REQUIREMENT_IDS
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("frozen Google Photos packet selection is invalid")

    try:
        state = _json_object(
            _read_regular(root / STATE_FILE, max_bytes=MAX_SOURCE_BYTES)
        )
    except (OSError, ValueError):
        state = {}
    review = state.get("review") if isinstance(state.get("review"), dict) else {}
    spec_hashes = (
        state.get("spec_hashes")
        if isinstance(state.get("spec_hashes"), dict)
        else {}
    )
    if (
        state.get("run_id") != RUN_ID
        or state.get("phase") != "P06"
        or state.get("status")
        not in {
            "APPROVED",
            "BUILD_FAILED",
            "BUILT",
            "EVALUATED",
            "EVALUATION_FAILED",
        }
        or set(state.get("selected_requirement_ids", [])) != REQUIREMENT_IDS
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash")
        != EXPECTED_PACKET_HASHES[str(PACKET_DIR / "proposal.md")]
        or spec_hashes.get("specs/system.md")
        != EXPECTED_PACKET_HASHES["specs/system.md"]
        or spec_hashes.get("specs/phases/P06-connectors.md")
        != EXPECTED_PACKET_HASHES["specs/phases/P06-connectors.md"]
    ):
        errors.append("Google Photos packet approval state is invalid")
    review = contents.get(str(PACKET_DIR / "review.md"), b"")
    if b"Status: APPROVED" not in review or b"\nAPPROVE\n" not in review:
        errors.append("Google Photos independent review approval is missing")
    return PacketValidation(tuple(dict.fromkeys(errors)), _aggregate(contents))


def _source_paths(root: Path) -> tuple[str, ...]:
    paths = set(REQUIRED_SOURCE_FILES)
    for relative_root in SOURCE_ROOTS:
        directory = root / relative_root
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if (
                path.is_file()
                and not path.name.endswith((".test.ts", ".test.tsx"))
                and path.suffix.lower() in SOURCE_SUFFIXES
            ):
                paths.add(path.relative_to(root).as_posix())
    return tuple(sorted(paths))


def _between(text: str, start: str, end: str) -> str:
    if text.count(start) != 1:
        return ""
    suffix = text.split(start, 1)[1]
    if suffix.count(end) < 1:
        return ""
    return suffix.split(end, 1)[0]


def _structural_errors(decoded: dict[str, str]) -> list[str]:
    errors: list[str] = []
    desktop = decoded.get("src-tauri/src/lib.rs", "")
    local_only = decoded.get("src-tauri/src/local_only.rs", "")
    app = decoded.get("apps/desktop-ui/src/App.tsx", "")
    contracts = decoded.get("apps/desktop-ui/src/generated/contracts.ts", "")
    makefile = decoded.get("Makefile", "")

    handler = _between(desktop, "tauri::generate_handler![", "])")
    commands = tuple(
        re.findall(r"(?m)^\s*([a-z][a-z0-9_]+),?\s*$", handler)
    )
    if commands != EXPECTED_COMMANDS:
        errors.append("production command registry is not exact")

    classifier = _between(
        desktop,
        "fn classify_command(name: &str)",
        "fn acquire_command_authority(",
    )
    classified = {
        value
        for value in re.findall(r'"([a-z][a-z0-9_]+)"', classifier)
        if value.endswith(("_v1", "_v2"))
    }
    if classified != set(EXPECTED_COMMANDS):
        errors.append("command network classification is not exact")

    capability_body = _between(
        local_only,
        "enum OutboundCapability {",
        "}",
    )
    capabilities = tuple(
        re.findall(r"(?m)^\s*([A-Z][A-Za-z0-9]+),\s*$", capability_body)
    )
    if capabilities != EXPECTED_OUTBOUND_CAPABILITIES:
        errors.append("outbound capability registry is not exact")

    try:
        capability = json.loads(
            decoded.get("src-tauri/capabilities/main.json", "")
        )
    except json.JSONDecodeError:
        capability = {}
    permissions = capability.get("permissions")
    expected_permissions = {
        "allow-" + command.replace("_", "-") for command in EXPECTED_COMMANDS
    } | set(EXPECTED_DIALOG_PERMISSIONS)
    if (
        not isinstance(permissions, list)
        or len(permissions) != len(set(permissions))
        or set(permissions) != expected_permissions
    ):
        errors.append("Tauri permission registry is not exact")

    views_body = _between(
        app,
        "const views: ReadonlyArray<{ id: View; label: string }> = [",
        "];",
    )
    views = tuple(re.findall(r'\{\s*id:\s*"([^"]+)"', views_body))
    if views != EXPECTED_VIEWS:
        errors.append("desktop navigation registry is not exact")

    source_kind = re.search(
        r'export type ImportSourceKindV1 = ([^;]+);',
        contracts,
    )
    source_kinds = tuple(
        re.findall(r'"([^"]+)"', source_kind.group(1))
        if source_kind
        else ()
    )
    if source_kinds != EXPECTED_SOURCE_KINDS:
        errors.append("import source-kind registry is not exact")

    rust_gates = set(
        re.findall(r'option_env!\("([A-Z][A-Z0-9_]+)"\)', "\n".join(decoded.values()))
    )
    vite_gates = {
        value
        for value in re.findall(
            r'import\.meta\.env\.([A-Z][A-Z0-9_]+)',
            "\n".join(decoded.values()),
        )
        if "WARDROBE" in value
    }
    if rust_gates | vite_gates != set(EXPECTED_RELEASE_VARIABLES):
        errors.append("compile-time release-variable registry is not exact")
    for variable in EXPECTED_RELEASE_VARIABLES:
        if f"-u {variable}" not in makefile:
            errors.append(f"production build does not scrub release variable: {variable}")
    return errors


def validate_source(root: Path) -> SourceValidation:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    total = 0
    paths = _source_paths(root)
    if len(paths) > MAX_SOURCE_FILES:
        errors.append("production source inventory is unbounded")
        paths = paths[:MAX_SOURCE_FILES]
    for relative in paths:
        path = root / relative
        if any(pattern.search(relative.encode()) for pattern in FORBIDDEN_MARKERS):
            errors.append(f"Google Photos production path is present: {relative}")
        try:
            data = _read_regular(path, max_bytes=MAX_SOURCE_BYTES)
        except (OSError, ValueError):
            errors.append(f"production source is unreadable: {relative}")
            continue
        total += len(data)
        if total > MAX_TOTAL_SOURCE_BYTES:
            errors.append("production source bytes are unbounded")
            break
        contents[relative] = data
        if any(pattern.search(data) for pattern in FORBIDDEN_MARKERS):
            errors.append(f"Google Photos production marker is present: {relative}")

    decoded: dict[str, str] = {}
    for relative, data in contents.items():
        try:
            decoded[relative] = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"production source is not UTF-8: {relative}")
    errors.extend(_structural_errors(decoded))
    return SourceValidation(
        tuple(dict.fromkeys(errors)),
        _aggregate(contents),
        len(contents),
    )


def inspect_package(root: Path) -> tuple[AppIdentity | None, dict[str, Any], list[str]]:
    environment = os.environ.copy()
    for variable in EXPECTED_RELEASE_VARIABLES:
        environment.pop(variable, None)
    identity, checks, errors = _evaluated_app_identity(root, environment)
    app = root / "target/release/bundle/macos/Wardrobe.app"
    file_count = 0
    total = 0
    command_hits: set[str] = set()
    if not errors and identity is not None:
        try:
            for path in sorted(app.rglob("*")):
                metadata = path.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    continue
                if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    errors.append("Wardrobe.app contains an unsafe non-regular file")
                    break
                file_count += 1
                if file_count > MAX_APP_FILES:
                    errors.append("Wardrobe.app file inventory is unbounded")
                    break
                relative = path.relative_to(app).as_posix()
                if any(pattern.search(relative.encode()) for pattern in FORBIDDEN_MARKERS):
                    errors.append("Wardrobe.app contains a Google Photos path marker")
                    break
                data = _read_regular(path, max_bytes=MAX_APP_FILE_BYTES)
                total += len(data)
                if total > MAX_APP_BYTES:
                    errors.append("Wardrobe.app bytes are unbounded")
                    break
                if any(pattern.search(data) for pattern in FORBIDDEN_MARKERS):
                    errors.append("Wardrobe.app contains a Google Photos content marker")
                    break
                command_hits.update(
                    command for command in EXPECTED_COMMANDS if command.encode() in data
                )
        except (OSError, ValueError):
            errors.append("Wardrobe.app bounded inspection failed")
    if identity is not None and command_hits != set(EXPECTED_COMMANDS):
        errors.append("Wardrobe.app command surface is not exact")
    summary = {
        "identity_checks": checks,
        "app_file_count": file_count,
        "app_bytes": total,
        "packaged_command_count": len(command_hits),
    }
    return identity, summary, list(dict.fromkeys(errors))


def _bounded_json(value: dict[str, Any]) -> None:
    data = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("Google Photos evaluator artifact exceeds size limit")


def _remove_stale(evidence_dir: Path) -> None:
    for name in (f"{next(iter(REQUIREMENT_IDS))}.json", DIAGNOSTICS_NAME):
        (evidence_dir / name).unlink(missing_ok=True)
        for temporary in evidence_dir.glob(f".{name}.*.tmp"):
            temporary.unlink(missing_ok=True)


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0
    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale(evidence_dir)
    recorded_at = utc_now()
    packet = validate_packet(root)
    source = validate_source(root)
    identity, package, package_errors = inspect_package(root)
    failures = [*packet.errors, *source.errors, *package_errors]

    diagnostics = {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "recorded_at": recorded_at,
        "selected_requirement_ids": sorted(requested),
        "failures": list(dict.fromkeys(failures)),
        "packet_sha256": packet.packet_sha256,
        "source_sha256": source.source_sha256,
        "source_file_count": source.source_file_count,
        "app_identity": identity.as_dict() if identity else {},
        "package": package,
        "feature_enabled": False,
        "pass_evidence_written": False,
    }
    _bounded_json(diagnostics)
    if failures or identity is None:
        write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    limitation = (
        "Google Photos Picker integration, immutable import-batch "
        "materialization, and expired-URL verification are not implemented."
    )
    requirement = next(iter(REQUIREMENT_IDS))
    payload = {
        "schema_version": 1,
        "requirement_id": requirement,
        "status": "deferred",
        "test": "p06_google_photos::disabled_exact_package_verification",
        "recorded_at": recorded_at,
        "details": {
            "verification_sha256": _sha256(
                json.dumps(
                    {
                        "packet_sha256": packet.packet_sha256,
                        "source_sha256": source.source_sha256,
                        "app_identity": identity.as_dict(),
                        "package": package,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ),
            "public_summary": {
                "profile": "personal_mvp",
                "feature_enabled": False,
                "google_photos_picker_enabled": False,
                "acceptance_claim": "deferred_not_passed",
                "deferred_limitation": limitation,
                "exact_package_inspected": True,
                "production_commands": len(EXPECTED_COMMANDS),
            },
        },
    }
    _bounded_json(payload)
    written: list[Path] = []
    try:
        path = evidence_dir / f"{requirement}.json"
        write_atomic_json(path, payload)
        written.append(path)
        write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
    except BaseException:
        for path in written:
            path.unlink(missing_ok=True)
        (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)
        raise
    return 0
