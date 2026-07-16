"""Fail-closed evaluator for the approved P04 photo-analysis vertical."""

from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib
from typing import Any

from tools.evaluators.p03_receipts import (
    CommandResult,
    run_bounded_command,
    write_atomic_json,
)


REQUIREMENT_IDS = frozenset(
    {
        "P04-SCP-001",
        "P04-SEG-001",
        "P04-SEG-002",
        "P04-ART-001",
    }
)
RUN_ID = "20260715T045533Z-a1466b2b"
PACKET_DIR = f"artifacts/harness/P04/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p04-photo-analysis-diagnostics.json"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 96 * 1024
COMMAND_TIMEOUT_SECONDS = 10 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546",
    "specs/phases/P04-photo-analysis.md": (
        "3fb58a5c42f5c15763d31fe629aafeaba58117b03550ad1742bc939db1d25390"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "3b15b114a5f9aafbcdb7a506a27854f08f3243164eaddfd5de5de3a2e2adb22b"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "bf126b7fe0ec98eaa13c43b77251706f02f14000496ae524e0eab5e735a72164"
    ),
    f"{PACKET_DIR}/review.md": (
        "251b191da117684a1902bb37a9389668aa90444400f7bcb9790f36e3fe5a8559"
    ),
}

PHOTO_COMMANDS = (
    "list_imported_photo_roots_v1",
    "create_photo_scope_v1",
    "analyze_photo_scope_v1",
    "list_photo_observations_v1",
    "read_photo_artifact_v1",
    "prompt_photo_observation_v1",
    "review_photo_observation_v1",
)

SOURCE_FILES = (
    "Cargo.lock",
    "crates/wardrobe-core/Cargo.toml",
    "crates/wardrobe-core/src/lib.rs",
    "crates/wardrobe-core/src/photo_analysis.rs",
    "crates/wardrobe-core/src/ports.rs",
    "crates/wardrobe-core/src/service.rs",
    "crates/wardrobe-core/src/bindings.rs",
    "crates/wardrobe-core/src/bin/generate-bindings.rs",
    "crates/wardrobe-core/tests/photo_analysis_contracts.rs",
    "crates/wardrobe-core/tests/photo_analysis_provider.rs",
    "crates/wardrobe-core/tests/photo_analysis_service.rs",
    "crates/wardrobe-platform/Cargo.toml",
    "crates/wardrobe-platform/src/lib.rs",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/photo_repository.rs",
    "crates/wardrobe-platform/src/source_image.rs",
    "crates/wardrobe-platform/migrations/0005_photo_analysis.sql",
    "crates/wardrobe-platform/migrations/0005_photo_analysis.sha256",
    "src-tauri/Cargo.toml",
    "src-tauri/src/lib.rs",
    "src-tauri/build.rs",
    "src-tauri/capabilities/main.json",
    "apps/desktop-ui/package.json",
    "apps/desktop-ui/vite.config.ts",
    "apps/desktop-ui/playwright.config.ts",
    "apps/desktop-ui/scripts/check-production-transport.mjs",
    "apps/desktop-ui/src/generated/contracts.ts",
    "apps/desktop-ui/src/invoke-transport.ts",
    "apps/desktop-ui/src/e2e/invoke-transport.ts",
    "apps/desktop-ui/src/photo-analysis-bridge.ts",
    "apps/desktop-ui/src/photo-analysis-model.ts",
    "apps/desktop-ui/src/PhotoAnalysisWorkspace.tsx",
    "apps/desktop-ui/src/photo-analysis-bridge.test.ts",
    "apps/desktop-ui/src/photo-analysis-model.test.ts",
    "apps/desktop-ui/src/PhotoAnalysisWorkspace.test.tsx",
    "apps/desktop-ui/src/App.tsx",
    "apps/desktop-ui/e2e/photo-analysis.spec.ts",
)

PRODUCTION_PHOTO_FILES = (
    "crates/wardrobe-core/src/photo_analysis.rs",
    "crates/wardrobe-platform/src/photo_repository.rs",
    "crates/wardrobe-platform/src/source_image.rs",
    "apps/desktop-ui/src/photo-analysis-bridge.ts",
    "apps/desktop-ui/src/photo-analysis-model.ts",
    "apps/desktop-ui/src/PhotoAnalysisWorkspace.tsx",
)


@dataclass(frozen=True)
class CommandCheck:
    name: str
    command: tuple[str, ...]
    require_rust_test: bool = False


COMMAND_CHECKS = (
    CommandCheck(
        "core_photo_analysis_contracts",
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
    ),
    CommandCheck(
        "migration_v5_matrix",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "--lib",
            "database::tests",
        ),
    ),
    CommandCheck(
        "platform_photo_repository",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-platform",
            "photo_",
        ),
        require_rust_test=True,
    ),
    CommandCheck(
        "desktop_photo_analysis",
        (
            "cargo",
            "test",
            "--offline",
            "-p",
            "wardrobe-desktop",
            "photo_",
        ),
        require_rust_test=True,
    ),
    CommandCheck(
        "photo_bindings_drift",
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
        "ui_photo_analysis",
        (
            "npm",
            "--workspace",
            "@wardrobe/desktop-ui",
            "test",
            "--",
            "src/photo-analysis-bridge.test.ts",
            "src/photo-analysis-model.test.ts",
            "src/PhotoAnalysisWorkspace.test.tsx",
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
        "photo_analysis_playwright",
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
    production_provider_wired: bool
    automatic_masks_disabled: bool
    production_network_free: bool
    production_transport_isolated: bool
    playwright_specs: tuple[str, ...]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _read_bounded(path: Path) -> bytes | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_SOURCE_BYTES + 1)
    except OSError:
        return None
    return data if len(data) <= MAX_SOURCE_BYTES else None


def _json_object(data: bytes | str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _toml_object(text: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def validate_packet(root: Path) -> PacketValidation:
    errors: list[str] = []
    hashes: dict[str, str] = {}
    aggregate = hashlib.sha256()
    contents: dict[str, bytes] = {}
    for relative, expected_hash in EXPECTED_PACKET_HASHES.items():
        data = _read_bounded(root / relative)
        if data is None:
            errors.append(f"frozen packet file is unreadable or oversized: {relative}")
            continue
        actual_hash = hashlib.sha256(data).hexdigest()
        hashes[relative] = actual_hash
        contents[relative] = data
        if actual_hash != expected_hash:
            errors.append(f"frozen packet hash changed: {relative}")
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(data)
        aggregate.update(b"\0")
    state_data = _read_bounded(root / STATE_FILE)
    if state_data is None:
        errors.append(f"mutable harness state is unreadable or oversized: {STATE_FILE}")
    else:
        hashes[STATE_FILE] = hashlib.sha256(state_data).hexdigest()
        contents[STATE_FILE] = state_data

    requirements = _json_object(
        contents.get(f"{PACKET_DIR}/requirements.json", b"")
    )
    state = _json_object(contents.get(STATE_FILE, b""))
    selected = requirements.get("selected_requirement_ids")
    requirement_rows = requirements.get("requirements")
    evidenced = {
        row.get("id")
        for row in requirement_rows
        if isinstance(row, dict) and row.get("evidence_required") is True
    } if isinstance(requirement_rows, list) else set()
    if (
        requirements.get("phase") != "P04"
        or requirements.get("git_revision")
        != "8a8d99f2f6313a11d12cc1aefcf45dd2789614f8"
        or not isinstance(selected, list)
        or set(selected) != REQUIREMENT_IDS
        or len(selected) != len(REQUIREMENT_IDS)
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("frozen P04 requirement selection is invalid")

    review = state.get("review")
    spec_hashes = state.get("spec_hashes")
    if (
        state.get("phase") != "P04"
        or state.get("run_id") != RUN_ID
        or state.get("status") not in {"APPROVED", "BUILT", "EVALUATED"}
        or state.get("selected_requirement_ids") != selected
        or not isinstance(review, dict)
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash")
        != EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"]
        or not isinstance(review.get("reviewer"), str)
        or not review.get("reviewer")
        or spec_hashes
        != {
            "specs/phases/P04-photo-analysis.md": EXPECTED_PACKET_HASHES[
                "specs/phases/P04-photo-analysis.md"
            ],
            "specs/system.md": EXPECTED_PACKET_HASHES["specs/system.md"],
        }
    ):
        errors.append("approved P04 state or independent review is invalid")
    if state.get("status") in {"BUILT", "EVALUATED"}:
        build = state.get("build")
        if (
            not isinstance(build, dict)
            or build.get("exit_code") != 0
            or not isinstance(build.get("source_fingerprint"), str)
            or len(build.get("source_fingerprint", "")) != 64
        ):
            errors.append("P04 harness build record is missing or invalid")

    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(
        "utf-8", errors="replace"
    )
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append("approved P04 review decision is missing")

    return PacketValidation(
        errors=tuple(dict.fromkeys(errors)),
        packet_sha256=aggregate.hexdigest(),
        hashes=hashes,
    )


def _read_sources(root: Path) -> tuple[dict[str, bytes], list[str], str]:
    sources: dict[str, bytes] = {}
    errors: list[str] = []
    digest = hashlib.sha256()
    for relative in SOURCE_FILES:
        data = _read_bounded(root / relative)
        if data is None:
            errors.append(f"required P04 file is unreadable or oversized: {relative}")
            continue
        sources[relative] = data
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return sources, errors, digest.hexdigest()


def _text(sources: dict[str, bytes], relative: str) -> str:
    try:
        return sources[relative].decode("utf-8")
    except (KeyError, UnicodeDecodeError):
        return ""


def _block(text: str, start: str, end: str) -> str:
    start_index = text.find(start)
    if start_index < 0:
        return ""
    end_index = text.find(end, start_index + len(start))
    return text[start_index:] if end_index < 0 else text[start_index:end_index]


def _dependency_names(manifest: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    dependencies = manifest.get("dependencies")
    if isinstance(dependencies, dict):
        names.update(str(name).lower() for name in dependencies)
    targets = manifest.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            dependencies = target.get("dependencies")
            if isinstance(dependencies, dict):
                names.update(str(name).lower() for name in dependencies)
    return names


def _automatic_approval_files(root: Path) -> tuple[list[Path], bool]:
    matches: list[Path] = []
    valid = True
    for base in ("crates", "src-tauri", "apps/desktop-ui"):
        directory = root / base
        if not directory.is_dir():
            continue
        try:
            candidates = directory.rglob("*")
            for path in candidates:
                if any(
                    part in {"node_modules", "target", "dist", "test-results"}
                    for part in path.parts
                ):
                    continue
                lowered = path.name.lower()
                if not path.is_file() or "approval" not in lowered:
                    continue
                if "mask" not in lowered and "segment" not in lowered:
                    continue
                matches.append(path)
                data = _read_bounded(path)
                if data is None:
                    valid = False
                    continue
                if path.suffix == ".json":
                    value: Any
                    try:
                        value = json.loads(data)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        valid = False
                        continue
                    valid = valid and value in ({}, [], {"approvals": []})
                else:
                    text = data.decode("utf-8", errors="replace")
                    valid = valid and not re.search(
                        r"(?i)(approved|enabled)\s*[:=]\s*(true|1)", text
                    )
        except OSError:
            valid = False
    return matches, valid


def validate_source_contract(root: Path) -> SourceValidation:
    sources, errors, source_sha256 = _read_sources(root)
    photo = _text(sources, "crates/wardrobe-core/src/photo_analysis.rs")
    ports = _text(sources, "crates/wardrobe-core/src/ports.rs")
    service = _text(sources, "crates/wardrobe-core/src/service.rs")
    bindings = _text(sources, "crates/wardrobe-core/src/bindings.rs")
    generator = _text(
        sources, "crates/wardrobe-core/src/bin/generate-bindings.rs"
    )
    generated = _text(sources, "apps/desktop-ui/src/generated/contracts.ts")
    platform_lib = _text(sources, "crates/wardrobe-platform/src/lib.rs")
    database = _text(sources, "crates/wardrobe-platform/src/database.rs")
    repository = _text(
        sources, "crates/wardrobe-platform/src/photo_repository.rs"
    )
    source_image = _text(
        sources, "crates/wardrobe-platform/src/source_image.rs"
    )
    desktop = _text(sources, "src-tauri/src/lib.rs")
    build_rs = _text(sources, "src-tauri/build.rs")
    bridge = _text(sources, "apps/desktop-ui/src/photo-analysis-bridge.ts")
    model = _text(sources, "apps/desktop-ui/src/photo-analysis-model.ts")
    workspace = _text(sources, "apps/desktop-ui/src/PhotoAnalysisWorkspace.tsx")
    workspace_test = _text(
        sources, "apps/desktop-ui/src/PhotoAnalysisWorkspace.test.tsx"
    )
    e2e = _text(sources, "apps/desktop-ui/e2e/photo-analysis.spec.ts")

    required_contracts = (
        "GarmentSegmentationProvider",
        "SegmentationRequestV1",
        "SegmentationOutcomeV1",
        "SegmentationResultV1",
        "CanonicalSrgbPixelBufferV1",
        "PhotoScopeV1",
        "PhotoArtifactV1",
        "PhotoObservationV1",
    )
    if (
        not all(marker in photo or marker in ports for marker in required_contracts)
        or photo.count("deny_unknown_fields") < 20
        or not all(command in service for command in PHOTO_COMMANDS)
        or "ConformingGarmentSegmentationProviderV1" not in service
    ):
        errors.append("P04 core contracts, provider boundary, or service methods are incomplete")

    if not (
        "generated_bindings_are_current" in bindings
        and "typescript_bindings" in generator
        and "// @generated by wardrobe-core." in generated
        and all(
            marker in generated
            for marker in (
                "CreatePhotoScopeV1Request",
                "AnalyzePhotoScopeV1Request",
                "PromptPhotoObservationV1Request",
                "ReviewPhotoObservationV1Response",
            )
        )
    ):
        errors.append("P04 generated TypeScript bindings are incomplete")

    sql_name = "crates/wardrobe-platform/migrations/0005_photo_analysis.sql"
    checksum_name = (
        "crates/wardrobe-platform/migrations/0005_photo_analysis.sha256"
    )
    sql = sources.get(sql_name, b"")
    migration_sha256 = hashlib.sha256(sql).hexdigest()
    recorded_checksum = _text(sources, checksum_name).strip()
    ordered_versions = [database.find(f"version: {version}") for version in range(1, 6)]
    if (
        not sql
        or recorded_checksum != migration_sha256
        or re.fullmatch(r"[0-9a-f]{64}", recorded_checksum) is None
        or min(ordered_versions) < 0
        or ordered_versions != sorted(ordered_versions)
        or 'include_str!("../migrations/0005_photo_analysis.sql")' not in database
        or 'include_str!("../migrations/0005_photo_analysis.sha256")' not in database
        or "photo_revision" not in database
        or "version: 5" not in database
        or 'pragma_update(None, "user_version", migration.version)' not in database
    ):
        errors.append("checksummed ordered v5 migration is incomplete")

    if not (
        "mod photo_repository;" in platform_lib
        and "mod source_image;" in platform_lib
        and "impl PhotoAnalysisPort for Database" in repository
        and "TransactionBehavior::Immediate" in repository
        and "photo_scope_members" in repository
        and "membership_hash" in repository
        and "source_revision_hash" in repository
        and "canonical_pixels" in source_image
        and "BlobStore" in repository
    ):
        errors.append("platform photo repository or verified image source is incomplete")

    production_ports = ports.split("#[cfg(test)]", 1)[0]
    provider_impls = re.findall(
        r"impl\s+GarmentSegmentationProvider\s+for\s+([A-Za-z0-9_]+)",
        production_ports,
    )
    desktop_production = desktop.split("#[cfg(test)]", 1)[0]
    production_provider_wired = (
        provider_impls
        == [
            "ConformingGarmentSegmentationProviderV1",
            "UnavailableGarmentSegmentationProviderV1",
        ]
        and desktop_production.count(
            ".with_garment_segmentation_provider("
            "UnavailableGarmentSegmentationProviderV1)"
        )
        == 1
        and "UnavailableGarmentSegmentationProviderV1," in desktop_production
        and "model_revision: None" in production_ports
        and "ReviewedModelPackAbsent" in production_ports
    )
    if not production_provider_wired:
        errors.append("production must wire only UnavailableGarmentSegmentationProviderV1")
    if any(
        marker in desktop_production
        for marker in (
            "MockGarmentSegmentation",
            "ScriptedProvider",
            "TestGarmentSegmentation",
        )
    ):
        errors.append("production construction contains a test segmentation provider")

    approval_files, approval_files_empty = _automatic_approval_files(root)
    production_photo_text = "\n".join(
        _text(sources, relative) for relative in PRODUCTION_PHOTO_FILES
    )
    automatic_masks_disabled = (
        b"quality_approved INTEGER NOT NULL CHECK (quality_approved = 0)" in sql
        and "!self.quality_approved" in photo
        and "quality_approved: true" not in production_photo_text
        and '"quality_approved": true' not in production_photo_text
        and approval_files_empty
    )
    if not automatic_masks_disabled:
        errors.append("automatic-mask approval is nonempty or can be persisted as approved")

    core_manifest = _toml_object(
        _text(sources, "crates/wardrobe-core/Cargo.toml")
    )
    platform_manifest = _toml_object(
        _text(sources, "crates/wardrobe-platform/Cargo.toml")
    )
    banned_dependencies = {
        "candle-core",
        "candle-nn",
        "candle-transformers",
        "hf-hub",
        "onnxruntime",
        "ort",
        "reqwest-middleware",
        "tch",
        "tokenizers",
        "tract",
        "ureq",
    }
    core_dependencies = _dependency_names(core_manifest)
    dependencies = core_dependencies | _dependency_names(platform_manifest)
    ui_manifest = _json_object(
        sources.get("apps/desktop-ui/package.json", b"")
    )
    ui_dependency_value = ui_manifest.get("dependencies")
    ui_dependencies = (
        {str(name).lower() for name in ui_dependency_value}
        if isinstance(ui_dependency_value, dict)
        else set()
    )
    allowed_ui_dependencies = {
        "@tauri-apps/api",
        "@tauri-apps/plugin-dialog",
        "react",
        "react-dom",
    }
    forbidden_source_markers = (
        "reqwest::",
        "ureq::",
        "hyper::",
        "tokio::net",
        "std::net::",
        "TcpStream",
        "WebSocket",
        "fetch(",
        "Keychain",
        "CredentialPort",
        "api_key",
        "candle_",
        "hf_hub",
        "model_path",
        "model_url",
        "ort::",
        "tch::",
        "tract_onnx",
        "http://",
        "https://",
    )
    production_network_free = (
        dependencies.isdisjoint(banned_dependencies)
        and core_dependencies.isdisjoint(
            {"hyper", "reqwest", "tokio-tungstenite", "tungstenite"}
        )
        and ui_dependencies <= allowed_ui_dependencies
        and not any(
            marker in production_photo_text for marker in forbidden_source_markers
        )
    )
    if not production_network_free:
        errors.append("P04 production has a model, network, or credential dependency")

    handler_block = _block(
        desktop_production,
        ".invoke_handler(tauri::generate_handler![",
        "])",
    )
    registered_commands = tuple(
        command for command in PHOTO_COMMANDS if command in handler_block
    )
    build_commands = tuple(
        command for command in PHOTO_COMMANDS if f'"{command}"' in build_rs
    )
    capability = _json_object(
        sources.get("src-tauri/capabilities/main.json", b"")
    )
    permissions = capability.get("permissions")
    acl_permissions = tuple(
        permission
        for permission in permissions
        if isinstance(permission, str)
    ) if isinstance(permissions, list) else ()
    for command in PHOTO_COMMANDS:
        permission = "allow-" + command.replace("_", "-")
        if (
            command not in registered_commands
            or command not in build_commands
            or command not in desktop_production
            or permission not in acl_permissions
        ):
            errors.append(f"Tauri command, dispatcher, manifest, or ACL is missing {command}")

    production_transport = _text(
        sources, "apps/desktop-ui/src/invoke-transport.ts"
    )
    e2e_transport = _text(
        sources, "apps/desktop-ui/src/e2e/invoke-transport.ts"
    )
    vite_config = _text(sources, "apps/desktop-ui/vite.config.ts")
    transport_check = _text(
        sources, "apps/desktop-ui/scripts/check-production-transport.mjs"
    )
    production_transport_isolated = (
        "@tauri-apps/api/core" in production_transport
        and "__WARDROBE_E2E_TRANSPORT__" not in production_transport
        and "__WARDROBE_E2E_TRANSPORT__" in e2e_transport
        and "__WARDROBE_E2E_TRANSPORT__" not in bridge
        and "__WARDROBE_E2E_TRANSPORT__" not in workspace
        and "WARDROBE_E2E" in vite_config
        and "./src/e2e/invoke-transport.ts" in vite_config
        and "./src/invoke-transport.ts" in vite_config
        and "__WARDROBE_E2E_TRANSPORT__" in transport_check
    )
    if not production_transport_isolated:
        errors.append("production transport includes the P04 test transport")

    if not (
        all(command in bridge for command in PHOTO_COMMANDS)
        and "bytes_sha256" in model
        and "URL.createObjectURL" in workspace
        and "URL.revokeObjectURL" in workspace
        and "observationOutcome" in workspace
        and "Segmentation unavailable" in model
        and "Needs review" in workspace
        and "PhotoAnalysisWorkspace" in workspace_test
        and "AxeBuilder" in e2e
        and "setViewportSize" in e2e
        and len(re.findall(r"(?m)^\s*test\s*\(", e2e)) == 1
    ):
        errors.append("P04 React bridge, workspace, tests, or preview integrity is incomplete")

    try:
        playwright_specs = tuple(
            sorted(
                path.relative_to(root).as_posix()
                for path in (root / "apps/desktop-ui/e2e").glob(
                    "*photo-analysis*.spec.ts"
                )
                if path.is_file()
            )
        )
    except OSError:
        playwright_specs = ()
    if playwright_specs != ("apps/desktop-ui/e2e/photo-analysis.spec.ts",):
        errors.append("exactly one photo-analysis Playwright spec is required")

    # Keep this detail in the source hash without exposing local paths.
    if approval_files and not approval_files_empty:
        errors.append("automatic-mask approval file is not empty")

    return SourceValidation(
        errors=tuple(dict.fromkeys(errors)),
        source_sha256=source_sha256,
        migration_sha256=migration_sha256,
        registered_commands=registered_commands,
        acl_permissions=acl_permissions,
        production_provider_wired=production_provider_wired,
        automatic_masks_disabled=automatic_masks_disabled,
        production_network_free=production_network_free,
        production_transport_isolated=production_transport_isolated,
        playwright_specs=playwright_specs,
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


def _remove_stale_outputs(evidence_dir: Path) -> None:
    for requirement in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement}.json").unlink(missing_ok=True)
    (evidence_dir / DIAGNOSTICS_NAME).unlink(missing_ok=True)


def _bounded_json_bytes(value: dict[str, Any]) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("P04 evaluator artifact exceeds size limit")
    return data


def _write_bounded_json(path: Path, value: dict[str, Any]) -> None:
    _bounded_json_bytes(value)
    write_atomic_json(path, value)


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
    }
    return hashlib.sha256(_bounded_json_bytes(value)).hexdigest()


def _diagnostics(
    *,
    requested: set[str],
    failures: list[str],
    packet: PacketValidation,
    source: SourceValidation | None,
    checks: dict[str, dict[str, Any]],
    generated_at: str,
    pass_evidence_written: bool,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "fail" if failures else "pass",
        "generated_at": generated_at,
        "selected_requirement_ids": sorted(requested),
        "failures": failures,
        "packet_sha256": packet.packet_sha256,
        "packet_hashes": packet.hashes,
        "source_sha256": source.source_sha256 if source else "",
        "migration_sha256": source.migration_sha256 if source else "",
        "registered_commands": list(source.registered_commands) if source else [],
        "acl_permissions": list(source.acl_permissions) if source else [],
        "production_provider_wired": (
            source.production_provider_wired if source else False
        ),
        "automatic_masks_disabled": (
            source.automatic_masks_disabled if source else False
        ),
        "production_network_free": (
            source.production_network_free if source else False
        ),
        "production_transport_isolated": (
            source.production_transport_isolated if source else False
        ),
        "playwright_specs": list(source.playwright_specs) if source else [],
        "checks": checks,
        "deferred_limitations": [
            "external segmentation model and automatic-mask quality are deferred",
            "notarization and clean-machine certification are deferred",
        ],
        "pass_evidence_written": pass_evidence_written,
    }


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_stale_outputs(evidence_dir)
    generated_at = utc_now()
    packet = validate_packet(root)
    source: SourceValidation | None = None
    checks: dict[str, dict[str, Any]] = {}
    failures = list(packet.errors)

    if not failures:
        source = validate_source_contract(root)
        failures.extend(source.errors)

    if not failures:
        assert source is not None
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
        diagnostics = _diagnostics(
            requested=requested,
            failures=list(dict.fromkeys(failures)),
            packet=packet,
            source=source,
            checks=checks,
            generated_at=generated_at,
            pass_evidence_written=False,
        )
        _write_bounded_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        return 1

    payloads: dict[str, dict[str, Any]] = {}
    for requirement in sorted(requested):
        payloads[requirement] = {
            "schema_version": 1,
            "requirement_id": requirement,
            "status": "pass",
            "test": "p04_photo_analysis::focused_production_verification",
            "recorded_at": generated_at,
            "details": {
                "evaluator": "tools/evaluators/p04_photo_analysis.py",
                "verification_sha256": _verification_hash(
                    requirement, packet, source, checks
                ),
                "checks": list(checks),
                "public_summary": {
                    "profile": "personal_mvp",
                    "packet_sha256": packet.packet_sha256,
                    "source_sha256": source.source_sha256,
                    "migration_sha256": source.migration_sha256,
                    "provider": "UnavailableGarmentSegmentationProviderV1",
                    "automatic_masks": "disabled",
                    "external_model_certification": "deferred",
                    "notarization": "deferred",
                    "clean_machine_certification": "deferred",
                },
            },
        }
        _bounded_json_bytes(payloads[requirement])

    diagnostics = _diagnostics(
        requested=requested,
        failures=[],
        packet=packet,
        source=source,
        checks=checks,
        generated_at=generated_at,
        pass_evidence_written=True,
    )
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
