"""Fail-closed evaluator for the P00 PhotoKit materialization spike."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable
from urllib.parse import quote


REQUIREMENT_ID = "P00-PHO-001"
DETERMINISTIC_PREFIX = "P00_PHOTOS_DETERMINISTIC "
LIVE_PREFIX = "P00_PHOTOS_LIVE "
NONCE_ENV = "P00_PHOTOS_EVIDENCE_NONCE"
LIVE_CHALLENGE_ENV = "P00_PHOTOS_LIVE_CHALLENGE_JSON"
FORBIDDEN_LIVE_APP_ENV = "P00_PHOTOS_LIVE_APP"
FIXTURE_ROOT_RELATIVE = Path("spikes/p00-photokit-fixtures")
FIXTURE_MANIFEST_RELATIVE = FIXTURE_ROOT_RELATIVE / "manifest.json"
FIXTURE_GENERATOR_RELATIVE = FIXTURE_ROOT_RELATIVE / "generate.py"
APPROVED_FIXTURE_MANIFEST_SHA256 = (
    "bf97ddab71805cebe13eaa417d8c67f4f26d00fb5f4c01c78bf48bdb5c750a11"
)
APPROVED_FIXTURE_GENERATOR_SHA256 = (
    "8fb8248bb2443c60f3b50269817802251637dea023faa06bc3006b841012b2b1"
)

NATIVE_RELATIVE_ROOT = Path("spikes/p00-photokit-native")
PACKAGE_SCRIPT_RELATIVE = NATIVE_RELATIVE_ROOT / "scripts/package-app.sh"
PACKAGED_APP_NAME = "P00PhotoKitNativeProbe.app"
EXPECTED_BUNDLE_ID = "com.wardrobe.p00-photokit-native"
EXPECTED_EXECUTABLE_NAME = "P00PhotoKitProbe"
NONPERSONAL_PROVENANCE = "dedicated_nonpersonal_synthetic_photos_library_v1"
OUTPUT_ROOT_COMPONENT = "P00PhotoKitNative"
APPROVED_FIXTURES: dict[str, dict[str, Any]] = {
    "local": {
        "fixture_id": "p00-synthetic-local-v1",
        "sha256": "78b167d1451183a20b6ea88c3a4701d59335699aa2c947ead7282c31edff35a5",
        "pixel_width": 96,
        "pixel_height": 96,
    },
    "cloud": {
        "fixture_id": "p00-synthetic-cloud-v1",
        "sha256": "0a954174688fa3cf1fd32faa5601e6a7978b5fda3b90a470fac6fbce9686cf34",
        "pixel_width": 96,
        "pixel_height": 96,
    },
}
EXPECTED_USAGE_DESCRIPTION = (
    "Reads only the synthetic photos you select to verify local and iCloud "
    "PhotoKit materialization."
)

TEST_COMMAND = [
    "cargo",
    "test",
    "-p",
    "p00-photokit-materialization",
    "--test",
    "contract",
    "--",
    "--nocapture",
    "--test-threads=1",
]

LOCAL_CLOUD = "local_and_cloud_materialization"
CANCELLATION = "cancellation_and_late_callbacks"
CRASH = "crash_atomicity_and_replay"
PROVENANCE = "provenance_and_generation"
FILESYSTEM = "filesystem_and_bounds"
REDACTION = "diagnostic_redaction"
DETERMINISTIC_SCENARIOS = (
    LOCAL_CLOUD,
    CANCELLATION,
    CRASH,
    PROVENANCE,
    FILESYSTEM,
    REDACTION,
)

MAX_CAPTURE_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_TOTAL_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_FILES = 256
TEST_TIMEOUT_SECONDS = 15 * 60
PACKAGE_TIMEOUT_SECONDS = 15 * 60
LIVE_TIMEOUT_SECONDS = 10 * 60

LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
RUN_ID = re.compile(r"p00-[0-9a-f]{32}")
NATIVE_ALIAS = re.compile(r"[0-9a-f]{64}")

LIVE_SCENARIO = "p00_photokit_native_live"
RUNTIME_CHALLENGE_FIELDS = frozenset(
    {
        "schema_version",
        "nonce",
        "run_id",
        "harness_run_id",
        "source_fingerprint",
        "executable_sha256",
        "nonpersonal_provenance",
        "output_contract",
        "local",
        "cloud",
    }
)
RUNTIME_FIXTURE_FIELDS = frozenset(
    {
        "fixture_id",
        "sha256",
        "pixel_width",
        "pixel_height",
    }
)
RUNTIME_OUTPUT_FIELDS = frozenset(
    {
        "kind",
        "bundle_id",
        "relative_directory",
        "must_not_exist",
        "asset_suffix",
        "provenance_suffix",
    }
)

KNOWN_SENTINELS = (
    "P00_PHOTOS_ASSET_IDENTIFIER_SENTINEL",
    "P00_PHOTOS_ORIGINAL_FILENAME_SENTINEL.HEIC",
    "/private/P00_PHOTOS_PATH_SENTINEL",
    "P00_PHOTOS_ACCOUNT_SENTINEL",
    "https://photos.invalid/P00_PHOTOS_URL_SENTINEL",
    "P00_PHOTOS_FRAMEWORK_ERROR_SENTINEL",
    "P00_PHOTOS_IMAGE_BYTES_SENTINEL",
    "P00_PHOTOS_KEYCHAIN_SENTINEL",
)

# Type-sensitive, exact deterministic oracles emitted by the Rust contract.
EXPECTED_RECORD_VALUES: dict[str, dict[str, Any]] = {
    LOCAL_CLOUD: {
        "schema_version": 1,
        "status": "pass",
        "gateway": "scripted_photokit_v1",
        "representation_policy": "original_primary_v1",
        "selected_assets": 2,
        "local_probe_network_allowed": False,
        "local_probe_nonempty": True,
        "cloud_probe_network_allowed": False,
        "cloud_probe_accepted_bytes": 0,
        "cloud_probe_error_domain": "PHPhotosErrorDomain",
        "cloud_probe_error_code": 3164,
        "cloud_retry_network_allowed": True,
        "cloud_retry_same_resource": True,
        "cloud_progress_callbacks": 2,
        "cloud_progress_monotonic": True,
        "terminal_completions": 2,
        "fresh_reopen_decodes": 2,
        "source_count": 2,
        "revision_count": 2,
        "blob_count": 2,
    },
    CANCELLATION: {
        "schema_version": 1,
        "status": "pass",
        "cancel_idempotent": True,
        "cancel_before_registration_fenced": True,
        "late_registration_cancelled": True,
        "late_callbacks_ignored": 3,
        "stale_generation_callbacks_ignored": 2,
        "terminal_events": 1,
        "post_fence_revisions": 0,
        "unfinished_staging_files": 1,
        "committed_revision_preserved": True,
    },
    CRASH: {
        "schema_version": 1,
        "status": "pass",
        "fault_boundaries": 4,
        "old_state_cases": 2,
        "new_state_cases": 2,
        "partial_state_cases": 0,
        "no_replace_promotion": True,
        "mismatched_collision_rejected": True,
        "matching_collision_reused": True,
        "duplicate_blobs_after_replay": 0,
        "duplicate_revisions_after_replay": 0,
        "fresh_process_reopen": True,
        "sqlite_integrity_check": "ok",
        "foreign_key_violations": 0,
    },
    PROVENANCE: {
        "schema_version": 1,
        "status": "pass",
        "connector_generations": 2,
        "reenrollment_rotates_keys": True,
        "retired_generation_preserved": True,
        "cross_generation_locator_collision_distinct": True,
        "same_source_replay_revision_delta": 0,
        "changed_content_revision_delta": 1,
        "identical_bytes_distinct_sources": 2,
        "identical_bytes_shared_blobs": 1,
        "encrypted_locator_version": 1,
        "lookup_hmac_version": 1,
        "original_filenames_persisted": 0,
        "provenance_fields_verified": 10,
    },
    FILESYSTEM: {
        "schema_version": 1,
        "status": "pass",
        "selection_limit": 100,
        "resource_byte_limit": 536870912,
        "batch_byte_limit": 5368709120,
        "active_staging_byte_limit": 1073741824,
        "concurrent_request_limit": 2,
        "frame_limit": 1,
        "pixel_limit": 200000000,
        "free_space_reserve_bytes": 2147483648,
        "message_byte_limit": 65536,
        "chunk_byte_limit": 1048576,
        "private_directory_mode": 448,
        "private_file_mode": 384,
        "traversal_rejected": True,
        "absolute_path_rejected": True,
        "symlink_rejected": True,
        "hardlink_rejected": True,
        "root_device_change_rejected": True,
        "oversize_rejected_before_decode": True,
        "invalid_image_rejected": True,
    },
    REDACTION: {
        "schema_version": 1,
        "status": "pass",
        "sentinel_count": len(KNOWN_SENTINELS),
        "encoding_variants_per_sentinel": 7,
        "public_leak_count": 0,
        "private_blob_scan_excluded": True,
        "bounded_diagnostics": True,
        "raw_framework_error_persisted": False,
        "identifier_persisted_in_public_artifact": False,
        "filename_persisted": False,
    },
}

LIVE_ORACLES: dict[str, dict[str, Any]] = {
    "authorization_granted": {},
    "resource_selected": {
        "asset_alias": str,
        "resource_alias": str,
    },
    "probe_started": {
        "asset_alias": str,
        "resource_alias": str,
        "network_allowed": False,
    },
    "probe_network_required": {
        "asset_alias": str,
        "resource_alias": str,
        "network_allowed": False,
    },
    "retry_started": {
        "asset_alias": str,
        "resource_alias": str,
        "network_allowed": True,
    },
    "transfer_progress": {
        "asset_alias": str,
        "resource_alias": str,
        "progress_permille": int,
    },
    "asset_completed": {
        "asset_alias": str,
        "resource_alias": str,
        "byte_count": int,
        "progress_callback_count": int,
        "residency": str,
        "outcome": "pass",
    },
    "session_completed": {
        "outcome": "pass",
    },
}


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output: str
    output_sha256: str
    output_bytes: int
    truncated: bool = False
    timed_out: bool = False
    launch_failed: bool = False
    sentinel_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourceBinding:
    harness_run_id: str
    source_fingerprint: str


@dataclass(frozen=True)
class BundleInspection:
    app: Path
    executable: Path
    executable_sha256: str
    bundle_id: str


@dataclass(frozen=True)
class AssetProof:
    asset_alias: str
    resource_alias: str
    byte_count: int
    progress_callback_count: int
    output_name: str
    residency: str


@dataclass(frozen=True)
class LiveProof:
    local: AssetProof
    cloud: AssetProof
    event_count: int


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sentinel_variants(sentinel: str) -> set[bytes]:
    raw = sentinel.encode("ascii")
    return {
        raw,
        json.dumps(sentinel, ensure_ascii=True)[1:-1].encode("ascii"),
        quote(sentinel, safe="").encode("ascii"),
        "".join(f"%{byte:02X}" for byte in raw).encode("ascii"),
        base64.b64encode(raw),
        raw.hex().encode("ascii"),
        raw.hex().upper().encode("ascii"),
    }


def sentinel_findings(data: bytes, location: str) -> list[str]:
    return [
        f"known PhotoKit privacy sentinel leaked in {location}"
        for sentinel in KNOWN_SENTINELS
        if any(variant in data for variant in sentinel_variants(sentinel))
    ]


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        if process.poll() is None:
            process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=3)


def run_bounded_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
) -> CommandResult:
    digest = hashlib.sha256()
    captured = bytearray()
    total = 0
    truncated = False
    timed_out = False
    scanner_tail = b""
    scanner_errors: set[str] = set()
    max_variant = max(
        len(variant)
        for sentinel in KNOWN_SENTINELS
        for variant in sentinel_variants(sentinel)
    )
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        return CommandResult(
            127,
            "",
            hashlib.sha256(b"").hexdigest(),
            0,
            launch_failed=True,
        )

    assert process.stdout is not None
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 and process.poll() is None:
            timed_out = True
            _terminate(process)
        readable, _, _ = select.select(
            [process.stdout],
            [],
            [],
            0 if process.poll() is not None else min(0.25, max(remaining, 0)),
        )
        if readable:
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if chunk:
                total += len(chunk)
                digest.update(chunk)
                available = MAX_CAPTURE_BYTES - len(captured)
                if available > 0:
                    captured.extend(chunk[:available])
                truncated = truncated or len(chunk) > available
                scan_data = scanner_tail + chunk
                scanner_errors.update(
                    sentinel_findings(scan_data, "subprocess output")
                )
                scanner_tail = scan_data[-max(0, max_variant - 1) :]
                continue
        if process.poll() is not None:
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if chunk:
                total += len(chunk)
                digest.update(chunk)
                available = MAX_CAPTURE_BYTES - len(captured)
                if available > 0:
                    captured.extend(chunk[:available])
                truncated = truncated or len(chunk) > available
                scanner_errors.update(
                    sentinel_findings(
                        scanner_tail + chunk, "subprocess output"
                    )
                )
                continue
            break
    process.stdout.close()
    return CommandResult(
        process.returncode,
        captured.decode("utf-8", errors="replace"),
        digest.hexdigest(),
        total,
        truncated=truncated,
        timed_out=timed_out,
        sentinel_errors=tuple(sorted(scanner_errors)),
    )


def parse_deterministic_evidence(
    output: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for line in output.splitlines():
        occurrences = line.count(DETERMINISTIC_PREFIX)
        if occurrences == 0:
            continue
        if occurrences != 1 or not line.startswith(DETERMINISTIC_PREFIX):
            errors.append("PhotoKit deterministic evidence is not line-framed")
            continue
        try:
            payload = json.loads(line.removeprefix(DETERMINISTIC_PREFIX))
        except (json.JSONDecodeError, UnicodeError):
            errors.append("PhotoKit deterministic evidence has malformed JSON")
            continue
        if not isinstance(payload, dict):
            errors.append("PhotoKit deterministic evidence is not an object")
            continue
        scenario = payload.get("scenario")
        if not isinstance(scenario, str) or not scenario:
            errors.append("PhotoKit deterministic evidence lacks a scenario")
            continue
        if scenario in records:
            errors.append("PhotoKit deterministic evidence repeats a scenario")
            continue
        records[scenario] = payload
    return records, errors


def _exact(actual: Any, expected: Any) -> bool:
    return type(actual) is type(expected) and actual == expected


def validate_deterministic_records(
    records: dict[str, dict[str, Any]],
    nonce: str,
) -> list[str]:
    errors: list[str] = []
    expected_names = set(DETERMINISTIC_SCENARIOS)
    missing = expected_names - set(records)
    if missing:
        errors.append(
            "missing deterministic scenarios: " + ", ".join(sorted(missing))
        )
    if set(records) - expected_names:
        errors.append("unexpected deterministic scenarios were emitted")
    for scenario in DETERMINISTIC_SCENARIOS:
        record = records.get(scenario)
        if record is None:
            continue
        expected = EXPECTED_RECORD_VALUES[scenario]
        expected_keys = {"scenario", "nonce", *expected}
        if set(record) != expected_keys:
            missing_fields = expected_keys - set(record)
            if missing_fields:
                errors.append(
                    f"{scenario}: missing fields "
                    + ", ".join(sorted(missing_fields))
                )
            if set(record) - expected_keys:
                errors.append(f"{scenario}: unexpected fields were emitted")
        if record.get("scenario") != scenario:
            errors.append(f"{scenario}: scenario identity is invalid")
        if not _exact(record.get("nonce"), nonce):
            errors.append(f"{scenario}: runtime evidence nonce is stale")
        for field, value in expected.items():
            if not _exact(record.get(field), value):
                errors.append(f"{scenario}: expected {field}={value!r}")
    return errors


def validate_deterministic_command(
    result: CommandResult,
    nonce: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records, errors = parse_deterministic_evidence(result.output)
    if result.launch_failed:
        errors.append("PhotoKit deterministic contract test could not start")
    elif result.timed_out:
        errors.append("PhotoKit deterministic contract test timed out")
    elif result.returncode != 0:
        errors.append("PhotoKit deterministic contract test failed")
    if result.truncated:
        errors.append("PhotoKit deterministic output exceeded capture limit")
    if LIVE_PREFIX in result.output:
        errors.append("deterministic command emitted live evidence")
    errors.extend(result.sentinel_errors)
    errors.extend(sentinel_findings(result.output.encode(), "command output"))
    errors.extend(validate_deterministic_records(records, nonce))
    return records, list(dict.fromkeys(errors))


def _safe_id(value: Any) -> bool:
    return isinstance(value, str) and SAFE_IDENTIFIER.fullmatch(value) is not None


def _sha(value: Any) -> bool:
    return isinstance(value, str) and LOWER_SHA256.fullmatch(value) is not None


def run_bound_alias(nonce: str, context: str, value: str) -> str:
    message = f"p00-photokit-native:{context}:{value}".encode()
    return hmac.new(nonce.encode(), message, hashlib.sha256).hexdigest()


def expected_connector_provenance(
    challenge: dict[str, Any],
) -> tuple[str, str]:
    connector_instance = run_bound_alias(
        challenge["nonce"],
        "connector-instance-v1",
        ":".join(
            (
                challenge["output_contract"]["bundle_id"],
                challenge["nonpersonal_provenance"],
            )
        ),
    )
    connector_generation = run_bound_alias(
        challenge["nonce"],
        "enrolled-library-generation-v1",
        ":".join(
            (
                challenge["nonpersonal_provenance"],
                challenge["local"]["fixture_id"],
                challenge["local"]["sha256"],
                challenge["cloud"]["fixture_id"],
                challenge["cloud"]["sha256"],
            )
        ),
    )
    return connector_instance, connector_generation


def validate_operator_challenge(
    environ: dict[str, str],
    root: Path | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    repository_root = root or Path(__file__).resolve().parents[2]
    errors.extend(validate_approved_fixture_source(repository_root))
    if FORBIDDEN_LIVE_APP_ENV in environ:
        errors.append(f"{FORBIDDEN_LIVE_APP_ENV} is prohibited")
    raw = environ.get(LIVE_CHALLENGE_ENV)
    if not raw:
        return None, errors + [
            f"{LIVE_CHALLENGE_ENV} is required for live acceptance"
        ]
    try:
        challenge = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError):
        return None, errors + [
            f"{LIVE_CHALLENGE_ENV} must contain valid JSON"
        ]
    if not isinstance(challenge, dict):
        return None, errors + ["operator fixture challenge must be an object"]
    expected_fields = {
        "schema_version",
        "nonpersonal_provenance",
        "local",
        "cloud",
    }
    if set(challenge) != expected_fields:
        errors.append("operator fixture challenge fields are not exact")
    if (
        type(challenge.get("schema_version")) is not int
        or challenge.get("schema_version") != 1
    ):
        errors.append("operator fixture challenge schema_version must be 1")
    if challenge.get("nonpersonal_provenance") != NONPERSONAL_PROVENANCE:
        errors.append("operator fixture provenance is not approved")

    fixture_fields = {
        "fixture_id",
        "sha256",
        "pixel_width",
        "pixel_height",
    }
    for role in ("local", "cloud"):
        fixture = challenge.get(role)
        if not isinstance(fixture, dict) or set(fixture) != fixture_fields:
            errors.append(f"{role} fixture fields are not exact")
            continue
        if not _safe_id(fixture.get("fixture_id")):
            errors.append(f"{role} fixture ID is invalid")
        if not _sha(fixture.get("sha256")):
            errors.append(f"{role} fixture SHA-256 is invalid")
        width = fixture.get("pixel_width")
        height = fixture.get("pixel_height")
        if (
            type(width) is not int
            or type(height) is not int
            or width <= 0
            or height <= 0
            or width * height > 200_000_000
        ):
            errors.append(f"{role} fixture dimensions are invalid")
        expected_fixture = APPROVED_FIXTURES[role]
        if isinstance(fixture, dict) and any(
            not _exact(fixture.get(field), value)
            for field, value in expected_fixture.items()
        ):
            errors.append(
                f"{role} fixture does not match the reviewed synthetic manifest"
            )
    local = challenge.get("local")
    cloud = challenge.get("cloud")
    if isinstance(local, dict) and isinstance(cloud, dict):
        if local.get("fixture_id") == cloud.get("fixture_id"):
            errors.append("fixture IDs must be distinct")
        if local.get("sha256") == cloud.get("sha256"):
            errors.append("fixture SHA-256 values must be distinct")
    return challenge, errors


def validate_approved_fixture_source(root: Path) -> list[str]:
    manifest_path = root / FIXTURE_MANIFEST_RELATIVE
    generator_path = root / FIXTURE_GENERATOR_RELATIVE
    try:
        if sha256_file(manifest_path) != APPROVED_FIXTURE_MANIFEST_SHA256:
            return ["reviewed synthetic fixture manifest hash is invalid"]
        if sha256_file(generator_path) != APPROVED_FIXTURE_GENERATOR_SHA256:
            return ["reviewed synthetic fixture generator hash is invalid"]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ["reviewed synthetic fixture source cannot be read"]

    expected_rows = []
    for role in ("local", "cloud"):
        fixture = APPROVED_FIXTURES[role]
        expected_rows.append(
            {
                **fixture,
                "role": role,
                "filename": f"{role}.png",
                "byte_count": 323 if role == "local" else 337,
                "mime_type": "image/png",
            }
        )
    expected_manifest = {
        "schema_version": 1,
        "generator_revision": "p00-photokit-fixtures-v1",
        "nonpersonal_provenance": NONPERSONAL_PROVENANCE,
        "fixtures": expected_rows,
    }
    if not _exact(manifest, expected_manifest):
        return ["reviewed synthetic fixture manifest contents are invalid"]
    return []


def repository_source_fingerprint(root: Path) -> str:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise OSError("cannot enumerate repository source")
    paths = sorted(
        Path(item.decode("utf-8"))
        for item in result.stdout.split(b"\0")
        if item
        and Path(item.decode("utf-8")).parts[:2]
        != ("artifacts", "accepted")
    )
    digest = hashlib.sha256()
    for relative in paths:
        path = root / relative
        if not path.is_file():
            continue
        digest.update(str(relative).encode())
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def validate_source_binding(
    root: Path,
    environ: dict[str, str],
) -> tuple[SourceBinding | None, list[str]]:
    run_value = environ.get("HARNESS_RUN_DIR")
    if not run_value:
        return None, ["HARNESS_RUN_DIR is required for source binding"]
    run_dir = Path(run_value)
    try:
        expected_root = (root / "artifacts" / "harness").resolve(strict=False)
        resolved_run = run_dir.resolve(strict=True)
    except OSError:
        return None, ["harness run directory cannot be resolved"]
    if not resolved_run.is_relative_to(expected_root):
        return None, ["harness run directory is outside the repository"]
    try:
        state = json.loads(
            (resolved_run / "state.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, ["harness state cannot be read"]
    if not isinstance(state, dict):
        return None, ["harness state is not an object"]
    run_id = state.get("run_id")
    fingerprint = state.get("build", {}).get("source_fingerprint")
    if run_id != resolved_run.name or not _safe_id(run_id):
        return None, ["harness run identity is invalid"]
    if REQUIREMENT_ID not in state.get("selected_requirement_ids", []):
        return None, ["harness run did not select PhotoKit evidence"]
    if state.get("status") not in {"BUILT", "EVALUATION_FAILED"}:
        return None, ["harness run is not in an evaluatable state"]
    if not _sha(fingerprint):
        return None, ["harness build source fingerprint is missing"]
    try:
        current = repository_source_fingerprint(root)
    except OSError:
        return None, ["repository source fingerprint cannot be computed"]
    if current != fingerprint:
        return None, ["repository source differs from the harness build"]
    return SourceBinding(run_id, fingerprint), []


def make_runtime_challenge(
    operator_challenge: dict[str, Any],
    *,
    nonce: str,
    run_id: str,
    binding: SourceBinding,
    executable_sha256: str,
) -> dict[str, Any]:
    if RUN_ID.fullmatch(run_id) is None:
        raise ValueError("invalid evaluator run ID")
    return {
        "schema_version": 1,
        "nonce": nonce,
        "run_id": run_id,
        "harness_run_id": binding.harness_run_id,
        "source_fingerprint": binding.source_fingerprint,
        "executable_sha256": executable_sha256,
        "nonpersonal_provenance": NONPERSONAL_PROVENANCE,
        "output_contract": {
            "kind": "sandbox_container_v1",
            "bundle_id": EXPECTED_BUNDLE_ID,
            "relative_directory": (
                f"Library/Application Support/{OUTPUT_ROOT_COMPONENT}/{run_id}"
            ),
            "must_not_exist": True,
            "asset_suffix": ".asset",
            "provenance_suffix": ".provenance.json",
        },
        "local": {
            "fixture_id": operator_challenge["local"]["fixture_id"],
            "sha256": operator_challenge["local"]["sha256"],
            "pixel_width": operator_challenge["local"]["pixel_width"],
            "pixel_height": operator_challenge["local"]["pixel_height"],
        },
        "cloud": {
            "fixture_id": operator_challenge["cloud"]["fixture_id"],
            "sha256": operator_challenge["cloud"]["sha256"],
            "pixel_width": operator_challenge["cloud"]["pixel_width"],
            "pixel_height": operator_challenge["cloud"]["pixel_height"],
        },
    }


def validate_runtime_challenge(challenge: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(challenge) != RUNTIME_CHALLENGE_FIELDS:
        return ["runtime challenge fields are not exact"]
    fixed_values = {
        "schema_version": 1,
        "nonpersonal_provenance": NONPERSONAL_PROVENANCE,
    }
    for field, value in fixed_values.items():
        if not _exact(challenge.get(field), value):
            errors.append(f"runtime challenge {field} is invalid")
    if (
        not isinstance(challenge.get("run_id"), str)
        or RUN_ID.fullmatch(challenge["run_id"]) is None
    ):
        errors.append("runtime challenge ID is invalid")
    if not _sha(challenge.get("nonce")):
        errors.append("runtime challenge nonce is invalid")
    if not _safe_id(challenge.get("harness_run_id")):
        errors.append("runtime challenge harness run ID is invalid")
    if not _sha(challenge.get("source_fingerprint")):
        errors.append("runtime challenge source fingerprint is invalid")
    if not _sha(challenge.get("executable_sha256")):
        errors.append("runtime challenge executable hash is invalid")
    output = challenge.get("output_contract")
    if not isinstance(output, dict) or set(output) != RUNTIME_OUTPUT_FIELDS:
        errors.append("runtime output contract fields are not exact")
    else:
        expected_output = {
            "kind": "sandbox_container_v1",
            "bundle_id": EXPECTED_BUNDLE_ID,
            "relative_directory": (
                "Library/Application Support/"
                f"{OUTPUT_ROOT_COMPONENT}/{challenge.get('run_id')}"
            ),
            "must_not_exist": True,
            "asset_suffix": ".asset",
            "provenance_suffix": ".provenance.json",
        }
        for field, value in expected_output.items():
            if not _exact(output.get(field), value):
                errors.append(f"runtime output contract {field} is invalid")
    for role in ("local", "cloud"):
        fixture = challenge.get(role)
        if (
            not isinstance(fixture, dict)
            or set(fixture) != RUNTIME_FIXTURE_FIELDS
        ):
            errors.append(f"runtime {role} fixture fields are not exact")
            continue
        if not _safe_id(fixture.get("fixture_id")):
            errors.append(f"runtime {role} fixture ID is invalid")
        if not _sha(fixture.get("sha256")):
            errors.append(f"runtime {role} fixture hash is invalid")
        width = fixture.get("pixel_width")
        height = fixture.get("pixel_height")
        if (
            type(width) is not int
            or type(height) is not int
            or width <= 0
            or height <= 0
            or width > 200_000_000 // height
        ):
            errors.append(f"runtime {role} fixture dimensions are invalid")
    local = challenge.get("local")
    cloud = challenge.get("cloud")
    if isinstance(local, dict) and isinstance(cloud, dict):
        if local.get("fixture_id") == cloud.get("fixture_id"):
            errors.append("runtime fixture IDs are not distinct")
        if local.get("sha256") == cloud.get("sha256"):
            errors.append("runtime fixture hashes are not distinct")
    return list(dict.fromkeys(errors))


def serialize_runtime_challenge(challenge: dict[str, Any]) -> str:
    errors = validate_runtime_challenge(challenge)
    if errors:
        raise ValueError("; ".join(errors))
    return json.dumps(challenge, separators=(",", ":"), sort_keys=True)


def sandbox_output_directory_for_run(
    run_id: str,
    *,
    home: Path | None = None,
) -> Path:
    base = home or Path.home()
    return (
        base
        / "Library"
        / "Containers"
        / EXPECTED_BUNDLE_ID
        / "Data"
        / "Library"
        / "Application Support"
        / OUTPUT_ROOT_COMPONENT
        / run_id
    )


def validate_output_directory_absent(output_dir: Path) -> list[str]:
    if os.path.lexists(output_dir):
        return ["sandbox run output directory existed before launch"]
    return []


def make_package_root() -> Path:
    path = Path(tempfile.mkdtemp(prefix="wardrobe-p00-photos-package-"))
    os.chmod(path, 0o700)
    return path


def _path_is_regular_single_link(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_nlink == 1
    )


def package_current_source(
    root: Path,
    package_root: Path,
    env: dict[str, str],
) -> tuple[Path | None, CommandResult, list[str]]:
    errors: list[str] = []
    script = root / PACKAGE_SCRIPT_RELATIVE
    native_root = root / NATIVE_RELATIVE_ROOT
    app = package_root / PACKAGED_APP_NAME
    if (
        not package_root.is_dir()
        or package_root.is_symlink()
        or any(package_root.iterdir())
    ):
        errors.append("randomized package directory is not fresh and empty")
    if not _path_is_regular_single_link(script) or not os.access(
        script, os.X_OK
    ):
        errors.append("native packaging script is missing or unsafe")
    if not native_root.is_dir() or native_root.is_symlink():
        errors.append("native package source directory is missing or unsafe")
    if os.path.lexists(app):
        errors.append("packaged app path existed before source build")
    if errors:
        empty = CommandResult(127, "", hashlib.sha256(b"").hexdigest(), 0)
        return None, empty, errors

    command = [str(script), str(package_root)]
    result = run_bounded_command(
        command,
        cwd=root,
        env=env,
        timeout_seconds=PACKAGE_TIMEOUT_SECONDS,
    )
    if result.launch_failed:
        errors.append("native packaging script could not start")
    elif result.timed_out:
        errors.append("native packaging script timed out")
    elif result.returncode != 0:
        errors.append("native packaging script failed")
    if result.truncated:
        errors.append("native packaging output exceeded capture limit")
    errors.extend(result.sentinel_errors)
    errors.extend(sentinel_findings(result.output.encode(), "packaging output"))
    lines = [line.strip() for line in result.output.splitlines() if line.strip()]
    if not lines or lines[-1] != str(app):
        errors.append("native packaging script did not report the exact app")
    if not app.is_dir() or app.is_symlink():
        errors.append("source-built native app is missing or unsafe")
    elif any(path.is_symlink() for path in app.rglob("*")):
        errors.append("source-built native app contains a symlink")
    return app if not errors else None, result, list(dict.fromkeys(errors))


def _run_tool(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=30,
    )


def _plist_from_tool_output(output: str) -> dict[str, Any] | None:
    start = output.find("<?xml")
    end = output.rfind("</plist>")
    if start < 0 or end < start:
        return None
    try:
        value = plistlib.loads(output[start : end + 8].encode())
    except (plistlib.InvalidFileException, ValueError):
        return None
    return value if isinstance(value, dict) else None


def inspect_source_built_app(
    root: Path,
    app: Path,
) -> tuple[BundleInspection | None, list[str]]:
    errors: list[str] = []
    try:
        source_info = plistlib.loads(
            (root / NATIVE_RELATIVE_ROOT / "AppInfo.plist").read_bytes()
        )
        packaged_info = plistlib.loads(
            (app / "Contents" / "Info.plist").read_bytes()
        )
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None, ["source or packaged Info.plist cannot be read"]
    if source_info != packaged_info:
        errors.append("packaged Info.plist differs from reviewed source")
    if packaged_info.get("CFBundleIdentifier") != EXPECTED_BUNDLE_ID:
        errors.append("packaged bundle identifier is invalid")
    if packaged_info.get("CFBundleExecutable") != EXPECTED_EXECUTABLE_NAME:
        errors.append("packaged executable name is invalid")
    usage = packaged_info.get("NSPhotoLibraryUsageDescription")
    if usage != EXPECTED_USAGE_DESCRIPTION:
        errors.append("Photos usage description is missing or inaccurate")
    if "NSPhotoLibraryAddUsageDescription" in packaged_info:
        errors.append("packaged app declares prohibited add-only Photos usage")

    executable = app / "Contents" / "MacOS" / EXPECTED_EXECUTABLE_NAME
    if not _path_is_regular_single_link(executable):
        return None, errors + ["packaged executable is not a regular unique file"]
    executable_hash = sha256_file(executable)

    try:
        verify = _run_tool(
            [
                "codesign",
                "--verify",
                "--deep",
                "--strict",
                "--verbose=2",
                str(app),
            ]
        )
        details = _run_tool(["codesign", "-dv", "--verbose=4", str(app)])
        entitlements_result = _run_tool(
            ["codesign", "-d", "--entitlements", ":-", str(app)]
        )
        linkage = _run_tool(["otool", "-L", str(executable)])
        file_result = _run_tool(["file", str(executable)])
    except (OSError, subprocess.TimeoutExpired):
        return None, errors + ["native app inspection tool failed"]

    if verify.returncode != 0:
        errors.append("strict code-signature verification failed")
    identifier = re.search(r"^Identifier=(.+)$", details.stdout, re.MULTILINE)
    if identifier is None or identifier.group(1).strip() != EXPECTED_BUNDLE_ID:
        errors.append("signature identifier does not match bundle ID")
    if "Signature=adhoc" not in details.stdout:
        errors.append("source-built app signature is not ad hoc")
    team = re.search(r"^TeamIdentifier=(.+)$", details.stdout, re.MULTILINE)
    if team is not None and team.group(1).strip() not in {"", "not set"}:
        errors.append("ad hoc app unexpectedly declares a signing team")

    entitlements = _plist_from_tool_output(entitlements_result.stdout)
    required_entitlements = {
        "com.apple.security.app-sandbox": True,
        "com.apple.security.personal-information.photos-library": True,
    }
    if entitlements != required_entitlements:
        errors.append("app sandbox and Photos entitlements are not exact")
    if isinstance(entitlements, dict):
        forbidden_fragments = (
            ".files.",
            ".assets.pictures.",
            "delete",
            "temporary-exception",
            "automation",
        )
        if any(
            fragment in key.lower()
            for key in entitlements
            for fragment in forbidden_fragments
        ):
            errors.append("app has broad file-access or deletion entitlements")

    for framework in (
        "/System/Library/Frameworks/Photos.framework/",
        "/System/Library/Frameworks/PhotosUI.framework/",
    ):
        if linkage.returncode != 0 or framework not in linkage.stdout:
            errors.append(f"packaged executable does not link {framework}")
    if (
        file_result.returncode != 0
        or "Mach-O 64-bit executable arm64" not in file_result.stdout
        or "script" in file_result.stdout.lower()
    ):
        errors.append("packaged executable is not a native arm64 Mach-O")

    return (
        BundleInspection(app, executable, executable_hash, EXPECTED_BUNDLE_ID),
        list(dict.fromkeys(errors)),
    )


def validate_gui_session() -> list[str]:
    if platform.system() != "Darwin":
        return ["live PhotoKit acceptance requires macOS"]
    command = [
        "/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession",
        "-s",
    ]
    try:
        result = _run_tool(command)
    except (OSError, subprocess.TimeoutExpired):
        return ["cannot inspect the macOS GUI session"]
    if (
        result.returncode != 0
        or "CGSSessionOnConsoleKey = 1" not in result.stdout
        or "kCGSessionLoginDoneKey = 1" not in result.stdout
    ):
        return ["an unlocked on-console GUI session is required"]
    return []


def parse_live_evidence(
    output: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for line in output.splitlines():
        occurrences = line.count(LIVE_PREFIX)
        if occurrences == 0:
            continue
        if occurrences != 1 or not line.startswith(LIVE_PREFIX):
            errors.append("PhotoKit live evidence is not exactly line-framed")
            continue
        try:
            payload = json.loads(line.removeprefix(LIVE_PREFIX))
        except (json.JSONDecodeError, UnicodeError):
            errors.append("PhotoKit live evidence contains malformed JSON")
            continue
        if not isinstance(payload, dict):
            errors.append("PhotoKit live evidence record is not an object")
            continue
        if payload.get("scenario") != LIVE_SCENARIO:
            errors.append("PhotoKit live evidence scenario is not approved")
            continue
        records.append(payload)
    return records, errors


def _alias(value: Any) -> bool:
    return isinstance(value, str) and NATIVE_ALIAS.fullmatch(value) is not None


def validate_live_records(
    records: list[dict[str, Any]],
    nonce: str,
    challenge: dict[str, Any],
    inspection: BundleInspection,
) -> tuple[LiveProof | None, list[str]]:
    errors: list[str] = []
    common_fields = {
        "schema_version",
        "scenario",
        "challenge_nonce",
        "sequence",
        "event",
    }
    for offset, record in enumerate(records, start=1):
        event = record.get("event")
        oracle = LIVE_ORACLES.get(event)
        if oracle is None:
            errors.append("native live event is not approved")
            continue
        if set(record) != common_fields | set(oracle):
            errors.append(f"live sequence {offset}: fields are not exact")
        common_expected = {
            "schema_version": 1,
            "scenario": LIVE_SCENARIO,
            "challenge_nonce": nonce,
            "sequence": offset,
            "event": event,
        }
        for field, value in common_expected.items():
            if not _exact(record.get(field), value):
                errors.append(f"live sequence {offset}: {field} is invalid")
        for field, value in oracle.items():
            actual = record.get(field)
            if isinstance(value, type):
                if type(actual) is not value:
                    errors.append(
                        f"live sequence {offset}: {field} type is invalid"
                    )
            elif not _exact(actual, value):
                errors.append(
                    f"live sequence {offset}: {field} value is invalid"
                )
        for field in ("asset_alias", "resource_alias"):
            if field in oracle and not _alias(record.get(field)):
                errors.append(
                    f"live sequence {offset}: {field} is invalid"
                )
        if event == "transfer_progress":
            progress = record.get("progress_permille")
            if type(progress) is not int or not 0 <= progress <= 1000:
                errors.append(
                    f"live sequence {offset}: progress is out of bounds"
                )

    if errors:
        return None, list(dict.fromkeys(errors))
    if challenge.get("executable_sha256") != inspection.executable_sha256:
        errors.append("live challenge executable hash is not inspected hash")

    events = [record["event"] for record in records]
    if not events or events[0] != "authorization_granted":
        errors.append("live sequence does not begin with authorization")
    if len(events) < 4 or events[1:3] != [
        "resource_selected",
        "resource_selected",
    ]:
        errors.append("live sequence does not contain two initial selections")

    selections = (
        records[1:3]
        if len(records) >= 3
        else []
    )
    selected_pairs = {
        (record.get("asset_alias"), record.get("resource_alias"))
        for record in selections
    }
    if len(selected_pairs) != 2:
        errors.append("live selections are not structurally distinct")

    proofs: dict[str, AssetProof] = {}
    used_pairs: set[tuple[Any, Any]] = set()
    cursor = 3
    for _ in range(2):
        if cursor >= len(records) or records[cursor]["event"] != "probe_started":
            errors.append("live resource operation does not start with probe")
            break
        pair = (
            records[cursor]["asset_alias"],
            records[cursor]["resource_alias"],
        )
        if pair not in selected_pairs or pair in used_pairs:
            errors.append("live probe does not match one unique selection")
        used_pairs.add(pair)
        cursor += 1

        role = "local"
        progress_values: list[int] = []
        if (
            cursor < len(records)
            and records[cursor]["event"] == "probe_network_required"
        ):
            role = "cloud"
            for expected_event in (
                "probe_network_required",
                "retry_started",
            ):
                if (
                    cursor >= len(records)
                    or records[cursor]["event"] != expected_event
                ):
                    errors.append(
                        "cloud live retry sequence is incomplete"
                    )
                    break
                retry_pair = (
                    records[cursor]["asset_alias"],
                    records[cursor]["resource_alias"],
                )
                if retry_pair != pair:
                    errors.append("cloud retry changed selected resource")
                cursor += 1
            while (
                cursor < len(records)
                and records[cursor]["event"] == "transfer_progress"
            ):
                progress_pair = (
                    records[cursor]["asset_alias"],
                    records[cursor]["resource_alias"],
                )
                if progress_pair != pair:
                    errors.append("cloud progress changed selected resource")
                progress_values.append(records[cursor]["progress_permille"])
                cursor += 1
            if not progress_values:
                errors.append("cloud retry emitted no real progress callback")
            if progress_values != sorted(progress_values):
                errors.append("cloud progress callbacks are not monotonic")

        if cursor >= len(records) or records[cursor]["event"] != "asset_completed":
            errors.append("live resource operation lacks completion")
            break
        completed = records[cursor]
        completed_pair = (
            completed["asset_alias"],
            completed["resource_alias"],
        )
        if completed_pair != pair:
            errors.append("live completion changed selected resource")
        if completed.get("residency") != role:
            errors.append("live completion residency is inconsistent")
        byte_count = completed.get("byte_count")
        callbacks = completed.get("progress_callback_count")
        if type(byte_count) is not int or byte_count <= 0:
            errors.append("live completion byte count is invalid")
            byte_count = 0
        if type(callbacks) is not int or callbacks < 0:
            errors.append("live completion progress count is invalid")
            callbacks = 0
        if role == "local" and callbacks != 0:
            errors.append("local probe unexpectedly reported progress")
        if role == "cloud" and (
            callbacks <= 0 or callbacks < len(progress_values)
        ):
            errors.append("cloud progress callback count is invalid")
        if role in proofs:
            errors.append("live sequence repeats a residency completion")
        proofs[role] = AssetProof(
            pair[0],
            pair[1],
            byte_count,
            callbacks,
            pair[1] + challenge["output_contract"]["asset_suffix"],
            role,
        )
        cursor += 1

    if used_pairs != selected_pairs:
        errors.append("not every selected resource was completed")
    if set(proofs) != {"local", "cloud"}:
        errors.append("live sequence lacks exact local and cloud completions")
    if (
        cursor >= len(records)
        or records[cursor]["event"] != "session_completed"
        or cursor != len(records) - 1
    ):
        errors.append("live sequence does not end with one session completion")
    if errors or len(proofs) != 2:
        return None, list(dict.fromkeys(errors))
    return LiveProof(proofs["local"], proofs["cloud"], len(records)), []


def validate_live_command(
    result: CommandResult,
    nonce: str,
    challenge: dict[str, Any],
    inspection: BundleInspection,
) -> tuple[list[dict[str, Any]], LiveProof | None, list[str]]:
    records, errors = parse_live_evidence(result.output)
    if result.launch_failed:
        errors.append("source-built native PhotoKit app could not start")
    elif result.timed_out:
        errors.append("source-built native PhotoKit app timed out")
    elif result.returncode != 0:
        errors.append("source-built native PhotoKit app failed")
    if result.truncated:
        errors.append("native PhotoKit output exceeded capture limit")
    if DETERMINISTIC_PREFIX in result.output:
        errors.append("native app emitted deterministic evidence")
    errors.extend(result.sentinel_errors)
    errors.extend(sentinel_findings(result.output.encode(), "live app output"))
    proof, proof_errors = validate_live_records(
        records, nonce, challenge, inspection
    )
    errors.extend(proof_errors)
    return records, proof, list(dict.fromkeys(errors))


def _run_sips(path: Path) -> tuple[tuple[int, int] | None, list[str]]:
    try:
        result = _run_tool(
            ["sips", "-g", "pixelWidth", "-g", "pixelHeight", str(path)]
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, ["fresh image decoder could not start"]
    width = re.search(r"pixelWidth:\s*(\d+)", result.stdout)
    height = re.search(r"pixelHeight:\s*(\d+)", result.stdout)
    if result.returncode != 0 or width is None or height is None:
        return None, ["fresh image decoder rejected a materialized blob"]
    return (int(width.group(1)), int(height.group(1))), []


def _validate_private_regular(path: Path) -> tuple[int | None, list[str]]:
    try:
        metadata = path.lstat()
    except OSError:
        return None, ["required private output is missing"]
    errors: list[str] = []
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
    ):
        errors.append("private output is not a regular unique file")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        errors.append("private output mode is not 0600")
    return metadata.st_size, errors


def verify_live_outputs(
    output_dir: Path,
    runtime_challenge: dict[str, Any],
    proof: LiveProof,
) -> list[str]:
    errors: list[str] = []
    connector_instance, connector_generation = expected_connector_provenance(
        runtime_challenge
    )
    try:
        metadata = output_dir.lstat()
    except OSError:
        return ["sandbox run output directory was not created"]
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or output_dir.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        errors.append("sandbox run output directory is not a private directory")

    expected_names = {
        proof.local.output_name,
        proof.local.resource_alias
        + runtime_challenge["output_contract"]["provenance_suffix"],
        proof.cloud.output_name,
        proof.cloud.resource_alias
        + runtime_challenge["output_contract"]["provenance_suffix"],
    }
    try:
        actual_names = {path.name for path in output_dir.iterdir()}
    except OSError:
        return errors + ["sandbox run output directory cannot be enumerated"]
    if actual_names != expected_names:
        errors.append("sandbox run output file set is not exact")

    for role, asset_proof in (("local", proof.local), ("cloud", proof.cloud)):
        fixture = runtime_challenge[role]
        blob = output_dir / asset_proof.output_name
        sidecar = output_dir / (
            asset_proof.resource_alias
            + runtime_challenge["output_contract"]["provenance_suffix"]
        )
        byte_count, file_errors = _validate_private_regular(blob)
        errors.extend(file_errors)
        if byte_count is None:
            continue
        try:
            blob_hash = sha256_file(blob)
        except OSError:
            errors.append("materialized blob cannot be hashed")
            continue
        if blob_hash != fixture["sha256"]:
            errors.append(f"{role} blob hash does not match fixture challenge")
        if byte_count != asset_proof.byte_count:
            errors.append(f"{role} event byte count does not match blob")
        dimensions, decode_errors = _run_sips(blob)
        errors.extend(decode_errors)
        expected_dimensions = (
            fixture["pixel_width"],
            fixture["pixel_height"],
        )
        if dimensions is not None and dimensions != expected_dimensions:
            errors.append(f"{role} decoded dimensions do not match challenge")

        _, sidecar_errors = _validate_private_regular(sidecar)
        errors.extend(sidecar_errors)
        try:
            provenance = json.loads(sidecar.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            errors.append(f"{role} provenance sidecar cannot be read")
            continue
        expected_provenance = {
            "schema_version": 1,
            "run_id": runtime_challenge["run_id"],
            "harness_run_id": runtime_challenge["harness_run_id"],
            "source_fingerprint": runtime_challenge["source_fingerprint"],
            "executable_sha256": runtime_challenge["executable_sha256"],
            "bundle_id": runtime_challenge["output_contract"]["bundle_id"],
            "fixture_role": role,
            "fixture_id": fixture["fixture_id"],
            "nonpersonal_provenance": runtime_challenge[
                "nonpersonal_provenance"
            ],
            "connector_instance": connector_instance,
            "connector_generation": connector_generation,
            "asset_alias": asset_proof.asset_alias,
            "resource_alias": asset_proof.resource_alias,
            "representation_policy": "original_primary_v1",
            "residency": role,
            "blob_sha256": fixture["sha256"],
            "byte_count": asset_proof.byte_count,
            "pixel_width": fixture["pixel_width"],
            "pixel_height": fixture["pixel_height"],
        }
        if not isinstance(provenance, dict) or set(provenance) != set(
            expected_provenance
        ):
            errors.append(f"{role} provenance fields are not exact")
            continue
        for field, value in expected_provenance.items():
            if not _exact(provenance.get(field), value):
                errors.append(f"{role} provenance {field} does not match")
    return list(dict.fromkeys(errors))


def _is_within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def scan_artifacts(
    artifact_root: Path,
    *,
    private_roots: tuple[Path, ...] = (),
) -> list[str]:
    errors: list[str] = []
    if not artifact_root.exists():
        return errors
    try:
        excluded = tuple(path.resolve(strict=False) for path in private_roots)
        excluded_lexical = tuple(
            Path(os.path.abspath(path)) for path in private_roots
        )
    except OSError:
        return ["cannot resolve private blob scan exclusion"]
    files = 0
    total = 0
    for path in sorted(artifact_root.rglob("*")):
        lexical = Path(os.path.abspath(path))
        if any(_is_within(lexical, root) for root in excluded_lexical):
            continue
        if path.is_symlink():
            errors.append("a public evaluator artifact is a symlink")
            continue
        try:
            resolved = path.resolve(strict=False)
        except OSError:
            errors.append("cannot resolve a public evaluator artifact")
            continue
        if any(_is_within(resolved, root) for root in excluded):
            errors.append("a public artifact resolves into private blob storage")
            continue
        relative = path.relative_to(artifact_root)
        errors.extend(
            sentinel_findings(
                relative.as_posix().encode("utf-8", "surrogateescape"),
                "public artifact path",
            )
        )
        if not path.is_file():
            continue
        files += 1
        if files > MAX_ARTIFACT_FILES:
            errors.append("public artifact count exceeds scan limit")
            break
        try:
            size = path.stat().st_size
        except OSError:
            errors.append("cannot inspect a public evaluator artifact")
            continue
        total += size
        if size > MAX_ARTIFACT_BYTES:
            errors.append("a public artifact exceeds scan limit")
            continue
        if total > MAX_ARTIFACT_TOTAL_BYTES:
            errors.append("public artifacts exceed aggregate scan limit")
            break
        try:
            data = path.read_bytes()
        except OSError:
            errors.append("cannot scan a public evaluator artifact")
            continue
        errors.extend(sentinel_findings(data, "public artifact contents"))
    return list(dict.fromkeys(errors))


def public_summary(
    deterministic: dict[str, dict[str, Any]],
    nonce: str,
    proof: LiveProof,
    binding: SourceBinding,
    inspection: BundleInspection,
) -> dict[str, Any]:
    if validate_deterministic_records(deterministic, nonce):
        raise ValueError("cannot summarize invalid deterministic evidence")
    return {
        "evidence_planes": [
            "rust_deterministic_core",
            "swift_native_live",
        ],
        "native_rust_integration": "not_claimed_deferred_p06",
        "deterministic_scenarios": len(deterministic),
        "live_native_scenarios": proof.event_count,
        "native_adapter": True,
        "local_network_disabled_nonempty": proof.local.byte_count > 0,
        "icloud_network_required_error_code": 3164,
        "icloud_probe_accepted_bytes": 0,
        "same_resource_cloud_retry": True,
        "real_progress_callbacks": proof.cloud.progress_callback_count,
        "terminal_completions": 2,
        "fresh_reopen_decodes": 2,
        "verified_provenance_records": 2,
        "bundle_hash_verified": True,
        "executable_sha256": inspection.executable_sha256,
        "source_fingerprint": binding.source_fingerprint,
        "harness_run_id": binding.harness_run_id,
        "photos_frameworks_linked": 2,
        "read_write_authorized": True,
        "public_sentinel_leaks": 0,
    }


def _safe_diagnostics_text(diagnostics: dict[str, Any]) -> tuple[str, list[str]]:
    text = json.dumps(diagnostics, indent=2, sort_keys=True) + "\n"
    findings = sentinel_findings(
        text.encode(), "prospective evaluator diagnostics"
    )
    if findings:
        text = json.dumps(
            {
                "errors": [
                    "PhotoKit privacy sentinel detected; diagnostics redacted"
                ],
                "deterministic_command": TEST_COMMAND,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
    return text, findings


def _source_still_bound(root: Path, binding: SourceBinding) -> list[str]:
    try:
        current = repository_source_fingerprint(root)
    except OSError:
        return ["repository source fingerprint cannot be recomputed"]
    if current != binding.source_fingerprint:
        return ["repository source changed during PhotoKit evaluation"]
    return []


def _executable_still_bound(inspection: BundleInspection) -> list[str]:
    if not _path_is_regular_single_link(inspection.executable):
        return ["inspected native executable was replaced by an unsafe file"]
    try:
        current = sha256_file(inspection.executable)
    except OSError:
        return ["inspected native executable cannot be rehashed"]
    if current != inspection.executable_sha256:
        return ["source-built executable changed after inspection"]
    return []


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    if REQUIREMENT_ID not in selected:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    passing_path = evidence_dir / f"{REQUIREMENT_ID}.json"
    passing_path.unlink(missing_ok=True)

    nonce = secrets.token_hex(32)
    evaluator_run_id = f"p00-{secrets.token_hex(16)}"
    command_env = os.environ.copy()
    command_env[NONCE_ENV] = nonce

    deterministic_result = run_bounded_command(
        TEST_COMMAND,
        cwd=root,
        env=command_env,
        timeout_seconds=TEST_TIMEOUT_SECONDS,
    )
    deterministic, errors = validate_deterministic_command(
        deterministic_result, nonce
    )
    operator_challenge, challenge_errors = validate_operator_challenge(
        command_env, root
    )
    errors.extend(challenge_errors)
    binding, binding_errors = validate_source_binding(root, command_env)
    errors.extend(binding_errors)
    errors.extend(validate_gui_session())

    package_root: Path | None = None
    package_result: CommandResult | None = None
    inspection: BundleInspection | None = None
    runtime_challenge: dict[str, Any] | None = None
    output_dir: Path | None = None
    live_result: CommandResult | None = None
    live_records: list[dict[str, Any]] = []
    proof: LiveProof | None = None

    if not errors and operator_challenge is not None and binding is not None:
        package_root = make_package_root()
        app, package_result, package_errors = package_current_source(
            root, package_root, command_env
        )
        errors.extend(package_errors)
        if app is not None:
            inspection, inspection_errors = inspect_source_built_app(root, app)
            errors.extend(inspection_errors)
        errors.extend(_source_still_bound(root, binding))

    if not errors and inspection is not None and binding is not None:
        assert operator_challenge is not None
        assert package_root is not None
        output_dir = sandbox_output_directory_for_run(evaluator_run_id)
        runtime_challenge = make_runtime_challenge(
            operator_challenge,
            nonce=nonce,
            run_id=evaluator_run_id,
            binding=binding,
            executable_sha256=inspection.executable_sha256,
        )
        errors.extend(_executable_still_bound(inspection))
        errors.extend(validate_output_directory_absent(output_dir))
        if not errors:
            live_env = command_env.copy()
            live_env[NONCE_ENV] = nonce
            live_env[LIVE_CHALLENGE_ENV] = serialize_runtime_challenge(
                runtime_challenge
            )
            live_env.pop(FORBIDDEN_LIVE_APP_ENV, None)
            live_result = run_bounded_command(
                [
                    str(inspection.executable),
                    "--p00-photos-live-challenge",
                ],
                cwd=inspection.executable.parent,
                env=live_env,
                timeout_seconds=LIVE_TIMEOUT_SECONDS,
            )
            live_records, proof, live_errors = validate_live_command(
                live_result, nonce, runtime_challenge, inspection
            )
            errors.extend(live_errors)
            if proof is not None:
                errors.extend(
                    verify_live_outputs(
                        output_dir,
                        runtime_challenge,
                        proof,
                    )
                )
            errors.extend(_executable_still_bound(inspection))
            errors.extend(_source_still_bound(root, binding))

    private_roots = (output_dir,) if output_dir is not None else ()
    errors.extend(scan_artifacts(evidence_dir, private_roots=private_roots))
    if package_root is not None:
        errors.extend(scan_artifacts(package_root))

    if package_root is not None:
        try:
            shutil.rmtree(package_root)
        except OSError:
            errors.append("cannot remove evaluator-owned package directory")

    package_hash = (
        inspection.executable_sha256 if inspection is not None else None
    )
    diagnostics = {
        "errors": list(dict.fromkeys(errors)),
        "deterministic_command": TEST_COMMAND,
        "deterministic_exit_code": deterministic_result.returncode,
        "deterministic_output_bytes": deterministic_result.output_bytes,
        "deterministic_output_sha256": deterministic_result.output_sha256,
        "deterministic_record_count": len(deterministic),
        "source_bound": binding is not None,
        "source_fingerprint": (
            binding.source_fingerprint if binding is not None else None
        ),
        "package_executed": package_result is not None,
        "package_exit_code": (
            package_result.returncode if package_result is not None else None
        ),
        "package_output_sha256": (
            package_result.output_sha256
            if package_result is not None
            else None
        ),
        "executable_sha256": package_hash,
        "bundle_inspected": inspection is not None,
        "live_challenge_declared": bool(
            command_env.get(LIVE_CHALLENGE_ENV)
        ),
        "live_executed": live_result is not None,
        "live_exit_code": live_result.returncode if live_result else None,
        "live_output_bytes": live_result.output_bytes if live_result else 0,
        "live_output_sha256": (
            live_result.output_sha256 if live_result else None
        ),
        "live_record_count": len(live_records),
        "output_directory_was_fresh": (
            output_dir is not None and live_result is not None
        ),
    }
    diagnostics_text, diagnostic_findings = _safe_diagnostics_text(diagnostics)
    errors.extend(diagnostic_findings)
    (evidence_dir / "p00-photos-diagnostics.json").write_text(
        diagnostics_text, encoding="utf-8"
    )

    if errors:
        for error in dict.fromkeys(errors):
            if sentinel_findings(error.encode(), "evaluator error"):
                error = "PhotoKit privacy sentinel detected; detail redacted"
            print(f"P00 PhotoKit evaluation: {error}")
        return 1

    assert proof is not None
    assert binding is not None
    assert inspection is not None
    summary = public_summary(
        deterministic, nonce, proof, binding, inspection
    )
    payload = {
        "requirement_id": REQUIREMENT_ID,
        "status": "pass",
        "test": "tools.evaluators.p00_photos.evaluate",
        "recorded_at": utc_now(),
        "details": {
            "diagnostics": "p00-photos-diagnostics.json",
            "public_summary": summary,
        },
    }
    payload_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    findings = sentinel_findings(
        payload_text.encode(), "prospective passing evidence"
    )
    if findings:
        return 1
    passing_path.write_text(payload_text, encoding="utf-8")
    return 0
