"""Personal-MVP evaluator for the deferred P00 segmentation requirement."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import subprocess
import time
from typing import Any


REQUIREMENT_ID = "P00-SEG-001"
FALLBACK_REQUIREMENT_ID = "P00-GAT-001"
FALLBACK_REVISION = "rectangle_uniform_background_v1"
DEFERRED_REASON = "no_genuine_garment_segmentation_provider_available"

TEST_COMMAND = ["cargo", "test", "-p", "p00-segmentation"]
TEST_TIMEOUT_SECONDS = 5 * 60
MAX_CAPTURE_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024
MAX_SOURCE_BYTES = 256 * 1024

DIAGNOSTICS_NAME = "p00-segmentation-diagnostics.json"
FALLBACK_DECISION_NAME = "p00-segmentation-fallback-decision.json"
P04_DENY_NAME = "p04-automatic-segmentation-deny.json"

SOURCE_FILES = (
    "spikes/p00-segmentation/src/contract.rs",
    "spikes/p00-segmentation/src/dataset.rs",
    "spikes/p00-segmentation/src/fallback.rs",
    "spikes/p00-segmentation/src/candidate.rs",
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output_sha256: str
    output_bytes: int
    truncated: bool = False
    timed_out: bool = False
    launch_failed: bool = False


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
    """Run a real command while hashing all output and retaining none of it."""
    digest = hashlib.sha256()
    output_bytes = 0
    timed_out = False
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
            returncode=127,
            output_sha256=hashlib.sha256(b"").hexdigest(),
            output_bytes=0,
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
                output_bytes += len(chunk)
                digest.update(chunk)
                continue
        if process.poll() is not None:
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if chunk:
                output_bytes += len(chunk)
                digest.update(chunk)
                continue
            break

    process.stdout.close()
    return CommandResult(
        returncode=process.returncode,
        output_sha256=digest.hexdigest(),
        output_bytes=output_bytes,
        truncated=output_bytes > MAX_CAPTURE_BYTES,
        timed_out=timed_out,
    )


def _read_source(root: Path, relative: str) -> tuple[str, str | None]:
    path = root / relative
    try:
        data = path.read_bytes()
    except OSError:
        return "", f"required source is unreadable: {relative}"
    if len(data) > MAX_SOURCE_BYTES:
        return "", f"required source exceeds size limit: {relative}"
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return "", f"required source is not UTF-8: {relative}"


def _constant(text: str, name: str) -> int | None:
    match = re.search(
        rf"\bpub\s+const\s+{re.escape(name)}\s*:\s*usize\s*=\s*(\d+)\s*;",
        text,
    )
    return int(match.group(1)) if match else None


def validate_source_contract(root: Path) -> tuple[list[str], str]:
    """Check compact invariants that must remain true around the Rust tests."""
    sources: dict[str, str] = {}
    errors: list[str] = []
    digest = hashlib.sha256()
    for relative in SOURCE_FILES:
        text, error = _read_source(root, relative)
        if error:
            errors.append(error)
            continue
        sources[relative] = text
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(text.encode("utf-8"))
        digest.update(b"\0")
    if errors:
        return errors, digest.hexdigest()

    contract = sources[SOURCE_FILES[0]]
    dataset = sources[SOURCE_FILES[1]]
    fallback = sources[SOURCE_FILES[2]]
    candidate = sources[SOURCE_FILES[3]]

    provider_limit = _constant(contract, "MAX_PROVIDER_MASKS")
    if provider_limit is None:
        provider_limit = _constant(contract, "MAX_MASKS")
    if provider_limit != 8:
        errors.append("provider output capacity must be exactly eight masks")
    if _constant(dataset, "MAX_TRUTHS_PER_CASE") != 4 or not re.search(
        r"\btruths\.len\(\)\s*>\s*MAX_TRUTHS_PER_CASE\b",
        dataset,
    ):
        errors.append("dataset truth cardinality must remain bounded at four")

    expected_fallback = re.search(
        r'\bFALLBACK_ID\s*:\s*&str\s*=\s*"([^"]+)"', fallback
    )
    if not expected_fallback or expected_fallback.group(1) != FALLBACK_REVISION:
        errors.append("fallback revision constant is missing or inconsistent")
    if "needs_review: true" not in fallback:
        errors.append("fallback implementation does not require user review")

    if "coreml_garment_provider_slot_v1" not in candidate:
        errors.append("planned Core ML provider slot is missing")
    if "reviewed_model_pack_absent" not in candidate:
        errors.append("planned provider absence reason is missing")
    reviewed_state = candidate
    start = candidate.find("reviewed_state")
    end = candidate.find("pub fn validate", start)
    if start >= 0 and end > start:
        reviewed_state = candidate[start:end]
    if re.search(
        r"github\.com/example|https?://",
        reviewed_state,
        re.IGNORECASE,
    ):
        errors.append("planned provider contains a fake or remote source locator")
    required_unavailable_values = (
        r"\binvocations\s*:\s*0\b",
        r"\bsource_locator\s*:\s*None\b",
        r"\bmodel_revision\s*:\s*None\b",
        r"\blicense_decision\s*:\s*None\b",
        r"\bmeasurements\s*:\s*None\b",
    )
    if not all(
        re.search(pattern, reviewed_state)
        for pattern in required_unavailable_values
    ):
        errors.append("planned provider slot contains incomplete or fabricated state")

    return errors, digest.hexdigest()


def _command_errors(result: CommandResult) -> list[str]:
    errors: list[str] = []
    if result.launch_failed:
        errors.append("segmentation Rust tests could not start")
    elif result.timed_out:
        errors.append("segmentation Rust tests timed out")
    elif result.returncode != 0:
        errors.append("segmentation Rust tests failed")
    if result.truncated:
        errors.append("segmentation Rust test output exceeded the capture bound")
    return errors


def deferred_artifacts(
    result: CommandResult,
    source_sha256: str,
) -> dict[str, dict[str, Any]]:
    diagnostics = {
        "schema_version": 1,
        "status": "deferred",
        "requirement_id": REQUIREMENT_ID,
        "reason": DEFERRED_REASON,
        "fallback_revision": FALLBACK_REVISION,
        "fallback_smoke_test": "pass",
        "automatic_masks_enabled": False,
        "rust_test_command": TEST_COMMAND,
        "rust_test_exit_code": result.returncode,
        "rust_test_output_bytes": result.output_bytes,
        "rust_test_output_sha256": result.output_sha256,
        "source_contract_sha256": source_sha256,
        "pass_evidence_written": False,
    }
    fallback = {
        "schema_version": 1,
        "requirement_id": FALLBACK_REQUIREMENT_ID,
        "decision": "accepted_fallback",
        "fallback_revision": FALLBACK_REVISION,
        "all_outputs_need_review": True,
        "blocks_p01": False,
    }
    deny = {
        "schema_version": 1,
        "gate_id": "automatic_garment_segmentation",
        "automatic_masks_allowed": False,
        "reason": "no_genuine_provider_evaluated",
        "superseding_phase_required": "P04",
    }
    return {
        DIAGNOSTICS_NAME: diagnostics,
        FALLBACK_DECISION_NAME: fallback,
        P04_DENY_NAME: deny,
    }


def invalid_diagnostics(
    result: CommandResult,
    source_sha256: str,
    errors: list[str],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "invalid",
        "requirement_id": REQUIREMENT_ID,
        "reason": "implementation_validation_failed",
        "fallback_smoke_test": "fail",
        "automatic_masks_enabled": False,
        "errors": list(dict.fromkeys(errors)),
        "rust_test_command": TEST_COMMAND,
        "rust_test_exit_code": result.returncode,
        "rust_test_output_bytes": result.output_bytes,
        "rust_test_output_sha256": result.output_sha256,
        "source_contract_sha256": source_sha256,
        "pass_evidence_written": False,
    }


def validate_artifact_consistency(
    artifacts: dict[str, dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    if set(artifacts) != {
        DIAGNOSTICS_NAME,
        FALLBACK_DECISION_NAME,
        P04_DENY_NAME,
    }:
        return ["deferred artifact set is incomplete"]
    diagnostics = artifacts[DIAGNOSTICS_NAME]
    fallback = artifacts[FALLBACK_DECISION_NAME]
    deny = artifacts[P04_DENY_NAME]
    expected = (
        (diagnostics.get("status"), "deferred", "diagnostics status"),
        (diagnostics.get("requirement_id"), REQUIREMENT_ID, "requirement"),
        (diagnostics.get("reason"), DEFERRED_REASON, "deferred reason"),
        (diagnostics.get("fallback_smoke_test"), "pass", "fallback smoke"),
        (diagnostics.get("automatic_masks_enabled"), False, "automatic masks"),
        (diagnostics.get("pass_evidence_written"), False, "pass evidence"),
        (fallback.get("requirement_id"), FALLBACK_REQUIREMENT_ID, "fallback gate"),
        (fallback.get("decision"), "accepted_fallback", "fallback decision"),
        (fallback.get("all_outputs_need_review"), True, "fallback review"),
        (fallback.get("blocks_p01"), False, "P01 block"),
        (deny.get("gate_id"), "automatic_garment_segmentation", "P04 gate"),
        (deny.get("automatic_masks_allowed"), False, "automatic deny"),
        (deny.get("reason"), "no_genuine_provider_evaluated", "deny reason"),
        (deny.get("superseding_phase_required"), "P04", "superseding phase"),
    )
    for actual, wanted, label in expected:
        if type(actual) is not type(wanted) or actual != wanted:
            errors.append(f"{label} is inconsistent")
    revisions = {
        diagnostics.get("fallback_revision"),
        fallback.get("fallback_revision"),
    }
    if revisions != {FALLBACK_REVISION}:
        errors.append("fallback revisions are inconsistent")
    return errors


def _json_bytes(value: dict[str, Any]) -> bytes:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > MAX_ARTIFACT_BYTES:
        raise ValueError("segmentation artifact exceeds size limit")
    return data


def write_atomic_json(path: Path, value: dict[str, Any]) -> None:
    data = _json_bytes(value)
    temporary = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short artifact write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _remove_outputs(evidence_dir: Path) -> None:
    for name in (
        f"{REQUIREMENT_ID}.json",
        DIAGNOSTICS_NAME,
        FALLBACK_DECISION_NAME,
        P04_DENY_NAME,
    ):
        (evidence_dir / name).unlink(missing_ok=True)


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    if REQUIREMENT_ID not in selected:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    _remove_outputs(evidence_dir)
    result = run_bounded_command(
        TEST_COMMAND,
        cwd=root,
        env=os.environ.copy(),
        timeout_seconds=TEST_TIMEOUT_SECONDS,
    )
    source_errors, source_sha256 = validate_source_contract(root)
    errors = _command_errors(result) + source_errors
    if errors:
        diagnostics = invalid_diagnostics(
            result,
            source_sha256,
            errors,
        )
        write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        for error in errors:
            print(f"P00 segmentation evaluation: {error}")
        return 1

    artifacts = deferred_artifacts(result, source_sha256)
    consistency_errors = validate_artifact_consistency(artifacts)
    if consistency_errors:
        diagnostics = invalid_diagnostics(
            result,
            source_sha256,
            consistency_errors,
        )
        write_atomic_json(evidence_dir / DIAGNOSTICS_NAME, diagnostics)
        for error in consistency_errors:
            print(f"P00 segmentation evaluation: {error}")
        return 1

    for name, value in artifacts.items():
        write_atomic_json(evidence_dir / name, value)
    print(
        "P00 segmentation evaluation: deferred because no genuine garment "
        "segmentation provider is available; review-required fallback passed"
    )
    return 1
