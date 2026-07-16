"""Fail-closed evaluator for the approved P09 aggregate acceptance packet."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools import p09_acceptance_smoke  # noqa: E402
from tools.evaluators.p03_receipts import write_atomic_json  # noqa: E402
from tools.harness import source_fingerprint  # noqa: E402


RUN_ID = p09_acceptance_smoke.RUN_ID
PACKET_DIR = f"artifacts/harness/P09/{RUN_ID}"
STATE_FILE = f"{PACKET_DIR}/state.json"
DIAGNOSTICS_NAME = "p09-acceptance-evaluator.json"
REQUIREMENT_IDS = frozenset(p09_acceptance_smoke.REQUIREMENT_IDS)
TRIGGER_REQUIREMENT_IDS = frozenset({"P09-ACC-001"})
DEFERRED_REQUIREMENT_IDS: frozenset[str] = frozenset()

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024
MAX_PUBLIC_FIELDS = 32
COMMAND_TIMEOUT_SECONDS = 25 * 60

EXPECTED_PACKET_HASHES = {
    "specs/system.md": (
        "1cb32b71698c8accfafa34dab8c73eb47e047a49ccc6f2ac0b25734e1d8d1546"
    ),
    "specs/phases/P09-hardening.md": (
        "b88c11b3f97bf7936f19cc6f6e187268eeb0c6a6c11f12de17ed2edf36455846"
    ),
    f"{PACKET_DIR}/requirements.json": (
        "d5c05077c28c89db512138eb4600d9ed174f925ecae88514c8928d0c49989300"
    ),
    f"{PACKET_DIR}/proposal.md": (
        "7110e657d980e8f02f6561959b4bb85d964cb69a4ac8fa07cc620ac8297dbe00"
    ),
    f"{PACKET_DIR}/review.md": (
        "386e173d7406a512cf64b06eb7e8b64f093b3ecb1b1b24e3502ccb4f537d64a3"
    ),
}

REQUIRED_SOURCE_FILES = (
    "tools/p09_acceptance_smoke.py",
    "tools/evaluators/p09_acceptance.py",
    "tools/harness.py",
    "tools/p09_offline_smoke.py",
    "tools/p09_supply_chain_smoke.py",
    "tools/release_supply_chain.py",
    "tests/test_p09_acceptance_smoke.py",
    "tests/test_p09_acceptance_evaluator.py",
    "tests/test_harness.py",
    "crates/wardrobe-platform/src/database.rs",
    "crates/wardrobe-platform/src/restore_repository.rs",
    "crates/wardrobe-platform/src/deletion_repository.rs",
    "crates/wardrobe-platform/src/credential.rs",
    "crates/wardrobe-platform/src/imports.rs",
    "crates/wardrobe-platform/src/receipt_parser.rs",
    "crates/wardrobe-platform/src/receipt_image_downloader.rs",
    "crates/wardrobe-platform/src/update_package.rs",
    "crates/wardrobe-core/tests/catalog_service.rs",
    "crates/wardrobe-core/tests/receipt_service.rs",
    "src-tauri/src/lib.rs",
    "apps/desktop-ui/src/App.tsx",
)

EXPECTED_SUITES = p09_acceptance_smoke.EXPECTED_SUITE_NAMES


def run_bounded_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
    capture_output: bool = False,
) -> p09_acceptance_smoke.CommandOutcome:
    del capture_output
    return p09_acceptance_smoke.run_command(
        p09_acceptance_smoke.CommandSpec(
            logical=("python3", "tools/p09_acceptance_smoke.py"),
            actual=tuple(command),
            required_markers=(),
        ),
        cwd,
        env,
        timeout_seconds,
    )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


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
            value = handle.read(limit + 1)
    except OSError:
        return None
    return value if len(value) <= limit else None


def _json_object(value: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _aggregate(contents: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for relative, value in sorted(contents.items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(value)
        digest.update(b"\0")
    return digest.hexdigest()


def validate_packet(root: Path) -> tuple[list[str], str]:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    for relative, expected in EXPECTED_PACKET_HASHES.items():
        value = _read_regular(root / relative)
        if value is None:
            errors.append(f"frozen packet file is unreadable or unsafe: {relative}")
            continue
        contents[relative] = value
        if _sha256(value) != expected:
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
    if (
        requirements.get("phase") != "P09"
        or requirements.get("selected_requirement_ids") != ["P09-ACC-001"]
        or evidenced != REQUIREMENT_IDS
    ):
        errors.append("frozen P09 acceptance requirement contract is invalid")

    state_data = _read_regular(root / STATE_FILE)
    state = _json_object(state_data or b"")
    review = state.get("review")
    if (
        state_data is None
        or state.get("phase") != "P09"
        or state.get("run_id") != RUN_ID
        or state.get("status")
        not in {"APPROVED", "BUILT", "EVALUATED", "EVALUATION_FAILED"}
        or state.get("selected_requirement_ids") != ["P09-ACC-001"]
        or not isinstance(review, dict)
        or review.get("decision") != "APPROVE"
        or review.get("proposal_hash")
        != EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"]
        or state.get("spec_hashes")
        != {
            "specs/phases/P09-hardening.md": EXPECTED_PACKET_HASHES[
                "specs/phases/P09-hardening.md"
            ],
            "specs/system.md": EXPECTED_PACKET_HASHES["specs/system.md"],
        }
    ):
        errors.append("P09 acceptance packet is not independently approved")
    review_text = contents.get(f"{PACKET_DIR}/review.md", b"").decode(
        errors="replace"
    )
    if "Status: APPROVED" not in review_text or "\nAPPROVE\n" not in review_text:
        errors.append("approved P09 acceptance review decision is missing")
    return list(dict.fromkeys(errors)), _aggregate(contents)


def validate_source(root: Path) -> tuple[list[str], str, int]:
    errors: list[str] = []
    contents: dict[str, bytes] = {}
    for relative in REQUIRED_SOURCE_FILES:
        value = _read_regular(root / relative)
        if value is None:
            errors.append(
                f"required P09 acceptance source is unreadable or unsafe: {relative}"
            )
        else:
            contents[relative] = value
    smoke_text = contents.get("tools/p09_acceptance_smoke.py", b"").decode(
        errors="replace"
    )
    harness_text = contents.get("tools/harness.py", b"").decode(
        errors="replace"
    )
    if (
        "P09ReleaseEvidence.bundle" not in smoke_text
        or "renameatx_np" not in smoke_text
        or "Signature=adhoc" not in smoke_text
        or "deferred_not_passed" not in smoke_text
        or "P09-ACC-001" not in harness_text
        or "tools/evaluators/p09_acceptance.py" not in harness_text
    ):
        errors.append("P09 acceptance source contract is incomplete")
    return list(dict.fromkeys(errors)), _aggregate(contents), len(contents)


def _validate_payload(
    root: Path,
    validation: p09_acceptance_smoke.BundleValidation,
) -> list[str]:
    payload = validation.payload
    errors: list[str] = []
    try:
        p09_acceptance_smoke._validate_signed_payload(payload)
    except p09_acceptance_smoke.AcceptanceFailure as error:
        errors.append(str(error))
    if payload.get("source_fingerprint") != source_fingerprint():
        errors.append("signed acceptance payload is not current-source evidence")
    packet_hashes = payload.get("packet_hashes")
    if packet_hashes != {
        "proposal.md": EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/proposal.md"],
        "requirements.json": EXPECTED_PACKET_HASHES[
            f"{PACKET_DIR}/requirements.json"
        ],
        "review.md": EXPECTED_PACKET_HASHES[f"{PACKET_DIR}/review.md"],
    }:
        errors.append("signed acceptance payload packet hashes are invalid")
    suites = payload.get("suites")
    if (
        not isinstance(suites, list)
        or [row.get("name") for row in suites if isinstance(row, dict)]
        != list(EXPECTED_SUITES)
    ):
        errors.append("signed acceptance suite inventory is not exact")
    else:
        for suite in suites:
            if (
                not isinstance(suite, dict)
                or suite.get("status") != "pass"
                or not isinstance(suite.get("budget_ns"), int)
                or isinstance(suite.get("budget_ns"), bool)
                or not isinstance(suite.get("duration_ns"), int)
                or isinstance(suite.get("duration_ns"), bool)
                or suite["duration_ns"] < 0
                or suite["duration_ns"] > suite["budget_ns"]
                or not isinstance(suite.get("commands"), list)
                or not suite["commands"]
            ):
                errors.append("signed acceptance suite result is invalid")
                break
            for command in suite["commands"]:
                if (
                    not isinstance(command, dict)
                    or set(command)
                    != {
                        "command",
                        "duration_ns",
                        "executable_sha256",
                        "exit_code",
                        "output_bytes",
                        "output_limit_exceeded",
                        "output_sha256",
                        "timed_out",
                    }
                    or command.get("exit_code") != 0
                    or command.get("timed_out") is not False
                    or command.get("output_limit_exceeded") is not False
                    or not isinstance(command.get("command"), list)
                    or not command["command"]
                    or any(
                        not isinstance(part, str)
                        or not part
                        or Path(part).is_absolute()
                        or str(Path.home()) in part
                        for part in command["command"]
                    )
                    or not isinstance(command.get("output_bytes"), int)
                    or not isinstance(command.get("duration_ns"), int)
                    or re.fullmatch(
                        r"[0-9a-f]{64}",
                        command.get("output_sha256", ""),
                    )
                    is None
                    or re.fullmatch(
                        r"[0-9a-f]{64}",
                        command.get("executable_sha256", ""),
                    )
                    is None
                ):
                    errors.append("signed acceptance command result is invalid")
                    break

    application = payload.get("application")
    current_application: dict[str, Any] = {}
    try:
        current_application = p09_acceptance_smoke._application_identity(root)
    except (OSError, p09_acceptance_smoke.AcceptanceFailure) as error:
        errors.append(f"current production package cannot be verified: {error}")
    else:
        if application != current_application:
            errors.append("signed acceptance package identity is stale")

    packaged = payload.get("packaged_workflow")
    if (
        not isinstance(packaged, dict)
        or packaged.get("network_denied_for_process_tree") is not True
        or packaged.get("accessibility_automation_used") is not True
        or packaged.get("browser_mock_used") is not False
        or packaged.get("bundle_sha256")
        != current_application.get("bundle_sha256", "")
    ):
        errors.append("signed packaged workflow evidence is invalid")
    supply = payload.get("supply_chain")
    if (
        not isinstance(supply, dict)
        or supply.get("network_sandbox_enforced") is not True
        or supply.get("remote_model_code_allowed") is not False
        or supply.get("model_artifact_count") != 0
        or supply.get("bundle_sha256")
        != current_application.get("bundle_sha256", "")
    ):
        errors.append("signed supply-chain evidence is invalid")
    privacy = payload.get("privacy")
    if privacy != {
        "absolute_host_paths_included": False,
        "browser_mock_used_for_packaged_e2e": False,
        "personal_source_content_included": False,
        "private_credentials_used": False,
        "raw_command_output_included": False,
    }:
        errors.append("signed acceptance privacy declaration is invalid")
    signature = payload.get("local_signature")
    if signature != {
        "external_signer_identity": False,
        "kind": "macos_adhoc_codesign",
        "whole_bundle_integrity": True,
    }:
        errors.append("signed acceptance local-signature declaration is invalid")
    return list(dict.fromkeys(errors))


def _public_summary(
    validation: p09_acceptance_smoke.BundleValidation,
    packet_sha256: str,
    source_sha256: str,
    source_file_count: int,
) -> dict[str, str | bool | int]:
    payload = validation.payload
    summary: dict[str, str | bool | int] = {
        "profile": "personal_mvp",
        "feature_enabled": True,
        "acceptance_claim": "personal_mvp_production_acceptance_passed",
        "packet_sha256": packet_sha256,
        "source_sha256": source_sha256,
        "source_file_count": source_file_count,
        "source_fingerprint": payload["source_fingerprint"],
        "bundle_tree_sha256": validation.tree_sha256,
        "payload_sha256": validation.payload_sha256,
        "bundle_file_count": validation.file_count,
        "suite_count": len(payload["suites"]),
        "requirement_count": len(payload["requirements"]),
        "performance_budgets_passed": True,
        "packaged_app_tested": True,
        "network_denied_for_process_tree": True,
        "accessibility_automation_used": True,
        "browser_mock_used_for_packaged_e2e": False,
        "local_adhoc_signed": True,
        "developer_id_signed": False,
        "notarized": False,
        "clean_machine_certified": False,
        "genuine_segmentation_pack_tested": False,
        "live_external_credentials_tested": False,
        "external_limitations_claim": "deferred_not_passed",
    }
    if len(summary) > MAX_PUBLIC_FIELDS:
        raise ValueError("P09 acceptance public summary is oversized")
    return summary


def _verification_hash(
    requirement_id: str,
    validation: p09_acceptance_smoke.BundleValidation,
    packet_sha256: str,
    source_sha256: str,
) -> str:
    return _sha256(
        p09_acceptance_smoke.canonical_json(
            {
                "requirement_id": requirement_id,
                "bundle_tree_sha256": validation.tree_sha256,
                "payload_sha256": validation.payload_sha256,
                "packet_sha256": packet_sha256,
                "source_sha256": source_sha256,
            }
        )
    )


def _write_bounded(path: Path, value: dict[str, Any]) -> None:
    encoded = p09_acceptance_smoke.canonical_json(value)
    if len(encoded) > MAX_ARTIFACT_BYTES:
        raise ValueError("P09 acceptance evaluator artifact is oversized")
    write_atomic_json(path, value)


def _assert_clean_outputs(evidence_dir: Path) -> None:
    owned = {
        p09_acceptance_smoke.BUNDLE_NAME,
        p09_acceptance_smoke.ROUTING_DIRECTORY_NAME,
        DIAGNOSTICS_NAME,
        *(f"{requirement_id}.json" for requirement_id in REQUIREMENT_IDS),
    }
    existing = [
        entry.name
        for entry in evidence_dir.iterdir()
        if entry.name in owned
        or entry.name.startswith(
            f".{p09_acceptance_smoke.ROUTING_DIRECTORY_NAME}."
        )
    ]
    if existing:
        raise ValueError("P09 acceptance output inventory is not empty")


def _routing_record(
    requirement_id: str,
    *,
    recorded_at: str,
    validation: p09_acceptance_smoke.BundleValidation,
    packet_sha256: str,
    source_sha256: str,
    public_summary: dict[str, str | bool | int],
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "status": "pass",
        "test": "p09_acceptance::locally_signed_personal_mvp_release_bundle",
        "recorded_at": recorded_at,
        "details": {
            "verification_sha256": _verification_hash(
                requirement_id,
                validation,
                packet_sha256,
                source_sha256,
            ),
            "bundle_name": p09_acceptance_smoke.BUNDLE_NAME,
            "bundle_tree_sha256": validation.tree_sha256,
            "payload_sha256": validation.payload_sha256,
            "public_summary": public_summary,
        },
    }


def _publish_routing_directory(
    evidence_dir: Path,
    *,
    diagnostic: dict[str, Any],
    recorded_at: str,
    validation: p09_acceptance_smoke.BundleValidation,
    packet_sha256: str,
    source_sha256: str,
    source_file_count: int,
) -> None:
    destination = evidence_dir / p09_acceptance_smoke.ROUTING_DIRECTORY_NAME
    if destination.exists() or destination.is_symlink():
        raise ValueError("P09 acceptance routing directory already exists")
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{p09_acceptance_smoke.ROUTING_DIRECTORY_NAME}.",
            dir=evidence_dir,
        )
    )
    os.chmod(temporary, 0o700)
    renamed = False
    try:
        _write_bounded(temporary / DIAGNOSTICS_NAME, diagnostic)
        public_summary = _public_summary(
            validation,
            packet_sha256,
            source_sha256,
            source_file_count,
        )
        for requirement_id in p09_acceptance_smoke.REQUIREMENT_IDS:
            _write_bounded(
                temporary / f"{requirement_id}.json",
                _routing_record(
                    requirement_id,
                    recorded_at=recorded_at,
                    validation=validation,
                    packet_sha256=packet_sha256,
                    source_sha256=source_sha256,
                    public_summary=public_summary,
                ),
            )
        p09_acceptance_smoke._fsync_tree(temporary)
        p09_acceptance_smoke._rename_exclusive(temporary, destination)
        renamed = True
        parent = os.open(evidence_dir, os.O_RDONLY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if not renamed and temporary.exists():
            shutil.rmtree(temporary)


def evaluate(
    root: Path,
    evidence_dir: Path,
    selected: set[str],
) -> int:
    if not (selected & TRIGGER_REQUIREMENT_IDS):
        return 0
    evidence_dir.mkdir(parents=True, exist_ok=True)
    recorded_at = utc_now()
    failures: list[str] = []
    packet_errors, packet_sha256 = validate_packet(root)
    source_errors, source_sha256, source_file_count = validate_source(root)
    failures.extend(packet_errors)
    failures.extend(source_errors)
    if selected & TRIGGER_REQUIREMENT_IDS != TRIGGER_REQUIREMENT_IDS:
        failures.append("selected P09 acceptance requirement ID is incomplete")
    if selected - REQUIREMENT_IDS:
        failures.append("P09 acceptance evaluator received unsupported requirements")
    try:
        _assert_clean_outputs(evidence_dir)
    except ValueError as error:
        failures.append(str(error))

    command_summary: dict[str, Any] = {}
    validation: p09_acceptance_smoke.BundleValidation | None = None
    if not failures:
        environment = p09_acceptance_smoke.clean_environment()
        environment.update(
            {
                "HARNESS_RUN_DIR": str(evidence_dir.parent),
                "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                "HARNESS_PHASE": "P09",
                "HARNESS_RUN_ID": RUN_ID,
            }
        )
        result = run_bounded_command(
            [sys.executable, str(root / "tools/p09_acceptance_smoke.py")],
            cwd=root,
            env=environment,
            timeout_seconds=COMMAND_TIMEOUT_SECONDS,
            capture_output=True,
        )
        duration_ms = (
            result.duration_ms
            if hasattr(result, "duration_ms")
            else result.duration_ns // 1_000_000
        )
        command_summary = {
            "returncode": result.returncode,
            "duration_ms": duration_ms,
            "output_bytes": result.output_bytes,
            "output_sha256": result.output_sha256,
            "timed_out": result.timed_out,
            "output_limit_exceeded": result.output_limit_exceeded,
            "launch_failed": result.launch_failed,
            "cleanup_failed": getattr(result, "cleanup_failed", False),
        }
        if (
            result.returncode != 0
            or result.timed_out
            or result.output_limit_exceeded
            or result.launch_failed
            or getattr(result, "cleanup_failed", False)
        ):
            failures.append("P09 acceptance runner failed")
        else:
            try:
                validation = p09_acceptance_smoke.validate_bundle(
                    evidence_dir / p09_acceptance_smoke.BUNDLE_NAME
                )
            except (OSError, p09_acceptance_smoke.AcceptanceFailure) as error:
                failures.append(f"signed acceptance bundle is invalid: {error}")
            else:
                failures.extend(_validate_payload(root, validation))

    diagnostic = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "recorded_at": recorded_at,
        "status": "pass" if not failures else "fail",
        "failures": list(dict.fromkeys(failures)),
        "packet_sha256": packet_sha256,
        "source_sha256": source_sha256,
        "source_file_count": source_file_count,
        "command": command_summary,
        "bundle_tree_sha256": validation.tree_sha256 if validation else None,
        "payload_sha256": validation.payload_sha256 if validation else None,
    }
    if failures or validation is None:
        try:
            _write_bounded(evidence_dir / DIAGNOSTICS_NAME, diagnostic)
        except (OSError, ValueError):
            pass
        return 1

    try:
        _publish_routing_directory(
            evidence_dir,
            diagnostic=diagnostic,
            recorded_at=recorded_at,
            validation=validation,
            packet_sha256=packet_sha256,
            source_sha256=source_sha256,
            source_file_count=source_file_count,
        )
    except (
        OSError,
        ValueError,
        p09_acceptance_smoke.AcceptanceFailure,
    ):
        return 1
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
    snapshot_path = Path(run_dir) / "requirements.json"
    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("P09 acceptance requirements snapshot is unreadable", file=sys.stderr)
        return 2
    selected = set(snapshot.get("selected_requirement_ids", []))
    result = evaluate(REPOSITORY_ROOT, Path(evidence_dir), selected)
    if result:
        print("P09 acceptance evaluation failed", file=sys.stderr)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
