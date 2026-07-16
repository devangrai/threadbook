#!/usr/bin/env python3
"""Run and publish the current-code P09 personal-MVP acceptance bundle."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Sequence

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools import p09_supply_chain_smoke  # noqa: E402
from tools.evaluators import p09_offline, p09_supply_chain  # noqa: E402
from tools.harness import sha256_file, source_fingerprint  # noqa: E402


RUN_ID = "20260716T062700Z-4487ef2e"
BUNDLE_NAME = "P09ReleaseEvidence.bundle"
ROUTING_DIRECTORY_NAME = "P09AcceptanceRouting"
BUNDLE_RELATIVE = Path("target/release/bundle/macos/Wardrobe.app")
EXECUTABLE_RELATIVE = BUNDLE_RELATIVE / "Contents/MacOS/wardrobe-desktop"
SUPPLY_MANIFEST_RELATIVE = Path(
    "release/generated/supply-chain-manifest-v1.json"
)
PAYLOAD_RELATIVE = Path("Contents/Resources/release-evidence-v1.json")
INFO_RELATIVE = Path("Contents/Info.plist")
SIGNATURE_RELATIVE = Path("Contents/_CodeSignature/CodeResources")
EXPECTED_BUNDLE_FILES = frozenset(
    {
        str(INFO_RELATIVE),
        str(PAYLOAD_RELATIVE),
        str(SIGNATURE_RELATIVE),
        "Contents/_CodeSignature/CodeDirectory",
        "Contents/_CodeSignature/CodeRequirements",
        "Contents/_CodeSignature/CodeRequirements-1",
        "Contents/_CodeSignature/CodeSignature",
    }
)

MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_FILES = 128
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_COMMANDS = 64
MAX_COMMAND_PART_BYTES = 256
MAX_REQUIREMENTS = 14
MAX_LIMITATIONS = 5
PACKAGE_SIZE_BUDGET_BYTES = 250 * 1024 * 1024
EXPECTED_SUITE_NAMES = (
    "migration_rollback",
    "restore",
    "deletion",
    "user_authority",
    "security",
    "packaged_offline_accessibility_e2e",
    "supply_chain_package",
)

CODESIGN = Path("/usr/bin/codesign")
RENAME_EXCL = 0x00000004
AT_FDCWD = -2
SECRET_ENV_NAMES = frozenset(
    {
        "OPENAI_API_KEY",
        "GMAIL_CLIENT_SECRET",
        "GMAIL_REFRESH_TOKEN",
        "GOOGLE_CLIENT_SECRET",
        "NPM_TOKEN",
        "NODE_AUTH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    }
)

REQUIREMENT_IDS = (
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
    "P09-ACC-001",
)

LIMITATIONS = (
    (
        "developer_id_signing",
        "Developer ID identity and hardened-runtime distribution certification "
        "are not available on this host.",
    ),
    (
        "notarization",
        "Apple notarization, stapling, and Gatekeeper distribution acceptance "
        "were not run.",
    ),
    (
        "clean_machine_certification",
        "A clean supported Mac installation certification was not run.",
    ),
    (
        "genuine_segmentation_model",
        "No genuine local segmentation model pack or private quality study is "
        "available; reviewed source-crop fallbacks remain active.",
    ),
    (
        "live_external_credentials",
        "Live Gmail, OpenAI, and Photos credentials and paid-provider quality "
        "studies were not used.",
    ),
)


class AcceptanceFailure(RuntimeError):
    pass


class PublicationOutcomeUnknown(AcceptanceFailure):
    pass


@dataclass(frozen=True)
class CommandSpec:
    logical: tuple[str, ...]
    actual: tuple[str, ...]
    required_markers: tuple[str, ...]
    environment: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class SuiteSpec:
    name: str
    budget_seconds: int
    commands: tuple[CommandSpec, ...]


@dataclass(frozen=True)
class CommandOutcome:
    returncode: int
    output_sha256: str
    output_bytes: int
    duration_ns: int
    captured_output: bytes
    timed_out: bool = False
    output_limit_exceeded: bool = False
    launch_failed: bool = False
    cleanup_failed: bool = False


@dataclass(frozen=True)
class BundleValidation:
    payload: dict[str, Any]
    payload_sha256: str
    tree_sha256: str
    file_count: int
    total_bytes: int


Runner = Callable[
    [CommandSpec, Path, dict[str, str], float],
    CommandOutcome,
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _signal_process_group(process: subprocess.Popen[bytes], value: int) -> bool:
    try:
        os.killpg(process.pid, value)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _terminate(process: subprocess.Popen[bytes]) -> bool:
    _signal_process_group(process, signal.SIGTERM)
    deadline = time.monotonic() + 1.0
    while process.poll() is None and time.monotonic() < deadline:
        try:
            process.wait(timeout=0.05)
        except subprocess.TimeoutExpired:
            pass

    # The parent may already be gone while descendants still retain the pipe.
    _signal_process_group(process, signal.SIGKILL)
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        return False
    return True


def run_command(
    specification: CommandSpec,
    cwd: Path,
    base_environment: dict[str, str],
    timeout_seconds: float,
) -> CommandOutcome:
    environment = base_environment.copy()
    environment.update(dict(specification.environment))
    digest = hashlib.sha256()
    captured = bytearray()
    output_bytes = 0
    timed_out = False
    output_limit_exceeded = False
    cleanup_failed = False
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            list(specification.actual),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        return CommandOutcome(
            returncode=127,
            output_sha256=hashlib.sha256(b"").hexdigest(),
            output_bytes=0,
            duration_ns=time.monotonic_ns() - started,
            captured_output=b"",
            launch_failed=True,
        )

    assert process.stdout is not None
    os.set_blocking(process.stdout.fileno(), False)
    deadline_ns = started + int(timeout_seconds * 1_000_000_000)
    process_group_cleaned = False
    drain_deadline_ns: int | None = None
    while True:
        remaining_ns = deadline_ns - time.monotonic_ns()
        if remaining_ns <= 0 and process.poll() is None:
            timed_out = True
            cleanup_failed = not _terminate(process)
            process_group_cleaned = True
            drain_deadline_ns = time.monotonic_ns() + 3_000_000_000
        wait_seconds = max(0.0, remaining_ns / 1_000_000_000)
        readable, _, _ = select.select(
            [process.stdout],
            [],
            [],
            0 if process.poll() is not None else min(0.25, wait_seconds),
        )
        if readable:
            try:
                chunk = os.read(process.stdout.fileno(), 64 * 1024)
            except BlockingIOError:
                chunk = None
            if chunk:
                output_bytes += len(chunk)
                digest.update(chunk)
                remaining_capture = MAX_COMMAND_OUTPUT_BYTES - len(captured)
                if remaining_capture > 0:
                    captured.extend(chunk[:remaining_capture])
                if output_bytes > MAX_COMMAND_OUTPUT_BYTES:
                    output_limit_exceeded = True
                    if process.poll() is None:
                        cleanup_failed = not _terminate(process)
                        process_group_cleaned = True
                        drain_deadline_ns = (
                            time.monotonic_ns() + 3_000_000_000
                        )
                continue
            if chunk == b"" and process.poll() is not None:
                break
        if process.poll() is not None:
            if not process_group_cleaned:
                _signal_process_group(process, signal.SIGKILL)
                process_group_cleaned = True
                drain_deadline_ns = time.monotonic_ns() + 3_000_000_000
            if drain_deadline_ns is not None and time.monotonic_ns() > drain_deadline_ns:
                cleanup_failed = True
                break
            time.sleep(0.01)
    process.stdout.close()
    return CommandOutcome(
        returncode=process.returncode,
        output_sha256=digest.hexdigest(),
        output_bytes=output_bytes,
        duration_ns=time.monotonic_ns() - started,
        captured_output=bytes(captured),
        timed_out=timed_out,
        output_limit_exceeded=output_limit_exceeded,
        cleanup_failed=cleanup_failed,
    )


def _executable(command: str) -> str:
    resolved = shutil.which(command)
    if resolved is None:
        raise AcceptanceFailure(f"required executable is unavailable: {command}")
    # Preserve toolchain proxy names such as ~/.cargo/bin/cargo -> rustup.
    # Their argv[0] selects the delegated tool.
    return str(Path(resolved).absolute())


def _python_command(
    root: Path,
    relative_script: str,
    logical_arguments: Sequence[str],
    actual_arguments: Sequence[str],
    *markers: str,
) -> CommandSpec:
    return CommandSpec(
        logical=("python3", relative_script, *logical_arguments),
        actual=(
            str(Path(sys.executable).resolve()),
            str((root / relative_script).resolve()),
            *actual_arguments,
        ),
        required_markers=tuple(markers),
    )


def _cargo_command(
    root: Path,
    arguments: Sequence[str],
    *markers: str,
    environment: tuple[tuple[str, str], ...] = (),
) -> CommandSpec:
    del root
    return CommandSpec(
        logical=("cargo", *arguments),
        actual=(_executable("cargo"), *arguments),
        required_markers=tuple(markers),
        environment=environment,
    )


def _focused_test(
    root: Path,
    package: str,
    test_name: str,
    *,
    target: tuple[str, str] = ("--lib", ""),
    ignored: bool = False,
    environment: tuple[tuple[str, str], ...] = (),
) -> CommandSpec:
    target_flag, target_name = target
    arguments = ["test", "-p", package, "--offline"]
    if target_flag == "--lib":
        arguments.append("--lib")
    else:
        arguments.extend((target_flag, target_name))
    arguments.extend((test_name, "--", "--test-threads=1"))
    if ignored:
        arguments.append("--ignored")
    return _cargo_command(
        root,
        arguments,
        test_name.split("::")[-1],
        "test result: ok",
        environment=environment,
    )


def _suite_specs(
    root: Path,
    work: Path,
) -> tuple[SuiteSpec, ...]:
    offline_report = work / "offline-report.json"
    supply_report = work / "supply-report.json"
    offline_relative = "acceptance-work/offline-report.json"
    supply_relative = "acceptance-work/supply-report.json"

    migration = SuiteSpec(
        "migration_rollback",
        120,
        (
            _cargo_command(
                root,
                (
                    "test",
                    "-p",
                    "wardrobe-platform",
                    "--offline",
                    "--lib",
                    "database::tests::",
                    "--",
                    "--test-threads=1",
                ),
                "migration_0013_preserves_v12_disconnect_rows_and_extends_one_outcome_domain",
                "interrupted_migration_0013_rolls_back_to_complete_v12",
                "rejects_applied_checksum_tampering",
                "test result: ok",
            ),
        ),
    )
    restore = SuiteSpec(
        "restore",
        120,
        (
            _cargo_command(
                root,
                (
                    "test",
                    "-p",
                    "wardrobe-platform",
                    "--offline",
                    "--lib",
                    "restore_repository::tests::",
                    "--",
                    "--test-threads=1",
                ),
                "child_process_restart_restores_catalog_assets_and_database_family",
                "rejects_checksummed_intent_tampering_before_live_changes",
                "empty_rollback_directory_never_removes_live_database_family",
                "test result: ok",
            ),
            _focused_test(
                root,
                "wardrobe-desktop",
                "backup_commands_prepare_and_apply_a_real_restart_restore",
            ),
        ),
    )
    deletion = SuiteSpec(
        "deletion",
        120,
        (
            _cargo_command(
                root,
                (
                    "test",
                    "-p",
                    "wardrobe-platform",
                    "--offline",
                    "--lib",
                    "deletion_repository::tests::hard_deletion_",
                    "--",
                    "--test-threads=1",
                ),
                "hard_deletion_schema_inventory_and_blob_classification",
                "hard_deletion_trigger_authority_requires_exact_key",
                "hard_deletion_compiled_sqlite_filesystem_restart_residual_smoke",
                "test result: ok",
            ),
        ),
    )
    authority = SuiteSpec(
        "user_authority",
        90,
        (
            _focused_test(
                root,
                "wardrobe-core",
                "automated_rerun_cannot_clear_a_user_review_head",
                target=("--test", "receipt_service"),
            ),
            _focused_test(
                root,
                "wardrobe-core",
                "imports_advance_evidence_generation_without_advancing_catalog_revision",
                target=("--test", "catalog_service"),
            ),
            _focused_test(
                root,
                "wardrobe-core",
                "stale_catalog_cas_is_rejected_without_a_decision_or_projection_write",
                target=("--test", "catalog_service"),
            ),
        ),
    )

    security_commands = (
        _focused_test(
            root,
            "wardrobe-core",
            "requests_reject_unknown_fields_and_non_v1_versions",
            target=("--test", "contracts"),
        ),
        _focused_test(
            root,
            "wardrobe-core",
            "tool_arguments_and_results_reject_unknown_or_unbounded_data",
            target=("--test", "recommendation_contracts"),
        ),
        _focused_test(
            root,
            "wardrobe-core",
            "service_rejects_bad_artifact_hashes_and_replay_headers",
            target=("--test", "photo_analysis_service"),
        ),
        _focused_test(
            root,
            "wardrobe-core",
            "malformed_provider_output_is_rejected_before_persistence",
            target=("--test", "receipt_service"),
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "parser_accepts_real_mime_and_rejects_unbounded_headers",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "parser_is_stable_and_attachment_bytes_do_not_enter_fragments",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "parser_enforces_raw_header_and_fragment_bounds",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "sanitizer_removes_active_and_hidden_content_but_preserves_visible_data",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "injection_text_is_data_and_cannot_create_output_lines",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "parser_extracts_bounded_inert_candidates_without_evidence_leakage",
            target=("--test", "receipt_image_downloader"),
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "production_policy_rejects_special_ranges_and_allows_global_unicast",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "structural_validators_reject_trailing_and_animated_payloads",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "valid_png_derivative_is_deterministic_and_metadata_free",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "png_validator_rejects_apng_control_chunks",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "production_policy_rejects_mixed_and_metadata_answers",
            target=("--test", "receipt_image_downloader"),
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "cross_host_redirect_is_rejected_before_alternate_dns",
            target=("--test", "receipt_image_downloader"),
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "invalid_credentials_references_and_counts_fail_before_network_io",
            target=("--test", "try_on_http"),
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "hard_deletion_filesystem_rejects_dangling_symlink_directory_and_hard_link",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "malformed_framing_and_json_corpus_fails_without_publication",
        ),
        _focused_test(
            root,
            "wardrobe-desktop",
            "malformed_requests_return_only_structured_command_errors",
        ),
        _focused_test(
            root,
            "wardrobe-desktop",
            "navigation_policy_denies_remote_or_ambiguous_pages",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "exporter_writes_a_complete_redacted_report",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "writes_only_bounded_allowlisted_json",
        ),
        _focused_test(
            root,
            "wardrobe-platform",
            "real_keychain_round_trip",
            ignored=True,
            environment=(("P01_LIVE_KEYCHAIN", "1"),),
        ),
    )
    security = SuiteSpec("security", 180, security_commands)
    offline = SuiteSpec(
        "packaged_offline_accessibility_e2e",
        300,
        (
            _python_command(
                root,
                "tools/p09_offline_smoke.py",
                ("--output", offline_relative),
                ("--output", str(offline_report)),
                offline_relative,
            ),
        ),
    )
    supply = SuiteSpec(
        "supply_chain_package",
        300,
        (
            _python_command(
                root,
                "tools/p09_supply_chain_smoke.py",
                ("--repo", ".", "--report", supply_relative),
                ("--repo", str(root), "--report", str(supply_report)),
            ),
        ),
    )
    return migration, restore, deletion, authority, security, offline, supply


def clean_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in SECRET_ENV_NAMES:
        environment.pop(name, None)
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "npm_config_offline": "true",
            "npm_config_ignore_scripts": "true",
        }
    )
    return environment


def _executable_hash(command: CommandSpec) -> str:
    executable = Path(command.actual[0])
    if not executable.is_file():
        raise AcceptanceFailure("command executable is not a regular file")
    return sha256_file(executable)


def _validate_logical_command(command: tuple[str, ...]) -> None:
    if (
        not command
        or len(command) > 32
        or command[0] not in {"cargo", "python3"}
    ):
        raise AcceptanceFailure("logical command is outside the closed allowlist")
    for part in command:
        encoded = part.encode("utf-8")
        if (
            not part
            or len(encoded) > MAX_COMMAND_PART_BYTES
            or "\0" in part
            or Path(part).is_absolute()
            or str(Path.home()) in part
        ):
            raise AcceptanceFailure("logical command contains a private path")


def run_suite(
    specification: SuiteSpec,
    root: Path,
    environment: dict[str, str],
    runner: Runner = run_command,
) -> dict[str, Any]:
    if not specification.commands or len(specification.commands) > MAX_COMMANDS:
        raise AcceptanceFailure(f"{specification.name}: invalid command inventory")
    started_ns = time.monotonic_ns()
    command_records: list[dict[str, Any]] = []
    for command in specification.commands:
        _validate_logical_command(command.logical)
        elapsed = time.monotonic_ns() - started_ns
        remaining = specification.budget_seconds - elapsed / 1_000_000_000
        if remaining <= 0:
            raise AcceptanceFailure(
                f"{specification.name}: performance budget exceeded"
            )
        result = runner(command, root, environment, remaining)
        text = result.captured_output.decode("utf-8", errors="replace")
        marker_errors = [
            marker for marker in command.required_markers if marker not in text
        ]
        if (
            result.returncode != 0
            or result.timed_out
            or result.output_limit_exceeded
            or result.launch_failed
            or result.cleanup_failed
            or marker_errors
        ):
            reason = (
                f" missing markers {marker_errors}" if marker_errors else ""
            )
            raise AcceptanceFailure(
                f"{specification.name}: command failed{reason}"
            )
        command_records.append(
            {
                "command": list(command.logical),
                "duration_ns": result.duration_ns,
                "executable_sha256": _executable_hash(command),
                "exit_code": result.returncode,
                "output_bytes": result.output_bytes,
                "output_sha256": result.output_sha256,
                "output_limit_exceeded": result.output_limit_exceeded,
                "timed_out": result.timed_out,
            }
        )
    duration_ns = time.monotonic_ns() - started_ns
    budget_ns = specification.budget_seconds * 1_000_000_000
    if duration_ns > budget_ns:
        raise AcceptanceFailure(
            f"{specification.name}: performance budget exceeded"
        )
    return {
        "name": specification.name,
        "status": "pass",
        "budget_ns": budget_ns,
        "duration_ns": duration_ns,
        "commands": command_records,
    }


def _validate_external_reports(
    root: Path,
    work: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    offline_path = work / "offline-report.json"
    offline = p09_offline.validate_smoke_report(offline_path, root=root)
    if offline.errors:
        raise AcceptanceFailure(
            "packaged offline/accessibility report failed validation: "
            + "; ".join(offline.errors)
        )

    manifest = p09_supply_chain.validate_generated_manifest(root)
    bundle = p09_supply_chain.validate_bundle(root, manifest)
    supply = p09_supply_chain.validate_smoke(
        work / "supply-report.json",
        manifest,
        bundle,
    )
    errors = (*manifest.errors, *bundle.errors, *supply.errors)
    if errors:
        raise AcceptanceFailure(
            "supply-chain/package report failed validation: "
            + "; ".join(errors)
        )
    return (
        {
            "report_sha256": offline.report_sha256,
            "bundle_sha256": offline.bundle_sha256,
            "executable_sha256": offline.executable_sha256,
            "collage_sha256": offline.collage_sha256,
            "network_denied_for_process_tree": True,
            "accessibility_automation_used": True,
            "browser_mock_used": False,
        },
        {
            "report_sha256": supply.sha256,
            "bundle_sha256": bundle.sha256,
            "manifest_sha256": manifest.sha256,
            "dependency_count": manifest.dependency_count,
            "license_count": manifest.license_count,
            "model_artifact_count": manifest.model_artifact_count,
            "network_sandbox_enforced": True,
            "remote_model_code_allowed": False,
        },
    )


def _migration_prefix_sha256(root: Path) -> str:
    migration_root = root / "crates/wardrobe-platform/migrations"
    paths = sorted(
        (
            path
            for path in migration_root.iterdir()
            if path.suffix in {".sql", ".sha256"}
        ),
        key=lambda path: path.name,
    )
    if len(paths) != 26:
        raise AcceptanceFailure("migration source inventory is not exact")
    digest = hashlib.sha256()
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise AcceptanceFailure("migration source is unsafe")
        digest.update(path.name.encode("ascii"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def _git_status_sha256(root: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    if result.returncode != 0 or len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES:
        raise AcceptanceFailure("working-tree status cannot be bound")
    return sha256_bytes(result.stdout)


def _packet_hashes(run_dir: Path) -> dict[str, str]:
    names = ("requirements.json", "proposal.md", "review.md")
    hashes: dict[str, str] = {}
    for name in names:
        path = run_dir / name
        if path.is_symlink() or not path.is_file():
            raise AcceptanceFailure(f"packet file is unsafe: {name}")
        hashes[name] = sha256_file(path)
    return hashes


def _application_identity(root: Path) -> dict[str, Any]:
    bundle = root / BUNDLE_RELATIVE
    executable = root / EXECUTABLE_RELATIVE
    supply_manifest = root / SUPPLY_MANIFEST_RELATIVE
    if not executable.is_file() or not supply_manifest.is_file():
        raise AcceptanceFailure("production application is incomplete")
    bundle_sha256, file_count = p09_supply_chain_smoke.hash_and_scan_bundle(
        bundle
    )
    total_bytes = sum(
        path.stat(follow_symlinks=False).st_size
        for path in bundle.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    if total_bytes > PACKAGE_SIZE_BUDGET_BYTES:
        raise AcceptanceFailure("production package size budget exceeded")
    return {
        "bundle_sha256": bundle_sha256,
        "bundle_file_count": file_count,
        "bundle_bytes": total_bytes,
        "bundle_budget_bytes": PACKAGE_SIZE_BUDGET_BYTES,
        "executable_sha256": sha256_file(executable),
        "supply_manifest_sha256": sha256_file(supply_manifest),
        "migration_prefix_sha256": _migration_prefix_sha256(root),
    }


def _safe_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        mode,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _fsync_tree(root: Path) -> None:
    files: list[Path] = []
    directories: list[Path] = [root]
    for path in root.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise AcceptanceFailure("evidence bundle contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            files.append(path)
        elif stat.S_ISDIR(metadata.st_mode):
            directories.append(path)
        else:
            raise AcceptanceFailure("evidence bundle contains a special file")
    for path in files:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _codesign(bundle: Path) -> None:
    if not CODESIGN.is_file():
        raise AcceptanceFailure("macOS codesign is unavailable")
    result = subprocess.run(
        [
            str(CODESIGN),
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            str(bundle),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=60,
    )
    if result.returncode != 0 or len(result.stdout) > 64 * 1024:
        raise AcceptanceFailure("ad-hoc evidence bundle signing failed")


def _verify_codesign(bundle: Path) -> None:
    verify = subprocess.run(
        [str(CODESIGN), "--verify", "--strict", "--verbose=4", str(bundle)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=60,
    )
    details = subprocess.run(
        [str(CODESIGN), "--display", "--verbose=4", str(bundle)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        timeout=60,
    )
    rendered = details.stdout.decode("utf-8", errors="replace")
    if (
        verify.returncode != 0
        or details.returncode != 0
        or len(verify.stdout) > 64 * 1024
        or len(details.stdout) > 64 * 1024
        or "Signature=adhoc" not in rendered
        or (
            "TeamIdentifier=" in rendered
            and "TeamIdentifier=not set" not in rendered
        )
    ):
        raise AcceptanceFailure("evidence bundle signature is not strict ad-hoc")


def _bounded_bundle_tree(bundle: Path) -> tuple[str, int, int]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise AcceptanceFailure("evidence bundle root is unsafe")
    files: list[tuple[str, Path, os.stat_result]] = []
    total_bytes = 0
    for path in bundle.rglob("*"):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise AcceptanceFailure("evidence bundle contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise AcceptanceFailure(
                "evidence bundle contains a non-regular or linked file"
            )
        relative = str(path.relative_to(bundle))
        files.append((relative, path, metadata))
        total_bytes += metadata.st_size
    if (
        frozenset(relative for relative, _, _ in files) != EXPECTED_BUNDLE_FILES
        or len(files) > MAX_BUNDLE_FILES
        or total_bytes > MAX_BUNDLE_BYTES
    ):
        raise AcceptanceFailure("evidence bundle inventory is not exact and bounded")
    digest = hashlib.sha256()
    for relative, path, metadata in sorted(files):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(f"{stat.S_IMODE(metadata.st_mode):04o}".encode("ascii"))
        digest.update(b"\0")
        digest.update(str(metadata.st_size).encode("ascii"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest(), len(files), total_bytes


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AcceptanceFailure(f"acceptance {label} schema is not exact")
    return value


def _is_int(value: Any, *, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_payload_strings(payload: dict[str, Any]) -> None:
    forbidden_values = {
        value
        for name in SECRET_ENV_NAMES
        if (value := os.environ.get(name)) and len(value) >= 8
    }
    home = str(Path.home())
    home_component = Path.home().name
    absolute_path = re.compile(
        r"(?:(?<=^)|(?<=[\s\"'=]))/"
        r"(?:Users|home|private|tmp|var|Volumes|Applications|opt|usr|etc)"
        r"(?:/|$)"
    )
    windows_path = re.compile(r"(?i)(?:(?<=^)|(?<=[\s\"'=]))[a-z]:\\")
    credential_pattern = re.compile(
        r"(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|"
        r"AIza[A-Za-z0-9_-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
    )

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                visit(key)
                visit(item)
            return
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, str):
            return
        if (
            not value
            or len(value.encode("utf-8")) > 1024
            or "\0" in value
            or not value.isascii()
            or Path(value).is_absolute()
            or home in value
            or (
                home_component
                and home_component in re.split(r"[/\\\s]+", value)
            )
            or absolute_path.search(value)
            or windows_path.search(value)
            or credential_pattern.search(value)
            or "file://" in value.lower()
            or "--token=" in value.lower()
            or any(secret in value for secret in forbidden_values)
        ):
            raise AcceptanceFailure(
                "acceptance payload contains a private path, secret, or "
                "unbounded string"
            )

    visit(payload)


def _validate_signed_payload(payload: dict[str, Any]) -> None:
    _exact_keys(
        payload,
        {
            "schema_version",
            "artifact_kind",
            "profile",
            "run_id",
            "created_at",
            "overall_status",
            "source_fingerprint",
            "git_revision",
            "working_tree_status_sha256",
            "packet_hashes",
            "platform",
            "application",
            "suites",
            "packaged_workflow",
            "supply_chain",
            "requirements",
            "limitations",
            "local_signature",
            "privacy",
        },
        "top-level",
    )
    if (
        payload["schema_version"] != 1
        or payload["artifact_kind"] != "p09_release_evidence"
        or payload["profile"] != "personal_mvp"
        or payload["overall_status"] != "pass"
        or payload["run_id"] != RUN_ID
        or not _is_sha256(payload["source_fingerprint"])
        or not _is_sha256(payload["working_tree_status_sha256"])
        or re.fullmatch(r"[0-9a-f]{40}", payload["git_revision"]) is None
    ):
        raise AcceptanceFailure("acceptance payload identity is invalid")
    try:
        created_at = dt.datetime.fromisoformat(payload["created_at"])
    except (TypeError, ValueError) as error:
        raise AcceptanceFailure("acceptance timestamp is invalid") from error
    if created_at.tzinfo is None:
        raise AcceptanceFailure("acceptance timestamp is invalid")

    packet_hashes = _exact_keys(
        payload["packet_hashes"],
        {"proposal.md", "requirements.json", "review.md"},
        "packet-hash",
    )
    if not all(_is_sha256(value) for value in packet_hashes.values()):
        raise AcceptanceFailure("acceptance packet hashes are invalid")

    platform_value = _exact_keys(
        payload["platform"],
        {"system", "release", "machine"},
        "platform",
    )
    if platform_value != {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
    }:
        raise AcceptanceFailure("acceptance platform is invalid")

    application = _exact_keys(
        payload["application"],
        {
            "bundle_sha256",
            "bundle_file_count",
            "bundle_bytes",
            "bundle_budget_bytes",
            "executable_sha256",
            "supply_manifest_sha256",
            "migration_prefix_sha256",
        },
        "application",
    )
    if (
        not all(
            _is_sha256(application[name])
            for name in (
                "bundle_sha256",
                "executable_sha256",
                "supply_manifest_sha256",
                "migration_prefix_sha256",
            )
        )
        or not _is_int(application["bundle_file_count"], minimum=1)
        or not _is_int(application["bundle_bytes"], minimum=1)
        or application["bundle_budget_bytes"] != PACKAGE_SIZE_BUDGET_BYTES
        or application["bundle_bytes"] > application["bundle_budget_bytes"]
    ):
        raise AcceptanceFailure("acceptance application identity is invalid")

    suites = payload["suites"]
    if (
        not isinstance(suites, list)
        or [row.get("name") for row in suites if isinstance(row, dict)]
        != list(EXPECTED_SUITE_NAMES)
    ):
        raise AcceptanceFailure("acceptance suite inventory is not exact")
    expected_suites = _suite_specs(
        REPOSITORY_ROOT,
        REPOSITORY_ROOT / "acceptance-work",
    )
    for suite, expected_suite in zip(suites, expected_suites, strict=True):
        suite = _exact_keys(
            suite,
            {"name", "status", "budget_ns", "duration_ns", "commands"},
            "suite",
        )
        if (
            suite["name"] != expected_suite.name
            or suite["status"] != "pass"
            or suite["budget_ns"]
            != expected_suite.budget_seconds * 1_000_000_000
            or not _is_int(suite["duration_ns"])
            or suite["duration_ns"] > suite["budget_ns"]
            or not isinstance(suite["commands"], list)
            or not suite["commands"]
            or len(suite["commands"]) > MAX_COMMANDS
        ):
            raise AcceptanceFailure("acceptance suite result is invalid")
        if [
            command.get("command")
            for command in suite["commands"]
            if isinstance(command, dict)
        ] != [
            list(command.logical) for command in expected_suite.commands
        ]:
            raise AcceptanceFailure(
                "acceptance suite command inventory is not exact"
            )
        for command in suite["commands"]:
            command = _exact_keys(
                command,
                {
                    "command",
                    "duration_ns",
                    "executable_sha256",
                    "exit_code",
                    "output_bytes",
                    "output_limit_exceeded",
                    "output_sha256",
                    "timed_out",
                },
                "command",
            )
            logical = command["command"]
            if not isinstance(logical, list) or not all(
                isinstance(part, str) for part in logical
            ):
                raise AcceptanceFailure("acceptance command is invalid")
            _validate_logical_command(tuple(logical))
            if (
                command["exit_code"] != 0
                or command["timed_out"] is not False
                or command["output_limit_exceeded"] is not False
                or not _is_int(command["duration_ns"])
                or not _is_int(command["output_bytes"])
                or not _is_sha256(command["executable_sha256"])
                or not _is_sha256(command["output_sha256"])
            ):
                raise AcceptanceFailure("acceptance command result is invalid")

    packaged = _exact_keys(
        payload["packaged_workflow"],
        {
            "report_sha256",
            "bundle_sha256",
            "executable_sha256",
            "collage_sha256",
            "network_denied_for_process_tree",
            "accessibility_automation_used",
            "browser_mock_used",
        },
        "packaged-workflow",
    )
    if (
        not all(
            _is_sha256(packaged[name])
            for name in (
                "report_sha256",
                "bundle_sha256",
                "executable_sha256",
                "collage_sha256",
            )
        )
        or packaged["bundle_sha256"] != application["bundle_sha256"]
        or packaged["network_denied_for_process_tree"] is not True
        or packaged["accessibility_automation_used"] is not True
        or packaged["browser_mock_used"] is not False
    ):
        raise AcceptanceFailure("acceptance packaged workflow is invalid")

    supply = _exact_keys(
        payload["supply_chain"],
        {
            "report_sha256",
            "bundle_sha256",
            "manifest_sha256",
            "dependency_count",
            "license_count",
            "model_artifact_count",
            "network_sandbox_enforced",
            "remote_model_code_allowed",
        },
        "supply-chain",
    )
    if (
        not all(
            _is_sha256(supply[name])
            for name in ("report_sha256", "bundle_sha256", "manifest_sha256")
        )
        or supply["bundle_sha256"] != application["bundle_sha256"]
        or not _is_int(supply["dependency_count"], minimum=1)
        or not _is_int(supply["license_count"], minimum=1)
        or supply["model_artifact_count"] != 0
        or supply["network_sandbox_enforced"] is not True
        or supply["remote_model_code_allowed"] is not False
    ):
        raise AcceptanceFailure("acceptance supply-chain result is invalid")

    if payload["requirements"] != _requirements():
        raise AcceptanceFailure("acceptance requirement decisions are incomplete")
    if payload["limitations"] != _limitations():
        raise AcceptanceFailure("acceptance limitations are not truthful")
    if payload["local_signature"] != {
        "kind": "macos_adhoc_codesign",
        "whole_bundle_integrity": True,
        "external_signer_identity": False,
    }:
        raise AcceptanceFailure("acceptance local signature claim is invalid")
    if payload["privacy"] != {
        "raw_command_output_included": False,
        "absolute_host_paths_included": False,
        "private_credentials_used": False,
        "personal_source_content_included": False,
        "browser_mock_used_for_packaged_e2e": False,
    }:
        raise AcceptanceFailure("acceptance privacy claim is invalid")
    _validate_payload_strings(payload)


def validate_bundle(bundle: Path) -> BundleValidation:
    _verify_codesign(bundle)
    tree_sha256, file_count, total_bytes = _bounded_bundle_tree(bundle)
    payload_path = bundle / PAYLOAD_RELATIVE
    data = payload_path.read_bytes()
    if len(data) > MAX_BUNDLE_BYTES:
        raise AcceptanceFailure("acceptance payload is oversized")
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceFailure("acceptance payload is invalid JSON") from error
    if not isinstance(payload, dict) or canonical_json(payload) != data:
        raise AcceptanceFailure("acceptance payload is not canonical JSON")
    _validate_signed_payload(payload)
    return BundleValidation(
        payload,
        sha256_bytes(data),
        tree_sha256,
        file_count,
        total_bytes,
    )


def _rename_exclusive(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx_np = getattr(libc, "renameatx_np", None)
    if renameatx_np is None:
        raise AcceptanceFailure("exclusive macOS rename is unavailable")
    renameatx_np.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx_np.restype = ctypes.c_int
    result = renameatx_np(
        AT_FDCWD,
        os.fsencode(source),
        AT_FDCWD,
        os.fsencode(destination),
        RENAME_EXCL,
    )
    if result != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise AcceptanceFailure("acceptance bundle already exists")
        raise OSError(error, os.strerror(error), str(destination))


def _publish_bundle(
    evidence_dir: Path,
    payload: dict[str, Any],
) -> BundleValidation:
    destination = evidence_dir / BUNDLE_NAME
    if destination.exists() or destination.is_symlink():
        raise AcceptanceFailure("acceptance bundle already exists")
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{BUNDLE_NAME}.", dir=evidence_dir)
    )
    os.chmod(temporary, 0o700)
    renamed = False
    try:
        info = {
            "CFBundleIdentifier": "com.devrai.wardrobe.release-evidence",
            "CFBundleName": "Wardrobe P09 Release Evidence",
            "CFBundlePackageType": "BNDL",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
        }
        _safe_write(
            temporary / INFO_RELATIVE,
            plistlib.dumps(info, fmt=plistlib.FMT_XML, sort_keys=True),
        )
        _safe_write(temporary / PAYLOAD_RELATIVE, canonical_json(payload))
        _fsync_tree(temporary)
        _codesign(temporary)
        _fsync_tree(temporary)
        validate_bundle(temporary)
        _rename_exclusive(temporary, destination)
        renamed = True
        try:
            parent_descriptor = os.open(evidence_dir, os.O_RDONLY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except OSError as error:
            raise PublicationOutcomeUnknown(
                "acceptance bundle rename durability is unknown"
            ) from error
        return validate_bundle(destination)
    finally:
        if not renamed and temporary.exists():
            shutil.rmtree(temporary)


def _requirements() -> list[dict[str, str]]:
    return [
        {
            "requirement_id": requirement_id,
            "status": "pass",
            "test": "p09_acceptance::locally_signed_personal_mvp_release_bundle",
        }
        for requirement_id in REQUIREMENT_IDS
    ]


def _limitations() -> list[dict[str, Any]]:
    return [
        {
            "id": identifier,
            "feature_enabled": False,
            "acceptance_claim": "deferred_not_passed",
            "deferred_limitation": limitation,
        }
        for identifier, limitation in LIMITATIONS
    ]


def run_acceptance(
    root: Path,
    run_dir: Path,
    evidence_dir: Path,
    *,
    runner: Runner = run_command,
) -> BundleValidation:
    root = root.resolve()
    run_dir = run_dir.resolve()
    evidence_dir = evidence_dir.resolve()
    expected_run = root / "artifacts/harness/P09" / RUN_ID
    if (
        run_dir != expected_run
        or evidence_dir != run_dir / "evidence"
        or run_dir.is_symlink()
        or evidence_dir.is_symlink()
    ):
        raise AcceptanceFailure("acceptance paths are outside the approved run")
    evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    owned_names = {
        BUNDLE_NAME,
        ROUTING_DIRECTORY_NAME,
        "p09-acceptance-evaluator.json",
        *(f"{requirement_id}.json" for requirement_id in REQUIREMENT_IDS),
    }
    entries = tuple(evidence_dir.iterdir())
    if any(
        entry.name in owned_names
        or entry.name.startswith(f".{BUNDLE_NAME}.")
        for entry in entries
    ):
        raise AcceptanceFailure("acceptance output inventory is not empty")
    if sys.platform != "darwin":
        raise AcceptanceFailure("P09 acceptance requires macOS")

    initial_source = source_fingerprint()
    application = _application_identity(root)
    packet_hashes = _packet_hashes(run_dir)
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    if (
        state.get("status") not in {"APPROVED", "BUILT", "EVALUATED", "EVALUATION_FAILED"}
        or state.get("selected_requirement_ids") != ["P09-ACC-001"]
        or not isinstance(state.get("review"), dict)
        or state["review"].get("decision") != "APPROVE"
    ):
        raise AcceptanceFailure("acceptance packet is not independently approved")

    work = Path(tempfile.mkdtemp(prefix=".p09-acceptance-work-", dir=run_dir))
    environment = clean_environment()
    try:
        suite_records = [
            run_suite(specification, root, environment, runner)
            for specification in _suite_specs(root, work)
        ]
        offline, supply = _validate_external_reports(root, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    final_source = source_fingerprint()
    final_application = _application_identity(root)
    if initial_source != final_source or application != final_application:
        raise AcceptanceFailure("source or production package changed during acceptance")

    payload = {
        "schema_version": 1,
        "artifact_kind": "p09_release_evidence",
        "profile": "personal_mvp",
        "run_id": RUN_ID,
        "created_at": utc_now(),
        "overall_status": "pass",
        "source_fingerprint": initial_source,
        "git_revision": state.get("git_revision", "UNCOMMITTED"),
        "working_tree_status_sha256": _git_status_sha256(root),
        "packet_hashes": packet_hashes,
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "application": application,
        "suites": suite_records,
        "packaged_workflow": offline,
        "supply_chain": supply,
        "requirements": _requirements(),
        "limitations": _limitations(),
        "local_signature": {
            "kind": "macos_adhoc_codesign",
            "whole_bundle_integrity": True,
            "external_signer_identity": False,
        },
        "privacy": {
            "raw_command_output_included": False,
            "absolute_host_paths_included": False,
            "private_credentials_used": False,
            "personal_source_content_included": False,
            "browser_mock_used_for_packaged_e2e": False,
        },
    }
    encoded = canonical_json(payload)
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise AcceptanceFailure("acceptance payload exceeds its bound")
    validation = _publish_bundle(evidence_dir, payload)
    if source_fingerprint() != initial_source:
        raise PublicationOutcomeUnknown(
            "source changed after acceptance bundle publication"
        )
    return validation


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=Path(os.environ.get("HARNESS_RUN_DIR", "")),
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path(os.environ.get("HARNESS_EVIDENCE_DIR", "")),
    )
    arguments = parser.parse_args(argv)
    if not str(arguments.run_dir) or not str(arguments.evidence_dir):
        print(
            "HARNESS_RUN_DIR and HARNESS_EVIDENCE_DIR are required",
            file=sys.stderr,
        )
        return 2
    try:
        validation = run_acceptance(
            REPOSITORY_ROOT,
            arguments.run_dir,
            arguments.evidence_dir,
        )
    except (
        AcceptanceFailure,
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        print(f"P09 acceptance failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "pass",
                "bundle": BUNDLE_NAME,
                "payload_sha256": validation.payload_sha256,
                "tree_sha256": validation.tree_sha256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
