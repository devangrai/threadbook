#!/usr/bin/env python3
"""Denied-network macOS smoke for the P09 supply-chain release packet."""

from __future__ import annotations

import argparse
import errno
import hashlib
import http.server
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from typing import Any, Callable, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_RELATIVE = Path("release/generated/supply-chain-manifest-v1.json")
BUNDLE_RELATIVE = Path("target/release/bundle/macos/Wardrobe.app")
BUNDLE_MANIFEST_RELATIVE = Path(
    "Contents/Resources/release/supply-chain-manifest-v1.json"
)
SANDBOX_EXECUTABLE = Path("/usr/bin/sandbox-exec")
SANDBOX_PROFILE = "(version 1)(allow default)(deny network*)"
COMMAND_TIMEOUT_SECONDS = 20 * 60
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
MAX_BUNDLE_FILES = 4096
MAX_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
MODEL_SUFFIXES = frozenset(
    {
        ".bin",
        ".ckpt",
        ".dylib",
        ".gguf",
        ".mlmodel",
        ".mlpackage",
        ".onnx",
        ".pt",
        ".pth",
        ".safetensors",
        ".so",
        ".tflite",
        ".wasm",
    }
)
PRIVATE_KEY_SUFFIXES = frozenset({".key", ".p12", ".pem", ".pk8"})
PRIVATE_KEY_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
)
REMOTE_SERVICES = {
    "outfit_recommendation": {
        "downloads_code": False,
        "model": "gpt-5.6-sol",
        "provider": "openai",
    },
    "try_on_visualization": {
        "downloads_code": False,
        "model": "gpt-image-2",
        "provider": "openai",
    },
}
PROHIBITIONS = [
    "dynamic_model_plugins",
    "executable_model_artifacts",
    "remote_model_code",
    "runtime_model_downloads",
]


class SmokeFailure(RuntimeError):
    """A supply-chain smoke invariant was not established."""


CommandRunner = Callable[[Sequence[str], Path, dict[str, str]], bytes]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise SmokeFailure(f"{label} must be a bounded regular file")
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as error:
        raise SmokeFailure(f"{label} is unreadable") from error
    if len(data) > limit:
        raise SmokeFailure(f"{label} exceeds its size bound")
    return data


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    data = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()
    if len(data) > MAX_REPORT_BYTES:
        raise SmokeFailure("smoke report exceeds its size bound")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def clean_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "ALL_PROXY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "HARNESS_EVIDENCE_DIR",
        "HARNESS_RUN_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NPM_TOKEN",
        "NODE_AUTH_TOKEN",
        "OPENAI_API_KEY",
        "TAURI_SIGNING_PRIVATE_KEY",
        "TAURI_SIGNING_PRIVATE_KEY_PASSWORD",
        "http_proxy",
        "https_proxy",
        "npm_config_proxy",
        "npm_config_https_proxy",
        "npm_config_registry",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "CARGO_NET_OFFLINE": "true",
            "npm_config_offline": "true",
            "npm_config_ignore_scripts": "true",
        }
    )
    return environment


def run_checked(
    command: Sequence[str],
    cwd: Path,
    environment: dict[str, str],
) -> bytes:
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmokeFailure(f"command did not complete: {command[0]}") from error
    if len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES:
        raise SmokeFailure(f"command output exceeded bound: {command[0]}")
    if result.returncode != 0:
        raise SmokeFailure(f"command failed: {' '.join(command)}")
    return result.stdout


def network_probe(port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        response = connection.recv(128)
    if b" 204 " not in response:
        raise SmokeFailure(
            "loopback network control did not return the expected response"
        )


def require_network_denied(port: int) -> None:
    try:
        network_probe(port)
    except OSError as error:
        if error.errno not in {errno.EACCES, errno.EPERM}:
            raise SmokeFailure(
                f"sandbox probe failed for a non-policy reason: errno={error.errno}"
            ) from error
    else:
        raise SmokeFailure("denied-network sandbox allowed a loopback connection")


def _contained_relative(root: Path, value: str, label: str) -> Path:
    pure = PurePosixPath(value)
    if pure.is_absolute() or "\\" in value or ".." in pure.parts:
        raise SmokeFailure(f"{label} is not a contained relative path")
    candidate = (root / value).resolve(strict=False)
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise SmokeFailure(f"{label} escapes the repository") from error
    return candidate


def validate_manifest(repo: Path) -> tuple[dict[str, Any], bytes]:
    data = read_regular(
        repo / MANIFEST_RELATIVE,
        MAX_MANIFEST_BYTES,
        "generated supply-chain manifest",
    )
    try:
        manifest = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SmokeFailure("generated supply-chain manifest is invalid JSON") from error
    if not isinstance(manifest, dict):
        raise SmokeFailure("generated supply-chain manifest must be an object")
    canonical = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()
    if canonical != data:
        raise SmokeFailure("generated supply-chain manifest is not canonical")
    if set(manifest) != {
        "counts",
        "dependencies",
        "input_hashes",
        "licenses",
        "models",
        "release",
        "schema_version",
        "targets",
    }:
        raise SmokeFailure("generated supply-chain manifest schema is not closed")
    dependencies = manifest.get("dependencies")
    licenses = manifest.get("licenses")
    counts = manifest.get("counts")
    if (
        manifest.get("schema_version") != 1
        or not isinstance(dependencies, list)
        or not dependencies
        or not isinstance(licenses, list)
        or not isinstance(counts, dict)
        or counts
        != {
            "dependencies": len(dependencies),
            "licenses": len(licenses),
            "model_artifacts": 0,
        }
        or len(licenses) != len(dependencies)
        or manifest.get("targets") != ["aarch64-apple-darwin", "x86_64-apple-darwin"]
    ):
        raise SmokeFailure("generated dependency/license inventory is incomplete")
    models = manifest.get("models")
    if (
        not isinstance(models, dict)
        or set(models)
        != {
            "artifacts",
            "local_providers",
            "prohibitions",
            "remote_model_code_allowed",
            "remote_services",
            "root",
        }
        or models.get("artifacts") != []
        or models.get("local_providers")
        != {"segmentation": {"availability": "unavailable"}}
        or models.get("prohibitions") != PROHIBITIONS
        or models.get("remote_model_code_allowed") is not False
        or models.get("remote_services") != REMOTE_SERVICES
        or models.get("root") != "assets/model-artifacts"
    ):
        raise SmokeFailure("generated model truth is not the reviewed empty inventory")
    input_hashes = manifest.get("input_hashes")
    if not isinstance(input_hashes, dict) or not input_hashes:
        raise SmokeFailure("generated input hash inventory is empty")
    for relative, expected in input_hashes.items():
        if (
            not isinstance(relative, str)
            or not isinstance(expected, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected) is None
        ):
            raise SmokeFailure("generated input hash record is invalid")
        path = _contained_relative(repo, relative, "input hash path")
        if path.is_symlink() or not path.is_file() or sha256_file(path) != expected:
            raise SmokeFailure(f"generated input hash drift: {relative}")
    model_root = repo / "assets/model-artifacts"
    if model_root.is_symlink():
        raise SmokeFailure("model artifact root is a symlink")
    if model_root.exists() and any(model_root.rglob("*")):
        raise SmokeFailure("empty model inventory has files on disk")
    return manifest, data


def hash_and_scan_bundle(bundle: Path) -> tuple[str, int]:
    if not bundle.is_dir() or bundle.is_symlink():
        raise SmokeFailure("macOS application bundle is missing or unsafe")
    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0
    resources = bundle / "Contents/Resources"
    if not resources.is_dir() or resources.is_symlink():
        raise SmokeFailure("macOS application resources are missing or unsafe")
    for path in sorted(bundle.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(bundle).as_posix()
        if path.is_symlink():
            if path == resources or resources in path.parents:
                raise SmokeFailure(f"symlink in application resources: {relative}")
            continue
        if not stat.S_ISREG(metadata.st_mode):
            continue
        file_count += 1
        total_bytes += metadata.st_size
        if file_count > MAX_BUNDLE_FILES or total_bytes > MAX_BUNDLE_BYTES:
            raise SmokeFailure("macOS application bundle exceeds evaluator bounds")
        if path.suffix.lower() in PRIVATE_KEY_SUFFIXES:
            raise SmokeFailure(f"private-key-shaped bundle resource: {relative}")
        if resources in path.parents:
            if path.suffix.lower() in MODEL_SUFFIXES:
                raise SmokeFailure(f"unlisted model-shaped bundle resource: {relative}")
            if metadata.st_mode & 0o111:
                raise SmokeFailure(f"executable application resource: {relative}")
        file_digest = hashlib.sha256()
        overlap = b""
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                file_digest.update(block)
                scanned = overlap + block
                if any(marker in scanned for marker in PRIVATE_KEY_MARKERS):
                    raise SmokeFailure(
                        f"private key marker in application bundle: {relative}"
                    )
                overlap = scanned[-64:]
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(file_digest.digest())
        digest.update(b"\0")
    return digest.hexdigest(), file_count


def verify_release_state(repo: Path) -> dict[str, Any]:
    manifest, generated = validate_manifest(repo)
    bundle = repo / BUNDLE_RELATIVE
    bundled = read_regular(
        bundle / BUNDLE_MANIFEST_RELATIVE,
        MAX_MANIFEST_BYTES,
        "bundled supply-chain manifest",
    )
    if bundled != generated:
        raise SmokeFailure("bundled supply-chain manifest differs from generated bytes")
    bundle_sha256, bundle_file_count = hash_and_scan_bundle(bundle)
    return {
        "bundle_file_count": bundle_file_count,
        "bundle_sha256": bundle_sha256,
        "dependency_count": manifest["counts"]["dependencies"],
        "generated_manifest_sha256": sha256_bytes(generated),
        "license_count": manifest["counts"]["licenses"],
        "model_artifact_count": manifest["counts"]["model_artifacts"],
    }


def run_child(
    repo: Path,
    report_path: Path,
    probe_port: int,
    *,
    runner: CommandRunner = run_checked,
) -> None:
    report_path.unlink(missing_ok=True)
    require_network_denied(probe_port)
    environment = clean_environment()
    commands = (
        (
            sys.executable,
            "tools/release_supply_chain.py",
            "check",
        ),
        (
            sys.executable,
            "tools/release_supply_chain.py",
            "check-installed",
        ),
    )
    for command in commands:
        runner(command, repo, environment)
    rust_output = runner(
        (
            "cargo",
            "test",
            "-p",
            "wardrobe-desktop",
            "--offline",
            "release_manifest",
            "--",
            "--test-threads=1",
        ),
        repo,
        environment,
    ).decode(errors="replace")
    if (
        re.search(r"running [1-9][0-9]* tests?", rust_output) is None
        or "release_manifest" not in rust_output
        or "release_manifest_failure_prevents_private_path_and_state_initialization"
        not in rust_output
        or "test result: ok" not in rust_output
    ):
        raise SmokeFailure("focused startup release-manifest verifier did not execute")
    state = verify_release_state(repo)
    atomic_write_json(
        report_path,
        {
            "schema_version": 1,
            "status": "pass",
            "platform": "macos",
            "network_control_passed": True,
            "network_sandbox_enforced": True,
            "sandbox_profile_sha256": sha256_bytes(SANDBOX_PROFILE.encode()),
            "supply_check_passed": True,
            "installed_tree_check_passed": True,
            "startup_gate_verified": True,
            "canonical_manifest_verified": True,
            "bundled_manifest_exact": True,
            "generated_manifest_sha256": state["generated_manifest_sha256"],
            "bundled_manifest_sha256": state["generated_manifest_sha256"],
            "bundle_sha256": state["bundle_sha256"],
            "bundle_file_count": state["bundle_file_count"],
            "dependency_count": state["dependency_count"],
            "license_count": state["license_count"],
            "model_artifact_count": state["model_artifact_count"],
            "local_segmentation_availability": "unavailable",
            "remote_model_code_allowed": False,
            "private_credentials_used": False,
            "developer_id_signed": False,
            "notarized": False,
            "clean_machine_certified": False,
            "acceptance_claim": "focused_supply_chain_packet_passed",
            "scope_limitation": (
                "Developer ID signing, notarization, clean-machine certification, "
                "and whole-bundle authenticity are outside this packet."
            ),
        },
    )


class _ProbeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        self.send_response(204)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def run_smoke(repo: Path, report_path: Path) -> None:
    report_path.unlink(missing_ok=True)
    if sys.platform != "darwin":
        raise SmokeFailure("P09 supply-chain smoke requires macOS")
    if not SANDBOX_EXECUTABLE.is_file():
        raise SmokeFailure("macOS sandbox-exec is unavailable")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ProbeHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        network_probe(port)
        environment = clean_environment()
        command = [
            str(SANDBOX_EXECUTABLE),
            "-p",
            SANDBOX_PROFILE,
            sys.executable,
            str(Path(__file__).resolve()),
            "--child",
            "--repo",
            str(repo.resolve()),
            "--report",
            str(report_path.resolve()),
            "--probe-port",
            str(port),
        ]
        result = subprocess.run(
            command,
            cwd=repo,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
        if len(result.stdout) > MAX_COMMAND_OUTPUT_BYTES:
            raise SmokeFailure("sandboxed smoke output exceeded its bound")
        if result.returncode != 0:
            raise SmokeFailure("sandboxed supply-chain smoke failed")
        if not report_path.is_file():
            raise SmokeFailure("sandboxed supply-chain smoke did not publish a report")
    except BaseException:
        report_path.unlink(missing_ok=True)
        raise
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPOSITORY_ROOT)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--probe-port", type=int, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    try:
        if arguments.child:
            if arguments.probe_port is None:
                raise SmokeFailure("sandbox child requires a probe port")
            run_child(
                arguments.repo.resolve(),
                arguments.report.resolve(),
                arguments.probe_port,
            )
        else:
            run_smoke(arguments.repo.resolve(), arguments.report.resolve())
    except SmokeFailure as error:
        arguments.report.unlink(missing_ok=True)
        print(f"P09 supply-chain smoke failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
