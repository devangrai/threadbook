"""Evidence evaluator for the P00 local desktop package and fallback gate."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import select
import signal
import subprocess
import time
import tomllib
from typing import Any, Iterable


EXPECTED_CSP = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src ipc: http://ipc.localhost; font-src 'self'; "
    "object-src 'none'; frame-src 'none'; base-uri 'none'; "
    "form-action 'none'"
)
EXPECTED_PERMISSIONS = ["allow-get-runtime-info"]
RUNTIME_READY_MARKER = "WARDROBE_RUNTIME_BRIDGE_READY schema=1 local_only=true"
FORBIDDEN_TERMS = (
    "python",
    "pytorch",
    "torch",
    "cuda",
    "tensorflow",
    "onnx",
    "safetensors",
)
FORBIDDEN_SUFFIXES = (".pt", ".pth", ".onnx", ".safetensors")
P00_STATUSES = {"NOT_STARTED", "IN_PROGRESS", "PASSED", "BLOCKED"}
FALLBACK_FIELDS = (
    "Failed condition",
    "Accepted fallback",
    "Owner action",
    "Unblock evidence",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_security_config(
    config: dict[str, Any], capability: dict[str, Any]
) -> list[str]:
    errors: list[str] = []
    build = config.get("build", {})
    security = config.get("app", {}).get("security", {})

    if build.get("frontendDist") != "../apps/desktop-ui/dist":
        errors.append("production frontendDist must be local desktop-ui output")
    if build.get("devUrl") != "http://localhost:1420":
        errors.append("development URL must be exact loopback port 1420")
    if security.get("csp") != EXPECTED_CSP:
        errors.append("CSP does not match the approved allowlist")
    if security.get("capabilities") != ["main"]:
        errors.append("only the main named capability may be active")

    serialized = json.dumps(config).lower()
    if "dangerousremotedomainipcaccess" in serialized:
        errors.append("remote-domain IPC configuration is prohibited")
    for window in config.get("app", {}).get("windows", []):
        url = window.get("url") if isinstance(window, dict) else None
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            errors.append("remote window navigation is prohibited")

    if capability.get("identifier") != "main":
        errors.append("capability identifier must be main")
    if capability.get("windows") != ["main"]:
        errors.append("capability must apply only to the main window")
    if capability.get("permissions") != EXPECTED_PERMISSIONS:
        errors.append(
            "main window capability must grant only allow-get-runtime-info"
        )
    return errors


def validate_navigation_policy_source(source: str) -> list[str]:
    direct_policy_hook = re.compile(
        r"\.on_navigation\(\s*\|_webview,\s*url\|\s*"
        r"is_allowed_navigation\(url\)\s*\)"
    )
    if not direct_policy_hook.search(source):
        return [
            "navigation hook must delegate directly to is_allowed_navigation"
        ]
    return []


def validate_app_acl_source(source: str) -> list[str]:
    app_manifest = re.compile(
        r"AppManifest::new\(\)\.commands\(\s*&\[\s*"
        r'"get_runtime_info"\s*\]\s*\)'
    )
    if not app_manifest.search(source):
        return [
            "Tauri app ACL must declare only the get_runtime_info command"
        ]
    return []


def validate_generated_app_acl(manifests: dict[str, Any]) -> list[str]:
    app_manifest = manifests.get("__app-acl__")
    if not isinstance(app_manifest, dict):
        return ["generated Tauri app ACL manifest is missing"]
    permissions = app_manifest.get("permissions")
    if not isinstance(permissions, dict):
        return ["generated Tauri app ACL permissions are missing"]
    permission = permissions.get("allow-get-runtime-info")
    if not isinstance(permission, dict):
        return ["generated allow-get-runtime-info permission is missing"]
    commands = permission.get("commands")
    if not isinstance(commands, dict):
        return ["generated runtime permission commands are missing"]
    if commands.get("allow") != ["get_runtime_info"] or commands.get("deny") != []:
        return ["generated runtime permission must allow only get_runtime_info"]
    if set(permissions) != {
        "allow-get-runtime-info",
        "deny-get-runtime-info",
    }:
        return ["generated app ACL contains unexpected command permissions"]
    return []


def validate_dependency_names(names: Iterable[str]) -> list[str]:
    errors: list[str] = []
    for name in names:
        lowered = name.lower()
        if any(term in lowered for term in FORBIDDEN_TERMS):
            errors.append(f"forbidden dependency: {name}")
    return errors


def validate_bundle_records(records: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    if not records:
        return ["bundle inventory is empty"]
    for record in records:
        path = record.get("path", "")
        file_type = record.get("type", "")
        lowered = path.lower()
        if any(term in lowered for term in FORBIDDEN_TERMS):
            errors.append(f"forbidden bundle path: {path}")
        if lowered.endswith(FORBIDDEN_SUFFIXES):
            errors.append(f"forbidden model asset: {path}")
        if not file_type:
            errors.append(f"missing file type for {path}")
    return errors


def validate_architecture(file_output: str) -> list[str]:
    if "Mach-O 64-bit executable arm64" not in file_output:
        return [f"main executable is not arm64 Mach-O: {file_output.strip()}"]
    if "x86_64" in file_output:
        return ["main executable unexpectedly contains x86_64"]
    return []


def validate_signature(returncode: int, output: str) -> list[str]:
    if returncode != 0:
        return [f"strict code-signature verification failed: {output.strip()}"]
    return []


def validate_ad_hoc_signature(returncode: int, output: str) -> list[str]:
    if returncode != 0:
        return [f"code-signature identity inspection failed: {output.strip()}"]
    if "Signature=adhoc" not in output:
        return ["application signature is not ad hoc"]
    return []


def run_runtime_smoke(
    executable: Path,
    *,
    timeout_seconds: float = 12.0,
) -> tuple[str, list[str]]:
    try:
        process = subprocess.Popen(
            [str(executable)],
            cwd=executable.parent,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as error:
        return "", [f"cannot launch packaged runtime bridge smoke test: {error}"]
    output_lines: list[str] = []
    deadline = time.monotonic() + timeout_seconds
    errors: list[str] = []
    try:
        assert process.stdout is not None
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select(
                [process.stdout],
                [],
                [],
                min(0.25, remaining),
            )
            if readable:
                line = process.stdout.readline()
                if line:
                    stripped = line.strip()
                    if len(output_lines) < 100:
                        output_lines.append(stripped[:1000])
                    if stripped == RUNTIME_READY_MARKER:
                        break
                elif process.poll() is not None:
                    break
            elif process.poll() is not None:
                break
        else:
            errors.append("packaged runtime bridge smoke test timed out")

        if RUNTIME_READY_MARKER not in output_lines and not errors:
            errors.append(
                "packaged frontend did not invoke the runtime metadata command"
            )
    finally:
        terminate_process_group(process)
        if process.stdout is not None:
            process.stdout.close()
    return "\n".join(output_lines), errors


def terminate_process_group(process: subprocess.Popen[str]) -> bool:
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=3)
        return False

    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            break
        except PermissionError:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=3)
            return False
        time.sleep(0.05)
    else:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    return True


def dependency_inventory(root: Path) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    names: set[str] = set()

    package_lock_path = root / "package-lock.json"
    cargo_lock_path = root / "Cargo.lock"
    if not package_lock_path.is_file():
        errors.append("package-lock.json is missing")
    else:
        package_lock = json.loads(package_lock_path.read_text(encoding="utf-8"))
        packages = package_lock.get("packages")
        if not isinstance(packages, dict):
            errors.append("package-lock.json packages inventory is missing")
        else:
            for path, package in packages.items():
                name = package.get("name") if isinstance(package, dict) else None
                names.add(name or path or "<root>")

    if not cargo_lock_path.is_file():
        errors.append("Cargo.lock is missing")
    else:
        cargo_lock = tomllib.loads(cargo_lock_path.read_text(encoding="utf-8"))
        packages = cargo_lock.get("package")
        if not isinstance(packages, list):
            errors.append("Cargo.lock package inventory is missing")
        else:
            for package in packages:
                name = package.get("name")
                if isinstance(name, str):
                    names.add(name)

    errors.extend(validate_dependency_names(names))
    return sorted(names), errors


def bundle_inventory(bundle: Path) -> tuple[list[dict[str, str]], list[str]]:
    errors: list[str] = []
    records: list[dict[str, str]] = []
    if not bundle.is_dir():
        return [], [f"application bundle is missing: {bundle}"]

    for path in sorted(item for item in bundle.rglob("*") if item.is_file()):
        result = run(["file", "-b", str(path)], cwd=bundle)
        relative_path = str(path.relative_to(bundle))
        if result.returncode != 0:
            errors.append(f"file inspection failed for {relative_path}")
        records.append(
            {
                "path": relative_path,
                "type": result.stdout.strip() if result.returncode == 0 else "",
            }
        )
    errors.extend(validate_bundle_records(records))
    return records, errors


def bundle_executable(bundle: Path) -> tuple[Path | None, list[str]]:
    plist_path = bundle / "Contents/Info.plist"
    if not plist_path.is_file():
        return None, ["application Info.plist is missing"]
    try:
        with plist_path.open("rb") as handle:
            metadata = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException) as error:
        return None, [f"cannot parse application Info.plist: {error}"]
    executable_name = metadata.get("CFBundleExecutable")
    if not isinstance(executable_name, str) or not executable_name:
        return None, ["CFBundleExecutable is missing from Info.plist"]
    executable = bundle / "Contents/MacOS" / executable_name
    if not executable.is_file():
        return None, [f"bundle executable is missing: {executable_name}"]
    return executable, []


def p00_requirement_ids(root: Path) -> set[str]:
    text = (root / "specs/phases/P00-feasibility.md").read_text(encoding="utf-8")
    return set(re.findall(r"^### (P00-[A-Z][A-Z0-9]*-\d{3}):", text, re.MULTILINE))


def inspect_phase_gate(root: Path) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    summary: dict[str, Any] = {
        "blocked_requirements": [],
        "accepted_fallback_adrs": [],
    }
    report_path = root / "docs/phase-reports/P00.md"
    adr_path = root / "docs/adr/0001-desktop-packaging.md"
    if not report_path.is_file():
        return ["P00 phase report is missing"], summary
    if not adr_path.is_file():
        return ["desktop packaging ADR is missing"], summary

    report = report_path.read_text(encoding="utf-8")
    row_matches = re.findall(
        r"^\| `(P00-[A-Z][A-Z0-9]*-\d{3})` \| "
        r"([A-Z_]+) \| ([^|\n]+) \|$",
        report,
        re.MULTILINE,
    )
    rows = {
        requirement_id: (status, detail.strip())
        for requirement_id, status, detail in row_matches
    }
    if len(rows) != len(row_matches):
        errors.append("phase report contains duplicate requirement rows")

    for requirement_id in sorted(p00_requirement_ids(root)):
        status = rows.get(requirement_id, ("", ""))[0]
        if status not in P00_STATUSES:
            errors.append(f"phase report lacks valid status for {requirement_id}")
    if rows.get("P00-PKG-001", ("", ""))[0] != "BLOCKED":
        errors.append("P00-PKG-001 must remain BLOCKED")

    blocked = sorted(
        requirement_id
        for requirement_id, (status, _) in rows.items()
        if status == "BLOCKED"
    )
    accepted_adrs: set[str] = set()
    for requirement_id in blocked:
        detail = rows[requirement_id][1]
        adr_reference = re.search(r"\bADR\s+(\d{4})\b", detail)
        if not adr_reference:
            errors.append(
                f"blocked requirement {requirement_id} has no ADR reference"
            )
            continue
        adr_number = adr_reference.group(1)
        matches = sorted((root / "docs/adr").glob(f"{adr_number}-*.md"))
        if len(matches) != 1:
            errors.append(
                f"blocked requirement {requirement_id} does not resolve one ADR "
                f"{adr_number}"
            )
            continue
        adr = matches[0].read_text(encoding="utf-8")
        if "Status: Accepted" not in adr:
            errors.append(f"ADR {adr_number} is not accepted")
        fallback_match = re.search(
            rf"^## Fallback: {re.escape(requirement_id)}\s*$"
            rf"(?P<body>.*?)(?=^## |\Z)",
            adr,
            re.MULTILINE | re.DOTALL,
        )
        if not fallback_match:
            errors.append(
                f"ADR {adr_number} lacks fallback section for {requirement_id}"
            )
            continue
        body = fallback_match.group("body")
        for field in FALLBACK_FIELDS:
            if not re.search(
                rf"^- {re.escape(field)}: \S.+$",
                body,
                re.MULTILINE,
            ):
                errors.append(
                    f"ADR {adr_number} fallback for {requirement_id} "
                    f"lacks {field}"
                )
        accepted_adrs.add(adr_number)

    adr = adr_path.read_text(encoding="utf-8")
    for required_text in (
        "Developer ID Application",
        "notarytool",
        "clean supported Mac",
        "P00-PKG-001",
    ):
        if required_text not in adr:
            errors.append(f"desktop packaging ADR omits {required_text}")
    if "ADR 0001" not in report:
        errors.append("phase report does not link ADR 0001")
    summary["blocked_requirements"] = blocked
    summary["accepted_fallback_adrs"] = sorted(accepted_adrs)
    return errors, summary


def validate_phase_gate(root: Path) -> list[str]:
    errors, _ = inspect_phase_gate(root)
    return errors


def write_evidence(
    evidence_dir: Path,
    requirement_id: str,
    test: str,
    details: dict[str, Any],
) -> None:
    payload = {
        "requirement_id": requirement_id,
        "status": "pass",
        "test": test,
        "recorded_at": utc_now(),
        "details": details,
    }
    (evidence_dir / f"{requirement_id}.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    diagnostics: dict[str, Any] = {"selected": sorted(selected)}
    all_errors: list[str] = []

    config = json.loads(
        (root / "src-tauri/tauri.conf.json").read_text(encoding="utf-8")
    )
    capability = json.loads(
        (root / "src-tauri/capabilities/main.json").read_text(encoding="utf-8")
    )
    security_errors = validate_security_config(config, capability)
    diagnostics["security_errors"] = security_errors

    rust_source = (root / "src-tauri/src/lib.rs").read_text(encoding="utf-8")
    navigation_errors = validate_navigation_policy_source(rust_source)
    diagnostics["navigation_errors"] = navigation_errors

    build_source = (root / "src-tauri/build.rs").read_text(encoding="utf-8")
    app_acl_errors = validate_app_acl_source(build_source)
    diagnostics["app_acl_errors"] = app_acl_errors

    generated_acl_path = root / "src-tauri/gen/schemas/acl-manifests.json"
    if generated_acl_path.is_file():
        generated_acl = json.loads(
            generated_acl_path.read_text(encoding="utf-8")
        )
        generated_acl_errors = validate_generated_app_acl(generated_acl)
    else:
        generated_acl_errors = ["generated Tauri ACL manifest is missing"]
    diagnostics["generated_acl_errors"] = generated_acl_errors

    dependencies, dependency_errors = dependency_inventory(root)
    diagnostics["dependencies"] = dependencies
    diagnostics["dependency_errors"] = dependency_errors

    bundle = root / "target/release/bundle/macos/Wardrobe.app"
    bundle_records, bundle_errors = bundle_inventory(bundle)
    diagnostics["bundle_files"] = bundle_records
    diagnostics["bundle_errors"] = bundle_errors

    executable, executable_errors = bundle_executable(bundle)
    architecture = (
        run(["file", str(executable)], cwd=root)
        if executable is not None
        else None
    )
    architecture_errors = list(executable_errors)
    if architecture is not None:
        if architecture.returncode == 0:
            architecture_errors.extend(validate_architecture(architecture.stdout))
        else:
            architecture_errors.append("main executable architecture inspection failed")
    diagnostics["architecture_output"] = (
        architecture.stdout.strip() if architecture is not None else ""
    )
    diagnostics["architecture_errors"] = architecture_errors

    if executable is not None:
        runtime_smoke_output, runtime_smoke_errors = run_runtime_smoke(executable)
    else:
        runtime_smoke_output = ""
        runtime_smoke_errors = ["packaged runtime bridge executable is missing"]
    diagnostics["runtime_smoke_output"] = runtime_smoke_output
    diagnostics["runtime_smoke_errors"] = runtime_smoke_errors

    signature = run(
        ["codesign", "--verify", "--deep", "--strict", "--verbose=4", str(bundle)],
        cwd=root,
    )
    signature_errors = validate_signature(signature.returncode, signature.stdout)
    diagnostics["signature_output"] = signature.stdout.strip()
    signature_details = run(
        ["codesign", "-dv", "--verbose=4", str(bundle)],
        cwd=root,
    )
    signature_errors.extend(
        validate_ad_hoc_signature(
            signature_details.returncode,
            signature_details.stdout,
        )
    )
    diagnostics["signature_details_output"] = signature_details.stdout.strip()
    diagnostics["signature_errors"] = signature_errors

    gate_errors, gate_summary = inspect_phase_gate(root)
    diagnostics["gate_errors"] = gate_errors

    package_errors = (
        security_errors
        + navigation_errors
        + app_acl_errors
        + generated_acl_errors
        + dependency_errors
        + bundle_errors
        + architecture_errors
        + runtime_smoke_errors
        + signature_errors
    )
    if "P00-PKG-002" in selected and not package_errors:
        write_evidence(
            evidence_dir,
            "P00-PKG-002",
            "tools.evaluators.p00_package.evaluate",
            {
                "bundle": str(bundle.relative_to(root)),
                "dependency_count": len(dependencies),
                "bundle_file_count": len(bundle_records),
                "diagnostics": "p00-package-diagnostics.json",
                "public_summary": {
                    "target_architecture": "arm64",
                    "bundle_format": "Mach-O app bundle",
                    "signature": "adhoc",
                    "hardened_runtime": "runtime" in signature_details.stdout,
                    "executable_sha256": (
                        sha256_file(executable)
                        if executable is not None
                        else ""
                    ),
                    "capability_permission_count": len(EXPECTED_PERMISSIONS),
                    "app_permissions": list(EXPECTED_PERMISSIONS),
                    "runtime_bridge_ready": True,
                    "csp_sha256": hashlib.sha256(
                        EXPECTED_CSP.encode("utf-8")
                    ).hexdigest(),
                    "navigation_policy_revision": (
                        "v1-tauri-localhost-loopback-debug"
                    ),
                    "remote_navigation_denied": True,
                    "remote_ipc_denied": True,
                    "dependency_count": len(dependencies),
                    "bundle_file_count": len(bundle_records),
                    "forbidden_runtime_findings": 0,
                },
            },
        )
    elif "P00-PKG-002" in selected:
        all_errors.extend(package_errors)

    if "P00-GAT-001" in selected and not gate_errors:
        write_evidence(
            evidence_dir,
            "P00-GAT-001",
            "tools.evaluators.p00_package.validate_phase_gate",
            {
                "phase_report": "docs/phase-reports/P00.md",
                "adr": "docs/adr/0001-desktop-packaging.md",
                "diagnostics": "p00-package-diagnostics.json",
                "public_summary": gate_summary,
            },
        )
    elif "P00-GAT-001" in selected:
        all_errors.extend(gate_errors)

    (evidence_dir / "p00-package-diagnostics.json").write_text(
        json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if all_errors:
        for error in all_errors:
            print(f"P00 package evaluation: {error}")
        return 1
    return 0
