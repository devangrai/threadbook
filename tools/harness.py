#!/usr/bin/env python3
"""Specification-first generator -> review -> build -> evaluate harness."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "specs/phases/manifest.json"
SYSTEM_SPEC_PATH = ROOT / "specs/system.md"
RUNS_PATH = ROOT / "artifacts/harness"
ACCEPTED_PATH = ROOT / "artifacts/accepted"
ATOMIC_EVIDENCE_DIRECTORY = "P09AcceptanceRouting"
ATOMIC_EVIDENCE_TRIGGER_ID = "P09-ACC-001"

REQUIREMENT_HEADING = re.compile(
    r"^### (?P<id>(?:SYS|P\d{2})-[A-Z][A-Z0-9]*-\d{3}): (?P<title>.+)$"
)
FIELD = re.compile(r"^- (?P<name>Type|Statement|Verification): (?P<value>.+)$")
ALLOWED_TYPES = {
    "Ubiquitous",
    "Event-driven",
    "State-driven",
    "Optional",
    "Unwanted",
}
BUILDABLE_STATES = frozenset(
    {
        "APPROVED",
        "BUILD_FAILED",
        "BUILT",
        "EVALUATED",
        "EVALUATION_FAILED",
    }
)
PUBLIC_SUMMARY_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
EVALUATOR_SIDECARS = {
    "P04-OWN-001": Path("tools/evaluators/p04_people.py"),
    "P04-PER-001": Path("tools/evaluators/p04_people.py"),
    "P04-PERF-001": Path("tools/evaluators/p04_people.py"),
    "P04-QLT-001": Path("tools/evaluators/p04_people.py"),
    "P09-ACC-001": Path("tools/evaluators/p09_acceptance.py"),
    "P09-OFF-001": Path("tools/evaluators/p09_offline.py"),
}


class HarnessError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class Requirement:
    requirement_id: str
    title: str
    requirement_type: str
    statement: str
    verification: str
    source: str
    line: int

    def as_dict(self, *, evidence_required: bool) -> dict[str, Any]:
        return {
            "id": self.requirement_id,
            "title": self.title,
            "type": self.requirement_type,
            "statement": self.statement,
            "verification": self.verification,
            "source": self.source,
            "line": self.line,
            "evidence_required": evidence_required,
        }


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_fingerprint() -> str:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise HarnessError("Cannot enumerate repository files for fingerprinting")
    paths = sorted(
        Path(item.decode("utf-8"))
        for item in result.stdout.split(b"\0")
        if item and is_source_fingerprint_path(Path(item.decode("utf-8")))
    )
    digest = hashlib.sha256()
    for relative_path in paths:
        path = ROOT / relative_path
        if not path.is_file():
            continue
        digest.update(str(relative_path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def is_source_fingerprint_path(relative_path: Path) -> bool:
    return relative_path.parts[:2] != ("artifacts", "accepted")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HarnessError(f"Cannot read JSON from {path}: {error}") from error


def write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_spec(path: Path) -> list[Requirement]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise HarnessError(f"Cannot read specification {path}: {error}") from error

    requirements: list[Requirement] = []
    index = 0
    while index < len(lines):
        heading = REQUIREMENT_HEADING.match(lines[index])
        if not heading:
            index += 1
            continue

        heading_line = index + 1
        fields: dict[str, str] = {}
        index += 1
        while index < len(lines) and not lines[index].startswith("### "):
            field = FIELD.match(lines[index])
            if field:
                fields[field.group("name")] = field.group("value").strip()
            index += 1

        missing = {"Type", "Statement", "Verification"} - fields.keys()
        if missing:
            raise HarnessError(
                f"{path}:{heading_line}: missing fields: {', '.join(sorted(missing))}"
            )

        requirements.append(
            Requirement(
                requirement_id=heading.group("id"),
                title=heading.group("title").strip(),
                requirement_type=fields["Type"],
                statement=fields["Statement"],
                verification=fields["Verification"],
                source=str(path.relative_to(ROOT)),
                line=heading_line,
            )
        )
    return requirements


def validate_ears(requirement: Requirement) -> list[str]:
    statement = requirement.statement
    requirement_type = requirement.requirement_type
    errors: list[str] = []

    if requirement_type not in ALLOWED_TYPES:
        return [f"unsupported EARS type {requirement_type!r}"]
    if not statement.endswith("."):
        errors.append("statement must end with a period")

    patterns = {
        "Ubiquitous": r"^The .+ shall .+",
        "Event-driven": r"^When .+, the .+ shall .+",
        "State-driven": r"^While .+, the .+ shall .+",
        "Optional": r"^Where .+, the .+ shall .+",
        "Unwanted": r"^If .+, the .+ shall .+",
    }
    if not re.match(patterns[requirement_type], statement):
        errors.append(
            f"statement does not match the {requirement_type} EARS form"
        )
    return errors


def load_manifest() -> dict[str, Any]:
    manifest = load_json(MANIFEST_PATH)
    if manifest.get("schema_version") != 1:
        raise HarnessError("Unsupported phase manifest schema")
    phases = manifest.get("phases")
    if not isinstance(phases, list) or not phases:
        raise HarnessError("Phase manifest must contain a non-empty phases list")
    return manifest


def phase_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    phases: dict[str, dict[str, Any]] = {}
    for phase in manifest["phases"]:
        phase_id = phase.get("id")
        if not isinstance(phase_id, str) or not re.fullmatch(r"P\d{2}", phase_id):
            raise HarnessError(f"Invalid phase id: {phase_id!r}")
        if phase_id in phases:
            raise HarnessError(f"Duplicate phase id: {phase_id}")
        for key in ("name", "spec", "depends_on", "build_command", "evaluate_command"):
            if key not in phase:
                raise HarnessError(f"{phase_id} is missing manifest field {key}")
        if not all(
            isinstance(command, str) and command
            for command in phase["build_command"] + phase["evaluate_command"]
        ):
            raise HarnessError(f"{phase_id} commands must be non-empty string arrays")
        phases[phase_id] = phase
    return phases


def validate_dependencies(phases: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    for phase_id, phase in phases.items():
        for dependency in phase["depends_on"]:
            if dependency not in phases:
                errors.append(f"{phase_id} depends on unknown phase {dependency}")

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(phase_id: str) -> None:
        if phase_id in visiting:
            errors.append(f"Dependency cycle includes {phase_id}")
            return
        if phase_id in visited:
            return
        visiting.add(phase_id)
        for dependency in phases[phase_id]["depends_on"]:
            if dependency in phases:
                visit(dependency)
        visiting.remove(phase_id)
        visited.add(phase_id)

    for phase_id in phases:
        visit(phase_id)
    return errors


def validate_repository() -> tuple[
    dict[str, dict[str, Any]], dict[str, list[Requirement]]
]:
    manifest = load_manifest()
    phases = phase_map(manifest)
    errors = validate_dependencies(phases)
    requirements_by_source: dict[str, list[Requirement]] = {}
    seen_ids: dict[str, str] = {}

    spec_paths = [SYSTEM_SPEC_PATH] + [
        ROOT / phase["spec"] for phase in phases.values()
    ]
    for path in spec_paths:
        if not path.is_file():
            errors.append(f"Missing specification: {path.relative_to(ROOT)}")
            continue
        try:
            requirements = parse_spec(path)
        except HarnessError as error:
            errors.append(str(error))
            continue
        requirements_by_source[str(path.relative_to(ROOT))] = requirements
        if len(requirements) < 5:
            errors.append(f"{path.relative_to(ROOT)} has fewer than five requirements")

        expected_prefix = "SYS" if path == SYSTEM_SPEC_PATH else path.name[:3]
        for requirement in requirements:
            if not requirement.requirement_id.startswith(expected_prefix + "-"):
                errors.append(
                    f"{requirement.source}:{requirement.line}: "
                    f"{requirement.requirement_id} must start with {expected_prefix}-"
                )
            if requirement.requirement_id in seen_ids:
                errors.append(
                    f"Duplicate requirement {requirement.requirement_id} in "
                    f"{requirement.source} and {seen_ids[requirement.requirement_id]}"
                )
            seen_ids[requirement.requirement_id] = requirement.source
            for message in validate_ears(requirement):
                errors.append(
                    f"{requirement.source}:{requirement.line}: "
                    f"{requirement.requirement_id}: {message}"
                )

    if errors:
        raise HarnessError("\n".join(errors))
    return phases, requirements_by_source


def find_phase(phase_id: str) -> tuple[
    dict[str, Any], list[Requirement], list[Requirement]
]:
    phases, requirements_by_source = validate_repository()
    phase_id = phase_id.upper()
    if phase_id not in phases:
        raise HarnessError(f"Unknown phase {phase_id}")
    phase = phases[phase_id]
    system_requirements = requirements_by_source[
        str(SYSTEM_SPEC_PATH.relative_to(ROOT))
    ]
    phase_requirements = requirements_by_source[phase["spec"]]
    return phase, system_requirements, phase_requirements


def select_phase_requirements(
    phase_id: str,
    requirements: list[Requirement],
    requested_ids: list[str] | None,
) -> list[Requirement]:
    by_id = {
        requirement.requirement_id: requirement for requirement in requirements
    }
    if not requested_ids:
        return requirements

    normalized_ids = [requirement_id.upper() for requirement_id in requested_ids]
    if len(normalized_ids) != len(set(normalized_ids)):
        raise HarnessError("Requirement selection contains duplicate ids")
    unknown = [
        requirement_id
        for requirement_id in normalized_ids
        if requirement_id not in by_id
    ]
    if unknown:
        raise HarnessError(
            f"{phase_id} selection contains unknown requirements: "
            + ", ".join(unknown)
        )
    return [by_id[requirement_id] for requirement_id in normalized_ids]


def git_revision() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "UNCOMMITTED"


def run_path(phase_id: str, run_id: str) -> Path:
    path = RUNS_PATH / phase_id.upper() / run_id
    if not path.is_dir():
        raise HarnessError(f"Unknown work packet: {path.relative_to(ROOT)}")
    return path


def load_state(path: Path) -> dict[str, Any]:
    return load_json(path / "state.json")


def save_state(path: Path, state: dict[str, Any]) -> None:
    state["updated_at"] = utc_now()
    write_json(path / "state.json", state)


def verify_spec_snapshot(path: Path, state: dict[str, Any]) -> None:
    for relative_path, expected_hash in state["spec_hashes"].items():
        current_path = ROOT / relative_path
        if not current_path.is_file() or sha256_file(current_path) != expected_hash:
            raise HarnessError(
                f"Specification changed after generation: {relative_path}; "
                "generate and review a new work packet"
            )


def verify_approved_proposal(path: Path, state: dict[str, Any]) -> None:
    review = state.get("review")
    expected_hash = review.get("proposal_hash") if review else None
    proposal_path = path / "proposal.md"
    if not expected_hash or sha256_file(proposal_path) != expected_hash:
        raise HarnessError(
            "Proposal changed after review; record a new independent review"
        )


def command_check(_: argparse.Namespace) -> None:
    phases, requirements = validate_repository()
    requirement_count = sum(len(items) for items in requirements.values())
    print(
        f"Validated {len(phases)} phases and {requirement_count} EARS requirements."
    )


def command_trace(args: argparse.Namespace) -> None:
    phases, requirements_by_source = validate_repository()
    rows: list[dict[str, str]] = []
    system_path = str(SYSTEM_SPEC_PATH.relative_to(ROOT))
    for requirement in requirements_by_source[system_path]:
        rows.append(
            {
                "phase": "ALL",
                "requirement_id": requirement.requirement_id,
                "verification": requirement.verification,
                "source": requirement.source,
            }
        )
    for phase_id, phase in phases.items():
        for requirement in requirements_by_source[phase["spec"]]:
            rows.append(
                {
                    "phase": phase_id,
                    "requirement_id": requirement.requirement_id,
                    "verification": requirement.verification,
                    "source": requirement.source,
                }
            )

    output = json.dumps(rows, indent=2, sort_keys=True) + "\n"
    if args.output:
        destination = Path(args.output)
        if not destination.is_absolute():
            destination = ROOT / destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output, encoding="utf-8")
        print(f"Wrote {len(rows)} traceability rows to {destination}")
    else:
        print(output, end="")


def command_generate(args: argparse.Namespace) -> None:
    phase_id = args.phase.upper()
    phase, system_requirements, phase_requirements = find_phase(phase_id)
    selected_requirements = select_phase_requirements(
        phase_id, phase_requirements, args.requirements
    )
    selected_ids = {
        requirement.requirement_id for requirement in selected_requirements
    }
    created_at = utc_now()
    run_key = args.objective + "\0" + "\0".join(sorted(selected_ids))
    run_id = (
        dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + hashlib.sha256(run_key.encode("utf-8")).hexdigest()[:8]
    )
    path = RUNS_PATH / phase_id / run_id
    if path.exists():
        raise HarnessError(f"Work packet already exists: {path.relative_to(ROOT)}")
    (path / "evidence").mkdir(parents=True)

    system_relative = str(SYSTEM_SPEC_PATH.relative_to(ROOT))
    phase_relative = phase["spec"]
    requirements = [
        requirement.as_dict(evidence_required=phase_id == "P09")
        for requirement in system_requirements
    ] + [
        requirement.as_dict(
            evidence_required=requirement.requirement_id in selected_ids
        )
        for requirement in phase_requirements
    ]
    snapshot = {
        "schema_version": 1,
        "phase": phase_id,
        "phase_name": phase["name"],
        "objective": args.objective,
        "selected_requirement_ids": sorted(selected_ids),
        "generated_at": created_at,
        "git_revision": git_revision(),
        "requirements": requirements,
    }
    write_json(path / "requirements.json", snapshot)

    selected_markdown = "\n".join(
        f"- `{requirement.requirement_id}`: {requirement.statement}"
        for requirement in selected_requirements
    )
    proposal = f"""# Work Proposal: {phase_id} {phase["name"]}

Run: `{run_id}`

## Objective

{args.objective}

## Selected requirements

{selected_markdown}

## Proposed change

Describe the smallest vertical slice that satisfies the selected requirements.

## Interfaces and contracts

List domain, command, connector, provider, persistence, and user-interface
contracts that will change.

## Failure and rollback plan

Describe interruption, retry, cancellation, migration, deletion, and rollback
behavior.

## Verification plan

Map every evidence-required requirement in `requirements.json` to a test or
evaluation. Include negative and regression cases.

## Out of scope

List adjacent behavior intentionally excluded from this packet.
"""
    (path / "proposal.md").write_text(proposal, encoding="utf-8")
    (path / "review.md").write_text(
        f"""# Review: {phase_id} {run_id}

Status: PENDING

## Checklist

- [ ] Scope is smaller than or equal to the frozen requirements.
- [ ] Contracts preserve evidence versus canonical truth.
- [ ] Failure, retry, rollback, and deletion behavior are addressed.
- [ ] Verification maps every evidence-required requirement.
- [ ] Personal data is not introduced into source control.
- [ ] No evaluation threshold is weakened without a specification change.

## Findings

Pending independent review.
""",
        encoding="utf-8",
    )
    state = {
        "schema_version": 1,
        "phase": phase_id,
        "run_id": run_id,
        "status": "GENERATED",
        "created_at": created_at,
        "updated_at": created_at,
        "git_revision": snapshot["git_revision"],
        "selected_requirement_ids": sorted(selected_ids),
        "spec_hashes": {
            system_relative: sha256_file(ROOT / system_relative),
            phase_relative: sha256_file(ROOT / phase_relative),
        },
        "build_command": phase["build_command"],
        "evaluate_command": phase["evaluate_command"],
        "review": None,
    }
    write_json(path / "state.json", state)
    print(f"Generated {path.relative_to(ROOT)}")


def command_review(args: argparse.Namespace) -> None:
    phase_id = args.phase.upper()
    path = run_path(phase_id, args.run_id)
    state = load_state(path)
    if state["status"] not in {"GENERATED", "REJECTED"}:
        raise HarnessError(
            f"Cannot review work packet in state {state['status']}"
        )
    verify_spec_snapshot(path, state)
    decision = args.decision.upper()
    reviewed_at = utc_now()
    state["review"] = {
        "decision": decision,
        "reviewer": args.reviewer,
        "notes": args.notes,
        "reviewed_at": reviewed_at,
        "proposal_hash": sha256_file(path / "proposal.md"),
    }
    state["status"] = "APPROVED" if decision == "APPROVE" else "REJECTED"
    save_state(path, state)
    (path / "review.md").write_text(
        f"""# Review: {phase_id} {args.run_id}

Status: {state["status"]}

Reviewer: {args.reviewer}
Reviewed at: {reviewed_at}

## Decision

{decision}

## Notes

{args.notes}
""",
        encoding="utf-8",
    )
    print(f"{state['status']}: {path.relative_to(ROOT)}")


def execute_command(
    command: list[str],
    path: Path,
    log_name: str,
    *,
    include_phase_evidence: bool = True,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    harness_environment = {
        "HARNESS_RUN_DIR": str(path),
        "HARNESS_EVIDENCE_DIR": str(path / "evidence"),
        "HARNESS_PHASE": path.parent.name,
        "HARNESS_RUN_ID": path.name,
    }
    if include_phase_evidence:
        environment.update(harness_environment)
    else:
        for key in harness_environment:
            environment.pop(key, None)
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    (path / log_name).write_text(result.stdout, encoding="utf-8")
    return result


def evaluator_sidecars(selected_requirement_ids: list[str]) -> tuple[Path, ...]:
    return tuple(
        dict.fromkeys(
            EVALUATOR_SIDECARS[requirement_id]
            for requirement_id in selected_requirement_ids
            if requirement_id in EVALUATOR_SIDECARS
        )
    )


def accepted_manifest_path(path: Path) -> Path:
    return ACCEPTED_PATH / path.parent.name / f"{path.name}.json"


def clear_evidence_directory(evidence_dir: Path) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for entry in evidence_dir.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def clear_build_outputs(path: Path) -> None:
    clear_evidence_directory(path / "evidence")
    accepted_path = accepted_manifest_path(path)
    if accepted_path.exists():
        accepted_path.unlink()


def requirement_evidence_path(evidence_dir: Path, requirement_id: str) -> Path:
    direct = evidence_dir / f"{requirement_id}.json"
    routing_directory = evidence_dir / ATOMIC_EVIDENCE_DIRECTORY
    routed = routing_directory / f"{requirement_id}.json"
    if direct.exists() and routed.exists():
        raise HarnessError(
            f"ambiguous evidence locations for {requirement_id}"
        )
    if routed.exists():
        if routing_directory.is_symlink() or not routing_directory.is_dir():
            raise HarnessError(
                f"unsafe atomic evidence directory for {requirement_id}"
            )
        metadata = routed.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise HarnessError(
                f"unsafe atomic evidence record for {requirement_id}"
            )
        return routed
    if direct.exists():
        metadata = direct.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise HarnessError(f"unsafe evidence record for {requirement_id}")
    return direct


def validate_atomic_evidence_directory(
    evidence_dir: Path,
    required_ids: set[str],
) -> list[str]:
    routing_directory = evidence_dir / ATOMIC_EVIDENCE_DIRECTORY
    if not routing_directory.exists() and not routing_directory.is_symlink():
        if ATOMIC_EVIDENCE_TRIGGER_ID in required_ids:
            return ["atomic P09 acceptance evidence directory is missing"]
        return []
    if routing_directory.is_symlink() or not routing_directory.is_dir():
        return ["atomic evidence directory is unsafe"]
    expected = {
        "p09-acceptance-evaluator.json",
        *(f"{requirement_id}.json" for requirement_id in required_ids),
    }
    entries = list(routing_directory.iterdir())
    names = {entry.name for entry in entries}
    errors: list[str] = []
    if names != expected:
        errors.append("atomic evidence directory inventory is not exact")
    for entry in entries:
        try:
            metadata = entry.lstat()
        except OSError:
            errors.append(f"atomic evidence entry is unreadable: {entry.name}")
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > 256 * 1024
        ):
            errors.append(f"atomic evidence entry is unsafe: {entry.name}")
    diagnostic_path = routing_directory / "p09-acceptance-evaluator.json"
    if diagnostic_path.is_file() and not diagnostic_path.is_symlink():
        try:
            diagnostic = load_json(diagnostic_path)
        except HarnessError as error:
            errors.append(str(error))
        else:
            if (
                diagnostic.get("schema_version") != 1
                or diagnostic.get("status") != "pass"
                or diagnostic.get("failures") != []
            ):
                errors.append(
                    "atomic evidence diagnostic is not a passing commit"
                )
    else:
        errors.append("atomic evidence passing diagnostic is missing")
    return list(dict.fromkeys(errors))


def evidence_hash_files(evidence_dir: Path) -> list[Path]:
    files: list[Path] = []
    for path in evidence_dir.iterdir():
        if path.is_symlink():
            raise HarnessError(f"unsafe evidence symlink: {path}")
        if path.is_file():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise HarnessError(f"unsafe evidence file: {path}")
            files.append(path)
    routing_directory = evidence_dir / ATOMIC_EVIDENCE_DIRECTORY
    if routing_directory.exists():
        if routing_directory.is_symlink() or not routing_directory.is_dir():
            raise HarnessError("atomic evidence directory is unsafe")
        for path in routing_directory.iterdir():
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise HarnessError(f"unsafe atomic evidence file: {path}")
            files.append(path)
    return sorted(files, key=lambda path: str(path.relative_to(evidence_dir)))


def sanitize_public_summary(value: Any, *, context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > 32:
        raise HarnessError(f"{context}: public_summary must be an object of at most 32 fields")

    sanitized: dict[str, Any] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not PUBLIC_SUMMARY_KEY.fullmatch(key):
            raise HarnessError(f"{context}: invalid public_summary key {key!r}")
        if isinstance(item, str):
            if not item or len(item) > 256 or "\n" in item:
                raise HarnessError(f"{context}: invalid public_summary string for {key}")
            sanitized[key] = item
        elif isinstance(item, (bool, int, float)) and not isinstance(item, complex):
            sanitized[key] = item
        elif isinstance(item, list) and len(item) <= 32 and all(
            isinstance(element, str)
            and element
            and len(element) <= 128
            and "\n" not in element
            for element in item
        ):
            sanitized[key] = list(item)
        else:
            raise HarnessError(
                f"{context}: public_summary field {key} is not a bounded primitive"
            )
    return sanitized


def acceptance_payload(
    path: Path,
    state: dict[str, Any],
    snapshot: dict[str, Any],
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    required_ids = {
        requirement["id"]
        for requirement in snapshot["requirements"]
        if requirement["evidence_required"]
    }
    atomic_errors = validate_atomic_evidence_directory(
        path / "evidence",
        required_ids,
    )
    if atomic_errors:
        raise HarnessError("; ".join(atomic_errors))
    evidence_records: list[dict[str, Any]] = []
    for requirement in snapshot["requirements"]:
        if not requirement["evidence_required"]:
            continue
        evidence_path = requirement_evidence_path(
            path / "evidence",
            requirement["id"],
        )
        evidence = load_json(evidence_path)
        details = evidence.get("details")
        public_summary = (
            details.get("public_summary") if isinstance(details, dict) else None
        )
        if public_summary is None:
            raise HarnessError(
                f"{evidence_path}: required evidence has no public_summary"
            )
        evidence_records.append(
            {
                "requirement_id": requirement["id"],
                "status": evidence["status"],
                "test": evidence["test"],
                "recorded_at": evidence["recorded_at"],
                "sha256": sha256_file(evidence_path),
                "public_summary": sanitize_public_summary(
                    public_summary,
                    context=str(evidence_path),
                ),
            }
        )

    evidence_hashes = {
        str(evidence_path.relative_to(path / "evidence")): sha256_file(
            evidence_path
        )
        for evidence_path in evidence_hash_files(path / "evidence")
    }
    return {
        "schema_version": 1,
        "phase": state["phase"],
        "run_id": state["run_id"],
        "accepted_at": evaluation["completed_at"],
        "selected_requirement_ids": state["selected_requirement_ids"],
        "build_source_fingerprint": state["build"]["source_fingerprint"],
        "proposal_hash": state["review"]["proposal_hash"],
        "spec_hashes": state["spec_hashes"],
        "build_command": state["build_command"],
        "evaluate_command": state["evaluate_command"],
        "evidence": evidence_records,
        "evidence_file_hashes": evidence_hashes,
    }


def publish_acceptance_manifest(
    path: Path,
    state: dict[str, Any],
    snapshot: dict[str, Any],
    evaluation: dict[str, Any],
) -> Path:
    destination = accepted_manifest_path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_json(
        destination,
        acceptance_payload(path, state, snapshot, evaluation),
    )
    return destination


def command_build(args: argparse.Namespace) -> None:
    path = run_path(args.phase.upper(), args.run_id)
    state = load_state(path)
    if state["status"] not in BUILDABLE_STATES:
        raise HarnessError(
            f"Build requires an approved buildable state, found {state['status']}"
        )
    verify_spec_snapshot(path, state)
    verify_approved_proposal(path, state)
    clear_build_outputs(path)
    result = execute_command(state["build_command"], path, "build.log")
    state["build"] = {
        "command": state["build_command"],
        "exit_code": result.returncode,
        "completed_at": utc_now(),
        "source_fingerprint": source_fingerprint(),
    }
    state["status"] = "BUILT" if result.returncode == 0 else "BUILD_FAILED"
    save_state(path, state)
    if result.returncode != 0:
        raise HarnessError(f"Build failed; see {path / 'build.log'}")
    print(f"BUILT: {path.relative_to(ROOT)}")


def validate_evidence(
    path: Path, requirements: list[dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    evidence_dir = path / "evidence"
    required_ids = {
        requirement["id"]
        for requirement in requirements
        if requirement["evidence_required"]
    }
    errors.extend(
        validate_atomic_evidence_directory(evidence_dir, required_ids)
    )
    for requirement in requirements:
        if not requirement["evidence_required"]:
            continue
        requirement_id = requirement["id"]
        try:
            evidence_path = requirement_evidence_path(
                evidence_dir,
                requirement_id,
            )
        except HarnessError as error:
            errors.append(str(error))
            continue
        if not evidence_path.is_file():
            errors.append(f"missing evidence for {requirement_id}")
            continue
        try:
            evidence = load_json(evidence_path)
        except HarnessError as error:
            errors.append(str(error))
            continue
        if evidence.get("requirement_id") != requirement_id:
            errors.append(f"{evidence_path}: requirement_id mismatch")
        status = evidence.get("status")
        if status not in {"pass", "deferred"}:
            errors.append(f"{evidence_path}: status must be pass or deferred")
        if status == "deferred":
            details = evidence.get("details")
            summary = (
                details.get("public_summary")
                if isinstance(details, dict)
                else None
            )
            if (
                not isinstance(summary, dict)
                or summary.get("feature_enabled") is not False
                or summary.get("acceptance_claim") != "deferred_not_passed"
                or not isinstance(summary.get("deferred_limitation"), str)
                or not summary["deferred_limitation"]
            ):
                errors.append(
                    f"{evidence_path}: deferred evidence must disable the "
                    "feature and state deferred_not_passed"
                )
        for field in ("test", "recorded_at"):
            if not isinstance(evidence.get(field), str) or not evidence[field]:
                errors.append(f"{evidence_path}: missing {field}")
    return errors


def command_evaluate(args: argparse.Namespace) -> None:
    path = run_path(args.phase.upper(), args.run_id)
    state = load_state(path)
    if state["status"] not in {"BUILT", "EVALUATION_FAILED"}:
        raise HarnessError(
            f"Evaluation requires BUILT or EVALUATION_FAILED state, "
            f"found {state['status']}"
        )
    verify_spec_snapshot(path, state)
    verify_approved_proposal(path, state)
    expected_fingerprint = state.get("build", {}).get("source_fingerprint")
    if not expected_fingerprint or source_fingerprint() != expected_fingerprint:
        raise HarnessError(
            "Repository source changed after build; rebuild before evaluation"
        )
    snapshot = load_json(path / "requirements.json")
    sidecars = evaluator_sidecars(snapshot["selected_requirement_ids"])
    result = execute_command(
        state["evaluate_command"],
        path,
        "evaluation.log",
        include_phase_evidence=not sidecars,
    )
    sidecar_results: list[dict[str, Any]] = []
    if result.returncode == 0:
        for sidecar in sidecars:
            sidecar_result = execute_command(
                [sys.executable, str(ROOT / sidecar)],
                path,
                f"evaluation-{sidecar.stem}.log",
            )
            sidecar_results.append(
                {
                    "command": [sys.executable, str(sidecar)],
                    "exit_code": sidecar_result.returncode,
                }
            )
            if sidecar_result.returncode != 0:
                break
    evaluation_exit_code = max(
        [result.returncode, *(item["exit_code"] for item in sidecar_results)]
    )
    source_changed_during_evaluation = (
        source_fingerprint() != expected_fingerprint
    )
    evidence_errors = validate_evidence(path, snapshot["requirements"])
    if source_changed_during_evaluation:
        evidence_errors.append("repository source changed during evaluation")
    evaluation = {
        "command": state["evaluate_command"],
        "exit_code": evaluation_exit_code,
        "sidecars": sidecar_results,
        "evidence_errors": evidence_errors,
        "completed_at": utc_now(),
        "deferred_requirement_ids": [
            requirement["id"]
            for requirement in snapshot["requirements"]
            if requirement["evidence_required"]
            and (
                load_json(
                    requirement_evidence_path(
                        path / "evidence",
                        requirement["id"],
                    )
                ).get("status")
                == "deferred"
            )
        ]
        if not evidence_errors
        else [],
    }
    if evaluation_exit_code == 0 and not evidence_errors:
        try:
            accepted_path = publish_acceptance_manifest(
                path,
                state,
                snapshot,
                evaluation,
            )
            evaluation["accepted_manifest"] = str(
                accepted_path.relative_to(ROOT)
            )
        except HarnessError as error:
            evidence_errors.append(str(error))
    write_json(path / "evaluation.json", evaluation)
    passed = evaluation_exit_code == 0 and not evidence_errors
    state["evaluation"] = evaluation
    state["status"] = "EVALUATED" if passed else "EVALUATION_FAILED"
    save_state(path, state)
    if not passed:
        details = "; ".join(evidence_errors) or "evaluation command failed"
        raise HarnessError(f"Evaluation failed: {details}")
    print(f"EVALUATED: {path.relative_to(ROOT)}")


def command_status(args: argparse.Namespace) -> None:
    path = run_path(args.phase.upper(), args.run_id)
    print(json.dumps(load_state(path), indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="Validate specs and manifest")
    check.set_defaults(handler=command_check)

    trace = subparsers.add_parser(
        "trace", help="Render requirement traceability as JSON"
    )
    trace.add_argument("--output")
    trace.set_defaults(handler=command_trace)

    generate = subparsers.add_parser(
        "generate", help="Generate a frozen work packet"
    )
    generate.add_argument("phase")
    generate.add_argument("--objective", required=True)
    generate.add_argument(
        "--requirements",
        nargs="+",
        help="Phase requirement ids to include; defaults to the full phase",
    )
    generate.set_defaults(handler=command_generate)

    review = subparsers.add_parser("review", help="Record an independent review")
    review.add_argument("phase")
    review.add_argument("run_id")
    review.add_argument(
        "--decision", choices=("approve", "reject"), required=True
    )
    review.add_argument("--reviewer", required=True)
    review.add_argument("--notes", required=True)
    review.set_defaults(handler=command_review)

    build = subparsers.add_parser("build", help="Build an approved work packet")
    build.add_argument("phase")
    build.add_argument("run_id")
    build.set_defaults(handler=command_build)

    evaluate = subparsers.add_parser(
        "evaluate", help="Evaluate a built work packet"
    )
    evaluate.add_argument("phase")
    evaluate.add_argument("run_id")
    evaluate.set_defaults(handler=command_evaluate)

    status = subparsers.add_parser("status", help="Show work-packet state")
    status.add_argument("phase")
    status.add_argument("run_id")
    status.set_defaults(handler=command_status)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.handler(args)
    except HarnessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
