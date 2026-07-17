#!/usr/bin/env python3
"""Interactive exact-package PhotoKit acceptance smoke for P06."""

from __future__ import annotations

from contextlib import AbstractContextManager
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any


RUN_ID = "20260716T105025Z-10b259e2"
CHALLENGE_ENV = "P06_PHOTOKIT_CHALLENGE_JSON"
OUTPUT_PREFIX = "P06_PHOTOKIT_LIVE "
EXPECTED_FIXTURES = (
    "0a954174688fa3cf1fd32faa5601e6a7978b5fda3b90a470fac6fbce9686cf34",
    "78b167d1451183a20b6ea88c3a4701d59335699aa2c947ead7282c31edff35a5",
)
EXPECTED_BUNDLE_ID = "com.devrai.wardrobe"
EXPECTED_USAGE = (
    "Wardrobe uses your Photos library to let you select an album and import "
    "its original images into your private local wardrobe."
)
KEYCHAIN_SERVICE = "com.devrai.wardrobe.photokit.locator.v1"
SHA256 = re.compile(r"[0-9a-f]{64}")
KEY_REFERENCE = re.compile(r"photokit-locator-[0-9a-f-]{36}")
MARKER_NAME = ".wardrobe-p06-photokit-smoke-recovery.json"
MARKER_SCHEMA_VERSION = 2
EXPECTED_DATABASE_SCHEMA = 16
MAX_APP_FILES = 4096
MAX_APP_BYTES = 2 * 1024 * 1024 * 1024
MAX_PHOTOKIT_BLOB_BYTES = 40 * 1024 * 1024
JOURNAL_STATES = frozenset({"preparing", "isolated", "restoring"})
FAILURE_STAGES = frozenset(
    {
        "preflight",
        "fixture_setup",
        "isolation",
        "initial_album_setup",
        "initial_app_sync",
        "initial_verification",
        "album_removal",
        "startup_reconciliation",
        "final_verification",
        "fixture_cleanup_confirmation",
        "local_cleanup",
    }
)
CURRENT_FAILURE_STAGE = "preflight"
INITIAL_SYNC_INSTRUCTIONS = (
    "Wardrobe will open next in Local only mode. First open Privacy, choose "
    "Enable personal live, and confirm. Then open Apple Photos, connect, grant "
    "full read access, select the dedicated album, and choose Sync now. Wait "
    "for 2 available and 0 unavailable, then quit Wardrobe."
)
FAILURE_CLEANUP_INSTRUCTIONS = (
    "Remove the dedicated synthetic album and images from Photos. If this run "
    "changed Wardrobe Photos access, review that permission in System Settings "
    "before retrying."
)


class SmokeFailure(Exception):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
        raise SmokeFailure from None
    if len(lines) != 1:
        raise SmokeFailure
    return _sha256(lines[0].encode())


def _file_sha256(path: Path, *, max_bytes: int = MAX_APP_BYTES) -> str:
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise SmokeFailure from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise SmokeFailure
        copied = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            copied += len(chunk)
            if copied > max_bytes:
                raise SmokeFailure
            digest.update(chunk)
        if copied != metadata.st_size:
            raise SmokeFailure
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _read_regular_bounded(path: Path, *, max_bytes: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise SmokeFailure from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise SmokeFailure
        data = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024, max_bytes + 1)):
            data.extend(chunk)
            if len(data) > max_bytes:
                raise SmokeFailure
        if len(data) != metadata.st_size:
            raise SmokeFailure
        return bytes(data)
    finally:
        os.close(descriptor)


def _digest_part(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _bundle_sha256(bundle: Path) -> str:
    if bundle.is_symlink() or not bundle.is_dir():
        raise SmokeFailure
    records: list[tuple[str, Path, os.stat_result]] = []
    pending = [bundle]
    try:
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
                        stat.S_ISREG(metadata.st_mode)
                        or stat.S_ISLNK(metadata.st_mode)
                    ):
                        raise SmokeFailure
                    if len(records) > MAX_APP_FILES:
                        raise SmokeFailure

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
                    raise SmokeFailure
                _digest_part(digest, b"symlink")
                _digest_part(digest, target)
            else:
                total_bytes += metadata.st_size
                if total_bytes > MAX_APP_BYTES:
                    raise SmokeFailure
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
                        raise SmokeFailure
                    copied = 0
                    while chunk := os.read(descriptor, 1024 * 1024):
                        copied += len(chunk)
                        digest.update(chunk)
                    if copied != opened.st_size:
                        raise SmokeFailure
                finally:
                    os.close(descriptor)
        return digest.hexdigest()
    except (OSError, UnicodeError):
        raise SmokeFailure from None


def _challenge() -> dict[str, Any]:
    raw = os.environ.get(CHALLENGE_ENV)
    if raw is None or len(raw.encode()) > 4096:
        raise SmokeFailure
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise SmokeFailure from None
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "run_id",
        "challenge_nonce",
        "packet_sha256",
        "source_sha256",
        "fixture_sha256",
        "bundle_id",
        "info_plist_sha256",
        "executable_sha256",
        "bundle_sha256",
        "designated_requirement_sha256",
    }:
        raise SmokeFailure
    if (
        value["schema_version"] != 1
        or value["run_id"] != RUN_ID
        or not isinstance(value["challenge_nonce"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["challenge_nonce"])
        or not isinstance(value["packet_sha256"], str)
        or not SHA256.fullmatch(value["packet_sha256"])
        or not isinstance(value["source_sha256"], str)
        or not SHA256.fullmatch(value["source_sha256"])
        or value["fixture_sha256"] != list(EXPECTED_FIXTURES)
        or value["bundle_id"] != EXPECTED_BUNDLE_ID
        or any(
            not isinstance(value[field], str) or not SHA256.fullmatch(value[field])
            for field in (
                "info_plist_sha256",
                "executable_sha256",
                "bundle_sha256",
                "designated_requirement_sha256",
            )
        )
    ):
        raise SmokeFailure
    return value


def _run(
    command: list[str],
    *,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
        check=False,
    )
    if check and result.returncode != 0:
        raise SmokeFailure
    return result


def _dialog(message: str, title: str = "Wardrobe PhotoKit smoke") -> None:
    script = (
        f'display dialog {json.dumps(message)} with title {json.dumps(title)} '
        'buttons {"Cancel", "Continue"} default button "Continue" '
        'cancel button "Cancel"'
    )
    _run(["/usr/bin/osascript", "-e", script])


def _set_failure_stage(stage: str) -> None:
    if stage not in FAILURE_STAGES:
        raise SmokeFailure
    global CURRENT_FAILURE_STAGE
    CURRENT_FAILURE_STAGE = stage


def _failure_dialog(stage: str) -> None:
    if stage not in FAILURE_STAGES:
        stage = "preflight"
    script = (
        'display alert "Wardrobe PhotoKit smoke failed" '
        f'message "Stage: {stage}. No acceptance evidence was emitted. '
        f'{FAILURE_CLEANUP_INSTRUCTIONS}"'
    )
    _run(["/usr/bin/osascript", "-e", script], check=False)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _remove_private_tree(path: Path, expected_parent: Path) -> None:
    if path.parent != expected_parent or path.is_symlink():
        raise SmokeFailure
    if path.exists():
        shutil.rmtree(path)


class PrivateAppIsolation(AbstractContextManager["PrivateAppIsolation"]):
    def __init__(self, bundle_id: str) -> None:
        home = Path.home()
        self.data_parent = home / "Library" / "Application Support"
        self.log_parent = home / "Library" / "Logs"
        self.data_path = self.data_parent / bundle_id
        self.log_path = self.log_parent / bundle_id
        self.marker = self.data_parent / MARKER_NAME
        self.entries: list[dict[str, Any]] = []
        self.prepared = False

    def _write_marker(
        self,
        state: str,
        entries: list[dict[str, Any]] | None = None,
    ) -> None:
        if state not in JOURNAL_STATES:
            raise SmokeFailure
        _atomic_json(
            self.marker,
            {
                "schema_version": MARKER_SCHEMA_VERSION,
                "bundle_id": EXPECTED_BUNDLE_ID,
                "state": state,
                "entries": self.entries if entries is None else entries,
            },
        )

    def _validated_entry_paths(
        self, entry: dict[str, Any]
    ) -> tuple[Path, Path, Path]:
        if set(entry) != {"kind", "had_original", "backup_name"}:
            raise SmokeFailure
        kind = entry["kind"]
        if kind == "data":
            parent, current = self.data_parent, self.data_path
        elif kind == "logs":
            parent, current = self.log_parent, self.log_path
        else:
            raise SmokeFailure
        backup_name = entry["backup_name"]
        if (
            not isinstance(entry["had_original"], bool)
            or not isinstance(backup_name, str)
            or not re.fullmatch(
                rf"\.{re.escape(EXPECTED_BUNDLE_ID)}\.p06-[0-9a-f]{{32}}",
                backup_name,
            )
        ):
            raise SmokeFailure
        return parent, current, parent / backup_name

    def recover(self) -> None:
        if not self.marker.exists():
            return
        if self.marker.is_symlink() or self.marker.stat().st_size > 8192:
            raise SmokeFailure
        try:
            record = json.loads(self.marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise SmokeFailure from None
        if not isinstance(record, dict) or set(record) != {
            "schema_version",
            "bundle_id",
            "state",
            "entries",
        }:
            raise SmokeFailure
        if (
            record["schema_version"] != MARKER_SCHEMA_VERSION
            or record["bundle_id"] != EXPECTED_BUNDLE_ID
            or record["state"] not in JOURNAL_STATES
            or not isinstance(record["entries"], list)
            or len(record["entries"]) != 2
        ):
            raise SmokeFailure
        entries = record["entries"]
        for entry in entries:
            if not isinstance(entry, dict):
                raise SmokeFailure
            self._validated_entry_paths(entry)
        self.entries = entries
        if record["state"] == "isolated":
            self.cleanup_keychain()
            self._write_marker("restoring")
        for entry in reversed(record["entries"]):
            parent, current, backup = self._validated_entry_paths(entry)
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if entry["had_original"]:
                if backup.exists():
                    _remove_private_tree(current, parent)
                    os.replace(backup, current)
                elif not current.exists():
                    raise SmokeFailure
            else:
                _remove_private_tree(current, parent)
                if backup.exists():
                    raise SmokeFailure
        self.marker.unlink()
        self.entries = []

    def __enter__(self) -> "PrivateAppIsolation":
        self.recover()
        token = uuid.uuid4().hex
        self.entries = [
            {
                "kind": "data",
                "had_original": self.data_path.exists(),
                "backup_name": f".{EXPECTED_BUNDLE_ID}.p06-{token}",
            },
            {
                "kind": "logs",
                "had_original": self.log_path.exists(),
                "backup_name": f".{EXPECTED_BUNDLE_ID}.p06-{token}",
            },
        ]
        self._write_marker("preparing")
        try:
            for entry in self.entries:
                parent, current, backup = self._validated_entry_paths(entry)
                parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if current.is_symlink() or backup.exists():
                    raise SmokeFailure
                if entry["had_original"]:
                    os.replace(current, backup)
            self.prepared = True
            self._write_marker("isolated")
            return self
        except BaseException:
            self.recover()
            self.entries = []
            raise

    def cleanup_keychain(self) -> None:
        database = self.data_path / "wardrobe.sqlite3"
        if not database.is_file():
            return
        with sqlite3.connect(database) as connection:
            references = [
                row[0]
                for row in connection.execute(
                    "SELECT key_reference FROM photokit_enrollments"
                ).fetchall()
            ]
        for reference in references:
            if not isinstance(reference, str) or not KEY_REFERENCE.fullmatch(reference):
                raise SmokeFailure
            find_before = _run(
                [
                    "/usr/bin/security",
                    "find-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    reference,
                ],
                capture=True,
                check=False,
            )
            if find_before.returncode != 0:
                if not _keychain_item_not_found(find_before):
                    raise SmokeFailure
                continue
            deleted = _run(
                [
                    "/usr/bin/security",
                    "delete-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    reference,
                ],
                capture=True,
                check=False,
            )
            if deleted.returncode != 0:
                raise SmokeFailure
            find_after = _run(
                [
                    "/usr/bin/security",
                    "find-generic-password",
                    "-s",
                    KEYCHAIN_SERVICE,
                    "-a",
                    reference,
                ],
                capture=True,
                check=False,
            )
            if find_after.returncode == 0 or not _keychain_item_not_found(find_after):
                raise SmokeFailure

    def restore(self) -> None:
        if not self.entries:
            return
        if self.prepared:
            self.cleanup_keychain()
            self._write_marker("restoring")
        for entry in reversed(self.entries):
            parent, current, backup = self._validated_entry_paths(entry)
            _remove_private_tree(current, parent)
            if entry["had_original"]:
                if not backup.exists():
                    raise SmokeFailure
                os.replace(backup, current)
            elif backup.exists():
                raise SmokeFailure
        self.marker.unlink(missing_ok=True)
        self.entries = []
        self.prepared = False

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        self.restore()
        return False


def _app_identity(app: Path) -> dict[str, str]:
    if not app.is_dir() or app.is_symlink():
        raise SmokeFailure
    info_path = app / "Contents" / "Info.plist"
    info_bytes = _read_regular_bounded(info_path, max_bytes=1024 * 1024)
    try:
        info = plistlib.loads(info_bytes)
    except plistlib.InvalidFileException:
        raise SmokeFailure from None
    if not isinstance(info, dict):
        raise SmokeFailure
    executable_name = info.get("CFBundleExecutable")
    bundle_id = info.get("CFBundleIdentifier")
    if (
        not isinstance(executable_name, str)
        or not executable_name
        or bundle_id != EXPECTED_BUNDLE_ID
        or info.get("NSPhotoLibraryUsageDescription") != EXPECTED_USAGE
    ):
        raise SmokeFailure
    executable = app / "Contents" / "MacOS" / executable_name
    if not executable.is_file() or executable.is_symlink():
        raise SmokeFailure
    _run(
        [
            "/usr/bin/codesign",
            "--verify",
            "--deep",
            "--strict",
            "--verbose=4",
            str(app),
        ],
        capture=True,
    )
    codesign = _run(
        ["/usr/bin/codesign", "-d", "-r-", str(app)],
        capture=True,
    )
    requirement = codesign.stdout + codesign.stderr
    if len(requirement) > 16_384:
        raise SmokeFailure
    return {
        "bundle_id": bundle_id,
        "info_plist_sha256": _sha256(info_bytes),
        "executable_sha256": _file_sha256(executable),
        "bundle_sha256": _bundle_sha256(app),
        "designated_requirement_sha256": _designated_requirement_sha256(
            requirement
        ),
    }


def _ensure_not_running(app: Path) -> None:
    result = _run(
        ["/usr/bin/pgrep", "-f", str(app / "Contents" / "MacOS")],
        check=False,
    )
    if result.returncode == 0:
        raise SmokeFailure


def _launch_and_wait(app: Path) -> None:
    _run(["/usr/bin/open", "-W", "-n", str(app)])


def _generate_fixtures(root: Path, output: Path) -> tuple[Path, Path]:
    generator = root / "spikes" / "p00-photokit-fixtures" / "generate.py"
    _run([sys.executable, str(generator), "--output", str(output)])
    fixtures = (output / "cloud.png", output / "local.png")
    if (
        tuple(
            _file_sha256(path, max_bytes=MAX_PHOTOKIT_BLOB_BYTES)
            for path in fixtures
        )
        != EXPECTED_FIXTURES
    ):
        raise SmokeFailure
    return fixtures


def _open_fixture_folder(folder: Path) -> None:
    _run(["/usr/bin/open", str(folder)])


def _database_snapshot(database: Path) -> dict[str, Any]:
    if not database.is_file() or database.is_symlink():
        raise SmokeFailure
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        if (
            connection.execute("PRAGMA user_version").fetchone()[0]
            != EXPECTED_DATABASE_SCHEMA
        ):
            raise SmokeFailure
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SmokeFailure
        state = connection.execute(
            "SELECT state, authorization, active_enrollment_epoch, "
            "active_membership_generation, observed_count, available_count, "
            "unavailable_count FROM photokit_connector_state WHERE singleton = 1"
        ).fetchone()
        if (
            state is None
            or state[0] != "ready"
            or state[1] != "authorized"
            or not isinstance(state[2], str)
            or not isinstance(state[3], int)
        ):
            raise SmokeFailure
        enrollment, generation = state[2], state[3]
        operation = connection.execute(
            "SELECT operation.trigger_kind, operation.state, "
            "operation.accepted_bytes, membership.observed_count "
            "FROM photokit_membership_generations membership "
            "JOIN photokit_operations operation "
            "ON operation.operation_id = membership.operation_id "
            "WHERE membership.enrollment_epoch = ? "
            "AND membership.membership_generation = ?",
            (enrollment, generation),
        ).fetchone()
        if operation is None or operation[1] != "complete":
            raise SmokeFailure
        head_counts = connection.execute(
            "SELECT COUNT(*), "
            "SUM(CASE WHEN revision.availability = 'available' THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN revision.availability = 'unavailable' THEN 1 ELSE 0 END) "
            "FROM photokit_availability_heads head "
            "JOIN photokit_availability_revisions revision "
            "ON revision.revision_id = head.revision_id "
            "JOIN photokit_assets asset ON asset.asset_id = head.asset_id "
            "WHERE asset.enrollment_epoch = ?",
            (enrollment,),
        ).fetchone()
        if (
            head_counts is None
            or tuple(state[4:7])
            != tuple(0 if value is None else value for value in head_counts)
        ):
            raise SmokeFailure
        blob_rows = connection.execute(
            "SELECT DISTINCT materialization.blob_sha256, "
            "materialization.byte_length, blob.byte_length "
            "FROM photokit_materializations materialization "
            "JOIN photokit_assets asset "
            "ON asset.asset_id = materialization.asset_id "
            "JOIN blobs blob ON blob.sha256 = materialization.blob_sha256 "
            "WHERE asset.enrollment_epoch = ?",
            (enrollment,),
        ).fetchall()
        blob_records: list[tuple[str, int]] = []
        for content_hash, materialized_length, blob_length in blob_rows:
            if (
                not isinstance(content_hash, str)
                or not SHA256.fullmatch(content_hash)
                or type(materialized_length) is not int
                or type(blob_length) is not int
                or materialized_length != blob_length
                or not 1 <= blob_length <= MAX_PHOTOKIT_BLOB_BYTES
            ):
                raise SmokeFailure
            blob_records.append((content_hash, blob_length))
        blob_records.sort()
        if len({content_hash for content_hash, _ in blob_records}) != len(
            blob_records
        ):
            raise SmokeFailure
        blob_hashes = [content_hash for content_hash, _ in blob_records]
        attempt_count = connection.execute(
            "SELECT COUNT(*) FROM photokit_materialization_attempts attempt "
            "JOIN photokit_operations operation "
            "ON operation.operation_id = attempt.operation_id "
            "WHERE operation.enrollment_epoch = ? "
            "AND attempt.result = 'materialized'",
            (enrollment,),
        ).fetchone()[0]
        not_in_scope = connection.execute(
            "SELECT COUNT(*) FROM photokit_availability_revisions "
            "WHERE enrollment_epoch = ? AND reason = 'asset_not_in_scope'",
            (enrollment,),
        ).fetchone()[0]
        unavailable_blob_hashes = [
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT materialization.blob_sha256 "
                "FROM photokit_availability_heads head "
                "JOIN photokit_availability_revisions revision "
                "ON revision.revision_id = head.revision_id "
                "JOIN photokit_assets asset ON asset.asset_id = head.asset_id "
                "JOIN photokit_materializations materialization "
                "ON materialization.asset_id = asset.asset_id "
                "WHERE asset.enrollment_epoch = ? "
                "AND revision.availability = 'unavailable' "
                "ORDER BY materialization.blob_sha256",
                (enrollment,),
            ).fetchall()
        ]
        if any(
            not isinstance(content_hash, str)
            or not SHA256.fullmatch(content_hash)
            for content_hash in unavailable_blob_hashes
        ):
            raise SmokeFailure
        revision = connection.execute(
            "SELECT photokit_revision FROM revision_state WHERE singleton = 1"
        ).fetchone()[0]
    return {
        "generation": generation,
        "photokit_revision": revision,
        "observed": state[4],
        "available": state[5],
        "unavailable": state[6],
        "trigger": operation[0],
        "accepted_bytes": operation[2],
        "generation_observed": operation[3],
        "blob_hashes": blob_hashes,
        "blob_records": tuple(blob_records),
        "attempt_count": attempt_count,
        "asset_not_in_scope": not_in_scope,
        "unavailable_blob_hashes": unavailable_blob_hashes,
    }


def _verify_retained_cas(
    data_path: Path,
    blob_records: tuple[tuple[str, int], ...],
) -> None:
    if not blob_records:
        raise SmokeFailure
    blob_root = data_path / "blobs" / "sha256"
    checked_directories: set[Path] = set()
    for content_hash, expected_size in blob_records:
        if (
            not isinstance(content_hash, str)
            or not SHA256.fullmatch(content_hash)
            or type(expected_size) is not int
            or not 1 <= expected_size <= MAX_PHOTOKIT_BLOB_BYTES
        ):
            raise SmokeFailure
        path = (
            blob_root
            / content_hash[0:2]
            / content_hash[2:4]
            / content_hash
        )
        if path.parent.parent.parent != blob_root:
            raise SmokeFailure
        for directory in (
            data_path,
            data_path / "blobs",
            blob_root,
            path.parent.parent,
            path.parent,
        ):
            if directory in checked_directories:
                continue
            try:
                metadata = directory.lstat()
            except OSError:
                raise SmokeFailure from None
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise SmokeFailure
            checked_directories.add(directory)
        try:
            identity = path.lstat()
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            raise SmokeFailure from None
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(identity.st_mode)
                or stat.S_ISLNK(identity.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or identity.st_dev != opened.st_dev
                or identity.st_ino != opened.st_ino
                or opened.st_nlink != 1
                or opened.st_size != expected_size
            ):
                raise SmokeFailure
            digest = hashlib.sha256()
            copied = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                copied += len(chunk)
                if copied > expected_size:
                    raise SmokeFailure
                digest.update(chunk)
            if copied != expected_size or digest.hexdigest() != content_hash:
                raise SmokeFailure
        finally:
            os.close(descriptor)


def _seed_linked_canonical_closure(
    database: Path,
    blob_records: tuple[tuple[str, int], ...],
) -> tuple[str, str, str]:
    if len(blob_records) != 2:
        raise SmokeFailure
    item_id = str(uuid.uuid4())
    decision_id = str(uuid.uuid4())
    request_id = str(uuid.uuid4())
    evidence_ids: list[str] = []
    attributes = json.dumps(
        {
            "display_name": "P06 synthetic linked item",
            "category": "top",
            "subcategory": "T-Shirt",
            "brand": None,
            "primary_color": "White",
            "size": None,
            "notes": "Exact-package PhotoKit smoke",
            "tags": ["p06-synthetic"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    forward = json.dumps(
        {
            "action": "save",
            "item_id": item_id,
            "fixture_sha256": [record[0] for record in blob_records],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    inverse = json.dumps(
        {"action": "deactivate", "item_id": item_id},
        sort_keys=True,
        separators=(",", ":"),
    )
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        revision = connection.execute(
            "SELECT catalog_revision + 1 FROM revision_state WHERE singleton = 1"
        ).fetchone()[0]
        now_ms = int(time.time() * 1000)
        connection.execute(
            "INSERT INTO catalog_items("
            "item_id,display_name,attributes_json,active,created_revision,updated_revision"
            ") VALUES(?,?,?,?,?,?)",
            (
                item_id,
                "P06 synthetic linked item",
                attributes,
                1,
                revision,
                revision,
            ),
        )
        for ordinal, (content_hash, byte_length) in enumerate(blob_records):
            if (
                not SHA256.fullmatch(content_hash)
                or type(byte_length) is not int
                or not 1 <= byte_length <= MAX_PHOTOKIT_BLOB_BYTES
            ):
                raise SmokeFailure
            source_id = str(uuid.uuid4())
            provenance_id = str(uuid.uuid4())
            evidence_id = str(uuid.uuid4())
            evidence_ids.append(evidence_id)
            locator = f"p06-synthetic-fixture-{ordinal}-{content_hash}"
            connection.execute(
                "INSERT INTO local_sources("
                "source_id,root_id,parent_source_id,source_kind,identity_key,"
                "canonical_locator,device_id,file_id,raw_sha256,blob_sha256,"
                "byte_length,byte_start,byte_end,occurrence_ordinal,media_type,"
                "status,no_blob_reason,manifest_generation,created_at_ms,updated_at_ms"
                ") VALUES(?,NULL,NULL,'folder_image',?,?,NULL,NULL,?,?,?,NULL,NULL,"
                "NULL,'image/png','imported',NULL,NULL,?,?)",
                (
                    source_id,
                    locator,
                    locator,
                    content_hash,
                    content_hash,
                    byte_length,
                    now_ms,
                    now_ms,
                ),
            )
            connection.execute(
                "INSERT INTO source_provenance("
                "provenance_id,source_id,request_id,observed_locator,raw_sha256,"
                "blob_sha256,observed_at_ms) VALUES(?,?,?,?,?,?,?)",
                (
                    provenance_id,
                    source_id,
                    str(uuid.uuid4()),
                    locator,
                    content_hash,
                    content_hash,
                    now_ms,
                ),
            )
            connection.execute(
                "INSERT INTO evidence("
                "evidence_id,source_id,part_id,evidence_kind,state,"
                "created_at_ms,updated_at_ms) "
                "VALUES(?,?,NULL,'image','assigned',?,?)",
                (evidence_id, source_id, now_ms, now_ms),
            )
            connection.execute(
                "INSERT INTO item_evidence(item_id,evidence_id,assigned_revision) "
                "VALUES(?,?,?)",
                (item_id, evidence_id, revision),
            )
        connection.execute(
            "INSERT INTO catalog_decisions("
            "decision_id,request_id,decision_kind,catalog_revision,"
            "forward_json,inverse_json,compensates_decision_id,created_at_ms"
            ") VALUES(?,?,?,?,?,?,NULL,?)",
            (
                decision_id,
                request_id,
                "save",
                revision,
                forward,
                inverse,
                now_ms,
            ),
        )
        connection.execute(
            "INSERT INTO decision_entities(decision_id,entity_kind,entity_id) "
            "VALUES(?, 'item', ?)",
            (decision_id, item_id),
        )
        for evidence_id in evidence_ids:
            connection.execute(
                "INSERT INTO decision_entities(decision_id,entity_kind,entity_id) "
                "VALUES(?, 'evidence', ?)",
                (decision_id, evidence_id),
            )
        connection.execute(
            "UPDATE revision_state SET catalog_revision = ? WHERE singleton = 1",
            (revision,),
        )
        connection.commit()
    return (
        item_id,
        decision_id,
        _canonical_closure_hash(database, item_id, decision_id),
    )


def _canonical_closure_hash(
    database: Path,
    item_id: str,
    decision_id: str,
) -> str:
    with sqlite3.connect(database) as connection:
        item = connection.execute(
            "SELECT item_id,display_name,attributes_json,active,"
            "created_revision,updated_revision FROM catalog_items WHERE item_id = ?",
            (item_id,),
        ).fetchone()
        assignments = connection.execute(
            "SELECT assignment.evidence_id,assignment.assigned_revision,"
            "evidence.state,source.source_id,source.identity_key,"
            "source.canonical_locator,source.raw_sha256,source.blob_sha256,"
            "source.byte_length,provenance.provenance_id,"
            "provenance.raw_sha256,provenance.blob_sha256,blob.byte_length "
            "FROM item_evidence assignment "
            "JOIN evidence ON evidence.evidence_id = assignment.evidence_id "
            "JOIN local_sources source ON source.source_id = evidence.source_id "
            "JOIN source_provenance provenance "
            "ON provenance.source_id = source.source_id "
            "JOIN blobs blob ON blob.sha256 = source.blob_sha256 "
            "WHERE assignment.item_id = ? "
            "ORDER BY source.blob_sha256,evidence.evidence_id",
            (item_id,),
        ).fetchall()
        decision = connection.execute(
            "SELECT decision_id,request_id,decision_kind,catalog_revision,"
            "forward_json,inverse_json,compensates_decision_id,created_at_ms "
            "FROM catalog_decisions WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        entities = connection.execute(
            "SELECT entity_kind,entity_id FROM decision_entities "
            "WHERE decision_id = ? ORDER BY entity_kind,entity_id",
            (decision_id,),
        ).fetchall()
    if (
        item is None
        or decision is None
        or len(assignments) != 2
        or len(entities) != 3
    ):
        raise SmokeFailure
    return _sha256(
        json.dumps(
            {
                "item": list(item),
                "assignments": [list(row) for row in assignments],
                "decision": list(decision),
                "entities": [list(row) for row in entities],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    )


def _run_smoke() -> dict[str, Any]:
    _set_failure_stage("preflight")
    challenge = _challenge()
    root = Path(__file__).resolve().parents[3]
    app = root / "target" / "release" / "bundle" / "macos" / "Wardrobe.app"
    identity_before = _app_identity(app)
    challenged_identity = {
        field: challenge[field]
        for field in (
            "bundle_id",
            "info_plist_sha256",
            "executable_sha256",
            "bundle_sha256",
            "designated_requirement_sha256",
        )
    }
    if identity_before != challenged_identity:
        raise SmokeFailure
    _ensure_not_running(app)

    with tempfile.TemporaryDirectory(prefix="wardrobe-p06-photokit-") as temporary:
        _set_failure_stage("fixture_setup")
        temporary_path = Path(temporary)
        fixture_folder = temporary_path / "fixtures"
        fixtures = _generate_fixtures(root, fixture_folder)
        _open_fixture_folder(fixture_folder)

        _set_failure_stage("isolation")
        with PrivateAppIsolation(identity_before["bundle_id"]) as isolation:
            _set_failure_stage("initial_album_setup")
            _dialog(
                "Finder now shows two reviewed synthetic images. Add both to "
                "Apple Photos and place exactly those two images in a new regular "
                "album dedicated to this smoke. Click Continue when the album is ready."
            )
            _dialog(INITIAL_SYNC_INSTRUCTIONS)
            _set_failure_stage("initial_app_sync")
            _launch_and_wait(app)
            _set_failure_stage("initial_verification")
            database = isolation.data_path / "wardrobe.sqlite3"
            before = _database_snapshot(database)
            if (
                before["observed"] != 2
                or before["available"] != 2
                or before["unavailable"] != 0
                or before["generation_observed"] != 2
                or before["blob_hashes"] != list(EXPECTED_FIXTURES)
                or before["attempt_count"] < 2
                or before["accepted_bytes"] <= 0
                or before["unavailable_blob_hashes"]
            ):
                raise SmokeFailure
            _verify_retained_cas(isolation.data_path, before["blob_records"])
            (
                item_id,
                decision_id,
                canonical_before,
            ) = _seed_linked_canonical_closure(database, before["blob_records"])

            _set_failure_stage("album_removal")
            _dialog(
                "With Wardrobe stopped, remove exactly one synthetic image from "
                "the dedicated album without deleting it from the Photos library. "
                "Click Continue when the album contains one image."
            )
            _dialog(
                "Wardrobe will relaunch. Wait for startup reconciliation to show "
                "1 available and 1 unavailable, then quit Wardrobe."
            )
            _set_failure_stage("startup_reconciliation")
            _launch_and_wait(app)
            _set_failure_stage("final_verification")
            after = _database_snapshot(database)
            canonical_after = _canonical_closure_hash(
                database,
                item_id,
                decision_id,
            )
            identity_after = _app_identity(app)
            _verify_retained_cas(isolation.data_path, after["blob_records"])
            if (
                identity_after != challenged_identity
                or identity_after != identity_before
                or after["trigger"] != "startup"
                or after["observed"] != 2
                or after["available"] != 1
                or after["unavailable"] != 1
                or after["generation_observed"] != 1
                or after["blob_hashes"] != list(EXPECTED_FIXTURES)
                or len(after["unavailable_blob_hashes"]) != 1
                or after["unavailable_blob_hashes"][0]
                not in [record[0] for record in before["blob_records"]]
                or after["asset_not_in_scope"] - before["asset_not_in_scope"] != 1
                or after["generation"] <= before["generation"]
                or after["photokit_revision"] <= before["photokit_revision"]
                or canonical_after != canonical_before
            ):
                raise SmokeFailure
            _set_failure_stage("fixture_cleanup_confirmation")
            _dialog(
                "The smoke passed. Remove the dedicated album and its two synthetic "
                "images from Photos, then click Continue to clean local smoke state."
            )
            _set_failure_stage("local_cleanup")

    return {
        "schema_version": 1,
        "event": "exact_package_missed_change",
        "run_id": RUN_ID,
        "challenge_nonce": challenge["challenge_nonce"],
        "packet_sha256": challenge["packet_sha256"],
        "source_sha256": challenge["source_sha256"],
        "exact_package": True,
        "same_package_relaunched": True,
        "bundle_id": identity_before["bundle_id"],
        "info_plist_sha256": identity_before["info_plist_sha256"],
        "executable_sha256": identity_before["executable_sha256"],
        "bundle_sha256": identity_before["bundle_sha256"],
        "designated_requirement_sha256": identity_before[
            "designated_requirement_sha256"
        ],
        "fixture_sha256": challenge["fixture_sha256"],
        "native_callbacks": True,
        "tcc_authorized": True,
        "dedicated_fixture_album": True,
        "operator_removal_completed": True,
        "initial_complete_generation": True,
        "startup_reconciled": True,
        "asset_not_in_scope_delta": 1,
        "membership_generation_delta": after["generation"] - before["generation"],
        "photokit_revision_delta": (
            after["photokit_revision"] - before["photokit_revision"]
        ),
        "available_before": before["available"],
        "unavailable_after": after["unavailable"],
        "blob_count_before": len(before["blob_hashes"]),
        "blob_count_after": len(after["blob_hashes"]),
        "synthetic_decision_preserved": True,
        "raw_identifiers_emitted": False,
        "personal_metadata_emitted": False,
    }

def _keychain_item_not_found(result: subprocess.CompletedProcess[bytes]) -> bool:
    output = (result.stdout + result.stderr).lower()
    return b"could not be found" in output or b"-25300" in output


def main() -> int:
    try:
        record = _run_smoke()
        output = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(output.encode()) > 16_384:
            raise SmokeFailure
        sys.stdout.write(OUTPUT_PREFIX + output + "\n")
        sys.stdout.flush()
        return 0
    except BaseException:
        _failure_dialog(CURRENT_FAILURE_STAGE)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
