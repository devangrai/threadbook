#!/usr/bin/env python3
"""Exact-package, deny-network smoke for the P09 local-only workflow."""

from __future__ import annotations

import argparse
from contextlib import AbstractContextManager
import ctypes
import hashlib
import http.server
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zlib
from typing import Any, Callable

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from tools.evaluators.p09_offline import hash_app_bundle
from tools.harness import source_fingerprint


BUNDLE_ID = "com.devrai.wardrobe"
PROCESS_WAIT_SECONDS = 30
WORKFLOW_WAIT_SECONDS = 20
MARKER_NAME = ".wardrobe-p09-offline-smoke-recovery.json"
OUTBOUND_TABLES = (
    "gmail_oauth_attempts",
    "gmail_operations",
    "receipt_image_attempts",
    "outfit_recommendation_attempts",
    "try_on_attempts",
    "photokit_operations",
    "photokit_materialization_attempts",
)
PIXEL_MAGIC = b"WDRBPIX1"
MEMBER_PIXEL_MAGIC = b"WDRBMEM1"
FIXTURE_RGB = ((227, 28, 61), (0, 168, 120))
FIXTURE_DIGESTS = (
    "68d0b42bbcbfe4a86b64c43fb15cbb88df19994604d1fcdd21196c1f8feb716b",
    "f3e25057c2571bb3b159110e800260582df2d6f984be9c67ced8fd1ed685b1dc",
)
FIXTURE_DIGEST_RGB = dict(zip(FIXTURE_DIGESTS, FIXTURE_RGB, strict=True))
FIXTURE_PIXEL_MIN_COUNT = 32
FIXTURE_CHANNEL_TOLERANCE = 24
MAX_MEMBER_PIXEL_SET_BYTES = 64 * 1024 * 1024
MAX_IOREG_PLIST_BYTES = 1024 * 1024
PROCESS_NONCE_ENV = "WARDROBE_P09_SMOKE_NONCE"
SRGB_PROFILE = Path("/System/Library/ColorSync/Profiles/sRGB Profile.icc")
PROC_PIDPATHINFO_MAXSIZE = 4096


class SmokeFailure(RuntimeError):
    pass


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
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


def write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write(
        path,
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode(),
    )


def remove_private_tree(path: Path, expected_parent: Path) -> None:
    if path.parent != expected_parent or path.is_symlink():
        raise SmokeFailure("unsafe private tree")
    if path.exists():
        shutil.rmtree(path)


def process_group_commands(pgid: int) -> tuple[str, ...]:
    return tuple(command for _pid, command in process_group_members(pgid))


def process_group_members(pgid: int) -> tuple[tuple[int, str], ...]:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid=,command="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise SmokeFailure("cannot inspect smoke process groups")
    members: list[tuple[int, str]] = []
    for raw_line in result.stdout.decode(errors="replace").splitlines():
        fields = raw_line.strip().split(maxsplit=2)
        if len(fields) != 3:
            continue
        try:
            pid = int(fields[0])
            candidate = int(fields[1])
        except ValueError:
            continue
        if candidate == pgid:
            members.append((pid, fields[2]))
    return tuple(members)


def process_executable_path(pid: int) -> Path | None:
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        proc_pidpath = library.proc_pidpath
        proc_pidpath.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        proc_pidpath.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)
        length = proc_pidpath(pid, buffer, len(buffer))
    except (AttributeError, OSError):
        return None
    if length <= 0:
        return None
    try:
        return Path(os.fsdecode(buffer.value))
    except UnicodeError:
        return None


def process_runs_executable(pid: int, executable: Path) -> bool:
    process_path = process_executable_path(pid)
    if process_path is None:
        return False
    try:
        return os.path.samefile(process_path, executable)
    except OSError:
        return False


def terminate_process_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not process_group_commands(pgid):
            return
        time.sleep(0.1)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not process_group_commands(pgid):
            return
        time.sleep(0.1)
    raise SmokeFailure("smoke process group did not terminate")


def terminate_recorded_process_group(record: Any) -> None:
    if (
        not isinstance(record, dict)
        or set(record)
        != {"pgid", "executable", "executable_sha256", "launch_nonce"}
        or not isinstance(record["pgid"], int)
        or isinstance(record["pgid"], bool)
        or record["pgid"] <= 1
        or not isinstance(record["executable"], str)
        or not Path(record["executable"]).is_absolute()
        or not isinstance(record["executable_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", record["executable_sha256"])
        or not isinstance(record["launch_nonce"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", record["launch_nonce"])
    ):
        raise SmokeFailure("invalid recorded smoke process group")
    commands = process_group_commands(record["pgid"])
    if not commands:
        return
    executable = Path(record["executable"])
    if (
        not executable.is_file()
        or sha256_file(executable) != record["executable_sha256"]
        or not any(record["executable"] in command for command in commands)
        or not process_has_nonce(record["pgid"], record["launch_nonce"])
    ):
        raise SmokeFailure("cannot authenticate recorded smoke process group")
    terminate_process_group(record["pgid"])


def process_has_nonce(pid: int, nonce: str) -> bool:
    result = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "command="],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        return False
    marker = f"{PROCESS_NONCE_ENV}={nonce}".encode()
    return marker in result.stdout


class PrivateAppIsolation(AbstractContextManager["PrivateAppIsolation"]):
    def __init__(self) -> None:
        home = Path.home()
        self.data_parent = home / "Library" / "Application Support"
        self.log_parent = home / "Library" / "Logs"
        self.data_path = self.data_parent / BUNDLE_ID
        self.log_path = self.log_parent / BUNDLE_ID
        self.marker = self.data_parent / MARKER_NAME
        self.entries: list[dict[str, Any]] = []
        self.process_groups: list[dict[str, Any]] = []

    def _paths(self, entry: dict[str, Any]) -> tuple[Path, Path, Path]:
        if set(entry) != {"kind", "had_original", "backup_name"}:
            raise SmokeFailure("invalid recovery entry")
        if entry["kind"] == "data":
            parent, current = self.data_parent, self.data_path
        elif entry["kind"] == "logs":
            parent, current = self.log_parent, self.log_path
        else:
            raise SmokeFailure("invalid recovery kind")
        name = entry["backup_name"]
        if (
            not isinstance(entry["had_original"], bool)
            or not isinstance(name, str)
            or not re.fullmatch(
                rf"\.{re.escape(BUNDLE_ID)}\.p09-[0-9a-f]{{32}}",
                name,
            )
        ):
            raise SmokeFailure("invalid recovery identity")
        return parent, current, parent / name

    def recover(self) -> None:
        if not self.marker.exists():
            return
        if self.marker.is_symlink() or self.marker.stat().st_size > 8192:
            raise SmokeFailure("unsafe recovery marker")
        try:
            record = json.loads(self.marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SmokeFailure("invalid recovery marker") from error
        if (
            not isinstance(record, dict)
            or set(record)
            != {"schema_version", "bundle_id", "entries", "process_groups"}
            or record["schema_version"] != 1
            or record["bundle_id"] != BUNDLE_ID
            or not isinstance(record["entries"], list)
            or len(record["entries"]) != 2
            or not isinstance(record["process_groups"], list)
            or len(record["process_groups"]) > 2
        ):
            raise SmokeFailure("invalid recovery marker contract")
        for process_group in record["process_groups"]:
            terminate_recorded_process_group(process_group)
        for entry in reversed(record["entries"]):
            parent, current, backup = self._paths(entry)
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if entry["had_original"]:
                if backup.exists():
                    if backup.is_symlink():
                        raise SmokeFailure("unsafe recovery backup")
                    remove_private_tree(current, parent)
                    os.replace(backup, current)
                elif not current.exists() or current.is_symlink():
                    raise SmokeFailure("missing recovery backup")
            else:
                remove_private_tree(current, parent)
                if backup.exists():
                    raise SmokeFailure("unexpected recovery backup")
        self.marker.unlink()

    def _write_marker(self) -> None:
        write_json(
            self.marker,
            {
                "schema_version": 1,
                "bundle_id": BUNDLE_ID,
                "entries": self.entries,
                "process_groups": self.process_groups,
            },
        )

    def register_process_group(
        self,
        process: subprocess.Popen[bytes],
        executable: Path,
        launch_nonce: str,
    ) -> None:
        entry = {
            "pgid": process.pid,
            "executable": str(executable),
            "executable_sha256": sha256_file(executable),
            "launch_nonce": launch_nonce,
        }
        if entry in self.process_groups or len(self.process_groups) >= 2:
            raise SmokeFailure("invalid smoke process-group registration")
        self.process_groups.append(entry)
        self._write_marker()

    def unregister_process_group(self, process: subprocess.Popen[bytes] | None) -> None:
        if process is None:
            return
        self.process_groups = [
            entry for entry in self.process_groups if entry["pgid"] != process.pid
        ]
        if self.marker.exists():
            self._write_marker()

    def __enter__(self) -> "PrivateAppIsolation":
        self.recover()
        token = uuid.uuid4().hex
        self.entries = [
            {
                "kind": "data",
                "had_original": self.data_path.exists(),
                "backup_name": f".{BUNDLE_ID}.p09-{token}",
            },
            {
                "kind": "logs",
                "had_original": self.log_path.exists(),
                "backup_name": f".{BUNDLE_ID}.p09-{token}",
            },
        ]
        self.process_groups = []
        self._write_marker()
        try:
            for entry in self.entries:
                parent, current, backup = self._paths(entry)
                parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if current.is_symlink() or backup.exists():
                    raise SmokeFailure("unsafe isolation target")
                if entry["had_original"]:
                    os.replace(current, backup)
            return self
        except BaseException:
            self.recover()
            self.entries = []
            raise

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        self.recover()
        self.entries = []
        self.process_groups = []
        return False


class AccessibilityDriver:
    def __init__(self, pid: int) -> None:
        self.pid = pid

    def script(self, body: str) -> str:
        source = f"""
var systemEvents = Application("System Events");
var processes = systemEvents.processes.whose({{unixId: {self.pid}}});
if (processes.length === 0) throw new Error("process unavailable");
var appProcess = processes[0];
appProcess.frontmost = true;
var result = (function() {{
{body}
}})();
result;
"""
        result = subprocess.run(
            ["/usr/bin/osascript", "-l", "JavaScript", "-e", source],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
        if result.returncode != 0:
            detail = result.stderr.decode(errors="replace").strip()
            raise SmokeFailure(f"accessibility automation failed: {detail}")
        return result.stdout.decode(errors="replace").strip()

    def wait_ready(self) -> None:
        deadline = time.monotonic() + PROCESS_WAIT_SECONDS
        last_error = ""
        while time.monotonic() < deadline:
            try:
                if self.script(
                    '  return appProcess.windows.length > 0 ? "ready" : "waiting";'
                ) == "ready":
                    return
            except SmokeFailure as error:
                last_error = str(error)
            time.sleep(0.25)
        raise SmokeFailure(f"Wardrobe accessibility window unavailable: {last_error}")

    def dump(self) -> str:
        return self.script(
            """
  var elements = appProcess.windows[0].entireContents();
  var lines = [];
  function read(callback) {
    try {
      var value = callback();
      return value === null || value === undefined ? "" : String(value);
    } catch (_) {
      return "";
    }
  }
  for (var index = 0; index < elements.length; index++) {
    var element = elements[index];
    lines.push([
      read(function() { return element.role(); }),
      read(function() { return element.name(); }),
      read(function() { return element.value(); }),
      read(function() { return element.enabled(); })
    ].join("|"));
  }
  return lines.join("\\n");
"""
        )

    def wait_text(self, value: str) -> None:
        deadline = time.monotonic() + WORKFLOW_WAIT_SECONDS
        transcript = ""
        while time.monotonic() < deadline:
            transcript = self.dump()
            if value in transcript:
                return
            time.sleep(0.25)
        raise SmokeFailure(
            f"accessibility text did not appear: {value}; "
            f"tree={transcript[:4000]!r}"
        )

    def click(self, role: str, name: str, occurrence: int = 1) -> None:
        role_json = json.dumps(role)
        name_json = json.dumps(name)
        result = self.script(
            f"""
  var elements = appProcess.windows[0].entireContents();
  var matchCount = 0;
  for (var index = 0; index < elements.length; index++) {{
    var matches = false;
    try {{
      matches = elements[index].role() === {role_json} &&
        elements[index].name() === {name_json};
    }} catch (_) {{}}
    if (!matches) continue;
    matchCount += 1;
    if (matchCount === {occurrence}) {{
      try {{ elements[index].click(); }} catch (_) {{}}
      return "clicked";
    }}
  }}
  return "missing";
"""
        )
        if result != "clicked":
            raise SmokeFailure(
                f"accessibility element missing: {role} {name}; "
                f"tree={self.dump()[:4000]!r}"
            )

    def click_role(self, role: str, occurrence: int) -> None:
        role_json = json.dumps(role)
        result = self.script(
            f"""
  var elements = appProcess.windows[0].entireContents();
  var matchCount = 0;
  for (var index = 0; index < elements.length; index++) {{
    var matches = false;
    try {{
      matches = elements[index].role() === {role_json} &&
        elements[index].enabled();
    }} catch (_) {{}}
    if (!matches) continue;
    matchCount += 1;
    if (matchCount === {occurrence}) {{
      try {{ elements[index].click(); }} catch (_) {{}}
      return "clicked";
    }}
  }}
  return "missing";
"""
        )
        if result != "clicked":
            raise SmokeFailure(
                f"accessibility role missing: {role} #{occurrence}; "
                f"tree={self.dump()[:4000]!r}"
            )

    def select_next_popup_option(self, occurrence: int = 1) -> None:
        self.click_role("AXPopUpButton", occurrence)
        self.script(
            """
  systemEvents.keyCode(125);
  systemEvents.keyCode(36);
  return "selected";
"""
        )

    def element_enabled(self, role: str, name: str) -> bool:
        role_json = json.dumps(role)
        name_json = json.dumps(name)
        result = self.script(
            f"""
  var elements = appProcess.windows[0].entireContents();
  for (var index = 0; index < elements.length; index++) {{
    try {{
      if (elements[index].role() === {role_json} &&
          elements[index].name() === {name_json}) {{
        return elements[index].enabled() ? "true" : "false";
      }}
    }} catch (_) {{}}
  }}
  return "missing";
"""
        )
        if result == "true":
            return True
        if result == "false":
            return False
        raise SmokeFailure(f"accessibility element missing: {role} {name}")

    def element_value(self, role: str, name: str) -> str | None:
        role_json = json.dumps(role)
        name_json = json.dumps(name)
        result = self.script(
            f"""
  var elements = appProcess.windows[0].entireContents();
  for (var index = 0; index < elements.length; index++) {{
    try {{
      if (elements[index].role() === {role_json} &&
          elements[index].name() === {name_json}) {{
        return String(elements[index].value());
      }}
    }} catch (_) {{}}
  }}
  return "__missing__";
"""
        )
        return None if result == "__missing__" else result

    def element_frame(self, role: str, name: str) -> tuple[int, int, int, int]:
        role_json = json.dumps(role)
        name_json = json.dumps(name)
        result = self.script(
            f"""
  var elements = appProcess.windows[0].entireContents();
  for (var index = 0; index < elements.length; index++) {{
    try {{
      if (elements[index].role() === {role_json} &&
          elements[index].name() === {name_json}) {{
        var position = elements[index].position();
        var size = elements[index].size();
        return JSON.stringify({{
          x: Math.round(position[0]),
          y: Math.round(position[1]),
          width: Math.round(size[0]),
          height: Math.round(size[1])
        }});
      }}
    }} catch (_) {{}}
  }}
  return "__missing__";
"""
        )
        if result == "__missing__":
            raise SmokeFailure(f"accessibility frame missing: {role} {name}")
        try:
            frame = json.loads(result)
        except json.JSONDecodeError as error:
            raise SmokeFailure("invalid accessibility frame") from error
        if (
            not isinstance(frame, dict)
            or set(frame) != {"x", "y", "width", "height"}
            or not all(
                isinstance(frame[field], int)
                for field in ("x", "y", "width", "height")
            )
            or frame["width"] < 32
            or frame["height"] < 32
            or frame["width"] > 4096
            or frame["height"] > 4096
        ):
            raise SmokeFailure("unsafe accessibility frame")
        return (
            frame["x"],
            frame["y"],
            frame["width"],
            frame["height"],
        )

    def element_frame_named(self, name: str) -> tuple[int, int, int, int]:
        name_json = json.dumps(name)
        result = self.script(
            f"""
  var elements = appProcess.windows[0].entireContents();
  var matches = [];
  for (var index = 0; index < elements.length; index++) {{
    try {{
      if (elements[index].name() === {name_json}) {{
        var position = elements[index].position();
        var size = elements[index].size();
        matches.push({{
          x: Math.round(position[0]),
          y: Math.round(position[1]),
          width: Math.round(size[0]),
          height: Math.round(size[1])
        }});
      }}
    }} catch (_) {{}}
  }}
  return JSON.stringify(matches);
"""
        )
        try:
            matches = json.loads(result)
        except json.JSONDecodeError as error:
            raise SmokeFailure("invalid named accessibility frame") from error
        if (
            not isinstance(matches, list)
            or len(matches) != 1
            or not isinstance(matches[0], dict)
        ):
            raise SmokeFailure(f"accessibility frame is not unique: {name}")
        frame = matches[0]
        if (
            set(frame) != {"x", "y", "width", "height"}
            or not all(
                isinstance(frame[field], int)
                for field in ("x", "y", "width", "height")
            )
            or frame["width"] < 32
            or frame["height"] < 32
            or frame["width"] > 4096
            or frame["height"] > 4096
        ):
            raise SmokeFailure("unsafe named accessibility frame")
        return (
            frame["x"],
            frame["y"],
            frame["width"],
            frame["height"],
        )

    def keystroke(self, value: str, *, select_all: bool = False) -> None:
        value_json = json.dumps(value)
        prefix = (
            '  systemEvents.keystroke("a", {using: "command down"});\n'
            if select_all
            else ""
        )
        self.script(
            f"{prefix}  systemEvents.keystroke({value_json});\n"
            '  return "typed";'
        )

    def choose_folder(self, path: Path) -> None:
        self.click("AXButton", "Choose folder")
        time.sleep(0.5)
        path_json = json.dumps(str(path))
        self.script(
            """
  systemEvents.keystroke("g", {using: ["command down", "shift down"]});
  return "opened";
"""
        )
        deadline = time.monotonic() + WORKFLOW_WAIT_SECONDS
        while time.monotonic() < deadline:
            result = self.script(
                f"""
  var elements = appProcess.windows[0].entireContents();
  for (var index = elements.length - 1; index >= 0; index--) {{
    try {{
      if (elements[index].role() === "AXTextField" &&
          String(elements[index].value()).indexOf("/") === 0) {{
        elements[index].value = {path_json};
        return String(elements[index].value());
      }}
    }} catch (_) {{}}
  }}
  return "__missing__";
"""
            )
            if result == str(path):
                break
            time.sleep(0.25)
        else:
            raise SmokeFailure("native Go to Folder field did not appear")
        self.script(
            """
  systemEvents.keyCode(36);
  return "submitted";
"""
        )
        deadline = time.monotonic() + WORKFLOW_WAIT_SECONDS
        while time.monotonic() < deadline:
            if self.element_value("AXPopUpButton", "Where:") == path.name:
                break
            time.sleep(0.25)
        else:
            raise SmokeFailure("native chooser did not navigate to fixture folder")
        self.click("AXButton", "Open")

    def quit(self) -> None:
        self.script(
            '  systemEvents.keystroke("q", {using: "command down"});\n'
            '  return "quit";'
        )


def wait_for(predicate: Callable[[], bool], description: str) -> None:
    deadline = time.monotonic() + WORKFLOW_WAIT_SECONDS
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (OSError, sqlite3.Error):
            pass
        time.sleep(0.25)
    raise SmokeFailure(f"timed out waiting for {description}")


def scalar(database: Path, sql: str, parameters: tuple[Any, ...] = ()) -> Any:
    with sqlite3.connect(database) as connection:
        row = connection.execute(sql, parameters).fetchone()
    return row[0] if row else None


def launch(
    executable: Path,
    sandbox_profile: Path,
    process_log: Path,
) -> tuple[subprocess.Popen[bytes], Any, str]:
    log_handle = process_log.open("ab")
    launch_nonce = uuid.uuid4().hex
    environment = os.environ.copy()
    environment[PROCESS_NONCE_ENV] = launch_nonce
    process = subprocess.Popen(
        [
            "/bin/sh",
            "-c",
            (
                'IFS= read -r token || exit 0; '
                '[ "$token" = go ] || exit 0; '
                '/usr/bin/sandbox-exec -f "$1" "$2" & '
                'child=$!; wait "$child"'
            ),
            "wardrobe-p09-launch-gate",
            str(sandbox_profile),
            str(executable),
            f"{PROCESS_NONCE_ENV}={launch_nonce}",
        ],
        stdin=subprocess.PIPE,
        stdout=log_handle,
        stderr=log_handle,
        start_new_session=True,
        env=environment,
    )
    return process, log_handle, launch_nonce


def release_launch(
    process: subprocess.Popen[bytes],
    executable: Path,
) -> int:
    if process.stdin is None or process.stdin.closed or process.poll() is not None:
        raise SmokeFailure("smoke launch gate is unavailable")
    try:
        process.stdin.write(b"go\n")
        process.stdin.flush()
        process.stdin.close()
    except (BrokenPipeError, OSError) as error:
        raise SmokeFailure("smoke launch gate failed") from error
    deadline = time.monotonic() + PROCESS_WAIT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SmokeFailure("smoke process exited before application launch")
        for pid, _command in process_group_members(process.pid):
            if (
                pid != process.pid
                and process_runs_executable(pid, executable)
            ):
                return pid
        time.sleep(0.1)
    raise SmokeFailure("smoke application child did not launch")


def stop(
    process: subprocess.Popen[bytes],
    log_handle: Any,
    driver: AccessibilityDriver,
) -> int:
    driver.quit()
    try:
        returncode = process.wait(timeout=PROCESS_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait(timeout=5)
    finally:
        log_handle.close()
    if process_group_commands(process.pid):
        terminate_process_group(process.pid)
    return returncode


def force_stop(process: subprocess.Popen[bytes] | None, log_handle: Any) -> None:
    if process is not None and process.stdin is not None and not process.stdin.closed:
        try:
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    if process is not None and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
    if process is not None and process_group_commands(process.pid):
        terminate_process_group(process.pid)
    if log_handle is not None and not log_handle.closed:
        log_handle.close()


def fixture_png(rgb: tuple[int, int, int]) -> bytes:
    width = 64
    height = 64
    scanlines = b"".join(
        b"\0" + bytes(rgb) * width
        for _ in range(height)
    )

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"sRGB", b"\0")
        + chunk(b"IDAT", zlib.compress(scanlines))
        + chunk(b"IEND", b"")
    )


def fixture_sources(_root: Path, destination: Path) -> tuple[str, ...]:
    destination.mkdir(mode=0o700, parents=True)
    sources = (
        (destination / "white-shirt.png", fixture_png(FIXTURE_RGB[0])),
        (destination / "navy-trousers.png", fixture_png(FIXTURE_RGB[1])),
    )
    for target, contents in sources:
        atomic_write(target, contents)
        target.chmod(0o600)
    digests = tuple(sha256_file(target) for target, _ in sources)
    if digests != FIXTURE_DIGESTS:
        raise SmokeFailure("fixture bytes do not match the reviewed source digests")
    return digests


def canonical_collage(
    database: Path,
    data_path: Path,
    required_blob_digests: tuple[str, ...] | None = None,
) -> str:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        outfits = connection.execute(
            "SELECT outfit_id,name,created_outfit_revision FROM outfits "
            "ORDER BY created_outfit_revision"
        ).fetchall()
        if len(outfits) != 1:
            raise SmokeFailure("expected one saved outfit")
        members = connection.execute(
            "SELECT ordinal,item_id,item_updated_revision,attributes_json,"
            "asset_state,evidence_id,source_id,blob_sha256,media_type,"
            "byte_length,width,height FROM outfit_members "
            "WHERE outfit_id = ? ORDER BY ordinal",
            (outfits[0]["outfit_id"],),
        ).fetchall()
    if len(members) != 2:
        raise SmokeFailure("expected two collage members")
    encoded_members: list[dict[str, Any]] = []
    member_digests: list[str] = []
    for member in members:
        record = dict(member)
        blob_sha256 = record["blob_sha256"]
        if record["asset_state"] != "available" or blob_sha256 is None:
            raise SmokeFailure("collage member has no rendered source image")
        blob = (
            data_path
            / "blobs"
            / "sha256"
            / blob_sha256[:2]
            / blob_sha256[2:4]
            / blob_sha256
        )
        if (
            blob.is_symlink()
            or not blob.is_file()
            or sha256_file(blob) != blob_sha256
            or blob.stat().st_size != record["byte_length"]
        ):
            raise SmokeFailure("collage source blob is invalid")
        member_digests.append(blob_sha256)
        encoded_members.append(record)
    if required_blob_digests is not None and sorted(member_digests) != sorted(
        required_blob_digests
    ):
        raise SmokeFailure("collage members do not match imported source images")
    payload = {
        "outfit": dict(outfits[0]),
        "members": encoded_members,
    }
    return sha256_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )


def ordered_collage_member_digests(database: Path) -> tuple[str, ...]:
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT ordinal,blob_sha256 FROM outfit_members "
            "ORDER BY ordinal"
        ).fetchall()
    if (
        len(rows) != 2
        or [row[0] for row in rows] != [0, 1]
        or any(
            not isinstance(row[1], str)
            or re.fullmatch(r"[0-9a-f]{64}", row[1]) is None
            for row in rows
        )
        or {row[1] for row in rows} != set(FIXTURE_DIGESTS)
    ):
        raise SmokeFailure("ordered collage member digests are invalid")
    return tuple(row[1] for row in rows)


def paeth_predictor(left: int, up: int, upper_left: int) -> int:
    candidate = left + up - upper_left
    left_distance = abs(candidate - left)
    up_distance = abs(candidate - up)
    upper_left_distance = abs(candidate - upper_left)
    if left_distance <= up_distance and left_distance <= upper_left_distance:
        return left
    if up_distance <= upper_left_distance:
        return up
    return upper_left


def canonical_png_pixels(path: Path) -> bytes:
    data = path.read_bytes()
    if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) > 64 * 1024 * 1024:
        raise SmokeFailure("collage capture is not a bounded PNG")
    offset = 8
    header: tuple[int, int, int, int, int, int, int] | None = None
    compressed = bytearray()
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if chunk_end > len(data):
            raise SmokeFailure("collage PNG chunk is truncated")
        chunk = data[offset + 8 : offset + 8 + length]
        if chunk_type == b"IHDR":
            if header is not None or length != 13:
                raise SmokeFailure("collage PNG header is invalid")
            header = struct.unpack(">IIBBBBB", chunk)
        elif chunk_type == b"IDAT":
            compressed.extend(chunk)
        elif chunk_type == b"IEND":
            break
        offset = chunk_end
    if header is None or not compressed:
        raise SmokeFailure("collage PNG has no image data")
    width, height, depth, color_type, compression, filtering, interlace = header
    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color_type)
    if (
        channels is None
        or depth != 8
        or compression != 0
        or filtering != 0
        or interlace != 0
        or not 32 <= width <= 8192
        or not 32 <= height <= 8192
    ):
        raise SmokeFailure("collage PNG format is unsupported")
    stride = width * channels
    try:
        filtered = zlib.decompress(bytes(compressed))
    except zlib.error as error:
        raise SmokeFailure("collage PNG image data is corrupt") from error
    if len(filtered) != (stride + 1) * height:
        raise SmokeFailure("collage PNG scanline length is invalid")
    pixels = bytearray(stride * height)
    source_offset = 0
    for row in range(height):
        filter_type = filtered[source_offset]
        source_offset += 1
        row_start = row * stride
        prior_start = (row - 1) * stride
        for column in range(stride):
            encoded = filtered[source_offset + column]
            left = pixels[row_start + column - channels] if column >= channels else 0
            up = pixels[prior_start + column] if row > 0 else 0
            upper_left = (
                pixels[prior_start + column - channels]
                if row > 0 and column >= channels
                else 0
            )
            if filter_type == 0:
                value = encoded
            elif filter_type == 1:
                value = encoded + left
            elif filter_type == 2:
                value = encoded + up
            elif filter_type == 3:
                value = encoded + ((left + up) // 2)
            elif filter_type == 4:
                value = encoded + paeth_predictor(left, up, upper_left)
            else:
                raise SmokeFailure("collage PNG uses an invalid filter")
            pixels[row_start + column] = value & 0xFF
        source_offset += stride
    unique_pixels: set[bytes] = set()
    for offset in range(0, len(pixels), channels):
        unique_pixels.add(bytes(pixels[offset : offset + channels]))
        if len(unique_pixels) >= 16:
            break
    if len(unique_pixels) < 2:
        raise SmokeFailure("collage capture is blank or visually degenerate")
    return PIXEL_MAGIC + struct.pack(">IIB", width, height, channels) + bytes(pixels)


def normalize_capture_to_srgb(source: Path, destination: Path) -> None:
    if (
        SRGB_PROFILE.is_symlink()
        or not SRGB_PROFILE.is_file()
        or source.is_symlink()
        or not source.is_file()
    ):
        raise SmokeFailure("sRGB capture normalization inputs are unavailable")
    result = subprocess.run(
        [
            "/usr/bin/sips",
            "--matchTo",
            str(SRGB_PROFILE),
            str(source),
            "--out",
            str(destination),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    if (
        result.returncode != 0
        or destination.is_symlink()
        or not destination.is_file()
    ):
        detail = result.stderr.decode(errors="replace").strip()
        raise SmokeFailure(f"collage sRGB normalization failed: {detail}")


def require_member_fixture_pixels(
    canonical: bytes,
    expected_rgb: tuple[int, int, int],
) -> None:
    header_length = len(PIXEL_MAGIC) + 9
    if not canonical.startswith(PIXEL_MAGIC) or len(canonical) < header_length:
        raise SmokeFailure("member pixels are not canonical")
    width, height, channels = struct.unpack(
        ">IIB", canonical[len(PIXEL_MAGIC) : header_length]
    )
    pixels = canonical[header_length:]
    if channels < 3 or len(pixels) != width * height * channels:
        raise SmokeFailure("member pixels cannot prove fixture rendering")
    count = sum(
        all(
            abs(pixels[offset + channel] - expected_rgb[channel])
            <= FIXTURE_CHANNEL_TOLERANCE
            for channel in range(3)
        )
        for offset in range(0, len(pixels), channels)
    )
    minimum_count = max(FIXTURE_PIXEL_MIN_COUNT, width * height // 2)
    maximum_count = width * height * 9 // 10
    if count < minimum_count or count > maximum_count:
        raise SmokeFailure(
            "collage member did not render its pinned source image "
            f"(anchor count {count}, required {minimum_count}..{maximum_count})"
        )


def capture_stable_member(
    driver: AccessibilityDriver,
    ordinal: int,
    expected_rgb: tuple[int, int, int],
) -> bytes:
    previous: bytes | None = None
    with tempfile.TemporaryDirectory(prefix="wardrobe-p09-capture-") as directory:
        capture = Path(directory) / "member.png"
        normalized = Path(directory) / "member-srgb.png"
        for attempt in range(6):
            frame = driver.element_frame_named(
                f"Outfit member {ordinal} source image"
            )
            result = subprocess.run(
                [
                    "/usr/sbin/screencapture",
                    "-x",
                    f"-R{frame[0]},{frame[1]},{frame[2]},{frame[3]}",
                    str(capture),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
                timeout=20,
            )
            if result.returncode != 0:
                detail = result.stderr.decode(errors="replace").strip()
                raise SmokeFailure(f"member screen capture failed: {detail}")
            normalized.unlink(missing_ok=True)
            normalize_capture_to_srgb(capture, normalized)
            current = canonical_png_pixels(normalized)
            try:
                require_member_fixture_pixels(current, expected_rgb)
            except SmokeFailure:
                if attempt == 5:
                    raise
                time.sleep(0.4)
                continue
            if previous == current:
                return current
            previous = current
            time.sleep(0.4)
    raise SmokeFailure("member pixels did not stabilize")


def encode_member_pixel_set(
    records: tuple[tuple[int, str, bytes], ...],
) -> bytes:
    if (
        len(records) != 2
        or [record[0] for record in records] != [0, 1]
        or {record[1] for record in records} != set(FIXTURE_DIGESTS)
    ):
        raise SmokeFailure("member pixel records are not closed and ordered")
    encoded = bytearray(MEMBER_PIXEL_MAGIC)
    encoded.extend(struct.pack(">B", len(records)))
    for ordinal, digest, pixels in records:
        if (
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not pixels.startswith(PIXEL_MAGIC)
            or len(pixels) > MAX_MEMBER_PIXEL_SET_BYTES
        ):
            raise SmokeFailure("member pixel record is invalid")
        encoded.extend(
            struct.pack(">B32sI", ordinal, bytes.fromhex(digest), len(pixels))
        )
        encoded.extend(pixels)
    if len(encoded) > MAX_MEMBER_PIXEL_SET_BYTES:
        raise SmokeFailure("member pixel set exceeds the evidence size bound")
    return bytes(encoded)


def capture_stable_collage(
    driver: AccessibilityDriver,
    output: Path,
    member_digests: tuple[str, ...],
) -> str:
    if (
        len(member_digests) != 2
        or set(member_digests) != set(FIXTURE_DIGESTS)
    ):
        raise SmokeFailure("collage member digest set is invalid")
    records = tuple(
        (
            ordinal,
            digest,
            capture_stable_member(
                driver,
                ordinal,
                FIXTURE_DIGEST_RGB[digest],
            ),
        )
        for ordinal, digest in enumerate(member_digests)
    )
    encoded = encode_member_pixel_set(records)
    atomic_write(output, encoded)
    return sha256_bytes(encoded)


def outbound_attempt_count(connection: sqlite3.Connection) -> int:
    existing = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table'"
        )
    }
    return sum(
        connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in OUTBOUND_TABLES
        if table in existing
    )


def residual_scan(
    database: Path,
    data_path: Path,
    log_path: Path,
    fixture_digests: tuple[str, ...],
    fixture_path: Path,
) -> dict[str, Any]:
    with sqlite3.connect(database) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
        source_digests = sorted(
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT blob_sha256 FROM local_sources "
                "WHERE status = 'imported' AND blob_sha256 IS NOT NULL"
            )
        )
        blob_rows = connection.execute(
            "SELECT sha256,byte_length FROM blobs ORDER BY sha256"
        ).fetchall()
        item_count = connection.execute(
            "SELECT COUNT(*) FROM catalog_items WHERE active = 1"
        ).fetchone()[0]
        assigned_count = connection.execute(
            "SELECT COUNT(*) FROM evidence WHERE state = 'assigned'"
        ).fetchone()[0]
        outfit_count = connection.execute("SELECT COUNT(*) FROM outfits").fetchone()[0]
        outfit_member_digests = [
            {
                "ordinal": row[0],
                "blob_sha256": row[1],
            }
            for row in connection.execute(
                "SELECT ordinal,blob_sha256 FROM outfit_members "
                "ORDER BY ordinal"
            )
        ]
        outbound_count = outbound_attempt_count(connection)
    if (
        integrity != "ok"
        or foreign_keys
        or schema_version != 13
        or source_digests != sorted(fixture_digests)
        or item_count != 2
        or assigned_count != 2
        or outfit_count != 1
        or [row["ordinal"] for row in outfit_member_digests] != [0, 1]
        or {row["blob_sha256"] for row in outfit_member_digests}
        != set(fixture_digests)
        or outbound_count != 0
    ):
        raise SmokeFailure("database residual scan failed")
    verified_blobs: list[str] = []
    for digest, length in blob_rows:
        blob = (
            data_path
            / "blobs"
            / "sha256"
            / digest[:2]
            / digest[2:4]
            / digest
        )
        metadata = blob.lstat()
        if (
            blob.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != length
            or sha256_file(blob) != digest
        ):
            raise SmokeFailure("content-addressed blob scan failed")
        verified_blobs.append(digest)
    forbidden = private_markers(fixture_path)
    log_digest = hashlib.sha256()
    total_log_bytes = 0
    if log_path.exists():
        for path in sorted(log_path.rglob("*")):
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise SmokeFailure("application log tree has an unsafe entry")
            if metadata.st_nlink != 1 or metadata.st_size > 1024 * 1024:
                raise SmokeFailure("application log entry is unsafe or oversized")
            contents = path.read_bytes()
            total_log_bytes += len(contents)
            if total_log_bytes > 4 * 1024 * 1024:
                raise SmokeFailure("application log tree is unbounded")
            reject_private_bytes(contents, forbidden, "application logs")
            log_digest.update(path.relative_to(log_path).as_posix().encode())
            log_digest.update(b"\0")
            log_digest.update(contents)
            log_digest.update(b"\0")
    return {
        "schema_version": 1,
        "integrity_check": integrity,
        "foreign_key_violation_count": len(foreign_keys),
        "database_schema_version": schema_version,
        "source_digests": source_digests,
        "verified_blob_digests": verified_blobs,
        "active_item_count": item_count,
        "assigned_evidence_count": assigned_count,
        "outfit_count": outfit_count,
        "outfit_member_digests": outfit_member_digests,
        "outbound_attempt_record_count": outbound_count,
        "log_tree_sha256": log_digest.hexdigest(),
        "collage_contract_sha256": canonical_collage(
            database,
            data_path,
            fixture_digests,
        ),
    }


def private_markers(fixture_path: Path) -> tuple[bytes, ...]:
    return (
        str(fixture_path).encode(),
        b"white-shirt.png",
        b"navy-trousers.png",
        b"White Shirt",
        b"Navy Trousers",
        b"Navy Date Trousers",
        b"Dinner Date",
    )


def reject_private_bytes(
    contents: bytes,
    forbidden: tuple[bytes, ...],
    label: str,
) -> None:
    if any(marker in contents for marker in forbidden):
        raise SmokeFailure(f"{label} retained personal smoke content")


def verify_bundle(bundle: Path) -> tuple[Path, str, str]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise SmokeFailure("production application bundle is missing")
    info_path = bundle / "Contents" / "Info.plist"
    with info_path.open("rb") as handle:
        info = plistlib.load(handle)
    if info.get("CFBundleIdentifier") != BUNDLE_ID:
        raise SmokeFailure("unexpected application bundle identity")
    executable_name = info.get("CFBundleExecutable")
    if not isinstance(executable_name, str):
        raise SmokeFailure("application executable identity is missing")
    executable = bundle / "Contents" / "MacOS" / executable_name
    subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(bundle)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    bundle_hash, _, errors = hash_app_bundle(bundle)
    if errors:
        raise SmokeFailure("; ".join(errors))
    return executable, bundle_hash, sha256_file(executable)


def ensure_app_not_running(executable: Path) -> None:
    result = subprocess.run(
        ["/usr/bin/pgrep", "-f", str(executable)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if result.returncode not in {0, 1}:
        raise SmokeFailure("cannot inspect existing Wardrobe processes")
    if result.returncode == 0 and result.stdout.strip():
        raise SmokeFailure("Wardrobe must be closed before the offline smoke")


def require_interactive_console_session() -> None:
    result = subprocess.run(
        ["/usr/sbin/ioreg", "-a", "-n", "Root", "-d", "1"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if (
        result.returncode != 0
        or not result.stdout
        or len(result.stdout) > MAX_IOREG_PLIST_BYTES
    ):
        raise SmokeFailure("cannot verify the macOS console session")
    try:
        registry = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as error:
        raise SmokeFailure("cannot verify the macOS console session") from error
    if not isinstance(registry, dict):
        raise SmokeFailure("cannot verify the macOS console session")
    users = registry.get("IOConsoleUsers")
    if not isinstance(users, list):
        raise SmokeFailure("cannot verify the macOS console session")
    active = [
        user
        for user in users
        if isinstance(user, dict)
        and user.get("kCGSSessionOnConsoleKey") is True
    ]
    if len(active) != 1:
        raise SmokeFailure(
            "macOS console session is not active for the accessibility smoke"
        )
    session = active[0]
    if session.get("CGSSessionScreenIsLocked") is True:
        raise SmokeFailure(
            "macOS console session is locked; unlock it before the "
            "accessibility smoke"
        )
    if (
        session.get("CGSSessionScreenIsLocked") is not False
        or session.get("kCGSessionLoginDoneKey") is not True
    ):
        raise SmokeFailure("cannot verify an unlocked macOS console session")


def verify_sandbox(profile: Path, log: Path) -> None:
    class ProbeHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
            self.send_response(204)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    command = [
        "/usr/bin/curl",
        "--connect-timeout",
        "1",
        "--max-time",
        "2",
        url,
    ]
    try:
        control = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=10,
        )
        denied = subprocess.run(
            [
                "/usr/bin/sandbox-exec",
                "-f",
                str(profile),
                "/bin/sh",
                "-c",
                " ".join(command),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=10,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    with log.open("ab") as handle:
        handle.write(
            f"network-child-control returncode={control.returncode}\n".encode()
        )
        handle.write(control.stdout)
        handle.write(
            f"\nnetwork-child-denied returncode={denied.returncode}\n".encode()
        )
        handle.write(denied.stdout)
    if control.returncode != 0 or denied.returncode == 0:
        raise SmokeFailure("deny-network sandbox preflight was not established")


def run_smoke(root: Path, output: Path) -> None:
    output.unlink(missing_ok=True)
    support = output.parent / "offline-smoke"
    if support.exists() and (support.is_symlink() or not support.is_dir()):
        raise SmokeFailure("offline smoke support path is unsafe")
    if support.exists():
        remove_private_tree(support, output.parent)
    support.mkdir(mode=0o700, parents=True, exist_ok=True)
    profile = support / "deny-network.sb"
    sandbox_log = support / "sandbox.log"
    transcript_path = support / "accessibility.txt"
    residual_path = support / "residual-scan.json"
    collage_before_path = support / "collage-before.pixels"
    collage_after_path = support / "collage-after.pixels"
    bundle = root / "target/release/bundle/macos/Wardrobe.app"
    executable, bundle_hash, executable_hash = verify_bundle(bundle)
    isolation = PrivateAppIsolation()
    isolation.recover()
    ensure_app_not_running(executable)
    require_interactive_console_session()
    atomic_write(profile, b"(version 1)\n(allow default)\n(deny network*)\n")
    atomic_write(sandbox_log, b"")
    verify_sandbox(profile, sandbox_log)

    with tempfile.TemporaryDirectory(prefix="wardrobe-p09-offline-") as temporary:
        temporary_path = Path(temporary)
        fixture_path = temporary_path / "fixtures"
        fixture_digests = fixture_sources(root, fixture_path)
        process_log = temporary_path / "process.log"
        atomic_write(process_log, b"")
        with isolation:
            database = isolation.data_path / "wardrobe.sqlite3"
            first = None
            first_log = None
            try:
                first, first_log, first_nonce = launch(
                    executable,
                    profile,
                    process_log,
                )
                isolation.register_process_group(first, executable, first_nonce)
                first_app_pid = release_launch(first, executable)
                first_driver = AccessibilityDriver(first_app_pid)
                first_driver.wait_ready()
                first_driver.wait_text("Local only")
                first_driver.choose_folder(fixture_path)
                wait_for(
                    lambda: scalar(
                        database,
                        "SELECT COUNT(*) FROM local_sources "
                        "WHERE status = 'imported' AND blob_sha256 IS NOT NULL",
                    )
                    == 2,
                    "two native-chooser imports",
                )

                for expected_count, name in (
                    (1, "White Shirt"),
                    (2, "Navy Trousers"),
                ):
                    first_driver.click("AXButton", "Add item")
                    first_driver.wait_text("Add wardrobe item")
                    first_driver.click_role("AXTextField", 1)
                    first_driver.keystroke(name)
                    first_driver.click("AXButton", "Save item")
                    wait_for(
                        lambda count=expected_count: scalar(
                            database,
                            "SELECT COUNT(*) FROM catalog_items WHERE active = 1",
                        )
                        == count,
                        f"catalog item {expected_count}",
                    )

                first_driver.click("AXButton", "Inbox")
                for expected_count in (1, 2):
                    first_driver.wait_text("Assign")
                    if expected_count == 2:
                        first_driver.select_next_popup_option()
                    first_driver.click("AXButton", "Assign")
                    wait_for(
                        lambda count=expected_count: scalar(
                            database,
                            "SELECT COUNT(*) FROM evidence WHERE state = 'assigned'",
                        )
                        == count,
                        f"inbox assignment {expected_count}",
                    )

                first_driver.click("AXButton", "Wardrobe")
                first_driver.click("AXButton", "Edit", 1)
                first_driver.click_role("AXTextField", 1)
                first_driver.keystroke("Navy Date Trousers", select_all=True)
                first_driver.click("AXButton", "Save item")
                wait_for(
                    lambda: scalar(
                        database,
                        "SELECT COUNT(*) FROM catalog_items "
                        "WHERE active = 1 AND display_name = 'Navy Date Trousers'",
                    )
                    == 1,
                    "confirmed catalog edit",
                )

                first_driver.click("AXButton", "Outfits")
                first_driver.wait_text("Build outfit")
                first_driver.click_role("AXTextField", 1)
                first_driver.keystroke("Dinner Date")
                first_driver.click_role("AXCheckBox", 1)
                first_driver.click_role("AXCheckBox", 2)
                first_driver.click("AXButton", "Save outfit")
                wait_for(
                    lambda: scalar(database, "SELECT COUNT(*) FROM outfits") == 1,
                    "manual outfit",
                )
                first_driver.click("AXButton", "View collage")
                first_driver.wait_text("Saved wardrobe collage")
                first_driver.wait_text("Outfit collage ready")
                collage_contract_before = canonical_collage(
                    database,
                    isolation.data_path,
                    fixture_digests,
                )
                member_digests_before = ordered_collage_member_digests(database)
                collage_before = capture_stable_collage(
                    first_driver,
                    collage_before_path,
                    member_digests_before,
                )
                transcript_before = first_driver.dump()
                first_status = stop(first, first_log, first_driver)
                isolation.unregister_process_group(first)
                first = None
                first_log = None
                if first_status != 0:
                    raise SmokeFailure(f"first packaged process exited {first_status}")
            finally:
                force_stop(first, first_log)
                isolation.unregister_process_group(first)

            second = None
            second_log = None
            try:
                second, second_log, second_nonce = launch(
                    executable,
                    profile,
                    process_log,
                )
                isolation.register_process_group(second, executable, second_nonce)
                second_app_pid = release_launch(second, executable)
                second_driver = AccessibilityDriver(second_app_pid)
                second_driver.wait_ready()
                second_driver.wait_text("Local only")
                second_driver.wait_text("Navy Date Trousers")
                second_driver.click("AXButton", "Outfits")
                second_driver.wait_text("Dinner Date")
                second_driver.click("AXButton", "View collage")
                second_driver.wait_text("Saved wardrobe collage")
                second_driver.wait_text("Outfit collage ready")
                collage_contract_after = canonical_collage(
                    database,
                    isolation.data_path,
                    fixture_digests,
                )
                member_digests_after = ordered_collage_member_digests(database)
                collage_after = capture_stable_collage(
                    second_driver,
                    collage_after_path,
                    member_digests_after,
                )
                transcript_after = second_driver.dump()
                if (
                    collage_contract_before != collage_contract_after
                    or member_digests_before != member_digests_after
                    or collage_before != collage_after
                ):
                    raise SmokeFailure("collage changed across restart")

                second_driver.click("AXButton", "Back to outfits")
                second_driver.click("AXButton", "Settings")
                second_driver.wait_text("Network mode")
                second_driver.wait_text("Save settings")
                second_driver.wait_text("Not configured")
                second_driver.wait_text("Disconnect remains available")
                if second_driver.element_enabled("AXButton", "Save settings"):
                    raise SmokeFailure(
                        "Gmail setup control is enabled in local-only mode"
                    )
                second_driver.wait_text("Apple Photos")
                second_driver.wait_text("Connect")
                if second_driver.element_enabled("AXButton", "Connect"):
                    raise SmokeFailure(
                        "PhotoKit remote control is enabled in local-only mode"
                    )
                second_driver.wait_text("Save credential")
                second_driver.wait_text("Existing credentials can still be removed")
                if second_driver.element_enabled("AXButton", "Save credential"):
                    raise SmokeFailure(
                        "OpenAI credential setup is enabled in local-only mode"
                    )
                transcript_settings = second_driver.dump()
                second_driver.click("AXButton", "Wardrobe")
                second_driver.wait_text("Preview deletion")
                if not second_driver.element_enabled(
                    "AXButton", "Preview deletion"
                ):
                    raise SmokeFailure("local cleanup control is not reachable")
                transcript_cleanup = second_driver.dump()
                second_status = stop(second, second_log, second_driver)
                isolation.unregister_process_group(second)
                second = None
                second_log = None
                if second_status != 0:
                    raise SmokeFailure(
                        f"second packaged process exited {second_status}"
                    )
            finally:
                force_stop(second, second_log)
                isolation.unregister_process_group(second)

            forbidden = private_markers(fixture_path)
            reject_private_bytes(
                process_log.read_bytes(),
                forbidden,
                "packaged process output",
            )
            reject_private_bytes(
                sandbox_log.read_bytes(),
                forbidden,
                "sandbox proof",
            )
            scan = residual_scan(
                database,
                isolation.data_path,
                isolation.log_path,
                fixture_digests,
                fixture_path,
            )
            write_json(residual_path, scan)
            transcript = (
                "FIRST_COLLAGE\n"
                + transcript_before
                + "\nSECOND_COLLAGE\n"
                + transcript_after
                + "\nSETTINGS\n"
                + transcript_settings
                + "\nCLEANUP\n"
                + transcript_cleanup
            ).encode()
            atomic_write(transcript_path, transcript)

    report = {
        "schema_version": 1,
        "status": "pass",
        "artifact_kind": "macos_app",
        "packaging_identity": "ad_hoc_development_host",
        "process_exit_status": 0,
        "restart_count": 1,
        "source_digest_count": len(fixture_digests),
        "outbound_attempt_record_count": 0,
        "developer_id_signed": False,
        "notarized": False,
        "clean_machine_certified": False,
        "signed_acceptance_claim": "deferred_not_passed",
        "production_bundle": True,
        "sandbox_denied_network_for_process_and_children": True,
        "accessibility_automation_used": True,
        "native_file_chooser_used": True,
        "manual_import_passed": True,
        "inbox_review_passed": True,
        "catalog_confirm_edit_reload_passed": True,
        "manual_outfit_passed": True,
        "collage_before_restart_passed": True,
        "collage_after_restart_passed": True,
        "remote_controls_blocked": True,
        "local_deletion_control_reachable": True,
        "connector_cleanup_controls_applicable": False,
        "database_blob_residual_scan_passed": True,
        "source_fingerprint": source_fingerprint(),
        "bundle_sha256": bundle_hash,
        "executable_sha256": executable_hash,
        "sandbox_profile_sha256": sha256_file(profile),
        "accessibility_transcript_sha256": sha256_file(transcript_path),
        "residual_scan_sha256": sha256_file(residual_path),
        "sandbox_log_sha256": sha256_file(sandbox_log),
        "collage_before_sha256": collage_before,
        "collage_after_sha256": collage_after,
    }
    write_json(output, report)
    print(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "artifacts/harness/P09/20260716T000410Z-e46bd166/"
            "p09-offline-smoke-report.json"
        ),
    )
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = (
        arguments.output
        if arguments.output.is_absolute()
        else root / arguments.output
    )
    try:
        run_smoke(root, output)
    except (OSError, sqlite3.Error, subprocess.SubprocessError, SmokeFailure) as error:
        print(f"P09 offline smoke failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
