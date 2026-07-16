from __future__ import annotations

import hashlib
import binascii
import os
from pathlib import Path
import plistlib
import sqlite3
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import zlib

from tools import p09_offline_smoke as smoke


class P09OfflineSmokeTests(unittest.TestCase):
    def test_process_executable_identity_handles_spaces_and_wrappers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "Wardrobe App"
            wrapper = root / "sandbox-exec"
            executable.write_bytes(b"app")
            wrapper.write_bytes(b"wrapper")

            with mock.patch.object(
                smoke,
                "process_executable_path",
                return_value=executable,
            ):
                self.assertTrue(
                    smoke.process_runs_executable(345, executable)
                )
            with mock.patch.object(
                smoke,
                "process_executable_path",
                return_value=wrapper,
            ):
                self.assertFalse(
                    smoke.process_runs_executable(234, executable)
                )
            with mock.patch.object(
                smoke,
                "process_executable_path",
                return_value=None,
            ):
                self.assertFalse(
                    smoke.process_runs_executable(123, executable)
                )

        current = smoke.process_executable_path(os.getpid())
        self.assertIsNotNone(current)
        self.assertTrue(current.is_absolute())
        self.assertTrue(current.is_file())

    def test_release_launch_selects_only_the_real_executable_pid(self) -> None:
        executable = Path(
            "/Applications/Wardrobe.app/Contents/MacOS/wardrobe-desktop"
        )
        process = mock.Mock()
        process.pid = 123
        process.stdin = mock.Mock()
        process.stdin.closed = False
        process.poll.return_value = None
        members = (
            (123, "/bin/sh -c launch-gate"),
            (
                234,
                "/usr/bin/sandbox-exec -f /tmp/offline.sb "
                f"{executable}",
            ),
            (345, str(executable)),
        )

        with (
            mock.patch.object(
                smoke,
                "process_group_members",
                return_value=members,
            ),
            mock.patch.object(
                smoke,
                "process_runs_executable",
                side_effect=lambda pid, _executable: pid == 345,
            ) as runs_executable,
        ):
            self.assertEqual(
                smoke.release_launch(process, executable),
                345,
            )

        process.stdin.write.assert_called_once_with(b"go\n")
        process.stdin.flush.assert_called_once_with()
        process.stdin.close.assert_called_once_with()
        self.assertEqual(
            [call.args[0] for call in runs_executable.call_args_list],
            [234, 345],
        )

    def test_failed_rerun_removes_stale_success_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence" / "smoke.json"
            output.parent.mkdir()
            output.write_text('{"status":"pass"}', encoding="utf-8")
            support = output.parent / "offline-smoke"
            support.mkdir()
            (support / "process.log").write_text(
                "Navy Date Trousers",
                encoding="utf-8",
            )

            with self.assertRaises(smoke.SmokeFailure):
                smoke.run_smoke(root, output)

            self.assertFalse(output.exists())
            self.assertFalse((support / "process.log").exists())

    def test_private_isolation_restores_existing_data_and_logs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = home / "Library/Application Support" / smoke.BUNDLE_ID
            logs = home / "Library/Logs" / smoke.BUNDLE_ID
            data.mkdir(parents=True)
            logs.mkdir(parents=True)
            (data / "original.db").write_bytes(b"database")
            (logs / "original.log").write_bytes(b"log")

            with mock.patch.object(smoke.Path, "home", return_value=home):
                isolation = smoke.PrivateAppIsolation()
                with isolation:
                    self.assertFalse(data.exists())
                    self.assertFalse(logs.exists())
                    data.mkdir()
                    logs.mkdir()
                    (data / "smoke.db").write_bytes(b"smoke")
                    (logs / "smoke.log").write_bytes(b"smoke")

            self.assertEqual((data / "original.db").read_bytes(), b"database")
            self.assertEqual((logs / "original.log").read_bytes(), b"log")
            self.assertFalse((data / "smoke.db").exists())
            self.assertFalse(
                (
                    home
                    / "Library/Application Support"
                    / smoke.MARKER_NAME
                ).exists()
            )

            token = "a" * 32
            entries = [
                {
                    "kind": "data",
                    "had_original": True,
                    "backup_name": f".{smoke.BUNDLE_ID}.p09-{token}",
                },
                {
                    "kind": "logs",
                    "had_original": True,
                    "backup_name": f".{smoke.BUNDLE_ID}.p09-{token}",
                },
            ]
            marker = (
                home
                / "Library/Application Support"
                / smoke.MARKER_NAME
            )
            smoke.write_json(
                marker,
                {
                    "schema_version": 1,
                    "bundle_id": smoke.BUNDLE_ID,
                    "entries": entries,
                    "process_groups": [
                        {
                            "pgid": 1234,
                            "executable": "/tmp/Wardrobe",
                            "executable_sha256": "0" * 64,
                            "launch_nonce": "1" * 32,
                        }
                    ],
                },
            )
            with (
                mock.patch.object(smoke.Path, "home", return_value=home),
                mock.patch.object(
                    smoke, "terminate_recorded_process_group"
                ) as terminate,
            ):
                smoke.PrivateAppIsolation().recover()
            terminate.assert_called_once_with(
                {
                    "pgid": 1234,
                    "executable": "/tmp/Wardrobe",
                    "executable_sha256": "0" * 64,
                    "launch_nonce": "1" * 32,
                }
            )
            self.assertEqual((data / "original.db").read_bytes(), b"database")
            self.assertEqual((logs / "original.log").read_bytes(), b"log")
            self.assertFalse(marker.exists())

    def test_canonical_collage_is_stable_and_rejects_cas_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "wardrobe.sqlite3"
            blob_bytes = b"deterministic image"
            blob_digest = hashlib.sha256(blob_bytes).hexdigest()
            second_blob_bytes = b"second deterministic image"
            second_blob_digest = hashlib.sha256(second_blob_bytes).hexdigest()
            blob = (
                root
                / "blobs"
                / "sha256"
                / blob_digest[:2]
                / blob_digest[2:4]
                / blob_digest
            )
            blob.parent.mkdir(parents=True)
            blob.write_bytes(blob_bytes)
            second_blob = (
                root
                / "blobs"
                / "sha256"
                / second_blob_digest[:2]
                / second_blob_digest[2:4]
                / second_blob_digest
            )
            second_blob.parent.mkdir(parents=True)
            second_blob.write_bytes(second_blob_bytes)
            with sqlite3.connect(database) as connection:
                connection.executescript(
                    """
                    CREATE TABLE outfits(
                        outfit_id TEXT,
                        name TEXT,
                        created_outfit_revision INTEGER
                    );
                    CREATE TABLE outfit_members(
                        outfit_id TEXT,
                        ordinal INTEGER,
                        item_id TEXT,
                        item_updated_revision INTEGER,
                        attributes_json TEXT,
                        asset_state TEXT,
                        evidence_id TEXT,
                        source_id TEXT,
                        blob_sha256 TEXT,
                        media_type TEXT,
                        byte_length INTEGER,
                        width INTEGER,
                        height INTEGER
                    );
                    """
                )
                connection.execute(
                    "INSERT INTO outfits VALUES('outfit','Dinner Date',1)"
                )
                connection.execute(
                    "INSERT INTO outfit_members VALUES("
                    "'outfit',0,'shirt',1,'{}','available','e1','s1',?,"
                    "'image/png',?,32,32)",
                    (blob_digest, len(blob_bytes)),
                )
                connection.execute(
                    "INSERT INTO outfit_members VALUES("
                    "'outfit',1,'trousers',2,'{}','available','e2','s2',?,"
                    "'image/png',?,32,32)",
                    (second_blob_digest, len(second_blob_bytes)),
                )

            before = smoke.canonical_collage(
                database,
                root,
                (blob_digest, second_blob_digest),
            )
            self.assertEqual(before, smoke.canonical_collage(database, root))
            blob.write_bytes(b"tampered")
            with self.assertRaises(smoke.SmokeFailure):
                smoke.canonical_collage(database, root)

    def test_png_capture_is_canonical_pixel_data_and_rejects_blank_images(
        self,
    ) -> None:
        def chunk(kind: bytes, data: bytes) -> bytes:
            return (
                struct.pack(">I", len(data))
                + kind
                + data
                + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
            )

        def png(pixel) -> bytes:
            rows = bytearray()
            for y in range(32):
                rows.append(0)
                for x in range(32):
                    rows.extend(pixel(x, y))
            return (
                b"\x89PNG\r\n\x1a\n"
                + chunk(
                    b"IHDR",
                    struct.pack(">IIBBBBB", 32, 32, 8, 2, 0, 0, 0),
                )
                + chunk(b"IDAT", zlib.compress(bytes(rows)))
                + chunk(b"IEND", b"")
            )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.png"
            path.write_bytes(
                png(lambda x, y: (x * 7 % 256, y * 9 % 256, (x + y) * 5 % 256))
            )
            first = smoke.canonical_png_pixels(path)
            self.assertTrue(first.startswith(smoke.PIXEL_MAGIC))
            self.assertEqual(first, smoke.canonical_png_pixels(path))
            with self.assertRaises(smoke.SmokeFailure):
                smoke.require_member_fixture_pixels(
                    first,
                    smoke.FIXTURE_RGB[0],
                )

            path.write_bytes(
                png(
                    lambda x, _y: (
                        smoke.FIXTURE_RGB[0]
                        if x < 24
                        else (x * 7 % 256, 90, 130)
                    )
                )
            )
            member_pixels = smoke.canonical_png_pixels(path)
            smoke.require_member_fixture_pixels(
                member_pixels,
                smoke.FIXTURE_RGB[0],
            )
            with self.assertRaisesRegex(
                smoke.SmokeFailure,
                "pinned source image",
            ):
                smoke.require_member_fixture_pixels(
                    member_pixels,
                    smoke.FIXTURE_RGB[1],
                )
            encoded = smoke.encode_member_pixel_set(
                (
                    (0, smoke.FIXTURE_DIGESTS[0], member_pixels),
                    (1, smoke.FIXTURE_DIGESTS[1], member_pixels),
                )
            )
            self.assertTrue(encoded.startswith(smoke.MEMBER_PIXEL_MAGIC))
            with mock.patch.object(
                smoke,
                "MAX_MEMBER_PIXEL_SET_BYTES",
                len(encoded) - 1,
            ):
                with self.assertRaisesRegex(
                    smoke.SmokeFailure,
                    "evidence size bound",
                ):
                    smoke.encode_member_pixel_set(
                        (
                            (0, smoke.FIXTURE_DIGESTS[0], member_pixels),
                            (1, smoke.FIXTURE_DIGESTS[1], member_pixels),
                        )
                    )

            path.write_bytes(png(lambda _x, _y: (255, 255, 255)))
            with self.assertRaises(smoke.SmokeFailure):
                smoke.canonical_png_pixels(path)

    def test_capture_normalization_produces_srgb_fixture_pixels(self) -> None:
        def chunk(kind: bytes, data: bytes) -> bytes:
            return (
                struct.pack(">I", len(data))
                + kind
                + data
                + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.png"
            normalized = root / "normalized.png"
            width = 64
            height = 64
            rows = bytearray()
            for _y in range(height):
                rows.append(0)
                for x in range(width):
                    rows.extend(
                        smoke.FIXTURE_RGB[0]
                        if x >= 8
                        else (x * 20, x * 10, x * 5)
                    )
            source.write_bytes(
                b"\x89PNG\r\n\x1a\n"
                + chunk(
                    b"IHDR",
                    struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0),
                )
                + chunk(b"IDAT", zlib.compress(bytes(rows)))
                + chunk(b"IEND", b"")
            )

            smoke.normalize_capture_to_srgb(source, normalized)

            pixels = smoke.canonical_png_pixels(normalized)
            header_length = len(smoke.PIXEL_MAGIC) + 9
            channels = pixels[header_length - 1]
            rendered = pixels[header_length:]
            count = sum(
                tuple(rendered[offset : offset + 3]) == smoke.FIXTURE_RGB[0]
                for offset in range(0, len(rendered), channels)
            )
            self.assertGreaterEqual(count, 32)

    def test_sandbox_probe_requires_control_access_and_denied_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "offline.sb"
            log = root / "sandbox.log"
            profile.write_text(
                "(version 1)\n(allow default)\n(deny network*)\n",
                encoding="utf-8",
            )
            log.write_bytes(b"")
            server = mock.Mock()
            server.server_address = ("127.0.0.1", 43210)
            outcomes = [
                subprocess.CompletedProcess([], 0, b"control"),
                subprocess.CompletedProcess([], 7, b"denied"),
            ]
            with (
                mock.patch.object(
                    smoke.http.server,
                    "ThreadingHTTPServer",
                    return_value=server,
                ),
                mock.patch.object(smoke.subprocess, "run", side_effect=outcomes),
            ):
                smoke.verify_sandbox(profile, log)
            self.assertIn(b"network-child-control", log.read_bytes())
            self.assertIn(b"network-child-denied", log.read_bytes())

            outcomes = [
                subprocess.CompletedProcess([], 0, b"control"),
                subprocess.CompletedProcess([], 0, b"not denied"),
            ]
            with (
                mock.patch.object(
                    smoke.http.server,
                    "ThreadingHTTPServer",
                    return_value=server,
                ),
                mock.patch.object(smoke.subprocess, "run", side_effect=outcomes),
            ):
                with self.assertRaises(smoke.SmokeFailure):
                    smoke.verify_sandbox(profile, log)

    def test_interactive_console_preflight_rejects_locked_or_inactive_session(
        self,
    ) -> None:
        def encoded(*users: dict[str, object]) -> bytes:
            return plistlib.dumps({"IOConsoleUsers": list(users)})

        outcomes = (
            (
                encoded(
                    {
                        "kCGSSessionOnConsoleKey": True,
                        "CGSSessionScreenIsLocked": False,
                        "kCGSessionLoginDoneKey": True,
                    }
                ),
                None,
            ),
            (
                encoded(
                    {
                        "kCGSSessionOnConsoleKey": True,
                        "CGSSessionScreenIsLocked": True,
                        "kCGSessionLoginDoneKey": True,
                    }
                ),
                "console session is locked",
            ),
            (
                encoded(
                    {
                        "kCGSSessionOnConsoleKey": False,
                        "CGSSessionScreenIsLocked": True,
                        "kCGSessionLoginDoneKey": True,
                    },
                    {
                        "kCGSSessionOnConsoleKey": True,
                        "CGSSessionScreenIsLocked": False,
                        "kCGSessionLoginDoneKey": True,
                    },
                ),
                None,
            ),
            (
                encoded(
                    {
                        "kCGSSessionOnConsoleKey": False,
                        "CGSSessionScreenIsLocked": False,
                        "kCGSessionLoginDoneKey": True,
                    }
                ),
                "console session is not active",
            ),
            (
                encoded(
                    {
                        "kCGSSessionOnConsoleKey": True,
                        "kCGSessionLoginDoneKey": True,
                    }
                ),
                "cannot verify an unlocked",
            ),
            (b"not a plist", "cannot verify the macOS console session"),
        )
        for output, expected_error in outcomes:
            with (
                self.subTest(expected_error=expected_error),
                mock.patch.object(
                    smoke.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, output),
                ),
            ):
                if expected_error is None:
                    smoke.require_interactive_console_session()
                else:
                    with self.assertRaisesRegex(
                        smoke.SmokeFailure,
                        expected_error,
                    ):
                        smoke.require_interactive_console_session()

    def test_recovery_refuses_a_reused_or_unauthenticated_process_group(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "Wardrobe"
            executable.write_bytes(b"bundle executable")
            record = {
                "pgid": 4321,
                "executable": str(executable),
                "executable_sha256": smoke.sha256_file(executable),
                "launch_nonce": "a" * 32,
            }
            with (
                mock.patch.object(
                    smoke,
                    "process_group_commands",
                    return_value=("/unrelated/process",),
                ),
                mock.patch.object(
                    smoke,
                    "process_has_nonce",
                    return_value=False,
                ),
                mock.patch.object(smoke, "terminate_process_group") as terminate,
            ):
                with self.assertRaises(smoke.SmokeFailure):
                    smoke.terminate_recorded_process_group(record)
            terminate.assert_not_called()

            with (
                mock.patch.object(
                    smoke,
                    "process_group_commands",
                    return_value=(str(executable),),
                ),
                mock.patch.object(
                    smoke,
                    "process_has_nonce",
                    return_value=True,
                ),
                mock.patch.object(smoke, "terminate_process_group") as terminate,
            ):
                smoke.terminate_recorded_process_group(record)
            terminate.assert_called_once_with(4321)


if __name__ == "__main__":
    unittest.main()
