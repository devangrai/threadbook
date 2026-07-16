from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = (
    ROOT / "native" / "photokit" / "scripts" / "p06_photokit_live_smoke.py"
)
SPEC = importlib.util.spec_from_file_location("p06_photokit_live_smoke", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def challenge() -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": RUNNER.RUN_ID,
        "challenge_nonce": "a" * 64,
        "packet_sha256": "b" * 64,
        "source_sha256": "c" * 64,
        "fixture_sha256": list(RUNNER.EXPECTED_FIXTURES),
        "bundle_id": RUNNER.EXPECTED_BUNDLE_ID,
        "info_plist_sha256": "d" * 64,
        "executable_sha256": "e" * 64,
        "bundle_sha256": "f" * 64,
        "designated_requirement_sha256": "1" * 64,
    }


class P06PhotoKitLiveSmokeTests(unittest.TestCase):
    def test_expected_schema_matches_contiguous_migration_inventory(self) -> None:
        migrations = sorted(
            (ROOT / "crates" / "wardrobe-platform" / "migrations").glob(
                "[0-9][0-9][0-9][0-9]_*.sql"
            )
        )
        self.assertEqual(
            list(range(1, len(migrations) + 1)),
            [int(path.name[:4]) for path in migrations],
        )
        self.assertEqual(RUNNER.EXPECTED_DATABASE_SCHEMA, len(migrations))

    def test_fresh_state_and_failure_instructions_preserve_user_authority(
        self,
    ) -> None:
        self.assertIn("Local only", RUNNER.INITIAL_SYNC_INSTRUCTIONS)
        self.assertIn("Enable personal live", RUNNER.INITIAL_SYNC_INSTRUCTIONS)
        self.assertIn("Remove the dedicated synthetic", RUNNER.FAILURE_CLEANUP_INSTRUCTIONS)
        self.assertIn("review that permission", RUNNER.FAILURE_CLEANUP_INSTRUCTIONS)

        with mock.patch.object(RUNNER, "_run") as run:
            RUNNER._failure_dialog("initial_app_sync")
        script = run.call_args.args[0][-1]
        self.assertIn("Stage: initial_app_sync", script)
        self.assertIn(RUNNER.FAILURE_CLEANUP_INSTRUCTIONS, script)

        with self.assertRaises(RUNNER.SmokeFailure):
            RUNNER._set_failure_stage("private-path-value")

    def test_accepts_only_the_exact_nonce_bound_challenge(self) -> None:
        environment = {
            RUNNER.CHALLENGE_ENV: json.dumps(
                challenge(),
                sort_keys=True,
                separators=(",", ":"),
            )
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            self.assertEqual(challenge(), RUNNER._challenge())

        changed = challenge()
        changed["unexpected"] = True
        with mock.patch.dict(
            os.environ,
            {RUNNER.CHALLENGE_ENV: json.dumps(changed)},
            clear=True,
        ):
            with self.assertRaises(RUNNER.SmokeFailure):
                RUNNER._challenge()

    def test_keychain_absence_requires_the_native_not_found_result(self) -> None:
        absent = subprocess.CompletedProcess(
            [],
            44,
            b"",
            b"The specified item could not be found in the keychain.",
        )
        locked = subprocess.CompletedProcess([], 1, b"", b"User interaction is not allowed.")

        self.assertTrue(RUNNER._keychain_item_not_found(absent))
        self.assertFalse(RUNNER._keychain_item_not_found(locked))

    def test_crash_journal_cleans_only_isolated_smoke_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            data = (
                home
                / "Library"
                / "Application Support"
                / RUNNER.EXPECTED_BUNDLE_ID
            )
            logs = home / "Library" / "Logs" / RUNNER.EXPECTED_BUNDLE_ID
            data.mkdir(parents=True)
            logs.mkdir(parents=True)
            (data / "owner").write_text("user-data")
            (logs / "owner").write_text("user-logs")
            with mock.patch.object(Path, "home", return_value=home):
                isolation = RUNNER.PrivateAppIsolation(RUNNER.EXPECTED_BUNDLE_ID)
                isolation.__enter__()
                isolation.data_path.mkdir(parents=True)
                isolation.log_path.mkdir(parents=True)
                (isolation.data_path / "smoke").write_text("isolated")
                with mock.patch.object(isolation, "cleanup_keychain") as cleanup:
                    isolation.recover()
                cleanup.assert_called_once_with()

                self.assertEqual("user-data", (data / "owner").read_text())
                self.assertEqual("user-logs", (logs / "owner").read_text())
                self.assertFalse(isolation.marker.exists())

    def test_preparing_and_restoring_recovery_never_inspect_user_keychain(
        self,
    ) -> None:
        for journal_state in ("preparing", "restoring"):
            with self.subTest(journal_state=journal_state):
                with tempfile.TemporaryDirectory() as directory:
                    home = Path(directory)
                    data = (
                        home
                        / "Library"
                        / "Application Support"
                        / RUNNER.EXPECTED_BUNDLE_ID
                    )
                    logs = home / "Library" / "Logs" / RUNNER.EXPECTED_BUNDLE_ID
                    data.mkdir(parents=True)
                    logs.mkdir(parents=True)
                    (data / "owner").write_text("user-data")
                    (logs / "owner").write_text("user-logs")
                    with mock.patch.object(Path, "home", return_value=home):
                        isolation = RUNNER.PrivateAppIsolation(
                            RUNNER.EXPECTED_BUNDLE_ID
                        )
                        token = "a" * 32
                        isolation.entries = [
                            {
                                "kind": "data",
                                "had_original": True,
                                "backup_name": (
                                    f".{RUNNER.EXPECTED_BUNDLE_ID}.p06-{token}"
                                ),
                            },
                            {
                                "kind": "logs",
                                "had_original": True,
                                "backup_name": (
                                    f".{RUNNER.EXPECTED_BUNDLE_ID}.p06-{token}"
                                ),
                            },
                        ]
                        isolation._write_marker(journal_state)
                        with mock.patch.object(
                            isolation, "cleanup_keychain"
                        ) as cleanup:
                            isolation.recover()
                        cleanup.assert_not_called()
                        self.assertEqual("user-data", (data / "owner").read_text())
                        self.assertEqual("user-logs", (logs / "owner").read_text())

    def test_linked_canonical_closure_co_owns_exact_fixture_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "wardrobe.sqlite3"
            migrations = sorted(
                (ROOT / "crates" / "wardrobe-platform" / "migrations").glob(
                    "[0-9][0-9][0-9][0-9]_*.sql"
                )
            )
            with sqlite3.connect(database) as connection:
                connection.execute("PRAGMA foreign_keys = OFF")
                for migration in migrations:
                    connection.executescript(migration.read_text())
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute(
                    f"PRAGMA user_version = {RUNNER.EXPECTED_DATABASE_SCHEMA}"
                )
                records = tuple(
                    (content_hash, index + 10)
                    for index, content_hash in enumerate(RUNNER.EXPECTED_FIXTURES)
                )
                connection.executemany(
                    "INSERT INTO blobs(sha256,byte_length,created_at_ms) "
                    "VALUES(?,?,1)",
                    records,
                )
                connection.commit()

            item_id, decision_id, before = (
                RUNNER._seed_linked_canonical_closure(database, records)
            )
            self.assertEqual(
                before,
                RUNNER._canonical_closure_hash(database, item_id, decision_id),
            )
            with sqlite3.connect(database) as connection:
                linked = [
                    row[0]
                    for row in connection.execute(
                        "SELECT source.blob_sha256 FROM item_evidence assignment "
                        "JOIN evidence ON evidence.evidence_id=assignment.evidence_id "
                        "JOIN local_sources source ON source.source_id=evidence.source_id "
                        "WHERE assignment.item_id=? ORDER BY source.blob_sha256",
                        (item_id,),
                    )
                ]
            self.assertEqual(sorted(RUNNER.EXPECTED_FIXTURES), linked)

    def test_retained_cas_rejects_missing_corrupt_and_wrong_size_files(self) -> None:
        payload = b"reviewed retained blob"
        content_hash = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            data_path = Path(directory) / "app-data"
            blob = (
                data_path
                / "blobs"
                / "sha256"
                / content_hash[:2]
                / content_hash[2:4]
                / content_hash
            )
            blob.parent.mkdir(parents=True)
            records = ((content_hash, len(payload)),)

            blob.write_bytes(payload)
            RUNNER._verify_retained_cas(data_path, records)

            blob.unlink()
            with self.assertRaises(RUNNER.SmokeFailure):
                RUNNER._verify_retained_cas(data_path, records)

            blob.write_bytes(b"x" * len(payload))
            with self.assertRaises(RUNNER.SmokeFailure):
                RUNNER._verify_retained_cas(data_path, records)

            blob.write_bytes(payload + b"x")
            with self.assertRaises(RUNNER.SmokeFailure):
                RUNNER._verify_retained_cas(data_path, records)

    def test_retained_cas_rejects_symlink_identity(self) -> None:
        payload = b"reviewed retained blob"
        content_hash = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            data_path = Path(directory) / "app-data"
            blob = (
                data_path
                / "blobs"
                / "sha256"
                / content_hash[:2]
                / content_hash[2:4]
                / content_hash
            )
            blob.parent.mkdir(parents=True)
            target = data_path / "outside"
            target.write_bytes(payload)
            blob.symlink_to(target)

            with self.assertRaises(RUNNER.SmokeFailure):
                RUNNER._verify_retained_cas(
                    data_path, ((content_hash, len(payload)),)
                )

    def test_runner_and_evaluator_independently_match_bundle_aggregate(self) -> None:
        from tools.evaluators import p06_photokit

        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Wardrobe.app"
            file_path = bundle / "Contents/Resources/value"
            file_path.parent.mkdir(parents=True)
            file_path.write_bytes(b"package content")

            self.assertEqual(
                p06_photokit._bundle_sha256(bundle),
                RUNNER._bundle_sha256(bundle),
            )
        requirement = b"designated => cdhash H\"0123456789abcdef\""
        self.assertEqual(
            hashlib.sha256(requirement).hexdigest(),
            p06_photokit._designated_requirement_sha256(
                b"Executable=/private/path\n# " + requirement + b"\n"
            ),
        )
        self.assertEqual(
            hashlib.sha256(requirement).hexdigest(),
            RUNNER._designated_requirement_sha256(
                b"Executable=/private/path\n# " + requirement + b"\n"
            ),
        )

    def test_live_runner_is_the_only_discoverable_p06_photokit_runner(self) -> None:
        from tools.evaluators.p06_photokit import _discover_live_runners

        self.assertEqual((RUNNER_PATH,), _discover_live_runners(ROOT))


if __name__ == "__main__":
    unittest.main()
