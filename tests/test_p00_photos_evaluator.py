from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import harness
from tools.evaluators import p00_photos
from tools.evaluators import run as evaluator_run


NONCE = "a" * 64
RUN_TOKEN = "b" * 32
RUN_ID = f"p00-{RUN_TOKEN}"
SOURCE_FINGERPRINT = "c" * 64
EXECUTABLE_HASH = "d" * 64
LOCAL_HASH = p00_photos.APPROVED_FIXTURES["local"]["sha256"]
CLOUD_HASH = p00_photos.APPROVED_FIXTURES["cloud"]["sha256"]
LOCAL_ASSET = "1" * 64
LOCAL_RESOURCE = "3" * 64
CLOUD_ASSET = "4" * 64
CLOUD_RESOURCE = "6" * 64


def valid_deterministic_records(
    nonce: str = NONCE,
) -> dict[str, dict[str, object]]:
    return {
        scenario: {
            "scenario": scenario,
            "nonce": nonce,
            **copy.deepcopy(expected),
        }
        for scenario, expected in p00_photos.EXPECTED_RECORD_VALUES.items()
    }


def deterministic_output(
    records: dict[str, dict[str, object]] | None = None,
) -> str:
    records = records or valid_deterministic_records()
    return "\n".join(
        p00_photos.DETERMINISTIC_PREFIX
        + json.dumps(records[scenario], sort_keys=True)
        for scenario in p00_photos.DETERMINISTIC_SCENARIOS
        if scenario in records
    )


def operator_challenge() -> dict[str, object]:
    return {
        "schema_version": 1,
        "nonpersonal_provenance": p00_photos.NONPERSONAL_PROVENANCE,
        "local": copy.deepcopy(p00_photos.APPROVED_FIXTURES["local"]),
        "cloud": copy.deepcopy(p00_photos.APPROVED_FIXTURES["cloud"]),
    }


def source_binding() -> p00_photos.SourceBinding:
    return p00_photos.SourceBinding(
        harness_run_id="20260714T224112Z-5d6bbee6",
        source_fingerprint=SOURCE_FINGERPRINT,
    )


def runtime_challenge(
    challenge: dict[str, object] | None = None,
) -> dict[str, object]:
    return p00_photos.make_runtime_challenge(
        challenge or operator_challenge(),
        nonce=NONCE,
        run_id=RUN_ID,
        binding=source_binding(),
        executable_sha256=EXECUTABLE_HASH,
    )


def inspection(base: Path) -> p00_photos.BundleInspection:
    app = base / p00_photos.PACKAGED_APP_NAME
    return p00_photos.BundleInspection(
        app=app,
        executable=app
        / "Contents"
        / "MacOS"
        / p00_photos.EXPECTED_EXECUTABLE_NAME,
        executable_sha256=EXECUTABLE_HASH,
        bundle_id=p00_photos.EXPECTED_BUNDLE_ID,
    )


def valid_live_records(
    challenge: dict[str, object] | None = None,
    *,
    local_byte_count: int = 17,
    cloud_byte_count: int = 19,
) -> list[dict[str, object]]:
    del challenge
    records: list[dict[str, object]] = []

    def append(event: str, **fields: object) -> None:
        records.append(
            {
                "schema_version": 1,
                "scenario": p00_photos.LIVE_SCENARIO,
                "challenge_nonce": NONCE,
                "sequence": len(records) + 1,
                "event": event,
                **fields,
            }
        )

    append("authorization_granted")
    append(
        "resource_selected",
        asset_alias=LOCAL_ASSET,
        resource_alias=LOCAL_RESOURCE,
    )
    append(
        "resource_selected",
        asset_alias=CLOUD_ASSET,
        resource_alias=CLOUD_RESOURCE,
    )
    append(
        "probe_started",
        asset_alias=LOCAL_ASSET,
        resource_alias=LOCAL_RESOURCE,
        network_allowed=False,
    )
    append(
        "asset_completed",
        asset_alias=LOCAL_ASSET,
        resource_alias=LOCAL_RESOURCE,
        byte_count=local_byte_count,
        progress_callback_count=0,
        residency="local",
        outcome="pass",
    )
    append(
        "probe_started",
        asset_alias=CLOUD_ASSET,
        resource_alias=CLOUD_RESOURCE,
        network_allowed=False,
    )
    append(
        "probe_network_required",
        asset_alias=CLOUD_ASSET,
        resource_alias=CLOUD_RESOURCE,
        network_allowed=False,
    )
    append(
        "retry_started",
        asset_alias=CLOUD_ASSET,
        resource_alias=CLOUD_RESOURCE,
        network_allowed=True,
    )
    append(
        "transfer_progress",
        asset_alias=CLOUD_ASSET,
        resource_alias=CLOUD_RESOURCE,
        progress_permille=250,
    )
    append(
        "transfer_progress",
        asset_alias=CLOUD_ASSET,
        resource_alias=CLOUD_RESOURCE,
        progress_permille=1000,
    )
    append(
        "asset_completed",
        asset_alias=CLOUD_ASSET,
        resource_alias=CLOUD_RESOURCE,
        byte_count=cloud_byte_count,
        progress_callback_count=3,
        residency="cloud",
        outcome="pass",
    )
    append("session_completed", outcome="pass")
    return records


def live_output(
    records: list[dict[str, object]] | None = None,
) -> str:
    records = records or valid_live_records()
    return "\n".join(
        p00_photos.LIVE_PREFIX + json.dumps(record, sort_keys=True)
        for record in records
    )


def command_result(
    output: str,
    *,
    returncode: int = 0,
    timed_out: bool = False,
    launch_failed: bool = False,
    truncated: bool = False,
) -> p00_photos.CommandResult:
    raw = output.encode()
    return p00_photos.CommandResult(
        returncode,
        output,
        hashlib.sha256(raw).hexdigest(),
        len(raw),
        timed_out=timed_out,
        launch_failed=launch_failed,
        truncated=truncated,
    )


def mutated(value: object) -> object:
    if value is None:
        return "not-null"
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if isinstance(value, str):
        return value + "-mutated"
    raise AssertionError(f"no mutation for {value!r}")


class DeterministicEvidenceTests(unittest.TestCase):
    def test_accepts_all_exact_scenarios(self) -> None:
        records = valid_deterministic_records()
        self.assertEqual(
            [], p00_photos.validate_deterministic_records(records, NONCE)
        )

    def test_rejects_mutation_and_removal_of_every_oracle(self) -> None:
        baseline = valid_deterministic_records()
        for scenario, expected in p00_photos.EXPECTED_RECORD_VALUES.items():
            for field, value in {"nonce": NONCE, **expected}.items():
                with self.subTest(scenario=scenario, field=field):
                    changed = copy.deepcopy(baseline)
                    changed[scenario][field] = mutated(value)
                    self.assertTrue(
                        p00_photos.validate_deterministic_records(
                            changed, NONCE
                        )
                    )
                with self.subTest(scenario=scenario, missing=field):
                    changed = copy.deepcopy(baseline)
                    del changed[scenario][field]
                    self.assertTrue(
                        p00_photos.validate_deterministic_records(
                            changed, NONCE
                        )
                    )

    def test_rejects_missing_duplicate_malformed_and_cross_channel(self) -> None:
        records = valid_deterministic_records()
        del records[p00_photos.LOCAL_CLOUD]
        self.assertTrue(
            p00_photos.validate_deterministic_records(records, NONCE)
        )
        output = deterministic_output()
        first = output.splitlines()[0]
        for case in (
            output + "\n" + first,
            output + "\n" + p00_photos.DETERMINISTIC_PREFIX + "{",
            output + "\nprefix " + first,
        ):
            with self.subTest(case=case[-50:]):
                _, errors = p00_photos.parse_deterministic_evidence(case)
                self.assertTrue(errors)
        result = command_result(
            output + "\n" + p00_photos.LIVE_PREFIX + "{}"
        )
        _, errors = p00_photos.validate_deterministic_command(result, NONCE)
        self.assertTrue(errors)

    def test_rejects_command_failure_timeout_launch_and_truncation(self) -> None:
        output = deterministic_output()
        cases = (
            command_result(output, returncode=1),
            command_result(output, timed_out=True),
            command_result(output, launch_failed=True),
            command_result(output, truncated=True),
        )
        for result in cases:
            with self.subTest(result=result):
                _, errors = p00_photos.validate_deterministic_command(
                    result, NONCE
                )
                self.assertTrue(errors)


class OperatorChallengeTests(unittest.TestCase):
    def test_fixture_manifest_and_generator_are_review_bound(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        self.assertEqual(
            [],
            p00_photos.validate_approved_fixture_source(repository_root),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture_root = root / p00_photos.FIXTURE_ROOT_RELATIVE
            fixture_root.mkdir(parents=True)
            for relative in (
                p00_photos.FIXTURE_MANIFEST_RELATIVE,
                p00_photos.FIXTURE_GENERATOR_RELATIVE,
            ):
                destination = root / relative
                destination.write_bytes((repository_root / relative).read_bytes())
            (root / p00_photos.FIXTURE_MANIFEST_RELATIVE).write_text(
                "{}\n", encoding="utf-8"
            )
            self.assertTrue(
                p00_photos.validate_approved_fixture_source(root)
            )

    def test_accepts_only_fixture_expectations(self) -> None:
        challenge = operator_challenge()
        parsed, errors = p00_photos.validate_operator_challenge(
            {
                p00_photos.LIVE_CHALLENGE_ENV: json.dumps(challenge),
            }
        )
        self.assertEqual([], errors)
        self.assertEqual(challenge, parsed)

        for field in challenge:
            with self.subTest(missing=field):
                changed = copy.deepcopy(challenge)
                del changed[field]
                _, errors = p00_photos.validate_operator_challenge(
                    {
                        p00_photos.LIVE_CHALLENGE_ENV: json.dumps(changed),
                    }
                )
                self.assertTrue(errors)

    def test_rejects_missing_challenge_arbitrary_app_and_arbitrary_paths(
        self,
    ) -> None:
        _, errors = p00_photos.validate_operator_challenge({})
        self.assertTrue(errors)
        challenge = operator_challenge()
        challenge["output_path"] = "/tmp/operator-chosen"
        _, errors = p00_photos.validate_operator_challenge(
            {
                p00_photos.LIVE_CHALLENGE_ENV: json.dumps(challenge),
                p00_photos.FORBIDDEN_LIVE_APP_ENV: "/tmp/Fake.app",
            }
        )
        self.assertTrue(
            any("prohibited" in error for error in errors)
        )
        self.assertTrue(any("not exact" in error for error in errors))

    def test_rejects_each_fixture_mutation_and_nonpersonal_claim(self) -> None:
        baseline = operator_challenge()
        mutations = (
            ("schema_version", True),
            ("nonpersonal_provenance", "personal-library"),
            ("local.sha256", "not-a-sha256"),
            ("cloud.sha256", LOCAL_HASH),
            ("local.fixture_id", "p00-synthetic-cloud-v1"),
            ("local.pixel_width", 0),
            ("cloud.pixel_height", True),
            ("local.sha256", "0" * 64),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(baseline)
                if "." in field:
                    role, key = field.split(".")
                    changed[role][key] = value
                else:
                    changed[field] = value
                _, errors = p00_photos.validate_operator_challenge(
                    {
                        p00_photos.LIVE_CHALLENGE_ENV: json.dumps(changed),
                    }
                )
                self.assertTrue(errors)

    def test_serialized_runtime_contract_exactly_matches_swift_schema(
        self,
    ) -> None:
        challenge = runtime_challenge()
        serialized = p00_photos.serialize_runtime_challenge(challenge)
        parsed = json.loads(serialized)
        expected_swift_fixture = {
            "schema_version": 1,
            "nonce": NONCE,
            "run_id": RUN_ID,
            "harness_run_id": "20260714T224112Z-5d6bbee6",
            "source_fingerprint": SOURCE_FINGERPRINT,
            "executable_sha256": EXECUTABLE_HASH,
            "nonpersonal_provenance": p00_photos.NONPERSONAL_PROVENANCE,
            "output_contract": {
                "kind": "sandbox_container_v1",
                "bundle_id": p00_photos.EXPECTED_BUNDLE_ID,
                "relative_directory": (
                    "Library/Application Support/P00PhotoKitNative/"
                    + RUN_ID
                ),
                "must_not_exist": True,
                "asset_suffix": ".asset",
                "provenance_suffix": ".provenance.json",
            },
            "local": {
                "fixture_id": "p00-synthetic-local-v1",
                "sha256": LOCAL_HASH,
                "pixel_width": 96,
                "pixel_height": 96,
            },
            "cloud": {
                "fixture_id": "p00-synthetic-cloud-v1",
                "sha256": CLOUD_HASH,
                "pixel_width": 96,
                "pixel_height": 96,
            },
        }
        self.assertEqual(expected_swift_fixture, parsed)
        self.assertEqual(
            p00_photos.RUNTIME_CHALLENGE_FIELDS,
            set(parsed),
        )
        self.assertEqual(RUN_ID, challenge["run_id"])
        self.assertEqual(EXECUTABLE_HASH, challenge["executable_sha256"])
        self.assertEqual(
            p00_photos.RUNTIME_FIXTURE_FIELDS,
            set(parsed["local"]),
        )
        self.assertEqual(
            p00_photos.RUNTIME_OUTPUT_FIELDS,
            set(parsed["output_contract"]),
        )
        self.assertEqual(challenge, parsed)
        self.assertEqual([], p00_photos.validate_runtime_challenge(parsed))

    def test_runtime_serializer_rejects_each_schema_mutation(self) -> None:
        baseline = runtime_challenge()
        mutations = (
            ("schema_version", True),
            ("nonce", "not-a-hash"),
            ("run_id", "operator-run"),
            ("harness_run_id", ""),
            ("source_fingerprint", "not-a-hash"),
            ("executable_sha256", "not-a-hash"),
            ("nonpersonal_provenance", "personal-library"),
            ("output_contract", {}),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                challenge = copy.deepcopy(baseline)
                challenge[field] = value
                with self.assertRaises(ValueError):
                    p00_photos.serialize_runtime_challenge(challenge)
        for role in ("local", "cloud"):
            for field in p00_photos.RUNTIME_FIXTURE_FIELDS:
                with self.subTest(role=role, missing=field):
                    challenge = copy.deepcopy(baseline)
                    del challenge[role][field]
                    with self.assertRaises(ValueError):
                        p00_photos.serialize_runtime_challenge(challenge)
        for field in p00_photos.RUNTIME_OUTPUT_FIELDS:
            with self.subTest(output_missing=field):
                challenge = copy.deepcopy(baseline)
                del challenge["output_contract"][field]
                with self.assertRaises(ValueError):
                    p00_photos.serialize_runtime_challenge(challenge)


class SourceBindingTests(unittest.TestCase):
    @mock.patch(
        "tools.evaluators.p00_photos.repository_source_fingerprint",
        return_value=SOURCE_FINGERPRINT,
    )
    def test_binds_to_harness_build_fingerprint(
        self, _fingerprint: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "artifacts" / "harness" / "run-1"
            run.mkdir(parents=True)
            (run / "state.json").write_text(
                json.dumps(
                    {
                        "run_id": "run-1",
                        "status": "BUILT",
                        "selected_requirement_ids": [
                            p00_photos.REQUIREMENT_ID
                        ],
                        "build": {
                            "source_fingerprint": SOURCE_FINGERPRINT
                        },
                    }
                ),
                encoding="utf-8",
            )
            binding, errors = p00_photos.validate_source_binding(
                root, {"HARNESS_RUN_DIR": str(run)}
            )
        self.assertEqual([], errors)
        self.assertEqual(SOURCE_FINGERPRINT, binding.source_fingerprint)

    def test_rejects_external_harness_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "root"
            outside = Path(directory) / "outside"
            root.mkdir()
            outside.mkdir()
            binding, errors = p00_photos.validate_source_binding(
                root, {"HARNESS_RUN_DIR": str(outside)}
            )
        self.assertIsNone(binding)
        self.assertTrue(errors)


class PackagingAndInspectionTests(unittest.TestCase):
    def _source_tree(self, root: Path) -> tuple[Path, Path]:
        native = root / p00_photos.NATIVE_RELATIVE_ROOT
        script = root / p00_photos.PACKAGE_SCRIPT_RELATIVE
        script.parent.mkdir(parents=True)
        script.write_text("#!/bin/sh\n", encoding="utf-8")
        os.chmod(script, 0o755)
        return native, script

    @mock.patch("tools.evaluators.p00_photos.run_bounded_command")
    def test_packages_current_source_to_exact_fresh_destination(
        self, run: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            self._source_tree(root)
            package_root = Path(directory) / "package"
            package_root.mkdir()
            app = package_root / p00_photos.PACKAGED_APP_NAME

            def package(*_args: object, **_kwargs: object) -> object:
                (app / "Contents").mkdir(parents=True)
                return command_result(str(app) + "\n")

            run.side_effect = package
            built, _, errors = p00_photos.package_current_source(
                root, package_root, {}
            )
        self.assertEqual([], errors)
        self.assertEqual(app, built)
        self.assertEqual(
            [
                str(root / p00_photos.PACKAGE_SCRIPT_RELATIVE),
                str(package_root),
            ],
            run.call_args.args[0],
        )

    @mock.patch("tools.evaluators.p00_photos.run_bounded_command")
    def test_rejects_dead_link_script_and_app_shim(
        self, run: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            native = root / p00_photos.NATIVE_RELATIVE_ROOT
            native.mkdir(parents=True)
            script = root / p00_photos.PACKAGE_SCRIPT_RELATIVE
            script.parent.mkdir(parents=True, exist_ok=True)
            target = Path(directory) / "missing-script"
            script.symlink_to(target)
            package_root = Path(directory) / "package"
            package_root.mkdir()
            _, _, errors = p00_photos.package_current_source(
                root, package_root, {}
            )
        self.assertTrue(errors)
        run.assert_not_called()

    @mock.patch("tools.evaluators.p00_photos.run_bounded_command")
    def test_rejects_symlink_inside_packaged_app(
        self, run: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            self._source_tree(root)
            package_root = Path(directory) / "package"
            package_root.mkdir()
            app = package_root / p00_photos.PACKAGED_APP_NAME

            def package(*_args: object, **_kwargs: object) -> object:
                contents = app / "Contents"
                contents.mkdir(parents=True)
                (contents / "shim").symlink_to(Path(directory) / "missing")
                return command_result(str(app) + "\n")

            run.side_effect = package
            built, _, errors = p00_photos.package_current_source(
                root, package_root, {}
            )
        self.assertIsNone(built)
        self.assertTrue(any("symlink" in error for error in errors))

    def _app_fixture(self, base: Path) -> tuple[Path, Path, dict[str, object]]:
        root = base / "repo"
        app = base / p00_photos.PACKAGED_APP_NAME
        executable = (
            app
            / "Contents"
            / "MacOS"
            / p00_photos.EXPECTED_EXECUTABLE_NAME
        )
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"native executable")
        info = {
            "CFBundleIdentifier": p00_photos.EXPECTED_BUNDLE_ID,
            "CFBundleExecutable": p00_photos.EXPECTED_EXECUTABLE_NAME,
            "NSPhotoLibraryUsageDescription": p00_photos.EXPECTED_USAGE_DESCRIPTION,
        }
        source_info = root / p00_photos.NATIVE_RELATIVE_ROOT / "AppInfo.plist"
        source_info.parent.mkdir(parents=True)
        source_info.write_bytes(plistlib.dumps(info))
        (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
        return root, app, info

    def test_inspects_exact_source_plist_signature_entitlements_and_linkage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, app, _ = self._app_fixture(Path(directory))
            entitlements = plistlib.dumps(
                {
                    "com.apple.security.app-sandbox": True,
                    "com.apple.security.personal-information.photos-library": True,
                }
            ).decode()
            results = [
                subprocess.CompletedProcess([], 0, "valid"),
                subprocess.CompletedProcess(
                    [],
                    0,
                    f"Identifier={p00_photos.EXPECTED_BUNDLE_ID}\n"
                    "TeamIdentifier=not set\nSignature=adhoc\n",
                ),
                subprocess.CompletedProcess([], 0, entitlements),
                subprocess.CompletedProcess(
                    [],
                    0,
                    "/System/Library/Frameworks/Photos.framework/Versions/A/Photos\n"
                    "/System/Library/Frameworks/PhotosUI.framework/Versions/A/PhotosUI\n",
                ),
                subprocess.CompletedProcess(
                    [], 0, "Mach-O 64-bit executable arm64"
                ),
            ]
            with mock.patch(
                "tools.evaluators.p00_photos._run_tool",
                side_effect=results,
            ):
                inspected, errors = p00_photos.inspect_source_built_app(
                    root, app
                )
        self.assertEqual([], errors)
        self.assertIsNotNone(inspected)

    def test_rejects_broad_entitlement_and_mismatched_source_plist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, app, info = self._app_fixture(Path(directory))
            info["CFBundleVersion"] = "mutated"
            (app / "Contents" / "Info.plist").write_bytes(
                plistlib.dumps(info)
            )
            broad = plistlib.dumps(
                {
                    "com.apple.security.app-sandbox": True,
                    "com.apple.security.personal-information.photos-library": True,
                    "com.apple.security.files.user-selected.read-write": True,
                }
            ).decode()
            results = [
                subprocess.CompletedProcess([], 0, "valid"),
                subprocess.CompletedProcess(
                    [],
                    0,
                    f"Identifier={p00_photos.EXPECTED_BUNDLE_ID}\n"
                    "TeamIdentifier=not set\nSignature=adhoc\n",
                ),
                subprocess.CompletedProcess([], 0, broad),
                subprocess.CompletedProcess([], 1, ""),
                subprocess.CompletedProcess([], 1, "shell script"),
            ]
            with mock.patch(
                "tools.evaluators.p00_photos._run_tool",
                side_effect=results,
            ):
                _, errors = p00_photos.inspect_source_built_app(root, app)
        self.assertTrue(any("Info.plist" in error for error in errors))
        self.assertTrue(any("entitlement" in error for error in errors))
        self.assertTrue(any("native arm64" in error for error in errors))

    def test_rejects_executable_changed_after_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            app = base / p00_photos.PACKAGED_APP_NAME
            executable = (
                app
                / "Contents"
                / "MacOS"
                / p00_photos.EXPECTED_EXECUTABLE_NAME
            )
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"reviewed native binary")
            inspected = p00_photos.BundleInspection(
                app,
                executable,
                p00_photos.sha256_file(executable),
                p00_photos.EXPECTED_BUNDLE_ID,
            )
            self.assertEqual(
                [], p00_photos._executable_still_bound(inspected)
            )
            executable.write_bytes(b"mutated shim")
            errors = p00_photos._executable_still_bound(inspected)
        self.assertTrue(any("changed" in error for error in errors))


class LiveRecordTests(unittest.TestCase):
    def test_accepts_exact_swift_records_and_derives_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            challenge = runtime_challenge()
            records = valid_live_records(challenge)
            proof, errors = p00_photos.validate_live_records(
                records, NONCE, challenge, inspection(Path(directory))
            )
        self.assertEqual([], errors)
        self.assertEqual("local", proof.local.residency)
        self.assertEqual("cloud", proof.cloud.residency)
        self.assertEqual(3, proof.cloud.progress_callback_count)
        self.assertEqual(LOCAL_RESOURCE, proof.local.resource_alias)
        self.assertEqual(12, proof.event_count)

    def test_rejects_field_removal_and_sequence_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            challenge = runtime_challenge()
            baseline = valid_live_records(challenge)
            inspected = inspection(base)
            for index, record in enumerate(baseline):
                for field in record:
                    with self.subTest(index=index, missing=field):
                        changed = copy.deepcopy(baseline)
                        del changed[index][field]
                        _, errors = p00_photos.validate_live_records(
                            changed, NONCE, challenge, inspected
                        )
                        self.assertTrue(errors)

            mutations = (
                (0, "schema_version", True),
                (0, "scenario", "unapproved"),
                (0, "challenge_nonce", "0" * 64),
                (0, "sequence", 2),
                (3, "network_allowed", True),
                (6, "resource_alias", LOCAL_RESOURCE),
                (7, "network_allowed", False),
                (8, "progress_permille", 1001),
                (10, "progress_callback_count", 0),
                (10, "residency", "local"),
                (11, "outcome", "fail"),
            )
            for index, field, value in mutations:
                with self.subTest(index=index, field=field):
                    changed = copy.deepcopy(baseline)
                    changed[index][field] = value
                    _, errors = p00_photos.validate_live_records(
                        changed, NONCE, challenge, inspected
                    )
                    self.assertTrue(errors)

            changed = copy.deepcopy(baseline)
            changed[8]["progress_permille"] = 900
            changed[9]["progress_permille"] = 800
            _, errors = p00_photos.validate_live_records(
                changed, NONCE, challenge, inspected
            )
            self.assertTrue(errors)

            for changed in (
                baseline[:-1],
                baseline[:5] + baseline[6:],
                baseline[:8] + [copy.deepcopy(baseline[8])] + baseline[8:],
            ):
                with self.subTest(length=len(changed)):
                    _, errors = p00_photos.validate_live_records(
                        changed, NONCE, challenge, inspected
                    )
                    self.assertTrue(errors)

    def test_rejects_framing_command_failure_and_stale_nonce(self) -> None:
        output = live_output()
        records, errors = p00_photos.parse_live_evidence(
            output + "\nprefix " + output.splitlines()[0]
        )
        self.assertTrue(errors)
        self.assertTrue(records)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            challenge = runtime_challenge()
            stale = valid_live_records(challenge)
            stale[0]["challenge_nonce"] = "0" * 64
            result = command_result(live_output(stale), returncode=1)
            _, _, errors = p00_photos.validate_live_command(
                result, NONCE, challenge, inspection(base)
            )
        self.assertTrue(errors)


class OutputVerificationTests(unittest.TestCase):
    def _write_outputs(
        self,
        base: Path,
    ) -> tuple[
        dict[str, object],
        p00_photos.LiveProof,
    ]:
        local_bytes = b"synthetic-local"
        cloud_bytes = b"synthetic-cloud"
        operator = operator_challenge()
        operator["local"]["sha256"] = hashlib.sha256(
            local_bytes
        ).hexdigest()
        operator["cloud"]["sha256"] = hashlib.sha256(
            cloud_bytes
        ).hexdigest()
        runtime = runtime_challenge(operator)
        proof, errors = p00_photos.validate_live_records(
            valid_live_records(
                runtime,
                local_byte_count=len(local_bytes),
                cloud_byte_count=len(cloud_bytes),
            ),
            NONCE,
            runtime,
            inspection(base.parent),
        )
        self.assertEqual([], errors)
        os.mkdir(base, 0o700)
        os.chmod(base, 0o700)
        connector_instance, connector_generation = (
            p00_photos.expected_connector_provenance(runtime)
        )
        for role, asset_proof, data in (
            ("local", proof.local, local_bytes),
            ("cloud", proof.cloud, cloud_bytes),
        ):
            fixture = runtime[role]
            blob = base / asset_proof.output_name
            blob.write_bytes(data)
            os.chmod(blob, 0o600)
            provenance = {
                "schema_version": 1,
                "run_id": RUN_ID,
                "harness_run_id": source_binding().harness_run_id,
                "source_fingerprint": SOURCE_FINGERPRINT,
                "executable_sha256": EXECUTABLE_HASH,
                "bundle_id": p00_photos.EXPECTED_BUNDLE_ID,
                "fixture_role": role,
                "fixture_id": fixture["fixture_id"],
                "nonpersonal_provenance": p00_photos.NONPERSONAL_PROVENANCE,
                "connector_instance": connector_instance,
                "connector_generation": connector_generation,
                "asset_alias": asset_proof.asset_alias,
                "resource_alias": asset_proof.resource_alias,
                "representation_policy": "original_primary_v1",
                "residency": role,
                "blob_sha256": fixture["sha256"],
                "byte_count": len(data),
                "pixel_width": fixture["pixel_width"],
                "pixel_height": fixture["pixel_height"],
            }
            sidecar = base / (
                asset_proof.resource_alias
                + runtime["output_contract"]["provenance_suffix"]
            )
            sidecar.write_text(json.dumps(provenance), encoding="utf-8")
            os.chmod(sidecar, 0o600)
        return runtime, proof

    def test_hashes_decodes_and_validates_exact_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            runtime, proof = self._write_outputs(output)

            def sips(path: Path) -> tuple[tuple[int, int], list[str]]:
                role = (
                    "local"
                    if path.name == proof.local.output_name
                    else "cloud"
                )
                fixture = runtime[role]
                return (
                    (fixture["pixel_width"], fixture["pixel_height"]),
                    [],
                )

            with mock.patch(
                "tools.evaluators.p00_photos._run_sips",
                side_effect=sips,
            ):
                errors = p00_photos.verify_live_outputs(
                    output, runtime, proof
                )
        self.assertEqual([], errors)

    def test_rejects_hash_dimensions_alias_and_provenance_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            runtime, proof = self._write_outputs(output)
            local_blob = output / proof.local.output_name
            local_blob.write_bytes(b"mutated")
            os.chmod(local_blob, 0o600)
            with mock.patch(
                "tools.evaluators.p00_photos._run_sips",
                return_value=((99, 99), []),
            ):
                errors = p00_photos.verify_live_outputs(
                    output, runtime, proof
                )
        self.assertTrue(any("hash" in error for error in errors))
        self.assertTrue(any("dimensions" in error for error in errors))

    def test_rejects_preexisting_or_extra_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            runtime, proof = self._write_outputs(output)
            extra = output / "preexisting"
            extra.write_text("stale", encoding="utf-8")
            errors = p00_photos.verify_live_outputs(
                output, runtime, proof
            )
        self.assertTrue(any("file set" in error for error in errors))

    def test_rejects_every_provenance_field_mutation_and_removal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            runtime, proof = self._write_outputs(output)
            sidecar = output / (
                proof.local.resource_alias
                + runtime["output_contract"]["provenance_suffix"]
            )
            baseline = json.loads(sidecar.read_text(encoding="utf-8"))

            def sips(path: Path) -> tuple[tuple[int, int], list[str]]:
                role = (
                    "local"
                    if path.name == proof.local.output_name
                    else "cloud"
                )
                return (
                    (
                        runtime[role]["pixel_width"],
                        runtime[role]["pixel_height"],
                    ),
                    [],
                )

            for field, value in baseline.items():
                for remove in (False, True):
                    with self.subTest(field=field, remove=remove), mock.patch(
                        "tools.evaluators.p00_photos._run_sips",
                        side_effect=sips,
                    ):
                        provenance = copy.deepcopy(baseline)
                        if remove:
                            del provenance[field]
                        else:
                            provenance[field] = mutated(value)
                        sidecar.write_text(
                            json.dumps(provenance), encoding="utf-8"
                        )
                        os.chmod(sidecar, 0o600)
                        errors = p00_photos.verify_live_outputs(
                            output, runtime, proof
                        )
                        self.assertTrue(errors)
            sidecar.write_text(json.dumps(baseline), encoding="utf-8")

    def test_output_directory_must_not_preexist_in_any_form(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            absent = root / "absent"
            self.assertEqual(
                [],
                p00_photos.validate_output_directory_absent(absent),
            )
            existing = root / "existing"
            existing.mkdir()
            self.assertTrue(
                p00_photos.validate_output_directory_absent(existing)
            )
            dangling = root / "dangling"
            dangling.symlink_to(root / "missing")
            self.assertTrue(
                p00_photos.validate_output_directory_absent(dangling)
            )


class PrivacyTests(unittest.TestCase):
    def test_scans_all_public_sentinel_encodings(self) -> None:
        for sentinel in p00_photos.KNOWN_SENTINELS:
            for variant in p00_photos.sentinel_variants(sentinel):
                with self.subTest(sentinel=sentinel, variant=variant):
                    with tempfile.TemporaryDirectory() as directory:
                        artifact = Path(directory) / "artifact"
                        artifact.write_bytes(variant)
                        errors = p00_photos.scan_artifacts(Path(directory))
                    self.assertTrue(errors)

    def test_excludes_private_blobs_but_rejects_public_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "private"
            public = root / "public"
            private.mkdir()
            public.mkdir()
            source = private / "source"
            source.write_bytes(
                p00_photos.KNOWN_SENTINELS[0].encode()
            )
            self.assertEqual(
                [],
                p00_photos.scan_artifacts(
                    root, private_roots=(private,)
                ),
            )
            (public / "alias").symlink_to(source)
            self.assertTrue(
                p00_photos.scan_artifacts(
                    root, private_roots=(private,)
                )
            )


class EvaluatorIntegrationTests(unittest.TestCase):
    def _environment(self) -> dict[str, str]:
        return {
            p00_photos.LIVE_CHALLENGE_ENV: json.dumps(
                operator_challenge()
            ),
            "HARNESS_RUN_DIR": "/repo/artifacts/harness/run",
        }

    @mock.patch(
        "tools.evaluators.p00_photos._executable_still_bound",
        return_value=[],
    )
    @mock.patch(
        "tools.evaluators.p00_photos.validate_approved_fixture_source",
        return_value=[],
    )
    @mock.patch(
        "tools.evaluators.p00_photos._source_still_bound",
        return_value=[],
    )
    @mock.patch(
        "tools.evaluators.p00_photos.verify_live_outputs",
        return_value=[],
    )
    @mock.patch(
        "tools.evaluators.p00_photos.validate_gui_session",
        return_value=[],
    )
    @mock.patch(
        "tools.evaluators.p00_photos.sandbox_output_directory_for_run"
    )
    @mock.patch("tools.evaluators.p00_photos.inspect_source_built_app")
    @mock.patch("tools.evaluators.p00_photos.package_current_source")
    @mock.patch("tools.evaluators.p00_photos.make_package_root")
    @mock.patch("tools.evaluators.p00_photos.validate_source_binding")
    @mock.patch("tools.evaluators.p00_photos.run_bounded_command")
    @mock.patch(
        "tools.evaluators.p00_photos.secrets.token_hex",
        side_effect=(NONCE, RUN_TOKEN),
    )
    def test_builds_inspects_and_launches_only_source_built_binary(
        self,
        _token: mock.Mock,
        run: mock.Mock,
        bind: mock.Mock,
        make_root: mock.Mock,
        package: mock.Mock,
        inspect: mock.Mock,
        output_path: mock.Mock,
        _gui: mock.Mock,
        _verify: mock.Mock,
        _source: mock.Mock,
        _fixtures: mock.Mock,
        _executable: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            evidence = base / "evidence"
            package_root = base / "package"
            package_root.mkdir()
            inspected = inspection(base)
            output = base / "sandbox-output"
            make_root.return_value = package_root
            bind.return_value = (source_binding(), [])
            package.return_value = (
                inspected.app,
                command_result(str(inspected.app)),
                [],
            )
            inspect.return_value = (inspected, [])
            output_path.return_value = output
            def run_command(
                command: list[str],
                **kwargs: object,
            ) -> p00_photos.CommandResult:
                if command == p00_photos.TEST_COMMAND:
                    return command_result(deterministic_output())
                live_env = kwargs["env"]
                injected = json.loads(
                    live_env[p00_photos.LIVE_CHALLENGE_ENV]
                )
                return command_result(
                    live_output(valid_live_records(injected))
                )

            run.side_effect = run_command
            with mock.patch.dict(
                os.environ, self._environment(), clear=True
            ):
                result = p00_photos.evaluate(
                    base, evidence, {p00_photos.REQUIREMENT_ID}
                )
            payload = json.loads(
                (evidence / "P00-PHO-001.json").read_text(encoding="utf-8")
            )
            calls = run.call_args_list
        self.assertEqual(0, result)
        self.assertEqual("pass", payload["status"])
        self.assertEqual(p00_photos.TEST_COMMAND, calls[0].args[0])
        self.assertEqual(
            [
                str(inspected.executable),
                "--p00-photos-live-challenge",
            ],
            calls[1].args[0],
        )
        live_env = calls[1].kwargs["env"]
        self.assertEqual(NONCE, live_env[p00_photos.NONCE_ENV])
        injected = json.loads(live_env[p00_photos.LIVE_CHALLENGE_ENV])
        self.assertEqual(RUN_ID, injected["run_id"])
        self.assertEqual(EXECUTABLE_HASH, injected["executable_sha256"])
        self.assertNotIn(p00_photos.FORBIDDEN_LIVE_APP_ENV, live_env)
        self.assertEqual(
            EXECUTABLE_HASH,
            payload["details"]["public_summary"]["executable_sha256"],
        )
        self.assertEqual(
            "not_claimed_deferred_p06",
            payload["details"]["public_summary"][
                "native_rust_integration"
            ],
        )
        package.assert_called_once()
        inspect.assert_called_once_with(base, inspected.app)

    @mock.patch(
        "tools.evaluators.p00_photos.validate_gui_session",
        return_value=[],
    )
    @mock.patch("tools.evaluators.p00_photos.validate_source_binding")
    @mock.patch("tools.evaluators.p00_photos.run_bounded_command")
    @mock.patch(
        "tools.evaluators.p00_photos.secrets.token_hex",
        side_effect=(NONCE, RUN_TOKEN),
    )
    def test_missing_challenge_removes_stale_pass_and_never_packages(
        self,
        _token: mock.Mock,
        run: mock.Mock,
        bind: mock.Mock,
        _gui: mock.Mock,
    ) -> None:
        run.return_value = command_result(deterministic_output())
        bind.return_value = (source_binding(), [])
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            evidence = base / "evidence"
            evidence.mkdir()
            passing = evidence / "P00-PHO-001.json"
            passing.write_text('{"status":"pass"}', encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {"HARNESS_RUN_DIR": "/repo/run"},
                clear=True,
            ), mock.patch(
                "tools.evaluators.p00_photos.package_current_source"
            ) as package:
                result = p00_photos.evaluate(
                    base, evidence, {p00_photos.REQUIREMENT_ID}
                )
            exists = passing.exists()
        self.assertEqual(1, result)
        self.assertFalse(exists)
        package.assert_not_called()

    @mock.patch(
        "tools.evaluators.p00_photos.validate_gui_session",
        return_value=[],
    )
    @mock.patch("tools.evaluators.p00_photos.validate_source_binding")
    @mock.patch("tools.evaluators.p00_photos.run_bounded_command")
    @mock.patch(
        "tools.evaluators.p00_photos.secrets.token_hex",
        side_effect=(NONCE, RUN_TOKEN),
    )
    def test_arbitrary_live_app_is_rejected_before_package(
        self,
        _token: mock.Mock,
        run: mock.Mock,
        bind: mock.Mock,
        _gui: mock.Mock,
    ) -> None:
        run.return_value = command_result(deterministic_output())
        bind.return_value = (source_binding(), [])
        env = self._environment()
        env[p00_photos.FORBIDDEN_LIVE_APP_ENV] = "/tmp/Fake.app"
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, env, clear=True
        ), mock.patch(
            "tools.evaluators.p00_photos.package_current_source"
        ) as package:
            result = p00_photos.evaluate(
                Path(directory),
                Path(directory) / "evidence",
                {p00_photos.REQUIREMENT_ID},
            )
        self.assertEqual(1, result)
        package.assert_not_called()

    @mock.patch("tools.evaluators.p00_photos.run_bounded_command")
    def test_ignores_unselected_requirement(self, run: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = p00_photos.evaluate(
                Path(directory), Path(directory) / "evidence", set()
            )
        self.assertEqual(0, result)
        run.assert_not_called()


class DispatcherTests(unittest.TestCase):
    @mock.patch("tools.evaluators.run.p00_photos.evaluate", return_value=0)
    def test_registers_only_photo_requirement(
        self, evaluate: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            run_dir = base / "run"
            evidence = base / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {
                        "selected_requirement_ids": [
                            p00_photos.REQUIREMENT_ID
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence),
                },
                clear=False,
            ):
                result = evaluator_run.main()
        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT,
            evidence,
            {p00_photos.REQUIREMENT_ID},
        )


if __name__ == "__main__":
    unittest.main()
