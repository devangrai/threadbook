from __future__ import annotations

import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import struct
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p09_offline
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def copy(relative: str, root: Path) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, destination)


def smoke_report() -> dict[str, object]:
    report: dict[str, object] = {
        "schema_version": 1,
        "status": "pass",
        "artifact_kind": "macos_app",
        "packaging_identity": "ad_hoc_development_host",
        "process_exit_status": 0,
        "restart_count": 1,
        "source_digest_count": 2,
        "outbound_attempt_record_count": 0,
        "developer_id_signed": False,
        "notarized": False,
        "clean_machine_certified": False,
        "signed_acceptance_claim": "deferred_not_passed",
        "connector_cleanup_controls_applicable": False,
        "source_fingerprint": p09_offline.source_fingerprint(),
    }
    report.update({field: True for field in p09_offline.SMOKE_BOOLEAN_FIELDS})
    report.update(
        {
            field: hashlib.sha256(field.encode()).hexdigest()
            for field in p09_offline.SMOKE_HASH_FIELDS
        }
    )
    report["collage_after_sha256"] = report["collage_before_sha256"]
    return report


def canonical_member_pixels(rgb: tuple[int, int, int]) -> bytes:
    pixels = bytearray()
    for y in range(32):
        for x in range(32):
            pixels.extend(
                rgb
                if x < 24
                else (x * 7 % 256, y * 9 % 256, (x + y) * 5 % 256)
            )
    return (
        p09_offline.PIXEL_MAGIC
        + struct.pack(">IIB", 32, 32, 3)
        + bytes(pixels)
    )


def member_pixel_sidecar(
    records: tuple[tuple[int, str, bytes], ...] | None = None,
) -> bytes:
    selected = records or tuple(
        (
            ordinal,
            digest,
            canonical_member_pixels(p09_offline.FIXTURE_DIGEST_RGB[digest]),
        )
        for ordinal, digest in enumerate(p09_offline.FIXTURE_DIGESTS)
    )
    encoded = bytearray(p09_offline.MEMBER_PIXEL_MAGIC)
    encoded.extend(struct.pack(">B", len(selected)))
    for ordinal, digest, pixels in selected:
        encoded.extend(
            struct.pack(">B32sI", ordinal, bytes.fromhex(digest), len(pixels))
        )
        encoded.extend(pixels)
    return bytes(encoded)


def smoke_sidecars() -> dict[str, bytes]:
    source_a, source_b = p09_offline.FIXTURE_DIGESTS
    canonical_pixels = member_pixel_sidecar()
    residual = {
        "schema_version": 1,
        "integrity_check": "ok",
        "foreign_key_violation_count": 0,
        "database_schema_version": 13,
        "source_digests": [source_a, source_b],
        "verified_blob_digests": [source_a, source_b],
        "active_item_count": 2,
        "assigned_evidence_count": 2,
        "outfit_count": 1,
        "outfit_member_digests": [
            {"ordinal": 0, "blob_sha256": source_a},
            {"ordinal": 1, "blob_sha256": source_b},
        ],
        "outbound_attempt_record_count": 0,
        "log_tree_sha256": "3" * 64,
        "collage_contract_sha256": "4" * 64,
    }
    return {
        "deny-network.sb": (
            b"(version 1)\n(allow default)\n(deny network*)\n"
        ),
        "accessibility.txt": (
            b"FIRST_COLLAGE\nSaved wardrobe collage\nLocal only\n"
            b"SECOND_COLLAGE\nSaved wardrobe collage\n"
            b"SETTINGS\nNetwork mode\nPreview deletion\nNot configured\n"
            b"Disconnect remains available\n"
            b"Existing credentials can still be removed\n"
        ),
        "residual-scan.json": json.dumps(
            residual,
            sort_keys=True,
            separators=(",", ":"),
        ).encode(),
        "sandbox.log": (
            b"network-child-control returncode=0\n"
            b"network-child-denied returncode=7\n"
        ),
        "collage-before.pixels": canonical_pixels,
        "collage-after.pixels": canonical_pixels,
    }


def write_smoke_report(directory: Path, name: str = "offline-smoke.json") -> Path:
    sidecar_dir = directory / "offline-smoke"
    sidecar_dir.mkdir()
    payloads = smoke_sidecars()
    for sidecar_name, data in payloads.items():
        (sidecar_dir / sidecar_name).write_bytes(data)
    report = smoke_report()
    for field, (sidecar_name, _limit) in p09_offline.SMOKE_SIDECARS.items():
        report[field] = hashlib.sha256(payloads[sidecar_name]).hexdigest()
    path = directory / name
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def packet_validation() -> p09_offline.PacketValidation:
    return p09_offline.PacketValidation((), "a" * 64, {"packet": "b" * 64})


def command_check(*, backend_smoke: bool = False) -> p09_offline.CommandCheck:
    return p09_offline.CommandCheck(
        name="backend" if backend_smoke else "ui",
        command=(
            ("cargo", "test", "required_test", "--", "--test-threads=1")
            if backend_smoke
            else ("npm", "test")
        ),
        require_rust_test=backend_smoke,
        backend_smoke=backend_smoke,
    )


def source_validation() -> p09_offline.SourceValidation:
    return p09_offline.SourceValidation(
        errors=(),
        source_sha256="c" * 64,
        source_hashes={"source.rs": "d" * 64},
        source_file_count=24,
        registered_command_count=len(p09_offline.EXPECTED_COMMANDS),
        outbound_command_count=len(p09_offline.OUTBOUND_COMMAND_CAPABILITIES),
        local_cleanup_command_count=len(p09_offline.LOCAL_CLEANUP_COMMANDS),
        capability_count=len(p09_offline.EXPECTED_CAPABILITIES),
        focused_checks=(command_check(backend_smoke=True), command_check()),
    )


def smoke_validation() -> p09_offline.SmokeValidation:
    return p09_offline.SmokeValidation(
        errors=(),
        report_sha256="e" * 64,
        bundle_sha256="f" * 64,
        executable_sha256="1" * 64,
        sandbox_profile_sha256="2" * 64,
        collage_sha256="3" * 64,
        source_digest_count=2,
        developer_id_signed=False,
        notarized=False,
        clean_machine_certified=False,
    )


def command_result(check: list[str]) -> CommandResult:
    output = (
        b"required_test\ntest result: ok\n"
        if check and check[0] == "cargo"
        else b"ok\n"
    )
    return CommandResult(
        returncode=0,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


class P09OfflineEvaluatorTests(unittest.TestCase):
    def test_current_frozen_packet_is_valid(self) -> None:
        packet = p09_offline.validate_packet(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual(set(p09_offline.EXPECTED_PACKET_HASHES), set(packet.hashes))
        self.assertEqual(64, len(packet.packet_sha256))

    def test_packet_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                *p09_offline.EXPECTED_PACKET_HASHES,
                p09_offline.STATE_FILE,
            ):
                copy(relative, root)
            proposal = root / p09_offline.PACKET_DIR / "proposal.md"
            proposal.write_text(
                proposal.read_text(encoding="utf-8") + "\nmutated\n",
                encoding="utf-8",
            )

            packet = p09_offline.validate_packet(root)

        self.assertTrue(
            any("proposal.md" in error for error in packet.errors),
            packet.errors,
        )

    def test_parses_balanced_handler_and_closed_capability_enum(self) -> None:
        source = """
        enum OutboundCapability {
            GmailAuthorize,
            OpenAiTryOn,
        }
        fn register() {
            builder.invoke_handler(tauri::generate_handler![
                get_foundation_snapshot_v1,
                command_with_nested_v1,
            ]);
        }
        """

        self.assertEqual(
            ("get_foundation_snapshot_v1", "command_with_nested_v1"),
            p09_offline.parse_registered_commands(source),
        )
        self.assertEqual(
            ("GmailAuthorize", "OpenAiTryOn"),
            p09_offline.parse_enum_variants(source, "OutboundCapability"),
        )

    def test_command_classification_rejects_unknown_missing_and_duplicate(self) -> None:
        valid = tuple(sorted(p09_offline.EXPECTED_COMMANDS))
        classification, errors = p09_offline.classify_registered_commands(valid)
        self.assertEqual((), errors)
        self.assertEqual(
            "outbound", classification["connect_gmail_v1"]
        )
        self.assertEqual(
            "local_cleanup", classification["disconnect_gmail_v1"]
        )
        self.assertEqual("local", classification["set_local_only_v1"])

        _, errors = p09_offline.classify_registered_commands(
            (*valid[1:], "unclassified_network_command_v1", valid[1])
        )
        self.assertTrue(any("duplicates" in error for error in errors))
        self.assertTrue(any("missing" in error for error in errors))
        self.assertTrue(any("no closed" in error for error in errors))

    def test_focused_test_decisions_require_every_boundary_and_one_real_smoke(
        self,
    ) -> None:
        core = p09_offline.RustTest(
            "crates/wardrobe-core/tests/local_only_contracts.rs",
            "wardrobe-core",
            "test",
            "local_only_contracts",
            "local_only_contract",
            "SetLocalOnlyV1Request local_only",
        )
        store = p09_offline.RustTest(
            "crates/wardrobe-platform/tests/local_only_store.rs",
            "wardrobe-platform",
            "test",
            "local_only_store",
            "local_only_store",
            "LocalOnlyModeStore local_only",
        )
        exact = tuple(
            p09_offline.RustTest(
                (
                    "src-tauri/src/lib.rs"
                    if package == "wardrobe-desktop"
                    else "crates/wardrobe-platform/src/database.rs"
                ),
                package,
                "lib",
                "lib",
                test_name,
                "real production-path focused behavior",
            )
            for _label, package, test_name, _backend_smoke
            in p09_offline.REQUIRED_FOCUSED_RUST_TESTS
        )

        checks, errors = p09_offline._focused_checks(
            (core, store, *exact),
            ("src/LocalOnlySettings.test.tsx",),
        )

        self.assertEqual([], errors)
        self.assertEqual(1, sum(check.backend_smoke for check in checks))

        _, errors = p09_offline._focused_checks(
            (core, store, *exact[:-1]),
            ("src/LocalOnlySettings.test.tsx",),
        )
        self.assertTrue(
            any(
                "local_only_import_review_outfit_collage_restart_smoke" in error
                for error in errors
            )
        )

    def test_smoke_report_accepts_only_truthful_ad_hoc_functional_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid_path = write_smoke_report(root)
            validation = p09_offline.validate_smoke_report(valid_path)
            self.assertEqual((), validation.errors)
            self.assertFalse(validation.developer_id_signed)
            self.assertEqual(2, validation.source_digest_count)

            extra = root / "offline-smoke/process.log"
            extra.write_text("Navy Date Trousers", encoding="utf-8")
            extra_rejected = p09_offline.validate_smoke_report(valid_path)
            self.assertTrue(
                any("inventory is not exact" in error for error in extra_rejected.errors)
            )
            extra.unlink()

            zero_hashes = json.loads(valid_path.read_text(encoding="utf-8"))
            for field in p09_offline.SMOKE_SIDECARS:
                zero_hashes[field] = "0" * 64
            zero_path = root / "zero-hashes.json"
            zero_path.write_text(json.dumps(zero_hashes), encoding="utf-8")
            zero_rejected = p09_offline.validate_smoke_report(zero_path)
            self.assertTrue(
                any("sidecar hash changed" in error for error in zero_rejected.errors)
            )

            transcript = root / "offline-smoke/accessibility.txt"
            transcript.write_bytes(transcript.read_bytes() + b"tampered")
            sidecar_rejected = p09_offline.validate_smoke_report(valid_path)
            self.assertTrue(
                any(
                    "sidecar hash changed" in error
                    for error in sidecar_rejected.errors
                )
            )

            invalid = smoke_report()
            invalid["developer_id_signed"] = True
            invalid["signed_acceptance_claim"] = "pass"
            invalid["packaging_identity"] = "playwright browser mock"
            invalid_path = root / "invalid.json"
            invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
            rejected = p09_offline.validate_smoke_report(invalid_path)

        self.assertTrue(any("identity" in error for error in rejected.errors))
        self.assertTrue(any("may not claim developer" in error for error in rejected.errors))
        self.assertTrue(any("signed release" in error for error in rejected.errors))
        self.assertTrue(any("browser/mock" in error for error in rejected.errors))

    def test_smoke_report_rejects_nonblank_pixels_without_fixture_images(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid_path = write_smoke_report(root)
            pixels = bytearray()
            for y in range(32):
                for x in range(32):
                    pixels.extend(
                        (x * 5 % 251, y * 7 % 251, (x + y) * 11 % 251)
                    )
            unrelated_pixels = (
                p09_offline.PIXEL_MAGIC
                + struct.pack(">IIB", 32, 32, 3)
                + bytes(pixels)
            )
            missing_fixture = member_pixel_sidecar(
                tuple(
                    (ordinal, digest, unrelated_pixels)
                    for ordinal, digest in enumerate(
                        p09_offline.FIXTURE_DIGESTS
                    )
                )
            )
            report = json.loads(valid_path.read_text(encoding="utf-8"))
            for field, name in (
                ("collage_before_sha256", "collage-before.pixels"),
                ("collage_after_sha256", "collage-after.pixels"),
            ):
                (root / "offline-smoke" / name).write_bytes(missing_fixture)
                report[field] = hashlib.sha256(missing_fixture).hexdigest()
            valid_path.write_text(json.dumps(report), encoding="utf-8")

            rejected = p09_offline.validate_smoke_report(valid_path)

        self.assertTrue(
            any(
                "do not match the pinned source digest" in error
                for error in rejected.errors
            )
        )

    def test_smoke_report_rejects_swapped_member_pixels_and_residual_order(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid_path = write_smoke_report(root)
            first, second = p09_offline.FIXTURE_DIGESTS
            swapped = member_pixel_sidecar(
                (
                    (
                        0,
                        first,
                        canonical_member_pixels(
                            p09_offline.FIXTURE_DIGEST_RGB[second]
                        ),
                    ),
                    (
                        1,
                        second,
                        canonical_member_pixels(
                            p09_offline.FIXTURE_DIGEST_RGB[first]
                        ),
                    ),
                )
            )
            report = json.loads(valid_path.read_text(encoding="utf-8"))
            for field, name in (
                ("collage_before_sha256", "collage-before.pixels"),
                ("collage_after_sha256", "collage-after.pixels"),
            ):
                (root / "offline-smoke" / name).write_bytes(swapped)
                report[field] = hashlib.sha256(swapped).hexdigest()
            valid_path.write_text(json.dumps(report), encoding="utf-8")

            rejected = p09_offline.validate_smoke_report(valid_path)

        self.assertTrue(
            any(
                "do not match the pinned source digest" in error
                for error in rejected.errors
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid_path = write_smoke_report(root)
            residual_path = root / "offline-smoke/residual-scan.json"
            residual = json.loads(residual_path.read_text(encoding="utf-8"))
            member_digests = residual["outfit_member_digests"]
            member_digests[0]["blob_sha256"], member_digests[1]["blob_sha256"] = (
                member_digests[1]["blob_sha256"],
                member_digests[0]["blob_sha256"],
            )
            residual_bytes = json.dumps(
                residual,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            residual_path.write_bytes(residual_bytes)
            report = json.loads(valid_path.read_text(encoding="utf-8"))
            report["residual_scan_sha256"] = hashlib.sha256(
                residual_bytes
            ).hexdigest()
            valid_path.write_text(json.dumps(report), encoding="utf-8")

            rejected = p09_offline.validate_smoke_report(valid_path)

        self.assertTrue(
            any(
                "do not match residual digest order" in error
                for error in rejected.errors
            )
        )

    def test_smoke_report_rejects_malformed_member_mapping_and_sidecar(
        self,
    ) -> None:
        for malformed in (
            [
                {
                    "ordinal": False,
                    "blob_sha256": p09_offline.FIXTURE_DIGESTS[0],
                },
                {
                    "ordinal": True,
                    "blob_sha256": p09_offline.FIXTURE_DIGESTS[1],
                },
            ],
            [
                {
                    "ordinal": 0,
                    "blob_sha256": p09_offline.FIXTURE_DIGESTS[0],
                },
                {
                    "ordinal": 1,
                    "blob_sha256": p09_offline.FIXTURE_DIGESTS[1],
                },
                "ignored-extra-row",
            ],
            [
                {"ordinal": 0, "blob_sha256": []},
                {
                    "ordinal": 1,
                    "blob_sha256": p09_offline.FIXTURE_DIGESTS[1],
                },
            ],
        ):
            with self.subTest(malformed=malformed):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    valid_path = write_smoke_report(root)
                    residual_path = root / "offline-smoke/residual-scan.json"
                    residual = json.loads(
                        residual_path.read_text(encoding="utf-8")
                    )
                    residual["outfit_member_digests"] = malformed
                    residual_bytes = json.dumps(
                        residual,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                    residual_path.write_bytes(residual_bytes)
                    report = json.loads(
                        valid_path.read_text(encoding="utf-8")
                    )
                    report["residual_scan_sha256"] = hashlib.sha256(
                        residual_bytes
                    ).hexdigest()
                    valid_path.write_text(json.dumps(report), encoding="utf-8")

                    rejected = p09_offline.validate_smoke_report(valid_path)

                self.assertTrue(
                    any(
                        "residual scan contract is invalid" in error
                        for error in rejected.errors
                    )
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid_path = write_smoke_report(root)
            report = json.loads(valid_path.read_text(encoding="utf-8"))
            malformed_sidecar = member_pixel_sidecar() + b"trailing"
            for field, name in (
                ("collage_before_sha256", "collage-before.pixels"),
                ("collage_after_sha256", "collage-after.pixels"),
            ):
                (root / "offline-smoke" / name).write_bytes(malformed_sidecar)
                report[field] = hashlib.sha256(malformed_sidecar).hexdigest()
            valid_path.write_text(json.dumps(report), encoding="utf-8")

            rejected = p09_offline.validate_smoke_report(valid_path)

        self.assertTrue(
            any(
                "not closed and ordered" in error
                for error in rejected.errors
            )
        )

    def test_smoke_report_hashes_the_real_production_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / p09_offline.BUNDLE_RELATIVE
            executable = bundle / "Contents/MacOS/Wardrobe"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"real packaged executable")
            with (bundle / "Contents/Info.plist").open("wb") as handle:
                plistlib.dump({"CFBundleExecutable": "Wardrobe"}, handle)
            report_path = write_smoke_report(root, "smoke.json")
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["executable_sha256"] = hashlib.sha256(
                executable.read_bytes()
            ).hexdigest()
            report["bundle_sha256"] = p09_offline.hash_app_bundle(bundle)[0]
            report_path.write_text(json.dumps(report), encoding="utf-8")

            validation = p09_offline.validate_smoke_report(
                report_path,
                root=root,
            )
            self.assertEqual((), validation.errors)

            executable.write_bytes(b"changed after smoke")
            rejected = p09_offline.validate_smoke_report(
                report_path,
                root=root,
            )

        self.assertTrue(
            any("bundle hash" in error for error in rejected.errors)
        )
        self.assertTrue(
            any("executable hash" in error for error in rejected.errors)
        )

    def test_success_writes_functional_passes_but_defers_p09_acceptance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with (
                mock.patch.object(
                    p09_offline,
                    "validate_packet",
                    return_value=packet_validation(),
                ),
                mock.patch.object(
                    p09_offline,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p09_offline,
                    "validate_smoke_report",
                    return_value=smoke_validation(),
                ),
                mock.patch.object(
                    p09_offline,
                    "run_bounded_command",
                    side_effect=lambda command, **_: command_result(command),
                ),
            ):
                result = p09_offline.evaluate(
                    ROOT,
                    evidence,
                    {"P09-OFF-001"},
                    smoke_report_path=Path("/external/smoke.json"),
                )

            self.assertEqual(0, result)
            self.assertEqual(
                {
                    *(f"{item}.json" for item in p09_offline.REQUIREMENT_IDS),
                    p09_offline.DIAGNOSTICS_NAME,
                },
                {path.name for path in evidence.iterdir()},
            )
            offline = json.loads(
                (evidence / "P09-OFF-001.json").read_text(encoding="utf-8")
            )
            self.assertEqual("deferred", offline["status"])
            summary = offline["details"]["public_summary"]
            self.assertTrue(summary["functional_ad_hoc_package_passed"])
            self.assertFalse(summary["feature_enabled"])
            self.assertEqual("deferred_not_passed", summary["acceptance_claim"])
            self.assertFalse(summary["developer_id_signed"])

            functional = json.loads(
                (evidence / "SYS-REL-002.json").read_text(encoding="utf-8")
            )
            self.assertEqual("pass", functional["status"])
            self.assertEqual(
                "functional_ad_hoc_package_passed",
                functional["details"]["public_summary"]["acceptance_claim"],
            )

    def test_failure_removes_stale_acceptance_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P09-OFF-001.json"
            stale.write_text('{"status":"pass"}', encoding="utf-8")
            with mock.patch.object(
                p09_offline,
                "validate_packet",
                return_value=p09_offline.PacketValidation(
                    ("packet changed",), "", {}
                ),
            ):
                result = p09_offline.evaluate(
                    ROOT,
                    evidence,
                    {"P09-OFF-001"},
                )

            self.assertEqual(1, result)
            self.assertFalse(stale.exists())
            diagnostics = json.loads(
                (evidence / p09_offline.DIAGNOSTICS_NAME).read_text()
            )
            self.assertEqual("fail", diagnostics["status"])
            self.assertIn("packet changed", diagnostics["failures"])


if __name__ == "__main__":
    unittest.main()
