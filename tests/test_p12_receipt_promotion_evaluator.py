from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p12_receipt_promotion as p12
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def successful_result(check: p12.CommandCheck) -> CommandResult:
    output = "\n".join(
        (
            "running 1 test",
            *check.output_markers,
            check.success_marker or "command completed",
        )
    ).encode()
    return CommandResult(
        returncode=0,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


def packet_validation() -> p12.PacketValidation:
    return p12.PacketValidation((), "a" * 64)


def write_manual_review(evidence: Path, source_sha256: str) -> None:
    evidence.mkdir(parents=True, exist_ok=True)
    write(
        evidence / p12.MANUAL_REVIEW_NAME,
        json.dumps(
            {
                "schema_version": 1,
                "reviewer": "reviewer-evaluator-test",
                "reviewed_at": "2026-07-17T02:00:00+00:00",
                "build_fingerprint": source_sha256,
                "tested_viewport": {"width": 390, "height": 844},
                "steps": [
                    {"id": step_id, "result": "pass"}
                    for step_id in p12.MANUAL_STEP_IDS
                ],
            }
        ),
    )


def write_valid_source(root: Path) -> p12.SourceValidation:
    for relative in p12.SOURCE_REQUIREMENTS:
        write(root / relative, "P12 fixture\n")

    write(
        root / "crates/wardrobe-core/src/receipt_promotion.rs",
        """
struct ReceiptPurchaseUnitId;
struct ReceiptPromotionId;
struct ReceiptAuthoritySnapshotId;
enum ReceiptPurchaseUnitExclusionReasonV1 {}
enum ReceiptPurchaseUnitFieldProvenanceV1 {}
struct ListReceiptPurchaseUnitsV1Request;
struct PromoteReceiptPurchaseUnitV1Request;
enum ReceiptPromotionConfirmationV1 {}
#[serde(deny_unknown_fields)]
struct Strict;
""",
    )
    write(
        root / "crates/wardrobe-core/src/catalog.rs",
        """
ReceiptPurchaseUnit
PromoteReceiptPurchaseUnit
PurchaseUnit
ReceiptPurchaseUnitEvidence
RetainedSharedRecords
allows_generic_undo
""",
    )
    write(
        root / "crates/wardrobe-core/src/service.rs",
        """
pub fn list_receipt_purchase_units_v1() {}
pub fn promote_receipt_purchase_unit_v1() {}
""",
    )
    write(
        root / "crates/wardrobe-core/src/bindings.rs",
        """
ReceiptPurchaseUnitId::decl()
ListReceiptPurchaseUnitsV1Request::decl()
ListReceiptPurchaseUnitsV1Response::decl()
PromoteReceiptPurchaseUnitV1Request::decl()
PromoteReceiptPurchaseUnitV1Response::decl()
""",
    )
    write(
        root / "crates/wardrobe-core/src/lib.rs",
        "mod receipt_promotion;\npub use receipt_promotion::*;\n",
    )
    write(
        root / "crates/wardrobe-core/tests/receipt_promotion_contracts.rs",
        "\n".join(f"fn {name}() {{}}" for name in p12.CORE_TESTS),
    )
    write(
        root / "crates/wardrobe-platform/src/receipt_promotion_repository.rs",
        """
transaction_with_behavior(TransactionBehavior::Immediate)
replay::<_, PromoteReceiptPurchaseUnitV1Response>
receipt_authority_snapshots
receipt_purchase_unit_promotions
receipt_purchase_unit_deletions
DecisionKindV1::PromoteReceiptPurchaseUnit
reversible: false
store_receipt(
""",
    )
    write(
        root / "crates/wardrobe-platform/src/receipt_promotion_repository_tests.rs",
        "\n".join(f"fn {name}() {{}}" for name in p12.REPOSITORY_TESTS),
    )
    write(
        root / "crates/wardrobe-platform/src/catalog_repository.rs",
        """
DeletionTargetKindV1::PurchaseUnit
DeletionTargetKindV1::ReceiptPurchaseUnitEvidence
DeletionDependencyClassV1::RetainedSharedRecords
receipt_purchase_unit_deletions
receipt_purchase_unit_promotions
receipt_authority_snapshots
""",
    )
    write(
        root / "crates/wardrobe-platform/src/deletion_repository.rs",
        """
ReceiptAuthoritySnapshots => "receipt_authority_snapshots"
ReceiptPurchaseUnitPromotions => "receipt_purchase_unit_promotions"
ReceiptPurchaseUnitDeletions => "receipt_purchase_unit_deletions"
DeletionTargetKindV1::PurchaseUnit
DeletionTargetKindV1::ReceiptPurchaseUnitEvidence
""",
    )
    write(
        root / "crates/wardrobe-platform/src/backup_repository.rs",
        """
DeletionTargetKindV1::PurchaseUnit
DeletionTargetKindV1::ReceiptPurchaseUnitEvidence
receipt_purchase_unit_deletions
""",
    )
    write(
        root / "crates/wardrobe-platform/src/database.rs",
        "\n".join(
            (
                "const MIGRATION_0017_SQL: &str = \"migration\";",
                "const MIGRATION_0017_SHA256: &str = \"hash\";",
                "Migration { version: 17 }",
                *(f"fn {name}() {{}}" for name in p12.MIGRATION_TESTS),
            )
        ),
    )
    write(
        root / "crates/wardrobe-platform/src/lib.rs",
        """
mod receipt_promotion_repository;
mod receipt_promotion_repository_tests;
""",
    )
    shutil.copyfile(ROOT / p12.MIGRATION_FILE, root / p12.MIGRATION_FILE)
    shutil.copyfile(
        ROOT / p12.MIGRATION_CHECKSUM_FILE,
        root / p12.MIGRATION_CHECKSUM_FILE,
    )

    write(
        root / "src-tauri/src/lib.rs",
        """
"list_receipt_purchase_units_v1"
"promote_receipt_purchase_unit_v1"
handle_list_receipt_purchase_units
handle_promote_receipt_purchase_unit
list_receipt_purchase_units_v1,
promote_receipt_purchase_unit_v1,
fn classify_command() {}
fn receipt_purchase_unit_commands_use_real_local_state_across_restart() {}
""",
    )
    write(
        root / "src-tauri/build.rs",
        '"list_receipt_purchase_units_v1"\n"promote_receipt_purchase_unit_v1"\n',
    )
    write(
        root / "src-tauri/capabilities/main.json",
        """
allow-list-receipt-purchase-units-v1
allow-promote-receipt-purchase-unit-v1
""",
    )
    write(
        root
        / "src-tauri/permissions/autogenerated/list_receipt_purchase_units_v1.toml",
        """
allow-list-receipt-purchase-units-v1
commands.allow = ["list_receipt_purchase_units_v1"]
deny-list-receipt-purchase-units-v1
commands.deny = ["list_receipt_purchase_units_v1"]
""",
    )
    write(
        root
        / "src-tauri/permissions/autogenerated/promote_receipt_purchase_unit_v1.toml",
        """
allow-promote-receipt-purchase-unit-v1
commands.allow = ["promote_receipt_purchase_unit_v1"]
deny-promote-receipt-purchase-unit-v1
commands.deny = ["promote_receipt_purchase_unit_v1"]
""",
    )

    write(
        root / "apps/desktop-ui/src/ReceiptsWorkspace.tsx",
        'from "./ReceiptPurchaseUnits"\n<ReceiptPurchaseUnits\n',
    )
    write(
        root / "apps/desktop-ui/src/ReceiptPurchaseUnits.tsx",
        """
Purchase units
Add to wardrobe
Create one wardrobe item
role="dialog"
aria-live="assertive"
conflictRef.current?.focus()
successRef.current?.focus()
""",
    )
    write(
        root / "apps/desktop-ui/src/ReceiptPurchaseUnits.test.tsx",
        "\n".join(p12.UI_TESTS),
    )
    write(
        root / "apps/desktop-ui/src/receipt-promotion-bridge.ts",
        """
"list_receipt_purchase_units_v1"
"promote_receipt_purchase_unit_v1"
confirmation: "create_one_wardrobe_item"
category_authority: "user_selected"
""",
    )
    write(
        root / "apps/desktop-ui/src/receipt-promotion-bridge.test.ts",
        """
uses snapshot-bound generated list and promotion contracts
list_receipt_purchase_units_v1
promote_receipt_purchase_unit_v1
""",
    )
    write(
        root / "apps/desktop-ui/src/generated/contracts.ts",
        """
ListReceiptPurchaseUnitsV1Request
ListReceiptPurchaseUnitsV1Response
PromoteReceiptPurchaseUnitV1Request
PromoteReceiptPurchaseUnitV1Response
""",
    )
    write(
        root / "apps/desktop-ui/e2e/receipt-promotion.spec.ts",
        """
keyboard-only reviewed receipt promotion survives restart at 390px
AxeBuilder
width: 390
page.keyboard.press("Tab")
page.keyboard.press("Shift+Tab")
page.keyboard.press("Enter")
page.keyboard.press("Space")
page.keyboard.press("Escape")
expectNoHorizontalOverflow
replayLastPromotion
""",
    )
    write(
        root / p12.EVALUATOR_TEST_FILE,
        "\n".join(f"def {name}(): pass" for name in p12.EVALUATOR_TESTS),
    )
    return p12.validate_source(root)


class PacketAndSourceTests(unittest.TestCase):
    def test_approved_packet_hashes_state_and_review_are_valid(self) -> None:
        validation = p12.validate_packet(ROOT)
        self.assertEqual((), validation.errors)
        self.assertEqual(64, len(validation.sha256))

    def test_packet_tampering_is_rejected_for_every_pinned_file(self) -> None:
        for relative in p12.EXPECTED_PACKET_HASHES:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    for source in (*p12.EXPECTED_PACKET_HASHES, p12.STATE_FILE):
                        destination = root / source
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(ROOT / source, destination)
                    with (root / relative).open("ab") as handle:
                        handle.write(b"\ntampered\n")
                    validation = p12.validate_packet(root)
                self.assertTrue(
                    any("hash mismatch" in error for error in validation.errors)
                )

    def test_valid_source_covers_all_requirements_and_exact_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            validation = write_valid_source(Path(directory))
        self.assertEqual(12, len(p12.REQUIREMENT_IDS))
        self.assertTrue(all(not messages for messages in validation.errors.values()))
        self.assertEqual(len(p12.SOURCE_REQUIREMENTS), validation.file_count)
        self.assertEqual(
            {
                "focused_core",
                "focused_repository",
                "focused_migration",
                "focused_tauri",
                "focused_ui",
                "focused_playwright",
                "focused_evaluator_tests",
                "make_check",
                "diff_check",
                "regression_make_test",
            },
            {check.name for check in p12.COMMAND_CHECKS},
        )
        self.assertEqual(
            set(p12.REQUIREMENT_IDS),
            set().union(*(check.requirements for check in p12.COMMAND_CHECKS)),
        )

    def test_source_migration_and_forbidden_sentinel_tampering_fail_closed(self) -> None:
        mutations = (
            (
                "P12-IDN-001",
                "crates/wardrobe-core/src/receipt_promotion.rs",
                "ReceiptPurchaseUnitId",
            ),
            (
                "P12-DEL-001",
                "crates/wardrobe-platform/src/deletion_repository.rs",
                "ReceiptPurchaseUnitDeletions",
            ),
            (
                "P12-E2E-001",
                "src-tauri/src/lib.rs",
                "receipt_purchase_unit_commands_use_real_local_state_across_restart",
            ),
            (
                "P12-UI-001",
                "apps/desktop-ui/e2e/receipt-promotion.spec.ts",
                'page.keyboard.press("Shift+Tab")',
            ),
        )
        for requirement, relative, marker in mutations:
            with self.subTest(requirement=requirement):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    write_valid_source(root)
                    path = root / relative
                    path.write_text(path.read_text().replace(marker, "removed"))
                    validation = p12.validate_source(root)
                self.assertTrue(validation.errors[requirement])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            write(root / p12.MIGRATION_CHECKSUM_FILE, "0" * 64 + "\n")
            validation = p12.validate_source(root)
        self.assertTrue(validation.errors["P12-UPG-001"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            migration_path = root / p12.MIGRATION_FILE
            migration_path.write_text(migration_path.read_text() + "\n-- mutation\n")
            write(
                root / p12.MIGRATION_CHECKSUM_FILE,
                hashlib.sha256(migration_path.read_bytes()).hexdigest() + "\n",
            )
            validation = p12.validate_source(root)
        self.assertTrue(validation.errors["P12-UPG-001"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            path = root / "crates/wardrobe-core/src/receipt_promotion.rs"
            with path.open("ab") as handle:
                handle.write(b"\n" + p12.FORBIDDEN_SENTINELS[0] + b"\n")
            validation = p12.validate_source(root)
        self.assertTrue(validation.errors["P12-IDN-001"])

    def test_manual_review_is_strict_and_bound_to_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_valid_source(root)
            evidence = root / "evidence"
            write_manual_review(evidence, source.sha256)
            valid = p12.validate_manual_review(evidence, source.sha256)
            self.assertEqual((), valid.errors)

            payload = json.loads((evidence / p12.MANUAL_REVIEW_NAME).read_text())
            payload["steps"][0]["result"] = "fail"
            write(evidence / p12.MANUAL_REVIEW_NAME, json.dumps(payload))
            invalid = p12.validate_manual_review(evidence, source.sha256)
        self.assertTrue(invalid.errors)


class EvaluatorTests(unittest.TestCase):
    def run_successfully(
        self, root: Path, evidence: Path, selected: set[str]
    ) -> int:
        source = p12.validate_source(root)
        write_manual_review(evidence, source.sha256)

        def run(command: list[str], **_: object) -> CommandResult:
            check = next(
                check for check in p12.COMMAND_CHECKS if list(check.command) == command
            )
            return successful_result(check)

        with (
            mock.patch.object(p12, "validate_packet", return_value=packet_validation()),
            mock.patch.object(p12, "run_bounded_command", side_effect=run),
        ):
            return p12.evaluate(root, evidence, selected)

    def test_missing_named_command_marker_fails_without_pass_evidence(self) -> None:
        selected = {"P12-IDN-001"}

        def run(command: list[str], **_: object) -> CommandResult:
            check = next(
                check for check in p12.COMMAND_CHECKS if list(check.command) == command
            )
            if check.name == "focused_core":
                output = b"running 1 test\ntest result: ok\n"
                return CommandResult(
                    returncode=0,
                    output_sha256=hashlib.sha256(output).hexdigest(),
                    output_bytes=len(output),
                    duration_ms=1,
                    captured_output=output,
                )
            return successful_result(check)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_valid_source(root)
            evidence = root / "evidence"
            write_manual_review(evidence, source.sha256)
            with (
                mock.patch.object(
                    p12, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(p12, "run_bounded_command", side_effect=run),
            ):
                result = p12.evaluate(root, evidence, selected)
            diagnostics = json.loads(
                (evidence / p12.DIAGNOSTICS_NAME).read_text()
            )
        self.assertEqual(1, result)
        self.assertFalse((evidence / "P12-IDN-001.json").exists())
        self.assertTrue(
            any("expected scope" in failure for failure in diagnostics["failures"])
        )

    def test_command_failure_stops_checks_and_removes_stale_evidence(self) -> None:
        selected = {"P12-E2E-001"}
        calls: list[list[str]] = []

        def run(command: list[str], **_: object) -> CommandResult:
            calls.append(command)
            return CommandResult(
                returncode=2,
                output_sha256=hashlib.sha256(b"failed").hexdigest(),
                output_bytes=6,
                duration_ms=1,
                captured_output=b"failed",
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_valid_source(root)
            evidence = root / "evidence"
            write_manual_review(evidence, source.sha256)
            stale = evidence / "P12-E2E-001.json"
            write(stale, '{"status":"pass"}')
            with (
                mock.patch.object(
                    p12, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(p12, "run_bounded_command", side_effect=run),
            ):
                result = p12.evaluate(root, evidence, selected)
            diagnostics = json.loads(
                (evidence / p12.DIAGNOSTICS_NAME).read_text()
            )
        self.assertEqual(1, result)
        self.assertEqual(1, len(calls))
        self.assertFalse(stale.exists())
        self.assertIn("P12 check failed", diagnostics["failures"][0])

    def test_runtime_sentinel_fails_and_never_enters_diagnostics(self) -> None:
        selected = {"P12-IDN-001"}
        sentinel = p12.FORBIDDEN_SENTINELS[1]

        def run(command: list[str], **_: object) -> CommandResult:
            output = b"running 1 test\n" + sentinel + b"\ntest result: ok\n"
            return CommandResult(
                returncode=0,
                output_sha256=hashlib.sha256(output).hexdigest(),
                output_bytes=len(output),
                duration_ms=1,
                captured_output=output,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_valid_source(root)
            evidence = root / "evidence"
            write_manual_review(evidence, source.sha256)
            with (
                mock.patch.object(
                    p12, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(p12, "run_bounded_command", side_effect=run),
            ):
                result = p12.evaluate(root, evidence, selected)
            diagnostics_bytes = (evidence / p12.DIAGNOSTICS_NAME).read_bytes()
            diagnostics = json.loads(diagnostics_bytes)
        self.assertEqual(1, result)
        self.assertNotIn(sentinel, diagnostics_bytes)
        self.assertTrue(
            any("forbidden sentinel" in failure for failure in diagnostics["failures"])
        )

    def test_evidence_publication_rolls_back_on_any_write_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_valid_source(root)
            evidence = root / "evidence"
            write_manual_review(evidence, source.sha256)

            def run(command: list[str], **_: object) -> CommandResult:
                check = next(
                    check
                    for check in p12.COMMAND_CHECKS
                    if list(check.command) == command
                )
                return successful_result(check)

            real_write = p12._write_bounded
            write_count = 0

            def fail_third_write(path: Path, value: dict[str, object]) -> None:
                nonlocal write_count
                write_count += 1
                if write_count == 3:
                    raise OSError("injected evidence write failure")
                real_write(path, value)

            with (
                mock.patch.object(
                    p12, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(p12, "run_bounded_command", side_effect=run),
                mock.patch.object(
                    p12, "_write_bounded", side_effect=fail_third_write
                ),
                self.assertRaisesRegex(OSError, "injected evidence write failure"),
            ):
                p12.evaluate(root, evidence, set(p12.REQUIREMENT_IDS))

            published = {
                path.name
                for path in evidence.iterdir()
                if path.name != p12.MANUAL_REVIEW_NAME
            }
        self.assertEqual(set(), published)

    def test_success_emits_one_record_per_requirement_and_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evidence = root / "evidence"
            result = self.run_successfully(
                root, evidence, set(p12.REQUIREMENT_IDS)
            )
            names = {path.name for path in evidence.iterdir()}
            diagnostics = json.loads(
                (evidence / p12.DIAGNOSTICS_NAME).read_text()
            )
            records = [
                json.loads((evidence / f"{requirement}.json").read_text())
                for requirement in sorted(p12.REQUIREMENT_IDS)
            ]
        self.assertEqual(0, result)
        self.assertEqual(
            {
                *(f"{requirement}.json" for requirement in p12.REQUIREMENT_IDS),
                p12.DIAGNOSTICS_NAME,
                p12.MANUAL_REVIEW_NAME,
            },
            names,
        )
        self.assertEqual("pass", diagnostics["status"])
        self.assertTrue(diagnostics["pass_evidence_written"])
        self.assertEqual(
            set(p12.REQUIREMENT_IDS),
            {record["requirement_id"] for record in records},
        )
        self.assertTrue(all(record["status"] == "pass" for record in records))


class DispatcherTests(unittest.TestCase):
    @mock.patch(
        "tools.evaluators.run.p12_receipt_promotion.evaluate", return_value=0
    )
    def test_dispatches_exact_p12_requirement_ids(
        self, evaluate: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {"selected_requirement_ids": sorted(p12.REQUIREMENT_IDS)}
                )
            )
            with mock.patch.dict(
                "os.environ",
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence),
                },
                clear=False,
            ):
                result = evaluator_run.main()
        self.assertEqual(0, result)
        evaluate.assert_called_once_with(ROOT, evidence, set(p12.REQUIREMENT_IDS))

    def test_unknown_p12_requirement_remains_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": ["P12-ATM-999"]})
            )
            with mock.patch.dict(
                "os.environ",
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence),
                },
                clear=False,
            ):
                result = evaluator_run.main()
        self.assertEqual(1, result)


if __name__ == "__main__":
    unittest.main()
