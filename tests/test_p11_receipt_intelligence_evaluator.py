from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p11_receipt_intelligence as p11
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def successful_result(check: p11.CommandCheck) -> CommandResult:
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


def packet_validation() -> p11.PacketValidation:
    return p11.PacketValidation((), "a" * 64)


def write_valid_source(root: Path) -> None:
    for relative in p11.SOURCE_REQUIREMENTS:
        write(root / relative, "P11 fixture\n")

    write(
        root / "crates/wardrobe-core/src/receipt_intelligence.rs",
        """
const RECEIPT_INTELLIGENCE_MODEL_V1: &str = "gpt-5.6-sol";
struct ReceiptIntelligencePreparationBoundsV1;
struct ReceiptIntelligenceExecutionBoundsV1;
enum ReceiptIntelligenceAttemptStateV1 {}
enum ReceiptIntelligenceClassificationV1 {}
let store_false_is_not_organization_zdr = true;
#[serde(deny_unknown_fields)]
struct Strict;
""",
    )
    write(
        root / "crates/wardrobe-core/build.rs",
        """
openai_receipt_intelligence
evaluator_sha256
receipt-intelligence-prompt-v1
receipt-intelligence-v1
receipt-intelligence-projection-v1
p11-openai-responses-retention-v1
""",
    )
    write(
        root / "crates/wardrobe-platform/src/receipt_intelligence_provider.rs",
        """
fn build_receipt_intelligence_request() {
    "store": false; "background": false; "tools": []; "json_schema";
    InvalidCitation; RECEIPT_INTELLIGENCE_MAX_OUTPUT_TOKENS;
    StringEvidenceField; strip_allowlisted_field_separator;
}
""",
    )
    write(
        root
        / "crates/wardrobe-platform/src/receipt_intelligence_coordinator.rs",
        """
struct ReceiptIntelligenceCoordinator;
trait ReceiptIntelligenceCredentialStore {
    fn get_receipt_intelligence_secret();
}
fn reserve_receipt_intelligence() {}
fn mark_receipt_intelligence_dispatched() {}
fn mark_receipt_intelligence_outcome_unknown() {}
fn provider_outcome_unknown() {}
fn terminal_replay() {}
RetentionDeclarationUnavailable;
""",
    )
    write(
        root
        / "crates/wardrobe-platform/src/receipt_intelligence_coordinator_tests.rs",
        "\n".join(
            (
                *(f"async fn {name}() {{}}" for name in p11.COORDINATOR_TESTS),
                "OpenAiReceiptIntelligenceProvider",
                "OpenAiResponsesHttpTransport",
                "request_json(&wire)",
            )
        ),
    )
    write(
        root / "crates/wardrobe-platform/src/receipt_intelligence_repository.rs",
        """
fn preview_receipt_intelligence() {}
fn reserve_receipt_intelligence() {}
fn mark_receipt_intelligence_dispatched() {}
fn mark_receipt_intelligence_outcome_unknown() {}
fn complete_receipt_intelligence_with_publication() {}
fn recover_receipt_intelligence_attempts() {}
fn receipt_source_authority_head() {}
Sha256::digest(visible_text.as_bytes());
""",
    )
    write(
        root / "crates/wardrobe-platform/src/receipt_repository.rs",
        """
fn complete_receipt_intelligence_with_order() {}
fn publish_receipt_intelligence_order() {}
""",
    )
    write(
        root / "crates/wardrobe-platform/src/database.rs",
        """
const MIGRATION_0016_SQL: &str = include_str!("0016_receipt_intelligence.sql");
""",
    )
    write(
        root / "crates/wardrobe-platform/src/deletion_repository.rs",
        """
"receipt_intelligence_approvals"
"receipt_intelligence_attempts"
"receipt_intelligence_audits"
"receipt_intelligence_classifications"
""",
    )
    write(
        root / "crates/wardrobe-platform/src/lib.rs",
        """
mod receipt_intelligence_coordinator;
mod receipt_intelligence_provider;
mod receipt_intelligence_repository;
pub use receipt_intelligence_coordinator::*;
""",
    )
    contracts = {
        "preview_consent_and_commands_are_strict_v1_contracts",
        "provider_projection_has_only_opaque_handles_and_visible_text",
        "every_preparation_bound_is_closed_and_fails_one_over",
        "consent_binds_every_disclosed_fragment_and_configured_bound",
        "all_execution_bounds_and_stateless_parameters_are_exact",
        "retention_and_disclosure_fail_closed",
        "receipt_intelligence_types_are_exported_to_typescript",
    }
    write(
        root / "crates/wardrobe-core/tests/receipt_intelligence_contracts.rs",
        "\n".join(f"fn {name}() {{}}" for name in p11.CORE_TESTS if name in contracts),
    )
    write(
        root / "crates/wardrobe-core/tests/receipt_intelligence_states.rs",
        "\n".join(
            f"fn {name}() {{}}" for name in p11.CORE_TESTS if name not in contracts
        ),
    )
    write(
        root / "crates/wardrobe-platform/tests/receipt_intelligence_provider.rs",
        "\n".join(f"async fn {name}() {{}}" for name in p11.PROVIDER_TESTS),
    )
    write(
        root
        / "crates/wardrobe-platform/src/receipt_intelligence_repository_tests.rs",
        "\n".join(f"fn {name}() {{}}" for name in p11.REPOSITORY_TESTS),
    )
    migration = """
CREATE TABLE receipt_intelligence_approvals(id TEXT);
CREATE TABLE receipt_intelligence_attempts(id TEXT);
CREATE TABLE receipt_intelligence_classifications(id TEXT);
CREATE TRIGGER receipt_intelligence_attempts_state_transition;
CREATE TABLE receipt_source_authority_heads(id TEXT);
"""
    write(root / p11.MIGRATION_FILE, migration)
    write(
        root / p11.MIGRATION_CHECKSUM_FILE,
        hashlib.sha256(migration.encode()).hexdigest() + "\n",
    )
    tauri_markers = """
preview_receipt_intelligence_v1
request_receipt_intelligence_v1
list_receipt_intelligence_v1
receipt_intelligence_commands
receipt_intelligence_packaged_disabled_state_smoke
receipt_intelligence_availability_override_is_truthful_and_ordered
receipt_intelligence_terminal_replay_precedes_remote_gates
"""
    write(root / "src-tauri/src/lib.rs", tauri_markers)
    write(
        root / "src-tauri/src/release_manifest.rs",
        """
EXPECTED_RECEIPT_INTELLIGENCE_EVALUATOR_SHA256
service.evaluator_sha256 == EXPECTED_RECEIPT_INTELLIGENCE_EVALUATOR_SHA256
receipt_intelligence_release_requires_exact_evaluator_revision
""",
    )
    write(
        root / "src-tauri/src/local_only.rs",
        "enum OutboundCapability { OpenAiReceiptIntelligence }\n",
    )
    release_markers = """
openai_receipt_intelligence
evaluator_sha256
receipt-intelligence-prompt-v1
receipt-intelligence-v1
receipt-intelligence-projection-v1
p11-openai-responses-retention-v1
"""
    for relative in (
        "release/supply-chain-policy-v1.json",
        "release/generated/supply-chain-manifest-v1.json",
        "tools/release_supply_chain.py",
        "tests/test_release_supply_chain.py",
    ):
        write(root / relative, release_markers)
    evaluator_sha256 = hashlib.sha256((root / p11.EVALUATOR_FILE).read_bytes()).hexdigest()
    for relative in (
        "crates/wardrobe-core/build.rs",
        "release/supply-chain-policy-v1.json",
        "release/generated/supply-chain-manifest-v1.json",
        "src-tauri/src/release_manifest.rs",
        "tools/release_supply_chain.py",
        "tests/test_release_supply_chain.py",
    ):
        path = root / relative
        path.write_text(path.read_text() + evaluator_sha256 + "\n", encoding="utf-8")
    write(
        root / "src-tauri/build.rs",
        """
"preview_receipt_intelligence_v1"
"request_receipt_intelligence_v1"
"list_receipt_intelligence_v1"
""",
    )
    write(
        root / "src-tauri/capabilities/main.json",
        """
allow-preview-receipt-intelligence-v1
allow-request-receipt-intelligence-v1
allow-list-receipt-intelligence-v1
""",
    )
    write(
        root / "apps/desktop-ui/src/ReceiptIntelligencePanel.tsx",
        """
Analyze with OpenAI
store:false
organization-level Zero Data
outcome_unknown
""",
    )
    write(
        root / "apps/desktop-ui/src/receipt-intelligence-bridge.ts",
        """
preview_receipt_intelligence_v1
request_receipt_intelligence_v1
list_receipt_intelligence_v1
""",
    )
    write(
        root / "apps/desktop-ui/src/ReceiptIntelligencePanel.test.tsx",
        """
shows the exact accessible disclosure
executes only after approval
keeps remote analysis disabled
release_evidence_unavailable
credential_unavailable
""",
    )
    write(
        root / "apps/desktop-ui/e2e/receipt-intelligence.spec.ts",
        """
OpenAI receipt availability is truthful and preserves saved status
OpenAI receipt preview, cancellation, approval, and review handoff
AxeBuilder
""",
    )


class PacketAndSourceTests(unittest.TestCase):
    def test_approved_packet_hashes_state_and_review_are_valid(self) -> None:
        validation = p11.validate_packet(ROOT)
        self.assertEqual((), validation.errors)
        self.assertEqual(64, len(validation.sha256))

    def test_every_pinned_packet_mutation_is_rejected(self) -> None:
        for relative in p11.EXPECTED_PACKET_HASHES:
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    for source in (*p11.EXPECTED_PACKET_HASHES, p11.STATE_FILE):
                        destination = root / source
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(ROOT / source, destination)
                    with (root / relative).open("ab") as handle:
                        handle.write(b"\nmutation\n")
                    validation = p11.validate_packet(root)
                self.assertTrue(
                    any("hash mismatch" in error for error in validation.errors)
                )

    def test_approval_state_must_match_frozen_selection_and_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in (*p11.EXPECTED_PACKET_HASHES, p11.STATE_FILE):
                destination = root / source
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / source, destination)
            state_path = root / p11.STATE_FILE
            state = json.loads(state_path.read_text())
            state["review"]["decision"] = "REJECT"
            state_path.write_text(json.dumps(state))
            validation = p11.validate_packet(root)
        self.assertIn("P11 packet is not independently approved", validation.errors)

    def test_all_nineteen_requirements_have_source_and_command_coverage(self) -> None:
        self.assertEqual(19, len(p11.REQUIREMENT_IDS))
        source_coverage = set().union(*p11.SOURCE_REQUIREMENTS.values())
        command_coverage = set().union(
            *(check.requirements for check in p11.COMMAND_CHECKS)
        )
        self.assertEqual(set(p11.REQUIREMENT_IDS), source_coverage)
        self.assertEqual(set(p11.REQUIREMENT_IDS), command_coverage)
        self.assertEqual(
            {
                "focused_core",
                "focused_provider",
                "focused_repository",
                "focused_coordinator",
                "focused_tauri",
                "focused_ui",
                "packaged_disabled_state",
                "vertical_smoke",
                "ui_preview_review_smoke",
                "focused_evaluator_tests",
                "regression_make_test",
                "make_check",
                "diff_check",
            },
            {check.name for check in p11.COMMAND_CHECKS},
        )

    def test_rust_filters_execute_real_repository_and_coordinator_tests(self) -> None:
        checks = {check.name: check for check in p11.COMMAND_CHECKS}
        repository = checks["focused_repository"]
        coordinator = checks["focused_coordinator"]
        vertical = checks["vertical_smoke"]

        self.assertIn(
            "receipt_intelligence_repository::tests::", repository.command
        )
        self.assertIn(
            "receipt_intelligence_coordinator::tests::", coordinator.command
        )
        self.assertIn(
            (
                "receipt_intelligence_coordinator::tests::"
                "gmail_source_to_validated_order_review_is_atomic_and_catalog_free"
            ),
            vertical.command,
        )
        self.assertTrue(repository.reject_zero_tests)
        self.assertTrue(coordinator.reject_zero_tests)
        self.assertTrue(vertical.reject_zero_tests)
        self.assertNotIn("wardrobe-desktop", vertical.command)

    def test_valid_source_fixture_covers_every_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            validation = p11.validate_source(root)
        self.assertTrue(all(not messages for messages in validation.errors.values()))
        self.assertEqual(len(p11.SOURCE_REQUIREMENTS), validation.file_count)

    def test_source_and_migration_mutations_fail_closed(self) -> None:
        mutations = (
            (
                "P11-AI-001",
                "crates/wardrobe-platform/src/receipt_intelligence_provider.rs",
                '"tools": []',
            ),
            (
                "P11-REL-001",
                "crates/wardrobe-platform/src/receipt_intelligence_repository.rs",
                "reserve_receipt_intelligence",
            ),
            (
                "P11-GAT-001",
                "src-tauri/src/lib.rs",
                "receipt_intelligence_packaged_disabled_state_smoke",
            ),
            (
                "P11-UI-001",
                "apps/desktop-ui/src/ReceiptIntelligencePanel.tsx",
                "organization-level Zero Data",
            ),
        )
        for requirement, relative, marker in mutations:
            with self.subTest(requirement=requirement):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    write_valid_source(root)
                    path = root / relative
                    path.write_text(path.read_text().replace(marker, "weakened"))
                    validation = p11.validate_source(root)
                self.assertTrue(validation.errors[requirement])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            write(root / p11.MIGRATION_CHECKSUM_FILE, "0" * 64 + "\n")
            validation = p11.validate_source(root)
        self.assertTrue(validation.errors["P11-ATM-001"])
        self.assertTrue(validation.errors["P11-GAT-001"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evaluator = root / p11.EVALUATOR_FILE
            evaluator.write_text(evaluator.read_text() + "\nmutation\n")
            validation = p11.validate_source(root)
        self.assertTrue(validation.errors["P11-AI-001"])
        self.assertTrue(validation.errors["P11-GAT-001"])


class EvaluatorTests(unittest.TestCase):
    def test_nonzero_filtered_binary_tolerates_a_second_zero_test_binary(self) -> None:
        check = next(
            check for check in p11.COMMAND_CHECKS if check.name == "focused_tauri"
        )
        output = "\n".join(
            (
                "running 4 tests",
                *(f"test tests::{marker} ... ok" for marker in check.output_markers),
                "test result: ok. 4 passed; 0 failed",
                "running 0 tests",
                "test result: ok. 0 passed; 0 failed",
            )
        ).encode()
        result = CommandResult(
            returncode=0,
            output_sha256=hashlib.sha256(output).hexdigest(),
            output_bytes=len(output),
            duration_ms=1,
            captured_output=output,
        )
        self.assertIsNone(p11._command_error(check, result))

    def test_all_selected_requirements_emit_nineteen_evidence_records(self) -> None:
        def run(command: list[str], **_: object) -> CommandResult:
            check = next(
                check for check in p11.COMMAND_CHECKS if list(check.command) == command
            )
            return successful_result(check)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evidence = root / "evidence"
            with (
                mock.patch.object(
                    p11, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(p11, "run_bounded_command", side_effect=run),
            ):
                result = p11.evaluate(
                    root, evidence, set(p11.REQUIREMENT_IDS)
                )

            requirement_files = {
                path.stem
                for path in evidence.glob("P11-*.json")
                if path.name != p11.DIAGNOSTICS_NAME
            }
        self.assertEqual(0, result)
        self.assertEqual(set(p11.REQUIREMENT_IDS), requirement_files)

    def test_selected_requirements_emit_one_truthful_record_each(self) -> None:
        selected = {"P11-GAT-001", "P11-E2E-001"}

        def run(command: list[str], **_: object) -> CommandResult:
            check = next(
                check for check in p11.COMMAND_CHECKS if list(check.command) == command
            )
            return successful_result(check)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evidence = root / "evidence"
            with (
                mock.patch.object(
                    p11, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(
                    p11, "run_bounded_command", side_effect=run
                ) as runner,
            ):
                result = p11.evaluate(root, evidence, selected)

            self.assertEqual(0, result)
            expected_checks = {
                check.name
                for check in p11.COMMAND_CHECKS
                if check.requirements & selected
            }
            self.assertEqual(len(expected_checks), runner.call_count)
            self.assertEqual(
                {
                    "P11-GAT-001.json",
                    "P11-E2E-001.json",
                    p11.DIAGNOSTICS_NAME,
                },
                {path.name for path in evidence.iterdir()},
            )
            gate = json.loads((evidence / "P11-GAT-001.json").read_text())
            self.assertTrue(
                gate["details"]["public_summary"][
                    "packaged_disabled_state_coverage"
                ]
            )
            e2e = json.loads((evidence / "P11-E2E-001.json").read_text())
            summary = e2e["details"]["public_summary"]
            self.assertEqual("pass", e2e["status"])
            self.assertTrue(summary["vertical_smoke_coverage"])
            self.assertEqual("deferred", summary["live_openai_canary_status"])
            self.assertEqual(
                "deferred_not_passed",
                summary["live_openai_canary_acceptance_claim"],
            )
            self.assertEqual(
                0, summary["live_openai_canary_production_provider_calls"]
            )

    def test_live_canary_environment_is_ignored_and_secrets_are_stripped(self) -> None:
        selected = {"P11-AI-001"}
        environments: list[dict[str, str]] = []

        def run(command: list[str], **kwargs: object) -> CommandResult:
            environments.append(dict(kwargs["env"]))  # type: ignore[arg-type]
            check = next(
                check for check in p11.COMMAND_CHECKS if list(check.command) == command
            )
            return successful_result(check)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evidence = root / "evidence"
            with (
                mock.patch.object(
                    p11, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(p11, "run_bounded_command", side_effect=run),
                mock.patch.dict(
                    "os.environ",
                    {
                        "OPENAI_API_KEY": "secret",
                        "P11_LIVE_CANARY": "pass",
                        "P11_LIVE_CANARY_COMMAND": '["unsafe"]',
                    },
                ),
            ):
                result = p11.evaluate(root, evidence, selected)

            payload = json.loads((evidence / "P11-AI-001.json").read_text())
        self.assertEqual(0, result)
        self.assertTrue(environments)
        for environment in environments:
            self.assertNotIn("OPENAI_API_KEY", environment)
            self.assertNotIn("P11_LIVE_CANARY", environment)
            self.assertNotIn("P11_LIVE_CANARY_COMMAND", environment)
        self.assertEqual(
            "deferred",
            payload["details"]["public_summary"]["live_openai_canary_status"],
        )

    def test_missing_named_test_fails_and_removes_stale_evidence(self) -> None:
        selected = {"P11-CIT-001"}
        first = True

        def run(command: list[str], **_: object) -> CommandResult:
            nonlocal first
            check = next(
                check for check in p11.COMMAND_CHECKS if list(check.command) == command
            )
            result = successful_result(check)
            if first:
                first = False
                output = b"running 0 tests\ntest result: ok. 0 passed\n"
                return CommandResult(
                    returncode=0,
                    output_sha256=hashlib.sha256(output).hexdigest(),
                    output_bytes=len(output),
                    duration_ms=1,
                    captured_output=output,
                )
            return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evidence = root / "evidence"
            evidence.mkdir()
            stale = evidence / "P11-CIT-001.json"
            stale.write_text('{"status":"pass"}')
            with (
                mock.patch.object(
                    p11, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(p11, "run_bounded_command", side_effect=run),
            ):
                result = p11.evaluate(root, evidence, selected)
            diagnostics = json.loads(
                (evidence / p11.DIAGNOSTICS_NAME).read_text()
            )
        self.assertEqual(1, result)
        self.assertFalse(stale.exists())
        self.assertTrue(
            any("expected scope" in failure for failure in diagnostics["failures"])
        )


class DispatcherTests(unittest.TestCase):
    @mock.patch(
        "tools.evaluators.run.p11_receipt_intelligence.evaluate", return_value=0
    )
    def test_dispatches_exact_p11_requirement_ids(
        self, evaluate: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {"selected_requirement_ids": sorted(p11.REQUIREMENT_IDS)}
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
        evaluate.assert_called_once_with(ROOT, evidence, set(p11.REQUIREMENT_IDS))

    def test_unknown_p11_requirement_remains_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": ["P11-AI-999"]})
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
