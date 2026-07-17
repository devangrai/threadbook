from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p10_gmail
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def command_result(
    test_names: tuple[str, ...],
    returncode: int = 0,
    success_marker: str = "test result: ok",
) -> CommandResult:
    output = (
        f"running {len(test_names)} tests\n"
        + "".join(f"test tests::{name} ... ok\n" for name in test_names)
        + f"{success_marker}. {len(test_names)} passed; 0 failed\n"
    ).encode()
    return CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


def write_valid_source(root: Path) -> None:
    migration = """ALTER TABLE gmail_connector_settings RENAME TO gmail_connector_settings_v1;
CREATE TABLE gmail_connector_settings(discovery_kind TEXT, discovery_value TEXT);
INSERT INTO gmail_connector_settings
SELECT
    singleton, oauth_client_id, 'label', label_name, page_size, max_pages,
    max_unique_messages, max_total_raw_bytes, updated_at_ms
FROM gmail_connector_settings_v1;
ALTER TABLE gmail_scopes ADD COLUMN discovery_kind TEXT DEFAULT 'label';
UPDATE gmail_scopes
SET discovery_value = label_id
WHERE discovery_kind = 'label';
CREATE TABLE gmail_request_reservations(request_id TEXT PRIMARY KEY);
CREATE TRIGGER gmail_request_reservations_no_update BEFORE UPDATE
ON gmail_request_reservations BEGIN SELECT RAISE(ABORT, 'immutable'); END;
CREATE TRIGGER gmail_request_reservations_no_delete BEFORE DELETE
ON gmail_request_reservations BEGIN SELECT RAISE(ABORT, 'durable'); END;
"""
    files = {
        "crates/wardrobe-core/src/gmail_connector.rs": """
const MAX_GMAIL_QUERY_BYTES: usize = 2048;
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum GmailDiscoveryScopeV2 {
    Search { query: String },
    Label { label_name: String },
}
struct SaveGmailSettingsV2Request;
struct GetGmailConnectorV2Response;
fn validate(value: &str) {
    value.len() > MAX_GMAIL_QUERY_BYTES;
    value.chars().any(char::is_control);
}
""",
        "crates/wardrobe-core/src/bindings.rs": """
GmailDiscoveryScopeV2::decl();
SaveGmailSettingsV2Request::decl();
GetGmailConnectorV2Response::decl();
""",
        "crates/wardrobe-core/src/service.rs": """
fn save_gmail_settings_v2() {
    response.settings.discovery_scope != request.discovery_scope;
}
""",
        "crates/wardrobe-core/tests/gmail_connector_contracts.rs": """
#[test]
fn gmail_v2_discovery_scopes_have_exact_strict_tagged_wire_shapes() {
    GmailDiscoveryScopeV2; serde_json; "search"; "label"; "label_name";
}
fn gmail_v2_requests_settings_and_responses_reject_unknown_fields() {
    SaveGmailSettingsV2Request; GetGmailConnectorV2Response; "extra";
}
fn gmail_search_queries_use_utf8_byte_boundaries_and_reject_controls() {
    MAX_GMAIL_QUERY_BYTES; GmailQuery; control;
}
fn gmail_search_query_whitespace_is_preserved_without_normalization() {
    query; serde_json; validate;
}
fn gmail_v2_schema_versions_are_strict_at_decode_and_validation() {
    schema_version; SaveGmailSettingsV2Request; SchemaVersion;
}
""",
        "crates/wardrobe-platform/src/database.rs": """
fn migration_0015_preserves_populated_v14_gmail_state_and_reopens() {
    "discovery_kind"; "history_id"; "credential_locator";
    "account_key"; "label_id"; "connected";
}
""",
        p10_gmail.MIGRATION_FILE: migration,
        p10_gmail.MIGRATION_CHECKSUM_FILE: (
            hashlib.sha256(migration.encode()).hexdigest() + "\n"
        ),
        "crates/wardrobe-platform/src/gmail_sync.rs": """
fn expired_history_reconciles_listed_union_known_unlisted_once() {
    assert!(true);
}
fn search_pagination_and_repeated_revisions_publish_once_to_real_repository() {
    assert!(true);
}
fn search_exhausts_pages_deduplicates_and_ignores_known_unlisted_sources() {
    assert!(true);
}
fn search_limit_and_raw_fetch_failures_preserve_real_repository_atomically() {
    assert!(true);
}
fn search_boundaries_and_late_raw_failure_never_commit() { assert!(true); }
fn search_runs_a_complete_scan_every_time_and_retains_unlisted_known_messages() {
    assert!(true);
}
fn search_accepts_exact_byte_and_call_limits_and_rejects_one_over_atomically() {
    assert!(true);
}
fn search_rejects_token_cycles_timeouts_and_vanished_listed_messages_atomically() {
    assert!(true);
}
fn search_persistence_failure_does_not_publish_a_batch() { assert!(true); }
""",
        "crates/wardrobe-platform/src/gmail_connector.rs": """
const GOOGLE_OAUTH_SCOPE: &str = "openid https://www.googleapis.com/auth/gmail.readonly";
const PARSER_REVISION: &str = "parser";
const MATERIALIZATION_REVISION: &str = "materializer";
fn scope_fingerprint(
    account_key: &str,
    discovery_kind: &str,
    discovery_value: &str,
    storage_scope_key: &str,
) {
    if discovery_kind == "label" { storage_scope_key; }
    "gmail-search-scope-v2"; GOOGLE_OAUTH_SCOPE; PARSER_REVISION;
    MATERIALIZATION_REVISION; account_key; discovery_value;
}
fn gmail_scope_identity_is_versioned_and_byte_exact() {
    scope_fingerprint; "account"; "query"; GOOGLE_OAUTH_SCOPE;
}
fn gmail_authority_is_exact_and_read_only() {
    GOOGLE_OAUTH_SCOPE; "gmail.readonly"; Method::GET; "users/me/messages";
}
fn startup_reopens_and_discards_interrupted_sync_without_losing_evidence() {
    assert!(true);
}
fn completed_sync_replay_is_write_free_and_cross_command_reuse_conflicts() {
    assert!(true);
}
fn terminal_connect_replay_is_provider_keychain_and_write_free() {
    assert!(true);
}
fn cleaned_up_request_reservation_conflicts_after_restart() {
    assert!(true);
}
fn reserve_request<T: DeserializeOwned>() {
    gmail_request_reservations; command_receipts;
    RequestReservation::Replayed; RequestReservation::Pending;
    RequestReservation::New;
}
""",
        "crates/wardrobe-platform/src/gmail_repository.rs": """
fn initialize_gmail_scope_v2() { discovery_kind; discovery_value; }
fn interrupted_publication_is_removed_on_reopen_and_retry_succeeds() {
    assert!(true);
}
fn committed_cleanup_failure_returns_success_and_recovers_manifest() {
    assert!(true);
}
fn failed_publication_never_removes_preexisting_same_hash_blob() {
    assert!(true);
}
fn first_scope_and_account_roll_back_with_failed_publication() {
    assert!(true);
}
fn later_search_scan_retains_sources_absent_from_current_results() {
    assert!(true);
}
fn label_removal_does_not_hide_overlapping_search_scope() {
    assert!(true);
}
""",
        "crates/wardrobe-platform/src/gmail_http.rs": """
pub const GOOGLE_OAUTH_SCOPE: &str = "openid https://www.googleapis.com/auth/gmail.readonly";
fn authorize() { url.append_pair("scope", GOOGLE_OAUTH_SCOPE); }
fn calls() {
    let url = gmail_url(endpoints, "users/me/labels");
    client.request_json(Method::GET, url);
    let url = gmail_url(endpoints, "users/me/profile");
    client.request_json(Method::GET, url);
    let mut url = gmail_url(endpoints, "users/me/messages");
    client.request_json(Method::GET, url);
    let mut url = gmail_url(endpoints, &format!("users/me/messages/{message_id}"));
    client.request_json(Method::GET, url);
    let mut url = gmail_url(endpoints, "users/me/history");
    client.request_json(Method::GET, url);
}
fn gmail_authority_is_exact_and_read_only() {
    GOOGLE_OAUTH_SCOPE; "gmail.readonly"; Method::GET; "users/me/messages";
}
fn local_tls_drives_token_userinfo_and_gmail_adapter() {
    assert!(true);
}
fn discovery_modes_reject_cross_mode_listing_and_history_calls() {
    assert!(true);
}
""",
        "crates/wardrobe-platform/src/blob.rs": """
fn operation_rollback_serializes_same_hash_importer_before_removal() {
    assert!(true);
}
""",
        "crates/wardrobe-platform/src/deletion_repository.rs": """
fn gmail_scope_availability_rows_are_guarded_and_planned_with_membership() {
    assert!(true);
}
""",
        "apps/desktop-ui/src/GmailConnectorSettings.tsx": """
const labels = [
  "Gmail search",
  "Existing label",
  "completely reconciles every result",
  "Previously imported messages stay in Wardrobe",
  "Sync bounds",
];
""",
        "apps/desktop-ui/src/GmailConnectorSettings.test.tsx": """
it("saves settings before enabling the explicit connect action", () => {});
it("preserves exact search text through keyboard mode changes and save", () => {});
it("renders migrated label settings as the distinct label-history mode", () => {});
""",
        "apps/desktop-ui/src/gmail-connector-bridge.test.ts": """
it("uses only the five typed production commands", () => {});
it("sends exact search query bytes without UI normalization", () => {});
""",
        "apps/desktop-ui/e2e/gmail-connector.spec.ts": """
// Fixture-only UI smoke: backend contract acceptance is covered outside Vite.
test("Gmail settings UI persists through reload and retains imported evidence", () => {
  "Enable personal live"; page.reload(); "Disconnect"; AxeBuilder;
});
""",
        "apps/desktop-ui/src/generated/contracts.ts": """
type GetGmailConnectorV2Request = {};
type SaveGmailSettingsV2Request = {};
type GmailDiscoveryScopeV2 = {};
const max_total_raw_bytes = 1;
""",
        "src-tauri/src/lib.rs": """
fn get_gmail_connector_v2() {
    handle_get_gmail_connector_v2();
}
fn save_gmail_settings_v2() {
    handle_save_gmail_settings_v2();
}
generate_handler![get_gmail_connector_v2, save_gmail_settings_v2];
""",
        "src-tauri/capabilities/main.json": """
{"permissions":["allow-get-gmail-connector-v2","allow-save-gmail-settings-v2"]}
""",
        "src-tauri/permissions/autogenerated/get_gmail_connector_v2.toml": """
commands.allow = ["get_gmail_connector_v2"]
""",
        "src-tauri/permissions/autogenerated/save_gmail_settings_v2.toml": """
commands.allow = ["save_gmail_settings_v2"]
""",
    }
    for relative, content in files.items():
        write(root / relative, content)


def packet_validation() -> p10_gmail.PacketValidation:
    return p10_gmail.PacketValidation(
        (),
        "a" * 64,
        tuple(sorted(p10_gmail.APPROVED_PACKETS)),
    )


class PacketAndSourceTests(unittest.TestCase):
    def test_current_first_approved_packet_is_valid(self) -> None:
        validation = p10_gmail.validate_packet(ROOT)
        self.assertEqual((), validation.errors)
        self.assertEqual(64, len(validation.sha256))

    def test_all_approved_packet_hashes_and_decisions_are_valid(self) -> None:
        for run_id in p10_gmail.APPROVED_PACKETS:
            with self.subTest(run_id=run_id):
                validation = p10_gmail.validate_packet(ROOT, run_id)
                self.assertEqual((), validation.errors)
                self.assertEqual((run_id,), validation.run_ids)

    def test_each_approved_packet_mutation_is_rejected(self) -> None:
        for run_id, packet in p10_gmail.APPROVED_PACKETS.items():
            with self.subTest(run_id=run_id):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    for relative in (*packet.expected_hashes, packet.state_file):
                        destination = root / relative
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(ROOT / relative, destination)
                    proposal = root / packet.packet_dir / "proposal.md"
                    proposal.write_text(
                        proposal.read_text(encoding="utf-8") + "\nmutation\n",
                        encoding="utf-8",
                    )
                    validation = p10_gmail.validate_packet(root, run_id)
                self.assertTrue(
                    any("proposal.md" in error for error in validation.errors)
                )

    def test_selected_requirements_validate_only_their_approved_packets(self) -> None:
        validation = p10_gmail.validate_packets(
            ROOT,
            {"P10-GML-004", "P10-GML-010", "P10-UI-001"},
        )
        self.assertEqual((), validation.errors)
        self.assertEqual(
            (p10_gmail.PACKET_2_RUN_ID, p10_gmail.PACKET_3_RUN_ID),
            validation.run_ids,
        )

    def test_valid_source_fixture_covers_all_approved_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            validation = p10_gmail.validate_source(root)
        self.assertTrue(all(not messages for messages in validation.errors.values()))
        self.assertEqual(len(p10_gmail.SOURCE_REQUIREMENTS), validation.file_count)

    def test_missing_or_weakened_artifacts_fail_the_owned_requirement(self) -> None:
        mutations = {
            "P10-GML-001": (
                "crates/wardrobe-core/tests/gmail_connector_contracts.rs",
                "gmail_v2_discovery_scopes_have_exact_strict_tagged_wire_shapes",
            ),
            "P10-GML-002": (p10_gmail.MIGRATION_FILE, "'label'"),
            "P10-GML-003": (
                "crates/wardrobe-platform/src/gmail_connector.rs",
                "gmail-search-scope-v2",
            ),
            "P10-GML-004": (
                "crates/wardrobe-platform/src/gmail_http.rs",
                "local_tls_drives_token_userinfo_and_gmail_adapter",
            ),
            "P10-GML-005": (
                "crates/wardrobe-platform/src/gmail_sync.rs",
                "search_limit_and_raw_fetch_failures_preserve_real_repository_atomically",
            ),
            "P10-GML-006": (
                "crates/wardrobe-platform/src/gmail_sync.rs",
                "search_pagination_and_repeated_revisions_publish_once_to_real_repository",
            ),
            "P10-GML-007": (
                "crates/wardrobe-platform/src/gmail_repository.rs",
                "later_search_scan_retains_sources_absent_from_current_results",
            ),
            "P10-GML-008": (
                "crates/wardrobe-platform/src/gmail_connector.rs",
                "startup_reopens_and_discards_interrupted_sync_without_losing_evidence",
            ),
            "P10-GML-009": (
                "crates/wardrobe-platform/src/gmail_repository.rs",
                "label_removal_does_not_hide_overlapping_search_scope",
            ),
            "P10-GML-010": (
                "crates/wardrobe-platform/src/gmail_connector.rs",
                "completed_sync_replay_is_write_free_and_cross_command_reuse_conflicts",
            ),
            "P10-AUT-001": (
                "crates/wardrobe-platform/src/gmail_http.rs",
                "Method::GET",
            ),
            "P10-UI-001": (
                "apps/desktop-ui/src/GmailConnectorSettings.tsx",
                "completely reconciles every result",
            ),
        }
        for requirement, (relative, marker) in mutations.items():
            with self.subTest(requirement=requirement):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    write_valid_source(root)
                    path = root / relative
                    path.write_text(
                        path.read_text(encoding="utf-8").replace(marker, "weakened"),
                        encoding="utf-8",
                    )
                    validation = p10_gmail.validate_source(root)
                self.assertTrue(validation.errors[requirement])

    def test_reservation_and_fixture_scope_mutations_fail_closed(self) -> None:
        mutations = (
            (
                "P10-GML-010",
                p10_gmail.MIGRATION_FILE,
                "gmail_request_reservations_no_delete",
            ),
            (
                "P10-GML-010",
                "crates/wardrobe-platform/src/gmail_connector.rs",
                "cleaned_up_request_reservation_conflicts_after_restart",
            ),
            (
                "P10-UI-001",
                "apps/desktop-ui/e2e/gmail-connector.spec.ts",
                "Fixture-only UI smoke",
            ),
        )
        for requirement, relative, marker in mutations:
            with self.subTest(requirement=requirement, marker=marker):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    write_valid_source(root)
                    path = root / relative
                    path.write_text(
                        path.read_text(encoding="utf-8").replace(marker, "weakened"),
                        encoding="utf-8",
                    )
                    if relative == p10_gmail.MIGRATION_FILE:
                        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
                        write(root / p10_gmail.MIGRATION_CHECKSUM_FILE, checksum + "\n")
                    validation = p10_gmail.validate_source(root)
                self.assertTrue(validation.errors[requirement])


class EvaluatorTests(unittest.TestCase):
    def test_success_emits_only_selected_truthful_local_evidence(self) -> None:
        selected = {"P10-GML-001", "P10-AUT-001"}

        def run(command: list[str], **_: object) -> CommandResult:
            check = next(
                check
                for check in p10_gmail.COMMAND_CHECKS
                if list(check.command) == command
            )
            return command_result(
                check.test_names,
                success_marker=check.success_marker,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evidence = root / "evidence"
            with (
                mock.patch.object(
                    p10_gmail, "validate_packets", return_value=packet_validation()
                ),
                mock.patch.object(
                    p10_gmail, "run_bounded_command", side_effect=run
                ) as runner,
            ):
                result = p10_gmail.evaluate(root, evidence, selected)

            self.assertEqual(0, result)
            self.assertEqual(2, runner.call_count)
            self.assertEqual(
                {"P10-GML-001.json", "P10-AUT-001.json", p10_gmail.DIAGNOSTICS_NAME},
                {path.name for path in evidence.iterdir()},
            )
            payload = json.loads((evidence / "P10-AUT-001.json").read_text())
            summary = payload["details"]["public_summary"]
            self.assertEqual("pass", payload["status"])
            self.assertFalse(summary["live_gmail_access"])
            self.assertFalse(summary["external_credentials_used"])
            self.assertEqual(
                "focused_local_contracts_and_tests", summary["verification_scope"]
            )

    def test_packet_three_evidence_is_run_scoped_and_disclaims_packaged_tauri(
        self,
    ) -> None:
        selected = {"P10-GML-010", "P10-UI-001"}

        def run(command: list[str], **_: object) -> CommandResult:
            check = next(
                check
                for check in p10_gmail.COMMAND_CHECKS
                if list(check.command) == command
            )
            return command_result(
                check.test_names,
                success_marker=check.success_marker,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evidence = root / "evidence"
            with (
                mock.patch.object(
                    p10_gmail, "validate_packets", return_value=packet_validation()
                ),
                mock.patch.object(p10_gmail, "run_bounded_command", side_effect=run),
            ):
                result = p10_gmail.evaluate(root, evidence, selected)

            self.assertEqual(0, result)
            self.assertEqual(
                {
                    "P10-GML-010.json",
                    "P10-UI-001.json",
                    p10_gmail.DIAGNOSTICS_NAME,
                },
                {path.name for path in evidence.iterdir()},
            )
            for requirement in selected:
                payload = json.loads((evidence / f"{requirement}.json").read_text())
                self.assertEqual(
                    p10_gmail.PACKET_3_RUN_ID,
                    payload["details"]["approved_packet_run_id"],
                )
                self.assertFalse(
                    payload["details"]["public_summary"]["packaged_tauri_coverage"]
                )
            ui_summary = json.loads((evidence / "P10-UI-001.json").read_text())[
                "details"
            ]["public_summary"]
            self.assertEqual(
                "vite_transport_fixture_only",
                ui_summary["playwright_scope"],
            )

    def test_missing_named_test_in_successful_output_fails_closed(self) -> None:
        selected = {"P10-GML-010"}
        first = True

        def run(command: list[str], **_: object) -> CommandResult:
            nonlocal first
            check = next(
                check
                for check in p10_gmail.COMMAND_CHECKS
                if list(check.command) == command
            )
            names = check.test_names
            if first:
                first = False
                names = ()
            return command_result(names, success_marker=check.success_marker)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evidence = root / "evidence"
            with (
                mock.patch.object(
                    p10_gmail, "validate_packets", return_value=packet_validation()
                ),
                mock.patch.object(p10_gmail, "run_bounded_command", side_effect=run),
            ):
                result = p10_gmail.evaluate(root, evidence, selected)

            diagnostics = json.loads(
                (evidence / p10_gmail.DIAGNOSTICS_NAME).read_text()
            )
            self.assertEqual(1, result)
            self.assertFalse((evidence / "P10-GML-010.json").exists())
            self.assertTrue(
                any("did not execute" in failure for failure in diagnostics["failures"])
            )

    def test_zero_test_success_fails_and_removes_stale_pass(self) -> None:
        output = b"running 0 tests\ntest result: ok. 0 passed\n"
        empty_result = CommandResult(
            returncode=0,
            output_sha256=hashlib.sha256(output).hexdigest(),
            output_bytes=len(output),
            duration_ms=1,
            captured_output=output,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_source(root)
            evidence = root / "evidence"
            evidence.mkdir()
            stale = evidence / "P10-GML-001.json"
            stale.write_text('{"status":"pass"}')
            with (
                mock.patch.object(
                    p10_gmail, "validate_packets", return_value=packet_validation()
                ),
                mock.patch.object(
                    p10_gmail, "run_bounded_command", return_value=empty_result
                ),
            ):
                result = p10_gmail.evaluate(root, evidence, {"P10-GML-001"})

            diagnostics = json.loads(
                (evidence / p10_gmail.DIAGNOSTICS_NAME).read_text()
            )
        self.assertEqual(1, result)
        self.assertFalse(stale.exists())
        self.assertEqual("fail", diagnostics["status"])
        self.assertFalse(diagnostics["live_gmail_access"])


class DispatcherTests(unittest.TestCase):
    @mock.patch("tools.evaluators.run.p10_gmail.evaluate", return_value=0)
    def test_dispatches_exact_p10a_packet_ids(self, evaluate: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {"selected_requirement_ids": sorted(p10_gmail.REQUIREMENT_IDS)}
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
        evaluate.assert_called_once_with(ROOT, evidence, set(p10_gmail.REQUIREMENT_IDS))

    def test_dispatches_packet_two_and_three_ids_without_cross_claiming(self) -> None:
        for selected in (
            p10_gmail.PACKET_2_REQUIREMENT_IDS,
            p10_gmail.PACKET_3_REQUIREMENT_IDS,
        ):
            with self.subTest(selected=sorted(selected)):
                with tempfile.TemporaryDirectory() as directory:
                    run_dir = Path(directory) / "run"
                    evidence = Path(directory) / "evidence"
                    run_dir.mkdir()
                    (run_dir / "requirements.json").write_text(
                        json.dumps({"selected_requirement_ids": sorted(selected)})
                    )
                    with (
                        mock.patch.dict(
                            "os.environ",
                            {
                                "HARNESS_RUN_DIR": str(run_dir),
                                "HARNESS_EVIDENCE_DIR": str(evidence),
                            },
                            clear=False,
                        ),
                        mock.patch(
                            "tools.evaluators.run.p10_gmail.evaluate",
                            return_value=0,
                        ) as evaluate,
                    ):
                        result = evaluator_run.main()
                self.assertEqual(0, result)
                evaluate.assert_called_once_with(ROOT, evidence, set(selected))

    def test_unknown_p10_requirement_remains_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory) / "run"
            evidence = Path(directory) / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps({"selected_requirement_ids": ["P10-GML-999"]})
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
