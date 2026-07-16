from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import harness  # noqa: E402


class EarsValidationTests(unittest.TestCase):
    def requirement(self, requirement_type: str, statement: str) -> harness.Requirement:
        return harness.Requirement(
            requirement_id="P00-TST-001",
            title="Test requirement",
            requirement_type=requirement_type,
            statement=statement,
            verification="Unit test.",
            source="test",
            line=1,
        )

    def test_accepts_each_ears_form(self) -> None:
        examples = {
            "Ubiquitous": "The system shall preserve evidence.",
            "Event-driven": (
                "When a source is imported, the system shall preserve evidence."
            ),
            "State-driven": (
                "While the network is unavailable, the system shall remain usable."
            ),
            "Optional": (
                "Where remote inference is enabled, the system shall request consent."
            ),
            "Unwanted": (
                "If a job is interrupted, the system shall resume safely."
            ),
        }
        for requirement_type, statement in examples.items():
            with self.subTest(requirement_type=requirement_type):
                self.assertEqual(
                    [],
                    harness.validate_ears(
                        self.requirement(requirement_type, statement)
                    ),
                )

    def test_rejects_non_ears_statement(self) -> None:
        errors = harness.validate_ears(
            self.requirement("Event-driven", "Evidence should be stored.")
        )
        self.assertTrue(errors)


class SpecParsingTests(unittest.TestCase):
    def test_parses_machine_readable_requirement(self) -> None:
        content = """# Spec

### P00-TST-001: Preserve evidence
- Type: Event-driven
- Statement: When evidence arrives, the system shall preserve it.
- Verification: Unit test.
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "P00-test.md"
            path.write_text(content, encoding="utf-8")
            original_root = harness.ROOT
            try:
                harness.ROOT = Path(directory)
                requirements = harness.parse_spec(path)
            finally:
                harness.ROOT = original_root
        self.assertEqual(1, len(requirements))
        self.assertEqual("P00-TST-001", requirements[0].requirement_id)

    def test_parses_numeric_requirement_category(self) -> None:
        content = """# Spec

### SYS-A11Y-001: Support accessible workflows
- Type: Ubiquitous
- Statement: The system shall support accessible workflows.
- Verification: Accessibility test.
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "system.md"
            path.write_text(content, encoding="utf-8")
            original_root = harness.ROOT
            try:
                harness.ROOT = Path(directory)
                requirements = harness.parse_spec(path)
            finally:
                harness.ROOT = original_root
        self.assertEqual(["SYS-A11Y-001"], [item.requirement_id for item in requirements])


class RequirementSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requirements = [
            harness.Requirement(
                requirement_id=f"P00-TST-00{index}",
                title=f"Requirement {index}",
                requirement_type="Ubiquitous",
                statement="The system shall preserve evidence.",
                verification="Unit test.",
                source="test",
                line=index,
            )
            for index in (1, 2)
        ]

    def test_defaults_to_all_phase_requirements(self) -> None:
        selected = harness.select_phase_requirements(
            "P00", self.requirements, None
        )
        self.assertEqual(self.requirements, selected)

    def test_selects_requested_requirements(self) -> None:
        selected = harness.select_phase_requirements(
            "P00", self.requirements, ["p00-tst-002"]
        )
        self.assertEqual(["P00-TST-002"], [item.requirement_id for item in selected])

    def test_rejects_unknown_requirement(self) -> None:
        with self.assertRaises(harness.HarnessError):
            harness.select_phase_requirements(
                "P00", self.requirements, ["P00-TST-999"]
            )


class EvidenceValidationTests(unittest.TestCase):
    def test_reports_missing_required_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "evidence").mkdir()
            errors = harness.validate_evidence(
                path,
                [{"id": "P00-TST-001", "evidence_required": True}],
            )
        self.assertEqual(["missing evidence for P00-TST-001"], errors)

    def test_accepts_complete_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            evidence_dir = path / "evidence"
            evidence_dir.mkdir()
            harness.write_json(
                evidence_dir / "P00-TST-001.json",
                {
                    "requirement_id": "P00-TST-001",
                    "status": "pass",
                    "test": "example::passes",
                    "recorded_at": "2026-07-14T20:00:00Z",
                },
            )
            errors = harness.validate_evidence(
                path,
                [{"id": "P00-TST-001", "evidence_required": True}],
            )
        self.assertEqual([], errors)

    def test_accepts_atomic_routing_evidence_and_rejects_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            evidence_dir = path / "evidence"
            routing = evidence_dir / harness.ATOMIC_EVIDENCE_DIRECTORY
            routing.mkdir(parents=True)
            payload = {
                "requirement_id": "P09-ACC-001",
                "status": "pass",
                "test": "acceptance::passes",
                "recorded_at": "2026-07-16T20:00:00Z",
            }
            harness.write_json(routing / "P09-ACC-001.json", payload)
            harness.write_json(
                routing / "p09-acceptance-evaluator.json",
                {
                    "schema_version": 1,
                    "status": "pass",
                    "failures": [],
                },
            )
            requirements = [
                {"id": "P09-ACC-001", "evidence_required": True}
            ]

            self.assertEqual(
                [],
                harness.validate_evidence(path, requirements),
            )

            harness.write_json(
                evidence_dir / "P09-ACC-001.json",
                payload,
            )
            errors = harness.validate_evidence(path, requirements)

        self.assertTrue(
            any("ambiguous evidence locations" in error for error in errors)
        )

    def test_atomic_routing_rejects_symlinks_unexpected_files_and_no_diagnostic(
        self,
    ) -> None:
        requirements = [
            {"id": "P09-ACC-001", "evidence_required": True}
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            routing = (
                path
                / "evidence"
                / harness.ATOMIC_EVIDENCE_DIRECTORY
            )
            routing.mkdir(parents=True)
            target = path / "fake.json"
            harness.write_json(
                target,
                {
                    "requirement_id": "P09-ACC-001",
                    "status": "pass",
                    "test": "forged",
                    "recorded_at": "2026-07-16T20:00:00Z",
                },
            )
            (routing / "P09-ACC-001.json").symlink_to(target)
            (routing / "unexpected.json").write_text(
                "{}",
                encoding="utf-8",
            )

            errors = harness.validate_evidence(path, requirements)

        self.assertTrue(
            any("inventory is not exact" in error for error in errors)
        )
        self.assertTrue(
            any("entry is unsafe" in error for error in errors)
        )
        self.assertTrue(
            any("passing diagnostic is missing" in error for error in errors)
        )

    def test_p09_acceptance_rejects_loose_direct_pass_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            evidence = path / "evidence"
            evidence.mkdir()
            harness.write_json(
                evidence / "P09-ACC-001.json",
                {
                    "requirement_id": "P09-ACC-001",
                    "status": "pass",
                    "test": "forged::direct",
                    "recorded_at": "2026-07-16T20:00:00Z",
                },
            )

            errors = harness.validate_evidence(
                path,
                [{"id": "P09-ACC-001", "evidence_required": True}],
            )

        self.assertIn(
            "atomic P09 acceptance evidence directory is missing",
            errors,
        )

    def test_accepts_explicit_disabled_deferred_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            evidence_dir = path / "evidence"
            evidence_dir.mkdir()
            harness.write_json(
                evidence_dir / "P00-TST-001.json",
                {
                    "requirement_id": "P00-TST-001",
                    "status": "deferred",
                    "test": "external_credential_gate",
                    "recorded_at": "2026-07-14T20:00:00Z",
                    "details": {
                        "public_summary": {
                            "feature_enabled": False,
                            "acceptance_claim": "deferred_not_passed",
                            "deferred_limitation": "credential_not_supplied",
                        }
                    },
                },
            )
            errors = harness.validate_evidence(
                path,
                [{"id": "P00-TST-001", "evidence_required": True}],
            )
        self.assertEqual([], errors)

    def test_rejects_deferred_evidence_that_looks_enabled_or_passed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            evidence_dir = path / "evidence"
            evidence_dir.mkdir()
            harness.write_json(
                evidence_dir / "P00-TST-001.json",
                {
                    "requirement_id": "P00-TST-001",
                    "status": "deferred",
                    "test": "external_credential_gate",
                    "recorded_at": "2026-07-14T20:00:00Z",
                    "details": {
                        "public_summary": {
                            "feature_enabled": True,
                            "acceptance_claim": "pass",
                            "deferred_limitation": "credential_not_supplied",
                        }
                    },
                },
            )
            errors = harness.validate_evidence(
                path,
                [{"id": "P00-TST-001", "evidence_required": True}],
            )
        self.assertTrue(any("deferred evidence" in error for error in errors))


class ProposalReviewTests(unittest.TestCase):
    def test_detects_proposal_change_after_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            proposal = path / "proposal.md"
            proposal.write_text("approved", encoding="utf-8")
            state = {
                "review": {
                    "proposal_hash": harness.sha256_file(proposal),
                }
            }
            harness.verify_approved_proposal(path, state)
            proposal.write_text("changed", encoding="utf-8")
            with self.assertRaises(harness.HarnessError):
                harness.verify_approved_proposal(path, state)


class HarnessLifecycleTests(unittest.TestCase):
    def test_p09_acceptance_selects_exactly_its_evaluator_sidecar(self) -> None:
        self.assertEqual(
            (Path("tools/evaluators/p09_acceptance.py"),),
            harness.evaluator_sidecars(
                ["P09-DIA-001", "P09-ACC-001"]
            ),
        )

    def test_p09_offline_keeps_its_owned_evaluator_sidecar(self) -> None:
        self.assertEqual(
            (Path("tools/evaluators/p09_offline.py"),),
            harness.evaluator_sidecars(["P09-OFF-001"]),
        )
        self.assertEqual((), harness.evaluator_sidecars(["P09-DIA-001"]))

    def test_evaluate_suppresses_make_test_evidence_before_acceptance_sidecar(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=harness.ROOT) as directory:
            path = Path(directory) / "P09/run"
            path.mkdir(parents=True)
            state = {
                "phase": "P09",
                "run_id": "run",
                "status": "BUILT",
                "evaluate_command": ["make", "test"],
                "build": {"source_fingerprint": "fingerprint"},
            }
            snapshot = {
                "selected_requirement_ids": ["P09-ACC-001"],
                "requirements": [],
            }
            completed = harness.subprocess.CompletedProcess(
                ["command"],
                0,
                stdout="ok",
            )
            inherited_evidence = {
                "HARNESS_RUN_DIR": "inherited-run",
                "HARNESS_EVIDENCE_DIR": "inherited-evidence",
                "HARNESS_PHASE": "inherited-phase",
                "HARNESS_RUN_ID": "inherited-id",
            }
            with (
                mock.patch.object(harness, "run_path", return_value=path),
                mock.patch.object(harness, "load_state", return_value=state),
                mock.patch.object(harness, "verify_spec_snapshot"),
                mock.patch.object(harness, "verify_approved_proposal"),
                mock.patch.object(
                    harness,
                    "source_fingerprint",
                    return_value="fingerprint",
                ),
                mock.patch.object(harness, "load_json", return_value=snapshot),
                mock.patch.object(
                    harness,
                    "validate_evidence",
                    return_value=[],
                ),
                mock.patch.object(
                    harness,
                    "publish_acceptance_manifest",
                    return_value=(
                        harness.ROOT / "artifacts/accepted/P09/run.json"
                    ),
                ),
                mock.patch.object(
                    harness.subprocess,
                    "run",
                    return_value=completed,
                ) as run,
                mock.patch.dict(
                    harness.os.environ,
                    inherited_evidence,
                ),
            ):
                harness.command_evaluate(
                    mock.Mock(phase="P09", run_id="run")
                )

        self.assertEqual(2, run.call_count)
        make_test, acceptance_sidecar = run.call_args_list
        self.assertEqual(["make", "test"], make_test.args[0])
        for key in inherited_evidence:
            self.assertNotIn(key, make_test.kwargs["env"])
        self.assertEqual(
            [
                sys.executable,
                str(
                    harness.ROOT
                    / "tools/evaluators/p09_acceptance.py"
                ),
            ],
            acceptance_sidecar.args[0],
        )
        self.assertEqual(
            str(path),
            acceptance_sidecar.kwargs["env"]["HARNESS_RUN_DIR"],
        )
        self.assertEqual(
            str(path / "evidence"),
            acceptance_sidecar.kwargs["env"]["HARNESS_EVIDENCE_DIR"],
        )

    def test_evaluated_packet_can_be_rebuilt(self) -> None:
        self.assertIn("EVALUATED", harness.BUILDABLE_STATES)
        self.assertNotIn("GENERATED", harness.BUILDABLE_STATES)
        self.assertNotIn("REJECTED", harness.BUILDABLE_STATES)

    def test_build_cleanup_removes_stale_evidence_and_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_path = root / "artifacts/harness/P00/test-run"
            evidence_dir = run_path / "evidence"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "P00-TST-001.json").write_text(
                "stale",
                encoding="utf-8",
            )
            accepted_path = (
                root / "artifacts/accepted/P00/test-run.json"
            )
            accepted_path.parent.mkdir(parents=True)
            accepted_path.write_text("stale", encoding="utf-8")

            original_accepted_path = harness.ACCEPTED_PATH
            try:
                harness.ACCEPTED_PATH = root / "artifacts/accepted"
                harness.clear_build_outputs(run_path)
            finally:
                harness.ACCEPTED_PATH = original_accepted_path

            self.assertEqual([], list(evidence_dir.iterdir()))
            self.assertFalse(accepted_path.exists())

    def test_accepted_outputs_do_not_change_source_fingerprint(self) -> None:
        self.assertFalse(
            harness.is_source_fingerprint_path(
                Path("artifacts/accepted/P00/run.json")
            )
        )
        self.assertTrue(
            harness.is_source_fingerprint_path(Path("src-tauri/src/lib.rs"))
        )


class AcceptanceManifestTests(unittest.TestCase):
    def test_manifest_keeps_public_summary_and_excludes_raw_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_path = Path(directory) / "P00/test-run"
            evidence_dir = run_path / "evidence"
            evidence_dir.mkdir(parents=True)
            evidence_path = evidence_dir / "P00-TST-001.json"
            harness.write_json(
                evidence_path,
                {
                    "requirement_id": "P00-TST-001",
                    "status": "pass",
                    "test": "example::passes",
                    "recorded_at": "2026-07-14T21:00:00Z",
                    "details": {
                        "private_payload": "do-not-publish",
                        "public_summary": {
                            "target_architecture": "arm64",
                            "finding_count": 0,
                            "remote_navigation_denied": True,
                            "blocked_requirements": ["P00-PKG-001"],
                        },
                    },
                },
            )
            state = {
                "phase": "P00",
                "run_id": "test-run",
                "selected_requirement_ids": ["P00-TST-001"],
                "build": {"source_fingerprint": "abc123"},
                "review": {"proposal_hash": "proposal123"},
                "spec_hashes": {"specs/system.md": "spec123"},
                "build_command": ["make", "build"],
                "evaluate_command": ["make", "test"],
            }
            snapshot = {
                "requirements": [
                    {
                        "id": "P00-TST-001",
                        "evidence_required": True,
                    }
                ]
            }
            evaluation = {"completed_at": "2026-07-14T21:01:00Z"}

            payload = harness.acceptance_payload(
                run_path,
                state,
                snapshot,
                evaluation,
            )

            rendered = repr(payload)
            self.assertNotIn("do-not-publish", rendered)
            summary = payload["evidence"][0]["public_summary"]
            self.assertEqual("arm64", summary["target_architecture"])
            self.assertTrue(summary["remote_navigation_denied"])

    def test_manifest_reads_atomically_published_routing_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_path = Path(directory) / "P09/test-run"
            routing = (
                run_path
                / "evidence"
                / harness.ATOMIC_EVIDENCE_DIRECTORY
            )
            routing.mkdir(parents=True)
            evidence_path = routing / "P09-ACC-001.json"
            harness.write_json(
                evidence_path,
                {
                    "requirement_id": "P09-ACC-001",
                    "status": "pass",
                    "test": "acceptance::passes",
                    "recorded_at": "2026-07-16T21:00:00Z",
                    "details": {
                        "public_summary": {
                            "feature_enabled": True,
                            "acceptance_claim": "personal_mvp_passed",
                        }
                    },
                },
            )
            harness.write_json(
                routing / "p09-acceptance-evaluator.json",
                {
                    "schema_version": 1,
                    "status": "pass",
                    "failures": [],
                },
            )
            payload = harness.acceptance_payload(
                run_path,
                {
                    "phase": "P09",
                    "run_id": "test-run",
                    "selected_requirement_ids": ["P09-ACC-001"],
                    "build": {"source_fingerprint": "source"},
                    "review": {"proposal_hash": "proposal"},
                    "spec_hashes": {},
                    "build_command": ["make", "build"],
                    "evaluate_command": ["make", "test"],
                },
                {
                    "requirements": [
                        {
                            "id": "P09-ACC-001",
                            "evidence_required": True,
                        }
                    ]
                },
                {"completed_at": "2026-07-16T21:01:00Z"},
            )

        self.assertEqual(
            "P09-ACC-001",
            payload["evidence"][0]["requirement_id"],
        )
        self.assertIn(
            (
                f"{harness.ATOMIC_EVIDENCE_DIRECTORY}/"
                "P09-ACC-001.json"
            ),
            payload["evidence_file_hashes"],
        )

    def test_manifest_rejects_nested_or_unbounded_summary(self) -> None:
        with self.assertRaises(harness.HarnessError):
            harness.sanitize_public_summary(
                {"nested": {"secret": "value"}},
                context="test",
            )


if __name__ == "__main__":
    unittest.main()
