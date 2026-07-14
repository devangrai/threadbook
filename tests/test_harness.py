from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest


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


if __name__ == "__main__":
    unittest.main()
