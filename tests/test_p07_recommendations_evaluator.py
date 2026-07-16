from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p07_recommendations
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def copy(relative: str, root: Path) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, destination)


def successful_command() -> CommandResult:
    return CommandResult(
        returncode=0,
        output_sha256="a" * 64,
        output_bytes=10,
        duration_ms=1,
    )


def source_validation() -> p07_recommendations.SourceValidation:
    return p07_recommendations.SourceValidation(
        errors=(),
        source_sha256="c" * 64,
        migration_sha256="d" * 64,
        fixture_sha256=p07_recommendations.EXPECTED_FIXTURE_SHA256,
        fixture_case_count=500,
    )


class P07RecommendationEvaluatorTests(unittest.TestCase):
    def test_current_packet_and_source_are_valid(self) -> None:
        packet = p07_recommendations.validate_packet(ROOT)
        source = p07_recommendations.validate_source(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual((), source.errors)
        self.assertEqual(64, len(packet.packet_sha256))
        self.assertEqual(500, source.fixture_case_count)
        self.assertEqual(
            p07_recommendations.EXPECTED_FIXTURE_SHA256,
            source.fixture_sha256,
        )

    def test_source_validation_rejects_tampered_500_case_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in p07_recommendations.SOURCE_FILES:
                copy(relative, root)
            fixture_path = root / p07_recommendations.FIXTURE_FILE
            fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
            fixture["case_count"] = 499
            fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

            source = p07_recommendations.validate_source(root)

        self.assertTrue(
            any("500-case" in error for error in source.errors),
            source.errors,
        )

    def test_source_validation_requires_the_deferred_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in p07_recommendations.SOURCE_FILES:
                copy(relative, root)
            desktop = root / "src-tauri/src/lib.rs"
            desktop.write_text(
                desktop.read_text(encoding="utf-8").replace(
                    'option_env!("WARDROBE_REMOTE_RECOMMENDATIONS_RELEASE")',
                    "None",
                ),
                encoding="utf-8",
            )

            source = p07_recommendations.validate_source(root)

        self.assertIn(
            "deferred remote recommendation release gate is incomplete",
            source.errors,
        )

    def test_local_requirements_pass_and_live_requirements_defer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P07-AI-001.json"
            stale.write_text('{"status":"pass"}', encoding="utf-8")
            with (
                mock.patch.object(
                    p07_recommendations,
                    "validate_packet",
                    return_value=p07_recommendations.PacketValidation(
                        (), "b" * 64
                    ),
                ),
                mock.patch.object(
                    p07_recommendations,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p07_recommendations,
                    "run_bounded_command",
                    return_value=successful_command(),
                ),
                mock.patch.dict(os.environ, {}, clear=True),
            ):
                result = p07_recommendations.evaluate(
                    ROOT,
                    evidence,
                    set(p07_recommendations.REQUIREMENT_IDS),
                )

            self.assertEqual(0, result)
            for requirement in p07_recommendations.LOCAL_REQUIREMENT_IDS:
                payload = json.loads(
                    (evidence / f"{requirement}.json").read_text()
                )
                self.assertEqual("pass", payload["status"])
            for requirement in p07_recommendations.LIVE_REQUIREMENT_IDS:
                payload = json.loads(
                    (evidence / f"{requirement}.json").read_text()
                )
                summary = payload["details"]["public_summary"]
                self.assertEqual("deferred", payload["status"])
                self.assertIs(False, summary["feature_enabled"])
                self.assertEqual(
                    "deferred_not_passed",
                    summary["acceptance_claim"],
                )
                self.assertTrue(summary["deferred_limitation"])
                self.assertEqual(0, summary["production_adapter_calls"])

    def test_ambient_api_key_never_substitutes_for_500_real_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    p07_recommendations,
                    "validate_packet",
                    return_value=p07_recommendations.PacketValidation(
                        (), "b" * 64
                    ),
                ),
                mock.patch.object(
                    p07_recommendations,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p07_recommendations,
                    "run_bounded_command",
                    return_value=successful_command(),
                ),
                mock.patch.dict(
                    os.environ,
                    {"OPENAI_API_KEY": "must-not-create-pass-evidence"},
                    clear=True,
                ),
            ):
                evidence = Path(directory)
                result = p07_recommendations.evaluate(
                    ROOT,
                    evidence,
                    set(p07_recommendations.REQUIREMENT_IDS),
                )

            self.assertEqual(0, result)
            self.assertTrue(
                all(
                    json.loads(
                        (evidence / f"{requirement}.json").read_text()
                    )["status"]
                    == "deferred"
                    for requirement in p07_recommendations.LIVE_REQUIREMENT_IDS
                )
            )

    def test_failed_local_check_writes_only_diagnostics(self) -> None:
        failed = CommandResult(
            returncode=1,
            output_sha256="f" * 64,
            output_bytes=12,
            duration_ms=2,
        )
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    p07_recommendations,
                    "validate_packet",
                    return_value=p07_recommendations.PacketValidation(
                        (), "b" * 64
                    ),
                ),
                mock.patch.object(
                    p07_recommendations,
                    "validate_source",
                    return_value=source_validation(),
                ),
                mock.patch.object(
                    p07_recommendations,
                    "run_bounded_command",
                    return_value=failed,
                ),
            ):
                evidence = Path(directory)
                result = p07_recommendations.evaluate(
                    ROOT,
                    evidence,
                    set(p07_recommendations.REQUIREMENT_IDS),
                )
                names = {path.name for path in evidence.iterdir()}

        self.assertEqual(1, result)
        self.assertEqual(
            {p07_recommendations.DIAGNOSTICS_NAME},
            names,
        )

    def test_dispatcher_registers_recommendation_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence = root / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {
                        "selected_requirement_ids": sorted(
                            p07_recommendations.REQUIREMENT_IDS
                        )
                    }
                ),
                encoding="utf-8",
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "HARNESS_RUN_DIR": str(run_dir),
                        "HARNESS_EVIDENCE_DIR": str(evidence),
                    },
                    clear=False,
                ),
                mock.patch.object(
                    evaluator_run.p07_recommendations,
                    "evaluate",
                    return_value=0,
                ) as evaluate,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT,
            evidence,
            set(p07_recommendations.REQUIREMENT_IDS),
        )


if __name__ == "__main__":
    unittest.main()
