from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p08_try_on
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def copy(relative: str, root: Path) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, destination)


def successful_command(output: bytes = b"") -> CommandResult:
    import hashlib

    return CommandResult(
        returncode=0,
        output_sha256=hashlib.sha256(output).hexdigest(),
        output_bytes=len(output),
        duration_ms=1,
        captured_output=output,
    )


def source_validation() -> p08_try_on.SourceValidation:
    return p08_try_on.SourceValidation(
        errors=(),
        source_sha256="c" * 64,
        migration_sha256="d" * 64,
    )


def packet_validation() -> p08_try_on.PacketValidation:
    return p08_try_on.PacketValidation(errors=(), packet_sha256="b" * 64)


class P08TryOnEvaluatorTests(unittest.TestCase):
    def test_current_packet_and_source_are_valid(self) -> None:
        packet = p08_try_on.validate_packet(ROOT)
        source = p08_try_on.validate_source(ROOT)

        self.assertEqual((), packet.errors)
        self.assertEqual((), source.errors)
        self.assertEqual(64, len(packet.packet_sha256))
        self.assertEqual(64, len(source.migration_sha256))

    def test_packet_validation_rejects_changed_approved_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (*p08_try_on.EXPECTED_PACKET_HASHES, p08_try_on.STATE_FILE):
                copy(relative, root)
            proposal = root / p08_try_on.PACKET_DIR / "proposal.md"
            proposal.write_text(
                proposal.read_text(encoding="utf-8") + "\nchanged\n",
                encoding="utf-8",
            )

            packet = p08_try_on.validate_packet(root)

        self.assertTrue(
            any("proposal.md" in error for error in packet.errors),
            packet.errors,
        )

    def test_source_validation_requires_exact_experimental_release_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in p08_try_on.SOURCE_FILES:
                copy(relative, root)
            desktop = root / "src-tauri/src/lib.rs"
            desktop.write_text(
                desktop.read_text(encoding="utf-8").replace(
                    'const TRY_ON_RELEASE_TOKEN: &str = "experimental"',
                    'const TRY_ON_RELEASE_TOKEN: &str = "enabled"',
                ),
                encoding="utf-8",
            )

            source = p08_try_on.validate_source(root)

        self.assertIn("experimental P08 release gate is incomplete", source.errors)

    def test_local_requirements_pass_but_canary_and_quality_study_defer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            stale = evidence / "P08-QLT-001.json"
            stale.write_text('{"status":"pass"}', encoding="utf-8")
            with (
                mock.patch.object(
                    p08_try_on, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(
                    p08_try_on, "validate_source", return_value=source_validation()
                ),
                mock.patch.object(
                    p08_try_on,
                    "run_bounded_command",
                    return_value=successful_command(),
                ) as run,
                mock.patch.dict(os.environ, {}, clear=True),
            ):
                result = p08_try_on.evaluate(
                    ROOT, evidence, set(p08_try_on.REQUIREMENT_IDS)
                )

            self.assertEqual(0, result)
            self.assertEqual(len(p08_try_on.COMMAND_CHECKS), run.call_count)
            for requirement in p08_try_on.LOCAL_REQUIREMENT_IDS:
                payload = json.loads(
                    (evidence / f"{requirement}.json").read_text(encoding="utf-8")
                )
                self.assertEqual("pass", payload["status"])
                summary = payload["details"]["public_summary"]
                self.assertEqual(
                    "deferred_not_passed",
                    summary["live_canary_acceptance_claim"],
                )
                self.assertEqual(0, summary["production_adapter_calls"])
                self.assertTrue(
                    all(
                        isinstance(value, (str, bool, int, float, list))
                        for value in summary.values()
                    )
                )

            quality = json.loads(stale.read_text(encoding="utf-8"))
            summary = quality["details"]["public_summary"]
            self.assertEqual("deferred", quality["status"])
            self.assertEqual("deferred_not_passed", summary["acceptance_claim"])
            self.assertFalse(summary["feature_enabled"])
            self.assertEqual(0, summary["human_evaluation_cases"])

    def test_ambient_openai_key_does_not_opt_in_to_live_canary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    p08_try_on, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(
                    p08_try_on, "validate_source", return_value=source_validation()
                ),
                mock.patch.object(
                    p08_try_on,
                    "run_bounded_command",
                    return_value=successful_command(),
                ) as run,
                mock.patch.dict(
                    os.environ,
                    {"OPENAI_API_KEY": "must-not-trigger-a-call"},
                    clear=True,
                ),
            ):
                evidence = Path(directory)
                result = p08_try_on.evaluate(
                    ROOT, evidence, set(p08_try_on.REQUIREMENT_IDS)
                )

            diagnostics = json.loads(
                (evidence / p08_try_on.DIAGNOSTICS_NAME).read_text()
            )
            self.assertEqual(0, result)
            self.assertEqual(len(p08_try_on.COMMAND_CHECKS), run.call_count)
            self.assertTrue(
                all(
                    "OPENAI_API_KEY" not in call.kwargs["env"]
                    for call in run.call_args_list
                )
            )
            self.assertEqual(0, diagnostics["production_adapter_calls"])
            self.assertEqual(
                "deferred_not_passed",
                diagnostics["live_openai_canary"]["acceptance_claim"],
            )

    def test_explicit_valid_live_canary_records_exactly_one_call(self) -> None:
        canary_record = json.dumps(
            {
                "schema_version": 1,
                "canary": p08_try_on.LIVE_CANARY_NAME,
                "adapter": p08_try_on.LIVE_CANARY_ADAPTER,
                "endpoint": p08_try_on.LIVE_CANARY_ENDPOINT,
                "model": p08_try_on.LIVE_CANARY_MODEL,
                "production_adapter_calls": 1,
                "response_contract_valid": True,
                "fixture_contains_personal_data": False,
                "fixture_sha256": "a" * 64,
            }
        ).encode()
        results = [
            *(successful_command() for _ in p08_try_on.COMMAND_CHECKS),
            successful_command(canary_record),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    p08_try_on, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(
                    p08_try_on, "validate_source", return_value=source_validation()
                ),
                mock.patch.object(
                    p08_try_on,
                    "run_bounded_command",
                    side_effect=results,
                ) as run,
                mock.patch.dict(
                    os.environ,
                    {
                        p08_try_on.LIVE_CANARY_OPT_IN_ENV: (
                            p08_try_on.LIVE_CANARY_OPT_IN_TOKEN
                        ),
                        p08_try_on.LIVE_CANARY_COMMAND_ENV: json.dumps(
                            ["p08-production-canary"]
                        ),
                    },
                    clear=True,
                ),
            ):
                evidence = Path(directory)
                result = p08_try_on.evaluate(
                    ROOT, evidence, set(p08_try_on.REQUIREMENT_IDS)
                )

            diagnostics = json.loads(
                (evidence / p08_try_on.DIAGNOSTICS_NAME).read_text()
            )
            quality = json.loads(
                (evidence / f"{p08_try_on.QUALITY_REQUIREMENT_ID}.json").read_text()
            )
            self.assertEqual(0, result)
            self.assertEqual(len(p08_try_on.COMMAND_CHECKS) + 1, run.call_count)
            self.assertEqual(1, diagnostics["production_adapter_calls"])
            self.assertEqual(
                "live_canary_passed",
                diagnostics["live_openai_canary"]["acceptance_claim"],
            )
            self.assertEqual("deferred", quality["status"])
            self.assertEqual(
                "deferred_not_passed",
                quality["details"]["public_summary"]["acceptance_claim"],
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
                    p08_try_on, "validate_packet", return_value=packet_validation()
                ),
                mock.patch.object(
                    p08_try_on, "validate_source", return_value=source_validation()
                ),
                mock.patch.object(
                    p08_try_on, "run_bounded_command", return_value=failed
                ),
            ):
                evidence = Path(directory)
                result = p08_try_on.evaluate(
                    ROOT, evidence, set(p08_try_on.REQUIREMENT_IDS)
                )
                names = {path.name for path in evidence.iterdir()}

        self.assertEqual(1, result)
        self.assertEqual({p08_try_on.DIAGNOSTICS_NAME}, names)

    def test_dispatcher_registers_all_p08_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence = root / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {
                        "selected_requirement_ids": sorted(
                            p08_try_on.REQUIREMENT_IDS
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
                    evaluator_run.p08_try_on,
                    "evaluate",
                    return_value=0,
                ) as evaluate,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT,
            evidence,
            set(p08_try_on.REQUIREMENT_IDS),
        )


if __name__ == "__main__":
    unittest.main()
