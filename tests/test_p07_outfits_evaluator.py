from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p07_outfits
from tools.evaluators import run as evaluator_run
from tools.evaluators.p03_receipts import CommandResult


ROOT = Path(__file__).resolve().parents[1]


def copy(relative: str, root: Path) -> None:
    destination = root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / relative, destination)


class P07EvaluatorTests(unittest.TestCase):
    def test_current_packet_and_source_are_valid(self) -> None:
        packet_errors, packet_hash = p07_outfits.validate_packet(ROOT)
        source_errors, source_hash, migration_hash = p07_outfits.validate_source(
            ROOT
        )

        self.assertEqual([], packet_errors)
        self.assertEqual([], source_errors)
        self.assertEqual(64, len(packet_hash))
        self.assertEqual(64, len(source_hash))
        self.assertEqual(64, len(migration_hash))

    def test_source_validation_rejects_remote_manual_outfit_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in p07_outfits.SOURCE_FILES:
                copy(relative, root)
            bridge = root / "apps/desktop-ui/src/outfit-bridge.ts"
            bridge.write_text(
                bridge.read_text(encoding="utf-8") + "\n// https://example.invalid\n",
                encoding="utf-8",
            )

            errors, _, _ = p07_outfits.validate_source(root)

        self.assertTrue(any("remote dependency" in error for error in errors))

    def test_success_writes_exactly_two_requirement_records(self) -> None:
        result = CommandResult(
            returncode=0,
            output_sha256="a" * 64,
            output_bytes=10,
            duration_ms=1,
        )
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(
                    p07_outfits,
                    "validate_packet",
                    return_value=([], "b" * 64),
                ),
                mock.patch.object(
                    p07_outfits,
                    "validate_source",
                    return_value=([], "c" * 64, "d" * 64),
                ),
                mock.patch.object(
                    p07_outfits,
                    "run_bounded_command",
                    return_value=result,
                ),
            ):
                evidence = Path(directory)
                status = p07_outfits.evaluate(
                    ROOT, evidence, set(p07_outfits.REQUIREMENT_IDS)
                )
                names = {path.name for path in evidence.iterdir()}

        self.assertEqual(0, status)
        self.assertEqual(
            {
                *(f"{requirement}.json" for requirement in p07_outfits.REQUIREMENT_IDS),
                p07_outfits.DIAGNOSTICS_NAME,
            },
            names,
        )

    def test_dispatcher_registers_all_p07_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence = root / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {
                        "selected_requirement_ids": sorted(
                            p07_outfits.REQUIREMENT_IDS
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
                    evaluator_run.p07_outfits,
                    "evaluate",
                    return_value=0,
                ) as evaluate,
            ):
                result = evaluator_run.main()

        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT,
            evidence,
            set(p07_outfits.REQUIREMENT_IDS),
        )


if __name__ == "__main__":
    unittest.main()
