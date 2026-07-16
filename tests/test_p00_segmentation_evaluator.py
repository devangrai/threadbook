from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from tools.evaluators import p00_segmentation
from tools.evaluators import run as evaluator_run


def command_result(
    *,
    returncode: int = 0,
    output_bytes: int = 128,
    truncated: bool = False,
    timed_out: bool = False,
    launch_failed: bool = False,
) -> p00_segmentation.CommandResult:
    return p00_segmentation.CommandResult(
        returncode=returncode,
        output_sha256=hashlib.sha256(b"cargo output").hexdigest(),
        output_bytes=output_bytes,
        truncated=truncated,
        timed_out=timed_out,
        launch_failed=launch_failed,
    )


def write_valid_sources(root: Path, *, fake_provider: bool = False) -> None:
    source = root / "spikes/p00-segmentation/src"
    source.mkdir(parents=True, exist_ok=True)
    (source / "contract.rs").write_text(
        "pub const MAX_PROVIDER_MASKS: usize = 8;\n",
        encoding="utf-8",
    )
    (source / "dataset.rs").write_text(
        "pub const MAX_TRUTHS_PER_CASE: usize = 4;\n"
        "if case.truths.len() > MAX_TRUTHS_PER_CASE { return Err(()); }\n",
        encoding="utf-8",
    )
    (source / "fallback.rs").write_text(
        'pub const FALLBACK_ID: &str = '
        '"rectangle_uniform_background_v1";\n'
        "fn result() { let _ = needs_review: true; }\n",
        encoding="utf-8",
    )
    locator = (
        'source_locator: Some("https://github.com/example/model"),'
        if fake_provider
        else "source_locator: None,"
    )
    (source / "candidate.rs").write_text(
        """
pub const ID: &str = "coreml_garment_provider_slot_v1";
pub const REASON: &str = "reviewed_model_pack_absent";
pub fn reviewed_state() {
    Candidate {
        invocations: 0,
        %s
        model_revision: None,
        license_decision: None,
        measurements: None,
    };
}
pub fn validate() {}
"""
        % locator,
        encoding="utf-8",
    )


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


class SourceContractTests(unittest.TestCase):
    def test_accepts_compact_contract_and_rejects_fake_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_sources(root)
            errors, digest = p00_segmentation.validate_source_contract(root)
            self.assertEqual([], errors)
            self.assertEqual(64, len(digest))

            write_valid_sources(root, fake_provider=True)
            errors, _ = p00_segmentation.validate_source_contract(root)
            self.assertTrue(any("fake or remote" in error for error in errors))

    def test_rejects_wrong_limits_and_fabricated_slot_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_sources(root)
            contract = root / p00_segmentation.SOURCE_FILES[0]
            contract.write_text(
                "pub const MAX_PROVIDER_MASKS: usize = 4;\n",
                encoding="utf-8",
            )
            candidate = root / p00_segmentation.SOURCE_FILES[3]
            candidate.write_text(
                candidate.read_text(encoding="utf-8").replace(
                    "measurements: None", "measurements: Some(fake)"
                ),
                encoding="utf-8",
            )
            errors, _ = p00_segmentation.validate_source_contract(root)
            self.assertTrue(any("eight masks" in error for error in errors))
            self.assertTrue(any("fabricated state" in error for error in errors))


class BoundedCommandTests(unittest.TestCase):
    def test_hashes_output_and_marks_bound_exceeded(self) -> None:
        size = p00_segmentation.MAX_CAPTURE_BYTES + 1
        result = p00_segmentation.run_bounded_command(
            [sys.executable, "-c", f"import sys;sys.stdout.write('x'*{size})"],
            cwd=Path.cwd(),
            env=os.environ.copy(),
            timeout_seconds=5,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(size, result.output_bytes)
        self.assertTrue(result.truncated)
        self.assertEqual(
            hashlib.sha256(b"x" * size).hexdigest(),
            result.output_sha256,
        )

    def test_times_out_process(self) -> None:
        result = p00_segmentation.run_bounded_command(
            [sys.executable, "-c", "import time;time.sleep(5)"],
            cwd=Path.cwd(),
            env=os.environ.copy(),
            timeout_seconds=0.05,
        )
        self.assertTrue(result.timed_out)
        self.assertNotEqual(0, result.returncode)


class ArtifactTests(unittest.TestCase):
    def test_consistency_validation_detects_cross_artifact_mutation(self) -> None:
        artifacts = p00_segmentation.deferred_artifacts(
            command_result(), "a" * 64
        )
        self.assertEqual(
            [],
            p00_segmentation.validate_artifact_consistency(artifacts),
        )
        artifacts[p00_segmentation.FALLBACK_DECISION_NAME][
            "fallback_revision"
        ] = "different"
        artifacts[p00_segmentation.P04_DENY_NAME][
            "automatic_masks_allowed"
        ] = True
        errors = p00_segmentation.validate_artifact_consistency(artifacts)
        self.assertTrue(any("revisions" in error for error in errors))
        self.assertTrue(any("automatic deny" in error for error in errors))

    def test_atomic_writer_enforces_bound_and_leaves_no_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "artifact.json"
            p00_segmentation.write_atomic_json(path, {"status": "deferred"})
            self.assertEqual("deferred", read_json(path)["status"])
            self.assertEqual([], list(root.glob(".*.tmp")))
            with self.assertRaises(ValueError):
                p00_segmentation.write_atomic_json(
                    path,
                    {"too_large": "x" * p00_segmentation.MAX_ARTIFACT_BYTES},
                )
            self.assertEqual("deferred", read_json(path)["status"])


class EvaluatorTests(unittest.TestCase):
    @mock.patch("tools.evaluators.p00_segmentation.run_bounded_command")
    def test_success_publishes_deferred_artifacts_and_removes_stale_pass(
        self,
        run: mock.Mock,
    ) -> None:
        run.return_value = command_result()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_sources(root)
            evidence = root / "evidence"
            evidence.mkdir()
            stale = evidence / f"{p00_segmentation.REQUIREMENT_ID}.json"
            stale.write_text('{"status":"pass"}', encoding="utf-8")

            result = p00_segmentation.evaluate(
                root, evidence, {p00_segmentation.REQUIREMENT_ID}
            )

            diagnostics = read_json(
                evidence / p00_segmentation.DIAGNOSTICS_NAME
            )
            fallback = read_json(
                evidence / p00_segmentation.FALLBACK_DECISION_NAME
            )
            deny = read_json(evidence / p00_segmentation.P04_DENY_NAME)
            self.assertFalse(stale.exists())
            self.assertEqual("deferred", diagnostics["status"])
            self.assertEqual(
                "no_genuine_garment_segmentation_provider_available",
                diagnostics["reason"],
            )
            self.assertEqual("pass", diagnostics["fallback_smoke_test"])
            self.assertFalse(diagnostics["automatic_masks_enabled"])
            self.assertEqual("accepted_fallback", fallback["decision"])
            self.assertTrue(fallback["all_outputs_need_review"])
            self.assertFalse(fallback["blocks_p01"])
            self.assertFalse(deny["automatic_masks_allowed"])
            self.assertEqual("P04", deny["superseding_phase_required"])

        self.assertEqual(1, result)
        run.assert_called_once()
        self.assertEqual(p00_segmentation.TEST_COMMAND, run.call_args.args[0])
        self.assertEqual(
            p00_segmentation.TEST_TIMEOUT_SECONDS,
            run.call_args.kwargs["timeout_seconds"],
        )

    @mock.patch("tools.evaluators.p00_segmentation.run_bounded_command")
    def test_test_failure_emits_invalid_only_and_cleans_old_decisions(
        self,
        run: mock.Mock,
    ) -> None:
        run.return_value = command_result(returncode=101)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_sources(root)
            evidence = root / "evidence"
            evidence.mkdir()
            for name in (
                f"{p00_segmentation.REQUIREMENT_ID}.json",
                p00_segmentation.DIAGNOSTICS_NAME,
                p00_segmentation.FALLBACK_DECISION_NAME,
                p00_segmentation.P04_DENY_NAME,
            ):
                (evidence / name).write_text("stale", encoding="utf-8")

            result = p00_segmentation.evaluate(
                root, evidence, {p00_segmentation.REQUIREMENT_ID}
            )

            diagnostics = read_json(
                evidence / p00_segmentation.DIAGNOSTICS_NAME
            )
            self.assertEqual("invalid", diagnostics["status"])
            self.assertEqual("fail", diagnostics["fallback_smoke_test"])
            self.assertFalse(
                (evidence / p00_segmentation.FALLBACK_DECISION_NAME).exists()
            )
            self.assertFalse(
                (evidence / p00_segmentation.P04_DENY_NAME).exists()
            )
            self.assertFalse(
                (
                    evidence / f"{p00_segmentation.REQUIREMENT_ID}.json"
                ).exists()
            )
        self.assertEqual(1, result)

    @mock.patch("tools.evaluators.p00_segmentation.run_bounded_command")
    def test_source_failure_is_invalid_not_deferred(
        self,
        run: mock.Mock,
    ) -> None:
        run.return_value = command_result()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_valid_sources(root, fake_provider=True)
            evidence = root / "evidence"
            result = p00_segmentation.evaluate(
                root, evidence, {p00_segmentation.REQUIREMENT_ID}
            )
            diagnostics = read_json(
                evidence / p00_segmentation.DIAGNOSTICS_NAME
            )
            self.assertEqual("invalid", diagnostics["status"])
            self.assertFalse(
                (evidence / p00_segmentation.FALLBACK_DECISION_NAME).exists()
            )
        self.assertEqual(1, result)

    @mock.patch("tools.evaluators.p00_segmentation.run_bounded_command")
    def test_unselected_does_nothing(self, run: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = p00_segmentation.evaluate(
                root, root / "evidence", set()
            )
            self.assertFalse((root / "evidence").exists())
        self.assertEqual(0, result)
        run.assert_not_called()


class DispatcherTests(unittest.TestCase):
    @mock.patch(
        "tools.evaluators.run.p00_segmentation.evaluate",
        return_value=1,
    )
    def test_dispatcher_propagates_deferred_nonzero(
        self,
        evaluate: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence_dir = root / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {
                        "selected_requirement_ids": [
                            p00_segmentation.REQUIREMENT_ID
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                },
            ):
                result = evaluator_run.main()
        self.assertEqual(1, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT,
            evidence_dir,
            {p00_segmentation.REQUIREMENT_ID},
        )

    @mock.patch("tools.evaluators.run.p00_segmentation.evaluate")
    def test_dispatcher_does_not_call_segmentation_when_unselected(
        self,
        evaluate: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence_dir = root / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                '{"selected_requirement_ids":[]}',
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                },
            ):
                result = evaluator_run.main()
        self.assertEqual(0, result)
        evaluate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
