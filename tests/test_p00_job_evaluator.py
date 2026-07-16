from __future__ import annotations

import json
import unittest

from tools.evaluators import p00_jobs


class DurableJobSourceValidationTests(unittest.TestCase):
    def valid_sources(self) -> tuple[str, str]:
        source = "\n".join(p00_jobs.REQUIRED_SOURCE_MARKERS.values())
        tests = "\n".join(p00_jobs.REQUIRED_TEST_MARKERS.values()) + "\n"
        tests += "\n".join(
            'assert_fresh_oracle(&inspection, "succeeded", 1, 1, 1, 0);'
            for _ in range(p00_jobs.EXPECTED_SINGLE_OUTPUT_ORACLES)
        )
        return source, tests

    def test_accepts_complete_contract(self) -> None:
        source, tests = self.valid_sources()
        self.assertEqual([], p00_jobs.validate_sources(source, tests))

    def test_rejects_each_missing_source_contract(self) -> None:
        source, tests = self.valid_sources()
        for marker in p00_jobs.REQUIRED_SOURCE_MARKERS.values():
            with self.subTest(marker=marker):
                mutated = source.replace(marker, "", 1)
                self.assertTrue(p00_jobs.validate_sources(mutated, tests))

    def test_rejects_each_missing_crash_verification(self) -> None:
        source, tests = self.valid_sources()
        for marker in p00_jobs.REQUIRED_TEST_MARKERS.values():
            with self.subTest(marker=marker):
                mutated = tests.replace(marker, "", 1)
                self.assertTrue(p00_jobs.validate_sources(source, mutated))

    def test_rejects_graceful_or_in_memory_crash_test(self) -> None:
        source, tests = self.valid_sources()
        tests = tests.replace("libc::SIGKILL", "libc::SIGTERM")
        tests += "\nConnection::open_in_memory()"
        errors = p00_jobs.validate_sources(source, tests)
        self.assertGreaterEqual(len(errors), 2)

    def test_rejects_output_count_other_than_one(self) -> None:
        source, tests = self.valid_sources()
        mutated = tests.replace(
            'assert_fresh_oracle(&inspection, "succeeded", 1, 1, 1, 0);',
            'assert_fresh_oracle(&inspection, "succeeded", 1, 1, 2, 0);',
            1,
        )
        self.assertTrue(p00_jobs.validate_sources(source, mutated))


class DurableJobRuntimeEvidenceTests(unittest.TestCase):
    def valid_output(self) -> str:
        records = []
        for scenario, test in p00_jobs.CRASH_SCENARIOS.items():
            owner, fence = p00_jobs.EXPECTED_WINNERS[scenario]
            records.append(self.database_record(scenario, test, owner, fence))
        owner, fence = p00_jobs.EXPECTED_WINNERS[p00_jobs.STALE_SCENARIO]
        stale = self.database_record(
            p00_jobs.STALE_SCENARIO,
            p00_jobs.EXPECTED_SCENARIOS[p00_jobs.STALE_SCENARIO],
            owner,
            fence,
        )
        stale.update(
            stale_fence_rejected=True,
            fabricated_owner_rejected=True,
            fabricated_fence_rejected=True,
        )
        records.append(stale)
        records.append(
            {
                "test": p00_jobs.EXPECTED_SCENARIOS[p00_jobs.CLEANUP_SCENARIO],
                "scenario": p00_jobs.CLEANUP_SCENARIO,
                "status": "pass",
                "recovery_process": "sigkill",
                "process_tree_cleanup": True,
            }
        )
        return "\n".join(
            p00_jobs.EVIDENCE_PREFIX + json.dumps(record, sort_keys=True)
            for record in records
        )

    def database_record(
        self, scenario: str, test: str, owner: str, fence: int
    ) -> dict[str, object]:
        record: dict[str, object] = {
            "test": test,
            "scenario": scenario,
            "status": "pass",
            "database": "sqlite",
            "journal_mode": "wal",
            "synchronous": 2,
            "integrity_check": "ok",
            "foreign_key_violations": 0,
            "result_count": 1,
            "winning_owner": owner,
            "winning_fence": fence,
            "fresh_process_oracle": True,
        }
        if scenario in p00_jobs.CRASH_SCENARIOS:
            record["recovery_process"] = "sigkill"
        return record

    def test_accepts_complete_runtime_evidence_and_derives_summary(self) -> None:
        records, errors = p00_jobs.validate_runtime_evidence(0, self.valid_output())
        self.assertEqual([], errors)
        self.assertEqual(
            {
                "database": "sqlite",
                "journal_mode": "wal",
                "synchronous": "full",
                "recovery_process": "sigkill",
                "crash_scenarios": 4,
                "fencing": True,
                "exactly_once_scope": "sqlite-local-committed-effects",
                "process_tree_cleanup": True,
            },
            p00_jobs.public_summary(records),
        )

    def test_rejects_each_missing_runtime_scenario(self) -> None:
        output = self.valid_output()
        for scenario in p00_jobs.EXPECTED_SCENARIOS:
            with self.subTest(scenario=scenario):
                lines = [
                    line
                    for line in output.splitlines()
                    if f'"scenario": "{scenario}"' not in line
                ]
                _, errors = p00_jobs.validate_runtime_evidence(0, "\n".join(lines))
                self.assertTrue(errors)

    def test_rejects_mutated_runtime_oracles(self) -> None:
        mutations = {
            '"result_count": 1': '"result_count": 2',
            '"recovery_process": "sigkill"': '"recovery_process": "sigterm"',
            '"process_tree_cleanup": true': '"process_tree_cleanup": false',
            '"stale_fence_rejected": true': '"stale_fence_rejected": false',
            '"fresh_process_oracle": true': '"fresh_process_oracle": false',
        }
        output = self.valid_output()
        for original, replacement in mutations.items():
            with self.subTest(field=original):
                mutated = output.replace(original, replacement, 1)
                _, errors = p00_jobs.validate_runtime_evidence(0, mutated)
                self.assertTrue(errors)

    def test_rejects_failed_command_malformed_or_duplicate_records(self) -> None:
        output = self.valid_output()
        first_record = output.splitlines()[0]
        for exit_code, mutated in (
            (1, output),
            (0, output + "\n" + p00_jobs.EVIDENCE_PREFIX + "{"),
            (0, output + "\n" + first_record),
        ):
            with self.subTest(exit_code=exit_code, suffix=mutated[-20:]):
                _, errors = p00_jobs.validate_runtime_evidence(exit_code, mutated)
                self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
