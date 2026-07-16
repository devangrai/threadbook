from __future__ import annotations

import base64
import copy
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import harness
from tools.evaluators import p00_openai
from tools.evaluators import run as evaluator_run


NONCE = "a" * 64
STALE_NONCE = "b" * 64

CALLABLE_VALUES: dict[str, object] = {
    "nonce": NONCE,
    "transmitted": {},
    "retention_mode": "default",
    "retention_provenance": "reviewed-project-settings",
    "client_request_id": "p00-" + "1" * 48,
    "returned_model": "gpt-5.6-sol-2026-07-01",
    "provider_request_id": "req_provider_00000001",
    "response_id": "resp_provider_00000001",
    "latency_millis": 123,
    "usage": {
        "input_tokens": 100,
        "cached_input_tokens": 0,
        "cache_write_tokens": 0,
        "output_tokens": 20,
        "reasoning_tokens": 5,
        "total_tokens": 120,
    },
    "estimated_micro_usd": 42,
    "rate_card_id": "approved-rate-card",
    "calculation_revision": "v1",
    "service_tier_uplift_bps": 0,
    "region_uplift_bps": 0,
    "model_revision": "gpt-5.6-sol",
    "schema_or_refusal": "schema_valid",
}


def text_transmitted() -> dict[str, object]:
    return {
        "request_field_names": list(p00_openai.REQUEST_FIELD_NAMES),
        "receipt_field_names": ["merchant", "line_items.0.description"],
        "sanitized_text_bytes": 128,
        "sanitized_text_sha256": "c" * 64,
        "media": [],
    }


def crop_transmitted() -> dict[str, object]:
    return {
        "request_field_names": list(p00_openai.REQUEST_FIELD_NAMES),
        "receipt_field_names": [],
        "sanitized_text_bytes": 0,
        "sanitized_text_sha256": None,
        "media": [
            {
                "mime": "image/png",
                "width": 64,
                "height": 64,
                "byte_count": 1024,
                "base64_byte_count": 1368,
                "detail": "low",
                "sha256": "d" * 64,
                "metadata_stripped": True,
                "face_free": True,
            }
        ],
    }


def valid_records(
    oracles: dict[str, dict[str, p00_openai.Oracle]],
) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for index, (scenario, expected) in enumerate(oracles.items()):
        record: dict[str, object] = {
            "scenario": scenario,
        }
        for field, oracle in expected.items():
            value = (
                CALLABLE_VALUES[field]
                if callable(oracle)
                else copy.deepcopy(oracle)
            )
            record[field] = value
        if scenario in p00_openai.LIVE_SCENARIOS:
            record["transmitted"] = (
                text_transmitted()
                if scenario == p00_openai.LIVE_TEXT
                else crop_transmitted()
            )
            record["client_request_id"] = f"p00-{index:048x}"
            record["provider_request_id"] = f"req_provider_{index:012d}"
            record["response_id"] = f"resp_provider_{index:012d}"
        records[scenario] = record
    return records


def output_for(
    records: dict[str, dict[str, object]],
    scenarios: tuple[str, ...],
) -> str:
    return "\n".join(
        p00_openai.EVIDENCE_PREFIX
        + json.dumps(records[scenario], sort_keys=True)
        for scenario in scenarios
        if scenario in records
    )


def deterministic_output() -> str:
    return output_for(
        valid_records(p00_openai.DETERMINISTIC_ORACLES),
        p00_openai.DETERMINISTIC_SCENARIOS,
    )


def live_output() -> str:
    return output_for(
        valid_records(p00_openai.LIVE_ORACLES),
        p00_openai.LIVE_SCENARIOS,
    )


def invalid_value(field: str, value: object) -> object:
    callable_invalid: dict[str, object] = {
        "nonce": "",
        "transmitted": {},
        "retention_mode": "unreviewed",
        "retention_provenance": "",
        "returned_model": "gpt-4o",
        "client_request_id": "",
        "provider_request_id": "fabricated",
        "response_id": "fabricated",
        "latency_millis": 0,
        "input_tokens": 0,
        "cached_input_tokens": -1,
        "cache_write_tokens": -1,
        "output_tokens": 0,
        "reasoning_tokens": -1,
        "total_tokens": 0,
        "estimated_micro_usd": 0,
        "usage": {},
        "rate_card_id": "",
        "calculation_revision": "",
        "service_tier_uplift_bps": -1,
        "region_uplift_bps": -1,
        "model_revision": "gpt-4o",
        "schema_or_refusal": "malformed",
    }
    if field in callable_invalid:
        return callable_invalid[field]
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is float:
        return value + 1.0
    if isinstance(value, str):
        return value + "-mutated"
    raise AssertionError(f"no mutation for {field}={value!r}")


def command_result(output: str, *, returncode: int = 0) -> p00_openai.CommandResult:
    encoded = output.encode("utf-8")
    import hashlib

    return p00_openai.CommandResult(
        returncode=returncode,
        output=output,
        output_sha256=hashlib.sha256(encoded).hexdigest(),
        output_bytes=len(encoded),
    )


def valid_live_env() -> dict[str, str]:
    return {
        "OPENAI_API_KEY": "test-only-key",
        p00_openai.RETENTION_MODE_ENV: "default",
        p00_openai.RETENTION_PROVENANCE_ENV: "reviewed-project-settings",
        p00_openai.RATE_CARD_ENV: json.dumps(
            {
                "rate_card_id": "approved-rate-card",
                "approved": True,
                "approved_at": "2026-01-01",
                "valid_from": "2026-01-02",
                "valid_through": "2026-12-31",
                "currency": "USD",
                "model_revision": "gpt-5.6-sol",
                "uncached_input_micro_usd_per_million": 1,
                "cached_input_micro_usd_per_million": 1,
                "output_micro_usd_per_million": 1,
                "cache_write_multiplier_milli": 1250,
                "max_text_input_tokens": 8192,
                "image_tokens": {
                    "low_detail_tokens": 85,
                    "high_detail_base_tokens": 85,
                    "high_detail_tile_tokens": 170,
                    "high_detail_tile_pixels": 512,
                },
                "service_tier_uplift_bps": {"default": 0},
                "region_uplift_bps": {"global_default": 0},
                "calculation_revision": "v1",
            }
        ),
    }


class OpenAIRecordValidationTests(unittest.TestCase):
    def assert_every_oracle_is_independent(
        self,
        oracles: dict[str, dict[str, p00_openai.Oracle]],
    ) -> None:
        baseline = valid_records(oracles)
        for scenario, expected in oracles.items():
            for field in expected:
                with self.subTest(scenario=scenario, mutated_field=field):
                    records = copy.deepcopy(baseline)
                    records[scenario][field] = invalid_value(
                        field, records[scenario][field]
                    )
                    errors = p00_openai.validate_record_set(records, oracles)
                    self.assertTrue(errors)
                with self.subTest(scenario=scenario, missing_field=field):
                    records = copy.deepcopy(baseline)
                    del records[scenario][field]
                    errors = p00_openai.validate_record_set(records, oracles)
                    self.assertTrue(errors)

    def test_accepts_exact_deterministic_and_live_records(self) -> None:
        deterministic, deterministic_errors = p00_openai.parse_evidence(
            deterministic_output()
        )
        live, live_errors = p00_openai.parse_evidence(live_output())
        self.assertEqual([], deterministic_errors)
        self.assertEqual([], live_errors)
        self.assertEqual(
            [],
            p00_openai.validate_record_set(
                deterministic, p00_openai.DETERMINISTIC_ORACLES
            ),
        )
        self.assertEqual(
            [],
            p00_openai.validate_record_set(live, p00_openai.LIVE_ORACLES),
        )

    def test_rejects_independent_mutation_of_every_deterministic_oracle(
        self,
    ) -> None:
        self.assert_every_oracle_is_independent(
            p00_openai.DETERMINISTIC_ORACLES
        )

    def test_rejects_independent_mutation_of_every_live_oracle(self) -> None:
        self.assert_every_oracle_is_independent(p00_openai.LIVE_ORACLES)

    def test_rejects_each_missing_or_mutated_transmitted_audit_field(
        self,
    ) -> None:
        invalid = {
            "request_field_names": [],
            "receipt_field_names": [1],
            "sanitized_text_bytes": -1,
            "sanitized_text_sha256": "invalid",
            "media": "invalid",
        }
        for scenario in p00_openai.LIVE_SCENARIOS:
            for field, value in invalid.items():
                with self.subTest(scenario=scenario, missing=field):
                    records = valid_records(p00_openai.LIVE_ORACLES)
                    del records[scenario]["transmitted"][field]
                    self.assertTrue(
                        p00_openai.validate_record_set(
                            records, p00_openai.LIVE_ORACLES
                        )
                    )
                with self.subTest(scenario=scenario, mutated=field):
                    records = valid_records(p00_openai.LIVE_ORACLES)
                    records[scenario]["transmitted"][field] = value
                    self.assertTrue(
                        p00_openai.validate_record_set(
                            records, p00_openai.LIVE_ORACLES
                        )
                    )

    def test_rejects_each_missing_or_mutated_media_audit_field(self) -> None:
        invalid = {
            "mime": "text/plain",
            "width": 0,
            "height": 0,
            "byte_count": 0,
            "base64_byte_count": 0,
            "detail": "auto",
            "sha256": "invalid",
            "metadata_stripped": False,
            "face_free": False,
        }
        for field, value in invalid.items():
            with self.subTest(missing=field):
                records = valid_records(p00_openai.LIVE_ORACLES)
                del records[p00_openai.LIVE_CROP]["transmitted"]["media"][0][
                    field
                ]
                self.assertTrue(
                    p00_openai.validate_record_set(
                        records, p00_openai.LIVE_ORACLES
                    )
                )
            with self.subTest(mutated=field):
                records = valid_records(p00_openai.LIVE_ORACLES)
                records[p00_openai.LIVE_CROP]["transmitted"]["media"][0][
                    field
                ] = value
                self.assertTrue(
                    p00_openai.validate_record_set(
                        records, p00_openai.LIVE_ORACLES
                    )
                )

    def test_rejects_each_missing_or_mutated_usage_field(self) -> None:
        invalid = {
            "input_tokens": 0,
            "cached_input_tokens": -1,
            "cache_write_tokens": -1,
            "output_tokens": 0,
            "reasoning_tokens": 21,
            "total_tokens": 121,
        }
        for field, value in invalid.items():
            with self.subTest(missing=field):
                records = valid_records(p00_openai.LIVE_ORACLES)
                del records[p00_openai.LIVE_TEXT]["usage"][field]
                self.assertTrue(
                    p00_openai.validate_record_set(
                        records, p00_openai.LIVE_ORACLES
                    )
                )
            with self.subTest(mutated=field):
                records = valid_records(p00_openai.LIVE_ORACLES)
                records[p00_openai.LIVE_TEXT]["usage"][field] = value
                self.assertTrue(
                    p00_openai.validate_record_set(
                        records, p00_openai.LIVE_ORACLES
                    )
                )

    def test_rejects_each_missing_scenario(self) -> None:
        for oracles in (
            p00_openai.DETERMINISTIC_ORACLES,
            p00_openai.LIVE_ORACLES,
        ):
            for scenario in oracles:
                with self.subTest(scenario=scenario):
                    records = valid_records(oracles)
                    del records[scenario]
                    self.assertTrue(
                        p00_openai.validate_record_set(records, oracles)
                    )

    def test_rejects_extra_fields_and_unexpected_scenarios(self) -> None:
        records = valid_records(p00_openai.DETERMINISTIC_ORACLES)
        records[p00_openai.TEXT_CONTRACT]["unvalidated_claim"] = True
        self.assertTrue(
            p00_openai.validate_record_set(
                records, p00_openai.DETERMINISTIC_ORACLES
            )
        )
        records = valid_records(p00_openai.DETERMINISTIC_ORACLES)
        records["unexpected"] = {
            "scenario": "unexpected",
            "nonce": NONCE,
            "status": "pass",
        }
        self.assertTrue(
            p00_openai.validate_record_set(
                records, p00_openai.DETERMINISTIC_ORACLES
            )
        )

    def test_rejects_mutated_scenario_identity_and_missing_required_field(
        self,
    ) -> None:
        records = valid_records(p00_openai.DETERMINISTIC_ORACLES)
        records[p00_openai.TEXT_CONTRACT]["scenario"] = p00_openai.CROP_CONTRACT
        self.assertTrue(
            p00_openai.validate_record_set(
                records, p00_openai.DETERMINISTIC_ORACLES
            )
        )
        records = valid_records(p00_openai.DETERMINISTIC_ORACLES)
        del records[p00_openai.TEXT_CONTRACT]["status"]
        self.assertTrue(
            p00_openai.validate_record_set(
                records, p00_openai.DETERMINISTIC_ORACLES
            )
        )

    def test_rejects_duplicate_malformed_unframed_and_extra_records(self) -> None:
        output = deterministic_output()
        first = output.splitlines()[0]
        stale = json.loads(
            first.removeprefix(p00_openai.EVIDENCE_PREFIX)
        )
        stale["nonce"] = "old-run"
        cases = (
            output + "\n" + first,
            output + "\n" + p00_openai.EVIDENCE_PREFIX + "{",
            output + "\nprefix " + first,
            output + "\n" + p00_openai.EVIDENCE_PREFIX + "[]",
            output + "\n" + p00_openai.EVIDENCE_PREFIX + '{"status":"pass"}',
            output
            + "\n"
            + p00_openai.EVIDENCE_PREFIX
            + json.dumps(stale),
        )
        for mutated in cases:
            with self.subTest(suffix=mutated[-80:]):
                records, errors = p00_openai.parse_evidence(mutated)
                errors.extend(
                    p00_openai.validate_record_set(
                        records, p00_openai.DETERMINISTIC_ORACLES
                    )
                )
                self.assertTrue(errors)

    def test_rejects_a_complete_record_set_from_a_stale_nonce(self) -> None:
        records = valid_records(p00_openai.DETERMINISTIC_ORACLES)
        for record in records.values():
            record["nonce"] = STALE_NONCE
        result = command_result(
            output_for(records, p00_openai.DETERMINISTIC_SCENARIOS)
        )
        records, errors = p00_openai.validate_command_evidence(
            result,
            nonce=NONCE,
            oracles=p00_openai.DETERMINISTIC_ORACLES,
            command_name="test",
        )
        self.assertEqual(8, len(records))
        self.assertTrue(any("nonce is stale" in error for error in errors))

    def test_rejects_missing_nonce_in_each_record_set(self) -> None:
        for oracles, scenarios in (
            (
                p00_openai.DETERMINISTIC_ORACLES,
                p00_openai.DETERMINISTIC_SCENARIOS,
            ),
            (p00_openai.LIVE_ORACLES, p00_openai.LIVE_SCENARIOS),
        ):
            records = valid_records(oracles)
            del records[scenarios[0]]["nonce"]
            _, errors = p00_openai.validate_command_evidence(
                command_result(output_for(records, scenarios)),
                nonce=NONCE,
                oracles=oracles,
                command_name="test",
            )
            self.assertTrue(errors)

    def test_rejects_command_failures_timeout_launch_and_truncation(self) -> None:
        baseline = command_result(deterministic_output())
        mutations = (
            p00_openai.CommandResult(**{**baseline.__dict__, "returncode": 9}),
            p00_openai.CommandResult(**{**baseline.__dict__, "timed_out": True}),
            p00_openai.CommandResult(
                **{**baseline.__dict__, "launch_failed": True}
            ),
            p00_openai.CommandResult(**{**baseline.__dict__, "truncated": True}),
        )
        for result in mutations:
            with self.subTest(result=result):
                _, errors = p00_openai.validate_command_evidence(
                    result,
                    nonce=NONCE,
                    oracles=p00_openai.DETERMINISTIC_ORACLES,
                    command_name="test",
                )
                self.assertTrue(errors)

    def test_rejects_bogus_ids_usage_and_cost(self) -> None:
        mutations = {
            "provider_request_id": "req_",
            "response_id": "resp_",
            "latency_millis": 0,
            "usage": {},
            "estimated_micro_usd": 0,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                records = valid_records(p00_openai.LIVE_ORACLES)
                records[p00_openai.LIVE_TEXT][field] = value
                self.assertTrue(
                    p00_openai.validate_record_set(
                        records, p00_openai.LIVE_ORACLES
                    )
                )

    def test_rejects_inconsistent_or_duplicate_live_accounting(self) -> None:
        records = valid_records(p00_openai.LIVE_ORACLES)
        records[p00_openai.LIVE_TEXT]["usage"]["total_tokens"] = 121
        self.assertTrue(
            p00_openai.validate_record_set(
                records, p00_openai.LIVE_ORACLES
            )
        )
        records = valid_records(p00_openai.LIVE_ORACLES)
        records[p00_openai.LIVE_CROP]["provider_request_id"] = records[
            p00_openai.LIVE_TEXT
        ]["provider_request_id"]
        self.assertTrue(
            p00_openai.validate_record_set(
                records, p00_openai.LIVE_ORACLES
            )
        )

    def test_rejects_live_records_bound_to_different_environment(self) -> None:
        records = valid_records(p00_openai.LIVE_ORACLES)
        environment = valid_live_env()
        rate_card = json.loads(environment[p00_openai.RATE_CARD_ENV])
        self.assertEqual(
            [],
            p00_openai.validate_live_context(
                records, environment, rate_card
            ),
        )
        records[p00_openai.LIVE_TEXT]["rate_card_id"] = "other-rate-card"
        self.assertTrue(
            p00_openai.validate_live_context(
                records, environment, rate_card
            )
        )
        mutations = {
            "retention_mode": "ZDR",
            "retention_provenance": "other-attestation",
            "calculation_revision": "v2",
            "service_tier": "priority",
            "region": "regional",
            "service_tier_uplift_bps": 1,
            "region_uplift_bps": 1,
            "model_revision": "gpt-5.6-sol-other",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                records = valid_records(p00_openai.LIVE_ORACLES)
                records[p00_openai.LIVE_TEXT][field] = value
                self.assertTrue(
                    p00_openai.validate_live_context(
                        records, environment, rate_card
                    )
                )

    def test_public_summaries_derive_from_validated_runtime_records(self) -> None:
        deterministic = valid_records(p00_openai.DETERMINISTIC_ORACLES)
        live = valid_records(p00_openai.LIVE_ORACLES)
        rate_card, errors = p00_openai.validate_live_inputs(
            valid_live_env(), today=dt.date(2026, 7, 14)
        )
        self.assertEqual([], errors)
        assert rate_card is not None
        ai = p00_openai.ai_public_summary(deterministic, live)
        privacy = p00_openai.privacy_public_summary(live)
        self.assertEqual(8, ai["deterministic_scenarios"])
        self.assertEqual(2, ai["live_canaries"])
        self.assertEqual(84, privacy["estimated_cost_micro_usd"])
        self.assertEqual("default", privacy["retention_mode"])
        self.assertEqual(
            "reviewed-project-settings", privacy["retention_provenance"]
        )
        self.assertEqual(
            p00_openai.REQUEST_FIELD_NAMES,
            privacy["transmitted_request_fields"],
        )
        self.assertEqual(1, privacy["transmitted_media_count"])
        self.assertEqual(
            ai,
            harness.sanitize_public_summary(
                ai, context="OpenAI AI evaluator test"
            ),
        )
        self.assertEqual(
            privacy,
            harness.sanitize_public_summary(
                privacy, context="OpenAI privacy evaluator test"
            ),
        )

    def test_public_summaries_reject_unvalidated_records(self) -> None:
        deterministic = valid_records(p00_openai.DETERMINISTIC_ORACLES)
        live = valid_records(p00_openai.LIVE_ORACLES)
        deterministic[p00_openai.SUCCESS]["schema_valid"] = False
        with self.assertRaises(ValueError):
            p00_openai.ai_public_summary(deterministic, live)

    def test_privacy_summary_uses_live_retention_and_transmission_records(
        self,
    ) -> None:
        live = valid_records(p00_openai.LIVE_ORACLES)
        for record in live.values():
            record["retention_mode"] = "ZDR"
            record["retention_provenance"] = "zdr-admin-attestation"
            record["calculation_revision"] = "cost-v2"
        live[p00_openai.LIVE_TEXT]["transmitted"][
            "receipt_field_names"
        ].append("currency")
        summary = p00_openai.privacy_public_summary(live)
        self.assertEqual("ZDR", summary["retention_mode"])
        self.assertEqual(
            "zdr-admin-attestation", summary["retention_provenance"]
        )
        self.assertEqual("cost-v2", summary["calculation_revision"])
        self.assertEqual(3, summary["transmitted_receipt_field_count"])


class OpenAILiveInputTests(unittest.TestCase):
    def test_accepts_explicit_current_approved_configuration(self) -> None:
        rate_card, errors = p00_openai.validate_live_inputs(
            valid_live_env(), today=dt.date(2026, 7, 14)
        )
        self.assertEqual([], errors)
        self.assertEqual("approved-rate-card", rate_card["rate_card_id"])

    def test_rejects_each_missing_live_input(self) -> None:
        for name in (
            "OPENAI_API_KEY",
            p00_openai.RETENTION_MODE_ENV,
            p00_openai.RETENTION_PROVENANCE_ENV,
            p00_openai.RATE_CARD_ENV,
        ):
            with self.subTest(name=name):
                environment = valid_live_env()
                del environment[name]
                _, errors = p00_openai.validate_live_inputs(
                    environment, today=dt.date(2026, 7, 14)
                )
                self.assertTrue(errors)

    def test_rejects_whitespace_api_key_without_disclosing_it(self) -> None:
        environment = valid_live_env()
        environment["OPENAI_API_KEY"] = "secret value"
        _, errors = p00_openai.validate_live_inputs(
            environment, today=dt.date(2026, 7, 14)
        )
        self.assertTrue(errors)
        self.assertNotIn("secret value", "\n".join(errors))

    def test_rejects_unapproved_future_stale_or_wrong_model_rate_cards(
        self,
    ) -> None:
        base = json.loads(valid_live_env()[p00_openai.RATE_CARD_ENV])
        mutations = (
            {"approved": False},
            {"approved_at": "2027-01-01"},
            {"valid_through": "2026-07-13"},
            {"model_revision": "gpt-4o"},
            {"rate_card_id": ""},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                environment = valid_live_env()
                card = {**base, **mutation}
                environment[p00_openai.RATE_CARD_ENV] = json.dumps(card)
                _, errors = p00_openai.validate_live_inputs(
                    environment, today=dt.date(2026, 7, 14)
                )
                self.assertTrue(errors)

    def test_diagnostics_do_not_contain_environment_values(self) -> None:
        environment = valid_live_env()
        diagnostics = {
            "retention_mode_declared": bool(
                environment[p00_openai.RETENTION_MODE_ENV]
            ),
            "retention_provenance_declared": bool(
                environment[p00_openai.RETENTION_PROVENANCE_ENV]
            ),
            "rate_card_approved": True,
        }
        text, findings = p00_openai._safe_diagnostics_text(diagnostics)
        self.assertEqual([], findings)
        for value in environment.values():
            self.assertNotIn(value, text)


class OpenAISentinelTests(unittest.TestCase):
    def test_rejects_raw_json_url_base64_and_hex_sentinel_variants(self) -> None:
        for sentinel in p00_openai.KNOWN_SENTINELS:
            variants = p00_openai.sentinel_variants(sentinel)
            self.assertIn(sentinel.encode("ascii"), variants)
            self.assertIn(base64.b64encode(sentinel.encode("ascii")), variants)
            for variant in variants:
                with self.subTest(sentinel=sentinel, variant=variant):
                    findings = p00_openai.sentinel_findings(
                        b"prefix=" + variant, "fixture"
                    )
                    self.assertTrue(findings)

    def test_rejects_sentinel_in_bounded_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "artifact.json"
            path.parent.mkdir()
            path.write_text(
                p00_openai.KNOWN_SENTINELS[0], encoding="utf-8"
            )
            errors = p00_openai.scan_artifacts(Path(directory))
        self.assertTrue(any("sentinel leaked" in error for error in errors))

    def test_rejects_oversize_artifact_without_unbounded_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversize"
            path.write_bytes(b"x" * (p00_openai.MAX_ARTIFACT_BYTES + 1))
            with mock.patch.object(
                Path, "read_bytes", side_effect=AssertionError("must not read")
            ):
                errors = p00_openai.scan_artifacts(Path(directory))
        self.assertTrue(any("exceeds the scan limit" in error for error in errors))

    def test_command_evidence_rejects_streaming_sentinel_finding(self) -> None:
        result = command_result(deterministic_output())
        result = p00_openai.CommandResult(
            **{
                **result.__dict__,
                "sentinel_errors": (
                    "known privacy sentinel leaked in subprocess output",
                ),
            }
        )
        _, errors = p00_openai.validate_command_evidence(
            result,
            nonce=NONCE,
            oracles=p00_openai.DETERMINISTIC_ORACLES,
            command_name="test",
        )
        self.assertTrue(any("sentinel leaked" in error for error in errors))


class OpenAIEvaluatorIntegrationTests(unittest.TestCase):
    @mock.patch("tools.evaluators.p00_openai.secrets.token_hex", return_value=NONCE)
    @mock.patch("tools.evaluators.p00_openai.run_bounded_command")
    def test_runs_exact_commands_and_writes_separate_evidence(
        self,
        run: mock.Mock,
        _token_hex: mock.Mock,
    ) -> None:
        run.side_effect = (
            command_result(deterministic_output()),
            command_result(live_output()),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            with mock.patch.dict(os.environ, valid_live_env(), clear=True):
                result = p00_openai.evaluate(
                    root, evidence, set(p00_openai.REQUIREMENT_IDS)
                )
            ai = json.loads(
                (evidence / "P00-AI-001.json").read_text(encoding="utf-8")
            )
            privacy = json.loads(
                (evidence / "P00-PRV-001.json").read_text(encoding="utf-8")
            )
            diagnostics = (
                evidence / "p00-openai-diagnostics.json"
            ).read_text(encoding="utf-8")
        self.assertEqual(0, result)
        self.assertEqual(2, run.call_count)
        self.assertEqual(
            [
                "cargo",
                "test",
                "-p",
                "p00-openai-provider",
                "--test",
                "contract",
                "--",
                "--nocapture",
                "--test-threads=1",
            ],
            run.call_args_list[0].args[0],
        )
        self.assertEqual(
            [
                "cargo",
                "run",
                "--quiet",
                "-p",
                "p00-openai-provider",
                "--features",
                "live-canary",
                "--bin",
                "p00-openai-canary",
            ],
            run.call_args_list[1].args[0],
        )
        self.assertEqual("pass", ai["status"])
        self.assertEqual("pass", privacy["status"])
        self.assertNotEqual(
            ai["details"]["public_summary"],
            privacy["details"]["public_summary"],
        )
        self.assertNotIn("test-only-key", diagnostics)
        self.assertNotIn("reviewed-project-settings", diagnostics)

    @mock.patch("tools.evaluators.p00_openai.secrets.token_hex", return_value=NONCE)
    @mock.patch("tools.evaluators.p00_openai.run_bounded_command")
    def test_missing_live_inputs_runs_deterministic_and_removes_stale_passes(
        self,
        run: mock.Mock,
        _token_hex: mock.Mock,
    ) -> None:
        run.return_value = command_result(deterministic_output())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            for requirement_id in p00_openai.REQUIREMENT_IDS:
                (evidence / f"{requirement_id}.json").write_text(
                    '{"status":"pass"}', encoding="utf-8"
                )
            with mock.patch.dict(os.environ, {}, clear=True):
                result = p00_openai.evaluate(
                    root, evidence, set(p00_openai.REQUIREMENT_IDS)
                )
            passes_exist = any(
                (evidence / f"{requirement_id}.json").exists()
                for requirement_id in p00_openai.REQUIREMENT_IDS
            )
            diagnostics = json.loads(
                (evidence / "p00-openai-diagnostics.json").read_text(
                    encoding="utf-8"
                )
            )
        self.assertEqual(1, result)
        self.assertEqual(1, run.call_count)
        self.assertFalse(passes_exist)
        self.assertFalse(diagnostics["live_executed"])
        self.assertTrue(
            any("OPENAI_API_KEY" in error for error in diagnostics["errors"])
        )

    @mock.patch("tools.evaluators.p00_openai.secrets.token_hex", return_value=NONCE)
    @mock.patch("tools.evaluators.p00_openai.run_bounded_command")
    def test_command_failure_emits_no_pass_or_raw_output(
        self,
        run: mock.Mock,
        _token_hex: mock.Mock,
    ) -> None:
        raw = "private raw subprocess output"
        run.return_value = command_result(raw, returncode=1)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            with mock.patch.dict(os.environ, valid_live_env(), clear=True):
                result = p00_openai.evaluate(
                    root, evidence, {"P00-AI-001"}
                )
            diagnostics = (
                evidence / "p00-openai-diagnostics.json"
            ).read_text(encoding="utf-8")
        self.assertEqual(1, result)
        self.assertFalse((evidence / "P00-AI-001.json").exists())
        self.assertNotIn(raw, diagnostics)

    @mock.patch("tools.evaluators.p00_openai.secrets.token_hex", return_value=NONCE)
    @mock.patch("tools.evaluators.p00_openai.run_bounded_command")
    def test_untrusted_record_names_are_not_logged_or_persisted(
        self,
        run: mock.Mock,
        _token_hex: mock.Mock,
    ) -> None:
        private_scenario = "PRIVATE_RECEIPT_CONTENT"
        private_field = "PRIVATE_FIELD_CONTENT"
        output = (
            p00_openai.EVIDENCE_PREFIX
            + json.dumps(
                {
                    "scenario": private_scenario,
                    "nonce": NONCE,
                    private_field: True,
                }
            )
        )
        run.return_value = command_result(output)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            with (
                mock.patch.dict(os.environ, valid_live_env(), clear=True),
                mock.patch("builtins.print") as print_mock,
            ):
                result = p00_openai.evaluate(
                    root, evidence, {"P00-AI-001"}
                )
            diagnostics = (
                evidence / "p00-openai-diagnostics.json"
            ).read_text(encoding="utf-8")
            printed = "\n".join(
                " ".join(str(argument) for argument in call.args)
                for call in print_mock.call_args_list
            )
        self.assertEqual(1, result)
        self.assertNotIn(private_scenario, diagnostics + printed)
        self.assertNotIn(private_field, diagnostics + printed)

    @mock.patch("tools.evaluators.p00_openai.run_bounded_command")
    def test_ignores_unselected_requirements(self, run: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = p00_openai.evaluate(
                Path(directory), Path(directory) / "evidence", set()
            )
        self.assertEqual(0, result)
        run.assert_not_called()


class OpenAIDispatcherTests(unittest.TestCase):
    @mock.patch("tools.evaluators.run.p00_openai.evaluate", return_value=0)
    def test_dispatcher_registers_both_requirements(
        self, evaluate: mock.Mock
    ) -> None:
        selected = {"P00-AI-001", "P00-PRV-001"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence_dir = root / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {"selected_requirement_ids": sorted(selected)}
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                },
                clear=False,
            ):
                result = evaluator_run.main()
        self.assertEqual(0, result)
        evaluate.assert_called_once_with(
            evaluator_run.ROOT, evidence_dir, selected
        )

    @mock.patch("tools.evaluators.run.p00_openai.evaluate", return_value=7)
    def test_dispatcher_propagates_openai_failure(
        self, evaluate: mock.Mock
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            evidence_dir = root / "evidence"
            run_dir.mkdir()
            (run_dir / "requirements.json").write_text(
                json.dumps(
                    {"selected_requirement_ids": ["P00-AI-001"]}
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "HARNESS_RUN_DIR": str(run_dir),
                    "HARNESS_EVIDENCE_DIR": str(evidence_dir),
                },
                clear=False,
            ):
                result = evaluator_run.main()
        self.assertEqual(7, result)
        evaluate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
