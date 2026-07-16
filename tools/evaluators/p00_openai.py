"""Fail-closed runtime evaluator for the P00 OpenAI provider spike."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import subprocess
import time
from typing import Any, Callable
from urllib.parse import quote


REQUIREMENT_IDS = frozenset({"P00-AI-001", "P00-PRV-001"})
EVIDENCE_PREFIX = "P00_OPENAI_EVIDENCE "
NONCE_ENV = "P00_OPENAI_EVIDENCE_NONCE"
RETENTION_MODE_ENV = "OPENAI_RETENTION_MODE"
RETENTION_PROVENANCE_ENV = "OPENAI_RETENTION_PROVENANCE"
RATE_CARD_ENV = "OPENAI_RATE_CARD_JSON"

TEST_COMMAND = [
    "cargo",
    "test",
    "-p",
    "p00-openai-provider",
    "--test",
    "contract",
    "--",
    "--nocapture",
    "--test-threads=1",
]
CANARY_COMMAND = [
    "cargo",
    "run",
    "--quiet",
    "-p",
    "p00-openai-provider",
    "--features",
    "live-canary",
    "--bin",
    "p00-openai-canary",
]

TEXT_CONTRACT = "request_contract_text"
CROP_CONTRACT = "request_contract_crop"
SUCCESS = "success_and_catalog_immutability"
FAILURES = "refusal_and_failure_taxonomy"
APPROVAL = "approval_and_cancellation"
INJECTION = "injection_isolation"
AUDIT = "audit_and_cost"
REDACTION = "sentinel_redaction"
LIVE_TEXT = "live_text_canary"
LIVE_CROP = "live_crop_canary"

DETERMINISTIC_SCENARIOS = (
    TEXT_CONTRACT,
    CROP_CONTRACT,
    SUCCESS,
    FAILURES,
    APPROVAL,
    INJECTION,
    AUDIT,
    REDACTION,
)
LIVE_SCENARIOS = (LIVE_TEXT, LIVE_CROP)

MAX_CAPTURE_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_ARTIFACT_TOTAL_BYTES = 4 * 1024 * 1024
MAX_ARTIFACT_FILES = 128
TEST_TIMEOUT_SECONDS = 15 * 60
CANARY_TIMEOUT_SECONDS = 3 * 60

KNOWN_SENTINELS = (
    "sk-P00_CREDENTIAL_SENTINEL_NEVER_LOG",
    "PERSONAL_RECEIPT_BODY_SENTINEL",
    "BASE64_IMAGE_SENTINEL",
    "private-receipt-filename.png",
    "https://source.invalid/private-receipt",
    "PROVIDER_ERROR_BODY_SENTINEL",
    "REFUSAL_TEXT_SENTINEL",
    "P00_LIVE_TEXT_SENTINEL_ALPHA",
    "P00_LIVE_CROP_SENTINEL_BETA",
)
PROVIDER_REQUEST_ID = re.compile(r"req_[A-Za-z0-9_-]{12,}")
RESPONSE_ID = re.compile(r"resp_[A-Za-z0-9_-]{12,}")
CLIENT_REQUEST_ID = re.compile(r"p00-[0-9a-f]{48}")
LOWER_HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
EVIDENCE_NONCE = re.compile(r"[0-9a-f]{64}")

REQUEST_FIELD_NAMES = [
    "model",
    "store",
    "background",
    "tools",
    "conversation",
    "previous_response_id",
    "input",
    "text.format",
    "reasoning.effort",
    "prompt_cache_options.mode",
    "service_tier",
    "max_output_tokens",
]


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _safe_record_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 128
        and value.isascii()
        and all(character.isalnum() or character in "._-:" for character in value)
    )


def _valid_nonce(value: Any) -> bool:
    return isinstance(value, str) and EVIDENCE_NONCE.fullmatch(value) is not None


def _valid_usage(value: Any) -> bool:
    fields = {
        "input_tokens",
        "cached_input_tokens",
        "cache_write_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
    }
    if not isinstance(value, dict) or set(value) != fields:
        return False
    if any(type(value[field]) is not int or value[field] < 0 for field in fields):
        return False
    return (
        value["input_tokens"] > 0
        and value["output_tokens"] > 0
        and value["total_tokens"]
        == value["input_tokens"] + value["output_tokens"]
        and value["cached_input_tokens"] + value["cache_write_tokens"]
        <= value["input_tokens"]
        and value["reasoning_tokens"] <= value["output_tokens"]
    )


def _valid_media(value: Any) -> bool:
    fields = {
        "mime",
        "width",
        "height",
        "byte_count",
        "base64_byte_count",
        "detail",
        "sha256",
        "metadata_stripped",
        "face_free",
    }
    if not isinstance(value, dict) or set(value) != fields:
        return False
    return (
        value["mime"] in {"image/png", "image/jpeg", "image/webp"}
        and type(value["width"]) is int
        and 0 < value["width"] <= 2048
        and type(value["height"]) is int
        and 0 < value["height"] <= 2048
        and value["width"] * value["height"] <= 4_194_304
        and type(value["byte_count"]) is int
        and 0 < value["byte_count"] <= 4 * 1024 * 1024
        and type(value["base64_byte_count"]) is int
        and value["base64_byte_count"]
        == ((value["byte_count"] + 2) // 3) * 4
        and value["detail"] in {"low", "high"}
        and isinstance(value["sha256"], str)
        and LOWER_HEX_SHA256.fullmatch(value["sha256"]) is not None
        and value["metadata_stripped"] is True
        and value["face_free"] is True
    )


def _valid_transmitted(value: Any) -> bool:
    fields = {
        "request_field_names",
        "receipt_field_names",
        "sanitized_text_bytes",
        "sanitized_text_sha256",
        "media",
    }
    if not isinstance(value, dict) or set(value) != fields:
        return False
    request_fields = value["request_field_names"]
    receipt_fields = value["receipt_field_names"]
    media = value["media"]
    return (
        request_fields == REQUEST_FIELD_NAMES
        and isinstance(receipt_fields, list)
        and len(receipt_fields) <= 704
        and all(
            isinstance(field, str)
            and 0 < len(field) <= 128
            and field.isascii()
            for field in receipt_fields
        )
        and type(value["sanitized_text_bytes"]) is int
        and 0 <= value["sanitized_text_bytes"] <= 32 * 1024
        and (
            value["sanitized_text_sha256"] is None
            or (
                isinstance(value["sanitized_text_sha256"], str)
                and LOWER_HEX_SHA256.fullmatch(
                    value["sanitized_text_sha256"]
                )
                is not None
            )
        )
        and isinstance(media, list)
        and len(media) <= 4
        and all(_valid_media(item) for item in media)
    )


Oracle = Any | Callable[[Any], bool]

COMMON_ORACLES: dict[str, Oracle] = {
    "nonce": _valid_nonce,
    "status": "pass",
}

# Assertion counts are part of the frozen runtime protocol. They fail closed if
# an executed contract scenario is weakened without revising this evaluator.
DETERMINISTIC_ORACLES: dict[str, dict[str, Oracle]] = {
    TEXT_CONTRACT: {
        **COMMON_ORACLES,
        "assertions": 25,
        "deterministic": True,
    },
    CROP_CONTRACT: {
        **COMMON_ORACLES,
        "assertions": 29,
        "deterministic": True,
    },
    SUCCESS: {
        **COMMON_ORACLES,
        "assertions": 10,
        "deterministic": True,
    },
    FAILURES: {
        **COMMON_ORACLES,
        "assertions": 19,
        "deterministic": True,
    },
    APPROVAL: {
        **COMMON_ORACLES,
        "assertions": 20,
        "deterministic": True,
    },
    INJECTION: {
        **COMMON_ORACLES,
        "assertions": 11,
        "deterministic": True,
    },
    AUDIT: {
        **COMMON_ORACLES,
        "assertions": 32,
        "deterministic": True,
    },
    REDACTION: {
        **COMMON_ORACLES,
        "assertions": 16,
        "deterministic": True,
    },
}

LIVE_ORACLES: dict[str, dict[str, Oracle]] = {
    scenario: {
        **COMMON_ORACLES,
        "transmitted": _valid_transmitted,
        "retention_mode": lambda value: value
        in {"unknown", "default", "MAM", "ZDR"},
        "retention_provenance": _safe_record_identifier,
        "client_request_id": lambda value: (
            isinstance(value, str)
            and CLIENT_REQUEST_ID.fullmatch(value) is not None
        ),
        "returned_model": lambda value: (
            isinstance(value, str)
            and (
                value == "gpt-5.6-sol"
                or value.startswith("gpt-5.6-sol-")
            )
        ),
        "provider_request_id": lambda value: (
            isinstance(value, str)
            and PROVIDER_REQUEST_ID.fullmatch(value) is not None
        ),
        "response_id": lambda value: (
            isinstance(value, str)
            and RESPONSE_ID.fullmatch(value) is not None
        ),
        "latency_millis": _positive_int,
        "usage": _valid_usage,
        "estimated_micro_usd": _positive_int,
        "rate_card_id": _safe_record_identifier,
        "calculation_revision": _safe_record_identifier,
        "service_tier": "default",
        "region": "global_default",
        "service_tier_uplift_bps": _nonnegative_int,
        "region_uplift_bps": _nonnegative_int,
        "model_revision": lambda value: (
            isinstance(value, str)
            and (
                value == "gpt-5.6-sol"
                or value.startswith("gpt-5.6-sol-")
            )
        ),
        "store_false": True,
        "schema_or_refusal": lambda value: value
        in {"schema_valid", "explicit_refusal"},
        "no_sentinel_leaks": True,
        "synthetic_nonpersonal_data": True,
    }
    for scenario in LIVE_SCENARIOS
}


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    output: str
    output_sha256: str
    output_bytes: int
    truncated: bool = False
    timed_out: bool = False
    launch_failed: bool = False
    sentinel_errors: tuple[str, ...] = ()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sentinel_variants(sentinel: str) -> set[bytes]:
    raw = sentinel.encode("ascii")
    return {
        raw,
        json.dumps(sentinel, ensure_ascii=True)[1:-1].encode("ascii"),
        quote(sentinel, safe="").encode("ascii"),
        "".join(f"%{byte:02X}" for byte in raw).encode("ascii"),
        base64.b64encode(raw),
        raw.hex().encode("ascii"),
        raw.hex().upper().encode("ascii"),
    }


def sentinel_findings(data: bytes, location: str) -> list[str]:
    findings: list[str] = []
    for sentinel in KNOWN_SENTINELS:
        if any(variant in data for variant in sentinel_variants(sentinel)):
            findings.append(f"known privacy sentinel leaked in {location}")
    return findings


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        if process.poll() is None:
            process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=3)


def run_bounded_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
) -> CommandResult:
    digest = hashlib.sha256()
    captured = bytearray()
    total = 0
    truncated = False
    timed_out = False
    scanner_tail = b""
    scanner_errors: set[str] = set()
    max_variant = max(
        len(variant)
        for sentinel in KNOWN_SENTINELS
        for variant in sentinel_variants(sentinel)
    )
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        return CommandResult(
            returncode=127,
            output="",
            output_sha256=hashlib.sha256(b"").hexdigest(),
            output_bytes=0,
            launch_failed=True,
        )

    assert process.stdout is not None
    deadline = time.monotonic() + timeout_seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 and process.poll() is None:
            timed_out = True
            _terminate(process)
        readable, _, _ = select.select(
            [process.stdout],
            [],
            [],
            0 if process.poll() is not None else min(0.25, max(remaining, 0)),
        )
        if readable:
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if chunk:
                total += len(chunk)
                digest.update(chunk)
                available = MAX_CAPTURE_BYTES - len(captured)
                if available > 0:
                    captured.extend(chunk[:available])
                if len(chunk) > available:
                    truncated = True
                scan_data = scanner_tail + chunk
                scanner_errors.update(
                    sentinel_findings(scan_data, "subprocess output")
                )
                scanner_tail = scan_data[-max(0, max_variant - 1) :]
                continue
        if process.poll() is not None:
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if chunk:
                total += len(chunk)
                digest.update(chunk)
                available = MAX_CAPTURE_BYTES - len(captured)
                if available > 0:
                    captured.extend(chunk[:available])
                if len(chunk) > available:
                    truncated = True
                scan_data = scanner_tail + chunk
                scanner_errors.update(
                    sentinel_findings(scan_data, "subprocess output")
                )
                scanner_tail = scan_data[-max(0, max_variant - 1) :]
                continue
            break

    process.stdout.close()
    return CommandResult(
        returncode=process.returncode,
        output=captured.decode("utf-8", errors="replace"),
        output_sha256=digest.hexdigest(),
        output_bytes=total,
        truncated=truncated,
        timed_out=timed_out,
        sentinel_errors=tuple(sorted(scanner_errors)),
    )


def parse_evidence(
    output: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for line in output.splitlines():
        occurrences = line.count(EVIDENCE_PREFIX)
        if occurrences == 0:
            continue
        if occurrences != 1 or not line.startswith(EVIDENCE_PREFIX):
            errors.append("OpenAI runtime evidence is not exactly line-framed")
            continue
        payload_text = line.removeprefix(EVIDENCE_PREFIX)
        try:
            payload = json.loads(payload_text)
        except (json.JSONDecodeError, UnicodeError):
            errors.append("OpenAI runtime evidence contains malformed JSON")
            continue
        if not isinstance(payload, dict):
            errors.append("OpenAI runtime evidence record is not an object")
            continue
        scenario = payload.get("scenario")
        if not isinstance(scenario, str) or not scenario:
            errors.append("OpenAI runtime evidence has no string scenario")
            continue
        if scenario in records:
            errors.append("OpenAI runtime evidence repeats a scenario")
            continue
        records[scenario] = payload
    return records, errors


def _matches(actual: Any, oracle: Oracle) -> bool:
    if callable(oracle):
        try:
            return oracle(actual) is True
        except (TypeError, ValueError, OverflowError):
            return False
    return type(actual) is type(oracle) and actual == oracle


def validate_record_set(
    records: dict[str, dict[str, Any]],
    oracles: dict[str, dict[str, Oracle]],
) -> list[str]:
    errors: list[str] = []
    expected_names = set(oracles)
    actual_names = set(records)
    missing = expected_names - actual_names
    unexpected = actual_names - expected_names
    if missing:
        errors.append("missing runtime scenarios: " + ", ".join(sorted(missing)))
    if unexpected:
        errors.append("unexpected runtime scenarios were emitted")

    for scenario, expected in oracles.items():
        record = records.get(scenario)
        if record is None:
            continue
        expected_keys = {"scenario", *expected}
        missing_keys = expected_keys - set(record)
        unexpected_keys = set(record) - expected_keys
        if missing_keys:
            errors.append(
                f"{scenario}: missing fields " + ", ".join(sorted(missing_keys))
            )
        if unexpected_keys:
            errors.append(f"{scenario}: unexpected fields were emitted")
        if record.get("scenario") != scenario:
            errors.append(f"{scenario}: scenario identity is invalid")
        for field, oracle in expected.items():
            if not _matches(record.get(field), oracle):
                errors.append(f"{scenario}: {field} oracle failed")

    if set(LIVE_SCENARIOS).issubset(records):
        identifier_fields = (
            "client_request_id",
            "provider_request_id",
            "response_id",
        )
        for field in identifier_fields:
            values = {records[scenario].get(field) for scenario in LIVE_SCENARIOS}
            if len(values) != len(LIVE_SCENARIOS):
                errors.append(f"live canary {field} values are not distinct")
        all_ids = [
            records[scenario].get(field)
            for scenario in LIVE_SCENARIOS
            for field in identifier_fields
        ]
        if len(set(all_ids)) != len(all_ids):
            errors.append("live canary request and response IDs are not distinct")

        text_transmitted = records[LIVE_TEXT].get("transmitted")
        crop_transmitted = records[LIVE_CROP].get("transmitted")
        if isinstance(text_transmitted, dict):
            if (
                not text_transmitted.get("receipt_field_names")
                or text_transmitted.get("sanitized_text_bytes", 0) <= 0
                or text_transmitted.get("sanitized_text_sha256") is None
                or text_transmitted.get("media") != []
            ):
                errors.append("live text transmitted audit is invalid")
        if isinstance(crop_transmitted, dict):
            if (
                crop_transmitted.get("receipt_field_names") != []
                or crop_transmitted.get("sanitized_text_bytes") != 0
                or crop_transmitted.get("sanitized_text_sha256") is not None
                or len(crop_transmitted.get("media", [])) != 1
            ):
                errors.append("live crop transmitted audit is invalid")

        consistent_fields = (
            "retention_mode",
            "retention_provenance",
            "rate_card_id",
            "calculation_revision",
            "service_tier",
            "region",
            "service_tier_uplift_bps",
            "region_uplift_bps",
            "model_revision",
        )
        for field in consistent_fields:
            values = {records[scenario].get(field) for scenario in LIVE_SCENARIOS}
            if len(values) != 1:
                errors.append(f"live canary {field} values are inconsistent")
    return errors


def validate_command_evidence(
    result: CommandResult,
    *,
    nonce: str,
    oracles: dict[str, dict[str, Oracle]],
    command_name: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    records, errors = parse_evidence(result.output)
    for scenario, record in records.items():
        if record.get("nonce") != nonce:
            if scenario in oracles:
                errors.append(f"{scenario}: runtime evidence nonce is stale")
            else:
                errors.append(f"{command_name} emitted a stale evidence nonce")
    if result.launch_failed:
        errors.append(f"{command_name} command could not start")
    elif result.timed_out:
        errors.append(f"{command_name} command timed out")
    elif result.returncode != 0:
        errors.append(f"{command_name} command failed")
    if result.truncated:
        errors.append(f"{command_name} output exceeded the capture limit")
    errors.extend(result.sentinel_errors)
    errors.extend(validate_record_set(records, oracles))
    return records, errors


def _parse_date(value: Any) -> dt.date | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def _safe_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 128
        and all(
            character.isascii()
            and (character.isalnum() or character in "._-:")
            for character in value
        )
    )


def _exact_nonnegative_int_map(value: Any, required_key: str) -> bool:
    return (
        isinstance(value, dict)
        and required_key in value
        and all(
            isinstance(key, str)
            and _safe_identifier(key)
            and type(item) is int
            and item >= 0
            for key, item in value.items()
        )
    )


def validate_rate_card(
    rate_card: dict[str, Any],
    *,
    today: dt.date,
) -> list[str]:
    errors: list[str] = []
    expected_fields = {
        "rate_card_id",
        "approved",
        "approved_at",
        "valid_from",
        "valid_through",
        "currency",
        "model_revision",
        "uncached_input_micro_usd_per_million",
        "cached_input_micro_usd_per_million",
        "output_micro_usd_per_million",
        "cache_write_multiplier_milli",
        "max_text_input_tokens",
        "image_tokens",
        "service_tier_uplift_bps",
        "region_uplift_bps",
        "calculation_revision",
    }
    if set(rate_card) != expected_fields:
        errors.append("OpenAI rate card fields do not match the approved schema")
    if rate_card.get("approved") is not True:
        errors.append("OpenAI rate card must be explicitly approved")
    if not _safe_identifier(rate_card.get("rate_card_id")):
        errors.append("OpenAI rate card must have a bounded ASCII ID")
    if not _safe_identifier(rate_card.get("calculation_revision")):
        errors.append("OpenAI rate card calculation revision is invalid")
    if rate_card.get("model_revision") != "gpt-5.6-sol":
        errors.append("OpenAI rate card must cover gpt-5.6-sol")
    if rate_card.get("currency") != "USD":
        errors.append("OpenAI rate card currency must be USD")

    approved_at = _parse_date(rate_card.get("approved_at"))
    valid_from = _parse_date(rate_card.get("valid_from"))
    valid_through = _parse_date(rate_card.get("valid_through"))
    if approved_at is None:
        errors.append("OpenAI rate card approval date is invalid")
    elif approved_at > today:
        errors.append("OpenAI rate card approval date is in the future")
    if valid_from is None or valid_through is None:
        errors.append("OpenAI rate card validity dates are required")
    elif not (valid_from <= today <= valid_through):
        errors.append("OpenAI rate card is not currently valid")

    for field in (
        "uncached_input_micro_usd_per_million",
        "cached_input_micro_usd_per_million",
        "output_micro_usd_per_million",
        "max_text_input_tokens",
    ):
        value = rate_card.get(field)
        if type(value) is not int or value <= 0:
            errors.append(f"OpenAI rate card {field} must be positive")
    if rate_card.get("cache_write_multiplier_milli") != 1250:
        errors.append("OpenAI rate card cache-write multiplier must be 1250")

    image_tokens = rate_card.get("image_tokens")
    image_fields = {
        "low_detail_tokens",
        "high_detail_base_tokens",
        "high_detail_tile_tokens",
        "high_detail_tile_pixels",
    }
    if not isinstance(image_tokens, dict) or set(image_tokens) != image_fields:
        errors.append("OpenAI rate card image-token policy is invalid")
    elif any(
        type(image_tokens[field]) is not int or image_tokens[field] <= 0
        for field in image_fields
    ):
        errors.append("OpenAI rate card image-token values must be positive")

    if not _exact_nonnegative_int_map(
        rate_card.get("service_tier_uplift_bps"), "default"
    ):
        errors.append("OpenAI rate card lacks the default service tier")
    if not _exact_nonnegative_int_map(
        rate_card.get("region_uplift_bps"), "global_default"
    ):
        errors.append("OpenAI rate card lacks the global region")
    return errors


def validate_live_inputs(
    environ: dict[str, str],
    *,
    today: dt.date | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    api_key = environ.get("OPENAI_API_KEY")
    if not api_key or any(character.isspace() for character in api_key):
        errors.append("OPENAI_API_KEY is required for live canaries")

    mode = environ.get(RETENTION_MODE_ENV)
    if mode not in {"unknown", "default", "MAM", "ZDR"}:
        errors.append(
            "OPENAI_RETENTION_MODE must be explicit: "
            "unknown, default, MAM, or ZDR"
        )
    provenance = environ.get(RETENTION_PROVENANCE_ENV)
    if (
        not provenance
        or len(provenance) > 128
        or not _safe_identifier(provenance)
    ):
        errors.append(
            "OPENAI_RETENTION_PROVENANCE must identify the reviewed source"
        )

    raw_rate_card = environ.get(RATE_CARD_ENV)
    rate_card: dict[str, Any] | None = None
    if not raw_rate_card:
        errors.append("OPENAI_RATE_CARD_JSON is required for live canaries")
    else:
        try:
            parsed = json.loads(raw_rate_card)
        except (json.JSONDecodeError, UnicodeError):
            errors.append("OPENAI_RATE_CARD_JSON must be valid JSON")
        else:
            if not isinstance(parsed, dict):
                errors.append("OPENAI_RATE_CARD_JSON must be an object")
            else:
                rate_card = parsed

    if rate_card is not None:
        current = today or dt.datetime.now(dt.timezone.utc).date()
        errors.extend(validate_rate_card(rate_card, today=current))
    return rate_card, errors


def validate_live_context(
    records: dict[str, dict[str, Any]],
    environ: dict[str, str],
    rate_card: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    if rate_card is None:
        return ["live canary rate-card context is unavailable"]
    expected_rate_card_id = rate_card.get("rate_card_id")
    expected_values = {
        "retention_mode": environ.get(RETENTION_MODE_ENV),
        "retention_provenance": environ.get(RETENTION_PROVENANCE_ENV),
        "rate_card_id": expected_rate_card_id,
        "calculation_revision": rate_card.get("calculation_revision"),
        "service_tier": "default",
        "region": "global_default",
        "service_tier_uplift_bps": rate_card.get(
            "service_tier_uplift_bps", {}
        ).get("default"),
        "region_uplift_bps": rate_card.get("region_uplift_bps", {}).get(
            "global_default"
        ),
        "model_revision": rate_card.get("model_revision"),
    }
    for scenario in LIVE_SCENARIOS:
        record = records.get(scenario)
        if record is None:
            continue
        for field, expected in expected_values.items():
            if record.get(field) != expected:
                errors.append(f"{scenario}: {field} context does not match")
    return errors


def scan_artifacts(evidence_dir: Path) -> list[str]:
    errors: list[str] = []
    if not evidence_dir.exists():
        return errors
    files = sorted(item for item in evidence_dir.rglob("*") if item.is_file())
    if len(files) > MAX_ARTIFACT_FILES:
        return ["evaluator artifact count exceeds the scan limit"]
    total = 0
    for path in files:
        if path.is_symlink():
            errors.append("an evaluator artifact is a symlink")
            continue
        try:
            size = path.stat().st_size
        except OSError:
            errors.append("cannot inspect an evaluator artifact")
            continue
        total += size
        if size > MAX_ARTIFACT_BYTES:
            errors.append("an evaluator artifact exceeds the scan limit")
            continue
        if total > MAX_ARTIFACT_TOTAL_BYTES:
            errors.append("evaluator artifacts exceed the aggregate scan limit")
            break
        try:
            data = path.read_bytes()
        except OSError:
            errors.append("cannot scan an evaluator artifact")
            continue
        errors.extend(sentinel_findings(data, "an evaluator artifact"))
    return errors


def ai_public_summary(
    deterministic: dict[str, dict[str, Any]],
    live: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    errors = validate_record_set(deterministic, DETERMINISTIC_ORACLES)
    errors.extend(validate_record_set(live, LIVE_ORACLES))
    if errors:
        raise ValueError("cannot summarize invalid OpenAI runtime evidence")
    return {
        "returned_models": sorted(
            {live[scenario]["returned_model"] for scenario in LIVE_SCENARIOS}
        ),
        "deterministic_scenarios": len(deterministic),
        "live_canaries": len(live),
        "text_contract_assertions": deterministic[TEXT_CONTRACT]["assertions"],
        "crop_contract_assertions": deterministic[CROP_CONTRACT]["assertions"],
        "strict_json_schema": deterministic[TEXT_CONTRACT]["status"] == "pass",
        "explicit_refusal": deterministic[FAILURES]["status"] == "pass",
        "catalog_unchanged": all(
            record["status"] == "pass"
            for record in (*deterministic.values(), *live.values())
        ),
        "live_schema_or_refusal": all(
            live[scenario]["schema_or_refusal"]
            in {"schema_valid", "explicit_refusal"}
            for scenario in LIVE_SCENARIOS
        ),
    }


def privacy_public_summary(
    live: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    errors = validate_record_set(live, LIVE_ORACLES)
    if errors:
        raise ValueError("cannot summarize invalid OpenAI runtime evidence")
    text_transmitted = live[LIVE_TEXT]["transmitted"]
    crop_transmitted = live[LIVE_CROP]["transmitted"]
    return {
        "store": not live[LIVE_TEXT]["store_false"],
        "request_ids_recorded": True,
        "client_request_ids": len(
            {live[scenario]["client_request_id"] for scenario in LIVE_SCENARIOS}
        ),
        "provider_request_ids": len(
            {
                live[scenario]["provider_request_id"]
                for scenario in LIVE_SCENARIOS
            }
        ),
        "response_ids": len(
            {live[scenario]["response_id"] for scenario in LIVE_SCENARIOS}
        ),
        "actual_usage_recorded": all(
            _valid_usage(live[scenario]["usage"])
            for scenario in LIVE_SCENARIOS
        ),
        "actual_latency_recorded": all(
            live[scenario]["latency_millis"] > 0
            for scenario in LIVE_SCENARIOS
        ),
        "estimated_cost_micro_usd": sum(
            live[scenario]["estimated_micro_usd"]
            for scenario in LIVE_SCENARIOS
        ),
        "rate_card_id": live[LIVE_TEXT]["rate_card_id"],
        "calculation_revision": live[LIVE_TEXT]["calculation_revision"],
        "model_revision": live[LIVE_TEXT]["model_revision"],
        "service_tier": live[LIVE_TEXT]["service_tier"],
        "region": live[LIVE_TEXT]["region"],
        "service_tier_uplift_bps": live[LIVE_TEXT][
            "service_tier_uplift_bps"
        ],
        "region_uplift_bps": live[LIVE_TEXT]["region_uplift_bps"],
        "retention_mode": live[LIVE_TEXT]["retention_mode"],
        "retention_provenance": live[LIVE_TEXT]["retention_provenance"],
        "transmitted_request_fields": text_transmitted[
            "request_field_names"
        ],
        "transmitted_receipt_field_count": len(
            text_transmitted["receipt_field_names"]
        ),
        "transmitted_media_count": len(crop_transmitted["media"]),
        "transmitted_text_bytes": text_transmitted[
            "sanitized_text_bytes"
        ],
        "sentinel_leaks": 0
        if all(
            live[scenario]["no_sentinel_leaks"]
            for scenario in LIVE_SCENARIOS
        )
        else 1,
    }


def _safe_diagnostics_text(diagnostics: dict[str, Any]) -> tuple[str, list[str]]:
    text = json.dumps(diagnostics, indent=2, sort_keys=True) + "\n"
    findings = sentinel_findings(
        text.encode("utf-8"), "prospective evaluator diagnostics"
    )
    if findings:
        text = json.dumps(
            {
                "errors": [
                    "privacy sentinel detected; diagnostics fully redacted"
                ],
                "deterministic_command": TEST_COMMAND,
                "live_command": CANARY_COMMAND,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
    return text, findings


def evaluate(root: Path, evidence_dir: Path, selected: set[str]) -> int:
    requested = selected & REQUIREMENT_IDS
    if not requested:
        return 0

    evidence_dir.mkdir(parents=True, exist_ok=True)
    for requirement_id in REQUIREMENT_IDS:
        (evidence_dir / f"{requirement_id}.json").unlink(missing_ok=True)

    nonce = secrets.token_hex(32)
    command_env = os.environ.copy()
    command_env[NONCE_ENV] = nonce
    for source, destination in (
        (RETENTION_MODE_ENV, "P00_OPENAI_RETENTION_MODE"),
        (RETENTION_PROVENANCE_ENV, "P00_OPENAI_RETENTION_PROVENANCE"),
        (RATE_CARD_ENV, "P00_OPENAI_RATE_CARD_JSON"),
    ):
        if source in command_env:
            command_env[destination] = command_env[source]

    deterministic_result = run_bounded_command(
        TEST_COMMAND,
        cwd=root,
        env=command_env,
        timeout_seconds=TEST_TIMEOUT_SECONDS,
    )
    deterministic, errors = validate_command_evidence(
        deterministic_result,
        nonce=nonce,
        oracles=DETERMINISTIC_ORACLES,
        command_name="OpenAI deterministic contract test",
    )

    rate_card, live_input_errors = validate_live_inputs(command_env)
    errors.extend(live_input_errors)

    live: dict[str, dict[str, Any]] = {}
    live_result: CommandResult | None = None
    if not errors:
        live_result = run_bounded_command(
            CANARY_COMMAND,
            cwd=root,
            env=command_env,
            timeout_seconds=CANARY_TIMEOUT_SECONDS,
        )
        live, live_errors = validate_command_evidence(
            live_result,
            nonce=nonce,
            oracles=LIVE_ORACLES,
            command_name="OpenAI live canary",
        )
        errors.extend(live_errors)
        errors.extend(validate_live_context(live, command_env, rate_card))

    errors.extend(scan_artifacts(evidence_dir))
    diagnostics: dict[str, Any] = {
        "errors": errors,
        "deterministic_command": TEST_COMMAND,
        "deterministic_exit_code": deterministic_result.returncode,
        "deterministic_output_bytes": deterministic_result.output_bytes,
        "deterministic_output_sha256": deterministic_result.output_sha256,
        "deterministic_record_count": len(deterministic),
        "live_command": CANARY_COMMAND,
        "live_executed": live_result is not None,
        "live_exit_code": live_result.returncode if live_result else None,
        "live_output_bytes": live_result.output_bytes if live_result else 0,
        "live_output_sha256": live_result.output_sha256 if live_result else None,
        "live_record_count": len(live),
        "retention_mode_declared": bool(
            command_env.get(RETENTION_MODE_ENV)
        ),
        "retention_provenance_declared": bool(
            command_env.get(RETENTION_PROVENANCE_ENV)
        ),
        "rate_card_approved": bool(
            rate_card and rate_card.get("approved") is True
        ),
    }
    diagnostics_text, diagnostic_findings = _safe_diagnostics_text(diagnostics)
    if diagnostic_findings:
        errors.extend(diagnostic_findings)
    (evidence_dir / "p00-openai-diagnostics.json").write_text(
        diagnostics_text,
        encoding="utf-8",
    )

    if errors:
        for error in errors:
            if sentinel_findings(
                error.encode("utf-8"), "an evaluator error"
            ):
                error = "privacy sentinel detected; detail redacted"
            print(f"P00 OpenAI evaluation: {error}")
        return 1

    assert rate_card is not None
    summaries = {
        "P00-AI-001": ai_public_summary(deterministic, live),
        "P00-PRV-001": privacy_public_summary(live),
    }
    payloads: dict[str, str] = {}
    for requirement_id in requested:
        payload = {
            "requirement_id": requirement_id,
            "status": "pass",
            "test": "tools.evaluators.p00_openai.evaluate",
            "recorded_at": utc_now(),
            "details": {
                "diagnostics": "p00-openai-diagnostics.json",
                "public_summary": summaries[requirement_id],
            },
        }
        payload_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        findings = sentinel_findings(
            payload_text.encode("utf-8"),
            "prospective passing evidence",
        )
        if findings:
            for error in findings:
                print(f"P00 OpenAI evaluation: {error}")
            return 1
        payloads[requirement_id] = payload_text

    for requirement_id, payload_text in payloads.items():
        (evidence_dir / f"{requirement_id}.json").write_text(
            payload_text,
            encoding="utf-8",
        )
    return 0
