#!/usr/bin/env python3
"""Run the frozen P03 corpus test and emit one bounded JSON quality report."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time


APPROVED_CORPUS_SHA256 = (
    "a13dc0d6a28308ab01232b800f23a77119479cde4fe9db44f05a3102a69a5cac"
)
MAX_CORPUS_BYTES = 96 * 1024
MAX_CHILD_OUTPUT_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 10 * 60
METRICS = re.compile(
    rb"receipt corpus: matched=(\d+) gold=(\d+) recall=(\d+\.\d+) "
    rb"unsupported_failures=(\d+) citation_failures=(\d+)"
)


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


def _run(root: Path) -> tuple[int, bytes, bool, bool]:
    command = [
        "cargo",
        "test",
        "-p",
        "wardrobe-platform",
        "--offline",
        "--test",
        "receipt_parser_provider",
        "frozen_corpus_has_full_recall_valid_citations_and_no_unsupported_fabrication",
        "--",
        "--exact",
        "--nocapture",
    ]
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError:
        return 127, b"", False, False

    assert process.stdout is not None
    output = bytearray()
    exceeded = False
    timed_out = False
    deadline = time.monotonic() + TIMEOUT_SECONDS
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
                if len(output) + len(chunk) <= MAX_CHILD_OUTPUT_BYTES:
                    output.extend(chunk)
                else:
                    exceeded = True
                    _terminate(process)
                continue
        if process.poll() is not None:
            chunk = os.read(process.stdout.fileno(), 64 * 1024)
            if chunk:
                if len(output) + len(chunk) <= MAX_CHILD_OUTPUT_BYTES:
                    output.extend(chunk)
                else:
                    exceeded = True
                continue
            break
    process.stdout.close()
    return process.returncode, bytes(output), exceeded, timed_out


def _manifest_summary(root: Path) -> tuple[int, int, int]:
    path = root / "fixtures/receipts/v1/manifest.json"
    with path.open("rb") as handle:
        data = handle.read(MAX_CORPUS_BYTES + 1)
    if len(data) > MAX_CORPUS_BYTES:
        raise ValueError("oversized corpus")
    if hashlib.sha256(data).hexdigest() != APPROVED_CORPUS_SHA256:
        raise ValueError("unapproved corpus")
    manifest = json.loads(data)
    messages = manifest["messages"]
    lines = sum(len(message["expected"]["lines"]) for message in messages)
    coverage = {
        item for message in messages for item in message["coverage"]
    }
    return len(messages), lines, len(coverage)


def main() -> int:
    root = Path.cwd()
    try:
        message_count, gold_lines, coverage_count = _manifest_summary(root)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return 2

    returncode, output, exceeded, timed_out = _run(root)
    if returncode != 0 or exceeded or timed_out:
        return 1
    matches = METRICS.findall(output)
    if len(matches) != 1:
        return 1
    matched, gold, recall, unsupported, citations = matches[0]
    if b"test result: ok." not in output or b"1 passed" not in output:
        return 1

    report = {
        "schema_version": 1,
        "status": "pass",
        "test_name": (
            "frozen_corpus_has_full_recall_valid_citations_and_no_"
            "unsupported_fabrication"
        ),
        "corpus_sha256": APPROVED_CORPUS_SHA256,
        "message_count": message_count,
        "coverage_count": coverage_count,
        "matched_lines": int(matched),
        "gold_lines": int(gold),
        "manifest_gold_lines": gold_lines,
        "recall": float(recall),
        "spurious_lines": 0,
        "unsupported_field_failures": int(unsupported),
        "citation_failures": int(citations),
        "parser_revision": "mail-parser-0.11.5/receipt-parser-v1",
        "sanitizer_revision": "html5ever-0.38/receipt-sanitizer-v1",
        "provider_id": "local-deterministic-receipt-provider",
        "provider_revision": "local-deterministic-receipt-provider-v1",
        "schema_revision": "receipt-extraction-v1",
        "ruleset_revision": "explicit-receipt-evidence-rules-v1",
    }
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 4096:
        return 1
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
