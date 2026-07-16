#!/usr/bin/env python3
"""Generate the reviewed non-personal PhotoKit acceptance fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib


WIDTH = 96
HEIGHT = 96
SCHEMA_VERSION = 1
GENERATOR_REVISION = "p00-photokit-fixtures-v1"

GLYPHS = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "C": ("01111", "10000", "10000", "10000", "10000", "10000", "01111"),
    "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
    "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
}


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _draw_label(
    pixels: list[list[tuple[int, int, int]]],
    label: str,
    *,
    foreground: tuple[int, int, int],
) -> None:
    scale = 3
    spacing = scale
    glyph_width = 5 * scale
    total_width = len(label) * glyph_width + (len(label) - 1) * spacing
    origin_x = (WIDTH - total_width) // 2
    origin_y = (HEIGHT - 7 * scale) // 2
    for glyph_index, character in enumerate(label):
        glyph = GLYPHS[character]
        offset_x = origin_x + glyph_index * (glyph_width + spacing)
        for row, bits in enumerate(glyph):
            for column, bit in enumerate(bits):
                if bit != "1":
                    continue
                for dy in range(scale):
                    for dx in range(scale):
                        pixels[origin_y + row * scale + dy][
                            offset_x + column * scale + dx
                        ] = foreground


def _pixels(role: str) -> list[list[tuple[int, int, int]]]:
    if role == "local":
        first = (245, 72, 126)
        second = (255, 211, 65)
        label = "LOCAL"
    elif role == "cloud":
        first = (40, 184, 212)
        second = (70, 82, 168)
        label = "CLOUD"
    else:
        raise ValueError("unknown fixture role")

    pixels = []
    for y in range(HEIGHT):
        row = []
        for x in range(WIDTH):
            color = first if ((x // 12) + (y // 12)) % 2 == 0 else second
            if x < 4 or y < 4 or x >= WIDTH - 4 or y >= HEIGHT - 4:
                color = (20, 20, 20)
            row.append(color)
        pixels.append(row)
    _draw_label(pixels, label, foreground=(255, 255, 255))
    return pixels


def fixture_bytes(role: str) -> bytes:
    rows = bytearray()
    for row in _pixels(role):
        rows.append(0)
        for red, green, blue in row:
            rows.extend((red, green, blue))
    header = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", WIDTH, HEIGHT, 8, 2, 0, 0, 0)
    return (
        header
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", zlib.compress(bytes(rows), level=9))
        + _chunk(b"IEND", b"")
    )


def build_manifest() -> dict[str, object]:
    fixtures = []
    for role in ("local", "cloud"):
        payload = fixture_bytes(role)
        fixtures.append(
            {
                "fixture_id": f"p00-synthetic-{role}-v1",
                "role": role,
                "filename": f"{role}.png",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "byte_count": len(payload),
                "pixel_width": WIDTH,
                "pixel_height": HEIGHT,
                "mime_type": "image/png",
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "generator_revision": GENERATOR_REVISION,
        "nonpersonal_provenance": (
            "dedicated_nonpersonal_synthetic_photos_library_v1"
        ),
        "fixtures": fixtures,
    }


def generate(output: Path) -> None:
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = build_manifest()
    for fixture in manifest["fixtures"]:
        assert isinstance(fixture, dict)
        role = fixture["role"]
        filename = fixture["filename"]
        assert isinstance(role, str) and isinstance(filename, str)
        (output / filename).write_bytes(fixture_bytes(role))
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    generate(arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
