import { describe, expect, it } from "vitest";

import type { ReadPhotoArtifactV1Response } from "./generated/contracts";
import {
  abbreviateHash,
  parseRectangleDraft,
  verifyPhotoArtifact,
} from "./photo-analysis-model";

describe("photo analysis model", () => {
  it("validates keyboard rectangle bounds", () => {
    expect(
      parseRectangleDraft(
        { x: "10", y: "20", width: "30", height: "40" },
        100,
        100,
      ),
    ).toEqual({
      rectangle: { x: 10, y: 20, width: 30, height: 40 },
      error: null,
    });
    expect(
      parseRectangleDraft(
        { x: "90", y: "20", width: "30", height: "40" },
        100,
        100,
      ).error,
    ).toContain("fit within");
    expect(
      parseRectangleDraft(
        { x: "1.5", y: "0", width: "2", height: "2" },
        100,
        100,
      ).error,
    ).toContain("whole numbers");
  });

  it("verifies preview bytes before returning them", async () => {
    const response: ReadPhotoArtifactV1Response = {
      schema_version: 1,
      request_id: "request",
      artifact_id: "artifact",
      media_type: "image/png",
      width: 1,
      height: 1,
      bytes_sha256:
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      bytes: [],
    };
    await expect(verifyPhotoArtifact(response)).resolves.toEqual(
      expect.objectContaining({ artifactId: "artifact", bytes: new Uint8Array() }),
    );
    await expect(
      verifyPhotoArtifact({ ...response, bytes_sha256: "0".repeat(64) }),
    ).rejects.toThrow("integrity");
  });

  it("abbreviates membership hashes without exposing other metadata", () => {
    expect(abbreviateHash("a".repeat(64))).toBe(
      `${"a".repeat(10)}...${"a".repeat(8)}`,
    );
  });
});
