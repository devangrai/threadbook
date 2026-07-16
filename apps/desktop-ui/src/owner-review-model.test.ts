import { describe, expect, it } from "vitest";

import { verifyOwnerPreview } from "./owner-review-model";

describe("owner review model", () => {
  it("rejects preview length and digest mismatches before rendering", async () => {
    const response = {
      schema_version: 1 as const,
      request_id: "request-1",
      owner_review_id: "review-1",
      preview_id: "preview-1",
      media_type: "image/png" as const,
      width: 1,
      height: 1,
      byte_length: 1,
      bytes_sha256:
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      bytes: [],
    };

    await expect(verifyOwnerPreview(response)).rejects.toThrow(
      "Owner preview bytes are invalid.",
    );
    await expect(
      verifyOwnerPreview({
        ...response,
        byte_length: 0,
        bytes_sha256: "0".repeat(64),
      }),
    ).rejects.toThrow("Owner preview integrity check failed.");
  });
});
