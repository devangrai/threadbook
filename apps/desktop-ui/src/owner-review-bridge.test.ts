import { describe, expect, it, vi } from "vitest";

import type { InvokeCommand } from "@wardrobe/invoke-transport";
import { createOwnerReviewBridge } from "./owner-review-bridge";
import type { PhotoOwnerReviewV1 } from "./generated/contracts";

const requestId = "92000000-0000-4000-8000-000000000001";

describe("owner review bridge", () => {
  it("uses every owner command and hash-verifies previews", async () => {
    const invokeMock = vi.fn(async (command: string) => {
      if (command === "read_photo_owner_preview_v1") {
        return {
          schema_version: 1,
          request_id: requestId,
          owner_review_id: "review-1",
          preview_id: "preview-1",
          media_type: "image/png",
          width: 1,
          height: 1,
          byte_length: 0,
          bytes_sha256:
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          bytes: [],
        };
      }
      return {};
    });
    const bridge = createOwnerReviewBridge(
      invokeMock as unknown as InvokeCommand,
      () => requestId,
    );
    const review = reviewFixture();
    const rectangle = { x: 2, y: 3, width: 40, height: 50 };

    await bridge.detectPeople("scope-1");
    await bridge.listReviews("instances_available", "cursor-1", 12);
    await bridge.readPreview("review-1", "preview-1");
    await bridge.decideOwner(review, "select_person", "person-1");
    await bridge.correctOwner(
      review,
      "decision-1",
      "owner_absent",
      null,
    );
    await bridge.correctDetection(review, rectangle);
    await bridge.retryDetection(review);

    expect(invokeMock.mock.calls.map(([command]) => command)).toEqual([
      "detect_photo_scope_people_v1",
      "list_photo_owner_reviews_v1",
      "read_photo_owner_preview_v1",
      "decide_photo_owner_v1",
      "correct_photo_owner_v1",
      "correct_photo_person_detection_v1",
      "retry_photo_person_detection_v1",
    ]);
    expect(invokeMock).toHaveBeenNthCalledWith(
      4,
      "decide_photo_owner_v1",
      {
        request: {
          schema_version: 1,
          request_id: requestId,
          owner_review_id: "review-1",
          action: "select_person",
          selected_person_instance_id: "person-1",
          expected_detection_revision: 4,
          expected_owner_head_revision: 2,
          expected_photo_revision: 9,
        },
      },
    );
    expect(invokeMock).toHaveBeenNthCalledWith(
      6,
      "correct_photo_person_detection_v1",
      {
        request: {
          schema_version: 1,
          request_id: requestId,
          owner_review_id: "review-1",
          manual_rectangle: rectangle,
          expected_terminal_attempt_id: "attempt-1",
          expected_detection_revision: 4,
          expected_owner_head_revision: 2,
          expected_photo_revision: 9,
        },
      },
    );
  });
});

function reviewFixture(): PhotoOwnerReviewV1 {
  return {
    owner_review_id: "review-1",
    source_revision_id: "source-1",
    source_revision_sha256: "a".repeat(64),
    preview_id: "preview-1",
    terminal_attempt_id: "attempt-1",
    terminal_detection_state: "succeeded_instances",
    state: "instances_available",
    instances: [
      {
        person_instance_id: "person-1",
        owner_review_id: "review-1",
        source_revision_id: "source-1",
        source_revision_sha256: "a".repeat(64),
        source_kind: "apple_vision",
        rectangle: { x: 10, y: 12, width: 80, height: 120 },
        confidence_basis_points: 9400,
        provider_revision: "apple-vision-human-rectangles-v1",
      },
    ],
    provider_contract_revision: "local-person-detection-v1",
    provider_revision: "apple-vision-human-rectangles-v1",
    preprocessing_revision: "canonical-srgb-orientation-v1",
    vision_request_revision: 1,
    safe_reason_code: null,
    detection_revision: 4,
    owner_head_revision: 2,
    photo_revision: 9,
  };
}
