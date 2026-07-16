import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { OwnerReviewBridge } from "./owner-review-bridge";
import type {
  PhotoOwnerReviewStateV1,
  PhotoOwnerReviewV1,
} from "./generated/contracts";
import { OwnerReviewWorkspace } from "./OwnerReviewWorkspace";

describe("owner review workspace", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "URL",
      Object.assign(URL, {
        createObjectURL: vi.fn(() => "blob:owner-preview"),
        revokeObjectURL: vi.fn(),
      }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("supports keyboard selection, absence, and owner correction", async () => {
    const bridge = testBridge();
    const onAuthorityChange = vi.fn(async () => undefined);
    const user = userEvent.setup();
    render(
      <OwnerReviewWorkspace
        scopeId="scope-1"
        bridge={bridge}
        onAuthorityChange={onAuthorityChange}
      />,
    );

    const person = await screen.findByRole("radio", { name: "Person 1" });
    person.focus();
    await user.keyboard(" ");
    await user.click(screen.getByRole("button", { name: "This is me" }));

    expect(bridge.decideOwner).toHaveBeenCalledWith(
      expect.objectContaining({ owner_review_id: "review-1" }),
      "select_person",
      "person-1",
    );
    expect(onAuthorityChange).toHaveBeenCalledWith(3, true);
    expect(await screen.findByText("Owner confirmed")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Change owner" }));
    await user.click(
      screen.getByRole("button", { name: "I'm not in this photo" }),
    );
    expect(bridge.correctOwner).toHaveBeenCalledWith(
      expect.objectContaining({ owner_review_id: "review-1" }),
      "decision-1",
      "owner_absent",
      null,
    );
    expect(await screen.findByText("Owner absent")).toBeInTheDocument();
  });

  it("preserves a keyboard-entered missed-person rectangle on conflict", async () => {
    const bridge = testBridge({
      correctDetection: vi.fn(async () => {
        throw { code: "request_conflict" };
      }),
    });
    const user = userEvent.setup();
    render(
      <OwnerReviewWorkspace
        scopeId="scope-1"
        bridge={bridge}
        onAuthorityChange={vi.fn()}
      />,
    );

    await screen.findByRole("radio", { name: "Person 1" });
    await user.click(screen.getByRole("button", { name: "Person missed" }));
    const x = screen.getByRole("spinbutton", { name: "X" });
    await user.clear(x);
    await user.type(x, "11");
    const width = screen.getByRole("spinbutton", { name: "Width" });
    await user.clear(width);
    await user.type(width, "100");
    await user.click(screen.getByRole("button", { name: "Add person" }));

    expect(await screen.findByText(/selection is still here/i)).toBeInTheDocument();
    expect(screen.getByRole("spinbutton", { name: "X" })).toHaveValue(11);
  });

  it("retries only explicit failure reviews and reruns local detection", async () => {
    const bridge = testBridge();
    const user = userEvent.setup();
    render(
      <OwnerReviewWorkspace
        scopeId="scope-1"
        bridge={bridge}
        onAuthorityChange={vi.fn()}
      />,
    );

    await screen.findByRole("radio", { name: "Person 1" });
    await user.click(screen.getByRole("button", { name: "Needs retry" }));
    await user.click(
      await screen.findByRole("button", { name: "Retry detection" }),
    );

    await waitFor(() =>
      expect(bridge.retryDetection).toHaveBeenCalledTimes(1),
    );
    expect(bridge.detectPeople).toHaveBeenCalledWith("scope-1");
    expect(await screen.findByText("Person detection retried.")).toBeInTheDocument();
  });
});

function testBridge(
  overrides: Partial<OwnerReviewBridge> = {},
): OwnerReviewBridge {
  return {
    detectPeople: vi.fn(async () => detectionResponse()),
    listReviews: vi.fn(async (state: PhotoOwnerReviewStateV1) => ({
      schema_version: 1 as const,
      request_id: "request",
      state,
      reviews:
        state === "instances_available"
          ? [reviewFixture()]
          : state === "retryable_failure"
            ? [failureReview()]
            : [],
      next_cursor: null,
      photo_revision: 9,
      owner_revision: 2,
    })),
    readPreview: vi.fn(async () => ({
      ownerReviewId: "review-1",
      previewId: "preview-1",
      mediaType: "image/png",
      width: 200,
      height: 200,
      bytes: new Uint8Array(),
    })),
    decideOwner: vi.fn(async (review) => ({
      schema_version: 1 as const,
      request_id: "request",
      review: { ...review, owner_head_revision: 3, photo_revision: 10 },
      decision: {
        owner_decision_id: "decision-1",
        owner_review_id: review.owner_review_id,
        action: "select_person" as const,
        selected_person_instance_id: "person-1",
        supersedes_owner_decision_id: null,
        detection_revision: 4,
        owner_revision: 3,
        photo_revision: 10,
      },
      replay_status: "created" as const,
    })),
    correctOwner: vi.fn(async (review) => ({
      schema_version: 1 as const,
      request_id: "request",
      review: { ...review, owner_head_revision: 4, photo_revision: 11 },
      decision: {
        owner_decision_id: "decision-2",
        owner_review_id: review.owner_review_id,
        action: "owner_absent" as const,
        selected_person_instance_id: null,
        supersedes_owner_decision_id: "decision-1",
        detection_revision: 4,
        owner_revision: 4,
        photo_revision: 11,
      },
      replay_status: "created" as const,
    })),
    correctDetection: vi.fn(async (review, manualRectangle) => {
      const instance = {
        person_instance_id: "person-2",
        owner_review_id: review.owner_review_id,
        source_revision_id: review.source_revision_id,
        source_revision_sha256: review.source_revision_sha256,
        source_kind: "manual_user_rectangle" as const,
        rectangle: manualRectangle,
        confidence_basis_points: null,
        provider_revision: null,
      };
      return {
        schema_version: 1 as const,
        request_id: "request",
        review: {
          ...review,
          instances: [...review.instances, instance],
          detection_revision: review.detection_revision + 1,
          photo_revision: review.photo_revision + 1,
        },
        instance,
        replay_status: "created" as const,
      };
    }),
    retryDetection: vi.fn(async (review) => ({
      schema_version: 1 as const,
      request_id: "request",
      owner_review_id: review.owner_review_id,
      detection_revision: review.detection_revision + 1,
      owner_revision: review.owner_head_revision,
      photo_revision: review.photo_revision + 1,
      replay_status: "created" as const,
    })),
    ...overrides,
  };
}

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
        rectangle: { x: 10, y: 20, width: 80, height: 120 },
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

function failureReview(): PhotoOwnerReviewV1 {
  return {
    ...reviewFixture(),
    owner_review_id: "review-failure",
    preview_id: "preview-failure",
    terminal_attempt_id: "attempt-failure",
    terminal_detection_state: "retryable_failure",
    state: "retryable_failure",
    instances: [],
    safe_reason_code: "vision_request_failed",
  };
}

function detectionResponse() {
  return {
    schema_version: 1 as const,
    request_id: "request",
    scope_id: "scope-1",
    run_id: "run-1",
    state: "completed" as const,
    member_count: 1,
    completed_count: 1,
    terminal_review_count: 1,
    instances_available_count: 1,
    no_person_detected_count: 0,
    overflow_count: 0,
    retryable_failure_count: 0,
    permanent_unavailable_count: 0,
    skipped_count: 0,
    photo_revision: 9,
    owner_revision: 2,
    evidence_generation: 4,
    replay_status: "created" as const,
  };
}
