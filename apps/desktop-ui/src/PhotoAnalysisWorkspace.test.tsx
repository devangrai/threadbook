import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PhotoAnalysisBridge } from "./photo-analysis-bridge";
import type { OwnerReviewBridge } from "./owner-review-bridge";
import type { ReconciliationBridge } from "./reconciliation-bridge";
import type {
  PhotoObservationV1,
  PhotoObservationStateV1,
  PhotoOwnerReviewV1,
  PhotoReviewActionV1,
  ReconciliationCaseV2,
} from "./generated/contracts";
import { PhotoAnalysisWorkspace } from "./PhotoAnalysisWorkspace";

const rootId = "90000000-0000-4000-8000-000000000010";
const scopeId = "90000000-0000-4000-8000-000000000011";
const observationId = "90000000-0000-4000-8000-000000000012";
const artifactId = "90000000-0000-4000-8000-000000000013";

describe("photo analysis workspace", { timeout: 15_000 }, () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.stubGlobal(
      "URL",
      Object.assign(URL, {
        createObjectURL: vi.fn(() => "blob:local-preview"),
        revokeObjectURL: vi.fn(),
      }),
    );
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("keeps listing inert, then explicitly freezes and analyzes", async () => {
    const bridge = testBridge();
    const owner = ownerTestBridge();
    const user = userEvent.setup();
    render(<PhotoAnalysisWorkspace bridge={bridge} ownerBridge={owner} />);

    const root = await screen.findByRole("radio", {
      name: /Folder 90000000/i,
    });
    await user.click(root);
    expect(bridge.createScope).not.toHaveBeenCalled();
    expect(bridge.analyzeScope).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Freeze scope" }));
    expect(await screen.findByText("Photo scope frozen.")).toBeInTheDocument();
    expect(screen.getByText("3", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText(/a{10}\.\.\.a{8}/i)).toBeInTheDocument();
    expect(bridge.analyzeScope).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Detect people" }));
    expect(owner.detectPeople).toHaveBeenCalledWith(scopeId);
    expect(bridge.analyzeScope).not.toHaveBeenCalled();
    await user.click(await screen.findByRole("radio", { name: "Person 1" }));
    await user.click(screen.getByRole("button", { name: "This is me" }));
    expect(
      await screen.findByText(/Segmentation unavailable: reviewed model pack absent/i),
    ).toBeInTheDocument();
    expect(bridge.readArtifact).toHaveBeenCalledWith(artifactId);
  });

  it("preserves a replacement draft on conflict and restores focus after review", async () => {
    let conflict = true;
    const bridge = testBridge({
      reviewObservation: vi.fn(async (
        _observationId: string,
        action: PhotoReviewActionV1,
      ) => {
        if (conflict) {
          conflict = false;
          throw { code: "request_conflict" };
        }
        return reviewResponse(action);
      }),
    });
    const owner = ownerTestBridge();
    const user = userEvent.setup();
    render(<PhotoAnalysisWorkspace bridge={bridge} ownerBridge={owner} />);

    await user.click(
      await screen.findByRole("radio", { name: /Folder 90000000/i }),
    );
    await user.click(screen.getByRole("button", { name: "Freeze scope" }));
    await user.click(screen.getByRole("button", { name: "Detect people" }));
    await user.click(await screen.findByRole("radio", { name: "Person 1" }));
    await user.click(screen.getByRole("button", { name: "This is me" }));
    await user.click(
      await screen.findByRole("button", { name: "Adjust rectangle" }),
    );
    const editor = screen.getByRole("spinbutton", { name: "X" });
    await user.clear(editor);
    await user.type(editor, "12");
    await user.click(screen.getByRole("button", { name: "Replace crop" }));

    expect(await screen.findByText(/rectangle is still here/i)).toBeInTheDocument();
    expect(screen.getByRole("spinbutton", { name: "X" })).toHaveValue(12);

    await user.click(screen.getByRole("button", { name: "Replace crop" }));
    await waitFor(() =>
      expect(bridge.reviewObservation).toHaveBeenLastCalledWith(
        observationId,
        "replace_crop",
        { x: 12, y: 20, width: 80, height: 100 },
        5,
      ),
    );
    expect(await screen.findByText("Photo crop replaced.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Review" })).toHaveFocus();
  });

  it("opens local matches only from an explicit confirmed-photo action", async () => {
    const observation = photoObservation();
    observation.state = "confirmed";
    observation.review_head = {
      state: "confirmed",
      decision: {
        decision_id: "decision-confirmed",
        observation_id: observationId,
        action: "confirm_crop",
        selected_artifact_id: artifactId,
        photo_revision: 5,
      },
    };
    const bridge = testBridge({
      listObservations: vi.fn(async (
        _scopeId: string,
        state: PhotoObservationStateV1,
      ) => ({
        schema_version: 1 as const,
        request_id: "request",
        scope_id: scopeId,
        state,
        observations: state === "needs_review" ? [observation] : [],
        total_count: state === "needs_review" ? 1 : 0,
        photo_revision: 5,
        evidence_generation: 4,
        next_cursor: null,
      })),
    });
    const reconciliation = reconciliationTestBridge();
    const owner = ownerTestBridge();
    const user = userEvent.setup();
    render(
      <PhotoAnalysisWorkspace
        bridge={bridge}
        ownerBridge={owner}
        reconciliation={reconciliation}
      />,
    );

    await user.click(
      await screen.findByRole("radio", { name: /Folder 90000000/i }),
    );
    await user.click(screen.getByRole("button", { name: "Freeze scope" }));
    await user.click(screen.getByRole("button", { name: "Detect people" }));
    await user.click(await screen.findByRole("radio", { name: "Person 1" }));
    await user.click(screen.getByRole("button", { name: "This is me" }));

    expect(reconciliation.openCase).not.toHaveBeenCalled();
    await user.click(
      screen.getByRole("button", { name: "Find local matches" }),
    );

    expect(reconciliation.openCase).toHaveBeenCalledTimes(1);
    expect(reconciliation.openCase).toHaveBeenCalledWith(
      observationId,
      artifactId,
      5,
      1,
    );
    expect(
      await screen.findByRole("heading", { name: "Local matches" }),
    ).toHaveFocus();
    expect(screen.getByText("Local match candidates ready.")).toBeInTheDocument();
  });
});

function testBridge(
  overrides: Partial<PhotoAnalysisBridge> = {},
): PhotoAnalysisBridge {
  const observation = photoObservation();
  return {
    listImportedRoots: vi.fn(async () => ({
      schema_version: 1 as const,
      request_id: "request",
      roots: [
        {
          import_root_id: rootId,
          completed_scan_id: "scan-1",
          manifest_generation: 7,
          member_count: 3,
          eligible_count: 2,
          quarantined_count: 1,
        },
      ],
      total_count: 1,
      evidence_generation: 4,
      next_cursor: null,
    })),
    createScope: vi.fn(async () => ({
      schema_version: 1 as const,
      request_id: "request",
      scope: scopeFixture(),
      replay_status: "created" as const,
    })),
    analyzeScope: vi.fn(async () => runFixture()),
    listObservations: vi.fn(async (
      _scopeId: string,
      state: PhotoObservationStateV1,
    ) => ({
      schema_version: 1 as const,
      request_id: "request",
      scope_id: scopeId,
      state,
      observations: state === "needs_review" ? [observation] : [],
      total_count: state === "needs_review" ? 1 : 0,
      photo_revision: 5,
      evidence_generation: 4,
      next_cursor: null,
    })),
    readArtifact: vi.fn(async () => ({
      artifactId,
      mediaType: "image/png",
      width: 2,
      height: 2,
      bytes: new Uint8Array(),
    })),
    promptObservation: vi.fn(async () => ({
      schema_version: 1 as const,
      request_id: "request",
      observation,
      photo_revision: 5,
      evidence_generation: 4,
      replay_status: "created" as const,
    })),
    reviewObservation: vi.fn(async (
      _observationId: string,
      action: PhotoReviewActionV1,
    ) => reviewResponse(action)),
    ...overrides,
  };
}

function ownerTestBridge(): OwnerReviewBridge {
  const review = ownerReviewFixture();
  return {
    detectPeople: vi.fn(async () => ({
      schema_version: 1 as const,
      request_id: "request",
      scope_id: scopeId,
      run_id: "detection-run",
      state: "completed" as const,
      member_count: 3,
      completed_count: 3,
      terminal_review_count: 1,
      instances_available_count: 1,
      no_person_detected_count: 0,
      overflow_count: 0,
      retryable_failure_count: 0,
      permanent_unavailable_count: 0,
      skipped_count: 2,
      photo_revision: 4,
      owner_revision: 0,
      evidence_generation: 4,
      replay_status: "created" as const,
    })),
    listReviews: vi.fn(async (state) => ({
      schema_version: 1 as const,
      request_id: "request",
      state,
      reviews: state === "instances_available" ? [review] : [],
      next_cursor: null,
      photo_revision: 4,
      owner_revision: 0,
    })),
    readPreview: vi.fn(async () => ({
      ownerReviewId: review.owner_review_id,
      previewId: review.preview_id,
      mediaType: "image/png",
      width: 200,
      height: 200,
      bytes: new Uint8Array(),
    })),
    decideOwner: vi.fn(async () => ({
      schema_version: 1 as const,
      request_id: "request",
      review: { ...review, owner_head_revision: 1, photo_revision: 5 },
      decision: {
        owner_decision_id: "owner-decision-1",
        owner_review_id: review.owner_review_id,
        action: "select_person" as const,
        selected_person_instance_id: "person-1",
        supersedes_owner_decision_id: null,
        detection_revision: 1,
        owner_revision: 1,
        photo_revision: 5,
      },
      replay_status: "created" as const,
    })),
    correctOwner: vi.fn(),
    correctDetection: vi.fn(),
    retryDetection: vi.fn(),
  };
}

function ownerReviewFixture(): PhotoOwnerReviewV1 {
  return {
    owner_review_id: "owner-review-1",
    source_revision_id: "revision-1",
    source_revision_sha256: "b".repeat(64),
    preview_id: "owner-preview-1",
    terminal_attempt_id: "detection-attempt-1",
    terminal_detection_state: "succeeded_instances",
    state: "instances_available",
    instances: [
      {
        person_instance_id: "person-1",
        owner_review_id: "owner-review-1",
        source_revision_id: "revision-1",
        source_revision_sha256: "b".repeat(64),
        source_kind: "apple_vision",
        rectangle: { x: 10, y: 20, width: 80, height: 100 },
        confidence_basis_points: 9500,
        provider_revision: "apple-vision-human-rectangles-v1",
      },
    ],
    provider_contract_revision: "local-person-detection-v1",
    provider_revision: "apple-vision-human-rectangles-v1",
    preprocessing_revision: "canonical-srgb-orientation-v1",
    vision_request_revision: 1,
    safe_reason_code: null,
    detection_revision: 1,
    owner_head_revision: 0,
    photo_revision: 4,
  };
}

function scopeFixture() {
  return {
    scope_id: scopeId,
    import_root_id: rootId,
    completed_scan_id: "scan-1",
    manifest_generation: 7,
    member_count: 3,
    eligible_count: 2,
    quarantined_count: 1,
    membership_sha256: "a".repeat(64),
  };
}

function runFixture() {
  return {
    schema_version: 1 as const,
    request_id: "request",
    scope_id: scopeId,
    run_id: "run-1",
    state: "completed" as const,
    member_count: 3,
    completed_count: 3,
    needs_review_count: 1,
    skipped_count: 1,
    failed_count: 0,
    photo_revision: 5,
    evidence_generation: 4,
    replay_status: "created" as const,
  };
}

function photoObservation(): PhotoObservationV1 {
  return {
    observation_id: observationId,
    scope_id: scopeId,
    source_revision_id: "revision-1",
    state: "needs_review",
    artifact: {
      artifact_id: artifactId,
      kind: "rectangle_source_crop",
      artifact_schema_revision: "rectangle-source-crop-v1",
      artifact_revision: "crop-v1",
      scope_id: scopeId,
      source_revision_id: "revision-1",
      source_revision_sha256: "b".repeat(64),
      input_blob_sha256: "c".repeat(64),
      media_type: "image/png",
      source_width: 200,
      source_height: 200,
      rectangle: { x: 10, y: 20, width: 80, height: 100 },
      preprocessing_revision: "srgb-v1",
      provider_contract_revision: "garment-segmentation-v1",
      provider_id: "unavailable-local",
      provider_revision: "1",
      model_revision: null,
      request_mode: "automatic",
      prompt_parameters_sha256: "d".repeat(64),
      quality_gate_revision: "quality-v1",
      quality_approved: false,
      segmentation_outcome: "unavailable",
      unavailable_reason: "reviewed_model_pack_absent",
      failure_code: null,
      parent_artifact_ids: [],
      provenance_sha256: "e".repeat(64),
      artifact_sha256: "f".repeat(64),
    },
    review_head: null,
  };
}

function reviewResponse(action: PhotoReviewActionV1) {
  const observation = photoObservation();
  observation.state = action === "replace_crop" ? "replaced" : "confirmed";
  return {
    schema_version: 1 as const,
    request_id: "request",
    observation,
    decision: {
      decision_id: "decision-1",
      observation_id: observationId,
      action,
      selected_artifact_id: artifactId,
      photo_revision: 6,
    },
    new_photo_revision: 6,
    replay_status: "created" as const,
  };
}

function reconciliationTestBridge(): ReconciliationBridge {
  return {
    openCase: vi.fn(async () => ({
      schema_version: 2 as const,
      request_id: "request",
      case: reconciliationCase(),
      evidence_generation: 4,
      photo_revision: 5,
      owner_revision: 1,
      reconciliation_revision: 1,
      replay_status: "created" as const,
    })),
    listCases: vi.fn(async () => ({
      schema_version: 2 as const,
      request_id: "request",
      observation_id: observationId,
      state: "all" as const,
      cases: [],
      next_cursor: null,
      photo_revision: 5,
      owner_revision: 1,
      reconciliation_revision: 0,
    })),
    decideCase: vi.fn(),
  };
}

function reconciliationCase(): ReconciliationCaseV2 {
  return {
    case_id: "92000000-0000-4000-8000-000000000001",
    observation_id: observationId,
    artifact_id: artifactId,
    artifact_sha256: "f".repeat(64),
    observation_date: "2026-07-15",
    retrieval_revision: "local-reconciliation-v1",
    candidates: [
      {
        candidate_id: "92000000-0000-4000-8000-000000000002",
        target: { kind: "wardrobe_item", item_id: "item-1" },
        proposed_relation: "same_physical_item",
        observed_relations: ["visual_similarity"],
        rank: 1,
        display_name: "White Oxford shirt",
        detail: "White cotton",
        date: { kind: "catalog_created", value: "2026-06-01" },
        evidence: [],
      },
      {
        candidate_id: "92000000-0000-4000-8000-000000000003",
        target: { kind: "no_match" },
        proposed_relation: null,
        observed_relations: [],
        rank: null,
        display_name: "No match",
        detail: "None of the local candidates",
        date: null,
        evidence: [],
      },
    ],
    leading_candidate_id: "92000000-0000-4000-8000-000000000002",
    decision_head: null,
    case_revision: 1,
    owner_decision_id: "owner-decision-1",
    person_instance_id: "person-1",
    owner_evidence_sha256: "6".repeat(64),
    owner_revision: 1,
    crop_decision_id: "decision-confirmed",
    crop_revision: 5,
    source_revision_sha256: "b".repeat(64),
    authority_state: "open_eligible",
    authority_reason: "current_authority",
    created_at_ms: 1,
  };
}
