import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  DecideReconciliationCaseV2Response,
  ReconciliationCaseV2,
  ReconciliationOutcomeV1,
} from "./generated/contracts";
import type { ReconciliationBridge } from "./reconciliation-bridge";
import { ReconciliationPanel } from "./ReconciliationPanel";

afterEach(cleanup);

describe("reconciliation panel", { timeout: 15_000 }, () => {
  it("shows alternatives, dates, evidence groups, and records all five outcomes", async () => {
    const bridge = testBridge();
    const user = userEvent.setup();
    render(
      <ReconciliationPanel
        reconciliationCase={caseFixture()}
        photoRevision={20}
        ownerRevision={8}
        reconciliationRevision={10}
        bridge={bridge}
      />,
    );

    expect(screen.getByText("Leading candidate")).toBeInTheDocument();
    expect(screen.getAllByText("Alternative")).toHaveLength(2);
    expect(screen.getByText("Catalog date 2026-05-12")).toBeInTheDocument();
    expect(screen.getByText("Purchase date 2026-04-03")).toBeInTheDocument();
    expect(screen.getByText("Date unknown")).toBeInTheDocument();
    expect(screen.getByText("Explicit no match")).toBeInTheDocument();
    expect(
      screen.getAllByRole("heading", { name: "Supporting" }),
    ).not.toHaveLength(0);
    expect(
      screen.getAllByRole("heading", { name: "Contradictory" }),
    ).not.toHaveLength(0);
    expect(
      screen.getAllByRole("heading", { name: "Neutral" }),
    ).not.toHaveLength(0);
    expect(
      screen.getByText(/Catalog image evidence revision catalog-r8/i),
    ).toBeInTheDocument();

    await user.click(
      screen.getByRole("button", { name: "Same wardrobe item" }),
    );
    await waitFor(() =>
      expect(screen.getByText(/Current decision: Same wardrobe item/i)).toHaveFocus(),
    );

    await user.click(
      screen.getByRole("radio", { name: /Merino overshirt/i }),
    );
    await user.click(
      screen.getByRole("button", { name: "Same product variant" }),
    );
    await user.click(screen.getByRole("button", { name: "Different" }));

    await user.click(screen.getByRole("radio", { name: /^No match/i }));
    await user.click(screen.getByRole("button", { name: "No match" }));
    await user.click(screen.getByRole("button", { name: "Unresolved" }));

    expect(bridge.decideCase).toHaveBeenCalledTimes(5);
    expect(bridge.decideCase.mock.calls.map((call) => call.slice(1, 3))).toEqual([
      ["same_item", "candidate-wardrobe"],
      ["same_variant", "candidate-receipt"],
      ["different", "candidate-receipt"],
      ["no_match", "candidate-no-match"],
      ["unresolved", null],
    ]);
  });

  it("preserves the selected candidate when a decision conflicts", async () => {
    const bridge = testBridge({
      decideCase: vi.fn(async () => {
        throw { code: "request_conflict" };
      }),
    });
    const user = userEvent.setup();
    render(
      <ReconciliationPanel
        reconciliationCase={caseFixture()}
        photoRevision={20}
        ownerRevision={8}
        reconciliationRevision={10}
        bridge={bridge}
      />,
    );

    const receipt = screen.getByRole("radio", {
      name: /Merino overshirt/i,
    });
    await user.click(receipt);
    await user.click(screen.getByRole("button", { name: "Different" }));

    expect(
      await screen.findByText(/candidate selection is still here/i),
    ).toBeInTheDocument();
    expect(receipt).toBeChecked();
    expect(bridge.decideCase).toHaveBeenCalledTimes(1);
  });

  it("dispatches only once while a decision is in flight", () => {
    const decideCase = vi.fn(
      () => new Promise<DecideReconciliationCaseV2Response>(() => undefined),
    );
    const bridge = testBridge({ decideCase });
    render(
      <ReconciliationPanel
        reconciliationCase={caseFixture()}
        photoRevision={20}
        ownerRevision={8}
        reconciliationRevision={10}
        bridge={bridge}
      />,
    );

    const button = screen.getByRole("button", {
      name: "Same wardrobe item",
    });
    act(() => {
      button.click();
      button.click();
    });

    expect(decideCase).toHaveBeenCalledTimes(1);
  });
});

function testBridge(
  overrides: Partial<ReconciliationBridge> = {},
): ReconciliationBridge & {
  decideCase: ReturnType<typeof vi.fn>;
} {
  let current = caseFixture();
  const decideCase = vi.fn(async (
    _caseId: string,
    outcome: ReconciliationOutcomeV1,
    selectedCandidateId: string | null,
    expectedCaseRevision: number,
  ) => {
    current = {
      ...current,
      case_revision: expectedCaseRevision + 1,
      decision_head: {
        decision_id: `decision-${expectedCaseRevision + 1}`,
        case_id: current.case_id,
        outcome,
        selected_candidate_id: selectedCandidateId,
        case_revision: expectedCaseRevision + 1,
      },
    };
    return {
      schema_version: 2 as const,
      request_id: "request",
      case: current,
      decision: current.decision_head,
      photo_revision: 20,
      owner_revision: 8,
      reconciliation_revision: expectedCaseRevision + 10,
      replay_status: "created" as const,
    };
  });
  return {
    openCase: vi.fn(),
    listCases: vi.fn(),
    decideCase,
    ...overrides,
  } as ReconciliationBridge & {
    decideCase: ReturnType<typeof vi.fn>;
  };
}

function caseFixture(): ReconciliationCaseV2 {
  return {
    case_id: "case-1",
    observation_id: "observation-1",
    artifact_id: "artifact-1",
    artifact_sha256: "a".repeat(64),
    observation_date: "2026-07-14",
    retrieval_revision: "local-reconciliation-v1",
    candidates: [
      {
        candidate_id: "candidate-receipt",
        target: {
          kind: "receipt_line",
          order_line_id: "line-1",
          variant_evidence_id: "variant-1",
        },
        proposed_relation: "same_product_variant",
        observed_relations: [],
        rank: 2,
        display_name: "Merino overshirt",
        detail: "Northstar Outfitters",
        date: { kind: "purchase", value: "2026-04-03" },
        evidence: [
          {
            evidence_id: "evidence-neutral",
            polarity: "neutral",
            relation: "same_product_variant",
            feature: "receipt_review_state",
            source_kind: "receipt_review_decision",
            source_id: "receipt-review",
            source_revision: "receipt-r11",
            input_sha256: ["b".repeat(64)],
            extractor_id: "local-reconciliation-v1",
            extractor_revision: "1",
            value_code: "confirmed",
            measured_value: null,
          },
        ],
      },
      {
        candidate_id: "candidate-no-date",
        target: { kind: "wardrobe_item", item_id: "item-2" },
        proposed_relation: "same_physical_item",
        observed_relations: [],
        rank: 3,
        display_name: "Navy field shirt",
        detail: "No comparison image",
        date: null,
        evidence: [],
      },
      {
        candidate_id: "candidate-no-match",
        target: { kind: "no_match" },
        proposed_relation: null,
        observed_relations: [],
        rank: null,
        display_name: "No match",
        detail: "None of the local candidates",
        date: null,
        evidence: [],
      },
      {
        candidate_id: "candidate-wardrobe",
        target: { kind: "wardrobe_item", item_id: "item-1" },
        proposed_relation: "same_physical_item",
        observed_relations: ["visual_similarity"],
        rank: 1,
        display_name: "White Oxford shirt",
        detail: "White cotton",
        date: { kind: "catalog_created", value: "2026-05-12" },
        evidence: [
          {
            evidence_id: "evidence-supporting",
            polarity: "supporting",
            relation: "visual_similarity",
            feature: "difference_hash_distance",
            source_kind: "catalog_image_evidence",
            source_id: "catalog-image",
            source_revision: "catalog-r8",
            input_sha256: ["c".repeat(64), "d".repeat(64)],
            extractor_id: "local-visual-features-v1",
            extractor_revision: "1",
            value_code: "distance_measured",
            measured_value: 3,
          },
          {
            evidence_id: "evidence-contradictory",
            polarity: "contradictory",
            relation: "visual_similarity",
            feature: "mean_color_distance",
            source_kind: "photo_artifact",
            source_id: "artifact-1",
            source_revision: "artifact-r3",
            input_sha256: ["c".repeat(64), "d".repeat(64)],
            extractor_id: "local-visual-features-v1",
            extractor_revision: "1",
            value_code: "distance_measured",
            measured_value: 214,
          },
        ],
      },
    ],
    leading_candidate_id: "candidate-wardrobe",
    decision_head: null,
    case_revision: 1,
    owner_decision_id: "owner-decision-1",
    person_instance_id: "person-1",
    owner_evidence_sha256: "e".repeat(64),
    owner_revision: 8,
    crop_decision_id: "crop-decision-1",
    crop_revision: 3,
    source_revision_sha256: "f".repeat(64),
    authority_state: "open_eligible",
    authority_reason: "current_authority",
    created_at_ms: 1,
  };
}
