import { describe, expect, it } from "vitest";

import type {
  ReconciliationCandidateV1,
  ReconciliationCaseV2,
} from "./generated/contracts";
import {
  canApplyOutcome,
  candidateDateLabel,
  decisionSummary,
  evidenceProvenanceLabel,
  orderedCandidates,
} from "./reconciliation-model";

describe("reconciliation model", () => {
  it("orders the leading candidate first and the explicit no match last", () => {
    const value = reconciliationCase();
    expect(
      orderedCandidates(value).map((candidate) => candidate.candidate_id),
    ).toEqual(["wardrobe", "receipt", "no-match"]);
  });

  it("keeps all five outcomes target-specific", () => {
    const [wardrobe, receipt, noMatch] =
      reconciliationCase().candidates as [
        ReconciliationCandidateV1,
        ReconciliationCandidateV1,
        ReconciliationCandidateV1,
      ];
    expect(canApplyOutcome("same_item", wardrobe)).toBe(true);
    expect(canApplyOutcome("same_item", receipt)).toBe(false);
    expect(canApplyOutcome("same_variant", receipt)).toBe(true);
    expect(canApplyOutcome("different", wardrobe)).toBe(true);
    expect(canApplyOutcome("different", noMatch)).toBe(false);
    expect(canApplyOutcome("no_match", noMatch)).toBe(true);
    expect(canApplyOutcome("unresolved", null)).toBe(true);
  });

  it("formats unknown dates, provenance revisions, and the current head", () => {
    const value = reconciliationCase();
    expect(candidateDateLabel(value.candidates[1]!)).toBe("Date unknown");
    expect(
      evidenceProvenanceLabel(value.candidates[0]!.evidence[0]!),
    ).toBe(
      "Catalog image evidence revision catalog-r4; local-visual-features-v1 revision 1",
    );
    value.decision_head = {
      decision_id: "decision",
      case_id: value.case_id,
      outcome: "same_item",
      selected_candidate_id: "wardrobe",
      case_revision: 2,
    };
    expect(decisionSummary(value)).toBe(
      "Current decision: Same wardrobe item: Oxford shirt.",
    );
  });
});

function reconciliationCase(): ReconciliationCaseV2 {
  return {
    case_id: "case",
    observation_id: "observation",
    artifact_id: "artifact",
    artifact_sha256: "a".repeat(64),
    observation_date: "2026-07-14T10:00:00Z",
    retrieval_revision: "local-reconciliation-v1",
    candidates: [
      {
        candidate_id: "wardrobe",
        target: { kind: "wardrobe_item", item_id: "item" },
        proposed_relation: "same_physical_item",
        observed_relations: ["visual_similarity"],
        rank: 1,
        display_name: "Oxford shirt",
        detail: "White cotton",
        date: { kind: "catalog_created", value: "2026-06-01" },
        evidence: [
          {
            evidence_id: "evidence",
            polarity: "supporting",
            relation: "visual_similarity",
            feature: "difference_hash_distance",
            source_kind: "catalog_image_evidence",
            source_id: "source",
            source_revision: "catalog-r4",
            input_sha256: ["b".repeat(64)],
            extractor_id: "local-visual-features-v1",
            extractor_revision: "1",
            value_code: "distance_measured",
            measured_value: 4,
          },
        ],
      },
      {
        candidate_id: "receipt",
        target: {
          kind: "receipt_line",
          order_line_id: "line",
          variant_evidence_id: "variant",
        },
        proposed_relation: "same_product_variant",
        observed_relations: [],
        rank: 2,
        display_name: "Overshirt",
        detail: "Receipt line",
        date: null,
        evidence: [],
      },
      {
        candidate_id: "no-match",
        target: { kind: "no_match" },
        proposed_relation: null,
        observed_relations: [],
        rank: null,
        display_name: "No match",
        detail: "None of these candidates",
        date: null,
        evidence: [],
      },
    ],
    leading_candidate_id: "wardrobe",
    decision_head: null,
    case_revision: 1,
    owner_decision_id: "owner-decision-1",
    person_instance_id: "person-1",
    owner_evidence_sha256: "e".repeat(64),
    owner_revision: 1,
    crop_decision_id: "crop-decision-1",
    crop_revision: 1,
    source_revision_sha256: "f".repeat(64),
    authority_state: "open_eligible",
    authority_reason: "current_authority",
    created_at_ms: 1,
  };
}
