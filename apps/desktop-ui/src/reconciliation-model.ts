import type {
  CandidateEvidenceFeatureV1,
  CandidateEvidencePolarityV1,
  CandidateEvidenceSourceKindV1,
  CandidateEvidenceV1,
  IdentityRelationV1,
  ReconciliationCandidateV1,
  ReconciliationCaseV2,
  ReconciliationOutcomeV1,
} from "./generated/contracts";

export const evidencePolarities: ReadonlyArray<{
  id: CandidateEvidencePolarityV1;
  label: string;
}> = [
  { id: "supporting", label: "Supporting" },
  { id: "contradictory", label: "Contradictory" },
  { id: "neutral", label: "Neutral" },
];

export function orderedCandidates(
  reconciliationCase: ReconciliationCaseV2,
): ReconciliationCandidateV1[] {
  const leading = reconciliationCase.candidates.find(
    (candidate) =>
      candidate.candidate_id === reconciliationCase.leading_candidate_id,
  );
  const alternatives = reconciliationCase.candidates
    .filter(
      (candidate) =>
        candidate.candidate_id !== reconciliationCase.leading_candidate_id &&
        candidate.target.kind !== "no_match",
    )
    .sort(
      (left, right) =>
        (left.rank ?? Number.MAX_SAFE_INTEGER) -
          (right.rank ?? Number.MAX_SAFE_INTEGER) ||
        left.display_name.localeCompare(right.display_name),
    );
  const noMatch = reconciliationCase.candidates.filter(
    (candidate) => candidate.target.kind === "no_match",
  );
  return [...(leading ? [leading] : []), ...alternatives, ...noMatch];
}

export function candidateSourceLabel(
  candidate: ReconciliationCandidateV1,
): string {
  if (candidate.target.kind === "wardrobe_item") return "Wardrobe item";
  if (candidate.target.kind === "receipt_line") return "Receipt line";
  return "Explicit no match";
}

export function candidateDateLabel(
  candidate: ReconciliationCandidateV1,
): string {
  if (candidate.target.kind === "no_match") return "Date not applicable";
  if (!candidate.date) return "Date unknown";
  return `${candidate.date.kind === "purchase" ? "Purchase date" : "Catalog date"} ${candidate.date.value}`;
}

export function relationLabel(relation: IdentityRelationV1 | null): string {
  if (relation === "same_physical_item") return "Same physical wardrobe item";
  if (relation === "same_product_variant") return "Same product variant";
  if (relation === "visual_similarity") return "Visual similarity";
  return "No proposed relation";
}

export function evidenceValueLabel(evidence: CandidateEvidenceV1): string {
  const label = featureLabel(evidence.feature);
  if (evidence.measured_value !== null) {
    return `${label}: ${evidence.measured_value}`;
  }
  return `${label}: ${valueCodeLabel(evidence.value_code)}`;
}

export function evidenceProvenanceLabel(
  evidence: CandidateEvidenceV1,
): string {
  return `${sourceKindLabel(evidence.source_kind)} revision ${evidence.source_revision}; ${evidence.extractor_id} revision ${evidence.extractor_revision}`;
}

export function canApplyOutcome(
  outcome: ReconciliationOutcomeV1,
  selectedCandidate: ReconciliationCandidateV1 | null,
): boolean {
  if (outcome === "unresolved") return true;
  if (!selectedCandidate) return false;
  if (outcome === "same_item") {
    return selectedCandidate.target.kind === "wardrobe_item";
  }
  if (outcome === "same_variant") {
    return selectedCandidate.target.kind === "receipt_line";
  }
  if (outcome === "different") {
    return selectedCandidate.target.kind !== "no_match";
  }
  return selectedCandidate.target.kind === "no_match";
}

export function selectedCandidateForOutcome(
  outcome: ReconciliationOutcomeV1,
  selectedCandidate: ReconciliationCandidateV1 | null,
): string | null {
  return outcome === "unresolved"
    ? null
    : selectedCandidate?.candidate_id ?? null;
}

export function outcomeLabel(outcome: ReconciliationOutcomeV1): string {
  if (outcome === "same_item") return "Same wardrobe item";
  if (outcome === "same_variant") return "Same product variant";
  if (outcome === "different") return "Different";
  if (outcome === "no_match") return "No match";
  return "Unresolved";
}

export function decisionSummary(
  reconciliationCase: ReconciliationCaseV2,
): string {
  const decision = reconciliationCase.decision_head;
  if (!decision) return "No reconciliation decision recorded.";
  const selected = reconciliationCase.candidates.find(
    (candidate) =>
      candidate.candidate_id === decision.selected_candidate_id,
  );
  const target =
    selected && selected.target.kind !== "no_match"
      ? `: ${selected.display_name}`
      : "";
  return `Current decision: ${outcomeLabel(decision.outcome)}${target}.`;
}

export function isReconciliationConflict(error: unknown): boolean {
  return (
    !!error &&
    typeof error === "object" &&
    "code" in error &&
    (error as { code?: unknown }).code === "request_conflict"
  );
}

export function displayReconciliationError(error: unknown): string {
  return isReconciliationConflict(error)
    ? "This reconciliation case changed. Your candidate selection is still here."
    : "The local reconciliation operation could not be completed.";
}

function featureLabel(feature: CandidateEvidenceFeatureV1): string {
  const labels: Record<CandidateEvidenceFeatureV1, string> = {
    difference_hash_distance: "Difference hash distance",
    mean_color_distance: "Mean color distance",
    catalog_image_status: "Catalog image",
    receipt_review_state: "Receipt review",
    receipt_event_kind: "Receipt event",
    purchase_chronology: "Purchase chronology",
    extracted_receipt_provenance: "Extracted receipt provenance",
  };
  return labels[feature];
}

function sourceKindLabel(source: CandidateEvidenceSourceKindV1): string {
  const labels: Record<CandidateEvidenceSourceKindV1, string> = {
    photo_artifact: "Photo artifact",
    catalog_image_evidence: "Catalog image evidence",
    catalog_decision: "Catalog decision",
    receipt_field: "Receipt field",
    receipt_review_decision: "Receipt review decision",
  };
  return labels[source];
}

function valueCodeLabel(value: string): string {
  return value
    .split("_")
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}
