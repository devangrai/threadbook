import { useEffect, useRef, useState } from "react";

import type {
  CandidateEvidencePolarityV1,
  DecideReconciliationCaseV2Response,
  ReconciliationCandidateV1,
  ReconciliationCaseV2,
  ReconciliationOutcomeV1,
} from "./generated/contracts";
import {
  reconciliationBridge,
  type ReconciliationBridge,
} from "./reconciliation-bridge";
import {
  canApplyOutcome,
  candidateDateLabel,
  candidateSourceLabel,
  decisionSummary,
  displayReconciliationError,
  evidencePolarities,
  evidenceProvenanceLabel,
  evidenceValueLabel,
  orderedCandidates,
  outcomeLabel,
  relationLabel,
  selectedCandidateForOutcome,
} from "./reconciliation-model";

const outcomes: ReadonlyArray<ReconciliationOutcomeV1> = [
  "same_item",
  "same_variant",
  "different",
  "no_match",
  "unresolved",
];

type ReconciliationPanelProps = {
  reconciliationCase: ReconciliationCaseV2;
  photoRevision: number;
  ownerRevision: number;
  reconciliationRevision: number;
  bridge?: ReconciliationBridge;
  focusOnMount?: boolean;
  onCaseChange?: (value: DecideReconciliationCaseV2Response) => void;
};

export function ReconciliationPanel({
  reconciliationCase: initialCase,
  photoRevision: initialPhotoRevision,
  ownerRevision: initialOwnerRevision,
  reconciliationRevision: initialReconciliationRevision,
  bridge = reconciliationBridge,
  focusOnMount = false,
  onCaseChange,
}: ReconciliationPanelProps) {
  const [reconciliationCase, setReconciliationCase] =
    useState<ReconciliationCaseV2>(initialCase);
  const [photoRevision, setPhotoRevision] = useState(initialPhotoRevision);
  const [ownerRevision, setOwnerRevision] = useState(initialOwnerRevision);
  const [reconciliationRevision, setReconciliationRevision] = useState(
    initialReconciliationRevision,
  );
  const [selectedCandidateId, setSelectedCandidateId] = useState(
    initialCase.decision_head?.selected_candidate_id ??
      initialCase.leading_candidate_id,
  );
  const [busy, setBusy] = useState<ReconciliationOutcomeV1 | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [focusSummary, setFocusSummary] = useState(false);
  const decisionInFlightRef = useRef(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const summaryRef = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    setReconciliationCase(initialCase);
  }, [initialCase]);

  useEffect(() => {
    if (focusOnMount) headingRef.current?.focus();
  }, [focusOnMount]);

  useEffect(() => {
    if (!focusSummary) return;
    summaryRef.current?.focus();
    setFocusSummary(false);
  }, [focusSummary, reconciliationCase]);

  const selectedCandidate =
    reconciliationCase.candidates.find(
      (candidate) => candidate.candidate_id === selectedCandidateId,
    ) ?? null;

  const decide = async (outcome: ReconciliationOutcomeV1) => {
    if (
      decisionInFlightRef.current ||
      reconciliationCase.authority_state !== "open_eligible" ||
      !canApplyOutcome(outcome, selectedCandidate)
    ) {
      return;
    }
    const selected = selectedCandidateForOutcome(outcome, selectedCandidate);
    decisionInFlightRef.current = true;
    setBusy(outcome);
    setMessage(null);
    try {
      const response = await bridge.decideCase(
        reconciliationCase.case_id,
        outcome,
        selected,
        reconciliationCase.case_revision,
        ownerRevision,
        photoRevision,
        reconciliationRevision,
      );
      setReconciliationCase(response.case);
      setPhotoRevision(response.photo_revision);
      setOwnerRevision(response.owner_revision);
      setReconciliationRevision(response.reconciliation_revision);
      onCaseChange?.(response);
      setMessage(`${outcomeLabel(outcome)} recorded.`);
      setFocusSummary(true);
    } catch (error) {
      setMessage(displayReconciliationError(error));
    } finally {
      decisionInFlightRef.current = false;
      setBusy(null);
    }
  };

  return (
    <section
      className="reconciliation-panel"
      aria-labelledby={`reconciliation-${reconciliationCase.case_id}-heading`}
    >
      <div className="reconciliation-heading">
        <div>
          <h4
            id={`reconciliation-${reconciliationCase.case_id}-heading`}
            ref={headingRef}
            tabIndex={-1}
          >
            Local matches
          </h4>
          <p>
            Observation date {reconciliationCase.observation_date} ·{" "}
            {reconciliationCase.retrieval_revision}
          </p>
        </div>
      </div>

      <p
        className="reconciliation-decision-summary"
        ref={summaryRef}
        tabIndex={-1}
      >
        {decisionSummary(reconciliationCase)}
      </p>
      {reconciliationCase.authority_state !== "open_eligible" && (
        <p className="authority-notice" role="status">
          Owner or crop authority changed. Review this photo again before
          recording a reconciliation decision.
        </p>
      )}
      <div className="reconciliation-status" role="status" aria-live="polite">
        {message}
      </div>

      <fieldset className="reconciliation-candidates">
        <legend>Candidate</legend>
        <ol>
          {orderedCandidates(reconciliationCase).map((candidate) => (
            <CandidateRow
              key={candidate.candidate_id}
              candidate={candidate}
              groupName={`reconciliation-candidate-${reconciliationCase.case_id}`}
              leading={
                candidate.candidate_id ===
                reconciliationCase.leading_candidate_id
              }
              checked={candidate.candidate_id === selectedCandidateId}
              disabled={
                busy !== null ||
                reconciliationCase.authority_state !== "open_eligible"
              }
              onSelect={() => setSelectedCandidateId(candidate.candidate_id)}
            />
          ))}
        </ol>
      </fieldset>

      <div
        className="reconciliation-actions"
        aria-label="Reconciliation decision"
      >
        {outcomes.map((outcome) => (
          <button
            className={
              outcome === "same_item" || outcome === "same_variant"
                ? "button button-primary"
                : "button"
            }
            type="button"
            disabled={
              busy !== null ||
              !canApplyOutcome(outcome, selectedCandidate) ||
              reconciliationCase.authority_state !== "open_eligible"
            }
            onClick={() => void decide(outcome)}
            key={outcome}
          >
            {busy === outcome ? "Recording..." : outcomeLabel(outcome)}
          </button>
        ))}
      </div>
    </section>
  );
}

function CandidateRow({
  candidate,
  groupName,
  leading,
  checked,
  disabled,
  onSelect,
}: {
  candidate: ReconciliationCandidateV1;
  groupName: string;
  leading: boolean;
  checked: boolean;
  disabled: boolean;
  onSelect: () => void;
}) {
  const label = candidate.target.kind === "no_match"
    ? "No match"
    : leading
      ? "Leading candidate"
      : "Alternative";

  return (
    <li className="reconciliation-candidate">
      <label className="reconciliation-candidate-select">
        <input
          type="radio"
          name={groupName}
          value={candidate.candidate_id}
          checked={checked}
          disabled={disabled}
          onChange={onSelect}
        />
        <span>
          <span className="reconciliation-candidate-kicker">{label}</span>
          <strong>{candidate.display_name}</strong>
          <small>{candidate.detail}</small>
        </span>
      </label>
      <dl className="reconciliation-candidate-facts">
        <div>
          <dt>Source</dt>
          <dd>{candidateSourceLabel(candidate)}</dd>
        </div>
        <div>
          <dt>Proposed relation</dt>
          <dd>{relationLabel(candidate.proposed_relation)}</dd>
        </div>
        <div>
          <dt>Date</dt>
          <dd>{candidateDateLabel(candidate)}</dd>
        </div>
      </dl>
      <div className="reconciliation-evidence">
        {evidencePolarities.map((polarity) => (
          <EvidenceGroup
            key={polarity.id}
            polarity={polarity.id}
            label={polarity.label}
            candidate={candidate}
          />
        ))}
      </div>
    </li>
  );
}

function EvidenceGroup({
  polarity,
  label,
  candidate,
}: {
  polarity: CandidateEvidencePolarityV1;
  label: string;
  candidate: ReconciliationCandidateV1;
}) {
  const evidence = candidate.evidence.filter(
    (value) => value.polarity === polarity,
  );
  return (
    <section
      className={`reconciliation-evidence-group evidence-${polarity}`}
      aria-labelledby={`${candidate.candidate_id}-${polarity}-heading`}
    >
      <h5 id={`${candidate.candidate_id}-${polarity}-heading`}>{label}</h5>
      {evidence.length === 0 ? (
        <p>None</p>
      ) : (
        <ul>
          {evidence.map((value) => (
            <li key={value.evidence_id}>
              <strong>{evidenceValueLabel(value)}</strong>
              <span>{relationLabel(value.relation)}</span>
              <small>{evidenceProvenanceLabel(value)}</small>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
