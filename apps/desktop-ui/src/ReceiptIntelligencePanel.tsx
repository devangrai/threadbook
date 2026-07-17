import { useEffect, useRef, useState } from "react";

import {
  receiptIntelligenceBridge,
  type ReceiptIntelligenceBridge,
  type ReceiptIntelligenceAttemptView,
} from "./receipt-intelligence-bridge";
import type {
  PreviewReceiptIntelligenceV1Response,
  ReceiptIntelligenceAvailabilityReasonV1,
  ReceiptIntelligenceAvailabilityV1,
} from "./generated/contracts";

export type ReceiptIntelligencePanelProps = {
  sourceId: string;
  localOnly: boolean;
  bridge?: ReceiptIntelligenceBridge;
  onOpenReview: () => void;
};

export function ReceiptIntelligencePanel({
  sourceId,
  localOnly,
  bridge = receiptIntelligenceBridge,
  onOpenReview,
}: ReceiptIntelligencePanelProps) {
  const [preview, setPreview] =
    useState<PreviewReceiptIntelligenceV1Response | null>(null);
  const [attempt, setAttempt] =
    useState<ReceiptIntelligenceAttemptView | null>(null);
  const [availability, setAvailability] =
    useState<ReceiptIntelligenceAvailabilityV1 | null>(null);
  const [busy, setBusy] = useState<"loading" | "preview" | "request" | null>(
    "loading",
  );
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setBusy("loading");
    setAvailability(null);
    void bridge
      .latest(sourceId)
      .then((status) => {
        if (active) {
          setAvailability(status.availability);
          setAttempt(status.attempt);
        }
      })
      .catch(() => {
        if (active) {
          setMessage("Saved OpenAI analysis status could not be loaded.");
        }
      })
      .finally(() => {
        if (active) setBusy(null);
      });
    return () => {
      active = false;
    };
  }, [bridge, localOnly, sourceId]);

  useEffect(() => {
    if (availability && !availability.available) setPreview(null);
  }, [availability]);

  const remoteAvailable = availability?.available === true;

  const prepare = async () => {
    if (!remoteAvailable || busy) return;
    setBusy("preview");
    setMessage(null);
    try {
      const response = await bridge.preview(sourceId);
      setPreview(response);
    } catch {
      setMessage("The OpenAI disclosure could not be prepared locally.");
    } finally {
      setBusy(null);
    }
  };

  const approve = async () => {
    if (!preview || !remoteAvailable || busy) return;
    const approved = preview;
    setPreview(null);
    setBusy("request");
    setMessage(null);
    try {
      setAttempt(await bridge.request(approved.preview));
    } catch {
      setAttempt({
        attempt_id: "unavailable",
        source_id: sourceId,
        state: "failed",
        classification: null,
        review_available: false,
        failure_code: null,
      });
    } finally {
      setBusy(null);
    }
  };

  return (
    <section
      className="receipt-intelligence"
      aria-label="OpenAI receipt analysis"
    >
      <div className="receipt-actions">
        <button
          className="button"
          type="button"
          disabled={!remoteAvailable || busy !== null}
          onClick={() => void prepare()}
        >
          {busy === "preview" ? "Preparing disclosure..." : "Analyze with OpenAI"}
        </button>
      </div>

      {availability && !availability.available && (
        <p className="receipt-muted">
          {availabilityMessage(availability.reason)}
        </p>
      )}
      {busy === "request" && (
        <div className="receipt-intelligence-state" role="status">
          <span className="spinner" aria-hidden="true" />
          <div>
            <strong>OpenAI analysis in progress</strong>
            <p>
              The approved request is being executed once. It will not retry
              automatically.
            </p>
          </div>
        </div>
      )}
      {message && (
        <p className="receipt-intelligence-message" role="status">
          {message}
        </p>
      )}
      {attempt && busy !== "request" && (
        <ReceiptIntelligenceState
          attempt={attempt}
          onOpenReview={onOpenReview}
        />
      )}
      {preview && remoteAvailable && (
        <ReceiptIntelligenceDisclosureDialog
          preview={preview}
          onCancel={() => setPreview(null)}
          onApprove={() => void approve()}
        />
      )}
    </section>
  );
}

function availabilityMessage(
  reason: ReceiptIntelligenceAvailabilityReasonV1 | null,
) {
  const explanation = {
    local_only: "OpenAI analysis is unavailable in local-only mode.",
    release_evidence_unavailable:
      "OpenAI analysis is unavailable in this release.",
    outbound_authority_unavailable:
      "OpenAI analysis is unavailable while outbound access is unavailable.",
    credential_unavailable:
      "OpenAI analysis requires an active OpenAI credential.",
    retention_declaration_unavailable:
      "OpenAI analysis is unavailable because current provider retention information is unavailable.",
  }[reason ?? "outbound_authority_unavailable"];
  return `${explanation} Offline receipt analysis and existing wardrobe access remain available.`;
}

function ReceiptIntelligenceDisclosureDialog({
  preview,
  onCancel,
  onApprove,
}: {
  preview: PreviewReceiptIntelligenceV1Response;
  onCancel: () => void;
  onApprove: () => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const priorFocus = useRef<HTMLElement | null>(
    document.activeElement instanceof HTMLElement ? document.activeElement : null,
  );
  const cancelRef = useRef(onCancel);
  const { disclosure } = preview.preview;

  useEffect(() => {
    cancelRef.current = onCancel;
  }, [onCancel]);

  useEffect(() => {
    const panel = panelRef.current;
    panel?.querySelector<HTMLElement>("[data-autofocus]")?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        cancelRef.current();
        return;
      }
      if (event.key !== "Tab" || !panel) return;
      const controls = [
        ...panel.querySelectorAll<HTMLElement>("button:not(:disabled)"),
      ];
      const first = controls[0];
      const last = controls.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      priorFocus.current?.focus();
    };
  }, []);

  return (
    <div className="modal-backdrop" role="presentation">
      <div
        className="modal-panel receipt-intelligence-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="receipt-intelligence-dialog-title"
        aria-describedby="receipt-intelligence-dialog-summary"
        ref={panelRef}
      >
        <div className="modal-heading">
          <h2 id="receipt-intelligence-dialog-title">
            Review OpenAI receipt analysis
          </h2>
          <button
            className="icon-button"
            type="button"
            aria-label="Cancel OpenAI receipt analysis"
            data-autofocus
            onClick={onCancel}
          >
            ×
          </button>
        </div>

        <p id="receipt-intelligence-dialog-summary">
          Review the exact visible text and limits before approving this
          one-time request.
        </p>
        <dl className="receipt-intelligence-facts">
          <Fact label="Provider" value={disclosure.provider} />
          <Fact label="Model" value={disclosure.model} />
          <Fact label="Purpose" value={disclosure.purpose} />
          <Fact
            label="Visible text bytes"
            value={`${disclosure.aggregate_text_bytes} bytes`}
          />
          <Fact
            label="Local retention"
            value={
              disclosure.retention.local_provider_payload_retained
                ? "Provider payload retained locally"
                : "Provider payload is not retained locally"
            }
          />
          <Fact
            label="Provider retention"
            value={disclosure.retention.declaration.provenance}
          />
        </dl>

        <p className="receipt-intelligence-caveat">
          <code>store:false</code> is not organization-level Zero Data
          Retention (ZDR).
        </p>

        <section aria-labelledby="disclosed-text-title">
          <h3 id="disclosed-text-title">Exact visible text sent</h3>
          <ol className="receipt-intelligence-fragments">
            {disclosure.projection.fragments.map((fragment, index) => (
              <li key={fragment.fragment_ref}>
                <div>
                  <strong>Fragment {index + 1}</strong>
                  <span>{new TextEncoder().encode(fragment.text).length} bytes</span>
                </div>
                <pre>{fragment.text}</pre>
              </li>
            ))}
          </ol>
        </section>

        <div className="receipt-intelligence-bounds">
          <Bounds
            title="Preparation bounds"
            values={[
              ["Fragments", disclosure.preparation_bounds.max_fragment_count],
              [
                "Bytes per fragment",
                disclosure.preparation_bounds.max_fragment_bytes,
              ],
              [
                "Aggregate text bytes",
                disclosure.preparation_bounds.max_aggregate_text_bytes,
              ],
              [
                "Serialized request bytes",
                disclosure.preparation_bounds.max_serialized_request_bytes,
              ],
            ]}
          />
          <Bounds
            title="Execution bounds"
            values={[
              ["Request bytes", disclosure.execution_bounds.max_request_bytes],
              [
                "Response bytes",
                disclosure.execution_bounds.max_response_bytes,
              ],
              ["Output tokens", disclosure.execution_bounds.max_output_tokens],
              ["Timeout", `${disclosure.execution_bounds.timeout_millis} ms`],
              ["Attempts", disclosure.execution_bounds.max_attempts],
            ]}
          />
        </div>

        <div className="modal-actions">
          <button className="button" type="button" onClick={onCancel}>
            Cancel
          </button>
          <button
            className="button button-primary"
            type="button"
            onClick={onApprove}
          >
            Approve and analyze
          </button>
        </div>
      </div>
    </div>
  );
}

function ReceiptIntelligenceState({
  attempt,
  onOpenReview,
}: {
  attempt: ReceiptIntelligenceAttemptView;
  onOpenReview: () => void;
}) {
  const content = attemptContent(attempt);
  return (
    <div
      className={`receipt-intelligence-state receipt-intelligence-${attempt.state}`}
      data-state={attempt.state}
      role="status"
    >
      <div>
        <strong>{content.title}</strong>
        <p>{content.description}</p>
      </div>
      {attempt.review_available && (
        <button className="button button-primary" type="button" onClick={onOpenReview}>
          Open receipt review
        </button>
      )}
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function Bounds({
  title,
  values,
}: {
  title: string;
  values: ReadonlyArray<readonly [string, string | number]>;
}) {
  return (
    <section>
      <h3>{title}</h3>
      <dl>
        {values.map(([label, value]) => (
          <Fact label={label} value={String(value)} key={label} />
        ))}
      </dl>
    </section>
  );
}

function attemptContent(attempt: ReceiptIntelligenceAttemptView) {
  if (attempt.state === "not_sent") {
    return {
      title: "OpenAI analysis approved",
      description: "The request is reserved locally and has not been sent.",
    };
  }
  if (attempt.state === "dispatched") {
    return {
      title: "OpenAI analysis in progress",
      description:
        "The request was dispatched once and will not retry automatically.",
    };
  }
  if (attempt.state === "refused") {
    return {
      title: "OpenAI analysis refused",
      description:
        "The provider returned a refusal. No receipt order or wardrobe item was created.",
    };
  }
  if (attempt.state === "failed") {
    return {
      title: "OpenAI analysis failed",
      description:
        "No partial receipt evidence or wardrobe item was created. Offline analysis remains available.",
    };
  }
  if (attempt.state === "outcome_unknown") {
    return {
      title: "OpenAI analysis outcome unknown",
      description:
        "The request may have reached OpenAI. It will not retry automatically, and no result is treated as receipt evidence.",
    };
  }
  if (attempt.classification === "unrelated") {
    return {
      title: "Unrelated message",
      description:
        "OpenAI classified this message as unrelated. No receipt order or wardrobe item was created.",
    };
  }
  if (attempt.classification === "ambiguous") {
    return {
      title: "Ambiguous message",
      description:
        "OpenAI could not classify this message safely. No receipt order or wardrobe item was created.",
    };
  }
  return {
    title: "OpenAI analysis complete",
    description:
      "Extracted evidence is ready for separate receipt review. Nothing was added to your wardrobe.",
  };
}
