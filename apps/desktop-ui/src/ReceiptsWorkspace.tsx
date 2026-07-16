import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  receiptBridge,
  type ReceiptBridge,
} from "./receipt-bridge";
import type {
  CorrectedReceiptOrderV1,
  ApproveAndFetchReceiptImageV1Response,
  EvidenceEventKindV1,
  EvidenceStringV1,
  EvidenceU64V1,
  ListReceiptsV1Response,
  ReceiptOrderEvidenceV1,
  ReceiptImageCandidateSummaryV1,
  ReceiptReviewActionV1,
  ReceiptStateV1,
  ReceiptSummaryV1,
} from "./generated/contracts";
import {
  citationKey,
  correctedOrderFromDraft,
  createCorrectionDraft,
  displayReceiptError,
  evidenceValue,
  isReceiptConflict,
  type ReceiptCorrectionDraft,
  type VerifiedReceiptOrder,
} from "./receipt-model";

const receiptStates: ReadonlyArray<{
  id: ReceiptStateV1;
  label: string;
}> = [
  { id: "unanalyzed", label: "Unanalyzed" },
  { id: "needs_review", label: "Needs review" },
  { id: "confirmed", label: "Confirmed" },
  { id: "corrected", label: "Corrected" },
  { id: "deferred", label: "Deferred" },
  { id: "rejected", label: "Rejected" },
  { id: "failed", label: "Failed" },
];

type ReceiptsWorkspaceProps = {
  localOnly: boolean;
  bridge?: ReceiptBridge;
};

export function ReceiptsWorkspace({
  localOnly,
  bridge = receiptBridge,
}: ReceiptsWorkspaceProps) {
  const [filter, setFilter] = useState<ReceiptStateV1>("unanalyzed");
  const [page, setPage] = useState<ListReceiptsV1Response | null>(null);
  const [details, setDetails] = useState<
    ReadonlyMap<string, VerifiedReceiptOrder>
  >(new Map());
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [correction, setCorrection] = useState<{
    order: ReceiptOrderEvidenceV1;
    draft: ReceiptCorrectionDraft;
  } | null>(null);
  const [focusOrderId, setFocusOrderId] = useState<string | null>(null);
  const [imageCandidates, setImageCandidates] = useState<
    ReadonlyMap<string, ReadonlyArray<ReceiptImageCandidateSummaryV1>>
  >(new Map());
  const [imageResults, setImageResults] = useState<
    ReadonlyMap<string, ApproveAndFetchReceiptImageV1Response>
  >(new Map());
  const [imageConfirmation, setImageConfirmation] = useState<{
    candidate: ReceiptImageCandidateSummaryV1;
    priorAttemptId: string | null;
  } | null>(null);

  const load = useCallback(
    async (
      state: ReceiptStateV1,
      cursor: string | null = null,
      append = false,
    ) => {
      const next = await bridge.listReceipts(state, cursor, 20);
      setPage((current) =>
        append && current
          ? {
              ...next,
              receipts: appendReceipts(current.receipts, next.receipts),
            }
          : next,
      );
      return next;
    },
    [bridge],
  );

  useEffect(() => {
    let active = true;
    setLoading(true);
    setMessage(null);
    void load(filter)
      .catch((error) => {
        if (active) setMessage(displayReceiptError(error));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [filter, load]);

  useEffect(() => {
    if (!focusOrderId) return;
    const target = document.getElementById(`receipt-${focusOrderId}`);
    if (target instanceof HTMLElement) {
      target.focus();
      setFocusOrderId(null);
    }
  }, [focusOrderId, page]);

  useEffect(() => {
    if (localOnly) {
      setImageConfirmation(null);
    }
  }, [localOnly]);

  const analyze = async (summary: ReceiptSummaryV1) => {
    setBusy(`analyze:${summary.source_id}`);
    setMessage(null);
    try {
      const analyzed = await bridge.analyzeReceipt(summary.source_id);
      setDetails((current) => {
        const next = new Map(current);
        next.set(analyzed.order.order_evidence_id, analyzed.verified);
        return next;
      });
      setFilter("needs_review");
      setFocusOrderId(analyzed.order.order_evidence_id);
      setMessage("Receipt analyzed. Review the extracted evidence.");
      await loadImages(summary.source_id);
    } catch (error) {
      setMessage(displayReceiptError(error));
    } finally {
      setBusy(null);
    }
  };

  const loadImages = async (sourceId: string) => {
    setBusy(`images:list:${sourceId}`);
    try {
      const response = await bridge.listReceiptImageCandidates(sourceId);
      setImageCandidates((current) => {
        const next = new Map(current);
        next.set(sourceId, response.candidates);
        return next;
      });
    } catch (error) {
      setMessage(displayReceiptError(error));
    } finally {
      setBusy(null);
    }
  };

  const fetchImage = async () => {
    if (!imageConfirmation || localOnly) return;
    const { candidate, priorAttemptId } = imageConfirmation;
    setBusy(`images:fetch:${candidate.candidate_id}`);
    setMessage(null);
    try {
      const response = await bridge.approveAndFetchReceiptImage(
        candidate.candidate_id,
        candidate.display_host,
        candidate.candidate_url_sha256,
        priorAttemptId,
      );
      setImageResults((current) => {
        const next = new Map(current);
        next.set(candidate.candidate_id, response);
        return next;
      });
      setImageConfirmation(null);
      setMessage(imageOutcomeMessage(response));
    } catch (error) {
      setMessage(displayReceiptError(error));
    } finally {
      setBusy(null);
    }
  };

  const review = async (
    order: ReceiptOrderEvidenceV1,
    action: ReceiptReviewActionV1,
    correctedOrder: CorrectedReceiptOrderV1 | null,
  ) => {
    if (!page) return false;
    setBusy(`review:${order.order_evidence_id}`);
    setMessage(null);
    try {
      await bridge.reviewReceipt(
        order.order_evidence_id,
        action,
        correctedOrder,
        page.receipt_revision,
      );
      await load(filter);
      setMessage(
        action === "correct"
          ? "Receipt correction saved."
          : `Receipt ${pastTense(action)}.`,
      );
      return true;
    } catch (error) {
      if (isReceiptConflict(error)) {
        try {
          await load(filter);
        } catch {
          // Keep the conflict message and draft if the refresh also fails.
        }
      }
      setMessage(displayReceiptError(error));
      return false;
    } finally {
      setBusy(null);
    }
  };

  if (loading && !page) {
    return (
      <section className="state-view" aria-label="Loading receipts">
        <span className="spinner" aria-hidden="true" />
        <p>Loading receipts...</p>
      </section>
    );
  }

  return (
    <section aria-labelledby="receipts-title" aria-busy={loading}>
      <div className="sr-live" role="status" aria-live="polite">
        {message}
      </div>
      <div className="view-heading">
        <div>
          <h2 id="receipts-title">Receipts</h2>
          <p className="count">{page?.total_count ?? 0} in this view</p>
        </div>
      </div>

      <div className="receipt-filter-scroll">
        <div className="segmented receipt-filters" aria-label="Receipt state">
          {receiptStates.map((state) => (
            <button
              type="button"
              aria-pressed={filter === state.id}
              onClick={() => setFilter(state.id)}
              key={state.id}
            >
              {state.label}
            </button>
          ))}
        </div>
      </div>

      {!page?.receipts.length ? (
        <div className="empty-state compact">
          <p>No {humanize(filter).toLowerCase()} receipts</p>
        </div>
      ) : (
        <ol className="receipt-list">
          {page.receipts.map((summary) => {
            const orderId = summary.order_evidence_id;
            const verified = orderId ? details.get(orderId) : undefined;
            return (
              <li key={summary.source_id}>
                <ReceiptSummary
                  summary={summary}
                  localOnly={localOnly}
                  verified={verified}
                  busy={busy}
                  onAnalyze={() => void analyze(summary)}
                  onReview={(order, action) =>
                    void review(order, action, null)
                  }
                  onCorrect={(order) =>
                    setCorrection({
                      order,
                      draft: createCorrectionDraft(order),
                    })
                  }
                  candidates={imageCandidates.get(summary.source_id)}
                  imageResults={imageResults}
                  onListImages={() => void loadImages(summary.source_id)}
                  onApproveImage={(candidate, priorAttemptId) =>
                    setImageConfirmation({ candidate, priorAttemptId })
                  }
                />
              </li>
            );
          })}
        </ol>
      )}

      {page?.next_cursor && (
        <button
          className="button load-more"
          type="button"
          disabled={loading}
          onClick={() => {
            setLoading(true);
            void load(filter, page.next_cursor, true)
              .catch((error) => setMessage(displayReceiptError(error)))
              .finally(() => setLoading(false));
          }}
        >
          {loading ? "Loading..." : "Load more receipts"}
        </button>
      )}

      {correction && (
        <CorrectionDialog
          value={correction.draft}
          busy={busy === `review:${correction.order.order_evidence_id}`}
          onChange={(draft) =>
            setCorrection((current) =>
              current ? { ...current, draft } : current,
            )
          }
          onClose={() => setCorrection(null)}
          onSubmit={async (correctedOrder) => {
            const saved = await review(
              correction.order,
              "correct",
              correctedOrder,
            );
            if (saved) setCorrection(null);
          }}
        />
      )}
      {imageConfirmation && (
        <Modal
          title={
            imageConfirmation.priorAttemptId
              ? "Start new image attempt"
              : "Download receipt image"
          }
          onClose={() => setImageConfirmation(null)}
        >
          <p>
            Wardrobe will connect only to{" "}
            <strong>{imageConfirmation.candidate.display_host}</strong> and
            store a local metadata-free copy.
          </p>
          <div className="modal-actions">
            <button
              className="button"
              type="button"
              onClick={() => setImageConfirmation(null)}
            >
              Cancel
            </button>
            <button
              className="button button-primary"
              type="button"
              disabled={busy !== null}
              onClick={() => void fetchImage()}
            >
              {imageConfirmation.priorAttemptId
                ? "Start new attempt"
                : `Download image from ${imageConfirmation.candidate.display_host}`}
            </button>
          </div>
        </Modal>
      )}
    </section>
  );
}

function ReceiptSummary({
  summary,
  localOnly,
  verified,
  busy,
  onAnalyze,
  onReview,
  onCorrect,
  candidates,
  imageResults,
  onListImages,
  onApproveImage,
}: {
  summary: ReceiptSummaryV1;
  localOnly: boolean;
  verified?: VerifiedReceiptOrder;
  busy: string | null;
  onAnalyze: () => void;
  onReview: (
    order: ReceiptOrderEvidenceV1,
    action: Exclude<ReceiptReviewActionV1, "correct">,
  ) => void;
  onCorrect: (order: ReceiptOrderEvidenceV1) => void;
  candidates?: ReadonlyArray<ReceiptImageCandidateSummaryV1>;
  imageResults: ReadonlyMap<string, ApproveAndFetchReceiptImageV1Response>;
  onListImages: () => void;
  onApproveImage: (
    candidate: ReceiptImageCandidateSummaryV1,
    priorAttemptId: string | null,
  ) => void;
}) {
  const corrected = summary.review_head?.decision.corrected_order;
  const order = verified?.order;
  const titleId = summary.order_evidence_id
    ? `receipt-${summary.order_evidence_id}`
    : `receipt-${summary.source_id}`;
  const reviewBusy =
    !!summary.order_evidence_id &&
    busy === `review:${summary.order_evidence_id}`;

  return (
    <article className="receipt-row" aria-labelledby={titleId}>
      <div className="receipt-summary-line">
        <div>
          <h3 id={titleId} tabIndex={-1}>
            {summary.merchant ?? "Unknown merchant"}
          </h3>
          <span>
            {summary.line_item_count}{" "}
            {summary.line_item_count === 1 ? "line" : "lines"}
          </span>
        </div>
        <span className={`status-pill status-${summary.state}`}>
          {humanize(summary.state)}
        </span>
      </div>

      {summary.state === "failed" && (
        <p className="receipt-failure">Analysis failed</p>
      )}

      {order && verified ? (
        <>
          <ExtractedOrderView verified={verified} />
          <ReviewActions
            order={order}
            disabled={reviewBusy}
            onReview={onReview}
            onCorrect={onCorrect}
          />
        </>
      ) : corrected ? (
        <CorrectedOrderView order={corrected} />
      ) : summary.state === "unanalyzed" || summary.state === "failed" ? (
        <div className="receipt-actions">
          <button
            className="button button-primary"
            type="button"
            disabled={busy !== null}
            onClick={onAnalyze}
            aria-label={`Analyze receipt from ${summary.merchant ?? "unknown merchant"}`}
          >
            {busy === `analyze:${summary.source_id}`
              ? "Analyzing..."
              : "Analyze"}
          </button>
        </div>
      ) : (
        <p className="receipt-muted">
          {summary.review_head
            ? `Latest review: ${humanize(summary.review_head.decision.action)}`
            : "Receipt evidence available"}
        </p>
      )}

      {summary.processing && (
        <dl className="processing-line">
          <div>
            <dt>Provider</dt>
            <dd>{summary.processing.provider_id}</dd>
          </div>
          <div>
            <dt>Ruleset</dt>
            <dd>{summary.processing.ruleset_revision}</dd>
          </div>
        </dl>
      )}
      {summary.state !== "unanalyzed" && (
        <ReceiptImages
          sourceId={summary.source_id}
          localOnly={localOnly}
          candidates={candidates}
          imageResults={imageResults}
          busy={busy}
          onList={onListImages}
          onApprove={onApproveImage}
        />
      )}
    </article>
  );
}

function ReceiptImages({
  sourceId,
  localOnly,
  candidates,
  imageResults,
  busy,
  onList,
  onApprove,
}: {
  sourceId: string;
  localOnly: boolean;
  candidates?: ReadonlyArray<ReceiptImageCandidateSummaryV1>;
  imageResults: ReadonlyMap<string, ApproveAndFetchReceiptImageV1Response>;
  busy: string | null;
  onList: () => void;
  onApprove: (
    candidate: ReceiptImageCandidateSummaryV1,
    priorAttemptId: string | null,
  ) => void;
}) {
  if (!candidates) {
    return (
      <div className="receipt-images">
        <button
          className="button"
          type="button"
          disabled={busy !== null}
          onClick={onList}
        >
          {busy === `images:list:${sourceId}`
            ? "Finding images..."
            : "Find receipt images"}
        </button>
      </div>
    );
  }
  if (candidates.length === 0) {
    return <p className="receipt-muted">No product images found</p>;
  }
  return (
    <section className="receipt-images" aria-label="Receipt image candidates">
      <h4>Product images</h4>
      <ul>
        {candidates.map((candidate) => {
          const result = imageResults.get(candidate.candidate_id);
          const outcome = result?.outcome ?? candidate.latest_attempt?.outcome;
          const attemptId =
            result?.attempt_id ?? candidate.latest_attempt?.attempt_id ?? null;
          return (
            <li key={candidate.candidate_id}>
              <div>
                <strong>{candidate.display_host}</strong>
                <span>{imageStatus(candidate, result)}</span>
              </div>
              {candidate.eligibility === "eligible" && !outcome && (
                <button
                  className="button"
                  type="button"
                  disabled={busy !== null || localOnly}
                  onClick={() => onApprove(candidate, null)}
                >
                  Download image from {candidate.display_host}
                </button>
              )}
              {outcome === "ambiguous" && attemptId && (
                <button
                  className="button"
                  type="button"
                  disabled={busy !== null || localOnly}
                  onClick={() => onApprove(candidate, attemptId)}
                >
                  Start new attempt
                </button>
              )}
            </li>
          );
        })}
      </ul>
      {localOnly && (
        <p className="settings-description">
          Receipt-image downloads are unavailable in local-only mode.
        </p>
      )}
    </section>
  );
}

function imageStatus(
  candidate: ReceiptImageCandidateSummaryV1,
  result?: ApproveAndFetchReceiptImageV1Response,
) {
  if (candidate.eligibility === "blocked") return "Blocked by policy";
  const outcome = result?.outcome ?? candidate.latest_attempt?.outcome;
  if (!outcome) return "Ready for approval";
  if (outcome === "succeeded" && result?.artifact) {
    return `Stored locally, ${result.artifact.width} by ${result.artifact.height}`;
  }
  return humanize(outcome);
}

function imageOutcomeMessage(response: ApproveAndFetchReceiptImageV1Response) {
  if (response.outcome === "succeeded") return "Receipt image stored locally.";
  if (response.outcome === "ambiguous") {
    return "The attempt outcome is uncertain. Start a new attempt only if needed.";
  }
  return `Image attempt ${humanize(response.outcome).toLowerCase()}.`;
}

function ExtractedOrderView({
  verified,
}: {
  verified: VerifiedReceiptOrder;
}) {
  const { order, quotes } = verified;
  return (
    <div className="receipt-order">
      <dl className="receipt-order-fields">
        <EvidenceField label="Merchant" evidence={order.merchant} quotes={quotes} />
        <EvidenceField
          label="Order identifier"
          evidence={order.order_identifier}
          quotes={quotes}
        />
        <EvidenceField
          label="Purchase date"
          evidence={order.purchase_date}
          quotes={quotes}
        />
        <EvidenceField label="Currency" evidence={order.currency} quotes={quotes} />
      </dl>
      <ol className="receipt-lines" aria-label="Order lines">
        {order.line_items.map((line) => (
          <li key={line.order_line_id}>
            <h4>Order line {line.line_number}</h4>
            <dl className="receipt-line-fields">
              <EvidenceField
                label="Description"
                evidence={line.description}
                quotes={quotes}
              />
              <EvidenceField
                label="Event"
                evidence={line.event_kind}
                quotes={quotes}
              />
              <EvidenceField
                label="Quantity"
                evidence={line.quantity}
                quotes={quotes}
              />
              <EvidenceField
                label="Unit price (minor units)"
                evidence={line.unit_price_minor}
                quotes={quotes}
              />
            </dl>
            <section
              className="receipt-variant"
              aria-labelledby={`variant-${line.variant.variant_evidence_id}`}
            >
              <h5 id={`variant-${line.variant.variant_evidence_id}`}>
                Variant evidence
              </h5>
              <dl className="receipt-line-fields">
                <EvidenceField
                  label="Brand"
                  evidence={line.variant.brand}
                  quotes={quotes}
                />
                <EvidenceField
                  label="SKU"
                  evidence={line.variant.sku}
                  quotes={quotes}
                />
                <EvidenceField
                  label="Size"
                  evidence={line.variant.size}
                  quotes={quotes}
                />
                <EvidenceField
                  label="Color"
                  evidence={line.variant.color}
                  quotes={quotes}
                />
              </dl>
            </section>
          </li>
        ))}
      </ol>
    </div>
  );
}

function EvidenceField({
  label,
  evidence,
  quotes,
}: {
  label: string;
  evidence: EvidenceStringV1 | EvidenceU64V1 | EvidenceEventKindV1;
  quotes: ReadonlyMap<string, string>;
}) {
  return (
    <div>
      <dt>{label}</dt>
      <dd className={evidence.value === null ? "unknown-value" : undefined}>
        {evidenceValue(evidence.value)}
        {evidence.citations.length > 0 && (
          <details className="citation-disclosure">
            <summary>
              {evidence.citations.length === 1
                ? "Verified source quote"
                : `${evidence.citations.length} verified source quotes`}
            </summary>
            {evidence.citations.map((citation) => (
              <blockquote key={citationKey(citation)}>
                {quotes.get(citationKey(citation))}
              </blockquote>
            ))}
          </details>
        )}
      </dd>
    </div>
  );
}

function ReviewActions({
  order,
  disabled,
  onReview,
  onCorrect,
}: {
  order: ReceiptOrderEvidenceV1;
  disabled: boolean;
  onReview: (
    order: ReceiptOrderEvidenceV1,
    action: Exclude<ReceiptReviewActionV1, "correct">,
  ) => void;
  onCorrect: (order: ReceiptOrderEvidenceV1) => void;
}) {
  return (
    <div className="receipt-actions" aria-label="Receipt review actions">
      <button
        className="button button-primary"
        type="button"
        disabled={disabled}
        onClick={() => onReview(order, "confirm")}
      >
        Confirm
      </button>
      <button
        className="button"
        type="button"
        disabled={disabled}
        onClick={() => onCorrect(order)}
      >
        Correct
      </button>
      <button
        className="button button-danger"
        type="button"
        disabled={disabled}
        onClick={() => onReview(order, "reject")}
      >
        Reject
      </button>
      <button
        className="button"
        type="button"
        disabled={disabled}
        onClick={() => onReview(order, "defer")}
      >
        Defer
      </button>
    </div>
  );
}

function CorrectedOrderView({ order }: { order: CorrectedReceiptOrderV1 }) {
  return (
    <div className="receipt-order">
      <dl className="receipt-order-fields">
        <ValueField label="Merchant" value={order.merchant} />
        <ValueField label="Order identifier" value={order.order_identifier} />
        <ValueField label="Purchase date" value={order.purchase_date} />
        <ValueField label="Currency" value={order.currency} />
      </dl>
      <ol className="receipt-lines" aria-label="Corrected order lines">
        {order.line_items.map((line, index) => (
          <li key={line.order_line_id}>
            <h4>Order line {index + 1}</h4>
            <dl className="receipt-line-fields">
              <ValueField label="Description" value={line.description} />
              <ValueField label="Event" value={line.event_kind} />
              <ValueField label="Quantity" value={line.quantity} />
              <ValueField
                label="Unit price (minor units)"
                value={line.unit_price_minor}
              />
            </dl>
            <section className="receipt-variant" aria-label="Variant evidence">
              <h5>Variant evidence</h5>
              <dl className="receipt-line-fields">
                <ValueField label="Brand" value={line.variant.brand} />
                <ValueField label="SKU" value={line.variant.sku} />
                <ValueField label="Size" value={line.variant.size} />
                <ValueField label="Color" value={line.variant.color} />
              </dl>
            </section>
          </li>
        ))}
      </ol>
    </div>
  );
}

function ValueField({
  label,
  value,
}: {
  label: string;
  value: string | number | null;
}) {
  return (
    <div>
      <dt>{label}</dt>
      <dd className={value === null ? "unknown-value" : undefined}>
        {evidenceValue(value)}
      </dd>
    </div>
  );
}

function CorrectionDialog({
  value,
  busy,
  onChange,
  onClose,
  onSubmit,
}: {
  value: ReceiptCorrectionDraft;
  busy: boolean;
  onChange: (value: ReceiptCorrectionDraft) => void;
  onClose: () => void;
  onSubmit: (value: CorrectedReceiptOrderV1) => Promise<void>;
}) {
  const [error, setError] = useState<string | null>(null);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const result = correctedOrderFromDraft(value);
    setError(result.error);
    if (result.value) void onSubmit(result.value);
  };
  const updateOrder = (
    field: "merchant" | "order_identifier" | "purchase_date" | "currency",
    next: string,
  ) => onChange({ ...value, [field]: next });
  const updateLine = (
    index: number,
    change: Partial<ReceiptCorrectionDraft["line_items"][number]>,
  ) =>
    onChange({
      ...value,
      line_items: value.line_items.map((line, lineIndex) =>
        lineIndex === index ? { ...line, ...change } : line,
      ),
    });
  const updateVariant = (
    index: number,
    field: "brand" | "sku" | "size" | "color",
    next: string,
  ) => {
    const line = value.line_items[index];
    if (!line) return;
    updateLine(index, { variant: { ...line.variant, [field]: next } });
  };

  return (
    <Modal title="Correct receipt" onClose={onClose}>
      <form className="receipt-correction-form" onSubmit={submit}>
        <div className="field-grid">
          <TextField
            label="Merchant"
            value={value.merchant}
            autoFocus
            onChange={(next) => updateOrder("merchant", next)}
          />
          <TextField
            label="Order identifier"
            value={value.order_identifier}
            onChange={(next) => updateOrder("order_identifier", next)}
          />
          <label>
            Purchase date
            <input
              type="date"
              value={value.purchase_date}
              onChange={(event) =>
                updateOrder("purchase_date", event.currentTarget.value)
              }
            />
          </label>
          <TextField
            label="Currency"
            value={value.currency}
            maxLength={3}
            onChange={(next) => updateOrder("currency", next)}
          />
        </div>

        <ol className="correction-lines">
          {value.line_items.map((line, index) => (
            <li key={line.order_line_id}>
              <fieldset>
                <legend>Order line {index + 1}</legend>
                <div className="field-grid">
                  <TextField
                    label={`Line ${index + 1} description`}
                    value={line.description}
                    onChange={(next) =>
                      updateLine(index, { description: next })
                    }
                  />
                  <label>
                    {`Line ${index + 1} event`}
                    <select
                      value={line.event_kind}
                      onChange={(event) =>
                        updateLine(index, {
                          event_kind: event.currentTarget
                            .value as ReceiptCorrectionDraft["line_items"][number]["event_kind"],
                        })
                      }
                    >
                      <option value="">Unknown</option>
                      <option value="purchase">Purchase</option>
                      <option value="exchange">Exchange</option>
                      <option value="return">Return</option>
                    </select>
                  </label>
                  <TextField
                    label={`Line ${index + 1} quantity`}
                    value={line.quantity}
                    inputMode="numeric"
                    onChange={(next) => updateLine(index, { quantity: next })}
                  />
                  <TextField
                    label={`Line ${index + 1} unit price in minor units`}
                    value={line.unit_price_minor}
                    inputMode="numeric"
                    onChange={(next) =>
                      updateLine(index, { unit_price_minor: next })
                    }
                  />
                </div>
                <h3>Variant evidence</h3>
                <div className="field-grid correction-variant-fields">
                  {(["brand", "sku", "size", "color"] as const).map((field) => (
                    <TextField
                      key={field}
                      label={`Line ${index + 1} ${field.toUpperCase() === "SKU" ? "SKU" : field}`}
                      value={line.variant[field]}
                      onChange={(next) => updateVariant(index, field, next)}
                    />
                  ))}
                </div>
              </fieldset>
            </li>
          ))}
        </ol>

        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button className="button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button button-primary"
            type="submit"
            disabled={busy}
          >
            {busy ? "Saving..." : "Save correction"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function TextField({
  label,
  value,
  onChange,
  maxLength = 500,
  inputMode,
  autoFocus = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  maxLength?: number;
  inputMode?: "numeric";
  autoFocus?: boolean;
}) {
  return (
    <label>
      {label}
      <input
        type="text"
        value={value}
        maxLength={maxLength}
        inputMode={inputMode}
        data-autofocus={autoFocus || undefined}
        onChange={(event) => onChange(event.currentTarget.value)}
      />
    </label>
  );
}

function Modal({
  title,
  children,
  onClose,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(
    document.activeElement instanceof HTMLElement ? document.activeElement : null,
  );
  const onCloseRef = useRef(onClose);
  const titleId = "receipt-correction-title";

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    const panel = panelRef.current;
    (
      panel?.querySelector<HTMLElement>("[data-autofocus]") ??
      panel?.querySelector<HTMLElement>(
        "input, button, select, textarea, [tabindex]:not([tabindex='-1'])",
      )
    )?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
      }
      if (event.key !== "Tab" || !panel) return;
      const controls = [
        ...panel.querySelectorAll<HTMLElement>(
          "input:not(:disabled), button:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])",
        ),
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
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      previousFocus.current?.focus();
    };
  }, []);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <div
        className="modal-panel receipt-correction-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        ref={panelRef}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="modal-heading">
          <h2 id={titleId}>{title}</h2>
          <button
            className="icon-button"
            type="button"
            aria-label="Close correction"
            onClick={onClose}
          >
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function appendReceipts(
  current: ReceiptSummaryV1[],
  incoming: ReceiptSummaryV1[],
): ReceiptSummaryV1[] {
  const values = new Map(current.map((value) => [value.source_id, value]));
  for (const value of incoming) values.set(value.source_id, value);
  return [...values.values()];
}

function pastTense(action: Exclude<ReceiptReviewActionV1, "correct">): string {
  if (action === "confirm") return "confirmed";
  if (action === "defer") return "deferred";
  return "rejected";
}

function humanize(value: string): string {
  return value
    .split("_")
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}
