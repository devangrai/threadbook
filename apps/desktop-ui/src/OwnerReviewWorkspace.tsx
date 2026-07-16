import {
  type PointerEvent as ReactPointerEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import type {
  PhotoOwnerActionV1,
  PhotoOwnerDecisionV1,
  PhotoOwnerReviewStateV1,
  PhotoOwnerReviewV1,
  RectV1,
} from "./generated/contracts";
import {
  ownerReviewBridge,
  type OwnerReviewBridge,
} from "./owner-review-bridge";
import {
  displayOwnerError,
  isOwnerConflict,
  ownerReviewStateLabel,
  type VerifiedOwnerPreview,
} from "./owner-review-model";
import {
  parseRectangleDraft,
  rectangleDraft,
  type RectangleDraft,
} from "./photo-analysis-model";

const reviewStates: readonly PhotoOwnerReviewStateV1[] = [
  "instances_available",
  "no_person_detected",
  "retryable_failure",
  "permanent_unavailable",
  "overflow",
];

type OwnerReviewWorkspaceProps = {
  scopeId: string;
  bridge?: OwnerReviewBridge;
  onAuthorityChange: (
    ownerRevision: number,
    ownerSelected: boolean,
  ) => Promise<void>;
};

export function OwnerReviewWorkspace({
  scopeId,
  bridge = ownerReviewBridge,
  onAuthorityChange,
}: OwnerReviewWorkspaceProps) {
  const [filter, setFilter] =
    useState<PhotoOwnerReviewStateV1>("instances_available");
  const [reviews, setReviews] = useState<PhotoOwnerReviewV1[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [decisions, setDecisions] = useState<
    Record<string, PhotoOwnerDecisionV1>
  >({});
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);

  const load = useCallback(
    async (
      state: PhotoOwnerReviewStateV1,
      cursor: string | null = null,
      append = false,
    ) => {
      const response = await bridge.listReviews(state, cursor, 20);
      setReviews((current) =>
        append
          ? appendReviews(current, response.reviews)
          : response.reviews,
      );
      setNextCursor(response.next_cursor);
    },
    [bridge],
  );

  useEffect(() => {
    let active = true;
    setLoading(true);
    void load(filter)
      .catch((error) => {
        if (active) setMessage(displayOwnerError(error));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [filter, load]);

  const recoverConflict = async (error: unknown) => {
    if (isOwnerConflict(error)) {
      try {
        await load(filter);
      } catch {
        // Preserve the authority conflict and the row's local draft.
      }
    }
    setMessage(displayOwnerError(error));
  };

  const updateReview = (review: PhotoOwnerReviewV1) => {
    setReviews((current) =>
      current.map((value) =>
        value.owner_review_id === review.owner_review_id ? review : value,
      ),
    );
  };

  const decide = async (
    review: PhotoOwnerReviewV1,
    action: PhotoOwnerActionV1,
    personId: string | null,
    supersededDecisionId: string | null,
  ) => {
    setBusy(`owner:${review.owner_review_id}`);
    setMessage(null);
    try {
      const response = supersededDecisionId
        ? await bridge.correctOwner(
            review,
            supersededDecisionId,
            action,
            personId,
          )
        : await bridge.decideOwner(review, action, personId);
      updateReview(response.review);
      setDecisions((current) => ({
        ...current,
        [review.owner_review_id]: response.decision,
      }));
      await onAuthorityChange(
        response.decision.owner_revision,
        action === "select_person",
      );
      if (action === "select_person") {
        await load(filter);
        setMessage(
          supersededDecisionId
            ? "Owner corrected. Garment review was refreshed."
            : "Owner confirmed. Garment review is ready.",
        );
      } else {
        setMessage(
          supersededDecisionId
            ? "Owner absence correction recorded."
            : "Owner absence recorded.",
        );
        headingRef.current?.focus();
      }
    } catch (error) {
      await recoverConflict(error);
    } finally {
      setBusy(null);
    }
  };

  const correctDetection = async (
    review: PhotoOwnerReviewV1,
    rectangle: RectV1,
  ) => {
    setBusy(`missed:${review.owner_review_id}`);
    setMessage(null);
    try {
      const response = await bridge.correctDetection(review, rectangle);
      updateReview(response.review);
      setMessage("Missed person added. Select the rectangle to confirm owner.");
      headingRef.current?.focus();
    } catch (error) {
      await recoverConflict(error);
      throw error;
    } finally {
      setBusy(null);
    }
  };

  const retry = async (review: PhotoOwnerReviewV1) => {
    setBusy(`retry:${review.owner_review_id}`);
    setMessage(null);
    try {
      await bridge.retryDetection(review);
      await bridge.detectPeople(scopeId);
      await load(filter);
      setMessage("Person detection retried.");
      headingRef.current?.focus();
    } catch (error) {
      await recoverConflict(error);
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="owner-review-workspace" aria-labelledby="owner-review-title">
      <div className="sr-live" role="status" aria-live="polite">
        {message}
      </div>
      <div className="photo-results-heading">
        <div>
          <h3 id="owner-review-title" ref={headingRef} tabIndex={-1}>
            Confirm owner
          </h3>
          <p className="count">{reviews.length} in this view</p>
        </div>
      </div>
      <div className="receipt-filter-scroll">
        <div className="segmented photo-filters" aria-label="Owner review state">
          {reviewStates.map((state) => (
            <button
              type="button"
              aria-pressed={filter === state}
              onClick={() => setFilter(state)}
              key={state}
            >
              {ownerReviewStateLabel(state)}
            </button>
          ))}
        </div>
      </div>

      {loading && reviews.length === 0 ? (
        <div className="state-view compact" aria-label="Loading owner reviews">
          <span className="spinner" aria-hidden="true" />
          <p>Loading owner reviews...</p>
        </div>
      ) : reviews.length === 0 ? (
        <div className="empty-state compact">
          <p>No {ownerReviewStateLabel(filter).toLowerCase()} reviews</p>
        </div>
      ) : (
        <ol className="owner-review-list">
          {reviews.map((review, index) => (
            <li key={review.owner_review_id}>
              <OwnerReviewRow
                review={review}
                index={index}
                bridge={bridge}
                busy={busy !== null}
                decision={decisions[review.owner_review_id] ?? null}
                onDecide={(action, personId, supersededDecisionId) =>
                  void decide(
                    review,
                    action,
                    personId,
                    supersededDecisionId,
                  )
                }
                onCorrectDetection={(rectangle) =>
                  correctDetection(review, rectangle)
                }
                onRetry={() => void retry(review)}
              />
            </li>
          ))}
        </ol>
      )}

      {nextCursor && (
        <button
          className="button load-more"
          type="button"
          disabled={loading}
          onClick={() => {
            setLoading(true);
            void load(filter, nextCursor, true)
              .catch((error) => setMessage(displayOwnerError(error)))
              .finally(() => setLoading(false));
          }}
        >
          {loading ? "Loading..." : "Load more owner reviews"}
        </button>
      )}
    </section>
  );
}

function OwnerReviewRow({
  review,
  index,
  bridge,
  busy,
  decision,
  onDecide,
  onCorrectDetection,
  onRetry,
}: {
  review: PhotoOwnerReviewV1;
  index: number;
  bridge: OwnerReviewBridge;
  busy: boolean;
  decision: PhotoOwnerDecisionV1 | null;
  onDecide: (
    action: PhotoOwnerActionV1,
    personId: string | null,
    supersededDecisionId: string | null,
  ) => void;
  onCorrectDetection: (rectangle: RectV1) => Promise<void>;
  onRetry: () => void;
}) {
  const [preview, setPreview] = useState<VerifiedOwnerPreview | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState(false);
  const [selectedPersonId, setSelectedPersonId] = useState<string | null>(
    decision?.selected_person_instance_id ?? null,
  );
  const [correcting, setCorrecting] = useState(false);
  const [manualDraft, setManualDraft] = useState<RectangleDraft | null>(null);
  const [manualError, setManualError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    let url: string | null = null;
    setPreview(null);
    setPreviewError(false);
    void bridge
      .readPreview(review.owner_review_id, review.preview_id)
      .then((verified) => {
        if (!active) return;
        url = URL.createObjectURL(
          new Blob([Uint8Array.from(verified.bytes).buffer], {
            type: verified.mediaType,
          }),
        );
        setPreview(verified);
        setPreviewUrl(url);
      })
      .catch(() => {
        if (active) setPreviewError(true);
      });
    return () => {
      active = false;
      if (url) URL.revokeObjectURL(url);
    };
  }, [bridge, review.owner_review_id, review.preview_id]);

  useEffect(() => {
    if (!decision) return;
    setCorrecting(false);
    setSelectedPersonId(decision.selected_person_instance_id);
  }, [decision]);

  const openManual = () => {
    if (!preview) return;
    setManualDraft(
      rectangleDraft(null, preview.width, preview.height),
    );
    setManualError(null);
  };
  const parsedManual =
    manualDraft && preview
      ? parseRectangleDraft(manualDraft, preview.width, preview.height)
      : null;
  const selectable = review.instances.length > 0;
  const correctionDecisionId =
    correcting && decision ? decision.owner_decision_id : null;

  return (
    <article className="owner-review-row">
      <OwnerPreview
        review={review}
        preview={preview}
        previewUrl={previewUrl}
        previewError={previewError}
        selectedPersonId={selectedPersonId}
        manualRectangle={parsedManual?.rectangle ?? null}
        onManualRectangle={(rectangle) =>
          setManualDraft(rectangleDraft(rectangle, 0, 0))
        }
        drawing={manualDraft !== null}
      />
      <div className="owner-review-body">
        <div className="photo-observation-title">
          <div>
            <h4>Owner review {index + 1}</h4>
            <span className="photo-state">
              {ownerReviewStateLabel(review.state)}
            </span>
          </div>
          <code title={review.source_revision_sha256}>
            {review.source_revision_sha256.slice(0, 10)}...
          </code>
        </div>

        {selectable && (!decision || correcting) && (
          <fieldset className="person-selection">
            <legend>Which person is you?</legend>
            {review.instances.map((instance, personIndex) => (
              <label key={instance.person_instance_id}>
                <input
                  type="radio"
                  name={`owner-${review.owner_review_id}`}
                  checked={selectedPersonId === instance.person_instance_id}
                  onChange={() =>
                    setSelectedPersonId(instance.person_instance_id)
                  }
                />
                <span>
                  Person {personIndex + 1}
                  {instance.source_kind === "manual_user_rectangle"
                    ? " (added manually)"
                    : ""}
                </span>
              </label>
            ))}
          </fieldset>
        )}

        {decision && !correcting ? (
          <div className="owner-authority-summary">
            <strong>
              {decision.action === "select_person"
                ? "Owner confirmed"
                : "Owner absent"}
            </strong>
            <button
              className="button"
              type="button"
              disabled={busy}
              onClick={() => setCorrecting(true)}
            >
              Change owner
            </button>
          </div>
        ) : manualDraft ? (
          <ManualRectangleEditor
            draft={manualDraft}
            error={manualError ?? parsedManual?.error ?? null}
            disabled={busy}
            onChange={(draft) => {
              setManualDraft(draft);
              setManualError(null);
            }}
            onCancel={() => {
              setManualDraft(null);
              setManualError(null);
            }}
            onSubmit={() => {
              if (!parsedManual?.rectangle) {
                setManualError(parsedManual?.error ?? "Rectangle is invalid.");
                return;
              }
              void onCorrectDetection(parsedManual.rectangle)
                .then(() => setManualDraft(null))
                .catch(() => undefined);
            }}
          />
        ) : (
          <div className="photo-review-actions owner-actions">
            {selectable && (
              <button
                className="button button-primary"
                type="button"
                disabled={busy || !selectedPersonId}
                onClick={() =>
                  onDecide(
                    "select_person",
                    selectedPersonId,
                    correctionDecisionId,
                  )
                }
              >
                This is me
              </button>
            )}
            <button
              className="button"
              type="button"
              disabled={busy}
              onClick={() =>
                onDecide("owner_absent", null, correctionDecisionId)
              }
            >
              I'm not in this photo
            </button>
            <button
              className="button"
              type="button"
              disabled={busy || !preview}
              onClick={openManual}
            >
              Person missed
            </button>
            {(review.state === "retryable_failure" ||
              review.state === "permanent_unavailable") && (
              <button
                className="button"
                type="button"
                disabled={busy}
                onClick={onRetry}
              >
                Retry detection
              </button>
            )}
            {correcting && (
              <button
                className="button"
                type="button"
                disabled={busy}
                onClick={() => {
                  setCorrecting(false);
                  setSelectedPersonId(
                    decision?.selected_person_instance_id ?? null,
                  );
                }}
              >
                Cancel correction
              </button>
            )}
          </div>
        )}
      </div>
    </article>
  );
}

function OwnerPreview({
  review,
  preview,
  previewUrl,
  previewError,
  selectedPersonId,
  manualRectangle,
  onManualRectangle,
  drawing,
}: {
  review: PhotoOwnerReviewV1;
  preview: VerifiedOwnerPreview | null;
  previewUrl: string | null;
  previewError: boolean;
  selectedPersonId: string | null;
  manualRectangle: RectV1 | null;
  onManualRectangle: (rectangle: RectV1) => void;
  drawing: boolean;
}) {
  const drawStart = useRef<{ x: number; y: number } | null>(null);
  const point = (
    event: ReactPointerEvent<HTMLDivElement>,
  ): { x: number; y: number } | null => {
    if (!preview) return null;
    const bounds = event.currentTarget.getBoundingClientRect();
    return {
      x: Math.max(
        0,
        Math.min(
          preview.width,
          Math.round(
            ((event.clientX - bounds.left) / bounds.width) * preview.width,
          ),
        ),
      ),
      y: Math.max(
        0,
        Math.min(
          preview.height,
          Math.round(
            ((event.clientY - bounds.top) / bounds.height) * preview.height,
          ),
        ),
      ),
    };
  };
  const update = (event: ReactPointerEvent<HTMLDivElement>) => {
    const current = point(event);
    if (!preview || !current || !drawStart.current) return;
    const x = Math.min(drawStart.current.x, current.x);
    const y = Math.min(drawStart.current.y, current.y);
    onManualRectangle({
      x,
      y,
      width: Math.max(
        1,
        Math.min(Math.abs(current.x - drawStart.current.x), preview.width - x),
      ),
      height: Math.max(
        1,
        Math.min(
          Math.abs(current.y - drawStart.current.y),
          preview.height - y,
        ),
      ),
    });
  };

  return (
    <div
      className={`photo-preview owner-preview${drawing ? " photo-preview-editing" : ""}`}
      onPointerDown={
        drawing
          ? (event) => {
              drawStart.current = point(event);
              event.currentTarget.setPointerCapture(event.pointerId);
            }
          : undefined
      }
      onPointerMove={drawing ? update : undefined}
      onPointerUp={
        drawing
          ? (event) => {
              update(event);
              drawStart.current = null;
              event.currentTarget.releasePointerCapture(event.pointerId);
            }
          : undefined
      }
    >
      {!preview && !previewError && (
        <span className="spinner" aria-label="Loading owner preview" />
      )}
      {previewError && (
        <span className="photo-preview-error">Preview unavailable</span>
      )}
      {previewUrl && (
        <img
          src={previewUrl}
          alt={`Owner review photo ${review.owner_review_id.slice(0, 8)}`}
          draggable={false}
        />
      )}
      {preview &&
        review.instances.map((instance, index) => (
          <span
            className={`owner-person-rectangle${
              selectedPersonId === instance.person_instance_id
                ? " owner-person-selected"
                : ""
            }`}
            aria-hidden="true"
            key={instance.person_instance_id}
            style={rectangleStyle(
              instance.rectangle,
              preview.width,
              preview.height,
            )}
          >
            {index + 1}
          </span>
        ))}
      {preview && manualRectangle && (
        <span
          className="owner-person-rectangle owner-person-manual"
          aria-hidden="true"
          style={rectangleStyle(
            manualRectangle,
            preview.width,
            preview.height,
          )}
        />
      )}
    </div>
  );
}

function ManualRectangleEditor({
  draft,
  error,
  disabled,
  onChange,
  onCancel,
  onSubmit,
}: {
  draft: RectangleDraft;
  error: string | null;
  disabled: boolean;
  onChange: (draft: RectangleDraft) => void;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  return (
    <div className="rectangle-editor">
      <div className="rectangle-fields">
        {(["x", "y", "width", "height"] as const).map((field) => (
          <label key={field}>
            {field === "x" || field === "y"
              ? field.toUpperCase()
              : field[0]?.toUpperCase() + field.slice(1)}
            <input
              type="number"
              min={field === "width" || field === "height" ? 1 : 0}
              step="1"
              value={draft[field]}
              onChange={(event) =>
                onChange({ ...draft, [field]: event.currentTarget.value })
              }
            />
          </label>
        ))}
      </div>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <div className="photo-review-actions">
        <button className="button" type="button" onClick={onCancel}>
          Cancel
        </button>
        <button
          className="button button-primary"
          type="button"
          disabled={disabled || !!error}
          onClick={onSubmit}
        >
          Add person
        </button>
      </div>
    </div>
  );
}

function rectangleStyle(
  rectangle: RectV1,
  width: number,
  height: number,
) {
  return {
    left: `${(rectangle.x / width) * 100}%`,
    top: `${(rectangle.y / height) * 100}%`,
    width: `${(rectangle.width / width) * 100}%`,
    height: `${(rectangle.height / height) * 100}%`,
  };
}

function appendReviews(
  current: readonly PhotoOwnerReviewV1[],
  incoming: readonly PhotoOwnerReviewV1[],
) {
  const values = new Map(
    current.map((review) => [review.owner_review_id, review]),
  );
  for (const review of incoming) {
    values.set(review.owner_review_id, review);
  }
  return [...values.values()];
}
