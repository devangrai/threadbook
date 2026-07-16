import {
  type PointerEvent as ReactPointerEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  photoAnalysisBridge,
  type PhotoAnalysisBridge,
} from "./photo-analysis-bridge";
import {
  ownerReviewBridge,
  type OwnerReviewBridge,
} from "./owner-review-bridge";
import { OwnerReviewWorkspace } from "./OwnerReviewWorkspace";
import {
  reconciliationBridge,
  type ReconciliationBridge,
} from "./reconciliation-bridge";
import { ReconciliationPanel } from "./ReconciliationPanel";
import type {
  AnalyzePhotoScopeV1Response,
  DetectPhotoScopePeopleV1Response,
  ImportedPhotoRootV1,
  ListImportedPhotoRootsV1Response,
  ListPhotoObservationsV1Response,
  ListReconciliationCasesV2Response,
  OpenReconciliationCaseV2Response,
  PhotoObservationStateV1,
  PhotoObservationV1,
  PhotoReviewActionV1,
  PhotoScopeV1,
  ReconciliationCaseV2,
  RectV1,
} from "./generated/contracts";
import {
  abbreviateHash,
  appendUniqueObservations,
  displayPhotoError,
  isPhotoConflict,
  observationOutcome,
  parseRectangleDraft,
  rectangleDraft,
  type RectangleDraft,
  type VerifiedPhotoArtifact,
} from "./photo-analysis-model";
import { displayReconciliationError } from "./reconciliation-model";

const workspaceStorageKey = "wardrobe-photo-workspace-v1";

const observationStates: ReadonlyArray<{
  id: PhotoObservationStateV1;
  label: string;
}> = [
  { id: "needs_review", label: "Needs review" },
  { id: "confirmed", label: "Confirmed" },
  { id: "replaced", label: "Replaced" },
  { id: "deferred", label: "Deferred" },
  { id: "rejected", label: "Rejected" },
];

type PersistedWorkspace = {
  scope: PhotoScopeV1;
  detection: DetectPhotoScopePeopleV1Response | null;
  run: AnalyzePhotoScopeV1Response | null;
  ownerRevision: number;
  ownerEligible: boolean;
};

type ReconciliationSnapshot = {
  reconciliationCase: ReconciliationCaseV2;
  photoRevision: number;
  ownerRevision: number;
  reconciliationRevision: number;
};

type EditorState = {
  observationId: string;
  draft: RectangleDraft;
  error: string | null;
};

type PhotoAnalysisWorkspaceProps = {
  bridge?: PhotoAnalysisBridge;
  ownerBridge?: OwnerReviewBridge;
  reconciliation?: ReconciliationBridge;
};

export function PhotoAnalysisWorkspace({
  bridge = photoAnalysisBridge,
  ownerBridge = ownerReviewBridge,
  reconciliation = reconciliationBridge,
}: PhotoAnalysisWorkspaceProps) {
  const restored = useRef(loadWorkspace()).current;
  const [roots, setRoots] = useState<ListImportedPhotoRootsV1Response | null>(
    null,
  );
  const [selectedRootId, setSelectedRootId] = useState<string | null>(null);
  const [scope, setScope] = useState<PhotoScopeV1 | null>(
    restored?.scope ?? null,
  );
  const [detection, setDetection] =
    useState<DetectPhotoScopePeopleV1Response | null>(
      restored?.detection ?? null,
    );
  const [run, setRun] = useState<AnalyzePhotoScopeV1Response | null>(
    restored?.run ?? null,
  );
  const [ownerRevision, setOwnerRevision] = useState(
    restored?.ownerRevision ?? restored?.detection?.owner_revision ?? 0,
  );
  const [ownerEligible, setOwnerEligible] = useState(
    restored?.ownerEligible ?? false,
  );
  const [filter, setFilter] =
    useState<PhotoObservationStateV1>("needs_review");
  const [page, setPage] =
    useState<ListPhotoObservationsV1Response | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [focusTarget, setFocusTarget] = useState<string | null>(null);
  const [reconciliationCases, setReconciliationCases] = useState<
    Record<string, ReconciliationSnapshot>
  >({});

  const loadRoots = useCallback(
    async (cursor: string | null = null, append = false) => {
      const next = await bridge.listImportedRoots(cursor, 20);
      setRoots((current) =>
        append && current
          ? {
              ...next,
              roots: appendRoots(current.roots, next.roots),
            }
          : next,
      );
    },
    [bridge],
  );

  const loadObservations = useCallback(
    async (
      activeScope: PhotoScopeV1,
      state: PhotoObservationStateV1,
      cursor: string | null = null,
      append = false,
    ) => {
      const next = await bridge.listObservations(
        activeScope.scope_id,
        state,
        cursor,
        20,
      );
      setPage((current) =>
        append && current
          ? {
              ...next,
              observations: appendUniqueObservations(
                current.observations,
                next.observations,
              ),
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
    void Promise.all([
      loadRoots(),
      scope && run
        ? loadObservations(scope, filter)
        : Promise.resolve(undefined),
    ])
      .catch((error) => {
        if (active) setMessage(displayPhotoError(error));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []); // Listing on mount is inert; later filter changes are explicit.

  useEffect(() => {
    if (!focusTarget) return;
    const target = document.getElementById(focusTarget);
    if (target instanceof HTMLElement) {
      target.focus();
      setFocusTarget(null);
    }
  }, [focusTarget, page, editor]);

  const freezeScope = async () => {
    const root = roots?.roots.find(
      (candidate) => candidate.import_root_id === selectedRootId,
    );
    if (!root) return;
    setBusy("freeze");
    setMessage(null);
    try {
      const response = await bridge.createScope(
        root.import_root_id,
        root.manifest_generation,
      );
      setScope(response.scope);
      setDetection(null);
      setRun(null);
      setOwnerRevision(0);
      setOwnerEligible(false);
      setPage(null);
      persistWorkspace({
        scope: response.scope,
        detection: null,
        run: null,
        ownerRevision: 0,
        ownerEligible: false,
      });
      setMessage("Photo scope frozen.");
      setFocusTarget("photo-scope-heading");
    } catch (error) {
      setMessage(displayPhotoError(error));
    } finally {
      setBusy(null);
    }
  };

  const detectPeople = async () => {
    if (!scope) return;
    setBusy("detect");
    setMessage(null);
    try {
      const response = await ownerBridge.detectPeople(scope.scope_id);
      setDetection(response);
      setOwnerRevision(response.owner_revision);
      setOwnerEligible(false);
      setRun(null);
      setPage(null);
      persistWorkspace({
        scope,
        detection: response,
        run: null,
        ownerRevision: response.owner_revision,
        ownerEligible: false,
      });
      setMessage("Person detection completed. Confirm owner presence.");
      setFocusTarget("owner-review-title");
    } catch (error) {
      setMessage(displayPhotoError(error));
    } finally {
      setBusy(null);
    }
  };

  const updateOwnerAuthority = async (
    nextOwnerRevision: number,
    selected: boolean,
  ) => {
    if (!scope || !detection) return;
    setOwnerRevision(nextOwnerRevision);
    setOwnerEligible(selected);
    setReconciliationCases({});
    if (!selected) {
      persistWorkspace({
        scope,
        detection,
        run,
        ownerRevision: nextOwnerRevision,
        ownerEligible: false,
      });
      return;
    }
    setBusy("analyze");
    setMessage(null);
    try {
      const response = await bridge.analyzeScope(scope.scope_id);
      setRun(response);
      persistWorkspace({
        scope,
        detection,
        run: response,
        ownerRevision: nextOwnerRevision,
        ownerEligible: true,
      });
      setFilter("needs_review");
      await loadObservations(scope, "needs_review");
      setMessage("Garment analysis completed. Review local fallback crops.");
      setFocusTarget("photo-results-heading");
    } catch (error) {
      setMessage(displayPhotoError(error));
      throw error;
    } finally {
      setBusy(null);
    }
  };

  const changeFilter = async (state: PhotoObservationStateV1) => {
    if (!scope || !run) return;
    setFilter(state);
    setEditor(null);
    setReconciliationCases({});
    setLoading(true);
    setMessage(null);
    try {
      await loadObservations(scope, state);
    } catch (error) {
      setMessage(displayPhotoError(error));
    } finally {
      setLoading(false);
    }
  };

  const openReconciliation = async (observation: PhotoObservationV1) => {
    if (!page || !ownerEligible) return;
    setBusy(`reconcile:${observation.observation_id}`);
    setMessage(null);
    try {
      const listed = await reconciliation.listCases(
        observation.observation_id,
        "all",
        null,
        20,
      );
      const existing = listed.cases[0];
      const response = existing
        ? snapshotFromList(existing, listed)
        : snapshotFromOpen(
            await reconciliation.openCase(
              observation.observation_id,
              observation.artifact.artifact_id,
              page.photo_revision,
              ownerRevision,
            ),
          );
      setReconciliationCases((current) => ({
        ...current,
        [observation.observation_id]: response,
      }));
      setMessage("Local match candidates ready.");
    } catch (error) {
      setMessage(displayReconciliationError(error));
    } finally {
      setBusy(null);
    }
  };

  const review = async (
    observation: PhotoObservationV1,
    action: PhotoReviewActionV1,
    replacement: RectV1 | null,
  ) => {
    if (!scope || !page) return;
    setBusy(`review:${observation.observation_id}`);
    setMessage(null);
    try {
      await bridge.reviewObservation(
        observation.observation_id,
        action,
        replacement,
        page.photo_revision,
      );
      setEditor(null);
      await loadObservations(scope, filter);
      setMessage(reviewMessage(action));
      setFocusTarget("photo-results-heading");
    } catch (error) {
      if (isPhotoConflict(error)) {
        try {
          await loadObservations(scope, filter);
        } catch {
          // Preserve the original conflict and the local rectangle draft.
        }
      }
      setMessage(displayPhotoError(error));
    } finally {
      setBusy(null);
    }
  };

  const prompt = async (observation: PhotoObservationV1) => {
    if (!editor || !page) return;
    const parsed = parseRectangleDraft(
      editor.draft,
      observation.artifact.source_width,
      observation.artifact.source_height,
    );
    if (!parsed.rectangle) {
      setEditor({ ...editor, error: parsed.error });
      return;
    }
    setBusy(`prompt:${observation.observation_id}`);
    setMessage(null);
    try {
      const response = await bridge.promptObservation(
        observation.observation_id,
        parsed.rectangle,
      );
      setPage({
        ...page,
        photo_revision: response.photo_revision,
        evidence_generation: response.evidence_generation,
        observations: page.observations.map((value) =>
          value.observation_id === observation.observation_id
            ? response.observation
            : value,
        ),
      });
      setEditor({
        observationId: observation.observation_id,
        draft: rectangleDraft(
          response.observation.artifact.rectangle,
          response.observation.artifact.source_width,
          response.observation.artifact.source_height,
        ),
        error: null,
      });
      setMessage(observationOutcome(response.observation));
      setFocusTarget(`replace-${observation.observation_id}`);
    } catch (error) {
      setMessage(displayPhotoError(error));
    } finally {
      setBusy(null);
    }
  };

  if (loading && !roots) {
    return (
      <section className="state-view" aria-label="Loading photos">
        <span className="spinner" aria-hidden="true" />
        <p>Loading photos...</p>
      </section>
    );
  }

  return (
    <section aria-labelledby="photos-title" aria-busy={loading}>
      <div className="sr-live" role="status" aria-live="polite">
        {message}
      </div>
      <div className="view-heading">
        <div>
          <h2 id="photos-title">Photos</h2>
          <p className="count">{roots?.total_count ?? 0} imported generations</p>
        </div>
      </div>

      {!scope ? (
        <RootPicker
          roots={roots}
          selectedRootId={selectedRootId}
          busy={busy}
          onSelect={setSelectedRootId}
          onFreeze={() => void freezeScope()}
          onLoadMore={() => {
            if (!roots?.next_cursor) return;
            setLoading(true);
            void loadRoots(roots.next_cursor, true)
              .catch((error) => setMessage(displayPhotoError(error)))
              .finally(() => setLoading(false));
          }}
        />
      ) : (
        <>
          <ScopeSummary
            scope={scope}
            detection={detection}
            run={run}
            busy={busy}
            onDetect={() => void detectPeople()}
            onChangeScope={() => {
              clearWorkspace();
              setScope(null);
              setDetection(null);
              setOwnerRevision(0);
              setOwnerEligible(false);
              setRun(null);
              setPage(null);
              setSelectedRootId(null);
            }}
          />
          {detection && (
            <OwnerReviewWorkspace
              scopeId={scope.scope_id}
              bridge={ownerBridge}
              onAuthorityChange={updateOwnerAuthority}
            />
          )}
          {run && (
            <section className="photo-results" aria-labelledby="photo-results-heading">
              <div className="photo-results-heading">
                <div>
                  <h3 id="photo-results-heading" tabIndex={-1}>
                    Review
                  </h3>
                  <p className="count">{page?.total_count ?? 0} in this view</p>
                </div>
              </div>
              <div className="receipt-filter-scroll">
                <div
                  className="segmented photo-filters"
                  aria-label="Photo review state"
                >
                  {observationStates.map((state) => (
                    <button
                      type="button"
                      aria-pressed={filter === state.id}
                      onClick={() => void changeFilter(state.id)}
                      key={state.id}
                    >
                      {state.label}
                    </button>
                  ))}
                </div>
              </div>

              {!page?.observations.length ? (
                <div className="empty-state compact">
                  <p>No {stateLabel(filter).toLowerCase()} photos</p>
                </div>
              ) : (
                <ol className="photo-observation-list">
                  {page.observations.map((observation, index) => (
                    <li key={observation.observation_id}>
                      <ObservationRow
                        observation={observation}
                        index={index}
                        bridge={bridge}
                        reconciliation={reconciliation}
                        busy={busy}
                        reconciliationCase={
                          reconciliationCases[observation.observation_id] ?? null
                        }
                        ownerEligible={ownerEligible}
                        editor={
                          editor?.observationId === observation.observation_id
                            ? editor
                            : null
                        }
                        onEdit={() =>
                          setEditor({
                            observationId: observation.observation_id,
                            draft: rectangleDraft(
                              observation.artifact.rectangle,
                              observation.artifact.source_width,
                              observation.artifact.source_height,
                            ),
                            error: null,
                          })
                        }
                        onDraft={(draft) =>
                          setEditor((current) =>
                            current
                              ? { ...current, draft, error: null }
                              : current,
                          )
                        }
                        onCancel={() => {
                          setEditor(null);
                          setFocusTarget(
                            `adjust-${observation.observation_id}`,
                          );
                        }}
                        onPrompt={() => void prompt(observation)}
                        onReview={(action, replacement) =>
                          void review(observation, action, replacement)
                        }
                        onOpenReconciliation={() =>
                          void openReconciliation(observation)
                        }
                        onReconciliationCaseChange={(value) =>
                          setReconciliationCases((current) => ({
                            ...current,
                            [observation.observation_id]: {
                              reconciliationCase: value.case,
                              photoRevision: value.photo_revision,
                              ownerRevision: value.owner_revision,
                              reconciliationRevision:
                                value.reconciliation_revision,
                            },
                          }))
                        }
                      />
                    </li>
                  ))}
                </ol>
              )}
              {page?.next_cursor && (
                <button
                  className="button load-more"
                  type="button"
                  disabled={loading}
                  onClick={() => {
                    setLoading(true);
                    void loadObservations(
                      scope,
                      filter,
                      page.next_cursor,
                      true,
                    )
                      .catch((error) => setMessage(displayPhotoError(error)))
                      .finally(() => setLoading(false));
                  }}
                >
                  {loading ? "Loading..." : "Load more photos"}
                </button>
              )}
            </section>
          )}
        </>
      )}
    </section>
  );
}

function RootPicker({
  roots,
  selectedRootId,
  busy,
  onSelect,
  onFreeze,
  onLoadMore,
}: {
  roots: ListImportedPhotoRootsV1Response | null;
  selectedRootId: string | null;
  busy: string | null;
  onSelect: (rootId: string) => void;
  onFreeze: () => void;
  onLoadMore: () => void;
}) {
  if (!roots?.roots.length) {
    return (
      <div className="empty-state compact">
        <p>No completed photo generations</p>
      </div>
    );
  }

  return (
    <fieldset className="photo-root-picker">
      <legend>Imported generations</legend>
      <ul>
        {roots.roots.map((root) => (
          <li key={`${root.import_root_id}:${root.manifest_generation}`}>
            <label>
              <input
                type="radio"
                name="photo-root"
                value={root.import_root_id}
                checked={selectedRootId === root.import_root_id}
                onChange={() => onSelect(root.import_root_id)}
              />
              <span>
                <strong>Folder {root.import_root_id.slice(0, 8)}</strong>
                <small>
                  Generation {root.manifest_generation} · {root.member_count}{" "}
                  members · {root.quarantined_count} quarantined
                </small>
              </span>
            </label>
          </li>
        ))}
      </ul>
      <div className="photo-picker-actions">
        {roots.next_cursor && (
          <button className="button" type="button" onClick={onLoadMore}>
            Load more generations
          </button>
        )}
        <button
          className="button button-primary"
          type="button"
          disabled={!selectedRootId || busy === "freeze"}
          onClick={onFreeze}
        >
          {busy === "freeze" ? "Freezing..." : "Freeze scope"}
        </button>
      </div>
    </fieldset>
  );
}

function ScopeSummary({
  scope,
  detection,
  run,
  busy,
  onDetect,
  onChangeScope,
}: {
  scope: PhotoScopeV1;
  detection: DetectPhotoScopePeopleV1Response | null;
  run: AnalyzePhotoScopeV1Response | null;
  busy: string | null;
  onDetect: () => void;
  onChangeScope: () => void;
}) {
  return (
    <section className="photo-scope" aria-labelledby="photo-scope-heading">
      <div className="section-title-row">
        <div>
          <h3 id="photo-scope-heading" tabIndex={-1}>
            Frozen scope
          </h3>
          <p>Generation {scope.manifest_generation}</p>
        </div>
        <div className="photo-scope-actions">
          <button className="button" type="button" onClick={onChangeScope}>
            Choose generation
          </button>
          {!detection && (
            <button
              className="button button-primary"
              type="button"
              disabled={busy === "detect"}
              onClick={onDetect}
            >
              {busy === "detect" ? "Detecting..." : "Detect people"}
            </button>
          )}
        </div>
      </div>
      <dl className="photo-scope-facts">
        <div>
          <dt>Members</dt>
          <dd>{scope.member_count}</dd>
        </div>
        <div>
          <dt>Membership hash</dt>
          <dd title={scope.membership_sha256}>
            <code>{abbreviateHash(scope.membership_sha256)}</code>
          </dd>
        </div>
        <div>
          <dt>Eligible</dt>
          <dd>{scope.eligible_count}</dd>
        </div>
        <div>
          <dt>Quarantined</dt>
          <dd>{scope.quarantined_count}</dd>
        </div>
      </dl>
      {detection && (
        <div className="photo-run-summary">
          <span>{detection.completed_count} checked</span>
          <span>{detection.terminal_review_count} need owner review</span>
          <span>
            {detection.instances_available_count} with people detected
          </span>
          <span>{detection.skipped_count} skipped</span>
        </div>
      )}
      {run && (
        <div className="photo-run-summary">
          <span>{run.completed_count} completed</span>
          <span>{run.needs_review_count} need review</span>
          <span>{run.skipped_count} skipped</span>
          <span>{run.failed_count} failed</span>
        </div>
      )}
    </section>
  );
}

function ObservationRow({
  observation,
  index,
  bridge,
  reconciliation,
  busy,
  reconciliationCase,
  ownerEligible,
  editor,
  onEdit,
  onDraft,
  onCancel,
  onPrompt,
  onReview,
  onOpenReconciliation,
  onReconciliationCaseChange,
}: {
  observation: PhotoObservationV1;
  index: number;
  bridge: PhotoAnalysisBridge;
  reconciliation: ReconciliationBridge;
  busy: string | null;
  reconciliationCase: ReconciliationSnapshot | null;
  ownerEligible: boolean;
  editor: EditorState | null;
  onEdit: () => void;
  onDraft: (draft: RectangleDraft) => void;
  onCancel: () => void;
  onPrompt: () => void;
  onReview: (
    action: PhotoReviewActionV1,
    replacement: RectV1 | null,
  ) => void;
  onOpenReconciliation: () => void;
  onReconciliationCaseChange: (
    value: import("./generated/contracts").DecideReconciliationCaseV2Response,
  ) => void;
}) {
  const parsed = editor
    ? parseRectangleDraft(
        editor.draft,
        observation.artifact.source_width,
        observation.artifact.source_height,
      )
    : null;
  const editingRectangle = parsed?.rectangle ?? null;
  const disabled = busy !== null;
  const canReconcile =
    ownerEligible &&
    (observation.state === "confirmed" || observation.state === "replaced");

  return (
    <article className="photo-observation">
      <PhotoPreview
        observation={observation}
        bridge={bridge}
        editingRectangle={editingRectangle}
        onDraw={
          editor
            ? (rectangle) => onDraft(rectangleDraft(rectangle, 0, 0))
            : undefined
        }
      />
      <div className="photo-observation-body">
        <div className="photo-observation-title">
          <div>
            <h4>Photo {index + 1}</h4>
            <span className={`photo-state photo-state-${observation.state}`}>
              {stateLabel(observation.state)}
            </span>
          </div>
          <code title={observation.artifact.artifact_sha256}>
            {abbreviateHash(observation.artifact.artifact_sha256)}
          </code>
        </div>
        <p className="photo-outcome">{observationOutcome(observation)}</p>

        {editor ? (
          <RectangleEditor
            observation={observation}
            editor={editor}
            parsedError={parsed?.error ?? null}
            disabled={disabled}
            onDraft={onDraft}
            onCancel={onCancel}
            onPrompt={onPrompt}
            onReplace={(rectangle) => onReview("replace_crop", rectangle)}
          />
        ) : (
          <div className="photo-review-actions">
            <button
              className="button button-primary"
              type="button"
              disabled={disabled}
              onClick={() => onReview("confirm_crop", null)}
            >
              Confirm
            </button>
            <button
              className="button"
              id={`adjust-${observation.observation_id}`}
              type="button"
              disabled={disabled}
              onClick={onEdit}
            >
              Adjust rectangle
            </button>
            <button
              className="button"
              type="button"
              disabled={disabled}
              onClick={() => onReview("defer", null)}
            >
              Defer
            </button>
            <button
              className="button button-danger"
              type="button"
              disabled={disabled}
              onClick={() => onReview("reject", null)}
            >
              Reject
            </button>
          </div>
        )}
        {canReconcile && (
          <div className="reconciliation-entry">
            {!reconciliationCase ? (
              <button
                className="button"
                type="button"
                disabled={
                  disabled ||
                  busy === `reconcile:${observation.observation_id}`
                }
                onClick={onOpenReconciliation}
              >
                {busy === `reconcile:${observation.observation_id}`
                  ? "Finding local matches..."
                  : "Find local matches"}
              </button>
            ) : (
              <ReconciliationPanel
                reconciliationCase={reconciliationCase.reconciliationCase}
                photoRevision={reconciliationCase.photoRevision}
                ownerRevision={reconciliationCase.ownerRevision}
                reconciliationRevision={
                  reconciliationCase.reconciliationRevision
                }
                bridge={reconciliation}
                focusOnMount
                onCaseChange={onReconciliationCaseChange}
              />
            )}
          </div>
        )}
      </div>
    </article>
  );
}

function PhotoPreview({
  observation,
  bridge,
  editingRectangle,
  onDraw,
}: {
  observation: PhotoObservationV1;
  bridge: PhotoAnalysisBridge;
  editingRectangle: RectV1 | null;
  onDraw?: (rectangle: RectV1) => void;
}) {
  const [preview, setPreview] = useState<{
    artifact: VerifiedPhotoArtifact;
    url: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const drawStart = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => {
    let active = true;
    let url: string | null = null;
    setPreview(null);
    setError(null);
    void bridge
      .readArtifact(observation.artifact.artifact_id)
      .then((artifact) => {
        if (!active) return;
        const buffer = Uint8Array.from(artifact.bytes).buffer;
        url = URL.createObjectURL(
          new Blob([buffer], { type: artifact.mediaType }),
        );
        setPreview({ artifact, url });
      })
      .catch((reason) => {
        if (active) setError(displayPhotoError(reason));
      });
    return () => {
      active = false;
      if (url) URL.revokeObjectURL(url);
    };
  }, [bridge, observation.artifact.artifact_id]);

  const rectangle = editingRectangle ?? observation.artifact.rectangle;
  const drawPoint = (event: ReactPointerEvent<HTMLDivElement>) => {
    const bounds = event.currentTarget.getBoundingClientRect();
    return {
      x: Math.max(
        0,
        Math.min(
          observation.artifact.source_width,
          Math.round(
            ((event.clientX - bounds.left) / bounds.width) *
              observation.artifact.source_width,
          ),
        ),
      ),
      y: Math.max(
        0,
        Math.min(
          observation.artifact.source_height,
          Math.round(
            ((event.clientY - bounds.top) / bounds.height) *
              observation.artifact.source_height,
          ),
        ),
      ),
    };
  };
  const updateDraw = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!drawStart.current || !onDraw) return;
    const point = drawPoint(event);
    const x = Math.min(drawStart.current.x, point.x);
    const y = Math.min(drawStart.current.y, point.y);
    const width = Math.max(1, Math.abs(point.x - drawStart.current.x));
    const height = Math.max(1, Math.abs(point.y - drawStart.current.y));
    onDraw({
      x,
      y,
      width: Math.min(width, observation.artifact.source_width - x),
      height: Math.min(height, observation.artifact.source_height - y),
    });
  };

  return (
    <div
      className={`photo-preview${onDraw ? " photo-preview-editing" : ""}`}
      onPointerDown={
        onDraw
          ? (event) => {
              drawStart.current = drawPoint(event);
              event.currentTarget.setPointerCapture(event.pointerId);
            }
          : undefined
      }
      onPointerMove={onDraw ? updateDraw : undefined}
      onPointerUp={
        onDraw
          ? (event) => {
              updateDraw(event);
              drawStart.current = null;
              event.currentTarget.releasePointerCapture(event.pointerId);
            }
          : undefined
      }
    >
      {!preview && !error && <span className="spinner" aria-label="Loading preview" />}
      {error && <span className="photo-preview-error">Preview unavailable</span>}
      {preview && (
        <img
          src={preview.url}
          alt={`Local preview for photo ${observation.observation_id.slice(0, 8)}`}
          draggable={false}
        />
      )}
      {rectangle && (
        <span
          className="photo-rectangle"
          aria-hidden="true"
          style={{
            left: `${(rectangle.x / observation.artifact.source_width) * 100}%`,
            top: `${(rectangle.y / observation.artifact.source_height) * 100}%`,
            width: `${(rectangle.width / observation.artifact.source_width) * 100}%`,
            height: `${(rectangle.height / observation.artifact.source_height) * 100}%`,
          }}
        />
      )}
    </div>
  );
}

function RectangleEditor({
  observation,
  editor,
  parsedError,
  disabled,
  onDraft,
  onCancel,
  onPrompt,
  onReplace,
}: {
  observation: PhotoObservationV1;
  editor: EditorState;
  parsedError: string | null;
  disabled: boolean;
  onDraft: (draft: RectangleDraft) => void;
  onCancel: () => void;
  onPrompt: () => void;
  onReplace: (rectangle: RectV1) => void;
}) {
  const update = (field: keyof RectangleDraft, value: string) =>
    onDraft({ ...editor.draft, [field]: value });
  const parsed = parseRectangleDraft(
    editor.draft,
    observation.artifact.source_width,
    observation.artifact.source_height,
  );

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
              value={editor.draft[field]}
              onChange={(event) => update(field, event.currentTarget.value)}
            />
          </label>
        ))}
      </div>
      {(editor.error || parsedError) && (
        <p className="form-error">{editor.error ?? parsedError}</p>
      )}
      <div className="photo-review-actions">
        <button className="button" type="button" onClick={onCancel}>
          Cancel
        </button>
        <button
          className="button"
          type="button"
          disabled={disabled || !parsed.rectangle}
          onClick={onPrompt}
        >
          Preview rectangle
        </button>
        <button
          className="button button-primary"
          id={`replace-${observation.observation_id}`}
          type="button"
          disabled={disabled || !parsed.rectangle}
          onClick={() => {
            if (parsed.rectangle) onReplace(parsed.rectangle);
          }}
        >
          Replace crop
        </button>
      </div>
    </div>
  );
}

function appendRoots(
  current: readonly ImportedPhotoRootV1[],
  incoming: readonly ImportedPhotoRootV1[],
): ImportedPhotoRootV1[] {
  const values = new Map(
    current.map((root) => [
      `${root.import_root_id}:${root.manifest_generation}`,
      root,
    ]),
  );
  for (const root of incoming) {
    values.set(`${root.import_root_id}:${root.manifest_generation}`, root);
  }
  return [...values.values()];
}

function snapshotFromOpen(
  response: OpenReconciliationCaseV2Response,
): ReconciliationSnapshot {
  return {
    reconciliationCase: response.case,
    photoRevision: response.photo_revision,
    ownerRevision: response.owner_revision,
    reconciliationRevision: response.reconciliation_revision,
  };
}

function snapshotFromList(
  reconciliationCase: ReconciliationCaseV2,
  response: ListReconciliationCasesV2Response,
): ReconciliationSnapshot {
  return {
    reconciliationCase,
    photoRevision: response.photo_revision,
    ownerRevision: response.owner_revision,
    reconciliationRevision: response.reconciliation_revision,
  };
}

function reviewMessage(action: PhotoReviewActionV1): string {
  if (action === "confirm_crop") return "Photo crop confirmed.";
  if (action === "replace_crop") return "Photo crop replaced.";
  if (action === "defer") return "Photo review deferred.";
  return "Photo observation rejected.";
}

function stateLabel(state: PhotoObservationStateV1): string {
  return state
    .split("_")
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

function loadWorkspace(): PersistedWorkspace | null {
  try {
    const stored = sessionStorage.getItem(workspaceStorageKey);
    return stored ? (JSON.parse(stored) as PersistedWorkspace) : null;
  } catch {
    return null;
  }
}

function persistWorkspace(workspace: PersistedWorkspace) {
  sessionStorage.setItem(workspaceStorageKey, JSON.stringify(workspace));
}

function clearWorkspace() {
  sessionStorage.removeItem(workspaceStorageKey);
}
