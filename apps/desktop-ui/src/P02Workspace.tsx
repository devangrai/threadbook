import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";

import { catalogBridge, type CatalogBridge } from "./catalog-bridge";
import {
  appendUniqueById,
  type CatalogAttributes,
  type CatalogItem,
  type CatalogPage,
  type DeletionPlan,
  type DeletionResult,
  displayCatalogError,
  type Evidence,
  type EvidenceState,
  type ImportResult,
  type InboxPage,
  isConflict,
  normalizeAttributes,
  validateAttributes,
} from "./catalog-model";

const emptyAttributes: CatalogAttributes = {
  display_name: "",
  category: "other",
  color: "",
  notes: "",
};

type P02WorkspaceProps = {
  mode: "catalog" | "inbox";
  bridge?: CatalogBridge;
  onDeletionActivity?: () => void | Promise<void>;
  pickFiles?: () => Promise<string[]>;
  pickFolder?: () => Promise<string[]>;
};

export function P02Workspace({
  mode,
  bridge = catalogBridge,
  onDeletionActivity,
  pickFiles = pickImportFiles,
  pickFolder = pickImportFolder,
}: P02WorkspaceProps) {
  const [catalog, setCatalog] = useState<CatalogPage | null>(null);
  const [inbox, setInbox] = useState<InboxPage | null>(null);
  const [inboxState, setInboxState] = useState<EvidenceState>("unresolved");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [editor, setEditor] = useState<{
    kind: "item" | "merge";
    item: CatalogItem | null;
  } | null>(null);
  const [splitItem, setSplitItem] = useState<CatalogItem | null>(null);
  const [deletionTarget, setDeletionTarget] = useState<CatalogItem | null>(null);
  const [deletionPlan, setDeletionPlan] = useState<DeletionPlan | null>(null);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);

  const loadCatalog = useCallback(
    async (append = false) => {
      const page = await bridge.listCatalog(
        append ? catalog?.next_cursor : null,
        20,
      );
      setCatalog((current) =>
        append && current
          ? {
              ...page,
              items: appendUniqueById(
                current.items,
                page.items,
                (item) => item.item_id,
              ),
            }
          : page,
      );
    },
    [bridge, catalog?.next_cursor],
  );

  const loadInbox = useCallback(
    async (append = false) => {
      const page = await bridge.listInbox(
        inboxState,
        append ? inbox?.next_cursor : null,
        20,
      );
      setInbox((current) =>
        append && current
          ? {
              ...page,
              items: appendUniqueById(
                current.items,
                page.items,
                (item) => item.evidence_id,
              ),
            }
          : page,
      );
    },
    [bridge, inbox?.next_cursor, inboxState],
  );

  const refreshAll = useCallback(async () => {
    setLoading(true);
    setMessage(null);
    try {
      await Promise.all([loadCatalog(), loadInbox()]);
    } catch (error) {
      setMessage(displayCatalogError(error));
    } finally {
      setLoading(false);
    }
  }, [loadCatalog, loadInbox]);

  useEffect(() => {
    void refreshAll();
  }, [inboxState]); // eslint-disable-line react-hooks/exhaustive-deps

  const runMutation = async (
    action: string,
    operation: () => Promise<unknown>,
    success: string,
  ) => {
    setBusy(action);
    setMessage(null);
    try {
      await operation();
      setMessage(success);
      setSelectedIds([]);
      await Promise.all([loadCatalog(), loadInbox()]);
      return true;
    } catch (error) {
      setMessage(displayCatalogError(error));
      return false;
    } finally {
      setBusy(null);
    }
  };

  const saveItem = async (
    attributes: CatalogAttributes,
    evidenceIds: string[],
  ) => {
    if (!catalog || !editor) return;
    const saved = await runMutation(
      "save-item",
      () =>
        bridge.saveItem(
          editor.item?.item_id ?? null,
          normalizeAttributes(attributes),
          evidenceIds,
          catalog.catalog_revision,
        ),
      editor.item ? "Item updated." : "Item created.",
    );
    if (saved) setEditor(null);
  };

  const mergeItems = async (attributes: CatalogAttributes) => {
    if (!catalog) return;
    const merged = await runMutation(
      "merge",
      () =>
        bridge.mergeItems(
          selectedIds,
          normalizeAttributes(attributes),
          catalog.catalog_revision,
        ),
      "Items merged. You can undo this decision from the item row.",
    );
    if (merged) setEditor(null);
  };

  const split = async (
    item: CatalogItem,
    firstName: string,
    movedEvidenceIds: string[],
  ) => {
    if (!catalog) return;
    const retained = item.evidence_ids.filter(
      (evidenceId) => !movedEvidenceIds.includes(evidenceId),
    );
    const completed = await runMutation(
      "split",
      () =>
        bridge.splitItem(
          item.item_id,
          [
            {
              attributes: {
                ...item,
                display_name: item.display_name,
              },
              evidence_ids: retained,
            },
            {
              attributes: {
                ...item,
                display_name: firstName.trim(),
              },
              evidence_ids: movedEvidenceIds,
            },
          ],
          catalog.catalog_revision,
        ),
      "Item split. Both items retain their evidence.",
    );
    if (completed) setSplitItem(null);
  };

  const undo = async (item: CatalogItem) => {
    if (!catalog || !item.last_decision_id) return;
    await runMutation(
      `undo:${item.item_id}`,
      () =>
        bridge.undoDecision(
          item.last_decision_id as string,
          catalog.catalog_revision,
        ),
      "Decision undone.",
    );
  };

  const previewDeletion = async (item: CatalogItem) => {
    setDeletionTarget(item);
    setDeletionPlan(null);
    setBusy(`preview:${item.item_id}`);
    try {
      setDeletionPlan(await bridge.previewDeletion("item", item.item_id));
    } catch (error) {
      setMessage(displayCatalogError(error));
      setDeletionTarget(null);
    } finally {
      setBusy(null);
    }
  };

  if (loading && !catalog && !inbox) {
    return <WorkspaceLoading />;
  }

  const importPaths = async (paths: string[]) => {
    if (!paths.length) return;
    await runMutation(
      "import",
      async () => {
        const result = await bridge.importLocalSources(paths);
        setImportResult(result);
      },
      "Import completed. Review unresolved evidence in Inbox.",
    );
  };

  const chooseImportPaths = async (
    picker: () => Promise<string[]>,
  ) => {
    try {
      await importPaths(await picker());
    } catch (error) {
      setMessage(displayCatalogError(error));
    }
  };

  return (
    <>
      <div className="sr-live" role="status" aria-live="polite">
        {message}
      </div>
      {mode === "catalog" ? (
        <CatalogView
          catalog={catalog}
          busy={busy}
          selectedIds={selectedIds}
          importResult={importResult}
          onSelect={setSelectedIds}
          onNew={() => setEditor({ kind: "item", item: null })}
          onEdit={(item) => setEditor({ kind: "item", item })}
          onMerge={() => {
            const first = catalog?.items.find((item) =>
              selectedIds.includes(item.item_id),
            );
            setEditor({ kind: "merge", item: first ?? null });
          }}
          onSplit={setSplitItem}
          onUndo={(item) => void undo(item)}
          onPreview={(item) => void previewDeletion(item)}
          onLoadMore={() => void loadCatalog(true)}
          onImport={importPaths}
          onChooseFiles={() => chooseImportPaths(pickFiles)}
          onChooseFolder={() => chooseImportPaths(pickFolder)}
          onRefreshRoots={async () => {
            const roots =
              importResult?.roots ?? catalog?.roots ?? [];
            if (!roots.length) {
              setMessage("No saved folder roots to refresh.");
              return;
            }
            await runMutation(
              "refresh-roots",
              async () => {
                const result = await bridge.refreshImportRoots(
                  roots.map((root) => root.root_id),
                );
                setImportResult(result);
              },
              "Saved folders refreshed.",
            );
          }}
        />
      ) : (
        <InboxView
          page={inbox}
          catalog={catalog}
          state={inboxState}
          busy={busy}
          onState={setInboxState}
          onLoadMore={() => void loadInbox(true)}
          onDecision={async (evidence, decision, itemId) => {
            if (!catalog) return;
            await runMutation(
              `${decision}:${evidence.evidence_id}`,
              () =>
                bridge.decideEvidence(
                  evidence.evidence_id,
                  decision,
                  itemId,
                  catalog.catalog_revision,
                ),
              decision === "assign"
                ? "Evidence assigned."
                : decision === "reject"
                  ? "Evidence rejected."
                  : "Evidence deferred.",
            );
          }}
        />
      )}

      {editor && (
        <ItemEditor
          kind={editor.kind}
          item={editor.item}
          selectedCount={selectedIds.length}
          busy={busy !== null}
          onClose={() => setEditor(null)}
          onSave={(attributes, evidenceIds) =>
            editor.kind === "merge"
              ? void mergeItems(attributes)
              : void saveItem(attributes, evidenceIds)
          }
        />
      )}
      {splitItem && (
        <SplitDialog
          item={splitItem}
          busy={busy !== null}
          onClose={() => setSplitItem(null)}
          onSplit={(name, ids) => void split(splitItem, name, ids)}
        />
      )}
      {deletionTarget && (
        <DeletionPreviewDialog
          item={deletionTarget}
          plan={deletionPlan}
          bridge={bridge}
          onPlan={setDeletionPlan}
          onAttempt={async () => {
            await onDeletionActivity?.();
          }}
          onComplete={async () => {
            setDeletionTarget(null);
            setDeletionPlan(null);
            setMessage("Active local data deleted.");
            await Promise.all([loadCatalog(), loadInbox()]);
          }}
          onClose={() => {
            setDeletionTarget(null);
            setDeletionPlan(null);
          }}
        />
      )}
    </>
  );
}

function WorkspaceLoading() {
  return (
    <section className="state-view" aria-label="Loading wardrobe">
      <span className="spinner" aria-hidden="true" />
      <p>Loading local catalog...</p>
    </section>
  );
}

type CatalogViewProps = {
  catalog: CatalogPage | null;
  busy: string | null;
  selectedIds: string[];
  importResult: ImportResult | null;
  onSelect: (ids: string[]) => void;
  onNew: () => void;
  onEdit: (item: CatalogItem) => void;
  onMerge: () => void;
  onSplit: (item: CatalogItem) => void;
  onUndo: (item: CatalogItem) => void;
  onPreview: (item: CatalogItem) => void;
  onLoadMore: () => void;
  onImport: (paths: string[]) => Promise<void>;
  onChooseFiles: () => Promise<void>;
  onChooseFolder: () => Promise<void>;
  onRefreshRoots: () => Promise<void>;
};

function CatalogView({
  catalog,
  busy,
  selectedIds,
  importResult,
  onSelect,
  onNew,
  onEdit,
  onMerge,
  onSplit,
  onUndo,
  onPreview,
  onLoadMore,
  onImport,
  onChooseFiles,
  onChooseFolder,
  onRefreshRoots,
}: CatalogViewProps) {
  const [path, setPath] = useState("");
  const roots = importResult?.roots ?? catalog?.roots ?? [];

  const submitImport = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const value = path.trim();
    if (!value) return;
    await onImport([value]);
    setPath("");
  };

  return (
    <section aria-labelledby="wardrobe-title">
      <div className="view-heading">
        <div>
          <h2 id="wardrobe-title">Wardrobe</h2>
          <p className="count">
            {catalog?.total_count ?? 0} items · revision{" "}
            {catalog?.catalog_revision ?? 0}
          </p>
        </div>
        <button
          className="button button-primary"
          type="button"
          onClick={onNew}
        >
          Add item
        </button>
      </div>

      <section className="import-band" aria-labelledby="imports-title">
        <div className="section-title-row">
          <div>
            <h3 id="imports-title">Local imports</h3>
            <p>Photos, folders, EML, and MBOX stay on this device.</p>
          </div>
          <button
            className="button"
            type="button"
            disabled={busy !== null}
            onClick={() => void onChooseFiles()}
          >
            Choose files
          </button>
          <button
            className="button"
            type="button"
            disabled={busy !== null}
            onClick={() => void onChooseFolder()}
          >
            Choose folder
          </button>
          <button
            className="button"
            type="button"
            disabled={busy !== null || roots.length === 0}
            onClick={() => void onRefreshRoots()}
          >
            {busy === "refresh-roots" ? "Refreshing..." : "Refresh folders"}
          </button>
        </div>
        <form className="import-form" onSubmit={(event) => void submitImport(event)}>
          <label htmlFor="import-path">Path</label>
          <input
            id="import-path"
            value={path}
            onChange={(event) => setPath(event.target.value)}
            placeholder="/Users/me/Pictures or order.mbox"
            autoComplete="off"
          />
          <button
            className="button"
            type="submit"
            disabled={busy !== null || path.trim().length === 0}
          >
            {busy === "import" ? "Importing..." : "Import path"}
          </button>
        </form>
        {roots.length > 0 && (
          <ul className="root-list" aria-label="Saved import folders">
            {roots.map((root) => (
              <li key={root.root_id}>
                <span>{root.display_name}</span>
                <StatusPill value={root.status} />
              </li>
            ))}
          </ul>
        )}
        {importResult && (
          <p className="import-summary">
            {importResult.summaries.reduce(
              (total, result) => total + result.imported,
              0,
            )}{" "}
            imported ·{" "}
            {importResult.summaries.reduce(
              (total, result) => total + result.quarantined,
              0,
            )}{" "}
            quarantined
          </p>
        )}
      </section>

      <div className="catalog-toolbar" aria-label="Catalog actions">
        <span>{selectedIds.length} selected</span>
        <button
          className="button"
          type="button"
          disabled={selectedIds.length < 2 || busy !== null}
          onClick={onMerge}
        >
          Merge selected
        </button>
        {selectedIds.length > 0 && (
          <button className="text-button" type="button" onClick={() => onSelect([])}>
            Clear
          </button>
        )}
      </div>

      {!catalog || catalog.items.length === 0 ? (
        <div className="empty-state compact">
          <p>No wardrobe items yet</p>
        </div>
      ) : (
        <ul className="catalog-list" aria-label="Wardrobe items">
          {catalog.items.map((item) => {
            const selected = selectedIds.includes(item.item_id);
            return (
              <li key={item.item_id}>
                <label className="select-item">
                  <input
                    type="checkbox"
                    checked={selected}
                    onChange={() =>
                      onSelect(
                        selected
                          ? selectedIds.filter((id) => id !== item.item_id)
                          : [...selectedIds, item.item_id],
                      )
                    }
                    aria-label={`Select ${item.display_name}`}
                  />
                </label>
                <div className="item-swatch" aria-hidden="true">
                  {item.display_name.slice(0, 1).toUpperCase()}
                </div>
                <div className="item-copy">
                  <strong>{item.display_name}</strong>
                  <span>
                    {[item.category, item.color].filter(Boolean).join(" · ") ||
                      "Uncategorized"}
                  </span>
                  <small>{item.evidence_ids.length} evidence</small>
                </div>
                <div className="row-actions">
                  <button className="text-button" type="button" onClick={() => onEdit(item)}>
                    Edit
                  </button>
                  <button
                    className="text-button"
                    type="button"
                    disabled={item.evidence_ids.length < 2}
                    onClick={() => onSplit(item)}
                  >
                    Split
                  </button>
                  <button
                    className="text-button"
                    type="button"
                    disabled={!item.last_decision_id || busy !== null}
                    onClick={() => onUndo(item)}
                  >
                    {busy === `undo:${item.item_id}` ? "Undoing..." : "Undo"}
                  </button>
                  <button
                    className="text-button danger-link"
                    type="button"
                    onClick={() => onPreview(item)}
                  >
                    Preview deletion
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {catalog?.next_cursor && (
        <button
          className="button load-more"
          type="button"
          disabled={busy !== null}
          onClick={onLoadMore}
        >
          Load more items
        </button>
      )}
    </section>
  );
}

async function pickImportFiles(): Promise<string[]> {
  return selectedPaths(
    await openDialog({
      multiple: true,
      directory: false,
      title: "Choose wardrobe files",
    }),
  );
}

async function pickImportFolder(): Promise<string[]> {
  return selectedPaths(
    await openDialog({
      multiple: false,
      directory: true,
      title: "Choose wardrobe folder",
    }),
  );
}

function selectedPaths(value: string | string[] | null): string[] {
  if (value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function InboxView({
  page,
  catalog,
  state,
  busy,
  onState,
  onDecision,
  onLoadMore,
}: {
  page: InboxPage | null;
  catalog: CatalogPage | null;
  state: EvidenceState;
  busy: string | null;
  onState: (state: EvidenceState) => void;
  onDecision: (
    evidence: Evidence,
    decision: "assign" | "reject" | "defer",
    itemId: string | null,
  ) => Promise<void>;
  onLoadMore: () => void;
}) {
  return (
    <section aria-labelledby="inbox-title">
      <div className="view-heading">
        <div>
          <h2 id="inbox-title">Inbox</h2>
          <p className="count">{page?.total_count ?? 0} to review</p>
        </div>
      </div>
      <div className="segmented" aria-label="Inbox state">
        {(["unresolved", "quarantine"] as const).map((value) => (
          <button
            key={value}
            type="button"
            aria-pressed={state === value}
            onClick={() => onState(value)}
          >
            {value === "unresolved" ? "Unresolved" : "Quarantine"}
          </button>
        ))}
      </div>
      {!page || page.items.length === 0 ? (
        <div className="empty-state compact">
          <p>No {state} evidence</p>
        </div>
      ) : (
        <ul className="inbox-list">
          {page.items.map((evidence) => (
            <InboxRow
              key={evidence.evidence_id}
              evidence={evidence}
              items={catalog?.items ?? []}
              busy={busy}
              onDecision={onDecision}
            />
          ))}
        </ul>
      )}
      {page?.next_cursor && (
        <button
          className="button load-more"
          type="button"
          disabled={busy !== null}
          onClick={onLoadMore}
        >
          Load more evidence
        </button>
      )}
    </section>
  );
}

function InboxRow({
  evidence,
  items,
  busy,
  onDecision,
}: {
  evidence: Evidence;
  items: CatalogItem[];
  busy: string | null;
  onDecision: (
    evidence: Evidence,
    decision: "assign" | "reject" | "defer",
    itemId: string | null,
  ) => Promise<void>;
}) {
  const [itemId, setItemId] = useState(items[0]?.item_id ?? "");
  const active = busy?.endsWith(evidence.evidence_id) ?? false;

  useEffect(() => {
    if (!items.some((item) => item.item_id === itemId)) {
      setItemId(items[0]?.item_id ?? "");
    }
  }, [itemId, items]);

  return (
    <li>
      <div className={`evidence-icon evidence-${evidence.kind}`} aria-hidden="true">
        {evidence.kind === "image" ? "IMG" : "EML"}
      </div>
      <div className="evidence-copy">
        <strong>{evidence.display_name}</strong>
        <span>{evidence.source_label}</span>
        {evidence.quarantine_reason && (
          <small>Reason: {evidence.quarantine_reason}</small>
        )}
      </div>
      <div className="inbox-actions">
        <label>
          <span className="visually-hidden">Assign {evidence.display_name} to</span>
          <select
            value={itemId}
            onChange={(event) => setItemId(event.target.value)}
            disabled={active || items.length === 0}
            aria-label={`Item for ${evidence.display_name}`}
          >
            {items.map((item) => (
              <option value={item.item_id} key={item.item_id}>
                {item.display_name}
              </option>
            ))}
          </select>
        </label>
        <button
          className="button button-primary"
          type="button"
          disabled={active || !itemId || !evidence.decision_capable}
          onClick={() => void onDecision(evidence, "assign", itemId)}
        >
          Assign
        </button>
        <button
          className="button"
          type="button"
          disabled={active || !evidence.decision_capable}
          onClick={() => void onDecision(evidence, "defer", null)}
        >
          Defer
        </button>
        <button
          className="button button-danger"
          type="button"
          disabled={active || !evidence.decision_capable}
          onClick={() => void onDecision(evidence, "reject", null)}
        >
          Reject
        </button>
      </div>
    </li>
  );
}

function ItemEditor({
  kind,
  item,
  selectedCount,
  busy,
  onClose,
  onSave,
}: {
  kind: "item" | "merge";
  item: CatalogItem | null;
  selectedCount: number;
  busy: boolean;
  onClose: () => void;
  onSave: (attributes: CatalogAttributes, evidenceIds: string[]) => void;
}) {
  const [values, setValues] = useState<CatalogAttributes>(
    item
      ? {
          display_name: item.display_name,
          category: item.category,
          color: item.color,
          notes: item.notes,
        }
      : emptyAttributes,
  );
  const [error, setError] = useState<string | null>(null);

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const validation = validateAttributes(values);
    if (validation) {
      setError(validation);
      return;
    }
    onSave(values, item?.evidence_ids ?? []);
  };

  const title =
    kind === "merge"
      ? `Merge ${selectedCount} items`
      : item
        ? `Edit ${item.display_name}`
        : "Add wardrobe item";

  return (
    <Modal title={title} onClose={onClose}>
      <form className="editor-form" onSubmit={submit}>
        <label>
          Name
          <input
            autoFocus
            required
            maxLength={80}
            value={values.display_name}
            onChange={(event) =>
              setValues({ ...values, display_name: event.target.value })
            }
          />
        </label>
        <div className="field-grid">
          <label>
            Category
            <select
              value={values.category}
              onChange={(event) =>
                setValues({
                  ...values,
                  category: event.target.value as CatalogAttributes["category"],
                })
              }
            >
              <option value="top">Top</option>
              <option value="bottom">Bottom</option>
              <option value="dress">Dress</option>
              <option value="outerwear">Outerwear</option>
              <option value="shoes">Shoes</option>
              <option value="accessory">Accessory</option>
              <option value="underwear">Underwear</option>
              <option value="activewear">Activewear</option>
              <option value="other">Other</option>
            </select>
          </label>
          <label>
            Color
            <input
              maxLength={80}
              value={values.color}
              onChange={(event) =>
                setValues({ ...values, color: event.target.value })
              }
            />
          </label>
        </div>
        <label>
          Notes
          <textarea
            maxLength={1000}
            rows={4}
            value={values.notes}
            onChange={(event) =>
              setValues({ ...values, notes: event.target.value })
            }
          />
        </label>
        {error && <p className="form-error">{error}</p>}
        <div className="modal-actions">
          <button className="button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="button button-primary" type="submit" disabled={busy}>
            {busy ? "Saving..." : kind === "merge" ? "Merge items" : "Save item"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function SplitDialog({
  item,
  busy,
  onClose,
  onSplit,
}: {
  item: CatalogItem;
  busy: boolean;
  onClose: () => void;
  onSplit: (name: string, evidenceIds: string[]) => void;
}) {
  const [name, setName] = useState(`${item.display_name} 2`);
  const [movedIds, setMovedIds] = useState<string[]>([
    item.evidence_ids[item.evidence_ids.length - 1] ?? "",
  ]);
  const invalid =
    !name.trim() ||
    movedIds.length === 0 ||
    movedIds.length === item.evidence_ids.length;

  return (
    <Modal title={`Split ${item.display_name}`} onClose={onClose}>
      <form
        className="editor-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (!invalid) onSplit(name, movedIds);
        }}
      >
        <p className="modal-copy">
          Choose evidence to move into the new item. The original keeps the
          remaining evidence.
        </p>
        <label>
          New item name
          <input
            autoFocus
            maxLength={80}
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <fieldset className="evidence-options">
          <legend>Evidence to move</legend>
          {item.evidence_ids.map((evidenceId, index) => (
            <label key={evidenceId}>
              <input
                type="checkbox"
                checked={movedIds.includes(evidenceId)}
                onChange={() =>
                  setMovedIds(
                    movedIds.includes(evidenceId)
                      ? movedIds.filter((id) => id !== evidenceId)
                      : [...movedIds, evidenceId],
                  )
                }
              />
              Evidence {index + 1}
            </label>
          ))}
        </fieldset>
        {invalid && (
          <p className="form-hint">
            Each resulting item must retain at least one evidence record.
          </p>
        )}
        <div className="modal-actions">
          <button className="button" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button button-primary"
            type="submit"
            disabled={invalid || busy}
          >
            Split item
          </button>
        </div>
      </form>
    </Modal>
  );
}

function DeletionPreviewDialog({
  item,
  plan,
  bridge,
  onPlan,
  onAttempt,
  onComplete,
  onClose,
}: {
  item: CatalogItem;
  plan: DeletionPlan | null;
  bridge: CatalogBridge;
  onPlan: (plan: DeletionPlan) => void;
  onAttempt: () => Promise<void>;
  onComplete: () => Promise<void>;
  onClose: () => void;
}) {
  const [loadingClass, setLoadingClass] = useState<string | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [result, setResult] = useState<DeletionResult | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const progressRef = useRef<HTMLDivElement>(null);
  const doneRef = useRef<HTMLButtonElement>(null);
  const executionRequestIdRef = useRef(crypto.randomUUID());

  useEffect(() => {
    if (executing) progressRef.current?.focus();
  }, [executing]);

  useEffect(() => {
    if (result) doneRef.current?.focus();
  }, [result]);

  const loadMore = async (className: string, cursor: string) => {
    if (!plan) return;
    setLoadingClass(className);
    try {
      const page = await bridge.listDeletionPlanItems(
        plan.preview_snapshot_token,
        className,
        cursor,
      );
      onPlan({
        ...plan,
        classes: plan.classes.map((group) =>
          group.class_name === className
            ? {
                ...page,
                items: appendUniqueById(
                  group.items,
                  page.items,
                  (row) => row.id,
                ),
              }
            : group,
        ),
      });
    } finally {
      setLoadingClass(null);
    }
  };

  const executeDeletion = async () => {
    if (!plan || !acknowledged || executing) return;
    setExecuting(true);
    setStatus(
      "Deleting active local records and files. This must complete within one hour.",
    );
    try {
      const response = await bridge.executeDeletion(
        plan,
        executionRequestIdRef.current,
      );
      if (!response.complete) {
        throw new Error("incomplete deletion response");
      }
      setResult(response);
      setStatus("Active local deletion complete.");
    } catch (error) {
      if (isConflict(error)) {
        setAcknowledged(false);
        setStatus("The deletion plan changed. Refreshing it for review...");
        try {
          onPlan(await bridge.previewDeletion("item", item.item_id));
          executionRequestIdRef.current = crypto.randomUUID();
          setStatus("The plan was refreshed. Review it before confirming.");
        } catch (refreshError) {
          setStatus(displayCatalogError(refreshError));
        }
      } else {
        setStatus(displayCatalogError(error));
      }
    } finally {
      setExecuting(false);
      await onAttempt().catch(() => undefined);
    }
  };

  return (
    <Modal
      title={`Delete ${item.display_name}`}
      onClose={onClose}
      closeDisabled={executing}
    >
      {!plan ? (
        <div className="modal-loading" role="status">
          Loading dependencies...
        </div>
      ) : result ? (
        <div className="deletion-complete">
          <p role="status">Active local deletion complete.</p>
          <dl className="deletion-totals">
            <div>
              <dt>Records deleted</dt>
              <dd>{result.deleted_local_record_count}</dd>
            </div>
            <div>
              <dt>Files deleted</dt>
              <dd>{result.deleted_unique_blob_count}</dd>
            </div>
          </dl>
          <p className="modal-copy">
            Completed {formatTimestamp(result.completed_at)} before the{" "}
            {formatTimestamp(result.deadline_at)} deadline.
          </p>
          <section className="deletion-retention" aria-label="Retained backups">
            <h3>Retained backups</h3>
            {result.backup_retention.length ? (
              <ul>
                {result.backup_retention.map((backup) => (
                  <li key={backup.backup_id}>
                    {humanize(backup.reason)} backup expires{" "}
                    {formatTimestamp(backup.expires_at)}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No Wardrobe backups retain this data.</p>
            )}
          </section>
          <section className="deletion-retention" aria-label="Provider retention">
            <h3>Provider retention</h3>
            {result.remote_retention.length ? (
              <ul>
                {result.remote_retention.map((remote) => (
                  <li
                    key={`${remote.provider}:${remote.purpose}:${remote.dispatched_at}`}
                  >
                    {humanize(remote.provider)} {humanize(remote.purpose)}:
                    provider deletion unavailable;{" "}
                    {remote.policy_expires_at
                      ? `policy expiry ${formatTimestamp(remote.policy_expires_at)}`
                      : "policy expiry unknown"}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No provider retention is recorded for this data.</p>
            )}
          </section>
          <div className="modal-actions">
            <button
              className="button button-primary"
              type="button"
              ref={doneRef}
              onClick={() => void onComplete()}
            >
              Done
            </button>
          </div>
        </div>
      ) : (
        <>
          <p className="modal-copy">
            Review the active local data that will be permanently deleted.
          </p>
          <dl className="deletion-totals deletion-totals-wide">
            <div>
              <dt>Local records</dt>
              <dd>{plan.overall_count}</dd>
            </div>
            <div>
              <dt>Files deleted</dt>
              <dd>
                {plan.unique_blob_count} / {formatBytes(plan.unique_blob_bytes)}
              </dd>
            </div>
            <div>
              <dt>Shared blobs retained</dt>
              <dd>{plan.retained_shared_blob_count}</dd>
            </div>
          </dl>
          <div className="deletion-groups" aria-label="Active local data">
            <h3>Active local data</h3>
            {plan.classes.map((group) => (
              <section key={group.class_name}>
                <h3>
                  {humanize(group.class_name)} <span>{group.count}</span>
                </h3>
                <ul>
                  {group.items.map((row) => (
                    <li key={row.id}>{row.label}</li>
                  ))}
                </ul>
                {group.next_cursor && (
                  <button
                    className="text-button"
                    type="button"
                    disabled={loadingClass === group.class_name}
                    onClick={() =>
                      void loadMore(group.class_name, group.next_cursor as string)
                    }
                  >
                    {loadingClass === group.class_name
                      ? "Loading..."
                      : `Load more ${humanize(group.class_name)}`}
                  </button>
                )}
              </section>
            ))}
          </div>
          <section className="deletion-retention" aria-label="Retained backups">
            <h3>Retained backups</h3>
            {plan.backup_retention.length ? (
              <ul>
                {plan.backup_retention.map((backup) => (
                  <li key={backup.backup_id}>
                    {humanize(backup.reason)} backup expires{" "}
                    {formatTimestamp(backup.expires_at)}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No Wardrobe backups contain this data.</p>
            )}
          </section>
          <section
            className="deletion-retention"
            aria-label="Provider retention"
          >
            <h3>Provider retention</h3>
            {plan.remote_retention.length ? (
              <ul>
                {plan.remote_retention.map((remote) => (
                  <li
                    key={`${remote.provider}:${remote.purpose}:${remote.dispatched_at}`}
                  >
                    {humanize(remote.provider)} {humanize(remote.purpose)}:
                    provider deletion unavailable;{" "}
                    {remote.policy_expires_at
                      ? `policy expiry ${formatTimestamp(remote.policy_expires_at)}`
                      : "policy expiry unknown"}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No provider retention is recorded for this data.</p>
            )}
          </section>
          <label className="deletion-acknowledgement">
            <input
              type="checkbox"
              checked={acknowledged}
              disabled={executing}
              onChange={(event) => setAcknowledged(event.target.checked)}
            />
            <span>
              I understand active local deletion is irreversible and does not
              erase listed backups or provider-retained data.
            </span>
          </label>
          <div
            className="sr-live"
            role="status"
            aria-live="assertive"
            ref={progressRef}
            tabIndex={-1}
          >
            {status}
          </div>
          <div className="modal-actions">
            <button
              className="button"
              type="button"
              disabled={executing}
              onClick={onClose}
            >
              Cancel
            </button>
            <button
              className="button button-danger"
              type="button"
              disabled={!acknowledged || executing}
              onClick={() => void executeDeletion()}
            >
              {executing ? "Deleting..." : "Delete active local data"}
            </button>
          </div>
        </>
      )}
    </Modal>
  );
}

function Modal({
  title,
  children,
  onClose,
  closeDisabled = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  closeDisabled?: boolean;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const closeDisabledRef = useRef(closeDisabled);
  const onCloseRef = useRef(onClose);
  const previousFocus = useRef<HTMLElement | null>(
    document.activeElement instanceof HTMLElement ? document.activeElement : null,
  );
  const titleId = `modal-${title.toLowerCase().replace(/[^a-z0-9]+/gu, "-")}`;

  useEffect(() => {
    closeDisabledRef.current = closeDisabled;
    onCloseRef.current = onClose;
  }, [closeDisabled, onClose]);

  useEffect(() => {
    const panel = panelRef.current;
    const first = panel?.querySelector<HTMLElement>(
      "input:not(:disabled), button:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])",
    );
    first?.focus();

    const keydown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        if (!closeDisabledRef.current) onCloseRef.current();
      }
      if (event.key !== "Tab" || !panel) return;
      const focusable = [...panel.querySelectorAll<HTMLElement>(
        "input:not(:disabled), button:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])",
      )];
      if (!focusable.length) return;
      const firstControl = focusable[0];
      const lastControl = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === firstControl) {
        event.preventDefault();
        lastControl?.focus();
      } else if (!event.shiftKey && document.activeElement === lastControl) {
        event.preventDefault();
        firstControl?.focus();
      }
    };
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      previousFocus.current?.focus();
    };
  }, []);

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={() => {
        if (!closeDisabled) onClose();
      }}
    >
      <div
        className="modal-panel"
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
            aria-label="Close dialog"
            disabled={closeDisabled}
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

function StatusPill({ value }: { value: string }) {
  return <span className={`status-pill status-${value}`}>{humanize(value)}</span>;
}

function humanize(value: string) {
  return value
    .split("_")
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let amount = value / 1024;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount.toFixed(amount >= 10 ? 0 : 1)} ${units[index]}`;
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}
