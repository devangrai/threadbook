import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import type {
  CatalogItemV1,
  ItemAttributesV1,
  ItemCategoryV1,
  ListReceiptPurchaseUnitsV1Response,
  ReceiptPurchaseUnitFieldProvenanceV1,
  ReceiptPurchaseUnitV1,
} from "./generated/contracts";
import {
  receiptPromotionBridge,
  type ReceiptPromotionBridge,
} from "./receipt-promotion-bridge";

const categories: ReadonlyArray<{
  value: ItemCategoryV1;
  label: string;
}> = [
  { value: "top", label: "Top" },
  { value: "bottom", label: "Bottom" },
  { value: "dress", label: "Dress" },
  { value: "outerwear", label: "Outerwear" },
  { value: "shoes", label: "Shoes" },
  { value: "accessory", label: "Accessory" },
  { value: "underwear", label: "Underwear" },
  { value: "activewear", label: "Activewear" },
  { value: "other", label: "Other" },
];

type ItemDraft = Omit<ItemAttributesV1, "category" | "tags"> & {
  category: ItemCategoryV1 | "";
  tags: string;
};

type ActivePromotion = {
  unit: ReceiptPurchaseUnitV1;
  draft: ItemDraft;
  step: "edit" | "confirm";
};

type ReceiptPurchaseUnitsProps = {
  sourceId: string;
  bridge?: ReceiptPromotionBridge;
  onNavigateToCatalogItem?: (item: CatalogItemV1) => void;
};

export function ReceiptPurchaseUnits({
  sourceId,
  bridge = receiptPromotionBridge,
  onNavigateToCatalogItem,
}: ReceiptPurchaseUnitsProps) {
  const [page, setPage] =
    useState<ListReceiptPurchaseUnitsV1Response | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [active, setActive] = useState<ActivePromotion | null>(null);
  const [busy, setBusy] = useState(false);
  const [dialogMessage, setDialogMessage] = useState<string | null>(null);
  const [successes, setSuccesses] = useState<
    ReadonlyMap<string, CatalogItemV1>
  >(new Map());
  const [successAnnouncement, setSuccessAnnouncement] = useState<string | null>(
    null,
  );
  const [focusSuccessId, setFocusSuccessId] = useState<string | null>(null);
  const conflictRef = useRef<HTMLParagraphElement>(null);
  const successRef = useRef<HTMLAnchorElement>(null);

  const load = useCallback(async () => {
    const response = await bridge.listPurchaseUnits(sourceId);
    setPage(response);
    return response;
  }, [bridge, sourceId]);

  useEffect(() => {
    let current = true;
    setLoading(true);
    setLoadError(null);
    setPage(null);
    setActive(null);
    void load()
      .catch(() => {
        if (current) {
          setLoadError("Purchase units could not be loaded.");
        }
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [load]);

  useEffect(() => {
    if (!focusSuccessId) return;
    successRef.current?.focus();
    setFocusSuccessId(null);
  }, [focusSuccessId, successes]);

  const beginPromotion = (unit: ReceiptPurchaseUnitV1) => {
    setDialogMessage(null);
    setSuccessAnnouncement(null);
    setActive({
      unit,
      draft: draftFromUnit(unit),
      step: "edit",
    });
  };

  const promote = async () => {
    if (!active || active.unit.status.status !== "available") return;
    const attributes = attributesFromDraft(active.draft);
    if (!attributes) {
      setActive({ ...active, step: "edit" });
      setDialogMessage(
        "Enter a display name and choose a category before continuing.",
      );
      requestAnimationFrame(() => conflictRef.current?.focus());
      return;
    }

    setBusy(true);
    setDialogMessage(null);
    try {
      const response = await bridge.promotePurchaseUnit(
        active.unit,
        attributes,
      );
      setPage((current) =>
        current
          ? {
              ...current,
              units: current.units.map((unit) =>
                unit.purchase_unit_id === response.unit.purchase_unit_id
                  ? response.unit
                  : unit,
              ),
              snapshot: {
                ...current.snapshot,
                catalog_revision: response.new_catalog_revision,
                evidence_generation: response.new_evidence_generation,
              },
            }
          : current,
      );
      setSuccesses((current) => {
        const next = new Map(current);
        next.set(response.unit.purchase_unit_id, response.item);
        return next;
      });
      setSuccessAnnouncement(
        `One wardrobe item was created: ${response.item.attributes.display_name}.`,
      );
      setActive(null);
      setFocusSuccessId(response.unit.purchase_unit_id);
    } catch (error) {
      if (isConflict(error)) {
        try {
          const refreshed = await load();
          const refreshedUnit = refreshed.units.find(
            (unit) => unit.purchase_unit_id === active.unit.purchase_unit_id,
          );
          if (refreshedUnit) {
            setActive((current) =>
              current
                ? {
                    ...current,
                    unit: refreshedUnit,
                  }
                : current,
            );
          }
        } catch {
          // The draft remains available even when the conflict refresh fails.
        }
        setDialogMessage(
          "The receipt or wardrobe changed. Current revisions were refreshed and your item draft was preserved.",
        );
      } else {
        setDialogMessage(
          "This item could not be added. Your item draft was preserved.",
        );
      }
      requestAnimationFrame(() => conflictRef.current?.focus());
    } finally {
      setBusy(false);
    }
  };

  const navigate = (item: CatalogItemV1) => {
    if (onNavigateToCatalogItem) {
      onNavigateToCatalogItem(item);
      return;
    }
    navigateToCatalogItem(item);
  };

  return (
    <section
      className="receipt-purchase-units"
      aria-labelledby={`purchase-units-${sourceId}`}
      aria-busy={loading}
    >
      <div className="receipt-purchase-heading">
        <div>
          <h4 id={`purchase-units-${sourceId}`}>Purchase units</h4>
          {page && (
            <span>
              {page.total_count} eligible physical{" "}
              {page.total_count === 1 ? "item" : "items"}
            </span>
          )}
        </div>
      </div>

      {loading && <p className="receipt-muted">Loading purchase units...</p>}
      {loadError && (
        <p className="receipt-purchase-error" role="status">
          {loadError}
        </p>
      )}
      {!loading && !loadError && page?.units.length === 0 && (
        <p className="receipt-muted">
          No physical purchase units are eligible for promotion.
        </p>
      )}

      {page && page.units.length > 0 && (
        <ol className="receipt-purchase-list">
          {page.units.map((unit) => {
            const success = successes.get(unit.purchase_unit_id);
            const promoted = unit.status.status === "promoted";
            return (
              <li key={unit.purchase_unit_id}>
                <div className="receipt-purchase-unit-heading">
                  <div>
                    <h5>
                      Item {unit.unit_ordinal + 1} of{" "}
                      {unit.authoritative_quantity}
                    </h5>
                    <strong>
                      {unit.values.description ?? "Unnamed reviewed item"}
                    </strong>
                  </div>
                  <span
                    className={`status-pill ${
                      promoted ? "status-confirmed" : "status-needs_review"
                    }`}
                  >
                    {promoted ? "Added" : "Ready"}
                  </span>
                </div>

                <PurchaseUnitProvenance unit={unit} />

                <div className="receipt-purchase-actions">
                  <button
                    className="button button-primary"
                    type="button"
                    disabled={promoted}
                    onClick={() => beginPromotion(unit)}
                  >
                    {promoted ? "Added to wardrobe" : "Add to wardrobe"}
                  </button>
                  {success && (
                    <a
                      className="receipt-success-link"
                      href={`#catalog-item-${success.item_id}`}
                      ref={
                        focusSuccessId === unit.purchase_unit_id
                          ? successRef
                          : undefined
                      }
                      onClick={(event) => {
                        event.preventDefault();
                        navigate(success);
                      }}
                    >
                      Open {success.attributes.display_name} in Wardrobe
                    </a>
                  )}
                  {!success && promoted && (
                    <button
                      className="text-button"
                      type="button"
                      onClick={() =>
                        navigate({
                          item_id: unit.status.status === "promoted"
                            ? unit.status.item_id
                            : "",
                          attributes: {
                            ...draftFromUnit(unit),
                            category: "other",
                            tags: [],
                          },
                          evidence_ids: [],
                          last_decision_id:
                            unit.status.status === "promoted"
                              ? unit.status.decision_id
                              : "",
                        })
                      }
                    >
                      Open wardrobe item
                    </button>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      )}

      {page && page.exclusions.length > 0 && (
        <details className="receipt-purchase-exclusions">
          <summary>
            {page.total_exclusion_count} reviewed{" "}
            {page.total_exclusion_count === 1 ? "line" : "lines"} not eligible
          </summary>
          <ul>
            {page.exclusions.map((exclusion, index) => (
              <li key={`${exclusion.order_line_id ?? "order"}-${index}`}>
                {humanize(exclusion.reason)}
              </li>
            ))}
          </ul>
        </details>
      )}

      <div
        className="sr-live"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        {successAnnouncement}
      </div>

      {active && (
        <PromotionDialog
          active={active}
          busy={busy}
          message={dialogMessage}
          messageRef={conflictRef}
          onChange={(draft) =>
            setActive((current) =>
              current ? { ...current, draft } : current,
            )
          }
          onStep={(step) =>
            setActive((current) =>
              current ? { ...current, step } : current,
            )
          }
          onInvalid={() => {
            setDialogMessage(
              "Enter a display name and choose a category before continuing.",
            );
            requestAnimationFrame(() => conflictRef.current?.focus());
          }}
          onCancel={() => {
            setActive(null);
            setDialogMessage(null);
          }}
          onPromote={() => void promote()}
        />
      )}
    </section>
  );
}

function PurchaseUnitProvenance({
  unit,
}: {
  unit: ReceiptPurchaseUnitV1;
}) {
  const { values, provenance } = unit;
  return (
    <div className="receipt-purchase-provenance">
      <section aria-label="Order-level reviewed provenance">
        <h6>Reviewed order</h6>
        <dl>
          <ProvenanceField
            label="Merchant"
            value={values.merchant}
            provenance={provenance.merchant}
          />
          <ProvenanceField
            label="Order"
            value={values.order_identifier}
            provenance={provenance.order_identifier}
          />
          <ProvenanceField
            label="Purchase date"
            value={values.purchase_date}
            provenance={provenance.purchase_date}
          />
          <ProvenanceField
            label="Currency"
            value={values.currency}
            provenance={provenance.currency}
          />
        </dl>
      </section>
      <section aria-label="Line-level reviewed provenance">
        <h6>Reviewed line</h6>
        <dl>
          <ProvenanceField
            label="Description"
            value={values.description}
            provenance={provenance.description}
          />
          <ProvenanceField
            label="Brand"
            value={values.brand}
            provenance={provenance.brand}
          />
          <ProvenanceField
            label="Size"
            value={values.size}
            provenance={provenance.size}
          />
          <ProvenanceField
            label="Color"
            value={values.color}
            provenance={provenance.color}
          />
          <ProvenanceField
            label="Unit price"
            value={values.unit_price_minor}
            provenance={provenance.unit_price_minor}
          />
        </dl>
      </section>
    </div>
  );
}

function ProvenanceField({
  label,
  value,
  provenance,
}: {
  label: string;
  value: string | number | null;
  provenance: ReceiptPurchaseUnitFieldProvenanceV1;
}) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>
        <span className={value === null ? "unknown-value" : undefined}>
          {value ?? "Unknown"}
        </span>
        <small>{provenanceText(provenance)}</small>
      </dd>
    </div>
  );
}

function PromotionDialog({
  active,
  busy,
  message,
  messageRef,
  onChange,
  onStep,
  onInvalid,
  onCancel,
  onPromote,
}: {
  active: ActivePromotion;
  busy: boolean;
  message: string | null;
  messageRef: React.RefObject<HTMLParagraphElement | null>;
  onChange: (draft: ItemDraft) => void;
  onStep: (step: ActivePromotion["step"]) => void;
  onInvalid: () => void;
  onCancel: () => void;
  onPromote: () => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(
    document.activeElement instanceof HTMLElement ? document.activeElement : null,
  );
  const cancelRef = useRef(onCancel);

  useEffect(() => {
    cancelRef.current = onCancel;
  }, [onCancel]);

  useEffect(() => {
    panelRef.current
      ?.querySelector<HTMLElement>("[data-autofocus]")
      ?.focus();
  }, [active.step]);

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      const panel = panelRef.current;
      if (event.key === "Escape") {
        event.preventDefault();
        cancelRef.current();
        return;
      }
      if (event.key !== "Tab" || !panel) return;
      const controls = [
        ...panel.querySelectorAll<HTMLElement>(
          "input:not(:disabled), button:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex]:not([tabindex='-1'])",
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

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (active.step === "edit") {
      if (!attributesFromDraft(active.draft)) {
        onInvalid();
        return;
      }
      onStep("confirm");
    } else {
      onPromote();
    }
  };

  return (
    <div className="modal-backdrop" role="presentation">
      <div
        className="modal-panel receipt-promotion-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="receipt-promotion-title"
        aria-describedby="receipt-promotion-description"
        ref={panelRef}
      >
        <div className="modal-heading">
          <h2 id="receipt-promotion-title">
            {active.step === "edit"
              ? "Create wardrobe item"
              : "Confirm one wardrobe item"}
          </h2>
          <button
            className="icon-button"
            type="button"
            aria-label="Cancel adding wardrobe item"
            onClick={onCancel}
          >
            ×
          </button>
        </div>

        <p id="receipt-promotion-description">
          {active.step === "edit"
            ? "Edit the canonical wardrobe attributes. Receipt values remain evidence."
            : "This action creates exactly one wardrobe item from the displayed physical purchase unit."}
        </p>

        {message && (
          <p
            className="receipt-promotion-conflict"
            role="alert"
            aria-live="assertive"
            tabIndex={-1}
            ref={messageRef}
          >
            {message}
          </p>
        )}

        <form onSubmit={submit}>
          {active.step === "edit" ? (
            <ItemAttributesForm value={active.draft} onChange={onChange} />
          ) : (
            <div className="receipt-promotion-confirmation">
              <dl>
                <div>
                  <dt>Item</dt>
                  <dd>{active.draft.display_name}</dd>
                </div>
                <div>
                  <dt>Category</dt>
                  <dd>{humanize(active.draft.category)}</dd>
                </div>
                <div>
                  <dt>Physical unit</dt>
                  <dd>
                    Item {active.unit.unit_ordinal + 1} of{" "}
                    {active.unit.authoritative_quantity}
                  </dd>
                </div>
              </dl>
              <p>
                Later receipt analysis will not silently change this wardrobe
                item.
              </p>
            </div>
          )}

          <div className="modal-actions">
            <button className="button" type="button" onClick={onCancel}>
              Cancel
            </button>
            {active.step === "confirm" && (
              <button
                className="button"
                type="button"
                onClick={() => onStep("edit")}
              >
                Back
              </button>
            )}
            <button
              className="button button-primary"
              type="submit"
              data-autofocus={active.step === "confirm" || undefined}
              disabled={
                busy ||
                (active.step === "confirm" &&
                  active.unit.status.status !== "available")
              }
            >
              {active.step === "edit"
                ? "Review one item"
                : busy
                  ? "Creating one item..."
                  : "Create one wardrobe item"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function ItemAttributesForm({
  value,
  onChange,
}: {
  value: ItemDraft;
  onChange: (value: ItemDraft) => void;
}) {
  const update = <K extends keyof ItemDraft>(field: K, next: ItemDraft[K]) =>
    onChange({ ...value, [field]: next });
  return (
    <div className="receipt-item-attributes">
      <label>
        Display name
        <input
          type="text"
          value={value.display_name}
          maxLength={200}
          required
          data-autofocus
          onChange={(event) =>
            update("display_name", event.currentTarget.value)
          }
        />
      </label>
      <fieldset className="receipt-category-options">
        <legend>Category</legend>
        {categories.map((category) => (
          <button
            type="button"
            aria-pressed={value.category === category.value}
            onClick={() => update("category", category.value)}
            key={category.value}
          >
            {category.label}
          </button>
        ))}
      </fieldset>
      <label>
        Subcategory
        <input
          type="text"
          value={value.subcategory ?? ""}
          maxLength={200}
          onChange={(event) =>
            update("subcategory", nullable(event.currentTarget.value))
          }
        />
      </label>
      <label>
        Brand
        <input
          type="text"
          value={value.brand ?? ""}
          maxLength={200}
          onChange={(event) =>
            update("brand", nullable(event.currentTarget.value))
          }
        />
      </label>
      <label>
        Primary color
        <input
          type="text"
          value={value.primary_color ?? ""}
          maxLength={100}
          onChange={(event) =>
            update("primary_color", nullable(event.currentTarget.value))
          }
        />
      </label>
      <label>
        Size
        <input
          type="text"
          value={value.size ?? ""}
          maxLength={100}
          onChange={(event) =>
            update("size", nullable(event.currentTarget.value))
          }
        />
      </label>
      <label className="receipt-item-notes">
        Notes
        <textarea
          value={value.notes ?? ""}
          maxLength={2000}
          onChange={(event) =>
            update("notes", nullable(event.currentTarget.value))
          }
        />
      </label>
      <label className="receipt-item-tags">
        Tags
        <input
          type="text"
          value={value.tags}
          maxLength={500}
          placeholder="Comma-separated"
          onChange={(event) => update("tags", event.currentTarget.value)}
        />
      </label>
    </div>
  );
}

function draftFromUnit(unit: ReceiptPurchaseUnitV1): ItemDraft {
  return {
    display_name: unit.values.description ?? "",
    category: "",
    subcategory: null,
    brand: unit.values.brand,
    primary_color: unit.values.color,
    size: unit.values.size,
    notes: null,
    tags: "",
  };
}

function attributesFromDraft(draft: ItemDraft): ItemAttributesV1 | null {
  const displayName = draft.display_name.trim();
  if (!displayName || !draft.category) return null;
  return {
    display_name: displayName,
    category: draft.category,
    subcategory: nullable(draft.subcategory),
    brand: nullable(draft.brand),
    primary_color: nullable(draft.primary_color),
    size: nullable(draft.size),
    notes: nullable(draft.notes),
    tags: [
      ...new Set(
        draft.tags
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean),
      ),
    ],
  };
}

function nullable(value: string | null): string | null {
  const normalized = value?.trim() ?? "";
  return normalized || null;
}

function provenanceText(
  provenance: ReceiptPurchaseUnitFieldProvenanceV1,
): string {
  if (provenance.kind === "user_correction") {
    return "User correction from reviewed receipt";
  }
  if (provenance.kind === "unknown_receipt_field") {
    return "Unknown in reviewed receipt";
  }
  const count = provenance.citations.length;
  return `${count} verified receipt source ${count === 1 ? "citation" : "citations"}`;
}

function isConflict(error: unknown): boolean {
  if (!error || typeof error !== "object" || !("code" in error)) return false;
  return ["request_conflict", "snapshot_expired"].includes(
    String((error as { code: unknown }).code),
  );
}

function navigateToCatalogItem(item: CatalogItemV1) {
  window.location.hash = `catalog-item-${item.item_id}`;
  const wardrobeTab = [
    ...document.querySelectorAll<HTMLButtonElement>(
      'nav[aria-label="Workspace"] button',
    ),
  ].find((button) => button.textContent?.trim() === "Wardrobe");
  wardrobeTab?.click();

  let attempts = 0;
  const focusItem = () => {
    const label = [
      ...document.querySelectorAll<HTMLElement>(".catalog-list .item-copy strong"),
    ].find(
      (candidate) =>
        candidate.textContent?.trim() === item.attributes.display_name,
    );
    const row = label?.closest<HTMLElement>("li");
    if (row) {
      row.id = `catalog-item-${item.item_id}`;
      row.tabIndex = -1;
      row.focus();
      return;
    }
    attempts += 1;
    if (attempts < 20) window.setTimeout(focusItem, 25);
  };
  window.setTimeout(focusItem, 0);
}

function humanize(value: string): string {
  return value
    .split("_")
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}
