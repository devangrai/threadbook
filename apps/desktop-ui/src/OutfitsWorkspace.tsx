import { useCallback, useEffect, useMemo, useState } from "react";

import { catalogBridge, type CatalogBridge } from "./catalog-bridge";
import type {
  CatalogItemV1,
  CredentialReferenceV1,
  GetOutfitCollageV1Response,
  ListOutfitsV1Response,
  OutfitCollageMemberV1,
  OutfitV1,
} from "./generated/contracts";
import { OutfitRecommendationPanel } from "./OutfitRecommendationPanel";
import { outfitBridge, type OutfitBridge } from "./outfit-bridge";
import { loadOutfitRecommendationCredentials } from "./outfit-recommendation-bridge";
import { TryOnPanel } from "./TryOnPanel";
import { tryOnBridge, type TryOnBridge } from "./try-on-bridge";

type OutfitsWorkspaceProps = {
  localOnly: boolean;
  catalog?: CatalogBridge;
  outfits?: OutfitBridge;
  recommendationsEnabled?: boolean;
  tryOnEnabled?: boolean;
  tryOn?: TryOnBridge;
  loadRecommendationCredentials?: () => Promise<CredentialReferenceV1[]>;
};

export function OutfitsWorkspace({
  localOnly,
  catalog = catalogBridge,
  outfits = outfitBridge,
  recommendationsEnabled =
    import.meta.env.MODE === "e2e" ||
    import.meta.env.VITE_WARDROBE_REMOTE_RECOMMENDATIONS_RELEASE ===
      "credentialed-live",
  tryOnEnabled =
    import.meta.env.VITE_WARDROBE_TRY_ON_RELEASE === "experimental",
  tryOn = tryOnBridge,
  loadRecommendationCredentials = loadOutfitRecommendationCredentials,
}: OutfitsWorkspaceProps) {
  const [items, setItems] = useState<CatalogItemV1[]>([]);
  const [credentials, setCredentials] = useState<CredentialReferenceV1[]>([]);
  const [catalogRevision, setCatalogRevision] = useState(0);
  const [page, setPage] = useState<ListOutfitsV1Response | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [collage, setCollage] =
    useState<GetOutfitCollageV1Response | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [catalogPage, outfitPage, credentialPage] = await Promise.all([
        catalog.listCatalog(null, 100),
        outfits.listOutfits(null, 20),
        recommendationsEnabled || tryOnEnabled
          ? loadRecommendationCredentials().catch(() => [])
          : Promise.resolve([]),
      ]);
      setItems(
        catalogPage.items.map((item) => ({
          item_id: item.item_id,
          attributes: {
            display_name: item.display_name,
            category: item.category,
            subcategory: null,
            brand: null,
            primary_color: item.color || null,
            size: null,
            notes: item.notes || null,
            tags: [],
          },
          evidence_ids: item.evidence_ids,
          last_decision_id: item.last_decision_id ?? crypto.randomUUID(),
        })),
      );
      setCatalogRevision(catalogPage.catalog_revision);
      setPage(outfitPage);
      setCredentials(credentialPage);
    } catch {
      setMessage("The local outfit workspace could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, [
    catalog,
    loadRecommendationCredentials,
    outfits,
    recommendationsEnabled,
    tryOnEnabled,
  ]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = (itemId: string) => {
    setSelectedIds((current) =>
      current.includes(itemId)
        ? current.filter((value) => value !== itemId)
        : current.length < 8
          ? [...current, itemId]
          : current,
    );
  };

  const move = (index: number, direction: -1 | 1) => {
    setSelectedIds((current) => {
      const target = index + direction;
      if (target < 0 || target >= current.length) return current;
      const next = [...current];
      [next[index], next[target]] = [next[target], next[index]];
      return next;
    });
  };

  const save = async () => {
    if (!page || selectedIds.length < 2 || !name.trim()) return;
    setBusy("save");
    setMessage(null);
    try {
      await outfits.createManualOutfit(
        name,
        selectedIds,
        catalogRevision,
        page.outfit_revision,
      );
      setName("");
      setSelectedIds([]);
      setPage(await outfits.listOutfits(null, 20));
      setMessage("Outfit saved locally.");
    } catch {
      setMessage(
        "The wardrobe changed. Your selection is still here; refresh and try again.",
      );
    } finally {
      setBusy(null);
    }
  };

  const saveProposal = async (proposal: {
    name: string;
    item_ids: string[];
  }) => {
    if (!page) throw new Error("outfit page unavailable");
    await outfits.createManualOutfit(
      proposal.name,
      proposal.item_ids,
      catalogRevision,
      page.outfit_revision,
    );
    setPage(await outfits.listOutfits(null, 20));
  };

  const openCollage = async (outfit: OutfitV1) => {
    setBusy(`collage:${outfit.outfit_id}`);
    setMessage(null);
    try {
      setCollage(await outfits.getCollage(outfit.outfit_id));
    } catch {
      setMessage("The saved outfit could not be opened.");
    } finally {
      setBusy(null);
    }
  };

  if (loading && !page) {
    return (
      <section className="state-view" aria-label="Loading outfits">
        <span className="spinner" aria-hidden="true" />
        <p>Loading outfits...</p>
      </section>
    );
  }

  if (collage) {
    return (
      <OutfitCollage
        key={`${collage.outfit_id}:${collage.outfit_revision}`}
        collage={collage}
        credentials={credentials}
        localOnly={localOnly}
        tryOn={tryOn}
        tryOnEnabled={tryOnEnabled}
        onBack={() => setCollage(null)}
      />
    );
  }

  return (
    <section aria-labelledby="outfits-title">
      <div className="sr-live" role="status" aria-live="polite">
        {message}
      </div>
      <div className="view-heading">
        <div>
          <h2 id="outfits-title">Outfits</h2>
          <p className="count">{page?.total_count ?? 0} saved outfits</p>
        </div>
      </div>

      {recommendationsEnabled && credentials.length > 0 && (
        <OutfitRecommendationPanel
          localOnly={localOnly}
          items={items}
          catalogRevision={catalogRevision}
          outfitRevision={page?.outfit_revision ?? 0}
          credentials={credentials}
          onSaveProposal={saveProposal}
        />
      )}

      <div className="outfit-workspace">
        <section className="outfit-builder" aria-labelledby="build-outfit-title">
          <div className="settings-title-row">
            <h3 id="build-outfit-title">Build outfit</h3>
            <span className="muted">{selectedIds.length}/8 selected</span>
          </div>
          <label className="field">
            <span>Name</span>
            <input
              value={name}
              maxLength={80}
              onChange={(event) => setName(event.target.value)}
              placeholder="Dinner date"
            />
          </label>
          <div className="outfit-item-picker" role="group" aria-label="Wardrobe items">
            {items.map((item) => (
              <label className="outfit-item-option" key={item.item_id}>
                <input
                  type="checkbox"
                  checked={selectedIds.includes(item.item_id)}
                  disabled={
                    selectedIds.length >= 8 &&
                    !selectedIds.includes(item.item_id)
                  }
                  onChange={() => toggle(item.item_id)}
                />
                <span>
                  <strong>{item.attributes.display_name}</strong>
                  <small>
                    {item.attributes.primary_color ??
                      formatCategory(item.attributes.category)}
                  </small>
                </span>
              </label>
            ))}
          </div>
          {selectedIds.length > 0 && (
            <ol className="outfit-order" aria-label="Outfit order">
              {selectedIds.map((itemId, index) => {
                const item = items.find((candidate) => candidate.item_id === itemId);
                return (
                  <li key={itemId}>
                    <span>{item?.attributes.display_name ?? "Wardrobe item"}</span>
                    <div className="row-actions">
                      <button
                        className="icon-button"
                        type="button"
                        aria-label={`Move ${item?.attributes.display_name ?? "item"} up`}
                        title="Move up"
                        disabled={index === 0}
                        onClick={() => move(index, -1)}
                      >
                        ↑
                      </button>
                      <button
                        className="icon-button"
                        type="button"
                        aria-label={`Move ${item?.attributes.display_name ?? "item"} down`}
                        title="Move down"
                        disabled={index === selectedIds.length - 1}
                        onClick={() => move(index, 1)}
                      >
                        ↓
                      </button>
                    </div>
                  </li>
                );
              })}
            </ol>
          )}
          <button
            className="button button-primary"
            type="button"
            disabled={
              busy !== null || !name.trim() || selectedIds.length < 2
            }
            onClick={() => void save()}
          >
            {busy === "save" ? "Saving..." : "Save outfit"}
          </button>
        </section>

        <section className="saved-outfits" aria-labelledby="saved-outfits-title">
          <h3 id="saved-outfits-title">Saved</h3>
          {!page?.outfits.length ? (
            <div className="empty-state compact">
              <p>No saved outfits</p>
            </div>
          ) : (
            <ul className="outfit-list">
              {page.outfits.map((outfit) => (
                <li key={outfit.outfit_id}>
                  <div>
                    <strong>{outfit.name}</strong>
                    <span>
                      {outfit.members
                        .map((member) => member.attributes.display_name)
                        .join(", ")}
                    </span>
                  </div>
                  <button
                    className="button"
                    type="button"
                    disabled={busy !== null}
                    onClick={() => void openCollage(outfit)}
                  >
                    View collage
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </section>
  );
}

function OutfitCollage({
  collage,
  credentials,
  localOnly,
  tryOn,
  tryOnEnabled,
  onBack,
}: {
  collage: GetOutfitCollageV1Response;
  credentials: CredentialReferenceV1[];
  localOnly: boolean;
  tryOn: TryOnBridge;
  tryOnEnabled: boolean;
  onBack: () => void;
}) {
  const expectedImageKeys = useMemo(
    () =>
      collage.members
        .filter(
          (member) =>
            member.bytes !== null && member.member.asset.media_type !== null,
        )
        .map(
          (member) =>
            `${member.member.item_id}:${member.member.ordinal}`,
        ),
    [collage],
  );
  const [loadedImageKeys, setLoadedImageKeys] = useState<Set<string>>(
    () => new Set(),
  );
  const [failedImageKeys, setFailedImageKeys] = useState<Set<string>>(
    () => new Set(),
  );

  const imageStatus =
    failedImageKeys.size > 0
      ? "Outfit collage image error"
      : expectedImageKeys.every((key) => loadedImageKeys.has(key))
        ? "Outfit collage ready"
        : "Outfit collage loading";

  return (
    <section aria-labelledby="collage-title">
      <div className="view-heading">
        <div>
          <button className="text-button" type="button" onClick={onBack}>
            Back to outfits
          </button>
          <h2 id="collage-title">{collage.name}</h2>
          <p className="muted">Saved wardrobe collage</p>
        </div>
      </div>
      <div className="outfit-collage" aria-label="Outfit collage">
        <span
          className="visually-hidden"
          role="status"
          aria-label={imageStatus}
        />
        {collage.members.map((member) => {
          const key = `${member.member.item_id}:${member.member.ordinal}`;
          return (
            <CollagePanel
              member={member}
              key={key}
              onImageLoad={() =>
                setLoadedImageKeys((current) => new Set(current).add(key))
              }
              onImageError={() =>
                setFailedImageKeys((current) => new Set(current).add(key))
              }
            />
          );
        })}
      </div>
      {tryOnEnabled && (
        <TryOnPanel
          localOnly={localOnly}
          outfitId={collage.outfit_id}
          outfitRevision={collage.outfit_revision}
          credentials={credentials}
          bridge={tryOn}
        />
      )}
    </section>
  );
}

function CollagePanel({
  member,
  onImageLoad,
  onImageError,
}: {
  member: OutfitCollageMemberV1;
  onImageLoad: () => void;
  onImageError: () => void;
}) {
  const imageUrl = useMemo(() => {
    if (!member.bytes || !member.member.asset.media_type) return null;
    return URL.createObjectURL(
      new Blob([new Uint8Array(member.bytes)], {
        type: member.member.asset.media_type,
      }),
    );
  }, [member]);

  useEffect(
    () => () => {
      if (imageUrl) URL.revokeObjectURL(imageUrl);
    },
    [imageUrl],
  );

  const attributes = member.member.attributes;
  const captionId = `outfit-member-${member.member.ordinal}-caption`;
  return (
    <figure className="outfit-collage-panel">
      <div
        className="outfit-collage-media"
        role={imageUrl ? "img" : undefined}
        aria-label={
          imageUrl
            ? `Outfit member ${member.member.ordinal} source image`
            : undefined
        }
        aria-describedby={imageUrl ? captionId : undefined}
        style={
          imageUrl
            ? undefined
            : { backgroundColor: attributes.primary_color ?? "#e8e8e4" }
        }
      >
        {imageUrl ? (
          <img
            src={imageUrl}
            alt=""
            aria-hidden="true"
            onLoad={onImageLoad}
            onError={onImageError}
          />
        ) : (
          <span>No image</span>
        )}
      </div>
      <figcaption id={captionId}>
        <strong>{attributes.display_name}</strong>
        <span>{formatCategory(attributes.category)}</span>
      </figcaption>
    </figure>
  );
}

function formatCategory(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
