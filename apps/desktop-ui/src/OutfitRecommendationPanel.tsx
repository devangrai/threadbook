import { useEffect, useMemo, useState } from "react";

import type {
  CatalogItemV1,
  CredentialReferenceV1,
  OpenAiRetentionDeclarationV1,
  OutfitDisclosureFieldClassV1,
  OutfitOccasionV1,
  OutfitPrecipitationV1,
  OutfitProposalV1,
  OutfitRecommendationEnvelopeV1,
  OutfitRecommendationOutcomeV1,
  PreviewOutfitRecommendationV1Response,
} from "./generated/contracts";
import {
  outfitRecommendationBridge,
  type OutfitRecommendationBridge,
} from "./outfit-recommendation-bridge";

const occasions: ReadonlyArray<OutfitOccasionV1> = [
  "casual",
  "date",
  "work",
  "formal",
  "active",
  "travel",
];
const precipitationOptions: ReadonlyArray<OutfitPrecipitationV1> = [
  "none",
  "rain",
  "snow",
];
const defaultRetention: OpenAiRetentionDeclarationV1 = {
  mode: "unknown",
  provenance: "user_not_declared",
};

type PendingApproval = {
  envelope: OutfitRecommendationEnvelopeV1;
  preview: PreviewOutfitRecommendationV1Response;
};

export type OutfitRecommendationPanelProps = {
  localOnly: boolean;
  items: CatalogItemV1[];
  catalogRevision: number;
  outfitRevision: number;
  credentials: CredentialReferenceV1[];
  onSaveProposal: (proposal: OutfitProposalV1) => void | Promise<void>;
  retention?: OpenAiRetentionDeclarationV1;
  bridge?: OutfitRecommendationBridge;
};

export function OutfitRecommendationPanel({
  localOnly,
  items,
  catalogRevision,
  outfitRevision,
  credentials,
  onSaveProposal,
  retention = defaultRetention,
  bridge = outfitRecommendationBridge,
}: OutfitRecommendationPanelProps) {
  const activeCredentials = useMemo(
    () =>
      credentials.filter(
        (credential) =>
          credential.provider === "open_ai" && credential.status === "active",
      ),
    [credentials],
  );
  const [prompt, setPrompt] = useState("");
  const [occasion, setOccasion] = useState<OutfitOccasionV1 | "">("");
  const [temperature, setTemperature] = useState("");
  const [precipitation, setPrecipitation] = useState<
    OutfitPrecipitationV1 | ""
  >("");
  const [excludedIds, setExcludedIds] = useState<string[]>([]);
  const [credentialId, setCredentialId] = useState(
    activeCredentials[0]?.credential_id ?? "",
  );
  const [pending, setPending] = useState<PendingApproval | null>(null);
  const [outcome, setOutcome] =
    useState<OutfitRecommendationOutcomeV1 | null>(null);
  const [busy, setBusy] = useState<"preview" | "send" | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [savingIndex, setSavingIndex] = useState<number | null>(null);

  useEffect(() => {
    if (
      !activeCredentials.some(
        (credential) => credential.credential_id === credentialId,
      )
    ) {
      setCredentialId(activeCredentials[0]?.credential_id ?? "");
    }
  }, [activeCredentials, credentialId]);

  useEffect(() => {
    setPending(null);
  }, [catalogRevision, outfitRevision]);

  useEffect(() => {
    if (localOnly) {
      setPending(null);
    }
  }, [localOnly]);

  const preview = async () => {
    const trimmedPrompt = prompt.trim();
    const parsedTemperature =
      temperature === "" ? null : Number(temperature);
    if (
      localOnly ||
      !trimmedPrompt ||
      !credentialId ||
      (parsedTemperature !== null && !Number.isFinite(parsedTemperature))
    ) {
      return;
    }
    const envelope: OutfitRecommendationEnvelopeV1 = {
      prompt: trimmedPrompt,
      credential_id: credentialId,
      constraints: {
        occasion: occasion || null,
        temperature_c: parsedTemperature,
        precipitation: precipitation || null,
      },
      excluded_item_ids: [...excludedIds].sort(),
      requested_proposal_count: 1,
      expected_catalog_revision: catalogRevision,
      expected_outfit_revision: outfitRevision,
      retention,
    };
    setBusy("preview");
    setMessage(null);
    setOutcome(null);
    setPending(null);
    try {
      const response = await bridge.preview(envelope);
      setPending({ envelope, preview: response });
    } catch {
      setMessage("The local disclosure preview could not be prepared.");
    } finally {
      setBusy(null);
    }
  };

  const send = async () => {
    if (
      localOnly ||
      !pending ||
      pending.preview.provider_status !== "ready"
    ) {
      return;
    }
    const approved = pending;
    setPending(null);
    setBusy("send");
    setMessage(null);
    try {
      const response = await bridge.request(
        approved.preview.approval.approval_id,
        approved.envelope,
      );
      setOutcome(response.outcome);
    } catch {
      setMessage("The recommendation request could not be completed.");
    } finally {
      setBusy(null);
    }
  };

  const save = async (proposal: OutfitProposalV1, index: number) => {
    setSavingIndex(index);
    setMessage(null);
    try {
      await onSaveProposal(proposal);
      setMessage(`Saved "${proposal.name}" as an outfit.`);
    } catch {
      setMessage(`"${proposal.name}" was not saved.`);
    } finally {
      setSavingIndex(null);
    }
  };

  const toggleExclusion = (itemId: string) => {
    setExcludedIds((current) =>
      current.includes(itemId)
        ? current.filter((value) => value !== itemId)
        : [...current, itemId],
    );
  };

  return (
    <section
      className="outfit-recommendation-panel"
      aria-labelledby="outfit-recommendation-title"
    >
      <div className="settings-title-row">
        <div>
          <h3 id="outfit-recommendation-title">Outfit ideas</h3>
          <p className="muted">Recommendations use confirmed wardrobe items.</p>
        </div>
      </div>

      <div className="sr-live" role="status" aria-live="polite">
        {message}
      </div>

      {localOnly && (
        <p className="settings-description">
          OpenAI recommendations are unavailable in local-only mode. Saved
          recommendation results remain available.
        </p>
      )}

      <label className="field">
        <span>What do you need?</span>
        <textarea
          value={prompt}
          maxLength={1000}
          rows={3}
          onChange={(event) => setPrompt(event.target.value)}
          placeholder="A comfortable outfit for dinner"
        />
      </label>

      <div className="recommendation-constraints">
        <label className="field">
          <span>Occasion</span>
          <select
            value={occasion}
            onChange={(event) =>
              setOccasion(event.target.value as OutfitOccasionV1 | "")
            }
          >
            <option value="">Any</option>
            {occasions.map((value) => (
              <option value={value} key={value}>
                {capitalize(value)}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Temperature (C)</span>
          <input
            type="number"
            min={-50}
            max={60}
            step={1}
            value={temperature}
            onChange={(event) => setTemperature(event.target.value)}
          />
        </label>
        <label className="field">
          <span>Precipitation</span>
          <select
            value={precipitation}
            onChange={(event) =>
              setPrecipitation(
                event.target.value as OutfitPrecipitationV1 | "",
              )
            }
          >
            <option value="">Unspecified</option>
            {precipitationOptions.map((value) => (
              <option value={value} key={value}>
                {capitalize(value)}
              </option>
            ))}
          </select>
        </label>
      </div>

      <label className="field">
        <span>OpenAI credential</span>
        <select
          value={credentialId}
          disabled={activeCredentials.length === 0}
          onChange={(event) => setCredentialId(event.target.value)}
        >
          {activeCredentials.length === 0 && (
            <option value="">No active credential</option>
          )}
          {activeCredentials.map((credential) => (
            <option
              value={credential.credential_id}
              key={credential.credential_id}
            >
              {credential.display_label}
            </option>
          ))}
        </select>
      </label>

      <fieldset className="outfit-item-picker">
        <legend>Exclude items</legend>
        {items.map((item) => (
          <label className="outfit-item-option" key={item.item_id}>
            <input
              type="checkbox"
              checked={excludedIds.includes(item.item_id)}
              onChange={() => toggleExclusion(item.item_id)}
            />
            <span>{item.attributes.display_name}</span>
          </label>
        ))}
      </fieldset>

      <div className="row-actions">
        <button
          className="button button-primary"
          type="button"
          disabled={
            localOnly ||
            busy !== null ||
            prompt.trim() === "" ||
            credentialId === ""
          }
          onClick={() => void preview()}
        >
          {busy === "preview" ? "Preparing..." : "Preview disclosure"}
        </button>
      </div>

      {pending && !localOnly && (
        <DisclosureDialog
          pending={pending}
          sending={busy === "send"}
          onDismiss={() => setPending(null)}
          onSend={() => void send()}
        />
      )}

      {busy === "send" && (
        <p className="muted" role="status">
          Requesting outfit ideas...
        </p>
      )}
      {outcome && (
        <RecommendationResult
          outcome={outcome}
          items={items}
          savingIndex={savingIndex}
          onSave={(proposal, index) => void save(proposal, index)}
        />
      )}
    </section>
  );
}

function DisclosureDialog({
  pending,
  sending,
  onDismiss,
  onSend,
}: {
  pending: PendingApproval;
  sending: boolean;
  onDismiss: () => void;
  onSend: () => void;
}) {
  const { disclosure } = pending.preview;
  const retention = disclosure.retention;
  return (
    <div className="modal-backdrop">
      <div
        className="modal-panel recommendation-disclosure"
        role="dialog"
        aria-modal="true"
        aria-labelledby="recommendation-disclosure-title"
      >
        <div className="settings-title-row">
          <h4 id="recommendation-disclosure-title">Review OpenAI disclosure</h4>
          <button
            className="icon-button"
            type="button"
            aria-label="Dismiss disclosure"
            disabled={sending}
            onClick={onDismiss}
          >
            ×
          </button>
        </div>

        <p>
          The local app will disclose these exact data classes to{" "}
          <strong>{disclosure.provider}</strong> using{" "}
          <strong>{disclosure.model}</strong>:
        </p>
        <ul aria-label="Disclosed data classes">
          {disclosure.disclosed_field_classes.map((fieldClass) => (
            <li key={fieldClass}>{disclosureLabel(fieldClass)}</li>
          ))}
        </ul>
        <p>
          No photos, email content, file paths, notes, sizes, or evidence
          metadata will be sent.
        </p>
        <dl className="recommendation-disclosure-facts">
          <div>
            <dt>Storage</dt>
            <dd>
              store={String(retention.store)}. store=false is not Zero Data
              Retention (ZDR).
            </dd>
          </div>
          <div>
            <dt>Abuse monitoring</dt>
            <dd>
              Data may be retained for abuse monitoring for up to{" "}
              {retention.default_abuse_monitoring_max_days} days; safety review
              exceptions may apply.
            </dd>
          </div>
          <div>
            <dt>Prompt cache policy</dt>
            <dd>
              {retention.prompt_cache_mode};{" "}
              {retention.prompt_cache_breakpoint_count} breakpoints.{" "}
              {retention.no_breakpoints_no_cache_reads_or_writes
                ? "No breakpoints means no cache reads or writes."
                : "Prompt cache reads or writes may occur."}
            </dd>
          </div>
          <div>
            <dt>Declared retention</dt>
            <dd>
              {retention.declaration.mode} from{" "}
              {retention.declaration.provenance}.
            </dd>
          </div>
        </dl>
        {pending.preview.provider_status !== "ready" && (
          <p role="alert">
            Provider status:{" "}
            {pending.preview.provider_status.replaceAll("_", " ")}. Sending is
            unavailable.
          </p>
        )}
        <div className="row-actions">
          <button
            className="button"
            type="button"
            disabled={sending}
            onClick={onDismiss}
          >
            Cancel
          </button>
          <button
            className="button button-primary"
            type="button"
            disabled={
              sending || pending.preview.provider_status !== "ready"
            }
            onClick={onSend}
          >
            {sending ? "Sending..." : "Send to OpenAI"}
          </button>
        </div>
      </div>
    </div>
  );
}

function RecommendationResult({
  outcome,
  items,
  savingIndex,
  onSave,
}: {
  outcome: OutfitRecommendationOutcomeV1;
  items: CatalogItemV1[];
  savingIndex: number | null;
  onSave: (proposal: OutfitProposalV1, index: number) => void;
}) {
  if (outcome.outcome === "refused") {
    return (
      <section className="recommendation-result" aria-label="Recommendation result">
        <h4>Request refused</h4>
        <p>OpenAI did not provide outfit recommendations for this request.</p>
      </section>
    );
  }
  if (outcome.outcome === "failed") {
    return (
      <section className="recommendation-result" aria-label="Recommendation result">
        <h4>Recommendation failed</h4>
        <p>
          {failureLabel(outcome.code)}
          {outcome.retryable ? " You can prepare a new preview and retry." : ""}
        </p>
      </section>
    );
  }
  if (outcome.outcome === "historical_stale") {
    return (
      <section className="recommendation-result" aria-label="Recommendation result">
        <h4>Historical recommendation</h4>
        <p>
          This saved result is stale because{" "}
          {staleReason(outcome.catalog_changed, outcome.outfit_changed)}. It
          cannot be presented as a current recommendation.
        </p>
      </section>
    );
  }

  return (
    <section className="recommendation-result" aria-labelledby="ideas-title">
      <h4 id="ideas-title">Recommended outfits</h4>
      <ol className="recommendation-proposals">
        {outcome.recommendation.proposals.map((proposal, index) => (
          <li key={`${proposal.name}-${index}`}>
            <h5>{proposal.name}</h5>
            <p>{proposal.rationale}</p>
            <ul aria-label={`${proposal.name} items`}>
              {proposal.item_ids.map((itemId) => (
                <li key={itemId}>{itemName(items, itemId)}</li>
              ))}
            </ul>
            {proposal.caveats.length > 0 && (
              <p className="muted">{proposal.caveats.join(" ")}</p>
            )}
            <button
              className="button"
              type="button"
              disabled={savingIndex !== null}
              onClick={() => onSave(proposal, index)}
            >
              {savingIndex === index ? "Saving..." : "Save outfit"}
            </button>
          </li>
        ))}
      </ol>
    </section>
  );
}

function disclosureLabel(value: OutfitDisclosureFieldClassV1): string {
  const labels: Record<OutfitDisclosureFieldClassV1, string> = {
    prompt: "Your request",
    explicit_constraints: "Explicit occasion and weather constraints",
    excluded_item_ids: "Excluded wardrobe item IDs",
    item_ids: "Confirmed wardrobe item IDs",
    display_names: "Wardrobe item display names",
    categories: "Wardrobe categories",
    primary_colors: "Primary colors",
    brands: "Brands",
    capability_tags: "Closed weather capability tags",
    wear_history: "Wear history",
    style_preferences: "Style preferences",
    saved_outfit_membership: "Saved outfit membership",
  };
  return labels[value];
}

function failureLabel(code: OutfitRecommendationOutcomeV1 extends infer _T
  ? Extract<OutfitRecommendationOutcomeV1, { outcome: "failed" }>["code"]
  : never): string {
  return `Typed failure: ${code.replaceAll("_", " ")}.`;
}

function staleReason(catalogChanged: boolean, outfitChanged: boolean): string {
  if (catalogChanged && outfitChanged) return "the wardrobe and outfits changed";
  if (catalogChanged) return "the wardrobe changed";
  if (outfitChanged) return "saved outfits changed";
  return "its approved snapshot is no longer current";
}

function itemName(items: CatalogItemV1[], itemId: string): string {
  return (
    items.find((item) => item.item_id === itemId)?.attributes.display_name ??
    "Unavailable wardrobe item"
  );
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
