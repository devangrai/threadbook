import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";

import type {
  CredentialReferenceV1,
  OpenAiRetentionDeclarationV1,
} from "./generated/contracts";
import {
  tryOnBridge,
  type TryOnAssetDescriptorView,
  type TryOnBridge,
  type TryOnImageV1,
  type TryOnJobView,
  type TryOnPortraitCandidateView,
  type TryOnPreviewView,
} from "./try-on-bridge";

const AI_DISCLAIMER =
  "AI visualization. Not an accurate representation of fit or garment construction.";

const defaultRetention: OpenAiRetentionDeclarationV1 = {
  mode: "unknown",
  provenance: "user_not_declared",
};

export type TryOnPanelProps = {
  localOnly: boolean;
  outfitId: string;
  outfitRevision: number;
  credentials: CredentialReferenceV1[];
  retention?: OpenAiRetentionDeclarationV1;
  bridge?: TryOnBridge;
};

export function TryOnPanel({
  localOnly,
  outfitId,
  outfitRevision,
  credentials,
  retention = defaultRetention,
  bridge = tryOnBridge,
}: TryOnPanelProps) {
  const activeCredentials = useMemo(
    () =>
      credentials.filter(
        (credential) =>
          credential.provider === "open_ai" && credential.status === "active",
      ),
    [credentials],
  );
  const [credentialId, setCredentialId] = useState(
    activeCredentials[0]?.credential_id ?? "",
  );
  const [portraits, setPortraits] = useState<TryOnPortraitCandidateView[]>([]);
  const [portraitId, setPortraitId] = useState("");
  const [preview, setPreview] = useState<TryOnPreviewView | null>(null);
  const [job, setJob] = useState<TryOnJobView | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<"preview" | "submit" | null>(null);
  const [message, setMessage] = useState<string | null>(null);

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
    if (localOnly) {
      setPreview(null);
    }
  }, [localOnly]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setMessage(null);
    Promise.allSettled([
      bridge.listPortraitCandidates(null, 20),
      bridge.getOutfitTryOn(outfitId),
    ]).then(([portraitResult, jobResult]) => {
      if (cancelled) return;
      if (portraitResult.status === "fulfilled") {
        setPortraits(portraitResult.value.candidates);
        setPortraitId(
          (current) =>
            current || portraitResult.value.candidates[0]?.sourceRevisionId || "",
        );
      } else {
        setMessage("Portraits could not be loaded. Check local photo analysis.");
      }
      if (jobResult.status === "fulfilled") {
        setJob(jobResult.value);
      } else {
        setMessage("The saved visualization status could not be loaded.");
      }
      setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [bridge, outfitId]);

  useEffect(() => {
    if (job?.state !== "queued" && job?.state !== "running") return;
    let cancelled = false;
    let timer = 0;
    const poll = async () => {
      try {
        const latest = await bridge.getOutfitTryOn(outfitId);
        if (!cancelled && latest) setJob(latest);
      } catch {
        if (!cancelled) {
          setMessage("Visualization status could not be refreshed.");
        }
      } finally {
        if (!cancelled) timer = window.setTimeout(() => void poll(), 1500);
      }
    };
    timer = window.setTimeout(() => void poll(), 1500);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [bridge, job?.state, outfitId]);

  const preparePreview = async () => {
    if (localOnly || !portraitId || !credentialId) return;
    setBusy("preview");
    setMessage(null);
    setPreview(null);
    try {
      setPreview(
        await bridge.preview(
          outfitId,
          portraitId,
          credentialId,
          retention,
          outfitRevision,
        ),
      );
    } catch {
      setMessage(
        "The disclosure could not be prepared. Verify the portrait, garment images, and credential.",
      );
    } finally {
      setBusy(null);
    }
  };

  const submit = async () => {
    if (localOnly || !preview || preview.providerStatus !== "ready") return;
    const approvalId = preview.approvalId;
    setBusy("submit");
    setMessage(null);
    try {
      const submitted = await bridge.submit(approvalId);
      setJob(submitted);
      setPreview(null);
    } catch {
      setMessage(
        "The visualization was not queued. Prepare a new disclosure before trying again.",
      );
      setPreview(null);
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="try-on-panel" aria-labelledby="try-on-title">
      <div className="settings-title-row">
        <div>
          <h3 id="try-on-title">Try-on visualization</h3>
          <p className="muted">
            Experimental generation from one local portrait and this saved
            outfit.
          </p>
        </div>
      </div>

      <div className="sr-live" role="status" aria-live="polite">
        {message}
      </div>

      {localOnly && (
        <p className="settings-description">
          OpenAI try-on actions are unavailable in local-only mode. Saved
          visualization status and history remain available.
        </p>
      )}

      {loading ? (
        <p className="muted" role="status">
          Loading portraits and saved status...
        </p>
      ) : (
        <>
          <fieldset className="try-on-portrait-picker">
            <legend>Choose a portrait</legend>
            {portraits.length === 0 ? (
              <p className="muted">
                No analyzed portraits are available. Analyze a local photo
                first.
              </p>
            ) : (
              <div className="try-on-portrait-options">
                {portraits.map((portrait) => (
                  <PortraitOption
                    key={portrait.sourceRevisionId}
                    portrait={portrait}
                    checked={portraitId === portrait.sourceRevisionId}
                    onChange={() => {
                      setPortraitId(portrait.sourceRevisionId);
                      setPreview(null);
                    }}
                  />
                ))}
              </div>
            )}
          </fieldset>

          {activeCredentials.length > 1 && (
            <label className="field try-on-credential">
              <span>OpenAI credential</span>
              <select
                value={credentialId}
                onChange={(event) => {
                  setCredentialId(event.target.value);
                  setPreview(null);
                }}
              >
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
          )}

          {activeCredentials.length === 0 && (
            <p className="try-on-callout" role="note">
              Add an active OpenAI credential in Settings to prepare a
              visualization.
            </p>
          )}

          <div className="row-actions">
            <button
              className="button button-primary"
              type="button"
              disabled={
                localOnly ||
                busy !== null ||
                portraitId === "" ||
                credentialId === ""
              }
              onClick={() => void preparePreview()}
            >
              {busy === "preview" ? "Preparing..." : "Preview disclosure"}
            </button>
          </div>
        </>
      )}

      {job && <TryOnResult job={job} />}

      {preview && !localOnly && (
        <TryOnDisclosureDialog
          preview={preview}
          submitting={busy === "submit"}
          onDismiss={() => setPreview(null)}
          onGenerate={() => void submit()}
        />
      )}
    </section>
  );
}

function PortraitOption({
  portrait,
  checked,
  onChange,
}: {
  portrait: TryOnPortraitCandidateView;
  checked: boolean;
  onChange: () => void;
}) {
  const imageUrl = useImageUrl(portrait.thumbnail);
  return (
    <label className="try-on-portrait-option">
      <input
        type="radio"
        name="try-on-portrait"
        value={portrait.sourceRevisionId}
        aria-label={portrait.label}
        checked={checked}
        onChange={onChange}
      />
      <span className="try-on-portrait-thumbnail">
        {imageUrl ? <img src={imageUrl} alt="" /> : <span>No preview</span>}
      </span>
      <span>{portrait.label}</span>
    </label>
  );
}

function TryOnDisclosureDialog({
  preview,
  submitting,
  onDismiss,
  onGenerate,
}: {
  preview: TryOnPreviewView;
  submitting: boolean;
  onDismiss: () => void;
  onGenerate: () => void;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(
    document.activeElement instanceof HTMLElement ? document.activeElement : null,
  );

  useEffect(() => {
    const first = focusableControls(dialogRef.current)[0];
    first?.focus();
    return () => previousFocus.current?.focus();
  }, []);

  const handleKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape" && !submitting) {
      event.preventDefault();
      onDismiss();
      return;
    }
    if (event.key !== "Tab") return;
    const controls = focusableControls(dialogRef.current);
    if (controls.length === 0) {
      event.preventDefault();
      return;
    }
    const first = controls[0];
    const last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  return (
    <div className="modal-backdrop">
      <div
        ref={dialogRef}
        className="modal-panel try-on-disclosure"
        role="dialog"
        aria-modal="true"
        aria-labelledby="try-on-disclosure-title"
        onKeyDown={handleKeyDown}
      >
        <div className="modal-heading">
          <h4 id="try-on-disclosure-title">Review try-on disclosure</h4>
          <button
            className="icon-button"
            type="button"
            aria-label="Dismiss disclosure"
            title="Close"
            disabled={submitting}
            onClick={onDismiss}
          >
            ×
          </button>
        </div>

        <dl className="try-on-disclosure-facts">
          <div>
            <dt>Provider</dt>
            <dd>{preview.provider}</dd>
          </div>
          <div>
            <dt>Model</dt>
            <dd>{preview.model}</dd>
          </div>
          <div>
            <dt>Purpose</dt>
            <dd>{preview.purpose}</dd>
          </div>
          <div>
            <dt>Retention</dt>
            <dd>{preview.retentionSummary}</dd>
          </div>
        </dl>

        <div>
          <h5>Images sent in this order</h5>
          <ol
            className="try-on-disclosure-assets"
            aria-label="Images sent to OpenAI"
          >
            {[...preview.assets]
              .sort((left, right) => left.ordinal - right.ordinal)
              .map((asset) => (
                <DisclosureAsset asset={asset} key={`${asset.role}:${asset.ordinal}`} />
              ))}
          </ol>
        </div>

        <p className="muted">
          OpenAI scans image inputs for safety. Flagged inputs may be retained
          for manual review. No local paths, item IDs, source IDs, or hashes are
          transmitted.
        </p>

        {preview.providerStatus !== "ready" && (
          <p role="alert">
            Provider status: {preview.providerStatus.replaceAll("_", " ")}.
            Generation is unavailable.
          </p>
        )}

        <div className="modal-actions">
          <button
            className="button"
            type="button"
            disabled={submitting}
            onClick={onDismiss}
          >
            Cancel
          </button>
          <button
            className="button button-primary"
            type="button"
            disabled={submitting || preview.providerStatus !== "ready"}
            onClick={onGenerate}
          >
            {submitting ? "Queuing..." : "Generate visualization"}
          </button>
        </div>
      </div>
    </div>
  );
}

function DisclosureAsset({ asset }: { asset: TryOnAssetDescriptorView }) {
  return (
    <li>
      <strong>{asset.role === "portrait" ? "Portrait" : asset.label}</strong>
      <span>
        {asset.transmittedFilename}; {asset.mediaType}; {asset.byteLength} bytes;{" "}
        {asset.width} × {asset.height}
      </span>
      <span>
        Canonical SHA-256 <code>{asset.canonicalSha256}</code>
      </span>
      <span>
        Local {asset.role === "portrait" ? "source revision" : "item"}{" "}
        <code>{asset.localReferenceId}</code> (identifier not transmitted)
      </span>
    </li>
  );
}

function TryOnResult({ job }: { job: TryOnJobView }) {
  if (job.state === "queued" || job.state === "running") {
    return (
      <section className="try-on-result" aria-label="Try-on status">
        <h4>Visualization pending</h4>
        <p role="status">{job.statusMessage}</p>
        <p className="muted">You can leave this view while generation runs.</p>
      </section>
    );
  }

  if (job.state === "failed") {
    return (
      <section className="try-on-result" aria-label="Try-on status">
        <h4>Visualization failed</h4>
        <p role="alert">{failureMessage(job)}</p>
        <p className="muted">
          The saved outfit and deterministic collage above were not changed.
        </p>
      </section>
    );
  }

  return <CompletedTryOn job={job} />;
}

function CompletedTryOn({ job }: { job: TryOnJobView }) {
  const outputUrl = useImageUrl(job.output);
  return (
    <section className="try-on-result" aria-labelledby="try-on-result-title">
      <div>
        <h4 id="try-on-result-title">Generated visualization</h4>
        <p className="try-on-disclaimer">{AI_DISCLAIMER}</p>
        <p className="try-on-identifiers">
          Outfit ID <code>{job.outfitId}</code>
        </p>
      </div>

      <div className="try-on-result-layout">
        <figure className="try-on-generated" aria-label={AI_DISCLAIMER}>
          {outputUrl ? (
            <img
              src={outputUrl}
              alt={`Generated try-on visualization for outfit ${job.outfitId}`}
            />
          ) : (
            <div className="try-on-missing-output">Output unavailable</div>
          )}
          <figcaption>{AI_DISCLAIMER}</figcaption>
        </figure>

        <div className="try-on-source-column">
          <h5>Real source garments</h5>
          <ol className="try-on-source-garments">
            {[...job.garments]
              .sort((left, right) => left.ordinal - right.ordinal)
              .map((garment) => (
                <SourceGarment garment={garment} key={garment.itemId} />
              ))}
          </ol>
        </div>
      </div>
    </section>
  );
}

function SourceGarment({ garment }: { garment: TryOnJobView["garments"][number] }) {
  const imageUrl = useImageUrl(garment.image);
  return (
    <li>
      <div className="try-on-source-image">
        {imageUrl ? <img src={imageUrl} alt="" /> : <span>No image</span>}
      </div>
      <div>
        <strong>{garment.label}</strong>
        <span>
          Item ID <code>{garment.itemId}</code>
        </span>
      </div>
    </li>
  );
}

function useImageUrl(image: TryOnImageV1 | null): string | null {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!image || image.bytes.length === 0) {
      setUrl(null);
      return;
    }
    const nextUrl = URL.createObjectURL(
      new Blob([Uint8Array.from(image.bytes)], { type: image.mediaType }),
    );
    setUrl(nextUrl);
    return () => URL.revokeObjectURL(nextUrl);
  }, [image]);
  return url;
}

function focusableControls(root: HTMLElement | null): HTMLElement[] {
  if (!root) return [];
  return Array.from(
    root.querySelectorAll<HTMLElement>(
      'button:not([disabled]), select:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
    ),
  ).filter((element) => !element.hasAttribute("hidden"));
}

function failureMessage(job: TryOnJobView): string {
  const action =
    job.failureCode === "authentication"
      ? "Check the OpenAI credential in Settings."
      : job.failureCode === "moderation_blocked"
        ? "Choose a different portrait and prepare a new disclosure."
        : job.retryable
          ? "Prepare a new disclosure to try again."
          : "Review the local status before preparing another disclosure.";
  return `${job.statusMessage} ${action}`;
}
