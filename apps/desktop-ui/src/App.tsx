import { type FormEvent, useCallback, useEffect, useState } from "react";

import {
  foundationBridge,
  setLocalOnlyAndRefresh,
} from "./foundation-bridge";
import type { CredentialProviderV1 } from "./generated/contracts";
import { BackupSettings } from "./BackupSettings";
import { DiagnosticsSettings } from "./DiagnosticsSettings";
import { GmailConnectorSettings } from "./GmailConnectorSettings";
import { LocalOnlySettings } from "./LocalOnlySettings";
import { OutfitsWorkspace } from "./OutfitsWorkspace";
import {
  credentialStatusLabel,
  formatAction,
  formatError,
  formatJobKind,
  formatTimestamp,
  type FoundationSnapshot,
} from "./foundation-model";
import { P02Workspace } from "./P02Workspace";
import { PhotoAnalysisWorkspace } from "./PhotoAnalysisWorkspace";
import { PhotoKitConnectorSettings } from "./PhotoKitConnectorSettings";
import { ReceiptsWorkspace } from "./ReceiptsWorkspace";

type View =
  | "wardrobe"
  | "inbox"
  | "receipts"
  | "photos"
  | "outfits"
  | "activity"
  | "settings";
type LoadState =
  | { status: "loading" }
  | { status: "ready"; snapshot: FoundationSnapshot }
  | { status: "error"; message: string };

const views: ReadonlyArray<{ id: View; label: string }> = [
  { id: "wardrobe", label: "Wardrobe" },
  { id: "inbox", label: "Inbox" },
  { id: "receipts", label: "Receipts" },
  { id: "photos", label: "Photos" },
  { id: "outfits", label: "Outfits" },
  { id: "activity", label: "Activity" },
  { id: "settings", label: "Settings" },
];

function App() {
  const [view, setView] = useState<View>("wardrobe");
  const [state, setState] = useState<LoadState>({ status: "loading" });
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const snapshot = await foundationBridge.getSnapshot();
      setState({ status: "ready", snapshot });
    } catch (error) {
      setState({ status: "error", message: formatError(error) });
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const runStorageCheck = async () => {
    setBusyAction("storage-check");
    setActionMessage(null);
    try {
      const replayed = await foundationBridge.runStorageCheck();
      setActionMessage(
        replayed ? "Storage check already queued." : "Storage check queued.",
      );
      await refresh();
    } catch (error) {
      setActionMessage(formatError(error));
    } finally {
      setBusyAction(null);
    }
  };

  const saveCredential = async (
    provider: CredentialProviderV1,
    displayLabel: string,
    secret: string,
  ) => {
    setBusyAction("credential-save");
    setActionMessage(null);
    try {
      await foundationBridge.saveCredential(provider, displayLabel, secret);
      setActionMessage("Credential saved.");
      await refresh();
    } catch (error) {
      setActionMessage(formatError(error));
    } finally {
      setBusyAction(null);
    }
  };

  const removeCredential = async (credentialId: string) => {
    setBusyAction(`credential-remove:${credentialId}`);
    setActionMessage(null);
    try {
      await foundationBridge.deleteCredential(credentialId);
      setActionMessage("Credential removed.");
      await refresh();
    } catch (error) {
      setActionMessage(formatError(error));
    } finally {
      setBusyAction(null);
    }
  };

  const setLocalOnly = async (
    enabled: boolean,
    expectedRevision: number,
  ) => {
    await setLocalOnlyAndRefresh(
      foundationBridge,
      enabled,
      expectedRevision,
      (snapshot) => setState({ status: "ready", snapshot }),
    );
  };

  return (
    <main className="shell">
      <header className="topbar">
        <div className="identity">
          <img src="/app-icon.png" alt="" width="40" height="40" />
          <h1>Wardrobe</h1>
        </div>
        <div className="topbar-status">
          {state.status === "ready" &&
            state.snapshot.deletionHealth.status !== "none" && (
              <span className="deletion-health" role="status">
                Deletion {formatAction(state.snapshot.deletionHealth.status)}
              </span>
            )}
          {state.status === "ready" && (
            <span className="local-status">
              {state.snapshot.localOnly ? "Local only" : "Personal live"}
            </span>
          )}
        </div>
      </header>

      <nav className="tabs" aria-label="Workspace">
        {views.map(({ id, label }) => (
          <button
            className={view === id ? "tab tab-active" : "tab"}
            type="button"
            aria-current={view === id ? "page" : undefined}
            onClick={() => setView(id)}
            key={id}
          >
            {label}
          </button>
        ))}
      </nav>

      <div className="workspace" aria-live="polite">
        {state.status === "loading" && <LoadingView />}
        {state.status === "error" && (
          <ErrorView message={state.message} onRetry={() => void refresh()} />
        )}
        {state.status === "ready" && view === "wardrobe" && (
          <P02Workspace mode="catalog" onDeletionActivity={refresh} />
        )}
        {state.status === "ready" && view === "inbox" && (
          <P02Workspace mode="inbox" />
        )}
        {state.status === "ready" && view === "receipts" && (
          <ReceiptsWorkspace localOnly={state.snapshot.localOnly} />
        )}
        {state.status === "ready" && view === "photos" && (
          <PhotoAnalysisWorkspace />
        )}
        {state.status === "ready" && view === "outfits" && (
          <OutfitsWorkspace localOnly={state.snapshot.localOnly} />
        )}
        {state.status === "ready" && view === "activity" && (
          <ActivityView
            snapshot={state.snapshot}
            onOpenSettings={() => setView("settings")}
          />
        )}
        {state.status === "ready" && view === "settings" && (
          <SettingsView
            snapshot={state.snapshot}
            busyAction={busyAction}
            actionMessage={actionMessage}
            onRunStorageCheck={() => void runStorageCheck()}
            onSetLocalOnly={setLocalOnly}
            onSaveCredential={saveCredential}
            onRemoveCredential={(id) => void removeCredential(id)}
          />
        )}
      </div>
    </main>
  );
}

function LoadingView() {
  return (
    <section className="state-view" aria-label="Loading">
      <span className="spinner" aria-hidden="true" />
      <p>Opening local wardrobe...</p>
    </section>
  );
}

function ErrorView({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <section className="state-view" aria-labelledby="load-error-title">
      <h2 id="load-error-title">Could not open Wardrobe</h2>
      <p>{message}</p>
      <button className="button button-primary" type="button" onClick={onRetry}>
        Try again
      </button>
    </section>
  );
}

function ActivityView({
  snapshot,
  onOpenSettings,
}: {
  snapshot: FoundationSnapshot;
  onOpenSettings: () => void;
}) {
  return (
    <section aria-labelledby="activity-title">
      <div className="view-heading">
        <div>
          <h2 id="activity-title">Activity</h2>
          <p className="muted">Recent local jobs</p>
        </div>
      </div>
      {snapshot.recentJobs.length === 0 ? (
        <div className="empty-state compact">
          <p>No recent activity</p>
        </div>
      ) : (
        <ul className="activity-list">
          {snapshot.recentJobs.map((job) => (
            <li className="activity-row" key={job.id}>
              <span className={`job-mark job-${job.status}`} aria-hidden="true" />
              <div className="activity-copy">
                <div className="activity-summary">
                  <strong>{formatJobKind(job.kind)}</strong>
                  <span className={`job-status job-status-${job.status}`}>
                    {job.status}
                  </span>
                </div>
                <time dateTime={job.updatedAt}>
                  {formatTimestamp(job.updatedAt)}
                </time>
                {job.status === "failed" && (
                  <div className="failure-action">
                    <span>
                      {job.userAction
                        ? formatAction(job.userAction)
                        : "Needs attention"}
                    </span>
                    <button type="button" onClick={onOpenSettings}>
                      Open Settings
                    </button>
                  </div>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

type SettingsViewProps = {
  snapshot: FoundationSnapshot;
  busyAction: string | null;
  actionMessage: string | null;
  onRunStorageCheck: () => void;
  onSetLocalOnly: (
    enabled: boolean,
    expectedRevision: number,
  ) => Promise<void>;
  onSaveCredential: (
    provider: CredentialProviderV1,
    displayLabel: string,
    secret: string,
  ) => Promise<void>;
  onRemoveCredential: (credentialId: string) => void;
};

export function SettingsView({
  snapshot,
  busyAction,
  actionMessage,
  onRunStorageCheck,
  onSetLocalOnly,
  onSaveCredential,
  onRemoveCredential,
}: SettingsViewProps) {
  const submitCredential = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (snapshot.localOnly) return;
    const form = event.currentTarget;
    const values = new FormData(form);
    const provider: CredentialProviderV1 = "open_ai";
    const displayLabel = String(values.get("displayLabel") ?? "");
    const secret = String(values.get("secret") ?? "");

    await onSaveCredential(provider, displayLabel, secret);
    form.reset();
  };

  return (
    <section aria-labelledby="settings-title">
      <div className="view-heading">
        <div>
          <h2 id="settings-title">Settings</h2>
          <p className="muted">Local storage and credentials</p>
        </div>
      </div>

      <LocalOnlySettings
        localOnly={snapshot.localOnly}
        revision={snapshot.revision}
        authorityHealth={snapshot.authorityHealth}
        onSetLocalOnly={onSetLocalOnly}
      />

      <section className="settings-section" aria-labelledby="storage-title">
        <div className="settings-title-row">
          <h3 id="storage-title">Storage</h3>
          <button
            className="button"
            type="button"
            disabled={busyAction !== null}
            onClick={onRunStorageCheck}
          >
            {busyAction === "storage-check" ? "Checking..." : "Run storage check"}
          </button>
        </div>
        <dl className="status-list">
          <div>
            <dt>Database</dt>
            <dd>
              <ReadinessStatus value={snapshot.storage.database} />
            </dd>
          </div>
          <div>
            <dt>Blob storage</dt>
            <dd>
              <ReadinessStatus value={snapshot.storage.blobs} />
            </dd>
          </div>
        </dl>
      </section>

      <BackupSettings />

      <DiagnosticsSettings />

      <GmailConnectorSettings localOnly={snapshot.localOnly} />

      <PhotoKitConnectorSettings localOnly={snapshot.localOnly} />

      <section className="settings-section" aria-labelledby="credentials-title">
        <h3 id="credentials-title">OpenAI credential</h3>
        {snapshot.credentials.length > 0 && (
          <ul className="credential-list">
            {snapshot.credentials.map((credential) => (
              <li key={credential.id}>
                <div>
                  <strong>{credential.displayLabel}</strong>
                  <span>
                    {credential.provider} ·{" "}
                    {credentialStatusLabel(credential.status)}
                  </span>
                </div>
                <button
                  className="button button-danger"
                  type="button"
                  disabled={busyAction !== null}
                  onClick={() => onRemoveCredential(credential.id)}
                  aria-label={`Remove ${credential.displayLabel}`}
                >
                  {busyAction === `credential-remove:${credential.id}`
                    ? "Removing..."
                    : "Remove"}
                </button>
              </li>
            ))}
          </ul>
        )}
        <form
          className="credential-form"
          onSubmit={(event) => void submitCredential(event)}
        >
          <label>
            Label
            <input
              name="displayLabel"
              type="text"
              required
              minLength={1}
              maxLength={80}
              autoComplete="off"
              disabled={snapshot.localOnly || busyAction !== null}
            />
          </label>
          <label>
            Secret
            <input
              name="secret"
              type="password"
              required
              minLength={1}
              maxLength={4096}
              autoComplete="new-password"
              disabled={snapshot.localOnly || busyAction !== null}
            />
          </label>
          <button
            className="button button-primary form-submit"
            type="submit"
            disabled={snapshot.localOnly || busyAction !== null}
          >
            {busyAction === "credential-save" ? "Saving..." : "Save credential"}
          </button>
        </form>
        {snapshot.localOnly && (
          <p className="settings-description">
            Saving new OpenAI credentials is unavailable in local-only mode.
            Existing credentials can still be removed.
          </p>
        )}
      </section>

      {actionMessage && (
        <p className="action-message" role="status">
          {actionMessage}
        </p>
      )}
    </section>
  );
}

function ReadinessStatus({ value }: { value: "ready" | "unavailable" }) {
  return (
    <span className={`readiness-status readiness-${value}`}>
      <span aria-hidden="true" />
      {value === "ready" ? "Ready" : "Unavailable"}
    </span>
  );
}

export default App;
