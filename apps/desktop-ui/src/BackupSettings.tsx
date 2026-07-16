import { useCallback, useEffect, useRef, useState } from "react";

import {
  backupBridge,
  type BackupBridge,
  type BackupRecord,
} from "./backup-bridge";
import { formatError } from "./foundation-model";

type LoadState =
  | { status: "loading" }
  | { status: "ready"; backups: BackupRecord[] }
  | { status: "error"; message: string };

export function BackupSettings({
  bridge = backupBridge,
}: {
  bridge?: BackupBridge;
}) {
  const [state, setState] = useState<LoadState>({ status: "loading" });
  const [busy, setBusy] = useState<"create" | "restore" | null>(null);
  const [pendingRestore, setPendingRestore] = useState<BackupRecord | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const restoreTrigger = useRef<HTMLButtonElement | null>(null);

  const load = useCallback(async () => {
    try {
      setState({ status: "ready", backups: await bridge.list() });
    } catch (error) {
      setState({ status: "error", message: formatError(error) });
    }
  }, [bridge]);

  useEffect(() => {
    void load();
  }, [load]);

  const create = async () => {
    setBusy("create");
    setMessage(null);
    try {
      const backup = await bridge.create();
      setState((current) =>
        current.status === "ready"
          ? { status: "ready", backups: [backup, ...current.backups] }
          : { status: "ready", backups: [backup] },
      );
      setMessage("Backup created.");
    } catch (error) {
      setMessage(formatError(error));
    } finally {
      setBusy(null);
    }
  };

  const openRestore = (
    backup: BackupRecord,
    trigger: HTMLButtonElement,
  ) => {
    restoreTrigger.current = trigger;
    setMessage(null);
    setPendingRestore(backup);
  };

  const closeRestore = () => {
    setPendingRestore(null);
    requestAnimationFrame(() => restoreTrigger.current?.focus());
  };

  const restore = async () => {
    if (!pendingRestore) {
      return;
    }
    setBusy("restore");
    setMessage(null);
    try {
      await bridge.prepareRestore(pendingRestore);
      closeRestore();
      setMessage("Restore prepared. Restart Wardrobe to apply it.");
    } catch (error) {
      setMessage(formatError(error));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="settings-section" aria-labelledby="backups-title">
      <div className="settings-title-row">
        <div>
          <h3 id="backups-title">Backups</h3>
          <p className="settings-description">
            Private local snapshots of the catalog and its assets
          </p>
        </div>
        <button
          className="button"
          type="button"
          disabled={busy !== null}
          onClick={() => void create()}
        >
          {busy === "create" ? "Creating..." : "Create backup"}
        </button>
      </div>

      {state.status === "loading" && <p className="muted">Loading backups...</p>}
      {state.status === "error" && (
        <div className="inline-error" role="alert">
          <span>{state.message}</span>
          <button className="text-button" type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}
      {state.status === "ready" && state.backups.length === 0 && (
        <p className="muted">No backups yet.</p>
      )}
      {state.status === "ready" && state.backups.length > 0 && (
        <ul className="backup-list">
          {state.backups.map((backup) => (
            <li key={backup.id}>
              <div className="backup-summary">
                <strong>{reasonLabel(backup.reason)}</strong>
                <span>
                  {formatDate(backup.createdAt)} · {formatBytes(backup.totalBytes)}
                  {" · "}
                  {backup.assetCount} {backup.assetCount === 1 ? "asset" : "assets"}
                </span>
                <small>Expires {formatDate(backup.expiresAt)}</small>
              </div>
              <button
                className="button"
                type="button"
                disabled={busy !== null}
                onClick={(event) => openRestore(backup, event.currentTarget)}
              >
                Restore
              </button>
            </li>
          ))}
        </ul>
      )}

      {message && (
        <p className="action-message" role="status">
          {message}
        </p>
      )}

      {pendingRestore && (
        <RestoreConfirmation
          backup={pendingRestore}
          busy={busy === "restore"}
          onCancel={closeRestore}
          onConfirm={() => void restore()}
        />
      )}
    </section>
  );
}

function RestoreConfirmation({
  backup,
  busy,
  onCancel,
  onConfirm,
}: {
  backup: BackupRecord;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelButton = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    cancelButton.current?.focus();
  }, []);

  return (
    <div className="modal-backdrop">
      <section
        className="modal-panel restore-confirmation"
        role="dialog"
        aria-modal="true"
        aria-labelledby="restore-title"
        aria-describedby="restore-description"
      >
        <div className="modal-heading">
          <h2 id="restore-title">Restore this backup?</h2>
        </div>
        <p id="restore-description" className="modal-copy">
          Wardrobe will create a safety backup, then replace the current local
          catalog after you restart the app.
        </p>
        <dl className="restore-details">
          <div>
            <dt>Created</dt>
            <dd>{formatDate(backup.createdAt)}</dd>
          </div>
          <div>
            <dt>Assets</dt>
            <dd>{backup.assetCount}</dd>
          </div>
        </dl>
        <div className="modal-actions">
          <button
            ref={cancelButton}
            className="button"
            type="button"
            disabled={busy}
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            className="button button-danger"
            type="button"
            disabled={busy}
            onClick={onConfirm}
          >
            {busy ? "Preparing..." : "Prepare restore"}
          </button>
        </div>
      </section>
    </div>
  );
}

function reasonLabel(reason: BackupRecord["reason"]): string {
  switch (reason) {
    case "manual":
      return "Manual backup";
    case "scheduled":
      return "Scheduled backup";
    case "pre_upgrade":
      return "Before upgrade";
    case "pre_restore":
      return "Safety backup";
  }
  throw new Error("Unsupported backup reason");
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`;
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}
