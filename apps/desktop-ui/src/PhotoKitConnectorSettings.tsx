import {
  type FormEvent,
  type KeyboardEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import { formatError, formatTimestamp } from "./foundation-model";
import type {
  PhotoKitAlbumCandidateV1,
  PhotoKitAuthorizationV1,
  PhotoKitConnectorSnapshotV1,
  PhotoKitConnectorStateV1,
  PhotoKitSetupSessionIdV1,
} from "./generated/contracts";
import {
  photoKitConnectorBridge,
  type PhotoKitConnectorBridge,
} from "./photokit-connector-bridge";

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; snapshot: PhotoKitConnectorSnapshotV1 };

type SetupState = {
  sessionId: PhotoKitSetupSessionIdV1;
  albums: PhotoKitAlbumCandidateV1[];
};

type BusyAction = "connect" | "configure" | "sync" | "disable";
type Announcement = {
  kind: "success" | "failure";
  message: string;
};

export function PhotoKitConnectorSettings({
  localOnly,
  bridge = photoKitConnectorBridge,
}: {
  localOnly: boolean;
  bridge?: PhotoKitConnectorBridge;
}) {
  const [state, setState] = useState<LoadState>({ kind: "loading" });
  const [setup, setSetup] = useState<SetupState | null>(null);
  const [selectedAlbum, setSelectedAlbum] = useState("");
  const [allowIcloudDownloads, setAllowIcloudDownloads] = useState(false);
  const [busy, setBusy] = useState<BusyAction | null>(null);
  const [announcement, setAnnouncement] = useState<Announcement | null>(null);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const connectButton = useRef<HTMLButtonElement>(null);
  const albumSelect = useRef<HTMLSelectElement>(null);
  const disableButton = useRef<HTMLButtonElement>(null);
  const liveRegion = useRef<HTMLParagraphElement>(null);

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const response = await bridge.getState();
      setState({ kind: "ready", snapshot: response.snapshot });
    } catch (error) {
      setState({ kind: "error", message: formatError(error) });
    }
  }, [bridge]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (setup) {
      albumSelect.current?.focus();
    }
  }, [setup]);

  useEffect(() => {
    if (localOnly) {
      setSetup(null);
      setSelectedAlbum("");
      setAllowIcloudDownloads(false);
    }
  }, [localOnly]);

  const focusLiveRegion = () => {
    requestAnimationFrame(() => liveRegion.current?.focus());
  };

  const beginSetup = async () => {
    if (localOnly) return;
    setBusy("connect");
    setAnnouncement(null);
    setSelectedAlbum("");
    setAllowIcloudDownloads(false);
    try {
      const response = await bridge.beginSetup();
      setState({ kind: "ready", snapshot: response.snapshot });
      if (
        response.setup_session_id !== null &&
        response.album_candidates.length > 0
      ) {
        setSetup({
          sessionId: response.setup_session_id,
          albums: response.album_candidates.map(
            ({ selection_token, display_label }) => ({
              selection_token,
              display_label,
            }),
          ),
        });
        setAnnouncement({
          kind: "success",
          message: "Choose an Apple Photos album.",
        });
      } else {
        setSetup(null);
        setAnnouncement({
          kind: "failure",
          message:
            response.snapshot.authorization === "authorized"
              ? "No regular Apple Photos albums are available."
              : `Apple Photos authorization is ${authorizationLabel(
                  response.snapshot.authorization,
                ).toLowerCase()}.`,
        });
        focusLiveRegion();
      }
    } catch (error) {
      setSetup(null);
      setAnnouncement({ kind: "failure", message: formatError(error) });
      focusLiveRegion();
    } finally {
      setBusy(null);
    }
  };

  const cancelSetup = () => {
    setSetup(null);
    setSelectedAlbum("");
    setAllowIcloudDownloads(false);
    setAnnouncement({
      kind: "success",
      message: "Apple Photos setup cancelled.",
    });
    requestAnimationFrame(() => connectButton.current?.focus());
  };

  const configure = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!setup || localOnly) return;

    const selectedIndex = Number(selectedAlbum);
    const album = setup.albums[selectedIndex];
    if (!Number.isInteger(selectedIndex) || !album) return;

    setBusy("configure");
    setAnnouncement(null);
    try {
      const response = await bridge.configureScope(
        setup.sessionId,
        album.selection_token,
        allowIcloudDownloads,
      );
      setState({ kind: "ready", snapshot: response.snapshot });
      setSetup(null);
      setSelectedAlbum("");
      setAllowIcloudDownloads(false);
      setAnnouncement({
        kind: "success",
        message: "Apple Photos connected.",
      });
    } catch (error) {
      // Setup tokens are one-use, so a failed terminal attempt starts over.
      setSetup(null);
      setSelectedAlbum("");
      setAllowIcloudDownloads(false);
      setAnnouncement({ kind: "failure", message: formatError(error) });
    } finally {
      setBusy(null);
      focusLiveRegion();
    }
  };

  const sync = async () => {
    if (localOnly) return;
    setBusy("sync");
    setAnnouncement(null);
    try {
      const response = await bridge.sync();
      setState({ kind: "ready", snapshot: response.snapshot });
      setAnnouncement({
        kind: "success",
        message: `Apple Photos synced. ${formatCounts(response.snapshot)}.`,
      });
    } catch (error) {
      setAnnouncement({ kind: "failure", message: formatError(error) });
    } finally {
      setBusy(null);
      focusLiveRegion();
    }
  };

  const disable = async () => {
    if (state.kind !== "ready") return;
    const current = state.snapshot;

    setBusy("disable");
    setAnnouncement(null);
    try {
      const response = await bridge.disable(current.photokit_revision);
      setState({
        kind: "ready",
        snapshot: {
          ...current,
          state: response.state,
          enrollment_epoch: null,
          membership_generation: response.preserved_membership_generation,
          photokit_revision: response.photokit_revision,
          allow_icloud_downloads: false,
          counts: response.preserved_counts,
        },
      });
      setConfirmDisable(false);
      setAnnouncement({
        kind: "success",
        message:
          "Apple Photos disabled. Existing wardrobe data was preserved.",
      });
    } catch (error) {
      setConfirmDisable(false);
      setAnnouncement({ kind: "failure", message: formatError(error) });
    } finally {
      setBusy(null);
      focusLiveRegion();
    }
  };

  if (state.kind === "loading") {
    return (
      <section
        className="settings-section photokit-settings"
        aria-labelledby="photokit-title"
      >
        <h3 id="photokit-title">Apple Photos</h3>
        <p className="muted" role="status" aria-live="polite">
          Loading Apple Photos status...
        </p>
      </section>
    );
  }

  if (state.kind === "error") {
    return (
      <section
        className="settings-section photokit-settings"
        aria-labelledby="photokit-title"
      >
        <div className="settings-title-row">
          <h3 id="photokit-title">Apple Photos</h3>
          <button className="button" type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
        <p className="action-message" role="alert">
          {state.message}
        </p>
      </section>
    );
  }

  const snapshot = state.snapshot;
  const configured =
    snapshot.state !== "unconfigured" &&
    snapshot.state !== "setup_required";
  const externallyBusy = snapshot.state === "reconciling";
  const controlsDisabled = busy !== null || externallyBusy;
  const liveMessage = busy ? busyLabel(busy) : announcement?.message;

  return (
    <section
      className="settings-section photokit-settings"
      aria-labelledby="photokit-title"
    >
      <div className="settings-title-row">
        <div>
          <h3 id="photokit-title">Apple Photos</h3>
          <span
            className={`connector-status connector-${snapshot.state}`}
            aria-label={`Status: ${stateLabel(snapshot.state)}`}
          >
            {stateLabel(snapshot.state)}
          </span>
        </div>
        <div className="connector-actions">
          {!configured && !setup && (
            <button
              ref={connectButton}
              className="button button-primary"
              type="button"
              disabled={busy !== null || localOnly}
              onClick={() => void beginSetup()}
            >
              {busy === "connect" ? "Connecting..." : "Connect"}
            </button>
          )}
          {configured && (
            <>
              <button
                className="button"
                type="button"
                disabled={controlsDisabled || localOnly}
                onClick={() => void sync()}
              >
                {busy === "sync" || externallyBusy
                  ? "Syncing..."
                  : "Sync now"}
              </button>
              <button
                ref={disableButton}
                className="button button-danger"
                type="button"
                disabled={controlsDisabled}
                onClick={() => setConfirmDisable(true)}
              >
                Disable
              </button>
            </>
          )}
        </div>
      </div>

      <dl className="photokit-status-grid">
        <div>
          <dt>Authorization</dt>
          <dd>{authorizationLabel(snapshot.authorization)}</dd>
        </div>
        <div>
          <dt>iCloud downloads</dt>
          <dd>{snapshot.allow_icloud_downloads ? "Allowed" : "Off"}</dd>
        </div>
        <div>
          <dt>Last complete</dt>
          <dd>
            {snapshot.last_complete_at
              ? formatTimestamp(snapshot.last_complete_at)
              : "Not completed"}
          </dd>
        </div>
        <div>
          <dt>Available</dt>
          <dd>{snapshot.counts.available}</dd>
        </div>
        <div>
          <dt>Unavailable</dt>
          <dd>{snapshot.counts.unavailable}</dd>
        </div>
      </dl>

      {setup && (
        <form
          className="photokit-setup-form"
          onSubmit={(event) => void configure(event)}
          onKeyDown={(event) => handleSetupKeyDown(event, cancelSetup)}
        >
          <label htmlFor="photokit-album">Album</label>
          <select
            ref={albumSelect}
            id="photokit-album"
            value={selectedAlbum}
            required
            disabled={busy !== null || localOnly}
            onChange={(event) => setSelectedAlbum(event.currentTarget.value)}
          >
            <option value="">Choose an album</option>
            {setup.albums.map((album, index) => (
              <option value={String(index)} key={index}>
                {album.display_label}
              </option>
            ))}
          </select>
          <label className="photokit-consent">
            <input
              type="checkbox"
              checked={allowIcloudDownloads}
              disabled={busy !== null || localOnly}
              onChange={(event) =>
                setAllowIcloudDownloads(event.currentTarget.checked)
              }
            />
            Allow downloads of originals stored in iCloud
          </label>
          <div className="connector-actions photokit-setup-actions">
            <button
              className="button"
              type="button"
              disabled={busy !== null}
              onClick={cancelSetup}
            >
              Cancel
            </button>
            <button
              className="button button-primary"
              type="submit"
              disabled={busy !== null || selectedAlbum === "" || localOnly}
            >
              {busy === "configure" ? "Configuring..." : "Configure"}
            </button>
          </div>
        </form>
      )}

      {localOnly && (
        <p className="settings-description">
          Apple Photos setup and synchronization are unavailable. Disable
          remains available to remove local enrollment.
        </p>
      )}

      {liveMessage && (
        <p
          ref={liveRegion}
          className="action-message"
          role={announcement?.kind === "failure" && !busy ? "alert" : "status"}
          aria-live={
            announcement?.kind === "failure" && !busy
              ? "assertive"
              : "polite"
          }
          aria-atomic="true"
          tabIndex={-1}
        >
          {liveMessage}
        </p>
      )}

      {confirmDisable && (
        <DisableConfirmation
          busy={busy === "disable"}
          onCancel={() => {
            setConfirmDisable(false);
            requestAnimationFrame(() => disableButton.current?.focus());
          }}
          onConfirm={() => void disable()}
        />
      )}
    </section>
  );
}

function DisableConfirmation({
  busy,
  onCancel,
  onConfirm,
}: {
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
        className="modal-panel photokit-disable-confirmation"
        role="dialog"
        aria-modal="true"
        aria-labelledby="photokit-disable-title"
        aria-describedby="photokit-disable-description"
        onKeyDown={(event) => {
          if (event.key === "Escape" && !busy) {
            event.preventDefault();
            onCancel();
          }
        }}
      >
        <div className="modal-heading">
          <h2 id="photokit-disable-title">Disable Apple Photos?</h2>
        </div>
        <p id="photokit-disable-description" className="modal-copy">
          Future synchronization will stop. Existing wardrobe data will be
          preserved.
        </p>
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
            {busy ? "Disabling..." : "Disable"}
          </button>
        </div>
      </section>
    </div>
  );
}

function handleSetupKeyDown(
  event: KeyboardEvent<HTMLFormElement>,
  cancel: () => void,
) {
  if (event.key === "Escape") {
    event.preventDefault();
    cancel();
  }
}

function stateLabel(state: PhotoKitConnectorStateV1): string {
  switch (state) {
    case "unconfigured":
      return "Not connected";
    case "setup_required":
      return "Setup required";
    case "ready":
      return "Connected";
    case "reconciling":
      return "Syncing";
    case "needs_attention":
      return "Needs attention";
  }
}

function authorizationLabel(value: PhotoKitAuthorizationV1): string {
  switch (value) {
    case "not_determined":
      return "Not requested";
    case "restricted":
      return "Restricted";
    case "denied":
      return "Denied";
    case "limited":
      return "Limited";
    case "authorized":
      return "Authorized";
  }
}

function busyLabel(action: BusyAction): string {
  switch (action) {
    case "connect":
      return "Opening Apple Photos setup...";
    case "configure":
      return "Configuring Apple Photos...";
    case "sync":
      return "Syncing Apple Photos...";
    case "disable":
      return "Disabling Apple Photos...";
  }
}

function formatCounts(snapshot: PhotoKitConnectorSnapshotV1): string {
  return `${snapshot.counts.available} available, ${snapshot.counts.unavailable} unavailable`;
}
