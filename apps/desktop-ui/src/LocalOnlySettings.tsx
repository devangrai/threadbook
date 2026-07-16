import { useEffect, useRef, useState } from "react";

import type { LocalOnlyAuthorityHealthV1 } from "./generated/contracts";
import {
  authorityHealthLabel,
  formatError,
} from "./foundation-model";

type LocalOnlySettingsProps = {
  localOnly: boolean;
  revision: number;
  authorityHealth: LocalOnlyAuthorityHealthV1;
  onSetLocalOnly: (enabled: boolean, expectedRevision: number) => Promise<void>;
};

export function LocalOnlySettings({
  localOnly,
  revision,
  authorityHealth,
  onSetLocalOnly,
}: LocalOnlySettingsProps) {
  const [busy, setBusy] = useState(false);
  const [confirmPersonalLive, setConfirmPersonalLive] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const switchRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!localOnly) {
      setConfirmPersonalLive(false);
    }
  }, [localOnly]);

  const restoreSwitchFocus = () => {
    requestAnimationFrame(() => switchRef.current?.focus());
  };

  const applyMode = async (enabled: boolean) => {
    if (busy) return;
    setBusy(true);
    setMessage(null);
    try {
      await onSetLocalOnly(enabled, revision);
      setMessage(
        enabled
          ? "Local-only mode enabled."
          : "Personal-live mode enabled.",
      );
    } catch (error) {
      setMessage(formatError(error));
    } finally {
      setBusy(false);
      setConfirmPersonalLive(false);
      restoreSwitchFocus();
    }
  };

  const toggle = () => {
    if (busy) return;
    if (localOnly) {
      setConfirmPersonalLive(true);
      return;
    }
    void applyMode(true);
  };

  return (
    <section
      className="settings-section local-only-settings"
      aria-labelledby="local-only-title"
    >
      <div className="settings-title-row local-only-row">
        <div>
          <h3 id="local-only-title">Network mode</h3>
          <p className="settings-description">
            {localOnly
              ? "Outbound connectors and OpenAI actions are blocked."
              : "Approved personal connectors and OpenAI actions are available."}
          </p>
        </div>
        <button
          ref={switchRef}
          className="mode-switch"
          type="button"
          role="switch"
          aria-checked={localOnly}
          aria-describedby="local-only-health"
          disabled={busy}
          onClick={toggle}
        >
          <span className="mode-switch-track" aria-hidden="true">
            <span />
          </span>
          <span>{localOnly ? "Local only" : "Personal live"}</span>
        </button>
      </div>

      <p id="local-only-health" className="authority-health">
        Authority: {authorityHealthLabel(authorityHealth)} · Revision {revision}
      </p>

      <p
        className="local-only-announcement"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        {busy ? "Updating network mode..." : message}
      </p>

      {confirmPersonalLive && (
        <PersonalLiveConfirmation
          busy={busy}
          onCancel={() => {
            setConfirmPersonalLive(false);
            restoreSwitchFocus();
          }}
          onConfirm={() => void applyMode(false)}
        />
      )}
    </section>
  );
}

function PersonalLiveConfirmation({
  busy,
  onCancel,
  onConfirm,
}: {
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    cancelRef.current?.focus();
  }, []);

  return (
    <div className="modal-backdrop">
      <section
        className="modal-panel local-only-confirmation"
        role="dialog"
        aria-modal="true"
        aria-labelledby="personal-live-title"
        aria-describedby="personal-live-description"
        onKeyDown={(event) => {
          if (event.key === "Escape" && !busy) {
            event.preventDefault();
            onCancel();
          }
        }}
      >
        <div className="modal-heading">
          <h2 id="personal-live-title">Enable personal live?</h2>
        </div>
        <p id="personal-live-description" className="modal-copy">
          Gmail, OpenAI, receipt-image downloads, and cloud-backed Apple Photos
          actions can contact their named providers. Changing this setting does
          not send data by itself.
        </p>
        <div className="modal-actions">
          <button
            ref={cancelRef}
            className="button"
            type="button"
            disabled={busy}
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            className="button button-primary"
            type="button"
            disabled={busy}
            onClick={onConfirm}
          >
            {busy ? "Enabling..." : "Enable personal live"}
          </button>
        </div>
      </section>
    </div>
  );
}
