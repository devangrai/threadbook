import { useRef, useState } from "react";

import {
  diagnosticsBridge,
  type DiagnosticsBridge,
} from "./diagnostics-bridge";
import { formatError } from "./foundation-model";

export function DiagnosticsSettings({
  bridge = diagnosticsBridge,
}: {
  bridge?: DiagnosticsBridge;
}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const trigger = useRef<HTMLButtonElement>(null);

  const exportDiagnostics = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await bridge.export();
      if (result.cancelled) {
        setMessage("Export cancelled.");
      } else {
        setMessage(`Diagnostics exported (${formatBytes(result.byteLength)}).`);
      }
    } catch (error) {
      setMessage(formatError(error));
    } finally {
      setBusy(false);
      requestAnimationFrame(() => trigger.current?.focus());
    }
  };

  return (
    <section className="settings-section" aria-labelledby="diagnostics-title">
      <div className="settings-title-row">
        <div>
          <h3 id="diagnostics-title">Diagnostics</h3>
          <p className="settings-description">
            Redacted operational data saved locally under your control
          </p>
        </div>
        <button
          ref={trigger}
          className="button"
          type="button"
          disabled={busy}
          onClick={() => void exportDiagnostics()}
        >
          {busy ? "Exporting..." : "Export diagnostics"}
        </button>
      </div>
      {message && (
        <p className="action-message" role="status">
          {message}
        </p>
      )}
    </section>
  );
}

function formatBytes(value: number): string {
  if (value < 1024) {
    return `${value} B`;
  }
  return `${(value / 1024).toFixed(1)} KB`;
}
