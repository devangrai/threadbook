import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import { formatError } from "./foundation-model";
import type {
  GetGmailConnectorV2Response,
  GmailDiscoveryScopeV2,
  GmailConnectorLimitsV1,
  GmailSyncSummaryV1,
} from "./generated/contracts";
import {
  gmailConnectorBridge,
  type GmailConnectorBridge,
} from "./gmail-connector-bridge";

const defaultLimits: GmailConnectorLimitsV1 = {
  page_size: 50,
  max_pages: 5,
  max_unique_messages: 100,
  max_total_raw_bytes: 50 * 1024 * 1024,
};

type ConnectorState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; value: GetGmailConnectorV2Response };

const defaultReceiptQuery =
  'newer_than:3m -in:spam -in:trash {"order confirmation" "order confirmed" "thanks for your order" "we received your order" "purchase confirmation" "your order has shipped"}';

export function GmailConnectorSettings({
  localOnly,
  bridge = gmailConnectorBridge,
}: {
  localOnly: boolean;
  bridge?: GmailConnectorBridge;
}) {
  const [state, setState] = useState<ConnectorState>({ kind: "loading" });
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [summary, setSummary] = useState<GmailSyncSummaryV1 | null>(null);
  const [discoveryMode, setDiscoveryMode] = useState<"search" | "label">(
    "search",
  );
  const [query, setQuery] = useState(defaultReceiptQuery);
  const [labelName, setLabelName] = useState("Wardrobe Receipts");
  const resultRef = useRef<HTMLParagraphElement>(null);

  const load = useCallback(async () => {
    try {
      const value = await bridge.getState();
      const scope = value.settings?.discovery_scope;
      setDiscoveryMode(scope?.kind ?? "search");
      if (scope?.kind === "search") {
        setQuery(scope.query);
      } else if (!scope) {
        setQuery(defaultReceiptQuery);
      }
      if (scope?.kind === "label") {
        setLabelName(scope.label_name);
      } else if (!scope) {
        setLabelName("Wardrobe Receipts");
      }
      setState({ kind: "ready", value });
    } catch (error) {
      setState({ kind: "error", message: formatError(error) });
    }
  }, [bridge]);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (
    action: string,
    operation: () => Promise<{
      summary?: GmailSyncSummaryV1;
      revocation_outcome?:
        | "succeeded"
        | "already_invalid"
        | "failed"
        | "not_attempted_local_only";
    }>,
  ) => {
    if (localOnly && action !== "disconnect") return;
    setBusy(action);
    setMessage(null);
    setSummary(null);
    try {
      const response = await operation();
      if (response.summary) setSummary(response.summary);
      if (action === "disconnect") {
        setMessage(
          response.revocation_outcome === "not_attempted_local_only"
            ? "Gmail disconnected locally. Provider revocation was not attempted in local-only mode."
            : response.revocation_outcome === "failed"
            ? "Disconnected. Local credential removed; provider revocation was not confirmed."
            : "Gmail disconnected.",
        );
      } else {
        setMessage(action === "connect" ? "Gmail connected." : "Gmail synced.");
      }
      await load();
    } catch (error) {
      setMessage(formatError(error));
    } finally {
      setBusy(null);
      requestAnimationFrame(() => resultRef.current?.focus());
    }
  };

  if (state.kind === "loading") {
    return (
      <section className="settings-section" aria-labelledby="gmail-title">
        <h3 id="gmail-title">Gmail</h3>
        <p className="muted">Loading...</p>
      </section>
    );
  }

  if (state.kind === "error") {
    return (
      <section className="settings-section" aria-labelledby="gmail-title">
        <div className="settings-title-row">
          <h3 id="gmail-title">Gmail</h3>
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

  const connector = state.value;
  const editable =
    connector.status === "not_configured" ||
    connector.status === "disconnected";
  const connected = connector.status === "connected";

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (localOnly) return;
    const values = new FormData(event.currentTarget);
    const limits: GmailConnectorLimitsV1 = {
      page_size: Number(values.get("pageSize")),
      max_pages: Number(values.get("maxPages")),
      max_unique_messages: Number(values.get("maxMessages")),
      max_total_raw_bytes: Number(values.get("maxBytes")),
    };
    setBusy("save");
    setMessage(null);
    try {
      const discoveryScope: GmailDiscoveryScopeV2 =
        discoveryMode === "search"
          ? {
              kind: "search",
              query: String(values.get("query") ?? ""),
            }
          : {
              kind: "label",
              label_name: String(values.get("labelName") ?? "").trim(),
            };
      await bridge.saveSettings(
        String(values.get("clientId") ?? "").trim(),
        discoveryScope,
        limits,
      );
      setMessage("Gmail settings saved.");
      await load();
    } catch (error) {
      setMessage(formatError(error));
    } finally {
      setBusy(null);
      requestAnimationFrame(() => resultRef.current?.focus());
    }
  };

  return (
    <section className="settings-section" aria-labelledby="gmail-title">
      <div className="settings-title-row">
        <div>
          <h3 id="gmail-title">Gmail</h3>
          <span className={`connector-status connector-${connector.status}`}>
            {statusLabel(connector.status)}
          </span>
        </div>
        <div className="connector-actions">
          {connected && (
            <button
              className="button"
              type="button"
              disabled={busy !== null || localOnly}
              onClick={() => void run("sync", bridge.sync)}
            >
              {busy === "sync" ? "Syncing..." : "Sync now"}
            </button>
          )}
          {connector.status === "disconnected" && (
            <button
              className="button button-primary"
              type="button"
              disabled={busy !== null || localOnly}
              onClick={() => void run("connect", bridge.connect)}
            >
              {busy === "connect" ? "Connecting..." : "Connect Gmail"}
            </button>
          )}
          {connected && (
            <button
              className="button button-danger"
              type="button"
              disabled={busy !== null}
              onClick={() => void run("disconnect", bridge.disconnect)}
            >
              {busy === "disconnect" ? "Disconnecting..." : "Disconnect"}
            </button>
          )}
        </div>
      </div>

      <form className="gmail-settings-form" onSubmit={(event) => void save(event)}>
        <label className="gmail-client-id">
          OAuth client ID
          <input
            name="clientId"
            type="text"
            required
            maxLength={256}
            autoComplete="off"
            disabled={!editable || busy !== null || localOnly}
            defaultValue={connector.settings?.oauth_client_id ?? ""}
          />
        </label>
        <fieldset
          className="gmail-discovery-mode"
          aria-describedby={
            discoveryMode === "search"
              ? "gmail-search-disclosure"
              : "gmail-label-disclosure"
          }
        >
          <legend>Receipt discovery</legend>
          <label>
            <input
              name="discoveryMode"
              type="radio"
              value="search"
              checked={discoveryMode === "search"}
              onChange={() => setDiscoveryMode("search")}
              disabled={!editable || busy !== null || localOnly}
            />
            Gmail search
          </label>
          <label>
            <input
              name="discoveryMode"
              type="radio"
              value="label"
              checked={discoveryMode === "label"}
              onChange={() => setDiscoveryMode("label")}
              disabled={!editable || busy !== null || localOnly}
            />
            Existing label
          </label>
        </fieldset>
        {discoveryMode === "search" ? (
          <label className="gmail-query">
            Gmail query
            <textarea
              name="query"
              required
              maxLength={2048}
              autoComplete="off"
              disabled={!editable || busy !== null || localOnly}
              aria-label="Gmail query"
              aria-describedby="gmail-query-hint gmail-search-disclosure"
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
            />
            <span id="gmail-query-hint" className="gmail-field-hint">
              Run exactly as entered; whitespace is preserved.
            </span>
          </label>
        ) : (
          <label className="gmail-query">
            Gmail label
            <input
              name="labelName"
              type="text"
              required
              maxLength={80}
              autoComplete="off"
              disabled={!editable || busy !== null || localOnly}
              aria-label="Gmail label"
              aria-describedby="gmail-label-disclosure"
              value={labelName}
              onChange={(event) => setLabelName(event.currentTarget.value)}
            />
          </label>
        )}
        {discoveryMode === "search" ? (
          <p
            id="gmail-search-disclosure"
            className="muted gmail-discovery-note"
          >
            Search mode is read-only. Each sync runs the exact query shown
            above and completely reconciles every result within the four
            configured bounds below. Previously imported messages stay in
            Wardrobe if they no longer match. Wardrobe never changes Gmail
            messages, labels, or mailbox content.
          </p>
        ) : (
          <p
            id="gmail-label-disclosure"
            className="muted gmail-discovery-note"
          >
            Label mode includes settings migrated from earlier Wardrobe
            versions. It keeps label-history synchronization with read-only
            Gmail access. Wardrobe never creates or changes Gmail labels,
            messages, or mailbox content.
          </p>
        )}
        <fieldset className="gmail-sync-limits">
          <legend>Sync bounds</legend>
          <div className="gmail-limit-grid">
            <label>
              Page size
              <input
                name="pageSize"
                type="number"
                min={1}
                max={100}
                step={1}
                required
                disabled={!editable || busy !== null || localOnly}
                aria-label="Page size"
                aria-describedby="gmail-page-size-hint"
                defaultValue={
                  connector.settings?.limits.page_size ??
                  defaultLimits.page_size
                }
              />
              <span id="gmail-page-size-hint" className="gmail-field-hint">
                1-100 messages per page
              </span>
            </label>
            <label>
              Max pages
              <input
                name="maxPages"
                type="number"
                min={1}
                max={10}
                step={1}
                required
                disabled={!editable || busy !== null || localOnly}
                aria-label="Max pages"
                aria-describedby="gmail-max-pages-hint"
                defaultValue={
                  connector.settings?.limits.max_pages ??
                  defaultLimits.max_pages
                }
              />
              <span id="gmail-max-pages-hint" className="gmail-field-hint">
                1-10 pages
              </span>
            </label>
            <label>
              Max messages
              <input
                name="maxMessages"
                type="number"
                min={1}
                max={200}
                step={1}
                required
                disabled={!editable || busy !== null || localOnly}
                aria-label="Max messages"
                aria-describedby="gmail-max-messages-hint"
                defaultValue={
                  connector.settings?.limits.max_unique_messages ??
                  defaultLimits.max_unique_messages
                }
              />
              <span id="gmail-max-messages-hint" className="gmail-field-hint">
                1-200 unique messages
              </span>
            </label>
            <label>
              Max total raw bytes
              <input
                name="maxBytes"
                type="number"
                min={1}
                max={100 * 1024 * 1024}
                step={1}
                required
                disabled={!editable || busy !== null || localOnly}
                aria-label="Max total raw bytes"
                aria-describedby="gmail-max-bytes-hint"
                defaultValue={
                  connector.settings?.limits.max_total_raw_bytes ??
                  defaultLimits.max_total_raw_bytes
                }
              />
              <span id="gmail-max-bytes-hint" className="gmail-field-hint">
                1-104857600 bytes total
              </span>
            </label>
          </div>
        </fieldset>
        {editable && (
          <button
            className="button form-submit"
            type="submit"
            disabled={busy !== null || localOnly}
          >
            {busy === "save" ? "Saving..." : "Save settings"}
          </button>
        )}
      </form>

      {localOnly && (
        <p className="settings-description">
          Gmail setup and synchronization are unavailable. Disconnect remains
          available for local cleanup; Google revocation will not be attempted.
        </p>
      )}

      <p
        className="action-message"
        role="status"
        tabIndex={-1}
        ref={resultRef}
      >
        {message}
        {summary && (
          <span className="connector-summary">
            {` ${summary.messages_imported} imported, ${summary.messages_updated} updated, ${summary.messages_unavailable} unavailable.`}
          </span>
        )}
      </p>
    </section>
  );
}

function statusLabel(
  status: GetGmailConnectorV2Response["status"],
): string {
  switch (status) {
    case "not_configured":
      return "Not configured";
    case "disconnected":
      return "Disconnected";
    case "connecting":
      return "Connecting";
    case "connected":
      return "Connected";
    case "syncing":
      return "Syncing";
    case "disconnecting":
      return "Disconnecting";
    case "needs_attention":
      return "Needs attention";
  }
}
