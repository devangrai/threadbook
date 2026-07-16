import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  GetGmailConnectorV1Response,
  GmailConnectorSettingsV1,
} from "./generated/contracts";
import type { GmailConnectorBridge } from "./gmail-connector-bridge";
import { GmailConnectorSettings } from "./GmailConnectorSettings";

const settings: GmailConnectorSettingsV1 = {
  provider_profile: "google",
  oauth_client_id: "desktop.apps.googleusercontent.com",
  label_name: "Wardrobe Receipts",
  limits: {
    page_size: 50,
    max_pages: 5,
    max_unique_messages: 100,
    max_total_raw_bytes: 52_428_800,
  },
};

afterEach(cleanup);

describe("Gmail connector settings", () => {
  it("saves settings before enabling the explicit connect action", async () => {
    let state = connectorState("not_configured", null);
    const bridge = testBridge(() => state, {
      saveSettings: vi.fn(async () => {
        state = connectorState("disconnected", settings);
        return {
          schema_version: 1 as const,
          request_id: "request",
          settings,
          status: "disconnected" as const,
          user_action: "connect_gmail" as const,
          replay_status: "created" as const,
        };
      }),
    });
    const user = userEvent.setup();
    render(<GmailConnectorSettings localOnly={false} bridge={bridge} />);

    expect(
      await screen.findByText("Not configured", { selector: "span" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Connect Gmail" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: /secret/i })).toBeNull();

    await user.type(
      screen.getByRole("textbox", { name: "OAuth client ID" }),
      settings.oauth_client_id,
    );
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() => expect(bridge.saveSettings).toHaveBeenCalled());
    expect(
      await screen.findByRole("button", { name: "Connect Gmail" }),
    ).toBeEnabled();
  });

  it("connects, syncs, and disconnects while preserving a safe summary", async () => {
    let state = connectorState("disconnected", settings);
    const bridge = testBridge(() => state, {
      connect: vi.fn(async () => {
        state = connectorState("connected", settings);
        return syncResponse("connect");
      }),
      sync: vi.fn(async () => syncResponse("sync")),
      disconnect: vi.fn(async () => {
        state = connectorState("disconnected", settings);
        return {
          schema_version: 1 as const,
          request_id: "request",
          status: "disconnected" as const,
          user_action: "connect_gmail" as const,
          revocation_outcome: "failed" as const,
          replay_status: "created" as const,
        };
      }),
    });
    const user = userEvent.setup();
    render(<GmailConnectorSettings localOnly={false} bridge={bridge} />);

    await user.click(
      await screen.findByRole("button", { name: "Connect Gmail" }),
    );
    expect(await screen.findByText("Gmail connected.")).toBeInTheDocument();
    expect(screen.getByText(/2 imported, 1 updated, 0 unavailable/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sync now" })).toBeEnabled();

    await user.click(screen.getByRole("button", { name: "Sync now" }));
    expect(await screen.findByText("Gmail synced.")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Disconnect" }));
    expect(
      await screen.findByText(/Local credential removed/i),
    ).toBeInTheDocument();
    expect(bridge.disconnect).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("button", { name: "Connect Gmail" }),
    ).toBeEnabled();
  });

  it("denies outbound actions while keeping local disconnect reachable", async () => {
    let state = connectorState("connected", settings);
    const bridge = testBridge(() => state, {
      sync: vi.fn(async () => syncResponse("sync")),
      disconnect: vi.fn(async () => {
        state = connectorState("disconnected", settings);
        return {
          schema_version: 1 as const,
          request_id: "request",
          status: "disconnected" as const,
          user_action: "connect_gmail" as const,
          revocation_outcome: "failed" as const,
          replay_status: "created" as const,
        };
      }),
    });
    const user = userEvent.setup();
    render(<GmailConnectorSettings localOnly bridge={bridge} />);

    const sync = await screen.findByRole("button", { name: "Sync now" });
    const disconnect = screen.getByRole("button", { name: "Disconnect" });
    expect(sync).toBeDisabled();
    expect(disconnect).toBeEnabled();

    await user.click(sync);
    expect(bridge.sync).not.toHaveBeenCalled();
    await user.click(disconnect);
    await waitFor(() => expect(bridge.disconnect).toHaveBeenCalledOnce());
    expect(
      await screen.findByRole("button", { name: "Connect Gmail" }),
    ).toBeDisabled();
  });
});

function connectorState(
  status: GetGmailConnectorV1Response["status"],
  value: GmailConnectorSettingsV1 | null,
): GetGmailConnectorV1Response {
  return {
    schema_version: 1,
    request_id: "request",
    settings: value,
    status,
    user_action:
      status === "not_configured"
        ? "configure_gmail"
        : status === "connected"
          ? "none"
          : "connect_gmail",
  };
}

function syncResponse(command: "connect" | "sync") {
  return {
    schema_version: 1 as const,
    request_id: "request",
    status: "connected" as const,
    user_action: "none" as const,
    summary: {
      pages_scanned: 1,
      unique_messages: 3,
      messages_imported: 2,
      messages_updated: 1,
      messages_unavailable: 0,
      raw_bytes_read: 2048,
    },
    replay_status: "created" as const,
    command,
  };
}

function testBridge(
  state: () => GetGmailConnectorV1Response,
  overrides: Partial<GmailConnectorBridge> = {},
): GmailConnectorBridge {
  return {
    getState: vi.fn(async () => state()),
    saveSettings: vi.fn(),
    connect: vi.fn(),
    sync: vi.fn(),
    disconnect: vi.fn(),
    ...overrides,
  };
}
