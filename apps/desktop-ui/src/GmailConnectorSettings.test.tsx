import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  GetGmailConnectorV2Response,
  GmailConnectorSettingsV2,
} from "./generated/contracts";
import type { GmailConnectorBridge } from "./gmail-connector-bridge";
import { GmailConnectorSettings } from "./GmailConnectorSettings";

const settings: GmailConnectorSettingsV2 = {
  provider_profile: "google",
  oauth_client_id: "desktop.apps.googleusercontent.com",
  discovery_scope: {
    kind: "search",
    query: 'newer_than:3m "order confirmation"',
  },
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
          schema_version: 2 as const,
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
    expect(
      (
        screen.getByRole("textbox", {
          name: "Gmail query",
        }) as HTMLTextAreaElement
      ).value,
    ).toContain("newer_than:3m");
    expect(
      screen.getByRole("group", { name: "Receipt discovery" }),
    ).toHaveAccessibleDescription(/Search mode is read-only/i);
    expect(
      screen.getByText(/completely reconciles every result/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Previously imported messages stay in Wardrobe/i),
    ).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Sync bounds" })).toBeVisible();
    expect(screen.getByRole("spinbutton", { name: "Page size" })).toHaveAttribute(
      "max",
      "100",
    );
    expect(screen.getByRole("spinbutton", { name: "Max pages" })).toHaveAttribute(
      "max",
      "10",
    );
    expect(
      screen.getByRole("spinbutton", { name: "Max messages" }),
    ).toHaveAttribute("max", "200");
    expect(
      screen.getByRole("spinbutton", { name: "Max total raw bytes" }),
    ).toHaveValue(52_428_800);
    expect(screen.getByText("1-104857600 bytes total")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() => expect(bridge.saveSettings).toHaveBeenCalled());
    expect(bridge.saveSettings).toHaveBeenCalledWith(
      settings.oauth_client_id,
      expect.objectContaining({ kind: "search" }),
      expect.objectContaining({ max_unique_messages: 100 }),
    );
    expect(
      await screen.findByRole("button", { name: "Connect Gmail" }),
    ).toBeEnabled();
  });

  it("preserves exact search text through keyboard mode changes and save", async () => {
    const bridge = testBridge(
      () => connectorState("not_configured", null),
      {
        saveSettings: vi.fn(async (_clientId, discoveryScope, limits) => ({
          schema_version: 2 as const,
          request_id: "request",
          settings: {
            ...settings,
            discovery_scope: discoveryScope,
            limits,
          },
          status: "disconnected" as const,
          user_action: "connect_gmail" as const,
          replay_status: "created" as const,
        })),
      },
    );
    const user = userEvent.setup();
    render(<GmailConnectorSettings localOnly={false} bridge={bridge} />);

    await user.type(
      await screen.findByRole("textbox", { name: "OAuth client ID" }),
      settings.oauth_client_id,
    );
    const query = screen.getByRole("textbox", { name: "Gmail query" });
    await user.clear(query);
    const exactQuery = '  newer_than:3m subject:"Order ready"  ';
    await user.type(query, exactQuery);
    const searchMode = screen.getByRole("radio", { name: "Gmail search" });
    searchMode.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("radio", { name: "Existing label" })).toBeChecked();
    await user.keyboard("{ArrowLeft}");
    expect(screen.getByRole("radio", { name: "Gmail search" })).toBeChecked();
    expect(screen.getByRole("textbox", { name: "Gmail query" })).toHaveValue(
      exactQuery,
    );
    await user.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() =>
      expect(bridge.saveSettings).toHaveBeenLastCalledWith(
        settings.oauth_client_id,
        {
          kind: "search",
          query: exactQuery,
        },
        {
          page_size: 50,
          max_pages: 5,
          max_unique_messages: 100,
          max_total_raw_bytes: 52_428_800,
        },
      ),
    );
  });

  it("renders migrated label settings as the distinct label-history mode", async () => {
    const migratedSettings: GmailConnectorSettingsV2 = {
      ...settings,
      discovery_scope: {
        kind: "label",
        label_name: "Wardrobe Legacy Receipts",
      },
    };
    render(
      <GmailConnectorSettings
        localOnly={false}
        bridge={testBridge(() =>
          connectorState("disconnected", migratedSettings),
        )}
      />,
    );

    expect(
      await screen.findByRole("radio", { name: "Existing label" }),
    ).toBeChecked();
    expect(screen.getByRole("textbox", { name: "Gmail label" })).toHaveValue(
      "Wardrobe Legacy Receipts",
    );
    expect(
      screen.getByRole("group", { name: "Receipt discovery" }),
    ).toHaveAccessibleDescription(/migrated from earlier Wardrobe versions/i);
    expect(
      screen.getByText(/keeps label-history synchronization/i),
    ).toBeVisible();
    expect(
      screen.queryByRole("textbox", { name: "Gmail query" }),
    ).not.toBeInTheDocument();
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
  status: GetGmailConnectorV2Response["status"],
  value: GmailConnectorSettingsV2 | null,
): GetGmailConnectorV2Response {
  return {
    schema_version: 2,
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
  state: () => GetGmailConnectorV2Response,
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
