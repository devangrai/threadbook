import { describe, expect, it, vi } from "vitest";

import { createGmailConnectorBridge } from "./gmail-connector-bridge";

const requestId = "a5b238c1-df7e-4ec8-8330-abe67f7ad536";
const limits = {
  page_size: 50,
  max_pages: 5,
  max_unique_messages: 100,
  max_total_raw_bytes: 52_428_800,
};

describe("Gmail connector bridge", () => {
  it("uses only the five typed production commands", async () => {
    const invoke = vi.fn(
      async <T>(
        _command: string,
        _args?: Record<string, unknown>,
      ): Promise<T> => ({}) as T,
    );
    const bridge = createGmailConnectorBridge(
      invoke as unknown as Parameters<typeof createGmailConnectorBridge>[0],
      () => requestId,
    );
    await bridge.getState();
    await bridge.saveSettings(
      "desktop.apps.googleusercontent.com",
      { kind: "label", label_name: "Wardrobe Receipts" },
      limits,
    );
    await bridge.connect();
    await bridge.sync();
    await bridge.disconnect();

    expect(invoke.mock.calls.map(([command]) => command)).toEqual([
      "get_gmail_connector_v2",
      "save_gmail_settings_v2",
      "connect_gmail_v1",
      "sync_gmail_v1",
      "disconnect_gmail_v1",
    ]);
    expect(invoke).toHaveBeenNthCalledWith(2, "save_gmail_settings_v2", {
      request: {
        schema_version: 2,
        request_id: requestId,
        client_id: "desktop.apps.googleusercontent.com",
        discovery_scope: {
          kind: "label",
          label_name: "Wardrobe Receipts",
        },
        limits,
      },
    });
    for (const [index, [, args]] of invoke.mock.calls.entries()) {
      expect(args).toEqual(
        expect.objectContaining({
          request: expect.objectContaining({
            schema_version: index < 2 ? 2 : 1,
            request_id: requestId,
          }),
        }),
      );
      expect(JSON.stringify(args)).not.toMatch(/refresh|access_token|secret/i);
    }
  });

  it("sends exact search query bytes without UI normalization", async () => {
    const invoke = vi.fn(async () => ({}));
    const bridge = createGmailConnectorBridge(
      invoke as unknown as Parameters<typeof createGmailConnectorBridge>[0],
      () => requestId,
    );
    const query = '  newer_than:3m subject:"Order ready"  ';

    await bridge.saveSettings(
      "desktop.apps.googleusercontent.com",
      { kind: "search", query },
      limits,
    );

    expect(invoke).toHaveBeenCalledWith("save_gmail_settings_v2", {
      request: {
        schema_version: 2,
        request_id: requestId,
        client_id: "desktop.apps.googleusercontent.com",
        discovery_scope: { kind: "search", query },
        limits,
      },
    });
  });
});
