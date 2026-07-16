import { describe, expect, it, vi } from "vitest";

import { createPhotoKitConnectorBridge } from "./photokit-connector-bridge";

const requestId = "a5b238c1-df7e-4ec8-8330-abe67f7ad536";

describe("PhotoKit connector bridge", () => {
  it("uses the five typed commands and sends consent and revision authority", async () => {
    const invoke = vi.fn(
      async <T>(
        _command: string,
        _args?: Record<string, unknown>,
      ): Promise<T> => ({}) as T,
    );
    const bridge = createPhotoKitConnectorBridge(
      invoke as unknown as Parameters<
        typeof createPhotoKitConnectorBridge
      >[0],
      () => requestId,
    );

    await bridge.getState();
    await bridge.beginSetup();
    await bridge.configureScope("setup-session", "selection-token", false);
    await bridge.sync();
    await bridge.disable(9);

    expect(invoke.mock.calls.map(([command]) => command)).toEqual([
      "get_photokit_connector_v1",
      "begin_photokit_setup_v1",
      "configure_photokit_scope_v1",
      "sync_photokit_v1",
      "disable_photokit_v1",
    ]);
    expect(invoke).toHaveBeenNthCalledWith(
      3,
      "configure_photokit_scope_v1",
      {
        request: {
          schema_version: 1,
          request_id: requestId,
          setup_session_id: "setup-session",
          selection_token: "selection-token",
          allow_icloud_downloads: false,
        },
      },
    );
    expect(invoke).toHaveBeenNthCalledWith(5, "disable_photokit_v1", {
      request: {
        schema_version: 1,
        request_id: requestId,
        expected_photokit_revision: 9,
      },
    });
  });

  it("never sends native identifiers, filenames, or paths", async () => {
    const invoke = vi.fn(
      async <T>(
        _command: string,
        _args?: Record<string, unknown>,
      ): Promise<T> => ({}) as T,
    );
    const bridge = createPhotoKitConnectorBridge(
      invoke as unknown as Parameters<
        typeof createPhotoKitConnectorBridge
      >[0],
      () => requestId,
    );

    await bridge.configureScope("setup-session", "opaque-token", true);
    await bridge.sync();

    const requests = invoke.mock.calls.map(([, args]) => args);
    expect(JSON.stringify(requests)).not.toMatch(
      /local_identifier|filename|file_name|\/Users\/|\/private\//i,
    );
  });
});
