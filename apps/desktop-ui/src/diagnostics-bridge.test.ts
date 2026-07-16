import { describe, expect, it, vi } from "vitest";

import { createDiagnosticsBridge } from "./diagnostics-bridge";

describe("diagnostics bridge", () => {
  it("does not invoke the backend when the save panel is cancelled", async () => {
    const invoke = vi.fn();
    const bridge = createDiagnosticsBridge(
      invoke,
      async () => null,
      () => "11111111-1111-4111-8111-111111111111",
    );

    await expect(bridge.export()).resolves.toEqual({ cancelled: true });
    expect(invoke).not.toHaveBeenCalled();
  });

  it("sends the selected destination once and does not return it", async () => {
    const destination = "/tmp/private-name.json";
    const invoke = vi.fn().mockResolvedValue({
      schema_version: 1,
      request_id: "11111111-1111-4111-8111-111111111111",
      generated_at: "2026-07-15T18:00:00Z",
      complete: true,
      media_type: "application/json",
      sha256: "a".repeat(64),
      byte_length: 512,
    });
    const bridge = createDiagnosticsBridge(
      invoke,
      async () => destination,
      () => "11111111-1111-4111-8111-111111111111",
    );

    const result = await bridge.export();

    expect(invoke).toHaveBeenCalledWith("export_diagnostics_v1", {
      request: {
        schema_version: 1,
        request_id: "11111111-1111-4111-8111-111111111111",
        destination_path: destination,
      },
    });
    expect(JSON.stringify(result)).not.toContain(destination);
  });

  it("rejects an incomplete or mismatched backend response", async () => {
    const invoke = vi.fn().mockResolvedValue({
      schema_version: 1,
      request_id: "22222222-2222-4222-8222-222222222222",
      complete: false,
      media_type: "text/plain",
      generated_at: "2026-07-15T18:00:00Z",
      sha256: "not-a-hash",
      byte_length: 0,
    });
    const bridge = createDiagnosticsBridge(
      invoke,
      async () => "/tmp/report.json",
      () => "11111111-1111-4111-8111-111111111111",
    );

    await expect(bridge.export()).rejects.toThrow(
      "Diagnostics export returned an invalid response.",
    );
  });
});
