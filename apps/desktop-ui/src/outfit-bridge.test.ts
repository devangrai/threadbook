import { describe, expect, it, vi } from "vitest";

import type { InvokeCommand } from "./invoke-transport";
import { createOutfitBridge } from "./outfit-bridge";

describe("outfit bridge", () => {
  it("sends bounded revisioned commands without provider data", async () => {
    const invoke = vi.fn(async (command: string, payload: unknown) => ({
      command,
      payload,
      outfits: [],
      total_count: 0,
      outfit_revision: 0,
      next_cursor: null,
    }));
    const bridge = createOutfitBridge(invoke as InvokeCommand, () => "request-1");

    await bridge.createManualOutfit(" Date ", ["item-1", "item-2"], 4, 2);
    await bridge.listOutfits(null, 20);
    await bridge.getCollage("outfit-1");

    expect(invoke).toHaveBeenNthCalledWith(1, "create_manual_outfit_v1", {
      request: {
        schema_version: 1,
        request_id: "request-1",
        name: "Date",
        item_ids: ["item-1", "item-2"],
        expected_catalog_revision: 4,
        expected_outfit_revision: 2,
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "list_outfits_v1", {
      request: {
        schema_version: 1,
        request_id: "request-1",
        cursor: null,
        limit: 20,
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "get_outfit_collage_v1", {
      request: {
        schema_version: 1,
        request_id: "request-1",
        outfit_id: "outfit-1",
      },
    });
  });
});
