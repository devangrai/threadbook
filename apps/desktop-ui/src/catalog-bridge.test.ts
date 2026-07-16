import { describe, expect, it, vi } from "vitest";

import { createCatalogBridge } from "./catalog-bridge";
import type { InvokeCommand } from "@wardrobe/invoke-transport";

const requestId = "90000000-0000-4000-8000-000000000001";

describe("catalog bridge", () => {
  it("sends revisions and paging fields to production command names", async () => {
    const invoke = vi.fn(async (command: string) =>
      command.startsWith("list_")
        ? {
            items: [],
            total_count: 0,
            catalog_revision: 4,
            evidence_generation: 2,
            next_cursor: null,
          }
        : {
            decision: { decision_id: "decision-1" },
            new_catalog_revision: 5,
          },
    ) as unknown as InvokeCommand;
    const bridge = createCatalogBridge(invoke, () => requestId);

    await bridge.listCatalog("opaque", 25);
    await bridge.decideEvidence("evidence-1", "assign", "item-1", 4);
    await bridge.mergeItems(
      ["item-1", "item-2"],
      {
        display_name: "Merged",
        category: "top",
        color: "White",
        notes: "",
      },
      5,
    );

    expect(invoke).toHaveBeenNthCalledWith(1, "list_catalog_v1", {
      request: {
        schema_version: 1,
        request_id: requestId,
        cursor: "opaque",
        limit: 25,
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "decide_evidence_v1", {
      request: expect.objectContaining({
        evidence_id: "evidence-1",
        action: "assign",
        item_id: "item-1",
        expected_catalog_revision: 4,
      }),
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "merge_items_v1", {
      request: expect.objectContaining({
        item_ids: ["item-1", "item-2"],
        expected_catalog_revision: 5,
      }),
    });
  });

  it("executes only the frozen preview authority", async () => {
    const invoke = vi.fn(async () => ({
      run_id: "90000000-0000-4000-8000-000000000002",
      complete: true,
      accepted_at: "2026-07-15T00:00:30Z",
      deadline_at: "2026-07-15T01:00:30Z",
      completed_at: "2026-07-15T00:01:00Z",
      deleted_local_record_count: 2,
      deleted_unique_blob_count: 1,
      deleted_unique_blob_bytes: 128,
      retained_shared_blob_count: 1,
      backup_retention: [],
      remote_retention: [],
      replay_status: "created",
    })) as unknown as InvokeCommand;
    const bridge = createCatalogBridge(invoke, () => requestId);
    const plan = {
      preview_snapshot_token: "opaque-preview",
      plan_sha256: "a".repeat(64),
      prepared_at: "2026-07-15T00:00:00Z",
      expires_at: "2026-07-15T00:15:00Z",
      revisions: {
        catalog_revision: 4,
        evidence_generation: 2,
        receipt_revision: 1,
        photo_revision: 1,
        photokit_revision: 1,
        reconciliation_revision: 1,
        outfit_revision: 1,
        try_on_revision: 1,
      },
      overall_count: 2,
      retained_shared_blob_count: 1,
      unique_blob_count: 1,
      unique_blob_bytes: 128,
      backup_retention: [],
      remote_retention: [],
      classes: [],
    };

    await bridge.executeDeletion(plan, requestId);

    expect(invoke).toHaveBeenCalledWith("execute_deletion_v1", {
      request: {
        schema_version: 1,
        request_id: requestId,
        preview_snapshot_token: "opaque-preview",
        plan_sha256: "a".repeat(64),
        expected_revisions: plan.revisions,
        confirmation: "delete_active_local_data",
      },
    });
  });

  it("does not surface an incomplete deletion response as success", async () => {
    const invoke = vi.fn(async () => ({ complete: false })) as unknown as InvokeCommand;
    const bridge = createCatalogBridge(invoke, () => requestId);

    await expect(
      bridge.executeDeletion(
        {
          preview_snapshot_token: "opaque-preview",
          plan_sha256: "a".repeat(64),
          prepared_at: "2026-07-15T00:00:00Z",
          expires_at: "2026-07-15T00:15:00Z",
          revisions: {
            catalog_revision: 1,
            evidence_generation: 1,
            receipt_revision: 1,
            photo_revision: 1,
            photokit_revision: 1,
            reconciliation_revision: 1,
            outfit_revision: 1,
            try_on_revision: 1,
          },
          overall_count: 1,
          retained_shared_blob_count: 0,
          unique_blob_count: 0,
          unique_blob_bytes: 0,
          backup_retention: [],
          remote_retention: [],
          classes: [],
        },
        requestId,
      ),
    ).rejects.toThrow("returned before completion");
  });
});
