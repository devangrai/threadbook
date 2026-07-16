import { describe, expect, it, vi } from "vitest";

import type {
  GetFoundationSnapshotV1Response,
  RunStorageCheckV1Response,
} from "./generated/contracts";
import {
  createFoundationBridge,
  mapSnapshot,
  setLocalOnlyAndRefresh,
} from "./foundation-bridge";

const requestId = "a5b238c1-df7e-4ec8-8330-abe67f7ad536";

const snapshotResponse: GetFoundationSnapshotV1Response = {
  schema_version: 1,
  request_id: requestId,
  snapshot: {
    schema_version: 1,
    versions: {
      application: "0.1.0",
      database_schema: 1,
      job_pipeline: 1,
    },
    local_settings: {
      local_only: true,
      revision: 4,
      authority_health: "persisted",
      storage_status: "ready",
      deletion_health: {
        status: "none",
        deadline_at: null,
        counts: { in_progress: 0, overdue: 0, needs_attention: 0 },
      },
    },
    credential_references: [
      {
        credential_id: "7d2942a0-b625-4973-960b-0c29ac6abdef",
        provider: "open_ai",
        display_label: "Personal OpenAI",
        status: "active",
        updated_at: "2026-07-15T01:05:11Z",
      },
    ],
    recent_jobs: [
      {
        job_id: "51fcdf76-93ce-4c97-8c86-c2bc285a8468",
        kind: "verify_blob_v1",
        status: "failed",
        attempts: 3,
        max_attempts: 3,
        updated_at: "2026-07-15T01:06:11Z",
        terminal_failure: {
          code: "not_found",
          user_action: "review_storage",
        },
      },
    ],
    catalog: { items: [] },
  },
};

describe("foundation bridge", () => {
  it("maps only non-secret snapshot fields into the view model", () => {
    const snapshot = mapSnapshot(snapshotResponse);

    expect(snapshot).toEqual({
      itemCount: 0,
      localOnly: true,
      revision: 4,
      authorityHealth: "persisted",
      storage: { database: "ready", blobs: "ready" },
      deletionHealth: { status: "none", deadlineAt: null, count: 0 },
      credentials: [
        {
          id: "7d2942a0-b625-4973-960b-0c29ac6abdef",
          provider: "OpenAI",
          displayLabel: "Personal OpenAI",
          status: "active",
        },
      ],
      recentJobs: [
        {
          id: "51fcdf76-93ce-4c97-8c86-c2bc285a8468",
          kind: "verify_blob_v1",
          status: "failed",
          updatedAt: "2026-07-15T01:06:11Z",
          failureCode: "not_found",
          userAction: "review_storage",
        },
      ],
    });
    expect(JSON.stringify(snapshot)).not.toContain("secret");
  });

  it("uses production command names and typed request envelopes", async () => {
    const storageResponse: RunStorageCheckV1Response = {
      schema_version: 1,
      request_id: requestId,
      check_id: "8c1577db-8450-4a5d-9ed7-449fab83de0a",
      job_id: "51fcdf76-93ce-4c97-8c86-c2bc285a8468",
      replay_status: "created",
    };
    const invokeCommand = vi.fn(async <T>(command: string): Promise<T> => {
      if (command === "get_foundation_snapshot_v1") {
        return snapshotResponse as T;
      }
      if (command === "set_local_only_v1") {
        return {
          schema_version: 1,
          request_id: requestId,
          local_only: false,
          revision: 5,
          authority_health: "persisted",
          replay_status: "created",
        } as T;
      }
      return storageResponse as T;
    });
    const bridge = createFoundationBridge(
      invokeCommand as unknown as Parameters<
        typeof createFoundationBridge
      >[0],
      () => requestId,
    );

    await bridge.getSnapshot();
    await bridge.setLocalOnly(false, 4);
    expect(await bridge.runStorageCheck()).toBe(false);
    await bridge.saveCredential(
      "open_ai",
      "Personal OpenAI",
      "synthetic-secret",
    );
    await bridge.deleteCredential(
      "7d2942a0-b625-4973-960b-0c29ac6abdef",
    );
    expect(invokeCommand).toHaveBeenNthCalledWith(
      1,
      "get_foundation_snapshot_v1",
      {
        request: { schema_version: 1, request_id: requestId },
      },
    );
    expect(invokeCommand).toHaveBeenNthCalledWith(
      2,
      "set_local_only_v1",
      {
        request: {
          schema_version: 1,
          request_id: requestId,
          enabled: false,
          expected_revision: 4,
        },
      },
    );
    expect(invokeCommand).toHaveBeenNthCalledWith(
      3,
      "run_storage_check_v1",
      {
        request: { schema_version: 1, request_id: requestId },
      },
    );
    expect(invokeCommand).toHaveBeenNthCalledWith(4, "save_credential_v1", {
      request: {
        schema_version: 1,
        request_id: requestId,
        provider: "open_ai",
        display_label: "Personal OpenAI",
        secret: "synthetic-secret",
      },
    });
    expect(invokeCommand).toHaveBeenNthCalledWith(
      5,
      "delete_credential_v1",
      {
        request: {
          schema_version: 1,
          request_id: requestId,
          credential_id: "7d2942a0-b625-4973-960b-0c29ac6abdef",
        },
      },
    );
  });

  it("publishes a fresh snapshot after any mode-change error", async () => {
    const current = mapSnapshot(snapshotResponse);
    const publish = vi.fn();
    const bridge = {
      setLocalOnly: vi.fn(async () => {
        throw {
          code: "storage_unavailable",
          retryable: true,
          user_action: "retry",
        };
      }),
      getSnapshot: vi.fn(async () => current),
    } as unknown as Parameters<typeof setLocalOnlyAndRefresh>[0];

    await expect(
      setLocalOnlyAndRefresh(bridge, false, 3, publish),
    ).rejects.toMatchObject({ code: "storage_unavailable" });

    expect(bridge.setLocalOnly).toHaveBeenCalledWith(false, 3);
    expect(bridge.getSnapshot).toHaveBeenCalledTimes(1);
    expect(publish).toHaveBeenCalledWith(current);
  });
});
