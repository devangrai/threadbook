import { describe, expect, it, vi } from "vitest";

import { createBackupBridge } from "./backup-bridge";

describe("backup bridge", () => {
  it("paginates opaque records and hash-binds restore without paths", async () => {
    const invoke = vi
      .fn()
      .mockResolvedValueOnce({
        schema_version: 1,
        request_id: "10000000-0000-4000-8000-000000000001",
        backups: [record("10000000-0000-4000-8000-000000000010")],
        total_count: 2,
        next_cursor: "opaque",
      })
      .mockResolvedValueOnce({
        schema_version: 1,
        request_id: "10000000-0000-4000-8000-000000000002",
        backups: [record("10000000-0000-4000-8000-000000000011")],
        total_count: 2,
        next_cursor: null,
      })
      .mockResolvedValueOnce({
        schema_version: 1,
        request_id: "10000000-0000-4000-8000-000000000003",
        restart_required: true,
        safety_backup_id: "10000000-0000-4000-8000-000000000012",
      });
    let request = 0;
    const bridge = createBackupBridge(invoke, () => `request-${++request}`);

    const backups = await bridge.list();
    await bridge.prepareRestore(backups[0]);

    expect(backups).toHaveLength(2);
    expect(invoke).toHaveBeenLastCalledWith("prepare_restore_v1", {
      request: {
        schema_version: 1,
        request_id: "request-3",
        backup_id: backups[0].id,
        expected_manifest_sha256: "a".repeat(64),
      },
    });
    expect(JSON.stringify(invoke.mock.calls)).not.toContain("path");
  });
});

function record(backupId: string) {
  return {
    backup_id: backupId,
    reason: "manual",
    created_at: "2026-07-15T11:03:00Z",
    expires_at: "2026-08-14T11:03:00Z",
    manifest_sha256: "a".repeat(64),
    database_schema_version: 10,
    asset_count: 2,
    total_bytes: 2048,
  };
}
