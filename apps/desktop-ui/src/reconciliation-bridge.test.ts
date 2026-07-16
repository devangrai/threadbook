import { describe, expect, it, vi } from "vitest";

import type { InvokeCommand } from "@wardrobe/invoke-transport";
import { createReconciliationBridge } from "./reconciliation-bridge";

const requestId = "92000000-0000-4000-8000-000000000001";

describe("reconciliation bridge", () => {
  it("uses all three V2 reconciliation commands with authority revisions", async () => {
    const invokeMock = vi.fn(async () => ({}));
    const bridge = createReconciliationBridge(
      invokeMock as unknown as InvokeCommand,
      () => requestId,
    );

    await bridge.listCases("observation-1", "open_stale", "cursor-1", 12);
    await bridge.openCase("observation-1", "artifact-1", 17, 8);
    await bridge.decideCase(
      "case-1",
      "same_item",
      "candidate-1",
      4,
      8,
      17,
      6,
    );

    expect(invokeMock).toHaveBeenCalledTimes(3);
    expect(invokeMock).toHaveBeenNthCalledWith(
      1,
      "list_reconciliation_cases_v2",
      {
        request: {
          schema_version: 2,
          request_id: requestId,
          observation_id: "observation-1",
          state: "open_stale",
          cursor: "cursor-1",
          limit: 12,
        },
      },
    );
    expect(invokeMock).toHaveBeenNthCalledWith(
      2,
      "open_reconciliation_case_v2",
      {
        request: {
          schema_version: 2,
          request_id: requestId,
          observation_id: "observation-1",
          selected_artifact_id: "artifact-1",
          expected_photo_revision: 17,
          expected_owner_revision: 8,
        },
      },
    );
    expect(invokeMock).toHaveBeenNthCalledWith(
      3,
      "decide_reconciliation_case_v2",
      {
        request: {
          schema_version: 2,
          request_id: requestId,
          case_id: "case-1",
          outcome: "same_item",
          selected_candidate_id: "candidate-1",
          expected_case_revision: 4,
          expected_owner_revision: 8,
          expected_photo_revision: 17,
          expected_reconciliation_revision: 6,
        },
      },
    );
  });
});
