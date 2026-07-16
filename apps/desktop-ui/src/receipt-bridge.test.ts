import { describe, expect, it, vi } from "vitest";

import type { InvokeCommand } from "@wardrobe/invoke-transport";
import { createReceiptBridge } from "./receipt-bridge";
import {
  parsedReceiptFixture,
  processingFixture,
  receiptIds,
  receiptOrderFixture,
} from "./receipt-test-data";

const requestId = "79000000-0000-4000-8000-000000000009";

describe("receipt bridge", () => {
  it("uses final generated envelopes, command names, and receipt revisions", async () => {
    const invoke = vi.fn(async (command: string) => {
      if (command === "list_receipts_v1") {
        return {
          schema_version: 1,
          request_id: requestId,
          receipts: [],
          total_count: 0,
          receipt_revision: 8,
          evidence_generation: 3,
          next_cursor: null,
        };
      }
      if (command === "analyze_receipt_v1") {
        return {
          schema_version: 1,
          request_id: requestId,
          parsed: parsedReceiptFixture,
          order: receiptOrderFixture,
          processing: processingFixture,
          state: "needs_review",
          receipt_revision: 8,
          evidence_generation: 3,
          replay_status: "created",
        };
      }
      if (command === "list_receipt_image_candidates_v1") {
        return {
          schema_version: 1,
          request_id: requestId,
          source_id: receiptIds.source,
          candidates: [],
          omitted_count: 0,
        };
      }
      if (command === "approve_and_fetch_receipt_image_v1") {
        return {
          schema_version: 1,
          request_id: requestId,
          candidate_id: "78000000-0000-4000-8000-000000000001",
          attempt_id: "78000000-0000-4000-8000-000000000002",
          outcome: "transport_failed",
          failure_code: "transport_failed",
          artifact: null,
          replay_status: "created",
        };
      }
      return {
        schema_version: 1,
        request_id: requestId,
        order: receiptOrderFixture,
        decision: {
          decision_id: "decision-1",
          order_evidence_id: receiptIds.order,
          action: "confirm",
          corrected_order: null,
          receipt_revision: 9,
          created_at: "2026-07-15T03:00:00Z",
        },
        new_receipt_revision: 9,
        evidence_generation: 3,
        replay_status: "created",
      };
    }) as unknown as InvokeCommand;
    const bridge = createReceiptBridge(invoke, () => requestId);

    await bridge.listReceipts("needs_review", "opaque", 25);
    const analyzed = await bridge.analyzeReceipt(receiptIds.source);
    await bridge.reviewReceipt(receiptIds.order, "confirm", null, 8);
    await bridge.listReceiptImageCandidates(receiptIds.source);
    await bridge.approveAndFetchReceiptImage(
      "78000000-0000-4000-8000-000000000001",
      "images.example.test",
      "a".repeat(64),
      null,
    );

    expect(analyzed.verified.quotes.size).toBeGreaterThan(0);
    expect(invoke).toHaveBeenNthCalledWith(1, "list_receipts_v1", {
      request: {
        schema_version: 1,
        request_id: requestId,
        state: "needs_review",
        cursor: "opaque",
        limit: 25,
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(2, "analyze_receipt_v1", {
      request: {
        schema_version: 1,
        request_id: requestId,
        source_id: receiptIds.source,
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "review_receipt_v1", {
      request: {
        schema_version: 1,
        request_id: requestId,
        order_evidence_id: receiptIds.order,
        action: "confirm",
        corrected_order: null,
        expected_receipt_revision: 8,
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(
      4,
      "list_receipt_image_candidates_v1",
      {
        request: {
          schema_version: 1,
          request_id: requestId,
          source_id: receiptIds.source,
        },
      },
    );
    expect(invoke).toHaveBeenNthCalledWith(
      5,
      "approve_and_fetch_receipt_image_v1",
      {
        request: {
          schema_version: 1,
          request_id: requestId,
          candidate_id: "78000000-0000-4000-8000-000000000001",
          approved_display_host: "images.example.test",
          candidate_url_sha256: "a".repeat(64),
          prior_attempt_id: null,
        },
      },
    );
  });
});
