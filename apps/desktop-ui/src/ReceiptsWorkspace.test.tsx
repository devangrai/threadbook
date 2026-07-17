import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { ReceiptBridge } from "./receipt-bridge";
import type { ReceiptIntelligenceBridge } from "./receipt-intelligence-bridge";
import type {
  CorrectedReceiptOrderV1,
  ReceiptReviewActionV1,
  ReceiptStateV1,
} from "./generated/contracts";
import {
  analyzedReceiptFixture,
  receiptIds,
  receiptOrderFixture,
  receiptSummaryFixture,
} from "./receipt-test-data";
import { ReceiptsWorkspace } from "./ReceiptsWorkspace";

describe("receipts workspace", { timeout: 15_000 }, () => {
  it("analyzes, discloses verified quotes, and preserves a correction on conflict", async () => {
    let revision = 4;
    let conflict = true;
    const bridge: ReceiptBridge = {
      listReceipts: vi.fn(async (state: ReceiptStateV1) => ({
        schema_version: 1 as const,
        request_id: "request",
        receipts: [
          state === "unanalyzed"
            ? receiptSummaryFixture("unanalyzed")
            : receiptSummaryFixture("needs_review"),
        ],
        total_count: 1,
        receipt_revision: revision,
        evidence_generation: 3,
        next_cursor: null,
      })),
      analyzeReceipt: vi.fn(analyzedReceiptFixture),
      listReceiptImageCandidates: vi.fn(async () => ({
        schema_version: 1 as const,
        request_id: "request",
        source_id: receiptIds.source,
        candidates: [
          {
            candidate_id: "78000000-0000-4000-8000-000000000001",
            source_id: receiptIds.source,
            display_host: "images.example.test",
            candidate_url_sha256: "a".repeat(64),
            eligibility: "eligible" as const,
            latest_attempt: null,
          },
        ],
        omitted_count: 0,
      })),
      approveAndFetchReceiptImage: vi.fn(async () => ({
        schema_version: 1 as const,
        request_id: "request",
        candidate_id: "78000000-0000-4000-8000-000000000001",
        attempt_id: "78000000-0000-4000-8000-000000000002",
        outcome: "succeeded" as const,
        failure_code: null,
        artifact: {
          image_id: "78000000-0000-4000-8000-000000000003",
          source_blob_sha256: "b".repeat(64),
          source_byte_length: 1024,
          source_media_type: "image/png",
          display_blob_sha256: "c".repeat(64),
          display_byte_length: 900,
          display_media_type: "image/png",
          width: 640,
          height: 800,
          policy_revision: "policy-v1",
          decoder_revision: "decoder-v1",
          derivative_revision: "derivative-v1",
        },
        replay_status: "created" as const,
      })),
      reviewReceipt: vi.fn(async (
        _orderId: string,
        action: ReceiptReviewActionV1,
        correctedOrder: CorrectedReceiptOrderV1 | null,
      ) => {
        if (conflict) {
          conflict = false;
          revision = 5;
          throw { code: "request_conflict" };
        }
        revision += 1;
        return {
          schema_version: 1 as const,
          request_id: "request",
          order: receiptOrderFixture,
          decision: {
            decision_id: "decision",
            order_evidence_id: receiptIds.order,
            action,
            corrected_order: correctedOrder,
            receipt_revision: revision,
            created_at: "2026-07-15T03:00:00Z",
          },
          new_receipt_revision: revision,
          evidence_generation: 3,
          replay_status: "created" as const,
        };
      }),
    };
    const user = userEvent.setup();
    render(
      <ReceiptsWorkspace
        localOnly={false}
        bridge={bridge}
        intelligenceBridge={emptyIntelligenceBridge()}
      />,
    );

    await user.click(
      await screen.findByRole("button", {
        name: "Offline analyze receipt from unknown merchant",
      }),
    );
    expect(
      await screen.findByRole("heading", { name: "Order line 1" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Unknown").length).toBeGreaterThan(0);
    await user.click(
      await screen.findByRole("button", {
        name: "Download image from images.example.test",
      }),
    );
    expect(
      screen.getByText(/connect only to/i),
    ).toHaveTextContent("images.example.test");
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Download image from images.example.test",
      }),
    );
    expect(
      await screen.findByText("Receipt image stored locally."),
    ).toBeInTheDocument();
    expect(screen.getByText(/stored locally, 640 by 800/i)).toBeInTheDocument();

    await user.click(
      screen.getAllByText("Verified source quote", {
        selector: "summary",
      })[0]!,
    );
    expect(screen.getByText("Northstar Outfitters", { selector: "blockquote" }))
      .toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Correct" }));
    const merchant = screen.getByRole("textbox", { name: "Merchant" });
    await user.clear(merchant);
    await user.type(merchant, "Northstar Revised");
    await user.click(screen.getByRole("button", { name: "Save correction" }));

    expect(
      await screen.findByText(/latest review was reloaded/i),
    ).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Merchant" })).toHaveValue(
      "Northstar Revised",
    );

    await user.click(screen.getByRole("button", { name: "Save correction" }));
    await waitFor(() =>
      expect(bridge.reviewReceipt).toHaveBeenLastCalledWith(
        receiptIds.order,
        "correct",
        expect.objectContaining({ merchant: "Northstar Revised" }),
        5,
      ),
    );
    expect(
      await screen.findByText("Receipt correction saved."),
    ).toBeInTheDocument();
  });

  it("lists local receipt-image status but denies image fetching in local-only mode", async () => {
    const approveAndFetchReceiptImage = vi.fn();
    const bridge = {
      listReceipts: vi.fn(async () => ({
        schema_version: 1 as const,
        request_id: "request",
        receipts: [receiptSummaryFixture("needs_review")],
        total_count: 1,
        receipt_revision: 4,
        evidence_generation: 3,
        next_cursor: null,
      })),
      analyzeReceipt: vi.fn(),
      reviewReceipt: vi.fn(),
      listReceiptImageCandidates: vi.fn(async () => ({
        schema_version: 1 as const,
        request_id: "request",
        source_id: receiptIds.source,
        candidates: [
          {
            candidate_id: "78000000-0000-4000-8000-000000000001",
            source_id: receiptIds.source,
            display_host: "images.example.test",
            candidate_url_sha256: "a".repeat(64),
            eligibility: "eligible" as const,
            latest_attempt: null,
          },
        ],
        omitted_count: 0,
      })),
      approveAndFetchReceiptImage,
    } as unknown as ReceiptBridge;
    const user = userEvent.setup();
    render(
      <ReceiptsWorkspace
        localOnly
        bridge={bridge}
        intelligenceBridge={emptyIntelligenceBridge()}
      />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Find receipt images" }),
    );
    const download = await screen.findByRole("button", {
      name: "Download image from images.example.test",
    });
    expect(download).toBeDisabled();
    await user.click(download);

    expect(bridge.listReceiptImageCandidates).toHaveBeenCalledOnce();
    expect(approveAndFetchReceiptImage).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

function emptyIntelligenceBridge(): ReceiptIntelligenceBridge {
  return {
    preview: vi.fn(),
    request: vi.fn(),
    latest: vi.fn(async () => ({
      availability: {
        available: false,
        reason: "release_evidence_unavailable" as const,
        offline_receipt_analysis_available: true,
        existing_wardrobe_access_available: true,
      },
      attempt: null,
    })),
  };
}
