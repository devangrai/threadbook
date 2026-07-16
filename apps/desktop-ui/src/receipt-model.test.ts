import { describe, expect, it } from "vitest";

import {
  parsedReceiptFixture,
  receiptIds,
  receiptOrderFixture,
} from "./receipt-test-data";
import {
  citationKey,
  correctedOrderFromDraft,
  createCorrectionDraft,
  verifyReceiptCitations,
} from "./receipt-model";

describe("receipt model", () => {
  it("verifies exact byte-span quotes before disclosure", async () => {
    const verified = await verifyReceiptCitations(
      parsedReceiptFixture,
      receiptOrderFixture,
    );
    const source = receiptOrderFixture.merchant.citations[0]!;
    expect(verified.quotes.get(citationKey(source))).toBe(
      "Northstar Outfitters",
    );

    await expect(
      verifyReceiptCitations(parsedReceiptFixture, {
        ...receiptOrderFixture,
        merchant: {
          ...receiptOrderFixture.merchant,
          citations: [{ ...source, quote_sha256: "0".repeat(64) }],
        },
      }),
    ).rejects.toThrow("could not be verified");
  });

  it("builds a complete correction snapshot with explicit nulls", () => {
    const draft = createCorrectionDraft(receiptOrderFixture);
    draft.currency = " usd ";
    const result = correctedOrderFromDraft(draft);

    expect(result.error).toBeNull();
    expect(result.value).toEqual(
      expect.objectContaining({
        order_evidence_id: receiptIds.order,
        purchase_date: null,
        currency: "USD",
        line_items: [
          expect.objectContaining({
            order_line_id: receiptIds.line,
            quantity: 2,
            variant: {
              variant_evidence_id: receiptIds.variant,
              brand: null,
              sku: null,
              size: null,
              color: null,
            },
          }),
        ],
      }),
    );
  });
});
