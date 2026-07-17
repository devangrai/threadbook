import { describe, expect, it, vi } from "vitest";

import type {
  ItemAttributesV1,
  ListReceiptPurchaseUnitsV1Response,
  PromoteReceiptPurchaseUnitV1Response,
  ReceiptPurchaseUnitV1,
} from "./generated/contracts";
import type { InvokeCommand } from "./invoke-transport";
import { createReceiptPromotionBridge } from "./receipt-promotion-bridge";

describe("receipt promotion bridge", () => {
  it("uses snapshot-bound generated list and promotion contracts", async () => {
    const unit = purchaseUnitFixture();
    const attributes: ItemAttributesV1 = {
      display_name: "Linen overshirt",
      category: "outerwear",
      subcategory: "overshirt",
      brand: "Northstar",
      primary_color: "Blue",
      size: "M",
      notes: null,
      tags: ["linen"],
    };
    const invoke = vi.fn(async (
      command: string,
      args?: Record<string, unknown>,
    ) => {
      const request = args?.request as { request_id: string };
      if (command === "list_receipt_purchase_units_v1") {
        return {
          schema_version: 1,
          request_id: request.request_id,
          units: [unit],
          exclusions: [],
          total_count: 1,
          total_exclusion_count: 0,
          snapshot: {
            receipt_revision: 9,
            evidence_generation: 4,
            catalog_revision: 7,
          },
          next_cursor: null,
        } satisfies ListReceiptPurchaseUnitsV1Response;
      }
      return {
        schema_version: 1,
        request_id: request.request_id,
        unit: {
          ...unit,
          status: {
            status: "promoted",
            promotion_id: uuid(8),
            item_id: uuid(9),
            evidence_id: uuid(10),
            decision_id: uuid(11),
          },
        },
        item: {
          item_id: uuid(9),
          attributes,
          evidence_ids: [uuid(10)],
          last_decision_id: uuid(11),
        },
        authority_snapshot: {
          authority_snapshot_id: uuid(12),
          authority: unit.authority,
          order_line_id: unit.order_line_id,
          values: unit.values,
          provenance: unit.provenance,
          snapshot_sha256: "b".repeat(64),
          created_at: "2026-07-17T01:00:00Z",
        },
        promotion: {
          promotion_id: uuid(8),
          purchase_unit_id: unit.purchase_unit_id,
          order_line_id: unit.order_line_id,
          unit_ordinal: 0,
          item_id: uuid(9),
          evidence_id: uuid(10),
          decision_id: uuid(11),
          authority_snapshot_id: uuid(12),
          request_id: request.request_id,
          promoted_at: "2026-07-17T01:00:00Z",
        },
        decision: {
          decision_id: uuid(11),
          kind: "promote_receipt_purchase_unit",
          affected_item_ids: [uuid(9)],
          affected_evidence_ids: [uuid(10)],
          compensates_decision_id: null,
          reversible: false,
        },
        new_catalog_revision: 8,
        new_evidence_generation: 5,
        replay_status: "created",
      } satisfies PromoteReceiptPurchaseUnitV1Response;
    });
    const ids = [uuid(20), uuid(21)];
    const bridge = createReceiptPromotionBridge(
      invoke as unknown as InvokeCommand,
      () => ids.shift() ?? uuid(22),
    );

    await bridge.listPurchaseUnits(uuid(1));
    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "list_receipt_purchase_units_v1",
      {
        request: {
          schema_version: 1,
          request_id: uuid(20),
          source_id: uuid(1),
          status: null,
          cursor: null,
          limit: 100,
        },
      },
    );

    await bridge.promotePurchaseUnit(unit, attributes);
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "promote_receipt_purchase_unit_v1",
      {
        request: {
          schema_version: 1,
          request_id: uuid(21),
          purchase_unit_id: unit.purchase_unit_id,
          expected_purchase_unit_revision: 3,
          expected_unit_snapshot_sha256: "a".repeat(64),
          expected_authority_id: uuid(4),
          expected_authority_revision: 2,
          expected_receipt_revision: 9,
          expected_review_decision_id: uuid(5),
          expected_catalog_revision: 7,
          confirmation: "create_one_wardrobe_item",
          category_authority: "user_selected",
          attributes,
        },
      },
    );
  });
});

function purchaseUnitFixture(): ReceiptPurchaseUnitV1 {
  const citation = {
    fragment_id: uuid(30),
    byte_start: 0,
    byte_end: 16,
    quote_sha256: "c".repeat(64),
  };
  const receipt = { kind: "receipt_citations" as const, citations: [citation] };
  const unknown = { kind: "unknown_receipt_field" as const };
  return {
    purchase_unit_id: uuid(2),
    order_line_id: uuid(3),
    unit_ordinal: 0,
    authoritative_quantity: 1,
    values: {
      merchant: "Northstar",
      order_identifier: "ORDER-100",
      purchase_date: "2026-07-16",
      currency: "USD",
      description: "Linen overshirt",
      event_kind: "purchase",
      quantity: 1,
      unit_price_minor: 8900,
      brand: "Northstar",
      sku: null,
      size: "M",
      color: "Blue",
    },
    provenance: {
      merchant: receipt,
      order_identifier: receipt,
      purchase_date: receipt,
      currency: receipt,
      description: receipt,
      event_kind: receipt,
      quantity: receipt,
      unit_price_minor: receipt,
      brand: receipt,
      sku: unknown,
      size: receipt,
      color: receipt,
    },
    authority: {
      authority_id: uuid(4),
      source_id: uuid(1),
      order_evidence_id: uuid(6),
      review_decision_id: uuid(5),
      review_action: "confirm",
      authority_revision: 2,
      receipt_revision: 9,
    },
    purchase_unit_revision: 3,
    unit_snapshot_sha256: "a".repeat(64),
    catalog_revision: 7,
    evidence_generation: 4,
    status: { status: "available" },
  };
}

function uuid(value: number) {
  return `00000000-0000-4000-8000-${String(value).padStart(12, "0")}`;
}
