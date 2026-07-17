import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type {
  ItemAttributesV1,
  ListReceiptPurchaseUnitsV1Response,
  PromoteReceiptPurchaseUnitV1Response,
  ReceiptPurchaseUnitV1,
} from "./generated/contracts";
import { ReceiptPurchaseUnits } from "./ReceiptPurchaseUnits";
import type { ReceiptPromotionBridge } from "./receipt-promotion-bridge";

describe("receipt purchase units", () => {
  it("shows reviewed provenance and requires one item confirmation", async () => {
    const unit = purchaseUnitFixture();
    const promotePurchaseUnit = vi.fn(async (
      current: ReceiptPurchaseUnitV1,
      attributes: ItemAttributesV1,
    ) => promotionResponse(current, attributes));
    const bridge: ReceiptPromotionBridge = {
      listPurchaseUnits: vi.fn(async () => listResponse(unit)),
      promotePurchaseUnit,
    };
    const user = userEvent.setup();
    render(<ReceiptPurchaseUnits sourceId={unit.authority.source_id} bridge={bridge} />);

    expect(
      await screen.findByRole("heading", { name: "Purchase units" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("region", { name: "Order-level reviewed provenance" }),
    ).toHaveTextContent("Northstar Outfitters");
    expect(
      screen.getByRole("region", { name: "Line-level reviewed provenance" }),
    ).toHaveTextContent("Linen overshirt");
    expect(
      screen.getAllByText("1 verified receipt source citation").length,
    ).toBeGreaterThan(1);

    const add = screen.getByRole("button", { name: "Add to wardrobe" });
    await user.click(add);
    const dialog = screen.getByRole("dialog", {
      name: "Create wardrobe item",
    });
    await user.click(
      within(dialog).getByRole("button", { name: "Outerwear" }),
    );
    await user.click(
      within(dialog).getByRole("button", { name: "Review one item" }),
    );

    expect(promotePurchaseUnit).not.toHaveBeenCalled();
    expect(
      screen.getByRole("dialog", { name: "Confirm one wardrobe item" }),
    ).toHaveTextContent("creates exactly one wardrobe item");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(promotePurchaseUnit).not.toHaveBeenCalled();
    expect(add).toHaveFocus();
  });

  it("preserves the draft and focuses a live conflict summary", async () => {
    const initial = purchaseUnitFixture();
    const refreshed = {
      ...initial,
      purchase_unit_revision: initial.purchase_unit_revision + 1,
      catalog_revision: initial.catalog_revision + 1,
      unit_snapshot_sha256: "d".repeat(64),
    };
    const listPurchaseUnits = vi
      .fn<ReceiptPromotionBridge["listPurchaseUnits"]>()
      .mockResolvedValueOnce(listResponse(initial))
      .mockResolvedValueOnce(listResponse(refreshed));
    const promotePurchaseUnit = vi.fn(async () => {
      throw {
        schema_version: 1,
        code: "request_conflict",
        retryable: false,
        user_action: "start_new_request",
        field: "receipt_purchase_unit",
      };
    });
    const bridge: ReceiptPromotionBridge = {
      listPurchaseUnits,
      promotePurchaseUnit,
    };
    const user = userEvent.setup();
    render(<ReceiptPurchaseUnits sourceId={initial.authority.source_id} bridge={bridge} />);

    await user.click(
      await screen.findByRole("button", { name: "Add to wardrobe" }),
    );
    const name = screen.getByRole("textbox", { name: "Display name" });
    await user.clear(name);
    await user.type(name, "Edited linen layer");
    await user.click(screen.getByRole("button", { name: "Outerwear" }));
    await user.click(screen.getByRole("button", { name: "Review one item" }));
    await user.click(
      screen.getByRole("button", { name: "Create one wardrobe item" }),
    );

    const conflict = await screen.findByRole("alert");
    expect(conflict).toHaveTextContent("draft was preserved");
    await waitFor(() => expect(conflict).toHaveFocus());
    expect(listPurchaseUnits).toHaveBeenCalledTimes(2);

    await user.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByRole("textbox", { name: "Display name" })).toHaveValue(
      "Edited linen layer",
    );
    expect(
      screen.getByRole("button", { name: "Outerwear" }),
    ).toHaveAttribute("aria-pressed", "true");
  });

  it("navigates through the success link to the created catalog item", async () => {
    const unit = purchaseUnitFixture();
    const onNavigate = vi.fn();
    const bridge: ReceiptPromotionBridge = {
      listPurchaseUnits: vi.fn(async () => listResponse(unit)),
      promotePurchaseUnit: vi.fn(async (current, attributes) =>
        promotionResponse(current, attributes),
      ),
    };
    const user = userEvent.setup();
    render(
      <ReceiptPurchaseUnits
        sourceId={unit.authority.source_id}
        bridge={bridge}
        onNavigateToCatalogItem={onNavigate}
      />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Add to wardrobe" }),
    );
    await user.click(screen.getByRole("button", { name: "Outerwear" }));
    await user.click(screen.getByRole("button", { name: "Review one item" }));
    await user.click(
      screen.getByRole("button", { name: "Create one wardrobe item" }),
    );

    const link = await screen.findByRole("link", {
      name: "Open Linen overshirt in Wardrobe",
    });
    await waitFor(() => expect(link).toHaveFocus());
    expect(
      screen.getByRole("button", { name: "Added to wardrobe" }),
    ).toBeDisabled();

    await user.click(link);
    expect(onNavigate).toHaveBeenCalledWith(
      expect.objectContaining({
        item_id: uuid(9),
        attributes: expect.objectContaining({
          display_name: "Linen overshirt",
          category: "outerwear",
        }),
      }),
    );
  });
});

function listResponse(
  unit: ReceiptPurchaseUnitV1,
): ListReceiptPurchaseUnitsV1Response {
  return {
    schema_version: 1,
    request_id: uuid(20),
    units: [unit],
    exclusions: [],
    total_count: 1,
    total_exclusion_count: 0,
    snapshot: {
      receipt_revision: unit.authority.receipt_revision,
      evidence_generation: unit.evidence_generation,
      catalog_revision: unit.catalog_revision,
    },
    next_cursor: null,
  };
}

function promotionResponse(
  unit: ReceiptPurchaseUnitV1,
  attributes: ItemAttributesV1,
): PromoteReceiptPurchaseUnitV1Response {
  const promotedUnit: ReceiptPurchaseUnitV1 = {
    ...unit,
    catalog_revision: unit.catalog_revision + 1,
    evidence_generation: unit.evidence_generation + 1,
    status: {
      status: "promoted",
      promotion_id: uuid(8),
      item_id: uuid(9),
      evidence_id: uuid(10),
      decision_id: uuid(11),
    },
  };
  return {
    schema_version: 1,
    request_id: uuid(21),
    unit: promotedUnit,
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
      snapshot_sha256: "e".repeat(64),
      created_at: "2026-07-17T01:00:00Z",
    },
    promotion: {
      promotion_id: uuid(8),
      purchase_unit_id: unit.purchase_unit_id,
      order_line_id: unit.order_line_id,
      unit_ordinal: unit.unit_ordinal,
      item_id: uuid(9),
      evidence_id: uuid(10),
      decision_id: uuid(11),
      authority_snapshot_id: uuid(12),
      request_id: uuid(21),
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
    new_catalog_revision: unit.catalog_revision + 1,
    new_evidence_generation: unit.evidence_generation + 1,
    replay_status: "created",
  };
}

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
    authoritative_quantity: 2,
    values: {
      merchant: "Northstar Outfitters",
      order_identifier: "ORDER-100",
      purchase_date: "2026-07-16",
      currency: "USD",
      description: "Linen overshirt",
      event_kind: "purchase",
      quantity: 2,
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
