import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  ItemAttributesV1,
  ListReceiptPurchaseUnitsV1Request,
  ListReceiptPurchaseUnitsV1Response,
  PromoteReceiptPurchaseUnitV1Request,
  PromoteReceiptPurchaseUnitV1Response,
  ReceiptPurchaseUnitV1,
} from "./generated/contracts";

type RequestIdFactory = () => string;

export type ReceiptPromotionBridge = {
  listPurchaseUnits: (
    sourceId: string,
  ) => Promise<ListReceiptPurchaseUnitsV1Response>;
  promotePurchaseUnit: (
    unit: ReceiptPurchaseUnitV1,
    attributes: ItemAttributesV1,
  ) => Promise<PromoteReceiptPurchaseUnitV1Response>;
};

export function createReceiptPromotionBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): ReceiptPromotionBridge {
  return {
    async listPurchaseUnits(sourceId) {
      const request: ListReceiptPurchaseUnitsV1Request = {
        schema_version: 1,
        request_id: createRequestId(),
        source_id: sourceId,
        status: null,
        cursor: null,
        limit: 100,
      };
      return invokeCommand<ListReceiptPurchaseUnitsV1Response>(
        "list_receipt_purchase_units_v1",
        { request },
      );
    },

    async promotePurchaseUnit(unit, attributes) {
      const request: PromoteReceiptPurchaseUnitV1Request = {
        schema_version: 1,
        request_id: createRequestId(),
        purchase_unit_id: unit.purchase_unit_id,
        expected_purchase_unit_revision: unit.purchase_unit_revision,
        expected_unit_snapshot_sha256: unit.unit_snapshot_sha256,
        expected_authority_id: unit.authority.authority_id,
        expected_authority_revision: unit.authority.authority_revision,
        expected_receipt_revision: unit.authority.receipt_revision,
        expected_review_decision_id: unit.authority.review_decision_id,
        expected_catalog_revision: unit.catalog_revision,
        confirmation: "create_one_wardrobe_item",
        category_authority: "user_selected",
        attributes,
      };
      return invokeCommand<PromoteReceiptPurchaseUnitV1Response>(
        "promote_receipt_purchase_unit_v1",
        { request },
      );
    },
  };
}

export const receiptPromotionBridge = createReceiptPromotionBridge(
  productionInvoke,
);
