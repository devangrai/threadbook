import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  CreateManualOutfitV1Request,
  CreateManualOutfitV1Response,
  GetOutfitCollageV1Request,
  GetOutfitCollageV1Response,
  ListOutfitsV1Request,
  ListOutfitsV1Response,
} from "./generated/contracts";

type RequestIdFactory = () => string;

export type OutfitBridge = {
  createManualOutfit: (
    name: string,
    itemIds: string[],
    expectedCatalogRevision: number,
    expectedOutfitRevision: number,
  ) => Promise<CreateManualOutfitV1Response>;
  listOutfits: (
    cursor?: string | null,
    limit?: number,
  ) => Promise<ListOutfitsV1Response>;
  getCollage: (outfitId: string) => Promise<GetOutfitCollageV1Response>;
};

export function createOutfitBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): OutfitBridge {
  const envelope = () => ({
    schema_version: 1 as const,
    request_id: createRequestId(),
  });

  return {
    async createManualOutfit(
      name,
      itemIds,
      expectedCatalogRevision,
      expectedOutfitRevision,
    ) {
      const request: CreateManualOutfitV1Request = {
        ...envelope(),
        name: name.trim(),
        item_ids: itemIds,
        expected_catalog_revision: expectedCatalogRevision,
        expected_outfit_revision: expectedOutfitRevision,
      };
      return invokeCommand<CreateManualOutfitV1Response>(
        "create_manual_outfit_v1",
        { request },
      );
    },

    async listOutfits(cursor = null, limit = 20) {
      const request: ListOutfitsV1Request = {
        ...envelope(),
        cursor,
        limit,
      };
      return invokeCommand<ListOutfitsV1Response>("list_outfits_v1", {
        request,
      });
    },

    async getCollage(outfitId) {
      const request: GetOutfitCollageV1Request = {
        ...envelope(),
        outfit_id: outfitId,
      };
      return invokeCommand<GetOutfitCollageV1Response>(
        "get_outfit_collage_v1",
        { request },
      );
    },
  };
}

export const outfitBridge = createOutfitBridge(productionInvoke);
