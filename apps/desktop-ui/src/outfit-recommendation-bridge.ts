import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  CredentialReferenceV1,
  GetFoundationSnapshotV1Response,
  OutfitRecommendationApprovalId,
  OutfitRecommendationEnvelopeV1,
  PreviewOutfitRecommendationV1Request,
  PreviewOutfitRecommendationV1Response,
  RequestOutfitRecommendationV1Request,
  RequestOutfitRecommendationV1Response,
} from "./generated/contracts";

type RequestIdFactory = () => string;

export type OutfitRecommendationBridge = {
  preview: (
    envelope: OutfitRecommendationEnvelopeV1,
  ) => Promise<PreviewOutfitRecommendationV1Response>;
  request: (
    approvalId: OutfitRecommendationApprovalId,
    envelope: OutfitRecommendationEnvelopeV1,
  ) => Promise<RequestOutfitRecommendationV1Response>;
};

export function createOutfitRecommendationBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): OutfitRecommendationBridge {
  return {
    async preview(envelope) {
      const request: PreviewOutfitRecommendationV1Request = {
        schema_version: 1,
        request_id: createRequestId(),
        envelope,
      };
      return invokeCommand<PreviewOutfitRecommendationV1Response>(
        "preview_outfit_recommendation_v1",
        { request },
      );
    },

    async request(approvalId, envelope) {
      const request: RequestOutfitRecommendationV1Request = {
        schema_version: 1,
        request_id: createRequestId(),
        approval_id: approvalId,
        envelope,
      };
      return invokeCommand<RequestOutfitRecommendationV1Response>(
        "request_outfit_recommendation_v1",
        { request },
      );
    },
  };
}

export const outfitRecommendationBridge =
  createOutfitRecommendationBridge(productionInvoke);

export async function loadOutfitRecommendationCredentials(): Promise<
  CredentialReferenceV1[]
> {
  const response = await productionInvoke<GetFoundationSnapshotV1Response>(
    "get_foundation_snapshot_v1",
    {
      request: {
        schema_version: 1,
        request_id: crypto.randomUUID(),
      },
    },
  );
  return response.snapshot.credential_references.filter(
    (credential) =>
      credential.provider === "open_ai" && credential.status === "active",
  );
}
