import { describe, expect, it, vi } from "vitest";

import type {
  OutfitRecommendationEnvelopeV1,
  PreviewOutfitRecommendationV1Response,
  RequestOutfitRecommendationV1Response,
} from "./generated/contracts";
import type { InvokeCommand } from "./invoke-transport";
import { createOutfitRecommendationBridge } from "./outfit-recommendation-bridge";

describe("outfit recommendation bridge", () => {
  it("uses only the two v1 commands and reuses the exact approved envelope", async () => {
    const previewResponse = {
      schema_version: 1,
      request_id: "request-preview",
      provider_status: "ready",
      approval: {
        approval_id: "approval-1",
        expires_at: "2026-07-15T12:00:00Z",
        single_use: true,
        catalog_revision: 8,
        outfit_revision: 3,
      },
    } as PreviewOutfitRecommendationV1Response;
    const requestResponse = {
      schema_version: 1,
      request_id: "request-send",
      outcome: {
        outcome: "historical_stale",
        catalog_changed: true,
        outfit_changed: false,
      },
    } as RequestOutfitRecommendationV1Response;
    const invoke = vi
      .fn()
      .mockResolvedValueOnce(previewResponse)
      .mockResolvedValueOnce(requestResponse);
    const ids = ["request-preview", "request-send"];
    const bridge = createOutfitRecommendationBridge(
      invoke as unknown as InvokeCommand,
      () => ids.shift() ?? "unexpected",
    );
    const envelope: OutfitRecommendationEnvelopeV1 = {
      prompt: "A relaxed dinner outfit",
      credential_id: "credential-1",
      constraints: {
        occasion: "date",
        temperature_c: 18,
        precipitation: "none",
      },
      excluded_item_ids: ["item-3"],
      requested_proposal_count: 3,
      expected_catalog_revision: 8,
      expected_outfit_revision: 3,
      retention: {
        mode: "MAM",
        provenance: "OpenAI project data controls",
      },
    };

    const preview = await bridge.preview(envelope);
    await bridge.request(preview.approval.approval_id, envelope);

    expect(invoke).toHaveBeenCalledTimes(2);
    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "preview_outfit_recommendation_v1",
      {
        request: {
          schema_version: 1,
          request_id: "request-preview",
          envelope,
        },
      },
    );
    expect(invoke).toHaveBeenNthCalledWith(
      2,
      "request_outfit_recommendation_v1",
      {
        request: {
          schema_version: 1,
          request_id: "request-send",
          approval_id: "approval-1",
          envelope,
        },
      },
    );
    expect(invoke.mock.calls[0][1].request.envelope).toBe(envelope);
    expect(invoke.mock.calls[1][1].request.envelope).toBe(envelope);
  });
});
