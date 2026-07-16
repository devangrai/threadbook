import { describe, expect, it, vi } from "vitest";

import type { InvokeCommand } from "./invoke-transport";
import { createTryOnBridge } from "./try-on-bridge";

describe("try-on bridge", () => {
  it("uses the four revisioned commands and keeps request identifiers local", async () => {
    const invoke = vi.fn(async (command: string) => {
      if (command === "list_try_on_portrait_candidates_v1") {
        return {
          candidates: [
            {
              source_revision_id: "portrait-revision",
              captured_at: "2026-07-10T12:00:00Z",
              media_type: "image/png",
              thumbnail_bytes: [1, 2],
            },
          ],
          next_cursor: null,
        };
      }
      if (command === "preview_try_on_v1") {
        return {
          approval: { approval_id: "approval-1" },
          disclosure: {
            provider: "openai",
            model: "gpt-image-2",
            purpose: "outfit_try_on_visualization",
            retention: {
              images_api_has_application_state_retention: false,
              default_abuse_monitoring_max_days: 30,
              model_is_zdr_compatible: true,
              compatibility_is_not_project_enrollment: true,
              csam_input_scanning_applies: true,
              flagged_inputs_may_be_retained_for_review: true,
            },
            assets: [
              {
                ordinal: 0,
                role: "portrait",
                transmitted_filename: "reference-00.png",
                portrait_source_revision_id: "portrait-revision",
                item_id: null,
                canonical_sha256: "a".repeat(64),
                media_type: "image/png",
                byte_length: 1024,
                width: 800,
                height: 1200,
              },
              {
                ordinal: 1,
                role: "garment",
                transmitted_filename: "reference-01.png",
                portrait_source_revision_id: null,
                item_id: "item-top",
                canonical_sha256: "b".repeat(64),
                media_type: "image/png",
                byte_length: 2048,
                width: 800,
                height: 1000,
              },
            ],
          },
        };
      }
      const queuedJob = {
        job_id: "job-1",
        outfit_id: "outfit-1",
        state: "queued",
        failure: null,
      };
      if (command === "submit_try_on_v1") return { job: queuedJob };
      return {
        latest_job: {
          ...queuedJob,
          state: "succeeded",
        },
        output: {
          media_type: "image/png",
          bytes: [9, 8, 7],
          label:
            "AI visualization. Not an accurate representation of fit or garment construction.",
        },
        garment_sources: [
          {
            ordinal: 1,
            item_id: "item-top",
            attributes: { display_name: "Ivory Shirt" },
            media_type: "image/png",
            bytes: [3, 2, 1],
          },
        ],
      };
    });
    const bridge = createTryOnBridge(
      invoke as unknown as InvokeCommand,
      () => "request-1",
    );
    const retention = {
      mode: "unknown" as const,
      provenance: "user_not_declared",
    };

    const portraits = await bridge.listPortraitCandidates(null, 12);
    const preview = await bridge.preview(
      "outfit-1",
      "portrait-revision",
      "credential-1",
      retention,
      7,
    );
    const submitted = await bridge.submit(preview.approvalId);
    const existing = await bridge.getOutfitTryOn("outfit-1");

    expect(portraits.candidates[0]).toMatchObject({
      sourceRevisionId: "portrait-revision",
      thumbnail: { mediaType: "image/png", bytes: [1, 2] },
    });
    expect(preview.assets[0]).toMatchObject({
      role: "portrait",
      transmittedFilename: "reference-00.png",
      localReferenceId: "portrait-revision",
    });
    expect(submitted).toMatchObject({
      state: "queued",
      statusMessage: "Visualization queued.",
    });
    expect(existing).toMatchObject({
      state: "succeeded",
      output: { mediaType: "image/png", bytes: [9, 8, 7] },
      garments: [
        {
          ordinal: 1,
          itemId: "item-top",
          label: "Ivory Shirt",
          image: { mediaType: "image/png", bytes: [3, 2, 1] },
        },
      ],
    });
    expect(invoke).toHaveBeenNthCalledWith(
      1,
      "list_try_on_portrait_candidates_v1",
      {
        request: {
          schema_version: 1,
          request_id: "request-1",
          cursor: null,
          limit: 12,
        },
      },
    );
    expect(invoke).toHaveBeenNthCalledWith(2, "preview_try_on_v1", {
      request: {
        schema_version: 1,
        request_id: "request-1",
        outfit_id: "outfit-1",
        portrait_source_revision_id: "portrait-revision",
        credential_id: "credential-1",
        retention,
        expected_outfit_revision: 7,
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(3, "submit_try_on_v1", {
      request: {
        schema_version: 1,
        request_id: "request-1",
        approval_id: "approval-1",
      },
    });
    expect(invoke).toHaveBeenNthCalledWith(4, "get_outfit_try_on_v1", {
      request: {
        schema_version: 1,
        request_id: "request-1",
        outfit_id: "outfit-1",
      },
    });
  });
});
