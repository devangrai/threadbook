import { describe, expect, it, vi } from "vitest";

import type { InvokeCommand } from "@wardrobe/invoke-transport";
import { createPhotoAnalysisBridge } from "./photo-analysis-bridge";

const requestId = "90000000-0000-4000-8000-000000000001";

describe("photo analysis bridge", () => {
  it("uses all seven generated commands and verifies artifact bytes", async () => {
    const invokeMock = vi.fn(async (command: string) => {
      if (command === "read_photo_artifact_v1") {
        return {
          schema_version: 1,
          request_id: requestId,
          artifact_id: "artifact-1",
          media_type: "image/png",
          width: 1,
          height: 1,
          bytes_sha256:
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          bytes: [],
        };
      }
      return {};
    });
    const bridge = createPhotoAnalysisBridge(
      invokeMock as unknown as InvokeCommand,
      () => requestId,
    );
    const rectangle = { x: 1, y: 2, width: 30, height: 40 };

    await bridge.listImportedRoots("roots:2", 10);
    await bridge.createScope("root-1", 7);
    await bridge.analyzeScope("scope-1");
    await bridge.listObservations("scope-1", "needs_review", "obs:2", 12);
    await bridge.readArtifact("artifact-1");
    await bridge.promptObservation("observation-1", rectangle);
    await bridge.reviewObservation(
      "observation-1",
      "replace_crop",
      rectangle,
      9,
    );

    expect(invokeMock.mock.calls.map(([command]) => command)).toEqual([
      "list_imported_photo_roots_v1",
      "create_photo_scope_v1",
      "analyze_photo_scope_v1",
      "list_photo_observations_v1",
      "read_photo_artifact_v1",
      "prompt_photo_observation_v1",
      "review_photo_observation_v1",
    ]);
    expect(invokeMock).toHaveBeenNthCalledWith(2, "create_photo_scope_v1", {
      request: {
        schema_version: 1,
        request_id: requestId,
        import_root_id: "root-1",
        expected_manifest_generation: 7,
      },
    });
    expect(invokeMock).toHaveBeenNthCalledWith(6, "prompt_photo_observation_v1", {
      request: {
        schema_version: 1,
        request_id: requestId,
        observation_id: "observation-1",
        box_rectangle: rectangle,
        positive_points: [],
        negative_points: [],
      },
    });
    expect(invokeMock).toHaveBeenNthCalledWith(
      7,
      "review_photo_observation_v1",
      {
        request: {
          schema_version: 1,
          request_id: requestId,
          observation_id: "observation-1",
          action: "replace_crop",
          replacement_rectangle: rectangle,
          expected_photo_revision: 9,
        },
      },
    );
  });
});
