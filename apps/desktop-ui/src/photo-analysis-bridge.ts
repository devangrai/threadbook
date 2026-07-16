import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  AnalyzePhotoScopeV1Request,
  AnalyzePhotoScopeV1Response,
  CreatePhotoScopeV1Request,
  CreatePhotoScopeV1Response,
  ListImportedPhotoRootsV1Request,
  ListImportedPhotoRootsV1Response,
  ListPhotoObservationsV1Request,
  ListPhotoObservationsV1Response,
  PhotoObservationStateV1,
  PhotoReviewActionV1,
  PointV1,
  PromptPhotoObservationV1Request,
  PromptPhotoObservationV1Response,
  ReadPhotoArtifactV1Request,
  ReadPhotoArtifactV1Response,
  RectV1,
  ReviewPhotoObservationV1Request,
  ReviewPhotoObservationV1Response,
} from "./generated/contracts";
import {
  verifyPhotoArtifact,
  type VerifiedPhotoArtifact,
} from "./photo-analysis-model";

type RequestIdFactory = () => string;

export type PhotoAnalysisBridge = {
  listImportedRoots: (
    cursor?: string | null,
    limit?: number,
  ) => Promise<ListImportedPhotoRootsV1Response>;
  createScope: (
    importRootId: string,
    expectedManifestGeneration: number,
  ) => Promise<CreatePhotoScopeV1Response>;
  analyzeScope: (scopeId: string) => Promise<AnalyzePhotoScopeV1Response>;
  listObservations: (
    scopeId: string,
    state: PhotoObservationStateV1,
    cursor?: string | null,
    limit?: number,
  ) => Promise<ListPhotoObservationsV1Response>;
  readArtifact: (artifactId: string) => Promise<VerifiedPhotoArtifact>;
  promptObservation: (
    observationId: string,
    rectangle: RectV1,
    positivePoints?: PointV1[],
    negativePoints?: PointV1[],
  ) => Promise<PromptPhotoObservationV1Response>;
  reviewObservation: (
    observationId: string,
    action: PhotoReviewActionV1,
    replacementRectangle: RectV1 | null,
    expectedPhotoRevision: number,
  ) => Promise<ReviewPhotoObservationV1Response>;
};

export function createPhotoAnalysisBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): PhotoAnalysisBridge {
  const envelope = () => ({
    schema_version: 1 as const,
    request_id: createRequestId(),
  });

  return {
    async listImportedRoots(cursor = null, limit = 20) {
      const request: ListImportedPhotoRootsV1Request = {
        ...envelope(),
        cursor,
        limit,
      };
      return invokeCommand<ListImportedPhotoRootsV1Response>(
        "list_imported_photo_roots_v1",
        { request },
      );
    },

    async createScope(importRootId, expectedManifestGeneration) {
      const request: CreatePhotoScopeV1Request = {
        ...envelope(),
        import_root_id: importRootId,
        expected_manifest_generation: expectedManifestGeneration,
      };
      return invokeCommand<CreatePhotoScopeV1Response>(
        "create_photo_scope_v1",
        { request },
      );
    },

    async analyzeScope(scopeId) {
      const request: AnalyzePhotoScopeV1Request = {
        ...envelope(),
        scope_id: scopeId,
      };
      return invokeCommand<AnalyzePhotoScopeV1Response>(
        "analyze_photo_scope_v1",
        { request },
      );
    },

    async listObservations(
      scopeId,
      state,
      cursor = null,
      limit = 20,
    ) {
      const request: ListPhotoObservationsV1Request = {
        ...envelope(),
        scope_id: scopeId,
        state,
        cursor,
        limit,
      };
      return invokeCommand<ListPhotoObservationsV1Response>(
        "list_photo_observations_v1",
        { request },
      );
    },

    async readArtifact(artifactId) {
      const request: ReadPhotoArtifactV1Request = {
        ...envelope(),
        artifact_id: artifactId,
      };
      const response = await invokeCommand<ReadPhotoArtifactV1Response>(
        "read_photo_artifact_v1",
        { request },
      );
      if (response.artifact_id !== artifactId) {
        throw new Error("Photo preview references a different artifact.");
      }
      return verifyPhotoArtifact(response);
    },

    async promptObservation(
      observationId,
      rectangle,
      positivePoints = [],
      negativePoints = [],
    ) {
      const request: PromptPhotoObservationV1Request = {
        ...envelope(),
        observation_id: observationId,
        box_rectangle: rectangle,
        positive_points: positivePoints,
        negative_points: negativePoints,
      };
      return invokeCommand<PromptPhotoObservationV1Response>(
        "prompt_photo_observation_v1",
        { request },
      );
    },

    async reviewObservation(
      observationId,
      action,
      replacementRectangle,
      expectedPhotoRevision,
    ) {
      const request: ReviewPhotoObservationV1Request = {
        ...envelope(),
        observation_id: observationId,
        action,
        replacement_rectangle: replacementRectangle,
        expected_photo_revision: expectedPhotoRevision,
      };
      return invokeCommand<ReviewPhotoObservationV1Response>(
        "review_photo_observation_v1",
        { request },
      );
    },
  };
}

export const photoAnalysisBridge = createPhotoAnalysisBridge(productionInvoke);
