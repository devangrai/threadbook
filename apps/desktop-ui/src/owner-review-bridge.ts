import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  CorrectPhotoOwnerV1Request,
  CorrectPhotoOwnerV1Response,
  CorrectPhotoPersonDetectionV1Request,
  CorrectPhotoPersonDetectionV1Response,
  DecidePhotoOwnerV1Request,
  DecidePhotoOwnerV1Response,
  DetectPhotoScopePeopleV1Request,
  DetectPhotoScopePeopleV1Response,
  ListPhotoOwnerReviewsV1Request,
  ListPhotoOwnerReviewsV1Response,
  PhotoOwnerActionV1,
  PhotoOwnerReviewStateV1,
  PhotoOwnerReviewV1,
  ReadPhotoOwnerPreviewV1Request,
  ReadPhotoOwnerPreviewV1Response,
  RectV1,
  RetryPhotoPersonDetectionV1Request,
  RetryPhotoPersonDetectionV1Response,
} from "./generated/contracts";
import {
  verifyOwnerPreview,
  type VerifiedOwnerPreview,
} from "./owner-review-model";

type RequestIdFactory = () => string;

export type OwnerReviewBridge = {
  detectPeople: (scopeId: string) => Promise<DetectPhotoScopePeopleV1Response>;
  listReviews: (
    state: PhotoOwnerReviewStateV1,
    cursor?: string | null,
    limit?: number,
  ) => Promise<ListPhotoOwnerReviewsV1Response>;
  readPreview: (
    ownerReviewId: string,
    previewId: string,
  ) => Promise<VerifiedOwnerPreview>;
  decideOwner: (
    review: PhotoOwnerReviewV1,
    action: PhotoOwnerActionV1,
    selectedPersonInstanceId: string | null,
  ) => Promise<DecidePhotoOwnerV1Response>;
  correctOwner: (
    review: PhotoOwnerReviewV1,
    supersededOwnerDecisionId: string,
    action: PhotoOwnerActionV1,
    selectedPersonInstanceId: string | null,
  ) => Promise<CorrectPhotoOwnerV1Response>;
  correctDetection: (
    review: PhotoOwnerReviewV1,
    manualRectangle: RectV1,
  ) => Promise<CorrectPhotoPersonDetectionV1Response>;
  retryDetection: (
    review: PhotoOwnerReviewV1,
  ) => Promise<RetryPhotoPersonDetectionV1Response>;
};

export function createOwnerReviewBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): OwnerReviewBridge {
  const envelope = () => ({
    schema_version: 1 as const,
    request_id: createRequestId(),
  });
  const revisions = (review: PhotoOwnerReviewV1) => ({
    expected_detection_revision: review.detection_revision,
    expected_owner_head_revision: review.owner_head_revision,
    expected_photo_revision: review.photo_revision,
  });

  return {
    async detectPeople(scopeId) {
      const request: DetectPhotoScopePeopleV1Request = {
        ...envelope(),
        scope_id: scopeId,
      };
      return invokeCommand<DetectPhotoScopePeopleV1Response>(
        "detect_photo_scope_people_v1",
        { request },
      );
    },

    async listReviews(state, cursor = null, limit = 20) {
      const request: ListPhotoOwnerReviewsV1Request = {
        ...envelope(),
        state,
        cursor,
        limit,
      };
      return invokeCommand<ListPhotoOwnerReviewsV1Response>(
        "list_photo_owner_reviews_v1",
        { request },
      );
    },

    async readPreview(ownerReviewId, previewId) {
      const request: ReadPhotoOwnerPreviewV1Request = {
        ...envelope(),
        owner_review_id: ownerReviewId,
        preview_id: previewId,
      };
      const response = await invokeCommand<ReadPhotoOwnerPreviewV1Response>(
        "read_photo_owner_preview_v1",
        { request },
      );
      if (
        response.owner_review_id !== ownerReviewId ||
        response.preview_id !== previewId
      ) {
        throw new Error("Owner preview references a different review.");
      }
      return verifyOwnerPreview(response);
    },

    async decideOwner(review, action, selectedPersonInstanceId) {
      const request: DecidePhotoOwnerV1Request = {
        ...envelope(),
        owner_review_id: review.owner_review_id,
        action,
        selected_person_instance_id: selectedPersonInstanceId,
        ...revisions(review),
      };
      return invokeCommand<DecidePhotoOwnerV1Response>(
        "decide_photo_owner_v1",
        { request },
      );
    },

    async correctOwner(
      review,
      supersededOwnerDecisionId,
      action,
      selectedPersonInstanceId,
    ) {
      const request: CorrectPhotoOwnerV1Request = {
        ...envelope(),
        owner_review_id: review.owner_review_id,
        superseded_owner_decision_id: supersededOwnerDecisionId,
        action,
        selected_person_instance_id: selectedPersonInstanceId,
        ...revisions(review),
      };
      return invokeCommand<CorrectPhotoOwnerV1Response>(
        "correct_photo_owner_v1",
        { request },
      );
    },

    async correctDetection(review, manualRectangle) {
      const request: CorrectPhotoPersonDetectionV1Request = {
        ...envelope(),
        owner_review_id: review.owner_review_id,
        manual_rectangle: manualRectangle,
        expected_terminal_attempt_id: review.terminal_attempt_id,
        ...revisions(review),
      };
      return invokeCommand<CorrectPhotoPersonDetectionV1Response>(
        "correct_photo_person_detection_v1",
        { request },
      );
    },

    async retryDetection(review) {
      const request: RetryPhotoPersonDetectionV1Request = {
        ...envelope(),
        owner_review_id: review.owner_review_id,
        expected_terminal_attempt_id: review.terminal_attempt_id,
        ...revisions(review),
      };
      return invokeCommand<RetryPhotoPersonDetectionV1Response>(
        "retry_photo_person_detection_v1",
        { request },
      );
    },
  };
}

export const ownerReviewBridge = createOwnerReviewBridge(productionInvoke);
