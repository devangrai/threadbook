import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  AnalyzeReceiptV1Request,
  AnalyzeReceiptV1Response,
  ApproveAndFetchReceiptImageV1Request,
  ApproveAndFetchReceiptImageV1Response,
  CorrectedReceiptOrderV1,
  ListReceiptImageCandidatesV1Request,
  ListReceiptImageCandidatesV1Response,
  ListReceiptsV1Request,
  ListReceiptsV1Response,
  ReceiptReviewActionV1,
  ReceiptStateV1,
  ReviewReceiptV1Request,
  ReviewReceiptV1Response,
} from "./generated/contracts";
import {
  verifyReceiptCitations,
  type VerifiedReceiptOrder,
} from "./receipt-model";

type RequestIdFactory = () => string;

export type AnalyzedReceipt = AnalyzeReceiptV1Response & {
  verified: VerifiedReceiptOrder;
};

export type ReceiptBridge = {
  listReceipts: (
    state: ReceiptStateV1,
    cursor?: string | null,
    limit?: number,
  ) => Promise<ListReceiptsV1Response>;
  analyzeReceipt: (sourceId: string) => Promise<AnalyzedReceipt>;
  reviewReceipt: (
    orderEvidenceId: string,
    action: ReceiptReviewActionV1,
    correctedOrder: CorrectedReceiptOrderV1 | null,
    expectedReceiptRevision: number,
  ) => Promise<ReviewReceiptV1Response>;
  listReceiptImageCandidates: (
    sourceId: string,
  ) => Promise<ListReceiptImageCandidatesV1Response>;
  approveAndFetchReceiptImage: (
    candidateId: string,
    approvedDisplayHost: string,
    candidateUrlSha256: string,
    priorAttemptId: string | null,
  ) => Promise<ApproveAndFetchReceiptImageV1Response>;
};

export function createReceiptBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): ReceiptBridge {
  const envelope = () => ({
    schema_version: 1 as const,
    request_id: createRequestId(),
  });

  return {
    async listReceipts(state, cursor = null, limit = 20) {
      const request: ListReceiptsV1Request = {
        ...envelope(),
        state,
        cursor,
        limit,
      };
      return invokeCommand<ListReceiptsV1Response>("list_receipts_v1", {
        request,
      });
    },

    async analyzeReceipt(sourceId) {
      const request: AnalyzeReceiptV1Request = {
        ...envelope(),
        source_id: sourceId,
      };
      const response = await invokeCommand<AnalyzeReceiptV1Response>(
        "analyze_receipt_v1",
        { request },
      );
      const verified = await verifyReceiptCitations(
        response.parsed,
        response.order,
      );
      return { ...response, verified };
    },

    async reviewReceipt(
      orderEvidenceId,
      action,
      correctedOrder,
      expectedReceiptRevision,
    ) {
      const request: ReviewReceiptV1Request = {
        ...envelope(),
        order_evidence_id: orderEvidenceId,
        action,
        corrected_order: correctedOrder,
        expected_receipt_revision: expectedReceiptRevision,
      };
      return invokeCommand<ReviewReceiptV1Response>("review_receipt_v1", {
        request,
      });
    },

    async listReceiptImageCandidates(sourceId) {
      const request: ListReceiptImageCandidatesV1Request = {
        ...envelope(),
        source_id: sourceId,
      };
      return invokeCommand<ListReceiptImageCandidatesV1Response>(
        "list_receipt_image_candidates_v1",
        { request },
      );
    },

    async approveAndFetchReceiptImage(
      candidateId,
      approvedDisplayHost,
      candidateUrlSha256,
      priorAttemptId,
    ) {
      const request: ApproveAndFetchReceiptImageV1Request = {
        ...envelope(),
        candidate_id: candidateId,
        approved_display_host: approvedDisplayHost,
        candidate_url_sha256: candidateUrlSha256,
        prior_attempt_id: priorAttemptId,
      };
      return invokeCommand<ApproveAndFetchReceiptImageV1Response>(
        "approve_and_fetch_receipt_image_v1",
        { request },
      );
    },
  };
}

export const receiptBridge = createReceiptBridge(productionInvoke);
