import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  PreviewReceiptIntelligenceV1Request,
  PreviewReceiptIntelligenceV1Response,
  ReceiptIntelligenceAvailabilityV1,
  ReceiptIntelligenceAttemptStateV1,
  ReceiptIntelligenceClassificationV1,
  ReceiptIntelligenceOutcomeV1,
  ReceiptIntelligencePreviewV1,
  ReceiptIntelligenceSummaryV1,
  RequestReceiptIntelligenceV1Request,
  RequestReceiptIntelligenceV1Response,
  ListReceiptIntelligenceV1Request,
  ListReceiptIntelligenceV1Response,
} from "./generated/contracts";

type RequestIdFactory = () => string;

export type ReceiptIntelligenceAttemptView = {
  attempt_id: string;
  source_id: string;
  state: ReceiptIntelligenceAttemptStateV1;
  classification: ReceiptIntelligenceClassificationV1 | null;
  review_available: boolean;
  failure_code: string | null;
};

export type ReceiptIntelligenceStatusView = {
  availability: ReceiptIntelligenceAvailabilityV1;
  attempt: ReceiptIntelligenceAttemptView | null;
};

export type ReceiptIntelligenceBridge = {
  preview: (
    sourceId: string,
  ) => Promise<PreviewReceiptIntelligenceV1Response>;
  request: (
    preview: ReceiptIntelligencePreviewV1,
  ) => Promise<ReceiptIntelligenceAttemptView>;
  latest: (
    sourceId: string,
  ) => Promise<ReceiptIntelligenceStatusView>;
};

export function createReceiptIntelligenceBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): ReceiptIntelligenceBridge {
  return {
    async preview(sourceId) {
      const request: PreviewReceiptIntelligenceV1Request = {
        schema_version: 1,
        request_id: createRequestId(),
        source_id: sourceId,
      };
      return invokeCommand<PreviewReceiptIntelligenceV1Response>(
        "preview_receipt_intelligence_v1",
        { request },
      );
    },

    async request(preview) {
      const request: RequestReceiptIntelligenceV1Request = {
        schema_version: 1,
        request_id: createRequestId(),
        consent: {
          affirmative: true,
          preview,
        },
      };
      const response = await invokeCommand<RequestReceiptIntelligenceV1Response>(
        "request_receipt_intelligence_v1",
        { request },
      );
      return outcomeView(response.outcome, preview.consent_envelope.source_id);
    },

    async latest(sourceId) {
      const request: ListReceiptIntelligenceV1Request = {
        schema_version: 1,
        request_id: createRequestId(),
        state: null,
        classification: null,
        cursor: null,
        limit: 100,
      };
      const response = await invokeCommand<ListReceiptIntelligenceV1Response>(
        "list_receipt_intelligence_v1",
        { request },
      );
      const attempt = response.attempts.find(
        (candidate) => candidate.source_id === sourceId,
      );
      return {
        availability: response.availability,
        attempt: attempt ? summaryView(attempt) : null,
      };
    },
  };
}

function summaryView(
  summary: ReceiptIntelligenceSummaryV1,
): ReceiptIntelligenceAttemptView {
  return {
    attempt_id: summary.attempt_id,
    source_id: summary.source_id,
    state: summary.state,
    classification: summary.classification?.classification ?? null,
    review_available: summary.classification?.order_evidence_id != null,
    failure_code: summary.failure?.code ?? null,
  };
}

function outcomeView(
  outcome: ReceiptIntelligenceOutcomeV1,
  fallbackSourceId: string,
): ReceiptIntelligenceAttemptView {
  switch (outcome.outcome) {
    case "reserved":
      return {
        attempt_id: outcome.reservation.attempt_id,
        source_id: outcome.reservation.source_id,
        state: "not_sent",
        classification: null,
        review_available: false,
        failure_code: null,
      };
    case "dispatched":
      return emptyOutcome(outcome.attempt_id, fallbackSourceId, "dispatched");
    case "completed":
      return {
        attempt_id: outcome.classification.attempt_id,
        source_id: outcome.classification.source_id,
        state: "completed",
        classification: outcome.classification.classification,
        review_available: outcome.classification.order_evidence_id != null,
        failure_code: null,
      };
    case "refused":
      return emptyOutcome(outcome.attempt_id, fallbackSourceId, "refused");
    case "failed":
      return {
        ...emptyOutcome(outcome.attempt_id, fallbackSourceId, "failed"),
        failure_code: outcome.failure.code,
      };
    case "outcome_unknown":
      return emptyOutcome(
        outcome.attempt_id,
        fallbackSourceId,
        "outcome_unknown",
      );
  }
}

function emptyOutcome(
  attemptId: string,
  sourceId: string,
  state: ReceiptIntelligenceAttemptStateV1,
): ReceiptIntelligenceAttemptView {
  return {
    attempt_id: attemptId,
    source_id: sourceId,
    state,
    classification: null,
    review_available: false,
    failure_code: null,
  };
}

export const receiptIntelligenceBridge = createReceiptIntelligenceBridge(
  productionInvoke,
);
