import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  DecideReconciliationCaseV2Request,
  DecideReconciliationCaseV2Response,
  ListReconciliationCasesV2Request,
  ListReconciliationCasesV2Response,
  OpenReconciliationCaseV2Request,
  OpenReconciliationCaseV2Response,
  ReconciliationCaseStateFilterV2,
  ReconciliationOutcomeV1,
} from "./generated/contracts";

type RequestIdFactory = () => string;

export type ReconciliationBridge = {
  openCase: (
    observationId: string,
    selectedArtifactId: string,
    expectedPhotoRevision: number,
    expectedOwnerRevision: number,
  ) => Promise<OpenReconciliationCaseV2Response>;
  listCases: (
    observationId: string,
    state?: ReconciliationCaseStateFilterV2,
    cursor?: string | null,
    limit?: number,
  ) => Promise<ListReconciliationCasesV2Response>;
  decideCase: (
    caseId: string,
    outcome: ReconciliationOutcomeV1,
    selectedCandidateId: string | null,
    expectedCaseRevision: number,
    expectedOwnerRevision: number,
    expectedPhotoRevision: number,
    expectedReconciliationRevision: number,
  ) => Promise<DecideReconciliationCaseV2Response>;
};

export function createReconciliationBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): ReconciliationBridge {
  const envelope = () => ({
    schema_version: 2 as const,
    request_id: createRequestId(),
  });

  return {
    async openCase(
      observationId,
      selectedArtifactId,
      expectedPhotoRevision,
      expectedOwnerRevision,
    ) {
      const request: OpenReconciliationCaseV2Request = {
        ...envelope(),
        observation_id: observationId,
        selected_artifact_id: selectedArtifactId,
        expected_photo_revision: expectedPhotoRevision,
        expected_owner_revision: expectedOwnerRevision,
      };
      return invokeCommand<OpenReconciliationCaseV2Response>(
        "open_reconciliation_case_v2",
        { request },
      );
    },

    async listCases(
      observationId,
      state = "all",
      cursor = null,
      limit = 20,
    ) {
      const request: ListReconciliationCasesV2Request = {
        ...envelope(),
        observation_id: observationId,
        state,
        cursor,
        limit,
      };
      return invokeCommand<ListReconciliationCasesV2Response>(
        "list_reconciliation_cases_v2",
        { request },
      );
    },

    async decideCase(
      caseId,
      outcome,
      selectedCandidateId,
      expectedCaseRevision,
      expectedOwnerRevision,
      expectedPhotoRevision,
      expectedReconciliationRevision,
    ) {
      const request: DecideReconciliationCaseV2Request = {
        ...envelope(),
        case_id: caseId,
        outcome,
        selected_candidate_id: selectedCandidateId,
        expected_case_revision: expectedCaseRevision,
        expected_owner_revision: expectedOwnerRevision,
        expected_photo_revision: expectedPhotoRevision,
        expected_reconciliation_revision: expectedReconciliationRevision,
      };
      return invokeCommand<DecideReconciliationCaseV2Response>(
        "decide_reconciliation_case_v2",
        { request },
      );
    },
  };
}

export const reconciliationBridge =
  createReconciliationBridge(productionInvoke);
