import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  CatalogItemV1,
  DecideEvidenceV1Request,
  DecideEvidenceV1Response,
  DeletionPlanItemV1,
  ExecuteDeletionV1Request,
  ExecuteDeletionV1Response,
  ImportLocalSourcesV1Request,
  ImportLocalSourcesV1Response,
  ImportSummaryV1,
  ItemAttributesV1,
  ListCatalogV1Request,
  ListCatalogV1Response,
  ListDeletionPlanItemsV1Request,
  ListDeletionPlanItemsV1Response,
  ListInboxV1Request,
  ListInboxV1Response,
  MergeItemsV1Request,
  MergeItemsV1Response,
  PreviewDeletionV1Request,
  PreviewDeletionV1Response,
  RefreshImportRootsV1Request,
  RefreshImportRootsV1Response,
  SaveItemV1Request,
  SaveItemV1Response,
  SplitItemV1Request,
  SplitItemV1Response,
  UndoDecisionV1Request,
  UndoDecisionV1Response,
} from "./generated/contracts";
import type {
  CatalogAttributes,
  CatalogItem,
  CatalogPage,
  DecisionReceipt,
  DeletionPlan,
  DeletionPlanClass,
  DeletionResult,
  Evidence,
  ImportResult,
  InboxPage,
} from "./catalog-model";

type RequestIdFactory = () => string;
type InboxState = "unresolved" | "quarantine";

export type CatalogBridge = {
  listCatalog: (cursor?: string | null, limit?: number) => Promise<CatalogPage>;
  listInbox: (
    state: InboxState,
    cursor?: string | null,
    limit?: number,
  ) => Promise<InboxPage>;
  importLocalSources: (paths: string[]) => Promise<ImportResult>;
  refreshImportRoots: (rootIds: string[]) => Promise<ImportResult>;
  saveItem: (
    itemId: string | null,
    attributes: CatalogAttributes,
    evidenceIds: string[],
    expectedRevision: number,
  ) => Promise<DecisionReceipt>;
  decideEvidence: (
    evidenceId: string,
    decision: "assign" | "reject" | "defer",
    itemId: string | null,
    expectedRevision: number,
  ) => Promise<DecisionReceipt>;
  mergeItems: (
    itemIds: string[],
    targetAttributes: CatalogAttributes,
    expectedRevision: number,
  ) => Promise<DecisionReceipt>;
  splitItem: (
    itemId: string,
    groups: Array<{
      attributes: CatalogAttributes;
      evidence_ids: string[];
    }>,
    expectedRevision: number,
  ) => Promise<DecisionReceipt>;
  undoDecision: (
    decisionId: string,
    expectedRevision: number,
  ) => Promise<DecisionReceipt>;
  previewDeletion: (
    targetKind: "item" | "import_root",
    targetId: string,
  ) => Promise<DeletionPlan>;
  listDeletionPlanItems: (
    snapshotToken: string,
    className: string,
    cursor: string | null,
  ) => Promise<DeletionPlanClass>;
  executeDeletion: (
    plan: DeletionPlan,
    executionRequestId: string,
  ) => Promise<DeletionResult>;
};

export function createCatalogBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): CatalogBridge {
  const envelope = () => ({
    schema_version: 1 as const,
    request_id: createRequestId(),
  });

  return {
    async listCatalog(cursor = null, limit = 20) {
      const request: ListCatalogV1Request = {
        ...envelope(),
        cursor,
        limit,
      };
      const response = await invokeCommand<ListCatalogV1Response>(
        "list_catalog_v1",
        { request },
      );
      return {
        items: response.items.map(mapCatalogItem),
        total_count: response.total_count,
        catalog_revision: response.catalog_revision,
        evidence_generation: response.evidence_generation,
        next_cursor: response.next_cursor,
      };
    },

    async listInbox(state, cursor = null, limit = 20) {
      const request: ListInboxV1Request = {
        ...envelope(),
        state,
        cursor,
        limit,
      };
      const response = await invokeCommand<ListInboxV1Response>(
        "list_inbox_v1",
        { request },
      );
      return {
        items: [
          ...response.evidence.map<Evidence>((value) => ({
            evidence_id: value.evidence_id,
            state: "unresolved",
            kind: value.kind === "image" ? "image" : "email",
            display_name: value.review_label,
            source_label: value.source.provenance_label,
            imported_at: "",
            quarantine_reason: null,
            decision_capable: true,
          })),
          ...response.quarantines.map<Evidence>((value) => ({
            evidence_id: value.quarantine_id,
            state: "quarantine",
            kind: value.source.kind === "image_file" ? "image" : "email",
            display_name: value.source.provenance_label,
            source_label: value.source.provenance_label,
            imported_at: "",
            quarantine_reason: value.code,
            decision_capable: false,
          })),
        ],
        total_count: response.total_count,
        catalog_revision: response.catalog_revision,
        evidence_generation: response.evidence_generation,
        next_cursor: response.next_cursor,
      };
    },

    async importLocalSources(paths) {
      const request: ImportLocalSourcesV1Request = {
        ...envelope(),
        paths,
      };
      const response = await invokeCommand<ImportLocalSourcesV1Response>(
        "import_local_sources_v1",
        { request },
      );
      return mapImportResult(response.summaries);
    },

    async refreshImportRoots(rootIds) {
      const request: RefreshImportRootsV1Request = {
        ...envelope(),
        import_root_ids: rootIds,
      };
      const response = await invokeCommand<RefreshImportRootsV1Response>(
        "refresh_import_roots_v1",
        { request },
      );
      return mapImportResult(response.summaries);
    },

    async saveItem(itemId, attributes, evidenceIds, expectedRevision) {
      const request: SaveItemV1Request = {
        ...envelope(),
        item_id: itemId,
        attributes: toWireAttributes(attributes),
        evidence_ids: evidenceIds,
        expected_catalog_revision: expectedRevision,
      };
      const response = await invokeCommand<SaveItemV1Response>("save_item_v1", {
        request,
      });
      return receipt(response);
    },

    async decideEvidence(evidenceId, decision, itemId, expectedRevision) {
      const request: DecideEvidenceV1Request = {
        ...envelope(),
        evidence_id: evidenceId,
        action: decision,
        item_id: itemId,
        expected_catalog_revision: expectedRevision,
      };
      const response = await invokeCommand<DecideEvidenceV1Response>(
        "decide_evidence_v1",
        { request },
      );
      return receipt(response);
    },

    async mergeItems(itemIds, targetAttributes, expectedRevision) {
      const request: MergeItemsV1Request = {
        ...envelope(),
        item_ids: itemIds,
        target_attributes: toWireAttributes(targetAttributes),
        expected_catalog_revision: expectedRevision,
      };
      const response = await invokeCommand<MergeItemsV1Response>(
        "merge_items_v1",
        { request },
      );
      return receipt(response);
    },

    async splitItem(itemId, groups, expectedRevision) {
      const request: SplitItemV1Request = {
        ...envelope(),
        item_id: itemId,
        groups: groups.map((group) => ({
          attributes: toWireAttributes(group.attributes),
          evidence_ids: group.evidence_ids,
        })),
        expected_catalog_revision: expectedRevision,
      };
      const response = await invokeCommand<SplitItemV1Response>(
        "split_item_v1",
        { request },
      );
      return receipt(response);
    },

    async undoDecision(decisionId, expectedRevision) {
      const request: UndoDecisionV1Request = {
        ...envelope(),
        decision_id: decisionId,
        expected_catalog_revision: expectedRevision,
      };
      const response = await invokeCommand<UndoDecisionV1Response>(
        "undo_decision_v1",
        { request },
      );
      return receipt(response);
    },

    async previewDeletion(targetKind, targetId) {
      const request: PreviewDeletionV1Request = {
        ...envelope(),
        target_kind: targetKind,
        target_id: targetId,
        limit: 20,
      };
      const response = await invokeCommand<PreviewDeletionV1Response>(
        "preview_deletion_v1",
        { request },
      );
      return {
        preview_snapshot_token: response.preview_snapshot_token,
        plan_sha256: response.plan_sha256,
        prepared_at: response.prepared_at,
        expires_at: response.expires_at,
        revisions: response.revisions,
        overall_count: response.overall_count,
        retained_shared_blob_count: response.retained_shared_blob_count,
        unique_blob_count: response.unique_blob_count,
        unique_blob_bytes: response.unique_blob_bytes,
        backup_retention: response.backup_retention,
        remote_retention: response.remote_retention,
        classes: response.counts.map((count) => ({
          class_name: count.class,
          count: Number(count.count),
          items:
            count.class === response.first_class
              ? response.first_page.map(mapDeletionRow)
              : [],
          next_cursor:
            count.class === response.first_class ? response.next_cursor : null,
        })),
      };
    },

    async listDeletionPlanItems(snapshotToken, className, cursor) {
      const request: ListDeletionPlanItemsV1Request = {
        ...envelope(),
        preview_snapshot_token: snapshotToken,
        class:
          className as ListDeletionPlanItemsV1Request["class"],
        cursor,
        limit: 20,
      };
      const response = await invokeCommand<ListDeletionPlanItemsV1Response>(
        "list_deletion_plan_items_v1",
        { request },
      );
      return {
        class_name: response.class,
        count: response.total_count,
        items: response.items.map(mapDeletionRow),
        next_cursor: response.next_cursor,
      };
    },

    async executeDeletion(plan, executionRequestId) {
      const request: ExecuteDeletionV1Request = {
        schema_version: 1,
        request_id: executionRequestId,
        preview_snapshot_token: plan.preview_snapshot_token,
        plan_sha256: plan.plan_sha256,
        expected_revisions: plan.revisions,
        confirmation: "delete_active_local_data",
      };
      const response = await invokeCommand<ExecuteDeletionV1Response>(
        "execute_deletion_v1",
        { request },
      );
      if (!response.complete) {
        throw new Error("Deletion command returned before completion");
      }
      return {
        run_id: response.run_id,
        complete: response.complete,
        accepted_at: response.accepted_at,
        deadline_at: response.deadline_at,
        completed_at: response.completed_at,
        deleted_local_record_count: response.deleted_local_record_count,
        deleted_unique_blob_count: response.deleted_unique_blob_count,
        deleted_unique_blob_bytes: response.deleted_unique_blob_bytes,
        retained_shared_blob_count: response.retained_shared_blob_count,
        backup_retention: response.backup_retention,
        remote_retention: response.remote_retention,
        replay_status: response.replay_status,
      };
    },
  };
}

function toWireAttributes(attributes: CatalogAttributes): ItemAttributesV1 {
  return {
    display_name: attributes.display_name,
    category: attributes.category,
    subcategory: null,
    brand: null,
    primary_color: attributes.color || null,
    size: null,
    notes: attributes.notes || null,
    tags: [],
  };
}

function mapCatalogItem(item: CatalogItemV1): CatalogItem {
  return {
    item_id: item.item_id,
    display_name: item.attributes.display_name,
    category: item.attributes.category,
    color: item.attributes.primary_color ?? "",
    notes: item.attributes.notes ?? "",
    evidence_ids: item.evidence_ids,
    updated_at: "",
    last_decision_id: item.last_decision_id,
  };
}

function mapImportResult(summaries: ImportSummaryV1[]): ImportResult {
  const roots = new Map<
    string,
    ImportResult["roots"][number]
  >();
  for (const summary of summaries) {
    if (!summary.import_root_id) continue;
    roots.set(summary.import_root_id, {
      root_id: summary.import_root_id,
      display_name: `Folder ${summary.import_root_id.slice(0, 8)}`,
      status: summary.unavailable > 0 ? "unavailable" : "available",
    });
  }
  return {
    summaries: summaries.map((summary) => ({
      source_label: summary.source_id
        ? `Source ${summary.source_id.slice(0, 8)}`
        : "Local source",
      imported: summary.imported,
      reused: summary.reused,
      quarantined: summary.quarantined,
      skipped: summary.skipped,
      unavailable: summary.unavailable,
      root_id: summary.import_root_id,
    })),
    roots: [...roots.values()],
  };
}

function receipt(response: {
  decision: { decision_id: string };
  new_catalog_revision: number;
}): DecisionReceipt {
  return {
    decision_id: response.decision.decision_id,
    new_catalog_revision: response.new_catalog_revision,
  };
}

function mapDeletionRow(item: DeletionPlanItemV1) {
  return {
    id: item.record_id,
    label: item.display_label,
  };
}

export const catalogBridge = createCatalogBridge(productionInvoke);
