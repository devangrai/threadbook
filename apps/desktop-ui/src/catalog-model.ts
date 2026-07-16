import type {
  DeletionBackupRetentionV1,
  DeletionRemoteRetentionV1,
  DeletionRevisionSnapshotV1,
  ItemCategoryV1,
} from "./generated/contracts";

export type CatalogAttributes = {
  display_name: string;
  category: ItemCategoryV1;
  color: string;
  notes: string;
};

export type CatalogItem = CatalogAttributes & {
  item_id: string;
  evidence_ids: string[];
  updated_at: string;
  last_decision_id: string | null;
};

export type EvidenceState = "unresolved" | "quarantine";

export type Evidence = {
  evidence_id: string;
  state: EvidenceState;
  kind: "image" | "email";
  display_name: string;
  source_label: string;
  imported_at: string;
  quarantine_reason: string | null;
  decision_capable: boolean;
};

export type ImportRoot = {
  root_id: string;
  display_name: string;
  status: "available" | "unavailable" | "incomplete";
};

export type CatalogPage = {
  items: CatalogItem[];
  total_count: number;
  catalog_revision: number;
  evidence_generation: number;
  next_cursor: string | null;
  roots?: ImportRoot[];
};

export type InboxPage = {
  items: Evidence[];
  total_count: number;
  catalog_revision: number;
  evidence_generation: number;
  next_cursor: string | null;
};

export type DecisionReceipt = {
  decision_id: string;
  new_catalog_revision: number;
};

export type ImportSummary = {
  source_label: string;
  imported: number;
  reused: number;
  quarantined: number;
  skipped: number;
  unavailable: number;
  root_id: string | null;
};

export type ImportResult = {
  summaries: ImportSummary[];
  roots: ImportRoot[];
};

export type DeletionPlanRow = {
  id: string;
  label: string;
};

export type DeletionPlanClass = {
  class_name: string;
  count: number;
  items: DeletionPlanRow[];
  next_cursor: string | null;
};

export type DeletionPlan = {
  preview_snapshot_token: string;
  plan_sha256: string;
  prepared_at: string;
  expires_at: string;
  revisions: DeletionRevisionSnapshotV1;
  overall_count: number;
  retained_shared_blob_count: number;
  unique_blob_count: number;
  unique_blob_bytes: number;
  backup_retention: DeletionBackupRetentionV1[];
  remote_retention: DeletionRemoteRetentionV1[];
  classes: DeletionPlanClass[];
};

export type DeletionResult = {
  run_id: string;
  complete: boolean;
  accepted_at: string;
  deadline_at: string;
  completed_at: string;
  deleted_local_record_count: number;
  deleted_unique_blob_count: number;
  deleted_unique_blob_bytes: number;
  retained_shared_blob_count: number;
  backup_retention: DeletionBackupRetentionV1[];
  remote_retention: DeletionRemoteRetentionV1[];
  replay_status: "created" | "replayed";
};

export function appendUniqueById<T>(
  current: readonly T[],
  incoming: readonly T[],
  id: (value: T) => string,
): T[] {
  const values = new Map(current.map((value) => [id(value), value]));
  for (const value of incoming) {
    values.set(id(value), value);
  }
  return [...values.values()];
}

export function normalizeAttributes(
  values: CatalogAttributes,
): CatalogAttributes {
  return {
    display_name: values.display_name.trim(),
    category: values.category,
    color: values.color.trim(),
    notes: values.notes.trim(),
  };
}

export function validateAttributes(values: CatalogAttributes): string | null {
  const normalized = normalizeAttributes(values);
  if (!normalized.display_name) {
    return "Name is required.";
  }
  if (normalized.display_name.length > 80) {
    return "Name must be 80 characters or fewer.";
  }
  if (
    normalized.category.length > 80 ||
    normalized.color.length > 80 ||
    normalized.notes.length > 1000
  ) {
    return "One or more fields exceed the allowed length.";
  }
  return null;
}

export function isConflict(error: unknown): boolean {
  return (
    !!error &&
    typeof error === "object" &&
    "code" in error &&
    ["request_conflict", "snapshot_expired"].includes(
      String((error as { code?: unknown }).code),
    )
  );
}

export function displayCatalogError(error: unknown): string {
  if (isConflict(error)) {
    return "The wardrobe changed in another action. Your edits are still here; refresh and try again.";
  }
  if (
    error &&
    typeof error === "object" &&
    "user_action" in error &&
    typeof (error as { user_action?: unknown }).user_action === "string"
  ) {
    return String((error as { user_action: string }).user_action)
      .split("_")
      .map((part) => part[0]?.toUpperCase() + part.slice(1))
      .join(" ");
  }
  return "The local operation could not be completed.";
}
