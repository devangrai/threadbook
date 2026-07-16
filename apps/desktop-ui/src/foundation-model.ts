import type { LocalOnlyAuthorityHealthV1 } from "./generated/contracts";

export type Readiness = "ready" | "unavailable";

export type LocalStorageStatus = {
  database: Readiness;
  blobs: Readiness;
};

export type CredentialReference = {
  id: string;
  provider: string;
  displayLabel: string;
  status: "active" | "pending_save" | "pending_delete" | "failed";
};

export type RecentJob = {
  id: string;
  kind: string;
  status: "queued" | "running" | "succeeded" | "failed";
  updatedAt: string;
  failureCode?: string;
  userAction?: string;
};

export type FoundationSnapshot = {
  itemCount: number;
  localOnly: boolean;
  revision: number;
  authorityHealth: LocalOnlyAuthorityHealthV1;
  storage: LocalStorageStatus;
  deletionHealth: {
    status: "none" | "in_progress" | "overdue" | "needs_attention";
    deadlineAt: string | null;
    count: number;
  };
  credentials: CredentialReference[];
  recentJobs: RecentJob[];
};

export type FoundationError = {
  code: string;
  retryable: boolean;
  user_action?: string;
};

export function formatJobKind(kind: string): string {
  return kind
    .replace(/_v\d+$/u, "")
    .split("_")
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

export function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "Unknown time";
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function formatError(error: unknown): string {
  if (isFoundationError(error)) {
    if (error.user_action) {
      return formatAction(error.user_action);
    }
    return formatAction(error.code);
  }

  return "Local data is unavailable.";
}

export function formatAction(action: string): string {
  return action
    .split("_")
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

export function authorityHealthLabel(
  health: LocalOnlyAuthorityHealthV1,
): string {
  switch (health) {
    case "persisted":
      return "Saved";
    case "fail_closed_default":
      return "Fail-closed default";
    case "fail_closed_uncertain":
      return "Fail-closed pending repair";
  }

  throw new Error("Unsupported local-only authority health");
}

export function isConflictError(error: unknown): boolean {
  return (
    !!error &&
    typeof error === "object" &&
    "code" in error &&
    (error as { code?: unknown }).code === "request_conflict"
  );
}

export function credentialStatusLabel(
  status: CredentialReference["status"],
): string {
  switch (status) {
    case "active":
      return "Saved";
    case "pending_save":
      return "Saving";
    case "pending_delete":
      return "Removing";
    case "failed":
      return "Needs attention";
  }
}

function isFoundationError(value: unknown): value is FoundationError {
  if (!value || typeof value !== "object") {
    return false;
  }

  const candidate = value as Partial<FoundationError>;
  return (
    typeof candidate.code === "string" &&
    typeof candidate.retryable === "boolean" &&
    (candidate.user_action === undefined ||
      typeof candidate.user_action === "string")
  );
}
