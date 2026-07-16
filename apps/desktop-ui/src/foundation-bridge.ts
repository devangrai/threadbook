import type {
  CredentialProviderV1,
  CredentialStatusV1,
  DeleteCredentialV1Request,
  DeleteCredentialV1Response,
  GetFoundationSnapshotV1Request,
  GetFoundationSnapshotV1Response,
  JobStatusV1,
  RunStorageCheckV1Request,
  RunStorageCheckV1Response,
  SaveCredentialV1Request,
  SaveCredentialV1Response,
  SetLocalOnlyV1Request,
  SetLocalOnlyV1Response,
  StorageStatusV1,
} from "./generated/contracts";
import type {
  CredentialReference,
  FoundationSnapshot,
  RecentJob,
  Readiness,
} from "./foundation-model";
import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

type RequestIdFactory = () => string;

export type FoundationBridge = {
  getSnapshot: () => Promise<FoundationSnapshot>;
  setLocalOnly: (
    enabled: boolean,
    expectedRevision: number,
  ) => Promise<SetLocalOnlyV1Response>;
  runStorageCheck: () => Promise<boolean>;
  saveCredential: (
    provider: CredentialProviderV1,
    displayLabel: string,
    secret: string,
  ) => Promise<void>;
  deleteCredential: (credentialId: string) => Promise<void>;
};

export function createFoundationBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): FoundationBridge {
  return {
    async getSnapshot() {
      const request: GetFoundationSnapshotV1Request = requestEnvelope(
        createRequestId,
      );
      const response =
        await invokeCommand<GetFoundationSnapshotV1Response>(
          "get_foundation_snapshot_v1",
          { request },
        );
      return mapSnapshot(response);
    },

    async setLocalOnly(enabled, expectedRevision) {
      const request: SetLocalOnlyV1Request = {
        ...requestEnvelope(createRequestId),
        enabled,
        expected_revision: expectedRevision,
      };
      return invokeCommand<SetLocalOnlyV1Response>("set_local_only_v1", {
        request,
      });
    },

    async runStorageCheck() {
      const request: RunStorageCheckV1Request =
        requestEnvelope(createRequestId);
      const response = await invokeCommand<RunStorageCheckV1Response>(
        "run_storage_check_v1",
        { request },
      );
      return response.replay_status === "replayed";
    },

    async saveCredential(provider, displayLabel, secret) {
      const request: SaveCredentialV1Request = {
        ...requestEnvelope(createRequestId),
        provider,
        display_label: displayLabel,
        secret,
      };
      await invokeCommand<SaveCredentialV1Response>("save_credential_v1", {
        request,
      });
    },

    async deleteCredential(credentialId) {
      const request: DeleteCredentialV1Request = {
        ...requestEnvelope(createRequestId),
        credential_id: credentialId,
      };
      await invokeCommand<DeleteCredentialV1Response>(
        "delete_credential_v1",
        { request },
      );
    },
  };
}

export function mapSnapshot(
  response: GetFoundationSnapshotV1Response,
): FoundationSnapshot {
  const { snapshot } = response;
  const readiness = mapReadiness(snapshot.local_settings.storage_status);

  return {
    itemCount: snapshot.catalog.items.length,
    localOnly: snapshot.local_settings.local_only,
    revision: snapshot.local_settings.revision,
    authorityHealth: snapshot.local_settings.authority_health,
    storage: {
      database: readiness,
      blobs: readiness,
    },
    deletionHealth: {
      status: snapshot.local_settings.deletion_health.status,
      deadlineAt: snapshot.local_settings.deletion_health.deadline_at,
      count:
        snapshot.local_settings.deletion_health.counts.in_progress +
        snapshot.local_settings.deletion_health.counts.overdue +
        snapshot.local_settings.deletion_health.counts.needs_attention,
    },
    credentials: snapshot.credential_references.map(mapCredential),
    recentJobs: snapshot.recent_jobs.map(mapJob),
  };
}

export async function setLocalOnlyAndRefresh(
  bridge: FoundationBridge,
  enabled: boolean,
  expectedRevision: number,
  publishSnapshot: (snapshot: FoundationSnapshot) => void,
): Promise<FoundationSnapshot> {
  try {
    await bridge.setLocalOnly(enabled, expectedRevision);
  } catch (error) {
    try {
      const snapshot = await bridge.getSnapshot();
      publishSnapshot(snapshot);
    } catch {
      // Preserve the authoritative mode-change error for the caller.
    }
    throw error;
  }

  const snapshot = await bridge.getSnapshot();
  publishSnapshot(snapshot);
  return snapshot;
}

function requestEnvelope(createRequestId: RequestIdFactory) {
  return {
    schema_version: 1 as const,
    request_id: createRequestId(),
  };
}

function mapReadiness(status: StorageStatusV1): Readiness {
  return status === "ready" ? "ready" : "unavailable";
}

function mapCredential(
  credential: GetFoundationSnapshotV1Response["snapshot"]["credential_references"][number],
): CredentialReference {
  return {
    id: credential.credential_id,
    provider: credential.provider === "open_ai" ? "OpenAI" : "Gmail",
    displayLabel: credential.display_label,
    status: mapCredentialStatus(credential.status),
  };
}

function mapCredentialStatus(
  status: CredentialStatusV1,
): CredentialReference["status"] {
  switch (status) {
    case "active":
      return "active";
    case "pending_save":
      return "pending_save";
    case "pending_delete":
      return "pending_delete";
    case "needs_attention":
      return "failed";
  }

  throw new Error("Unsupported credential status");
}

function mapJob(
  job: GetFoundationSnapshotV1Response["snapshot"]["recent_jobs"][number],
): RecentJob {
  return {
    id: job.job_id,
    kind: job.kind,
    status: mapJobStatus(job.status),
    updatedAt: job.updated_at,
    failureCode: job.terminal_failure?.code,
    userAction: job.terminal_failure?.user_action,
  };
}

function mapJobStatus(status: JobStatusV1): RecentJob["status"] {
  switch (status) {
    case "pending":
    case "retry_waiting":
      return "queued";
    case "running":
      return "running";
    case "succeeded":
      return "succeeded";
    case "failed":
      return "failed";
  }

  throw new Error("Unsupported job status");
}

export const foundationBridge = createFoundationBridge(productionInvoke);
