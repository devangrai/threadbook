import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  BackupRecordV1,
  CreateBackupV1Request,
  CreateBackupV1Response,
  ListBackupsV1Request,
  ListBackupsV1Response,
  PrepareRestoreV1Request,
  PrepareRestoreV1Response,
} from "./generated/contracts";

export type BackupRecord = {
  id: string;
  reason: BackupRecordV1["reason"];
  createdAt: string;
  expiresAt: string;
  manifestSha256: string;
  databaseSchemaVersion: number;
  assetCount: number;
  totalBytes: number;
};

export type PrepareRestoreResult = {
  restartRequired: true;
  safetyBackupId: string;
};

export type BackupBridge = {
  list: () => Promise<BackupRecord[]>;
  create: () => Promise<BackupRecord>;
  prepareRestore: (backup: BackupRecord) => Promise<PrepareRestoreResult>;
};

type RequestIdFactory = () => string;

export function createBackupBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): BackupBridge {
  const envelope = () => ({
    schema_version: 1 as const,
    request_id: createRequestId(),
  });

  return {
    async list() {
      const records: BackupRecord[] = [];
      let cursor: string | null = null;
      do {
        const request: ListBackupsV1Request = {
          ...envelope(),
          cursor,
          limit: 50,
        };
        const response = await invokeCommand<ListBackupsV1Response>(
          "list_backups_v1",
          { request },
        );
        records.push(...response.backups.map(mapBackup));
        cursor = response.next_cursor;
      } while (cursor !== null);
      return records;
    },

    async create() {
      const request: CreateBackupV1Request = {
        ...envelope(),
        reason: "manual",
      };
      const response = await invokeCommand<CreateBackupV1Response>(
        "create_backup_v1",
        { request },
      );
      return mapBackup(response.backup);
    },

    async prepareRestore(backup) {
      const request: PrepareRestoreV1Request = {
        ...envelope(),
        backup_id: backup.id,
        expected_manifest_sha256: backup.manifestSha256,
      };
      const response = await invokeCommand<PrepareRestoreV1Response>(
        "prepare_restore_v1",
        { request },
      );
      if (!response.restart_required) {
        throw new Error("Restore preparation did not require a restart.");
      }
      return {
        restartRequired: true,
        safetyBackupId: response.safety_backup_id,
      };
    },
  };
}

function mapBackup(record: BackupRecordV1): BackupRecord {
  return {
    id: record.backup_id,
    reason: record.reason,
    createdAt: record.created_at,
    expiresAt: record.expires_at,
    manifestSha256: record.manifest_sha256,
    databaseSchemaVersion: record.database_schema_version,
    assetCount: record.asset_count,
    totalBytes: record.total_bytes,
  };
}

export const backupBridge = createBackupBridge(productionInvoke);
