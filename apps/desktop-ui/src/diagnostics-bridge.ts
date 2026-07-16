import { save } from "@tauri-apps/plugin-dialog";

import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  ExportDiagnosticsV1Request,
  ExportDiagnosticsV1Response,
} from "./generated/contracts";

export type DiagnosticsExportResult =
  | { cancelled: true }
  | {
      cancelled: false;
      generatedAt: string;
      sha256: string;
      byteLength: number;
    };

export type DiagnosticsBridge = {
  export: () => Promise<DiagnosticsExportResult>;
};

type RequestIdFactory = () => string;
type SaveDestination = () => Promise<string | null>;

export function createDiagnosticsBridge(
  invokeCommand: InvokeCommand,
  chooseDestination: SaveDestination,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): DiagnosticsBridge {
  return {
    async export() {
      const destination = await chooseDestination();
      if (destination === null) {
        return { cancelled: true };
      }
      const request: ExportDiagnosticsV1Request = {
        schema_version: 1,
        request_id: createRequestId(),
        destination_path: destination,
      };
      const response = await invokeCommand<ExportDiagnosticsV1Response>(
        "export_diagnostics_v1",
        { request },
      );
      if (
        response.schema_version !== 1 ||
        response.request_id !== request.request_id ||
        response.complete !== true ||
        response.media_type !== "application/json" ||
        !Number.isSafeInteger(response.byte_length) ||
        response.byte_length <= 0 ||
        !/^[0-9a-f]{64}$/.test(response.sha256)
      ) {
        throw new Error("Diagnostics export returned an invalid response.");
      }
      return {
        cancelled: false,
        generatedAt: response.generated_at,
        sha256: response.sha256,
        byteLength: response.byte_length,
      };
    },
  };
}

async function chooseDiagnosticsDestination(): Promise<string | null> {
  const destination = await save({
    title: "Export diagnostics",
    defaultPath: diagnosticsFilename(new Date()),
    canCreateDirectories: true,
    filters: [{ name: "JSON", extensions: ["json"] }],
  });
  return typeof destination === "string" ? destination : null;
}

function diagnosticsFilename(now: Date): string {
  const timestamp = now
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}Z$/, "Z");
  return `wardrobe-diagnostics-${timestamp}.json`;
}

export const diagnosticsBridge = createDiagnosticsBridge(
  productionInvoke,
  chooseDiagnosticsDestination,
);
