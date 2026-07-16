import type {
  ConnectGmailV1Request,
  ConnectGmailV1Response,
  DisconnectGmailV1Request,
  DisconnectGmailV1Response,
  GetGmailConnectorV1Request,
  GetGmailConnectorV1Response,
  GmailConnectorLimitsV1,
  SaveGmailSettingsV1Request,
  SaveGmailSettingsV1Response,
  SyncGmailV1Request,
  SyncGmailV1Response,
} from "./generated/contracts";
import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

type RequestIdFactory = () => string;

export type GmailConnectorBridge = {
  getState: () => Promise<GetGmailConnectorV1Response>;
  saveSettings: (
    clientId: string,
    labelName: string,
    limits: GmailConnectorLimitsV1,
  ) => Promise<SaveGmailSettingsV1Response>;
  connect: () => Promise<ConnectGmailV1Response>;
  sync: () => Promise<SyncGmailV1Response>;
  disconnect: () => Promise<DisconnectGmailV1Response>;
};

export function createGmailConnectorBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): GmailConnectorBridge {
  const envelope = () => ({
    schema_version: 1 as const,
    request_id: createRequestId(),
  });

  return {
    async getState() {
      const request: GetGmailConnectorV1Request = envelope();
      return invokeCommand<GetGmailConnectorV1Response>(
        "get_gmail_connector_v1",
        { request },
      );
    },

    async saveSettings(clientId, labelName, limits) {
      const request: SaveGmailSettingsV1Request = {
        ...envelope(),
        client_id: clientId,
        label_name: labelName,
        limits,
      };
      return invokeCommand<SaveGmailSettingsV1Response>(
        "save_gmail_settings_v1",
        { request },
      );
    },

    async connect() {
      const request: ConnectGmailV1Request = envelope();
      return invokeCommand<ConnectGmailV1Response>("connect_gmail_v1", {
        request,
      });
    },

    async sync() {
      const request: SyncGmailV1Request = envelope();
      return invokeCommand<SyncGmailV1Response>("sync_gmail_v1", { request });
    },

    async disconnect() {
      const request: DisconnectGmailV1Request = envelope();
      return invokeCommand<DisconnectGmailV1Response>(
        "disconnect_gmail_v1",
        { request },
      );
    },
  };
}

export const gmailConnectorBridge =
  createGmailConnectorBridge(productionInvoke);
