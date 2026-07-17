import type {
  ConnectGmailV1Request,
  ConnectGmailV1Response,
  DisconnectGmailV1Request,
  DisconnectGmailV1Response,
  GetGmailConnectorV2Request,
  GetGmailConnectorV2Response,
  GmailDiscoveryScopeV2,
  GmailConnectorLimitsV1,
  SaveGmailSettingsV2Request,
  SaveGmailSettingsV2Response,
  SyncGmailV1Request,
  SyncGmailV1Response,
} from "./generated/contracts";
import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

type RequestIdFactory = () => string;

export type GmailConnectorBridge = {
  getState: () => Promise<GetGmailConnectorV2Response>;
  saveSettings: (
    clientId: string,
    discoveryScope: GmailDiscoveryScopeV2,
    limits: GmailConnectorLimitsV1,
  ) => Promise<SaveGmailSettingsV2Response>;
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
  const envelopeV2 = () => ({
    schema_version: 2 as const,
    request_id: createRequestId(),
  });

  return {
    async getState() {
      const request: GetGmailConnectorV2Request = envelopeV2();
      return invokeCommand<GetGmailConnectorV2Response>(
        "get_gmail_connector_v2",
        { request },
      );
    },

    async saveSettings(clientId, discoveryScope, limits) {
      const request: SaveGmailSettingsV2Request = {
        ...envelopeV2(),
        client_id: clientId,
        discovery_scope: discoveryScope,
        limits,
      };
      return invokeCommand<SaveGmailSettingsV2Response>(
        "save_gmail_settings_v2",
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
