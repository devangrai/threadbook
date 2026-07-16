import {
  productionInvoke,
  type InvokeCommand,
} from "@wardrobe/invoke-transport";

import type {
  BeginPhotoKitSetupV1Request,
  BeginPhotoKitSetupV1Response,
  ConfigurePhotoKitScopeV1Request,
  ConfigurePhotoKitScopeV1Response,
  DisablePhotoKitV1Request,
  DisablePhotoKitV1Response,
  GetPhotoKitConnectorV1Request,
  GetPhotoKitConnectorV1Response,
  PhotoKitRevisionV1,
  PhotoKitSelectionTokenV1,
  PhotoKitSetupSessionIdV1,
  SyncPhotoKitV1Request,
  SyncPhotoKitV1Response,
} from "./generated/contracts";

type RequestIdFactory = () => string;

export type PhotoKitConnectorBridge = {
  getState: () => Promise<GetPhotoKitConnectorV1Response>;
  beginSetup: () => Promise<BeginPhotoKitSetupV1Response>;
  configureScope: (
    setupSessionId: PhotoKitSetupSessionIdV1,
    selectionToken: PhotoKitSelectionTokenV1,
    allowIcloudDownloads: boolean,
  ) => Promise<ConfigurePhotoKitScopeV1Response>;
  sync: () => Promise<SyncPhotoKitV1Response>;
  disable: (
    expectedPhotoKitRevision: PhotoKitRevisionV1,
  ) => Promise<DisablePhotoKitV1Response>;
};

export function createPhotoKitConnectorBridge(
  invokeCommand: InvokeCommand,
  createRequestId: RequestIdFactory = () => crypto.randomUUID(),
): PhotoKitConnectorBridge {
  const envelope = () => ({
    schema_version: 1 as const,
    request_id: createRequestId(),
  });

  return {
    async getState() {
      const request: GetPhotoKitConnectorV1Request = envelope();
      return invokeCommand<GetPhotoKitConnectorV1Response>(
        "get_photokit_connector_v1",
        { request },
      );
    },

    async beginSetup() {
      const request: BeginPhotoKitSetupV1Request = envelope();
      return invokeCommand<BeginPhotoKitSetupV1Response>(
        "begin_photokit_setup_v1",
        { request },
      );
    },

    async configureScope(
      setupSessionId,
      selectionToken,
      allowIcloudDownloads,
    ) {
      const request: ConfigurePhotoKitScopeV1Request = {
        ...envelope(),
        setup_session_id: setupSessionId,
        selection_token: selectionToken,
        allow_icloud_downloads: allowIcloudDownloads,
      };
      return invokeCommand<ConfigurePhotoKitScopeV1Response>(
        "configure_photokit_scope_v1",
        { request },
      );
    },

    async sync() {
      const request: SyncPhotoKitV1Request = envelope();
      return invokeCommand<SyncPhotoKitV1Response>("sync_photokit_v1", {
        request,
      });
    },

    async disable(expectedPhotoKitRevision) {
      const request: DisablePhotoKitV1Request = {
        ...envelope(),
        expected_photokit_revision: expectedPhotoKitRevision,
      };
      return invokeCommand<DisablePhotoKitV1Response>(
        "disable_photokit_v1",
        { request },
      );
    },
  };
}

export const photoKitConnectorBridge =
  createPhotoKitConnectorBridge(productionInvoke);
