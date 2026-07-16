import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type {
  BeginPhotoKitSetupV1Response,
  DisablePhotoKitV1Response,
  PhotoKitConnectorSnapshotV1,
  SyncPhotoKitV1Response,
} from "./generated/contracts";
import type { PhotoKitConnectorBridge } from "./photokit-connector-bridge";
import { PhotoKitConnectorSettings } from "./PhotoKitConnectorSettings";

describe("PhotoKit connector settings", () => {
  it("starts setup explicitly, defaults consent off, and cancels with Escape", async () => {
    const user = userEvent.setup();
    const bridge = testBridge(snapshot(), {
      beginSetup: vi.fn(async () => setupResponse()),
    });
    const { container } = render(
      <PhotoKitConnectorSettings localOnly={false} bridge={bridge} />,
    );

    const connect = await screen.findByRole("button", { name: "Connect" });
    expect(bridge.beginSetup).not.toHaveBeenCalled();
    await user.click(connect);

    const album = await screen.findByRole("combobox", { name: "Album" });
    const consent = screen.getByRole("checkbox", {
      name: "Allow downloads of originals stored in iCloud",
    });
    expect(album).toHaveFocus();
    expect(consent).not.toBeChecked();
    expect(container.innerHTML).not.toContain("opaque-selection-token");
    expect(container.innerHTML).not.toContain("PHAsset/secret-identifier");
    expect(container.innerHTML).not.toContain("IMG_0042.HEIC");
    expect(container.innerHTML).not.toContain("/Users/private/Pictures");

    await user.keyboard("{Escape}");

    expect(screen.queryByRole("combobox", { name: "Album" })).toBeNull();
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Apple Photos setup cancelled.",
    );
    expect(bridge.configureScope).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Connect" })).toHaveFocus(),
    );
  });

  it("configures the selected regular album with explicit consent state", async () => {
    const user = userEvent.setup();
    let current = snapshot();
    const configured = snapshot({
      state: "ready",
      authorization: "authorized",
      enrollment_epoch: "enrollment-epoch",
      membership_generation: 1,
      photokit_revision: 3,
      allow_icloud_downloads: true,
      last_complete_at: "2026-07-15T19:00:00Z",
      counts: { observed: 6, available: 5, unavailable: 1 },
    });
    const bridge = testBridge(current, {
      getState: vi.fn(async () => response(current)),
      beginSetup: vi.fn(async () => setupResponse()),
      configureScope: vi.fn(async () => {
        current = configured;
        return {
          ...response(configured),
          replay_status: "created" as const,
        };
      }),
    });

    render(
      <PhotoKitConnectorSettings localOnly={false} bridge={bridge} />,
    );
    await user.click(await screen.findByRole("button", { name: "Connect" }));
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Album" }),
      "Trips",
    );
    await user.click(
      screen.getByRole("checkbox", {
        name: "Allow downloads of originals stored in iCloud",
      }),
    );
    await user.click(screen.getByRole("button", { name: "Configure" }));

    await waitFor(() =>
      expect(bridge.configureScope).toHaveBeenCalledWith(
        "setup-session",
        "opaque-selection-token",
        true,
      ),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Apple Photos connected.",
    );
    expect(screen.getByText("Connected")).toBeInTheDocument();
    expect(screen.getByText("5", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText("1", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText("Allowed", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText("Jul 15, 2026", { exact: false })).toBeInTheDocument();
  });

  it("announces sync progress, success, and failure", async () => {
    const user = userEvent.setup();
    const ready = snapshot({
      state: "ready",
      authorization: "authorized",
      enrollment_epoch: "enrollment-epoch",
      photokit_revision: 7,
    });
    const synced = snapshot({
      ...ready,
      photokit_revision: 8,
      counts: { observed: 6, available: 4, unavailable: 2 },
      last_complete_at: "2026-07-15T20:00:00Z",
    });
    let resolveSync!: (value: SyncPhotoKitV1Response) => void;
    const sync = vi
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise<SyncPhotoKitV1Response>((resolve) => {
            resolveSync = resolve;
          }),
      )
      .mockRejectedValueOnce(new Error("private native failure"));
    const bridge = testBridge(ready, { sync });

    render(
      <PhotoKitConnectorSettings localOnly={false} bridge={bridge} />,
    );
    const syncButton = await screen.findByRole("button", { name: "Sync now" });
    await user.click(syncButton);
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Syncing Apple Photos...",
    );

    resolveSync(syncResponse(synced));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Apple Photos synced. 4 available, 2 unavailable.",
    );

    await user.click(screen.getByRole("button", { name: "Sync now" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Local data is unavailable.",
    );
    expect(screen.getByRole("alert")).not.toHaveTextContent(
      "private native failure",
    );
  });

  it("requires confirmation and disables with the loaded revision", async () => {
    const user = userEvent.setup();
    const ready = snapshot({
      state: "ready",
      authorization: "authorized",
      enrollment_epoch: "enrollment-epoch",
      membership_generation: 4,
      photokit_revision: 11,
      counts: { observed: 3, available: 2, unavailable: 1 },
    });
    const disable = vi.fn(async (): Promise<DisablePhotoKitV1Response> => ({
      schema_version: 1,
      request_id: "request",
      state: "unconfigured",
      disabled_enrollment_epoch: "sensitive-enrollment-epoch",
      preserved_membership_generation: 4,
      photokit_revision: 12,
      preserved_counts: ready.counts,
      replay_status: "created",
    }));
    const bridge = testBridge(ready, { disable });

    const { container } = render(
      <PhotoKitConnectorSettings localOnly={false} bridge={bridge} />,
    );
    const disableButton = await screen.findByRole("button", {
      name: "Disable",
    });
    await user.click(disableButton);
    expect(screen.getByRole("dialog")).toHaveTextContent(
      "Existing wardrobe data will be preserved.",
    );
    expect(disable).not.toHaveBeenCalled();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    await waitFor(() => expect(disableButton).toHaveFocus());

    await user.click(disableButton);
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Disable",
      }),
    );

    await waitFor(() => expect(disable).toHaveBeenCalledWith(11));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Apple Photos disabled. Existing wardrobe data was preserved.",
    );
    expect(screen.getByText("Not connected")).toBeInTheDocument();
    expect(container.innerHTML).not.toContain("sensitive-enrollment-epoch");
  });

  it("blocks setup and sync while keeping local disable reachable", async () => {
    const ready = snapshot({
      state: "ready",
      authorization: "authorized",
      enrollment_epoch: "enrollment-epoch",
      photokit_revision: 14,
    });
    const disable = vi.fn(async (): Promise<DisablePhotoKitV1Response> => ({
      schema_version: 1,
      request_id: "request",
      state: "unconfigured",
      disabled_enrollment_epoch: "enrollment-epoch",
      preserved_membership_generation: null,
      photokit_revision: 15,
      preserved_counts: ready.counts,
      replay_status: "created",
    }));
    const bridge = testBridge(ready, { disable });
    const user = userEvent.setup();
    render(
      <PhotoKitConnectorSettings localOnly bridge={bridge} />,
    );

    const sync = await screen.findByRole("button", { name: "Sync now" });
    const disableButton = screen.getByRole("button", { name: "Disable" });
    expect(sync).toBeDisabled();
    expect(disableButton).toBeEnabled();

    await user.click(sync);
    expect(bridge.sync).not.toHaveBeenCalled();
    await user.click(disableButton);
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: "Disable",
      }),
    );
    await waitFor(() => expect(disable).toHaveBeenCalledWith(14));
  });
});

function snapshot(
  overrides: Partial<PhotoKitConnectorSnapshotV1> = {},
): PhotoKitConnectorSnapshotV1 {
  return {
    state: "unconfigured",
    authorization: "not_determined",
    enrollment_epoch: null,
    membership_generation: null,
    photokit_revision: 0,
    allow_icloud_downloads: false,
    last_complete_at: null,
    counts: { observed: 0, available: 0, unavailable: 0 },
    availability_counts: [],
    ...overrides,
  };
}

function response(value: PhotoKitConnectorSnapshotV1) {
  return {
    schema_version: 1 as const,
    request_id: "request",
    snapshot: value,
  };
}

function setupResponse(): BeginPhotoKitSetupV1Response {
  const album = {
    selection_token: "opaque-selection-token",
    display_label: "Trips",
    local_identifier: "PHAsset/secret-identifier",
    filename: "IMG_0042.HEIC",
    path: "/Users/private/Pictures",
  };
  return {
    ...response(
      snapshot({
        state: "setup_required",
        authorization: "authorized",
        photokit_revision: 1,
      }),
    ),
    setup_session_id: "setup-session",
    expires_at: "2026-07-15T20:10:00Z",
    album_candidates: [album],
    replay_status: "created",
  };
}

function syncResponse(
  value: PhotoKitConnectorSnapshotV1,
): SyncPhotoKitV1Response {
  return {
    ...response(value),
    operation_id: "operation",
    trigger: "user",
    reconciliation_fence: 2,
    replay_status: "created",
  };
}

function testBridge(
  initial: PhotoKitConnectorSnapshotV1,
  overrides: Partial<PhotoKitConnectorBridge> = {},
): PhotoKitConnectorBridge {
  return {
    getState: vi.fn(async () => response(initial)),
    beginSetup: vi.fn(),
    configureScope: vi.fn(),
    sync: vi.fn(),
    disable: vi.fn(),
    ...overrides,
  };
}
