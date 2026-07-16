import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { BackupBridge, BackupRecord } from "./backup-bridge";
import { BackupSettings } from "./BackupSettings";

const backup: BackupRecord = {
  id: "10000000-0000-4000-8000-000000000010",
  reason: "manual",
  createdAt: "2026-07-15T11:03:00Z",
  expiresAt: "2026-08-14T11:03:00Z",
  manifestSha256: "a".repeat(64),
  databaseSchemaVersion: 10,
  assetCount: 2,
  totalBytes: 2048,
};

describe("backup settings", () => {
  it("creates a backup and prepares an explicitly confirmed restore", async () => {
    const user = userEvent.setup();
    const bridge: BackupBridge = {
      list: vi.fn(async () => []),
      create: vi.fn(async () => backup),
      prepareRestore: vi.fn(async () => ({
        restartRequired: true as const,
        safetyBackupId: "10000000-0000-4000-8000-000000000011",
      })),
    };

    render(<BackupSettings bridge={bridge} />);
    await screen.findByText("No backups yet.");

    await user.click(screen.getByRole("button", { name: "Create backup" }));
    expect(await screen.findByText("Backup created.")).toBeInTheDocument();

    const restore = screen.getByRole("button", { name: "Restore" });
    await user.click(restore);
    expect(screen.getByRole("dialog")).toHaveTextContent(
      "replace the current local catalog",
    );
    expect(bridge.prepareRestore).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Prepare restore" }));
    await waitFor(() => expect(bridge.prepareRestore).toHaveBeenCalledWith(backup));
    expect(
      await screen.findByText("Restore prepared. Restart Wardrobe to apply it."),
    ).toBeInTheDocument();
    await waitFor(() => expect(restore).toHaveFocus());
  });
});
