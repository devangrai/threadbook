import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { CatalogBridge } from "./catalog-bridge";
import { P02Workspace } from "./P02Workspace";

afterEach(cleanup);

function testBridge(): CatalogBridge {
  return {
    listCatalog: vi.fn(async () => ({
      items: [
        {
          item_id: "item-1",
          display_name: "White Shirt",
          category: "top" as const,
          color: "White",
          notes: "",
          evidence_ids: ["evidence-a", "evidence-b"],
          updated_at: "2026-07-15T00:00:00Z",
          last_decision_id: "decision-1",
        },
      ],
      total_count: 1,
      catalog_revision: 3,
      evidence_generation: 2,
      next_cursor: null,
    })),
    listInbox: vi.fn(async () => ({
      items: [
        {
          evidence_id: "evidence-1",
          state: "unresolved" as const,
          kind: "email" as const,
          display_name: "Order email",
          source_label: "orders.mbox",
          imported_at: "2026-07-15T00:00:00Z",
          quarantine_reason: null,
          decision_capable: true,
        },
      ],
      total_count: 1,
      catalog_revision: 3,
      evidence_generation: 2,
      next_cursor: null,
    })),
    importLocalSources: vi.fn(),
    refreshImportRoots: vi.fn(),
    saveItem: vi.fn(async () => ({
      decision_id: "decision-2",
      new_catalog_revision: 4,
    })),
    decideEvidence: vi.fn(async () => ({
      decision_id: "decision-2",
      new_catalog_revision: 4,
    })),
    mergeItems: vi.fn(),
    splitItem: vi.fn(),
    undoDecision: vi.fn(),
    previewDeletion: vi.fn(async () => ({
      preview_snapshot_token: "preview",
      plan_sha256: "a".repeat(64),
      prepared_at: "2026-07-15T00:00:00Z",
      expires_at: "2026-07-15T00:15:00Z",
      revisions: {
        catalog_revision: 3,
        evidence_generation: 2,
        receipt_revision: 0,
        photo_revision: 0,
        photokit_revision: 0,
        reconciliation_revision: 0,
        outfit_revision: 0,
        try_on_revision: 0,
      },
      overall_count: 2,
      retained_shared_blob_count: 1,
      unique_blob_count: 1,
      unique_blob_bytes: 128,
      backup_retention: [
        {
          backup_id: "90000000-0000-4000-8000-000000000002",
          reason: "scheduled" as const,
          expires_at: "2026-07-22T00:00:00Z",
        },
      ],
      remote_retention: [
        {
          provider: "open_ai" as const,
          purpose: "try_on" as const,
          retention_mode: "default" as const,
          retention_provenance: "provider-policy",
          dispatched_at: "2026-07-15T00:00:00Z",
          policy_expires_at: null,
          status: "provider_deletion_unavailable" as const,
        },
      ],
      classes: [
        {
          class_name: "evidence",
          count: 2,
          items: [{ id: "one", label: "Order email" }],
          next_cursor: "next",
        },
      ],
    })),
    listDeletionPlanItems: vi.fn(async () => ({
      class_name: "evidence",
      count: 2,
      items: [{ id: "two", label: "Photo" }],
      next_cursor: null,
    })),
    executeDeletion: vi.fn(async () => ({
      run_id: "90000000-0000-4000-8000-000000000003",
      complete: true,
      accepted_at: "2026-07-15T00:00:30Z",
      deadline_at: "2026-07-15T01:00:30Z",
      completed_at: "2026-07-15T00:01:00Z",
      deleted_local_record_count: 2,
      deleted_unique_blob_count: 1,
      deleted_unique_blob_bytes: 128,
      retained_shared_blob_count: 1,
      backup_retention: [],
      remote_retention: [],
      replay_status: "created" as const,
    })),
  };
}

describe("P02 workspace", () => {
  it("imports every path selected by the native file chooser", async () => {
    const bridge = testBridge();
    const pickFiles = vi.fn(async () => [
      "/Users/me/Pictures/shirt.jpg",
      "/Users/me/Downloads/order.eml",
    ]);
    const user = userEvent.setup();
    render(
      <P02Workspace
        mode="catalog"
        bridge={bridge}
        pickFiles={pickFiles}
      />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Choose files" }),
    );

    expect(pickFiles).toHaveBeenCalledOnce();
    await waitFor(() =>
      expect(bridge.importLocalSources).toHaveBeenCalledWith([
        "/Users/me/Pictures/shirt.jpg",
        "/Users/me/Downloads/order.eml",
      ]),
    );
  });

  it("imports a selected folder and treats chooser cancellation as a no-op", async () => {
    const bridge = testBridge();
    const pickFolder = vi
      .fn<() => Promise<string[]>>()
      .mockResolvedValueOnce(["/Users/me/Pictures/Wardrobe"])
      .mockResolvedValueOnce([]);
    const user = userEvent.setup();
    render(
      <P02Workspace
        mode="catalog"
        bridge={bridge}
        pickFolder={pickFolder}
      />,
    );

    const chooseFolder = await screen.findByRole("button", {
      name: "Choose folder",
    });
    await user.click(chooseFolder);
    await waitFor(() =>
      expect(bridge.importLocalSources).toHaveBeenCalledWith([
        "/Users/me/Pictures/Wardrobe",
      ]),
    );

    await user.click(chooseFolder);
    expect(pickFolder).toHaveBeenCalledTimes(2);
    expect(bridge.importLocalSources).toHaveBeenCalledOnce();
  });

  it("reports a native chooser failure without starting an import", async () => {
    const bridge = testBridge();
    const pickFiles = vi.fn(async () => {
      throw {
        code: "storage_unavailable",
        retryable: true,
        user_action: "retry",
      };
    });
    const user = userEvent.setup();
    render(
      <P02Workspace
        mode="catalog"
        bridge={bridge}
        pickFiles={pickFiles}
      />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Choose files" }),
    );

    expect(await screen.findByText("Retry")).toBeInTheDocument();
    expect(bridge.importLocalSources).not.toHaveBeenCalled();
  });

  it("edits with a revision and confirms dependency-aware deletion", async () => {
    const bridge = testBridge();
    const onDeletionActivity = vi.fn();
    const user = userEvent.setup();
    render(
      <P02Workspace
        mode="catalog"
        bridge={bridge}
        onDeletionActivity={onDeletionActivity}
      />,
    );

    await screen.findByText("White Shirt");
    await user.click(screen.getByRole("button", { name: "Edit" }));
    const name = screen.getByRole("textbox", { name: "Name" });
    await user.clear(name);
    await user.type(name, "Ivory Shirt");
    await user.click(screen.getByRole("button", { name: "Save item" }));

    await waitFor(() =>
      expect(bridge.saveItem).toHaveBeenCalledWith(
        "item-1",
        expect.objectContaining({ display_name: "Ivory Shirt" }),
        ["evidence-a", "evidence-b"],
        3,
      ),
    );

    await user.click(
      screen.getByRole("button", { name: "Preview deletion" }),
    );
    expect(
      await screen.findByRole("dialog", {
        name: "Delete White Shirt",
      }),
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Retained backups" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Provider retention" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Load more Evidence" }));
    expect(await screen.findByText("Photo")).toBeInTheDocument();
    const deleteButton = screen.getByRole("button", {
      name: "Delete active local data",
    });
    expect(deleteButton).toBeDisabled();
    await user.click(
      screen.getByRole("checkbox", {
        name: /active local deletion is irreversible/i,
      }),
    );
    await user.click(deleteButton);
    await waitFor(() => expect(bridge.executeDeletion).toHaveBeenCalledOnce());
    expect(
      await screen.findByText("Active local deletion complete."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Done" })).toHaveFocus();
    expect(onDeletionActivity).toHaveBeenCalledOnce();
  });

  it("assigns unresolved evidence to a concrete item", async () => {
    const bridge = testBridge();
    const user = userEvent.setup();
    render(<P02Workspace mode="inbox" bridge={bridge} />);

    await screen.findByText("Order email");
    await user.click(screen.getByRole("button", { name: "Assign" }));
    await waitFor(() =>
      expect(bridge.decideEvidence).toHaveBeenCalledWith(
        "evidence-1",
        "assign",
        "item-1",
        3,
      ),
    );
  });

  it("enables assignment when catalog items load after inbox evidence", async () => {
    const bridge = testBridge();
    let resolveCatalog:
      | ((page: Awaited<ReturnType<CatalogBridge["listCatalog"]>>) => void)
      | undefined;
    vi.mocked(bridge.listCatalog).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveCatalog = resolve;
        }),
    );
    const user = userEvent.setup();
    render(<P02Workspace mode="inbox" bridge={bridge} />);

    await screen.findByText("Order email");
    const assign = screen.getByRole("button", { name: "Assign" });
    expect(assign).toBeDisabled();
    resolveCatalog?.({
      items: [
        {
          item_id: "item-late",
          display_name: "Late Shirt",
          category: "top",
          color: "White",
          notes: "",
          evidence_ids: [],
          updated_at: "2026-07-15T00:00:00Z",
          last_decision_id: "decision-late",
        },
      ],
      total_count: 1,
      catalog_revision: 4,
      evidence_generation: 2,
      next_cursor: null,
    });
    await waitFor(() => expect(assign).toBeEnabled());
    await user.click(assign);
    expect(bridge.decideEvidence).toHaveBeenCalledWith(
      "evidence-1",
      "assign",
      "item-late",
      4,
    );
  });

  it("refreshes stale deletion authority and requires acknowledgement again", async () => {
    const bridge = testBridge();
    vi.mocked(bridge.executeDeletion).mockRejectedValueOnce({
      code: "snapshot_expired",
      retryable: false,
      user_action: "start_new_request",
    });
    const user = userEvent.setup();
    render(<P02Workspace mode="catalog" bridge={bridge} />);

    await user.click(
      await screen.findByRole("button", { name: "Preview deletion" }),
    );
    await user.click(
      await screen.findByRole("checkbox", {
        name: /active local deletion is irreversible/i,
      }),
    );
    await user.click(
      screen.getByRole("button", { name: "Delete active local data" }),
    );

    expect(
      await screen.findByText(
        "The plan was refreshed. Review it before confirming.",
      ),
    ).toBeInTheDocument();
    expect(bridge.previewDeletion).toHaveBeenCalledTimes(2);
    expect(
      screen.getByRole("checkbox", {
        name: /active local deletion is irreversible/i,
      }),
    ).not.toBeChecked();
    expect(
      screen.getByRole("button", { name: "Delete active local data" }),
    ).toBeDisabled();
  });

  it("reuses deletion request authority after an uncertain transport error", async () => {
    const bridge = testBridge();
    vi.mocked(bridge.executeDeletion).mockRejectedValueOnce({
      code: "storage_unavailable",
      retryable: true,
      user_action: "retry",
    });
    const user = userEvent.setup();
    render(<P02Workspace mode="catalog" bridge={bridge} />);

    await user.click(
      await screen.findByRole("button", { name: "Preview deletion" }),
    );
    await user.click(
      await screen.findByRole("checkbox", {
        name: /active local deletion is irreversible/i,
      }),
    );
    await user.click(
      screen.getByRole("button", { name: "Delete active local data" }),
    );
    await screen.findByText("Retry");
    await user.click(
      screen.getByRole("button", { name: "Delete active local data" }),
    );

    await screen.findByText("Active local deletion complete.");
    const calls = vi.mocked(bridge.executeDeletion).mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[0]?.[1]).toBe(calls[1]?.[1]);
  });
});
