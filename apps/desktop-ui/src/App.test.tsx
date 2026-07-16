import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SettingsView } from "./App";
import type { FoundationSnapshot } from "./foundation-model";

vi.mock("./BackupSettings", () => ({
  BackupSettings: () => null,
}));
vi.mock("./DiagnosticsSettings", () => ({
  DiagnosticsSettings: () => null,
}));
vi.mock("./GmailConnectorSettings", () => ({
  GmailConnectorSettings: () => null,
}));
vi.mock("./PhotoKitConnectorSettings", () => ({
  PhotoKitConnectorSettings: () => null,
}));

describe("settings view", () => {
  it("keeps credential removal reachable while local-only blocks credential setup", async () => {
    const onRemoveCredential = vi.fn();
    const onSaveCredential = vi.fn(async () => undefined);
    const user = userEvent.setup();
    render(
      <SettingsView
        snapshot={snapshot()}
        busyAction={null}
        actionMessage={null}
        onRunStorageCheck={vi.fn()}
        onSetLocalOnly={vi.fn(async () => undefined)}
        onSaveCredential={onSaveCredential}
        onRemoveCredential={onRemoveCredential}
      />,
    );

    expect(screen.getByRole("textbox", { name: "Label" })).toBeDisabled();
    expect(screen.getByLabelText("Secret")).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Save credential" }),
    ).toBeDisabled();

    const remove = screen.getByRole("button", {
      name: "Remove Personal OpenAI",
    });
    expect(remove).toBeEnabled();
    await user.click(remove);

    expect(onRemoveCredential).toHaveBeenCalledWith("credential-openai");
    expect(onSaveCredential).not.toHaveBeenCalled();
  });
});

function snapshot(): FoundationSnapshot {
  return {
    itemCount: 0,
    localOnly: true,
    revision: 6,
    authorityHealth: "persisted",
    storage: { database: "ready", blobs: "ready" },
    deletionHealth: { status: "none", deadlineAt: null, count: 0 },
    credentials: [
      {
        id: "credential-openai",
        provider: "OpenAI",
        displayLabel: "Personal OpenAI",
        status: "active",
      },
    ],
    recentJobs: [],
  };
}
