import "@testing-library/jest-dom/vitest";

import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CredentialReferenceV1 } from "./generated/contracts";
import { TryOnPanel } from "./TryOnPanel";
import type {
  TryOnBridge,
  TryOnJobView,
  TryOnPreviewView,
} from "./try-on-bridge";

beforeEach(() => {
  let objectUrl = 0;
  Object.defineProperty(URL, "createObjectURL", {
    configurable: true,
    value: vi.fn(() => `blob:try-on-${++objectUrl}`),
  });
  Object.defineProperty(URL, "revokeObjectURL", {
    configurable: true,
    value: vi.fn(),
  });
});

afterEach(cleanup);

describe("try-on panel", () => {
  it("shows exact transmitted images before one explicit submission and restores focus", async () => {
    const bridge = testBridge(null);
    const user = userEvent.setup();
    renderPanel(bridge);

    const previewButton = await screen.findByRole("button", {
      name: "Preview disclosure",
    });
    expect(
      screen.getByRole("radio", { name: "Portrait from July 10" }),
    ).toBeChecked();
    await user.click(previewButton);

    expect(bridge.preview).toHaveBeenCalledWith(
      outfitId,
      "portrait-revision",
      "credential-openai",
      { mode: "unknown", provenance: "user_not_declared" },
      7,
    );
    expect(bridge.submit).not.toHaveBeenCalled();

    const dialog = await screen.findByRole("dialog", {
      name: "Review try-on disclosure",
    });
    expect(dialog).toHaveTextContent("OpenAI");
    expect(dialog).toHaveTextContent("gpt-image-2");
    expect(dialog).toHaveTextContent("Generate an AI outfit visualization");
    expect(dialog).toHaveTextContent(
      "Default abuse monitoring may retain content for up to 30 days.",
    );
    const disclosed = screen.getByRole("list", {
      name: "Images sent to OpenAI",
    });
    expect(disclosed.textContent).toMatch(
      /Portrait.*Ivory Shirt.*Navy Trousers/,
    );
    expect(disclosed).toHaveTextContent("reference-00.png");
    expect(disclosed).toHaveTextContent("reference-01.png");
    expect(disclosed).toHaveTextContent("Canonical SHA-256");
    expect(screen.getByRole("button", { name: "Dismiss disclosure" })).toHaveFocus();

    await user.click(
      screen.getByRole("button", { name: "Generate visualization" }),
    );
    await waitFor(() => expect(bridge.submit).toHaveBeenCalledWith("approval-1"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "Visualization pending" }),
    ).toBeVisible();
    expect(previewButton).toHaveFocus();
  });

  it("renders a persisted completed output with its exact disclaimer and real source garments", async () => {
    const bridge = testBridge(completedJob());
    const view = renderPanel(bridge);

    expect(
      await screen.findByRole("heading", { name: "Generated visualization" }),
    ).toBeVisible();
    expect(
      screen.getAllByText(
        "AI visualization. Not an accurate representation of fit or garment construction.",
      ),
    ).toHaveLength(2);
    expect(screen.getByText(outfitId)).toBeVisible();
    expect(screen.getByText("Ivory Shirt")).toBeVisible();
    expect(screen.getByText("Navy Trousers")).toBeVisible();
    expect(screen.getByText("item-top")).toBeVisible();
    expect(screen.getByText("item-bottom")).toBeVisible();
    expect(
      await screen.findByRole("img", {
        name: `Generated try-on visualization for outfit ${outfitId}`,
      }),
    ).toHaveAttribute("src", expect.stringMatching(/^blob:try-on-/));

    view.unmount();
    expect(URL.revokeObjectURL).toHaveBeenCalled();
  });

  it("keeps a typed failure actionable without removing the saved outfit context", async () => {
    const bridge = testBridge({
      ...queuedJob(),
      state: "failed",
      statusMessage: "OpenAI rejected the credential.",
      failureCode: "authentication",
    });
    renderPanel(bridge);

    expect(
      await screen.findByRole("heading", { name: "Visualization failed" }),
    ).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Check the OpenAI credential in Settings.",
    );
    expect(
      screen.getByText(/deterministic collage above were not changed/),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Preview disclosure" }),
    ).toBeEnabled();
  });

  it("keeps local history readable without invoking try-on previews", async () => {
    const bridge = testBridge(completedJob());
    const user = userEvent.setup();
    renderPanel(bridge, true);

    expect(
      await screen.findByRole("heading", { name: "Generated visualization" }),
    ).toBeVisible();
    const preview = screen.getByRole("button", {
      name: "Preview disclosure",
    });
    expect(preview).toBeDisabled();
    await user.click(preview);

    expect(bridge.listPortraitCandidates).toHaveBeenCalledOnce();
    expect(bridge.getOutfitTryOn).toHaveBeenCalledWith(outfitId);
    expect(bridge.preview).not.toHaveBeenCalled();
    expect(bridge.submit).not.toHaveBeenCalled();
  });
});

const outfitId = "33333333-3333-4333-8333-333333333333";

type TestBridge = TryOnBridge & {
  listPortraitCandidates: ReturnType<typeof vi.fn>;
  preview: ReturnType<typeof vi.fn>;
  submit: ReturnType<typeof vi.fn>;
  getOutfitTryOn: ReturnType<typeof vi.fn>;
};

function renderPanel(bridge: TestBridge, localOnly = false) {
  return render(
    <TryOnPanel
      localOnly={localOnly}
      outfitId={outfitId}
      outfitRevision={7}
      credentials={credentials()}
      bridge={bridge}
    />,
  );
}

function testBridge(existingJob: TryOnJobView | null): TestBridge {
  return {
    listPortraitCandidates: vi.fn(async () => ({
      candidates: [
        {
          sourceRevisionId: "portrait-revision",
          label: "Portrait from July 10",
          thumbnail: { mediaType: "image/png", bytes: [1] },
        },
      ],
      nextCursor: null,
    })),
    preview: vi.fn(async () => preview()),
    submit: vi.fn(async () => queuedJob()),
    getOutfitTryOn: vi.fn(async () => existingJob),
  };
}

function preview(): TryOnPreviewView {
  return {
    approvalId: "approval-1",
    providerStatus: "ready",
    provider: "OpenAI",
    model: "gpt-image-2",
    purpose: "Generate an AI outfit visualization",
    retentionSummary:
      "Default abuse monitoring may retain content for up to 30 days.",
    assets: [
      {
        ordinal: 0,
        role: "portrait",
        label: "Portrait from July 10",
        itemId: null,
        localReferenceId: "portrait-revision",
        transmittedFilename: "reference-00.png",
        canonicalSha256: "a".repeat(64),
        mediaType: "image/png",
        byteLength: 4096,
        width: 1024,
        height: 1365,
      },
      {
        ordinal: 1,
        role: "garment",
        label: "Ivory Shirt",
        itemId: "item-top",
        localReferenceId: "item-top",
        transmittedFilename: "reference-01.png",
        canonicalSha256: "b".repeat(64),
        mediaType: "image/png",
        byteLength: 4096,
        width: 800,
        height: 1000,
      },
      {
        ordinal: 2,
        role: "garment",
        label: "Navy Trousers",
        itemId: "item-bottom",
        localReferenceId: "item-bottom",
        transmittedFilename: "reference-02.png",
        canonicalSha256: "c".repeat(64),
        mediaType: "image/png",
        byteLength: 4096,
        width: 800,
        height: 1000,
      },
    ],
  };
}

function queuedJob(): TryOnJobView {
  return {
    jobId: "job-1",
    outfitId,
    state: "queued",
    statusMessage: "Visualization queued.",
    failureCode: null,
    retryable: false,
    output: null,
    garments: [],
  };
}

function completedJob(): TryOnJobView {
  return {
    ...queuedJob(),
    state: "succeeded",
    statusMessage: "Visualization ready.",
    output: { mediaType: "image/png", bytes: [9] },
    garments: [
      {
        ordinal: 1,
        itemId: "item-top",
        label: "Ivory Shirt",
        image: { mediaType: "image/png", bytes: [2] },
      },
      {
        ordinal: 2,
        itemId: "item-bottom",
        label: "Navy Trousers",
        image: { mediaType: "image/png", bytes: [3] },
      },
    ],
  };
}

function credentials(): CredentialReferenceV1[] {
  return [
    {
      credential_id: "credential-openai",
      provider: "open_ai",
      display_label: "Personal OpenAI",
      status: "active",
      updated_at: "2026-07-15T08:00:00Z",
    },
  ];
}
