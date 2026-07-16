import "@testing-library/jest-dom/vitest";

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CatalogBridge } from "./catalog-bridge";
import type {
  CreateManualOutfitV1Response,
  CredentialReferenceV1,
  GetOutfitCollageV1Response,
  ListOutfitsV1Response,
  OutfitV1,
} from "./generated/contracts";
import type { OutfitBridge } from "./outfit-bridge";
import { OutfitsWorkspace } from "./OutfitsWorkspace";

beforeEach(() => {
  Object.defineProperty(URL, "createObjectURL", {
    configurable: true,
    value: vi.fn(() => "blob:outfit-source"),
  });
  Object.defineProperty(URL, "revokeObjectURL", {
    configurable: true,
    value: vi.fn(),
  });
});

afterEach(cleanup);

const itemIds = [
  "11111111-1111-4111-8111-111111111111",
  "22222222-2222-4222-8222-222222222222",
];
const outfitId = "33333333-3333-4333-8333-333333333333";
const tinyPngBytes = [
  137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0,
  1, 0, 0, 0, 1, 8, 4, 0, 0, 0, 181, 28, 12, 2, 0, 0, 0, 11, 73, 68, 65,
  84, 120, 218, 99, 100, 248, 15, 0, 1, 5, 1, 1, 39, 24, 227, 102, 0, 0,
  0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
];
const activeCredential: CredentialReferenceV1 = {
  credential_id: "44444444-4444-4444-8444-444444444444",
  provider: "open_ai",
  display_label: "Test OpenAI",
  status: "active",
  updated_at: "2026-07-15T00:00:00Z",
};

function member(index: number, name: string) {
  return {
    ordinal: index,
    item_id: itemIds[index],
    item_updated_revision: 1,
    attributes: {
      display_name: name,
      category: index === 0 ? ("top" as const) : ("bottom" as const),
      subcategory: null,
      brand: null,
      primary_color: index === 0 ? "Ivory" : "Navy",
      size: null,
      notes: null,
      tags: [],
    },
    asset: {
      state: "metadata_only" as const,
      evidence_id: null,
      source_id: null,
      blob_sha256: null,
      media_type: null,
      byte_length: null,
      width: null,
      height: null,
    },
  };
}

function savedOutfit(): OutfitV1 {
  return {
    outfit_id: outfitId,
    name: "Dinner date",
    members: [member(0, "Ivory Shirt"), member(1, "Navy Trousers")],
    created_outfit_revision: 1,
  };
}

function savedOutfitPage(): ListOutfitsV1Response {
  return {
    schema_version: 1,
    request_id: "request-saved",
    outfits: [savedOutfit()],
    total_count: 1,
    outfit_revision: 1,
    next_cursor: null,
  };
}

function collageResponse(): GetOutfitCollageV1Response {
  return {
    schema_version: 1,
    request_id: "request-collage",
    outfit_id: outfitId,
    name: "Dinner date",
    members: savedOutfit().members.map((value, index) => ({
      member:
        index === 0
          ? {
              ...value,
              asset: {
                state: "available" as const,
                evidence_id: "55555555-5555-4555-8555-555555555555",
                source_id: "66666666-6666-4666-8666-666666666666",
                blob_sha256: "a".repeat(64),
                media_type: "image/png",
                byte_length: tinyPngBytes.length,
                width: 1,
                height: 1,
              },
            }
          : value,
      bytes: index === 0 ? tinyPngBytes : null,
    })),
    outfit_revision: 1,
  };
}

function emptyCatalog(): CatalogBridge {
  return {
    listCatalog: vi.fn(async () => ({
      items: [],
      total_count: 0,
      catalog_revision: 0,
      evidence_generation: 0,
      next_cursor: null,
    })),
  } as unknown as CatalogBridge;
}

function emptyOutfits(): OutfitBridge {
  return {
    listOutfits: vi.fn(async () => ({
      schema_version: 1,
      request_id: "request-empty",
      outfits: [],
      total_count: 0,
      outfit_revision: 0,
      next_cursor: null,
    })),
    createManualOutfit: vi.fn(),
    getCollage: vi.fn(),
  } as unknown as OutfitBridge;
}

describe("outfits workspace", () => {
  it("keeps remote recommendations disabled by default despite an active credential", async () => {
    const loadRecommendationCredentials = vi.fn(async () => [
      activeCredential,
    ]);
    render(
      <OutfitsWorkspace
        localOnly={false}
        catalog={emptyCatalog()}
        outfits={emptyOutfits()}
        loadRecommendationCredentials={loadRecommendationCredentials}
      />,
    );

    await screen.findByRole("heading", { name: "Outfits" });
    expect(loadRecommendationCredentials).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("heading", { name: "Outfit ideas" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Build outfit" }),
    ).toBeVisible();
  });

  it("allows deliberate recommendation enablement in a gated test", async () => {
    const loadRecommendationCredentials = vi.fn(async () => [
      activeCredential,
    ]);
    render(
      <OutfitsWorkspace
        localOnly={false}
        catalog={emptyCatalog()}
        outfits={emptyOutfits()}
        recommendationsEnabled
        loadRecommendationCredentials={loadRecommendationCredentials}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "Outfit ideas" }),
    ).toBeVisible();
    expect(loadRecommendationCredentials).toHaveBeenCalledOnce();
  });

  it("creates an ordered manual outfit and opens its offline collage", async () => {
    const catalog = {
      listCatalog: vi.fn(async () => ({
        items: [
          {
            item_id: itemIds[0],
            display_name: "Ivory Shirt",
            category: "top" as const,
            color: "Ivory",
            notes: "",
            evidence_ids: [],
            updated_at: "",
            last_decision_id: "decision-1",
          },
          {
            item_id: itemIds[1],
            display_name: "Navy Trousers",
            category: "bottom" as const,
            color: "Navy",
            notes: "",
            evidence_ids: [],
            updated_at: "",
            last_decision_id: "decision-2",
          },
        ],
        total_count: 2,
        catalog_revision: 4,
        evidence_generation: 1,
        next_cursor: null,
      })),
    } as unknown as CatalogBridge;
    let listCount = 0;
    const empty: ListOutfitsV1Response = {
      schema_version: 1,
      request_id: "request-1",
      outfits: [],
      total_count: 0,
      outfit_revision: 0,
      next_cursor: null,
    };
    const saved = savedOutfitPage();
    const createResponse: CreateManualOutfitV1Response = {
      schema_version: 1,
      request_id: "request-2",
      outfit: savedOutfit(),
      outfit_revision: 1,
      replay_status: "created",
    };
    const collage = collageResponse();
    const outfits: OutfitBridge = {
      listOutfits: vi.fn(async () => (listCount++ === 0 ? empty : saved)),
      createManualOutfit: vi.fn(async () => createResponse),
      getCollage: vi.fn(async () => collage),
    };
    const user = userEvent.setup();
    render(
      <OutfitsWorkspace
        localOnly={false}
        catalog={catalog}
        outfits={outfits}
      />,
    );

    await screen.findByRole("heading", { name: "Outfits" });
    await user.type(screen.getByRole("textbox", { name: "Name" }), "Dinner date");
    await user.click(screen.getByRole("checkbox", { name: /Ivory Shirt/ }));
    await user.click(screen.getByRole("checkbox", { name: /Navy Trousers/ }));
    await user.click(screen.getByRole("button", { name: "Move Navy Trousers up" }));
    await user.click(screen.getByRole("button", { name: "Save outfit" }));

    await waitFor(() =>
      expect(outfits.createManualOutfit).toHaveBeenCalledWith(
        "Dinner date",
        [itemIds[1], itemIds[0]],
        4,
        0,
      ),
    );
    await user.click(await screen.findByRole("button", { name: "View collage" }));
    expect(
      await screen.findByRole("heading", { name: "Dinner date" }),
    ).toBeVisible();
    expect(screen.getByLabelText("Outfit collage")).toBeVisible();
    expect(screen.getByLabelText("Outfit collage loading")).toBeInTheDocument();
    const sourceMedia = screen.getByRole("img", {
      name: "Outfit member 0 source image",
    });
    expect(sourceMedia).toHaveAccessibleDescription("Ivory Shirt Top");
    const sourceImage = sourceMedia.querySelector("img");
    expect(sourceImage).not.toBeNull();
    expect(URL.createObjectURL).toHaveBeenCalledOnce();
    const blob = vi.mocked(URL.createObjectURL).mock.calls[0][0];
    expect(blob).toBeInstanceOf(Blob);
    expect(blob).toMatchObject({
      type: "image/png",
      size: tinyPngBytes.length,
    });

    fireEvent.load(sourceImage!);
    expect(screen.getByLabelText("Outfit collage ready")).toBeInTheDocument();
    expect(screen.getAllByText("No image")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Back to outfits" }));
    expect(screen.getByRole("heading", { name: "Outfits" })).toBeVisible();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:outfit-source");
  });

  it("reports a source image error and revokes its object URL on unmount", async () => {
    const outfits: OutfitBridge = {
      listOutfits: vi.fn(async () => savedOutfitPage()),
      createManualOutfit: vi.fn(),
      getCollage: vi.fn(async () => collageResponse()),
    };
    const user = userEvent.setup();
    const view = render(
      <OutfitsWorkspace
        localOnly={false}
        catalog={emptyCatalog()}
        outfits={outfits}
      />,
    );

    await user.click(
      await screen.findByRole("button", { name: "View collage" }),
    );
    const sourceMedia = await screen.findByRole("img", {
      name: "Outfit member 0 source image",
    });
    const sourceImage = sourceMedia.querySelector("img");
    expect(sourceImage).not.toBeNull();
    expect(screen.getByLabelText("Outfit collage loading")).toBeInTheDocument();

    fireEvent.error(sourceImage!);

    expect(
      screen.getByLabelText("Outfit collage image error"),
    ).toBeInTheDocument();
    view.unmount();
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:outfit-source");
  });
});
