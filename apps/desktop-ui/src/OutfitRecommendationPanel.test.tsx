import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  CatalogItemV1,
  CredentialReferenceV1,
  OutfitProposalV1,
  OutfitRecommendationOutcomeV1,
  PreviewOutfitRecommendationV1Response,
} from "./generated/contracts";
import type { OutfitRecommendationBridge } from "./outfit-recommendation-bridge";
import { OutfitRecommendationPanel } from "./OutfitRecommendationPanel";

afterEach(cleanup);

describe("outfit recommendation panel", () => {
  it("previews before sending, reuses the approved envelope, and discloses privacy limits", async () => {
    const bridge = testBridge(completedOutcome());
    const user = userEvent.setup();
    renderPanel(bridge);

    await user.type(
      screen.getByRole("textbox", { name: "What do you need?" }),
      " Dinner date ",
    );
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Occasion" }),
      "date",
    );
    await user.type(
      screen.getByRole("spinbutton", { name: "Temperature (C)" }),
      "18",
    );
    await user.selectOptions(
      screen.getByRole("combobox", { name: "Precipitation" }),
      "rain",
    );
    await user.click(
      screen.getByRole("checkbox", { name: "Navy trousers" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Preview disclosure" }),
    );

    expect(bridge.preview).toHaveBeenCalledTimes(1);
    expect(bridge.request).not.toHaveBeenCalled();
    const dialog = await screen.findByRole("dialog", {
      name: "Review OpenAI disclosure",
    });
    expect(dialog).toHaveTextContent("Your request");
    expect(dialog).toHaveTextContent("Confirmed wardrobe item IDs");
    expect(dialog).toHaveTextContent(
      "No photos, email content, file paths, notes, sizes, or evidence metadata will be sent.",
    );
    expect(dialog).toHaveTextContent("store=false is not Zero Data Retention");
    expect(dialog).toHaveTextContent("abuse monitoring for up to 30 days");
    expect(dialog).toHaveTextContent("explicit; 0 breakpoints");
    expect(dialog).toHaveTextContent("MAM from OpenAI project settings");

    await user.click(screen.getByRole("button", { name: "Send to OpenAI" }));
    await waitFor(() => expect(bridge.request).toHaveBeenCalledTimes(1));

    const previewEnvelope = bridge.preview.mock.calls[0][0];
    expect(bridge.request.mock.calls[0][1]).toBe(previewEnvelope);
    expect(previewEnvelope).toEqual({
      prompt: "Dinner date",
      credential_id: "credential-openai",
      constraints: {
        occasion: "date",
        temperature_c: 18,
        precipitation: "rain",
      },
      excluded_item_ids: ["item-bottom"],
      requested_proposal_count: 1,
      expected_catalog_revision: 7,
      expected_outfit_revision: 4,
      retention: {
        mode: "MAM",
        provenance: "OpenAI project settings",
      },
    });
    expect(
      await screen.findByRole("heading", { name: "Recommended outfits" }),
    ).toBeVisible();
  });

  it("dismisses a disclosure without sending", async () => {
    const bridge = testBridge(completedOutcome());
    const user = userEvent.setup();
    renderPanel(bridge);

    await user.type(
      screen.getByRole("textbox", { name: "What do you need?" }),
      "Travel day",
    );
    await user.click(
      screen.getByRole("button", { name: "Preview disclosure" }),
    );
    await screen.findByRole("dialog");
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(bridge.request).not.toHaveBeenCalled();
  });

  it("does not invoke recommendation previews in local-only mode", async () => {
    const bridge = testBridge(completedOutcome());
    const user = userEvent.setup();
    renderPanel(bridge, undefined, true);

    const preview = screen.getByRole("button", {
      name: "Preview disclosure",
    });
    expect(preview).toBeDisabled();
    await user.click(preview);

    expect(bridge.preview).not.toHaveBeenCalled();
    expect(bridge.request).not.toHaveBeenCalled();
  });

  it("renders completed proposals and saves only after an explicit action", async () => {
    const bridge = testBridge(completedOutcome());
    const onSaveProposal = vi.fn(async () => undefined);
    const user = userEvent.setup();
    renderPanel(bridge, onSaveProposal);

    await requestRecommendation(user);
    expect(onSaveProposal).not.toHaveBeenCalled();
    const proposalItems = screen.getByRole("list", {
      name: "Simple dinner items",
    });
    expect(proposalItems).toHaveTextContent("White Oxford shirt");
    expect(proposalItems).toHaveTextContent("Navy trousers");

    await user.click(screen.getByRole("button", { name: "Save outfit" }));
    await waitFor(() => expect(onSaveProposal).toHaveBeenCalledTimes(1));
    expect(onSaveProposal).toHaveBeenCalledWith(proposal());
  });

  it.each([
    [
      {
        outcome: "refused",
        audit: audit(),
      } satisfies OutfitRecommendationOutcomeV1,
      "Request refused",
    ],
    [
      {
        outcome: "failed",
        code: "grounding",
        retryable: false,
        audit: null,
      } satisfies OutfitRecommendationOutcomeV1,
      "Typed failure: grounding.",
    ],
    [
      {
        outcome: "historical_stale",
        catalog_changed: true,
        outfit_changed: false,
      } satisfies OutfitRecommendationOutcomeV1,
      "This saved result is stale because the wardrobe changed.",
    ],
  ])("renders provider outcome %#", async (outcome, expected) => {
    const bridge = testBridge(outcome);
    const user = userEvent.setup();
    renderPanel(bridge);

    await requestRecommendation(user);
    expect(await screen.findByText(expected, { exact: false })).toBeVisible();
  });
});

async function requestRecommendation(
  user: ReturnType<typeof userEvent.setup>,
) {
  await user.type(
    screen.getByRole("textbox", { name: "What do you need?" }),
    "Dinner",
  );
  await user.click(
    screen.getByRole("button", { name: "Preview disclosure" }),
  );
  await user.click(
    await screen.findByRole("button", { name: "Send to OpenAI" }),
  );
}

function renderPanel(
  bridge: TestBridge,
  onSaveProposal = vi.fn(async () => undefined),
  localOnly = false,
) {
  return render(
    <OutfitRecommendationPanel
      localOnly={localOnly}
      items={items()}
      catalogRevision={7}
      outfitRevision={4}
      credentials={credentials()}
      retention={{
        mode: "MAM",
        provenance: "OpenAI project settings",
      }}
      bridge={bridge}
      onSaveProposal={onSaveProposal}
    />,
  );
}

type TestBridge = OutfitRecommendationBridge & {
  preview: ReturnType<typeof vi.fn>;
  request: ReturnType<typeof vi.fn>;
};

function testBridge(outcome: OutfitRecommendationOutcomeV1): TestBridge {
  return {
    preview: vi.fn(async () => previewResponse()),
    request: vi.fn(async () => ({
      schema_version: 1 as const,
      request_id: "request-result",
      outcome,
    })),
  };
}

function previewResponse(): PreviewOutfitRecommendationV1Response {
  return {
    schema_version: 1,
    request_id: "request-preview",
    provider_status: "ready",
    disclosure: {
      provider: "OpenAI",
      model: "gpt-5.6-sol",
      purpose: "Grounded outfit recommendations",
      disclosed_field_classes: ["prompt", "item_ids"],
      photos_disclosed: false,
      email_disclosed: false,
      paths_disclosed: false,
      notes_disclosed: false,
      sizes_disclosed: false,
      evidence_metadata_disclosed: false,
      retention: {
        revision: "openai-retention-v1",
        declaration: {
          mode: "MAM",
          provenance: "OpenAI project settings",
        },
        store: false,
        store_false_is_not_zdr: true,
        default_abuse_monitoring_max_days: 30,
        safety_review_exceptions_apply: true,
        prompt_cache_mode: "explicit",
        prompt_cache_breakpoint_count: 0,
        prompt_cache_ttl_minimum_default: "5m",
        prompt_cache_may_retain_longer: true,
        no_breakpoints_no_cache_reads_or_writes: true,
      },
    },
    approval: {
      approval_id: "approval-1",
      expires_at: "2026-07-15T12:00:00Z",
      single_use: true,
      catalog_revision: 7,
      outfit_revision: 4,
    },
  };
}

function completedOutcome(): OutfitRecommendationOutcomeV1 {
  return {
    outcome: "completed",
    recommendation: {
      schema_revision: "recommendation-v1",
      compatibility_revision: "compatibility-v1",
      capability_revision: "capability-v1",
      catalog_revision: 7,
      outfit_revision: 4,
      proposals: [proposal()],
    },
    audit: audit(),
  };
}

function proposal(): OutfitProposalV1 {
  return {
    name: "Simple dinner",
    item_ids: ["item-top", "item-bottom"],
    rationale: "A clean, relaxed combination.",
    caveats: [],
    unresolved_constraints: [],
    constraint_assessment: [],
  };
}

function audit() {
  return {
    provider: "OpenAI",
    model: "gpt-5.6-sol",
    provider_request_id: "provider-request",
    response_id: "response-1",
    retention: previewResponse().disclosure.retention,
    reported_cache_usage: false,
    usage: {
      input_tokens: 100,
      output_tokens: 50,
      reasoning_tokens: 20,
      response_calls: 1,
      tool_calls: 1,
      prompt_cache_read_tokens: 0,
      prompt_cache_write_tokens: 0,
    },
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
    {
      credential_id: "credential-gmail",
      provider: "gmail",
      display_label: "Gmail",
      status: "active",
      updated_at: "2026-07-15T08:00:00Z",
    },
  ];
}

function items(): CatalogItemV1[] {
  return [
    catalogItem("item-top", "White Oxford shirt", "top"),
    catalogItem("item-bottom", "Navy trousers", "bottom"),
  ];
}

function catalogItem(
  itemId: string,
  displayName: string,
  category: "top" | "bottom",
): CatalogItemV1 {
  return {
    item_id: itemId,
    attributes: {
      display_name: displayName,
      category,
      subcategory: null,
      brand: null,
      primary_color: null,
      size: null,
      notes: null,
      tags: [],
    },
    evidence_ids: [],
    last_decision_id: `decision-${itemId}`,
  };
}
