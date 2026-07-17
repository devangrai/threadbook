import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type {
  ReceiptIntelligenceAttemptView,
  ReceiptIntelligenceBridge,
} from "./receipt-intelligence-bridge";
import type {
  PreviewReceiptIntelligenceV1Response,
  ReceiptIntelligenceAvailabilityReasonV1,
} from "./generated/contracts";
import { ReceiptIntelligencePanel } from "./ReceiptIntelligencePanel";

describe("receipt intelligence panel", () => {
  it("shows the exact accessible disclosure and cancellation has no approval side effect", async () => {
    const bridge = testBridge();
    const user = userEvent.setup();
    renderPanel(bridge);

    const analyze = await screen.findByRole("button", {
      name: "Analyze with OpenAI",
    });
    await user.click(analyze);

    expect(bridge.preview).toHaveBeenCalledWith("source-1");
    expect(bridge.request).not.toHaveBeenCalled();
    const dialog = await screen.findByRole("dialog", {
      name: "Review OpenAI receipt analysis",
    });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(within(dialog).getByText("OpenAI")).toBeVisible();
    expect(within(dialog).getByText("gpt-5.6-sol")).toBeVisible();
    expect(within(dialog).getByText("Classify and extract apparel receipt evidence")).toBeVisible();
    expect(dialog.querySelector("pre")).toHaveTextContent(
      "Order confirmed Linen overshirt, blue",
    );
    expect(dialog).toHaveTextContent("35 bytes");
    expect(dialog).toHaveTextContent("Provider payload is not retained locally");
    expect(dialog).toHaveTextContent("OpenAI retention declaration 2026-07-16");
    expect(dialog).toHaveTextContent(
      "store:false is not organization-level Zero Data Retention (ZDR).",
    );
    expect(
      within(dialog).getByRole("heading", { name: "Preparation bounds" }),
    ).toBeVisible();
    expect(
      within(dialog).getByRole("heading", { name: "Execution bounds" }),
    ).toBeVisible();
    expect(
      within(dialog).getByRole("button", {
        name: "Cancel OpenAI receipt analysis",
      }),
    ).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(bridge.request).not.toHaveBeenCalled();
    expect(analyze).toHaveFocus();
  });

  it("executes only after approval and hands completed evidence to separate review", async () => {
    const bridge = testBridge(completedAttempt());
    const onOpenReview = vi.fn();
    const user = userEvent.setup();
    renderPanel(bridge, false, onOpenReview);

    await user.click(
      await screen.findByRole("button", { name: "Analyze with OpenAI" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Approve and analyze" }),
    );

    await waitFor(() => expect(bridge.request).toHaveBeenCalledOnce());
    expect(bridge.request.mock.calls[0]?.[0]).toEqual(
      previewResponse().preview,
    );
    expect(
      await screen.findByText("OpenAI analysis complete"),
    ).toBeVisible();
    expect(screen.getByText(/Nothing was added to your wardrobe/)).toBeVisible();
    expect(onOpenReview).not.toHaveBeenCalled();

    await user.click(
      screen.getByRole("button", { name: "Open receipt review" }),
    );
    expect(onOpenReview).toHaveBeenCalledOnce();
  });

  it("shows content-safe progress while the single approved request is executing", async () => {
    let finish: ((value: ReceiptIntelligenceAttemptView) => void) | undefined;
    const bridge = testBridge();
    bridge.request.mockImplementation(
      () =>
        new Promise<ReceiptIntelligenceAttemptView>((resolve) => {
          finish = resolve;
        }),
    );
    const user = userEvent.setup();
    renderPanel(bridge);

    await user.click(
      await screen.findByRole("button", { name: "Analyze with OpenAI" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Approve and analyze" }),
    );

    expect(
      await screen.findByText("OpenAI analysis in progress"),
    ).toBeVisible();
    expect(
      screen.getByText(/It will not retry automatically/),
    ).toBeVisible();

    finish?.(completedAttempt());
    expect(await screen.findByText("OpenAI analysis complete")).toBeVisible();
  });

  it.each([
    ["unrelated", completedAttempt("unrelated"), "Unrelated message"],
    ["ambiguous", completedAttempt("ambiguous"), "Ambiguous message"],
    ["refusal", attempt("refused"), "OpenAI analysis refused"],
    ["failure", attempt("failed"), "OpenAI analysis failed"],
    [
      "outcome unknown",
      attempt("outcome_unknown"),
      "OpenAI analysis outcome unknown",
    ],
  ])("renders the safe %s state", async (_label, result, expected) => {
    const bridge = testBridge(result);
    const user = userEvent.setup();
    renderPanel(bridge);

    await user.click(
      await screen.findByRole("button", { name: "Analyze with OpenAI" }),
    );
    await user.click(
      screen.getByRole("button", { name: "Approve and analyze" }),
    );

    expect(await screen.findByText(expected)).toBeVisible();
    expect(screen.queryByRole("button", { name: "Open receipt review" }))
      .not.toBeInTheDocument();
  });

  it("keeps remote analysis disabled while offline analysis and saved status remain available", async () => {
    const bridge = testBridge(completedAttempt());
    bridge.latest.mockResolvedValue(
      unavailableStatus("local_only", completedAttempt()),
    );
    renderPanel(bridge, true);

    const analyze = await screen.findByRole("button", {
      name: "Analyze with OpenAI",
    });
    expect(analyze).toBeDisabled();
    expect(
      await screen.findByText(
        /Offline receipt analysis and existing wardrobe access remain available/,
      ),
    ).toBeVisible();
    expect(bridge.preview).not.toHaveBeenCalled();
    expect(await screen.findByText("OpenAI analysis complete")).toBeVisible();
  });

  it.each([
    ["release_evidence_unavailable", "unavailable in this release"],
    [
      "outbound_authority_unavailable",
      "outbound access is unavailable",
    ],
    ["credential_unavailable", "requires an active OpenAI credential"],
    [
      "retention_declaration_unavailable",
      "current provider retention information is unavailable",
    ],
  ] satisfies ReadonlyArray<
    readonly [ReceiptIntelligenceAvailabilityReasonV1, string]
  >)(
    "disables remote analysis for %s while preserving local access",
    async (reason, explanation) => {
      const bridge = testBridge();
      bridge.latest.mockResolvedValue(unavailableStatus(reason, null));
      renderPanel(bridge);

      expect(
        await screen.findByRole("button", { name: "Analyze with OpenAI" }),
      ).toBeDisabled();
      expect(await screen.findByText(new RegExp(explanation))).toBeVisible();
      expect(
        screen.getByText(
          /Offline receipt analysis and existing wardrobe access remain available/,
        ),
      ).toBeVisible();
      expect(bridge.preview).not.toHaveBeenCalled();
    },
  );
});

function renderPanel(
  bridge: TestBridge,
  localOnly = false,
  onOpenReview = vi.fn(),
) {
  return render(
    <ReceiptIntelligencePanel
      sourceId="source-1"
      localOnly={localOnly}
      bridge={bridge}
      onOpenReview={onOpenReview}
    />,
  );
}

type TestBridge = ReceiptIntelligenceBridge & {
  preview: ReturnType<typeof vi.fn>;
  request: ReturnType<typeof vi.fn>;
  latest: ReturnType<typeof vi.fn>;
};

function testBridge(
  result: ReceiptIntelligenceAttemptView = completedAttempt(),
): TestBridge {
  return {
    preview: vi.fn(async () => previewResponse()),
    request: vi.fn(async () => result),
    latest: vi.fn(async () => ({
      availability: {
        available: true,
        reason: null,
        offline_receipt_analysis_available: true,
        existing_wardrobe_access_available: true,
      },
      attempt: null,
    })),
  };
}

function unavailableStatus(
  reason: ReceiptIntelligenceAvailabilityReasonV1,
  savedAttempt: ReceiptIntelligenceAttemptView | null,
) {
  return {
    availability: {
      available: false,
      reason,
      offline_receipt_analysis_available: true,
      existing_wardrobe_access_available: true,
    },
    attempt: savedAttempt,
  };
}

function previewResponse(): PreviewReceiptIntelligenceV1Response {
  const preparation_bounds = {
    max_fragment_count: 64,
    max_fragment_bytes: 16_384,
    max_aggregate_text_bytes: 131_072,
    max_serialized_request_bytes: 262_144,
  };
  const execution_bounds = {
    max_request_bytes: 262_144,
    max_response_bytes: 2_097_152,
    max_output_tokens: 4_000,
    timeout_millis: 60_000,
    max_attempts: 1,
  };
  const retention = {
    revision: "p11-openai-responses-retention-v1",
    declaration: {
      mode: "default" as const,
      provenance: "OpenAI retention declaration 2026-07-16",
    },
    local_provider_payload_retained: false,
    store: false,
    store_false_is_not_organization_zdr: true,
    default_abuse_monitoring_max_days: 30,
    safety_review_exceptions_apply: true,
  };
  return {
    schema_version: 1,
    request_id: "preview-request",
    preview: {
      disclosure: {
      provider: "OpenAI",
      model: "gpt-5.6-sol",
      purpose: "Classify and extract apparel receipt evidence",
      projection: {
        revision: "receipt-intelligence-projection-v1",
        fragments: [
          {
            fragment_ref: "fragment-0000",
            text: "Order confirmed\nLinen overshirt, blue",
          },
        ],
      },
      aggregate_text_bytes: 35,
      raw_mime_disclosed: false,
      headers_disclosed: false,
      urls_disclosed: false,
      filenames_disclosed: false,
      attachment_metadata_disclosed: false,
      cid_metadata_disclosed: false,
      internal_identifiers_disclosed: false,
      hashes_disclosed: false,
      credentials_disclosed: false,
      image_bytes_disclosed: false,
      retention,
      preparation_bounds,
      execution_bounds,
      },
      consent_envelope: {
        source_id: "00000000-0000-4000-8000-000000000001",
        source_revision_id: "00000000-0000-4000-8000-000000000002",
        source_revision_sha256: "1".repeat(64),
        disclosed_fragment_sha256: ["2".repeat(64)],
        projection_sha256: "3".repeat(64),
        serialized_request_sha256: "4".repeat(64),
        serialized_request_bytes: 2048,
        credential_id: "00000000-0000-4000-8000-000000000003",
        provider: "OpenAI",
        model: "gpt-5.6-sol",
        prompt_revision: "receipt-intelligence-prompt-v1",
        schema_revision: "receipt-intelligence-v1",
        projection_revision: "receipt-intelligence-projection-v1",
        parameter_revision: "receipt-intelligence-parameters-v1",
        retention,
        preparation_bounds,
        execution_bounds,
        expires_at: "2026-07-16T22:00:00Z",
      },
    },
  };
}

function completedAttempt(
  classification: "apparel_order" | "unrelated" | "ambiguous" =
    "apparel_order",
): ReceiptIntelligenceAttemptView {
  return {
    ...attempt("completed"),
    classification,
    review_available: classification === "apparel_order",
  };
}

function attempt(
  state: ReceiptIntelligenceAttemptView["state"],
): ReceiptIntelligenceAttemptView {
  return {
    attempt_id: "attempt-1",
    source_id: "source-1",
    state,
    classification: null,
    review_available: false,
    failure_code: state === "failed" ? "provider_response_invalid" : null,
  };
}
