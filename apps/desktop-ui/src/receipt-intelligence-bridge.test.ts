import { describe, expect, it, vi } from "vitest";

import { createReceiptIntelligenceBridge } from "./receipt-intelligence-bridge";
import type { InvokeCommand } from "./invoke-transport";
import type {
  ListReceiptIntelligenceV1Response,
  PreviewReceiptIntelligenceV1Response,
  ReceiptIntelligencePreviewV1,
  RequestReceiptIntelligenceV1Response,
} from "./generated/contracts";

describe("receipt intelligence bridge", () => {
  it("uses generated preview, consent, outcome, and durable-list contracts", async () => {
    const preview = previewFixture();
    const invokeMock = vi.fn(
      async (command: string, args?: Record<string, unknown>) => {
        const request = args?.request as { request_id: string };
        if (command === "preview_receipt_intelligence_v1") {
          return {
            schema_version: 1,
            request_id: request.request_id,
            preview,
          } satisfies PreviewReceiptIntelligenceV1Response;
        }
        if (command === "request_receipt_intelligence_v1") {
          return {
            schema_version: 1,
            request_id: request.request_id,
            outcome: {
              outcome: "completed",
              classification: {
                classification_id: uuid(5),
                attempt_id: uuid(4),
                source_id: uuid(1),
                source_revision_id: uuid(2),
                classification: "apparel_order",
                order_evidence_id: uuid(6),
                created_at: "2026-07-16T21:00:00Z",
              },
              audit: auditFixture(),
            },
            replay_status: "created",
          } satisfies RequestReceiptIntelligenceV1Response;
        }
        return {
          schema_version: 1,
          request_id: request.request_id,
          availability: {
            available: false,
            reason: "release_evidence_unavailable",
            offline_receipt_analysis_available: true,
            existing_wardrobe_access_available: true,
          },
          attempts: [
            {
              attempt_id: uuid(4),
              approval_id: uuid(3),
              source_id: uuid(1),
              source_revision_id: uuid(2),
              state: "completed",
              classification: {
                classification_id: uuid(5),
                attempt_id: uuid(4),
                source_id: uuid(1),
                source_revision_id: uuid(2),
                classification: "apparel_order",
                order_evidence_id: uuid(6),
                created_at: "2026-07-16T21:00:00Z",
              },
              failure: null,
              audit: auditFixture(),
              created_at: "2026-07-16T21:00:00Z",
              updated_at: "2026-07-16T21:00:01Z",
            },
          ],
          total_count: 1,
          receipt_intelligence_revision: 1,
          next_cursor: null,
        } satisfies ListReceiptIntelligenceV1Response;
      },
    );
    const ids = [uuid(10), uuid(11), uuid(12)];
    const bridge = createReceiptIntelligenceBridge(
      invokeMock as unknown as InvokeCommand,
      () => ids.shift() ?? uuid(13),
    );

    const response = await bridge.preview(uuid(1));
    expect(invokeMock).toHaveBeenNthCalledWith(
      1,
      "preview_receipt_intelligence_v1",
      {
        request: {
          schema_version: 1,
          request_id: uuid(10),
          source_id: uuid(1),
        },
      },
    );

    await expect(bridge.request(response.preview)).resolves.toMatchObject({
      state: "completed",
      classification: "apparel_order",
      review_available: true,
    });
    expect(invokeMock.mock.calls[1]?.[1]?.request).toEqual({
      schema_version: 1,
      request_id: uuid(11),
      consent: { affirmative: true, preview },
    });

    await expect(bridge.latest(uuid(1))).resolves.toMatchObject({
      availability: {
        available: false,
        reason: "release_evidence_unavailable",
      },
      attempt: {
        state: "completed",
        source_id: uuid(1),
      },
    });
    expect(invokeMock.mock.calls[2]?.[1]?.request).toEqual({
      schema_version: 1,
      request_id: uuid(12),
      state: null,
      classification: null,
      cursor: null,
      limit: 100,
    });
  });
});

function previewFixture(): ReceiptIntelligencePreviewV1 {
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
      provenance: "openai-api-data-controls-2026-07-16",
    },
    local_provider_payload_retained: false,
    store: false,
    store_false_is_not_organization_zdr: true,
    default_abuse_monitoring_max_days: 30,
    safety_review_exceptions_apply: true,
  };
  return {
    disclosure: {
      provider: "openai",
      model: "gpt-5.6-sol",
      purpose: "receipt_intelligence",
      projection: {
        revision: "receipt-intelligence-projection-v1",
        fragments: [{ fragment_ref: "fragment-0000", text: "Trail Tee" }],
      },
      aggregate_text_bytes: 9,
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
      source_id: uuid(1),
      source_revision_id: uuid(2),
      source_revision_sha256: "1".repeat(64),
      disclosed_fragment_sha256: ["2".repeat(64)],
      projection_sha256: "3".repeat(64),
      serialized_request_sha256: "4".repeat(64),
      serialized_request_bytes: 2048,
      credential_id: uuid(9),
      provider: "openai",
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
  };
}

function auditFixture() {
  return {
    audit_id: uuid(7),
    attempt_id: uuid(4),
    source_id: uuid(1),
    source_revision_id: uuid(2),
    source_revision_sha256: "1".repeat(64),
    projection_sha256: "3".repeat(64),
    serialized_request_sha256: "4".repeat(64),
    response_sha256: null,
    provider: "openai",
    model: "gpt-5.6-sol",
    provider_request_id: "req_fixture",
    response_id: "resp_fixture",
    prompt_revision: "receipt-intelligence-prompt-v1",
    schema_revision: "receipt-intelligence-v1",
    projection_revision: "receipt-intelligence-projection-v1",
    retention_provenance: "openai-api-data-controls-2026-07-16",
    parameters: {
      revision: "receipt-intelligence-parameters-v1",
      store: false,
      background: false,
      tools_enabled: false,
      previous_response_id_present: false,
      strict_schema: true,
      reasoning_effort: "low" as const,
      max_output_tokens: 4000,
      timeout_millis: 60_000,
      max_attempts: 1,
    },
    execution_bounds: {
      max_request_bytes: 262_144,
      max_response_bytes: 2_097_152,
      max_output_tokens: 4_000,
      timeout_millis: 60_000,
      max_attempts: 1,
    },
    usage: {
      request_bytes: 2048,
      response_bytes: 1024,
      input_tokens: 100,
      output_tokens: 50,
      total_tokens: 150,
      reasoning_tokens: 10,
      cached_input_tokens: 0,
      attempts: 1,
    },
    dispatched_at: "2026-07-16T21:00:00Z",
    finished_at: "2026-07-16T21:00:01Z",
  };
}

function uuid(value: number) {
  return `00000000-0000-4000-8000-${value.toString().padStart(12, "0")}`;
}
