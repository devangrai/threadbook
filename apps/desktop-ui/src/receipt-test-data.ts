import type {
  AnalyzeReceiptV1Response,
  ParsedReceiptEvidenceV1,
  ReceiptOrderEvidenceV1,
  ReceiptProcessingMetadataV1,
  ReceiptSummaryV1,
} from "./generated/contracts";
import type { AnalyzedReceipt } from "./receipt-bridge";
import { verifyReceiptCitations } from "./receipt-model";

export const receiptIds = {
  source: "71000000-0000-4000-8000-000000000001",
  parse: "72000000-0000-4000-8000-000000000001",
  fragment: "73000000-0000-4000-8000-000000000001",
  run: "74000000-0000-4000-8000-000000000001",
  order: "75000000-0000-4000-8000-000000000001",
  line: "76000000-0000-4000-8000-000000000001",
  variant: "77000000-0000-4000-8000-000000000001",
};

const text =
  "Northstar Outfitters\nOrder R-100\nPurchase Cotton Shirt x2 2599 USD";

const citation = (
  byteStart: number,
  byteEnd: number,
  quoteSha256: string,
) => ({
  fragment_id: receiptIds.fragment,
  byte_start: byteStart,
  byte_end: byteEnd,
  quote_sha256: quoteSha256,
});

export const parsedReceiptFixture: ParsedReceiptEvidenceV1 = {
  parse_id: receiptIds.parse,
  source_id: receiptIds.source,
  raw_blob_sha256: "1".repeat(64),
  parser_revision: "mail-parser-v1",
  sanitizer_revision: "html-sanitizer-v1",
  canonical_input_sha256: "2".repeat(64),
  fragments: [
    {
      fragment_id: receiptIds.fragment,
      ordinal: 0,
      kind: "plain_text",
      text,
      content_sha256: "3".repeat(64),
      metadata: null,
    },
  ],
};

export const processingFixture: ReceiptProcessingMetadataV1 = {
  provider_id: "local-deterministic-receipt",
  provider_revision: "1",
  extraction_schema: "receipt-extraction-v1",
  extraction_schema_sha256: "4".repeat(64),
  ruleset_revision: "receipt-rules-v1",
  ruleset_sha256: "5".repeat(64),
  parameters: {
    deterministic: true,
    temperature_milli: 0,
    locale: null,
  },
  canonical_input_sha256: parsedReceiptFixture.canonical_input_sha256,
  parent_source_id: receiptIds.source,
  parent_source_sha256: parsedReceiptFixture.raw_blob_sha256,
  fragment_sha256: [parsedReceiptFixture.fragments[0]!.content_sha256],
};

export const receiptOrderFixture: ReceiptOrderEvidenceV1 = {
  order_evidence_id: receiptIds.order,
  extraction_run_id: receiptIds.run,
  source_id: receiptIds.source,
  parse_id: receiptIds.parse,
  merchant: {
    value: "Northstar Outfitters",
    citations: [
      citation(
        0,
        20,
        "17989b325de992256170abd67c13fb7574495f93f443eea31ca92a776305654c",
      ),
    ],
  },
  order_identifier: {
    value: "R-100",
    citations: [
      citation(
        27,
        32,
        "6a457dee260e4f807e648e88f8519669ac791a027136aa6c8a7d51a2402a4641",
      ),
    ],
  },
  purchase_date: { value: null, citations: [] },
  currency: {
    value: "USD",
    citations: [
      citation(
        63,
        66,
        "a26cdf3a6e709124385d4d7eb9bff6b897a58ed5597fbab779b89849dbe81b21",
      ),
    ],
  },
  line_items: [
    {
      order_line_id: receiptIds.line,
      line_number: 1,
      description: {
        value: "Cotton Shirt",
        citations: [
          citation(
            42,
            54,
            "5e780e4a4a0fa4f6f65de74c8d746f10af4efb75274e8c7641621ae58f70cb2b",
          ),
        ],
      },
      event_kind: {
        value: "purchase",
        citations: [
          citation(
            33,
            41,
            "5b5e9c65b400565c2cd80615d8c56ebdc45b769dd18b950344428dbcf67b5069",
          ),
        ],
      },
      quantity: {
        value: 2,
        citations: [
          citation(
            56,
            57,
            "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
          ),
        ],
      },
      unit_price_minor: {
        value: 2599,
        citations: [
          citation(
            58,
            62,
            "533099ac357e5586238f6be92e706eacb5dea6559fa61b979069c39c5efe8cee",
          ),
        ],
      },
      variant: {
        variant_evidence_id: receiptIds.variant,
        brand: { value: null, citations: [] },
        sku: { value: null, citations: [] },
        size: { value: null, citations: [] },
        color: { value: null, citations: [] },
      },
    },
  ],
  review_head: null,
};

export function receiptSummaryFixture(
  state: ReceiptSummaryV1["state"] = "needs_review",
): ReceiptSummaryV1 {
  return {
    source_id: receiptIds.source,
    state,
    order_evidence_id: state === "unanalyzed" ? null : receiptIds.order,
    merchant: state === "unanalyzed" ? null : "Northstar Outfitters",
    line_item_count: state === "unanalyzed" ? 0 : 1,
    processing: state === "unanalyzed" ? null : processingFixture,
    review_head: null,
  };
}

export async function analyzedReceiptFixture(): Promise<AnalyzedReceipt> {
  const response: AnalyzeReceiptV1Response = {
    schema_version: 1,
    request_id: "79000000-0000-4000-8000-000000000001",
    parsed: parsedReceiptFixture,
    order: receiptOrderFixture,
    processing: processingFixture,
    state: "needs_review",
    receipt_revision: 4,
    evidence_generation: 3,
    replay_status: "created",
  };
  return {
    ...response,
    verified: await verifyReceiptCitations(response.parsed, response.order),
  };
}
