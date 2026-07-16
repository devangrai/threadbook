import type {
  CorrectedReceiptOrderV1,
  FragmentCitationV1,
  ParsedReceiptEvidenceV1,
  ReceiptEventKindV1,
  ReceiptOrderEvidenceV1,
} from "./generated/contracts";

export const UNKNOWN_VALUE = "Unknown";

export type ReceiptCorrectionDraft = {
  order_evidence_id: string;
  merchant: string;
  order_identifier: string;
  purchase_date: string;
  currency: string;
  line_items: Array<{
    order_line_id: string;
    description: string;
    event_kind: ReceiptEventKindV1 | "";
    quantity: string;
    unit_price_minor: string;
    variant: {
      variant_evidence_id: string;
      brand: string;
      sku: string;
      size: string;
      color: string;
    };
  }>;
};

export type VerifiedReceiptOrder = {
  order: ReceiptOrderEvidenceV1;
  quotes: ReadonlyMap<string, string>;
};

export function evidenceValue<T>(value: T | null): T | typeof UNKNOWN_VALUE {
  return value ?? UNKNOWN_VALUE;
}

export function createCorrectionDraft(
  order: ReceiptOrderEvidenceV1,
): ReceiptCorrectionDraft {
  const corrected = order.review_head?.decision.corrected_order;
  if (corrected) {
    return {
      order_evidence_id: corrected.order_evidence_id,
      merchant: corrected.merchant ?? "",
      order_identifier: corrected.order_identifier ?? "",
      purchase_date: corrected.purchase_date ?? "",
      currency: corrected.currency ?? "",
      line_items: corrected.line_items.map((line) => ({
        order_line_id: line.order_line_id,
        description: line.description ?? "",
        event_kind: line.event_kind ?? "",
        quantity: line.quantity?.toString() ?? "",
        unit_price_minor: line.unit_price_minor?.toString() ?? "",
        variant: {
          variant_evidence_id: line.variant.variant_evidence_id,
          brand: line.variant.brand ?? "",
          sku: line.variant.sku ?? "",
          size: line.variant.size ?? "",
          color: line.variant.color ?? "",
        },
      })),
    };
  }

  return {
    order_evidence_id: order.order_evidence_id,
    merchant: order.merchant.value ?? "",
    order_identifier: order.order_identifier.value ?? "",
    purchase_date: order.purchase_date.value ?? "",
    currency: order.currency.value ?? "",
    line_items: order.line_items.map((line) => ({
      order_line_id: line.order_line_id,
      description: line.description.value ?? "",
      event_kind: line.event_kind.value ?? "",
      quantity: line.quantity.value?.toString() ?? "",
      unit_price_minor: line.unit_price_minor.value?.toString() ?? "",
      variant: {
        variant_evidence_id: line.variant.variant_evidence_id,
        brand: line.variant.brand.value ?? "",
        sku: line.variant.sku.value ?? "",
        size: line.variant.size.value ?? "",
        color: line.variant.color.value ?? "",
      },
    })),
  };
}

export function correctedOrderFromDraft(
  draft: ReceiptCorrectionDraft,
): { value: CorrectedReceiptOrderV1 | null; error: string | null } {
  const currency = nullableText(draft.currency)?.toUpperCase() ?? null;
  if (currency && !/^[A-Z]{3}$/u.test(currency)) {
    return { value: null, error: "Currency must be a three-letter code." };
  }
  const purchaseDate = nullableText(draft.purchase_date);
  if (purchaseDate && !isIsoDate(purchaseDate)) {
    return { value: null, error: "Purchase date must be a valid date." };
  }

  const lineItems: CorrectedReceiptOrderV1["line_items"] = [];
  for (const [index, line] of draft.line_items.entries()) {
    const quantity = nullableInteger(line.quantity);
    if (quantity === undefined || (quantity !== null && quantity < 1)) {
      return {
        value: null,
        error: `Line ${index + 1} quantity must be a whole number of at least 1.`,
      };
    }
    if (quantity !== null && quantity > 10_000) {
      return {
        value: null,
        error: `Line ${index + 1} quantity must be 10,000 or less.`,
      };
    }
    const unitPrice = nullableInteger(line.unit_price_minor);
    if (
      unitPrice === undefined ||
      (unitPrice !== null &&
        (unitPrice < 0 || !Number.isSafeInteger(unitPrice)))
    ) {
      return {
        value: null,
        error: `Line ${index + 1} unit price must be a non-negative whole number.`,
      };
    }
    lineItems.push({
      order_line_id: line.order_line_id,
      description: nullableText(line.description),
      event_kind: line.event_kind || null,
      quantity,
      unit_price_minor: unitPrice,
      variant: {
        variant_evidence_id: line.variant.variant_evidence_id,
        brand: nullableText(line.variant.brand),
        sku: nullableText(line.variant.sku),
        size: nullableText(line.variant.size),
        color: nullableText(line.variant.color),
      },
    });
  }

  return {
    value: {
      order_evidence_id: draft.order_evidence_id,
      merchant: nullableText(draft.merchant),
      order_identifier: nullableText(draft.order_identifier),
      purchase_date: purchaseDate,
      currency,
      line_items: lineItems,
    },
    error: null,
  };
}

export function citationKey(citation: FragmentCitationV1): string {
  return [
    citation.fragment_id,
    citation.byte_start,
    citation.byte_end,
    citation.quote_sha256,
  ].join(":");
}

export async function verifyReceiptCitations(
  parsed: ParsedReceiptEvidenceV1,
  order: ReceiptOrderEvidenceV1,
): Promise<VerifiedReceiptOrder> {
  const fragments = new Map(
    parsed.fragments.map((fragment) => [fragment.fragment_id, fragment]),
  );
  const quotes = new Map<string, string>();

  for (const citation of orderCitations(order)) {
    const fragment = fragments.get(citation.fragment_id);
    if (!fragment) {
      throw new Error("Receipt citation references an unknown fragment.");
    }
    const bytes = new TextEncoder().encode(fragment.text);
    if (
      !Number.isInteger(citation.byte_start) ||
      !Number.isInteger(citation.byte_end) ||
      citation.byte_start < 0 ||
      citation.byte_end <= citation.byte_start ||
      citation.byte_end > bytes.length
    ) {
      throw new Error("Receipt citation has an invalid byte span.");
    }

    let quote: string;
    try {
      quote = new TextDecoder("utf-8", { fatal: true }).decode(
        bytes.slice(citation.byte_start, citation.byte_end),
      );
    } catch {
      throw new Error("Receipt citation does not align to UTF-8 text.");
    }
    const digest = await sha256Hex(
      bytes.slice(citation.byte_start, citation.byte_end),
    );
    if (digest !== citation.quote_sha256.toLowerCase()) {
      throw new Error("Receipt citation quote could not be verified.");
    }
    quotes.set(citationKey(citation), quote);
  }

  return { order, quotes };
}

export function isReceiptConflict(error: unknown): boolean {
  return (
    !!error &&
    typeof error === "object" &&
    "code" in error &&
    (error as { code?: unknown }).code === "request_conflict"
  );
}

export function displayReceiptError(error: unknown): string {
  if (isReceiptConflict(error)) {
    return "This receipt changed. The latest review was reloaded and your correction is still here.";
  }
  if (error instanceof Error && error.message.startsWith("Receipt citation")) {
    return error.message;
  }
  return "The local receipt operation could not be completed.";
}

function nullableText(value: string): string | null {
  const normalized = value.trim();
  return normalized || null;
}

function nullableInteger(value: string): number | null | undefined {
  const normalized = value.trim();
  if (!normalized) return null;
  if (!/^\d+$/u.test(normalized)) return undefined;
  const number = Number(normalized);
  return Number.isSafeInteger(number) ? number : undefined;
}

function isIsoDate(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) return false;
  const date = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 10) === value;
}

function orderCitations(order: ReceiptOrderEvidenceV1): FragmentCitationV1[] {
  return [
    ...order.merchant.citations,
    ...order.order_identifier.citations,
    ...order.purchase_date.citations,
    ...order.currency.citations,
    ...order.line_items.flatMap((line) => [
      ...line.description.citations,
      ...line.event_kind.citations,
      ...line.quantity.citations,
      ...line.unit_price_minor.citations,
      ...line.variant.brand.citations,
      ...line.variant.sku.citations,
      ...line.variant.size.citations,
      ...line.variant.color.citations,
    ]),
  ];
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Receipt citation verification is unavailable.");
  }
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    Uint8Array.from(bytes).buffer,
  );
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}
