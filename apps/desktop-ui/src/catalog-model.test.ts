import { describe, expect, it } from "vitest";

import {
  appendUniqueById,
  displayCatalogError,
  normalizeAttributes,
  validateAttributes,
} from "./catalog-model";

describe("catalog model", () => {
  it("appends cursor pages without duplicate identities", () => {
    expect(
      appendUniqueById(
        [
          { id: "a", label: "Old" },
          { id: "b", label: "Second" },
        ],
        [
          { id: "a", label: "New" },
          { id: "c", label: "Third" },
        ],
        (value) => value.id,
      ),
    ).toEqual([
      { id: "a", label: "New" },
      { id: "b", label: "Second" },
      { id: "c", label: "Third" },
    ]);
  });

  it("normalizes and validates bounded item attributes", () => {
    const values = {
      display_name: "  White shirt ",
      category: "top" as const,
      color: " White ",
      notes: " Personal staple ",
    };
    expect(validateAttributes(values)).toBeNull();
    expect(normalizeAttributes(values)).toEqual({
      display_name: "White shirt",
      category: "top",
      color: "White",
      notes: "Personal staple",
    });
    expect(validateAttributes({ ...values, display_name: " " })).toBe(
      "Name is required.",
    );
  });

  it("gives revision conflicts a state-preserving instruction", () => {
    expect(
      displayCatalogError({
        code: "request_conflict",
        retryable: false,
      }),
    ).toContain("Your edits are still here");
  });
});
