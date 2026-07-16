import { describe, expect, it } from "vitest";

import {
  authorityHealthLabel,
  credentialStatusLabel,
  formatAction,
  formatError,
  formatJobKind,
  formatTimestamp,
  isConflictError,
} from "./foundation-model";

describe("foundation view formatting", () => {
  it("turns stable machine values into compact labels", () => {
    expect(formatJobKind("verify_blob_v1")).toBe("Verify Blob");
    expect(formatAction("run_storage_check")).toBe("Run Storage Check");
    expect(credentialStatusLabel("pending_delete")).toBe("Removing");
    expect(authorityHealthLabel("fail_closed_default")).toBe(
      "Fail-closed default",
    );
    expect(authorityHealthLabel("fail_closed_uncertain")).toBe(
      "Fail-closed pending repair",
    );
  });

  it("uses actionable structured errors without exposing unknown payloads", () => {
    expect(
      formatError({
        code: "blob_unavailable",
        retryable: true,
        user_action: "run_storage_check",
      }),
    ).toBe("Run Storage Check");
    expect(formatError(new Error("synthetic-secret-value"))).toBe(
      "Local data is unavailable.",
    );
  });

  it("handles malformed timestamps deterministically", () => {
    expect(formatTimestamp("not-a-date")).toBe("Unknown time");
  });

  it("recognizes only typed request conflicts for authority refresh", () => {
    expect(isConflictError({ code: "request_conflict" })).toBe(true);
    expect(isConflictError({ code: "storage_unavailable" })).toBe(false);
    expect(isConflictError(new Error("request_conflict"))).toBe(false);
  });
});
