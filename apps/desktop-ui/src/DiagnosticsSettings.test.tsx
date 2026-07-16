import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { DiagnosticsSettings } from "./DiagnosticsSettings";
import type { DiagnosticsBridge } from "./diagnostics-bridge";

describe("diagnostics settings", () => {
  it("treats save-panel cancellation as a local no-op and restores focus", async () => {
    const user = userEvent.setup();
    const exportDiagnostics = vi.fn().mockResolvedValue({ cancelled: true });
    render(
      <DiagnosticsSettings
        bridge={{ export: exportDiagnostics } satisfies DiagnosticsBridge}
      />,
    );

    const button = screen.getByRole("button", { name: "Export diagnostics" });
    await user.click(button);

    expect(exportDiagnostics).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Export cancelled.",
    );
    await waitFor(() => expect(button).toHaveFocus());
  });

  it("announces one completed redacted export without exposing its path", async () => {
    const user = userEvent.setup();
    const exportDiagnostics = vi.fn().mockResolvedValue({
      cancelled: false,
      generatedAt: "2026-07-15T18:00:00Z",
      sha256: "a".repeat(64),
      byteLength: 2048,
    });
    render(
      <DiagnosticsSettings
        bridge={{ export: exportDiagnostics } satisfies DiagnosticsBridge}
      />,
    );

    await user.click(
      screen.getByRole("button", { name: "Export diagnostics" }),
    );

    const status = await screen.findByRole("status");
    expect(status).toHaveTextContent("Diagnostics exported (2.0 KB).");
    expect(status).not.toHaveTextContent("/");
    expect(exportDiagnostics).toHaveBeenCalledTimes(1);
  });
});
