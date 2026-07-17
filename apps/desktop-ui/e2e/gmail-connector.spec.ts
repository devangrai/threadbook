import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Fixture-only UI smoke: backend contract acceptance is covered outside Vite.
test("Gmail settings UI persists through reload and retains imported evidence", async ({
  page,
}) => {
  const remoteRequests: string[] = [];
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (
      (url.protocol === "http:" || url.protocol === "https:") &&
      url.hostname !== "127.0.0.1"
    ) {
      remoteRequests.push(request.url());
    }
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByRole("switch", { name: "Local only" }).click();
  await expect(
    page.getByRole("dialog", { name: "Enable personal live?" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Enable personal live" }).click();
  await expect(page.getByText("Personal-live mode enabled.")).toBeVisible();
  await expect(
    page.getByRole("switch", { name: "Personal live" }),
  ).toHaveAttribute("aria-checked", "false");
  await expect(page.getByText("Not configured", { exact: true })).toBeVisible();
  await page
    .getByRole("textbox", { name: "OAuth client ID" })
    .fill("personal-desktop.apps.googleusercontent.com");
  const query = '  newer_than:3m subject:"Wardrobe P10A receipt"  ';
  await page.getByRole("textbox", { name: "Gmail query" }).fill(query);
  await expect(
    page.getByText(/completely reconciles every result/i),
  ).toBeVisible();
  await expect(
    page.getByText(/Previously imported messages stay in Wardrobe/i),
  ).toBeVisible();
  await page.getByRole("spinbutton", { name: "Page size" }).fill("25");
  await page.getByRole("spinbutton", { name: "Max pages" }).fill("3");
  await page.getByRole("spinbutton", { name: "Max messages" }).fill("75");
  await page
    .getByRole("spinbutton", { name: "Max total raw bytes" })
    .fill("1048576");
  await expect(page.getByText("1-104857600 bytes total")).toBeVisible();
  await page.getByRole("button", { name: "Save settings" }).click();
  await expect(page.getByText("Gmail settings saved.")).toBeVisible();

  await page.getByRole("button", { name: "Connect Gmail" }).click();
  await expect(page.getByText("Gmail connected.")).toBeVisible();
  await expect(page.getByText(/1 imported, 0 updated/)).toBeVisible();

  await page.getByRole("button", { name: "Inbox" }).click();
  await expect(
    page.getByText("Gmail purchase: Linen overshirt", { exact: true }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByRole("button", { name: "Sync now" }).click();
  await expect(page.getByText("Gmail synced.")).toBeVisible();

  await page.reload();
  await expect(page.locator(".local-status")).toHaveText("Personal live");
  await page.getByRole("button", { name: "Inbox" }).click();
  await expect(
    page.getByText("Gmail purchase: Linen overshirt", { exact: true }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Settings" }).click();
  await expect(page.getByRole("button", { name: "Sync now" })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Gmail query" })).toHaveValue(
    query,
  );
  await expect(page.getByRole("spinbutton", { name: "Page size" })).toHaveValue(
    "25",
  );
  await expect(page.getByRole("spinbutton", { name: "Max pages" })).toHaveValue(
    "3",
  );
  await expect(
    page.getByRole("spinbutton", { name: "Max messages" }),
  ).toHaveValue("75");
  await expect(
    page.getByRole("spinbutton", { name: "Max total raw bytes" }),
  ).toHaveValue("1048576");
  await page.getByRole("button", { name: "Disconnect" }).click();
  await expect(page.getByText(/Local credential removed/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "Connect Gmail" })).toBeVisible();

  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  expect(
    await page.evaluate(() => {
      const blocks = Array.from(
        document.querySelectorAll<HTMLElement>(
          ".gmail-settings-form > .gmail-client-id, " +
            ".gmail-settings-form > .gmail-discovery-mode, " +
            ".gmail-settings-form > .gmail-query, " +
            ".gmail-settings-form > .gmail-discovery-note, " +
            ".gmail-settings-form > .gmail-sync-limits, " +
            ".gmail-settings-form > .form-submit",
        ),
      ).filter((element) => element.offsetParent !== null);
      const rectangles = blocks.map((element) => element.getBoundingClientRect());
      return rectangles.some((rectangle, index) =>
        rectangles.slice(index + 1).some(
          (other) =>
            Math.min(rectangle.right, other.right) -
                Math.max(rectangle.left, other.left) >
              0 &&
            Math.min(rectangle.bottom, other.bottom) -
                Math.max(rectangle.top, other.top) >
              0,
        ),
      );
    }),
  ).toBe(false);

  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);

  await page.getByRole("button", { name: "Inbox" }).click();
  await expect(
    page.getByText("Gmail purchase: Linen overshirt", { exact: true }),
  ).toBeVisible();

  const calls = await page.evaluate(() => {
    const target = window as typeof window & {
      __WARDROBE_E2E__?: {
        calls: Array<{ command: string; request: Record<string, unknown> }>;
      };
    };
    return target.__WARDROBE_E2E__?.calls ?? [];
  });
  const gmailCalls = calls.filter((call) => call.command.includes("gmail"));
  expect(gmailCalls.map((call) => call.command)).toEqual([
    "get_gmail_connector_v2",
    "save_gmail_settings_v2",
    "get_gmail_connector_v2",
    "connect_gmail_v1",
    "get_gmail_connector_v2",
    "get_gmail_connector_v2",
    "sync_gmail_v1",
    "get_gmail_connector_v2",
    "get_gmail_connector_v2",
    "disconnect_gmail_v1",
    "get_gmail_connector_v2",
  ]);
  expect(
    (
      gmailCalls.find((call) => call.command === "save_gmail_settings_v2")
        ?.request.discovery_scope as { kind?: string; query?: string }
    ),
  ).toEqual({ kind: "search", query });
  expect(
    gmailCalls.find((call) => call.command === "save_gmail_settings_v2")
      ?.request.limits,
  ).toEqual({
    page_size: 25,
    max_pages: 3,
    max_unique_messages: 75,
    max_total_raw_bytes: 1_048_576,
  });
  expect(JSON.stringify(gmailCalls)).not.toMatch(/refresh|access_token|secret/i);

  expect(remoteRequests).toEqual([]);
  expect(pageErrors).toEqual([]);
});
