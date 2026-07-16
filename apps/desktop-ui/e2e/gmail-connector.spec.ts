import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("configure, import, sync, and disconnect Gmail while preserving evidence", async ({
  page,
}) => {
  const remoteRequests: string[] = [];
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
  await expect(page.getByText("Not configured", { exact: true })).toBeVisible();
  await page
    .getByRole("textbox", { name: "OAuth client ID" })
    .fill("personal-desktop.apps.googleusercontent.com");
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
  await page.getByRole("button", { name: "Disconnect" }).click();
  await expect(page.getByText(/Local credential removed/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "Connect Gmail" })).toBeVisible();

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
    "get_gmail_connector_v1",
    "save_gmail_settings_v1",
    "get_gmail_connector_v1",
    "connect_gmail_v1",
    "get_gmail_connector_v1",
    "get_gmail_connector_v1",
    "sync_gmail_v1",
    "get_gmail_connector_v1",
    "disconnect_gmail_v1",
    "get_gmail_connector_v1",
  ]);
  expect(JSON.stringify(gmailCalls)).not.toMatch(/refresh|access_token|secret/i);

  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  expect(remoteRequests).toEqual([]);

  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});
