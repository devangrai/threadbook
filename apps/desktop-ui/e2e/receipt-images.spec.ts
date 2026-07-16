import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

async function expectAccessible(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
}

test("receipt image approval remains inert until one explicit host confirmation", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Receipts" }).click();
  await page
    .getByRole("button", { name: "Analyze receipt from unknown merchant" })
    .click();

  const approval = page.getByRole("button", {
    name: "Download image from images.example.test",
  });
  await expect(approval).toBeVisible();
  await expect(page.locator('img[src^="http"], a[href^="http"]')).toHaveCount(0);
  expect(
    (await transportCalls(page)).filter(
      (call) => call.command === "approve_and_fetch_receipt_image_v1",
    ),
  ).toHaveLength(0);

  await approval.click();
  await expect(page.getByText(/connect only to/i)).toContainText(
    "images.example.test",
  );
  await page.getByRole("dialog")
    .getByRole("button", {
      name: "Download image from images.example.test",
    })
    .click();

  await expect(page.getByText("Receipt image stored locally.")).toBeVisible();
  await expect(page.getByText(/stored locally, 640 by 800/i)).toBeVisible();
  const calls = await transportCalls(page);
  expect(
    calls.filter(
      (call) => call.command === "approve_and_fetch_receipt_image_v1",
    ),
  ).toHaveLength(1);
  const fetch = calls.find(
    (call) => call.command === "approve_and_fetch_receipt_image_v1",
  );
  expect(fetch?.request).toEqual(
    expect.objectContaining({
      approved_display_host: "images.example.test",
      candidate_url_sha256: "a".repeat(64),
      prior_attempt_id: null,
    }),
  );
  expect(JSON.stringify(fetch?.request)).not.toContain("https://");

  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await expectAccessible(page);
  await page.screenshot({
    path: "test-results/p03-receipt-images-mobile.png",
    fullPage: true,
  });
});

async function transportCalls(page: Page) {
  return page.evaluate(() => {
    const target = window as typeof window & {
      __WARDROBE_E2E__?: {
        calls: Array<{ command: string; request: Record<string, unknown> }>;
      };
    };
    return target.__WARDROBE_E2E__?.calls ?? [];
  });
}
