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

test("receipt analysis, review, correction, reload, and mobile workflow", async ({
  page,
}) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Receipts" }).click();
  await expect(
    page.getByRole("heading", { name: "Receipts", level: 2 }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Load more receipts" }).click();
  await expect(page.getByText("Second Look")).toBeVisible();

  await page
    .getByRole("button", { name: "Analyze receipt from unknown merchant" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Northstar Outfitters", level: 3 }),
  ).toBeFocused();
  await expect(
    page.getByRole("heading", { name: "Order line 1" }),
  ).toBeVisible();
  await expect(page.getByText("Unknown").first()).toBeVisible();
  await page.getByText("Verified source quote", { exact: true }).first().click();
  await expect(
    page.getByText("Northstar Outfitters", { exact: true }).last(),
  ).toBeVisible();
  await expectAccessible(page);

  const correct = page.getByRole("button", { name: "Correct", exact: true });
  await correct.click();
  const merchant = page.getByRole("textbox", { name: "Merchant" });
  await expect(merchant).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(correct).toBeFocused();

  await correct.click();
  await merchant.fill("Northstar Atelier");
  await page.getByRole("textbox", { name: "Line 1 brand" }).fill("Northstar");
  await page.getByRole("button", { name: "Save correction" }).click();
  await expect(page.getByText("Receipt correction saved.")).toBeVisible();

  const callsBeforeReload = await transportCalls(page);
  await page.reload();
  await page.getByRole("button", { name: "Receipts" }).click();
  await page.getByRole("button", { name: "Corrected" }).click();
  await expect(
    page.getByRole("heading", { name: "Northstar Atelier", level: 3 }),
  ).toBeVisible();
  await expect(page.getByText("Northstar", { exact: true })).toBeVisible();

  const calls = [...callsBeforeReload, ...await transportCalls(page)];
  const review = calls.find((call) => call.command === "review_receipt_v1");
  expect(review?.request).toEqual(
    expect.objectContaining({
      action: "correct",
      expected_receipt_revision: expect.any(Number),
      corrected_order: expect.objectContaining({
        merchant: "Northstar Atelier",
        line_items: [
          expect.objectContaining({
            order_line_id: expect.any(String),
            variant: expect.objectContaining({
              variant_evidence_id: expect.any(String),
              brand: "Northstar",
              sku: null,
              size: null,
              color: null,
            }),
          }),
        ],
      }),
    }),
  );
  expect(
    calls.filter((call) =>
      [
        "save_item_v1",
        "decide_evidence_v1",
        "merge_items_v1",
        "split_item_v1",
      ].includes(call.command),
    ),
  ).toEqual([]);

  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await expect(page.locator('a[href^="http"], img[src^="http"]')).toHaveCount(0);
  await expectAccessible(page);
  await page.screenshot({
    path: "test-results/p03-receipts-mobile.png",
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
