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

test("manual catalog, inbox, decisions, and read-only deletion workflow", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Wardrobe", level: 2 }),
  ).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: "Load more items" }).click();
  await expect(page.getByText("Black Derby Shoes")).toBeVisible();

  const firstItem = page.getByRole("listitem").filter({
    hasText: "White Oxford Shirt",
  });
  await firstItem.getByRole("button", { name: "Edit" }).click();
  await page.getByRole("textbox", { name: "Name" }).fill("Ivory Oxford Shirt");
  await page.getByRole("button", { name: "Save item" }).click();
  await expect(page.getByText("Item updated.")).toBeVisible();

  await page.getByRole("checkbox", { name: "Select Ivory Oxford Shirt" }).check();
  await page.getByRole("checkbox", { name: "Select Navy Chinos" }).check();
  await page.getByRole("button", { name: "Merge selected" }).click();
  await page.getByRole("textbox", { name: "Name" }).fill("Date Night Separates");
  await page.getByRole("button", { name: "Merge items" }).click();
  await expect(page.getByText(/Items merged/)).toBeVisible();
  await page.getByRole("button", { name: "Load more items" }).click();

  const merged = page.getByRole("listitem").filter({
    hasText: "Date Night Separates",
  });
  await merged.getByRole("button", { name: "Split" }).click();
  await expect(
    page.getByRole("dialog", { name: "Split Date Night Separates" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Split item" }).click();
  await expect(page.getByText(/Item split/)).toBeVisible();
  await page.getByRole("button", { name: "Load more items" }).click();
  const splitRow = page.getByRole("listitem").filter({
    hasText: "Date Night Separates 2",
  });
  await splitRow.getByRole("button", { name: "Undo" }).click();
  await expect(page.getByText("Decision undone.")).toBeVisible();

  await page.getByRole("button", { name: "Inbox" }).click();
  await expect(page.getByRole("heading", { name: "Inbox" })).toBeVisible();
  await expectAccessible(page);
  await page.getByRole("button", { name: "Assign" }).first().click();
  await expect(page.getByText("Evidence assigned.")).toBeVisible();
  await page.getByRole("button", { name: "Defer" }).first().click();
  await expect(page.getByText("Evidence deferred.")).toBeVisible();
  await page.getByRole("button", { name: "Reject" }).nth(1).click();
  await expect(page.getByText("Evidence rejected.")).toBeVisible();
  await page.getByRole("button", { name: "Quarantine" }).click();
  await expect(
    page.getByText("Unsupported animation", { exact: true }).first(),
  ).toBeVisible();

  await page.getByRole("button", { name: "Wardrobe" }).click();
  await page.getByRole("button", { name: "Load more items" }).click();
  await page
    .getByRole("listitem")
    .filter({ hasText: "Date Night Separates" })
    .getByRole("button", { name: "Preview deletion" })
    .click();
  const preview = page.getByRole("dialog", {
    name: /Deletion preview: Date Night Separates/,
  });
  await expect(preview).toBeVisible();
  await expect(preview.getByText("Read-only preview")).toBeVisible();
  await expect(preview.getByRole("button", { name: /delete/i })).toHaveCount(0);
  await preview
    .getByRole("button", { name: "Load more Evidence records" })
    .click();
  await expect(preview.getByText("Manual note")).toBeVisible();
  await expectAccessible(page);
  await preview.getByRole("button", { name: "Done" }).click();

  const addItem = page.getByRole("button", { name: "Add item" });
  await addItem.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog", { name: "Add wardrobe item" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(addItem).toBeFocused();

  await page.screenshot({
    path: "test-results/p02-desktop.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    page.getByRole("heading", { name: "Wardrobe", level: 2 }),
  ).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await expectAccessible(page);
  await page.screenshot({
    path: "test-results/p02-mobile.png",
    fullPage: true,
  });

  const calls = await page.evaluate(() => {
    const target = window as typeof window & {
      __WARDROBE_E2E__?: {
        calls: Array<{ command: string; request: Record<string, unknown> }>;
      };
    };
    return target.__WARDROBE_E2E__?.calls ?? [];
  });
  for (const command of [
    "save_item_v1",
    "merge_items_v1",
    "split_item_v1",
    "undo_decision_v1",
    "decide_evidence_v1",
  ]) {
    const call = calls.find((candidate) => candidate.command === command);
    expect(call?.request.expected_catalog_revision).toEqual(expect.any(Number));
  }
});
