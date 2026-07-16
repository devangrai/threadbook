import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const reconciliationCommands = [
  "list_reconciliation_cases_v2",
  "open_reconciliation_case_v2",
  "decide_reconciliation_case_v2",
] as const;

test("explicit local reconciliation review and all five decisions", async ({
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
  await page.getByRole("button", { name: "Photos" }).click();
  await page.getByRole("radio", { name: /Folder 91000000/i }).check();
  await page.getByRole("button", { name: "Freeze scope" }).click();
  await page.getByRole("button", { name: "Detect people" }).click();
  await page.getByRole("radio", { name: "Person 1" }).check();
  await page.getByRole("button", { name: "This is me" }).click();
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await page.getByRole("button", { name: "Confirmed" }).click();

  const findMatches = page.getByRole("button", {
    name: "Find local matches",
  });
  await expect(findMatches).toBeVisible();
  expect(await invokedReconciliationCommands(page)).toEqual([]);

  await findMatches.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Local match candidates ready.")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Local matches" }),
  ).toBeFocused();
  expect(await invokedReconciliationCommands(page)).toEqual([
    "list_reconciliation_cases_v2",
    "open_reconciliation_case_v2",
  ]);

  const leading = page
    .locator(".reconciliation-candidate")
    .filter({ hasText: "White Oxford shirt" });
  await expect(leading.getByText("Leading candidate")).toBeVisible();
  await expect(leading.getByText("Catalog date 2026-05-12")).toBeVisible();
  await expect(
    leading.getByText("Difference hash distance: 3"),
  ).toBeVisible();
  await expect(leading.getByText("Mean color distance: 212")).toBeVisible();
  await expect(
    leading.getByText(/Catalog image evidence revision catalog-r8/i),
  ).toBeVisible();

  const receipt = page
    .locator(".reconciliation-candidate")
    .filter({ hasText: "Merino overshirt" });
  await expect(receipt.getByText("Alternative")).toBeVisible();
  await expect(receipt.getByText("Purchase date 2026-04-03")).toBeVisible();
  await expect(receipt.getByText("Receipt line")).toBeVisible();

  const wardrobeAlternative = page
    .locator(".reconciliation-candidate")
    .filter({ hasText: "Navy field shirt" });
  await expect(wardrobeAlternative.getByText("Alternative")).toBeVisible();
  await expect(wardrobeAlternative.getByText("Date unknown")).toBeVisible();
  await expect(page.getByText("Explicit no match")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Supporting" }).first(),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Contradictory" }).first(),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Neutral" }).first(),
  ).toBeVisible();

  const sameItem = page.getByRole("button", {
    name: "Same wardrobe item",
  });
  await sameItem.focus();
  await page.keyboard.press("Enter");
  await expectDecision(page, "Current decision: Same wardrobe item");

  const receiptChoice = page.getByRole("radio", {
    name: /Merino overshirt/i,
  });
  await receiptChoice.focus();
  await page.keyboard.press("Space");
  await expect(sameItem).toBeDisabled();
  const sameVariant = page.getByRole("button", {
    name: "Same product variant",
  });
  await sameVariant.focus();
  await page.keyboard.press("Enter");
  await expectDecision(page, "Current decision: Same product variant");

  await page.getByRole("button", { name: "Different" }).click();
  await expectDecision(page, "Current decision: Different");

  const noMatchChoice = page.getByRole("radio", { name: /^No match/i });
  await noMatchChoice.focus();
  await page.keyboard.press("Space");
  await expect(sameVariant).toBeDisabled();
  await page.getByRole("button", { name: "No match" }).click();
  await expectDecision(page, "Current decision: No match.");

  await page.getByRole("button", { name: "Unresolved" }).click();
  await expectDecision(page, "Current decision: Unresolved.");

  const calls = await reconciliationCalls(page);
  expect(calls).toHaveLength(7);
  expect(calls.map((call) => call.command)).toEqual([
    "list_reconciliation_cases_v2",
    "open_reconciliation_case_v2",
    "decide_reconciliation_case_v2",
    "decide_reconciliation_case_v2",
    "decide_reconciliation_case_v2",
    "decide_reconciliation_case_v2",
    "decide_reconciliation_case_v2",
  ]);
  expect(calls.slice(2).map((call) => call.request.outcome)).toEqual([
    "same_item",
    "same_variant",
    "different",
    "no_match",
    "unresolved",
  ]);
  expect(calls.at(-1)?.request.selected_candidate_id).toBeNull();
  expect(JSON.stringify(calls)).not.toMatch(
    /(?:\/Users\/|file:\/\/|https?:\/\/(?!127\.0\.0\.1))/,
  );

  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await expect(page.locator('a[href^="http"], img[src^="http"]')).toHaveCount(0);
  expect(remoteRequests).toEqual([]);

  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
});

async function expectDecision(page: Page, value: string) {
  const summary = page.locator(".reconciliation-decision-summary");
  await expect(summary).toContainText(value);
  await expect(summary).toBeFocused();
}

async function invokedReconciliationCommands(page: Page) {
  return (await reconciliationCalls(page)).map((call) => call.command);
}

async function reconciliationCalls(page: Page) {
  const calls = await page.evaluate(() => {
    const target = window as typeof window & {
      __WARDROBE_E2E__?: {
        calls: Array<{
          command: string;
          request: Record<string, unknown>;
        }>;
      };
    };
    return target.__WARDROBE_E2E__?.calls ?? [];
  });
  return calls.filter((call) =>
    reconciliationCommands.includes(
      call.command as (typeof reconciliationCommands)[number],
    ),
  );
}
