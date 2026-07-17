import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

test("OpenAI receipt availability is truthful and preserves saved status", async ({
  page,
}) => {
  await page.addInitScript(() => {
    sessionStorage.setItem(
      "wardrobe-e2e-receipt-intelligence-state-v1",
      JSON.stringify({
        attempt_id: "79000000-0000-4000-8000-000000000001",
        source_id: "71000000-0000-4000-8000-000000000001",
        state: "completed",
        classification: "apparel_order",
        review_available: true,
        failure_code: null,
      }),
    );
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Receipts" }).click();
  await expect(
    page.getByRole("button", {
      name: "Offline analyze receipt from unknown merchant",
    }),
  ).toBeEnabled();
  const analyze = page.getByRole("button", { name: "Analyze with OpenAI" }).first();
  await expect(analyze).toBeDisabled();
  await expect(
    page.getByText(/OpenAI analysis is unavailable in local-only mode/).first(),
  ).toBeVisible();
  await expect(
    page.getByText(
      /Offline receipt analysis and existing wardrobe access remain available/,
    ).first(),
  ).toBeVisible();
  await expect(page.getByText("OpenAI analysis complete")).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: "Settings" }).click();
  await page.getByRole("switch", { name: "Local only" }).click();
  await page.getByRole("button", { name: "Enable personal live" }).click();
  await expect(page.getByRole("switch", { name: "Personal live" }))
    .toHaveAttribute("aria-checked", "false");

  await page.getByRole("button", { name: "Receipts" }).click();
  await expect(
    page.getByRole("button", { name: "Analyze with OpenAI" }).first(),
  ).toBeDisabled();
  await expect(
    page.getByText(/OpenAI analysis is unavailable in this release/).first(),
  ).toBeVisible();
  await expect(page.getByText("OpenAI analysis complete")).toBeVisible();
  expect(
    (await transportCalls(page)).filter((call) =>
      [
        "preview_receipt_intelligence_v1",
        "request_receipt_intelligence_v1",
      ].includes(call.command),
    ),
  ).toEqual([]);
  await expectAccessible(page);
});

test("OpenAI receipt preview, cancellation, approval, and review handoff", async ({
  page,
}) => {
  await page.addInitScript(() => {
    sessionStorage.setItem(
      "wardrobe-e2e-foundation-state-v1",
      JSON.stringify({ localOnly: false, revision: 2 }),
    );
    sessionStorage.setItem(
      "wardrobe-e2e-receipt-intelligence-release-v1",
      "enabled",
    );
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Receipts" }).click();

  const analyze = page.getByRole("button", { name: "Analyze with OpenAI" }).first();
  await expect(analyze).toBeEnabled();
  await analyze.click();
  const dialog = page.getByRole("dialog", {
    name: "Review OpenAI receipt analysis",
  });
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText("gpt-5.6-sol");
  await expect(dialog).toContainText("Linen overshirt, blue");
  await expect(dialog).toContainText(
    "store:false is not organization-level Zero Data Retention",
  );
  await page
    .getByRole("button", { name: "Cancel OpenAI receipt analysis" })
    .click();
  await expect(dialog).not.toBeVisible();
  expect(
    (await transportCalls(page)).filter(
      (call) => call.command === "request_receipt_intelligence_v1",
    ),
  ).toEqual([]);

  await analyze.click();
  await page.getByRole("button", { name: "Approve and analyze" }).click();
  await expect(page.getByText("OpenAI analysis complete")).toBeVisible();
  await expect(page.getByText(/Nothing was added to your wardrobe/)).toBeVisible();
  await page.getByRole("button", { name: "Open receipt review" }).click();
  await expect(page.getByText("Needs review").first()).toBeVisible();

  const requests = (await transportCalls(page)).filter(
    (call) => call.command === "request_receipt_intelligence_v1",
  );
  expect(requests).toHaveLength(1);
  expect(requests[0]?.request).toMatchObject({
    schema_version: 1,
    consent: { affirmative: true },
  });
  await expectAccessible(page);
});

async function expectAccessible(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
}

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
