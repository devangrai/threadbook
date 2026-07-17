import AxeBuilder from "@axe-core/playwright";
import {
  expect,
  test,
  type Locator,
  type Page,
} from "@playwright/test";

test("keyboard-only reviewed receipt promotion survives restart at 390px", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(() => {
    sessionStorage.setItem(
      "wardrobe-e2e-receipt-state-v1",
      JSON.stringify({
        analyzed: true,
        state: "confirmed",
        correctedOrder: null,
        receiptRevision: 13,
        reviewSequence: 1,
      }),
    );
    sessionStorage.setItem(
      "wardrobe-e2e-gmail-state-v1",
      JSON.stringify({
        settings: {
          provider_profile: "google",
          oauth_client_id: "synthetic-client",
          discovery_scope: {
            kind: "gmail_search_query",
            query: "synthetic-apparel-orders",
          },
          limits: {
            max_pages: 1,
            max_messages: 2,
            max_raw_bytes_per_message: 4096,
            max_total_raw_bytes: 8192,
          },
        },
        status: "connected",
        imported: true,
      }),
    );
  });
  await page.goto("/");

  const receiptsTab = page.getByRole("button", { name: "Receipts" });
  await focusWithTab(page, receiptsTab);
  await page.keyboard.press("Enter");

  const confirmedFilter = page.getByRole("button", {
    name: "Confirmed",
    exact: true,
  });
  await focusWithTab(page, confirmedFilter);
  await page.keyboard.press("Space");
  await expect(
    page.getByRole("heading", { name: "Purchase units" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Item 1 of 2" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Item 2 of 2" }),
  ).toBeVisible();
  await expectNoHorizontalOverflow(page);

  const firstAdd = page
    .getByRole("button", { name: "Add to wardrobe" })
    .first();
  await focusWithTab(page, firstAdd);
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("dialog", { name: "Create wardrobe item" }),
  ).toBeVisible();
  await expectNoHorizontalOverflow(page);

  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(firstAdd).toBeFocused();

  await page.keyboard.press("Enter");
  const outerwear = page.getByRole("button", { name: "Outerwear" });
  await focusWithTab(page, outerwear);
  await page.keyboard.press("Space");
  await expect(outerwear).toHaveAttribute("aria-pressed", "true");
  await page.keyboard.press("Shift+Tab");
  await page.keyboard.press("Tab");
  await expect(outerwear).toBeFocused();

  const review = page.getByRole("button", { name: "Review one item" });
  await focusWithTab(page, review);
  await page.keyboard.press("Enter");
  const create = page.getByRole("button", {
    name: "Create one wardrobe item",
  });
  await expect(create).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(page.getByRole("button", { name: "Back" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(create).toBeFocused();
  await expectNoHorizontalOverflow(page);
  await page.keyboard.press("Enter");

  const successLink = page.getByRole("link", {
    name: "Open Cotton Shirt in Wardrobe",
  });
  await expect(successLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("heading", { name: "Wardrobe", level: 2 }),
  ).toBeVisible();
  await expect(page.getByText("Cotton Shirt", { exact: true })).toBeVisible();

  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Wardrobe", level: 2 }),
  ).toBeVisible();
  await expect(page.getByText("Cotton Shirt", { exact: true })).toHaveCount(1);
  await expect(replayLastPromotion(page)).resolves.toMatchObject({
    replay_status: "replayed",
    item: {
      attributes: {
        display_name: "Cotton Shirt",
        category: "outerwear",
      },
    },
  });
  await expect(page.getByText("Cotton Shirt", { exact: true })).toHaveCount(1);

  await focusWithTab(page, page.getByRole("button", { name: "Receipts" }));
  await page.keyboard.press("Enter");
  await focusWithTab(
    page,
    page.getByRole("button", { name: "Confirmed", exact: true }),
  );
  await page.keyboard.press("Space");
  await expect(
    page.getByRole("button", { name: "Added to wardrobe" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Add to wardrobe" }),
  ).toHaveCount(1);
  await expectNoHorizontalOverflow(page);
  await expectAccessible(page);

  const calls = await transportCalls(page);
  const promotions = calls.filter(
    (call) => call.command === "promote_receipt_purchase_unit_v1",
  );
  expect(promotions).toHaveLength(2);
  expect(promotions[1]?.request).toEqual(promotions[0]?.request);
  expect(promotions[0]?.request).toMatchObject({
    confirmation: "create_one_wardrobe_item",
    category_authority: "user_selected",
    expected_purchase_unit_revision: 13,
    attributes: {
      display_name: "Cotton Shirt",
      category: "outerwear",
    },
  });
  expect(
    calls.filter((call) =>
      [
        "preview_receipt_intelligence_v1",
        "request_receipt_intelligence_v1",
      ].includes(call.command),
    ),
  ).toEqual([]);
});

async function focusWithTab(
  page: Page,
  target: Locator,
  limit = 120,
) {
  await expect(target).toBeVisible();
  for (let index = 0; index < limit; index += 1) {
    if (await target.evaluate((element) => element === document.activeElement)) {
      return;
    }
    await page.keyboard.press("Tab");
  }
  throw new Error("Target was not reached with Tab");
}

async function expectNoHorizontalOverflow(page: Page) {
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
}

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

async function replayLastPromotion(page: Page) {
  return page.evaluate(async () => {
    const target = window as typeof window & {
      __WARDROBE_E2E__?: {
        calls: Array<{ command: string; request: Record<string, unknown> }>;
        invoke: <T>(
          command: string,
          args?: Record<string, unknown>,
        ) => Promise<T>;
      };
    };
    const transport = target.__WARDROBE_E2E__;
    const promotion = transport?.calls.findLast(
      (call) => call.command === "promote_receipt_purchase_unit_v1",
    );
    if (!transport || !promotion) {
      throw new Error("Promotion command was not available for replay");
    }
    return transport.invoke<Record<string, unknown>>(
      "promote_receipt_purchase_unit_v1",
      { request: promotion.request },
    );
  });
}
