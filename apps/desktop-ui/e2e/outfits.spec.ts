import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("approved outfit ideas save explicitly and manual collages remain offline", async ({
  page,
}) => {
  await page.route(/^https?:\/\/(?!127\.0\.0\.1:4173)/, (route) =>
    route.abort(),
  );
  await page.goto("/");
  await page.getByRole("button", { name: "Outfits" }).click();
  await expect(page.getByRole("heading", { name: "Outfits" })).toBeVisible();
  expect(
    await page.evaluate(() => {
      const target = window as typeof window & {
        __WARDROBE_E2E__?: { marker: string };
      };
      return target.__WARDROBE_E2E__?.marker;
    }),
  ).toBe("__WARDROBE_E2E_TRANSPORT__");

  await page
    .getByRole("textbox", { name: "What do you need?" })
    .fill("A good dinner outfit");
  await page.getByRole("combobox", { name: "Occasion" }).selectOption("date");
  await page.getByRole("button", { name: "Preview disclosure" }).click();
  const disclosure = page.getByRole("dialog", {
    name: "Review OpenAI disclosure",
  });
  await expect(
    disclosure.getByText(/No photos, email content, file paths, notes, sizes/),
  ).toBeVisible();
  await disclosure.getByRole("button", { name: "Send to OpenAI" }).click();
  await expect(
    page.getByRole("heading", { name: "Grounded dinner" }),
  ).toBeVisible();
  await page
    .getByRole("listitem")
    .filter({ hasText: "Grounded dinner" })
    .getByRole("button", { name: "Save outfit" })
    .click();
  await expect(page.getByText(/Saved "Grounded dinner"/)).toBeVisible();

  await page.getByRole("textbox", { name: "Name" }).fill("Dinner date");
  const choices = page
    .getByRole("group", { name: "Wardrobe items" })
    .getByRole("checkbox");
  await choices.nth(0).check();
  await choices.nth(1).check();
  const secondName = await choices.nth(1).locator("xpath=..").locator("strong").innerText();
  await page.getByRole("button", { name: `Move ${secondName} up` }).click();
  await page
    .getByRole("region", { name: "Build outfit" })
    .getByRole("button", { name: "Save outfit" })
    .click();
  await expect(page.getByText("Outfit saved locally.")).toBeVisible();

  await page
    .getByRole("listitem")
    .filter({ hasText: "Dinner date" })
    .getByRole("button", { name: "View collage" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Dinner date" }),
  ).toBeVisible();
  await expect(page.getByText("No image")).toHaveCount(2);

  await expect(
    page.getByRole("heading", { name: "Try-on visualization" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Preview disclosure" }).click();
  const tryOnDisclosure = page.getByRole("dialog", {
    name: "Review try-on disclosure",
  });
  await expect(tryOnDisclosure.getByText("OpenAI", { exact: true })).toBeVisible();
  await expect(tryOnDisclosure.getByText("gpt-image-2")).toBeVisible();
  await expect(
    tryOnDisclosure.getByRole("list", { name: "Images sent to OpenAI" }),
  ).toContainText("reference-00.png");
  await expect(
    tryOnDisclosure.getByRole("list", { name: "Images sent to OpenAI" }),
  ).toContainText("reference-02.png");
  await expect(tryOnDisclosure.getByText(/up to 30 days/)).toBeVisible();
  await tryOnDisclosure
    .getByRole("button", { name: "Generate visualization" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Visualization pending" }),
  ).toBeVisible();

  await page.reload();
  await page.getByRole("button", { name: "Outfits" }).click();
  await page
    .getByRole("listitem")
    .filter({ hasText: "Dinner date" })
    .getByRole("button", { name: "View collage" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Generated visualization" }),
  ).toBeVisible();
  await expect(
    page.getByText(
      "AI visualization. Not an accurate representation of fit or garment construction.",
      { exact: true },
    ),
  ).toHaveCount(2);
  await expect(page.getByRole("heading", { name: "Real source garments" })).toBeVisible();
  const generatedVisualization = page.getByRole("region", {
    name: "Generated visualization",
  });
  await expect(
    generatedVisualization.getByText("White Oxford Shirt", { exact: true }),
  ).toBeVisible();
  await expect(
    generatedVisualization.getByText("Navy Chinos", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("No image")).toHaveCount(2);
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter((violation) =>
      ["serious", "critical"].includes(violation.impact ?? ""),
    ),
  ).toEqual([]);
  await page.screenshot({
    path: "test-results/p08-try-on-desktop.png",
    fullPage: true,
  });

  await page.setViewportSize({ width: 390, height: 844 });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  const mobileNavigation = await page.evaluate(() => {
    const navigation = document.querySelector<HTMLElement>(".tabs");
    if (!navigation) return null;
    const bounds = navigation.getBoundingClientRect();
    return {
      flexWrap: getComputedStyle(navigation).flexWrap,
      right: bounds.right,
      bottom: bounds.bottom,
      tabs: Array.from(navigation.querySelectorAll("button")).map((button) => {
        const tab = button.getBoundingClientRect();
        return { right: tab.right, bottom: tab.bottom };
      }),
    };
  });
  expect(mobileNavigation?.flexWrap).toBe("wrap");
  expect(
    mobileNavigation?.tabs.every(
      (tab) =>
        tab.right <= (mobileNavigation?.right ?? 0) + 1 &&
        tab.bottom <= (mobileNavigation?.bottom ?? 0) + 1,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/p08-try-on-mobile.png",
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
  const create = calls.find(
    (candidate) => candidate.command === "create_manual_outfit_v1",
  );
  expect(create?.request.expected_catalog_revision).toEqual(expect.any(Number));
  expect(create?.request.expected_outfit_revision).toEqual(expect.any(Number));
  expect(
    calls.some((candidate) => candidate.command === "get_outfit_collage_v1"),
  ).toBe(true);
  expect(
    calls.some(
      (candidate) =>
        candidate.command === "preview_outfit_recommendation_v1",
    ),
  ).toBe(true);
  expect(
    calls.some(
      (candidate) =>
        candidate.command === "request_outfit_recommendation_v1",
    ),
  ).toBe(true);
  expect(
    calls.filter((candidate) => candidate.command === "submit_try_on_v1"),
  ).toHaveLength(1);
  expect(
    calls.some((candidate) => candidate.command === "preview_try_on_v1"),
  ).toBe(true);
  expect(
    calls.some((candidate) => candidate.command === "get_outfit_try_on_v1"),
  ).toBe(true);
});
