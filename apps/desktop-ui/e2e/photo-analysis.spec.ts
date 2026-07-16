import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const photoCommands = [
  "list_imported_photo_roots_v1",
  "create_photo_scope_v1",
  "detect_photo_scope_people_v1",
  "list_photo_owner_reviews_v1",
  "read_photo_owner_preview_v1",
  "decide_photo_owner_v1",
  "correct_photo_owner_v1",
  "correct_photo_person_detection_v1",
  "retry_photo_person_detection_v1",
  "analyze_photo_scope_v1",
  "list_photo_observations_v1",
  "read_photo_artifact_v1",
  "prompt_photo_observation_v1",
  "review_photo_observation_v1",
] as const;

test("person authority, fallback garment review, reload, and mobile workflow", async ({
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
  const ownerReview = page.locator("section.owner-review-workspace");
  const garmentReview = page.locator("section.photo-results");
  const garmentReviewHeading = garmentReview.getByRole("heading", {
    name: "Review",
    exact: true,
    level: 3,
  });
  await expect(
    page.getByRole("heading", { name: "Photos", level: 2 }),
  ).toBeVisible();

  const root = page.getByRole("radio", { name: /Folder 91000000/i });
  await expect(root).toBeVisible();
  expect(await invokedPhotoCommands(page)).toEqual([
    "list_imported_photo_roots_v1",
  ]);
  await root.check();
  expect(await invokedPhotoCommands(page)).toEqual([
    "list_imported_photo_roots_v1",
  ]);

  await page.getByRole("button", { name: "Freeze scope" }).click();
  await expect(page.getByText("Photo scope frozen.")).toBeVisible();
  await expect(page.getByText("3", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("1234567890...90abcdef")).toBeVisible();
  expect(await invokedPhotoCommands(page)).not.toContain(
    "analyze_photo_scope_v1",
  );

  await page.getByRole("button", { name: "Detect people" }).click();
  await expect(
    ownerReview.getByRole("heading", {
      name: "Confirm owner",
      exact: true,
    }),
  ).toBeFocused();
  expect(await invokedPhotoCommands(page)).not.toContain(
    "analyze_photo_scope_v1",
  );
  await expect(page.locator('.owner-preview img[src^="blob:"]')).toBeVisible();

  await ownerReview.getByRole("button", { name: "Person missed" }).click();
  const ownerX = ownerReview.getByRole("spinbutton", { name: "X" });
  await ownerX.focus();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.type("160");
  const ownerWidth = ownerReview.getByRole("spinbutton", { name: "Width" });
  await ownerWidth.focus();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.type("100");
  const ownerHeight = ownerReview.getByRole("spinbutton", { name: "Height" });
  await ownerHeight.focus();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.type("190");
  await ownerReview.getByRole("button", { name: "Add person" }).click();
  await ownerReview.getByRole("radio", { name: /Person 2/ }).check();
  await ownerReview.getByRole("button", { name: "This is me" }).click();

  await expect(
    page.getByText(
      /Segmentation unavailable: reviewed model pack absent/i,
    ),
  ).toBeVisible();
  await expect(
    page.locator('.photo-observation .photo-preview img[src^="blob:"]'),
  ).toBeVisible();
  await expect(garmentReviewHeading).toBeFocused();

  await ownerReview.getByRole("button", { name: "Change owner" }).click();
  await ownerReview
    .getByRole("button", { name: "I'm not in this photo" })
    .click();
  await expect(ownerReview.getByText("Owner absent", { exact: true })).toBeVisible();

  await ownerReview.getByRole("button", { name: "Needs retry" }).click();
  await ownerReview.getByRole("button", { name: "Retry detection" }).click();
  await expect(page.getByText("Person detection retried.")).toBeVisible();

  await page.getByRole("button", { name: "Adjust rectangle" }).click();
  const x = page.getByRole("spinbutton", { name: "X" });
  await x.focus();
  await page.keyboard.press("ControlOrMeta+A");
  await page.keyboard.type("48");
  await page.getByRole("button", { name: "Preview rectangle" }).click();
  await expect(
    page.getByText(
      /Segmentation unavailable: reviewed model pack absent/i,
    ).first(),
  ).toBeVisible();
  const replace = page.getByRole("button", { name: "Replace crop" });
  await expect(replace).toBeFocused();
  await replace.click();
  await expect(page.getByText("Photo crop replaced.")).toBeVisible();
  await expect(garmentReviewHeading).toBeFocused();

  await page.reload();
  await page.getByRole("button", { name: "Photos" }).click();
  await expect(page.getByText("1234567890...90abcdef")).toBeVisible();
  await page.getByRole("button", { name: "Replaced" }).click();
  await expect(page.getByText("Replaced", { exact: true }).last()).toBeVisible();
  await expect(
    page.getByText(
      /Segmentation unavailable: reviewed model pack absent/i,
    ),
  ).toBeVisible();

  const calls = await transportCalls(page);
  const p04Calls = calls.filter((call) =>
    photoCommands.includes(call.command as (typeof photoCommands)[number]),
  );
  expect([...new Set(p04Calls.map((call) => call.command))].sort()).toEqual(
    [...photoCommands].sort(),
  );
  expect(
    p04Calls.find((call) => call.command === "create_photo_scope_v1")?.request,
  ).toEqual(
    expect.objectContaining({
      import_root_id: "91000000-0000-4000-8000-000000000001",
      expected_manifest_generation: 12,
    }),
  );
  expect(
    p04Calls.find(
      (call) => call.command === "detect_photo_scope_people_v1",
    )?.request,
  ).toEqual(
    expect.objectContaining({
      scope_id: "91000000-0000-4000-8000-000000000003",
    }),
  );
  expect(
    p04Calls.find(
      (call) => call.command === "correct_photo_person_detection_v1",
    )?.request,
  ).toEqual(
    expect.objectContaining({
      manual_rectangle: { x: 160, y: 0, width: 100, height: 190 },
      expected_detection_revision: expect.any(Number),
      expected_owner_head_revision: expect.any(Number),
      expected_photo_revision: expect.any(Number),
    }),
  );
  expect(
    p04Calls.find(
      (call) => call.command === "decide_photo_owner_v1",
    )?.request,
  ).toEqual(
    expect.objectContaining({
      action: "select_person",
      selected_person_instance_id:
        "91000000-0000-4000-8000-000000000110",
    }),
  );
  expect(
    p04Calls.find((call) => call.command === "analyze_photo_scope_v1")?.request,
  ).toEqual(
    expect.objectContaining({
      scope_id: "91000000-0000-4000-8000-000000000003",
    }),
  );
  expect(
    p04Calls.find(
      (call) => call.command === "prompt_photo_observation_v1",
    )?.request,
  ).toEqual(
    expect.objectContaining({
      observation_id: "91000000-0000-4000-8000-000000000005",
      box_rectangle: { x: 48, y: 30, width: 200, height: 160 },
      positive_points: [],
      negative_points: [],
    }),
  );
  expect(
    p04Calls.find(
      (call) => call.command === "review_photo_observation_v1",
    )?.request,
  ).toEqual(
    expect.objectContaining({
      action: "replace_crop",
      replacement_rectangle: { x: 48, y: 30, width: 200, height: 160 },
      expected_photo_revision: expect.any(Number),
    }),
  );
  expect(JSON.stringify(p04Calls)).not.toMatch(
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

async function invokedPhotoCommands(page: Page) {
  return (await transportCalls(page))
    .map((call) => call.command)
    .filter((command) =>
      photoCommands.includes(command as (typeof photoCommands)[number]),
    );
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
