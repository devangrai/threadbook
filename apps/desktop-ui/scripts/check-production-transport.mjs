import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

const marker = "__WARDROBE_E2E_TRANSPORT__";
const assets = join(process.cwd(), "dist", "assets");
const files = await readdir(assets);

for (const file of files) {
  if (!file.endsWith(".js")) continue;
  const contents = await readFile(join(assets, file), "utf8");
  if (contents.includes(marker) || contents.includes("WARDROBE_E2E")) {
    throw new Error(`Test transport leaked into production asset ${file}`);
  }
}

console.log("Production bundle excludes the e2e transport.");
