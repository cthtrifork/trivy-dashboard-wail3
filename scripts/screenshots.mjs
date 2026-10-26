// Drives the running app (started by screenshots.sh in fake-podman mode) and
// saves one screenshot per panel view. Usage: node screenshots.mjs <url> <outDir>
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
import { mkdirSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const [url, outDir] = process.argv.slice(2);
if (!url || !outDir) {
  console.error("usage: node screenshots.mjs <url> <outDir>");
  process.exit(2);
}

function loadPlaywright() {
  const here = createRequire(import.meta.url);
  try {
    return here("playwright");
  } catch {
    const root = execSync("npm root -g", { encoding: "utf8" }).trim();
    return createRequire(path.join(root, "noop.js"))("playwright");
  }
}
const { chromium } = loadPlaywright();

mkdirSync(outDir, { recursive: true });
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1400, height: 900 } });
// system-ui resolves to whatever sans font the machine has, so the PNGs differed between a laptop
// and CI on every run. Pin it to Inter (CI installs fonts-inter); monospace is DejaVu Sans Mono.
await page.addInitScript(() => {
  document.addEventListener("DOMContentLoaded", () => {
    const style = document.createElement("style");
    style.textContent = "body{font-family:Inter,sans-serif !important}";
    document.head.append(style);
  });
});
const problems = [];
page.on("pageerror", (e) => problems.push("page error: " + e.message));

const shot = async (name) => {
  await page.waitForTimeout(700); // transitions (dialog open, tab switch) must be finished: pixels are committed
  await page.evaluate(() => Promise.all(document.getAnimations()
    .filter((a) => Number.isFinite(a.effect?.getComputedTiming().endTime))
    .map((a) => a.finished.catch(() => {}))));
  await page.screenshot({ path: path.join(outDir, name + ".png"), animations: "disabled", caret: "hide" });
  console.log("  " + name + ".png");
};
const tab = (name) => page.click(`[data-tab=${name}]`);
const text = (sel) => page.textContent(sel);
const expect = (cond, what) => { if (!cond) problems.push("unexpected: " + what); };

await page.goto(url);
await page.waitForSelector("#mode-banner:not([hidden])", { timeout: 15000 });
expect((await text("#mode-banner")).includes("Demo mode"), "demo banner should be visible");

// ---- scan the recorded base image ----
await page.click("#scan-btn");
await page.waitForFunction(() => !document.querySelector("#scan-btn").disabled && document.querySelector("#vuln-count").textContent !== "0", null, { timeout: 30000 });
expect((await text("#vuln-count")) === "29", "3.7.13 should have 29 findings, got " + (await text("#vuln-count")));
const scrollTop = () => page.evaluate(() => {
  document.getElementById("prio-list").scrollTop = 0;
});

// ---- Priorities ----
await scrollTop();
await shot("01-priorities");

const first = page.locator(".prow").first();
await first.locator(".prow-main").click();
await first.locator(".vexbtn").click();
const drawer = page.locator("dialog.drawer");
await drawer.locator('.seg label:has-text("Not affected")').click();
await drawer.locator('.radio:has-text("never run")').click();
await drawer.locator("#vex-impact").fill("The vulnerable HTTP/2 path is not reachable: the entrypoint only serves HTTP/1.1.");
await shot("02-priorities-vex-editor");
await drawer.locator('.drawer-actions button:has-text("Save")').click();
await page.waitForTimeout(400);

await page.click("#vex-export-btn");
await page.fill("#vex-author", "Security Team");
await page.fill("#vex-role", "Platform Security");
await page.waitForFunction(() => document.querySelector("#vex-preview").value.includes("@context"));
// The document and its statements are stamped with the current time, and the document id is a hash
// over them; pin all of it so reruns produce identical pixels.
await page.evaluate(() => {
  const ta = document.querySelector("#vex-preview");
  ta.value = ta.value
    .replace(/("timestamp":\s*")[^"]+"/g, '$1' + '2026-01-01T00:00:00Z"')
    .replace(/(openvex\.dev\/docs\/public\/vex-)[0-9a-f]+/g, "$1" + "0".repeat(64));
});
await shot("03-priorities-export-openvex");
await page.click("#vex-close");

// ---- Vulnerabilities ----
await tab("vulns");
await shot("04-vulnerabilities");
// Expand a finding that has no VEX assessment, so the trigger reads "Assess this finding".
await page.click("#vuln-table tbody:not(.pad) tr.row >> nth=1");
await shot("05-vulnerability-details");

// ---- Dependencies ----
// A runaway layout shows up as a blank canvas, so fail loudly instead of saving it.
const graphSane = async (what) => {
  const g = await page.evaluate(() => {
    const gr = window.__depGraph, n = gr.nodes;
    const xs = n.map((a) => a.x), ys = n.map((a) => a.y);
    return { count: n.length, finite: n.every((a) => Number.isFinite(a.x) && Number.isFinite(a.y)),
      w: Math.max(...xs) - Math.min(...xs), h: Math.max(...ys) - Math.min(...ys), k: gr.k };
  });
  expect(g.count > 0 && g.finite, `${what}: graph has ${g.count} nodes, finite=${g.finite}`);
  expect(g.w < 8000 && g.h < 8000, `${what}: layout exploded (${Math.round(g.w)}x${Math.round(g.h)}px)`);
  console.log(`    ${what}: ${g.count} nodes, ${Math.round(g.w)}x${Math.round(g.h)}px, zoom ${g.k.toFixed(2)}`);
};
// Screenshots are committed, so they must be reproducible: wait for the force layout to come to
// rest (not a fixed time, which captures a different frame on a slower machine), and park the
// mouse so no hover tooltip is drawn.
const settled = async () => {
  await page.mouse.move(0, 0);
  await page.waitForTimeout(300); // let a just-triggered rebuild start before asking whether it is done
  // At rest on three polls in a row, so one quiet moment between a rebuild and its first frame
  // is not mistaken for the end of the layout.
  let calm = 0;
  for (let i = 0; i < 600 && calm < 3; i++) {
    const rest = await page.evaluate(() => window.__depGraph.alpha <= 0.015 && !window.__depGraph.raf);
    calm = rest ? calm + 1 : 0;
    await page.waitForTimeout(200);
  }
  expect(calm >= 3, "dependency graph layout did not settle");
};
await tab("deps");
await settled();
await graphSane("overview");
await shot("06-dependencies-graph");

const pick = async (label) => {
  const pos = await page.evaluate((l) => {
    const g = window.__depGraph;
    const n = g.nodes.find((x) => x.label === l);
    return n ? g.screenPos(n.id) : null;
  }, label);
  expect(!!pos, "graph node " + label + " should exist");
  if (pos) await page.mouse.click(pos.x, pos.y);
  await settled();
};
await pick("golang.org/x/net");
await shot("07-dependencies-node-selected");
await page.selectOption("#dep-focus", "2");
await settled();
await graphSane("focus ±2");
await shot("08-dependencies-focus");
await page.selectOption("#dep-focus", "0");
await settled(); // each change rebuilds from the previous layout, so let every step finish
await page.uncheck("#dep-vuln-only");
await settled();
await graphSane("all components");
await shot("09-dependencies-all-components");

// ---- SBOM ----
await tab("sbom");
await shot("10-sbom");

// ---- Compare ----
await tab("compare");
await page.click("#cmp-go");
await page.waitForSelector(".verdict", { timeout: 30000 });
expect((await text(".verdict")).includes("28 fewer"), "compare verdict: " + (await text(".verdict")));
await shot("11-compare-vulnerabilities");
await page.click('.seg button:has-text("Packages")');
await page.locator("label:has-text('upgraded') input").check();
await shot("12-compare-packages");

// ---- Log ----
await tab("log");
await shot("13-log");

await browser.close();

const files = readdirSync(outDir).filter((f) => f.endsWith(".png"));
console.log(`${files.length} screenshots in ${outDir} (${files.reduce((n, f) => n + statSync(path.join(outDir, f)).size, 0) >> 10} KiB)`);
if (problems.length) {
  console.error("\nProblems:\n - " + problems.join("\n - "));
  process.exit(1);
}
