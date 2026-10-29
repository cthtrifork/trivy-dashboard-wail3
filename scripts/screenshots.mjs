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
  // frontend/node_modules (playwright-core, from `make frontend`) first, then the script's own
  // resolution (a local `npm install --no-save playwright`), then a global install.
  const requirers = [
    createRequire(new URL("../frontend/noop.js", import.meta.url)),
    createRequire(import.meta.url),
  ];
  for (const here of requirers) {
    for (const name of ["playwright", "playwright-core"]) {
      try {
        return here(name);
      } catch {}
    }
  }
  const root = execSync("npm root -g", { encoding: "utf8" }).trim();
  return createRequire(path.join(root, "noop.js"))("playwright");
}
const { chromium } = loadPlaywright();

mkdirSync(outDir, { recursive: true });
// SCREENSHOT_BROWSER_CHANNEL=chrome drives an installed Google Chrome (preinstalled on GitHub's
// runners) instead of Playwright's own Chromium download.
const browser = await chromium.launch({ channel: process.env.SCREENSHOT_BROWSER_CHANNEL || undefined });
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
// SCREENSHOT_VIEWS=core skips the dependency graph (06-09) and =deps renders only it; the default
// renders everything. The graph is a canvas whose anti-aliasing varies between runs, so CI keeps it
// out of the main-branch render and refreshes it only on PRs that touch the graph code.
const views = process.env.SCREENSHOT_VIEWS || "all";
const depsShot = (name) => /^0[6-9]-dependencies-/.test(name);
const problems = [];
page.on("pageerror", (e) => problems.push("page error: " + e.message));

const shot = async (name) => {
  if ((views === "core" && depsShot(name)) || (views === "deps" && !depsShot(name))) return;
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
// The top finding expanded: ratings by source, where it lives in the image, what it means and the score.
const top = page.locator(".prow").first();
// An expanded row is taller than the list at the usual size, so take this one in a taller window.
await page.setViewportSize({ width: 1400, height: 1300 });
await top.locator(".prow-main").click();
await page.waitForTimeout(300);
await scrollTop();
await shot("01b-priorities-expanded-row");
await top.locator(".prow-main").click(); // collapse it again; the VEX editor below opens it itself
await page.setViewportSize({ width: 1400, height: 900 });
await scrollTop();

const first = page.locator(".prow").first();
await first.locator(".prow-main").click();
await first.locator(".vexbtn").click();
const drawer = page.locator("dialog.drawer");
await drawer.locator('.drawer-seg label:has-text("Not affected")').click();
await drawer.locator('.radio:has-text("never run")').click();
await drawer.locator("#vex-impact").fill("The vulnerable HTTP/2 path is not reachable: the entrypoint only serves HTTP/1.1.");
await shot("02-priorities-vex-editor");
await drawer.locator('.drawer-actions button:has-text("Save")').click();
await page.waitForTimeout(400);

await page.click("#export-vex-btn");
await page.fill("#vex-author", "Security Team");
// The editors are CodeMirror views; JsonBox keeps the view on the container as __cm. They are lazy
// chunks mounted when a dialog first opens, so wait for the view before touching it.
const editorReady = (sel) => page.waitForFunction((s) => document.querySelector(s)?.__cm, sel);
const editorText = async (sel) => {
  await editorReady(sel);
  return page.evaluate((s) => document.querySelector(s).__cm.state.doc.toString(), sel);
};
const setEditor = async (sel, text) => {
  await editorReady(sel);
  await page.evaluate(([s, t]) => { const v = document.querySelector(s).__cm; v.dispatch({ changes: { from: 0, to: v.state.doc.length, insert: t } }); }, [sel, text]);
};
await page.waitForFunction(() => document.querySelector("#vex-preview")?.__cm?.state.doc.toString().includes("@context"));
// The document and its statements are stamped with the current time, and the document id is a hash
// over them; pin all of it so reruns produce identical pixels.
const pin = (t) => t
  .replace(/("timestamp":\s*")[^"]+"/g, '$1' + '2026-01-01T00:00:00Z"')
  .replace(/(openvex\.dev\/docs\/public\/vex-)[0-9a-f]+/g, "$1" + "0".repeat(64));
const exported = pin(await editorText("#vex-preview"));
await setEditor("#vex-preview", exported);
await shot("03-priorities-export-openvex");
await page.click("#vex-close");

// Import the document back: the dialog reports what matched.
await page.click("#vex-menu-btn");
await page.click("#vex-menu-import");
// A broken document first: the editor flags the syntax error inline.
await setEditor("#vex-paste", exported.replace('"statements": [', '"statements" [').split("\n").slice(0, 14).join("\n"));
await page.waitForSelector("#vex-paste .cm-lint-marker-error");
await page.hover("#vex-paste .cm-lint-marker-error"); // show the message tooltip
await shot("03a-priorities-import-error");
await setEditor("#vex-paste", exported);
await page.selectOption("#vex-uncovered", "ALL");
await page.click("#vex-apply");
await page.waitForSelector("#vex-import-log");
await shot("03b-priorities-import-openvex");
await page.click("#vex-import-close");

// ---- Vulnerabilities ----
await tab("vulns");
await shot("04-vulnerabilities");
// Expand a finding that has no VEX assessment, so the trigger reads "Assess this finding".
await page.click("#vuln-table tbody:not(.pad) tr.row >> nth=1");
await shot("05-vulnerability-details");
// MEDIUM from Red Hat with a 9.1 from Bitnami: the expanded row lists every source's rating.
await page.fill("#vuln-filter", "CVE-2026-78663");
await page.click("#vuln-table tbody:not(.pad) tr.row >> nth=0");
await page.locator(".ratings").first().scrollIntoViewIfNeeded();
await shot("05b-vulnerability-ratings-by-source");
await page.fill("#vuln-filter", "");

// ---- Dependencies ----
if (views !== "core") {
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
}

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

// ---- Options ----
// One image with the four tabs side by side: each tab's popover is captured on its own, then the
// pictures are laid out on a blank page and photographed again.
if (views !== "deps") {
  await page.setViewportSize({ width: 1400, height: 1100 }); // the popup is taller than the usual window
  await page.click("#opts summary");
  await page.waitForTimeout(700);
  // Pin sample ignore rules through the editor dialog so the Sources summary shows real counts.
  const pinRules = (id, text) => setEditor(`#${id}`, text);
  await page.click("#opts-tab-sources");
  await page.click("#edit-ignore-policy");
  await pinRules("ignore-policy", '# Ignore kernel headers\npackage trivy\n\ndefault ignore := false\n\nignore if {\n  input.PkgName == "linux-libc-dev"\n}\n');
  await page.click("#ignore-tab-file");
  await pinRules("ignore-file", "vulnerabilities:\n  - id: CVE-2024-12345\n    statement: Not reachable in our setup\n");
  await page.waitForTimeout(700);
  await shot("15-ignore-rules");
  await page.click("#ignore-close");
  const panes = [];
  for (const t of ["findings", "sources", "scanner", "updates"]) {
    await page.click(`#opts-tab-${t}`);
    if (t === "scanner") await page.waitForSelector("#trivy-image");
    await page.waitForTimeout(700);
    panes.push((await page.locator(".opts-body").screenshot({ animations: "disabled", caret: "hide" })).toString("base64"));
  }
  const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const sheet = await browser.newPage({ viewport: { width: 1500, height: 100 } });
  await sheet.setContent(
    `<body style="margin:0;padding:24px;background:${background};display:flex;gap:24px;align-items:flex-start">` +
      panes.map((b) => `<img src="data:image/png;base64,${b}">`).join("") +
      "</body>",
  );
  await sheet.screenshot({ path: path.join(outDir, "14-options.png"), fullPage: true });
  console.log("  14-options.png");
  await sheet.close();
}

// ---- Help ----
// One image with the glossary and the app config side by side, like the Options image. The dialog
// scrolls, so each half is photographed with its height limit lifted while the other is hidden, then
// the two are laid out on a blank page and photographed again. Paths that depend on the machine or
// the throwaway temp dir are replaced, so the image does not change from one run or machine to the next.
if (views !== "deps") {
  await page.click("#help-btn");
  await page.waitForSelector("#help-config .hgroup");
  await page.evaluate(() => {
    const sample = {
      Executable: "/usr/local/bin/trivy-scanner",
      "Working directory": "/home/user",
      Home: "/home/user",
      "User cache dir": "/home/user/.cache",
      "User config dir": "/home/user/.config",
      "Trivy cache": "/home/user/.cache/trivy-scanner/trivy",
      "EPSS / KEV cache": "/home/user/.cache/trivy-scanner/enrich",
      "VEX assessments": "/home/user/.config/trivy-scanner/vex.json",
    };
    // "Where it runs" rows are dt/dd pairs, "Data it keeps" are cards; both carry the path in a <code>.
    for (const label of document.querySelectorAll("#help-config .hpaths dt, #help-config .hcard h5")) {
      const holder = label.matches("dt") ? label.nextElementSibling : label.parentElement;
      const code = holder?.querySelector("code");
      const value = sample[label.textContent.trim()];
      if (value && code) code.textContent = value;
    }
    for (const code of document.querySelectorAll("#help-config .henv code, #help-config .hcard code")) {
      code.textContent = code.textContent.replace(/(\/[^\s/]+)*\/tmp\.[A-Za-z0-9]+/g, "/tmp/screenshots");
    }
  });
  const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  const half = async (hide) => {
    const style = await page.addStyleTag({
      content: `#help-dialog{height:fit-content !important;max-height:none !important}.help-body{overflow:visible !important}${hide}{display:none !important}`,
    });
    await page.setViewportSize({ width: 1400, height: 8000 });
    const height = await page.locator("#help-dialog").evaluate((d) => Math.ceil(d.getBoundingClientRect().height));
    await page.setViewportSize({ width: 1400, height: height + 80 });
    await page.waitForTimeout(700);
    const png = await page.locator("#help-dialog").screenshot({ animations: "disabled", caret: "hide" });
    await style.evaluate((el) => el.remove());
    return png.toString("base64");
  };
  const glossary = await half("#help-config");
  await page.setViewportSize({ width: 1400, height: 900 });
  await page.click(".help-nav .tab:nth-child(2)"); // the header follows the scroll position
  await page.waitForTimeout(300);
  const config = await half("#help-glossary");
  const sheet = await browser.newPage({ viewport: { width: 1800, height: 100 } });
  await sheet.setContent(
    `<body style="margin:0;padding:24px;background:${background};display:flex;gap:24px;align-items:flex-start">` +
      [glossary, config].map((b) => `<img src="data:image/png;base64,${b}">`).join("") +
      "</body>",
  );
  await sheet.screenshot({ path: path.join(outDir, "16-help.png"), fullPage: true });
  console.log("  16-help.png");
  await sheet.close();
  await page.setViewportSize({ width: 1400, height: 900 });
}

await browser.close();

const files = readdirSync(outDir).filter((f) => f.endsWith(".png"));
console.log(`${files.length} screenshots in ${outDir} (${files.reduce((n, f) => n + statSync(path.join(outDir, f)).size, 0) >> 10} KiB)`);
if (problems.length) {
  console.error("\nProblems:\n - " + problems.join("\n - "));
  process.exit(1);
}
