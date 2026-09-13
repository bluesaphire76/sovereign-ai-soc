/* Local read-only capture, then offline API replay. Private snapshots never belong in git. */
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const { chromium } = require(process.env.UX_BROWSER_MODULE || "playwright");
const base = process.env.UX_BASE_URL || "http://127.0.0.1:3001";
const output =
  process.env.UX_BROWSER_OUTPUT || "/home/lele/.cache/ux12-browser";
const snapshotPath =
  process.env.UX_SNAPSHOT || path.join(output, "snapshot.json");
const capture = process.env.UX_CAPTURE === "1";
const widths = (
  process.env.UX_WIDTHS || (capture ? "1440" : "390,768,1024,1440,1920")
)
  .split(",")
  .map(Number);
const axePath = require.resolve("../frontend/node_modules/axe-core/axe.min.js");
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const key = (url) =>
  url.pathname +
  (url.searchParams.size
    ? "?" +
      [...url.searchParams]
        .sort()
        .map(([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v))
        .join("&")
    : "");
const pageRoutes = (incident, caseId) => [
  "/login",
  "/",
  "/executive",
  "/incidents",
  `/incidents/${incident}`,
  "/cases",
  `/cases/${caseId}`,
  "/cases/kanban",
  "/assistant",
  "/health",
  "/detection-quality",
  "/settings/detection-control",
  "/network-events",
  "/dns-telemetry",
  "/system-information/operation-history",
  "/admin/users",
  "/system-information/security-audit",
  "/settings/ai-providers",
  "/settings/ai-data-control",
  "/settings/semantic-memory",
];

async function main() {
  process.umask(0o077);
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  const auth = capture ? JSON.parse(fs.readFileSync(0, "utf8")) : null;
  const snapshot = capture
    ? {
        incident: auth.incident,
        caseId: auth.caseId,
        responses: fs.existsSync(snapshotPath)
          ? JSON.parse(fs.readFileSync(snapshotPath)).responses
          : {},
      }
    : JSON.parse(fs.readFileSync(snapshotPath));
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.UX_BROWSER_EXECUTABLE,
  });
  const results = [];
  try {
    for (const width of widths) {
      const context = await browser.newContext({
        viewport: { width, height: 1000 },
        timezoneId: "Europe/Zurich",
      });
      const user = auth?.user || {
        id: 1,
        username: "ux12-fixture",
        role: "ADMIN",
        is_active: true,
      };
      const token = auth?.token || "ux12-fixture";
      await context.addInitScript(
        ({ token, user }) => {
          localStorage.setItem("ai_soc_access_token", token);
          localStorage.setItem("ai_soc_user", JSON.stringify(user));
        },
        { token, user },
      );
      const page = await context.newPage();
      page.setDefaultTimeout(20000);
      let inFlight = 0,
        requests = [],
        errors = [],
        unexpected = [],
        expectedFailures = [];
      page.on("pageerror", (e) => errors.push(e.message));
      page.on("console", (m) => {
        if (m.type() !== "error") return;
        if (
          m.text().startsWith("Failed to load resource:") &&
          expectedFailures.includes(m.location().url)
        )
          return;
        errors.push(m.text());
      });
      await context.route("**/*", async (route) => {
        const r = route.request(),
          url = new URL(r.url());
        if (url.origin !== new URL(base).origin) {
          unexpected.push(url.origin + url.pathname);
          return route.abort();
        }
        if (!url.pathname.startsWith("/api-backend/")) {
          if (r.method() !== "GET") {
            unexpected.push(r.method() + " " + url.pathname);
            return route.abort();
          }
          return route.continue();
        }
        const apiUrl = new URL(
          url.pathname.slice("/api-backend".length) + url.search,
          "http://127.0.0.1:8008",
        );
        if (r.method() !== "GET") {
          unexpected.push(r.method() + " " + apiUrl.pathname);
          return route.abort();
        }
        const k = key(apiUrl);
        requests.push(k);
        inFlight++;
        try {
          let saved;
          if (capture) {
            try {
              const response = await fetch(apiUrl.href, {
                headers: { authorization: "Bearer " + token },
                signal: AbortSignal.timeout(30000),
              });
              saved = { status: response.status, body: await response.text() };
            } catch {
              // Never log a transport exception containing credential headers.
              saved = {
                status: 504,
                body: JSON.stringify({
                  detail: "Read-only snapshot capture timed out.",
                }),
                captureError: true,
              };
            }
            snapshot.responses[k] = saved;
            fs.writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2));
          } else {
            saved = snapshot.responses[k];
            if (!saved) {
              unexpected.push("Uncaptured GET " + k);
              return route.fulfill({ status: 501, body: "Uncaptured fixture" });
            }
          }
          if (saved.status >= 400) expectedFailures.push(r.url());
          return await route.fulfill({
            status: saved.status,
            contentType: "application/json",
            body: saved.body,
          });
        } catch {
          errors.push(
            "Fixture response could not be delivered: " + apiUrl.pathname,
          );
        } finally {
          inFlight--;
        }
      });
      for (const route of pageRoutes(snapshot.incident, snapshot.caseId)) {
        if (
          process.env.UX_ROUTES &&
          !process.env.UX_ROUTES.split(",").includes(route)
        )
          continue;
        requests = [];
        errors = [];
        unexpected = [];
        expectedFailures = [];
        await page.goto(base + route);
        await page.getByRole("heading", { level: 1 }).first().waitFor();
        await pause(700);
        for (let i = 0; inFlight && i < 150; i++) await pause(200);
        await pause(300);
        const loading = await page
          .getByRole("status")
          .filter({ hasText: /^Loading/ })
          .count();
        const dom = await page.evaluate(() => {
          const workspace =
            document.querySelector(".ai-soc-shell-content") ||
            document.querySelector("main");
          // Closed details and clipped table cells are not visible collisions.
          const rects = Array.from(
            workspace.querySelectorAll("button,input,select,textarea"),
          )
            .filter((e) => e.checkVisibility({ checkVisibilityCSS: true }))
            .map((e) => {
              const box = e.getBoundingClientRect();
              const r = {
                left: box.left,
                right: box.right,
                top: box.top,
                bottom: box.bottom,
              };
              for (
                let p = e.parentElement;
                p && p !== workspace;
                p = p.parentElement
              ) {
                const style = getComputedStyle(p),
                  clip = p.getBoundingClientRect();
                if (/auto|scroll|hidden|clip/.test(style.overflowX)) {
                  r.left = Math.max(r.left, clip.left);
                  r.right = Math.min(r.right, clip.right);
                }
                if (/auto|scroll|hidden|clip/.test(style.overflowY)) {
                  r.top = Math.max(r.top, clip.top);
                  r.bottom = Math.min(r.bottom, clip.bottom);
                }
              }
              return {
                name:
                  e.getAttribute("aria-label") ||
                  e.textContent?.trim().slice(0, 45),
                r,
              };
            })
            .filter(({ r }) => r.right > r.left && r.bottom > r.top);
          const overlaps = rects.flatMap((a, i) =>
            rects
              .slice(i + 1)
              .filter(
                (b) =>
                  Math.min(a.r.right, b.r.right) -
                    Math.max(a.r.left, b.r.left) >
                    2 &&
                  Math.min(a.r.bottom, b.r.bottom) -
                    Math.max(a.r.top, b.r.top) >
                    2,
              )
              .map((b) => [a.name, b.name]),
          );
          return {
            overflow: document.documentElement.scrollWidth - innerWidth,
            h1: document.querySelectorAll("h1").length,
            overlaps,
            tables: workspace.querySelectorAll("table").length,
            headings: Array.from(workspace.querySelectorAll("h1,h2,h3,h4")).map(
              (e) => ({
                level: e.tagName,
                text: e.textContent.trim().slice(0, 100),
              }),
            ),
          };
        });
        await page.addScriptTag({ path: axePath });
        const accessibility = await page.evaluate(async () => {
          const r = await window.axe.run(
            document.querySelector(".ai-soc-shell") ||
              document.querySelector("main"),
            {
              runOnly: {
                type: "tag",
                values: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"],
              },
            },
          );
          return {
            violations: r.violations.map((v) => ({
              id: v.id,
              impact: v.impact,
              description: v.description,
              nodes: v.nodes.map((n) => ({
                target: n.target,
                html: n.html,
                summary: n.failureSummary,
              })),
            })),
            incomplete: r.incomplete.map((v) => ({
              id: v.id,
              count: v.nodes.length,
            })),
          };
        });
        const result = {
          route,
          width,
          ...dom,
          loading,
          inFlight,
          requests,
          errors,
          unexpected,
          failedResponses: expectedFailures.length,
          ...accessibility,
        };
        results.push(result);
        console.log(
          JSON.stringify({
            route,
            width,
            overflow: dom.overflow,
            h1: dom.h1,
            overlaps: dom.overlaps.length,
            errors: errors.length,
            unexpected: unexpected.length,
            violations: accessibility.violations.map(
              (v) => v.id + ":" + v.nodes.length,
            ),
          }),
        );
        await page.screenshot({
          path: path.join(
            output,
            route.replaceAll("/", "_") + "-" + width + ".png",
          ),
          fullPage: true,
        });
        fs.writeFileSync(
          path.join(output, capture ? "baseline.json" : "audit.json"),
          JSON.stringify(results, null, 2),
        );
        if (capture)
          fs.writeFileSync(snapshotPath, JSON.stringify(snapshot, null, 2));
      }
      await context.close();
    }
  } finally {
    await browser.close();
  }
  if (process.env.UX_STRICT === "1") {
    assert.equal(
      results.filter(
        (r) =>
          r.overflow > 1 ||
          r.h1 !== 1 ||
          r.overlaps.length ||
          r.errors.length ||
          r.unexpected.length ||
          r.loading ||
          r.inFlight,
      ).length,
      0,
      "Layout/runtime findings; inspect private audit.json",
    );
    assert.equal(
      results.filter((r) => r.violations.length).length,
      0,
      "Accessibility findings; inspect private audit.json",
    );
  }
}
main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
