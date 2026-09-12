/* Keyboard and governed workflows on private read-only snapshots and isolated mutations. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require(process.env.UX_BROWSER_MODULE || "playwright");
const {
  fixture: detectionFixture,
  section,
} = require("./validate_ux10_browser.cjs");
const base = process.env.UX_BASE_URL || "http://127.0.0.1:3001";
const output =
  process.env.UX_BROWSER_OUTPUT ||
  "/home/lele/.cache/ux12-browser/interactions";
const snapshot = JSON.parse(
  fs.readFileSync(
    process.env.UX_SNAPSHOT || "/home/lele/.cache/ux12-browser/snapshot.json",
  ),
);
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const button = (root, name) => root.getByRole("button", { name, exact: true });

async function fixture(
  browser,
  { role = "ADMIN", width = 390, height = 1000, handler } = {},
) {
  const context = await browser.newContext({
    viewport: { width, height },
    timezoneId: "Europe/Zurich",
  });
  const user = { id: 1, username: "ux12-fixture", role, is_active: true };
  await context.addInitScript((user) => {
    localStorage.setItem("ai_soc_access_token", "ux12-fixture");
    localStorage.setItem("ai_soc_user", JSON.stringify(user));
  }, user);
  const errors = [],
    unexpected = [],
    requests = [],
    expectedFailures = [];
  const page = await context.newPage();
  page.setDefaultTimeout(20000);
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
      u = new URL(r.url()),
      method = r.method();
    if (u.origin !== new URL(base).origin) {
      unexpected.push(u.origin + u.pathname);
      return route.abort();
    }
    if (!u.pathname.startsWith("/api-backend/")) {
      if (method !== "GET") {
        unexpected.push(method + " " + u.pathname);
        return route.abort();
      }
      return route.continue();
    }
    const p = u.pathname.slice("/api-backend".length);
    const k =
      p +
      (u.searchParams.size
        ? "?" +
          [...u.searchParams]
            .sort()
            .map(
              ([k, v]) => encodeURIComponent(k) + "=" + encodeURIComponent(v),
            )
            .join("&")
        : "");
    const request = { p, method, body: r.postDataJSON(), key: k };
    requests.push(request);
    const send = (body, status = 200) => {
      if (status >= 400) expectedFailures.push(r.url());
      return route.fulfill({
        status,
        contentType: "application/json",
        body: JSON.stringify(body),
      });
    };
    if (p === "/auth/me") return send(user);
    if (handler && (await handler(request, send, route))) return;
    const saved = method === "GET" && snapshot.responses[k];
    if (saved) return send(JSON.parse(saved.body), saved.status);
    unexpected.push(method + " " + k);
    return send({ detail: "Unmapped fixture" }, 501);
  });
  async function open(route) {
    await page.goto(base + route);
    await page.getByRole("heading", { level: 1 }).waitFor();
    await page.waitForFunction(
      () =>
        !Array.from(document.querySelectorAll('[role="status"]')).some((e) =>
          /^Loading/.test(e.textContent.trim()),
        ),
    );
    await pause(350);
  }
  function check(label) {
    assert.deepEqual(errors, [], label + " console");
    assert.deepEqual(unexpected, [], label + " unexpected requests");
  }
  return { page, context, requests, open, check };
}

async function run() {
  process.umask(0o077);
  fs.mkdirSync(output, { recursive: true, mode: 0o700 });
  const browser = await chromium.launch({
    headless: true,
    executablePath: process.env.UX_BROWSER_EXECUTABLE,
  });
  const results = [];
  const pass = (label) => {
    results.push(label);
    console.log(label + " PASS");
  };
  try {
    for (const width of [390, 768, 1024, 1440, 1920]) {
      const f = await fixture(browser, { width });
      const { page } = f;
      await f.open("/incidents");
      const referenceHeight = await page
        .locator('[title="Visible incidents"]')
        .evaluate(
          (e) => e.parentElement.parentElement.getBoundingClientRect().height,
        );
      await page.keyboard.press("Tab");
      assert.equal(
        await page
          .getByRole("link", { name: "Skip to content", exact: true })
          .evaluate((e) => e === document.activeElement),
        true,
      );
      await page.keyboard.press("Enter");
      assert.equal(
        await page
          .locator("main")
          .evaluate((e) => e === document.activeElement),
        true,
      );
      if (width < 1280) {
        const toggle = button(page, "Open navigation");
        await toggle.focus();
        await page.keyboard.press("Enter");
        assert.equal(
          await button(page, "Close navigation").getAttribute("aria-expanded"),
          "true",
        );
        await page.keyboard.press("Tab");
        await page.keyboard.press("Escape");
        assert.equal(await toggle.getAttribute("aria-expanded"), "false");
        assert.equal(
          await toggle.evaluate((e) => e === document.activeElement),
          true,
        );
        await page.keyboard.press("Space");
      }
      const nav = page.getByRole("navigation", {
        name: "Primary navigation",
        exact: true,
      });
      assert.equal(
        await nav
          .getByRole("link", { name: "Incidents", exact: true })
          .getAttribute("aria-current"),
        "page",
      );
      const cases = nav.getByRole("link", { name: "Cases", exact: true });
      await cases.focus();
      await page.keyboard.press("Enter");
      await page
        .getByRole("heading", { level: 1, name: "Cases", exact: true })
        .waitFor();
      if (width < 1280)
        assert.equal(
          await button(page, "Open navigation").getAttribute("aria-expanded"),
          "false",
        );
      await f.open("/dns-telemetry");
      const scroll = page.getByRole("region", {
        name: "DNS events",
        exact: true,
      });
      await scroll.focus();
      await page.keyboard.press("ArrowRight");
      await pause(200);
      if (width === 390)
        assert.ok((await scroll.evaluate((e) => e.scrollLeft)) > 0);
      await f.open("/executive");
      const sizes = await page
        .locator(".ai-soc-shell-content")
        .evaluate((root) =>
          Array.from(root.querySelectorAll('[class*="min-h-[58px]"]'))
            .slice(0, 6)
            .map((e) => e.getBoundingClientRect().height),
        );
      assert.equal(sizes.length, 6);
      assert.equal(new Set(sizes).size, 1);
      assert.equal(sizes[0], referenceHeight);
      await page.screenshot({
        path: path.join(output, "executive-" + width + ".png"),
      });
      f.check("Keyboard " + width);
      pass(
        "Skip, navigation keys/transition, DNS scroll and six compact metrics " +
          width,
      );
      await f.context.close();
    }
    for (const role of ["ADMIN", "ANALYST", "VIEWER"]) {
      const f = await fixture(browser, { role, width: 1440 });
      await f.open("/incidents");
      const nav = f.page.getByRole("navigation", {
        name: "Primary navigation",
        exact: true,
      });
      const external = nav.getByRole("link", { name: /^Observability/ });
      assert.equal(await external.count(), role === "VIEWER" ? 0 : 1);
      assert.equal(
        await nav.getByRole("link", { name: "Assistant", exact: true }).count(),
        role === "VIEWER" ? 0 : 1,
      );
      assert.equal(
        await nav
          .getByRole("link", { name: "Semantic Memory", exact: true })
          .count(),
        role === "VIEWER" ? 0 : 1,
      );
      assert.equal(
        await nav
          .getByRole("link", { name: "Security Audit", exact: true })
          .count(),
        role === "ADMIN" ? 1 : 0,
      );
      if (role !== "VIEWER") {
        assert.equal(await external.getAttribute("target"), "_blank");
        assert.match(await external.getAttribute("href"), /^https:\/\//);
      }
      f.check(role);
      pass(role + " navigation RBAC/external link");
      await f.context.close();
    }
    for (const width of [390, 768, 1024, 1440, 1920]) {
      const f = await detectionFixture(browser, "ADMIN", "normal", width);
      await f.open();
      await f.page.setViewportSize({ width, height: 420 });
      const trigger = section(f.page, "Managed Service Restart").getByRole(
        "button",
        { name: "Restart", exact: true },
      );
      await trigger.focus();
      await f.page.keyboard.press("Enter");
      const dialog = f.page.getByRole("dialog", {
        name: "Restart AI SOC Worker",
        exact: true,
      });
      await dialog.waitFor();
      const box = await dialog.boundingBox();
      assert.ok(
        box.y >= 0 &&
          box.y + box.height <= 420 &&
          box.x >= 0 &&
          box.x + box.width <= width,
      );
      for (const key of [
        "Tab",
        "Tab",
        "Shift+Tab",
        "Tab",
        "Tab",
        "Tab",
        "Tab",
        "Tab",
      ]) {
        await f.page.keyboard.press(key);
        assert.equal(
          await f.page.evaluate(
            () =>
              !document.hasFocus() ||
              Boolean(document.activeElement.closest("dialog")),
          ),
          true,
        );
      }
      assert.equal(await button(dialog, "Run preview").isEnabled(), false);
      assert.equal(await button(dialog, "Restart service").isEnabled(), false);
      await button(dialog, "Cancel").focus();
      await f.page.keyboard.press("Space");
      await dialog.waitFor({ state: "hidden" });
      assert.equal(
        await trigger.evaluate((e) => e === document.activeElement),
        true,
      );
      assert.equal(f.requests.filter((r) => r.method !== "GET").length, 0);
      await f.check("Short dialog");
      pass(
        "Short viewport modal, Tab/Shift+Tab, Cancel and reason gate " + width,
      );
      await f.context.close();
    }
    for (const role of ["ADMIN", "ANALYST", "VIEWER"]) {
      const f = await fixture(browser, {
        role,
        handler: async (r, send) => {
          if (
            r.method === "PATCH" &&
            r.p === `/incidents/${snapshot.incident}/status`
          ) {
            await send({ status: r.body.status });
            return true;
          }
          if (
            r.method === "PATCH" &&
            r.p === `/cases/${snapshot.caseId}/workflow`
          ) {
            await send(
              {
                detail:
                  "Fixture closure blocked: approval and evidence required",
              },
              400,
            );
            return true;
          }
          return false;
        },
      });
      const { page } = f;
      await f.open("/incidents/" + snapshot.incident);
      const status = page.getByRole("combobox", {
        name: "Lifecycle status",
        exact: true,
      });
      assert.equal(await status.isEnabled(), role !== "VIEWER");
      if (role !== "VIEWER") {
        await status.focus();
        await page.keyboard.press("ArrowDown");
        await page.keyboard.press("Enter");
        const value = await status.inputValue();
        assert.notEqual(value, "NEW");
        const changed = page.waitForResponse(
          (r) => r.request().method() === "PATCH",
        );
        await button(page, "Update").focus();
        await page.keyboard.press("Enter");
        await changed;
        assert.deepEqual(f.requests.find((r) => r.method === "PATCH").body, {
          status: value,
        });
      }
      await f.open("/cases/" + snapshot.caseId);
      const workflow = page.locator("#case-workflow");
      const summary = workflow.locator("summary");
      if ((await workflow.getAttribute("open")) === null) {
        await summary.focus();
        await page.keyboard.press("Space");
      }
      if (role === "VIEWER") {
        assert.equal(
          await button(workflow, "Save workflow").isVisible(),
          false,
        );
        assert.equal(f.requests.filter((r) => r.method !== "GET").length, 0);
      } else {
        await workflow
          .getByRole("combobox", { name: "Status", exact: true })
          .selectOption("CLOSED");
        await workflow
          .getByRole("textbox", { name: /Status reason \/ analyst comment/ })
          .fill("Fixture closure review");
        const blocked = page.waitForResponse(
          (r) => r.request().method() === "PATCH",
        );
        await button(workflow, "Save workflow").focus();
        await page.keyboard.press("Enter");
        await blocked;
        await page.getByText(/Fixture closure blocked/).waitFor();
        const r = f.requests.filter((r) => r.method === "PATCH").at(-1);
        assert.equal(r.body.status, "CLOSED");
        assert.equal(r.body.status_reason, "Fixture closure review");
        assert.equal(await button(workflow, "Save workflow").isEnabled(), true);
      }
      await page.screenshot({
        path: path.join(output, "case-workflow-" + role + ".png"),
        fullPage: true,
      });
      f.check(role + " investigation");
      pass(
        role +
          " incident status keyboard/payload and case closure rejection/read-only safety",
      );
      await f.context.close();
    }
    {
      const f = await fixture(browser, { width: 390 });
      await f.open("/cases/kanban");
      const card = f.page
        .locator(`main a[href="/cases/${snapshot.caseId}"]`)
        .first();
      await card.focus();
      await f.page.keyboard.press("Enter");
      await f.page.waitForURL(base + "/cases/" + snapshot.caseId);
      await f.page.getByRole("heading", { level: 1 }).waitFor();
      assert.match(f.page.url(), /\/cases\/\d+$/);
      f.check("Kanban");
      pass("Kanban card reachable and opens by keyboard");
      await f.context.close();
    }
    for (const width of [390, 1440]) {
      const f = await fixture(browser, {
        width,
        handler: async (r, send) => {
          if (r.method !== "GET" || r.p !== "/cases") return false;
          const data = JSON.parse(snapshot.responses["/cases?limit=100"].body);
          data.items = data.items.map((item) => ({
            ...item,
            demo_origin: item.id === snapshot.caseId ? "seed" : null,
          }));
          await send(data);
          return true;
        },
      });
      await f.open("/cases");
      const trigger = button(f.page, "Delete");
      for (const cancelKey of ["Escape", "Space"]) {
        await trigger.focus();
        await f.page.keyboard.press("Enter");
        const dialog = f.page.getByRole("dialog", {
          name: `Delete synthetic case #${snapshot.caseId}?`,
          exact: true,
        });
        await dialog.waitFor();
        const cancel = button(dialog, "Cancel");
        assert.equal(
          await cancel.evaluate((e) => e === document.activeElement),
          true,
        );
        await f.page.keyboard.press(cancelKey);
        await dialog.waitFor({ state: "hidden" });
        assert.equal(
          await trigger.evaluate((e) => e === document.activeElement),
          true,
        );
        assert.equal(f.requests.filter((r) => r.method !== "GET").length, 0);
      }
      f.check("Case confirmation");
      pass(
        "Case demo confirmation initial/return focus and Escape/Cancel safety " +
          width,
      );
      await f.context.close();
    }
    for (const scope of ["global", "incident", "case"]) {
      let kind = "model",
        delay = 0;
      const f = await fixture(browser, {
        handler: async (r, send) => {
          if (r.p !== "/assistant/query" || r.method !== "POST") return false;
          await pause(delay);
          const source = {
            source_id: "I1",
            source_type: "incident",
            authority: "authoritative",
            provenance_class: "operational_source",
            record_id: String(snapshot.incident),
            label: "Isolated incident source",
            url: "/incidents/" + snapshot.incident,
            score: null,
            section: null,
          };
          await send({
            status: "ok",
            generation_kind: kind,
            answer: "Fixture answer",
            blocks: [
              {
                kind: "direct_answer",
                text: "Fixture answer",
                source_ids: ["I1"],
                provenance_classes: ["operational_source"],
              },
            ],
            scope,
            incident_id: scope === "incident" ? snapshot.incident : null,
            case_id: scope === "case" ? snapshot.caseId : null,
            sources: [source],
            limitations: ["Fixture limitation: no action executed."],
            metadata: {
              generation_kind: kind,
              grounding_validation: "passed",
              semantic_proof_status: "not_run",
              response_language: "en",
              secondary_intents: [],
              semantic_status: "not_requested",
              semantic_index_status: "not_requested",
              focus_validation: "passed",
              plan_validation_status: "not_run",
              semantic_degraded: false,
              source_count: 1,
              effective_profile: "standard",
              effective_model: "fixture",
              queue_wait_ms: 0,
              generation_ms: 0,
              total_latency_ms: 0,
            },
          });
          return true;
        },
      });
      const { page } = f;
      await f.open(
        scope === "global"
          ? "/assistant"
          : scope === "incident"
            ? "/incidents/" + snapshot.incident
            : "/cases/" + snapshot.caseId,
      );
      const question =
        scope === "global"
          ? page.getByLabel("Assistant question", { exact: true })
          : page.getByLabel(
              "Question for " +
                (scope === "incident"
                  ? "Incident #" + snapshot.incident
                  : "Case #" + snapshot.caseId),
              { exact: true },
            );
      // Incident contextual assistance belongs to an existing section tab.
      if (!(await question.isVisible()) && scope === "incident") {
        await button(page, "AI analysis").focus();
        await page.keyboard.press("Enter");
      }
      for (const generation of ["model", "deterministic_fallback"]) {
        kind = generation;
        await question.fill("Summarize this isolated fixture.");
        await question.press(scope === "global" ? "Enter" : "Control+Enter");
        const answer = page
          .getByRole("article", { name: "SOC Assistant response", exact: true })
          .last();
        await answer
          .getByText(
            generation === "model" ? "AI generated" : "Deterministic fallback",
            { exact: true },
          )
          .waitFor();
        await answer.getByText("Grounding: passed", { exact: true }).waitFor();
        await answer
          .getByText("Semantic proof: not run", { exact: true })
          .waitFor();
        const cite = answer.getByRole("link", {
          name: "Jump to source I1",
          exact: true,
        });
        await cite.focus();
        await page.keyboard.press("Enter");
        assert.equal(
          await page.evaluate(() => document.activeElement.tagName === "LI"),
          true,
        );
        await page.keyboard.press("Tab");
        assert.equal(
          await answer
            .getByRole("link", {
              name: "Open source I1: Isolated incident source",
              exact: true,
            })
            .evaluate((e) => e === document.activeElement),
          true,
        );
        const technical = answer
          .locator("summary")
          .filter({ hasText: "Technical details" });
        await technical.focus();
        await page.keyboard.press("Space");
        assert.equal(
          await technical.evaluate((e) => e.parentElement.open),
          true,
        );
        await answer
          .getByText("Fixture limitation: no action executed.", { exact: true })
          .waitFor();
        await page.addScriptTag({
          path: require.resolve("../frontend/node_modules/axe-core/axe.min.js"),
        });
        const violations = await answer.evaluate(async (e) =>
          (
            await window.axe.run(e, {
              runOnly: {
                type: "tag",
                values: ["wcag2a", "wcag2aa", "wcag21aa"],
              },
            })
          ).violations.map((v) => ({
            id: v.id,
            targets: v.nodes.map((n) => n.target),
          })),
        );
        assert.deepEqual(violations, [], scope + " answer accessibility");
        const request = f.requests
          .filter((r) => r.p === "/assistant/query")
          .at(-1);
        assert.equal(request.body.scope, scope);
        assert.equal(
          request.body.incident_id,
          scope === "incident" ? snapshot.incident : null,
        );
        assert.equal(
          request.body.case_id,
          scope === "case" ? snapshot.caseId : null,
        );
        pass(
          scope +
            " " +
            generation +
            " provenance, source focus, keyboard technical details and axe",
        );
      }
      delay = 1500;
      await page.emulateMedia({ reducedMotion: "reduce" });
      await question.fill("Cancel isolated request.");
      await question.press(scope === "global" ? "Enter" : "Control+Enter");
      const cancel = button(
        page,
        scope === "global" ? "Cancel request" : "Cancel",
      );
      await cancel.waitFor();
      const spinner = page.locator(".animate-spin").first();
      if (await spinner.count())
        assert.ok(
          (await spinner.evaluate((e) =>
            parseFloat(getComputedStyle(e).animationDuration),
          )) < 0.001,
        );
      await cancel.focus();
      await page.keyboard.press("Space");
      await cancel.waitFor({ state: "hidden" });
      await pause(1600);
      assert.equal(
        await page
          .getByRole("article", { name: "SOC Assistant response", exact: true })
          .count(),
        2,
      );
      await page.screenshot({
        path: path.join(output, scope + "-assistant.png"),
        fullPage: true,
      });
      f.check(scope);
      pass(scope + " cancellation and reduced motion");
      await f.context.close();
    }
    {
      const f = await fixture(browser, { width: 1440 });
      await f.open("/health");
      const count = () =>
        f.requests.filter((r) => r.p === "/platform/health").length;
      const initial = count();
      await pause(32000);
      assert.equal(
        count() - initial,
        1,
        "Health retains its 30 second interval without runaway polling",
      );
      f.check("Polling");
      pass("Health bounded 30 second polling");
      await f.context.close();
    }
    fs.writeFileSync(
      path.join(output, "results.json"),
      JSON.stringify(results, null, 2),
    );
  } finally {
    await browser.close();
  }
}
module.exports = { fixture, snapshot, base };
if (require.main === module)
  run().catch((e) => {
    console.error(e);
    process.exitCode = 1;
  });
