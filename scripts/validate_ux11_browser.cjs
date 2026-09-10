/* Reuses cached Playwright. All backend requests fail closed into isolated fixtures. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require(process.env.UX_BROWSER_MODULE || "playwright");
const base = process.env.UX_BASE_URL || "http://127.0.0.1:3001";
const output = process.env.UX_BROWSER_OUTPUT || "/tmp/ux11-browser";
const audit = "/system-information/security-audit";
const routes = ["/login", "/admin/users", audit];
const stamp = "2026-09-09T12:00:00Z";
const secret = "fixture-only-password";
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const button = (root, name) => root.getByRole("button", {name, exact:true});
const enabled = async (locator, value) => assert.equal(await locator.isEnabled(), value);

async function fixture(browser, role = "ADMIN", width = 1440) {
  const context = await browser.newContext({viewport:{width, height:1000}, timezoneId:"Europe/Zurich"});
  const users = ["ADMIN", "ANALYST", "VIEWER"].map((role, i) => ({id:i+1, username:role.toLowerCase(),
    display_name:"Fixture " + role, role, is_active:true, last_login_at:stamp, created_at:stamp, updated_at:stamp}));
  const user = users.find(u => u.role === role) || null;
  const control = {user, users, delay:0, authDelay:0, authStatus:200, status:200, empty:false,
    mutationStatus:200, loginStatus:401, loginDelay:0, loginAbort:false};
  // Seed only once per context so redirect/logout tests cannot silently recreate a session.
  await context.addInitScript(user => {
    if (!sessionStorage.getItem("ux11-seeded")) {
      sessionStorage.setItem("ux11-seeded", "yes");
      if (user) {
        localStorage.setItem("ai_soc_access_token", "ux11-fixture");
        localStorage.setItem("ai_soc_user", JSON.stringify(user));
      }
    }
  }, user);
  const requests = [], errors = [], unexpected = [], expectedFailures = [];
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on("pageerror", error => errors.push(error.message));
  page.on("console", message => {
    if (message.type() !== "error") return;
    // Browser resource diagnostics are expected only for deliberately failed fixture responses.
    if (message.text().startsWith("Failed to load resource:") && expectedFailures.includes(message.location().url)) return;
    errors.push(message.text());
  });
  await context.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url()), method = request.method();
    if (url.origin !== new URL(base).origin) { unexpected.push(request.url()); return route.abort(); }
    const body = request.postData() ? JSON.parse(request.postData()) : null;
    const send = (data, status = 200) => {
      if (status >= 400) expectedFailures.push(request.url());
      return route.fulfill({status, contentType:"application/json", body:JSON.stringify(data)});
    };
    if (url.pathname.startsWith("/api/auth/")) {
      requests.push({p:url.pathname, method, body});
      // Local Next cookie-only handlers are real; they neither authenticate nor contact the backend.
      if (["/api/auth/session", "/api/auth/logout"].includes(url.pathname) && method === "POST") return route.continue();
      unexpected.push(method + " " + url.pathname); return send({}, 501);
    }
    if (!url.pathname.startsWith("/api-backend/")) {
      if (url.pathname === "/" && request.isNavigationRequest()) {
        return route.fulfill({contentType:"text/html", body:"<!doctype html><title>Fixture redirect</title><h1>Fixture dashboard</h1>"});
      }
      if (method !== "GET") { unexpected.push(method + " " + url.pathname); return route.abort(); }
      return route.continue();
    }
    const p = url.pathname.slice("/api-backend".length);
    requests.push({p, method, body, query:Object.fromEntries(url.searchParams)});
    if (p === "/auth/login" && method === "POST") {
      await pause(control.loginDelay);
      if (control.loginAbort) { expectedFailures.push(request.url()); return route.abort(); }
      return send(control.loginStatus === 200 ? {access_token:"ux11-login-fixture", expires_at:Math.floor(Date.now()/1000)+3600,
        token_type:"bearer", user:users[0]} : {detail:"RAW_BACKEND_TRACE secret=do-not-display"}, control.loginStatus);
    }
    if (p === "/auth/me") {
      await pause(control.authDelay);
      const authenticated = control.user && request.headers().authorization;
      return send(authenticated ? control.user : {detail:"Authentication required"}, authenticated ? control.authStatus : 401);
    }
    await pause(control.delay);
    if (method !== "GET") {
      if (control.mutationStatus !== 200) return send({detail:"RAW_BACKEND_TRACE"}, control.mutationStatus);
      if (p === "/users" && method === "POST") {
        const created = {...body, id:control.users.length+1, username:body.username.trim().toLowerCase(), password:undefined};
        control.users.push(created); return send(created);
      }
      const match = p.match(/^\/users\/(\d+)(\/password)?$/);
      if (match) {
        const target = control.users.find(u => u.id === Number(match[1]));
        if (method === "POST" && match[2]) return send({status:"password_updated", user:target});
        if (method === "DELETE") { control.users = control.users.filter(u => u !== target); return send({status:"deleted"}); }
        if (method === "PATCH") {
          for (const [key, value] of Object.entries(body)) if (value !== null) target[key] = value;
          return send(target);
        }
      }
      unexpected.push(method + " " + p); return send({}, 501);
    }
    if (control.status !== 200) return send({detail:"RAW_BACKEND_TRACE"}, control.status);
    if (p === "/users") return send({items:control.empty ? [] : control.user?.role === "ADMIN" ? control.users : control.users.filter(u => u.id === control.user?.id)});
    if (p === "/security-audit/events") {
      const pageNumber = Number(url.searchParams.get("page") || 1);
      const items = ["SUCCESS", "FAILURE", "DENIED", "UNKNOWN"].map((outcome, i) => ({
        id:(pageNumber-1)*25+i+1, created_at:stamp, event_type:i === 2 ? "RBAC_DENIED" : i === 3 ? "UNCLASSIFIED" : "USER_UPDATED",
        outcome, actor_user_id:1, actor_username:"admin", actor_role:"ADMIN", target_type:"USER", target_id:"2",
        target_username:"analyst", method:"PATCH", path:"/users/2", client_ip:"192.0.2.1",
        user_agent:"Fixture user agent with a full technical value ".repeat(6), details:i === 3 ? {raw:"malformed fixture JSON"} : {changes:{role:["ANALYST","VIEWER"]}},
      }));
      return send({items:control.empty ? [] : items, page:pageNumber, limit:25, total:control.empty ? 0 : 29, total_pages:control.empty ? 1 : 2});
    }
    unexpected.push(method + " " + p); return send({}, 501);
  });
  async function settled() {
    await page.waitForFunction(() => !Array.from(document.querySelectorAll('[role="status"]'))
      .some(e => e.textContent.trim().startsWith("Loading")));
    await pause(80);
  }
  async function open(route) {
    await page.goto(base + route);
    await page.getByRole("heading", {level:1}).waitFor();
    if (route.startsWith("/login")) { await page.getByLabel("Username", {exact:true}).fill(""); await pause(100); }
    else { await settled(); }
  }
  async function check(label) {
    assert.deepEqual(errors, [], label + " JavaScript/console errors");
    assert.deepEqual(unexpected, [], label + " unexpected requests");
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth+1), true, label + " page overflow");
    const collisions = await page.locator("main button:visible, main input:visible, main select:visible").evaluateAll(nodes => {
      const rects = nodes.filter(n => !n.closest("nav")).map(n => ({name:n.getAttribute("aria-label") || n.textContent, r:n.getBoundingClientRect()}));
      return rects.flatMap((a, i) => rects.slice(i+1).filter(b => Math.min(a.r.right,b.r.right)-Math.max(a.r.left,b.r.left)>1 &&
        Math.min(a.r.bottom,b.r.bottom)-Math.max(a.r.top,b.r.top)>1).map(b => [a.name, b.name]));
    });
    // Modal overlays intentionally cover background controls; check ordinary layouts separately.
    if (!await page.getByRole("dialog").count()) assert.deepEqual(collisions, [], label + " control overlap");
    assert.equal((await page.textContent("body")).includes("RAW_BACKEND_TRACE"), false);
  }
  const mutations = () => requests.filter(r => r.p.startsWith("/users") && r.method !== "GET");
  return {page, context, control, requests, mutations, open, settled, check};
}

async function run() {
  fs.mkdirSync(output, {recursive:true});
  const browser = await chromium.launch({headless:true, executablePath:process.env.UX_BROWSER_EXECUTABLE});
  const results = [];
  const pass = label => { results.push(label + " PASS"); console.log(label + " PASS"); };
  try {
    for (const width of [390, 1440, 1920]) {
      const f = await fixture(browser, "ADMIN", width);
      for (const route of routes) {
        await f.open(route); await f.check(route + " " + width);
        await f.page.screenshot({path:path.join(output, route.replaceAll("/", "_") + "-" + width + ".png"), fullPage:true});
        if (route === "/login") assert.equal(await f.page.getByRole("navigation").count(), 0);
        else assert.equal(await f.page.getByRole("table").count(), 1);
        pass(route + " responsive " + width);
        if (route === audit) {
          await button(f.page,"Show details for event 1").click();
          await f.page.getByText("Full event / raw metadata", {exact:true}).click();
          await f.check("Expanded audit " + width);
          assert.equal(JSON.parse(await f.page.locator('pre[aria-label="Full event JSON for event 1"]').textContent()).created_at, stamp);
          await f.page.screenshot({path:path.join(output,"audit-expanded-" + width + ".png"), fullPage:true});
          pass("Expanded audit JSON responsive " + width);
        }
      }
      await f.open("/admin/users");
      await button(f.page.getByRole("row").filter({hasText:"Fixture ANALYST"}), "Reset password").click();
      const dialog = f.page.getByRole("dialog", {name:"Reset password for analyst", exact:true});
      await dialog.waitFor();
      assert.equal(await dialog.getByLabel("New password", {exact:true}).getAttribute("type"), "password");
      const box = await dialog.boundingBox();
      assert.ok(box.x >= 0 && box.x+box.width <= width && box.height <= 1000);
      for (let i=0; i<7; i++) {
        await f.page.keyboard.press("Tab");
        assert.equal(await f.page.evaluate(() => !document.hasFocus() || Boolean(document.activeElement.closest("dialog"))), true);
      }
      await f.page.screenshot({path:path.join(output, "password-dialog-" + width + ".png")});
      await f.page.keyboard.press("Escape");
      await dialog.waitFor({state:"hidden"});
      assert.equal(await f.page.evaluate(() => document.activeElement?.tagName === "BUTTON" && document.activeElement.textContent.trim() === "Reset password"), true, "Password cancel restores trigger focus");
      assert.equal(f.mutations().length, 0);
      await f.check("Dialog " + width);
      pass("Password dialog viewport/focus/Escape " + width);
      await f.context.close();
    }
    for (const role of ["ADMIN", "ANALYST", "VIEWER"]) {
      const f = await fixture(browser, role); const {page} = f;
      await f.open("/admin/users");
      assert.equal(await page.locator("tbody tr").count(), role === "ADMIN" ? 3 : 1);
      assert.equal(await button(page, "Create").count(), role === "ADMIN" ? 1 : 0);
      const row = page.getByRole("row").filter({hasText:"Fixture " + role});
      if (role === "ADMIN") {
        await enabled(button(row,"Delete"), false); await enabled(button(row,"Disable"), false);
        await enabled(button(row,"Change account status for admin"), false);
      } else {
        assert.equal(await button(page,"Delete").count(), 0);
        assert.equal(await page.getByRole("combobox").count(), 0);
      }
      await button(row,"Reset password").click();
      const dialog = page.getByRole("dialog", {name:"Reset password for " + role.toLowerCase(), exact:true});
      await dialog.getByLabel("New password", {exact:true}).fill("short");
      await enabled(button(dialog,"Reset password"), false);
      await button(dialog,"Cancel").click(); assert.equal(f.mutations().length, 0);
      await button(row,"Reset password").click();
      assert.equal(await dialog.getByLabel("New password", {exact:true}).inputValue(), "");
      await dialog.getByLabel("New password", {exact:true}).fill(secret);
      f.control.delay = 500;
      await dialog.getByLabel("New password", {exact:true}).press("Enter");
      await enabled(button(dialog,"Cancel"), false);
      await page.keyboard.press("Escape"); assert.equal(await dialog.isVisible(), true);
      await dialog.waitFor({state:"hidden"}); await f.settled();
      assert.deepEqual(f.mutations().map(r => ({p:r.p, method:r.method, body:r.body})),
        [{p:"/users/" + f.control.user.id + "/password", method:"POST", body:{password:secret}}]);
      assert.equal((await page.textContent("body")).includes(secret), false);
      f.control.delay = 0;
      await f.open(audit);
      assert.equal(f.requests.filter(r => r.p === "/security-audit/events").length > 0, role === "ADMIN");
      if (role !== "ADMIN") {
        await page.getByRole("alert").filter({hasText:/Forbidden/}).waitFor();
        assert.equal(await page.getByRole("table").count(), 0);
      }
      await f.check(role); pass(role + " listing/self-service/audit RBAC");
      await f.context.close();
    }
    {
      const f = await fixture(browser); const {page, control} = f;
      await f.open("/admin/users");
      await page.getByLabel("Username", {exact:true}).fill(" Fixture ");
      await page.getByLabel("Display name", {exact:true}).fill("Disposable");
      await page.getByLabel("Password (minimum 8 characters)", {exact:true}).fill(secret);
      await page.getByLabel("Password (minimum 8 characters)", {exact:true}).press("Enter");
      await page.getByText("User created.", {exact:true}).waitFor(); await f.settled();
      assert.deepEqual(f.mutations()[0].body, {username:" Fixture ", display_name:"Disposable", role:"ANALYST", password:secret, is_active:true});
      assert.equal(await page.getByLabel("Username", {exact:true}).inputValue(), "");
      const row = page.getByRole("row").filter({hasText:"Disposable"});
      await row.getByRole("combobox").selectOption("VIEWER"); await f.settled();
      assert.deepEqual(f.mutations().at(-1).body, {role:"VIEWER"});
      const before = f.mutations().length;
      page.once("dialog", d => d.dismiss()); await button(row,"Edit").click();
      assert.equal(f.mutations().length, before);
      page.once("dialog", d => d.accept(" Renamed ")); await button(row,"Edit").click(); await f.settled();
      const renamed = page.getByRole("row").filter({hasText:"Renamed"});
      await renamed.waitFor(); assert.deepEqual(f.mutations().at(-1).body, {display_name:"Renamed"});
      for (const trigger of ["Change account status for fixture", "Disable", "Delete"]) {
        await button(renamed, trigger).click();
        const dialog = page.getByRole("dialog");
        assert.ok((await dialog.textContent()).includes("fixture"));
        await button(dialog,"Cancel").click();
        await button(renamed, trigger).click(); await page.keyboard.press("Escape");
        assert.equal(f.mutations().length, before + 1);
      }
      await button(renamed,"Disable").click();
      await button(page.getByRole("dialog"),"Disable user").click(); await f.settled();
      await button(renamed,"Enable").waitFor(); assert.deepEqual(f.mutations().at(-1).body, {is_active:false});
      await button(renamed,"Enable").click();
      await button(page.getByRole("dialog"),"Enable user").click(); await f.settled();
      await button(renamed,"Disable").waitFor(); assert.deepEqual(f.mutations().at(-1).body, {is_active:true});
      await button(renamed,"Reset password").click();
      let dialog = page.getByRole("dialog", {name:"Reset password for fixture", exact:true});
      control.mutationStatus = 503;
      await dialog.getByLabel("New password", {exact:true}).fill(secret);
      await button(dialog,"Reset password").click();
      await dialog.getByRole("alert").waitFor(); await enabled(button(dialog,"Cancel"), true);
      assert.equal((await dialog.textContent()).includes(secret), false);
      assert.equal((await dialog.textContent()).includes("RAW_BACKEND_TRACE"), false);
      await button(dialog,"Cancel").click(); control.mutationStatus = 200;
      await button(renamed,"Delete").click();
      await button(page.getByRole("dialog"),"Delete user").click(); await f.settled();
      await renamed.waitFor({state:"hidden"});
      assert.equal(f.mutations().at(-1).method, "DELETE"); assert.equal(f.mutations().at(-1).body, null);
      await page.getByRole("combobox", {name:"Role for admin", exact:true}).selectOption("VIEWER");
      await page.getByRole("heading", {name:"User Profile", exact:true}).waitFor();
      assert.equal(await button(page,"Create").count(), 0); assert.equal(await page.locator("tbody tr").count(), 1);
      await f.check("Admin operations"); pass("Admin create/edit/role/status/reset/delete payloads, errors and cancellation");
      await f.context.close();
    }
    {
      const f = await fixture(browser); const {page, control} = f;
      await f.open(audit);
      await button(page,"Show details for event 1").click();
      assert.deepEqual(JSON.parse(await page.locator('pre[aria-label="Details JSON for event 1"]').textContent()), {changes:{role:["ANALYST","VIEWER"]}});
      await page.getByText("Full event / raw metadata", {exact:true}).click();
      const raw = JSON.parse(await page.locator('pre[aria-label="Full event JSON for event 1"]').textContent());
      assert.equal(raw.created_at, stamp); assert.equal(raw.actor_user_id, 1); assert.equal(raw.target_id, "2");
      assert.ok(raw.user_agent.length > 240);
      assert.ok((await page.getByText("UNKNOWN", {exact:true}).getAttribute("class")).includes("slate"));
      await button(page,"Next").click(); await page.getByText("Page 2 of 2", {exact:true}).last().waitFor();
      for (const [label, value, key] of [["Event type","USER_UPDATED","event_type"], ["Outcome","SUCCESS","outcome"], ["Target type","USER","target_type"]]) {
        await page.getByRole("combobox", {name:label, exact:true}).selectOption(value); await f.settled();
        assert.equal(f.requests.filter(r => r.p === "/security-audit/events").at(-1).query[key], value);
        assert.equal(f.requests.filter(r => r.p === "/security-audit/events").at(-1).query.page, "1");
      }
      for (const [label, value, key] of [["Actor","admin","actor_username"], ["Target ID","2","target_id"], ["Date from","2026-09-09","date_from"], ["Date to","2026-09-10","date_to"], ["Search audit events","fixture","search"]]) {
        const input = page.getByLabel(label, {exact:true});
        await input.fill(value); await f.settled();
        assert.equal(f.requests.filter(r => r.p === "/security-audit/events").at(-1).query[key], value);
      }
      const search = page.getByRole("searchbox", {name:"Search audit events", exact:true});
      await search.fill(""); await search.pressSequentially("keyboard", {delay:120}); await f.settled();
      assert.equal(await search.inputValue(), "keyboard"); assert.equal(await search.evaluate(e => e === document.activeElement), true);
      await button(page,"Reset").click(); await f.settled();
      assert.deepEqual(f.requests.filter(r => r.p === "/security-audit/events").at(-1).query, {page:"1", limit:"25"});
      // No previous records may remain visible during a permission recheck or after role revocation.
      control.authDelay = 600;
      await button(page,"Refresh").click();
      await page.getByRole("status").filter({hasText:/Loading security audit/}).waitFor();
      assert.equal(await page.getByText("Event #1", {exact:true}).count(), 0);
      control.user = {...control.user, role:"VIEWER"};
      await page.getByRole("alert").filter({hasText:/Forbidden/}).waitFor();
      assert.equal(await page.getByRole("table").count(), 0);
      await f.check("Audit"); pass("Audit metadata/neutral outcomes, all eight filters, paging, focus and access recheck");
      await f.context.close();
    }
    for (const alias of ["/security-audit", "/admin/security-audit"]) {
      const f = await fixture(browser); await f.open(alias);
      await f.page.waitForURL(base + audit); await f.check(alias); pass(alias + " canonical redirect");
      await f.context.close();
    }
    for (const mode of ["empty", "unavailable", "forbidden", "loading"]) {
      const f = await fixture(browser);
      if (mode === "empty") f.control.empty = true;
      if (mode === "unavailable") f.control.status = 503;
      if (mode === "forbidden") f.control.status = 403;
      if (mode === "loading") f.control.delay = 1800;
      for (const route of ["/admin/users", audit]) {
        if (mode === "loading") {
          await f.page.goto(base + route);
          await f.page.getByRole("status").filter({hasText:/Loading/}).first().waitFor();
          await f.settled();
        } else await f.open(route);
        if (["unavailable","forbidden"].includes(mode)) await f.page.getByRole("alert").filter({hasText:/request failed/}).waitFor();
        if (mode === "empty") assert.match(await f.page.textContent("body"), /No users available|No security audit events match/);
        await f.check(mode + route); pass(mode + " " + route);
      }
      await f.context.close();
    }
    for (const mode of ["anonymous", "expired", "invalid"]) {
      for (const route of ["/admin/users", audit]) {
        const f = await fixture(browser, mode === "anonymous" ? null : "ADMIN");
        if (mode === "expired") await f.context.addInitScript(() => localStorage.setItem("ai_soc_access_token_expires_at", "1"));
        if (mode === "invalid") f.control.authStatus = 401;
        await f.page.goto(base + route, {waitUntil:"commit"});
        // Both existing auth checks can redirect; assert the final UI rather than an intermediate navigation.
        await f.page.getByText("Your session is no longer available. Please sign in again.", {exact:true}).waitFor();
        assert.equal(f.page.url(), base + "/login?session=expired");
        assert.equal(await f.page.evaluate(() => localStorage.getItem("ai_soc_access_token")), null);
        assert.equal(f.requests.some(r => r.p === "/security-audit/events"), false);
        await f.check(mode); pass(mode + " session redirect " + route); await f.context.close();
      }
    }
    {
      const f = await fixture(browser, null); const {page, control} = f;
      await f.open("/login"); await enabled(button(page,"Sign in"), false);
      const username = page.getByLabel("Username", {exact:true}), password = page.getByLabel("Password", {exact:true});
      await username.focus(); await page.keyboard.press("Tab");
      assert.equal(await password.evaluate(e => e === document.activeElement), true);
      assert.equal(await password.getAttribute("autocomplete"), "current-password");
      await username.fill(" Admin "); await password.fill(secret);
      for (const [status, message] of [[401,"Invalid username or password."], [403,"User account is disabled."], [503,"Authentication service unavailable. Please try again."]]) {
        control.loginStatus = status;
        await password.press("Enter"); await page.getByText(message, {exact:true}).waitFor();
        assert.equal((await page.textContent("body")).includes("RAW_BACKEND_TRACE"), false);
        await enabled(button(page,"Sign in"), true);
      }
      control.loginAbort = true;
      await password.press("Enter"); await page.getByText("Unable to complete sign-in. Check your connection and try again.", {exact:true}).waitFor();
      control.loginAbort = false; control.loginStatus = 200; control.loginDelay = 600;
      const before = f.requests.filter(r => r.p === "/auth/login").length;
      await password.press("Enter"); await enabled(button(page,"Signing in..."), false);
      await enabled(username, false); await page.keyboard.press("Enter");
      await page.waitForURL(base + "/");
      assert.equal(f.requests.filter(r => r.p === "/auth/login").length, before + 1);
      assert.deepEqual(f.requests.filter(r => r.p === "/auth/login").at(-1).body, {username:" Admin ", password:secret});
      assert.equal(await page.evaluate(() => localStorage.getItem("ai_soc_access_token")), "ux11-login-fixture");
      assert.ok(Number(await page.evaluate(() => localStorage.getItem("ai_soc_access_token_expires_at"))) > Date.now()/1000);
      const session = f.requests.find(r => r.p === "/api/auth/session");
      assert.equal(session.body.token, "ux11-login-fixture"); assert.ok(session.body.max_age_seconds <= 3600);
      const cookie = (await f.context.cookies()).find(c => c.name === "ai_soc_access_token");
      assert.equal(cookie.httpOnly, true); assert.equal(cookie.sameSite, "Lax"); assert.equal(cookie.path, "/");
      control.user = control.users[0];
      await f.open("/admin/users"); await button(page,"Logout").click(); await page.waitForURL(base + "/login");
      assert.equal(await page.evaluate(() => localStorage.getItem("ai_soc_access_token")), null);
      assert.equal((await f.context.cookies()).some(c => c.name === "ai_soc_access_token"), false);
      assert.ok(f.requests.some(r => r.p === "/api/auth/logout"));
      await f.check("Authentication"); pass("Login keyboard/errors/duplicate guard, real local session cookie and logout cleanup");
      await f.context.close();
    }
    fs.writeFileSync(path.join(output,"results.json"), JSON.stringify(results, null, 2));
  } finally { await browser.close(); }
}
if (require.main === module) run().catch(error => {console.error(error); process.exitCode=1;});
