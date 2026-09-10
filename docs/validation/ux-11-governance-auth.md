# UX-11: Governance And Authentication

Phase: UX-11. Implementation complete; manual user verification required.
UX-12 is not started.

Branch: `feature/ux-harmonization-11-governance-auth`

Approved base: `56fc3f843c1380f0ba9f5756241a0c83a7ba0671`
(`feat: harmonize detection and operational control surfaces`). Before code edits,
the branch HEAD was verified equal to this exact commit; its parent is
`e627c687a27190f0ced46e2f1baa289fca118b48`.
The separate Executive sizing fix `02fd540` is not part of this requested base.

## Protected Pre-flight Inventory

Recorded before frontend edits. Source: complete Users, canonical Audit and Login
pages, both audit aliases, `frontend/src/lib/auth.ts`, session/logout route handlers,
AppNavigation, `routers/auth.py`, `routers/users.py`, `routers/security_audit.py`,
`security/auth.py`, `security/rbac.py`, user schemas/services and `auth_utils.py`.
Backend remains authoritative; there is no frontend middleware/proxy auth gate.

### Users

| Capability / callback | Actual contract and safeguards |
| --- | --- |
| `loadUsers` | GET /auth/me then GET /users, initial and manual refresh, no polling. ADMIN gets all users sorted by username; other authenticated roles get only their own record. |
| Identity/table | ADMIN User Management, otherwise User Profile; six columns: username, display name, role, active/disabled, last login, actions. Count only; no search/filter/pagination or email field exists. |
| `createUser` | ADMIN POST /users with username, display_name or null, role, password, is_active=true. Username nonblank, password >=8; default ANALYST; reset form and reload on success. Backend normalizes username, validates role, rejects duplicates with 409 and hashes password. |
| `updateUser` / role | ADMIN PATCH /users/{id}, single role/display_name/is_active patch. Three roles unchanged. Role selection applies directly, no existing confirmation. |
| `updateDisplayName` | ADMIN native prompt with existing display name; Cancel does nothing; trims to null before same PATCH. Backend ignores null display_name; do not silently change that contract. No username editing exists. |
| `toggleUserActive` | ADMIN Enable/Disable action checks self-disable then named native confirmation, then PATCH. A second clickable status badge directly calls PATCH without this confirmation; consolidate it into the protected flow. |
| `deleteUser` | ADMIN named native confirmation stating irreversible deletion, DELETE /users/{id}, reload. Backend prohibits self-delete; baseline UI did not disable this control. |
| `resetPassword` | POST /users/{id}/password with password only, minimum 8 characters. ADMIN any account; ANALYST/VIEWER own only, enforced by backend. Native prompt supplies new password and OK/Cancel; no separate confirmation or old-password field. No generated credential is returned. |
| Feedback | Shared page error for requests/mutations, create busy flag, reload after success. Other mutations lack busy state. Initial loading and table empty row. No explicit mutation success banner. |
| Self protection | Backend rejects self-disable and self-delete. Own role downgrade and last-admin protection are NOT implemented; preserve actual permissions, do not invent restrictions in UX-11. |
| Timestamp | Users uses en-GB with explicit Europe/Zurich and zone name. Preserve formatter and raw timestamp value. |

### Security Audit

| Capability / callback | Actual contract and safeguards |
| --- | --- |
| Canonical/aliases | /system-information/security-audit; /security-audit and /admin/security-audit server redirect to canonical. No duplicated page implementation. |
| `loadEvents` | GET /auth/me, require ADMIN before GET /security-audit/events. Non-admin clears data and shows forbidden. Backend route and RBAC are ADMIN-only. Initial loading currently invisible until ADMIN response; refresh can retain old data. |
| Metrics | Total matching events, events on page, DENIED/FAILURE count on page, RBAC_DENIED count on page. No severity field. |
| Filters/query | page, limit 25; event_type, outcome, target_type, actor_username, target_id, search, date_from/date_to. Existing fixed option lists retained; each filter resets page 1 and triggers automatic reload. No debounce or manual Apply exists. Reset clears all 8 filters. |
| Dates | Date inputs sent unchanged; backend treats date-only boundaries as UTC day start/end. Audit display uses browser-local en-GB, unlike explicit Zurich Users formatter. Preserve both, expose raw timestamp in details. |
| Table | Eight columns: time, event, outcome, actor/role, target type/name-or-ID, method/path, client IP/user agent, details. Event ID/actor ID and some target/raw values exist in API but not all exposed in baseline table. |
| `expandedId` | One expanded event, toggled by existing detail button. JSON.stringify(details,null,2), null becomes {}; malformed backend JSON serialized as {raw:...}. User agent truncated without full-value mechanism. Preserve details and expose full returned event safely. |
| Pagination | Previous/Next, backend total_pages minimum 1, limit 25; no page-size selector. Backend orders created_at DESC then ID DESC. |
| Outcomes | SUCCESS, FAILURE, DENIED filters. Unknown currently falls through to red; must become neutral. Event families categorical, not severity; use actual outcome for result. |
| Failures | Unauthorized authFetch clears session and redirects; authenticated non-admin forbidden; failed API requests have page error. Do not render raw exception bodies or expose prior audit data after auth failure. No audit mutations exist. |

### Login And Session

| Capability / callback | Actual contract and safeguards |
| --- | --- |
| Form | Standalone /login, no AppShell. Username (not email), password, autocomplete username/current-password, native form Enter submit. Disabled submit for blank trimmed username/password or loggingIn. No remember-me, SSO or recovery. |
| `handleLogin` | POST API_BASE/auth/login, JSON {username,password} without client trimming/transformation. Backend normalizes username;401 invalid credentials,403 disabled account. Successful login updates last_login and writes audit. |
| `setAuthSession` | localStorage token/user/expiry, client cookie, then POST /api/auth/session with token/max_age_seconds. Cookie HTTP-only, SameSite=Lax, path/, Secure in production, max8h. Keep protocol/storage exactly. |
| Redirect | Successful login always window.location.assign('/'), no next parameter. No auto-redirect of an already-authenticated /login user exists. |
| Expiry/invalid | authFetch uses stored expiry with30s skew; expiry or401 clears local storage and cookie, POST /api/auth/logout, then /login?session=expired. Initial absent token also reaches this401 path. Backend checks token AND current database active user/role. |
| Logout | AppNavigation calls clearAuthSession then /login; only local Next cookie cleanup endpoint, no backend logout/revocation endpoint. |
| Errors | Baseline displays backend detail or fetch exception. UX-11 will safely distinguish invalid credentials, disabled account, unavailable backend and expired-session arrival without exposing raw errors. |

## Implementation Boundaries

Reuse existing Enterprise controls, states and modal/confirmation components.
No shared primitive API change is planned. No backend/auth helper, RBAC, cookie,
navigation, CSP, Nginx or Cloudflare edits are planned. Preserve native display-name
prompt; replace password prompt with a masked input dialog retaining explicit submit,
minimum 8 characters and Cancel/Escape. Both status entry points use the same named confirmation.
Backend-only self-delete/self-disable restrictions may be clarified in the UI.

All user mutations and authentication attempts in automated UX tests must use
fixtures/in-memory users. Live smoke uses read-only requests and no real password
reset, deletion, role or activation change. The only approved operational restart
is `ai-soc-frontend.service` after the final production build; validate current HTML,
referenced JS/CSS and the Nginx Host-header path, not just route HTTP status.

## Implementation Decisions

- Users now uses the shared compact header, breadcrumb, section, controls and
  loading/empty/error states. Six table columns and every existing action remain.
  Actions are grouped; deletion is separated by a divider and explicit text.
- A single in-flight mutation guard covers create, PATCH, delete and password
  reset. Successful mutations acknowledge completion and reload the same endpoint.
  Refresh is disabled during mutation; failed mutations remain retryable.
- Both status entry points now open the same named confirmation. Own disable and
  delete are visibly disabled, matching the existing backend restrictions.
  Immediate role selection and the native display-name prompt remain unchanged.
- `UserPasswordDialog` is a page-local flow using `EnterpriseModal`, not a new
  shared component family. It masks input, requires minimum 8 characters, submits explicitly,
  blocks close during submission and clears input on close. Keeping the dialog
  mounted lets the native close operation restore focus on Cancel/Escape.
- Audit retains the dense eight-column table, four original metrics and all eight
  filters with limit 25. Shared metric/section/control/state components replace
  local styling. Unknown event types/outcomes are neutral; no severity is invented.
- Audit filters remain mounted while authorization is rechecked, preserving typing
  focus. Records/metrics are hidden during the check and cleared on failures;
  late responses cannot replace newer filter results. No stale result is presented
  under a newly failed query. Auth failures and forbidden states clear audit data.
- Original details JSON remains expandable. Full returned event JSON additionally
  exposes IDs, raw timestamp and full metadata; long user-agent values have a title.
  Existing timestamp formatters are preserved, with their distinct zones disclosed.
- Login remains standalone with the same username/password transport, storage,
  cookie helpers and redirect. Fields have labels, autocomplete, disabled/busy
  states and associated safe errors. A synchronous submission guard prevents
  duplicates; expired/invalid-session arrivals have a concise notice.
- No shared primitive, auth helper, backend, role, alias, navigation, deployment
  configuration, dependency or lockfile is changed. No UX-12 work is included.

### Files And Shared Components

| File | Reason |
| --- | --- |
| `frontend/src/app/admin/users/page.tsx` | Harmonized admin/self-service controls, states, confirmations and mutation feedback |
| `frontend/src/app/admin/users/UserPasswordDialog.tsx` | Local masked-password flow using existing modal and controls |
| `frontend/src/app/system-information/security-audit/page.tsx` | Dense shared presentation, safe authorization states and complete raw metadata |
| `frontend/src/app/login/page.tsx` | Standalone shared form styling, safe errors and submission states |
| `scripts/validate_ux11_browser.cjs` | Fail-closed browser fixtures; responsive, role, mutation and session checks |
| `scripts/validate_ux11_runtime.py` | Production/Nginx routes, current assets versus disk, and local cookie-handler checks |
| `tests/test_ux_governance_auth.py` | Real router/auth contracts against isolated SQLite users/audit data; alias source checks |
| `docs/validation/ux-11-governance-auth.md` | Pre-flight inventory, implementation, evidence and user verification package |
| `docs/validation/README.md` | Validation report index |

Reused: AppShell, EnterprisePageHeader, EnterpriseBreadcrumbs,
EnterpriseMetricStrip, EnterpriseMetricCard, EnterpriseSection, EnterpriseButton,
EnterpriseBadge, EnterpriseSelect, EnterpriseSearchInput,
EnterpriseConfirmationDialog, EnterpriseModal, EnterpriseSkeleton,
EnterpriseEmptyState, EnterpriseErrorState, `SOC_CONTROL_CLASSES`,
`SOC_TONE_CLASSES` and `statusTone`. No shared component was modified, so no other
consumer requires a compatibility migration. The UX-11 local password form is
the only new UI component. Previously approved page sources remain untouched.

## Functional Regression Matrix

Evidence: B = isolated browser fixture, P = real Python router with in-memory DB,
R = source/contract review. Runtime evidence is recorded separately below.

| Area | Before | After | Evidence |
| --- | --- | --- | --- |
| Users route/list | ADMIN all, other roles own; auth check first | Same endpoints, role ownership and six columns | PASS B P |
| Identity | Username/display name/role/active/last login | Same fields; current account labeled You | PASS B P R |
| Create | ADMIN, password minimum 8 characters, default ANALYST, five-field body | Same constraints/payload/reset; Enter and busy state | PASS B P |
| Display name | Native prompt, trimmed string or null PATCH | Same prompt, Cancel and payload; null still ignored backend-side | PASS B P |
| Role | ADMIN immediate single-role PATCH | Same roles/payload/authorization, no new restriction | PASS B P |
| Active state | Named confirm via action; badge skipped confirmation | Both entry points confirm named target, same PATCH | PASS B P |
| Password reset | ADMIN any; other roles own; password-only POST | Same contract; masked input, minimum 8 characters, explicit submit, safe feedback | PASS B P |
| Delete | Named irreversible confirmation, ADMIN DELETE | Shared named confirmation, same DELETE and reload | PASS B P |
| Self protections | Backend disallows self-disable/delete | Backend unchanged; corresponding controls disabled | PASS B P |
| Self-role downgrade | Allowed, database role governs subsequent requests | Still allowed; admin controls removed after reload | PASS B P |
| Cancellation | Native prompts/confirmations execute nothing on cancel | Display prompt unchanged; modal Cancel/Escape send nothing | PASS B |
| Mutation failure | Shared error; limited busy handling | Safe errors, busy guard, no credential echo, retry/cancel retained | PASS B P |
| Users states | Loading, empty and request failure | Shared skeleton/empty/error, same refresh | PASS B |
| Users time | Explicit Europe/Zurich, en-GB | Same formatter and raw timestamp title | PASS B R |
| Audit authorization | ADMIN only, non-admin forbidden | Same backend rule; no record visible during access check | PASS B P |
| Audit metrics | Matching total/page count/failed-denied/RBAC-denied | Same four calculations and scope; unavailable is not zero | PASS B R |
| Audit query | Eight filters, page 1 on change, limit 25 | Same query keys and fixed options; focus retained while typing | PASS B P |
| Audit dates | Date strings; inclusive UTC boundaries backend-side | Same inputs, boundaries and browser-local display formatter | PASS B P R |
| Audit pagination | Previous/Next, total pages minimum1 | Same order, bounds and limit | PASS B P |
| Audit result semantics | Actual outcome; unknown default red | Actual SUCCESS/FAILURE/DENIED; unknown neutral, no severity | PASS B P R |
| Audit raw data | Details JSON, malformed data becomes raw wrapper | Same details plus complete returned record, no discarded IDs | PASS B P |
| Audit refresh/states | Refresh, loading/no result/failure | Shared states; failed/new authorization cannot leave stale data | PASS B |
| Audit aliases | Two server redirects to canonical | Alias sources untouched, both resolve canonical | PASS B R |
| Login submit | Native Enter, username/password POST, blank guard | Same transport, labels and autocomplete; duplicate guard | PASS B P |
| Login failures | 401 invalid,403 disabled, other request error | Safe distinct invalid/disabled/unavailable/connection messages | PASS B P |
| Session creation | setAuthSession, token/user/expiry storage, local cookie POST | Helpers and protocol unchanged | PASS B R; runtime cookie checks |
| Session expiry/logout | Clear storage/cookie, existing redirects | Helpers unchanged; session-unavailable notice added | PASS B P R; runtime cookie checks |

## Explicit RBAC Matrix

Values verified against real router dependencies and isolated browser roles.
No live account was mutated. Backend checks remain authoritative.

| Capability | ADMIN | ANALYST | VIEWER |
| --- | --- | --- | --- |
| Users route | All users | Own record | Own record |
| Create user | Yes | No | No |
| Display name / role edit | Any user, including own | No | No |
| Enable / disable | Other users; cannot disable self | No | No |
| Delete | Other users; cannot delete self | No | No |
| Password reset | Any user, including own | Own only | Own only |
| Security Audit / aliases | Read/filter/raw details | Forbidden, no events request | Forbidden, no events request |
| Login | Valid active account | Valid active account | Valid active account |
| Expired/invalid token |401, existing session cleanup/redirect | Same | Same |
| Logout | Existing local session cleanup | Same | Same |

Unauthenticated Users/Audit: the existing401 handler redirects to
`/login?session=expired`; it is not a new server-side HTML gate. Login itself is
public. A disabled account cannot log in, and an existing token cannot authenticate
an inactive/deleted user. Tests verify that a stale ADMIN claim does not override
the current database role.

## Automated Validation

- `npm --prefix frontend run lint`: PASS.
- `npm --prefix frontend run build`: PASS, including TypeScript and 27 generated
  static pages. Final production build on 2026-09-10; no frontend source edit after it.
- TypeScript no-emit: PASS before and after final build; build also validates types.
- Focused Python: 158 PASS; three warnings from existing dependencies
  (Starlette/httpx test-client deprecation and two SWIG import deprecations).
- `./ai-soc docs-validate`: 27/27 PASS. Documentation structure: PASS.
- `git diff --check`: PASS.
- `node --check scripts/validate_ux11_browser.cjs`: PASS.
- Python compilation of runtime runner/new tests: PASS.
- Browser: initial dev suite 34 groups PASS; extended suite 37 groups PASS on
  production port 3000 and 37 groups PASS through Nginx port 8088.
- No frontend test package/script exists beyond lint/build. Existing cached
  Playwright and pytest were reused; no dependency or system package was installed.

### Browser Evidence

- 390, 1440, 1920px: Login, Users and Audit, plus masked-password dialog and
  expanded full Audit JSON at each width. No horizontal page overflow or control
  overlap; table scrolling remains internal. Screenshots visually inspected.
- ADMIN/ANALYST/VIEWER listing, forbidden controls, own password reset and Audit
  access. ADMIN-only operations assert exact endpoint/method/body and result.
- Named status/delete confirmations, Cancel/Escape without requests, password
  minimum length/masking, busy controls, failure without secret echo, clean reopen
  and focus return on cancellation. Current-account guards and fixture-only
  self-role downgrade checked; real backend rejects cross-user non-admin reset.
- Audit all eight filters/reset, page bounds, raw JSON/IDs/timestamp/user agent,
  unknown neutral result, keyboard focus while typing, delayed authorization and
  role revocation without stale records. Empty,503,403 and loading on both pages.
- Login blank/keyboard submission,401/403/503/network failures, duplicate-submit
  guard, exact original credential payload, token/user/expiry storage, real local
  session cookie, redirect and logout cleanup. Anonymous/expired/invalid sessions
  on both protected pages reach the existing expired-session login URL.
- Both audit aliases resolve to the single canonical page. No unexpected console
  or page errors. Deliberately failed fixture HTTP requests are identified separately.
- Test harness accounts for concurrent redirects from the existing navigation and
  page authorization checks by asserting the final login UI/URL, rather than
  waiting for an intermediate navigation that another401 handler may cancel.

Evidence directories (not committed): `/home/lele/.cache/ux11-browser/evidence`,
`/home/lele/.cache/ux11-browser/production` and
`/home/lele/.cache/ux11-browser/nginx`.

Python command:

```bash
.venv/bin/python -m pytest -q \
  tests/test_ux_governance_auth.py \
  tests/test_auth_router_refactor.py \
  tests/test_users_router_refactor.py \
  tests/test_security_audit_router_refactor.py \
  tests/test_security_refactor_helpers.py \
  tests/test_api_route_inventory.py \
  tests/test_ux_detection_operations_rbac.py
```

Browser runner requires the existing Playwright/Chromium cache, not new packages:

```bash
UX_BROWSER_MODULE=/home/lele/.npm/_npx/e41f203b7505f1fb/node_modules/playwright \
UX_BROWSER_EXECUTABLE=/home/lele/.cache/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell \
LD_LIBRARY_PATH=/home/lele/.cache/ux10-browser/libs/usr/lib/x86_64-linux-gnu \
UX_BROWSER_OUTPUT=/home/lele/.cache/ux11-browser/evidence \
node scripts/validate_ux11_browser.cjs
```

Default origin is the isolated dev frontend at port 3001. All backend requests are
intercepted, including unknown mutations; external requests fail closed. Only local
Next cookie-only handlers run without interception, with dummy fixture tokens.
Expected failed-resource browser diagnostics are accepted only for intentionally
failed fixture URLs; all other console/page errors fail validation. Measurements
exclude the Next dev diagnostic overlay, not application controls. Screenshots and
results stay outside git. Browser fixtures are not a substitute for a real IdP,
Cloudflare Access session or live production-account mutation test.

## Runtime And Asset Consistency

Final build ID: `s7cM2NiY_op5KficA4wYz`.

`sudo -n systemctl restart ai-soc-frontend.service`: PASS on 2026-09-10 at
11:36:43 CEST. Frontend MainPID changed from 3155 to 31202; read-only
`systemctl is-active ai-soc-frontend.service` returned `active`. The sudo rule
permits restart but not passwordless status, so status was read without sudo.
API PID 3150 and worker PID 3153, both started at 10:56:45 CEST, were unchanged.
No other service was restarted; no Nginx/Cloudflare configuration was modified.

Systemd briefly reported active before the frontend socket was ready. The runtime
runner now waits up to 15 seconds for that socket and then requires every check
to pass without ignoring asset/HTTP failures.

| Route |3000 GET/HEAD |8088 GET/HEAD, Host soc.varqon.net |
| --- | --- | --- |
| /login |200 PASS |200 PASS |
| /admin/users |200 PASS |200 PASS |
| /system-information/security-audit |200 PASS |200 PASS |
| /security-audit |307 to canonical PASS |307 to canonical PASS |
| /admin/security-audit |307 to canonical PASS |307 to canonical PASS |

All 14 distinct current HTML-referenced assets (11 JS chunks, 1 CSS, 2 fonts)
returned 200 on BOTH paths and had SHA-256 equal to the corresponding on-disk
`.next` file. Asset names were extracted from current HTML, never taken from an
old build. Example current JS: `/_next/static/chunks/08ttfj81-47mu.js`;
CSS: `/_next/static/chunks/1nstzmp4ygnvw.css`. The restarted process, served pages
and static files are synchronized.

Local Next session/logout handlers passed on BOTH paths with dummy tokens:
missing-token 400, HttpOnly/Secure/SameSite=Lax/path=/, 8-hour max-age cap and
logout max-age 0. These handlers do not authenticate or mutate backend users.

Non-destructive authenticated live reads also passed on 8008 and through 8088:
GET `/auth/me`, `/users`, `/security-audit/events?limit=25&page=1`, all 200 with
expected JSON shape. A 60-second local ADMIN token was held only in process
memory; no credentials, live payloads or tokens were printed or saved, and no
login attempt or account/audit mutation was performed in this smoke.

Reproduce route/assets/cookie validation only against the synchronized build:

```bash
.venv/bin/python scripts/validate_ux11_runtime.py
```

Browser production reruns use the same command above with
`UX_BASE_URL=http://127.0.0.1:3000` or `UX_BASE_URL=http://127.0.0.1:8088`
and a separate output directory. Backend traffic remains fixture-intercepted.
Public Cloudflare Access authentication is left to the user's normal login flow.

## Manual User Verification

Use the normal Cloudflare Access flow for `https://soc.varqon.net`. Mutations below
must use disposable test accounts, never operational users or the active ADMIN.

### Login

1. Open `/login`: verify compact Sovereign AI SOC identity, visible Username and Password labels and no authenticated sidebar.
2. Tab through both inputs and Sign in; check visible focus. Blank fields must not submit. Enter must submit once.
3. Submit invalid fixture credentials; verify safe failure. Use interception for503/connection failure and verify it is not described as invalid credentials.
4. Sign in normally with an authorized account; verify redirect to `/`, normal navigation and persisted session on reload.
5. Log out using the existing sidebar action; verify `/login` and session cleanup. In an isolated browser, test an expired/invalid token and the session-unavailable notice.
6. Repeat at390px and with a short viewport/onscreen keyboard; the form must remain reachable without horizontal page scrolling.

### Users: ADMIN

1. Open `/admin/users`; inspect compact header/breadcrumb, ADMIN identity, timezone and the six-column list. No search/filter existed in this page.
2. Check the current-user You marker and disabled own Delete/Disable/status controls. Do not test self-role downgrade on a real administrator.
3. Create a disposable user: verify minimum 8 password characters, default ANALYST, optional display name, Enter/submit, single request and success/form reset.
4. Edit its display name; first cancel, then submit. Check existing trim/null behavior. Select another role on the disposable row and verify immediate update.
5. Open both status entry points; verify the named target. Cancel and Escape must do nothing. On a disposable account only, confirm Disable and then Enable.
6. Open Reset password; check masked input, minimum 8 characters, keyboard focus and clear input on reopening. Cancel/Escape must not submit. Use an isolated user only to confirm once and check safe success/failure without credential echo.
7. Open Delete for the disposable account; verify target/consequence and cancel using both Cancel and Escape. Confirm only for that test account.
8. Refresh; inspect loading, empty and503/403 fixture states. At390px, forms stack and only the table scrolls horizontally; actions remain separate and reachable.

### Users: ANALYST And VIEWER

1. Use each role in turn and navigate directly to `/admin/users`.
2. Verify User Profile, only the current record, role/status read-only and own Reset password available.
3. Confirm Create/Edit/role/status/Delete controls are absent. In isolated tests, a password request for another user must receive403.
4. Cancel own password reset; test successful reset only on a disposable account. Never reset a real user's password solely for UX verification.

### Security Audit

1. As ADMIN, open `/system-information/security-audit`; inspect four metrics, compact filters and the dense eight-column table.
2. Refresh. Exercise Event type, Outcome, Target type, Actor, Target ID, Date from, Date to and Search; each resets page 1. Reset clears all eight.
3. Type continuously in Search/Actor while data reloads; focus must stay in the input. Check Previous/Next where sufficient data exists.
4. Inspect event ID, actor/role, target, outcome, request and client. Open details JSON, then Full event / raw metadata; verify full IDs, user agent and original timestamp.
5. Verify Audit remains browser-local time and Users Europe/Zurich; date-only query boundaries remain UTC. Unknown outcomes must be neutral, not invented severity.
6. Use no-result, delayed,503 and403 fixtures. No old audit record should appear while access is checked or after denial.
7. Navigate directly as ANALYST/VIEWER: forbidden, no event request/content. Without a valid session, verify the existing login redirect.
8. Open `/security-audit` and `/admin/security-audit`; both must reach the single canonical page.
9. Repeat at390,1440 and1920px; filters wrap, the table scrolls internally, details remain accessible and there is no page overflow.

## Residual Risk And Scope Limits

- Self-role downgrade and last-admin protection do not exist in the backend;
  UX-11 deliberately does not invent new RBAC. Treat real role changes as governed.
- Backend ignores null display names; clearing a name is not newly implemented.
- Token storage, JS cookie handoff, expiry skew and the lack of server-side token
  revocation on password change/logout are existing contracts, not changed here.
- Users and Audit have different existing timezone semantics, preserved explicitly.
- Native display-name prompt remains browser-dependent. Automated Chromium checks
  do not replace Safari/Firefox, screen-reader or actual mobile-keyboard verification.
- No shared primitive changed; no broad redesign or new mutation was applied to
  previously approved pages. UX-12 and the final product accessibility pass remain
  out of scope. The separate Executive sizing fix `02fd540` is not included because
  the user required this branch to start exactly at `56fc3f8`.
- Cloudflare Access is not bypassed; public authenticated verification remains
  for the user. No destructive action was exercised on a live account.
