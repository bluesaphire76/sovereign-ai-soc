# UX-12: Responsive, Accessibility And Final Regression

Status: implementation and local validation completed on 2026-09-12.
Public-path and release-readiness approval remain pending.
No release, merge or tag is authorized. The route inventory below was recorded
before application edits.

Branch: `feature/ux-harmonization-12-responsive-accessibility-regression`.
HEAD at branch creation equals approved UX-11 `5bab7eb7b9b5c5c463460d12c9f43ef692e467a3`;
its parent is `56fc3f843c1380f0ba9f5756241a0c83a7ba0671`. Worktree was clean.

## Protected Route Inventory

Source: all `frontend/src/app/**/page.tsx` and `route.ts` files, existing production
`app-paths-manifest.json`, navigation model, auth helpers, backend `security/rbac.py`
and page callbacks. There are **26 authored application routes**: 24 pages
(20 content pages, including two entity-detail patterns; four aliases) and two
local cookie handlers. The manifest has 29 entries including favicon and two
framework error entries. The build's 27 static-generation count is not a count
of application pages. Reconcile with the final build without adding routes.

All authenticated page HTML is client-rendered/publicly retrievable: absence or
expiry of authentication leads through the existing API 401 handler to
`/login?session=expired`. The API remains authoritative; HTML 200 is not evidence
of permission. In the table A=ADMIN, O=ADMIN/ANALYST, *=all three authenticated roles.
AppShell/navigation applies to every content page except Login. Common shared
header, badges, sections/panels and states are denoted Enterprise.

| Route | Category/archetype | Access and operations | Main components | Responsive / accessibility risk | Smoke strategy |
| --- | --- | --- | --- | --- | --- |
| /login | Public/authentication, compact form | Public; login POST, local session handoff | EnterpriseButton, ErrorState; no shell | Input labels, busy/Enter, focus, short viewport | Fixture credentials, real local cookie-only handlers |
| / | Overview, operational dashboard | * read, charts/filter/paging | Enterprise header/metrics/charts/sections | Charts and wide tables, headings, contrast | Read-only snapshot at five widths |
| /executive | Overview, lower-density summary | * read | Enterprise header/metric strip/sections | Six oversized pulse cards vs Incidents; charts | Snapshot; compare compact metric geometry |
| /health | Operations, monitoring | * read; existing polling | Enterprise header/metrics/panels | Dense runtime metadata, external links | Snapshot, bounded request-count check |
| /detection-quality | Detection, analytical/operational | * read and guidance; O synthetic execution/semantic context | Enterprise header/sections/select/states | Tables, filters, governed run controls | Snapshot; fixture-only action checks |
| /incidents | Investigation, queue | * read; O demo deletion | Enterprise dense shell/header/table/metrics/modal | Wide queue/actions, accessible sorting/filters | Snapshot plus governed fixture checks |
| /incidents/[id] | Dynamic investigation detail | * read; O status/notes/case creation/generation/execution; A proposal approvals | Enterprise header/tabs/sections, Assistant, local workflows | Dense header, notes, tabs, nested workflow forms | Safe existing ID for read-only snapshot; fixture mutations only |
| /cases | Investigation, queue | * read; O demo deletion | Enterprise header/metrics/panels/confirmation | Table and action reachability | Snapshot and cancel-only fixture |
| /cases/[id] | Dynamic investigation detail | * read; O workflow/closure/actions/generation | Enterprise header/sections, Assistant, local dialogs | Closure validations, tabs, dialog fit/focus | Safe existing ID snapshot; fixture-only workflow tests |
| /cases/kanban | Investigation, board | * read; existing card links/filters, no invented drag mutation | Enterprise header and board columns | Internal board scroll, keyboard card links | Snapshot, keyboard links, contained scrolling |
| /assistant | AI, grounded workspace | O capabilities/query; VIEWER forbidden | AssistantWorkspace inside dense shell | Input names, source links, proof/fallback text, cancellation | Capability snapshot and isolated query fixtures |
| /settings/detection-control | Detection, control plane | * read; O drafts/validate/preview; A apply/rollback/restart/rule admin | Enterprise sections/modal, Lifecycle/Operations/Service panels | Dense forms, required reason/preview/confirm, tables | UX-10 fail-closed fixtures plus five-width audit |
| /network-events | Operations/telemetry, table | * read/filter | Enterprise header/metrics/panels/filters | Wide technical values and table | Read-only snapshot and UX-10 fixtures |
| /dns-telemetry | Operations/telemetry, table | * read/filter | Enterprise header/metrics/panels/filters | Names/IPs, contained table overflow | Read-only snapshot and UX-10 fixtures |
| /system-information/operation-history | Operations, history table | * read/filter/paging | Enterprise header/metrics/panels/states | Filters, pagination, long results | Snapshot and UX-10 fixtures |
| /admin/users | Administration, admin/self-service | * own record/password; A all users/create/edit/role/reset/delete; no self-disable/delete | Enterprise header/sections/controls/confirmation; local password dialog | Wide actions, masked input, deliberate confirmation | UX-11 role/payload/focus fixtures plus snapshots |
| /system-information/security-audit | Governance, forensic table | A only; non-admin blocked before event request | Enterprise metrics/filter/section/states | Raw JSON, dates, permissions and old snapshots | UX-11 fixtures; snapshot five widths |
| /settings/ai-providers | Governance, registry/settings | * read; A config/test | Enterprise sections/panel, existing native form controls | Unlabeled legacy inputs, dense provider registry | Read-only snapshot; no live test/config POST |
| /settings/ai-data-control | Governance, policy workbench | * read; O previews; A policy edits | Existing workbench and native controls | Dense grid, labels, policy text truncation | Snapshot; previews only in fixtures |
| /settings/semantic-memory | Governance, memory operations | O read/search; A backfill/cleanup | Wide shell, existing panels/forms | Technical table, search labels, governed cleanup | Snapshot; no live backfill/cleanup |
| /security-audit | Alias | Server redirect to canonical Audit; destination A | No duplicate UI | Redirect/auth integrity | GET/HEAD307, canonical role tests |
| /admin/security-audit | Alias | Same Audit redirect | No duplicate UI | Same | GET/HEAD307 |
| /operation-history | Alias | Server redirect to canonical Operation History; destination * | No duplicate UI | Redirect/auth integrity | GET/HEAD307 |
| /admin/operation-history | Alias | Same Operation History redirect | No duplicate UI | Same | GET/HEAD307 |
| /api/auth/session | Local cookie handler | POST token/max_age; no backend authentication | NextResponse cookie helper | HttpOnly/Secure/Lax, unchanged transport | Dummy-token handler contract, no real credential |
| /api/auth/logout | Local cookie handler | POST clears cookie | NextResponse cookie helper | Cleanup unchanged | Dummy-token expiry test |
| /favicon.ico | Static asset | Public | Existing icon | Asset integrity |200 and content |
| /_not-found | Framework error |404 | Next default error | Framework title/semantics | Unknown route404 |
| /_global-error | Framework boundary entry | Internal, not navigation | Next default boundary | Not a product page | Build presence; no manufactured live error |

## Pre-flight Findings And Boundaries

- `02fd540ebe439a46a1f22d72c33fca60de26fe71` changes only ExecutivePulseBar and
  its static test: remove icons and `compact={false}` from its six existing
  metrics, using the same default compact component as Incidents. Those overrides
  are still present at this base. Apply the minimal equivalent, not a cherry-pick;
  preserve all values, labels, tones and datasets.
- Existing shared Modal uses native `showModal`/`close`, blocks cancel while busy,
  but lacks an explicit short-viewport height limit and unmount cleanup. Inspect
  every consumer before any shared correction. Tooltip is hover/focus CSS-only.
- Global CSS has no reduced-motion override. Shared muted text and legacy
  slate500/600 metadata need measured contrast review, not indiscriminate brightening.
- Native role checks and exact API/body/state contracts remain protected. Do not
  add last-admin or self-demotion business logic: UX-11 in-memory tests prove
  self-demotion is allowed, while self-delete/self-disable are rejected. Classify
  as a pre-existing governance release risk and recommend a separate decision.
- Observability remains external and O only. Navigation groups remain Overview,
  Investigation, Detection, Operations / Telemetry, Governance and AI.
- No new dependencies: cached Chromium/Playwright and installed `axe-core` are
  available. Check Firefox availability; do not claim Safari or screen-reader coverage.
- All mutation tests must fail closed into fixtures. Any live reads are local,
  read-only, with existing entity IDs; private snapshots stay outside git.
- Final build MUST be followed by restart of only ai-soc-frontend.service, then
  current HTML/JS/CSS/font hash comparison on3000 and8088 Host soc.varqon.net.
- Public Cloudflare Access validation needs the user's normal authenticated
  session. Requested separately; never bypass or infer its completion from Nginx.

## Changes And Shared Consumers

No backend, RBAC, route, request body, domain state, dependency or polling interval
was changed. No duplicate primitive family or unused abstraction was added.

| File / component | Measured issue and correction | Consumer regression |
| --- | --- | --- |
| `frontend/src/app/globals.css` | Legacy slate500/600 metadata failed contrast on dark backgrounds; map only those foreground classes to existing `--soc-text-subtle`. Add visible native focus outlines and reduced-motion overrides. No background/palette redesign. | All 20 content routes, five widths; Assistant generation/motion; existing UX-10/11 workflows |
| `AppShell.tsx` | Separate primary navigation from the main landmark; one focusable `main` and a skip link. | All 19 authenticated content routes; keyboard skip and navigation |
| `AppNavigation.tsx` | Group headings retain their labels/order but use groups rather than duplicate region landmarks. Escape closes mobile navigation and restores toggle focus. | All authenticated routes; three roles, five widths, active state and keyboard route transition |
| `EnterprisePageHeader.tsx` | Case #2's long correlation-type word caused 42px overflow at 390px; constrain and wrap the existing H1. | Dashboard, Executive, Incident list/detail, Case list/detail/Kanban, Assistant, Health, Detection Quality, Control Plane, Network, DNS, Operation History, Users, Audit, AI Providers |
| `EnterpriseButton.tsx` | Executive white-on-violet500 measured 4.4:1; darker violet600/700 normal/hover treatment. | Executive links and shared controls across all consumers; existing handlers untouched |
| `EnterpriseModal.tsx` | Short-viewport height/scroll bound. Layout-effect cleanup closes native dialogs before removal, restoring opener focus on service-dialog unmount. | Users/password and confirmations; Case demo deletion consumer; Control Plane archive, Lifecycle deletion and Service restart; busy/Escape/Cancel gates |
| Executive page | Minimal equivalent of excluded `02fd540`: six pulse cards now use default compact metrics with no icons or `compact={false}`. Exposure table receives a named keyboard scroll region. | All five widths; compare all six heights against actual Incident compact metric height, not a hard-coded pixel assumption |
| Incidents page; `OperationsPanel.tsx` | Inspector asides nested inside main become named sections; no layout/action changes. | Queue inspection and all UX-10 operation workflows |
| Detection Quality, Network, DNS, Operation History pages | Named focusable scroll containers for non-interactive tables. Rows are not made tabbable. | Narrow/wide tables, keyboard horizontal scrolling, existing filters/paging |
| AI Data Control page | Explicit visible preview-payload label and named focusable policy-decision scroll region. | Read-only snapshot and control geometry; no live policy edits |
| Semantic Memory page | Visible labels for search query/source type; align the unchanged native controls. | Read-only snapshot; no live cleanup or backfill |
| `tests/test_ux_overview_pages_static.py` | Compact Executive regression from the excluded fix, reapplied minimally. | Static contract test |
| `tests/test_ux_governance_auth.py` | Extend existing isolated last-user test to assert zero active ADMINs after self-demotion and denial of self-restoration. | Real routers, in-memory SQLite; no production account changes |
| `tests/test_ux_final_regression.py` | 140 cross-product role assertions plus shared accessibility guards. | Actual backend authorization function, not an invented permission matrix |
| `scripts/validate_ux12_browser.cjs` | Read-only local capture; strict offline replay, geometry, axe and screenshots. | 20 content routes x five widths |
| `scripts/validate_ux12_interactions.cjs` | Keyboard, role visibility, short dialogs, investigation, AI and polling fixtures. | Isolated backend traffic, fail closed on unknown requests |
| `scripts/validate_ux12_runtime.py` | Actual build manifest, route/alias and current asset hash gate; reuses UX-11 HTTP/parser helpers. | Both Next and Nginx paths |
| This report, validation index and `docs/ux-harmonization/v0.9.0-summary.md` | Final inventories, evidence, history reconciliation and release decisions. | Both documentation validators |

Shared inventory also inspected: Badge/SeverityBadge/StatusBadge, metrics, sections,
panels, SearchInput, Select, states, confirmation and Tooltip. Existing compatibility
wrappers and Case density/read-only CSS were retained: this phase is not a cleanup
or redesign. Tooltip remains the existing CSS hover/focus primitive; see residual
findings below. Global/contextual Assistant, Incident and Case logic is unchanged.

## Responsive And Accessibility Evidence

Read-only capture used existing Incident **5358** and Case **2**, not manufactured
production entities. No production mutation or model generation was executed.
Private snapshots and screenshots are outside git under
`/home/lele/.cache/ux12-browser/` (private directory/files); they can contain real
operational data and must not be published as release artifacts.

Baseline: 20 pages at 1440px, one H1 each, no runtime errors, but 2,097 axe
contrast-node findings across metadata and the Executive button. Foreground
slate500 on the observed dark surfaces measured approximately 3.69-4.23:1 and
slate600 approximately 2.35-2.65:1. Local fixes use the existing semantic token;
no wholesale brightening or new color semantics was introduced.

The first five-width pass identified the Case mobile title overflow and four
additional keyboard-inaccessible scroll containers; both were corrected. Geometry
checks exclude closed disclosures and intersect controls with actual overflow
clipping ancestors, so hidden table cells are not misreported as collisions.

| Final matrix | 390 | 768 | 1024 | 1440 | 1920 |
| --- | --- | --- | --- | --- | --- |
| All 20 content pages | 20/20 pass | 20/20 pass | 20/20 pass | 20/20 pass | 20/20 pass |
| Navigation/skip/metric comparison | Pass | Pass | Pass | Pass | Pass |
| Service modal at 420px height | Pass | Pass | Pass | Pass | Pass |

The strict browser gate checks one meaningful H1, page overflow <=1px, visible
control collisions, completion of initial loading, unknown requests, console/page
errors and axe violations. Final production replay: **100/100 pass**, zero page
overflow, control collisions, unexpected requests, JavaScript errors or axe
violations. Axe tags: WCAG2A, WCAG2AA, WCAG21AA and best-practice;
this is **not WCAG certification**. Incomplete results require human judgment:
970 `aria-prohibited-attr` and 2,929 `color-contrast` node findings, not unique
elements (repeated across widths). These are not silently counted as passes.
Native dense tables/boards keep internal scrolling. No controls, columns, workflow
steps or source values were removed for responsive reasons.

| Accessibility area | Evidence / outcome |
| --- | --- |
| Landmarks/headings | One H1 on each route; navigation separate from main; duplicate Investigation region removed; inspector landmarks corrected. Existing chart/section hierarchy inspected. |
| Names/forms | Axe label checks, explicit added labels, existing Login/Users validation and masked passwords, icon `aria-label`s; no backend validation change. |
| Focus/navigation | Tab/Shift+Tab, Enter/Space, Escape; skip link focuses main, menu expanded state and focus restoration, active link and route transition. |
| Dialogs | Native modal focus containment, initial focus and return; 420px-height bounds; Cancel causes zero mutation. Existing UX-10/11 tests cover reason/preview/confirmation invalidation and busy cancellation lock. |
| Tables/filters | Headers remain native table semantics. Five named horizontal scroll regions plus policy-decision vertical region; no focusable inert rows. UX-10/11 filter reset, pagination and raw detail tests retained. |
| Severity/status | Canonical helper/static tests preserve CRITICAL red, HIGH orange, MEDIUM amber, LOW blue and unknown neutral; textual labels remain. Health success/healthy green, degraded amber, failure red, unavailable neutral. No backend values changed. |
| AI | Global/Incident/Case model and deterministic-fallback fixtures: generated/proof/grounding labels, visible limitations, keyboard source focus/link, expandable technical details, cancellation and no late answer insertion. Six answer-specific axe audits. |
| Loading/motion | Existing live/status indicators retained; reduced-motion generation checks, skeleton/spinner shared CSS; no invented progress percentage. |
| Errors/access | Existing UX-10/11 loading, empty, 403, 503, session expiry/anonymous and validation cases; failed Case closure remains an error, not empty success. |
| Charts | Existing titles, labels, legends and surrounding metrics retained; overview screenshots and narrow-width chart geometry inspected. No library/dataset rewrite or performance claim. |

## Keyboard And Functional Browser Regression

- UX-12 interaction script: **29/29 production groups passed**. Covers five-width
  navigation and metric comparison, three-role navigation visibility, five
  short-height service dialogs, three-role Incident/Case workflows, Kanban links,
  two Case demo confirmation focus/Cancel/Escape checks,
  six AI generated/fallback answers, three cancellation/motion cases and Health
  polling across a 32-second observation window.
- UX-10 script: **33/33 fixture groups passed on development and production**.
  Covers all four operational routes, lifecycle states and three roles,
  apply/rollback prompt and confirmation cancellation, archive/delete cancellation,
  restart reason/preview/confirm, invalidated preview, failed restart, filters,
  pagination, empty/error/forbidden/loading.
- UX-11 script: **37/37 fixture groups passed on development and production**.
  Covers Users/Audit/Login, all three roles, password masking/validation/focus,
  payloads, busy/duplicate submission protection, logout and cookie cleanup,
  raw metadata, aliases, auth failures and stale access recheck.
- No fixture request can fall through to a real backend mutation. Unknown API
  requests fail the suite. Local Next session/logout handlers only receive dummy
  tokens in UX-11 tests, and do not authenticate to or mutate the backend.

## Final RBAC Matrix

Verified against `security/rbac.py`, 140 new parametrized assertions, retained
UX-09/10/11 router/contract suites and browser controls. A role check at the route
layer is not the whole permission contract: routers still enforce entity state,
ownership, validation and approval. Observability visibility is frontend-only;
its external service authenticates separately.

| Area / operation | ADMIN | ANALYST | VIEWER |
| --- | --- | --- | --- |
| Incident read / timeline / evidence | Read | Read | Read |
| Incident lifecycle, notes, case link, approved-action execution | Operate, subject to existing gates | Operate, subject to existing gates | Denied |
| Remediation proposal approval/rejection | Allowed | Denied | Denied |
| Case read / reports / Kanban | Read | Read | Read |
| Case workflow, action plan, closure, generation | Operate; closure gates authoritative | Operate; closure gates authoritative | Denied |
| Assistant capabilities/query, all scopes | Allowed | Allowed | Denied |
| Overview / Health / Detection Quality read | Read | Read | Read |
| Detection Quality guidance | Allowed | Allowed | Allowed |
| Synthetic scenarios/run and semantic context | Allowed | Allowed | Denied |
| Detection Control read | Read | Read | Read |
| Config validate/diff, lifecycle draft/submit, operation preview/review | Allowed | Allowed | Denied |
| Config apply/rollback, lifecycle approve/apply, managed rule administration | Allowed | Denied | Denied |
| Service restart preview / restart | Both | Preview only | Neither |
| Observability external navigation | Visible | Visible | Hidden |
| Network / DNS / Operation History | Read | Read | Read |
| Semantic Memory read/search | Allowed | Allowed | Denied |
| Semantic Memory backfill/retention | Allowed | Denied | Denied |
| AI Providers read / configuration | Both | Read only | Read only |
| AI Data Control read / previews / policy edits | All | Read and preview | Read only |
| Users listing | All accounts | Own only | Own only |
| Users create/edit/role/status/delete | Allowed, existing self-delete/disable guards | Denied | Denied |
| Password update | Own or other account | Own only | Own only |
| Security Audit | Read | Denied | Denied |
| Unknown role or unclassified protected API | Denied | Denied | Denied |

### Known Governance Limitation

**HIGH; recommended tag blocker pending a separate fix or explicit risk acceptance
with a tested recovery procedure.** No governance business logic was changed.

The isolated real-router test begins with exactly one ADMIN. Self-delete and
self-disable return 400. Self-demotion to VIEWER succeeds (200), leaves **zero
active ADMINs**, and the same token immediately receives VIEWER privileges:
`/auth/me` returns VIEWER, Audit returns 403 and attempting to restore ADMIN via
`PATCH /users/1` returns 403. There is no explicit last-ADMIN guard. Thus current
guards do not prevent administrative lockout; stale token claims do not bypass
the database role. This predates v0.9.0. Never test it on the production account.

## Automated Checks

| Check | Result |
| --- | --- |
| `npm --prefix frontend run lint` | PASS, no warnings |
| `./node_modules/.bin/tsc --noEmit` from frontend | PASS, separate TypeScript check |
| `npm --prefix frontend run build` | PASS, Next 16.3.0; 27 generated entries, unchanged 29-entry manifest |
| `git diff --check` | PASS |
| `./ai-soc docs-validate` | PASS, 27/27 checks |
| `.venv/bin/python scripts/validate_docs_structure.py` | PASS |
| Focused UX Python suites | 288 passed, 3 dependency warnings |
| Full baseline pytest, before app edits | 1,386 passed, 4 failed, 0 skipped, 106 warnings, 26 subtests passed |
| Full final pytest | **1,528 passed, 4 failed, 0 skipped, 106 warnings, 26 subtests passed**; 192.24s |
| Model routing in isolated explicit default-token environment | 27 passed with `AI_SOC_ASSISTANT_MAX_VISIBLE_TOKENS=384`; no `.env` edit |

The same four canonical-suite failures occurred before and after UX changes:

1. `test_only_gateway_and_low_level_modules_touch_generative_providers` and
   `test_production_callers_use_gateway_client_and_no_raw_chat_endpoint` scan
   `.venv-xpu-test/lib/python3.14/site-packages/joblib/test/test_func_inspect_special_encoding.py`
   as UTF-8. That unrelated environment contains a Big5 fixture. The scanner
   excludes `.venv` but not `.venv-xpu-test`; its assertions do not complete.
2. Model routing `auto-standard-384` and `standard-standard-384` expect 384, while
   this environment explicitly configures 600 visible tokens. The separate 27-test
   default-value run passes. No provider configuration or production limits were
   changed to obtain a green result.

Warnings: two SWIG import deprecations, one Starlette/httpx deprecation and 103
dateparser day/month-without-year warnings (future Python 3.15 behavior). These
are dependency warnings, not new UX failures. JUnit evidence is private cache
`pytest-baseline.xml` and `pytest-final.xml`. The canonical full run is **not green**.

## Production Build And Assets

Build ID: `V-oqxLZtiaT90CNuZCBuE`.

Immediately after the successful final build, executed only
`sudo -n systemctl restart ai-soc-frontend.service`: exit 0. The unit became
`active`, `SubState=running`, MainPID 70369 at **2026-09-12 10:54:32 CEST**.
The sudo allowlist permits restart but not `sudo systemctl is-active`; that read
returned an authentication-required error. The unprivileged, read-only
`systemctl is-active ai-soc-frontend.service` returned `active`, and `systemctl show`
confirmed the new PID/timestamp. No API, worker, Nginx or unrelated service restart.

`validate_ux12_runtime.py --incident-id 5358 --case-id 2` passed:

- Actual current manifest: 29 entries, 24 application pages/aliases, unchanged paths.
- 20 content routes return 200, four aliases 307 to the canonical destinations, both
  GET and HEAD on 3000 and 8088 with `Host: soc.varqon.net` (96 route requests).
- Unknown route 404 and favicon 200 on both paths.
- **41 current assets**, derived from current HTML, including JS/CSS/two fonts:
  every response 200 and SHA-256 identical to current `.next` files on BOTH paths
  (82 asset responses). No stale/hard-coded asset hashes.
- UX-11 runtime script also passes its 14-asset subset and dummy local cookie
  handler contracts: HttpOnly/Secure/Lax, 8-hour max age clamp, logout expiry.

This proves current build on disk == running Next server == assets served by Next
and local Nginx for the measured routes. HTML 200 alone does not prove API access.

### Public Path And Browser Limits

Public authenticated verification on `https://soc.varqon.net` remains **PENDING**.
The user was asked again after the final build became active to check Dashboard,
Incidents, Cases, Assistant, Detection Control Plane, Users and Security Audit,
and confirm no `/_next/static` Network/console failures. No Access bypass or
credentials in chat. Local Nginx evidence is not a substitute for that gate.

- Chromium automated: final production matrix and all three interaction suites passed.
- Edge/Chromium manual: no new UX-12 user verification recorded yet.
- Firefox: executable and cached browser unavailable; not automated, manual pending.
- Safari: unavailable in this environment; not tested.
- Screen reader: manual validation pending; axe is not a screen reader.
- Visual inspection uses actual screenshots and DOM geometry; no claim of pixel
  equivalence across unrelated charts or of exhaustive contrast in every state.

## Release-Readiness Findings

| Severity | Description / scope / user impact | Introduced by v0.9.0? | Recommendation before tag |
| --- | --- | --- | --- |
| BLOCKER | Final public authenticated route/asset verification and explicit user release-readiness approval are outstanding. Entire public delivery path is not independently proven by local checks. | Validation gate, not a demonstrated regression | Complete the seven-route public checklist and obtain explicit approval. Do not tag/merge/release. |
| HIGH | Sole ADMIN can self-demote, leaving zero active admins and no permitted self-restoration path; governance lockout risk. | No, pre-existing | Recommend blocking tag until separately approved backend safeguard or explicit documented risk acceptance and tested recovery. |
| MEDIUM | Four pre-existing full-suite failures; two boundary scans never reach assertions, two token expectations are environment-sensitive. | No | Correct/isolate test environment in separate scoped work; retain failed baseline/final evidence. Do not advertise a green full suite. |
| MEDIUM | Axe incomplete contrast/ARIA findings require manual assessment; normal-state and fixture automation does not establish conformance for all dynamic states or assistive technologies. | Existing/unclassified, not demonstrated new failures | Review incomplete findings and perform screen-reader checks before broad accessibility claims. |
| LOW | Existing CSS Tooltip is hover/focus based; Escape does not independently dismiss it, and an overflow ancestor can clip it. Icon controls retain native title and accessible names, so primary actions remain operable. | Yes, earlier UX primitive phase; unchanged in UX-12 | Targeted tooltip interaction follow-up and manual assessment before making broad accessibility conformance claims. |
| LOW | One initial live Incident remediation read exceeded 30s; successful retry and offline fixtures show no UX-attributable request storm. | Not established; observed before application edits | Monitor API latency separately; do not redesign fetching in this phase. |
| ACCEPTED LIMITATION | Automation is Chromium-only; no Safari/Firefox or screen-reader validation and axe incomplete results need human review. | Environment coverage limitation | This classification records scope, not user acceptance of release risk. Schedule manual coverage; no WCAG certification claim. |

No release/tag/merge/push was performed. The excluded Executive commit was not
cherry-picked: only its still-needed compact-card change and regression test were
reconciled on the exact approved UX-11 ancestry. All six labels, values, tones and
datasets are unchanged.

## Reproduction And Manual Review

Use the existing cached Playwright module via `UX_BROWSER_MODULE`, cached Chromium
via `UX_BROWSER_EXECUTABLE` and available shared libraries via `LD_LIBRARY_PATH`.
`UX_BASE_URL=http://127.0.0.1:3000` targets production frontend assets while API
fixtures intercept all data/mutations. `UX_SNAPSHOT` selects the private read-only
capture; `UX_BROWSER_OUTPUT` selects a private evidence directory.

```bash
node scripts/validate_ux12_browser.cjs
node scripts/validate_ux12_interactions.cjs
node scripts/validate_ux10_browser.cjs
node scripts/validate_ux11_browser.cjs
.venv/bin/python scripts/validate_ux12_runtime.py --incident-id 5358 --case-id 2
.venv/bin/python scripts/validate_ux11_runtime.py
```

Set `UX_STRICT=1` for the final five-width browser gate. Optional `UX_ROUTES` and
`UX_WIDTHS` narrow a diagnostic run; they were not used to omit failing final
routes. Capture mode is opt-in (`UX_CAPTURE=1`), accepts local short-lived token,
user and safe entity IDs on stdin, permits GET only, and keeps token out of saved
snapshot data. A failed/unknown request is reported, never fabricated as success.

Manual review: compare Executive/Incident metric density; Tab to skip/menu and
Escape back; wrap Case titles at 390px; scroll DNS/Network/history tables; open
and cancel a service dialog without preview/restart; review generated/fallback AI
labels and sources; check VIEWER restrictions; test Login and Users only with
disposable test accounts. **Do not self-demote the production ADMIN or execute
destructive operations to validate the UI.**

## Changed File Inventory

24 files: 15 frontend source files, three test files, three validation scripts and
three documentation files. Reasons and shared consumer coverage are listed above.
Next's generated `frontend/AGENTS.md` change was restored; no unrelated metadata,
backend implementation, secret, snapshot or screenshot is included.

```text
docs/ux-harmonization/v0.9.0-summary.md
docs/validation/README.md
docs/validation/ux-12-responsive-accessibility-regression.md
frontend/src/app/detection-quality/page.tsx
frontend/src/app/dns-telemetry/page.tsx
frontend/src/app/executive/page.tsx
frontend/src/app/globals.css
frontend/src/app/incidents/page.tsx
frontend/src/app/network-events/page.tsx
frontend/src/app/settings/ai-data-control/page.tsx
frontend/src/app/settings/detection-control/OperationsPanel.tsx
frontend/src/app/settings/semantic-memory/page.tsx
frontend/src/app/system-information/operation-history/page.tsx
frontend/src/components/AppNavigation.tsx
frontend/src/components/AppShell.tsx
frontend/src/components/enterprise/EnterpriseButton.tsx
frontend/src/components/enterprise/EnterpriseModal.tsx
frontend/src/components/enterprise/EnterprisePageHeader.tsx
scripts/validate_ux12_browser.cjs
scripts/validate_ux12_interactions.cjs
scripts/validate_ux12_runtime.py
tests/test_ux_final_regression.py
tests/test_ux_governance_auth.py
tests/test_ux_overview_pages_static.py
```
