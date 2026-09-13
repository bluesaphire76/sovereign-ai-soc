# UX-09: Overview And Monitoring Pages

Phase: UX-09, pending user verification. UX-10 is not started.

Branch: `feature/ux-harmonization-09-overview-pages`

Approved base: `cbd65125765530eb1377b124c55c9849d9c26c22`
(`feat: harmonize contextual ai assistant`).

## Protected Functional Inventory

The pre-flight inventory was taken from the approved base before implementation.
The matrices below retain that inventory and record the implementation audit.
`PASS (review)` means preserved in the code and checked against the base, not an
assertion that every production data combination was exercised in a browser.
Browser fixtures, endpoint smoke tests and outstanding manual checks are listed
separately below.

Protected boundaries:

- Same routes, backend contracts, query parameters, payloads and domain values.
- Same metrics, formulas, chart datasets/types, thresholds and local fallbacks.
- Same 30-second polling and explicit refresh on all four pages.
- Same filters, pagination, row limits, links and collapsed diagnostic details.
- Same ADMIN/ANALYST synthetic execution and VIEWER read-only runner.
- Same manually requested advisory guidance, caching and provider disclosure.
- Same external Observability link, visible only to ADMIN/ANALYST in AppShell.
- No shell, navigation, backend, Incident/Case Detail or Assistant changes.

## Dashboard Regression Matrix

| Capability | Before | After | Result |
| --- | --- | --- | --- |
| Eight KPIs | Incident total, average/max risk, correlated incidents, case total/active, breached SLA, cases with open actions, cases needing AI | Same values; shared compact metric strip | PASS (review) |
| Priority case queue | Nonterminal cases; SLA breach then open actions then risk; top eight from loaded cases | Same ranking, columns and links; moved before analytical charts | PASS (review) |
| Noisy hosts | Top eight, incident count and max risk | Same list beside attention queue | PASS (review) |
| Risk chart | Vertical bars; API risk bins 0-30, 31-60, 61-80, 81-100 | Same bins and values; LOW remains blue | PASS (review) |
| Case status chart | Status counts from loaded cases | Same bar chart and counts | PASS (review) |
| Operational backlog chart | SLA breaches, open actions, needs AI, ready to close | Same bars and computations | PASS (review) |
| Incident trend | Seven-day total and high-or-critical line series | Same chart and local fallback | PASS (review) |
| Queue aging | Incident/case stacked bars and breached SLA series | Same chart, buckets and fallback | PASS (review) |
| Detection funnel | Backend stages or existing local incident/case fallback | Same chart and fallback | PASS (review) |
| Optional analytics failure | Trend, aging and funnel fail independently to local fallback | Same behavior, now explicitly marked Partial analytics | PASS (review) |
| Incident stream | Nine columns; incident/status/time/host/rule/level/risk/priority/correlation | Same fields; canonical status and priority badges | PASS (review) |
| Ten filters | Status, risk, priority, correlated, host, rule search, correlation type, MITRE, from/to date | Same automatic request parameters and page reset | PASS (review) |
| Reset and paging | Reset all filters; Previous/Next; 15 incidents/page; totals | Same controls and disabled boundaries | PASS (review) |
| Case loading | `/cases?limit=100` | Unchanged | PASS (review) |
| Refresh/polling | Refresh and 30 seconds | Unchanged | PASS (review) |
| Navigation | Incident ID/rule and case links; Open Queue; Kanban | Same destinations | PASS (review) |
| States | Loading, API error, empty charts/queues/stream, filtered no-result | Shared states and retry; failed initial request no longer resembles zero data; stale data labeled after refresh failure | PASS (review) |
| Permissions | Read-only overview for all three roles | Unchanged; no new management commands | PASS (review) |

## Executive Regression Matrix

| Capability | Before | After | Result |
| --- | --- | --- | --- |
| Source | `/executive/summary` | Same endpoint and payload interpretation | PASS (review) |
| Six posture metrics | SOC posture, open exposure, critical pressure, escalation load, correlation percentage, risk ceiling/average | Same arithmetic; roomier shared metrics | PASS (review) |
| Decision brief | Backend decision/reason/next action with existing fallback | Same text; full reason and next action wrap | PASS (review) |
| Management action queue | Top five recommendations with count and existing classification | Preserved; placed beside decision brief | PASS (review) |
| Operating assurance | SLA posture/coverage, AI case/incident contribution, dedup/noise reduction; existing fallback values | Same metrics below management attention | PASS (review) |
| Latest AI case analysis | Case link, model, recommended status/severity, created time; empty state | Same information; severity uses severity semantics | PASS (review) |
| Exposure matrix | Incident state, case state, priority; count/share/distribution; first 14 rows with count | Same values, share calculation and bars | PASS (review) |
| Operational hotspots | Top six hosts and top six correlation types, counts and risk | Same limits and values | PASS (review) |
| Case management queue | Ten latest cases, six columns, case links | Same queue; LOW blue and unknown neutral | PASS (review) |
| High-risk queue | Ten latest high-risk incidents, six columns, incident links | Same data and risk thresholds | PASS (review) |
| Charts/trends | Distribution bars only; no standalone historical chart or time filter | No invented trend series or metrics | PASS (review) |
| Refresh/polling | Refresh and 30 seconds | Unchanged | PASS (review) |
| States | Initial loading, page error, empty recommendation/analysis/queues | Shared skeleton/error/empty; retry and stale-data notice | PASS (review) |
| Permissions/links | All three roles; Dashboard breadcrumb and existing drill-downs | Unchanged; no new technical controls | PASS (review) |

## Health Regression Matrix

| Capability | Before | After | Result |
| --- | --- | --- | --- |
| Source/polling | `/platform/health`; refresh and 30 seconds | Unchanged | PASS (review) |
| Seven KPIs | Overall, component counts, average latency, checked time, active users, latest incident, latest risk | Same computations; shared compact metrics; missing latency/risk shown as unavailable | PASS (review) |
| Overall/dependencies | Backend overall and independent component OK/WARN/ERROR/UNKNOWN states | Canonical tones; successful HTTP does not override degraded status | PASS (review) |
| Component coverage | Existing ordered component list plus unfamiliar future components | No components filtered out; API/Postgres/Wazuh/worker/AI/Qdrant and others retained | PASS (review) |
| Component details | Message, latency, status, non-blocking flag, collapsed JSON details | Same content and default collapse | PASS (review) |
| Latest incident | ID, timestamp, host, risk, rule, Open incident link | Preserved; LOW risk no longer success green | PASS (review) |
| Worker/ingest metrics | Mode, pending events and latest-event lag, existing fallback extraction | Same extraction and values | PASS (review) |
| STABLE derivation | Catching-up batch with zero pending and recognized all-skipped outcomes; raw mode retained | Unchanged | PASS (review) |
| Ingest/backlog detail | Seen, pending, watermark lag, batch limit, poll interval, total ingested | Same collapsed group | PASS (review) |
| Batch outcomes | Processed, skipped, suppressed, observed, aggregated, duplicate, no-ID, other | Same collapsed group and counts | PASS (review) |
| AI triage detail | Success/fallback/skipped, configured/effective model/profile, last fallback | Same collapsed group | PASS (review) |
| Timestamps | Last event, watermark, heartbeat | Preserved | PASS (review) |
| Provider registry | Default/fallback providers, external switch/count; each provider's enabled/reachable/model/latency flags | Same data and collapsed entries | PASS (review) |
| Local runtime | llama.cpp router/current LLM, base URLs, profiles and native UI link | Preserved, including existing new-tab behavior | PASS (review) |
| Observability | Existing sidebar external link for ADMIN/ANALYST; no embedded Grafana | Unchanged | PASS (review) |
| States | Loading, full request failure, component degradation and absent component/provider data | Shared states; degraded dependencies remain visible; no fake zero dashboard on initial failure | PASS (review) |
| Permissions | All roles can view Health and existing native runtime link; Observability operators only | Unchanged | PASS (review) |

## Detection Quality Regression Matrix

| Capability | Before | After | Result |
| --- | --- | --- | --- |
| Source/sample | Incident search SYNTHETIC, page 1, limit 20; existing synthetic parser | Same sample and parsing; no new aggregation | PASS (review) |
| Runner filters | All/catalog scenario, count 1-10, host, created by | Same four controls and constraints | PASS (review) |
| Scenario catalog | `/synthetic-tests/scenarios`, operators only | Same request and error handling | PASS (review) |
| Execution | `/synthetic-tests/run`, same payload, in-flight disable, success IDs, refresh | Same behavior with shared controls/status | PASS (review) |
| Permissions | ADMIN/ANALYST runner; VIEWER read-only | Unchanged; backend authoritative | PASS (review) |
| Five KPIs | Synthetic count, correlation, expected-priority validation, MITRE coverage, averaged quality score | Same formulas and denominators | PASS (review) |
| Thresholds | Risk 81/61/31 and coverage 90/70/40 | Unchanged; not replaced by global risk thresholds | PASS (review) |
| Validation brief | Deterministic summary, next action, correlation/priority/MITRE/quality/weakest-scenario signals | Same computations and recommendations | PASS (review) |
| Coverage chart | Horizontal stacked correlated/gap bars by scenario; max/average risk | Same datasets, orientation, series and compact height | PASS (review) |
| Scenario breakdown | Seven columns: scenario, count, correlation, priority, MITRE, average/max risk | Same table and values | PASS (review) |
| Latest incidents | Seven columns; up to 25 rows from the loaded 20-record sample; incident links | Same source, limit and navigation | PASS (review) |
| Guidance request | Manual `/detection-quality/action-guidance`; action/scenario cache keys; local storage/in-flight handling | Unchanged; shared generate/retry controls | PASS (review) |
| Guidance disclosure | Model/profile/fallback/cache, steps, validation notes, provider/external/redaction/latency metadata | Retained; visibly advisory and separate from deterministic metrics | PASS (review) |
| Guidance roles | All three roles can request existing advisory guidance | Unchanged; this is not synthetic execution permission | PASS (review) |
| Refresh/polling | Explicit refresh, refresh after synthetic execution, 30 seconds | Unchanged | PASS (review) |
| States | Page/catalog/runner/guidance errors; loading/in-flight; success; empty sample/chart/table | Shared states; initial failure distinct from zero coverage | PASS (review) |
| Other filters/paging | No analytics filter bar or pagination controls in baseline | None invented or removed | PASS (review) |

## Shared Components And Semantics

Reused AppShell, EnterprisePageHeader, EnterpriseBreadcrumbs, EnterpriseMetricStrip,
EnterpriseMetricCard, EnterprisePanel, EnterpriseSection, EnterpriseChartCard,
EnterpriseButton, EnterpriseSelect, EnterpriseBadge, EnterpriseSeverityBadge,
EnterpriseStatusBadge, EnterpriseSkeleton, EnterpriseErrorState and EnterpriseEmptyState.
Page-specific chart, assurance, ingest and guidance helpers remain where useful.

MetricCard adds opt-in stacked compact metadata, full-value/title access and
contained roomier values/icons. Panel/Section add `min-w-0` so grid children and
wide tables scroll within their own panel rather than expanding the page.
No parallel component family or dependencies were introduced.

Status helpers now recognize CRITICAL as danger. Severity remains CRITICAL red,
HIGH orange, MEDIUM amber, LOW blue, unknown neutral. Priority color follows the
displayed priority, independently of numeric risk. Domain-specific detection
score/coverage thresholds remain local and unchanged. Green represents healthy,
completed or favorable measured outcomes, not merely successful requests.

## Automated And Runtime Evidence

- `npm --prefix frontend run lint`: PASS.
- `npm --prefix frontend run build`: PASS, including TypeScript and 27 pages.
  A sandbox port restriction initially failed Turbopack; a fresh cache and an
  authorized build outside that restriction passed. No build configuration changed.
- `git diff --check`: PASS.
- `./ai-soc docs-validate`: PASS, 27 checks.
- `.venv/bin/python scripts/validate_docs_structure.py`: PASS.
- Focused pytest selection: overview contracts/RBAC/synthetic in-memory fixture,
  Dashboard metrics, Executive routes, provider metrics, route inventory,
  detection guidance/routing/semantic context, synthetic router, security
  helpers and platform ingest routes. 41 tests pass; two SWIG deprecation
  warnings are unrelated to this change.
- Real read-only smoke: four frontend routes and summary/incidents/cases/hosts/
  risk-distribution/trend/aging/funnel/Executive/Health/synthetic-search/scenario
  catalog API paths all returned HTTP 200 (four pages and 12 API GET requests).
  The final preview also passed authenticated read-only Chromium checks on all
  four routes at 1440 and 390 pixels: no failed API requests, JavaScript errors,
  visible page errors or page-wide overflow. No production synthetic run or LLM
  generation is included.
- Browser verification uses cached Playwright/Chromium and intercepted fixtures,
  not a newly installed project testing framework. The suite covers normal,
  loading, failure/retry, empty and degraded states; refresh/polling; filter reset;
  ingest collapse; synthetic result and guidance; role visibility and responsive
  layout. All four routes passed at 390, 1440 and 1920 pixels, with zero page
  JavaScript errors, no page-wide overflow and no clipped KPI values. Each of
  ADMIN, ANALYST and VIEWER passed all four routes, active navigation and external
  link visibility. Native llama.cpp links remain available for all existing roles.
  Synthetic runs were intercepted for ADMIN/ANALYST; VIEWER had neither a runner
  command nor a scenario catalog request. Advisory guidance remains available to
  all three roles. Error/retry/empty and refresh/polling checks passed on all four;
  Dashboard partial analytics/filter reset, Health ingest expansion and unknown
  state treatment also passed.
- Health has no dedicated endpoint-behavior unit test in the existing selection;
  route inventory, provider metrics, fixture UI and the real GET smoke provide
  partial coverage. Exhaustive live dependency failure injection is not claimed.

Focused regression command:

```bash
.venv/bin/python -m pytest -q \
  tests/test_ux_overview_pages_static.py \
  tests/test_dashboard_metrics.py \
  tests/test_executive_metrics_router_refactor.py \
  tests/test_ai_provider_metrics.py \
  tests/test_api_route_inventory.py \
  tests/test_detection_quality_guidance_routing.py \
  tests/test_detection_quality_semantic_context.py \
  tests/test_synthetic_tests_router_refactor.py \
  tests/test_security_refactor_helpers.py \
  tests/test_platform_ingest_router_refactor.py
```

One-time browser scripts and screenshots are local verification artifacts under
`/tmp/ux09-browser.cjs`, `/tmp/ux09-live.cjs` and `/tmp/ux09-browser/`. They are not
project dependencies or a portable CI browser suite. The fixture results are
recorded in `/tmp/ux09-browser/results.json`.

## Manual User Verification

Use `http://127.0.0.1:3003` for the local final-build preview. Its temporary
loopback-only proxy forwards UI requests to port 3001 and `/api-backend` to the
existing backend on port 8008. It does not change repository or deployment
configuration; pre-existing services on ports 3000 and 3002 are untouched.
Sign in with existing
ADMIN, ANALYST and VIEWER test accounts; do not alter production configuration.
Open all four routes side-by-side at desktop size, then at a 390px-wide mobile
viewport. Compare common headers, metrics, panels, status labels and focus states.
Executive should remain less dense than Dashboard and Detection Quality.

### Dashboard

1. Open `/`. Check eight KPI values against the network responses. Hover any
   shortened label/metadata for the full text. Confirm priority cases/noisy hosts
   precede the six analytical charts.
2. Check risk/status/backlog bars, trend lines, aging stacks and funnel. Hover
   charts for labels/values. Confirm LOW is blue, closed/healthy is green.
3. Change each of the ten incident filters, including a host with no matches.
   Confirm request parameters/page reset, empty message, Reset filters and
   Previous/Next boundaries. Verify case and incident links, Open Queue and Kanban.
4. Press Refresh and watch Network for automatic requests after 30 seconds.
   Block an optional analytics endpoint: the attention queue must remain visible
   with Partial analytics. Restore requests and refresh.

### Executive

1. Open `/executive`. Verify posture plus five metrics; compare decision, full
   reason and next action with the backend response. Check the adjacent action queue.
2. Inspect SLA/AI/noise assurance, latest AI analysis and its case link. Check
   exposure shares/bars, both hotspot lists and the two detailed queues.
3. Follow a case and high-risk incident link. Refresh and confirm 30-second polling.
   There was no standalone historical trend chart in the baseline; none is added.
4. Confirm it remains a decision-oriented view, without new runtime diagnostics.

### Health

1. Open `/health`. Compare overall status with component states, including a
   degraded/unavailable dependency. A successful request must not make WARN green.
2. Check API, Postgres, Wazuh indexer/ingest, worker, AI runtime and Qdrant, plus
   every other returned component. Expand Details and verify message/latency/JSON.
3. Expand Ingest & backlog, Batch outcome and AI triage. Check mode/raw mode,
   pending/lag, all counters, configured/effective model/profile and timestamps.
4. Expand provider entries and review enabled/reachability/model/latency flags.
   Where configured, open the existing llama.cpp native UI in its new tab.
5. Follow Open incident; return, press Refresh, then observe polling after 30 seconds.
   As ADMIN/ANALYST open Observability from the sidebar: it must be external.
   As VIEWER confirm Observability is absent, without losing native Health data.

### Detection Quality

1. Open `/detection-quality`. Compare five KPIs, validation brief, coverage/gap
   bars and both seven-column tables with the existing synthetic sample.
2. As ADMIN and ANALYST, select an approved scenario, count 1 and a dedicated
   non-production test host/creator. Only in an isolated test environment, press
   Run synthetic test. Verify disabled in-flight state, result IDs and refreshed
   metrics. Do not perform this step against production detection configuration.
3. Generate an AI suggestion on a safe test dataset. Verify advisory labeling,
   steps, validation note, model/profile/fallback/cache and provider/external/
   redaction/latency metadata. Revisit to verify existing cache behavior.
4. As VIEWER confirm the runner is read-only and no executable synthetic button
   or scenario request appears. Advisory generation retains its existing permission.
5. Follow an incident link; verify Refresh and polling. Check runner/guidance
   errors in a test fixture without changing live detection rules.

### State And Accessibility Checks

1. In browser DevTools enable network throttling and reload each route. Confirm
   labeled skeletons, then loaded content. Disable throttling afterwards.
2. Block the route's primary API request and reload: expect an error/retry, not
   zero-valued healthy metrics. Unblock and Retry. Repeat after a successful load:
   the error must identify the retained data as last loaded.
3. Use a zero-data test fixture to inspect empty queues/charts/component data.
   Test partial Health degradation without taking down production dependencies.
4. Tab through refresh, filters, links, expand controls and permitted actions.
   Confirm visible focus, accessible control labels and disabled in-flight states.
5. On mobile, horizontally scroll wide tables within their panels. Ensure there
   is no page-wide overflow, KPI collision or inaccessible clipped numeric value.

## Limitations And Approval Gate

Fixture browser tests cannot prove live synthetic processing, real model quality,
every dependency failure combination, screen-reader behavior or user acceptance.
Health native links depend on local runtime configuration. Shared sizing changes
also affect other consumers of MetricCard/Panel/Section; review their dense strips
and tables during user acceptance. Backend calculations and authorization are
unchanged. No framework, package/lockfile, routes or navigation were added.

UX-09 requires explicit user approval after these checks. Do not start UX-10.
