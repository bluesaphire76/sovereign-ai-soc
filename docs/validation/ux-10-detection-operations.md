# UX-10: Detection Governance And Operations

Phase: UX-10, pending user verification. UX-11 is not started.

Branch: `feature/ux-harmonization-10-detection-operations`

Approved base: `e627c687a27190f0ced46e2f1baa289fca118b48`
(`feat: harmonize overview and monitoring pages`).

## Protected Pre-flight Inventory

Recorded before editing Detection Control Plane. Source of truth: the complete
four frontend modules in `frontend/src/app/settings/detection-control`, the three
other target pages, `routers/detection_control.py`, `routers/service_operations.py`,
`security/rbac.py` and their domain implementations. No backend, shell, navigation,
Health, Incident Detail, Case Detail or Assistant changes are intended.

In the tables below, D = `/detection-control`, C = D + `/config-versions/{domain}`,
L = D + `/lifecycle/items`, O = D + `/operations`, S = `/service-operations`.
All roles means ADMIN, ANALYST and VIEWER; operators means ADMIN and ANALYST.
Backend authorization remains authoritative. GET config version routes can seed
missing baselines; service status checks record audit operations. These are not
used as mutation substitutes during live verification.

| Area / callback | Existing endpoint / data | Permission and deliberate steps to preserve |
| --- | --- | --- |
| Page `loadData` | GET `/settings/detection-control`, D/rules, C, C/active | All roles; initial/domain/manual refresh, no polling; independent child panels |
| Posture metrics | Unified native inventory plus standalone managed rules, linked overlays deduplicated by metadata.inventory_id | Six KPIs; preserve active/disabled/failed calculations, category counts and generated time |
| Inventory | Rules, Exceptions, Sources, Policies, Service Control tabs; nine-column inventory with source, scope/target, status, governance, reload, metadata | All roles inspect; ADMIN Manage/Edit; no existing inventory search/paging to invent |
| Version selection | Four domains: noise_suppression, exceptions, detection_rules, source_controls; GET C/{version} | All roles; active checksum, actors, timestamps, reason, payload and selected details |
| `validateSelectedConfig` | POST C/validate, `{items: proposedItems}` | Operators only; blocking messages, warnings, valid flag, affected services/restart; domain/proposal changes clear results |
| `previewSelectedDiff` | POST C/diff, same items | Operators only; added/removed/modified counts, identifiers, changed fields, unchanged count |
| `applySelectedConfig` | POST C/apply, `{items, reason}` | ADMIN; valid result AND diff required by button; reason prompt then confirmation; new active version and restart consequences |
| `rollbackToVersion` | POST C/rollback, `{version_number, reason}` | ADMIN, non-ACTIVE history row; reason prompt then confirmation; restores payload as NEW active version |
| Version audit | Version history table and GET C/{version} details | All roles; seven columns, reason, validation details, rollback link ID, payload preview; no history deletion |
| `submitForm` | POST D/rules or PATCH D/rules/{id} | ADMIN; full rule payload, JSON metadata, backend validation; saving gate; refresh and advisory context afterwards |
| Managed form | Name, six rule types, scope, five matcher kinds/value, reason, owner, enabled, description | Disabled for non-ADMIN; form reset and inventory-to-managed draft/overlay mapping preserved |
| `validateRule` | POST D/rules/{id}/validate | ADMIN; validation result and list refresh; not equivalent to merely successful HTTP |
| `setRuleEnabled` | POST D/rules/{id}/enable or disable | ADMIN, saving gate; no pre-existing prompt/confirmation; status/payload values unchanged |
| `archiveRule` | DELETE D/rules/{id} | ADMIN, named archive confirmation, cancel does nothing; editor reset if target selected |
| Advisory memory | POST D/semantic-context, rule payload plus current_rule_id | Operators; automatic on edit/manage/save, manual refresh; similar controls, closures, incidents, playbooks, scores, provenance, warnings, decision boundary; advisory only |
| Lifecycle load/select | GET L?limit=200 and filters; GET L/{id}/history and /diff | All roles; default collapsed, still loads; selected record preserved if present; partial errors stay local |
| Lifecycle filters | Policy type, state, source, validation, owner, search | Same query names, nine states, three policy types, source choices; no polling |
| Lifecycle create/edit | POST L or PATCH L/{id}; structured content_json/match JSON parser | Operators create; ADMIN or owning ANALYST edit DRAFT/FAILED_VALIDATION; all 13 form fields and metadata preserved |
| Lifecycle `runAction` validate | POST L/{id}/validate | Operators; DRAFT/PROPOSED/FAILED_VALIDATION; actual failed validation must remain failure on HTTP 200 |
| Lifecycle submit | POST L/{id}/submit with existing readiness comment | Operators; DRAFT/FAILED_VALIDATION; backend validates before transition |
| Lifecycle approve | POST L/{id}/approve with existing approval comment | ADMIN; PROPOSED; backend prerequisites preserved |
| Lifecycle reject | POST L/{id}/reject with rejection_reason | ADMIN; PROPOSED/APPROVED; required reason prompt, cancel does nothing |
| Lifecycle return | POST L/{id}/return-to-draft with existing editing comment | Operators; PROPOSED/FAILED_VALIDATION/REJECTED/DISABLED |
| Lifecycle apply | POST L/{id}/apply with existing apply comment | ADMIN; APPROVED; confirmation; backend revalidates, creates configuration version; parent reload |
| Lifecycle disable | POST L/{id}/disable with disable_reason | ADMIN; ACTIVE; required reason prompt; parent reload |
| Lifecycle clone | POST L/{id}/clone, empty object | Operators; REJECTED/DISABLED/ACTIVE/SUPERSEDED; creates editable draft, does not apply |
| Lifecycle delete | DELETE L/{id} | DRAFT only, ADMIN or owning ANALYST; named confirmation; cancel does nothing |
| Lifecycle detail | State, validation findings, owner/source/creator, version, approval/config link, restart/expiry, raw rule JSON, diff, event history | All roles; service anchor preserved; backend allowed_transitions contains target STATE names, not role-specific action names |
| Exceptions/noise/rules | GET O/overview; GET O/noise-suppression, /exceptions or /rules?limit=200 | All roles; category tabs, five KPIs, scope/state/review/search filters; no polling |
| Scope/review semantics | narrow/moderate/broad/dangerously_broad/unknown; review state, expiry, reasons, hits and source | Preserve actual classifications, no new risk score; active suppression is not resolved detection |
| Matched evidence | GET O/items/{id}/matched-events?limit=25&scan_limit=1000 | All roles; source table/ID, timestamp, agent, rule, level, payload preview |
| `runPreview` | POST O/match-preview; selected metadata content, matcher/scope, limit25/scan1000 | Operators via existing rbac flag or role; preview only, no apply. Existing detail button appears enabled for VIEWER despite callback guard; align presentation with guard |
| `markReviewed` | POST O/items/{id}/mark-reviewed, review_status and review_notes | Operators; reviewed/needs_follow_up/risk_accepted; preserve audit and refresh |
| `extendReview` | POST O/items/{id}/extend-review, expires_at and reason from review notes | Operators; selected date required; preserve backend checks and refresh |
| Service list/history | GET S/services and S/operations?limit=200 | All roles; per-service state, command family, risk, impact, last operation; config restart clears only on matching successful restart AND running service |
| `checkStatus` | GET S/services/{key}/status | All roles; backend records status check/audit; explicit button and refresh preserved |
| `openRestart` | Selects service; resets reason, checkbox, preview, result | Existing UI ADMIN only AND restart_allowed; although API preview supports ANALYST, do not broaden this entry point |
| `runPreview` restart | POST S/services/{key}/restart-preview, reason and related_config_version_id | Operators API; nonblank reason; displays allowed/blocked, warnings, impact, checks; audit recorded; never executes restart |
| `restartService` | POST S/services/{key}/restart, same fields plus confirm | ADMIN; allowed preview AND nonblank reason AND explicit checkbox; allowlisted commands, server authorization, capability and confirmation checks remain unchanged |
| Restart result/close | Operation ID/status, pre/post state, safe message/error; Cancel/Close resets modal | Busy disables controls; cancel/escape must not execute; retain reason, preview, execution as separate steps |
| Request feedback | Main error, lifecycle boundary retry, local panel errors, service modal result | Do not equate request completion, validation success, apply success and restart success; retain old data on refresh failure |

## Telemetry And History Inventory

| Route | Existing behavior to preserve | Residual audit finding |
| --- | --- | --- |
| `/network-events` | All-role read-only Suricata; GET /network-events/summary and /network-events?limit=100; event_type/src_ip/dest_ip/hostname; automatic filter request, Apply filters, Clear, Refresh; four KPIs; event distribution, top destinations with local country/resolver context, hostnames, seven-column events with numeric IDS severity | Local header/metric/filter/state styles; initial empty appears while loading; retain numeric severity interpretation, no mapping to invented backend severity |
| `/dns-telemetry` | All-role read-only Wazuh DNS; GET /dns-events/summary and /dns-events?limit=100; query_name/client_ip/query_type; automatic filter request, Apply filters, Reset, Refresh; total/freshness/topclient/toptype; record distribution, top10 clients, top20 domains, six-column events with raw line | Local header/metrics/panels/controls/states; DNS A record color is categorical, not success; retain freshness threshold and formulas |
| `/system-information/operation-history` | All-role GET S/operations; service/type/status/search350ms/page size25/50/100/200; offset and Previous/Next; four KPIs; status/prepost/config/actor/time/message table; errors/retry/loading/empty/reset | Already shared header, metric strip, panels, controls, states and status badges. No concrete redesign need; leave source unchanged and regression test |

## Implementation

The page order now places configuration governance and lifecycle before managed
entries, native inventory, exceptions/noise review and service operations. All four
existing Detection Control Plane modules retain ownership of their callbacks.
No capability was removed. Backend routes, payloads, domain states, formulas and
permission rules are unchanged. No new domain concepts or component families were added.

Reused AppShell, EnterprisePageHeader, EnterpriseBreadcrumbs, EnterpriseMetricStrip,
EnterpriseMetricCard, EnterpriseSection, EnterprisePanel, EnterpriseButton,
EnterpriseIconButton, EnterpriseBadge, EnterpriseStatusBadge, EnterpriseSearchInput,
EnterpriseSelect, EnterpriseConfirmationDialog, EnterpriseModal, EnterpriseSkeleton,
EnterpriseEmptyState and EnterpriseErrorState. Existing local adapters now delegate
to Enterprise controls instead of maintaining duplicate implementations.

The only shared primitive change is EnterpriseButton: additive `info` tone uses
the existing semantic informational palette, and optional `aria-expanded` /
`aria-controls` are forwarded for the existing lifecycle disclosure. Existing
tones and consumers are unchanged. No Health compatibility changes were needed.

Inspection remains secondary, validation uses informational outline treatment,
apply/submit/approve use governed primary treatment, and rollback/restart/disable/
reject/archive/delete use danger treatment with their existing names and icons.
ACTIVE suppression is informational, not resolved/success; broad scope and review
state remain independent. Missing validation is neutral Not run, and an invalid
validation body remains failure even when HTTP succeeds or severity says OK.

Simple archive and draft-delete confirmations use the shared dialog. Native
reason-prompt plus confirmation flows for config apply/rollback and reason prompts
for lifecycle reject/disable remain intact. Lifecycle apply now names its target.
The restart modal retains reason, checkbox, preview and execute as separate steps.
Changing the reason clears the previous preview and confirmation; a new preview
attempt clears its previous permission result. Failures are visible inside the modal.

Match preview now selects the row being previewed and binds returned evidence to
that row's ID, so it cannot be shown under another selected entry. The VIEWER
detail Preview button is disabled consistently with its pre-existing callback/API
permission. Preview is labeled Preview / expected matches and never Applied.

Network and DNS retain distinct layouts/data but share headers, controls, metrics,
unframed sections and states. Numeric Suricata severity, destination resolver context,
DNS freshness arithmetic and ranked limits are unchanged. DNS A record types use
categorical blue, not success green. Tables have explicit minimum widths and scroll
inside their containers; DNS grid wrappers now constrain the wide event table.
Operation History passed its residual audit with no source changes.

### Changed Files

| File | Reason |
| --- | --- |
| `frontend/src/app/settings/detection-control/page.tsx` | Page hierarchy, config governance, managed/inventory controls, validation, technical diff and archive confirmation |
| `frontend/src/app/settings/detection-control/LifecyclePanel.tsx` | Shared lifecycle controls/states, transition presentation, failed-validation feedback, draft confirmation and raw diff |
| `frontend/src/app/settings/detection-control/OperationsPanel.tsx` | Scope/review semantics, accessible controls and target-bound match preview/evidence |
| `frontend/src/app/settings/detection-control/ServiceOperationsPanel.tsx` | Shared service controls and restart modal preserving reason, preview, consent and execution gates |
| `frontend/src/app/network-events/page.tsx` | Shared read-only telemetry header, metrics, filters, sections and states |
| `frontend/src/app/dns-telemetry/page.tsx` | Related DNS presentation, categorical badges and contained event table |
| `frontend/src/components/enterprise/EnterpriseButton.tsx` | Additive informational tone and disclosure ARIA attributes |
| `scripts/validate_ux10_browser.cjs` | Fail-closed browser fixtures, role/state/safety checks and responsive screenshots |
| `tests/test_ux_detection_operations_rbac.py` | Protected route-role permission regression matrix |
| `docs/validation/ux-10-detection-operations.md` | Pre-flight inventory, before/after matrix, evidence, limits and manual verification |
| `docs/validation/README.md` | Index this validation package |

## Before / After Regression Matrix

All rows below passed implementation review against the approved base.
Evidence codes: R = code/contract review; P = isolated Python tests;
B = intercepted browser fixture; L = authenticated live GET-only smoke.
A PASS does not claim that a real production mutation was executed.

| Area | Capability before | After | Result / evidence |
| --- | --- | --- | --- |
| Identity | Dashboard back link, title, role guards | Breadcrumb, shared header, explicit permission metadata; same routes | PASS R B L |
| Metrics | Six unified posture KPIs with overlay deduplication | Shared strip, unchanged calculations/counts | PASS R B L |
| Inventory | Five tabs, native data/source/scope/status/reload/metadata, ADMIN Manage/Edit | All tabs/columns/actions retained, contained wide table | PASS R B L |
| Config domains | Four domain selectors and automatic reload | Same domains and reset behavior, selected state accessible | PASS R B L |
| Active config | Version/checksum/time/actor/validation/restart metadata | Same values and active-version source | PASS R B L |
| Versions | Seven-column history and Details action | Same history/actions, explicit table width | PASS R B P L |
| Version details | Selected version, reason, validation, payload preview, rollback ID | Retained without payload transformation | PASS R P |
| Validate config | Operator-only validation of proposed items | Same callback/payload; informational command | PASS R B P |
| Validation details | Valid flag, severity, blocking errors/warnings/restart | Invalid flag takes precedence over successful HTTP; Not run explicit | PASS R B P |
| Diff | Operator-only preview, counts and change summaries | Same response; added expandable complete raw from/to diff | PASS R B P |
| Apply | ADMIN, valid result and diff, reason prompt then confirm | Same prerequisites/payload and deliberate steps | PASS R B (both cancellation stages) P |
| Rollback | ADMIN, non-active row, reason then confirmation, new version | Same semantics and restart warning; danger command | PASS R B (both cancellation stages) P |
| Managed create/update | ADMIN full form and POST/PATCH; saving state | Same fields, payload, submit/reset and validation | PASS R P |
| Inventory management | Convert native entry to draft or edit linked overlay | Same mapping/metadata and save path | PASS R |
| Managed validation | ADMIN /rules/{id}/validate, result and reload | Same action; null last status no longer invented OK | PASS R B P |
| Enable/disable | ADMIN state action without pre-existing prompt | Same action/role; disable visibly sensitive | PASS R P |
| Archive | ADMIN named native confirmation and DELETE archive contract | Named shared confirmation; Cancel/Escape do nothing; same endpoint | PASS R B P |
| Advisory context | Operators, four memory groups, provenance and decision boundary | Same requests/data; explicitly Advisory, separate from validation | PASS R P |
| Lifecycle disclosure | Initially collapsed, independently loaded, retry boundary | Same behavior; expanded state exposed on shared button | PASS R B L |
| Lifecycle filters | Policy/state/source/validation/owner/search and limit200 | Same filters, query names and refresh; shared labeled controls | PASS R B |
| Lifecycle create/edit | Operators; edit own ANALYST drafts or ADMIN drafts; JSON parsing | Same role/ownership/field rules; read-only/busy form fieldset disabled | PASS R B P |
| Lifecycle validate | Operators, DRAFT/PROPOSED/FAILED_VALIDATION | Same state gates; failed result remains failure on HTTP200 | PASS R B P |
| Lifecycle submit | Operators, DRAFT/FAILED_VALIDATION, readiness comment | Same prerequisites/comment and endpoint | PASS R B (visibility) P |
| Lifecycle approve | ADMIN, PROPOSED, approval comment | Same prerequisites/comment and endpoint | PASS R B P |
| Lifecycle reject | ADMIN, PROPOSED/APPROVED, rejection reason prompt | Same reason/cancel behavior; danger icon | PASS R B (visibility) P |
| Return to draft | Operators, four existing allowed source states | Same action/comment and state gates | PASS R B (visibility) |
| Lifecycle apply | ADMIN, APPROVED, confirmation, apply comment | Same action; confirmation additionally identifies target title | PASS R B (visibility) P |
| Lifecycle disable | ADMIN, ACTIVE, disable reason prompt | Same prerequisites/reason/reload; danger icon | PASS R B P |
| Clone | Operators on four existing source states | Same draft clone, no apply | PASS R B (visibility) P |
| Delete draft | ADMIN or owner ANALYST, DRAFT, confirmation | Same restriction; shared named dialog and defensive DRAFT guard | PASS R B |
| Lifecycle details | Overview/findings/impact/raw JSON/diff/history/service link | All retained; raw full diff added, metadata wraps | PASS R B P |
| Operations categories | Noise Suppression / Exceptions / Rules | Same endpoints, selection reset and categories | PASS R B P L |
| Operations metrics/filters | Five KPIs, status/scope/review/search | Same values and query limits; shared controls | PASS R B P L |
| Scope and review | Scope reasons, broad/dangerous classification, expiry, state | Same data; control state, scope and review independently styled | PASS R B P |
| Match evidence | Read-only recent events and recorded hit provenance | Same matches/source table/IDs/time/payload, target-ID binding | PASS R B P |
| Match preview | Operator-only query, scan1000/limit25 | Same payload; selects target and labels expected matches; VIEWER disabled | PASS R B |
| Mark reviewed | Operators, status plus notes, audit and reload | Same options/body; no invented approval semantics | PASS R P |
| Extend review | Operators, expiry date and reason from notes | Same date requirement/body/audit; labeled controls | PASS R P |
| Service inventory | Five allowlisted service definitions and status metadata | Same live services, risk/command/config/last-operation data | PASS R B L |
| Status check | All roles, explicit audited GET status operation | Same button/callback; not called by live smoke | PASS R P |
| Restart entry | UI ADMIN and restart_allowed; preview API operators | Same narrower UI access, no added ANALYST execution entry point | PASS R B P |
| Restart reason | Nonblank reason required before preview/execute | Same requirement, labeled required; edits invalidate previous preview/consent | PASS R B P |
| Restart preview | Explicit request, allow/deny, warnings, audit | Same endpoint/body, no auto-execute; old preview cleared on retry | PASS R B P |
| Restart confirmation | Explicit impact checkbox and allowed preview | Both still required independently; Cancel/Escape are non-mutating | PASS R B P |
| Restart execute | ADMIN + reason + confirmation + allowed preview; server allowlist | Same endpoint/body/authorization; failure fixture tested, real execution excluded | PASS R B P |
| Restart result/history | Operation ID, pre/post, safe message/error, last operation | Same data, domain status badge; error visible inside modal | PASS R B P L |
| Restart clearance | Successful restart for same config AND running service | Exact computation preserved, not cleared by preview | PASS R |
| States | Page/local errors, loading, partial child failure, empty lists | Shared states; old data retained on refresh failure; API error not healthy-zero telemetry | PASS R B L |
| Network Events | Four KPIs, four filters, distributions/destinations/hostnames, seven-column data | Same evidence, limits, numeric severity and query parameters | PASS R B L |
| DNS Telemetry | Four KPIs, three filters, record/client/domain rankings, six-column data | Same values, freshness formula and top10/top20 limits | PASS R B L |
| Operation History | Four KPIs, filters, search350ms, paging, statuses and inline history fields | Source unchanged; no new detail capability invented | PASS R B P L |

## Automated Evidence

- Frontend lint: PASS, no warnings. Production build: PASS, TypeScript and 27 routes.
- `git diff --check`: PASS.
- `./ai-soc docs-validate`: PASS, 27 checks.
- `.venv/bin/python scripts/validate_docs_structure.py`: PASS.
- Focused pytest: 194 PASS, two existing SWIG deprecation warnings. Includes
  Detection Control Plane, rule validation, semantic context, config version/diff/
  apply/rollback, lifecycle/approval, exceptions/noise/review/matches, service preview/
  restart/reasons/authorization/audit/history, detection engineering, route inventory,
  security helpers, the new UX-10 route-role matrix and all seven UX-09 overview
  static regression checks, including Health and external Observability.
- No standalone backend telemetry test suite exists in the repository. Existing
  route-inventory checks, new role tests, browser fixtures and live endpoint reads
  cover these pages; backend telemetry code and calculations are unchanged.
- Cached Playwright/Chromium: 33 browser check groups PASS. Four routes at
  390/1440/1920; three roles; all nine lifecycle states; invalid validation on
  HTTP200; raw diff; apply/rollback cancel at both stages; archive/delete Cancel/
  Escape; required reason, allowed/blocked restart previews, checkbox prerequisite,
  changed-reason invalidation, fixture restart failure/result; mobile expanded
  lifecycle/modal/keyboard; empty/unavailable/403/loading; telemetry filters/reset
  and Operation History pagination/search. No unhandled JavaScript errors or
  page-wide overflow in checked final states.
- Browser API interception fails closed, including unknown paths and external
  requests. Restart execution in this suite is a JSON fixture, never a command.
  Python service tests use fake runners and an in-memory database.
- Live smoke: 15 API GET endpoints returned HTTP200. Four UI routes returned
  HTTP200 at 1440 and 390 with authenticated GET-only browser traffic, loaded
  content, no unhandled JavaScript errors and no page-wide overflow. No real
  apply, rollback, archive, lifecycle/review mutation, preview audit, explicit
  service status-check audit or restart was invoked for this verification.

Reproducible browser runner: `scripts/validate_ux10_browser.cjs`. It needs an
already available Playwright installation and Chromium, not a new project dependency.
Set `UX_BROWSER_MODULE` to the installed module path and optionally
`UX_BROWSER_EXECUTABLE` to the existing Chromium executable. This environment also
needs `LD_LIBRARY_PATH` pointing to the extracted libasound library under the
local browser cache; no system package was installed. `UX_BASE_URL` defaults to
`http://127.0.0.1:3001`; `UX_BROWSER_OUTPUT` defaults to `/tmp/ux10-browser`.
Screenshots and `results.json` are local artifacts, not committed telemetry data.
The final run uses `UX_BROWSER_OUTPUT=/home/lele/.cache/ux10-browser/evidence`
to preserve its screenshots/results across host restarts.

Final Python command:

```bash
.venv/bin/python -m pytest -q \
  tests/test_ux_detection_operations_rbac.py \
  tests/test_detection_control_plane.py \
  tests/test_detection_control_validation.py \
  tests/test_detection_control_semantic_context.py \
  tests/test_detection_config_versioning.py \
  tests/test_detection_rule_lifecycle.py \
  tests/test_detection_operations.py \
  tests/test_service_operations.py \
  tests/test_security_refactor_helpers.py \
  tests/test_detection_engineering_analyzer.py \
  tests/test_detection_engineering_recommendations.py \
  tests/test_detection_engineering_models.py \
  tests/test_api_route_inventory.py \
  tests/test_ux_overview_pages_static.py
```

The live preview is `http://127.0.0.1:3003`, forwarding the unchanged
`/api-backend` prefix to the existing API on port8008 and UI to port3001.
The temporary proxy also forwards Next's development WebSocket connection;
without it this Next version remained at the pre-hydration loading state.
Existing services on ports3000 and3002 were not stopped or reconfigured.
Temporary preview processes must be restarted after a host reboot. The local
support scripts are under `/home/lele/.cache/ux10-browser`; they are not deployed
or part of the repository. Live authentication tokens were short-lived, passed
through process stdin and neither logged nor stored in the evidence directory.

## Manual Verification

Use the preview URL above or the normal deployment after updating this branch.
Use existing ADMIN, ANALYST and VIEWER accounts. Do not complete a live mutation
solely for UX approval. Create/modify/approve/reject/disable/archive/delete/apply/
rollback/restart execution must use an isolated fixture/demo environment. Native
prompts are intentionally retained where they collect reasons.

At `/settings/detection-control`:

1. Check title, Dashboard breadcrumb and Detection sidebar selection; observe role metadata and operator-only external Observability link.
2. Compare Unified Inventory, Rules, Exceptions, Sources, Policies and Failed Validation to the prior baseline/API; check active/disabled counts.
3. Scroll to existing inventory; switch Rules, Exceptions, Sources, Policies and Service Control; horizontally scroll to metadata/actions.
4. Select each configuration domain; inspect active checksum/actor/time/restart flag. Click Details on a history row, inspect reason/payload/rollback ID, then Close.
5. As ADMIN/ANALYST, run Validate only on safe fixture data. VIEWER must have validation disabled.
6. Inspect valid, warnings, invalid and Not run states in the fixture runner. HTTP200 with valid=false must display a failed/blocked result.
7. Run Preview diff on fixture data; compare counts and summaries, then expand Raw diff / technical changes and inspect full from/to JSON.
8. As ADMIN, observe Apply disabled before valid validation and diff. With fixture prerequisites satisfied, open Apply version and Cancel the reason prompt. Repeat with a fixture reason and Cancel confirmation; no apply request may occur.
9. Inspect Rollback only on a non-active version as ADMIN. Cancel its reason prompt and then its second confirmation in separate attempts; no rollback request may occur.
10. Open Detection Lifecycle; inspect entries and all eight table columns. Close and reopen without losing other page sections.
11. Compare actions for DRAFT/PROPOSED/APPROVED/ACTIVE/DISABLED/SUPERSEDED/FAILED_VALIDATION/REJECTED/ROLLED_BACK. Only ADMIN may approve/reject/apply/disable; only approved items may apply; ownership still limits ANALYST editing/deleting.
12. Inspect managed-entry fields and actions; Edit/Manage must prefill the same data. Check null Last Validation is Not run, not OK. Exercise save/validate/enable/disable/archive only in the isolated fixture environment.
13. In Exceptions and Noise Operations, select Exceptions; inspect type, scope, state, expiry and review state independently.
14. Select Noise Suppression; verify ACTIVE is not resolution green and broad/dangerously broad scope remains prominent. No numeric risk score should appear.
15. Inspect Status/Scope/Review/search filters and Review Workflow status/date/notes. Exercise Mark/Extend only with isolated fixture records and verify unchanged request fields.
16. As operator, run a fixture row's match preview; selection and evidence must refer to that row. Check Preview / expected matches, observed count/provenance, source/ID/time/agent/rule/payload. VIEWER detail Preview is disabled.
17. In Service Operations inspect service status/impact/command family/last operation and config restart clearance. Do not use audited live Status checks purely for smoke.
18. In an isolated fixture environment open an allowed service's Restart dialog as ADMIN, enter a reason and run preview. Check allowed/blocked, warnings, affected service/config and post-check; nothing executes automatically.
19. Clear the reason: preview/execute must be disabled. Changing a previously previewed reason must invalidate preview and clear the checkbox.
20. Open archive/delete/restart dialogs and test Cancel/Escape. For restart, tab through controls; background controls must remain inert. No request executes on dismissal.
21. In the restart fixture, an allowed preview alone is insufficient: explicitly check impact consent before execute enables. Inspect only in live environments; do not press Restart service on production.
22. Inspect fixture failure/success operation results and lifecycle history actors/comments/times. Check last operation/config clearance without mistaking preview success for restart success.
23. Inspect raw lifecycle Rule Content, Raw lifecycle diff, config raw diff and retained version payload preview. Technical data must remain readable and scrollable.
24. Repeat with all three roles. ANALYST retains config validation/diff, lifecycle drafting/own edits and review/preview; ADMIN retains managed writes/config activation/restarts; VIEWER remains read-only. Backend remains authoritative.
25. Compare every row of the inventory/matrix above to the approved baseline. Stop approval if any capability, scope, field, confirmation or gate is missing.

At `/network-events`: compare four KPIs; filter event type/source/destination/
hostname; Apply filters, Clear and Refresh; inspect event distribution, destination
country/resolver context, hostnames and all seven table columns. Check numeric IDS
severity and read-only evidence. Use browser interception to test empty/503/loading,
never alter live telemetry to manufacture those states.

At `/dns-telemetry`: compare total/freshness/top client/type; filter domain/client/
record type, Apply filters, Reset and Refresh. Inspect query-type distribution,
top clients/domains and all six columns including raw line, resolver and source.
Check blue A type does not imply health; test empty/error/loading through fixtures.

At `/system-information/operation-history`: regression only. Filter service,
operation and status, search by reason/user/service, change page size, use Previous/
Next and Reset. Inspect status/pre-post/config/actor/time/message fields. There was
no separate detail dialog in this page's baseline; none is claimed or invented.

Repeat at desktop widths and 390px. Dense tables should scroll within their own
surface, forms must not overlap, and dangerous controls/dialog Cancel must remain
reachable. Final cross-product responsive work remains UX-12.

## Limits And Approval Gate

Production mutations and actual service interruptions are deliberately excluded.
Live browser checks use an existing ADMIN account; ANALYST/VIEWER behaviors are
verified using browser fixtures and backend role tests. Runtime-specific restart
permissions/allowlists remain backend-enforced and must be evaluated operationally
before any authorized restart, independently of this UX approval.

Native reason/confirmation prompts retain browser-dependent appearance. Some
compact table metadata remains truncated as in the baseline; technical diff JSON
is expandable and tables scroll. No generalized page redesign, new dropdown/
drawer framework, backend refactor or UX-11 work was performed.

The user must approve UX-10 before any next phase starts.
