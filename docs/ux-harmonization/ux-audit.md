# AI SOC v0.9.0 UX Audit

Phase: UX-01 - UX audit and foundation baseline
Branch: `feature/ux-harmonization-01-audit-foundation`
Baseline: `main` at `c728228`
Scope: Static frontend UX audit only. No runtime UI code was changed.

## Evidence Reviewed

- Frontend route files under `frontend/src/app`.
- Shared shell and UI components under `frontend/src/components`.
- Styling baseline in `frontend/src/app/globals.css`.
- Validation scripts declared in `frontend/package.json`, `docs/README.md`, and `CONTRIBUTING.md`.

No screenshot artifacts were created in this phase. The frontend package does not expose a screenshot or browser-test script, and no Playwright/Cypress config is present in the repository.

## Route Inventory

| Route | Product area | Source | Current baseline |
|---|---|---|---|
| `/` | Dashboard / Overview | `frontend/src/app/page.tsx` | Uses `AppNavigation`, `EnterprisePageHeader`, `EnterpriseSection`, chart cards, KPI strip, filters and data tables. This is the strongest seed for the target product language. |
| `/login` | Authentication | `frontend/src/app/login/page.tsx` | Standalone centered sign-in form. No application shell. Preserves login errors, disabled submit state, and session handoff. |
| `/assistant` | AI Assistant | `frontend/src/app/assistant/page.tsx`, `frontend/src/components/assistant/GlobalAssistantWorkspace.tsx` | Uses `AppNavigation` plus a full assistant workspace. Global assistant is available to ADMIN/ANALYST only. |
| `/incidents` | Investigation | `frontend/src/app/incidents/page.tsx` | Dense incident grid with summary counters, filter bar, selected-row preview pane, pagination, demo mode, and demo deletion for authorized users. |
| `/incidents/[id]` | Investigation detail | `frontend/src/app/incidents/[id]/page.tsx` | Large command-center page covering lifecycle, reports, AI brief, playbooks, remediation, evidence, timeline, graph, notes, audit and RBAC-aware actions. Highest regression risk. |
| `/cases` | Investigation | `frontend/src/app/cases/page.tsx` | Case queue with metrics, quick views, search/filter controls, wide table, AI/readiness/SLA badges, demo controls and demo deletion. |
| `/cases/[id]` | Investigation detail | `frontend/src/app/cases/[id]/page.tsx` | Large case detail workflow covering case metadata, workflow edits, linked incidents, AI analysis jobs, action suggestions, closure, timeline, graph, playbooks and audit. Highest regression risk. |
| `/cases/kanban` | Investigation | `frontend/src/app/cases/kanban/page.tsx` | Horizontal Kanban board with metrics, search, hide-closed toggle and compact-card toggle. |
| `/detection-quality` | Detection | `frontend/src/app/detection-quality/page.tsx` | Detection quality dashboard with synthetic test runner, metrics, coverage/priority panels, LLM guidance, filters and tables. Synthetic execution is ADMIN/ANALYST only. |
| `/settings/detection-control` | Detection / Operations / Governance | `frontend/src/app/settings/detection-control/page.tsx`, `LifecyclePanel.tsx`, `OperationsPanel.tsx`, `ServiceOperationsPanel.tsx` | Dense control plane for inventory, config versions, validation, diff, apply/rollback, lifecycle entries, exceptions/noise operations and governed service restarts. High-risk admin surface. |
| `/health` | Operations | `frontend/src/app/health/page.tsx` | Native health dashboard for API, database, Wazuh, Ollama, Qdrant, worker heartbeat, AI runtime and observability links. Grafana remains linked externally through navigation and native links. |
| `/executive` | Executive / Overview | `frontend/src/app/executive/page.tsx` | Lower-density posture dashboard, decision brief, assurance, management queue, exposure matrix and latest high-risk queues. |
| `/admin/users` | Governance / Users | `frontend/src/app/admin/users/page.tsx` | Admin user management plus self-service profile behavior for non-admin users. Create, edit role/status, reset password and delete are guarded. |
| `/system-information/security-audit` | Governance / Audit | `frontend/src/app/system-information/security-audit/page.tsx` | Canonical security audit trail with admin-only content, metrics, filters, search, event table and JSON detail expansion. |
| `/security-audit` | Governance / Audit alias | `frontend/src/app/security-audit/page.tsx` | Redirects to `/system-information/security-audit`. |
| `/admin/security-audit` | Governance / Audit alias | `frontend/src/app/admin/security-audit/page.tsx` | Redirects to `/system-information/security-audit`. |
| `/system-information/operation-history` | Operations / Audit | `frontend/src/app/system-information/operation-history/page.tsx` | Governed service operation history with metrics, filters, search, pagination and status badges. |
| `/operation-history` | Operations alias | `frontend/src/app/operation-history/page.tsx` | Redirects to `/system-information/operation-history`. |
| `/admin/operation-history` | Operations alias | `frontend/src/app/admin/operation-history/page.tsx` | Redirects to `/system-information/operation-history`. |
| `/settings/ai-providers` | AI Governance | `frontend/src/app/settings/ai-providers/page.tsx` | Provider registry, health, local profiles, external provider controls, provider tests and save operations. |
| `/settings/ai-data-control` | AI Governance | `frontend/src/app/settings/ai-data-control/page.tsx` | Policy library, policy workbench, redaction preview, evaluation preview and decision history. |
| `/settings/semantic-memory` | AI Governance / Knowledge | `frontend/src/app/settings/semantic-memory/page.tsx` | Qdrant status, capabilities, indexed documents, search, auto-index status and admin-controlled memory operations. Uses a different shell structure from most pages. |
| `/network-events` | Operations / Telemetry | `frontend/src/app/network-events/page.tsx` | Read-only Suricata telemetry with filters, metrics, distribution panels and event data. |
| `/dns-telemetry` | Operations / Telemetry | `frontend/src/app/dns-telemetry/page.tsx` | Read-only endpoint DNS evidence with filters, metrics, ranked panels and event data. |
| `/api/auth/session` | Frontend API utility | `frontend/src/app/api/auth/session/route.ts` | Stores the auth cookie for the browser shell. Not a UX page. |
| `/api/auth/logout` | Frontend API utility | `frontend/src/app/api/auth/logout/route.ts` | Clears the auth cookie. Not a UX page. |

## Current Shell And Navigation

- Most authenticated pages render `<main className="min-h-screen bg-slate-950 text-slate-100">`, then a centered container with `max-w-[1600px]` or `max-w-[1900px]`, `px-4`, and `py-4`.
- `frontend/src/components/AppNavigation.tsx` is a fixed desktop sidebar at `xl` via `.ai-soc-sidebar`; below `xl` it behaves as an in-flow wrapped nav.
- `frontend/src/app/globals.css` shifts main content on desktop using `main:has(.ai-soc-sidebar) > div`, `max-width: calc(100vw - 18rem)`, `margin-left: 17rem`.
- Sidebar grouping exists through flat nav items plus collapsible Settings and System Information sections. It does not yet match the requested OVERVIEW / INVESTIGATION / DETECTION / OPERATIONS / GOVERNANCE grouping.
- Grafana/Observability is an external navigation item for ADMIN/ANALYST. It uses `target="_blank"` and `rel="noreferrer"`.
- Breadcrumbs are not centralized. Pages use local links such as "Back to dashboard", "Dashboard", "Case Queue", and "Back to cases".

## Current Shared Components

Existing reusable components:

- `EnterprisePageHeader`
- `EnterpriseSection`
- `EnterpriseButton`
- `EnterpriseBadge`
- `EnterpriseMetricCard`
- `EnterpriseChartCard`
- Assistant components: `GlobalAssistantWorkspace`, `ContextualAssistantPanel`, `AssistantAnswer`, `AssistantSources`
- Investigation components: `IncidentTimeline`, `InvestigationGraph`
- SOC-specific panels: `GovernedRemediationPanel`, `RecommendedPlaybooksPanel`

The enterprise components are useful seeds, but adoption is partial. Dashboard and Cases use them more than Incidents, Detection Control, Health, Users, Security Audit and Operation History.

## Per-Page UX Audit

| Page | Container and padding | Header and actions | Cards, tables and filters | States | Responsive and accessibility notes |
|---|---|---|---|---|---|
| Dashboard | `max-w-[1600px] px-4 py-4`; desktop shell offset from global CSS. | `EnterprisePageHeader`, title `text-2xl`, refresh action. No breadcrumb. | Mix of enterprise sections, KPI cards, chart cards, local tables and dense filters. | Error banner, enterprise loading section, empty table rows in local helpers. | Good desktop density. Uses many icon+text buttons. Some local helper components duplicate future primitives. |
| Login | Centered `max-w-md` form with `px-4`; no shell. | Product mark plus `Sign in` title. | Local inputs and submit button. | Inline error and disabled submit state. | Simpler than app shell as desired. Needs future focus/contrast pass but should remain standalone. |
| Global Assistant | `max-w-[1900px] px-4 py-4`; assistant workspace manages its own max width. | Assistant header inside workspace, not page-level header. | Conversation log, starter prompts, mode segmented buttons, semantic discovery checkbox. | Role denial, capability error, pending, completed, cancelled and failed states. | Good ARIA labels for icon buttons/input; technical details and sources remain accessible. |
| Incidents | `max-w-[1900px] px-4 py-4`; nested bordered console. | Custom header with local dashboard link, title row, demo and refresh actions. | Dense counters, custom filter grid, table-fixed incident grid, selected summary pane. | Error panel, text loading state, no-match handling through table/preview behavior. | High-density and operationally useful. Row selection plus explicit links/actions need later consistency review to avoid ambiguous click targets. |
| Incident Detail | `max-w-[1600px] px-4 py-3`. | Custom header with dashboard link, title, refresh, create case, Markdown and JSON report actions. | Many local sections, details, panels, badges, status controls, evidence, timeline, graph, AI, remediation and notes. | Loading/error sections plus many local async lines for AI/remediation/playbooks. | Very high risk due size and interaction count. Must avoid losing RBAC-gated controls and technical AI metadata. |
| Cases | `max-w-[1600px] px-4 py-4`. | Custom header with dashboard link, title, demo and refresh actions. | Uses enterprise sections for controls/table; local quick views, local filter selects, local case KPI, wide table. | Error banner, enterprise loading section, empty state for no matching cases. | Good queue density. Uses larger rounded controls than other dense pages. Duplicate severity/status/SLA badge mappings. |
| Case Detail | `max-w-[1600px] px-4 py-4`. | Custom header with case back link, title and metadata chips. | Many local sections for workflow, linked incidents, actions, closure, AI, graph, timeline and audit. Includes scoped inline CSS under `data-case-focus`. | Loading/error panels, action and AI generation states, closure/semantic context states. | Highest risk with Incident Detail. Inline scoped CSS is a consolidation smell and can hide actual component inconsistency. |
| Case Kanban | `max-w-[1800px] px-4 py-4`. | Custom header with case queue link, queue view and refresh actions. | Local metrics, filter/search panel, horizontal board, local columns/cards/badges. | Error banner, loading section, empty columns. | Horizontal scroll is suitable. Toggle buttons need future shared control treatment. |
| Detection Quality | `max-w-[1600px] px-4 py-4`. | Custom header with dashboard link and refresh. | Synthetic runner, many local metric/panel/table/guidance components. | Error, loading, synthetic error/result, viewer read-only explanation, guidance loading/error. | Strong operational density. Uses local tone functions and badge bases instead of common severity/status primitives. |
| Detection Control Plane | `max-w-[1600px] px-4 py-4`. | Custom settings header with refresh disabled by RBAC. | Dense metrics, operations panels, version governance, lifecycle panel, service operations, managed entries, source inventory and forms. | Error/loading/read-only panels, validation/diff/apply results, service restart preview/results. | High-risk admin surface. Dangerous actions have prompts/confirmation and should gain consistent danger affordances later without changing semantics. |
| Health | `max-w-[1600px] px-4 py-4`. | Custom header with refresh. | Health status tiles, component tiles, AI provider runtime, ingest metrics, details panels and native observability links. | Error, loading, empty component sections where applicable. | Strong use of collapsed details for dense operations. Mixes `rounded-lg`, `rounded-xl`, and `rounded-sm`. |
| Executive | `max-w-[1600px] px-4 py-4`. | Custom header with auto-refresh badge and refresh. | Lower-density decision sections, pulse bar, management queue, exposure matrix and high-risk tables. | Error and loading sections. | Good audience distinction. Local tone/badge helpers duplicate Dashboard/Cases. |
| Users | `max-w-[1600px] px-4 py-4`. | Custom header changes title/eyebrow for admin vs self-service. | Admin create-user form, user table, inline role/status controls and row actions. | Error and loading states. No explicit empty state observed for zero users. | RBAC-sensitive: non-admin profile behavior must stay intact. There is a small formatting anomaly near `)}          <section`. |
| Security Audit | `max-w-[1600px] px-4 py-4`. | Custom header with dashboard link and refresh. | Admin-only metrics, filters/search, audit event table and detail display. | Error; admin-only content. | Strong density. Needs future forbidden/read-only state treatment for non-admin rather than relying only on hidden content. |
| Operation History | `max-w-[1600px] px-4 py-4`. | Custom header with dashboard link and refresh. | Metrics, filters/search, table and pagination. | Error, loading, empty state. | Good structure, but local `statusTone`, filter controls and metric card duplicate other operations pages. |
| AI Providers | `max-w-[1600px] px-4 py-4`. | Custom settings header with refresh. | Provider summary cards, registry settings, provider rows, local status badges, save/test controls. | Error, notice, health/test result states. | Governance controls are dense and specific. Boolean badges need common StatusBadge semantics. |
| AI Data Control | `max-w-[1600px] px-4 py-4`. | Custom settings header with refresh. | Policy library, workbench, provider scope toggles, redaction/evaluation preview, decision history. | Error, notice, preview result/error states. | Good product-specific workflow. Risk/mode badges are local and should become SOC-specific primitives. |
| Semantic Memory | `max-w-[1800px] px-3 py-3`, custom flex shell with an extra `<aside>` around `AppNavigation`. | Custom header with refresh. | Metrics, collapsible sections, Qdrant/index details, search, operations. | Error, loading, forbidden/read-only behavior, empty knowledge sections. | Shell structure differs from all other pages and may interact oddly with global sidebar CSS. |
| Network Activity | `max-w-[1600px] px-4 py-4`. | Custom header with dashboard link and enterprise refresh button. | Local metrics, panels, filters, distribution and tables. | Error and read-only empty text states. No top-level loading gate before metrics. | Good read-only telemetry clarity. Local panel/badge/control constants duplicate DNS and future operations primitives. |
| DNS Telemetry | `max-w-[1600px] px-4 py-4`. | Custom header with dashboard link and enterprise refresh button. | Local metrics, filters, ranked panels and DNS event data. | Error, loading, multiple empty states. | Similar to Network Activity but with slightly different layout and control labels. Good consolidation candidate. |

## Component Duplication Findings

- Page headers are implemented at least three ways: `EnterprisePageHeader` on Dashboard; custom headers on most pages; workspace-specific header on Assistant.
- Breadcrumb/back navigation is local text and link markup across pages. Labels and hierarchy differ by page.
- Button classes are repeated across pages with `h-8`, `h-9`, `rounded-sm`, `rounded-md`, `rounded-lg`, `rounded-xl`, `border-slate-700`, `bg-slate-900`, and cyan primary styles. `EnterpriseButton` exists but is not the canonical action primitive yet.
- Badge and tone logic is repeated in many files: Dashboard, Incidents, Incident Detail, Cases, Case Detail, Kanban, Detection Quality, Health, Executive, Security Audit, Operation History, AI Provider/Data Control, Detection Control panels, Timeline, Graph, Remediation and Recommended Playbooks.
- Severity/risk color decisions are inconsistent. Examples include Critical/High sometimes both red, High sometimes orange, risk score buckets sometimes warning/danger, and MITRE sometimes red independent of severity.
- Status styles are page-local and domain-specific. This is reasonable semantically, but the visual grammar should be centralized with a domain mapping layer.
- Metric cards exist as `EnterpriseMetricCard`, Dashboard-specific KPI cards, Health `StatusTile`, Detection Control `MetricCard`, Security Audit/Operation History metric cards, Executive pulse cards and local DNS/Network cards.
- Tables are hand-built everywhere. Sticky headers, row hover, padding, column sizing, empty rows and horizontal scroll differ.
- Filter bars are local and inconsistent: sections, grids, labels, quick-view buttons, search input wrapping and reset/apply placement vary.
- Empty, loading and error states are mostly inline text/panels. Some pages include icons; others use plain text only.
- The Case Detail page uses scoped inline CSS under `data-case-focus` to normalize density, which indicates missing layout primitives and can make later component work harder.
- Local `IconButton` helpers exist inside Detection Control panels. They should be consolidated before broad migration.

## Semantic Consistency Findings

- Current dominant product direction is dark enterprise: `bg-slate-950`, `bg-slate-900`, `border-slate-800`, `text-slate-*`, and cyan as primary interaction/accent.
- Existing additive CSS variables in `globals.css` define enterprise colors and severity values, but most page code still uses hardcoded Tailwind color classes directly.
- Current colors generally align to meaning, but mappings are not canonical:
  - Red/rose: errors, destructive actions, critical/high risk, failed states.
  - Orange/amber: warning, SLA, broad/dangerous scope, degraded states.
  - Yellow is rarely used directly.
  - Cyan/sky/blue: primary actions, active states, info and links.
  - Emerald/green: success, healthy, enabled, completed.
  - Violet: executive, case, AI and semantic/correlation concepts.
  - Slate: neutral and metadata.
- Several pages encode state primarily through color and short text. Future phases should keep labels/icons with semantic colors.

## High-Risk Pages

1. `frontend/src/app/incidents/[id]/page.tsx`
   - Very large file with many local components and callbacks.
   - Protect incident status update, notes, case creation, report downloads, AI brief generation, playbook generation, remediation analysis, dry-run, rollback readiness, audit trail, replay, controlled workflow actions, network/DNS evidence, timeline and graph.

2. `frontend/src/app/cases/[id]/page.tsx`
   - Very large file with workflow, actions, AI jobs, closure, timeline, linked incidents, graph and audit behavior.
   - Protect case workflow saves, generated analysis, generated action suggestions, action create/update, closure checklist, closure semantic context, linked incident navigation and report downloads.

3. `frontend/src/app/settings/detection-control/page.tsx` plus child panels
   - Contains validation, config version diff/apply/rollback, managed rules, exceptions/noise controls, lifecycle state transitions and service restart controls.
   - Protect ADMIN/ANALYST/VIEWER distinctions, prompts/confirmations, restart preview and audit behavior.

4. `frontend/src/components/assistant/*`
   - Must preserve sources, limitations, grounding/fallback states, provider/model metadata, latency, semantic status, technical details and read-only boundaries.

5. `frontend/src/app/admin/users/page.tsx` and `frontend/src/app/system-information/security-audit/page.tsx`
   - RBAC-sensitive governance surfaces. Avoid visual changes that imply actions are available when backend authorization will deny them.

## Functional Areas That Must Not Regress

- Auth session lifecycle, login errors, logout behavior and expired-session redirects.
- ADMIN/ANALYST/VIEWER RBAC behavior in navigation, assistant, detection control, synthetic tests, semantic memory, users and audit pages.
- Grafana Observability must remain an external link and must not be embedded.
- Incident list filters, selected-row preview, row open behavior, pagination, demo mode and demo deletion safeguards.
- Incident Detail lifecycle/status update, notes, case creation, report downloads, AI brief, recommended playbooks, remediation analysis, dry-run, rollback readiness, remediation audit trail, replay, controlled workflow action creation, evidence/timeline/graph visibility and raw/technical details.
- Case queue filters, quick views, table actions, demo behavior and incident relationship links.
- Case Detail workflow save, action management, AI generation jobs, closure checklist, semantic context, linked incidents, timeline, graph, audit trail and exports.
- Detection Quality synthetic test runner permissions, synthetic result feedback, LLM guidance and detection calculations.
- Detection Control validation, diff, apply, rollback, lifecycle transition rules, exception/noise review, match preview, restart preview and restart execution confirmation.
- Health native component status, AI runtime visibility, worker/backlog signals and observability links.
- AI provider settings, provider health, tests, external-provider controls and local profile visibility.
- AI Data Control policy saves, redaction preview, evaluation preview and decision history.
- Semantic Memory Qdrant visibility, search, auto-index status and admin operations.
- Security Audit filters and audit detail semantics.

## Recommended Consolidation Targets

Use `docs/ux-harmonization/ux-design-system.md` as the target architecture for later phases. The highest-return consolidation order is:

1. Semantic tokens and tone mapping:
   - App/surface/border/text tokens.
   - Severity, risk, status, health and action tones.
   - Keep domain states as-is; centralize only presentation.

2. Shell and navigation:
   - AppShell owning sidebar placement, max content width and page gutters.
   - Predictable nav groups and external-link treatment.
   - Breadcrumb component fed by route metadata.

3. Page composition:
   - PageHeader, PageSection, Panel, MetricCard, DataTable and FilterBar.
   - Preserve density variants for overview, list, detail and control-plane surfaces.

4. Primitive controls:
   - Button, IconButton, SearchInput, Select/Input wrappers, Tabs, Modal/Drawer, ConfirmationDialog and Toast/Notice.

5. SOC-specific displays:
   - SeverityBadge, StatusBadge, RiskScore, SLAIndicator, MITREBadge, AgentBadge, CorrelationBadge, SourceBadge, GroundingBadge and HealthStatusBadge.

6. Shared states:
   - Loading, empty, error, forbidden/read-only and degraded/fallback states.

## Baseline Behavior Notes For Future Manual Comparison

- Most pages are client components and fetch through `authFetch`, which prefixes `NEXT_PUBLIC_API_BASE_URL` or `http://localhost:8008`.
- Pages frequently load current user through `fetchCurrentUser` or stored user state to determine local UI affordances. This is presentation gating only; backend RBAC must remain authoritative.
- Tables generally use horizontal scroll for dense SOC data. Mobile behavior is mostly in-flow stacking plus overflow, not fully card-adapted.
- Many details and raw payloads use `<details>` or scrollable `<pre>` blocks. Future harmonization should keep technical data available but less visually dominant.
- Current accessibility strengths include labeled selects in several pages, `aria-label` on some assistant icon buttons, `role="alert"`/`role="status"` in the assistant, and visible focus borders on many inputs.
- Current accessibility gaps include inconsistent icon-only button labeling outside the assistant/control panels, inconsistent focus classes, color-heavy badges, and non-centralized table semantics.

## UX-01 Conclusion

The application already has a coherent dark SOC direction and several reusable enterprise components, but consistency is uneven because most pages still encode layout, tone, badges, filters, cards and states locally. UX-02 should centralize semantic tokens and tone mappings first, then UX-03 can promote the existing enterprise components into a broader primitive set before shell/page migration begins.
