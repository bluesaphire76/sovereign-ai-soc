# AI SOC v0.9.0 Target UX Architecture

Phase: UX-01 - foundation definition
Companion audit: [ux-audit.md](ux-audit.md)

This document defines the intended UX architecture for the v0.9.0 harmonization program. It is conceptual guidance for later phases and does not authorize broad refactors in UX-01.

## Product Principles

- Preserve the current dark enterprise SOC direction.
- Keep analyst workflows dense, scannable and operationally precise.
- Use semantic color, labels and icons together. Do not communicate state through color alone.
- Preserve existing backend payloads, route contracts, state names and RBAC behavior.
- Make reusable components thin and practical. Avoid large abstraction layers.
- Keep Grafana external. The AI SOC native UI may link to Grafana but must not embed it.
- Keep AI assistance transparent: sources, limitations, fallback state and technical metadata must stay available.

## Architecture Overview

The harmonized frontend should converge on these layers:

1. Design tokens
   - CSS variables and Tailwind-compatible semantic classes for product color, spacing, radius, typography and elevation.

2. Primitives
   - Buttons, badges, panels, inputs, tabs, dialogs, tables and common UI states.

3. SOC-specific components
   - Severity, status, risk, SLA, MITRE, source, correlation, grounding, health and governance displays.

4. Layout patterns
   - App shell, page headers, overview pages, list pages, entity details and control/governance pages.

5. Product pages
   - Route files should compose shared patterns and only keep page-specific data loading, state transitions and domain behavior.

## AppShell

Target responsibility:

- Own authenticated page chrome.
- Render Sidebar and optional GlobalHeader region if later needed.
- Define consistent content gutters, desktop sidebar offset and max widths.
- Provide slots for breadcrumbs, page header, main content and optional contextual panels.
- Preserve unauthenticated routes such as `/login` as standalone pages.

Recommended content widths:

- Overview pages: max 1600px.
- High-density lists and assistant workspace: max 1900px when needed.
- Detail pages: max 1600px unless evidence/table width requires a wider variant.
- Settings/control-plane pages: max 1600px, with explicit dense grid support.

## Sidebar

Target responsibility:

- Centralize navigation entries, active matching, external-link affordances and role-sensitive visibility.
- Use consistent icon size, row height, hover, selected and disabled states.
- Group entries using only routes that exist.

Recommended groups:

| Group | Routes |
|---|---|
| Overview | `/`, `/executive` |
| Investigation | `/incidents`, `/cases`, `/cases/kanban` |
| Detection | `/detection-quality`, `/settings/detection-control` |
| Operations / Telemetry | `/health`, `/network-events`, `/dns-telemetry`, `/system-information/operation-history`, external Observability |
| Governance | `/admin/users`, `/system-information/security-audit`, `/settings/ai-providers`, `/settings/ai-data-control`, `/settings/semantic-memory` |
| AI | `/assistant` where permitted |

Grafana/Observability remains an external ADMIN/ANALYST link.

## Breadcrumbs

Target responsibility:

- Replace local back-link variations with route-aware breadcrumbs.
- Use concise labels and preserve obvious return paths.
- Avoid redundant breadcrumbs on single-node pages.

Examples:

- `Dashboard`
- `Incidents`
- `Incidents / #5333`
- `Cases`
- `Cases / #42`
- `Settings / Detection Control Plane`
- `System Information / Security Audit Trail`

## PageHeader

Target responsibility:

- Standardize title, description, eyebrow, icon, metadata, status/severity adornments and actions.
- Support dense enterprise sizing by default.
- Place primary and secondary actions predictably at the end of the header.

Suggested props:

```ts
type PageHeaderProps = {
  eyebrow?: string;
  title: string;
  description?: string;
  icon?: React.ReactNode;
  breadcrumbs?: React.ReactNode;
  metadata?: React.ReactNode;
  status?: React.ReactNode;
  actions?: React.ReactNode;
  density?: "compact" | "standard";
};
```

## PageSection And Panel

Target responsibility:

- Provide consistent borders, backgrounds, padding, section titles, descriptions and action placement.
- Keep cards at small radius. Do not nest cards inside cards.
- Support dense, standard and roomy variants based on page type.

Usage guidance:

- `PageSection`: full-width page band or major content section.
- `Panel`: bounded tool/detail surface inside a layout grid.
- `Card`: repeated item only, such as Kanban cards, metric cards or source records.

## Buttons

Target responsibility:

- Centralize primary, secondary, ghost, success, warning and danger styles.
- Provide icon+text and icon-only forms.
- Ensure icon-only buttons have `aria-label` and `title` or Tooltip.
- Preserve disabled states and keyboard focus.

Action hierarchy:

| Tone | Use |
|---|---|
| Primary | Main safe action for the current surface, such as Apply filters or Save. |
| Secondary | Routine actions such as Refresh, Queue view or Open detail. |
| Ghost | Low-emphasis actions such as Reset filters where appropriate. |
| Success | Explicit positive lifecycle actions where current semantics support it. |
| Warning | Operationally sensitive actions such as restart preview or broad-scope review. |
| Danger | Delete, archive, disable, reject or destructive operations. |

Danger actions should remain separated from routine actions and preserve confirmations.

## Badge

Target responsibility:

- Provide a low-level labeled badge with neutral, info, success, warning, danger and muted tones.
- Keep the component semantic, not page-specific.
- Support optional icon and compact sizing.

## SeverityBadge

Target responsibility:

- Present existing severity values only.
- Normalize visual mapping without renaming backend values.

Initial target mapping:

| Existing value | Tone |
|---|---|
| `CRITICAL` | critical / red |
| `HIGH` | high / orange-red |
| `MEDIUM` | medium / amber |
| `LOW` | low / blue or slate-blue informational |
| unknown/null | neutral |

If a page currently derives severity from numeric risk, the component should make that derivation explicit through props or copy.

Green/success semantics are reserved primarily for healthy, successful, resolved, completed or equivalent positive states. Severity presentation must not imply that a `LOW` severity event is healthy or resolved.

## StatusBadge

Target responsibility:

- Normalize visual representation while preserving actual status names.
- Use domain-specific mapping tables where needed.

Example domains:

- Incident lifecycle: `OPEN`, `TRIAGED`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`, `FALSE_POSITIVE`, legacy escalated states.
- Case lifecycle: `OPEN`, `TRIAGED`, `INVESTIGATING`, `ESCALATED`, `CLOSED`, `FALSE_POSITIVE`.
- Detection control lifecycle: draft, submitted, approved, rejected, applied, disabled and validation states.
- Health: `OK`, `WARN`, `ERROR`, unavailable.
- AI/runtime: ready, warming, disabled, unavailable, fallback and degraded states.

Do not introduce new status names.

## MetricCard

Target responsibility:

- Replace local dashboard, health, executive, detection, audit and telemetry metric variants.
- Support title, value, subtitle, icon, tone, trend/metadata and compact density.
- Keep text sizes constrained for dashboard/control surfaces.

## DataTable

Target responsibility:

- Standardize table wrapper, header style, row hover, selected row, empty row, horizontal overflow and pagination controls.
- Keep tables dense and scan-friendly.
- Allow page-specific column definitions and cell renderers.
- Preserve row click behavior only when unambiguous.

Table requirements:

- Header text uses compact uppercase metadata style.
- Rows have predictable hover/selected states.
- Wide SOC tables prefer horizontal scroll over hiding critical columns.
- Empty states should state whether no data exists or filters removed all results.

## FilterBar

Target responsibility:

- Centralize search, select filters, quick views, reset/apply actions and result counts.
- Support list/operations density.
- Keep filter labels accessible.

Controls to standardize:

- `SearchInput`
- `FilterSelect`
- `FilterChip`
- segmented quick views
- checkbox/toggle for binary filters
- date inputs
- reset/apply actions

## Tabs

Target responsibility:

- Standardize tabs/subnavigation for detection control, details pages and settings-like surfaces.
- Use actual routes or local state deliberately, not mixed accidentally.
- Provide keyboard focus and selected-state semantics.

## Modal, Drawer And ConfirmationDialog

Target responsibility:

- Provide consistent dialog structure for create/edit forms, detail drawers and confirmation flows.
- Use ConfirmationDialog for dangerous operations where replacing `window.confirm` is safe.
- Preserve required reason prompts for apply/restart/disable workflows.
- Keep dangerous actions visibly separated and hard to trigger accidentally.

## EmptyState, ErrorState And Skeleton

Target responsibility:

- Standardize loading, empty, error, forbidden, read-only, degraded and fallback states.
- Keep messages concise and operational.
- Use icons where they clarify state.
- Use `role="alert"` for actionable errors and `aria-live` for async progress where appropriate.

State types:

- Loading inline
- Loading page
- Empty dataset
- Empty filtered result
- Error retryable
- Error forbidden
- Read-only permission notice
- Degraded dependency
- Deterministic fallback

## Tooltip And Dropdown

Target responsibility:

- Tooltip: required for unfamiliar icon-only controls.
- Dropdown: use for compact action menus only when the action hierarchy remains clear.
- Avoid hiding primary or dangerous actions in ambiguous menus.

## KeyValueList And MetadataRow

Target responsibility:

- Standardize dense metadata in Incident Detail, Case Detail, Health, Detection Control, AI Provider/Data Control and assistant technical details.
- Support long values through wrapping/truncation rules.
- Make copyable identifiers a future option only if already supported or explicitly requested.

## SOC-Specific Components

| Component | Responsibility |
|---|---|
| `RiskScore` | Render numeric risk and risk bucket consistently. |
| `SLAIndicator` | Render SLA state, due time and breach risk where data exists. |
| `MITREBadge` | Render MITRE technique IDs/labels without treating every MITRE item as severity. |
| `AgentBadge` | Render host/agent identity consistently. |
| `CorrelationBadge` | Render correlation state/type without implying causality. |
| `SourceBadge` | Render source/provenance class for AI and evidence records. |
| `GroundingBadge` | Render existing grounding/citation/fallback states. |
| `HealthStatusBadge` | Render component health without page-local mappings. |
| `PolicyModeBadge` | Render AI data control/policy exposure modes. |

These components must use only data already exposed by existing APIs.

## AI Assistant Presentation

Target responsibility:

- Preserve the current read-only boundary, sources, limitations and technical details.
- Make primary answer content easier to scan without hiding transparency.
- Keep technical metadata collapsed or visually secondary by default.

Supported response groups where data exists:

- Summary
- Assessment
- Evidence
- Recommended next checks/actions
- Sources
- Limitations
- Technical details

Existing metadata that must remain retrievable:

- Provider/model/profile.
- Requested/effective mode.
- Latency and queue timing.
- Generation kind and fallback reason.
- Source count and source provenance.
- Semantic status/degraded state.
- Grounding/focus/plan validation.
- Automatic retries and model switches.
- Thinking-disabled flag.

## Responsive Strategy

- Preserve high-density desktop behavior.
- Use horizontal scrolling for operational tables where it protects important columns.
- Stack headers, filters and action bars below desktop.
- Use drawer/sidebar navigation only if current architecture supports it cleanly in a later phase.
- Do not hide critical incident/case identity, severity, status or risk.

## Accessibility Baseline

Minimum requirements for later phases:

- Visible keyboard focus for links, buttons, fields, tabs and dialogs.
- `aria-label` for icon-only actions.
- Labels for inputs and selects.
- `role="alert"` for important errors.
- `aria-live` or status role for long async operations where practical.
- Dialog focus management.
- State labels/icons in addition to color.
- Tables retain semantic table markup unless intentionally replaced with list cards on small screens.

## Migration Guardrails

- UX-02 should centralize tokens and semantic mappings before broad visual changes.
- UX-03 should expand primitives and migrate only pilot usage.
- UX-04 should make the shell/navigation consistent.
- UX-05 should introduce page archetypes.
- UX-06 and UX-07 must use the UX-01 protected workflow lists before touching Incident and Case detail pages.
- UX-08 must preserve assistant transparency and technical metadata.
- UX-09 through UX-12 should reduce remaining local duplication only after the foundations are stable.

## Non-Goals

- No new product features.
- No new backend fields.
- No new severity, status, workflow or permission values.
- No Grafana embedding.
- No RBAC simplification.
- No broad file splitting unless it is needed to safely preserve behavior during a later phase.
