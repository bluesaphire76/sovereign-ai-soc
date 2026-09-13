# Sovereign AI SOC v0.9.0 - UX Harmonization

Release approved for publication on 2026-09-13: **GO**, explicitly authorized again
after dependency hardening. The prior authenticated public verification passed;
the observed systemd restart propagation is accepted.
See the [release decision and publication status](../validation/v0.9.0-release-readiness.md).

v0.9.0 delivers product-wide UX harmonization while preserving existing security,
investigation and AI governance workflows. UX-01 through UX-12 are user-approved.

## Highlights

- Unified enterprise shell, navigation, semantic tokens and shared UI primitives.
- Harmonized Incident, Case and Kanban investigation, ownership, closure and AI workflows.
- Clearer contextual Assistant sources, provenance, grounding and deterministic
  fallback presentation, with keyboard-accessible citations.
- Consistent Dashboard, Executive, Health and Detection Quality workspaces.
- Clearer Detection Control preview, validation, confirmation and approval steps.
- Consistent Network/DNS telemetry and operational history presentation.
- Harmonized Users, Security Audit, authentication and self-service surfaces.
- Responsive layouts, visible focus, skip navigation, accessible labels, native
  dialog focus handling and reduced-motion support.
- Backend protection against removing the final enabled administrator, including
  concurrent role changes, disabling and deletion. Rejected operations return a
  controlled conflict; normal multi-administrator management remains available.
- Dependency security hardening: Next.js 16.3.5, sharp 0.35.4 with libheif 1.23.2,
  and development-only js-yaml 4.3.2 resolve the four reported dependency advisories.
  The committed frontend lockfile passes `npm audit` with zero reported vulnerabilities.

Existing backend security and domain semantics are preserved except for the new
last-ADMIN safety protection. No new roles, severity values, AI generation paths,
inference/grounding behavior or autonomous response capabilities are introduced.
Observability remains external and restricted to ADMIN/ANALYST.

## Validation

Release checks cover full backend regression, real-router account/RBAC tests,
isolated SQLite and PostgreSQL concurrency, frontend lint/build/TypeScript,
Chromium responsive/accessibility and protected workflow regression, documentation,
and current-build JS/CSS/font consistency through Next.js and Nginx. Full pytest:
**1,558 passed, 0 failed**, with all four baseline failures resolved. Chromium:
60 responsive page/viewport audits plus 100 workflow groups passed again after
dependency hardening, along with 297 targeted tests and the complete GitHub CI.
All four Dependabot alerts are fixed. The user confirmed the authenticated
Cloudflare path before dependency hardening; the patched build was revalidated
through Next.js and Nginx. A second manual Cloudflare result was not separately
recorded before the user's final publication instruction. Exact results and
accepted coverage limitations are recorded in the
[release-readiness report](../validation/v0.9.0-release-readiness.md).

## Upgrade

Follow [v0.8.x to v0.9.0 upgrade instructions](../operations/v0.9.0-upgrade.md)
and the [installation guide](../../INSTALL.md). No database or configuration
migration is introduced. Refresh dependencies, rebuild the production frontend,
restart its matching service, and restart the API to activate the last-ADMIN
protection. Do not restart unrelated services.

## Documentation

- [README](../../README.md)
- [UX Harmonization summary](../ux-harmonization/v0.9.0-summary.md)
- [Release readiness](../validation/v0.9.0-release-readiness.md)
- [Validation index](../validation/README.md)

## Notes

Automated browser coverage is Chromium, not Firefox or Safari. Screen-reader
testing and manual assessment of incomplete contrast/ARIA results remain outside
that coverage. This is not WCAG certification. CSS tooltips retain their existing
Escape-dismissal/clipping limitation. Existing bounded Assistant language and
fallback limitations remain; no model/runtime experiment was part of this release.
