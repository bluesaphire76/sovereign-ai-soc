# Roadmap

This roadmap summarizes implemented milestones and candidate future direction. It avoids promising features that are not currently present.

| Version | Status | Theme | Highlights |
|---|---:|---|---|
| v0.1 | Historical | SOC lab foundation | Initial lab scaffolding and stable SOC prototype baseline. |
| v0.2 | Completed | Initial SOC platform | Incident views, synthetic scenarios, detection quality foundation and early reporting. |
| v0.3 | Completed | RBAC and hardening | ADMIN/ANALYST/VIEWER roles, user management, Security Audit, session hardening, Nginx headers, secrets hardening and PostgreSQL 18.4 upgrade. |
| v0.4 | Completed | Ingestion quality and observability | Raw event/security alert/incident/case separation, aggregation, deduplication, noise suppression, correlation-first incident creation, AI hardening, reporting, retention and health visibility. |
| v0.5 | Active product-grade track | Enterprise demo and workflow polish | Demo scenario pack, enterprise UX, Incident Command Room, AI workflow refinement, Detection Quality review, report/export polish, Suricata network telemetry, DNS context and correlation visualization. |
| v0.6 | Candidate | Next product evolution | Candidate areas include richer detection engineering workflows, additional connectors, deeper case collaboration, stronger report automation and broader validation tooling. |

## Completed Product Themes

- Local-first AI SOC architecture.
- Wazuh endpoint/security monitoring.
- Suricata network IDS visibility.
- DNS telemetry context.
- Correlation-first incident creation.
- Human-in-the-loop incident and case workflow.
- RBAC and audit governance.
- Local AI runtime with fallback behavior.
- Executive-ready reporting and evidence packs.

## Candidate v0.6 Ideas

These are candidate directions, not implemented commitments:

- Additional telemetry connectors.
- Detection rule lifecycle management.
- Case collaboration enhancements.
- Advanced timeline and graph views.
- Scheduled report generation.
- Expanded CI/demo validation harness.
- Optional external AI provider abstraction with strict data controls.
