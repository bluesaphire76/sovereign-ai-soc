# Roadmap

This roadmap separates published releases from future work. The current release
baseline is `v0.7.1`.

| Version | Status | Theme | Highlights |
|---|---:|---|---|
| v0.1 | Historical | SOC lab foundation | Initial lab scaffolding and stable SOC prototype baseline. |
| v0.2 | Completed | Initial SOC platform | Incident views, synthetic scenarios, detection quality foundation and early reporting. |
| v0.3 | Completed | RBAC and hardening | ADMIN/ANALYST/VIEWER roles, user management, Security Audit, session hardening, Nginx headers, secrets hardening and PostgreSQL 18.4 upgrade. |
| v0.4 | Completed | Ingestion quality and observability | Raw event/security alert/incident/case separation, aggregation, deduplication, noise suppression, correlation-first incident creation, AI hardening, reporting, retention and health visibility. |
| v0.5 | Completed | Enterprise demo and workflow polish | Demo scenario pack, enterprise UX, Incident Command Room, AI workflow refinement, Detection Quality review, report/export polish, Suricata network telemetry, DNS context and correlation visualization. |
| v0.6 | Released | AI investigation and governed remediation | Investigation intelligence, evidence confidence, LLM-backed remediation intelligence, approval gates, dry-run simulation, rollback readiness, execution audit trail, replay simulation, controlled internal SOAR workflow actions, Incident Command Center rewrite and observability improvements. |
| v0.7 | Released | Governed AI, semantic memory and operational control | AI providers/OpenRouter, AI Data Control, Qdrant Semantic Memory, Recommended Playbooks, investigation graph, advanced timeline, Detection Control lifecycle/versioning, governed remediation connectors, Operation History, Alertmanager, Loki/Alloy, installability and expanded validation. |

## Completed Product Themes

- Local-first AI SOC architecture.
- Wazuh endpoint/security monitoring.
- Suricata network IDS visibility.
- DNS telemetry context.
- Correlation-first incident creation.
- Human-in-the-loop incident and case workflow.
- AI-assisted investigation and evidence confidence workflows.
- Human-governed remediation with approval, dry-run, rollback readiness, audit trail and replay simulation.
- Controlled SOAR workflow actions limited to safe internal product records.
- RBAC and audit governance.
- Local AI runtime with fallback behavior.
- Optional governed external AI providers, disabled by default.
- AI Data Control policies with deterministic redaction and audit-safe previews.
- Qdrant Semantic Memory for knowledge, historical incident, Detection Control
  and approved/final Case Closure context.
- Platform-aware Recommended Playbooks with deterministic fallback and optional
  LLM synthesis.
- Advanced Incident Timeline and Investigation Graph.
- Detection Control write mode, lifecycle, validation, configuration versioning
  and rollback.
- Governed remediation proposals and internal connectors.
- Service Operations and Operation History.
- Prometheus/Alertmanager alerting and Loki/Grafana Alloy logging.
- Executive-ready reporting and evidence packs.

## Candidate Post-v0.7 Direction

These are candidate directions, not implemented commitments:

- Additional telemetry connectors.
- Case collaboration enhancements.
- Scheduled report generation.
- Production adapters for provider types beyond OpenAI-compatible endpoints.
- Governed real ticketing, EDR, firewall or SOAR connectors.
- Published container images and fuller deployment orchestration.
- Stronger cost/token accounting and provider usage reporting.
- Additional automated documentation and API schema generation.
