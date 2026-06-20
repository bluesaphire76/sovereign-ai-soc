# User Guide

This guide follows the user-facing pages present in `frontend/src/app`.

## Dashboard

The main Dashboard provides operational SOC posture:

- Active incident and risk metrics.
- Incident risk distribution.
- Top operational signals.
- Compact status badges aligned with the enterprise UI style.
- Links into incidents, cases, health and executive views.

Use it as the starting point for analyst review.

## Executive Dashboard

The Executive Dashboard is designed for management-ready posture review:

- Executive decision brief.
- Risk posture and recommendations.
- Incident and case summary.
- Concise trend and operational context.

It is intentionally less technical than the Incident Detail and Evidence Pack views.

## Incidents

The Incidents page lists analyst-facing incidents created after ingestion policy, deduplication, suppression and correlation.

Typical workflow:

1. Review severity, status, risk and AI/correlation indicators.
2. Filter or scan for high-risk items.
3. Open an incident detail page.
4. Validate evidence and recommended actions.
5. Update status or create a case if investigation is needed.

## Incident Detail / Incident Command Room

Incident Detail is the primary analyst workspace for an incident.

Key areas:

- Incident overview and lifecycle.
- AI Command Brief.
- Risk rationale and evidence summary.
- Correlation Visualization.
- Raw Wazuh alert details.
- Suricata network evidence where available.
- Endpoint DNS context where available.
- Analyst notes and audit context.
- Report and evidence pack exports.

DNS context is contextual telemetry only. It is matched by host/client IP and selected time window; it does not imply causal correlation with the incident.

## Correlation Visualization

Correlation Visualization helps answer:

- Why did the platform create this incident?
- Which signals contributed?
- What happened in the timeline?
- Which MITRE or attack-chain elements are involved?
- Which related alerts or incidents support the decision?

Raw JSON remains secondary so the analyst sees context before technical dumps.

## Cases

Cases group incidents into investigation workflows.

The Cases page shows:

- Priority.
- Status.
- Severity.
- SLA posture.
- Closure readiness.
- AI availability.

Use cases when an incident requires ownership, investigation tracking or closure governance.

## Case Detail

Case Detail supports:

- Ownership and assignee review.
- SLA target and status.
- Linked incidents.
- Case AI analysis.
- Action planning.
- Notes and audit trail.
- Closure checklist and readiness.
- Case report and evidence exports.

## Case Kanban

The Kanban page gives a workflow view of cases by status. It is useful during standups, reviews and demo flows where the case lifecycle matters more than incident-level details.

## Detection Quality

Detection Quality supports detection engineering review:

- Synthetic scenario coverage.
- Correlation coverage.
- Priority validation.
- MITRE coverage.
- Quality score.
- Weakest scenario.
- Recommended next action.
- AI-generated remediation suggestion for explicit user requests.

Synthetic test execution is available to roles permitted by RBAC. Viewer roles are read-only.

## Network Events

Network Events displays Suricata-derived IDS telemetry. Use it to understand network-side detections and supporting evidence without treating every network event as an incident.

## DNS Telemetry

DNS Telemetry displays endpoint DNS activity normalized from the DNS telemetry path.

DNS data is useful as context around host activity. It is not causal evidence unless another detection explicitly supports that interpretation.

## Health

Health shows platform and runtime posture:

- API and component status.
- Wazuh freshness.
- Suricata/network ingest status.
- DNS telemetry status.
- Worker and backlog metrics.
- PostgreSQL and Ollama runtime context.

Use Health before demos and after restarts.

## Users and Security Audit

Users and Security Audit are role-aware admin areas:

- ADMIN can manage users and review audit activity.
- ANALYST and VIEWER access is constrained by RBAC.
- Security Audit is admin-only.

See [Admin Guide](../operations/admin-guide.md) and [Security Model](../architecture/security-model.md).
