# User Guide

This guide follows the user-facing pages present in `frontend/src/app`.

## Dashboard

The main Dashboard provides operational SOC posture:

- Active incident and risk metrics.
- Incident risk distribution.
- Incident trend, queue aging and detection-funnel operational trends.
- Top operational signals and recent incidents.
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
- Advanced Incident Timeline.
- Investigation Graph.
- Similar historical incidents where semantic memory is available.
- Recommended Playbooks retrieved from Qdrant and refined with governed AI.
- Correlation Visualization.
- Raw Wazuh alert details.
- Suricata network evidence where available.
- Endpoint DNS context where available.
- Governed Remediation proposals, approval state and internal conversion links.
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

## Advanced Incident Timeline

The Advanced Incident Timeline combines linked event, alert, correlation,
lifecycle, AI, note, case and detection/noise records. Use filters to focus on
key events, raw evidence, AI activity, lifecycle changes or case actions.

Raw payload access is role-controlled and is not requested by the standard UI.

## Investigation Graph

The Investigation Graph connects incident or case records to related hosts,
users, IP addresses, processes, files, packages, MITRE techniques, alerts,
detection controls and AI hypotheses.

Graph relationships are investigative context, not proof of root cause. Review
the underlying evidence references and any truncation or redaction warnings.

## Recommended Playbooks

Recommended Playbooks retrieve metadata-aware playbook sections from Qdrant.
The system uses deterministic platform and incident-type checks before optional
LLM synthesis. Guidance includes:

- why a playbook applies;
- immediate analyst checks;
- evidence to collect;
- false-positive checks;
- escalation criteria;
- approval-required containment/remediation considerations;
- closure considerations.

Recommendations are advisory and cannot set severity, close work items,
suppress detections or approve remediation.

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
- Persisted AI generation job status.
- Recommended Playbooks.
- Investigation Graph.
- Advisory semantic context for closure review.
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
- Advisory Qdrant semantic context for reviewed detection patterns.

Synthetic test execution is available to roles permitted by RBAC. Viewer roles are read-only.

## Detection Control Plane

Detection Control Plane provides:

- unified inventory for detection rules, noise suppression and exceptions;
- create/edit/enable/disable/validate operations;
- match previews and matched-event evidence;
- review dates, owners and expiration visibility;
- lifecycle states from draft through approval, activation and disablement;
- configuration snapshots, diffs, validation, apply and rollback;
- advisory semantic context from prior detection/case/historical memory;
- governed service restart previews and operations.

ADMIN approval is required for activation, disablement, configuration apply or
rollback and service restart execution.

## AI Providers

AI Providers shows the default provider, external-provider global state, local
Ollama profiles, configured models, allowlists, redaction mode and health.

Local Ollama is the default. OpenRouter and other external configurations do
not receive SOC data unless all provider and AI Data Control checks allow it.
Only ADMIN can change provider settings or run the confirmed provider test.

## AI Data Control

AI Data Control exposes per-feature policy modes, role/provider allowlists,
redaction/evaluation previews and recent policy decisions.

ADMIN can edit policies. ADMIN and ANALYST can run previews. Raw prompts,
responses and secrets are not stored in decision history.

## Semantic Memory

Semantic Memory is available to ADMIN and ANALYST. It shows Qdrant health,
collection/index status, source-type counts, automatic freshness and read-only
search.

ADMIN can explicitly run dry-run/apply backfills and historical-memory
retention cleanup. Apply operations require confirmation.

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
- Worker and backlog metrics.
- PostgreSQL, Qdrant and Ollama runtime context.
- Local and external AI provider health/configuration state.
- Optional Grafana, Prometheus and Alertmanager reachability.
- Active users and latest-incident context.

Use Health before demos and after restarts.

Loki and Grafana Alloy are validated and operated through the observability
stack; they are not currently separate components in `/platform/health`.
DNS telemetry is reviewed on its dedicated page rather than as a separate
Health component.

## Operation History

Operation History lists service status checks, restart previews and restart
attempts with actor, reason, pre/post status and safe outcome details. All
roles can read it. Restart previews require ADMIN or ANALYST; execution is
ADMIN-only and limited to allowlisted services.

## Users and Security Audit

Users and Security Audit are role-aware admin areas:

- ADMIN can manage users and review audit activity.
- ANALYST and VIEWER access is constrained by RBAC.
- Security Audit is admin-only.

See [Admin Guide](../operations/admin-guide.md) and [Security Model](../architecture/security-model.md).
