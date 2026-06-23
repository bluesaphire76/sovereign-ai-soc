# Architecture

Sovereign AI SOC uses a local-first architecture with a Next.js frontend,
FastAPI backend, PostgreSQL operational datastore, Qdrant semantic memory,
Wazuh and Suricata signal sources, local Ollama inference and optional governed
external AI providers.

## System Overview

![High-level architecture](../assets/architecture/high-level-architecture.svg)

Editable Mermaid source: [high-level-architecture.mmd](../diagrams/high-level-architecture.mmd).

## Components

| Component | Role |
|---|---|
| Next.js frontend | Enterprise SOC console for dashboards, incidents, cases, Detection Control, AI governance, semantic memory, health and system information. |
| FastAPI backend | API, RBAC and governance layer for SOC workflow, AI routing, semantic retrieval, remediation and operations. |
| PostgreSQL | Operational storage for events, alerts, incidents, cases, users, audit, detection lifecycle, remediation proposals and operation history. |
| Qdrant | Local semantic memory for knowledge-base chunks, historical incidents, Detection Control and approved/final Case Closure context. |
| Wazuh | Host and endpoint security monitoring source. |
| Suricata | Network IDS source normalized into network events. |
| DNS telemetry | Endpoint DNS context normalized into `dns_events`. |
| AI provider layer | Ollama by default; optional OpenAI-compatible providers such as OpenRouter under explicit data-control policy. |
| Nginx | TLS reverse proxy and security headers for production-style demo deployments. |
| Detection Control | Governed rules, exceptions, suppression, lifecycle, versioning and rollback. |
| Remediation governance | Proposal lifecycle, internal connectors, approvals, dry-run, rollback and audit views. |
| Observability stack | Prometheus, Grafana, Alertmanager, Loki, Grafana Alloy, cAdvisor, node-exporter and optional ntfy delivery. |
| systemd/Docker operations | Runtime management with allowlisted service status/restart controls and Operation History. |

## Data Flow

1. Wazuh, Suricata and DNS collectors produce telemetry.
2. Ingestion normalizes telemetry into internal storage.
3. Raw events and security alerts remain separate from incidents.
4. Aggregation and deduplication reduce repeated signals.
5. Noise suppression prevents known low-value findings from becoming incidents.
6. Correlation-first policy decides whether an incident should be created.
7. Incidents can become cases with ownership, SLA and closure workflow.
8. Qdrant retrieves advisory playbooks and historical context.
9. The AI provider/data-control layer selects an allowed provider and redacts
   context before any external request.
10. Analysts use timelines, graphs, Recommended Playbooks and governed
    remediation proposals.
11. Detection changes flow through validation, approval, versioning and audit.
12. Reports and evidence packs are generated from stored operational context.

See [Ingestion and Correlation Pipeline](ingestion-correlation-pipeline.md).

## Storage Model

The platform separates operational concepts:

- `raw_events`: ingested source-level telemetry.
- `security_alerts`: normalized security alerts derived from source events.
- `incidents`: analyst-facing correlated work items.
- `cases`: multi-incident workflow containers with ownership and closure state.
- `network_events`: Suricata-derived IDS visibility.
- `dns_events`: contextual DNS telemetry.
- detection lifecycle/configuration tables: governed rules and version history.
- remediation proposal/event tables: proposal state and conversion audit.
- service operation tables: status checks, previews, restart attempts and outcomes.
- audit/user tables: RBAC and governance.

Qdrant is not the operational source of truth. Its vector records are derived
advisory memory and can be rebuilt from governed source data.

This separation keeps reporting, workflow and detection logic clear.

## AI Runtime Role

The governed AI layer supports:

- Incident AI analysis.
- Qdrant-backed playbook, procedure and historical-context retrieval.
- AI Command Brief generation.
- Risk rationale and evidence summaries.
- Recommended Playbooks, actions and HOW TO EXECUTE guidance.
- Case analysis.
- Detection Quality remediation suggestions.
- Executive insight and report enrichment.

Provider selection is server-side. External providers are disabled by default
and must pass AI Data Control before receiving metadata or redacted context.

AI and semantic memory do not decide access control, mutate lifecycle state by
themselves or execute arbitrary response actions. See
[AI Capabilities](../product/ai-capabilities.md).

## Local-first Sovereignty View

![Local-first sovereignty architecture](../assets/architecture/local-first-sovereignty-architecture.svg)

Editable Mermaid source: [local-first-sovereignty-architecture.mmd](../diagrams/local-first-sovereignty-architecture.mmd).

## Deployment Model

The repository includes deployment artifacts for:

- Nginx reverse proxy and security headers.
- FastAPI API service.
- Next.js frontend service.
- Suricata EVE ingest worker.
- DNS collector worker.
- PostgreSQL lab runtime.
- Qdrant local vector knowledge base.
- Ollama local runtime.
- Optional governed external AI endpoints.
- Prometheus/Grafana/Alertmanager observability.
- Loki/Grafana Alloy logging.
- Qdrant backfill and retention timers.

![Deployment architecture](../assets/architecture/deployment-architecture.svg)

See [Deployment Guide](../operations/deployment-guide.md). Editable Mermaid source: [deployment-architecture.mmd](../diagrams/deployment-architecture.mmd).

## Human-in-the-loop Boundaries

Human operators control:

- Incident escalation and status changes.
- Case ownership, SLA handling and closure.
- Interpretation and validation of AI recommendations.
- External provider enablement and AI data policy.
- Detection Control approval, apply and rollback.
- Semantic memory backfill/retention apply operations.
- Remediation proposal approval and conversion.
- Operational response actions.
- Report review and distribution.

The architecture is intentionally AI-assisted, not analyst-replacing.
