# Product Overview

Sovereign AI SOC is a local-first, human-governed security operations platform
for product-grade SOC demos, analyst workflow evaluation and security
engineering experimentation.

It combines deterministic SOC controls with governed AI and semantic retrieval:

- Wazuh host and endpoint monitoring.
- Suricata network IDS visibility.
- DNS telemetry as contextual endpoint activity.
- Raw events, security alerts, incidents and cases as separate entities.
- Correlation-first incident creation and explainable noise suppression.
- Advanced incident timelines and investigation relationship graphs.
- Local Ollama model routing with optional governed external providers such as
  OpenRouter.
- AI Data Control policies, deterministic redaction and provider auditability.
- Qdrant Semantic Memory and incident-specific Recommended Playbooks.
- Detection Control lifecycle, configuration versioning and rollback governance.
- Human-approved remediation proposals and safe internal conversions.
- Case ownership, SLA posture, closure readiness and local reporting.
- Health, Operation History, Prometheus alerting and Loki/Alloy logging.

## Product Principles

| Principle | Meaning |
|---|---|
| Local-first | Core telemetry, AI analysis, semantic memory and report generation can run locally. |
| Sovereign by default | External AI is optional, disabled by default and governed by explicit provider/data policies. |
| Correlation-first | Incident creation is driven by deterministic policy, deduplication, noise suppression and correlation. |
| Evidence-based | Reports and briefings are grounded in available alert, correlation, case and telemetry data. |
| Human-controlled | AI and semantic retrieval recommend and explain; authorized humans decide and act. |
| Enterprise-oriented | UX, exports, RBAC, audit and observability are designed for credible SOC workflows. |

## What the Platform Demonstrates

Sovereign AI SOC is not a simple alert viewer. The repository demonstrates a layered SOC operating model:

1. Ingest host/security and network telemetry.
2. Normalize source data into raw events and security alerts.
3. Suppress low-value noise and aggregate repeated signals.
4. Correlate signals before creating incidents.
5. Retrieve relevant local playbooks and historical context from Qdrant.
6. Use a policy-selected AI provider to explain risk, evidence and next actions.
7. Investigate with timelines, graphs, cases and governed remediation proposals.
8. Govern detection changes through lifecycle, validation, versioning and audit.
9. Export professional reports and evidence packs.
10. Monitor runtime health, operations, metrics, alerts and selected platform logs.

## Current Product Surface

The frontend includes pages for:

- Dashboard
- Executive Dashboard
- Incidents
- Incident Detail / Incident Command Room
- Cases
- Case Detail
- Case Kanban
- Detection Quality
- Network Events
- DNS Telemetry
- Health
- Detection Control Plane
- AI Providers
- AI Data Control
- Semantic Memory
- Operation History
- Users / RBAC
- Security Audit

## Intended Audiences

- SOC analysts who need compact, evidence-based incident context.
- Detection engineers who need validation and synthetic scenario coverage.
- SOC managers who need operational posture and case readiness.
- CISOs and executives who need concise risk summaries and reporting.
- Engineers and reviewers evaluating local-first AI security architectures.

## Boundaries

The project does not claim autonomous response. It does not replace analysts,
execute arbitrary or destructive external actions, or assert causal
relationships from contextual telemetry or semantic similarity without
deterministic evidence.

AI output, semantic memory and Recommended Playbooks are decision support.
RBAC, deterministic controls, audit and authorized human approval remain
authoritative.
