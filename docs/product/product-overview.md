# Product Overview

Sovereign AI SOC is a local-first AI-powered security operations platform for product-grade SOC demos and security engineering experimentation.

It combines deterministic security operations workflows with local AI-assisted decision support:

- Wazuh for host and endpoint security monitoring.
- Suricata for network IDS visibility.
- DNS telemetry as contextual endpoint activity.
- Raw events, security alerts, incidents and cases as separate workflow entities.
- Correlation-first incident creation.
- Case ownership, SLA posture and closure readiness.
- Local Ollama-based AI analysis.
- Human-in-the-loop analyst control.
- Executive-ready reporting and analyst evidence packs.

## Product Principles

| Principle | Meaning |
|---|---|
| Local-first | Core telemetry, AI analysis and report generation run in the local environment. |
| Sovereign | Sensitive security context does not require a mandatory external AI provider. |
| Correlation-first | Incident creation is driven by deterministic policy, deduplication, noise suppression and correlation. |
| Evidence-based | Reports and briefings are grounded in available alert, correlation, case and telemetry data. |
| Human-controlled | AI recommends and explains; analysts decide and act. |
| Enterprise-oriented | UX, exports, RBAC, audit and observability are designed for credible SOC workflows. |

## What the Platform Demonstrates

Sovereign AI SOC is not a simple alert viewer. The repository demonstrates a layered SOC operating model:

1. Ingest host/security and network telemetry.
2. Normalize source data into raw events and security alerts.
3. Suppress low-value noise and aggregate repeated signals.
4. Correlate signals before creating incidents.
5. Use local AI to explain risk, evidence and next actions.
6. Manage incidents and cases through human-in-the-loop workflows.
7. Export professional reports and evidence packs.
8. Monitor the health of the platform and AI runtime.

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
- Users / RBAC
- Security Audit

## Intended Audiences

- SOC analysts who need compact, evidence-based incident context.
- Detection engineers who need validation and synthetic scenario coverage.
- SOC managers who need operational posture and case readiness.
- CISOs and executives who need concise risk summaries and reporting.
- Engineers and reviewers evaluating local-first AI security architectures.

## Boundaries

The project does not claim automated response. It does not replace analysts, execute destructive actions, or assert causal relationships from contextual telemetry such as DNS without explicit detection evidence.

AI output is decision support. The analyst remains accountable for validation, response and closure.
