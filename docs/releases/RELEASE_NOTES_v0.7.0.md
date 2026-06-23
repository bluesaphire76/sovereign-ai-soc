# Sovereign AI SOC v0.7.0 — Unreleased Main-Branch Summary

Status: implemented on `main`, not yet published as a Git tag.

The latest published tag is `v0.6.0`. This document summarizes the v0.7
capabilities currently present in the repository so release preparation and
external documentation have one accurate source.

## Highlights

- Governed AI provider abstraction with local Ollama as the default and
  OpenRouter/OpenAI-compatible external routing disabled by default.
- AI Data Control policies with feature/role/provider decisions, deterministic
  redaction previews and audit-safe decision history.
- Qdrant Semantic Memory for local knowledge, historical incidents, Detection
  Control and approved/final Case Closure context.
- Metadata-aware, platform-aware Recommended Playbooks with deterministic
  fallback and optional LLM synthesis.
- Advanced Incident Timeline and Investigation Graph on incident/case detail.
- Detection Control Plane write mode, lifecycle, validation, versioning,
  rollback, exceptions and noise-suppression operations.
- Governed remediation proposals and internal connectors with explicit
  proposal-only boundaries for firewall, EDR, ticketing and external SOAR.
- Service Operations, restart previews and searchable Operation History.
- Expanded Health with AI provider, Qdrant, backlog, worker, ingest and
  non-blocking Grafana/Prometheus/Alertmanager visibility.
- Prometheus alert rules, Alertmanager routing, optional ntfy delivery, Loki
  log storage, Grafana Alloy collection and Grafana dashboards.
- Operational dashboard trends, demo-data management, release readiness,
  install doctor, Docker packaging and Ubuntu guided preparation.

## AI Providers and Data Governance

Local Ollama remains the default provider. External providers require all of
the following:

- global external-provider enablement;
- an enabled and fully configured provider;
- feature allowlisting;
- a compatible AI Data Control policy;
- role authorization and any required confirmation;
- deterministic redaction before external transmission.

OpenRouter is implemented through the OpenAI-compatible adapter. Azure,
Anthropic and custom HTTP provider types remain visible configuration types
without dedicated production adapters.

## Semantic Memory and Recommended Playbooks

Qdrant stores multiple governed source types:

- `knowledge_base`;
- `historical_incident`;
- `detection_control`;
- `case_closure`.

Semantic search is advisory only. It cannot decide severity, deduplication,
suppression, incident/case closure, Detection Control approval or remediation.

Recommended Playbooks use metadata, incident telemetry, platform/type filters,
retrieved playbook sections and optional LLM synthesis. Unknown generated
playbook titles are discarded. Timeout, invalid JSON or provider failure
returns deterministic analyst guidance.

## Investigation and Remediation

The Advanced Incident Timeline aggregates linked security, lifecycle, AI,
case, note and noise-control events. Investigation Graph provides bounded
incident/case relationship visualization with role-aware redaction.

Governed remediation persists proposals through draft, review, approval and
conversion states. Supported conversions create only internal case records,
documents or Detection Control drafts. External network, endpoint, identity,
ticketing and SOAR execution is not enabled.

## Observability

The v0.7 observability layer adds:

- Wazuh ingest backlog metrics and alert rules;
- Alertmanager routing and optional ntfy notifications;
- Loki retention-backed log storage;
- Grafana Alloy collection from selected containers and systemd journals;
- a platform logs dashboard and Qdrant semantic-memory dashboard;
- expanded Health component and AI-provider visibility.

Grafana, Prometheus and Alertmanager are non-blocking in the application
overall health calculation when explicitly marked optional.

## Safety Boundaries

v0.7 does not claim:

- autonomous incident classification;
- autonomous remediation;
- arbitrary command execution;
- automatic firewall, EDR, identity or external SOAR actions;
- external AI use without explicit policy and configuration;
- semantic similarity as proof;
- production-ready one-command deployment.

Human review, RBAC, deterministic policy, auditability and explicit approval
remain authoritative.

## Validation

Use the repository release gate:

```bash
./ai-soc release-check
```

See the [v0.7 validation harness](../validation/v0.7-expanded-validation-harness.md)
and [documentation home](../README.md).
