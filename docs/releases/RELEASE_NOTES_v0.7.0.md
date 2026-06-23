# Sovereign AI SOC v0.7.0 — Governed AI, Semantic Memory and Observability

Release date: 2026-06-23
Tag: `v0.7.0`
Previous release: `v0.6.0`

## Release Theme

v0.7.0 moves Sovereign AI SOC from local AI-assisted investigation into a more
governed SOC operations platform: external AI can be enabled under explicit
policy, Qdrant-backed Semantic Memory becomes part of analyst workflows,
playbook recommendations become platform-aware, incident investigation gains a
relationship graph, remediation remains governed, and Health/observability now
cover more of the runtime.

The default posture remains local-first. Ollama is still the default AI runtime,
external AI is disabled unless explicitly configured and allowed, and every
high-impact workflow keeps deterministic policy, RBAC, auditability and human
review in front of AI output.

## Highlights

- Governed AI provider abstraction with local Ollama as the default provider
  and optional OpenRouter/OpenAI-compatible routing.
- AI Data Control policy layer with per-feature modes, provider allowlists,
  role checks, redaction previews and audit-safe decision history.
- Qdrant Semantic Memory for knowledge base content, historical incidents,
  Detection Control context and approved case-closure memory.
- Metadata-aware Recommended Playbooks with platform/type filtering,
  deterministic fallback and optional LLM synthesis.
- Advanced Incident Timeline and Investigation Graph for bounded incident and
  case relationship exploration.
- Detection Control lifecycle coverage for draft/validation/review/publish,
  versioning, rollback, exceptions and noise operations.
- Governed remediation proposals with approval workflow and internal
  conversion paths.
- Service Operations with restart preview, allowlisted actions and searchable
  Operation History.
- Expanded Health page with AI runtime/provider state, Qdrant visibility,
  ingest backlog, worker status, service status and optional observability
  component checks.
- Prometheus alert rules, Alertmanager routing, optional ntfy delivery, Loki log
  storage, Grafana Alloy collection and Grafana dashboards.
- Improved Docker demo packaging, Ubuntu guided preparation, release readiness
  checks and external-user documentation.

## AI Providers and AI Data Control

v0.7.0 introduces a provider abstraction while preserving the local-first
baseline:

- Ollama remains the default and expected local provider.
- OpenRouter is supported through the OpenAI-compatible adapter.
- External AI calls require explicit global enablement, provider configuration,
  feature allowlisting, AI Data Control policy approval, role authorization and
  redaction before data leaves the local environment.
- Provider/model/fallback state is exposed so operators can understand which AI
  path is actually being used.

AI Data Control is the governing layer for AI context sharing. It supports
policy modes such as local-only, metadata-only, redacted context, admin-only
full context and custom allowlists. Redaction previews help operators review
what would be sent before allowing external use.

## Semantic Memory and Recommended Playbooks

Qdrant Semantic Memory is now documented and surfaced as an analyst-facing
capability rather than just backend infrastructure. It can index and retrieve:

- `knowledge_base`;
- `historical_incident`;
- `detection_control`;
- `case_closure`.

Semantic Memory remains advisory. It does not decide severity, suppression,
deduplication, closure, Detection Control approval or remediation.

Recommended Playbooks now combine structured metadata, incident telemetry,
platform/type filters, Qdrant context and optional LLM synthesis. Unknown
LLM-generated playbook titles are discarded, and timeout/provider failures
return deterministic guidance instead of blocking the analyst workflow.

## Investigation, Detection Control and Remediation

The incident workflow gains more context without giving AI authority over the
case:

- Advanced Incident Timeline aggregates linked security, lifecycle, AI, case,
  note and noise-control events.
- Investigation Graph exposes bounded incident/case relationships with
  role-aware redaction and hard graph-size limits.
- Detection Control supports a governed lifecycle with validation, review,
  publication, version history, rollback and exception/noise operations.
- Governed remediation persists proposals through draft, review, approval and
  conversion states.

Remediation remains intentionally bounded. Supported conversions create
internal case records, documents or Detection Control drafts. v0.7.0 does not
enable automatic endpoint, firewall, identity, ticketing or external SOAR
execution.

## Operations, Health and Observability

Operational visibility expands across application runtime, AI, memory and
supporting observability services:

- Health includes API, PostgreSQL, Ollama, AI runtime/provider registry, Wazuh,
  Suricata/network ingest, event queue, Qdrant, Grafana, Prometheus,
  Alertmanager, worker and Cloudflare tunnel visibility.
- Grafana, Prometheus and Alertmanager can be configured as optional,
  non-blocking Health components.
- Service Operations supports status and governed restart previews for a small
  allowlist of services.
- Operation History records preview/restart attempts, denied operations,
  outcomes and audit context.
- Prometheus rules and Alertmanager routing cover Wazuh backlog alerting, with
  optional ntfy notification delivery.
- Loki and Grafana Alloy provide selected platform-log troubleshooting with
  conservative collection boundaries.

## Installability and Documentation

v0.7.0 also refreshes the external documentation set:

- canonical documentation home;
- updated README, install, admin, user, deployment and troubleshooting guides;
- product and AI capability documentation aligned to the current UI;
- architecture diagrams refreshed in the project visual style;
- release readiness, Docker packaging and Ubuntu guided demo preparation docs;
- explicit notes for screenshots, validation and operational runbooks.

## Safety Boundaries

v0.7.0 does not introduce or claim:

- autonomous incident classification;
- autonomous remediation;
- arbitrary shell command execution;
- LLM-generated command execution;
- automatic firewall, EDR, identity or SOAR actions;
- unrestricted service restart control;
- external AI usage without explicit policy and provider configuration;
- semantic similarity as proof;
- production-ready one-command deployment.

Human review, RBAC, deterministic policy, audit trails and explicit approval
remain authoritative.

## Upgrade Notes

Recommended upgrade path:

1. Pull tag `v0.7.0`.
2. Review `.env.example`, frontend environment examples and AI provider
   settings before enabling external providers.
3. Keep external AI disabled until AI Data Control policies, provider
   allowlists and role permissions are reviewed.
4. Rebuild/restart API, frontend and worker services in production-style demo
   deployments.
5. Reindex Qdrant/Semantic Memory content if upgrading from an older local
   knowledge base.
6. Start observability stacks explicitly if you want Prometheus,
   Alertmanager, Loki, Grafana Alloy or Grafana.
7. Run the release readiness gate before stakeholder demos:

   ```bash
   ./ai-soc release-check
   ```

## Validation

Release-preparation checks for this release-note update passed:

- documentation structure validation;
- external documentation validation;
- release/CLI documentation pytest subset;
- SVG accessibility, endpoint and diagram-overlap validation;
- whitespace/diff hygiene.

Before tagging or publishing in a new environment, run the full release gate:

```bash
./ai-soc release-check
```

## Known Limitations

- External AI provider support is intentionally conservative; OpenRouter uses
  the OpenAI-compatible adapter and all external use remains opt-in.
- Azure, Anthropic and custom provider types may be represented in configuration
  surfaces, but dedicated production adapters should be validated before use.
- Semantic Memory is advisory and depends on indexed local content quality.
- Recommended Playbooks are metadata/platform-aware but still require analyst
  review.
- Loki/Alloy collect selected platform logs only, not raw security telemetry,
  AI prompts or investigation payloads.
- Browser screenshots are still tracked through the screenshot checklist rather
  than committed as a complete product gallery.
