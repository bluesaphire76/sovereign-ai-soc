# Admin Guide

This guide covers administrative operation for local/demo deployments.

## Roles

The product uses three primary roles:

| Role | Intent |
|---|---|
| ADMIN | User management, Security Audit, full SOC workflow access and privileged operations. |
| ANALYST | Incident/case investigation, AI generation, semantic context, previews, validation, proposal preparation and reporting. |
| VIEWER | Read-only SOC, health, operation-history and reporting visibility. |

Detailed permission notes are available in [permission-matrix-v0.3.md](../architecture/permission-matrix-v0.3.md).

## User Management

The Users page supports role-aware user administration. ADMIN users can manage platform users. Non-admin users are constrained to self-service behavior where implemented.

Initial admin creation is handled by:

```bash
AI_SOC_ADMIN_USERNAME=admin \
AI_SOC_ADMIN_PASSWORD='<set-a-strong-password>' \
AI_SOC_ADMIN_DISPLAY_NAME='SOC Administrator' \
python3 scripts/create_default_admin_user.py
```

Use a strong password and rotate any default/demo credentials before sharing a system.

## Security Audit

Security Audit provides governance visibility for:

- Login activity.
- RBAC denials.
- User management operations.
- Privileged SOC workflow actions.
- AI provider and AI Data Control decisions.
- Detection Control lifecycle and configuration changes.
- remediation proposal and conversion events.
- service operations.

Security Audit is intended for ADMIN users only.

## Health and Runtime Observability

The Health page should be checked before demos, after deploys and during troubleshooting.

Watch:

- API health.
- PostgreSQL connectivity.
- Wazuh ingest freshness.
- Suricata network event freshness.
- Worker backlog and lag.
- Ollama/local AI runtime status.
- configured AI providers and external-provider global state.
- Qdrant collection state, point count and auto-index freshness.
- optional Grafana, Prometheus and Alertmanager reachability.

Loki and Grafana Alloy are operated through the observability stack and are
not currently separate `/platform/health` components.
DNS telemetry is inspected through its dedicated product page rather than a
separate Health component.

## AI Provider Administration

`Settings > AI Providers` is readable by authenticated users and editable by
ADMIN. External providers are disabled by default.

Before enabling OpenRouter or another OpenAI-compatible endpoint:

1. keep the API key in `.env`;
2. configure model, timeout and feature allowlist;
3. enable external providers globally;
4. set a non-blocking provider redaction mode;
5. configure the matching AI Data Control feature policy;
6. run the confirmed harmless provider test;
7. review Security Audit and Health provider metadata.

Provider enablement alone does not authorize external data transfer.

## AI Data Control

ADMIN can edit per-feature policy with a required reason. ADMIN and ANALYST can
run evaluation/redaction previews. Keep raw prompt/response storage disabled.

## Semantic Memory Administration

ADMIN and ANALYST can inspect/search semantic memory. ADMIN can run explicit
dry-run/apply operations for:

- historical incident backfill;
- Detection Control and Case Closure backfill;
- historical-memory retention cleanup.

Apply actions require confirmation. Review point counts and source-type counts
after each operation.

## Detection and Remediation Governance

Detection Control approval, apply, rollback, disable and direct rule writes are
ADMIN-only. Analysts can prepare and validate drafts.

Remediation proposals can be prepared by ADMIN/ANALYST and approved/rejected by
ADMIN. External connector placeholders remain proposal-only.

## Service Operations

The Detection Control Plane contains governed service status and restart
controls. Operation History is available under System Information.

- ADMIN/ANALYST: status and restart preview.
- ADMIN: confirmed restart execution.
- VIEWER: status/history read-only.
- API self-restart: blocked.
- arbitrary service names/commands: blocked.

Host-level common operations remain:

```bash
sudo systemctl restart ai-soc-api
sudo systemctl restart ai-soc-frontend
sudo systemctl status ai-soc-api --no-pager
sudo systemctl status ai-soc-frontend --no-pager
```

If Suricata or DNS telemetry workers are deployed:

```bash
sudo systemctl status ai-soc-suricata-ingest --no-pager
sudo systemctl status ai-soc-dns-collector --no-pager
```

## Configuration

Runtime configuration is read from `.env`. Start from `.env.example`, set real local values and never commit `.env`.

Important configuration areas:

- Wazuh indexer connection.
- PostgreSQL connection.
- Ollama model and base URL.
- Authentication signing secret.
- Ingestion polling and backlog thresholds.
- Noise suppression policy.
- AI timeout and fallback behavior.
- AI provider registry and AI Data Control policy.
- Qdrant indexing, auto-index and retention.
- observability and Alertmanager endpoints.
- Retention settings.

## Operational Guardrails

- Do not commit secrets, database backups, generated reports or local runtime files.
- Validate Health after service restarts.
- Review Security Audit after RBAC or user changes.
- Keep AI output as decision support, not automatic response.
- Keep semantic memory advisory and external providers disabled until governed.
- Review Operation History after managed service changes.
- Treat DNS telemetry as contextual host/time-window activity only.
