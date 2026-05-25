# Admin Guide

This guide covers administrative operation for local/demo deployments.

## Roles

The product uses three primary roles:

| Role | Intent |
|---|---|
| ADMIN | User management, Security Audit, full SOC workflow access and privileged operations. |
| ANALYST | Incident and case investigation workflows, synthetic test execution where allowed, report generation and analysis. |
| VIEWER | Read-only SOC visibility with restricted workflow actions. |

Detailed permission notes are available in [permission-matrix-v0.3.md](permission-matrix-v0.3.md).

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

Security Audit is intended for ADMIN users only.

## Health and Runtime Observability

The Health page should be checked before demos, after deploys and during troubleshooting.

Watch:

- API health.
- PostgreSQL connectivity.
- Wazuh ingest freshness.
- Suricata network event freshness.
- DNS telemetry freshness.
- Worker backlog and lag.
- Ollama/local AI runtime status.

## Service Operations

The repository includes systemd-oriented deployment artifacts. Common operations:

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
- Retention settings.

## Operational Guardrails

- Do not commit secrets, database backups, generated reports or local runtime files.
- Validate Health after service restarts.
- Review Security Audit after RBAC or user changes.
- Keep AI output as decision support, not automatic response.
- Treat DNS telemetry as contextual host/time-window activity only.
