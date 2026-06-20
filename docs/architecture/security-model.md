# Security Model

Sovereign AI SOC is designed around local-first data sovereignty, RBAC, auditability and human-controlled operations.

## Local-first Data Sovereignty

Core telemetry, AI prompts, AI output, reports and evidence packs are generated in the local environment. Ollama provides a local AI runtime so the platform does not require sending sensitive SOC context to an external AI provider.

## RBAC

The platform uses role-based access control:

- `ADMIN`: administrative access, Security Audit, user management and SOC workflows.
- `ANALYST`: investigation workflows and operational SOC actions where permitted.
- `VIEWER`: read-only access with restricted workflow actions.

See [permission-matrix-v0.3.md](permission-matrix-v0.3.md).

## Security Audit

Security Audit records governance-relevant activity such as:

- Authentication events.
- RBAC denials.
- User management.
- Privileged SOC actions.

The Security Audit page is intended for ADMIN users.

## Session and Token Hardening

Authentication uses a backend signing secret configured through `.env`. The secret must be at least 32 characters and should be randomly generated.

Never commit:

- `.env`
- credentials
- access tokens
- database backups
- generated reports containing sensitive data

## Nginx and Browser Security

The repository includes Nginx security header snippets and local TLS proxy configuration. Sensitive application routes use no-store cache controls.

## Local AI Boundaries

AI can summarize, recommend and explain. It does not automatically execute operational response.

AI does not automatically:

- Terminate processes.
- Disable accounts.
- Block traffic.
- Modify firewall rules.
- Close incidents or cases.
- Override RBAC.
- Suppress detections.

## Human Approval

Analysts remain responsible for:

- Validating AI guidance.
- Performing containment or remediation.
- Escalating or closing incidents.
- Closing cases.
- Distributing reports.

## Contextual Telemetry Boundaries

DNS telemetry is context, not proof:

> DNS context is matched by host/client IP and selected time window only. It does not imply causal correlation with the incident.

This wording should be preserved in reports, UI and demos.
