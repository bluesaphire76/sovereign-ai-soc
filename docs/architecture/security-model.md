# Security Model

Sovereign AI SOC is designed around local-first data sovereignty, secure
defaults, backend RBAC, auditability and human-controlled operations.

## Local-first Data Sovereignty

Core telemetry, semantic memory, AI prompts/output, reports and evidence packs
can remain in the local environment. Ollama is the default provider.

External AI is optional and disabled by default. A request can leave the local
environment only when the provider registry and AI Data Control both allow the
feature, role, provider and data-exposure mode.

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
- AI provider tests, external calls and blocked calls.
- AI Data Control decisions.
- Detection Control lifecycle/configuration changes.
- remediation proposal transitions and conversions.
- service status/restart operations.

The Security Audit page is intended for ADMIN users.

## Session and Token Hardening

Authentication uses a backend signing secret configured through `.env`. The secret must be at least 32 characters and should be randomly generated.

Never commit:

- `.env`
- credentials
- access tokens
- database backups
- generated reports containing sensitive data
- provider runtime configuration containing credentials

## Nginx and Browser Security

The repository includes Nginx security header snippets and local TLS proxy configuration. Sensitive application routes use no-store cache controls.

## AI Provider and Data Boundaries

AI can summarize, recommend and explain. It does not automatically execute
operational response.

External-provider safeguards include:

- global external-provider disable switch;
- provider enablement and configuration checks;
- per-feature allowlists;
- AI Data Control policy modes;
- deterministic redaction;
- harmless confirmed provider tests;
- safe audit metadata without raw prompts/responses;
- deterministic fallback.

`FULL_CONTEXT_ADMIN_ONLY` is not unredacted-secret mode: secrets and
credentials remain redacted.

AI does not automatically:

- Terminate processes.
- Disable accounts.
- Block traffic.
- Modify firewall rules.
- Close incidents or cases.
- Override RBAC.
- Suppress detections.
- Bypass provider/data policy.
- Treat semantic similarity as proof.

## Semantic Memory Boundary

Qdrant stores advisory derived context. It must not be used for primary
deduplication, final severity, automatic suppression, incident/case closure,
Detection Control approval or remediation authorization.

Knowledge, historical incident, Detection Control and Case Closure source types
remain distinguishable. Case Closure memory includes only final or explicitly
approved outcomes.

## Detection and Remediation Boundaries

Detection Control writes require server-side validation and role-specific
lifecycle transitions. Apply, rollback, approval and disable actions are
ADMIN-only.

Governed remediation can create internal records, documents and Detection
Control drafts. External ticketing, firewall, EDR and SOAR connectors are
disabled/proposal-only. Arbitrary shell input is not accepted.

Service Operations uses a fixed allowlist and command shape. Restart execution
is ADMIN-only, requires reason and confirmation, and stores a safe operation
record. The API cannot restart itself through its own request.

## Human Approval

Analysts remain responsible for:

- Validating AI guidance.
- Performing containment or remediation.
- Escalating or closing incidents.
- Closing cases.
- Distributing reports.
- Reviewing semantic context and playbooks.
- Approving Detection Control or remediation changes where their role permits.

## Contextual Telemetry Boundaries

DNS telemetry is context, not proof:

> DNS context is matched by host/client IP and selected time window only. It does not imply causal correlation with the incident.

This wording should be preserved in reports, UI and demos.

Semantic memory has an equivalent boundary:

> Retrieved semantic memory is advisory context only. Current deterministic
> evidence, RBAC, audit and human validation remain authoritative.
