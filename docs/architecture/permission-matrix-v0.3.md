# Current RBAC Permission Matrix

The filename is retained for compatibility because RBAC was introduced in
v0.3. The matrix below describes the current v0.7 backend policy.

## Security Principle

Frontend visibility is a usability feature, not a security boundary. The
FastAPI authentication middleware matches every protected method/path against
an explicit role allowlist. Authenticated routes that are not classified are
denied by default and generate `RBAC_DENIED` audit events.

## Roles

| Role | Intended authority |
|---|---|
| `ADMIN` | Platform administration, privileged configuration, approvals, governed apply/rollback and all analyst/read actions. |
| `ANALYST` | Investigation, case workflow, AI generation, previews, validation, proposal preparation and other operator actions. |
| `VIEWER` | Read-only access to permitted SOC, health, history and reporting views. |

## Current Capability Matrix

| Capability | ADMIN | ANALYST | VIEWER |
|---|---:|---:|---:|
| Dashboards, incidents, cases, reports and metrics | Yes | Yes | Yes |
| Update incident/case workflow and notes | Yes | Yes | No |
| Generate incident/case AI analysis | Yes | Yes | No |
| Run synthetic tests | Yes | Yes | No |
| Advanced Incident Timeline | Yes | Yes | Yes |
| Investigation Graph | Yes | Yes | Yes, with raw-event metadata redaction |
| Similar incidents and Recommended Playbooks | Yes | Yes | No |
| Detection Quality semantic context | Yes | Yes | No |
| Read Detection Control inventory/lifecycle/history | Yes | Yes | Yes |
| Create/edit/validate/submit Detection Control lifecycle drafts | Yes | Yes | No |
| Approve/reject/apply/disable lifecycle items | Yes | No | No |
| Direct Detection Control rule write/enable/disable/delete | Yes | No | No |
| Validate/diff configuration versions | Yes | Yes | No |
| Apply/rollback configuration versions | Yes | No | No |
| Match preview, mark reviewed, extend review | Yes | Yes | No |
| Read AI provider state and health | Yes | Yes | Yes |
| Edit/test AI providers | Yes | No | No |
| Read AI Data Control policies/decisions | Yes | Yes | Yes |
| Run AI Data Control previews | Yes | Yes | No |
| Edit AI Data Control policy | Yes | No | No |
| View/search Semantic Memory | Yes | Yes | No |
| Run semantic backfill or retention operations | Yes | No | No |
| Read remediation catalogs/proposals/history | Yes | Yes | Yes |
| Create/edit/submit/cancel/convert proposals | Yes | Yes | No |
| Approve/reject remediation proposals | Yes | No | No |
| Execute approved allowlisted internal SOAR workflow action | Yes | Yes | No |
| Read Health, service status and Operation History | Yes | Yes | Yes |
| Request service restart preview | Yes | Yes | No |
| Execute allowlisted service restart | Yes | No | No |
| Read Security Audit | Yes | No | No |
| Manage users | Yes | No | No |
| View own user/reset own password | Yes | Yes | Yes |

## Endpoint Groups

### Public

- `POST /auth/login`
- `GET /health`
- explicitly configured public report/static prefixes, where applicable

All other API routes require authentication.

### All Authenticated Roles

Read-oriented groups include:

- incidents, cases, timelines, investigation graphs, reports and metrics;
- remediation plans, dry-runs, rollback readiness, audit trail and replay;
- remediation catalogs and proposal history;
- Detection Control inventory, lifecycle history and configuration versions;
- platform health and Wazuh ingest status;
- AI provider state/health and AI Data Control policy visibility;
- service status and Operation History;
- self-service user/profile operations.

### ADMIN and ANALYST

Operator groups include:

- incident/case updates, notes and AI generation;
- synthetic tests and demo-record deletion;
- Similar Incidents, Recommended Playbooks and semantic decision support;
- Detection Control draft lifecycle, validation, previews and reviews;
- remediation proposal preparation and internal conversion;
- service restart preview;
- AI Data Control redaction/evaluation previews.

### ADMIN Only

Privileged groups include:

- user administration and Security Audit;
- AI provider configuration/test;
- AI Data Control policy changes;
- Qdrant backfill/retention apply operations;
- Detection Control approval, apply, rollback, disable and direct rule writes;
- remediation proposal approval/rejection;
- allowlisted service restart execution.

## Additional Object-Level Rules

- Non-admin users receive only their own user record from `GET /users`.
- Password reset is self-only for ANALYST and VIEWER; ADMIN may reset any user.
- Raw incident timeline payloads are available only to ADMIN and ANALYST and
  audited when requested.
- Semantic Memory UI/API is intentionally unavailable to VIEWER.
- Service restart requires an allowlisted service, reason and explicit
  confirmation in addition to ADMIN role.
- Proposal conversion may impose stricter risk/action-specific ADMIN checks.
- Detection lifecycle transitions are enforced by state as well as role.

## Audit Expectations

Authentication failures, RBAC denials, privileged configuration changes,
external-provider decisions, remediation transitions, Detection Control
changes and service operations must remain auditable without storing secrets
or raw external-provider prompts/responses.
