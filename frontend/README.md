# Sovereign AI SOC Frontend

The frontend is the Next.js 16 analyst console for Sovereign AI SOC.

## Product Routes

- `/` dashboard and operational trends
- `/incidents` and `/incidents/[id]`
- `/cases`, `/cases/[id]` and `/cases/kanban`
- `/executive`
- `/detection-quality`
- `/network-events`
- `/dns-telemetry`
- `/health`
- `/settings/detection-control`
- `/settings/ai-providers`
- `/settings/ai-data-control`
- `/settings/semantic-memory`
- `/system-information/operation-history`
- `/system-information/security-audit`
- `/admin/users`

Incident and case detail include Advanced Timeline/Investigation Graph,
Qdrant-backed Recommended Playbooks and Governed Remediation where applicable.

## Requirements

- Node.js 20 or newer
- npm
- FastAPI backend on the configured API base URL

## Configuration

Copy the example:

```bash
cp .env.local.example .env.local
```

Important variables:

```env
NEXT_PUBLIC_API_BASE_URL=/api-backend
NEXT_PUBLIC_AI_SOC_DEMO_MODE=false
NEXT_PUBLIC_GRAFANA_URL=https://grafana.varqon.net/grafana/
```

Use `http://127.0.0.1:8008` as the API base only when running the frontend
directly without Nginx.
Use the public HTTPS Grafana URL for the deployed ADMIN/ANALYST Observability
link. The local `http://127.0.0.1:3002/grafana/` URL is only for direct local
Docker troubleshooting.

Never place backend secrets or AI provider API keys in `NEXT_PUBLIC_*`
variables. They are embedded into the browser bundle.

## Development

```bash
npm ci
npm run dev
```

Open `http://127.0.0.1:3000`.

## Production Build

```bash
npm ci
npm run build
npm run start
```

The production-style systemd service is named `ai-soc-frontend`.

## Authentication and RBAC

The frontend hides or disables actions by role, but backend RBAC is the
security boundary.

- ADMIN: privileged settings, approvals, apply/rollback and user administration.
- ANALYST: investigation, AI generation, previews, validation and proposal work.
- VIEWER: read-only permitted views.

## Validation

```bash
npm run build
```

Public CI installs with `npm ci` and runs the production build. When changing
routes or navigation, also run the repository documentation validators because
the user guide and permission matrix mirror the current frontend surface.

## Related Documentation

- [User Guide](../docs/product/user-guide.md)
- [Architecture](../docs/architecture/architecture.md)
- [Security Model](../docs/architecture/security-model.md)
- [Current RBAC Matrix](../docs/architecture/permission-matrix-v0.3.md)
