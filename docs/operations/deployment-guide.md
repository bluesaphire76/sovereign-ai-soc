# Deployment Guide

Sovereign AI SOC is intended for local lab and production-style demo deployments. The repository includes Nginx, systemd and collector artifacts that support that model.

![Deployment architecture](../assets/architecture/deployment-architecture.svg)

Editable Mermaid source: [deployment-architecture.mmd](../diagrams/deployment-architecture.mmd).

## Runtime Components

| Component | Typical role |
|---|---|
| Nginx | TLS termination, reverse proxy and security headers. |
| Next.js frontend | SOC user interface on port `3000` behind Nginx. |
| FastAPI backend | API service on port `8008` behind Nginx. |
| PostgreSQL | Operational datastore. |
| Qdrant | Local vector knowledge base for SOC playbook context used by RAG-enabled AI workflows. |
| Wazuh | Host/security telemetry source. |
| Suricata | Network IDS telemetry source. |
| Ollama | Default local AI runtime. |
| External AI providers | Optional OpenAI-compatible endpoints such as OpenRouter, disabled by default. |
| Prometheus/Grafana/Alertmanager | Optional metrics, dashboards and Wazuh backlog alerting. |
| Loki/Grafana Alloy | Optional selected platform-log storage and collection. |
| systemd workers/timers | API, frontend, ingestion and Qdrant maintenance process management. |

The SVG above is committed so the architecture remains visible in Markdown viewers that do not render Mermaid directly.

## Configuration

Start from `.env.example`:

```bash
cp .env.example .env
```

Set local values for:

- Wazuh indexer URL and credentials.
- PostgreSQL host, database, user and password.
- Qdrant URL, collection and knowledge base path if RAG context is enabled.
- Ollama model and base URL.
- AI provider registry and AI Data Control policy paths.
- External provider credentials only when explicitly governed.
- Authentication secret.
- Ingestion and health thresholds.
- Retention policy.

Never commit `.env`.

## Frontend

The frontend is under `frontend/`:

```bash
cd frontend
npm install
npm run build
npm run start
```

The deployed service is represented by `ai-soc-frontend` in existing systemd documentation.

## Backend

The backend is FastAPI:

```bash
PYTHONPATH=. .venv/bin/uvicorn api:app --host 127.0.0.1 --port 8008
```

The deployed service is represented by `ai-soc-api`.

## Qdrant Knowledge Base

Qdrant-backed RAG is configured with `AI_SOC_RAG_ENABLED`, `QDRANT_URL`, `QDRANT_COLLECTION` and `QDRANT_KNOWLEDGE_BASE_PATH`.

Index local Markdown playbooks into the configured collection:

```bash
PYTHONPATH=. .venv/bin/python rag_index.py --recreate
```

The Health page reports Qdrant as `WARN` when the service is reachable but the configured collection is missing or empty.

For playbook-only changes:

```bash
PYTHONPATH=. .venv/bin/python scripts/reindex_qdrant_playbooks.py --dry-run
PYTHONPATH=. .venv/bin/python scripts/reindex_qdrant_playbooks.py --apply
PYTHONPATH=. .venv/bin/python scripts/validate_qdrant_playbook_expansion.py
```

Historical, Detection Control and Case Closure memory have separate backfill
and retention runbooks in
[Qdrant Semantic Memory](../architecture/v0.7-qdrant-semantic-memory.md).

## AI Providers

Local Ollama requires no external credential. OpenRouter uses the
OpenAI-compatible adapter and is disabled by default.

Do not enable an external provider until provider allowlists and AI Data
Control policy are configured. The real provider and policy JSON files are
local ignored runtime files; use the committed examples as templates.

## Observability

The optional observability stack is separate from the Docker application demo:

```bash
docker compose -f deploy/observability/docker-compose.loki.yml config --quiet
docker compose -f deploy/observability/docker-compose.yml config --quiet
```

Start order matters because the Loki/Alloy file uses the external
`ai_soc_observability` network created by the main observability stack. Review
the [observability guide](v0.6.0-observability.md),
[Alertmanager runbook](v0.7.0-alertmanager-wazuh-backlog-alerting.md) and
[Loki/Alloy runbook](v0.7.0-minimal-loki-observability.md).

## Nginx

Nginx configuration exists under `deploy/nginx/` and includes:

- Local TLS proxying.
- `/api-backend/` routing to FastAPI.
- `/reports/` routing for generated report access.
- Security headers.
- Cache controls for sensitive pages.

## Ingestion Workers

Suricata ingest:

- `deploy/systemd/ai-soc-suricata-ingest.service`
- `workers/suricata_ingest_worker.py`
- `scripts/ingest_suricata_eve.py`

DNS collector:

- `deploy/systemd/ai-soc-dns-collector.service`
- `deploy/dns/ai-soc-dns-collector.py`
- `scripts/ingest_dns_events_from_wazuh.py`

## Service Operations

```bash
sudo systemctl restart ai-soc-api
sudo systemctl restart ai-soc-frontend
sudo systemctl status ai-soc-api --no-pager
sudo systemctl status ai-soc-frontend --no-pager
```

Optional worker checks:

```bash
sudo systemctl status ai-soc-suricata-ingest --no-pager
sudo systemctl status ai-soc-dns-collector --no-pager
```

The UI/API managed-operation path is allowlisted and audited. See
[Service Operations and Operation History](v0.7-service-operations-history.md).

## Validation

After deployment or restart:

1. Open `/health`.
2. Confirm API, PostgreSQL and Qdrant are healthy/populated as expected.
3. Confirm Wazuh and Suricata/network freshness if those sources are expected;
   inspect DNS telemetry on its dedicated page.
4. Confirm Ollama and provider-registry state.
5. Confirm optional Grafana, Prometheus and Alertmanager state when deployed.
6. Open `/incidents`, `/executive`, `/detection-quality`,
   `/settings/semantic-memory` and `/system-information/operation-history`.
7. Generate a report only with clean demo data.
