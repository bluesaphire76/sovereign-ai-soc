# Ports and Components

Defaults below describe the documented local and Docker demo paths. Change
ports through the relevant untracked environment file when they conflict with
existing services.

## Default ports

| Component | Default endpoint | Requirement | Notes |
|---|---|---|---|
| Next.js frontend | `127.0.0.1:3000` | Core application | Exposed by the Docker demo and host service. |
| FastAPI backend | `127.0.0.1:8008` | Core application | Frontend browser requests use this host endpoint by default. |
| PostgreSQL | `127.0.0.1:5432` | Core datastore | Host-runtime default. Docker demo keeps PostgreSQL internal as `postgres:5432`. |
| Qdrant | `127.0.0.1:6333` | Required for semantic memory | Docker-internal name is `qdrant:6333`. |
| Ollama | `127.0.0.1:11434` | Optional for deterministic flow; needed for full local AI | Docker-internal name is `ollama:11434`. |
| llama.cpp router/API | `127.0.0.1:8081` | Optional local AI runtime | Disabled by default; exposes router control and local OpenAI-compatible API when configured. |
| Grafana | `127.0.0.1:3002/grafana/` | Optional observability | Not included in the Docker demo foundation. |
| Prometheus | `127.0.0.1:9090` | Optional observability | Not included in the Docker demo foundation. |
| Alertmanager | `127.0.0.1:9093` | Optional alerting | Not included in the Docker demo foundation. |
| Loki | `127.0.0.1:3100` | Optional logging | Not included in the Docker demo foundation. |
| Grafana Alloy | `127.0.0.1:12345` | Optional log collector UI/health | Forwards selected Docker/journal logs to Loki. |
| cAdvisor | `127.0.0.1:8082` | Optional container metrics | Scraped by Prometheus. |
| node-exporter | `127.0.0.1:9100` | Optional host metrics | Scraped by Prometheus. |
| ntfy bridge | `127.0.0.1:8011` | Optional Alertmanager notification bridge | Requires an intentionally untracked local environment file. |

Wazuh and Suricata use deployment-specific ports and integrations and are
treated as advanced external telemetry sources rather than part of the basic
Docker demo.

The hosted operator Grafana endpoint is published through Cloudflare at
`https://grafana.varqon.net/grafana/`. Keep Prometheus, Alertmanager,
exporters, Loki, Alloy and application `/metrics` endpoints private/local.
When Qdrant, Grafana, llama.cpp native/router UI or other operational consoles
are exposed beyond loopback, prefer the configured HTTPS reverse-proxy path and
keep direct HTTP endpoints for local health checks and service-to-service use.

## Mandatory and optional components

| Component | Synthetic demo | Full feature value |
|---|---|---|
| Frontend and API | Required | Required |
| PostgreSQL | Required | Required |
| Qdrant | Needed for semantic-memory/playbook retrieval | Recommended |
| Ollama and local model | Optional for deterministic fallback | Required for full AI-assisted analysis |
| llama.cpp local runtime | Optional local provider path | Optional for GGUF/profile-based local AI evaluation |
| GPU | Not required | Optional performance improvement |
| Wazuh | Not required | Required for real host/security telemetry |
| Suricata | Not required | Required for real network IDS telemetry |
| Grafana/Prometheus/Alertmanager | Not required | Optional metrics, dashboards and alerting |
| Loki/Grafana Alloy | Not required | Optional selected platform-log troubleshooting |
| External AI provider | Not required | Optional; disabled by default and policy-governed |

## Host and Docker names

Use loopback addresses from the browser and host processes. Containers on the
Docker demo network use Compose service names:

| Host-side URL | Docker-side URL |
|---|---|
| `http://127.0.0.1:8008` | `http://ai-soc-api:8008` where applicable |
| `http://127.0.0.1:6333` | `http://qdrant:6333` |
| `http://127.0.0.1:11434` | `http://ollama:11434` |
| `http://127.0.0.1:8081` | operator-managed llama.cpp router/runtime |
| `127.0.0.1:5432` | `postgres:5432` |

The Docker demo publishes frontend, API, Qdrant, and Ollama ports on loopback.
PostgreSQL remains internal to the Compose network.

See [Docker Demo Packaging](docker-demo-packaging.md) and
[Troubleshooting](troubleshooting.md) for setup boundaries and failure modes.
