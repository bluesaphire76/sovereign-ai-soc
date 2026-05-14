# Sovereign AI SOC

**Sovereign AI SOC** is a local-first AI-assisted Security Operations Center lab that combines Wazuh alert ingestion, PostgreSQL persistence, local LLM analysis, incident correlation, investigation case management, executive dashboards, and secure HTTPS access.

The project is designed as a defensive cybersecurity platform for learning, experimentation, and prototyping AI-assisted SOC workflows while keeping sensitive data under local control.

> Current stable baseline: `v0.1.0-soc-lab-stable`

---

## Purpose

Modern SOC teams face three recurring challenges:

1. Too many alerts and too little context.
2. Limited analyst time for triage, correlation, and documentation.
3. Pressure to adopt AI without losing control over data, evidence, and decisions.

Sovereign AI SOC explores a practical answer to those challenges:

- ingest security alerts locally;
- enrich and analyze them with a local LLM;
- correlate related incidents;
- group them into investigation cases;
- support analysts with notes, audit trails, and AI-generated case analysis;
- provide executive-level visibility;
- export investigation reports;
- expose the dashboard through local authentication and HTTPS.

The system is intentionally defensive. It does not perform offensive activity, exploitation, or automated remediation.

---

## Key Features

### Alert Ingestion

- Wazuh alert ingestion from the Wazuh Indexer.
- Persistent deduplication using Wazuh document IDs.
- Watermark-based incremental ingestion.
- Ingestion state tracking for operational visibility.

### AI-Assisted Incident Analysis

- Local LLM-based incident analysis through Ollama.
- Defensive triage output in Italian.
- RAG-based security context enrichment.
- MITRE ATT&CK information extraction when available from Wazuh alerts.

### Incident Lifecycle

- Incident list with filtering and pagination.
- Incident detail page.
- Status management.
- Analyst notes.
- Audit trail for lifecycle changes.
- Advanced filters:
  - status;
  - risk;
  - host;
  - search;
  - MITRE technique;
  - recommended priority;
  - correlation type;
  - correlated yes/no;
  - date range.

### Correlation Engine

- Local correlation of related incidents.
- Correlation score.
- Attack chain detection.
- Correlation explanation visible in the UI.
- Structured correlation summary stored in PostgreSQL.

### Investigation Cases

- Automatic grouping of correlated incidents into investigation cases.
- Case detail page.
- Linked incident view.
- Case AI analysis with recommended actions.
- Case report export.

### Executive Dashboard

- Management-oriented SOC posture view.
- Open incidents.
- High and critical risk backlog.
- Open cases.
- Top risky hosts.
- Correlation type distribution.
- Operational recommendations.

### Platform Health

- Health dashboard for:
  - FastAPI backend;
  - PostgreSQL;
  - Ollama;
  - Wazuh Indexer;
  - Qdrant;
  - AI SOC worker heartbeat;
  - Wazuh ingest watermark.

### Report Export

- Incident report export in Markdown and JSON.
- Case report export in Markdown and JSON.
- Export includes AI analysis, notes, audit trail, correlation information, MITRE metadata, and raw alert data where applicable.

### Local Security

- Local dashboard authentication.
- HttpOnly session cookie.
- Secure cookie support for HTTPS.
- Nginx reverse proxy.
- HTTPS access for the AI SOC dashboard.
- Separation between:
  - Wazuh Dashboard: `https://localhost`
  - AI SOC Dashboard: `https://localhost:8443`

---

## Architecture

```text
Wazuh Indexer
    |
    | alerts
    v
AI SOC Worker
    |
    | deduplication + watermark
    v
PostgreSQL
    |
    | incidents, notes, audit trail, cases, reports
    v
FastAPI Backend
    |
    | REST API
    v
Next.js Dashboard
    |
    | HTTPS reverse proxy
    v
Browser
```

Supporting services:

```text
Ollama     -> local LLM analysis
Qdrant     -> local vector/search component
PostgreSQL -> persistent SOC data
Nginx      -> HTTPS reverse proxy
Wazuh      -> alert source
```

---

## Current Stable Release

The current stable baseline is:

```bash
v0.1.0-soc-lab-stable
```

This version includes:

- Wazuh ingestion;
- AI incident analysis;
- correlation engine;
- incident lifecycle;
- analyst notes;
- audit trail;
- case grouping;
- case AI analysis;
- executive dashboard;
- report export;
- local authentication;
- HTTPS local hardening.

---

## Repository Status

This project is currently a **local SOC lab and prototype**, not a production-ready commercial SOC platform.

It is suitable for:

- defensive cybersecurity experimentation;
- AI SOC workflow prototyping;
- local-first security architecture research;
- SOC analyst workflow demos;
- learning how LLMs can support triage and investigation;
- testing sovereign AI patterns for security operations.

It is not intended to be used as-is for regulated production environments without additional hardening, review, testing, and governance.

---

## Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Wazuh Indexer API
- Ollama
- Qdrant
- Uvicorn

### Frontend

- Next.js
- React
- TypeScript
- Tailwind CSS
- lucide-react

### Infrastructure

- WSL2 Ubuntu
- Docker for supporting services
- Nginx reverse proxy
- HTTPS with local certificate
- systemd services for local runtime

---

## Main URLs

In the current local hardened setup:

| Component | URL |
|---|---|
| Wazuh Dashboard | `https://localhost` |
| AI SOC Dashboard | `https://localhost:8443` |
| FastAPI backend | `127.0.0.1:8008` |
| Next.js frontend | `127.0.0.1:3000` |
| PostgreSQL | Docker container `postgres-soc` |

The browser should access the AI SOC UI through:

```text
https://localhost:8443
```

Direct HTTP access to the frontend should not be used.

---

## Main UI Areas

| Area | Purpose |
|---|---|
| `/` | Operational incident dashboard |
| `/incidents/[id]` | Incident investigation detail |
| `/cases` | Investigation case list |
| `/cases/[id]` | Case investigation detail and AI case analysis |
| `/health` | Platform health dashboard |
| `/executive` | Executive summary dashboard |
| `/login` | Local dashboard login |

---

## Environment Variables

The project uses environment variables for local configuration.

Typical backend variables include:

```env
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=aisoc
POSTGRES_USER=soc-userX
POSTGRES_PASSWORD=socpasswordX

WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_USER=userXYZ
WAZUH_PASSWORD=SecretPasswordXYZ

OLLAMA_MODEL=qwen3:8b
POLL_INTERVAL_SECONDS=30

QDRANT_URL=http://localhost:6333
APP_TIMEZONE=Europe/Zurich
```

Typical frontend local authentication variables include:

```env
LOCAL_AUTH_ENABLED=true
LOCAL_AUTH_USERNAME=userXYZ
LOCAL_AUTH_PASSWORD=change-this-password
LOCAL_AUTH_SESSION_SECRET=change-this-secret
LOCAL_AUTH_COOKIE_NAME=ai_soc_session
LOCAL_AUTH_COOKIE_SECURE=true

NEXT_PUBLIC_API_BASE_URL=/api-backend
```

Do not commit local secrets such as `.env`, `.env.local`, passwords, API keys, certificates, or private keys.

---

## Local Runtime Overview

A typical local setup uses:

```text
PostgreSQL      -> Docker
Wazuh           -> Docker stack
Qdrant          -> Docker
Ollama          -> local service
FastAPI         -> systemd service
AI SOC Worker   -> systemd service
Next.js         -> systemd service
Nginx           -> HTTPS reverse proxy
```

---

## Development Workflow

The recommended development workflow is:

```bash
git checkout main
git pull origin main
git checkout -b feature/<feature-name>
```

After implementation and testing:

```bash
git status -sb
git add <changed-files>
git commit -m "<clear commit message>"
git push -u origin feature/<feature-name>

git checkout main
git pull origin main
git merge feature/<feature-name>
git push origin main
```

Stable releases can be tagged:

```bash
git tag -a v0.1.0-soc-lab-stable -m "Stable AI SOC lab baseline with HTTPS and local auth"
git push origin v0.1.0-soc-lab-stable
```

---

## Defensive Use Only

This project is intended for defensive cybersecurity use only.

Do not use this project to:

- attack third-party systems;
- bypass authorization;
- perform unauthorized scanning;
- automate exploitation;
- conduct offensive activity outside legally authorized environments.

The platform is designed to support SOC triage, alert enrichment, investigation, reporting, and learning.

---

## Security Notes

This project includes local authentication and HTTPS hardening, but it should not be considered production-hardened by default.

Before any production-like use, review at least:

- authentication model;
- API authorization;
- TLS certificate trust;
- secret management;
- network exposure;
- dependency security;
- logging and retention;
- backup and restore;
- role-based access control;
- auditability;
- data protection requirements;
- legal and regulatory obligations.

---

## Known Limitations

Current limitations include:

- local authentication is intentionally simple;
- FastAPI does not yet enforce full API-level authentication;
- no role-based access control;
- no multi-user analyst workflow;
- no production-grade certificate authority integration;
- no formal threat model;
- no CI/CD security gate yet;
- no automated test suite covering all workflows;
- no production deployment guide.

---

## Suggested v0.2 Roadmap

Possible next phase:

1. Synthetic attack scenarios.
2. Detection quality dashboard.
3. Case workflow maturity:
   - owner;
   - SLA;
   - severity review;
   - case status lifecycle.
4. PDF report export.
5. AI SOC playbooks.
6. Multi-agent triage.
7. API authentication hardening.
8. Role-based access control.
9. CI/CD and automated smoke tests.
10. Local CA or trusted certificate workflow.

---

## Disclaimer

This project is a defensive security lab and research prototype.

It is provided without warranty. Users are responsible for validating the system, securing their environment, and ensuring that any use complies with applicable laws, regulations, internal policies, and authorization boundaries.

---

## License

License Apache License 2.0
