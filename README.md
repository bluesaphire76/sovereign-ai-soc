# Sovereign AI SOC

**Sovereign AI SOC** is a local-first Security Operations Center assistant designed to support incident triage, case management, analyst workflow, evidence review, reporting, detection-quality validation, and executive SOC visibility.

The project is built for environments where **data sovereignty**, **local execution**, **transparency**, and **operational control** matter. It is intended as a practical AI-assisted SOC console, not as a black-box managed service.

---

## Current Status

This repository is currently moving toward the **v0.2 Release Candidate**.

The v0.2 scope includes:

- Enterprise-style SOC dashboard
- Incident queue and incident detail views
- Case queue, case detail, and Kanban board
- AI case analysis and suggested action plans
- Case workflow management
- Case closure checklist and closure readiness validation
- Analyst evidence pack export
- Executive PDF report generation
- Executive summary dashboard
- Detection quality dashboard
- Synthetic test runner from the GUI
- Platform health dashboard
- Local user management and personal login
- Admin user management page
- Local HTTPS access through Nginx

---

## Why This Project Exists

Traditional SOC tools often create three problems:

1. **Too much raw data**
2. **Too little operational context**
3. **Limited analyst workflow support**

Sovereign AI SOC aims to reduce that gap by combining:

- Structured incident ingestion
- Risk scoring
- Correlation context
- Case grouping
- AI-assisted analysis
- Human workflow tracking
- Evidence export
- Executive visibility
- Local-first deployment

The goal is not to replace analysts, but to give analysts and SOC leaders a clearer operational console.

---

## Key Capabilities

### Incident Management

The platform provides incident-level visibility with:

- Incident list and filtering
- Incident detail page
- Risk score
- Correlation score
- Recommended priority
- MITRE information
- Raw Wazuh alert evidence
- Analyst notes
- Audit trail
- Markdown and JSON report export

---

### Case Management

Incidents can be grouped into investigation cases.

Case functionality includes:

- Case queue
- Case detail
- Case Kanban board
- Case ownership
- Status management
- Severity review
- SLA state
- Related incidents
- Case workflow audit
- Case timeline
- Case actions
- AI-generated action suggestions
- Closure checklist
- Closure readiness validation

---

### AI Case Analysis

The system can generate AI-assisted case analysis with:

- Case summary
- Risk interpretation
- Suggested investigation direction
- Recommended status
- Recommended severity
- Analyst-oriented explanation

The AI output is presented as decision support. The analyst remains responsible for review and final decisions.

---

### Evidence Packs and Reporting

The platform supports export-oriented workflows, including:

- Analyst evidence pack in Markdown
- Incident report export
- Case report export
- Executive PDF report
- Structured case metadata
- Related incidents
- Case actions
- Closure readiness
- AI case analysis
- Timeline and audit context

This makes the system useful not only for investigation, but also for governance, handover, and management reporting.

---

### Executive Dashboard

The Executive dashboard provides a compact management view of SOC posture, including:

- Overall SOC posture
- Open incidents
- High and critical incidents
- Open cases
- Escalated items
- Maximum and average risk
- Recommended operational focus
- Incident status distribution
- Case status distribution
- Priority distribution
- Top risk hosts
- Top correlation types
- Latest cases
- Latest high-risk incidents

---

### Detection Quality Dashboard

The Detection Quality dashboard helps validate detection pipeline effectiveness.

It includes:

- Synthetic incident count
- Correlation coverage
- High and critical priority assignment
- MITRE signal coverage
- Quality score
- Scenario coverage chart
- Scenario quality breakdown
- Latest synthetic incidents

---

### Synthetic Test Runner

The GUI includes a synthetic test runner to generate controlled test incidents.

Supported scenarios include:

- SSH brute force
- Privilege escalation
- Malware indicator
- All scenarios

The runner allows the analyst to configure:

- Scenario
- Count per scenario
- Host
- Created by

Generated synthetic incidents are inserted into the local incident store and immediately appear in the Detection Quality dashboard.

This is useful for validating:

- Detection visibility
- Correlation logic
- Priority assignment
- MITRE tagging
- Dashboard updates
- Report generation

---

### Platform Health Dashboard

The Health dashboard provides an operational view of the local platform components.

It shows:

- Overall health
- Components checked
- Average latency
- Latest incident
- Component status tiles
- Backend/API status
- Database status
- Wazuh-related status
- Worker heartbeat
- Local AI component status where available

---

### User Management and Login

The system includes local user management.

Current functionality includes:

- Personal login
- Local user table
- Password hashing with PBKDF2-SHA256
- Signed local access token
- Admin user management page
- Create users
- Enable or disable users
- Reset passwords
- Roles:
  - `ADMIN`
  - `ANALYST`
  - `VIEWER`

The GUI uses the signed-in user for workflow actions such as case ownership and review attribution.

> Note: the current v0.2 implementation protects the GUI and user-management APIs. Full backend API hardening for every existing endpoint should be handled as a dedicated security-hardening step.

---

## Architecture

High-level architecture:

```text
Browser / Analyst GUI
        |
        | HTTPS
        v
Nginx reverse proxy
        |
        v
Next.js frontend
        |
        | REST API
        v
FastAPI backend
        |
        v
Local database
        |
        +--> Incidents
        +--> Cases
        +--> Case actions
        +--> Case audits
        +--> Closure checklists
        +--> AI analyses
        +--> Users
        +--> Worker health
```

The system is designed to run locally and avoid sending sensitive SOC data to external services by default.

---

## Technology Stack

### Backend

- Python
- FastAPI
- SQLAlchemy
- Pydantic
- Local database through SQLAlchemy
- Local authentication utilities
- Report builders
- Case workflow logic
- Synthetic test generation

### Frontend

- Next.js
- TypeScript
- Tailwind CSS
- Recharts
- Lucide icons
- Enterprise-style dashboard pages

### Deployment

- Linux host
- Systemd services
- Nginx reverse proxy
- Local HTTPS endpoint

---

## Main Pages

| Page | Purpose |
|---|---|
| `/` | Main SOC dashboard |
| `/incidents/[id]` | Incident detail and evidence |
| `/cases` | Case queue |
| `/cases/[id]` | Case detail and workflow |
| `/cases/kanban` | Case Kanban board |
| `/executive` | Executive SOC summary |
| `/detection-quality` | Detection quality and synthetic tests |
| `/health` | Platform health |
| `/login` | User login |
| `/admin/users` | User management for administrators |

---

## Repository Structure

Typical key files and folders:

```text
.
├── api.py
├── auth_utils.py
├── models.py
├── database.py
├── report_builder.py
├── evidence_pack_builder.py
├── executive_pdf_builder.py
├── case_ai_analysis.py
├── case_action_suggestions.py
├── case_timeline.py
├── platform_health.py
├── wazuh_ingest_state.py
├── scripts/
│   ├── create_users_table.py
│   └── create_default_admin_user.py
└── frontend/
    ├── src/app/
    │   ├── page.tsx
    │   ├── login/page.tsx
    │   ├── admin/users/page.tsx
    │   ├── cases/page.tsx
    │   ├── cases/[id]/page.tsx
    │   ├── cases/kanban/page.tsx
    │   ├── incidents/[id]/page.tsx
    │   ├── executive/page.tsx
    │   ├── detection-quality/page.tsx
    │   └── health/page.tsx
    ├── src/components/AppNavigation.tsx
    └── src/lib/auth.ts
```

---

## Local Setup

### 1. Clone the repository

```bash
git clone <repository-url>
cd ai-soc-assistant
```

---

### 2. Create Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

### 3. Install frontend dependencies

```bash
cd frontend
npm install
```

---

### 4. Configure environment

Recommended environment variables:

```bash
export AI_SOC_AUTH_SECRET="change-this-secret-before-real-use"
export AI_SOC_AUTH_TOKEN_TTL_SECONDS="28800"
export AI_SOC_ADMIN_USERNAME="admin"
export AI_SOC_ADMIN_PASSWORD="<set-a-strong-password>"
export AI_SOC_ADMIN_DISPLAY_NAME="SOC Administrator"
```

Frontend `.env.local` example:

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:8008
```

> Change the default admin password immediately after first login.

---

### 5. Initialize user table

```bash
cd ~/lab/ai-soc-assistant

.venv/bin/python scripts/create_users_table.py
```

---

### 6. Create default admin user

```bash
AI_SOC_ADMIN_PASSWORD='<set-a-strong-password>' \
.venv/bin/python scripts/create_default_admin_user.py \
  --username admin \
  --display-name "SOC Administrator"
```

---

### 7. Start backend manually

```bash
cd ~/lab/ai-soc-assistant

.venv/bin/uvicorn api:app --host 0.0.0.0 --port 8008
```

---

### 8. Start frontend manually

```bash
cd ~/lab/ai-soc-assistant/frontend

npm run build
npm run start -- -H 0.0.0.0 -p 3000
```

---

## Systemd Deployment

Example services used in local deployment:

```text
ai-soc-api.service
ai-soc-frontend.service
```

Example frontend service properties:

```text
WorkingDirectory=/home/lele/lab/ai-soc-assistant/frontend
Environment="NODE_ENV=production"
Environment="PORT=3000"
ExecStart=npm run start -- -H 0.0.0.0 -p 3000
```

The local HTTPS endpoint can be exposed through Nginx, for example:

```text
https://localhost:8443
```

---

## Useful Smoke Tests

### Backend health

```bash
curl -s http://localhost:8008/health | python3 -m json.tool
```

---

### Platform health

```bash
curl -s http://localhost:8008/platform/health | python3 -m json.tool
```

---

### Login

```bash
curl -s -X POST "http://localhost:8008/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "<set-a-strong-password>"
  }' | python3 -m json.tool
```

---

### Authenticated user

```bash
TOKEN="<PASTE_TOKEN_HERE>"

curl -s "http://localhost:8008/auth/me" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

### Synthetic scenarios

```bash
curl -s "http://localhost:8008/synthetic-tests/scenarios" | python3 -m json.tool
```

---

### Run synthetic test

```bash
curl -s -X POST "http://localhost:8008/synthetic-tests/run" \
  -H "Content-Type: application/json" \
  -d '{
    "scenario": "ssh_bruteforce",
    "count": 1,
    "host": "synthetic-sensor-01",
    "created_by": "local_analyst"
  }' | python3 -m json.tool
```

---

### Detection quality search

```bash
curl -s "http://localhost:8008/incidents?page=1&limit=20&search=SYNTHETIC" \
  | python3 -m json.tool
```

---

## Build and Validation

Backend compile:

```bash
cd ~/lab/ai-soc-assistant

.venv/bin/python -m py_compile \
  api.py \
  auth_utils.py \
  models.py \
  scripts/create_users_table.py \
  scripts/create_default_admin_user.py
```

Frontend build:

```bash
cd ~/lab/ai-soc-assistant/frontend

rm -rf .next
npm run build
```

Restart services:

```bash
sudo systemctl restart ai-soc-api
sudo systemctl restart ai-soc-frontend
```

## Security Notes

This project is currently intended for local-first controlled environments.

Important notes:

- Change `AI_SOC_AUTH_SECRET` before any real use.
- Use a strong initial admin password and rotate it regularly.
- Do not expose the system directly to the public Internet.
- Use HTTPS through a trusted reverse proxy.
- Restrict network access where possible.
- Full API-wide authorization enforcement should be implemented as a dedicated hardening step.
- Audit logs and case workflow attribution should be reviewed before production use.

---

## Roadmap

### v0.3 completed

Sovereign AI SOC v0.3 focused on security hardening, RBAC, operational control, enterprise UX and production-like runtime maturity.

Completed v0.3 improvements include:

- API-wide authentication and authorization hardening
- Role-based access control for `ADMIN`, `ANALYST` and `VIEWER`
- Frontend authorization alignment with backend session state
- Admin-only Security Audit UI
- Security audit logging for privileged and security-relevant actions
- Token/session robustness and expiry handling
- Nginx security headers and reverse proxy hardening
- Secrets and configuration hardening
- PostgreSQL 18.4 Docker runtime migration
- Wazuh ingest worker hardening
- Health observability components
- Sidebar navigation
- Enterprise-style Incidents page
- Improved Case Queue and Case Detail UX
- Create Case from Incident workflow
- Admin-only enable/disable user workflow

### Planned next improvements

Planned improvements for future releases include:

- Event aggregation and deduplication before incident creation
- Correlation-first ingestion to reduce noise from repetitive Wazuh events
- Better separation between raw events, alerts, incidents and cases
- More advanced case workflow automation
- Improved report templates
- Additional synthetic scenarios
- More detection quality metrics
- Optional external identity provider integration
- More granular admin settings
- Production-like deployment documentation
- Backup and restore documentation
- Database retention and cleanup policies
- Improved AI model runtime observability

---

## License


```text
Apache License 2.0
```

---

## Disclaimer

Sovereign AI SOC is an experimental AI-assisted SOC platform.

It is not a certified SIEM, SOAR, MDR platform, or compliance product. All AI-generated content must be reviewed by qualified security personnel before operational or executive decisions are made.

## v0.3 release status

Sovereign AI SOC v0.3 introduces the security, operational and enterprise UX hardening needed to move the project beyond the initial prototype stage.

Key v0.3 improvements include:

- Role-based access control for `ADMIN`, `ANALYST` and `VIEWER`
- Admin-only Security Audit UI
- Security-relevant audit logging
- Token/session robustness
- Frontend authorization alignment with `/auth/me`
- Nginx security headers and runtime binding hardening
- Secrets and configuration hardening
- PostgreSQL 18.4 Docker runtime migration
- Wazuh ingest and worker hardening
- Health observability components
- Enterprise-style sidebar navigation
- Improved Case Queue and Case Detail UX
- Dedicated Incidents page
- Create Case from Incident workflow
- Admin-only enable/disable user workflow

The platform remains local-first and human-in-the-loop: AI supports triage, correlation, investigation summaries and remediation planning, but does not execute security actions automatically.

See:

- `docs/v0.3-release-notes.md`
- `docs/v0.3-release-checklist.md`
- `docs/v0.3-final-validation.md`

## v0.4 operational maturity documents

The v0.4 roadmap adds operational hardening around ingestion quality, AI triage robustness, risk governance, reporting, database lifecycle and release validation.

Key v0.4 documents:

- `docs/v0.4-risk-normalization-dry-run.md`
- `docs/v0.4-db-retention-backup-restore.md`
- `docs/v0.4-regression-smoke-validation.md`
- `docs/v0.4-production-demo-hardening.md`
- `docs/v0.4-release-checklist.md`

