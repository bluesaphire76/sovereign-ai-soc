# Contributing to Sovereign AI SOC

Thank you for your interest in contributing to Sovereign AI SOC.

This project is focused on building a local-first, security-conscious AI-assisted SOC platform.

Core principles:

- Local-first execution
- Data sovereignty
- Security by design
- Clear analyst workflow
- Transparent AI assistance
- Operational reliability

---

## Contribution Principles

Before opening a pull request, make sure your change:

- Has a clear operational purpose.
- Does not weaken authentication, authorization, logging, or data protection.
- Does not introduce hardcoded secrets, credentials, tokens, or private data.
- Does not expose stack traces or internal exception details to users.
- Does not send SOC data to external services unless explicitly documented and approved.
- Keeps the UI usable, compact, and aligned with the enterprise SOC console design.
- Is small enough to review safely.

---

## Branching Model

Do not work directly on `main`.

Recommended branch naming:

```text
feature/<short-description>
fix/<short-description>
docs/<short-description>
security/<short-description>
release/<version>
```

Examples:

```text
feature/case-escalation-rules
fix/auth-token-validation
docs/community-standards
security/api-rbac-hardening
```

---

## Local Setup

Backend:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Frontend:

```bash
cd frontend
npm install
```

---

## Required Validation Before Pull Request

Backend compile check:

```bash
cd ~/lab/ai-soc-assistant

.venv/bin/python -m py_compile \
  api.py \
  auth_utils.py \
  models.py \
  database.py \
  report_builder.py \
  evidence_pack_builder.py \
  executive_pdf_builder.py \
  case_ai_analysis.py \
  case_action_suggestions.py \
  case_timeline.py \
  platform_health.py \
  wazuh_ingest_state.py \
  scripts/create_users_table.py \
  scripts/create_default_admin_user.py
```

Frontend build:

```bash
cd ~/lab/ai-soc-assistant/frontend

rm -rf .next
npm run build
```

Recommended smoke tests:

```bash
curl -s http://localhost:8008/health | python3 -m json.tool
curl -s http://localhost:8008/platform/health | python3 -m json.tool | head -80
```

---

## Pull Request Requirements

A pull request should include:

- Clear summary of the change
- Reason for the change
- Files or modules affected
- Tests performed
- Security impact, if any
- Screenshots for UI changes, where useful
- Known limitations or follow-up work

---

## Security Expectations

Do not commit:

- `.env` files
- `.runtime/`
- Private keys
- Certificates
- Passwords
- Tokens
- Real SOC logs containing sensitive data
- Customer-specific data

If a contribution touches authentication, authorization, reporting, evidence export, or external integrations, explicitly describe the security impact in the pull request.

---

## UI Contribution Guidelines

For frontend changes:

- Keep layouts compact and operational.
- Avoid large empty spaces.
- Prefer dense but readable enterprise dashboards.
- Avoid generic global CSS changes unless strictly necessary.
- Use page-level or component-level changes where possible.
- Do not introduce UI flows that break analyst workflow.

---

## AI Output Guidelines

AI-generated content must remain analyst decision support.

Do not present AI output as authoritative or final. Analyst review must remain explicit in the workflow.

---

## Documentation

Update documentation when changing:

- APIs
- Authentication
- Deployment
- Reports
- User workflows
- Security behavior
- Release scope

---

## Commit Style

Use clear commit messages:

```text
Add GUI synthetic test runner
Fix auth token validation
Update README for v0.2 release candidate
Document PostCSS advisory exposure assessment
```

Keep commits focused and easy to review.
