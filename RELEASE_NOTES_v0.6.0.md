# Sovereign AI SOC v0.6.0

## Release Theme

AI-assisted investigation and human-governed remediation workflow.

v0.6.0 turns the platform into a more structured analyst command center: investigation intelligence, evidence-backed AI output, remediation planning, governance checks, dry-run simulation, rollback readiness, replay, auditability and controlled internal workflow actions are now connected in the incident experience.

## Highlights

- Incident Command Center rewrite with clearer AI Situation Brief, analyst decision flow, evidence panels and collapsible sections.
- Investigation intelligence foundation with structured evidence, confidence and cross-incident context.
- LLM-backed remediation intelligence with deterministic fallback and visible model metadata.
- Configurable local LLM model routing by task/profile so the platform can select the needed model instead of assuming every model is always loaded.
- AI governance safeguards for confidence, evidence coverage, assumptions, limitations, unsupported claims and human-review labels.
- Remediation approval workflow with explicit human decision requirements.
- Dry-run and simulation for remediation plans.
- Rollback readiness and execution audit trail previews.
- Replay simulation for remediation workflow phases and proposed actions.
- Controlled SOAR remediation actions for safe internal product workflow records.
- Observability improvements through Health, Prometheus/Grafana and LLM usage metrics.

## Safety Boundaries

v0.6.0 does not introduce autonomous remediation.

The platform does not:

- execute arbitrary shell commands;
- execute LLM-generated commands;
- perform unrestricted SSH;
- isolate hosts;
- disable users;
- block network traffic;
- modify firewall rules;
- kill processes;
- quarantine files;
- stop or restart services;
- execute Wazuh active response;
- bypass RBAC or human approval.

Controlled SOAR support is limited to allowlisted internal workflow actions such as remediation tasks, incident notes, case actions and audit records. External host, identity, network and endpoint remediation requires future connector/playbook integration with explicit governance.

## Validation

Validation completed for this release branch:

- Incident Detail hard gate inspected after the Command Center rewrite.
- Backend compile passed with `python3 -m py_compile`.
- Governance/remediation tests passed: `38 passed`.
- Replay/SOAR/executor tests passed: `24 passed`.
- Frontend production build passed with `npm run build`.
- Tracked secret scan reviewed; no real tracked secrets were found.
- API smoke checks returned expected results:
  - `/health`: `200 OK`
  - `/metrics`: `200 OK`
  - protected incident/remediation endpoints without token: `401 Unauthorized`, not `500`
  - frontend incident route: `200 OK`
- Runtime services were confirmed active after operator validation:
  - `ai-soc-api`
  - `ai-soc-frontend`
  - `ai-soc-worker`
- Manual UI validation was confirmed by the operator before proceeding with release completion.

## Known Limitations

- Local LLM latency depends on the configured Ollama models and hardware.
- Fallback output is conservative and intentionally low-confidence when the local model is unavailable or returns invalid output.
- High-impact remediation action types remain blocked or unsupported.
- Controlled SOAR actions create internal workflow records only.
- External remediation connectors and production-impacting playbooks are future work.
- Browser screenshots are still not committed; the screenshot checklist remains the source for producing product preview assets.

## Upgrade Notes

- Review `.env.example` and frontend environment examples for LLM routing, observability and local API/Grafana URLs.
- After pulling the release, restart the API, frontend and worker services in production-style demo deployments.
- Re-run the v0.6 release checklist before demo or stakeholder validation.
