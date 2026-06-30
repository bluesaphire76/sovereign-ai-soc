# Feature Map

This map helps first-time evaluators connect user-facing features to the
implementation areas and validation evidence in the repository.

| Domain | User-facing feature | Backend / module area | Docs | Validation |
|---|---|---|---|---|
| Incident workflow | Incident Command Room, AI Brief, timeline and graph | `routers/incidents*`, `incident_ai_brief.py`, `incident_timeline.py`, `investigation_graph.py` | [User guide](user-guide.md), [AI capabilities](ai-capabilities.md) | incident, API route and OpenAPI tests |
| Case workflow | Case queue, Kanban, case AI analysis and closure readiness | `routers/cases*`, `case_ai_analysis.py`, `case_timeline.py` | [User guide](user-guide.md), [Demo guide](demo-guide.md) | case workflow and report tests |
| AI runtime | Ollama default, llama.cpp local path and governed external providers | `ai_provider_*`, `llm_client.py`, `llama_cpp_profiles.py` | [AI capabilities](ai-capabilities.md), [AI Providers](../architecture/v0.7-external-ai-provider-abstraction.md), [llama.cpp runtime](../architecture/v0.7.1-llama-cpp-runtime.md) | AI provider, routing and policy tests |
| AI governance | AI Data Control, deterministic redaction and provider audit metadata | `ai_data_control_policy.py`, `ai_provider_redaction.py`, `ai_provider_audit.py` | [AI Data Control policy](../architecture/v0.7-ai-data-control-policy.md), [Security model](../architecture/security-model.md) | policy, redaction and security audit tests |
| Semantic memory | Qdrant knowledge base, similar incidents, playbooks and detection/case memory | `qdrant_knowledge.py`, `rag_*`, `qdrant_auto_index.py`, semantic-memory routers | [Qdrant Semantic Memory](../architecture/v0.7-qdrant-semantic-memory.md) | Qdrant, retrieval and playbook validators |
| Detection governance | Detection Control lifecycle, versioning, validation and rollback | `detection_control*`, `detection_rule_lifecycle.py` | [Detection Rule Lifecycle](../architecture/v0.7-detection-rule-lifecycle.md) | detection control and lifecycle tests |
| Remediation governance | Proposals, approvals, dry-run, rollback readiness and safe internal conversions | `remediation/`, remediation routers and services | [Governed Remediation Connectors](../architecture/v0.7-governed-remediation-connectors.md), [AI capabilities](ai-capabilities.md) | remediation and approval tests |
| Observability | Health, Prometheus metrics, Alertmanager, Loki/Alloy and Operation History | `platform_health.py`, `routers/metrics.py`, `service_operations.py` | [Admin guide](../operations/admin-guide.md), [Observability](../operations/v0.6.0-observability.md) | runtime validation, docs validation and dashboard JSON checks |
| Reporting | Incident reports, case reports, evidence packs and executive PDFs | `report_builder.py`, `evidence_pack_builder.py`, `executive_pdf_builder.py` | [Reporting guide](reporting-guide.md) | report and export tests |
| Deployment | Ubuntu guided preparation, Docker demo packaging and reverse-proxy artifacts | `install-demo.sh`, `scripts/install_demo_ubuntu.py`, `deploy/` | [Evaluation guide](evaluation-guide.md), [Deployment guide](../operations/deployment-guide.md), [Ubuntu installer](../operations/ubuntu-installer-guide.md) | installer, package and release checks |

## Boundaries

- AI and Qdrant provide context and recommendations, not final authority.
- External AI is disabled by default and governed by AI Data Control.
- Controlled SOAR remains limited to allowlisted internal product records.
- Production deployment requires operator-owned hardening beyond the local demo
  preparation flow.
