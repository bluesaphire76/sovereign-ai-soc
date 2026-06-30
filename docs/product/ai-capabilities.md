# AI Capabilities

Sovereign AI SOC uses governed AI as a multi-stage decision-support capability
across incident, case, detection quality, remediation, executive and reporting
workflows.

AI is not limited to triage. It helps interpret evidence, explain correlation, draft next actions, generate execution guidance and enrich reports while preserving human control.

![AI capabilities flow](../assets/architecture/ai-capabilities-flow.svg)

Editable Mermaid source: [ai-capabilities-flow.mmd](../diagrams/ai-capabilities-flow.mmd).

## 1. Overview

The AI layer is designed around evidence-based support:

- Input comes from incidents, raw alert context, correlation summaries, cases,
  detection quality data, selected telemetry and advisory semantic memory.
- Output is structured for analyst review.
- Timeout and fallback behavior keeps the product usable when the local runtime is unavailable.
- Provider selection and external data exposure are evaluated server-side.
- AI output is never treated as an automatic operational command.

## 2. AI Runtime and Provider Routing

The platform uses Ollama as the default local LLM runtime. v0.7.1 also includes
an optional llama.cpp local provider path for router-managed GGUF profiles.
Runtime configuration is controlled through `.env` values such as
`OLLAMA_MODEL`, `OLLAMA_BASE_URL`, `AI_SOC_LLM_*`, and the `LLAMA_CPP_*`
profile settings.

The routing policy selects a model profile by task, severity and whether the action is user-triggered. The intent is to load the appropriate model when needed, not to keep every configured model active at the same time.

v0.7 also provides a governed provider registry. `LOCAL_OLLAMA` remains the
default local provider. `LOCAL_LLAMA_CPP` is local and disabled by default
through `LLAMA_CPP_ENABLED=false`. OpenRouter is available through the
OpenAI-compatible external adapter, while external AI remains globally disabled
by default. External requests require provider enablement, configuration,
feature allowlisting and a compatible AI Data Control decision.

The Health and AI Providers pages expose configured models, loaded Ollama
models, llama.cpp router/profile state, provider state, last LLM profile/model
and fallback metadata where available.

## 3. AI Data Control

AI Data Control evaluates every provider request against feature, role,
provider and data-exposure policy.

Supported policy modes include:

- external AI disabled;
- local only;
- metadata only;
- redacted context;
- admin-only full context, with secrets and credentials still redacted;
- feature disabled.

Deterministic redaction covers secrets, credentials, personal data, IP
addresses, hostnames, raw telemetry and selected sensitive fields. Audit
records store safe metadata, hashes and redaction counts rather than raw
prompts or responses.

## 4. Incident AI Analysis

Incident analysis helps answer:

- What happened?
- Why does it matter?
- What evidence supports the assessment?
- What should an analyst validate next?
- What limitations or uncertainty remain?

Incident AI analysis is grounded in incident fields, raw alert context, correlation summaries, notes and available evidence.

Incident AI Brief can include Qdrant context, but labels it as advisory and
keeps current incident evidence authoritative.

## 5. AI Command Brief

The Command Brief converts raw operational context into a structured analyst briefing:

- Situation summary.
- Risk rationale.
- Evidence summary.
- Recommended actions.
- Confidence and limitations.
- Human validation requirements.

It is designed for fast analyst comprehension, not automated response.

## 6. Risk Rationale and Evidence Summary

AI-generated risk rationale explains why a signal may matter in operational terms. Evidence summaries help connect:

- Wazuh rule and level.
- Correlation score and type.
- Attack chain or MITRE metadata when present.
- Related events.
- Network evidence.
- DNS context, clearly labeled as contextual telemetry only.

The system avoids implying causality from DNS context alone.

## 7. Recommended Playbooks and Actions

Qdrant-backed Recommended Playbooks combine:

- authoritative incident/case facts;
- platform and incident-type retrieval filters;
- metadata-aware playbook sections;
- optional similar historical incidents;
- optional LLM synthesis constrained to retrieved playbook titles;
- deterministic fallback when the provider fails or returns invalid output.

Playbook guidance includes evidence collection, false-positive checks,
escalation criteria, approval-required containment/remediation guidance and
closure considerations.

Recommended actions are analyst guidance, such as:

- Validate affected host state.
- Review related alerts and timeline.
- Confirm whether activity is expected.
- Check containment prerequisites.
- Open or update a case.
- Review detection coverage gaps.

Actions and playbooks are suggestions. The analyst decides what to do.

## 8. Remediation Intelligence and Governance

The remediation workflow can produce:

- remediation objectives and containment strategy;
- recommended actions with evidence basis;
- approval requirements;
- business impact and rollback considerations;
- assumptions, limitations and unsupported claims;
- AI governance status, confidence and safety labels.

This output is advisory. It is evaluated by deterministic governance checks and remains human-reviewed even when generated by a local LLM.

v0.7 adds persistent governed remediation proposals with action, connector and
playbook catalogs. Proposals move through draft, proposed, approved, rejected,
cancelled and converted states.

Supported conversions create internal case actions, deterministic documents or
Detection Control drafts. Firewall, EDR, ticketing and external SOAR
connectors remain disabled/proposal-only.

## 9. Remediation Simulation and Controlled SOAR

The remediation workflow includes approval gates, dry-run simulation, rollback readiness, execution audit trail and replay simulation.

Controlled SOAR execution is intentionally narrow. It supports allowlisted internal product workflow records only, such as remediation tasks, incident notes, case actions and audit records. It does not execute host isolation, identity changes, firewall updates, shell commands, SSH commands, Wazuh active response, process termination or file quarantine.

High-impact and external remediation actions are represented as governed
proposals only unless a separate explicitly approved connector is implemented.

## 10. HOW TO EXECUTE Guidance

Detection Quality can generate AI-supported execution guidance for a recommended action. This is presented as practical remediation or validation guidance, not as an automatic command runner.

The implementation is explicit-click only and uses caching to avoid repeated local LLM generation for the same request.

## 11. Case AI Analysis

Case AI analysis supports:

- Investigation summary.
- Risk interpretation.
- Open gaps.
- Recommended next actions.
- Human decision points.
- Closure readiness context.

It helps analysts manage multi-incident workflows without removing ownership
from the case owner. Case analysis may use advisory semantic memory and is
available through persisted generation jobs so long-running requests can be
tracked safely.

## 12. Timeline and Investigation Graph

AI-related timeline records and hypotheses can appear in the Advanced Incident
Timeline and Investigation Graph. The graph distinguishes AI analysis or
hypothesis nodes from deterministic evidence and applies role-aware metadata
redaction.

Graph relationships and semantic similarity are context, not proof.

## 13. Correlation Explanation

Correlation explanation helps reviewers understand why an event became an incident:

- Correlation score and type.
- Matched patterns.
- Attack chain view.
- Related timeline entries.
- MITRE context when available.
- Evidence that contributed to the decision.

## 14. Detection Quality and Detection Control Assistance

Detection Quality uses AI-assisted and deterministic summaries to support detection engineering:

- Synthetic scenario coverage.
- Weakest scenario identification.
- Recommended next action.
- AI-generated remediation suggestions.
- Human validation required before tuning production detections.
- Advisory semantic context from historical Detection Control, Case Closure,
  incident and knowledge-base memory.
- Draft-only governed remediation conversions for detection rules, exceptions
  and noise suppression.

AI and semantic memory never apply a detection configuration. Lifecycle
validation, ADMIN approval, versioning and rollback remain deterministic.

## 15. Executive Insights and Report Enrichment

Executive workflows use concise summaries:

- SOC posture.
- Operational risk.
- Key recommendations.
- Case and incident state.
- Executive-ready report sections.

Executive outputs avoid raw technical dumps unless the report type explicitly requires evidence detail.

## 16. Timeout, Fallback and Runtime Observability

The platform includes runtime health checks and deterministic fallback behavior so a local model outage does not break core SOC workflows.

Expected behavior:

- AI calls can time out.
- Fallback text preserves report and UI continuity.
- Health pages expose runtime status.
- Last profile/model/fallback metadata is surfaced for LLM calls where available.
- Provider, model, external-use and redaction metadata are exposed where the
  workflow returns them.
- Generated output should never expose tracebacks to end users.

## 17. Human-in-the-loop Boundaries

The analyst controls:

- Escalation.
- Case creation.
- Case closure.
- Response execution.
- Evidence validation.
- Report approval.
- Remediation approval and operational decision-making.
- Detection Control approval, apply and rollback.
- External AI enablement and data-exposure policy.

AI helps explain and prepare. It does not own the decision.

## 18. What AI Does Not Do Automatically

AI does not automatically:

- Disable accounts.
- Kill processes.
- Block network traffic.
- Modify firewall rules.
- Close incidents or cases.
- Change RBAC policy.
- Suppress detections.
- Assert causality without evidence.
- Execute arbitrary commands or LLM-generated instructions.
- Enable an external provider or bypass AI Data Control.
- Treat Qdrant similarity as proof or deterministic evidence.

This boundary is intentional and central to the product design.
