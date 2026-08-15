# AI Assistant V3.1 Part A Validation

## Pre-Change Implementation Preservation Ledger

This ledger was recorded before any Part A production-code edit. It defines the
V3 boundaries that the conversational recovery is required to preserve.

| Subsystem | Existing implementation | Responsibility | Part A treatment | Regression evidence and rationale |
| --- | --- | --- | --- | --- |
| Authority model | `services/assistant/v3/contracts.py`: `AuthorityClass`, evidence and knowledge atoms, `AnalyticalRelationship` | Keeps operational facts, analytical derivations, reference/advisory knowledge, and semantic candidates distinct | Preserve | `tests/test_ai_assistant_v3_contracts.py`, `tests/test_ai_assistant_v3_answer_plan.py`, and `tests/test_ai_assistant_grounding.py` protect typed authority and forbidden promotions. The prose layer must consume these classes, never redefine them. |
| Operational authority | `services/assistant/retrieval.py`, `services/assistant/v3/builder.py` | Retrieves incident/case state from SQL and normalizes authoritative atoms | Preserve | `tests/test_ai_assistant_retrieval.py` and `tests/test_ai_assistant_v3_integration.py` protect SQL-backed retrieval. Qdrant remains candidate discovery only. |
| Semantic/Qdrant retrieval | `qdrant_knowledge.py`, `services/assistant/v3/semantic_index.py`, V3 builder candidate pipeline | Retrieves advisory knowledge and incident candidates, then authorizes and rehydrates candidates from SQL | Extend diagnostics and phase-budget handling | `tests/test_qdrant_knowledge.py`, `tests/test_ai_assistant_retrieval.py`, `tests/test_ai_assistant_v3_integration.py`, and `tests/test_ai_assistant_v3_semantic_index.py` protect readiness, deadlines, filtering, and rehydration. |
| Cross-incident analysis | `services/assistant/v3/candidates.py`, `graph.py`, `contracts.py`: `RelationshipRegistry`, `CrossIncidentEvidenceGraph` | Builds bounded candidate sets and structurally verifiable relationships | Preserve | `tests/test_ai_assistant_v3_candidates.py`, `tests/test_ai_assistant_v3_graph.py`, and answer-plan tests protect pair discipline, provenance, and relationship refs. |
| Conversation state | `services/assistant/v3/conversation.py`, `ValidatedConversationState` | Stores owner/scope-bound validated refs with TTL; never stores generated prose as authority | Preserve | `tests/test_ai_assistant_v3_conversation.py` and integration tests protect isolation, stale/deleted refs, and scope continuity. |
| Intent and focus | `services/assistant/v3/intent.py`, `focus.py`, shared embedding provider | Routes semantically with one shared non-generative request embedding | Preserve | `tests/test_ai_assistant_v3_intent.py`, `tests/test_ai_assistant_v3_focus.py`, and production-quality tests protect embedding-only routing and degradation behavior. |
| One-generation invariant | `services/assistant/orchestrator.py`, AI Execution Gateway | Owns exactly one standard-profile provider generation per query | Preserve | V3 integration, product-quality, gateway, and inference tests assert generation count, no retry, and no model switch. Part A replaces the generated schema, not the generation count. |
| Gateway | `services/ai_execution/`, `ai_provider_abstraction.py` | Sole generative owner with queue protection and bounded timeout hierarchy | Preserve | `tests/test_ai_execution_*` and `tests/test_llama_cpp_provider.py` protect startup, queue, timeout, and standard-profile behavior. |
| Grounding | `services/assistant/v3/plan_validation.py` and typed registries | Deterministically validates refs, scope, authority, pair constraints, and forbidden implications | Replace response-contract sub-layer, preserve validation boundary | Existing answer-plan and grounding tests remain a fallback baseline. New V3.1 validation tests must cover model-authored prose and typed claims without an LLM judge. |
| Sources and attribution | `services/assistant/v3/attribution.py`, API Assistant schemas, frontend source presentation | Exposes typed operational, analytical, reference, advisory, and semantic provenance | Extend presentation only | Attribution, API router, V3 integration, and frontend tests protect source identity and safe links. Sources move out of the primary prose hierarchy but remain inspectable. |
| RBAC | `services/assistant/v3/authorization.py`, builder filtering | Authorizes incident/case/candidate/graph/conversation data before model exposure | Preserve | Authorization and V3 integration tests protect pre-exposure filtering. The conversational contract accepts only refs already present in the authorized package. |
| Observability | Assistant/gateway Prometheus metrics and bounded diagnostics | Measures retrieval, semantic, generation, validation, and fallback stages without record/user labels | Extend with closed semantic states | Observability and runtime tests protect bounded labels. No incident, case, user, or conversation ID becomes a metric label. |
| V2 rollback | `services/assistant/orchestrator.py`, `AI_ASSISTANT_RESPONSE_ARCHITECTURE` | Explicit legacy rollback compatibility | Preserve | Existing V2 Assistant tests continue to run. V2 is not reused as the V3.1 implementation. |
| Deterministic renderer | `services/assistant/v3/discourse.py`, `plan_fallback.py` | Produces safe grounded prose from a validated/deterministic plan | Retain as emergency fallback only | Existing answer-plan/product-quality tests preserve it as a regression baseline. It must not write normal V3.1 visible prose. |

## Product Gate

Automated validation can pass the technical gate only. Real-user content,
naturalness, organization, SOC usefulness, and conversational UX acceptance
remain pending and require an average score of at least 8/10.

`MANUAL USER ACCEPTANCE: PENDING`

## V3.1.1 Conversational Contract

The proof-gate contract accepts one to four segments and one to eight typed
claims. The first segment remains direct; later analysis, evidence,
comparison, uncertainty, conclusion, and advisory-grounded next-step segments
are selected only when useful. Each segment cites one to four supporting claims
instead of the complete answer claim set. Non-implication claims are
conditionally required in the segment that names a protected unsupported
concept, and are not globally mandatory. The former 75-105 visible-word rule is
no longer a validity condition.

Model-facing refs now declare their allowed claim type, and code-only claims are
offered as closed atomic options. This avoids decoder ambiguity without adding
post-generation citation repair; invalid type/ref/qualifier combinations still
fail deterministic validation.

Deterministic validation still resolves every model-visible source ref through
the typed registries, rejects authority promotions and unknown refs, and keeps
semantic similarity distinct from recorded correlation. This change does not
add a retry, critic, repair, rewrite, model switch, or second generation.

## V3.1.2 Grounded Analytical Synthesis

EXPLAIN now permits the model to connect multiple supplied facts into a coherent
analytical explanation. It may describe what and where the platform observed,
the exact meaning of a recorded relationship, the technical classification
provided by reference knowledge, and the combined meaning supported by those
typed sources. This is grounded synthesis, not authority promotion: it cannot
introduce cause, intent, maliciousness, compromise, persistence, lateral
movement, attacker or campaign attribution, probability, impact, urgency, or an
unrecorded outcome.

`analyst_utility` remains attached to each operational atom as its maximum
defensible analytical meaning. It is explicitly not a phrase template. The
prompt asks for related evidence to be combined rather than emitted as a field
inventory, and status or risk should appear only when materially useful.
The EXPLAIN model view applies that rule through the existing typed focus: risk,
priority, and recorded correlation are exposed only when their focus is selected.
An unrequested numeric detection-rule level is omitted so it cannot be promoted
to qualitative incident meaning. Generic identity and latest-timeline metadata
are also omitted when stronger EXPLAIN evidence is available, preventing a later
workflow event from being presented as the detection time. Matching MITRE
operational atoms carry the typed reference ref that supplies their technical
definition.
Ordinary EXPLAIN answers omit protected concepts by default; they do not need a
gratuitous compromise caveat. If a protected concept is materially relevant and
named or negated, the existing segment-local non-implication claim remains
mandatory. Recorded correlations remain exact platform relationships, and
reference knowledge remains explanatory rather than current operational state.
An undefined compromise-state placeholder is not exposed to the conversational
model; only an explicit authoritative boolean `true` or `false` is model-visible.
No generation, retry, repair, response-contract, gateway, retrieval, or frontend
behavior changes in V3.1.2.

## Part A Technical Validation

The final proof preparation used the unchanged existing Incident `5333` and
comparison records already present in the local SOC database. Eight of eight
required prompts completed through the V3.1 model-authored path with grounding
and focus validation `passed`. The aggregate provider generation count was 8,
with zero automatic retries and zero model switches. Prompt 5 retained typed
conversation scope from prompt 4 and selected Incident `5187` instead of the
anchor record.

The embedding prewarm ran from API lifespan startup and the process-level
encoder was reused. Semantic requests reported `available`; the first isolated
request measured 743 ms and the subsequent warm requests measured 32-36 ms.
The semantic phase deadline is computed from semantic-phase start and clamped
to the global request deadline. No request timeout was increased.

The contextual frontend now commits the user and pending assistant turns
immediately, preserves earlier turns, and presents validated prose before
collapsed Sources and Technical details. The provider returns one complete
schema-constrained object, so no unvalidated token or segment is emitted.

`TRUE VALIDATED STREAMING NOT TECHNICALLY POSSIBLE WITH CURRENT PROVIDER; FALLBACK UX IMPLEMENTED`

Automated checks establish technical readiness only. The real frontend must
still be scored by the user; Part B remains blocked.

`MANUAL USER ACCEPTANCE: PENDING`
