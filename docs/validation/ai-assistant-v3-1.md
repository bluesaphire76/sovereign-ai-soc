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
