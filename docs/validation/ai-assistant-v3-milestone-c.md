# AI Assistant V3 Milestone C Validation

## Result

Milestone C Steps 87-93 passed on the local production-like stack. The
accepted runtime runs used the standard gateway model and exactly one provider
generation per Assistant request. Runtime JSON and human-review artifacts were
kept outside the repository.

## Step 87: Analytical Quality

The reusable bilingual catalog ran 155 questions against 180 available
incidents and eight cases. All 155 requests succeeded with full grounded source
coverage, no route mismatch, no missing required section or evidence, no
dangling or unsupported ref, and no compare-scope drift. Open-answer rates were
0% near-identical, 0% limitation-first, 0% raw-advisory payload, 0%
single-sentence, and 2.14% field-list-like.

Manual review covered 75 complete answers without an LLM judge. Every rubric
dimension passed at 100%; actionability passed for all 13 applicable answers
and was N/A for 62.

Total latency was 2,530 ms minimum, 7,291 ms p50, 13,927.4 ms p90, 14,278.7 ms
p95, 15,414.58 ms p99, 15,977 ms maximum, and 8,438.09 ms mean. Four requests
exceeded 15 seconds and none exceeded 20 seconds.

## Step 88: Adversarial Grounding

The adversarial matrix ran 84 requests across 12 categories, seven requests
per category. All completed successfully. Unsupported factual claims,
authority promotions, invented compromise, actor/campaign, severity, risk
band, or escalation, prompt-injection bypasses, conversation-poisoning
promotions, dangling refs, retries, model switches, and second-generation calls
were all zero. Every full response was also read manually.

## Steps 89-91: Runtime, UX, and Hardening

The production path caches embedding prototypes and shares one normalized
request embedding across intent and focus routing. Retrieval is bounded,
semantic candidates are authorized and SQL-rehydrated, and stage timings and
candidate rejection counts use low-cardinality metrics. Conversation state is
owner-bound, scope-bound, TTL-bounded, size-bounded, and stores validated refs
rather than Assistant prose.

The contextual frontend renders typed V3 sections, provenance classes,
guidance caveats, source links, technical metadata, loading, failure, disabled,
and empty states. Backend authorization filters incident, case, candidate,
graph, registry, source, and conversation references before model exposure.

## Step 92: Large-Scale Acceptance

The final matrix ran 250 requests across 150 primary incidents, 192 visible
incidents, and eight cases. It included 80 cross-incident requests, 50
follow-ups, 30 explicit comparisons, 50 advisory/next-action requests, 45
executive/handover requests, 89 Italian requests, and 161 English requests.
All ten intents were represented and all 250 requests succeeded.

Grounding and authority failures were zero, including Qdrant-only operational
claims, semantic-similarity promotion, analytical-relationship causality,
advisory promotion, reference-to-state promotion, and invented severity, risk
band, escalation, compromise, actor, or campaign. Quality rates were 2.67%
near-identical, 0% limitation-first, 0% raw advisory payload, 0% compare drift,
0% single-sentence open answers, and 2.22% field-list-like.

Manual review covered 75 stratified complete responses without an LLM judge:

| Criterion | Result |
| --- | ---: |
| Answers the question | 75/75 (100%) |
| Explains rather than lists | 75/75 (100%) |
| Relevant evidence | 75/75 (100%) |
| Analytical value | 75/75 (100%) |
| Natural discourse | 70/75 (93.33%) |
| Scope focus | 75/75 (100%) |
| Applicable actionability | 16/16 (100%) |
| Grounding safety | 75/75 (100%) |

Generation latency was 2,494 ms minimum, 7,186.5 ms p50, 13,393.9 ms p90,
14,141.3 ms p95, 14,904.42 ms p99, 15,584 ms maximum, and 8,175.104 ms mean.
Total latency was 2,535 ms minimum, 7,318 ms p50, 13,563.5 ms p90, 14,270.7
ms p95, 15,063.57 ms p99, 15,699 ms maximum, and 8,288.036 ms mean. Four
requests exceeded 15 seconds and none exceeded 20, 25, 35, or 45 seconds.

Total-latency cohort p50/p95 values were 2,832/3,214.2 ms for fact lookup,
5,691/10,008.1 ms for current analytical requests, 12,849/14,970.4 ms for
cross-incident requests, and 6,706.5/14,033.7 ms for follow-ups. Semantic index
stage p95 across all requests was 26 ms. For the 80 requests that queried the
index, query p50/p95/max was 23/40/51 ms.

## Generation Invariant

The accepted Step 87, Step 88, and Step 92 runs account for 489 Assistant
requests and a matching gateway success delta of 489. Automatic retries, model
switches, critic or second-generation calls, structured truncations, and
dangling refs were zero.

Exploratory runs exposed generalized priority-absence, all-equal comparison,
EXPLAIN completeness, intent-prototype, and language-detection defects. Those
runs were preserved outside the repository, fixed with typed contracts and
regression tests, and excluded from the accepted generation invariant.

## Semantic Index

The final reconciliation reported 5,325 eligible and indexed incidents with
zero missing, duplicate, stale, or fingerprint-mismatched points. Qdrant
remains retrieval-only: candidates are authorized and rehydrated from the
operational database before becoming model-visible evidence.

## Step 93: Configuration

The key-only audit found 210 unique local environment keys and 214 unique
example keys, no duplicates, no missing required V3 keys, no unknown or
confirmed-obsolete keys, and no staged `.env`. The ignored local `.env` matched
its mode-0600 external backup byte for byte; no existing local value changed.

V3 is the repository default through
`AI_ASSISTANT_RESPONSE_ARCHITECTURE=v3`. Existing deployments may retain a
local V2 value until deliberately activated. V2 remains an explicit rollback
by setting the same key to `v2` and restarting the API; no data migration is
required.

## Final Repository Validation

- Milestone C and targeted Assistant/V3 tests: 218 passed.
- Assistant V2 compatibility and gateway/inference tests: 252 passed.
- Full backend suite: 1,053 tests and 26 subtests passed; one upstream
  Starlette/httpx deprecation warning remains non-blocking.
- CLI smoke, documentation structure, public CI baseline, Docker packaging,
  and release-check validators completed with no failure.
- API and frontend container images built successfully; all four applicable
  Compose configurations validated.
- Frontend ESLint, TypeScript validation, and the Next.js production build
  passed.
- Strict runtime validation reported 12/12 checks healthy; gateway, API,
  worker, PostgreSQL, Qdrant, frontend, Ollama, Prometheus, and Grafana were
  ready.
- Python `compileall` and tracked-file compilation passed; `git diff --check`
  passed.
- CodeQL has no checked-in local workflow or local runner; the repository
  badge points to GitHub code scanning, so its result remains a remote PR gate.

## Non-Blocking Limitations

- The local model can produce mildly repetitive or mechanical discourse; the
  final manual natural-discourse score remains above the acceptance threshold.
- Cross-incident responses are slower than fact lookups because they perform
  bounded semantic retrieval, authorization, SQL rehydration, and graph work.
- The current platform roles have global incident visibility; the typed access
  policy is injectable for a future row-level or tenant predicate.
