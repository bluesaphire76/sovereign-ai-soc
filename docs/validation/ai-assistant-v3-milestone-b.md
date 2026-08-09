# AI Assistant V3 Milestone B/B.1 Validation

## Scope

This report records the read-only Milestone B.1 Product Quality Closure
validation performed on 2026-08-09. The matrix used real operational records
and the production V3 pipeline. It did not create incidents or cases, did not
use an LLM judge, and did not introduce a second generation.

The final run covered:

- 100 Assistant requests;
- 60 unique incident anchors and four real cases;
- 90 open analytical requests and 34 cross-incident requests;
- 20 dedicated follow-up messages, with 36 responses observing validated
  conversation state after case-flow continuations;
- ten explicit pair comparisons;
- 14 isolated conversation flows.

All 100 requests returned a model-generated, deterministically validated plan
without fallback.

## Grounding and Generation

| Gate | Result |
| --- | ---: |
| Unsupported operational claims | 0 |
| Authority violations | 0 |
| Dangling visible source refs | 0 |
| Semantic similarity promoted to recorded correlation | 0 |
| Analytical relationship promoted to causality | 0 |
| Advisory/reference knowledge promoted to record state | 0 |
| Invented severity, risk, escalation, or compromise state | 0 |
| Provider generations | 100 for 100 requests |
| Automatic retries / model switches | 0 / 0 |
| Structured-output truncations | 0 |
| Gateway generation delta | exactly 100 success |

Every relationship ref was resolved through the typed relationship registry.
Relationship citations recurse to the operational evidence atoms on which the
relationship is based. Qdrant supplied candidate IDs only; every candidate was
rehydrated from SQL and fingerprint checked before entering the V3 package.

## Deterministic Quality Metrics

| Metric | Result |
| --- | ---: |
| Identical open responses across distinct records | 0 |
| Near-identical open-response rate | 0.00% |
| Repeated boilerplate sentence rate | 16.27% |
| Grounded section coverage | 100% |
| Open answers with at least three plan units | 97.78% |
| Cross-incident explanation coverage | 100% |
| Limitation-first rate | 0.00% |
| Raw advisory payload rate | 0.00% |
| Explicit compare scope-drift rate | 0.00% |
| Single-sentence open-answer rate | 0.00% |
| Field-list-like answer rate | 0.00% |

## Human Review

Thirty complete answers were selected deterministically as the first, median,
and last response for each of the ten intents. Each output was read manually;
no LLM quality judge was used. Fact lookup was marked not applicable for the
explanation and analytical-value dimensions. Three handover outputs were
marked down for a dense semicolon-chained advisory sentence, while remaining
grounded and useful.

| Dimension | Result |
| --- | ---: |
| Answers the question | 100% |
| Explains rather than lists | 100% |
| Selects relevant evidence | 100% |
| Adds analytical value | 100% |
| Natural discourse | 90% |
| Grounding safety | 100% |

The full review artifact is
`/tmp/ai-soc-v3-b1-representative-answers.md`; structured metrics and all 100
responses are in `/tmp/ai-soc-v3-b1-quality-validation.json`.

## Response Structure

Values are `min / p50 / p95 / max`.

| Intent | Words | Sections | Plan units |
| --- | --- | --- | --- |
| `COMPARE` | 90 / 104.5 / 121.6 / 127 | 4 / 4 / 4.55 / 5 | 6 / 6 / 6 / 6 |
| `CROSS_INCIDENT_ANALYSIS` | 54 / 54.5 / 76.1 / 86 | 3 / 3 / 3.55 / 4 | 4 / 4 / 5.1 / 6 |
| `EXECUTIVE_SUMMARY` | 43 / 59 / 87 / 87 | 3 / 3 / 3 / 3 | 3 / 3 / 3 / 3 |
| `EXPLAIN` | 78 / 81.5 / 91 / 91 | 4 / 4 / 4 / 4 | 4 / 4 / 4 / 4 |
| `FACT_LOOKUP` | 4 / 4 / 4 / 4 | 1 / 1 / 1 / 1 | 1 / 1 / 1 / 1 |
| `HANDOVER` | 72 / 72 / 83 / 83 | 3 / 3 / 3 / 3 | 3 / 3 / 3 / 3 |
| `INVESTIGATE` | 57 / 63 / 72 / 72 | 4 / 4 / 4 / 4 | 4 / 4 / 4 / 4 |
| `NEXT_ACTION` | 78 / 78 / 78.8 / 79 | 2 / 3 / 3 / 3 | 2 / 3 / 3.8 / 4 |
| `PATTERN_ANALYSIS` | 76 / 94.5 / 103.05 / 105 | 4 / 4 / 4 / 4 | 4 / 4 / 4 / 4 |
| `SUMMARY` | 42 / 51 / 60 / 60 | 3 / 3 / 3 / 3 | 4 / 4 / 4 / 4 |

The schema offers adaptive bounded variants. Runtime variation appears where
the available evidence supports it, notably comparison, cross-incident, and
next-action answers. Fact lookup remains intentionally fixed and concise.

## Semantic Index Full Estate

The dedicated `incident_semantic_index` was rebuilt over the complete eligible
SQL corpus in 28,745.360 ms. Reconciliation status after the final code change:

| Gate | Result |
| --- | ---: |
| Eligible database records | 5,324 |
| Indexed / unique IDs | 5,324 / 5,324 |
| Deliberately ineligible records | 0 |
| Missing expected IDs | 0 |
| Duplicate IDs | 0 |
| Stale fingerprints | 0 |
| Embedding failures | 0 |

Across 34 final runtime queries, non-zero semantic-index latency was 26.5 ms
p50, 211 ms p95, and 856 ms max. The high tail was limited to initial runtime
warm-up. Qdrant failure tests continue to degrade safely to authoritative SQL
retrieval without authority promotion.

## Performance

| Stage | Min | p50 | p90 | p95 | Max | Mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Provider generation | 2,404 ms | 8,277 ms | 14,186.8 ms | 15,323.5 ms | 20,300 ms | 9,080.6 ms |
| Total request | 2,434 ms | 8,512 ms | 14,287.8 ms | 15,483.3 ms | 20,511 ms | 9,217.98 ms |

Seven requests exceeded 15 seconds, one exceeded 20 seconds, and none exceeded
25, 35, or 45 seconds. Prompt tokens were 477 min, 1,165 p50, 3,395.8 p95,
and 3,530 max. Structured output was 66 min, 232 p50, 368.1 p95, and 401 max,
well below the bounded 768-token V3 completion budget.

Local GPU cooldown was applied only between completed requests. It did not
enter per-response generation or total-latency measurements.

## Reproduction

Start an isolated inference gateway using the deployed model, then run:

```bash
AI_INFERENCE_GATEWAY_SOCKET=/path/to/gateway.sock \
  .venv/bin/python scripts/validate_assistant_v3_milestone_b.py \
  --inter-query-delay-seconds 30
```

The harness rejects concurrent gateway execution, records provider counters
before and after the matrix, and emits its detailed JSON report under `/tmp`.
Conversation state is isolated by owner and thread, and previous Assistant
prose is never accepted as evidence.
