# AI Assistant V3 Milestone A Validation

Validation date: 2026-08-08

## Result

Milestone A Steps 74-82 passed local implementation, real-data, runtime, and
regression gates. Validation was read-only: no incident, case, Qdrant, Wazuh,
or Suricata state was created or changed.

The temporary non-generative and runtime harnesses live under `/tmp`; they are
not production endpoints or repository utilities. Their JSON results were
written to:

```text
/tmp/ai_assistant_v3_milestone_a_validation.json
/tmp/ai_assistant_v3_runtime_smoke.json
```

## Real-Data Foundation

The deterministic sample spans 60 unique incidents distributed across the
available incident ID range and four real cases:

```text
records processed:                         64
operational atoms generated:             1515
atom normalization failures:                0
candidate searches:                        12
candidate count distribution:         12 -> 12
records with candidates:                   12
records with zero candidates:               0
records with cross-incident relationships: 12
reference atoms:                           74
advisory retrieval attempts:                4
advisory retrieval no-match:                0
conversation follow-up scope checks:        1
```

The 149 graph edges were evidence-backed:

```text
SHARED_AGENT:                    49
SHARED_CORRELATION_TYPE:         66
SHARED_RULE:                     22
TEMPORAL_PROXIMITY:              12
```

No semantic similarity was promoted to recorded correlation, and no graph edge
represented causality or compromise. The dataset naturally produced no zero-
candidate cross-incident records in this bounded sample; zero candidates remain
a tested valid result.

The pre-merge hardening assigns deterministic cross-incident edges to
`ANALYTICAL_DERIVATION`; only explicit platform-recorded correlation edges are
`OPERATIONAL_AUTHORITATIVE`. Their referenced evidence atoms remain operational
authority. A closed relationship registry now mirrors the graph exactly and
supports exact typed validation of relationship reference and expected
authority.

The current authoritative retrieval exposes `escalation_reason` but no boolean
escalation state (`NO_AUTHORITATIVE_ESCALATION_BOOLEAN`). Regression coverage
confirms that a missing or present reason and non-boolean values never create an
escalation-state atom. Only an explicit authoritative boolean can create one,
including an explicit `false`.

## Dataset Diversity

```text
status: CLOSED 4, CONTAINED 1, FALSE_POSITIVE 1, INVESTIGATING 1,
        NEW 9, TRIAGED 48
priority: CRITICAL 2, HIGH 2, INFORMATIONAL 1, LOW 50, MEDIUM 5
distinct agent/host values:        3
distinct MITRE techniques:         6
distinct correlation types:        6
case coverage:                      4
```

## Performance

All values are milliseconds and include cached local embedding inference. Total
context build includes intent, focus, policy, normalization, retrieval, graph,
knowledge, and conversation phases.

| Phase | p50 | p95 | max |
|---|---:|---:|---:|
| intent routing | 10.570 | 17.059 | 222.212 |
| focus routing | 9.344 | 15.789 | 18.027 |
| context policy | 0.041 | 0.055 | 0.065 |
| atom normalization | 0.108 | 0.274 | 0.492 |
| candidate retrieval | 0.000 | 32.751 | 40.073 |
| authoritative rehydration | 0.000 | 2.402 | 2.565 |
| graph construction | 0.027 | 0.582 | 0.926 |
| reference retrieval | 0.001 | 0.046 | 0.051 |
| advisory normalization | 0.002 | 0.075 | 0.104 |
| conversation state | 0.002 | 0.002 | 0.003 |
| total foundation | 22.016 | 55.370 | 232.776 |

The 55.370 ms p95 is substantially below the multi-second model generations
observed in the controlled runtime smoke.

## Runtime Compatibility

Four real Assistant requests exercised fact lookup, explanation, cross-incident
analysis, and validated follow-up state. The existing V2 answer schema and
renderer remained active.

```text
runtime requests:                  4
provider generation count:         4
provider generation delta/query:   1, 1, 1, 1
grounding failures:                0
focus failures:                    0
automatic retries:                 0
model/profile switches:            0
```

Detected intents were `FACT_LOOKUP`, `EXPLAIN`,
`CROSS_INCIDENT_ANALYSIS`, and neutral `SUMMARY` for the follow-up. The
cross-incident package contained 12 rehydrated candidates and 14 evidence-
backed graph edges. The second request in the same conversation reported
`conversation_followup=true`. All four provider responses had status `ok`,
finish reason `stop`, and passed V2 grounding and focus validation.

## Regression Gates

```text
Milestone A tests:             46 passed
Assistant/cross targeted:     282 passed
full backend suite:           908 passed, 26 subtests passed
Public CI baseline:           PASS
Docker packaging validator:   PASS
CLI smoke validator:          PASS
documentation validator:      PASS
API composition guard:        PASS
frontend production build:    PASS
compileall:                    PASS
git diff --check:              PASS
```

The aggregate release check initially observed a transient failure while its
installer dry-run overlapped the parallel CLI validator. The isolated command
`./ai-soc install --profile demo --dry-run` was rerun and returned
`DRY_RUN_READY` with exit code 0. Release-check warnings about the dirty feature
worktree, non-main branch, and absent optional demo seed are expected during
implementation and are not Milestone A regressions.

## Static Architecture Scan

New production modules contain no regex, keyword, or substring intent routing;
record-specific or test-question special cases; JSON repair; permissive output
parsing; LLM retries; second-model calls; or Qdrant-to-authority promotion. All
historical semantic candidates require successful SQL rehydration before they
enter operational comparison.

The pre-merge hardening changed no provider, orchestration-generation, prompt,
or renderer path and introduced no second LLM generation.
