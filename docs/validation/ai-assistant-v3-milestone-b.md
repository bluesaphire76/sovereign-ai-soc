# AI Assistant V3 Milestone B Validation

## Scope

This report records the read-only Milestone B validation performed on
2026-08-08. The matrix used real operational records and the production V3
pipeline. It did not create incidents or cases and did not use an LLM judge.
The quality metrics were computed by
`scripts/validate_assistant_v3_milestone_b.py` from response structure, exact
source identity, and visible output.

The run covered 60 unique anchor incidents, four cases, 84 Assistant requests,
34 cross-incident requests, and 20 follow-up messages in ten isolated
conversation flows. All 84 normal requests returned a model-generated,
validated plan with no fallback.

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
| Provider generations | 84 for 84 requests |
| Automatic retries / model switches | 0 / 0 |
| Structured-output truncations | 0 |

Every relationship ref was resolved through the typed relationship registry.
Relationship citations recurse to the operational evidence atoms on which the
relationship is based. Qdrant supplied candidate IDs only; every candidate was
rehydrated from SQL and fingerprint checked before entering the V3 package.

## Quality

The final evidence-identity-aware diversity pass reported:

| Metric | Result |
| --- | ---: |
| Identical open responses across distinct evidence records | 0 |
| Near-identical open-response rate | 0.00% |
| Repeated boilerplate sentence rate | 14.45% |
| Open-answer grounded section coverage | 100% |
| Open answers with at least three units when available | 86.49% |
| Cross-incident relationship explanation coverage | 100% |

Twelve representative answers were manually reviewed across `EXPLAIN`,
`INVESTIGATE`, `CROSS_INCIDENT_ANALYSIS`, `COMPARE`, `PATTERN_ANALYSIS`,
`NEXT_ACTION`, `HANDOVER`, `EXECUTIVE_SUMMARY`, `FACT_LOOKUP`, follow-up, and
case scope. The sample passed grounding and authority review and was materially
richer than the V2 field-list response. Short answers remained intentional for
fact lookup and records with sparse evidence.

## Response Structure

Values are `min / p50 / p95 / max`.

| Intent | Words | Sections | Plan units | Sources |
| --- | --- | --- | --- | --- |
| `COMPARE` | 54 / 55 / 72.55 / 73 | 4 / 4 / 4 / 4 | 4 / 4 / 4 / 4 | 2 / 3 / 4 / 4 |
| `CROSS_INCIDENT_ANALYSIS` | 43 / 61 / 62 / 62 | 3 / 3 / 3 / 3 | 3 / 3 / 3 / 3 | 2 / 3 / 3 / 3 |
| `EXECUTIVE_SUMMARY` | 21 / 21 / 21 / 21 | 2 / 2 / 2 / 2 | 2 / 2 / 2 / 2 | 1 / 1 / 1 / 1 |
| `EXPLAIN` | 54 / 55 / 80.75 / 83 | 3 / 3 / 3 / 3 | 3 / 3 / 3 / 3 | 2 / 2 / 3 / 3 |
| `FACT_LOOKUP` | 4 / 4 / 4 / 4 | 1 / 1 / 1 / 1 | 1 / 1 / 1 / 1 | 1 / 1 / 1 / 1 |
| `HANDOVER` | 94 / 95 / 150.6 / 164 | 3 / 3 / 3 / 3 | 3 / 3 / 3 / 3 | 2 / 2 / 2.8 / 3 |
| `INVESTIGATE` | 30 / 53.5 / 58 / 58 | 3 / 3 / 3 / 3 | 3 / 3 / 3 / 3 | 1 / 1 / 1 / 1 |
| `NEXT_ACTION` | 80 / 140 / 149.6 / 152 | 2 / 2 / 2 / 2 | 2 / 2 / 2 / 2 | 1 / 2 / 2 / 2 |
| `PATTERN_ANALYSIS` | 35 / 38.5 / 42 / 42 | 3 / 3 / 3 / 3 | 3 / 3 / 3 / 3 | 3 / 3 / 3 / 3 |
| `SUMMARY` | 34 / 45 / 55 / 55 | 3 / 3 / 3 / 3 | 3 / 3 / 3 / 3 | 1 / 1 / 1 / 1 |

## Semantic Index

The dedicated `incident_semantic_index` collection was rebuilt over the
100-record validation corpus in approximately 15.2 seconds. The corpus had no
duplicate IDs, missing expected IDs, stale fingerprints, embedding failures,
or DB rehydration failures. Current global status reports 5,224 database
records outside that intentionally partial corpus; this is not counted as a
validation-corpus loss.

Across 34 runtime semantic-index queries, latency was 21 ms p50, 37 ms p95,
and 1,210 ms max. Candidate discovery produced SQL-validated relationships for
same agent, same case, same correlation type, and temporal proximity. The
available data/model selections did not produce visible shared-rule,
shared-MITRE, semantic-only, hybrid-semantic, or no-strong-candidate examples;
no data was altered to force those categories. Qdrant failure tests confirmed
safe degradation to authoritative retrieval without authority promotion.

## Performance

| Stage | Min | p50 | p90 | p95 | Max | Mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Provider generation | 1,754 ms | 8,888.5 ms | 16,923.4 ms | 17,377.15 ms | 19,197 ms | 9,574.143 ms |
| Total request | 1,835 ms | 9,155.5 ms | 17,013 ms | 17,545.3 ms | 19,279 ms | 9,695.714 ms |

There were 18 requests above 15 seconds and none above 20, 25, 35, or 45
seconds. Prompt tokens were 399 min, 1,087 p50, 3,083.55 p95, and 3,136 max.
Structured output was 35 min, 120 p50, 150 p95, and 175 max, below the
384-token V3 completion budget.

## Representative Outputs

These are exact excerpts from the final runtime report.

**EXPLAIN, incident 1**
Question: `Explain the meaning and significance of this security record using supporting facts.`

> Canonical severity is not recorded and is not replaced by risk score or priority. For incident 1, reference knowledge explains: Canonical severity, risk-normalization severity, numeric risk, and recommended priority are separate recorded concepts and cannot replace one another. Incident 1 has recorded correlation, the recorded type is SINGLE_HOST_PATTERN_CORRELATION and the correlation score is 100.

**INVESTIGATE, incident 2**
Question: `What happened and what evidence supports it?`

> Incident 2 has recorded timestamp 2026-05-13T08:04:52.498Z and is CLOSED. Incident 2 was raised by detection rule Successful sudo to ROOT executed. (level 3). Correlation does not by itself establish compromise.

**CROSS_INCIDENT_ANALYSIS, incident 3**
Question: `Could this connect to other incidents?`

> Incidents 3 and 1 share temporal proximity within 24 hours; this is an analytical relationship derived from records. Incidents 3 and 24 share the same correlation type; this is an analytical relationship derived from records. An analytical relationship does not establish causality, a common cause, attacker, or campaign.

**COMPARE, incident 4**
Question: `Compare these two incidents.`

> In comparison, Incident 4 is NEW, Incident 5 is NEW. Incidents 4 and 14 share the same correlation type; this is an analytical relationship derived from records. Incidents 4 and 15 share temporal proximity within 24 hours; this is an analytical relationship derived from records. An analytical relationship does not establish causality, a common cause, attacker, or campaign.

**PATTERN_ANALYSIS, incident 5**
Question: `Find recurring patterns across alerts.`

> The supported pattern covers 3 incidents (5, 10, 12) sharing the same agent. An analytical relationship does not establish causality, a common cause, attacker, or campaign.

**NEXT_ACTION, incident 6**
Question: `What should the analyst verify next?`

> Canonical severity is not recorded and is not replaced by risk score or priority. For incident 6, investigative guidance suggests: Historical Incident Memory Incident ID: 4847 Rule: Integrity checksum changed. Agent: atomicstar Status: CLOSED Severity/Priority: MEDIUM Risk Score: 55 Wazuh Level: 7 MITRE: {'technique': ['Stored Data Manipulation'], 'id': ['T1565.001'], 'tactic': ['Impact']} [...]

**EXECUTIVE_SUMMARY, incident 9**
Question: `Give leadership an executive summary.`

> Canonical severity is not recorded and is not replaced by risk score or priority. Incident 9 is linked to case 4.

**FOLLOW_UP, incident 1**
Question: `Find recurring patterns across alerts.`

> The supported pattern covers 3 incidents (1, 2, 3) sharing temporal proximity within 24 hours. An analytical relationship does not establish causality, a common cause, attacker, or campaign.

## Reproduction

Start an isolated inference gateway using the deployed model, then run:

```bash
AI_INFERENCE_GATEWAY_SOCKET=/path/to/gateway.sock \
  .venv/bin/python scripts/validate_assistant_v3_milestone_b.py
```

The harness rejects concurrent gateway execution, records provider counters
before and after the matrix, and emits its detailed JSON report to standard
output. Conversation state is isolated by owner and thread, and previous
Assistant prose is never accepted as evidence.
