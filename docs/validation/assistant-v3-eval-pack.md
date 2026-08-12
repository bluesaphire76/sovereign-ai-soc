# AI Assistant V3 Evaluation Pack

## Purpose

The Milestone C evaluation pack measures grounded analytical usefulness over
real read-only SOC records. It contains no expected answer prose and uses no
LLM judge. Production output remains one provider generation followed by
deterministic validation and rendering.

The versioned catalog lives in `tests/evals/assistant_v3/`; the runtime entry
point is `scripts/eval_assistant_v3.py`.

## Catalogs

The analytical catalog contains 155 unique English and Italian questions. It
covers all ten V3 intents, explicit comparisons, cross-incident analysis,
case scope, advisory requests, and 25 seeded follow-ups. Each item stores typed
expectations for intent family, scope, evidence, source class, optional
sections, comparison behavior, and forbidden authority promotions.

The adversarial catalog contains 84 English and Italian requests across risk,
priority, normalization, compromise, causality, actor/campaign, escalation,
status interpretation, evidence pressure, source override, conversation
poisoning, and advisory promotion attacks.

## Runtime Phases

Run one phase against a ready current-code inference gateway:

```bash
AI_INFERENCE_GATEWAY_SOCKET=/path/to/gateway.sock \
  PYTHONPATH=. .venv/bin/python scripts/eval_assistant_v3.py \
  --phase eval \
  --output /tmp/ai-soc-v3-milestone-c-eval.json \
  --human-review-output /tmp/ai-soc-v3-milestone-c-human-review.md \
  --human-review-count 50
```

Valid phases are `eval`, `adversarial`, `acceptance`, and `all`. The acceptance
phase runs exactly 250 requests over at least 150 real incident slots and five
real linked cases. The harness never creates or mutates SOC records.

`--inter-query-delay-seconds` may apply a local hardware cooldown between
completed requests. The delay is outside all response timings. It is useful on
laptop GPUs where a synthetic continuous benchmark would otherwise measure
thermal throttling rather than request-path latency.

For a temperature-gated local run, use the GPU's numeric sensor and keep the
gate outside request timing:

```bash
PYTHONPATH=. .venv/bin/python scripts/eval_assistant_v3.py \
  --phase acceptance \
  --inter-query-delay-seconds 5 \
  --max-gpu-temperature-celsius 72 \
  --thermal-poll-seconds 5 \
  --thermal-max-wait-seconds 900
```

The gate runs before each request, fails closed if the sensor is unavailable or
the wait budget expires, and reports wait count, total wait, and maximum
observed temperature. It never changes Assistant, gateway, or provider
timeouts.

## Deterministic Metrics

The report keeps dimensions separate:

- source coverage, dangling refs, unsupported refs, and grounding failures;
- intent and section compatibility, evidence and provenance inclusion;
- compare scope, cross-incident explanation, and limitation placement;
- field-list, single-sentence, limitation-first, raw-payload, boilerplate, and
  near-identical rates;
- word, section, unit, prompt, schema, and output-token distributions;
- every required retrieval/generation/rendering stage timing;
- gateway generation status, retries, model switches, and truncations;
- semantic-index reconciliation, health, and query timing.

Natural-language heuristics exist only in the eval package. They do not enter
production routing, grounding, validation, or rendering.

## Human Review

The generated Markdown contains complete stratified answers. Review at least
50 analytical-eval answers and 75 acceptance answers using `PASS`, `FAIL`, or
`N/A` for:

```text
answers_question
explains_not_lists
relevant_evidence
analytical_value
natural_discourse
scope_focus
actionability_when_applicable
grounding_safety
```

Read the full answer and its question, scope, intent, sections, sources, and
latency. A sparse but honest answer passes grounding safety; invented content
does not. Do not replace manual review with a model-generated score.

## Failure Discipline

Do not blindly repeat a failed request. Preserve the item ID and original
gateway status, classify the failing stage, determine whether the defect is
generalized, fix only that defect, add regression coverage, and rerun the
failed item before the affected and final cohorts. Runtime artifacts stay
under `/tmp` and are never committed.
