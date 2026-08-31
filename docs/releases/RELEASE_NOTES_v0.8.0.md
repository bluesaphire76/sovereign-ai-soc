# AI SOC v0.8.0 - Grounded AI Assistant and Global SOC Analytics

v0.8.0 consolidates the grounded AI Assistant as a local-first analyst support
surface across global, incident and case workflows. It preserves deterministic
operational authority and fail-closed publication while adding compositional,
typed analytics over authorized platform data.

## Assistant architecture

The shared `/assistant/query` API supports:

- the Global AI SOC Assistant for cross-platform questions and analytics;
- contextual Incident Assistant questions backed by incident evidence;
- contextual Case Assistant questions backed by case and linked-incident data;
- local inference through the single-owner llama.cpp execution gateway;
- bounded typed conversation state that never treats prior generated prose as
  evidence;
- one maximum Qwen answer-generation call followed by V3.2 whole-response
  semantic proof and atomic model-response or deterministic-fallback
  publication.

The Assistant is an analyst decision-support capability. It is not an
autonomous response authority and does not provide ChatGPT-equivalent
open-language understanding.

## Authoritative analytics

Global analytics compile natural-language requests into a closed
`SemanticQueryAST` and a registered SQLAlchemy execution plan. The bounded
analytics surface includes:

- record and distinct counts;
- typed positive and negative filters;
- grouping, ranking and distributions;
- daily trends and period/entity comparisons;
- recorded relationship lookup;
- semantic similarity discovery with SQL rehydration;
- MITRE and bounded reference lookup.

The closed source-domain decision owns retrieval before execution. Reference,
playbook, investigation, remediation, relationship, similarity, operational
fact and analytics requests can use only their registered execution families;
an incompatible analytics candidate is rejected before its executor runs.

Natural language cannot supply SQL, table names, joins, columns, functions or
arbitrary predicates. Requests that cannot be mapped and validated safely fail
closed or return a deterministic clarification/fallback.

## Grounding and security boundaries

- SQL records are `OPERATIONAL_AUTHORITATIVE` and RBAC scope is applied before
  query, grouping or aggregation.
- Registered deterministic analytical results are
  `ANALYTICAL_DERIVATION`.
- Platform-recorded correlations retain operational authority; constructed
  analytical relationships cannot be promoted to recorded correlation,
  causality, compromise, attacker identity or campaign identity.
- Bounded reference material and advisory guidance retain their typed
  authority classes.
- Qdrant remains discovery and supporting context only. Candidate records are
  authorized and rehydrated through SQL before operational use.
- Model-authored references and prior generated prose are never authority.
- Unvalidated generated prose cannot be published.
- Free natural-language-to-SQL execution remains absent.

Generation invariants remain one maximum final-answer generation with no
retry-generation, repair-generation, critic, rewrite, model switching or cloud
inference path in the accepted local architecture.

## Natural-language recovery

The committed recovery architecture supports English and Italian through local
language identification, Universal Dependencies parsing, multilingual semantic
primitives and bounded whole-plan ranking. It improves compositional entity,
filter, grouping, temporal and source-domain interpretation while keeping the
output constrained to registered structures. Typed conversation state can
carry authorized prior plans, result identifiers, filters, dimensions and time
windows between turns.

## Validated product quality

The last fully validated objective engineering/product score is **7.79 / 10**.
This is a project-specific acceptance measurement, not a formal industry
benchmark and not a claim of general-purpose conversational equivalence.

The validated architecture preserves zero security-critical false accepts in
the accepted security corpus, exact SQL/RBAC boundaries and fail-closed
publication. Release-candidate validation covers targeted Assistant, V3.2
proof, Incident, Case, analytics, SQL/RBAC, Qdrant-boundary, backend, frontend,
public-CI, container/configuration and live-smoke paths.

## Known limitations

- Generalization to previously unseen language remains imperfect.
- Supported usefulness on the existing blind evaluation remains below 90%.
- Complex temporal requests can be misunderstood or fail closed.
- Multi-turn references and composition can fail.
- Ambiguity resolution remains incomplete.
- Some answerable requests can still return deterministic fallback or
  clarification.
- Minor English and Italian grammar imperfections remain possible.
- Inference latency depends strongly on local GPU capacity and current runtime
  load.
- Hardware with more VRAM may permit future evaluation of stronger local
  models, but no such model is part of v0.8.0.

These are accepted release limitations. v0.8.0 does not include the failed
post-recovery structured-semantic-parser experiment.

## Compatibility and upgrade notes

No intentional breaking API change is introduced by release consolidation.
Existing local `.env`, llama.cpp profiles, operational databases and Qdrant
data must be preserved during upgrade.

After deployment, run:

```bash
./ai-soc validate
./ai-soc validate-runtime
./ai-soc demo-validate
```

Confirm that the API, inference gateway, `ai-soc-standard`, semantic proof
runtime, database and Qdrant are ready before running Assistant smoke tests.
