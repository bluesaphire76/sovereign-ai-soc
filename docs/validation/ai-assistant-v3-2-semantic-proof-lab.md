# AI Assistant V3.2 Phase 0 Semantic Proof Lab

## Boundary

Phase 0 is an offline, local evaluation laboratory. It is not imported by the
Assistant orchestrator or router and does not alter `/assistant/query`, the AI
Execution Gateway, V3.1, frontend behavior, SQL authority, or Qdrant behavior.
It adds no generative call.

The laboratory evaluates the mandatory NLI direction:

```text
premise = package-local evidence proof unit
hypothesis = proposition under evaluation
```

Only `ENTAILMENT` may be accepted. `NEUTRAL`, `CONTRADICTION`, unavailable
providers, malformed provider output, and partially supported fragment sets
fail closed.

## Components

- `services/assistant/v3/semantic_proof/contracts.py` defines closed proof,
  scope, provider, pair, decision, and aggregate result contracts.
- `services/assistant/v3/semantic_proof/compiler.py` compiles literal bilingual
  proof units from an already-built `V3AnalyticalContextPackage` without any
  retrieval or semantic expansion. Operational templates are emitted in EN/IT;
  reference/advisory content without typed source-language metadata remains
  verbatim and is marked `und` rather than being translated or guessed.
- `services/assistant/v3/semantic_proof/corpus.py` defines 147 deterministic
  golden cases across all 23 required categories. It contains 49 IT-to-IT, 49
  EN-to-IT, and 49 EN-to-EN cases; 96 are security-critical.
- `services/assistant/v3/semantic_proof/provider.py` supplies an experimental,
  replaceable GPU-only Transformers NLI provider with explicit label mapping.
- `services/assistant/v3/semantic_proof/evaluation.py` validates provider result
  shape and requires every supplied hypothesis fragment to be entailed.
- `scripts/benchmark_assistant_v32_semantic_proof.py` is the explicit benchmark
  entry point. It never starts, stops, loads, or unloads production services or
  production models.

The first benchmark candidate may be
`MoritzLaurer/mDeBERTa-v3-base-mnli-xnli`, but no model is an architectural
dependency or approved validator. The normal test suite does not import model
runtime dependencies, access the network, download a model, or initialize CUDA.

## Deterministic Validation

```bash
PYTHONPATH=. .venv/bin/pytest -q \
  tests/test_ai_assistant_v32_semantic_proof_lab.py
```

## Controlled GPU Benchmark

Use a local model directory or an already cached model ID. This command checks
free GPU memory before loading the NLI candidate and exits safely when the
configured minimum is unavailable. It queries the llama.cpp models endpoint to
report whether `ai-soc-standard` is resident, but performs no Qwen generation:

```bash
PYTHONPATH=. .venv/bin/python \
  scripts/benchmark_assistant_v32_semantic_proof.py \
  --model /absolute/path/to/local/mdeberta-v3-base-mnli-xnli \
  --device cuda:0 \
  --precision float32 \
  --quantization none \
  --entailment-threshold 0.80 \
  --batch-size 8 \
  --warmup-batches 2 \
  --runs 3 \
  --min-free-gpu-mib 1536 \
  --output /tmp/ai-soc-v32-semantic-proof.json
```

The threshold above is a benchmark input, not an approved production value.
Repeat the benchmark for every precision, batch size, model, and threshold under
consideration. Quantized NLI loading is deliberately not implemented in Phase 0
and is reported as `none`.

To measure Qwen latency before and while the NLI model is resident, both explicit
flags are mandatory. This performs exactly two controlled, minimal Qwen
generation probes through the existing AI Execution Gateway UDS and still
performs no service or model lifecycle operation:

```bash
PYTHONPATH=. .venv/bin/python \
  scripts/benchmark_assistant_v32_semantic_proof.py \
  --model /absolute/path/to/local/mdeberta-v3-base-mnli-xnli \
  --device cuda:0 \
  --precision float32 \
  --quantization none \
  --entailment-threshold 0.80 \
  --batch-size 8 \
  --warmup-batches 2 \
  --runs 3 \
  --min-free-gpu-mib 1536 \
  --measure-qwen-latency \
  --allow-generative-probe \
  --output /tmp/ai-soc-v32-semantic-proof-with-qwen.json
```

The report includes backend, model, precision, quantization, device, free and
resident GPU memory, cold startup, warm latency, p50, p95, pairs per second,
per-language accuracy, false accepts, false rejects, security-critical false
accepts, Qwen residency, coexistence status, and optional Qwen probe latencies.
The command returns a non-zero status when `ai-soc-standard` is not explicitly
reported as resident both before and while the NLI candidate is resident; a
standalone NLI result therefore cannot be mistaken for a coexistence result.

## Deliberately Not Integrated

Phase 0 does not implement sentence segmentation, automatic candidate evidence
selection, production thresholds, `_run_v32_response`, Assistant metadata,
frontend changes, runtime prewarm, systemd integration, CPU fallback, or any
publication decision in the production Assistant path.

`PRODUCTION V3.2 INTEGRATION AUTHORIZED: NO`
