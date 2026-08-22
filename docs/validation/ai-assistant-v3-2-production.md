# AI Assistant V3.2 Production Validation

## Proof Gate

The deterministic golden corpus contains 210 cases: 70 IT-to-IT, 70
EN-to-IT, and 70 EN-to-EN. It covers exact facts, faithful paraphrases,
contradictions, compounds, causal/intent/compromise overreach, authority
promotion, temporal and count claims, negation, relationships, reference
knowledge, advisory guidance, and semantic candidates.

The selected hybrid result with FP16 CUDA and entailment threshold 0.80 is:

| Gate | Result |
| --- | ---: |
| security-critical false accepts | 0 |
| exact fact acceptance | 100% |
| faithful paraphrase acceptance | 100% |
| critical contradiction rejection | 100% |
| critical compound rejection | 100% |
| critical overreach rejection | 100% |
| IT_IT acceptance accuracy | 100% |
| EN_IT acceptance accuracy | 100% |
| EN_EN acceptance accuracy | 98.57% |

Proof paths were 129 typed guard rejects, 75 typed deterministic proofs, and 6
NLI proof obligations. The sole false reject was a supported EN_EN advisory;
there were no false accepts. MiniLM NLI by itself had five security-critical
false accepts, so it is approved only inside the hybrid gate. The earlier
mDeBERTa candidate remains rejected as a sole proof gate.

## Performance And Coexistence

With `ai-soc-standard` resident on the RTX 4070 Laptop 8 GB, the selected NLI
runtime added about 212 MiB resident VRAM and reached a 236 MiB process reserve
peak. Qwen remained resident before and during the benchmark. Warm raw NLI was
13.7 ms, with p50 12.8 ms, p95 19.8 ms, and about 567 pairs/s. Cold model load
was about 6.0 s and is handled by conditional API prewarm.

The full 210-case hybrid corpus, including all typed guards and six NLI pairs,
measured p50 169.7 ms and p95 173.6 ms. This is a corpus batch measurement, not
the expected latency of a bounded 1-12 proposition response. The first Qwen
probe before NLI was a cold/warm-up sample, so its 1096 ms versus 98 ms resident
sample is evidence of coexistence and continued residency, not a controlled
generation-regression ratio.

## Runtime Invariants

- exactly one gateway generation per query;
- no retry, critic, repair, rewrite, citation repair, or second generation;
- every visible model proposition is covered by one structurally valid proof;
- final attribution comes from accepted proof units;
- any proof failure or timeout discards the full draft and uses deterministic
  grounded fallback;
- local pinned GPU model only, with no runtime download or CPU fallback;
- SQL remains operational authority and Qdrant remains discovery support.

The final automated suite and Prompt 1-8 product evidence are recorded in the
mission engineering report after full validation.
