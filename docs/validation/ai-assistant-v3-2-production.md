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
peak. Qwen remained resident before and during the final benchmark. Warm raw
NLI was 14.4 ms, with p50 13.3 ms, p95 21.8 ms, and about 539 pairs/s. Cold
model load was about 6.3 s and is handled by conditional API prewarm.

The full 210-case hybrid corpus, including all typed guards and six NLI pairs,
measured p50 217.6 ms and p95 226.9 ms. This is a corpus batch measurement, not
the expected latency of a bounded 1-8 proposition response. The first Qwen
probe before NLI was a cold/warm-up sample, so its 1096 ms versus 98 ms resident
sample is evidence of coexistence and continued residency, not a controlled
generation-regression ratio.

## Runtime Invariants

- exactly one gateway generation per query;
- no retry, critic, repair, rewrite, citation repair, or second generation;
- every visible model proposition is covered by one to four structurally
  compatible proof units;
- analytical boundaries remain analytical derivations and can combine with an
  operational fact only through matching typed source refs;
- final attribution comes from accepted proof units;
- any proof failure or timeout discards the full draft and uses deterministic
  grounded fallback;
- local pinned GPU model only, with no runtime download or CPU fallback;
- SQL remains operational authority and Qdrant remains discovery support.

The final automated suite and Prompt 1-8 product evidence are recorded in the
mission engineering report after full validation.

## Prompt 1-8 Product Proof

The final read-only product run used authoritative incidents 5333 and 5318 in
one conversation through the temporary V3.2 gateway. It issued exactly eight
provider generations for eight queries, with zero retries and zero model
switches. Two drafts passed whole-response proof and six unsafe or incomplete
drafts were discarded in favor of the typed deterministic fallback.

| Prompt | Published path | Product result |
| --- | --- | --- |
| 1 incident analysis | model | Direct facts, MITRE meaning, risk and correlation boundaries |
| 2 important evidence | fallback | Prioritized operational evidence with reference context |
| 3 immediate next action | fallback | Explicitly reports unavailable advisory context |
| 4 related incidents | model | Pair-scoped relationships plus non-causality boundary |
| 5 comparison follow-up | fallback | Preserves the explicit 5333/5318 conversation scope |
| 6 proven vs unproven | fallback | Separates recorded facts from compromise conclusions |
| 7 executive explanation | fallback | Concise operational summary without threat promotion |
| 8 playbook checks | fallback | Advisory guidance from a historical similarity lead |

The published responses scored 8.4/10 in manual product review. They answered
the requested intent in coherent Italian, retained relevant uncertainty, and
contained no unsupported security-critical assertion. Remaining quality limits
are fallback verbosity and occasional platform enum terminology, not grounding
failures.

Across the eight queries, generation averaged 54.36 s (p50 34.23 s, p95
75.91 s). End-to-end wall time averaged 54.68 s (p50 34.35 s, p95 76.06 s;
maximum 116.19 s). Semantic proof averaged 75.4 ms with p50 30 ms, p95 164 ms,
and maximum 244 ms across 44 proof pairs. The gateway was `ready` on the
standard Qwen profile before and after the run; no unload, OOM, service restart,
or profile switch occurred.
