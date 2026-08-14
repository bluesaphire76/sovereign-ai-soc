# AI Assistant V3.1 Real-User Proof Gate

## Existing Target Records

The proof target was selected from the existing local SOC database on
2026-08-14 without creating or modifying SOC data.

- Primary incident: `5333`, Registry Value Entry Added to the System on
  `darkstar-windows`, with recorded MITRE T1112 context.
- First explicit comparison target: `5318`.
- Other deterministic candidates observed during preparation: `5187`, `5225`,
  `5254`, `5264`, `5300`, and `5302`.
- Candidate signals include shared agent, shared rule, shared recorded
  correlation type, and temporal proximity. These are analytical derivations,
  not proof of a common attack.

The initial standalone preparation process reported degraded because it did
not run the API lifespan prewarm. The final isolated V3.1 API run completed
prewarm, reused the shared encoder, and reported semantic status `available`
for every proof query that requested semantic retrieval.

## Required Prompts

Run prompts 1-4 on Incident `5333`, prompt 5 in the same mounted conversation,
and prompts 6-8 on Incident `5333`.

1. `Analizza questo incidente: spiegami cosa è successo, quali sono le evidenze più importanti, cosa possiamo concludere dai dati disponibili e cosa invece non possiamo concludere.`
2. `Quali sono le evidenze più importanti di questo incidente e perché contano dal punto di vista dell'analista SOC?`
3. `Analizza questo incidente come farebbe un analista SOC e indicami cosa controlleresti subito dopo.`
4. `Ci sono altri incidenti realmente rilevanti rispetto a questo? Spiegami quali e perché, senza assumere che appartengano allo stesso attacco.`
5. Follow-up: `Tra quelli che hai citato, quale merita di essere confrontato per primo e perché?`
6. `Cosa possiamo affermare con sicurezza e cosa non è ancora dimostrato?`
7. `Spiegami il significato operativo di questo incidente in modo comprensibile a un responsabile non tecnico.`
8. `In base alle evidenze e ai playbook disponibili, quali verifiche sono più pertinenti e perché?`

For an explicit pair check, compare Incident `5333` with Incident `5318`. Do
not edit either record to improve the response.

## Automated Technical Preparation

The eight required prompts were exercised on 2026-08-14 against the existing
records with V3.1 enabled. Prompt 5 used the same conversation as prompt 4 and
selected Incident `5187`, not the anchor Incident `5333`. All eight responses
used the model-authored normal path, passed deterministic grounding and focus
validation, and recorded exactly one provider generation, zero automatic
retries, and zero model switches. This is technical preparation only; it does
not score answer quality or pass the user-only gate.

Measured with a warm local Qwen3 8B Q4_K_M standard profile and 10-second
analyst-like spacing between non-cross requests:

| Metric | min | p50 | p95 | max |
| --- | ---: | ---: | ---: | ---: |
| Generation | 19.115 s | 22.637 s | 26.946 s | 28.122 s |
| Total | 19.323 s | 23.292 s | 27.352 s | 28.226 s |
| Semantic phase (`available` only) | 32 ms | 36 ms | 566 ms | 743 ms |
| Cross-incident total (prompts 4-5) | 19.323 s | 22.527 s | 25.410 s | 25.730 s |

The 743 ms semantic maximum was the first request after isolated API startup;
subsequent available semantic phases were 32-36 ms. The user turn and pending
assistant state are committed synchronously on submit and become visible on
the next browser frame. There is no first validated segment measurement:
validation occurs after the provider returns the complete structured object.

`TRUE VALIDATED STREAMING NOT TECHNICALLY POSSIBLE WITH CURRENT PROVIDER; FALLBACK UX IMPLEMENTED`

## User-Only Scorecard

Score selected frontend answers from 0 to 10 for content, naturalness,
organization, SOC usefulness, and conversational UX. The required average is
at least 8.0/10, with zero unsupported claims, authority violations, invented
compromise/severity/risk/actor/campaign, and exactly one provider generation
per query.

`MANUAL USER ACCEPTANCE: PENDING`
