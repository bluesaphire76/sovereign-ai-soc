# AI SOC Assistant Observability

## Scope

The `AI SOC Assistant - End-to-End Observability` Grafana dashboard follows an
Assistant request from the API through analytical retrieval, the single-owner
inference gateway, semantic proof, and atomic model-response or deterministic
fallback publication.

The dashboard is provisioned from:

```text
deploy/observability/grafana/dashboards/ai-soc-assistant-observability.json
```

Its stable Grafana UID is `ai-soc-assistant-observability`.

## Collection Path

The inference gateway remains bound only to
`/run/ai-soc/inference-gateway.sock`. The public API exposes a read-only
`GET /metrics/ai-inference` bridge that returns the gateway's Prometheus text
payload. It does not proxy `/v1/generate`, `/status`, or any other gateway
operation.

Prometheus uses two explicit jobs:

| Job | Target | Responsibility |
| --- | --- | --- |
| `ai-soc-api` | `127.0.0.1:8008/metrics` | Assistant lifecycle, retrieval, proof, fallback, HTTP and GPU metrics |
| `ai-inference-gateway` | `127.0.0.1:8008/metrics/ai-inference` | Gateway readiness, queue, generation, token and deadline metrics |

Dashboard queries always constrain the `job` label so identically registered
metric families in separate Python processes cannot be combined accidentally.

## Coverage

The dashboard reports:

- gateway scrape and runtime readiness;
- active standard model identity and profile-switch invariant;
- request throughput and outcomes by bounded task/status;
- exact inference runtime invocation count for the one-generation invariant;
- queue depth, capacity, utilization, wait latency and active generation;
- provider generation and Assistant end-to-end p50/p95/p99 latency;
- prompt/completion token throughput and truncation events;
- published model responses and deterministic fallback rates/reasons;
- semantic proof execution status, latency, obligations and decision reasons;
- grounding rejection and structural fail-closed events;
- analytical context, stage, semantic-index and degradation telemetry;
- GPU, llama.cpp router and standard-model readiness;
- sanitized operational API and gateway warnings/errors from Loki.

Metric labels contain only closed operational values such as task, status,
stage, reason, intent and scope. They never contain user, incident, case,
conversation, prompt, response or evidence content.

## Alerts

`deploy/observability/prometheus/rules/ai-soc-assistant-alerts.yml` defines
alerts for:

- an unavailable gateway metrics target;
- a reachable but non-ready gateway runtime;
- sustained queue saturation;
- Assistant deadline failures and high inference latency;
- any forbidden gateway profile switch;
- unavailable semantic proof;
- structural fail-closed fallback conditions;
- Assistant API server errors.

Semantic-proof rejection itself is visible but is not an alert: rejecting an
unsupported proposition is expected fail-closed behavior. The alert focuses on
proof-runtime unavailability instead.

## Operational Logs

Grafana Alloy reads `ai-soc-inference-gateway.service` from the journal under
the `ai-soc-inference-gateway` service label. The shared pipeline keeps only
operationally useful events and drops access logs, prompts, responses,
incident/case identifiers, secrets and security telemetry before Loki ingestion.

## Deployment

After deploying these files, restart the code-owning services and reload the
observability stack:

```bash
sudo systemctl restart ai-soc-inference-gateway.service ai-soc-api.service
curl -fsS -X POST http://127.0.0.1:9090/-/reload
docker compose -f deploy/observability/docker-compose.loki.yml restart alloy
docker compose -f deploy/observability/docker-compose.yml restart grafana
```

Grafana file provisioning also polls the dashboard directory every 30 seconds,
so a Grafana restart is optional when the mounted file is already updated.

## Verification

Verify both metric sources independently:

```bash
curl --unix-socket /run/ai-soc/inference-gateway.sock \
  http://localhost/metrics | grep ai_execution_gateway_ready

curl -fsS http://127.0.0.1:8008/metrics/ai-inference \
  | grep ai_execution_gateway_ready

curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22ai-inference-gateway%22%7D'
```

Expected results are a ready value of `1`, a successful bridge response, and a
Prometheus target value of `1`. Generate one Assistant request and confirm that
`ai_execution_requests_total{task="soc_assistant"}` and
`assistant_v3_responses_total` both advance while
`ai_execution_profile_switch_total` remains zero.

Open the dashboard locally at:

```text
http://127.0.0.1:3002/grafana/d/ai-soc-assistant-observability/ai-soc-assistant-end-to-end-observability
```

## Failure Interpretation

- `up=0`: the API bridge, API service, Unix socket, or gateway service is not reachable.
- `up=1` and `gateway_ready=0`: the bridge works but the model runtime is warming, failed or stopped.
- rising queue wait with low GPU utilization: inspect gateway/runtime readiness and upstream model logs.
- rising generation time with high GPU utilization: inspect context/token volume and resource saturation.
- proof `failed`: a generated proposition was rejected and the response failed closed as designed.
- proof `unavailable`: inspect the NLI runtime immediately; the deterministic fallback is protecting publication.
- structural fallback: inspect structured-output, schema and proof-runtime logs without weakening validation.
- profile switch above zero: treat as a single-standard-profile contract violation.
