# AI Inference Gateway Operations

## Prerequisites

The deployment must provide an operator-managed
`ai-soc-llama-cpp-router.service` with the `ai-soc-standard` alias. This
repository does not install or download the router or GGUF model. The gateway,
API, worker, and frontend templates are parameterized and expect one service
account with access to the project and `/run/ai-soc`.

Required environment:

```dotenv
AI_EXECUTION_MODE=gateway
AI_INFERENCE_GATEWAY_SOCKET=/run/ai-soc/inference-gateway.sock
AI_INFERENCE_PROFILE=standard
AI_INFERENCE_MAX_QUEUE=50
AI_INFERENCE_STARTUP_TIMEOUT_SECONDS=180
AI_INFERENCE_REQUEST_TIMEOUT_SECONDS=35
AI_INFERENCE_MAX_OUTPUT_TOKENS=384
AI_SOC_ASSISTANT_REQUEST_TIMEOUT_SECONDS=45
```

The Assistant uses its dedicated request deadline for constrained structured
generation. Other gateway tasks continue to use the global request timeout.

## Render And Review

Rendering is a dry-run unless `--apply` is explicit:

```bash
python3 scripts/manage_systemd_units.py render \
  --project-root "$PWD" \
  --output-dir /tmp/ai-soc-systemd \
  --service-user ai-soc \
  --service-group ai-soc
```

After reviewing `/tmp/ai-soc-systemd`, an operator can render directly to the
host directory:

```bash
sudo python3 scripts/manage_systemd_units.py render \
  --project-root "$PWD" \
  --output-dir /etc/systemd/system \
  --service-user ai-soc \
  --service-group ai-soc \
  --allow-system-directory \
  --apply
sudo systemctl daemon-reload
```

Use `upgrade` with the same arguments to replace the four managed templates.
Use `uninstall` to preview removal, then add `--apply` to remove only those
four unit files. Service stop, disable, daemon reload, and project deletion
remain explicit operator actions.

## Lifecycle

The required start order is:

```text
ai-soc-llama-cpp-router
ai-soc-inference-gateway
ai-soc-api
ai-soc-worker
ai-soc-frontend
```

After installation:

```bash
sudo systemctl start ai-soc-llama-cpp-router.service
sudo systemctl start ai-soc-inference-gateway.service
sudo systemctl start ai-soc-api.service
sudo systemctl start ai-soc-worker.service
sudo systemctl start ai-soc-frontend.service
```

The repository lifecycle helper previews the four application operations by
default and applies them only with its existing explicit apply option.

## Health

```bash
sudo systemctl status ai-soc-llama-cpp-router.service \
  ai-soc-inference-gateway.service ai-soc-api.service \
  ai-soc-worker.service ai-soc-frontend.service --no-pager

sudo curl --silent --show-error \
  --unix-socket /run/ai-soc/inference-gateway.sock \
  http://localhost/status

sudo curl --silent --show-error \
  --unix-socket /run/ai-soc/inference-gateway.sock \
  http://localhost/metrics
```

Healthy status reports `ready`, `standard`, `ai-soc-standard`, queue depth,
and one or zero active requests. During normal use
`ai_execution_profile_switch_total` remains zero.

## Troubleshooting

For `warming`, inspect the router unit, alias, model availability, and gateway
journal. For `failed`, fix the router first and allow the readiness monitor to
recover automatically:

```bash
sudo journalctl -u ai-soc-inference-gateway.service -n 200 --no-pager
sudo journalctl -u ai-soc-llama-cpp-router.service -n 200 --no-pager
```

For queue deadlines, inspect queue depth, active requests, task status, and
request durations. Do not enable a second provider path or a second prewarm
owner as a workaround. Qdrant failure is independent: Assistant SQL-grounded
answers continue with semantic status `failed` or `timed_out`.

## Assistant V3 Rollout And Rollback

The response architecture has one rollout control:

```text
AI_ASSISTANT_RESPONSE_ARCHITECTURE=v2|v3
```

The repository default is `v3`. Set it explicitly in a deployment environment
when reconciling an existing rollout, then restart the API through the normal
service workflow. A successful verification request reports response
architecture `v3`, passed grounding and plan validation, standard profile/model,
exactly one provider generation, no automatic retry, and no fallback. Confirm
the gateway returns to `ready` with `queue_depth=0` and `active_requests=0`.

Rollback requires no schema or data migration. Restore the setting to `v2` and
restart the API. V3 conversation state contains only bounded validated refs and
is not consumed as authoritative prose by V2. The incident semantic index may
remain populated because Qdrant is retrieval support only.

Do not copy `.env.example` over a deployment `.env`. Reconcile key names only,
preserve all local values, and never print secrets during an audit.

## Supervised Acceptance A-G

Set deployment-specific values without printing the token:

```bash
export API_BASE="https://soc.example"
export TOKEN="<analyst-or-admin-token>"
export INCIDENT_ID="<existing-incident-id>"
```

### A. Startup

```bash
sudo systemctl restart ai-soc-llama-cpp-router.service
sudo systemctl restart ai-soc-inference-gateway.service
sudo systemctl restart ai-soc-api.service
sudo systemctl restart ai-soc-worker.service
sudo systemctl restart ai-soc-frontend.service
sudo systemctl is-active ai-soc-llama-cpp-router.service \
  ai-soc-inference-gateway.service ai-soc-api.service \
  ai-soc-worker.service ai-soc-frontend.service
sudo curl --silent --show-error \
  --unix-socket /run/ai-soc/inference-gateway.sock \
  http://localhost/status | python3 -m json.tool
```

Expected: five `active` lines and gateway state `ready`, profile `standard`,
model `ai-soc-standard`. Gateway/router journals contain no fast or quality
load during normal startup after standard is ready.

### B. Page Load

In one terminal:

```bash
sudo journalctl -f -u ai-soc-inference-gateway.service
```

Open `${API_BASE}/incidents/${INCIDENT_ID}` in the frontend, without selecting
a Generate control. Expected: no `recommended_playbooks` or
`remediation_explanation` task appears and the profile remains standard.

### C. First Assistant Query

```bash
curl --silent --show-error \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"Explain the risk and correlation without changing the recorded severity.\",\"scope\":\"incident\",\"incident_id\":${INCIDENT_ID},\"requested_mode\":\"standard\",\"include_semantic_memory\":true}" \
  "${API_BASE}/assistant/query" | tee /tmp/assistant-c.json | python3 -m json.tool
```

Expected: `status=ok`, `generation_kind=model`, grounding and focus `passed`,
profile/model standard, internal source chips, no invented fact, and total
latency at most 30 seconds with a target of 20 seconds.

### D. Five Repetitions

```bash
for i in 1 2 3 4 5; do
  curl --silent --show-error \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"message\":\"Explain the risk and correlation without changing the recorded severity.\",\"scope\":\"incident\",\"incident_id\":${INCIDENT_ID},\"requested_mode\":\"standard\",\"include_semantic_memory\":true}" \
    "${API_BASE}/assistant/query" > "/tmp/assistant-${i}.json"
done
python3 - <<'PY'
import json
from pathlib import Path

items = [json.loads(Path(f"/tmp/assistant-{i}.json").read_text()) for i in range(1, 6)]
assert all(item["status"] == "ok" for item in items)
assert all(item["generation_kind"] == "model" for item in items)
assert all(item["metadata"]["grounding_validation"] == "passed" for item in items)
assert all(item["metadata"]["focus_validation"] == "passed" for item in items)
print("5/5 grounded model responses")
PY
sudo curl --silent --show-error \
  --unix-socket /run/ai-soc/inference-gateway.sock \
  http://localhost/metrics | grep ai_execution_profile_switch_total
```

Expected: `5/5 grounded model responses` and profile-switch total `0`.

### E. Semantic Memory Degraded

For the demo Compose deployment:

```bash
docker compose -f deploy/demo/docker-compose.demo.yml stop qdrant
curl --silent --show-error \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"Explain the recorded risk.\",\"scope\":\"incident\",\"incident_id\":${INCIDENT_ID},\"requested_mode\":\"standard\",\"include_semantic_memory\":true}" \
  "${API_BASE}/assistant/query" | tee /tmp/assistant-e.json | python3 -m json.tool
docker compose -f deploy/demo/docker-compose.demo.yml start qdrant
```

Expected: an authoritative model response still succeeds; semantic status is
`failed` or `timed_out`, and Qdrant unavailability alone does not cause
fallback.

### F. Concurrent Platform Use

Start a background gateway job, then submit the three user operations:

```bash
sudo curl --silent --show-error \
  --unix-socket /run/ai-soc/inference-gateway.sock \
  -H "Content-Type: application/json" \
  -d '{"task":"worker_enrichment","priority":"background","request_id":"runtime-background-1","deadline_ms":30000,"system_instructions":"Return only a concise defensive summary.","input":"Summarize the supplied background lifecycle check without adding facts.","output_schema":"text_v1","max_output_tokens":384,"temperature":0}' \
  http://localhost/v1/generate > /tmp/gateway-background.json &
curl --silent --show-error -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"Explain the current risk.\",\"scope\":\"incident\",\"incident_id\":${INCIDENT_ID},\"requested_mode\":\"standard\",\"include_semantic_memory\":false}" \
  "${API_BASE}/assistant/query" > /tmp/gateway-assistant.json &
curl --silent --show-error -X POST -H "Authorization: Bearer ${TOKEN}" \
  "${API_BASE}/incidents/${INCIDENT_ID}/recommended-playbooks" \
  > /tmp/gateway-playbook.json &
curl --silent --show-error -X POST -H "Authorization: Bearer ${TOKEN}" \
  "${API_BASE}/incidents/${INCIDENT_ID}/remediation-plan" \
  > /tmp/gateway-remediation.json &
wait
sudo curl --silent --show-error \
  --unix-socket /run/ai-soc/inference-gateway.sock \
  http://localhost/status | python3 -m json.tool
```

Expected: one active generation at a time; after the active background job,
Assistant runs before playbook and remediation according to priority. All jobs
complete or return an accurate deadline status, with no profile switch.

### G. Italian

```bash
curl --silent --show-error \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"Spiega il rischio e la correlazione senza modificare la severità registrata.\",\"scope\":\"incident\",\"incident_id\":${INCIDENT_ID},\"requested_mode\":\"standard\",\"include_semantic_memory\":true}" \
  "${API_BASE}/assistant/query" | tee /tmp/assistant-g.json | python3 -m json.tool
```

Expected: fully Italian grounded response, one safe read-only next check,
backend-owned sources, and no severity mutation or invented fact.
