# Docker Demo Packaging Foundation

## Purpose and scope

The Docker demo packaging is a controlled foundation for evaluating Sovereign
AI SOC without attempting to containerize the complete SOC ecosystem. It
provides buildable application images and a readable Compose model for:

- the FastAPI backend;
- the Next.js frontend;
- PostgreSQL;
- Qdrant;
- Ollama.

This is a local demo foundation, not a production deployment or a one-command
installer. Database schema initialization, the first admin account and demo
data remain explicit operator steps.

## Why Ollama is included

Local AI is a core product capability rather than an optional visual add-on.
AI-assisted triage, incident analysis, the command brief, recommended actions
and analyst decision support require a model runtime. Including Ollama keeps
that execution local and preserves the product's data-sovereignty and
local-first design.

The Compose file persists downloaded models in `ollama_demo_models`. It never
downloads a model automatically.

## Intentionally excluded

The demo Compose file does not include Wazuh, Suricata, Grafana, Prometheus,
Loki, Alertmanager, production Nginx or Cloudflare integration. These
components are valuable in a fuller deployment, but they add privileged,
host-network, telemetry and operational concerns that would obscure this
small, safe packaging baseline.

The ingest worker is also omitted because its normal workflow requires Wazuh
and persistent database schema. It can be packaged later with the telemetry
stack and explicit lifecycle controls.

## Configuration

The committed environment example contains demo-only placeholders:

```bash
cp deploy/demo/.env.demo.example deploy/demo/.env.demo
```

Review and change those values before use. Pass the file explicitly:

```bash
docker compose \
  --env-file deploy/demo/.env.demo \
  -f deploy/demo/docker-compose.demo.yml \
  config --quiet
```

`NEXT_PUBLIC_API_BASE_URL` is embedded into the browser bundle while the
frontend image is built. Its default, `http://localhost:8008`, is appropriate
for the documented local port mapping.

The demo uses the real application settings:

- `POSTGRES_*` with the internal hostname `postgres`;
- `QDRANT_URL=http://qdrant:6333`;
- `OLLAMA_BASE_URL=http://ollama:11434`;
- `AI_OLLAMA_BASE_URL=http://ollama:11434`;
- `AI_SOC_LLM_FAST`, `AI_SOC_LLM_STANDARD` and `AI_SOC_LLM_QUALITY`.

All demo profiles default to `qwen3.5:4b` so a basic evaluation needs only one
local model. Operators can select different profile models in their untracked
demo environment file.

## Validation

The default validator is read-only and does not build images or contact
runtime services:

```bash
./ai-soc package-validate
./ai-soc package-validate --json
docker compose -f deploy/demo/docker-compose.demo.yml config --quiet
```

The guided local installer also runs packaging validation:

```bash
./ai-soc install --profile demo --dry-run
```

It does not start Docker services or pull Ollama models.

Image builds are explicit:

```bash
./ai-soc package-validate --build
```

The build option creates only local API and frontend images. It does not run
containers, pull Ollama models, push images or prune Docker state.

## Explicit model setup

Models are not downloaded by Compose, CI or the packaging validator. After an
operator has started the demo stack, pull the selected model explicitly:

```bash
docker compose \
  --env-file deploy/demo/.env.demo \
  -f deploy/demo/docker-compose.demo.yml \
  exec ollama ollama pull qwen3.5:4b
```

CPU execution is the default baseline. NVIDIA GPU acceleration is an advanced
future option and is not required by the committed Compose file.

## Safety and limitations

- Never put real secrets directly in a Dockerfile or Compose file.
- Never commit `.env`, `.env.demo` or operational credentials.
- The committed demo environment is not suitable for production.
- Demo records are synthetic and are not real security evidence.
- CI and Codex validation intentionally do not execute `docker compose up` or
  `docker compose down`.
- Images are not published to GHCR in this step.
- The API image prioritizes dependency compatibility over image size and is
  not yet split into minimal runtime dependency groups.
- Production hardening, schema orchestration and full SOC telemetry deployment
  remain separate work.

Future packaging can add optional GHCR publishing, fuller demo orchestration
and a hardened optional GPU profile.
