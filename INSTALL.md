# Sovereign AI SOC Installation and Demo Guide

New to the repository? Read the
[External User Quickstart](docs/external-user-quickstart.md) first for the
shortest safe path, component requirements, and project boundaries.

## What this guide covers

This guide prepares Sovereign AI SOC for a local lab or product demo and
describes the public validation workflow. It is not a production-grade
installer or a one-command deployment system.

## Supported environment

The current workflow targets Ubuntu, WSL2 Ubuntu, or a comparable Linux lab
host. Public CI uses Python 3.12 and Node.js 20; Python 3.12 or newer is
recommended.

The frontend requires Node.js and npm. Docker Engine and the Docker Compose
plugin are system prerequisites for infrastructure stacks. Ollama is optional
for local AI execution. PostgreSQL, Qdrant, Grafana, Prometheus, Wazuh and
Suricata are runtime components whose availability depends on the selected
deployment mode.

## System prerequisites

Confirm the required tools before cloning:

```bash
git --version
python3 --version
python3 -m venv --help
node --version
npm --version
docker --version
docker compose version
```

Install missing tools through the supported package-management process for
your Linux distribution. Docker Compose should be installed as the modern
Docker CLI plugin, not as a Python package.

## Clone and prepare

```bash
git clone https://github.com/bluesaphire76/sovereign-ai-soc.git
cd sovereign-ai-soc
```

## Guided local installer

Start with the safe plan, then apply it explicitly:

```bash
./ai-soc install --profile demo --dry-run
./ai-soc install --profile demo --apply
```

The guided installer creates or reuses `.venv`, installs Python requirements,
runs `npm ci`, initializes `.env` through the existing safe workflow and runs
read-only validation. An existing `.env` is not overwritten. It does not start
services or containers, run Docker Compose up/down, pull Ollama models or seed
demo data. Use `--profile local` for a non-demo local configuration.

## Create the Python virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The root requirements file covers the API, PostgreSQL driver, local AI client,
semantic-memory tooling, reporting, observability and test baseline. The
optional ntfy bridge has its own requirements file under
`deploy/observability/ntfy-bridge/`.

## Install frontend dependencies

```bash
cd frontend
npm ci
cd ..
```

## Run local checks

```bash
./ai-soc doctor
./ai-soc validate
./ai-soc docs-validate
```

`doctor` checks local tools, repository files and optional local endpoints.
`validate` runs the lightweight public CI baseline without starting services.
`docs-validate` checks the external quickstart, troubleshooting paths, command
references, and obvious secret patterns without modifying files.

Before publishing a release or sharing the demo, run:

```bash
./ai-soc release-check
./ai-soc release-check --skip-runtime --skip-frontend-build --skip-pytest --json
./ai-soc release-check --write-report
./ai-soc release-check --strict
```

The default release check is read-only. It validates repository state, core
CLI behavior, installer and initializer dry runs, Docker packaging, demo
ownership/status, optional runtime readiness, Python dependencies and syntax,
backend tests, the frontend production build, Compose configuration and
release documentation. It never starts or stops services, writes demo data,
builds Docker images, pulls models or changes `.env`.

Use `--skip-runtime`, `--skip-frontend-build` and `--skip-pytest` for a faster
targeted run. Docker image builds are never performed by default;
`--skip-docker-build` records that explicit policy in machine-readable output.
`--write-report` is the only mode that writes files, producing ignored
Markdown and JSON reports under `reports/validation/`. In `--strict` mode,
every warning makes the release not ready. Generated reports are local
validation artifacts and must not be committed.

## Validate Docker packaging

The Docker demo foundation packages the API and frontend alongside PostgreSQL,
Qdrant and the local Ollama AI runtime:

```bash
./ai-soc package-validate
./ai-soc package-validate --build
```

The default command validates files and Compose configuration without building
or running containers. `--build` creates only local application images; it
does not start containers. Ollama model download remains an explicit manual
operator step. See
[Docker Demo Packaging Foundation](docs/operations/docker-demo-packaging.md).

## Create the local environment file

```bash
./ai-soc init --profile demo
```

The initializer does not overwrite an existing `.env` by default and does not
print generated secrets by default. Review the generated values locally and
never commit `.env`.

Use `--profile local` instead when preparing a non-demo local configuration.

## Validate a running runtime

```bash
./ai-soc validate-runtime
```

This command is read-only. It may report warnings when optional or expected
runtime components are not running.

## Seed synthetic demo data

Inspect the plan first, then apply it only to the intended local demo database:

```bash
./ai-soc demo-seed --dry-run
./ai-soc demo-seed --apply
```

Demo records are clearly marked synthetic, the operation is designed to be
idempotent, and the generated content must not be treated as real security
evidence.

## Validate demo readiness

```bash
./ai-soc demo-validate
./ai-soc demo-status
```

`demo-validate` checks runtime, synthetic records and report readiness.
`demo-status` performs a read-only inspection of the application systemd
services.

## Clean demo mode

Inspect the explicit synthetic-data boundary and review a reset before applying
it:

```bash
./ai-soc demo-info
./ai-soc demo-reset --dry-run
./ai-soc demo-reset --apply
```

`demo-info` is read-only. `demo-reset` removes only records owned by the stable
demo seed marker and refuses to proceed when non-demo child records are
attached. It never cleans Wazuh or Suricata telemetry. Always use dry-run
first; synthetic demo data is not real security evidence.

## Demo lifecycle

Lifecycle actions default to a dry run:

```bash
./ai-soc demo-up --dry-run
./ai-soc demo-up --apply
./ai-soc demo-down --dry-run
./ai-soc demo-down --apply
./ai-soc demo-restart --dry-run
```

The current lifecycle helper manages only `ai-soc-api` and
`ai-soc-frontend`. The worker is opt-in with `--include-worker`. It does not
start or stop Wazuh, Suricata, PostgreSQL, Qdrant, Grafana, Prometheus,
Alertmanager, Loki, Ollama or Docker Compose. It never invokes `sudo`; if
systemd permissions are required, it prints actionable manual guidance.

## 10-minute demo flow

After installing Python and frontend dependencies:

```bash
./ai-soc doctor
./ai-soc validate
./ai-soc package-validate
./ai-soc init --profile demo
./ai-soc validate-runtime
./ai-soc demo-info
./ai-soc demo-reset --dry-run
./ai-soc demo-seed --apply
./ai-soc demo-validate
./ai-soc demo-status
./ai-soc release-check
```

When the frontend service is available, open
`http://127.0.0.1:3000` in a browser. Use
[docs/product/demo-guide.md](docs/product/demo-guide.md) for the presenter flow.

## Troubleshooting

For command-oriented diagnosis covering Python, Node.js, Docker, Ollama,
PostgreSQL, Qdrant, demo data, and systemd, use the
[Troubleshooting Guide](docs/troubleshooting.md).

- **`.env` is missing:** run `./ai-soc init --profile demo`, then review the
  local values.
- **Docker or Compose is unavailable:** install Docker Engine and the Compose
  CLI plugin, then rerun `./ai-soc doctor`.
- **Node.js or npm is missing:** install a supported Node.js release; public CI
  currently uses Node.js 20.
- **Frontend installation or build fails:** rerun `npm ci` and `npm run build`
  inside `frontend/` and inspect the first reported error.
- **Backend is unreachable:** confirm PostgreSQL configuration and inspect
  `./ai-soc validate-runtime`.
- **Ollama is unreachable:** local deterministic workflows remain available,
  but AI-backed features may use fallback behavior.
- **Qdrant is unreachable:** semantic-memory features will be unavailable or
  degraded; core deterministic workflows remain separate.
- **Lifecycle apply needs permission:** run the printed systemd commands
  manually with the privileges appropriate for your host.

## Safety notes

- Never commit `.env`, tokens, generated secrets or private operational data.
- Demo data is synthetic and is not real security evidence.
- AI recommendations support analyst review; they do not replace human
  validation or governed approval.
- The platform is local-first and should not be exposed directly to the public
  Internet without additional deployment and security hardening.

## Next steps

Future packaging may add published container images or fuller demo
orchestration. The current workflow intentionally prioritizes explicit,
reversible setup and safe validation.
