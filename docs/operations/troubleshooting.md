# Troubleshooting

Use this guide for common local installation, validation, demo, and runtime
problems. Start with read-only checks and fix the first concrete error rather
than applying broad system changes.

## First checks

```bash
./ai-soc doctor
./ai-soc validate
./ai-soc release-check --skip-runtime --skip-frontend-build --skip-pytest
```

`doctor` distinguishes required tools from optional local services. `validate`
checks the public repository baseline. The shortened release check verifies
installation, packaging, demo, and documentation readiness without running
the test suite or frontend build.

## Python and virtual environment issues

- If `python3` is missing, install Python 3.12 or newer through your Linux
  distribution.
- If `python3 -m venv` fails, install the distribution package commonly named
  `python3-venv`.
- If pip is missing from the system interpreter, install the matching Python
  pip/venv package rather than using an unrelated global interpreter.
- If `.venv` was not created, inspect the plan first:

  ```bash
  ./ai-soc install --profile demo --dry-run
  ```

- If requirement installation fails, preserve the first package/build error.
  Packages such as `sentence-transformers` and `torch` are comparatively large
  and may require more disk space and installation time.
- After dependencies are installed, check consistency with:

  ```bash
  .venv/bin/python -m pip check
  ```

## Node and frontend issues

- Install a supported Node.js release and npm if either command is missing.
  Public CI currently uses Node.js 20.
- If `npm ci` fails, inspect the first dependency or network error and keep
  `frontend/package-lock.json` unchanged unless dependency maintenance is
  intentional.
- npm audit warnings are not the same as a failed production build. Validate
  the actual build separately:

  ```bash
  cd frontend
  npm ci
  npm run build
  cd ..
  ```

- Do not use `npm audit fix --force` as a generic troubleshooting step.

## Docker and Compose issues

- If Docker reports that it cannot connect to the daemon, verify that Docker
  Engine is running.
- If access is denied, use the Docker permissions model approved for your host;
  do not make the daemon publicly accessible.
- Install the modern Docker Compose plugin so `docker compose version` works.
- Validate repository packaging with:

  ```bash
  ./ai-soc package-validate
  ```

- A Compose config failure usually identifies a missing file, variable, or
  invalid YAML structure. Packaging validation does not run `docker compose
  up` or `docker compose down`.
- `./ai-soc package-validate --build` can be slow because application images
  include backend and frontend dependencies. It builds images but does not
  start containers.

## Ollama and local AI issues

- Check whether Ollama is reachable at the configured URL, commonly
  `http://127.0.0.1:11434`.
- A reachable runtime still needs the configured model to be installed.
- Model selection and download are manual operator actions. CI, the installer,
  and packaging validation do not download models.
- CPU inference is supported and may be noticeably slower. A GPU improves
  performance but is not required for the basic local demo.
- Deterministic workflows and fallback output remain available when Ollama is
  unavailable, but the full AI-assisted value requires a working model runtime.

## PostgreSQL and Qdrant issues

- Confirm the configured PostgreSQL host, port, database, and user without
  printing passwords or the complete `.env`.
- For a host-based runtime, PostgreSQL and Qdrant commonly use
  `127.0.0.1:5432` and `127.0.0.1:6333`.
- Inside the Docker demo network, the API uses service names such as
  `postgres`, `qdrant`, and `ollama`, not `127.0.0.1`.
- Qdrant can be reachable while the configured collection is missing or empty;
  in that case semantic-memory features remain degraded until the knowledge
  base is indexed.

See [Ports and Components](ports-and-components.md) for the default endpoints.

## Demo data issues

Inspect state before making changes:

```bash
./ai-soc demo-seed --status
./ai-soc demo-info
./ai-soc demo-validate
```

Reset only demo-owned records and always review the plan first:

```bash
./ai-soc demo-reset --dry-run
./ai-soc demo-reset --apply
```

Do not manually delete application records unless you understand the database
schema and relationships. Demo reset deliberately refuses unsafe ownership or
dependency situations.

## Runtime and systemd issues

`demo-status` is read-only:

```bash
./ai-soc demo-status
```

Lifecycle changes use dry-run mode unless `--apply` is provided:

```bash
./ai-soc demo-up --dry-run
./ai-soc demo-down --dry-run
./ai-soc demo-restart --dry-run
```

The scripts do not invoke `sudo`. Apply mode may require privileges configured
for the local systemd units. If the API or frontend is inactive, inspect the
unit status and logs using the normal administrative process for your host.
These commands do not manage PostgreSQL, Qdrant, Ollama, Wazuh, Suricata, or
the observability stack.

## Wazuh and Suricata expectations

Wazuh and Suricata are not required for the synthetic demo path. They are
needed when evaluating real endpoint/security-event ingestion or real network
IDS telemetry. Neither is included in the current Docker demo foundation;
their deployment is an advanced integration task.

## Security and secrets

- Never commit `.env`, `.env.demo`, tokens, passwords, or operational
  credentials.
- Do not paste unredacted tokens or private telemetry into issues or logs.
- Rotate any credential immediately if it has been exposed.
- Keep default application and infrastructure ports bound to loopback where
  documented.
- Do not expose the local demo directly to the public Internet. Add proper
  authentication, TLS, network controls, secret management, and deployment
  hardening first.

## Useful commands cheat sheet

```bash
./ai-soc help
./ai-soc doctor
./ai-soc install --profile demo --dry-run
./ai-soc package-validate
./ai-soc demo-info
./ai-soc demo-validate
./ai-soc release-check
```

For the complete first-run sequence, see the
[External User Quickstart](../product/external-user-quickstart.md).
