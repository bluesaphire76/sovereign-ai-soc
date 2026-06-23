# Ubuntu Guided Demo Installer

This guide is the detailed, low-technical path for preparing a Sovereign AI SOC
demo checkout on Ubuntu.

## Supported target

The tested target is Ubuntu 24.04 LTS or newer, on Ubuntu Server or Ubuntu
Desktop. This is not a production deployment installer, generic-Linux support
claim, WSL-specific installer, cloud installer, Kubernetes installer, or
package-manager replacement.

## What the installer does

`install-demo.sh`:

- checks Ubuntu, Python, Node.js, Docker, and Docker Compose prerequisites;
- explains missing Ubuntu packages without installing them;
- delegates repo-local Python, frontend, and environment preparation to the
  existing safe installer;
- validates the Docker packaging foundation;
- detects Grafana, Prometheus, Alertmanager, cAdvisor, node-exporter, Loki,
  Grafana Alloy, and the ntfy bridge;
- validates observability Compose configuration where local files permit it;
- prints safe manual next steps.

## What it never does automatically

The installer never:

- invokes `sudo`, `apt`, `usermod`, `newgrp`, or systemd start/stop/restart;
- runs Docker Compose up/down or starts containers;
- pulls an Ollama model;
- seeds or resets demo data;
- creates notification secrets;
- exposes Grafana or any dashboard publicly.

Privileged and runtime-changing commands may be displayed as clearly labelled
manual guidance, but they are never executed.

## Quick start

From the repository root:

```bash
./install-demo.sh --check
./install-demo.sh --apply
./install-demo.sh --check-observability
./install-demo.sh --observability-plan
./ai-soc demo-info
./ai-soc demo-seed --apply
./ai-soc demo-validate
./ai-soc release-check
```

The default `./install-demo.sh` behavior is the read-only `--check` mode.
Review the output before using `--apply`.

## Installer modes

| Mode | Behavior |
|---|---|
| `--check` | Read-only prerequisite, packaging, demo-readiness, and observability checks. |
| `--apply` | Repository-local dependency and environment preparation, followed by safe validation. |
| `--repair` | Read-only diagnostic reruns and targeted manual guidance. |
| `--check-observability` | Read-only observability file and Compose validation. |
| `--observability-plan` | Prints components, ports, validation commands, and manual start guidance without executing commands. |
| `--json` | Adds machine-readable output to the selected mode. |
| `--non-interactive` | Explicitly disables prompts; the installer is non-interactive by default. |

`--apply` does not seed demo records. The explicit follow-up remains:

```bash
./ai-soc demo-seed --apply
```

## Common missing prerequisites

### Python and virtual environments

Python 3.12 or newer is required. If Python, venv, or pip support is missing,
the installer prints the Ubuntu package commands to run manually. It does not
invoke `apt`.

### Node.js

Node.js 20 or newer and npm are required for the frontend build. Install a
supported Node.js 20+ release using your preferred Ubuntu-compatible method;
the installer does not run external bootstrap scripts.

### Docker Engine and Compose

Docker Engine and the Docker Compose plugin must be installed, and the current
user must be able to reach the daemon. If access fails, the installer prints
manual service and Docker-group guidance. Group changes may require logout and
login. The installer never runs `sudo`, `usermod`, or `newgrp`.

### Ollama

Ollama is optional for basic deterministic demo workflows and required for the
full local AI-assisted experience. A GPU is optional; CPU inference is
supported but slower. Models are selected and downloaded manually.

## Observability stack

The repository contains:

- Grafana dashboards;
- Prometheus metrics and rules;
- Alertmanager routing;
- cAdvisor container metrics;
- node-exporter host metrics;
- Loki log storage;
- Grafana Alloy log collection;
- an optional ntfy bridge.

The installer detects these components and validates configuration where safe.
It does not start containers or expose dashboards. The full observability
Compose file may require the intentionally untracked
`deploy/observability/ntfy-bridge/.env`.

Safe manual validation:

```bash
docker compose -f deploy/observability/docker-compose.loki.yml config --quiet
docker compose -f deploy/observability/docker-compose.yml config --quiet
```

Manual start—review local environment files and security boundaries first:

```bash
docker compose -f deploy/observability/docker-compose.yml up -d
```

The installer only displays that start command. It never executes it.

Default local endpoints, when the relevant stack is started, include Grafana
on `127.0.0.1:3002`, Prometheus on `127.0.0.1:9090`, Alertmanager on
`127.0.0.1:9093`, cAdvisor on `127.0.0.1:8082`, node-exporter on
`127.0.0.1:9100`, Loki on `127.0.0.1:3100`, Alloy on `127.0.0.1:12345`, and
the ntfy bridge on `127.0.0.1:8011`.

## After successful preparation

```bash
./ai-soc demo-info
./ai-soc demo-seed --dry-run
./ai-soc demo-seed --apply
./ai-soc demo-validate
./ai-soc demo-reset --dry-run
./ai-soc release-check
./install-demo.sh --observability-plan
```

Demo data is synthetic and is not real security evidence. Reset only
marker-owned demo records through the provided dry-run-first command.

## Further help

- [Installation and Demo Guide](../../INSTALL.md)
- [Troubleshooting](troubleshooting.md)
- [Docker Demo Packaging](docker-demo-packaging.md)
- [Demo Guide](../product/demo-guide.md)
