# External User Quickstart

This page is for a first-time GitHub visitor who wants to understand what can
be evaluated safely without assuming a complete SOC deployment.

## What you can try

Sovereign AI SOC is a local-first, human-controlled security operations
prototype. The repository supports:

- a local readiness and validation workflow;
- synthetic demo incidents and cases;
- a Docker packaging foundation for the application and local AI services;
- AI-assisted investigation, reporting, and guidance when Ollama and a model
  are available.

The current packaging is not a production deployment or a one-command full SOC
installer. Synthetic demo records are not real security evidence, and AI output
does not replace analyst review.

## What you need

Mandatory for the documented preparation and validation path:

- Linux, Ubuntu, or WSL2 Ubuntu;
- Git;
- Python 3.12 or newer and `python3-venv`;
- Node.js and npm;
- Docker Engine and the Docker Compose plugin.

Optional or feature-dependent:

- Ollama and a local model for the full AI-assisted experience;
- a GPU for faster local inference—CPU execution is supported but slower;
- Wazuh for real host and endpoint security telemetry;
- Suricata for real network IDS telemetry;
- Grafana, Prometheus, Loki, and Alertmanager for extended observability.

Wazuh and Suricata are not required for the synthetic demo-data workflow.

## Fastest safe path

For a low-technical user on Ubuntu 24.04 LTS or newer, use the guided wrapper:

```bash
./install-demo.sh --check
./install-demo.sh --apply
./install-demo.sh --check-observability
./install-demo.sh --observability-plan
```

It checks prerequisites, prepares only repository-local dependencies, validates
Docker packaging, and explains the optional Grafana, Prometheus, Alertmanager,
cAdvisor, node-exporter, Loki, Grafana Alloy, and ntfy bridge setup. It never
starts containers or pulls models.

The existing technical path remains available:

Start with the installer plan and apply it only after reviewing the output:

```bash
git clone https://github.com/bluesaphire76/sovereign-ai-soc.git
cd sovereign-ai-soc
./ai-soc install --profile demo --dry-run
./ai-soc install --profile demo --apply
./ai-soc doctor
./ai-soc validate
./ai-soc package-validate
./ai-soc demo-info
./ai-soc demo-seed --dry-run
./ai-soc demo-seed --apply
./ai-soc demo-validate
./ai-soc demo-status
```

The installer prepares dependencies and local configuration but does not start
services, containers, or models. If the application systemd units are already
installed, review lifecycle changes before applying them:

```bash
./ai-soc demo-up --dry-run
./ai-soc demo-up --apply
./ai-soc demo-down --dry-run
./ai-soc demo-down --apply
```

These lifecycle commands manage only the API and frontend application layer.

## Docker packaging path

The Docker demo foundation includes:

- FastAPI backend;
- Next.js frontend;
- PostgreSQL;
- Qdrant;
- Ollama.

It does not currently include Wazuh, Suricata, Grafana, Prometheus, Loki, or
Alertmanager. Models are not pulled automatically.

Validate the packaging or explicitly build the local application images:

```bash
./ai-soc package-validate
./ai-soc package-validate --build
```

Validation does not start containers. The build option does not run them.

## Demo data boundary

Demo data is synthetic and must not be presented as real security evidence.
Inspect its ownership and counts before using or removing it:

```bash
./ai-soc demo-info
./ai-soc demo-reset --dry-run
./ai-soc demo-reset --apply
```

The reset targets only records owned by the stable demo marker and refuses
unsafe deletion when unrelated workflow data is attached.

## Validate before showing

Run the aggregated release check before a demo or release review:

```bash
./ai-soc release-check
./ai-soc release-check --write-report
```

The default command is read-only. Reports are written only when explicitly
requested and are ignored by Git.

## Where to go next

- [Installation and Demo Guide](../../INSTALL.md)
- [Ubuntu Guided Demo Installer](../operations/ubuntu-installer-guide.md)
- [Demo Guide](demo-guide.md)
- [Docker Demo Packaging](../operations/docker-demo-packaging.md)
- [Troubleshooting](../operations/troubleshooting.md)
- [Ports and Components](../operations/ports-and-components.md)
- [Product Overview](product-overview.md)
- [Architecture](../architecture/architecture.md)
