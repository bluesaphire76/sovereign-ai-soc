# Evaluation Guide

This guide helps external readers evaluate Sovereign AI SOC without assuming a
full production SOC deployment.

## What You Can Evaluate in 10 Minutes

With repository dependencies installed, you can review:

- documentation structure and release readiness;
- public validation commands;
- screenshots and product workflow;
- architecture boundaries;
- demo lifecycle commands in dry-run mode;
- synthetic demo readiness where local runtime services are available.

Recommended read-only checks:

```bash
./ai-soc doctor
./ai-soc validate
./ai-soc docs-validate
./ai-soc release-check --skip-runtime --skip-frontend-build --skip-pytest --skip-docker-build --json
```

## What Requires Local Services

Runtime validation needs local services such as the API, frontend, PostgreSQL
and optional observability stack:

```bash
./ai-soc validate-runtime
./ai-soc demo-validate
```

Warnings for optional services should be interpreted in context. Missing
Grafana or Alertmanager does not mean the core SOC workflow is unavailable.

## What Requires Wazuh or Suricata

Real endpoint and network telemetry evaluation requires Wazuh and Suricata
sources. Synthetic demo data can show the workflow shape, but it does not prove
coverage for a live environment.

## What Requires Local AI Runtime

Deterministic workflows remain available without a model runtime. The full
AI-assisted experience requires a configured local provider:

- Ollama remains the default local path.
- llama.cpp is an optional local provider path with router/profile support.
- External providers are optional, disabled by default and governed by policy.

Model downloads and runtime startup are explicit operator actions, not
installer side effects.

## What Requires Qdrant Data

Qdrant-backed features need both a reachable Qdrant service and populated
collections. Reachability alone is not enough for useful semantic memory.

For playbook indexing:

```bash
PYTHONPATH=. .venv/bin/python scripts/reindex_qdrant_playbooks.py --dry-run
PYTHONPATH=. .venv/bin/python scripts/reindex_qdrant_playbooks.py --apply
PYTHONPATH=. .venv/bin/python scripts/validate_qdrant_playbook_expansion.py
```

## Proposal-Only and Human-Approved Areas

The platform intentionally does not perform autonomous destructive response.
Firewall, EDR, identity, ticketing and external SOAR integrations remain
disabled/proposal-only unless a separate governed connector is implemented and
explicitly approved.

## Recommended Demo Narrative

1. Start with Dashboard or Executive posture.
2. Open an incident and explain deterministic correlation.
3. Review AI Command Brief, evidence boundaries and provider metadata.
4. Show timeline, graph and Recommended Playbooks.
5. Explain Qdrant as advisory memory.
6. Review governed remediation as proposal/approval workflow.
7. Open Detection Control, AI Data Control, AI Providers and Health.
8. Close with reports, Security Audit and release validation output.

## Safe Validation Commands

```bash
git diff --check
./ai-soc docs-validate
.venv/bin/python scripts/validate_docs_structure.py
python3 scripts/validate_public_ci_baseline.py
./ai-soc validate
```

## How to Report Issues or Contribute

Use [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution expectations and
[SECURITY.md](../../SECURITY.md) for private vulnerability reporting. Include
validation commands, environment boundaries and redacted logs when reporting
issues.
