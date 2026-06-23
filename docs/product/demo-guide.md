# Demo Guide

This guide helps present Sovereign AI SOC as a local-first, AI-assisted SOC platform.
For dependency installation and environment preparation, start with the
[Installation and Demo Guide](../../INSTALL.md).
First-time evaluators can use the
[External User Quickstart](external-user-quickstart.md); common failures are
covered in [Troubleshooting](../operations/troubleshooting.md).

## Demo Objective

Show how the platform turns host, network and contextual telemetry into
correlated incidents, governed AI analysis, semantic playbook guidance,
investigation views, case workflow and executive-ready reporting while keeping
local AI as the default and every operational decision human-controlled.

## Prerequisites

- Demo data or live lab telemetry is available.
- Wazuh and Suricata sources are configured if those screens are part of the demo.
- Ollama/local AI runtime is reachable for the strongest default demo.
- If an external provider is demonstrated, use a non-sensitive synthetic
  scenario and verify AI Data Control first.
- Health page is clean enough for presentation.
- Browser is using the dark enterprise UI with a desktop-sized viewport.
- No secrets, tokens or private operational data are visible.

## Pre-Demo Readiness

For the guided Ubuntu path:

```bash
./install-demo.sh --check
./install-demo.sh --apply
./install-demo.sh --observability-plan
./ai-soc demo-info
./ai-soc demo-validate
```

Observability is optional for the synthetic demo, but Grafana, Prometheus,
Alertmanager, cAdvisor, node-exporter, Loki, and Grafana Alloy provide a
stronger product demonstration when they have been started and validated
manually.

Use this short pre-demo checklist after the application layer is available:

```bash
./ai-soc release-check
./ai-soc demo-info
./ai-soc demo-validate
./ai-soc demo-status
```

The repository now provides three lightweight validation layers for preparing a demo:

1. **Public CI foundation** validates backend tests and Python syntax, the frontend production build and public Docker Compose configuration syntax on GitHub Actions.
2. **AI SOC Doctor** checks the local development tools, repository files and optional runtime endpoints without starting, stopping or modifying services.
3. **Local CLI wrapper** provides a stable root-level interface for the doctor and public CI baseline validation.

Run the local checks from the repository root:

```bash
./ai-soc doctor --strict
./ai-soc validate
./ai-soc validate-runtime
./ai-soc demo-seed --dry-run
./ai-soc demo-info
./ai-soc demo-validate
./ai-soc demo-status
./ai-soc demo-up --dry-run
./ai-soc demo-down --dry-run
./ai-soc release-check
./ai-soc version
```

The doctor exits successfully when required checks pass. Optional local services such as Ollama, PostgreSQL, Qdrant, Grafana or Prometheus may report `WARN` when unavailable without failing the readiness check.

The runtime validator is read-only. The demo seed is synthetic, defaults to a
dry run, and writes only when `./ai-soc demo-seed --apply` is explicitly used.
After seeding, `./ai-soc demo-validate` checks runtime, synthetic records and
report readiness without modifying the database. Add `--write-report` only
when a local validation artifact under `reports/validation/` is useful.
The lifecycle status command is read-only, while up, down and restart use
dry-run mode unless `--apply` is explicitly provided. These commands control
only the API and frontend application services; use `--include-worker` only
when that optional unit is installed and intended for the demo.
Use `demo-up --apply` or `demo-down --apply` only after reviewing the dry-run
plan. Seeded demo records remain synthetic and must never be presented as real
security evidence.

Ollama and a configured local model provide the strongest AI-assisted demo
experience. Without them, deterministic workflows and fallback behavior remain
available but AI analysis will be degraded. If any readiness command fails,
follow the [Troubleshooting Guide](../operations/troubleshooting.md).

As the final pre-demo or pre-release gate, run `./ai-soc release-check`. It
aggregates the safe dry-run, packaging, demo, test, build, Compose and
documentation checks without changing services or demo data. Add
`--write-report` only when an ignored local readiness artifact is needed.

Before presenting, verify the explicit demo boundary:

```bash
./ai-soc demo-info
```

For a controlled reset and reseed:

```bash
./ai-soc demo-reset --dry-run
./ai-soc demo-reset --apply
./ai-soc demo-seed --apply
./ai-soc demo-validate
```

The reset applies only to stable-marker-owned synthetic records and refuses to
remove records with unrecognized analyst or workflow dependencies.

Before presenting, also confirm that the latest [Public CI workflow](https://github.com/bluesaphire76/sovereign-ai-soc/actions/workflows/ci.yml) is green for the revision being demonstrated.

## Recommended Demo Path

1. **Dashboard**: introduce SOC posture, active risk and operational density.
2. **Executive Dashboard**: show management-ready summary and decision framing.
3. **Incidents**: explain that not every alert becomes an incident.
4. **Incident Detail**: open a correlated incident and review the Incident Command Room.
5. **AI Command Brief**: explain provider/model visibility, situation summary,
   risk rationale, evidence and fallback behavior.
6. **Advanced Timeline and Investigation Graph**: show sequence and
   relationships without presenting graph edges as proof.
7. **Recommended Playbooks**: show Qdrant retrieval, platform-aware relevance,
   evidence checks and human-approval boundaries.
8. **Correlation Visualization**: show why deterministic policy created the incident.
9. **Network/DNS Context**: show Suricata or DNS context where available,
   emphasizing non-causal DNS wording.
10. **Governed Remediation**: create or review a proposal and explain why
    external/high-risk actions remain proposal-only.
11. **Detection Control Plane**: show inventory, lifecycle, versioning,
    exceptions/noise operations and semantic context.
12. **Cases**: show ownership, SLA, closure readiness, graph and semantic closure context.
13. **AI Providers / AI Data Control / Semantic Memory**: show governance
    state, not secret values.
14. **Health and Operation History**: show provider, Qdrant, worker, ingest,
    Alertmanager and governed operations visibility.
15. **Grafana Observability**: show metrics, Wazuh backlog alerts, Loki logs and
    Qdrant dashboards when the optional stack is running.
16. **Reports, Security Audit and Users**: close with local exports, RBAC and accountability.

## Talking Points

### Local-first and Governed AI

- AI analysis runs through local Ollama by default.
- Sensitive security data does not require a mandatory external AI provider.
- External providers are disabled by default and require provider allowlists,
  data policy, redaction and role authorization.
- AI outputs are structured for review and fallback behavior keeps workflows resilient.

### Semantic Memory

- Qdrant retrieves local playbooks, historical incidents and governed
  operational memory.
- Retrieved context is advisory and clearly separated from current evidence.
- Platform/type filters prevent cross-platform playbook spillover.
- Semantic similarity never decides severity, closure, suppression or response.

### Human-in-the-loop

- AI recommends and explains.
- Analysts validate and act.
- Incident status, case closure and operational response remain human-controlled.

### Wazuh and Suricata

- Wazuh contributes host and endpoint security context.
- Suricata contributes network IDS visibility.
- The product normalizes both into a SOC workflow rather than mixing all events into one flat alert list.

### Correlation-first Incident Creation

- Raw events and alerts are retained.
- Suppression and aggregation reduce noise.
- Correlation determines whether a signal deserves an incident.
- Correlation Visualization explains the decision.

### Reports and Evidence Packs

- Reports are locally generated.
- Executive reports stay concise.
- Evidence packs include technical appendix material.
- DNS context is labeled as contextual telemetry, not root cause evidence.

## Troubleshooting

Before a demo:

```bash
./ai-soc doctor --strict
./ai-soc validate

sudo systemctl status ai-soc-api --no-pager
sudo systemctl status ai-soc-frontend --no-pager
```

Check the Health page for:

- API status.
- Database connectivity.
- AI runtime.
- Worker backlog.
- Wazuh and Suricata/network freshness.
- Qdrant collection state and AI provider health.
- Grafana, Prometheus and Alertmanager reachability when expected.

Review DNS telemetry on its dedicated page; it is not currently a separate
Health component.

If AI is unavailable, use the fallback behavior as a product talking point: deterministic workflows still work and AI outages do not stop incident review.
