# Screenshot Checklist

This folder contains the product screenshots used by the Sovereign AI SOC README and project documentation.

## Screenshot inventory

| # | Screenshot | Purpose |
|---:|---|---|
| 01 | [Primary Dashboard](01-primary-dashboard.png) | Main dashboard and product landing view |
| 02 | [Incidents Workbench](02-incidents-workbench.png) | Incident queue and analyst workbench |
| 03 | [Incident AI Analysis](03-incident-ai-analysis.png) | AI-assisted incident analysis |
| 04 | [Incident AI Situation Brief](04-incident-ai-situation-brief.png) | Executive/situation summary for an incident |
| 05 | [Incident Correlation Timeline / Attack Chain](05-incident-correlation-timeline-attack-chain.png) | Correlation, timeline and attack-chain view |
| 06 | [Incident Details Control Room](06-incident-details-control-room.png) | Incident detail operational view |
| 07 | [Incident Remediation Governance](07-incident-remediation-governance.png) | Remediation governance and human approval |
| 08 | [Case Kanban SLA Workflow](08-case-kanban-sla-workflow.png) | Case workflow, SLA and ownership view |
| 09 | [Detection Quality Validation](09-detection-quality-validation.png) | Detection quality and validation view |
| 10 | [Detection Control Plane](10-detection-control-plane.png) | Detection control plane overview |
| 11 | [Detection Control Plane Inventory](11-detection-control-plane-inventory.png) | Detection inventory and configuration view |
| 12 | [Incident Technical Evidence](12-incident-technical-evidence.png) | Technical evidence and supporting details |
| 13 | [Platform Health Components](13-platform-health-components.png) | Health page component status |
| 14 | [Grafana AI SOC Observability Foundation](14-grafana-ai-soc-observability-foundation.png) | Grafana observability overview |
| 15 | [Grafana AI SOC Observability Health](15-grafana-ai-soc-observability-health.png) | Grafana health/observability detail |
| 16 | [Platform Health Overall](16-platform-health-overall.png) | Overall platform health view |

## Maintenance checklist

When screenshots are updated:

- keep filenames stable when possible, so README links remain valid;
- add new screenshots with a numeric prefix;
- update this inventory when adding or removing screenshots;
- verify local Markdown links before committing;
- avoid committing temporary captures, drafts or large duplicate images.

## v0.7.1 Capture Plan

The current committed screenshot set is useful but still predates several
v0.7.x and v0.7.1 surfaces. The next sanitized capture pass should add stable
screenshots for:

- AI Providers showing Ollama plus llama.cpp provider/profile metadata;
- AI Data Control policy and redaction preview;
- Semantic Memory with source counts, index freshness and Qdrant health;
- Operation History;
- Advanced Incident Timeline;
- Investigation Graph;
- Recommended Playbooks;
- Detection Control lifecycle and versioning;
- Health page with provider, fallback and Qdrant state;
- Grafana Qdrant Semantic Memory dashboard;
- Loki Platform Logs Overview;
- HTTPS-first internal platform access where visually useful.

Do not claim these screenshots exist until the PNG files are committed and this
inventory is updated. Until then, the current user, architecture and operations
guides are the source of truth for these views.
