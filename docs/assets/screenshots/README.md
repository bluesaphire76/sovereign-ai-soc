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

## v0.7 Coverage Gap

The current committed screenshot set predates several implemented v0.7 pages.
The next sanitized capture pass should add stable screenshots for:

- Advanced Incident Timeline and Investigation Graph;
- Recommended Playbooks and governed remediation proposals;
- AI Providers and AI Data Control;
- Semantic Memory and Operation History;
- Detection Control lifecycle/versioning;
- Loki platform logs and Qdrant semantic-memory dashboards.

Until those captures exist, the current user and architecture guides are the
source of truth for these views.
