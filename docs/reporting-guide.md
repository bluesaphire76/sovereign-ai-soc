# Reporting Guide

Sovereign AI SOC includes local report and export generation for analyst, case and executive workflows.

## Report Types

| Report | Audience | Purpose |
|---|---|---|
| Incident report | Analyst / SOC lead | Explain incident overview, AI analysis, evidence, notes, audit and technical appendix. |
| Case report | Analyst / manager | Summarize case state, linked incidents, action plan, AI case analysis and closure governance. |
| Analyst evidence pack | Analyst / reviewer | Preserve technical evidence, timeline, notes, audit and raw appendix material. |
| Executive report / PDF | Management | Provide concise risk posture and executive-ready recommendations. |

## Incident Report

Incident reports include:

- Executive Summary.
- Incident Overview.
- AI Analysis / Incident AI Brief.
- Evidence Overview.
- DNS Context where available.
- Network evidence where available.
- Analyst Notes.
- Audit Trail.
- Technical Appendix.

Raw JSON is placed in the appendix rather than at the top of the report.

## Case Report

Case reports include:

- Executive Case Summary.
- Case Overview.
- Linked Incidents.
- AI Case Analysis.
- Action Plan.
- Closure Governance.
- Notes and Audit.
- DNS context around linked incidents where available, using non-causal wording.

## Analyst Evidence Pack

Evidence packs include more technical detail:

- Evidence Summary.
- Timeline / relevant events.
- AI reasoning.
- Analyst notes.
- Audit trail.
- Contextual DNS Telemetry.
- Network evidence.
- Raw Wazuh alert.
- Correlation summary.
- MITRE metadata.

DNS sections must say:

> DNS context is matched by host/client IP and selected time window only. It does not imply causal correlation with the incident.

## Executive Reports

Executive reports remain concise:

- They summarize posture, risk and recommended decisions.
- They avoid raw technical dumps.
- DNS is summarized as context availability only when appropriate.
- No causal relationship is inferred from DNS context alone.

## Export Naming

Report export naming is designed to be professional and predictable, such as:

- `incident-000123-enterprise-report.md`
- `incident-000123-evidence-pack.md`
- `case-000045-enterprise-report.md`
- `case-000045-evidence-pack.md`
- `executive-ai-soc-report-YYYY-MM-DD.pdf`

## Local Storage

Generated reports are local artifacts and may contain sensitive security data. Do not commit generated reports or report directories unless a sanitized example is intentionally added.
