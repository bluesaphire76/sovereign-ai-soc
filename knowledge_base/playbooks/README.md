# AI SOC Playbook Knowledge Base

## Purpose

This directory contains incident-specific SOC playbooks intended to improve Qdrant-backed Recommended Playbooks, AI analysis context, and incident detail guidance.

The playbooks are written for analysts. They should help answer:

- why a playbook applies to a specific incident;
- what evidence is required before decisions are made;
- what the analyst should check first;
- which related signals should be correlated;
- when the activity may be benign;
- when escalation, containment, remediation, or closure is appropriate.

## How Qdrant and RAG Use These Files

Qdrant indexes Markdown content recursively from the configured knowledge base path. These files are designed to be retrieved as semantic context for incident-specific recommendations.

Recommended Playbooks must remain advisory. A retrieved playbook can suggest review paths, evidence requirements, and analyst actions, but it must not decide severity, apply containment, approve closure, suppress detections, or replace deterministic SOC controls.

## Indexing and Exclusion Strategy

The Qdrant indexing job includes operational Markdown documents from `knowledge_base/` and nested playbook categories such as `knowledge_base/playbooks/authentication/`.

The indexing job excludes these locations and files by design:

- `archive/`, `_archive/`, `legacy/`, `_legacy/`, `excluded/`, `_excluded/` - retired or intentionally disabled documents;
- `_templates/` - authoring templates, not analyst guidance;
- `README.md` - documentation for maintainers, not incident guidance.

Use `knowledge_base/archive/legacy_playbooks/` for older broad playbooks that should remain available for review but should not influence recommended playbook retrieval after a clean Qdrant reindex.

When changing the active playbook set, run a clean rebuild instead of a non-destructive upsert so old vectors are removed:

```bash
PYTHONPATH=. .venv/bin/python scripts/reindex_qdrant_playbooks.py --dry-run
PYTHONPATH=. .venv/bin/python scripts/reindex_qdrant_playbooks.py --apply
```

The selective playbook reindex removes and replaces only playbook points. It preserves historical, Detection Control and Case Closure semantic memory.

After a full collection recreate, historical incident memory must be re-applied:

```bash
PYTHONPATH=. .venv/bin/python scripts/index_historical_incidents_to_qdrant.py \
  --apply --include-open --limit 10000
```

Validate indexed metadata and representative retrieval scenarios with:

```bash
PYTHONPATH=. .venv/bin/python scripts/validate_qdrant_playbook_expansion.py
```

## Directory Structure

Current playbook categories:

- `authentication/` - SSH, sudo, login and account-compromise investigations.
- `linux_host/` - Linux host activity such as packages, services and persistence.
- `windows_host/` - Windows authentication, account, execution, persistence, lateral movement and defense-evasion activity.
- `network_suricata/` - Suricata IDS, network intrusion and reconnaissance playbooks.
- `dns/` - DNS beaconing, tunneling and suspicious DNS behavior.
- `malware/` - suspicious process, script, encoded command, reverse shell and downloaded payload execution.
- `data_exfiltration/` - suspicious outbound connections, data transfers, rare destinations and DNS exfiltration.
- `governance/` - Analyst decision-support and false-positive classification.
- `_templates/` - reusable authoring templates.

Windows host playbooks are intended for Windows security telemetry ingested through Wazuh, Windows Event Log, Sysmon where available, or future endpoint telemetry integrations. They are used as retrieval context for LLM-generated Recommended Playbooks and do not replace analyst approval.

Related future knowledge areas may live under:

- `knowledge_base/policies/`
- `knowledge_base/tuning/`

## Metadata Requirements

Every playbook must start with YAML front matter and include these fields:

```yaml
---
title:
type: playbook
domain:
source:
incident_types:
severity_hint:
mitre_tactics:
mitre_techniques:
applicability:
not_applicable_when:
recommended_for_pages:
tags:
---
```

Use `recommended_for_pages` with at least:

```yaml
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
```

## Required Playbook Sections

Every playbook must use the same section structure:

```markdown
# Title

## Purpose

## When to Use

## Detection Signals

## Initial Triage

## Evidence to Collect

## Investigation Steps

## Correlation Checks

## False Positive Conditions

## Escalation Criteria

## Containment Actions

## Remediation Actions

## Closure Criteria

## Analyst Notes
```

## Naming Convention

Use lowercase, descriptive filenames with underscores:

```text
<domain>/<incident_type>_playbook.md
```

Examples:

- `authentication/ssh_bruteforce_investigation_playbook.md`
- `dns/dns_c2_beaconing_playbook.md`
- `network_suricata/suricata_port_scan_playbook.md`

## Authoring Rules

- Playbooks must be incident-specific, not generic.
- Avoid reusable boilerplate as the main content.
- Prefer concrete SOC language over vague instructions.
- Include observable signals, evidence requirements and decision points.
- Include false-positive conditions and closure criteria.
- Write for the analyst working the incident detail page.
- Keep playbooks readable, sectioned, and suitable for semantic retrieval.

Avoid vague wording such as:

- investigate further;
- check logs;
- take appropriate action.

Prefer specific wording such as:

- review the authentication timeline for the affected user;
- confirm whether the source IP belongs to an approved administrator, VPN, scanner, or monitoring platform;
- correlate the successful login with sudo activity, new process execution, package installation, systemd service changes, and outbound network connections.

## Governance Rules

- Deterministic SOC decisions remain outside Qdrant.
- Qdrant supports recommendations only.
- Qdrant must not automatically approve containment, closure, severity changes, detection exceptions, or suppression.
- Human-in-the-loop review remains mandatory.
- Auditability remains mandatory.
- RBAC and approval workflows remain authoritative.
- Retrieved context must be validated against current incident evidence.

## Current Categories

The initial incident-specific playbook set covers:

- SSH brute force;
- SSH success after failures;
- sudo privilege escalation;
- suspicious package activity;
- suspicious systemd service changes;
- Suricata high severity alerts;
- Suricata port scan activity;
- DNS command-and-control beaconing;
- DNS tunneling;
- Windows authentication, account, PowerShell, persistence, lateral movement and security-control events;
- suspicious malware and script execution;
- suspicious outbound traffic and data exfiltration;
- false-positive classification.

## Future Expansion

Future playbooks should be added when the SOC has a recurring incident type, a known validation workflow, or a useful investigation pattern that can be expressed as concrete analyst guidance.

Recommended future categories include:

- endpoint process execution;
- file integrity monitoring;
- vulnerability findings;
- cloud identity;
- endpoint isolation governance;
- detection tuning and exceptions.
