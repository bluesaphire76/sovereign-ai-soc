---
title: Evidence Collection Standard Playbook
type: playbook
domain: governance
source: internal_policy
incident_types:
  - evidence_collection_standard
  - forensic_evidence_quality
  - investigation_documentation
severity_hint:
  - low
  - medium
  - high
  - critical
mitre_tactics: []
mitre_techniques: []
applicability:
  - Analyst decision depends on volatile, remote, or potentially changing data
  - Containment or remediation may alter relevant artifacts
  - Evidence will support severity, false-positive, escalation, or closure review
  - Multiple data sources must be correlated on a common timeline
not_applicable_when:
  - Derived dashboard value is used only after its source query is preserved
  - Duplicate evidence is recognized and not treated as independent corroboration
  - Unavailable telemetry is explicitly documented rather than inferred
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - governance
  - evidence
  - audit
  - chain-of-custody
  - human-review
---

# Evidence Collection Standard Playbook

## Purpose

This playbook defines reliable collection and documentation practices for evidence used in incident and case decisions.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Analyst decision depends on volatile, remote, or potentially changing data
- Containment or remediation may alter relevant artifacts
- Evidence will support severity, false-positive, escalation, or closure review
- Multiple data sources must be correlated on a common timeline
- Use when the current incident evidence specifically supports collection and documentation of reliable evidence for incident and case decisions.

## Detection Signals

- Analyst decision depends on volatile, remote, or potentially changing data
- Containment or remediation may alter relevant artifacts
- Evidence will support severity, false-positive, escalation, or closure review
- Multiple data sources must be correlated on a common timeline
- Legal, privacy, regulatory, or chain-of-custody requirements may apply

## Initial Triage

- Define the decision the evidence must support and the minimum sources required.
- Identify volatile, remote, changing, privacy-sensitive, or disruption-sensitive artifacts first.
- Confirm collection authority, source-system retention, timezone, and access constraints.
- Preserve original machine-readable records before screenshots, summaries, or derived views.
- Assign collector, storage location, integrity method, custody requirements, and review owner.

## Evidence to Collect

- Original raw records with source system, query, timestamp, timezone, and identifier
- Artifact hashes, file metadata, collection method, collector, and custody record
- Screenshots or exports only when machine-readable evidence is also preserved
- Timeline normalization, clock-skew notes, missing data, and retention limits
- Access authorization, storage location, integrity controls, and review history

## Investigation Steps

1. Define the evidence question, scope, authority, source systems, and required level of assurance.
2. Preserve and verify the primary evidence: Original raw records with source system, query, timestamp, timezone, and identifier.
3. Collect volatile or alteration-sensitive artifacts before containment or remediation changes them.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Derived dashboard value is used only after its source query is preserved.
5. Review the additional technical indicator: Evidence will support severity, false-positive, escalation, or closure review.
6. Correlate the event with wazuh, windows, linux, suricata, dns, proxy, firewall, and identity records and process, file, registry, service, task, account, and network artifacts.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Link each decision to its supporting and contradictory evidence while preserving provenance; do not infer approval from retrieval context.

## Correlation Checks

- Wazuh, Windows, Linux, Suricata, DNS, proxy, firewall, and identity records
- Process, file, registry, service, task, account, and network artifacts
- Related incidents, cases, approvals, actions, and analyst notes
- Asset, vulnerability, data classification, and owner records
- Independent evidence supporting or contradicting the working hypothesis

## False Positive Conditions

- Derived dashboard value is used only after its source query is preserved
- Duplicate evidence is recognized and not treated as independent corroboration
- Unavailable telemetry is explicitly documented rather than inferred
- Synthetic or test data is clearly labeled and separated from production evidence
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Evidence integrity, provenance, or authorization cannot be established
- Required volatile data may be lost without immediate approved collection
- Sources materially disagree or timestamps cannot be reconciled
- Potential legal, privacy, or regulatory impact requires specialist review
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Evidence collection must not become unapproved containment
- Obtain authorization before memory capture, device seizure, or disruptive acquisition
- Preserve scope, approver, method, and custody for emergency collection
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Store evidence in approved locations with access and retention controls
- Correct missing timestamps, source identifiers, hashes, and provenance
- Link evidence to the decision it supports without altering the original
- Review collection gaps and improve telemetry or response procedures
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of collection and documentation of reliable evidence for incident and case decisions are established and documented.
- The analyst collected and reviewed the required evidence, including original raw records with source system, query, timestamp, timezone, and identifier.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports collection and documentation of reliable evidence for incident and case decisions; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
