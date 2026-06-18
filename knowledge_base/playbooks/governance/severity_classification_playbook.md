---
title: Severity Classification Playbook
type: playbook
domain: governance
source: internal_policy
incident_types:
  - severity_classification
  - incident_priority_review
  - risk_classification
severity_hint:
  - low
  - medium
  - high
  - critical
mitre_tactics: []
mitre_techniques: []
applicability:
  - Current severity conflicts with observed evidence or business impact
  - New correlation changes confidence, affected scope, or attack stage
  - Incident involves privileged identity, critical asset, lateral movement, or data exposure
  - Detection confidence is weak and severity may be overstated
not_applicable_when:
  - High-confidence detection affects a non-production test asset with no impact
  - Broad rule overstates risk and evidence supports a lower classification
  - Approved activity is fully validated but still requires documented closure
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - governance
  - severity
  - risk
  - human-review
  - decision-support
---

# Severity Classification Playbook

## Purpose

This playbook supports consistent analyst classification of incident severity using evidence, asset criticality, confidence, scope, and potential impact.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Current severity conflicts with observed evidence or business impact
- New correlation changes confidence, affected scope, or attack stage
- Incident involves privileged identity, critical asset, lateral movement, or data exposure
- Detection confidence is weak and severity may be overstated
- Use when the current incident evidence specifically supports analyst review of incident severity using evidence, asset criticality, confidence, scope, and potential impact.

## Detection Signals

- Current severity conflicts with observed evidence or business impact
- New correlation changes confidence, affected scope, or attack stage
- Incident involves privileged identity, critical asset, lateral movement, or data exposure
- Detection confidence is weak and severity may be overstated
- Case workflow requires a documented severity rationale

## Initial Triage

- Confirm the current severity, confidence, rationale, affected entities, and decision owner.
- Separate observed facts from assumptions, model output, retrieved context, and unverified impact.
- Determine whether activity is active, contained, expanding, or already resolved.
- Validate asset criticality, identity privilege, data sensitivity, business service impact, and affected scope.
- Record evidence gaps and obtain required owner or specialist input before changing severity.

## Evidence to Collect

- Raw detection, correlated telemetry, and evidence confidence
- Affected assets, identities, data, business services, and criticality
- Attack stage, scope, persistence, containment status, and observed impact
- Known gaps, contradictory evidence, and alternative benign explanations
- Analyst rationale, reviewer, timestamp, and applicable policy matrix

## Investigation Steps

1. Build a timestamp-normalized timeline of detections, confirmed actions, impact, and response decisions.
2. Preserve and verify the primary evidence: Raw detection, correlated telemetry, and evidence confidence.
3. Map the evidence to affected identities, assets, data, attack stage, scope, and business services.
4. Determine whether the activity matches an approved baseline or this specific benign condition: High-confidence detection affects a non-production test asset with no impact.
5. Review the additional technical indicator: Incident involves privileged identity, critical asset, lateral movement, or data exposure.
6. Correlate the event with related incidents and cases for the same entities and authentication, endpoint, network, dns, persistence, and exfiltration evidence.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Record the final severity, confidence, evidence, approver, contradictory facts, and review trigger; do not infer approval from retrieval context.

## Correlation Checks

- Related incidents and cases for the same entities
- Authentication, endpoint, network, DNS, persistence, and exfiltration evidence
- Asset inventory, vulnerability, data classification, and business ownership
- Historical outcomes as supporting context rather than proof
- Current containment and recovery state

## False Positive Conditions

- High-confidence detection affects a non-production test asset with no impact
- Broad rule overstates risk and evidence supports a lower classification
- Approved activity is fully validated but still requires documented closure
- Duplicate events are already represented by an authoritative case
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Confirmed compromise affects critical assets, privileged accounts, or regulated data
- Scope expands, persistence is present, or attacker access remains active
- Evidence supports lateral movement, command-and-control, or exfiltration
- Policy threshold requires management, legal, privacy, or incident-response escalation
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Do not initiate containment solely from a severity label
- Route urgent defensive options through the local containment approval workflow
- Record the approving analyst and evidence for any emergency action
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Correct missing asset, identity, and data context that distorted classification
- Update the incident rationale and linked case without overwriting audit history
- Create follow-up actions for evidence gaps or policy exceptions
- Review detection enrichment when recurring incidents are misclassified
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of analyst review of incident severity using evidence, asset criticality, confidence, scope, and potential impact are established and documented.
- The analyst collected and reviewed the required evidence, including raw detection, correlated telemetry, and evidence confidence.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports analyst review of incident severity using evidence, asset criticality, confidence, scope, and potential impact; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
