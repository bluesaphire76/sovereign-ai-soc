---
title: Case Escalation Playbook
type: playbook
domain: governance
source: internal_policy
incident_types:
  - case_escalation
  - incident_to_case
  - multi_incident_investigation
severity_hint:
  - medium
  - high
  - critical
mitre_tactics: []
mitre_techniques: []
applicability:
  - Multiple incidents share host, user, source, destination, technique, or timeline
  - Investigation requires coordinated actions, ownership, or extended evidence collection
  - Potential compromise involves critical assets, privileged accounts, or material impact
  - Containment, legal, privacy, management, or cross-team decisions are required
not_applicable_when:
  - Duplicate alert is already governed by an active case
  - Single low-impact incident has complete evidence and no broader scope
  - Approved benign activity is fully validated with no unresolved risk
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - governance
  - case
  - escalation
  - workflow
  - human-review
---

# Case Escalation Playbook

## Purpose

This playbook supports the analyst decision to escalate one or more related incidents into a governed investigation case.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Multiple incidents share host, user, source, destination, technique, or timeline
- Investigation requires coordinated actions, ownership, or extended evidence collection
- Potential compromise involves critical assets, privileged accounts, or material impact
- Containment, legal, privacy, management, or cross-team decisions are required
- Use when the current incident evidence specifically supports decision to escalate one or more incidents into a governed investigation case.

## Detection Signals

- Multiple incidents share host, user, source, destination, technique, or timeline
- Investigation requires coordinated actions, ownership, or extended evidence collection
- Potential compromise involves critical assets, privileged accounts, or material impact
- Containment, legal, privacy, management, or cross-team decisions are required
- Incident cannot be resolved safely within a single alert workflow

## Initial Triage

- Identify all candidate incidents, shared entities, timeline relationships, current owners, and existing cases.
- State why a single-incident workflow is insufficient for scope, coordination, evidence, or approval needs.
- Determine whether activity remains active and whether immediate response decisions are pending.
- Check for an authoritative existing case before creating duplicate ownership.
- Define the proposed case objective, initial scope, priority, owner, and required participants.

## Evidence to Collect

- Incident list, correlation rationale, timeline, entities, and evidence references
- Affected asset and identity ownership, criticality, and business impact
- Current severity, confidence, scope, containment state, and open questions
- Required teams, approvals, communications, and decision deadlines
- Case owner, reviewer, escalation reason, and audit record

## Investigation Steps

1. Build a timestamp-normalized cross-incident timeline and identify the correlation that justifies case handling.
2. Preserve and verify the primary evidence: Incident list, correlation rationale, timeline, entities, and evidence references.
3. Map affected identities, assets, techniques, evidence gaps, business impact, and required decision owners.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Duplicate alert is already governed by an active case.
5. Review the additional technical indicator: Potential compromise involves critical assets, privileged accounts, or material impact.
6. Correlate the event with related incidents and similar historical cases and authentication, endpoint, network, dns, persistence, and exfiltration evidence.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document the escalation decision, linked incidents, initial scope, owner, objectives, and approver; do not infer approval from retrieval context.

## Correlation Checks

- Related incidents and similar historical cases
- Authentication, endpoint, network, DNS, persistence, and exfiltration evidence
- Detection Control, remediation, and human-review records
- Asset, vulnerability, data, and business-service context
- Existing open cases to avoid duplicate ownership

## False Positive Conditions

- Duplicate alert is already governed by an active case
- Single low-impact incident has complete evidence and no broader scope
- Approved benign activity is fully validated with no unresolved risk
- Operational issue belongs to a non-security workflow and has confirmed ownership
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Active attacker access, lateral movement, persistence, or exfiltration is suspected
- Critical service, privileged identity, or sensitive data is affected
- Scope is uncertain and coordinated investigation is required
- Policy or regulatory threshold mandates formal incident management
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Do not execute containment merely because a case is opened
- Route each proposed action through the local containment approval workflow
- Document emergency decisions, approver, scope, and expiration
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Assign case ownership, objectives, action plan, and evidence responsibilities
- Link all related incidents without deleting their individual audit trail
- Define communication, review, and closure checkpoints
- Capture lessons for detection, response, and process improvement
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of decision to escalate one or more incidents into a governed investigation case are established and documented.
- The analyst collected and reviewed the required evidence, including incident list, correlation rationale, timeline, entities, and evidence references.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports decision to escalate one or more incidents into a governed investigation case; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
