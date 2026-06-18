---
title: Containment Approval Playbook
type: playbook
domain: governance
source: internal_policy
incident_types:
  - containment_approval
  - remediation_authorization
  - defensive_action_review
severity_hint:
  - medium
  - high
  - critical
mitre_tactics: []
mitre_techniques: []
applicability:
  - Analyst proposes account disablement, session revocation, host isolation, or network blocking
  - Action may disrupt production, users, evidence, or dependent services
  - Active compromise creates urgency but evidence confidence is incomplete
  - Containment scope, duration, rollback, or owner is not yet explicit
not_applicable_when:
  - Monitoring or evidence preservation is safer than immediate disruption
  - Target is shared infrastructure and proposed scope is too broad
  - Evidence does not connect the target to the suspected activity
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - governance
  - containment
  - approval
  - risk
  - human-review
---

# Containment Approval Playbook

## Purpose

This playbook supports human approval of a proposed containment action after balancing evidence, urgency, scope, reversibility, and business impact.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Analyst proposes account disablement, session revocation, host isolation, or network blocking
- Action may disrupt production, users, evidence, or dependent services
- Active compromise creates urgency but evidence confidence is incomplete
- Containment scope, duration, rollback, or owner is not yet explicit
- Use when the current incident evidence specifically supports human approval of a proposed containment action after balancing evidence, urgency, scope, and business impact.

## Detection Signals

- Analyst proposes account disablement, session revocation, host isolation, or network blocking
- Action may disrupt production, users, evidence, or dependent services
- Active compromise creates urgency but evidence confidence is incomplete
- Containment scope, duration, rollback, or owner is not yet explicit
- Emergency action requires retrospective review and audit

## Initial Triage

- State the exact proposed action, target, scope, duration, urgency, requester, and expected security outcome.
- Confirm the evidence connecting the target to active risk and identify material uncertainty.
- Identify business dependencies, safety constraints, shared infrastructure, and likely operational impact.
- Compare the proposal with narrower, reversible, monitoring-only, or evidence-preserving alternatives.
- Define approval authority, execution owner, validation signal, expiration, and rollback before action.

## Evidence to Collect

- Evidence supporting the threat, confidence, affected entities, and active risk
- Exact proposed action, target, scope, duration, owner, and expected effect
- Business impact, dependencies, safety constraints, and alternative options
- Evidence-preservation steps, rollback plan, and validation criteria
- Requester, approver, timestamps, decision, conditions, and execution result

## Investigation Steps

1. Summarize the active threat timeline and the decision deadline for the proposed action.
2. Preserve and verify the primary evidence: Evidence supporting the threat, confidence, affected entities, and active risk.
3. Map the target to owners, dependencies, shared services, user impact, and evidence-preservation requirements.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Monitoring or evidence preservation is safer than immediate disruption.
5. Review the additional technical indicator: Active compromise creates urgency but evidence confidence is incomplete.
6. Correlate the event with incident and case evidence supporting the action and asset owner, identity owner, network, application, and response-team context.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Record approval, rejection, conditions, scope, expiration, execution result, and rollback status; do not infer approval from retrieval context.

## Correlation Checks

- Incident and case evidence supporting the action
- Asset owner, identity owner, network, application, and response-team context
- Existing sessions, dependencies, redundancy, and operational status
- Related containment actions and risk of attacker displacement
- Policy, RBAC, maintenance, and emergency authorization requirements

## False Positive Conditions

- Monitoring or evidence preservation is safer than immediate disruption
- Target is shared infrastructure and proposed scope is too broad
- Evidence does not connect the target to the suspected activity
- An existing approved control already contains the risk
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Active attacker access, destructive behavior, or data transfer requires urgent decision
- The proposed action affects critical, shared, or safety-sensitive systems
- Approval authority is unavailable and emergency policy must be invoked
- Containment fails, causes unexpected impact, or attacker activity shifts
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Every containment action requires analyst approval and the local approval workflow
- Use the narrowest effective scope and define expiration or rollback
- Preserve evidence and record execution outcome before expanding the action
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove temporary controls only after validating that risk is addressed
- Convert emergency controls into reviewed long-term remediation where needed
- Correct identity, segmentation, endpoint, or monitoring gaps exposed by the incident
- Complete retrospective approval review for any emergency action
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of human approval of a proposed containment action after balancing evidence, urgency, scope, and business impact are established and documented.
- The analyst collected and reviewed the required evidence, including evidence supporting the threat, confidence, affected entities, and active risk.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports human approval of a proposed containment action after balancing evidence, urgency, scope, and business impact; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
