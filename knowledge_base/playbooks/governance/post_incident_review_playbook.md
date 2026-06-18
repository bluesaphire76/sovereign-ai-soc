---
title: Post-Incident Review Playbook
type: playbook
domain: governance
source: internal_policy
incident_types:
  - post_incident_review
  - lessons_learned
  - case_retrospective
severity_hint:
  - low
  - medium
  - high
  - critical
mitre_tactics: []
mitre_techniques: []
applicability:
  - Incident or case reached containment, remediation, or closure decision
  - Response exposed detection, evidence, communication, ownership, or tooling gaps
  - Material impact, critical assets, or cross-team actions were involved
  - False-positive or duplicate patterns suggest detection improvement
not_applicable_when:
  - Minor incident may use a lightweight review when policy permits
  - Duplicate events are reviewed through the authoritative parent case
  - Operational outage without security relevance follows the service-review process
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - governance
  - post-incident
  - lessons-learned
  - closure
  - human-review
---

# Post-Incident Review Playbook

## Purpose

This playbook supports a structured review after incident or case resolution to validate outcomes, residual risk, and corrective actions.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Incident or case reached containment, remediation, or closure decision
- Response exposed detection, evidence, communication, ownership, or tooling gaps
- Material impact, critical assets, or cross-team actions were involved
- False-positive or duplicate patterns suggest detection improvement
- Use when the current incident evidence specifically supports structured review after incident or case resolution to validate outcomes and improve controls.

## Detection Signals

- Incident or case reached containment, remediation, or closure decision
- Response exposed detection, evidence, communication, ownership, or tooling gaps
- Material impact, critical assets, or cross-team actions were involved
- False-positive or duplicate patterns suggest detection improvement
- Policy requires formal lessons learned or management review

## Initial Triage

- Confirm the authoritative incident or case, final status, owner, reviewers, and review scope.
- Assemble the final timeline, root cause, affected entities, impact, evidence, decisions, and approvals.
- Verify that containment, remediation, recovery, and closure outcomes were actually validated.
- Identify unresolved risk, recurring failure patterns, control gaps, and incomplete corrective actions.
- Agree on review depth, participants, deliverables, and deadlines according to policy and impact.

## Evidence to Collect

- Final timeline, root cause, initial access, scope, impact, and evidence references
- Detection, triage, escalation, containment, remediation, and recovery timestamps
- Decisions, approvals, rejected alternatives, communications, and business impact
- What worked, what failed, evidence gaps, and unresolved residual risk
- Assigned improvements with owner, priority, due date, and validation method

## Investigation Steps

1. Reconstruct the detection-to-closure timeline, including delays, handoffs, approvals, and rejected alternatives.
2. Preserve and verify the primary evidence: Final timeline, root cause, initial access, scope, impact, and evidence references.
3. Identify detection, evidence, communication, ownership, tooling, and governance gaps exposed by the response.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Minor incident may use a lightweight review when policy permits.
5. Review the additional technical indicator: Material impact, critical assets, or cross-team actions were involved.
6. Correlate the event with all related incidents, cases, alerts, and historical memory and detection control changes, exceptions, and tuning proposals.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Approve measurable corrective actions with owners, dates, validation methods, and residual-risk acceptance; do not infer approval from retrieval context.

## Correlation Checks

- All related incidents, cases, alerts, and historical memory
- Detection Control changes, exceptions, and tuning proposals
- Containment and remediation audit records
- Asset, vulnerability, identity, architecture, and data context
- Comparable past incidents and whether prior actions were effective

## False Positive Conditions

- Minor incident may use a lightweight review when policy permits
- Duplicate events are reviewed through the authoritative parent case
- Operational outage without security relevance follows the service-review process
- Review scope is reduced only with owner and policy approval
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Root cause, scope, impact, or residual risk remains unresolved
- Required evidence or approval is missing from closure
- The same failure pattern is recurring without effective corrective action
- Legal, privacy, regulatory, or executive follow-up remains open
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Do not introduce new containment after closure without reopening governed review
- Any residual defensive action requires normal analyst approval
- Document emergency actions and confirm their rollback or conversion
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Assign measurable detection, response, architecture, and governance improvements
- Update playbooks and training with validated lessons rather than assumptions
- Track corrective actions to completion and test their effectiveness
- Index approved historical outcome context without treating it as future decision authority
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of structured review after incident or case resolution to validate outcomes and improve controls are established and documented.
- The analyst collected and reviewed the required evidence, including final timeline, root cause, initial access, scope, impact, and evidence references.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports structured review after incident or case resolution to validate outcomes and improve controls; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
