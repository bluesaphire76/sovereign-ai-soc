---
title: Windows Local Administrators Membership Change Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_local_admin_membership_change
  - privileged_group_change
  - windows_privilege_change
severity_hint:
  - high
  - critical
mitre_tactics:
  - Privilege Escalation
  - Persistence
mitre_techniques:
  - T1098
applicability:
  - Event ID 4732 adds a member to a security-enabled local group
  - Target group SID maps to BUILTIN Administrators or another privileged role
  - Change is performed by an unexpected account, process, or remote session
  - New member is newly created, dormant, external, or not approved for the host
not_applicable_when:
  - Approved endpoint-management or Group Policy change
  - Authorized support access with matching ticket and expiration
  - Documented service-account deployment requiring local administration
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - administrators-group
  - privilege-change
  - event-4732
  - wazuh
---

# Windows Local Administrators Membership Change Playbook

## Purpose

This playbook supports investigation of addition of an account to the local Administrators group or another privileged Windows group.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Event ID 4732 adds a member to a security-enabled local group
- Target group SID maps to BUILTIN Administrators or another privileged role
- Change is performed by an unexpected account, process, or remote session
- New member is newly created, dormant, external, or not approved for the host
- Use when the current incident evidence specifically supports addition of an account to the local Administrators group or another privileged Windows group.

## Detection Signals

- Event ID 4732 adds a member to a security-enabled local group
- Target group SID maps to BUILTIN Administrators or another privileged role
- Change is performed by an unexpected account, process, or remote session
- New member is newly created, dormant, external, or not approved for the host
- Membership change is followed by privileged logon or remote administration

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with addition of an account to the local Administrators group or another privileged Windows group.
- Confirm the raw detection fields that support: Event ID 4732 adds a member to a security-enabled local group.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved endpoint-management or Group Policy change.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Event IDs 4732 and 4733 with actor, member SID, group SID, host, and timestamp
- Resolved account names, group inventory, nested membership, and current local policy
- Event IDs 4624, 4648, 4672, 4720, 4722, and 4738 around the change
- Process or management channel that performed the modification
- Privileged-access request, endpoint-management job, and owner approval

## Investigation Steps

1. Build a timestamp-normalized timeline around addition of an account to the local Administrators group or another privileged Windows group.
2. Preserve and verify the primary evidence: Event IDs 4732 and 4733 with actor, member SID, group SID, host, and timestamp.
3. Identify the initiating identity, process, device, and access path associated with: Target group SID maps to BUILTIN Administrators or another privileged role.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved endpoint-management or Group Policy change.
5. Review the additional technical indicator: Change is performed by an unexpected account, process, or remote session.
6. Correlate the event with new account creation or enablement before group addition and privileged logon and process execution by the added member.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- New account creation or enablement before group addition
- Privileged logon and process execution by the added member
- PowerShell, net localgroup, Group Policy, WinRM, or endpoint-management activity
- Similar membership changes on peer hosts
- Service, task, registry, or Defender changes after privilege assignment

## False Positive Conditions

- Approved endpoint-management or Group Policy change
- Authorized support access with matching ticket and expiration
- Documented service-account deployment requiring local administration
- Break-glass access reviewed under the emergency procedure
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- No approved request or owner explains the new member
- The actor or member has suspicious authentication activity
- The account uses the privilege immediately for persistence or security-control changes
- Membership is added across multiple hosts outside policy
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Remove unauthorized membership after evidence preservation and approval
- Disable or restrict the affected account through the containment workflow
- Isolate hosts when the change supports active lateral movement
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Restore local group membership from the approved baseline
- Rotate credentials and invalidate sessions for compromised accounts
- Remove unauthorized actions performed with the new privileges
- Enforce managed local administrator controls and periodic membership review
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of addition of an account to the local Administrators group or another privileged Windows group are established and documented.
- The analyst collected and reviewed the required evidence, including event ids 4732 and 4733 with actor, member sid, group sid, host, and timestamp.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports addition of an account to the local Administrators group or another privileged Windows group; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
