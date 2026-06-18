---
title: Linux Privileged Group Membership Change Playbook
type: playbook
domain: linux_host
source: wazuh
incident_types:
  - user_group_membership_change
  - privileged_group_change
  - linux_privilege_change
severity_hint:
  - medium
  - high
  - critical
mitre_tactics:
  - Privilege Escalation
  - Persistence
mitre_techniques:
  - T1098
applicability:
  - Wazuh or auditd event for usermod, gpasswd, adduser, or direct group-file modification
  - Membership added to sudo, wheel, root, adm, docker, lxd, disk, or shadow groups
  - Privileged group change outside an approved access request window
  - Group modification performed by an unusual administrator or process
not_applicable_when:
  - Approved privileged-access grant with matching scope and expiration
  - Documented role change performed by identity automation
  - Configuration-management reconciliation from an authorized controller
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - linux
  - group-membership
  - privilege-change
  - sudo
  - wazuh
---

# Linux Privileged Group Membership Change Playbook

## Purpose

This playbook supports investigation of addition of a user or service account to a privileged Linux group.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Wazuh or auditd event for usermod, gpasswd, adduser, or direct group-file modification
- Membership added to sudo, wheel, root, adm, docker, lxd, disk, or shadow groups
- Privileged group change outside an approved access request window
- Group modification performed by an unusual administrator or process
- Use when the current incident evidence specifically supports addition of a user or service account to a privileged Linux group.

## Detection Signals

- Wazuh or auditd event for usermod, gpasswd, adduser, or direct group-file modification
- Membership added to sudo, wheel, root, adm, docker, lxd, disk, or shadow groups
- Privileged group change outside an approved access request window
- Group modification performed by an unusual administrator or process
- New membership followed by sudo, container, disk, or credential-store access

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with addition of a user or service account to a privileged Linux group.
- Confirm the raw detection fields that support: Wazuh or auditd event for usermod, gpasswd, adduser, or direct group-file modification.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved privileged-access grant with matching scope and expiration.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- /etc/group and /etc/gshadow before-and-after values
- Command line, parent process, effective UID, and terminal for the group change
- Target account history, current groups, sudo rights, and active sessions
- Subsequent sudo, docker, lxd, disk, or sensitive file access
- Privileged-access request and approver evidence

## Investigation Steps

1. Build a timestamp-normalized timeline around addition of a user or service account to a privileged Linux group.
2. Preserve and verify the primary evidence: /etc/group and /etc/gshadow before-and-after values.
3. Identify the initiating identity, process, device, and access path associated with: Membership added to sudo, wheel, root, adm, docker, lxd, disk, or shadow groups.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved privileged-access grant with matching scope and expiration.
5. Review the additional technical indicator: Privileged group change outside an approved access request window.
6. Correlate the event with authentication and sudo timeline for the actor and target account and new user creation, password reset, ssh key, or sudoers changes.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Authentication and sudo timeline for the actor and target account
- New user creation, password reset, SSH key, or sudoers changes
- Container creation or host filesystem mounts after docker or lxd membership
- Sensitive file access after adm, disk, or shadow membership
- Equivalent group changes across other Linux assets

## False Positive Conditions

- Approved privileged-access grant with matching scope and expiration
- Documented role change performed by identity automation
- Configuration-management reconciliation from an authorized controller
- Emergency access approved and reviewed under the break-glass process
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Membership grants root-equivalent access and has no valid approval
- The actor or target account shows suspicious authentication activity
- Privilege use occurs immediately after the membership change
- The same actor modifies privileged groups on multiple hosts
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Remove unauthorized membership after preserving evidence and obtaining approval
- Terminate privileged sessions or revoke temporary access through the approved workflow
- Isolate the host if the change is part of active lateral movement
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Restore group membership to the approved identity baseline
- Rotate credentials for affected privileged accounts when compromise is suspected
- Review sudoers, SSH keys, local accounts, containers, and mounted filesystems
- Correct privileged-access automation or governance gaps that allowed the change
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of addition of a user or service account to a privileged Linux group are established and documented.
- The analyst collected and reviewed the required evidence, including /etc/group and /etc/gshadow before-and-after values.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports addition of a user or service account to a privileged Linux group; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
