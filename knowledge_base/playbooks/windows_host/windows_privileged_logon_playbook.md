---
title: Windows Privileged Logon Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_privileged_logon
  - privileged_account_access
  - suspicious_admin_logon
severity_hint:
  - medium
  - high
mitre_tactics:
  - Initial Access
  - Privilege Escalation
mitre_techniques:
  - T1078
applicability:
  - Event ID 4672 assigns special privileges to a new logon
  - Event ID 4624 involves a domain admin, local administrator, or sensitive service account
  - Privileged Logon Type 2, 3, 10, or 11 occurs from an unusual source or time
  - Event ID 4648 explicit credentials are used from an unexpected process
not_applicable_when:
  - Approved administrator session through the designated jump host or PAM workflow
  - Documented maintenance with matching operator, scope, and time
  - Expected service account logon on an authorized system
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - privileged-logon
  - admin
  - authentication
  - event-4672
  - wazuh
---

# Windows Privileged Logon Playbook

## Purpose

This playbook supports investigation of interactive, remote, or network logon that grants administrative privileges on Windows.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Event ID 4672 assigns special privileges to a new logon
- Event ID 4624 involves a domain admin, local administrator, or sensitive service account
- Privileged Logon Type 2, 3, 10, or 11 occurs from an unusual source or time
- Event ID 4648 explicit credentials are used from an unexpected process
- Use when the current incident evidence specifically supports interactive, remote, or network logon that grants administrative privileges on Windows.

## Detection Signals

- Event ID 4672 assigns special privileges to a new logon
- Event ID 4624 involves a domain admin, local administrator, or sensitive service account
- Privileged Logon Type 2, 3, 10, or 11 occurs from an unusual source or time
- Event ID 4648 explicit credentials are used from an unexpected process
- Privileged session is followed by administration outside the account baseline

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with interactive, remote, or network logon that grants administrative privileges on Windows.
- Confirm the raw detection fields that support: Event ID 4672 assigns special privileges to a new logon.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved administrator session through the designated jump host or PAM workflow.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Event IDs 4624, 4672, and 4648 with Logon ID, source, workstation, and authentication package
- Privileged group membership and account tier
- Processes, commands, services, tasks, shares, and registry changes tied to the Logon ID
- VPN, MFA, jump-host, PAM, and administrative ticket records
- If Sysmon is available, Event IDs 1 and 3 for the privileged session

## Investigation Steps

1. Build a timestamp-normalized timeline around interactive, remote, or network logon that grants administrative privileges on Windows.
2. Preserve and verify the primary evidence: Event IDs 4624, 4672, and 4648 with Logon ID, source, workstation, and authentication package.
3. Identify the initiating identity, process, device, and access path associated with: Event ID 4624 involves a domain admin, local administrator, or sensitive service account.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved administrator session through the designated jump host or PAM workflow.
5. Review the additional technical indicator: Privileged Logon Type 2, 3, 10, or 11 occurs from an unusual source or time.
6. Correlate the event with failed logons before success and password or account changes and powershell, lolbin, service, task, wmi, or remote management execution.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Failed logons before success and password or account changes
- PowerShell, LOLBin, service, task, WMI, or remote management execution
- SMB administrative shares and access to multiple hosts
- Defender, audit policy, or security-log changes
- Other privileged sessions by the account

## False Positive Conditions

- Approved administrator session through the designated jump host or PAM workflow
- Documented maintenance with matching operator, scope, and time
- Expected service account logon on an authorized system
- Emergency access with completed break-glass review
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- The privileged source, device, or access path is unapproved
- Commands modify security controls, persistence, accounts, or credentials
- The account owner denies the session or MFA evidence is absent
- The same credentials are used across multiple hosts anomalously
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Terminate the privileged session or disable the account after approval
- Restrict remote administration paths when active misuse is confirmed
- Isolate affected systems if the account is enabling lateral movement
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Rotate privileged credentials and invalidate tokens or tickets
- Remove unauthorized changes made during the session
- Review all hosts accessed by the account and validate administrative actions
- Enforce PAM, MFA, tiering, and jump-host controls for privileged identities
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of interactive, remote, or network logon that grants administrative privileges on Windows are established and documented.
- The analyst collected and reviewed the required evidence, including event ids 4624, 4672, and 4648 with logon id, source, workstation, and authentication package.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports interactive, remote, or network logon that grants administrative privileges on Windows; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
