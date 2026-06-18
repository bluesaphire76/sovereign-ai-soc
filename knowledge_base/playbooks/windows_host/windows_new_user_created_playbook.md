---
title: Windows New User Created Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_new_user_created
  - suspicious_account_creation
  - windows_account_change
severity_hint:
  - medium
  - high
mitre_tactics:
  - Persistence
mitre_techniques:
  - T1136.001
  - T1136.002
applicability:
  - Event ID 4720 records creation of a user account
  - Event ID 4722 enables a new or previously disabled account
  - Creator is unusual, remote, compromised, or outside identity automation
  - Account name mimics a service, administrator, or legitimate employee
not_applicable_when:
  - Approved employee, contractor, or service-account provisioning
  - Domain join, application installation, or endpoint management created a documented account
  - Lab or test account created within approved scope and lifetime
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - user-created
  - account-change
  - event-4720
  - wazuh
---

# Windows New User Created Playbook

## Purpose

This playbook supports investigation of creation of an unexpected local or domain Windows account.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Event ID 4720 records creation of a user account
- Event ID 4722 enables a new or previously disabled account
- Creator is unusual, remote, compromised, or outside identity automation
- Account name mimics a service, administrator, or legitimate employee
- Use when the current incident evidence specifically supports creation of an unexpected local or domain Windows account.

## Detection Signals

- Event ID 4720 records creation of a user account
- Event ID 4722 enables a new or previously disabled account
- Creator is unusual, remote, compromised, or outside identity automation
- Account name mimics a service, administrator, or legitimate employee
- Creation is followed by Event ID 4732 group membership or Event ID 4624 logon

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with creation of an unexpected local or domain Windows account.
- Confirm the raw detection fields that support: Event ID 4720 records creation of a user account.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved employee, contractor, or service-account provisioning.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Event IDs 4720, 4722, 4738, 4732, and 4624 with actor and target SIDs
- Account attributes, creation time, password settings, groups, and expiration
- Creator logon session, source workstation, process, and administrative channel
- Identity request, HR record, service-account registry, and owner approval
- Subsequent processes, network access, shares, tasks, services, and registry changes

## Investigation Steps

1. Build a timestamp-normalized timeline around creation of an unexpected local or domain Windows account.
2. Preserve and verify the primary evidence: Event IDs 4720, 4722, 4738, 4732, and 4624 with actor and target SIDs.
3. Identify the initiating identity, process, device, and access path associated with: Event ID 4722 enables a new or previously disabled account.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved employee, contractor, or service-account provisioning.
5. Review the additional technical indicator: Creator is unusual, remote, compromised, or outside identity automation.
6. Correlate the event with privileged group addition and special-privilege assignment and interactive, rdp, smb, winrm, or service logons by the new account.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Privileged group addition and special-privilege assignment
- Interactive, RDP, SMB, WinRM, or service logons by the new account
- PowerShell, command shell, service, scheduled task, and Defender events
- Equivalent account names or SIDs on other hosts
- Related authentication failures and password changes

## False Positive Conditions

- Approved employee, contractor, or service-account provisioning
- Domain join, application installation, or endpoint management created a documented account
- Lab or test account created within approved scope and lifetime
- Recovery account created under a reviewed emergency procedure
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- The account gains administrative rights or authenticates immediately without approval
- The creator session is anomalous or compromised
- Account attributes weaken password or expiration controls
- The account is used for lateral movement, persistence, or security-control changes
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Disable the account and revoke sessions after evidence capture and approval
- Remove unauthorized group membership through the containment workflow
- Isolate the host or domain controller when creation is part of active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Delete or retain the account according to forensic and identity policy
- Restore group and access-control assignments to approved state
- Rotate affected credentials and review creator activity across the environment
- Correct provisioning or monitoring gaps that allowed ungoverned account creation
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of creation of an unexpected local or domain Windows account are established and documented.
- The analyst collected and reviewed the required evidence, including event ids 4720, 4722, 4738, 4732, and 4624 with actor and target sids.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports creation of an unexpected local or domain Windows account; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
