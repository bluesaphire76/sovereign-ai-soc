---
title: Windows SMB Lateral Movement Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_lateral_movement_smb
  - admin_share_access
  - network_logon_lateral_movement
severity_hint:
  - high
mitre_tactics:
  - Lateral Movement
mitre_techniques:
  - T1021.002
applicability:
  - Event ID 4624 Logon Type 3 occurs from an unusual internal host
  - Event IDs 5140 or 5145 show access to ADMIN$, C$, IPC$, or sensitive shares
  - One account accesses multiple hosts or shares in a short time
  - Executable or service payload is written through an administrative share
not_applicable_when:
  - Approved software deployment, backup, inventory, or endpoint-management traffic
  - Authorized administrator uses a designated jump host and documented ticket
  - Expected file-server or domain-controller access pattern
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - smb
  - lateral-movement
  - admin-share
  - event-5140
  - event-5145
---

# Windows SMB Lateral Movement Playbook

## Purpose

This playbook supports investigation of suspicious SMB network logon, administrative-share access, file transfer, or remote execution between Windows hosts.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Event ID 4624 Logon Type 3 occurs from an unusual internal host
- Event IDs 5140 or 5145 show access to ADMIN$, C$, IPC$, or sensitive shares
- One account accesses multiple hosts or shares in a short time
- Executable or service payload is written through an administrative share
- Use when the current incident evidence specifically supports suspicious SMB network logon, administrative-share access, file transfer, or remote execution between Windows hosts.

## Detection Signals

- Event ID 4624 Logon Type 3 occurs from an unusual internal host
- Event IDs 5140 or 5145 show access to ADMIN$, C$, IPC$, or sensitive shares
- One account accesses multiple hosts or shares in a short time
- Executable or service payload is written through an administrative share
- SMB access is followed by service creation, task creation, WMI, or remote process execution

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with suspicious SMB network logon, administrative-share access, file transfer, or remote execution between Windows hosts.
- Confirm the raw detection fields that support: Event ID 4624 Logon Type 3 occurs from an unusual internal host.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved software deployment, backup, inventory, or endpoint-management traffic.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Event IDs 4624, 4648, 4672, 5140, and 5145 with account, source, share, path, and access mask
- SMB server/client logs, firewall flows, and source/destination asset roles
- Transferred files with hashes, timestamps, signatures, and destination paths
- Service, task, WMI, PowerShell, and process events on the destination
- Account owner, jump-host, deployment, backup, and administration records

## Investigation Steps

1. Build a timestamp-normalized timeline around suspicious SMB network logon, administrative-share access, file transfer, or remote execution between Windows hosts.
2. Preserve and verify the primary evidence: Event IDs 4624, 4648, 4672, 5140, and 5145 with account, source, share, path, and access mask.
3. Identify the initiating identity, process, device, and access path associated with: Event IDs 5140 or 5145 show access to ADMIN$, C$, IPC$, or sensitive shares.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved software deployment, backup, inventory, or endpoint-management traffic.
5. Review the additional technical indicator: One account accesses multiple hosts or shares in a short time.
6. Correlate the event with credential failures or privileged logon before share access and event id 7045 service installation and 4698 scheduled task creation.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Credential failures or privileged logon before share access
- Event ID 7045 service installation and 4698 scheduled task creation
- Network connections from the destination after file transfer
- The same source or account accessing multiple endpoints
- Suricata east-west alerts and endpoint malware detections

## False Positive Conditions

- Approved software deployment, backup, inventory, or endpoint-management traffic
- Authorized administrator uses a designated jump host and documented ticket
- Expected file-server or domain-controller access pattern
- Security scanner or response tool performs approved share access
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Administrative shares are accessed by an unapproved source or identity
- Transferred content is unknown, executable, or followed by remote execution
- The account moves across several hosts outside its baseline
- Endpoint or network evidence indicates credential compromise
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Restrict the account and terminate sessions after approval
- Block malicious east-west SMB paths through the containment workflow
- Isolate source and destination endpoints when movement is active
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove transferred payloads, services, tasks, and remote-execution artifacts
- Rotate affected credentials and invalidate Kerberos tickets or tokens
- Review all systems accessed by the source and account
- Improve SMB segmentation, local administrator controls, and privileged access paths
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of suspicious SMB network logon, administrative-share access, file transfer, or remote execution between Windows hosts are established and documented.
- The analyst collected and reviewed the required evidence, including event ids 4624, 4648, 4672, 5140, and 5145 with account, source, share, path, and access mask.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports suspicious SMB network logon, administrative-share access, file transfer, or remote execution between Windows hosts; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
