---
title: Windows Successful Logon After Failures Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_successful_logon_after_failures
  - possible_account_compromise
  - credential_attack
severity_hint:
  - high
  - critical
mitre_tactics:
  - Initial Access
  - Credential Access
  - Lateral Movement
mitre_techniques:
  - T1110
  - T1078
  - T1021.001
applicability:
  - Event ID 4624 follows repeated Event ID 4625 for the same account or source
  - Successful Logon Type 3 or 10 originates from an unusual address or workstation
  - The account is privileged, dormant, service-oriented, or not expected on the destination
  - Success is followed by process creation, share access, service creation, or privilege use
not_applicable_when:
  - User corrected an accidental password error from a known managed device
  - Approved password rotation caused a short stale-credential sequence
  - Authorized support or jump-host session matches the ticket and operator
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - successful-logon
  - failed-logon
  - account-compromise
  - event-4624
  - event-4625
---

# Windows Successful Logon After Failures Playbook

## Purpose

This playbook supports investigation of Windows Event ID 4624 success following a related sequence of Event ID 4625 failures.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Event ID 4624 follows repeated Event ID 4625 for the same account or source
- Successful Logon Type 3 or 10 originates from an unusual address or workstation
- The account is privileged, dormant, service-oriented, or not expected on the destination
- Success is followed by process creation, share access, service creation, or privilege use
- Use when the current incident evidence specifically supports Windows Event ID 4624 success following a related sequence of Event ID 4625 failures.

## Detection Signals

- Event ID 4624 follows repeated Event ID 4625 for the same account or source
- Successful Logon Type 3 or 10 originates from an unusual address or workstation
- The account is privileged, dormant, service-oriented, or not expected on the destination
- Success is followed by process creation, share access, service creation, or privilege use
- Source geography, VPN assignment, device identity, or login time differs from baseline

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with Windows Event ID 4624 success following a related sequence of Event ID 4625 failures.
- Confirm the raw detection fields that support: Event ID 4624 follows repeated Event ID 4625 for the same account or source.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: User corrected an accidental password error from a known managed device.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Complete 4625-to-4624 timeline with Logon ID, Logon Type, source, workstation, and authentication package
- Event IDs 4648, 4672, 4688, 4698, 4720, 4732, 7045, 5140, and 5145 where present
- VPN, MFA, identity-provider, domain-controller, and endpoint records
- If Sysmon is available, Event IDs 1 and 3 for post-logon processes and connections
- Account owner validation and expected access path

## Investigation Steps

1. Build a timestamp-normalized timeline around Windows Event ID 4624 success following a related sequence of Event ID 4625 failures.
2. Preserve and verify the primary evidence: Complete 4625-to-4624 timeline with Logon ID, Logon Type, source, workstation, and authentication package.
3. Identify the initiating identity, process, device, and access path associated with: Successful Logon Type 3 or 10 originates from an unusual address or workstation.
4. Determine whether the activity matches an approved baseline or this specific benign condition: User corrected an accidental password error from a known managed device.
5. Review the additional technical indicator: The account is privileged, dormant, service-oriented, or not expected on the destination.
6. Correlate the event with privileged logon event id 4672 and explicit credentials event id 4648 and powershell, command shell, scheduled task, service, or registry persistence.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Privileged logon Event ID 4672 and explicit credentials Event ID 4648
- PowerShell, command shell, scheduled task, service, or registry persistence
- SMB, RDP, WinRM, remote service, and administrative-share access
- DNS, Suricata, and outbound connections from the destination
- Similar incidents for the account, source, and destination host

## False Positive Conditions

- User corrected an accidental password error from a known managed device
- Approved password rotation caused a short stale-credential sequence
- Authorized support or jump-host session matches the ticket and operator
- Application or service recovered after credentials were legitimately updated
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Post-logon activity includes privilege use, persistence, lateral movement, or defense evasion
- MFA, VPN, device, or owner evidence does not support the successful session
- The source targeted multiple accounts or hosts before success
- The account is highly privileged or the destination is critical
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Revoke the session and restrict the account after evidence capture and approval
- Isolate the destination when post-logon compromise indicators are active
- Block the confirmed hostile source through approved network controls
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Reset credentials, validate MFA, and review delegated or cached credentials
- Remove persistence and unauthorized changes created after the logon
- Hunt for the source, account, Logon ID, and artifacts across Windows systems
- Address exposed services or access-control weaknesses used by the session
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of Windows Event ID 4624 success following a related sequence of Event ID 4625 failures are established and documented.
- The analyst collected and reviewed the required evidence, including complete 4625-to-4624 timeline with logon id, logon type, source, workstation, and authentication package.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports Windows Event ID 4624 success following a related sequence of Event ID 4625 failures; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
