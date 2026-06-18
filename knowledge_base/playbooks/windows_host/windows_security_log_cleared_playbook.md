---
title: Windows Security Log Cleared Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_security_log_cleared
  - anti_forensics
  - possible_compromise
severity_hint:
  - high
  - critical
mitre_tactics:
  - Defense Evasion
mitre_techniques:
  - T1070.001
applicability:
  - Security Event ID 1102 reports that the audit log was cleared
  - System Event ID 104 reports an event log was cleared
  - Audit, PowerShell, Defender, or Sysmon logs stop unexpectedly or roll over abnormally
  - wevtutil, Clear-EventLog, PowerShell, or API-based clearing is observed
not_applicable_when:
  - Approved log maintenance or forensic collection with a matching ticket
  - Lab or test-system reset within documented scope
  - Retention rollover caused by verified capacity or policy behavior
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - security-log-cleared
  - anti-forensics
  - event-1102
  - wazuh
---

# Windows Security Log Cleared Playbook

## Purpose

This playbook supports investigation of clearing of the Windows Security event log or related evidence that may indicate anti-forensics.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Security Event ID 1102 reports that the audit log was cleared
- System Event ID 104 reports an event log was cleared
- Audit, PowerShell, Defender, or Sysmon logs stop unexpectedly or roll over abnormally
- wevtutil, Clear-EventLog, PowerShell, or API-based clearing is observed
- Use when the current incident evidence specifically supports clearing of the Windows Security event log or related evidence that may indicate anti-forensics.

## Detection Signals

- Security Event ID 1102 reports that the audit log was cleared
- System Event ID 104 reports an event log was cleared
- Audit, PowerShell, Defender, or Sysmon logs stop unexpectedly or roll over abnormally
- wevtutil, Clear-EventLog, PowerShell, or API-based clearing is observed
- Clearing follows privileged logon, suspicious execution, lateral movement, or security-control tampering

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with clearing of the Windows Security event log or related evidence that may indicate anti-forensics.
- Confirm the raw detection fields that support: Security Event ID 1102 reports that the audit log was cleared.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved log maintenance or forensic collection with a matching ticket.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Event IDs 1102 and 104 with subject account, Logon ID, host, and timestamp
- Central Wazuh copies of events preceding and following the clear
- Process execution for wevtutil, PowerShell, MMC, or other clearing mechanism
- Audit policy, retention, channel configuration, and disk-capacity state
- Administrator, maintenance, incident-response, and change-control records

## Investigation Steps

1. Build a timestamp-normalized timeline around clearing of the Windows Security event log or related evidence that may indicate anti-forensics.
2. Preserve and verify the primary evidence: Event IDs 1102 and 104 with subject account, Logon ID, host, and timestamp.
3. Identify the initiating identity, process, device, and access path associated with: System Event ID 104 reports an event log was cleared.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved log maintenance or forensic collection with a matching ticket.
5. Review the additional technical indicator: Audit, PowerShell, Defender, or Sysmon logs stop unexpectedly or roll over abnormally.
6. Correlate the event with privileged event ids 4624, 4648, and 4672 for the clearing subject and event id 4719 audit-policy changes and defender configuration changes.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Privileged Event IDs 4624, 4648, and 4672 for the clearing subject
- Event ID 4719 audit-policy changes and Defender configuration changes
- PowerShell, service, task, account, and remote-access activity before clearing
- Network and DNS activity from the host around the evidence gap
- Other hosts touched by the same account or source

## False Positive Conditions

- Approved log maintenance or forensic collection with a matching ticket
- Lab or test-system reset within documented scope
- Retention rollover caused by verified capacity or policy behavior
- Authorized incident responder cleared a log after central preservation
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- No authorized operational reason exists for the clear
- Clearing follows compromise indicators or affects a critical system
- Audit policy or security tooling is also disabled
- The same account clears logs on multiple systems
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Preserve central logs, volatile evidence, and remaining channels before intervention
- Restrict the clearing account or session after analyst approval
- Isolate the host when anti-forensics accompanies active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Restore audit policy, channel configuration, forwarding, and retention
- Remove malicious tools or persistence associated with the clearing session
- Rotate compromised privileged credentials
- Ensure critical logs are forwarded centrally and alert on evidence gaps
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of clearing of the Windows Security event log or related evidence that may indicate anti-forensics are established and documented.
- The analyst collected and reviewed the required evidence, including event ids 1102 and 104 with subject account, logon id, host, and timestamp.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports clearing of the Windows Security event log or related evidence that may indicate anti-forensics; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
