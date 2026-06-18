---
title: Windows Defender Tampering Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_defender_tampering
  - endpoint_protection_disabled
  - defense_evasion
severity_hint:
  - high
  - critical
mitre_tactics:
  - Defense Evasion
mitre_techniques:
  - T1562.001
applicability:
  - Microsoft-Windows-Windows Defender Event ID 5007 reports configuration change
  - Real-time protection, cloud protection, behavior monitoring, or scanning is disabled
  - New path, process, extension, or network exclusion is added unexpectedly
  - PowerShell Set-MpPreference, registry, WMI, or policy commands weaken protection
not_applicable_when:
  - Approved security-team troubleshooting with short duration and recorded owner
  - Managed policy transition from an authorized endpoint platform
  - Application compatibility exclusion that is reviewed, narrow, and documented
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - defender
  - tampering
  - defense-evasion
  - event-5007
  - wazuh
---

# Windows Defender Tampering Playbook

## Purpose

This playbook supports investigation of unauthorized disabling, exclusion, policy change, or impairment of Microsoft Defender protections.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Microsoft-Windows-Windows Defender Event ID 5007 reports configuration change
- Real-time protection, cloud protection, behavior monitoring, or scanning is disabled
- New path, process, extension, or network exclusion is added unexpectedly
- PowerShell Set-MpPreference, registry, WMI, or policy commands weaken protection
- Use when the current incident evidence specifically supports unauthorized disabling, exclusion, policy change, or impairment of Microsoft Defender protections.

## Detection Signals

- Microsoft-Windows-Windows Defender Event ID 5007 reports configuration change
- Real-time protection, cloud protection, behavior monitoring, or scanning is disabled
- New path, process, extension, or network exclusion is added unexpectedly
- PowerShell Set-MpPreference, registry, WMI, or policy commands weaken protection
- Tampering occurs before or after malware execution, download, persistence, or lateral movement

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with unauthorized disabling, exclusion, policy change, or impairment of Microsoft Defender protections.
- Confirm the raw detection fields that support: Microsoft-Windows-Windows Defender Event ID 5007 reports configuration change.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved security-team troubleshooting with short duration and recorded owner.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Defender operational events including 5007 and related protection-state changes
- Before-and-after preferences, exclusions, policy source, and tamper-protection state
- Process tree, command line, user, Logon ID, and remote source responsible for the change
- EDR alerts, quarantines, scan history, AMSI, and optional Sysmon telemetry
- Endpoint-management, security-team, troubleshooting, and change records

## Investigation Steps

1. Build a timestamp-normalized timeline around unauthorized disabling, exclusion, policy change, or impairment of Microsoft Defender protections.
2. Preserve and verify the primary evidence: Defender operational events including 5007 and related protection-state changes.
3. Identify the initiating identity, process, device, and access path associated with: Real-time protection, cloud protection, behavior monitoring, or scanning is disabled.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved security-team troubleshooting with short duration and recorded owner.
5. Review the additional technical indicator: New path, process, extension, or network exclusion is added unexpectedly.
6. Correlate the event with suspicious powershell, lolbin, encoded command, service, task, or registry activity and malware detections or payload execution near the change.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Suspicious PowerShell, LOLBin, encoded command, service, task, or registry activity
- Malware detections or payload execution near the change
- Security-log clearing and Event ID 4719 audit-policy changes
- External connections or lateral movement after protection is weakened
- Equivalent exclusions or commands across other endpoints

## False Positive Conditions

- Approved security-team troubleshooting with short duration and recorded owner
- Managed policy transition from an authorized endpoint platform
- Application compatibility exclusion that is reviewed, narrow, and documented
- Lab or security test activity within approved scope
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Protection is disabled or broad exclusions are added without approval
- The actor session is suspicious or privileged credentials may be compromised
- Malware executes while controls are weakened
- The same tampering pattern affects multiple endpoints
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Re-enable protection and remove malicious exclusions after evidence capture and approval
- Restrict the responsible account or management channel through the containment workflow
- Isolate the endpoint when active malware is present
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Restore Defender policy from the authoritative management baseline
- Run approved scans and remediate detected payloads and persistence
- Rotate compromised credentials and review adjacent systems
- Enable tamper protection and monitor high-risk Defender configuration changes
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of unauthorized disabling, exclusion, policy change, or impairment of Microsoft Defender protections are established and documented.
- The analyst collected and reviewed the required evidence, including defender operational events including 5007 and related protection-state changes.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports unauthorized disabling, exclusion, policy change, or impairment of Microsoft Defender protections; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
