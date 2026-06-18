---
title: Windows Registry Run Key Persistence Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_registry_run_key_persistence
  - registry_persistence
  - windows_persistence
severity_hint:
  - high
mitre_tactics:
  - Persistence
mitre_techniques:
  - T1060
  - T1112
applicability:
  - Run, RunOnce, Winlogon, StartupApproved, or related autostart key gains a new value
  - Registry value points to a user-writable, temporary, hidden, downloaded, or network path
  - Value launches PowerShell, script host, rundll32, mshta, or an unknown binary
  - If Sysmon is available, Event IDs 12, 13, or 14 record suspicious registry activity
not_applicable_when:
  - Approved application installer created a documented autostart entry
  - Enterprise management or Group Policy applied the expected value
  - Vendor updater uses a signed binary in an approved path
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - registry
  - run-key
  - persistence
  - wazuh
---

# Windows Registry Run Key Persistence Playbook

## Purpose

This playbook supports investigation of modification of Windows autostart registry locations that may establish user or machine persistence.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Run, RunOnce, Winlogon, StartupApproved, or related autostart key gains a new value
- Registry value points to a user-writable, temporary, hidden, downloaded, or network path
- Value launches PowerShell, script host, rundll32, mshta, or an unknown binary
- If Sysmon is available, Event IDs 12, 13, or 14 record suspicious registry activity
- Use when the current incident evidence specifically supports modification of Windows autostart registry locations that may establish user or machine persistence.

## Detection Signals

- Run, RunOnce, Winlogon, StartupApproved, or related autostart key gains a new value
- Registry value points to a user-writable, temporary, hidden, downloaded, or network path
- Value launches PowerShell, script host, rundll32, mshta, or an unknown binary
- If Sysmon is available, Event IDs 12, 13, or 14 record suspicious registry activity
- Change follows suspicious login, download, document execution, or privilege escalation

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with modification of Windows autostart registry locations that may establish user or machine persistence.
- Confirm the raw detection fields that support: Run, RunOnce, Winlogon, StartupApproved, or related autostart key gains a new value.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved application installer created a documented autostart entry.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Registry hive, key, value name, type, data, actor, process, and timestamp
- Before-and-after registry values and exported key evidence
- Referenced executable or script with hash, signature, origin, and metadata
- Security 4688 and optional Sysmon Event IDs 1, 11, 12, 13, and 14
- User profile, software deployment, Group Policy, and application-owner context

## Investigation Steps

1. Build a timestamp-normalized timeline around modification of Windows autostart registry locations that may establish user or machine persistence.
2. Preserve and verify the primary evidence: Registry hive, key, value name, type, data, actor, process, and timestamp.
3. Identify the initiating identity, process, device, and access path associated with: Registry value points to a user-writable, temporary, hidden, downloaded, or network path.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved application installer created a documented autostart entry.
5. Review the additional technical indicator: Value launches PowerShell, script host, rundll32, mshta, or an unknown binary.
6. Correlate the event with process and file creation that produced the registry change and logon events that trigger execution of the value.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Process and file creation that produced the registry change
- Logon events that trigger execution of the value
- Network and DNS activity from the referenced payload
- Scheduled tasks, services, startup-folder files, and WMI persistence
- Matching registry values across peer endpoints

## False Positive Conditions

- Approved application installer created a documented autostart entry
- Enterprise management or Group Policy applied the expected value
- Vendor updater uses a signed binary in an approved path
- Authorized administrator change has matching ticket and baseline
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Value references an unsigned or unknown payload in a writable path
- The modifying process or session is suspicious
- Persistence launches malware, command-and-control, or credential theft
- The same value appears across endpoints outside software deployment
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Disable or remove the value only after registry export and analyst approval
- Terminate the associated process through the containment workflow
- Isolate the endpoint when the autostart entry maintains active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove unauthorized values and associated files
- Restore approved registry baseline and application startup state
- Rotate credentials exposed during the persistence window
- Add registry monitoring for high-risk autostart locations
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of modification of Windows autostart registry locations that may establish user or machine persistence are established and documented.
- The analyst collected and reviewed the required evidence, including registry hive, key, value name, type, data, actor, process, and timestamp.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports modification of Windows autostart registry locations that may establish user or machine persistence; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
