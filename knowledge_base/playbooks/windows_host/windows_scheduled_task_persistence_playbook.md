---
title: Windows Scheduled Task Persistence Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_scheduled_task_persistence
  - scheduled_task_abuse
  - windows_persistence
severity_hint:
  - high
mitre_tactics:
  - Persistence
  - Execution
mitre_techniques:
  - T1053.005
applicability:
  - Security Event ID 4698 records a new scheduled task
  - Task action launches PowerShell, cmd, mshta, rundll32, script host, or user-writable content
  - Task runs as SYSTEM, with highest privileges, at logon, startup, or high frequency
  - Task name or path mimics a Windows or vendor component
not_applicable_when:
  - Approved application, patching, backup, monitoring, or management task
  - Documented administrator task with matching owner and ticket
  - Vendor task with trusted path, signature, and expected XML
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - scheduled-task
  - persistence
  - event-4698
  - wazuh
---

# Windows Scheduled Task Persistence Playbook

## Purpose

This playbook supports investigation of creation or modification of a Windows scheduled task that may provide execution or persistence.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Security Event ID 4698 records a new scheduled task
- Task action launches PowerShell, cmd, mshta, rundll32, script host, or user-writable content
- Task runs as SYSTEM, with highest privileges, at logon, startup, or high frequency
- Task name or path mimics a Windows or vendor component
- Use when the current incident evidence specifically supports creation or modification of a Windows scheduled task that may provide execution or persistence.

## Detection Signals

- Security Event ID 4698 records a new scheduled task
- Task action launches PowerShell, cmd, mshta, rundll32, script host, or user-writable content
- Task runs as SYSTEM, with highest privileges, at logon, startup, or high frequency
- Task name or path mimics a Windows or vendor component
- Task creation follows suspicious logon, download, PowerShell, or remote administration

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with creation or modification of a Windows scheduled task that may provide execution or persistence.
- Confirm the raw detection fields that support: Security Event ID 4698 records a new scheduled task.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved application, patching, backup, monitoring, or management task.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Event IDs 4698, 4702, 4699, and TaskScheduler operational events
- Complete task XML, action, trigger, principal, author, URI, and security descriptor
- Referenced script or binary with hash, origin, and file metadata
- Creator Logon ID, process, source host, and remote management channel
- Optional Sysmon Event IDs 1, 3, and 11 for execution and file creation

## Investigation Steps

1. Build a timestamp-normalized timeline around creation or modification of a Windows scheduled task that may provide execution or persistence.
2. Preserve and verify the primary evidence: Event IDs 4698, 4702, 4699, and TaskScheduler operational events.
3. Identify the initiating identity, process, device, and access path associated with: Task action launches PowerShell, cmd, mshta, rundll32, script host, or user-writable content.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved application, patching, backup, monitoring, or management task.
5. Review the additional technical indicator: Task runs as SYSTEM, with highest privileges, at logon, startup, or high frequency.
6. Correlate the event with authentication and privileged logon before task creation and powershell, lolbin, wmi, service, and registry events.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Authentication and privileged logon before task creation
- PowerShell, LOLBin, WMI, service, and registry events
- Network callbacks repeating on the task schedule
- The same task name, action, or payload across hosts
- Deployment and endpoint-management records

## False Positive Conditions

- Approved application, patching, backup, monitoring, or management task
- Documented administrator task with matching owner and ticket
- Vendor task with trusted path, signature, and expected XML
- Security test task within approved scope and cleanup time
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Task runs an untrusted payload as SYSTEM or with highest privileges
- Creator, task name, or action is unexplained
- Task triggers command-and-control, credential access, or defense evasion
- Task is deployed remotely or across multiple endpoints without approval
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Disable the task after exporting its XML and obtaining analyst approval
- Terminate active task processes through the containment workflow
- Isolate the endpoint when the task sustains active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Delete unauthorized tasks and associated payloads after evidence preservation
- Restore approved tasks from endpoint-management baseline
- Rotate credentials used by the task or exposed in its arguments
- Monitor high-risk task actions, principals, and remote creation
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of creation or modification of a Windows scheduled task that may provide execution or persistence are established and documented.
- The analyst collected and reviewed the required evidence, including event ids 4698, 4702, 4699, and taskscheduler operational events.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports creation or modification of a Windows scheduled task that may provide execution or persistence; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
