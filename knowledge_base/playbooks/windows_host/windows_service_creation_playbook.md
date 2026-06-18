---
title: Windows Service Creation Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_service_creation
  - remote_service_execution
  - windows_persistence
severity_hint:
  - high
  - critical
mitre_tactics:
  - Persistence
  - Privilege Escalation
  - Lateral Movement
mitre_techniques:
  - T1543.003
  - T1021
applicability:
  - System Event ID 7045 reports a newly installed service
  - Security Event ID 4697 records service installation where enabled
  - Service binary path points to a writable, temporary, administrative-share, or unusual location
  - Service runs as LocalSystem and has an unexplained or masquerading name
not_applicable_when:
  - Approved software, agent, driver, or endpoint-management installation
  - Documented patch or application deployment with trusted signed binary
  - Authorized administrator created the service under change control
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - service-creation
  - persistence
  - event-7045
  - wazuh
---

# Windows Service Creation Playbook

## Purpose

This playbook supports investigation of installation or modification of a Windows service that may enable persistence, privilege escalation, or remote execution.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- System Event ID 7045 reports a newly installed service
- Security Event ID 4697 records service installation where enabled
- Service binary path points to a writable, temporary, administrative-share, or unusual location
- Service runs as LocalSystem and has an unexplained or masquerading name
- Use when the current incident evidence specifically supports installation or modification of a Windows service that may enable persistence, privilege escalation, or remote execution.

## Detection Signals

- System Event ID 7045 reports a newly installed service
- Security Event ID 4697 records service installation where enabled
- Service binary path points to a writable, temporary, administrative-share, or unusual location
- Service runs as LocalSystem and has an unexplained or masquerading name
- Creation follows SMB, remote administration, suspicious logon, or file transfer

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with installation or modification of a Windows service that may enable persistence, privilege escalation, or remote execution.
- Confirm the raw detection fields that support: System Event ID 7045 reports a newly installed service.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved software, agent, driver, or endpoint-management installation.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Event IDs 7045 and 4697 with service name, path, account, start type, and host
- Service registry configuration and Service Control Manager operational records
- Binary hash, signature, origin, owner, ACL, and creation timestamp
- Creator logon, process, source workstation, SMB transfer, and remote-service evidence
- Optional Sysmon Event IDs 1, 3, and 11 for execution, network, and file creation

## Investigation Steps

1. Build a timestamp-normalized timeline around installation or modification of a Windows service that may enable persistence, privilege escalation, or remote execution.
2. Preserve and verify the primary evidence: Event IDs 7045 and 4697 with service name, path, account, start type, and host.
3. Identify the initiating identity, process, device, and access path associated with: Security Event ID 4697 records service installation where enabled.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved software, agent, driver, or endpoint-management installation.
5. Review the additional technical indicator: Service binary path points to a writable, temporary, administrative-share, or unusual location.
6. Correlate the event with smb administrative shares, event ids 5140/5145, and remote logons and psexec-like execution, winrm, wmi, scheduled tasks, and powershell.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- SMB administrative shares, Event IDs 5140/5145, and remote logons
- PsExec-like execution, WinRM, WMI, scheduled tasks, and PowerShell
- Network callbacks and child processes from the service binary
- The same service name, hash, or source host across systems
- Deployment, patching, EDR, and software inventory records

## False Positive Conditions

- Approved software, agent, driver, or endpoint-management installation
- Documented patch or application deployment with trusted signed binary
- Authorized administrator created the service under change control
- Vendor service path, account, and start type match known baseline
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Service binary is unknown, unsigned, remote, or staged through an administrative share
- Creation is associated with suspicious remote logon or lateral movement
- Service starts as SYSTEM and contacts external infrastructure
- The same unauthorized service is deployed to multiple hosts
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Stop and disable the service after capturing configuration and obtaining approval
- Quarantine the binary and restrict remote service creation through governed controls
- Isolate affected endpoints when service-based lateral movement is active
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove the unauthorized service, binary, registry configuration, and related artifacts
- Restore approved service inventory and endpoint-management state
- Rotate credentials used for remote installation
- Hunt for matching services, hashes, source hosts, and administrative-share transfers
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of installation or modification of a Windows service that may enable persistence, privilege escalation, or remote execution are established and documented.
- The analyst collected and reviewed the required evidence, including event ids 7045 and 4697 with service name, path, account, start type, and host.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports installation or modification of a Windows service that may enable persistence, privilege escalation, or remote execution; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
