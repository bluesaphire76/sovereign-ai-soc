---
title: Windows Suspicious PowerShell Execution Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_suspicious_powershell
  - suspicious_script_execution
  - possible_malware_execution
severity_hint:
  - medium
  - high
mitre_tactics:
  - Execution
  - Defense Evasion
mitre_techniques:
  - T1059.001
  - T1027
applicability:
  - PowerShell uses download, reflection, in-memory execution, hidden window, or execution-policy bypass
  - Script Block Logging Event ID 4104 contains Invoke-Expression, WebClient, encoded data, or credential access
  - PowerShell Operational Event IDs 4103 or 4104 originate from an unusual user or parent
  - Process is launched by Office, browser, archive utility, service, WMI, or scheduled task
not_applicable_when:
  - Approved administration, deployment, monitoring, or configuration script
  - Signed enterprise script from a trusted repository and expected operator
  - Authorized security test within scope
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - powershell
  - script
  - execution
  - wazuh
---

# Windows Suspicious PowerShell Execution Playbook

## Purpose

This playbook supports investigation of PowerShell execution with suspicious command, parent process, content, or network behavior.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- PowerShell uses download, reflection, in-memory execution, hidden window, or execution-policy bypass
- Script Block Logging Event ID 4104 contains Invoke-Expression, WebClient, encoded data, or credential access
- PowerShell Operational Event IDs 4103 or 4104 originate from an unusual user or parent
- Process is launched by Office, browser, archive utility, service, WMI, or scheduled task
- Use when the current incident evidence specifically supports PowerShell execution with suspicious command, parent process, content, or network behavior.

## Detection Signals

- PowerShell uses download, reflection, in-memory execution, hidden window, or execution-policy bypass
- Script Block Logging Event ID 4104 contains Invoke-Expression, WebClient, encoded data, or credential access
- PowerShell Operational Event IDs 4103 or 4104 originate from an unusual user or parent
- Process is launched by Office, browser, archive utility, service, WMI, or scheduled task
- If Sysmon is available, Event ID 1 shows suspicious command line and Event ID 3 shows outbound traffic

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with PowerShell execution with suspicious command, parent process, content, or network behavior.
- Confirm the raw detection fields that support: PowerShell uses download, reflection, in-memory execution, hidden window, or execution-policy bypass.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved administration, deployment, monitoring, or configuration script.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- PowerShell 4103 and 4104 records, module logs, transcript, and complete command line
- Security Event ID 4688 or Sysmon Event ID 1 process tree
- Downloaded content, script files, hashes, AMSI or Defender detections
- DNS, proxy, firewall, and Sysmon Event ID 3 network destinations
- User, device, administration, deployment, and security-testing context

## Investigation Steps

1. Build a timestamp-normalized timeline around PowerShell execution with suspicious command, parent process, content, or network behavior.
2. Preserve and verify the primary evidence: PowerShell 4103 and 4104 records, module logs, transcript, and complete command line.
3. Identify the initiating identity, process, device, and access path associated with: Script Block Logging Event ID 4104 contains Invoke-Expression, WebClient, encoded data, or credential access.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved administration, deployment, monitoring, or configuration script.
5. Review the additional technical indicator: PowerShell Operational Event IDs 4103 or 4104 originate from an unusual user or parent.
6. Correlate the event with initial document, browser download, archive, or email delivery and credential access, registry changes, services, tasks, wmi, and child processes.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Initial document, browser download, archive, or email delivery
- Credential access, registry changes, services, tasks, WMI, and child processes
- Defender configuration changes or exclusions
- Connections to rare or newly observed external destinations
- The same script hash, command fragment, or destination on other hosts

## False Positive Conditions

- Approved administration, deployment, monitoring, or configuration script
- Signed enterprise script from a trusted repository and expected operator
- Authorized security test within scope
- Vendor installer using PowerShell with validated hash and command line
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Script downloads or executes untrusted content in memory
- Obfuscation, credential access, defense evasion, or persistence is present
- Execution originates from a user application or unexplained remote session
- The script contacts suspicious infrastructure or affects multiple hosts
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Terminate the process after volatile evidence capture and analyst approval
- Quarantine scripts and block confirmed destinations through approved controls
- Isolate the endpoint when active malware or command-and-control is present
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove malicious scripts, payloads, tasks, services, and registry changes
- Restore PowerShell logging, Defender, and execution policy to approved settings
- Rotate credentials exposed by the script
- Constrain PowerShell through signing, language mode, application control, and least privilege
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of PowerShell execution with suspicious command, parent process, content, or network behavior are established and documented.
- The analyst collected and reviewed the required evidence, including powershell 4103 and 4104 records, module logs, transcript, and complete command line.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports PowerShell execution with suspicious command, parent process, content, or network behavior; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
