---
title: Windows Sysmon Suspicious Process Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_sysmon_suspicious_process
  - suspicious_process_execution
  - process_anomaly
severity_hint:
  - medium
  - high
mitre_tactics:
  - Defense Evasion
  - Privilege Escalation
mitre_techniques:
  - T1055
applicability:
  - Wazuh reports Sysmon suspicious process or process-anomaly activity
  - Sysmon Event ID 1 contains an unusual image, parent, command line, user, or integrity level
  - A trusted Windows binary executes from an unexpected path or with unusual arguments
  - Process ancestry conflicts with the endpoint role, software inventory, or expected installer chain
not_applicable_when:
  - Approved software installation or update explains the complete process tree
  - Signed enterprise software matches the expected path, hash, owner, and change window
  - Authorized administration or security testing is validated within scope
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - sysmon
  - process
  - process-anomaly
  - event-1
  - wazuh
---

# Windows Sysmon Suspicious Process Playbook

## Purpose

This playbook supports investigation of suspicious Windows process creation detected through Sysmon Event ID 1 and Wazuh process-anomaly rules.

It focuses on process identity, ancestry, command line, integrity, hash, signer, user context, and related endpoint or network behavior.

## When to Use

- Wazuh reports `Sysmon - Suspicious Process` or a `sysmon_process-anomalies` rule.
- Sysmon Event ID 1 contains an unexpected process image, parent-child relationship, command line, user, or integrity level.
- A Windows binary runs from an unusual directory, launches an unexpected child, or receives anomalous arguments.
- The alert maps to process injection or another execution or defense-evasion technique but the raw process evidence still requires validation.
- Use only when current Sysmon process telemetry supports this scenario.

## Detection Signals

- Sysmon Event ID 1 with image, original filename, command line, current directory, user, integrity level, hash, and process GUID.
- Parent image or parent command line is inconsistent with the child process or endpoint baseline.
- Binary path, company, product, signature, or hash differs from the expected Windows or application version.
- Process executes from a temporary, user-writable, installer, download, archive, or application cache directory.
- Follow-on file, registry, service, task, PowerShell, Defender, DNS, or network activity increases confidence.

## Initial Triage

- Confirm the raw Sysmon Event ID, Wazuh rule ID, host, UTC timestamp, process GUID, and process ID.
- Review the full child and parent command lines before classifying the executable name as malicious.
- Verify image path, original filename, company, product, version, hash, signer, user, parent user, and integrity level.
- Determine whether an installer, updater, endpoint-management tool, or approved application explains the complete ancestry.
- Preserve the original Sysmon and Wazuh records before process termination or file quarantine.

## Evidence to Collect

- Complete Sysmon Event ID 1 record and Wazuh alert.
- Child and parent process GUIDs, IDs, images, command lines, users, and integrity levels.
- SHA-256 hash, Authenticode signer, file version, creation time, and filesystem path.
- Related Sysmon Event IDs 3, 7, 8, 10, 11, 12, 13, 14, 22, and 25 where available.
- Defender or EDR alerts, software inventory, installer logs, change records, and endpoint owner confirmation.

## Investigation Steps

1. Build a timestamp-normalized process tree using process GUIDs rather than process IDs alone.
2. Validate the child image path, original filename, hash, signer, version, and command line.
3. Determine how the parent process started, which account initiated it, and whether privilege or session context changed.
4. Compare the complete process chain with approved software, installer, updater, administration, and endpoint-role baselines.
5. Review child processes, loaded modules, file writes, registry changes, services, tasks, and network destinations.
6. Search for the same hash, command line, parent-child pair, signer, or destination across other endpoints.
7. Resolve any Wazuh MITRE mapping against observed behavior; do not treat a technique label as proof.
8. Classify the event as expected software behavior, suspicious execution, or confirmed compromise with reproducible evidence.

## Correlation Checks

- Sysmon network, image-load, process-access, file-create, registry, DNS, and process-tampering events.
- Windows Security 4624, 4648, 4672, and 4688 records for the same user or Logon ID.
- Defender, PowerShell, scheduled task, service, registry, application-control, and EDR telemetry.
- Installer, update, software inventory, device-management, and change-management records.
- Matching process ancestry, hash, command line, or destination on peer endpoints.

## False Positive Conditions

- Approved installer or updater produces the exact expected process tree, path, signer, hash, and command line.
- Vendor software uses a Windows binary in a documented and owner-validated way.
- Enterprise management, packaging, monitoring, or security tooling explains the activity.
- Authorized testing reproduces the detection within its approved time and asset scope.
- A benign conclusion requires raw process evidence and accountable owner validation.

## Escalation Criteria

- Image, hash, signer, parent, command line, user, or integrity context is unauthorized or cannot be explained.
- Process access, injection, hollowing, tampering, credential access, persistence, or defense evasion is supported by telemetry.
- The process launches payloads, changes security controls, or contacts suspicious infrastructure.
- Equivalent unexplained activity appears on multiple hosts or privileged sessions.
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Preserve process, file, memory, and network evidence before disruptive action.
- Terminate or quarantine the process only after analyst approval and scope review.
- Isolate the endpoint when active compromise or command-and-control is supported by evidence.
- Restrict a responsible account through the governed containment workflow when misuse is established.
- Record approver, scope, expected impact, and rollback or recovery requirements.

## Remediation Actions

- Remove confirmed malicious files, persistence, services, tasks, registry changes, and related payloads.
- Restore affected binaries or application components from authoritative sources.
- Correct vulnerable or unauthorized software and rotate exposed credentials where supported.
- Improve process-ancestry, signer, hash, path, and command-line allowlists without broad suppression.
- Validate remediation with fresh Sysmon, Defender, process, and network telemetry.

## Closure Criteria

- Child and parent process identity, path, command line, hash, signer, user, and integrity were reviewed.
- The initiating mechanism and complete process ancestry are documented.
- Related endpoint, authentication, persistence, Defender, and network evidence was reviewed or marked unavailable.
- Benign activity is validated by authoritative software or owner evidence.
- Approved containment and remediation are complete and verified.
- Residual risk and any detection improvement have an owner.
- Closure requires analyst approval and follows incident or case governance.

## Analyst Notes

- Executable name alone is not sufficient; path, signer, hash, command line, parent, and user context are decisive.
- Sysmon Event ID 1 records process creation and does not by itself prove process injection.
- Qdrant and LLM output remain advisory; raw Sysmon and Wazuh telemetry is authoritative.
- Historical incidents are supporting context and must not determine classification or closure.
