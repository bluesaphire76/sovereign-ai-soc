---
title: Windows Encoded PowerShell Command Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_encoded_powershell
  - obfuscated_command_execution
  - possible_malware_execution
severity_hint:
  - high
mitre_tactics:
  - Execution
  - Defense Evasion
mitre_techniques:
  - T1059.001
  - T1027
applicability:
  - Command line contains -EncodedCommand, -enc, FromBase64String, GZipStream, or character reconstruction
  - Event ID 4104 reveals decoded download, execution, credential, or persistence content
  - PowerShell runs hidden, noninteractive, bypassed, or without a profile
  - Parent process is Office, browser, script host, service, WMI, or scheduled task
not_applicable_when:
  - Approved deployment tool uses encoding to preserve script transport
  - Authorized security test contains the exact reviewed command
  - Signed vendor tooling produces a known encoded command
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - powershell
  - encoded-command
  - obfuscation
  - wazuh
---

# Windows Encoded PowerShell Command Playbook

## Purpose

This playbook supports investigation of PowerShell execution using encoded, compressed, concatenated, or otherwise obfuscated command content.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Command line contains -EncodedCommand, -enc, FromBase64String, GZipStream, or character reconstruction
- Event ID 4104 reveals decoded download, execution, credential, or persistence content
- PowerShell runs hidden, noninteractive, bypassed, or without a profile
- Parent process is Office, browser, script host, service, WMI, or scheduled task
- Use when the current incident evidence specifically supports PowerShell execution using encoded, compressed, concatenated, or otherwise obfuscated command content.

## Detection Signals

- Command line contains -EncodedCommand, -enc, FromBase64String, GZipStream, or character reconstruction
- Event ID 4104 reveals decoded download, execution, credential, or persistence content
- PowerShell runs hidden, noninteractive, bypassed, or without a profile
- Parent process is Office, browser, script host, service, WMI, or scheduled task
- Decoded content references external URLs, shellcode, AMSI bypass, or security exclusions

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with PowerShell execution using encoded, compressed, concatenated, or otherwise obfuscated command content.
- Confirm the raw detection fields that support: Command line contains -EncodedCommand, -enc, FromBase64String, GZipStream, or character reconstruction.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved deployment tool uses encoding to preserve script transport.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Original and safely decoded command with encoding method documented
- PowerShell 4103/4104, Security 4688, and process ancestry
- Payloads, URLs, domains, IPs, hashes, and file-system artifacts
- AMSI, Defender, proxy, DNS, firewall, and optional Sysmon Event IDs 1 and 3
- User session, delivery mechanism, and business justification

## Investigation Steps

1. Build a timestamp-normalized timeline around PowerShell execution using encoded, compressed, concatenated, or otherwise obfuscated command content.
2. Preserve and verify the primary evidence: Original and safely decoded command with encoding method documented.
3. Identify the initiating identity, process, device, and access path associated with: Event ID 4104 reveals decoded download, execution, credential, or persistence content.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved deployment tool uses encoding to preserve script transport.
5. Review the additional technical indicator: PowerShell runs hidden, noninteractive, bypassed, or without a profile.
6. Correlate the event with email, office, browser, archive, or script delivery before execution and child processes, registry changes, scheduled tasks, services, and wmi activity.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Email, Office, browser, archive, or script delivery before execution
- Child processes, registry changes, scheduled tasks, services, and WMI activity
- Defender tampering and security-log changes
- Outbound connections and DNS queries in the execution window
- Reuse of the encoded command or decoded indicators on other endpoints

## False Positive Conditions

- Approved deployment tool uses encoding to preserve script transport
- Authorized security test contains the exact reviewed command
- Signed vendor tooling produces a known encoded command
- Administrative automation has owner, repository, hash, and change record
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Decoded content downloads payloads, bypasses controls, or invokes shellcode
- The command is unexplained, unsigned, or launched from a user application
- Post-execution behavior includes persistence, credentials, or lateral movement
- Indicators appear across multiple hosts or accounts
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Stop the process after capturing command and memory-relevant evidence and approval
- Block confirmed payload sources and quarantine artifacts through approved controls
- Isolate the host when decoded behavior confirms active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove payloads and persistence created by the decoded command
- Restore Defender, AMSI, logging, and policy settings
- Rotate credentials accessed during execution
- Add detections for stable decoded indicators rather than broad encoding alone
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of PowerShell execution using encoded, compressed, concatenated, or otherwise obfuscated command content are established and documented.
- The analyst collected and reviewed the required evidence, including original and safely decoded command with encoding method documented.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports PowerShell execution using encoded, compressed, concatenated, or otherwise obfuscated command content; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
