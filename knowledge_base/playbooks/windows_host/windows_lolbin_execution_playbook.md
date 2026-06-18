---
title: Windows LOLBin Execution Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_lolbin_execution
  - proxy_execution
  - defense_evasion
severity_hint:
  - medium
  - high
mitre_tactics:
  - Defense Evasion
  - Execution
mitre_techniques:
  - T1218
  - T1105
applicability:
  - rundll32, regsvr32, mshta, certutil, bitsadmin, installutil, msbuild, or wmic uses unusual arguments
  - Trusted binary loads content from a URL, user-writable path, scriptlet, or remote share
  - Process parent is Office, browser, archive tool, script host, or unexpected service
  - Command line references JavaScript, DLL exports, encoded data, alternate data streams, or remote files
not_applicable_when:
  - Approved software installation or enterprise management workflow
  - Documented vendor component invokes the binary with a validated command line
  - Authorized security testing within scope
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - lolbin
  - proxy-execution
  - defense-evasion
  - wazuh
---

# Windows LOLBin Execution Playbook

## Purpose

This playbook supports investigation of suspicious use of a trusted Windows binary to proxy execution, download content, or evade controls.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- rundll32, regsvr32, mshta, certutil, bitsadmin, installutil, msbuild, or wmic uses unusual arguments
- Trusted binary loads content from a URL, user-writable path, scriptlet, or remote share
- Process parent is Office, browser, archive tool, script host, or unexpected service
- Command line references JavaScript, DLL exports, encoded data, alternate data streams, or remote files
- Use when the current incident evidence specifically supports suspicious use of a trusted Windows binary to proxy execution, download content, or evade controls.

## Detection Signals

- rundll32, regsvr32, mshta, certutil, bitsadmin, installutil, msbuild, or wmic uses unusual arguments
- Trusted binary loads content from a URL, user-writable path, scriptlet, or remote share
- Process parent is Office, browser, archive tool, script host, or unexpected service
- Command line references JavaScript, DLL exports, encoded data, alternate data streams, or remote files
- If Sysmon is available, Event ID 1 shows execution and Event ID 3 shows related network activity

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with suspicious use of a trusted Windows binary to proxy execution, download content, or evade controls.
- Confirm the raw detection fields that support: rundll32, regsvr32, mshta, certutil, bitsadmin, installutil, msbuild, or wmic uses unusual arguments.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved software installation or enterprise management workflow.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Full process tree, command line, working directory, user, integrity level, and hashes
- Referenced DLL, scriptlet, document, URL, certificate, BITS job, or remote share
- Security 4688 and optional Sysmon Event IDs 1, 3, 7, and 11
- DNS, proxy, firewall, Defender, and application-control records
- Software deployment, administrator, vendor, and security-test validation

## Investigation Steps

1. Build a timestamp-normalized timeline around suspicious use of a trusted Windows binary to proxy execution, download content, or evade controls.
2. Preserve and verify the primary evidence: Full process tree, command line, working directory, user, integrity level, and hashes.
3. Identify the initiating identity, process, device, and access path associated with: Trusted binary loads content from a URL, user-writable path, scriptlet, or remote share.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved software installation or enterprise management workflow.
5. Review the additional technical indicator: Process parent is Office, browser, archive tool, script host, or unexpected service.
6. Correlate the event with file download or email delivery preceding lolbin execution and child processes, persistence, credential access, and security-control changes.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- File download or email delivery preceding LOLBin execution
- Child processes, persistence, credential access, and security-control changes
- Network connections and DNS requests from the trusted binary
- The same command, file hash, URL, or parent process across endpoints
- Successful logon or remote execution before the event

## False Positive Conditions

- Approved software installation or enterprise management workflow
- Documented vendor component invokes the binary with a validated command line
- Authorized security testing within scope
- Administrator action from an approved jump host with matching ticket
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- The trusted binary retrieves or runs untrusted remote content
- Command line matches known proxy-execution patterns and lacks business context
- Execution is followed by persistence, command-and-control, or credential access
- Application-control or Defender alerts corroborate malicious use
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Terminate the process and quarantine referenced content after approval
- Block confirmed URLs, domains, or hashes through governed controls
- Isolate the endpoint when proxy execution is part of active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove payloads, BITS jobs, scriptlets, services, tasks, and registry persistence
- Restore application-control and Defender policy
- Rotate exposed credentials and review remote systems accessed
- Constrain high-risk LOLBins where business usage permits
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of suspicious use of a trusted Windows binary to proxy execution, download content, or evade controls are established and documented.
- The analyst collected and reviewed the required evidence, including full process tree, command line, working directory, user, integrity level, and hashes.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports suspicious use of a trusted Windows binary to proxy execution, download content, or evade controls; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
