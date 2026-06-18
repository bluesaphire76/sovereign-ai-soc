---
title: Suspicious Binary Execution From Temporary Path Playbook
type: playbook
domain: linux_host
source: wazuh
incident_types:
  - suspicious_binary_execution_tmp
  - temporary_path_execution
  - possible_malware_execution
severity_hint:
  - high
mitre_tactics:
  - Execution
  - Defense Evasion
mitre_techniques:
  - T1059
  - T1204
applicability:
  - Process executes from /tmp, /var/tmp, /dev/shm, Downloads, or a hidden user directory
  - Executable was created or downloaded shortly before launch
  - Binary has no package ownership, trusted signature, or expected deployment source
  - Command line includes deleted executable, memfd, chmod, curl, wget, or shell staging
not_applicable_when:
  - Approved installer or update script that stages files in a temporary directory
  - Security testing tool executed during an authorized exercise
  - Application build or CI job with a documented temporary execution path
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - linux
  - temporary-path
  - binary-execution
  - malware
  - wazuh
---

# Suspicious Binary Execution From Temporary Path Playbook

## Purpose

This playbook supports investigation of execution of a binary or script from a Linux temporary or other user-writable location.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Process executes from /tmp, /var/tmp, /dev/shm, Downloads, or a hidden user directory
- Executable was created or downloaded shortly before launch
- Binary has no package ownership, trusted signature, or expected deployment source
- Command line includes deleted executable, memfd, chmod, curl, wget, or shell staging
- Use when the current incident evidence specifically supports execution of a binary or script from a Linux temporary or other user-writable location.

## Detection Signals

- Process executes from /tmp, /var/tmp, /dev/shm, Downloads, or a hidden user directory
- Executable was created or downloaded shortly before launch
- Binary has no package ownership, trusted signature, or expected deployment source
- Command line includes deleted executable, memfd, chmod, curl, wget, or shell staging
- Process opens external connections, modifies persistence, or accesses credentials

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with execution of a binary or script from a Linux temporary or other user-writable location.
- Confirm the raw detection fields that support: Process executes from /tmp, /var/tmp, /dev/shm, Downloads, or a hidden user directory.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved installer or update script that stages files in a temporary directory.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Executable bytes, hash, path, owner, permissions, timestamps, and package ownership
- Full process tree, command line, environment, effective UID, and terminal
- File creation, download source, DNS lookups, and network connections
- Open files, child processes, persistence changes, and deleted-file state
- User, host owner, software deployment, and security-tool validation

## Investigation Steps

1. Build a timestamp-normalized timeline around execution of a binary or script from a Linux temporary or other user-writable location.
2. Preserve and verify the primary evidence: Executable bytes, hash, path, owner, permissions, timestamps, and package ownership.
3. Identify the initiating identity, process, device, and access path associated with: Executable was created or downloaded shortly before launch.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved installer or update script that stages files in a temporary directory.
5. Review the additional technical indicator: Binary has no package ownership, trusted signature, or expected deployment source.
6. Correlate the event with web proxy, dns, and suricata events for the download or callback and authentication and sudo activity for the executing user.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Web proxy, DNS, and Suricata events for the download or callback
- Authentication and sudo activity for the executing user
- Cron, systemd, shell profile, and SSH key changes after execution
- The same hash or destination on other hosts
- Historical incidents involving the same path, user, or binary

## False Positive Conditions

- Approved installer or update script that stages files in a temporary directory
- Security testing tool executed during an authorized exercise
- Application build or CI job with a documented temporary execution path
- Vendor software whose expected behavior and hash are confirmed
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- The binary is unknown, packed, deleted after launch, or associated with malicious infrastructure
- Execution occurs as root or after suspicious authentication
- The process creates persistence, reverse shell, credential access, or lateral movement
- The same artifact appears on multiple hosts without authorization
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Suspend or terminate the process after volatile evidence capture and approval
- Quarantine the artifact and block confirmed destinations through approved controls
- Isolate the host when active command-and-control or lateral movement is present
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove the artifact, staging files, persistence, and unauthorized tools
- Restore affected files and services from trusted sources
- Rotate credentials exposed to the process and review adjacent hosts
- Restrict execution from writable paths where operationally feasible
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of execution of a binary or script from a Linux temporary or other user-writable location are established and documented.
- The analyst collected and reviewed the required evidence, including executable bytes, hash, path, owner, permissions, timestamps, and package ownership.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports execution of a binary or script from a Linux temporary or other user-writable location; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
