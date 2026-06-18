---
title: Sensitive Linux File Modification Playbook
type: playbook
domain: linux_host
source: wazuh
incident_types:
  - sensitive_file_modification
  - linux_configuration_tampering
  - credential_file_change
severity_hint:
  - high
  - critical
mitre_tactics:
  - Persistence
  - Privilege Escalation
  - Defense Evasion
mitre_techniques:
  - T1098
  - T1112
applicability:
  - Wazuh file-integrity alert for /etc/passwd, /etc/shadow, /etc/sudoers, or /etc/sudoers.d
  - Change to sshd_config, authorized_keys, PAM configuration, or trusted authentication files
  - File ownership, mode, ACL, immutable flag, or hash changed unexpectedly
  - Direct editor, shell redirection, sed, perl, or script write to a protected file
not_applicable_when:
  - Approved hardening, identity, or SSH configuration deployment
  - Authorized password rotation or account lifecycle operation
  - Package upgrade that changes vendor-managed PAM or SSH files
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - linux
  - fim
  - passwd
  - sudoers
  - ssh
  - wazuh
---

# Sensitive Linux File Modification Playbook

## Purpose

This playbook supports investigation of unauthorized modification of Linux identity, privilege, authentication, or remote-access configuration.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Wazuh file-integrity alert for /etc/passwd, /etc/shadow, /etc/sudoers, or /etc/sudoers.d
- Change to sshd_config, authorized_keys, PAM configuration, or trusted authentication files
- File ownership, mode, ACL, immutable flag, or hash changed unexpectedly
- Direct editor, shell redirection, sed, perl, or script write to a protected file
- Use when the current incident evidence specifically supports unauthorized modification of Linux identity, privilege, authentication, or remote-access configuration.

## Detection Signals

- Wazuh file-integrity alert for /etc/passwd, /etc/shadow, /etc/sudoers, or /etc/sudoers.d
- Change to sshd_config, authorized_keys, PAM configuration, or trusted authentication files
- File ownership, mode, ACL, immutable flag, or hash changed unexpectedly
- Direct editor, shell redirection, sed, perl, or script write to a protected file
- Sensitive change following suspicious login, sudo, package, or service activity

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with unauthorized modification of Linux identity, privilege, authentication, or remote-access configuration.
- Confirm the raw detection fields that support: Wazuh file-integrity alert for /etc/passwd, /etc/shadow, /etc/sudoers, or /etc/sudoers.d.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved hardening, identity, or SSH configuration deployment.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Wazuh FIM before-and-after hashes, diff, actor, and timestamp
- Current and trusted-baseline copies of each modified file
- auditd file-write and process-execution records
- Sudo, shell, SSH, package-manager, and configuration-management history
- Change ticket and asset-owner validation

## Investigation Steps

1. Build a timestamp-normalized timeline around unauthorized modification of Linux identity, privilege, authentication, or remote-access configuration.
2. Preserve and verify the primary evidence: Wazuh FIM before-and-after hashes, diff, actor, and timestamp.
3. Identify the initiating identity, process, device, and access path associated with: Change to sshd_config, authorized_keys, PAM configuration, or trusted authentication files.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved hardening, identity, or SSH configuration deployment.
5. Review the additional technical indicator: File ownership, mode, ACL, immutable flag, or hash changed unexpectedly.
6. Correlate the event with account and group changes introduced by the modified files and successful logins or privilege use after the modification.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Account and group changes introduced by the modified files
- Successful logins or privilege use after the modification
- Systemd, cron, binary, and network activity by the modifying process
- The same file modification across peer hosts
- Configuration-management drift and deployment records

## False Positive Conditions

- Approved hardening, identity, or SSH configuration deployment
- Authorized password rotation or account lifecycle operation
- Package upgrade that changes vendor-managed PAM or SSH files
- Configuration-management correction matching a reviewed baseline
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- The change creates privileged access, weakens authentication, or installs an unknown key
- The actor, parent process, or source session is unexplained
- The file was modified on multiple hosts outside change control
- New access or suspicious execution follows the modification
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Prevent further privileged access only after preserving the changed files and approval
- Revoke unauthorized keys or sessions through the containment workflow
- Isolate the host when tampering supports active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Restore files from a trusted baseline and validate ownership, mode, ACLs, and syntax
- Remove unauthorized accounts, keys, sudo rules, or PAM changes
- Rotate exposed credentials and review identity changes on related systems
- Improve FIM coverage and change-control correlation for sensitive paths
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of unauthorized modification of Linux identity, privilege, authentication, or remote-access configuration are established and documented.
- The analyst collected and reviewed the required evidence, including wazuh fim before-and-after hashes, diff, actor, and timestamp.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports unauthorized modification of Linux identity, privilege, authentication, or remote-access configuration; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
