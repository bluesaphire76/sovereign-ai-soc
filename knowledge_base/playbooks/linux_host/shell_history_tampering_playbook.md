---
title: Linux Shell History Tampering Playbook
type: playbook
domain: linux_host
source: wazuh
incident_types:
  - shell_history_tampering
  - anti_forensics
  - indicator_removal
severity_hint:
  - medium
  - high
mitre_tactics:
  - Defense Evasion
mitre_techniques:
  - T1070
applicability:
  - Wazuh FIM alert for .bash_history, .zsh_history, or other shell history files
  - Commands use history -c, unset HISTFILE, HISTSIZE=0, truncate, shred, or rm
  - History file size, ownership, timestamps, or symlink target changes unexpectedly
  - Shell profile modifies HISTCONTROL, HISTIGNORE, PROMPT_COMMAND, or history destination
not_applicable_when:
  - Approved privacy or shell-hardening policy documented for the account
  - Automated profile deployment that intentionally changes history retention
  - Controlled security exercise with recorded scope
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - linux
  - shell-history
  - anti-forensics
  - defense-evasion
  - wazuh
---

# Linux Shell History Tampering Playbook

## Purpose

This playbook supports investigation of deletion, truncation, redirection, or suppression of Linux shell history.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Wazuh FIM alert for .bash_history, .zsh_history, or other shell history files
- Commands use history -c, unset HISTFILE, HISTSIZE=0, truncate, shred, or rm
- History file size, ownership, timestamps, or symlink target changes unexpectedly
- Shell profile modifies HISTCONTROL, HISTIGNORE, PROMPT_COMMAND, or history destination
- Use when the current incident evidence specifically supports deletion, truncation, redirection, or suppression of Linux shell history.

## Detection Signals

- Wazuh FIM alert for .bash_history, .zsh_history, or other shell history files
- Commands use history -c, unset HISTFILE, HISTSIZE=0, truncate, shred, or rm
- History file size, ownership, timestamps, or symlink target changes unexpectedly
- Shell profile modifies HISTCONTROL, HISTIGNORE, PROMPT_COMMAND, or history destination
- History tampering follows privileged access, suspicious commands, or malware execution

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with deletion, truncation, redirection, or suppression of Linux shell history.
- Confirm the raw detection fields that support: Wazuh FIM alert for .bash_history, .zsh_history, or other shell history files.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved privacy or shell-hardening policy documented for the account.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- FIM records, file metadata, prior hash, and recoverable history content
- auditd, sudo, process accounting, terminal, and authentication records
- Shell profile and environment changes affecting history behavior
- Commands executed before and after the tampering window from independent telemetry
- User explanation, administrative procedure, and maintenance record

## Investigation Steps

1. Build a timestamp-normalized timeline around deletion, truncation, redirection, or suppression of Linux shell history.
2. Preserve and verify the primary evidence: FIM records, file metadata, prior hash, and recoverable history content.
3. Identify the initiating identity, process, device, and access path associated with: Commands use history -c, unset HISTFILE, HISTSIZE=0, truncate, shred, or rm.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved privacy or shell-hardening policy documented for the account.
5. Review the additional technical indicator: History file size, ownership, timestamps, or symlink target changes unexpectedly.
6. Correlate the event with sudo, ssh, process, package, cron, and systemd activity in the same session and file deletion, log clearing, timestomping, or audit configuration changes.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Sudo, SSH, process, package, cron, and systemd activity in the same session
- File deletion, log clearing, timestomping, or audit configuration changes
- Outbound network or DNS activity after history suppression
- Other hosts accessed by the same account
- Similar anti-forensics incidents involving the same identity

## False Positive Conditions

- Approved privacy or shell-hardening policy documented for the account
- Automated profile deployment that intentionally changes history retention
- Controlled security exercise with recorded scope
- Legitimate cleanup performed under an approved incident-response procedure
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Tampering occurs in a privileged or suspicious remote session
- Independent telemetry shows commands associated with persistence or credential access
- The user denies the activity or the session source is anomalous
- History suppression is combined with log clearing or audit disabling
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Preserve independent audit, process, and authentication evidence before session termination
- Revoke the affected session or account after approval when compromise is likely
- Isolate the host if anti-forensics accompanies active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Restore approved shell history and audit configuration
- Remove malicious profile changes and unauthorized cleanup scripts
- Rotate credentials when the tampering session is unauthorized
- Improve auditd or process-accounting coverage independent of user history files
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of deletion, truncation, redirection, or suppression of Linux shell history are established and documented.
- The analyst collected and reviewed the required evidence, including fim records, file metadata, prior hash, and recoverable history content.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports deletion, truncation, redirection, or suppression of Linux shell history; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
