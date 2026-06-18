---
title: Linux Persistence Mechanism Playbook
type: playbook
domain: linux_host
source: wazuh
incident_types:
  - linux_persistence_mechanism
  - unauthorized_persistence
  - post_compromise_persistence
severity_hint:
  - high
  - critical
mitre_tactics:
  - Persistence
  - Privilege Escalation
mitre_techniques:
  - T1053.003
  - T1543.002
  - T1098
applicability:
  - Unexpected systemd unit, timer, cron entry, rc script, shell profile, or init modification
  - New authorized key, local account, sudo rule, PAM module, or SSH configuration change
  - Modification to /etc/ld.so.preload, shared libraries, kernel modules, or boot configuration
  - Persistence artifact references a temporary, hidden, downloaded, or unsigned payload
not_applicable_when:
  - Approved package, agent, monitoring, backup, or configuration-management installation
  - Documented application startup configuration
  - Authorized administrator key or service account with valid governance record
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - linux
  - persistence
  - systemd
  - cron
  - ssh
  - wazuh
---

# Linux Persistence Mechanism Playbook

## Purpose

This playbook supports investigation of suspected Linux persistence spanning services, timers, cron, startup files, accounts, keys, or dynamic-loader configuration.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Unexpected systemd unit, timer, cron entry, rc script, shell profile, or init modification
- New authorized key, local account, sudo rule, PAM module, or SSH configuration change
- Modification to /etc/ld.so.preload, shared libraries, kernel modules, or boot configuration
- Persistence artifact references a temporary, hidden, downloaded, or unsigned payload
- Use when the current incident evidence specifically supports suspected Linux persistence spanning services, timers, cron, startup files, accounts, keys, or dynamic-loader configuration.

## Detection Signals

- Unexpected systemd unit, timer, cron entry, rc script, shell profile, or init modification
- New authorized key, local account, sudo rule, PAM module, or SSH configuration change
- Modification to /etc/ld.so.preload, shared libraries, kernel modules, or boot configuration
- Persistence artifact references a temporary, hidden, downloaded, or unsigned payload
- Artifact appears after suspicious login, privilege escalation, or malware execution

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with suspected Linux persistence spanning services, timers, cron, startup files, accounts, keys, or dynamic-loader configuration.
- Confirm the raw detection fields that support: Unexpected systemd unit, timer, cron entry, rc script, shell profile, or init modification.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved package, agent, monitoring, backup, or configuration-management installation.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Complete inventory and contents of changed persistence locations
- File hashes, ownership, permissions, timestamps, package ownership, and baseline differences
- Process tree and session that created each artifact
- Execution history, network activity, and child processes produced by persistence
- Authentication, identity, deployment, and host-owner records

## Investigation Steps

1. Build a timestamp-normalized timeline around suspected Linux persistence spanning services, timers, cron, startup files, accounts, keys, or dynamic-loader configuration.
2. Preserve and verify the primary evidence: Complete inventory and contents of changed persistence locations.
3. Identify the initiating identity, process, device, and access path associated with: New authorized key, local account, sudo rule, PAM module, or SSH configuration change.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved package, agent, monitoring, backup, or configuration-management installation.
5. Review the additional technical indicator: Modification to /etc/ld.so.preload, shared libraries, kernel modules, or boot configuration.
6. Correlate the event with ssh, sudo, account, group, package, cron, and systemd events and dns, suricata, firewall, and proxy traffic from persisted processes.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- SSH, sudo, account, group, package, cron, and systemd events
- DNS, Suricata, firewall, and proxy traffic from persisted processes
- Credential access, sensitive file reads, and lateral movement
- Matching artifact names, hashes, or destinations across hosts
- Previous incidents and threat intelligence for the persistence method

## False Positive Conditions

- Approved package, agent, monitoring, backup, or configuration-management installation
- Documented application startup configuration
- Authorized administrator key or service account with valid governance record
- Security test artifact within approved scope and cleanup window
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Persistence executes as root or survives reboot without authorization
- Artifact launches malware, a reverse shell, credential theft, or command-and-control
- Multiple persistence mechanisms are present
- The creator identity or source session is compromised or unknown
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Disable persistence only after collecting the artifact and receiving approval
- Revoke affected accounts, keys, or sessions through the containment workflow
- Isolate the host if persistence maintains active attacker access
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove every confirmed persistence artifact and associated payload
- Restore startup, identity, SSH, loader, and service configuration from trusted baseline
- Rotate credentials and inspect other hosts reached by the affected identity
- Hunt for the same mechanism, hash, key, account, or destination across the estate
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of suspected Linux persistence spanning services, timers, cron, startup files, accounts, keys, or dynamic-loader configuration are established and documented.
- The analyst collected and reviewed the required evidence, including complete inventory and contents of changed persistence locations.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports suspected Linux persistence spanning services, timers, cron, startup files, accounts, keys, or dynamic-loader configuration; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
