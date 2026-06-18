---
title: Suspicious Linux Cron Job Playbook
type: playbook
domain: linux_host
source: wazuh
incident_types:
  - suspicious_cron_job
  - cron_persistence
  - scheduled_execution
severity_hint:
  - medium
  - high
mitre_tactics:
  - Persistence
  - Execution
mitre_techniques:
  - T1053.003
applicability:
  - Wazuh FIM alert for /etc/crontab, /etc/cron.d, /var/spool/cron, or user crontabs
  - New cron entry launches shell, curl, wget, Python, Perl, netcat, or an unknown binary
  - Job executes from /tmp, /var/tmp, /dev/shm, a hidden directory, or a user-writable path
  - Crontab modification follows suspicious SSH, sudo, download, or account activity
not_applicable_when:
  - Approved backup, monitoring, certificate, cleanup, or application job
  - Configuration-management deployment matching the expected template
  - Package installation that creates a documented cron entry
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - linux
  - cron
  - scheduled-task
  - persistence
  - wazuh
---

# Suspicious Linux Cron Job Playbook

## Purpose

This playbook supports investigation of creation or modification of a cron entry that may provide scheduled execution or persistence.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Wazuh FIM alert for /etc/crontab, /etc/cron.d, /var/spool/cron, or user crontabs
- New cron entry launches shell, curl, wget, Python, Perl, netcat, or an unknown binary
- Job executes from /tmp, /var/tmp, /dev/shm, a hidden directory, or a user-writable path
- Crontab modification follows suspicious SSH, sudo, download, or account activity
- Use when the current incident evidence specifically supports creation or modification of a cron entry that may provide scheduled execution or persistence.

## Detection Signals

- Wazuh FIM alert for /etc/crontab, /etc/cron.d, /var/spool/cron, or user crontabs
- New cron entry launches shell, curl, wget, Python, Perl, netcat, or an unknown binary
- Job executes from /tmp, /var/tmp, /dev/shm, a hidden directory, or a user-writable path
- Crontab modification follows suspicious SSH, sudo, download, or account activity
- High-frequency schedule, encoded command, output redirection, or environment manipulation

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with creation or modification of a cron entry that may provide scheduled execution or persistence.
- Confirm the raw detection fields that support: Wazuh FIM alert for /etc/crontab, /etc/cron.d, /var/spool/cron, or user crontabs.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved backup, monitoring, certificate, cleanup, or application job.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Complete crontab entry, owner, schedule, environment, and file metadata
- Command, script, binary, hash, parent process, and creation source
- cron daemon logs and execution timestamps
- Network, DNS, file, and process activity produced by each execution
- Deployment, backup, maintenance, or application-owner records

## Investigation Steps

1. Build a timestamp-normalized timeline around creation or modification of a cron entry that may provide scheduled execution or persistence.
2. Preserve and verify the primary evidence: Complete crontab entry, owner, schedule, environment, and file metadata.
3. Identify the initiating identity, process, device, and access path associated with: New cron entry launches shell, curl, wget, Python, Perl, netcat, or an unknown binary.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved backup, monitoring, certificate, cleanup, or application job.
5. Review the additional technical indicator: Job executes from /tmp, /var/tmp, /dev/shm, a hidden directory, or a user-writable path.
6. Correlate the event with authentication and sudo activity before the cron change and downloaded files or scripts referenced by the job.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Authentication and sudo activity before the cron change
- Downloaded files or scripts referenced by the job
- Outbound connections repeating on the cron schedule
- Related systemd timers, at jobs, user accounts, or SSH keys
- Matching cron entries across similar hosts

## False Positive Conditions

- Approved backup, monitoring, certificate, cleanup, or application job
- Configuration-management deployment matching the expected template
- Package installation that creates a documented cron entry
- Temporary maintenance job with owner, ticket, and expiration
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- The job runs as root from a writable or temporary path
- The command downloads content, opens a reverse shell, or uses obfuscation
- The owner cannot validate the job or no deployment record exists
- Execution correlates with beaconing, malware, privilege escalation, or data transfer
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Disable the cron entry after preserving content and receiving approval
- Block confirmed malicious destinations through the containment workflow
- Isolate the host if scheduled execution is actively maintaining compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove unauthorized cron files, spool entries, scripts, and downloaded payloads
- Restore approved scheduled jobs from configuration management
- Rotate credentials used by the job if scripts or environment files exposed secrets
- Monitor cron paths and command patterns for recurrence
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of creation or modification of a cron entry that may provide scheduled execution or persistence are established and documented.
- The analyst collected and reviewed the required evidence, including complete crontab entry, owner, schedule, environment, and file metadata.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports creation or modification of a cron entry that may provide scheduled execution or persistence; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
