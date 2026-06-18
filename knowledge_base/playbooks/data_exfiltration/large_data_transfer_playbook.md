---
title: Large Outbound Data Transfer Playbook
type: playbook
domain: data_exfiltration
source: suricata
incident_types:
  - large_data_transfer
  - bulk_outbound_transfer
  - possible_data_exfiltration
severity_hint:
  - high
  - critical
mitre_tactics:
  - Exfiltration
mitre_techniques:
  - T1041
  - T1048
applicability:
  - Outbound bytes exceed role-based or historical transfer thresholds
  - Large upload targets rare cloud storage, file-sharing, raw IP, or external host
  - Transfer occurs outside approved time, process, user, or business workflow
  - Archive, compression, encryption, or staging activity precedes the transfer
not_applicable_when:
  - Approved backup, replication, migration, release, or data-delivery job
  - Documented transfer to an authorized partner or cloud tenant
  - Business process with expected volume, source data, owner, and schedule
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - exfiltration
  - large-transfer
  - suricata
  - data-loss
  - outbound
---

# Large Outbound Data Transfer Playbook

## Purpose

This playbook supports investigation of outbound transfer volume materially above the expected baseline for a host, user, process, or destination.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Outbound bytes exceed role-based or historical transfer thresholds
- Large upload targets rare cloud storage, file-sharing, raw IP, or external host
- Transfer occurs outside approved time, process, user, or business workflow
- Archive, compression, encryption, or staging activity precedes the transfer
- Use when the current incident evidence specifically supports outbound transfer volume materially above the expected baseline for a host, user, process, or destination.

## Detection Signals

- Outbound bytes exceed role-based or historical transfer thresholds
- Large upload targets rare cloud storage, file-sharing, raw IP, or external host
- Transfer occurs outside approved time, process, user, or business workflow
- Archive, compression, encryption, or staging activity precedes the transfer
- Traffic uses unusual protocol, port, direct connection, or DNS channel

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with outbound transfer volume materially above the expected baseline for a host, user, process, or destination.
- Confirm the raw detection fields that support: Outbound bytes exceed role-based or historical transfer thresholds.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved backup, replication, migration, release, or data-delivery job.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Flow and proxy records with bytes, duration, protocol, destination, and time series
- Files accessed, staged, archived, encrypted, or uploaded
- Endpoint process, command line, user, parent, and open-file evidence
- Data classification, source repository, host role, and user authorization
- Destination ownership, transfer ticket, partner agreement, and retention context

## Investigation Steps

1. Build a timestamp-normalized timeline around outbound transfer volume materially above the expected baseline for a host, user, process, or destination.
2. Preserve and verify the primary evidence: Flow and proxy records with bytes, duration, protocol, destination, and time series.
3. Identify the initiating identity, process, device, and access path associated with: Large upload targets rare cloud storage, file-sharing, raw IP, or external host.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved backup, replication, migration, release, or data-delivery job.
5. Review the additional technical indicator: Transfer occurs outside approved time, process, user, or business workflow.
6. Correlate the event with file access, archive utilities, cloud clients, scripts, and removable media and authentication anomalies, privilege escalation, and account compromise.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- File access, archive utilities, cloud clients, scripts, and removable media
- Authentication anomalies, privilege escalation, and account compromise
- DNS, TLS, Suricata, DLP, proxy, and CASB alerts
- Other large transfers by the same user or to the same destination
- Historical baseline and approved batch or backup schedules

## False Positive Conditions

- Approved backup, replication, migration, release, or data-delivery job
- Documented transfer to an authorized partner or cloud tenant
- Business process with expected volume, source data, owner, and schedule
- Security or disaster-recovery exercise within approved scope
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Sensitive or regulated data is involved without authorization
- Destination, user, process, or time is unexplained
- The transfer follows account compromise, malware, or data staging
- Volume is increasing, repeated, or distributed across destinations
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Pause or block the transfer only after evidence review and approval
- Restrict the account, token, or destination through the containment workflow
- Isolate the host if active unauthorized transfer continues
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove unauthorized tools, scripts, archives, and persistence
- Revoke exposed tokens and rotate credentials
- Correct egress, DLP, sharing, and access-control gaps
- Complete data-impact, legal, privacy, and notification review where required
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of outbound transfer volume materially above the expected baseline for a host, user, process, or destination are established and documented.
- The analyst collected and reviewed the required evidence, including flow and proxy records with bytes, duration, protocol, destination, and time series.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports outbound transfer volume materially above the expected baseline for a host, user, process, or destination; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
