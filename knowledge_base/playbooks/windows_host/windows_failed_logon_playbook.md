---
title: Windows Failed Logon Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_failed_logon
  - repeated_failed_logon
  - credential_attack
severity_hint:
  - low
  - medium
  - high
mitre_tactics:
  - Credential Access
mitre_techniques:
  - T1110
applicability:
  - Windows Security Event ID 4625 repeated for one account, source, or destination
  - Failure Status and SubStatus indicate bad password, disabled account, lockout, or logon restriction
  - Logon Type 3 or 10 failures originate from an unusual workstation or external address
  - One source targets many accounts or one account is tested from many sources
not_applicable_when:
  - User entered an old password after a documented credential change
  - Approved vulnerability scanner or authentication test generated the failures
  - Service, scheduled task, mapped drive, or application retained stale credentials
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - failed-logon
  - authentication
  - event-4625
  - wazuh
---

# Windows Failed Logon Playbook

## Purpose

This playbook supports investigation of repeated or anomalous Windows authentication failures that may indicate credential attack.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Windows Security Event ID 4625 repeated for one account, source, or destination
- Failure Status and SubStatus indicate bad password, disabled account, lockout, or logon restriction
- Logon Type 3 or 10 failures originate from an unusual workstation or external address
- One source targets many accounts or one account is tested from many sources
- Use when the current incident evidence specifically supports repeated or anomalous Windows authentication failures that may indicate credential attack.

## Detection Signals

- Windows Security Event ID 4625 repeated for one account, source, or destination
- Failure Status and SubStatus indicate bad password, disabled account, lockout, or logon restriction
- Logon Type 3 or 10 failures originate from an unusual workstation or external address
- One source targets many accounts or one account is tested from many sources
- Failures precede Event ID 4624 success, account lockout, or privileged activity

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with repeated or anomalous Windows authentication failures that may indicate credential attack.
- Confirm the raw detection fields that support: Windows Security Event ID 4625 repeated for one account, source, or destination.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: User entered an old password after a documented credential change.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Event ID 4625 fields including account, source address, workstation, logon type, status, and process
- Domain controller and destination-host authentication timeline
- Event IDs 4624, 4648, 4740, and relevant VPN or identity-provider records
- Asset ownership, account role, expected source systems, and maintenance context
- Firewall, Suricata, and endpoint process telemetry for the source

## Investigation Steps

1. Build a timestamp-normalized timeline around repeated or anomalous Windows authentication failures that may indicate credential attack.
2. Preserve and verify the primary evidence: Event ID 4625 fields including account, source address, workstation, logon type, status, and process.
3. Identify the initiating identity, process, device, and access path associated with: Failure Status and SubStatus indicate bad password, disabled account, lockout, or logon restriction.
4. Determine whether the activity matches an approved baseline or this specific benign condition: User entered an old password after a documented credential change.
5. Review the additional technical indicator: Logon Type 3 or 10 failures originate from an unusual workstation or external address.
6. Correlate the event with successful event id 4624 logons after the failure sequence and account lockout, password reset, privileged logon, or group changes.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Successful Event ID 4624 logons after the failure sequence
- Account lockout, password reset, privileged logon, or group changes
- VPN, RDP, SMB, WinRM, and application authentication from the source
- Suricata scanning or brute-force alerts involving the same address
- Similar failure patterns against other Windows hosts or identities

## False Positive Conditions

- User entered an old password after a documented credential change
- Approved vulnerability scanner or authentication test generated the failures
- Service, scheduled task, mapped drive, or application retained stale credentials
- Known corporate VPN or jump host activity matches the account and time
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- A successful logon follows the failures from the same or related source
- Privileged, service, executive, or sensitive account is targeted
- The source sprays credentials across multiple accounts or hosts
- Failures correlate with scanning, malware, or suspicious endpoint activity
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Temporarily restrict the source or affected account only after analyst approval
- Revoke active sessions when evidence supports account compromise
- Block an external source through the local containment approval workflow
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Reset credentials and review MFA state when compromise is confirmed
- Correct stale service or application credentials when the cause is operational
- Harden exposed RDP, SMB, VPN, or identity services
- Tune detection only for verified, narrowly scoped benign sources
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of repeated or anomalous Windows authentication failures that may indicate credential attack are established and documented.
- The analyst collected and reviewed the required evidence, including event id 4625 fields including account, source address, workstation, logon type, status, and process.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports repeated or anomalous Windows authentication failures that may indicate credential attack; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
