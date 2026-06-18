---
title: Windows RDP Brute Force Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_rdp_bruteforce
  - rdp_failed_logon
  - credential_attack
severity_hint:
  - medium
  - high
mitre_tactics:
  - Credential Access
  - Initial Access
mitre_techniques:
  - T1110
  - T1021.001
applicability:
  - Event ID 4625 Logon Type 10 repeats against one or more accounts
  - TerminalServices RemoteConnectionManager Event ID 1149 shows repeated remote authentication attempts
  - External or unusual internal source connects to TCP 3389 across multiple hosts
  - One source cycles usernames or one username is attempted from distributed sources
not_applicable_when:
  - Approved penetration test or authentication control validation
  - Known user repeatedly entered an old password from an approved device
  - Authorized support gateway produced retries during a documented outage
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - rdp
  - brute-force
  - authentication
  - event-4625
  - wazuh
---

# Windows RDP Brute Force Playbook

## Purpose

This playbook supports investigation of credential guessing or password spraying against Remote Desktop Protocol.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Event ID 4625 Logon Type 10 repeats against one or more accounts
- TerminalServices RemoteConnectionManager Event ID 1149 shows repeated remote authentication attempts
- External or unusual internal source connects to TCP 3389 across multiple hosts
- One source cycles usernames or one username is attempted from distributed sources
- Use when the current incident evidence specifically supports credential guessing or password spraying against Remote Desktop Protocol.

## Detection Signals

- Event ID 4625 Logon Type 10 repeats against one or more accounts
- TerminalServices RemoteConnectionManager Event ID 1149 shows repeated remote authentication attempts
- External or unusual internal source connects to TCP 3389 across multiple hosts
- One source cycles usernames or one username is attempted from distributed sources
- RDP failure burst is followed by Event ID 4624 Logon Type 10

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with credential guessing or password spraying against Remote Desktop Protocol.
- Confirm the raw detection fields that support: Event ID 4625 Logon Type 10 repeats against one or more accounts.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved penetration test or authentication control validation.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Security 4625 and 4624 records with source address, account, status, and Logon Type
- TerminalServices operational logs and RemoteConnectionManager events
- Firewall, NAT, VPN, load-balancer, and Suricata flow records
- RDP exposure, Network Level Authentication, MFA, and gateway configuration
- Account lockout, password reset, device, and user-owner evidence

## Investigation Steps

1. Build a timestamp-normalized timeline around credential guessing or password spraying against Remote Desktop Protocol.
2. Preserve and verify the primary evidence: Security 4625 and 4624 records with source address, account, status, and Logon Type.
3. Identify the initiating identity, process, device, and access path associated with: TerminalServices RemoteConnectionManager Event ID 1149 shows repeated remote authentication attempts.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved penetration test or authentication control validation.
5. Review the additional technical indicator: External or unusual internal source connects to TCP 3389 across multiple hosts.
6. Correlate the event with port scanning and exploit attempts from the same source and successful rdp session and post-logon process execution.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Port scanning and exploit attempts from the same source
- Successful RDP session and post-logon process execution
- Privileged logon, service creation, scheduled task, or Defender tampering
- Similar attacks against other internet-facing or internal hosts
- Threat intelligence and reputation for external sources

## False Positive Conditions

- Approved penetration test or authentication control validation
- Known user repeatedly entered an old password from an approved device
- Authorized support gateway produced retries during a documented outage
- Security scanner tested RDP according to an approved schedule
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- A successful RDP logon follows the attempts
- The service is internet-exposed without gateway, MFA, or source restriction
- Privileged or sensitive accounts are targeted
- Post-logon endpoint or network behavior indicates compromise
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block or rate-limit the source only after analyst and network approval
- Disable or restrict RDP access through the approved containment workflow
- Revoke compromised sessions and isolate the host when success is confirmed
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Reset affected credentials and validate MFA enrollment
- Place RDP behind an approved gateway, VPN, and source restrictions
- Enable Network Level Authentication and reduce exposed administrative services
- Hunt for successful access and persistence from the attacking source
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of credential guessing or password spraying against Remote Desktop Protocol are established and documented.
- The analyst collected and reviewed the required evidence, including security 4625 and 4624 records with source address, account, status, and logon type.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports credential guessing or password spraying against Remote Desktop Protocol; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
