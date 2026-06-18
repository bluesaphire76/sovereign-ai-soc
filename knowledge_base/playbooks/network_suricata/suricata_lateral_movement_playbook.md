---
title: Suricata Network Lateral Movement Playbook
type: playbook
domain: network_suricata
source: suricata
incident_types:
  - suricata_lateral_movement
  - east_west_suspicious_traffic
  - remote_service_activity
severity_hint:
  - high
mitre_tactics:
  - Lateral Movement
mitre_techniques:
  - T1021
applicability:
  - Suricata flags SMB, RDP, WinRM, SSH, RPC, WMI, database, or remote-service abuse
  - One internal host contacts many peers or management ports outside its baseline
  - Traffic originates from a workstation or server not authorized for administration
  - Remote connections follow credential attack, malware, or suspicious privileged logon
not_applicable_when:
  - Approved endpoint management, backup, vulnerability scanning, or deployment
  - Authorized administrator activity from a designated jump host
  - Expected application-tier or cluster communication
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - suricata
  - lateral-movement
  - east-west
  - remote-services
  - network
---

# Suricata Network Lateral Movement Playbook

## Purpose

This playbook supports investigation of suspicious east-west traffic using remote services, administrative protocols, or repeated internal connections.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Suricata flags SMB, RDP, WinRM, SSH, RPC, WMI, database, or remote-service abuse
- One internal host contacts many peers or management ports outside its baseline
- Traffic originates from a workstation or server not authorized for administration
- Remote connections follow credential attack, malware, or suspicious privileged logon
- Use when the current incident evidence specifically supports suspicious east-west traffic using remote services, administrative protocols, or repeated internal connections.

## Detection Signals

- Suricata flags SMB, RDP, WinRM, SSH, RPC, WMI, database, or remote-service abuse
- One internal host contacts many peers or management ports outside its baseline
- Traffic originates from a workstation or server not authorized for administration
- Remote connections follow credential attack, malware, or suspicious privileged logon
- Internal flow is followed by service creation, file transfer, or new authentication

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with suspicious east-west traffic using remote services, administrative protocols, or repeated internal connections.
- Confirm the raw detection fields that support: Suricata flags SMB, RDP, WinRM, SSH, RPC, WMI, database, or remote-service abuse.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved endpoint management, backup, vulnerability scanning, or deployment.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Suricata alerts and east-west flow records with source, destination, protocol, and timing
- Firewall, switch, VPN, and segmentation telemetry
- Authentication, share, process, service, and task events on both endpoints
- Transferred files, commands, hashes, and remote management artifacts
- Asset roles, administrative paths, and authorized management inventory

## Investigation Steps

1. Build a timestamp-normalized timeline around suspicious east-west traffic using remote services, administrative protocols, or repeated internal connections.
2. Preserve and verify the primary evidence: Suricata alerts and east-west flow records with source, destination, protocol, and timing.
3. Identify the initiating identity, process, device, and access path associated with: One internal host contacts many peers or management ports outside its baseline.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved endpoint management, backup, vulnerability scanning, or deployment.
5. Review the additional technical indicator: Traffic originates from a workstation or server not authorized for administration.
6. Correlate the event with credential failures and successes between source and destination and smb shares, remote services, rdp, winrm, ssh, and wmi activity.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Credential failures and successes between source and destination
- SMB shares, remote services, RDP, WinRM, SSH, and WMI activity
- Endpoint process and malware alerts on both systems
- Additional hosts contacted by the source account or device
- Command-and-control or exfiltration after the movement

## False Positive Conditions

- Approved endpoint management, backup, vulnerability scanning, or deployment
- Authorized administrator activity from a designated jump host
- Expected application-tier or cluster communication
- Security response action with documented scope
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Source is compromised or not authorized for remote administration
- Credentials are reused across multiple hosts anomalously
- Remote access creates services, tasks, payloads, or privileged sessions
- Movement reaches critical systems or continues across network segments
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Restrict east-west traffic and affected credentials after approval
- Terminate remote sessions through the containment workflow
- Isolate source and destination systems when movement is active
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove remote-execution artifacts, payloads, and persistence
- Rotate credentials and invalidate active sessions or tickets
- Review every system reached by the source and identity
- Improve segmentation, privileged paths, and remote-service controls
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of suspicious east-west traffic using remote services, administrative protocols, or repeated internal connections are established and documented.
- The analyst collected and reviewed the required evidence, including suricata alerts and east-west flow records with source, destination, protocol, and timing.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports suspicious east-west traffic using remote services, administrative protocols, or repeated internal connections; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
