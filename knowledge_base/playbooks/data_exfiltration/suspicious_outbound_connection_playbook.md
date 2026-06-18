---
title: Suspicious Outbound Connection Playbook
type: playbook
domain: data_exfiltration
source: suricata
incident_types:
  - suspicious_outbound_connection
  - possible_exfiltration
  - unauthorized_external_connection
severity_hint:
  - medium
  - high
mitre_tactics:
  - Exfiltration
  - Command and Control
mitre_techniques:
  - T1041
  - T1071
applicability:
  - Managed host connects to a rare external IP, domain, ASN, country, or port
  - Connection is initiated by an unexpected process, user, service, or privileged session
  - Traffic persists, repeats, or transfers data outside normal business hours
  - Destination uses dynamic DNS, bulletproof hosting, anonymity, or suspicious reputation
not_applicable_when:
  - Approved SaaS, backup, vendor, API, telemetry, or update connection
  - Documented business transfer to a known partner
  - Security tool or monitoring platform sends expected telemetry
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - exfiltration
  - outbound
  - suricata
  - network
  - external
---

# Suspicious Outbound Connection Playbook

## Purpose

This playbook supports investigation of outbound network connection that is rare, unauthorized, or inconsistent with the source host role.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Managed host connects to a rare external IP, domain, ASN, country, or port
- Connection is initiated by an unexpected process, user, service, or privileged session
- Traffic persists, repeats, or transfers data outside normal business hours
- Destination uses dynamic DNS, bulletproof hosting, anonymity, or suspicious reputation
- Use when the current incident evidence specifically supports outbound network connection that is rare, unauthorized, or inconsistent with the source host role.

## Detection Signals

- Managed host connects to a rare external IP, domain, ASN, country, or port
- Connection is initiated by an unexpected process, user, service, or privileged session
- Traffic persists, repeats, or transfers data outside normal business hours
- Destination uses dynamic DNS, bulletproof hosting, anonymity, or suspicious reputation
- Connection follows archive creation, sensitive file access, malware, or credential activity

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with outbound network connection that is rare, unauthorized, or inconsistent with the source host role.
- Confirm the raw detection fields that support: Managed host connects to a rare external IP, domain, ASN, country, or port.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved SaaS, backup, vendor, API, telemetry, or update connection.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Suricata and firewall flow records with source, destination, protocol, bytes, duration, and timing
- DNS, TLS, HTTP, proxy, certificate, SNI, and reputation context
- Endpoint process, user, command line, open files, and parent process
- Data classification and source-host business role
- Destination owner, vendor, application, and transfer authorization

## Investigation Steps

1. Build a timestamp-normalized timeline around outbound network connection that is rare, unauthorized, or inconsistent with the source host role.
2. Preserve and verify the primary evidence: Suricata and firewall flow records with source, destination, protocol, bytes, duration, and timing.
3. Identify the initiating identity, process, device, and access path associated with: Connection is initiated by an unexpected process, user, service, or privileged session.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved SaaS, backup, vendor, API, telemetry, or update connection.
5. Review the additional technical indicator: Traffic persists, repeats, or transfers data outside normal business hours.
6. Correlate the event with sensitive file access, archive creation, staging, and removable-media activity and malware callback, c2 beaconing, tls anomaly, and dns alerts.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Sensitive file access, archive creation, staging, and removable-media activity
- Malware callback, C2 beaconing, TLS anomaly, and DNS alerts
- Authentication and privilege activity for the source user
- Other hosts contacting the same destination
- Historical transfer baseline for the host, process, and destination

## False Positive Conditions

- Approved SaaS, backup, vendor, API, telemetry, or update connection
- Documented business transfer to a known partner
- Security tool or monitoring platform sends expected telemetry
- Application release introduced a validated new destination
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- The destination or process is untrusted and no owner validates the traffic
- Sensitive data staging or unusual byte volume precedes the connection
- Traffic correlates with compromise, credential misuse, or evasion
- Multiple hosts communicate with the same suspicious infrastructure
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block the destination or restrict egress only after analyst and network approval
- Terminate the responsible process through the containment workflow
- Isolate the source host when active exfiltration or C2 is supported
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove malware, unauthorized transfer tooling, and persistence
- Restore approved egress and application configuration
- Rotate exposed credentials and assess data impact
- Add precise monitoring for validated process, destination, protocol, and volume patterns
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of outbound network connection that is rare, unauthorized, or inconsistent with the source host role are established and documented.
- The analyst collected and reviewed the required evidence, including suricata and firewall flow records with source, destination, protocol, bytes, duration, and timing.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports outbound network connection that is rare, unauthorized, or inconsistent with the source host role; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
