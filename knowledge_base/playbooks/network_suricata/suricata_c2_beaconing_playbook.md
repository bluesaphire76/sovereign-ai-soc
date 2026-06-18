---
title: Suricata Command-and-Control Beaconing Playbook
type: playbook
domain: network_suricata
source: suricata
incident_types:
  - suricata_c2_beaconing
  - network_beaconing
  - command_and_control
severity_hint:
  - high
  - critical
mitre_tactics:
  - Command and Control
mitre_techniques:
  - T1071
applicability:
  - Suricata signature identifies known C2 protocol, infrastructure, or beacon pattern
  - One internal host contacts the same rare destination at regular intervals
  - Low-volume connections repeat with stable byte counts, URI, SNI, JA3, or user agent
  - Beacon persists across user inactivity, reboot, or unrelated application use
not_applicable_when:
  - Approved monitoring, EDR, backup, update, or telemetry service
  - Business application heartbeat with documented destination and interval
  - Synthetic availability check from an authorized source
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - suricata
  - c2
  - beaconing
  - network
  - command-and-control
---

# Suricata Command-and-Control Beaconing Playbook

## Purpose

This playbook supports investigation of periodic network communication that may represent command-and-control beaconing.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Suricata signature identifies known C2 protocol, infrastructure, or beacon pattern
- One internal host contacts the same rare destination at regular intervals
- Low-volume connections repeat with stable byte counts, URI, SNI, JA3, or user agent
- Beacon persists across user inactivity, reboot, or unrelated application use
- Use when the current incident evidence specifically supports periodic network communication that may represent command-and-control beaconing.

## Detection Signals

- Suricata signature identifies known C2 protocol, infrastructure, or beacon pattern
- One internal host contacts the same rare destination at regular intervals
- Low-volume connections repeat with stable byte counts, URI, SNI, JA3, or user agent
- Beacon persists across user inactivity, reboot, or unrelated application use
- Destination reputation, age, ASN, certificate, or domain history is suspicious

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with periodic network communication that may represent command-and-control beaconing.
- Confirm the raw detection fields that support: Suricata signature identifies known C2 protocol, infrastructure, or beacon pattern.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved monitoring, EDR, backup, update, or telemetry service.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Suricata alert, flow, HTTP, TLS, and DNS records for the full time window
- Source host, user, process, destination, ports, protocol, interval, and byte counts
- PCAP or session metadata where collection policy permits
- Endpoint process tree and socket owner for the beacon
- Proxy, firewall, DNS, threat-intelligence, and asset-owner evidence

## Investigation Steps

1. Build a timestamp-normalized timeline around periodic network communication that may represent command-and-control beaconing.
2. Preserve and verify the primary evidence: Suricata alert, flow, HTTP, TLS, and DNS records for the full time window.
3. Identify the initiating identity, process, device, and access path associated with: One internal host contacts the same rare destination at regular intervals.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved monitoring, EDR, backup, update, or telemetry service.
5. Review the additional technical indicator: Low-volume connections repeat with stable byte counts, URI, SNI, JA3, or user agent.
6. Correlate the event with dns queries and resolved addresses preceding each connection and endpoint malware, persistence, suspicious execution, and authentication events.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- DNS queries and resolved addresses preceding each connection
- Endpoint malware, persistence, suspicious execution, and authentication events
- Other hosts contacting the same domain, IP, certificate, or URI
- Inbound exploitation or phishing preceding the first beacon
- Historical incidents involving the same infrastructure or timing pattern

## False Positive Conditions

- Approved monitoring, EDR, backup, update, or telemetry service
- Business application heartbeat with documented destination and interval
- Synthetic availability check from an authorized source
- Known vendor CDN behavior validated by process and ownership
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Destination or signature is associated with known malicious infrastructure
- The responsible process is unknown, unsigned, injected, or persistent
- Multiple hosts beacon to the same rare destination
- Beaconing correlates with credential access, lateral movement, or exfiltration
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block the confirmed C2 destination only after evidence review and approval
- Terminate the responsible process through the containment workflow
- Isolate the source host when active command-and-control is confirmed
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove malware, persistence, scheduled execution, and downloaded payloads
- Restore affected endpoint and network controls
- Rotate credentials exposed on the compromised host
- Hunt for shared infrastructure, fingerprints, processes, and persistence across the estate
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of periodic network communication that may represent command-and-control beaconing are established and documented.
- The analyst collected and reviewed the required evidence, including suricata alert, flow, http, tls, and dns records for the full time window.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports periodic network communication that may represent command-and-control beaconing; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
