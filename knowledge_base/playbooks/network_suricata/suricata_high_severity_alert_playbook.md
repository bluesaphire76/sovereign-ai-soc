---
title: Suricata High Severity Alert Playbook
type: playbook
domain: network_suricata
source: suricata
incident_types:
  - suricata_high_severity_alert
  - network_intrusion_alert
  - possible_exploit_or_c2
severity_hint:
  - high
  - critical
mitre_tactics:
  - Command and Control
  - Initial Access
  - Discovery
mitre_techniques:
  - T1071
  - T1190
applicability:
  - High severity IDS alert
  - Network event involving suspicious source or destination
  - Possible exploit, malware callback, or command-and-control behavior
not_applicable_when:
  - Signature is known to be noisy in the local environment
  - Traffic belongs to approved scanner, test, or lab activity
  - Destination and payload are confirmed benign
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - suricata
  - network-alert
  - ids
  - high-severity
---

# Suricata High Severity Alert Playbook

## Purpose

This playbook supports investigation of high severity Suricata alerts that may indicate exploit attempts, command-and-control traffic, malware communication, or suspicious network behavior.

It helps analysts validate signature context, asset role, event direction, recurrence, and host correlation before escalation.

## When to Use

- Suricata raises a high or critical severity alert.
- The alert signature indicates exploit, malware, C2, policy violation, or suspicious protocol behavior.
- An internal host communicates with suspicious external infrastructure.
- A destination or payload is not immediately explainable as approved business traffic.
- The same signature repeats across one host or many hosts.

## Detection Signals

- Suricata `alert.signature`, `alert.category`, or severity indicates high risk.
- Internal source connects to external destination associated with malware, exploit, or C2.
- External source targets exposed internal service.
- Suspicious protocol on unusual port.
- Alert repeats with consistent source, destination, SNI, domain, or URI.
- Alert occurs near DNS, authentication, package, or host-change anomalies.

## Initial Triage

- Identify source IP, destination IP, ports, protocol, signature, category, timestamp, and direction.
- Determine whether the internal host is client, server, production, user endpoint, or lab asset.
- Check whether traffic is inbound, outbound, lateral, or internal-only.
- Review whether the signature is known noisy in the local environment.
- Check whether the destination domain, IP, SNI, URI, or JA3/JA4 is expected.
- Determine whether the event is single, repeated, or part of a broader sequence.

## Evidence to Collect

- Full Suricata alert record with signature, category, severity, flow ID, protocol, ports, and direction.
- Related DNS events, TLS SNI, HTTP host, URI, and user-agent where available.
- Packet metadata or payload summary when available and policy allows.
- Host logs for the internal endpoint around the alert time.
- Authentication, process, package, and service-change telemetry for the internal host.
- Reputation and ownership context for external infrastructure.
- Previous alerts with same signature, source, destination, or domain.

## Investigation Steps

1. Confirm whether the alert direction indicates inbound attack, outbound callback, or internal lateral movement.
2. Validate whether the internal host role makes the traffic expected.
3. Review the signature documentation and local tuning notes.
4. Compare source and destination against known scanners, update services, CDNs, security tools, and business applications.
5. Check whether DNS resolution preceded the alert and whether the domain is rare or suspicious.
6. Review host evidence for process execution, login, sudo, package activity, and service changes around the event.
7. Search for repeated alerts from the same host or against the same destination.
8. Determine whether the alert is confirmed suspicious, benign but noisy, or insufficient evidence.

## Correlation Checks

- Correlate with DNS C2 beaconing or DNS tunneling patterns.
- Correlate with host-based alerts from Wazuh.
- Correlate with authentication anomalies on the same host.
- Correlate with suspicious package or systemd activity before outbound alerts.
- Correlate with vulnerability findings for the targeted service.
- Correlate with other internal hosts contacting the same destination.

## False Positive Conditions

- Signature is documented as noisy and locally reviewed.
- Traffic belongs to approved scanner, penetration test, lab, or monitoring platform.
- Destination is confirmed vendor, CDN, SaaS, or internal service.
- Payload or protocol context confirms benign application behavior.
- Alert maps to expected vulnerability scanning against a test system.
- No host evidence supports compromise and owner validates the traffic.

## Escalation Criteria

- Internal host contacts known malicious or suspicious infrastructure.
- Alert repeats with regular timing or across multiple hosts.
- Host evidence indicates compromise, persistence, suspicious process, or credential misuse.
- Inbound exploit attempt targets vulnerable or exposed service.
- Payload or URI suggests exploit delivery, malware, or data exfiltration.
- Owner cannot validate traffic and destination has poor reputation.

## Containment Actions

- Preserve Suricata alert, related flow records, and DNS context.
- Block destination domain or IP after validation and approval.
- Isolate internal host if alert correlates with endpoint compromise.
- Disable exposed service only through approved operational workflow.
- Increase monitoring for same signature, host, or destination.

## Remediation Actions

- Patch or harden vulnerable exposed services.
- Remove malware, persistence, or unauthorized tools if host compromise is confirmed.
- Review firewall and egress controls for suspicious destination.
- Add detection tuning only when benign behavior is confirmed and recurring.
- Create case actions for host owner validation, packet review, or endpoint forensic review.

## Closure Criteria

- Signature, direction, asset role, and destination context are documented.
- DNS, host, authentication, and network correlations were reviewed.
- False-positive rationale or confirmed suspicious classification is recorded.
- Any containment or blocking action is approved and audited.
- Recurrence risk and tuning decision are documented.

## Analyst Notes

- A high severity Suricata alert is a strong signal, not proof by itself.
- Direction matters: outbound callbacks often carry different risk than inbound probes.
- Local signature history is important; repeated false positives should lead to tuning review, not automatic closure.
- Escalate faster when network evidence aligns with endpoint compromise.
