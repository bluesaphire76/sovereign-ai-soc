---
title: Suricata Port Scan Playbook
type: playbook
domain: network_suricata
source: suricata
incident_types:
  - port_scan
  - network_reconnaissance
  - suspicious_probe
severity_hint:
  - low
  - medium
  - high
mitre_tactics:
  - Discovery
  - Reconnaissance
mitre_techniques:
  - T1046
  - T1595
applicability:
  - Port scan or network reconnaissance alert
  - Single source probing multiple ports or hosts
  - Internal host scanning other internal assets
  - External source scanning exposed services
not_applicable_when:
  - Approved vulnerability scanner
  - Approved monitoring or inventory platform
  - Documented network discovery activity
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - suricata
  - port-scan
  - reconnaissance
  - network
---

# Suricata Port Scan Playbook

## Purpose

This playbook supports investigation of Suricata port scan and network reconnaissance alerts.

It helps analysts distinguish approved scanning from hostile reconnaissance, compromised internal hosts, or pre-exploitation activity.

## When to Use

- Suricata reports port scan, network scan, or suspicious probe behavior.
- One source IP connects to many destination ports on one host.
- One source IP connects to the same port across many hosts.
- An internal host scans other internal assets.
- External infrastructure scans exposed services.
- Scanning is followed by exploit attempts or authentication failures.

## Detection Signals

- High number of connection attempts from one source.
- Large destination port diversity against one destination.
- Large destination host spread against one or few ports.
- TCP SYN patterns, rejected connections, or incomplete handshakes.
- Scan signatures from Suricata or firewall telemetry.
- Follow-up exploit, SSH brute force, web attack, or malware alert after the scan.

## Initial Triage

- Identify scanner source IP, destination hosts, destination ports, protocol, and time window.
- Determine whether scan is horizontal, vertical, or mixed.
- Determine whether source is internal, external, VPN, scanner, monitoring system, or unknown.
- Check whether scanning maps to an approved vulnerability scan schedule.
- Identify whether destination hosts are production, exposed, sensitive, or lab assets.
- Check whether scan intensity is increasing or repeated over time.

## Evidence to Collect

- Suricata alert records and flow summaries.
- Source IP ownership, scanner inventory, VPN assignment, or external reputation.
- Destination host list and port list.
- Firewall accept/deny records and packet metadata where available.
- Vulnerability scanner schedule, scan job ID, and owner confirmation.
- Follow-up alerts from the same source or against the scanned destinations.
- Host logs for internal scanner source if source is inside the environment.

## Investigation Steps

1. Classify the scan pattern as vertical, horizontal, distributed, or targeted.
2. Validate whether the source IP is an approved scanner or monitoring platform.
3. Compare scan time with approved vulnerability management schedule.
4. Check whether the source scans sensitive ports such as SSH, RDP, SMB, databases, Kubernetes, or management interfaces.
5. Review whether any scanned service later receives exploit or authentication attempts.
6. For internal scan sources, review host authentication, process execution, and owner context.
7. For external scan sources, review exposure and whether firewall policy is behaving as expected.
8. Decide whether to classify as approved scan, benign monitoring, hostile reconnaissance, or compromised internal host.

## Correlation Checks

- Correlate with vulnerability scanner jobs and inventory systems.
- Correlate with firewall deny spikes.
- Correlate with SSH brute force, web exploit, or high severity Suricata alerts after the scan.
- Correlate internal scanner sources with host compromise indicators.
- Correlate destination services with known vulnerabilities or internet exposure.
- Correlate repeated scans from same ASN or external range.

## False Positive Conditions

- Source is a documented vulnerability scanner.
- Source is approved monitoring, inventory, or asset discovery platform.
- Activity occurs during scheduled scan window and matches expected scope.
- Internal source belongs to lab, security validation, or synthetic test.
- Destination and port spread match approved scan profile.
- No follow-up exploit or authentication activity is observed.

## Escalation Criteria

- Internal host scans broadly and is not approved scanner.
- Scan targets sensitive management ports or production assets.
- Scan is followed by exploit attempts, brute force, or malware alerts.
- External source repeatedly scans exposed services across time.
- Source reputation is poor or related to known threat infrastructure.
- Scanner owner cannot validate the activity.

## Containment Actions

- For unauthorized external scans, request firewall block or rate limiting if risk justifies it.
- For unauthorized internal scans, isolate or restrict the source host after approval.
- Preserve flow records, alert evidence, and destination list before blocking.
- Avoid blocking approved scanner ranges without vulnerability management approval.
- Increase monitoring on scanned critical services.

## Remediation Actions

- Harden exposed services and restrict management ports.
- Review firewall policy and segmentation for scanned destinations.
- Investigate internal source host for compromise if scanning is unauthorized.
- Tune Suricata only for approved scanners with narrow source and schedule conditions.
- Create follow-up tasks for vulnerable scanned services.

## Closure Criteria

- Source ownership and scan purpose are documented.
- Scan pattern, scope, destinations, and ports are summarized.
- Approved scanner or hostile reconnaissance classification is recorded.
- Follow-up exploit or authentication correlation was checked.
- Containment, tuning, or monitoring decision is documented.
- Residual exposure is tracked if scanned services remain reachable.

## Analyst Notes

- Port scans are often low severity alone but important as precursor activity.
- Internal scans by non-scanner hosts require stronger scrutiny.
- A scan followed by exploit or login attempts should be escalated.
- Treat scanner allowlisting as detection tuning, not incident closure.
