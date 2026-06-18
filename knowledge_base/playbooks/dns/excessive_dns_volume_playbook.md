---
title: Excessive DNS Volume Playbook
type: playbook
domain: dns
source: dns
incident_types:
  - excessive_dns_volume
  - dns_query_spike
  - possible_dns_abuse
severity_hint:
  - medium
  - high
mitre_tactics:
  - Command and Control
  - Exfiltration
mitre_techniques:
  - T1071.004
  - T1048
applicability:
  - Query rate or byte volume exceeds the host-role baseline
  - One host generates sustained or burst traffic to one parent domain
  - Unique-domain, unique-subdomain, NXDOMAIN, or TXT-query counts spike
  - Direct external DNS bypasses approved resolvers
not_applicable_when:
  - Approved CDN, software update, browser, telemetry, or security-tool behavior
  - Resolver retry storm caused by a documented outage or misconfiguration
  - Load test, migration, or deployment with owner-confirmed volume
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - dns
  - volume
  - query-spike
  - tunneling
  - resolver
---

# Excessive DNS Volume Playbook

## Purpose

This playbook supports investigation of DNS query volume materially above the expected baseline for a host, user, application, or domain.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Query rate or byte volume exceeds the host-role baseline
- One host generates sustained or burst traffic to one parent domain
- Unique-domain, unique-subdomain, NXDOMAIN, or TXT-query counts spike
- Direct external DNS bypasses approved resolvers
- Use when the current incident evidence specifically supports DNS query volume materially above the expected baseline for a host, user, application, or domain.

## Detection Signals

- Query rate or byte volume exceeds the host-role baseline
- One host generates sustained or burst traffic to one parent domain
- Unique-domain, unique-subdomain, NXDOMAIN, or TXT-query counts spike
- Direct external DNS bypasses approved resolvers
- Volume increase follows suspicious process, service, task, or account activity

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with DNS query volume materially above the expected baseline for a host, user, application, or domain.
- Confirm the raw detection fields that support: Query rate or byte volume exceeds the host-role baseline.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved CDN, software update, browser, telemetry, or security-tool behavior.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Query counts and bytes by host, process, domain, type, response code, and interval
- Baseline for peer assets and the same host over comparable periods
- Resolver path, external DNS destinations, and network flow records
- Endpoint process, user, service, and application ownership
- Parent-domain reputation, business purpose, and vendor validation

## Investigation Steps

1. Build a timestamp-normalized timeline around DNS query volume materially above the expected baseline for a host, user, application, or domain.
2. Preserve and verify the primary evidence: Query counts and bytes by host, process, domain, type, response code, and interval.
3. Identify the initiating identity, process, device, and access path associated with: One host generates sustained or burst traffic to one parent domain.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved CDN, software update, browser, telemetry, or security-tool behavior.
5. Review the additional technical indicator: Unique-domain, unique-subdomain, NXDOMAIN, or TXT-query counts spike.
6. Correlate the event with high-entropy labels, dga families, tunneling, and beaconing and suricata dns, c2, or exfiltration alerts.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- High-entropy labels, DGA families, tunneling, and beaconing
- Suricata DNS, C2, or exfiltration alerts
- Endpoint execution, persistence, and outbound connections
- Other hosts showing the same volume anomaly
- Application release, outage, update, or configuration changes

## False Positive Conditions

- Approved CDN, software update, browser, telemetry, or security-tool behavior
- Resolver retry storm caused by a documented outage or misconfiguration
- Load test, migration, or deployment with owner-confirmed volume
- Business application legitimately changed its DNS usage
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Volume contains encoded labels, unusual types, or direct external DNS
- No application owner can explain the increase
- Data transfer or C2 indicators accompany the spike
- The activity affects multiple hosts or degrades resolver availability
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Rate-limit or block the offending domain or resolver path only after approval
- Terminate the responsible process through the containment workflow
- Isolate the host if DNS abuse supports active compromise or exfiltration
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove malware or correct the application causing abusive queries
- Restore approved resolver configuration and egress controls
- Review data exposure when tunneling is plausible
- Establish role-based DNS volume baselines and targeted detections
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of DNS query volume materially above the expected baseline for a host, user, application, or domain are established and documented.
- The analyst collected and reviewed the required evidence, including query counts and bytes by host, process, domain, type, response code, and interval.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports DNS query volume materially above the expected baseline for a host, user, application, or domain; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
