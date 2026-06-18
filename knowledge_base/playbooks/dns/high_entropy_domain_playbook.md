---
title: High Entropy Domain Playbook
type: playbook
domain: dns
source: dns
incident_types:
  - high_entropy_domain
  - suspicious_dns_label
  - possible_dns_tunneling
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
  - Labels have high entropy, excessive length, or base64-like or hex-like character distribution
  - Many unique subdomains appear under one parent domain
  - Query size, label depth, or response pattern differs from the host baseline
  - TXT, NULL, CNAME, or repeated NXDOMAIN responses accompany the labels
not_applicable_when:
  - Approved CDN, browser security, EDR, telemetry, tracking, or SaaS behavior
  - Known application encodes identifiers in DNS labels
  - DNSSEC or service-discovery behavior explains label structure
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - dns
  - high-entropy
  - encoded-label
  - tunneling
---

# High Entropy Domain Playbook

## Purpose

This playbook supports investigation of DNS queries containing random-looking, encoded, or unusually long labels.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Labels have high entropy, excessive length, or base64-like or hex-like character distribution
- Many unique subdomains appear under one parent domain
- Query size, label depth, or response pattern differs from the host baseline
- TXT, NULL, CNAME, or repeated NXDOMAIN responses accompany the labels
- Use when the current incident evidence specifically supports DNS queries containing random-looking, encoded, or unusually long labels.

## Detection Signals

- Labels have high entropy, excessive length, or base64-like or hex-like character distribution
- Many unique subdomains appear under one parent domain
- Query size, label depth, or response pattern differs from the host baseline
- TXT, NULL, CNAME, or repeated NXDOMAIN responses accompany the labels
- The same process generates regular high-entropy queries over time

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with DNS queries containing random-looking, encoded, or unusually long labels.
- Confirm the raw detection fields that support: Labels have high entropy, excessive length, or base64-like or hex-like character distribution.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved CDN, browser security, EDR, telemetry, tracking, or SaaS behavior.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Full query names, parent domain, types, response codes, timestamps, and requesting host
- Label length, entropy, unique-subdomain ratio, and query-volume measurements
- Resolver, destination DNS server, response addresses, and TTL values
- Endpoint process and network context for the requesting application
- Vendor, SaaS, security-tool, CDN, and application-owner validation

## Investigation Steps

1. Build a timestamp-normalized timeline around DNS queries containing random-looking, encoded, or unusually long labels.
2. Preserve and verify the primary evidence: Full query names, parent domain, types, response codes, timestamps, and requesting host.
3. Identify the initiating identity, process, device, and access path associated with: Many unique subdomains appear under one parent domain.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved CDN, browser security, EDR, telemetry, tracking, or SaaS behavior.
5. Review the additional technical indicator: Query size, label depth, or response pattern differs from the host baseline.
6. Correlate the event with dns tunneling, c2 beaconing, dga, and excessive-volume patterns and endpoint suspicious execution, persistence, and outbound connections.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- DNS tunneling, C2 beaconing, DGA, and excessive-volume patterns
- Endpoint suspicious execution, persistence, and outbound connections
- Other hosts querying the same parent domain
- Suricata DNS or exfiltration alerts
- Domain age, ownership, reputation, and resolved infrastructure

## False Positive Conditions

- Approved CDN, browser security, EDR, telemetry, tracking, or SaaS behavior
- Known application encodes identifiers in DNS labels
- DNSSEC or service-discovery behavior explains label structure
- Vendor documentation and process ownership confirm the pattern
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Labels appear to carry changing data and lack a legitimate application explanation
- Volume, regularity, or response behavior supports tunneling or C2
- The requesting process is unknown or compromised
- Related network or endpoint evidence indicates execution or exfiltration
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block the parent domain or direct external resolver only after approval
- Terminate the responsible process through the containment workflow
- Isolate the host when tunneling or active C2 is supported by evidence
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove tunneling tools, malware, and persistence
- Restore approved resolver and application configuration
- Review potential data exposure and rotate affected secrets
- Tune detections using validated parent domain, process, label, and volume context
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of DNS queries containing random-looking, encoded, or unusually long labels are established and documented.
- The analyst collected and reviewed the required evidence, including full query names, parent domain, types, response codes, timestamps, and requesting host.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports DNS queries containing random-looking, encoded, or unusually long labels; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
