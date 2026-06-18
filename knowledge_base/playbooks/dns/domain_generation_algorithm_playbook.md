---
title: Domain Generation Algorithm Playbook
type: playbook
domain: dns
source: dns
incident_types:
  - domain_generation_algorithm
  - dga_activity
  - malware_domain_generation
severity_hint:
  - high
mitre_tactics:
  - Command and Control
mitre_techniques:
  - T1568.002
  - T1071.004
applicability:
  - Host queries many random-looking second-level domains in a short window
  - High NXDOMAIN ratio accompanies changing labels, TLDs, or registrars
  - Domains share length, character distribution, timing, or generation pattern
  - A small subset resolves and receives follow-on connections
not_applicable_when:
  - Approved software generates randomized cloud, telemetry, or anti-abuse domains
  - Security products perform sinkhole or threat-intelligence queries
  - Development test intentionally exercises DGA detection
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - dns
  - dga
  - malware
  - algorithmic-domain
  - c2
---

# Domain Generation Algorithm Playbook

## Purpose

This playbook supports investigation of bursts of algorithmically generated domain queries that may indicate malware seeking command-and-control.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Host queries many random-looking second-level domains in a short window
- High NXDOMAIN ratio accompanies changing labels, TLDs, or registrars
- Domains share length, character distribution, timing, or generation pattern
- A small subset resolves and receives follow-on connections
- Use when the current incident evidence specifically supports bursts of algorithmically generated domain queries that may indicate malware seeking command-and-control.

## Detection Signals

- Host queries many random-looking second-level domains in a short window
- High NXDOMAIN ratio accompanies changing labels, TLDs, or registrars
- Domains share length, character distribution, timing, or generation pattern
- A small subset resolves and receives follow-on connections
- Endpoint process, malware alert, or persistence aligns with the query burst

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with bursts of algorithmically generated domain queries that may indicate malware seeking command-and-control.
- Confirm the raw detection fields that support: Host queries many random-looking second-level domains in a short window.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved software generates randomized cloud, telemetry, or anti-abuse domains.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Complete domain list, timestamps, response codes, TLDs, and resolved addresses
- Query count, NXDOMAIN ratio, entropy, lexical similarity, and interval data
- Requesting process, user, host role, and persistence context
- Connections to successfully resolved domains and transferred bytes
- Threat-intelligence, passive DNS, registration, and certificate relationships

## Investigation Steps

1. Build a timestamp-normalized timeline around bursts of algorithmically generated domain queries that may indicate malware seeking command-and-control.
2. Preserve and verify the primary evidence: Complete domain list, timestamps, response codes, TLDs, and resolved addresses.
3. Identify the initiating identity, process, device, and access path associated with: High NXDOMAIN ratio accompanies changing labels, TLDs, or registrars.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved software generates randomized cloud, telemetry, or anti-abuse domains.
5. Review the additional technical indicator: Domains share length, character distribution, timing, or generation pattern.
6. Correlate the event with malware execution, scheduled tasks, services, and startup activity and connections to resolved dga domains and tls fingerprints.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Malware execution, scheduled tasks, services, and startup activity
- Connections to resolved DGA domains and TLS fingerprints
- Other hosts producing the same domain family
- Suricata C2, malware callback, and TLS anomaly alerts
- Historical incidents involving the same algorithmic pattern

## False Positive Conditions

- Approved software generates randomized cloud, telemetry, or anti-abuse domains
- Security products perform sinkhole or threat-intelligence queries
- Development test intentionally exercises DGA detection
- Vendor documentation and process identity explain the entire domain set
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- A suspicious process generates the domain family
- Resolved domains receive callbacks or payload transfers
- The same pattern appears on multiple unmanaged or compromised hosts
- Threat intelligence links the family to malware infrastructure
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block validated DGA domains or sinkhole traffic after approval
- Terminate the generating process through the containment workflow
- Isolate affected endpoints when malware communication is active
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove malware, persistence, and scheduled execution
- Restore endpoint controls and approved DNS configuration
- Rotate credentials exposed on infected systems
- Hunt using process, domain-family, network, and persistence indicators
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of bursts of algorithmically generated domain queries that may indicate malware seeking command-and-control are established and documented.
- The analyst collected and reviewed the required evidence, including complete domain list, timestamps, response codes, tlds, and resolved addresses.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports bursts of algorithmically generated domain queries that may indicate malware seeking command-and-control; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
