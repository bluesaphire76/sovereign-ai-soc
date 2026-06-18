---
title: DNS-Based Exfiltration Playbook
type: playbook
domain: data_exfiltration
source: dns
incident_types:
  - dns_based_exfiltration
  - dns_tunneling_exfiltration
  - covert_data_transfer
severity_hint:
  - high
  - critical
mitre_tactics:
  - Exfiltration
mitre_techniques:
  - T1048
  - T1071.004
applicability:
  - Long or high-entropy labels change repeatedly under one parent domain
  - Query volume, byte volume, unique-subdomain ratio, or TXT usage is abnormal
  - Labels resemble encoded, compressed, chunked, or sequenced data
  - Host uses direct external DNS or an unauthorized resolver
not_applicable_when:
  - Approved security, CDN, telemetry, SaaS, or application protocol uses encoded labels
  - Known vendor documents the query format, volume, and process
  - Controlled DNS testing or security exercise within scope
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - exfiltration
  - dns
  - tunneling
  - encoded-data
  - covert-channel
---

# DNS-Based Exfiltration Playbook

## Purpose

This playbook supports investigation of suspected transfer of data through encoded DNS queries or responses.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Long or high-entropy labels change repeatedly under one parent domain
- Query volume, byte volume, unique-subdomain ratio, or TXT usage is abnormal
- Labels resemble encoded, compressed, chunked, or sequenced data
- Host uses direct external DNS or an unauthorized resolver
- Use when the current incident evidence specifically supports suspected transfer of data through encoded DNS queries or responses.

## Detection Signals

- Long or high-entropy labels change repeatedly under one parent domain
- Query volume, byte volume, unique-subdomain ratio, or TXT usage is abnormal
- Labels resemble encoded, compressed, chunked, or sequenced data
- Host uses direct external DNS or an unauthorized resolver
- Sensitive file access or archive activity precedes the DNS pattern

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with suspected transfer of data through encoded DNS queries or responses.
- Confirm the raw detection fields that support: Long or high-entropy labels change repeatedly under one parent domain.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved security, CDN, telemetry, SaaS, or application protocol uses encoded labels.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Full DNS samples, parent domain, types, responses, timestamps, and requesting host
- Label entropy, length, sequence, volume, unique ratio, and payload estimates
- Resolver path, external DNS flow, destination ownership, and passive DNS
- Endpoint process, command line, open files, user, and persistence
- Data classification, potential source files, and business-owner validation

## Investigation Steps

1. Build a timestamp-normalized timeline around suspected transfer of data through encoded DNS queries or responses.
2. Preserve and verify the primary evidence: Full DNS samples, parent domain, types, responses, timestamps, and requesting host.
3. Identify the initiating identity, process, device, and access path associated with: Query volume, byte volume, unique-subdomain ratio, or TXT usage is abnormal.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved security, CDN, telemetry, SaaS, or application protocol uses encoded labels.
5. Review the additional technical indicator: Labels resemble encoded, compressed, chunked, or sequenced data.
6. Correlate the event with high-entropy, excessive-volume, dga, and c2 dns patterns and file staging, archiving, encryption, and sensitive repository access.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- High-entropy, excessive-volume, DGA, and C2 DNS patterns
- File staging, archiving, encryption, and sensitive repository access
- Suricata DNS, C2, and exfiltration alerts
- Other hosts querying the same parent domain
- Authentication, malware, persistence, and lateral movement before the transfer

## False Positive Conditions

- Approved security, CDN, telemetry, SaaS, or application protocol uses encoded labels
- Known vendor documents the query format, volume, and process
- Controlled DNS testing or security exercise within scope
- Business application behavior is validated and contains no sensitive data
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Encoded labels plausibly contain changing source data
- The requesting process or domain is malicious or unexplained
- Sensitive access and DNS transfer align in time
- The channel persists, increases, or affects multiple hosts
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block the parent domain or unauthorized resolver only after approval
- Terminate the responsible process through the containment workflow
- Isolate the source host when active data transfer is likely
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove tunneling tools, malware, persistence, and staged data
- Restore approved DNS egress and resolver controls
- Rotate exposed credentials and complete data-impact assessment
- Detect validated parent domains, processes, label patterns, and transfer volumes
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of suspected transfer of data through encoded DNS queries or responses are established and documented.
- The analyst collected and reviewed the required evidence, including full dns samples, parent domain, types, responses, timestamps, and requesting host.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports suspected transfer of data through encoded DNS queries or responses; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
