---
title: Unusual External Destination Playbook
type: playbook
domain: data_exfiltration
source: suricata
incident_types:
  - unusual_external_destination
  - rare_destination_contact
  - possible_data_exfiltration
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
  - Destination has not been observed for the host, peer group, or organization
  - IP, ASN, country, domain, certificate, or hosting provider has elevated risk
  - Connection uses an unusual port, protocol, SNI, user agent, or direct IP
  - The responsible process or user does not normally communicate externally
not_applicable_when:
  - New approved vendor, SaaS, CDN, cloud service, or business partner
  - Application release or infrastructure migration introduced the destination
  - Security, monitoring, update, or telemetry service with validated ownership
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - exfiltration
  - rare-destination
  - suricata
  - reputation
  - outbound
---

# Unusual External Destination Playbook

## Purpose

This playbook supports investigation of connection to an external destination that is new, rare, geographically unusual, or inconsistent with business use.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Destination has not been observed for the host, peer group, or organization
- IP, ASN, country, domain, certificate, or hosting provider has elevated risk
- Connection uses an unusual port, protocol, SNI, user agent, or direct IP
- The responsible process or user does not normally communicate externally
- Use when the current incident evidence specifically supports connection to an external destination that is new, rare, geographically unusual, or inconsistent with business use.

## Detection Signals

- Destination has not been observed for the host, peer group, or organization
- IP, ASN, country, domain, certificate, or hosting provider has elevated risk
- Connection uses an unusual port, protocol, SNI, user agent, or direct IP
- The responsible process or user does not normally communicate externally
- Traffic follows sensitive access, archive creation, or suspicious execution

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with connection to an external destination that is new, rare, geographically unusual, or inconsistent with business use.
- Confirm the raw detection fields that support: Destination has not been observed for the host, peer group, or organization.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: New approved vendor, SaaS, CDN, cloud service, or business partner.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Destination IP, domain, ASN, geography, reputation, certificate, SNI, and first-seen time
- Flow bytes, duration, protocol, frequency, and source-host baseline
- Endpoint process, user, command line, parent, and files accessed
- DNS, proxy, TLS, firewall, and Suricata evidence
- Application owner, vendor, business partner, and change validation

## Investigation Steps

1. Build a timestamp-normalized timeline around connection to an external destination that is new, rare, geographically unusual, or inconsistent with business use.
2. Preserve and verify the primary evidence: Destination IP, domain, ASN, geography, reputation, certificate, SNI, and first-seen time.
3. Identify the initiating identity, process, device, and access path associated with: IP, ASN, country, domain, certificate, or hosting provider has elevated risk.
4. Determine whether the activity matches an approved baseline or this specific benign condition: New approved vendor, SaaS, CDN, cloud service, or business partner.
5. Review the additional technical indicator: Connection uses an unusual port, protocol, SNI, user agent, or direct IP.
6. Correlate the event with newly registered domains, tls anomalies, c2, malware callbacks, and data transfers and endpoint download, execution, persistence, and sensitive file access.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Newly registered domains, TLS anomalies, C2, malware callbacks, and data transfers
- Endpoint download, execution, persistence, and sensitive file access
- Other hosts contacting related domains, IPs, certificates, or ASNs
- Authentication and privileged activity for the source identity
- Historical incidents involving the destination relationships

## False Positive Conditions

- New approved vendor, SaaS, CDN, cloud service, or business partner
- Application release or infrastructure migration introduced the destination
- Security, monitoring, update, or telemetry service with validated ownership
- User accessed a legitimate rare destination for documented business need
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- No owner validates the destination or responsible process
- Infrastructure is malicious, newly registered, or associated with threats
- Traffic includes suspicious upload, beaconing, or payload transfer
- The destination appears across compromised hosts
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block the destination only after validation and approval
- Terminate the responsible process through the containment workflow
- Isolate the source when the destination supports active compromise or exfiltration
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove malware or unauthorized applications responsible for the traffic
- Restore approved egress, proxy, and application configuration
- Rotate credentials and assess any data sent
- Maintain monitored destination inventory and first-seen enrichment
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of connection to an external destination that is new, rare, geographically unusual, or inconsistent with business use are established and documented.
- The analyst collected and reviewed the required evidence, including destination ip, domain, asn, geography, reputation, certificate, sni, and first-seen time.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports connection to an external destination that is new, rare, geographically unusual, or inconsistent with business use; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
