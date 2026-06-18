---
title: Newly Registered Domain Playbook
type: playbook
domain: dns
source: dns
incident_types:
  - newly_registered_domain
  - suspicious_domain_contact
  - possible_command_and_control
severity_hint:
  - medium
  - high
mitre_tactics:
  - Command and Control
mitre_techniques:
  - T1071.004
applicability:
  - Domain age is below the local risk threshold or first seen recently
  - Managed host queries a rare domain with no established business ownership
  - Domain uses privacy registration, suspicious registrar, fast-flux, or short-lived hosting
  - Query is followed by downloads, authentication, TLS anomalies, or repeated callbacks
not_applicable_when:
  - New legitimate vendor, campaign, SaaS tenant, or customer domain
  - Development or testing domain registered by an approved owner
  - CDN or cloud-hosted domain validated through the responsible application
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - dns
  - newly-registered-domain
  - domain-reputation
  - c2
---

# Newly Registered Domain Playbook

## Purpose

This playbook supports investigation of contact with a recently registered or newly observed domain that may support phishing, malware, or command-and-control.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Domain age is below the local risk threshold or first seen recently
- Managed host queries a rare domain with no established business ownership
- Domain uses privacy registration, suspicious registrar, fast-flux, or short-lived hosting
- Query is followed by downloads, authentication, TLS anomalies, or repeated callbacks
- Use when the current incident evidence specifically supports contact with a recently registered or newly observed domain that may support phishing, malware, or command-and-control.

## Detection Signals

- Domain age is below the local risk threshold or first seen recently
- Managed host queries a rare domain with no established business ownership
- Domain uses privacy registration, suspicious registrar, fast-flux, or short-lived hosting
- Query is followed by downloads, authentication, TLS anomalies, or repeated callbacks
- Multiple related domains share infrastructure, certificate, naming, or registration patterns

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with contact with a recently registered or newly observed domain that may support phishing, malware, or command-and-control.
- Confirm the raw detection fields that support: Domain age is below the local risk threshold or first seen recently.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: New legitimate vendor, campaign, SaaS tenant, or customer domain.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Full DNS query, response, requesting host, resolver, timestamp, and record type
- WHOIS or registration age, registrar, nameservers, ASN, hosting, and certificate history
- Proxy, HTTP, TLS, firewall, and Suricata activity for resolved addresses
- Endpoint process responsible for the lookup and subsequent connections
- Business owner, vendor, application, and threat-intelligence validation

## Investigation Steps

1. Build a timestamp-normalized timeline around contact with a recently registered or newly observed domain that may support phishing, malware, or command-and-control.
2. Preserve and verify the primary evidence: Full DNS query, response, requesting host, resolver, timestamp, and record type.
3. Identify the initiating identity, process, device, and access path associated with: Managed host queries a rare domain with no established business ownership.
4. Determine whether the activity matches an approved baseline or this specific benign condition: New legitimate vendor, campaign, SaaS tenant, or customer domain.
5. Review the additional technical indicator: Domain uses privacy registration, suspicious registrar, fast-flux, or short-lived hosting.
6. Correlate the event with downloaded files, browser, email, or process execution preceding the query and other hosts querying the domain or related infrastructure.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- Downloaded files, browser, email, or process execution preceding the query
- Other hosts querying the domain or related infrastructure
- C2 beaconing, malware callback, TLS anomaly, and outbound transfer alerts
- Authentication or credential events involving the same user
- Similar incidents for sibling domains, IPs, certificates, or registrants

## False Positive Conditions

- New legitimate vendor, campaign, SaaS tenant, or customer domain
- Development or testing domain registered by an approved owner
- CDN or cloud-hosted domain validated through the responsible application
- Security research, sandbox, or threat-intelligence lookup from an approved system
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- Domain is linked to malicious content, payloads, phishing, or C2
- The responsible process or user activity is suspicious
- Several endpoints contact related new domains
- Traffic includes credential submission, download, beaconing, or data transfer
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block the domain and resolved infrastructure only after validation and approval
- Terminate the responsible process through the containment workflow
- Isolate endpoints when contact is part of active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove payloads, persistence, or browser artifacts associated with the domain
- Reset exposed credentials and invalidate sessions
- Hunt for related domains, IPs, certificates, processes, and users
- Add time-bounded monitoring for validated infrastructure relationships
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of contact with a recently registered or newly observed domain that may support phishing, malware, or command-and-control are established and documented.
- The analyst collected and reviewed the required evidence, including full dns query, response, requesting host, resolver, timestamp, and record type.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports contact with a recently registered or newly observed domain that may support phishing, malware, or command-and-control; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
