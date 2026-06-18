---
title: Suricata TLS Anomaly Playbook
type: playbook
domain: network_suricata
source: suricata
incident_types:
  - suricata_tls_anomaly
  - suspicious_encrypted_channel
  - certificate_anomaly
severity_hint:
  - medium
  - high
mitre_tactics:
  - Command and Control
mitre_techniques:
  - T1573
applicability:
  - Self-signed, expired, mismatched, weak, or newly observed certificate is used unexpectedly
  - Rare JA3/JA4 fingerprint or SNI appears from a managed host
  - TLS session omits expected SNI, uses unusual port, or targets raw IP infrastructure
  - Certificate subject, issuer, SAN, age, or reuse pattern is suspicious
not_applicable_when:
  - Internal TLS inspection or proxy certificate is expected
  - Approved appliance, embedded device, or development service uses a self-signed certificate
  - Vendor application uses a documented rare fingerprint or destination
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - suricata
  - tls
  - certificate
  - encrypted-channel
  - network
---

# Suricata TLS Anomaly Playbook

## Purpose

This playbook supports investigation of TLS communication with anomalous certificate, fingerprint, SNI, protocol, or destination characteristics.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Self-signed, expired, mismatched, weak, or newly observed certificate is used unexpectedly
- Rare JA3/JA4 fingerprint or SNI appears from a managed host
- TLS session omits expected SNI, uses unusual port, or targets raw IP infrastructure
- Certificate subject, issuer, SAN, age, or reuse pattern is suspicious
- Use when the current incident evidence specifically supports TLS communication with anomalous certificate, fingerprint, SNI, protocol, or destination characteristics.

## Detection Signals

- Self-signed, expired, mismatched, weak, or newly observed certificate is used unexpectedly
- Rare JA3/JA4 fingerprint or SNI appears from a managed host
- TLS session omits expected SNI, uses unusual port, or targets raw IP infrastructure
- Certificate subject, issuer, SAN, age, or reuse pattern is suspicious
- Encrypted connection repeats periodically or follows suspicious endpoint execution

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with TLS communication with anomalous certificate, fingerprint, SNI, protocol, or destination characteristics.
- Confirm the raw detection fields that support: Self-signed, expired, mismatched, weak, or newly observed certificate is used unexpectedly.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Internal TLS inspection or proxy certificate is expected.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Suricata TLS, flow, certificate, SNI, JA3/JA4, protocol, and byte metadata
- Certificate chain, fingerprints, validity, subject, issuer, and SAN values
- DNS history, destination reputation, ASN, geolocation, and first-seen time
- Source process and user from endpoint telemetry
- Proxy, firewall, application, vendor, and asset-owner context

## Investigation Steps

1. Build a timestamp-normalized timeline around TLS communication with anomalous certificate, fingerprint, SNI, protocol, or destination characteristics.
2. Preserve and verify the primary evidence: Suricata TLS, flow, certificate, SNI, JA3/JA4, protocol, and byte metadata.
3. Identify the initiating identity, process, device, and access path associated with: Rare JA3/JA4 fingerprint or SNI appears from a managed host.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Internal TLS inspection or proxy certificate is expected.
5. Review the additional technical indicator: TLS session omits expected SNI, uses unusual port, or targets raw IP infrastructure.
6. Correlate the event with dns queries and certificate reuse across domains or hosts and endpoint process, persistence, malware, and network events.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- DNS queries and certificate reuse across domains or hosts
- Endpoint process, persistence, malware, and network events
- Other internal hosts using the same fingerprint or destination
- Suricata C2, malware callback, and data-transfer alerts
- Approved vendor, proxy, inspection, and certificate-management records

## False Positive Conditions

- Internal TLS inspection or proxy certificate is expected
- Approved appliance, embedded device, or development service uses a self-signed certificate
- Vendor application uses a documented rare fingerprint or destination
- Certificate rotation or test environment explains the anomaly
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- TLS anomaly is tied to an unknown process or suspicious destination
- Fingerprint or certificate is linked to malicious infrastructure
- Multiple hosts establish the same unexplained encrypted channel
- Traffic pattern suggests C2, payload transfer, or exfiltration
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block the confirmed malicious destination or certificate indicator after approval
- Terminate the source process through the containment workflow
- Isolate the endpoint when the encrypted channel supports active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove malicious software and persistence responsible for the channel
- Restore approved proxy, certificate, and trust configuration
- Rotate credentials or secrets exposed through the session
- Monitor validated TLS fingerprints, SNI, and certificate relationships
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of TLS communication with anomalous certificate, fingerprint, SNI, protocol, or destination characteristics are established and documented.
- The analyst collected and reviewed the required evidence, including suricata tls, flow, certificate, sni, ja3/ja4, protocol, and byte metadata.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports TLS communication with anomalous certificate, fingerprint, SNI, protocol, or destination characteristics; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
