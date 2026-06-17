# DNS and Suricata Investigation Playbook

This playbook supports suspicious DNS, Suricata network telemetry, beaconing, domain reputation, protocol anomaly and network detection review.

Retrieved context from Qdrant is advisory only. It must not confirm compromise without deterministic network, endpoint or case evidence.

## Suspicious DNS Review

Suspicious DNS alerts become stronger when several signals align:

- rare or newly observed domain;
- high entropy hostname or generated-looking subdomain;
- repeated queries at regular intervals;
- DNS response resolving to newly seen infrastructure;
- endpoint also shows process, authentication or network anomalies;
- domain appears in threat intelligence or internal blocklists.

Analyst actions:

- check query volume and first-seen time;
- inspect requesting host and user context;
- compare with known update services, CDN usage and internal applications;
- review whether the domain appears in historical false positives;
- link DNS evidence to endpoint, proxy, firewall or EDR evidence before escalating.

## Suricata Alert Review

Suricata signatures require packet and environment context. A signature alone may indicate suspicious traffic, but classification should consider direction, asset criticality, recurrence and corroborating telemetry.

Useful fields:

- signature name and category;
- source and destination direction;
- destination port and protocol;
- flow duration and byte counts;
- related DNS queries;
- target host business role;
- matching Wazuh or endpoint event near the same timestamp.

## Beaconing and Command-and-Control Indicators

Beaconing suspicion increases when an endpoint contacts the same domain or IP at stable intervals, especially with small payloads, unusual user-agent strings, suspicious TLS SNI or no matching business application.

Do not classify as command-and-control solely from periodic traffic. Many update agents, telemetry collectors and monitoring systems generate periodic network patterns.

## False Positive Patterns

Common benign patterns include:

- software update checks;
- certificate revocation and OCSP traffic;
- browser prefetch and safe browsing lookups;
- vulnerability scanner traffic;
- monitoring and synthetic network tests;
- internal DNS suffix search noise.

Document the allowed application, endpoint owner and recurrence expectation before requesting suppression.

## Escalation Criteria

Escalate when suspicious DNS or Suricata evidence aligns with endpoint compromise, credential misuse, known malicious infrastructure, lateral movement or data transfer anomalies.
