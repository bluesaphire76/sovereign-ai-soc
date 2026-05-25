# Detection Sources

Sovereign AI SOC combines host, security, network and contextual telemetry sources into a unified SOC workflow.

## Wazuh

Wazuh is the primary host and endpoint security monitoring source. It provides:

- Agent identity and host context.
- Security rules and levels.
- Operational findings.
- Raw alert data.
- MITRE metadata when available.
- DNS telemetry through the v0.5 DNS collector/rule path.

Wazuh events are normalized into internal event and alert structures before they can become incidents.

## Suricata

Suricata provides network IDS visibility. The v0.5 network telemetry work adds:

- EVE JSON ingestion.
- Network event normalization.
- Network event listing and summary pages.
- Network evidence context for reports and incident review.

Suricata is complementary to Wazuh: it provides packet/network detection context while Wazuh provides host/security context.

## DNS Telemetry

DNS telemetry is treated as contextual endpoint activity. It is matched by host/client IP and a selected time window only.

Required wording:

> DNS context is matched by host/client IP and selected time window only. It does not imply causal correlation with the incident.

DNS context can help an analyst understand what was happening around the same host and time window, but it is not root cause evidence by itself.

## Internal Normalization

Telemetry is normalized into purpose-specific models:

- Raw source events.
- Security alerts.
- Network events.
- DNS events.
- Correlated incidents.
- Cases.

This protects the workflow from turning every observed signal into an incident.

## Limitations

- Source coverage depends on the deployed Wazuh agents, Suricata sensor placement and DNS collector configuration.
- MITRE data is present only when source events or enrichment provide it.
- DNS context is not causal unless explicit detection evidence supports that interpretation.
- Future sources should follow the same separation between observation, alert, incident and case.
