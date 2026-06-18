---
title: Suricata Suspicious HTTP Request Playbook
type: playbook
domain: network_suricata
source: suricata
incident_types:
  - suricata_http_suspicious_request
  - web_attack
  - suspicious_http_activity
severity_hint:
  - medium
  - high
mitre_tactics:
  - Initial Access
  - Command and Control
mitre_techniques:
  - T1190
  - T1071.001
applicability:
  - Suricata HTTP signature detects traversal, injection, scanner, web shell, or malicious user agent
  - Request uses unusual method, encoded path, suspicious parameter, or exploit payload
  - Rare user agent, host header, URI, or content type targets a sensitive endpoint
  - Response status, size, or timing differs from normal application behavior
not_applicable_when:
  - Approved scanner, monitoring, synthetic test, or penetration test
  - Application legitimately accepts the unusual method or encoded parameter
  - WAF or application rejected the request without side effects
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - suricata
  - http
  - web-attack
  - request
  - network
---

# Suricata Suspicious HTTP Request Playbook

## Purpose

This playbook supports investigation of HTTP request with suspicious method, URI, headers, body, user agent, or application-layer behavior.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Suricata HTTP signature detects traversal, injection, scanner, web shell, or malicious user agent
- Request uses unusual method, encoded path, suspicious parameter, or exploit payload
- Rare user agent, host header, URI, or content type targets a sensitive endpoint
- Response status, size, or timing differs from normal application behavior
- Use when the current incident evidence specifically supports HTTP request with suspicious method, URI, headers, body, user agent, or application-layer behavior.

## Detection Signals

- Suricata HTTP signature detects traversal, injection, scanner, web shell, or malicious user agent
- Request uses unusual method, encoded path, suspicious parameter, or exploit payload
- Rare user agent, host header, URI, or content type targets a sensitive endpoint
- Response status, size, or timing differs from normal application behavior
- Source repeats requests, changes payloads, or follows reconnaissance

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with HTTP request with suspicious method, URI, headers, body, user agent, or application-layer behavior.
- Confirm the raw detection fields that support: Suricata HTTP signature detects traversal, injection, scanner, web shell, or malicious user agent.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved scanner, monitoring, synthetic test, or penetration test.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- Suricata HTTP and flow records including method, URI, host, user agent, status, and bytes
- Reverse-proxy, WAF, load-balancer, and application logs
- Request and response samples within privacy and retention policy
- Server process, file, authentication, and outbound network events
- Source reputation, application owner, release, and testing context

## Investigation Steps

1. Build a timestamp-normalized timeline around HTTP request with suspicious method, URI, headers, body, user agent, or application-layer behavior.
2. Preserve and verify the primary evidence: Suricata HTTP and flow records including method, URI, host, user agent, status, and bytes.
3. Identify the initiating identity, process, device, and access path associated with: Request uses unusual method, encoded path, suspicious parameter, or exploit payload.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved scanner, monitoring, synthetic test, or penetration test.
5. Review the additional technical indicator: Rare user agent, host header, URI, or content type targets a sensitive endpoint.
6. Correlate the event with waf action and application response for the exact request and file creation, web-shell indicators, child processes, and callbacks on the server.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- WAF action and application response for the exact request
- File creation, web-shell indicators, child processes, and callbacks on the server
- Authentication success or session creation after the request
- Other destinations targeted by the same source or user agent
- Vulnerability and change records for the affected route

## False Positive Conditions

- Approved scanner, monitoring, synthetic test, or penetration test
- Application legitimately accepts the unusual method or encoded parameter
- WAF or application rejected the request without side effects
- Internal developer testing matches the source, route, and release window
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- The request reaches a vulnerable endpoint and produces suspicious server behavior
- A web shell, new file, process, account, or outbound connection follows
- The source performs repeated or multi-stage attack activity
- Sensitive data or privileged application functions are accessed
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Block the source, URI, or signature only after application and analyst approval
- Disable the affected route or place it behind additional controls through the containment workflow
- Isolate the server if post-exploitation is confirmed
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Patch the application and remove malicious files or sessions
- Correct input validation, authentication, and WAF coverage
- Rotate secrets exposed through the affected application
- Add precise detections for validated request and post-exploitation indicators
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of HTTP request with suspicious method, URI, headers, body, user agent, or application-layer behavior are established and documented.
- The analyst collected and reviewed the required evidence, including suricata http and flow records including method, uri, host, user agent, status, and bytes.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports HTTP request with suspicious method, URI, headers, body, user agent, or application-layer behavior; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
