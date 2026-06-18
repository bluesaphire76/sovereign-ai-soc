---
title: Windows Audit Failure Investigation Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_audit_failure
  - windows_security_audit_failure
severity_hint:
  - low
  - medium
  - high
mitre_tactics: []
mitre_techniques: []
applicability:
  - Wazuh reports a generic Windows audit failure event
  - Windows Security channel records an AUDIT_FAILURE outcome
  - Event-specific failure requires validation before security classification
  - Event ID 5061 reports a failed cryptographic operation
not_applicable_when:
  - A more specific Windows playbook exactly matches the Event ID and behavior
  - The event is a known application failure with validated owner and baseline
  - The record is malformed or lacks sufficient Windows event fields
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - audit-failure
  - security-event
  - event-5061
  - cryptographic-operation
  - wazuh
---

# Windows Audit Failure Investigation Playbook

## Purpose

This playbook supports investigation of generic Windows Security audit failures when the Wazuh rule description does not identify a more specific attack technique.

It is particularly useful for Event ID 5061 cryptographic operation failures and other AUDIT_FAILURE events that require event-specific validation before escalation.

## When to Use

- Wazuh reports `Windows audit failure event` or another broad Windows Security failure rule.
- The raw event contains `data.win.system`, a Windows Event ID, provider, channel, and failure outcome.
- No dedicated playbook precisely matches the Event ID and observed operation.
- Event ID 5061 reports a failed key, provider, algorithm, or cryptographic operation.
- Prior AI text or correlation output contains assumptions that are not supported by the raw Windows event.

## Detection Signals

- Windows Security channel event with `AUDIT_FAILURE` severity or failure keyword.
- Event ID 5061 with provider name, algorithm, key name, operation, and non-zero return code.
- Repeated failures for the same account, Logon ID, key, provider, process, or host.
- Failure occurs near authentication, privilege, Defender, service, task, registry, or malware events.
- Wazuh generic rule masks event-specific fields that materially change the interpretation.
- Event volume or timing differs from the endpoint and application baseline.

## Initial Triage

- Read the raw Windows Event ID before using the generic Wazuh rule description.
- Identify provider, channel, computer, account, domain, Logon ID, process ID, operation, object, and return code.
- Resolve the Windows return code through authoritative Microsoft or application documentation.
- Determine whether the failure is isolated, repeated, user-driven, service-driven, or system-wide.
- Compare the event with successful operations for the same account, process, key, or provider.
- Treat generated AI analysis as unverified until it matches the raw event fields.

## Evidence to Collect

- Complete raw Windows event and Wazuh document.
- Event ID, provider name, channel, system time, record ID, process ID, and thread ID.
- Subject account, SID, domain, Logon ID, session type, and source workstation where available.
- Event-specific fields such as cryptographic provider, algorithm, key name, key type, operation, and return code.
- Adjacent Windows Security, System, Application, Defender, and PowerShell events.
- Process telemetry and optional Sysmon Event ID 1 for the process associated with the failure.
- Application, browser, certificate, key-storage, TPM, user-profile, or service context.
- Endpoint owner confirmation and relevant maintenance or deployment records.

## Investigation Steps

1. Confirm the raw Event ID and do not classify the incident from the generic Wazuh description alone.
2. Build a timestamp-normalized timeline around the failure and related Windows events.
3. Resolve the account, SID, Logon ID, process ID, provider, operation, and return code.
4. For Event ID 5061, determine which application or process requested the cryptographic key operation.
5. Compare the key name, provider, algorithm, and return code with expected browser, certificate, TPM, application, or user-profile behavior.
6. Search for repeated failures across the same host, account, process, provider, and key.
7. Correlate with authentication, privilege, process, Defender, registry, service, task, and network telemetry.
8. Verify whether the failure caused operational impact, security-control degradation, credential misuse, or suspicious follow-on behavior.
9. Classify the event as expected operational failure, configuration issue, suspicious activity, or confirmed security incident.

## Correlation Checks

- Event IDs 4624, 4625, 4648, and 4672 for the same account or Logon ID.
- Defender Event ID 5007 and endpoint protection alerts.
- Process creation, PowerShell, scheduled task, service, registry, and security-log events.
- Optional Sysmon Event IDs 1, 3, 11, 12, 13, and 14 when available.
- Certificate enrollment, browser, TPM, key-storage, application, and user-profile errors.
- DNS, proxy, firewall, and Suricata activity from the associated process or endpoint.
- Similar audit failures on peer Windows systems after a deployment or policy change.

## False Positive Conditions

- Browser, certificate, TPM, credential-vault, or application key access fails with a documented return code.
- User profile, key container, certificate, or cryptographic provider is missing or unavailable.
- Approved software update, policy deployment, certificate rotation, or endpoint maintenance explains the failure.
- Event is isolated, has no suspicious process or network correlation, and the responsible owner validates the behavior.
- Repeated events map to a known operational defect with a tracked remediation owner.
- A false-positive conclusion requires raw-event evidence and owner validation, not only prior AI analysis.

## Escalation Criteria

- The responsible process, account, key, provider, or operation is unknown or unauthorized.
- Failure correlates with credential access, privileged logon, malware, persistence, or defense evasion.
- Cryptographic failures affect security tooling, code signing, authentication, certificate trust, or protected data.
- The same unexplained pattern affects multiple hosts, accounts, or critical services.
- Follow-on activity includes suspicious process execution, outbound traffic, account changes, or control tampering.
- Evidence conflicts materially with generated AI analysis or the current incident classification.

## Containment Actions

- Preserve the raw event, process context, certificate or key metadata, and adjacent logs before intervention.
- Restrict the responsible account or process only when current evidence supports misuse and approval is obtained.
- Isolate the endpoint when the failure is part of active malware, credential compromise, or security-control impairment.
- Avoid deleting keys, certificates, profiles, or application state before evidence and recovery impact are reviewed.
- These actions require analyst approval and must follow the local containment approval workflow.

## Remediation Actions

- Correct the application, certificate, TPM, profile, provider, key-container, or policy issue when the failure is operational.
- Remove malicious processes, persistence, unauthorized keys, or security-control changes when compromise is confirmed.
- Restore affected cryptographic and endpoint security configuration from authoritative policy.
- Rotate credentials, certificates, tokens, or keys only when exposure or compromise is supported by evidence.
- Add event-specific enrichment so future incidents expose Event ID, operation, process, and return code.
- Review generic Wazuh correlation and AI prompts when they repeatedly infer unsupported Linux behavior.

## Closure Criteria

- Raw Event ID, operation, provider, account, process, and return code were reviewed.
- The event-specific cause is documented with authoritative technical or owner evidence.
- Authentication, endpoint, Defender, process, and network correlations were completed or documented as unavailable.
- Unsupported assumptions from prior AI or correlation output were corrected in the incident record.
- Approved containment or remediation actions are complete and validated.
- Residual risk, recurrence monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Generic Windows audit failure rules are not equivalent to failed logon or brute-force detections.
- Event ID 5061 reports a cryptographic operation; the return code and requesting process are central to interpretation.
- Do not recommend Linux SSH, sudo, or `/etc` checks for native Windows Security events.
- Sysmon is optional enrichment and may be unavailable.
- Qdrant and LLM output remain advisory; current raw Windows telemetry is authoritative.
