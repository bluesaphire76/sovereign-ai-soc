---
title: Windows CIS Benchmark Failure Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_cis_benchmark_failure
  - windows_security_configuration_gap
  - compliance_finding
severity_hint:
  - low
  - medium
  - high
mitre_tactics: []
mitre_techniques: []
applicability:
  - Wazuh Security Configuration Assessment reports a failed CIS Microsoft Windows benchmark check
  - The SCA payload identifies policy, check ID, result, rationale, command, and remediation
  - A Windows hardening control differs from the approved baseline
  - The finding requires asset-owner validation, exception review, or governed remediation
not_applicable_when:
  - The benchmark control is not applicable to the asset role and an approved exception exists
  - An authoritative compensating control satisfies the security objective
  - The check result is stale and a current scan confirms compliance
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - cis
  - sca
  - benchmark
  - compliance
  - hardening
  - wazuh
---

# Windows CIS Benchmark Failure Playbook

## Purpose

This playbook supports investigation and governed disposition of failed CIS Microsoft Windows benchmark checks reported by Wazuh SCA.

It separates a configuration finding from active compromise and requires current state, applicability, ownership, and exception evidence.

## When to Use

- Wazuh rule group `sca` reports a failed CIS Windows benchmark check.
- The raw payload provides the policy version, check ID, CIS control, result, rationale, command, and remediation.
- A security policy, registry value, audit setting, account policy, service, or local security option differs from baseline.
- The finding may require remediation, compensating control, accepted exception, or false-positive correction.
- Use only when current SCA evidence supports the specific failed control.

## Detection Signals

- `data.sca.check.result` equals `failed`.
- Policy identifies a CIS Microsoft Windows benchmark and version.
- Check contains a stable ID, title, description, rationale, compliance mapping, command, and remediation.
- Repeated failure persists across scans or affects multiple assets.
- The failed control concerns authentication, logging, privilege, firewall, Defender, account policy, or another material security boundary.

## Initial Triage

- Record the asset, scan ID, policy and version, check ID, CIS control, result, and scan timestamp.
- Read the exact title, rationale, command output, and remediation rather than classifying from severity alone.
- Confirm the asset role, operating-system edition, domain membership, policy source, and applicability.
- Determine whether local policy, Group Policy, MDM, application requirements, or an approved exception explains the state.
- Distinguish configuration exposure from evidence of active exploitation or compromise.

## Evidence to Collect

- Complete Wazuh SCA finding with scan ID, policy version, check ID, result, command, rationale, and remediation.
- Current local configuration and Resultant Set of Policy or equivalent authoritative policy state.
- Group Policy, MDM, endpoint-management, security baseline, and asset-role records.
- Approved exception, compensating-control, risk acceptance, owner, and expiry evidence.
- Previous and subsequent SCA results and equivalent findings across peer assets.

## Investigation Steps

1. Confirm the current finding directly from the latest SCA scan and identify the exact control.
2. Validate that the benchmark version and check apply to the operating system, edition, role, and management model.
3. Reproduce or verify the check using a read-only authoritative command where safe.
4. Determine the effective policy source and whether local configuration is overridden or stale.
5. Review approved exceptions, compensating controls, application dependencies, and business requirements.
6. Assess exposure, asset criticality, control objective, prevalence, and whether exploitation evidence exists.
7. Compare affected and compliant peer systems to identify drift or deployment failure.
8. Record disposition as true configuration gap, accepted exception, not applicable, stale result, or false positive.

## Correlation Checks

- Related authentication, privilege, audit-policy, Defender, firewall, service, registry, and endpoint detections.
- Group Policy, MDM, endpoint-management, configuration-management, and change records.
- Vulnerability findings and attack paths affected by the missing hardening control.
- Equivalent SCA failures across the same organizational unit, image, role, or deployment wave.
- Historical exceptions, remediation tasks, owners, due dates, and validation scans.

## False Positive Conditions

- The control is not applicable to the documented asset role and an approved exception is active.
- An authoritative compensating control meets the objective and is tested.
- The SCA result is stale, malformed, or based on an unsupported benchmark version.
- Effective domain or MDM policy is compliant although a local read reports otherwise.
- A benign or exception disposition requires documented evidence, owner, approver, and review date.

## Escalation Criteria

- High-impact control failure affects privileged access, authentication, logging, firewall, Defender, or critical assets.
- The gap is widespread, recurrent, unmanaged, or lacks an accountable remediation owner.
- Current telemetry indicates the missing control has been exploited or security visibility is impaired.
- An exception is expired, unsupported, or materially broader than approved.
- Escalation or severity change requires risk evidence and authorized human review.

## Containment Actions

- Do not treat a configuration finding alone as authority to isolate an endpoint.
- Apply urgent temporary safeguards only through the approved containment or change workflow.
- Preserve current configuration and policy evidence before modification.
- Coordinate changes that may affect logon, application compatibility, remote access, or service availability.
- Record approver, scope, rollback, validation, and business impact.

## Remediation Actions

- Apply the required setting through the authoritative Group Policy, MDM, configuration-management, or local-control path.
- Remove conflicting local settings and correct failed policy deployment.
- Implement and document a compensating control when direct remediation is not feasible.
- Create a governed exception with owner, rationale, scope, expiry, and review criteria when risk is accepted.
- Run a fresh SCA scan and verify effective policy after remediation.

## Closure Criteria

- Policy version, check ID, applicability, effective state, and control objective were reviewed.
- Current configuration was verified from an authoritative source.
- Exception or compensating-control evidence is complete where remediation is deferred.
- Approved remediation is deployed and a fresh scan confirms the expected result.
- Related security impact and exploitation evidence were assessed.
- Residual risk, owner, due date, and recurrence monitoring are documented.
- Closure requires analyst approval and follows incident or case governance.

## Analyst Notes

- A failed CIS check is a configuration and risk finding, not proof of compromise.
- Benchmark severity must be combined with asset criticality, exposure, prevalence, and compensating controls.
- Qdrant and LLM output remain advisory; the current SCA payload and effective configuration are authoritative.
- Do not copy remediation commands into production without change review and rollback planning.
