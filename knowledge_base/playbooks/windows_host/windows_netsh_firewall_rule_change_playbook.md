---
title: Windows Netsh Firewall Rule Change Playbook
type: playbook
domain: windows_host
source: wazuh
incident_types:
  - windows_netsh_firewall_rule_change
  - windows_firewall_configuration_change
  - defense_evasion
severity_hint:
  - medium
  - high
mitre_tactics:
  - Defense Evasion
mitre_techniques:
  - T1562.004
applicability:
  - Wazuh reports netsh used to add, modify, or delete a Windows Firewall rule
  - Sysmon Event ID 1 records netsh advfirewall execution
  - A new inbound allow rule exposes an application, service, port, or profile
  - Firewall configuration changes outside approved management or installation workflows
not_applicable_when:
  - Approved installer creates a documented least-privilege rule for the expected application
  - Authorized network or endpoint policy deployment owns and validates the change
  - Temporary troubleshooting rule is approved, time-bound, and removed as planned
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - windows
  - netsh
  - firewall
  - rule-change
  - defense-evasion
  - wazuh
---

# Windows Netsh Firewall Rule Change Playbook

## Purpose

This playbook supports investigation of Windows Firewall changes performed with `netsh advfirewall`, especially new or broadened allow rules.

It distinguishes approved installer or policy activity from unauthorized exposure or defense evasion.

## When to Use

- Wazuh reports `Netsh used to add firewall rule` or an equivalent firewall-change detection.
- Sysmon Event ID 1 records `netsh.exe advfirewall firewall add`, `set`, or `delete rule`.
- A rule changes inbound or outbound access for an application, service, port, protocol, address, or network profile.
- The actor, parent process, installer, management channel, or change record is unexpected.
- Use only when the raw command or authoritative firewall evidence confirms a rule change.

## Detection Signals

- `netsh advfirewall firewall add rule`, `set rule`, or `delete rule` command line.
- Rule action, direction, profile, enabled state, program, service, protocol, port, and remote-address scope.
- Execution as SYSTEM, administrator, installer, remote-management process, script, service, or suspicious parent.
- New inbound allow rule with broad profiles, addresses, ports, or executable scope.
- Firewall change near malware execution, lateral movement, remote service access, or security-control tampering.

## Initial Triage

- Preserve the complete netsh command, process tree, user, integrity level, host, and timestamp.
- Parse the rule name, action, direction, enabled state, profiles, program, service, protocol, ports, and address scope.
- Determine whether the rule exists, whether it differs from policy, and whether it is currently effective.
- Validate the parent installer, endpoint-management platform, change ticket, application owner, and expected rule specification.
- Check whether the change enables access not required by the named application or service.

## Evidence to Collect

- Sysmon Event ID 1 or Security 4688 process creation for netsh and its parent.
- Complete netsh command line and Wazuh rule metadata.
- `Get-NetFirewallRule` and associated port, application, service, and address filters.
- Windows Firewall operational logs, policy source, active profiles, and before-and-after configuration.
- Installer logs, software inventory, endpoint-management policy, owner validation, and approved change record.

## Investigation Steps

1. Reconstruct the process ancestry and identify the account or service that launched netsh.
2. Parse and document every effective firewall-rule parameter from the command.
3. Compare the resulting rule with local policy, centrally managed policy, application requirements, and peer hosts.
4. Validate the binary path, signer, hash, installer package, and parent command line.
5. Determine whether the rule creates unnecessary inbound exposure or bypasses segmentation and endpoint controls.
6. Correlate with listening services, process execution, authentication, remote access, Defender, DNS, and network activity.
7. Search for the same rule name, application, command line, or installer across other endpoints.
8. Classify the change as approved configuration, excessive but benign exposure, suspicious defense evasion, or confirmed compromise.

## Correlation Checks

- Sysmon process, network, file, registry, and DNS telemetry for the responsible process.
- Security logons, privileged sessions, remote service use, RDP, SMB, WinRM, WMI, and scheduled tasks.
- Windows Firewall operational events and centrally managed policy changes.
- Listening ports, application services, network flows, Suricata alerts, and external exposure.
- Matching installer, command, rule, application, or policy change across peer systems.

## False Positive Conditions

- Approved signed installer creates the documented rule required by the installed application.
- Endpoint-management or Group Policy deploys the expected configuration.
- Authorized administrator performs a reviewed and time-bound troubleshooting change.
- Rule is narrow, owner-validated, policy-compliant, and matches peer-system baseline.
- A benign conclusion requires the effective rule and authoritative change evidence.

## Escalation Criteria

- Rule permits unauthorized inbound access, broad remote addresses, unnecessary profiles, or sensitive ports.
- Actor, parent process, binary, installer, or management channel is suspicious or unknown.
- Change correlates with malware, persistence, remote access, lateral movement, or security-control impairment.
- Equivalent unauthorized rules appear on multiple endpoints.
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Preserve process and firewall configuration evidence before changing the rule.
- Disable or remove the rule only through an approved action with rollback information.
- Restrict the responsible account or process when current evidence supports misuse.
- Isolate the endpoint when the rule enables active compromise or unauthorized remote access.
- Record approver, scope, business impact, and validation plan.

## Remediation Actions

- Remove unauthorized rules and restore the authoritative firewall baseline.
- Narrow required rules by profile, direction, program, service, protocol, port, and remote address.
- Remove malicious installers, scripts, services, tasks, or persistence responsible for the change.
- Correct software-deployment packages that create excessive or duplicate rules.
- Validate remediation using effective firewall state and fresh endpoint and network telemetry.

## Closure Criteria

- The initiating process, account, parent, command line, and effective rule were reviewed.
- Rule scope and business requirement were validated against authoritative policy.
- Related endpoint, authentication, remote-access, listening-service, and network evidence was reviewed.
- Approved or benign activity has accountable owner and change evidence.
- Unauthorized exposure is removed or accepted through the proper risk process.
- Follow-up monitoring and detection improvements have owners.
- Closure requires analyst approval and follows incident or case governance.

## Analyst Notes

- A recognizable application name does not prove the firewall rule is safe.
- Review the effective rule, not only the command-line intent.
- Qdrant and LLM output remain advisory; process and firewall telemetry is authoritative.
- Do not apply firewall changes directly from a recommendation card.
