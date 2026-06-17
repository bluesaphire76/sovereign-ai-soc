---
title: SSH Success After Multiple Failures Playbook
type: playbook
domain: authentication
source: wazuh
incident_types:
  - ssh_success_after_failures
  - possible_account_compromise
  - credential_attack
severity_hint:
  - high
  - critical
mitre_tactics:
  - Initial Access
  - Credential Access
  - Privilege Escalation
mitre_techniques:
  - T1110
  - T1021.004
  - T1078
applicability:
  - Repeated failed SSH authentication followed by successful login
  - Successful login from an unusual source after failures
  - Successful login to privileged, service, or admin account after failures
not_applicable_when:
  - Successful login was confirmed by the account owner
  - Source is an approved administrator location or VPN
  - Activity occurred during an approved maintenance window
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - ssh
  - successful-login
  - failed-login
  - account-compromise
  - wazuh
---

# SSH Success After Multiple Failures Playbook

## Purpose

This playbook supports investigation when failed SSH attempts are followed by a successful login.

Treat this as higher risk than simple brute force because the event may represent credential compromise, password guessing success, password spraying success, or unauthorized access with valid credentials.

## When to Use

- A successful SSH login occurs after repeated failed attempts.
- The success uses the same source IP as the failures.
- The success targets a privileged, service, or administrative account.
- The source is unusual for the user, host, geography, VPN, or bastion pattern.
- The successful session is followed by sudo, package installation, new process execution, or network activity.

## Detection Signals

- `Failed password` or PAM failures followed by `Accepted password` or `Accepted publickey`.
- Login success after invalid-user attempts against nearby usernames.
- Successful login from external, unknown, or high-risk source IP.
- Successful login outside expected business or maintenance hours.
- Short time gap between repeated failures and success.
- Multiple hosts attempted before one successful login.

## Initial Triage

- Identify the account, source IP, target host, login method, and exact success timestamp.
- Determine whether the successful login reused the same source as the failed attempts.
- Check whether the account owner confirms the login.
- Check whether the source is an approved VPN, bastion, administrator workstation, scanner, or automation host.
- Review whether the account has sudo rights or access to sensitive systems.
- Treat the case as potential account compromise until ownership is confirmed.

## Evidence to Collect

- Full authentication timeline covering failures, success, session open, and session close.
- User ownership and expected access patterns.
- VPN, bastion, identity provider, and MFA records where available.
- Sudo commands and shell history indicators after login.
- Process execution, package installation, service creation, and file integrity events after login.
- Outbound network, DNS, proxy, and Suricata events from the host after login.
- Confirmation from the account owner or system owner.

## Investigation Steps

1. Build a timeline from the first failed attempt through post-login activity.
2. Confirm whether the successful login came from the same IP, ASN, VPN, or workstation as the failed attempts.
3. Validate the source location and access path against normal user behavior.
4. Contact the account owner or system owner for confirmation when policy permits.
5. Review sudo activity after login, including commands, target binaries, and timestamps.
6. Review new processes, package manager activity, file writes, SSH key changes, and systemd service changes.
7. Check whether the user accessed sensitive directories, credentials, logs, or configuration files.
8. Search for lateral movement: outbound SSH, SMB, RDP, database, or internal service connections.
9. Decide whether the login is confirmed user activity, suspicious but unconfirmed, or likely compromise.

## Correlation Checks

- Correlate with brute force attempts against the same account on other hosts.
- Correlate with sudo privilege escalation alerts.
- Correlate with package installation and suspicious service creation.
- Correlate with DNS C2 beaconing or Suricata alerts after the login.
- Correlate with identity provider anomalies such as impossible travel or unusual device.
- Correlate with case history for the same user, source IP, or host.

## False Positive Conditions

- Account owner confirms the login and the failure pattern.
- Source belongs to an approved VPN, bastion, or administrator workstation.
- Activity matches an approved maintenance window or incident response action.
- Failures were caused by stale saved credentials before the user successfully logged in.
- Automation retried with old credentials before using a valid key.

## Escalation Criteria

- Account owner denies the activity or cannot confirm it.
- Successful login uses privileged, service, or shared account.
- Sudo, package install, persistence, or suspicious process activity follows the login.
- The host initiates unusual outbound network or DNS activity after login.
- Source IP has poor reputation or belongs to anonymization infrastructure.
- The same actor attempts or succeeds on multiple hosts.

## Containment Actions

- Revoke active sessions when compromise is suspected and approval is obtained.
- Temporarily disable or lock the account according to identity policy.
- Isolate the host if post-login activity indicates compromise.
- Block the source IP only after validating it is not shared trusted infrastructure.
- Preserve authentication and host logs before disruptive containment.

## Remediation Actions

- Rotate the user password and SSH keys when unauthorized access cannot be excluded.
- Review and remove unauthorized SSH keys.
- Review sudoers changes, user group changes, cron entries, and systemd services.
- Patch exposed SSH configuration and restrict access paths.
- Enforce MFA, bastion access, or key-only authentication where possible.
- Create follow-up actions for host forensic review.

## Closure Criteria

- User or owner confirmation is documented, or compromise handling is completed.
- Post-login commands and host changes were reviewed.
- Sudo, package, service, process, DNS, and network correlations were checked.
- Credential rotation or session revocation decision is documented.
- Any containment action includes approval and audit evidence.
- Residual risk is recorded.

## Analyst Notes

- Successful login after failures should not be treated as routine brute force.
- Public key success still requires validation if failures preceded it.
- Shared accounts require stronger scrutiny because ownership is harder to prove.
- If user confirmation is unavailable, document the uncertainty and keep the case open.
