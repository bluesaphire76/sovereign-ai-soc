---
title: SSH Brute Force Investigation Playbook
type: playbook
domain: authentication
source: wazuh
incident_types:
  - ssh_bruteforce
  - repeated_failed_login
  - credential_attack
severity_hint:
  - medium
  - high
mitre_tactics:
  - Credential Access
  - Initial Access
mitre_techniques:
  - T1110
  - T1021.004
applicability:
  - Multiple failed SSH login attempts
  - Repeated authentication failures from the same source IP
  - Username enumeration attempts
  - Failed SSH logins against privileged or service accounts
not_applicable_when:
  - Source is a confirmed approved vulnerability scanner
  - Activity belongs to an approved penetration test
  - Failures are caused by a known administrative mistake
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - ssh
  - brute-force
  - authentication
  - linux
  - wazuh
---

# SSH Brute Force Investigation Playbook

## Purpose

This playbook supports investigation of repeated failed SSH authentication attempts against Linux hosts.

Use it to separate attacker behavior from expected scanner activity, lab tests, maintenance mistakes, and normal administrative failures.

## When to Use

- A Wazuh rule reports repeated SSH authentication failures.
- Multiple usernames are tried from the same source IP.
- A privileged, service, or disabled account is targeted.
- Failures occur in a short window against one exposed host.
- Failures appear across multiple hosts from the same source.
- The incident has no confirmed successful login yet.

## Detection Signals

- `sshd: authentication failed` or equivalent PAM failure messages.
- Repeated `Failed password` events from one source IP.
- Multiple invalid users or common usernames such as `root`, `admin`, `test`, `oracle`, or `ubuntu`.
- High count of attempts in a narrow time window.
- Source IP not previously associated with approved administration.
- Authentication failures followed by lockout, rate limiting, or firewall deny events.

## Initial Triage

- Identify the target host, source IP, target user, first seen time, last seen time, and failure count.
- Determine whether the source is internal, VPN, external, scanner, NAT, bastion, or monitoring platform.
- Check whether the host is internet-facing, production, sensitive, or part of a lab.
- Review whether any successful login occurred from the same source IP or against the same user after the failures.
- Confirm whether the attempted usernames are valid in the environment.
- Check if the same source appears in other incidents or recent Wazuh alerts.

## Evidence to Collect

- Raw SSH authentication events for the detection window.
- Source IP, destination host, destination port, and target usernames.
- Successful login events for the same user, source IP, and host within at least 60 minutes.
- Sudo events and process execution after any successful authentication.
- Known scanner inventory, VPN logs, bastion logs, and maintenance records.
- GeoIP, ASN, reputation, or internal ownership context for the source IP.
- Related firewall, Suricata, proxy, or DNS telemetry when available.

## Investigation Steps

1. Build a timeline of failed SSH attempts grouped by source IP, username, and destination host.
2. Count unique usernames attempted by the source.
3. Check whether the source targets only one host or moves horizontally across several hosts.
4. Verify whether the source IP belongs to an approved scanner, VPN, administrator, monitoring tool, or test environment.
5. Search for `Accepted password`, `Accepted publickey`, or equivalent successful login records after the failures.
6. If a successful login exists, switch to the SSH Success After Multiple Failures playbook.
7. Review whether the target account is privileged, disabled, service-owned, or externally exposed.
8. Determine whether rate limiting, firewall deny rules, or account lockout prevented further access.
9. Document whether the event is attack traffic, benign scanning, approved testing, or administrator error.

## Correlation Checks

- Correlate the same source IP with other SSH brute force incidents.
- Correlate target username with failed logins on other hosts.
- Correlate with sudo, new process execution, package installation, or systemd service changes.
- Correlate with Suricata alerts for scanning, exploit attempts, or suspicious outbound traffic.
- Correlate with DNS lookups or proxy activity from the target host after the failure window.
- Correlate with vulnerability scanner schedules and penetration test windows.

## False Positive Conditions

- Source IP is a documented vulnerability scanner with approved scan window.
- Activity is part of an approved penetration test or lab validation.
- Attempts are from a known administrator using incorrect credentials.
- Attempts originate from a trusted bastion or VPN with confirmed user ownership.
- The target account is disabled and no successful authentication occurred.
- Attempts are low volume and match a documented operational script failure.

## Escalation Criteria

- Failures are followed by a successful login.
- A privileged, service, or sensitive account is targeted repeatedly.
- The source moves from one host to many hosts.
- Attempts are paired with exploit, malware, or reconnaissance alerts.
- The source IP has poor reputation or belongs to hostile infrastructure.
- Sudo or suspicious process execution follows the authentication window.
- The target host is internet-facing or contains sensitive data.

## Containment Actions

- Request temporary blocking of the source IP when activity is active and not approved.
- Lock or monitor targeted accounts if password spraying is suspected.
- Increase SSH logging and alerting for the target host.
- Require administrator approval before blocking internal scanners, VPN ranges, or shared NAT sources.
- Preserve raw authentication logs before changing firewall, account, or SSH configuration.

## Remediation Actions

- Enforce key-based SSH authentication where feasible.
- Disable password authentication for sensitive hosts when operationally approved.
- Apply account lockout or rate limiting policy.
- Review exposed SSH services and restrict access to trusted networks.
- Rotate credentials for targeted accounts if compromise cannot be excluded.
- Add detection tuning only when the source is confirmed benign and recurring.

## Closure Criteria

- No successful login occurred from the suspicious source.
- Source identity and ownership were reviewed.
- Scanner, test, administrator error, or hostile source classification is documented.
- Containment or monitoring decision is recorded.
- Related incidents and correlated telemetry were reviewed.
- Residual risk is documented when the source was not blocked.

## Analyst Notes

- Do not close solely because brute force attempts failed; verify whether the same actor succeeded elsewhere.
- Username enumeration against valid privileged accounts increases risk.
- Scanner classification requires evidence, not assumption.
- If success follows failures, reclassify the incident as possible account compromise.
