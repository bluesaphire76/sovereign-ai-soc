---
title: Suspicious Package Activity Playbook
type: playbook
domain: linux_host
source: wazuh
incident_types:
  - suspicious_package_activity
  - unauthorized_software_installation
  - package_manager_abuse
severity_hint:
  - medium
  - high
mitre_tactics:
  - Execution
  - Persistence
  - Defense Evasion
mitre_techniques:
  - T1105
  - T1059
  - T1543
applicability:
  - Unexpected package installation
  - Package manager execution after suspicious login
  - New repository or package source configured
  - Installation of tools commonly used for reconnaissance or persistence
not_applicable_when:
  - Approved patching or maintenance window
  - Expected package lifecycle activity
  - Change linked to approved deployment pipeline
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - package-manager
  - apt
  - software-install
  - linux
  - wazuh
---

# Suspicious Package Activity Playbook

## Purpose

This playbook supports investigation of unexpected Linux package manager activity that may indicate unauthorized software installation, tooling deployment, or post-compromise setup.

It focuses on package installation, repository changes, package source validation, and correlation with suspicious access or persistence.

## When to Use

- Wazuh reports package installation or package database changes.
- `apt`, `dpkg`, `yum`, `dnf`, `rpm`, `snap`, or equivalent package tools run unexpectedly.
- A package install occurs after suspicious SSH login or sudo activity.
- A new package repository, signing key, or package source is configured.
- Tools associated with reconnaissance, tunneling, remote access, crypto mining, or persistence are installed.

## Detection Signals

- New package install event outside patch windows.
- Package manager process executed by unexpected user.
- New repository files under `/etc/apt/sources.list.d/` or package manager configuration paths.
- Installation of tools such as `nmap`, `netcat`, `socat`, `curl`, `wget`, compilers, miners, proxy tools, or remote access utilities.
- Package activity followed by new service, cron entry, binary, or outbound connection.
- Package signature, repository, or source cannot be tied to approved vendor or internal mirror.

## Initial Triage

- Identify package name, version, user, host, command, repository, and timestamp.
- Determine whether the host was in an approved patching or deployment window.
- Check whether the package was installed by a known automation platform.
- Review sudo and authentication activity immediately before package manager execution.
- Determine whether the installed package changes system exposure or execution capability.
- Confirm whether the package appears on the approved software baseline for the asset.

## Evidence to Collect

- Package manager logs such as `/var/log/apt/history.log`, `/var/log/dpkg.log`, `/var/log/yum.log`, or equivalent.
- Wazuh raw event showing package activity.
- User, process, parent process, and command line if available.
- Repository file changes, signing key changes, and package source URLs.
- Sudo logs and authentication timeline before installation.
- File integrity events for new binaries, services, cron entries, or configuration files.
- Network telemetry for downloads and outbound connections after installation.
- Change ticket, deployment record, or package owner confirmation.

## Investigation Steps

1. Determine whether the package activity is install, upgrade, remove, repository change, or package database update.
2. Validate package source against approved repositories and mirrors.
3. Check whether the package name is expected for the host role.
4. Review the user or automation identity that initiated the installation.
5. Correlate with SSH success after failures or suspicious sudo activity.
6. Inspect whether the package created new services, timers, binaries, cron jobs, or users.
7. Review package post-install scripts when available.
8. Check whether the host initiated new outbound DNS or network sessions after installation.
9. Decide whether activity is approved maintenance, suspicious tooling, or likely compromise.

## Correlation Checks

- Correlate with sudo command execution.
- Correlate with systemd service creation or service restart.
- Correlate with new files in `/usr/local/bin`, `/opt`, `/tmp`, `/var/tmp`, and user home paths.
- Correlate with DNS or Suricata alerts after installation.
- Correlate with vulnerability management or patch deployment tools.
- Correlate with historical package activity on the same host.

## False Positive Conditions

- Package activity matches approved patching schedule.
- Change is performed by approved configuration management or deployment pipeline.
- Package is part of standard image update, security patching, or vendor installation.
- Repository change is linked to documented business application deployment.
- Installed package is approved and expected for the asset role.
- Owner confirms the installation and provides change reference.

## Escalation Criteria

- Package installation follows suspicious login or unauthorized sudo use.
- Package source is external, unsigned, unknown, or inconsistent with approved repositories.
- Installed tool enables tunneling, remote access, scanning, credential theft, crypto mining, or persistence.
- Package activity creates or modifies systemd services, cron jobs, users, firewall rules, or SSH configuration.
- Host begins suspicious outbound network or DNS behavior after installation.
- Owner cannot validate the package activity.

## Containment Actions

- Preserve package logs, repository files, and new binaries before removal.
- Disable network access if installed package enables active compromise and approval is obtained.
- Stop suspicious services created by the package only after evidence is captured.
- Temporarily block external repository or download source if malicious and confirmed.
- Avoid package removal before recording version, source, command, and related files.

## Remediation Actions

- Remove unauthorized packages after evidence preservation.
- Remove unauthorized repositories, package signing keys, and package configuration files.
- Restore baseline package state from trusted deployment records.
- Rotate credentials if package installation follows account compromise.
- Review host for persistence, new users, cron jobs, services, and modified security controls.
- Add package activity monitoring for sensitive hosts.

## Closure Criteria

- Package name, version, source, user, and reason are documented.
- Package activity is tied to approved maintenance or remediated as unauthorized.
- Repository changes and post-install artifacts were reviewed.
- Authentication, sudo, service, DNS, and network correlations were checked.
- Any removal or restoration action is recorded.
- Residual risk and owner confirmation are documented.

## Analyst Notes

- Package manager activity is not malicious by itself; source, timing, user, and follow-on behavior decide risk.
- Installation after suspicious login is materially higher risk.
- Repository changes are often more important than the package install event itself.
- Preserve evidence before cleanup because package removal may destroy useful context.
