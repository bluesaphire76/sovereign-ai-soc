---
title: Suspicious Systemd Service Playbook
type: playbook
domain: linux_host
source: wazuh
incident_types:
  - suspicious_systemd_service
  - linux_persistence
  - unauthorized_service_change
severity_hint:
  - high
mitre_tactics:
  - Persistence
  - Privilege Escalation
mitre_techniques:
  - T1543.002
applicability:
  - New or modified systemd unit file
  - Unexpected service enablement or start
  - Service executing scripts from temporary or user-controlled paths
  - Service creation after suspicious login or sudo activity
not_applicable_when:
  - Service belongs to approved deployment or package installation
  - Change is documented in maintenance records
  - Unit file belongs to a known vendor package
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - systemd
  - persistence
  - service
  - linux
  - wazuh
---

# Suspicious Systemd Service Playbook

## Purpose

This playbook supports investigation of suspicious systemd service creation, modification, enablement, or start events on Linux hosts.

Use it when service changes may represent persistence, privilege escalation, unauthorized deployment, or post-compromise execution.

## When to Use

- A new `.service`, `.timer`, or systemd unit file appears.
- An existing service is modified outside approved deployment windows.
- A service is enabled or started unexpectedly.
- `ExecStart` points to a script or binary in `/tmp`, `/var/tmp`, `/dev/shm`, a user home directory, or another unusual path.
- Service creation follows suspicious SSH login, sudo activity, package installation, or file write events.

## Detection Signals

- File integrity alert for `/etc/systemd/system/*.service`.
- New or modified unit under `/usr/lib/systemd/system/` or `/lib/systemd/system/`.
- `systemctl enable`, `systemctl start`, `systemctl daemon-reload`, or `systemctl restart` run by unexpected user.
- Service executing shell, Python, Perl, curl, wget, netcat, or custom binary.
- Unit file configured to restart automatically or run as root.
- Service name mimics a legitimate daemon but points to non-vendor path.

## Initial Triage

- Identify service name, unit path, user, timestamp, and triggering process.
- Capture the unit file contents before editing or disabling it.
- Review `ExecStart`, `User`, `Group`, `WorkingDirectory`, `Restart`, `WantedBy`, and environment values.
- Determine whether the unit belongs to an installed package or approved deployment.
- Check whether systemd activity follows suspicious authentication, sudo, or package activity.
- Determine whether the service is currently active.

## Evidence to Collect

- Full unit file content and file metadata.
- `systemctl status <service>` output if available.
- Journal entries for the service around creation and start.
- Wazuh file integrity and process events.
- Sudo and authentication timeline before service creation.
- Binary or script referenced by `ExecStart`.
- Hash, owner, permissions, and path of executed files.
- Network and DNS telemetry from the host after service start.
- Change ticket or deployment record for the service.

## Investigation Steps

1. Preserve the unit file and referenced executable before making changes.
2. Determine whether the service is vendor-owned, package-owned, deployment-owned, or manually created.
3. Review `ExecStart` for temporary paths, encoded commands, remote downloads, shells, or suspicious arguments.
4. Check whether the service runs as root or another privileged user.
5. Review journal logs for errors, outbound callbacks, repeated restarts, or command output.
6. Validate service creation against package manager history and deployment records.
7. Correlate with suspicious login, sudo, package installation, and file changes.
8. Check whether the service created persistence, network listeners, scheduled behavior, or privilege escalation.
9. Classify as approved service change, suspicious persistence, or confirmed malicious service.

## Correlation Checks

- Correlate with SSH success after failures.
- Correlate with sudo commands that wrote unit files or ran `systemctl`.
- Correlate with package installation that may legitimately create the service.
- Correlate with suspicious binaries in `/tmp`, `/var/tmp`, `/opt`, `/usr/local/bin`, or user home paths.
- Correlate with DNS beaconing, Suricata alerts, or unusual outbound connections.
- Correlate with new users, cron jobs, firewall changes, or SSH key changes.

## False Positive Conditions

- Service is created by approved package installation.
- Service is part of documented deployment or maintenance activity.
- Unit file path and ownership match known vendor package.
- Service content matches baseline or configuration management template.
- Owner confirms the service purpose and change record.
- Service runs an expected application in an approved path.

## Escalation Criteria

- Service runs a binary or script from temporary or user-controlled path.
- Service was created after suspicious login or unauthorized sudo.
- Unit runs as root without business justification.
- Service command downloads remote content or starts reverse shell tooling.
- Service name disguises itself as a known daemon.
- Host shows suspicious outbound traffic after service start.
- Owner cannot validate service creation.

## Containment Actions

- Preserve unit file, executable, journal logs, and file metadata before disabling.
- Stop and disable the service when persistence or active compromise is likely and approval is obtained.
- Isolate the host if the service is actively communicating with suspicious infrastructure.
- Block suspicious destination domains or IPs only after evidence review and approval.
- Avoid deleting the unit or binary before forensic capture.

## Remediation Actions

- Remove unauthorized unit files, timers, symlinks, binaries, and configuration.
- Run `systemctl daemon-reload` after approved cleanup.
- Restore expected service state from trusted baseline.
- Review package manager, sudoers, cron, SSH keys, and user accounts for related persistence.
- Rotate credentials when service creation follows account compromise.
- Add monitoring for high-risk systemd paths and unexpected `systemctl` usage.

## Closure Criteria

- Service ownership and purpose are confirmed or unauthorized service is remediated.
- Unit file content, executable path, and privilege context were reviewed.
- Authentication, sudo, package, DNS, and network correlations were checked.
- Any containment or cleanup action is approved and documented.
- Host owner acknowledges final state.
- Residual risk and follow-up monitoring are documented.

## Analyst Notes

- Systemd changes are high-signal because services provide durable persistence.
- A legitimate package install can create services; always validate package ownership.
- Temporary-path `ExecStart` values are suspicious and require escalation.
- Capturing the unit file before cleanup is essential for evidence quality.
