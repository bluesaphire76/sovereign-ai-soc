---
title: Unauthorized Linux User Creation Playbook
type: playbook
domain: linux_host
source: wazuh
incident_types:
  - unauthorized_user_creation
  - suspicious_account_creation
  - linux_account_change
severity_hint:
  - medium
  - high
mitre_tactics:
  - Persistence
mitre_techniques:
  - T1136.001
applicability:
  - Wazuh account-management alert for useradd, adduser, or equivalent account creation
  - New entry in /etc/passwd or /etc/shadow without an approved identity request
  - Account created with UID 0, privileged shell, or unexpected home directory
  - Account creation immediately after suspicious SSH or sudo activity
not_applicable_when:
  - Approved employee or service-account provisioning with a matching ticket
  - Configuration-management action from an authorized automation identity
  - Package installation that creates a documented system account
recommended_for_pages:
  - recommended_playbooks
  - ai_analysis
  - incident_detail
tags:
  - linux
  - user-creation
  - account-change
  - wazuh
---

# Unauthorized Linux User Creation Playbook

## Purpose

This playbook supports investigation of creation or enablement of an unexpected local Linux account.

It provides evidence-driven triage and decision support for the SOC analyst. Retrieved guidance remains advisory; deterministic controls and human review remain authoritative.

## When to Use

- Wazuh account-management alert for useradd, adduser, or equivalent account creation
- New entry in /etc/passwd or /etc/shadow without an approved identity request
- Account created with UID 0, privileged shell, or unexpected home directory
- Account creation immediately after suspicious SSH or sudo activity
- Use when the current incident evidence specifically supports creation or enablement of an unexpected local Linux account.

## Detection Signals

- Wazuh account-management alert for useradd, adduser, or equivalent account creation
- New entry in /etc/passwd or /etc/shadow without an approved identity request
- Account created with UID 0, privileged shell, or unexpected home directory
- Account creation immediately after suspicious SSH or sudo activity
- New account followed by SSH key installation, cron creation, or service changes

## Initial Triage

- Identify the affected host, account, process, source, destination, and time window associated with creation or enablement of an unexpected local Linux account.
- Confirm the raw detection fields that support: Wazuh account-management alert for useradd, adduser, or equivalent account creation.
- Establish whether the activity is still active and whether additional assets or identities are involved.
- Validate the most likely benign explanation with an accountable owner: Approved employee or service-account provisioning with a matching ticket.
- Preserve volatile and original-source evidence before containment, remediation, or configuration changes.

## Evidence to Collect

- /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow change records
- auditd or process telemetry for useradd, adduser, passwd, and chage
- Account UID, GID, shell, home directory, creator, and creation timestamp
- SSH authorized_keys, sudoers entries, and recent login history for the account
- Identity ticket, provisioning record, and system owner confirmation

## Investigation Steps

1. Build a timestamp-normalized timeline around creation or enablement of an unexpected local Linux account.
2. Preserve and verify the primary evidence: /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow change records.
3. Identify the initiating identity, process, device, and access path associated with: New entry in /etc/passwd or /etc/shadow without an approved identity request.
4. Determine whether the activity matches an approved baseline or this specific benign condition: Approved employee or service-account provisioning with a matching ticket.
5. Review the additional technical indicator: Account created with UID 0, privileged shell, or unexpected home directory.
6. Correlate the event with ssh authentication and sudo activity preceding account creation and group membership, authorized key, cron, and systemd changes for the account.
7. Search for the same account, artifact, source, destination, technique, or time pattern across related assets.
8. Document whether evidence supports benign activity, suspicious activity, or confirmed compromise; do not infer approval from retrieval context.

## Correlation Checks

- SSH authentication and sudo activity preceding account creation
- Group membership, authorized key, cron, and systemd changes for the account
- Processes and outbound connections executed under the new UID
- Similar account-creation incidents on the same host or by the same administrator
- Identity governance records and approved service-account inventory

## False Positive Conditions

- Approved employee or service-account provisioning with a matching ticket
- Configuration-management action from an authorized automation identity
- Package installation that creates a documented system account
- Recovery activity performed by an authorized administrator and fully recorded
- A false-positive conclusion requires evidence, owner validation, and documented analyst rationale.

## Escalation Criteria

- The account has UID 0, sudo access, or membership in a privileged group
- No owner, ticket, or provisioning record explains the account
- Creation follows compromised credentials or is followed by persistence activity
- The account authenticates remotely or executes suspicious commands
- Escalation or severity change requires current evidence and authorized human review.

## Containment Actions

- Disable interactive login for the account after evidence capture and approval
- Revoke newly added SSH keys or active sessions through the containment workflow
- Isolate the host when account creation is part of active compromise
- These actions require analyst approval and must follow the local containment approval workflow.
- Preserve evidence, define scope and rollback, and record the approver before disruptive action.

## Remediation Actions

- Remove the unauthorized account and owned persistence only after preserving evidence
- Restore passwd, shadow, group, sudoers, and SSH configuration from trusted state
- Rotate affected credentials and review other systems administered by the creator
- Add monitoring for unauthorized account creation and privileged UID assignment
- Validate remediation effectiveness with fresh telemetry before considering closure.

## Closure Criteria

- The cause and scope of creation or enablement of an unexpected local Linux account are established and documented.
- The analyst collected and reviewed the required evidence, including /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow change records.
- Relevant endpoint, identity, network, DNS, and historical correlations were completed or documented as unavailable.
- Benign explanations were validated with accountable owner or authoritative records.
- Approved containment and remediation actions are completed, audited, and verified.
- Residual risk, follow-up monitoring, and any detection improvement are assigned.
- Closure requires analyst approval and must follow incident or case closure governance.

## Analyst Notes

- Use this playbook only when current evidence supports creation or enablement of an unexpected local Linux account; semantic similarity alone is insufficient.
- Qdrant supplies retrieval context, while the LLM may synthesize incident-specific guidance.
- Historical incidents are supporting context and must not determine classification or closure.
- Record evidence references and decision rationale so another analyst can reproduce the conclusion.
