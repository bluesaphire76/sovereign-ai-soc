# Wazuh Authentication Investigation Playbook

This playbook supports analyst review for Wazuh authentication alerts, SSH activity, PAM failures, sudo events, impossible login patterns and privileged access changes.

Qdrant retrieval from this document is advisory only. It must not decide final severity, close an incident, suppress a rule or replace deterministic correlation.

## SSH Brute Force Review

Treat repeated SSH failures as suspicious when several failed attempts target the same account, source host, destination host or privileged identity in a short window.

Useful confirming signals include:

- repeated authentication failures followed by a successful login;
- password spray across several usernames;
- failed login attempts against disabled, service or privileged accounts;
- source IP or ASN not normally associated with the environment;
- matching Wazuh rule names such as `sshd: authentication failed`, `PAM: User login failed` or synthetic brute-force scenarios;
- MITRE mapping around credential access or brute force techniques.

Analyst actions:

- verify source and target identity;
- inspect successful login events near the failed attempts;
- check whether the account was locked, disabled or recently changed;
- compare with known vulnerability scans, test labs and maintenance windows;
- document whether the result is confirmed attack, benign test, operational noise or false positive.

## Privileged Access and Sudo

Sudo and privilege escalation alerts require context. A single sudo command by an authorized administrator may be benign, while sudo after suspicious authentication may raise risk.

Useful context includes:

- who executed the command;
- whether the command matches normal administrative work;
- whether a change ticket or maintenance window exists;
- whether the host is production, internet-facing or security-sensitive;
- whether the event follows failed logins, new user creation or persistence activity.

## False Positive Patterns

Common benign patterns include:

- vulnerability scanners testing SSH authentication;
- lab users generating demo brute-force events;
- monitoring systems using invalid credentials;
- configuration management opening PAM sessions;
- scheduled administrative activity during maintenance windows.

False positive closure should include the benign source, business reason, recurrence expectation and the detection control or exception used if suppression is requested.

## Escalation Criteria

Escalate when authentication failures are followed by success, when privileged accounts are involved, when source reputation is poor, when multiple hosts are touched or when raw evidence shows lateral movement.

Do not escalate solely because Qdrant retrieved a similar historical incident. Similarity is context, not proof.
