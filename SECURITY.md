# Security Policy

## Project security posture

Sovereign AI SOC is a local-first, human-in-the-loop security operations platform.

The project is designed to support:

- local SOC experimentation and demos;
- AI-assisted incident triage;
- Wazuh event ingestion;
- incident and case management;
- security audit visibility;
- role-based access control;
- operational health monitoring.

AI is used to support investigation, correlation, summarization and remediation planning. It does not execute remediation actions automatically.

## Supported versions

| Version | Security support |
|---|---|
| v0.3.x | Supported |
| v0.2.x | Best-effort critical fixes only |
| < v0.2 | Not supported |

## Reporting a vulnerability

Please do **not** report security vulnerabilities through public GitHub issues.

Use one of the following private channels:

1. GitHub private vulnerability reporting, if enabled for this repository.
2. Direct contact with the repository maintainer.

When reporting a vulnerability, please include:

- affected version or commit;
- clear description of the issue;
- steps to reproduce;
- expected impact;
- relevant logs, screenshots or payloads if safe to share;
- whether the issue affects local-only deployments, exposed demo deployments or both.

Do not include production secrets, passwords, tokens, private keys or sensitive personal data in the report.

## Security response expectations

This is an open-source project and response times are best-effort.

Target response times:

| Severity | Target initial response |
|---|---|
| Critical | 72 hours |
| High | 7 days |
| Medium | 14 days |
| Low | Best effort |

Fix timelines depend on impact, reproducibility and project capacity.

## Security boundaries

The following are considered in scope:

- authentication and session handling;
- authorization and RBAC bypasses;
- privilege escalation between `VIEWER`, `ANALYST` and `ADMIN`;
- exposure of secrets or sensitive configuration;
- unauthenticated access to protected API routes;
- security audit bypass or tampering;
- unsafe case/incident operations;
- injection vulnerabilities;
- unsafe file or report handling;
- insecure default deployment configuration.

The following are generally out of scope:

- vulnerabilities in local lab infrastructure not caused by this project;
- attacks requiring full administrative access to the host;
- denial-of-service through intentionally excessive local workload;
- vulnerabilities in third-party dependencies without a demonstrated impact on this project;
- findings based only on automated scanner output without validation.

## Deployment security notes

Recommended secure deployment practices:

- keep `.env` and runtime secrets out of version control;
- use strong JWT secrets;
- expose the application only behind a trusted reverse proxy;
- keep API and frontend runtime bindings on `127.0.0.1` where possible;
- use TLS when exposing the UI remotely;
- restrict remote access through a controlled tunnel, VPN or equivalent secure access layer;
- keep Wazuh, PostgreSQL, Python dependencies and Node dependencies updated;
- use `ADMIN` accounts only where required;
- regularly review Security Audit events.

## Secrets handling

The repository must not contain:

- `.env` files with real secrets;
- passwords;
- API tokens;
- private keys;
- production database credentials;
- Cloudflare tunnel credentials;
- Wazuh credentials.

Use the provided example files as templates only.

## Responsible disclosure

Please allow reasonable time for investigation and remediation before public disclosure.

Security fixes may be released as patch versions when appropriate.
