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
- governed AI providers and data controls;
- Qdrant semantic memory;
- Detection Control and remediation governance;
- service-operation auditability.
- local AI runtime governance for Ollama and optional llama.cpp.

AI is used to support investigation, summarization and remediation planning.
Semantic memory supports retrieval. Neither is an autonomous decision or
response authority.

## Supported versions

| Version | Security support |
|---|---|
| `main` / v0.7.1 current baseline | Supported |
| v0.6.x | Supported |
| v0.4-v0.5 | Best-effort critical fixes only |
| < v0.4 | Not supported |

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
- AI provider/data-policy bypass;
- unauthorized external transmission of SOC context;
- semantic-memory authorization or data-isolation failures;
- Detection Control/remediation approval bypass;
- arbitrary command execution through Service Operations.

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
- keep external AI providers disabled until allowlists, redaction and AI Data
  Control are explicitly reviewed;
- bind Qdrant, Ollama, llama.cpp, Grafana, Prometheus, Alertmanager, Loki and
  Alloy to trusted local networks/endpoints;
- expose Grafana, Qdrant, llama.cpp native/router UI and other operational
  consoles only through trusted internal or HTTPS-first access paths;
- use narrow sudoers rules for Service Operations.

## Secrets handling

The repository must not contain:

- `.env` files with real secrets;
- passwords;
- API tokens;
- private keys;
- production database credentials;
- Cloudflare tunnel credentials;
- Wazuh credentials.
- external AI provider credentials.

Use the provided example files as templates only.

## Responsible disclosure

Please allow reasonable time for investigation and remediation before public disclosure.

Security fixes may be released as patch versions when appropriate.
