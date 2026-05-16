# Security Policy

## Supported Versions

Sovereign AI SOC is currently in early release development.

| Version | Supported |
|---|---|
| v0.2.x | Yes |
| v0.1.x | Limited |
| Older versions | No |

---

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

If you discover a vulnerability, use one of the following options:

1. Open a private GitHub Security Advisory, if available for this repository.
2. Contact the repository maintainer privately through an agreed secure channel.

When reporting a vulnerability, include:

- A clear description of the issue
- Affected component or file
- Steps to reproduce
- Potential impact
- Suggested mitigation, if known
- Whether the issue may expose credentials, tokens, SOC data, or internal system details

Do not include real customer data, production secrets, or sensitive SOC logs.

---

## Security Scope

Security-sensitive areas include:

- Authentication and session handling
- User management
- Authorization and role enforcement
- API endpoints
- Evidence export
- Executive PDF report generation
- Case and incident data handling
- Synthetic test generation
- Local runtime secrets
- Nginx and systemd deployment configuration
- Any future external AI provider integration

---

## Current Security Notes

Sovereign AI SOC is intended for local-first controlled environments.

Important operational notes:

- Do not expose the system directly to the public Internet without additional hardening.
- Use HTTPS through a trusted reverse proxy.
- Use strong secrets for authentication token signing.
- Do not commit `.runtime/`, `.env`, credentials, certificates, or private keys.
- Rotate default or temporary credentials immediately.
- Review access to local SOC data before enabling external integrations.
- Treat AI-generated analysis as decision support, not as authoritative security evidence.

---

## Dependency Vulnerabilities

Dependency vulnerabilities should be reviewed based on:

- Actual runtime usage
- Exploitability in the project context
- Availability of a patched version
- Risk of breaking the application through forced upgrades
- Whether the vulnerable code path is actually used

If a dependency advisory is not exploitable in the current project usage, document the assessment under `docs/security/`.

---

## Disclosure Process

After a vulnerability is reported, maintainers should:

1. Acknowledge receipt.
2. Validate the finding.
3. Assess severity and exploitability.
4. Prepare a fix or mitigation.
5. Release the fix.
6. Credit the reporter if appropriate and agreed.

---

## Security Hardening Roadmap

Planned security improvements include:

- API-wide authentication enforcement
- Full role-based access control
- More granular audit logging
- Stronger session handling
- Improved secrets management
- Production deployment hardening
- Optional external identity provider integration
