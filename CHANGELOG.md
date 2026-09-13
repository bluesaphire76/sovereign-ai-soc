# Changelog

## v0.9.0 - 2026-09-13

Approved for publication on 2026-09-13. Authenticated Cloudflare verification
passed; systemd restart propagation is accepted operational behavior.

### Added

- Shared product-wide design system and reusable enterprise page patterns.
- Clearer contextual AI provenance and fallback presentation.
- Responsive and accessibility improvements across SOC workflows.

### Changed

- Unified navigation, Incident/Case workflows, overview and monitoring pages.
- Harmonized Detection Control, telemetry, governance and authentication surfaces.

### Security / Governance

- Prevent account operations from leaving no enabled administrator, including
  concurrent requests; retain existing RBAC and self-service boundaries.
- Update Next.js to 16.3.5, sharp to 0.35.4 (libheif 1.23.2), and the development
  dependency js-yaml to 4.3.2 to address four dependency security advisories.

### Validation

- Product-wide responsive, accessibility, RBAC and functional regression.
- Production Next.js build/runtime/current-static-asset consistency gate.

See [release notes](docs/releases/RELEASE_NOTES_v0.9.0.md) and
[release readiness](docs/validation/v0.9.0-release-readiness.md).
Earlier release history remains in [release notes](docs/releases/README.md).
