# Sovereign AI SOC v0.2.0-rc1

## Release Candidate Scope

This release candidate introduces the first complete enterprise-style SOC console experience for Sovereign AI SOC.

## Highlights

- Enterprise dashboard UX redesign
- Case Queue enterprise alignment
- Case Detail enterprise alignment
- Incident Detail enterprise alignment
- Kanban board enterprise redesign
- Executive dashboard redesign
- Detection Quality dashboard redesign
- Health dashboard redesign
- Synthetic test runner from GUI
- Local user management and login
- Admin user management
- Personal user attribution for case ownership
- Evidence pack export
- Executive PDF reporting
- Closure checklist and readiness validation
- Case workflow audit and timeline improvements

## Validation Checklist

- Backend compile: PASSED
- Frontend build: PASSED
- API health: PASSED
- Login: PASSED
- User management: PASSED
- Case ownership attribution: PASSED
- Synthetic tests: PASSED
- GUI smoke test: PASSED
- Report export: PASSED

## Known Limitations

- Full API-wide authorization hardening is not yet enforced across all existing endpoints.
- Local authentication is suitable for controlled local environments and should be hardened before production exposure.
- Default admin password must be changed after first login.
- The system should not be exposed directly to the public Internet.

## Next Steps

- Final RC validation
- Security hardening
- API-wide RBAC enforcement
- Additional synthetic scenarios
- More complete release documentation
