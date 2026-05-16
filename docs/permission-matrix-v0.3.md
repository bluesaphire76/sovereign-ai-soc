# v0.3 Permission Matrix — Sovereign AI SOC

## Purpose

This document defines the role-based access model for Sovereign AI SOC v0.3.

The goal is to clearly separate administrative, operational, self-service and read-only capabilities before implementing endpoint-level RBAC enforcement.

---

## Roles

### ADMIN

Full platform administration role.

Allowed to:
- access all dashboards and operational SOC views
- access the Admin page
- see the Admin navigation button
- access the Users page with full user management capabilities
- see all configured users
- create new users
- modify users
- disable users
- delete users
- reset the password of any user
- run synthetic tests
- update incidents and cases
- generate AI analysis
- export reports
- view platform health
- perform all analyst and viewer actions

### ANALYST

Operational SOC analyst role.

Allowed to:
- access dashboards
- view incidents
- update incident status
- add incident notes
- view cases
- update case workflow
- manage case actions
- update closure checklist
- generate and view AI case analysis
- view reports
- export reports
- run synthetic tests, if enabled for operational testing
- access the Users page in self-service mode
- see only their own user profile
- reset only their own password

Not allowed to:
- access Admin page
- see the Admin navigation button
- see all configured users
- create users
- modify other users
- disable users
- delete users
- reset passwords for other users
- modify user roles

### VIEWER

Read-only audit/review role.

Allowed to:
- access dashboards
- view incidents
- view cases
- view timelines
- view audit logs
- view AI analysis
- view reports, if approved
- access the Users page in self-service mode
- see only their own user profile
- reset only their own password

Not allowed to:
- access Admin page
- see the Admin navigation button
- see all configured users
- create users
- modify other users
- disable users
- delete users
- reset passwords for other users
- modify user roles
- update incident status
- add notes
- update case workflow
- create or modify case actions
- update closure checklist
- generate new AI analysis
- run synthetic tests

---

## Frontend RBAC Rules

The frontend must improve user experience by hiding unavailable actions.

However, frontend visibility is not a security boundary.

Security enforcement must happen in the backend.

### Admin navigation

| Capability | ADMIN | ANALYST | VIEWER |
|---|---:|---:|---:|
| See Admin button | Yes | No | No |
| Access Admin page | Yes | No | No |

If an ANALYST or VIEWER opens the Admin URL directly, the page must block access and show an appropriate unauthorized message or redirect.

### Users page

| Capability | ADMIN | ANALYST | VIEWER |
|---|---:|---:|---:|
| Access Users page | Yes | Yes | Yes |
| See all users | Yes | No | No |
| See own user only | Yes | Yes | Yes |
| Create users | Yes | No | No |
| Modify users | Yes | No | No |
| Disable users | Yes | No | No |
| Delete users | Yes | No | No |
| Reset any user password | Yes | No | No |
| Reset own password | Yes | Yes | Yes |

For ANALYST and VIEWER, the Users page must behave as a self-service profile/password page.

---

## Backend API Permission Matrix

| API Area | Endpoint | ADMIN | ANALYST | VIEWER | Notes |
|---|---|---:|---:|---:|---|
| Auth | POST /auth/login | Public | Public | Public | Login endpoint |
| Auth | GET /auth/me | Yes | Yes | Yes | Requires authenticated user |
| Health | GET /health | Public | Public | Public | Basic liveness only |
| Users | GET /users | Yes | Self only | Self only | Admin sees all users; analyst/viewer receive only their own user |
| Users | POST /users | Yes | No | No | Admin only user creation |
| Users | PATCH /users/{user_id} | Yes | No | No | Admin only user modification |
| Users | DELETE /users/{user_id} | Yes | No | No | Admin only user deletion; to be implemented |
| Users | POST /users/{user_id}/password | Yes | Own user only | Own user only | Admin can reset any password; analyst/viewer can reset only their own password |
| Synthetic tests | GET /synthetic-tests/scenarios | Yes | Yes | No | Operational testing |
| Synthetic tests | POST /synthetic-tests/run | Yes | Yes | No | Creates synthetic incidents |
| Incidents | GET /incidents | Yes | Yes | Yes | Read access |
| Incidents | GET /incidents/{incident_id} | Yes | Yes | Yes | Read access |
| Incidents | PATCH /incidents/{incident_id}/status | Yes | Yes | No | Operational update |
| Incidents | GET /incidents/{incident_id}/audit | Yes | Yes | Yes | Audit visibility |
| Incidents | GET /incidents/{incident_id}/notes | Yes | Yes | Yes | Read notes |
| Incidents | POST /incidents/{incident_id}/notes | Yes | Yes | No | Operational update |
| Platform | GET /platform/health | Yes | Yes | No | Operational health |
| Platform | GET /platform/ingest/wazuh | Yes | Yes | No | Operational ingestion status |
| Executive | GET /executive/summary | Yes | Yes | Yes | Executive/read-only dashboard |
| Reports | GET /reports/incidents/{incident_id} | Yes | Yes | Yes | Read/export |
| Reports | GET /reports/cases/{case_id} | Yes | Yes | Yes | Read/export |
| Reports | GET /reports/cases/{case_id}/executive-pdf | Yes | Yes | Yes | Read/export |
| Reports | GET /reports/cases/{case_id}/evidence-pack | Yes | Yes | Yes | Read/export |
| Metrics | GET /metrics/status-distribution | Yes | Yes | Yes | Read access |
| Metrics | GET /metrics/summary | Yes | Yes | Yes | Read access |
| Metrics | GET /metrics/top-hosts | Yes | Yes | Yes | Read access |
| Metrics | GET /metrics/risk-distribution | Yes | Yes | Yes | Read access |
| Cases | GET /cases | Yes | Yes | Yes | Read access |
| Cases | GET /cases/{case_id} | Yes | Yes | Yes | Read access |
| Cases | PATCH /cases/{case_id}/workflow | Yes | Yes | No | Operational update |
| Cases | GET /cases/{case_id}/audit | Yes | Yes | Yes | Audit visibility |
| Cases | GET /cases/{case_id}/closure | Yes | Yes | Yes | Read closure checklist |
| Cases | PATCH /cases/{case_id}/closure | Yes | Yes | No | Operational update |
| Cases | POST /cases/{case_id}/actions/suggestions | Yes | Yes | No | AI-generated operational suggestions |
| Cases | GET /cases/{case_id}/timeline | Yes | Yes | Yes | Read access |
| Cases | GET /cases/{case_id}/actions | Yes | Yes | Yes | Read access |
| Cases | POST /cases/{case_id}/actions | Yes | Yes | No | Operational update |
| Cases | PATCH /cases/{case_id}/actions/{action_id} | Yes | Yes | No | Operational update |
| Cases | GET /cases/{case_id}/incidents | Yes | Yes | Yes | Read access |
| Cases | GET /cases/{case_id}/analysis | Yes | Yes | Yes | Read AI analysis |
| Cases | POST /cases/{case_id}/analysis | Yes | Yes | No | Generate/update AI analysis |

---

## Implementation Principles

1. Authentication is required for all protected endpoints.
2. Authorization must be enforced in the backend.
3. Frontend role-based visibility is required for usability, but it is not sufficient for security.
4. Admin page access must be restricted to ADMIN only.
5. Admin navigation button must be visible only to ADMIN.
6. Users page must support two modes:
   - full user management for ADMIN
   - self-service profile/password management for ANALYST and VIEWER
7. ADMIN can see and manage all users.
8. ANALYST and VIEWER can see only their own user and reset only their own password.
9. Viewer must remain read-only for SOC operational data.
10. Analyst can perform SOC operational actions but cannot administer the platform.
11. Synthetic test execution is allowed for ADMIN and ANALYST only.
12. Public endpoints must remain minimal.

---

## Acceptance Criteria for v0.3 RBAC

### ADMIN

- Can log in.
- Can see Admin button.
- Can access Admin page.
- Can access Users page.
- Can see all users.
- Can create users.
- Can modify users.
- Can disable users.
- Can delete users.
- Can reset any user password.
- Can access all operational pages.
- Can execute synthetic tests.
- Can update incidents and cases.

### ANALYST

- Can log in.
- Cannot see Admin button.
- Cannot access Admin page directly.
- Can access Users page in self-service mode.
- Can see only their own user profile.
- Can reset only their own password.
- Cannot call administrative user-management APIs.
- Can work on incidents and cases.
- Can run synthetic tests.
- Can generate AI case analysis.

### VIEWER

- Can log in.
- Cannot see Admin button.
- Cannot access Admin page directly.
- Can access Users page in self-service mode.
- Can see only their own user profile.
- Can reset only their own password.
- Cannot create, modify, disable or delete users.
- Cannot reset passwords for other users.
- Cannot modify incidents.
- Cannot modify cases.
- Cannot add notes.
- Cannot run synthetic tests.
- Cannot generate AI analysis.
- Can view dashboards, incidents, cases, timelines, audit logs and reports.

---

## Step 3 Implementation Target

The next step will implement backend RBAC helpers such as:

```python
require_role("ADMIN")
require_any_role(["ADMIN", "ANALYST"])
```

and apply them consistently to the endpoints listed in this matrix.

The Users API requires special handling:

```text
GET /users
- ADMIN: return all users
- ANALYST/VIEWER: return only current user

POST /users
- ADMIN only

PATCH /users/{user_id}
- ADMIN only

DELETE /users/{user_id}
- ADMIN only

POST /users/{user_id}/password
- ADMIN: any user
- ANALYST/VIEWER: own user only
```
