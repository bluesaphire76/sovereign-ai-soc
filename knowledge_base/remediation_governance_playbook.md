# Governed Remediation Playbook

This playbook supports proposal-only remediation, connector governance, approval flow and dry-run validation.

Retrieved semantic memory is advisory only. It must not execute remediation, approve a proposal or bypass human review.

## Proposal First

Remediation starts as a proposal. The proposal should describe:

- affected incident or case;
- action type;
- expected impact;
- rollback option;
- required approval role;
- risk level;
- evidence supporting the action;
- dry-run result when available.

## Connector Boundaries

Connectors should operate in governed modes:

- proposal only;
- dry-run simulation;
- approved execution;
- rollback readiness;
- audit trail generation.

Do not allow a semantic match, AI answer or historical incident similarity to execute an action directly.

## Approval Criteria

Approval should consider:

- whether deterministic evidence supports the action;
- whether blast radius is clear;
- whether rollback is available;
- whether the action affects production, identity, firewall or endpoint isolation;
- whether the case owner and admin reviewer agree.

## Common Remediation Patterns

Low-risk examples:

- create an investigation task;
- enrich a case with recommended checks;
- propose a detection tuning review;
- request password reset review;
- open a containment checklist.

Higher-risk examples:

- disable user;
- block IP;
- isolate host;
- change firewall policy;
- restart production service.

High-risk actions require explicit approval and audit.

## Audit Requirements

Every governed remediation decision should record actor, role, timestamp, proposal state, reason, payload summary and outcome.

Failed execution must preserve enough detail for review without exposing secrets.
