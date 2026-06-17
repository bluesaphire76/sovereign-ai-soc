# Detection Noise and Tuning Guide

This guide supports Detection Quality, exception review, noise suppression and rule lifecycle decisions.

Qdrant may retrieve this guide to support analyst judgment. It must not automatically create, approve, apply or disable detection controls.

## Tuning Decision Model

Before creating an exception or suppression, answer these questions:

- Is the event benign, expected and recurring?
- Is the scope narrow enough to avoid hiding true positives?
- Is there a business owner and review date?
- Is there evidence from matched events, case notes or historical incidents?
- Does the detection still protect critical assets after tuning?

Prefer narrow matchers over broad global scope. Global scope should be used only for reviewed, low-risk and highly specific patterns.

## Suppression Scope

Safe suppressions usually include several constraints:

- exact rule id or rule name;
- specific host, service, source or environment;
- exact maintenance window or recurring job;
- owner and expiration;
- review note explaining residual risk.

Risky suppressions include:

- broad text contains matchers;
- generic error strings;
- global scope with no target;
- no expiration or owner;
- suppressing high severity alerts without compensating controls.

## Exception Review

An exception should preserve visibility where possible. Prefer lowering priority, adding context or narrowing scope before hiding events entirely.

Useful evidence includes:

- historical false-positive examples;
- analyst notes;
- closure reason;
- affected services;
- frequency and last match;
- related case decision.

## Validation Warnings

Warnings such as broad scope, missing owner, missing expiration or global matcher are not blockers by themselves, but they require review and documented rationale.

Apply remains governed by Detection Control Plane RBAC, validation and audit.

## Retuning After Incident Closure

When an incident is closed as false positive or operational noise, update detection quality only if recurrence is expected. One-off events should be documented, not automatically suppressed.
