# Case Closure Policy

This policy supports case closure checklist, residual risk review, final severity rationale and false-positive classification.

Qdrant retrieval is advisory. It must not close a case or decide final severity automatically.

## Closure Preconditions

Before closing a case, verify:

- relevant incidents are reviewed;
- evidence is summarized;
- action plan is complete or accepted as residual risk;
- false positive rationale is documented when applicable;
- final severity is justified;
- remediation or detection tuning follow-up is tracked;
- closure approval is recorded when required.

## Closure Decisions

Common closure decisions include:

- true positive remediated;
- true positive contained with residual risk;
- false positive;
- benign authorized activity;
- duplicate case;
- insufficient evidence with monitoring continued.

Duplicate case decisions require a deterministic relationship, not only semantic similarity.

## Residual Risk

Residual risk should describe what remains unresolved, why it is acceptable, who owns it and when it should be reviewed again.

Examples:

- recurring scanner noise accepted until a tuning change is approved;
- endpoint evidence unavailable but network telemetry is stable;
- remediation deferred due to business maintenance window;
- low-risk configuration finding accepted by system owner.

## Evidence Summary

A useful closure summary includes:

- trigger and timeline;
- affected assets and users;
- key evidence;
- analyst reasoning;
- actions taken;
- follow-up tasks;
- final severity and rationale.

## False Positive Closure

False-positive closure should include the benign pattern, source system, recurrence expectation and whether a detection-control change is needed.

Avoid closing as false positive simply because a previous incident looks similar. Historical memory can suggest review paths, not final decisions.
