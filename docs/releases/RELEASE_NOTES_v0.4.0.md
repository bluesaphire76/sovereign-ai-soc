# Sovereign AI SOC v0.4.0 Release Notes

## Release theme

Sovereign AI SOC v0.4.0 focuses on operational maturity.

This release improves the ingestion pipeline, reduces event noise, separates raw events from security alerts and incidents, strengthens AI-assisted triage, normalizes risk scoring, adds enterprise-grade reporting, introduces DB lifecycle controls, and provides repeatable release validation.

The overall direction remains unchanged:

- local-first execution;
- data sovereignty;
- human-in-the-loop security operations;
- AI used to support analysis, correlation and remediation planning;
- no automatic remediation without analyst validation.

## Main improvements

### Event aggregation and deduplication

v0.4 introduces event aggregation and deduplication for repetitive Wazuh events.

Repeated events within the aggregation window are grouped through deterministic fingerprints instead of creating unnecessary incidents or repeatedly invoking AI analysis.

Key outcomes:

- reduced incident noise;
- lower unnecessary LLM usage;
- better operational visibility through event aggregates;
- preserved auditability of raw events and normalized security alerts.

### Raw events, security alerts, incidents and cases separation

The ingestion model now separates the data lifecycle more clearly:

- `raw_events`
- `security_alerts`
- `incidents`
- `incident_cases`

This improves traceability and makes the SOC data model more realistic.

Raw events and normalized security alerts are persisted before incident creation decisions, while incidents are created only when correlation and triage criteria justify escalation.

### Correlation-first ingestion

The pipeline now performs deterministic correlation checks before creating incidents.

Low-level events can remain as observed security alerts without becoming incidents.

Incident creation is reserved for signals that meet policy-based thresholds such as:

- Wazuh level;
- MITRE mapping;
- suspicious volume;
- matched patterns;
- attack-chain evidence.

### Noise suppression

v0.4 adds deterministic noise suppression for known operational activity.

Examples include controlled low-level PAM/sudo operational events.

Suppressed events are still preserved as raw/security records where appropriate, but they do not trigger incident creation or AI analysis.

### Backlog and ingest metrics

Worker and ingest visibility were improved with operational metrics such as:

- ingest mode;
- pending events;
- latest event lag;
- watermark lag;
- batch size;
- processed/skipped counters;
- suppressed noise;
- observed-only alerts;
- aggregated duplicates;
- AI triage success/fallback/skipped counters.

The Health page now renders these metrics in a more readable form.

### AI triage hardening

AI-assisted triage now uses a clearer policy for when LLM analysis should be invoked.

The release adds:

- timeout handling;
- deterministic fallback analysis;
- audit-friendly fallback behavior;
- health metrics for AI success/fallback/skipped outcomes.

This reduces the risk of pipeline fragility when the local model runtime is slow, unavailable or returns invalid output.

### Risk normalization and historical backfill

v0.4 normalizes risk scoring and severity governance to avoid excessive escalation of operational events.

The historical dry-run showed a significant reduction in overstated `CRITICAL` / `ESCALATED` classifications.

A controlled historical backfill was then performed with backup protection and dry-run-first scripts.

Key principles:

- do not over-escalate operational noise;
- preserve real attack-chain evidence;
- avoid rewriting closed or false-positive records by default;
- keep changes auditable and controlled.

### AI runtime observability

The Health page now includes AI runtime observability.

The AI runtime check verifies:

- Ollama reachability;
- configured model availability.

A chat probe is not enabled by default because it can be slow on local models.

### Enterprise report templates

Incident and case reports now use more enterprise-oriented Markdown templates.

This improves readability for:

- incident review;
- case governance;
- management communication;
- executive evidence review.

The Analyst Evidence Pack remains separate and technical.

Executive PDF reports now include an Executive Decision Brief.

### DB retention, cleanup, backup and restore

v0.4 introduces a safe DB lifecycle baseline.

New retention cleanup script:

```bash
scripts/db_retention_cleanup.py
```

Characteristics:

- dry-run by default;
- apply mode requires explicit `--apply`;
- max delete safety threshold;
- raw/security rows linked to incidents are preserved;
- investigation, case and audit tables are protected.

Documentation:

```text
docs/operations/v0.4-db-retention-backup-restore.md
```

### Regression and smoke validation

v0.4 introduces a repeatable smoke validation script:

```bash
scripts/v0_4_smoke_validation.py
```

It validates:

- core Python imports;
- database connectivity;
- required DB tables;
- `/health`;
- protected endpoint behavior;
- DB retention dry-run.

Documentation:

```text
docs/validation/v0.4-regression-smoke-validation.md
```

### Production/demo hardening documentation

v0.4 adds production/demo hardening guidance.

Documentation:

```text
docs/operations/v0.4-production-demo-hardening.md
docs/validation/v0.4-release-checklist.md
```

The documentation covers:

- local runtime posture;
- Cloudflare Access;
- Nginx/security headers;
- systemd services;
- exposed Wazuh/Qdrant/Indexer ports;
- secret hygiene;
- backup before release;
- demo readiness checklist.

## Security posture

v0.4 improves security and operational control through:

- reduced unnecessary incident creation;
- reduced unnecessary LLM usage;
- protected audit/investigation data;
- explicit retention policy;
- stronger release validation;
- documented demo exposure risks;
- Cloudflare Access-based public demo posture;
- continued loopback binding for backend, frontend and PostgreSQL.

Known lab-specific exposure requiring review before production-like use:

- Wazuh Dashboard may expose port `443`;
- Wazuh Indexer may expose port `9200`;
- Wazuh Manager API may expose port `55000`;
- Wazuh agent ports may expose `1514` / `1515`;
- Qdrant may expose `6333` / `6334`.

These are acceptable only in a trusted lab network or when protected by firewall/VPN/private access controls.

## Validation performed

Before release, run:

```bash
source .venv/bin/activate

python -m py_compile \
  api.py \
  ai_soc_worker.py \
  platform_health.py \
  models.py \
  database.py \
  scripts/v0_4_smoke_validation.py \
  scripts/db_retention_cleanup.py

python scripts/v0_4_smoke_validation.py

cd frontend
npm run build
```

Expected result:

- smoke validation: zero failures;
- frontend build: successful;
- services active after restart;
- no runtime secrets tracked;
- DB backup available before release.

## Documentation added or updated

- `docs/validation/v0.4-risk-normalization-dry-run.md`
- `docs/operations/v0.4-db-retention-backup-restore.md`
- `docs/validation/v0.4-regression-smoke-validation.md`
- `docs/operations/v0.4-production-demo-hardening.md`
- `docs/validation/v0.4-release-checklist.md`
- `README.md`

## Release status

Release candidate status: ready for final validation, tag and GitHub release creation.
