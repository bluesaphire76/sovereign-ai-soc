# Sovereign AI SOC Documentation

This is the canonical documentation entry point for the repository.

The current `main` branch contains the v0.7 product baseline. The latest
published Git tag is still `v0.6.0`; v0.7 documentation therefore describes
the implemented state of `main`, not a published release tag.

## Start Here

- [Product overview](product/product-overview.md)
- [External user quickstart](product/external-user-quickstart.md)
- [Installation and demo guide](../INSTALL.md)
- [User guide](product/user-guide.md)
- [Architecture](architecture/architecture.md)
- [Admin guide](operations/admin-guide.md)
- [Troubleshooting](operations/troubleshooting.md)

## Current v0.7 Capability Guides

| Area | Documentation |
|---|---|
| AI providers and OpenRouter | [External AI provider abstraction](architecture/v0.7-external-ai-provider-abstraction.md) |
| AI data governance | [AI Data Control policy](architecture/v0.7-ai-data-control-policy.md) |
| Qdrant semantic memory | [Qdrant Semantic Memory](architecture/v0.7-qdrant-semantic-memory.md) |
| Recommended playbooks | [Metadata-aware indexing](architecture/v0.7.0-qdrant-playbook-metadata-indexing.md) and [LLM synthesis](architecture/v0.7.0-qdrant-recommended-playbooks-llm.md) |
| Investigation visualization | [Investigation Graph](architecture/v0.7-investigation-graph.md) and [Advanced Incident Timeline](architecture/v0.7-advanced-incident-timeline.md) |
| Detection governance | [Detection Rule Lifecycle](architecture/v0.7-detection-rule-lifecycle.md) and [Exceptions and Noise Operations](operations/v0.7-exceptions-noise-operations.md) |
| Governed remediation | [Governed Remediation Connectors](architecture/v0.7-governed-remediation-connectors.md) |
| Runtime operations | [Service Operations and Operation History](operations/v0.7-service-operations-history.md) |
| Metrics, alerting and logs | [Observability](operations/v0.6.0-observability.md), [Alertmanager](operations/v0.7.0-alertmanager-wazuh-backlog-alerting.md) and [Loki/Alloy](operations/v0.7.0-minimal-loki-observability.md) |
| Validation and installability | [Expanded validation harness](validation/v0.7-expanded-validation-harness.md), [Ubuntu installer](operations/ubuntu-installer-guide.md) and [Docker demo packaging](operations/docker-demo-packaging.md) |

## Documentation Taxonomy

- `docs/product/`: user-facing behavior, workflows, demos and roadmap.
- `docs/architecture/`: current architecture, security model and feature design.
- `docs/operations/`: installation, administration, observability and runbooks.
- `docs/releases/`: immutable release notes and the v0.7 unreleased summary.
- `docs/validation/`: historical validation evidence and current validation guides.
- `docs/diagrams/`: editable Mermaid architecture sources.
- `docs/assets/`: committed screenshots and rendered architecture assets.

Top-level Markdown files under `docs/` are compatibility stubs for older links.
Canonical documents live in the folders above.

## Historical Documents

Versioned v0.2-v0.6 documents record the design and validation state at the
time they were written. They are intentionally retained for traceability and
must not be interpreted as the current product surface when a newer current
guide exists.

## Documentation Validation

Run both validators after changing documentation:

```bash
./ai-soc docs-validate
.venv/bin/python scripts/validate_docs_structure.py
```

The validators check the canonical taxonomy, compatibility stubs, local links,
external-user command references and obvious secret patterns.
