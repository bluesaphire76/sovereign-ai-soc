# Knowledge Base Archive

This directory stores retired or legacy knowledge-base documents that should remain available for operator review but should not be indexed into Qdrant.

Documents under `archive/` are excluded by the Qdrant knowledge-base indexing job. Use this area for broad, duplicate, outdated or superseded playbooks that could dilute incident-specific recommendations.

Use `archive/legacy_playbooks/` for older playbooks that were previously indexed and have been replaced by more specific documents under `knowledge_base/playbooks/`.

When moving documents into or out of this archive, run a clean Qdrant rebuild so stale vectors are removed:

```bash
PYTHONPATH=. .venv/bin/python rag_index.py --recreate
```

If historical incident memory is stored in the same collection, re-apply it after recreating the collection.
