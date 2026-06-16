import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from scripts.qdrant_memory_retention import (
    HISTORICAL_INCIDENT_SOURCE_TYPE,
    QdrantMemoryPoint,
    build_retention_plan,
    run_retention,
)


class FakePoint:
    def __init__(self, point_id, payload):
        self.id = point_id
        self.payload = payload


class FakeClient:
    def __init__(self, points):
        self.points = points
        self.deleted = []
        self.scroll_calls = []

    def scroll(self, **kwargs):
        self.scroll_calls.append(kwargs)
        return self.points, None

    def delete(self, **kwargs):
        self.deleted.append(kwargs)


class FakeKnowledgeBase:
    def __init__(self, client):
        self.config = SimpleNamespace(collection_name="security_kb")
        self.client = client


class FakeDb:
    def close(self):
        pass


def historical_payload(
    incident_id,
    *,
    indexed_at="2025-01-01T00:00:00+00:00",
    status="CLOSED",
    source_type=HISTORICAL_INCIDENT_SOURCE_TYPE,
):
    return {
        "source_type": source_type,
        "source": f"incident:{incident_id}",
        "incident_id": incident_id,
        "status": status,
        "indexed_at": indexed_at,
        "content_hash": f"hash-{incident_id}",
        "text": "Historical Incident Memory",
    }


class QdrantMemoryRetentionTests(unittest.TestCase):
    def test_dry_run_does_not_delete_candidates(self):
        client = FakeClient(
            [
                FakePoint("historical-old", historical_payload(1)),
            ]
        )

        with patch(
            "scripts.qdrant_memory_retention.load_incident_statuses",
            return_value={1: "CLOSED"},
        ):
            result = run_retention(
                apply=False,
                retention_days=30,
                max_records=100,
                include_open=False,
                db_factory=FakeDb,
                knowledge_base_factory=lambda: FakeKnowledgeBase(client),
            )

        self.assertEqual(result["mode"], "DRY_RUN")
        self.assertEqual(result["candidates"], 1)
        self.assertEqual(result["deleted"], 0)
        self.assertEqual(client.deleted, [])

    def test_apply_deletes_only_historical_incident_points(self):
        client = FakeClient(
            [
                FakePoint("historical-old", historical_payload(1)),
                FakePoint(
                    "knowledge-base",
                    {
                        "source_type": "knowledge_base",
                        "source": "knowledge_base/security_playbook.md",
                        "text": "Playbook must be preserved.",
                    },
                ),
            ]
        )

        with patch(
            "scripts.qdrant_memory_retention.load_incident_statuses",
            return_value={1: "CLOSED"},
        ):
            result = run_retention(
                apply=True,
                retention_days=30,
                max_records=100,
                include_open=False,
                db_factory=FakeDb,
                knowledge_base_factory=lambda: FakeKnowledgeBase(client),
            )

        self.assertEqual(result["deleted"], 1)
        self.assertEqual(client.deleted[0]["points_selector"], ["historical-old"])
        self.assertEqual(result["skipped"]["protected_source_type"], 1)

    def test_knowledge_base_points_are_preserved_by_plan(self):
        candidates, skipped = build_retention_plan(
            [
                QdrantMemoryPoint(
                    point_id="knowledge-base",
                    payload={
                        "source_type": "knowledge_base",
                        "source": "knowledge_base/security_playbook.md",
                    },
                )
            ],
            incident_statuses={},
            retention_days=1,
            include_open=True,
            now=datetime(2026, 6, 16, tzinfo=timezone.utc),
        )

        self.assertEqual(candidates, [])
        self.assertEqual(skipped["protected_source_type"], 1)

    def test_missing_or_invalid_payload_is_skipped_safely(self):
        candidates, skipped = build_retention_plan(
            [
                QdrantMemoryPoint(
                    point_id="invalid",
                    payload={
                        "source_type": HISTORICAL_INCIDENT_SOURCE_TYPE,
                        "source": "incident:missing-id",
                    },
                ),
                QdrantMemoryPoint(
                    point_id="unknown",
                    payload={"source_type": "custom", "source": "custom:1"},
                ),
            ],
            incident_statuses={},
            retention_days=1,
            include_open=True,
            now=datetime(2026, 6, 16, tzinfo=timezone.utc),
        )

        self.assertEqual(candidates, [])
        self.assertEqual(skipped["invalid_payload"], 2)

    def test_summary_reports_missing_and_duplicate_candidates(self):
        client = FakeClient(
            [
                FakePoint("missing-incident", historical_payload(999)),
                FakePoint(
                    "new-memory",
                    historical_payload(1, indexed_at="2026-06-15T00:00:00+00:00"),
                ),
                FakePoint(
                    "stale-memory",
                    historical_payload(1, indexed_at="2026-06-14T00:00:00+00:00"),
                ),
            ]
        )

        with patch(
            "scripts.qdrant_memory_retention.load_incident_statuses",
            return_value={1: "CLOSED"},
        ):
            result = run_retention(
                apply=False,
                retention_days=180,
                max_records=100,
                include_open=False,
                db_factory=FakeDb,
                knowledge_base_factory=lambda: FakeKnowledgeBase(client),
            )

        self.assertEqual(result["candidates"], 2)
        self.assertEqual(result["candidate_reasons"]["incident_missing_in_db"], 1)
        self.assertEqual(result["candidate_reasons"]["duplicate_incident_memory"], 1)
        self.assertIn("historical_incident", result["decision_boundary"])


if __name__ == "__main__":
    unittest.main()
