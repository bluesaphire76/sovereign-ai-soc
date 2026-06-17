import unittest
from pathlib import Path
from unittest.mock import patch

from models import Incident, IncidentNote
from qdrant_knowledge import (
    QdrantKnowledgeBase,
    QdrantKnowledgeConfig,
    stable_memory_point_id,
)
from scripts.index_historical_incidents_to_qdrant import (
    HISTORICAL_INCIDENT_DECISION_BOUNDARY,
    HISTORICAL_INCIDENT_SOURCE_TYPE,
    build_historical_incident_memory,
    run_indexing,
    should_include_incident,
)


class FakeEncoder:
    def encode(self, text):
        return [0.1, 0.2, 0.3]


class FakeCollection:
    name = "security_kb"


class FakeCollections:
    collections = [FakeCollection()]


class FakeClient:
    def __init__(self):
        self.upserts = []

    def get_collections(self):
        return FakeCollections()

    def upsert(self, **kwargs):
        self.upserts.append(kwargs)


class FakeDb:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def config():
    return QdrantKnowledgeConfig(
        enabled=True,
        url="http://qdrant.test:6333",
        collection_name="security_kb",
        embedding_model="test-model",
        timeout_seconds=1.0,
        default_limit=4,
        knowledge_base_path=Path("knowledge_base"),
    )


def incident():
    return Incident(
        id=1234,
        wazuh_doc_id="wazuh-doc-1234",
        status="CLOSED",
        timestamp="2026-06-15T14:51:27Z",
        agent="endpoint-51",
        rule="Multiple failed SSH logins",
        level=8,
        mitre="T1110",
        risk_score=70,
        ai_analysis="Likely brute force. token=super-secret should be redacted.",
        raw_alert='{"full_log": "password=secret raw telemetry must never be indexed"}',
        correlation_type="auth_burst",
        attack_chain="Initial Access",
        escalation_reason="Repeated failures followed by accepted login.",
        recommended_priority="HIGH",
    )


class HistoricalIncidentMemoryTests(unittest.TestCase):
    def test_safe_text_builder_does_not_include_raw_alert(self):
        memory = build_historical_incident_memory(
            incident(),
            notes=[
                IncidentNote(
                    note="Analyst validated this as password=hidden maintenance noise.",
                    created_by="analyst",
                )
            ],
        )

        self.assertEqual(memory.record.source_type, HISTORICAL_INCIDENT_SOURCE_TYPE)
        self.assertEqual(memory.record.payload["source_type"], HISTORICAL_INCIDENT_SOURCE_TYPE)
        self.assertEqual(memory.record.payload["incident_id"], 1234)
        self.assertIn("Historical Incident Memory", memory.record.text)
        self.assertIn(HISTORICAL_INCIDENT_DECISION_BOUNDARY, memory.record.text)
        self.assertIn("<REDACTED_TOKEN>", memory.record.text)
        self.assertIn("<REDACTED_SECRET>", memory.record.text)
        self.assertNotIn("raw telemetry", memory.record.text)
        self.assertNotIn("raw_alert", memory.record.text)
        self.assertNotIn("super-secret", memory.record.text)

    def test_dry_run_does_not_call_qdrant_upsert(self):
        memory = build_historical_incident_memory(incident())

        class FailingKb:
            def index_memory_records(self, records):
                raise AssertionError("dry-run must not upsert")

        with patch(
            "scripts.index_historical_incidents_to_qdrant.load_historical_incident_memories",
            return_value=[memory],
        ):
            result = run_indexing(
                limit=10,
                since_days=None,
                include_open=False,
                apply=False,
                db_factory=FakeDb,
                knowledge_base_factory=FailingKb,
            )

        self.assertEqual(result["mode"], "dry-run")
        self.assertEqual(result["records_prepared"], 1)
        self.assertEqual(result["indexed_points"], 0)
        self.assertIn("advisory only", result["decision_boundary"])

    def test_apply_calls_qdrant_upsert_with_stable_payload(self):
        memory = build_historical_incident_memory(incident())
        client = FakeClient()
        kb = QdrantKnowledgeBase(config(), client=client, encoder=FakeEncoder())

        result = kb.index_memory_records([memory.record])

        self.assertEqual(result["indexed_points"], 1)
        self.assertEqual(len(client.upserts), 1)

        point = client.upserts[0]["points"][0]
        payload = point.payload
        expected_point_id = stable_memory_point_id(
            HISTORICAL_INCIDENT_SOURCE_TYPE,
            "incident:1234",
            payload["content_hash"],
        )

        self.assertEqual(str(point.id), expected_point_id)
        self.assertEqual(payload["source_type"], HISTORICAL_INCIDENT_SOURCE_TYPE)
        self.assertEqual(payload["source"], "incident:1234")
        self.assertEqual(payload["incident_id"], 1234)
        self.assertEqual(payload["rule"], "Multiple failed SSH logins")
        self.assertIn("Historical Incident Memory", payload["text"])
        self.assertIn(HISTORICAL_INCIDENT_DECISION_BOUNDARY, payload["text"])

    def test_run_indexing_apply_uses_knowledge_base_factory(self):
        memory = build_historical_incident_memory(incident())

        class RecordingKb:
            calls = []

            def index_memory_records(self, records):
                self.calls.append(records)
                return {"collection": "security_kb", "indexed_points": len(records)}

        with patch(
            "scripts.index_historical_incidents_to_qdrant.load_historical_incident_memories",
            return_value=[memory],
        ):
            result = run_indexing(
                limit=10,
                since_days=None,
                include_open=False,
                apply=True,
                db_factory=FakeDb,
                knowledge_base_factory=RecordingKb,
            )

        self.assertEqual(result["mode"], "apply")
        self.assertEqual(result["indexed_points"], 1)
        self.assertEqual(result["collection"], "security_kb")
        self.assertEqual(RecordingKb.calls[0][0].payload["source_type"], HISTORICAL_INCIDENT_SOURCE_TYPE)

    def test_investigating_status_is_excluded_from_historical_memory_by_default(self):
        item = incident()
        item.status = "INVESTIGATING"

        self.assertFalse(
            should_include_incident(
                item,
                include_open=False,
                since_days=None,
            )
        )

    def test_include_open_allows_non_terminal_historical_memory_indexing(self):
        item = incident()
        item.status = "CONTAINED"

        self.assertTrue(
            should_include_incident(
                item,
                include_open=True,
                since_days=None,
            )
        )


if __name__ == "__main__":
    unittest.main()
