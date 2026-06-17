import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from api import is_request_authorized
from models import (
    CaseClosureChecklist,
    DetectionControlRule,
    Incident,
    IncidentCase,
    IncidentNote,
)
from qdrant_auto_index import (
    CASE_CLOSURE_SOURCE_TYPE,
    DETECTION_CONTROL_SOURCE_TYPE,
    HISTORICAL_INCIDENT_SOURCE_TYPE,
    get_auto_index_status,
    index_case_closure_memory,
    index_detection_control_memory,
    index_incident_memory,
)


class FakePoint:
    def __init__(self, point_id):
        self.id = point_id


class FakeClient:
    def __init__(self):
        self.deleted = []
        self.scroll_calls = []

    def scroll(self, **kwargs):
        self.scroll_calls.append(kwargs)
        return [FakePoint("old-point")], None

    def delete(self, *, collection_name, points_selector, wait):
        self.deleted.append(
            {
                "collection_name": collection_name,
                "points_selector": points_selector,
                "wait": wait,
            }
        )


class FakeKnowledgeBase:
    def __init__(self):
        self.config = SimpleNamespace(enabled=True, collection_name="security_kb")
        self.client = FakeClient()
        self.records = []

    def collection_exists(self):
        return True

    def index_memory_records(self, records):
        self.records.extend(records)
        return {
            "collection": self.config.collection_name,
            "indexed_points": len(records),
        }


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows if isinstance(rows, list) else [rows] if rows else []

    def filter(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return self.rows

    def count(self):
        return len(self.rows)


class FakeDb:
    def __init__(
        self,
        *,
        detection_rule=None,
        incident=None,
        case=None,
        closure=None,
        notes=None,
        actions=None,
        case_incidents=None,
    ):
        self.detection_rule = detection_rule
        self.incident = incident
        self.case = case
        self.closure = closure
        self.notes = notes or []
        self.actions = actions or []
        self.case_incidents = case_incidents or []
        self.closed = False

    def query(self, model):
        if model is DetectionControlRule:
            return FakeQuery(self.detection_rule)
        if model is Incident:
            return FakeQuery(self.incident)
        if model is IncidentCase:
            return FakeQuery(self.case)
        if model is CaseClosureChecklist:
            return FakeQuery(self.closure)
        if model is IncidentNote:
            return FakeQuery(self.notes)
        return FakeQuery(self.case_incidents if self.case_incidents else self.actions)

    def close(self):
        self.closed = True


def detection_rule():
    return DetectionControlRule(
        id="dcr-test",
        rule_type="NOISE_SUPPRESSION",
        name="Scanner noise suppression",
        description="Reviewed scanner maintenance noise.",
        scope="global",
        matcher_kind="CONTAINS",
        matcher_value="scanner maintenance",
        reason="Reviewed maintenance window.",
        owner="soc-admin",
        enabled=True,
        status="ACTIVE",
        last_validation_status="OK",
        last_validation_message="Validation passed.",
    )


def incident():
    return Incident(
        id=42,
        status="NEW",
        timestamp="2026-06-15T12:00:00Z",
        agent="server-01",
        rule="Multiple failed SSH logins",
        level=8,
        mitre="T1110",
        risk_score=82,
        ai_analysis="Reviewed authentication burst.",
        correlation_type="auth_burst",
        recommended_priority="HIGH",
    )


def closure(approved=False):
    return CaseClosureChecklist(
        case_id=7,
        root_cause="Expected scanner.",
        evidence_reviewed="Wazuh alerts.",
        actions_summary="Reviewed.",
        closure_reason="Benign.",
        closure_decision="FALSE_POSITIVE" if approved else None,
        final_severity="LOW" if approved else None,
        residual_risk="Low.",
        closure_approved=approved,
    )


class QdrantAutoIndexTests(unittest.TestCase):
    def test_detection_control_auto_index_replaces_existing_source_points(self):
        kb = FakeKnowledgeBase()
        result = index_detection_control_memory(
            "dcr-test",
            db_factory=lambda: FakeDb(detection_rule=detection_rule()),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["deleted_points"], 1)
        self.assertEqual(result["indexed_points"], 1)
        self.assertEqual(kb.records[0].source_type, DETECTION_CONTROL_SOURCE_TYPE)
        self.assertEqual(kb.records[0].source, "detection_control:dcr-test")
        self.assertEqual(kb.client.deleted[0]["points_selector"], ["old-point"])

    def test_case_closure_auto_index_skips_and_deletes_non_final_closure(self):
        kb = FakeKnowledgeBase()
        result = index_case_closure_memory(
            7,
            db_factory=lambda: FakeDb(
                case=IncidentCase(id=7, group_key="case-7", title="Case 7", status="OPEN"),
                closure=closure(approved=False),
            ),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["deleted_points"], 1)
        self.assertEqual(result["indexed_points"], 0)
        self.assertEqual(result["skip_reason"], "case_closure_not_final_or_approved")
        self.assertEqual(kb.records, [])

    def test_incident_auto_index_uses_current_incident_context(self):
        kb = FakeKnowledgeBase()
        note = IncidentNote(incident_id=42, note="Analyst confirmed scanner pattern.")
        result = index_incident_memory(
            42,
            db_factory=lambda: FakeDb(incident=incident(), notes=[note]),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["indexed_points"], 1)
        self.assertEqual(kb.records[0].source_type, HISTORICAL_INCIDENT_SOURCE_TYPE)
        self.assertEqual(kb.records[0].source, "incident:42")
        self.assertIn("Analyst confirmed scanner pattern", kb.records[0].text)

    def test_auto_index_status_is_read_only_and_reports_config(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch.dict(
            os.environ,
            {
                "QDRANT_AUTO_INDEX_STATE_PATH": os.path.join(tmpdir, "state.json"),
                "QDRANT_AUTO_INDEX_ENABLED": "true",
                "AI_SOC_RAG_ENABLED": "true",
            },
            clear=False,
        ):
            status = get_auto_index_status()

        self.assertEqual(status["status"], "OK")
        self.assertEqual(status["config"]["collection"], "security_kb")
        self.assertEqual(status["state"]["pending_operations"], 0)
        self.assertIn("best-effort", status["message"])

    def test_rbac_allows_operators_to_read_auto_index_status(self):
        self.assertTrue(
            is_request_authorized(
                "GET",
                "/semantic-memory/auto-index-status",
                {"role": "ANALYST"},
            )
        )
        self.assertFalse(
            is_request_authorized(
                "GET",
                "/semantic-memory/auto-index-status",
                {"role": "VIEWER"},
            )
        )


if __name__ == "__main__":
    unittest.main()
