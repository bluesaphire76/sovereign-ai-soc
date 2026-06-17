import unittest
from pathlib import Path
from unittest.mock import patch

from models import CaseAction, CaseClosureChecklist, DetectionControlRule, IncidentCase
from qdrant_knowledge import QdrantKnowledgeBase, QdrantKnowledgeConfig
from scripts.index_detection_case_memory_to_qdrant import (
    CASE_CLOSURE_SOURCE_TYPE,
    DETECTION_CASE_DECISION_BOUNDARY,
    DETECTION_CONTROL_SOURCE_TYPE,
    DetectionCaseMemoryLoad,
    build_case_closure_memory,
    build_detection_control_memory,
    run_indexing,
    should_include_case_closure,
)


class FakeEncoder:
    def encode(self, text):
        return [0.1, 0.2, 0.3]


class FakeCollection:
    name = "security_kb"


class FakeCollections:
    collections = [FakeCollection()]


class FakeClient:
    def __init__(self, points=None):
        self.upserts = []
        self.deleted = []
        self.points = points or []

    def get_collections(self):
        return FakeCollections()

    def upsert(self, **kwargs):
        self.upserts.append(kwargs)

    def scroll(self, **kwargs):
        return self.points, None

    def delete(self, **kwargs):
        self.deleted.append(kwargs)


class FakePoint:
    def __init__(self, point_id, payload):
        self.id = point_id
        self.payload = payload


class FakeDb:
    def close(self):
        pass


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


def detection_rule():
    return DetectionControlRule(
        id="dcr-test",
        rule_type="NOISE_SUPPRESSION",
        name="Scanner token=hidden noise suppression",
        description="Suppress benign scanner password=secret pattern.",
        scope="host:web-01",
        matcher_kind="CONTAINS",
        matcher_value="scanner token=super-secret source",
        reason="Known vulnerability scanner maintenance noise.",
        owner="soc_admin",
        enabled=True,
        status="ACTIVE",
        last_validation_status="OK",
        last_validation_message="Validation passed.",
    )


def closure():
    return CaseClosureChecklist(
        case_id=42,
        root_cause="Authorized scanner password=secret generated alert.",
        evidence_reviewed="Wazuh alert, scanner schedule and analyst notes.",
        actions_summary="No remediation needed. Tuning review opened.",
        closure_reason="False positive validated by SOC.",
        closure_decision="FALSE_POSITIVE",
        final_severity="LOW",
        residual_risk="Low residual risk accepted by owner.",
        closure_approved=True,
    )


class QdrantDetectionCaseMemoryTests(unittest.TestCase):
    def test_detection_control_memory_redacts_sensitive_matcher_text(self):
        memory = build_detection_control_memory(detection_rule())

        self.assertEqual(memory.record.source_type, DETECTION_CONTROL_SOURCE_TYPE)
        self.assertEqual(memory.record.payload["source_type"], DETECTION_CONTROL_SOURCE_TYPE)
        self.assertEqual(memory.record.payload["rule_id"], "dcr-test")
        self.assertIn("Detection Control Semantic Memory", memory.record.text)
        self.assertIn(DETECTION_CASE_DECISION_BOUNDARY, memory.record.text)
        self.assertIn("<REDACTED_TOKEN>", memory.record.text)
        self.assertIn("<REDACTED_SECRET>", memory.record.text)
        self.assertNotIn("super-secret", memory.record.text)

    def test_case_closure_memory_includes_case_context_without_raw_payloads(self):
        memory = build_case_closure_memory(
            closure(),
            case=IncidentCase(
                id=42,
                group_key="case-test",
                title="Scanner false positive",
                status="CLOSED",
                severity="LOW",
                risk_score=15,
                summary="Scanner generated expected authentication failures.",
            ),
            incident_count=3,
            actions=[
                CaseAction(
                    title="Review scanner scope",
                    description="Validated as expected maintenance.",
                    category="INVESTIGATION",
                    priority="LOW",
                    status="DONE",
                )
            ],
        )

        self.assertEqual(memory.record.source_type, CASE_CLOSURE_SOURCE_TYPE)
        self.assertEqual(memory.record.payload["case_id"], 42)
        self.assertIn("Case Closure Semantic Memory", memory.record.text)
        self.assertIn("Scanner false positive", memory.record.text)
        self.assertIn("<REDACTED_SECRET>", memory.record.text)
        self.assertNotIn("password=secret", memory.record.text)

    def test_dry_run_does_not_upsert_records(self):
        detection_memory = build_detection_control_memory(detection_rule())
        closure_memory = build_case_closure_memory(closure())

        class FailingKb:
            def index_memory_records(self, records):
                raise AssertionError("dry-run must not upsert")

        with patch(
            "scripts.index_detection_case_memory_to_qdrant.load_detection_case_memories",
            return_value=DetectionCaseMemoryLoad(
                memories=[detection_memory, closure_memory],
                detection_control_rows_scanned=1,
                case_closure_rows_scanned=1,
                case_closure_skipped_non_final=0,
            ),
        ):
            result = run_indexing(
                limit=100,
                include_detection_control=True,
                include_case_closure=True,
                apply=False,
                db_factory=FakeDb,
                knowledge_base_factory=FailingKb,
            )

        self.assertEqual(result["mode"], "dry-run")
        self.assertEqual(result["records_prepared"], 2)
        self.assertEqual(result["detection_control_records"], 1)
        self.assertEqual(result["case_closure_records"], 1)
        self.assertEqual(result["indexed_points"], 0)

    def test_case_closure_memory_requires_final_status_or_approval(self):
        item = closure()
        item.closure_approved = False

        self.assertFalse(
            should_include_case_closure(
                item,
                IncidentCase(id=42, status="INVESTIGATING"),
            )
        )
        self.assertTrue(
            should_include_case_closure(
                item,
                IncidentCase(id=42, status="CLOSED"),
            )
        )

    def test_apply_indexes_distinct_source_types(self):
        detection_memory = build_detection_control_memory(detection_rule())
        closure_memory = build_case_closure_memory(closure())
        client = FakeClient()
        kb = QdrantKnowledgeBase(config(), client=client, encoder=FakeEncoder())

        result = kb.index_memory_records([detection_memory.record, closure_memory.record])

        self.assertEqual(result["indexed_points"], 2)
        payloads = [point.payload for point in client.upserts[0]["points"]]
        self.assertEqual(
            {payload["source_type"] for payload in payloads},
            {DETECTION_CONTROL_SOURCE_TYPE, CASE_CLOSURE_SOURCE_TYPE},
        )

    def test_apply_prunes_stale_detection_case_points_after_complete_scan(self):
        detection_memory = build_detection_control_memory(detection_rule())
        closure_memory = build_case_closure_memory(closure())
        client = FakeClient(
            points=[
                FakePoint(
                    "stale-case-closure",
                    {
                        "source_type": CASE_CLOSURE_SOURCE_TYPE,
                        "source": "case_closure:99",
                        "text": "Stale non-final closure memory.",
                    },
                )
            ]
        )

        with patch(
            "scripts.index_detection_case_memory_to_qdrant.load_detection_case_memories",
            return_value=DetectionCaseMemoryLoad(
                memories=[detection_memory, closure_memory],
                detection_control_rows_scanned=1,
                case_closure_rows_scanned=1,
                case_closure_skipped_non_final=2,
            ),
        ):
            result = run_indexing(
                limit=100,
                include_detection_control=True,
                include_case_closure=True,
                apply=True,
                db_factory=FakeDb,
                knowledge_base_factory=lambda: QdrantKnowledgeBase(
                    config(),
                    client=client,
                    encoder=FakeEncoder(),
                ),
            )

        self.assertEqual(result["indexed_points"], 2)
        self.assertEqual(result["case_closure_skipped_non_final"], 2)
        self.assertEqual(result["case_closure_prune_candidates"], 1)
        self.assertEqual(result["case_closure_pruned"], 1)
        self.assertEqual(client.deleted[0]["points_selector"], ["stale-case-closure"])


if __name__ == "__main__":
    unittest.main()
