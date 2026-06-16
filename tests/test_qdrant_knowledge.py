import unittest
from pathlib import Path

import qdrant_knowledge
from investigation_ai.adapters import normalize_investigation_context
from investigation_ai.models import (
    InvestigationClaimClassification,
    InvestigationEvidenceStrength,
)
from investigation_ai.retrieval import (
    InvestigationRetrievalContext,
    InvestigationRetrievalRequest,
    InvestigationRetrievalType,
)
from qdrant_knowledge import (
    SEMANTIC_MEMORY_DECISION_BOUNDARY,
    QdrantKnowledgeBase,
    QdrantKnowledgeConfig,
    chunk_text,
    format_semantic_memory_context_for_prompt,
)


class FakeEncoder:
    def __init__(self):
        self.inputs = []

    def encode(self, text):
        self.inputs.append(text)
        return [0.1, 0.2, 0.3]


class FakePoint:
    def __init__(self, point_id, payload, score=0.82):
        self.id = point_id
        self.payload = payload
        self.score = score


class FakeQueryResult:
    def __init__(self, points):
        self.points = points


class FakeClient:
    def __init__(self, points):
        self.points = points
        self.queries = []

    def query_points(self, **kwargs):
        self.queries.append(kwargs)
        return FakeQueryResult(self.points)


def config(enabled=True):
    return QdrantKnowledgeConfig(
        enabled=enabled,
        url="http://qdrant.test:6333",
        collection_name="security_kb",
        embedding_model="test-model",
        timeout_seconds=1.0,
        default_limit=4,
        knowledge_base_path=Path("knowledge_base"),
    )


def retrieval_request():
    return InvestigationRetrievalRequest(
        request_id="retrieval-1-auth",
        request_type=InvestigationRetrievalType.AUTH_ACTIVITY,
        reason="Missing evidence requires retrieval: successful login verification",
        evidence_requested=["successful login verification"],
        entity_filters={"host": ["endpoint-51"], "user": ["alice"]},
        source_systems=["wazuh"],
        max_results=2,
    )


class QdrantKnowledgeBaseTests(unittest.TestCase):
    def test_markdown_playbooks_are_chunked_by_section(self):
        chunks = chunk_text(
            """
# Security Playbook Base

## SSH brute force
Indicatori:
- failed password

## Privilege escalation via sudo
Indicatori:
- sudo anomaly
""",
            max_chars=900,
        )

        self.assertEqual(len(chunks), 2)
        self.assertIn("SSH brute force", chunks[0])
        self.assertIn("Privilege escalation via sudo", chunks[1])

    def test_fetch_investigation_evidence_returns_contextual_evidence(self):
        encoder = FakeEncoder()
        client = FakeClient(
            [
                FakePoint(
                    "point-1",
                    {
                        "source": "knowledge_base/security_playbook.md",
                        "text": "SSH brute force playbook: verify accepted logins after repeated failures.",
                        "chunk_index": 0,
                    },
                )
            ]
        )
        kb = QdrantKnowledgeBase(config(), client=client, encoder=encoder)
        context = normalize_investigation_context(
            incident={
                "id": 51,
                "agent": "endpoint-51",
                "rule": "SSH brute force authentication failures",
                "mitre": "T1110",
            }
        )

        evidence = kb.fetch_investigation_evidence(
            retrieval_request(),
            InvestigationRetrievalContext(base_context=context),
        )

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0].source_system, "qdrant")
        self.assertEqual(evidence[0].source_table, "security_kb")
        self.assertEqual(evidence[0].strength, InvestigationEvidenceStrength.CONTEXTUAL)
        self.assertEqual(
            evidence[0].claim_classification,
            InvestigationClaimClassification.INFERRED,
        )
        self.assertIn("AUTH_ACTIVITY", evidence[0].summary)
        self.assertIn("Advisory-only semantic memory context", evidence[0].summary)
        self.assertIn("endpoint-51", encoder.inputs[0])
        self.assertEqual(client.queries[0]["collection_name"], "security_kb")
        self.assertEqual(client.queries[0]["limit"], 2)

    def test_semantic_memory_prompt_formatter_marks_context_advisory_only(self):
        formatted = format_semantic_memory_context_for_prompt(
            [
                {
                    "source": "knowledge_base/security_playbook.md",
                    "text": "SSH brute force playbook: verify accepted logins.",
                    "chunk_index": 3,
                    "score": 0.77,
                }
            ],
            max_items=1,
        )

        self.assertIn("Retrieved Semantic Memory Context (Qdrant)", formatted)
        self.assertIn(SEMANTIC_MEMORY_DECISION_BOUNDARY, formatted)
        self.assertIn("source: knowledge_base/security_playbook.md", formatted)
        self.assertIn("chunk_index: 3", formatted)
        self.assertIn("semantic_score: 0.770", formatted)
        self.assertIn("advisory_context", formatted)

    def test_semantic_memory_prompt_formatter_handles_empty_context(self):
        formatted = format_semantic_memory_context_for_prompt([])

        self.assertIn("Retrieved Semantic Memory Context (Qdrant)", formatted)
        self.assertIn("advisory only", formatted)
        self.assertIn("No semantic memory context was retrieved.", formatted)

    def test_disabled_retrieval_does_not_query_qdrant(self):
        encoder = FakeEncoder()
        client = FakeClient([])
        kb = QdrantKnowledgeBase(config(enabled=False), client=client, encoder=encoder)

        self.assertEqual(kb.retrieve_contexts("ssh brute force", limit=3), [])
        self.assertEqual(client.queries, [])
        self.assertEqual(encoder.inputs, [])

    def test_legacy_retrieve_security_context_uses_default_knowledge_base(self):
        old_default = qdrant_knowledge._DEFAULT_KNOWLEDGE_BASE
        encoder = FakeEncoder()
        client = FakeClient(
            [
                FakePoint(
                    "point-legacy",
                    {
                        "source": "knowledge_base/security_playbook.md",
                        "text": "Privilege escalation playbook: review sudo usage and owner approval.",
                    },
                    score=0.77,
                )
            ]
        )
        qdrant_knowledge._DEFAULT_KNOWLEDGE_BASE = QdrantKnowledgeBase(
            config(),
            client=client,
            encoder=encoder,
        )

        try:
            contexts = qdrant_knowledge.retrieve_security_context("sudo escalation", limit=1)
        finally:
            qdrant_knowledge._DEFAULT_KNOWLEDGE_BASE = old_default

        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["source"], "knowledge_base/security_playbook.md")
        self.assertEqual(contexts[0]["score"], 0.77)
        self.assertEqual(client.queries[0]["limit"], 1)


if __name__ == "__main__":
    unittest.main()
