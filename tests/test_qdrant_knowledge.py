import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

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
    build_knowledge_base_index_plan,
    chunk_text,
    discover_knowledge_base_documents,
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
        self.upserts = []

    def query_points(self, **kwargs):
        self.queries.append(kwargs)
        return FakeQueryResult(self.points)

    def get_collections(self):
        return SimpleNamespace(collections=[SimpleNamespace(name="security_kb")])

    def upsert(self, **kwargs):
        self.upserts.append(kwargs)


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

    def test_discover_knowledge_base_documents_is_recursive_and_excludes_non_operational_docs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir) / "knowledge_base"
            (base_path / "playbooks" / "authentication").mkdir(parents=True)
            (base_path / "playbooks" / "_templates").mkdir(parents=True)
            (base_path / "archive" / "legacy_playbooks").mkdir(parents=True)
            (base_path / "playbooks" / "README.md").write_text(
                "# Maintainer README\n",
                encoding="utf-8",
            )
            active_top_level = base_path / "case_closure_policy.md"
            active_nested = (
                base_path
                / "playbooks"
                / "authentication"
                / "ssh_bruteforce_investigation_playbook.md"
            )
            template_doc = base_path / "playbooks" / "_templates" / "playbook_template.md"
            archived_doc = (
                base_path / "archive" / "legacy_playbooks" / "security_playbook.md"
            )
            active_top_level.write_text("# Case Closure\n\n## Purpose\nClose safely.\n", encoding="utf-8")
            active_nested.write_text("# SSH\n\n## Purpose\nInvestigate SSH.\n", encoding="utf-8")
            template_doc.write_text("# Template\n\n## Purpose\nAuthoring only.\n", encoding="utf-8")
            archived_doc.write_text("# Legacy\n\n## Purpose\nRetired.\n", encoding="utf-8")

            documents, excluded = discover_knowledge_base_documents(base_path)

        self.assertEqual(documents, [active_top_level, active_nested])
        self.assertEqual(
            excluded,
            [
                archived_doc,
                base_path / "playbooks" / "README.md",
                template_doc,
            ],
        )

    def test_index_documents_indexes_recursive_playbooks_and_reports_exclusions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir) / "knowledge_base"
            (base_path / "playbooks" / "dns").mkdir(parents=True)
            (base_path / "playbooks" / "_templates").mkdir(parents=True)
            active_nested = base_path / "playbooks" / "dns" / "dns_c2_beaconing_playbook.md"
            excluded_readme = base_path / "playbooks" / "README.md"
            excluded_template = base_path / "playbooks" / "_templates" / "playbook_template.md"
            active_nested.write_text(
                "# DNS C2\n\n## Purpose\nInvestigate suspicious DNS beaconing.\n",
                encoding="utf-8",
            )
            excluded_readme.write_text("# README\n", encoding="utf-8")
            excluded_template.write_text("# Template\n", encoding="utf-8")

            encoder = FakeEncoder()
            client = FakeClient([])
            kb = QdrantKnowledgeBase(
                config(),
                client=client,
                encoder=encoder,
            )

            result = kb.index_documents(path=base_path)

        self.assertEqual(result["documents"], 1)
        self.assertEqual(result["excluded_documents"], 2)
        self.assertEqual(result["indexed_points"], 1)
        self.assertEqual(len(client.upserts), 1)
        indexed_sources = [
            point.payload["source"] for point in client.upserts[0]["points"]
        ]
        self.assertEqual(indexed_sources, [str(active_nested)])

    def test_playbook_front_matter_becomes_payload_metadata_not_embedded_text(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir) / "knowledge_base"
            playbook_path = (
                base_path
                / "playbooks"
                / "authentication"
                / "ssh_bruteforce_investigation_playbook.md"
            )
            playbook_path.parent.mkdir(parents=True)
            playbook_path.write_text(
                """---
title: SSH Brute Force Investigation Playbook
type: playbook
domain: authentication
source: wazuh
incident_types:
  - ssh_bruteforce
severity_hint:
  - high
mitre_tactics:
  - Credential Access
mitre_techniques:
  - T1110
applicability:
  - Multiple failed SSH login attempts
not_applicable_when:
  - Known vulnerability scanner
recommended_for_pages:
  - recommended_playbooks
  - incident_detail
tags:
  - ssh
  - brute-force
---
# SSH Brute Force Investigation Playbook

## Investigation Steps

- Review failed authentication attempts.
""",
                encoding="utf-8",
            )

            plan = build_knowledge_base_index_plan(base_path, playbooks_only=True)

        self.assertEqual(len(plan.documents), 1)
        self.assertEqual(len(plan.missing_metadata), 0)
        self.assertEqual(len(plan.chunks), 1)
        payload = plan.chunks[0].payload
        self.assertEqual(payload["doc_type"], "playbook")
        self.assertEqual(payload["kb_type"], "playbook")
        self.assertEqual(payload["title"], "SSH Brute Force Investigation Playbook")
        self.assertEqual(payload["domain"], "authentication")
        self.assertEqual(payload["playbook_source"], "wazuh")
        self.assertEqual(payload["incident_types"], ["ssh_bruteforce"])
        self.assertEqual(payload["mitre_techniques"], ["T1110"])
        self.assertEqual(payload["recommended_for_pages"], ["recommended_playbooks", "incident_detail"])
        self.assertEqual(payload["tags"], ["ssh", "brute-force"])
        self.assertEqual(payload["section"], "Investigation Steps")
        self.assertEqual(payload["section_order"], 1)
        self.assertEqual(payload["content_kind"], "playbook_section")
        self.assertNotIn("title:", payload["text"])
        self.assertNotIn("---", payload["text"])

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

    def test_retrieve_contexts_supports_source_type_filter_and_payload_fields(self):
        encoder = FakeEncoder()
        client = FakeClient(
            [
                FakePoint(
                    "point-historical",
                    {
                        "source_type": "historical_incident",
                        "source": "incident:4210",
                        "incident_id": 4210,
                        "status": "CLOSED",
                        "text": "Historical Incident Memory: similar SSH failures.",
                    },
                    score=0.81,
                )
            ]
        )
        kb = QdrantKnowledgeBase(config(), client=client, encoder=encoder)

        contexts = kb.retrieve_contexts(
            "ssh brute force",
            limit=1,
            source_type="historical_incident",
            payload_filter={"status": "CLOSED"},
            payload_fields=["incident_id", "status"],
        )

        self.assertEqual(len(contexts), 1)
        self.assertEqual(contexts[0]["source_type"], "historical_incident")
        self.assertEqual(contexts[0]["incident_id"], 4210)
        self.assertEqual(contexts[0]["status"], "CLOSED")
        self.assertIsNotNone(client.queries[0]["query_filter"])
        self.assertIn("historical_incident", str(client.queries[0]["query_filter"]))
        self.assertIn("CLOSED", str(client.queries[0]["query_filter"]))

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
