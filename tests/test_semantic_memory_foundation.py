from pathlib import Path
import unittest

from qdrant_knowledge import QdrantKnowledgeBase, QdrantKnowledgeConfig


class FakeCollection:
    def __init__(self, name: str):
        self.name = name


class FakeCollectionsResponse:
    def __init__(self, names):
        self.collections = [FakeCollection(name) for name in names]


class FakeCollectionInfo:
    points_count = 3
    indexed_vectors_count = 3
    vectors_count = 3
    status = "green"


class FakeClient:
    def __init__(self, names=None):
        self.names = names or ["security_kb"]
        self.collection_requests = []

    def get_collections(self):
        return FakeCollectionsResponse(self.names)

    def get_collection(self, collection_name):
        self.collection_requests.append(collection_name)
        return FakeCollectionInfo()


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


class SemanticMemoryFoundationTests(unittest.TestCase):
    def test_capabilities_expose_support_only_boundary(self):
        kb = QdrantKnowledgeBase(config(), client=FakeClient())

        capabilities = kb.capabilities()

        self.assertTrue(capabilities["enabled"])
        self.assertEqual(capabilities["mode"], "semantic_memory_support_only")
        self.assertIn("playbook_retrieval", capabilities["allowed_uses"])
        self.assertIn("final_severity_decision", capabilities["forbidden_uses"])
        self.assertIn("decision support only", capabilities["decision_boundary"].lower())

    def test_collection_info_reports_existing_collection_without_embedding(self):
        client = FakeClient(["security_kb"])
        kb = QdrantKnowledgeBase(config(), client=client)

        info = kb.collection_info()

        self.assertEqual(info["status"], "OK")
        self.assertTrue(info["exists"])
        self.assertEqual(info["points_count"], 3)
        self.assertEqual(client.collection_requests, ["security_kb"])

    def test_collection_info_warns_when_collection_missing(self):
        kb = QdrantKnowledgeBase(config(), client=FakeClient(["other_collection"]))

        info = kb.collection_info()

        self.assertEqual(info["status"], "WARN")
        self.assertFalse(info["exists"])
        self.assertIn("missing", info["message"].lower())

    def test_health_check_includes_guardrails(self):
        kb = QdrantKnowledgeBase(config(), client=FakeClient())

        health = kb.health_check()

        self.assertEqual(health["component"], "semantic_memory")
        self.assertEqual(health["provider"], "qdrant")
        self.assertIn("forbidden_uses", health["capabilities"])


if __name__ == "__main__":
    unittest.main()
