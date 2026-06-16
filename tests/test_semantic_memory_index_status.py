import unittest
from dataclasses import replace

from qdrant_knowledge import QdrantKnowledgeBase, config_from_env


class FakeCollection:
    def __init__(self, name: str):
        self.name = name


class FakeCollections:
    collections = [FakeCollection("security_kb")]


class FakeCollectionInfo:
    points_count = 3
    indexed_vectors_count = 3
    vectors_count = None
    status = "green"


class FakePoint:
    def __init__(self, payload):
        self.payload = payload


class FakeQdrantClient:
    def get_collections(self):
        return FakeCollections()

    def get_collection(self, collection_name):
        return FakeCollectionInfo()

    def scroll(self, **kwargs):
        return (
            [
                FakePoint(
                    {
                        "source": "knowledge_base/security_playbook.md",
                        "chunk_index": 0,
                        "content_hash": "hash-0",
                        "text": "Do not expose full text in index governance.",
                    }
                ),
                FakePoint(
                    {
                        "source": "knowledge_base/security_playbook.md",
                        "chunk_index": 1,
                        "content_hash": "hash-1",
                        "text": "Do not expose full text in index governance.",
                    }
                ),
                FakePoint(
                    {
                        "source": "knowledge_base/case_policy.md",
                        "chunk_index": 0,
                        "content_hash": "hash-2",
                        "text": "Do not expose full text in index governance.",
                    }
                ),
            ],
            None,
        )


class FakeKnowledgeBase(QdrantKnowledgeBase):
    @property
    def client(self):
        return FakeQdrantClient()


class SemanticMemoryIndexStatusTests(unittest.TestCase):
    def test_index_status_groups_documents_without_exposing_text(self):
        config = replace(
            config_from_env(),
            enabled=True,
            collection_name="security_kb",
        )

        kb = FakeKnowledgeBase(config)

        result = kb.index_status()

        self.assertTrue(result["enabled"])
        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["collection"], "security_kb")
        self.assertEqual(result["documents_count"], 2)
        self.assertEqual(result["points_scanned"], 3)
        self.assertEqual(result["indexing_mode"], "manual_cli_only")
        self.assertEqual(result["source_type_counts"], {"knowledge_base": 3})

        documents = {item["source"]: item for item in result["documents"]}
        self.assertEqual(documents["knowledge_base/security_playbook.md"]["source_type"], "knowledge_base")
        self.assertEqual(documents["knowledge_base/security_playbook.md"]["chunks"], 2)
        self.assertEqual(documents["knowledge_base/security_playbook.md"]["first_chunk_index"], 0)
        self.assertEqual(documents["knowledge_base/security_playbook.md"]["last_chunk_index"], 1)
        self.assertEqual(documents["knowledge_base/security_playbook.md"]["content_hashes_count"], 2)

        for document in result["documents"]:
            self.assertNotIn("text", document)

    def test_index_status_disabled_is_safe(self):
        config = replace(
            config_from_env(),
            enabled=False,
            collection_name="security_kb",
        )

        kb = QdrantKnowledgeBase(config)
        result = kb.index_status()

        self.assertEqual(result["status"], "DISABLED")
        self.assertEqual(result["documents"], [])
        self.assertEqual(result["indexing_mode"], "manual_cli_only")


if __name__ == "__main__":
    unittest.main()
