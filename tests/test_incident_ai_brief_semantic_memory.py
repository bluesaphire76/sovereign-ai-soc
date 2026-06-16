import unittest

from incident_ai_brief import (
    SEMANTIC_MEMORY_DECISION_BOUNDARY,
    build_prompt,
    enrich_brief_with_semantic_memory_context,
    format_retrieved_semantic_memory_context,
)


class IncidentAiBriefSemanticMemoryTests(unittest.TestCase):
    def test_format_retrieved_semantic_memory_context_labels_support_only_boundary(self):
        context = [
            {
                "source": "knowledge_base/security_playbook.md",
                "chunk_index": 1,
                "score": 0.70748055,
                "text": "SSH brute force investigation guidance.",
            }
        ]

        formatted = format_retrieved_semantic_memory_context(context)

        self.assertIn("Retrieved semantic memory", formatted)
        self.assertIn("advisory only", formatted)
        self.assertIn("source: knowledge_base/security_playbook.md", formatted)
        self.assertIn("chunk_index: 1", formatted)
        self.assertIn("semantic_score: 0.707", formatted)
        self.assertIn("must not be used as primary operational deduplication", formatted)

    def test_build_prompt_contains_semantic_memory_guardrails(self):
        incident_payload = {
            "id": 123,
            "status": "NEW",
            "timestamp_local": "2026-06-16 10:00:00 CEST",
            "agent": "test-host",
            "rule": "Multiple failed SSH logins",
            "level": 8,
            "mitre": "T1110",
            "risk_score": 70,
            "risk_band": "High",
            "raw_alert": {},
            "extracted_entities": {},
            "network_evidence": {"available": False},
            "dns_context": {"available": False},
        }
        security_context = [
            {
                "source": "knowledge_base/security_playbook.md",
                "chunk_index": 1,
                "score": 0.66,
                "text": "SSH brute force investigation playbook.",
            }
        ]

        prompt = build_prompt(incident_payload, security_context)

        self.assertIn("Retrieved Semantic Memory Context", prompt)
        self.assertIn("Semantic memory usage rules", prompt)
        self.assertIn("Do not use semantic memory to decide final severity", prompt)
        self.assertIn("Do not use semantic memory for operational deduplication", prompt)
        self.assertIn("Do not use semantic memory for automatic noise suppression", prompt)
        self.assertIn("Do not use semantic memory for incident or case closure", prompt)
        self.assertIn(SEMANTIC_MEMORY_DECISION_BOUNDARY, prompt)

    def test_enrich_brief_with_semantic_memory_context_adds_visible_context_only_evidence(self):
        brief = {
            "evidence_used": [],
            "evidence_overview": [],
            "recommended_actions": [],
        }
        context = [
            {
                "source": "knowledge_base/security_playbook.md",
                "chunk_index": 2,
                "score": 0.71,
                "text": "SSH guidance.",
            }
        ]

        enriched = enrich_brief_with_semantic_memory_context(brief, context)

        evidence_labels = [item["label"] for item in enriched["evidence_used"]]
        overview_sources = [item["source"] for item in enriched["evidence_overview"]]
        actions = [item["action"] for item in enriched["recommended_actions"]]

        self.assertIn("Retrieved semantic memory context", evidence_labels)
        self.assertIn("Semantic memory (Qdrant)", overview_sources)
        self.assertIn("Review retrieved semantic memory context as advisory guidance only", actions)

        description = enriched["evidence_used"][0]["description"]
        self.assertIn("advisory only", description)
        self.assertIn("must not be used as primary evidence", description)
        self.assertIn("final severity", description)
        self.assertIn("deduplication", description)
        self.assertIn("suppression", description)
        self.assertIn("closure", description)


if __name__ == "__main__":
    unittest.main()
