import unittest
from unittest.mock import patch

from case_ai_analysis import build_case_prompt
from models import Incident, IncidentCase
from qdrant_knowledge import (
    SEMANTIC_MEMORY_DECISION_BOUNDARY,
    format_semantic_memory_context_for_prompt,
)


def sample_case():
    return IncidentCase(
        id=42,
        group_key="case-auth-endpoint-51",
        title="Repeated SSH authentication failures on endpoint-51",
        status="OPEN",
        severity="HIGH",
        agent="endpoint-51",
        correlation_type="auth_burst",
        risk_score=78,
        summary='{"summary": "Repeated SSH failures followed by an accepted login."}',
    )


def sample_incidents():
    return [
        Incident(
            id=5100,
            timestamp="2026-06-15T14:51:27Z",
            status="NEW",
            agent="endpoint-51",
            rule="SSH brute force authentication failures",
            level=10,
            mitre="T1110",
            risk_score=75,
            correlation_score=82,
            correlation_type="auth_burst",
            recommended_priority="HIGH",
            attack_chain="Initial Access",
            escalation_reason="Repeated failures require accepted-login validation.",
        )
    ]


class CaseAiAnalysisSemanticMemoryTests(unittest.TestCase):
    def test_formatter_includes_source_score_chunk_and_decision_boundary(self):
        formatted = format_semantic_memory_context_for_prompt(
            [
                {
                    "source": "knowledge_base/security_playbook.md",
                    "text": "SSH brute force playbook: validate accepted logins.",
                    "chunk_index": 2,
                    "score": 0.8123,
                }
            ],
            max_items=1,
        )

        self.assertIn("Retrieved Semantic Memory Context (Qdrant)", formatted)
        self.assertIn(SEMANTIC_MEMORY_DECISION_BOUNDARY, formatted)
        self.assertIn("source: knowledge_base/security_playbook.md", formatted)
        self.assertIn("chunk_index: 2", formatted)
        self.assertIn("semantic_score: 0.812", formatted)

    def test_case_prompt_includes_governed_semantic_memory_context(self):
        with patch(
            "case_ai_analysis.retrieve_security_context",
            return_value=[
                {
                    "source": "knowledge_base/security_playbook.md",
                    "text": "SSH brute force playbook: validate accepted logins.",
                    "chunk_index": 2,
                    "score": 0.81,
                }
            ],
        ):
            prompt = build_case_prompt(sample_case(), sample_incidents())

        self.assertIn("Retrieved Semantic Memory Context (Qdrant)", prompt)
        self.assertIn(SEMANTIC_MEMORY_DECISION_BOUNDARY, prompt)
        self.assertIn("semantic_score: 0.810", prompt)
        self.assertIn("chunk_index: 2", prompt)
        self.assertIn("Treat retrieved semantic memory as advisory context only", prompt)
        self.assertIn("Do not use semantic memory as primary evidence", prompt)
        self.assertIn("Do not use semantic memory to decide final severity", prompt)
        self.assertIn("Do not use semantic memory for operational deduplication", prompt)
        self.assertIn("Do not use semantic memory for automatic noise suppression", prompt)
        self.assertIn("Do not use semantic memory for incident or case closure", prompt)

    def test_case_prompt_handles_empty_semantic_memory_retrieval_safely(self):
        with patch("case_ai_analysis.retrieve_security_context", return_value=[]):
            prompt = build_case_prompt(sample_case(), sample_incidents())

        self.assertIn("Retrieved Semantic Memory Context (Qdrant)", prompt)
        self.assertIn("No semantic memory context was retrieved for this case.", prompt)
        self.assertIn("Do not use semantic memory to decide final severity", prompt)

    def test_case_prompt_handles_semantic_memory_failure_safely(self):
        with self.assertLogs("case_ai_analysis", level="WARNING"):
            with patch(
                "case_ai_analysis.retrieve_security_context",
                side_effect=RuntimeError("qdrant unavailable"),
            ):
                prompt = build_case_prompt(sample_case(), sample_incidents())

        self.assertIn("Retrieved Semantic Memory Context (Qdrant)", prompt)
        self.assertIn(
            "Semantic memory retrieval failed; continuing with case-only context.",
            prompt,
        )
        self.assertIn("Do not use semantic memory for incident or case closure", prompt)


if __name__ == "__main__":
    unittest.main()
