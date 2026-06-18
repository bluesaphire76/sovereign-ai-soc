import json
import unittest
from types import SimpleNamespace

from recommended_playbooks_llm import (
    apply_generation_to_recommendations,
    build_case_generation_facts,
    build_deterministic_playbooks_generation,
    build_recommended_playbooks_prompt,
    generate_recommended_playbooks,
)


def recommendation(
    *,
    title="SSH Brute Force Investigation Playbook",
    category="authentication",
    retrieval_stage="strong_source_domain_type_mitre",
):
    return {
        "title": title,
        "category": category,
        "source": "knowledge_base/playbooks/authentication/ssh_bruteforce_investigation_playbook.md",
        "file_path": "knowledge_base/playbooks/authentication/ssh_bruteforce_investigation_playbook.md",
        "domain": "authentication",
        "playbook_source": "wazuh",
        "incident_types": ["ssh_bruteforce", "repeated_failed_login"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110"],
        "matched_metadata": ["source", "domain", "incident_type", "mitre_technique"],
        "retrieval_stage": retrieval_stage,
        "why_suggested": ["Repeated SSH failures matched the authentication playbook."],
        "recommended_checks": [
            "Review failed and successful authentication events.",
            "Validate source ownership.",
        ],
        "supporting_chunks": [
            {
                "section": "Evidence to Collect",
                "excerpt": "Collect SSH authentication events, source IP and target usernames.",
                "relevance_score": 84,
            },
            {
                "section": "False Positive Conditions",
                "excerpt": "Confirm approved scanner, penetration test or administrator activity.",
                "relevance_score": 78,
            },
        ],
    }


class RecommendedPlaybooksLlmTests(unittest.TestCase):
    def test_prompt_separates_facts_playbooks_history_and_governance(self):
        prompt = build_recommended_playbooks_prompt(
            target_type="incident",
            current_facts={
                "rule_name": "Repeated SSH failed password",
                "mitre": "T1110",
            },
            recommendations=[recommendation()],
            similar_incidents=[
                {
                    "incident_id": 77,
                    "score": 0.88,
                    "status": "FALSE_POSITIVE",
                    "rule": "Approved scanner SSH activity",
                    "excerpt": "Scanner ownership was confirmed by the analyst.",
                }
            ],
        )

        self.assertIn("CURRENT INCIDENT FACTS", prompt)
        self.assertIn("RETRIEVED PLAYBOOK CONTEXT", prompt)
        self.assertIn("SIMILAR HISTORICAL INCIDENTS", prompt)
        self.assertIn("GOVERNANCE AND HUMAN-IN-THE-LOOP CONSTRAINTS", prompt)
        self.assertIn("OUTPUT REQUIREMENTS", prompt)
        self.assertIn("SSH Brute Force Investigation Playbook", prompt)
        self.assertIn("Historical incidents are supporting validation patterns only", prompt)
        self.assertIn("Evidence to Collect", prompt)

    def test_valid_llm_output_uses_only_retrieved_titles_and_enriches_cards(self):
        recommendations = [
            recommendation(),
            recommendation(
                title="False Positive Classification Playbook",
                category="closure",
            ),
        ]
        captured = {}

        def fake_llm(**kwargs):
            captured.update(kwargs)
            return {
                "text": json.dumps(
                    {
                        "selection_summary": "SSH failures require authentication and benign-source validation.",
                        "playbooks": [
                            {
                                "title": "SSH Brute Force Investigation Playbook",
                                "why_applies": "The incident contains repeated failed SSH authentication attempts.",
                                "supporting_incident_facts": [
                                    "The current rule reports repeated failed passwords."
                                ],
                                "immediate_analyst_checks": [
                                    "Review the authentication timeline for the affected account."
                                ],
                                "evidence_to_collect": [
                                    "Collect failed and successful SSH events for the source and user."
                                ],
                                "false_positive_checks": [
                                    "Confirm whether the source belongs to an approved scanner."
                                ],
                                "escalation_criteria": [
                                    "Escalate if a successful login follows the failures."
                                ],
                                "containment_remediation_guidance": [
                                    "Consider source blocking only after analyst approval."
                                ],
                                "closure_considerations": [
                                    "Document source ownership before false-positive closure."
                                ],
                            },
                            {
                                "title": "Invented Malware Eradication Playbook",
                                "why_applies": "This title was not retrieved.",
                            },
                        ],
                        "limitations": [],
                    }
                ),
                "profile": "standard",
                "model": "qwen-test",
                "fallback_used": False,
                "latency_ms": 123,
                "provider_key": "local_ollama",
                "provider_type": "LOCAL_OLLAMA",
                "used_external_provider": False,
            }

        generation = generate_recommended_playbooks(
            target_type="incident",
            current_facts={"rule_name": "Repeated SSH failures"},
            recommendations=recommendations,
            similar_incidents=[],
            severity="HIGH",
            llm_generator=fake_llm,
        )
        enriched = apply_generation_to_recommendations(recommendations, generation)

        titles = [item["title"] for item in generation["playbooks"]]
        self.assertEqual(
            titles,
            [
                "SSH Brute Force Investigation Playbook",
                "False Positive Classification Playbook",
            ],
        )
        self.assertNotIn("Invented Malware Eradication Playbook", titles)
        self.assertEqual(generation["generation"]["source"], "local_ai")
        self.assertEqual(generation["generation"]["model"], "qwen-test")
        self.assertIn("Human Decision Required", generation["generated_markdown"])
        self.assertEqual(
            enriched[0]["recommended_checks"][0],
            "Review the authentication timeline for the affected account.",
        )
        self.assertIn("messages", captured)
        self.assertEqual(captured["requested_mode"], "standard")

    def test_llm_failure_returns_structured_deterministic_fallback(self):
        def failing_llm(**_kwargs):
            raise TimeoutError("timeout")

        generation = generate_recommended_playbooks(
            target_type="incident",
            current_facts={"rule_name": "Repeated SSH failures"},
            recommendations=[recommendation()],
            llm_generator=failing_llm,
        )

        self.assertEqual(generation["generation"]["source"], "deterministic_fallback")
        self.assertEqual(generation["generation"]["error_type"], "TimeoutError")
        self.assertIn(
            "local AI model was unavailable",
            generation["selection_summary"],
        )
        self.assertTrue(generation["playbooks"][0]["evidence_to_collect"])
        self.assertTrue(generation["playbooks"][0]["false_positive_checks"])
        self.assertIn("analyst review and approval", generation["generated_markdown"])

    def test_broad_retrieval_is_labeled_as_weak_in_fallback(self):
        generation = build_deterministic_playbooks_generation(
            recommendations=[
                recommendation(retrieval_stage="broad_knowledge_base")
            ],
            reason="InvalidLlmOutput",
        )

        self.assertIn(
            "broad guidance match",
            generation["playbooks"][0]["why_applies"],
        )

    def test_expanded_categories_have_specific_deterministic_fallbacks(self):
        scenarios = [
            ("windows_host", "Windows Event IDs"),
            ("malware", "process tree"),
            ("data_exfiltration", "outbound bytes"),
            ("governance", "supporting and contradictory evidence"),
        ]

        for category, expected_text in scenarios:
            with self.subTest(category=category):
                generation = build_deterministic_playbooks_generation(
                    recommendations=[
                        recommendation(
                            title=f"{category} playbook",
                            category=category,
                        )
                    ],
                    reason="TimeoutError",
                )
                evidence = " ".join(
                    generation["playbooks"][0]["evidence_to_collect"]
                )
                self.assertIn(expected_text, evidence)
                self.assertTrue(
                    generation["playbooks"][0][
                        "containment_remediation_guidance"
                    ]
                )

    def test_case_facts_keep_linked_incidents_and_actions_structured(self):
        facts = build_case_generation_facts(
            SimpleNamespace(
                id=99,
                title="SSH investigation",
                status="INVESTIGATING",
                severity="HIGH",
                severity_review=None,
                risk_score=80,
                correlation_type="auth_burst",
                summary="Authentication case.",
            ),
            incidents=[
                SimpleNamespace(
                    id=42,
                    status="OPEN",
                    rule="Repeated SSH failures",
                    level=10,
                    risk_score=75,
                    recommended_priority="HIGH",
                    agent="server-01",
                    mitre="T1110",
                    correlation_type="auth_burst",
                    correlation_summary=None,
                    attack_chain="Credential Access",
                    escalation_reason="Repeated failures",
                    ai_analysis="Possible brute force",
                    raw_alert="large raw alert",
                )
            ],
            actions=[
                SimpleNamespace(
                    title="Validate source",
                    category="INVESTIGATION",
                    priority="HIGH",
                    status="OPEN",
                    description="Confirm scanner ownership.",
                )
            ],
            closure=None,
            latest_analysis=None,
        )

        self.assertIsInstance(facts["linked_incidents"], list)
        self.assertIsInstance(facts["linked_incidents"][0], dict)
        self.assertEqual(
            facts["linked_incidents"][0]["rule_name"],
            "Repeated SSH failures",
        )
        self.assertEqual(facts["existing_actions"][0]["title"], "Validate source")


if __name__ == "__main__":
    unittest.main()
