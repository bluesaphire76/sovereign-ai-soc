import unittest
from types import SimpleNamespace

from api import is_request_authorized
from models import CaseAIAnalysis, CaseAction, CaseClosureChecklist, Incident, IncidentCase
from routers.playbook_recommendations import (
    KNOWLEDGE_BASE_SOURCE_TYPE,
    PLAYBOOK_RECOMMENDATION_DECISION_BOUNDARY,
    build_case_playbook_recommendations,
    build_incident_playbook_recommendations,
)


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows if isinstance(rows, list) else [rows] if rows else []

    def filter(self, *args, **kwargs):
        return self

    def join(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return self.rows


class FakeDb:
    def __init__(
        self,
        *,
        incident=None,
        case=None,
        incidents=None,
        actions=None,
        closure=None,
        latest_analysis=None,
    ):
        self.incident = incident
        self.case = case
        self.incidents = incidents or []
        self.actions = actions or []
        self.closure = closure
        self.latest_analysis = latest_analysis

    def query(self, model):
        if model is IncidentCase:
            return FakeQuery(self.case)
        if model is Incident:
            if self.incident is not None:
                return FakeQuery(self.incident)
            return FakeQuery(self.incidents)
        if model is CaseAction:
            return FakeQuery(self.actions)
        if model is CaseClosureChecklist:
            return FakeQuery(self.closure)
        if model is CaseAIAnalysis:
            return FakeQuery(self.latest_analysis)
        return FakeQuery([])


class FakeKnowledgeBase:
    def __init__(self, contexts=None, *, enabled=True, error=None):
        self.config = SimpleNamespace(enabled=enabled)
        self.contexts = contexts or []
        self.error = error
        self.calls = []
        self.mutation_calls = []

    def retrieve_contexts(self, query, *, limit=None, source_type=None, payload_fields=None):
        self.calls.append(
            {
                "query": query,
                "limit": limit,
                "source_type": source_type,
                "payload_fields": payload_fields,
            }
        )
        if self.error:
            raise self.error
        return list(self.contexts)[: limit or 25]

    def apply_remediation(self, *args, **kwargs):
        self.mutation_calls.append(("apply_remediation", args, kwargs))
        raise AssertionError("playbook recommendations must not apply remediation")

    def close_case(self, *args, **kwargs):
        self.mutation_calls.append(("close_case", args, kwargs))
        raise AssertionError("playbook recommendations must not close cases")


def incident():
    return Incident(
        id=42,
        rule="Multiple failed SSH logins",
        agent="server-01",
        level=10,
        mitre="T1110",
        risk_score=72,
        ai_analysis="Brute-force pattern against an exposed service.",
        attack_chain="Credential access",
        correlation_type="auth_burst",
        escalation_reason="Repeated failed logins from unusual source.",
        recommended_priority="HIGH",
    )


def network_incident():
    return Incident(
        id=43,
        rule="Suricata suspicious DNS beaconing alert",
        agent="endpoint-02",
        level=9,
        mitre="T1071",
        risk_score=68,
        ai_analysis="Suspicious DNS domain with periodic network beaconing pattern.",
        attack_chain="Command and control via DNS",
        correlation_type="network_dns",
        escalation_reason="Suricata and DNS telemetry indicate protocol anomaly.",
        recommended_priority="HIGH",
    )


def case():
    return IncidentCase(
        id=99,
        group_key="case-99",
        title="SSH brute force investigation",
        status="INVESTIGATING",
        severity="HIGH",
        severity_review="HIGH",
        risk_score=78,
        summary="Linked authentication alerts require triage and containment review.",
        correlation_type="auth_burst",
    )


def action():
    return CaseAction(
        id=7,
        case_id=99,
        title="Review authentication source",
        description="Validate source reputation and account lockout status.",
        category="INVESTIGATION",
        priority="HIGH",
        status="OPEN",
    )


def closure():
    return CaseClosureChecklist(
        case_id=99,
        closure_decision="RESOLVED",
        final_severity="MEDIUM",
        residual_risk="Monitor for repeated brute-force attempts.",
    )


def analysis():
    return CaseAIAnalysis(
        case_id=99,
        analysis="AI analysis recommends brute-force playbook and credential validation.",
        recommended_status="INVESTIGATING",
        recommended_severity="HIGH",
    )


def playbook_context(source="knowledge_base/security_playbook.md"):
    return {
        "source_type": KNOWLEDGE_BASE_SOURCE_TYPE,
        "source": source,
        "score": 0.82,
        "chunk_index": 2,
        "content_hash": "abc123",
        "text": "SSH brute-force playbook: validate account activity, source reputation and containment options.",
    }


def dns_playbook_context():
    return {
        "source_type": KNOWLEDGE_BASE_SOURCE_TYPE,
        "source": "knowledge_base/dns_suricata_investigation_playbook.md",
        "score": 0.87,
        "chunk_index": 0,
        "content_hash": "dns123",
        "text": (
            "# DNS and Suricata Investigation Playbook\n\n"
            "This playbook supports suspicious DNS and Suricata network telemetry.\n\n"
            "Analyst actions:\n\n"
            "- check query volume and first-seen time;\n"
            "- inspect requesting host and user context;\n"
            "- compare with known update services and internal applications;\n"
            "- link DNS evidence to endpoint, proxy, firewall or EDR evidence before escalating.\n"
        ),
    }


def closure_playbook_context():
    return {
        "source_type": KNOWLEDGE_BASE_SOURCE_TYPE,
        "source": "knowledge_base/case_closure_policy.md",
        "score": 0.79,
        "chunk_index": 0,
        "content_hash": "closure123",
        "text": (
            "# Case Closure Policy\n\n"
            "This policy supports case closure checklist and residual risk review.\n\n"
            "Closure preconditions:\n\n"
            "- relevant incidents are reviewed;\n"
            "- evidence is summarized;\n"
            "- action plan is complete or accepted as residual risk;\n"
            "- closure approval is recorded when required.\n"
        ),
    }


def remediation_playbook_context():
    return {
        "source_type": KNOWLEDGE_BASE_SOURCE_TYPE,
        "source": "knowledge_base/remediation_governance_playbook.md",
        "score": 0.95,
        "chunk_index": 3,
        "content_hash": "remediation123",
        "text": (
            "# Governed Remediation Playbook\n\n"
            "This playbook supports proposal-only remediation and approval flow.\n\n"
            "## Common Remediation Patterns\n\n"
            "Low-risk examples:\n\n"
            "- create an investigation task;\n"
            "- enrich a case with recommended checks;\n"
            "- propose a detection tuning review;\n"
            "- request password reset review.\n"
        ),
    }


class PlaybookRecommendationTests(unittest.TestCase):
    def test_incident_recommendations_are_read_only_knowledge_base_context(self):
        kb = FakeKnowledgeBase(contexts=[playbook_context()])

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["target_type"], "incident")
        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["recommendations"][0]["source"], "knowledge_base/security_playbook.md")
        self.assertEqual(result["recommendations"][0]["card_type"], "playbook_action_card")
        self.assertEqual(len(result["recommendations"][0]["recommended_checks"]), 4)
        self.assertEqual(result["recommendations"][0]["chunk_index"], 2)
        self.assertEqual(result["decision_boundary"], PLAYBOOK_RECOMMENDATION_DECISION_BOUNDARY)
        self.assertIn("must not apply remediation", result["decision_boundary"])
        self.assertEqual(kb.mutation_calls, [])
        self.assertEqual(kb.calls[0]["source_type"], KNOWLEDGE_BASE_SOURCE_TYPE)
        self.assertIn("Multiple failed SSH logins", kb.calls[0]["query"])

    def test_case_recommendations_include_case_context_without_mutating_state(self):
        kb = FakeKnowledgeBase(contexts=[playbook_context("knowledge_base/bruteforce.md")])

        result = build_case_playbook_recommendations(
            FakeDb(
                case=case(),
                incidents=[incident()],
                actions=[action()],
                closure=closure(),
                latest_analysis=analysis(),
            ),
            99,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["target_type"], "case")
        self.assertEqual(result["target_id"], 99)
        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["recommendations"][0]["source"], "knowledge_base/bruteforce.md")
        self.assertEqual(kb.mutation_calls, [])
        self.assertEqual(kb.calls[0]["source_type"], KNOWLEDGE_BASE_SOURCE_TYPE)
        self.assertIn("SSH brute force investigation", kb.calls[0]["query"])
        self.assertIn("Review authentication source", kb.calls[0]["query"])
        self.assertIn("Credential access", kb.calls[0]["query"])

    def test_markdown_playbook_is_normalized_into_action_card(self):
        kb = FakeKnowledgeBase(contexts=[dns_playbook_context()])

        result = build_incident_playbook_recommendations(
            FakeDb(incident=network_incident()),
            43,
            knowledge_base_factory=lambda: kb,
        )

        recommendation = result["recommendations"][0]

        self.assertEqual(recommendation["title"], "DNS and Suricata Investigation Playbook")
        self.assertEqual(recommendation["category"], "network")
        self.assertEqual(
            recommendation["recommended_checks"][0],
            "Check query volume and first-seen time.",
        )
        self.assertIn("DNS Evidence", recommendation["gui_targets"])
        self.assertIn("Network Evidence", recommendation["gui_targets"])
        self.assertIn("deterministic", result["decision_boundary"])

    def test_different_incident_profiles_do_not_return_identical_playbook_cards(self):
        contexts = [
            dns_playbook_context(),
            playbook_context("knowledge_base/wazuh_authentication_playbook.md"),
            closure_playbook_context(),
        ]

        auth_kb = FakeKnowledgeBase(contexts=contexts)
        network_kb = FakeKnowledgeBase(contexts=contexts)

        auth_result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: auth_kb,
        )
        network_result = build_incident_playbook_recommendations(
            FakeDb(incident=network_incident()),
            43,
            knowledge_base_factory=lambda: network_kb,
        )

        auth_titles = [item["title"] for item in auth_result["recommendations"]]
        network_titles = [item["title"] for item in network_result["recommendations"]]

        self.assertNotEqual(auth_titles, network_titles)
        self.assertEqual(auth_result["recommendations"][0]["category"], "authentication")
        self.assertEqual(network_result["recommendations"][0]["category"], "network")
        self.assertEqual(auth_kb.calls[0]["limit"], 25)
        self.assertEqual(network_kb.calls[0]["limit"], 25)

    def test_generic_remediation_playbook_is_not_returned_for_incident_recommendations(self):
        kb = FakeKnowledgeBase(
            contexts=[
                remediation_playbook_context(),
                playbook_context("knowledge_base/wazuh_authentication_playbook.md"),
            ]
        )

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        titles = [item["title"] for item in result["recommendations"]]
        categories = [item["category"] for item in result["recommendations"]]

        self.assertIn("authentication", categories)
        self.assertNotIn("remediation", categories)
        self.assertNotIn("Governed Remediation Playbook", titles)
        self.assertEqual(result["target_profile"]["allowed_categories"], ["authentication", "network"])

    def test_incident_returns_empty_when_only_generic_operational_playbooks_match(self):
        kb = FakeKnowledgeBase(contexts=[remediation_playbook_context()])

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(result["recommendations"], [])
        self.assertIn("strict relevance filtering", result["message"])

    def test_disabled_semantic_memory_returns_safe_empty_response(self):
        kb = FakeKnowledgeBase(enabled=False)

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "DISABLED")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(result["recommendations"], [])
        self.assertEqual(kb.calls, [])

    def test_qdrant_error_returns_warning_without_state_change(self):
        kb = FakeKnowledgeBase(error=RuntimeError("qdrant down"))

        result = build_case_playbook_recommendations(
            FakeDb(case=case()),
            99,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "WARN")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(result["error_type"], "RuntimeError")
        self.assertIn("no operational state", result["message"])
        self.assertEqual(kb.mutation_calls, [])

    def test_rbac_allows_operators_and_denies_viewers(self):
        self.assertTrue(
            is_request_authorized(
                "GET",
                "/incidents/42/recommended-playbooks",
                {"role": "ANALYST"},
            )
        )
        self.assertTrue(
            is_request_authorized(
                "GET",
                "/cases/99/recommended-playbooks",
                {"role": "ADMIN"},
            )
        )
        self.assertFalse(
            is_request_authorized(
                "GET",
                "/incidents/42/recommended-playbooks",
                {"role": "VIEWER"},
            )
        )
        self.assertFalse(
            is_request_authorized(
                "GET",
                "/cases/99/recommended-playbooks",
                {"role": "VIEWER"},
            )
        )


if __name__ == "__main__":
    unittest.main()
