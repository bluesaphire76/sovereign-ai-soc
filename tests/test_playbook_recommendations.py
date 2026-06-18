import json
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

    def retrieve_contexts(
        self,
        query,
        *,
        limit=None,
        source_type=None,
        payload_filter=None,
        payload_fields=None,
    ):
        self.calls.append(
            {
                "query": query,
                "limit": limit,
                "source_type": source_type,
                "payload_filter": payload_filter,
                "payload_fields": payload_fields,
            }
        )
        if self.error:
            raise self.error
        contexts = [
            context
            for context in self.contexts
            if self._matches_payload_filter(context, payload_filter)
        ]
        return contexts[: limit or 25]

    @staticmethod
    def _matches_payload_filter(context, payload_filter):
        for key, expected in (payload_filter or {}).items():
            actual = context.get(key)
            if isinstance(actual, list):
                if expected not in actual:
                    return False
                continue
            if actual != expected:
                return False
        return True

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


def metadata_playbook_context():
    return {
        "source_type": KNOWLEDGE_BASE_SOURCE_TYPE,
        "source": "knowledge_base/playbooks/authentication/ssh_bruteforce_investigation_playbook.md",
        "file_path": "knowledge_base/playbooks/authentication/ssh_bruteforce_investigation_playbook.md",
        "score": 0.91,
        "chunk_index": 5,
        "content_hash": "metadata123",
        "doc_type": "playbook",
        "kb_type": "playbook",
        "content_kind": "playbook_section",
        "title": "SSH Brute Force Investigation Playbook",
        "domain": "authentication",
        "playbook_source": "wazuh",
        "incident_types": ["ssh_bruteforce", "credential_attack"],
        "severity_hint": ["medium", "high"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110"],
        "recommended_for_pages": ["recommended_playbooks", "incident_detail"],
        "tags": ["ssh", "brute-force", "authentication"],
        "section": "Investigation Steps",
        "section_order": 6,
        "text": (
            "# SSH Brute Force Investigation Playbook\n\n"
            "## Investigation Steps\n\n"
            "- review failed and successful authentication attempts;\n"
            "- identify targeted accounts and source host.\n"
        ),
    }


def metadata_context(
    *,
    title,
    source,
    domain,
    playbook_source,
    incident_types,
    tags,
    section="Investigation Steps",
    mitre_techniques=None,
    score=0.88,
    text=None,
    chunk_index=0,
    content_hash=None,
):
    return {
        "source_type": KNOWLEDGE_BASE_SOURCE_TYPE,
        "source": source,
        "file_path": source,
        "score": score,
        "chunk_index": chunk_index,
        "content_hash": content_hash or f"{source}:{chunk_index}",
        "doc_type": "playbook",
        "kb_type": "playbook",
        "content_kind": "playbook_section",
        "title": title,
        "domain": domain,
        "playbook_source": playbook_source,
        "incident_types": list(incident_types),
        "severity_hint": ["medium", "high"],
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": list(mitre_techniques or []),
        "recommended_for_pages": ["recommended_playbooks", "incident_detail"],
        "tags": list(tags),
        "section": section,
        "section_order": 4,
        "text": text
        or (
            f"# {title}\n\n"
            f"## {section}\n\n"
            "- collect incident-specific evidence;\n"
            "- validate deterministic telemetry before escalation.\n"
        ),
    }


def ssh_success_context():
    return metadata_context(
        title="SSH Success After Multiple Failures Playbook",
        source="knowledge_base/playbooks/authentication/ssh_success_after_failures_playbook.md",
        domain="authentication",
        playbook_source="wazuh",
        incident_types=[
            "ssh_success_after_failures",
            "possible_account_compromise",
            "credential_attack",
        ],
        tags=["ssh", "successful-login", "failed-login", "account-compromise"],
        mitre_techniques=["T1110", "T1021.004", "T1078"],
        section="Initial Triage",
    )


def sudo_context():
    return metadata_context(
        title="Sudo Privilege Escalation Playbook",
        source="knowledge_base/playbooks/authentication/sudo_privilege_escalation_playbook.md",
        domain="authentication",
        playbook_source="wazuh",
        incident_types=["sudo_privilege_escalation", "privileged_command_execution"],
        tags=["sudo", "privilege-escalation", "linux", "wazuh"],
        mitre_techniques=["T1548", "T1078"],
        section="Evidence to Collect",
    )


def false_positive_context():
    return metadata_context(
        title="False Positive Classification Playbook",
        source="knowledge_base/playbooks/governance/false_positive_classification_playbook.md",
        domain="governance",
        playbook_source="soc",
        incident_types=["false_positive_review", "benign_activity_validation"],
        tags=["false-positive", "governance", "analyst-decision"],
        mitre_techniques=[],
        section="False Positive Conditions",
    )


def suricata_port_scan_context():
    return metadata_context(
        title="Suricata Port Scan Playbook",
        source="knowledge_base/playbooks/network_suricata/suricata_port_scan_playbook.md",
        domain="network_suricata",
        playbook_source="suricata",
        incident_types=["port_scan", "network_reconnaissance", "suspicious_probe"],
        tags=["suricata", "port-scan", "reconnaissance", "network"],
        mitre_techniques=["T1046", "T1595"],
        section="Investigation Steps",
    )


def suricata_high_context():
    return metadata_context(
        title="Suricata High Severity Alert Playbook",
        source="knowledge_base/playbooks/network_suricata/suricata_high_severity_alert_playbook.md",
        domain="network_suricata",
        playbook_source="suricata",
        incident_types=["suricata_high_severity_alert", "network_intrusion_alert"],
        tags=["suricata", "network-alert", "ids", "high-severity"],
        mitre_techniques=[],
        section="Correlation Checks",
    )


def dns_c2_context():
    return metadata_context(
        title="DNS Command-and-Control Beaconing Playbook",
        source="knowledge_base/playbooks/dns/dns_c2_beaconing_playbook.md",
        domain="dns",
        playbook_source="dns",
        incident_types=["dns_c2_beaconing", "command_and_control", "suspicious_dns_activity"],
        tags=["dns", "c2", "beaconing", "command-and-control"],
        mitre_techniques=["T1071.004"],
        section="Initial Triage",
    )


def dns_tunneling_context():
    return metadata_context(
        title="DNS Tunneling Investigation Playbook",
        source="knowledge_base/playbooks/dns/dns_tunneling_investigation_playbook.md",
        domain="dns",
        playbook_source="dns",
        incident_types=["dns_tunneling", "dns_exfiltration", "suspicious_dns_volume"],
        tags=["dns", "tunneling", "exfiltration", "high-entropy"],
        mitre_techniques=["T1071.004", "T1048"],
        section="Evidence to Collect",
    )


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

    def test_incident_recommendations_prioritize_metadata_playbook_sections(self):
        kb = FakeKnowledgeBase(contexts=[metadata_playbook_context()])

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        recommendation = result["recommendations"][0]

        self.assertEqual(recommendation["title"], "SSH Brute Force Investigation Playbook")
        self.assertEqual(recommendation["domain"], "authentication")
        self.assertEqual(recommendation["playbook_source"], "wazuh")
        self.assertEqual(recommendation["section"], "Investigation Steps")
        self.assertEqual(recommendation["mitre_techniques"], ["T1110"])
        self.assertIn("ssh_bruteforce", recommendation["incident_types"])
        self.assertEqual(kb.calls[0]["payload_filter"]["doc_type"], "playbook")
        self.assertEqual(kb.calls[0]["payload_filter"]["content_kind"], "playbook_section")
        self.assertEqual(kb.calls[0]["payload_filter"]["recommended_for_pages"], "recommended_playbooks")
        self.assertEqual(kb.calls[0]["payload_filter"]["playbook_source"], "wazuh")
        self.assertEqual(kb.calls[0]["payload_filter"]["domain"], "authentication")
        self.assertEqual(kb.calls[0]["payload_filter"]["incident_types"], "ssh_bruteforce")
        self.assertEqual(kb.calls[0]["payload_filter"]["mitre_techniques"], "T1110")
        self.assertIn("recommended_for_pages", kb.calls[0]["payload_fields"])
        self.assertIn("source", recommendation["matched_metadata"])
        self.assertIn("sections_used", recommendation)

    def test_incident_runtime_generation_uses_llm_and_existing_similar_incident_service(self):
        kb = FakeKnowledgeBase(contexts=[metadata_playbook_context()])
        captured = {}

        def fake_llm(**kwargs):
            captured.update(kwargs)
            return {
                "text": json.dumps(
                    {
                        "selection_summary": "SSH failures match the retrieved authentication playbook.",
                        "playbooks": [
                            {
                                "title": "SSH Brute Force Investigation Playbook",
                                "why_applies": "Repeated failed SSH logins are present in the current incident.",
                                "supporting_incident_facts": [
                                    "The incident rule reports multiple failed SSH logins."
                                ],
                                "immediate_analyst_checks": [
                                    "Review the SSH authentication timeline for the affected host."
                                ],
                                "evidence_to_collect": [
                                    "Collect failed and successful SSH events for the source and target accounts."
                                ],
                                "false_positive_checks": [
                                    "Confirm whether the source is an approved scanner or administrator."
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
                            }
                        ],
                        "limitations": [],
                    }
                ),
                "profile": "standard",
                "model": "qwen-test",
                "fallback_used": False,
                "latency_ms": 321,
                "provider_key": "local_ollama",
                "provider_type": "LOCAL_OLLAMA",
                "used_external_provider": False,
            }

        def fake_similar_builder(*_args, **_kwargs):
            return {
                "status": "OK",
                "results": [
                    {
                        "incident_id": 7,
                        "score": 0.88,
                        "status": "FALSE_POSITIVE",
                        "rule": "Approved scanner SSH activity",
                        "excerpt": "Scanner ownership was confirmed by an analyst.",
                    }
                ],
            }

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
            generate_llm=True,
            llm_generator=fake_llm,
            similar_incidents_builder=fake_similar_builder,
        )

        self.assertEqual(result["generation"]["source"], "local_ai")
        self.assertEqual(result["generation"]["similar_incidents_included"], 1)
        self.assertIn("# Recommended Playbooks", result["generated_markdown"])
        self.assertEqual(
            result["recommendations"][0]["recommended_checks"][0],
            "Review the SSH authentication timeline for the affected host.",
        )
        self.assertEqual(
            result["recommendations"][0]["generation_source"],
            "local_ai",
        )
        self.assertIn("SIMILAR HISTORICAL INCIDENTS", captured["messages"][1]["content"])

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
        self.assertEqual(
            result["target_profile"]["allowed_categories"],
            ["authentication", "closure", "linux_host", "network"],
        )

    def test_incident_uses_broad_fallback_when_only_generic_operational_playbooks_match(self):
        kb = FakeKnowledgeBase(contexts=[remediation_playbook_context()])

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["recommendations"][0]["retrieval_stage"], "broad_knowledge_base")
        self.assertEqual(result["recommendations"][0]["title"], "Governed Remediation Playbook")

    def test_ssh_failure_retrieval_prefers_authentication_and_false_positive_playbooks(self):
        kb = FakeKnowledgeBase(
            contexts=[
                dns_c2_context(),
                false_positive_context(),
                ssh_success_context(),
                metadata_playbook_context(),
                sudo_context(),
            ]
        )

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        titles = [item["title"] for item in result["recommendations"]]

        self.assertEqual(titles[0], "SSH Brute Force Investigation Playbook")
        self.assertIn("SSH Success After Multiple Failures Playbook", titles)
        self.assertIn("False Positive Classification Playbook", titles)
        self.assertNotEqual(titles[0], "DNS Command-and-Control Beaconing Playbook")
        self.assertEqual(
            result["target_profile"]["retrieval_hints"]["incident_types"][0],
            "ssh_bruteforce",
        )

    def test_ssh_success_after_failures_retrieval_prefers_success_and_sudo_playbooks(self):
        success_incident = Incident(
            id=44,
            rule="Failed SSH attempts followed by Accepted password",
            agent="server-02",
            level=12,
            mitre="T1110,T1078",
            risk_score=88,
            ai_analysis=(
                "Multiple Failed password events were followed by Accepted publickey "
                "from the same source. Review sudo usage after login."
            ),
            attack_chain="Credential access and valid account use",
            correlation_type="auth_success_after_failures",
            escalation_reason="Successful login after brute-force pattern.",
            recommended_priority="HIGH",
        )
        kb = FakeKnowledgeBase(
            contexts=[
                metadata_playbook_context(),
                false_positive_context(),
                sudo_context(),
                ssh_success_context(),
            ]
        )

        result = build_incident_playbook_recommendations(
            FakeDb(incident=success_incident),
            44,
            knowledge_base_factory=lambda: kb,
        )

        titles = [item["title"] for item in result["recommendations"]]

        self.assertEqual(titles[0], "SSH Success After Multiple Failures Playbook")
        self.assertIn("Sudo Privilege Escalation Playbook", titles[:3])
        self.assertIn("SSH Brute Force Investigation Playbook", titles)
        self.assertEqual(
            result["target_profile"]["retrieval_hints"]["matched_signals"][0],
            "ssh_success_after_failures",
        )

    def test_sudo_privilege_escalation_retrieval_prefers_sudo_playbook(self):
        sudo_incident = Incident(
            id=45,
            rule="Wazuh sudo COMMAND=/bin/bash root command",
            agent="server-03",
            level=11,
            mitre="T1548",
            risk_score=82,
            ai_analysis="Suspicious sudo command executed as root outside maintenance.",
            attack_chain="Privilege escalation",
            correlation_type="sudo_privileged_command",
            escalation_reason="Unexpected privileged command.",
            recommended_priority="HIGH",
        )
        kb = FakeKnowledgeBase(
            contexts=[metadata_playbook_context(), false_positive_context(), sudo_context()]
        )

        result = build_incident_playbook_recommendations(
            FakeDb(incident=sudo_incident),
            45,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(
            result["recommendations"][0]["title"],
            "Sudo Privilege Escalation Playbook",
        )
        self.assertIn("mitre_technique", result["recommendations"][0]["matched_metadata"])

    def test_suricata_port_scan_retrieval_prefers_port_scan_playbook(self):
        scan_incident = Incident(
            id=46,
            rule="Suricata ET SCAN port scan network reconnaissance",
            agent="sensor-01",
            level=8,
            mitre="T1046",
            risk_score=70,
            ai_analysis="Suricata observed port scan behavior against multiple ports.",
            attack_chain="Reconnaissance",
            correlation_type="suricata_scan",
            escalation_reason="One source probed many destination ports.",
            recommended_priority="MEDIUM",
        )
        kb = FakeKnowledgeBase(
            contexts=[
                dns_c2_context(),
                false_positive_context(),
                suricata_high_context(),
                suricata_port_scan_context(),
            ]
        )

        result = build_incident_playbook_recommendations(
            FakeDb(incident=scan_incident),
            46,
            knowledge_base_factory=lambda: kb,
        )

        titles = [item["title"] for item in result["recommendations"]]

        self.assertEqual(titles[0], "Suricata Port Scan Playbook")
        self.assertIn("Suricata High Severity Alert Playbook", titles)
        self.assertIn("False Positive Classification Playbook", titles)
        self.assertEqual(
            result["target_profile"]["retrieval_hints"]["source"],
            "suricata",
        )

    def test_dns_beaconing_retrieval_prefers_dns_playbooks(self):
        dns_incident = Incident(
            id=47,
            rule="DNS C2 beaconing regular interval domain queries",
            agent="endpoint-04",
            level=10,
            mitre="T1071.004",
            risk_score=74,
            ai_analysis="Repeated DNS queries to the same suspicious domain at regular intervals.",
            attack_chain="Command and control",
            correlation_type="dns_beaconing",
            escalation_reason="Periodic DNS activity suggests possible C2 beaconing.",
            recommended_priority="HIGH",
        )
        kb = FakeKnowledgeBase(
            contexts=[
                suricata_high_context(),
                false_positive_context(),
                dns_tunneling_context(),
                dns_c2_context(),
            ]
        )

        result = build_incident_playbook_recommendations(
            FakeDb(incident=dns_incident),
            47,
            knowledge_base_factory=lambda: kb,
        )

        titles = [item["title"] for item in result["recommendations"]]

        self.assertEqual(titles[0], "DNS Command-and-Control Beaconing Playbook")
        self.assertIn("DNS Tunneling Investigation Playbook", titles[:3])
        self.assertIn("Suricata High Severity Alert Playbook", titles)
        self.assertEqual(result["target_profile"]["retrieval_hints"]["domain"], "dns")

    def test_retrieval_deduplicates_multiple_chunks_from_same_playbook(self):
        first_chunk = metadata_playbook_context()
        second_chunk = metadata_context(
            title="SSH Brute Force Investigation Playbook",
            source="knowledge_base/playbooks/authentication/ssh_bruteforce_investigation_playbook.md",
            domain="authentication",
            playbook_source="wazuh",
            incident_types=["ssh_bruteforce", "repeated_failed_login"],
            tags=["ssh", "brute-force", "authentication"],
            mitre_techniques=["T1110"],
            section="False Positive Conditions",
            chunk_index=8,
            content_hash="ssh-fp",
        )
        kb = FakeKnowledgeBase(
            contexts=[first_chunk, second_chunk, ssh_success_context(), false_positive_context()]
        )

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        titles = [item["title"] for item in result["recommendations"]]
        ssh_items = [
            item
            for item in result["recommendations"]
            if item["title"] == "SSH Brute Force Investigation Playbook"
        ]

        self.assertEqual(titles.count("SSH Brute Force Investigation Playbook"), 1)
        self.assertIn("Investigation Steps", ssh_items[0]["sections_used"])
        self.assertIn("False Positive Conditions", ssh_items[0]["sections_used"])

    def test_metadata_missing_playbook_can_still_be_returned_as_last_resort(self):
        kb = FakeKnowledgeBase(contexts=[playbook_context("knowledge_base/security_playbook.md")])

        result = build_incident_playbook_recommendations(
            FakeDb(incident=incident()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["result_count"], 1)
        self.assertEqual(result["recommendations"][0]["retrieval_stage"], "broad_knowledge_base")

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
