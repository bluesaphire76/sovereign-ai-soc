from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from recommended_playbooks_llm import (  # noqa: E402
    build_deterministic_playbooks_generation,
    build_recommended_playbooks_prompt,
    render_recommended_playbooks_markdown,
)


def playbook(
    title: str,
    *,
    category: str,
    domain: str,
    source: str,
    incident_types: list[str],
    matched_metadata: list[str],
    sections: list[tuple[str, str]],
    retrieval_stage: str = "strong_source_domain_type_mitre",
) -> dict:
    return {
        "title": title,
        "category": category,
        "domain": domain,
        "playbook_source": source,
        "incident_types": incident_types,
        "matched_metadata": matched_metadata,
        "retrieval_stage": retrieval_stage,
        "why_suggested": [f"{title} matched the current incident context."],
        "recommended_checks": [
            "Validate the current evidence against the retrieved playbook.",
            "Document the analyst decision and supporting telemetry.",
        ],
        "supporting_chunks": [
            {
                "section": section,
                "excerpt": excerpt,
                "relevance_score": 80 - index,
            }
            for index, (section, excerpt) in enumerate(sections)
        ],
    }


SCENARIOS = {
    "ssh_bruteforce": {
        "facts": {
            "source": "wazuh",
            "rule_name": "sshd failed password",
            "mitre": "T1110",
            "evidence_summary": "Repeated failed login attempts from one source IP.",
            "observed_entities": ["source_ip", "username", "hostname"],
        },
        "playbooks": [
            playbook(
                "SSH Brute Force Investigation Playbook",
                category="authentication",
                domain="authentication",
                source="wazuh",
                incident_types=["ssh_bruteforce", "repeated_failed_login"],
                matched_metadata=["source", "domain", "incident_type", "mitre_technique"],
                sections=[
                    ("Initial Triage", "Identify source, target accounts and failure count."),
                    ("False Positive Conditions", "Validate scanners, VPN and administrator activity."),
                ],
            ),
            playbook(
                "False Positive Classification Playbook",
                category="closure",
                domain="governance",
                source="soc",
                incident_types=["false_positive_review"],
                matched_metadata=["supporting_incident_type", "tag"],
                sections=[
                    ("False Positive Conditions", "Require evidence and owner confirmation."),
                ],
            ),
        ],
    },
    "ssh_success_after_failures": {
        "facts": {
            "source": "wazuh",
            "rule_name": "Failed password followed by Accepted publickey",
            "mitre": "T1110, T1078",
            "evidence_summary": "Successful login followed repeated SSH failures.",
        },
        "playbooks": [
            playbook(
                "SSH Success After Multiple Failures Playbook",
                category="authentication",
                domain="authentication",
                source="wazuh",
                incident_types=["ssh_success_after_failures", "possible_account_compromise"],
                matched_metadata=["source", "domain", "incident_type", "mitre_technique"],
                sections=[
                    ("Investigation Steps", "Validate the successful login and post-login activity."),
                    ("Escalation Criteria", "Escalate unauthorized sudo or persistence activity."),
                ],
            ),
        ],
    },
    "sudo_privilege_escalation": {
        "facts": {
            "source": "wazuh",
            "rule_name": "sudo COMMAND=/bin/bash",
            "mitre": "T1548",
            "evidence_summary": "Unexpected privileged command outside maintenance.",
        },
        "playbooks": [
            playbook(
                "Sudo Privilege Escalation Playbook",
                category="authentication",
                domain="authentication",
                source="wazuh",
                incident_types=["sudo_privilege_escalation"],
                matched_metadata=["source", "domain", "incident_type", "mitre_technique"],
                sections=[
                    ("Evidence to Collect", "Collect sudo command, user, TTY and parent login."),
                    ("Correlation Checks", "Correlate package, service and file changes."),
                ],
            ),
        ],
    },
    "suricata_port_scan": {
        "facts": {
            "source": "suricata",
            "rule_name": "ET SCAN port scan",
            "mitre": "T1046",
            "evidence_summary": "One source probed multiple ports and hosts.",
        },
        "playbooks": [
            playbook(
                "Suricata Port Scan Playbook",
                category="network",
                domain="network_suricata",
                source="suricata",
                incident_types=["port_scan", "network_reconnaissance"],
                matched_metadata=["source", "domain", "incident_type", "mitre_technique"],
                sections=[
                    ("Initial Triage", "Determine whether the source is internal or external."),
                    ("False Positive Conditions", "Validate approved vulnerability scans."),
                ],
            ),
        ],
    },
    "dns_tunneling": {
        "facts": {
            "source": "dns",
            "rule_name": "Long high-entropy DNS subdomains",
            "mitre": "T1071.004, T1048",
            "evidence_summary": "High-volume TXT queries may indicate DNS tunneling.",
        },
        "playbooks": [
            playbook(
                "DNS Tunneling Investigation Playbook",
                category="network",
                domain="dns",
                source="dns",
                incident_types=["dns_tunneling", "dns_exfiltration"],
                matched_metadata=["source", "domain", "incident_type", "mitre_technique"],
                sections=[
                    ("Detection Signals", "Review entropy, subdomain length and query types."),
                    ("Escalation Criteria", "Escalate when host evidence supports exfiltration."),
                ],
            ),
        ],
    },
    "weak_context": {
        "facts": {
            "rule_name": "Unclassified security alert",
            "evidence_summary": "Limited alert metadata is available.",
        },
        "playbooks": [
            playbook(
                "General SOC Investigation Playbook",
                category="general",
                domain="general",
                source="knowledge_base",
                incident_types=[],
                matched_metadata=[],
                sections=[("Purpose", "Broad investigation guidance only.")],
                retrieval_stage="broad_knowledge_base",
            ),
        ],
    },
}


def main() -> None:
    report = {}
    for name, scenario in SCENARIOS.items():
        prompt = build_recommended_playbooks_prompt(
            target_type="incident",
            current_facts=scenario["facts"],
            recommendations=scenario["playbooks"],
            similar_incidents=[],
        )
        fallback = build_deterministic_playbooks_generation(
            recommendations=scenario["playbooks"],
            reason="validation_preview",
        )
        report[name] = {
            "current_facts": scenario["facts"],
            "selected_playbook_titles": [
                item["title"] for item in scenario["playbooks"]
            ],
            "similar_incident_context_included": False,
            "prompt_preview": prompt[:2200],
            "fallback_preview": render_recommended_playbooks_markdown(fallback)[:2200],
        }

    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
