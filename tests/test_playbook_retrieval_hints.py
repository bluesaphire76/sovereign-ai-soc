import unittest
from types import SimpleNamespace

from playbook_retrieval_hints import (
    build_playbook_retrieval_query,
    infer_incident_playbook_hints,
    playbook_retrieval_filter_stages,
)


class PlaybookRetrievalHintsTests(unittest.TestCase):
    def test_ssh_bruteforce_hints(self):
        incident = SimpleNamespace(
            rule="Wazuh sshd failed password repeated failed login",
            mitre="T1110",
            ai_analysis="Multiple invalid user SSH attempts from the same source.",
        )

        hints = infer_incident_playbook_hints(incident)

        self.assertEqual(hints.source, "wazuh")
        self.assertEqual(hints.domain, "authentication")
        self.assertIn("ssh_bruteforce", hints.incident_types)
        self.assertIn("false_positive_review", hints.supporting_incident_types)
        self.assertIn("T1110", hints.mitre_techniques)

    def test_ssh_success_after_failures_hints(self):
        incident = SimpleNamespace(
            rule="SSH failed password then Accepted publickey",
            mitre="T1110,T1078",
            ai_analysis="Failed logins were followed by a successful login from the same source.",
        )

        hints = infer_incident_playbook_hints(incident)

        self.assertEqual(hints.source, "wazuh")
        self.assertIn("ssh_success_after_failures", hints.incident_types)
        self.assertIn("sudo_privilege_escalation", hints.supporting_incident_types)
        self.assertIn("T1078", hints.mitre_techniques)

    def test_sudo_privilege_escalation_hints(self):
        incident = SimpleNamespace(
            rule="sudo COMMAND=/bin/bash privileged command",
            mitre="T1548",
            ai_analysis="Unexpected root command outside approved maintenance.",
        )

        hints = infer_incident_playbook_hints(incident)

        self.assertEqual(hints.source, "wazuh")
        self.assertEqual(hints.domain, "authentication")
        self.assertIn("sudo_privilege_escalation", hints.incident_types)
        self.assertIn("privilege-escalation", hints.tags)

    def test_suricata_port_scan_hints(self):
        incident = SimpleNamespace(
            rule="Suricata ET SCAN port scan network reconnaissance",
            mitre="T1046",
            ai_analysis="One source scanned many ports.",
        )

        hints = infer_incident_playbook_hints(incident)

        self.assertEqual(hints.source, "suricata")
        self.assertEqual(hints.domain, "network_suricata")
        self.assertIn("port_scan", hints.incident_types)
        self.assertIn("T1046", hints.mitre_techniques)

    def test_dns_beaconing_query_and_filter_stages(self):
        incident = SimpleNamespace(
            rule="DNS C2 beaconing regular interval domain queries",
            mitre="T1071.004",
            ai_analysis="Repeated DNS queries to the same suspicious domain at regular intervals.",
        )

        hints = infer_incident_playbook_hints(incident)
        query = build_playbook_retrieval_query(
            target_type="incident",
            facts="DNS C2 beaconing regular interval domain queries",
            hints=hints,
        )
        stages = playbook_retrieval_filter_stages(hints)

        self.assertEqual(hints.source, "dns")
        self.assertEqual(hints.domain, "dns")
        self.assertIn("dns_c2_beaconing", hints.incident_types)
        self.assertIn("T1071.004", hints.mitre_techniques)
        self.assertIn("Target page: recommended_playbooks", query)
        self.assertEqual(stages[0].payload_filter["playbook_source"], "dns")
        self.assertEqual(stages[0].payload_filter["domain"], "dns")
        self.assertEqual(stages[-1].name, "broad_knowledge_base")
        self.assertIsNone(stages[-1].payload_filter)


if __name__ == "__main__":
    unittest.main()
