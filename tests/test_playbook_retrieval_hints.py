import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

from playbook_retrieval_catalog import (
    EXPANDED_PLAYBOOK_PRIMARY_INCIDENT_TYPES,
    EXPANDED_PLAYBOOK_SIGNAL_RULES,
)
from playbook_retrieval_hints import (
    build_playbook_retrieval_query,
    infer_incident_playbook_hints,
    infer_playbook_retrieval_hints,
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

    def test_expanded_catalog_covers_50_playbook_primary_incident_types(self):
        indexed_primary_types = set()
        for path in Path("knowledge_base/playbooks").rglob("*.md"):
            if "_templates" in path.parts or path.name == "README.md":
                continue
            text = path.read_text(encoding="utf-8")
            metadata = yaml.safe_load(text.split("---", 2)[1])
            incident_types = metadata.get("incident_types") or []
            if incident_types:
                indexed_primary_types.add(incident_types[0])

        self.assertEqual(len(EXPANDED_PLAYBOOK_SIGNAL_RULES), 50)
        self.assertEqual(len(EXPANDED_PLAYBOOK_PRIMARY_INCIDENT_TYPES), 50)
        self.assertTrue(
            EXPANDED_PLAYBOOK_PRIMARY_INCIDENT_TYPES.issubset(indexed_primary_types)
        )

    def test_expanded_domain_scenarios_build_strong_metadata_filters(self):
        scenarios = [
            (
                "linux",
                "Wazuh unauthorized user creation: useradd created UID 0 local account T1136.001",
                "wazuh",
                "linux_host",
                "unauthorized_user_creation",
                "T1136.001",
            ),
            (
                "windows",
                "Windows Event ID 7045 service installed from ADMIN$ after remote logon T1543.003",
                "wazuh",
                "windows_host",
                "windows_service_creation",
                "T1543.003",
            ),
            (
                "windows_sysmon_suspicious_process",
                "Sysmon - Suspicious Process - explorer.exe Event ID 1 process anomaly T1055",
                "wazuh",
                "windows_host",
                "windows_sysmon_suspicious_process",
                "T1055",
            ),
            (
                "windows_netsh_firewall_rule_change",
                "Netsh used to add firewall rule netsh advfirewall firewall add rule T1562.004",
                "wazuh",
                "windows_host",
                "windows_netsh_firewall_rule_change",
                "T1562.004",
            ),
            (
                "windows_cis_benchmark_failure",
                "CIS Microsoft Windows 11 Enterprise Benchmark Wazuh SCA check result failed",
                "wazuh",
                "windows_host",
                "windows_cis_benchmark_failure",
                None,
            ),
            (
                "wazuh_agent_queue_saturation",
                "Wazuh Agent event queue is flooded agent buffer full",
                "wazuh",
                "governance",
                "wazuh_agent_queue_saturation",
                None,
            ),
            (
                "suricata",
                "Suricata ET EXPLOIT exploit attempt against public-facing application CVE T1190",
                "suricata",
                "network_suricata",
                "suricata_exploit_attempt",
                "T1190",
            ),
            (
                "dns",
                "DNS domain generation algorithm DGA high NXDOMAIN ratio T1568.002",
                "dns",
                "dns",
                "domain_generation_algorithm",
                "T1568.002",
            ),
            (
                "malware",
                "Reverse shell detected: Python process opened interactive outbound shell T1059",
                "wazuh",
                "malware",
                "reverse_shell_detection",
                "T1059",
            ),
            (
                "exfiltration",
                "Large outbound data transfer to rare external destination possible data exfiltration T1041",
                "suricata",
                "data_exfiltration",
                "large_data_transfer",
                "T1041",
            ),
            (
                "governance",
                "Containment approval required before host isolation and account disablement",
                "internal_policy",
                "governance",
                "containment_approval",
                None,
            ),
        ]

        for name, text, source, domain, incident_type, technique in scenarios:
            with self.subTest(name=name):
                hints = infer_playbook_retrieval_hints(text)
                first_filter = playbook_retrieval_filter_stages(hints)[0].payload_filter

                self.assertEqual(hints.source, source)
                self.assertEqual(hints.domain, domain)
                self.assertEqual(hints.incident_types[0], incident_type)
                self.assertEqual(first_filter["playbook_source"], source)
                self.assertEqual(first_filter["domain"], domain)
                self.assertEqual(first_filter["incident_types"], incident_type)
                if technique:
                    self.assertEqual(first_filter["mitre_techniques"], technique)
                else:
                    self.assertNotIn("mitre_techniques", first_filter)

    def test_specific_linux_temporary_path_signal_precedes_generic_malware_signal(self):
        hints = infer_playbook_retrieval_hints(
            "Wazuh suspicious binary execution from /tmp followed by outbound network activity"
        )

        self.assertEqual(hints.domain, "linux_host")
        self.assertEqual(
            hints.incident_types[0],
            "suspicious_binary_execution_tmp",
        )
        self.assertIn("malware_suspicious_execution", hints.incident_types)

    def test_windows_platform_telemetry_overrides_polluted_linux_ai_text(self):
        incident = SimpleNamespace(
            agent="darkstar-windows",
            rule="Windows audit failure event",
            mitre="{}",
            correlation_summary=(
                '{"matched_patterns":{"failed_login":{"keywords":["failed login"]},'
                '"sudo_activity":{"keywords":["sudo"]}}}'
            ),
            ai_analysis=(
                "Review multiple login failures, the sudoers file and unusual sudo "
                "usage. This prior AI text may contain Linux-oriented guidance."
            ),
            raw_alert=(
                '{"data":{"win":{"system":{"eventID":"5061",'
                '"providerName":"Microsoft-Windows-Security-Auditing",'
                '"channel":"Security"}}}}'
            ),
        )

        hints = infer_incident_playbook_hints(incident)
        first_filter = playbook_retrieval_filter_stages(hints)[0].payload_filter

        self.assertEqual(hints.platform, "windows")
        self.assertEqual(hints.domain, "windows_host")
        self.assertEqual(hints.source, "wazuh")
        self.assertNotIn("sudo_privilege_escalation", hints.incident_types)
        self.assertIn("windows_platform", hints.matched_signals)
        self.assertEqual(first_filter["domain"], "windows_host")


if __name__ == "__main__":
    unittest.main()
