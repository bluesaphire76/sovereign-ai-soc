import tempfile
import unittest
from pathlib import Path

from scripts.reindex_qdrant_playbooks import build_report


class FakeKnowledgeBase:
    def collection_info(self):
        return {"status": "OK", "exists": True}


class QdrantPlaybookReindexTests(unittest.TestCase):
    def test_dry_run_report_parses_metadata_without_writing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base_path = Path(temp_dir) / "knowledge_base"
            playbook_path = base_path / "playbooks" / "dns" / "dns_tunneling_investigation_playbook.md"
            playbook_path.parent.mkdir(parents=True)
            playbook_path.write_text(
                """---
title: DNS Tunneling Investigation Playbook
type: playbook
domain: dns
source: suricata
incident_types:
  - dns_tunneling
severity_hint:
  - high
mitre_tactics:
  - Command and Control
mitre_techniques:
  - T1071.004
applicability:
  - High entropy DNS subdomains
not_applicable_when:
  - Approved scanner
recommended_for_pages:
  - recommended_playbooks
tags:
  - dns
  - tunneling
---
# DNS Tunneling Investigation Playbook

## Detection Signals

- high entropy subdomains;
- unusual DNS query volume.
""",
                encoding="utf-8",
            )

            report = build_report(path=base_path, kb=FakeKnowledgeBase())

        self.assertEqual(report["mode"], "dry-run")
        self.assertEqual(report["collection_status"], "OK")
        self.assertEqual(report["playbook_files_discovered"], 1)
        self.assertEqual(report["files_with_valid_front_matter"], 1)
        self.assertEqual(report["files_missing_required_metadata"], 0)
        self.assertEqual(report["sections_or_chunks_to_index"], 1)
        self.assertEqual(report["sample_payloads"][0]["title"], "DNS Tunneling Investigation Playbook")
        self.assertEqual(report["sample_payloads"][0]["domain"], "dns")
        self.assertEqual(report["sample_payloads"][0]["content_kind"], "playbook_section")


if __name__ == "__main__":
    unittest.main()
