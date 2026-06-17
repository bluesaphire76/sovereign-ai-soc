from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from playbook_retrieval_hints import (
    build_playbook_retrieval_query,
    infer_incident_playbook_hints,
    playbook_retrieval_filter_stages,
)


SAMPLES = {
    "ssh_bruteforce": SimpleNamespace(
        rule="Wazuh sshd failed password repeated failed login",
        mitre="T1110",
        ai_analysis="Multiple invalid user SSH attempts from the same source.",
    ),
    "ssh_success_after_failures": SimpleNamespace(
        rule="SSH failed password followed by Accepted publickey",
        mitre="T1110,T1078",
        ai_analysis="Failed logins were followed by a successful login from the same source.",
    ),
    "sudo_privilege_escalation": SimpleNamespace(
        rule="sudo COMMAND=/bin/bash privileged command",
        mitre="T1548",
        ai_analysis="Unexpected root command outside approved maintenance.",
    ),
    "suricata_port_scan": SimpleNamespace(
        rule="Suricata ET SCAN port scan network reconnaissance",
        mitre="T1046",
        ai_analysis="One source scanned many ports.",
    ),
    "dns_beaconing": SimpleNamespace(
        rule="DNS C2 beaconing regular interval domain queries",
        mitre="T1071.004",
        ai_analysis="Repeated DNS queries to the same suspicious domain at regular intervals.",
    ),
}


def main() -> None:
    report = {}
    for name, incident in SAMPLES.items():
        facts = f"{incident.rule} {incident.mitre} {incident.ai_analysis}"
        hints = infer_incident_playbook_hints(incident)
        report[name] = {
            "hints": hints.to_public_dict(),
            "query": build_playbook_retrieval_query(
                target_type="incident",
                facts=facts,
                hints=hints,
            ),
            "filter_stages": [
                {
                    "name": stage.name,
                    "payload_filter": stage.payload_filter,
                }
                for stage in playbook_retrieval_filter_stages(hints)
            ],
        }

    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
