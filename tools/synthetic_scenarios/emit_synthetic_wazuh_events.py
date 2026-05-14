#!/usr/bin/env python3
"""
Defensive synthetic security event generator for Sovereign AI SOC.

This script does NOT perform attacks.
It writes controlled JSON log events that can be collected by Wazuh
to test ingestion, correlation, case grouping, AI analysis, dashboarding,
and report export end-to-end.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCENARIOS: dict[str, list[dict[str, Any]]] = {
    "ssh_bruteforce": [
        {
            "event_type": "authentication_failure",
            "severity": "medium",
            "category": "authentication",
            "description": "Synthetic failed SSH login attempt",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Brute Force",
            "mitre_id": "T1110",
        },
        {
            "event_type": "authentication_success_after_failures",
            "severity": "high",
            "category": "authentication",
            "description": "Synthetic successful SSH login after repeated failures",
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Brute Force",
            "mitre_id": "T1110",
        },
    ],
    "privilege_escalation": [
        {
            "event_type": "sudo_failure",
            "severity": "medium",
            "category": "privilege",
            "description": "Synthetic sudo authentication failure",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "Abuse Elevation Control Mechanism",
            "mitre_id": "T1548",
        },
        {
            "event_type": "suspicious_root_command",
            "severity": "high",
            "category": "privilege",
            "description": "Synthetic suspicious command executed with elevated privileges",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique": "Abuse Elevation Control Mechanism",
            "mitre_id": "T1548",
        },
    ],
    "malware_indicator": [
        {
            "event_type": "suspicious_file_created",
            "severity": "high",
            "category": "malware",
            "description": "Synthetic suspicious executable-like file creation",
            "mitre_tactic": "Execution",
            "mitre_technique": "User Execution",
            "mitre_id": "T1204",
        },
        {
            "event_type": "suspicious_persistence_hint",
            "severity": "critical",
            "category": "malware",
            "description": "Synthetic persistence-like indicator detected",
            "mitre_tactic": "Persistence",
            "mitre_technique": "Boot or Logon Autostart Execution",
            "mitre_id": "T1547",
        },
    ],
}


HOSTS = ["soc-lab-linux-01", "soc-lab-linux-02", "soc-lab-db-01"]
USERS = ["alice", "bob", "service-account", "admin"]
SOURCE_IPS = ["10.10.10.25", "10.10.10.44", "192.168.56.20", "172.16.10.15"]


def build_event(scenario: str, sequence: int) -> dict[str, Any]:
    templates = SCENARIOS[scenario]
    template = templates[sequence % len(templates)]

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "sovereign-ai-soc-synthetic",
        "lab": True,
        "scenario": scenario,
        "scenario_sequence": sequence,
        "host": random.choice(HOSTS),
        "user": random.choice(USERS),
        "src_ip": random.choice(SOURCE_IPS),
        "event": template,
        "message": (
            f"[SYNTHETIC][{scenario}] {template['description']} "
            f"user={random.choice(USERS)} src_ip={random.choice(SOURCE_IPS)}"
        ),
    }


def emit_events(output: Path, scenario: str, count: int, dry_run: bool) -> None:
    if scenario not in SCENARIOS:
        available = ", ".join(sorted(SCENARIOS))
        raise ValueError(f"Unknown scenario '{scenario}'. Available scenarios: {available}")

    events = [build_event(scenario, i + 1) for i in range(count)]

    if dry_run:
        for event in events:
            print(json.dumps(event, ensure_ascii=False))
        return

    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"Emitted {count} synthetic events for scenario '{scenario}' into {output}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit defensive synthetic SOC events for Wazuh ingestion testing."
    )
    parser.add_argument(
        "--scenario",
        required=True,
        choices=sorted(SCENARIOS),
        help="Synthetic scenario to emit.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of synthetic events to emit.",
    )
    parser.add_argument(
        "--output",
        default="/var/log/ai-soc-synthetic/alerts.jsonl",
        help="Output JSONL log file collected by Wazuh.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print events to stdout without writing to disk.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.count < 1:
        print("count must be greater than zero", file=sys.stderr)
        return 2

    emit_events(
        output=Path(args.output),
        scenario=args.scenario,
        count=args.count,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
