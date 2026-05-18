#!/usr/bin/env python3
"""
v0.5 demo scenario pack for Sovereign AI SOC.

This script does NOT execute attacks.
It emits controlled defensive JSONL events that can be collected by Wazuh
from /var/log/ai-soc-synthetic/alerts.jsonl.

Goal:
- repeatable demo data
- local-first / lab-only execution
- clear demo/synthetic marking
- no changes to api.py, frontend, RBAC, or runtime endpoints
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT = "/var/log/ai-soc-synthetic/alerts.jsonl"
DEFAULT_SEED = 505

HOSTS = [
    "demo-soc-linux-01",
    "demo-soc-linux-02",
    "demo-soc-db-01",
    "demo-soc-app-01",
]

USERS = [
    "analyst",
    "admin",
    "svc-backup",
    "svc-deploy",
    "demo-user",
]

SOURCE_IPS = [
    "10.50.10.25",
    "10.50.10.44",
    "192.168.56.20",
    "172.16.10.15",
]


SCENARIOS: dict[str, dict[str, Any]] = {
    "brute_force_ssh": {
        "title": "Brute force SSH",
        "expected_outcome": "incident",
        "events": [
            {
                "event_type": "ssh_failed_password",
                "severity": "medium",
                "category": "authentication",
                "description": "Repeated failed SSH login attempt",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Brute Force",
                "mitre_id": "T1110",
                "wazuh_rule_hint": "sshd authentication failure",
            },
            {
                "event_type": "ssh_success_after_failures",
                "severity": "high",
                "category": "authentication",
                "description": "Successful SSH login after repeated failures",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Remote Services: SSH",
                "mitre_id": "T1021.004",
                "wazuh_rule_hint": "sshd successful login",
            },
        ],
    },
    "sudo_escalation": {
        "title": "Sudo escalation",
        "expected_outcome": "incident",
        "events": [
            {
                "event_type": "sudo_authentication_failure",
                "severity": "medium",
                "category": "privilege",
                "description": "Sudo authentication failure for privileged command",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Abuse Elevation Control Mechanism",
                "mitre_id": "T1548",
                "wazuh_rule_hint": "sudo authentication failure",
            },
            {
                "event_type": "suspicious_root_command",
                "severity": "high",
                "category": "privilege",
                "description": "Suspicious command executed with root privileges",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Abuse Elevation Control Mechanism",
                "mitre_id": "T1548",
                "wazuh_rule_hint": "successful sudo to root",
            },
        ],
    },
    "suspicious_package_activity": {
        "title": "Suspicious package activity",
        "expected_outcome": "incident_or_triage",
        "events": [
            {
                "event_type": "new_package_installed",
                "severity": "medium",
                "category": "system_change",
                "description": "New Debian package installed outside normal maintenance window",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Software Deployment Tools",
                "mitre_id": "T1072",
                "wazuh_rule_hint": "dpkg package installed",
            },
            {
                "event_type": "package_configuration_changed",
                "severity": "medium",
                "category": "system_change",
                "description": "Package configuration changed after privileged session",
                "mitre_tactic": "Persistence",
                "mitre_technique": "Event Triggered Execution",
                "mitre_id": "T1546",
                "wazuh_rule_hint": "dpkg package configured",
            },
        ],
    },
    "noisy_operational_baseline": {
        "title": "Noisy operational baseline",
        "expected_outcome": "suppressed_or_observed",
        "events": [
            {
                "event_type": "routine_service_status_check",
                "severity": "low",
                "category": "operations",
                "description": "Routine service status check executed by trusted operator",
                "mitre_tactic": "None",
                "mitre_technique": "Operational activity",
                "mitre_id": "NONE",
                "wazuh_rule_hint": "sudo systemctl status",
            },
            {
                "event_type": "routine_pam_session_closed",
                "severity": "low",
                "category": "operations",
                "description": "Routine PAM session closed after administrative status check",
                "mitre_tactic": "None",
                "mitre_technique": "Operational activity",
                "mitre_id": "NONE",
                "wazuh_rule_hint": "pam session closed",
            },
        ],
    },
    "false_positive": {
        "title": "False positive scenario",
        "expected_outcome": "false_positive",
        "events": [
            {
                "event_type": "authorized_admin_change",
                "severity": "low",
                "category": "operations",
                "description": "Authorized administrator changed a lab configuration during approved maintenance",
                "mitre_tactic": "None",
                "mitre_technique": "Approved change",
                "mitre_id": "NONE",
                "wazuh_rule_hint": "approved maintenance activity",
            },
            {
                "event_type": "change_ticket_context",
                "severity": "low",
                "category": "governance",
                "description": "Change ticket context confirms the activity is expected",
                "mitre_tactic": "None",
                "mitre_technique": "Human validated false positive",
                "mitre_id": "NONE",
                "wazuh_rule_hint": "change ticket validation",
            },
        ],
    },
    "real_incident": {
        "title": "Real incident scenario",
        "expected_outcome": "critical_incident",
        "events": [
            {
                "event_type": "ssh_bruteforce_from_external_ip",
                "severity": "high",
                "category": "authentication",
                "description": "Multiple failed SSH attempts from unusual source",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Brute Force",
                "mitre_id": "T1110",
                "wazuh_rule_hint": "external ssh brute force",
            },
            {
                "event_type": "successful_login_after_bruteforce",
                "severity": "high",
                "category": "initial_access",
                "description": "Successful login observed after brute force sequence",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Remote Services: SSH",
                "mitre_id": "T1021.004",
                "wazuh_rule_hint": "successful ssh login",
            },
            {
                "event_type": "root_privilege_activity_after_login",
                "severity": "critical",
                "category": "privilege",
                "description": "Root-level activity observed shortly after suspicious login",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Abuse Elevation Control Mechanism",
                "mitre_id": "T1548",
                "wazuh_rule_hint": "successful sudo to root",
            },
        ],
    },
    "case_ready": {
        "title": "Case-ready scenario",
        "expected_outcome": "case_ready",
        "events": [
            {
                "event_type": "multi_stage_authentication_anomaly",
                "severity": "high",
                "category": "correlation",
                "description": "Authentication anomaly linked to later privileged activity",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Brute Force",
                "mitre_id": "T1110",
                "wazuh_rule_hint": "correlated authentication anomaly",
            },
            {
                "event_type": "privileged_activity_on_same_host",
                "severity": "critical",
                "category": "correlation",
                "description": "Privileged activity observed on same host after authentication anomaly",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Abuse Elevation Control Mechanism",
                "mitre_id": "T1548",
                "wazuh_rule_hint": "same host sudo/root activity",
            },
            {
                "event_type": "analyst_case_context",
                "severity": "medium",
                "category": "case_context",
                "description": "Scenario includes enough evidence to open and review an investigation case",
                "mitre_tactic": "None",
                "mitre_technique": "Case workflow validation",
                "mitre_id": "NONE",
                "wazuh_rule_hint": "case-ready demo evidence",
            },
        ],
    },
}


def _choose(items: list[str]) -> str:
    return random.choice(items)


def build_event(
    scenario_name: str,
    template: dict[str, Any],
    sequence: int,
    base_time: datetime,
    host: str | None,
    created_by: str,
) -> dict[str, Any]:
    scenario = SCENARIOS[scenario_name]
    event_time = base_time + timedelta(seconds=sequence * 20)

    selected_host = host or _choose(HOSTS)
    selected_user = _choose(USERS)
    selected_ip = _choose(SOURCE_IPS)

    return {
        "timestamp": event_time.isoformat(),
        "source": "sovereign-ai-soc-demo-pack",
        "lab": True,
        "demo": True,
        "synthetic": True,
        "version": "v0.5",
        "scenario": scenario_name,
        "scenario_title": scenario["title"],
        "scenario_sequence": sequence,
        "expected_outcome": scenario["expected_outcome"],
        "created_by": created_by,
        "host": selected_host,
        "user": selected_user,
        "src_ip": selected_ip,
        "event": template,
        "message": (
            f"[DEMO][SYNTHETIC][{scenario_name}] {template['description']} "
            f"user={selected_user} src_ip={selected_ip} host={selected_host} "
            f"mitre={template['mitre_id']} expected_outcome={scenario['expected_outcome']}"
        ),
    }


def build_events(
    scenario_name: str,
    count: int,
    host: str | None,
    created_by: str,
) -> list[dict[str, Any]]:
    if scenario_name not in SCENARIOS:
        available = ", ".join(sorted(SCENARIOS))
        raise ValueError(f"Unknown scenario '{scenario_name}'. Available scenarios: {available}")

    templates = SCENARIOS[scenario_name]["events"]
    base_time = datetime.now(timezone.utc)
    events: list[dict[str, Any]] = []

    for index in range(count):
        template = templates[index % len(templates)]
        events.append(
            build_event(
                scenario_name=scenario_name,
                template=template,
                sequence=index + 1,
                base_time=base_time,
                host=host,
                created_by=created_by,
            )
        )

    return events


def emit_events(
    output: Path,
    scenario_names: list[str],
    count: int,
    host: str | None,
    created_by: str,
    dry_run: bool,
) -> int:
    all_events: list[dict[str, Any]] = []

    for scenario_name in scenario_names:
        all_events.extend(
            build_events(
                scenario_name=scenario_name,
                count=count,
                host=host,
                created_by=created_by,
            )
        )

    if dry_run:
        for event in all_events:
            print(json.dumps(event, ensure_ascii=False))
        return len(all_events)

    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("a", encoding="utf-8") as handle:
        for event in all_events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    print(f"Emitted {len(all_events)} demo synthetic events into {output}")
    return len(all_events)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Emit v0.5 demo scenario pack events for Wazuh ingestion testing."
    )
    parser.add_argument(
        "--scenario",
        choices=sorted(SCENARIOS),
        help="Scenario to emit. Omit when using --all.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Emit all v0.5 demo scenarios.",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Number of events per scenario.",
    )
    parser.add_argument(
        "--host",
        help="Optional fixed host name for all emitted events.",
    )
    parser.add_argument(
        "--created-by",
        default="demo_operator",
        help="Logical actor recorded in the synthetic event payload.",
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help="Output JSONL log file collected by Wazuh.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed for repeatable demo events.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available scenarios and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print events to stdout without writing to disk.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    random.seed(args.seed)

    if args.list:
        for name, scenario in sorted(SCENARIOS.items()):
            print(f"{name}: {scenario['title']} [{scenario['expected_outcome']}]")
        return 0

    if args.count < 1:
        print("count must be greater than zero", file=sys.stderr)
        return 2

    if args.all:
        scenario_names = sorted(SCENARIOS)
    elif args.scenario:
        scenario_names = [args.scenario]
    else:
        print("Either --scenario or --all is required.", file=sys.stderr)
        return 2

    try:
        emit_events(
            output=Path(args.output),
            scenario_names=scenario_names,
            count=args.count,
            host=args.host,
            created_by=args.created_by,
            dry_run=args.dry_run,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
