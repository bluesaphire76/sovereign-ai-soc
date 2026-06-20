#!/usr/bin/env python3
"""Safely seed a small, idempotent synthetic demo dataset."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from demo_data_management import (
    DEMO_ACTOR,
    DEMO_CASE_GROUP_KEY,
    DEMO_MARKER,
    DEMO_VERSION,
    is_seed_demo_case,
    is_seed_demo_incident,
)

CASE_GROUP_KEY = DEMO_CASE_GROUP_KEY
DECISION_BOUNDARY = (
    "Demo data is synthetic and must not be used as real security evidence."
)


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    host: str
    source_ip: str
    status: str
    rule: str
    level: int
    mitre: tuple[str, ...]
    risk_score: int
    correlation_score: int
    correlation_type: str
    priority: str
    attack_chain: str
    summary: str

    @property
    def external_id(self) -> str:
        return f"{DEMO_MARKER}:{DEMO_VERSION}:incident:{self.scenario_id}"


SCENARIOS = (
    Scenario(
        "demo_brute_force_ssh",
        "[DEMO] Repeated SSH authentication failures",
        "demo-linux-server",
        "192.0.2.10",
        "NEW",
        "[DEMO] Repeated failed SSH logins from a documentation address",
        10,
        ("T1110", "T1021.004"),
        76,
        84,
        "DEMO_SSH_BRUTE_FORCE",
        "HIGH",
        "Initial Access -> Credential Access",
        "Synthetic SSH brute-force activity for detection and triage validation.",
    ),
    Scenario(
        "demo_sudo_escalation",
        "[DEMO] Suspicious sudo privilege activity",
        "demo-linux-server",
        "192.0.2.10",
        "INVESTIGATING",
        "[DEMO] Suspicious sudo command executed by demo.admin",
        12,
        ("T1068", "T1548"),
        88,
        91,
        "DEMO_SUDO_ESCALATION",
        "CRITICAL",
        "Execution -> Privilege Escalation",
        "Synthetic privilege activity linked to the demo authentication sequence.",
    ),
    Scenario(
        "demo_suspicious_package_activity",
        "[DEMO] Package activity outside maintenance window",
        "demo-workstation",
        "198.51.100.20",
        "TRIAGED",
        "[DEMO] Unexpected package installation by demo.service",
        8,
        ("T1072", "T1546"),
        58,
        68,
        "DEMO_SUSPICIOUS_PACKAGE_ACTIVITY",
        "MEDIUM",
        "Defense Evasion -> Persistence",
        "Synthetic package and process activity for evidence review.",
    ),
    Scenario(
        "demo_noisy_operational_baseline",
        "[DEMO] Approved operational activity",
        "demo-admin-host",
        "203.0.113.30",
        "FALSE_POSITIVE",
        "[DEMO] Authorized service restart during a documented maintenance window",
        3,
        (),
        18,
        32,
        "DEMO_OPERATIONAL_FALSE_POSITIVE",
        "LOW",
        "Approved Change -> Human Validation",
        "Synthetic false-positive example with approved maintenance context.",
    ),
    Scenario(
        "demo_case_ready",
        "[DEMO] Investigation-ready correlated evidence",
        "demo-linux-server",
        "192.0.2.10",
        "TRIAGED",
        "[DEMO] Correlated authentication and privilege evidence",
        13,
        ("T1110", "T1548"),
        90,
        94,
        "DEMO_CASE_READY",
        "CRITICAL",
        "Credential Access -> Privilege Escalation -> Case Workflow",
        "Synthetic case-ready signal for ownership, SLA and reporting workflows.",
    ),
)


REQUIRED_SCHEMA = {
    "incidents": {
        "id",
        "wazuh_doc_id",
        "status",
        "timestamp",
        "agent",
        "rule",
        "level",
        "mitre",
        "risk_score",
        "ai_analysis",
        "raw_alert",
        "correlated",
        "correlation_summary",
        "correlation_score",
        "attack_chain",
        "correlation_type",
        "escalation_reason",
        "recommended_priority",
    },
    "incident_audit": {
        "incident_id",
        "event_type",
        "new_value",
        "comment",
        "created_by",
    },
    "incident_notes": {"incident_id", "note", "created_by"},
    "incident_cases": {
        "id",
        "group_key",
        "title",
        "status",
        "severity",
        "agent",
        "correlation_type",
        "risk_score",
        "summary",
        "owner",
        "assignee",
        "sla_due_at",
        "severity_review",
        "status_reason",
        "last_reviewed_by",
        "last_reviewed_at",
        "created_by",
    },
    "case_incidents": {"case_id", "incident_id", "relationship_type"},
    "case_audit": {
        "case_id",
        "event_type",
        "new_value",
        "comment",
        "created_by",
    },
    "case_actions": {
        "case_id",
        "title",
        "description",
        "category",
        "priority",
        "status",
        "due_at",
        "created_by",
        "updated_at",
    },
    "case_ai_analyses": {
        "case_id",
        "model",
        "analysis",
        "recommended_status",
        "recommended_severity",
        "created_by",
    },
}


class UnsafeSeedError(RuntimeError):
    """Raised when the script cannot prove a write is demo-only."""


class SchemaMismatchError(UnsafeSeedError):
    """Raised when the configured database is not compatible with the seed."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def planned_records() -> list[dict[str, str]]:
    records = [
        {
            "type": "incident",
            "marker": scenario.external_id,
            "title": scenario.title,
        }
        for scenario in SCENARIOS
    ]
    records.extend(
        (
            {
                "type": "case",
                "marker": CASE_GROUP_KEY,
                "title": "[DEMO] Correlated SSH and privilege activity",
            },
            {
                "type": "case_action",
                "marker": DEMO_ACTOR,
                "title": "[DEMO] Review synthetic authentication evidence",
            },
            {
                "type": "case_ai_analysis",
                "marker": DEMO_ACTOR,
                "title": "[DEMO] Deterministic synthetic case summary",
            },
        )
    )
    return records


def scenario_raw_alert(scenario: Scenario, timestamp: str) -> str:
    return json.dumps(
        {
            "demo": True,
            "synthetic": True,
            "source": DEMO_MARKER,
            "seed_version": DEMO_VERSION,
            "scenario_id": scenario.scenario_id,
            "generated_at": timestamp,
            "agent": {"name": scenario.host},
            "source_ip": scenario.source_ip,
            "user": "demo.analyst",
            "rule": {
                "description": scenario.rule,
                "level": scenario.level,
                "mitre": {"id": list(scenario.mitre)},
            },
            "data": {
                "test_type": "local_demo_seed",
                "evidence_boundary": DECISION_BOUNDARY,
            },
        },
        sort_keys=True,
    )


def scenario_correlation_summary(scenario: Scenario) -> str:
    return json.dumps(
        {
            "synthetic": True,
            "source": DEMO_MARKER,
            "scenario_id": scenario.scenario_id,
            "agent": scenario.host,
            "related_events": 3 if scenario.host == "demo-linux-server" else 1,
            "final_correlation_score": scenario.correlation_score,
            "recommended_priority": scenario.priority,
            "explanation": scenario.summary,
        },
        sort_keys=True,
    )


def is_owned_incident(incident: Any) -> bool:
    return is_seed_demo_incident(incident)


def is_owned_case(case: Any) -> bool:
    return is_seed_demo_case(case)


def load_database() -> tuple[Any, Any, Any]:
    if str(REPOSITORY_ROOT) not in sys.path:
        sys.path.insert(0, str(REPOSITORY_ROOT))
    try:
        from sqlalchemy import inspect

        from database import SessionLocal, engine
        import models
    except Exception as exc:
        raise UnsafeSeedError(
            "Application database dependencies/configuration are unavailable: "
            f"{exc.__class__.__name__}"
        ) from exc
    return engine, SessionLocal, (inspect, models)


def validate_schema(engine: Any, inspect_function: Any) -> None:
    try:
        inspector = inspect_function(engine)
        table_names = set(inspector.get_table_names())
        problems: list[str] = []
        for table_name, required_columns in REQUIRED_SCHEMA.items():
            if table_name not in table_names:
                problems.append(f"missing table {table_name}")
                continue
            available = {
                column["name"] for column in inspector.get_columns(table_name)
            }
            missing = sorted(required_columns - available)
            if missing:
                problems.append(
                    f"{table_name} missing columns: {', '.join(missing)}"
                )
    except Exception as exc:
        raise UnsafeSeedError(
            f"Could not inspect the application database: {exc.__class__.__name__}"
        ) from exc

    if problems:
        raise SchemaMismatchError("Schema mismatch: " + "; ".join(problems))


def seed_status(db: Any, models: Any) -> dict[str, Any]:
    incidents = (
        db.query(models.Incident)
        .filter(
            models.Incident.wazuh_doc_id.in_(
                [scenario.external_id for scenario in SCENARIOS]
            )
        )
        .all()
    )
    unsafe_incidents = [
        incident.wazuh_doc_id
        for incident in incidents
        if not is_owned_incident(incident)
    ]

    case = (
        db.query(models.IncidentCase)
        .filter(models.IncidentCase.group_key == CASE_GROUP_KEY)
        .first()
    )
    unsafe_case = bool(case and not is_owned_case(case))

    incidents_by_marker = {
        incident.wazuh_doc_id: incident for incident in incidents
    }
    linked_markers = (
        SCENARIOS[0].external_id,
        SCENARIOS[1].external_id,
        SCENARIOS[4].external_id,
    )
    linked_incident_ids = {
        incidents_by_marker[marker].id
        for marker in linked_markers
        if marker in incidents_by_marker
    }
    linked_count = 0
    action_count = 0
    analysis_count = 0
    if case and not unsafe_case:
        linked_count = (
            db.query(models.CaseIncident)
            .filter(
                models.CaseIncident.case_id == case.id,
                models.CaseIncident.incident_id.in_(
                    linked_incident_ids or {-1}
                ),
            )
            .count()
        )
        action_count = (
            db.query(models.CaseAction)
            .filter(
                models.CaseAction.case_id == case.id,
                models.CaseAction.created_by == DEMO_ACTOR,
                models.CaseAction.title
                == "[DEMO] Review synthetic authentication evidence",
            )
            .count()
        )
        analysis_count = (
            db.query(models.CaseAIAnalysis)
            .filter(
                models.CaseAIAnalysis.case_id == case.id,
                models.CaseAIAnalysis.created_by == DEMO_ACTOR,
                models.CaseAIAnalysis.model
                == "deterministic-demo-placeholder",
            )
            .count()
        )

    return {
        "complete": (
            len(incidents) == len(SCENARIOS)
            and case is not None
            and linked_count == 3
            and action_count >= 1
            and analysis_count >= 1
            and not unsafe_incidents
            and not unsafe_case
        ),
        "incident_count": len(incidents),
        "expected_incident_count": len(SCENARIOS),
        "case_present": case is not None,
        "linked_incident_count": linked_count,
        "demo_action_count": action_count,
        "demo_analysis_count": analysis_count,
        "unsafe_collisions": unsafe_incidents
        + ([CASE_GROUP_KEY] if unsafe_case else []),
    }


def status_metadata(status: dict[str, Any]) -> dict[str, Any]:
    complete = bool(status.get("complete"))
    return {
        "demo_marker": DEMO_MARKER,
        "seed_version": DEMO_VERSION,
        "seed_result": "SEEDED" if complete else "NOT_SEEDED",
        "synthetic": True,
        "idempotent": True,
        "counts": {
            "incidents": int(status.get("incident_count") or 0),
            "cases": 1 if status.get("case_present") else 0,
            "case_links": int(status.get("linked_incident_count") or 0),
            "case_actions": int(status.get("demo_action_count") or 0),
            "case_ai_analyses": int(
                status.get("demo_analysis_count") or 0
            ),
        },
    }


def create_incident(db: Any, models: Any, scenario: Scenario, now: datetime) -> Any:
    timestamp = now.isoformat()
    incident = models.Incident(
        wazuh_doc_id=scenario.external_id,
        status=scenario.status,
        timestamp=timestamp,
        agent=scenario.host,
        rule=scenario.rule,
        level=scenario.level,
        mitre=json.dumps(list(scenario.mitre)),
        risk_score=scenario.risk_score,
        ai_analysis=(
            f"{scenario.summary} {DECISION_BOUNDARY} "
            "Recommended actions are advisory and require analyst review."
        ),
        raw_alert=scenario_raw_alert(scenario, timestamp),
        correlated=True,
        correlation_summary=scenario_correlation_summary(scenario),
        correlation_score=scenario.correlation_score,
        attack_chain=scenario.attack_chain,
        correlation_type=scenario.correlation_type,
        escalation_reason=scenario.summary,
        recommended_priority=scenario.priority,
    )
    db.add(incident)
    db.flush()
    db.add(
        models.IncidentAudit(
            incident_id=incident.id,
            event_type="DEMO_SEED_CREATED",
            new_value=scenario.scenario_id,
            comment=DECISION_BOUNDARY,
            created_by=DEMO_ACTOR,
        )
    )
    db.add(
        models.IncidentNote(
            incident_id=incident.id,
            note=(
                f"[DEMO] {scenario.summary} This note is synthetic and "
                "contains no real security evidence."
            ),
            created_by=DEMO_ACTOR,
        )
    )
    return incident


def apply_seed(db: Any, models: Any) -> dict[str, Any]:
    now = utc_now()
    created = {
        "incidents": 0,
        "cases": 0,
        "case_links": 0,
        "case_actions": 0,
        "case_ai_analyses": 0,
    }
    skipped = {
        "incidents": 0,
        "cases": 0,
        "case_links": 0,
        "case_actions": 0,
        "case_ai_analyses": 0,
    }
    incidents_by_marker: dict[str, Any] = {}

    for offset, scenario in enumerate(SCENARIOS):
        incident = (
            db.query(models.Incident)
            .filter(models.Incident.wazuh_doc_id == scenario.external_id)
            .first()
        )
        if incident:
            if not is_owned_incident(incident):
                raise UnsafeSeedError(
                    f"Stable incident marker collision: {scenario.external_id}"
                )
            skipped["incidents"] += 1
        else:
            incident = create_incident(
                db,
                models,
                scenario,
                now - timedelta(minutes=(len(SCENARIOS) - offset) * 4),
            )
            created["incidents"] += 1
        incidents_by_marker[scenario.scenario_id] = incident

    case = (
        db.query(models.IncidentCase)
        .filter(models.IncidentCase.group_key == CASE_GROUP_KEY)
        .first()
    )
    if case:
        if not is_owned_case(case):
            raise UnsafeSeedError(
                f"Stable case marker collision: {CASE_GROUP_KEY}"
            )
        skipped["cases"] += 1
    else:
        case = models.IncidentCase(
            group_key=CASE_GROUP_KEY,
            title="[DEMO] Correlated SSH and privilege activity",
            status="OPEN",
            severity="CRITICAL",
            agent="demo-linux-server",
            correlation_type="DEMO_CREDENTIAL_COMPROMISE",
            risk_score=90,
            summary=json.dumps(
                {
                    "synthetic": True,
                    "source": DEMO_MARKER,
                    "incident_markers": [
                        incidents_by_marker[name].wazuh_doc_id
                        for name in (
                            "demo_brute_force_ssh",
                            "demo_sudo_escalation",
                            "demo_case_ready",
                        )
                    ],
                    "evidence_boundary": DECISION_BOUNDARY,
                },
                sort_keys=True,
            ),
            owner="demo.analyst",
            assignee="demo.analyst",
            sla_due_at=now + timedelta(hours=4),
            severity_review="Synthetic severity for demo workflow validation.",
            status_reason="Open synthetic case for local product demonstration.",
            last_reviewed_by="demo.analyst",
            last_reviewed_at=now,
            created_by=DEMO_ACTOR,
        )
        db.add(case)
        db.flush()
        db.add(
            models.CaseAudit(
                case_id=case.id,
                event_type="DEMO_SEED_CREATED",
                new_value=CASE_GROUP_KEY,
                comment=DECISION_BOUNDARY,
                created_by=DEMO_ACTOR,
            )
        )
        created["cases"] += 1

    linked_names = (
        "demo_brute_force_ssh",
        "demo_sudo_escalation",
        "demo_case_ready",
    )
    existing_links = {
        row.incident_id
        for row in db.query(models.CaseIncident)
        .filter(models.CaseIncident.case_id == case.id)
        .all()
    }
    for name in linked_names:
        incident = incidents_by_marker[name]
        if incident.id in existing_links:
            skipped["case_links"] += 1
            continue
        db.add(
            models.CaseIncident(
                case_id=case.id,
                incident_id=incident.id,
                relationship_type="SYNTHETIC_CORRELATED",
            )
        )
        created["case_links"] += 1

    action = (
        db.query(models.CaseAction)
        .filter(
            models.CaseAction.case_id == case.id,
            models.CaseAction.created_by == DEMO_ACTOR,
            models.CaseAction.title
            == "[DEMO] Review synthetic authentication evidence",
        )
        .first()
    )
    if action:
        skipped["case_actions"] += 1
    else:
        db.add(
            models.CaseAction(
                case_id=case.id,
                title="[DEMO] Review synthetic authentication evidence",
                description=(
                    "Read-only analyst task: compare the synthetic SSH and "
                    "sudo evidence. Do not execute remediation."
                ),
                category="EVIDENCE_REVIEW",
                priority="HIGH",
                status="OPEN",
                due_at=now + timedelta(hours=2),
                created_by=DEMO_ACTOR,
                updated_at=now,
            )
        )
        created["case_actions"] += 1

    analysis = (
        db.query(models.CaseAIAnalysis)
        .filter(
            models.CaseAIAnalysis.case_id == case.id,
            models.CaseAIAnalysis.created_by == DEMO_ACTOR,
        )
        .first()
    )
    if analysis:
        skipped["case_ai_analyses"] += 1
    else:
        db.add(
            models.CaseAIAnalysis(
                case_id=case.id,
                model="deterministic-demo-placeholder",
                analysis=(
                    "[DEMO] Synthetic authentication failures are followed by "
                    "synthetic sudo activity on demo-linux-server. Validate the "
                    "evidence and ownership workflow; no automated remediation "
                    "is authorized. "
                    + DECISION_BOUNDARY
                ),
                recommended_status="INVESTIGATING",
                recommended_severity="CRITICAL",
                created_by=DEMO_ACTOR,
            )
        )
        created["case_ai_analyses"] += 1

    db.flush()
    return {
        "created": created,
        "skipped": skipped,
        "case_id": case.id,
        "incident_ids": {
            scenario_id: incident.id
            for scenario_id, incident in incidents_by_marker.items()
        },
    }


def database_operation(mode: str) -> tuple[dict[str, Any], int]:
    try:
        engine, session_factory, dependencies = load_database()
        inspect_function, models = dependencies
        validate_schema(engine, inspect_function)
        db = session_factory()
    except SchemaMismatchError as exc:
        return {
            "mode": mode,
            "result": "NOT_READY",
            "exit_code": 1,
            "message": str(exc),
        }, 1
    except UnsafeSeedError as exc:
        return {
            "mode": mode,
            "result": "NOT_READY" if mode == "apply" else "UNAVAILABLE",
            "exit_code": 1 if mode == "apply" else 0,
            "message": str(exc),
        }, 1 if mode == "apply" else 0

    try:
        if mode == "status":
            status = seed_status(db, models)
            if status["unsafe_collisions"]:
                raise UnsafeSeedError(
                    "Unsafe stable marker collision detected: "
                    + ", ".join(status["unsafe_collisions"])
                )
            report = {
                "mode": mode,
                "result": "PRESENT" if status["complete"] else "NOT_PRESENT",
                "exit_code": 0,
                "marker": DEMO_ACTOR,
                "status": status,
                **status_metadata(status),
            }
            return report, 0

        result = apply_seed(db, models)
        db.commit()
        status = seed_status(db, models)
        report = {
            "mode": mode,
            "result": "APPLIED",
            "exit_code": 0,
            "marker": DEMO_ACTOR,
            "changes": result,
            "status": status,
            **status_metadata(status),
        }
        return report, 0
    except UnsafeSeedError as exc:
        db.rollback()
        report = {
            "mode": mode,
            "result": "NOT_READY",
            "exit_code": 1,
            "message": str(exc),
        }
        return report, 1
    except Exception as exc:
        db.rollback()
        report = {
            "mode": mode,
            "result": "FAILED",
            "exit_code": 1,
            "message": f"Database operation failed: {exc.__class__.__name__}",
        }
        return report, 1
    finally:
        db.close()


def dry_run_report() -> dict[str, Any]:
    return {
        "mode": "dry-run",
        "result": "DRY_RUN",
        "exit_code": 0,
        "marker": DEMO_ACTOR,
        "decision_boundary": DECISION_BOUNDARY,
        "records": planned_records(),
        "safety": {
            "writes_performed": False,
            "default_is_dry_run": True,
            "idempotency": "stable incident and case markers; existing demo-owned records are skipped",
            "real_records_modified": False,
            "remediation_actions_created": False,
        },
    }


def print_human(report: dict[str, Any]) -> None:
    print("Sovereign AI SOC Demo Seed")
    print(f"[WARN] {DECISION_BOUNDARY}")
    print(f"[INFO] Mode: {report['mode']}")
    if report.get("marker"):
        print(f"[INFO] Stable marker: {report['marker']}")

    if report["mode"] == "dry-run":
        print("[OK] Dry run only; no database writes were performed")
        for record in report["records"]:
            print(
                f"[INFO] Would ensure {record['type']}: "
                f"{record['title']} ({record['marker']})"
            )
        print("[OK] Existing non-demo records would not be changed")
        return

    if report["result"] in {"UNAVAILABLE", "NOT_READY", "FAILED"}:
        status = "WARN" if report["result"] == "UNAVAILABLE" else "FAIL"
        print(f"[{status}] {report['message']}")
        return

    if report["mode"] == "status":
        status = report["status"]
        print(
            f"[{'OK' if status['complete'] else 'INFO'}] "
            f"Demo seed is {report['result'].lower().replace('_', ' ')}"
        )
        print(
            f"[INFO] Incidents: {status['incident_count']}/"
            f"{status['expected_incident_count']}; "
            f"case: {'present' if status['case_present'] else 'missing'}; "
            f"links: {status['linked_incident_count']}/3"
        )
        return

    changes = report["changes"]
    labels = {
        "incidents": ("incident", "incidents"),
        "cases": ("case", "cases"),
        "case_links": ("case link", "case links"),
        "case_actions": ("case action", "case actions"),
        "case_ai_analyses": ("case AI analysis", "case AI analyses"),
    }

    def count_label(name: str, count: int) -> str:
        singular, plural = labels[name]
        return f"{count} {singular if count == 1 else plural}"

    print(
        "[OK] Demo seed transaction committed: "
        + ", ".join(
            f"{count_label(name, count)} created"
            for name, count in changes["created"].items()
        )
    )
    print(
        "[INFO] Existing demo-owned records skipped: "
        + ", ".join(
            count_label(name, count)
            for name, count in changes["skipped"].items()
        )
    )
    print("[OK] No non-demo records were modified")
    print("[OK] No remediation or SOAR action was executed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed controlled synthetic data for a local demo.",
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the synthetic records without writing (default).",
    )
    modes.add_argument(
        "--apply",
        action="store_true",
        help="Write missing demo-owned records transactionally.",
    )
    modes.add_argument(
        "--status",
        action="store_true",
        help="Report whether the stable demo records exist.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a machine-readable JSON report.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.apply:
        report, exit_code = database_operation("apply")
    elif args.status:
        report, exit_code = database_operation("status")
    else:
        report, exit_code = dry_run_report(), 0

    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        print_human(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
