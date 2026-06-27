from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid

from fastapi import APIRouter, HTTPException, Request

from database import SessionLocal
from models import Incident, IncidentAudit
from qdrant_auto_index import schedule_incident_auto_index
from schemas.synthetic_tests import SyntheticTestRunCreate
from security.audit import security_audit_actor, write_security_audit


router = APIRouter()


SYNTHETIC_SCENARIOS = {
    "ssh_bruteforce": {
        "title": "SYNTHETIC ssh_bruteforce: repeated authentication failures",
        "rule": "SYNTHETIC ssh_bruteforce - repeated failed SSH login attempts",
        "level": 10,
        "mitre": ["T1110", "T1021.004"],
        "risk_score": 76,
        "correlation_score": 84,
        "correlation_type": "SYNTHETIC_SSH_BRUTEFORCE",
        "recommended_priority": "HIGH",
        "attack_chain": "Initial Access -> Credential Access",
        "escalation_reason": "Synthetic brute force scenario generated repeated failed SSH authentication events.",
        "ai_analysis": "Synthetic SSH brute-force test. Validate detection, correlation, priority assignment and MITRE mapping.",
        "matched_patterns": {
            "ssh_bruteforce": {
                "keywords": ["ssh", "failed password", "authentication failure", "bruteforce"],
                "weight": 40,
            }
        },
    },
    "privilege_escalation": {
        "title": "SYNTHETIC privilege_escalation: suspicious sudo/root activity",
        "rule": "SYNTHETIC privilege_escalation - suspicious sudo/root command execution",
        "level": 12,
        "mitre": ["T1068", "T1548"],
        "risk_score": 88,
        "correlation_score": 91,
        "correlation_type": "SYNTHETIC_PRIVILEGE_ESCALATION",
        "recommended_priority": "CRITICAL",
        "attack_chain": "Execution -> Privilege Escalation",
        "escalation_reason": "Synthetic privilege escalation scenario generated suspicious root-level activity.",
        "ai_analysis": "Synthetic privilege-escalation test. Validate escalation logic, critical priority and MITRE coverage.",
        "matched_patterns": {
            "privilege_escalation": {
                "keywords": ["sudo", "root", "privilege escalation", "setuid"],
                "weight": 50,
            }
        },
    },
    "malware_indicator": {
        "title": "SYNTHETIC malware_indicator: suspicious process and persistence signal",
        "rule": "SYNTHETIC malware_indicator - suspicious process persistence indicator",
        "level": 11,
        "mitre": ["T1059", "T1547"],
        "risk_score": 82,
        "correlation_score": 87,
        "correlation_type": "SYNTHETIC_MALWARE_INDICATOR",
        "recommended_priority": "HIGH",
        "attack_chain": "Execution -> Persistence",
        "escalation_reason": "Synthetic malware indicator scenario generated suspicious execution and persistence evidence.",
        "ai_analysis": "Synthetic malware-indicator test. Validate detection quality, correlation score and persistence classification.",
        "matched_patterns": {
            "malware_indicator": {
                "keywords": ["malware", "persistence", "suspicious process", "autorun"],
                "weight": 45,
            }
        },
    },
    "suspicious_package_activity": {
        "title": "SYNTHETIC suspicious_package_activity: package and configuration change",
        "rule": "SYNTHETIC suspicious_package_activity - package activity outside maintenance window",
        "level": 8,
        "mitre": ["T1072", "T1546"],
        "risk_score": 58,
        "correlation_score": 68,
        "correlation_type": "SYNTHETIC_SUSPICIOUS_PACKAGE_ACTIVITY",
        "recommended_priority": "MEDIUM",
        "attack_chain": "Defense Evasion -> Persistence",
        "escalation_reason": "Synthetic package activity scenario generated system-change evidence outside the expected maintenance context.",
        "ai_analysis": "Synthetic package-activity test. Validate medium-risk triage, package-change evidence and MITRE mapping.",
        "matched_patterns": {
            "suspicious_package_activity": {
                "keywords": ["package", "dpkg", "apt", "configuration", "maintenance"],
                "weight": 35,
            }
        },
    },
    "noisy_operational_baseline": {
        "title": "SYNTHETIC noisy_operational_baseline: benign operational activity",
        "rule": "SYNTHETIC noisy_operational_baseline - routine administrative signal",
        "level": 3,
        "mitre": [],
        "risk_score": 18,
        "correlation_score": 32,
        "correlation_type": "SYNTHETIC_NOISY_OPERATIONAL_BASELINE",
        "recommended_priority": "LOW",
        "attack_chain": "Operational Activity",
        "escalation_reason": "Synthetic operational baseline scenario generated benign activity for noise-handling validation.",
        "ai_analysis": "Synthetic noisy-baseline test. Validate that routine operational activity stays low priority and remains analyst-verifiable.",
        "matched_patterns": {
            "noisy_operational_baseline": {
                "keywords": ["routine", "systemctl", "pam session", "trusted operator"],
                "weight": 15,
            }
        },
    },
    "false_positive": {
        "title": "SYNTHETIC false_positive: approved maintenance context",
        "rule": "SYNTHETIC false_positive - approved administrative change with ticket context",
        "level": 4,
        "mitre": [],
        "risk_score": 16,
        "correlation_score": 28,
        "correlation_type": "SYNTHETIC_FALSE_POSITIVE",
        "recommended_priority": "LOW",
        "attack_chain": "Approved Change -> Human Validation",
        "escalation_reason": "Synthetic false-positive scenario generated approved maintenance context for analyst disposition validation.",
        "ai_analysis": "Synthetic false-positive test. Validate benign classification, analyst decision support and audit-ready rationale.",
        "matched_patterns": {
            "false_positive": {
                "keywords": ["approved maintenance", "change ticket", "false positive", "authorized"],
                "weight": 15,
            }
        },
    },
    "real_incident": {
        "title": "SYNTHETIC real_incident: multi-stage critical compromise signal",
        "rule": "SYNTHETIC real_incident - brute force followed by privileged activity",
        "level": 14,
        "mitre": ["T1110", "T1021.004", "T1548"],
        "risk_score": 94,
        "correlation_score": 96,
        "correlation_type": "SYNTHETIC_REAL_INCIDENT",
        "recommended_priority": "CRITICAL",
        "attack_chain": "Credential Access -> Initial Access -> Privilege Escalation",
        "escalation_reason": "Synthetic real incident scenario generated a multi-stage authentication and privilege escalation chain.",
        "ai_analysis": "Synthetic real-incident test. Validate critical priority, multi-stage correlation, MITRE coverage and escalation workflow.",
        "matched_patterns": {
            "real_incident": {
                "keywords": ["bruteforce", "successful login", "root", "privilege escalation"],
                "weight": 60,
            }
        },
    },
    "case_ready": {
        "title": "SYNTHETIC case_ready: investigation-ready correlated evidence",
        "rule": "SYNTHETIC case_ready - correlated authentication and privilege evidence",
        "level": 13,
        "mitre": ["T1110", "T1548"],
        "risk_score": 90,
        "correlation_score": 94,
        "correlation_type": "SYNTHETIC_CASE_READY",
        "recommended_priority": "CRITICAL",
        "attack_chain": "Credential Access -> Privilege Escalation -> Case Workflow",
        "escalation_reason": "Synthetic case-ready scenario generated correlated evidence suitable for incident-to-case validation.",
        "ai_analysis": "Synthetic case-ready test. Validate case creation, investigation evidence, AI case analysis and closure governance.",
        "matched_patterns": {
            "case_ready": {
                "keywords": ["case", "correlated", "same host", "analyst context", "escalation"],
                "weight": 55,
            }
        },
    },
}


def build_synthetic_incident(
    *,
    scenario_name: str,
    index: int,
    host: str,
    created_by: str,
) -> Incident:
    scenario = SYNTHETIC_SCENARIOS[scenario_name]
    now = datetime.now(timezone.utc)
    timestamp = now.isoformat()
    synthetic_id = f"synthetic-{scenario_name}-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"

    raw_alert = {
        "synthetic": True,
        "source": "sovereign-ai-soc-synthetic",
        "scenario": scenario_name,
        "scenario_index": index,
        "created_by": created_by,
        "generated_at": timestamp,
        "agent": {
            "name": host,
        },
        "rule": {
            "description": scenario["rule"],
            "level": scenario["level"],
            "mitre": {
                "id": scenario["mitre"],
            },
        },
        "data": {
            "test_type": "gui_synthetic_test",
            "expected_priority": scenario["recommended_priority"],
            "expected_correlation_type": scenario["correlation_type"],
        },
    }

    correlation_summary = {
        "agent": host,
        "window_minutes": 60,
        "related_events": 1,
        "current_incident_id": None,
        "base_score": scenario["risk_score"],
        "pattern_score": 35,
        "volume_score": 10,
        "chain_bonus": 10,
        "final_correlation_score": scenario["correlation_score"],
        "recommended_priority": scenario["recommended_priority"],
        "matched_patterns": scenario["matched_patterns"],
        "matched_attack_chains": [
            {
                "name": scenario["attack_chain"],
                "correlation_type": scenario["correlation_type"],
                "priority": scenario["recommended_priority"],
                "reason": scenario["escalation_reason"],
                "score_bonus": 10,
            }
        ],
        "related_event_details": [],
    }

    return Incident(
        wazuh_doc_id=synthetic_id,
        status="NEW",
        timestamp=timestamp,
        agent=host,
        rule=scenario["rule"],
        level=scenario["level"],
        mitre=json.dumps(scenario["mitre"]),
        risk_score=scenario["risk_score"],
        ai_analysis=scenario["ai_analysis"],
        raw_alert=json.dumps(raw_alert),
        correlated=True,
        correlation_summary=json.dumps(correlation_summary),
        correlation_score=scenario["correlation_score"],
        attack_chain=scenario["attack_chain"],
        correlation_type=scenario["correlation_type"],
        escalation_reason=scenario["escalation_reason"],
        recommended_priority=scenario["recommended_priority"],
    )


@router.get("/synthetic-tests/scenarios")
def list_synthetic_test_scenarios():
    return {
        "items": [
            {
                "id": key,
                "title": value["title"],
                "rule": value["rule"],
                "recommended_priority": value["recommended_priority"],
                "risk_score": value["risk_score"],
                "correlation_type": value["correlation_type"],
                "mitre": value["mitre"],
            }
            for key, value in SYNTHETIC_SCENARIOS.items()
        ]
    }


@router.post("/synthetic-tests/run")
def run_synthetic_tests(payload: SyntheticTestRunCreate, request: Request):
    requested_scenario = payload.scenario.lower().strip()
    count = max(1, min(payload.count, 10))
    host = (payload.host or "synthetic-sensor-01").strip() or "synthetic-sensor-01"
    created_by = (payload.created_by or "local_analyst").strip() or "local_analyst"

    if requested_scenario == "all":
        scenarios = list(SYNTHETIC_SCENARIOS.keys())
    elif requested_scenario in SYNTHETIC_SCENARIOS:
        scenarios = [requested_scenario]
    else:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Unknown synthetic scenario.",
                "requested_scenario": requested_scenario,
                "available_scenarios": ["all", *SYNTHETIC_SCENARIOS.keys()],
            },
        )

    db = SessionLocal()

    try:
        created_incidents: list[Incident] = []

        for scenario_name in scenarios:
            for index in range(1, count + 1):
                incident = build_synthetic_incident(
                    scenario_name=scenario_name,
                    index=index,
                    host=host,
                    created_by=created_by,
                )
                db.add(incident)
                db.flush()

                db.add(
                    IncidentAudit(
                        incident_id=incident.id,
                        event_type="SYNTHETIC_TEST_CREATED",
                        old_value=None,
                        new_value=scenario_name,
                        comment=(
                            f"Synthetic test incident generated from GUI. "
                            f"Scenario={scenario_name}; host={host}; created_by={created_by}"
                        ),
                        created_by=created_by,
                    )
                )

                created_incidents.append(incident)

        db.commit()
        for incident in created_incidents:
            schedule_incident_auto_index(
                incident.id,
                reason="synthetic_incident_created",
            )

        write_security_audit(
            event_type="SYNTHETIC_TEST_RUN",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="SYNTHETIC_TEST",
            target_id=requested_scenario,
            request=request,
            details={
                "requested_scenario": requested_scenario,
                "scenarios": scenarios,
                "host": host,
                "count_per_scenario": count,
                "created": len(created_incidents),
                "created_by": created_by,
                "incident_ids": [incident.id for incident in created_incidents],
            },
        )

        return {
            "status": "created",
            "scenario": requested_scenario,
            "host": host,
            "count_per_scenario": count,
            "created": len(created_incidents),
            "incidents": [
                {
                    "id": incident.id,
                    "scenario": incident.correlation_type,
                    "rule": incident.rule,
                    "risk_score": incident.risk_score,
                    "recommended_priority": incident.recommended_priority,
                    "correlation_score": incident.correlation_score,
                }
                for incident in created_incidents
            ],
        }
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
