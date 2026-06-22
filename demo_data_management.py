from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from models import (
    CaseAIAnalysis,
    CaseAction,
    CaseAiGenerationJob,
    CaseAudit,
    CaseClosureChecklist,
    CaseIncident,
    EventAggregate,
    Incident,
    IncidentAudit,
    IncidentCase,
    IncidentNote,
    InvestigationSessionRecord,
    InvestigationSimilarityHistoryRecord,
    RemediationProposal,
    RemediationProposalEvent,
    SecurityAlert,
)
from sqlalchemy import and_, or_


DEMO_MARKER = "AI_SOC_DEMO_SEED"
DEMO_VERSION = "v1"
DEMO_ACTOR = f"{DEMO_MARKER}:{DEMO_VERSION}"
DEMO_INCIDENT_PREFIX = f"{DEMO_ACTOR}:incident:"
DEMO_CASE_PREFIX = f"{DEMO_ACTOR}:case:"
DEMO_SCENARIO_IDS = (
    "demo_brute_force_ssh",
    "demo_sudo_escalation",
    "demo_suspicious_package_activity",
    "demo_noisy_operational_baseline",
    "demo_case_ready",
)
DEMO_INCIDENT_MARKERS = tuple(
    f"{DEMO_INCIDENT_PREFIX}{scenario_id}"
    for scenario_id in DEMO_SCENARIO_IDS
)
DEMO_CASE_GROUP_KEY = f"{DEMO_CASE_PREFIX}credential-compromise"
LEGACY_SYNTHETIC_SOURCE = "sovereign-ai-soc-synthetic"
LEGACY_SYNTHETIC_PREFIX = "synthetic-"


class DemoManagementError(RuntimeError):
    pass


class DemoRecordNotFound(DemoManagementError):
    pass


class DemoOwnershipError(DemoManagementError):
    pass


class DemoDependencyError(DemoManagementError):
    def __init__(self, blockers: list[str]):
        self.blockers = blockers
        super().__init__(
            "Deletion blocked by protected references: " + ", ".join(blockers)
        )


@dataclass(frozen=True)
class DemoDeletionResult:
    record_type: str
    record_id: int
    demo_origin: str
    deleted_counts: dict[str, int]


def _raw_payload(incident: Incident) -> dict[str, Any]:
    try:
        payload = json.loads(incident.raw_alert or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def is_seed_demo_incident(incident: Incident) -> bool:
    payload = _raw_payload(incident)
    return (
        str(incident.wazuh_doc_id or "") in DEMO_INCIDENT_MARKERS
        and payload.get("synthetic") is True
        and payload.get("demo") is True
        and payload.get("source") == DEMO_MARKER
        and payload.get("seed_version") == DEMO_VERSION
    )


def is_legacy_synthetic_incident(incident: Incident) -> bool:
    payload = _raw_payload(incident)
    data = payload.get("data")
    if not isinstance(data, dict):
        data = {}
    return (
        str(incident.wazuh_doc_id or "").startswith(LEGACY_SYNTHETIC_PREFIX)
        and payload.get("synthetic") is True
        and payload.get("source") == LEGACY_SYNTHETIC_SOURCE
        and data.get("test_type") == "gui_synthetic_test"
    )


def incident_demo_origin(incident: Incident) -> str | None:
    if is_seed_demo_incident(incident):
        return "seed"
    if is_legacy_synthetic_incident(incident):
        return "synthetic_test"
    return None


def is_seed_demo_case(case: IncidentCase) -> bool:
    return (
        case.group_key == DEMO_CASE_GROUP_KEY
        and case.created_by == DEMO_ACTOR
        and str(case.title or "").startswith("[DEMO]")
    )


def case_demo_origin(case: IncidentCase) -> str | None:
    return "seed" if is_seed_demo_case(case) else None


def demo_incident_filter():
    return or_(
        Incident.wazuh_doc_id.in_(DEMO_INCIDENT_MARKERS),
        and_(
            Incident.wazuh_doc_id.like(f"{LEGACY_SYNTHETIC_PREFIX}%"),
            Incident.raw_alert.contains('"synthetic": true'),
            Incident.raw_alert.contains(
                f'"source": "{LEGACY_SYNTHETIC_SOURCE}"'
            ),
            Incident.raw_alert.contains('"test_type": "gui_synthetic_test"'),
        ),
    )


def _count_and_delete(db: Any, model: Any, criterion: Any) -> int:
    rows = list(db.query(model).filter(criterion).all())
    for row in rows:
        db.delete(row)
    if rows:
        db.flush()
    return len(rows)


def _incident_blockers(db: Any, incident: Incident) -> list[str]:
    blockers: list[str] = []
    if incident.raw_event_id is not None:
        blockers.append("raw_event")
    if incident.security_alert_id is not None:
        blockers.append("security_alert")
    if (
        db.query(SecurityAlert)
        .filter(SecurityAlert.incident_id == incident.id)
        .count()
    ):
        blockers.append("security_alert_reference")
    if (
        db.query(EventAggregate)
        .filter(EventAggregate.last_incident_id == incident.id)
        .count()
    ):
        blockers.append("event_aggregate")
    if (
        db.query(InvestigationSessionRecord)
        .filter(InvestigationSessionRecord.incident_id == incident.id)
        .count()
    ):
        blockers.append("investigation_session")
    if (
        db.query(InvestigationSimilarityHistoryRecord)
        .filter(
            (
                InvestigationSimilarityHistoryRecord.incident_id
                == incident.id
            )
            | (
                InvestigationSimilarityHistoryRecord.related_incident_id
                == incident.id
            )
        )
        .count()
    ):
        blockers.append("investigation_similarity_history")

    links = (
        db.query(CaseIncident)
        .filter(CaseIncident.incident_id == incident.id)
        .all()
    )
    for link in links:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == link.case_id)
            .first()
        )
        if (
            not case
            or not is_seed_demo_case(case)
            or link.relationship_type != "SYNTHETIC_CORRELATED"
        ):
            blockers.append("non_demo_case_link")
            break
    return sorted(set(blockers))


def _delete_remediation_proposals(
    db: Any,
    *,
    incident_id: int | None = None,
    case_id: int | None = None,
) -> dict[str, int]:
    criteria = []
    if incident_id is not None:
        criteria.append(RemediationProposal.incident_id == incident_id)
    if case_id is not None:
        criteria.append(RemediationProposal.case_id == case_id)
    if not criteria:
        return {
            "remediation_proposal_events": 0,
            "remediation_proposals": 0,
        }

    proposals = list(
        db.query(RemediationProposal).filter(or_(*criteria)).all()
    )
    proposal_ids = [proposal.id for proposal in proposals]
    event_count = 0
    if proposal_ids:
        event_count = _count_and_delete(
            db,
            RemediationProposalEvent,
            RemediationProposalEvent.proposal_id.in_(proposal_ids),
        )
    for proposal in proposals:
        db.delete(proposal)
    if proposals:
        db.flush()
    return {
        "remediation_proposal_events": event_count,
        "remediation_proposals": len(proposals),
    }


def delete_demo_incident(db: Any, incident_id: int) -> DemoDeletionResult:
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )
    if not incident:
        raise DemoRecordNotFound("Incident not found.")

    origin = incident_demo_origin(incident)
    if origin not in {"seed", "synthetic_test"}:
        raise DemoOwnershipError(
            "Incident is not owned by a supported synthetic data marker."
        )

    blockers = _incident_blockers(db, incident)
    if blockers:
        raise DemoDependencyError(blockers)

    counts = {
        **_delete_remediation_proposals(db, incident_id=incident.id),
        "case_links": _count_and_delete(
            db,
            CaseIncident,
            CaseIncident.incident_id == incident.id,
        ),
        "incident_notes": _count_and_delete(
            db,
            IncidentNote,
            IncidentNote.incident_id == incident.id,
        ),
        "incident_audit": _count_and_delete(
            db,
            IncidentAudit,
            IncidentAudit.incident_id == incident.id,
        ),
        "incidents": 1,
    }
    db.delete(incident)
    db.flush()
    return DemoDeletionResult("incident", incident_id, origin, counts)


def _case_blockers(db: Any, case: IncidentCase) -> list[str]:
    blockers: list[str] = []
    links = (
        db.query(CaseIncident)
        .filter(CaseIncident.case_id == case.id)
        .all()
    )
    for link in links:
        incident = (
            db.query(Incident)
            .filter(Incident.id == link.incident_id)
            .first()
        )
        if (
            not incident
            or not is_seed_demo_incident(incident)
            or link.relationship_type != "SYNTHETIC_CORRELATED"
        ):
            blockers.append("non_demo_incident_link")
            break
    return sorted(set(blockers))


def delete_demo_case(db: Any, case_id: int) -> DemoDeletionResult:
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == case_id)
        .first()
    )
    if not case:
        raise DemoRecordNotFound("Case not found.")
    if not is_seed_demo_case(case):
        raise DemoOwnershipError(
            "Case is not owned by the stable synthetic demo marker."
        )

    blockers = _case_blockers(db, case)
    if blockers:
        raise DemoDependencyError(blockers)

    counts = {
        **_delete_remediation_proposals(db, case_id=case.id),
        "case_ai_generation_jobs": _count_and_delete(
            db,
            CaseAiGenerationJob,
            CaseAiGenerationJob.case_id == case.id,
        ),
        "case_closure_checklists": _count_and_delete(
            db,
            CaseClosureChecklist,
            CaseClosureChecklist.case_id == case.id,
        ),
        "case_ai_analyses": _count_and_delete(
            db,
            CaseAIAnalysis,
            CaseAIAnalysis.case_id == case.id,
        ),
        "case_actions": _count_and_delete(
            db,
            CaseAction,
            CaseAction.case_id == case.id,
        ),
        "case_audit": _count_and_delete(
            db,
            CaseAudit,
            CaseAudit.case_id == case.id,
        ),
        "case_links": _count_and_delete(
            db,
            CaseIncident,
            CaseIncident.case_id == case.id,
        ),
        "cases": 1,
    }
    db.delete(case)
    db.flush()
    return DemoDeletionResult("case", case_id, "seed", counts)
