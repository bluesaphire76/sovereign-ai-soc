from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from ai_provider_redaction import RedactionOptions, redact_text
from database import SessionLocal
from investigation_ai.adapters import safe_text
from models import CaseClosureChecklist, CaseIncident, Incident, IncidentCase, IncidentNote
from qdrant_knowledge import (
    SEMANTIC_MEMORY_DECISION_BOUNDARY,
    QdrantKnowledgeBase,
    SemanticMemoryRecord,
)


HISTORICAL_INCIDENT_SOURCE_TYPE = "historical_incident"
HISTORICAL_INCIDENT_DECISION_BOUNDARY = (
    "Historical incident memory is advisory only. Similarity may support analyst "
    "review, but it does not prove the same root cause, duplicate status, final "
    "severity, suppression, incident or case closure, or remediation. "
    "Deterministic evidence and human validation remain required."
)
OPEN_INCIDENT_STATUSES = {
    "NEW",
    "OPEN",
    "TRIAGED",
    "ESCALATED",
    "IN_PROGRESS",
    "INVESTIGATING",
    "CONTAINED",
}


@dataclass(frozen=True)
class HistoricalIncidentMemory:
    record: SemanticMemoryRecord
    redaction_applied: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Index safe historical incident memory summaries into Qdrant."
    )
    parser.add_argument("--limit", type=int, default=1000, help="Maximum incidents to scan.")
    parser.add_argument(
        "--since-days",
        type=int,
        default=None,
        help="Only include incidents whose timestamp is within this number of days.",
    )
    parser.add_argument(
        "--include-open",
        action="store_true",
        help="Include currently open/non-terminal incident statuses.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write generated historical incident memory records to Qdrant.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview generated records without writing to Qdrant. This is the default.",
    )
    return parser.parse_args()


def _short_text(value: Any, *, max_chars: int = 700) -> str:
    text = " ".join(safe_text(value).split())
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3].rstrip()}..."


def _safe_memory_text(value: Any, *, max_chars: int = 700) -> tuple[str, bool]:
    result = redact_text(
        _short_text(value, max_chars=max_chars),
        RedactionOptions(
            redact_ips=True,
            redact_usernames=True,
            redact_hostnames=True,
            redact_file_paths=True,
        ),
    )
    return safe_text(result.value), result.applied


def _serialize_datetime(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, datetime):
        return value.isoformat()

    text = safe_text(value)
    return text or None


def _parse_incident_timestamp(value: Any) -> datetime | None:
    text = safe_text(value)
    if not text:
        return None

    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _case_context(case: IncidentCase | None, closure: CaseClosureChecklist | None) -> tuple[str, bool]:
    if not case:
        return "No linked case context available.", False

    parts = [
        f"Case ID: {case.id}",
        f"Case Title: {case.title}",
        f"Case Status: {case.status}",
        f"Case Severity: {case.severity}",
        f"Case Summary: {case.summary}",
    ]

    if closure:
        parts.extend(
            [
                f"Closure Decision: {closure.closure_decision}",
                f"Closure Reason: {closure.closure_reason}",
                f"Root Cause: {closure.root_cause}",
                f"Residual Risk: {closure.residual_risk}",
            ]
        )

    return _safe_memory_text("\n".join(part for part in parts if safe_text(part)), max_chars=900)


def _notes_summary(notes: list[IncidentNote]) -> tuple[str, bool]:
    if not notes:
        return "No analyst notes available.", False

    text = "\n".join(
        f"{note.created_by or 'analyst'}: {note.note}"
        for note in notes[:5]
        if safe_text(note.note)
    )
    return _safe_memory_text(text, max_chars=900)


def build_historical_incident_memory(
    incident: Incident,
    *,
    case: IncidentCase | None = None,
    closure: CaseClosureChecklist | None = None,
    notes: list[IncidentNote] | None = None,
    indexed_at: datetime | None = None,
) -> HistoricalIncidentMemory:
    """Build a redacted, advisory-only semantic memory record for one incident."""

    rule, rule_redacted = _safe_memory_text(incident.rule, max_chars=220)
    agent, agent_redacted = _safe_memory_text(incident.agent, max_chars=160)
    status, status_redacted = _safe_memory_text(incident.status, max_chars=80)
    priority, priority_redacted = _safe_memory_text(
        incident.recommended_priority,
        max_chars=80,
    )
    mitre, mitre_redacted = _safe_memory_text(incident.mitre, max_chars=160)
    correlation_type, correlation_redacted = _safe_memory_text(
        incident.correlation_type,
        max_chars=160,
    )
    attack_chain, attack_redacted = _safe_memory_text(
        incident.attack_chain,
        max_chars=500,
    )
    ai_summary, ai_redacted = _safe_memory_text(incident.ai_analysis, max_chars=900)
    escalation_reason, escalation_redacted = _safe_memory_text(
        incident.escalation_reason,
        max_chars=500,
    )
    case_text, case_redacted = _case_context(case, closure)
    notes_text, notes_redacted = _notes_summary(notes or [])
    indexed_at_value = indexed_at or datetime.now(timezone.utc)

    lines = [
        "Historical Incident Memory",
        f"Incident ID: {incident.id}",
        f"Rule: {rule}",
        f"Agent: {agent}",
        f"Status: {status}",
        f"Severity/Priority: {priority}",
        f"Risk Score: {incident.risk_score}",
        f"Wazuh Level: {incident.level}",
        f"MITRE: {mitre}",
        f"Correlation Type: {correlation_type}",
        f"Attack Chain: {attack_chain}",
        f"Escalation Reason: {escalation_reason}",
        f"AI Analysis Summary: {ai_summary}",
        f"Case/Closure Context: {case_text}",
        f"Analyst Notes Summary: {notes_text}",
        f"Decision Boundary: {HISTORICAL_INCIDENT_DECISION_BOUNDARY}",
        f"Semantic Memory Boundary: {SEMANTIC_MEMORY_DECISION_BOUNDARY}",
    ]

    text = "\n".join(line for line in lines if safe_text(line))
    redaction_applied = any(
        [
            rule_redacted,
            agent_redacted,
            status_redacted,
            priority_redacted,
            mitre_redacted,
            correlation_redacted,
            attack_redacted,
            ai_redacted,
            escalation_redacted,
            case_redacted,
            notes_redacted,
        ]
    )

    payload = {
        "source_type": HISTORICAL_INCIDENT_SOURCE_TYPE,
        "source": f"incident:{incident.id}",
        "incident_id": incident.id,
        "rule": rule,
        "agent": agent,
        "status": status,
        "risk_score": incident.risk_score,
        "level": incident.level,
        "mitre": mitre,
        "correlation_type": correlation_type,
        "recommended_priority": priority,
        "created_at": _serialize_datetime(getattr(incident, "timestamp", None)),
        "updated_at": _serialize_datetime(getattr(incident, "timestamp", None)),
        "indexed_at": indexed_at_value.isoformat(),
        "redaction_applied": redaction_applied,
        "decision_boundary": HISTORICAL_INCIDENT_DECISION_BOUNDARY,
    }

    return HistoricalIncidentMemory(
        record=SemanticMemoryRecord(
            source_type=HISTORICAL_INCIDENT_SOURCE_TYPE,
            source=f"incident:{incident.id}",
            text=text,
            payload=payload,
        ),
        redaction_applied=redaction_applied,
    )


def should_include_incident(
    incident: Incident,
    *,
    include_open: bool,
    since_days: int | None,
    now: datetime | None = None,
) -> bool:
    if not include_open and safe_text(incident.status).upper() in OPEN_INCIDENT_STATUSES:
        return False

    if since_days is None:
        return True

    timestamp = _parse_incident_timestamp(incident.timestamp)
    if timestamp is None:
        return False

    reference = now or datetime.now(timezone.utc)
    return timestamp >= reference - timedelta(days=max(0, since_days))


def load_historical_incident_memories(
    db,
    *,
    limit: int,
    since_days: int | None,
    include_open: bool,
    now: datetime | None = None,
) -> list[HistoricalIncidentMemory]:
    incidents = db.query(Incident).order_by(Incident.id.desc()).limit(max(1, limit)).all()
    memories: list[HistoricalIncidentMemory] = []

    for incident in incidents:
        if not should_include_incident(
            incident,
            include_open=include_open,
            since_days=since_days,
            now=now,
        ):
            continue

        case_link = (
            db.query(CaseIncident)
            .filter(CaseIncident.incident_id == incident.id)
            .order_by(CaseIncident.id.desc())
            .first()
        )
        case = None
        closure = None

        if case_link:
            case = db.query(IncidentCase).filter(IncidentCase.id == case_link.case_id).first()
            closure = (
                db.query(CaseClosureChecklist)
                .filter(CaseClosureChecklist.case_id == case_link.case_id)
                .first()
            )

        notes = (
            db.query(IncidentNote)
            .filter(IncidentNote.incident_id == incident.id)
            .order_by(IncidentNote.created_at.desc())
            .limit(5)
            .all()
        )

        memories.append(build_historical_incident_memory(incident, case=case, closure=closure, notes=notes))

    return memories


def run_indexing(
    *,
    limit: int,
    since_days: int | None,
    include_open: bool,
    apply: bool,
    db_factory=SessionLocal,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    db = db_factory()

    try:
        memories = load_historical_incident_memories(
            db,
            limit=limit,
            since_days=since_days,
            include_open=include_open,
        )
    finally:
        db.close()

    records = [memory.record for memory in memories]
    redacted = sum(1 for memory in memories if memory.redaction_applied)
    result = {
        "mode": "apply" if apply else "dry-run",
        "source_type": HISTORICAL_INCIDENT_SOURCE_TYPE,
        "records_prepared": len(records),
        "redaction_applied_count": redacted,
        "indexed_points": 0,
        "collection": None,
        "decision_boundary": HISTORICAL_INCIDENT_DECISION_BOUNDARY,
    }

    if apply and records:
        upsert_result = knowledge_base_factory().index_memory_records(records)
        result["indexed_points"] = upsert_result.get("indexed_points", 0)
        result["collection"] = upsert_result.get("collection")

    return result


def main() -> None:
    args = parse_args()
    apply = bool(args.apply)

    result = run_indexing(
        limit=args.limit,
        since_days=args.since_days,
        include_open=args.include_open,
        apply=apply,
    )

    print(
        "Historical incident semantic memory {mode}: prepared={records_prepared}, "
        "indexed={indexed_points}, redacted={redaction_applied_count}, "
        "source_type={source_type}.".format(**result)
    )
    print(f"Decision boundary: {result['decision_boundary']}")


if __name__ == "__main__":
    main()
