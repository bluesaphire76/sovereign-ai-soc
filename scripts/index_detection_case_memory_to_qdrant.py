from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ai_provider_redaction import RedactionOptions, redact_text
from database import SessionLocal
from investigation_ai.adapters import safe_text
from models import (
    CaseAction,
    CaseClosureChecklist,
    CaseIncident,
    DetectionControlRule,
    IncidentCase,
)
from qdrant_knowledge import (
    SEMANTIC_MEMORY_DECISION_BOUNDARY,
    QdrantKnowledgeBase,
    SemanticMemoryRecord,
    stable_memory_point_id,
)


DETECTION_CONTROL_SOURCE_TYPE = "detection_control"
CASE_CLOSURE_SOURCE_TYPE = "case_closure"
CASE_CLOSURE_FINAL_STATUSES = {"CLOSED", "RESOLVED", "FALSE_POSITIVE"}
DETECTION_CASE_DECISION_BOUNDARY = (
    "Detection control and case closure semantic memory is advisory only. "
    "It may support analyst review, tuning rationale, case comparison and "
    "closure quality checks, but it must not create, approve, apply, disable "
    "or delete detection controls, close cases, set final severity, suppress "
    "alerts or replace deterministic RBAC, audit and human review."
)


@dataclass(frozen=True)
class DetectionCaseMemory:
    record: SemanticMemoryRecord
    redaction_applied: bool


@dataclass(frozen=True)
class DetectionCaseMemoryLoad:
    memories: list[DetectionCaseMemory]
    detection_control_rows_scanned: int
    case_closure_rows_scanned: int
    case_closure_skipped_non_final: int


@dataclass(frozen=True)
class QdrantMemoryPoint:
    point_id: str
    payload: dict[str, Any]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Index safe Detection Control and Case Closure memory into Qdrant."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=1000,
        help="Maximum rows to scan per domain.",
    )
    parser.add_argument(
        "--skip-detection-control",
        action="store_true",
        help="Do not index Detection Control rules.",
    )
    parser.add_argument(
        "--skip-case-closure",
        action="store_true",
        help="Do not index Case Closure records.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write generated records to Qdrant.",
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


def _normalized_status(value: Any) -> str:
    return safe_text(value).strip().upper()


def should_include_case_closure(
    closure: CaseClosureChecklist,
    case: IncidentCase | None,
) -> bool:
    if bool(closure.closure_approved):
        return True
    return _normalized_status(getattr(case, "status", None)) in CASE_CLOSURE_FINAL_STATUSES


def build_detection_control_memory(
    rule: DetectionControlRule,
    *,
    indexed_at: datetime | None = None,
) -> DetectionCaseMemory:
    name, name_redacted = _safe_memory_text(rule.name, max_chars=220)
    description, description_redacted = _safe_memory_text(rule.description, max_chars=500)
    matcher, matcher_redacted = _safe_memory_text(rule.matcher_value, max_chars=500)
    reason, reason_redacted = _safe_memory_text(rule.reason, max_chars=700)
    owner, owner_redacted = _safe_memory_text(rule.owner, max_chars=120)
    validation_message, validation_redacted = _safe_memory_text(
        rule.last_validation_message,
        max_chars=500,
    )
    indexed_at_value = indexed_at or datetime.now(timezone.utc)

    lines = [
        "Detection Control Semantic Memory",
        f"Rule ID: {rule.id}",
        f"Rule Type: {rule.rule_type}",
        f"Name: {name}",
        f"Description: {description}",
        f"Status: {rule.status}",
        f"Enabled: {bool(rule.enabled)}",
        f"Scope: {rule.scope}",
        f"Matcher Kind: {rule.matcher_kind}",
        f"Matcher Value: {matcher}",
        f"Reason: {reason}",
        f"Owner: {owner}",
        f"Validation Status: {rule.last_validation_status}",
        f"Validation Message: {validation_message}",
        f"Decision Boundary: {DETECTION_CASE_DECISION_BOUNDARY}",
        f"Semantic Memory Boundary: {SEMANTIC_MEMORY_DECISION_BOUNDARY}",
    ]

    redaction_applied = any(
        [
            name_redacted,
            description_redacted,
            matcher_redacted,
            reason_redacted,
            owner_redacted,
            validation_redacted,
        ]
    )

    payload = {
        "source_type": DETECTION_CONTROL_SOURCE_TYPE,
        "source": f"detection_control:{rule.id}",
        "rule_id": rule.id,
        "rule_type": rule.rule_type,
        "name": name,
        "status": rule.status,
        "enabled": bool(rule.enabled),
        "scope": rule.scope,
        "matcher_kind": rule.matcher_kind,
        "owner": owner,
        "last_validation_status": rule.last_validation_status,
        "created_at": _serialize_datetime(rule.created_at),
        "updated_at": _serialize_datetime(rule.updated_at),
        "indexed_at": indexed_at_value.isoformat(),
        "redaction_applied": redaction_applied,
        "decision_boundary": DETECTION_CASE_DECISION_BOUNDARY,
    }

    return DetectionCaseMemory(
        record=SemanticMemoryRecord(
            source_type=DETECTION_CONTROL_SOURCE_TYPE,
            source=f"detection_control:{rule.id}",
            text="\n".join(line for line in lines if safe_text(line)),
            payload=payload,
        ),
        redaction_applied=redaction_applied,
    )


def _case_actions_summary(actions: list[CaseAction]) -> tuple[str, bool]:
    if not actions:
        return "No case action summary available.", False

    lines = [
        (
            f"{action.category}: {action.title}; status={action.status}; "
            f"priority={action.priority}; description={action.description}"
        )
        for action in actions[:8]
    ]
    return _safe_memory_text("\n".join(lines), max_chars=1200)


def build_case_closure_memory(
    closure: CaseClosureChecklist,
    *,
    case: IncidentCase | None = None,
    incident_count: int = 0,
    actions: list[CaseAction] | None = None,
    indexed_at: datetime | None = None,
) -> DetectionCaseMemory:
    case_title, title_redacted = _safe_memory_text(getattr(case, "title", None), max_chars=260)
    case_summary, summary_redacted = _safe_memory_text(getattr(case, "summary", None), max_chars=700)
    root_cause, root_redacted = _safe_memory_text(closure.root_cause, max_chars=700)
    evidence, evidence_redacted = _safe_memory_text(closure.evidence_reviewed, max_chars=900)
    actions_summary, closure_actions_redacted = _safe_memory_text(
        closure.actions_summary,
        max_chars=900,
    )
    closure_reason, reason_redacted = _safe_memory_text(closure.closure_reason, max_chars=700)
    residual_risk, risk_redacted = _safe_memory_text(closure.residual_risk, max_chars=700)
    action_text, action_redacted = _case_actions_summary(actions or [])
    indexed_at_value = indexed_at or datetime.now(timezone.utc)

    lines = [
        "Case Closure Semantic Memory",
        f"Case ID: {closure.case_id}",
        f"Case Title: {case_title}",
        f"Case Status: {getattr(case, 'status', None)}",
        f"Case Severity: {getattr(case, 'severity', None)}",
        f"Case Risk Score: {getattr(case, 'risk_score', None)}",
        f"Linked Incidents: {incident_count}",
        f"Case Summary: {case_summary}",
        f"Closure Decision: {closure.closure_decision}",
        f"Final Severity: {closure.final_severity}",
        f"Closure Approved: {bool(closure.closure_approved)}",
        f"Closure Reason: {closure_reason}",
        f"Root Cause: {root_cause}",
        f"Evidence Reviewed: {evidence}",
        f"Actions Summary: {actions_summary}",
        f"Residual Risk: {residual_risk}",
        f"Case Action Context: {action_text}",
        f"Decision Boundary: {DETECTION_CASE_DECISION_BOUNDARY}",
        f"Semantic Memory Boundary: {SEMANTIC_MEMORY_DECISION_BOUNDARY}",
    ]

    redaction_applied = any(
        [
            title_redacted,
            summary_redacted,
            root_redacted,
            evidence_redacted,
            closure_actions_redacted,
            reason_redacted,
            risk_redacted,
            action_redacted,
        ]
    )

    payload = {
        "source_type": CASE_CLOSURE_SOURCE_TYPE,
        "source": f"case_closure:{closure.case_id}",
        "case_id": closure.case_id,
        "case_title": case_title,
        "case_status": getattr(case, "status", None),
        "case_severity": getattr(case, "severity", None),
        "closure_decision": closure.closure_decision,
        "final_severity": closure.final_severity,
        "closure_approved": bool(closure.closure_approved),
        "incident_count": incident_count,
        "created_at": _serialize_datetime(closure.created_at),
        "updated_at": _serialize_datetime(closure.updated_at),
        "indexed_at": indexed_at_value.isoformat(),
        "redaction_applied": redaction_applied,
        "decision_boundary": DETECTION_CASE_DECISION_BOUNDARY,
    }

    return DetectionCaseMemory(
        record=SemanticMemoryRecord(
            source_type=CASE_CLOSURE_SOURCE_TYPE,
            source=f"case_closure:{closure.case_id}",
            text="\n".join(line for line in lines if safe_text(line)),
            payload=payload,
        ),
        redaction_applied=redaction_applied,
    )


def load_detection_case_memories(
    db,
    *,
    limit: int,
    include_detection_control: bool,
    include_case_closure: bool,
) -> DetectionCaseMemoryLoad:
    memories: list[DetectionCaseMemory] = []
    resolved_limit = max(1, limit)
    detection_rows_scanned = 0
    closure_rows_scanned = 0
    closure_skipped_non_final = 0

    if include_detection_control:
        rules = (
            db.query(DetectionControlRule)
            .filter(DetectionControlRule.deleted_at.is_(None))
            .order_by(DetectionControlRule.updated_at.desc(), DetectionControlRule.name.asc())
            .limit(resolved_limit)
            .all()
        )
        detection_rows_scanned = len(rules)
        memories.extend(build_detection_control_memory(rule) for rule in rules)

    if include_case_closure:
        closures = (
            db.query(CaseClosureChecklist)
            .order_by(CaseClosureChecklist.updated_at.desc(), CaseClosureChecklist.case_id.desc())
            .limit(resolved_limit)
            .all()
        )
        closure_rows_scanned = len(closures)

        for closure in closures:
            case = (
                db.query(IncidentCase)
                .filter(IncidentCase.id == closure.case_id)
                .first()
            )
            if not should_include_case_closure(closure, case):
                closure_skipped_non_final += 1
                continue

            incident_count = (
                db.query(CaseIncident)
                .filter(CaseIncident.case_id == closure.case_id)
                .count()
            )
            actions = (
                db.query(CaseAction)
                .filter(CaseAction.case_id == closure.case_id)
                .order_by(CaseAction.updated_at.desc(), CaseAction.id.desc())
                .limit(8)
                .all()
            )
            memories.append(
                build_case_closure_memory(
                    closure,
                    case=case,
                    incident_count=incident_count,
                    actions=actions,
                )
            )

    return DetectionCaseMemoryLoad(
        memories=memories,
        detection_control_rows_scanned=detection_rows_scanned,
        case_closure_rows_scanned=closure_rows_scanned,
        case_closure_skipped_non_final=closure_skipped_non_final,
    )


def _source_type_filter(source_type: str):
    from qdrant_client.models import FieldCondition, Filter, MatchValue

    return Filter(
        must=[
            FieldCondition(
                key="source_type",
                match=MatchValue(value=source_type),
            )
        ]
    )


def _expected_point_ids(records: list[SemanticMemoryRecord]) -> set[str]:
    point_ids: set[str] = set()
    for record in records:
        text = safe_text(record.text)
        source_type = safe_text(record.source_type)
        source = safe_text(record.source)
        if not text or not source_type or not source:
            continue
        content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        point_ids.add(stable_memory_point_id(source_type, source, content_hash))
    return point_ids


def scroll_memory_points_by_source_type(
    client,
    *,
    collection_name: str,
    source_type: str,
    max_records: int,
) -> list[QdrantMemoryPoint]:
    points: list[QdrantMemoryPoint] = []
    next_offset: Any = None

    while len(points) < max_records:
        batch_limit = min(250, max_records - len(points))
        batch, next_offset = client.scroll(
            collection_name=collection_name,
            scroll_filter=_source_type_filter(source_type),
            limit=batch_limit,
            offset=next_offset,
            with_payload=True,
            with_vectors=False,
        )

        if not batch:
            break

        for point in batch:
            payload = dict(getattr(point, "payload", None) or {})
            if safe_text(payload.get("source_type")) != source_type:
                continue
            points.append(
                QdrantMemoryPoint(
                    point_id=str(getattr(point, "id", "")),
                    payload=payload,
                )
            )

        if next_offset is None:
            break

    return points


def prune_stale_source_type_points(
    kb: QdrantKnowledgeBase,
    *,
    source_type: str,
    expected_point_ids: set[str],
    max_records: int,
    apply: bool,
) -> dict[str, int]:
    points = scroll_memory_points_by_source_type(
        kb.client,
        collection_name=kb.config.collection_name,
        source_type=source_type,
        max_records=max(1, max_records),
    )
    stale_point_ids = [
        point.point_id
        for point in points
        if point.point_id and point.point_id not in expected_point_ids
    ]

    if apply and stale_point_ids:
        kb.client.delete(
            collection_name=kb.config.collection_name,
            points_selector=stale_point_ids,
            wait=True,
        )

    return {
        "scanned": len(points),
        "candidates": len(stale_point_ids),
        "deleted": len(stale_point_ids) if apply else 0,
    }


def run_indexing(
    *,
    limit: int,
    include_detection_control: bool,
    include_case_closure: bool,
    apply: bool,
    db_factory=SessionLocal,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    db = db_factory()
    try:
        load_result = load_detection_case_memories(
            db,
            limit=limit,
            include_detection_control=include_detection_control,
            include_case_closure=include_case_closure,
        )
    finally:
        db.close()

    memories = load_result.memories
    records = [memory.record for memory in memories]
    detection_records = sum(1 for record in records if record.source_type == DETECTION_CONTROL_SOURCE_TYPE)
    closure_records = sum(1 for record in records if record.source_type == CASE_CLOSURE_SOURCE_TYPE)
    redacted = sum(1 for memory in memories if memory.redaction_applied)
    resolved_limit = max(1, limit)
    result = {
        "mode": "apply" if apply else "dry-run",
        "source_types": [DETECTION_CONTROL_SOURCE_TYPE, CASE_CLOSURE_SOURCE_TYPE],
        "records_prepared": len(records),
        "detection_control_records": detection_records,
        "case_closure_records": closure_records,
        "detection_control_rows_scanned": load_result.detection_control_rows_scanned,
        "case_closure_rows_scanned": load_result.case_closure_rows_scanned,
        "case_closure_skipped_non_final": load_result.case_closure_skipped_non_final,
        "redaction_applied_count": redacted,
        "indexed_points": 0,
        "pruned_points": 0,
        "prune_skipped_reason": None,
        "collection": None,
        "decision_boundary": DETECTION_CASE_DECISION_BOUNDARY,
    }

    if apply:
        kb = knowledge_base_factory()
        if records:
            upsert_result = kb.index_memory_records(records)
            result["indexed_points"] = upsert_result.get("indexed_points", 0)
            result["collection"] = upsert_result.get("collection")
        else:
            result["collection"] = kb.config.collection_name

        prune_results: dict[str, dict[str, int]] = {}
        expected_by_type = {
            source_type: _expected_point_ids(
                [record for record in records if record.source_type == source_type]
            )
            for source_type in [DETECTION_CONTROL_SOURCE_TYPE, CASE_CLOSURE_SOURCE_TYPE]
        }

        if include_detection_control and load_result.detection_control_rows_scanned < resolved_limit:
            prune_results[DETECTION_CONTROL_SOURCE_TYPE] = prune_stale_source_type_points(
                kb,
                source_type=DETECTION_CONTROL_SOURCE_TYPE,
                expected_point_ids=expected_by_type[DETECTION_CONTROL_SOURCE_TYPE],
                max_records=50000,
                apply=True,
            )
        elif include_detection_control:
            result["prune_skipped_reason"] = "detection_control_limit_reached"

        if include_case_closure and load_result.case_closure_rows_scanned < resolved_limit:
            prune_results[CASE_CLOSURE_SOURCE_TYPE] = prune_stale_source_type_points(
                kb,
                source_type=CASE_CLOSURE_SOURCE_TYPE,
                expected_point_ids=expected_by_type[CASE_CLOSURE_SOURCE_TYPE],
                max_records=50000,
                apply=True,
            )
        elif include_case_closure:
            result["prune_skipped_reason"] = "case_closure_limit_reached"

        for source_type, prune_result in prune_results.items():
            result[f"{source_type}_prune_candidates"] = prune_result["candidates"]
            result[f"{source_type}_pruned"] = prune_result["deleted"]
            result["pruned_points"] += prune_result["deleted"]

    return result


def main() -> None:
    args = parse_args()
    result = run_indexing(
        limit=args.limit,
        include_detection_control=not args.skip_detection_control,
        include_case_closure=not args.skip_case_closure,
        apply=bool(args.apply),
    )

    print(
        "Detection/case semantic memory {mode}: prepared={records_prepared}, "
        "indexed={indexed_points}, detection_control={detection_control_records}, "
        "case_closure={case_closure_records}, skipped_non_final={case_closure_skipped_non_final}, "
        "pruned={pruned_points}, redacted={redaction_applied_count}.".format(
            **result
        )
    )
    print(f"Decision boundary: {result['decision_boundary']}")


if __name__ == "__main__":
    main()
