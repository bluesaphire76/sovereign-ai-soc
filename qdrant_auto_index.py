from __future__ import annotations

import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from database import SessionLocal
from investigation_ai.adapters import safe_text
from models import (
    CaseAction,
    CaseClosureChecklist,
    CaseIncident,
    DetectionControlRule,
    Incident,
    IncidentCase,
    IncidentNote,
)
from qdrant_knowledge import QdrantKnowledgeBase, SemanticMemoryRecord, config_from_env
from scripts.index_detection_case_memory_to_qdrant import (
    CASE_CLOSURE_SOURCE_TYPE,
    DETECTION_CONTROL_SOURCE_TYPE,
    build_case_closure_memory,
    build_detection_control_memory,
    should_include_case_closure,
)
from scripts.index_historical_incidents_to_qdrant import (
    HISTORICAL_INCIDENT_SOURCE_TYPE,
    build_historical_incident_memory,
    should_include_incident,
)


logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent
STATE_VERSION = "v0.7.0-auto-index"
RECENT_EVENT_LIMIT = 30
AUTO_INDEX_DECISION_BOUNDARY = (
    "Automatic Qdrant indexing refreshes advisory semantic memory only. It must "
    "not make or change incident status, severity, deduplication, suppression, "
    "case closure, Detection Control approval or any other SOC decision."
)

_STATE_LOCK = threading.Lock()
_EXECUTOR_LOCK = threading.Lock()
_EXECUTOR: ThreadPoolExecutor | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int = 32) -> int:
    try:
        return max(minimum, min(maximum, int(os.getenv(name, str(default)))))
    except ValueError:
        return default


def auto_index_config() -> dict[str, Any]:
    qdrant_config = config_from_env()
    configured_enabled = _env_bool("QDRANT_AUTO_INDEX_ENABLED", True)
    semantic_memory_enabled = bool(qdrant_config.enabled)
    return {
        "configured_enabled": configured_enabled,
        "semantic_memory_enabled": semantic_memory_enabled,
        "enabled": configured_enabled and semantic_memory_enabled,
        "async_enabled": _env_bool("QDRANT_AUTO_INDEX_ASYNC", True),
        "include_open_incidents": _env_bool("QDRANT_AUTO_INDEX_INCLUDE_OPEN_INCIDENTS", True),
        "max_workers": _env_int("QDRANT_AUTO_INDEX_WORKERS", 1, minimum=1, maximum=4),
        "state_path": str(_state_path()),
        "collection": qdrant_config.collection_name,
        "decision_boundary": AUTO_INDEX_DECISION_BOUNDARY,
    }


def _state_path() -> Path:
    configured = os.getenv("QDRANT_AUTO_INDEX_STATE_PATH")
    if configured:
        return Path(configured)
    return PROJECT_ROOT / ".runtime" / "qdrant_auto_index_state.json"


def _empty_source_state() -> dict[str, Any]:
    return {
        "last_attempt_at": None,
        "last_success_at": None,
        "last_error_at": None,
        "last_source": None,
        "last_reason": None,
        "last_status": None,
        "last_result": None,
        "last_error": None,
        "success_count": 0,
        "failure_count": 0,
        "skipped_count": 0,
    }


def _default_state() -> dict[str, Any]:
    return {
        "version": STATE_VERSION,
        "last_updated_at": None,
        "last_attempt_at": None,
        "last_success_at": None,
        "last_error_at": None,
        "last_error": None,
        "pending_operations": 0,
        "success_count": 0,
        "failure_count": 0,
        "skipped_count": 0,
        "source_types": {
            HISTORICAL_INCIDENT_SOURCE_TYPE: _empty_source_state(),
            DETECTION_CONTROL_SOURCE_TYPE: _empty_source_state(),
            CASE_CLOSURE_SOURCE_TYPE: _empty_source_state(),
        },
        "recent_events": [],
    }


def _read_state_unlocked() -> dict[str, Any]:
    path = _state_path()
    if not path.exists():
        return _default_state()

    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _default_state()

    state = _default_state()
    if isinstance(loaded, dict):
        state.update(loaded)

    source_types = state.setdefault("source_types", {})
    for source_type in [
        HISTORICAL_INCIDENT_SOURCE_TYPE,
        DETECTION_CONTROL_SOURCE_TYPE,
        CASE_CLOSURE_SOURCE_TYPE,
    ]:
        existing = source_types.get(source_type)
        source_state = _empty_source_state()
        if isinstance(existing, dict):
            source_state.update(existing)
        source_types[source_type] = source_state

    if not isinstance(state.get("recent_events"), list):
        state["recent_events"] = []

    return state


def _write_state_unlocked(state: dict[str, Any]) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    state["version"] = STATE_VERSION
    state["last_updated_at"] = _utc_now()
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")


def _mutate_state(mutator: Callable[[dict[str, Any]], None]) -> None:
    try:
        with _STATE_LOCK:
            state = _read_state_unlocked()
            mutator(state)
            _write_state_unlocked(state)
    except OSError as exc:
        logger.warning(
            "qdrant_auto_index_state_write_failed",
            extra={"error_type": exc.__class__.__name__},
        )


def _append_recent_event(
    state: dict[str, Any],
    *,
    source_type: str,
    source: str,
    status: str,
    reason: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    event = {
        "at": _utc_now(),
        "source_type": source_type,
        "source": source,
        "status": status,
        "reason": reason,
        "result": result or {},
        "error": error,
    }
    events = [event, *(state.get("recent_events") or [])]
    state["recent_events"] = events[:RECENT_EVENT_LIMIT]


def _record_started(source_type: str, source: str, reason: str) -> None:
    def update(state: dict[str, Any]) -> None:
        source_state = state["source_types"].setdefault(source_type, _empty_source_state())
        now = _utc_now()
        state["last_attempt_at"] = now
        state["pending_operations"] = max(0, int(state.get("pending_operations") or 0)) + 1
        source_state["last_attempt_at"] = now
        source_state["last_source"] = source
        source_state["last_reason"] = reason
        source_state["last_status"] = "RUNNING"

    _mutate_state(update)


def _record_finished(
    *,
    source_type: str,
    source: str,
    reason: str,
    status: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    def update(state: dict[str, Any]) -> None:
        source_state = state["source_types"].setdefault(source_type, _empty_source_state())
        pending = max(0, int(state.get("pending_operations") or 0) - 1)
        state["pending_operations"] = pending
        source_state["last_status"] = status
        source_state["last_result"] = result or {}
        source_state["last_error"] = error

        if status == "SUCCESS":
            now = _utc_now()
            state["last_success_at"] = now
            source_state["last_success_at"] = now
            state["success_count"] = int(state.get("success_count") or 0) + 1
            source_state["success_count"] = int(source_state.get("success_count") or 0) + 1
        elif status == "SKIPPED":
            state["skipped_count"] = int(state.get("skipped_count") or 0) + 1
            source_state["skipped_count"] = int(source_state.get("skipped_count") or 0) + 1
        else:
            now = _utc_now()
            state["last_error_at"] = now
            source_state["last_error_at"] = now
            state["last_error"] = error
            state["failure_count"] = int(state.get("failure_count") or 0) + 1
            source_state["failure_count"] = int(source_state.get("failure_count") or 0) + 1

        _append_recent_event(
            state,
            source_type=source_type,
            source=source,
            status=status,
            reason=reason,
            result=result,
            error=error,
        )

    _mutate_state(update)


def get_auto_index_status() -> dict[str, Any]:
    with _STATE_LOCK:
        state = _read_state_unlocked()

    config = auto_index_config()
    return {
        "status": "OK" if config["enabled"] else "DISABLED",
        "mode": "best_effort_async" if config["async_enabled"] else "best_effort_inline",
        "config": config,
        "state": state,
        "decision_boundary": AUTO_INDEX_DECISION_BOUNDARY,
        "message": (
            "Automatic semantic memory indexing is best-effort and advisory-only. "
            "Failures are reported here and do not block SOC write operations."
        ),
    }


def _source_filter(source_type: str, source: str):
    from qdrant_client.models import FieldCondition, Filter, MatchValue

    return Filter(
        must=[
            FieldCondition(key="source_type", match=MatchValue(value=source_type)),
            FieldCondition(key="source", match=MatchValue(value=source)),
        ]
    )


def _delete_existing_source_points(
    kb: QdrantKnowledgeBase,
    *,
    source_type: str,
    source: str,
) -> dict[str, Any]:
    if not kb.config.enabled:
        return {"deleted_points": 0, "skip_reason": "semantic_memory_disabled"}

    if not kb.collection_exists():
        return {"deleted_points": 0, "skip_reason": "collection_missing"}

    point_ids: list[str] = []
    next_offset: Any = None

    while True:
        points, next_offset = kb.client.scroll(
            collection_name=kb.config.collection_name,
            scroll_filter=_source_filter(source_type, source),
            limit=250,
            offset=next_offset,
            with_payload=False,
            with_vectors=False,
        )

        for point in points or []:
            point_id = safe_text(getattr(point, "id", ""))
            if point_id:
                point_ids.append(point_id)

        if not points or next_offset is None:
            break

    if point_ids:
        kb.client.delete(
            collection_name=kb.config.collection_name,
            points_selector=point_ids,
            wait=True,
        )

    return {"deleted_points": len(point_ids)}


def _replace_source_record(
    record: SemanticMemoryRecord,
    *,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    kb = knowledge_base_factory()
    delete_result = _delete_existing_source_points(
        kb,
        source_type=record.source_type,
        source=record.source,
    )
    index_result = kb.index_memory_records([record])
    return {
        **delete_result,
        "indexed_points": index_result.get("indexed_points", 0),
        "collection": index_result.get("collection"),
    }


def _delete_source(
    source_type: str,
    source: str,
    *,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    kb = knowledge_base_factory()
    delete_result = _delete_existing_source_points(
        kb,
        source_type=source_type,
        source=source,
    )
    return {
        **delete_result,
        "indexed_points": 0,
        "collection": kb.config.collection_name,
    }


def _incident_context(db, incident: Incident) -> tuple[IncidentCase | None, CaseClosureChecklist | None]:
    case_link = (
        db.query(CaseIncident)
        .filter(CaseIncident.incident_id == incident.id)
        .order_by(CaseIncident.id.desc())
        .first()
    )
    if not case_link:
        return None, None

    case = db.query(IncidentCase).filter(IncidentCase.id == case_link.case_id).first()
    closure = (
        db.query(CaseClosureChecklist)
        .filter(CaseClosureChecklist.case_id == case_link.case_id)
        .first()
    )
    return case, closure


def _incident_notes(db, incident_id: int) -> list[IncidentNote]:
    return (
        db.query(IncidentNote)
        .filter(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at.desc())
        .limit(5)
        .all()
    )


def index_incident_memory(
    incident_id: int,
    *,
    db_factory=SessionLocal,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    db = db_factory()
    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        source = f"incident:{incident_id}"
        if not incident:
            return _delete_source(
                HISTORICAL_INCIDENT_SOURCE_TYPE,
                source,
                knowledge_base_factory=knowledge_base_factory,
            )

        include_open = auto_index_config()["include_open_incidents"]
        if not should_include_incident(incident, include_open=include_open, since_days=None):
            return {
                **_delete_source(
                    HISTORICAL_INCIDENT_SOURCE_TYPE,
                    source,
                    knowledge_base_factory=knowledge_base_factory,
                ),
                "skip_reason": "incident_status_not_indexable",
            }

        case, closure = _incident_context(db, incident)
        notes = _incident_notes(db, incident.id)
        memory = build_historical_incident_memory(
            incident,
            case=case,
            closure=closure,
            notes=notes,
        )
    finally:
        db.close()

    return _replace_source_record(memory.record, knowledge_base_factory=knowledge_base_factory)


def index_detection_control_memory(
    rule_id: str,
    *,
    db_factory=SessionLocal,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    source = f"detection_control:{rule_id}"
    db = db_factory()
    try:
        rule = db.query(DetectionControlRule).filter(DetectionControlRule.id == rule_id).first()
        if not rule or rule.deleted_at is not None:
            return _delete_source(
                DETECTION_CONTROL_SOURCE_TYPE,
                source,
                knowledge_base_factory=knowledge_base_factory,
            )

        memory = build_detection_control_memory(rule)
    finally:
        db.close()

    return _replace_source_record(memory.record, knowledge_base_factory=knowledge_base_factory)


def index_case_closure_memory(
    case_id: int,
    *,
    db_factory=SessionLocal,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    source = f"case_closure:{case_id}"
    db = db_factory()
    try:
        closure = (
            db.query(CaseClosureChecklist)
            .filter(CaseClosureChecklist.case_id == case_id)
            .first()
        )
        case = db.query(IncidentCase).filter(IncidentCase.id == case_id).first()

        if not closure or not should_include_case_closure(closure, case):
            return {
                **_delete_source(
                    CASE_CLOSURE_SOURCE_TYPE,
                    source,
                    knowledge_base_factory=knowledge_base_factory,
                ),
                "skip_reason": "case_closure_not_final_or_approved",
            }

        incident_count = (
            db.query(CaseIncident)
            .filter(CaseIncident.case_id == case_id)
            .count()
        )
        actions = (
            db.query(CaseAction)
            .filter(CaseAction.case_id == case_id)
            .order_by(CaseAction.updated_at.desc(), CaseAction.id.desc())
            .limit(8)
            .all()
        )
        memory = build_case_closure_memory(
            closure,
            case=case,
            incident_count=incident_count,
            actions=actions,
        )
    finally:
        db.close()

    return _replace_source_record(memory.record, knowledge_base_factory=knowledge_base_factory)


def _run_auto_index_event(
    source_type: str,
    source_id: str | int,
    *,
    reason: str,
    db_factory=SessionLocal,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    config = auto_index_config()
    source = _event_source(source_type, source_id)

    if not config["enabled"]:
        result = {
            "scheduled": False,
            "status": "SKIPPED",
            "skip_reason": "auto_index_disabled",
        }
        _record_finished(
            source_type=source_type,
            source=source,
            reason=reason,
            status="SKIPPED",
            result=result,
        )
        return result

    _record_started(source_type, source, reason)

    try:
        if source_type == HISTORICAL_INCIDENT_SOURCE_TYPE:
            result = index_incident_memory(
                int(source_id),
                db_factory=db_factory,
                knowledge_base_factory=knowledge_base_factory,
            )
        elif source_type == DETECTION_CONTROL_SOURCE_TYPE:
            result = index_detection_control_memory(
                str(source_id),
                db_factory=db_factory,
                knowledge_base_factory=knowledge_base_factory,
            )
        elif source_type == CASE_CLOSURE_SOURCE_TYPE:
            result = index_case_closure_memory(
                int(source_id),
                db_factory=db_factory,
                knowledge_base_factory=knowledge_base_factory,
            )
        else:
            result = {"skip_reason": "unsupported_source_type", "indexed_points": 0}

        status = "SKIPPED" if result.get("skip_reason") else "SUCCESS"
        _record_finished(
            source_type=source_type,
            source=source,
            reason=reason,
            status=status,
            result=result,
        )
        return {"scheduled": False, "status": status, **result}
    except Exception as exc:
        logger.warning(
            "qdrant_auto_index_failed",
            extra={
                "source_type": source_type,
                "source": source,
                "reason": reason,
                "error_type": exc.__class__.__name__,
            },
        )
        _record_finished(
            source_type=source_type,
            source=source,
            reason=reason,
            status="ERROR",
            error=exc.__class__.__name__,
        )
        return {
            "scheduled": False,
            "status": "ERROR",
            "error_type": exc.__class__.__name__,
        }


def _event_source(source_type: str, source_id: str | int) -> str:
    if source_type == HISTORICAL_INCIDENT_SOURCE_TYPE:
        return f"incident:{source_id}"
    if source_type == DETECTION_CONTROL_SOURCE_TYPE:
        return f"detection_control:{source_id}"
    if source_type == CASE_CLOSURE_SOURCE_TYPE:
        return f"case_closure:{source_id}"
    return f"{source_type}:{source_id}"


def _executor() -> ThreadPoolExecutor:
    global _EXECUTOR
    with _EXECUTOR_LOCK:
        config = auto_index_config()
        if _EXECUTOR is None:
            _EXECUTOR = ThreadPoolExecutor(
                max_workers=config["max_workers"],
                thread_name_prefix="qdrant-auto-index",
            )
        return _EXECUTOR


def schedule_auto_index_event(
    source_type: str,
    source_id: str | int,
    *,
    reason: str,
    async_enabled: bool | None = None,
) -> dict[str, Any]:
    config = auto_index_config()
    use_async = config["async_enabled"] if async_enabled is None else async_enabled

    if not config["enabled"]:
        return _run_auto_index_event(source_type, source_id, reason=reason)

    if not use_async:
        return _run_auto_index_event(source_type, source_id, reason=reason)

    try:
        _executor().submit(
            _run_auto_index_event,
            source_type,
            source_id,
            reason=reason,
        )
        return {
            "scheduled": True,
            "status": "QUEUED",
            "source_type": source_type,
            "source": _event_source(source_type, source_id),
            "reason": reason,
            "decision_boundary": AUTO_INDEX_DECISION_BOUNDARY,
        }
    except Exception as exc:
        logger.warning(
            "qdrant_auto_index_schedule_failed",
            extra={
                "source_type": source_type,
                "source": _event_source(source_type, source_id),
                "reason": reason,
                "error_type": exc.__class__.__name__,
            },
        )
        return {
            "scheduled": False,
            "status": "ERROR",
            "error_type": exc.__class__.__name__,
            "decision_boundary": AUTO_INDEX_DECISION_BOUNDARY,
        }


def schedule_incident_auto_index(
    incident_id: int,
    *,
    reason: str,
    async_enabled: bool | None = None,
) -> dict[str, Any]:
    return schedule_auto_index_event(
        HISTORICAL_INCIDENT_SOURCE_TYPE,
        incident_id,
        reason=reason,
        async_enabled=async_enabled,
    )


def schedule_detection_control_auto_index(
    rule_id: str,
    *,
    reason: str,
    async_enabled: bool | None = None,
) -> dict[str, Any]:
    return schedule_auto_index_event(
        DETECTION_CONTROL_SOURCE_TYPE,
        rule_id,
        reason=reason,
        async_enabled=async_enabled,
    )


def schedule_case_closure_auto_index(
    case_id: int,
    *,
    reason: str,
    async_enabled: bool | None = None,
) -> dict[str, Any]:
    return schedule_auto_index_event(
        CASE_CLOSURE_SOURCE_TYPE,
        case_id,
        reason=reason,
        async_enabled=async_enabled,
    )
