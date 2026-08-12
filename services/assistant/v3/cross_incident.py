from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Mapping

from sqlalchemy import or_

from models import CaseIncident, Incident
from services.assistant.v3.contracts import (
    ContextLimits,
    DiscoverySignal,
    IncidentCandidate,
)
from services.assistant.v3.authorization import (
    IncidentAccessPolicy,
    get_incident_access_policy,
)
from services.assistant.v3.semantic_index import incident_source_fingerprint


_SIGNAL_WEIGHTS = {
    DiscoverySignal.EXPLICIT_SELECTION: 6.0,
    DiscoverySignal.SAME_CASE: 5.0,
    DiscoverySignal.SHARED_HOST: 4.0,
    DiscoverySignal.SHARED_AGENT: 4.0,
    DiscoverySignal.SHARED_USER: 4.0,
    DiscoverySignal.SHARED_OBSERVABLE: 4.0,
    DiscoverySignal.SHARED_RULE: 3.0,
    DiscoverySignal.SHARED_MITRE: 2.5,
    DiscoverySignal.SHARED_DETECTION_FAMILY: 2.5,
    DiscoverySignal.SHARED_EVENT_FAMILY: 2.5,
    DiscoverySignal.SHARED_CORRELATION_TYPE: 1.5,
    DiscoverySignal.TEMPORAL_PROXIMITY: 0.5,
    DiscoverySignal.SEMANTIC_SIMILARITY: 0.0,
}


@dataclass(frozen=True)
class SemanticIncidentHit:
    incident_id: int
    score: float | None = None
    source_fingerprint: str | None = None


@dataclass(frozen=True)
class RehydratedIncident:
    incident_id: int
    facts: dict[str, Any]


@dataclass(frozen=True)
class CandidateRetrievalResult:
    candidates: tuple[IncidentCandidate, ...]
    incidents: tuple[RehydratedIncident, ...]
    candidate_retrieval_ms: float
    authoritative_rehydration_ms: float
    discovered_count: int
    rehydrated_count: int = 0
    stale_reject_count: int = 0


def _strict_mitre(value: Any) -> list[dict[str, str | None]]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return []
    values = value if isinstance(value, list) else [value]
    result: list[dict[str, str | None]] = []
    for item in values:
        if isinstance(item, str):
            identifier = item.strip().upper()
            base, separator, subtechnique = identifier.partition(".")
            valid = (
                len(base) == 5
                and base.startswith("T")
                and base[1:].isdigit()
                and (not separator or (len(subtechnique) == 3 and subtechnique.isdigit()))
            )
            if valid:
                result.append({"id": identifier, "name": None})
            continue
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("id") or item.get("technique_id") or "").strip() or None
        name = str(item.get("name") or item.get("label") or "").strip() or None
        if technique_id or name:
            result.append({"id": technique_id, "name": name})
    return result[:12]


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _row_facts(row: Incident, linked_case_ids: list[int]) -> dict[str, Any]:
    return {
        "source_type": "incident",
        "incident_id": row.id,
        "status": row.status,
        "severity": None,
        "timestamp": row.timestamp,
        "agent": row.agent,
        "rule": row.rule,
        "wazuh_level": row.level,
        "risk_score": row.risk_score,
        "mitre": _strict_mitre(row.mitre),
        "correlated": row.correlated,
        "correlation_type": row.correlation_type,
        "correlation_score": row.correlation_score,
        "recommended_priority": row.recommended_priority,
        "linked_case_ids": linked_case_ids,
        "compromise_confirmed": None,
    }


def semantic_incident_hits(sources: Iterable[Any]) -> list[SemanticIncidentHit]:
    hits: list[SemanticIncidentHit] = []
    seen: set[int] = set()
    for source in sources:
        if getattr(source, "source_type", None) != "historical_incident":
            continue
        try:
            incident_id = int(getattr(source, "record_id", None))
        except (TypeError, ValueError):
            continue
        if incident_id <= 0 or incident_id in seen:
            continue
        seen.add(incident_id)
        raw_score = getattr(source, "score", None)
        score = float(raw_score) if isinstance(raw_score, (int, float)) else None
        if score is not None:
            score = max(-1.0, min(1.0, score))
        hits.append(SemanticIncidentHit(incident_id=incident_id, score=score))
    return hits


class CrossIncidentCandidateRetriever:
    def __init__(
        self,
        *,
        access_policy: IncidentAccessPolicy | None = None,
    ) -> None:
        self._access_policy = access_policy or get_incident_access_policy()

    def retrieve(
        self,
        *,
        db: Any,
        anchor_facts: dict[str, Any],
        semantic_hits: Iterable[SemanticIncidentHit],
        explicit_incident_ids: Iterable[int] = (),
        limits: ContextLimits,
        current_user: Mapping[str, Any] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> CandidateRetrievalResult:
        started = clock()
        anchor_id = anchor_facts.get("incident_id")
        if not isinstance(anchor_id, int):
            return CandidateRetrievalResult((), (), 0.0, 0.0, 0)
        semantic_by_id = {
            hit.incident_id: hit
            for hit in semantic_hits
            if hit.incident_id != anchor_id
        }
        explicit_ordered = list(
            dict.fromkeys(
                value
                for value in explicit_incident_ids
                if isinstance(value, int) and value > 0 and value != anchor_id
            )
        )
        explicit_ids = set(explicit_ordered)
        pool_limit = min(500, limits.max_candidates_discovered * 5)
        anchor_case_ids = [
            value
            for value in anchor_facts.get("linked_case_ids", [])
            if isinstance(value, int) and value > 0
        ]
        exact_conditions = []
        if anchor_facts.get("agent"):
            exact_conditions.append(Incident.agent == anchor_facts["agent"])
        if anchor_facts.get("rule"):
            exact_conditions.append(Incident.rule == anchor_facts["rule"])
        if anchor_facts.get("correlation_type"):
            exact_conditions.append(
                Incident.correlation_type == anchor_facts["correlation_type"]
            )
        try:
            recent_rows = (
                db.query(Incident)
                .filter(Incident.id != anchor_id)
                .order_by(Incident.id.desc())
                .limit(pool_limit)
                .all()
            )
            exact_rows = (
                db.query(Incident)
                .filter(Incident.id != anchor_id, or_(*exact_conditions))
                .order_by(Incident.id.desc())
                .limit(pool_limit)
                .all()
                if exact_conditions
                else []
            )
            same_case_rows = []
            if anchor_case_ids:
                linked_ids = [
                    row.incident_id
                    for row in (
                        db.query(CaseIncident)
                        .filter(CaseIncident.case_id.in_(anchor_case_ids))
                        .limit(pool_limit)
                        .all()
                    )
                    if row.incident_id != anchor_id
                ]
                if linked_ids:
                    same_case_rows = (
                        db.query(Incident).filter(Incident.id.in_(linked_ids)).all()
                    )
        except Exception:
            return CandidateRetrievalResult(
                (), (), max(0.0, (clock() - started) * 1000), 0.0, 0
            )
        pool_by_id = {
            row.id: row
            for row in [*exact_rows, *same_case_rows, *recent_rows]
            if self._access_policy.can_read_incident(
                row,
                current_user=current_user,
            )
        }
        rehydration_started = clock()
        missing_candidate_ids = [
            incident_id
            for incident_id in [*explicit_ordered, *semantic_by_id]
            if incident_id not in pool_by_id
        ][: limits.max_candidates_discovered]
        if missing_candidate_ids:
            rows = db.query(Incident).filter(Incident.id.in_(missing_candidate_ids)).all()
            pool_by_id.update(
                {
                    row.id: row
                    for row in rows
                    if self._access_policy.can_read_incident(
                        row,
                        current_user=current_user,
                    )
                }
            )

        all_ids = [anchor_id, *pool_by_id]
        case_ids_by_incident: dict[int, list[int]] = {incident_id: [] for incident_id in all_ids}
        try:
            case_rows = (
                db.query(CaseIncident)
                .filter(CaseIncident.incident_id.in_(all_ids))
                .all()
            )
        except Exception:
            case_rows = []
        for row in case_rows:
            case_ids_by_incident.setdefault(row.incident_id, []).append(row.case_id)
        rehydration_ms = max(0.0, (clock() - rehydration_started) * 1000)

        anchor_cases = set(
            value
            for value in anchor_facts.get("linked_case_ids", [])
            if isinstance(value, int)
        ) | set(case_ids_by_incident.get(anchor_id, []))
        anchor_mitre = {
            str(item.get("id") or item.get("name"))
            for item in anchor_facts.get("mitre", [])
            if isinstance(item, dict) and (item.get("id") or item.get("name"))
        }
        anchor_time = _timestamp(anchor_facts.get("timestamp"))
        ranked: list[tuple[IncidentCandidate, RehydratedIncident]] = []
        stale_reject_count = 0
        for candidate_id, row in pool_by_id.items():
            candidate_facts = _row_facts(row, sorted(set(case_ids_by_incident.get(candidate_id, []))))
            signals: list[DiscoverySignal] = []
            if candidate_id in explicit_ids:
                signals.append(DiscoverySignal.EXPLICIT_SELECTION)
            if anchor_facts.get("agent") and row.agent == anchor_facts.get("agent"):
                signals.append(DiscoverySignal.SHARED_AGENT)
            if anchor_facts.get("host") and candidate_facts.get("host") == anchor_facts.get("host"):
                signals.append(DiscoverySignal.SHARED_HOST)
            if anchor_facts.get("user") and candidate_facts.get("user") == anchor_facts.get("user"):
                signals.append(DiscoverySignal.SHARED_USER)
            if anchor_facts.get("rule") and row.rule == anchor_facts.get("rule"):
                signals.append(DiscoverySignal.SHARED_RULE)
            candidate_mitre = {
                str(item.get("id") or item.get("name"))
                for item in candidate_facts.get("mitre", [])
                if isinstance(item, dict) and (item.get("id") or item.get("name"))
            }
            if anchor_mitre & candidate_mitre:
                signals.append(DiscoverySignal.SHARED_MITRE)
            if (
                anchor_facts.get("correlation_type")
                and row.correlation_type == anchor_facts.get("correlation_type")
            ):
                signals.append(DiscoverySignal.SHARED_CORRELATION_TYPE)
            if anchor_cases & set(case_ids_by_incident.get(candidate_id, [])):
                signals.append(DiscoverySignal.SAME_CASE)
            candidate_time = _timestamp(row.timestamp)
            if anchor_time and candidate_time:
                hours = abs((candidate_time - anchor_time).total_seconds()) / 3600
                if hours <= 24:
                    signals.append(DiscoverySignal.TEMPORAL_PROXIMITY)
            semantic_hit = semantic_by_id.get(candidate_id)
            semantic_valid = semantic_hit is not None
            if semantic_hit is not None and semantic_hit.source_fingerprint:
                semantic_valid = semantic_hit.source_fingerprint == (
                    incident_source_fingerprint(
                        row,
                        linked_case_ids=case_ids_by_incident.get(candidate_id, []),
                    )
                )
                if not semantic_valid:
                    stale_reject_count += 1
            semantic_score = semantic_hit.score if semantic_valid else None
            if semantic_valid:
                signals.append(DiscoverySignal.SEMANTIC_SIMILARITY)
            substantial = [
                signal
                for signal in signals
                if signal not in {
                    DiscoverySignal.TEMPORAL_PROXIMITY,
                    DiscoverySignal.SEMANTIC_SIMILARITY,
                }
            ]
            if not substantial and not semantic_valid:
                continue
            deterministic_count = len(
                [signal for signal in signals if signal is not DiscoverySignal.SEMANTIC_SIMILARITY]
            )
            ranking_score = sum(_SIGNAL_WEIGHTS[signal] for signal in signals)
            if semantic_score is not None:
                ranking_score += max(0.0, semantic_score) * 2.0
            source = (
                "hybrid"
                if substantial and semantic_valid
                else "semantic"
                if semantic_valid
                else "explicit"
                if candidate_id in explicit_ids
                else "deterministic"
            )
            ranked.append(
                (
                    IncidentCandidate(
                        candidate_id=f"candidate:incident:{candidate_id}",
                        candidate_incident_id=candidate_id,
                        discovery_signals=list(dict.fromkeys(signals)),
                        semantic_score=semantic_score,
                        deterministic_signal_count=deterministic_count,
                        discovery_source=source,
                        ranking_score=round(ranking_score, 6),
                    ),
                    RehydratedIncident(incident_id=candidate_id, facts=candidate_facts),
                )
            )
        ranked.sort(
            key=lambda item: (
                item[0].candidate_incident_id not in explicit_ids,
                -item[0].ranking_score,
                item[0].candidate_incident_id,
            )
        )
        discovered_count = min(len(ranked), limits.max_candidates_discovered)
        selected = ranked[: limits.max_candidates_rehydrated]
        return CandidateRetrievalResult(
            candidates=tuple(item[0] for item in selected),
            incidents=tuple(item[1] for item in selected),
            candidate_retrieval_ms=max(0.0, (clock() - started) * 1000),
            authoritative_rehydration_ms=rehydration_ms,
            discovered_count=discovered_count,
            rehydrated_count=len(pool_by_id),
            stale_reject_count=stale_reject_count,
        )
