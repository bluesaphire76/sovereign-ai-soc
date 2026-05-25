from __future__ import annotations

import json
import logging
from typing import Any
from uuid import uuid4

from sqlalchemy import func

from models import (
    InvestigationConfidenceHistoryRecord,
    InvestigationFeedbackRecord,
    InvestigationHypothesisHistoryRecord,
    InvestigationRetrievalHistoryRecord,
    InvestigationSessionRecord,
    InvestigationSimilarityHistoryRecord,
    InvestigationSnapshotRecord,
    utc_now,
)

from .intelligence import HistoricalInvestigationContext
from .models import (
    InvestigationBaseModel,
    InvestigationBrief,
)
from .retrieval import InvestigationEvidenceExpansion


logger = logging.getLogger(__name__)


class InvestigationPersistenceResult(InvestigationBaseModel):
    success: bool = True
    session_id: str | None = None
    snapshot_id: str | None = None
    investigation_version: int | None = None
    records_written: int = 0
    error: str | None = None


class InvestigationSessionHistoryItem(InvestigationBaseModel):
    session_id: str
    incident_id: int
    status: str
    investigation_version: int
    enrichment_pass_count: int
    fallback_used: bool
    confidence_score: int | None = None
    confidence_level: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class InvestigationSnapshotSummary(InvestigationBaseModel):
    snapshot_id: str
    session_id: str
    snapshot_type: str
    investigation_version: int
    evidence_count: int
    hypothesis_count: int
    recommended_check_count: int
    recommended_action_count: int
    created_at: str | None = None


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _json_loads(value: str | None) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        logger.warning("investigation_snapshot_deserialization_failed")
        return None


def _datetime_text(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def serialize_investigation_brief(brief: InvestigationBrief) -> dict[str, Any]:
    return brief.model_dump(mode="json", exclude_none=True)


def deserialize_investigation_brief(payload: str | dict[str, Any]) -> InvestigationBrief:
    data = _json_loads(payload) if isinstance(payload, str) else payload
    if not isinstance(data, dict):
        raise ValueError("Investigation snapshot payload must be a JSON object.")
    return InvestigationBrief(**data)


def snapshot_type_for_enrichment(enrichment_pass_count: int) -> str:
    return "ENRICHED_BRIEF" if enrichment_pass_count > 0 else "INITIAL_BRIEF"


def fallback_used_from_brief(brief: InvestigationBrief) -> bool:
    return any(
        limitation.limitation_id == "investigation-engine-fallback"
        for limitation in brief.limitations
    )


class InvestigationPersistenceStore:
    def __init__(self, db: Any):
        self.db = db

    def _session_record(self, session_id: str) -> InvestigationSessionRecord | None:
        return (
            self.db.query(InvestigationSessionRecord)
            .filter(InvestigationSessionRecord.session_id == session_id)
            .first()
        )

    def _next_version(self, session_id: str) -> int:
        current = (
            self.db.query(func.max(InvestigationSnapshotRecord.investigation_version))
            .filter(InvestigationSnapshotRecord.session_id == session_id)
            .scalar()
        )
        return int(current or 0) + 1

    def _snapshot_id(self, session_id: str, version: int) -> str:
        return f"{session_id}-v{version}-{uuid4().hex[:8]}"

    def persist_investigation_brief(
        self,
        brief: InvestigationBrief,
        *,
        generated_by: str = "system",
        model_name: str | None = None,
        parent_session_id: str | None = None,
        enrichment_pass_count: int = 0,
        fallback_used: bool | None = None,
        expansion: InvestigationEvidenceExpansion | None = None,
        historical_context: HistoricalInvestigationContext | None = None,
    ) -> InvestigationPersistenceResult:
        records_written = 0
        session_id = brief.session_id

        try:
            version = self._next_version(session_id)
            snapshot_id = self._snapshot_id(session_id, version)
            existing = self._session_record(session_id)
            previous_score = existing.confidence_score if existing else None
            previous_level = existing.confidence_level if existing else None
            resolved_fallback = fallback_used_from_brief(brief) if fallback_used is None else fallback_used

            if existing is None:
                existing = InvestigationSessionRecord(
                    session_id=session_id,
                    incident_id=brief.incident_id,
                    status=brief.status.value,
                    generated_by=generated_by,
                    model_name=model_name,
                    parent_session_id=parent_session_id,
                    investigation_version=version,
                    enrichment_pass_count=enrichment_pass_count,
                    fallback_used=resolved_fallback,
                    confidence_score=brief.confidence.score,
                    confidence_level=brief.confidence.level.value,
                )
                self.db.add(existing)
                records_written += 1
            else:
                existing.incident_id = brief.incident_id
                existing.status = brief.status.value
                existing.generated_by = generated_by
                existing.model_name = model_name
                existing.parent_session_id = parent_session_id or existing.parent_session_id
                existing.investigation_version = version
                existing.enrichment_pass_count = max(
                    int(existing.enrichment_pass_count or 0),
                    enrichment_pass_count,
                )
                existing.fallback_used = bool(existing.fallback_used or resolved_fallback)
                existing.confidence_score = brief.confidence.score
                existing.confidence_level = brief.confidence.level.value
                existing.updated_at = utc_now()
                records_written += 1

            snapshot = InvestigationSnapshotRecord(
                snapshot_id=snapshot_id,
                session_id=session_id,
                snapshot_type=snapshot_type_for_enrichment(enrichment_pass_count),
                investigation_version=version,
                investigation_payload=_json_dumps(serialize_investigation_brief(brief)),
                evidence_count=len(brief.evidence_used),
                hypothesis_count=len(brief.hypotheses),
                recommended_check_count=len(brief.recommended_checks),
                recommended_action_count=len(brief.recommended_actions),
            )
            self.db.add(snapshot)
            records_written += 1

            for hypothesis in brief.hypotheses:
                self.db.add(
                    InvestigationHypothesisHistoryRecord(
                        session_id=session_id,
                        hypothesis_id=hypothesis.hypothesis_id,
                        investigation_version=version,
                        hypothesis_status=hypothesis.status.value,
                        confidence_score=hypothesis.confidence.score,
                        claim_classification=hypothesis.claim_classification.value,
                        supporting_evidence_count=len(hypothesis.supporting_evidence),
                        contradictory_evidence_count=len(hypothesis.contradicting_evidence),
                        missing_evidence_count=len(hypothesis.missing_evidence),
                    )
                )
                records_written += 1

            if (
                version == 1
                or previous_score != brief.confidence.score
                or previous_level != brief.confidence.level.value
            ):
                self.db.add(
                    InvestigationConfidenceHistoryRecord(
                        session_id=session_id,
                        snapshot_id=snapshot_id,
                        investigation_version=version,
                        previous_score=previous_score,
                        new_score=brief.confidence.score,
                        previous_level=previous_level,
                        new_level=brief.confidence.level.value,
                        reason="Structured investigation confidence persisted for replay.",
                    )
                )
                records_written += 1

            records_written += self._persist_retrieval_history(
                session_id=session_id,
                version=version,
                enrichment_pass=enrichment_pass_count,
                expansion=expansion,
            )
            records_written += self._persist_similarity_history(
                session_id=session_id,
                version=version,
                historical_context=historical_context,
            )

            self.db.commit()
            logger.info(
                "investigation_snapshot_persisted",
                extra={
                    "session_id": session_id,
                    "incident_id": brief.incident_id,
                    "investigation_version": version,
                    "snapshot_id": snapshot_id,
                },
            )
            return InvestigationPersistenceResult(
                success=True,
                session_id=session_id,
                snapshot_id=snapshot_id,
                investigation_version=version,
                records_written=records_written,
            )
        except Exception as exc:
            if hasattr(self.db, "rollback"):
                self.db.rollback()
            logger.warning(
                "investigation_persistence_failure",
                extra={"session_id": session_id, "reason": exc.__class__.__name__},
            )
            raise

    def _persist_retrieval_history(
        self,
        *,
        session_id: str,
        version: int,
        enrichment_pass: int,
        expansion: InvestigationEvidenceExpansion | None,
    ) -> int:
        if expansion is None:
            return 0

        records_written = 0
        audit_by_type = {
            result.request_type.value: audit
            for result, audit in zip(expansion.results, expansion.audit)
        }

        for result in expansion.results:
            self.db.add(
                InvestigationRetrievalHistoryRecord(
                    session_id=session_id,
                    investigation_version=version,
                    enrichment_pass=enrichment_pass,
                    request_id=result.request_id,
                    retrieval_type=result.request_type.value,
                    retrieval_status=result.status.value,
                    duration_ms=result.duration_ms,
                    evidence_count=len(result.evidence),
                    limits_applied_json=_json_dumps(result.limits_applied),
                    failures_json=_json_dumps(result.failures),
                    audit_summary=audit_by_type.get(result.request_type.value),
                )
            )
            records_written += 1

        return records_written

    def add_analyst_feedback(
        self,
        *,
        session_id: str,
        analyst: str,
        feedback_type: str,
        feedback_text: str | None = None,
        confidence_override: int | None = None,
        hypothesis_reference: str | None = None,
    ) -> str:
        feedback_id = f"feedback-{uuid4().hex}"
        self.db.add(
            InvestigationFeedbackRecord(
                feedback_id=feedback_id,
                session_id=session_id,
                analyst=analyst,
                feedback_type=feedback_type,
                feedback_text=feedback_text,
                confidence_override=confidence_override,
                hypothesis_reference=hypothesis_reference,
            )
        )
        self.db.commit()
        logger.info(
            "investigation_feedback_persisted",
            extra={"session_id": session_id, "feedback_type": feedback_type},
        )
        return feedback_id

    def list_investigation_history(
        self,
        *,
        incident_id: int,
        limit: int = 25,
    ) -> list[InvestigationSessionHistoryItem]:
        rows = (
            self.db.query(InvestigationSessionRecord)
            .filter(InvestigationSessionRecord.incident_id == incident_id)
            .order_by(
                InvestigationSessionRecord.updated_at.desc(),
                InvestigationSessionRecord.id.desc(),
            )
            .limit(limit)
            .all()
        )
        return [
            InvestigationSessionHistoryItem(
                session_id=row.session_id,
                incident_id=row.incident_id,
                status=row.status,
                investigation_version=row.investigation_version,
                enrichment_pass_count=row.enrichment_pass_count,
                fallback_used=bool(row.fallback_used),
                confidence_score=row.confidence_score,
                confidence_level=row.confidence_level,
                created_at=_datetime_text(row.created_at),
                updated_at=_datetime_text(row.updated_at),
            )
            for row in rows
        ]

    def list_snapshots(self, *, session_id: str) -> list[InvestigationSnapshotSummary]:
        rows = (
            self.db.query(InvestigationSnapshotRecord)
            .filter(InvestigationSnapshotRecord.session_id == session_id)
            .order_by(
                InvestigationSnapshotRecord.investigation_version.asc(),
                InvestigationSnapshotRecord.id.asc(),
            )
            .all()
        )
        return [
            InvestigationSnapshotSummary(
                snapshot_id=row.snapshot_id,
                session_id=row.session_id,
                snapshot_type=row.snapshot_type,
                investigation_version=row.investigation_version,
                evidence_count=row.evidence_count,
                hypothesis_count=row.hypothesis_count,
                recommended_check_count=row.recommended_check_count,
                recommended_action_count=row.recommended_action_count,
                created_at=_datetime_text(row.created_at),
            )
            for row in rows
        ]

    def latest_brief(self, *, session_id: str) -> InvestigationBrief | None:
        row = (
            self.db.query(InvestigationSnapshotRecord)
            .filter(InvestigationSnapshotRecord.session_id == session_id)
            .order_by(
                InvestigationSnapshotRecord.investigation_version.desc(),
                InvestigationSnapshotRecord.id.desc(),
            )
            .first()
        )
        if row is None:
            return None
        return deserialize_investigation_brief(row.investigation_payload)

    def list_retrieval_history(
        self,
        *,
        session_id: str,
    ) -> list[InvestigationRetrievalHistoryRecord]:
        return (
            self.db.query(InvestigationRetrievalHistoryRecord)
            .filter(InvestigationRetrievalHistoryRecord.session_id == session_id)
            .order_by(
                InvestigationRetrievalHistoryRecord.investigation_version.asc(),
                InvestigationRetrievalHistoryRecord.id.asc(),
            )
            .all()
        )

    def _persist_similarity_history(
        self,
        *,
        session_id: str,
        version: int,
        historical_context: HistoricalInvestigationContext | None,
    ) -> int:
        if historical_context is None or not historical_context.matches:
            return 0

        records_written = 0
        recurring_entities = [
            item.model_dump(mode="json", exclude_none=True)
            for item in historical_context.recurring_entities
        ]
        recurring_patterns = [
            item.model_dump(mode="json", exclude_none=True)
            for item in historical_context.recurring_patterns
        ]

        for match in historical_context.matches:
            self.db.add(
                InvestigationSimilarityHistoryRecord(
                    session_id=session_id,
                    investigation_version=version,
                    incident_id=historical_context.incident_id,
                    related_incident_id=match.incident_id,
                    similarity_score=match.score.score,
                    similarity_strength=match.score.strength.value,
                    signals_json=_json_dumps(
                        [
                            signal.model_dump(mode="json", exclude_none=True)
                            for signal in match.score.signals
                        ]
                    ),
                    recurring_entities_json=_json_dumps(recurring_entities),
                    recurring_patterns_json=_json_dumps(recurring_patterns),
                    rationale=match.rationale,
                )
            )
            records_written += 1

        return records_written

    def list_similarity_history(
        self,
        *,
        session_id: str,
    ) -> list[InvestigationSimilarityHistoryRecord]:
        return (
            self.db.query(InvestigationSimilarityHistoryRecord)
            .filter(InvestigationSimilarityHistoryRecord.session_id == session_id)
            .order_by(
                InvestigationSimilarityHistoryRecord.investigation_version.asc(),
                InvestigationSimilarityHistoryRecord.similarity_score.desc(),
                InvestigationSimilarityHistoryRecord.id.asc(),
            )
            .all()
        )


def safe_persist_investigation_brief(
    db: Any,
    brief: InvestigationBrief,
    *,
    generated_by: str = "system",
    model_name: str | None = None,
    parent_session_id: str | None = None,
    enrichment_pass_count: int = 0,
    fallback_used: bool | None = None,
    expansion: InvestigationEvidenceExpansion | None = None,
    historical_context: HistoricalInvestigationContext | None = None,
) -> InvestigationPersistenceResult:
    try:
        store = InvestigationPersistenceStore(db)
        return store.persist_investigation_brief(
            brief,
            generated_by=generated_by,
            model_name=model_name,
            parent_session_id=parent_session_id,
            enrichment_pass_count=enrichment_pass_count,
            fallback_used=fallback_used,
            expansion=expansion,
            historical_context=historical_context,
        )
    except Exception as exc:
        logger.warning(
            "investigation_persistence_safe_fallback",
            extra={"reason": exc.__class__.__name__},
        )
        return InvestigationPersistenceResult(
            success=False,
            session_id=brief.session_id,
            records_written=0,
            error=exc.__class__.__name__,
        )
