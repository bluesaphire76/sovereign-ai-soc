from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Literal
from uuid import NAMESPACE_URL, uuid5

from models import CaseIncident, Incident
from qdrant_knowledge import embedding_runtime_snapshot, get_knowledge_base


logger = logging.getLogger(__name__)

INCIDENT_SEMANTIC_SOURCE_TYPE = "incident_semantic_candidate"
INCIDENT_DOCUMENT_VERSION = "v1"
INCIDENT_INDEX_DECISION_BOUNDARY = (
    "The incident semantic index discovers comparison candidates only. Qdrant "
    "content and similarity scores are not operational facts, risk, severity, "
    "correlation, causality, compromise, attacker, or campaign evidence. Every "
    "candidate must be rehydrated from the operational database."
)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return min(max(value, minimum), maximum)


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return min(max(value, minimum), maximum)


@dataclass(frozen=True)
class IncidentSemanticIndexConfig:
    enabled: bool = True
    url: str = "http://localhost:6333"
    collection_name: str = "incident_semantic_index"
    embedding_model: str = "sentence-transformers/multi-qa-MiniLM-L6-cos-v1"
    timeout_seconds: float = 2.0
    score_threshold: float = 0.45
    query_limit: int = 12
    upsert_batch_size: int = 128


def incident_index_config_from_env() -> IncidentSemanticIndexConfig:
    return IncidentSemanticIndexConfig(
        enabled=_env_bool("QDRANT_INCIDENT_INDEX_ENABLED", True),
        url=os.getenv("QDRANT_URL", "http://localhost:6333"),
        collection_name=os.getenv(
            "QDRANT_INCIDENT_INDEX_COLLECTION",
            "incident_semantic_index",
        ),
        embedding_model=os.getenv(
            "QDRANT_EMBEDDING_MODEL",
            "sentence-transformers/multi-qa-MiniLM-L6-cos-v1",
        ),
        timeout_seconds=_env_float(
            "QDRANT_TIMEOUT_SECONDS",
            2.0,
            minimum=0.1,
            maximum=30.0,
        ),
        score_threshold=_env_float(
            "QDRANT_INCIDENT_INDEX_SCORE_THRESHOLD",
            0.45,
            minimum=-1.0,
            maximum=1.0,
        ),
        query_limit=_env_int(
            "QDRANT_INCIDENT_INDEX_QUERY_LIMIT",
            12,
            minimum=1,
            maximum=24,
        ),
        upsert_batch_size=_env_int(
            "QDRANT_INCIDENT_INDEX_UPSERT_BATCH_SIZE",
            128,
            minimum=1,
            maximum=512,
        ),
    )


@dataclass(frozen=True)
class IncidentSemanticDocument:
    incident_id: int
    point_id: str
    text: str
    source_fingerprint: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class IncidentSemanticHit:
    incident_id: int
    score: float
    source_fingerprint: str


@dataclass(frozen=True)
class IncidentSemanticQueryResult:
    hits: tuple[IncidentSemanticHit, ...] = ()
    status: Literal["ready", "degraded", "unavailable", "not_requested"] = (
        "not_requested"
    )
    query_ms: float = 0.0
    error_category: str | None = None
    raw_candidate_count: int = 0
    threshold_reject_count: int = 0
    invalid_candidate_reject_count: int = 0
    duplicate_candidate_reject_count: int = 0
    excluded_candidate_reject_count: int = 0


@dataclass(frozen=True)
class IncidentIndexOperationResult:
    collection: str
    eligible_count: int = 0
    ineligible_count: int = 0
    indexed_count: int = 0
    deleted_count: int = 0
    embedding_failures: int = 0
    duration_ms: float = 0.0
    status: Literal["ok", "degraded", "disabled"] = "ok"
    error_category: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IncidentIndexStatus:
    collection: str
    status: Literal["ready", "missing", "disabled", "unavailable"]
    indexed_count: int = 0
    unique_incident_ids: int = 0
    duplicate_ids: int = 0
    missing_ids: int = 0
    stale_fingerprints: int = 0
    database_incidents: int = 0
    eligible_incidents: int = 0
    ineligible_incidents: int = 0
    error_category: str | None = None
    decision_boundary: str = INCIDENT_INDEX_DECISION_BOUNDARY

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _bounded(value: Any, maximum: int) -> str:
    text = " ".join(str(value or "").split())
    return text[:maximum]


def _mitre_values(value: Any) -> list[str]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            value = [value]
    values = value if isinstance(value, list) else [value]
    result: list[str] = []
    for item in values:
        if isinstance(item, dict):
            selected = item.get("id") or item.get("technique_id") or item.get("name")
        else:
            selected = item
        normalized = _bounded(selected, 80)
        if normalized and normalized not in result:
            result.append(normalized)
    return result[:12]


def incident_semantic_source_fields(
    incident: Incident,
    *,
    linked_case_ids: Iterable[int] = (),
) -> dict[str, Any]:
    case_ids = sorted(
        {
            value
            for value in linked_case_ids
            if isinstance(value, int) and value > 0
        }
    )
    return {
        "incident_id": int(incident.id),
        "rule": _bounded(incident.rule, 500),
        "agent": _bounded(incident.agent, 240),
        "mitre_ids": _mitre_values(incident.mitre),
        "correlation_type": _bounded(incident.correlation_type, 160),
        "event_family": _bounded(incident.correlation_type, 160),
        "case_relationship_category": "linked_case" if case_ids else "none",
    }


def incident_source_fingerprint(
    incident: Incident,
    *,
    linked_case_ids: Iterable[int] = (),
) -> str:
    fields = incident_semantic_source_fields(
        incident,
        linked_case_ids=linked_case_ids,
    )
    encoded = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def incident_semantic_point_id(incident_id: int) -> str:
    return str(uuid5(NAMESPACE_URL, f"ai-soc-incident-semantic:{incident_id}"))


def build_incident_semantic_document(
    incident: Incident,
    *,
    linked_case_ids: Iterable[int] = (),
    indexed_at: datetime | None = None,
    embedding_version: str = "unknown",
) -> IncidentSemanticDocument:
    fields = incident_semantic_source_fields(
        incident,
        linked_case_ids=linked_case_ids,
    )
    fingerprint = incident_source_fingerprint(
        incident,
        linked_case_ids=linked_case_ids,
    )
    lines = [
        "Operational incident candidate",
        f"Detection rule: {fields['rule']}",
        f"Agent or host: {fields['agent']}",
        f"MITRE techniques: {', '.join(fields['mitre_ids'])}",
        f"Event family: {fields['event_family']}",
        f"Correlation type: {fields['correlation_type']}",
        f"Case relationship: {fields['case_relationship_category']}",
    ]
    text = "\n".join(line for line in lines if line.rsplit(":", 1)[-1].strip())
    payload = {
        "incident_id": fields["incident_id"],
        "source_type": INCIDENT_SEMANTIC_SOURCE_TYPE,
        "embedding_version": embedding_version,
        "document_version": INCIDENT_DOCUMENT_VERSION,
        "source_fingerprint": fingerprint,
        "updated_at": _bounded(incident.timestamp, 80) or None,
        "indexed_at": (indexed_at or datetime.now(timezone.utc)).isoformat(),
        "mitre_ids": fields["mitre_ids"],
        "correlation_type": fields["correlation_type"] or None,
        "rule_family": fields["rule"] or None,
        "event_family": fields["event_family"] or None,
        "case_relationship_category": fields["case_relationship_category"],
        "decision_boundary": INCIDENT_INDEX_DECISION_BOUNDARY,
    }
    return IncidentSemanticDocument(
        incident_id=fields["incident_id"],
        point_id=incident_semantic_point_id(fields["incident_id"]),
        text=text,
        source_fingerprint=fingerprint,
        payload=payload,
    )


def semantic_query_text_from_facts(facts: dict[str, Any]) -> str:
    mitre = _mitre_values(facts.get("mitre"))
    values = [
        f"Detection rule: {_bounded(facts.get('rule'), 500)}",
        f"Agent or host: {_bounded(facts.get('host') or facts.get('agent'), 240)}",
        f"MITRE techniques: {', '.join(mitre)}",
        f"Event family: {_bounded(facts.get('event_family') or facts.get('correlation_type'), 160)}",
        f"Correlation type: {_bounded(facts.get('correlation_type'), 160)}",
        "Case relationship: linked_case"
        if facts.get("linked_case_ids")
        else "Case relationship: none",
    ]
    return "\n".join(value for value in values if value.rsplit(":", 1)[-1].strip())


class IncidentSemanticIndex:
    def __init__(
        self,
        config: IncidentSemanticIndexConfig | None = None,
        *,
        client: Any | None = None,
        embedder: Callable[[str], list[float]] | None = None,
    ) -> None:
        self.config = config or incident_index_config_from_env()
        self._client = client
        self._embedder = embedder

    @property
    def client(self) -> Any:
        if self._client is None:
            from qdrant_client import QdrantClient

            self._client = QdrantClient(
                url=self.config.url,
                timeout=self.config.timeout_seconds,
            )
        return self._client

    def _embed(self, text: str, *, require_ready: bool) -> list[float]:
        if self._embedder is not None:
            return [float(value) for value in self._embedder(text)]
        snapshot = embedding_runtime_snapshot(self.config.embedding_model)
        if require_ready and not snapshot.get("embedding_ready"):
            raise RuntimeError("incident_embedding_not_ready")
        return [float(value) for value in get_knowledge_base().embed(text)]

    def _embed_many(self, texts: list[str]) -> list[list[float]]:
        if self._embedder is not None:
            return [self._embed(text, require_ready=False) for text in texts]
        encoded = get_knowledge_base().encoder.encode(
            texts,
            batch_size=self.config.upsert_batch_size,
            show_progress_bar=False,
            convert_to_numpy=True,
        )
        values = encoded.tolist() if hasattr(encoded, "tolist") else list(encoded)
        vectors = [
            [float(value) for value in vector]
            for vector in values
        ]
        if len(vectors) != len(texts):
            raise RuntimeError("incident_embedding_batch_size_mismatch")
        return vectors

    def collection_exists(self) -> bool:
        collections = self.client.get_collections().collections
        return self.config.collection_name in {item.name for item in collections}

    def recreate_collection(self, vector_size: int) -> None:
        from qdrant_client.models import Distance, VectorParams

        if self.collection_exists():
            self.client.delete_collection(self.config.collection_name)
        self.client.create_collection(
            collection_name=self.config.collection_name,
            vectors_config=VectorParams(size=vector_size, distance=Distance.COSINE),
        )

    def ensure_collection(self, vector_size: int) -> None:
        if not self.collection_exists():
            self.recreate_collection(vector_size)

    def _point(self, document: IncidentSemanticDocument, vector: list[float]) -> Any:
        from qdrant_client.models import PointStruct

        return PointStruct(
            id=document.point_id,
            vector=vector,
            payload=document.payload,
        )

    @staticmethod
    def _case_ids(db: Any, incident_ids: Iterable[int]) -> dict[int, list[int]]:
        ids = list(dict.fromkeys(incident_ids))
        result = {incident_id: [] for incident_id in ids}
        if not ids:
            return result
        rows = db.query(CaseIncident).filter(CaseIncident.incident_id.in_(ids)).all()
        for row in rows:
            result.setdefault(row.incident_id, []).append(row.case_id)
        return result

    def upsert_incident(
        self,
        db: Any,
        incident_id: int,
        *,
        require_ready_embedding: bool = True,
    ) -> IncidentIndexOperationResult:
        started = time.monotonic()
        if not self.config.enabled:
            return IncidentIndexOperationResult(
                collection=self.config.collection_name,
                status="disabled",
            )
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident is None:
            return self.delete(incident_id)
        case_ids = self._case_ids(db, [incident_id]).get(incident_id, [])
        try:
            document = build_incident_semantic_document(
                incident,
                linked_case_ids=case_ids,
                embedding_version=self.config.embedding_model,
            )
            vector = self._embed(document.text, require_ready=require_ready_embedding)
            self.ensure_collection(len(vector))
            self.client.upsert(
                collection_name=self.config.collection_name,
                points=[self._point(document, vector)],
                wait=True,
            )
        except Exception as exc:
            return IncidentIndexOperationResult(
                collection=self.config.collection_name,
                embedding_failures=(
                    1 if "embedding" in str(exc).lower() else 0
                ),
                duration_ms=(time.monotonic() - started) * 1000,
                status="degraded",
                error_category=exc.__class__.__name__,
            )
        return IncidentIndexOperationResult(
            collection=self.config.collection_name,
            indexed_count=1,
            duration_ms=(time.monotonic() - started) * 1000,
        )

    def delete(self, incident_id: int) -> IncidentIndexOperationResult:
        started = time.monotonic()
        if not self.config.enabled:
            return IncidentIndexOperationResult(
                collection=self.config.collection_name,
                status="disabled",
            )
        try:
            if not self.collection_exists():
                return IncidentIndexOperationResult(
                    collection=self.config.collection_name,
                    duration_ms=(time.monotonic() - started) * 1000,
                )
            self.client.delete(
                collection_name=self.config.collection_name,
                points_selector=[incident_semantic_point_id(incident_id)],
                wait=True,
            )
        except Exception as exc:
            return IncidentIndexOperationResult(
                collection=self.config.collection_name,
                duration_ms=(time.monotonic() - started) * 1000,
                status="degraded",
                error_category=exc.__class__.__name__,
            )
        return IncidentIndexOperationResult(
            collection=self.config.collection_name,
            deleted_count=1,
            duration_ms=(time.monotonic() - started) * 1000,
        )

    def rebuild(
        self,
        db: Any,
        *,
        limit: int | None = None,
    ) -> IncidentIndexOperationResult:
        started = time.monotonic()
        if not self.config.enabled:
            return IncidentIndexOperationResult(
                collection=self.config.collection_name,
                status="disabled",
            )
        query = db.query(Incident).order_by(Incident.id.asc())
        if limit is not None:
            query = query.limit(max(1, min(limit, 100_000)))
        incidents = query.all()
        case_ids = self._case_ids(db, [item.id for item in incidents])
        documents: list[IncidentSemanticDocument] = []
        failures = 0
        for incident in incidents:
            try:
                documents.append(
                    build_incident_semantic_document(
                        incident,
                        linked_case_ids=case_ids.get(incident.id, []),
                        embedding_version=self.config.embedding_model,
                    )
                )
            except Exception:
                failures += 1
        points = []
        vector_size = None
        for index in range(0, len(documents), self.config.upsert_batch_size):
            batch = documents[index : index + self.config.upsert_batch_size]
            try:
                vectors = self._embed_many([document.text for document in batch])
            except Exception:
                vectors = []
                for document in batch:
                    try:
                        vectors.append(
                            self._embed(document.text, require_ready=False)
                        )
                    except Exception:
                        vectors.append([])
                        failures += 1
            for document, vector in zip(batch, vectors, strict=True):
                if not vector:
                    continue
                vector_size = vector_size or len(vector)
                points.append(self._point(document, vector))
        try:
            if vector_size is not None:
                self.recreate_collection(vector_size)
                for index in range(0, len(points), self.config.upsert_batch_size):
                    self.client.upsert(
                        collection_name=self.config.collection_name,
                        points=points[index : index + self.config.upsert_batch_size],
                        wait=True,
                    )
        except Exception as exc:
            return IncidentIndexOperationResult(
                collection=self.config.collection_name,
                eligible_count=len(incidents),
                indexed_count=0,
                embedding_failures=failures,
                duration_ms=(time.monotonic() - started) * 1000,
                status="degraded",
                error_category=exc.__class__.__name__,
            )
        return IncidentIndexOperationResult(
            collection=self.config.collection_name,
            eligible_count=len(incidents),
            indexed_count=len(points),
            embedding_failures=failures,
            duration_ms=(time.monotonic() - started) * 1000,
            status="degraded" if failures else "ok",
        )

    def query(
        self,
        query_text: str,
        *,
        exclude_incident_id: int | None = None,
        limit: int | None = None,
    ) -> IncidentSemanticQueryResult:
        started = time.monotonic()
        if not self.config.enabled:
            return IncidentSemanticQueryResult(status="not_requested")
        try:
            vector = self._embed(query_text, require_ready=True)
            result = self.client.query_points(
                collection_name=self.config.collection_name,
                query=vector,
                limit=max(1, min(limit or self.config.query_limit, 24)),
                with_payload=True,
                timeout=max(1, int(self.config.timeout_seconds)),
            )
        except Exception as exc:
            category = exc.__class__.__name__
            status = (
                "degraded"
                if "embedding" in str(exc).lower()
                else "unavailable"
            )
            return IncidentSemanticQueryResult(
                status=status,
                query_ms=(time.monotonic() - started) * 1000,
                error_category=category,
            )
        points = list(getattr(result, "points", []))
        hits: list[IncidentSemanticHit] = []
        seen = set()
        threshold_rejects = 0
        invalid_rejects = 0
        duplicate_rejects = 0
        excluded_rejects = 0
        for point in points:
            payload = getattr(point, "payload", None) or {}
            if payload.get("source_type") != INCIDENT_SEMANTIC_SOURCE_TYPE:
                invalid_rejects += 1
                continue
            incident_id = payload.get("incident_id")
            fingerprint = payload.get("source_fingerprint")
            score = getattr(point, "score", None)
            if (
                not isinstance(incident_id, int)
                or incident_id <= 0
                or not isinstance(fingerprint, str)
                or not isinstance(score, (int, float))
            ):
                invalid_rejects += 1
                continue
            if incident_id == exclude_incident_id:
                excluded_rejects += 1
                continue
            if incident_id in seen:
                duplicate_rejects += 1
                continue
            if float(score) < self.config.score_threshold:
                threshold_rejects += 1
                continue
            seen.add(incident_id)
            hits.append(
                IncidentSemanticHit(
                    incident_id=incident_id,
                    score=max(-1.0, min(1.0, float(score))),
                    source_fingerprint=fingerprint,
                )
            )
        return IncidentSemanticQueryResult(
            hits=tuple(hits),
            status="ready",
            query_ms=(time.monotonic() - started) * 1000,
            raw_candidate_count=len(points),
            threshold_reject_count=threshold_rejects,
            invalid_candidate_reject_count=invalid_rejects,
            duplicate_candidate_reject_count=duplicate_rejects,
            excluded_candidate_reject_count=excluded_rejects,
        )

    def _scroll_payloads(self, *, limit: int | None) -> list[dict[str, Any]]:
        payloads = []
        offset = None
        while limit is None or len(payloads) < limit:
            batch_limit = 250 if limit is None else min(250, limit - len(payloads))
            points, offset = self.client.scroll(
                collection_name=self.config.collection_name,
                limit=batch_limit,
                offset=offset,
                with_payload=True,
                with_vectors=False,
            )
            payloads.extend(
                (getattr(point, "payload", None) or {}) for point in points or []
            )
            if not points or offset is None:
                break
        return payloads

    def status(
        self,
        db: Any,
        *,
        limit: int | None = None,
    ) -> IncidentIndexStatus:
        if not self.config.enabled:
            return IncidentIndexStatus(
                collection=self.config.collection_name,
                status="disabled",
            )
        try:
            if not self.collection_exists():
                return IncidentIndexStatus(
                    collection=self.config.collection_name,
                    status="missing",
                )
            resolved_limit = (
                max(1, min(limit, 100_000)) if limit is not None else None
            )
            payloads = self._scroll_payloads(limit=resolved_limit)
            query = db.query(Incident).order_by(Incident.id.asc())
            if resolved_limit is not None:
                query = query.limit(resolved_limit)
            incidents = query.all()
            case_ids = self._case_ids(db, [item.id for item in incidents])
        except Exception as exc:
            return IncidentIndexStatus(
                collection=self.config.collection_name,
                status="unavailable",
                error_category=exc.__class__.__name__,
            )
        database_by_id = {item.id: item for item in incidents}
        indexed_ids = [
            payload.get("incident_id")
            for payload in payloads
            if isinstance(payload.get("incident_id"), int)
        ]
        unique_ids = set(indexed_ids)
        stale = 0
        for payload in payloads:
            incident_id = payload.get("incident_id")
            incident = database_by_id.get(incident_id)
            if incident is None:
                stale += 1
                continue
            current = incident_source_fingerprint(
                incident,
                linked_case_ids=case_ids.get(incident_id, []),
            )
            if payload.get("source_fingerprint") != current:
                stale += 1
        return IncidentIndexStatus(
            collection=self.config.collection_name,
            status="ready",
            indexed_count=len(payloads),
            unique_incident_ids=len(unique_ids),
            duplicate_ids=max(0, len(indexed_ids) - len(unique_ids)),
            missing_ids=len(set(database_by_id) - unique_ids),
            stale_fingerprints=stale,
            database_incidents=len(database_by_id),
            eligible_incidents=len(database_by_id),
        )


_DEFAULT_INCIDENT_SEMANTIC_INDEX: IncidentSemanticIndex | None = None


def get_incident_semantic_index() -> IncidentSemanticIndex:
    global _DEFAULT_INCIDENT_SEMANTIC_INDEX
    if _DEFAULT_INCIDENT_SEMANTIC_INDEX is None:
        _DEFAULT_INCIDENT_SEMANTIC_INDEX = IncidentSemanticIndex()
    return _DEFAULT_INCIDENT_SEMANTIC_INDEX
