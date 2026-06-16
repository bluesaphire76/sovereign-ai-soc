from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

from investigation_ai.adapters import safe_text
from investigation_ai.models import (
    EvidenceReference,
    InvestigationClaimClassification,
    InvestigationEvidenceStrength,
    InvestigationEvidenceType,
)
from investigation_ai.retrieval import (
    InvestigationRetrievalContext,
    InvestigationRetrievalRequest,
)


logger = logging.getLogger(__name__)

SEMANTIC_MEMORY_DECISION_BOUNDARY = (
    "Retrieved semantic memory context is advisory only. It may support analyst "
    "review, but it must not be used as primary evidence, final severity, "
    "operational deduplication, automatic noise suppression, incident or case "
    "closure, or replacement for deterministic correlation, RBAC, audit, "
    "approval workflow or human validation."
)


class EmbeddingModel(Protocol):
    def encode(self, text: str) -> Any:
        ...


@dataclass(frozen=True)
class QdrantKnowledgeConfig:
    enabled: bool = True
    url: str = "http://localhost:6333"
    collection_name: str = "security_kb"
    embedding_model: str = "sentence-transformers/multi-qa-MiniLM-L6-cos-v1"
    timeout_seconds: float = 2.0
    default_limit: int = 4
    score_threshold: float | None = None
    knowledge_base_path: Path = Path("knowledge_base")
    chunk_max_chars: int = 900


@dataclass(frozen=True)
class SemanticMemoryRecord:
    source_type: str
    source: str
    text: str
    payload: dict[str, Any] = field(default_factory=dict)


def _env_bool(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def config_from_env() -> QdrantKnowledgeConfig:
    threshold_raw = os.getenv("QDRANT_SCORE_THRESHOLD", "").strip()
    threshold = None
    if threshold_raw:
        try:
            threshold = float(threshold_raw)
        except ValueError:
            threshold = None

    return QdrantKnowledgeConfig(
        enabled=_env_bool("AI_SOC_RAG_ENABLED", True),
        url=os.getenv("QDRANT_URL", "http://localhost:6333"),
        collection_name=os.getenv("QDRANT_COLLECTION", "security_kb"),
        embedding_model=os.getenv(
            "QDRANT_EMBEDDING_MODEL",
            "sentence-transformers/multi-qa-MiniLM-L6-cos-v1",
        ),
        timeout_seconds=_env_float("QDRANT_TIMEOUT_SECONDS", 2.0),
        default_limit=max(1, _env_int("QDRANT_DEFAULT_LIMIT", 4)),
        score_threshold=threshold,
        knowledge_base_path=Path(os.getenv("QDRANT_KNOWLEDGE_BASE_PATH", "knowledge_base")),
        chunk_max_chars=max(200, _env_int("QDRANT_CHUNK_MAX_CHARS", 900)),
    )


def _split_markdown_sections(text: str) -> list[list[str]]:
    sections: list[list[str]] = []
    current: list[str] = []
    pending_title: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("# ") and not current:
            pending_title = [line]
            continue

        if line.startswith("## "):
            if current:
                sections.append(current)
            current = [*pending_title, line]
            pending_title = []
            continue

        if not current:
            current = [*pending_title]
            pending_title = []

        current.append(line)

    if current:
        sections.append(current)

    return sections


def _split_long_section(lines: list[str], max_chars: int) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for line in lines:
        if current and current_len + len(line) + 1 > max_chars:
            chunks.append("\n".join(current))
            current = []
            current_len = 0

        current.append(line)
        current_len += len(line) + 1

    if current:
        chunks.append("\n".join(current))

    return chunks


def chunk_text(text: str, max_chars: int = 900) -> list[str]:
    chunks: list[str] = []

    for section in _split_markdown_sections(text):
        section_text = "\n".join(section)
        if len(section_text) <= max_chars:
            chunks.append(section_text)
        else:
            chunks.extend(_split_long_section(section, max_chars))

    return [chunk for chunk in chunks if chunk.strip()]


def _vector_from_encoded(value: Any) -> list[float]:
    if hasattr(value, "tolist"):
        value = value.tolist()
    return [float(item) for item in value]


def _point_id(source: str, chunk_index: int, text: str) -> str:
    digest = hashlib.sha256(f"{source}:{chunk_index}:{text}".encode("utf-8")).hexdigest()
    return str(uuid5(NAMESPACE_URL, f"ai-soc-qdrant:{source}:{chunk_index}:{digest}"))


def stable_memory_point_id(source_type: str, source: str, content_hash: str) -> str:
    """Return a deterministic Qdrant point id for a semantic memory record."""

    return str(
        uuid5(
            NAMESPACE_URL,
            f"ai-soc-semantic-memory:{source_type}:{source}:{content_hash}",
        )
    )


def _short_text(value: str, *, max_chars: int = 900) -> str:
    text = " ".join(value.split())
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3].rstrip()}..."


def _payload_source_type(payload: dict[str, Any]) -> str:
    source_type = safe_text(payload.get("source_type"))
    if source_type:
        return source_type

    source = safe_text(payload.get("source"))
    if source.startswith("knowledge_base/") or source.startswith("knowledge_base\\"):
        return "knowledge_base"

    return "unknown"


class QdrantKnowledgeBase:
    def __init__(
        self,
        config: QdrantKnowledgeConfig | None = None,
        *,
        client: Any | None = None,
        encoder: EmbeddingModel | None = None,
    ) -> None:
        self.config = config or config_from_env()
        self._client = client
        self._encoder = encoder

    @property
    def client(self) -> Any:
        if self._client is None:
            from qdrant_client import QdrantClient

            self._client = QdrantClient(url=self.config.url, timeout=self.config.timeout_seconds)
        return self._client

    @property
    def encoder(self) -> EmbeddingModel:
        if self._encoder is None:
            from sentence_transformers import SentenceTransformer

            self._encoder = SentenceTransformer(self.config.embedding_model)
        return self._encoder

    def embed(self, text: str) -> list[float]:
        return _vector_from_encoded(self.encoder.encode(text))

    def collection_exists(self) -> bool:
        existing = [item.name for item in self.client.get_collections().collections]
        return self.config.collection_name in existing

    def recreate_collection(self, vector_size: int | None = None) -> None:
        from qdrant_client.models import Distance, VectorParams

        resolved_size = vector_size or len(self.embed("ai soc knowledge base"))

        if self.collection_exists():
            self.client.delete_collection(self.config.collection_name)

        self.client.create_collection(
            collection_name=self.config.collection_name,
            vectors_config=VectorParams(size=resolved_size, distance=Distance.COSINE),
        )

    def ensure_collection(self, vector_size: int) -> None:
        if self.collection_exists():
            return
        self.recreate_collection(vector_size=vector_size)

    def index_documents(
        self,
        *,
        path: str | Path | None = None,
        recreate: bool = False,
    ) -> dict[str, Any]:
        from qdrant_client.models import PointStruct

        base_path = Path(path) if path is not None else self.config.knowledge_base_path
        files = sorted(base_path.glob("*.md"))
        points: list[Any] = []
        vector_size: int | None = None

        for file_path in files:
            text = file_path.read_text(encoding="utf-8")
            for chunk_index, chunk in enumerate(
                chunk_text(text, max_chars=self.config.chunk_max_chars)
            ):
                vector = self.embed(chunk)
                vector_size = vector_size or len(vector)
                source = str(file_path)
                points.append(
                    PointStruct(
                        id=_point_id(source, chunk_index, chunk),
                        vector=vector,
                        payload={
                            "source_type": "knowledge_base",
                            "source": source,
                            "text": chunk,
                            "chunk_index": chunk_index,
                            "content_hash": hashlib.sha256(chunk.encode("utf-8")).hexdigest(),
                        },
                    )
                )

        if recreate:
            self.recreate_collection(vector_size=vector_size)
        elif vector_size is not None:
            self.ensure_collection(vector_size=vector_size)

        if points:
            self.client.upsert(collection_name=self.config.collection_name, points=points)

        return {
            "collection": self.config.collection_name,
            "path": str(base_path),
            "documents": len(files),
            "indexed_points": len(points),
            "recreated": recreate,
        }

    def index_memory_records(self, records: list[SemanticMemoryRecord]) -> dict[str, Any]:
        from qdrant_client.models import PointStruct

        points: list[Any] = []
        vector_size: int | None = None

        for record in records:
            text = safe_text(record.text)
            source_type = safe_text(record.source_type)
            source = safe_text(record.source)

            if not text or not source_type or not source:
                continue

            content_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
            vector = self.embed(text)
            vector_size = vector_size or len(vector)
            payload = {
                **record.payload,
                "source_type": source_type,
                "source": source,
                "text": text,
                "content_hash": content_hash,
            }
            points.append(
                PointStruct(
                    id=stable_memory_point_id(source_type, source, content_hash),
                    vector=vector,
                    payload=payload,
                )
            )

        if vector_size is not None:
            self.ensure_collection(vector_size=vector_size)

        if points:
            self.client.upsert(collection_name=self.config.collection_name, points=points)

        return {
            "collection": self.config.collection_name,
            "records_received": len(records),
            "indexed_points": len(points),
        }

    def retrieve_contexts(self, query: str, *, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.config.enabled:
            return []

        text = safe_text(query)
        if not text:
            return []

        resolved_limit = max(1, min(limit or self.config.default_limit, 25))
        vector = self.embed(text)
        results = self.client.query_points(
            collection_name=self.config.collection_name,
            query=vector,
            limit=resolved_limit,
            with_payload=True,
        )

        contexts: list[dict[str, Any]] = []
        for point in getattr(results, "points", []):
            score = getattr(point, "score", None)
            if self.config.score_threshold is not None and score is not None:
                if float(score) < self.config.score_threshold:
                    continue

            payload = getattr(point, "payload", None) or {}
            contexts.append(
                {
                    "id": str(getattr(point, "id", "")),
                    "source_type": _payload_source_type(payload),
                    "source": payload.get("source"),
                    "text": payload.get("text"),
                    "chunk_index": payload.get("chunk_index"),
                    "score": score,
                    "collection": self.config.collection_name,
                }
            )

        return contexts


    def capabilities(self) -> dict[str, Any]:
        """Return safe, non-secret Qdrant semantic memory capabilities."""

        return {
            "enabled": self.config.enabled,
            "mode": "semantic_memory_support_only",
            "provider": "qdrant",
            "collection": self.config.collection_name,
            "url": self.config.url,
            "embedding_model": self.config.embedding_model,
            "default_limit": self.config.default_limit,
            "score_threshold": self.config.score_threshold,
            "knowledge_base_path": str(self.config.knowledge_base_path),
            "chunk_max_chars": self.config.chunk_max_chars,
            "allowed_uses": [
                "semantic_search_historical_context",
                "playbook_retrieval",
                "soc_documentation_rag",
                "ai_analysis_context_enrichment",
                "detection_quality_decision_support",
            ],
            "forbidden_uses": [
                "primary_operational_deduplication",
                "final_severity_decision",
                "automatic_noise_suppression",
                "automatic_incident_closure",
                "final_classification_without_deterministic_verification",
                "replacement_of_correlation_rules",
            ],
            "decision_boundary": (
                "Qdrant provides semantic context and decision support only. "
                "Deterministic rules, RBAC, audit and human review remain authoritative."
            ),
        }

    def collection_info(self) -> dict[str, Any]:
        """Return collection status without loading the embedding model."""

        if not self.config.enabled:
            return {
                "enabled": False,
                "status": "DISABLED",
                "collection": self.config.collection_name,
                "exists": False,
                "message": "Semantic memory is disabled by configuration.",
            }

        try:
            collections = self.client.get_collections().collections
            collection_names = [
                str(getattr(item, "name", ""))
                for item in collections
                if getattr(item, "name", None)
            ]
            exists = self.config.collection_name in collection_names

            details: dict[str, Any] = {
                "enabled": True,
                "status": "OK" if exists else "WARN",
                "collection": self.config.collection_name,
                "exists": exists,
                "collections": collection_names,
                "collection_count": len(collection_names),
                "points_count": None,
                "indexed_vectors_count": None,
                "vectors_count": None,
                "collection_status": None,
            }

            if not exists:
                details["message"] = "Configured Qdrant collection is missing."
                return details

            info = self.client.get_collection(self.config.collection_name)
            details.update(
                {
                    "points_count": getattr(info, "points_count", None),
                    "indexed_vectors_count": getattr(info, "indexed_vectors_count", None),
                    "vectors_count": getattr(info, "vectors_count", None),
                    "collection_status": str(getattr(info, "status", None) or ""),
                }
            )

            if not details["points_count"]:
                details["status"] = "WARN"
                details["message"] = "Configured Qdrant collection exists but appears empty."
            else:
                details["message"] = "Configured Qdrant collection is available."

            return details

        except Exception as exc:
            logger.warning(
                "qdrant_collection_info_failed",
                extra={"reason": exc.__class__.__name__},
            )
            return {
                "enabled": self.config.enabled,
                "status": "ERROR",
                "collection": self.config.collection_name,
                "exists": False,
                "message": "Qdrant collection inspection failed.",
                "error_type": exc.__class__.__name__,
            }


    def index_status(self, *, max_points: int = 5000) -> dict[str, Any]:
        """Return read-only governance metadata about the Qdrant semantic index.

        This method intentionally does not index, delete, recreate or mutate
        Qdrant data. It only summarizes payload metadata already stored in the
        configured collection.
        """

        if not self.config.enabled:
            return {
                "enabled": False,
                "status": "DISABLED",
                "provider": "qdrant",
                "collection": self.config.collection_name,
                "documents_count": 0,
                "documents": [],
                "source_type_counts": {},
                "points_scanned": 0,
                "indexing_mode": "manual_cli_only",
                "indexing_command": "PYTHONPATH=. .venv/bin/python rag_index.py --recreate",
                "message": "Semantic memory is disabled.",
                "decision_boundary": (
                    "Index status is operational metadata only. It does not "
                    "make or change SOC decisions."
                ),
            }

        collection = self.collection_info()
        if not collection.get("exists"):
            return {
                "enabled": True,
                "status": collection.get("status", "WARN"),
                "provider": "qdrant",
                "collection": self.config.collection_name,
                "collection_info": collection,
                "documents_count": 0,
                "documents": [],
                "source_type_counts": {},
                "points_scanned": 0,
                "indexing_mode": "manual_cli_only",
                "indexing_command": "PYTHONPATH=. .venv/bin/python rag_index.py --recreate",
                "message": collection.get("message", "Configured collection is not available."),
                "decision_boundary": (
                    "Index status is operational metadata only. It does not "
                    "make or change SOC decisions."
                ),
            }

        documents: dict[str, dict[str, Any]] = {}
        source_type_counts: dict[str, int] = {}
        scanned = 0
        next_offset: Any = None

        try:
            while scanned < max_points:
                batch_limit = min(250, max_points - scanned)
                points, next_offset = self.client.scroll(
                    collection_name=self.config.collection_name,
                    limit=batch_limit,
                    offset=next_offset,
                    with_payload=True,
                    with_vectors=False,
                )

                if not points:
                    break

                for point in points:
                    payload = getattr(point, "payload", None) or {}
                    source = str(payload.get("source") or "unknown")
                    source_type = _payload_source_type(payload)
                    chunk_index = payload.get("chunk_index")
                    content_hash = payload.get("content_hash")
                    source_type_counts[source_type] = source_type_counts.get(source_type, 0) + 1

                    doc = documents.setdefault(
                        source,
                        {
                            "source_type": source_type,
                            "source": source,
                            "chunks": 0,
                            "first_chunk_index": None,
                            "last_chunk_index": None,
                            "content_hashes_count": 0,
                            "_content_hashes": set(),
                        },
                    )

                    doc["chunks"] += 1

                    if isinstance(chunk_index, int):
                        if doc["first_chunk_index"] is None or chunk_index < doc["first_chunk_index"]:
                            doc["first_chunk_index"] = chunk_index
                        if doc["last_chunk_index"] is None or chunk_index > doc["last_chunk_index"]:
                            doc["last_chunk_index"] = chunk_index

                    if content_hash:
                        doc["_content_hashes"].add(str(content_hash))

                    scanned += 1

                if next_offset is None:
                    break

            public_documents = []
            for source in sorted(documents):
                doc = documents[source]
                hashes = doc.pop("_content_hashes", set())
                doc["content_hashes_count"] = len(hashes)
                public_documents.append(doc)

            return {
                "enabled": True,
                "status": collection.get("status", "OK"),
                "provider": "qdrant",
                "collection": self.config.collection_name,
                "collection_info": collection,
                "points_count": collection.get("points_count"),
                "points_scanned": scanned,
                "max_points": max_points,
                "documents_count": len(public_documents),
                "documents": public_documents,
                "source_type_counts": source_type_counts,
                "indexing_mode": "manual_cli_only",
                "indexing_command": "PYTHONPATH=. .venv/bin/python rag_index.py --recreate",
                "message": (
                    "Semantic memory index metadata retrieved successfully. "
                    "Indexing remains an explicit manual CLI operation."
                ),
                "decision_boundary": (
                    "Index status is operational metadata only. It does not "
                    "perform indexing and does not make or change SOC decisions."
                ),
            }
        except Exception as exc:
            return {
                "enabled": True,
                "status": "ERROR",
                "provider": "qdrant",
                "collection": self.config.collection_name,
                "documents_count": 0,
                "documents": [],
                "source_type_counts": {},
                "points_scanned": scanned,
                "indexing_mode": "manual_cli_only",
                "indexing_command": "PYTHONPATH=. .venv/bin/python rag_index.py --recreate",
                "message": "Failed to retrieve semantic memory index metadata.",
                "error_type": exc.__class__.__name__,
                "decision_boundary": (
                    "Index status is operational metadata only. It does not "
                    "make or change SOC decisions."
                ),
            }


    def health_check(self) -> dict[str, Any]:
        """Return a compact health view for semantic memory."""

        capabilities = self.capabilities()
        collection = self.collection_info()

        return {
            "status": collection.get("status", "UNKNOWN"),
            "enabled": self.config.enabled,
            "component": "semantic_memory",
            "provider": "qdrant",
            "collection": self.config.collection_name,
            "message": collection.get("message"),
            "collection": collection,
            "capabilities": {
                "allowed_uses": capabilities["allowed_uses"],
                "forbidden_uses": capabilities["forbidden_uses"],
                "decision_boundary": capabilities["decision_boundary"],
            },
        }


    def build_investigation_query(
        self,
        request: InvestigationRetrievalRequest,
        retrieval_context: InvestigationRetrievalContext,
    ) -> str:
        context = retrieval_context.base_context
        incident = context.incident
        entity_values = [
            value
            for values in request.entity_filters.values()
            for value in values
            if safe_text(value)
        ]

        parts = [
            request.request_type.value,
            request.reason,
            " ".join(request.evidence_requested),
            " ".join(entity_values),
            " ".join(request.source_systems),
            safe_text(incident.get("rule")),
            safe_text(incident.get("agent")),
            safe_text(incident.get("mitre")),
            safe_text(incident.get("attack_chain")),
            safe_text(incident.get("correlation_type")),
            safe_text(incident.get("escalation_reason")),
        ]

        return _short_text(" ".join(part for part in parts if safe_text(part)), max_chars=2000)

    def fetch_investigation_evidence(
        self,
        request: InvestigationRetrievalRequest,
        retrieval_context: InvestigationRetrievalContext,
    ) -> list[EvidenceReference]:
        query = self.build_investigation_query(request, retrieval_context)
        contexts = self.retrieve_contexts(query, limit=request.max_results)
        return [
            self.context_to_evidence(context, request=request, index=index)
            for index, context in enumerate(contexts)
            if safe_text(context.get("text"))
        ]

    def context_to_evidence(
        self,
        context: dict[str, Any],
        *,
        request: InvestigationRetrievalRequest | None = None,
        index: int = 0,
    ) -> EvidenceReference:
        text = safe_text(context.get("text"))
        source = safe_text(context.get("source")) or self.config.collection_name
        point_id = safe_text(context.get("id")) or hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        digest = hashlib.sha256(
            f"{self.config.collection_name}:{source}:{point_id}:{text}".encode("utf-8")
        ).hexdigest()[:16]

        base_summary = _short_text(text, max_chars=600)
        if request is not None:
            summary = _short_text(
                "Advisory-only semantic memory context for "
                f"{request.request_type.value}: {base_summary}",
                max_chars=700,
            )
        else:
            summary = _short_text(
                f"Advisory-only semantic memory context: {base_summary}",
                max_chars=700,
            )

        return EvidenceReference(
            evidence_id=f"qdrant-kb-{digest}",
            evidence_type=InvestigationEvidenceType.OTHER,
            source_system="qdrant",
            source_table=self.config.collection_name,
            source_reference=source,
            summary=summary,
            raw_reference=f"qdrant:{self.config.collection_name}:{point_id or index}",
            strength=InvestigationEvidenceStrength.CONTEXTUAL,
            claim_classification=InvestigationClaimClassification.INFERRED,
        )


_DEFAULT_KNOWLEDGE_BASE: QdrantKnowledgeBase | None = None


def get_knowledge_base() -> QdrantKnowledgeBase:
    global _DEFAULT_KNOWLEDGE_BASE
    if _DEFAULT_KNOWLEDGE_BASE is None:
        _DEFAULT_KNOWLEDGE_BASE = QdrantKnowledgeBase()
    return _DEFAULT_KNOWLEDGE_BASE


def retrieve_security_context(query: str, limit: int = 3) -> list[dict[str, Any]]:
    try:
        return get_knowledge_base().retrieve_contexts(query, limit=limit)
    except Exception as exc:
        logger.warning(
            "qdrant_security_context_retrieval_failed",
            extra={"reason": exc.__class__.__name__},
        )
        return []


def qdrant_retrieval_fetcher(
    request: InvestigationRetrievalRequest,
    retrieval_context: InvestigationRetrievalContext,
) -> list[EvidenceReference]:
    return get_knowledge_base().fetch_investigation_evidence(request, retrieval_context)


def format_semantic_memory_context_for_prompt(
    contexts: list[dict[str, Any]],
    *,
    empty_message: str = "No semantic memory context was retrieved.",
    max_items: int = 4,
) -> str:
    """Format Qdrant context with explicit prompt-visible decision boundaries."""

    lines = [
        "Retrieved Semantic Memory Context (Qdrant)",
        f"Decision boundary: {SEMANTIC_MEMORY_DECISION_BOUNDARY}",
    ]

    if not contexts:
        lines.append(empty_message)
        return "\n".join(lines)

    added_items = 0

    for index, item in enumerate(contexts[:max_items], start=1):
        text = safe_text(item.get("text"))
        if not text:
            continue

        source = safe_text(item.get("source")) or "semantic_memory"
        chunk_index = item.get("chunk_index")
        score = item.get("score")
        score_text = f"{score:.3f}" if isinstance(score, (int, float)) else "unknown"
        added_items += 1

        lines.extend(
            [
                "",
                f"[{index}] source: {source}",
                f"[{index}] chunk_index: {chunk_index if chunk_index is not None else 'unknown'}",
                f"[{index}] semantic_score: {score_text}",
                f"[{index}] advisory_context: {_short_text(text, max_chars=900)}",
            ]
        )

    if added_items == 0:
        lines.append(empty_message)

    return "\n".join(lines)


def contexts_to_legacy_text(contexts: list[dict[str, Any]]) -> str:
    return format_semantic_memory_context_for_prompt(contexts)
