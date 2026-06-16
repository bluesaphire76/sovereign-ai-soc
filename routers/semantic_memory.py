from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from qdrant_knowledge import QdrantKnowledgeBase, config_from_env


router = APIRouter(prefix="/semantic-memory", tags=["Semantic Memory"])


def _knowledge_base() -> QdrantKnowledgeBase:
    return QdrantKnowledgeBase(config_from_env())


@router.get("/capabilities")
def semantic_memory_capabilities() -> dict[str, Any]:
    return _knowledge_base().capabilities()


@router.get("/health")
def semantic_memory_health() -> dict[str, Any]:
    return _knowledge_base().health_check()


@router.get("/collection")
def semantic_memory_collection() -> dict[str, Any]:
    return _knowledge_base().collection_info()


@router.get("/index-status")
def semantic_memory_index_status(
    max_points: int = Query(default=5000, ge=1, le=20000),
) -> dict[str, Any]:
    """Return read-only semantic memory index governance metadata.

    This endpoint does not trigger indexing. Indexing remains an explicit
    manual CLI operation through rag_index.py.
    """

    return _knowledge_base().index_status(max_points=max_points)


@router.get("/search")
def semantic_memory_search(
    query: str = Query(..., min_length=1, max_length=500),
    limit: int = Query(default=4, ge=1, le=25),
) -> dict[str, Any]:
    """Run a read-only semantic search against the configured Qdrant collection.

    This endpoint is intentionally support-only. It does not change incident
    state, severity, deduplication, suppression, closure or correlation.
    """

    kb = _knowledge_base()

    if not kb.config.enabled:
        return {
            "enabled": False,
            "query": query,
            "collection": kb.config.collection_name,
            "result_count": 0,
            "results": [],
            "decision_boundary": (
                "Semantic memory is disabled. No operational decision was made."
            ),
        }

    try:
        results = kb.retrieve_contexts(query, limit=limit)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Semantic memory search failed.",
                "error_type": exc.__class__.__name__,
            },
        ) from exc

    return {
        "enabled": True,
        "query": query,
        "collection": kb.config.collection_name,
        "limit": limit,
        "result_count": len(results),
        "results": results,
        "decision_boundary": (
            "Qdrant results are semantic context only. They must not be used as "
            "primary deduplication, final severity, automatic suppression, "
            "incident closure or replacement for deterministic correlation rules."
        ),
    }
