from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Callable

from ai_model_policy import AiTask
from database import SessionLocal
from llm_client import generate_ai_response
from qdrant_knowledge import QdrantKnowledgeBase
from schemas.assistant import (
    AssistantCapabilitiesResponse,
    AssistantMetadata,
    AssistantQueryRequest,
    AssistantQueryResponse,
)
from services.assistant.context_builder import build_assistant_context
from services.assistant.prompting import build_assistant_messages
from services.assistant.retrieval import (
    CaseNotFound,
    IncidentNotFound,
    RetrievalResult,
    retrieve_assistant_context,
)
from services.assistant.sources import SourceRecord, assign_source_ids


FEATURE_KEY = "soc_assistant"
DECISION_BOUNDARY = "The assistant provides analyst decision support only."
TIMEOUT_ERRORS = {"ReadTimeout", "Timeout", "TimeoutError", "TimeoutException"}
SOURCE_TOKEN_RE = re.compile(r"\[S\d+\]")


@dataclass(frozen=True)
class AssistantSettings:
    enabled: bool = False
    max_message_chars: int = 2000
    max_context_chars: int = 16000
    max_sources: int = 8
    semantic_limit: int = 4
    timeout_seconds: int = 60


class AssistantError(Exception):
    def __init__(self, *, category: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.category = category
        self.status_code = status_code
        self.message = message


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    try:
        value = int(str(raw if raw is not None else default).strip())
    except Exception:
        value = default
    return max(minimum, min(value, maximum))


def get_assistant_settings() -> AssistantSettings:
    return AssistantSettings(
        enabled=_env_bool("AI_SOC_ASSISTANT_ENABLED", False),
        max_message_chars=_env_int("AI_SOC_ASSISTANT_MAX_MESSAGE_CHARS", 2000, minimum=1, maximum=2000),
        max_context_chars=_env_int("AI_SOC_ASSISTANT_MAX_CONTEXT_CHARS", 16000, minimum=1000, maximum=24000),
        max_sources=_env_int("AI_SOC_ASSISTANT_MAX_SOURCES", 8, minimum=1, maximum=12),
        semantic_limit=_env_int("AI_SOC_ASSISTANT_SEMANTIC_LIMIT", 4, minimum=1, maximum=8),
        timeout_seconds=_env_int("AI_SOC_ASSISTANT_TIMEOUT_SECONDS", 60, minimum=1, maximum=180),
    )


def assistant_capabilities(settings: AssistantSettings | None = None) -> AssistantCapabilitiesResponse:
    current = settings or get_assistant_settings()
    return AssistantCapabilitiesResponse(
        enabled=current.enabled,
        supported_scopes=["global", "incident", "case"],
        supported_modes=["auto", "standard", "quality"],
        decision_boundary=DECISION_BOUNDARY,
    )


def _metadata_from_result(result: dict[str, Any] | None = None) -> AssistantMetadata:
    payload = result or {}
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    latency = payload.get("latency_ms")
    return AssistantMetadata(
        provider_key=payload.get("provider_key"),
        provider_type=payload.get("provider_type"),
        profile=payload.get("profile"),
        model=payload.get("model"),
        fallback_used=bool(payload.get("fallback_used", False)),
        latency_ms=int(latency) if isinstance(latency, int) else None,
        usage=usage,
    )


def _fallback_answer(*, sources: list[SourceRecord], category: str) -> str:
    citations = " ".join(f"[{source.source_id}]" for source in sources[:3])
    if citations:
        return (
            "I have grounded source records, but model generation is unavailable. "
            f"Review the retrieved context manually using {citations}. "
            "No operational action, severity change, closure, suppression, or remediation approval was performed."
        )
    return (
        "I do not have enough grounded context to answer safely. Use incident or case scope for exact "
        "operational facts, or enable semantic memory for advisory global context."
    )


def _sanitize_answer_citations(answer: str, sources: list[SourceRecord]) -> tuple[str, list[str]]:
    valid_tokens = {f"[{source.source_id}]" for source in sources if source.source_id}
    removed = False

    def replace(match: re.Match[str]) -> str:
        nonlocal removed
        token = match.group(0)
        if token in valid_tokens:
            return token
        removed = True
        return ""

    updated = SOURCE_TOKEN_RE.sub(replace, str(answer or "")).strip()
    limitations = []
    if removed:
        limitations.append("Unsupported model citation tokens were removed from the answer.")
    return updated, limitations


def _provider_error_category(result: dict[str, Any]) -> str:
    error_type = str(result.get("safe_error") or result.get("error_type") or "")
    return "GenerationTimeout" if error_type in TIMEOUT_ERRORS else "ProviderUnavailable"


def _no_context_response(payload: AssistantQueryRequest, limitations: list[str]) -> AssistantQueryResponse:
    return AssistantQueryResponse(
        status="fallback",
        answer=_fallback_answer(sources=[], category="NoGroundingContext"),
        scope=payload.scope,
        incident_id=payload.incident_id,
        case_id=payload.case_id,
        sources=[],
        limitations=[*limitations, "NoGroundingContext"],
        metadata=AssistantMetadata(),
    )


def run_assistant_query(
    payload: AssistantQueryRequest,
    *,
    current_user: dict[str, Any] | None = None,
    settings: AssistantSettings | None = None,
    db_factory: Callable[[], Any] = SessionLocal,
    knowledge_base_factory=QdrantKnowledgeBase,
    generator: Callable[..., dict[str, Any]] = generate_ai_response,
) -> AssistantQueryResponse:
    current_settings = settings or get_assistant_settings()

    if not current_settings.enabled:
        raise AssistantError(
            category="AssistantDisabled",
            status_code=503,
            message="SOC assistant is disabled.",
        )

    if len(payload.message) > current_settings.max_message_chars:
        raise AssistantError(
            category="NoGroundingContext",
            status_code=422,
            message="Assistant message exceeds the configured limit.",
        )

    db = db_factory()
    try:
        retrieval = retrieve_assistant_context(
            payload,
            db=db,
            settings=current_settings,
            knowledge_base_factory=knowledge_base_factory,
        )
    except IncidentNotFound as exc:
        raise AssistantError(
            category="IncidentNotFound",
            status_code=404,
            message="Incident not found.",
        ) from exc
    except CaseNotFound as exc:
        raise AssistantError(
            category="CaseNotFound",
            status_code=404,
            message="Case not found.",
        ) from exc
    finally:
        close = getattr(db, "close", None)
        if callable(close):
            close()

    sources = assign_source_ids(retrieval.sources, max_sources=current_settings.max_sources)
    limitations = list(retrieval.limitations)
    if len(sources) < len(retrieval.sources):
        limitations.append("Source list was truncated to the configured source limit.")

    if not sources:
        return _no_context_response(payload, limitations)

    context_result = build_assistant_context(
        message=payload.message,
        sources=sources,
        max_context_chars=current_settings.max_context_chars,
    )
    limitations.extend(context_result.limitations)

    result = generator(
        messages=build_assistant_messages(context_result.context),
        prompt=None,
        task=AiTask.SOC_ASSISTANT,
        requested_mode=payload.requested_mode,
        user_triggered=True,
        timeout_seconds=current_settings.timeout_seconds,
        context={
            "scope": payload.scope,
            "incident_id": payload.incident_id,
            "case_id": payload.case_id,
            "source_count": len(sources),
            "semantic_memory_attempted": retrieval.semantic_memory_attempted,
        },
        current_user=current_user,
    )

    metadata = _metadata_from_result(result)
    text = str(result.get("text") or "").strip()
    if not text or result.get("safe_error") or result.get("error_type"):
        category = _provider_error_category(result)
        return AssistantQueryResponse(
            status="fallback",
            answer=_fallback_answer(sources=sources, category=category),
            scope=payload.scope,
            incident_id=payload.incident_id,
            case_id=payload.case_id,
            sources=[source.to_response_source() for source in sources],
            limitations=[*limitations, category],
            metadata=metadata,
        )

    answer, citation_limitations = _sanitize_answer_citations(text, sources)
    if not answer:
        return AssistantQueryResponse(
            status="fallback",
            answer=_fallback_answer(sources=sources, category="NoGroundingContext"),
            scope=payload.scope,
            incident_id=payload.incident_id,
            case_id=payload.case_id,
            sources=[source.to_response_source() for source in sources],
            limitations=[*limitations, *citation_limitations, "NoGroundingContext"],
            metadata=metadata,
        )

    return AssistantQueryResponse(
        status="success",
        answer=answer,
        scope=payload.scope,
        incident_id=payload.incident_id,
        case_id=payload.case_id,
        sources=[source.to_response_source() for source in sources],
        limitations=[*limitations, *citation_limitations],
        metadata=metadata,
    )
