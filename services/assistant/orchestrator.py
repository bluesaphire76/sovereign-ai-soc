from __future__ import annotations

import logging
import math
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal
from uuid import uuid4

from ai_model_policy import AiTask
from database import SessionLocal
from qdrant_knowledge import get_knowledge_base
from schemas.assistant import (
    AssistantCapabilitiesResponse,
    AssistantFallbackReason,
    AssistantMetadata,
    AssistantQueryRequest,
    AssistantQueryResponse,
    AssistantResponseBlock,
    AssistantResponseLanguage,
)
from services.ai_execution.client import generate_ai_response
from services.ai_execution.metrics import (
    ASSISTANT_SEMANTIC_DEGRADED,
    ASSISTANT_SEMANTIC_DURATION,
    ASSISTANT_V3_CONTEXT_DURATION,
    ASSISTANT_V3_CONTEXT_PACKAGES,
    ASSISTANT_V3_PLAN_DURATION,
    ASSISTANT_V3_PLAN_UNITS,
    ASSISTANT_V3_RENDER_DURATION,
    ASSISTANT_V3_RESPONSES,
    ASSISTANT_V3_SEMANTIC_INDEX_DURATION,
    FALLBACK_TOTAL,
    GROUNDING_REJECTIONS,
)
from services.assistant.context_builder import build_assistant_context
from services.assistant.claims import grounded_claim_output_schema
from services.assistant.focus import (
    SemanticFocusRouter,
    build_focused_fact_view,
    general_focus_selection,
    get_semantic_focus_router,
)
from services.assistant.grounding import (
    deterministic_claim_output,
    parse_grounded_output,
    validate_focus,
    validate_grounded_output,
)
from services.assistant.prompting import build_assistant_messages
from services.assistant.rendering import render_claim_output, response_blocks
from services.assistant.retrieval import (
    CaseNotFound,
    IncidentNotFound,
    retrieve_assistant_context,
)
from services.assistant.runtime import assistant_runtime_snapshot
from services.assistant.sources import SourceRecord, assign_source_ids
from services.assistant.v3.builder import V3AnalyticalContextBuilder
from services.assistant.v3.contracts import V3AnalyticalContextPackage
from services.assistant.v3.attribution import build_v3_attribution
from services.assistant.v3.discourse import (
    RenderedV3Answer,
    RichGroundedDiscourseRenderer,
)
from services.assistant.v3.intent import (
    SemanticIntentRouter,
    get_semantic_intent_router,
    neutral_intent_selection,
)
from services.assistant.v3.policy import advisory_retrieval_allowed
from services.assistant.v3.plan_contracts import (
    AnalyticalUnitType,
    AnswerSectionType,
    GroundedAnswerPlanV3,
)
from services.assistant.v3.plan_fallback import deterministic_answer_plan_v3
from services.assistant.v3.plan_prompting import build_v3_plan_messages
from services.assistant.v3.plan_schema import grounded_answer_plan_v3_schema
from services.assistant.v3.plan_validation import (
    GroundedAnswerPlanV3Validator,
    parse_grounded_answer_plan_v3,
)


FEATURE_KEY = "soc_assistant"
DECISION_BOUNDARY = "The assistant provides read-only analyst decision support."
logger = logging.getLogger(__name__)
_SEMANTIC_LIMITATION_KINDS = {
    "Semantic memory was not requested for this assistant query.": "not_requested",
    (
        "Semantic memory was skipped because the assistant request budget "
        "was exhausted."
    ): "timed_out",
    "Semantic memory is disabled; continuing without advisory context.": "disabled",
    (
        "Semantic memory was unavailable within its time budget; the answer "
        "uses authoritative platform data."
    ): "timed_out",
    (
        "Semantic memory retrieval failed safely; exact operational facts "
        "remain usable."
    ): "failed",
}
_SEMANTIC_LIMITATION_TEXT = {
    "timed_out": {
        "en": (
            "Semantic memory was unavailable within its time budget; the answer "
            "uses authoritative platform data."
        ),
        "it": (
            "La memoria semantica non era disponibile entro il tempo previsto; "
            "la risposta usa i dati autorevoli della piattaforma."
        ),
    },
    "disabled": {
        "en": (
            "Semantic memory is disabled; the answer uses authoritative "
            "platform data."
        ),
        "it": (
            "La memoria semantica è disabilitata; la risposta usa i dati "
            "autorevoli della piattaforma."
        ),
    },
    "failed": {
        "en": (
            "Semantic memory retrieval failed; authoritative operational facts "
            "remain available."
        ),
        "it": (
            "Il recupero dalla memoria semantica non è riuscito; i fatti "
            "operativi autorevoli restano disponibili."
        ),
    },
}


@dataclass(frozen=True)
class AssistantSettings:
    enabled: bool = False
    max_message_chars: int = 2000
    max_context_chars: int = 16000
    max_sources: int = 8
    semantic_limit: int = 4
    semantic_timeout_seconds: float = 2.0
    request_timeout_seconds: float = 45.0
    max_output_tokens: int = 768
    response_architecture: Literal["v2", "v3"] = "v2"
    v3_max_output_tokens: int = 768


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
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return min(max(value, minimum), maximum)


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    if not math.isfinite(value):
        value = default
    return min(max(value, minimum), maximum)


def _response_architecture() -> Literal["v2", "v3"]:
    value = os.getenv("AI_ASSISTANT_RESPONSE_ARCHITECTURE", "v2").strip().lower()
    return "v3" if value == "v3" else "v2"


def get_assistant_settings() -> AssistantSettings:
    return AssistantSettings(
        enabled=_env_bool("AI_SOC_ASSISTANT_ENABLED", False),
        max_message_chars=_env_int(
            "AI_SOC_ASSISTANT_MAX_MESSAGE_CHARS",
            2000,
            minimum=1,
            maximum=2000,
        ),
        max_context_chars=_env_int(
            "AI_SOC_ASSISTANT_MAX_CONTEXT_CHARS",
            16000,
            minimum=1000,
            maximum=24000,
        ),
        max_sources=_env_int(
            "AI_SOC_ASSISTANT_MAX_SOURCES",
            8,
            minimum=1,
            maximum=12,
        ),
        semantic_limit=_env_int(
            "AI_SOC_ASSISTANT_SEMANTIC_LIMIT",
            4,
            minimum=1,
            maximum=8,
        ),
        semantic_timeout_seconds=_env_float(
            "AI_SOC_ASSISTANT_SEMANTIC_TIMEOUT_SECONDS",
            2.0,
            minimum=0.1,
            maximum=2.0,
        ),
        request_timeout_seconds=_env_float(
            "AI_SOC_ASSISTANT_REQUEST_TIMEOUT_SECONDS",
            45.0,
            minimum=1.0,
            maximum=300.0,
        ),
        max_output_tokens=_env_int(
            "AI_INFERENCE_MAX_OUTPUT_TOKENS",
            384,
            minimum=64,
            maximum=2048,
        ),
        response_architecture=_response_architecture(),
        v3_max_output_tokens=_env_int(
            "AI_SOC_ASSISTANT_V3_MAX_OUTPUT_TOKENS",
            768,
            minimum=256,
            maximum=2048,
        ),
    )


def assistant_capabilities(
    settings: AssistantSettings | None = None,
) -> AssistantCapabilitiesResponse:
    current = settings or get_assistant_settings()
    runtime = assistant_runtime_snapshot()
    return AssistantCapabilitiesResponse(
        enabled=current.enabled,
        supported_scopes=["global", "incident", "case"],
        supported_modes=["auto", "standard"],
        decision_boundary=DECISION_BOUNDARY,
        runtime_state=runtime.get("runtime_state"),
        loaded_profile=runtime.get("loaded_profile"),
        runtime_message=runtime.get("runtime_message"),
    )


def _response_language(message: str) -> AssistantResponseLanguage:
    words = set(re.findall(r"[a-zàèéìòù]+", message.lower()))
    strong_italian = {
        "analizza",
        "cerca",
        "collegamenti",
        "confronta",
        "cosa",
        "evidenze",
        "incidente",
        "incidenti",
        "perché",
        "prepara",
        "quali",
        "riassumi",
        "rischio",
        "severità",
        "sintesi",
        "spiega",
        "verifica",
    }
    italian = strong_italian | {
        "che",
        "come",
        "della",
        "delle",
        "non",
        "questa",
        "questo",
        "stato",
    }
    if words & strong_italian:
        return "it"
    return "it" if len(words & italian) >= 2 else "en"


def _fallback_reason(result: dict[str, Any]) -> AssistantFallbackReason:
    safe_error = str(
        result.get("safe_error")
        or result.get("error_type")
        or result.get("provider_status")
        or ""
    ).lower()
    if safe_error in {"queue_deadline_exceeded", "queue_full"}:
        return "queue_deadline_exceeded"
    if safe_error == "generation_timeout" or "timeout" in safe_error:
        return "generation_timeout"
    if safe_error == "invalid_visible_output":
        return "invalid_visible_output"
    if safe_error == "invalid_json":
        return "invalid_json"
    if safe_error == "invalid_json_type":
        return "invalid_json_type"
    if safe_error == "invalid_structured_claim_schema":
        return "invalid_structured_claim_schema"
    if safe_error == "gateway_unavailable" or "unavailable" in safe_error:
        return "gateway_unavailable"
    return "invalid_structured_output"


def _selected_sources(
    records: list[SourceRecord],
    *,
    used_advisory_context: bool,
    max_sources: int,
) -> list[SourceRecord]:
    selected = [
        source
        for source in records
        if source.authority == "authoritative"
        or used_advisory_context
    ]
    return assign_source_ids(selected, max_sources=max_sources)


def _human_limitations(
    values: list[str],
    *,
    language: AssistantResponseLanguage,
    semantic_status: str,
) -> list[str]:
    translated: list[str] = []
    for value in values:
        normalized = " ".join(str(value or "").split())
        if not normalized:
            continue
        semantic_kind = _SEMANTIC_LIMITATION_KINDS.get(normalized)
        if semantic_status == "not_requested" and (
            semantic_kind is not None
            or normalized.lower().startswith(
                (
                    "semantic memory",
                    "la memoria semantica",
                    "il recupero dalla memoria semantica",
                )
            )
        ):
            continue
        if semantic_kind is not None:
            effective_status = (
                semantic_status
                if semantic_status in _SEMANTIC_LIMITATION_TEXT
                else semantic_kind
            )
            localized = _SEMANTIC_LIMITATION_TEXT.get(effective_status)
            if localized is not None:
                normalized = localized[language]
        if normalized not in translated:
            translated.append(normalized)
    return translated


def _build_response(
    *,
    payload: AssistantQueryRequest,
    output,
    source_records: list[SourceRecord],
    retrieval,
    response_language: AssistantResponseLanguage,
    generation_kind: str,
    fallback_reason: AssistantFallbackReason | None,
    grounding_validation: str,
    focus_validation: str,
    result: dict[str, Any],
    request_started: float,
    clock: Callable[[], float],
    settings: AssistantSettings,
    v3_package: V3AnalyticalContextPackage | None,
) -> AssistantQueryResponse:
    sources = _selected_sources(
        source_records,
        used_advisory_context=output.used_advisory_context,
        max_sources=settings.max_sources,
    )
    blocks = response_blocks(output, sources=sources)
    answer = "\n\n".join(block.text for block in blocks)
    metadata = AssistantMetadata(
        generation_kind=generation_kind,
        queue_wait_ms=max(0, int(result.get("queue_wait_ms") or 0)),
        generation_ms=max(0, int(result.get("generation_ms") or 0)),
        total_latency_ms=max(0, int((clock() - request_started) * 1000)),
        semantic_status=retrieval.semantic_status,
        semantic_elapsed_ms=max(0, retrieval.semantic_elapsed_ms),
        semantic_degraded=retrieval.semantic_degraded,
        grounding_validation=grounding_validation,
        focus_validation=focus_validation,
        fallback_reason=fallback_reason,
        response_language=response_language,
        source_count=len(sources),
        assistant_intent=(
            v3_package.intent_selection.primary_intent.value
            if v3_package is not None
            else None
        ),
        secondary_intents=(
            [item.value for item in v3_package.intent_selection.secondary_intents]
            if v3_package is not None
            else []
        ),
        analysis_scope=(
            v3_package.resolved_scope.analysis_scope.value
            if v3_package is not None
            else None
        ),
        context_atoms=(
            len(v3_package.operational_atoms)
            + len(v3_package.reference_atoms)
            + len(v3_package.advisory_atoms)
            if v3_package is not None
            else 0
        ),
        operational_atoms=(len(v3_package.operational_atoms) if v3_package else 0),
        reference_atoms=(len(v3_package.reference_atoms) if v3_package else 0),
        advisory_atoms=(len(v3_package.advisory_atoms) if v3_package else 0),
        cross_incident_candidates=(
            len(v3_package.cross_incident_candidates) if v3_package else 0
        ),
        graph_edges=(
            len(v3_package.cross_incident_graph.relationships) if v3_package else 0
        ),
        conversation_followup=(
            v3_package.resolved_scope.conversation_followup if v3_package else False
        ),
        context_build_ms=(
            max(0, int(v3_package.metrics.total_context_build_ms))
            if v3_package
            else 0
        ),
        response_architecture=settings.response_architecture,
        provider_generation_count=max(
            0,
            int(result.get("_provider_generation_count") or 0),
        ),
        automatic_retries=0,
        model_switches=max(
            0,
            int(
                (result.get("provider_diagnostics") or {}).get(
                    "profile_switch_count"
                )
                or 0
            ),
        ),
        finish_reason=str(result.get("finish_reason") or "") or None,
        semantic_index_status=(
            v3_package.semantic_index_status if v3_package else "not_requested"
        ),
    )
    return AssistantQueryResponse(
        status="ok" if generation_kind == "model" else "fallback",
        generation_kind=generation_kind,
        answer=answer,
        blocks=blocks,
        scope=payload.scope,
        incident_id=payload.incident_id,
        case_id=payload.case_id,
        sources=[source.to_response_source() for source in sources],
        limitations=_human_limitations(
            retrieval.limitations,
            language=response_language,
            semantic_status=retrieval.semantic_status,
        ),
        metadata=metadata,
    )


_V3_BLOCK_KINDS = {
    AnswerSectionType.DIRECT_ANSWER: "direct_answer",
    AnswerSectionType.KEY_FINDINGS: "key_findings",
    AnswerSectionType.INCIDENT_OVERVIEW: "analysis",
    AnswerSectionType.EVIDENCE: "evidence",
    AnswerSectionType.TIMELINE: "analysis",
    AnswerSectionType.RELATED_INCIDENTS: "related_incidents",
    AnswerSectionType.COMPARISON: "analysis",
    AnswerSectionType.PATTERN: "analysis",
    AnswerSectionType.TECHNICAL_CONTEXT: "technical_context",
    AnswerSectionType.WHAT_WE_CAN_CONCLUDE: "analysis",
    AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE: "limitations",
    AnswerSectionType.NEXT_STEPS: "next_check",
    AnswerSectionType.LIMITATIONS: "limitations",
}


def _v3_response_blocks(
    rendered: RenderedV3Answer,
    *,
    source_ids_by_ref: dict[str, tuple[str, ...]],
) -> list[AssistantResponseBlock]:
    blocks = []
    for block in rendered.blocks:
        source_ids = list(
            dict.fromkeys(
                source_id
                for ref in block.source_refs
                for source_id in source_ids_by_ref.get(ref, ())
            )
        )
        blocks.append(
            AssistantResponseBlock(
                kind=_V3_BLOCK_KINDS[block.section_type],
                text=block.text,
                source_ids=source_ids,
            )
        )
    return blocks


def _v3_plan_counts(plan: GroundedAnswerPlanV3) -> tuple[int, int, int]:
    cross_types = {
        AnalyticalUnitType.COMPARISON,
        AnalyticalUnitType.DIFFERENCE,
        AnalyticalUnitType.SHARED_PATTERN,
        AnalyticalUnitType.RECORDED_CORRELATION,
        AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
        AnalyticalUnitType.SEMANTIC_SIMILARITY,
        AnalyticalUnitType.TEMPORAL_SEQUENCE,
        AnalyticalUnitType.CANDIDATE_RELEVANCE,
    }
    cross_units = sum(
        unit.unit_type in cross_types for unit in plan.analytical_units
    )
    reference_units = sum(
        unit.unit_type is AnalyticalUnitType.REFERENCE_EXPLANATION
        for unit in plan.analytical_units
    )
    advisory_units = sum(
        unit.unit_type
        in {AnalyticalUnitType.ADVISORY_GUIDANCE, AnalyticalUnitType.NEXT_CHECK}
        for unit in plan.analytical_units
    )
    return cross_units, reference_units, advisory_units


def _deterministic_v2_response_for_v3_failure(
    *,
    payload: AssistantQueryRequest,
    focused_fact_inventory: dict[str, Any],
    source_records: list[SourceRecord],
    retrieval: Any,
    response_language: AssistantResponseLanguage,
    fallback_reason: AssistantFallbackReason,
    result: dict[str, Any],
    request_started: float,
    clock: Callable[[], float],
    settings: AssistantSettings,
    v3_package: V3AnalyticalContextPackage | None,
) -> AssistantQueryResponse:
    output = deterministic_claim_output(
        fact_inventory=focused_fact_inventory,
        authoritative_source_ids=[
            source.source_id
            for source in source_records
            if source.authority == "authoritative" and source.source_id
        ],
    )
    rendered = render_claim_output(
        output,
        fact_inventory=focused_fact_inventory,
        response_language=response_language,
    )
    FALLBACK_TOTAL.labels(fallback_reason).inc()
    ASSISTANT_V3_RESPONSES.labels(
        generation_kind="deterministic_fallback",
        validation_status="failed",
    ).inc()
    return _build_response(
        payload=payload,
        output=rendered,
        source_records=source_records,
        retrieval=retrieval,
        response_language=response_language,
        generation_kind="deterministic_fallback",
        fallback_reason=fallback_reason,
        grounding_validation="failed",
        focus_validation="not_run",
        result=result,
        request_started=request_started,
        clock=clock,
        settings=settings,
        v3_package=v3_package,
    )


def _run_v3_response(
    *,
    payload: AssistantQueryRequest,
    package: V3AnalyticalContextPackage | None,
    focused_fact_inventory: dict[str, Any],
    source_records: list[SourceRecord],
    retrieval: Any,
    response_language: AssistantResponseLanguage,
    request_id: str,
    request_started: float,
    settings: AssistantSettings,
    generator: Callable[..., dict[str, Any]],
    clock: Callable[[], float],
) -> AssistantQueryResponse:
    result: dict[str, Any] = {"_provider_generation_count": 0}
    if package is None:
        return _deterministic_v2_response_for_v3_failure(
            payload=payload,
            focused_fact_inventory=focused_fact_inventory,
            source_records=source_records,
            retrieval=retrieval,
            response_language=response_language,
            fallback_reason="v3_context_build_failed",
            result=result,
            request_started=request_started,
            clock=clock,
            settings=settings,
            v3_package=None,
        )

    schema_started = clock()
    prompt_chars = 0
    try:
        prompt = build_v3_plan_messages(
            package,
            max_context_chars=settings.max_context_chars,
        )
        schema = grounded_answer_plan_v3_schema(package)
        prompt_chars = prompt.context_chars
        schema_build_ms = max(0, int((clock() - schema_started) * 1000))
        ASSISTANT_V3_PLAN_DURATION.labels(stage="schema", status="passed").observe(
            schema_build_ms / 1000
        )
    except Exception as exc:
        schema_build_ms = max(0, int((clock() - schema_started) * 1000))
        ASSISTANT_V3_PLAN_DURATION.labels(stage="schema", status="failed").observe(
            schema_build_ms / 1000
        )
        logger.warning(
            "assistant_v3_schema_build_failed request_id=%s reason=%s",
            request_id,
            exc.__class__.__name__,
        )
        fallback_reason: AssistantFallbackReason | None = "v3_schema_build_failed"
        plan = deterministic_answer_plan_v3(package)
        plan_validation_status = "not_run"
        plan_validation_ms = 0
    else:
        try:
            result = generator(
                messages=prompt.messages,
                task=AiTask.SOC_ASSISTANT,
                requested_mode="standard",
                user_triggered=True,
                timeout_seconds=settings.request_timeout_seconds,
                max_visible_tokens=settings.v3_max_output_tokens,
                context={
                    "caller_kind": "assistant_primary",
                    "request_id_hash": request_id,
                    "assistant_intent": (
                        package.intent_selection.primary_intent.value
                    ),
                    "response_architecture": "v3",
                    "v3_context_atoms": (
                        len(package.operational_atoms)
                        + len(package.reference_atoms)
                        + len(package.advisory_atoms)
                    ),
                },
                output_schema="assistant_grounded_v3",
                structured_output_schema=schema,
            )
        except Exception as exc:
            logger.warning(
                "assistant_v3_generation_failed request_id=%s reason=%s",
                request_id,
                exc.__class__.__name__,
            )
            result = {
                "safe_error": "invalid_structured_output",
                "error_type": "invalid_structured_output",
            }
        result["_provider_generation_count"] = 1
        structured = result.get("structured_output")
        if structured is None:
            structured = result.get("text")
        parsed = parse_grounded_answer_plan_v3(structured, package=package)
        finish_reason = str(result.get("finish_reason") or "").strip().lower()
        truncated = finish_reason in {
            "length",
            "max_length",
            "max_tokens",
            "token_limit",
        }
        plan_validation_started = clock()
        plan_validation_status = "not_run"
        fallback_reason = None
        if result.get("safe_error") or result.get("error_type"):
            fallback_reason = _fallback_reason(result)
            if fallback_reason in {
                "invalid_structured_output",
                "invalid_structured_claim_schema",
                "invalid_json",
                "invalid_json_type",
            }:
                fallback_reason = "v3_invalid_structured_output"
        elif parsed is None or truncated:
            fallback_reason = "v3_invalid_structured_output"
        else:
            validation = GroundedAnswerPlanV3Validator().validate(
                parsed,
                package=package,
            )
            plan_validation_status = "passed" if validation.accepted else "failed"
            if not validation.accepted:
                GROUNDING_REJECTIONS.labels(
                    validation.reason or "v3_plan_validation_failed"
                ).inc()
                fallback_reason = "v3_plan_validation_failed"
        plan_validation_ms = max(
            0,
            int((clock() - plan_validation_started) * 1000),
        )
        ASSISTANT_V3_PLAN_DURATION.labels(
            stage="validation",
            status=plan_validation_status,
        ).observe(plan_validation_ms / 1000)
        plan = (
            parsed
            if fallback_reason is None and parsed is not None
            else deterministic_answer_plan_v3(package)
        )

    fallback_validation = GroundedAnswerPlanV3Validator().validate(
        plan,
        package=package,
    )
    if not fallback_validation.accepted:
        logger.error(
            "assistant_v3_fallback_plan_failed request_id=%s reason=%s",
            request_id,
            fallback_validation.reason,
        )
        return _deterministic_v2_response_for_v3_failure(
            payload=payload,
            focused_fact_inventory=focused_fact_inventory,
            source_records=source_records,
            retrieval=retrieval,
            response_language=response_language,
            fallback_reason="v3_plan_validation_failed",
            result=result,
            request_started=request_started,
            clock=clock,
            settings=settings,
            v3_package=package,
        )

    try:
        rendered = RichGroundedDiscourseRenderer().render(plan, package=package)
        attribution = build_v3_attribution(
            package=package,
            rendered=rendered,
            existing_sources=source_records,
            max_sources=settings.max_sources,
        )
    except Exception as exc:
        logger.warning(
            "assistant_v3_renderer_failed request_id=%s reason=%s",
            request_id,
            exc.__class__.__name__,
        )
        if fallback_reason is None:
            fallback_reason = "v3_renderer_failed"
            plan = deterministic_answer_plan_v3(package)
            try:
                rendered = RichGroundedDiscourseRenderer().render(
                    plan,
                    package=package,
                )
                attribution = build_v3_attribution(
                    package=package,
                    rendered=rendered,
                    existing_sources=source_records,
                    max_sources=settings.max_sources,
                )
            except Exception:
                return _deterministic_v2_response_for_v3_failure(
                    payload=payload,
                    focused_fact_inventory=focused_fact_inventory,
                    source_records=source_records,
                    retrieval=retrieval,
                    response_language=response_language,
                    fallback_reason="v3_renderer_failed",
                    result=result,
                    request_started=request_started,
                    clock=clock,
                    settings=settings,
                    v3_package=package,
                )
        else:
            return _deterministic_v2_response_for_v3_failure(
                payload=payload,
                focused_fact_inventory=focused_fact_inventory,
                source_records=source_records,
                retrieval=retrieval,
                response_language=response_language,
                fallback_reason="v3_renderer_failed",
                result=result,
                request_started=request_started,
                clock=clock,
                settings=settings,
                v3_package=package,
            )

    generation_kind = "model" if fallback_reason is None else "deterministic_fallback"
    if fallback_reason is not None:
        FALLBACK_TOTAL.labels(fallback_reason).inc()
    blocks = _v3_response_blocks(
        rendered,
        source_ids_by_ref=attribution.source_ids_by_ref,
    )
    sources = list(attribution.sources)
    cross_units, reference_units, advisory_units = _v3_plan_counts(plan)
    ASSISTANT_V3_PLAN_UNITS.observe(len(plan.analytical_units))
    ASSISTANT_V3_RENDER_DURATION.observe(rendered.render_ms / 1000)
    ASSISTANT_V3_RESPONSES.labels(
        generation_kind=generation_kind,
        validation_status=plan_validation_status,
    ).inc()
    metadata = AssistantMetadata(
        generation_kind=generation_kind,
        queue_wait_ms=max(0, int(result.get("queue_wait_ms") or 0)),
        generation_ms=max(0, int(result.get("generation_ms") or 0)),
        total_latency_ms=max(0, int((clock() - request_started) * 1000)),
        semantic_status=retrieval.semantic_status,
        semantic_elapsed_ms=max(0, retrieval.semantic_elapsed_ms),
        semantic_degraded=retrieval.semantic_degraded,
        grounding_validation=plan_validation_status,
        focus_validation="passed" if fallback_validation.accepted else "failed",
        fallback_reason=fallback_reason,
        response_language=response_language,
        source_count=len(sources),
        assistant_intent=package.intent_selection.primary_intent.value,
        secondary_intents=[
            item.value for item in package.intent_selection.secondary_intents
        ],
        analysis_scope=package.resolved_scope.analysis_scope.value,
        context_atoms=(
            len(package.operational_atoms)
            + len(package.reference_atoms)
            + len(package.advisory_atoms)
        ),
        operational_atoms=len(package.operational_atoms),
        reference_atoms=len(package.reference_atoms),
        advisory_atoms=len(package.advisory_atoms),
        cross_incident_candidates=len(package.cross_incident_candidates),
        graph_edges=len(package.cross_incident_graph.relationships),
        conversation_followup=package.resolved_scope.conversation_followup,
        context_build_ms=max(0, int(package.metrics.total_context_build_ms)),
        intent_routing_ms=max(0, int(package.metrics.intent_routing_ms)),
        focus_routing_ms=max(0, int(package.metrics.focus_routing_ms)),
        context_policy_ms=max(0, int(package.metrics.context_policy_ms)),
        atom_normalization_ms=max(0, int(package.metrics.atom_normalization_ms)),
        semantic_candidate_ms=max(0, int(package.metrics.candidate_retrieval_ms)),
        semantic_index_query_ms=max(0, int(package.metrics.semantic_index_query_ms)),
        authoritative_rehydration_ms=max(
            0,
            int(package.metrics.authoritative_rehydration_ms),
        ),
        graph_ms=max(0, int(package.metrics.graph_construction_ms)),
        reference_retrieval_ms=max(
            0,
            int(package.metrics.reference_retrieval_ms),
        ),
        advisory_retrieval_ms=max(
            0,
            int(package.metrics.advisory_retrieval_ms),
        ),
        conversation_state_ms=max(
            0,
            int(package.metrics.conversation_state_ms),
        ),
        response_architecture="v3",
        plan_sections=len(plan.sections),
        plan_units=len(plan.analytical_units),
        cross_incident_units=cross_units,
        reference_units=reference_units,
        advisory_units=advisory_units,
        plan_validation_status=plan_validation_status,
        schema_build_ms=schema_build_ms,
        plan_validation_ms=plan_validation_ms,
        rendering_ms=max(0, int(rendered.render_ms)),
        prompt_chars=prompt_chars,
        prompt_tokens=max(0, int(result.get("prompt_tokens") or 0)),
        structured_output_tokens=max(
            0,
            int(result.get("completion_tokens") or 0),
        ),
        provider_generation_count=max(
            0,
            int(result.get("_provider_generation_count") or 0),
        ),
        automatic_retries=0,
        model_switches=max(
            0,
            int(
                (result.get("provider_diagnostics") or {}).get(
                    "profile_switch_count"
                )
                or 0
            ),
        ),
        finish_reason=str(result.get("finish_reason") or "") or None,
        semantic_index_status=package.semantic_index_status,
    )
    return AssistantQueryResponse(
        status="ok" if generation_kind == "model" else "fallback",
        generation_kind=generation_kind,
        answer="\n\n".join(block.text for block in blocks),
        blocks=blocks,
        scope=payload.scope,
        incident_id=payload.incident_id,
        case_id=payload.case_id,
        sources=[source.to_response_source() for source in sources],
        limitations=_human_limitations(
            retrieval.limitations,
            language=response_language,
            semantic_status=retrieval.semantic_status,
        ),
        metadata=metadata,
    )


def run_assistant_query(
    payload: AssistantQueryRequest,
    *,
    current_user: dict[str, Any] | None = None,
    settings: AssistantSettings | None = None,
    db_factory: Callable[[], Any] = SessionLocal,
    knowledge_base_factory=get_knowledge_base,
    generator: Callable[..., dict[str, Any]] = generate_ai_response,
    focus_router: SemanticFocusRouter | None = None,
    intent_router: SemanticIntentRouter | None = None,
    v3_context_builder: V3AnalyticalContextBuilder | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> AssistantQueryResponse:
    current_settings = settings or get_assistant_settings()
    request_started = clock()
    request_id = uuid4().hex
    response_language = _response_language(payload.message)

    if not current_settings.enabled:
        raise AssistantError(
            category="AssistantDisabled",
            status_code=503,
            message="SOC assistant is disabled.",
        )
    if len(payload.message) > current_settings.max_message_chars:
        raise AssistantError(
            category="InvalidAssistantRequest",
            status_code=422,
            message="Assistant message exceeds the configured limit.",
        )

    selected_intent_router = intent_router or get_semantic_intent_router()
    try:
        intent_selection = selected_intent_router.route(payload.message)
    except Exception:
        intent_selection = neutral_intent_selection()
    selected_focus_router = focus_router or get_semantic_focus_router()
    try:
        focus_selection = selected_focus_router.route(payload.message)
    except Exception:
        focus_selection = general_focus_selection(
            focus_degraded=True,
            routing_status="router_failure",
        )

    retrieval_payload = payload.model_copy(
        update={
            "include_semantic_memory": (
                payload.include_semantic_memory
                and advisory_retrieval_allowed(intent_selection)
            )
        }
    )
    db = db_factory()
    v3_package: V3AnalyticalContextPackage | None = None
    try:
        retrieval = retrieve_assistant_context(
            retrieval_payload,
            db=db,
            settings=current_settings,
            knowledge_base_factory=knowledge_base_factory,
            semantic_timeout_seconds=current_settings.semantic_timeout_seconds,
            deadline_monotonic=(
                request_started + current_settings.semantic_timeout_seconds
            ),
            clock=clock,
        )
        try:
            v3_package = (v3_context_builder or V3AnalyticalContextBuilder()).build(
                payload=payload,
                response_language=response_language,
                intent_selection=intent_selection,
                focus_selection=focus_selection,
                retrieval=retrieval,
                db=db,
                current_user=current_user,
                clock=clock,
            )
            metric_labels = {
                "intent": v3_package.intent_selection.primary_intent.value,
                "scope": v3_package.resolved_scope.analysis_scope.value,
            }
            ASSISTANT_V3_CONTEXT_DURATION.labels(**metric_labels).observe(
                v3_package.metrics.total_context_build_ms / 1000
            )
            ASSISTANT_V3_CONTEXT_PACKAGES.labels(**metric_labels).inc()
            ASSISTANT_V3_SEMANTIC_INDEX_DURATION.labels(
                status=v3_package.semantic_index_status
            ).observe(v3_package.metrics.semantic_index_query_ms / 1000)
        except Exception as exc:
            logger.warning(
                "assistant_v3_context_build_failed request_id=%s reason=%s",
                request_id,
                exc.__class__.__name__,
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

    semantic_seconds = max(0.0, retrieval.semantic_elapsed_ms / 1000)
    ASSISTANT_SEMANTIC_DURATION.observe(semantic_seconds)
    if retrieval.semantic_degraded:
        ASSISTANT_SEMANTIC_DEGRADED.labels(
            retrieval.semantic_status
        ).inc()

    focused_fact_inventory = build_focused_fact_view(
        fact_inventory=retrieval.fact_inventory,
        focus=focus_selection,
    )
    candidate_sources = assign_source_ids(
        retrieval.sources,
        max_sources=current_settings.max_sources,
    )

    if current_settings.response_architecture == "v3":
        response = _run_v3_response(
            payload=payload,
            package=v3_package,
            focused_fact_inventory=focused_fact_inventory,
            source_records=candidate_sources,
            retrieval=retrieval,
            response_language=response_language,
            request_id=request_id,
            request_started=request_started,
            settings=current_settings,
            generator=generator,
            clock=clock,
        )
        logger.info(
            "assistant_v3_execution request_id=%s scope=%s target_id=%s "
            "generation_kind=%s generation_ms=%s total_latency_ms=%s "
            "plan_validation=%s fallback_reason=%s plan_sections=%s "
            "plan_units=%s provider_generations=%s",
            request_id,
            payload.scope,
            payload.incident_id or payload.case_id,
            response.generation_kind,
            response.metadata.generation_ms,
            response.metadata.total_latency_ms,
            response.metadata.plan_validation_status,
            response.metadata.fallback_reason,
            response.metadata.plan_sections,
            response.metadata.plan_units,
            response.metadata.provider_generation_count,
        )
        return response

    try:
        context_result = build_assistant_context(
            message=payload.message,
            fact_inventory=focused_fact_inventory,
            sources=candidate_sources,
            max_context_chars=current_settings.max_context_chars,
        )
    except ValueError:
        retrieval.limitations.append(
            "The model context budget was unavailable; the response uses the "
            "authoritative fact inventory directly."
        )
        result = {
            "safe_error": "invalid_structured_output",
            "error_type": "invalid_structured_output",
        }
    else:
        if context_result.limitations:
            retrieval.limitations.extend(context_result.limitations)
        messages = build_assistant_messages(
            context_result.context,
            focus=focus_selection,
            fact_inventory=focused_fact_inventory,
            response_language=response_language,
        )
        result = generator(
            messages=messages,
            task=AiTask.SOC_ASSISTANT,
            requested_mode="standard",
            user_triggered=True,
            timeout_seconds=current_settings.request_timeout_seconds,
            max_visible_tokens=current_settings.max_output_tokens,
            context={
                "caller_kind": "assistant_primary",
                "request_id_hash": request_id,
                "focus_dimensions": [
                    dimension.value for dimension in focus_selection.dimensions
                ],
                "focus_routing_ms": round(
                    focus_selection.focus_routing_ms,
                    3,
                ),
                "focus_degraded": focus_selection.focus_degraded,
                "assistant_intent": intent_selection.primary_intent.value,
                "intent_degraded": intent_selection.degraded,
                "v3_context_atoms": (
                    len(v3_package.operational_atoms)
                    + len(v3_package.reference_atoms)
                    + len(v3_package.advisory_atoms)
                    if v3_package
                    else 0
                ),
            },
            output_schema="assistant_grounded_v2",
            structured_output_schema=grounded_claim_output_schema(
                fact_inventory=focused_fact_inventory,
                allow_advisory=any(
                    source.authority == "advisory"
                    for source in candidate_sources
                ),
            ),
        )
        result["_provider_generation_count"] = 1

    structured = result.get("structured_output")
    if structured is None:
        structured = result.get("text")
    output = parse_grounded_output(structured)
    fallback_reason: AssistantFallbackReason | None = None
    grounding_status = "not_run"
    focus_status = "not_run"

    finish_reason = str(result.get("finish_reason") or "").strip().lower()
    truncated = finish_reason in {
        "length",
        "max_length",
        "max_tokens",
        "token_limit",
    }
    if result.get("safe_error") or result.get("error_type"):
        fallback_reason = _fallback_reason(result)
    elif output is None:
        fallback_reason = "invalid_structured_claim_schema"
    elif truncated:
        fallback_reason = "invalid_structured_output"
    else:
        grounding = validate_grounded_output(
            output,
            fact_inventory=focused_fact_inventory,
            sources=candidate_sources,
        )
        grounding_status = "passed" if grounding.accepted else "failed"
        if not grounding.accepted:
            GROUNDING_REJECTIONS.labels(
                grounding.reason or "grounding_validation_failed"
            ).inc()
            fallback_reason = "grounding_validation_failed"
        else:
            focus = validate_focus(
                output,
                focus=focus_selection,
                fact_inventory=focused_fact_inventory,
            )
            focus_status = "passed" if focus.accepted else "failed"
            if not focus.accepted:
                GROUNDING_REJECTIONS.labels(
                    focus.reason or "focus_validation_failed"
                ).inc()
                fallback_reason = "focus_validation_failed"

    if fallback_reason is not None:
        FALLBACK_TOTAL.labels(fallback_reason).inc()
        output = deterministic_claim_output(
            fact_inventory=focused_fact_inventory,
            authoritative_source_ids=[
                source.source_id
                for source in candidate_sources
                if source.authority == "authoritative" and source.source_id
            ],
        )
        generation_kind = "deterministic_fallback"
    else:
        generation_kind = "model"
    output = render_claim_output(
        output,
        fact_inventory=focused_fact_inventory,
        response_language=response_language,
    )

    response = _build_response(
        payload=payload,
        output=output,
        source_records=candidate_sources,
        retrieval=retrieval,
        response_language=response_language,
        generation_kind=generation_kind,
        fallback_reason=fallback_reason,
        grounding_validation=grounding_status,
        focus_validation=focus_status,
        result=result,
        request_started=request_started,
        clock=clock,
        settings=current_settings,
        v3_package=v3_package,
    )
    logger.info(
        "assistant_execution request_id=%s scope=%s target_id=%s "
        "generation_kind=%s queue_wait_ms=%s generation_ms=%s "
        "semantic_status=%s grounding_validation=%s focus_validation=%s "
        "fallback_reason=%s source_count=%s profile=standard "
        "model=ai-soc-standard intent=%s context_atoms=%s graph_edges=%s",
        request_id,
        payload.scope,
        payload.incident_id or payload.case_id,
        response.generation_kind,
        response.metadata.queue_wait_ms,
        response.metadata.generation_ms,
        response.metadata.semantic_status,
        response.metadata.grounding_validation,
        response.metadata.focus_validation,
        response.metadata.fallback_reason,
        response.metadata.source_count,
        response.metadata.assistant_intent,
        response.metadata.context_atoms,
        response.metadata.graph_edges,
    )
    return response
