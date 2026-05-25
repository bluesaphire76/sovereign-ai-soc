from __future__ import annotations

import logging
import time
from collections.abc import Callable, Sequence
from enum import Enum

from pydantic import Field, field_validator

from .adapters import InvestigationContext, safe_text
from .evidence import evidence_text, normalize_evidence_references, strongest_evidence
from .models import EvidenceReference, InvestigationBaseModel, utc_now


logger = logging.getLogger(__name__)


class InvestigationRetrievalType(str, Enum):
    SAME_HOST_EVENTS = "SAME_HOST_EVENTS"
    SAME_USER_EVENTS = "SAME_USER_EVENTS"
    SAME_IP_EVENTS = "SAME_IP_EVENTS"
    SAME_RULE_EVENTS = "SAME_RULE_EVENTS"
    RELATED_ALERTS = "RELATED_ALERTS"
    MITRE_RELATED_EVENTS = "MITRE_RELATED_EVENTS"
    TIMELINE_EXPANSION = "TIMELINE_EXPANSION"
    PACKAGE_ACTIVITY = "PACKAGE_ACTIVITY"
    SUDO_ACTIVITY = "SUDO_ACTIVITY"
    AUTH_ACTIVITY = "AUTH_ACTIVITY"
    DNS_ACTIVITY = "DNS_ACTIVITY"
    NETWORK_ACTIVITY = "NETWORK_ACTIVITY"


class InvestigationRetrievalStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"
    LIMIT_REACHED = "LIMIT_REACHED"


class InvestigationRetrievalPriority(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class InvestigationRetrievalLimits(InvestigationBaseModel):
    max_depth: int = 1
    max_objects: int = 25
    max_requests: int = 8
    max_timeline_expansion: int = 20
    max_related_entities: int = 10
    timeout_seconds: float = 2.0

    @field_validator("max_depth", mode="before")
    @classmethod
    def normalize_max_depth(cls, value: object) -> int:
        return max(0, min(3, int(value or 0)))

    @field_validator("max_objects", "max_timeline_expansion", mode="before")
    @classmethod
    def normalize_object_limits(cls, value: object) -> int:
        return max(1, min(100, int(value or 1)))

    @field_validator("max_requests", mode="before")
    @classmethod
    def normalize_max_requests(cls, value: object) -> int:
        return max(1, min(20, int(value or 1)))

    @field_validator("max_related_entities", mode="before")
    @classmethod
    def normalize_max_related_entities(cls, value: object) -> int:
        return max(1, min(50, int(value or 1)))

    @field_validator("timeout_seconds", mode="before")
    @classmethod
    def normalize_timeout_seconds(cls, value: object) -> float:
        return max(0.1, min(30.0, float(value or 0.1)))


class InvestigationRetrievalRequest(InvestigationBaseModel):
    request_id: str
    request_type: InvestigationRetrievalType
    reason: str
    priority: InvestigationRetrievalPriority = InvestigationRetrievalPriority.MEDIUM
    evidence_requested: list[str] = Field(default_factory=list)
    entity_filters: dict[str, list[str]] = Field(default_factory=dict)
    source_systems: list[str] = Field(default_factory=list)
    window_minutes: int = 120
    max_results: int = 5
    depth: int = 0


class InvestigationRetrievalResult(InvestigationBaseModel):
    request_id: str
    request_type: InvestigationRetrievalType
    status: InvestigationRetrievalStatus
    evidence: list[EvidenceReference] = Field(default_factory=list)
    requested_at: str
    completed_at: str | None = None
    duration_ms: int = 0
    limits_applied: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)
    skipped_reason: str | None = None


class InvestigationRetrievalContext(InvestigationBaseModel):
    base_context: InvestigationContext
    candidate_evidence: list[EvidenceReference] = Field(default_factory=list)
    limits: InvestigationRetrievalLimits = Field(default_factory=InvestigationRetrievalLimits)


class InvestigationEvidenceExpansion(InvestigationBaseModel):
    requests: list[InvestigationRetrievalRequest] = Field(default_factory=list)
    results: list[InvestigationRetrievalResult] = Field(default_factory=list)
    merged_evidence: list[EvidenceReference] = Field(default_factory=list)
    audit: list[str] = Field(default_factory=list)
    limits_applied: list[str] = Field(default_factory=list)


RetrievalFetcher = Callable[
    [InvestigationRetrievalRequest, InvestigationRetrievalContext],
    list[EvidenceReference],
]


RETRIEVAL_KEYWORDS: dict[InvestigationRetrievalType, tuple[str, ...]] = {
    InvestigationRetrievalType.SAME_HOST_EVENTS: ("host", "agent", "endpoint"),
    InvestigationRetrievalType.SAME_USER_EVENTS: ("user", "account", "principal"),
    InvestigationRetrievalType.SAME_IP_EVENTS: ("ip", "src", "dst", "source", "destination"),
    InvestigationRetrievalType.SAME_RULE_EVENTS: ("rule", "signature"),
    InvestigationRetrievalType.RELATED_ALERTS: ("alert", "security_alert", "raw_event", "incident"),
    InvestigationRetrievalType.MITRE_RELATED_EVENTS: ("mitre", "attack", "technique"),
    InvestigationRetrievalType.TIMELINE_EXPANSION: ("timeline", "timestamp", "event", "sequence"),
    InvestigationRetrievalType.PACKAGE_ACTIVITY: ("package", "install", "process", "file", "hash"),
    InvestigationRetrievalType.SUDO_ACTIVITY: ("sudo", "privilege", "escalation", "root"),
    InvestigationRetrievalType.AUTH_ACTIVITY: ("auth", "login", "ssh", "accepted password", "session"),
    InvestigationRetrievalType.DNS_ACTIVITY: ("dns", "query", "domain", "resolver"),
    InvestigationRetrievalType.NETWORK_ACTIVITY: ("network", "suricata", "connection", "outbound", "dest"),
}


PRIORITY_ORDER = {
    InvestigationRetrievalPriority.HIGH: 0,
    InvestigationRetrievalPriority.MEDIUM: 1,
    InvestigationRetrievalPriority.LOW: 2,
}


def _entity_filters_from_context(
    context: InvestigationContext,
    evidence: list[EvidenceReference],
    limits: InvestigationRetrievalLimits,
) -> dict[str, list[str]]:
    filters: dict[str, set[str]] = {
        "host": set(),
        "user": set(),
        "ip": set(),
        "rule_id": set(),
        "mitre": set(),
    }

    for value in (
        context.incident.get("agent"),
        context.incident.get("host"),
    ):
        text = safe_text(value)
        if text:
            filters["host"].add(text)

    for value in (
        context.incident.get("user"),
        context.incident.get("rule_id"),
        context.incident.get("rule"),
        context.incident.get("mitre"),
    ):
        text = safe_text(value)
        if not text:
            continue
        if value == context.incident.get("user"):
            filters["user"].add(text)
        elif value in (context.incident.get("rule_id"), context.incident.get("rule")):
            filters["rule_id"].add(text)
        else:
            filters["mitre"].add(text)

    for item in evidence:
        for key, value in (
            ("host", item.host),
            ("user", item.user),
            ("ip", item.source_ip),
            ("ip", item.destination_ip),
            ("rule_id", item.rule_id),
            ("mitre", item.mitre_technique),
        ):
            text = safe_text(value)
            if text:
                filters[key].add(text)

    return {
        key: sorted(values)[: limits.max_related_entities]
        for key, values in filters.items()
        if values
    }


def _request_type_for_missing_evidence(value: str) -> list[InvestigationRetrievalType]:
    text = value.lower()
    if "successful login" in text or "auth" in text or "ssh" in text:
        return [InvestigationRetrievalType.AUTH_ACTIVITY, InvestigationRetrievalType.SAME_USER_EVENTS]
    if "sudo" in text or "privilege" in text:
        return [InvestigationRetrievalType.SUDO_ACTIVITY, InvestigationRetrievalType.SAME_USER_EVENTS]
    if "process" in text or "file hash" in text or "package" in text:
        return [InvestigationRetrievalType.PACKAGE_ACTIVITY, InvestigationRetrievalType.SAME_HOST_EVENTS]
    if "dns" in text:
        return [InvestigationRetrievalType.DNS_ACTIVITY, InvestigationRetrievalType.NETWORK_ACTIVITY]
    if "outbound" in text or "network" in text:
        return [InvestigationRetrievalType.NETWORK_ACTIVITY, InvestigationRetrievalType.SAME_IP_EVENTS]
    if "timeline" in text:
        return [InvestigationRetrievalType.TIMELINE_EXPANSION]
    if "correlation" in text:
        return [InvestigationRetrievalType.RELATED_ALERTS, InvestigationRetrievalType.MITRE_RELATED_EVENTS]
    if "security alert" in text or "raw event" in text:
        return [InvestigationRetrievalType.RELATED_ALERTS, InvestigationRetrievalType.SAME_RULE_EVENTS]
    return [InvestigationRetrievalType.SAME_HOST_EVENTS]


def _priority_for_type(request_type: InvestigationRetrievalType) -> InvestigationRetrievalPriority:
    if request_type in {
        InvestigationRetrievalType.SAME_HOST_EVENTS,
        InvestigationRetrievalType.SAME_USER_EVENTS,
        InvestigationRetrievalType.SAME_IP_EVENTS,
        InvestigationRetrievalType.AUTH_ACTIVITY,
        InvestigationRetrievalType.SUDO_ACTIVITY,
    }:
        return InvestigationRetrievalPriority.HIGH
    if request_type in {
        InvestigationRetrievalType.RELATED_ALERTS,
        InvestigationRetrievalType.TIMELINE_EXPANSION,
        InvestigationRetrievalType.NETWORK_ACTIVITY,
        InvestigationRetrievalType.DNS_ACTIVITY,
    }:
        return InvestigationRetrievalPriority.MEDIUM
    return InvestigationRetrievalPriority.LOW


def _source_systems_for_type(request_type: InvestigationRetrievalType) -> list[str]:
    if request_type == InvestigationRetrievalType.DNS_ACTIVITY:
        return ["wazuh", "dns_events"]
    if request_type == InvestigationRetrievalType.NETWORK_ACTIVITY:
        return ["suricata", "network_events"]
    if request_type in {
        InvestigationRetrievalType.AUTH_ACTIVITY,
        InvestigationRetrievalType.SUDO_ACTIVITY,
        InvestigationRetrievalType.PACKAGE_ACTIVITY,
        InvestigationRetrievalType.RELATED_ALERTS,
        InvestigationRetrievalType.SAME_RULE_EVENTS,
    }:
        return ["wazuh"]
    return ["ai-soc"]


def build_retrieval_requests(
    *,
    context: InvestigationContext,
    missing_evidence: Sequence[str],
    existing_evidence: Sequence[EvidenceReference] | None = None,
    limits: InvestigationRetrievalLimits | None = None,
) -> list[InvestigationRetrievalRequest]:
    resolved_limits = limits or InvestigationRetrievalLimits()
    evidence = list(existing_evidence or normalize_evidence_references(context))
    filters = _entity_filters_from_context(context, evidence, resolved_limits)
    requests: list[InvestigationRetrievalRequest] = []
    seen_types: set[InvestigationRetrievalType] = set()

    for missing in missing_evidence:
        for request_type in _request_type_for_missing_evidence(missing):
            if request_type in seen_types:
                continue
            seen_types.add(request_type)
            max_results = resolved_limits.max_timeline_expansion if (
                request_type == InvestigationRetrievalType.TIMELINE_EXPANSION
            ) else 5
            requests.append(
                InvestigationRetrievalRequest(
                    request_id=f"retrieval-{len(requests) + 1}-{request_type.value.lower()}",
                    request_type=request_type,
                    reason=f"Missing evidence requires retrieval: {missing}",
                    priority=_priority_for_type(request_type),
                    evidence_requested=[missing],
                    entity_filters=filters,
                    source_systems=_source_systems_for_type(request_type),
                    max_results=min(max_results, resolved_limits.max_objects),
                    depth=0,
                )
            )

    prioritized = prioritize_retrieval_requests(requests)
    if len(prioritized) > resolved_limits.max_requests:
        logger.info(
            "retrieval_limits_triggered",
            extra={"limit": resolved_limits.max_requests, "requested": len(prioritized)},
        )
    return prioritized[: resolved_limits.max_requests]


def prioritize_retrieval_requests(
    requests: Sequence[InvestigationRetrievalRequest],
) -> list[InvestigationRetrievalRequest]:
    return sorted(
        requests,
        key=lambda request: (
            PRIORITY_ORDER.get(request.priority, 9),
            request.request_type.value,
            request.request_id,
        ),
    )


def _matches_entity_filters(
    evidence: EvidenceReference,
    filters: dict[str, list[str]],
) -> bool:
    if not filters:
        return True

    text = evidence_text(evidence).lower()
    for values in filters.values():
        if any(value.lower() in text for value in values):
            return True
    return False


def _matches_request_type(
    evidence: EvidenceReference,
    request_type: InvestigationRetrievalType,
) -> bool:
    text = evidence_text(evidence).lower()
    keywords = RETRIEVAL_KEYWORDS.get(request_type, ())
    return any(keyword in text for keyword in keywords)


def _filter_candidate_evidence(
    request: InvestigationRetrievalRequest,
    retrieval_context: InvestigationRetrievalContext,
) -> list[EvidenceReference]:
    matches: list[EvidenceReference] = []

    for item in retrieval_context.candidate_evidence:
        entity_match = _matches_entity_filters(item, request.entity_filters)
        type_match = _matches_request_type(item, request.request_type)

        if entity_match and type_match:
            matches.append(item)

    return strongest_evidence(matches, limit=request.max_results)


def execute_retrieval_request(
    request: InvestigationRetrievalRequest,
    retrieval_context: InvestigationRetrievalContext,
    *,
    fetcher: RetrievalFetcher | None = None,
) -> InvestigationRetrievalResult:
    requested_at = utc_now().isoformat()
    start = time.monotonic()
    limits_applied: list[str] = []

    logger.info(
        "investigation_retrieval_requested",
        extra={"request_id": request.request_id, "request_type": request.request_type.value},
    )

    if request.depth > retrieval_context.limits.max_depth:
        logger.info(
            "investigation_retrieval_skipped",
            extra={"request_id": request.request_id, "reason": "max_depth_exceeded"},
        )
        return InvestigationRetrievalResult(
            request_id=request.request_id,
            request_type=request.request_type,
            status=InvestigationRetrievalStatus.SKIPPED,
            requested_at=requested_at,
            completed_at=utc_now().isoformat(),
            skipped_reason="max_depth_exceeded",
            limits_applied=["max_depth"],
        )

    try:
        evidence = fetcher(request, retrieval_context) if fetcher else _filter_candidate_evidence(
            request,
            retrieval_context,
        )
        evidence = strongest_evidence(list(evidence), limit=request.max_results)
        duration_ms = int((time.monotonic() - start) * 1000)

        status = InvestigationRetrievalStatus.COMPLETED
        failures: list[str] = []
        if duration_ms > int(retrieval_context.limits.timeout_seconds * 1000):
            status = InvestigationRetrievalStatus.PARTIAL
            failures.append("retrieval_timeout_exceeded")
            limits_applied.append("timeout_seconds")

        if len(evidence) >= request.max_results:
            limits_applied.append("max_results")

        logger.info(
            "investigation_retrieval_completed",
            extra={
                "request_id": request.request_id,
                "request_type": request.request_type.value,
                "evidence_count": len(evidence),
                "duration_ms": duration_ms,
            },
        )
        return InvestigationRetrievalResult(
            request_id=request.request_id,
            request_type=request.request_type,
            status=status,
            evidence=evidence,
            requested_at=requested_at,
            completed_at=utc_now().isoformat(),
            duration_ms=duration_ms,
            limits_applied=limits_applied,
            failures=failures,
        )

    except TimeoutError:
        logger.warning(
            "investigation_retrieval_failure",
            extra={"request_id": request.request_id, "reason": "timeout"},
        )
        return InvestigationRetrievalResult(
            request_id=request.request_id,
            request_type=request.request_type,
            status=InvestigationRetrievalStatus.FAILED,
            requested_at=requested_at,
            completed_at=utc_now().isoformat(),
            duration_ms=int((time.monotonic() - start) * 1000),
            failures=["timeout"],
        )
    except Exception as exc:
        logger.warning(
            "investigation_retrieval_failure",
            extra={"request_id": request.request_id, "reason": exc.__class__.__name__},
        )
        return InvestigationRetrievalResult(
            request_id=request.request_id,
            request_type=request.request_type,
            status=InvestigationRetrievalStatus.FAILED,
            requested_at=requested_at,
            completed_at=utc_now().isoformat(),
            duration_ms=int((time.monotonic() - start) * 1000),
            failures=[exc.__class__.__name__],
        )


def merge_evidence(
    existing_evidence: Sequence[EvidenceReference],
    retrieved_evidence: Sequence[EvidenceReference],
) -> list[EvidenceReference]:
    merged: list[EvidenceReference] = []
    seen: set[str] = set()

    for item in [*existing_evidence, *retrieved_evidence]:
        if item.evidence_id in seen:
            continue
        seen.add(item.evidence_id)
        merged.append(item)

    return merged


def run_bounded_retrieval(
    *,
    context: InvestigationContext,
    missing_evidence: Sequence[str],
    candidate_evidence: Sequence[EvidenceReference] | None = None,
    limits: InvestigationRetrievalLimits | None = None,
    fetcher: RetrievalFetcher | None = None,
) -> InvestigationEvidenceExpansion:
    resolved_limits = limits or InvestigationRetrievalLimits()
    existing_evidence = normalize_evidence_references(context)
    retrieval_context = InvestigationRetrievalContext(
        base_context=context,
        candidate_evidence=list(candidate_evidence or []),
        limits=resolved_limits,
    )
    requests = build_retrieval_requests(
        context=context,
        missing_evidence=missing_evidence,
        existing_evidence=existing_evidence,
        limits=resolved_limits,
    )
    results: list[InvestigationRetrievalResult] = []
    retrieved: list[EvidenceReference] = []
    limits_applied: list[str] = []

    for request in requests:
        if len(retrieved) >= resolved_limits.max_objects:
            limits_applied.append("max_objects")
            logger.info(
                "retrieval_limits_triggered",
                extra={"limit": "max_objects", "max_objects": resolved_limits.max_objects},
            )
            break

        result = execute_retrieval_request(request, retrieval_context, fetcher=fetcher)
        allowed = max(0, resolved_limits.max_objects - len(retrieved))
        result_evidence = result.evidence[:allowed]

        if len(result.evidence) > allowed:
            result = result.model_copy(
                update={
                    "evidence": result_evidence,
                    "limits_applied": [*result.limits_applied, "max_objects"],
                    "status": InvestigationRetrievalStatus.LIMIT_REACHED,
                }
            )

        retrieved.extend(result_evidence)
        results.append(result)
        limits_applied.extend(result.limits_applied)

    merged = merge_evidence(existing_evidence, retrieved)
    audit = [
        f"{result.request_type.value}: {result.status.value} ({len(result.evidence)} evidence item(s))"
        for result in results
    ]

    return InvestigationEvidenceExpansion(
        requests=requests,
        results=results,
        merged_evidence=merged,
        audit=audit,
        limits_applied=sorted(set(limits_applied)),
    )


def evidence_from_contexts(
    contexts: Sequence[InvestigationContext],
) -> list[EvidenceReference]:
    evidence: list[EvidenceReference] = []
    for context in contexts:
        evidence.extend(normalize_evidence_references(context))
    return merge_evidence([], evidence)
