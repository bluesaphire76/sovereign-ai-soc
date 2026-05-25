from __future__ import annotations

import logging
from collections.abc import Sequence

from pydantic import Field

from .adapters import InvestigationContext
from .models import (
    EvidenceReference,
    InvestigationBaseModel,
    InvestigationBrief,
    InvestigationHypothesis,
    RecommendedCheck,
    RecommendedCheckPriority,
)
from .retrieval import (
    InvestigationEvidenceExpansion,
    InvestigationRetrievalLimits,
    RetrievalFetcher,
    evidence_from_contexts,
    merge_evidence,
    run_bounded_retrieval,
)


logger = logging.getLogger(__name__)


class InvestigationExpansionResult(InvestigationBaseModel):
    enrichment_performed: bool = False
    missing_evidence_requested: list[str] = Field(default_factory=list)
    retrieved_evidence: list[EvidenceReference] = Field(default_factory=list)
    expansion: InvestigationEvidenceExpansion = Field(default_factory=InvestigationEvidenceExpansion)
    confidence_delta: int = 0
    audit: list[str] = Field(default_factory=list)


def missing_evidence_from_brief(brief: InvestigationBrief) -> list[str]:
    values: list[str] = []
    values.extend(brief.confidence.missing_evidence)

    for hypothesis in brief.hypotheses:
        values.extend(hypothesis.missing_evidence)

    for limitation in brief.limitations:
        values.extend(limitation.missing_data)

    return sorted({value for value in values if value})


def build_candidate_evidence(
    *,
    retrieval_contexts: Sequence[InvestigationContext] | None = None,
    retrieval_evidence: Sequence[EvidenceReference] | None = None,
) -> list[EvidenceReference]:
    candidates: list[EvidenceReference] = []
    if retrieval_contexts:
        candidates.extend(evidence_from_contexts(retrieval_contexts))
    if retrieval_evidence:
        candidates.extend(retrieval_evidence)
    return merge_evidence([], candidates)


def run_single_enrichment_pass(
    *,
    context: InvestigationContext,
    brief: InvestigationBrief,
    retrieval_contexts: Sequence[InvestigationContext] | None = None,
    retrieval_evidence: Sequence[EvidenceReference] | None = None,
    limits: InvestigationRetrievalLimits | None = None,
    fetcher: RetrievalFetcher | None = None,
) -> InvestigationExpansionResult:
    missing = missing_evidence_from_brief(brief)
    if not missing:
        logger.info(
            "investigation_retrieval_skipped",
            extra={"reason": "no_missing_evidence"},
        )
        return InvestigationExpansionResult(
            enrichment_performed=False,
            missing_evidence_requested=[],
            audit=["No missing evidence required retrieval enrichment."],
        )

    candidates = build_candidate_evidence(
        retrieval_contexts=retrieval_contexts,
        retrieval_evidence=retrieval_evidence,
    )
    expansion = run_bounded_retrieval(
        context=context,
        missing_evidence=missing,
        candidate_evidence=candidates,
        limits=limits,
        fetcher=fetcher,
    )
    existing_ids = {item.evidence_id for item in brief.evidence_used}
    retrieved = [
        item
        for item in expansion.merged_evidence
        if item.evidence_id not in existing_ids
    ]
    enrichment_performed = bool(retrieved)

    logger.info(
        "investigation_enrichment_pass_completed",
        extra={
            "missing_requested": len(missing),
            "retrieved_evidence_count": len(retrieved),
            "enrichment_performed": enrichment_performed,
        },
    )

    return InvestigationExpansionResult(
        enrichment_performed=enrichment_performed,
        missing_evidence_requested=missing,
        retrieved_evidence=retrieved,
        expansion=expansion,
        audit=expansion.audit,
    )


def resolved_missing_evidence(expansion: InvestigationEvidenceExpansion) -> set[str]:
    resolved: set[str] = set()

    for result in expansion.results:
        if not result.evidence:
            continue
        for request in expansion.requests:
            if request.request_id == result.request_id:
                resolved.update(request.evidence_requested)

    return resolved


def refine_hypothesis_missing_evidence(
    hypotheses: list[InvestigationHypothesis],
    expansion: InvestigationEvidenceExpansion,
) -> list[InvestigationHypothesis]:
    resolved = resolved_missing_evidence(expansion)
    if not resolved:
        return hypotheses

    refined: list[InvestigationHypothesis] = []
    for hypothesis in hypotheses:
        missing = [
            item
            for item in hypothesis.missing_evidence
            if item not in resolved
        ]
        refined.append(hypothesis.model_copy(update={"missing_evidence": missing}))

    return refined


def refine_recommended_checks(
    checks: list[RecommendedCheck],
    expansion: InvestigationEvidenceExpansion,
) -> list[RecommendedCheck]:
    retrieved_count = sum(len(result.evidence) for result in expansion.results)
    if retrieved_count <= 0:
        return checks

    existing_ids = {check.check_id for check in checks}
    if "check-retrieved-evidence" in existing_ids:
        return checks

    return [
        *checks,
        RecommendedCheck(
            check_id="check-retrieved-evidence",
            title="Review retrieved evidence",
            description="Review additional evidence returned by the bounded retrieval enrichment pass.",
            priority=RecommendedCheckPriority.HIGH,
            reason="Retrieved evidence can refine hypotheses and confidence but still requires analyst validation.",
            expected_evidence=["retrieved evidence references", "retrieval audit trail"],
            requires_human_input=True,
        ),
    ]
