from __future__ import annotations

from uuid import uuid4

from .models import (
    ConfidenceAssessment,
    InvestigationBrief,
    InvestigationConfidenceLevel,
    InvestigationLimitation,
    InvestigationSessionStatus,
    RecommendedCheck,
    RecommendedCheckPriority,
)
from .validators import assert_valid_investigation_brief


def _new_session_id() -> str:
    return f"investigation-{uuid4().hex}"


def create_empty_investigation_brief(
    incident_id: int,
    *,
    session_id: str | None = None,
    summary: str | None = None,
) -> InvestigationBrief:
    brief = InvestigationBrief(
        incident_id=incident_id,
        session_id=session_id or _new_session_id(),
        status=InvestigationSessionStatus.INITIAL_ANALYSIS,
        summary=summary or "No structured investigation brief has been generated yet.",
        confidence=ConfidenceAssessment(
            score=0,
            level=InvestigationConfidenceLevel.UNKNOWN,
            rationale="No investigation evidence has been evaluated in this structured session.",
        ),
        limitations=[
            InvestigationLimitation(
                limitation_id="initial-brief-no-evidence",
                description="Structured investigation has not evaluated incident evidence yet.",
                impact="The brief is a placeholder and must not be treated as an analytical conclusion.",
                missing_data=["incident evidence", "correlation context", "analyst validation"],
                suggested_resolution="Generate or attach a structured investigation brief before making investigation decisions.",
            )
        ],
        next_investigation_steps=[
            "Review the incident evidence, correlation context and analyst notes before drawing conclusions."
        ],
    )
    assert_valid_investigation_brief(brief)
    return brief


def create_fallback_investigation_brief(
    incident_id: int,
    *,
    session_id: str | None = None,
    summary: str | None = None,
    reason: str | None = None,
) -> InvestigationBrief:
    fallback_reason = reason or "Structured investigation output was not available."
    brief = InvestigationBrief(
        incident_id=incident_id,
        session_id=session_id or _new_session_id(),
        status=InvestigationSessionStatus.NEEDS_HUMAN_INPUT,
        summary=summary or "Structured investigation requires analyst review before conclusions are drawn.",
        risk_assessment="Risk cannot be fully assessed from the fallback brief alone.",
        confidence=ConfidenceAssessment(
            score=10,
            level=InvestigationConfidenceLevel.LOW,
            rationale=fallback_reason,
            missing_evidence=["structured hypotheses", "validated evidence references"],
        ),
        recommended_checks=[
            RecommendedCheck(
                check_id="review-primary-incident-evidence",
                title="Review primary incident evidence",
                description="Review the source alert, correlation summary, related telemetry and analyst notes.",
                priority=RecommendedCheckPriority.HIGH,
                reason="Fallback output cannot establish evidence-backed conclusions.",
                expected_evidence=[
                    "source alert",
                    "correlation summary",
                    "related events",
                    "analyst validation",
                ],
                requires_human_input=True,
            )
        ],
        limitations=[
            InvestigationLimitation(
                limitation_id="fallback-structured-investigation-unavailable",
                description=fallback_reason,
                impact="The fallback brief is suitable for workflow continuity only.",
                missing_data=["validated hypotheses", "evidence-backed findings", "confidence evolution"],
                suggested_resolution="Run a full structured investigation step when the engine is available.",
            )
        ],
        next_investigation_steps=[
            "Validate the source alert and correlation context.",
            "Document supporting and contradictory evidence before selecting remediation.",
        ],
    )
    assert_valid_investigation_brief(brief)
    return brief
