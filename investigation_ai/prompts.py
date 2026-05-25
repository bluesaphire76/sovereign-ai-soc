from __future__ import annotations

import json
from typing import Any

from .adapters import InvestigationContext, mitre_techniques_from_context
from .evidence import normalize_evidence_references


INVESTIGATION_SYSTEM_PROMPT = """You are a structured SOC investigation engine.

Produce evidence-backed, human-in-the-loop investigation output for an enterprise SOC platform.
Do not execute actions. Do not claim certainty unless the provided evidence directly supports it.
Classify major claims as EVIDENCE_BACKED, INFERRED, SPECULATIVE or UNSUPPORTED.
Operational recommendations must require analyst or admin approval and execution_supported must be false.
Return only valid JSON. Do not include chain-of-thought, markdown fences, prose outside JSON, or remediation execution instructions.
"""


def _trim_text(value: Any, limit: int = 2400) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value or "")
    text = text.strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated]"


def build_investigation_prompt(context: InvestigationContext) -> str:
    evidence = [
        item.model_dump(mode="json", exclude_none=True)
        for item in normalize_evidence_references(context)
    ]
    mitre_techniques = mitre_techniques_from_context(context)

    payload = {
        "incident_id": context.incident_id,
        "incident": context.incident,
        "raw_event_count": len(context.raw_events),
        "security_alert_count": len(context.security_alerts),
        "correlation_summary": context.correlation_summary,
        "mitre_techniques": mitre_techniques,
        "related_entities": context.related_entities,
        "timeline": context.timeline[:12],
        "existing_ai_analysis": context.existing_ai_analysis,
        "evidence_references": evidence[:20],
    }

    schema_hint = {
        "summary": "Short professional investigation summary.",
        "risk_assessment": "Risk rationale with uncertainty where appropriate.",
        "hypotheses": [
            {
                "hypothesis_id": "hypothesis-1",
                "title": "Hypothesis title",
                "statement": "Evidence-aware hypothesis statement.",
                "status": "ACTIVE",
                "confidence": {
                    "score": 0,
                    "level": "LOW",
                    "rationale": "Why this confidence was assigned.",
                    "positive_signals": [],
                    "negative_signals": [],
                    "missing_evidence": [],
                    "contradictory_evidence": [],
                    "scoring_factors": [],
                },
                "supporting_evidence": [],
                "missing_evidence": [],
                "contradicting_evidence": [],
                "claim_classification": "INFERRED",
                "rationale": "Explain support and uncertainty.",
                "related_mitre_techniques": [],
            }
        ],
        "findings": [
            {
                "finding_id": "finding-1",
                "finding_type": "INDICATOR",
                "title": "Finding title",
                "description": "Finding description.",
                "claim_classification": "INFERRED",
                "confidence": {"score": 0, "level": "LOW", "scoring_factors": []},
                "evidence": [],
                "business_impact": None,
                "technical_impact": None,
            }
        ],
        "recommended_checks": [
            {
                "check_id": "check-1",
                "title": "Recommended check",
                "description": "What the analyst should verify.",
                "priority": "HIGH",
                "reason": "Why the check matters.",
                "expected_evidence": [],
                "related_hypothesis_ids": [],
                "suggested_query": None,
                "source_system": None,
                "requires_human_input": True,
            }
        ],
        "recommended_actions": [
            {
                "action_id": "action-1",
                "title": "Decision-support action",
                "description": "No execution. Analyst-controlled decision support only.",
                "category": "INVESTIGATION",
                "approval_requirement": "ANALYST_APPROVAL",
                "reason": "Why this action is recommended.",
                "expected_impact": None,
                "risk": None,
                "rollback_notes": None,
                "related_hypothesis_ids": [],
                "related_evidence_ids": [],
                "execution_supported": False,
            }
        ],
        "evidence_used": [],
        "confidence": {
            "score": 0,
            "level": "LOW",
            "rationale": "Overall confidence rationale.",
            "positive_signals": [],
            "negative_signals": [],
            "missing_evidence": [],
            "contradictory_evidence": [],
            "scoring_factors": [],
        },
        "limitations": [],
        "next_investigation_steps": [],
    }

    return "\n".join(
        [
            "Generate a structured InvestigationBrief-compatible JSON object.",
            "Do not include incident_id, session_id, generated_at or status; the engine will assign those fields.",
            "Use only the evidence and context provided below.",
            "Do not represent contextual DNS or network telemetry as causal evidence unless the supplied data explicitly says so.",
            "Every hypothesis must include supporting_evidence or explicit missing_evidence.",
            "Every operational recommendation must require approval and remain non-executable.",
            "",
            "Expected JSON shape:",
            _trim_text(schema_hint, limit=5000),
            "",
            "Investigation context:",
            _trim_text(payload, limit=9000),
        ]
    )
