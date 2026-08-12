from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from services.assistant.v3.contracts import V3AnalyticalContextPackage
from services.assistant.v3.plan_schema import (
    available_absence_fields,
    model_facing_evidence,
)
from services.assistant.v3.quality_policy import (
    evidence_priority_for_atom,
    plan_contract,
)


@dataclass(frozen=True)
class V3PromptBuildResult:
    messages: list[dict[str, str]]
    context_chars: int


def _atom_projection(
    atom: Any,
    *,
    package: V3AnalyticalContextPackage,
) -> dict[str, Any]:
    value = atom.model_dump(mode="json", exclude={"provenance", "authority_class"})
    return {
        "ref": value.pop("atom_id"),
        "evidence_priority": evidence_priority_for_atom(package, atom).value,
        **value,
    }


def _relationship_projection(relationship: Any) -> dict[str, Any]:
    return {
        "ref": relationship.relationship_id,
        "class": relationship.relationship_class.value,
        "type": relationship.relationship_type.value,
        "authority": relationship.authority_class.value,
        "left_incident_id": relationship.left_incident_id,
        "right_incident_id": relationship.right_incident_id,
        "evidence_refs": relationship.evidence_atom_refs,
        "strength": relationship.strength,
    }


def _candidate_projection(candidate: Any) -> dict[str, Any]:
    return {
        "ref": candidate.candidate_id,
        "incident_id": candidate.candidate_incident_id,
        "signals": [item.value for item in candidate.discovery_signals],
        "semantic_score": candidate.semantic_score,
        "ranking_score": candidate.ranking_score,
        "discovery_source": candidate.discovery_source,
    }


def _knowledge_projection(atom: Any) -> dict[str, Any]:
    result = {
        "ref": atom.knowledge_id,
        "type": atom.knowledge_type,
        "subject": atom.subject,
        "authority": atom.authority_class.value,
    }
    if hasattr(atom, "action_code"):
        return {
            **result,
            "action": atom.action_code.value,
            "reason": atom.reason_code.value,
            "target": atom.target_type.value,
            "context": atom.context_code.value,
        }
    return {**result, "content": atom.bounded_content}


def build_v3_plan_messages(
    package: V3AnalyticalContextPackage,
    *,
    max_context_chars: int,
    required_section_codes: tuple[str, ...] = (),
) -> V3PromptBuildResult:
    view = model_facing_evidence(package)
    usefulness = plan_contract(package.intent_selection.primary_intent)
    payload = {
        "question": package.question,
        "response_language": package.response_language,
        "answer_intent": package.intent_selection.primary_intent.value,
        "secondary_intents": [
            item.value for item in package.intent_selection.secondary_intents
        ],
        "focus": [item.value for item in package.focus_selection],
        "scope": package.resolved_scope.model_dump(mode="json"),
        "usefulness_bounds": {
            "sections": [usefulness.min_sections, usefulness.max_sections],
            "propositions": [usefulness.min_units, usefulness.max_units],
        },
        "required_sections": list(required_section_codes),
        "absence_fields": [item.value for item in available_absence_fields(package)],
        "operational_atoms": [
            _atom_projection(item, package=package) for item in view.operational_atoms
        ],
        "relationships": [
            _relationship_projection(item)
            for item in view.relationships
        ],
        "candidates": [
            _candidate_projection(item) for item in view.candidates
        ],
        "reference_knowledge": [
            _knowledge_projection(item) for item in view.reference_atoms
        ],
        "advisory_knowledge": [
            _knowledge_projection(item) for item in view.advisory_atoms
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    limit = max(4000, min(int(max_context_chars), 24000))
    if len(encoded) > limit:
        raise ValueError("v3 analytical context exceeds model prompt budget")
    system = (
        "Build a grounded analytical answer plan as strict JSON. Use only refs "
        "provided in the input and permitted by the response schema. Do not write "
        "answer prose or factual values. Distinguish operational facts, platform-"
        "recorded correlation, analytical derivation, semantic similarity, reference "
        "explanation, and advisory guidance. Semantic candidates are comparison "
        "candidates only. Never infer causality, attacker, campaign, compromise, "
        "lateral movement, persistence, maliciousness, severity, risk band, or "
        "escalation state. Select the smallest useful set of non-repetitive sections "
        "and propositions that directly answer the requested intent. Choose ordering, "
        "proposition/role mode and importance from the closed schema. "
        "Include every section listed in required_sections. "
        "Sections map to bounded arrays of proposition units. Each unit contains kind, "
        "mode, importance, and either refs or code. Lead with substantive "
        "evidence; place limitations after the answer unless the requested fact is "
        "unavailable. Include a closed "
        "non-implication when analytical or semantic relationships could mislead. "
        "Use refs only for evidence-backed units and code only for absence, "
        "non-implication, or limitation units."
    )
    return V3PromptBuildResult(
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": encoded},
        ],
        context_chars=len(encoded),
    )
