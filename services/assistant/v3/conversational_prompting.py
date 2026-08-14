from __future__ import annotations

import json

from services.assistant.v3.contracts import V3AnalyticalContextPackage
from services.assistant.v3.plan_prompting import (
    V3PromptBuildResult,
    _atom_projection,
    _candidate_projection,
    _relationship_projection,
)
from services.assistant.v3.plan_schema import (
    available_absence_fields,
    available_limitation_codes,
    available_non_implication_codes,
)
from services.assistant.v3.conversational_schema import (
    conversational_model_facing_evidence,
)


_ANALYST_UTILITY_BY_ATOM_TYPE = {
    "incident_identity": "identify_subject_record",
    "case_identity": "identify_case_scope",
    "status": "locate_workflow_state",
    "risk": "report_recorded_numeric_assessment",
    "priority": "report_recorded_recommended_priority",
    "host": "identify_endpoint_for_verification",
    "user": "identify_observed_identity",
    "detection": "identify_triggering_detection_rule",
    "mitre_technique": "classify_recorded_technical_context",
    "timeline_event": "anchor_observation_in_time",
    "observable": "identify_observable_for_verification",
    "process": "identify_observed_process",
    "evidence": "report_recorded_evidence_detail",
    "recorded_correlation": "report_platform_correlation_state",
    "escalation_state": "report_explicit_escalation_state",
    "escalation_reason": "report_recorded_escalation_reason_only",
    "compromise_state": "report_explicit_compromise_state",
    "case_relationship": "locate_recorded_case_membership",
}


def _conversational_atom_projection(
    atom,
    *,
    package: V3AnalyticalContextPackage,
) -> dict[str, object]:
    projection = _atom_projection(atom, package=package)
    projection["analyst_utility"] = _ANALYST_UTILITY_BY_ATOM_TYPE.get(
        atom.atom_type,
        "report_recorded_observation",
    )
    return projection


def _knowledge_projection(atom) -> dict[str, object]:
    result: dict[str, object] = {
        "ref": atom.knowledge_id,
        "type": atom.knowledge_type,
        "subject": atom.subject,
        "authority": atom.authority_class.value,
        "content": atom.bounded_content,
    }
    if hasattr(atom, "action_code"):
        result.update(
            {
                "action": atom.action_code.value,
                "reason": atom.reason_code.value,
                "target": atom.target_type.value,
                "context": atom.context_code.value,
            }
        )
    return result


def build_v31_conversational_messages(
    package: V3AnalyticalContextPackage,
    *,
    max_context_chars: int,
) -> V3PromptBuildResult:
    view = conversational_model_facing_evidence(package)
    anchor_incident_ids = package.resolved_scope.active_incident_ids[:1]
    anchor_ids = set(anchor_incident_ids)
    eligible_comparison_target_ids = list(
        dict.fromkeys(
            [item.candidate_incident_id for item in view.candidates]
            + [
                incident_id
                for item in view.relationships
                for incident_id in (item.left_incident_id, item.right_incident_id)
                if incident_id not in anchor_ids
            ]
        )
    )
    payload = {
        "question": package.question,
        "response_language": package.response_language,
        "answer_intent": package.intent_selection.primary_intent.value,
        "secondary_intents": [
            item.value for item in package.intent_selection.secondary_intents
        ],
        "focus": [item.value for item in package.focus_selection],
        "writing_contract": {
            "first_segment_kind": "direct_answer",
            "evidence_significance": "analyst_utility_only",
            "next_steps": (
                "cite_advisory_guidance_claims"
                if view.advisory_atoms
                else "omit_no_advisory_available"
            ),
            "unsupported_state_policy": (
                "never_assert_unrecorded_security_state; negative caveats require c1"
            ),
            "safety_qualifier_codes": {
                "unrecorded_security_conclusions": (
                    "EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS"
                ),
                "causality": "EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY",
                "actor_or_campaign": "UNSUPPORTED_ACTOR_OR_CAMPAIGN",
                "lateral_movement": "EVIDENCE_NOT_LATERAL_MOVEMENT",
                "persistence": "EVIDENCE_NOT_PERSISTENCE",
                "qualitative_risk": "RISK_BAND_NOT_RECORDED",
                "urgency_or_business_impact": "BUSINESS_IMPACT_NOT_RECORDED",
            },
        },
        "scope": package.resolved_scope.model_dump(mode="json"),
        "anchor_incident_ids": anchor_incident_ids,
        "eligible_comparison_target_ids": eligible_comparison_target_ids,
        "absence_codes": [item.value for item in available_absence_fields(package)],
        "non_implication_codes": [
            item.value for item in available_non_implication_codes(package)
        ],
        "limitation_codes": [
            item.value for item in available_limitation_codes(package)
        ],
        "operational_atoms": [
            _conversational_atom_projection(item, package=package)
            for item in view.operational_atoms
        ],
        "relationships": [
            _relationship_projection(item) for item in view.relationships
        ],
        "candidates": [_candidate_projection(item) for item in view.candidates],
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
        raise ValueError("V3.1 analytical context exceeds model prompt budget")
    answer_flow = (
        "happened, why the strongest evidence matters, supported conclusions, "
        "important uncertainty"
    )
    if view.advisory_atoms:
        answer_flow += ", and useful next checks grounded in advisory knowledge"
    system = (
        "Write the final user-facing SOC analyst answer as strict JSON in the "
        "requested response language. The first segment MUST use kind "
        "direct_answer and answer the actual question directly. Then cover "
        f"{answer_flow}. Use exactly 2 concise segments and exactly 4 claims; "
        "reserve one code-only claim for uncertainty when the answer "
        "mentions anything not established by evidence. Keep the complete visible "
        "answer between 75 and 105 words. Each segment must contain 1 or 2 complete "
        "sentences and end with punctuation. Claim c1 MUST be the required "
        "non_implication claim and MUST support the uncertainty segment. It "
        "covers only explicitly negative statements about unrecorded security "
        "conclusions. A concise caveat may appear in the direct answer when c1 "
        "is cited; expand at most 3 material uncertainties in the second segment. "
        "Never invent hypothetical benign or malicious explanations. Claims "
        "c2 through c4 carry evidence: c2 must cite operational facts, c3 "
        "covers the strongest typed operational or cross-incident evidence, and "
        "c4 adds the most relevant typed context. Write "
        "natural, professional, connected prose rather "
        "than field lists or a technical report. Do not expose ontology names, "
        "internal refs, or repetitive headings in text. Never write c1, c2, c3, "
        "c4, C1, C2, C3, or C4 inside segment text. Use only supplied evidence. "
        "Every visible segment must cite one or more typed claim IDs, and every "
        "evidence claim must cite only supplied refs. Use code-only absence, "
        "non_implication, or limitation claims when evidence does not support a "
        "statement. Operational facts require operational atoms. Recorded "
        "correlation requires a recorded correlation atom or platform-recorded "
        "relationship. Analytical relationships are derivations, never recorded "
        "correlation or causality. Semantic similarity identifies candidates only. "
        "The second segment MUST use kind uncertainty and cite c1. "
        "Reference knowledge is not current operational state. Advisory knowledge "
        "is guidance, not recorded action or fact. Explain why evidence matters "
        "only through each atom's analyst_utility code; these codes are exhaustive, "
        "not suggestions. State what the record lets the analyst locate, compare, "
        "correlate, or verify. Do not infer intent, outcome, "
        "probability, or harmfulness. A detection atom identifies the recorded "
        "triggering rule; it never means that the rule caused the incident. "
        "Never invent any security state, attribution, causal explanation, severity, "
        "qualitative risk, urgency, impact, attack stage, or outcome. Do not "
        "describe a detection as anomalous, dangerous, malicious, a threat, or "
        "proof of harmful activity unless an operational atom explicitly records "
        "that exact state. A numeric risk score is only the recorded number; it is "
        "not a qualitative risk band, threat level, urgency, or business impact. "
        "A correlation is only its recorded platform state and does not establish "
        "compromise or causality. Only mention one of those unsupported concepts "
        "in an uncertainty segment when the segment cites a separate applicable "
        "typed non_implication claim for every unsupported concept named, or an "
        "operational atom explicitly recording that "
        "state. Next checks must cite advisory_guidance claims; "
        "if no applicable advisory ref is supplied, omit next checks. Use only "
        "claim IDs c1 through c4 and make segment claim_refs point to those IDs, "
        "not directly to evidence refs. "
        "When selecting an incident to compare, select only an ID from "
        "eligible_comparison_target_ids and never present an anchor_incident_id "
        "as the selected comparison target. "
        "Do not "
        "add fields and do not place prose outside answer.segments. Use NONE as the "
        "qualifier_code for evidence claims; code-only claims use no source refs."
    )
    return V3PromptBuildResult(
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": encoded},
        ],
        context_chars=len(encoded),
    )
