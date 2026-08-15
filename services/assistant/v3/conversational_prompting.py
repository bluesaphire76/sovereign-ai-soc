from __future__ import annotations

import json

from services.assistant.v3.conversational_contracts import ConversationalClaimType
from services.assistant.v3.contracts import (
    AnswerIntent,
    DetectionAtom,
    MitreTechniqueAtom,
    RecordedCorrelationAtom,
    RelationshipClass,
    V3AnalyticalContextPackage,
)
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

_SOFT_WORD_TARGETS = {
    AnswerIntent.FACT_LOOKUP: "50-100",
    AnswerIntent.EXPLAIN: "120-200",
    AnswerIntent.SUMMARY: "90-160",
    AnswerIntent.INVESTIGATE: "100-180",
    AnswerIntent.COMPARE: "130-220",
    AnswerIntent.CROSS_INCIDENT_ANALYSIS: "140-240",
    AnswerIntent.PATTERN_ANALYSIS: "140-240",
    AnswerIntent.NEXT_ACTION: "100-180",
    AnswerIntent.HANDOVER: "90-160",
    AnswerIntent.EXECUTIVE_SUMMARY: "90-160",
}

_SOFT_FLOW_BY_INTENT = {
    AnswerIntent.FACT_LOOKUP: "direct_answer; add context only if it changes meaning",
    AnswerIntent.EXPLAIN: (
        "connect the strongest supplied facts into a coherent explanation of what was "
        "observed, where it was observed, the relevant recorded detection or exact "
        "relationship, its supplied technical classification, and the combined supported "
        "meaning; include a supported limitation only when materially useful; grounded "
        "synthesis across supplied evidence is allowed, but do not enumerate fields or "
        "speculate about cause, intent, harmfulness, attacker, outcome, probability, "
        "impact, or urgency"
    ),
    AnswerIntent.SUMMARY: "direct_answer, then optional conclusion",
    AnswerIntent.INVESTIGATE: "direct_answer, then evidence_explanation or analysis",
    AnswerIntent.COMPARE: "direct_answer, then comparison",
    AnswerIntent.CROSS_INCIDENT_ANALYSIS: "direct_answer, then comparison or pattern",
    AnswerIntent.PATTERN_ANALYSIS: "direct_answer, then pattern or analysis",
    AnswerIntent.NEXT_ACTION: "direct_answer, then advisory-grounded next_step",
    AnswerIntent.HANDOVER: "direct_answer, then evidence_explanation or conclusion",
    AnswerIntent.EXECUTIVE_SUMMARY: "executive_summary or direct_answer, then conclusion",
}

_GROUNDED_SYNTHESIS_ALLOWED = (
    "connect_supplied_operational_facts",
    "explain_what_and_where_was_observed",
    "explain_exact_recorded_relationship_meaning",
    "use_reference_knowledge_for_technical_classification",
    "summarize_combined_supported_meaning",
)

_GROUNDED_SYNTHESIS_FORBIDDEN = (
    "infer_cause_or_causality",
    "infer_intent_or_maliciousness",
    "infer_any_protected_or_unrecorded_security_state",
    "infer_unrecorded_attribution",
    "infer_probability_impact_or_urgency",
    "infer_unrecorded_outcome",
)


def _conversational_atom_projection(
    atom,
    *,
    package: V3AnalyticalContextPackage,
) -> dict[str, object]:
    projection = _atom_projection(atom, package=package)
    projection.pop("evidence_priority", None)
    projection["analyst_utility"] = _ANALYST_UTILITY_BY_ATOM_TYPE.get(
        atom.atom_type,
        "report_recorded_observation",
    )
    projection["allowed_claim_type"] = (
        ConversationalClaimType.RECORDED_CORRELATION.value
        if isinstance(atom, RecordedCorrelationAtom)
        else ConversationalClaimType.OPERATIONAL_FACT.value
    )
    if atom.atom_type == "risk" and "risk_normalization_severity" in projection:
        projection["recorded_risk_normalization"] = projection.pop(
            "risk_normalization_severity"
        )
    if (
        isinstance(atom, DetectionAtom)
        and package.intent_selection.primary_intent is AnswerIntent.EXPLAIN
    ):
        projection.pop("level", None)
    if projection.get("canonical_severity") is None:
        projection.pop("canonical_severity", None)
    if isinstance(atom, MitreTechniqueAtom):
        if package.intent_selection.primary_intent is AnswerIntent.EXPLAIN:
            projection.pop("technique_name", None)
        matching_reference = next(
            (
                item.knowledge_id
                for item in package.reference_atoms
                if item.knowledge_type == "mitre_definition"
                and item.subject == atom.technique_id
            ),
            None,
        )
        if matching_reference is not None:
            projection["matching_reference_ref"] = matching_reference
    return {key: value for key, value in projection.items() if value is not None}


def _conversational_relationship_projection(relationship) -> dict[str, object]:
    projection = _relationship_projection(relationship)
    projection["allowed_claim_type"] = {
        RelationshipClass.RECORDED_CORRELATION: (
            ConversationalClaimType.RECORDED_CORRELATION.value
        ),
        RelationshipClass.ANALYTICAL_RELATIONSHIP: (
            ConversationalClaimType.ANALYTICAL_RELATIONSHIP.value
        ),
        RelationshipClass.SEMANTIC_SIMILARITY: (
            ConversationalClaimType.SEMANTIC_CANDIDATE.value
        ),
    }[relationship.relationship_class]
    return projection


def _conversational_candidate_projection(candidate) -> dict[str, object]:
    projection = _candidate_projection(candidate)
    projection["allowed_claim_type"] = (
        ConversationalClaimType.SEMANTIC_CANDIDATE.value
    )
    return projection


def _knowledge_projection(atom) -> dict[str, object]:
    result: dict[str, object] = {
        "ref": atom.knowledge_id,
        "type": atom.knowledge_type,
        "subject": atom.subject,
        "authority": atom.authority_class.value,
        "content": atom.bounded_content,
        "allowed_claim_type": (
            ConversationalClaimType.ADVISORY_GUIDANCE.value
            if hasattr(atom, "action_code")
            else ConversationalClaimType.REFERENCE_EXPLANATION.value
        ),
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
    intent = package.intent_selection.primary_intent
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
    absence_codes = (
        []
        if intent is AnswerIntent.EXPLAIN
        else [item.value for item in available_absence_fields(package)]
    )
    non_implication_codes = [
        item.value for item in available_non_implication_codes(package)
    ]
    limitation_codes = (
        []
        if intent is AnswerIntent.EXPLAIN
        else [item.value for item in available_limitation_codes(package)]
    )
    scope_projection = {
        key: value
        for key, value in package.resolved_scope.model_dump(mode="json").items()
        if value is not None and value != []
    }
    payload = {
        "question": package.question,
        "response_language": package.response_language,
        "answer_intent": package.intent_selection.primary_intent.value,
        "secondary_intents": [
            item.value for item in package.intent_selection.secondary_intents
        ],
        "focus": [item.value for item in package.focus_selection],
        "writing_contract": {
            "first_segment_kind": (
                "direct_answer_or_executive_summary"
                if intent is AnswerIntent.EXECUTIVE_SUMMARY
                else "direct_answer"
            ),
            "segment_count": "1_to_4_as_needed",
            "claim_count": "1_to_8_as_needed",
            "claim_refs_per_segment": "1_to_4_relevant_claims_only",
            "claim_selection": "use_fewest_strong_claims; never_fill_slots",
            "soft_word_target": _SOFT_WORD_TARGETS[intent],
            "soft_intent_flow": _SOFT_FLOW_BY_INTENT[intent],
            "uncertainty": "include_only_when_materially_relevant",
            "protected_concepts": (
                "omit_by_default; before naming or negating one, create a matching "
                "non_implication claim and cite it from that exact segment"
            ),
            "detection_level": (
                "report_only_as_detection_rule_level; never rename it incident_severity "
                "or interpret it as suspicious_or_malicious_activity"
            ),
            "evidence_significance": (
                "analyst_utility_is_maximum_defensible_meaning_not_prose_recipe"
            ),
            "grounded_synthesis": {
                "allowed": list(_GROUNDED_SYNTHESIS_ALLOWED),
                "forbidden": list(_GROUNDED_SYNTHESIS_FORBIDDEN),
            },
            "explain_evidence_priority": (
                "observed_event_then_location_then_exact_detection_or_relationship_"
                "then_matching_technical_reference; status_risk_priority_timeline_"
                "only_when_they_change_the_answer"
            ),
            "next_steps": (
                "cite_advisory_guidance_claims"
                if view.advisory_atoms
                else "omit_no_advisory_available"
            ),
            "unsupported_state_policy": (
                "never_assert_unrecorded_security_state; negative caveats require "
                "a matching non_implication claim in the same segment"
            ),
        },
        "scope": scope_projection,
        "anchor_incident_ids": anchor_incident_ids,
        "eligible_comparison_target_ids": eligible_comparison_target_ids,
        "code_claim_options": [
            *(
                {
                    "claim_type": ConversationalClaimType.ABSENCE.value,
                    "source_refs": [],
                    "qualifier_code": code,
                }
                for code in absence_codes
            ),
            *(
                {
                    "claim_type": ConversationalClaimType.NON_IMPLICATION.value,
                    "source_refs": [],
                    "qualifier_code": code,
                }
                for code in non_implication_codes
            ),
            *(
                {
                    "claim_type": ConversationalClaimType.LIMITATION.value,
                    "source_refs": [],
                    "qualifier_code": code,
                }
                for code in limitation_codes
            ),
        ],
        "operational_atoms": [
            _conversational_atom_projection(item, package=package)
            for item in view.operational_atoms
        ],
        "relationships": [
            _conversational_relationship_projection(item)
            for item in view.relationships
        ],
        "candidates": [
            _conversational_candidate_projection(item) for item in view.candidates
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
        raise ValueError("V3.1 analytical context exceeds model prompt budget")
    system = (
        "Answer the user's actual question as a professional SOC analyst. Start "
        "with the direct answer, then explain only evidence that materially helps "
        "the analyst understand the situation. Distinguish recorded operational "
        "facts, analytical relationships, reference knowledge, advisory guidance, "
        "and uncertainty. Prefer connected explanatory prose; do not restate "
        "database fields merely because they are available. Explain what the "
        "strongest evidence means in natural language. Each atom's analyst_utility is "
        "its maximum defensible analytical meaning, not wording to copy or a prose "
        "recipe. Grounded synthesis is allowed: connect multiple supplied operational "
        "facts; explain what and where the record observed; explain a recorded "
        "relationship only within its exact class; use supplied reference knowledge "
        "to explain technical classification; and summarize the combined supported "
        "meaning. Grounded synthesis must not infer cause, intent, maliciousness, "
        "compromise, persistence, lateral movement, causality, attacker, campaign, "
        "probability, business impact, urgency, or any unrecorded outcome. Write in the "
        "requested response "
        "language and return the final user-facing answer as strict JSON. The first "
        "segment MUST use kind direct_answer, except that a genuine "
        "EXECUTIVE_SUMMARY intent may use executive_summary. Choose one to four "
        "segments and one to eight claims according to the resolved intent and "
        "available evidence. Uncertainty is optional. For an ordinary explanation, "
        "describe supported events and significance without adding a generic list "
        "of unsupported states. Follow this soft intent flow: "
        f"{_SOFT_FLOW_BY_INTENT[intent]}. This is writing guidance, not a fixed "
        "layout; a simple factual answer may still use one segment. "
        "For EXPLAIN, when supplied reference_knowledge directly classifies selected "
        "operational evidence, create a matching reference_explanation claim and cite "
        "it from the exact segment that explains the classification; keep operational "
        "and reference evidence as separate typed claims without imposing a layout. "
        "A reference definition matching a selected MITRE technique is material technical "
        "classification: select the matching operational and reference_explanation refs "
        "and explain them before considering workflow metadata. When detection, host, a "
        "MITRE technique, and its matching reference are available, they are the strongest "
        "EXPLAIN evidence; do not select status, risk, priority, or timeline unless the "
        "question asks for them. "
        "Use the fewest segments needed and keep related evidence in connected prose; "
        "do not turn available fields into an inventory or add visible section labels. "
        "Combine related supplied facts into meaningful statements instead of listing "
        "them field by field. For an ordinary technical EXPLAIN, omit workflow status, "
        "risk, priority, and timeline unless the question asks for them or they materially "
        "change the meaning of the observed event. Never include them merely to round out "
        "the answer. "
        "Do not report an unavailable or undefined field unless the question asks for it. "
        "Select the fewest strong claims needed; never fill claim slots merely because "
        "they are available. Explain the recorded technical classification, not a "
        "hypothetical cause: never use could, might, possibly, potrebbe, potrebbero, "
        "puo, or possono to invent "
        "an interpretation of operational evidence. For an ordinary EXPLAIN question, "
        "omit every protected concept entirely unless the user explicitly asks about "
        "that concept. Check the exact question in the payload: never write or negate a "
        "protected concept that is absent from the question. Code claim options are "
        "validation tools, not topics to introduce. Do not add a protected limitation "
        "or negative caveat merely because a relationship or code option is available. "
        "Explain a recorded correlation within its exact class without adding an "
        "unrelated caveat. "
        "The payload's "
        "safety_qualifier_codes and "
        "non_implication_codes define protected meanings. Omit those meanings by "
        "default. If a protected caveat directly answers the question, first create "
        "the matching code-only non_implication claim and cite that claim from the "
        "exact segment; if no matching claim is present, do not write the protected "
        "concept at all. Mention each protected concept in at most one segment, and "
        "never repeat its caveat across segments. An evidence or relationship claim "
        "alone cannot support a protected negative caveat. The soft visible-word target "
        "for this "
        f"intent is {_SOFT_WORD_TARGETS[intent]} words; this is guidance, not a "
        "hard validity rule. Each segment must contain complete sentences, end "
        "with punctuation, and cite only the one to four claims that support it. "
        "Mention only facts supported by those listed claim_refs; if another fact's "
        "claim does not fit, omit that fact from the segment. "
        "Use unique segment IDs s1 through s4 and unique claim IDs c1 through c8; "
        "claim numbers have no predefined meaning. Do not expose ontology names, "
        "claim IDs, internal refs, or repetitive headings in visible text. Use "
        "only supplied evidence. Evidence claims cite matching typed refs and use "
        "qualifier NONE; copy each ref's allowed_claim_type exactly and group refs "
        "only when they share that type. Never duplicate an identical claim merely "
        "to fill claim IDs. For a code-only claim, copy claim_type, source_refs, and "
        "qualifier_code together from one code_claim_options entry and add only a "
        "unique claim_id. Preserve every "
        "relationship_class and authority class exactly. Never promote analytical "
        "derivations, reference knowledge, advisory knowledge, or semantic candidates "
        "to operational facts or a stronger relationship class. A recorded correlation "
        "is only the platform-recorded relationship it describes and must not be "
        "promoted to any stronger relationship, state, attribution, cause, or outcome. "
        "Reference knowledge "
        "explains the technical meaning of supplied operational evidence but never "
        "records current incident or case state, intent, persistence, or maliciousness. "
        "Advisory "
        "knowledge is guidance, never a recorded action. A next_step must cite an "
        "advisory_guidance claim; otherwise omit it. When no advisory atom is supplied, "
        "do not suggest actions or use phrases such as should, recommend an action, "
        "dovrebbe, or si consiglia. "
        "Do not invent explanations, "
        "intent, outcomes, probability, or harmfulness. A detection atom identifies "
        "only the recorded triggering rule. Never "
        "rename a detection rule's numeric level as incident severity or gravita: "
        "report it only as the recorded detection-rule level, without adjectives or "
        "qualitative interpretation. In particular, never say that the level indicates "
        "suspicious, anomalous, or malicious activity. The rule level supports no "
        "conclusion about "
        "the nature or outcome of the activity. Use severity wording "
        "only when an operational status atom supplies canonical_severity. A numeric "
        "risk score is only the recorded number; report a qualitative risk band only "
        "when the authoritative risk atom records that exact normalization. "
        "When selecting an incident to compare, select only an ID from "
        "eligible_comparison_target_ids and never present an anchor_incident_id "
        "as the selected comparison target. Do not add fields or place prose "
        "outside answer.segments. Segment claim_refs contain claim IDs, never "
        "evidence refs."
    )
    return V3PromptBuildResult(
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": encoded},
        ],
        context_chars=len(encoded),
    )
