from __future__ import annotations

from typing import Any

from services.assistant.v3.conversational_contracts import (
    MAX_CONVERSATIONAL_CLAIMS,
    MAX_CONVERSATIONAL_CLAIMS_PER_SEGMENT,
    MAX_CONVERSATIONAL_SEGMENT_CHARS,
    MAX_CONVERSATIONAL_SEGMENTS,
    ConversationalClaimType,
    ConversationalQualifierCode,
    ConversationalSegmentKind,
)
from services.assistant.v3.contracts import (
    AnalysisScope,
    AnalyticalFocus,
    AnswerIntent,
    CompromiseStateAtom,
    RecordedCorrelationAtom,
    RelationshipClass,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_schema import (
    ModelFacingEvidence,
    available_absence_fields,
    available_limitation_codes,
    available_non_implication_codes,
    model_facing_evidence,
)


_MODEL_CLAIM_IDS = [f"c{index}" for index in range(1, MAX_CONVERSATIONAL_CLAIMS + 1)]

_BROAD_EXPLAIN_OPERATIONAL_CAP = 10
_BROAD_EXPLAIN_RELATIONSHIP_CAP = 2
_BROAD_EXPLAIN_CANDIDATE_CAP = 2
_BROAD_EXPLAIN_REFERENCE_CAP = 1
_BROAD_EXPLAIN_ADVISORY_CAP = 1

_BROAD_EXPLAIN_ATOM_ORDER = (
    "detection",
    "host",
    "mitre_technique",
    "evidence",
    "observable",
    "process",
    "user",
    "status",
    "risk",
    "recorded_correlation",
    "priority",
    "escalation_state",
    "escalation_reason",
    "compromise_state",
    "timeline_event",
    "case_relationship",
)
_BROAD_EXPLAIN_ATOM_TYPE_CAPS = {
    "mitre_technique": 2,
    "evidence": 2,
    "observable": 2,
}
_BROAD_EXPLAIN_TIER = {
    atom_type: tier
    for tier, atom_types in enumerate(
        (
            _BROAD_EXPLAIN_ATOM_ORDER[:7],
            _BROAD_EXPLAIN_ATOM_ORDER[7:14],
            _BROAD_EXPLAIN_ATOM_ORDER[14:],
        )
    )
    for atom_type in atom_types
}
_FOCUS_ATOM_TYPES = {
    AnalyticalFocus.RISK: frozenset({"risk"}),
    AnalyticalFocus.CORRELATION: frozenset({"recorded_correlation"}),
    AnalyticalFocus.SEVERITY: frozenset({"status"}),
    AnalyticalFocus.STATUS: frozenset({"status"}),
    AnalyticalFocus.HOST: frozenset({"host"}),
    AnalyticalFocus.EVIDENCE: frozenset(
        {"detection", "evidence", "observable", "process", "timeline_event"}
    ),
    AnalyticalFocus.PRIORITY: frozenset({"priority"}),
    AnalyticalFocus.ESCALATION: frozenset(
        {"escalation_state", "escalation_reason"}
    ),
    AnalyticalFocus.GENERAL: frozenset(),
}
_GENERIC_EXPLAIN_TIMELINE_EVENTS = frozenset(
    {
        "ALERT_CREATED",
        "CASE_CREATED",
        "CASE_UPDATED",
        "CASE_WORKFLOW_UPDATED",
        "INCIDENT_CREATED",
        "INCIDENT_UPDATED",
        "STATUS_CHANGE",
        "STATUS_CHANGED",
    }
)


def _is_current_record_explain(package: V3AnalyticalContextPackage) -> bool:
    return (
        package.intent_selection.primary_intent is AnswerIntent.EXPLAIN
        and package.resolved_scope.analysis_scope is AnalysisScope.CURRENT_RECORD
    )


def _broad_explain_atom_rank(package: V3AnalyticalContextPackage, atom) -> tuple:
    active_incident_ids = package.resolved_scope.active_incident_ids
    scope_rank = {
        incident_id: index for index, incident_id in enumerate(active_incident_ids)
    }
    focused_types = {
        atom_type
        for focus in package.focus_selection
        for atom_type in _FOCUS_ATOM_TYPES[focus]
    }
    type_rank = {
        atom_type: index
        for index, atom_type in enumerate(_BROAD_EXPLAIN_ATOM_ORDER)
    }
    return (
        scope_rank.get(atom.incident_id, len(scope_rank) + 1),
        0 if atom.atom_type in focused_types else 1,
        _BROAD_EXPLAIN_TIER.get(atom.atom_type, 3),
        type_rank.get(atom.atom_type, len(type_rank)),
        atom.incident_id or 0,
        atom.case_id or 0,
        atom.atom_id,
    )


def _broad_explain_atoms(
    package: V3AnalyticalContextPackage,
    atoms: list,
) -> tuple:
    ranked = sorted(atoms, key=lambda item: _broad_explain_atom_rank(package, item))
    selected = []
    fact_keys: set[tuple] = set()
    atom_type_counts: dict[tuple, int] = {}
    for atom in ranked:
        if atom.atom_type == "incident_identity":
            continue
        if (
            atom.atom_type == "timeline_event"
            and atom.event_type.strip().upper() in _GENERIC_EXPLAIN_TIMELINE_EVENTS
        ):
            continue
        fact_key = (
            atom.atom_type,
            atom.incident_id,
            atom.case_id,
            atom.model_dump_json(
                exclude={"atom_id", "authority_class", "provenance", "timestamp"}
            ),
        )
        if fact_key in fact_keys:
            continue
        scoped_type = (atom.atom_type, atom.incident_id, atom.case_id)
        type_cap = _BROAD_EXPLAIN_ATOM_TYPE_CAPS.get(atom.atom_type, 1)
        if atom_type_counts.get(scoped_type, 0) >= type_cap:
            continue
        fact_keys.add(fact_key)
        atom_type_counts[scoped_type] = atom_type_counts.get(scoped_type, 0) + 1
        selected.append(atom)
        if len(selected) == _BROAD_EXPLAIN_OPERATIONAL_CAP:
            break
    return tuple(selected)


def conversational_model_facing_evidence(
    package: V3AnalyticalContextPackage,
) -> ModelFacingEvidence:
    view = model_facing_evidence(package)
    visible_operational_atoms = [
        item
        for item in view.operational_atoms
        if not (
            isinstance(item, CompromiseStateAtom)
            and item.compromise_confirmed is None
        )
    ]
    broad_explain = _is_current_record_explain(package)
    if broad_explain:
        operational_atoms = _broad_explain_atoms(package, visible_operational_atoms)
        candidates = view.candidates[:_BROAD_EXPLAIN_CANDIDATE_CAP]
        available_evidence_refs = {
            item.atom_id for item in operational_atoms
        } | {item.candidate_id for item in candidates}
        relationships = tuple(
            item
            for item in view.relationships
            if set(item.evidence_atom_refs).issubset(available_evidence_refs)
        )[:_BROAD_EXPLAIN_RELATIONSHIP_CAP]
        return ModelFacingEvidence(
            operational_atoms=operational_atoms,
            relationships=relationships,
            candidates=candidates,
            reference_atoms=view.reference_atoms[:_BROAD_EXPLAIN_REFERENCE_CAP],
            advisory_atoms=view.advisory_atoms[:_BROAD_EXPLAIN_ADVISORY_CAP],
        )

    relationships = view.relationships[:3]
    required_atom_refs = {
        ref for item in relationships for ref in item.evidence_atom_refs
    }
    required_atoms = [
        item
        for item in visible_operational_atoms
        if item.atom_id in required_atom_refs
    ]
    remaining_atoms = [
        item
        for item in visible_operational_atoms
        if item.atom_id not in required_atom_refs
    ]
    operational_atoms = tuple((required_atoms + remaining_atoms)[:12])
    required_candidates = [
        item for item in view.candidates if item.candidate_id in required_atom_refs
    ]
    remaining_candidates = [
        item for item in view.candidates if item.candidate_id not in required_atom_refs
    ]
    return ModelFacingEvidence(
        operational_atoms=operational_atoms,
        relationships=relationships,
        candidates=tuple((required_candidates + remaining_candidates)[:2]),
        reference_atoms=view.reference_atoms[:1],
        advisory_atoms=view.advisory_atoms[:1],
    )


def _model_visible_refs(package: V3AnalyticalContextPackage) -> list[str]:
    view = conversational_model_facing_evidence(package)
    return list(
        dict.fromkeys(
            [item.atom_id for item in view.operational_atoms]
            + [item.relationship_id for item in view.relationships]
            + [item.candidate_id for item in view.candidates]
            + [item.knowledge_id for item in view.reference_atoms]
            + [item.knowledge_id for item in view.advisory_atoms]
        )
    )


def grounded_conversational_answer_v31_schema(
    package: V3AnalyticalContextPackage,
) -> dict[str, Any]:
    view = conversational_model_facing_evidence(package)
    if not _model_visible_refs(package):
        raise ValueError("V3.1 conversational schema requires typed evidence")
    safety_codes = list(
        dict.fromkeys(
            [item.value for item in available_non_implication_codes(package)]
            + [
                ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS.value,
                ConversationalQualifierCode.UNSUPPORTED_ACTOR_OR_CAMPAIGN.value,
                ConversationalQualifierCode.EVIDENCE_NOT_MALICIOUSNESS.value,
                ConversationalQualifierCode.EVIDENCE_NOT_LATERAL_MOVEMENT.value,
                ConversationalQualifierCode.EVIDENCE_NOT_PERSISTENCE.value,
                ConversationalQualifierCode.RISK_BAND_NOT_RECORDED.value,
                ConversationalQualifierCode.BUSINESS_IMPACT_NOT_RECORDED.value,
                ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY.value,
            ]
        )
    )
    evidence_refs_by_type = {
        ConversationalClaimType.OPERATIONAL_FACT: [
            item.atom_id for item in view.operational_atoms
        ],
        ConversationalClaimType.RECORDED_CORRELATION: [
            item.atom_id
            for item in view.operational_atoms
            if isinstance(item, RecordedCorrelationAtom)
        ]
        + [
            item.relationship_id
            for item in view.relationships
            if item.relationship_class is RelationshipClass.RECORDED_CORRELATION
        ],
        ConversationalClaimType.ANALYTICAL_RELATIONSHIP: [
            item.relationship_id
            for item in view.relationships
            if item.relationship_class is RelationshipClass.ANALYTICAL_RELATIONSHIP
        ],
        ConversationalClaimType.SEMANTIC_CANDIDATE: [
            item.candidate_id for item in view.candidates
        ]
        + [
            item.relationship_id
            for item in view.relationships
            if item.relationship_class is RelationshipClass.SEMANTIC_SIMILARITY
        ],
        ConversationalClaimType.REFERENCE_EXPLANATION: [
            item.knowledge_id for item in view.reference_atoms
        ],
        ConversationalClaimType.ADVISORY_GUIDANCE: [
            item.knowledge_id for item in view.advisory_atoms
        ],
    }

    available_claim_types = [
        claim_type.value
        for claim_type in (
            ConversationalClaimType.OPERATIONAL_FACT,
            ConversationalClaimType.RECORDED_CORRELATION,
            ConversationalClaimType.ANALYTICAL_RELATIONSHIP,
            ConversationalClaimType.SEMANTIC_CANDIDATE,
            ConversationalClaimType.REFERENCE_EXPLANATION,
            ConversationalClaimType.ADVISORY_GUIDANCE,
        )
        if evidence_refs_by_type[claim_type]
    ]
    code_claim_inputs = (
        (
            ConversationalClaimType.ABSENCE,
            [item.value for item in available_absence_fields(package)],
        ),
        (ConversationalClaimType.NON_IMPLICATION, safety_codes),
        (
            ConversationalClaimType.LIMITATION,
            [item.value for item in available_limitation_codes(package)],
        ),
    )
    available_claim_types.extend(
        claim_type.value
        for claim_type, qualifier_codes in code_claim_inputs
        if qualifier_codes
    )
    available_qualifier_codes = list(
        dict.fromkeys(
            [ConversationalQualifierCode.NONE.value]
            + [
                code
                for _, qualifier_codes in code_claim_inputs
                for code in qualifier_codes
            ]
        )
    )
    if not available_claim_types:
        raise ValueError("V3.1 conversational schema requires typed claims")

    claim_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "claim_id": {"type": "string", "enum": _MODEL_CLAIM_IDS},
            "claim_type": {"type": "string", "enum": available_claim_types},
            "source_refs": {
                "type": "array",
                "minItems": 0,
                "maxItems": MAX_CONVERSATIONAL_CLAIMS_PER_SEGMENT,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "enum": _model_visible_refs(package),
                },
            },
            "qualifier_code": {
                "type": "string",
                "enum": available_qualifier_codes,
            },
        },
        "required": [
            "claim_id",
            "claim_type",
            "source_refs",
            "qualifier_code",
        ],
    }

    def segment_schema() -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "segment_id": {
                    "type": "string",
                    "enum": ["s1", "s2", "s3", "s4"],
                },
                "kind": {
                    "type": "string",
                    "enum": [kind.value for kind in ConversationalSegmentKind],
                },
                "text": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_CONVERSATIONAL_SEGMENT_CHARS,
                },
                "claim_refs": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_CONVERSATIONAL_CLAIMS_PER_SEGMENT,
                    "uniqueItems": True,
                    "items": {"type": "string", "enum": _MODEL_CLAIM_IDS},
                },
            },
            "required": ["segment_id", "kind", "text", "claim_refs"],
        }

    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "response_language": {
                "type": "string",
                "const": package.response_language,
            },
            "answer": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "segments": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_CONVERSATIONAL_SEGMENTS,
                        "items": segment_schema(),
                    },
                },
                "required": ["segments"],
            },
            "claims": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_CONVERSATIONAL_CLAIMS,
                "items": claim_schema,
            },
        },
        "required": ["response_language", "answer", "claims"],
    }
