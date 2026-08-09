from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import Field, model_validator

from services.assistant.v3.contracts import AnswerIntent, ClosedModel, FactField


class AnswerDetailLevel(str, Enum):
    CONCISE = "CONCISE"
    STANDARD = "STANDARD"
    DETAILED = "DETAILED"


class AnswerAudience(str, Enum):
    SOC_ANALYST = "SOC_ANALYST"
    EXECUTIVE = "EXECUTIVE"
    GENERAL_SECURITY = "GENERAL_SECURITY"


class DiscourseOrdering(str, Enum):
    CONCLUSION_FIRST = "CONCLUSION_FIRST"
    EVIDENCE_FIRST = "EVIDENCE_FIRST"
    CHRONOLOGY_FIRST = "CHRONOLOGY_FIRST"
    COMPARISON_FIRST = "COMPARISON_FIRST"


class AnswerSectionType(str, Enum):
    DIRECT_ANSWER = "DIRECT_ANSWER"
    KEY_FINDINGS = "KEY_FINDINGS"
    INCIDENT_OVERVIEW = "INCIDENT_OVERVIEW"
    EVIDENCE = "EVIDENCE"
    TIMELINE = "TIMELINE"
    RELATED_INCIDENTS = "RELATED_INCIDENTS"
    COMPARISON = "COMPARISON"
    PATTERN = "PATTERN"
    TECHNICAL_CONTEXT = "TECHNICAL_CONTEXT"
    WHAT_WE_CAN_CONCLUDE = "WHAT_WE_CAN_CONCLUDE"
    WHAT_WE_CANNOT_CONCLUDE = "WHAT_WE_CANNOT_CONCLUDE"
    NEXT_STEPS = "NEXT_STEPS"
    LIMITATIONS = "LIMITATIONS"


class AnalyticalUnitType(str, Enum):
    RECORDED_FACT = "RECORDED_FACT"
    ABSENCE = "ABSENCE"
    COMPARISON = "COMPARISON"
    DIFFERENCE = "DIFFERENCE"
    SHARED_PATTERN = "SHARED_PATTERN"
    RECORDED_CORRELATION = "RECORDED_CORRELATION"
    ANALYTICAL_RELATIONSHIP = "ANALYTICAL_RELATIONSHIP"
    SEMANTIC_SIMILARITY = "SEMANTIC_SIMILARITY"
    TEMPORAL_SEQUENCE = "TEMPORAL_SEQUENCE"
    REFERENCE_EXPLANATION = "REFERENCE_EXPLANATION"
    NON_IMPLICATION = "NON_IMPLICATION"
    LIMITATION = "LIMITATION"
    ADVISORY_GUIDANCE = "ADVISORY_GUIDANCE"
    NEXT_CHECK = "NEXT_CHECK"
    CANDIDATE_RELEVANCE = "CANDIDATE_RELEVANCE"


class PropositionType(str, Enum):
    PRIMARY_FINDING = "PRIMARY_FINDING"
    SUPPORTING_EVIDENCE = "SUPPORTING_EVIDENCE"
    TECHNICAL_SIGNIFICANCE = "TECHNICAL_SIGNIFICANCE"
    COMPARATIVE_FINDING = "COMPARATIVE_FINDING"
    SIMILARITY = "SIMILARITY"
    DIFFERENCE = "DIFFERENCE"
    RELATIONSHIP_SUMMARY = "RELATIONSHIP_SUMMARY"
    PATTERN_SUMMARY = "PATTERN_SUMMARY"
    EVIDENCE_STRENGTH = "EVIDENCE_STRENGTH"
    UNCERTAINTY = "UNCERTAINTY"
    CAVEAT = "CAVEAT"
    INVESTIGATIVE_STEP = "INVESTIGATIVE_STEP"
    EXPECTED_VERIFICATION_TARGET = "EXPECTED_VERIFICATION_TARGET"
    HANDOVER_POINT = "HANDOVER_POINT"
    EXECUTIVE_POINT = "EXECUTIVE_POINT"


class PropositionImportance(str, Enum):
    PRIMARY = "PRIMARY"
    SECONDARY = "SECONDARY"
    SUPPORTING = "SUPPORTING"


class EvidencePriority(str, Enum):
    PRIMARY = "PRIMARY"
    SUPPORTING = "SUPPORTING"
    CONTEXTUAL = "CONTEXTUAL"
    OPTIONAL = "OPTIONAL"


class RhetoricalRole(str, Enum):
    LEAD = "LEAD"
    SUPPORT = "SUPPORT"
    EXPLAIN = "EXPLAIN"
    COMPARE = "COMPARE"
    CONTRAST = "CONTRAST"
    CAVEAT = "CAVEAT"
    EXPLANATION = "EXPLANATION"
    TRANSITION = "TRANSITION"
    FOLLOW_UP = "FOLLOW_UP"


class SurfaceVariant(str, Enum):
    SUMMARY_LED = "SUMMARY_LED"
    EVIDENCE_LED = "EVIDENCE_LED"
    CONTRASTIVE = "CONTRASTIVE"
    CHRONOLOGICAL = "CHRONOLOGICAL"
    COMPARISON_LED = "COMPARISON_LED"


class NonImplicationCode(str, Enum):
    CORRELATION_NOT_COMPROMISE = "CORRELATION_NOT_COMPROMISE"
    ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY = (
        "ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY"
    )
    SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION = (
        "SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION"
    )
    SHARED_MITRE_NOT_SAME_ATTACKER = "SHARED_MITRE_NOT_SAME_ATTACKER"
    SHARED_HOST_NOT_COMMON_ROOT_CAUSE = "SHARED_HOST_NOT_COMMON_ROOT_CAUSE"
    SAME_CASE_NOT_CAUSALITY = "SAME_CASE_NOT_CAUSALITY"
    CANDIDATE_RANK_NOT_RISK = "CANDIDATE_RANK_NOT_RISK"


class PlanLimitationCode(str, Enum):
    REQUESTED_DATA_NOT_RECORDED = "REQUESTED_DATA_NOT_RECORDED"
    CANONICAL_SEVERITY_NOT_RECORDED = "CANONICAL_SEVERITY_NOT_RECORDED"
    NO_AUTHORITATIVE_ESCALATION_BOOLEAN = "NO_AUTHORITATIVE_ESCALATION_BOOLEAN"
    NO_RELATED_INCIDENT_CANDIDATES = "NO_RELATED_INCIDENT_CANDIDATES"
    SEMANTIC_INDEX_DEGRADED = "SEMANTIC_INDEX_DEGRADED"
    REFERENCE_KNOWLEDGE_UNAVAILABLE = "REFERENCE_KNOWLEDGE_UNAVAILABLE"
    ADVISORY_KNOWLEDGE_UNAVAILABLE = "ADVISORY_KNOWLEDGE_UNAVAILABLE"
    EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY = (
        "EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY"
    )


_FACT_ONLY_UNITS = {
    AnalyticalUnitType.RECORDED_FACT,
    AnalyticalUnitType.COMPARISON,
    AnalyticalUnitType.DIFFERENCE,
}
_RELATIONSHIP_ONLY_UNITS = {
    AnalyticalUnitType.SHARED_PATTERN,
    AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
    AnalyticalUnitType.SEMANTIC_SIMILARITY,
    AnalyticalUnitType.TEMPORAL_SEQUENCE,
}

_UNIT_REFERENCE_FIELDS: dict[AnalyticalUnitType, frozenset[str]] = {
    AnalyticalUnitType.RECORDED_FACT: frozenset({"fact_refs"}),
    AnalyticalUnitType.ABSENCE: frozenset({"absence_field"}),
    AnalyticalUnitType.COMPARISON: frozenset({"fact_refs"}),
    AnalyticalUnitType.DIFFERENCE: frozenset({"fact_refs"}),
    AnalyticalUnitType.SHARED_PATTERN: frozenset({"relationship_refs"}),
    AnalyticalUnitType.RECORDED_CORRELATION: frozenset(
        {"fact_refs", "relationship_refs"}
    ),
    AnalyticalUnitType.ANALYTICAL_RELATIONSHIP: frozenset({"relationship_refs"}),
    AnalyticalUnitType.SEMANTIC_SIMILARITY: frozenset({"relationship_refs"}),
    AnalyticalUnitType.TEMPORAL_SEQUENCE: frozenset({"relationship_refs"}),
    AnalyticalUnitType.REFERENCE_EXPLANATION: frozenset({"reference_refs"}),
    AnalyticalUnitType.NON_IMPLICATION: frozenset(
        {"relationship_refs", "non_implication"}
    ),
    AnalyticalUnitType.LIMITATION: frozenset({"limitation"}),
    AnalyticalUnitType.ADVISORY_GUIDANCE: frozenset({"advisory_refs"}),
    AnalyticalUnitType.NEXT_CHECK: frozenset({"advisory_refs"}),
    AnalyticalUnitType.CANDIDATE_RELEVANCE: frozenset(
        {"candidate_refs", "relationship_refs"}
    ),
}


UNIT_PROPOSITION_TYPES: dict[AnalyticalUnitType, frozenset[PropositionType]] = {
    AnalyticalUnitType.RECORDED_FACT: frozenset(
        {
            PropositionType.PRIMARY_FINDING,
            PropositionType.SUPPORTING_EVIDENCE,
            PropositionType.TECHNICAL_SIGNIFICANCE,
            PropositionType.EVIDENCE_STRENGTH,
            PropositionType.HANDOVER_POINT,
            PropositionType.EXECUTIVE_POINT,
        }
    ),
    AnalyticalUnitType.ABSENCE: frozenset(
        {
            PropositionType.UNCERTAINTY,
            PropositionType.CAVEAT,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.COMPARISON: frozenset(
        {
            PropositionType.COMPARATIVE_FINDING,
            PropositionType.SIMILARITY,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.DIFFERENCE: frozenset(
        {
            PropositionType.COMPARATIVE_FINDING,
            PropositionType.DIFFERENCE,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.SHARED_PATTERN: frozenset(
        {PropositionType.PATTERN_SUMMARY, PropositionType.SUPPORTING_EVIDENCE}
    ),
    AnalyticalUnitType.RECORDED_CORRELATION: frozenset(
        {
            PropositionType.PRIMARY_FINDING,
            PropositionType.SUPPORTING_EVIDENCE,
            PropositionType.RELATIONSHIP_SUMMARY,
            PropositionType.EVIDENCE_STRENGTH,
            PropositionType.HANDOVER_POINT,
        }
    ),
    AnalyticalUnitType.ANALYTICAL_RELATIONSHIP: frozenset(
        {
            PropositionType.RELATIONSHIP_SUMMARY,
            PropositionType.COMPARATIVE_FINDING,
            PropositionType.SIMILARITY,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.SEMANTIC_SIMILARITY: frozenset(
        {
            PropositionType.SIMILARITY,
            PropositionType.RELATIONSHIP_SUMMARY,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.TEMPORAL_SEQUENCE: frozenset(
        {
            PropositionType.RELATIONSHIP_SUMMARY,
            PropositionType.SIMILARITY,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.REFERENCE_EXPLANATION: frozenset(
        {
            PropositionType.TECHNICAL_SIGNIFICANCE,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.NON_IMPLICATION: frozenset(
        {
            PropositionType.CAVEAT,
            PropositionType.UNCERTAINTY,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.LIMITATION: frozenset(
        {
            PropositionType.CAVEAT,
            PropositionType.UNCERTAINTY,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.ADVISORY_GUIDANCE: frozenset(
        {
            PropositionType.INVESTIGATIVE_STEP,
            PropositionType.EXPECTED_VERIFICATION_TARGET,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.NEXT_CHECK: frozenset(
        {
            PropositionType.INVESTIGATIVE_STEP,
            PropositionType.EXPECTED_VERIFICATION_TARGET,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnalyticalUnitType.CANDIDATE_RELEVANCE: frozenset(
        {
            PropositionType.RELATIONSHIP_SUMMARY,
            PropositionType.COMPARATIVE_FINDING,
            PropositionType.EVIDENCE_STRENGTH,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
}


class AnalyticalUnit(ClosedModel):
    unit_type: AnalyticalUnitType
    proposition_type: PropositionType = PropositionType.SUPPORTING_EVIDENCE
    importance: PropositionImportance = PropositionImportance.SUPPORTING
    evidence_priority: EvidencePriority = EvidencePriority.SUPPORTING
    subject_record_ids: list[int] = Field(default_factory=list, max_length=12)
    fact_refs: list[str] = Field(default_factory=list, max_length=8)
    relationship_refs: list[str] = Field(default_factory=list, max_length=8)
    candidate_refs: list[str] = Field(default_factory=list, max_length=6)
    reference_refs: list[str] = Field(default_factory=list, max_length=4)
    advisory_refs: list[str] = Field(default_factory=list, max_length=4)
    absence_field: FactField | None = None
    non_implication: NonImplicationCode | None = None
    limitation: PlanLimitationCode | None = None
    rhetorical_role: RhetoricalRole = RhetoricalRole.SUPPORT
    surface_variant: SurfaceVariant = SurfaceVariant.SUMMARY_LED

    @property
    def proposition_id(self) -> str:
        material = "\x1f".join(
            (
                self.unit_type.value,
                self.proposition_type.value,
                *(str(item) for item in self.subject_record_ids),
                *self.source_refs,
                self.absence_field.value if self.absence_field else "",
                self.non_implication.value if self.non_implication else "",
                self.limitation.value if self.limitation else "",
            )
        )
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]
        return f"proposition:{digest}"

    @property
    def source_refs(self) -> list[str]:
        return list(
            dict.fromkeys(
                (
                    *self.fact_refs,
                    *self.relationship_refs,
                    *self.candidate_refs,
                    *self.reference_refs,
                    *self.advisory_refs,
                )
            )
        )

    @model_validator(mode="after")
    def validate_unit_shape(self):
        if len(self.subject_record_ids) != len(set(self.subject_record_ids)) or any(
            value <= 0 for value in self.subject_record_ids
        ):
            raise ValueError("proposition subject record IDs must be unique and positive")
        if self.proposition_type not in UNIT_PROPOSITION_TYPES[self.unit_type]:
            raise ValueError("proposition type is incompatible with analytical unit")
        reference_lists = (
            self.fact_refs,
            self.relationship_refs,
            self.candidate_refs,
            self.reference_refs,
            self.advisory_refs,
        )
        if any(len(values) != len(set(values)) for values in reference_lists):
            raise ValueError("analytical unit references must be unique")
        if self.unit_type is AnalyticalUnitType.RECORDED_FACT and not self.fact_refs:
            raise ValueError("recorded fact requires fact references")
        if self.unit_type in {
            AnalyticalUnitType.COMPARISON,
            AnalyticalUnitType.DIFFERENCE,
        } and len(self.fact_refs) < 2:
            raise ValueError("comparison units require at least two fact references")
        if self.unit_type is AnalyticalUnitType.ABSENCE and self.absence_field is None:
            raise ValueError("absence unit requires an absence field")
        if self.unit_type in _RELATIONSHIP_ONLY_UNITS and not self.relationship_refs:
            raise ValueError("relationship unit requires relationship references")
        if (
            self.unit_type is AnalyticalUnitType.SHARED_PATTERN
            and len(self.relationship_refs) < 2
        ):
            raise ValueError("shared pattern requires multiple relationships")
        if self.unit_type is AnalyticalUnitType.RECORDED_CORRELATION and not (
            self.fact_refs or self.relationship_refs
        ):
            raise ValueError("recorded correlation requires recorded evidence")
        if (
            self.unit_type is AnalyticalUnitType.REFERENCE_EXPLANATION
            and not self.reference_refs
        ):
            raise ValueError("reference explanation requires reference knowledge")
        if self.unit_type in {
            AnalyticalUnitType.ADVISORY_GUIDANCE,
            AnalyticalUnitType.NEXT_CHECK,
        } and not self.advisory_refs:
            raise ValueError("advisory unit requires advisory knowledge")
        if self.unit_type is AnalyticalUnitType.NON_IMPLICATION and (
            self.non_implication is None
        ):
            raise ValueError("non-implication unit requires a closed code")
        if self.unit_type is AnalyticalUnitType.LIMITATION and self.limitation is None:
            raise ValueError("limitation unit requires a closed code")
        if (
            self.unit_type is AnalyticalUnitType.CANDIDATE_RELEVANCE
            and not self.candidate_refs
        ):
            raise ValueError("candidate relevance requires candidate references")
        if self.unit_type in _FACT_ONLY_UNITS and any(
            (
                self.relationship_refs,
                self.candidate_refs,
                self.reference_refs,
                self.advisory_refs,
                [self.absence_field] if self.absence_field else [],
                [self.non_implication] if self.non_implication else [],
                [self.limitation] if self.limitation else [],
            )
        ):
            raise ValueError("fact unit contains incompatible references")
        populated = {
            name
            for name, value in {
                "fact_refs": self.fact_refs,
                "relationship_refs": self.relationship_refs,
                "candidate_refs": self.candidate_refs,
                "reference_refs": self.reference_refs,
                "advisory_refs": self.advisory_refs,
                "absence_field": self.absence_field,
                "non_implication": self.non_implication,
                "limitation": self.limitation,
            }.items()
            if value
        }
        unsupported = populated - _UNIT_REFERENCE_FIELDS[self.unit_type]
        if unsupported:
            raise ValueError(
                "analytical unit contains incompatible fields: "
                + ", ".join(sorted(unsupported))
            )
        return self

    def semantic_key(self) -> tuple[object, ...]:
        return (
            self.unit_type,
            self.proposition_type,
            tuple(self.fact_refs),
            tuple(self.relationship_refs),
            tuple(self.candidate_refs),
            tuple(self.reference_refs),
            tuple(self.advisory_refs),
            self.absence_field,
            self.non_implication,
            self.limitation,
        )


class AnswerSection(ClosedModel):
    section_type: AnswerSectionType
    units: list[AnalyticalUnit] = Field(min_length=1, max_length=8)


class GroundedAnswerPlanV3(ClosedModel):
    answer_intent: AnswerIntent
    detail_level: AnswerDetailLevel
    audience: AnswerAudience
    ordering: DiscourseOrdering
    sections: list[AnswerSection] = Field(min_length=1, max_length=10)

    @model_validator(mode="after")
    def validate_plan_bounds_and_uniqueness(self):
        if len(self.analytical_units) > 32:
            raise ValueError("answer plan exceeds the analytical unit budget")
        keys = [unit.semantic_key() for unit in self.analytical_units]
        if len(keys) != len(set(keys)):
            raise ValueError("answer plan contains duplicate semantic units")
        section_types = [section.section_type for section in self.sections]
        if len(section_types) != len(set(section_types)):
            raise ValueError("answer plan section types must be unique")
        return self

    @property
    def analytical_units(self) -> list[AnalyticalUnit]:
        return [unit for section in self.sections for unit in section.units]

    @property
    def used_relationship_refs(self) -> list[str]:
        return list(
            dict.fromkeys(
                ref for unit in self.analytical_units for ref in unit.relationship_refs
            )
        )

    @property
    def used_reference_refs(self) -> list[str]:
        return list(
            dict.fromkeys(
                ref for unit in self.analytical_units for ref in unit.reference_refs
            )
        )

    @property
    def used_advisory_refs(self) -> list[str]:
        return list(
            dict.fromkeys(
                ref for unit in self.analytical_units for ref in unit.advisory_refs
            )
        )

    @property
    def used_candidate_refs(self) -> list[str]:
        return list(
            dict.fromkeys(
                ref for unit in self.analytical_units for ref in unit.candidate_refs
            )
        )

    @property
    def limitations(self) -> list[PlanLimitationCode]:
        return [
            unit.limitation
            for unit in self.analytical_units
            if unit.limitation is not None
        ]

    @property
    def next_checks(self) -> list[str]:
        return list(
            dict.fromkeys(
                ref
                for unit in self.analytical_units
                if unit.unit_type is AnalyticalUnitType.NEXT_CHECK
                for ref in unit.advisory_refs
            )
        )


INTENT_SECTION_TYPES: dict[AnswerIntent, tuple[AnswerSectionType, ...]] = {
    AnswerIntent.FACT_LOOKUP: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.LIMITATIONS,
    ),
    AnswerIntent.EXPLAIN: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.KEY_FINDINGS,
        AnswerSectionType.INCIDENT_OVERVIEW,
        AnswerSectionType.EVIDENCE,
        AnswerSectionType.TECHNICAL_CONTEXT,
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        AnswerSectionType.LIMITATIONS,
    ),
    AnswerIntent.SUMMARY: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.KEY_FINDINGS,
        AnswerSectionType.INCIDENT_OVERVIEW,
        AnswerSectionType.LIMITATIONS,
    ),
    AnswerIntent.INVESTIGATE: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.KEY_FINDINGS,
        AnswerSectionType.EVIDENCE,
        AnswerSectionType.TIMELINE,
        AnswerSectionType.TECHNICAL_CONTEXT,
        AnswerSectionType.WHAT_WE_CAN_CONCLUDE,
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        AnswerSectionType.NEXT_STEPS,
        AnswerSectionType.LIMITATIONS,
    ),
    AnswerIntent.COMPARE: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.COMPARISON,
        AnswerSectionType.RELATED_INCIDENTS,
        AnswerSectionType.EVIDENCE,
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        AnswerSectionType.LIMITATIONS,
    ),
    AnswerIntent.CROSS_INCIDENT_ANALYSIS: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.RELATED_INCIDENTS,
        AnswerSectionType.COMPARISON,
        AnswerSectionType.PATTERN,
        AnswerSectionType.EVIDENCE,
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        AnswerSectionType.NEXT_STEPS,
        AnswerSectionType.LIMITATIONS,
    ),
    AnswerIntent.PATTERN_ANALYSIS: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.PATTERN,
        AnswerSectionType.RELATED_INCIDENTS,
        AnswerSectionType.EVIDENCE,
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        AnswerSectionType.LIMITATIONS,
    ),
    AnswerIntent.NEXT_ACTION: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.EVIDENCE,
        AnswerSectionType.NEXT_STEPS,
        AnswerSectionType.LIMITATIONS,
    ),
    AnswerIntent.HANDOVER: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.INCIDENT_OVERVIEW,
        AnswerSectionType.EVIDENCE,
        AnswerSectionType.RELATED_INCIDENTS,
        AnswerSectionType.NEXT_STEPS,
        AnswerSectionType.LIMITATIONS,
    ),
    AnswerIntent.EXECUTIVE_SUMMARY: (
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.KEY_FINDINGS,
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        AnswerSectionType.LIMITATIONS,
    ),
}


SECTION_UNIT_TYPES: dict[AnswerSectionType, frozenset[AnalyticalUnitType]] = {
    AnswerSectionType.DIRECT_ANSWER: frozenset(
        {
            AnalyticalUnitType.RECORDED_FACT,
            AnalyticalUnitType.ABSENCE,
            AnalyticalUnitType.RECORDED_CORRELATION,
            AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
            AnalyticalUnitType.CANDIDATE_RELEVANCE,
            AnalyticalUnitType.LIMITATION,
        }
    ),
    AnswerSectionType.KEY_FINDINGS: frozenset(
        {
            AnalyticalUnitType.RECORDED_FACT,
            AnalyticalUnitType.RECORDED_CORRELATION,
            AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
            AnalyticalUnitType.SHARED_PATTERN,
        }
    ),
    AnswerSectionType.INCIDENT_OVERVIEW: frozenset(
        {AnalyticalUnitType.RECORDED_FACT, AnalyticalUnitType.ABSENCE}
    ),
    AnswerSectionType.EVIDENCE: frozenset(
        {
            AnalyticalUnitType.RECORDED_FACT,
            AnalyticalUnitType.RECORDED_CORRELATION,
            AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
            AnalyticalUnitType.SEMANTIC_SIMILARITY,
            AnalyticalUnitType.TEMPORAL_SEQUENCE,
        }
    ),
    AnswerSectionType.TIMELINE: frozenset(
        {AnalyticalUnitType.RECORDED_FACT, AnalyticalUnitType.TEMPORAL_SEQUENCE}
    ),
    AnswerSectionType.RELATED_INCIDENTS: frozenset(
        {
            AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
            AnalyticalUnitType.SEMANTIC_SIMILARITY,
            AnalyticalUnitType.CANDIDATE_RELEVANCE,
        }
    ),
    AnswerSectionType.COMPARISON: frozenset(
        {
            AnalyticalUnitType.COMPARISON,
            AnalyticalUnitType.DIFFERENCE,
            AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
            AnalyticalUnitType.SEMANTIC_SIMILARITY,
            AnalyticalUnitType.CANDIDATE_RELEVANCE,
        }
    ),
    AnswerSectionType.PATTERN: frozenset(
        {AnalyticalUnitType.SHARED_PATTERN, AnalyticalUnitType.TEMPORAL_SEQUENCE}
    ),
    AnswerSectionType.TECHNICAL_CONTEXT: frozenset(
        {AnalyticalUnitType.REFERENCE_EXPLANATION}
    ),
    AnswerSectionType.WHAT_WE_CAN_CONCLUDE: frozenset(
        {
            AnalyticalUnitType.RECORDED_FACT,
            AnalyticalUnitType.RECORDED_CORRELATION,
            AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
        }
    ),
    AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE: frozenset(
        {AnalyticalUnitType.NON_IMPLICATION, AnalyticalUnitType.LIMITATION}
    ),
    AnswerSectionType.NEXT_STEPS: frozenset(
        {AnalyticalUnitType.ADVISORY_GUIDANCE, AnalyticalUnitType.NEXT_CHECK}
    ),
    AnswerSectionType.LIMITATIONS: frozenset(
        {AnalyticalUnitType.LIMITATION, AnalyticalUnitType.NON_IMPLICATION}
    ),
}
