from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any

from services.assistant.claims import (
    ALLOWED_NON_IMPLICATIONS,
    FACT_FIELD_REGISTRY,
    FACT_RELATION_NODES,
    FORBIDDEN_DERIVATIONS,
    ClaimType,
    FactField,
    FactFieldPolicy,
    FactProvenance,
    FactValueType,
    GroundedClaim,
    GroundedClaimOutput,
    LimitationCode,
    SemanticRole,
)
from services.assistant.focus import FocusDimension, FocusSelection
from services.assistant.sources import SourceRecord


@dataclass(frozen=True)
class GroundingValidation:
    accepted: bool
    reason: str | None = None


def parse_grounded_output(value: Any) -> GroundedClaimOutput | None:
    payload = value
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            return None
    try:
        return GroundedClaimOutput.model_validate(payload)
    except Exception:
        return None


def _source_registry(sources: list[SourceRecord]) -> dict[str, SourceRecord]:
    return {
        source.source_id: source
        for source in sources
        if source.source_id is not None
    }


def _validate_sources(
    source_ids: list[str],
    *,
    registry: dict[str, SourceRecord],
    required_authority: str | None,
) -> GroundingValidation:
    records: list[SourceRecord] = []
    for source_id in source_ids:
        source = registry.get(source_id)
        if source is None:
            return GroundingValidation(False, "unknown_source_id")
        records.append(source)
    if required_authority and any(
        source.authority != required_authority for source in records
    ):
        reason = (
            "unsupported_advisory_authority"
            if required_authority == "advisory"
            else "unsupported_authoritative_source"
        )
        return GroundingValidation(False, reason)
    return GroundingValidation(True)


def _value_has_type(value: Any, policy: FactFieldPolicy) -> bool:
    if policy.value_type is FactValueType.BOOLEAN:
        return isinstance(value, bool)
    if policy.value_type is FactValueType.NUMBER:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (not isinstance(value, float) or math.isfinite(value))
        )
    if policy.value_type is FactValueType.TEXT:
        return isinstance(value, str)
    if policy.value_type is FactValueType.STRUCTURED:
        return isinstance(value, (dict, list))
    return isinstance(value, (str, int, float, bool)) and (
        not isinstance(value, float) or math.isfinite(value)
    )


def _values_equal(actual: Any, claimed: Any, policy: FactFieldPolicy) -> bool:
    if not _value_has_type(actual, policy) or not _value_has_type(claimed, policy):
        return False
    if policy.value_type is FactValueType.NUMBER:
        return float(actual) == float(claimed)
    return type(actual) is type(claimed) and actual == claimed


def _unsupported_missing_reason(field: FactField) -> str:
    if field in {FactField.SEVERITY, FactField.RISK_NORMALIZATION_SEVERITY}:
        return "unsupported_severity_provenance"
    if field in {
        FactField.RISK_BAND,
        FactField.RISK_LABEL,
        FactField.RISK_DESCRIPTION,
    }:
        return "unsupported_risk_interpretation"
    if field in {
        FactField.STATUS_DESCRIPTION,
        FactField.STATUS_MEANING,
        FactField.STATUS_CONTEXT,
    }:
        return "unsupported_status_interpretation"
    if field in {
        FactField.THREAT_ASSESSMENT,
        FactField.IMMEDIATE_THREAT,
        FactField.URGENCY,
        FactField.IMPACT,
        FactField.BUSINESS_IMPACT,
    }:
        return "unsupported_threat_assessment"
    if field is FactField.ESCALATED:
        return "unsupported_escalation_state"
    if field is FactField.COMPROMISE_CONFIRMED:
        return "unsupported_compromise_claim"
    return "unsupported_recorded_fact"


def _contradiction_reason(field: FactField) -> str:
    if field in {FactField.SEVERITY, FactField.RISK_NORMALIZATION_SEVERITY}:
        return "severity_contradiction"
    if field is FactField.RISK_SCORE:
        return "risk_contradiction"
    if field is FactField.CORRELATED:
        return "correlation_contradiction"
    if field is FactField.ESCALATED:
        return "unsupported_escalation_state"
    if field is FactField.COMPROMISE_CONFIRMED:
        return "unsupported_compromise_claim"
    return "fact_contradiction"


def _validate_claim_role(
    claim: GroundedClaim,
    policy: FactFieldPolicy,
) -> GroundingValidation:
    if claim.provenance is not policy.provenance:
        if policy.family.value == "severity":
            return GroundingValidation(False, "unsupported_severity_provenance")
        if policy.family.value == "priority":
            return GroundingValidation(False, "unsupported_priority_provenance")
        return GroundingValidation(False, "unsupported_fact_provenance")

    requires_distinct = policy.semantic_role is SemanticRole.DISTINCT_VALUE
    if requires_distinct and claim.claim_type is not ClaimType.DISTINCT_VALUE:
        reason = (
            "unsupported_severity_provenance"
            if policy.family.value == "severity"
            else "unsupported_priority_provenance"
        )
        return GroundingValidation(False, reason)
    if not requires_distinct and claim.claim_type is ClaimType.DISTINCT_VALUE:
        return GroundingValidation(False, "unsupported_fact_provenance")
    return GroundingValidation(True)


def _validate_fact_claim(
    claim: GroundedClaim,
    *,
    fact_inventory: dict[str, Any],
    sources: dict[str, SourceRecord],
) -> GroundingValidation:
    assert claim.field is not None
    policy = FACT_FIELD_REGISTRY[claim.field]
    source_result = _validate_sources(
        claim.source_ids,
        registry=sources,
        required_authority=policy.authority.value,
    )
    if not source_result.accepted:
        return source_result

    field_name = claim.field.value
    if field_name not in fact_inventory or fact_inventory[field_name] is None:
        return GroundingValidation(
            False,
            _unsupported_missing_reason(claim.field),
        )
    role_result = _validate_claim_role(claim, policy)
    if not role_result.accepted:
        return role_result
    if not _values_equal(fact_inventory[field_name], claim.value, policy):
        return GroundingValidation(False, _contradiction_reason(claim.field))
    return GroundingValidation(True)


def _validate_absence_claim(
    claim: GroundedClaim,
    *,
    fact_inventory: dict[str, Any],
    sources: dict[str, SourceRecord],
) -> GroundingValidation:
    assert claim.field is not None
    policy = FACT_FIELD_REGISTRY[claim.field]
    source_result = _validate_sources(
        claim.source_ids,
        registry=sources,
        required_authority=policy.authority.value,
    )
    if not source_result.accepted:
        return source_result
    field_name = claim.field.value
    if field_name not in fact_inventory:
        return GroundingValidation(False, "absence_outside_focused_view")
    if fact_inventory[field_name] is not None:
        return GroundingValidation(False, _contradiction_reason(claim.field))
    if claim.provenance is not None and claim.provenance is not policy.provenance:
        return _validate_claim_role(claim, policy)
    return GroundingValidation(True)


def _validate_structured_reference(
    claim: GroundedClaim,
    *,
    fact_inventory: dict[str, Any],
    sources: dict[str, SourceRecord],
) -> GroundingValidation:
    assert claim.field is not None
    policy = FACT_FIELD_REGISTRY[claim.field]
    if policy.value_type is not FactValueType.STRUCTURED:
        return GroundingValidation(False, "invalid_structured_reference")
    field_name = claim.field.value
    if field_name not in fact_inventory or fact_inventory[field_name] is None:
        return GroundingValidation(False, "invalid_structured_reference")
    if not _value_has_type(fact_inventory[field_name], policy):
        return GroundingValidation(False, "invalid_structured_reference")
    source_result = _validate_sources(
        claim.source_ids,
        registry=sources,
        required_authority=policy.authority.value,
    )
    if not source_result.accepted:
        return source_result
    role_result = _validate_claim_role(claim, policy)
    if not role_result.accepted:
        return role_result
    return GroundingValidation(True)


def _derivation_inputs(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    if isinstance(value, dict):
        return {key for key, enabled in value.items() if enabled is True}
    return set()


def _validate_derivation_claim(
    claim: GroundedClaim,
    *,
    fact_inventory: dict[str, Any],
    sources: dict[str, SourceRecord],
) -> GroundingValidation:
    assert claim.field is not None
    policy = FACT_FIELD_REGISTRY[claim.field]
    source_result = _validate_sources(
        claim.source_ids,
        registry=sources,
        required_authority=policy.authority.value,
    )
    if not source_result.accepted:
        return source_result
    if claim.field.value not in fact_inventory:
        return GroundingValidation(False, "unsupported_value_derivation")
    role_result = _validate_claim_role(claim, policy)
    if not role_result.accepted:
        return role_result

    supported_inputs: set[str] = set()
    for support_field in policy.derivation_support_fields:
        supported_inputs.update(
            _derivation_inputs(fact_inventory.get(support_field.value))
        )
    target_relation = FACT_RELATION_NODES.get(claim.field)
    forbidden_inputs = {
        field.value
        for field in claim.derived_from
        if target_relation is not None
        and (
            FACT_RELATION_NODES.get(field),
            target_relation,
        )
        in FORBIDDEN_DERIVATIONS
    }
    if forbidden_inputs - supported_inputs:
        return GroundingValidation(False, "unsupported_value_derivation")
    if not supported_inputs:
        return GroundingValidation(False, "unsupported_value_derivation")
    if any(field.value not in supported_inputs for field in claim.derived_from):
        return GroundingValidation(False, "unsupported_value_derivation")
    return GroundingValidation(True)


def validate_grounded_output(
    output: GroundedClaimOutput,
    *,
    fact_inventory: dict[str, Any],
    sources: list[SourceRecord],
) -> GroundingValidation:
    registry = _source_registry(sources)
    advisory_claims = [
        claim
        for claim in output.claims
        if claim.claim_type is ClaimType.ADVISORY_GUIDANCE
    ]
    has_advisory_use = bool(advisory_claims or output.next_check)
    if has_advisory_use and not output.used_advisory_context:
        return GroundingValidation(False, "undeclared_advisory_use")
    if output.used_advisory_context and not has_advisory_use:
        return GroundingValidation(False, "missing_advisory_source")

    for claim in output.claims:
        if claim.claim_type in {
            ClaimType.RECORDED_FACT,
            ClaimType.DISTINCT_VALUE,
        }:
            result = _validate_fact_claim(
                claim,
                fact_inventory=fact_inventory,
                sources=registry,
            )
        elif claim.claim_type is ClaimType.ABSENCE:
            result = _validate_absence_claim(
                claim,
                fact_inventory=fact_inventory,
                sources=registry,
            )
        elif claim.claim_type is ClaimType.STRUCTURED_REFERENCE:
            result = _validate_structured_reference(
                claim,
                fact_inventory=fact_inventory,
                sources=registry,
            )
        elif claim.claim_type is ClaimType.NON_IMPLICATION:
            if (claim.subject, claim.object) not in ALLOWED_NON_IMPLICATIONS:
                result = GroundingValidation(
                    False,
                    "unsupported_non_implication",
                )
            else:
                result = _validate_sources(
                    claim.source_ids,
                    registry=registry,
                    required_authority="authoritative"
                    if claim.source_ids
                    else None,
                )
        elif claim.claim_type is ClaimType.ADVISORY_GUIDANCE:
            result = _validate_sources(
                claim.source_ids,
                registry=registry,
                required_authority="advisory",
            )
        else:
            result = _validate_derivation_claim(
                claim,
                fact_inventory=fact_inventory,
                sources=registry,
            )
        if not result.accepted:
            return result

    if output.next_check is not None:
        next_check_sources = _validate_sources(
            output.next_check.source_ids,
            registry=registry,
            required_authority="advisory",
        )
        if not next_check_sources.accepted:
            return next_check_sources
    return GroundingValidation(True)


def validate_focus(
    output: GroundedClaimOutput,
    *,
    focus: FocusSelection,
    fact_inventory: dict[str, Any],
) -> GroundingValidation:
    selected = set(focus.dimensions) or {FocusDimension.GENERAL}
    general = FocusDimension.GENERAL in selected
    for claim in output.claims:
        if claim.claim_type is ClaimType.ADVISORY_GUIDANCE:
            continue
        if claim.claim_type is ClaimType.NON_IMPLICATION:
            if not general and FocusDimension.CORRELATION not in selected:
                return GroundingValidation(False, "claim_outside_focus")
            continue
        assert claim.field is not None
        policy = FACT_FIELD_REGISTRY[claim.field]
        if claim.field.value not in fact_inventory:
            return GroundingValidation(False, "claim_outside_focus")
        if (
            not general
            and policy.focus_dimension is not FocusDimension.GENERAL
            and policy.focus_dimension not in selected
        ):
            return GroundingValidation(False, "claim_outside_focus")
        if claim.claim_type is ClaimType.DERIVATION and any(
            field.value not in fact_inventory for field in claim.derived_from
        ):
            return GroundingValidation(False, "claim_outside_focus")
    return GroundingValidation(True)


def deterministic_claim_output(
    *,
    fact_inventory: dict[str, Any],
    authoritative_source_ids: list[str],
) -> GroundedClaimOutput:
    source_ids = authoritative_source_ids or ["S1"]
    claims: list[GroundedClaim] = []
    limitations: list[LimitationCode] = []
    for field, policy in FACT_FIELD_REGISTRY.items():
        if field.value not in fact_inventory:
            continue
        if policy.semantic_role in {
            SemanticRole.IDENTITY,
            SemanticRole.PROVENANCE,
        }:
            continue
        value = fact_inventory[field.value]
        if value is None:
            claims.append(
                GroundedClaim(
                    claim_type=ClaimType.ABSENCE,
                    field=field,
                    provenance=policy.provenance,
                    source_ids=source_ids,
                )
            )
            if field is FactField.SEVERITY:
                limitations.append(LimitationCode.CANONICAL_SEVERITY_MISSING)
            continue
        if policy.value_type is FactValueType.STRUCTURED:
            continue
        claim_type = (
            ClaimType.DISTINCT_VALUE
            if policy.semantic_role is SemanticRole.DISTINCT_VALUE
            else ClaimType.RECORDED_FACT
        )
        claims.append(
            GroundedClaim(
                claim_type=claim_type,
                field=field,
                value=value,
                provenance=policy.provenance,
                source_ids=source_ids,
            )
        )
    if not claims:
        identity_field = (
            FactField.INCIDENT_ID
            if "incident_id" in fact_inventory
            else FactField.CASE_ID
            if "case_id" in fact_inventory
            else FactField.SOURCE_TYPE
        )
        identity_policy = FACT_FIELD_REGISTRY[identity_field]
        claims.append(
            GroundedClaim(
                claim_type=ClaimType.RECORDED_FACT,
                field=identity_field,
                value=fact_inventory.get(identity_field.value, "record"),
                provenance=identity_policy.provenance,
                source_ids=source_ids,
            )
        )
        limitations.append(LimitationCode.DATA_NOT_RECORDED)
    return GroundedClaimOutput(
        claims=claims,
        limitations=list(dict.fromkeys(limitations)),
        used_advisory_context=False,
    )
