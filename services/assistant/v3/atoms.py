from __future__ import annotations

import hashlib
from typing import Any, Iterable

from services.assistant.v3.contracts import (
    AuthorityClass,
    CaseIdentityAtom,
    CaseRelationshipAtom,
    CompromiseStateAtom,
    ContextPlan,
    DetectionAtom,
    EscalationReasonAtom,
    EscalationStateAtom,
    EvidenceAtom,
    HostAtom,
    IncidentIdentityAtom,
    MitreTechniqueAtom,
    PriorityAtom,
    Provenance,
    RecordedCorrelationAtom,
    RiskAtom,
    StatusAtom,
    TimelineEventAtom,
    UserAtom,
)


def _bounded_text(value: Any, maximum: int) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    if not text:
        return None
    return text[:maximum]


def _stable_suffix(*values: Any) -> str:
    material = "\x1f".join(str(value) for value in values)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _source_identity(facts: dict[str, Any]) -> tuple[str, str, int | None, int | None]:
    incident_id = facts.get("incident_id") if isinstance(facts.get("incident_id"), int) else None
    case_id = facts.get("case_id") if isinstance(facts.get("case_id"), int) else None
    if incident_id is not None:
        return "incident", str(incident_id), incident_id, case_id
    if case_id is not None:
        return "case", str(case_id), None, case_id
    return "global", "global", None, None


def _provenance(
    source_type: str,
    record_id: str,
    source_ids: dict[tuple[str, str], str] | None,
) -> Provenance:
    return Provenance(
        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        source_type=source_type,
        source_record_id=record_id,
        source_id=(source_ids or {}).get((source_type, record_id)),
        retrieval_method="operational_query",
    )


class OperationalAtomNormalizer:
    def normalize(
        self,
        *,
        facts: dict[str, Any],
        plan: ContextPlan,
        source_ids: dict[tuple[str, str], str] | None = None,
    ) -> list[EvidenceAtom]:
        source_type, record_id, incident_id, case_id = _source_identity(facts)
        provenance = _provenance(source_type, record_id, source_ids)
        authority = AuthorityClass.OPERATIONAL_AUTHORITATIVE
        selected = {field.value for field in plan.fact_fields}
        atoms: list[EvidenceAtom] = []
        prefix = f"{source_type}:{record_id}"

        if incident_id is not None:
            atoms.append(
                IncidentIdentityAtom(
                    atom_id=f"{prefix}:identity",
                    authority_class=authority,
                    provenance=provenance,
                    incident_id=incident_id,
                    case_id=case_id,
                    timestamp=_bounded_text(facts.get("timestamp"), 80),
                )
            )
        elif case_id is not None:
            atoms.append(
                CaseIdentityAtom(
                    atom_id=f"{prefix}:identity",
                    authority_class=authority,
                    provenance=provenance,
                    case_id=case_id,
                    title=_bounded_text(facts.get("title"), 240),
                )
            )

        status = _bounded_text(facts.get("status"), 80)
        severity = _bounded_text(facts.get("severity"), 80)
        if status and ({"status", "severity"} & selected):
            atoms.append(
                StatusAtom(
                    atom_id=f"{prefix}:status",
                    authority_class=authority,
                    provenance=provenance,
                    incident_id=incident_id,
                    case_id=case_id,
                    status=status,
                    canonical_severity=severity,
                )
            )

        risk_score = facts.get("risk_score")
        normalized_severity = _bounded_text(facts.get("risk_normalization_severity"), 80)
        numeric_risk = float(risk_score) if isinstance(risk_score, (int, float)) else None
        if (numeric_risk is not None or normalized_severity) and (
            {"risk_score", "risk_normalization_severity"} & selected
        ):
            atoms.append(
                RiskAtom(
                    atom_id=f"{prefix}:risk",
                    authority_class=authority,
                    provenance=provenance,
                    incident_id=incident_id,
                    case_id=case_id,
                    risk_score=numeric_risk,
                    risk_normalization_severity=normalized_severity,
                )
            )

        priority = _bounded_text(facts.get("recommended_priority"), 80)
        if priority and "recommended_priority" in selected:
            atoms.append(
                PriorityAtom(
                    atom_id=f"{prefix}:priority",
                    authority_class=authority,
                    provenance=provenance,
                    incident_id=incident_id,
                    case_id=case_id,
                    recommended_priority=priority,
                )
            )

        host = _bounded_text(facts.get("host"), 240)
        agent = _bounded_text(facts.get("agent"), 240)
        represented_host = host or agent
        if represented_host and ({"host", "agent"} & selected):
            atoms.append(
                HostAtom(
                    atom_id=f"{prefix}:host",
                    authority_class=authority,
                    provenance=provenance,
                    incident_id=incident_id,
                    case_id=case_id,
                    host=represented_host,
                    representation="host" if host else "agent",
                )
            )

        user = _bounded_text(facts.get("user") or facts.get("username"), 240)
        if user and ({"user", "username"} & selected):
            atoms.append(
                UserAtom(
                    atom_id=f"{prefix}:user",
                    authority_class=authority,
                    provenance=provenance,
                    incident_id=incident_id,
                    case_id=case_id,
                    user=user,
                )
            )

        rule = _bounded_text(facts.get("rule"), 500)
        if rule and "rule" in selected:
            level = facts.get("wazuh_level")
            atoms.append(
                DetectionAtom(
                    atom_id=f"{prefix}:detection",
                    authority_class=authority,
                    provenance=provenance,
                    incident_id=incident_id,
                    case_id=case_id,
                    rule=rule,
                    level=level if isinstance(level, int) else None,
                )
            )

        if "mitre" in selected:
            mitre = facts.get("mitre")
            if isinstance(mitre, list):
                for item in mitre[:12]:
                    if not isinstance(item, dict):
                        continue
                    technique_id = _bounded_text(item.get("id"), 32)
                    technique_name = _bounded_text(item.get("name"), 240)
                    if technique_id is None and technique_name is None:
                        continue
                    atoms.append(
                        MitreTechniqueAtom(
                            atom_id=f"{prefix}:mitre:{_stable_suffix(technique_id, technique_name)}",
                            authority_class=authority,
                            provenance=provenance,
                            incident_id=incident_id,
                            case_id=case_id,
                            technique_id=technique_id,
                            technique_name=technique_name,
                        )
                    )

        if {"correlated", "correlation_type", "correlation_score"} & selected:
            correlated = facts.get("correlated")
            correlation_type = _bounded_text(facts.get("correlation_type"), 160)
            correlation_score = facts.get("correlation_score")
            if isinstance(correlated, bool) or correlation_type or isinstance(
                correlation_score, (int, float)
            ):
                atoms.append(
                    RecordedCorrelationAtom(
                        atom_id=f"{prefix}:recorded-correlation",
                        authority_class=authority,
                        provenance=provenance,
                        incident_id=incident_id,
                        case_id=case_id,
                        correlated=correlated if isinstance(correlated, bool) else None,
                        correlation_type=correlation_type,
                        correlation_score=(
                            float(correlation_score)
                            if isinstance(correlation_score, (int, float))
                            else None
                        ),
                    )
                )

        escalation_reason = _bounded_text(facts.get("escalation_reason"), 500)
        if "escalated" in selected and isinstance(facts.get("escalated"), bool):
            atoms.append(
                EscalationStateAtom(
                    atom_id=f"{prefix}:escalation-state",
                    authority_class=authority,
                    provenance=provenance,
                    incident_id=incident_id,
                    case_id=case_id,
                    escalated=facts["escalated"],
                )
            )
        if escalation_reason and "escalation_reason" in selected:
            atoms.append(
                EscalationReasonAtom(
                    atom_id=f"{prefix}:escalation-reason",
                    authority_class=authority,
                    provenance=provenance,
                    incident_id=incident_id,
                    case_id=case_id,
                    reason=escalation_reason,
                )
            )

        timeline = facts.get("latest_timeline_event")
        if timeline is not None and "latest_timeline_event" in selected:
            if isinstance(timeline, dict):
                event_type = _bounded_text(timeline.get("event_type"), 160)
                event_timestamp = _bounded_text(timeline.get("created_at"), 80)
            else:
                event_type = _bounded_text(timeline, 160)
                event_timestamp = None
            if event_type:
                atoms.append(
                    TimelineEventAtom(
                        atom_id=f"{prefix}:timeline:{_stable_suffix(event_type, event_timestamp)}",
                        authority_class=authority,
                        provenance=provenance,
                        incident_id=incident_id,
                        case_id=case_id,
                        timestamp=event_timestamp,
                        event_type=event_type,
                    )
                )

        if "compromise_confirmed" in selected:
            compromise = facts.get("compromise_confirmed")
            if compromise is None or isinstance(compromise, bool):
                atoms.append(
                    CompromiseStateAtom(
                        atom_id=f"{prefix}:compromise-state",
                        authority_class=authority,
                        provenance=provenance,
                        incident_id=incident_id,
                        case_id=case_id,
                        compromise_confirmed=compromise,
                    )
                )

        linked_cases = facts.get("linked_case_ids")
        if incident_id is not None and isinstance(linked_cases, list):
            for linked_case_id in linked_cases[:4]:
                if not isinstance(linked_case_id, int) or linked_case_id <= 0:
                    continue
                atoms.append(
                    CaseRelationshipAtom(
                        atom_id=f"{prefix}:case:{linked_case_id}",
                        authority_class=authority,
                        provenance=provenance,
                        incident_id=incident_id,
                        case_id=linked_case_id,
                        relationship_type="LINKED_TO_CASE",
                    )
                )

        return self._bounded(atoms, plan)

    @staticmethod
    def _bounded(atoms: Iterable[EvidenceAtom], plan: ContextPlan) -> list[EvidenceAtom]:
        timeline_count = 0
        bounded: list[EvidenceAtom] = []
        for atom in atoms:
            if isinstance(atom, TimelineEventAtom):
                if timeline_count >= plan.limits.max_timeline_atoms:
                    continue
                timeline_count += 1
            bounded.append(atom)
            if len(bounded) >= plan.limits.max_operational_atoms:
                break
        return bounded


def authoritative_source_ids(records: Iterable[Any]) -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    for record in records:
        if getattr(record, "authority", None) != "authoritative":
            continue
        source_id = getattr(record, "source_id", None)
        record_id = getattr(record, "record_id", None)
        source_type = getattr(record, "source_type", None)
        if source_id and record_id and source_type:
            result[(str(source_type), str(record_id))] = str(source_id)
    return result
