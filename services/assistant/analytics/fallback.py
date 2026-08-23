from __future__ import annotations

import time

from services.assistant.v3.contracts import (
    AnalyticalDimension,
    AnalyticalOperation,
    AnalyticalRelationship,
    AnalyticalResultAtom,
    AnalyticalResultRow,
    RelationshipClass,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.discourse import RenderedV3Answer, RenderedV3Block
from services.assistant.v3.plan_contracts import AnswerSectionType


def _number(value: int | float) -> str:
    numeric = float(value)
    return str(int(numeric)) if numeric.is_integer() else format(numeric, ".4g")


def _window(atom: AnalyticalResultAtom, *, language: str) -> str:
    if atom.time_window is None:
        return ""
    current = f"{atom.time_window.start_utc} - {atom.time_window.end_utc} UTC"
    if atom.comparison_window is None:
        return (
            f" nella finestra {current}"
            if language == "it"
            else f" in the {current} window"
        )
    previous = (
        f"{atom.comparison_window.start_utc} - "
        f"{atom.comparison_window.end_utc} UTC"
    )
    return (
        f" tra la finestra corrente {current} e quella precedente {previous}"
        if language == "it"
        else f" between the current window {current} and the previous window {previous}"
    )


def _filters(atom: AnalyticalResultAtom, *, language: str) -> str:
    if not atom.filters:
        return ""
    labels = {
        "AGENT": "host",
        "RECORDED_RISK": "rischio registrato",
        "SLA_STATE": "stato SLA",
        "STATUS": "stato",
    }
    filters = ", ".join(
        f"{labels.get(item.field.value, item.field.value.lower())} "
        f"{', '.join(item.values)}"
        if language == "it"
        else f"{item.field.value.lower().replace('_', ' ')} "
        f"{', '.join(item.values)}"
        for item in atom.filters
    )
    return f" con filtri {filters}" if language == "it" else f" with filters {filters}"


def _entity_count(
    atom: AnalyticalResultAtom,
    value: int | float,
    *,
    language: str,
) -> str:
    if atom.entity.value == "CASE":
        return "caso" if language == "it" and value == 1 else "casi" if language == "it" else "case" if value == 1 else "cases"
    return "incidente" if language == "it" and value == 1 else "incidenti" if language == "it" else "incident" if value == 1 else "incidents"


def _row_label(row: AnalyticalResultRow, *, language: str) -> str:
    if row.incident_id is not None:
        return (
            f"incidente {row.incident_id}"
            if language == "it"
            else f"incident {row.incident_id}"
        )
    if row.case_id is not None:
        return (
            f"caso {row.case_id}"
            if language == "it"
            else f"case {row.case_id}"
        )
    dimensions = ", ".join(
        f"MITRE {item.value}"
        if item.dimension is AnalyticalDimension.MITRE_TECHNIQUE
        else item.value
        for item in row.dimensions
    )
    return dimensions


def _row_text(row: AnalyticalResultRow, *, language: str) -> str:
    label = _row_label(row, language=language)
    measure = (
        _number(row.measure_value) if row.measure_value is not None else ""
    )
    return ": ".join(
        value for value in (label, measure) if value
    ) or row.row_id


def _ranked_rows(rows: list[AnalyticalResultRow], *, language: str) -> str:
    return "; ".join(
        f"{_row_label(row, language=language)} ({_number(row.measure_value or 0)})"
        for row in rows
    )


def _ranking_intro(dimension: AnalyticalDimension | None, *, language: str) -> str:
    if language == "it":
        return {
            AnalyticalDimension.AGENT: "Gli host con più incidenti sono",
            AnalyticalDimension.DETECTION_RULE: "Le regole di detection con più incidenti sono",
            AnalyticalDimension.MITRE_TECHNIQUE: "Le tecniche MITRE più frequenti sono",
            AnalyticalDimension.STATUS: "La distribuzione per stato è",
        }.get(dimension, "Il risultato analitico è")
    return {
        AnalyticalDimension.AGENT: "The hosts with the most incidents are",
        AnalyticalDimension.DETECTION_RULE: "The detection rules with the most incidents are",
        AnalyticalDimension.MITRE_TECHNIQUE: "The most frequent MITRE techniques are",
        AnalyticalDimension.STATUS: "The status distribution is",
    }.get(dimension, "The analytical result is")


def _identity_refs(
    package: V3AnalyticalContextPackage,
    result_ids: list[int],
) -> tuple[str, ...]:
    selected = set(result_ids[:6])
    return tuple(
        atom.atom_id
        for atom in package.operational_atoms
        if atom.atom_type in {"incident_identity", "case_identity"}
        and (atom.incident_id in selected or atom.case_id in selected)
    )


def _relationship_refs(
    atom: AnalyticalResultAtom,
    relationships: list[AnalyticalRelationship],
) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            [atom.atom_id, *(item.relationship_id for item in relationships[:6])]
        )
    )


def render_global_analytics_fallback(
    package: V3AnalyticalContextPackage,
) -> RenderedV3Answer:
    started = time.monotonic()
    atom = next(
        (
            item
            for item in package.operational_atoms
            if isinstance(item, AnalyticalResultAtom)
        ),
        None,
    )
    if atom is None:
        raise ValueError("global analytics fallback requires an analytical result")
    language = package.response_language
    source_refs = (atom.atom_id,)
    blocks: list[RenderedV3Block] = []

    if atom.operation is AnalyticalOperation.COUNT:
        value = _number(atom.scalar_value or 0)
        entity = _entity_count(
            atom,
            float(atom.scalar_value or 0),
            language=language,
        )
        text = (
            f"Il conteggio analitico è {value} {entity}"
            f"{_filters(atom, language=language)}{_window(atom, language=language)}."
            if language == "it"
            else f"The analytical count is {value} {entity}"
            f"{_filters(atom, language=language)}{_window(atom, language=language)}."
        )
        blocks.append(
            RenderedV3Block(AnswerSectionType.DIRECT_ANSWER, text, source_refs)
        )
    elif atom.operation is AnalyticalOperation.COMPARE_PERIODS:
        values = [row.measure_value for row in atom.rows[:2]]
        current = _number(values[0] or 0) if values else "0"
        previous = _number(values[1] or 0) if len(values) > 1 else "0"
        difference = _number((values[0] or 0) - (values[1] or 0)) if len(values) > 1 else "0"
        current_entity = _entity_count(atom, values[0] or 0, language=language)
        previous_entity = _entity_count(
            atom,
            values[1] or 0 if len(values) > 1 else 0,
            language=language,
        )
        text = (
            f"Il periodo corrente registra {current} {current_entity}, quello precedente "
            f"{previous} {previous_entity}; "
            f"la differenza è {difference}{_window(atom, language=language)}."
            if language == "it"
            else f"The current period records {current} {current_entity} and the previous "
            f"period {previous} {previous_entity}; "
            f"the difference is {difference}{_window(atom, language=language)}."
        )
        blocks.append(
            RenderedV3Block(AnswerSectionType.COMPARISON, text, source_refs)
        )
    elif atom.operation is AnalyticalOperation.RELATED_RECORDS:
        relationships = [
            item
            for item in package.relationship_registry.relationships
            if item.relationship_class is RelationshipClass.RECORDED_CORRELATION
        ]
        incident_ids = [item.right_incident_id for item in relationships]
        listed = ", ".join(str(value) for value in incident_ids) or (
            "nessuno" if language == "it" else "none"
        )
        text = (
            f"La piattaforma registra {len(relationships)} relazioni di correlazione con "
            f"gli incidenti: {listed}."
            if language == "it"
            else f"The platform records {len(relationships)} correlation relationships "
            f"with incidents: {listed}."
        )
        refs = _relationship_refs(atom, relationships)
        blocks.append(
            RenderedV3Block(AnswerSectionType.RELATED_INCIDENTS, text, refs)
        )
    elif atom.operation is AnalyticalOperation.SIMILAR_RECORDS:
        relationships = [
            item
            for item in package.relationship_registry.relationships
            if item.relationship_class is RelationshipClass.SEMANTIC_SIMILARITY
        ]
        incident_ids = [item.right_incident_id for item in relationships]
        listed = ", ".join(str(value) for value in incident_ids) or (
            "nessuno" if language == "it" else "none"
        )
        refs = _relationship_refs(atom, relationships)
        direct = (
            f"La discovery semantica ha restituito {len(relationships)} candidati reidratati "
            f"da SQL: {listed}."
            if language == "it"
            else f"Semantic discovery returned {len(relationships)} SQL-rehydrated "
            f"candidates: {listed}."
        )
        caveat = (
            "La similarità semantica non dimostra correlazione registrata, stesso attacco, "
            "stesso attaccante, stessa campagna, causalità o compromissione."
            if language == "it"
            else "Semantic similarity does not establish recorded correlation, the same attack, "
            "attacker, campaign, causality, or compromise."
        )
        blocks.extend(
            [
                RenderedV3Block(AnswerSectionType.RELATED_INCIDENTS, direct, refs),
                RenderedV3Block(
                    AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
                    caveat,
                    refs,
                ),
            ]
        )
    else:
        rows = atom.rows[:10]
        row_summary = "; ".join(
            _row_text(row, language=language) for row in rows
        ) or (
            "nessun risultato" if language == "it" else "no results"
        )
        if atom.operation is AnalyticalOperation.LIST:
            count = len(atom.result_ids)
            entity = _entity_count(atom, count, language=language)
            if count == 0:
                text = (
                    f"Non risultano {entity}{_filters(atom, language=language)}"
                    f"{_window(atom, language=language)}."
                    if language == "it"
                    else f"No {entity} were found{_filters(atom, language=language)}"
                    f"{_window(atom, language=language)}."
                )
            else:
                text = (
                    f"Sono stati trovati {count} {entity}: {row_summary}"
                    f"{_filters(atom, language=language)}{_window(atom, language=language)}."
                    if language == "it"
                    else f"The query found {count} {entity}: {row_summary}"
                    f"{_filters(atom, language=language)}{_window(atom, language=language)}."
                )
        elif atom.operation in {
            AnalyticalOperation.TOP_K,
            AnalyticalOperation.DISTRIBUTION,
        }:
            dimension = rows[0].dimensions[0].dimension if rows and rows[0].dimensions else None
            ranked = _ranked_rows(rows, language=language) or row_summary
            text = (
                f"{_ranking_intro(dimension, language=language)}: {ranked}"
                f"{_window(atom, language=language)}."
            )
        else:
            text = (
                f"Il risultato analitico è: {row_summary}{_window(atom, language=language)}."
                if language == "it"
                else f"The analytical result is: {row_summary}{_window(atom, language=language)}."
            )
        refs = tuple(
            dict.fromkeys([*source_refs, *_identity_refs(package, atom.result_ids)])
        )
        blocks.append(
            RenderedV3Block(AnswerSectionType.DIRECT_ANSWER, text, refs)
        )
        if atom.result_truncated:
            blocks.append(
                RenderedV3Block(
                    AnswerSectionType.LIMITATIONS,
                    (
                        "Il risultato è limitato dal massimo definito nel registry analytics."
                        if language == "it"
                        else "The result is bounded by the analytics registry maximum."
                    ),
                    source_refs,
                )
            )

    return RenderedV3Answer(
        blocks=tuple(blocks),
        render_ms=max(0.0, (time.monotonic() - started) * 1000),
    )
