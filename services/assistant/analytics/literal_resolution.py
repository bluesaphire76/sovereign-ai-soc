from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Sequence

from services.assistant.analytics.nlu_runtime import DependencyDocument


def normalized_literal_tokens(value: str) -> tuple[str, ...]:
    folded = unicodedata.normalize("NFKD", str(value or "").casefold())
    tokens: list[str] = []
    current: list[str] = []
    for character in folded:
        if unicodedata.combining(character):
            continue
        if character.isalnum():
            current.append(character)
        elif current:
            tokens.append("".join(current))
            current = []
    if current:
        tokens.append("".join(current))
    return tuple(tokens)


def _document_tokens(document: DependencyDocument) -> tuple[str, ...]:
    return tuple(
        part
        for token in document.tokens
        for part in normalized_literal_tokens(token.text)
    )


def resolve_closed_literals(
    document: DependencyDocument,
    candidates: Iterable[str],
    *,
    maximum: int = 10,
) -> tuple[str, ...]:
    """Resolve explicit canonical values after their typed domain is known."""

    query = _document_tokens(document)
    resolved: list[tuple[str, tuple[str, ...], int]] = []
    for candidate in candidates:
        parts = normalized_literal_tokens(candidate)
        if not parts or len(parts) > len(query):
            continue
        positions = tuple(
            offset
            for offset in range(len(query) - len(parts) + 1)
            if query[offset : offset + len(parts)] == parts
        )
        if positions:
            resolved.append((candidate, parts, positions[0]))
    resolved.sort(key=lambda item: (-len(item[1]), item[2], item[0]))
    selected: list[tuple[str, tuple[str, ...], int]] = []
    for item in resolved:
        _candidate, parts, position = item
        if any(
            position >= other_position
            and position + len(parts) <= other_position + len(other_parts)
            for _other, other_parts, other_position in selected
        ):
            continue
        selected.append(item)
    return tuple(item[0] for item in selected[:maximum])


def numeric_literals(document: DependencyDocument) -> tuple[int, ...]:
    return tuple(
        int(item.text)
        for item in document.tokens
        if item.upos == "NUM" and item.text.isdigit() and int(item.text) > 0
    )


def has_discourse_reference(document: DependencyDocument) -> bool:
    return any(
        item.feature("PronType") in {"Dem", "Rel", "Prs", "Int", "Ind"}
        and item.upos in {"PRON", "DET"}
        for item in document.tokens
    )


def semantic_token_spans(
    document: DependencyDocument,
    *,
    allowed_pos: Sequence[str] = ("ADJ", "NOUN", "PROPN", "VERB"),
) -> tuple[str, ...]:
    spans: list[str] = []
    for token in document.tokens:
        if token.upos not in allowed_pos:
            continue
        children = tuple(
            child
            for child in document.children(token.token_id)
            if child.relation in {"amod", "compound", "fixed", "flat"}
        )
        phrase = " ".join(
            item.lemma
            for item in sorted((token, *children), key=lambda item: item.token_id)
        )
        spans.append(phrase)
    return tuple(dict.fromkeys(spans))
