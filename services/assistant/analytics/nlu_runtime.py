from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol


@dataclass(frozen=True)
class DependencyToken:
    sentence_id: int
    token_id: int
    text: str
    lemma: str
    upos: str
    features: frozenset[tuple[str, str]]
    head_id: int
    relation: str

    def feature(self, name: str) -> str | None:
        return dict(self.features).get(name)


@dataclass(frozen=True)
class DependencyDocument:
    language: Literal["en", "it"]
    tokens: tuple[DependencyToken, ...]
    parse_ms: float

    def token(self, token_id: int) -> DependencyToken | None:
        return next((item for item in self.tokens if item.token_id == token_id), None)

    def children(self, token_id: int) -> tuple[DependencyToken, ...]:
        return tuple(item for item in self.tokens if item.head_id == token_id)


class DependencyParser(Protocol):
    def parse(self, text: str) -> DependencyDocument: ...

    def warm(self) -> bool: ...


def _features(value: str | None) -> frozenset[tuple[str, str]]:
    if not value:
        return frozenset()
    parsed: list[tuple[str, str]] = []
    for item in value.split("|"):
        name, separator, selected = item.partition("=")
        if separator and name and selected:
            parsed.append((name, selected))
    return frozenset(parsed)


class StanzaDependencyParser:
    """Lazy local UD parser. Runtime model downloads are deliberately disabled."""

    def __init__(self, *, model_dir: str | Path | None = None) -> None:
        self._model_dir = Path(
            model_dir
            or os.getenv(
                "AI_SOC_SEMANTIC_NLU_MODEL_DIR",
                "/opt/ai-soc/models/semantic-nlu/stanza",
            )
        )
        self._language_pipeline: Any | None = None
        self._pipelines: dict[str, Any] = {}
        self._load_lock = threading.Lock()
        self._parse_lock = threading.Lock()

    def _pipeline(self, language: str) -> Any:
        import stanza

        with self._load_lock:
            if self._language_pipeline is None:
                self._language_pipeline = stanza.Pipeline(
                    lang="multilingual",
                    processors="langid",
                    dir=str(self._model_dir),
                    download_method=None,
                    verbose=False,
                )
            if language not in self._pipelines:
                self._pipelines[language] = stanza.Pipeline(
                    lang=language,
                    processors="tokenize,pos,lemma,depparse",
                    package={
                        "tokenize": "default",
                        "pos": "combined_nocharlm",
                        "lemma": "default",
                        "depparse": "combined_nocharlm",
                    },
                    dir=str(self._model_dir),
                    download_method=None,
                    use_gpu=False,
                    verbose=False,
                )
            return self._pipelines[language]

    def warm(self) -> bool:
        try:
            for language in ("en", "it"):
                self._pipeline(language)
        except Exception:
            return False
        return True

    def parse(self, text: str) -> DependencyDocument:
        started = time.monotonic()
        with self._parse_lock:
            language_document = self._pipeline("en")
            del language_document
            detected = str(self._language_pipeline(text).lang or "en")
            language: Literal["en", "it"] = "it" if detected == "it" else "en"
            document = self._pipeline(language)(text)
        parsed_tokens: list[DependencyToken] = []
        offset = 0
        for sentence_id, sentence in enumerate(document.sentences, start=1):
            for word in sentence.words:
                local_head = int(word.head)
                parsed_tokens.append(
                    DependencyToken(
                        sentence_id=sentence_id,
                        token_id=offset + int(word.id),
                        text=str(word.text),
                        lemma=str(word.lemma or word.text).casefold(),
                        upos=str(word.upos or "X"),
                        features=_features(word.feats),
                        head_id=0 if local_head == 0 else offset + local_head,
                        relation=str(word.deprel or "dep"),
                    )
                )
            offset += len(sentence.words)
        tokens = tuple(parsed_tokens)
        return DependencyDocument(
            language=language,
            tokens=tokens,
            parse_ms=max(0.0, (time.monotonic() - started) * 1000),
        )


_DEFAULT_DEPENDENCY_PARSER = StanzaDependencyParser()


def get_dependency_parser() -> StanzaDependencyParser:
    return _DEFAULT_DEPENDENCY_PARSER
