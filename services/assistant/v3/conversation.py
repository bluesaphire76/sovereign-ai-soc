from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Mapping

from models import Incident, IncidentCase
from services.assistant.v3.contracts import (
    AnalyticalFocus,
    AnswerIntent,
    ValidatedConversationState,
)


def conversation_owner_key(current_user: Mapping[str, Any] | None) -> str:
    user = current_user or {}
    identity = next(
        (
            str(user[field])
            for field in ("id", "username", "sub", "actor")
            if user.get(field) is not None
        ),
        "local-anonymous",
    )
    role = str(user.get("role") or "unknown")
    return hashlib.sha256(f"{identity}\x1f{role}".encode("utf-8")).hexdigest()


class ConversationStateStore:
    def __init__(
        self,
        *,
        ttl_seconds: float = 3600.0,
        max_states: int = 512,
        max_states_per_owner: int = 16,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._ttl_seconds = max(60.0, ttl_seconds)
        self._max_states = max(1, max_states)
        self._max_states_per_owner = max(1, max_states_per_owner)
        self._clock = clock
        self._states: OrderedDict[tuple[str, str], ValidatedConversationState] = OrderedDict()
        self._lock = threading.Lock()

    def _purge_locked(self, now: float) -> None:
        expired = [
            key
            for key, state in self._states.items()
            if now - state.updated_at_epoch > self._ttl_seconds
        ]
        for key in expired:
            self._states.pop(key, None)

    def load(
        self,
        *,
        owner_key: str,
        conversation_id: str | None,
        db: Any | None = None,
    ) -> ValidatedConversationState | None:
        if not conversation_id:
            return None
        now = self._clock()
        key = (owner_key, conversation_id)
        with self._lock:
            self._purge_locked(now)
            state = self._states.get(key)
            if state is None:
                return None
            self._states.move_to_end(key)
        if db is None or not hasattr(db, "query"):
            return state
        incidents = self._existing_ids(db, Incident, [
            *state.active_incident_ids,
            *state.related_incident_ids,
        ])
        cases = self._existing_ids(db, IncidentCase, state.active_case_ids)
        active_incidents = [value for value in state.active_incident_ids if value in incidents]
        related_incidents = [value for value in state.related_incident_ids if value in incidents]
        active_cases = [value for value in state.active_case_ids if value in cases]
        if (
            active_incidents == state.active_incident_ids
            and related_incidents == state.related_incident_ids
            and active_cases == state.active_case_ids
        ):
            return state
        cleaned = state.model_copy(
            update={
                "active_incident_ids": active_incidents,
                "related_incident_ids": related_incidents,
                "active_case_ids": active_cases,
                "updated_at_epoch": now,
            }
        )
        self.save(cleaned)
        return cleaned

    @staticmethod
    def _existing_ids(db: Any, model: Any, values: list[int]) -> set[int]:
        ids = list(dict.fromkeys(values))
        if not ids:
            return set()
        try:
            rows = db.query(model.id).filter(model.id.in_(ids)).all()
        except Exception:
            return set()
        return {int(row[0] if isinstance(row, tuple) else row.id) for row in rows}

    def save(self, state: ValidatedConversationState) -> None:
        key = (state.owner_key, state.conversation_id)
        now = self._clock()
        with self._lock:
            self._purge_locked(now)
            self._states[key] = state
            self._states.move_to_end(key)
            owner_keys = [item for item in self._states if item[0] == state.owner_key]
            while len(owner_keys) > self._max_states_per_owner:
                self._states.pop(owner_keys.pop(0), None)
            while len(self._states) > self._max_states:
                self._states.popitem(last=False)

    def clear(self, *, owner_key: str, conversation_id: str) -> bool:
        with self._lock:
            return self._states.pop((owner_key, conversation_id), None) is not None


def updated_conversation_state(
    *,
    existing: ValidatedConversationState | None,
    conversation_id: str,
    owner_key: str,
    active_incident_ids: list[int],
    active_case_ids: list[int],
    related_incident_ids: list[int],
    intent: AnswerIntent,
    focus_dimensions: list[AnalyticalFocus],
    atom_refs: list[str],
    relationship_refs: list[str],
    reference_refs: list[str],
    advisory_refs: list[str],
    response_language: str,
    now: float,
) -> ValidatedConversationState:
    previous_intents = list(existing.previous_intents) if existing else []
    previous_intents = [*previous_intents, intent][-8:]
    return ValidatedConversationState(
        conversation_id=conversation_id,
        owner_key=owner_key,
        active_incident_ids=list(dict.fromkeys(active_incident_ids))[:12],
        active_case_ids=list(dict.fromkeys(active_case_ids))[:4],
        related_incident_ids=list(dict.fromkeys(related_incident_ids))[:12],
        previous_intents=previous_intents,
        previous_focus_dimensions=list(dict.fromkeys(focus_dimensions))[:9],
        validated_atom_refs=list(dict.fromkeys(atom_refs))[:160],
        validated_relationship_refs=list(dict.fromkeys(relationship_refs))[:80],
        reference_knowledge_refs=list(dict.fromkeys(reference_refs))[:40],
        advisory_refs=list(dict.fromkeys(advisory_refs))[:40],
        response_language="it" if response_language == "it" else "en",
        updated_at_epoch=max(0.0, now),
    )


_DEFAULT_CONVERSATION_STORE = ConversationStateStore()


def get_conversation_state_store() -> ConversationStateStore:
    return _DEFAULT_CONVERSATION_STORE
