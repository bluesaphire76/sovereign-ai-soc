from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Incident, IncidentCase
from services.assistant.v3.contracts import (
    AnalyticalFocus,
    AnswerIntent,
    ValidatedConversationState,
)
from services.assistant.v3.conversation import (
    ConversationStateStore,
    conversation_store_from_env,
    conversation_owner_key,
    updated_conversation_state,
)


def _state(*, owner: str, conversation: str, now: float = 100.0):
    return updated_conversation_state(
        existing=None,
        conversation_id=conversation,
        owner_key=owner,
        active_incident_ids=[1, 999],
        active_case_ids=[1, 999],
        related_incident_ids=[2, 998],
        intent=AnswerIntent.INVESTIGATE,
        focus_dimensions=[AnalyticalFocus.EVIDENCE],
        atom_refs=["incident:1:identity"],
        relationship_refs=["relationship:one"],
        reference_refs=["reference:one"],
        advisory_refs=["advisory:one"],
        response_language="it",
        now=now,
    )


def _db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    db.add_all(
        [
            Incident(id=1, wazuh_doc_id="conversation-1", status="OPEN"),
            Incident(id=2, wazuh_doc_id="conversation-2", status="OPEN"),
            IncidentCase(id=1, group_key="conversation-case", title="Conversation case"),
        ]
    )
    db.commit()
    return db


def test_conversation_state_is_user_and_conversation_isolated() -> None:
    store = ConversationStateStore(clock=lambda: 100.0)
    owner_a = conversation_owner_key({"username": "analyst-a", "role": "ANALYST"})
    owner_b = conversation_owner_key({"username": "analyst-b", "role": "ANALYST"})
    store.save(_state(owner=owner_a, conversation="thread-a"))

    assert store.load(owner_key=owner_a, conversation_id="thread-a") is not None
    assert store.load(owner_key=owner_b, conversation_id="thread-a") is None
    assert store.load(owner_key=owner_a, conversation_id="thread-b") is None


def test_conversation_load_drops_deleted_incident_and_case_references() -> None:
    db = _db()
    try:
        owner = conversation_owner_key({"username": "analyst"})
        store = ConversationStateStore(clock=lambda: 100.0)
        store.save(_state(owner=owner, conversation="cleanup"))

        loaded = store.load(owner_key=owner, conversation_id="cleanup", db=db)

        assert loaded is not None
        assert loaded.active_incident_ids == [1]
        assert loaded.related_incident_ids == [2]
        assert loaded.active_case_ids == [1]
        assert loaded.response_language == "it"
    finally:
        db.close()


def test_conversation_state_is_bounded_expires_and_contains_no_prose_field() -> None:
    now = [100.0]
    owner = conversation_owner_key({"username": "analyst"})
    store = ConversationStateStore(ttl_seconds=60, clock=lambda: now[0])
    state = _state(owner=owner, conversation="bounded")
    store.save(state)

    assert "answer" not in ValidatedConversationState.model_fields
    assert "assistant_prose" not in ValidatedConversationState.model_fields
    assert all(isinstance(item, str) for item in state.validated_atom_refs)
    now[0] = 161.0
    assert store.load(owner_key=owner, conversation_id="bounded") is None


def test_conversation_cleanup_is_explicit_and_scoped() -> None:
    owner = conversation_owner_key({"username": "analyst"})
    store = ConversationStateStore(clock=lambda: 100.0)
    store.save(_state(owner=owner, conversation="clear-me"))

    assert store.clear(owner_key=owner, conversation_id="clear-me") is True
    assert store.clear(owner_key=owner, conversation_id="clear-me") is False


def test_conversation_load_drops_refs_no_longer_authorized_for_owner() -> None:
    db = _db()
    try:
        owner = conversation_owner_key({"username": "analyst"})
        store = ConversationStateStore(clock=lambda: 100.0)
        store.save(_state(owner=owner, conversation="authorization-change"))

        loaded = store.load(
            owner_key=owner,
            conversation_id="authorization-change",
            db=db,
            authorized_incident_ids=lambda _values: {1},
        )

        assert loaded is not None
        assert loaded.active_incident_ids == [1]
        assert loaded.related_incident_ids == []
    finally:
        db.close()


def test_conversation_store_configuration_is_bounded(monkeypatch) -> None:
    monkeypatch.setenv("AI_SOC_ASSISTANT_CONVERSATION_TTL_SECONDS", "1")
    monkeypatch.setenv("AI_SOC_ASSISTANT_MAX_CONVERSATIONS", "99999")
    monkeypatch.setenv("AI_SOC_ASSISTANT_MAX_CONVERSATIONS_PER_USER", "0")

    store = conversation_store_from_env()

    assert store._ttl_seconds == 60
    assert store._max_states == 4096
    assert store._max_states_per_owner == 1
