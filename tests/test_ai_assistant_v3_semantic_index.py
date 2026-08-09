from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Incident
from scripts.manage_incident_semantic_index import run as run_index_command
from services.assistant.v3.semantic_index import (
    INCIDENT_INDEX_DECISION_BOUNDARY,
    INCIDENT_SEMANTIC_SOURCE_TYPE,
    IncidentIndexOperationResult,
    IncidentIndexStatus,
    IncidentSemanticIndex,
    IncidentSemanticIndexConfig,
    build_incident_semantic_document,
    incident_semantic_point_id,
    incident_source_fingerprint,
    semantic_query_text_from_facts,
)


class _Client:
    def __init__(self) -> None:
        self.collections = set()
        self.points = {}
        self.query_results = []
        self.upserts = []
        self.deleted = []
        self.fail_query = False

    def get_collections(self):
        return SimpleNamespace(
            collections=[SimpleNamespace(name=value) for value in self.collections]
        )

    def create_collection(self, *, collection_name, vectors_config):
        self.collections.add(collection_name)
        self.vector_size = vectors_config.size

    def delete_collection(self, collection_name):
        self.collections.discard(collection_name)
        self.points.clear()

    def upsert(self, *, collection_name, points, wait):
        self.collections.add(collection_name)
        self.upserts.append((collection_name, list(points), wait))
        for point in points:
            self.points[str(point.id)] = point

    def delete(self, *, collection_name, points_selector, wait):
        self.deleted.append((collection_name, list(points_selector), wait))
        for point_id in points_selector:
            self.points.pop(str(point_id), None)

    def query_points(self, **_kwargs):
        if self.fail_query:
            raise OSError("qdrant unavailable")
        return SimpleNamespace(points=list(self.query_results))

    def scroll(self, *, limit, offset, **_kwargs):
        points = list(self.points.values())
        start = int(offset or 0)
        selected = points[start : start + limit]
        next_offset = start + len(selected) if start + len(selected) < len(points) else None
        return selected, next_offset


def _db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def _incident(doc_id: str, *, rule: str = "Registry changed") -> Incident:
    return Incident(
        wazuh_doc_id=doc_id,
        status="OPEN",
        timestamp="2026-08-08T10:00:00Z",
        agent="endpoint-a",
        rule=rule,
        level=10,
        mitre='["T1112"]',
        risk_score=72,
        correlated=True,
        correlation_type="registry_activity",
        correlation_score=75,
        recommended_priority="HIGH",
    )


def _index(client: _Client) -> IncidentSemanticIndex:
    return IncidentSemanticIndex(
        IncidentSemanticIndexConfig(
            collection_name="incident_semantic_index",
            embedding_model="test-embedding-v1",
            score_threshold=0.60,
            query_limit=8,
            upsert_batch_size=2,
        ),
        client=client,
        embedder=lambda text: [float(len(text)), 1.0, 0.5],
    )


def test_document_payload_and_fingerprint_are_deterministic() -> None:
    incident = _incident("document")
    incident.id = 42
    indexed_at = datetime(2026, 8, 8, tzinfo=timezone.utc)

    first = build_incident_semantic_document(
        incident,
        linked_case_ids=[7],
        indexed_at=indexed_at,
        embedding_version="test-v1",
    )
    second = build_incident_semantic_document(
        incident,
        linked_case_ids=[7],
        indexed_at=indexed_at,
        embedding_version="test-v1",
    )

    assert first == second
    assert first.point_id == incident_semantic_point_id(42)
    assert first.payload["source_type"] == INCIDENT_SEMANTIC_SOURCE_TYPE
    assert first.payload["source_fingerprint"] == first.source_fingerprint
    assert first.payload["embedding_version"] == "test-v1"
    assert first.payload["document_version"] == "v1"
    assert first.payload["mitre_ids"] == ["T1112"]
    assert first.payload["case_relationship_category"] == "linked_case"
    assert "Risk Score" not in first.text
    assert "AI Analysis" not in first.text
    assert INCIDENT_INDEX_DECISION_BOUNDARY in first.payload["decision_boundary"]

    original = incident_source_fingerprint(incident, linked_case_ids=[7])
    incident.rule = "PowerShell execution"
    assert incident_source_fingerprint(incident, linked_case_ids=[7]) != original


def test_query_text_uses_bounded_authoritative_semantic_fields() -> None:
    text = semantic_query_text_from_facts(
        {
            "rule": "Registry changed",
            "agent": "endpoint-a",
            "mitre": [{"id": "T1112"}],
            "correlation_type": "registry_activity",
            "linked_case_ids": [7],
            "risk_score": 99,
            "ai_analysis": "untrusted generated prose",
        }
    )

    assert "Registry changed" in text
    assert "T1112" in text
    assert "linked_case" in text
    assert "99" not in text
    assert "untrusted generated prose" not in text


def test_upsert_refresh_and_delete_use_one_stable_point() -> None:
    db = _db()
    client = _Client()
    index = _index(client)
    try:
        incident = _incident("upsert")
        db.add(incident)
        db.commit()

        first = index.upsert_incident(db, incident.id)
        incident.rule = "Updated registry rule"
        db.commit()
        second = index.upsert_incident(db, incident.id)

        assert first.indexed_count == 1
        assert second.indexed_count == 1
        assert len(client.points) == 1
        point = next(iter(client.points.values()))
        assert point.payload["rule_family"] == "Updated registry rule"

        deleted = index.delete(incident.id)
        assert deleted.deleted_count == 1
        assert client.points == {}
    finally:
        db.close()


def test_rebuild_batches_without_duplicates_and_status_detects_stale_missing() -> None:
    db = _db()
    client = _Client()
    index = _index(client)
    try:
        incidents = [_incident(f"rebuild-{value}", rule=f"Rule {value}") for value in range(3)]
        db.add_all(incidents)
        db.commit()

        rebuilt = index.rebuild(db)
        status = index.status(db)

        assert rebuilt.indexed_count == 3
        assert rebuilt.eligible_count == 3
        assert rebuilt.ineligible_count == 0
        assert rebuilt.embedding_failures == 0
        assert len(client.upserts) == 2
        assert status.status == "ready"
        assert status.indexed_count == 3
        assert status.unique_incident_ids == 3
        assert status.duplicate_ids == 0
        assert status.missing_ids == 0
        assert status.stale_fingerprints == 0
        assert status.eligible_incidents == 3
        assert status.ineligible_incidents == 0

        client.points["duplicate-alias"] = next(iter(client.points.values()))
        duplicate = index.status(db)
        assert duplicate.duplicate_ids == 1
        client.points.pop("duplicate-alias")

        incidents[0].rule = "Changed after indexing"
        db.commit()
        stale = index.status(db)
        assert stale.stale_fingerprints == 1

        client.points.pop(incident_semantic_point_id(incidents[1].id))
        missing = index.status(db)
        assert missing.missing_ids == 1
    finally:
        db.close()


def test_semantic_query_filters_self_threshold_duplicates_and_invalid_payloads() -> None:
    client = _Client()
    index = _index(client)
    fingerprint = "a" * 64
    client.query_results = [
        SimpleNamespace(
            score=0.91,
            payload={
                "source_type": INCIDENT_SEMANTIC_SOURCE_TYPE,
                "incident_id": 1,
                "source_fingerprint": fingerprint,
            },
        ),
        SimpleNamespace(
            score=0.82,
            payload={
                "source_type": INCIDENT_SEMANTIC_SOURCE_TYPE,
                "incident_id": 2,
                "source_fingerprint": fingerprint,
            },
        ),
        SimpleNamespace(
            score=0.80,
            payload={
                "source_type": INCIDENT_SEMANTIC_SOURCE_TYPE,
                "incident_id": 2,
                "source_fingerprint": fingerprint,
            },
        ),
        SimpleNamespace(
            score=0.40,
            payload={
                "source_type": INCIDENT_SEMANTIC_SOURCE_TYPE,
                "incident_id": 3,
                "source_fingerprint": fingerprint,
            },
        ),
        SimpleNamespace(
            score=0.99,
            payload={"source_type": "knowledge_base", "incident_id": 4},
        ),
    ]

    result = index.query("registry activity", exclude_incident_id=1)

    assert result.status == "ready"
    assert [(item.incident_id, item.score) for item in result.hits] == [(2, 0.82)]
    assert result.hits[0].source_fingerprint == fingerprint


def test_qdrant_and_embedding_unavailability_degrade_without_hits(monkeypatch) -> None:
    client = _Client()
    client.fail_query = True
    unavailable = _index(client).query("registry activity")
    assert unavailable.status == "unavailable"
    assert unavailable.hits == ()

    index = IncidentSemanticIndex(
        IncidentSemanticIndexConfig(collection_name="incident_semantic_index"),
        client=client,
    )
    monkeypatch.setattr(
        "services.assistant.v3.semantic_index.embedding_runtime_snapshot",
        lambda *_args, **_kwargs: {"embedding_ready": False},
    )
    degraded = index.query("registry activity")
    assert degraded.status == "degraded"
    assert degraded.hits == ()


def test_cli_lifecycle_dispatch_is_typed_and_closes_db() -> None:
    class Db:
        closed = False

        def close(self):
            self.closed = True

    db = Db()

    class Index:
        def status(self, selected_db, *, limit):
            assert selected_db is db
            assert limit == 60
            return IncidentIndexStatus(
                collection="incident_semantic_index",
                status="ready",
                indexed_count=60,
                unique_incident_ids=60,
            )

    result = run_index_command(
        action="status",
        limit=60,
        db_factory=lambda: db,
        index_factory=Index,
    )

    assert result["indexed_count"] == 60
    assert result["decision_boundary"] == INCIDENT_INDEX_DECISION_BOUNDARY
    assert db.closed is True


def test_rebuild_uses_batch_embedding_and_default_cli_has_no_corpus_cap(
    monkeypatch,
) -> None:
    class Encoded(list):
        def tolist(self):
            return list(self)

    class Encoder:
        calls = []

        def encode(self, texts, **kwargs):
            self.calls.append((list(texts), kwargs))
            return Encoded([[float(len(text)), 1.0, 0.5] for text in texts])

    encoder = Encoder()
    monkeypatch.setattr(
        "services.assistant.v3.semantic_index.get_knowledge_base",
        lambda: SimpleNamespace(encoder=encoder),
    )
    db = _db()
    client = _Client()
    index = IncidentSemanticIndex(
        IncidentSemanticIndexConfig(
            collection_name="incident_semantic_index",
            embedding_model="test-embedding-v1",
            upsert_batch_size=8,
        ),
        client=client,
    )
    try:
        db.add_all([_incident(f"batch-{value}") for value in range(3)])
        db.commit()

        result = index.rebuild(db)

        assert result.status == "ok"
        assert result.indexed_count == result.eligible_count == 3
        assert len(encoder.calls) == 1
        assert len(encoder.calls[0][0]) == 3
        assert encoder.calls[0][1]["batch_size"] == 8
    finally:
        db.close()

    class Db:
        closed = False

        def close(self):
            self.closed = True

    uncapped_db = Db()

    class Index:
        def status(self, selected_db, *, limit):
            assert selected_db is uncapped_db
            assert limit is None
            return IncidentIndexStatus(
                collection="incident_semantic_index",
                status="ready",
            )

    run_index_command(
        action="status",
        db_factory=lambda: uncapped_db,
        index_factory=Index,
    )
    assert uncapped_db.closed is True


def test_operation_result_is_closed_for_best_effort_incremental_reporting() -> None:
    result = IncidentIndexOperationResult(
        collection="incident_semantic_index",
        indexed_count=1,
    )
    assert result.to_dict() == {
        "collection": "incident_semantic_index",
        "eligible_count": 0,
        "ineligible_count": 0,
        "indexed_count": 1,
        "deleted_count": 0,
        "embedding_failures": 0,
        "duration_ms": 0.0,
        "status": "ok",
        "error_category": None,
    }
