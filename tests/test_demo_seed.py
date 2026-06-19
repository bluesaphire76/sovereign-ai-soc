from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import (
    Base,
    CaseAction,
    CaseAIAnalysis,
    CaseIncident,
    Incident,
    IncidentCase,
)
from scripts import demo_seed


def database_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_demo_seed_is_idempotent_and_creates_only_demo_owned_records():
    db = database_session()

    first = demo_seed.apply_seed(db, __import__("models"))
    db.commit()
    second = demo_seed.apply_seed(db, __import__("models"))
    db.commit()

    assert first["created"]["incidents"] == 5
    assert first["created"]["cases"] == 1
    assert first["created"]["case_links"] == 3
    assert first["created"]["case_actions"] == 1
    assert first["created"]["case_ai_analyses"] == 1
    assert all(value == 0 for value in second["created"].values())
    assert second["skipped"]["incidents"] == 5
    assert db.query(Incident).count() == 5
    assert db.query(IncidentCase).count() == 1
    assert db.query(CaseIncident).count() == 3
    assert db.query(CaseAction).count() == 1
    assert db.query(CaseAIAnalysis).count() == 1
    assert demo_seed.seed_status(db, __import__("models"))["complete"] is True


def test_demo_seed_refuses_a_non_demo_marker_collision():
    db = database_session()
    db.add(
        Incident(
            wazuh_doc_id=demo_seed.SCENARIOS[0].external_id,
            rule="real record using a conflicting marker",
            raw_alert="{}",
        )
    )
    db.commit()

    try:
        demo_seed.apply_seed(db, __import__("models"))
    except demo_seed.UnsafeSeedError as exc:
        assert "marker collision" in str(exc)
    else:
        raise AssertionError("expected an unsafe marker collision")

    assert db.query(Incident).count() == 1
