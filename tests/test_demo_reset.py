from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

import models
from models import Base, Incident, IncidentNote
from scripts import demo_reset, demo_seed


def database_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def test_demo_reset_dry_run_does_not_delete_anything() -> None:
    db = database_session()
    demo_seed.apply_seed(db, models)
    db.commit()

    plan = demo_reset.collect_reset_plan(db, models)

    assert plan.counts["incidents"] == 5
    assert plan.counts["cases"] == 1
    assert db.query(models.Incident).count() == 5
    assert db.query(models.IncidentCase).count() == 1


def test_demo_reset_apply_deletes_only_demo_owned_records_and_is_idempotent() -> None:
    db = database_session()
    real_incident = Incident(
        wazuh_doc_id="real-operational-record",
        rule="Real record",
        raw_alert='{"synthetic": false}',
    )
    db.add(real_incident)
    demo_seed.apply_seed(db, models)
    db.commit()

    first_plan = demo_reset.collect_reset_plan(db, models)
    deleted = demo_reset.apply_reset(db, first_plan)
    db.commit()

    assert deleted["incidents"] == 5
    assert db.query(Incident).count() == 1
    assert db.query(Incident).one().wazuh_doc_id == "real-operational-record"
    second_plan = demo_reset.collect_reset_plan(db, models)
    assert all(count == 0 for count in second_plan.counts.values())


def test_demo_reset_refuses_non_demo_child_record() -> None:
    db = database_session()
    demo_seed.apply_seed(db, models)
    db.commit()
    incident = (
        db.query(Incident)
        .filter(Incident.wazuh_doc_id == demo_seed.SCENARIOS[0].external_id)
        .one()
    )
    db.add(
        IncidentNote(
            incident_id=incident.id,
            note="Analyst note that is not owned by the seed.",
            created_by="real.analyst",
        )
    )
    db.commit()

    with pytest.raises(demo_reset.UnsafeResetError, match="non-demo incident note"):
        demo_reset.collect_reset_plan(db, models)

    assert db.query(Incident).count() == 5
    assert db.query(IncidentNote).count() == 6


def test_demo_reset_does_not_delete_title_only_demo_record() -> None:
    db = database_session()
    db.add(
        Incident(
            wazuh_doc_id="real-record",
            rule="[DEMO] title alone is not ownership",
            raw_alert="{}",
        )
    )
    db.commit()

    plan = demo_reset.collect_reset_plan(db, models)
    demo_reset.apply_reset(db, plan)
    db.commit()

    assert db.query(Incident).count() == 1


def test_demo_reset_source_uses_orm_deletes_and_no_shell() -> None:
    source = Path(demo_reset.__file__).read_text(encoding="utf-8")
    assert "db.delete(row)" in source
    assert "DELETE FROM" not in source
    assert "TRUNCATE" not in source
    assert "DROP TABLE" not in source
    assert "shell=True" not in source


def test_demo_reset_defaults_to_dry_run() -> None:
    args = demo_reset.parse_args(["--json"])

    assert args.dry_run is True
    assert args.apply is False


def test_demo_reset_database_operation_reports_verified_final_status(
    monkeypatch,
) -> None:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    with session_factory() as db:
        demo_seed.apply_seed(db, models)
        db.commit()

    monkeypatch.setattr(
        demo_seed,
        "load_database",
        lambda: (engine, session_factory, (inspect, models)),
    )

    report, exit_code = demo_reset.database_operation("apply")

    assert exit_code == 0
    assert report["result"] == "DEMO_RESET_APPLIED"
    assert report["deleted_counts"]["incidents"] == 5
    assert report["final_status"]["seed_result"] == "NOT_SEEDED"
    with session_factory() as db:
        assert db.query(models.Incident).count() == 0
        assert db.query(models.IncidentCase).count() == 0
