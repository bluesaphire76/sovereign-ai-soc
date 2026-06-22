from __future__ import annotations

import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import api
import models
from models import Base, Incident, IncidentCase
from scripts import demo_seed


def database_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)


def test_incident_demo_filter_returns_seed_and_gui_synthetic_records(
    monkeypatch,
) -> None:
    factory = database_factory()
    with factory() as db:
        demo_seed.apply_seed(db, models)
        db.add(
            Incident(
                wazuh_doc_id="synthetic-old-test",
                timestamp="2026-05-01T00:00:00+00:00",
                rule="Legacy synthetic test",
                raw_alert=json.dumps(
                    {
                        "synthetic": True,
                        "source": "sovereign-ai-soc-synthetic",
                        "data": {"test_type": "gui_synthetic_test"},
                    }
                ),
            )
        )
        db.add(
            Incident(
                wazuh_doc_id="synthetic-marker-collision",
                timestamp="2026-05-02T00:00:00+00:00",
                rule="Not a supported synthetic test",
                raw_alert=json.dumps(
                    {
                        "synthetic": False,
                        "source": "external-system",
                    }
                ),
            )
        )
        db.commit()

    monkeypatch.setattr(api, "SessionLocal", factory)
    response = api.list_incidents(
        page=1,
        limit=20,
        status=None,
        risk=None,
        host=None,
        search=None,
        priority=None,
        correlation_type=None,
        correlated=None,
        mitre=None,
        date_from=None,
        date_to=None,
        demo_only=True,
    )

    assert response["total"] == 6
    assert {item["demo_origin"] for item in response["items"]} == {
        "seed",
        "synthetic_test",
    }
    assert all(item["is_demo"] is True for item in response["items"])


def test_case_demo_filter_excludes_operational_cases(monkeypatch) -> None:
    factory = database_factory()
    with factory() as db:
        demo_seed.apply_seed(db, models)
        db.add(
            IncidentCase(
                group_key="operational-case",
                title="Operational case",
                created_by="analyst",
            )
        )
        db.commit()

    monkeypatch.setattr(api, "SessionLocal", factory)
    response = api.list_cases(
        page=1,
        limit=20,
        status=None,
        severity=None,
        host=None,
        demo_only=True,
    )

    assert response["total"] == 1
    assert response["items"][0]["demo_origin"] == "seed"
    assert response["items"][0]["is_demo"] is True


def test_demo_delete_routes_require_operator_role() -> None:
    assert api.is_request_authorized(
        "DELETE",
        "/demo-management/incidents/12",
        {"role": "ANALYST"},
    )
    assert api.is_request_authorized(
        "DELETE",
        "/demo-management/cases/4",
        {"role": "ADMIN"},
    )
    assert not api.is_request_authorized(
        "DELETE",
        "/demo-management/incidents/12",
        {"role": "VIEWER"},
    )
