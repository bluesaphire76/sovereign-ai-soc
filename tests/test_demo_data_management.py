from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import models
from demo_data_management import (
    DEMO_SCENARIO_IDS,
    DemoDependencyError,
    DemoOwnershipError,
    case_demo_origin,
    delete_demo_case,
    delete_demo_incident,
    incident_demo_origin,
)
from models import Base, Incident, IncidentAudit, IncidentCase, SecurityAlert
from scripts import demo_seed


def session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)


def test_demo_origin_separates_current_seed_from_legacy_synthetic_tests() -> None:
    seed_incident = Incident(
        wazuh_doc_id="AI_SOC_DEMO_SEED:v1:incident:demo_brute_force_ssh",
        raw_alert=json.dumps(
            {
                "synthetic": True,
                "demo": True,
                "source": "AI_SOC_DEMO_SEED",
                "seed_version": "v1",
            }
        ),
    )
    legacy_incident = Incident(
        wazuh_doc_id="synthetic-example-20260620",
        raw_alert=json.dumps(
            {
                "synthetic": True,
                "source": "sovereign-ai-soc-synthetic",
                "data": {"test_type": "gui_synthetic_test"},
            }
        ),
    )

    assert incident_demo_origin(seed_incident) == "seed"
    assert incident_demo_origin(legacy_incident) == "synthetic_test"


def test_central_demo_scenario_ids_match_seed_catalog() -> None:
    assert set(DEMO_SCENARIO_IDS) == {
        scenario.scenario_id for scenario in demo_seed.SCENARIOS
    }


def test_delete_demo_incident_removes_exclusive_children_and_preserves_real_data() -> None:
    factory = session_factory()
    with factory() as db:
        real_incident = Incident(
            wazuh_doc_id="real-incident",
            rule="Operational incident",
            raw_alert=json.dumps({"synthetic": False}),
        )
        db.add(real_incident)
        demo_seed.apply_seed(db, models)
        db.commit()

        demo_incident = (
            db.query(Incident)
            .filter(
                Incident.wazuh_doc_id
                == demo_seed.SCENARIOS[0].external_id
            )
            .one()
        )
        db.add(
            IncidentAudit(
                incident_id=demo_incident.id,
                event_type="REMEDIATION_PLAN_SNAPSHOT",
                comment="Workflow artifact attached only to synthetic data.",
                created_by="analyst",
            )
        )
        db.commit()

        result = delete_demo_incident(db, demo_incident.id)
        db.commit()

        assert result.demo_origin == "seed"
        assert result.deleted_counts["incident_audit"] == 2
        assert result.deleted_counts["incident_notes"] == 1
        assert db.query(Incident).filter(Incident.id == demo_incident.id).first() is None
        assert (
            db.query(Incident)
            .filter(Incident.wazuh_doc_id == "real-incident")
            .one()
            .rule
            == "Operational incident"
        )


def test_delete_demo_incident_blocks_external_security_alert_reference() -> None:
    factory = session_factory()
    with factory() as db:
        demo_seed.apply_seed(db, models)
        db.commit()
        incident = db.query(Incident).order_by(Incident.id.asc()).first()
        db.add(
            SecurityAlert(
                raw_event_id=999,
                source="wazuh",
                source_event_id="protected-reference",
                incident_id=incident.id,
            )
        )
        db.commit()

        with pytest.raises(
            DemoDependencyError,
            match="security_alert_reference",
        ):
            delete_demo_incident(db, incident.id)

        assert db.query(Incident).filter(Incident.id == incident.id).first()


def test_delete_demo_case_removes_case_workflow_but_preserves_incidents() -> None:
    factory = session_factory()
    with factory() as db:
        demo_seed.apply_seed(db, models)
        db.commit()
        case = db.query(IncidentCase).one()

        assert case_demo_origin(case) == "seed"
        result = delete_demo_case(db, case.id)
        db.commit()

        assert result.deleted_counts["cases"] == 1
        assert result.deleted_counts["case_links"] == 3
        assert db.query(IncidentCase).count() == 0
        assert db.query(Incident).count() == 5


def test_delete_demo_management_refuses_non_demo_records() -> None:
    factory = session_factory()
    with factory() as db:
        incident = Incident(
            wazuh_doc_id="real-incident",
            raw_alert=json.dumps({"synthetic": False}),
        )
        case = IncidentCase(
            group_key="real-case",
            title="Real case",
            created_by="analyst",
        )
        db.add_all([incident, case])
        db.commit()

        with pytest.raises(DemoOwnershipError):
            delete_demo_incident(db, incident.id)
        with pytest.raises(DemoOwnershipError):
            delete_demo_case(db, case.id)
