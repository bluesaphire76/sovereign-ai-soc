from __future__ import annotations

import json
from pathlib import Path

from scripts import demo_info


def ready_status():
    return (
        {
            "result": "PRESENT",
            "marker": "AI_SOC_DEMO_SEED:v1",
            "seed_result": "SEEDED",
            "counts": {
                "incidents": 5,
                "cases": 1,
                "case_links": 3,
                "case_actions": 1,
                "case_ai_analyses": 1,
            },
        },
        0,
    )


def test_demo_info_ready_payload_is_read_only() -> None:
    calls = []

    def provider():
        calls.append("status")
        return ready_status()

    report = demo_info.build_report(*provider())

    assert calls == ["status"]
    assert report["result"] == "DEMO_INFO_READY"
    assert report["marker"] == "AI_SOC_DEMO_SEED:v1"
    assert report["counts"]["incidents"] == 5


def test_demo_info_missing_seed_is_a_clean_warning() -> None:
    report = demo_info.build_report(
        {
            "result": "NOT_PRESENT",
            "marker": "AI_SOC_DEMO_SEED:v1",
            "seed_result": "NOT_SEEDED",
            "counts": {},
        },
        0,
    )

    assert report["result"] == "DEMO_INFO_READY_WITH_WARNINGS"
    assert report["exit_code"] == 0


def test_demo_info_unavailable_database_fails_gracefully(capsys) -> None:
    exit_code = demo_info.main(
        ["--json"],
        status_provider=lambda: (
            {"result": "UNAVAILABLE", "message": "database unavailable"},
            0,
        ),
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert payload["result"] == "DEMO_INFO_NOT_READY"
    assert payload["message"] == "database unavailable"


def test_demo_info_source_has_no_database_write_calls() -> None:
    source = Path(demo_info.__file__).read_text(encoding="utf-8")
    assert ".commit(" not in source
    assert ".delete(" not in source
    assert "shell=True" not in source
