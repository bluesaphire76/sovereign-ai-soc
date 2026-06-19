import json
from pathlib import Path

import scripts.validate_demo as validate_demo


def make_repository(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir()
    (tmp_path / "reports" / "validation").mkdir(parents=True)
    for relative_path in (
        "README.md",
        "ai-soc",
        "scripts/demo_seed.py",
        "scripts/validate_runtime.py",
        "report_builder.py",
        "enterprise_report_templates.py",
        "evidence_pack_builder.py",
    ):
        (tmp_path / relative_path).write_text("test\n", encoding="utf-8")
    return tmp_path


def ready_seed_payload() -> dict:
    return {
        "result": "PRESENT",
        "seed_result": "SEEDED",
        "demo_marker": "AI_SOC_DEMO_SEED",
        "synthetic": True,
        "idempotent": True,
        "counts": {
            "incidents": 5,
            "cases": 1,
            "case_links": 3,
            "case_actions": 1,
            "case_ai_analyses": 1,
        },
        "status": {
            "expected_incident_count": 5,
            "unsafe_collisions": [],
        },
    }


def runner_for(
    *,
    runtime_result: str = "READY",
    seed_payload: dict | None = None,
):
    def runner(script: Path, _arguments: list[str]):
        if script.name == "validate_runtime.py":
            return {"result": runtime_result}, None
        return seed_payload or ready_seed_payload(), None

    return runner


def test_ready_demo_has_only_default_report_warning(tmp_path):
    validator = validate_demo.DemoValidator(
        strict=False,
        no_runtime=False,
        write_report=False,
        repository_root=make_repository(tmp_path),
        command_runner=runner_for(),
    )

    report, exit_code = validator.report()

    assert exit_code == 0
    assert report["result"] == "DEMO_READY_WITH_WARNINGS"
    assert report["summary"]["warn"] == 1
    assert report["runtime_result"] == "READY"
    assert report["demo_counts"]["incidents"] == 5


def test_strict_mode_fails_when_demo_data_is_missing(tmp_path):
    seed_payload = ready_seed_payload()
    seed_payload["seed_result"] = "NOT_SEEDED"
    seed_payload["counts"]["incidents"] = 0
    seed_payload["counts"]["cases"] = 0

    validator = validate_demo.DemoValidator(
        strict=True,
        no_runtime=False,
        write_report=False,
        repository_root=make_repository(tmp_path),
        command_runner=runner_for(seed_payload=seed_payload),
    )

    report, exit_code = validator.report()

    assert exit_code == 1
    assert report["result"] == "DEMO_NOT_READY"


def test_no_runtime_skips_runtime_subprocess(tmp_path):
    calls = []

    def runner(script: Path, _arguments: list[str]):
        calls.append(script.name)
        return ready_seed_payload(), None

    validator = validate_demo.DemoValidator(
        strict=False,
        no_runtime=True,
        write_report=False,
        repository_root=make_repository(tmp_path),
        command_runner=runner,
    )

    report, exit_code = validator.report()

    assert exit_code == 0
    assert "validate_runtime.py" not in calls
    assert report["runtime_skipped"] is True


def test_write_report_creates_only_requested_json_artifact(tmp_path):
    repository = make_repository(tmp_path)
    validator = validate_demo.DemoValidator(
        strict=False,
        no_runtime=False,
        write_report=True,
        repository_root=repository,
        command_runner=runner_for(),
    )

    report, exit_code = validator.report()

    assert exit_code == 0
    assert report["result"] == "DEMO_READY"
    report_path = Path(report["report_path"])
    assert report_path.parent == repository / "reports" / "validation"
    assert json.loads(report_path.read_text(encoding="utf-8"))["result"] == (
        "DEMO_READY"
    )


def test_invalid_demo_status_is_a_required_failure(tmp_path):
    def runner(script: Path, _arguments: list[str]):
        if script.name == "validate_runtime.py":
            return {"result": "READY"}, None
        return None, "invalid demo status"

    validator = validate_demo.DemoValidator(
        strict=False,
        no_runtime=False,
        write_report=False,
        repository_root=make_repository(tmp_path),
        command_runner=runner,
    )

    report, exit_code = validator.report()

    assert exit_code == 1
    assert report["result"] == "DEMO_NOT_READY"
