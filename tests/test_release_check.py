from __future__ import annotations

import json
from pathlib import Path

import scripts.release_check as release_check
from scripts.release_check import (
    Check,
    CommandResult,
    RESULT_NOT_READY,
    STATUS_OK,
    STATUS_WARN,
    build_report,
    collect_checks,
    parse_args,
    write_reports,
)


def _check(name: str, category: str, status: str) -> Check:
    return Check(name, category, status, None, 0, "summary", 0.0)


def _repository(*, clean: bool = True) -> dict[str, object]:
    return {
        "root": "/tmp/repository",
        "branch": "feature/release-check",
        "commit": "abc1234",
        "clean_worktree": clean,
        "status_short": "" if clean else " M README.md",
    }


def test_json_report_has_required_top_level_and_grouped_fields() -> None:
    report = build_report(
        args=parse_args(["--json", "--skip-runtime"]),
        repository=_repository(clean=False),
        checks=[
            _check("repo", "Repository", STATUS_WARN),
            _check("tests", "Python", STATUS_OK),
        ],
        report_paths=[],
    )

    json.loads(json.dumps(report))
    assert report["branch"] == "feature/release-check"
    assert report["commit"] == "abc1234"
    assert report["dirty"] is True
    assert report["skip_runtime"] is True
    assert set(report["checks_by_category"]) == {"Repository", "Python"}
    assert report["warnings"][0]["name"] == "repo"
    assert "report_paths" not in report


def test_default_mode_does_not_create_report_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    report_dir = tmp_path / "reports" / "validation"
    monkeypatch.setattr(release_check, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(release_check, "REPORT_DIR", report_dir)

    build_report(
        args=parse_args([]),
        repository=_repository(),
        checks=[_check("tests", "Python", STATUS_OK)],
        report_paths=[],
    )

    assert not report_dir.exists()


def test_strict_json_report_fails_on_dirty_tree_warning() -> None:
    report = build_report(
        args=parse_args(["--strict", "--json"]),
        repository=_repository(clean=False),
        checks=[_check("working tree", "Repository", STATUS_WARN)],
        report_paths=[],
    )

    assert report["result"] == RESULT_NOT_READY
    assert report["exit_code"] == 1


def test_write_report_creates_only_requested_ignored_style_artifacts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    report_dir = tmp_path / "reports" / "validation"
    monkeypatch.setattr(release_check, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(release_check, "REPORT_DIR", report_dir)

    report, checks = write_reports(
        args=parse_args(["--write-report"]),
        repository=_repository(),
        checks=[_check("tests", "Python", STATUS_OK)],
    )

    assert len(report["report_paths"]) == 2
    assert all((tmp_path / path).is_file() for path in report["report_paths"])
    assert checks[-1].name == "Release readiness report"
    json_path = next(path for path in report["report_paths"] if path.endswith(".json"))
    assert json.loads((tmp_path / json_path).read_text(encoding="utf-8"))["result"]


def test_collect_checks_uses_only_read_only_or_dry_run_commands() -> None:
    observed: list[list[str]] = []

    def runner(args, *, cwd, timeout, env):
        observed.append([str(arg) for arg in args])
        command = " ".join(str(arg) for arg in args)
        if args[:2] == ["git", "rev-parse"] and "--show-toplevel" in args:
            return CommandResult(0, "/tmp/repository\n", "", 0.01)
        if args[:2] == ["git", "branch"]:
            return CommandResult(0, "feature/release-check\n", "", 0.01)
        if args[:2] == ["git", "rev-parse"]:
            return CommandResult(0, "abc1234\n", "", 0.01)
        if args[:2] == ["git", "status"]:
            return CommandResult(0, "", "", 0.01)
        if args[:3] == ["git", "ls-files", "-z"]:
            return CommandResult(0, "api.py\0", "", 0.01)
        if "-m pip --version" in command or "-m pip check" in command:
            return CommandResult(0, "ok\n", "", 0.01)

        results = {
            "doctor": "READY",
            "validate_cli_smoke.py": "CLI_SMOKE_READY",
            "package-validate": "DOCKER_PACKAGING_READY",
            "demo-info": "DEMO_INFO_READY",
            "demo-seed": "PRESENT",
            "demo-validate": "DEMO_READY",
            "demo-status": "DEMO_RUNTIME_READY",
            "demo-reset": "DEMO_RESET_DRY_RUN_READY",
            "validate-runtime": "READY",
        }
        for marker, result in results.items():
            if marker in command:
                return CommandResult(0, json.dumps({"result": result}), "", 0.01)
        return CommandResult(0, "ok\n", "", 0.01)

    args = parse_args(
        [
            "--skip-runtime",
            "--skip-frontend-build",
            "--skip-pytest",
            "--skip-docker-build",
        ]
    )
    _, checks = collect_checks(args, runner=runner)
    commands = [" ".join(command) for command in observed]
    categories = {check.category for check in checks}

    assert checks
    assert {
        "Repository",
        "Core CLI",
        "Installability",
        "Packaging",
        "Demo mode",
        "Runtime",
        "Python",
        "Frontend",
        "Compose",
        "Documentation",
    } <= categories
    assert any("install --profile demo --dry-run" in command for command in commands)
    assert any("demo-reset --dry-run --json" in command for command in commands)
    assert not any("demo-status" in command for command in commands)
    assert not any("demo-seed --apply" in command for command in commands)
    assert not any("demo-reset --apply" in command for command in commands)
    assert not any("docker compose up" in command for command in commands)
    assert not any("docker compose down" in command for command in commands)
    assert not any("ollama pull" in command for command in commands)
    assert not any("package-validate --build" in command for command in commands)
    assert not any("systemctl start" in command for command in commands)
    assert not any("systemctl stop" in command for command in commands)
    assert not any("systemctl restart" in command for command in commands)


def test_command_runner_never_enables_shell_execution() -> None:
    source = Path(release_check.__file__).read_text(encoding="utf-8")

    assert "shell=True" not in source


def test_report_redacts_secret_like_repository_status() -> None:
    repository = _repository(clean=False)
    repository["status_short"] = "password=do-not-report"

    report = build_report(
        args=parse_args([]),
        repository=repository,
        checks=[_check("tests", "Python", STATUS_OK)],
        report_paths=[],
    )

    assert "do-not-report" not in json.dumps(report)
