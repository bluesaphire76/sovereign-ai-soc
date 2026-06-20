from __future__ import annotations

import json
from pathlib import Path

from scripts.install_local import (
    CommandResult,
    Installer,
    RESULT_DRY_RUN_READY,
    RESULT_INSTALL_NOT_READY,
    main,
    parse_args,
)


def create_repository(root: Path) -> None:
    for relative in (
        "ai-soc",
        "requirements.txt",
        "frontend/package.json",
        "frontend/package-lock.json",
        "scripts/doctor.py",
        "scripts/init_env.py",
        "scripts/validate_cli_smoke.py",
        "INSTALL.md",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n" if path.suffix == ".json" else "\n", encoding="utf-8")
    (root / ".git").mkdir()


def available_tool(name: str) -> str:
    return f"/usr/bin/{name}"


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], Path, int]] = []

    def __call__(self, args, *, cwd, timeout):
        self.calls.append((list(args), cwd, timeout))
        return CommandResult(0, "ok\n", "", 0.01)


def test_dry_run_does_not_create_venv_or_env_or_install_dependencies(tmp_path) -> None:
    create_repository(tmp_path)
    runner = RecordingRunner()
    args = parse_args(["--profile", "demo", "--dry-run"])

    payload = Installer(
        args,
        repository_root=tmp_path,
        runner=runner,
        which=available_tool,
    ).run()

    commands = [call[0] for call in runner.calls]
    assert payload["result"] == RESULT_DRY_RUN_READY
    assert not (tmp_path / ".venv").exists()
    assert not (tmp_path / ".env").exists()
    assert not any(command[1:4] == ["-m", "pip", "install"] for command in commands)
    assert not any(command[-2:] == ["npm", "ci"] for command in commands)
    assert not any(command[-1:] == ["ci"] for command in commands)


def test_dry_run_plan_contains_expected_steps(tmp_path) -> None:
    create_repository(tmp_path)
    payload = Installer(
        parse_args(["--profile", "local"]),
        repository_root=tmp_path,
        runner=RecordingRunner(),
        which=available_tool,
    ).run()

    plan = "\n".join(payload["planned_actions"])
    assert "Create .venv" in plan
    assert "npm ci" in plan
    assert "./ai-soc init --profile local --dry-run" in plan
    assert "./ai-soc package-validate" in plan


def test_missing_prerequisite_is_reported_cleanly(tmp_path) -> None:
    create_repository(tmp_path)

    def missing_docker(name: str) -> str | None:
        return None if name == "docker" else available_tool(name)

    payload = Installer(
        parse_args(["--profile", "demo", "--dry-run"]),
        repository_root=tmp_path,
        runner=RecordingRunner(),
        which=missing_docker,
    ).run()

    assert payload["result"] == RESULT_INSTALL_NOT_READY
    docker_checks = [check for check in payload["checks"] if check["name"] == "Docker"]
    assert docker_checks[0]["status"] == "FAIL"
    assert "missing" in docker_checks[0]["summary"]


def test_skip_flags_remove_install_actions(tmp_path) -> None:
    create_repository(tmp_path)
    runner = RecordingRunner()
    payload = Installer(
        parse_args(
            [
                "--profile",
                "demo",
                "--dry-run",
                "--skip-frontend",
                "--skip-python-install",
                "--skip-env-init",
                "--skip-validation",
            ]
        ),
        repository_root=tmp_path,
        runner=runner,
        which=available_tool,
    ).run()

    commands = [item for call in runner.calls for item in call[0]]
    assert "ci" not in commands
    assert "pip" not in commands
    assert "init" not in commands
    assert "package-validate" not in commands
    assert payload["result"] == RESULT_DRY_RUN_READY


def test_json_output_is_valid(tmp_path, capsys) -> None:
    create_repository(tmp_path)

    exit_code = main(
        ["--profile", "demo", "--dry-run", "--json"],
        repository_root=tmp_path,
        runner=RecordingRunner(),
        which=available_tool,
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["profile"] == "demo"
    assert payload["dry_run"] is True
    assert isinstance(payload["checks"], list)
    assert isinstance(payload["planned_actions"], list)


def test_wrapper_help_declares_install_command() -> None:
    wrapper = Path(__file__).resolve().parents[1] / "ai-soc"
    assert "install --profile <demo|local>" in wrapper.read_text(encoding="utf-8")


def test_installer_does_not_use_shell_true() -> None:
    source = (
        Path(__file__).resolve().parents[1] / "scripts" / "install_local.py"
    ).read_text(encoding="utf-8")
    assert "shell=True" not in source
