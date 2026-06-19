from pathlib import Path

import scripts.demo_lifecycle as demo_lifecycle


def make_repository(tmp_path: Path, *services: str) -> Path:
    systemd_directory = tmp_path / "systemd"
    systemd_directory.mkdir()
    for service in services:
        (systemd_directory / f"{service}.service").write_text(
            "[Unit]\n",
            encoding="utf-8",
        )
    return tmp_path


class FakeSystemctl:
    def __init__(
        self,
        states: dict[str, tuple[str, str, str, str]],
        *,
        action_failure: demo_lifecycle.CommandOutput | None = None,
    ) -> None:
        self.states = states
        self.action_failure = action_failure
        self.commands: list[list[str]] = []

    def __call__(self, arguments):
        command = list(arguments)
        self.commands.append(command)
        if command[1] == "show":
            service = command[2].removesuffix(".service")
            load, active, sub, unit_file = self.states.get(
                service,
                ("not-found", "inactive", "dead", "unknown"),
            )
            return demo_lifecycle.CommandOutput(
                returncode=0,
                stdout=(
                    f"LoadState={load}\n"
                    f"ActiveState={active}\n"
                    f"SubState={sub}\n"
                    f"UnitFileState={unit_file}\n"
                ),
            )
        if self.action_failure:
            return self.action_failure
        return demo_lifecycle.CommandOutput(returncode=0)


def active_states():
    return {
        "ai-soc-api": ("loaded", "active", "running", "enabled"),
        "ai-soc-frontend": ("loaded", "active", "running", "enabled"),
    }


def make_lifecycle(tmp_path, runner, *, include_worker=False):
    repository = make_repository(
        tmp_path,
        "ai-soc-api",
        "ai-soc-frontend",
    )
    return demo_lifecycle.DemoLifecycle(
        include_worker=include_worker,
        repository_root=repository,
        systemctl_path="/usr/bin/systemctl",
        runner=runner,
    )


def test_status_reports_ready_when_required_services_are_active(tmp_path):
    runner = FakeSystemctl(active_states())

    report, exit_code = make_lifecycle(tmp_path, runner).status_report()

    assert exit_code == 0
    assert report["result"] == "DEMO_RUNTIME_READY"
    assert [service["name"] for service in report["services"]] == [
        "ai-soc-api",
        "ai-soc-frontend",
    ]
    assert report["planned_commands"] == []
    assert report["executed_commands"] == []


def test_status_warns_but_succeeds_when_service_is_inactive(tmp_path):
    states = active_states()
    states["ai-soc-frontend"] = (
        "loaded",
        "inactive",
        "dead",
        "disabled",
    )

    report, exit_code = make_lifecycle(
        tmp_path,
        FakeSystemctl(states),
    ).status_report()

    assert exit_code == 0
    assert report["result"] == "DEMO_RUNTIME_READY_WITH_WARNINGS"


def test_up_defaults_to_dry_run_without_executing_actions(tmp_path):
    runner = FakeSystemctl(active_states())

    report, exit_code = make_lifecycle(tmp_path, runner).action_report(
        "up",
        apply=False,
    )

    assert exit_code == 0
    assert report["result"] == "DRY_RUN_ONLY"
    assert report["planned_commands"] == [
        "systemctl start ai-soc-api",
        "systemctl start ai-soc-frontend",
    ]
    assert report["executed_commands"] == []
    assert all(command[1] == "show" for command in runner.commands)


def test_down_and_restart_use_safe_service_order(tmp_path):
    lifecycle = make_lifecycle(tmp_path, FakeSystemctl(active_states()))

    down, _ = lifecycle.action_report("down", apply=False)
    restart, _ = lifecycle.action_report("restart", apply=False)

    assert down["planned_commands"] == [
        "systemctl stop ai-soc-frontend",
        "systemctl stop ai-soc-api",
    ]
    assert restart["planned_commands"] == [
        "systemctl restart ai-soc-api",
        "systemctl restart ai-soc-frontend",
    ]


def test_worker_is_only_included_when_requested(tmp_path):
    states = active_states()
    states["ai-soc-worker"] = ("loaded", "active", "running", "enabled")
    lifecycle = make_lifecycle(
        tmp_path,
        FakeSystemctl(states),
        include_worker=True,
    )

    report, exit_code = lifecycle.action_report("up", apply=False)

    assert exit_code == 0
    assert report["planned_commands"] == [
        "systemctl start ai-soc-api",
        "systemctl start ai-soc-worker",
        "systemctl start ai-soc-frontend",
    ]


def test_status_fails_safely_when_systemd_cannot_be_inspected(tmp_path):
    lifecycle = make_lifecycle(
        tmp_path,
        lambda _arguments: demo_lifecycle.CommandOutput(
            returncode=1,
            stderr="Failed to connect to bus: Operation not permitted",
        ),
    )

    report, exit_code = lifecycle.status_report()

    assert exit_code == 1
    assert report["result"] == "DEMO_RUNTIME_NOT_READY"
    assert report["services"][0]["exists"] is None


def test_apply_fails_before_changes_when_required_unit_is_missing(tmp_path):
    states = active_states()
    states["ai-soc-frontend"] = (
        "not-found",
        "inactive",
        "dead",
        "unknown",
    )
    runner = FakeSystemctl(states)

    report, exit_code = make_lifecycle(tmp_path, runner).action_report(
        "up",
        apply=True,
    )

    assert exit_code == 1
    assert report["result"] == "ACTION_FAILED"
    assert report["executed_commands"] == []
    assert all(command[1] == "show" for command in runner.commands)


def test_permission_failure_returns_manual_sudo_guidance(tmp_path):
    runner = FakeSystemctl(
        active_states(),
        action_failure=demo_lifecycle.CommandOutput(
            returncode=1,
            stderr="Interactive authentication required.",
        ),
    )

    report, exit_code = make_lifecycle(tmp_path, runner).action_report(
        "up",
        apply=True,
    )

    assert exit_code == 1
    assert report["result"] == "ACTION_FAILED"
    assert report["permission_denied"] is True
    assert report["manual_commands"] == [
        "sudo systemctl start ai-soc-api",
        "sudo systemctl start ai-soc-frontend",
    ]
