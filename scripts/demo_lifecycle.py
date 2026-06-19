#!/usr/bin/env python3
"""Safely inspect and control the local Sovereign AI SOC application layer."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT_SECONDS = 3.0
APPLICATION_SERVICES = ("ai-soc-api", "ai-soc-frontend")
WORKER_SERVICE = "ai-soc-worker"


@dataclass(frozen=True)
class CommandOutput:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


@dataclass(frozen=True)
class ServiceStatus:
    name: str
    exists: bool | None
    active_state: str
    sub_state: str
    unit_file_state: str
    repository_definition: bool
    inspection_error: str | None = None


CommandRunner = Callable[[Sequence[str]], CommandOutput]


def run_command(arguments: Sequence[str]) -> CommandOutput:
    try:
        completed = subprocess.run(
            list(arguments),
            capture_output=True,
            check=False,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandOutput(
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
        )
    except OSError as exc:
        return CommandOutput(returncode=127, stderr=str(exc))

    return CommandOutput(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def parse_systemctl_properties(output: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key.strip()] = value.strip()
    return properties


def concise_error(output: CommandOutput) -> str:
    if output.timed_out:
        return "systemctl inspection timed out"
    detail = (output.stderr or output.stdout).strip()
    if not detail:
        return f"systemctl exited with status {output.returncode}"
    return " ".join(detail.split())[:240]


def permission_denied(output: CommandOutput) -> bool:
    detail = f"{output.stdout}\n{output.stderr}".lower()
    markers = (
        "access denied",
        "authentication is required",
        "interactive authentication required",
        "permission denied",
        "not authorized",
    )
    return any(marker in detail for marker in markers)


class DemoLifecycle:
    def __init__(
        self,
        *,
        include_worker: bool = False,
        repository_root: Path = REPOSITORY_ROOT,
        systemctl_path: str | None = None,
        runner: CommandRunner = run_command,
    ) -> None:
        self.include_worker = include_worker
        self.repository_root = repository_root
        self.systemctl_path = (
            shutil.which("systemctl")
            if systemctl_path is None
            else systemctl_path
        )
        self.runner = runner

    @property
    def services(self) -> tuple[str, ...]:
        if self.include_worker:
            return (*APPLICATION_SERVICES, WORKER_SERVICE)
        return APPLICATION_SERVICES

    def inspect_service(self, name: str) -> ServiceStatus:
        repository_definition = (
            self.repository_root / "systemd" / f"{name}.service"
        ).is_file()
        if not self.systemctl_path:
            return ServiceStatus(
                name=name,
                exists=None,
                active_state="unknown",
                sub_state="unknown",
                unit_file_state="unknown",
                repository_definition=repository_definition,
                inspection_error="systemctl was not found",
            )

        output = self.runner(
            (
                self.systemctl_path,
                "show",
                f"{name}.service",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=UnitFileState",
            )
        )
        properties = parse_systemctl_properties(output.stdout)
        load_state = properties.get("LoadState", "").lower()

        if load_state == "loaded":
            exists: bool | None = True
        elif load_state == "not-found" or "not found" in (
            f"{output.stdout}\n{output.stderr}".lower()
        ):
            exists = False
        else:
            exists = None

        inspection_error = None
        if exists is None and output.returncode != 0:
            inspection_error = concise_error(output)
        elif exists is None and not properties:
            inspection_error = "systemctl returned no service state"

        return ServiceStatus(
            name=name,
            exists=exists,
            active_state=properties.get("ActiveState") or "unknown",
            sub_state=properties.get("SubState") or "unknown",
            unit_file_state=properties.get("UnitFileState") or "unknown",
            repository_definition=repository_definition,
            inspection_error=inspection_error,
        )

    def inspect_services(self) -> list[ServiceStatus]:
        return [self.inspect_service(name) for name in self.services]

    def planned_commands(self, action: str) -> list[list[str]]:
        if self.include_worker:
            startup_order = [
                "ai-soc-api",
                "ai-soc-worker",
                "ai-soc-frontend",
            ]
        else:
            startup_order = list(APPLICATION_SERVICES)
        ordered_services = (
            list(reversed(startup_order))
            if action == "down"
            else startup_order
        )
        verb = {"up": "start", "down": "stop", "restart": "restart"}[action]
        return [["systemctl", verb, name] for name in ordered_services]

    def status_report(self) -> tuple[dict[str, object], int]:
        services = self.inspect_services()
        required_services = [
            service
            for service in services
            if service.name in APPLICATION_SERVICES
        ]

        inspection_failed = any(
            service.exists is None for service in required_services
        )
        if inspection_failed or any(
            service.exists is False for service in required_services
        ):
            result = "DEMO_RUNTIME_NOT_READY"
        elif all(
            service.exists is True and service.active_state == "active"
            for service in required_services
        ):
            result = "DEMO_RUNTIME_READY"
        else:
            result = "DEMO_RUNTIME_READY_WITH_WARNINGS"

        exit_code = 1 if inspection_failed else 0
        report: dict[str, object] = {
            "action": "status",
            "applied": False,
            "dry_run": False,
            "result": result,
            "exit_code": exit_code,
            "systemctl_available": self.systemctl_path is not None,
            "services": [asdict(service) for service in services],
            "planned_commands": [],
            "executed_commands": [],
        }
        return report, exit_code

    def action_report(
        self,
        action: str,
        *,
        apply: bool,
    ) -> tuple[dict[str, object], int]:
        services = self.inspect_services()
        planned = self.planned_commands(action)
        planned_text = [" ".join(command) for command in planned]
        report: dict[str, object] = {
            "action": action,
            "applied": apply,
            "dry_run": not apply,
            "result": "DRY_RUN_ONLY",
            "exit_code": 0,
            "systemctl_available": self.systemctl_path is not None,
            "services": [asdict(service) for service in services],
            "planned_commands": planned_text,
            "executed_commands": [],
        }

        if not apply:
            if not self.systemctl_path:
                report["result"] = "ACTION_FAILED"
                report["exit_code"] = 1
                report["error"] = (
                    "systemctl was not found; install systemd units before "
                    "using demo lifecycle commands"
                )
                return report, 1
            return report, 0

        missing_or_unknown = [
            service.name for service in services if service.exists is not True
        ]
        if missing_or_unknown:
            report["result"] = "ACTION_FAILED"
            report["exit_code"] = 1
            report["error"] = (
                "Cannot safely apply action because these units are missing "
                f"or could not be inspected: {', '.join(missing_or_unknown)}"
            )
            return report, 1

        executed: list[str] = []
        for display_command in planned:
            command = [self.systemctl_path, *display_command[1:]]
            output = self.runner(command)
            executed.append(" ".join(display_command))
            report["executed_commands"] = executed
            if output.returncode == 0:
                continue

            report["result"] = "ACTION_FAILED"
            report["exit_code"] = 1
            report["error"] = concise_error(output)
            if permission_denied(output):
                report["permission_denied"] = True
                report["manual_commands"] = [
                    f"sudo {planned_command}"
                    for planned_command in planned_text
                ]
            return report, 1

        report["result"] = (
            "DEMO_RUNTIME_READY_WITH_WARNINGS"
            if action == "down"
            else "DEMO_RUNTIME_READY"
        )
        return report, 0


def render_service(service: dict[str, object]) -> str:
    exists = service["exists"]
    if exists is True:
        existence = "installed"
    elif exists is False:
        existence = "missing"
    else:
        existence = "unknown"

    return (
        f"{service['name']}: unit={existence}, "
        f"active={service['active_state']}, "
        f"sub={service['sub_state']}, "
        f"enabled={service['unit_file_state']}"
    )


def print_human_report(report: dict[str, object]) -> None:
    print("Sovereign AI SOC Demo Lifecycle")
    print(f"[INFO] Action: {report['action']}")

    for service in report["services"]:
        assert isinstance(service, dict)
        if service["exists"] is True and service["active_state"] == "active":
            label = "OK"
        else:
            label = "WARN"
        print(f"[{label}] {render_service(service)}")
        if service.get("inspection_error"):
            print(f"[WARN]   {service['inspection_error']}")
        if (
            service["exists"] is not True
            and service.get("repository_definition")
        ):
            print(
                "[INFO]   A repository unit definition exists under systemd/."
            )

    planned_commands = report.get("planned_commands", [])
    if report["dry_run"]:
        print("[DRY-RUN] No service changes were made.")
        for command in planned_commands:
            print(f"[DRY-RUN] {command}")

    if report.get("error"):
        print(f"[FAIL] {report['error']}")
    if report.get("permission_denied"):
        print("[FAIL] Permission denied. Run manually:")
        for command in report.get("manual_commands", []):
            print(command)

    print(f"Result: {report['result']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect or control only the local Sovereign AI SOC application "
            "systemd services."
        )
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    status_parser = subparsers.add_parser(
        "status",
        help="Inspect application service state without making changes.",
    )
    status_parser.add_argument("--json", action="store_true")
    status_parser.add_argument("--include-worker", action="store_true")

    for action in ("up", "down", "restart"):
        action_parser = subparsers.add_parser(
            action,
            help=f"{action.title()} application services (dry-run by default).",
        )
        mode = action_parser.add_mutually_exclusive_group()
        mode.add_argument("--dry-run", action="store_true")
        mode.add_argument("--apply", action="store_true")
        action_parser.add_argument("--json", action="store_true")
        action_parser.add_argument("--include-worker", action="store_true")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    lifecycle = DemoLifecycle(include_worker=args.include_worker)

    if args.action == "status":
        report, exit_code = lifecycle.status_report()
    else:
        report, exit_code = lifecycle.action_report(
            args.action,
            apply=args.apply,
        )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human_report(report)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
