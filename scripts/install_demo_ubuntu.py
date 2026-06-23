#!/usr/bin/env python3
"""Safe guided installer for an Ubuntu Sovereign AI SOC demo checkout."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
OS_RELEASE = Path("/etc/os-release")
SUPPORTED_TARGET = "Ubuntu 24.04 LTS or newer (Server or Desktop)"

STATUS_OK = "OK"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_INFO = "INFO"
STATUS_SKIP = "SKIP"

RESULT_READY = "UBUNTU_INSTALLER_READY"
RESULT_WARNINGS = "UBUNTU_INSTALLER_READY_WITH_WARNINGS"
RESULT_NOT_READY = "UBUNTU_INSTALLER_NOT_READY"
RESULT_APPLIED = "UBUNTU_INSTALLER_APPLIED"
RESULT_APPLIED_WARNINGS = "UBUNTU_INSTALLER_APPLIED_WITH_WARNINGS"
RESULT_REPAIR = "UBUNTU_INSTALLER_REPAIR_GUIDANCE"
RESULT_OBS_READY = "UBUNTU_OBSERVABILITY_READY"
RESULT_OBS_WARNINGS = "UBUNTU_OBSERVABILITY_READY_WITH_WARNINGS"
RESULT_OBS_NOT_READY = "UBUNTU_OBSERVABILITY_NOT_READY"
RESULT_OBS_PLAN = "UBUNTU_OBSERVABILITY_PLAN_READY"

SECRET_PATTERNS = (
    re.compile(r"\b(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bauthorization:\s*(?:bearer|basic)\s+\S{20,}"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)

MANUAL_PYTHON_COMMANDS = (
    "sudo apt update",
    "sudo apt install -y python3 python3-venv python3-pip",
)
MANUAL_DOCKER_COMMANDS = (
    "sudo apt update",
    "sudo apt install -y docker.io docker-compose-plugin",
    "sudo systemctl enable --now docker",
    'sudo usermod -aG docker "$USER"',
    "newgrp docker",
)
MANUAL_OBSERVABILITY_COMMANDS = (
    "docker compose -f deploy/observability/docker-compose.loki.yml config --quiet",
    "docker compose -f deploy/observability/docker-compose.yml config --quiet",
    "docker compose -f deploy/observability/docker-compose.yml up -d",
)
REPAIR_GUIDANCE = (
    "Docker daemon: verify the service and current-user access manually; a Docker "
    "group change may require logout and login.",
    "Python: install Python 3.12+, venv, and pip support manually if the capability "
    "checks fail.",
    "Node.js/npm: use Node.js 20+; if npm ci fails, review npm output and the lockfile "
    "without deleting project files.",
    "Ollama: the runtime and a manually selected model are optional for deterministic "
    "fallbacks but required for full local AI analysis.",
    "Observability: restore missing Grafana, Prometheus, Alertmanager, Loki, or Alloy "
    "configuration from the repository before retrying validation.",
    "ntfy bridge: create the intentionally untracked local .env only when configuring "
    "notifications, and never commit it.",
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    error: str | None = None


@dataclass(frozen=True)
class Check:
    category: str
    name: str
    status: str
    summary: str
    required: bool = False
    command: str | None = None
    returncode: int | None = None
    duration_seconds: float = 0.0


Runner = Callable[..., CommandResult]
Which = Callable[[str], str | None]
HttpProbe = Callable[[str, float], tuple[bool, str]]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Check or prepare a Sovereign AI SOC demo on Ubuntu 24.04+ "
            "without privileged or runtime-changing actions."
        ),
    )
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_const", const="check", dest="mode")
    modes.add_argument("--apply", action="store_const", const="apply", dest="mode")
    modes.add_argument("--repair", action="store_const", const="repair", dest="mode")
    modes.add_argument(
        "--check-observability",
        action="store_const",
        const="check-observability",
        dest="mode",
    )
    modes.add_argument(
        "--observability-plan",
        action="store_const",
        const="observability-plan",
        dest="mode",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; this is already the default behavior.",
    )
    args = parser.parse_args(argv)
    if args.mode is None:
        args.mode = "check"
    return args


def run_command(
    args: list[str],
    *,
    cwd: Path = REPO_ROOT,
    timeout: int = 60,
) -> CommandResult:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            None,
            _text(exc.stdout),
            _text(exc.stderr),
            round(time.monotonic() - started, 3),
            timed_out=True,
        )
    except OSError as exc:
        return CommandResult(
            None,
            duration_seconds=round(time.monotonic() - started, 3),
            error=f"{type(exc).__name__}: {exc}",
        )
    return CommandResult(
        completed.returncode,
        completed.stdout,
        completed.stderr,
        round(time.monotonic() - started, 3),
    )


def http_probe(url: str, timeout: float) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status < 500, f"HTTP {response.status}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, exc.__class__.__name__


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def contains_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in SECRET_PATTERNS)


def concise_output(value: str, limit: int = 180) -> str:
    lines = [" ".join(line.split()) for line in value.splitlines() if line.strip()]
    if not lines:
        return "Command completed successfully."
    summary = lines[-1]
    return summary if len(summary) <= limit else f"{summary[: limit - 3]}..."


def version_tuple(value: str) -> tuple[int, ...]:
    match = re.search(r"(\d+(?:\.\d+)+)", value)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def load_os_release(path: Path = OS_RELEASE) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, raw = line.split("=", 1)
        values[key] = raw.strip().strip("\"'")
    return values


def command_display(args: list[str], root: Path = REPO_ROOT) -> str:
    rendered: list[str] = []
    for arg in args:
        try:
            rendered.append(str(Path(arg).relative_to(root)))
        except (TypeError, ValueError):
            rendered.append(arg)
    return shlex.join(rendered)


def compose_service_blocks(text: str) -> dict[str, str]:
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    in_services = False
    for line in text.splitlines():
        if line == "services:":
            in_services = True
            continue
        if in_services and line and not line.startswith(" "):
            break
        service = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if in_services and service:
            current = service.group(1)
            blocks[current] = []
            continue
        if current is not None:
            blocks[current].append(line)
    return {name: "\n".join(lines) for name, lines in blocks.items()}


def exposed_ports(block: str) -> list[str]:
    values: list[str] = []
    for host, container in re.findall(
        r"""["']?127\.0\.0\.1:(\d+):(\d+)["']?""",
        block,
    ):
        value = host if host == container else f"{host} -> {container}"
        if value not in values:
            values.append(value)
    for port in re.findall(r"(?:listen-address=127\.0\.0\.1:|localhost:)(\d+)", block):
        if port not in values:
            values.append(port)
    return values


def local_access_url(ports: list[str], path: str = "") -> str | None:
    if not ports:
        return None
    match = re.match(r"^(\d+)", ports[0])
    if not match:
        return None
    suffix = path if not path or path.startswith("/") else f"/{path}"
    return f"http://127.0.0.1:{match.group(1)}{suffix}"


class UbuntuDemoInstaller:
    def __init__(
        self,
        args: argparse.Namespace,
        *,
        repository_root: Path = REPO_ROOT,
        runner: Runner = run_command,
        which: Which = shutil.which,
        probe: HttpProbe = http_probe,
        os_release: dict[str, str] | None = None,
    ) -> None:
        self.args = args
        self.root = repository_root
        self.runner = runner
        self.which = which
        self.probe = probe
        self.os_release = os_release if os_release is not None else load_os_release()
        self.checks: list[Check] = []
        self.suggested_commands: list[str] = []
        self.next_steps: list[str] = []
        self.executed_commands: list[str] = []

    def add(
        self,
        category: str,
        name: str,
        status: str,
        summary: str,
        *,
        required: bool = False,
        command: str | None = None,
        returncode: int | None = None,
        duration_seconds: float = 0.0,
    ) -> None:
        self.checks.append(
            Check(
                category,
                name,
                status,
                summary,
                required,
                command,
                returncode,
                duration_seconds,
            )
        )

    def suggest(self, *commands: str) -> None:
        for command in commands:
            if command not in self.suggested_commands:
                self.suggested_commands.append(command)

    def execute(
        self,
        category: str,
        name: str,
        args: list[str],
        *,
        required: bool,
        timeout: int = 60,
        cwd: Path | None = None,
        failure_status: str | None = None,
    ) -> bool:
        display = command_display(args, self.root)
        self.executed_commands.append(display)
        result = self.runner(args, cwd=cwd or self.root, timeout=timeout)
        combined = f"{result.stdout}\n{result.stderr}"
        status_on_failure = failure_status or (STATUS_FAIL if required else STATUS_WARN)
        if contains_secret(combined):
            self.add(
                category,
                name,
                STATUS_FAIL,
                "[REDACTED secret-like output]",
                required=required,
                command=display,
                returncode=result.returncode,
                duration_seconds=result.duration_seconds,
            )
            return False
        if "Traceback (most recent call last):" in combined:
            summary = "Command emitted an unhandled traceback."
        elif result.timed_out:
            summary = f"Timed out after {timeout} seconds."
        elif result.error:
            summary = result.error
        elif result.returncode != 0:
            summary = f"Command exited with status {result.returncode}."
        else:
            self.add(
                category,
                name,
                STATUS_OK,
                concise_output(result.stdout or result.stderr),
                required=required,
                command=display,
                returncode=result.returncode,
                duration_seconds=result.duration_seconds,
            )
            return True
        self.add(
            category,
            name,
            status_on_failure,
            summary,
            required=required,
            command=display,
            returncode=result.returncode,
            duration_seconds=result.duration_seconds,
        )
        return False

    def check_os(self) -> None:
        os_id = self.os_release.get("ID", "unknown").lower()
        version = self.os_release.get("VERSION_ID", "unknown")
        pretty = self.os_release.get("PRETTY_NAME", "Unknown operating system")
        if os_id != "ubuntu":
            self.add(
                "Ubuntu",
                "Supported target",
                STATUS_WARN,
                (
                    f"{pretty} detected. This installer is tested for Ubuntu 24.04+; "
                    "continue with manual validation at your own risk."
                ),
            )
            return
        if version_tuple(version) < (24, 4):
            self.add(
                "Ubuntu",
                "Supported target",
                STATUS_WARN,
                (
                    f"Ubuntu {version} detected. Recommended target: "
                    "Ubuntu 24.04 LTS or newer."
                ),
            )
            return
        self.add(
            "Ubuntu",
            "Supported target",
            STATUS_OK,
            f"{pretty} is within the supported Ubuntu 24.04+ target.",
        )

    def check_repository(self) -> None:
        required_paths = (
            "ai-soc",
            "requirements.txt",
            "frontend/package.json",
            "deploy/demo/docker-compose.demo.yml",
            "scripts/install_local.py",
        )
        missing = [path for path in required_paths if not (self.root / path).is_file()]
        self.add(
            "Repository",
            "Repository structure",
            STATUS_FAIL if missing else STATUS_OK,
            (
                f"Missing required paths: {', '.join(missing)}."
                if missing
                else f"Repository root detected at {self.root}."
            ),
            required=True,
        )

    def check_required_tools(self) -> None:
        self._simple_tool("Git", "git", ["--version"], required=True)
        python = self._simple_tool("Python 3", "python3", ["--version"], required=True)
        if python:
            result = self.runner([python, "--version"], cwd=self.root, timeout=30)
            detected = version_tuple(f"{result.stdout} {result.stderr}")
            if detected < (3, 12):
                self.add(
                    "Prerequisites",
                    "Python version",
                    STATUS_FAIL,
                    f"Python 3.12+ is required; detected {detected or 'unknown'}.",
                    required=True,
                )
                self.suggest(*MANUAL_PYTHON_COMMANDS)
            else:
                self.add(
                    "Prerequisites",
                    "Python version",
                    STATUS_OK,
                    f"Python {'.'.join(map(str, detected))} satisfies the 3.12+ requirement.",
                    required=True,
                )
            venv_ok = self.execute(
                "Prerequisites",
                "Python venv capability",
                [python, "-m", "venv", "--help"],
                required=True,
                timeout=30,
            )
            system_pip_command = [python, "-m", "pip", "--version"]
            self.executed_commands.append(command_display(system_pip_command, self.root))
            system_pip = self.runner(
                system_pip_command,
                cwd=self.root,
                timeout=30,
            )
            if system_pip.returncode == 0:
                self.add(
                    "Prerequisites",
                    "Python pip capability",
                    STATUS_OK,
                    concise_output(system_pip.stdout or system_pip.stderr),
                    required=True,
                    command=command_display(system_pip_command, self.root),
                    returncode=system_pip.returncode,
                    duration_seconds=system_pip.duration_seconds,
                )
            else:
                venv_python = self.root / ".venv" / "bin" / "python"
                if venv_python.is_file() and self.execute(
                    "Prerequisites",
                    "Python pip capability",
                    [str(venv_python), "-m", "pip", "--version"],
                    required=True,
                    timeout=30,
                ):
                    self.add(
                        "Prerequisites",
                        "System pip guidance",
                        STATUS_INFO,
                        (
                            "System python3 does not expose pip, but the existing "
                            "repository virtual environment has a working pip."
                        ),
                    )
                else:
                    self.add(
                        "Prerequisites",
                        "Python pip capability",
                        STATUS_FAIL,
                        (
                            "pip is unavailable for both system Python and the "
                            "repository virtual environment."
                        ),
                        required=True,
                    )
                    self.suggest(*MANUAL_PYTHON_COMMANDS)
            if not venv_ok:
                self.suggest(*MANUAL_PYTHON_COMMANDS)

        node = self._simple_tool("Node.js", "node", ["--version"], required=True)
        if node:
            result = self.runner([node, "--version"], cwd=self.root, timeout=30)
            detected = version_tuple(f"{result.stdout} {result.stderr}")
            if detected < (20,):
                self.add(
                    "Prerequisites",
                    "Node.js version",
                    STATUS_FAIL,
                    (
                        f"Node.js 20+ is required for frontend build; "
                        f"detected {detected or 'unknown'}."
                    ),
                    required=True,
                )
                self.suggest(
                    "Install Node.js 20 LTS using your preferred Ubuntu-compatible method."
                )
            else:
                self.add(
                    "Prerequisites",
                    "Node.js version",
                    STATUS_OK,
                    f"Node.js {'.'.join(map(str, detected))} satisfies the 20+ requirement.",
                    required=True,
                )
        self._simple_tool("npm", "npm", ["--version"], required=True)

        docker = self._simple_tool("Docker", "docker", ["--version"], required=True)
        if docker:
            daemon_ok = self.execute(
                "Prerequisites",
                "Docker daemon access",
                [docker, "info"],
                required=True,
                timeout=30,
            )
            if not daemon_ok:
                self.add(
                    "Prerequisites",
                    "Docker daemon guidance",
                    STATUS_INFO,
                    (
                        "Docker is installed but the daemon is not reachable by the "
                        "current user. Review the manual service/group commands below; "
                        "logout and login may be required after a group change."
                    ),
                )
                self.suggest(*MANUAL_DOCKER_COMMANDS)
            compose_ok = self.execute(
                "Prerequisites",
                "Docker Compose plugin",
                [docker, "compose", "version"],
                required=True,
                timeout=30,
            )
            if not compose_ok:
                self.suggest(*MANUAL_DOCKER_COMMANDS[:2])

    def _simple_tool(
        self,
        label: str,
        executable_name: str,
        arguments: list[str],
        *,
        required: bool,
    ) -> str | None:
        executable = self.which(executable_name)
        if executable is None:
            self.add(
                "Prerequisites",
                label,
                STATUS_FAIL if required else STATUS_WARN,
                f"{executable_name} is not installed or not on PATH.",
                required=required,
            )
            if executable_name == "python3":
                self.suggest(*MANUAL_PYTHON_COMMANDS)
            elif executable_name == "docker":
                self.suggest(*MANUAL_DOCKER_COMMANDS)
            return None
        self.execute(
            "Prerequisites",
            label,
            [executable, *arguments],
            required=required,
            timeout=30,
        )
        return executable

    def check_optional_tools(self) -> None:
        for label, executable_name in (
            ("NVIDIA GPU tooling", "nvidia-smi"),
            ("systemd tooling", "systemctl"),
            ("curl", "curl"),
            ("Ubuntu firewall tooling", "ufw"),
        ):
            detected = self.which(executable_name) is not None
            self.add(
                "Optional",
                label,
                STATUS_OK if detected else STATUS_SKIP,
                (
                    f"{executable_name} is available."
                    if detected
                    else f"{executable_name} is optional and was not found."
                ),
            )

        ollama = self.which("ollama")
        reachable, detail = self.probe("http://127.0.0.1:11434/api/tags", 2.0)
        if ollama and reachable:
            self.add(
                "Optional",
                "Ollama local AI",
                STATUS_OK,
                f"Ollama CLI and API are available ({detail}).",
            )
        else:
            self.add(
                "Optional",
                "Ollama local AI",
                STATUS_WARN,
                (
                    "Ollama or its local API is unavailable. Deterministic fallback "
                    "paths remain usable, but full local AI requires a running runtime "
                    "and a manually selected model."
                ),
            )
            self.suggest("ollama pull <your-selected-model>")

    def check_core_demo(self) -> None:
        wrapper = str(self.root / "ai-soc")
        self.execute(
            "Demo",
            "Local readiness doctor",
            [wrapper, "doctor", "--json"],
            required=False,
            timeout=90,
            failure_status=STATUS_WARN,
        )
        self.execute(
            "Packaging",
            "Docker packaging validation",
            [wrapper, "package-validate", "--json"],
            required=True,
            timeout=180,
        )

    def observability(self, *, validate_configs: bool) -> dict[str, object]:
        obs_root = self.root / "deploy" / "observability"
        main_compose = obs_root / "docker-compose.yml"
        loki_compose = obs_root / "docker-compose.loki.yml"
        main_text = main_compose.read_text(encoding="utf-8") if main_compose.is_file() else ""
        loki_text = loki_compose.read_text(encoding="utf-8") if loki_compose.is_file() else ""
        main_services = compose_service_blocks(main_text)
        loki_services = compose_service_blocks(loki_text)

        definitions = {
            "grafana": {
                "label": "Grafana",
                "service": "grafana",
                "blocks": main_services,
                "paths": ("grafana", "grafana/dashboards", "grafana/provisioning"),
                "access_path": "/grafana/",
            },
            "prometheus": {
                "label": "Prometheus",
                "service": "prometheus",
                "blocks": main_services,
                "paths": ("prometheus/prometheus.yml", "prometheus/rules"),
            },
            "alertmanager": {
                "label": "Alertmanager",
                "service": "alertmanager",
                "blocks": main_services,
                "paths": ("alertmanager/alertmanager.yml",),
            },
            "cadvisor": {
                "label": "cAdvisor",
                "service": "cadvisor",
                "blocks": main_services,
                "paths": (),
            },
            "node_exporter": {
                "label": "node-exporter",
                "service": "node-exporter",
                "blocks": main_services,
                "paths": (),
            },
            "loki": {
                "label": "Loki",
                "service": "loki",
                "blocks": loki_services,
                "paths": ("loki", "loki/loki.local.yml"),
            },
            "alloy": {
                "label": "Grafana Alloy",
                "service": "alloy",
                "blocks": loki_services,
                "paths": ("alloy", "alloy/config.alloy"),
            },
            "ntfy_bridge": {
                "label": "ntfy bridge",
                "service": "ntfy-bridge",
                "blocks": main_services,
                "paths": ("ntfy-bridge", "ntfy-bridge/.env.example"),
            },
        }
        components: dict[str, dict[str, object]] = {}
        for key, spec in definitions.items():
            service = str(spec["service"])
            blocks = spec["blocks"]
            paths = [
                str((obs_root / relative).relative_to(self.root))
                for relative in spec["paths"]
                if (obs_root / relative).exists()
            ]
            detected = service in blocks and (
                bool(paths) or key in {"cadvisor", "node_exporter"}
            )
            ports = exposed_ports(blocks.get(service, ""))
            if key == "prometheus" and (obs_root / "prometheus/prometheus.yml").is_file():
                config = (obs_root / "prometheus/prometheus.yml").read_text(encoding="utf-8")
                if "127.0.0.1:9090" in config and "9090" not in ports:
                    ports.append("9090 (host network)")
            components[key] = {
                "name": spec["label"],
                "detected": detected,
                "config_files": paths,
                "ports": ports or ["not exposed by compose"],
            }
            access_url = local_access_url(
                ports,
                str(spec.get("access_path", "")),
            )
            if access_url:
                components[key]["access_url"] = access_url
            if key == "ntfy_bridge":
                components[key]["env_required"] = True
                components[key]["env_present"] = (
                    obs_root / "ntfy-bridge" / ".env"
                ).is_file()
            self.add(
                "Observability",
                str(spec["label"]),
                STATUS_OK if detected else STATUS_FAIL,
                (
                    f"{spec['label']} configuration detected."
                    if detected
                    else f"{spec['label']} configuration is missing."
                ),
                required=True,
            )

        config_validation: dict[str, dict[str, str]] = {}
        if validate_configs:
            docker = self.which("docker")
            if docker is None:
                for key, label in (
                    ("loki_compose", "Loki Compose configuration"),
                    ("full_observability_compose", "Full observability Compose configuration"),
                ):
                    config_validation[key] = {
                        "status": STATUS_FAIL,
                        "reason": "Docker CLI is unavailable.",
                    }
                    self.add(
                        "Observability",
                        label,
                        STATUS_FAIL,
                        "Docker CLI is unavailable.",
                        required=True,
                    )
            else:
                loki_ok = self.execute(
                    "Observability",
                    "Loki Compose configuration",
                    [docker, "compose", "-f", str(loki_compose), "config", "--quiet"],
                    required=True,
                    timeout=90,
                )
                config_validation["loki_compose"] = {
                    "status": STATUS_OK if loki_ok else STATUS_FAIL,
                }
                ntfy_env = obs_root / "ntfy-bridge" / ".env"
                if ntfy_env.is_file():
                    full_ok = self.execute(
                        "Observability",
                        "Full observability Compose configuration",
                        [docker, "compose", "-f", str(main_compose), "config", "--quiet"],
                        required=True,
                        timeout=90,
                    )
                    config_validation["full_observability_compose"] = {
                        "status": STATUS_OK if full_ok else STATUS_FAIL,
                    }
                else:
                    reason = (
                        "missing local env file deploy/observability/ntfy-bridge/.env; "
                        "notification secrets are intentionally untracked"
                    )
                    config_validation["full_observability_compose"] = {
                        "status": STATUS_WARN,
                        "reason": reason,
                    }
                    self.add(
                        "Observability",
                        "Full observability Compose configuration",
                        STATUS_WARN,
                        f"Validation skipped: {reason}.",
                    )
        else:
            config_validation = {
                "loki_compose": {
                    "status": STATUS_SKIP,
                    "reason": "Plan mode does not execute validation commands.",
                },
                "full_observability_compose": {
                    "status": STATUS_SKIP,
                    "reason": "Plan mode does not execute validation commands.",
                },
            }

        return {
            "available": obs_root.is_dir(),
            "components": components,
            "compose_files": [
                str(path.relative_to(self.root))
                for path in (main_compose, loki_compose)
                if path.is_file()
            ],
            "config_validation": config_validation,
            "warnings": [
                check.summary
                for check in self.checks
                if check.category == "Observability" and check.status == STATUS_WARN
            ],
            "logging_note": (
                "Grafana Alloy collects local container and journal logs and forwards "
                "them to Loki; Grafana can then query Loki during troubleshooting."
            ),
            "manual_next_steps": list(MANUAL_OBSERVABILITY_COMMANDS),
        }

    def run_apply(self) -> None:
        wrapper = str(self.root / "ai-soc")
        commands = (
            (
                "Prepare repository-local dependencies",
                [wrapper, "install", "--profile", "demo", "--apply"],
                2400,
            ),
            ("Validate Docker packaging", [wrapper, "package-validate"], 180),
            ("Inspect demo data", [wrapper, "demo-info"], 90),
            (
                "Validate demo without runtime",
                [wrapper, "demo-validate", "--no-runtime"],
                120,
            ),
            (
                "Run lightweight release check",
                [
                    wrapper,
                    "release-check",
                    "--skip-runtime",
                    "--skip-frontend-build",
                    "--skip-pytest",
                    "--skip-docker-build",
                ],
                600,
            ),
        )
        for name, command, timeout in commands:
            if not self.execute(
                "Apply",
                name,
                command,
                required=True,
                timeout=timeout,
            ):
                break

    def run_repair(self) -> None:
        wrapper = str(self.root / "ai-soc")
        commands = (
            ("Doctor", [wrapper, "doctor"], 90),
            ("Public validation", [wrapper, "validate"], 120),
            ("Packaging validation", [wrapper, "package-validate"], 180),
            (
                "Installer dry run",
                [wrapper, "install", "--profile", "demo", "--dry-run"],
                300,
            ),
        )
        for name, command, timeout in commands:
            self.execute(
                "Repair guidance",
                name,
                command,
                required=False,
                timeout=timeout,
                failure_status=STATUS_WARN,
            )

    def blocking_failures(self) -> list[Check]:
        return [
            check
            for check in self.checks
            if check.status == STATUS_FAIL and check.required
        ]

    def result_for_mode(self) -> tuple[str, int]:
        failures = self.blocking_failures()
        warnings = [check for check in self.checks if check.status == STATUS_WARN]
        if self.args.mode == "repair":
            return RESULT_REPAIR, 0
        if self.args.mode == "observability-plan":
            return RESULT_OBS_PLAN, 0
        if self.args.mode == "check-observability":
            if failures:
                return RESULT_OBS_NOT_READY, 1
            return (RESULT_OBS_WARNINGS if warnings else RESULT_OBS_READY), 0
        if failures:
            return RESULT_NOT_READY, 1
        if self.args.mode == "apply":
            return (RESULT_APPLIED_WARNINGS if warnings else RESULT_APPLIED), 0
        return (RESULT_WARNINGS if warnings else RESULT_READY), 0

    def run(self) -> dict[str, object]:
        mode = self.args.mode
        if mode in {"check", "apply", "repair"}:
            self.check_os()
            self.check_repository()
            self.check_required_tools()
            self.check_optional_tools()
            self.check_core_demo()

        validate_observability = mode != "observability-plan"
        observability = self.observability(validate_configs=validate_observability)

        if mode == "apply" and not self.blocking_failures():
            self.run_apply()
        elif mode == "repair":
            self.run_repair()

        self.next_steps = [
            "./ai-soc demo-info",
            "./ai-soc demo-seed --apply",
            "./ai-soc demo-validate",
            "./ai-soc release-check",
            "./install-demo.sh --observability-plan",
        ]
        self.suggest(*MANUAL_OBSERVABILITY_COMMANDS)
        result, exit_code = self.result_for_mode()
        return {
            "result": result,
            "exit_code": exit_code,
            "mode": mode,
            "supported_target": SUPPORTED_TARGET,
            "detected_os": self.os_release.get("PRETTY_NAME", "unknown"),
            "detected_os_id": self.os_release.get("ID", "unknown"),
            "ubuntu_version": self.os_release.get("VERSION_ID", "unknown"),
            "checks": [asdict(check) for check in self.checks],
            "warnings": [
                check.summary for check in self.checks if check.status == STATUS_WARN
            ],
            "failures": [
                check.summary for check in self.checks if check.status == STATUS_FAIL
            ],
            "suggested_commands": self.suggested_commands,
            "next_steps": self.next_steps,
            "repair_guidance": list(REPAIR_GUIDANCE),
            "observability": observability,
            "executed_commands": self.executed_commands,
        }


def render_human(payload: dict[str, object]) -> None:
    print("Sovereign AI SOC Ubuntu Guided Demo Installer")
    print(f"[INFO] Mode: {payload['mode']}")
    print(f"[INFO] Supported target: {payload['supported_target']}")
    print(
        "[INFO] Detected OS: "
        f"{payload['detected_os']} "
        f"(ID={payload['detected_os_id']}, VERSION_ID={payload['ubuntu_version']})"
    )
    if payload["mode"] == "observability-plan":
        print("[INFO] Plan mode is read-only; no validation or start command was executed.")

    current_category: str | None = None
    for check in payload["checks"]:
        category = str(check["category"])
        if category != current_category:
            current_category = category
            print(f"\n{category}")
        print(f"[{check['status']}] {check['name']}: {check['summary']}")

    observability = payload["observability"]
    print("\nObservability stack")
    for component in observability["components"].values():
        status = STATUS_OK if component["detected"] else STATUS_FAIL
        ports = ", ".join(component["ports"])
        print(f"[{status}] {component['name']}: ports {ports}")
    if payload["mode"] == "observability-plan":
        print("\nDetected Compose files")
        for compose_file in observability["compose_files"]:
            print(f"[INFO] {compose_file}")
        print("\nDetected configuration")
        for component in observability["components"].values():
            config_files = component["config_files"]
            summary = ", ".join(config_files) if config_files else "service defined in Compose"
            print(f"[INFO] {component['name']}: {summary}")
        ntfy = observability["components"]["ntfy_bridge"]
        ntfy_status = "present" if ntfy.get("env_present") else "missing"
        print(
            "[INFO] ntfy bridge local env: "
            f"{ntfy_status} (deploy/observability/ntfy-bridge/.env)"
        )
        print("\nLocal access after a manual start")
        for component in observability["components"].values():
            if component.get("access_url"):
                print(f"[INFO] {component['name']}: {component['access_url']}")
        print(f"[INFO] Logging flow: {observability['logging_note']}")
    print("[INFO] Observability containers are not started automatically.")

    if payload["mode"] == "repair":
        print("\nRepair guidance")
        for guidance in payload["repair_guidance"]:
            print(f"[INFO] {guidance}")

    print("\nManual guidance")
    for command in payload["suggested_commands"]:
        print(f"[NEXT] {command}")

    print("\nNext steps")
    print("[INFO] Demo data is not seeded automatically.")
    print("[INFO] Ollama models are not downloaded automatically.")
    for command in payload["next_steps"]:
        print(f"[NEXT] {command}")
    print(f"\nResult: {payload['result']}")


def main(
    argv: list[str] | None = None,
    *,
    repository_root: Path = REPO_ROOT,
    runner: Runner = run_command,
    which: Which = shutil.which,
    probe: HttpProbe = http_probe,
    os_release: dict[str, str] | None = None,
) -> int:
    args = parse_args(argv)
    payload = UbuntuDemoInstaller(
        args,
        repository_root=repository_root,
        runner=runner,
        which=which,
        probe=probe,
        os_release=os_release,
    ).run()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        render_human(payload)
    return int(payload["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
