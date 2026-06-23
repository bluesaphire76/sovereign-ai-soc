from __future__ import annotations

import json
from pathlib import Path

import scripts.install_demo_ubuntu as ubuntu_installer


def make_repository(tmp_path: Path, *, ntfy_env: bool = True) -> Path:
    files = {
        "ai-soc": "#!/bin/sh\n",
        "requirements.txt": "pytest\n",
        "frontend/package.json": "{}\n",
        "deploy/demo/docker-compose.demo.yml": "services: {}\n",
        "scripts/install_local.py": "# installer\n",
        "deploy/observability/docker-compose.yml": """
services:
  prometheus:
    network_mode: host
  alertmanager:
    network_mode: host
    command:
      - --web.listen-address=127.0.0.1:9093
  grafana:
    ports:
      - "127.0.0.1:3002:3000"
  node-exporter:
    ports:
      - "127.0.0.1:9100:9100"
  cadvisor:
    ports:
      - "127.0.0.1:8082:8080"
  ntfy-bridge:
    env_file:
      - ./ntfy-bridge/.env
    ports:
      - "127.0.0.1:8011:8011"
""",
        "deploy/observability/docker-compose.loki.yml": """
services:
  loki:
    ports:
      - "127.0.0.1:3100:3100"
  alloy:
    ports:
      - "127.0.0.1:12345:12345"
""",
        "deploy/observability/prometheus/prometheus.yml": (
            "scrape_configs:\n  - targets: [127.0.0.1:9090]\n"
        ),
        "deploy/observability/alertmanager/alertmanager.yml": "route: {}\n",
        "deploy/observability/loki/loki.local.yml": "server: {}\n",
        "deploy/observability/alloy/config.alloy": "logging {}\n",
        "deploy/observability/grafana/dashboards/example.json": "{}\n",
        "deploy/observability/grafana/provisioning/example.yml": "{}\n",
        "deploy/observability/ntfy-bridge/.env.example": "NTFY_URL=<url>\n",
    }
    if ntfy_env:
        files["deploy/observability/ntfy-bridge/.env"] = "NTFY_URL=<local>\n"
    for relative, content in files.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def successful_runner(args, *, cwd, timeout):
    del cwd, timeout
    command = " ".join(str(arg) for arg in args)
    if command.endswith("python3 --version") or command.endswith("/python3 --version"):
        return ubuntu_installer.CommandResult(0, "Python 3.12.8\n")
    if command.endswith("node --version") or command.endswith("/node --version"):
        return ubuntu_installer.CommandResult(0, "v20.19.0\n")
    return ubuntu_installer.CommandResult(0, "ok\n")


def all_tools(name: str) -> str:
    return f"/usr/bin/{name}"


def ready_installer(
    tmp_path: Path,
    argv: list[str],
    *,
    ntfy_env: bool = True,
    runner=successful_runner,
    which=all_tools,
    os_release: dict[str, str] | None = None,
) -> ubuntu_installer.UbuntuDemoInstaller:
    return ubuntu_installer.UbuntuDemoInstaller(
        ubuntu_installer.parse_args(argv),
        repository_root=make_repository(tmp_path, ntfy_env=ntfy_env),
        runner=runner,
        which=which,
        probe=lambda _url, _timeout: (True, "HTTP 200"),
        os_release=os_release
        or {
            "ID": "ubuntu",
            "VERSION_ID": "24.04",
            "PRETTY_NAME": "Ubuntu 24.04 LTS",
        },
    )


def test_default_mode_is_check() -> None:
    assert ubuntu_installer.parse_args([]).mode == "check"


def test_ubuntu_2404_is_supported(tmp_path: Path) -> None:
    payload = ready_installer(tmp_path, ["--check"]).run()

    assert payload["result"] == ubuntu_installer.RESULT_READY
    assert payload["exit_code"] == 0


def test_non_ubuntu_and_old_ubuntu_warn_without_crashing(tmp_path: Path) -> None:
    non_ubuntu = ready_installer(
        tmp_path / "debian",
        ["--check"],
        os_release={
            "ID": "debian",
            "VERSION_ID": "12",
            "PRETTY_NAME": "Debian 12",
        },
    ).run()
    old_ubuntu = ready_installer(
        tmp_path / "ubuntu",
        ["--check"],
        os_release={
            "ID": "ubuntu",
            "VERSION_ID": "22.04",
            "PRETTY_NAME": "Ubuntu 22.04 LTS",
        },
    ).run()

    assert non_ubuntu["exit_code"] == 0
    assert old_ubuntu["exit_code"] == 0
    assert non_ubuntu["warnings"]
    assert old_ubuntu["warnings"]


def test_missing_required_tool_fails_cleanly(tmp_path: Path) -> None:
    def missing_node(name: str) -> str | None:
        return None if name == "node" else f"/usr/bin/{name}"

    payload = ready_installer(tmp_path, ["--check"], which=missing_node).run()

    assert payload["result"] == ubuntu_installer.RESULT_NOT_READY
    assert payload["exit_code"] == 1
    assert any("Node.js" in check["name"] for check in payload["checks"])


def test_existing_venv_pip_satisfies_missing_system_pip(tmp_path: Path) -> None:
    repository = make_repository(tmp_path)
    venv_python = repository / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("#!/bin/sh\n", encoding="utf-8")

    def runner(args, *, cwd, timeout):
        result = successful_runner(args, cwd=cwd, timeout=timeout)
        if args[:4] == ["/usr/bin/python3", "-m", "pip", "--version"]:
            return ubuntu_installer.CommandResult(1, "", "No module named pip")
        return result

    installer = ubuntu_installer.UbuntuDemoInstaller(
        ubuntu_installer.parse_args(["--check"]),
        repository_root=repository,
        runner=runner,
        which=all_tools,
        probe=lambda _url, _timeout: (True, "HTTP 200"),
        os_release={
            "ID": "ubuntu",
            "VERSION_ID": "24.04",
            "PRETTY_NAME": "Ubuntu 24.04 LTS",
        },
    )
    payload = installer.run()

    assert payload["exit_code"] == 0
    assert any(
        check["name"] == "System pip guidance"
        for check in payload["checks"]
    )


def test_old_node_fails_cleanly(tmp_path: Path) -> None:
    def runner(args, *, cwd, timeout):
        result = successful_runner(args, cwd=cwd, timeout=timeout)
        if str(args[0]).endswith("/node") and args[1:] == ["--version"]:
            return ubuntu_installer.CommandResult(0, "v18.20.0\n")
        return result

    payload = ready_installer(tmp_path, ["--check"], runner=runner).run()

    assert payload["exit_code"] == 1
    assert any("Node.js 20+" in item for item in payload["failures"])


def test_docker_daemon_failure_has_targeted_guidance(tmp_path: Path) -> None:
    def runner(args, *, cwd, timeout):
        result = successful_runner(args, cwd=cwd, timeout=timeout)
        if str(args[0]).endswith("/docker") and args[1:] == ["info"]:
            return ubuntu_installer.CommandResult(1, "", "permission denied")
        return result

    payload = ready_installer(tmp_path, ["--check"], runner=runner).run()

    assert payload["exit_code"] == 1
    assert 'sudo usermod -aG docker "$USER"' in payload["suggested_commands"]
    assert "newgrp docker" in payload["suggested_commands"]


def test_missing_ollama_is_warning_not_failure(tmp_path: Path) -> None:
    def no_ollama(name: str) -> str | None:
        return None if name == "ollama" else f"/usr/bin/{name}"

    installer = ubuntu_installer.UbuntuDemoInstaller(
        ubuntu_installer.parse_args(["--check"]),
        repository_root=make_repository(tmp_path),
        runner=successful_runner,
        which=no_ollama,
        probe=lambda _url, _timeout: (False, "unreachable"),
        os_release={
            "ID": "ubuntu",
            "VERSION_ID": "24.04",
            "PRETTY_NAME": "Ubuntu 24.04 LTS",
        },
    )
    payload = installer.run()

    assert payload["exit_code"] == 0
    assert payload["result"] == ubuntu_installer.RESULT_WARNINGS
    assert any("Ollama" in warning for warning in payload["warnings"])


def test_observability_components_and_ports_are_reported(tmp_path: Path) -> None:
    payload = ready_installer(
        tmp_path,
        ["--check-observability"],
    ).run()
    components = payload["observability"]["components"]

    assert payload["result"] == ubuntu_installer.RESULT_OBS_READY
    assert all(component["detected"] for component in components.values())
    assert components["grafana"]["ports"] == ["3002 -> 3000"]
    assert components["prometheus"]["ports"] == ["9090 (host network)"]
    assert components["cadvisor"]["ports"] == ["8082 -> 8080"]
    assert components["alloy"]["name"] == "Grafana Alloy"
    assert components["grafana"]["access_url"] == "http://127.0.0.1:3002/grafana/"
    assert components["prometheus"]["access_url"] == "http://127.0.0.1:9090"
    assert components["alertmanager"]["access_url"] == "http://127.0.0.1:9093"


def test_missing_ntfy_env_warns_and_skips_full_compose(tmp_path: Path) -> None:
    payload = ready_installer(
        tmp_path,
        ["--check-observability"],
        ntfy_env=False,
    ).run()

    full = payload["observability"]["config_validation"][
        "full_observability_compose"
    ]
    assert payload["exit_code"] == 0
    assert payload["result"] == ubuntu_installer.RESULT_OBS_WARNINGS
    assert full["status"] == ubuntu_installer.STATUS_WARN
    assert "missing local env" in full["reason"]
    assert not any(
        "docker-compose.yml config --quiet" in command
        for command in payload["executed_commands"]
    )


def test_observability_plan_executes_no_commands(tmp_path: Path, capsys) -> None:
    payload = ready_installer(tmp_path, ["--observability-plan"]).run()
    ubuntu_installer.render_human(payload)
    output = capsys.readouterr().out

    assert payload["result"] == ubuntu_installer.RESULT_OBS_PLAN
    assert payload["executed_commands"] == []
    assert any("up -d" in command for command in payload["suggested_commands"])
    assert "http://127.0.0.1:3002/grafana/" in output
    assert "http://127.0.0.1:9090" in output
    assert "http://127.0.0.1:9093" in output
    assert "Grafana Alloy collects" in output
    assert "deploy/observability/docker-compose.yml" in output
    assert "deploy/observability/alloy/config.alloy" in output
    assert "ntfy bridge local env: present" in output


def test_apply_delegates_only_to_safe_commands(tmp_path: Path) -> None:
    payload = ready_installer(tmp_path, ["--apply"]).run()
    commands = payload["executed_commands"]

    assert payload["exit_code"] == 0
    assert any("install --profile demo --apply" in command for command in commands)
    assert any("release-check --skip-runtime" in command for command in commands)
    forbidden = (
        "sudo",
        "apt ",
        "systemctl",
        "usermod",
        "newgrp",
        "docker compose up",
        "docker compose down",
        "ollama pull",
        "demo-seed --apply",
        "demo-reset --apply",
    )
    assert not any(marker in command for marker in forbidden for command in commands)


def test_repair_returns_guidance_even_when_diagnostic_command_warns(
    tmp_path: Path,
    capsys,
) -> None:
    def runner(args, *, cwd, timeout):
        result = successful_runner(args, cwd=cwd, timeout=timeout)
        if " doctor" in f" {' '.join(str(arg) for arg in args)}":
            return ubuntu_installer.CommandResult(1, "", "not ready")
        return result

    payload = ready_installer(tmp_path, ["--repair"], runner=runner).run()
    ubuntu_installer.render_human(payload)
    output = capsys.readouterr().out

    assert payload["result"] == ubuntu_installer.RESULT_REPAIR
    assert payload["exit_code"] == 0
    assert "npm ci fails" in output
    assert "Docker daemon" in output
    assert "ntfy bridge" in output


def test_json_output_is_valid(tmp_path: Path, capsys) -> None:
    exit_code = ubuntu_installer.main(
        ["--check-observability", "--json"],
        repository_root=make_repository(tmp_path),
        runner=successful_runner,
        which=all_tools,
        probe=lambda _url, _timeout: (True, "HTTP 200"),
        os_release={
            "ID": "ubuntu",
            "VERSION_ID": "24.04",
            "PRETTY_NAME": "Ubuntu 24.04 LTS",
        },
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["detected_os_id"] == "ubuntu"
    assert payload["observability"]["components"]["grafana"]["detected"] is True


def test_wrapper_is_safe_and_delegates_to_python() -> None:
    wrapper = (ubuntu_installer.REPO_ROOT / "install-demo.sh").read_text(
        encoding="utf-8"
    )
    source = Path(ubuntu_installer.__file__).read_text(encoding="utf-8")

    assert 'scripts/install_demo_ubuntu.py" "$@"' in wrapper
    assert "shell=True" not in source
    assert "subprocess.run(" in source
