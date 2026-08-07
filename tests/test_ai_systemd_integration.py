from __future__ import annotations

from pathlib import Path

from scripts.manage_systemd_units import UNIT_NAMES, main


ROOT = Path(__file__).resolve().parents[1]


def test_systemd_templates_are_generic_and_ordered() -> None:
    units = {
        name: (ROOT / "systemd" / name).read_text(encoding="utf-8")
        for name in UNIT_NAMES
    }
    for source in units.values():
        assert "User=ai-soc" in source
        assert "Group=ai-soc" in source
        assert "/opt/sovereign-ai-soc" in source
        assert "/home/lele" not in source

    gateway = units["ai-soc-inference-gateway.service"]
    assert "Requires=ai-soc-llama-cpp-router.service" in gateway
    assert "RuntimeDirectory=ai-soc" in gateway
    assert "UMask=0007" in gateway
    assert "--uds /run/ai-soc/inference-gateway.sock" in gateway

    api = units["ai-soc-api.service"]
    worker = units["ai-soc-worker.service"]
    frontend = units["ai-soc-frontend.service"]
    assert "Requires=docker.service ai-soc-inference-gateway.service" in api
    assert (
        "Requires=docker.service ai-soc-inference-gateway.service "
        "ai-soc-api.service"
    ) in worker
    assert "After=network.target ai-soc-api.service ai-soc-worker.service" in frontend
    assert "Requires=ai-soc-api.service ai-soc-worker.service" in frontend


def test_unit_manager_is_dry_run_by_default_and_supports_lifecycle(
    tmp_path,
) -> None:
    output = tmp_path / "units"
    base = [
        "--project-root",
        str(ROOT),
        "--output-dir",
        str(output),
        "--service-user",
        "socsvc",
        "--service-group",
        "socops",
    ]
    assert main(["render", *base]) == 0
    assert output.exists() is False

    assert main(["render", *base, "--apply"]) == 0
    rendered = (
        output / "ai-soc-inference-gateway.service"
    ).read_text(encoding="utf-8")
    assert "User=socsvc" in rendered
    assert "Group=socops" in rendered
    assert f"WorkingDirectory={ROOT}" in rendered

    assert main(["upgrade", *base, "--apply"]) == 0
    assert all((output / name).is_file() for name in UNIT_NAMES)
    assert main(["uninstall", *base]) == 0
    assert all((output / name).is_file() for name in UNIT_NAMES)
    assert main(["uninstall", *base, "--apply"]) == 0
    assert all(not (output / name).exists() for name in UNIT_NAMES)


def test_unit_manager_refuses_live_system_directory_without_opt_in() -> None:
    assert (
        main(
            [
                "render",
                "--project-root",
                str(ROOT),
                "--output-dir",
                "/etc/systemd/system",
            ]
        )
        == 2
    )
