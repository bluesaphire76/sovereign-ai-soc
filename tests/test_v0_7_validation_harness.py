from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS = REPO_ROOT / "scripts/v0_7_validation_harness.py"


def run_harness(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HARNESS), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )


def test_help_includes_mode_argument() -> None:
    result = run_harness("--help")

    assert result.returncode == 0
    assert "--mode" in result.stdout
    assert "local" in result.stdout
    assert "ci" in result.stdout
    assert "demo" in result.stdout


def test_ci_mode_writes_reports_without_live_runtime(tmp_path: Path) -> None:
    result = run_harness(
        "--mode",
        "ci",
        "--skip-frontend-build",
        "--output-dir",
        str(tmp_path),
        "--no-destructive",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    summary_path = tmp_path / "v0.7-validation-summary.json"
    details_path = tmp_path / "v0.7-validation-details.json"
    markdown_path = tmp_path / "v0.7-validation-summary.md"
    assert summary_path.exists()
    assert details_path.exists()
    assert markdown_path.exists()

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["mode"] == "ci"
    assert summary["counts"]["FAIL"] == 0
    assert any(check["id"] == "PY-001" for check in summary["checks"])


def test_local_mode_handles_unavailable_api_as_warning(tmp_path: Path) -> None:
    result = run_harness(
        "--mode",
        "local",
        "--skip-frontend-build",
        "--skip-db",
        "--base-url",
        "http://127.0.0.1:9",
        "--output-dir",
        str(tmp_path),
        "--no-destructive",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads((tmp_path / "v0.7-validation-summary.json").read_text(encoding="utf-8"))
    api_check = next(check for check in summary["checks"] if check["id"] == "API-001")
    assert api_check["status"] == "WARN"


def test_reports_do_not_contain_token_value(tmp_path: Path) -> None:
    secret = "unit-test-super-secret-token"
    result = run_harness(
        "--mode",
        "ci",
        "--skip-frontend-build",
        "--token",
        secret,
        "--output-dir",
        str(tmp_path),
        "--no-destructive",
    )

    assert result.returncode == 0, result.stdout + result.stderr
    for report in tmp_path.iterdir():
        assert secret not in report.read_text(encoding="utf-8")


def test_unknown_mode_is_rejected() -> None:
    result = run_harness("--mode", "unknown")

    assert result.returncode != 0
    assert "invalid choice" in result.stderr
