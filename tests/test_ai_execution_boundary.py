from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APPROVED_LOW_LEVEL = {
    Path("ai_provider_abstraction.py"),
    Path("ai_provider_policy.py"),
    Path("ai_provider_registry.py"),
    Path("llama_cpp_profiles.py"),
    Path("llm_client.py"),
}
FORBIDDEN_IMPORTS = {
    "ai_provider_abstraction",
    "llm_client",
    "llama_cpp_profiles",
}
FORBIDDEN_CALLS = {
    "build_provider_client",
    "ensure_profile",
    "load_profile",
    "prewarm_profile",
    "select_llama_cpp_profile",
    "unload_profile",
}


def _production_python_files():
    excluded = {".git", ".venv", "__pycache__", "node_modules",
                "config.backup.1779663398", "tests"}
    for directory, children, files in os.walk(ROOT):
        parent = Path(directory)
        children[:] = [name for name in children if name not in excluded
                       and not (parent / name / "pyvenv.cfg").is_file()]
        for name in files:
            if name.endswith(".py"):
                path = parent / name
                yield path, path.relative_to(ROOT)


def test_boundary_scanner_excludes_environments_not_application_code(tmp_path, monkeypatch):
    monkeypatch.setattr(__import__(__name__), "ROOT", tmp_path)
    for folder in (".venv-xpu-test", "custom-environment"):
        root = tmp_path / folder
        root.mkdir()
        (root / "pyvenv.cfg").write_text("home = /fixture/python\n")
        (root / "vendor.py").write_bytes(b"\xa4")
    for folder in ("services", "new_module", "frontend/node_modules/package"):
        root = tmp_path / folder
        root.mkdir(parents=True)
        (root / "app.py").write_text("import llm_client\n")
    assert {relative.as_posix() for _, relative in _production_python_files()} == {
        "services/app.py", "new_module/app.py",
    }
    with pytest.raises(AssertionError, match="import llm_client"):
        test_only_gateway_and_low_level_modules_touch_generative_providers()


def test_only_gateway_and_low_level_modules_touch_generative_providers() -> None:
    violations = []
    for path, relative in _production_python_files():
        if (
            relative in APPROVED_LOW_LEVEL
            or relative.parts[:2] == ("services", "ai_execution")
        ):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = str(node.module or "")
                if module in FORBIDDEN_IMPORTS:
                    violations.append(f"{relative}:{node.lineno}: import {module}")
            elif isinstance(node, ast.Import):
                for name in node.names:
                    if name.name in FORBIDDEN_IMPORTS:
                        violations.append(
                            f"{relative}:{node.lineno}: import {name.name}"
                        )
            elif isinstance(node, ast.Call):
                name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else ""
                )
                if name in FORBIDDEN_CALLS:
                    violations.append(
                        f"{relative}:{node.lineno}: call {name}"
                    )

    assert violations == []


def test_production_callers_use_gateway_client_and_no_raw_chat_endpoint() -> None:
    expected_callers = (
        "ai_triage.py",
        "ai_triage_hardening.py",
        "case_action_suggestions.py",
        "case_ai_analysis.py",
        "detection_quality_guidance.py",
        "recommended_playbooks_llm.py",
        "services/assistant/orchestrator.py",
    )
    for relative in expected_callers:
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "services.ai_execution.client" in source

    remediation = (ROOT / "remediation/intelligence.py").read_text(
        encoding="utf-8"
    )
    assert "from ai_triage_hardening import call_ai_gateway" in remediation

    for path, relative in _production_python_files():
        if (
            relative in APPROVED_LOW_LEVEL
            or relative.parts[:2] == ("services", "ai_execution")
        ):
            continue
        source = path.read_text(encoding="utf-8")
        assert "/v1/chat/completions" not in source
        assert "chat/completions" not in source
