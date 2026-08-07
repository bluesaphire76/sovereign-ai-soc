from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK_ROUTER = ROOT / "routers" / "playbook_recommendations.py"
REMEDIATION_ROUTER = ROOT / "routers" / "remediation.py"
INCIDENT_PAGE = (
    ROOT / "frontend" / "src" / "app" / "incidents" / "[id]" / "page.tsx"
)
CASE_PAGE = (
    ROOT / "frontend" / "src" / "app" / "cases" / "[id]" / "page.tsx"
)
PLAYBOOK_PANEL = (
    ROOT
    / "frontend"
    / "src"
    / "components"
    / "semantic-memory"
    / "RecommendedPlaybooksPanel.tsx"
)


def _keyword_value(
    source_path: Path,
    function_name: str,
    called_name: str,
    keyword: str,
) -> bool:
    tree = ast.parse(
        source_path.read_text(encoding="utf-8"),
        filename=str(source_path),
    )
    function = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    )
    call = next(
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Name)
            and node.func.id == called_name
        )
    )
    value = next(
        item.value for item in call.keywords if item.arg == keyword
    )
    assert isinstance(value, ast.Constant)
    return bool(value.value)


def test_get_routes_never_generate_and_post_routes_explicitly_generate() -> None:
    for getter, poster, builder in (
        (
            "get_incident_playbook_recommendations",
            "generate_incident_playbook_recommendations",
            "build_incident_playbook_recommendations",
        ),
        (
            "get_case_playbook_recommendations",
            "generate_case_playbook_recommendations",
            "build_case_playbook_recommendations",
        ),
    ):
        assert _keyword_value(
            PLAYBOOK_ROUTER,
            getter,
            builder,
            "generate_llm",
        ) is False
        assert _keyword_value(
            PLAYBOOK_ROUTER,
            poster,
            builder,
            "generate_llm",
        ) is True

    assert _keyword_value(
        REMEDIATION_ROUTER,
        "get_incident_remediation_plan",
        "generate_remediation_intelligence",
        "generate_llm",
    ) is False
    assert _keyword_value(
        REMEDIATION_ROUTER,
        "generate_incident_remediation_plan",
        "generate_remediation_intelligence",
        "generate_llm",
    ) is True


def test_pages_use_explicit_post_controls_and_block_duplicate_submit() -> None:
    incident = INCIDENT_PAGE.read_text(encoding="utf-8")
    case = CASE_PAGE.read_text(encoding="utf-8")
    panel = PLAYBOOK_PANEL.read_text(encoding="utf-8")

    assert 'method: "POST"' in incident
    assert 'method: "POST"' in case
    assert "Generate remediation analysis" in incident
    assert "Generate playbook suggestions" in panel
    assert "playbookGenerationActiveRef.current" in incident
    assert "playbookGenerationActiveRef.current" in case
    assert "remediationGenerationActiveRef.current" in incident
    assert 'generationStatus === "queued"' in panel
    assert 'generationStatus === "running"' in panel

    for status in ("queued", "running", "completed", "failed"):
        assert status in incident
        assert status in case or status in panel
