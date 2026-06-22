from __future__ import annotations

from pathlib import Path

import scripts.validate_external_docs as external_docs


def create_valid_docs(root: Path) -> None:
    for relative in external_docs.REQUIRED_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# Documentation\n", encoding="utf-8")

    (root / "README.md").write_text(
        "\n".join(
            (
                "docs/external-user-quickstart.md",
                "docs/troubleshooting.md",
                "docs/docker-demo-packaging.md",
                "docs/demo-guide.md",
            )
        ),
        encoding="utf-8",
    )
    (root / "INSTALL.md").write_text(
        "\n".join(
            (
                "docs/external-user-quickstart.md",
                "docs/troubleshooting.md",
                *external_docs.COMMAND_REQUIREMENTS,
            )
        ),
        encoding="utf-8",
    )


def test_valid_external_documentation_passes(tmp_path: Path) -> None:
    create_valid_docs(tmp_path)

    report, exit_code = external_docs.validate(tmp_path)

    assert exit_code == 0
    assert report["result"] == "EXTERNAL_DOCS_READY"
    assert report["summary"]["fail"] == 0


def test_missing_reference_fails(tmp_path: Path) -> None:
    create_valid_docs(tmp_path)
    (tmp_path / "README.md").write_text("docs/demo-guide.md\n", encoding="utf-8")

    report, exit_code = external_docs.validate(tmp_path)

    assert exit_code == 1
    assert report["result"] == "EXTERNAL_DOCS_NOT_READY"
    assert any(
        item["name"] == "README external quickstart"
        for item in report["failures"]
    )


def test_obvious_token_is_rejected(tmp_path: Path) -> None:
    create_valid_docs(tmp_path)
    quickstart = tmp_path / "docs" / "product" / "external-user-quickstart.md"
    quickstart.write_text(
        "github_pat_abcdefghijklmnopqrstuvwxyz123456\n",
        encoding="utf-8",
    )

    report, exit_code = external_docs.validate(tmp_path)

    assert exit_code == 1
    assert any(
        item["name"] == "Obvious secret patterns"
        for item in report["failures"]
    )


def test_json_mode_is_supported() -> None:
    args = external_docs.parse_args(["--json"])

    assert args.json is True
