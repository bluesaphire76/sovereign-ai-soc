#!/usr/bin/env python3
"""Validate the external-user documentation surface without network access."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "README.md",
    "INSTALL.md",
    "docs/external-user-quickstart.md",
    "docs/troubleshooting.md",
    "docs/ports-and-components.md",
    "docs/demo-guide.md",
    "docs/docker-demo-packaging.md",
    "docs/product/external-user-quickstart.md",
    "docs/operations/troubleshooting.md",
    "docs/operations/ports-and-components.md",
    "docs/product/demo-guide.md",
    "docs/operations/docker-demo-packaging.md",
)

REFERENCE_REQUIREMENTS = (
    ("README external quickstart", "README.md", "docs/external-user-quickstart.md"),
    ("README troubleshooting", "README.md", "docs/troubleshooting.md"),
    ("README Docker packaging", "README.md", "docs/docker-demo-packaging.md"),
    ("README demo guide", "README.md", "docs/demo-guide.md"),
    ("INSTALL external quickstart", "INSTALL.md", "docs/external-user-quickstart.md"),
    ("INSTALL troubleshooting", "INSTALL.md", "docs/troubleshooting.md"),
)

COMMAND_REQUIREMENTS = (
    "./ai-soc install --profile demo",
    "./ai-soc package-validate",
    "./ai-soc demo-info",
    "./ai-soc demo-reset",
    "./ai-soc release-check",
)

SECRET_PATTERNS = (
    ("GitHub token", re.compile(r"\b(?:github_pat_|ghp_)[A-Za-z0-9_]{20,}\b")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "bearer token",
        re.compile(r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    ),
)


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    summary: str


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate external-user documentation and command references.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    return parser.parse_args(argv)


def read_text(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8", errors="replace")


def validate(root: Path = ROOT) -> tuple[dict[str, object], int]:
    checks: list[Check] = []

    missing = [relative for relative in REQUIRED_FILES if not (root / relative).is_file()]
    checks.append(
        Check(
            "Required external documentation",
            "FAIL" if missing else "OK",
            (
                "Missing: " + ", ".join(missing)
                if missing
                else "All required quickstart, troubleshooting, compatibility, and canonical files exist."
            ),
        )
    )

    for name, relative, marker in REFERENCE_REQUIREMENTS:
        path = root / relative
        present = path.is_file() and marker in read_text(root, relative)
        checks.append(
            Check(
                name,
                "OK" if present else "FAIL",
                (
                    f"{relative} references {marker}."
                    if present
                    else f"{relative} must reference {marker}."
                ),
            )
        )

    command_sources = (
        "README.md",
        "INSTALL.md",
        "docs/product/external-user-quickstart.md",
        "docs/operations/troubleshooting.md",
    )
    combined = "\n".join(
        read_text(root, relative)
        for relative in command_sources
        if (root / relative).is_file()
    )
    for command in COMMAND_REQUIREMENTS:
        present = command in combined
        checks.append(
            Check(
                f"Command reference: {command}",
                "OK" if present else "FAIL",
                "Documented." if present else "Required external-user command is missing.",
            )
        )

    secret_hits: list[str] = []
    for relative in REQUIRED_FILES:
        path = root / relative
        if not path.is_file():
            continue
        text = read_text(root, relative)
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                secret_hits.append(f"{relative}: {label}")
    checks.append(
        Check(
            "Obvious secret patterns",
            "FAIL" if secret_hits else "OK",
            (
                "Potential secrets: " + ", ".join(secret_hits)
                if secret_hits
                else "No obvious raw token or private-key patterns found."
            ),
        )
    )

    failures = [asdict(check) for check in checks if check.status == "FAIL"]
    exit_code = int(bool(failures))
    report: dict[str, object] = {
        "validator": "Sovereign AI SOC external documentation",
        "result": "EXTERNAL_DOCS_NOT_READY" if exit_code else "EXTERNAL_DOCS_READY",
        "exit_code": exit_code,
        "summary": {
            "ok": sum(check.status == "OK" for check in checks),
            "fail": len(failures),
            "total": len(checks),
        },
        "checks": [asdict(check) for check in checks],
        "failures": failures,
    }
    return report, exit_code


def print_human(report: dict[str, object]) -> None:
    print("Sovereign AI SOC External Documentation Validation")
    for check in report["checks"]:
        print(f"[{check['status']}] {check['name']}: {check['summary']}")
    summary = report["summary"]
    print(
        f"\nChecks: {summary['ok']} OK, {summary['fail']} FAIL, "
        f"{summary['total']} total"
    )
    print(f"Result: {report['result']}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report, exit_code = validate()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
