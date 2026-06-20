#!/usr/bin/env python3
"""Validate the repository's lightweight public CI baseline."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent


def exists(relative_path: str) -> bool:
    return (REPOSITORY_ROOT / relative_path).exists()


def run_check(command: list[str], description: str, failures: list[str]) -> None:
    print(f"[INFO] {description}")
    result = subprocess.run(command, cwd=REPOSITORY_ROOT, check=False)

    if result.returncode == 0:
        print(f"[OK] {description}")
    else:
        print(f"[FAIL] {description}")
        failures.append(description)


def main() -> int:
    failures: list[str] = []

    required_paths = (
        (".github/workflows/ci.yml", "GitHub Actions workflow exists"),
        ("README.md", "README exists"),
        ("requirements.txt", "Backend requirements file exists"),
        ("scripts/validate_docs_structure.py", "Documentation structure validator exists"),
    )
    for relative_path, message in required_paths:
        if exists(relative_path):
            print(f"[OK] {message}")
        else:
            print(f"[FAIL] {message}: missing {relative_path}")
            failures.append(relative_path)

    optional_paths = (
        ("frontend/package.json", "Frontend package detected"),
        ("tests", "Tests directory detected"),
        ("deploy", "Deploy directory detected"),
    )
    for relative_path, message in optional_paths:
        if exists(relative_path):
            print(f"[OK] {message}")
        else:
            print(f"[WARN] {message}: {relative_path} not found; check skipped")

    if exists("scripts/validate_docs_structure.py"):
        run_check(
            [sys.executable, "scripts/validate_docs_structure.py"],
            "Documentation structure validation",
            failures,
        )

    print("[OK] No local secrets or external services are required")

    if failures:
        print(
            "[FAIL] Public CI baseline validation failed: "
            + ", ".join(failures)
        )
        return 1

    print("[OK] Public CI baseline validation completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
