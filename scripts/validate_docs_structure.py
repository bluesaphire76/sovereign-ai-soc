#!/usr/bin/env python3
"""Validate Sovereign AI SOC documentation structure.

This validator protects the documentation taxonomy introduced during the
documentation cleanup work:

- real release notes live in docs/releases/
- real validation notes live in docs/validation/
- real product docs live in docs/product/
- real operations docs live in docs/operations/
- real architecture docs live in docs/architecture/
- compatibility stubs may remain in root or docs/ to keep old links working
- local Markdown links must resolve
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DOCS = ROOT / "docs"
CANONICAL_DOC_DIRS = {
    "product",
    "operations",
    "architecture",
    "releases",
    "validation",
}

IGNORED_PARTS = {
    ".git",
    ".venv",
    "node_modules",
    ".next",
    "config.backup.1779663398",
}

LOCAL_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def is_ignored(path: Path) -> bool:
    try:
        rel_path = path.relative_to(ROOT)
    except ValueError:
        return True
    return any(part in IGNORED_PARTS for part in rel_path.parts)


def is_stub(text: str) -> bool:
    return "This document has moved to:" in text


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


def validate_required_dirs(errors: list[str]) -> None:
    for dirname in sorted(CANONICAL_DOC_DIRS):
        path = DOCS / dirname
        if not path.is_dir():
            fail(errors, f"Missing canonical docs directory: {rel(path)}")


def validate_root_release_note_stubs(errors: list[str]) -> None:
    for path in sorted(ROOT.glob("RELEASE_NOTES*.md")):
        text = read_text(path)
        base = path.name
        canonical = DOCS / "releases" / base

        if not canonical.exists():
            fail(
                errors,
                f"Root release note stub has missing canonical target: {rel(path)} -> docs/releases/{base}",
            )
            continue

        if not is_stub(text):
            fail(
                errors,
                f"Root release note must be a compatibility stub, not a full document: {rel(path)}",
            )

        expected_link = f"docs/releases/{base}"
        if expected_link not in text:
            fail(
                errors,
                f"Root release note stub must point to {expected_link}: {rel(path)}",
            )

        canonical_text = read_text(canonical)
        if is_stub(canonical_text):
            fail(
                errors,
                f"Canonical release note must not be a stub: {rel(canonical)}",
            )


def validate_top_level_docs_stubs(errors: list[str]) -> None:
    if not DOCS.exists():
        fail(errors, "Missing docs directory")
        return

    for path in sorted(DOCS.glob("*.md")):
        if path.name == "README.md":
            continue

        text = read_text(path)
        if not is_stub(text):
            fail(
                errors,
                f"Top-level docs file must be a compatibility stub or be moved to a canonical docs folder: {rel(path)}",
            )
            continue

        base = path.name
        expected_targets = [f"{dirname}/{base}" for dirname in sorted(CANONICAL_DOC_DIRS)]
        matching_targets = [target for target in expected_targets if target in text]

        if not matching_targets:
            fail(
                errors,
                f"Top-level docs stub must point to one of {sorted(CANONICAL_DOC_DIRS)}: {rel(path)}",
            )
            continue

        for target in matching_targets:
            target_path = DOCS / target
            if not target_path.exists():
                fail(
                    errors,
                    f"Top-level docs stub points to missing canonical file: {rel(path)} -> {target}",
                )


def validate_canonical_docs_not_stubs(errors: list[str]) -> None:
    for dirname in sorted(CANONICAL_DOC_DIRS):
        folder = DOCS / dirname
        if not folder.is_dir():
            continue

        for path in sorted(folder.glob("*.md")):
            if path.name == "README.md":
                continue

            text = read_text(path)
            if is_stub(text):
                fail(errors, f"Canonical document must not be a stub: {rel(path)}")


def validate_category_indexes(errors: list[str]) -> None:
    for dirname in sorted(CANONICAL_DOC_DIRS):
        folder = DOCS / dirname
        if not folder.is_dir():
            continue

        index = folder / "README.md"
        if not index.exists():
            fail(errors, f"Missing README index for canonical docs folder: {rel(folder)}")
            continue

        index_text = read_text(index)
        for document in sorted(folder.glob("*.md")):
            if document.name == "README.md":
                continue

            if document.name not in index_text:
                fail(
                    errors,
                    f"Canonical docs index does not reference {document.name}: {rel(index)}",
                )


def validate_local_markdown_links(errors: list[str]) -> None:
    for md in sorted(ROOT.rglob("*.md")):
        if is_ignored(md):
            continue

        text = read_text(md)
        for match in LOCAL_LINK_RE.finditer(text):
            raw = match.group(1).strip()

            if not raw:
                continue

            if raw.startswith(("http://", "https://", "mailto:", "#", "tel:")):
                continue

            if raw.startswith("<") and raw.endswith(">"):
                raw = raw[1:-1]

            target = raw.split("#", 1)[0]
            if not target:
                continue

            target_path = (md.parent / target).resolve()

            try:
                target_path.relative_to(ROOT)
            except ValueError:
                continue

            if not target_path.exists():
                fail(errors, f"Broken local Markdown link in {rel(md)} -> {raw}")


def main() -> int:
    errors: list[str] = []

    validate_required_dirs(errors)
    validate_root_release_note_stubs(errors)
    validate_top_level_docs_stubs(errors)
    validate_canonical_docs_not_stubs(errors)
    validate_category_indexes(errors)
    validate_local_markdown_links(errors)

    if errors:
        print("[ERROR] Documentation structure validation failed:")
        for error in errors:
            print(f" - {error}")
        return 1

    print("[OK] Documentation structure validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
