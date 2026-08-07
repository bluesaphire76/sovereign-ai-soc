#!/usr/bin/env python3
"""Render, upgrade, or remove project systemd units with explicit scope."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
UNIT_NAMES = (
    "ai-soc-inference-gateway.service",
    "ai-soc-api.service",
    "ai-soc-worker.service",
    "ai-soc-frontend.service",
)
SAFE_ACCOUNT_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage rendered Sovereign AI SOC systemd units.",
    )
    parser.add_argument(
        "action",
        choices=("render", "upgrade", "uninstall"),
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=REPOSITORY_ROOT,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--service-user",
        default=os.getenv("USER", "ai-soc"),
    )
    parser.add_argument("--service-group")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--allow-system-directory",
        action="store_true",
        help="Allow an operator-requested write below /etc or /usr/lib.",
    )
    return parser.parse_args(argv)


def _validate(args: argparse.Namespace) -> tuple[Path, Path, str, str]:
    project_root = args.project_root.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    user = str(args.service_user).strip()
    group = str(args.service_group or user).strip()
    if not project_root.is_dir():
        raise ValueError("project root does not exist")
    if not SAFE_ACCOUNT_RE.fullmatch(user):
        raise ValueError("invalid service user")
    if not SAFE_ACCOUNT_RE.fullmatch(group):
        raise ValueError("invalid service group")
    protected = output_dir == Path("/etc") or output_dir.is_relative_to(
        Path("/etc")
    ) or output_dir.is_relative_to(Path("/usr/lib"))
    if protected and not args.allow_system_directory:
        raise ValueError(
            "system directories require --allow-system-directory"
        )
    return project_root, output_dir, user, group


def render_unit(
    source: str,
    *,
    project_root: Path,
    user: str,
    group: str,
) -> str:
    return (
        source.replace("User=ai-soc", f"User={user}")
        .replace("Group=ai-soc", f"Group={group}")
        .replace("/opt/sovereign-ai-soc", str(project_root))
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        project_root, output_dir, user, group = _validate(args)
    except ValueError as exc:
        print(f"[FAIL] {exc}")
        return 2

    targets = [output_dir / name for name in UNIT_NAMES]
    if args.action == "uninstall":
        for target in targets:
            print(
                f"[{'REMOVE' if args.apply else 'DRY-RUN'}] {target}"
            )
            if args.apply:
                target.unlink(missing_ok=True)
        return 0

    source_dir = project_root / "systemd"
    missing = [
        name for name in UNIT_NAMES if not (source_dir / name).is_file()
    ]
    if missing:
        print(f"[FAIL] Missing unit templates: {', '.join(missing)}")
        return 1

    for name, target in zip(UNIT_NAMES, targets, strict=True):
        rendered = render_unit(
            (source_dir / name).read_text(encoding="utf-8"),
            project_root=project_root,
            user=user,
            group=group,
        )
        print(
            f"[{'WRITE' if args.apply else 'DRY-RUN'}] {target}"
        )
        if args.apply:
            output_dir.mkdir(parents=True, exist_ok=True)
            target.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
