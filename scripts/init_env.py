#!/usr/bin/env python3
"""Safely create a local .env file from the tracked example."""

from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SOURCE_PATH = REPOSITORY_ROOT / ".env.example"
DEFAULT_TARGET_PATH = REPOSITORY_ROOT / ".env"

ASSIGNMENT_PATTERN = re.compile(
    r"^(?P<prefix>\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)=)"
    r"(?P<value>.*)$"
)
PLACEHOLDER_MARKERS = (
    "placeholder",
    "replace-me",
    "replace_with",
    "change-me",
    "changeme",
    "set-a-",
    "set_",
    "your-",
    "your_",
)
OPTIONAL_EXTERNAL_CREDENTIAL_PREFIXES = (
    "AI_OPENROUTER_",
    "AI_OPENAI_COMPATIBLE_",
    "AI_AZURE_OPENAI_COMPATIBLE_",
    "AI_ANTHROPIC_COMPATIBLE_",
    "AI_CUSTOM_HTTP_COMPATIBLE_",
)
NON_SECRET_NAME_PARTS = {
    "COUNT",
    "ENABLED",
    "FILE",
    "LENGTH",
    "LIMIT",
    "MAX",
    "MIN",
    "PATH",
    "SECONDS",
    "TIMEOUT",
    "TTL",
    "URL",
}
PROFILE_DEFAULTS = {
    "demo": {
        "AI_PROVIDER_DEFAULT": "local_ollama",
        "AI_EXTERNAL_PROVIDERS_ENABLED": "false",
        "AI_SOC_LLM_MODE": "auto",
        "AI_SOC_RAG_ENABLED": "true",
    },
    "local": {
        "AI_PROVIDER_DEFAULT": "local_ollama",
        "AI_EXTERNAL_PROVIDERS_ENABLED": "false",
        "AI_SOC_LLM_MODE": "auto",
        "AI_SOC_RAG_ENABLED": "true",
    },
}


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(1)


def parse_args() -> argparse.Namespace:
    parser = ArgumentParser(
        description="Create a safe local .env from .env.example.",
    )
    parser.add_argument(
        "--profile",
        required=True,
        choices=sorted(PROFILE_DEFAULTS),
        help="Environment profile to initialize.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without writing files.",
    )
    parser.add_argument(
        "--show-generated",
        action="store_true",
        help="Print newly generated secret values with a security warning.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Back up and replace an existing target .env.",
    )
    return parser.parse_args()


def target_path() -> Path:
    override = os.getenv("AI_SOC_ENV_TARGET_PATH")
    if not override:
        return DEFAULT_TARGET_PATH

    path = Path(override).expanduser()
    return path if path.is_absolute() else REPOSITORY_ROOT / path


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPOSITORY_ROOT))
    except ValueError:
        return str(path)


def split_line_ending(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n") or line.endswith("\r"):
        return line[:-1], line[-1]
    return line, ""


def normalized_value(raw_value: str) -> str:
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1].strip()
    return value


def is_placeholder(raw_value: str) -> bool:
    value = normalized_value(raw_value)
    lowered = value.lower()
    if not value:
        return True
    if lowered.startswith("<") and lowered.endswith(">"):
        return True
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def secret_kind(variable_name: str) -> str | None:
    parts = set(variable_name.upper().split("_"))
    if "PUBLIC" in parts or parts.intersection(NON_SECRET_NAME_PARTS):
        return None
    if "PASSWORD" in parts:
        return "password"
    if parts.intersection({"SECRET", "TOKEN", "KEY"}):
        return "secret"
    return None


def should_preserve_empty_optional_credential(
    variable_name: str,
    raw_value: str,
) -> bool:
    return (
        not normalized_value(raw_value)
        and variable_name.upper().endswith("_API_KEY")
        and variable_name.upper().startswith(OPTIONAL_EXTERNAL_CREDENTIAL_PREFIXES)
    )


def generated_value(kind: str) -> str:
    if kind == "password":
        return secrets.token_urlsafe(24)
    return secrets.token_urlsafe(48)


def render_environment(
    source_text: str,
    *,
    profile: str,
) -> tuple[str, dict[str, str], list[str]]:
    generated: dict[str, str] = {}
    defaults_applied: list[str] = []
    rendered_lines: list[str] = []
    profile_defaults = PROFILE_DEFAULTS[profile]

    for line in source_text.splitlines(keepends=True):
        body, line_ending = split_line_ending(line)
        match = ASSIGNMENT_PATTERN.match(body)
        if not match:
            rendered_lines.append(line)
            continue

        variable_name = match.group("name")
        raw_value = match.group("value")
        replacement: str | None = None
        kind = secret_kind(variable_name)

        if (
            kind
            and is_placeholder(raw_value)
            and not should_preserve_empty_optional_credential(
                variable_name,
                raw_value,
            )
        ):
            replacement = generated_value(kind)
            generated[variable_name] = replacement
        elif variable_name in profile_defaults and is_placeholder(raw_value):
            replacement = profile_defaults[variable_name]
            defaults_applied.append(variable_name)

        if replacement is None:
            rendered_lines.append(line)
        else:
            rendered_lines.append(
                f"{match.group('prefix')}{replacement}{line_ending}"
            )

    return "".join(rendered_lines), generated, defaults_applied


def next_backup_path(path: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = path.with_name(f"{path.name}.backup-{timestamp}")
    counter = 1
    while candidate.exists():
        candidate = path.with_name(
            f"{path.name}.backup-{timestamp}-{counter}"
        )
        counter += 1
    return candidate


def write_private_file(path: Path, content: str) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)

        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


def print_header(profile: str, target: Path) -> None:
    print("Sovereign AI SOC environment initializer")
    print()
    print(f"[INFO] Profile: {profile}")
    print(f"[INFO] Source: {display_path(SOURCE_PATH)}")
    print(f"[INFO] Target: {display_path(target)}")


def print_generation_summary(
    *,
    generated: dict[str, str],
    defaults_applied: list[str],
    show_generated: bool,
    written: bool,
) -> None:
    print("[OK] Preserved comments and existing example structure")
    print(f"[OK] Generated {len(generated)} secret values")
    if defaults_applied:
        print(
            "[OK] Applied profile defaults for: "
            + ", ".join(defaults_applied)
        )

    if generated and show_generated:
        print("[WARN] Generated secret values are shown below; store them securely")
        for variable_name, value in generated.items():
            print(f"[INFO] {variable_name}={value}")
    elif generated:
        if written:
            print("[INFO] Secrets were written to the target but not printed")
        else:
            print("[INFO] Generated secret values were not printed")


def main() -> int:
    args = parse_args()
    target = target_path()
    print_header(args.profile, target)

    if not SOURCE_PATH.is_file():
        print("[FAIL] .env.example is missing")
        return 1

    if target.exists() and not args.force:
        print("[OK] .env already exists; no changes made")
        return 0

    try:
        source_text = SOURCE_PATH.read_text(encoding="utf-8")
        rendered, generated, defaults_applied = render_environment(
            source_text,
            profile=args.profile,
        )
    except (OSError, UnicodeError) as exc:
        print(f"[FAIL] Could not read .env.example: {exc.__class__.__name__}")
        return 1

    backup_path = next_backup_path(target) if target.exists() else None
    if args.dry_run:
        if backup_path:
            print(
                "[INFO] Existing target would be backed up to "
                f"{display_path(backup_path)}"
            )
        print("[OK] Dry run completed; no files written")
        print_generation_summary(
            generated=generated,
            defaults_applied=defaults_applied,
            show_generated=args.show_generated,
            written=False,
        )
        print("[INFO] Next: run ./ai-soc doctor")
        return 0

    try:
        if not target.parent.is_dir():
            raise FileNotFoundError(target.parent)
        if backup_path:
            shutil.copy2(target, backup_path)
            os.chmod(backup_path, 0o600)
            print(f"[OK] Backup created: {display_path(backup_path)}")
        write_private_file(target, rendered)
    except OSError as exc:
        print(f"[FAIL] Could not write target environment: {exc.__class__.__name__}")
        return 1

    print("[OK] Generated local .env")
    print_generation_summary(
        generated=generated,
        defaults_applied=defaults_applied,
        show_generated=args.show_generated,
        written=True,
    )
    print("[INFO] Next: run ./ai-soc doctor")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
