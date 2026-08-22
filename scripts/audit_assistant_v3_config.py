#!/usr/bin/env python3
"""Audit Assistant V3 configuration without exposing environment values."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Literal


ROOT = Path(__file__).resolve().parents[1]
Classification = Literal[
    "REQUIRED_RUNTIME",
    "OPTIONAL_RUNTIME",
    "DEVELOPMENT_ONLY",
    "TEST_ONLY",
    "EXAMPLE_DOCUMENTATION_ONLY",
    "OBSOLETE",
    "UNKNOWN_REQUIRES_REVIEW",
]

V3_CONFIG_KEYS = {
    "AI_ASSISTANT_RESPONSE_ARCHITECTURE",
    "AI_INFERENCE_GATEWAY_SOCKET",
    "AI_SOC_ASSISTANT_CONVERSATION_TTL_SECONDS",
    "AI_SOC_ASSISTANT_MAX_CONVERSATIONS",
    "AI_SOC_ASSISTANT_MAX_CONVERSATIONS_PER_USER",
    "AI_SOC_ASSISTANT_MAX_CONTEXT_CHARS",
    "AI_SOC_ASSISTANT_MAX_MESSAGE_CHARS",
    "AI_SOC_ASSISTANT_MAX_SOURCES",
    "AI_SOC_ASSISTANT_REQUEST_TIMEOUT_SECONDS",
    "AI_SOC_ASSISTANT_SEMANTIC_LIMIT",
    "AI_SOC_ASSISTANT_SEMANTIC_TIMEOUT_SECONDS",
    "AI_SOC_ASSISTANT_V3_MAX_OUTPUT_TOKENS",
    "AI_SOC_ASSISTANT_V31_MAX_OUTPUT_TOKENS",
    "AI_SOC_LLM_MODE",
    "QDRANT_EMBEDDING_MODEL",
    "QDRANT_INCIDENT_INDEX_COLLECTION",
    "QDRANT_INCIDENT_INDEX_ENABLED",
    "QDRANT_INCIDENT_INDEX_QUERY_LIMIT",
    "QDRANT_INCIDENT_INDEX_SCORE_THRESHOLD",
    "QDRANT_INCIDENT_INDEX_UPSERT_BATCH_SIZE",
    "QDRANT_TIMEOUT_SECONDS",
    "QDRANT_URL",
}

DYNAMIC_OPTIONAL_PREFIXES = (
    "AI_ANTHROPIC_COMPATIBLE_",
    "AI_AZURE_OPENAI_COMPATIBLE_",
    "AI_CUSTOM_HTTP_COMPATIBLE_",
    "AI_OPENAI_COMPATIBLE_",
    "AI_OPENROUTER_",
)

RUNTIME_SUFFIXES = {
    ".js",
    ".json",
    ".py",
    ".service",
    ".sh",
    ".socket",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}


def _tracked_paths() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [ROOT / value for value in completed.stdout.splitlines() if value]


def _parse_env(path: Path) -> tuple[list[str], dict[str, list[str]]]:
    keys: list[str] = []
    values: dict[str, list[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not key or not key.replace("_", "a").isalnum() or not key[0].isalpha():
            continue
        keys.append(key)
        values.setdefault(key, []).append(value)
    return keys, values


def _consumer_texts() -> tuple[str, str, str]:
    runtime: list[str] = []
    tests: list[str] = []
    documentation: list[str] = []
    for path in _tracked_paths():
        if not path.is_file() or path.name in {".env", ".env.example"}:
            continue
        relative = path.relative_to(ROOT)
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if relative.parts[0] == "tests":
            tests.append(text)
        elif relative.parts[0] == "docs" or path.suffix == ".md":
            documentation.append(text)
        elif path.suffix in RUNTIME_SUFFIXES or path.name.startswith("Dockerfile"):
            runtime.append(text)
    return "\n".join(runtime), "\n".join(tests), "\n".join(documentation)


def _classify(
    key: str,
    *,
    runtime_text: str,
    test_text: str,
    documentation_text: str,
) -> Classification:
    if key in runtime_text or key.startswith(DYNAMIC_OPTIONAL_PREFIXES):
        return "OPTIONAL_RUNTIME"
    if key in test_text:
        return "TEST_ONLY"
    if key in documentation_text:
        return "EXAMPLE_DOCUMENTATION_ONLY"
    return "UNKNOWN_REQUIRES_REVIEW"


def _gitignored(path: Path) -> bool:
    return subprocess.run(
        ["git", "check-ignore", "-q", str(path.relative_to(ROOT))],
        cwd=ROOT,
        check=False,
    ).returncode == 0


def _staged_paths() -> set[str]:
    completed = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return set(completed.stdout.splitlines())


def audit(env_path: Path, example_path: Path) -> dict[str, object]:
    env_keys, env_values = _parse_env(env_path)
    example_keys, example_values = _parse_env(example_path)
    all_keys = sorted(set(env_keys) | set(example_keys))
    runtime_text, test_text, documentation_text = _consumer_texts()
    classifications = {
        key: _classify(
            key,
            runtime_text=runtime_text,
            test_text=test_text,
            documentation_text=documentation_text,
        )
        for key in all_keys
    }
    classification_counts = Counter(classifications.values())
    unknown = sorted(
        key
        for key, classification in classifications.items()
        if classification == "UNKNOWN_REQUIRES_REVIEW"
    )
    duplicate_env = sorted(key for key, values in env_values.items() if len(values) > 1)
    duplicate_example = sorted(
        key for key, values in example_values.items() if len(values) > 1
    )
    env_relative = str(env_path.relative_to(ROOT))
    staged = _staged_paths()
    return {
        "env_key_count": len(env_keys),
        "env_unique_key_count": len(set(env_keys)),
        "env_example_key_count": len(example_keys),
        "env_example_unique_key_count": len(set(example_keys)),
        "classification_counts": dict(sorted(classification_counts.items())),
        "unknown_unclassified_keys": unknown,
        "duplicate_keys_env": duplicate_env,
        "duplicate_keys_env_value_match": {
            key: len(set(env_values[key])) == 1 for key in duplicate_env
        },
        "duplicate_keys_env_example": duplicate_example,
        "required_runtime_missing": sorted(V3_CONFIG_KEYS - set(example_keys)),
        "v3_env_uses_safe_code_defaults": sorted(V3_CONFIG_KEYS - set(env_keys)),
        "confirmed_obsolete_keys_env": [],
        "env_gitignored": _gitignored(env_path),
        "env_staged": env_relative in staged,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", type=Path, default=ROOT / ".env")
    parser.add_argument("--env-example", type=Path, default=ROOT / ".env.example")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    report = audit(args.env.resolve(), args.env_example.resolve())
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for key, value in report.items():
            print(f"{key}: {value}")
    failures = (
        report["unknown_unclassified_keys"]
        or report["duplicate_keys_env"]
        or report["duplicate_keys_env_example"]
        or report["required_runtime_missing"]
        or report["confirmed_obsolete_keys_env"]
        or not report["env_gitignored"]
        or report["env_staged"]
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
