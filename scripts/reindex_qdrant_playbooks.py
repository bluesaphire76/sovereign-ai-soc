from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from qdrant_knowledge import (
    PLAYBOOK_REQUIRED_METADATA_FIELDS,
    QdrantKnowledgeBase,
    build_knowledge_base_index_plan,
    config_from_env,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dry-run or apply Qdrant playbook metadata-aware indexing."
    )
    parser.add_argument(
        "--path",
        default=None,
        help="Knowledge base path. Defaults to QDRANT_KNOWLEDGE_BASE_PATH.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write playbook chunks to Qdrant after deleting only existing playbook points.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview playbook chunks without writing to Qdrant. This is the default.",
    )
    return parser.parse_args()


def _public_payload(payload: dict[str, Any]) -> dict[str, Any]:
    public = {key: value for key, value in payload.items() if key != "text"}
    public["text_preview"] = payload.get("content_preview")
    return public


def build_report(*, path: str | Path | None = None, kb: QdrantKnowledgeBase | None = None) -> dict[str, Any]:
    config = config_from_env()
    knowledge_base = kb or QdrantKnowledgeBase(config)
    base_path = Path(path) if path is not None else config.knowledge_base_path
    plan = build_knowledge_base_index_plan(
        base_path,
        chunk_max_chars=config.chunk_max_chars,
        excluded_dirs=config.excluded_dirs,
        excluded_filenames=config.excluded_filenames,
        playbooks_only=True,
    )
    missing_paths = {item["file_path"] for item in plan.missing_metadata}
    playbook_paths = [str(path) for path in plan.documents]
    valid_front_matter_paths = {
        chunk.payload["file_path"]
        for chunk in plan.chunks
        if chunk.payload.get("front_matter_present")
        and chunk.payload.get("file_path") not in missing_paths
    }

    collection_info = knowledge_base.collection_info()
    return {
        "mode": "dry-run",
        "collection": config.collection_name,
        "collection_status": collection_info.get("status"),
        "collection_exists": collection_info.get("exists"),
        "knowledge_base_path": str(base_path),
        "playbook_files_discovered": len(playbook_paths),
        "playbook_files": playbook_paths,
        "files_with_valid_front_matter": len(valid_front_matter_paths),
        "files_missing_required_metadata": len(plan.missing_metadata),
        "required_metadata_fields": list(PLAYBOOK_REQUIRED_METADATA_FIELDS),
        "sections_or_chunks_to_index": len(plan.chunks),
        "fallback_chunked_files": [str(path) for path in plan.fallback_chunked_files],
        "excluded_files": [str(path) for path in plan.excluded_files],
        "skipped_files": plan.skipped_files,
        "missing_metadata": plan.missing_metadata,
        "sample_payloads": [_public_payload(chunk.payload) for chunk in plan.chunks[:3]],
        "write_behavior": (
            "Dry-run does not write to Qdrant. Apply deletes only existing playbook "
            "knowledge-base points and upserts playbook section chunks; historical, "
            "case and detection-control memory source types are untouched."
        ),
    }


def run(*, path: str | Path | None = None, apply: bool = False) -> dict[str, Any]:
    kb = QdrantKnowledgeBase()
    report = build_report(path=path, kb=kb)
    if not apply:
        return report

    result = kb.index_playbook_documents(path=path, replace_existing=True)
    return {
        **report,
        "mode": "apply",
        "apply_result": result,
    }


def main() -> None:
    args = parse_args()
    apply = bool(args.apply)
    result = run(path=args.path, apply=apply)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
