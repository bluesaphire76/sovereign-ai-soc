#!/usr/bin/env python3
"""Explicitly provision offline semantic NLU assets for the API runtime."""

from __future__ import annotations

import argparse
from pathlib import Path

import stanza
from huggingface_hub import snapshot_download


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("/opt/ai-soc/models/semantic-nlu"),
    )
    parser.add_argument(
        "--embedding-revision",
        help="Optional immutable Hugging Face revision for release provisioning.",
    )
    parser.add_argument(
        "--joint-revision",
        help="Optional immutable revision for the joint semantic-plan encoder.",
    )
    args = parser.parse_args()

    stanza_dir = args.root / "stanza"
    embedding_dir = args.root / "multilingual-e5-small"
    joint_dir = args.root / "paraphrase-multilingual-mpnet-base-v2"
    stanza_dir.mkdir(parents=True, exist_ok=True)
    embedding_dir.mkdir(parents=True, exist_ok=True)
    joint_dir.mkdir(parents=True, exist_ok=True)

    stanza.download(
        "multilingual",
        model_dir=str(stanza_dir),
        processors="langid",
        verbose=False,
    )
    packages = {
        "tokenize": "default",
        "pos": "combined_nocharlm",
        "lemma": "default",
        "depparse": "combined_nocharlm",
    }
    for language in ("en", "it"):
        stanza.download(
            language,
            model_dir=str(stanza_dir),
            processors="tokenize,pos,lemma,depparse",
            package=packages,
            verbose=False,
        )

    download_options: dict[str, object] = {
        "repo_id": "intfloat/multilingual-e5-small",
        "local_dir": str(embedding_dir),
    }
    if args.embedding_revision:
        download_options["revision"] = args.embedding_revision
    snapshot_download(**download_options)
    joint_options: dict[str, object] = {
        "repo_id": "sentence-transformers/paraphrase-multilingual-mpnet-base-v2",
        "local_dir": str(joint_dir),
    }
    if args.joint_revision:
        joint_options["revision"] = args.joint_revision
    snapshot_download(**joint_options)
    print(f"Stanza models: {stanza_dir}")
    print(f"Embedding model: {embedding_dir}")
    print(f"Joint semantic model: {joint_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
