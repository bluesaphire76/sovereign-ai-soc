#!/usr/bin/env python3
"""Train the bounded Global Assistant AST-candidate ranker head."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
from safetensors.numpy import save_file
from sentence_transformers import SentenceTransformer
from sklearn.linear_model import LogisticRegression


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from eval_global_assistant_product_recovery import _split, build_corpus
from global_semantic_plan_development_set import (
    development_examples,
    source_development_examples,
)


DEFAULT_MODEL = Path(
    "/opt/ai-soc/models/semantic-nlu/paraphrase-multilingual-mpnet-base-v2"
)
DEFAULT_OUTPUT = (
    REPOSITORY_ROOT
    / "services/assistant/analytics/models/joint_plan_ranker.safetensors"
)


def _source_plan(definition_id: str | None) -> str:
    if definition_id == "mitre_reference_lookup":
        return "REFERENCE"
    if definition_id == "recorded_related_incidents":
        return "RELATIONSHIP"
    if definition_id == "semantic_similar_incidents":
        return "SIMILARITY"
    if definition_id is None or definition_id == "__unsupported__":
        return "UNSUPPORTED"
    return "OPERATIONAL_ANALYTICS"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    development = [item for item in build_corpus() if _split(item) == "development"]
    independent = development_examples()
    prompts = [item.prompt for item in development] + [item[0] for item in independent]
    labels = [
        item.expected_definition or "__unsupported__" for item in development
    ] + [item[1] for item in independent]
    encoder = SentenceTransformer(
        str(args.model),
        local_files_only=True,
        device="cpu",
    )
    vectors = encoder.encode(
        prompts,
        normalize_embeddings=True,
        batch_size=32,
        show_progress_bar=True,
    )
    classifier = LogisticRegression(
        C=12.0,
        max_iter=2500,
        class_weight="balanced",
        random_state=7,
    ).fit(vectors, labels)
    source_independent = source_development_examples()
    source_prompts = [item.prompt for item in development] + [
        item[0] for item in independent
    ] + [item[0] for item in source_independent]
    source_labels = [
        _source_plan(item.expected_definition) for item in development
    ] + [
        _source_plan(item[1]) for item in independent
    ] + [item[1] for item in source_independent]
    source_vectors = encoder.encode(
        source_prompts,
        normalize_embeddings=True,
        batch_size=32,
        show_progress_bar=True,
    )
    source_classifier = LogisticRegression(
        C=8.0,
        max_iter=2500,
        class_weight="balanced",
        random_state=7,
    ).fit(source_vectors, source_labels)
    digest = hashlib.sha256()
    for prompt, label in sorted(zip(prompts, labels)):
        digest.update(f"{label}\0{prompt}\n".encode())
    source_digest = hashlib.sha256()
    for prompt, label in sorted(zip(source_prompts, source_labels)):
        source_digest.update(f"{label}\0{prompt}\n".encode())

    args.output.parent.mkdir(parents=True, exist_ok=True)
    metadata = {
        "classes": json.dumps(classifier.classes_.tolist()),
        "encoder": args.model.name,
        "training_split": "development",
        "training_count": str(len(development)),
        "independent_structure_first_count": str(len(independent)),
        "training_sha256": digest.hexdigest(),
        "regularization_c": "12.0",
        "source_classes": json.dumps(source_classifier.classes_.tolist()),
        "source_training_count": str(len(source_prompts)),
        "source_independent_structure_first_count": str(len(source_independent)),
        "source_training_sha256": source_digest.hexdigest(),
        "source_regularization_c": "8.0",
    }
    save_file(
        {
            "weight": np.asarray(classifier.coef_, dtype=np.float32),
            "bias": np.asarray(classifier.intercept_, dtype=np.float32),
            "source_weight": np.asarray(source_classifier.coef_, dtype=np.float32),
            "source_bias": np.asarray(source_classifier.intercept_, dtype=np.float32),
        },
        str(args.output),
        metadata=metadata,
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
