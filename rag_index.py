from __future__ import annotations

import argparse

from qdrant_knowledge import QdrantKnowledgeBase


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Index local SOC knowledge base documents into Qdrant.")
    parser.add_argument(
        "--path",
        default=None,
        help="Directory containing Markdown knowledge base documents. Defaults to QDRANT_KNOWLEDGE_BASE_PATH.",
    )
    parser.add_argument(
        "--recreate",
        action="store_true",
        help="Delete and recreate the configured collection before indexing.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = QdrantKnowledgeBase().index_documents(path=args.path, recreate=args.recreate)
    print(
        "Indexed {indexed_points} chunk(s) from {documents} document(s) into {collection}; "
        "excluded {excluded_documents} document(s).".format(
            **result
        )
    )


if __name__ == "__main__":
    main()
