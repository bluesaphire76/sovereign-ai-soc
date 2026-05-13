from pathlib import Path
from uuid import uuid4

from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sentence_transformers import SentenceTransformer
from rich import print

COLLECTION_NAME = "security_kb"
MODEL_NAME = "sentence-transformers/multi-qa-MiniLM-L6-cos-v1"

client = QdrantClient(host="localhost", port=6333)
model = SentenceTransformer(MODEL_NAME)


def chunk_text(text, max_chars=900):
    chunks = []
    current = []

    for line in text.splitlines():
        if sum(len(x) for x in current) + len(line) > max_chars:
            chunks.append("\n".join(current))
            current = []

        current.append(line)

    if current:
        chunks.append("\n".join(current))

    return [chunk.strip() for chunk in chunks if chunk.strip()]


def recreate_collection():
    existing = [c.name for c in client.get_collections().collections]

    if COLLECTION_NAME in existing:
        client.delete_collection(COLLECTION_NAME)

    client.create_collection(
        collection_name=COLLECTION_NAME,
        vectors_config=VectorParams(
            size=384,
            distance=Distance.COSINE,
        ),
    )


def index_documents():
    points = []

    for file_path in Path("knowledge_base").glob("*.md"):
        text = file_path.read_text(encoding="utf-8")
        chunks = chunk_text(text)

        for chunk in chunks:
            vector = model.encode(chunk).tolist()

            points.append(
                PointStruct(
                    id=str(uuid4()),
                    vector=vector,
                    payload={
                        "source": str(file_path),
                        "text": chunk,
                    },
                )
            )

    client.upsert(
        collection_name=COLLECTION_NAME,
        points=points,
    )

    print(f"[green]Indexed {len(points)} chunks into Qdrant.[/green]")


if __name__ == "__main__":
    recreate_collection()
    index_documents()

