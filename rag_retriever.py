from qdrant_client import QdrantClient
from sentence_transformers import SentenceTransformer

COLLECTION_NAME = "security_kb"
MODEL_NAME = "sentence-transformers/multi-qa-MiniLM-L6-cos-v1"

client = QdrantClient(host="localhost", port=6333)
model = SentenceTransformer(MODEL_NAME)


def retrieve_security_context(query, limit=3):
    vector = model.encode(query).tolist()

    results = client.query_points(
        collection_name=COLLECTION_NAME,
        query=vector,
        limit=limit,
    )

    contexts = []

    for point in results.points:
        payload = point.payload or {}
        contexts.append(
            {
                "source": payload.get("source"),
                "text": payload.get("text"),
                "score": point.score,
            }
        )

    return contexts

