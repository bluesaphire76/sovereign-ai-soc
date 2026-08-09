from __future__ import annotations

import argparse
import json
from typing import Any

from database import SessionLocal
from services.assistant.v3.semantic_index import (
    INCIDENT_INDEX_DECISION_BOUNDARY,
    IncidentSemanticIndex,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Manage the dedicated Qdrant incident candidate index."
    )
    parser.add_argument("action", choices=("rebuild", "status", "upsert", "refresh", "delete"))
    parser.add_argument("--incident-id", type=int)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    if args.action in {"upsert", "refresh", "delete"} and not args.incident_id:
        parser.error(f"{args.action} requires --incident-id")
    if args.incident_id is not None and args.incident_id <= 0:
        parser.error("--incident-id must be positive")
    return args


def run(
    *,
    action: str,
    incident_id: int | None = None,
    limit: int | None = None,
    db_factory=SessionLocal,
    index_factory=IncidentSemanticIndex,
) -> dict[str, Any]:
    index = index_factory()
    if action == "delete":
        result = index.delete(int(incident_id or 0)).to_dict()
    else:
        db = db_factory()
        try:
            if action == "status":
                result = index.status(db, limit=limit).to_dict()
            elif action == "rebuild":
                result = index.rebuild(db, limit=limit).to_dict()
            elif action in {"upsert", "refresh"}:
                result = index.upsert_incident(
                    db,
                    int(incident_id or 0),
                    require_ready_embedding=False,
                ).to_dict()
            else:
                raise ValueError("unsupported incident index action")
        finally:
            db.close()
    return {
        "action": action,
        **result,
        "decision_boundary": INCIDENT_INDEX_DECISION_BOUNDARY,
    }


def main() -> None:
    args = parse_args()
    result = run(
        action=args.action,
        incident_id=args.incident_id,
        limit=(max(1, min(args.limit, 100_000)) if args.limit is not None else None),
    )
    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print(
        "Incident semantic index {action}: collection={collection}, status={status}, "
        "indexed={indexed}, missing={missing}, stale={stale}, duplicates={duplicates}.".format(
            action=result["action"],
            collection=result.get("collection"),
            status=result.get("status"),
            indexed=result.get("indexed_count", 0),
            missing=result.get("missing_ids", 0),
            stale=result.get("stale_fingerprints", 0),
            duplicates=result.get("duplicate_ids", 0),
        )
    )
    print(f"Decision boundary: {INCIDENT_INDEX_DECISION_BOUNDARY}")


if __name__ == "__main__":
    main()
