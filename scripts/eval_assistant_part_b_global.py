#!/usr/bin/env python3
"""Run the Part B global Assistant acceptance corpus against the local API."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from auth_utils import create_access_token
from database import SessionLocal
from models import AppUser


PROMPTS = (
    (
        "B1",
        "incident_count",
        "Quanti incidenti HIGH abbiamo avuto questa settimana?",
        "count-high-week",
    ),
    (
        "B2",
        "incident_count",
        "Quanti incidenti NEW ci sono stati nelle ultime 24 ore?",
        "count-new-day",
    ),
    (
        "B3",
        "incident_top_agents",
        "Quali host hanno generato più incidenti negli ultimi 7 giorni?",
        "top-hosts",
    ),
    (
        "B4",
        "incident_top_detection_rules",
        "Quali regole di detection hanno generato più incidenti negli ultimi 30 giorni?",
        "top-rules",
    ),
    (
        "B5",
        None,
        "Quali tecniche MITRE sono più frequenti negli incidenti dell'ultimo mese?",
        "mitre-month",
    ),
    (
        "B6",
        "incident_list",
        "Mostrami gli incidenti di darkstar-windows degli ultimi 7 giorni.",
        "incident-followup",
    ),
    (
        "B7",
        "incident_count_previous_result",
        "Di questi, quanti risultano ancora NEW?",
        "incident-followup",
    ),
    (
        "B8",
        "incident_compare_periods",
        "Confronta il numero di incidenti degli ultimi 7 giorni con i 7 giorni precedenti.",
        "period-comparison",
    ),
    (
        "B9",
        "recorded_related_incidents",
        "Quali incidenti risultano correlati al 5333?",
        "recorded-relations",
    ),
    (
        "B10",
        "semantic_similar_incidents",
        "Quali incidenti sono semanticamente simili al 5333?",
        "semantic-followup",
    ),
    (
        "B11",
        "semantic_similar_incidents",
        "I risultati simili al 5333 fanno parte dello stesso attacco?",
        "semantic-followup",
    ),
    (
        "B12",
        "case_sla_breached_list",
        "Quali casi hanno superato lo SLA?",
        "case-sla",
    ),
)


def _token() -> str:
    db = SessionLocal()
    try:
        user = (
            db.query(AppUser)
            .filter(
                AppUser.role.in_(["ADMIN", "ANALYST"]),
                AppUser.is_active.is_(True),
            )
            .order_by(AppUser.id)
            .first()
        )
        if user is None:
            raise RuntimeError("no active local analyst account is available")
        return create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role,
        )["access_token"]
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8008")
    parser.add_argument(
        "--output",
        default="/tmp/ai-soc-part-b-global-final.json",
    )
    parser.add_argument("--timeout", type=float, default=125.0)
    parser.add_argument("--delay", type=float, default=1.0)
    args = parser.parse_args()

    token = _token()
    headers = {"Authorization": f"Bearer {token}"}
    conversation_ids: dict[str, str] = {}
    results = []
    with httpx.Client(
        base_url=args.api,
        headers=headers,
        timeout=args.timeout,
    ) as client:
        capabilities = client.get("/assistant/capabilities")
        capabilities.raise_for_status()
        capability_payload = capabilities.json()
        if capability_payload.get("runtime_state") != "ready":
            raise RuntimeError("assistant runtime is not ready")
        for prompt_id, expected_definition, prompt, conversation_key in PROMPTS:
            conversation_id = conversation_ids.setdefault(
                conversation_key,
                f"part-b-{conversation_key}-{uuid4().hex[:12]}",
            )
            started = time.monotonic()
            response = client.post(
                "/assistant/query",
                json={
                    "message": prompt,
                    "scope": "global",
                    "incident_id": None,
                    "case_id": None,
                    "requested_mode": "auto",
                    "include_semantic_memory": True,
                    "conversation_id": conversation_id,
                },
            )
            wall_latency_ms = max(0, int((time.monotonic() - started) * 1000))
            response.raise_for_status()
            payload = response.json()
            metadata = payload["metadata"]
            checks = {
                "architecture_v32": metadata["response_architecture"] == "v3_2",
                "definition_matches": (
                    metadata["analytics_definition_id"] == expected_definition
                ),
                "clarification_matches": (
                    metadata["fallback_reason"] == "global_time_window_ambiguous"
                    and metadata["provider_generation_count"] == 0
                    if prompt_id == "B5"
                    else True
                ),
                "generation_max_one": metadata["provider_generation_count"] <= 1,
                "no_retry": metadata["automatic_retries"] == 0,
                "no_model_switch": metadata["model_switches"] == 0,
                "complete_answer": bool(payload.get("answer", "").strip()),
            }
            result = {
                "prompt_id": prompt_id,
                "prompt": prompt,
                "expected_definition": expected_definition,
                "wall_latency_ms": wall_latency_ms,
                "checks": checks,
                "response": payload,
            }
            results.append(result)
            print(
                prompt_id,
                metadata["analytics_definition_id"],
                payload["generation_kind"],
                metadata["semantic_proof_status"],
                metadata["fallback_reason"],
                f"{wall_latency_ms}ms",
                flush=True,
            )
            if args.delay > 0:
                time.sleep(args.delay)

    summary = {
        "total": len(results),
        "publication_eligible": sum(
            item["prompt_id"] != "B5" for item in results
        ),
        "model_responses": sum(
            item["response"]["generation_kind"] == "model" for item in results
        ),
        "deterministic_fallbacks": sum(
            item["response"]["generation_kind"] == "deterministic_fallback"
            for item in results
        ),
        "proof_passed": sum(
            item["response"]["metadata"]["semantic_proof_status"] == "passed"
            for item in results
        ),
        "proof_failed": sum(
            item["response"]["metadata"]["semantic_proof_status"] == "failed"
            for item in results
        ),
        "queue_deadline_exceeded": sum(
            item["response"]["metadata"]["fallback_reason"]
            == "queue_deadline_exceeded"
            for item in results
        ),
        "fallback_reasons": {
            reason: sum(
                item["response"]["metadata"]["fallback_reason"] == reason
                for item in results
            )
            for reason in sorted(
                {
                    item["response"]["metadata"]["fallback_reason"]
                    for item in results
                    if item["response"]["metadata"]["fallback_reason"] is not None
                }
            )
        },
        "all_invariants_passed": all(
            all(item["checks"].values()) for item in results
        ),
        "maximum_provider_generations": max(
            item["response"]["metadata"]["provider_generation_count"]
            for item in results
        ),
        "maximum_automatic_retries": max(
            item["response"]["metadata"]["automatic_retries"]
            for item in results
        ),
        "maximum_model_switches": max(
            item["response"]["metadata"]["model_switches"] for item in results
        ),
        "total_wall_latency_ms": sum(item["wall_latency_ms"] for item in results),
    }
    summary["eligible_model_publication_rate"] = round(
        summary["model_responses"] / summary["publication_eligible"],
        4,
    )
    output = {
        "capabilities": capability_payload,
        "summary": summary,
        "results": results,
    }
    Path(args.output).write_text(
        json.dumps(output, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2), flush=True)
    print(f"output={args.output}", flush=True)
    return 0 if summary["all_invariants_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
