import os
import time
from datetime import timezone

import ollama
import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from sqlalchemy import text as sql_text

from database import engine, SessionLocal
from models import Incident, WorkerHeartbeat, utc_now

urllib3.disable_warnings()
load_dotenv()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))


def now_iso():
    return utc_now().isoformat()


def component_result(component, status, message, started_at, details=None):
    latency_ms = round((time.perf_counter() - started_at) * 1000, 2)

    return {
        "component": component,
        "status": status,
        "message": message,
        "latency_ms": latency_ms,
        "checked_at": now_iso(),
        "details": details or {},
    }


def check_api():
    started_at = time.perf_counter()

    return component_result(
        component="api",
        status="OK",
        message="FastAPI application is responding.",
        started_at=started_at,
        details={"service": "sovereign-ai-soc-api"},
    )


def check_postgres():
    started_at = time.perf_counter()

    try:
        with engine.connect() as connection:
            value = connection.execute(sql_text("select 1")).scalar()

        return component_result(
            component="postgres",
            status="OK",
            message="PostgreSQL connection successful.",
            started_at=started_at,
            details={"select_1": value},
        )

    except Exception as exc:
        return component_result(
            component="postgres",
            status="ERROR",
            message=str(exc),
            started_at=started_at,
        )


def check_ollama():
    started_at = time.perf_counter()

    try:
        response = ollama.list()
        models = []

        for item in response.get("models", []):
            name = item.get("name") or item.get("model")
            if name:
                models.append(name)

        status = "OK" if models else "WARN"
        message = "Ollama is reachable." if models else "Ollama reachable, but no models returned."

        return component_result(
            component="ollama",
            status=status,
            message=message,
            started_at=started_at,
            details={
                "configured_model": OLLAMA_MODEL,
                "available_models": models,
            },
        )

    except Exception as exc:
        return component_result(
            component="ollama",
            status="ERROR",
            message=str(exc),
            started_at=started_at,
            details={"configured_model": OLLAMA_MODEL},
        )


def check_wazuh_indexer():
    started_at = time.perf_counter()

    if not WAZUH_INDEXER_URL:
        return component_result(
            component="wazuh_indexer",
            status="WARN",
            message="WAZUH_INDEXER_URL is not configured.",
            started_at=started_at,
        )

    try:
        response = requests.get(
            f"{WAZUH_INDEXER_URL}/_cluster/health",
            auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASSWORD),
            verify=False,
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()

        cluster_status = str(data.get("status", "unknown")).lower()

        status = "OK"
        if cluster_status == "yellow":
            status = "WARN"
        elif cluster_status not in {"green", "yellow"}:
            status = "ERROR"

        return component_result(
            component="wazuh_indexer",
            status=status,
            message=f"Wazuh indexer cluster status: {cluster_status}",
            started_at=started_at,
            details={
                "cluster_name": data.get("cluster_name"),
                "cluster_status": cluster_status,
                "number_of_nodes": data.get("number_of_nodes"),
                "active_primary_shards": data.get("active_primary_shards"),
                "active_shards": data.get("active_shards"),
            },
        )

    except Exception as exc:
        return component_result(
            component="wazuh_indexer",
            status="ERROR",
            message=str(exc),
            started_at=started_at,
            details={"url": WAZUH_INDEXER_URL},
        )


def check_qdrant():
    started_at = time.perf_counter()

    try:
        response = requests.get(
            f"{QDRANT_URL.rstrip('/')}/collections",
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()

        collections = data.get("result", {}).get("collections", [])

        return component_result(
            component="qdrant",
            status="OK",
            message="Qdrant is reachable.",
            started_at=started_at,
            details={
                "url": QDRANT_URL,
                "collections": [item.get("name") for item in collections],
                "collection_count": len(collections),
            },
        )

    except Exception as exc:
        return component_result(
            component="qdrant",
            status="ERROR",
            message=str(exc),
            started_at=started_at,
            details={"url": QDRANT_URL},
        )


def check_worker():
    started_at = time.perf_counter()
    db = SessionLocal()

    try:
        heartbeat = (
            db.query(WorkerHeartbeat)
            .filter(WorkerHeartbeat.component == "ai_soc_worker")
            .first()
        )

        if not heartbeat:
            return component_result(
                component="ai_soc_worker",
                status="WARN",
                message="No worker heartbeat found yet.",
                started_at=started_at,
            )

        last_seen = heartbeat.last_seen_at

        if last_seen and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        age_seconds = None
        if last_seen:
            age_seconds = round((utc_now() - last_seen).total_seconds(), 2)

        stale_after = max(POLL_INTERVAL_SECONDS * 3, 120)

        status = heartbeat.status or "UNKNOWN"
        normalized_status = "OK"

        if status == "ERROR":
            normalized_status = "ERROR"
        elif age_seconds is None or age_seconds > stale_after:
            normalized_status = "WARN"
        elif status in {"STARTING", "STOPPED", "UNKNOWN"}:
            normalized_status = "WARN"

        message = f"Worker status: {status}"

        if age_seconds is not None:
            message += f", last seen {age_seconds}s ago"

        return component_result(
            component="ai_soc_worker",
            status=normalized_status,
            message=message,
            started_at=started_at,
            details={
                "worker_status": status,
                "last_seen_at": heartbeat.last_seen_at.isoformat()
                if heartbeat.last_seen_at
                else None,
                "last_success_at": heartbeat.last_success_at.isoformat()
                if heartbeat.last_success_at
                else None,
                "last_error_at": heartbeat.last_error_at.isoformat()
                if heartbeat.last_error_at
                else None,
                "last_error": heartbeat.last_error,
                "details": heartbeat.details,
                "age_seconds": age_seconds,
                "stale_after_seconds": stale_after,
            },
        )

    except Exception as exc:
        return component_result(
            component="ai_soc_worker",
            status="ERROR",
            message=str(exc),
            started_at=started_at,
        )

    finally:
        db.close()


def latest_incident_snapshot():
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .order_by(Incident.timestamp.desc().nullslast(), Incident.id.desc())
            .first()
        )

        if not incident:
            return None

        return {
            "id": incident.id,
            "timestamp": incident.timestamp,
            "agent": incident.agent,
            "rule": incident.rule,
            "status": incident.status,
            "risk_score": incident.risk_score,
            "correlation_score": incident.correlation_score,
        }

    finally:
        db.close()


def overall_status(components):
    statuses = {item["status"] for item in components}

    if "ERROR" in statuses:
        return "ERROR"

    if "WARN" in statuses:
        return "WARN"

    return "OK"


def get_platform_health():
    components = [
        check_api(),
        check_postgres(),
        check_ollama(),
        check_wazuh_indexer(),
        check_qdrant(),
        check_worker(),
    ]

    return {
        "status": overall_status(components),
        "checked_at": now_iso(),
        "components": components,
        "latest_incident": latest_incident_snapshot(),
    }
