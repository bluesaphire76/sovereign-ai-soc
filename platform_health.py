import os
import subprocess
import time
from datetime import datetime, timedelta, timezone

import ollama
import requests
import urllib3
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from sqlalchemy import text as sql_text

from database import engine, SessionLocal
from models import Incident, WorkerHeartbeat, utc_now
from wazuh_ingest_state import get_watermark_snapshot

urllib3.disable_warnings()
load_dotenv()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
WORKER_STALE_AFTER_SECONDS = int(os.getenv("WORKER_STALE_AFTER_SECONDS", "300"))
EVENT_SOURCE_WINDOW_MINUTES = int(os.getenv("EVENT_SOURCE_WINDOW_MINUTES", "15"))
EVENT_BACKLOG_WARN_THRESHOLD = int(os.getenv("EVENT_BACKLOG_WARN_THRESHOLD", "50"))
EVENT_BACKLOG_ERROR_THRESHOLD = int(os.getenv("EVENT_BACKLOG_ERROR_THRESHOLD", "500"))
LATEST_INCIDENT_WARN_AFTER_SECONDS = int(os.getenv("LATEST_INCIDENT_WARN_AFTER_SECONDS", "900"))
LATEST_INCIDENT_ERROR_AFTER_SECONDS = int(os.getenv("LATEST_INCIDENT_ERROR_AFTER_SECONDS", "3600"))


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
            message="Component health check failed.",
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
            message="Component health check failed.",
            started_at=started_at,
            details={"configured_model": OLLAMA_MODEL},
        )


def parse_wazuh_dt(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def wazuh_search(payload, timeout=8):
    if not WAZUH_INDEXER_URL:
        raise RuntimeError("WAZUH_INDEXER_URL is not configured.")

    response = requests.get(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASSWORD),
        json=payload,
        verify=False,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def check_event_processing_queue():
    started_at = time.perf_counter()

    try:
        snapshot = get_watermark_snapshot()
        last_timestamp = snapshot.get("last_timestamp")

        if not last_timestamp:
            return component_result(
                component="event_processing_queue",
                status="WARN",
                message="Event backlog cannot be calculated because no ingest watermark timestamp is available.",
                started_at=started_at,
                details={
                    "pending_events": None,
                    "watermark_last_timestamp": last_timestamp,
                },
            )

        payload = {
            "size": 0,
            "track_total_hits": True,
            "query": {
                "range": {
                    "@timestamp": {
                        "gt": last_timestamp,
                    }
                }
            },
        }

        data = wazuh_search(payload)
        total = data.get("hits", {}).get("total", 0)

        if isinstance(total, dict):
            pending_events = int(total.get("value", 0) or 0)
        else:
            pending_events = int(total or 0)

        status = "OK"
        if pending_events > EVENT_BACKLOG_ERROR_THRESHOLD:
            status = "ERROR"
        elif pending_events > EVENT_BACKLOG_WARN_THRESHOLD:
            status = "WARN"

        return component_result(
            component="event_processing_queue",
            status=status,
            message=f"{pending_events} Wazuh event(s) are newer than the current ingest watermark.",
            started_at=started_at,
            details={
                "pending_events": pending_events,
                "watermark_last_timestamp": last_timestamp,
                "warn_threshold": EVENT_BACKLOG_WARN_THRESHOLD,
                "error_threshold": EVENT_BACKLOG_ERROR_THRESHOLD,
            },
        )

    except Exception as exc:
        return component_result(
            component="event_processing_queue",
            status="ERROR",
            message="Event backlog check failed.",
            started_at=started_at,
            details={"error": str(exc)},
        )


def check_active_event_sources():
    started_at = time.perf_counter()

    try:
        since = (
            utc_now() - timedelta(minutes=EVENT_SOURCE_WINDOW_MINUTES)
        ).isoformat().replace("+00:00", "Z")

        payload = {
            "size": 500,
            "_source": [
                "@timestamp",
                "agent.name",
            ],
            "sort": [
                {"@timestamp": {"order": "desc"}},
            ],
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": since,
                    }
                }
            },
        }

        data = wazuh_search(payload)
        hits = data.get("hits", {}).get("hits", [])

        sources = sorted({
            hit.get("_source", {}).get("agent", {}).get("name")
            for hit in hits
            if hit.get("_source", {}).get("agent", {}).get("name")
        })

        status = "OK" if sources else "WARN"
        message = (
            f"{len(sources)} active source(s) sent events in the last {EVENT_SOURCE_WINDOW_MINUTES} minutes."
            if sources
            else f"No active event sources detected in the last {EVENT_SOURCE_WINDOW_MINUTES} minutes."
        )

        return component_result(
            component="active_event_sources",
            status=status,
            message=message,
            started_at=started_at,
            details={
                "active_sources": len(sources),
                "window_minutes": EVENT_SOURCE_WINDOW_MINUTES,
                "sources": sources,
                "sampled_events": len(hits),
            },
        )

    except Exception as exc:
        return component_result(
            component="active_event_sources",
            status="ERROR",
            message="Active event source check failed.",
            started_at=started_at,
            details={"error": str(exc)},
        )


def check_cloudflare_tunnel():
    started_at = time.perf_counter()

    try:
        systemd = subprocess.run(
            ["systemctl", "is-active", "cloudflared"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )

        state = systemd.stdout.strip() or systemd.stderr.strip()

        if systemd.returncode == 0 and state == "active":
            return component_result(
                component="cloudflare_tunnel",
                status="OK",
                message="Cloudflare tunnel service is active.",
                started_at=started_at,
                details={
                    "service": "cloudflared",
                    "systemd_state": state,
                },
            )

        pgrep = subprocess.run(
            ["pgrep", "-af", "cloudflared"],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )

        if pgrep.returncode == 0 and pgrep.stdout.strip():
            return component_result(
                component="cloudflare_tunnel",
                status="OK",
                message="Cloudflared process is running.",
                started_at=started_at,
                details={
                    "service": "cloudflared",
                    "systemd_state": state or "unknown",
                    "process": pgrep.stdout.strip().splitlines()[:3],
                },
            )

        return component_result(
            component="cloudflare_tunnel",
            status="WARN",
            message="Cloudflare tunnel is not active or not configured.",
            started_at=started_at,
            details={
                "service": "cloudflared",
                "systemd_state": state or "unknown",
            },
        )

    except Exception as exc:
        return component_result(
            component="cloudflare_tunnel",
            status="ERROR",
            message="Cloudflare tunnel check failed.",
            started_at=started_at,
            details={"error": str(exc)},
        )


def check_latest_incident_freshness():
    started_at = time.perf_counter()
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .order_by(Incident.timestamp.desc().nullslast(), Incident.id.desc())
            .first()
        )

        if not incident or not incident.timestamp:
            return component_result(
                component="latest_incident_freshness",
                status="WARN",
                message="No processed incident timestamp is available.",
                started_at=started_at,
            )

        incident_ts = parse_wazuh_dt(incident.timestamp)

        if not incident_ts:
            return component_result(
                component="latest_incident_freshness",
                status="WARN",
                message="Latest incident timestamp could not be parsed.",
                started_at=started_at,
                details={
                    "incident_id": incident.id,
                    "timestamp": incident.timestamp,
                },
            )

        age_seconds = round((utc_now() - incident_ts).total_seconds(), 2)

        status = "OK"
        if age_seconds > LATEST_INCIDENT_ERROR_AFTER_SECONDS:
            status = "ERROR"
        elif age_seconds > LATEST_INCIDENT_WARN_AFTER_SECONDS:
            status = "WARN"

        return component_result(
            component="latest_incident_freshness",
            status=status,
            message=f"Latest processed incident is {age_seconds}s old.",
            started_at=started_at,
            details={
                "incident_id": incident.id,
                "timestamp": incident.timestamp,
                "agent": incident.agent,
                "rule": incident.rule,
                "risk_score": incident.risk_score,
                "age_seconds": age_seconds,
                "warn_after_seconds": LATEST_INCIDENT_WARN_AFTER_SECONDS,
                "error_after_seconds": LATEST_INCIDENT_ERROR_AFTER_SECONDS,
            },
        )

    except Exception as exc:
        return component_result(
            component="latest_incident_freshness",
            status="ERROR",
            message="Latest incident freshness check failed.",
            started_at=started_at,
            details={"error": str(exc)},
        )

    finally:
        db.close()


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
            message="Component health check failed.",
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
            message="Component health check failed.",
            started_at=started_at,
            details={"url": QDRANT_URL},
        )



def check_wazuh_ingest():
    started_at = time.perf_counter()

    try:
        snapshot = get_watermark_snapshot()

        last_error_at = snapshot.get("last_error_at")
        last_success_at = snapshot.get("last_success_at")
        last_timestamp = snapshot.get("last_timestamp")

        status = "OK"
        message = "Wazuh ingest watermark is available."

        if not last_timestamp:
            status = "WARN"
            message = "Wazuh ingest watermark exists, but no alert timestamp has been processed yet."

        if last_error_at and (not last_success_at or last_error_at > last_success_at):
            status = "ERROR"
            message = f"Wazuh ingest last error: {snapshot.get('last_error')}"

        return component_result(
            component="wazuh_ingest",
            status=status,
            message=message,
            started_at=started_at,
            details=snapshot,
        )

    except Exception as exc:
        return component_result(
            component="wazuh_ingest",
            status="ERROR",
            message="Component health check failed.",
            started_at=started_at,
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

        stale_after = max(POLL_INTERVAL_SECONDS * 5, WORKER_STALE_AFTER_SECONDS)

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
            message="Component health check failed.",
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
        check_wazuh_ingest(),
        check_event_processing_queue(),
        check_active_event_sources(),
        check_latest_incident_freshness(),
        check_qdrant(),
        check_worker(),
        check_cloudflare_tunnel(),
    ]

    return {
        "status": overall_status(components),
        "checked_at": now_iso(),
        "components": components,
        "latest_incident": latest_incident_snapshot(),
    }
