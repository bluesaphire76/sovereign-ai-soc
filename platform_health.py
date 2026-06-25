import json
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

from ai_model_config import PROFILES, get_profile
from database import engine, SessionLocal
from models import Incident, RawEvent, SecurityAlert, WorkerHeartbeat, utc_now
from ai_runtime_observability import get_ai_runtime_health_details
from active_users import get_active_users_snapshot
from wazuh_ingest_state import get_watermark_snapshot

urllib3.disable_warnings()
load_dotenv()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")
OLLAMA_MODEL = get_profile("standard").model
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "security_kb")
GRAFANA_URL = os.getenv(
    "GRAFANA_URL",
    os.getenv("GRAFANA_ROOT_URL", "http://127.0.0.1:3002/grafana/"),
)
GRAFANA_HEALTH_URL = os.getenv(
    "GRAFANA_HEALTH_URL",
    f"{GRAFANA_URL.rstrip('/')}/api/health",
)
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://127.0.0.1:9090")
PROMETHEUS_HEALTH_URL = os.getenv(
    "PROMETHEUS_HEALTH_URL",
    f"{PROMETHEUS_URL.rstrip('/')}/-/ready",
)
ALERTMANAGER_URL = os.getenv("ALERTMANAGER_URL", "http://127.0.0.1:9093")
ALERTMANAGER_HEALTH_URL = os.getenv(
    "ALERTMANAGER_HEALTH_URL",
    f"{ALERTMANAGER_URL.rstrip('/')}/-/ready",
)
NON_BLOCKING_OBSERVABILITY_COMPONENTS = {"grafana", "prometheus", "alertmanager"}
AI_SOC_RAG_ENABLED = os.getenv("AI_SOC_RAG_ENABLED", "true").strip().lower() not in {
    "0",
    "false",
    "no",
    "off",
}
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
WORKER_STALE_AFTER_SECONDS = int(os.getenv("WORKER_STALE_AFTER_SECONDS", "300"))
EVENT_SOURCE_WINDOW_MINUTES = int(os.getenv("EVENT_SOURCE_WINDOW_MINUTES", "15"))
EVENT_BACKLOG_WARN_THRESHOLD = int(os.getenv("EVENT_BACKLOG_WARN_THRESHOLD", "50"))
EVENT_BACKLOG_ERROR_THRESHOLD = int(os.getenv("EVENT_BACKLOG_ERROR_THRESHOLD", "500"))
LATEST_INCIDENT_WARN_AFTER_SECONDS = int(os.getenv("LATEST_INCIDENT_WARN_AFTER_SECONDS", "900"))
LATEST_INCIDENT_ERROR_AFTER_SECONDS = int(os.getenv("LATEST_INCIDENT_ERROR_AFTER_SECONDS", "3600"))
LATEST_EVENT_RECORD_WARN_AFTER_SECONDS = int(os.getenv("LATEST_EVENT_RECORD_WARN_AFTER_SECONDS", "900"))
LATEST_EVENT_RECORD_ERROR_AFTER_SECONDS = int(os.getenv("LATEST_EVENT_RECORD_ERROR_AFTER_SECONDS", "3600"))
SURICATA_CONTAINER_NAME = os.getenv("SURICATA_CONTAINER_NAME", "ai-soc-suricata")
SURICATA_INGEST_SERVICE = os.getenv("SURICATA_INGEST_SERVICE", "ai-soc-suricata-ingest")
LATEST_NETWORK_EVENT_WARN_AFTER_SECONDS = int(os.getenv("LATEST_NETWORK_EVENT_WARN_AFTER_SECONDS", "900"))
LATEST_NETWORK_EVENT_ERROR_AFTER_SECONDS = int(os.getenv("LATEST_NETWORK_EVENT_ERROR_AFTER_SECONDS", "3600"))



def parse_json_details(value):
    if not value:
        return None

    if isinstance(value, dict):
        return value

    try:
        return json.loads(value)
    except Exception:
        return {"raw": value}


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
                "configured_profile": "standard",
                "configured_profiles": {
                    name: profile.model
                    for name, profile in PROFILES.items()
                },
                "available_models": models,
            },
        )

    except Exception as exc:
        return component_result(
            component="ollama",
            status="ERROR",
            message="Component health check failed.",
            started_at=started_at,
            details={
                "configured_model": OLLAMA_MODEL,
                "configured_profile": "standard",
            },
        )


def parse_wazuh_dt(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None




def check_ai_runtime():
    started_at = time.perf_counter()

    try:
        details = get_ai_runtime_health_details()
        active_provider = details.get("active_provider") or {}
        active_health = details.get("active_provider_health") or {}
        active_key = active_provider.get("provider_key") or "local_ollama"

        if active_health:
            if active_health.get("enabled") is False:
                status = "WARN"
                message = f"Active AI provider {active_key} is disabled."
            elif active_health.get("reachable") is False:
                status = "ERROR"
                message = f"Active AI provider {active_key} is unavailable."
            elif active_health.get("model_available") is False:
                status = "WARN"
                message = f"Active AI provider {active_key} is reachable, but configured model is unavailable."
            else:
                status = "OK"
                message = f"Active AI provider {active_key} is reachable."
        elif not details.get("model_present"):
            status = "WARN"
            message = "Configured AI model is not available in Ollama."
        else:
            status = "OK"
            message = "AI runtime is reachable and configured model is available."

        return component_result(
            component="ai_runtime",
            status=status,
            message=message,
            started_at=started_at,
            details=details,
        )

    except Exception as exc:
        return component_result(
            component="ai_runtime",
            status="ERROR",
            message="AI runtime health check failed.",
            started_at=started_at,
            details={"error_type": type(exc).__name__},
        )

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
            details={"error": "internal_error"},
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
            details={"error": "internal_error"},
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
            details={"error": "internal_error"},
        )



def check_suricata_sensor():
    started_at = time.perf_counter()

    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", SURICATA_CONTAINER_NAME],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )

        running = result.stdout.strip().lower() == "true"

        if running:
            return component_result(
                component="suricata_sensor",
                status="OK",
                message="Suricata Docker sensor is running.",
                started_at=started_at,
                details={
                    "container": SURICATA_CONTAINER_NAME,
                    "running": True,
                },
            )

        return component_result(
            component="suricata_sensor",
            status="WARN",
            message="Suricata Docker sensor is not running.",
            started_at=started_at,
            details={
                "container": SURICATA_CONTAINER_NAME,
                "running": False,
                "docker_stdout": result.stdout.strip(),
                "docker_stderr": result.stderr.strip(),
            },
        )

    except Exception as exc:
        return component_result(
            component="suricata_sensor",
            status="ERROR",
            message="Suricata Docker sensor check failed.",
            started_at=started_at,
            details={"error": "internal_error", "error_type": type(exc).__name__},
        )


def check_suricata_ingest():
    started_at = time.perf_counter()

    try:
        systemd = subprocess.run(
            ["systemctl", "is-active", SURICATA_INGEST_SERVICE],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )

        service_state = systemd.stdout.strip() or systemd.stderr.strip()

        with engine.connect() as connection:
            state = connection.execute(
                sql_text("""
                    select source, file_path, byte_offset, updated_at, details
                    from suricata_ingest_state
                    where source = 'suricata'
                """)
            ).mappings().fetchone()

        details = {
            "service": SURICATA_INGEST_SERVICE,
            "systemd_state": service_state or "unknown",
            "watermark_present": bool(state),
        }

        if state:
            details.update(
                {
                    "source": state["source"],
                    "file_path": state["file_path"],
                    "byte_offset": state["byte_offset"],
                    "updated_at": state["updated_at"].isoformat() if state["updated_at"] else None,
                    "worker_details": parse_json_details(state["details"]),
                }
            )

        if systemd.returncode == 0 and service_state == "active":
            status = "OK" if state else "WARN"
            message = (
                "Suricata ingest worker is active and watermark state is available."
                if state
                else "Suricata ingest worker is active, but no watermark state is available yet."
            )
        else:
            status = "WARN"
            message = "Suricata ingest worker service is not active."

        return component_result(
            component="suricata_ingest",
            status=status,
            message=message,
            started_at=started_at,
            details=details,
        )

    except Exception as exc:
        return component_result(
            component="suricata_ingest",
            status="ERROR",
            message="Suricata ingest worker check failed.",
            started_at=started_at,
            details={"error": "internal_error", "error_type": type(exc).__name__},
        )


def check_latest_network_event_freshness():
    started_at = time.perf_counter()

    try:
        with engine.connect() as connection:
            row = connection.execute(
                sql_text("""
                    select
                        id,
                        event_type,
                        event_timestamp,
                        created_at,
                        src_ip,
                        dest_ip,
                        hostname,
                        app_proto,
                        alert_signature
                    from network_events
                    order by event_timestamp desc nulls last, created_at desc nulls last, id desc
                    limit 1
                """)
            ).mappings().fetchone()

        if not row:
            return component_result(
                component="latest_network_event_freshness",
                status="WARN",
                message="No Suricata network event is available yet.",
                started_at=started_at,
                details={
                    "warn_after_seconds": LATEST_NETWORK_EVENT_WARN_AFTER_SECONDS,
                    "error_after_seconds": LATEST_NETWORK_EVENT_ERROR_AFTER_SECONDS,
                },
            )

        event_ts = normalize_db_dt(row["event_timestamp"]) or normalize_db_dt(row["created_at"])

        if not event_ts:
            return component_result(
                component="latest_network_event_freshness",
                status="WARN",
                message="Latest Suricata network event timestamp could not be parsed.",
                started_at=started_at,
                details={
                    "event_id": row["id"],
                    "event_timestamp": str(row["event_timestamp"]),
                    "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                },
            )

        age_seconds = round((utc_now() - event_ts).total_seconds(), 2)

        status = "OK"
        if age_seconds > LATEST_NETWORK_EVENT_ERROR_AFTER_SECONDS:
            status = "ERROR"
        elif age_seconds > LATEST_NETWORK_EVENT_WARN_AFTER_SECONDS:
            status = "WARN"

        return component_result(
            component="latest_network_event_freshness",
            status=status,
            message=f"Latest Suricata network event is {age_seconds}s old.",
            started_at=started_at,
            details={
                "event_id": row["id"],
                "event_type": row["event_type"],
                "event_timestamp": row["event_timestamp"].isoformat() if row["event_timestamp"] else None,
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "src_ip": row["src_ip"],
                "dest_ip": row["dest_ip"],
                "hostname": row["hostname"],
                "app_proto": row["app_proto"],
                "alert_signature": row["alert_signature"],
                "age_seconds": age_seconds,
                "warn_after_seconds": LATEST_NETWORK_EVENT_WARN_AFTER_SECONDS,
                "error_after_seconds": LATEST_NETWORK_EVENT_ERROR_AFTER_SECONDS,
            },
        )

    except Exception as exc:
        return component_result(
            component="latest_network_event_freshness",
            status="ERROR",
            message="Latest Suricata network event freshness check failed.",
            started_at=started_at,
            details={"error": "internal_error", "error_type": type(exc).__name__},
        )


def normalize_db_dt(value):
    if not value:
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = parse_wazuh_dt(value)

    if parsed and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def latest_record_age_seconds(model, timestamp_field="updated_at"):
    db = SessionLocal()

    try:
        timestamp_column = getattr(model, timestamp_field)
        row = (
            db.query(model)
            .order_by(timestamp_column.desc().nullslast(), model.id.desc())
            .first()
        )

        if not row:
            return None, None

        timestamp_value = getattr(row, timestamp_field, None)
        timestamp_dt = normalize_db_dt(timestamp_value)

        if not timestamp_dt:
            return row, None

        return row, round((utc_now() - timestamp_dt).total_seconds(), 2)

    finally:
        db.close()


def check_event_record_freshness(model, component, label):
    started_at = time.perf_counter()
    row, age_seconds = latest_record_age_seconds(model, "updated_at")

    if not row:
        return component_result(
            component=component,
            status="WARN",
            message=f"No {label} record is available yet.",
            started_at=started_at,
            details={
                "warn_after_seconds": LATEST_EVENT_RECORD_WARN_AFTER_SECONDS,
                "error_after_seconds": LATEST_EVENT_RECORD_ERROR_AFTER_SECONDS,
            },
        )

    if age_seconds is None:
        return component_result(
            component=component,
            status="WARN",
            message=f"Latest {label} timestamp could not be parsed.",
            started_at=started_at,
            details={
                "record_id": row.id,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            },
        )

    status = "OK"

    if age_seconds > LATEST_EVENT_RECORD_ERROR_AFTER_SECONDS:
        status = "ERROR"
    elif age_seconds > LATEST_EVENT_RECORD_WARN_AFTER_SECONDS:
        status = "WARN"

    details = {
        "record_id": row.id,
        "source_event_id": getattr(row, "source_event_id", None),
        "event_timestamp": getattr(row, "event_timestamp", None),
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "agent": getattr(row, "agent", None),
        "rule_id": getattr(row, "rule_id", None),
        "age_seconds": age_seconds,
        "warn_after_seconds": LATEST_EVENT_RECORD_WARN_AFTER_SECONDS,
        "error_after_seconds": LATEST_EVENT_RECORD_ERROR_AFTER_SECONDS,
    }

    if hasattr(row, "status"):
        details["record_status"] = row.status

    if hasattr(row, "incident_id"):
        details["incident_id"] = row.incident_id

    return component_result(
        component=component,
        status=status,
        message=f"Latest {label} record was updated {age_seconds}s ago.",
        started_at=started_at,
        details=details,
    )


def check_latest_raw_event_freshness():
    return check_event_record_freshness(
        RawEvent,
        "latest_raw_event_freshness",
        "raw event",
    )


def check_latest_security_alert_freshness():
    return check_event_record_freshness(
        SecurityAlert,
        "latest_security_alert_freshness",
        "security alert",
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

        security_alert, security_alert_age_seconds = latest_record_age_seconds(
            SecurityAlert,
            "updated_at",
        )

        status = "OK"
        message = f"Latest processed incident is {age_seconds}s old."
        incident_creation_delayed_but_pipeline_active = False

        if age_seconds > LATEST_INCIDENT_ERROR_AFTER_SECONDS:
            status = "ERROR"
        elif age_seconds > LATEST_INCIDENT_WARN_AFTER_SECONDS:
            status = "WARN"

        if (
            status in {"WARN", "ERROR"}
            and security_alert_age_seconds is not None
            and security_alert_age_seconds <= LATEST_EVENT_RECORD_WARN_AFTER_SECONDS
        ):
            status = "OK"
            incident_creation_delayed_but_pipeline_active = True
            message = (
                f"Latest incident creation is {age_seconds}s old, "
                f"but security alert processing is active "
                f"({security_alert_age_seconds}s old)."
            )

        return component_result(
            component="latest_incident_freshness",
            status=status,
            message=message,
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
                "security_alert_age_seconds": security_alert_age_seconds,
                "latest_security_alert_id": security_alert.id if security_alert else None,
                "incident_creation_delayed_but_pipeline_active": incident_creation_delayed_but_pipeline_active,
            },
        )

    except Exception as exc:
        return component_result(
            component="latest_incident_freshness",
            status="ERROR",
            message="Latest incident freshness check failed.",
            started_at=started_at,
            details={"error": "internal_error"},
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
        collection_names = [item.get("name") for item in collections]
        collection_details = None
        points_count = None
        indexed_vectors_count = None
        status = "OK"
        message = "Qdrant is reachable and the configured knowledge base is indexed."

        if QDRANT_COLLECTION in collection_names:
            detail_response = requests.get(
                f"{QDRANT_URL.rstrip('/')}/collections/{QDRANT_COLLECTION}",
                timeout=8,
            )
            detail_response.raise_for_status()
            collection_details = detail_response.json().get("result", {})
            points_count = collection_details.get("points_count")
            indexed_vectors_count = collection_details.get("indexed_vectors_count")

            if not points_count:
                status = "WARN"
                message = "Qdrant is reachable, but the configured knowledge base collection is empty."
        else:
            status = "WARN"
            message = "Qdrant is reachable, but the configured knowledge base collection is missing."

        return component_result(
            component="qdrant",
            status=status,
            message=message,
            started_at=started_at,
            details={
                "url": QDRANT_URL,
                "rag_enabled": AI_SOC_RAG_ENABLED,
                "configured_collection": QDRANT_COLLECTION,
                "collections": collection_names,
                "collection_count": len(collections),
                "points_count": points_count,
                "indexed_vectors_count": indexed_vectors_count,
                "collection_status": collection_details.get("status") if collection_details else None,
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


def _response_body_preview(response):
    content_type = response.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            return response.json()
        except Exception:
            pass

    return (response.text or "")[:240]


def check_grafana():
    started_at = time.perf_counter()

    try:
        response = requests.get(GRAFANA_HEALTH_URL, timeout=5)
        body = _response_body_preview(response)
        database_status = body.get("database") if isinstance(body, dict) else None
        status = "OK" if response.ok and database_status != "fail" else "WARN"

        return component_result(
            component="grafana",
            status=status,
            message=(
                "Grafana health endpoint is reachable."
                if status == "OK"
                else "Grafana health endpoint is not ready."
            ),
            started_at=started_at,
            details={
                "url": GRAFANA_HEALTH_URL,
                "http_status": response.status_code,
                "database": database_status,
                "version": body.get("version") if isinstance(body, dict) else None,
                "body_preview": body if not isinstance(body, dict) else None,
                "non_blocking": True,
            },
        )

    except Exception as exc:
        return component_result(
            component="grafana",
            status="WARN",
            message="Grafana health check failed. Observability is degraded but application health is not blocked.",
            started_at=started_at,
            details={
                "url": GRAFANA_HEALTH_URL,
                "error_type": type(exc).__name__,
                "non_blocking": True,
            },
        )


def check_prometheus():
    started_at = time.perf_counter()

    try:
        response = requests.get(PROMETHEUS_HEALTH_URL, timeout=5)
        status = "OK" if response.ok else "WARN"

        return component_result(
            component="prometheus",
            status=status,
            message=(
                "Prometheus readiness endpoint is reachable."
                if status == "OK"
                else "Prometheus readiness endpoint is not ready."
            ),
            started_at=started_at,
            details={
                "url": PROMETHEUS_HEALTH_URL,
                "http_status": response.status_code,
                "body_preview": (response.text or "")[:240],
                "non_blocking": True,
            },
        )

    except Exception as exc:
        return component_result(
            component="prometheus",
            status="WARN",
            message="Prometheus health check failed. Observability is degraded but application health is not blocked.",
            started_at=started_at,
            details={
                "url": PROMETHEUS_HEALTH_URL,
                "error_type": type(exc).__name__,
                "non_blocking": True,
            },
        )


def check_alertmanager():
    started_at = time.perf_counter()

    try:
        response = requests.get(ALERTMANAGER_HEALTH_URL, timeout=5)
        status = "OK" if response.ok else "WARN"

        return component_result(
            component="alertmanager",
            status=status,
            message=(
                "Alertmanager readiness endpoint is reachable."
                if status == "OK"
                else "Alertmanager readiness endpoint is not ready."
            ),
            started_at=started_at,
            details={
                "url": ALERTMANAGER_HEALTH_URL,
                "http_status": response.status_code,
                "body_preview": (response.text or "")[:240],
                "non_blocking": True,
            },
        )

    except Exception as exc:
        return component_result(
            component="alertmanager",
            status="WARN",
            message="Alertmanager health check failed. Observability is degraded but application health is not blocked.",
            started_at=started_at,
            details={
                "url": ALERTMANAGER_HEALTH_URL,
                "error_type": type(exc).__name__,
                "non_blocking": True,
            },
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
            details={
                **snapshot,
                "details_raw": snapshot.get("details"),
                "details": parse_json_details(snapshot.get("details")),
            },
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

        worker_details = parse_json_details(heartbeat.details) or {}

        if not isinstance(worker_details, dict):
            worker_details = {"raw": worker_details}

        worker_details.setdefault("ollama_model", OLLAMA_MODEL)
        worker_details.setdefault("llm_configured_profile", "standard")
        worker_details.setdefault("llm_configured_model", OLLAMA_MODEL)

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
                "details": worker_details,
                "details_raw": heartbeat.details,
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
    blocking_components = [
        item
        for item in components
        if not (
            item.get("component") in NON_BLOCKING_OBSERVABILITY_COMPONENTS
            and isinstance(item.get("details"), dict)
            and item["details"].get("non_blocking") is True
        )
    ]
    statuses = {item["status"] for item in blocking_components}

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
        check_ai_runtime(),
        check_wazuh_indexer(),
        check_wazuh_ingest(),
        check_suricata_sensor(),
        check_suricata_ingest(),
        check_event_processing_queue(),
        check_active_event_sources(),
        check_latest_raw_event_freshness(),
        check_latest_security_alert_freshness(),
        check_latest_network_event_freshness(),
        check_latest_incident_freshness(),
        check_qdrant(),
        check_grafana(),
        check_prometheus(),
        check_alertmanager(),
        check_worker(),
        check_cloudflare_tunnel(),
    ]

    return {
        "status": overall_status(components),
        "checked_at": now_iso(),
        "components": components,
        "active_users": get_active_users_snapshot(),
        "latest_incident": latest_incident_snapshot(),
    }
