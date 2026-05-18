import json
import os
import time
import urllib3
from datetime import datetime, timezone
from correlation_engine import correlate_incident
from rag_retriever import retrieve_security_context
from llm_output import is_invalid_llm_output, sanitize_llm_output
from event_aggregation import (
    EVENT_AGGREGATION_WINDOW_MINUTES,
    aggregate_alert,
    record_aggregate_incident,
)
from timezone_utils import normalize_timestamp_utc
from wazuh_ingest_state import (
    WAZUH_BATCH_SIZE,
    build_wazuh_alert_query,
    get_or_create_watermark,
    update_watermark_error,
    update_watermark_success,
    update_watermark_progress,
    WAZUH_WATERMARK_FLUSH_EVERY,
)

import ollama
import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from rich import print

from database import SessionLocal
from models import Incident, WorkerHeartbeat, utc_now

urllib3.disable_warnings()
load_dotenv()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))


def get_latest_alerts(limit=None):
    db = SessionLocal()

    try:
        watermark = get_or_create_watermark(db)
        query, query_info = build_wazuh_alert_query(
            watermark=watermark,
            limit=limit or WAZUH_BATCH_SIZE,
        )

    finally:
        db.close()

    response = requests.get(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASSWORD),
        json=query,
        verify=False,
        timeout=20,
    )

    response.raise_for_status()

    hits = response.json()["hits"]["hits"]

    alerts = []

    for hit in hits:
        alert = hit["_source"]
        alert["_wazuh_doc_id"] = hit["_id"]
        alerts.append(alert)

    return alerts, query_info


def incident_exists(doc_id):
    db = SessionLocal()

    try:
        existing = (
            db.query(Incident)
            .filter(Incident.wazuh_doc_id == doc_id)
            .first()
        )

        return existing is not None

    finally:
        db.close()



def update_worker_heartbeat(status, last_error=None, details=None):
    db = SessionLocal()

    try:
        now = utc_now()

        heartbeat = (
            db.query(WorkerHeartbeat)
            .filter(WorkerHeartbeat.component == "ai_soc_worker")
            .first()
        )

        if not heartbeat:
            heartbeat = WorkerHeartbeat(component="ai_soc_worker")
            db.add(heartbeat)

        heartbeat.status = status
        heartbeat.last_seen_at = now
        heartbeat.updated_at = now
        heartbeat.details = json.dumps(details or {}, ensure_ascii=False)

        if status == "OK":
            heartbeat.last_success_at = now
            heartbeat.last_error = None
            heartbeat.last_error_at = None

        if last_error:
            heartbeat.last_error_at = now
            heartbeat.last_error = str(last_error)

        db.commit()

    except Exception as exc:
        print(f"[yellow]Impossibile aggiornare worker heartbeat:[/yellow] {exc}")

    finally:
        db.close()


def analyze_alert(alert):
    rag_query = " ".join([
        str(alert.get("rule", {}).get("description", "")),
        str(alert.get("full_log", "")),
        str(alert.get("rule", {}).get("mitre", "")),
    ])

    security_context = retrieve_security_context(rag_query, limit=3)

    context_text = "\n\n".join(
        [
            f"Source: {item['source']}\n{item['text']}"
            for item in security_context
        ]
    )

    prompt = f"""
/no_think

You are a defensive AI SOC Assistant.

Use the knowledge base context when relevant.
If the context is insufficient, state that clearly.

Knowledge base context:
{context_text}

Analyze the following Wazuh alert.

Respond in English using the following sections:

1. Event type
2. Actual severity
3. Likely MITRE ATT&CK mapping
4. Business risk
5. Recommended checks
6. Suggested remediation
7. Short executive summary

Output constraints:
- English only.
- Return only the final SOC analysis.
- Do not include hidden reasoning, chain-of-thought, internal deliberation, or <think> tags.
- Do not use Chinese, Italian, or any other language unless explicitly configured.

Rules:
- Do not propose offensive activities.
- Do not perform or suggest automatic remediation without human validation.
- Always require human analyst validation.
- Be pragmatic, concise, and operationally useful.

Alert JSON:
{json.dumps(alert, ensure_ascii=False)}
"""

    response = ollama.chat(
        model=OLLAMA_MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a professional defensive AI SOC Assistant focused on "
                    "operational triage, alert investigation, and response guidance. "
                    "Always answer in English unless explicitly configured otherwise. "
                    "Return only the final answer. Do not include chain-of-thought, "
                    "hidden reasoning, or <think> tags."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    )

    raw_analysis = response["message"]["content"]
    analysis = sanitize_llm_output(raw_analysis)

    if is_invalid_llm_output(raw_analysis) or is_invalid_llm_output(analysis):
        retry_response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The previous output was invalid. You must answer in English only. "
                        "Return only the final SOC analysis. Do not include chain-of-thought, "
                        "hidden reasoning, Chinese text, Italian text, or <think> tags."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "/no_think\n\n"
                        "Regenerate the Wazuh alert analysis below in English only. "
                        "Return only the final answer.\n\n"
                        f"{prompt}"
                    ),
                },
            ],
        )

        analysis = sanitize_llm_output(retry_response["message"]["content"])

    return analysis


def save_incident(alert, analysis):
    db = SessionLocal()

    try:
        incident = Incident(
            wazuh_doc_id=alert.get("_wazuh_doc_id"),
            timestamp=normalize_timestamp_utc(alert.get("@timestamp")),
            agent=alert.get("agent", {}).get("name"),
            rule=alert.get("rule", {}).get("description"),
            level=alert.get("rule", {}).get("level"),
            mitre=str(alert.get("rule", {}).get("mitre", {})),
            risk_score=alert.get("rule", {}).get("level", 0),
            ai_analysis=analysis,
            raw_alert=json.dumps(alert, ensure_ascii=False),
        )

        db.add(incident)
        db.commit()
        db.refresh(incident)
        incident_id = incident.id
        return incident_id

    finally:
        db.close()


def process_alert(alert):
    doc_id = alert.get("_wazuh_doc_id")

    if not doc_id:
        print("[yellow]Alert senza doc_id, salto.[/yellow]")
        return "skipped_no_doc_id"

    if incident_exists(doc_id):
        print(f"[dim]Già processato: {doc_id}[/dim]")
        return "skipped_duplicate"

    aggregation_result = {}

    try:
        aggregation_result = aggregate_alert(alert)

    except Exception as exc:
        print(f"[yellow]Event aggregation non riuscita, continuo senza dedup:[/yellow] {exc}")

    if aggregation_result.get("duplicate"):
        print(
            "[dim]Evento aggregato entro finestra dedup: "
            f"fingerprint={aggregation_result.get('fingerprint')} "
            f"count={aggregation_result.get('count')} "
            f"window={aggregation_result.get('window_minutes')}m[/dim]"
        )
        return "skipped_aggregated_duplicate"

    print("\n[bold cyan]Nuovo alert rilevato[/bold cyan]")
    print(
        {
            "timestamp": alert.get("@timestamp"),
            "rule": alert.get("rule", {}).get("description"),
            "level": alert.get("rule", {}).get("level"),
            "agent": alert.get("agent", {}).get("name"),
            "doc_id": doc_id,
        }
    )

    analysis = analyze_alert(alert)
    incident_id = save_incident(alert, analysis)

    if aggregation_result.get("fingerprint"):
        record_aggregate_incident(
            aggregation_result.get("fingerprint"),
            incident_id,
        )

    correlate_incident(incident_id)

    print("[bold green]Alert analizzato e salvato in PostgreSQL.[/bold green]")
    return "processed"


def run_worker():
    print("[bold green]AI SOC Worker avviato.[/bold green]")
    print(f"Polling interval: {POLL_INTERVAL_SECONDS} secondi")
    print(f"Modello Ollama: {OLLAMA_MODEL}")
    print(f"Event aggregation window: {EVENT_AGGREGATION_WINDOW_MINUTES} minuti")

    update_worker_heartbeat(
        "STARTING",
        details={
            "poll_interval_seconds": POLL_INTERVAL_SECONDS,
            "ollama_model": OLLAMA_MODEL,
        },
    )

    while True:
        query_info = {}

        try:
            update_worker_heartbeat(
                "OK",
                details={
                    "phase": "polling",
                    "poll_interval_seconds": POLL_INTERVAL_SECONDS,
                    "ollama_model": OLLAMA_MODEL,
                },
            )

            alerts, query_info = get_latest_alerts()

            if not alerts:
                print("[dim]Nessun nuovo alert trovato nel watermark window.[/dim]")

            processed_count = 0
            skipped_count = 0

            for index, alert in enumerate(alerts, start=1):
                update_worker_heartbeat(
                    "OK",
                    details={
                        "phase": "processing_alert",
                        "current_doc_id": alert.get("_wazuh_doc_id"),
                        "current_timestamp": alert.get("@timestamp"),
                        "poll_interval_seconds": POLL_INTERVAL_SECONDS,
                        "ollama_model": OLLAMA_MODEL,
                        "wazuh_ingest": query_info,
                    },
                )

                result = process_alert(alert)

                if result == "processed":
                    processed_count += 1
                else:
                    skipped_count += 1

                if index % WAZUH_WATERMARK_FLUSH_EVERY == 0:
                    update_watermark_progress(
                        alerts=alerts[:index],
                        processed_count=processed_count,
                        skipped_count=skipped_count,
                        query_info=query_info,
                    )

            update_watermark_success(
                alerts=alerts,
                processed_count=processed_count,
                skipped_count=skipped_count,
                query_info=query_info,
            )

            update_worker_heartbeat(
                "OK",
                details={
                    "alerts_seen": len(alerts),
                    "alerts_processed": processed_count,
                    "alerts_skipped": skipped_count,
                    "poll_interval_seconds": POLL_INTERVAL_SECONDS,
                    "ollama_model": OLLAMA_MODEL,
                    "wazuh_ingest": query_info,
                },
            )

        except KeyboardInterrupt:
            update_worker_heartbeat("STOPPED")
            print("\n[bold yellow]Worker fermato manualmente.[/bold yellow]")
            break

        except Exception as exc:
            update_watermark_error(str(exc), query_info=query_info)

            update_worker_heartbeat(
                "ERROR",
                last_error=str(exc),
                details={
                    "poll_interval_seconds": POLL_INTERVAL_SECONDS,
                    "ollama_model": OLLAMA_MODEL,
                    "wazuh_ingest": query_info,
                },
            )
            print(f"[bold red]Errore worker:[/bold red] {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_worker()

