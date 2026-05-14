import json
import os
import time
import urllib3
from datetime import datetime, timezone
from correlation_engine import correlate_incident
from rag_retriever import retrieve_security_context
from timezone_utils import normalize_timestamp_utc
from wazuh_ingest_state import (
    WAZUH_BATCH_SIZE,
    build_wazuh_alert_query,
    get_or_create_watermark,
    update_watermark_error,
    update_watermark_success,
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
Sei un AI SOC Assistant difensivo.

Usa il contesto della knowledge base quando rilevante.
Se il contesto non è sufficiente, dillo chiaramente.

Knowledge base context:
{context_text}

Analizza questo alert Wazuh.

Rispondi in italiano con:

1. Tipo evento
2. Severità reale
3. MITRE ATT&CK probabile
4. Rischio per l'azienda
5. Verifiche consigliate
6. Remediation suggerita
7. Executive summary breve

Regole:
- Non proporre attività offensive.
- Non eseguire remediation automatica.
- Richiedi sempre validazione umana.
- Sii pragmatico e sintetico.

Alert JSON:
{json.dumps(alert, ensure_ascii=False)}
"""

    response = ollama.chat(
        model=OLLAMA_MODEL,
        messages=[
            {
                "role": "system",
                "content": "Sei un AI SOC Assistant professionale, difensivo e orientato al triage operativo.",
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
    )

    return response["message"]["content"]


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
    correlate_incident(incident_id)

    print("[bold green]Alert analizzato e salvato in PostgreSQL.[/bold green]")
    return "processed"


def run_worker():
    print("[bold green]AI SOC Worker avviato.[/bold green]")
    print(f"Polling interval: {POLL_INTERVAL_SECONDS} secondi")
    print(f"Modello Ollama: {OLLAMA_MODEL}")

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
            alerts, query_info = get_latest_alerts()

            if not alerts:
                print("[dim]Nessun nuovo alert trovato nel watermark window.[/dim]")

            processed_count = 0
            skipped_count = 0

            for alert in alerts:
                result = process_alert(alert)

                if result == "processed":
                    processed_count += 1
                else:
                    skipped_count += 1

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

