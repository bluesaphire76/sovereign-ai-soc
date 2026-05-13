import json
import os
import time
import urllib3
from datetime import datetime, timezone
from correlation_engine import correlate_incident
from rag_retriever import retrieve_security_context

import ollama
import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth
from rich import print

from database import SessionLocal
from models import Incident

urllib3.disable_warnings()
load_dotenv()

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL")
WAZUH_USER = os.getenv("WAZUH_USER")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))


def get_latest_alerts(limit=10):
    query = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"match_all": {}},
    }

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

    return alerts


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
            timestamp=alert.get("@timestamp"),
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
        return

    if incident_exists(doc_id):
        print(f"[dim]Già processato: {doc_id}[/dim]")
        return

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


def run_worker():
    print("[bold green]AI SOC Worker avviato.[/bold green]")
    print(f"Polling interval: {POLL_INTERVAL_SECONDS} secondi")
    print(f"Modello Ollama: {OLLAMA_MODEL}")

    while True:
        try:
            alerts = get_latest_alerts(limit=10)

            if not alerts:
                print("[dim]Nessun alert trovato.[/dim]")

            for alert in alerts:
                process_alert(alert)

        except KeyboardInterrupt:
            print("\n[bold yellow]Worker fermato manualmente.[/bold yellow]")
            break

        except Exception as exc:
            print(f"[bold red]Errore worker:[/bold red] {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run_worker()

