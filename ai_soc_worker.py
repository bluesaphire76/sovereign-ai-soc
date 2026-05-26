import json
import os
import time
import urllib3
from datetime import datetime, timezone
from correlation_engine import correlate_incident
from correlation_precheck import evaluate_correlation_precheck
from noise_suppression import evaluate_noise_suppression
from worker_backlog_metrics import (
    build_batch_metrics,
    build_result_counts,
    is_processed_result,
    record_result,
)
from ai_triage_hardening import (
    AI_TRIAGE_ENABLED,
    AI_TRIAGE_FALLBACK_ON_ERROR,
    AI_TRIAGE_RETRY_ON_INVALID_OUTPUT,
    AI_TRIAGE_TIMEOUT_SECONDS,
    build_fallback_analysis,
    call_ollama_chat,
)
from rag_retriever import retrieve_security_context
from llm_output import is_invalid_llm_output, sanitize_llm_output
from event_aggregation import (
    EVENT_AGGREGATION_WINDOW_MINUTES,
    aggregate_alert,
    record_aggregate_incident,
)
from event_records import (
    link_security_alert_to_incident,
    persist_event_records,
    update_security_alert_status,
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
        alert["_wazuh_index"] = hit.get("_index")
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


def _build_alert_prompt(alert, context_text, context_warning=None):
    context_note = (
        context_warning
        if context_warning
        else "Knowledge base context retrieved successfully or not required."
    )

    return f"""
/no_think

You are a defensive AI SOC Assistant.

Use the knowledge base context when relevant.
If the context is insufficient, state that clearly.

Knowledge base context status:
{context_note}

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


def _ai_triage_system_message():
    return (
        "You are a professional defensive AI SOC Assistant focused on "
        "operational triage, alert investigation, and response guidance. "
        "Always answer in English unless explicitly configured otherwise. "
        "Return only the final answer. Do not include chain-of-thought, "
        "hidden reasoning, or <think> tags."
    )


def _build_retry_messages(prompt):
    return [
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
    ]


def analyze_alert_result(alert):
    if not AI_TRIAGE_ENABLED:
        return {
            "analysis": build_fallback_analysis(
                alert,
                reason="AI triage disabled by policy.",
                retry_attempted=False,
            ),
            "status": "fallback",
            "mode": "deterministic_fallback",
            "fallback_reason": "disabled_by_policy",
        }

    rag_query = " ".join([
        str(alert.get("rule", {}).get("description", "")),
        str(alert.get("full_log", "")),
        str(alert.get("rule", {}).get("mitre", "")),
    ])

    context_warning = None

    try:
        security_context = retrieve_security_context(rag_query, limit=3)

    except Exception as exc:
        security_context = []
        context_warning = (
            "Knowledge base context retrieval failed; continuing with alert-only triage."
        )
        print(
            "[yellow]Security context retrieval failed during AI triage; "
            f"continuing without RAG context: {type(exc).__name__}[/yellow]"
        )

    context_text = "\n\n".join(
        [
            f"Source: {item['source']}\n{item['text']}"
            for item in security_context
        ]
    )

    prompt = _build_alert_prompt(
        alert,
        context_text=context_text,
        context_warning=context_warning,
    )

    messages = [
        {
            "role": "system",
            "content": _ai_triage_system_message(),
        },
        {
            "role": "user",
            "content": prompt,
        },
    ]

    retry_attempted = False

    try:
        raw_analysis = call_ollama_chat(
            messages=messages,
            timeout_seconds=AI_TRIAGE_TIMEOUT_SECONDS,
        )
        analysis = sanitize_llm_output(raw_analysis)

        if is_invalid_llm_output(raw_analysis) or is_invalid_llm_output(analysis):
            if not AI_TRIAGE_RETRY_ON_INVALID_OUTPUT:
                raise ValueError("invalid_llm_output")

            retry_attempted = True
            retry_response = call_ollama_chat(
                messages=_build_retry_messages(prompt),
                timeout_seconds=AI_TRIAGE_TIMEOUT_SECONDS,
            )
            analysis = sanitize_llm_output(retry_response)

            if is_invalid_llm_output(retry_response) or is_invalid_llm_output(analysis):
                raise ValueError("invalid_llm_output_after_retry")

        return {
            "analysis": analysis,
            "status": "success",
            "mode": "llm",
            "fallback_reason": None,
            "retry_attempted": retry_attempted,
        }

    except Exception as exc:
        if not AI_TRIAGE_FALLBACK_ON_ERROR:
            raise

        print(
            "[yellow]AI triage fallback activated: "
            f"{type(exc).__name__}[/yellow]"
        )

        return {
            "analysis": build_fallback_analysis(
                alert,
                reason="AI triage failed, timed out or returned invalid output.",
                error_type=type(exc).__name__,
                retry_attempted=retry_attempted,
                context_note=context_warning,
            ),
            "status": "fallback",
            "mode": "deterministic_fallback",
            "fallback_reason": type(exc).__name__,
            "retry_attempted": retry_attempted,
        }


def analyze_alert(alert):
    return analyze_alert_result(alert)["analysis"]

def save_incident(alert, analysis, event_record_ids=None):
    event_record_ids = event_record_ids or {}
    db = SessionLocal()

    try:
        incident = Incident(
            wazuh_doc_id=alert.get("_wazuh_doc_id"),
            raw_event_id=event_record_ids.get("raw_event_id"),
            security_alert_id=event_record_ids.get("security_alert_id"),
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

    event_record_ids = {}

    try:
        event_record_ids = persist_event_records(alert)

    except Exception as exc:
        print(f"[yellow]Event record persistence non riuscita, continuo:[/yellow] {exc}")

    if incident_exists(doc_id):
        update_security_alert_status(
            event_record_ids.get("security_alert_id"),
            "DUPLICATE_DOC_ID",
        )
        print(f"[dim]Già processato: {doc_id}[/dim]")
        return "skipped_duplicate"

    aggregation_result = {}

    try:
        aggregation_result = aggregate_alert(alert)

    except Exception as exc:
        print(f"[yellow]Event aggregation non riuscita, continuo senza dedup:[/yellow] {exc}")

    noise_decision = evaluate_noise_suppression(
        alert,
        aggregation_result=aggregation_result,
    )

    if noise_decision.get("should_suppress"):
        update_security_alert_status(
            event_record_ids.get("security_alert_id"),
            "SUPPRESSED_NOISE",
        )
        print(
            "[dim]Security alert suppressed by noise policy: "
            f"doc_id={doc_id} "
            f"policy={noise_decision.get('policy_id')} "
            f"rule_id={noise_decision.get('rule_id')} "
            f"level={noise_decision.get('level')} "
            f"reasons={noise_decision.get('reasons')}[/dim]"
        )
        return "suppressed_noise"

    precheck = evaluate_correlation_precheck(
        alert,
        aggregation_result=aggregation_result,
    )

    if aggregation_result.get("duplicate") and not precheck.get("should_create_incident"):
        update_security_alert_status(
            event_record_ids.get("security_alert_id"),
            "AGGREGATED_DUPLICATE",
        )
        print(
            "[dim]Event aggregated within deduplication window: "
            f"fingerprint={aggregation_result.get('fingerprint')} "
            f"count={aggregation_result.get('count')} "
            f"window={aggregation_result.get('window_minutes')}m "
            f"decision={precheck.get('decision')}[/dim]"
        )
        return "skipped_aggregated_duplicate"

    if not precheck.get("should_create_incident"):
        update_security_alert_status(
            event_record_ids.get("security_alert_id"),
            "OBSERVED_NO_INCIDENT",
        )
        print(
            "[dim]Security alert osservato senza creazione incident: "
            f"doc_id={doc_id} "
            f"level={precheck.get('level')} "
            f"decision={precheck.get('decision')} "
            f"reasons={precheck.get('reasons')}[/dim]"
        )
        return "observed_no_incident"

    update_security_alert_status(
        event_record_ids.get("security_alert_id"),
        "CORRELATION_CANDIDATE",
    )

    print("\n[bold cyan]Nuovo alert candidato per incident[/bold cyan]")
    print(
        {
            "correlation_precheck": {
                "decision": precheck.get("decision"),
                "reasons": precheck.get("reasons"),
                "score": precheck.get("correlation_precheck_score"),
                "recommended_priority": precheck.get("recommended_priority"),
                "recent_alert_count": precheck.get("recent_alert_count"),
                "aggregate_count": precheck.get("aggregate_count"),
                "matched_attack_chains": precheck.get("matched_attack_chains"),
            }
        }
    )

    print(
        {
            "timestamp": alert.get("@timestamp"),
            "rule": alert.get("rule", {}).get("description"),
            "level": alert.get("rule", {}).get("level"),
            "agent": alert.get("agent", {}).get("name"),
            "doc_id": doc_id,
        }
    )

    triage_result = analyze_alert_result(alert)
    analysis = triage_result["analysis"]

    incident_id = save_incident(
        alert,
        analysis,
        event_record_ids=event_record_ids,
    )

    link_security_alert_to_incident(
        event_record_ids.get("security_alert_id"),
        incident_id,
    )

    if aggregation_result.get("fingerprint"):
        record_aggregate_incident(
            aggregation_result.get("fingerprint"),
            incident_id,
        )

    correlate_incident(incident_id)

    if triage_result.get("status") == "fallback":
        print("[bold yellow]Alert salvato con AI triage fallback.[/bold yellow]")
        return "processed_ai_fallback"

    print("[bold green]Alert analizzato e salvato in PostgreSQL.[/bold green]")
    return "processed_ai_success"


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
            result_counts = build_result_counts()

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

                record_result(result_counts, result)

                if is_processed_result(result):
                    processed_count += 1
                else:
                    skipped_count += 1

                if index % WAZUH_WATERMARK_FLUSH_EVERY == 0:
                    progress_metrics = build_batch_metrics(
                        alerts=alerts[:index],
                        processed_count=processed_count,
                        skipped_count=skipped_count,
                        result_counts=result_counts,
                        query_info=query_info,
                    )

                    update_watermark_progress(
                        alerts=alerts[:index],
                        processed_count=processed_count,
                        skipped_count=skipped_count,
                        query_info=query_info,
                        result_counts=result_counts,
                        batch_metrics=progress_metrics,
                    )

            batch_metrics = build_batch_metrics(
                alerts=alerts,
                processed_count=processed_count,
                skipped_count=skipped_count,
                result_counts=result_counts,
                query_info=query_info,
            )

            update_watermark_success(
                alerts=alerts,
                processed_count=processed_count,
                skipped_count=skipped_count,
                query_info=query_info,
                result_counts=result_counts,
                batch_metrics=batch_metrics,
            )

            update_worker_heartbeat(
                "OK",
                details={
                    "alerts_seen": len(alerts),
                    "alerts_processed": processed_count,
                    "alerts_skipped": skipped_count,
                    "result_counts": result_counts,
                    "ingest_mode": batch_metrics.get("ingest_mode"),
                    "latest_event_lag_seconds": batch_metrics.get("latest_event_lag_seconds"),
                    "latest_event_lag_minutes": batch_metrics.get("latest_event_lag_minutes"),
                    "poll_interval_seconds": POLL_INTERVAL_SECONDS,
                    "ollama_model": OLLAMA_MODEL,
                    "wazuh_ingest": query_info,
                    "batch_metrics": batch_metrics,
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

