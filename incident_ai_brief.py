from __future__ import annotations

import json
import os
import re
from datetime import timedelta
from typing import Any

from dotenv import load_dotenv
from sqlalchemy import text as sql_text

from ai_triage_hardening import call_ollama_chat
from database import SessionLocal
from llm_output import is_invalid_llm_output, sanitize_llm_output
from models import Incident, IncidentAudit, utc_now
from timezone_utils import APP_TIMEZONE, format_timestamp_local, normalize_timestamp_utc

try:
    from rag_retriever import retrieve_security_context
except Exception:
    retrieve_security_context = None


load_dotenv()

AI_BRIEF_TIMEOUT_SECONDS = float(os.getenv("AI_BRIEF_TIMEOUT_SECONDS", "60"))


def safe_json_loads(value: str | None) -> Any:
    if not value:
        return None

    try:
        return json.loads(value)
    except Exception:
        return None


def safe_text(value: Any) -> str:
    if value is None:
        return "-"

    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False)

    return str(value)


def risk_band(score: int | None) -> str:
    value = score or 0

    if value >= 80:
        return "Critical"

    if value >= 60:
        return "High"

    if value >= 40:
        return "Medium"

    return "Low"


def status_stage(status: str | None) -> str:
    value = (status or "NEW").upper()

    if value in {"NEW"}:
        return "Detected"

    if value in {"TRIAGED", "INVESTIGATING", "ESCALATED"}:
        return "Analyzing"

    if value in {"CONTAINED"}:
        return "Containment"

    if value in {"RESOLVED"}:
        return "Recovery"

    if value in {"CLOSED", "FALSE_POSITIVE"}:
        return "Closed"

    return "Detected"


def parse_raw_alert(raw_alert: str | None) -> dict[str, Any]:
    parsed = safe_json_loads(raw_alert)

    if isinstance(parsed, dict):
        return parsed

    return {}


def extract_entities_from_incident(incident_payload: dict[str, Any]) -> dict[str, list[str]]:
    raw = incident_payload.get("raw_alert")

    if not isinstance(raw, dict):
        raw = {}

    entities = {
        "users": [],
        "hosts": [],
        "ips": [],
        "accounts": [],
        "apps": [],
        "files": [],
        "processes": [],
    }

    agent = incident_payload.get("agent")

    if agent:
        entities["hosts"].append(str(agent))

    for key_path in [
        ("agent", "name"),
        ("host", "name"),
        ("data", "srcuser"),
        ("data", "dstuser"),
        ("data", "user"),
        ("data", "srcip"),
        ("data", "dstip"),
        ("data", "src_ip"),
        ("data", "dst_ip"),
        ("data", "process", "name"),
        ("data", "command"),
        ("full_log",),
    ]:
        current: Any = raw

        for key in key_path:
            if not isinstance(current, dict):
                current = None
                break

            current = current.get(key)

        if not current:
            continue

        value = str(current)

        if "user" in key_path[-1].lower() or "srcuser" in key_path or "dstuser" in key_path:
            entities["users"].append(value)
            entities["accounts"].append(value)

        elif "ip" in key_path[-1].lower():
            entities["ips"].append(value)

        elif "process" in key_path or "command" in key_path:
            entities["processes"].append(value)

    searchable_text = " ".join(
        [
            safe_text(incident_payload.get("rule")),
            safe_text(incident_payload.get("raw_alert")),
            safe_text(incident_payload.get("correlation_summary")),
        ]
    )

    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", searchable_text):
        entities["ips"].append(ip)

    for file_match in re.findall(r"[\w./\\-]+\.(?:exe|dll|ps1|sh|txt|log|xlsx|csv|zip|json)", searchable_text, flags=re.I):
        entities["files"].append(file_match)

    for app in ["PowerShell", "RDP", "SSH", "VPN", "sudo", "apt", "systemd", "pam"]:
        if app.lower() in searchable_text.lower():
            entities["apps"].append(app)

    return {
        key: sorted(set(value for value in values if value and value != "-"))[:12]
        for key, values in entities.items()
    }


def serialize_incident(incident: Incident) -> dict[str, Any]:
    raw_alert = parse_raw_alert(incident.raw_alert)
    correlation_summary = safe_json_loads(incident.correlation_summary)

    payload = {
        "id": incident.id,
        "status": incident.status or "NEW",
        "lifecycle_stage": status_stage(incident.status),
        "timestamp": normalize_timestamp_utc(incident.timestamp),
        "timestamp_local": format_timestamp_local(incident.timestamp),
        "timezone": APP_TIMEZONE,
        "agent": incident.agent,
        "rule": incident.rule,
        "level": incident.level,
        "mitre": incident.mitre,
        "risk_score": incident.risk_score,
        "risk_band": risk_band(incident.risk_score),
        "ai_analysis": incident.ai_analysis,
        "raw_alert": raw_alert or incident.raw_alert,
        "correlated": bool(incident.correlated),
        "correlation_summary": correlation_summary or incident.correlation_summary,
        "correlation_score": incident.correlation_score,
        "attack_chain": incident.attack_chain,
        "correlation_type": incident.correlation_type,
        "escalation_reason": incident.escalation_reason,
        "recommended_priority": incident.recommended_priority,
        "wazuh_doc_id": incident.wazuh_doc_id,
    }

    payload["extracted_entities"] = extract_entities_from_incident(payload)

    return payload


def build_security_context(incident_payload: dict[str, Any]) -> list[dict[str, Any]]:
    if retrieve_security_context is None:
        return []

    query = " ".join(
        [
            safe_text(incident_payload.get("rule")),
            safe_text(incident_payload.get("agent")),
            safe_text(incident_payload.get("mitre")),
            safe_text(incident_payload.get("attack_chain")),
            safe_text(incident_payload.get("correlation_type")),
            safe_text(incident_payload.get("escalation_reason")),
        ]
    )

    try:
        return retrieve_security_context(query, limit=4)
    except Exception:
        return []



def network_evidence_empty(reason: str = "not_available") -> dict[str, Any]:
    return {
        "source": "suricata",
        "available": False,
        "reason": reason,
        "correlation_window_minutes": 120,
        "matched_ips": [],
        "matched_hostnames": [],
        "summary": {
            "total": 0,
            "alert": 0,
            "dns": 0,
            "http": 0,
            "tls": 0,
            "flow": 0,
        },
        "items": [],
    }


def network_event_summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total": len(rows),
        "alert": 0,
        "dns": 0,
        "http": 0,
        "tls": 0,
        "flow": 0,
    }

    for row in rows:
        event_type = str(row.get("event_type") or "")
        if event_type in summary:
            summary[event_type] += 1

    return summary


def normalize_network_event_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "event_type": row.get("event_type"),
        "event_timestamp": row.get("event_timestamp").isoformat()
        if row.get("event_timestamp")
        else None,
        "src_ip": row.get("src_ip"),
        "src_port": row.get("src_port"),
        "dest_ip": row.get("dest_ip"),
        "dest_port": row.get("dest_port"),
        "proto": row.get("proto"),
        "app_proto": row.get("app_proto"),
        "hostname": row.get("hostname"),
        "tls_sni": row.get("tls_sni"),
        "url": row.get("url"),
        "http_method": row.get("http_method"),
        "alert_signature": row.get("alert_signature"),
        "alert_category": row.get("alert_category"),
        "alert_severity": row.get("alert_severity"),
    }


def load_network_evidence_summary(
    incident_payload: dict[str, Any],
    window_minutes: int = 120,
    limit: int = 12,
) -> dict[str, Any]:
    """Best-effort Suricata evidence enrichment for the AI brief.

    This function is read-only. Any failure must not block AI brief generation.
    """
    try:
        incident_ts = normalize_timestamp_utc(incident_payload.get("timestamp"))

        if not incident_ts:
            return network_evidence_empty("incident_timestamp_unavailable")

        entities = incident_payload.get("extracted_entities") or {}
        raw_alert = incident_payload.get("raw_alert") or {}

        candidate_ips = {
            str(value).strip()
            for value in entities.get("ips", [])
            if value and str(value).strip()
        }

        for key_path in [
            ("agent", "ip"),
            ("data", "srcip"),
            ("data", "dstip"),
            ("data", "src_ip"),
            ("data", "dst_ip"),
        ]:
            current: Any = raw_alert

            for key in key_path:
                if not isinstance(current, dict):
                    current = None
                    break

                current = current.get(key)

            if current:
                candidate_ips.add(str(current).strip())

        candidate_hostnames = {
            str(value).strip()
            for value in entities.get("hosts", [])
            if value and str(value).strip()
        }

        if incident_payload.get("agent"):
            candidate_hostnames.add(str(incident_payload["agent"]).strip())

        candidate_ips = {value for value in candidate_ips if value and value != "-"}
        candidate_hostnames = {
            value
            for value in candidate_hostnames
            if value
            and value != "-"
            and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value)
        }

        if not candidate_ips and not candidate_hostnames:
            return network_evidence_empty("no_ip_or_hostname_candidates")

        start_ts = incident_ts - timedelta(minutes=window_minutes)
        end_ts = incident_ts + timedelta(minutes=window_minutes)

        params: dict[str, Any] = {
            "start_ts": start_ts,
            "end_ts": end_ts,
            "limit": limit,
        }

        match_clauses: list[str] = []

        for index, ip in enumerate(sorted(candidate_ips)[:30]):
            key = f"ip_{index}"
            params[key] = ip
            match_clauses.append(f"(src_ip = :{key} OR dest_ip = :{key})")

        for index, hostname in enumerate(sorted(candidate_hostnames)[:20]):
            key = f"host_{index}"
            params[key] = f"%{hostname}%"
            match_clauses.append(f"(hostname ILIKE :{key} OR tls_sni ILIKE :{key})")

        if not match_clauses:
            return network_evidence_empty("no_valid_match_candidates")

        db = SessionLocal()

        try:
            rows = (
                db.execute(
                    sql_text(f"""
                        SELECT
                            id,
                            event_type,
                            event_timestamp,
                            src_ip,
                            src_port,
                            dest_ip,
                            dest_port,
                            proto,
                            app_proto,
                            hostname,
                            tls_sni,
                            url,
                            http_method,
                            alert_signature,
                            alert_category,
                            alert_severity
                        FROM network_events
                        WHERE event_timestamp BETWEEN :start_ts AND :end_ts
                          AND ({' OR '.join(match_clauses)})
                        ORDER BY event_timestamp DESC NULLS LAST, id DESC
                        LIMIT :limit
                    """),
                    params,
                )
                .mappings()
                .all()
            )
        finally:
            db.close()

        item_dicts = [dict(row) for row in rows]
        summary = network_event_summary(item_dicts)

        return {
            "source": "suricata",
            "available": summary["total"] > 0,
            "reason": "matched_network_telemetry"
            if summary["total"] > 0
            else "no_related_network_events_found",
            "correlation_window_minutes": window_minutes,
            "matched_ips": sorted(candidate_ips),
            "matched_hostnames": sorted(candidate_hostnames),
            "summary": summary,
            "items": [normalize_network_event_row(row) for row in item_dicts],
        }

    except Exception as exc:
        return {
            **network_evidence_empty("network_evidence_lookup_failed"),
            "error_type": type(exc).__name__,
        }




def dns_context_empty(reason: str = "not_available") -> dict[str, Any]:
    return {
        "available": False,
        "reason": reason,
        "source": "dns_events",
        "matching_logic": "same host/client IP and selected time window only",
        "causal_correlation_inferred": False,
        "window_minutes": 120,
        "matched_agents": [],
        "matched_client_ips": [],
        "summary": {
            "total": 0,
            "unique_domains": 0,
            "query_types": [],
            "top_domains": [],
        },
        "items": [],
        "limitations": [
            "DNS context is matched by host/client IP and selected time window only.",
            "DNS context does not imply causal correlation with the incident.",
            "For operational incidents such as Wazuh agent stopped, DNS context should be treated as surrounding host activity, not root cause evidence.",
        ],
    }


def normalize_dns_context_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "event_timestamp": safe_text(row.get("event_timestamp")),
        "agent_name": row.get("agent_name"),
        "agent_ip": row.get("agent_ip"),
        "client_ip": row.get("client_ip"),
        "resolver_ip": row.get("resolver_ip"),
        "query_name": row.get("query_name"),
        "query_type": row.get("query_type"),
        "query_status": row.get("query_status"),
        "collector": row.get("collector"),
        "source": row.get("source"),
    }


def load_dns_context_summary(
    incident_payload: dict[str, Any],
    window_minutes: int = 120,
    limit: int = 25,
) -> dict[str, Any]:
    """Best-effort DNS context enrichment for the AI brief.

    DNS context is matched by host/client IP and time window only.
    It must not be treated as causal incident evidence.
    """

    try:
        incident_ts = normalize_timestamp_utc(incident_payload.get("timestamp"))

        if not incident_ts:
            return dns_context_empty("incident_timestamp_unavailable")

        raw_alert = incident_payload.get("raw_alert") or {}
        if not isinstance(raw_alert, dict):
            raw_alert = {}

        candidate_agents: set[str] = set()
        candidate_ips: set[str] = set()

        if incident_payload.get("agent"):
            candidate_agents.add(str(incident_payload["agent"]).strip())

        for key_path in [("agent", "name"), ("host", "name")]:
            current: Any = raw_alert
            for key in key_path:
                if not isinstance(current, dict):
                    current = None
                    break
                current = current.get(key)
            if current:
                candidate_agents.add(str(current).strip())

        for key_path in [
            ("agent", "ip"),
            ("data", "srcip"),
            ("data", "dstip"),
            ("data", "src_ip"),
            ("data", "dst_ip"),
        ]:
            current: Any = raw_alert
            for key in key_path:
                if not isinstance(current, dict):
                    current = None
                    break
                current = current.get(key)
            if current:
                candidate_ips.add(str(current).strip())

        entities = incident_payload.get("extracted_entities") or {}
        for ip in entities.get("ips") or []:
            candidate_ips.add(str(ip).strip())

        candidate_agents = {value for value in candidate_agents if value and value != "-"}
        candidate_ips = {value for value in candidate_ips if value and value != "-"}

        if not candidate_agents and not candidate_ips:
            return dns_context_empty("no_agent_or_client_ip_candidates")

        start_ts = incident_ts - timedelta(minutes=window_minutes)
        end_ts = incident_ts + timedelta(minutes=window_minutes)

        match_clauses: list[str] = []
        params: dict[str, Any] = {"start_ts": start_ts, "end_ts": end_ts, "limit": limit}

        for index, agent in enumerate(sorted(candidate_agents)[:20]):
            key = f"agent_{index}"
            params[key] = agent
            match_clauses.append(f"agent_name = :{key}")

        for index, ip in enumerate(sorted(candidate_ips)[:20]):
            key = f"ip_{index}"
            params[key] = ip
            match_clauses.append(f"client_ip = :{key}")

        if not match_clauses:
            return dns_context_empty("no_valid_match_candidates")

        where_clause = (
            "event_timestamp BETWEEN :start_ts AND :end_ts "
            "AND (" + " OR ".join(match_clauses) + ")"
        )

        with SessionLocal() as db:
            rows = (
                db.execute(
                    text(f"""
                        SELECT
                            id,
                            source,
                            event_timestamp,
                            agent_name,
                            agent_ip,
                            client_ip,
                            resolver_ip,
                            query_name,
                            query_type,
                            query_status,
                            collector
                        FROM dns_events
                        WHERE {where_clause}
                        ORDER BY event_timestamp DESC NULLS LAST, id DESC
                        LIMIT :limit
                    """),
                    params,
                )
                .mappings()
                .all()
            )

            query_types = (
                db.execute(
                    text(f"""
                        SELECT query_type, count(*) AS count
                        FROM dns_events
                        WHERE {where_clause}
                        GROUP BY query_type
                        ORDER BY count DESC
                        LIMIT 10
                    """),
                    params,
                )
                .mappings()
                .all()
            )

            top_domains = (
                db.execute(
                    text(f"""
                        SELECT query_name, count(*) AS count
                        FROM dns_events
                        WHERE {where_clause}
                          AND query_name IS NOT NULL
                        GROUP BY query_name
                        ORDER BY count DESC
                        LIMIT 10
                    """),
                    params,
                )
                .mappings()
                .all()
            )

            unique_domains = db.execute(
                text(f"""
                    SELECT count(DISTINCT query_name)
                    FROM dns_events
                    WHERE {where_clause}
                """),
                params,
            ).scalar()

        items = [normalize_dns_context_row(dict(row)) for row in rows]
        total = len(items)

        return {
            "available": total > 0,
            "reason": "matched_dns_context" if total else "no_contextual_dns_events_found",
            "source": "dns_events",
            "matching_logic": "same host/client IP and selected time window only",
            "causal_correlation_inferred": False,
            "window_minutes": window_minutes,
            "matched_agents": sorted(candidate_agents),
            "matched_client_ips": sorted(candidate_ips),
            "summary": {
                "total": total,
                "unique_domains": unique_domains or 0,
                "query_types": [dict(row) for row in query_types],
                "top_domains": [dict(row) for row in top_domains],
            },
            "items": items,
            "limitations": [
                "DNS context is matched by host/client IP and selected time window only.",
                "DNS context does not imply causal correlation with the incident.",
                "For operational incidents such as Wazuh agent stopped, DNS context should be treated as surrounding host activity, not root cause evidence.",
            ],
        }

    except Exception:
        return {**dns_context_empty("dns_context_lookup_failed"), "lookup_error_handled": True}


def build_prompt(
    incident_payload: dict[str, Any],
    security_context: list[dict[str, Any]],
) -> str:
    context_text = "\n\n".join(
        [
            f"Source: {item.get('source')}\n{item.get('text')}"
            for item in security_context
        ]
    )

    required_schema = {
        "situation_summary": "string",
        "risk_rationale": "string",
        "confidence": 0,
        "impact": "Low|Medium|High|Critical",
        "likelihood": "Low|Medium|High|Very High",
        "limitations": ["string"],
        "evidence_used": [
            {
                "label": "string",
                "count": 0,
                "description": "string",
            }
        ],
        "investigation_hypotheses": [
            {
                "label": "string",
                "likelihood": "Most likely|Possible|Unlikely",
                "rationale": "string",
            }
        ],
        "evidence_overview": [
            {
                "time": "string",
                "description": "string",
                "source": "string",
                "verification": "Verified|Suspected|High fidelity|Unverified",
            }
        ],
        "attack_progression": [
            {
                "stage": "Initial Access|Credential Access|Execution|Privilege Escalation|Lateral Movement|Impact|Objectives",
                "time_window": "string",
                "events": [
                    {
                        "time": "string",
                        "title": "string",
                        "description": "string",
                        "entity": "string",
                        "observed": True,
                    }
                ],
            }
        ],
        "extracted_entities": {
            "users": ["string"],
            "hosts": ["string"],
            "ips": ["string"],
            "accounts": ["string"],
            "apps": ["string"],
            "files": ["string"],
            "processes": ["string"],
        },
        "primary_recommendation": {
            "title": "string",
            "reason": "string",
            "requires_human_approval": True,
        },
        "recommended_actions": [
            {
                "action": "string",
                "impact": "Low|Medium|High|Critical",
                "requires_approval": True,
            }
        ],
        "human_validation_required": True,
        "executive_summary": "string",
    }

    return f"""
/no_think

You are a professional defensive AI SOC Assistant embedded in a sovereign, local-first SOC platform.

You are generating an AI Incident Brief for an enterprise Incident Detail page.
This output will be used by a human SOC analyst.

Your goal:
- Explain what happened.
- Explain why it matters.
- Identify evidence used, including Wazuh alert data, correlation data and Suricata network evidence when available.
- Build an attack progression timeline.
- Extract entities.
- Suggest analyst checks and response actions.
- Keep human-in-the-loop explicit.
- Do not invent facts.
- If evidence is missing, state it clearly.
- Do not propose offensive actions.
- Do not perform or suggest automatic remediation without human approval.

Knowledge base context:
{context_text}

Incident data:
{json.dumps(incident_payload, ensure_ascii=False, indent=2, default=str)}

Network evidence guidance:
- If incident_data.network_evidence.available is true, explicitly mention the Suricata evidence in evidence_used and evidence_overview.
- If Suricata alert events are present, include them as high-fidelity supporting evidence, but do not automatically escalate without Wazuh/correlation support.
- If only flow/http/tls/dns events are present, treat them as investigation context, not proof of compromise.
- If incident_data.dns_context.available is true, treat DNS telemetry as contextual host activity matched by host/client IP and selected time window only.
- Do not claim DNS activity caused, triggered, or is causally correlated with the incident unless explicit detection evidence supports that conclusion.
- For operational incidents such as Wazuh agent stopped, describe DNS context as surrounding host network activity, not root cause evidence.
- If DNS context is unavailable or empty, state that DNS context did not add host/time-window observations.
- If network evidence is unavailable or empty, state that network telemetry did not add related evidence in the selected window.
- Keep all recommendations human-approved and read-only.

Return ONLY valid JSON.
Do not wrap JSON in markdown.
Do not include comments.
Do not include chain-of-thought, hidden reasoning, or <think> tags.

Required JSON schema:
{json.dumps(required_schema, ensure_ascii=False, indent=2)}
"""


def extract_json_object(text: str) -> dict[str, Any] | None:
    if not text:
        return None

    cleaned = text.strip()

    try:
        parsed = json.loads(cleaned)

        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)

    if not match:
        return None

    try:
        parsed = json.loads(match.group(0))

        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None

    return None


def as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        result = []

        for item in value:
            if isinstance(item, str) and item.strip():
                result.append(item.strip())
            elif item is not None:
                result.append(safe_text(item))

        return result

    if isinstance(value, str) and value.strip():
        return [value.strip()]

    return []


def normalize_evidence_used(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    result = []

    for item in value:
        if isinstance(item, dict):
            result.append(
                {
                    "label": safe_text(item.get("label")),
                    "count": int(item.get("count") or 0),
                    "description": safe_text(item.get("description")),
                }
            )
        elif isinstance(item, str):
            result.append(
                {
                    "label": item,
                    "count": 1,
                    "description": item,
                }
            )

    return result[:12]


def normalize_hypotheses(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []

    result = []

    for item in value:
        if isinstance(item, dict):
            result.append(
                {
                    "label": safe_text(item.get("label")),
                    "likelihood": safe_text(item.get("likelihood")),
                    "rationale": safe_text(item.get("rationale")),
                }
            )
        elif isinstance(item, str):
            result.append(
                {
                    "label": item,
                    "likelihood": "Possible",
                    "rationale": "-",
                }
            )

    return result[:8]


def normalize_evidence_overview(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []

    result = []

    for item in value:
        if not isinstance(item, dict):
            continue

        result.append(
            {
                "time": safe_text(item.get("time")),
                "description": safe_text(item.get("description")),
                "source": safe_text(item.get("source")),
                "verification": safe_text(item.get("verification")),
            }
        )

    return result[:12]


def normalize_attack_progression(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    result = []

    for item in value:
        if not isinstance(item, dict):
            continue

        raw_events = item.get("events")

        events = []

        if isinstance(raw_events, list):
            for event in raw_events:
                if not isinstance(event, dict):
                    continue

                events.append(
                    {
                        "time": safe_text(event.get("time")),
                        "title": safe_text(event.get("title")),
                        "description": safe_text(event.get("description")),
                        "entity": safe_text(event.get("entity")),
                        "observed": bool(event.get("observed", True)),
                    }
                )

        result.append(
            {
                "stage": safe_text(item.get("stage")),
                "time_window": safe_text(item.get("time_window")),
                "events": events[:6],
            }
        )

    return result[:8]


def normalize_entities(value: Any, fallback: dict[str, list[str]]) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return fallback

    result = {}

    for key in ["users", "hosts", "ips", "accounts", "apps", "files", "processes"]:
        result[key] = as_string_list(value.get(key)) or fallback.get(key, [])

    return result


def normalize_recommended_actions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    result = []

    for item in value:
        if isinstance(item, dict):
            result.append(
                {
                    "action": safe_text(item.get("action")),
                    "impact": safe_text(item.get("impact")),
                    "requires_approval": bool(item.get("requires_approval", True)),
                }
            )
        elif isinstance(item, str):
            result.append(
                {
                    "action": item,
                    "impact": "Medium",
                    "requires_approval": True,
                }
            )

    return result[:10]


def normalize_brief(value: dict[str, Any], fallback_entities: dict[str, list[str]]) -> dict[str, Any]:
    primary = value.get("primary_recommendation")

    if not isinstance(primary, dict):
        primary = {}

    return {
        "situation_summary": safe_text(value.get("situation_summary")),
        "risk_rationale": safe_text(value.get("risk_rationale")),
        "confidence": int(value.get("confidence") or 0),
        "impact": safe_text(value.get("impact")),
        "likelihood": safe_text(value.get("likelihood")),
        "limitations": as_string_list(value.get("limitations")),
        "evidence_used": normalize_evidence_used(value.get("evidence_used")),
        "investigation_hypotheses": normalize_hypotheses(value.get("investigation_hypotheses")),
        "evidence_overview": normalize_evidence_overview(value.get("evidence_overview")),
        "attack_progression": normalize_attack_progression(value.get("attack_progression")),
        "extracted_entities": normalize_entities(value.get("extracted_entities"), fallback_entities),
        "primary_recommendation": {
            "title": safe_text(primary.get("title")),
            "reason": safe_text(primary.get("reason")),
            "requires_human_approval": bool(primary.get("requires_human_approval", True)),
        },
        "recommended_actions": normalize_recommended_actions(value.get("recommended_actions")),
        "human_validation_required": bool(value.get("human_validation_required", True)),
        "executive_summary": safe_text(value.get("executive_summary")),
    }


def deterministic_brief(incident_payload: dict[str, Any], reason: str) -> dict[str, Any]:
    risk_score = int(incident_payload.get("risk_score") or 0)
    level = int(incident_payload.get("level") or 0)
    band = risk_band(risk_score)
    host = safe_text(incident_payload.get("agent"))
    rule = safe_text(incident_payload.get("rule"))
    correlated = bool(incident_payload.get("correlated"))
    entities = incident_payload.get("extracted_entities") or {}
    network_evidence = incident_payload.get("network_evidence") or {}
    network_summary = network_evidence.get("summary") or {}
    network_total = int(network_summary.get("total") or 0)
    network_alerts = int(network_summary.get("alert") or 0)

    evidence = [
        {
            "label": "Wazuh alert",
            "count": 1,
            "description": rule,
        },
        {
            "label": "Host telemetry",
            "count": 1 if host != "-" else 0,
            "description": f"Primary affected host: {host}",
        },
        {
            "label": "Correlation context",
            "count": 1 if correlated else 0,
            "description": "Correlation detected" if correlated else "No explicit correlation attached",
        },
        {
            "label": "Suricata network evidence",
            "count": network_total,
            "description": (
                f"{network_total} related network event(s) found in the ±"
                f"{network_evidence.get('correlation_window_minutes', 120)} minute window; "
                f"{network_alerts} IDS alert event(s)."
                if network_total
                else "No related Suricata network telemetry found in the selected window."
            ),
        },
    ]

    overview = [
        {
            "time": safe_text(incident_payload.get("timestamp_local")),
            "description": rule,
            "source": "Wazuh alert",
            "verification": "Verified",
        },
        {
            "time": safe_text(incident_payload.get("timestamp_local")),
            "description": f"Risk score assigned: {risk_score} ({band})",
            "source": "AI SOC risk engine",
            "verification": "Verified",
        },
    ]

    if correlated:
        overview.append(
            {
                "time": safe_text(incident_payload.get("timestamp_local")),
                "description": safe_text(incident_payload.get("escalation_reason") or "Correlation pattern detected"),
                "source": "Correlation engine",
                "verification": "High fidelity",
            }
        )

    if network_total:
        overview.append(
            {
                "time": safe_text(incident_payload.get("timestamp_local")),
                "description": (
                    f"Suricata observed {network_total} related network event(s), "
                    f"including {network_alerts} IDS alert event(s), in the selected evidence window."
                ),
                "source": "Suricata network telemetry",
                "verification": "High fidelity" if network_alerts else "Verified",
            }
        )

    progression = [
        {
            "stage": "Detection",
            "time_window": safe_text(incident_payload.get("timestamp_local")),
            "events": [
                {
                    "time": safe_text(incident_payload.get("timestamp_local")),
                    "title": "Detection triggered",
                    "description": rule,
                    "entity": host,
                    "observed": True,
                }
            ],
        },
        {
            "stage": "AI Triage",
            "time_window": safe_text(incident_payload.get("timestamp_local")),
            "events": [
                {
                    "time": safe_text(incident_payload.get("timestamp_local")),
                    "title": "Risk evaluated",
                    "description": f"Risk band {band}, Wazuh level {level}",
                    "entity": host,
                    "observed": True,
                }
            ],
        },
        {
            "stage": "Human Validation",
            "time_window": "Pending",
            "events": [
                {
                    "time": "Pending",
                    "title": "Analyst decision required",
                    "description": "Human validation is required before escalation, closure or remediation.",
                    "entity": "SOC analyst",
                    "observed": False,
                }
            ],
        },
    ]

    return {
        "situation_summary": (
            f"Incident #{incident_payload.get('id')} was detected on host {host}. "
            f"The triggering rule is: {rule}. Current risk is {band} with score {risk_score}."
        ),
        "risk_rationale": (
            f"This deterministic AI brief was generated because {reason}. "
            "Risk is derived from the current risk score, Wazuh level, correlation state and available evidence. "
            "A human analyst must validate context before any operational decision."
        ),
        "confidence": 65 if reason else 75,
        "impact": band,
        "likelihood": "High" if risk_score >= 60 or correlated else "Medium",
        "limitations": [
            "This response may not include all host, user or process telemetry.",
            "Intent cannot be confirmed without analyst validation.",
            "No automatic remediation was performed.",
        ],
        "evidence_used": evidence,
        "investigation_hypotheses": [
            {
                "label": "Legitimate operational activity",
                "likelihood": "Possible",
                "rationale": "Some security alerts are caused by expected administrative or system behavior.",
            },
            {
                "label": "Suspicious activity requiring investigation",
                "likelihood": "Most likely" if risk_score >= 60 or correlated else "Possible",
                "rationale": "The signal has enough severity or correlation context to require analyst validation.",
            },
        ],
        "evidence_overview": overview,
        "attack_progression": progression,
        "extracted_entities": entities,
        "primary_recommendation": {
            "title": "Validate incident evidence",
            "reason": "The analyst must confirm whether the observed behavior is expected, malicious or a false positive.",
            "requires_human_approval": True,
        },
        "recommended_actions": [
            {
                "action": "Review raw Wazuh alert and related logs",
                "impact": "High" if risk_score >= 60 else "Medium",
                "requires_approval": True,
            },
            {
                "action": "Check affected host, user and process context",
                "impact": "Medium",
                "requires_approval": True,
            },
            {
                "action": "Review related Suricata network evidence for matching IPs, hostnames, HTTP/TLS activity and IDS alerts",
                "impact": "Medium" if network_total else "Low",
                "requires_approval": True,
            },
            {
                "action": "Escalate to case if suspicious activity is confirmed",
                "impact": "High" if risk_score >= 60 or correlated else "Medium",
                "requires_approval": True,
            },
        ],
        "human_validation_required": True,
        "executive_summary": (
            f"A {band.lower()} risk security incident was detected on {host}. "
            "AI recommends human validation before escalation, closure or remediation."
        ),
    }



def append_unique_dict(items: list[dict[str, Any]], key: str, value: str, item: dict[str, Any]) -> None:
    if any(existing.get(key) == value for existing in items if isinstance(existing, dict)):
        return

    items.append(item)


def enrich_brief_with_dns_context(
    brief: dict[str, Any],
    incident_payload: dict[str, Any],
) -> dict[str, Any]:
    """Add DNS context to both deterministic preview and generated AI brief.

    DNS context is host/time-window context only. It must not be presented as
    causal evidence unless another explicit detection source supports that.
    """

    dns_context = incident_payload.get("dns_context") or {}
    dns_summary = dns_context.get("summary") or {}

    try:
        dns_total = int(dns_summary.get("total") or 0)
    except (TypeError, ValueError):
        dns_total = 0

    try:
        unique_domains = int(dns_summary.get("unique_domains") or 0)
    except (TypeError, ValueError):
        unique_domains = 0

    available = bool(dns_context.get("available")) and dns_total > 0
    window_minutes = dns_context.get("window_minutes", 120)

    evidence_used = brief.setdefault("evidence_used", [])
    evidence_overview = brief.setdefault("evidence_overview", [])
    attack_progression = brief.setdefault("attack_progression", [])
    recommended_actions = brief.setdefault("recommended_actions", [])

    if available:
        top_domains = dns_summary.get("top_domains") or []
        domain_names = [
            str(item.get("query_name"))
            for item in top_domains
            if isinstance(item, dict) and item.get("query_name")
        ][:5]

        domain_text = ", ".join(domain_names) if domain_names else "no dominant domain listed"

        append_unique_dict(
            evidence_used,
            "label",
            "Endpoint DNS context",
            {
                "label": "Endpoint DNS context",
                "count": dns_total,
                "description": (
                    f"{dns_total} DNS observation(s) were found for the same host/client IP "
                    f"in the ±{window_minutes} minute window, across {unique_domains} unique domain(s). "
                    f"Top observed domains: {domain_text}. This is contextual host telemetry only "
                    "and does not imply causal correlation with the incident."
                ),
            },
        )

        append_unique_dict(
            evidence_overview,
            "source",
            "Endpoint DNS context",
            {
                "time": safe_text(incident_payload.get("timestamp_local")),
                "description": (
                    f"DNS context shows host activity near the incident time: {dns_total} DNS "
                    f"observation(s), {unique_domains} unique queried domain(s). This helps describe "
                    "surrounding host network activity but does not explain or prove the incident cause."
                ),
                "source": "Endpoint DNS context",
                "verification": "Context only",
            },
        )

        append_unique_dict(
            attack_progression,
            "source",
            "Endpoint DNS context",
            {
                "time": safe_text(incident_payload.get("timestamp_local")),
                "description": (
                    f"Endpoint DNS context was observed in the selected window. It is matched by "
                    "host/client IP and time only; no causal relationship is inferred."
                ),
                "source": "Endpoint DNS context",
                "verification": "Context only",
            },
        )

    else:
        append_unique_dict(
            evidence_used,
            "label",
            "Endpoint DNS context",
            {
                "label": "Endpoint DNS context",
                "count": 0,
                "description": (
                    "No contextual DNS telemetry was found for the same host/client IP in the selected "
                    "time window, or DNS context was unavailable. No causal DNS relationship is inferred."
                ),
            },
        )

    append_unique_dict(
        recommended_actions,
        "action",
        "Review DNS context as host/time-window telemetry only; do not infer causal correlation without supporting evidence",
        {
            "action": "Review DNS context as host/time-window telemetry only; do not infer causal correlation without supporting evidence",
            "owner": "SOC analyst",
            "impact": "Low" if available else "Informational",
            "requires_approval": True,
        },
    )

    return brief


def load_incident_payload(db, incident_id: int) -> dict[str, Any]:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    payload = serialize_incident(incident)
    payload["network_evidence"] = load_network_evidence_summary(payload)
    payload["dns_context"] = load_dns_context_summary(payload)

    return payload


def build_ai_brief_preview(incident_id: int) -> dict[str, Any]:
    db = SessionLocal()

    try:
        incident_payload = load_incident_payload(db, incident_id)
        brief = deterministic_brief(
            incident_payload,
            "this GET endpoint returns a deterministic preview; use POST to generate the local AI brief",
        )
        brief = enrich_brief_with_dns_context(brief, incident_payload)

        return {
            "incident_id": incident_id,
            "generated_at": utc_now().isoformat(),
            "source": "deterministic_preview",
            "model_timeout_seconds": AI_BRIEF_TIMEOUT_SECONDS,
            "brief": brief,
        }

    finally:
        db.close()


def generate_ai_brief(incident_id: int) -> dict[str, Any]:
    db = SessionLocal()

    try:
        incident_payload = load_incident_payload(db, incident_id)
        security_context = build_security_context(incident_payload)
        prompt = build_prompt(incident_payload, security_context)

        source = "local_ai"
        raw_output = ""
        parsed = None
        retry_attempted = False
        error_type = None

        try:
            raw_output = call_ollama_chat(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a defensive AI SOC assistant. Return only valid JSON. "
                            "Do not include markdown, chain-of-thought, hidden reasoning or <think> tags."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                timeout_seconds=AI_BRIEF_TIMEOUT_SECONDS,
            )

            cleaned = sanitize_llm_output(raw_output)
            parsed = extract_json_object(cleaned)

            if parsed is None or is_invalid_llm_output(raw_output):
                retry_attempted = True

                raw_output = call_ollama_chat(
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "The previous output was invalid. Return only valid JSON. "
                                "No markdown. No chain-of-thought. No <think> tags."
                            ),
                        },
                        {
                            "role": "user",
                            "content": prompt,
                        },
                    ],
                    timeout_seconds=AI_BRIEF_TIMEOUT_SECONDS,
                )

                cleaned = sanitize_llm_output(raw_output)
                parsed = extract_json_object(cleaned)

            if parsed is None or is_invalid_llm_output(raw_output):
                source = "deterministic_fallback"
                parsed = deterministic_brief(
                    incident_payload,
                    "the local AI output was invalid or not valid JSON",
                )

        except Exception as exc:
            source = "deterministic_fallback"
            error_type = type(exc).__name__
            parsed = deterministic_brief(
                incident_payload,
                "the local AI call failed or timed out",
            )

        brief = normalize_brief(parsed, incident_payload.get("extracted_entities") or {})
        brief = enrich_brief_with_dns_context(brief, incident_payload)

        audit = IncidentAudit(
            incident_id=incident_id,
            event_type="INCIDENT_AI_BRIEF_GENERATED",
            old_value=None,
            new_value=source,
            comment=(
                f"source={source}; confidence={brief.get('confidence')}; "
                f"retry_attempted={retry_attempted}; error_type={error_type or '-'}"
            ),
            created_by="local_ai",
        )

        db.add(audit)
        db.commit()

        return {
            "incident_id": incident_id,
            "generated_at": utc_now().isoformat(),
            "source": source,
            "model_timeout_seconds": AI_BRIEF_TIMEOUT_SECONDS,
            "retry_attempted": retry_attempted,
            "error_type": error_type,
            "brief": brief,
        }

    finally:
        db.close()
