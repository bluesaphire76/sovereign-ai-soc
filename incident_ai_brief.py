from __future__ import annotations

import json
import os
import re
from typing import Any

from dotenv import load_dotenv

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
- Identify evidence used.
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


def load_incident_payload(db, incident_id: int) -> dict[str, Any]:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    return serialize_incident(incident)


def build_ai_brief_preview(incident_id: int) -> dict[str, Any]:
    db = SessionLocal()

    try:
        incident_payload = load_incident_payload(db, incident_id)
        brief = deterministic_brief(
            incident_payload,
            "this GET endpoint returns a deterministic preview; use POST to generate the local AI brief",
        )

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
