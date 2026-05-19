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

AI_COMMAND_ROOM_TIMEOUT_SECONDS = float(
    os.getenv("AI_COMMAND_ROOM_TIMEOUT_SECONDS", "60")
)


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
        return "CRITICAL"

    if value >= 60:
        return "HIGH"

    if value >= 40:
        return "MEDIUM"

    return "LOW"


def serialize_incident(incident: Incident) -> dict[str, Any]:
    correlation_summary = safe_json_loads(incident.correlation_summary)
    raw_alert = safe_json_loads(incident.raw_alert)

    return {
        "id": incident.id,
        "status": incident.status or "NEW",
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
        "correlated": bool(incident.correlated),
        "correlation_score": incident.correlation_score,
        "correlation_type": incident.correlation_type,
        "attack_chain": incident.attack_chain,
        "escalation_reason": incident.escalation_reason,
        "recommended_priority": incident.recommended_priority,
        "wazuh_doc_id": incident.wazuh_doc_id,
        "correlation_summary": correlation_summary or incident.correlation_summary,
        "raw_alert": raw_alert or incident.raw_alert,
    }


def build_security_context(incident_payload: dict[str, Any]) -> list[dict[str, Any]]:
    if retrieve_security_context is None:
        return []

    rag_query = " ".join(
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
        return retrieve_security_context(rag_query, limit=4)
    except Exception:
        return []


def build_command_room_prompt(
    incident_payload: dict[str, Any],
    security_context: list[dict[str, Any]],
) -> str:
    context_text = "\n\n".join(
        [
            f"Source: {item.get('source')}\n{item.get('text')}"
            for item in security_context
        ]
    )

    schema = {
        "situation_summary": "string, 3-5 lines, clear SOC summary",
        "risk_rationale": "string, explain why this is risky or likely noise",
        "evidence_used": ["string, concrete evidence item from incident/correlation/raw data"],
        "investigation_hypotheses": [
            {
                "hypothesis": "string",
                "likelihood": "low|medium|high",
                "why": "string",
                "evidence_gap": "string",
            }
        ],
        "recommended_checks": ["string, concrete validation checks for the analyst"],
        "recommended_actions": [
            {
                "action": "string",
                "priority": "low|medium|high|critical",
                "reason": "string",
            }
        ],
        "containment_plan": ["string, defensive containment steps if confirmed suspicious"],
        "remediation_plan": ["string, hardening/remediation steps after validation"],
        "case_readiness": {
            "ready": True,
            "reason": "string",
            "missing_items": ["string"],
        },
        "confidence": "low|medium|high",
        "limitations": ["string, what the AI cannot confirm from current evidence"],
        "executive_summary": "string, concise management-ready summary",
    }

    return f"""
/no_think

You are a professional defensive AI SOC Assistant embedded in a local-first sovereign SOC platform.

You are analyzing ONE security incident for an Incident Command Room.
Your output will be used by a human SOC analyst. The AI must support the analyst, not replace them.

Your task:
- Explain what happened.
- Explain why it matters.
- Identify the evidence used.
- Generate useful investigation hypotheses.
- Recommend concrete checks.
- Recommend operational actions.
- Provide containment and remediation guidance.
- Explain case readiness.
- State confidence and limitations clearly.
- Provide an executive summary.

Knowledge base context:
{context_text}

Incident data:
{json.dumps(incident_payload, ensure_ascii=False, indent=2, default=str)}

Return ONLY valid JSON.
Do not wrap the JSON in markdown.
Do not include comments.
Do not include chain-of-thought, hidden reasoning, or <think> tags.
Do not invent facts.
If evidence is missing, state what is missing.
Do not propose offensive actions.
Do not propose automatic remediation without human validation.

Required JSON schema:
{json.dumps(schema, ensure_ascii=False, indent=2)}
"""


def extract_first_json_object(text: str) -> dict[str, Any] | None:
    if not text:
        return None

    stripped = text.strip()

    try:
        parsed = json.loads(stripped)

        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)

    if not match:
        return None

    try:
        parsed = json.loads(match.group(0))

        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None

    return None


def list_of_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        result = []

        for item in value:
            if isinstance(item, str) and item.strip():
                result.append(item.strip())
            elif isinstance(item, dict):
                rendered = " - ".join(
                    str(part)
                    for part in item.values()
                    if part is not None and str(part).strip()
                )

                if rendered:
                    result.append(rendered)

        return result

    if isinstance(value, str) and value.strip():
        return [value.strip()]

    return []


def normalize_analysis(value: dict[str, Any]) -> dict[str, Any]:
    case_readiness = value.get("case_readiness")

    if not isinstance(case_readiness, dict):
        case_readiness = {}

    hypotheses = value.get("investigation_hypotheses")

    if not isinstance(hypotheses, list):
        hypotheses = []

    normalized_hypotheses = []

    for item in hypotheses:
        if isinstance(item, dict):
            normalized_hypotheses.append(
                {
                    "hypothesis": safe_text(item.get("hypothesis")),
                    "likelihood": safe_text(item.get("likelihood")).lower(),
                    "why": safe_text(item.get("why")),
                    "evidence_gap": safe_text(item.get("evidence_gap")),
                }
            )
        elif isinstance(item, str):
            normalized_hypotheses.append(
                {
                    "hypothesis": item,
                    "likelihood": "medium",
                    "why": "-",
                    "evidence_gap": "-",
                }
            )

    actions = value.get("recommended_actions")

    if not isinstance(actions, list):
        actions = []

    normalized_actions = []

    for item in actions:
        if isinstance(item, dict):
            normalized_actions.append(
                {
                    "action": safe_text(item.get("action")),
                    "priority": safe_text(item.get("priority")).lower(),
                    "reason": safe_text(item.get("reason")),
                }
            )
        elif isinstance(item, str):
            normalized_actions.append(
                {
                    "action": item,
                    "priority": "medium",
                    "reason": "-",
                }
            )

    return {
        "situation_summary": safe_text(value.get("situation_summary")),
        "risk_rationale": safe_text(value.get("risk_rationale")),
        "evidence_used": list_of_strings(value.get("evidence_used")),
        "investigation_hypotheses": normalized_hypotheses,
        "recommended_checks": list_of_strings(value.get("recommended_checks")),
        "recommended_actions": normalized_actions,
        "containment_plan": list_of_strings(value.get("containment_plan")),
        "remediation_plan": list_of_strings(value.get("remediation_plan")),
        "case_readiness": {
            "ready": bool(case_readiness.get("ready")),
            "reason": safe_text(case_readiness.get("reason")),
            "missing_items": list_of_strings(case_readiness.get("missing_items")),
        },
        "confidence": safe_text(value.get("confidence")).lower(),
        "limitations": list_of_strings(value.get("limitations")),
        "executive_summary": safe_text(value.get("executive_summary")),
    }


def build_deterministic_command_room_analysis(
    incident_payload: dict[str, Any],
    reason: str,
) -> dict[str, Any]:
    risk_score = int(incident_payload.get("risk_score") or 0)
    level = int(incident_payload.get("level") or 0)
    correlated = bool(incident_payload.get("correlated"))
    band = risk_band(risk_score)
    host = safe_text(incident_payload.get("agent"))
    rule = safe_text(incident_payload.get("rule"))

    ready = risk_score >= 60 or correlated or level >= 8
    missing_items = []

    if not incident_payload.get("raw_alert"):
        missing_items.append("Raw Wazuh alert is not available.")

    if not incident_payload.get("ai_analysis"):
        missing_items.append("Previous AI triage text is not available.")

    if not correlated:
        missing_items.append("No explicit correlation pattern is currently attached.")

    return {
        "situation_summary": (
            f"Incident #{incident_payload.get('id')} was raised on host {host}. "
            f"The triggering detection is: {rule}. "
            f"The current risk band is {band} with score {risk_score}. "
            f"Human validation is required before escalation or closure."
        ),
        "risk_rationale": (
            "This assessment was generated by deterministic fallback because "
            f"{reason}. Risk is based on Wazuh level, current risk score, "
            "correlation state and available incident metadata."
        ),
        "evidence_used": [
            f"Wazuh rule: {rule}",
            f"Host: {host}",
            f"Wazuh level: {level}",
            f"Risk score: {risk_score}",
            f"Correlation state: {'correlated' if correlated else 'not correlated'}",
        ],
        "investigation_hypotheses": [
            {
                "hypothesis": "Legitimate operational activity",
                "likelihood": "medium",
                "why": "Many host-level security alerts can be caused by expected administrative activity.",
                "evidence_gap": "Validate user, command/process and maintenance context around the event time.",
            },
            {
                "hypothesis": "Suspicious activity requiring investigation",
                "likelihood": "high" if ready else "medium",
                "why": "The signal has enough severity or context to require analyst validation.",
                "evidence_gap": "Review raw alert, authentication history, related alerts and host logs.",
            },
        ],
        "recommended_checks": [
            "Validate the raw Wazuh alert and full log.",
            "Confirm whether the host activity was expected and authorized.",
            "Review related events around the incident timestamp.",
            "Check authentication, sudo, process and package activity where available.",
            "Document the analyst decision before closure or escalation.",
        ],
        "recommended_actions": [
            {
                "action": "Start analyst investigation",
                "priority": "high" if ready else "medium",
                "reason": "The incident requires human validation before a lifecycle decision.",
            },
            {
                "action": "Escalate to case if suspicious activity is confirmed",
                "priority": "high" if ready else "medium",
                "reason": "Case ownership is appropriate only after evidence validation.",
            },
        ],
        "containment_plan": [
            "Do not perform automatic containment.",
            "If compromise is confirmed, isolate affected account or host according to local IR procedure.",
            "Preserve relevant logs before remediation.",
        ],
        "remediation_plan": [
            "Review and harden the control related to the triggering rule.",
            "Tune detection logic if the event is confirmed operational noise.",
            "Update runbook guidance if analyst validation identifies a repeatable pattern.",
        ],
        "case_readiness": {
            "ready": ready,
            "reason": (
                "The incident is ready for case review."
                if ready
                else "The incident should be triaged before becoming a case."
            ),
            "missing_items": missing_items,
        },
        "confidence": "medium",
        "limitations": [
            "This fallback did not use a live LLM response.",
            "The assessment cannot confirm intent without analyst validation.",
            "Host, user and process context may be incomplete in the current incident payload.",
        ],
        "executive_summary": (
            f"A security incident on host {host} requires analyst validation. "
            f"Current severity is {band}. No automated remediation was performed."
        ),
    }


def load_incident_payload(db, incident_id: int) -> dict[str, Any]:
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )

    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    return serialize_incident(incident)


def generate_command_room_analysis(incident_id: int) -> dict[str, Any]:
    db = SessionLocal()

    try:
        incident_payload = load_incident_payload(db, incident_id)
        security_context = build_security_context(incident_payload)
        prompt = build_command_room_prompt(incident_payload, security_context)

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
                            "You are a defensive AI SOC Assistant. "
                            "Return only valid JSON. Do not include markdown, chain-of-thought, "
                            "hidden reasoning, or <think> tags."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                timeout_seconds=AI_COMMAND_ROOM_TIMEOUT_SECONDS,
            )

            cleaned = sanitize_llm_output(raw_output)
            parsed = extract_first_json_object(cleaned)

            if is_invalid_llm_output(raw_output) or parsed is None:
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
                    timeout_seconds=AI_COMMAND_ROOM_TIMEOUT_SECONDS,
                )

                cleaned = sanitize_llm_output(raw_output)
                parsed = extract_first_json_object(cleaned)

            if parsed is None or is_invalid_llm_output(raw_output):
                source = "deterministic_fallback"
                parsed = build_deterministic_command_room_analysis(
                    incident_payload,
                    "the local AI output was invalid or not valid JSON",
                )

        except Exception as exc:
            source = "deterministic_fallback"
            error_type = type(exc).__name__
            parsed = build_deterministic_command_room_analysis(
                incident_payload,
                "the local AI call failed or timed out",
            )

        analysis = normalize_analysis(parsed)

        audit = IncidentAudit(
            incident_id=incident_id,
            event_type="COMMAND_ROOM_AI_GENERATED",
            old_value=None,
            new_value=source,
            comment=(
                f"source={source}; confidence={analysis.get('confidence')}; "
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
            "model_timeout_seconds": AI_COMMAND_ROOM_TIMEOUT_SECONDS,
            "retry_attempted": retry_attempted,
            "error_type": error_type,
            "analysis": analysis,
        }

    finally:
        db.close()


def build_command_room_preview(incident_id: int) -> dict[str, Any]:
    db = SessionLocal()

    try:
        incident_payload = load_incident_payload(db, incident_id)

        return {
            "incident_id": incident_id,
            "generated_at": utc_now().isoformat(),
            "source": "deterministic_preview",
            "analysis": build_deterministic_command_room_analysis(
                incident_payload,
                "this GET endpoint returns a deterministic preview; use POST to run the local AI model",
            ),
        }

    finally:
        db.close()
