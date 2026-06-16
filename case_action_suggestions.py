import json
import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from ai_model_config import get_profile
from ai_model_policy import AiTask
from database import SessionLocal
from llm_client import generate_ai_response
from llm_output import is_invalid_llm_output, sanitize_llm_output
from models import CaseAIAnalysis, CaseAction, CaseIncident, Incident, IncidentCase

load_dotenv()

OLLAMA_MODEL = get_profile("standard").model


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.getenv(name, str(default))).strip())
    except Exception:
        return default


CASE_AI_ACTION_PLAN_TIMEOUT_SECONDS = _env_int(
    "CASE_AI_ACTION_PLAN_TIMEOUT_SECONDS",
    _env_int("CASE_AI_GENERATION_TIMEOUT_SECONDS", 180),
)

VALID_CATEGORIES = {
    "INVESTIGATION",
    "CONTAINMENT",
    "EVIDENCE_REVIEW",
    "ESCALATION",
    "CLOSURE",
    "OTHER",
}

VALID_PRIORITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


def safe_json_loads(value):
    if not value:
        return None

    if isinstance(value, dict):
        return value

    try:
        return json.loads(value)
    except Exception:
        return None


def safe_isoformat(value):
    if not value:
        return None

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return str(value)


def extract_json_object(text: str) -> dict:
    cleaned = sanitize_llm_output(text)

    cleaned = cleaned.replace("```json", "").replace("```", "").strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ValueError("LLM output does not contain a JSON object")

    return json.loads(cleaned[start:end + 1])


def normalize_category(value: str | None) -> str:
    candidate = str(value or "INVESTIGATION").upper().strip()

    if candidate not in VALID_CATEGORIES:
        return "OTHER"

    return candidate


def normalize_priority(value: str | None) -> str:
    candidate = str(value or "MEDIUM").upper().strip()

    if candidate not in VALID_PRIORITIES:
        return "MEDIUM"

    return candidate


def normalize_due_hours(value, priority: str) -> int:
    try:
        hours = int(value)
    except Exception:
        hours = 24

    if hours <= 0:
        hours = 24

    if priority == "CRITICAL":
        return min(hours, 4)

    if priority == "HIGH":
        return min(hours, 8)

    if priority == "MEDIUM":
        return min(hours, 24)

    return min(hours, 72)


def load_case_context(db, case_id: int):
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == case_id)
        .first()
    )

    if not case:
        raise ValueError(f"Case {case_id} not found")

    incidents = (
        db.query(Incident)
        .join(CaseIncident, CaseIncident.incident_id == Incident.id)
        .filter(CaseIncident.case_id == case_id)
        .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
        .all()
    )

    latest_analysis = (
        db.query(CaseAIAnalysis)
        .filter(CaseAIAnalysis.case_id == case_id)
        .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
        .first()
    )

    existing_actions = (
        db.query(CaseAction)
        .filter(CaseAction.case_id == case_id)
        .order_by(CaseAction.created_at.asc(), CaseAction.id.asc())
        .all()
    )

    return case, incidents, latest_analysis, existing_actions


def build_case_action_prompt(
    case: IncidentCase,
    incidents: list[Incident],
    latest_analysis: CaseAIAnalysis | None,
    existing_actions: list[CaseAction],
) -> str:
    incident_summaries = []

    for incident in incidents:
        incident_summaries.append(
            {
                "id": incident.id,
                "timestamp": safe_isoformat(incident.timestamp),
                "status": incident.status,
                "agent": incident.agent,
                "rule": incident.rule,
                "level": incident.level,
                "mitre": safe_json_loads(incident.mitre) or incident.mitre,
                "risk_score": incident.risk_score,
                "recommended_priority": incident.recommended_priority,
                "correlated": incident.correlated,
                "correlation_score": incident.correlation_score,
                "correlation_type": incident.correlation_type,
                "escalation_reason": incident.escalation_reason,
                "correlation_summary": safe_json_loads(
                    incident.correlation_summary
                ),
            }
        )

    action_summaries = [
        {
            "id": action.id,
            "title": action.title,
            "status": action.status,
            "priority": action.priority,
            "category": action.category,
            "due_at": safe_isoformat(action.due_at),
        }
        for action in existing_actions
    ]

    payload = {
        "case": {
            "id": case.id,
            "title": case.title,
            "status": case.status,
            "severity": case.severity,
            "severity_review": case.severity_review,
            "owner": case.owner,
            "agent": case.agent,
            "correlation_type": case.correlation_type,
            "risk_score": case.risk_score,
            "summary": safe_json_loads(case.summary) or case.summary,
            "status_reason": case.status_reason,
        },
        "latest_case_ai_analysis": latest_analysis.analysis
        if latest_analysis
        else None,
        "existing_actions": action_summaries,
        "incidents": incident_summaries,
    }

    return f"""
/no_think

You are a professional defensive AI SOC Assistant.

Your task is to propose a practical action plan for a human SOC analyst.
The action plan must be based only on the case data, correlated incidents, existing actions, and the latest case AI analysis if available.

CASE DATA:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Generate an AI-suggested case action plan.

Output constraints:
- English only.
- Return JSON only.
- Do not include Markdown.
- Do not include explanations outside JSON.
- Do not include hidden reasoning, chain-of-thought, internal deliberation, or <think> tags.
- Do not use Chinese, Italian, or any other language unless explicitly configured.
- Do not suggest offensive actions.
- Do not suggest automatic remediation without human validation.
- Avoid duplicate actions already present in existing_actions.

Return exactly this JSON structure:

{{
  "actions": [
    {{
      "title": "Short action title",
      "description": "Concrete SOC analyst task with validation steps.",
      "category": "INVESTIGATION",
      "priority": "HIGH",
      "due_hours": 8
    }}
  ]
}}

Allowed category values:
- INVESTIGATION
- CONTAINMENT
- EVIDENCE_REVIEW
- ESCALATION
- CLOSURE
- OTHER

Allowed priority values:
- LOW
- MEDIUM
- HIGH
- CRITICAL

Rules:
- Generate between 3 and 6 actions.
- Each title must be short and operational.
- Each description must be concrete and actionable.
- Prefer evidence review and validation before containment.
- Use CRITICAL only when immediate business impact or active compromise is strongly supported.
- If evidence is weak, recommend investigation and evidence review rather than containment.
"""


def generate_raw_suggestions(prompt: str) -> tuple[dict, dict]:
    llm_result = generate_ai_response(
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a defensive AI SOC Assistant. "
                    "Return JSON only. Answer in English only. "
                    "Do not include chain-of-thought, hidden reasoning, or <think> tags."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        task=AiTask.CASE_ANALYSIS,
        requested_mode="auto",
        user_triggered=True,
        timeout_seconds=CASE_AI_ACTION_PLAN_TIMEOUT_SECONDS,
    )

    raw_output = str(llm_result.get("text") or "")

    if not raw_output:
        raise RuntimeError(str(llm_result.get("error_type") or "EmptyLlmResponse"))

    cleaned_output = sanitize_llm_output(raw_output)

    if is_invalid_llm_output(raw_output) or is_invalid_llm_output(cleaned_output):
        llm_result = generate_ai_response(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "The previous output was invalid. "
                        "Return valid JSON only. English only. "
                        "No chain-of-thought, no hidden reasoning, no Chinese text, "
                        "no Italian text, and no <think> tags."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            task=AiTask.CASE_ANALYSIS,
            requested_mode="auto",
            user_triggered=True,
            timeout_seconds=CASE_AI_ACTION_PLAN_TIMEOUT_SECONDS,
        )

        raw_output = str(llm_result.get("text") or "")

        if not raw_output:
            raise RuntimeError(str(llm_result.get("error_type") or "EmptyLlmResponse"))

        cleaned_output = sanitize_llm_output(raw_output)

    return extract_json_object(cleaned_output), llm_result


def normalize_actions(raw_payload: dict) -> list[dict]:
    now = datetime.now(timezone.utc)
    raw_actions = raw_payload.get("actions", [])

    if not isinstance(raw_actions, list):
        raise ValueError("LLM JSON does not contain an actions list")

    normalized = []

    for item in raw_actions[:6]:
        if not isinstance(item, dict):
            continue

        title = str(item.get("title") or "").strip()
        description = str(item.get("description") or "").strip()

        if not title:
            continue

        priority = normalize_priority(item.get("priority"))
        category = normalize_category(item.get("category"))
        due_hours = normalize_due_hours(item.get("due_hours"), priority)
        suggested_due_at = now + timedelta(hours=due_hours)

        normalized.append(
            {
                "title": title[:160],
                "description": description,
                "category": category,
                "priority": priority,
                "due_hours": due_hours,
                "suggested_due_at": suggested_due_at.isoformat(),
            }
        )

    if not normalized:
        raise ValueError("No valid actions were generated by the LLM")

    return normalized


def generate_case_action_suggestions(case_id: int) -> dict:
    db = SessionLocal()

    try:
        case, incidents, latest_analysis, existing_actions = load_case_context(
            db,
            case_id,
        )

        if not incidents:
            raise ValueError(f"Case {case_id} has no linked incidents")

        prompt = build_case_action_prompt(
            case=case,
            incidents=incidents,
            latest_analysis=latest_analysis,
            existing_actions=existing_actions,
        )

        raw_payload, llm_result = generate_raw_suggestions(prompt)
        actions = normalize_actions(raw_payload)

        return {
            "case_id": case.id,
            "model": str(llm_result.get("model") or OLLAMA_MODEL),
            "llm_profile": llm_result.get("profile"),
            "llm_fallback_used": bool(llm_result.get("fallback_used", False)),
            "llm_latency_ms": llm_result.get("latency_ms"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "actions": actions,
        }

    finally:
        db.close()
