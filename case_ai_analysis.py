import json
import os

import ollama
from dotenv import load_dotenv

from database import SessionLocal
from models import CaseAIAnalysis, CaseIncident, Incident, IncidentCase
from rag_retriever import retrieve_security_context
from llm_output import is_invalid_llm_output, sanitize_llm_output

load_dotenv()

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")


def safe_json_loads(value: str | None):
    if not value:
        return None

    try:
        return json.loads(value)
    except Exception:
        return None


def load_case_bundle(db, case_id: int):
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == case_id)
        .first()
    )

    if not case:
        return None, []

    incidents = (
        db.query(Incident)
        .join(CaseIncident, CaseIncident.incident_id == Incident.id)
        .filter(CaseIncident.case_id == case_id)
        .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
        .all()
    )

    return case, incidents


def build_case_prompt(case: IncidentCase, incidents: list[Incident]) -> str:
    case_summary = safe_json_loads(case.summary) or case.summary or ""

    rag_query = " ".join(
        [
            str(case.title or ""),
            str(case.correlation_type or ""),
            str(case.agent or ""),
            " ".join(str(incident.rule or "") for incident in incidents),
            " ".join(str(incident.mitre or "") for incident in incidents),
        ]
    )

    security_context = retrieve_security_context(rag_query, limit=4)

    context_text = "\n\n".join(
        [
            f"Source: {item['source']}\n{item['text']}"
            for item in security_context
        ]
    )

    incident_summaries = []

    for incident in incidents:
        correlation_summary = safe_json_loads(incident.correlation_summary)

        incident_summaries.append(
            {
                "id": incident.id,
                "timestamp": incident.timestamp,
                "status": incident.status,
                "agent": incident.agent,
                "rule": incident.rule,
                "level": incident.level,
                "mitre": incident.mitre,
                "risk_score": incident.risk_score,
                "correlation_score": incident.correlation_score,
                "correlation_type": incident.correlation_type,
                "recommended_priority": incident.recommended_priority,
                "attack_chain": incident.attack_chain,
                "escalation_reason": incident.escalation_reason,
                "correlation_summary": correlation_summary,
            }
        )

    payload = {
        "case": {
            "id": case.id,
            "title": case.title,
            "status": case.status,
            "severity": case.severity,
            "agent": case.agent,
            "correlation_type": case.correlation_type,
            "risk_score": case.risk_score,
            "summary": case_summary,
        },
        "incidents": incident_summaries,
    }

    return f"""
/no_think

You are a professional defensive AI SOC Assistant.

You must analyze an investigation CASE composed of multiple correlated Wazuh incidents.
Your task is to help a human SOC analyst understand what is happening, assess the risk, and decide what to do next.

Knowledge base context:
{context_text}

CASE DATA:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Respond in English, using a pragmatic and operational SOC style, with the following sections:

1. Executive summary
   - Provide a concise 3-5 line summary of the case.

2. Risk assessment
   - Assess the actual severity.
   - Explain why the case is or is not critical.
   - Describe the potential impact on hosts, accounts, privileges, or services.

3. Key evidence
   - List the most relevant incidents.
   - Explain how they are connected.
   - Highlight MITRE ATT&CK techniques when available.

4. SOC hypothesis
   - Could this be a false positive?
   - Could this be legitimate administrative activity?
   - Could this indicate compromise?
   - What evidence is missing to confirm the hypothesis?

5. Recommended immediate actions
   - Provide concrete checks to perform now.
   - Mention logs to review.
   - Mention accounts, processes, or hosts to validate.
   - Do not suggest offensive actions.

6. Suggested remediation
   - Recommend defensive and conservative actions only.
   - Include hardening or control improvements where relevant.
   - Require human validation before any operational change.

7. Operational recommendation
   - Recommended status, one of: OPEN, TRIAGED, ESCALATED, CLOSED, FALSE_POSITIVE.
   - Recommended severity, one of: LOW, MEDIUM, HIGH, CRITICAL.
   - The single most important next step.

Output constraints:
- English only.
- Return only the final SOC analysis.
- Do not include hidden reasoning, chain-of-thought, internal deliberation, or <think> tags.
- Do not use Chinese, Italian, or any other language unless explicitly configured.

Rules:
- Do not invent facts that are not present in the case data.
- If evidence is missing, state that clearly.
- Do not propose offensive activities.
- Do not perform or suggest automatic remediation without human validation.
- Be concrete, concise, and useful for a SOC analyst.
"""


def extract_recommendation(analysis: str):
    text = analysis.upper()

    status = None
    severity = None

    for candidate in ["FALSE_POSITIVE", "ESCALATED", "TRIAGED", "CLOSED", "OPEN"]:
        if candidate in text:
            status = candidate
            break

    for candidate in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if candidate in text:
            severity = candidate
            break

    return status, severity


def generate_case_ai_analysis(case_id: int) -> CaseAIAnalysis:
    db = SessionLocal()

    try:
        case, incidents = load_case_bundle(db, case_id)

        if not case:
            raise ValueError(f"Case {case_id} not found")

        if not incidents:
            raise ValueError(f"Case {case_id} has no linked incidents")

        prompt = build_case_prompt(case, incidents)

        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a defensive AI SOC Assistant focused on triage, "
                        "correlation, investigation support, and operational response guidance. "
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

        raw_analysis_text = response["message"]["content"]
        analysis_text = sanitize_llm_output(raw_analysis_text)

        if is_invalid_llm_output(raw_analysis_text) or is_invalid_llm_output(analysis_text):
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
                            "Regenerate the SOC case analysis below in English only. "
                            "Return only the final answer.\n\n"
                            f"{prompt}"
                        ),
                    },
                ],
            )

            analysis_text = sanitize_llm_output(
                retry_response["message"]["content"]
            )

        recommended_status, recommended_severity = extract_recommendation(analysis_text)

        row = CaseAIAnalysis(
            case_id=case.id,
            model=OLLAMA_MODEL,
            analysis=analysis_text,
            recommended_status=recommended_status,
            recommended_severity=recommended_severity,
            created_by="llm",
        )

        db.add(row)
        db.commit()
        db.refresh(row)

        return row

    finally:
        db.close()
