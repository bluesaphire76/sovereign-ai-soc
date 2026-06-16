import json
import logging
import os

from dotenv import load_dotenv

from ai_model_config import get_profile
from ai_model_policy import AiTask
from database import SessionLocal
from llm_client import generate_ai_response
from models import CaseAIAnalysis, CaseIncident, Incident, IncidentCase
from qdrant_knowledge import format_semantic_memory_context_for_prompt
from rag_retriever import retrieve_security_context
from llm_output import is_invalid_llm_output, sanitize_llm_output

load_dotenv()

OLLAMA_MODEL = get_profile("standard").model
logger = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.getenv(name, str(default))).strip())
    except Exception:
        return default


CASE_AI_ANALYSIS_TIMEOUT_SECONDS = _env_int(
    "CASE_AI_ANALYSIS_TIMEOUT_SECONDS",
    _env_int("CASE_AI_GENERATION_TIMEOUT_SECONDS", 180),
)


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

    context_empty_message = "No semantic memory context was retrieved for this case."

    try:
        security_context = retrieve_security_context(rag_query, limit=4)
    except Exception as exc:
        security_context = []
        context_empty_message = (
            "Semantic memory retrieval failed; continuing with case-only context."
        )
        logger.warning(
            "case_semantic_memory_retrieval_failed",
            extra={"reason": exc.__class__.__name__},
        )

    context_text = format_semantic_memory_context_for_prompt(
        security_context,
        empty_message=context_empty_message,
        max_items=4,
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

{context_text}

Semantic memory usage rules:
- Treat retrieved semantic memory as advisory context only.
- Do not use semantic memory as primary evidence.
- Do not use semantic memory to decide final severity.
- Do not use semantic memory for operational deduplication.
- Do not use semantic memory for automatic noise suppression.
- Do not use semantic memory for incident or case closure.
- Deterministic evidence, RBAC, audit, approval workflow and human validation remain authoritative.

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

        llm_result = generate_ai_response(
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
            task=AiTask.CASE_ANALYSIS,
            requested_mode="auto",
            user_triggered=True,
            timeout_seconds=CASE_AI_ANALYSIS_TIMEOUT_SECONDS,
        )

        raw_analysis_text = str(llm_result.get("text") or "")

        if not raw_analysis_text:
            raise RuntimeError(str(llm_result.get("error_type") or "EmptyLlmResponse"))

        analysis_text = sanitize_llm_output(raw_analysis_text)

        if is_invalid_llm_output(raw_analysis_text) or is_invalid_llm_output(analysis_text):
            llm_result = generate_ai_response(
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
                task=AiTask.CASE_ANALYSIS,
                requested_mode="auto",
                user_triggered=True,
                timeout_seconds=CASE_AI_ANALYSIS_TIMEOUT_SECONDS,
            )

            raw_analysis_text = str(llm_result.get("text") or "")

            if not raw_analysis_text:
                raise RuntimeError(str(llm_result.get("error_type") or "EmptyLlmResponse"))

            analysis_text = sanitize_llm_output(raw_analysis_text)

        recommended_status, recommended_severity = extract_recommendation(analysis_text)

        row = CaseAIAnalysis(
            case_id=case.id,
            model=str(llm_result.get("model") or OLLAMA_MODEL),
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
